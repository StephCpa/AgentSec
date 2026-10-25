"""Finite exhaustive DESIGN model; not implementation or cryptographic verification.

Two operations, unit costs, one revocable root, one authoritative ledger.
Atomic transitions abstract persistence; crash drops only volatile candidates.
No signatures, real database, provider effects, scheduler privacy or DP distributions.
"""
from collections import deque
from dataclasses import dataclass, replace
import json
from pathlib import Path


@dataclass(frozen=True)
class Op:
    state: str = "NEW"
    held: int = 0
    spent: int = 0
    candidate: bool = False
    delivered: int = 0  # bit 1: original sample; bit 2: a different sample
    authorized_start: bool = True


@dataclass(frozen=True)
class State:
    free: int
    revoked: bool = False
    ops: tuple = (Op(), Op())


def successors(s, variant):
    if not s.revoked:
        yield "revoke", replace(s, revoked=True)
    for i, op in enumerate(s.ops):
        def update(label, new_op, free=s.free):
            ops = list(s.ops)
            ops[i] = new_op
            return f"{label}[{i}]", replace(s, free=free, ops=tuple(ops))

        if op.state == "NEW" and not s.revoked and s.free > 0:
            yield update("reserve", replace(op, state="RESERVED", held=1), s.free-1)
        if op.state == "RESERVED":
            if not s.revoked or variant == "stale_admission":
                yield update("start", replace(op, state="STARTED", authorized_start=not s.revoked))
            yield update("cancel_before_start", replace(op, state="CANCELED", held=0), s.free+1)
        if op.state == "STARTED":
            if not op.candidate:
                yield update("compute_same_persisted_tape", replace(op, candidate=True))
            else:
                yield update("crash_lose_volatile_candidate", replace(op, candidate=False))
                yield update("commit_result_and_charge", replace(op, state="COMMITTED", held=0, spent=1, candidate=False))
                if variant == "early_output":
                    yield update("emit_before_commit", replace(op, delivered=1))
            yield update("abandon_and_burn", replace(op, state="BURNED", held=0, spent=1, candidate=False))
            if variant == "timeout_refund":
                yield update("refund_with_live_worker", replace(op, held=0), s.free+op.held)
        if op.state == "COMMITTED" and not s.revoked:
            if not op.delivered:
                yield update("deliver_original", replace(op, delivered=1))
            else:
                yield update("retry_same_result", op)
                if variant == "fresh_retry":
                    yield update("retry_with_new_sample", replace(op, delivered=3))


def violations(s, budget):
    errors = []
    if s.free < 0 or s.free + sum(o.held + o.spent for o in s.ops) != budget:
        errors.append("budget_conservation")
    for i, op in enumerate(s.ops):
        if op.state in ("RESERVED", "STARTED") and op.held != 1:
            errors.append(f"live_operation_charge_coverage[{i}]")
        if op.state in ("COMMITTED", "BURNED") and op.spent != 1:
            errors.append(f"terminal_charge_coverage[{i}]")
        if op.delivered and op.state != "COMMITTED":
            errors.append(f"commit_before_visibility[{i}]")
        if op.delivered == 3:
            errors.append(f"one_sample_per_operation[{i}]")
        if not op.authorized_start:
            errors.append(f"no_start_after_revocation[{i}]")
    return errors


def explore(budget, variant):
    initial = State(budget)
    paths = {initial: []}
    queue = deque([initial])
    transitions = 0
    max_depth = 0
    while queue:
        s = queue.popleft()
        for label, successor in successors(s, variant):
            transitions += 1
            path = paths[s] + [label]
            problems = violations(successor, budget)
            if problems:
                return dict(variant=variant, budget=budget, passed=False,
                            states_seen=len(paths), transitions=transitions,
                            violations=problems, counterexample=path)
            if successor not in paths:
                paths[successor] = path
                max_depth = max(max_depth, len(path))
                queue.append(successor)
    return dict(variant=variant, budget=budget, passed=True,
                reachable_states=len(paths), transitions=transitions,
                maximum_shortest_path=max_depth)


def main():
    variants = ["correct", "timeout_refund", "early_output", "fresh_retry", "stale_admission"]
    results = [explore(b, v) for b in (1, 2) for v in variants]
    report = {
        "scope": "Exhaustive finite design model: 2 operations, budgets 1 and 2, unit costs, 1 root revocation, atomic durable transitions, volatile candidate crash loss.",
        "excluded": ["cryptography", "database implementation", "external provider contracts", "DP proof", "timing/order side channels", "delegation chains", "rollback"],
        "results": results,
    }
    target = Path(__file__).with_name("model_results.json")
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    assert all(r["passed"] == (r["variant"] == "correct") for r in results)


if __name__ == "__main__":
    main()
