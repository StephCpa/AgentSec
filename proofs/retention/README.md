# Retention induction obligations

This directory checks two **abstract** models: authority-level window safety and
generation-to-image replica identity. It does not prove that arbitrary Python
executions refine either model, nor that their composition yields privacy.
The exact scope and obligation names are frozen in [contract.json](contract.json).

The window model has a ghost first-fact history, a live suffix, a confirmed
archive prefix, and ghost sets of ever-authentically-issued receipts, offers and
checkpoints. Facts are sequence-indexed opaque nonzero markers; signatures,
hashes, CBOR, deadlines, charging and private computation are outside this model.
The replica model separately assumes immutable, nonrollback authoritative
generation/image bindings and atomic local image/anchor installation. A candidate
image in that model is opaque: its window validity is **not** established there.

For each declared implication the checker asks whether its premise is satisfiable
and whether premise AND NOT conclusion is satisfiable. Positive implications must
return SAT then UNSAT; deliberate mutations must return SAT then SAT. UNKNOWN,
timeout, missing declarations and mismatched expected results fail the run.

Constructive ghost-array substitutions and small scalar witnesses are used only
for SAT queries. They establish consistency or exhibit a counterexample; they do
not restrict positive UNSAT induction queries. The false-universal-claim test
checks this separation explicitly. Positive window queries cover all widths
1..65535 and all sequence frontiers through 2^64-1, without enumerating lengths
or limiting executions to two operations. This is an induction argument about
the declared abstract transitions, not an arbitrary-input implementation proof.
Commit followed by a lost reply means the committed transition followed by a
stutter; an unavailable method call alone does not determine its commit outcome.

Use the pinned [Z3 solver](https://github.com/Z3Prover/z3) package in a separate
environment; production/protocol Python requirements are unchanged:

```sh
python3 -m venv /tmp/agentsec-retention-proof-env
/tmp/agentsec-retention-proof-env/bin/python -m pip install -r proofs/retention/requirements.txt
/tmp/agentsec-retention-proof-env/bin/python proofs/retention/check.py --output /tmp/agentsec-retention-proof-new
/tmp/agentsec-retention-proof-env/bin/python -m unittest discover -s proofs/retention -p 'test_*.py' -v
/tmp/agentsec-retention-proof-env/bin/python proofs/retention/replay.py /tmp/agentsec-retention-proof-new --solver /tmp/agentsec-retention-proof-env/bin/z3 --output /tmp/agentsec-retention-proof-replay-new.json
```

Outputs include the exact SMT-LIB queries, solver results, concrete mutation
witnesses, source hashes and environment. CLI replay starts a fresh solver
process for each query and does not import `model.py`. It uses the **same Z3
implementation**, not an independent theorem prover or checked proof kernel.
Repository evidence manifests bind the archived inputs and source versions;
hashes do not independently certify the semantic correctness of the abstraction.

See the [Chinese result and correspondence report](../../docs/research/2026-10-26-retention-inductive-invariants.md)
for the invariants, implementation obligations and remaining gaps.
