"""Symbolic authority-level retention safety; NOT an implementation refinement.

Facts are opaque nonzero integers. Receipt/offer/checkpoint arrays are ghost
sets of ever-authentically-issued messages, not retained production storage.
Authentication, root validation and atomic nonrollback authorities are premises.
"""
from dataclasses import dataclass, replace
import z3 as z

MAX_SEQ = 2**64 - 1
MAX_TIME = 2**62
MAX_WINDOW = 65535


@dataclass(frozen=True)
class Window:
    h: object
    f: object
    c: object
    s: object
    observed: object
    history: object
    live: object
    archive: object
    receipts: object
    receipt_facts: object
    offers: object
    checkpoints: object

    @classmethod
    def symbolic(cls, prefix):
        integers = [z.Int(prefix + '_' + n) for n in ('h', 'f', 'c', 's', 'observed')]
        arrays = [z.Array(prefix + '_' + n, z.IntSort(), z.BoolSort() if n in ('receipts', 'offers', 'checkpoints') else z.IntSort())
                  for n in ('history', 'live', 'archive', 'receipts', 'receipt_facts', 'offers', 'checkpoints')]
        return cls(*integers, *arrays)

    @classmethod
    def initial(cls):
        zero = z.K(z.IntSort(), z.IntVal(0)); absent = z.K(z.IntSort(), z.BoolVal(False))
        return cls(*([z.IntVal(0)] * 5), zero, zero, zero, absent, zero, absent, absent)


def invariant(a, width):
    q = z.Int('index')
    return z.And(1 <= width, width <= MAX_WINDOW, 0 <= a.s, a.s <= a.f, a.f <= a.c, a.c <= a.h,
        a.h <= MAX_SEQ, a.h - a.f <= width, 0 <= a.observed, a.observed <= MAX_TIME,
        z.ForAll(q, z.Implies(z.And(1 <= q, q <= a.h), a.history[q] != 0)),
        z.ForAll(q, a.live[q] == z.If(z.And(a.f < q, q <= a.h), a.history[q], 0)),
        z.ForAll(q, z.Implies(z.And(1 <= q, q <= a.c), a.archive[q] == a.history[q])),
        z.ForAll(q, z.Implies(a.receipts[q], z.And(1 <= q, q <= a.h, a.receipt_facts[q] == a.history[q]))),
        z.ForAll(q, z.Implies(a.offers[q], z.And(1 <= q, q <= a.c))),
        z.ForAll(q, z.Implies(a.checkpoints[q], z.And(0 <= q, q <= a.f))))


def retained(a, b):
    q = z.Int('index')
    return z.And(b.h >= a.h, b.f >= a.f, b.c >= a.c, b.s >= a.s, b.observed >= a.observed,
        z.ForAll(q, z.Implies(z.And(1 <= q, q <= a.h), b.history[q] == a.history[q])),
        z.ForAll(q, z.Implies(z.And(1 <= q, q <= a.c), b.archive[q] == a.archive[q])),
        z.ForAll(q, z.Implies(a.receipts[q], z.And(b.receipts[q], b.receipt_facts[q] == a.receipt_facts[q]))),
        z.ForAll(q, z.Implies(a.offers[q], b.offers[q])),
        z.ForAll(q, z.Implies(a.checkpoints[q], b.checkpoints[q])))


@dataclass(frozen=True)
class Obligation:
    name: str
    premise: object
    conclusion: object
    expected: str
    inspect: dict
    explanation: str
    witness_substitution: tuple = ()
    witness_bounds: object = None


def window_obligations():
    a = Window.symbolic('old'); width, target, now, value = z.Ints('width target now new_fact')
    q = z.Int('index'); inv = invariant(a, width)
    clock = z.And(a.observed <= now, now <= MAX_TIME)
    inspect = dict(width=width, target=target, now=now, new_fact=value,
                   high=a.h, floor=a.f, confirmed=a.c, sender_retired=a.s, observed=a.observed,
                   history_1=a.history[1], live_1=a.live[1], archive_1=a.archive[1])
    # Construct a small legal ghost-array interpretation for SAT witnesses only.
    # These substitutions are NEVER applied to positive induction queries.
    ones = z.K(z.IntSort(), z.IntVal(1))
    witness = ((a.history, ones), (a.live, z.Lambda(q, z.If(z.And(a.f < q, q <= a.h), 1, 0))),
               (a.archive, ones), (a.receipts, z.Lambda(q, z.And(1 <= q, q <= a.h))),
               (a.receipt_facts, ones), (a.offers, z.Lambda(q, z.And(1 <= q, q <= a.c))),
               (a.checkpoints, z.Lambda(q, z.And(0 <= q, q <= a.f))))
    result = [Obligation('window.initial', z.And(1 <= width, width <= MAX_WINDOW), invariant(Window.initial(), width),
                         'unsat', dict(width=width), 'Empty authorities satisfy the invariant for every supported window width.')]

    def step(name, guard, b, *, receiver_clock=False, expected='unsat', why=''):
        post = z.And(invariant(b, width), retained(a, b), b.observed == now if receiver_clock else z.BoolVal(True))
        result.append(Obligation('window.' + name, z.And(inv, guard), post, expected, inspect, why,
                                 witness, z.And(a.h <= 3, width <= 3)))

    receive = replace(a, h=a.h + 1, history=z.Store(a.history, a.h + 1, value),
                      live=z.Store(a.live, a.h + 1, value), observed=now)
    receive_guard = z.And(clock, a.h < MAX_SEQ, a.h - a.f < width, value != 0)
    step('receive_new', receive_guard, receive, receiver_clock=True,
         why='Append exactly high+1 only when capacity is available; preserve all older first facts.')
    receipt = replace(a, receipts=z.Store(a.receipts, target, True), receipt_facts=z.Store(a.receipt_facts, target, a.history[target]), observed=now)
    step('issue_live_receipt', z.And(clock, a.f < target, target <= a.h), receipt, receiver_clock=True,
         why='Only a committed live first fact can produce a new authenticated receipt token.')
    confirm = replace(a, c=a.c + 1, archive=z.Store(a.archive, a.c + 1, a.receipt_facts[a.c + 1]))
    step('confirm_next_receipt', a.receipts[a.c + 1], confirm,
         why='The issued-receipt invariant derives confirmed+1<=high and the immutable fact; no direct receiver read is assumed.')
    offer = replace(a, offers=z.Store(a.offers, target, True))
    step('issue_offer', z.And(a.s < target, target <= a.c), offer,
         why='An offer is issued only from the durable sender confirmation prefix.')
    retired_live = z.Lambda(q, z.If(q <= target, 0, a.live[q]))
    retire = replace(a, f=target, live=retired_live, observed=now)
    retire_guard = z.And(clock, a.f < target, a.offers[target])
    step('retire_issued_offer', retire_guard, retire, receiver_clock=True,
         why='An authenticated historical offer implies target<=current confirmed because confirmed is monotone.')
    checkpoint = replace(a, checkpoints=z.Store(a.checkpoints, a.f, True), observed=now)
    step('issue_checkpoint', clock, checkpoint, receiver_clock=True,
         why='A checkpoint witnesses the current committed floor, not a reconstructed deleted fact.')
    step('accept_old_or_current_checkpoint', z.And(a.checkpoints[target], a.s <= target), replace(a, s=target),
         why='Previously issued checkpoints remain at or below current receiver floor; sender floor never decreases.')
    step('duplicate_or_old_offer', z.And(clock, a.offers[target], target <= a.f), replace(a, observed=now), receiver_clock=True,
         why='An old offer can update observed time but must not delete newly received suffix facts.')
    step('full_window_denial', z.And(clock, a.h - a.f == width), replace(a, observed=now), receiver_clock=True,
         why='A valid business denial persists time without adding facts or receipts.')
    step('retired_delivery_denial', z.And(clock, 1 <= target, target <= a.f), replace(a, observed=now), receiver_clock=True,
         why='Previously retired sequence numbers cannot reenter the live map.')
    step('query_or_other_business_denial', clock, replace(a, observed=now), receiver_clock=True,
         why='Other read/denial transactions preserve facts but may advance observed time.')
    step('preauthentication_rejection', z.BoolVal(True), a,
         why='Rejections before the business transaction do not advance observed time.')
    step('lost_reply_or_precommit_exit', z.BoolVal(True), a,
         why='Lost replies and discarded precommit work are logical stutters at an unchanged authority.')

    # Mutations deliberately violate a necessary guard or a transaction update.
    step('negative.omit_window_guard', z.And(clock, a.h < MAX_SEQ, a.h - a.f == width, value != 0), receive,
         receiver_clock=True, expected='sat', why='A full receiver can exceed its live bound.')
    step('negative.delete_without_floor', retire_guard, replace(a, live=retired_live, observed=now),
         receiver_clock=True, expected='sat', why='Partial deletion breaks live=history suffix.')
    step('negative.floor_without_delete', retire_guard, replace(a, f=target, observed=now),
         receiver_clock=True, expected='sat', why='Advancing the floor without deletion leaves retired facts live.')
    step('negative.retire_without_issued_offer', z.And(clock, target == a.c + 1, target <= a.h), retire,
         receiver_clock=True, expected='sat', why='A valid receiver prefix alone is not a durable sender confirmation.')
    step('negative.reinsert_retired_fact', z.And(clock, 1 <= target, target <= a.f, value != 0),
         replace(a, live=z.Store(a.live, target, value), observed=now), receiver_clock=True, expected='sat',
         why='Replaying a deleted sequence resurrects a row below the floor.')
    step('negative.rewrite_old_fact', z.And(a.h >= 1, value != 0, value != a.history[1]),
         replace(a, history=z.Store(a.history, 1, value)), expected='sat', why='A first fact cannot change after its first event.')
    step('negative.prune_confirmed_archive', a.c >= 1, replace(a, archive=z.Store(a.archive, 1, 0)),
         expected='sat', why='Receiver retention is not authorization to remove the sender archive.')
    step('negative.lower_sender_floor', z.And(a.checkpoints[target], target < a.s), replace(a, s=target),
         expected='sat', why='An authentic old checkpoint must not roll the sender floor backward.')
    step('negative.reset_high_after_cleanup', z.And(retire_guard, target == a.h), replace(retire, h=z.IntVal(0)),
         receiver_clock=True, expected='sat', why='An empty live table is not a fresh sequence namespace.')
    step('negative.ignore_denial_clock', z.And(clock, now > a.observed, a.h - a.f == width), a,
         receiver_clock=True, expected='sat', why='An unchanged business state does not make authenticated denial a storage no-op.')
    return result


def replica_obligations():
    g, local_g, local_image, snapshot_g, proposal_g, new_image = z.Ints('authority_generation local_generation local_image snapshot_generation proposal_generation candidate_image')
    images = z.Array('committed_images', z.IntSort(), z.IntSort())
    inv = z.And(g >= 0, z.Or(local_g == -1, z.And(0 <= local_g, local_g <= g, local_image == images[local_g])))
    inspect = dict(generation=g, local_generation=local_g, local_image=local_image,
                   current_image=images[g], snapshot_generation=snapshot_g, snapshot_image=images[snapshot_g], proposal_generation=proposal_g)
    result = []
    def add(name, premise, conclusion, why, expected='unsat'):
        result.append(Obligation('replica.' + name, premise, conclusion, expected, inspect, why))
    def invariant_after(ng, nl, ni, table):
        return z.And(ng >= 0, z.Or(nl == -1, z.And(0 <= nl, nl <= ng, ni == table[nl])))
    add('fresh_replica', g >= 0, invariant_after(g, z.IntVal(-1), local_image, images), 'An empty replica has no authenticated anchor.')
    add('current_guard', z.And(inv, local_g == g), local_image == images[g], 'A current anchored replica reads exactly the current authority image.')
    cas_guard = z.And(inv, proposal_g == local_g, proposal_g == g)
    add('cas_read_identity', cas_guard, z.And(local_image == images[g], images[proposal_g] == images[g]),
        'Successful generation CAS binds the proposal to the image used by its transition proof.')
    committed = z.Store(images, g + 1, new_image)
    q = z.Int('index')
    commit_goal = z.And(invariant_after(g + 1, local_g, local_image, committed),
                        z.ForAll(q, z.Implies(z.And(0 <= q, q <= g), committed[q] == images[q])), g + 1 > g)
    add('authority_commit_local_loss', cas_guard, commit_goal,
        'A successful CAS appends a new generation; leaving the old local replica behind cannot rewrite historical images.')
    add('atomic_local_commit', cas_guard, invariant_after(g + 1, g + 1, new_image, committed),
        'Installing both the candidate image and its new anchor preserves the replica relation.')
    install_guard = z.And(inv, 0 <= snapshot_g, snapshot_g <= g)
    install_goal = z.And(invariant_after(g, snapshot_g, images[snapshot_g], images),
                        z.Implies(snapshot_g == g, images[snapshot_g] == images[g]))
    add('recover_historical_snapshot', install_guard, install_goal,
        'A recovery may install a now-stale authenticated snapshot; the current guard still distinguishes it.')
    add('recovery_precommit_stutter', inv, invariant_after(g, local_g, local_image, images),
        'A precommit recovery exit changes neither the committed local pair nor authority.')
    add('stale_install_frozen', z.And(install_guard, snapshot_g < g), snapshot_g != g,
        'After a concurrent authority advance, the recovered generation cannot pass the current guard.')
    add('fresh_replica_frozen', z.And(inv, local_g == -1), local_g != g,
        'No-anchor replicas cannot dispatch business through the current-generation gate.')
    add('negative.omit_current_guard', z.And(inv, 0 <= local_g, local_g < g, local_image != images[g]), local_image == images[g],
        'An internally consistent old image need not be current.', 'sat')
    add('negative.install_image_without_anchor', z.And(inv, local_g == g, 0 <= snapshot_g, snapshot_g < g,
        images[snapshot_g] != images[g]), invariant_after(g, local_g, images[snapshot_g], images),
        'A partial recovery can attach an old image to an apparently current anchor.', 'sat')
    add('negative.omit_cas_comparison', z.And(inv, proposal_g == local_g, 0 <= proposal_g, proposal_g < g, images[proposal_g] != images[g]),
        images[proposal_g] == images[g], 'Without CAS, an earlier state-transition proof does not apply to the new authority image.', 'sat')
    add('negative.authority_rollback', z.And(inv, g >= 1), g - 1 >= g,
        'Authentication alone cannot supply the nonrollback authority assumption.', 'sat')
    return result


def obligations():
    return window_obligations() + replica_obligations()
