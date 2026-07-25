"""
Adversarial tests for L5 (behavioural fingerprinting).

Governing question: can an adversary who has READ THIS FILE either (a) make an
attack run's capability stream statistically indistinguishable from the
baseline, or (b) poison the baseline itself by shaping what a compromised guest
reports?
"""

import pytest

from ames.canonical import payload_capability_request
from ames.events import Capability, Event, EventType, NO_PARENT
from containment.fingerprint import (
    BehaviorFingerprint, BehaviorObservation, FingerprintError,
    observations_from_ledger,
)
from containment.vmspec import HOST_ACTOR_ID

GUEST_ACTOR = 0x1000  # well below HOST_ACTOR_RANGE_START


def obs(cap: Capability, granted: bool, ts: int) -> BehaviorObservation:
    return BehaviorObservation(cap, granted, ts)


def cap_event(cap: Capability, granted: bool, ts: int, *,
              actor: int = HOST_ACTOR_ID, seq: int = 0) -> Event:
    return Event(
        EventType.CAPABILITY_REQUEST, seq, ts, actor, NO_PARENT,
        payload_capability_request(cap, granted, ""),
    )


def sealed_from(*runs) -> BehaviorFingerprint:
    """Build and seal a baseline from one or more reference runs, each a
    sequence of BehaviorObservation."""
    fp = BehaviorFingerprint()
    for run in runs:
        fp.absorb(list(run))
    fp.seal()
    return fp


# ---------------------------------------------------------------------------
# observations_from_ledger: provenance filtering
# ---------------------------------------------------------------------------

def test_guest_attributed_capability_events_are_excluded():
    """A guest cannot fabricate what the broker recorded about it. Only the
    broker's own (host-attributed) decisions are ever fingerprinted."""
    events = [
        cap_event(Capability.FILE_WRITE, True, 100, actor=HOST_ACTOR_ID, seq=0),
        cap_event(Capability.RAW_SYSCALL, True, 200, actor=GUEST_ACTOR, seq=1),  # forged claim
    ]
    result = observations_from_ledger(events)
    assert len(result) == 1
    assert result[0].capability is Capability.FILE_WRITE


def test_guest_flood_cannot_poison_or_dilute_a_baseline():
    """A compromised guest emitting many favourable-looking claims moves
    nothing: they are never decoded into observations at all."""
    real = [cap_event(Capability.FILE_WRITE, True, 100, actor=HOST_ACTOR_ID, seq=0)]
    forged = [cap_event(Capability.NET_EGRESS, True, 100 + i, actor=GUEST_ACTOR, seq=i + 1)
              for i in range(500)]
    result = observations_from_ledger(real + forged)
    assert result == observations_from_ledger(real)


def test_non_capability_events_are_ignored():
    events = [Event(EventType.PROCESS_SPAWN, 0, 100, HOST_ACTOR_ID, NO_PARENT, b"\x00" * 68)]
    assert observations_from_ledger(events) == []


def test_truncated_payload_is_skipped_not_raised():
    bad = Event(EventType.CAPABILITY_REQUEST, 0, 100, HOST_ACTOR_ID, NO_PARENT, b"\x01")
    good = cap_event(Capability.FILE_WRITE, True, 200, seq=1)
    result = observations_from_ledger([bad, good])
    assert len(result) == 1
    assert result[0].capability is Capability.FILE_WRITE


def test_unknown_capability_byte_is_skipped_not_raised():
    bad = Event(EventType.CAPABILITY_REQUEST, 0, 100, HOST_ACTOR_ID, NO_PARENT, b"\xff\x01")
    result = observations_from_ledger([bad])
    assert result == []


# ---------------------------------------------------------------------------
# Baseline lifecycle: frozen, same reasoning as L7's EnvironmentBaseline
# ---------------------------------------------------------------------------

def test_absorb_after_seal_raises():
    fp = sealed_from([obs(Capability.FILE_WRITE, True, 0)])
    with pytest.raises(FingerprintError):
        fp.absorb([obs(Capability.FILE_WRITE, True, 100)])


def test_seal_empty_baseline_raises():
    with pytest.raises(FingerprintError):
        BehaviorFingerprint().seal()


def test_evaluate_before_seal_raises():
    fp = BehaviorFingerprint()
    fp.absorb([obs(Capability.FILE_WRITE, True, 0)])
    with pytest.raises(FingerprintError):
        fp.evaluate([obs(Capability.FILE_WRITE, True, 100)])


def test_absorbing_empty_run_is_a_noop():
    fp = BehaviorFingerprint()
    fp.absorb([])
    assert fp.runs_absorbed == 0
    with pytest.raises(FingerprintError):
        fp.seal()


def test_runs_absorbed_counts_reference_runs_not_observations():
    fp = BehaviorFingerprint()
    fp.absorb([obs(Capability.FILE_WRITE, True, 0), obs(Capability.PROCESS_SPAWN, True, 100)])
    fp.absorb([obs(Capability.FILE_WRITE, True, 0)])
    assert fp.runs_absorbed == 2


# ---------------------------------------------------------------------------
# Novelty: capability and transition
# ---------------------------------------------------------------------------

def test_exact_replay_of_baseline_flags_nothing():
    """True-negative check: the detector must not always fire. Replaying the
    baseline run itself has to come back clean, or the signal is meaningless."""
    run = [
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.FILE_WRITE, True, 1_000_000_000),
        obs(Capability.PROCESS_SPAWN, False, 2_000_000_000),
    ]
    fp = sealed_from(run)
    verdicts = fp.evaluate(run)
    assert all(not v.flagged for _, v in verdicts)


def test_never_before_seen_capability_is_flagged():
    fp = sealed_from([obs(Capability.FILE_WRITE, True, 0)])
    verdicts = fp.evaluate([obs(Capability.RAW_SYSCALL, False, 100)])
    (_, v), = verdicts
    assert v.novel_capability
    assert v.flagged


def test_known_capabilities_in_a_never_seen_order_flag_transition_only():
    """Same two capabilities as the baseline, reversed order: no capability is
    novel, but the adjacency never occurred."""
    fp = sealed_from([
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.PROCESS_SPAWN, False, 100),
    ])
    verdicts = fp.evaluate([
        obs(Capability.PROCESS_SPAWN, False, 0),
        obs(Capability.FILE_WRITE, True, 100),
    ])
    first, second = verdicts
    assert not first[1].novel_capability and not first[1].novel_transition  # no predecessor yet
    assert not second[1].novel_capability
    assert second[1].novel_transition
    assert second[1].flagged


def test_transitions_are_not_synthesized_across_reference_run_boundaries():
    """Absorbing run A (ending in FILE_WRITE) then run B (starting with
    RAW_SYSCALL) must NOT invent a FILE_WRITE->RAW_SYSCALL transition that
    never actually happened within a single run."""
    run_a = [obs(Capability.PROCESS_SPAWN, True, 0), obs(Capability.FILE_WRITE, True, 100)]
    run_b = [obs(Capability.RAW_SYSCALL, False, 0), obs(Capability.PROCESS_SPAWN, True, 100)]
    fp = sealed_from(run_a, run_b)

    candidate = [obs(Capability.FILE_WRITE, True, 0), obs(Capability.RAW_SYSCALL, False, 100)]
    verdicts = fp.evaluate(candidate)
    _, second_verdict = verdicts[1]
    assert second_verdict.novel_transition
    assert not second_verdict.novel_capability  # both capabilities individually known


def test_multiple_reference_runs_union_capabilities_and_pool_intervals():
    fp = sealed_from(
        [obs(Capability.FILE_WRITE, True, 0)],
        [obs(Capability.PROCESS_SPAWN, True, 0)],
    )
    assert fp.known_capabilities == {Capability.FILE_WRITE, Capability.PROCESS_SPAWN}


# ---------------------------------------------------------------------------
# Cadence
# ---------------------------------------------------------------------------

def test_cadence_outlier_flagged_for_an_abnormally_fast_burst():
    ns = 1_000_000_000  # 1s in ns
    run = [obs(Capability.FILE_WRITE, True, i * ns) for i in range(20)]  # steady 1s cadence
    fp = sealed_from(run)

    burst = [
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.FILE_WRITE, True, 1_000),  # 1 microsecond later -- wildly off baseline
    ]
    verdicts = fp.evaluate(burst)
    _, second = verdicts[1]
    assert second.cadence_outlier
    assert second.z_score is not None


def test_cadence_outlier_flagged_for_an_abnormally_slow_gap():
    ns = 1_000_000_000
    run = [obs(Capability.FILE_WRITE, True, i * ns) for i in range(20)]
    fp = sealed_from(run)

    slow = [
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.FILE_WRITE, True, 10_000 * ns),  # 10,000s later
    ]
    verdicts = fp.evaluate(slow)
    _, second = verdicts[1]
    assert second.cadence_outlier


def test_single_observation_reference_run_has_no_cadence_signal_and_does_not_crash():
    """One observation means zero intervals: stddev is 0, and the code must
    guard division by zero rather than raising or false-flagging everything."""
    fp = sealed_from([obs(Capability.FILE_WRITE, True, 0)])
    verdicts = fp.evaluate([
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.FILE_WRITE, True, 999),
    ])
    assert all(not v.cadence_outlier for _, v in verdicts)


def test_first_observation_in_a_run_has_no_prior_so_no_transition_or_cadence_verdict():
    fp = sealed_from([obs(Capability.FILE_WRITE, True, 0)])
    ((first_obs, first_verdict),) = fp.evaluate([obs(Capability.FILE_WRITE, True, 0)])
    assert first_verdict.z_score is None
    assert not first_verdict.novel_transition
    assert not first_verdict.cadence_outlier


# ---------------------------------------------------------------------------
# Documented limit: cadence evasion by pacing
# ---------------------------------------------------------------------------

def test_pacing_at_the_baseline_mean_evades_cadence_but_not_capability_novelty():
    """A known, documented limit: an adversary who has learned (or guessed) the
    baseline's cadence can pace a new request at exactly the historical mean
    interval and slip past the cadence check. What that pacing cannot do is
    make a first-time capability look like one the baseline ever saw -- the
    capability-set check has no threshold to pace under."""
    ns = 1_000_000_000
    run = [obs(Capability.FILE_WRITE, True, i * ns) for i in range(20)]
    fp = sealed_from(run)

    paced_attack = [
        obs(Capability.FILE_WRITE, True, 0),
        obs(Capability.RAW_SYSCALL, False, ns),  # paced at exactly the 1s baseline mean
    ]
    verdicts = fp.evaluate(paced_attack)
    _, second = verdicts[1]
    assert not second.cadence_outlier          # cadence check evaded, as documented
    assert second.novel_capability              # but the capability itself is still caught
    assert second.flagged


# ---------------------------------------------------------------------------
# SequenceVerdict.flagged correctness
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kwargs", [
    dict(novel_capability=True, novel_transition=False, cadence_outlier=False),
    dict(novel_capability=False, novel_transition=True, cadence_outlier=False),
    dict(novel_capability=False, novel_transition=False, cadence_outlier=True),
])
def test_flagged_is_true_if_any_subsignal_is_true(kwargs):
    from containment.fingerprint import SequenceVerdict
    v = SequenceVerdict(z_score=None, detail="", **kwargs)
    assert v.flagged


def test_flagged_is_false_when_nothing_fired():
    from containment.fingerprint import SequenceVerdict
    v = SequenceVerdict(False, False, False, None, "")
    assert not v.flagged
