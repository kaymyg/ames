"""
Adversarial tests for L6 (cognitive drift detection).

Governing question: can a sloppy or deliberately misleading guest's narrative
diverge from what the host actually observed, and does the monitor catch each
distinct way that can happen -- while also being honest that a guest which
simply echoes what it already witnessed will always look clean?
"""

import pytest

from ames.canonical import payload_capability_request
from ames.events import Capability, Event, EventType, NO_PARENT
from containment.drift import DriftMonitor, DriftReason, narrative_from_ledger
from containment.fingerprint import BehaviorObservation, observations_from_ledger
from containment.vmspec import HOST_ACTOR_ID

GUEST_ACTOR = 0x1000


def obs(cap: Capability, granted: bool, ts: int = 0) -> BehaviorObservation:
    return BehaviorObservation(cap, granted, ts)


def cap_event(cap: Capability, granted: bool, ts: int, *,
              actor: int, seq: int = 0) -> Event:
    return Event(
        EventType.CAPABILITY_REQUEST, seq, ts, actor, NO_PARENT,
        payload_capability_request(cap, granted, ""),
    )


def find(findings, cap, reason):
    return [f for f in findings if f.capability is cap and f.reason is reason]


# ---------------------------------------------------------------------------
# Extraction: narrative_from_ledger keeps only guest-attributed claims
# ---------------------------------------------------------------------------

def test_narrative_from_ledger_excludes_host_attributed_events():
    events = [
        cap_event(Capability.FILE_WRITE, True, 100, actor=HOST_ACTOR_ID),
        cap_event(Capability.FILE_WRITE, True, 100, actor=GUEST_ACTOR, seq=1),
    ]
    result = narrative_from_ledger(events)
    assert len(result) == 1


def test_narrative_and_evidence_extractors_are_disjoint_over_the_same_ledger():
    """The two extractors must never both accept the same event -- that would
    let one event count as both testimony and evidence, collapsing the
    distinction the whole layer is built on."""
    events = [
        cap_event(Capability.FILE_WRITE, True, 100, actor=HOST_ACTOR_ID, seq=0),
        cap_event(Capability.PROCESS_SPAWN, True, 100, actor=GUEST_ACTOR, seq=1),
    ]
    host = observations_from_ledger(events)
    guest = narrative_from_ledger(events)
    assert len(host) == 1 and len(guest) == 1
    assert host[0].capability is Capability.FILE_WRITE
    assert guest[0].capability is Capability.PROCESS_SPAWN


# ---------------------------------------------------------------------------
# The documented limit: a faithful echo produces no findings
# ---------------------------------------------------------------------------

def test_perfect_echo_produces_no_findings():
    """A guest that narrates exactly what it witnessed from the broker looks
    completely clean. This is the limit, made explicit rather than implied:
    absence of drift is not proof of good behaviour."""
    host = [obs(Capability.FILE_WRITE, True), obs(Capability.PROCESS_SPAWN, False)]
    guest = [obs(Capability.FILE_WRITE, True), obs(Capability.PROCESS_SPAWN, False)]
    findings = DriftMonitor().evaluate(host=host, guest=guest)
    assert findings == []


def test_empty_run_produces_no_findings():
    assert DriftMonitor().evaluate(host=[], guest=[]) == []


# ---------------------------------------------------------------------------
# UNNARRATED: host has it, guest's account is silent
# ---------------------------------------------------------------------------

def test_host_only_capability_is_unnarrated():
    host = [obs(Capability.PRIVILEGE_RAISE, False)]
    findings = DriftMonitor().evaluate(host=host, guest=[])
    (f,) = findings
    assert f.reason is DriftReason.UNNARRATED
    assert f.capability is Capability.PRIVILEGE_RAISE


# ---------------------------------------------------------------------------
# UNCONFIRMED: guest claims it, host never decided it
# ---------------------------------------------------------------------------

def test_guest_only_capability_is_unconfirmed():
    """A guest narrating a request the broker never actually decided on --
    either a fabricated account or a transport/timing gap. Either way, the
    story and the ledger disagree."""
    guest = [obs(Capability.NET_EGRESS, True)]
    findings = DriftMonitor().evaluate(host=[], guest=guest)
    (f,) = findings
    assert f.reason is DriftReason.UNCONFIRMED
    assert f.capability is Capability.NET_EGRESS


def test_fabricated_favourable_narrative_with_no_host_backing_is_caught():
    """The concealment-shaped case: a guest claims a clean grant for
    something it never actually went through the broker for at all."""
    findings = DriftMonitor().evaluate(host=[], guest=[obs(Capability.FILE_WRITE, True)])
    assert find(findings, Capability.FILE_WRITE, DriftReason.UNCONFIRMED)


# ---------------------------------------------------------------------------
# OUTCOME_MISMATCH: both sides have it, outcomes disagree
# ---------------------------------------------------------------------------

def test_guest_claims_grant_but_host_only_ever_denied_it():
    host = [obs(Capability.FILE_WRITE, False), obs(Capability.FILE_WRITE, False)]
    guest = [obs(Capability.FILE_WRITE, True)]
    findings = DriftMonitor().evaluate(host=host, guest=guest)
    (f,) = findings
    assert f.reason is DriftReason.OUTCOME_MISMATCH
    assert "True" in f.detail and "False" in f.detail


def test_guest_claims_denial_but_host_only_ever_granted_it():
    """The inverse shape: a guest narrating a worse outcome than what
    actually happened is just as much a mismatch as narrating a better one --
    the monitor does not assume drift only runs in the flattering direction."""
    host = [obs(Capability.FILE_WRITE, True)]
    guest = [obs(Capability.FILE_WRITE, False)]
    findings = DriftMonitor().evaluate(host=host, guest=guest)
    (f,) = findings
    assert f.reason is DriftReason.OUTCOME_MISMATCH


def test_matching_outcome_among_multiple_host_decisions_is_not_flagged():
    """The host recorded both an allow and a deny for the same capability
    across the run (e.g. policy state changed, or two distinct requests). A
    guest narrating either real outcome must not be flagged -- only an
    outcome that occurred on NEITHER side is drift."""
    host = [obs(Capability.FILE_WRITE, True), obs(Capability.FILE_WRITE, False)]
    guest = [obs(Capability.FILE_WRITE, True)]
    findings = DriftMonitor().evaluate(host=host, guest=guest)
    assert findings == []


# ---------------------------------------------------------------------------
# Multiple capabilities in one run: each judged independently
# ---------------------------------------------------------------------------

def test_mixed_run_classifies_each_capability_independently():
    host = [
        obs(Capability.FILE_WRITE, True),        # echoed correctly below
        obs(Capability.PRIVILEGE_RAISE, False),  # never narrated -> UNNARRATED
    ]
    guest = [
        obs(Capability.FILE_WRITE, True),                 # matches
        obs(Capability.PACKAGE_INSTALL, True),             # no host backing -> UNCONFIRMED
    ]
    findings = DriftMonitor().evaluate(host=host, guest=guest)
    reasons = {(f.capability, f.reason) for f in findings}
    assert (Capability.PRIVILEGE_RAISE, DriftReason.UNNARRATED) in reasons
    assert (Capability.PACKAGE_INSTALL, DriftReason.UNCONFIRMED) in reasons
    assert not any(f.capability is Capability.FILE_WRITE for f in findings)
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# evaluate_ledger: single-pass convenience over a raw ledger
# ---------------------------------------------------------------------------

def test_evaluate_ledger_matches_manual_extraction():
    events = [
        cap_event(Capability.RAW_SYSCALL, True, 0, actor=HOST_ACTOR_ID, seq=0),
    ]
    via_ledger = DriftMonitor().evaluate_ledger(events)
    via_manual = DriftMonitor().evaluate(
        host=observations_from_ledger(events), guest=narrative_from_ledger(events),
    )
    assert via_ledger == via_manual
    (f,) = via_ledger
    assert f.reason is DriftReason.UNNARRATED


def test_evaluate_ledger_accepts_a_generator_not_just_a_list():
    """`events` must be materialised internally -- a generator can only be
    iterated once, and both extractors need their own pass."""
    def gen():
        yield cap_event(Capability.FILE_WRITE, True, 0, actor=HOST_ACTOR_ID)

    findings = DriftMonitor().evaluate_ledger(gen())
    assert len(findings) == 1
