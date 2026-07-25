"""
Adversarial tests for L9 (autonomous kill system).

Governing question: can an adversary who has READ THIS FILE either avoid the
kill switch or turn it against the operator?
"""

import pytest

from ames.events import Capability, Event, EventType, NO_PARENT
from ames.canonical import payload_capability_request
from containment.broker import Broker, DenialTracker
from containment.envstate import (
    EnvironmentBaseline, EnvironmentMonitor, MutationObservation,
)
from containment.killswitch import (
    ABSOLUTE_REASONS, Evidence, KillReason, KillSwitch, KillVerdict, kill_payload,
)
from containment.policy import CapabilityPolicy, CapabilityRequest
from containment.vmspec import HOST_ACTOR_ID, VM_ACTOR_ID
from ames.events import FileOp
from ames.commit import ZERO_DIGEST


def d(b): return bytes([b]) * 32


def sealed(**files):
    b = EnvironmentBaseline()
    for k, v in files.items():
        b.add(k.replace("__", "/"), d(v))
    b.seal()
    return b


# ---------------------------------------------------------------------------
# Absolute rules: one occurrence is proof
# ---------------------------------------------------------------------------

def test_clean_run_is_not_killed():
    assert not KillSwitch().evaluate(Evidence()).kill


@pytest.mark.parametrize("evidence,reason", [
    (Evidence(containment_failed=True), KillReason.CONTAINMENT_FAILURE),
    (Evidence(privilege_escalation_granted=True), KillReason.PRIVILEGE_ESCALATION),
    (Evidence(fatal_gate1_codes=("UNATTRIBUTED_ACTION",)), KillReason.UNATTRIBUTED_ACTION),
    (Evidence(dormant_actors=1), KillReason.DORMANT_PROCESS),
])
def test_absolute_rules_fire_on_a_single_occurrence(evidence, reason):
    """No threshold to pace under, no window to wait out."""
    v = KillSwitch().evaluate(evidence)
    assert v.kill and reason in v.reasons and v.absolute


def test_containment_failure_is_absolute_not_scored():
    """A write to a read-only region is not 'a lot of risk'. It is an invariant
    that did not hold."""
    v = KillSwitch().evaluate(Evidence(containment_failed=True))
    assert KillReason.CONTAINMENT_FAILURE in ABSOLUTE_REASONS
    assert v.absolute


def test_multiple_reasons_accumulate_in_one_verdict():
    v = KillSwitch().evaluate(Evidence(
        containment_failed=True, dormant_actors=2,
        fatal_gate1_codes=("ORPHAN_SPAWN",)))
    assert len(v.reasons) == 3


# ---------------------------------------------------------------------------
# The pacing evasion the original flat-threshold design invited
# ---------------------------------------------------------------------------

def test_patient_mutation_probing_still_trips():
    """An adversary who can read the rules paces one event under every burst
    limit. The EWMA is what makes that fail."""
    k = KillSwitch(mutation_burst=1000, mutation_window_s=1e-9,
                   mutation_ewma_threshold=0.30)
    v = None
    for _ in range(40):
        v = k.evaluate(Evidence(unexplained_mutations=1))
    assert KillReason.MUTATION_SUSTAINED in v.reasons
    assert KillReason.MUTATION_BURST not in v.reasons, "should not look like a burst"


def test_mutation_burst_trips_immediately():
    k = KillSwitch(mutation_burst=3)
    v = k.evaluate(Evidence(unexplained_mutations=3))
    assert KillReason.MUTATION_BURST in v.reasons


def test_denial_signal_from_l2_is_honoured():
    t = DenialTracker(burst_threshold=3)
    sig = None
    for i in range(3):
        sig = t.record(denied=True, now=float(i))
    v = KillSwitch().evaluate(Evidence(denial_signal=sig))
    assert KillReason.DENIAL_BURST in v.reasons


def test_a_single_unexplained_mutation_does_not_kill():
    """Accumulating rules must actually accumulate, or they are absolute rules
    with extra words."""
    assert not KillSwitch(mutation_burst=5, mutation_ewma_threshold=0.9).evaluate(
        Evidence(unexplained_mutations=1)).kill


# ---------------------------------------------------------------------------
# The guest must be unable to cause OR prevent a kill
# ---------------------------------------------------------------------------

def ev(etype, seq, actor, payload=b""):
    return Event(etype, seq, 1000 + seq, actor, NO_PARENT, payload)


def test_guest_claims_cannot_trigger_a_kill():
    """Otherwise a compromised guest fabricates claims and denies service to the
    operator by killing legitimate runs."""
    guest_priv = ev(EventType.CAPABILITY_REQUEST, 0, 0x1000,
                    payload_capability_request(Capability.PRIVILEGE_RAISE, True, "granted"))
    e = Evidence.from_run(ledger_events=[guest_priv])
    assert not e.privilege_escalation_granted
    assert e.guest_claims_seen == 1
    assert not KillSwitch().evaluate(e).kill


def test_the_same_claim_from_the_host_does_trigger_a_kill():
    """Proves the filter is provenance, not content."""
    host_priv = ev(EventType.CAPABILITY_REQUEST, 0, HOST_ACTOR_ID,
                   payload_capability_request(Capability.PRIVILEGE_RAISE, True, "granted"))
    e = Evidence.from_run(ledger_events=[host_priv])
    assert e.privilege_escalation_granted
    assert KillReason.PRIVILEGE_ESCALATION in KillSwitch().evaluate(e).reasons


def test_guest_flooding_cannot_suppress_a_kill():
    """Padding the log with benign claims must not dilute host evidence."""
    events = [ev(EventType.TOOL_CALL, i, 0x1000 + i) for i in range(5000)]
    events.append(ev(EventType.CAPABILITY_REQUEST, 5000, HOST_ACTOR_ID,
                     payload_capability_request(Capability.PRIVILEGE_RAISE, True, "x")))
    e = Evidence.from_run(ledger_events=events)
    assert e.guest_claims_seen == 5000
    assert KillSwitch().evaluate(e).kill


def test_vm_actor_counts_as_host_observed():
    """The microVM's lifecycle is observed by the host, not claimed by the guest."""
    e = Evidence.from_run(ledger_events=[
        ev(EventType.CAPABILITY_REQUEST, 0, VM_ACTOR_ID,
           payload_capability_request(Capability.PRIVILEGE_RAISE, True, "x"))])
    assert e.privilege_escalation_granted


def test_guest_claim_count_is_recorded_but_never_evaluated():
    a = KillSwitch().evaluate(Evidence(guest_claims_seen=0))
    b = KillSwitch().evaluate(Evidence(guest_claims_seen=10**6))
    assert a.kill == b.kill == False


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

class ExplodingEvidence:
    """Stands in for evidence whose source has failed -- e.g. the L7 monitor
    became unreachable mid-run.

    Deliberately NOT an Evidence subclass: Evidence is a frozen dataclass, so a
    subclass cannot shadow a field with a raising property. That freezing is
    itself the point -- evidence cannot be mutated after construction, including
    by a test.
    """
    @property
    def containment_failed(self):
        raise RuntimeError("monitor unavailable")


def test_evaluator_failure_kills_rather_than_passes():
    """An exception in the safety system must never mean 'carry on'. That is how
    a monitoring bug becomes a containment bypass."""
    v = KillSwitch().evaluate(ExplodingEvidence())
    assert v.kill
    assert KillReason.EVALUATOR_FAILURE in v.reasons
    assert "failing closed" in v.detail


# ---------------------------------------------------------------------------
# No escape hatches
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "disable", "override", "reset", "clear", "set_threshold", "add_rule",
    "remove_rule", "bypass", "allow", "acknowledge",
])
def test_kill_switch_exposes_no_escape_hatch(name):
    """An adversary who can add a rule can add one that never fires."""
    assert not hasattr(KillSwitch(), name)


def test_a_trip_is_never_reconsidered():
    """'It stopped happening' is exactly what a successful attacker produces."""
    k = KillSwitch()
    k.evaluate(Evidence(containment_failed=True))
    assert k.tripped
    k.evaluate(Evidence())          # clean evidence afterwards
    assert k.tripped, "a kill must not be undone by later quiet"


def test_verdict_is_frozen():
    v = KillSwitch().evaluate(Evidence(containment_failed=True))
    with pytest.raises(Exception):
        v.kill = False


def test_evidence_is_frozen():
    e = Evidence()
    with pytest.raises(Exception):
        e.containment_failed = True


# ---------------------------------------------------------------------------
# Integration with the layers below
# ---------------------------------------------------------------------------

def test_l7_containment_failure_flows_through_to_a_kill():
    m = EnvironmentMonitor(sealed(__rootfs__libc=1))
    m.observe(MutationObservation("/rootfs/libc", FileOp.WRITE, d(1), d(2), 1, 100))
    e = Evidence.from_run(monitor=m)
    v = KillSwitch().evaluate(e)
    assert v.kill and KillReason.CONTAINMENT_FAILURE in v.reasons


def test_l7_unexplained_mutations_flow_through_as_accumulating():
    m = EnvironmentMonitor(sealed(__workspace__a=1, __workspace__b=1, __workspace__c=1))
    for p, i in (("a", 1), ("b", 2), ("c", 3)):
        m.observe(MutationObservation(f"/workspace/{p}", FileOp.WRITE, d(i), d(i + 10), i, 100),
                  granted_write_paths=frozenset())
    e = Evidence.from_run(monitor=m)
    assert e.unexplained_mutations == 3
    assert not e.containment_failed
    assert KillSwitch(mutation_burst=3).evaluate(e).kill


def test_l2_granted_privilege_escalation_flows_through():
    """L2 lists PRIVILEGE_RAISE as never grantable, so a granted one means the
    policy engine was bypassed or replaced -- itself the emergency."""
    class FakeVerdict:  granted = True
    class FakeReq:      capability = Capability.PRIVILEGE_RAISE
    class FakeDecision: request, verdict = FakeReq(), FakeVerdict()

    e = Evidence.from_run(broker_history=[FakeDecision()])
    assert KillReason.PRIVILEGE_ESCALATION in KillSwitch().evaluate(e).reasons


def test_real_broker_never_produces_that_condition():
    """The corollary: with L2 intact, the trigger above is unreachable."""
    b = Broker(CapabilityPolicy())
    for _ in range(50):
        b.request(CapabilityRequest(Capability.PRIVILEGE_RAISE, "root"))
    e = Evidence.from_run(broker_history=b.history)
    assert not e.privilege_escalation_granted


def test_gate1_dormant_process_is_separated_from_lineage_breaks():
    e = Evidence.from_run(gate1_violation_codes=["UNTERMINATED_ACTOR"])
    assert e.dormant_actors == 1 and e.fatal_gate1_codes == ()
    assert KillReason.DORMANT_PROCESS in KillSwitch().evaluate(e).reasons


def test_non_fatal_gate1_codes_do_not_kill():
    """SEQ_GAP and TIME_REGRESSION are recorded by L8 but are not, alone,
    evidence that attribution is broken."""
    e = Evidence.from_run(gate1_violation_codes=["SEQ_GAP", "TIME_REGRESSION"])
    assert not KillSwitch().evaluate(e).kill


def test_kill_is_recordable_as_a_host_observed_event():
    v = KillSwitch().evaluate(Evidence(containment_failed=True))
    payload = kill_payload(v)
    assert payload[1] == 0, "a kill records granted=0"
    assert b"KILL[" in payload


def test_verdict_is_deterministic_for_identical_evidence():
    e = Evidence(containment_failed=True, dormant_actors=1)
    first = KillSwitch().evaluate(e)
    for _ in range(20):
        v = KillSwitch().evaluate(e)
        assert v.reasons == first.reasons and v.kill == first.kill
