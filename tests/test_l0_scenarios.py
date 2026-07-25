"""
L0 -- assertions over the full-stack composed scenarios in
`validation/scenarios.py`.

Every other test file in this repo tests one layer with the layers below it
faked or hand-constructed. These tests are the first ones anywhere in the repo
that drive a real `Supervisor`, `Broker`, and `EnvironmentMonitor` together
through one `Supervisor.run()` call and check the composed `KillSwitch`
verdict -- proving the pieces actually fit, not just that each piece is
correct in isolation.
"""

from containment.drift import DriftReason
from containment.killswitch import KillReason
from validation.scenarios import SCENARIOS, run_all


def test_every_registered_scenario_runs_without_raising():
    """The most basic adversarial-validation property: the composition itself
    does not blow up. A scenario that raises has already failed, regardless
    of what it was trying to prove."""
    results = run_all()
    assert set(results) == set(SCENARIOS)


def test_clean_baseline_run_trips_nothing():
    r = SCENARIOS["clean_baseline_run"]()
    assert r.gate1.ok
    assert not r.kill.kill


def test_read_only_breach_composes_into_an_absolute_kill():
    """Uses a REAL EnvironmentMonitor's verdict, not a hand-set
    `containment_failed=True` -- if L7's classification and L9's absolute-rule
    logic ever disagreed about what counts as a breach, this is where it
    would show up."""
    r = SCENARIOS["read_only_breach_triggers_absolute_kill"]()
    assert r.monitor.containment_failed
    assert r.kill.kill
    assert KillReason.CONTAINMENT_FAILURE in r.kill.reasons
    assert r.kill.absolute


def test_patient_enumeration_kills_via_sustained_not_burst():
    """The 'boil the frog' property, proven against a REAL DenialTracker
    driven by a REAL Broker, not a hand-built DenialSignal."""
    r = SCENARIOS["patient_enumeration_defeats_burst_not_ewma"]()
    assert r.kill.kill
    assert KillReason.DENIAL_SUSTAINED in r.kill.reasons
    assert KillReason.DENIAL_BURST not in r.kill.reasons


def test_well_formed_multi_actor_run_passes_gate1_and_does_not_kill():
    """A real guest actor (spawn -> action -> exit) interleaved with a real
    host-attributed broker decision, inside one real Supervisor.run() call.
    This exact composition is not exercised by any other test in the repo."""
    r = SCENARIOS["well_formed_multi_actor_run_passes_gate1"]()
    assert r.gate1.ok, [str(v) for v in r.gate1.violations]
    assert not r.kill.kill


def test_unattributed_action_after_run_end_is_fatal():
    """Derives FATAL_GATE1_CODES membership from a REAL Gate1Result produced
    by a REAL malformed ledger, rather than L9's own tests, which pass
    `fatal_gate1_codes` as a literal tuple of strings."""
    r = SCENARIOS["unattributed_guest_action_after_run_end_is_fatal"]()
    assert not r.gate1.ok
    codes = {v.code for v in r.gate1.violations}
    assert "UNATTRIBUTED_ACTION" in codes
    assert "NO_RUN_END" in codes
    assert r.kill.kill
    assert KillReason.UNATTRIBUTED_ACTION in r.kill.reasons


def test_concealed_narrative_is_flagged_by_drift_but_cannot_kill():
    """Structural proof, not prose: manufactures a real OUTCOME_MISMATCH (a
    guest narrating a grant for a capability the broker actually denied -- the
    concealment shape multi-agent-mcl models) and asserts the kill verdict is
    identical to the clean baseline despite it. `Evidence.from_run` has no
    parameter that consumes a `DriftFinding`, so this is not a coincidence of
    the scenario -- there is structurally no path from L6 to a kill."""
    r = SCENARIOS["concealed_capability_narrative_flags_drift_but_never_kills"]()
    mismatches = [f for f in r.drift if f.reason is DriftReason.OUTCOME_MISMATCH]
    assert mismatches, "expected at least one OUTCOME_MISMATCH finding"

    baseline = SCENARIOS["clean_baseline_run"]()
    assert r.kill.kill == baseline.kill.kill == False
    assert r.kill.reasons == baseline.kill.reasons == ()


def test_every_scenario_result_is_actually_inspectable():
    """Each ScenarioResult must carry a real Gate1Result and a real
    KillVerdict -- a scenario that forgot to run either check would silently
    prove nothing while still "passing" if nothing downstream asserted on the
    missing piece."""
    for name, result in run_all().items():
        assert result.name == name
        assert result.gate1 is not None, f"{name}: no gate1 result attached"
        assert result.kill is not None, f"{name}: no kill verdict attached"
        assert result.report is not None, f"{name}: no run report attached"
