"""
Adversarial tests for the Runtime -- the composed L1-L9 entrypoint.

Governing question: can a caller, a misconfiguration, or a failing component
produce a run that reports ALLOWED when it should not have?
"""

from pathlib import Path

import pytest

from ames.canonical import payload_capability_request
from ames.events import Capability, EventType, FileOp
from containment.backend import FakeBackend, VmBackend, VmResult, VmState
from containment.envstate import (
    EnvironmentBaseline, MutationObservation,
)
from containment.identity import BinaryPolicy
from containment.killswitch import KillReason
from containment.policy import CapabilityPolicy, CapabilityRequest
from containment.runtime import (
    ALLOWED, FAILED, KILLED, ContainmentReport, Runtime, RuntimeConfig,
    RuntimeError_,
)
from containment.vmspec import DiskSpec, VM_ACTOR_ID, VmSpec

ONE32 = bytes([1]) * 32
TWO32 = bytes([2]) * 32


def spec(**overrides) -> VmSpec:
    base = dict(
        run_id="rt-000001", kernel_image=Path("/k/vmlinux"),
        rootfs=DiskSpec(Path("/i/base.ext4"), read_only=True),
        overlay=DiskSpec(Path("/i/ovl.ext4"), read_only=False, is_ephemeral_overlay=True),
        vcpus=2, mem_mib=2048, timeout_seconds=900, vsock_cid=3,
    )
    base.update(overrides)
    return VmSpec(**base)


def sealed_baseline(path="/rootfs/bin/sh", digest=ONE32) -> EnvironmentBaseline:
    b = EnvironmentBaseline()
    b.add(path, digest)
    b.seal()
    return b


# ---------------------------------------------------------------------------
# The baseline: a clean run is allowed, and independently verifiable
# ---------------------------------------------------------------------------

def test_clean_run_is_allowed():
    """True-negative baseline. If this fails, every KILLED result below is
    meaningless because the runtime would be refusing everything."""
    r = Runtime().execute(spec(), FakeBackend())
    assert r.verdict == ALLOWED
    assert r.allowed
    assert not r.kill.kill
    assert r.gate1.ok


def test_report_is_independently_verifiable():
    """A report a reviewer cannot re-check is a summary, not evidence.
    `verify()` recomputes every commitment from the raw ledger."""
    r = Runtime().execute(spec(), FakeBackend())
    assert r.verify()


def test_tampering_with_the_ledger_breaks_verification():
    """The verification is real, not a stub that returns True."""
    import dataclasses
    r = Runtime().execute(spec(), FakeBackend())
    blk = r.ledger.blocks[0]
    blk.events[2] = dataclasses.replace(blk.events[2], payload=b"rewritten")
    assert not r.verify()


# ---------------------------------------------------------------------------
# An unsafe spec never runs at all
# ---------------------------------------------------------------------------

def test_network_device_spec_is_refused_before_anything_is_created():
    backend = FakeBackend()
    r = Runtime().execute(spec(allow_network_device=True), backend)
    assert r.verdict == FAILED
    assert not r.allowed
    assert "isolation policy" in r.error
    assert backend.calls == [], "nothing may be created for a refused spec"


@pytest.mark.parametrize("bad", [
    dict(allow_network_device=True),
    dict(allow_host_filesystem_share=True),
    dict(allow_persistent_state=True),
])
def test_every_escape_hatch_spec_is_refused(bad):
    r = Runtime().execute(spec(**bad), FakeBackend())
    assert not r.allowed


# ---------------------------------------------------------------------------
# Fail closed
# ---------------------------------------------------------------------------

class ExplodingBackend(FakeBackend):
    def wait(self, spec):
        raise RuntimeError("backend detonated mid-run")


def test_component_exception_fails_closed_to_killed():
    """An exception in the containment system must never read as 'nothing to
    report'. Note it is KILLED, not FAILED: the VM did start, so the
    conservative reading is that something ran uncontained."""
    r = Runtime().execute(spec(), ExplodingBackend())
    assert r.verdict == KILLED
    assert not r.allowed
    assert "failing closed" in r.error


def test_hook_exception_fails_closed():
    def boom(ctx):
        raise ValueError("hook detonated")

    r = Runtime().execute(spec(), FakeBackend(), during_run=boom)
    assert r.verdict == KILLED
    assert not r.allowed


def test_execute_never_raises_even_on_a_garbage_spec():
    r = Runtime().execute("not a spec", FakeBackend())
    assert not r.allowed
    assert r.error


# ---------------------------------------------------------------------------
# A real breach composes into a kill
# ---------------------------------------------------------------------------

def test_read_only_breach_during_the_run_kills():
    """The full path: L7 observes an impossible write -> Evidence.from_run
    picks it up -> KillSwitch fires absolutely -> the runtime reports KILLED."""
    def breach(ctx):
        ctx.monitor.observe(MutationObservation(
            path="/rootfs/bin/sh", op=FileOp.WRITE,
            before=ONE32, after=TWO32, timestamp_ns=1, actor_id=VM_ACTOR_ID,
        ))

    cfg = RuntimeConfig(environment_baseline=sealed_baseline())
    r = Runtime(cfg).execute(spec(), FakeBackend(), during_run=breach)

    assert r.verdict == KILLED
    assert KillReason.CONTAINMENT_FAILURE in r.kill.reasons
    assert r.kill.absolute
    assert r.monitor.containment_failed


def test_denial_burst_during_the_run_kills():
    """A real Broker driven through the runtime's own context, not a
    hand-built DenialSignal."""
    def probe(ctx):
        for _ in range(10):
            ctx.broker.request(CapabilityRequest(Capability.PROCESS_SPAWN, "spawn"))

    r = Runtime().execute(spec(), FakeBackend(), during_run=probe)
    assert r.verdict == KILLED
    assert r.broker.denial_count == 10


# ---------------------------------------------------------------------------
# The structural property: advisory layers cannot reach the verdict
# ---------------------------------------------------------------------------

def test_advisory_findings_never_change_the_verdict():
    """L5/L6 are computed after the kill decision and are not inputs to it.
    This drives a real OUTCOME_MISMATCH (guest narrates a grant the broker
    denied) and asserts the verdict is identical to a clean run's."""
    def conceal(ctx):
        actor = ctx.supervisor.record_guest_claim(EventType.PROCESS_SPAWN, b"")
        ctx.broker.request(CapabilityRequest(Capability.FILE_WRITE, "/workspace/x"))
        ctx.supervisor.record_guest_claim(
            EventType.CAPABILITY_REQUEST,
            payload_capability_request(Capability.FILE_WRITE, True, "narrated"),
            actor=actor,
        )
        ctx.supervisor.record_guest_claim(EventType.PROCESS_EXIT, b"", actor=actor)

    r = Runtime().execute(spec(), FakeBackend(), during_run=conceal)
    clean = Runtime().execute(spec(), FakeBackend())

    assert r.drift, "expected the concealment to be detected"
    assert r.advisory_findings > 0
    assert r.verdict == clean.verdict == ALLOWED
    assert r.kill.reasons == clean.kill.reasons == ()


def test_evidence_has_no_parameter_for_advisory_signals():
    """Structural, not behavioural: there is no wiring to remove because
    there is no parameter to wire. Asserted by inspecting the signature so a
    future refactor that adds one has to consciously break this test."""
    import inspect
    from containment.killswitch import Evidence
    params = set(inspect.signature(Evidence.from_run).parameters)
    assert "drift" not in params
    assert "fingerprint" not in params
    assert "behaviour" not in params


# ---------------------------------------------------------------------------
# Config cannot be used to weaken the system
# ---------------------------------------------------------------------------

def test_config_exposes_no_disable_switches():
    cfg = RuntimeConfig()
    for forbidden in ("disable_killswitch", "disable_gate1", "skip_verification",
                      "enable_network", "bypass", "allow_unsafe"):
        assert not hasattr(cfg, forbidden), f"RuntimeConfig exposes {forbidden}"


def test_unsealed_binary_policy_is_refused_at_config_time():
    p = BinaryPolicy()
    p.approve(ONE32)
    with pytest.raises(RuntimeError_):
        RuntimeConfig(binary_policy=p)


def test_unsealed_baseline_is_refused_at_config_time():
    b = EnvironmentBaseline()
    b.add("/rootfs/x", ONE32)
    with pytest.raises(RuntimeError_):
        RuntimeConfig(environment_baseline=b)


def test_runtime_does_not_share_state_between_runs():
    """Each execute() builds its own broker/monitor/authorizer. Sharing any of
    them would carry state across a run boundary -- the exact thing L1
    destroys the VM to prevent."""
    rt = Runtime()
    a = rt.execute(spec(run_id="rt-aaaaaa1"), FakeBackend())
    b = rt.execute(spec(run_id="rt-bbbbbb2"), FakeBackend())
    assert a.broker is not b.broker
    assert a.ledger is not b.ledger
    assert a.run_id != b.run_id


# ---------------------------------------------------------------------------
# Report completeness
# ---------------------------------------------------------------------------

def test_successful_report_carries_everything_a_review_needs():
    r = Runtime().execute(spec(), FakeBackend())
    assert r.ledger is not None
    assert r.checkpoint is not None
    assert r.gate1 is not None
    assert r.kill is not None
    assert r.broker is not None
    assert r.run_report is not None
    assert r.summary()


def test_authorizer_is_wired_only_when_an_allowlist_is_supplied():
    plain = Runtime().execute(spec(), FakeBackend())
    assert plain.authorizer is None

    p = BinaryPolicy()
    p.approve(ONE32, "sh")
    p.seal()
    withlist = Runtime(RuntimeConfig(binary_policy=p)).execute(spec(), FakeBackend())
    assert withlist.authorizer is not None
    assert VM_ACTOR_ID in withlist.authorizer.live_actors
