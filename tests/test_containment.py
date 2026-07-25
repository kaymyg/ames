"""
Adversarial tests for L1 (physical isolation).

Every test is an attack or an escape-enabling misconfiguration. The question
each one answers: if an operator, or a compromised toolchain, or a well-meaning
convenience patch tried this, would containment silently weaken?
"""

import dataclasses
from pathlib import Path

import pytest

from ames.events import EventType
from ames.gate1 import verify as gate1_verify
from ames.ledger import ChainError
from containment.backend import (
    FakeBackend, VmState, build_firecracker_config,
)
from containment.supervisor import GUEST_ACTOR_BASE, Supervisor
from containment.transport import (
    GuestEventReader, MAX_FRAME_PAYLOAD, TransportLimitExceeded, encode_frame,
)
from containment.vmspec import (
    HOST_ACTOR_ID, VM_ACTOR_ID, DiskSpec, IsolationPolicy, PolicyViolation,
    VmSpec, is_host_observed,
)


def good_spec(**overrides):
    base = dict(
        run_id="run-00000001",
        kernel_image=Path("/k/vmlinux"),
        rootfs=DiskSpec(Path("/i/base.ext4"), read_only=True),
        overlay=DiskSpec(Path("/i/ovl.ext4"), read_only=False, is_ephemeral_overlay=True),
        vcpus=2, mem_mib=2048, timeout_seconds=900, vsock_cid=3,
    )
    base.update(overrides)
    return VmSpec(**base)


# ---------------------------------------------------------------------------
# The invariant the OpenAI incident exists to teach
# ---------------------------------------------------------------------------

def test_network_device_is_refused_unconditionally():
    """The escape used a package-registry proxy that existed to give the sandbox
    network reach. There is no safe version of this."""
    with pytest.raises(PolicyViolation, match="NETWORK DEVICE"):
        IsolationPolicy.validate(good_spec(allow_network_device=True))


def test_generated_config_has_no_network_interface():
    """Firecracker only creates a NIC if configured. Absence, not filtering."""
    cfg = build_firecracker_config(good_spec())
    assert "network-interfaces" not in cfg
    assert not any("net" in k.lower() for k in cfg)


def test_host_filesystem_share_refused():
    with pytest.raises(PolicyViolation, match="HOST FILESYSTEM SHARE"):
        IsolationPolicy.validate(good_spec(allow_host_filesystem_share=True))


def test_persistent_state_refused():
    with pytest.raises(PolicyViolation, match="PERSISTENT STATE"):
        IsolationPolicy.validate(good_spec(allow_persistent_state=True))


# ---------------------------------------------------------------------------
# Disks: no writable persistence, no mutable base image
# ---------------------------------------------------------------------------

def test_writable_non_ephemeral_disk_refused_at_construction():
    with pytest.raises(PolicyViolation, match="persistence"):
        DiskSpec(Path("/i/state.ext4"), read_only=False, is_ephemeral_overlay=False)


def test_writable_rootfs_refused():
    with pytest.raises(PolicyViolation, match="rootfs must be read-only"):
        IsolationPolicy.validate(good_spec(
            rootfs=DiskSpec(Path("/i/base.ext4"), read_only=False, is_ephemeral_overlay=True)))


def test_rootfs_and_overlay_must_differ():
    same = Path("/i/same.ext4")
    with pytest.raises(PolicyViolation, match="distinct"):
        IsolationPolicy.validate(good_spec(
            rootfs=DiskSpec(same, read_only=True),
            overlay=DiskSpec(same, read_only=False, is_ephemeral_overlay=True)))


# ---------------------------------------------------------------------------
# Bounds: an unbounded run is an unbounded number of escape attempts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("vcpus", 0), ("vcpus", 999),
    ("mem_mib", 64), ("mem_mib", 99999),
    ("timeout_seconds", 0), ("timeout_seconds", 999999),
])
def test_resource_bounds_enforced(field, value):
    with pytest.raises(PolicyViolation):
        IsolationPolicy.validate(good_spec(**{field: value}))


@pytest.mark.parametrize("args", [
    "console=none init=/bin/sh",
    "console=none rw",
    "console=none single",
])
def test_dangerous_kernel_args_refused(args):
    with pytest.raises(PolicyViolation, match="kernel_args"):
        IsolationPolicy.validate(good_spec(kernel_args=args))


def test_reserved_vsock_cids_refused():
    with pytest.raises(PolicyViolation, match="vsock_cid"):
        IsolationPolicy.validate(good_spec(vsock_cid=2))


# ---------------------------------------------------------------------------
# Lifecycle: destroy must run on EVERY path
# ---------------------------------------------------------------------------

def test_destroy_runs_on_clean_exit():
    b = FakeBackend()
    Supervisor(b).run(good_spec())
    assert b.destroyed


@pytest.mark.parametrize("stage", ["measure_image", "prepare_overlay", "boot", "wait"])
def test_destroy_runs_even_when_a_stage_fails(stage):
    """A supervisor that leaks a live VM on an error path has failed at the one
    job that matters. These are the paths a real incident takes."""
    b = FakeBackend(fail_on=stage)
    with pytest.raises(RuntimeError, match="injected failure"):
        Supervisor(b).run(good_spec())
    assert b.destroyed, f"VM left alive after failure at {stage}"


def test_invalid_spec_never_reaches_the_backend():
    b = FakeBackend()
    with pytest.raises(PolicyViolation):
        Supervisor(b).run(good_spec(allow_network_device=True))
    assert b.calls == [], "policy must reject before anything is created"


def test_timeout_is_recorded_as_a_denied_capability():
    b = FakeBackend(timed_out=True)
    report = Supervisor(b).run(good_spec())
    assert report.result.timed_out
    assert not report.clean_exit
    kinds = [e.event_type for e in report.ledger.all_events()]
    assert EventType.CAPABILITY_REQUEST in kinds
    assert b.destroyed


# ---------------------------------------------------------------------------
# Provenance: a guest must not be able to forge a host observation
# ---------------------------------------------------------------------------

def test_guest_claim_cannot_use_the_host_actor_id():
    sup = Supervisor(FakeBackend())
    with pytest.raises(PolicyViolation, match="reserved host range"):
        sup.record_guest_claim(EventType.TOOL_CALL, b"", actor=HOST_ACTOR_ID)


def test_guest_claim_cannot_use_the_vm_actor_id():
    sup = Supervisor(FakeBackend())
    with pytest.raises(PolicyViolation, match="reserved host range"):
        sup.record_guest_claim(EventType.TOOL_CALL, b"", actor=VM_ACTOR_ID)


def test_auto_assigned_guest_actors_are_outside_the_host_band():
    sup = Supervisor(FakeBackend())
    for _ in range(50):
        assert not is_host_observed(sup.record_guest_claim(EventType.TOOL_CALL, b""))


def test_host_events_are_distinguishable_in_the_ledger():
    """An analyst must be able to separate evidence from testimony."""
    b = FakeBackend()
    sup = Supervisor(b)
    report = sup.run(good_spec())
    for ev in report.ledger.all_events():
        assert is_host_observed(ev.actor_id), "supervisor emitted a non-host actor"


# ---------------------------------------------------------------------------
# The run record itself must be sound
# ---------------------------------------------------------------------------

def test_run_produces_a_verifiable_ledger():
    report = Supervisor(FakeBackend()).run(good_spec())
    report.ledger.verify_chain(report.checkpoint)


def test_run_record_passes_gate1_lineage():
    report = Supervisor(FakeBackend()).run(good_spec())
    gate1_verify(list(report.ledger.all_events())).raise_if_failed()


def test_images_are_measured_before_boot():
    """Measuring after boot would let a running guest influence its own
    recorded provenance."""
    b = FakeBackend()
    Supervisor(b).run(good_spec())
    assert b.calls.index("measure_image") < b.calls.index("boot")


def test_tampering_with_the_run_record_is_detected():
    report = Supervisor(FakeBackend()).run(good_spec())
    blk = report.ledger.blocks[0]
    blk.events[2] = dataclasses.replace(blk.events[2], payload=b"rewritten")
    with pytest.raises(ChainError):
        report.ledger.verify_chain(report.checkpoint)


# ---------------------------------------------------------------------------
# Transport: the one channel crossing the boundary
# ---------------------------------------------------------------------------

def test_guest_cannot_forge_run_boundary_markers():
    r = GuestEventReader()
    assert r.read(encode_frame(EventType.RUN_BEGIN, b"")) == []
    assert r.read(encode_frame(EventType.RUN_END, b"")) == []


def test_oversized_payload_claim_is_refused_before_allocation():
    import struct
    r = GuestEventReader()
    assert r.read(struct.pack(">BI", int(EventType.TOOL_CALL), 0x0FFFFFFF)) == []
    assert "MAX_FRAME_PAYLOAD" in r.stats.rejections[0]


def test_payload_running_past_end_of_stream_refused():
    import struct
    r = GuestEventReader()
    assert r.read(struct.pack(">BI", int(EventType.TOOL_CALL), 500) + b"short") == []


def test_unknown_event_type_skipped_not_fatal():
    import struct
    r = GuestEventReader()
    stream = struct.pack(">BI", 0x42, 0) + encode_frame(EventType.TOOL_CALL, b"ok")
    assert len(r.read(stream)) == 1        # bad frame skipped, good one kept


def test_event_count_cap_truncates_rather_than_exhausting_host():
    r = GuestEventReader(max_events=10)
    flood = b"".join(encode_frame(EventType.TOOL_CALL, b"x") for _ in range(1000))
    assert len(r.read(flood)) == 10


def test_total_byte_cap_enforced():
    r = GuestEventReader(max_total_bytes=1000)
    flood = b"".join(encode_frame(EventType.TOOL_CALL, b"x" * 500) for _ in range(100))
    assert r.stats.bytes_accepted <= 1000 + 500


def test_rejection_log_is_bounded():
    """Error handling must not itself become a memory-exhaustion primitive."""
    import struct
    r = GuestEventReader()
    r.read(b"".join(struct.pack(">BI", 0x42, 0) for _ in range(5000)))
    assert len(r.stats.rejections) <= 100


def test_encode_frame_refuses_oversized_payload():
    with pytest.raises(TransportLimitExceeded):
        encode_frame(EventType.TOOL_CALL, b"x" * (MAX_FRAME_PAYLOAD + 1))


def test_truncated_trailing_frame_does_not_destroy_the_record():
    """A guest must not be able to erase its own audit trail with one bad byte
    at the end."""
    r = GuestEventReader()
    stream = encode_frame(EventType.TOOL_CALL, b"real") + b"\x05\x00"
    assert len(r.read(stream)) == 1
