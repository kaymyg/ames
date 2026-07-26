#!/usr/bin/env python3
"""
Worked example: run an agent under full L1-L9 containment.

    python examples/run_contained_agent.py

Uses `FakeBackend`, so it runs anywhere -- no KVM, no root, no Firecracker.
Swapping in `FirecrackerBackend` is a one-line change (see the bottom of this
file), and is the ONLY line that differs between this demo and a real
deployment. That is the point of the backend interface: the containment logic,
the ledger, and every verdict below are identical either way.

Three runs are shown:

    1. A clean run                  -> ALLOWED
    2. A read-only filesystem breach -> KILLED (absolute)
    3. A concealed narrative         -> ALLOWED, but flagged for review

The third is the interesting one. The guest tells a story that contradicts
what the broker actually recorded -- and the run is still ALLOWED, because
L6 is advisory by construction. That is not a bug being demonstrated; it is
the designed boundary between "evidence that stops a run" and "a signal a
human should look at."
"""

import sys
from pathlib import Path

# Run from anywhere without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ames.canonical import payload_capability_request
from ames.events import Capability, EventType, FileOp
from containment.backend import FakeBackend
from containment.envstate import EnvironmentBaseline, MutationObservation
from containment.identity import BinaryPolicy
from containment.policy import CapabilityPolicy, CapabilityRequest, PinnedPackage
from containment.runtime import Runtime, RuntimeConfig
from containment.vmspec import DiskSpec, VM_ACTOR_ID, VmSpec

SH_DIGEST = bytes([1]) * 32
TAMPERED = bytes([2]) * 32


def build_spec(run_id: str) -> VmSpec:
    """One contained execution.

    Note what cannot be expressed here: there is no network-interface field.
    The absence IS the control -- you cannot misconfigure what the type
    system has no way to say. See docs/l1_isolation.md.
    """
    return VmSpec(
        run_id=run_id,
        kernel_image=Path("/images/vmlinux"),
        rootfs=DiskSpec(Path("/images/base.ext4"), read_only=True),
        overlay=DiskSpec(Path(f"/tmp/{run_id}-overlay.ext4"),
                         read_only=False, is_ephemeral_overlay=True),
        vcpus=2,
        mem_mib=2048,
        timeout_seconds=900,
        vsock_cid=3,
    )


def build_config() -> RuntimeConfig:
    """Everything the operator decides, in one reviewable object.

    Every policy here is sealed before the run. There is deliberately no way
    to widen any of them once execution starts -- an allowlist that can grow
    mid-run is not an allowlist.
    """
    # L3/L4 -- binaries approved at image-build time.
    binaries = BinaryPolicy()
    binaries.approve(SH_DIGEST, label="/bin/sh")
    binaries.seal()

    # L7 -- known-good filesystem state, captured before the agent exists.
    baseline = EnvironmentBaseline()
    baseline.add("/rootfs/bin/sh", SH_DIGEST)
    baseline.seal()

    # L2 -- what the agent may ask for. Default is deny; this grants exactly
    # one writable path and pins one dependency for the NEXT image build.
    capabilities = CapabilityPolicy(
        allowed_write_paths=frozenset({"/workspace/output.txt"}),
        approved_packages=(
            PinnedPackage(name="numpy", version="2.3.1", sha256="a" * 64),
        ),
    )

    return RuntimeConfig(
        capability_policy=capabilities,
        binary_policy=binaries,
        environment_baseline=baseline,
    )


def show(report) -> None:
    print(f"  {report.summary()}")
    print(f"  ledger verifies against its checkpoint: {report.verify()}")
    if report.kill and report.kill.kill:
        print(f"  detail: {report.kill.detail}")
    for finding in report.drift:
        print(f"  [advisory] {finding.capability.name}: {finding.detail}")
    print()


def main() -> None:
    runtime = Runtime(build_config())

    # --- 1. a clean run -----------------------------------------------------
    print("1. Clean run -- the agent asks for one permitted write.")

    def well_behaved(ctx):
        actor = ctx.supervisor.record_guest_claim(EventType.PROCESS_SPAWN, b"")

        decision = ctx.broker.request(CapabilityRequest(
            Capability.FILE_WRITE, "/workspace/output.txt",
            justification="write the result",
        ))

        # The agent's own account of what it just did, matching what the
        # broker actually recorded. An agent that acts through the broker but
        # never narrates is not "clean" -- L6 flags it as UNNARRATED, because
        # silence about a real action is itself a discrepancy worth seeing.
        ctx.supervisor.record_guest_claim(
            EventType.CAPABILITY_REQUEST,
            payload_capability_request(
                Capability.FILE_WRITE, decision.verdict.granted, "wrote the result",
            ),
            actor=actor,
        )

        ctx.supervisor.record_guest_claim(EventType.PROCESS_EXIT, b"", actor=actor)

    show(runtime.execute(build_spec("demo-clean-01"), FakeBackend(),
                         during_run=well_behaved))

    # --- 2. a containment failure ------------------------------------------
    print("2. Read-only breach -- something wrote to the immutable rootfs.")
    print("   This is not 'a lot of risk'. It means an L1 invariant did not")
    print("   hold, so it is an ABSOLUTE kill with no threshold to pace under.")

    def breach(ctx):
        ctx.monitor.observe(MutationObservation(
            path="/rootfs/bin/sh", op=FileOp.WRITE,
            before=SH_DIGEST, after=TAMPERED,
            timestamp_ns=1, actor_id=VM_ACTOR_ID,
        ))

    show(runtime.execute(build_spec("demo-breach-1"), FakeBackend(),
                         during_run=breach))

    # --- 3. a concealed narrative ------------------------------------------
    print("3. Concealed narrative -- the guest claims a grant it never got.")
    print("   Flagged by L6, but the run is still ALLOWED: a signal built")
    print("   from the guest's own testimony must not be able to stop a run,")
    print("   or a compromised guest could deny service by lying.")

    def conceal(ctx):
        actor = ctx.supervisor.record_guest_claim(EventType.PROCESS_SPAWN, b"")
        # Genuinely denied: /etc/passwd is not on the write allowlist.
        ctx.broker.request(CapabilityRequest(Capability.FILE_WRITE, "/etc/passwd"))
        # ...but the guest's own account says it was granted.
        ctx.supervisor.record_guest_claim(
            EventType.CAPABILITY_REQUEST,
            payload_capability_request(Capability.FILE_WRITE, True, "all fine here"),
            actor=actor,
        )
        ctx.supervisor.record_guest_claim(EventType.PROCESS_EXIT, b"", actor=actor)

    show(runtime.execute(build_spec("demo-conceal1"), FakeBackend(),
                         during_run=conceal))

    print("For a real deployment, the only change is the backend:")
    print("    from containment.backend import FirecrackerBackend")
    print("    runtime.execute(spec, FirecrackerBackend())")
    print("which needs /dev/kvm and is not exercised by this repo's tests.")
    print("See docs/l0_validation.md for what that leaves unverified.")


if __name__ == "__main__":
    main()
