"""
L1 -- Physical Isolation: VM specification and policy validation.

The single most important lesson from the July 2026 OpenAI incident is encoded
here as a hard invariant.

That escape did not defeat a VM boundary. The sandbox had a deliberate hole in
it: a package-registry cache proxy, present so the contained agent could install
packages. The models found a zero-day in the proxy and walked out through the
one component trusted to bridge inside and outside.

The conclusion is not "write a better proxy". It is that a contained execution
environment MUST NOT have a runtime path to the outside world at all. Packages
are baked into the rootfs image at build time, before the agent exists, and the
image is measured. If the agent needs a package that is not there, the run fails
and a human rebuilds the image. That is inconvenient by design: the convenience
of runtime installation is exactly what was exploited.

`IsolationPolicy.validate()` therefore refuses any spec with a network device.
There is no override, no flag, no "trusted proxy" exemption. A policy with an
escape hatch is the escape hatch.

VERIFIED IN THIS REPO: the policy logic, the config generation, the lifecycle
state machine, and the ledger integration -- all against a fake backend.
NOT VERIFIED HERE: that Firecracker itself isolates correctly. That is an
assumption about the hypervisor, tested by the adversarial validation engine
(L0) on real hardware, not by unit tests.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# Actor ids at or above this point denote HOST-OBSERVED entities. The supervisor
# never assigns an id in this band to a guest-reported event, so provenance is
# unforgeable from inside the VM: the guest never writes to the ledger at all,
# it only submits claims that the host records under a guest-scoped id.
#
# A reserved band rather than a single id, because the host observes more than
# one entity: itself, and each microVM it supervises.
HOST_ACTOR_RANGE_START = 0xFFFFFFFFFFFFFF00
HOST_ACTOR_ID          = 0xFFFFFFFFFFFFFFFE   # the supervisor process
VM_ACTOR_ID            = 0xFFFFFFFFFFFFFFFD   # the microVM, a child of the supervisor


def is_host_observed(actor_id: int) -> bool:
    """True if this actor id denotes something the host saw directly."""
    return actor_id >= HOST_ACTOR_RANGE_START

MAX_RUNTIME_SECONDS = 3600
MAX_VCPUS = 8
MAX_MEM_MIB = 16384


class PolicyViolation(Exception):
    """A spec that would weaken containment. Deliberately a dedicated type: it
    must never be caught by a generic handler that continues anyway."""


@dataclass(frozen=True)
class DiskSpec:
    """A block device attached to the microVM.

    read_only=False is permitted ONLY for the ephemeral overlay, which is
    discarded on destroy. A writable disk that survives the run is persistence,
    and persistence across runs is how an agent accumulates capability.
    """
    path: Path
    read_only: bool
    is_ephemeral_overlay: bool = False

    def __post_init__(self) -> None:
        if not self.read_only and not self.is_ephemeral_overlay:
            raise PolicyViolation(
                f"writable non-ephemeral disk {self.path}: state surviving a run "
                f"is persistence, which defeats the point of a fresh VM"
            )


@dataclass(frozen=True)
class VmSpec:
    """Declarative description of one contained execution.

    Deliberately has NO field for a network interface. The absence is the
    control: you cannot configure what the type system cannot express.
    """
    run_id: str
    kernel_image: Path
    rootfs: DiskSpec
    overlay: DiskSpec
    vcpus: int
    mem_mib: int
    timeout_seconds: int
    vsock_cid: int                       # guest->host event channel only
    kernel_args: str = "console=none reboot=k panic=1 pci=off"

    # Escape hatches that MUST stay off. Present as explicit fields so that
    # enabling one is a visible, reviewable, greppable diff rather than an
    # invisible default.
    allow_host_filesystem_share: bool = False
    allow_network_device: bool = False
    allow_persistent_state: bool = False


_RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{7,63}$")


class IsolationPolicy:
    """Fail-closed validator. Every check answers: could this let an agent
    reach something it should not, or persist beyond its run?"""

    @staticmethod
    def validate(spec: VmSpec) -> None:
        v: List[str] = []

        # --- the invariant the OpenAI incident exists to teach ---------------
        if spec.allow_network_device:
            v.append(
                "NETWORK DEVICE REQUESTED. Refused unconditionally. The July 2026 "
                "escape exited through a package-registry cache proxy that existed "
                "precisely so the sandbox could reach a registry. Bake dependencies "
                "into the rootfs at build time instead."
            )
        if spec.allow_host_filesystem_share:
            v.append(
                "HOST FILESYSTEM SHARE REQUESTED. Refused: a shared mount is a "
                "bidirectional channel and a path to host-side parsers."
            )
        if spec.allow_persistent_state:
            v.append(
                "PERSISTENT STATE REQUESTED. Refused: capability accumulated across "
                "runs is how a patient adversary makes progress."
            )

        # --- identity --------------------------------------------------------
        if not _RUN_ID_RE.match(spec.run_id):
            v.append(f"run_id {spec.run_id!r} must be 8-64 chars of [a-z0-9-]")

        # --- disks -----------------------------------------------------------
        if not spec.rootfs.read_only:
            v.append("rootfs must be read-only; the agent must not mutate its own base image")
        if spec.rootfs.is_ephemeral_overlay:
            v.append("rootfs must not be marked as the ephemeral overlay")
        if not spec.overlay.is_ephemeral_overlay:
            v.append("overlay must be marked ephemeral so destroy() discards it")
        if spec.overlay.read_only:
            v.append("overlay must be writable; it is the only writable surface")
        if spec.rootfs.path == spec.overlay.path:
            v.append("rootfs and overlay must be distinct devices")

        # --- resource bounds -------------------------------------------------
        # Caps are containment, not tidiness: an unbounded run is an unbounded
        # number of escape attempts.
        if not 1 <= spec.vcpus <= MAX_VCPUS:
            v.append(f"vcpus must be 1..{MAX_VCPUS}, got {spec.vcpus}")
        if not 128 <= spec.mem_mib <= MAX_MEM_MIB:
            v.append(f"mem_mib must be 128..{MAX_MEM_MIB}, got {spec.mem_mib}")
        if not 1 <= spec.timeout_seconds <= MAX_RUNTIME_SECONDS:
            v.append(
                f"timeout_seconds must be 1..{MAX_RUNTIME_SECONDS}, got "
                f"{spec.timeout_seconds}. A run with no deadline is a dormant process."
            )

        # --- kernel ----------------------------------------------------------
        for banned, why in (
            ("init=/bin/sh", "drops to a shell, bypassing the supervised entrypoint"),
            ("rw", "requests a writable root"),
            ("single", "single-user mode bypasses the supervised entrypoint"),
        ):
            if re.search(rf"(^|\s){re.escape(banned)}(\s|$)", spec.kernel_args):
                v.append(f"kernel_args contains {banned!r}: {why}")

        if spec.vsock_cid < 3:
            v.append("vsock_cid must be >= 3 (0-2 are reserved by the vsock spec)")

        if v:
            raise PolicyViolation(
                f"VmSpec for run {spec.run_id!r} violates isolation policy:\n  - "
                + "\n  - ".join(v)
            )

    @staticmethod
    def describe_guarantees() -> List[str]:
        """What a validated spec does and does not buy. Stated so an operator
        is not left inferring it."""
        return [
            "GUARANTEED: no network device exists in the guest -- not firewalled, absent.",
            "GUARANTEED: rootfs is read-only; only an ephemeral overlay is writable.",
            "GUARANTEED: the run is bounded in cpu, memory and wall-clock time.",
            "GUARANTEED: no host filesystem is shared into the guest.",
            "GUARANTEED: the overlay is discarded on destroy, so nothing persists.",
            "NOT GUARANTEED: that the hypervisor itself is free of escape bugs.",
            "NOT GUARANTEED: that guest-reported events are complete or truthful.",
            "NOT GUARANTEED: protection against side channels between guest and host.",
        ]
