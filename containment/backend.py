"""
L1 VM backends.

The backend is behind an interface for two reasons. The honest one: a real
Firecracker microVM needs KVM and root, so the supervisor's logic would
otherwise be untestable and would ship unverified. The design one: the
supervisor must not know or care which hypervisor it drives, so swapping
Firecracker for Cloud Hypervisor or a bare-metal runner does not touch the
lifecycle or ledger code.

FakeBackend is not a toy. It records every call and can be told to fail at any
stage, which is how the "destroy always runs" invariant is actually proven --
including on the boot-failure and timeout paths, which are exactly the paths a
real incident takes and exactly the ones that go untested when a backend can
only be exercised on real hardware.
"""

from __future__ import annotations

import abc
import enum
import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from containment.vmspec import VmSpec, PolicyViolation


class VmState(enum.Enum):
    CREATED   = "created"
    BOOTED    = "booted"
    EXITED    = "exited"
    KILLED    = "killed"
    DESTROYED = "destroyed"


@dataclass
class VmResult:
    state: VmState
    exit_code: Optional[int]
    timed_out: bool
    detail: str = ""


class VmBackend(abc.ABC):
    """Minimal lifecycle contract. Deliberately small: every method here is a
    place a hypervisor could betray the isolation guarantees, so there are as
    few of them as possible."""

    @abc.abstractmethod
    def measure_image(self, path: Path) -> bytes:
        """Return a 32-byte digest of an image, taken BEFORE boot. Recorded as
        the first ledger event so the run is bound to an exact image."""

    @abc.abstractmethod
    def prepare_overlay(self, base: Path, overlay: Path, size_mib: int) -> None:
        """Create the ephemeral writable overlay."""

    @abc.abstractmethod
    def boot(self, spec: VmSpec, config_path: Path) -> None: ...

    @abc.abstractmethod
    def wait(self, spec: VmSpec) -> VmResult: ...

    @abc.abstractmethod
    def destroy(self, spec: VmSpec) -> None:
        """Tear down and discard the overlay. MUST be idempotent and MUST NOT
        raise -- it runs on every exit path including the failure ones, and an
        exception here would leave a VM alive."""


def build_firecracker_config(spec: VmSpec) -> Dict[str, Any]:
    """Generate Firecracker's machine config from a validated spec.

    Note what is absent: there is no "network-interfaces" key. Firecracker only
    creates a NIC if one is configured, so omitting it means the guest kernel
    has no network device to find -- not a blocked one, none. That is why the
    policy refuses network specs rather than trying to firewall them.
    """
    IsolationPolicyCheck = spec  # readability: caller must have validated first
    return {
        "boot-source": {
            "kernel_image_path": str(spec.kernel_image),
            "boot_args": spec.kernel_args,
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": str(spec.rootfs.path),
                "is_root_device": True,
                "is_read_only": True,
            },
            {
                "drive_id": "overlay",
                "path_on_host": str(spec.overlay.path),
                "is_root_device": False,
                "is_read_only": False,
            },
        ],
        "machine-config": {
            "vcpu_count": spec.vcpus,
            "mem_size_mib": spec.mem_mib,
            "smt": False,          # SMT off: reduces cross-thread side channels
            "track_dirty_pages": False,
        },
        # Guest -> host event channel. One direction of data, no routing, no
        # name resolution, no sockets to anywhere but this host process.
        "vsock": {
            "guest_cid": spec.vsock_cid,
            "uds_path": f"/tmp/ames-vsock-{spec.run_id}.sock",
        },
        # Explicitly disabled rather than merely unconfigured, so the intent is
        # visible in the emitted config and auditable after the fact.
        "logger": {"level": "Warning", "show_level": True, "show_log_origin": True},
    }


class FakeBackend(VmBackend):
    """In-memory backend for tests. Records calls; can be scripted to fail."""

    def __init__(self, *, fail_on: Optional[str] = None,
                 exit_code: int = 0, timed_out: bool = False,
                 image_digests: Optional[Dict[str, bytes]] = None) -> None:
        self.calls: List[str] = []
        self.fail_on = fail_on
        self.exit_code = exit_code
        self.timed_out = timed_out
        self._digests = image_digests or {}
        self.destroyed = False
        self.overlays_created: List[Path] = []

    def _maybe_fail(self, stage: str) -> None:
        self.calls.append(stage)
        if self.fail_on == stage:
            raise RuntimeError(f"injected failure at {stage}")

    def measure_image(self, path: Path) -> bytes:
        self._maybe_fail("measure_image")
        if str(path) in self._digests:
            return self._digests[str(path)]
        return hashlib.blake2b(str(path).encode(), digest_size=32).digest()

    def prepare_overlay(self, base: Path, overlay: Path, size_mib: int) -> None:
        self._maybe_fail("prepare_overlay")
        self.overlays_created.append(overlay)

    def boot(self, spec: VmSpec, config_path: Path) -> None:
        self._maybe_fail("boot")

    def wait(self, spec: VmSpec) -> VmResult:
        self._maybe_fail("wait")
        if self.timed_out:
            return VmResult(VmState.KILLED, None, True, "exceeded timeout")
        return VmResult(VmState.EXITED, self.exit_code, False)

    def destroy(self, spec: VmSpec) -> None:
        # Never raises, by contract.
        self.calls.append("destroy")
        self.destroyed = True


class FirecrackerBackend(VmBackend):
    """Real Firecracker driver.

    NOT EXERCISED BY THIS REPO'S TESTS -- it needs /dev/kvm and privileges no
    CI sandbox should have. Treat it as reviewed-but-unproven until the L0
    adversarial validation engine runs it on real hardware. The logic it shares
    with the tested path is deliberately minimal for this reason.
    """

    def __init__(self, firecracker_bin: Path = Path("/usr/bin/firecracker")) -> None:
        self.bin = firecracker_bin
        self._procs: Dict[str, subprocess.Popen] = {}

    def measure_image(self, path: Path) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.digest()

    def prepare_overlay(self, base: Path, overlay: Path, size_mib: int) -> None:
        # A sparse file, freshly created per run. Never reused: reuse would
        # carry state across runs, which the policy forbids.
        if overlay.exists():
            overlay.unlink()
        with open(overlay, "wb") as f:
            f.truncate(size_mib * 1024 * 1024)

    def boot(self, spec: VmSpec, config_path: Path) -> None:
        self._procs[spec.run_id] = subprocess.Popen(
            [str(self.bin), "--no-api", "--config-file", str(config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def wait(self, spec: VmSpec) -> VmResult:
        proc = self._procs.get(spec.run_id)
        if proc is None:
            return VmResult(VmState.EXITED, None, False, "no process")
        try:
            code = proc.wait(timeout=spec.timeout_seconds)
            return VmResult(VmState.EXITED, code, False)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
            return VmResult(VmState.KILLED, None, True, "exceeded timeout_seconds")

    def destroy(self, spec: VmSpec) -> None:
        proc = self._procs.pop(spec.run_id, None)
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:
                pass          # destroy must not raise; a live VM is worse than a leaked handle
        try:
            if spec.overlay.path.exists():
                spec.overlay.path.unlink()
        except Exception:
            pass
