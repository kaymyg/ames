"""
L1 host-side supervisor.

Runs one contained execution and records it into an AMES ledger. The supervisor
is the AMES producer, and it runs on the HOST, outside the VM boundary.

Why that placement is the whole design:

The July 2026 escape compromised a component that lived inside the isolation
perimeter -- a package-registry proxy trusted to bridge in and out. Anything
inside the perimeter is in the adversary's blast radius. A ledger writer running
in the guest would be corrupted by precisely the attack it exists to record, and
its log would be worth nothing at exactly the moment it mattered.

So the trust split is explicit and enforced structurally:

  HOST-OBSERVED  actor_id == HOST_ACTOR_ID
                 VM lifecycle, image measurements, resource caps, exit status.
                 The guest cannot fabricate these; it never writes to the ledger.

  GUEST-REPORTED actor_id assigned by the supervisor, always != HOST_ACTOR_ID
                 Claims submitted over vsock. Recorded faithfully, trusted no
                 further than the guest is. A compromised guest can omit or
                 fabricate these at will.

An analyst reading the ledger can therefore always tell which statements are
evidence and which are merely testimony.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from ames.canonical import (
    payload_capability_request, payload_process_exit, payload_process_spawn,
)
from ames.events import Capability, Event, EventType, NO_PARENT
from ames.ledger import Ledger, Checkpoint
from containment.backend import VmBackend, VmResult, VmState, build_firecracker_config
from containment.vmspec import (
    HOST_ACTOR_ID, HOST_ACTOR_RANGE_START, VM_ACTOR_ID,
    IsolationPolicy, PolicyViolation, VmSpec, is_host_observed,
)

# Guest-reported events are attributed to actor ids starting here. Well below
# HOST_ACTOR_ID, and the supervisor refuses to emit a guest event at or above it.
GUEST_ACTOR_BASE = 0x1000


@dataclass
class RunReport:
    run_id: str
    result: VmResult
    ledger: Ledger
    checkpoint: Checkpoint
    rootfs_digest: bytes
    kernel_digest: bytes
    host_event_count: int
    guest_event_count: int

    @property
    def clean_exit(self) -> bool:
        return (self.result.state is VmState.EXITED
                and self.result.exit_code == 0
                and not self.result.timed_out)


class Supervisor:
    """Drives one VM run and produces its tamper-evident record."""

    def __init__(self, backend: VmBackend, *, clock: Callable[[], int] = time.time_ns) -> None:
        self.backend = backend
        self._clock = clock
        self._ledger = Ledger()
        self._seq = 0
        self._host_events = 0
        self._guest_events = 0
        self._next_guest_actor = GUEST_ACTOR_BASE

    # --- event emission -----------------------------------------------------

    def _emit_host(self, etype: EventType, payload: bytes = b"",
                   actor: int = HOST_ACTOR_ID, parent: int = NO_PARENT) -> None:
        self._ledger.append(Event(etype, self._seq, self._clock(), actor, parent, payload))
        self._seq += 1
        self._host_events += 1

    def emit_host_event(self, etype: EventType, payload: bytes = b"") -> None:
        """Public seam for another HOST-side component to record its own
        observations into this run's ledger, attributed to `HOST_ACTOR_ID`.

        L2's broker is the first real user: `Broker(emit=supervisor.emit_host_event)`
        lets a broker decision made during this run land in the same
        sequence-numbered stream L1 and L8 already produce, instead of living
        in a separate, uncorrelated log. This is deliberately a thin wrapper
        around `_emit_host` with no new behaviour -- the broker is host-side
        code making a host-side observation, exactly like the measurement and
        lifecycle events the supervisor already emits, so it gets no special
        case."""
        self._emit_host(etype, payload)

    def record_guest_claim(self, etype: EventType, payload: bytes = b"",
                           actor: Optional[int] = None) -> int:
        """Record something the guest reported over vsock.

        Returns the actor id used. Refuses to attribute a guest claim to the
        host actor -- that separation is what makes provenance meaningful, so it
        is enforced here rather than left to caller discipline.
        """
        if actor is None:
            actor = self._next_guest_actor
            self._next_guest_actor += 1
        if is_host_observed(actor):
            raise PolicyViolation(
                f"guest actor id {actor:#x} collides with the reserved host range; "
                f"a guest claim must never be recorded as a host observation"
            )
        self._ledger.append(Event(etype, self._seq, self._clock(), actor, NO_PARENT, payload))
        self._seq += 1
        self._guest_events += 1
        return actor

    # --- lifecycle ----------------------------------------------------------

    def run(self, spec: VmSpec, config_dir: Optional[Path] = None) -> RunReport:
        """Validate, measure, boot, wait, destroy -- recording throughout.

        destroy() runs in a finally block. Every failure path leads through it,
        because a supervisor that leaks a live VM on an error path has failed at
        the one job that matters.
        """
        IsolationPolicy.validate(spec)          # raises before anything is created

        self._emit_host(EventType.RUN_BEGIN)

        # The supervisor is the root process of the run, and the microVM is its
        # child. Modelling it this way is not bookkeeping: it makes Gate 1's
        # lineage balance meaningful across the whole run, so a VM that is never
        # torn down shows up as an UNTERMINATED_ACTOR rather than as nothing.
        self._emit_host(EventType.PROCESS_SPAWN,
                        payload=payload_process_spawn(b"\x00" * 32, b"\x00" * 32, "/"),
                        actor=HOST_ACTOR_ID, parent=NO_PARENT)

        rootfs_digest = b""
        kernel_digest = b""
        result = VmResult(VmState.CREATED, None, False, "did not start")
        vm_spawned = False

        try:
            # Measure BEFORE boot. Measuring afterwards would let a running
            # guest influence what gets recorded as its own provenance.
            kernel_digest = self.backend.measure_image(spec.kernel_image)
            rootfs_digest = self.backend.measure_image(spec.rootfs.path)
            self._emit_host(
                EventType.FILE_MUTATION,
                payload=_measurement_payload(spec, kernel_digest, rootfs_digest),
            )

            self.backend.prepare_overlay(spec.rootfs.path, spec.overlay.path, 512)

            cfg_path = (config_dir or Path("/tmp")) / f"fc-{spec.run_id}.json"
            if config_dir is not None:
                import json
                cfg_path.write_text(json.dumps(build_firecracker_config(spec), indent=2))

            self._emit_host(
                EventType.PROCESS_SPAWN,
                payload=payload_process_spawn(kernel_digest, rootfs_digest, "/"),
                actor=VM_ACTOR_ID, parent=HOST_ACTOR_ID,
            )
            vm_spawned = True
            self.backend.boot(spec, cfg_path)

            result = self.backend.wait(spec)

        finally:
            # Unconditional. Never raises: destroy() is contractually total.
            self.backend.destroy(spec)

            code = result.exit_code if result.exit_code is not None else -1
            if vm_spawned:
                self._emit_host(EventType.PROCESS_EXIT,
                                payload=payload_process_exit(code),
                                actor=VM_ACTOR_ID, parent=HOST_ACTOR_ID)

            if result.timed_out:
                # A timeout is a containment action, not a mishap: record it as a
                # denied capability so L9 can count it like any other refusal.
                self._emit_host(
                    EventType.CAPABILITY_REQUEST,
                    payload=payload_capability_request(
                        Capability.PROCESS_SPAWN, False,
                        f"killed: exceeded timeout_seconds={spec.timeout_seconds}",
                    ),
                )

            self._emit_host(EventType.PROCESS_EXIT,
                            payload=payload_process_exit(0), actor=HOST_ACTOR_ID)
            self._emit_host(EventType.RUN_END)
            self._ledger.seal_block(self._clock())

        return RunReport(
            run_id=spec.run_id,
            result=result,
            ledger=self._ledger,
            checkpoint=self._ledger.checkpoint(),
            rootfs_digest=rootfs_digest,
            kernel_digest=kernel_digest,
            host_event_count=self._host_events,
            guest_event_count=self._guest_events,
        )


def _measurement_payload(spec: VmSpec, kernel_digest: bytes, rootfs_digest: bytes) -> bytes:
    """Binds the run to the exact images it booted. If either image differs from
    the approved build, the recorded digest proves it after the fact."""
    from ames.canonical import FileOp, payload_file_mutation
    return payload_file_mutation(FileOp.CREATE, f"vm://{spec.run_id}/images",
                                 kernel_digest, rootfs_digest)
