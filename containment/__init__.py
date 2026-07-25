"""L1 -- Physical Isolation. Ephemeral microVMs with a host-side AMES producer."""
from containment.vmspec import (
    VmSpec, DiskSpec, IsolationPolicy, PolicyViolation,
    HOST_ACTOR_ID, VM_ACTOR_ID, HOST_ACTOR_RANGE_START, is_host_observed,
)
from containment.backend import (
    VmBackend, FakeBackend, FirecrackerBackend, VmState, VmResult,
    build_firecracker_config,
)
from containment.supervisor import Supervisor, RunReport, GUEST_ACTOR_BASE
from containment.transport import (
    GuestEventReader, GuestClaim, TransportError, TransportLimitExceeded, encode_frame,
)

__all__ = [
    "VmSpec", "DiskSpec", "IsolationPolicy", "PolicyViolation",
    "HOST_ACTOR_ID", "VM_ACTOR_ID", "HOST_ACTOR_RANGE_START", "is_host_observed",
    "VmBackend", "FakeBackend", "FirecrackerBackend", "VmState", "VmResult",
    "build_firecracker_config",
    "Supervisor", "RunReport", "GUEST_ACTOR_BASE",
    "GuestEventReader", "GuestClaim", "TransportError", "TransportLimitExceeded",
    "encode_frame",
]
