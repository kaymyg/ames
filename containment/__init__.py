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
from containment.policy import (
    CapabilityPolicy, CapabilityRequest, Decision, PolicyVerdict, PinnedPackage,
    default_policy, NEVER_IN_RUN, DEFERRED,
)
from containment.broker import Broker, BrokerDecision, DenialTracker, DenialSignal
from containment.envstate import (
    EnvironmentBaseline, EnvironmentMonitor, MutationObservation, MutationVerdict,
    PathClass, PathPolicy, EnvStateError, normalise,
)
from containment.killswitch import (
    KillSwitch, KillVerdict, KillReason, Evidence, ABSOLUTE_REASONS,
    FATAL_GATE1_CODES, kill_payload,
)
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
    "CapabilityPolicy", "CapabilityRequest", "Decision", "PolicyVerdict",
    "PinnedPackage", "default_policy", "NEVER_IN_RUN", "DEFERRED",
    "Broker", "BrokerDecision", "DenialTracker", "DenialSignal",
    "EnvironmentBaseline", "EnvironmentMonitor", "MutationObservation",
    "MutationVerdict", "PathClass", "PathPolicy", "EnvStateError", "normalise",
    "KillSwitch", "KillVerdict", "KillReason", "Evidence", "ABSOLUTE_REASONS",
    "FATAL_GATE1_CODES", "kill_payload",
]
