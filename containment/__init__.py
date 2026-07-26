"""Containment layers L1-L9: physical isolation, zero external trust, binary
verification and spawn authorization, behavioural fingerprinting, cognitive
drift detection, environment mutation detection, and the autonomous kill
system -- all producing or consuming AMES (L8) events. Every layer but L6
reads only host-observed events; L6 is the deliberate, documented exception.
See docs/l3_l4_audit.md for exactly which parts of L3/L4 are enforced here
versus which need kernel-side enforcement in the guest image."""
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
from containment.fingerprint import (
    BehaviorFingerprint, BehaviorObservation, SequenceVerdict, FingerprintError,
    observations_from_ledger,
)
from containment.drift import (
    DriftMonitor, DriftFinding, DriftReason, narrative_from_ledger,
)
from containment.identity import (
    BinaryPolicy, SpawnAuthorizer, SpawnVerdict, SpawnDenial, IdentityError,
    binary_hash_from_spawn_payload,
)
from containment.runtime import (
    Runtime, RuntimeConfig, ContainmentReport, RunContext,
    Verdict, ALLOWED, KILLED, FAILED,
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
    "BehaviorFingerprint", "BehaviorObservation", "SequenceVerdict",
    "FingerprintError", "observations_from_ledger",
    "DriftMonitor", "DriftFinding", "DriftReason", "narrative_from_ledger",
    "BinaryPolicy", "SpawnAuthorizer", "SpawnVerdict", "SpawnDenial",
    "IdentityError", "binary_hash_from_spawn_payload",
    "Runtime", "RuntimeConfig", "ContainmentReport", "RunContext",
    "Verdict", "ALLOWED", "KILLED", "FAILED",
]
