"""
L2 -- Zero External Trust: the capability policy engine.

A broker is precisely what failed in July 2026. The package-registry cache proxy
WAS a broker: the agent asked it for packages, and it fetched them. So a design
that just says "add a broker" has rebuilt the hole with better documentation.

Three properties separate this from that proxy. Each is enforced in code below,
not merely intended.

1. THE BROKER IS NOT A NETWORK PATH.
   The proxy spoke HTTP on the agent's behalf, so the agent had a live, stateful
   channel to the outside and only needed one bug in it. Here a request is a
   structured record submitted over the L1 vsock channel; there is no transport
   the agent can drive, no connection it can hold open, no protocol it can
   confuse. The agent cannot address the outside world at all -- it can only
   cause a row to be written.

2. FULFILMENT THAT ADDS CODE HAPPENS BETWEEN RUNS, NEVER DURING ONE.
   This is the property the proxy lacked and the reason it was fatal. If the
   broker resolved "install numpy" while the VM was running, it would be
   streaming new executable code into a live adversarial environment -- the
   proxy's exact function. So PACKAGE_INSTALL is never granted in-run. It is
   recorded as DEFER_TO_REBUILD: the run continues without it or fails, and a
   human rebuilds the measured rootfs (L1) before the next run. Inconvenient by
   design; the convenience is what was exploited.

3. EVALUATION IS PURE AND STATIC.
   No DNS, no reputation lookups, no registry queries during a decision --
   those are themselves egress, and an adversary who can influence what the
   policy engine fetches can influence its verdict. The policy is a frozen data
   structure. Deciding cannot touch the network or the filesystem.

Default is DENY. An unknown capability is not an unhandled case, it is a refusal.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, Optional, Tuple

from ames.events import Capability


class Decision(enum.Enum):
    ALLOW             = "allow"
    DENY              = "deny"
    DEFER_TO_REBUILD  = "defer_to_rebuild"   # legitimate, but not while a VM is live


@dataclass(frozen=True)
class PinnedPackage:
    """A dependency approved for the NEXT image build.

    Version alone is not enough. `numpy==2.3.1` names a version, not an artifact:
    a compromised or re-uploaded index entry still satisfies it. The digest is
    what actually binds the approval to specific bytes, and it is what L1's
    rootfs measurement can be checked against afterwards.
    """
    name: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z0-9]([a-z0-9._-]*[a-z0-9])?", self.name):
            raise ValueError(f"invalid package name: {self.name!r}")
        if not re.fullmatch(r"[0-9][0-9a-zA-Z.\-+]*", self.version):
            raise ValueError(f"invalid version: {self.version!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValueError("sha256 must be 64 lowercase hex chars")


@dataclass(frozen=True)
class CapabilityRequest:
    """What the agent asked for.

    `justification` is recorded verbatim and NEVER consulted when deciding. An
    agent-authored string that can move a policy verdict is prompt injection with
    extra steps -- the model would simply learn which words unlock which
    capability. It exists for the audit trail and for humans, nothing else.
    """
    capability: Capability
    resource: str
    justification: str = ""

    MAX_RESOURCE = 512
    MAX_JUSTIFICATION = 4096

    def __post_init__(self) -> None:
        if len(self.resource) > self.MAX_RESOURCE:
            raise ValueError("resource string too long")
        if len(self.justification) > self.MAX_JUSTIFICATION:
            raise ValueError("justification too long")
        if "\x00" in self.resource:
            raise ValueError("NUL byte in resource")


@dataclass(frozen=True)
class PolicyVerdict:
    decision: Decision
    reason: str

    @property
    def granted(self) -> bool:
        return self.decision is Decision.ALLOW


# Capabilities that are NEVER granted inside a run, under any policy. Not a
# default -- a constant. L1 removes the network device entirely, so granting
# NET_EGRESS would be incoherent as well as unsafe; the other two are direct
# escape primitives.
NEVER_IN_RUN: FrozenSet[Capability] = frozenset({
    Capability.NET_EGRESS,
    Capability.RAW_SYSCALL,
    Capability.PRIVILEGE_RAISE,
})

# Legitimate but only satisfiable by rebuilding the measured image between runs.
DEFERRED: FrozenSet[Capability] = frozenset({
    Capability.PACKAGE_INSTALL,
})


@dataclass(frozen=True)
class CapabilityPolicy:
    """Frozen policy. Evaluation performs no I/O of any kind."""

    # Exact strings, never globs or regexes. A pattern like `numpy*` also admits
    # `numpy-evil`, and a regex adds a ReDoS surface reachable by agent input.
    allowed_read_paths: FrozenSet[str] = frozenset()
    allowed_write_paths: FrozenSet[str] = frozenset()
    approved_packages: Tuple[PinnedPackage, ...] = ()
    # Defaults to False. An earlier revision defaulted this to True while the
    # docstring claimed the baseline granted nothing -- the two disagreed, and
    # the test suite caught it. Default-deny has to hold for every capability or
    # it is a slogan rather than a property.
    allow_process_spawn: bool = False
    max_spawn_depth: int = 4

    def evaluate(self, request: CapabilityRequest) -> PolicyVerdict:
        """Total, deterministic, side-effect free. Same input, same verdict,
        on any host, at any time, with the network unplugged."""
        cap = request.capability

        if cap in NEVER_IN_RUN:
            return PolicyVerdict(
                Decision.DENY,
                f"{cap.name} is never granted in-run. The July 2026 escape used a "
                f"runtime egress path that existed for convenience.",
            )

        if cap in DEFERRED:
            pkg = self._match_package(request.resource)
            if pkg is None:
                return PolicyVerdict(
                    Decision.DENY,
                    f"{request.resource!r} is not in the pinned allowlist. Approval "
                    f"requires a name, version and sha256 reviewed by a human.",
                )
            return PolicyVerdict(
                Decision.DEFER_TO_REBUILD,
                f"{pkg.name}=={pkg.version} is approved, but code is never added to a "
                f"live VM. Rebuild the measured rootfs, then re-run.",
            )

        if cap is Capability.FILE_WRITE:
            if request.resource in self.allowed_write_paths:
                return PolicyVerdict(Decision.ALLOW, "path is on the write allowlist")
            return PolicyVerdict(Decision.DENY, f"{request.resource!r} is not writable")

        if cap is Capability.PROCESS_SPAWN:
            if self.allow_process_spawn:
                return PolicyVerdict(Decision.ALLOW, "process spawn permitted by policy")
            return PolicyVerdict(Decision.DENY, "process spawn disabled by policy")

        # Unreached for known capabilities; reached for anything added to the
        # enum later without a corresponding rule. A new capability must be
        # explicitly permitted, never implicitly inherited.
        return PolicyVerdict(
            Decision.DENY,
            f"{cap.name} has no rule in this policy; default is deny",
        )

    def _match_package(self, resource: str) -> Optional[PinnedPackage]:
        """Exact `name==version` match. No ranges, no wildcards, no resolution.

        Splitting on '==' and comparing exactly also refuses the injection shapes
        an agent would try -- 'numpy==2.3.1; curl evil' simply fails to match any
        pinned entry, because nothing is ever passed to a shell or a resolver.
        """
        if resource.count("==") != 1:
            return None
        name, _, version = resource.partition("==")
        for pkg in self.approved_packages:
            if pkg.name == name and pkg.version == version:
                return pkg
        return None


def default_policy() -> CapabilityPolicy:
    """The safe baseline: nothing readable, nothing writable, nothing approved.

    A policy object that is useful out of the box would be a policy that grants
    something nobody chose to grant.
    """
    return CapabilityPolicy()
