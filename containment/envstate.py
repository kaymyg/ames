"""
L7 -- Environment Mutation Detection.

The attack this defends against is slow and patient:

    install a package -> modify a config -> replace an executable -> exploit later

Each step looks unremarkable on its own. Only the sequence is an attack, and only
against a known-good baseline is the sequence visible.

WHAT L7 IS ACTUALLY FOR HERE

In a naive stack this layer catches ordinary drift. In this stack L1 already
makes the rootfs read-only and discards the overlay after every run, so drift of
that kind cannot persist. That makes L7's real job different, and more valuable:

    L7 detects that a layer below has already failed.

A write to a read-only region is not "unexpected configuration change". It is
evidence that the hypervisor, the kernel, or the mount enforcement did not hold.
That is the framework's own premise -- assume every other layer has already
failed -- turned into a tripwire, and it is the reason this layer is not
redundant with L1 rather than a nicer report on the same facts.

WHY NOT HASH EVERYTHING EVERY SECOND

The original design called for hashing the filesystem, memory maps, process
list, kernel state and loaded libraries once a second. That does not survive
contact with a real filesystem: a 100k-file rootfs is tens of gigabytes of reads
per minute, so the monitor becomes the dominant workload and is the first thing
an operator disables under load. A control that gets switched off is worse than
no control, because it is still on the architecture diagram.

So capture is EVENT-DRIVEN (fanotify / eBPF in production), and verification is
INCREMENTAL against a merkle baseline. Full re-verification is a checkpoint
operation, not a polling loop.

VERIFIED HERE: the state model, classification, correlation with L2 grants, and
drift detection, against injected observations.
NOT VERIFIED HERE: the fanotify/eBPF collector itself, which needs kernel
privileges this sandbox does not have. Its output shape is the `MutationObservation`
below, so the collector is a thin adapter -- deliberately, because untested code
should be as small as possible.
"""

from __future__ import annotations

import enum
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from ames.commit import DIGEST_SIZE, Domain, ZERO_DIGEST, commit, merkle_root
from ames.events import Capability, FileOp


class PathClass(enum.Enum):
    """How a path is permitted to change during a run."""

    IMMUTABLE = "immutable"   # rootfs. Any change means containment failed.
    MUTABLE   = "mutable"     # overlay. Changes allowed, but must be explained.
    EPHEMERAL = "ephemeral"   # tmpfs. Changes allowed and not individually tracked.


class MutationVerdict(enum.Enum):
    EXPECTED    = "expected"      # permitted by an L2 grant
    UNEXPLAINED = "unexplained"   # allowed region, but nothing granted it
    IMPOSSIBLE  = "impossible"    # read-only region changed -> a layer below failed


class EnvStateError(Exception):
    """Malformed observation or baseline. Dedicated type so it is never confused
    with an ordinary lookup failure."""


def normalise(path: str) -> str:
    """Canonical absolute path, with traversal resolved BEFORE classification.

    Classification decides whether a write is impossible, so a path that
    classifies differently before and after normalisation is a bypass:
    '/overlay/../rootfs/libc.so' must be judged as '/rootfs/libc.so', not as
    something under the writable overlay.
    """
    if not path or not isinstance(path, str):
        raise EnvStateError("path must be a non-empty string")
    if "\x00" in path:
        raise EnvStateError("NUL byte in path")
    if not path.startswith("/"):
        raise EnvStateError(f"path must be absolute: {path!r}")

    # Collapse leading slashes BEFORE normpath. POSIX leaves exactly two
    # leading slashes implementation-defined and Python preserves them, so
    # '//rootfs/libc.so' would not match the '/rootfs' prefix. That currently
    # fails safe (unknown regions classify as immutable), but it is latent: a
    # policy change that made unknown regions permissive would turn it into a
    # hole. Collapse it here rather than depend on the fail-safe holding.
    path = re.sub(r"^/+", "/", path)

    resolved = posixpath.normpath(path)

    # POSIX resolves a climb above root back to root, so '/../x' becomes '/x'
    # rather than escaping. This guard is therefore unreachable for the absolute
    # paths required above; it is kept as a cheap invariant in case the
    # precondition is ever relaxed.
    if resolved.startswith("/..") or resolved == "..":
        raise EnvStateError(f"path escapes root: {path!r}")
    return resolved


@dataclass(frozen=True)
class PathPolicy:
    """Which prefixes are immutable, mutable or ephemeral.

    Prefix matching here is deliberate and safe in a way that L2's package
    allowlist is not: a filesystem hierarchy IS a prefix tree, and the prefixes
    describe mount points chosen by the operator, not names supplied by the
    agent. The match is still anchored at a directory boundary so that
    '/rootfs-evil' cannot pass as a child of '/rootfs'.
    """
    immutable_prefixes: Tuple[str, ...] = ("/rootfs", "/usr", "/lib", "/bin", "/sbin", "/etc")
    mutable_prefixes:   Tuple[str, ...] = ("/workspace",)
    ephemeral_prefixes: Tuple[str, ...] = ("/tmp", "/run", "/dev/shm")

    def classify(self, path: str) -> PathClass:
        p = normalise(path)
        # Most restrictive wins: if a path is under both an immutable and a
        # mutable prefix through some misconfiguration, treat it as immutable.
        for prefix in self.immutable_prefixes:
            if _under(p, prefix):
                return PathClass.IMMUTABLE
        for prefix in self.mutable_prefixes:
            if _under(p, prefix):
                return PathClass.MUTABLE
        for prefix in self.ephemeral_prefixes:
            if _under(p, prefix):
                return PathClass.EPHEMERAL
        # Unknown region. Default to immutable: an unclassified path that turns
        # out to be writable is a hole, whereas a false alarm is merely noise.
        return PathClass.IMMUTABLE


def _under(path: str, prefix: str) -> bool:
    """True if `path` is `prefix` or sits beneath it, at a directory boundary."""
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


@dataclass(frozen=True)
class MutationObservation:
    """One filesystem change, as reported by the collector.

    `before` and `after` are 32-byte content digests; a 32-zero digest means the
    file did not exist on that side, which is how creation and deletion are
    represented without a separate flag that could disagree with the digests.
    """
    path: str
    op: FileOp
    before: bytes
    after: bytes
    timestamp_ns: int
    actor_id: int

    def __post_init__(self) -> None:
        for name in ("before", "after"):
            v = getattr(self, name)
            if not isinstance(v, (bytes, bytearray)) or len(v) != DIGEST_SIZE:
                raise EnvStateError(f"{name} must be a {DIGEST_SIZE}-byte digest")
        object.__setattr__(self, "path", normalise(self.path))
        if self.before == self.after:
            raise EnvStateError(
                f"{self.path}: before == after is not a mutation; a collector "
                f"reporting no-op changes would let real ones hide in the noise"
            )

    @property
    def is_creation(self) -> bool:
        return self.before == ZERO_DIGEST

    @property
    def is_deletion(self) -> bool:
        return self.after == ZERO_DIGEST


class EnvironmentBaseline:
    """Known-good state, captured before the agent runs.

    Frozen after `seal()`. A baseline that can be updated while the agent is
    running is not a baseline: an adversary that can move the reference can
    make any state look unchanged, which is the failure mode of anomaly
    detectors retrained on live traffic.
    """

    def __init__(self, policy: Optional[PathPolicy] = None) -> None:
        self.policy = policy or PathPolicy()
        self._digests: Dict[str, bytes] = {}
        self._sealed = False

    def add(self, path: str, digest: bytes) -> None:
        if self._sealed:
            raise EnvStateError("baseline is sealed; capture happens before the run")
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != DIGEST_SIZE:
            raise EnvStateError("digest must be 32 bytes")
        self._digests[normalise(path)] = bytes(digest)

    def seal(self) -> bytes:
        self._sealed = True
        return self.root()

    @property
    def sealed(self) -> bool:
        return self._sealed

    def root(self) -> bytes:
        """Merkle root over (path, digest) leaves, sorted by path.

        Sorting is what makes the root a function of the SET of files rather
        than of the order the collector happened to walk them.
        """
        leaves = [
            commit(Domain.MERKLE_LEAF, p.encode("utf-8") + d)
            for p, d in sorted(self._digests.items())
        ]
        return merkle_root(leaves) if leaves else ZERO_DIGEST

    def digest_of(self, path: str) -> Optional[bytes]:
        return self._digests.get(normalise(path))

    def __len__(self) -> int:
        return len(self._digests)


class EnvironmentMonitor:
    """Applies observations to a live view of state and classifies each one.

    Incremental by construction: applying an observation touches one entry.
    The root is recomputed over the current map, which is O(n log n) in the
    number of tracked files -- cheap at event rates, and never a full re-read of
    file CONTENT, which is the expensive part the polling design got wrong.
    """

    def __init__(self, baseline: EnvironmentBaseline) -> None:
        if not baseline.sealed:
            raise EnvStateError("seal the baseline before monitoring")
        self.baseline = baseline
        self.policy = baseline.policy
        self._current: Dict[str, bytes] = dict(baseline._digests)
        self.observations: List[Tuple[MutationObservation, MutationVerdict]] = []

    def observe(self, obs: MutationObservation,
                granted_write_paths: FrozenSet[str] = frozenset()) -> MutationVerdict:
        """Record one mutation and judge it.

        `granted_write_paths` comes from L2: the set of paths the broker actually
        permitted. That join is the point of this layer -- the interesting signal
        is not "a file changed", it is "a file changed and no permitted action
        explains it".
        """
        cls = self.policy.classify(obs.path)

        if cls is PathClass.IMMUTABLE:
            verdict = MutationVerdict.IMPOSSIBLE
        elif cls is PathClass.EPHEMERAL:
            verdict = MutationVerdict.EXPECTED
        else:
            granted = {normalise(p) for p in granted_write_paths}
            verdict = (MutationVerdict.EXPECTED if obs.path in granted
                       else MutationVerdict.UNEXPLAINED)

        if obs.is_deletion:
            self._current.pop(obs.path, None)
        else:
            self._current[obs.path] = obs.after

        self.observations.append((obs, verdict))
        return verdict

    # --- state ---------------------------------------------------------------

    def current_root(self) -> bytes:
        leaves = [
            commit(Domain.MERKLE_LEAF, p.encode("utf-8") + d)
            for p, d in sorted(self._current.items())
        ]
        return merkle_root(leaves) if leaves else ZERO_DIGEST

    @property
    def drifted(self) -> bool:
        return self.current_root() != self.baseline.root()

    def rollback_target(self) -> bytes:
        """The root to restore to. Rollback means discarding the overlay and
        rebooting from the measured image -- L1 already does exactly that, so
        L7's contribution is deciding WHEN, not how."""
        return self.baseline.root()

    # --- reporting -----------------------------------------------------------

    def by_verdict(self, verdict: MutationVerdict) -> List[MutationObservation]:
        return [o for o, v in self.observations if v is verdict]

    @property
    def containment_failed(self) -> bool:
        """True if anything wrote to a read-only region.

        This is not a policy violation to be scored and weighed. It means an
        invariant that L1 enforces structurally did not hold, so the correct
        response is to stop, not to raise the risk number.
        """
        return any(v is MutationVerdict.IMPOSSIBLE for _, v in self.observations)

    def summary(self) -> Dict[str, int]:
        counts = {v.value: 0 for v in MutationVerdict}
        for _, v in self.observations:
            counts[v.value] += 1
        return counts
