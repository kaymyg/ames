"""
L3/L4 -- Binary verification and process spawn authorization.

WHY THIS MODULE EXISTS AT ALL

An audit of the original nine-layer spec against what this repo actually
enforces (see `docs/l3_l4_audit.md`) found that most L3/L4 claims were indeed
already covered by L1's read-only rootfs and L8's Gate 1 lineage balance --
but two were not, and they were the two that matter most:

  L3: "Every binary is cryptographically verified before execution."
  L4: "Every child process must prove: Parent -> Signature -> Spawn token
       -> Allowed. If not: Kill. No exceptions."

Both are PREVENTIVE controls. Everything this repo had before this module is
DETECTIVE: `payload_process_spawn` already carries a `binary_hash`, but
nothing ever compared it to anything; Gate 1 already flags ORPHAN_SPAWN and
DOUBLE_SPAWN, but only after the fact, when the events are verified. Detection
after the fact is worth a great deal -- it is most of what L8 and L9 are for --
but it is not what those two claims say, and quietly treating "we would notice"
as equivalent to "it cannot happen" is exactly the kind of gap this framework's
own premise says to assume an adversary is looking for.

WHAT THIS ACTUALLY BUYS, STATED PRECISELY

`BinaryPolicy` turns the recorded-but-unchecked `binary_hash` into a checked
one against a frozen allowlist captured at image-build time. `SpawnAuthorizer`
requires an unforgeable, single-use, host-issued token for every spawn, bound
to the exact (parent, binary, run) triple it was issued for.

What that does NOT buy, and must not be claimed: this is host-side
authorization, not kernel enforcement. A guest that has already achieved
arbitrary code execution can call `fork()`/`execve()` directly without asking
anyone. The token gates what the HOST will authorize and record as
legitimately parented -- so an unauthorized spawn becomes an unforgeable,
attributable discrepancy rather than an invisible one. Real prevention needs
kernel-side enforcement (an LSM hook, seccomp, or IMA/dm-verity for the binary
half) inside the guest image, which this repo does not build and this sandbox
cannot test. That is stated here, in `docs/l3_l4_audit.md`, and in
`describe_guarantees()` below, rather than left for someone to assume.

Nothing here is a substitute for L1: a binary allowlist matters precisely
because the overlay is writable, and the rootfs being read-only is what makes
the allowlist small and knowable in the first place.
"""

from __future__ import annotations

import enum
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ames.commit import DIGEST_SIZE, Domain, commit
from ames.events import NO_PARENT

# Token size. 32 bytes of CSPRNG output; guessing one is not a threat model
# anyone needs to reason about at this width.
TOKEN_SIZE = 32


class IdentityError(Exception):
    """Malformed input, or an operation attempted out of order (sealing twice,
    verifying against an unsealed policy). Dedicated type so misuse is never
    confused with a genuine authorization failure."""


class SpawnDenial(enum.Enum):
    """Why a spawn was refused. Each is a distinct attack shape, kept separate
    so an incident review can tell them apart rather than reading one generic
    'denied'."""

    UNKNOWN_BINARY   = "unknown_binary"     # hash not on the build-time allowlist
    NO_TOKEN         = "no_token"           # spawn attempted without one
    UNKNOWN_TOKEN    = "unknown_token"      # token never issued by this authorizer
    TOKEN_REPLAY     = "token_replay"       # already consumed; single-use
    PARENT_MISMATCH  = "parent_mismatch"    # token issued for a different parent
    BINARY_MISMATCH  = "binary_mismatch"    # token issued for a different binary
    DEAD_PARENT      = "dead_parent"        # parent not live at spawn time


@dataclass(frozen=True)
class SpawnVerdict:
    allowed: bool
    denial: Optional[SpawnDenial] = None
    detail: str = ""


class BinaryPolicy:
    """Frozen allowlist of binary digests approved at image-build time.

    Sealed before the run, for the same reason L5's fingerprint and L7's
    baseline are: an allowlist an adversary can extend during a run is not an
    allowlist. There is deliberately no `remove`, no `update`, and no way to
    approve a digest after `seal()`.

    Digests here are whatever the image build recorded -- this module does not
    hash files itself. Hashing a file at authorization time would be checking
    the wrong thing anyway (a TOCTOU gap between hash and exec); the binding
    that matters is to the digest the approved BUILD produced, which
    `backend.measure_image` already records for the image as a whole.
    """

    def __init__(self) -> None:
        self._approved: Set[bytes] = set()
        self._labels: Dict[bytes, str] = {}
        self._sealed = False

    def approve(self, digest: bytes, label: str = "") -> None:
        if self._sealed:
            raise IdentityError("policy is sealed; approval happens at image-build time")
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != DIGEST_SIZE:
            raise IdentityError(f"digest must be {DIGEST_SIZE} bytes")
        d = bytes(digest)
        self._approved.add(d)
        if label:
            self._labels[d] = label

    def seal(self) -> None:
        self._sealed = True

    @property
    def sealed(self) -> bool:
        return self._sealed

    def is_approved(self, digest: bytes) -> bool:
        """Constant-time membership over the approved set.

        `hmac.compare_digest` per candidate rather than a plain `in` on a set:
        set membership short-circuits on the first differing byte, which is a
        timing oracle an adversary able to submit candidate digests could walk
        one byte at a time. The set is small (it is one image's binaries), so
        the linear scan costs nothing that matters.
        """
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != DIGEST_SIZE:
            return False
        d = bytes(digest)
        found = False
        for approved in self._approved:
            if hmac.compare_digest(approved, d):
                found = True
        return found

    def label_for(self, digest: bytes) -> str:
        return self._labels.get(bytes(digest), "")

    def __len__(self) -> int:
        return len(self._approved)


@dataclass
class _IssuedToken:
    parent_actor: int
    binary_hash: bytes
    consumed: bool = False


class SpawnAuthorizer:
    """Issues and verifies single-use spawn tokens, host-side.

    The spec's chain is `Parent -> Signature -> Spawn token -> Allowed`. The
    signature step is what this implements as a keyed commitment: the token is
    random, and the AUTHORIZER holds the only record binding it to a specific
    (parent, binary) pair. A guest cannot mint one because it never sees the
    issuing side; it can only present a token it was given.

    Single-use is load-bearing. A reusable token is a persistent capability,
    and persistent capability is precisely what L1 discards the VM to prevent.
    `test_token_cannot_be_replayed` is the test that pins this.
    """

    def __init__(self, run_id: str, policy: BinaryPolicy) -> None:
        if not policy.sealed:
            raise IdentityError("seal the BinaryPolicy before authorizing spawns")
        self.run_id = run_id
        self.policy = policy
        self._issued: Dict[bytes, _IssuedToken] = {}
        self._live_actors: Set[int] = set()
        self.denials: List[SpawnVerdict] = []

    # --- lineage tracking ---------------------------------------------------

    def register_root(self, actor_id: int) -> None:
        """Mark an actor live without requiring a token -- the supervisor and
        the VM itself, which exist before any spawn can be authorized. Kept
        explicit rather than implicit so that the set of actors exempt from
        token checks is a short, greppable list rather than an emergent
        property of call order."""
        self._live_actors.add(actor_id)

    def note_exit(self, actor_id: int) -> None:
        self._live_actors.discard(actor_id)

    @property
    def live_actors(self) -> FrozenSet[int]:
        return frozenset(self._live_actors)

    # --- token lifecycle ----------------------------------------------------

    def issue(self, *, parent_actor: int, binary_hash: bytes) -> bytes:
        """Issue a token for one specific (parent, binary) pair.

        Refuses to issue for an unapproved binary: issuing a token that
        `authorize` would then reject is a pointless round-trip that also
        leaks which binaries are approved via a different code path.
        """
        if not self.policy.is_approved(binary_hash):
            raise IdentityError(
                "refusing to issue a spawn token for a binary that is not on the "
                "build-time allowlist"
            )
        if parent_actor not in self._live_actors:
            raise IdentityError(
                f"refusing to issue a token to actor {parent_actor:#x}, which is not live; "
                f"a token issued to a dead parent is a persistence primitive"
            )
        token = secrets.token_bytes(TOKEN_SIZE)
        self._issued[token] = _IssuedToken(parent_actor, bytes(binary_hash))
        return token

    def authorize(self, *, parent_actor: int, child_actor: int,
                  binary_hash: bytes, token: Optional[bytes]) -> SpawnVerdict:
        """The `-> Allowed` step. Total: never raises, always returns a
        verdict, and every denial path records itself for L9 to read.

        Checks are ordered cheapest-and-most-fundamental first, and each is
        distinct rather than collapsed into one boolean, so a denial says
        WHICH property failed."""
        verdict = self._authorize_inner(
            parent_actor=parent_actor, child_actor=child_actor,
            binary_hash=binary_hash, token=token,
        )
        if not verdict.allowed:
            self.denials.append(verdict)
        else:
            self._live_actors.add(child_actor)
        return verdict

    def _authorize_inner(self, *, parent_actor: int, child_actor: int,
                         binary_hash: bytes, token: Optional[bytes]) -> SpawnVerdict:
        if not self.policy.is_approved(binary_hash):
            return SpawnVerdict(
                False, SpawnDenial.UNKNOWN_BINARY,
                "binary hash is not on the build-time allowlist; a binary that was "
                "not in the approved image has no business executing in it",
            )

        if token is None:
            return SpawnVerdict(False, SpawnDenial.NO_TOKEN,
                                "no spawn token presented")

        entry = self._issued.get(bytes(token))
        if entry is None:
            return SpawnVerdict(False, SpawnDenial.UNKNOWN_TOKEN,
                                "token was never issued by this authorizer")

        if entry.consumed:
            return SpawnVerdict(
                False, SpawnDenial.TOKEN_REPLAY,
                "token already consumed; tokens are single-use because a reusable "
                "token is a persistent capability",
            )

        if entry.parent_actor != parent_actor:
            return SpawnVerdict(
                False, SpawnDenial.PARENT_MISMATCH,
                f"token was issued to actor {entry.parent_actor:#x}, presented by "
                f"{parent_actor:#x}; a transferable token is not an identity proof",
            )

        if not hmac.compare_digest(entry.binary_hash, bytes(binary_hash)):
            return SpawnVerdict(
                False, SpawnDenial.BINARY_MISMATCH,
                "token was issued for a different binary; binding the token to the "
                "binary is what stops an approved token launching something else",
            )

        if parent_actor not in self._live_actors:
            return SpawnVerdict(
                False, SpawnDenial.DEAD_PARENT,
                f"parent {parent_actor:#x} is not live; a spawn from an exited "
                f"parent is the shape of a process surviving its own lineage",
            )

        entry.consumed = True
        return SpawnVerdict(True, None, "authorized")

    # --- reporting ----------------------------------------------------------

    @property
    def denial_count(self) -> int:
        return len(self.denials)

    def denials_by(self, reason: SpawnDenial) -> List[SpawnVerdict]:
        return [d for d in self.denials if d.denial is reason]

    @staticmethod
    def describe_guarantees() -> List[str]:
        """Stated in the same shape as `IsolationPolicy.describe_guarantees`,
        so an operator reads both in the same voice and neither overstates."""
        return [
            "GUARANTEED: a spawn the HOST authorizes has a binary on the build-time allowlist.",
            "GUARANTEED: spawn tokens are single-use, and bound to one parent and one binary.",
            "GUARANTEED: a token cannot be transferred to a different parent actor.",
            "GUARANTEED: every denial is recorded with which specific property failed.",
            "NOT GUARANTEED: that the guest cannot call execve() directly. This is "
            "host-side authorization, not kernel enforcement -- an unauthorized spawn "
            "becomes an attributable discrepancy, not an impossibility.",
            "NOT GUARANTEED: pre-execution verification INSIDE the guest. That needs "
            "IMA/dm-verity or an LSM hook in the guest image, which this repo does "
            "not build and this environment cannot test.",
        ]


def binary_hash_from_spawn_payload(payload: bytes) -> Optional[bytes]:
    """Extract `binary_hash` from a canonical PROCESS_SPAWN payload.

    Layout is fixed by `ames.canonical.payload_process_spawn`:
        binary_hash (32) || argv_hash (32) || u32 cwd_len || cwd

    Returns None rather than raising on a short payload, matching how
    `fingerprint.observations_from_ledger` and `transport.GuestEventReader`
    both treat malformed input: one bad record must not abort reconstruction
    of everything around it.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) < DIGEST_SIZE:
        return None
    return bytes(payload[:DIGEST_SIZE])
