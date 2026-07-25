"""
AMES-V1 hash-linked action ledger.

    Block 0 <- Block 1 <- Block 2 <- ...

Each block commits to its predecessor's digest and to a merkle root over the
events it contains. Editing any event changes its block's events_root, which
changes that block's digest, which breaks the prev_hash link of every later
block. Silent modification, reordering and splicing are therefore all detectable
by recomputation alone -- no trusted third party, no signature infrastructure.

What this does NOT solve, stated plainly:

  * TRUNCATION. An attacker with write access to the ledger file can delete the
    tail and present a shorter but internally consistent chain. Hash-linking
    cannot detect the absence of something it never saw. The countermeasure is
    Checkpoint: export the head digest to somewhere the agent cannot reach
    (append-only remote log, HSM, printed, another trust domain). A verifier
    holding a checkpoint at height N can prove the chain is at least N long.

  * A COMPROMISED PRODUCER. If the process emitting events is itself controlled
    by the adversary, it can simply omit events. The ledger proves what was
    recorded, not that everything was recorded. Completeness requires the
    producer to sit outside the agent's blast radius -- L1's job, not L8's.

Being precise about these two limits matters more than the guarantees. A log
that is believed to be tamper-proof, but is only tamper-evident against edits,
produces false confidence exactly when it is most costly.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence

from ames.canonical import encode_event, decode_event, enc_u64, HEADER_SIZE
from ames.commit import (
    Domain, DIGEST_SIZE, ZERO_DIGEST, commit, event_digest, merkle_root,
)
from ames.events import Event

GENESIS_PREV = ZERO_DIGEST

_BLOCK_HEADER = struct.Struct(">Q32sQ32sQ")   # height, prev, count, root, ts
BLOCK_HEADER_SIZE = _BLOCK_HEADER.size


@dataclass(frozen=True)
class BlockHeader:
    height:       int
    prev_hash:    bytes
    event_count:  int
    events_root:  bytes
    timestamp_ns: int

    def canonical_bytes(self) -> bytes:
        if len(self.prev_hash) != DIGEST_SIZE or len(self.events_root) != DIGEST_SIZE:
            raise ValueError("prev_hash and events_root must be 32 bytes")
        return _BLOCK_HEADER.pack(
            self.height, bytes(self.prev_hash), self.event_count,
            bytes(self.events_root), self.timestamp_ns,
        )

    def digest(self) -> bytes:
        return commit(Domain.BLOCK, self.canonical_bytes())


@dataclass
class Block:
    header: BlockHeader
    events: List[Event] = field(default_factory=list)

    def digest(self) -> bytes:
        return self.header.digest()

    def recompute_root(self) -> bytes:
        return merkle_root([event_digest(encode_event(e)) for e in self.events])


@dataclass(frozen=True)
class Checkpoint:
    """An externally-anchored commitment to the chain head.

    Export this outside the agent's reach. Holding a checkpoint at height N
    makes tail-truncation below N detectable: a chain claiming to end earlier
    than a checkpoint you already hold is provably incomplete.
    """
    height:     int
    head_digest: bytes
    digest:     bytes

    @staticmethod
    def create(height: int, head_digest: bytes) -> "Checkpoint":
        body = enc_u64(height) + bytes(head_digest)
        return Checkpoint(height, bytes(head_digest), commit(Domain.CHECKPOINT, body))

    def verify(self) -> bool:
        body = enc_u64(self.height) + self.head_digest
        return commit(Domain.CHECKPOINT, body) == self.digest


class LedgerError(Exception):
    """Base for ledger integrity failures. A dedicated hierarchy so a caller
    cannot swallow an integrity failure in a generic `except ValueError`."""


class SequenceError(LedgerError):
    """Event sequence numbers are not strictly increasing without gaps."""


class ChainError(LedgerError):
    """Block linkage is broken."""


class Ledger:
    """Append-only, hash-linked event ledger."""

    def __init__(self) -> None:
        self._blocks: List[Block] = []
        self._pending: List[Event] = []
        self._next_sequence: int = 0

    # --- writing ------------------------------------------------------------

    def append(self, event: Event) -> None:
        """Stage an event. Sequence numbers must be dense and strictly
        increasing: a gap means an event was dropped or withheld, which is
        exactly what an adversary would do, so it is rejected at write time
        rather than discovered later."""
        if event.sequence != self._next_sequence:
            raise SequenceError(
                f"expected sequence {self._next_sequence}, got {event.sequence}"
            )
        self._pending.append(event)
        self._next_sequence += 1

    def seal_block(self, timestamp_ns: int) -> Block:
        """Commit staged events into a new block linked to the current head."""
        if not self._pending:
            raise LedgerError("refusing to seal an empty block")

        prev = self._blocks[-1].digest() if self._blocks else GENESIS_PREV
        root = merkle_root([event_digest(encode_event(e)) for e in self._pending])
        header = BlockHeader(
            height=len(self._blocks),
            prev_hash=prev,
            event_count=len(self._pending),
            events_root=root,
            timestamp_ns=timestamp_ns,
        )
        block = Block(header=header, events=list(self._pending))
        self._blocks.append(block)
        self._pending = []
        return block

    # --- reading ------------------------------------------------------------

    @property
    def height(self) -> int:
        return len(self._blocks)

    @property
    def blocks(self) -> Sequence[Block]:
        return tuple(self._blocks)

    @property
    def pending(self) -> Sequence[Event]:
        return tuple(self._pending)

    def head_digest(self) -> bytes:
        return self._blocks[-1].digest() if self._blocks else GENESIS_PREV

    def checkpoint(self) -> Checkpoint:
        return Checkpoint.create(self.height, self.head_digest())

    def all_events(self) -> Iterator[Event]:
        for b in self._blocks:
            yield from b.events

    # --- verification -------------------------------------------------------

    def verify_chain(self, checkpoint: Optional[Checkpoint] = None) -> None:
        """Recompute every commitment. Raises on the first inconsistency.

        Pass a previously-exported checkpoint to additionally detect tail
        truncation, which linkage alone cannot catch.
        """
        expected_prev = GENESIS_PREV
        expected_seq = 0

        for i, block in enumerate(self._blocks):
            if block.header.height != i:
                raise ChainError(f"block {i}: height field says {block.header.height}")
            if block.header.prev_hash != expected_prev:
                raise ChainError(
                    f"block {i}: prev_hash {block.header.prev_hash.hex()[:16]} "
                    f"!= expected {expected_prev.hex()[:16]} (chain spliced or reordered)"
                )
            if block.header.event_count != len(block.events):
                raise ChainError(
                    f"block {i}: header claims {block.header.event_count} events, "
                    f"found {len(block.events)}"
                )
            recomputed = block.recompute_root()
            if recomputed != block.header.events_root:
                raise ChainError(
                    f"block {i}: events_root mismatch -- event content was altered"
                )
            for ev in block.events:
                if ev.sequence != expected_seq:
                    raise SequenceError(
                        f"block {i}: expected sequence {expected_seq}, got {ev.sequence}"
                    )
                expected_seq += 1

            expected_prev = block.digest()

        if checkpoint is not None:
            if not checkpoint.verify():
                raise ChainError("checkpoint is itself malformed")
            if self.height < checkpoint.height:
                raise ChainError(
                    f"chain height {self.height} is below checkpoint height "
                    f"{checkpoint.height} -- the tail was truncated"
                )
            if self.height == checkpoint.height and self.head_digest() != checkpoint.head_digest:
                raise ChainError("head digest disagrees with checkpoint at same height")
