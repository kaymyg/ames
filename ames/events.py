"""
AMES-V1 -- Agent Mutation Event Schema.

Generalises KAYSentinel's EMES (Execution Mutation Event Schema) from EVM state
transitions to autonomous-agent actions. The wire model is deliberately the same
shape as EMES: a flat, sequence-numbered event stream with explicit parent
linkage, so the existing Gate 1 structural invariants (sequence monotonicity,
frame balance) carry over directly -- an EVM call frame becomes a process.

Design constraints, in priority order:

1. CANONICAL. The same logical event stream must always produce identical bytes,
   on any implementation, in any language. No dict ordering, no float
   formatting, no locale, no timezone. Every field is fixed-width big-endian or
   explicitly length-prefixed.
2. APPEND-ONLY. Events carry a strictly increasing sequence number and are
   committed into a hash-linked chain. Reordering, splicing, or editing any
   event invalidates every commitment after it.
3. SELF-DESCRIBING. An event is interpretable without the producer's source
   code, so a forensic analyst is not dependent on the runtime that emitted it.

NOT claimed: tamper-PROOF. An attacker with write access to the ledger file can
truncate its tail. The chain makes silent modification impossible; it does not
make deletion impossible. Truncation resistance requires exporting the head
commitment somewhere the agent cannot reach -- see ledger.Checkpoint.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional

# Sentinel parent for a root actor (no parent). Mirrors EMES's noParentFrame.
NO_PARENT = 0xFFFFFFFFFFFFFFFF

MAX_SEQUENCE = 0xFFFFFFFFFFFFFFFF
MAX_PAYLOAD_BYTES = 1 << 20  # 1 MiB; larger payloads must be content-addressed


class EventType(enum.IntEnum):
    """Wire-stable event discriminants. Values are permanently immutable once
    published -- append new types, never renumber or recycle existing ones."""

    PROCESS_SPAWN       = 0x01
    PROCESS_EXIT        = 0x02
    FILE_MUTATION       = 0x03
    NETWORK_REQUEST     = 0x04
    TOOL_CALL           = 0x05
    CAPABILITY_REQUEST  = 0x06
    MEMORY_MAP          = 0x07
    # Boundary markers for a contained run.
    RUN_BEGIN           = 0x7E
    RUN_END             = 0x7F


class FileOp(enum.IntEnum):
    CREATE   = 0x01
    WRITE    = 0x02
    DELETE   = 0x03
    CHMOD    = 0x04
    SYMLINK  = 0x05
    RENAME   = 0x06


class Protocol(enum.IntEnum):
    OTHER = 0x00
    TCP   = 0x01
    UDP   = 0x02
    HTTP  = 0x03
    HTTPS = 0x04
    DNS   = 0x05


class Capability(enum.IntEnum):
    """Capabilities an agent may request. Denied requests are recorded too --
    a burst of denials is itself a strong escape-probing signal (L9)."""

    NET_EGRESS       = 0x01
    PACKAGE_INSTALL  = 0x02
    FILE_WRITE       = 0x03
    PROCESS_SPAWN    = 0x04
    RAW_SYSCALL      = 0x05
    PRIVILEGE_RAISE  = 0x06


@dataclass(frozen=True)
class Event:
    """A single agent mutation event.

    Fields common to every event type form the header; `payload` carries the
    type-specific body, itself canonically encoded (see canonical.py).

    actor_id / parent_id give the process lineage graph. Gate 1 verifies this
    graph is well-formed: no orphans, no unbalanced spawns, no depth violations.
    """

    event_type:   EventType
    sequence:     int          # strictly increasing within a run, no gaps
    timestamp_ns: int          # monotonic clock, non-decreasing
    actor_id:     int          # the process/agent performing the action
    parent_id:    int          # NO_PARENT for a root actor
    payload:      bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, EventType):
            raise TypeError(f"event_type must be an EventType, got {type(self.event_type).__name__}")
        for name in ("sequence", "timestamp_ns", "actor_id", "parent_id"):
            v = getattr(self, name)
            if not isinstance(v, int) or isinstance(v, bool):
                raise TypeError(f"{name} must be int, got {type(v).__name__}")
            if not (0 <= v <= MAX_SEQUENCE):
                raise ValueError(f"{name}={v} out of uint64 range")
        if not isinstance(self.payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        if len(self.payload) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload {len(self.payload)} bytes exceeds MAX_PAYLOAD_BYTES "
                f"({MAX_PAYLOAD_BYTES}); content-address it instead"
            )
        if self.actor_id == NO_PARENT:
            raise ValueError("actor_id may not be the NO_PARENT sentinel")
