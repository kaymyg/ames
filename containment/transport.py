"""
Guest -> host event transport.

The one channel that crosses the isolation boundary, so it is the highest-value
target in the design. The July 2026 escape went through exactly this kind of
component: the package-registry proxy was the trusted bridge, and the bridge was
the way out.

Two rules follow, and they are the reason this module is deliberately boring:

1. DATA ONLY, ONE DIRECTION. The guest submits event claims. The host never
   sends anything back that could influence guest behaviour, and the guest can
   never invoke host code paths beyond this parser. There is no RPC here, no
   command dispatch, no callbacks -- nothing that turns a message into an action.

2. THE PARSER IS THE ATTACK SURFACE. Hugging Face was compromised by a malicious
   uploaded dataset hitting a remote-code loader and a template-injection bug in
   config parsing. That is this exact shape of problem: untrusted bytes meeting a
   permissive parser. So the wire format here is fixed-width binary with explicit
   bounds -- no JSON, no pickle, no eval, no templates, no dynamic imports.

Everything accepted here is a CLAIM, recorded as guest-attributed and trusted no
further than the guest itself.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from ames.events import EventType

# frame: u8 type | u32 payload_len | payload
_FRAME_HEADER = struct.Struct(">BI")
FRAME_HEADER_SIZE = _FRAME_HEADER.size

# Bounds. A compromised guest will try to exhaust the host: unbounded payloads,
# unbounded event counts, unbounded total bytes. All three are capped, and the
# caps are enforced before any allocation proportional to the claimed size.
MAX_FRAME_PAYLOAD = 64 * 1024
MAX_EVENTS_PER_RUN = 100_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024

# Event types a guest is permitted to claim. RUN_BEGIN/RUN_END are host-only
# boundary markers -- letting a guest emit them would let it forge the shape of
# its own run and split one run into several in the record.
GUEST_PERMITTED = frozenset({
    EventType.PROCESS_SPAWN, EventType.PROCESS_EXIT, EventType.FILE_MUTATION,
    EventType.NETWORK_REQUEST, EventType.TOOL_CALL, EventType.CAPABILITY_REQUEST,
    EventType.MEMORY_MAP,
})


class TransportError(Exception):
    """Malformed or abusive guest input. Dedicated type so it is never confused
    with a host-side bug."""


class TransportLimitExceeded(TransportError):
    """The guest exceeded a resource bound. Itself a signal worth recording:
    flooding the audit channel is a recognised way to bury one real event."""


@dataclass
class GuestClaim:
    event_type: EventType
    payload: bytes


@dataclass
class TransportStats:
    frames_accepted: int = 0
    frames_rejected: int = 0
    bytes_accepted: int = 0
    rejections: List[str] = field(default_factory=list)

    def reject(self, reason: str) -> None:
        self.frames_rejected += 1
        # Bounded: an attacker who can make the host store one string per bad
        # frame has turned error handling into a memory-exhaustion primitive.
        if len(self.rejections) < 100:
            self.rejections.append(reason)


class GuestEventReader:
    """Parses a guest-produced frame stream into claims, enforcing all bounds.

    Never raises on a single malformed frame -- it records the rejection and
    stops. Aborting the whole run on bad input would let a guest destroy its own
    audit trail by sending one corrupt byte at the end.
    """

    def __init__(self, *, max_events: int = MAX_EVENTS_PER_RUN,
                 max_total_bytes: int = MAX_TOTAL_BYTES) -> None:
        self.max_events = max_events
        self.max_total_bytes = max_total_bytes
        self.stats = TransportStats()

    def read(self, stream: bytes) -> List[GuestClaim]:
        claims: List[GuestClaim] = []
        offset = 0
        total = 0

        while offset < len(stream):
            if len(claims) >= self.max_events:
                self.stats.reject(f"event count cap {self.max_events} reached; truncating")
                break

            if offset + FRAME_HEADER_SIZE > len(stream):
                self.stats.reject("truncated frame header")
                break

            raw_type, plen = _FRAME_HEADER.unpack_from(stream, offset)
            offset += FRAME_HEADER_SIZE

            # Bound-check BEFORE trusting plen for any slicing or allocation.
            if plen > MAX_FRAME_PAYLOAD:
                self.stats.reject(f"payload {plen} exceeds MAX_FRAME_PAYLOAD")
                break
            if offset + plen > len(stream):
                self.stats.reject("payload extends past end of stream")
                break

            payload = stream[offset:offset + plen]
            offset += plen

            total += plen
            if total > self.max_total_bytes:
                self.stats.reject("total byte cap exceeded; truncating")
                break

            try:
                etype = EventType(raw_type)
            except ValueError:
                self.stats.reject(f"unknown event type 0x{raw_type:02x}")
                continue

            if etype not in GUEST_PERMITTED:
                self.stats.reject(
                    f"{etype.name} is host-only; a guest may not forge run boundaries"
                )
                continue

            claims.append(GuestClaim(etype, payload))
            self.stats.frames_accepted += 1
            self.stats.bytes_accepted += plen

        return claims


def encode_frame(etype: EventType, payload: bytes) -> bytes:
    """Guest-side helper, provided so the wire format has exactly one
    implementation rather than a host parser and a drifting guest writer."""
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise TransportLimitExceeded(f"payload {len(payload)} exceeds cap")
    return _FRAME_HEADER.pack(int(etype), len(payload)) + payload
