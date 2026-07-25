"""
AMES-V1 canonical serialization.

Every value is fixed-width big-endian or explicitly length-prefixed. There is no
JSON anywhere on the commitment path: JSON permits key reordering, whitespace
variation, unicode escaping choices and float formatting differences, any one of
which silently changes the bytes and therefore the hash. A canonical format that
two implementations disagree about is worse than no canonical format at all,
because the disagreement only surfaces as an unexplained verification failure.

Header layout (fixed 41 bytes):

    offset  size  field
    0       1     event_type        u8
    1       8     sequence          u64 BE
    9       8     timestamp_ns      u64 BE
    17      8     actor_id          u64 BE
    25      8     parent_id         u64 BE
    33      4     payload_len       u32 BE
    37      4     reserved          u32 BE (MUST be zero in V1)
    41      ...   payload

`reserved` exists so a V2 can add header flags without changing the offset of
every field that follows. It is verified to be zero on decode: silently ignoring
unknown bits would let an attacker smuggle state past a V1 verifier.
"""

from __future__ import annotations

import struct
from typing import Iterable

from ames.events import (
    Capability, Event, EventType, FileOp, Protocol, MAX_PAYLOAD_BYTES,
)

HEADER_SIZE = 41
_RESERVED_V1 = 0

_HEADER = struct.Struct(">BQQQQII")


# --- primitives -------------------------------------------------------------

def enc_u8(v: int) -> bytes:
    if not 0 <= v <= 0xFF:
        raise ValueError(f"u8 out of range: {v}")
    return struct.pack(">B", v)


def enc_u32(v: int) -> bytes:
    if not 0 <= v <= 0xFFFFFFFF:
        raise ValueError(f"u32 out of range: {v}")
    return struct.pack(">I", v)


def enc_u64(v: int) -> bytes:
    if not 0 <= v <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"u64 out of range: {v}")
    return struct.pack(">Q", v)


def enc_bytes(b: bytes) -> bytes:
    """Length-prefixed byte string: u32 BE length || raw bytes."""
    if len(b) > 0xFFFFFFFF:
        raise ValueError("byte string too long")
    return enc_u32(len(b)) + bytes(b)


def enc_str(s: str) -> bytes:
    """Length-prefixed UTF-8. NFC-normalised so visually identical strings from
    different sources encode identically."""
    import unicodedata
    return enc_bytes(unicodedata.normalize("NFC", s).encode("utf-8"))


# --- event header -----------------------------------------------------------

def encode_event(ev: Event) -> bytes:
    """Canonical bytes for one event. Deterministic and total."""
    if len(ev.payload) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds MAX_PAYLOAD_BYTES")
    return _HEADER.pack(
        int(ev.event_type),
        ev.sequence,
        ev.timestamp_ns,
        ev.actor_id,
        ev.parent_id,
        len(ev.payload),
        _RESERVED_V1,
    ) + bytes(ev.payload)


def decode_event(raw: bytes) -> Event:
    """Inverse of encode_event. Rejects malformed input rather than guessing."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"truncated event header: {len(raw)} < {HEADER_SIZE}")
    etype, seq, ts, actor, parent, plen, reserved = _HEADER.unpack(raw[:HEADER_SIZE])

    if reserved != _RESERVED_V1:
        raise ValueError(f"reserved field must be 0 in AMES-V1, got {reserved}")
    body = raw[HEADER_SIZE:]
    if len(body) != plen:
        raise ValueError(f"payload length mismatch: header says {plen}, got {len(body)}")
    try:
        et = EventType(etype)
    except ValueError:
        raise ValueError(f"unknown event_type 0x{etype:02x}") from None

    return Event(
        event_type=et, sequence=seq, timestamp_ns=ts,
        actor_id=actor, parent_id=parent, payload=body,
    )


# --- typed payload builders -------------------------------------------------
#
# Large or variable-length content (argv, file contents, request bodies) is
# committed by hash rather than stored inline. The ledger stays bounded and
# inspectable; the content lives in a content-addressed store keyed by that
# hash. This is what keeps an action log from becoming a data exfiltration
# channel in its own right.

def payload_process_spawn(binary_hash: bytes, argv_hash: bytes, cwd: str) -> bytes:
    _require_hash(binary_hash, "binary_hash")
    _require_hash(argv_hash, "argv_hash")
    return binary_hash + argv_hash + enc_str(cwd)


def payload_process_exit(exit_code: int) -> bytes:
    # Encoded as unsigned; negative codes are two's-complement in 32 bits.
    return enc_u32(exit_code & 0xFFFFFFFF)


def payload_file_mutation(op: FileOp, path: str, before_hash: bytes, after_hash: bytes) -> bytes:
    _require_hash(before_hash, "before_hash")
    _require_hash(after_hash, "after_hash")
    return enc_u8(int(op)) + enc_str(path) + before_hash + after_hash


def payload_network_request(proto: Protocol, destination: str,
                            bytes_out: int, bytes_in: int) -> bytes:
    return enc_u8(int(proto)) + enc_str(destination) + enc_u64(bytes_out) + enc_u64(bytes_in)


def payload_tool_call(tool: str, args_hash: bytes, result_hash: bytes) -> bytes:
    _require_hash(args_hash, "args_hash")
    _require_hash(result_hash, "result_hash")
    return enc_str(tool) + args_hash + result_hash


def payload_capability_request(cap: Capability, granted: bool, reason: str = "") -> bytes:
    return enc_u8(int(cap)) + enc_u8(1 if granted else 0) + enc_str(reason)


def payload_memory_map(addr: int, length: int, prot: int) -> bytes:
    return enc_u64(addr) + enc_u64(length) + enc_u8(prot)


def _require_hash(h: bytes, name: str) -> None:
    if not isinstance(h, (bytes, bytearray)) or len(h) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes, got {len(h) if hasattr(h,'__len__') else '?'}")


def encode_stream(events: Iterable[Event]) -> bytes:
    """Concatenated canonical encoding of an event stream."""
    return b"".join(encode_event(e) for e in events)
