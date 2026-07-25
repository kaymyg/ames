"""Generates AMES-V1 conformance vectors. Any independent implementation must
reproduce these bytes and digests exactly. Same discipline as KAYSentinel's
pinned BLAKE3 vectors -- a spec without executable vectors is a suggestion."""
import json, sys
sys.path.insert(0, ".")
from ames.canonical import encode_event, payload_process_spawn, payload_network_request, payload_capability_request
from ames.commit import Domain, commit, event_digest, merkle_root
from ames.events import Event, EventType, NO_PARENT, Capability, Protocol
from ames.ledger import Ledger

vectors = {"profile_id": "AMES-V1", "spec_version": "1.0.0", "hash": "BLAKE3-256", "sections": {}}

# 1. domain tags
vectors["sections"]["domain_separation"] = [
    {"domain": d.name, "tag": d.value.decode(), "digest_of_01020304":
     commit(d, bytes.fromhex("01020304")).hex()} for d in Domain
]

# 2. canonical event encodings
evs = [
    ("run_begin", Event(EventType.RUN_BEGIN, 0, 1_000_000_000, 1, NO_PARENT, b"")),
    ("process_spawn", Event(EventType.PROCESS_SPAWN, 1, 1_000_000_100, 10, 1,
                            payload_process_spawn(bytes.fromhex("11"*32), bytes.fromhex("22"*32), "/workspace"))),
    ("network_request", Event(EventType.NETWORK_REQUEST, 2, 1_000_000_200, 10, 1,
                              payload_network_request(Protocol.HTTPS, "huggingface.co", 512, 4096))),
    ("capability_denied", Event(EventType.CAPABILITY_REQUEST, 3, 1_000_000_300, 10, 1,
                                payload_capability_request(Capability.PRIVILEGE_RAISE, False, "policy"))),
    ("process_exit", Event(EventType.PROCESS_EXIT, 4, 1_000_000_400, 10, 1, (0).to_bytes(4, "big"))),
    ("run_end", Event(EventType.RUN_END, 5, 1_000_000_500, 1, NO_PARENT, b"")),
]
vectors["sections"]["event_encoding"] = [
    {"name": n, "event_type": f"0x{int(e.event_type):02x}", "sequence": e.sequence,
     "canonical_hex": encode_event(e).hex(), "canonical_len": len(encode_event(e)),
     "event_digest": event_digest(encode_event(e)).hex()} for n, e in evs
]

# 3. merkle roots for 0..8 leaves
vectors["sections"]["merkle_roots"] = [
    {"leaf_count": n, "root": merkle_root([bytes([i+1])*32 for i in range(n)]).hex()}
    for n in range(0, 9)
]

# 4. a full chained ledger
led = Ledger()
for _, e in evs:
    led.append(e)
b0 = led.seal_block(1_000_001_000)
vectors["sections"]["ledger"] = {
    "block_count": led.height,
    "blocks": [{"height": b.header.height, "prev_hash": b.header.prev_hash.hex(),
                "event_count": b.header.event_count, "events_root": b.header.events_root.hex(),
                "timestamp_ns": b.header.timestamp_ns,
                "header_canonical_hex": b.header.canonical_bytes().hex(),
                "block_digest": b.digest().hex()} for b in led.blocks],
    "head_digest": led.head_digest().hex(),
    "checkpoint": {"height": led.checkpoint().height,
                   "head_digest": led.checkpoint().head_digest.hex(),
                   "digest": led.checkpoint().digest.hex()},
}

with open("vectors/ames_v1_conformance.json", "w") as f:
    json.dump(vectors, f, indent=2); f.write("\n")
print("wrote vectors/ames_v1_conformance.json")
for s, v in vectors["sections"].items():
    print(f"  {s}: {len(v) if isinstance(v, list) else 'ledger'} entries")
