"""Locks the pinned conformance vectors. If a refactor changes any canonical
byte or digest, these fail -- which is the point: the wire format is a
compatibility promise, not an implementation detail."""
import json, pathlib, pytest

from ames.canonical import encode_event, payload_process_spawn, payload_network_request, payload_capability_request
from ames.commit import Domain, commit, event_digest, merkle_root
from ames.events import Event, EventType, NO_PARENT, Capability, Protocol

VECTORS = json.loads((pathlib.Path(__file__).parent.parent / "vectors" / "ames_v1_conformance.json").read_text())


def test_domain_tags_are_frozen():
    for entry in VECTORS["sections"]["domain_separation"]:
        d = Domain[entry["domain"]]
        assert d.value.decode() == entry["tag"], "domain tags are immutable once published"
        assert commit(d, bytes.fromhex("01020304")).hex() == entry["digest_of_01020304"]


def test_all_domains_are_distinct():
    digests = {commit(d, b"same input").hex() for d in Domain}
    assert len(digests) == len(list(Domain)), "domain separation violated"


def _rebuild():
    return [
        Event(EventType.RUN_BEGIN, 0, 1_000_000_000, 1, NO_PARENT, b""),
        Event(EventType.PROCESS_SPAWN, 1, 1_000_000_100, 10, 1,
              payload_process_spawn(bytes.fromhex("11"*32), bytes.fromhex("22"*32), "/workspace")),
        Event(EventType.NETWORK_REQUEST, 2, 1_000_000_200, 10, 1,
              payload_network_request(Protocol.HTTPS, "huggingface.co", 512, 4096)),
        Event(EventType.CAPABILITY_REQUEST, 3, 1_000_000_300, 10, 1,
              payload_capability_request(Capability.PRIVILEGE_RAISE, False, "policy")),
        Event(EventType.PROCESS_EXIT, 4, 1_000_000_400, 10, 1, (0).to_bytes(4, "big")),
        Event(EventType.RUN_END, 5, 1_000_000_500, 1, NO_PARENT, b""),
    ]


@pytest.mark.parametrize("i", range(6))
def test_event_encoding_matches_vector(i):
    ev = _rebuild()[i]
    vec = VECTORS["sections"]["event_encoding"][i]
    assert encode_event(ev).hex() == vec["canonical_hex"]
    assert event_digest(encode_event(ev)).hex() == vec["event_digest"]


def test_merkle_roots_match_vectors():
    for vec in VECTORS["sections"]["merkle_roots"]:
        n = vec["leaf_count"]
        assert merkle_root([bytes([i+1])*32 for i in range(n)]).hex() == vec["root"]


def test_ledger_digests_match_vectors():
    from ames.ledger import Ledger
    led = Ledger()
    for e in _rebuild():
        led.append(e)
    led.seal_block(1_000_001_000)

    v = VECTORS["sections"]["ledger"]
    assert led.height == v["block_count"]
    assert led.head_digest().hex() == v["head_digest"]
    for blk, vb in zip(led.blocks, v["blocks"]):
        assert blk.header.canonical_bytes().hex() == vb["header_canonical_hex"]
        assert blk.digest().hex() == vb["block_digest"]
