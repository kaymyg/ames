"""
Adversarial tests for the AMES ledger.

Every test here is an ATTACK, not a feature check. Each names a specific thing
an adversary would try in order to hide what it did, and asserts the ledger
detects it. A control without a test that proves it fires is a hypothesis --
this file is the evidence.

Attacks covered: content edit, reorder, splice, block forgery, tail truncation,
checkpoint forgery, sequence withholding, and lineage suppression.
"""

import dataclasses
import pytest

from ames.canonical import encode_event, decode_event, payload_process_spawn
from ames.commit import merkle_root, merkle_proof, verify_proof, event_digest, Domain, commit
from ames.events import Event, EventType, NO_PARENT
from ames.gate1 import verify as gate1_verify
from ames.ledger import Ledger, Checkpoint, ChainError, SequenceError, LedgerError


def mk(seq, etype=EventType.TOOL_CALL, actor=10, parent=NO_PARENT, ts=None, payload=b""):
    return Event(etype, seq, ts if ts is not None else 1000 + seq, actor, parent, payload)


def build_ledger(n_blocks=3, per_block=4):
    led = Ledger()
    seq = 0
    for b in range(n_blocks):
        for _ in range(per_block):
            led.append(mk(seq, payload=f"action-{seq}".encode()))
            seq += 1
        led.seal_block(5000 + b)
    return led


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def test_untampered_chain_verifies():
    led = build_ledger()
    led.verify_chain(led.checkpoint())          # must not raise


# ---------------------------------------------------------------------------
# Attack 1: edit an event's content in place
# ---------------------------------------------------------------------------

def test_content_edit_is_detected():
    led = build_ledger()
    victim = led.blocks[1].events[2]
    forged = dataclasses.replace(victim, payload=b"exfiltrate-credentials")
    led.blocks[1].events[2] = forged

    with pytest.raises(ChainError, match="events_root mismatch"):
        led.verify_chain()


def test_edit_in_last_block_still_detected():
    """The final block has no successor to break, so it must be caught by its
    own events_root -- not merely by downstream linkage."""
    led = build_ledger()
    last = led.blocks[-1]
    last.events[0] = dataclasses.replace(last.events[0], payload=b"tampered")

    with pytest.raises(ChainError, match="events_root mismatch"):
        led.verify_chain()


# ---------------------------------------------------------------------------
# Attack 2: reorder events
# ---------------------------------------------------------------------------

def test_event_reorder_is_detected():
    led = build_ledger()
    evs = led.blocks[0].events
    evs[0], evs[1] = evs[1], evs[0]

    with pytest.raises(LedgerError):       # SequenceError or ChainError
        led.verify_chain()


def test_block_reorder_is_detected():
    led = build_ledger()
    led._blocks[0], led._blocks[1] = led._blocks[1], led._blocks[0]

    with pytest.raises(ChainError):
        led.verify_chain()


# ---------------------------------------------------------------------------
# Attack 3: splice a block out of the middle
# ---------------------------------------------------------------------------

def test_block_splice_is_detected():
    led = build_ledger()
    del led._blocks[1]

    with pytest.raises(ChainError):
        led.verify_chain()


def test_event_removal_within_block_is_detected():
    led = build_ledger()
    del led.blocks[1].events[1]

    with pytest.raises(ChainError):
        led.verify_chain()


# ---------------------------------------------------------------------------
# Attack 4: forge a block with a recomputed root
# ---------------------------------------------------------------------------

def test_forged_block_breaks_the_link():
    """The strongest forgery available to an attacker: replace a block's events,
    recompute events_root so the block is internally consistent, keep the event
    count and every sequence number identical, and relink prev_hash to the real
    predecessor. Nothing inside the block is detectably wrong.

    It must still fail, because the SUCCESSOR block's prev_hash commits to the
    original block's digest. That is the whole point of chaining: local
    consistency is not enough."""
    from ames.ledger import Block, BlockHeader

    led = build_ledger()
    original = led.blocks[1]

    # Same sequences (4..7), same count -- only the content differs.
    evil = [mk(e.sequence, payload=b"covert") for e in original.events]
    root = merkle_root([event_digest(encode_event(e)) for e in evil])
    header = BlockHeader(
        height=original.header.height,
        prev_hash=original.header.prev_hash,      # correctly linked backwards
        event_count=len(evil),                    # honest count
        events_root=root,                         # honest root for the new events
        timestamp_ns=original.header.timestamp_ns,
    )
    led._blocks[1] = Block(header=header, events=evil)

    # Block 1 is now internally flawless. Block 2 still remembers the truth.
    with pytest.raises(ChainError, match="prev_hash"):
        led.verify_chain()


def test_event_count_lie_is_detected():
    led = build_ledger()
    hdr = led.blocks[0].header
    led.blocks[0].header = dataclasses.replace(hdr, event_count=99)

    with pytest.raises(ChainError, match="event_count|claims"):
        led.verify_chain()


# ---------------------------------------------------------------------------
# Attack 5: truncate the tail  (linkage alone CANNOT catch this)
# ---------------------------------------------------------------------------

def test_truncation_is_invisible_without_a_checkpoint():
    """Documents the real limitation honestly: a truncated chain is internally
    consistent. This test asserts the weakness exists, so nobody assumes
    otherwise."""
    led = build_ledger()
    del led._blocks[-1]
    led.verify_chain()          # passes -- and that is the point


def test_truncation_is_detected_with_a_checkpoint():
    led = build_ledger()
    cp = led.checkpoint()       # exported outside the agent's reach
    del led._blocks[-1]

    with pytest.raises(ChainError, match="truncated"):
        led.verify_chain(cp)


def test_forged_checkpoint_is_rejected():
    led = build_ledger()
    cp = led.checkpoint()
    bad = Checkpoint(height=cp.height, head_digest=b"\xAA" * 32, digest=cp.digest)

    assert not bad.verify()
    with pytest.raises(ChainError, match="malformed"):
        led.verify_chain(bad)


def test_same_height_different_head_is_detected():
    """Fork attack: a chain of the correct length, but different contents."""
    led_a = build_ledger()
    cp = led_a.checkpoint()

    led_b = Ledger()
    seq = 0
    for b in range(3):
        for _ in range(4):
            led_b.append(mk(seq, payload=b"different"))
            seq += 1
        led_b.seal_block(5000 + b)

    with pytest.raises(ChainError, match="disagrees with checkpoint"):
        led_b.verify_chain(cp)


# ---------------------------------------------------------------------------
# Attack 6: withhold events at write time
# ---------------------------------------------------------------------------

def test_sequence_gap_rejected_at_append():
    led = Ledger()
    led.append(mk(0))
    with pytest.raises(SequenceError):
        led.append(mk(2))           # skipped 1


def test_empty_block_refused():
    led = Ledger()
    with pytest.raises(LedgerError, match="empty"):
        led.seal_block(1)


# ---------------------------------------------------------------------------
# Attack 7: hide a process by suppressing its spawn event
# ---------------------------------------------------------------------------

def run_stream(*events):
    return [mk(0, EventType.RUN_BEGIN, actor=1), *events,
            mk(len(events) + 1, EventType.RUN_END, actor=1)]


def test_suppressed_spawn_leaves_an_orphan():
    evs = run_stream(
        mk(1, EventType.PROCESS_SPAWN, actor=10),
        # spawn of actor 20 (child of 10) deliberately omitted
        mk(2, EventType.NETWORK_REQUEST, actor=20),
        mk(3, EventType.PROCESS_EXIT, actor=10),
    )
    res = gate1_verify(evs)
    assert not res.ok
    assert any(v.code == "UNATTRIBUTED_ACTION" for v in res.violations)


def test_orphan_spawn_detected():
    evs = run_stream(
        mk(1, EventType.PROCESS_SPAWN, actor=20, parent=999),   # parent never spawned
        mk(2, EventType.PROCESS_EXIT, actor=20),
    )
    res = gate1_verify(evs)
    assert any(v.code == "ORPHAN_SPAWN" for v in res.violations)


def test_dormant_process_detected():
    """A process left running past RUN_END is how persistence survives."""
    evs = run_stream(mk(1, EventType.PROCESS_SPAWN, actor=10))
    res = gate1_verify(evs)
    assert any(v.code == "UNTERMINATED_ACTOR" for v in res.violations)


def test_action_after_exit_detected():
    evs = run_stream(
        mk(1, EventType.PROCESS_SPAWN, actor=10),
        mk(2, EventType.PROCESS_EXIT, actor=10),
        mk(3, EventType.FILE_MUTATION, actor=10),
    )
    res = gate1_verify(evs)
    assert any(v.code == "ACTION_AFTER_EXIT" for v in res.violations)


def test_timestamp_regression_detected():
    evs = run_stream(
        mk(1, EventType.PROCESS_SPAWN, actor=10, ts=5000),
        mk(2, EventType.TOOL_CALL, actor=10, ts=100),    # clock rolled back
        mk(3, EventType.PROCESS_EXIT, actor=10, ts=6000),
    )
    res = gate1_verify(evs)
    assert any(v.code == "TIME_REGRESSION" for v in res.violations)


def test_truncated_log_missing_run_end():
    evs = [mk(0, EventType.RUN_BEGIN, actor=1),
           mk(1, EventType.PROCESS_SPAWN, actor=10),
           mk(2, EventType.PROCESS_EXIT, actor=10)]
    res = gate1_verify(evs)
    assert any(v.code == "NO_RUN_END" for v in res.violations)


# ---------------------------------------------------------------------------
# Encoding-level attacks
# ---------------------------------------------------------------------------

def test_reserved_bits_cannot_smuggle_state():
    ev = mk(1)
    raw = bytearray(encode_event(ev))
    raw[37:41] = (0xDEADBEEF).to_bytes(4, "big")     # set the reserved field
    with pytest.raises(ValueError, match="reserved"):
        decode_event(bytes(raw))


def test_payload_length_lie_is_rejected():
    ev = mk(1, payload=b"hello")
    raw = bytearray(encode_event(ev))
    raw[33:37] = (999).to_bytes(4, "big")
    with pytest.raises(ValueError, match="length mismatch"):
        decode_event(bytes(raw))


def test_unknown_event_type_rejected():
    ev = mk(1)
    raw = bytearray(encode_event(ev))
    raw[0] = 0x42
    with pytest.raises(ValueError, match="unknown event_type"):
        decode_event(bytes(raw))


def test_encoding_is_deterministic():
    a = mk(7, payload=payload_process_spawn(b"\x01" * 32, b"\x02" * 32, "/w"))
    b = decode_event(encode_event(a))
    assert encode_event(a) == encode_event(b)


def test_merkle_second_preimage_resistance():
    """Leaf and internal-node domains must differ, else an internal node can be
    presented as a leaf (CVE-2012-2459 class)."""
    assert commit(Domain.MERKLE_LEAF, b"x") != commit(Domain.MERKLE_NODE, b"x")


def test_inclusion_proof_roundtrip_and_forgery():
    leaves = [event_digest(encode_event(mk(i))) for i in range(9)]
    root = merkle_root(leaves)
    for i in range(9):
        assert verify_proof(leaves[i], merkle_proof(leaves, i), root)
    assert not verify_proof(b"\xFF" * 32, merkle_proof(leaves, 3), root)
