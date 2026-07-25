"""
L0 -- property-based validation of the pure, deterministic logic every other
layer's correctness depends on: canonical encoding, merkle commitments, and
Gate 1's structural invariants.

Every other test in this repo is example-based. These are not: each property
below is checked against hundreds of machine-generated cases per run (Hypothesis
also shrinks any failure to a minimal reproducing example automatically), which
is a genuinely different kind of adversarial validation than a human picking
attacks -- it is the closest thing this sandbox can do to the "adversarial
validation engine" the original design called for, given there is no /dev/kvm
here to validate the hypervisor itself. See docs/l0_validation.md for the full
scope statement.
"""

import dataclasses

from hypothesis import given, settings, strategies as st

from ames.canonical import decode_event, encode_event
from ames.commit import merkle_proof, merkle_root, verify_proof, ZERO_DIGEST
from ames.events import EventType
from ames.gate1 import verify as gate1_verify
from validation.properties import digest_list, lineage_stream, st_event


# ---------------------------------------------------------------------------
# Canonical encoding: round-trip is total over any structurally valid Event
# ---------------------------------------------------------------------------

@given(st_event())
@settings(max_examples=300)
def test_canonical_round_trip_is_total(ev):
    """For ANY event the type system allows, not just the hand-picked ones in
    test_conformance.py's pinned vectors: decode(encode(x)) == x."""
    decoded = decode_event(encode_event(ev))
    assert decoded == ev


# ---------------------------------------------------------------------------
# Merkle: proofs always verify, roots are sensitive to content
# ---------------------------------------------------------------------------

@given(digest_list(min_size=1, max_size=40))
@settings(max_examples=200)
def test_merkle_proof_always_verifies_for_every_index(leaves):
    root = merkle_root(leaves)
    for i in range(len(leaves)):
        proof = merkle_proof(leaves, i)
        assert verify_proof(leaves[i], proof, root), f"index {i} of {len(leaves)} failed to verify"


@given(digest_list(min_size=0, max_size=0))
def test_empty_tree_is_the_zero_digest(leaves):
    assert merkle_root(leaves) == ZERO_DIGEST


@given(digest_list(min_size=2, max_size=30), st.data())
@settings(max_examples=150)
def test_changing_any_single_leaf_changes_the_root(leaves, data):
    """A cheap avalanche/no-collision spot check: BLAKE3 collisions are not
    something unit tests can meaningfully search for, but flipping one byte of
    one leaf and getting the SAME root would indicate a construction bug (e.g.
    a leaf being ignored) long before it would indicate an actual hash break."""
    i = data.draw(st.integers(min_value=0, max_value=len(leaves) - 1))
    original_root = merkle_root(leaves)

    mutated = list(leaves)
    b = bytearray(mutated[i])
    b[0] ^= 0xFF  # flip a bit; still a valid 32-byte value
    mutated[i] = bytes(b)

    assert merkle_root(mutated) != original_root


# ---------------------------------------------------------------------------
# Gate 1: accepts well-formed streams, rejects specific known-bad mutations
# ---------------------------------------------------------------------------

@given(lineage_stream())
@settings(max_examples=200)
def test_gate1_accepts_any_well_formed_lineage(stream):
    """The property `test_tamper.py`'s hand-picked examples can only sample:
    for ANY randomly shaped but internally consistent process tree, Gate 1
    passes. If this ever fails, either the generator produced something that
    was never actually well-formed, or Gate 1 rejects something legitimate --
    Hypothesis will shrink to the minimal tree that shows which."""
    events, _ = stream
    result = gate1_verify(events)
    assert result.ok, [str(v) for v in result.violations]


@given(lineage_stream())
@settings(max_examples=150)
def test_gate1_rejects_a_missing_spawn_for_any_topology(stream):
    """Operationalises gate1.py's own claim -- 'hiding an action requires
    hiding a consistent set of events' -- as a fuzzed property instead of one
    hand-picked example. Removing exactly one actor's PROCESS_SPAWN, for ANY
    randomly generated tree and ANY actor within it, must leave a detectable
    trace: either an orphaned child (if the removed actor had one) or an
    exit-without-spawn / unattributed-action symptom for the removed actor
    itself."""
    events, actor_ids = stream
    target = actor_ids[0]  # first-created actor: guaranteed to exist in every draw

    pruned = [e for e in events
              if not (e.event_type is EventType.PROCESS_SPAWN and e.actor_id == target)]

    result = gate1_verify(pruned)
    assert not result.ok, "removing a spawn event must never leave Gate 1 satisfied"


@given(lineage_stream())
@settings(max_examples=150)
def test_gate1_rejects_a_duplicated_spawn_for_any_topology(stream):
    """Caught its own bug on the first run: appending the duplicate at the END
    of the stream lands it AFTER the actor's exit, which Gate 1 correctly
    reports as RESPAWN_AFTER_EXIT rather than DOUBLE_SPAWN -- a different, also
    correct, rejection, but not the one this test claims to check. Inserting
    the duplicate immediately after the original spawn, while the actor is
    still live, is what actually pins down DOUBLE_SPAWN specifically,
    regardless of which randomly generated topology it lands in."""
    events, actor_ids = stream
    target = actor_ids[0]

    idx = next(i for i, e in enumerate(events)
               if e.event_type is EventType.PROCESS_SPAWN and e.actor_id == target)
    dup = dataclasses.replace(events[idx], sequence=0)  # renumbered below
    duplicated = events[:idx + 1] + [dup] + events[idx + 1:]
    # Renumber sequence so it stays dense and strictly increasing -- otherwise
    # the insertion also trips SEQ_GAP as a confound, obscuring which
    # violation is actually being tested.
    duplicated = [dataclasses.replace(e, sequence=i) for i, e in enumerate(duplicated)]

    result = gate1_verify(duplicated)
    assert not result.ok
    assert any(v.code == "DOUBLE_SPAWN" for v in result.violations), \
        [v.code for v in result.violations]
