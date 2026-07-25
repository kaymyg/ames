"""
L0 -- reusable Hypothesis strategies for property-based validation.

Every example-based adversarial test in this repo answers "does the code
handle THIS specific attack a human thought of." That is necessary, and it is
also the exact kind of test an adversary who has read the test file can plan
around: a hand-picked example set is finite and knowable. Property-based
testing asks a different question -- "does this invariant hold for every input
in a class, including ones nobody picked" -- across machine-generated cases on
every run. The two techniques are complementary, not competing; this module
only provides the generators, `tests/test_l0_properties.py` is where the
properties themselves are asserted.

Kept deliberately narrow: strategies here generate STRUCTURALLY valid inputs
(respecting each type's own `__post_init__` constraints) at bounded sizes, not
the full range every field's type nominally allows. A `sequence` field is a
real uint64 in production; generating the full 0..2**64-1 range here would
mostly test integer-formatting edge cases already covered by
`test_conformance.py`'s pinned vectors, at a large cost in wall-clock time for
no corresponding gain in the properties this module actually checks.
"""

from __future__ import annotations

from typing import List, Tuple

from hypothesis import strategies as st

from ames.events import Event, EventType, NO_PARENT

# Bounded well under the real uint64 range -- see module docstring.
_SMALL_UINT = st.integers(min_value=0, max_value=2**32 - 1)
_TINY_UINT = st.integers(min_value=0, max_value=255)

# Event types a fuzzed "ordinary action" may take. Boundary markers and
# lineage events are handled structurally by `lineage_stream`, not chosen at
# random -- a random RUN_BEGIN in the middle of a stream is a real bug class
# (NESTED_RUN_MARKER), but it is already covered by example-based tests in
# `test_tamper.py`, and mixing it into a generic "any event" strategy would
# make most generated streams structurally invalid before the *content*
# fuzzing this module targets ever runs.
_ACTION_TYPES = st.sampled_from([
    EventType.FILE_MUTATION, EventType.NETWORK_REQUEST,
    EventType.TOOL_CALL, EventType.CAPABILITY_REQUEST, EventType.MEMORY_MAP,
])


@st.composite
def st_event(draw, *, actor_id=None, parent_id=None, sequence=None) -> Event:
    """One structurally valid Event, any type, with unconstrained content --
    for round-trip and single-event property tests. Actor/parent/sequence can
    be pinned by the caller (used by `lineage_stream` to keep a whole stream
    internally consistent) or left to be drawn freely."""
    etype = draw(st.sampled_from(list(EventType)))
    seq = sequence if sequence is not None else draw(_SMALL_UINT)
    ts = draw(_SMALL_UINT)
    actor = actor_id if actor_id is not None else draw(_SMALL_UINT.filter(lambda v: v != NO_PARENT))
    parent = parent_id if parent_id is not None else draw(st.one_of(st.just(NO_PARENT), _SMALL_UINT))
    payload = draw(st.binary(max_size=64))
    return Event(etype, seq, ts, actor, parent, payload)


@st.composite
def digest_list(draw, *, min_size=0, max_size=40) -> List[bytes]:
    """A list of 32-byte "digests" for merkle strategy tests. Not real BLAKE3
    outputs -- merkle_root/merkle_proof only require the right length, and
    generating arbitrary 32-byte strings exercises the tree-shape logic
    (pairing, odd-node promotion) independently of hash content."""
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    return [draw(st.binary(min_size=32, max_size=32)) for _ in range(n)]


@st.composite
def lineage_stream(draw, *, max_actors=6) -> Tuple[List[Event], List[int]]:
    """A structurally well-formed event stream: RUN_BEGIN, a randomly shaped
    but internally consistent process tree (every spawn's parent was spawned
    earlier, every actor that spawns also exits, interspersed action events
    only while their actor is live), RUN_END.

    Returns (events, actor_ids) so a property test can pick a real actor id to
    remove/duplicate/reorder -- `test_gate1_rejects_a_missing_spawn` and
    similar tests need to break something that was genuinely there, not a
    hand-picked value that might not exist in a given draw.

    Deliberately simple in TOPOLOGY (a random forest, actors created in a
    valid parent-before-child order, exited in reverse creation order) rather
    than trying to generate every legal interleaving Gate 1 would accept. The
    invariant this checks -- Gate 1 accepts well-formed streams and rejects
    ones with a piece removed -- does not depend on covering every legal
    interleaving, only on the generated streams actually being legal ones.
    """
    n_actors = draw(st.integers(min_value=1, max_value=max_actors))
    seq = 0
    ts = 0
    events: List[Event] = []

    def emit(etype: EventType, actor: int, parent: int = NO_PARENT) -> None:
        nonlocal seq, ts
        events.append(Event(etype, seq, ts, actor, parent, b""))
        seq += 1
        ts += draw(st.integers(min_value=0, max_value=5))

    emit(EventType.RUN_BEGIN, 0xFFFFFFFF)  # boundary marker actor id is unchecked by Gate 1

    actor_ids = list(range(1, n_actors + 1))
    parents: List[int] = []
    for a in actor_ids:
        # Parent is NO_PARENT or any actor already created -- guarantees the
        # parent was spawned earlier, so ORPHAN_SPAWN cannot occur.
        parent = draw(st.sampled_from([NO_PARENT] + parents)) if parents else NO_PARENT
        parents.append(a)
        emit(EventType.PROCESS_SPAWN, a, parent)
        # A random action or two while this actor is live.
        for _ in range(draw(st.integers(min_value=0, max_value=2))):
            etype = draw(_ACTION_TYPES)
            emit(etype, a)

    for a in reversed(actor_ids):
        emit(EventType.PROCESS_EXIT, a)

    emit(EventType.RUN_END, 0xFFFFFFFF)

    return events, actor_ids
