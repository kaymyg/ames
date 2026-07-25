"""
AMES-V1 Gate 1 -- structural verification.

Direct generalisation of KAYSentinel's EVM Gate 1. The mapping is exact:

    EVM call frame          ->  OS process
    frame enter / exit      ->  PROCESS_SPAWN / PROCESS_EXIT
    frame balance           ->  process lineage balance
    block/tx encapsulation  ->  RUN_BEGIN / RUN_END encapsulation
    sequence monotonicity   ->  sequence monotonicity (unchanged)

Gate 1 answers exactly one question: is this event stream STRUCTURALLY
well-formed? It says nothing about whether the actions were permitted -- that is
a later gate's job. Keeping the two separate matters, because a structurally
broken stream cannot be meaningfully policy-evaluated at all: if the lineage
graph has orphans, "which process did this" has no answer, and every downstream
attribution is guesswork.

An adversary who suppresses its own PROCESS_SPAWN event to hide a child process
leaves an orphan behind. That is the invariant doing real work: hiding an action
requires hiding a consistent *set* of events, and the balance check makes any
partial omission visible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ames.events import Event, EventType, NO_PARENT


@dataclass
class Violation:
    code: str
    sequence: Optional[int]
    detail: str

    def __str__(self) -> str:
        loc = f"seq={self.sequence}" if self.sequence is not None else "stream"
        return f"[{self.code}] {loc}: {self.detail}"


@dataclass
class Gate1Result:
    ok: bool
    violations: List[Violation] = field(default_factory=list)

    def raise_if_failed(self) -> None:
        if not self.ok:
            raise Gate1Error("Gate 1 failed:\n  " + "\n  ".join(str(v) for v in self.violations))


class Gate1Error(Exception):
    """Structural verification failure. Deliberately a dedicated type so it
    cannot be caught by a generic handler intended for parse errors."""


def verify(events: Sequence[Event], *, require_run_markers: bool = True) -> Gate1Result:
    """Run every structural invariant. Collects all violations rather than
    stopping at the first: during an incident you want the whole picture, and
    a single root cause often produces several distinct symptoms."""
    v: List[Violation] = []

    if not events:
        return Gate1Result(ok=True)

    # --- I1: sequence dense and strictly increasing -------------------------
    expected = events[0].sequence
    for ev in events:
        if ev.sequence != expected:
            v.append(Violation(
                "SEQ_GAP", ev.sequence,
                f"expected {expected}; a gap means an event was dropped or withheld",
            ))
            expected = ev.sequence
        expected += 1

    # --- I2: timestamps non-decreasing --------------------------------------
    # Equal timestamps are permitted (clock granularity); going backwards is not.
    last_ts = events[0].timestamp_ns
    for ev in events:
        if ev.timestamp_ns < last_ts:
            v.append(Violation(
                "TIME_REGRESSION", ev.sequence,
                f"timestamp {ev.timestamp_ns} < previous {last_ts}",
            ))
        last_ts = max(last_ts, ev.timestamp_ns)

    # --- I3: run encapsulation ----------------------------------------------
    if require_run_markers:
        if events[0].event_type is not EventType.RUN_BEGIN:
            v.append(Violation("NO_RUN_BEGIN", events[0].sequence,
                               "stream must open with RUN_BEGIN"))
        if events[-1].event_type is not EventType.RUN_END:
            v.append(Violation("NO_RUN_END", events[-1].sequence,
                               "stream must close with RUN_END (a missing close "
                               "is what a truncated log looks like)"))
        interior = [e for e in events[1:-1]
                    if e.event_type in (EventType.RUN_BEGIN, EventType.RUN_END)]
        for e in interior:
            v.append(Violation("NESTED_RUN_MARKER", e.sequence,
                               f"{e.event_type.name} inside an open run"))

    # --- I4: process lineage balance ----------------------------------------
    live: Dict[int, int] = {}          # actor_id -> spawn sequence
    exited: Dict[int, int] = {}        # actor_id -> exit sequence

    for ev in events:
        if ev.event_type is EventType.PROCESS_SPAWN:
            if ev.actor_id in live:
                v.append(Violation("DOUBLE_SPAWN", ev.sequence,
                                   f"actor {ev.actor_id} already live "
                                   f"(spawned at seq={live[ev.actor_id]})"))
            elif ev.actor_id in exited:
                v.append(Violation("RESPAWN_AFTER_EXIT", ev.sequence,
                                   f"actor {ev.actor_id} exited at "
                                   f"seq={exited[ev.actor_id]}; ids are not reusable"))
            else:
                if ev.parent_id != NO_PARENT and ev.parent_id not in live:
                    v.append(Violation(
                        "ORPHAN_SPAWN", ev.sequence,
                        f"parent {ev.parent_id} of actor {ev.actor_id} is not live -- "
                        f"a hidden intermediate process, or a suppressed spawn event",
                    ))
                live[ev.actor_id] = ev.sequence

        elif ev.event_type is EventType.PROCESS_EXIT:
            if ev.actor_id not in live:
                v.append(Violation("EXIT_WITHOUT_SPAWN", ev.sequence,
                                   f"actor {ev.actor_id} exited but was never spawned"))
            else:
                exited[ev.actor_id] = ev.sequence
                del live[ev.actor_id]

        elif ev.event_type in (EventType.RUN_BEGIN, EventType.RUN_END):
            pass   # boundary markers act outside the lineage graph

        else:
            # Any other action must be attributable to a live actor.
            if ev.actor_id not in live:
                if ev.actor_id in exited:
                    v.append(Violation("ACTION_AFTER_EXIT", ev.sequence,
                                       f"actor {ev.actor_id} acted after exiting at "
                                       f"seq={exited[ev.actor_id]}"))
                else:
                    v.append(Violation("UNATTRIBUTED_ACTION", ev.sequence,
                                       f"{ev.event_type.name} by actor {ev.actor_id}, "
                                       f"which was never spawned"))

    # --- I5: no process left running at close -------------------------------
    for actor_id, seq in sorted(live.items()):
        v.append(Violation(
            "UNTERMINATED_ACTOR", seq,
            f"actor {actor_id} spawned but never exited -- a dormant process is "
            f"how persistence survives a run boundary",
        ))

    return Gate1Result(ok=not v, violations=v)
