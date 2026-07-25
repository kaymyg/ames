"""
L5 -- Behavioural Fingerprinting.

THE QUESTION THIS LAYER ANSWERS IS NARROWER THAN IT SOUNDS

L2 asks "is this capability ever allowed". L7 asks "did a read-only invariant
break". L9 asks "did an absolute rule fire, or did an accumulating one cross its
line". None of them ask the question that catches an agent doing something it
has never done before while staying inside every rule those layers enforce: does
this SHAPE of behaviour look like what this agent normally does. That is what
L5 is for, and it is deliberately the only layer in this framework that produces
an opinion rather than a verdict.

WHY THE SUBSTRATE IS THE CAPABILITY STREAM, AND NOTHING ELSE

The obvious design fingerprints the agent's own reported actions -- TOOL_CALL
arguments, NETWORK_REQUEST destinations, the shape of what it claims to be
doing. That design is worthless against this framework's stated threat model: an
adaptive adversary with unlimited patience and perfect memory, able to read this
file. Guest-reported events are testimony the guest authored. An adversary that
knows its telemetry is being fingerprinted simply shapes what it claims to match
whatever profile it expects to be compared against -- the same way a fraud
model trained on self-reported features gets gamed by whoever can see the
features.

CAPABILITY_REQUEST events are different in kind, not just in degree. They are
not claims -- they are the BROKER's own record (L2, host-side) of a decision it
made, attributed to the host actor band and timestamped by the host's clock.
Section `observations_from_ledger` below filters to `is_host_observed()` first,
for exactly the reason `killswitch.Evidence.from_run` does: a guest cannot
fabricate what was recorded as asked of the broker, cannot avoid going through
the broker for anything gated (L1 removed every other path out), and cannot
forge the host's timestamp. An adversary can still choose WHAT to ask for and
WHEN -- it cannot choose what gets written down about that choice.

FROZEN BASELINE, SAME REASON AS L7

A detector that keeps learning from live traffic is a detector an adversary can
walk, one plausible-looking step at a time, until the attack itself is inside
the "normal" region. `BehaviorFingerprint` absorbs reference runs, then seals;
after `seal()` nothing can be added. The baseline is a statement about the past,
never a moving target.

WHAT GETS COMPARED

1. Capability set -- has this exact capability ever been requested in any
   reference run. A first-time capability is the strongest signal available:
   it needs no statistics, only set membership.
2. Transitions -- has this exact (previous capability -> this capability) pair
   ever occurred, WITHIN a single reference run (never synthesised across the
   boundary between two runs, which would invent adjacency that never happened).
   This catches reordering and novel sequencing even when every individual
   capability in the sequence is one the agent has used before.
3. Cadence -- inter-request timing, pooled across all reference runs into one
   mean/stddev, compared by z-score. This catches requests fired far faster or
   far slower than the agent's history, which a pure set/transition check is
   blind to.

ADVISORY, NOT ENFORCING. Nothing here can deny a capability, stop a run, or
feed a kill decision by itself. A `SequenceVerdict` is evidence weighed by a
human or wired into L9 as a non-absolute input -- a deployment decision this
module deliberately does not make. Treating a first "novel" observation as
proof of compromise would mean the framework breaks the first time an operator
does anything new, which makes the framework something people route around
rather than something that holds.

A KNOWN, DOCUMENTED LIMIT

An adversary who knows the baseline's cadence statistics can pace requests at
exactly the historical mean and evade the cadence check entirely -- this is the
same "boil the frog" shape L2's denial tracker and L9's mutation trigger both
defend against with an EWMA, and there is deliberately no equivalent trick
available here: cadence alone is genuinely gameable this way, once an attacker
has seen (or guessed) the baseline. What that pacing CANNOT do is make a
first-time capability, or a transition the baseline never saw, look like one it
did see -- the set and transition checks have no threshold to pace under. A test
below makes this limit explicit rather than leaving it to be discovered later.

VERIFIED HERE: baseline construction, sealing, extraction of capability set /
transition graph / cadence statistics, and classification of a candidate run,
against adversarial and legitimate reference sets.
NOT VERIFIED HERE: what an operator or L9 does with a flagged verdict, and
whether the pooled reference runs are themselves representative of legitimate
use. A baseline built from a compromised reference run bakes the compromise in
as "normal" -- the same limit every anomaly detector inherits from its training
data, and no amount of code in this file changes that.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from ames.events import Capability, EventType
from containment.vmspec import is_host_observed


class FingerprintError(Exception):
    """Malformed observation, or an operation attempted out of order (mutating
    a sealed baseline, evaluating against an unsealed one). Dedicated type so
    misuse is never confused with a genuine behavioural anomaly."""


@dataclass(frozen=True)
class BehaviorObservation:
    """One host-observed capability decision, in broker order.

    Decoded from a CAPABILITY_REQUEST event's canonical payload
    (`ames.canonical.payload_capability_request`: u8 capability | u8 granted |
    length-prefixed reason). `killswitch.Evidence.from_run` already decodes the
    first two bytes of this exact payload inline for its own purpose; this is
    the second consumer of that shape, not a new format.
    """
    capability: Capability
    granted: bool
    timestamp_ns: int


def observations_from_ledger(events: Iterable) -> List[BehaviorObservation]:
    """Extract the host-observed capability stream from a raw AMES event
    sequence (e.g. `Ledger.events`, or events read back from an exported run).

    Filters to `is_host_observed()` first. A CAPABILITY_REQUEST attributed to a
    guest actor is not decoded at all -- L2's `Broker.request` always emits
    from host-side code, so a guest-attributed one can only mean a forged or
    replayed record, and folding it in would let a compromised guest inflate or
    reshape its own fingerprint, or poison a baseline built from a mixed
    source.

    Malformed entries (truncated payload, unknown capability byte) are skipped
    rather than raising: a single corrupt or forward-versioned record must not
    abort reconstruction of everything around it, the same principle
    `GuestEventReader.read` applies to guest frames.
    """
    out: List[BehaviorObservation] = []
    for ev in events:
        if not is_host_observed(ev.actor_id):
            continue
        if ev.event_type is not EventType.CAPABILITY_REQUEST:
            continue
        if len(ev.payload) < 2:
            continue
        try:
            cap = Capability(ev.payload[0])
        except ValueError:
            continue
        granted = ev.payload[1] == 1
        out.append(BehaviorObservation(cap, granted, ev.timestamp_ns))
    return out


@dataclass(frozen=True)
class SequenceVerdict:
    """Judgement for one observation, relative to the sealed baseline it was
    compared against."""
    novel_capability: bool
    novel_transition: bool
    cadence_outlier: bool
    z_score: Optional[float]
    detail: str = ""

    @property
    def flagged(self) -> bool:
        return self.novel_capability or self.novel_transition or self.cadence_outlier


class BehaviorFingerprint:
    """Reference profile built from one or more trusted runs.

    Mutable only before `seal()`. There is deliberately no method that adds an
    observation after sealing, no `retrain`, no `update` -- the same reasoning
    L7's `EnvironmentBaseline` and L9's `KillSwitch` apply to their own frozen
    state: a reference that can move while it is being compared against is not
    a reference.
    """

    def __init__(self) -> None:
        self._capabilities: Set[Capability] = set()
        self._transitions: Set[Tuple[Capability, Capability]] = set()
        self._intervals_ns: List[int] = []
        self._runs_absorbed = 0
        self._sealed = False

    def absorb(self, observations: Sequence[BehaviorObservation]) -> None:
        """Fold one reference run's observations into the profile.

        Call once per trusted run, before `seal()`. Transitions and intervals
        are computed only WITHIN the given sequence -- absorbing two runs back
        to back never synthesises a transition or a timing gap spanning the
        boundary between them, which would invent adjacency that never
        actually happened.
        """
        if self._sealed:
            raise FingerprintError("baseline is sealed; reference capture happens before sealing")
        if not observations:
            return
        prev: Optional[BehaviorObservation] = None
        for obs in observations:
            self._capabilities.add(obs.capability)
            if prev is not None:
                self._transitions.add((prev.capability, obs.capability))
                gap = obs.timestamp_ns - prev.timestamp_ns
                if gap >= 0:
                    self._intervals_ns.append(gap)
            prev = obs
        self._runs_absorbed += 1

    def seal(self) -> None:
        if self._runs_absorbed == 0:
            raise FingerprintError(
                "cannot seal an empty baseline; absorb at least one reference run first"
            )
        self._sealed = True

    @property
    def sealed(self) -> bool:
        return self._sealed

    @property
    def runs_absorbed(self) -> int:
        return self._runs_absorbed

    @property
    def known_capabilities(self) -> FrozenSet[Capability]:
        return frozenset(self._capabilities)

    def _cadence_stats(self) -> Tuple[float, float, int]:
        """Returns (mean, stddev, sample_count). `sample_count` is what lets
        `evaluate` distinguish "no baseline timing data at all" (n < 2, no
        verdict possible) from "the baseline was perfectly steady" (n >= 2,
        stddev == 0 -- a real, informative outcome, not a missing one)."""
        n = len(self._intervals_ns)
        if n == 0:
            return 0.0, 0.0, 0
        mean = sum(self._intervals_ns) / n
        if n < 2:
            return mean, 0.0, n
        variance = sum((x - mean) ** 2 for x in self._intervals_ns) / (n - 1)
        return mean, math.sqrt(variance), n

    def evaluate(self, observations: Sequence[BehaviorObservation], *,
                 z_threshold: float = 4.0) -> List[Tuple[BehaviorObservation, SequenceVerdict]]:
        """Classify one candidate run against this sealed baseline.

        Returns one (observation, verdict) pair per input observation, in
        order -- the same "list of judged items" shape `EnvironmentMonitor`
        uses for mutations, so a caller can locate exactly which request in
        the run was flagged and why.
        """
        if not self._sealed:
            raise FingerprintError("seal the baseline before evaluating a candidate run")

        mean, stddev, n = self._cadence_stats()
        results: List[Tuple[BehaviorObservation, SequenceVerdict]] = []
        prev: Optional[BehaviorObservation] = None

        for obs in observations:
            novel_cap = obs.capability not in self._capabilities
            novel_trans = False
            cadence_outlier = False
            z: Optional[float] = None
            parts: List[str] = []

            if prev is not None:
                pair = (prev.capability, obs.capability)
                novel_trans = pair not in self._transitions
                gap = obs.timestamp_ns - prev.timestamp_ns
                if gap >= 0 and n >= 2:
                    if stddev > 0:
                        z = (gap - mean) / stddev
                        cadence_outlier = abs(z) >= z_threshold
                    elif gap != mean:
                        # The baseline's timing was perfectly steady -- every
                        # reference interval was identical, so there is no
                        # scale to divide by. That is not "no signal": it is
                        # the strongest possible one, reported as an infinite
                        # z-score (signed toward the direction of deviation)
                        # rather than silently suppressed.
                        cadence_outlier = True
                        z = math.inf if gap > mean else -math.inf
                # n < 2: fewer than two reference intervals exist at all, so
                # there is no baseline timing model to compare against -- not
                # even a degenerate one. No cadence verdict is possible, and
                # none is produced (as opposed to guessing).

            if novel_cap:
                parts.append(
                    f"{obs.capability.name} never requested in "
                    f"{self._runs_absorbed} reference run(s)"
                )
            if novel_trans and prev is not None:
                parts.append(
                    f"transition {prev.capability.name}->{obs.capability.name} "
                    f"not seen in baseline"
                )
            if cadence_outlier and z is not None:
                parts.append(f"inter-request gap z-score {z:.2f} exceeds {z_threshold:g}")

            results.append((
                obs,
                SequenceVerdict(novel_cap, novel_trans, cadence_outlier, z, "; ".join(parts)),
            ))
            prev = obs

        return results
