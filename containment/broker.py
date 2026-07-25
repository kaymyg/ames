"""
L2 -- Zero External Trust: the broker.

Sits on the HOST, beside the L1 supervisor and the L8 ledger producer, for the
same reason both of those do: anything inside the isolation perimeter is inside
the adversary's blast radius, and the July 2026 escape compromised precisely the
component trusted to bridge in and out.

The broker's job is narrow on purpose:

    receive a structured request  ->  evaluate against a frozen policy
                                  ->  record the decision as HOST-OBSERVED
                                  ->  return a verdict

It performs no I/O on the agent's behalf. It fetches nothing, resolves nothing,
connects to nothing. It writes a row and returns an answer. That is the whole
difference between a broker and a proxy.

DENIALS ARE THE PRODUCT, NOT THE FAILURE MODE.
A denied request is a recorded observation about what the agent tried to reach
for, and a burst of them is one of the strongest available escape-probing
signals. An agent methodically enumerating capabilities looks exactly like a
rising denial rate, so denials are counted with both an instantaneous and an
accumulating trigger and surfaced for L9.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, List, Optional, Tuple

from ames.canonical import payload_capability_request
from ames.events import Capability, EventType
from containment.policy import (
    CapabilityPolicy, CapabilityRequest, Decision, PolicyVerdict, default_policy,
)


@dataclass
class DenialSignal:
    """What the broker hands upward when refusals start to look like probing."""
    tripped: bool
    instantaneous: bool
    cumulative: bool
    recent_denials: int
    ewma: float
    detail: str = ""


class DenialTracker:
    """Counts refusals with two independent triggers.

    A single rate threshold is pace-able: an adversary with patience simply
    stays one request under it, forever. That is the same 'boil the frog'
    evasion the multi-agent-mcl work identified, and the fix is the same one --
    pair the instantaneous check with an accumulating EWMA that a slow, steady
    probe still drives upward.

    Neither trigger alone is sufficient. The burst check catches a fast sweep;
    the EWMA catches the patient enumeration that the burst check is blind to.
    """

    def __init__(self, *, window_seconds: float = 60.0, burst_threshold: int = 5,
                 ewma_alpha: float = 0.15, ewma_threshold: float = 0.35) -> None:
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.ewma_alpha = ewma_alpha
        self.ewma_threshold = ewma_threshold
        self._denial_times: Deque[float] = deque()
        self._ewma: float = 0.0

    def record(self, *, denied: bool, now: float) -> DenialSignal:
        # EWMA over every decision, allowed or not, so it measures the *rate* of
        # refusal rather than a raw count. Updated on allows too -- otherwise an
        # agent could dilute the signal by interleaving harmless requests.
        self._ewma = self.ewma_alpha * (1.0 if denied else 0.0) + (1 - self.ewma_alpha) * self._ewma

        if denied:
            self._denial_times.append(now)
        while self._denial_times and now - self._denial_times[0] > self.window_seconds:
            self._denial_times.popleft()

        recent = len(self._denial_times)
        inst = recent >= self.burst_threshold
        cum = self._ewma >= self.ewma_threshold

        detail = ""
        if inst:
            detail = f"{recent} denials in {self.window_seconds:g}s (burst)"
        elif cum:
            detail = f"sustained denial rate {self._ewma:.3f} (patient enumeration)"

        return DenialSignal(inst or cum, inst, cum, recent, self._ewma, detail)

    @property
    def ewma(self) -> float:
        return self._ewma


@dataclass
class BrokerDecision:
    request: CapabilityRequest
    verdict: PolicyVerdict
    signal: DenialSignal


class Broker:
    """Host-side capability broker.

    `emit` receives host-observed AMES events. Decisions are host observations,
    not guest claims: the host made them, so they are evidence rather than
    testimony, and an analyst can rely on them even if the guest is compromised.
    """

    def __init__(self, policy: Optional[CapabilityPolicy] = None, *,
                 emit: Optional[Callable[[EventType, bytes], None]] = None,
                 tracker: Optional[DenialTracker] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.policy = policy if policy is not None else default_policy()
        self._emit = emit
        self._tracker = tracker or DenialTracker()
        self._clock = clock
        self.history: List[BrokerDecision] = []

    def request(self, req: CapabilityRequest) -> BrokerDecision:
        """Evaluate one request. Never performs the requested action."""
        verdict = self.policy.evaluate(req)

        # DEFER counts as a denial for signalling purposes: from the agent's
        # side nothing was granted, and repeated deferrals are the same probing
        # shape as repeated refusals.
        denied = verdict.decision is not Decision.ALLOW
        signal = self._tracker.record(denied=denied, now=self._clock())

        if self._emit is not None:
            # Every decision is recorded, including allows. A ledger that only
            # holds refusals cannot answer "what was this agent permitted to do",
            # which is the question an incident review actually opens with.
            self._emit(
                EventType.CAPABILITY_REQUEST,
                payload_capability_request(
                    req.capability,
                    verdict.granted,
                    f"{verdict.decision.value}: {verdict.reason}"[:512],
                ),
            )

        decision = BrokerDecision(req, verdict, signal)
        self.history.append(decision)
        return decision

    # --- reporting ----------------------------------------------------------

    @property
    def denial_count(self) -> int:
        return sum(1 for d in self.history if not d.verdict.granted)

    @property
    def deferred_count(self) -> int:
        return sum(1 for d in self.history
                   if d.verdict.decision is Decision.DEFER_TO_REBUILD)

    def pending_rebuild(self) -> List[str]:
        """Approved dependencies awaiting an image rebuild.

        This is the handoff to L1: a human reviews the list, rebuilds the
        measured rootfs with those pinned artifacts, and the next run starts from
        an image that already contains them. Nothing is ever added to a VM that
        is currently running.
        """
        seen: List[str] = []
        for d in self.history:
            if d.verdict.decision is Decision.DEFER_TO_REBUILD:
                if d.request.resource not in seen:
                    seen.append(d.request.resource)
        return seen
