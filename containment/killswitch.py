"""
L9 -- Autonomous Kill System.

Two departures from the original design, both load-bearing.

FIRST: RULES COME IN TWO CLASSES, NOT ONE.

The original specification was a flat list of hardcoded thresholds -- privilege
escalation, unexpected process, dormant process, repeated denials -- each firing
a kill. Against the threat model the framework itself assumes (adaptive, patient,
perfect memory, and able to READ THIS FILE) a flat threshold list is a map of
exactly how far to go without being stopped. An adversary paces one request under
every limit, indefinitely.

So conditions are split by what they actually mean:

  ABSOLUTE      Never legitimate under any circumstances. One occurrence is
                proof, so there is no threshold to pace under and no window to
                wait out. A write to a read-only region is not "a lot of risk",
                it is an invariant that did not hold.

  ACCUMULATING  Individually plausible, suspicious in aggregate. These carry
                BOTH a burst trigger and an EWMA, because a burst check alone is
                blind to the patient enumeration that is the whole point of the
                threat model. Same fix as L2's denial tracker, and the same one
                the multi-agent-mcl work arrived at independently.

SECOND: THE KILLER READS ONLY HOST-OBSERVED EVIDENCE.

"No LLM decides, no policy engine decides" is necessary but not sufficient. If a
kill can be computed from guest-reported claims then a compromised guest has two
attacks: stay quiet to avoid tripping it, or fabricate claims to trip it against
a legitimate run and deny service to the operator. `Evidence.from_run` therefore
filters to the host-observed actor band before anything is counted, and tests
assert that guest claims can neither cause nor prevent a kill.

FAIL CLOSED. If the evaluator itself raises, the verdict is KILL. An exception in
the safety system must never mean "carry on" -- that is how a monitoring bug
becomes a containment bypass.

There is deliberately no disable, no override, no threshold setter and no way to
register a predicate at runtime. The rules are frozen module constants. An
adversary who can add a rule can add one that never fires.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from ames.events import Capability, EventType
# The tracker is a generic burst+EWMA rate detector; it is named for its first
# use in L2. Reused here rather than reimplemented so there is one
# implementation of this logic in the codebase, already under test.
from containment.broker import DenialSignal, DenialTracker as RateTrigger
from containment.envstate import EnvironmentMonitor, MutationVerdict
from containment.vmspec import is_host_observed


class KillReason(enum.Enum):
    # --- absolute: one occurrence is proof ---------------------------------
    CONTAINMENT_FAILURE   = "containment_failure"     # read-only region changed
    PRIVILEGE_ESCALATION  = "privilege_escalation"    # a priv raise was granted
    UNATTRIBUTED_ACTION   = "unattributed_action"     # Gate 1 lineage break
    DORMANT_PROCESS       = "dormant_process"         # actor alive past RUN_END
    EVALUATOR_FAILURE     = "evaluator_failure"       # fail-closed

    # --- accumulating: plausible alone, not in aggregate --------------------
    DENIAL_BURST          = "denial_burst"
    DENIAL_SUSTAINED      = "denial_sustained"
    MUTATION_BURST        = "unexplained_mutation_burst"
    MUTATION_SUSTAINED    = "unexplained_mutation_sustained"


ABSOLUTE_REASONS = frozenset({
    KillReason.CONTAINMENT_FAILURE,
    KillReason.PRIVILEGE_ESCALATION,
    KillReason.UNATTRIBUTED_ACTION,
    KillReason.DORMANT_PROCESS,
    KillReason.EVALUATOR_FAILURE,
})

# Gate 1 violation codes that are absolute kills rather than report-only.
# Each means the lineage graph is broken, so attribution is guesswork and no
# later judgement about "who did this" can be trusted.
FATAL_GATE1_CODES = frozenset({
    "UNATTRIBUTED_ACTION", "ACTION_AFTER_EXIT", "ORPHAN_SPAWN",
    "EXIT_WITHOUT_SPAWN", "DOUBLE_SPAWN", "RESPAWN_AFTER_EXIT",
})


@dataclass(frozen=True)
class Evidence:
    """Host-observed facts only. Never guest testimony.

    Construct via `from_run` rather than by hand in production: the filtering is
    the security property, and a hand-built Evidence can assert anything.
    """
    containment_failed: bool = False
    fatal_gate1_codes: Tuple[str, ...] = ()
    dormant_actors: int = 0
    privilege_escalation_granted: bool = False
    denial_signal: Optional[DenialSignal] = None
    unexplained_mutations: int = 0
    guest_claims_seen: int = 0          # recorded for context, never evaluated

    @staticmethod
    def from_run(*, monitor: Optional[EnvironmentMonitor] = None,
                 gate1_violation_codes: Iterable[str] = (),
                 broker_history: Iterable = (),
                 denial_signal: Optional[DenialSignal] = None,
                 ledger_events: Iterable = ()) -> "Evidence":
        """Assemble evidence, discarding anything the guest could have authored.

        Every input here is produced by a host-side component: L7's monitor, L8's
        Gate 1 over the ledger, L2's broker. Ledger events are filtered to the
        host-observed actor band, so a guest that floods claims changes only
        `guest_claims_seen`, which nothing evaluates.
        """
        host_events, guest_events = [], 0
        for ev in ledger_events:
            if is_host_observed(ev.actor_id):
                host_events.append(ev)
            else:
                guest_events += 1

        priv_granted = False
        for ev in host_events:
            if ev.event_type is EventType.CAPABILITY_REQUEST and len(ev.payload) >= 2:
                cap, granted = ev.payload[0], ev.payload[1]
                if cap == int(Capability.PRIVILEGE_RAISE) and granted == 1:
                    priv_granted = True

        # A granted privilege raise should be impossible: L2 lists it in
        # NEVER_IN_RUN. Seeing one recorded means the policy engine was bypassed
        # or replaced, which is itself the emergency.
        for dec in broker_history:
            if (dec.request.capability is Capability.PRIVILEGE_RAISE
                    and dec.verdict.granted):
                priv_granted = True

        codes = tuple(c for c in gate1_violation_codes if c in FATAL_GATE1_CODES)
        dormant = sum(1 for c in gate1_violation_codes if c == "UNTERMINATED_ACTOR")

        unexplained = 0
        contained_failed = False
        if monitor is not None:
            contained_failed = monitor.containment_failed
            unexplained = len(monitor.by_verdict(MutationVerdict.UNEXPLAINED))

        return Evidence(
            containment_failed=contained_failed,
            fatal_gate1_codes=codes,
            dormant_actors=dormant,
            privilege_escalation_granted=priv_granted,
            denial_signal=denial_signal,
            unexplained_mutations=unexplained,
            guest_claims_seen=guest_events,
        )


@dataclass(frozen=True)
class KillVerdict:
    kill: bool
    reasons: Tuple[KillReason, ...]
    detail: str = ""

    @property
    def absolute(self) -> bool:
        """True if any reason is one that needs no accumulation."""
        return any(r in ABSOLUTE_REASONS for r in self.reasons)


class KillSwitch:
    """Evaluates host-observed evidence and decides whether to stop.

    Deliberately exposes no way to disable, override, add a rule, or move a
    threshold after construction. Thresholds are constructor arguments so an
    operator can tune sensitivity for an environment; they cannot be changed
    while a run is in flight, and no argument can switch a rule off.
    """

    def __init__(self, *, mutation_burst: int = 3, mutation_window_s: float = 60.0,
                 mutation_ewma_threshold: float = 0.30) -> None:
        # Independent of L2's denial tracker: unexplained mutations and denied
        # requests are different signals and should not share a budget.
        self._mutation_trigger = RateTrigger(
            window_seconds=mutation_window_s,
            burst_threshold=mutation_burst,
            ewma_threshold=mutation_ewma_threshold,
        )
        self._tripped = False
        self._verdict: Optional[KillVerdict] = None

    # --- evaluation ---------------------------------------------------------

    def evaluate(self, evidence: Evidence) -> KillVerdict:
        """Total. Any internal failure yields KILL, never a pass."""
        try:
            reasons: List[KillReason] = []
            details: List[str] = []

            # --- absolute ---------------------------------------------------
            if evidence.containment_failed:
                reasons.append(KillReason.CONTAINMENT_FAILURE)
                details.append("a read-only region was modified; an L1 invariant did not hold")

            if evidence.privilege_escalation_granted:
                reasons.append(KillReason.PRIVILEGE_ESCALATION)
                details.append("a privilege raise was granted, which L2 lists as never grantable")

            if evidence.fatal_gate1_codes:
                reasons.append(KillReason.UNATTRIBUTED_ACTION)
                details.append(
                    "lineage broken (" + ", ".join(sorted(set(evidence.fatal_gate1_codes)))
                    + "); attribution is guesswork once the graph has holes"
                )

            if evidence.dormant_actors > 0:
                reasons.append(KillReason.DORMANT_PROCESS)
                details.append(
                    f"{evidence.dormant_actors} actor(s) alive past RUN_END; a dormant "
                    f"process is how persistence survives a run boundary"
                )

            # --- accumulating ----------------------------------------------
            sig = evidence.denial_signal
            if sig is not None:
                if sig.instantaneous:
                    reasons.append(KillReason.DENIAL_BURST)
                    details.append(f"denial burst: {sig.detail or sig.recent_denials}")
                if sig.cumulative:
                    reasons.append(KillReason.DENIAL_SUSTAINED)
                    details.append(f"sustained denial rate {sig.ewma:.3f} (patient enumeration)")

            if evidence.unexplained_mutations:
                m = None
                for _ in range(evidence.unexplained_mutations):
                    m = self._mutation_trigger.record(denied=True, now=self._tick())
                if m is not None:
                    if m.instantaneous:
                        reasons.append(KillReason.MUTATION_BURST)
                        details.append(f"{m.recent_denials} unexplained mutations in window")
                    if m.cumulative:
                        reasons.append(KillReason.MUTATION_SUSTAINED)
                        details.append(f"sustained unexplained-mutation rate {m.ewma:.3f}")

            verdict = KillVerdict(bool(reasons), tuple(reasons), "; ".join(details))

        except Exception as exc:                       # noqa: BLE001 -- deliberate
            # An exception in the safety system must not mean "carry on".
            verdict = KillVerdict(
                True, (KillReason.EVALUATOR_FAILURE,),
                f"kill evaluator raised {type(exc).__name__}: {exc}; failing closed",
            )

        if verdict.kill:
            self._tripped = True
            self._verdict = verdict
        return verdict

    def _tick(self) -> float:
        # Monotonic counter rather than wall clock: the trigger only needs
        # ordering, and a clock the guest could influence is an input the guest
        # could influence.
        self._counter = getattr(self, "_counter", 0.0) + 1.0
        return self._counter

    # --- state --------------------------------------------------------------

    @property
    def tripped(self) -> bool:
        """Once tripped, always tripped. A kill is not reconsidered: the
        condition that caused it may not recur, and 'it stopped happening' is
        exactly what a successful attacker produces."""
        return self._tripped

    @property
    def verdict(self) -> Optional[KillVerdict]:
        return self._verdict


def kill_payload(verdict: KillVerdict) -> bytes:
    """Encode a kill decision for the ledger as a denied capability.

    Recorded as host-observed: the host decided, so it is evidence rather than
    testimony, and survives a compromised guest.
    """
    from ames.canonical import payload_capability_request
    reasons = ",".join(r.value for r in verdict.reasons)
    return payload_capability_request(
        Capability.PROCESS_SPAWN, False, f"KILL[{reasons}] {verdict.detail}"[:512]
    )
