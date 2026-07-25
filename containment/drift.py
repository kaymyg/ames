"""
L6 -- Cognitive Drift Detection.

LAST IN THE BUILD ORDER, AND ADVISORY ONLY -- BOTH FOR THE SAME REASON

Every other layer in this framework (L1, L2, L5, L7, L9) was built around one
discipline, restated in each of their docstrings: only trust what the HOST
observed directly. `killswitch.Evidence.from_run` filters to the host actor
band. L5's fingerprint is built exclusively from the broker's own decisions.
L7 classifies filesystem writes, not filesystem claims. This layer breaks that
discipline on purpose, because there is no host-observable substrate for
"what did the agent think it was doing" -- no hypervisor-level signal captures
intent. Reading it at all means reading testimony, and `multi-agent-mcl`'s
concealment dimension exists specifically to model an agent that shapes its
own testimony to look benign while acting otherwise. So this is necessarily
the layer built last, on top of everything that can be trusted, and it is
necessarily advisory: a signal built from testimony cannot be allowed to kill
a run the way L9's host-observed evidence can.

WHAT THIS DOES NOT DO

It does not judge the CONTENT of a reasoning trace -- "does this plan sound
adversarial" is unfalsifiable without an LLM judge, and an LLM judge is itself
just another model that can be misled by the same adversary it is meant to
catch. Nothing in this codebase makes that call, and this module does not
either.

WHAT IT DOES INSTEAD: NARRATIVE VS. EVIDENCE

`transport.GUEST_PERMITTED` allows a guest to submit its own CAPABILITY_REQUEST
claims over vsock -- a self-report channel, architecturally separate from the
real request/decision cycle the broker (L2) mediates. Nothing forces the two to
agree: a guest could narrate a capability it never actually asked the broker
for, or exercise one through the broker and never mention it in its own
account. Comparing the two -- host-attributed broker decisions (evidence)
against guest-attributed self-reports (testimony) -- is what this module does,
classified three ways:

  UNNARRATED        The host recorded a decision for a capability; the
                     guest's own account never mentioned it at all.
  UNCONFIRMED        The guest narrated requesting a capability; the host has
                     no matching decision for it whatsoever.
  OUTCOME_MISMATCH   Both sides have it, but the guest claims an outcome
                     (granted/denied) that never occurred on the host side for
                     that capability.

A DOCUMENTED LIMIT: ABSENCE OF DRIFT PROVES NOTHING

The guest directly receives the broker's real answer to any request it
actually makes -- the request/response cycle is not blind to it. A guest that
simply copies what it already witnessed into its self-report channel will
always produce a perfect match, trivially, whether or not it is doing anything
else the framework should worry about. So a clean `DriftMonitor.evaluate()`
result is not evidence of good behaviour; it only shows the guest bothered to
keep its story consistent with what it directly observed. The value here is
entirely in the POSITIVE case -- catching inconsistency when a guest is sloppy
or is narrating something it did not verify against its own request history --
not in providing assurance when none appears. This is the same shape of limit
AMES documents for a compromised producer that can omit events: the mechanism
proves tampering when it is present, not its absence.

VERIFIED HERE: extraction of the host and guest streams from a raw ledger,
classification of the three drift reasons, and the "trivial echo" property
above, against adversarial and legitimate narratives.
NOT VERIFIED HERE: anything about the semantic truth of a reasoning trace, and
no code path here can deny a capability, stop a run, or feed a kill decision.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Set

from ames.events import Capability, EventType
from containment.fingerprint import BehaviorObservation, observations_from_ledger
from containment.vmspec import is_host_observed


class DriftReason(enum.Enum):
    UNNARRATED       = "unnarrated"        # host decided it; guest never mentioned it
    UNCONFIRMED      = "unconfirmed"       # guest narrated it; host has no matching decision
    OUTCOME_MISMATCH = "outcome_mismatch"  # both sides have it, outcomes disagree


@dataclass(frozen=True)
class DriftFinding:
    capability: Capability
    reason: DriftReason
    detail: str = ""


def narrative_from_ledger(events: Iterable) -> List[BehaviorObservation]:
    """The guest's own account of what it asked for: CAPABILITY_REQUEST claims
    it submitted itself, over the same self-report channel a sloppy or
    deliberately misleading guest would use.

    The mirror image of `fingerprint.observations_from_ledger`, which this
    module deliberately imports and reuses for the host side rather than
    reimplementing decode logic a third time -- the two extractors differ only
    in which side of `is_host_observed()` they keep, which is precisely the
    distinction this whole layer is built on. Never merge their outputs: one
    is evidence, the other is testimony, and conflating them would erase the
    only thing this module measures.
    """
    out: List[BehaviorObservation] = []
    for ev in events:
        if is_host_observed(ev.actor_id):
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


class DriftMonitor:
    """Compares host-observed evidence against the guest's own narrative of
    the same run. Produces `DriftFinding`s; enforces nothing."""

    def evaluate(self, *, host: Sequence[BehaviorObservation],
                 guest: Sequence[BehaviorObservation]) -> List[DriftFinding]:
        """Classify the gap between the two streams, one capability at a
        time. Correlation is by capability, not by individual request: the
        wire format carries no request id, so pairing a specific guest claim
        to a specific host decision one-to-one is not something this can
        honestly claim to do. Comparing the SET of outcomes recorded per
        capability on each side is the strongest claim the data supports.
        """
        host_outcomes: Dict[Capability, Set[bool]] = {}
        for o in host:
            host_outcomes.setdefault(o.capability, set()).add(o.granted)

        guest_outcomes: Dict[Capability, Set[bool]] = {}
        for o in guest:
            guest_outcomes.setdefault(o.capability, set()).add(o.granted)

        findings: List[DriftFinding] = []
        all_caps = sorted(set(host_outcomes) | set(guest_outcomes), key=lambda c: c.value)

        for cap in all_caps:
            h = host_outcomes.get(cap)
            g = guest_outcomes.get(cap)

            if h is not None and g is None:
                findings.append(DriftFinding(
                    cap, DriftReason.UNNARRATED,
                    f"host recorded outcome(s) {sorted(h)} for {cap.name}; "
                    f"the guest's own account never mentioned requesting it",
                ))
            elif g is not None and h is None:
                findings.append(DriftFinding(
                    cap, DriftReason.UNCONFIRMED,
                    f"guest narrated outcome(s) {sorted(g)} for {cap.name}; "
                    f"the host has no matching decision at all",
                ))
            else:
                # Both sides have it. Flag any guest-claimed outcome that
                # never occurred on the host side for this capability.
                impossible = g - h
                if impossible:
                    findings.append(DriftFinding(
                        cap, DriftReason.OUTCOME_MISMATCH,
                        f"guest claimed outcome(s) {sorted(impossible)} for {cap.name} "
                        f"that the host never recorded (host saw {sorted(h)})",
                    ))

        return findings

    def evaluate_ledger(self, events: Iterable) -> List[DriftFinding]:
        """Convenience: extract both streams from one raw ledger and evaluate
        in a single call. `events` is consumed into a list first because both
        extractors need an independent pass over it."""
        materialised = list(events)
        return self.evaluate(
            host=observations_from_ledger(materialised),
            guest=narrative_from_ledger(materialised),
        )
