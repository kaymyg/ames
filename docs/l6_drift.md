# L6 — Cognitive Drift Detection

**Status:** complete. 13 tests. 235 total across the repo.

---

## Last in the build order, advisory only — same reason

Every other layer here (L1, L2, L5, L7, L9) is built around one discipline,
restated in each of their own docs: only trust what the **host** observed
directly. `killswitch.Evidence.from_run` filters to the host actor band. L5's
fingerprint is built exclusively from the broker's own decisions. L7 classifies
filesystem *writes*, not filesystem *claims*.

L6 breaks that discipline on purpose, because there is no host-observable
substrate for "what did the agent think it was doing." No hypervisor-level
signal captures intent. Reading it at all means reading testimony, and
`multi-agent-mcl`'s concealment dimension exists specifically to model an agent
that shapes its own testimony to look benign while acting otherwise. So this is
necessarily the layer built last, on top of everything that *can* be trusted —
and necessarily advisory, because a signal built from testimony cannot be
allowed to kill a run the way L9's host-observed evidence can.

---

## What this deliberately does not do

It does not judge the *content* of a reasoning trace — "does this plan sound
adversarial" is unfalsifiable without an LLM judge, and an LLM judge is just
another model that the same adversary could mislead. Nothing in this codebase
makes that call, and this module doesn't either.

## What it does instead: narrative vs. evidence

`transport.GUEST_PERMITTED` lets a guest submit its own `CAPABILITY_REQUEST`
claims over vsock — a self-report channel, architecturally separate from the
real request/decision cycle the broker (L2) mediates. Nothing forces the two to
agree. `DriftMonitor` compares them:

| Reason | Meaning |
|---|---|
| `UNNARRATED` | Host recorded a decision for a capability; the guest's own account never mentioned it |
| `UNCONFIRMED` | Guest narrated a capability request; the host has no matching decision at all |
| `OUTCOME_MISMATCH` | Both sides have it, but the guest claims an outcome that never occurred on the host side |

Correlation is by capability, not by individual request — the wire format
carries no request id, so claiming exact one-to-one pairing between a specific
guest claim and a specific host decision would overstate what the data
supports. Comparing the *set* of outcomes recorded per capability on each side
is the strongest honest claim, and `test_matching_outcome_among_multiple_host_decisions_is_not_flagged`
exists specifically to prove a guest narrating any outcome that genuinely
occurred — even if the run saw both an allow and a deny for the same
capability — is never wrongly flagged.

---

## A documented limit: absence of drift proves nothing

The guest directly receives the broker's real answer to any request it
actually makes — the request/response cycle isn't blind to it. A guest that
simply copies what it already witnessed into its self-report channel will
always produce a perfect match, trivially, regardless of what else it's doing.
`test_perfect_echo_produces_no_findings` makes this the explicit baseline
rather than an implied assumption.

The value here is entirely in the **positive** case — catching inconsistency
when a guest is sloppy, or narrates something it never verified against its
own request history, or fabricates a favourable-looking claim with no backing
at all (`test_fabricated_favourable_narrative_with_no_host_backing_is_caught`).
It is not in providing assurance when nothing turns up. This is the same shape
of limit AMES documents for a compromised producer that can omit events: the
mechanism proves tampering when it's present, not its absence.

---

## Not guaranteed

- **Anything semantic.** No reasoning-trace content is read or scored here.
- **Assurance from a clean result**, for the reason above.
- **Enforcement.** `DriftFinding`s are advisory. Wiring them to a human review
  queue, or into L9 as a non-absolute input, is a deployment decision this
  module does not make — the same posture L5 takes toward its own
  `SequenceVerdict`.

## Next

**L0**, the adversarial validation engine, is built — see
`docs/l0_validation.md`, including the scenario that structurally proves the
"L6 cannot kill" claim made above rather than just asserting it. What's left:
whether **L3** (immutable filesystem) and **L4** (identity verification) from
the original nine-layer spec are genuinely subsumed by L1's read-only rootfs
and L8's process-lineage verification, or were simply never built.
