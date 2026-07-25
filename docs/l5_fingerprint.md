# L5 — Behavioural Fingerprinting

**Status:** complete. 24 tests. 222 total across the repo.

---

## The question the other layers don't ask

L2 asks *is this capability ever allowed*. L7 asks *did a read-only invariant
break*. L9 asks *did an absolute rule fire, or did an accumulating one cross its
line*. None of them ask the question that catches an agent doing something it
has never done before while staying inside every rule those layers enforce:
**does this shape of behaviour look like what this agent normally does.**

That is what L5 is for, and it is deliberately the only layer in the framework
that produces an opinion rather than a verdict.

---

## Why the substrate is the capability stream, and nothing else

The obvious design fingerprints the agent's own reported actions — `TOOL_CALL`
arguments, `NETWORK_REQUEST` destinations, whatever it claims to be doing. That
design is worthless against this framework's own threat model: an adaptive
adversary with unlimited patience and perfect memory, able to read this file. An
adversary that knows its telemetry is being fingerprinted simply shapes what it
*claims* to match whatever profile it expects to be compared against.

`CAPABILITY_REQUEST` events are different in kind, not degree. They are not
claims — they are the **broker's own record** (L2, host-side) of a decision it
made, attributed to the host actor band and timestamped by the host's clock.
`observations_from_ledger` filters to `is_host_observed()` first, for the same
reason `killswitch.Evidence.from_run` does: a guest cannot fabricate what was
recorded as asked of the broker, cannot avoid the broker for anything gated (L1
removed every other path out), and cannot forge the host's timestamp. An
adversary can still choose *what* to ask for and *when* — it cannot choose what
gets written down about that choice.

Two tests make this precise: a forged, guest-attributed `CAPABILITY_REQUEST` is
excluded entirely, and a 500-event guest flood moves nothing — the extracted
observations are byte-identical with or without the flood.

---

## Frozen baseline, same reasoning as L7

A detector that keeps learning from live traffic is a detector an adversary can
walk, one plausible-looking step at a time, until the attack itself is inside
the "normal" region. `BehaviorFingerprint` absorbs reference runs, then seals;
nothing can be added afterward. The baseline is a statement about the past,
never a moving target — the same property `EnvironmentBaseline` (L7) and
`KillSwitch`'s frozen rule set (L9) both hold for their own reasons.

---

## What gets compared

| Check | Question | Catches |
|---|---|---|
| **Capability set** | Has this exact capability ever been requested in any reference run? | A first-time capability — no statistics needed, only set membership |
| **Transition** | Has this exact `(previous → this)` pair occurred, *within* one reference run? | Reordering and novel sequencing, even when every individual capability is one the agent has used before |
| **Cadence** | How far off is the inter-request gap from the pooled reference mean, in standard deviations? | Requests fired far faster or far slower than history |

Transitions are computed only within a single absorbed run and never
synthesised across the boundary between two — a test absorbs run A (ending in
`FILE_WRITE`) and run B (starting with `RAW_SYSCALL`) and confirms the
candidate transition `FILE_WRITE → RAW_SYSCALL` is still flagged novel, proving
the two runs were never stitched into one sequence.

### The zero-variance edge case

A baseline built from a perfectly steady reference (every interval identical)
has stddev = 0, so a plain z-score divides by zero. The obvious fix — skip the
cadence check when stddev is 0 — is wrong: a perfectly steady baseline is not
*missing* a timing model, it *is* one, and it's the tightest one possible. Any
deviation from it is exactly as anomalous as an infinite z-score would say.
`evaluate()` distinguishes this from genuinely insufficient data (fewer than two
reference intervals, where no timing model exists at all) and reports the
zero-variance case as `cadence_outlier=True` with `z_score = ±inf`. Two tests
were written *because* the first cadence tests failed against an accidentally
perfectly-steady synthetic baseline — the same shape of self-caught bug as L1's
lineage ordering and L2's default-deny gap.

---

## Advisory, not enforcing

Nothing in this module can deny a capability, stop a run, or feed a kill
decision by itself. A `SequenceVerdict` is evidence weighed by a human or wired
into L9 as a non-absolute input — a deployment decision this module deliberately
does not make. Treating a first "novel" observation as proof of compromise would
mean the framework breaks the first time an operator does anything new, which is
how a control gets routed around rather than trusted.

Contrast L7's `IMPOSSIBLE` verdict: there is no legitimate reason a read-only
region changes, so it can be absolute. There are plenty of legitimate reasons an
agent does something for the first time, so L5 cannot be.

---

## A known, documented limit

An adversary who has learned (or guessed) the baseline's cadence can pace a new
request at exactly the historical mean interval and evade the cadence check
entirely. This is the same "boil the frog" shape L2's denial tracker and L9's
mutation trigger both defend against with an EWMA — and there is deliberately
no equivalent trick available here, because cadence *is* genuinely gameable this
way once an attacker has visibility into the baseline.

What pacing cannot do: make a first-time capability, or a transition the
baseline never saw, look like one it did see. Those checks have no threshold to
pace under. `test_pacing_at_the_baseline_mean_evades_cadence_but_not_capability_novelty`
makes the limit explicit rather than leaving it to be discovered in an incident
review.

---

## Not guaranteed

- **That the reference runs are representative.** A baseline built from a
  compromised reference run bakes the compromise in as "normal" — the limit
  every anomaly detector inherits from its training data.
- **Cadence evasion by a patient, baseline-aware adversary** (see above).
- **What happens after a flag.** Wiring `SequenceVerdict.flagged` into an
  operator queue or into L9 is a deployment decision, not a property tested
  here.

## Next

**L6** (cognitive drift detection) is built — see `docs/l6_drift.md`. **L0**,
the adversarial validation engine, is what's left: the layer that turns every
"not verified here" note across these docs into something checked on real
hardware.
