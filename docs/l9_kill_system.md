# L9 — Autonomous Kill System

**Status:** complete. 38 tests.

---

## Two departures from the original design

### 1. Rules come in two classes, not one

The original specification was a flat list of hardcoded thresholds — privilege
escalation, unexpected process, dormant process, repeated denials — each firing a
kill. Against the threat model the framework itself assumes (adaptive, patient,
perfect memory, **and able to read this file**) a flat threshold list is a map of
exactly how far to go without being stopped.

So conditions are split by what they actually mean:

| Class | Meaning | Trigger |
|---|---|---|
| **ABSOLUTE** | Never legitimate under any circumstance | One occurrence. No threshold to pace under, no window to wait out. |
| **ACCUMULATING** | Plausible alone, suspicious in aggregate | Burst **and** EWMA together |

A write to a read-only region is not "a lot of risk" — it is an invariant that
did not hold, so it is absolute. A single unexplained file write is genuinely
ambiguous, so it accumulates.

The EWMA is what makes patient enumeration fail. Same fix as L2's denial tracker,
and the same one `multi-agent-mcl` arrived at independently. A test paces one
mutation at a time under a burst limit of 1000 and asserts
`MUTATION_SUSTAINED` fires while `MUTATION_BURST` does not.

### 2. The killer reads only host-observed evidence

*"No LLM decides, no policy engine decides"* is necessary but not sufficient. If a
kill can be computed from guest-reported claims, a compromised guest gets two
attacks:

- **Stay quiet** to avoid tripping it
- **Fabricate claims** to trip it against a legitimate run — denial of service
  against the operator, using the safety system as the weapon

`Evidence.from_run()` filters to the host-observed actor band before anything is
counted. Two tests make the property precise: the *same* privilege-escalation
claim triggers a kill from `HOST_ACTOR_ID` and does not from a guest actor. The
filter is **provenance, not content**. A guest flooding 5,000 benign claims moves
only `guest_claims_seen`, which nothing evaluates.

---

## Fail closed

If the evaluator itself raises, the verdict is **KILL**. An exception in the
safety system must never mean "carry on" — that is how a monitoring bug becomes a
containment bypass.

---

## No escape hatches

There is no `disable`, `override`, `reset`, `set_threshold`, `add_rule` or
`bypass`. A parametrised test asserts each is absent. **An adversary who can add
a rule can add one that never fires.**

Thresholds are constructor arguments so an operator can tune sensitivity per
environment; they cannot be changed while a run is in flight, and no argument can
switch a rule off.

**A trip is never reconsidered.** Once tripped, always tripped — the condition
may not recur, and *"it stopped happening"* is exactly what a successful attacker
produces.

`Evidence` and `KillVerdict` are frozen. That freezing is load-bearing enough
that it blocked a test helper which tried to subclass `Evidence` and shadow a
field; the helper had to become a plain stand-in instead.

---

## What flows in from below

| Source | Signal | Class |
|---|---|---|
| L7 | `containment_failed` — read-only region changed | ABSOLUTE |
| L7 | unexplained mutations | ACCUMULATING |
| L8 Gate 1 | lineage breaks (orphan, action-after-exit, double spawn) | ABSOLUTE |
| L8 Gate 1 | `UNTERMINATED_ACTOR` — dormant process | ABSOLUTE |
| L2 | granted `PRIVILEGE_RAISE` | ABSOLUTE |
| L2 | denial burst / sustained denial rate | ACCUMULATING |

Lineage breaks are absolute because once the graph has holes, "who did this" has
no answer and every later judgement is guesswork.

A granted privilege raise **should be unreachable** — L2 lists it in
`NEVER_IN_RUN`. Seeing one recorded means the policy engine was bypassed or
replaced, which is itself the emergency. One test asserts the real broker never
produces it across 50 attempts; another asserts that if it somehow appears, the
kill fires.

Non-fatal Gate 1 codes (`SEQ_GAP`, `TIME_REGRESSION`) are recorded but do not
kill — they are not, alone, evidence that attribution is broken.

---

## Not guaranteed

- **Enforcement.** This layer decides; L1's `destroy()` is what actually stops
  the VM. A `KillVerdict` nobody acts on is a log line.
- **Timeliness.** Evaluation happens when evidence is presented. Continuous
  evaluation is a wiring decision for the supervisor loop, not a property here.
- **Correct thresholds.** Absolute rules need none, but the accumulating ones are
  tunable and an operator can set them uselessly high.

## Next

**L5** (behavioural fingerprinting) needs a frozen reference baseline — a
detector retrained on live traffic learns the attack. **L6** last and advisory
only: reading reasoning traces assumes they are faithful, which is precisely what
MCL's concealment dimension says not to assume. Then **L0**, the adversarial
validation engine, which is what turns every "not verified here" note in these
docs into something checked on real hardware.
