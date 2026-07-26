# The Runtime — one entrypoint for L1–L9

**Status:** complete. 20 tests. 292 total across the repo.

---

## Why this exists

Before this module, `ames` was nine individually correct layers with no way to
invoke them together. Every doc in `docs/` deferred the composition question
with some version of *"wiring this is a deployment decision."* That's honest
about scope — and it also means every operator would have to rediscover the
correct wiring themselves. **A framework whose safe use depends on each user
re-deriving the integration is a framework that will be integrated wrongly.**

L0's `validation/scenarios.py` proved the layers *can* compose. This is the
composition itself, as a supported API rather than a test fixture.

## Using it

```python
from containment.runtime import Runtime, RuntimeConfig
from containment.backend import FakeBackend

report = Runtime(config).execute(spec, FakeBackend())

print(report.summary())     # run demo-01: ALLOWED
report.allowed              # bool
report.verify()             # re-checks the ledger against its checkpoint
```

`examples/run_contained_agent.py` is a runnable end-to-end demo — clean run,
containment breach, and a concealed narrative — using `FakeBackend`, so it
runs anywhere with no KVM and no root.

## The order is not arbitrary

```
L1  validate spec     refuse an unsafe VM before anything is created
L1  run               boot, supervise, tear down; emit host-observed events
  L2  broker          capability decisions, into the SAME ledger
  L3/L4 authorizer    binary allowlist + spawn tokens, host-side
  L7  monitor         filesystem mutations against the sealed baseline
L8  gate1             structural verification of the resulting stream
L9  evidence + kill   host-observed evidence only, absolute rules first
L5/L6 advisory        computed AFTER the verdict, never inputs to it
```

The broker emits into the *same* ledger the supervisor produces, so capability
decisions are sequence-ordered against VM lifecycle events rather than living
in a second, uncorrelated log that a reviewer would have to align by hand.

### The advisory boundary is structural

L5 and L6 are computed *after* `KillVerdict` is decided, and their outputs are
not inputs to it. This isn't a convention the code politely follows:
`Evidence.from_run` has **no parameter** that accepts a `SequenceVerdict` or a
`DriftFinding`. There is no wiring to remove because there is no parameter to
wire.

Two tests pin this from different angles — one behavioural
(`test_advisory_findings_never_change_the_verdict`, which drives a real
concealment and asserts the verdict matches a clean run bit for bit) and one
structural (`test_evidence_has_no_parameter_for_advisory_signals`, which
inspects the signature, so a future refactor that adds such a parameter has to
consciously break a test to do it).

Why it matters: a signal built from the guest's own testimony must not be able
to stop a run, or a compromised guest gains a denial-of-service primitive
against the operator by simply lying.

## Fail closed, everywhere

If any component raises — including one this module doesn't anticipate —
`execute()` returns a report whose verdict is **KILLED**, never one that omits
the failure and looks clean. An exception in the containment system must never
read as "nothing to report."

One deliberate exception: a spec refused by `IsolationPolicy.validate` returns
**FAILED**, not KILLED. Nothing was created, so there's nothing to contain —
but it is still never `allowed`, and a test asserts the backend was never
touched.

## No off switches

`RuntimeConfig` has no `enable_*` / `disable_*` flag for any layer, and
`test_config_exposes_no_disable_switches` asserts it. An operator tunes
thresholds and supplies policies; there is no supported way to switch a layer
off — the same reasoning `KillSwitch` has no `disable()`.

Omitting a baseline or fingerprint means that layer has nothing to compare
against and reports nothing. That is **different from being disabled**: it
still runs, and it still cannot be told to approve something.

Every supplied policy must be **sealed** before the run — `RuntimeConfig`
rejects an unsealed `BinaryPolicy`, `EnvironmentBaseline`, or
`BehaviorFingerprint` at construction. An allowlist that can grow mid-run is
not an allowlist.

## State never crosses a run boundary

Each `execute()` builds its own supervisor, broker, monitor and authorizer.
Sharing any of them across runs would carry state over a boundary — the exact
thing L1 destroys the VM to prevent.

## A bug this module's own tests caught

The first revision constructed the `Supervisor` with the original backend and
*then* reassigned a local `backend` variable to the hook wrapper. The
supervisor had already captured the unwrapped one, so `during_run` silently
never fired. Four tests failed at once, which is what surfaced it — the hook
must be wrapped **before** the supervisor is built, and the context it
receives late-bound afterwards, because the context isn't complete until the
supervisor and broker exist.

Worth recording because it's the failure mode this whole module exists to
prevent: a plausible-looking integration where a control is wired in but never
actually runs.

---

## Not guaranteed

- **Continuous evaluation.** The kill decision happens *after* the run
  completes, because `Supervisor.run()` is a single synchronous call and the
  only in-flight hook is `backend.wait()`. A backend supporting periodic
  callbacks could evaluate mid-run; neither backend shipped here does. **"The
  kill fires after the run is already finished" is a real operational limit**,
  not a detail — for a long-running agent, a breach at minute 2 is not acted
  on until the run ends.
- **Enforcement of the verdict.** `Runtime` decides; L1's `destroy()` is what
  actually tears the VM down (and always runs, on every path). A `KILLED`
  report that a caller ignores is a log line.
- **Anything about real hardware.** Swapping in `FirecrackerBackend` is one
  line, and that line is not exercised by any test here. See
  `docs/l0_validation.md`.

## Next

The remaining work is all hardware-dependent, and the Runtime is what makes it
approachable: a single `execute()` call is now the thing to point at a real
KVM host, rather than a hand-assembled integration written for the occasion.
