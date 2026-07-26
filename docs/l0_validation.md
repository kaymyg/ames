# L0 — Adversarial Validation Engine

**Status:** complete, within an honestly stated scope. 15 tests (8 scenario, 7 property). 250 total across the repo.

---

## What L0 is here, and what it can't be

L0 sits outside the L1–L9 stack rather than inside it: every other layer
defends the run; this one checks whether the layers actually hold — and
whether they hold **together**, not just individually. The original design
described it as the layer that turns every "not verified here" note across
these docs into something checked on real hardware.

That can't be built in this environment. This sandbox has no `/dev/kvm` and no
kernel privileges, so `containment.backend.FirecrackerBackend` is still exactly
what its own docstring says: *"reviewed but not exercised... until the L0
adversarial validation engine runs it on real hardware."* That sentence is
still true after this module. Whether Firecracker actually isolates, whether
the fanotify/eBPF collector L7 assumes delivers what `MutationObservation`
expects, whether vsock actually enforces one-direction-only data flow — none of
that is checked here, and nothing below claims otherwise.

What **is** honestly buildable, and is what got built:

## 1. Full-stack composed scenarios (`validation/scenarios.py`)

Every adversarial test suite in this repo, up to this point, tests one layer
with the layers below it faked or hand-constructed. L9's own tests build
`Evidence` by typing `containment_failed=True` directly; L1's tests never drive
a real `Broker`. That's the *correct* way to unit-test a layer in isolation,
and it leaves exactly one thing unchecked: does the composition actually work
when real components are wired together, not a hand-typed stand-in for what
one "should" produce.

`ScriptedBackend` is the piece that makes this possible without touching
`Supervisor.run()`'s lifecycle. A guest, in reality, acts *while* the VM is
running — between L1's `PROCESS_SPAWN(VM_ACTOR_ID)` and its
`PROCESS_EXIT(VM_ACTOR_ID)`. Since `Supervisor.run()` is one synchronous call,
the only place caller code still runs inside it is `backend.wait()`.
`ScriptedBackend.wait()` runs a caller-supplied script there, so anything it
does through `supervisor.record_guest_claim()` or the new
`supervisor.emit_host_event()` seam lands at exactly the sequence position a
real interleaved action would have.

Six scenarios, each driving real components end to end:

| Scenario | Composes | Proves |
|---|---|---|
| `clean_baseline_run` | everything | true-negative baseline — nothing fires on nothing |
| `read_only_breach_triggers_absolute_kill` | real L7 `EnvironmentMonitor` → real `Evidence` → real `KillSwitch` | L7's `containment_failed` and L9's absolute rule agree |
| `patient_enumeration_defeats_burst_not_ewma` | real `Broker`/`DenialTracker` → real `KillSwitch` | the EWMA path fires from real denial pacing, not a hand-built signal |
| `well_formed_multi_actor_run_passes_gate1` | real guest spawn/act/exit + real host-attributed broker decision, interleaved | a legitimate multi-actor run doesn't false-positive |
| `unattributed_guest_action_after_run_end_is_fatal` | real Gate 1 over a real malformed ledger → real `KillSwitch` | persistence-after-exit is fatal through the real path, not a literal `fatal_gate1_codes` tuple |
| `concealed_capability_narrative_flags_drift_but_never_kills` | real `DriftMonitor` alongside real `KillSwitch` | L6 is *structurally* incapable of killing, not just documented as advisory |

That last one is the one worth dwelling on. Every L6 doc asserts, in prose,
that drift findings can't kill. This scenario doesn't trust the prose: it
manufactures a real `OUTCOME_MISMATCH` (a guest narrating a grant for a
capability the broker actually denied — the concealment shape
`multi-agent-mcl` models) and checks the kill verdict is bit-for-bit identical
to the clean baseline despite it. `Evidence.from_run` has no parameter that
consumes a `DriftFinding` — there is no path to check, which is a stronger
claim than "the current code doesn't happen to use it."

### Two bugs this caught in itself before a single test was written

Running the scenarios directly (before writing any assertions) surfaced two
real mistakes, both worth recording rather than quietly fixing:

1. `Ledger.all_events()` only yields **sealed** blocks. A guest claim recorded
   after `Supervisor.run()` returns sits in `_pending` — invisible to Gate 1
   until something seals a new block over it. The
   `unattributed_guest_action_after_run_end_is_fatal` scenario originally
   showed a clean Gate 1 result, which was wrong; the fix is an explicit
   second `seal_block()` call, and the fact that it's needed at all is itself
   a small, honest finding about what "the run is over" actually means for an
   operator inspecting the ledger immediately after `run()` returns.
2. `record_guest_claim` enforces Gate 1's lineage rule exactly like a real
   guest action would: an actor must be spawned before anything else can be
   attributed to it. The `concealed_capability_narrative` scenario's first
   draft skipped the spawn and got an unintended `UNATTRIBUTED_ACTION` kill
   instead of the intended drift-only finding — caught by running the
   scenario, not by trusting the docstring describing what it should do.

### A gap this surfaced, left open rather than papered over

`record_guest_claim` always attributes a spawn with `parent=NO_PARENT` — there
is currently no way to record a guest process as a structural child of
`VM_ACTOR_ID`, only as a root actor. Gate 1 still accepts this (a root-level
spawn/exit pair is legal on its own), but it means the lineage graph doesn't
actually connect "the VM" to "the guest process inside it" the way the
framework's narrative implies. Fixing it means adding a `parent` parameter to
`Supervisor.record_guest_claim` — real API surface, and a decision for whoever
owns L1's supervisor next, not something this scenario module should quietly
work around.

## 2. Property-based fuzzing (`validation/properties.py`, `tests/test_l0_properties.py`)

Every example-based test in this repo answers "does the code handle *this*
attack a human thought of" — necessary, and also exactly the kind of test an
adversary who has read the test file can plan around. A hand-picked example set
is finite and knowable. Property-based testing (via Hypothesis) asks a
different question — does an invariant hold for every input in a class,
including ones nobody picked — across machine-generated cases on every run.

Seven properties, each checked against 100–300 generated cases per run:

- Canonical encode/decode round-trips for **any** structurally valid `Event`, not
  just the pinned conformance vectors.
- Merkle inclusion proofs verify for every index, for randomly generated leaf
  lists from size 0 to 40.
- The empty tree is always `ZERO_DIGEST`.
- Flipping one byte of one leaf always changes the root (a cheap
  avalanche/no-collision spot check, not a claim about BLAKE3's cryptographic
  properties).
- Gate 1 accepts **any** randomly generated, internally consistent process
  lineage tree — not just the hand-built ones in `test_tamper.py`.
- Removing any one actor's spawn from any randomly generated tree always
  leaves Gate 1 unsatisfied — a fuzzed version of gate1.py's own claim that
  "hiding an action requires hiding a consistent set of events."
- Duplicating any one actor's spawn always trips `DOUBLE_SPAWN` specifically.

### The bug fuzzing caught immediately

The duplicated-spawn property failed on its first run. The test appended the
duplicate at the *end* of the stream, which — depending on the randomly
generated topology — could land after that actor had already exited, and Gate
1 correctly reported `RESPAWN_AFTER_EXIT` instead of `DOUBLE_SPAWN`: a
different, equally correct rejection, but not the one the test claimed to
check. Hypothesis's shrinking found the minimal case in seconds. The fix was
to insert the duplicate immediately after the original spawn, while the actor
is provably still live, which pins down `DOUBLE_SPAWN` regardless of topology.
This is precisely the class of bug example-based testing structurally cannot
find — a hand-picked example doesn't accidentally land on the wrong side of an
exit boundary — and it's the strongest evidence in this repo that fuzzing and
example-based testing are complementary rather than redundant.

---

## Not guaranteed

- **Anything about real hardware.** Firecracker's actual isolation, the
  fanotify/eBPF collector, vsock's actual one-directionality — none of it.
  This module validates composition and logical invariants in software.
- **Exhaustiveness of the lineage generator.** `lineage_stream` produces a
  random forest with actors created in valid order and exited in reverse —
  not every legal interleaving Gate 1 would accept. The properties checked
  don't require covering every legal interleaving, only that generated streams
  are genuinely legal ones.
- **That six scenarios exhaust the composition space.** They're the six that
  correspond to a specific claim made elsewhere in these docs (L7↔L9, L2↔L9,
  a legitimate multi-actor run, persistence-after-exit, L6's advisory
  boundary, and a clean baseline). More compositions are possible; these are
  the ones this pass checked.

## What's left

**Resolved since this doc was written:** the L3/L4 question is answered in
`docs/l3_l4_audit.md` — about half subsumed by L1/L8, half not, with the
un-subsumed half (per-binary verification, spawn-token authorization) now
implemented host-side in `containment/identity.py`.

What remains is only the hardware-dependent work named above: exercising
`FirecrackerBackend` on a host with `/dev/kvm`, validating the fanotify/eBPF
collector, and confirming vsock's one-directionality.
