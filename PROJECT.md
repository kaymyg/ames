# AMES — Containment for Autonomous AI Agents

**A nine-layer containment framework built on one assumption: the agent is an
adaptive adversary with unlimited patience, perfect memory, and the objective
of escaping.**

Reference implementation in Python. 292 adversarial tests. ~4,400 lines of
implementation, ~2,800 lines of tests.

**Status: designed and implemented, never run on real hardware.** That
sentence is load-bearing — see [Where this actually stands](#where-this-actually-stands).

---

## The problem

Most AI sandboxing starts from *"the agent follows the rules, we just need
guardrails."* That assumption fails the moment an agent is capable enough to
be worth sandboxing.

The design premise here is the one cryptographers use: assume the adversary is
patient, remembers everything, can read your source code and your test suite,
and is actively looking for the gap. You don't build guardrails against that.
You build containment layers, and **you assume every individual layer has
already failed.**

The specific lesson driving the architecture: sandbox escapes don't usually
defeat the isolation boundary. They walk out through the one component that
was deliberately given permission to cross it — a package-registry proxy, a
cache, a helper service that exists so the sandbox can reach a registry. The
hole is the feature.

The conclusion is inconvenient by design: **a contained environment must have
no runtime path to the outside world at all.** Not a filtered one. Not a
well-audited one. None.

---

## What the nine layers do

Each has its own doc in [`docs/`](docs/) explaining what it guarantees and —
just as explicitly — what it does not.

| Layer | Job | Key decision |
|---|---|---|
| **L1** Physical isolation | Ephemeral Firecracker microVM per run | `VmSpec` has **no field** for a network interface. You cannot misconfigure what the type system can't express |
| **L2** Zero external trust | Capability broker, default-deny | Package installs are **never** granted mid-run — deferred to an image rebuild between runs. The convenience is what gets exploited |
| **L3** Immutable filesystem | Read-only rootfs, build-time binary allowlist | Sealed before the run; no `remove`, no `update`, no `unseal` |
| **L4** Identity verification | Single-use spawn tokens bound to one parent and one binary | A reusable token is a persistent capability — the thing L1 destroys the VM to prevent |
| **L5** Behavioural fingerprinting | Frozen baseline over the broker's own decisions | Deliberately ignores what the agent *says* it did |
| **L6** Cognitive drift | Compares the agent's narrative against host-recorded evidence | **Advisory only, structurally** — see below |
| **L7** Environment mutation | Event-driven detection against a sealed merkle baseline | A write to a read-only region isn't "risk," it's proof a lower layer failed |
| **L8** Cryptographic ledger | Hash-linked, domain-separated BLAKE3, tamper-evident | Hiding one action requires hiding a *consistent set* of events |
| **L9** Autonomous kill | Absolute rules (one occurrence) vs accumulating (burst + EWMA) | No `disable()`, no `override()`, no threshold that can be set to infinity |

Plus **L0**, an adversarial validation engine: property-based fuzzing plus
full-stack composed scenarios that wire real components together instead of
testing each layer against fakes of its neighbours.

---

## Three design decisions worth explaining

### Evidence vs testimony

The single most important distinction in the codebase. Events the **host**
observed directly (VM lifecycle, image measurements, broker decisions) are
*evidence*. Events the **guest** reported about itself are *testimony*.

They're separated by a reserved actor-ID band and never merged. `Evidence.from_run()`
filters to host-observed events before anything is counted, so a compromised
guest that floods the channel with fabricated claims moves exactly one
counter: `guest_claims_seen`, which nothing evaluates.

This is why the ledger writer runs on the host and never inside the VM. A log
written by the thing being audited is worth nothing at precisely the moment it
matters.

### Two trigger classes, not one threshold

A flat list of thresholds is a map of exactly how far to go without being
stopped — and the threat model explicitly assumes the adversary has read it.

So conditions split by what they actually mean. **Absolute** rules fire on a
single occurrence and have no threshold to pace under: a write to a read-only
region is not "a lot of risk," it's an invariant that didn't hold.
**Accumulating** rules carry both a burst check *and* an EWMA, because a burst
check alone is blind to exactly the patient, one-request-at-a-time enumeration
the threat model assumes.

### L6 can't kill, structurally

Every doc asserts L6 is advisory. The repo doesn't ask you to trust the prose:
`Evidence.from_run()` has **no parameter** that accepts a drift finding. There
is no wiring to remove because there's no parameter to wire, and a test
inspects the signature so a future refactor has to consciously break it.

Why it matters: a signal built from the guest's own testimony must never be
able to stop a run — otherwise a compromised guest gains a denial-of-service
weapon against the operator by simply lying about itself.

---

## Quick start

```bash
pip install -r requirements.txt
python -m pytest tests/ -q                 # 292 tests
python examples/run_contained_agent.py     # end-to-end demo, no KVM needed
```

```python
from containment.runtime import Runtime, RuntimeConfig
from containment.backend import FakeBackend

report = Runtime(config).execute(spec, FakeBackend())

report.summary()    # "run demo-01: ALLOWED"
report.allowed      # bool
report.verify()     # independently re-checks the ledger against its checkpoint
```

The demo runs three scenarios: a clean run (allowed), a read-only filesystem
breach (killed, absolute), and a concealed narrative where the agent claims a
permission it was denied (allowed, but flagged for human review — the advisory
boundary in action).

---

## Where this actually stands

**Nothing has ever run.** Every one of the 292 tests exercises `FakeBackend`, a
test double. `FirecrackerBackend` has never been executed — there has been no
`/dev/kvm` at any point in this project's development.

The tests prove the code does what it was designed to do. They prove nothing
about whether it contains a real adversary, because it has never faced one, or
even booted.

Four things are missing, and none of them are small:

- **The guest image doesn't exist.** The framework assumes a rootfs with tmpfs
  `/tmp`, the overlay mounted at `/workspace`, and measured binaries. That
  image has never been built. L7's path policy assumes a layout nobody created.
- **The mutation collector doesn't exist.** L7 classifies filesystem
  mutations — but every test *injects them by hand*. The fanotify/eBPF
  component that would produce them in reality is unwritten.
- **The vsock channel has never carried a byte.** The frame parser is correct
  and bounded. Nothing has ever sent it a frame from a real guest.
- **Host-side authorization is not kernel enforcement.** An agent with code
  execution calls `execve()` and nothing here stops it. Spawn tokens and
  binary allowlists make an unauthorized spawn *attributable*, not
  *impossible*. Real prevention needs IMA/dm-verity or an LSM hook inside the
  guest image.

Two further limits, documented rather than buried:

- **The kill fires after the run completes**, not during it. For a
  long-running agent, a breach at minute two isn't acted on until the end.
  Continuous evaluation needs a backend supporting periodic callbacks; neither
  backend here has one.
- **`Runtime` decides; it doesn't enforce.** L1's `destroy()` tears the VM
  down on every path, but a `KILLED` report a caller ignores is just a log line.

The honest summary: **this is strong at making violations unforgeable and
attributable, and weaker at making them impossible.** Prevention lives in the
hypervisor and the guest image, not in Python. That's L1's premise, and it's
why everything remaining is hardware-dependent.

---

## What it's ultimately for

The goal is not a system that guarantees an AI never escapes. **No engineering
system can honestly promise that** against a sufficiently capable adversary —
software has unknown vulnerabilities, hardware has undiscovered flaws, and
operators misconfigure things.

The achievable goal is narrower and more defensible:

> Make successful escape require defeating multiple independent security
> domains simultaneously, while ensuring any attempt is rapidly detected,
> contained, and leaves an immutable forensic trail.

That's the philosophy behind nuclear safety, aviation, and modern
cryptographic systems: eliminate single points of failure, assume components
fail, design for graceful containment rather than perfect prevention.

Stated as a design objective:

> Assume the AI is adversarial. Assume every individual defence can fail.
> Minimise available privileges, continuously verify system integrity,
> independently monitor behaviour, maintain tamper-evident audit logs, and
> fail closed by default.

That's more durable than trying to anticipate every future escape technique,
because it treats containment as a **continuously verified property** rather
than a one-time checklist. A dormant defence is a hypothesis, not evidence —
which is why every control here has a test that proves it still fires, and why
L0 exists at all.

---

## Next step

Get a Linux host with KVM. Build the guest image. Run `Runtime.execute()`
against `FirecrackerBackend` for the first time.

The expectation should be that this first real run surfaces several problems
no unit test could have found. That's not a failure of the design — it's the
point at which the design stops being a hypothesis.

---

## Repository layout

```
ames/                  L8 — canonical encoding, BLAKE3 commitments, ledger, Gate 1
containment/runtime.py the composed L1–L9 entrypoint  ← start here
containment/           L1–L7, L9 — one module per layer
validation/            L0 — property-based fuzzing + composed scenarios
docs/                  one doc per layer: guarantees and explicit non-guarantees
examples/              runnable end-to-end demo
vectors/               pinned cross-language conformance vectors
```

Python for auditability. A Rust implementation validated against `vectors/` is
the intended production path.

Forked conceptually from [KAYSentinel](https://huggingface.co/Sahek/kaysentinel)'s
EMES, generalised from EVM state transitions to agent actions — an EVM call
frame becomes an OS process, so the frame-balance invariant carries over
directly as process lineage verification.

MIT.
