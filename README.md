# AMES — Containment for Autonomous AI Agents

**A nine-layer framework whose purpose is to prevent an AI agent from escaping
its execution environment — and, when prevention fails, to make the failure
immediately visible, provably attributable, and automatically stopped.**

Reference implementation in Python. 292 adversarial tests. ~4,400 lines of
implementation, ~2,800 lines of tests.

**Status: designed and implemented, never run on real hardware.** That sentence
is load-bearing — see [Status](#status-what-is-and-is-not-done).

---

## Introduction

An autonomous AI agent needs an execution environment: somewhere to run code,
write files, install dependencies, call tools. The security question is what
happens when that agent is capable enough — and motivated enough — to try
leaving it.

Most sandboxing starts from *"the agent follows the rules; we just need
guardrails."* That assumption fails precisely when it matters most. AMES starts
somewhere else:

> **Assume the agent is an adaptive adversary with unlimited patience, perfect
> memory, the ability to read this source code and its test suite, and the
> objective of escaping.**

That's the assumption cryptographers make about attackers. You don't build
guardrails against it. You build containment layers, and you assume every
individual layer has already failed.

## Purpose

**The purpose is prevention.** The forensic machinery exists because prevention
can fail — not as a substitute for it.

That ordering matters, because it's the opposite of how most agent-safety
tooling is built. Logging what an agent did is comparatively easy and reassuring
to look at. Making a category of action *structurally impossible* is harder,
less visible, and far more valuable. AMES puts the difficult half first: four of
its nine layers exist to stop escape, and the remaining five exist to catch,
prove, and halt what those four missed.

The design lesson underneath the whole architecture: **sandbox escapes usually
don't defeat the isolation boundary — they walk out through the component that
was deliberately given permission to cross it.** A package-registry proxy. A
cache. A helper service that exists so the sandbox can reach a registry. The
hole is the feature.

The conclusion is inconvenient on purpose: **a contained environment must have
no runtime path to the outside world at all.** Not a filtered one. Not a
carefully audited one. None. Dependencies are baked into a measured image before
the agent exists; if the agent needs something that isn't there, the run fails
and a human rebuilds the image. The convenience of runtime installation is
exactly what gets exploited.

## Scope

**In scope:**

- Preventing an agent from reaching the network, the host filesystem, or any
  resource outside its VM
- Preventing persistence — capability accumulated across runs
- Preventing execution of code that wasn't in the approved image
- Detecting environment mutation, behavioural anomaly, and self-reported/observed discrepancy
- Producing a tamper-evident record that survives a fully compromised guest
- Halting automatically, without human approval, on unambiguous evidence

**Out of scope:**

- Alignment, intent modelling, or judging whether an agent's *goals* are good
- Responding to an agent already loose on a network — that's incident response,
  a different problem
- Any claim of absolute guarantee (see [What success means](#what-success-means))

---

## The nine layers, by what they actually do

### Prevent — make it impossible

| Layer | Mechanism |
|---|---|
| **L1** Physical isolation | Ephemeral Firecracker microVM per run. `VmSpec` has **no field** for a network interface — you cannot misconfigure what the type system can't express. Read-only rootfs, ephemeral overlay discarded on teardown |
| **L2** Zero external trust | Default-deny capability broker. No DNS, sockets, HTTP, or registries. Package installs are **never** granted mid-run — deferred to an image rebuild between runs |
| **L3** Immutable filesystem | Read-only rootfs plus a build-time binary allowlist, sealed before the run — no `remove`, no `update`, no `unseal` |
| **L4** Identity verification | Single-use spawn tokens bound to one parent and one binary. A reusable token is a persistent capability — the thing L1 destroys the VM to prevent |

### Detect — make it visible

| Layer | Mechanism |
|---|---|
| **L5** Behavioural fingerprinting | Frozen baseline over the broker's own decisions. Deliberately ignores what the agent *says* it did |
| **L6** Cognitive drift | Compares the agent's narrative against host-recorded evidence. **Advisory only, structurally** |
| **L7** Environment mutation | Event-driven detection against a sealed merkle baseline. A write to a read-only region isn't "risk" — it's proof a lower layer failed |

### Prove — make it undeniable

| Layer | Mechanism |
|---|---|
| **L8** Cryptographic ledger | Hash-linked, domain-separated BLAKE3. Hiding one action requires hiding a *consistent set* of events, so partial omission is detectable |

### Respond — make it stop

| Layer | Mechanism |
|---|---|
| **L9** Autonomous kill | Absolute rules (one occurrence) vs accumulating (burst + EWMA). No `disable()`, no `override()`, no threshold settable to infinity |

Plus **L0**, an adversarial validation engine: property-based fuzzing and
full-stack composed scenarios that wire real components together rather than
testing each layer against fakes of its neighbours.

---

## Three decisions worth explaining

### Evidence vs testimony

The most important distinction in the codebase. Events the **host** observed
directly — VM lifecycle, image measurements, broker decisions — are *evidence*.
Events the **guest** reported about itself are *testimony*.

They're separated by a reserved actor-ID band and never merged. Evidence
assembly filters to host-observed events before anything is counted, so a
compromised guest flooding the channel with fabricated claims moves exactly one
counter — `guest_claims_seen` — which nothing evaluates.

This is why the ledger writer runs on the host, never inside the VM. A log
written by the thing being audited is worth nothing at precisely the moment it
matters.

### Two trigger classes, not one threshold

A flat list of thresholds is a map of exactly how far to go without being
stopped — and the threat model assumes the adversary has read it.

**Absolute** rules fire on a single occurrence and have no threshold to pace
under: a write to a read-only region is not "a lot of risk," it's an invariant
that didn't hold. **Accumulating** rules carry both a burst check *and* an EWMA,
because a burst check alone is blind to exactly the patient,
one-request-at-a-time enumeration the threat model assumes.

### L6 cannot kill, structurally

Every doc asserts L6 is advisory. The repo doesn't ask you to trust the prose:
the evidence constructor has **no parameter** that accepts a drift finding.
There's no wiring to remove because there's no parameter to wire, and a test
inspects the signature so a future refactor has to consciously break it.

A signal built from the guest's own testimony must never be able to stop a run —
otherwise a compromised guest gains a denial-of-service weapon against the
operator by lying about itself.

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
permission it was denied (allowed, but flagged — the advisory boundary in
action).

---

## Status: what is and is not done

**Nothing has ever run.** All 292 tests exercise `FakeBackend`, a test double.
`FirecrackerBackend` has never been executed — there has been no `/dev/kvm` at
any point in development.

The distinction that matters, given prevention is the point:

**The preventive *policy* works and is tested.** Unsafe VM specifications are
refused before anything is created — a spec requesting a network device, a host
filesystem share, a writable rootfs, or persistent state is rejected, and tests
confirm the backend is never even touched. The broker's default-deny, the
never-in-run capability set, the sealed allowlists, the spawn-token logic: all
tested, all working.

**The preventive *enforcement* is unexercised.** Whether Firecracker actually
isolates, whether the guest kernel really has no network device, whether a
read-only mount really is read-only — none of that has been observed. It's
configuration this repo emits correctly and a hypervisor this repo has never
launched.

Prevention, in other words, is designed and configured but not yet *switched
on*. That's what makes hardware testing the critical next step rather than a
nice-to-have.

Four components are missing outright:

- **The guest image doesn't exist.** The framework assumes a rootfs with tmpfs
  `/tmp`, the overlay at `/workspace`, and measured binaries. Never built.
- **The mutation collector doesn't exist.** L7 classifies filesystem mutations,
  but every test *injects them by hand*. The fanotify/eBPF component that would
  produce them is unwritten.
- **The vsock channel has never carried a byte.** The frame parser is correct
  and bounded; nothing has ever sent it a frame from a real guest.
- **Host-side authorization is not kernel enforcement.** An agent with code
  execution calls `execve()` and nothing here stops it. Spawn tokens make an
  unauthorized spawn *attributable*, not *impossible*. True prevention at that
  layer needs IMA/dm-verity or an LSM hook inside the guest image.

Two further limits, documented rather than buried:

- **The kill fires after the run completes**, not during it. For a long-running
  agent, a breach at minute two isn't acted on until the end.
- **`Runtime` decides; it doesn't enforce.** Teardown always runs, but a
  `KILLED` report a caller ignores is just a log line.

---

## What success means

The goal is not a system that guarantees an AI never escapes. **No engineering
system can honestly promise that** against a sufficiently capable adversary —
software has unknown vulnerabilities, hardware has undiscovered flaws, operators
misconfigure things. Any project claiming otherwise is selling something.

The achievable goal is narrower and genuinely defensible:

> Make successful escape require defeating multiple independent security domains
> simultaneously, while ensuring any attempt is rapidly detected, contained, and
> leaves an immutable forensic trail.

That's the philosophy behind nuclear safety, aviation, and modern cryptographic
systems: eliminate single points of failure, assume components fail, design for
graceful containment rather than perfect prevention.

As a design objective:

> Assume the AI is adversarial. Assume every individual defence can fail.
> Minimise available privileges, continuously verify system integrity,
> independently monitor behaviour, maintain tamper-evident audit logs, and fail
> closed by default.

This is more durable than trying to anticipate every future escape technique,
because it treats containment as a **continuously verified property** rather than
a one-time checklist. A dormant defence is a hypothesis, not evidence — which is
why every control here has a test proving it still fires, and why L0 exists.

## Next step

Get a Linux host with KVM. Build the guest image. Run `Runtime.execute()`
against `FirecrackerBackend` for the first time.

Expect that first real run to surface problems no unit test could have found.
That isn't a failure of the design — it's the point at which the design stops
being a hypothesis, and the preventive layers actually start preventing.

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
EMES, generalised from EVM state transitions to agent actions — an EVM call frame
becomes an OS process, so the frame-balance invariant carries over directly as
process lineage verification.

MIT.
