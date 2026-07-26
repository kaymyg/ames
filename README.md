# AMES — Agent Mutation Event Schema

Tamper-evident action ledger for autonomous AI agents. **Layer 8** of a
defence-in-depth containment framework, forked from
[KAYSentinel](https://huggingface.co/Sahek/kaysentinel)'s EMES.

Records what an agent actually did, in a form that cannot be silently edited,
reordered, or spliced — so that when containment fails, the forensic record is
still trustworthy.

## Why L8 first

Every other layer produces evidence; this one makes evidence trustworthy. Under
the framework's premise — *assume every other layer has already failed* — the
ledger is what still has to hold. A behavioural detector reading a log the
adversary can edit is not a detector.

## What it guarantees

Edits, reordering, block splicing, internally-consistent block forgery, count
lies, merkle second-preimages, withheld sequences, hidden child processes and
dormant processes are all **detected by recomputation alone** — no trusted third
party, no signature infrastructure.

## What it does not

**Tail truncation** is undetectable without an external `Checkpoint`, and a
**compromised producer** can omit events entirely. Both limits are tested and
documented rather than papered over — see `docs/ames_specification.md` §2.
`test_truncation_is_invisible_without_a_checkpoint` asserts the weakness exists
so nobody assumes otherwise.

## Quick start

```bash
pip install -r requirements.txt
python -m pytest tests/ -q                    # 292 tests
python examples/run_contained_agent.py        # runnable end-to-end demo
```

Run an agent under all nine layers:

```python
from containment.runtime import Runtime, RuntimeConfig
from containment.backend import FakeBackend

report = Runtime(RuntimeConfig()).execute(spec, FakeBackend())

print(report.summary())   # run demo-01: ALLOWED
report.allowed            # bool
report.verify()           # independently re-checks the ledger vs its checkpoint
```

`FakeBackend` needs no KVM and no root, so the demo runs anywhere. Swapping in
`FirecrackerBackend` is the single line that differs from a real deployment —
and the one line no test here exercises (see `docs/l0_validation.md`).

The L8 ledger is usable directly if you only want the tamper-evident record:

```python
from ames import Ledger, Event, EventType, NO_PARENT, gate1_verify

led = Ledger()
led.append(Event(EventType.RUN_BEGIN, 0, 1_000_000_000, 1, NO_PARENT))
led.append(Event(EventType.PROCESS_SPAWN, 1, 1_000_000_100, 10, 1))
led.append(Event(EventType.PROCESS_EXIT, 2, 1_000_000_200, 10, 1))
led.append(Event(EventType.RUN_END, 3, 1_000_000_300, 1, NO_PARENT))
led.seal_block(1_000_001_000)

checkpoint = led.checkpoint()        # export outside the agent's reach
led.verify_chain(checkpoint)         # raises on any tampering
gate1_verify(list(led.all_events())).raise_if_failed()
```

## Layout

```
ames/events.py              wire schema
ames/canonical.py           deterministic encoding (41-byte header)
ames/commit.py               domain-separated BLAKE3, merkle + inclusion proofs
ames/ledger.py                hash-linked blocks, checkpoints
ames/gate1.py                 structural verification (lineage balance)
vectors/                      pinned cross-language conformance vectors
docs/                         full specification, one doc per layer
containment/vmspec.py         L1 — VM spec, no-network invariant
containment/backend.py        L1 — VM backend interface, Firecracker adapter
containment/supervisor.py     L1 — host-side supervisor, AMES producer
containment/transport.py      L1 — guest→host event transport
containment/policy.py         L2 — capability policy engine
containment/broker.py         L2 — broker, denial-burst + EWMA tracker
containment/runtime.py        the composed L1-L9 entrypoint  <-- start here
containment/identity.py       L3/L4 — binary allowlist + spawn authorization
containment/fingerprint.py    L5 — behavioural fingerprinting
containment/drift.py          L6 — cognitive drift detection (advisory only)
containment/envstate.py       L7 — environment mutation detection
containment/killswitch.py     L9 — autonomous kill system
validation/scenarios.py       L0 — full-stack composed adversarial scenarios
validation/properties.py      L0 — Hypothesis strategies for property-based tests
examples/                     runnable end-to-end demo
```

## Status

AMES (L8) reference implementation complete, vectors pinned. Python for
auditability; a Rust implementation validated against `vectors/` is the intended
production path.

All nine containment layers are built, each with an adversarial test suite and
a doc under `docs/`, plus **L0** (the adversarial validation engine) within an
honestly stated scope, and a **composed Runtime** (`docs/runtime.md`) that
wires them into one entrypoint. **292 tests passing** across the whole repo
(`python -m pytest tests/ -q`).

Two documents state the limits rather than burying them:
`docs/l0_validation.md` (what L0 does and does not check — no real hardware in
this environment, so composition and logical invariants only) and
`docs/l3_l4_audit.md` (a per-claim audit of L3/L4 against the original spec,
including the two claims that were *not* covered before it and what closing
them did and did not buy).

The honest summary of where this lands: **strong at making violations
unforgeable and attributable, weaker at making them impossible.** Prevention
lives in the hypervisor and the guest image, not in Python — which is L1's
premise, and is why the remaining work is all hardware-dependent.

MIT.
