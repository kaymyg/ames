# AMES-V1 — Agent Mutation Event Schema

**Status:** Layer 8 (Cryptographic Action Ledger) reference implementation, complete and vector-pinned.
**Hash:** BLAKE3-256, unkeyed, no XOF, no derive_key.
**Lineage:** generalises KAYSentinel EMES from EVM state transitions to agent actions.

---

## 1. Why this layer comes first

Every other containment layer *produces* evidence. This layer is what makes that
evidence trustworthy. Under the framework's own premise — assume every other
layer has already failed — the ledger is the component that still has to hold,
because it is the forensic ground truth once L1–L7 are compromised.

A behavioural detector reading from a log an adversary can edit is not a
detector. Build outward from the thing that must survive.

---

## 2. Threat model

**Adversary.** Adaptive, patient, perfect memory, executing inside the contained
environment. Can read this specification. Objective: perform actions without
leaving usable evidence.

**Guaranteed against**

| Attack | Mechanism |
|---|---|
| Edit an event | `events_root` recomputation |
| Reorder events | dense sequence check + merkle order sensitivity |
| Reorder/splice blocks | `prev_hash` linkage |
| Forge an internally-consistent block | successor's `prev_hash` |
| Lie about event count | header vs actual comparison |
| Present an internal node as a leaf | leaf/node domain separation |
| Withhold an event at write time | dense sequence rejected at `append()` |
| Hide a child process | Gate 1 lineage balance (orphan detection) |
| Leave a dormant process | Gate 1 `UNTERMINATED_ACTOR` |
| Smuggle state in reserved bits | reserved field verified zero on decode |
| Truncate the tail | **only with an external `Checkpoint`** |

**NOT guaranteed — stated plainly**

1. **Tail truncation without a checkpoint.** A truncated chain is internally
   consistent. Hash-linking cannot detect the absence of something it never saw.
   Export checkpoints to a trust domain the agent cannot reach.
2. **A compromised producer.** If the emitter is adversary-controlled it can
   omit events entirely. The ledger proves what was *recorded*, not that
   everything was recorded. Completeness is L1's problem: the producer must sit
   outside the agent's blast radius.
3. **Confidentiality.** The ledger is integrity-protected, not encrypted.

A log believed tamper-*proof* but only tamper-*evident* produces false
confidence exactly when it is most expensive. These limits are load-bearing
documentation, not disclaimers.

---

## 3. Canonical encoding

No JSON on the commitment path. JSON permits key reordering, whitespace
variation, unicode escaping choices and float formatting differences — any one
silently changes the bytes and therefore the hash.

### Event header — fixed 41 bytes

| Offset | Size | Field | Type |
|---|---|---|---|
| 0 | 1 | `event_type` | u8 |
| 1 | 8 | `sequence` | u64 BE |
| 9 | 8 | `timestamp_ns` | u64 BE |
| 17 | 8 | `actor_id` | u64 BE |
| 25 | 8 | `parent_id` | u64 BE |
| 33 | 4 | `payload_len` | u32 BE |
| 37 | 4 | `reserved` | u32 BE, MUST be 0 |
| 41 | … | `payload` | bytes |

`reserved` lets V2 add header flags without moving any subsequent offset. A V1
decoder MUST reject a non-zero value — silently ignoring unknown bits lets an
adversary smuggle state past a V1 verifier.

`parent_id = 0xFFFFFFFFFFFFFFFF` (`NO_PARENT`) marks a root actor.

Strings are NFC-normalised UTF-8, u32 BE length-prefixed. Variable-length
content (argv, file bodies, request payloads) is committed **by 32-byte hash**,
not stored inline — this bounds the ledger and stops it becoming an exfiltration
channel in its own right.

### Event types

| Value | Type |
|---|---|
| `0x01` | `PROCESS_SPAWN` |
| `0x02` | `PROCESS_EXIT` |
| `0x03` | `FILE_MUTATION` |
| `0x04` | `NETWORK_REQUEST` |
| `0x05` | `TOOL_CALL` |
| `0x06` | `CAPABILITY_REQUEST` |
| `0x07` | `MEMORY_MAP` |
| `0x7E` | `RUN_BEGIN` |
| `0x7F` | `RUN_END` |

Values are permanently immutable. Append new types; never renumber or recycle.

---

## 4. Commitments

    Digest := BLAKE3(DomainTag || CanonicalBytes)

No framing bytes between tag and payload. Domain registry:

| Domain | Tag |
|---|---|
| `EVENT` | `AMES_V1_EVENT` |
| `MERKLE_LEAF` | `AMES_V1_MERKLE_LEAF` |
| `MERKLE_NODE` | `AMES_V1_MERKLE_NODE` |
| `BLOCK` | `AMES_V1_BLOCK` |
| `CHECKPOINT` | `AMES_V1_CHECKPOINT` |

**Merkle construction.** Leaves and internal nodes use *different* domains —
without this an internal node can be presented as a leaf (CVE-2012-2459 class).
On an odd level the final node is **promoted unchanged, never duplicated**;
duplication makes two distinct trees collapse to the same root, allowing forged
inclusion proofs. Empty tree → 32 zero bytes, which no real leaf can equal.

### Block header — fixed 88 bytes

| Size | Field |
|---|---|
| 8 | `height` u64 BE |
| 32 | `prev_hash` |
| 8 | `event_count` u64 BE |
| 32 | `events_root` |
| 8 | `timestamp_ns` u64 BE |

Genesis `prev_hash` = 32 zero bytes.

---

## 5. Gate 1 invariants

Structural well-formedness only — *not* policy. A structurally broken stream
cannot be meaningfully policy-evaluated: if the lineage graph has orphans,
"which process did this" has no answer and every downstream attribution is
guesswork.

| Code | Invariant |
|---|---|
| `SEQ_GAP` | sequences dense and strictly increasing |
| `TIME_REGRESSION` | timestamps non-decreasing (equal permitted) |
| `NO_RUN_BEGIN` / `NO_RUN_END` | stream encapsulated by run markers |
| `NESTED_RUN_MARKER` | no run marker inside an open run |
| `DOUBLE_SPAWN` | an actor id spawns once |
| `RESPAWN_AFTER_EXIT` | actor ids are not reusable |
| `ORPHAN_SPAWN` | a spawning parent must be live |
| `EXIT_WITHOUT_SPAWN` | no exit without a spawn |
| `UNATTRIBUTED_ACTION` | every action belongs to a live actor |
| `ACTION_AFTER_EXIT` | no action after exit |
| `UNTERMINATED_ACTOR` | nothing still running at `RUN_END` |

The lineage invariants do the real work: hiding an action requires hiding a
*consistent set* of events. Suppressing one spawn to conceal a child leaves an
orphan behind.

---

## 6. Conformance

`vectors/ames_v1_conformance.json` pins domain digests, canonical event
encodings, merkle roots for 0–8 leaves, and a full chained ledger. Any
independent implementation MUST reproduce every value byte-for-byte.

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # 37 tests
python scripts/gen_vectors.py       # regenerate (must be byte-identical)
```

Reference implementation is Python for auditability. A Rust implementation
validated against these vectors is the intended production path — the same
discipline KAYSentinel already uses for its BLAKE3 vectors.

---

## 7. Next layers

L8 is complete. Recommended order, each depending on the previous:

1. **L1 physical isolation** — Firecracker microVM per run, destroyed after. The
   OpenAI escape went through a package-registry cache proxy, so the AMES
   producer must live on the host side of the VM boundary, never inside it.
2. **L2 zero external trust** — broker + policy engine; every denial emits a
   `CAPABILITY_REQUEST` with `granted=0`. Denial bursts are a first-class
   escape-probing signal.
3. **L7 environment mutation** — eBPF/fanotify event-driven capture into
   `FILE_MUTATION`. Do **not** hash the full filesystem every second; use a
   merkle tree with incremental verification.
4. **L5 behavioural fingerprinting** — features derived from the ledger. Requires
   a **frozen** reference baseline; a detector retrained on live traffic learns
   the attack.
5. **L9 kill system** — needs both instantaneous and accumulating triggers.
   Pure thresholds are pace-able by a patient adversary; port the EWMA from
   multi-agent-mcl.
6. **L6 cognitive drift** — last, and advisory only. Reading reasoning traces
   assumes they are faithful to the computation, which is precisely what MCL's
   concealment dimension says not to assume. May raise suspicion; must never
   clear it.

**Missing from the original nine:** an untrusted-artifact ingestion boundary.
Hugging Face was compromised by an uploaded dataset hitting a remote-code loader
and a template-injection bug in config parsing. No agent-side layer defends a
platform's own parser. Needs isolated parsing, no-code-execution loaders by
default, schema validation before parse.
