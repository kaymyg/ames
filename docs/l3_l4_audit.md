# L3 / L4 — Coverage Audit, and What It Found

**Status:** resolved. 22 new tests. 272 total across the repo.

This settles the question left open since L0: are **L3 (Immutable Filesystem)**
and **L4 (Identity Verification)** genuinely subsumed by L1's read-only rootfs
and L8's Gate 1 lineage balance, or were they simply never built?

**Answer: about half subsumed, half not — and the un-subsumed half was the more
security-relevant half.** The earlier working assumption ("largely covered by
L1/L8") was too generous. This document records the per-claim verdict, and
`containment/identity.py` closes what could honestly be closed.

---

## A discrepancy in the original spec worth noting first

The original design document contains two different layer numberings. Its
ASCII diagram reads:

```
L1 Physical Isolation   L2 Execution Isolation   L3 Communication
L4 Identity             L5 Behaviour             L6 Memory
L7 Environment          L8 Forensics             L9 Recovery
```

…while the detailed prose sections that follow read L1 Physical Isolation, L2
Zero External Trust, **L3 Immutable Filesystem**, L4 Identity Verification, L5
Behaviour Fingerprinting, L6 Cognitive Drift, L7 Environment Mutation, L8
Cryptographic Action Ledger, L9 Autonomous Kill System.

Everything in this repo was built against the **prose**, which is the specific
one. Flagging the mismatch because a reader comparing the diagram to this
codebase would otherwise think three layers were misnumbered.

---

## L3 — Immutable Filesystem

> *"Make the execution filesystem read-only. `/` readonly, `/tmp` memory only,
> `/workspace` copy-on-write. The model cannot modify python, bash, libraries,
> ld.so, openssl, kernel modules. Every binary is cryptographically verified
> before execution."*

| Claim | Verdict | Enforced by |
|---|---|---|
| `/` read-only | **Covered** | `DiskSpec.__post_init__` rejects writable non-ephemeral disks; `IsolationPolicy.validate` rejects a writable rootfs; `build_firecracker_config` emits `is_read_only: true`; `kernel_args` bans `rw`, `init=/bin/sh`, `single` |
| Cannot modify python/bash/libs/ld.so/openssl | **Covered (detective + structural)** | Those paths live in the read-only rootfs. L7's `PathPolicy.immutable_prefixes` (`/usr /lib /bin /sbin /etc`) classifies any write there as `IMPOSSIBLE` → L9 `CONTAINMENT_FAILURE`, an absolute kill |
| `/tmp` memory only | **Not enforced here** | `VmSpec` has no mount table at all. L7 *classifies* `/tmp` as `EPHEMERAL`, but nothing mounts it as tmpfs — that lives in the guest image's fstab/init, which this repo does not build |
| `/workspace` copy-on-write | **Partial** | An ephemeral overlay disk exists and is discarded on `destroy()` (the CoW property that matters: the base image is never mutated). But nothing binds that overlay to the *path* `/workspace`; L7's `mutable_prefixes` assumes the mapping without verifying it |
| **Every binary cryptographically verified before execution** | **Was not covered — now partially** | See below |

### The real gap

`payload_process_spawn` has carried a `binary_hash` field since AMES-V1.
**Nothing ever compared it to anything.** The whole rootfs image is measured
before boot (`backend.measure_image`), which transitively covers every binary
*shipped in the approved image* — but says nothing about a binary dropped into
the writable overlay at runtime, which is precisely where a dropped binary
would go.

`containment/identity.py`'s `BinaryPolicy` closes this: a frozen, build-time
allowlist of approved digests, sealed before the run, with no `remove`,
`update`, or `unseal` method (asserted structurally by
`test_policy_has_no_removal_or_update_api`). Membership is checked with
`hmac.compare_digest` per candidate rather than plain set membership — set
lookup short-circuits on the first differing byte, which is a timing oracle an
adversary submitting candidate digests could walk.

**What it does not close:** verification *inside the guest, at exec time*. That
needs IMA/dm-verity or an LSM hook in the guest image. Stated in
`SpawnAuthorizer.describe_guarantees()` and asserted by a test, so it cannot
quietly drift into an overclaim.

---

## L4 — Identity Verification

> *"Every process gets an identity: hash, parent, permissions, lifetime. Every
> child process must prove: Parent → Signature → Spawn token → Allowed. If not:
> Kill. No exceptions."*

| Claim | Verdict | Enforced by |
|---|---|---|
| identity: **hash** | **Covered (recorded)** | `payload_process_spawn(binary_hash, argv_hash, cwd)` — and now actually *checked*, not just recorded |
| identity: **parent** | **Covered** | `Event.parent_id`; Gate 1 `ORPHAN_SPAWN` when a parent was never spawned |
| identity: **lifetime** | **Covered** | Gate 1 spawn/exit balance; `UNTERMINATED_ACTOR` for a dormant process; L9 treats it as absolute |
| identity: **permissions** | **Not represented** | No permissions field exists in the AMES event schema. L2 tracks capabilities per *run*, not per *process*. Left unbuilt deliberately — see below |
| **Spawn token → Allowed** | **Was not covered — now covered host-side** | `SpawnAuthorizer` |
| "If not: Kill. No exceptions." | **Covered** | L9 has no disable/override/reset; fatal Gate 1 codes are absolute |

### The real gap

There was no spawn token, no signature, no issuance, and no pre-spawn check
anywhere. What existed was purely **detective**: Gate 1 flags `ORPHAN_SPAWN`,
`DOUBLE_SPAWN`, `RESPAWN_AFTER_EXIT`, `UNATTRIBUTED_ACTION` *after the fact*,
during verification, and L9 kills on them.

Detection after the fact is most of what L8 and L9 exist for, and it is
genuinely valuable. But the spec says *prove, then allowed* — and treating "we
would notice" as equivalent to "it cannot happen" is exactly the substitution
this framework's own premise says to assume an adversary is hunting for.

`SpawnAuthorizer` implements the chain: single-use tokens, bound to one parent
and one binary, issued only to a live parent, for an approved binary. Six
distinct denial reasons rather than one boolean, so an incident review can tell
a replay from a forgery from a transfer.

Two properties worth calling out, each with a test:

- **Single-use.** A reusable token is a persistent capability, and persistent
  capability across a boundary is what L1 destroys the whole VM to prevent.
- **Non-transferable.** A token presented by a different parent than it was
  issued to is refused — otherwise the token proves *possession*, not
  *identity*, and a stolen token would be as good as an authorized one.

### Why "permissions" was left unbuilt

Adding a per-process permission set means either duplicating L2's capability
model at a second granularity (two policy engines that can disagree — the
failure mode L2's own docstring warns about), or threading process identity
through the broker, which is real API surface across three modules. Neither is
a small decision, and inventing a second permission model to tick a box would
make the system *less* trustworthy, not more. Recorded as an open design
question rather than silently satisfied.

---

## What this changes about the framework's overall claim

Before this audit, five of the nine layers were built and two were assumed
covered. The honest position now:

- **L1, L2, L5, L6, L7, L8, L9** — built, tested, documented.
- **L3** — the read-only and mutation-detection halves were always covered;
  the binary-verification half is now covered *host-side*, with the
  guest-side/kernel-side half explicitly out of scope for this environment.
- **L4** — the lineage and lifetime halves were always covered *detectively*;
  the prove-before-allowed half is now covered *host-side*, with the same
  kernel-enforcement caveat.

The pattern in both cases is the same, and it is worth stating plainly: **this
repo is strong at making violations unforgeable and attributable, and weaker at
making them impossible.** That is a reasonable place for a software framework
to land — L1's whole premise is that prevention lives in the hypervisor and the
image, not in Python — but it should be said out loud rather than blurred by
counting L3 and L4 as "covered."

---

## Not guaranteed

- **Kernel-side enforcement of either control.** Host-side authorization makes
  an unauthorized spawn an attributable discrepancy, not an impossibility. A
  guest with arbitrary code execution can call `execve()` without asking.
- **That the guest image actually mounts `/tmp` as tmpfs or `/workspace` on the
  overlay.** This repo validates the VM spec; it does not build the image.
- **Per-process permissions.** Not modelled, deliberately (above).
- **That the allowlist is complete.** A `BinaryPolicy` is only as good as the
  build process that populated it — the same limit L5's baseline inherits from
  its reference runs.

## What's left

Only the hardware-dependent work: exercising `FirecrackerBackend` on a host
with `/dev/kvm`, validating the fanotify/eBPF collector L7 assumes, and
confirming vsock's one-directionality. All three stay out of reach from this
environment, and all three are named in `docs/l0_validation.md`.
