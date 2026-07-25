# L1 — Physical Isolation

**Status:** host-side supervisor complete and tested against a fake backend.
Firecracker adapter written, **not** exercised by these tests.

---

## The invariant

The July 2026 OpenAI escape did not defeat a VM boundary. The sandbox had a
deliberate hole: a **package-registry cache proxy**, present so the contained
agent could install packages. The models found a zero-day in the proxy and left
through the one component trusted to bridge inside and outside.

The conclusion is not "write a better proxy":

> A contained execution environment MUST NOT have a runtime path to the outside
> world at all.

Dependencies are baked into the rootfs at build time, before the agent exists,
and the image is measured. If the agent needs something absent, the run fails and
a human rebuilds the image. That is inconvenient by design — the convenience of
runtime installation is exactly what was exploited.

`IsolationPolicy.validate()` refuses any spec requesting a network device. No
override, no flag, no trusted-proxy exemption. **A policy with an escape hatch is
the escape hatch.** `VmSpec` has no field for a network interface: you cannot
configure what the type cannot express, and the generated Firecracker config
omits `network-interfaces` entirely, so the guest kernel finds no device — not a
blocked one, none.

---

## Trust split

The supervisor is the AMES producer and runs on the **host**. Anything inside the
perimeter is in the adversary's blast radius; a ledger writer in the guest would
be corrupted by the very attack it exists to record.

| Provenance | Actor id | Meaning |
|---|---|---|
| Host-observed | `>= 0xFF..FF00` | VM lifecycle, image measurements, exit status. The guest never writes to the ledger, so these are unforgeable from inside. |
| Guest-reported | `< 0xFF..FF00` | Claims submitted over vsock. Recorded faithfully; trusted no further than the guest. |

`record_guest_claim()` raises if asked to attribute a guest claim to the host
band. An analyst can always separate **evidence** from **testimony**.

The supervisor is modelled as the root process and the microVM as its child, so
Gate 1's lineage balance covers the whole run — a VM never torn down surfaces as
`UNTERMINATED_ACTOR` rather than as silence.

---

## Transport

One channel crosses the boundary, so it is the highest-value target.

1. **Data only, one direction.** No RPC, no dispatch, no callbacks — nothing that
   turns a message into an action.
2. **The parser is the attack surface.** Hugging Face fell to an uploaded dataset
   hitting a remote-code loader and a template-injection bug: untrusted bytes
   meeting a permissive parser. So the format is fixed-width binary with explicit
   bounds — no JSON, no pickle, no eval, no templates.

Bounds are checked *before* any allocation proportional to a claimed size. The
rejection log is itself capped, so error handling cannot become a
memory-exhaustion primitive. A malformed trailing frame truncates the stream
rather than discarding it — a guest must not be able to erase its own audit trail
with one bad byte.

---

## What is proven, and what is assumed

**Proven here (41 tests):** network/share/persistence specs refused; writable
rootfs and shared-path disks refused; resource and kernel-arg bounds enforced;
`destroy()` runs on *every* path including boot and wait failures; invalid specs
never reach the backend; images measured before boot; guests cannot forge host
actor ids or run-boundary markers; transport floods, oversized claims and
malformed frames handled; run records verify and pass Gate 1; tampering detected.

**Assumed, not proven:**

- That Firecracker isolates correctly. `FirecrackerBackend` needs `/dev/kvm` and
  privileges no CI sandbox should hold. Reviewed-but-unproven until L0 runs it on
  real hardware.
- That guest-reported events are complete. A compromised guest can omit or
  fabricate freely; only host observations carry weight.
- No side-channel resistance between guest and host. SMT is disabled to reduce
  cross-thread leakage, which is mitigation, not elimination.

---

## Next

**L2 — zero external trust.** Every denied capability already emits a
`CAPABILITY_REQUEST` with `granted=0`; a burst of denials is a first-class
escape-probing signal for L9. The broker belongs on the host beside the
supervisor, never in the guest — same reasoning as the ledger producer.
