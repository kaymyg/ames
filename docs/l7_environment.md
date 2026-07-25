# L7 — Environment Mutation Detection

**Status:** state model, classifier and L2 correlation complete. 41 tests.
Collector (fanotify/eBPF) not exercised — needs kernel privileges.

---

## The attack

    install a package → modify a config → replace an executable → exploit later

Each step is unremarkable alone. Only the sequence is an attack, and only
against a frozen baseline is the sequence visible.

## What this layer is actually for here

In a naive stack L7 catches ordinary configuration drift. In *this* stack L1
already makes the rootfs read-only and discards the overlay after every run, so
drift of that kind cannot persist. That makes L7's real job different, and more
valuable:

> **L7 detects that a layer below has already failed.**

A write to a read-only region is not "unexpected configuration change". It is
evidence that the hypervisor, the kernel, or the mount enforcement did not hold.
That is the framework's own premise — *assume every other layer has already
failed* — turned into a tripwire, and it is why this layer is not a nicer report
on facts L1 already knows.

`containment_failed` is therefore not a score to weigh. It means an invariant
enforced structurally did not hold, so the response is to stop.

---

## Why not hash everything every second

The original design called for hashing the filesystem, memory maps, process
list, kernel state and loaded libraries once per second. That does not survive
contact with a real filesystem: a 100k-file rootfs is tens of gigabytes of reads
per minute. The monitor becomes the dominant workload and is the first thing an
operator disables under load — **a control that gets switched off is worse than
no control, because it is still on the architecture diagram.**

So capture is **event-driven** (fanotify/eBPF) and verification is
**incremental** against a merkle baseline. An observation touches one entry;
the root is recomputed over *digests*, never by re-reading file content. Full
re-verification is a checkpoint operation, not a polling loop.

---

## Three verdicts

| Verdict | Meaning |
|---|---|
| `EXPECTED` | A writable region changed and an L2 grant explains it |
| `UNEXPLAINED` | A writable region changed and **nothing** explains it |
| `IMPOSSIBLE` | A read-only region changed — a layer below failed |

The join with L2 is the point of the layer. The interesting signal is not
"a file changed" — it is **"a file changed and no permitted action explains
it."** A broker refusal does not stop a write that bypasses the broker, which is
precisely why observation is needed alongside authorisation.

---

## Path handling

Classification happens **after** normalisation, because a path that classifies
differently before and after is a bypass: `/workspace/../rootfs/libc.so` must be
judged as `/rootfs/libc.so`.

Two subtleties, both found by tests rather than by design:

- **`/../escape` is legitimate.** POSIX resolves a climb above root back to
  root, so it means `/escape` — which classifies as an unknown region, i.e.
  immutable. The test asserting this originally expected an error; the code was
  right and the test was wrong.
- **Leading slashes must be collapsed.** POSIX leaves exactly two leading
  slashes implementation-defined and Python *preserves* them, so
  `//rootfs/libc.so` would miss the `/rootfs` prefix. That failed safe today
  (unknown regions classify immutable) but was latent — a policy change making
  unknown regions permissive would have turned it into a hole.

Unknown regions default to **immutable**: an unclassified path that turns out to
be writable is a hole, whereas a false alarm is only noise. Prefix matching is
anchored at a directory boundary so `/rootfs-evil` cannot pass as a child of
`/rootfs`.

Prefix matching is safe here in a way L2's package allowlist is not: a filesystem
hierarchy *is* a prefix tree, and these prefixes describe operator-chosen mount
points, not agent-supplied names.

---

## Baseline integrity

The baseline is frozen by `seal()` and cannot be modified afterwards. **A
reference an adversary can move is not a reference** — that is the failure mode
of anomaly detectors retrained on live traffic, and the same reason L5 will need
a frozen distribution.

The merkle root is computed over `(path, digest)` leaves **sorted by path**, so
it is a function of the file *set* rather than of the order the collector
happened to walk them.

Collector hygiene is enforced: an observation whose `before == after` is
rejected, because a collector reporting unchanged files would let real changes
hide in the volume it generates.

---

## Not guaranteed

- **The collector itself.** fanotify/eBPF needs kernel privileges this sandbox
  lacks. Its output shape is `MutationObservation`, so the adapter is
  deliberately thin — untested code should be as small as possible.
- **Completeness.** An observation never delivered is never classified. A
  collector inside the guest could be silenced; it belongs on the host side of
  the L1 boundary for the same reason the ledger producer does.
- **Memory, process and kernel state.** Only filesystem mutation is modelled
  here. The other channels in the original design need their own collectors.

## Next

**L9 — the kill system.** Wire `containment_failed` to an unconditional stop,
and pair L2's denial signal with it. Both trigger types are needed: pure
thresholds are pace-able, which is the boil-the-frog problem already solved once
in L2.
