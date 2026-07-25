"""
L0 -- Adversarial Validation Engine.

Sits outside the L1-L9 stack rather than inside it: every other layer defends
the run; this one checks whether the layers actually hold, and whether they
hold TOGETHER, not just individually.

Two things are honestly buildable in this environment, and one is not.

BUILDABLE, AND BUILT HERE:

1. `validation.properties` -- property-based fuzzing (Hypothesis) of the pure,
   deterministic logic every other layer's correctness depends on: canonical
   encoding, merkle commitments, Gate 1's structural invariants. Every other
   test in this repo is example-based -- a human picked the attack. Fuzzing
   asks the same question across thousands of machine-generated cases a human
   would not have thought to pick, which is a different and complementary kind
   of adversarial validation.

2. `validation.scenarios` -- full-stack composed scenarios that wire real
   components together (`Supervisor`, `Broker`, `EnvironmentMonitor`,
   `KillSwitch`, `DriftMonitor`) and drive them through one coherent run, then
   check the SYSTEM's outcome. Every layer up to this point has been tested in
   isolation, which is necessary but not sufficient: `killswitch.Evidence` is
   deliberately assembled from independent inputs
   (`monitor`, `gate1_violation_codes`, `broker_history`, `denial_signal`,
   `ledger_events`), and nothing before this module has actually driven a real
   `Broker` or a real `EnvironmentMonitor` and fed their REAL output into a
   real `KillSwitch` end to end. `Evidence.from_run`'s signature was built for
   exactly this composition; this module is its first real caller.

NOT BUILDABLE HERE, AND NOT PRETENDED:

Whether Firecracker itself isolates correctly, whether the fanotify/eBPF
collector L7 assumes actually delivers what `MutationObservation` expects,
whether vsock enforces the one-direction-only property `transport.py` assumes
-- none of that can be checked from this sandbox, which has no `/dev/kvm` and
no kernel privileges. `containment.backend.FirecrackerBackend` says so in its
own docstring: "reviewed but not exercised... until the L0 adversarial
validation engine runs it on real hardware." That sentence is still true after
this module. L0 as built here validates COMPOSITION and LOGICAL INVARIANTS in
software; it does not and cannot validate the hypervisor underneath them. See
`docs/l0_validation.md` for the full scope statement.
"""

from validation.scenarios import (
    ScenarioResult, ScriptedBackend, SCENARIOS, run_all,
)

__all__ = ["ScenarioResult", "ScriptedBackend", "SCENARIOS", "run_all"]
