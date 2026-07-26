"""
The Runtime -- one entrypoint that wires L1-L9 into a single contained run.

WHY THIS EXISTS

Before this module, `ames` was nine individually correct layers with no way to
invoke them together. Every doc in `docs/` deferred the composition question
with some version of "wiring this is a deployment decision" -- which is honest
about scope, and also means every operator would have to rediscover the
correct wiring themselves. A framework whose safe use depends on each user
re-deriving the integration is a framework that will be integrated wrongly.

L0's `validation/scenarios.py` proved the layers *can* compose. This module is
the composition itself, as a supported API rather than a test fixture.

THE ORDER IS NOT ARBITRARY

    L1 validate spec    -- refuse an unsafe VM before anything is created
    L1 run              -- boot, supervise, tear down; emit host-observed events
      L2 broker         -- capability decisions, recorded into the SAME ledger
      L3/L4 authorizer  -- binary allowlist + spawn tokens, host-side
      L7 monitor        -- filesystem mutations classified against the baseline
    L8 gate1            -- structural verification of the resulting event stream
    L9 evidence + kill  -- host-observed evidence only, absolute rules first
    L5/L6 advisory      -- fingerprint and drift, computed AFTER the verdict

That last line is the load-bearing one. L5 and L6 are computed *after*
`KillVerdict` is already decided, and their outputs are not inputs to it. This
is not a convention the code politely follows -- `Evidence.from_run` has no
parameter that accepts a `SequenceVerdict` or a `DriftFinding`, so there is no
path from an advisory signal to a kill even if a future caller wanted one.
`test_advisory_findings_never_change_the_verdict` pins it.

FAIL CLOSED, EVERYWHERE

If any component raises -- including one this module does not anticipate --
`execute()` returns a report whose verdict is KILLED, never one that omits the
failure and looks clean. An exception in the containment system must never
read as "nothing to report." This mirrors `KillSwitch.evaluate`'s own
try/except, one level up.

WHAT THIS DOES NOT DO

It does not evaluate continuously. Kill evaluation happens after the run
completes, because `Supervisor.run()` is a single synchronous call and the
only in-flight hook is `backend.wait()`. A backend that supports periodic
callbacks could evaluate mid-run; the `FakeBackend` and `FirecrackerBackend`
shipped here do not. This is stated in `docs/runtime.md` rather than papered
over, because "the kill fires after the run is already finished" is a real
operational limit, not a detail.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from ames.events import EventType
from ames.gate1 import Gate1Result, verify as gate1_verify
from ames.ledger import Checkpoint, Ledger
from containment.backend import VmBackend
from containment.broker import Broker, DenialSignal, DenialTracker
from containment.drift import DriftFinding, DriftMonitor
from containment.envstate import EnvironmentBaseline, EnvironmentMonitor
from containment.fingerprint import (
    BehaviorFingerprint, SequenceVerdict, observations_from_ledger,
)
from containment.identity import BinaryPolicy, SpawnAuthorizer
from containment.killswitch import Evidence, KillSwitch, KillVerdict, kill_payload
from containment.policy import CapabilityPolicy, default_policy
from containment.supervisor import RunReport, Supervisor
from containment.vmspec import (
    HOST_ACTOR_ID, VM_ACTOR_ID, IsolationPolicy, PolicyViolation, VmSpec,
)


class RuntimeError_(Exception):
    """Runtime-level failure. Named with a trailing underscore to avoid
    shadowing the builtin, which a caller might legitimately want to catch
    separately."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Everything an operator chooses, in one reviewable object.

    Deliberately has no `enable_*` / `disable_*` flags for any layer. An
    operator tunes thresholds and supplies policies; there is no supported way
    to switch a layer off, for the same reason `KillSwitch` has no `disable()`
    -- a control with an off switch is a control an adversary looks for the
    off switch on. Omitting a baseline or a fingerprint means that layer has
    nothing to compare against and reports nothing, which is different from
    being disabled: it still runs, and it still cannot be told to approve
    something.
    """
    capability_policy: CapabilityPolicy = field(default_factory=default_policy)
    binary_policy: Optional[BinaryPolicy] = None
    environment_baseline: Optional[EnvironmentBaseline] = None
    fingerprint: Optional[BehaviorFingerprint] = None

    # L9 tuning. Thresholds only -- no rule can be removed.
    mutation_burst: int = 3
    mutation_window_s: float = 60.0
    mutation_ewma_threshold: float = 0.30

    # L2 tuning.
    denial_window_s: float = 60.0
    denial_burst: int = 5
    denial_ewma_threshold: float = 0.35

    def __post_init__(self) -> None:
        if self.binary_policy is not None and not self.binary_policy.sealed:
            raise RuntimeError_(
                "binary_policy must be sealed before the run; an allowlist that "
                "can grow mid-run is not an allowlist"
            )
        if self.environment_baseline is not None and not self.environment_baseline.sealed:
            raise RuntimeError_(
                "environment_baseline must be sealed before the run; a baseline "
                "that can move while it is being compared against is not a baseline"
            )
        if self.fingerprint is not None and not self.fingerprint.sealed:
            raise RuntimeError_("fingerprint must be sealed before the run")


class Verdict(str):
    """Terminal outcome of a contained run. A str subclass so it prints and
    compares naturally in logs and reports."""


ALLOWED = Verdict("allowed")
KILLED = Verdict("killed")
FAILED = Verdict("failed")     # the runtime itself could not complete; fail closed


@dataclass
class ContainmentReport:
    """Everything one run produced, in the order an incident review reads it.

    Deliberately carries the raw `ledger` and `checkpoint` alongside the
    computed verdicts: a report a reviewer cannot independently re-verify is a
    summary, not evidence. `verify()` below re-derives the structural result
    from the ledger rather than trusting the fields.
    """
    run_id: str
    verdict: Verdict
    kill: Optional[KillVerdict] = None
    gate1: Optional[Gate1Result] = None
    ledger: Optional[Ledger] = None
    checkpoint: Optional[Checkpoint] = None
    run_report: Optional[RunReport] = None

    # Host-observed detail
    broker: Optional[Broker] = None
    authorizer: Optional[SpawnAuthorizer] = None
    monitor: Optional[EnvironmentMonitor] = None

    # Advisory only -- never inputs to `kill`
    drift: List[DriftFinding] = field(default_factory=list)
    behaviour: List[Tuple] = field(default_factory=list)

    error: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOWED

    @property
    def advisory_findings(self) -> int:
        """Count of L5+L6 signals. Surfaced for a human queue; a nonzero value
        here has, by construction, no effect on `verdict`."""
        return len(self.drift) + sum(1 for _, v in self.behaviour if v.flagged)

    def verify(self) -> bool:
        """Independently re-check the ledger against its own checkpoint.

        A reviewer should not have to trust that this report's fields were
        computed honestly -- this recomputes every commitment from the raw
        events. Returns False rather than raising so it is safe to call while
        triaging an already-failed run.
        """
        if self.ledger is None or self.checkpoint is None:
            return False
        try:
            self.ledger.verify_chain(self.checkpoint)
            return True
        except Exception:
            return False

    def summary(self) -> str:
        parts = [f"run {self.run_id}: {self.verdict.upper()}"]
        if self.kill is not None and self.kill.kill:
            parts.append("kill=" + ",".join(r.value for r in self.kill.reasons))
        if self.gate1 is not None and not self.gate1.ok:
            parts.append(f"gate1={len(self.gate1.violations)} violation(s)")
        if self.advisory_findings:
            parts.append(f"advisory={self.advisory_findings} (no effect on verdict)")
        if self.error:
            parts.append(f"error={self.error}")
        return " | ".join(parts)


class Runtime:
    """Executes one contained run and returns a single verifiable report.

    Stateless between calls apart from the config: each `execute()` builds its
    own supervisor, broker, monitor and authorizer, because sharing any of
    them across runs would carry state over a run boundary -- the exact thing
    L1 destroys the VM to prevent.
    """

    def __init__(self, config: Optional[RuntimeConfig] = None) -> None:
        self.config = config or RuntimeConfig()

    def execute(self, spec: VmSpec, backend: VmBackend, *,
                during_run: Optional[Callable[["RunContext"], None]] = None,
                config_dir: Optional[Path] = None) -> ContainmentReport:
        """Validate, run, verify, judge. Never raises: every failure path
        returns a report, and an unexpected failure returns one whose verdict
        is KILLED.

        `during_run` receives a `RunContext` while the VM is notionally live,
        for callers driving a scripted or instrumented backend. It is the only
        hook, and it deliberately exposes the broker and authorizer rather
        than the supervisor's private emit path.
        """
        try:
            return self._execute_inner(spec, backend, during_run, config_dir)
        except PolicyViolation as exc:
            # An unsafe spec is refused before anything is created. This is the
            # one failure that is NOT a kill: nothing ran, so there is nothing
            # to contain -- but it is still never "allowed".
            return ContainmentReport(
                run_id=getattr(spec, "run_id", "<invalid>"),
                verdict=FAILED, error=f"spec refused by isolation policy: {exc}",
            )
        except Exception as exc:                       # noqa: BLE001 -- deliberate
            return ContainmentReport(
                run_id=getattr(spec, "run_id", "<unknown>"),
                verdict=KILLED,
                error=(f"runtime raised {type(exc).__name__}: {exc}; failing closed "
                       f"-- an exception in the containment system must never read "
                       f"as nothing to report"),
            )

    # --- internals ----------------------------------------------------------

    def _execute_inner(self, spec: VmSpec, backend: VmBackend,
                       during_run: Optional[Callable[["RunContext"], None]],
                       config_dir: Optional[Path]) -> ContainmentReport:
        cfg = self.config

        # L1. Refuse an unsafe spec before creating anything at all.
        IsolationPolicy.validate(spec)

        # The hook wrapper must be in place BEFORE the supervisor is built,
        # because the supervisor captures its backend at construction --
        # reassigning a local `backend` afterwards would leave the supervisor
        # holding the unwrapped one and the hook would silently never fire.
        # (It did exactly that in the first revision of this module; four
        # tests caught it.) The context the hook receives is not complete
        # until the supervisor and broker exist, so it is late-bound below,
        # the same shape `validation.scenarios.ScriptedBackend` uses.
        hooked = _HookedBackend(backend, during_run) if during_run is not None else None
        supervisor = Supervisor(hooked or backend)

        # L2. The broker emits into the SAME ledger the supervisor produces, so
        # capability decisions are sequence-ordered against VM lifecycle events
        # rather than living in a second, uncorrelated log.
        broker = Broker(
            cfg.capability_policy,
            emit=supervisor.emit_host_event,
            tracker=DenialTracker(
                window_seconds=cfg.denial_window_s,
                burst_threshold=cfg.denial_burst,
                ewma_threshold=cfg.denial_ewma_threshold,
            ),
        )

        # L3/L4. Only constructed when an allowlist was supplied: an authorizer
        # over an empty allowlist would deny every spawn, which is safe but
        # indistinguishable from a misconfiguration.
        authorizer: Optional[SpawnAuthorizer] = None
        if cfg.binary_policy is not None:
            authorizer = SpawnAuthorizer(spec.run_id, cfg.binary_policy)
            authorizer.register_root(HOST_ACTOR_ID)
            authorizer.register_root(VM_ACTOR_ID)

        # L7.
        monitor: Optional[EnvironmentMonitor] = None
        if cfg.environment_baseline is not None:
            monitor = EnvironmentMonitor(cfg.environment_baseline)

        if hooked is not None:
            hooked.ctx = RunContext(supervisor=supervisor, broker=broker,
                                    authorizer=authorizer, monitor=monitor)

        run_report = supervisor.run(spec, config_dir)
        events = list(run_report.ledger.all_events())

        # L8. Structural verification of what actually got recorded.
        gate1 = gate1_verify(events)

        # L9. Host-observed evidence only. Note what is NOT passed in: no
        # fingerprint, no drift. There is no parameter for them.
        evidence = Evidence.from_run(
            monitor=monitor,
            gate1_violation_codes=[v.code for v in gate1.violations],
            broker_history=broker.history,
            denial_signal=_last_signal(broker),
            ledger_events=events,
        )
        kill = KillSwitch(
            mutation_burst=cfg.mutation_burst,
            mutation_window_s=cfg.mutation_window_s,
            mutation_ewma_threshold=cfg.mutation_ewma_threshold,
        ).evaluate(evidence)

        # L5/L6. Computed AFTER the verdict, and structurally unable to reach
        # it. Advisory output for a human queue.
        drift = DriftMonitor().evaluate_ledger(events)
        behaviour: List[Tuple] = []
        if cfg.fingerprint is not None:
            behaviour = cfg.fingerprint.evaluate(observations_from_ledger(events))

        return ContainmentReport(
            run_id=spec.run_id,
            verdict=KILLED if kill.kill else ALLOWED,
            kill=kill, gate1=gate1,
            ledger=run_report.ledger, checkpoint=run_report.checkpoint,
            run_report=run_report,
            broker=broker, authorizer=authorizer, monitor=monitor,
            drift=drift, behaviour=behaviour,
        )


@dataclass
class RunContext:
    """What a caller may touch while the VM is notionally live.

    Deliberately exposes the broker and authorizer -- the two components an
    agent's activity legitimately drives -- and the supervisor for recording
    guest claims. It does not expose the kill switch: nothing that runs during
    the run should be able to reach into the decision made about it.
    """
    supervisor: Supervisor
    broker: Broker
    authorizer: Optional[SpawnAuthorizer] = None
    monitor: Optional[EnvironmentMonitor] = None


class _HookedBackend(VmBackend):
    """Wraps a backend so `during_run` fires inside `wait()` -- the only point
    at which caller code still runs between the VM's recorded spawn and exit.
    Same mechanism `validation.scenarios.ScriptedBackend` uses, promoted here
    so callers get it without importing a test helper."""

    def __init__(self, inner: VmBackend, hook: Callable[[RunContext], None]) -> None:
        self._inner = inner
        self._hook = hook
        # Late-bound: the context is not complete until the supervisor and
        # broker exist, and the supervisor cannot be built until this wrapper
        # does. Set by Runtime._execute_inner before run() is called.
        self.ctx: Optional[RunContext] = None

    def measure_image(self, path):
        return self._inner.measure_image(path)

    def prepare_overlay(self, base, overlay, size_mib):
        return self._inner.prepare_overlay(base, overlay, size_mib)

    def boot(self, spec, config_path):
        return self._inner.boot(spec, config_path)

    def wait(self, spec):
        if self.ctx is None:
            raise RuntimeError_("hook context was never bound; this is a Runtime bug")
        self._hook(self.ctx)
        return self._inner.wait(spec)

    def destroy(self, spec):
        # Contractually total, like every destroy(): a hook failure must never
        # prevent teardown.
        return self._inner.destroy(spec)


def _last_signal(broker: Broker) -> Optional[DenialSignal]:
    """The most recent denial signal, or None if nothing was ever requested.

    The tracker's state is cumulative, so the last signal carries the whole
    run's EWMA -- taking the last one is not sampling, it is reading the
    accumulated value.
    """
    return broker.history[-1].signal if broker.history else None
