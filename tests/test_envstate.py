"""
Adversarial tests for L7 (environment mutation detection).

The slow attack this layer exists for:
    install a package -> modify a config -> replace an executable -> exploit later
Each step is unremarkable alone. Only the sequence, against a frozen baseline,
is visible.
"""

import pytest

from ames.commit import ZERO_DIGEST
from ames.events import Capability, FileOp
from containment.broker import Broker
from containment.envstate import (
    EnvStateError, EnvironmentBaseline, EnvironmentMonitor, MutationObservation,
    MutationVerdict, PathClass, PathPolicy, normalise,
)
from containment.policy import CapabilityPolicy, CapabilityRequest


def d(b: int) -> bytes:
    return bytes([b]) * 32


def obs(path, before=1, after=2, op=FileOp.WRITE, actor=100, ts=1000):
    return MutationObservation(path, op,
                               d(before) if before else ZERO_DIGEST,
                               d(after) if after else ZERO_DIGEST, ts, actor)


def sealed_baseline(**files):
    b = EnvironmentBaseline()
    for path, val in files.items():
        b.add(path.replace("__", "/"), d(val))
    b.seal()
    return b


# ---------------------------------------------------------------------------
# Path classification -- decided AFTER normalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", [
    ("/rootfs/lib/libc.so", PathClass.IMMUTABLE),
    ("/usr/bin/python3",    PathClass.IMMUTABLE),
    ("/etc/passwd",         PathClass.IMMUTABLE),
    ("/workspace/out.txt",  PathClass.MUTABLE),
    ("/tmp/scratch",        PathClass.EPHEMERAL),
])
def test_classification(path, expected):
    assert PathPolicy().classify(path) is expected


@pytest.mark.parametrize("path", [
    "/workspace/../rootfs/libc.so",
    "/workspace/a/b/../../../usr/bin/python3",
    "/tmp/../etc/shadow",
    "/workspace/./../../etc/passwd",
])
def test_traversal_cannot_launder_an_immutable_path(path):
    """A path that classifies differently before and after normalisation is a
    bypass. Resolution must happen first."""
    assert PathPolicy().classify(path) is PathClass.IMMUTABLE


def test_unknown_regions_default_to_immutable():
    """An unclassified path that turns out to be writable is a hole; a false
    alarm is only noise."""
    assert PathPolicy().classify("/some/new/mount") is PathClass.IMMUTABLE


def test_sibling_prefix_is_not_a_child():
    """'/rootfs-evil' must not pass as living under '/rootfs'."""
    p = PathPolicy(immutable_prefixes=("/rootfs",), mutable_prefixes=("/workspace",))
    assert p.classify("/rootfs-evil/x") is PathClass.IMMUTABLE  # unknown -> immutable
    assert p.classify("/rootfs/x") is PathClass.IMMUTABLE


@pytest.mark.parametrize("bad", ["relative/path", "", "/x\x00y"])
def test_malformed_paths_rejected(bad):
    with pytest.raises(EnvStateError):
        normalise(bad)


def test_climbing_above_root_resolves_to_root_not_an_error():
    """POSIX resolves '/..' back to '/', so this is a legitimate path meaning
    '/escape' -- which then classifies as an unknown region, i.e. immutable."""
    assert normalise("/../escape") == "/escape"
    assert PathPolicy().classify("/../escape") is PathClass.IMMUTABLE


@pytest.mark.parametrize("path,expected", [
    ("//rootfs/libc.so", "/rootfs/libc.so"),
    ("///workspace/a",   "/workspace/a"),
    ("//workspace/x",    "/workspace/x"),
])
def test_leading_slashes_are_collapsed(path, expected):
    """POSIX leaves exactly two leading slashes implementation-defined and
    Python preserves them, so '//rootfs/x' would miss the '/rootfs' prefix."""
    assert normalise(path) == expected


def test_double_slash_cannot_dodge_immutable_classification():
    assert PathPolicy().classify("//rootfs/libc.so") is PathClass.IMMUTABLE
    assert PathPolicy().classify("//workspace/out.txt") is PathClass.MUTABLE


# ---------------------------------------------------------------------------
# The signal this layer exists for
# ---------------------------------------------------------------------------

def test_write_to_readonly_region_means_a_layer_below_failed():
    """L1 makes the rootfs read-only structurally. A write there is not a policy
    violation to be scored -- it is evidence the invariant did not hold."""
    m = EnvironmentMonitor(sealed_baseline(__rootfs__libc_so=1))
    v = m.observe(obs("/rootfs/libc_so"))
    assert v is MutationVerdict.IMPOSSIBLE
    assert m.containment_failed


def test_unexplained_write_in_writable_region_is_flagged():
    """The interesting signal is not 'a file changed', it is 'a file changed and
    no permitted action explains it'."""
    m = EnvironmentMonitor(sealed_baseline(__workspace__out_txt=1))
    v = m.observe(obs("/workspace/out_txt"), granted_write_paths=frozenset())
    assert v is MutationVerdict.UNEXPLAINED
    assert not m.containment_failed


def test_granted_write_is_expected():
    m = EnvironmentMonitor(sealed_baseline(__workspace__out_txt=1))
    v = m.observe(obs("/workspace/out_txt"),
                  granted_write_paths=frozenset({"/workspace/out_txt"}))
    assert v is MutationVerdict.EXPECTED


def test_grant_for_one_path_does_not_cover_another():
    m = EnvironmentMonitor(sealed_baseline(__workspace__a=1, __workspace__b=1))
    assert m.observe(obs("/workspace/b"),
                     granted_write_paths=frozenset({"/workspace/a"})) is MutationVerdict.UNEXPLAINED


def test_ephemeral_writes_are_not_noise():
    m = EnvironmentMonitor(sealed_baseline())
    assert m.observe(obs("/tmp/scratch")) is MutationVerdict.EXPECTED


# ---------------------------------------------------------------------------
# Correlation with L2 -- the actual join
# ---------------------------------------------------------------------------

def test_end_to_end_with_the_real_broker():
    """L2 decides; L7 checks what actually happened against what was permitted."""
    pol = CapabilityPolicy(allowed_write_paths=frozenset({"/workspace/allowed.txt"}))
    broker = Broker(pol)

    broker.request(CapabilityRequest(Capability.FILE_WRITE, "/workspace/allowed.txt"))
    broker.request(CapabilityRequest(Capability.FILE_WRITE, "/workspace/denied.txt"))

    granted = frozenset(
        dec.request.resource for dec in broker.history if dec.verdict.granted
    )
    assert granted == {"/workspace/allowed.txt"}

    m = EnvironmentMonitor(sealed_baseline(__workspace__allowed_txt=1,
                                           __workspace__denied_txt=1))
    assert m.observe(obs("/workspace/allowed.txt"), granted) is MutationVerdict.EXPECTED
    # The agent wrote it anyway -- refusal at the broker does not stop a write
    # that bypasses the broker, which is exactly why this layer exists.
    assert m.observe(obs("/workspace/denied.txt"), granted) is MutationVerdict.UNEXPLAINED


# ---------------------------------------------------------------------------
# Baseline integrity
# ---------------------------------------------------------------------------

def test_baseline_cannot_be_modified_after_sealing():
    """A reference an adversary can move is not a reference. This is the failure
    mode of anomaly detectors retrained on live traffic."""
    b = sealed_baseline(__workspace__a=1)
    with pytest.raises(EnvStateError, match="sealed"):
        b.add("/workspace/evil", d(9))


def test_monitor_requires_a_sealed_baseline():
    b = EnvironmentBaseline()
    b.add("/workspace/a", d(1))
    with pytest.raises(EnvStateError, match="seal"):
        EnvironmentMonitor(b)


def test_root_is_order_independent():
    """The root must be a function of the file SET, not of collector walk order."""
    a, b = EnvironmentBaseline(), EnvironmentBaseline()
    for p, v in [("/workspace/a", 1), ("/workspace/b", 2), ("/workspace/c", 3)]:
        a.add(p, d(v))
    for p, v in [("/workspace/c", 3), ("/workspace/a", 1), ("/workspace/b", 2)]:
        b.add(p, d(v))
    assert a.seal() == b.seal()


def test_empty_baseline_has_a_distinct_root():
    assert EnvironmentBaseline().seal() == ZERO_DIGEST


def test_any_content_change_moves_the_root():
    m = EnvironmentMonitor(sealed_baseline(__workspace__a=1))
    before = m.current_root()
    assert not m.drifted
    m.observe(obs("/workspace/a", 1, 2), frozenset({"/workspace/a"}))
    assert m.current_root() != before
    assert m.drifted


def test_creation_and_deletion_both_move_the_root():
    m = EnvironmentMonitor(sealed_baseline(__workspace__a=1))
    m.observe(obs("/workspace/new", before=None, after=5), frozenset({"/workspace/new"}))
    after_create = m.current_root()
    assert after_create != m.baseline.root()

    m.observe(obs("/workspace/a", before=1, after=None), frozenset({"/workspace/a"}))
    assert m.current_root() not in (after_create, m.baseline.root())


def test_deleting_then_recreating_identical_content_restores_the_root():
    """Round-tripping must be visible in the observation log even though the
    resulting state matches -- the log is the record, the root is only a summary."""
    m = EnvironmentMonitor(sealed_baseline(__workspace__a=1))
    base = m.baseline.root()
    g = frozenset({"/workspace/a"})
    m.observe(obs("/workspace/a", before=1, after=None), g)
    assert m.drifted
    m.observe(obs("/workspace/a", before=None, after=1), g)
    assert m.current_root() == base and not m.drifted
    assert len(m.observations) == 2, "the round trip must remain in the log"


def test_rollback_target_is_the_sealed_baseline():
    m = EnvironmentMonitor(sealed_baseline(__workspace__a=1))
    m.observe(obs("/workspace/a"), frozenset({"/workspace/a"}))
    assert m.rollback_target() == m.baseline.root()


# ---------------------------------------------------------------------------
# Collector hygiene
# ---------------------------------------------------------------------------

def test_noop_observation_rejected():
    """A collector reporting unchanged files would let real changes hide in the
    volume it generates."""
    with pytest.raises(EnvStateError, match="before == after"):
        MutationObservation("/workspace/a", FileOp.WRITE, d(1), d(1), 1, 1)


@pytest.mark.parametrize("bad", [b"short", b"", "notbytes", b"x" * 33])
def test_digests_must_be_32_bytes(bad):
    with pytest.raises(EnvStateError):
        MutationObservation("/workspace/a", FileOp.WRITE, bad, d(2), 1, 1)


def test_creation_and_deletion_flags_follow_the_digests():
    assert obs("/workspace/a", before=None, after=5).is_creation
    assert obs("/workspace/a", before=5, after=None).is_deletion


# ---------------------------------------------------------------------------
# The slow attack, end to end
# ---------------------------------------------------------------------------

def test_the_patient_sequence_is_visible_against_the_baseline():
    """No single step is alarming. The point is that all of them are recorded and
    the ones nothing explains are separable afterwards."""
    m = EnvironmentMonitor(sealed_baseline(
        __workspace__app_conf=1, __workspace__helper_sh=1, __usr__bin__python3=1))
    granted = frozenset({"/workspace/app_conf"})

    m.observe(obs("/workspace/app_conf", 1, 2), granted)      # permitted config edit
    m.observe(obs("/workspace/helper_sh", 1, 2), granted)     # unexplained
    m.observe(obs("/usr/bin/python3", 1, 2), granted)         # impossible

    s = m.summary()
    assert s["expected"] == 1 and s["unexplained"] == 1 and s["impossible"] == 1
    assert m.containment_failed
    assert [o.path for o in m.by_verdict(MutationVerdict.UNEXPLAINED)] == ["/workspace/helper_sh"]


def test_high_event_volume_does_not_require_rehashing_content():
    """Cost model: the polling design re-read file CONTENT every second. Here an
    observation touches one entry and the root is recomputed over digests only."""
    b = EnvironmentBaseline()
    for i in range(500):
        b.add(f"/workspace/f{i}", d(i % 256))
    b.seal()
    m = EnvironmentMonitor(b)
    g = frozenset(f"/workspace/f{i}" for i in range(500))
    for i in range(500):
        m.observe(obs(f"/workspace/f{i}", i % 256, (i + 1) % 256), g)
    assert len(m.observations) == 500
    assert m.summary()["expected"] == 500
