"""
Adversarial tests for L3/L4 (binary verification + spawn authorization).

Governing question: can an adversary who has read this file get a spawn
authorized for a binary that was not in the approved image, or for a parent
it does not control?
"""

import pytest

from ames.canonical import payload_process_spawn
from ames.commit import DIGEST_SIZE
from containment.identity import (
    BinaryPolicy, IdentityError, SpawnAuthorizer, SpawnDenial,
    binary_hash_from_spawn_payload,
)

PARENT = 0x100
CHILD = 0x200


def d(b: int) -> bytes:
    return bytes([b]) * DIGEST_SIZE


def sealed_policy(*digests: bytes) -> BinaryPolicy:
    p = BinaryPolicy()
    for i, dig in enumerate(digests):
        p.approve(dig, label=f"bin{i}")
    p.seal()
    return p


def authorizer(*digests: bytes) -> SpawnAuthorizer:
    a = SpawnAuthorizer("run-l3l4-001", sealed_policy(*digests))
    a.register_root(PARENT)
    return a


# ---------------------------------------------------------------------------
# BinaryPolicy: frozen after seal, same discipline as L5/L7 baselines
# ---------------------------------------------------------------------------

def test_approve_after_seal_raises():
    p = sealed_policy(d(1))
    with pytest.raises(IdentityError):
        p.approve(d(2))


def test_unapproved_binary_is_not_approved():
    p = sealed_policy(d(1))
    assert p.is_approved(d(1))
    assert not p.is_approved(d(2))


def test_malformed_digest_is_never_approved():
    p = sealed_policy(d(1))
    for bad in (b"", b"short", None, 12345, d(1)[:-1] + b"\x00\x00"):
        assert not p.is_approved(bad)


def test_policy_has_no_removal_or_update_api():
    """An adversary who can un-approve nothing and approve nothing after seal
    has no path to widen the allowlist. Asserted structurally rather than
    trusted from the docstring."""
    p = sealed_policy(d(1))
    for forbidden in ("remove", "revoke", "update", "unseal", "clear", "extend"):
        assert not hasattr(p, forbidden), f"BinaryPolicy exposes {forbidden}()"


def test_authorizer_refuses_an_unsealed_policy():
    p = BinaryPolicy()
    p.approve(d(1))
    with pytest.raises(IdentityError):
        SpawnAuthorizer("run-x", p)


# ---------------------------------------------------------------------------
# L3: "every binary is cryptographically verified before execution"
# ---------------------------------------------------------------------------

def test_unknown_binary_is_denied_even_with_a_valid_token():
    """The core L3 claim. A token is necessary but never sufficient: an
    approved parent presenting a genuinely-issued token still cannot launch a
    binary that was not in the approved image."""
    a = authorizer(d(1))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(9), token=token)
    assert not v.allowed
    assert v.denial is SpawnDenial.UNKNOWN_BINARY


def test_cannot_issue_a_token_for_an_unapproved_binary():
    a = authorizer(d(1))
    with pytest.raises(IdentityError):
        a.issue(parent_actor=PARENT, binary_hash=d(9))


def test_approved_binary_with_a_valid_token_is_authorized():
    """True-positive baseline: if this fails, every denial above is
    meaningless because the system would be refusing everything."""
    a = authorizer(d(1))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(1), token=token)
    assert v.allowed
    assert v.denial is None


# ---------------------------------------------------------------------------
# L4: "every child process must prove Parent -> Signature -> Spawn token"
# ---------------------------------------------------------------------------

def test_spawn_without_a_token_is_denied():
    a = authorizer(d(1))
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(1), token=None)
    assert not v.allowed
    assert v.denial is SpawnDenial.NO_TOKEN


def test_forged_token_is_denied():
    """A guest that fabricates 32 random bytes has not minted a token: the
    authorizer holds the only record of what was actually issued."""
    a = authorizer(d(1))
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(1), token=b"\xAB" * 32)
    assert not v.allowed
    assert v.denial is SpawnDenial.UNKNOWN_TOKEN


def test_token_cannot_be_replayed():
    """Single-use is load-bearing: a reusable token is a persistent
    capability, which is exactly what L1 discards the whole VM to prevent."""
    a = authorizer(d(1))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    first = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                        binary_hash=d(1), token=token)
    second = a.authorize(parent_actor=PARENT, child_actor=CHILD + 1,
                         binary_hash=d(1), token=token)
    assert first.allowed
    assert not second.allowed
    assert second.denial is SpawnDenial.TOKEN_REPLAY


def test_token_cannot_be_transferred_to_another_parent():
    """A stolen token is useless to an actor it was not issued to -- otherwise
    the token proves possession, not identity."""
    a = authorizer(d(1))
    a.register_root(0x999)
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    v = a.authorize(parent_actor=0x999, child_actor=CHILD,
                    binary_hash=d(1), token=token)
    assert not v.allowed
    assert v.denial is SpawnDenial.PARENT_MISMATCH


def test_token_is_bound_to_one_binary_not_just_one_parent():
    """Two binaries both approved: a token issued for the first must not
    launch the second. Binding to the binary is what stops an approved token
    becoming a general-purpose spawn capability."""
    a = authorizer(d(1), d(2))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(2), token=token)
    assert not v.allowed
    assert v.denial is SpawnDenial.BINARY_MISMATCH


def test_spawn_from_an_exited_parent_is_denied():
    """The lineage half of L4, enforced at authorization time rather than
    only detected afterwards by Gate 1's RESPAWN_AFTER_EXIT."""
    a = authorizer(d(1))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    a.note_exit(PARENT)
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=d(1), token=token)
    assert not v.allowed
    assert v.denial is SpawnDenial.DEAD_PARENT


def test_cannot_issue_a_token_to_a_parent_that_is_not_live():
    a = authorizer(d(1))
    a.note_exit(PARENT)
    with pytest.raises(IdentityError):
        a.issue(parent_actor=PARENT, binary_hash=d(1))


def test_authorized_child_becomes_live_and_can_itself_spawn():
    """Lineage actually chains: an authorized child is a legitimate parent for
    the next generation, which is what makes this a tree rather than a
    single-level check."""
    a = authorizer(d(1))
    t1 = a.issue(parent_actor=PARENT, binary_hash=d(1))
    assert a.authorize(parent_actor=PARENT, child_actor=CHILD,
                       binary_hash=d(1), token=t1).allowed
    assert CHILD in a.live_actors

    t2 = a.issue(parent_actor=CHILD, binary_hash=d(1))
    assert a.authorize(parent_actor=CHILD, child_actor=CHILD + 1,
                       binary_hash=d(1), token=t2).allowed


# ---------------------------------------------------------------------------
# Denials are recorded, in a form L9 can consume
# ---------------------------------------------------------------------------

def test_every_denial_is_recorded_with_its_specific_reason():
    a = authorizer(d(1))
    a.authorize(parent_actor=PARENT, child_actor=CHILD, binary_hash=d(9), token=None)
    a.authorize(parent_actor=PARENT, child_actor=CHILD, binary_hash=d(1), token=None)
    a.authorize(parent_actor=PARENT, child_actor=CHILD, binary_hash=d(1), token=b"\x00" * 32)

    assert a.denial_count == 3
    assert len(a.denials_by(SpawnDenial.UNKNOWN_BINARY)) == 1
    assert len(a.denials_by(SpawnDenial.NO_TOKEN)) == 1
    assert len(a.denials_by(SpawnDenial.UNKNOWN_TOKEN)) == 1


def test_a_successful_spawn_is_not_recorded_as_a_denial():
    a = authorizer(d(1))
    token = a.issue(parent_actor=PARENT, binary_hash=d(1))
    a.authorize(parent_actor=PARENT, child_actor=CHILD, binary_hash=d(1), token=token)
    assert a.denial_count == 0


# ---------------------------------------------------------------------------
# Payload extraction: reads the field AMES already recorded but never checked
# ---------------------------------------------------------------------------

def test_binary_hash_is_extracted_from_a_real_canonical_payload():
    """Closes the loop with L8: `payload_process_spawn` has carried a
    `binary_hash` since AMES-V1, and until this module nothing ever compared
    it to anything."""
    payload = payload_process_spawn(d(7), d(8), "/workspace")
    assert binary_hash_from_spawn_payload(payload) == d(7)


def test_short_payload_returns_none_rather_than_raising():
    assert binary_hash_from_spawn_payload(b"\x01\x02") is None
    assert binary_hash_from_spawn_payload(b"") is None


def test_extracted_hash_round_trips_through_the_policy_check():
    policy_digest = d(7)
    a = authorizer(policy_digest)
    payload = payload_process_spawn(policy_digest, d(8), "/workspace")
    extracted = binary_hash_from_spawn_payload(payload)

    token = a.issue(parent_actor=PARENT, binary_hash=extracted)
    v = a.authorize(parent_actor=PARENT, child_actor=CHILD,
                    binary_hash=extracted, token=token)
    assert v.allowed


# ---------------------------------------------------------------------------
# The guarantees statement must not overstate
# ---------------------------------------------------------------------------

def test_guarantees_explicitly_disclaim_kernel_enforcement():
    """The honest-limits discipline the rest of the repo follows: this is
    host-side authorization, and saying so is part of the deliverable."""
    text = " ".join(SpawnAuthorizer.describe_guarantees()).lower()
    assert "not guaranteed" in text
    assert "kernel enforcement" in text or "not kernel" in text
    assert "execve" in text
