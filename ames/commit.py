"""
AMES-V1 cryptographic commitments.

Follows KAYSentinel's established rule exactly:

    Digest := BLAKE3(DomainBytes || CanonicalBytes)

unkeyed BLAKE3, no derive_key mode, no XOF, no framing bytes between the domain
tag and the payload. Domain tags are permanently immutable once published --
new domains may be appended, but nothing may be renamed, reinterpreted or
recycled. Reusing a tag across contexts is how cross-protocol confusion attacks
begin: a value legitimately signed in one context becomes forgeable evidence in
another.

The merkle tree is deliberately domain-separated leaf-vs-branch. Without that
separation an attacker can present an internal node as if it were a leaf --
the classic second-preimage attack on naive Merkle constructions.
"""

from __future__ import annotations

import enum
from typing import List, Sequence

try:
    from blake3 import blake3
except ImportError:  # pragma: no cover
    raise ImportError("AMES requires the 'blake3' package: pip install blake3")

DIGEST_SIZE = 32
ZERO_DIGEST = b"\x00" * DIGEST_SIZE


class Domain(bytes, enum.Enum):
    """Hash domain registry, AMES version 1."""

    EVENT       = b"AMES_V1_EVENT"
    MERKLE_LEAF = b"AMES_V1_MERKLE_LEAF"
    MERKLE_NODE = b"AMES_V1_MERKLE_NODE"
    BLOCK       = b"AMES_V1_BLOCK"
    CHECKPOINT  = b"AMES_V1_CHECKPOINT"


def commit(domain: Domain, canonical_bytes: bytes) -> bytes:
    """The one and only commitment primitive. Total; never fails on valid bytes."""
    if not isinstance(domain, Domain):
        raise TypeError("domain must be a Domain member")
    h = blake3()
    h.update(domain.value)
    h.update(canonical_bytes)
    return h.digest()


def event_digest(canonical_event_bytes: bytes) -> bytes:
    return commit(Domain.EVENT, canonical_event_bytes)


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Binary merkle root over pre-hashed leaves.

    - Empty tree -> ZERO_DIGEST (distinct from any real leaf, since a real leaf
      is a BLAKE3 output over a non-empty domain tag).
    - Odd levels promote the final node unchanged rather than duplicating it.
      Duplicating the last node is the CVE-2012-2459 bug class: two distinct
      trees collapse to the same root, so an attacker can forge an inclusion
      proof for an event that was never logged.
    """
    if not leaves:
        return ZERO_DIGEST
    for i, leaf in enumerate(leaves):
        if not isinstance(leaf, (bytes, bytearray)) or len(leaf) != DIGEST_SIZE:
            raise ValueError(f"leaf {i} is not a {DIGEST_SIZE}-byte digest")

    level: List[bytes] = [commit(Domain.MERKLE_LEAF, bytes(l)) for l in leaves]

    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(commit(Domain.MERKLE_NODE, level[i] + level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])          # promote, never duplicate
        level = nxt
    return level[0]


def merkle_proof(leaves: Sequence[bytes], index: int) -> List[tuple]:
    """Inclusion proof for leaves[index] as a list of (sibling, is_right) pairs.

    Lets an auditor prove one action was recorded without disclosing the whole
    log -- useful when the log itself is sensitive.

    Index tracking mirrors merkle_root exactly. At a level of L nodes, the first
    2*(L//2) nodes pair up and each pair collapses to index i//2; when L is odd
    the final node is promoted unchanged to index L//2 with no sibling.
    """
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")

    level = [commit(Domain.MERKLE_LEAF, bytes(l)) for l in leaves]
    idx = index
    proof: List[tuple] = []

    while len(level) > 1:
        L = len(level)
        paired = 2 * (L // 2)          # nodes participating in a pair

        if idx < paired:
            if idx % 2 == 0:
                proof.append((level[idx + 1], True))   # sibling on the right
            else:
                proof.append((level[idx - 1], False))  # sibling on the left
            idx = idx // 2
        else:
            idx = L // 2               # promoted unchanged; contributes no sibling

        nxt = [commit(Domain.MERKLE_NODE, level[i] + level[i + 1])
               for i in range(0, paired, 2)]
        if L % 2 == 1:
            nxt.append(level[-1])
        level = nxt

    return proof


def verify_proof(leaf: bytes, proof: Sequence[tuple], root: bytes) -> bool:
    """Recompute a root from a leaf and its proof."""
    node = commit(Domain.MERKLE_LEAF, bytes(leaf))
    for sibling, sibling_is_right in proof:
        node = (commit(Domain.MERKLE_NODE, node + sibling) if sibling_is_right
                else commit(Domain.MERKLE_NODE, sibling + node))
    return node == root
