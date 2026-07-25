"""AMES -- Agent Mutation Event Schema.

Layer 8 (Cryptographic Action Ledger) of the AI containment framework.
Generalises KAYSentinel's EMES from EVM state transitions to agent actions.
"""
from ames.events import (
    Event, EventType, FileOp, Protocol, Capability, NO_PARENT,
)
from ames.canonical import encode_event, decode_event, encode_stream
from ames.commit import Domain, commit, event_digest, merkle_root, merkle_proof, verify_proof
from ames.ledger import Ledger, Block, BlockHeader, Checkpoint, LedgerError, ChainError, SequenceError
from ames.gate1 import verify as gate1_verify, Gate1Result, Gate1Error, Violation

__version__ = "1.0.0"
__all__ = [
    "Event", "EventType", "FileOp", "Protocol", "Capability", "NO_PARENT",
    "encode_event", "decode_event", "encode_stream",
    "Domain", "commit", "event_digest", "merkle_root", "merkle_proof", "verify_proof",
    "Ledger", "Block", "BlockHeader", "Checkpoint",
    "LedgerError", "ChainError", "SequenceError",
    "gate1_verify", "Gate1Result", "Gate1Error", "Violation",
]
