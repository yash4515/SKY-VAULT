"""
TraceVault — Local Hash-Chain Ledger (MVP)
==========================================
A local, tamper-evident hash-chained ledger that mirrors the data model
of Hyperledger Fabric for the MVP prototype. This can be swapped for
an actual Hyperledger Fabric network in production.

Properties:
  - Each block is hash-chained to the previous block (immutability).
  - Blocks contain signed decryption events.
  - The chain can be independently verified.
  - SQLite storage for persistence (air-gapped, no external DB).

Reference: TraceVault spec Section 10 — Permissioned BFT Distributed Ledger.

Production upgrade path: Replace this module with fabric_gateway.py
that connects to a real Hyperledger Fabric network with SmartBFT ordering.
"""

import json
import hashlib
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, List


# Genesis block hash
GENESIS_HASH = "0" * 64


class Block:
    """Represents a single block in the hash chain."""

    def __init__(
        self,
        block_id: int,
        previous_hash: str,
        timestamp: str,
        event_data: dict,
        block_hash: str = "",
    ):
        self.block_id = block_id
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.event_data = event_data
        self.block_hash = block_hash or self.compute_hash()

    def compute_hash(self) -> str:
        """Compute SHA3-256 hash of the block contents."""
        block_content = json.dumps(
            {
                "block_id": self.block_id,
                "previous_hash": self.previous_hash,
                "timestamp": self.timestamp,
                "event_data": self.event_data,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha3_256(block_content).hexdigest()

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "event_data": self.event_data,
            "block_hash": self.block_hash,
        }


class LocalLedger:
