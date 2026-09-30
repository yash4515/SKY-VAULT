"""
SKY-VAULT : Local Hash-Chain Ledger (MVP)
=========================================
A local, tamper-evident hash-chained ledger that mirrors the data model
of Hyperledger Fabric for the MVP prototype. This can be swapped for
an actual Hyperledger Fabric network in production.

Properties:
  - Each block is hash-chained to the previous block (immutability).
  - Blocks contain signed decryption events.
  - The chain can be independently verified.
  - SQLite storage for persistence (air-gapped, no external DB).

Reference: SKY-VAULT spec Section 10 : Permissioned BFT Distributed Ledger.

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
    """
    SQLite-backed hash-chain ledger for SKY-VAULT MVP.
    
    Mimics the Hyperledger Fabric data model:
    - Blocks are hash-chained.
    - Events are indexed by event_id, watermark_id, and recipient_key_id.
    - Chain integrity can be verified independently.
    """

    def __init__(self, db_path: str = ":memory:"):
        """
        Args:
            db_path: Path to SQLite database file, or ":memory:" for in-memory.
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Initialize the database schema."""
        cursor = self.conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                block_id INTEGER PRIMARY KEY,
                previous_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_data TEXT NOT NULL,
                block_hash TEXT NOT NULL UNIQUE
            );

            CREATE TABLE IF NOT EXISTS event_index (
                event_id TEXT PRIMARY KEY,
                block_id INTEGER NOT NULL,
                watermark_id TEXT,
                recipient_key_id TEXT,
                document_id TEXT,
                session_id TEXT,
                FOREIGN KEY (block_id) REFERENCES blocks(block_id)
            );

            CREATE INDEX IF NOT EXISTS idx_watermark ON event_index(watermark_id);
            CREATE INDEX IF NOT EXISTS idx_recipient ON event_index(recipient_key_id);
            CREATE INDEX IF NOT EXISTS idx_document ON event_index(document_id);
            CREATE INDEX IF NOT EXISTS idx_session ON event_index(session_id);
        """)
        self.conn.commit()

        # Create genesis block if chain is empty
        if self._get_chain_height() == 0:
            self._create_genesis_block()

    def _create_genesis_block(self):
        """Create the genesis block."""
        genesis = Block(
            block_id=0,
            previous_hash=GENESIS_HASH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_data={"type": "genesis", "message": "SKY-VAULT Ledger Initialized"},
        )
        self._store_block(genesis)

    def _get_chain_height(self) -> int:
        """Get the current chain height (number of blocks)."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM blocks")
        return cursor.fetchone()[0]

    def _get_last_block(self) -> Block:
        """Get the last block in the chain."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM blocks ORDER BY block_id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return Block(
            block_id=row["block_id"],
            previous_hash=row["previous_hash"],
            timestamp=row["timestamp"],
            event_data=json.loads(row["event_data"]),
            block_hash=row["block_hash"],
        )

    def _store_block(self, block: Block):
        """Store a block in the database."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO blocks (block_id, previous_hash, timestamp, event_data, block_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                block.block_id,
                block.previous_hash,
                block.timestamp,
                json.dumps(block.event_data, sort_keys=True),
                block.block_hash,
            ),
        )
        self.conn.commit()

    # ─── Public API ──────────────────────────────────────────

    def commit_event(self, event_record: dict) -> dict:
        """
        Commit a signed decryption event to the ledger.

        Args:
            event_record: The full event record (from DecryptionEvent.to_ledger_record())

        Returns:
            Transaction receipt with block_id, block_hash, and commit_time.
        """
        last_block = self._get_last_block()

        new_block = Block(
            block_id=last_block.block_id + 1,
            previous_hash=last_block.block_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_data=event_record,
        )
        self._store_block(new_block)

        # Index the event for fast lookup
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO event_index (event_id, block_id, watermark_id, "
            "recipient_key_id, document_id, session_id) VALUES (?, ?, ?, ?, ?, ?)",
            (
                event_record.get("event_id", ""),
                new_block.block_id,
                event_record.get("watermark_id", ""),
                event_record.get("recipient_key_id", ""),
                event_record.get("document_id", ""),
                event_record.get("session_id", ""),
            ),
        )
        self.conn.commit()

        return {
            "status": "COMMITTED",
            "block_id": new_block.block_id,
            "block_hash": new_block.block_hash,
            "commit_time": new_block.timestamp,
            "transaction_id": f"TX-{new_block.block_hash[:16]}",
        }

    def lookup_by_watermark(self, watermark_id: str) -> Optional[dict]:
        """Look up a decryption event by watermark ID (forensic query)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT b.* FROM blocks b JOIN event_index e ON b.block_id = e.block_id "
            "WHERE e.watermark_id = ?",
            (watermark_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "block_id": row["block_id"],
            "block_hash": row["block_hash"],
            "commit_time": row["timestamp"],
            "event_data": json.loads(row["event_data"]),
        }

    def lookup_by_event_id(self, event_id: str) -> Optional[dict]:
        """Look up a decryption event by event ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT b.* FROM blocks b JOIN event_index e ON b.block_id = e.block_id "
            "WHERE e.event_id = ?",
            (event_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "block_id": row["block_id"],
            "block_hash": row["block_hash"],
            "commit_time": row["timestamp"],
            "event_data": json.loads(row["event_data"]),
        }

    def lookup_by_recipient(self, recipient_key_id: str) -> List[dict]:
        """List all decryption events for a recipient."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT b.* FROM blocks b JOIN event_index e ON b.block_id = e.block_id "
            "WHERE e.recipient_key_id = ? ORDER BY b.block_id",
            (recipient_key_id,),
        )
        results = []
        for row in cursor.fetchall():
            results.append({
                "block_id": row["block_id"],
                "block_hash": row["block_hash"],
                "commit_time": row["timestamp"],
                "event_data": json.loads(row["event_data"]),
            })
        return results

    def lookup_by_session(self, session_id: str) -> Optional[dict]:
        """Look up by session ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT b.* FROM blocks b JOIN event_index e ON b.block_id = e.block_id "
            "WHERE e.session_id = ?",
            (session_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "block_id": row["block_id"],
            "block_hash": row["block_hash"],
            "commit_time": row["timestamp"],
            "event_data": json.loads(row["event_data"]),
        }

    def verify_chain_integrity(self) -> dict:
        """
        Verify the entire chain's integrity by recomputing all hashes.

        Returns:
            dict with 'valid' (bool), 'height', and 'errors' (list).
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM blocks ORDER BY block_id ASC")
        rows = cursor.fetchall()

        errors = []
        prev_hash = GENESIS_HASH

        for row in rows:
            block = Block(
                block_id=row["block_id"],
                previous_hash=row["previous_hash"],
                timestamp=row["timestamp"],
                event_data=json.loads(row["event_data"]),
            )
            computed_hash = block.compute_hash()

            # Check hash integrity
            if row["block_hash"] != computed_hash:
                errors.append(
                    f"Block {row['block_id']}: stored hash does not match computed hash"
                )

            # Check chain linkage (skip genesis)
            if row["block_id"] > 0 and row["previous_hash"] != prev_hash:
                errors.append(
                    f"Block {row['block_id']}: previous_hash does not link to prior block"
                )

            prev_hash = row["block_hash"]

        return {
            "valid": len(errors) == 0,
            "height": len(rows),
            "errors": errors,
        }

    def get_block_proof(self, block_id: int) -> Optional[dict]:
        """
        Get the block proof for a specific block (for evidence package).
        Includes the block itself and adjacent blocks for verification.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM blocks WHERE block_id BETWEEN ? AND ? ORDER BY block_id",
            (max(0, block_id - 1), block_id + 1),
        )
        blocks = []
        for row in cursor.fetchall():
            blocks.append({
                "block_id": row["block_id"],
                "previous_hash": row["previous_hash"],
                "timestamp": row["timestamp"],
                "block_hash": row["block_hash"],
            })
        return {
            "target_block_id": block_id,
            "proof_blocks": blocks,
        }

    def get_chain_summary(self) -> dict:
        """Get a summary of the chain state."""
        integrity = self.verify_chain_integrity()
        return {
            "chain_height": integrity["height"],
            "chain_valid": integrity["valid"],
            "db_path": self.db_path,
        }

    def close(self):
        """Close the database connection."""
        self.conn.close()


if __name__ == "__main__":
    print("=== Local Ledger Test ===\n")

    ledger = LocalLedger(":memory:")
    print(f"Chain initialized: {ledger.get_chain_summary()}\n")

    # Commit some test events
    for i, name in enumerate(["Alice", "Bob", "Charlie"]):
        event = {
            "event_id": f"EVT-{i:04d}",
            "document_id": "DOC-001",
            "document_version": 17,
            "recipient_key_id": f"RID-{name.lower()}",
            "watermark_id": f"WM-{name.lower()[:3]}",
            "session_id": f"SES-{name.lower()}-001",
            "signature": f"sig-{name.lower()}-placeholder",
        }
        receipt = ledger.commit_event(event)
        print(f"  {name}: Block #{receipt['block_id']} → {receipt['transaction_id']}")

    # Verify chain
    print(f"\nChain integrity: {ledger.verify_chain_integrity()}\n")

    # Forensic lookup
    result = ledger.lookup_by_watermark("WM-bob")
    print(f"Lookup WM-bob → Block #{result['block_id']}")
    print(f"  Recipient: {result['event_data']['recipient_key_id']}")
    print(f"  Event ID:  {result['event_data']['event_id']}")

    # Block proof
    proof = ledger.get_block_proof(result["block_id"])
    print(f"\nBlock proof for block #{result['block_id']}:")
    for b in proof["proof_blocks"]:
        print(f"  Block #{b['block_id']}: {b['block_hash'][:32]}...")

    print("\n[PASS] Ledger test complete!")
    ledger.close()
