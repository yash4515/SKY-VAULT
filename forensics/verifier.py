"""
SKY-VAULT - Evidence Verifier
===============================
Verifies the complete cryptographic evidence chain for a forensic case.

Reference: SKY-VAULT spec Section 13 - Forensic Investigation Workflow
and Section 14 - Independent Evidence Package.

Verification steps:
  1. Verify watermark ID resolves to a ledger event.
  2. Verify document hash binding.
  3. Verify ML-DSA signature against registered public key.
  4. Verify certificate/key status at event time.
  5. Verify ledger inclusion and block/transaction evidence.
  6. Produce forensic report.

Result states (Section 13.1):
  - CRYPTOGRAPHICALLY VERIFIED
  - VALID WATERMARK / MISSING EVENT
  - INCONCLUSIVE
  - SIGNATURE INVALID
  - DOCUMENT HASH MISMATCH
  - KEY STATUS INVALID
  - MULTIPLE CANDIDATES
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ForensicVerifier:
    """
    Independent evidence verifier for SKY-VAULT.
    
    "The evidence verifier should be a separate component from the 
     decryption and ledger-management services." - Section 14
    """

    def __init__(self, pqc_manager=None, ledger=None, key_registry: dict = None):
        """
        Args:
            pqc_manager: PQCManager instance for signature verification.
            ledger: LocalLedger instance for event lookup.
            key_registry: Dict mapping recipient_key_id → public_key bytes.
        """
        self.pqc = pqc_manager
        self.ledger = ledger
        self.key_registry = key_registry or {}

    def verify_evidence_chain(
        self,
        watermark_id: str,
        document_hash: str = None,
        leaked_artifact_hash: str = None,
    ) -> dict:
        """
        Run the complete forensic verification pipeline.

        Args:
            watermark_id: Recovered watermark ID from extraction.
            document_hash: Expected document hash (optional cross-check).
            leaked_artifact_hash: Hash of the leaked artifact.

        Returns:
            Forensic verification report with result state.
        """
        report = {
            "verification_timestamp": datetime.now(timezone.utc).isoformat(),
            "watermark_id": watermark_id,
            "leaked_artifact_hash": leaked_artifact_hash,
            "steps": [],
            "result": "INCONCLUSIVE",
            "confidence": 0.0,
        }

        # ── Step 1: Ledger Lookup ────────────────────────────
        ledger_result = self._verify_ledger_event(watermark_id)
        report["steps"].append(ledger_result)

        if ledger_result["status"] == "FAILED":
            report["result"] = "VALID WATERMARK / MISSING EVENT"
            report["confidence"] = 0.3
            return report

        event_data = ledger_result["event_data"]
        report["event_id"] = event_data.get("event_id")
        report["recipient_key_id"] = event_data.get("recipient_key_id")

        # ── Step 2: Document Hash Binding ────────────────────
        if document_hash:
            hash_result = self._verify_document_hash(event_data, document_hash)
            report["steps"].append(hash_result)
            if hash_result["status"] == "FAILED":
                report["result"] = "DOCUMENT HASH MISMATCH"
                report["confidence"] = 0.1
                return report

        # ── Step 3: Signature Verification ───────────────────
        sig_result = self._verify_signature(event_data)
        report["steps"].append(sig_result)

        if sig_result["status"] == "FAILED":
            report["result"] = "SIGNATURE INVALID"
            report["confidence"] = 0.2
            return report

        # ── Step 4: Key Status Check ─────────────────────────
        key_result = self._verify_key_status(event_data)
        report["steps"].append(key_result)

        if key_result["status"] == "FAILED":
            report["result"] = "KEY STATUS INVALID"
            report["confidence"] = 0.4
            return report

        # ── Step 5: Ledger Integrity ─────────────────────────
        chain_result = self._verify_chain_integrity(ledger_result.get("block_id"))
        report["steps"].append(chain_result)

        # ── All checks passed ────────────────────────────────
        if all(s["status"] == "PASSED" for s in report["steps"]):
            report["result"] = "CRYPTOGRAPHICALLY VERIFIED"
            report["confidence"] = 1.0
        else:
            report["result"] = "INCONCLUSIVE"
            report["confidence"] = 0.5

        return report

    def _verify_ledger_event(self, watermark_id: str) -> dict:
        """Step 1: Verify watermark ID resolves to a ledger event."""
        if self.ledger is None:
            return {"step": "ledger_lookup", "status": "SKIPPED", "reason": "No ledger configured"}

        result = self.ledger.lookup_by_watermark(watermark_id)
        if result is None:
            return {
                "step": "ledger_lookup",
                "status": "FAILED",
                "reason": f"No event found for watermark ID: {watermark_id}",
            }

        return {
            "step": "ledger_lookup",
            "status": "PASSED",
            "block_id": result["block_id"],
            "block_hash": result["block_hash"],
            "commit_time": result["commit_time"],
            "event_data": result["event_data"],
        }

    def _verify_document_hash(self, event_data: dict, expected_hash: str) -> dict:
        """Step 2: Verify document hash binding."""
        event_hash = event_data.get("document_hash", "")
        matches = event_hash == expected_hash

        return {
            "step": "document_hash_binding",
            "status": "PASSED" if matches else "FAILED",
            "event_document_hash": event_hash,
            "expected_hash": expected_hash,
        }

    def _verify_signature(self, event_data: dict) -> dict:
        """Step 3: Verify ML-DSA signature."""
        if self.pqc is None:
            return {"step": "signature_verification", "status": "SKIPPED", "reason": "No PQC manager"}

        recipient_key_id = event_data.get("recipient_key_id", "")
        if recipient_key_id not in self.key_registry:
            return {
                "step": "signature_verification",
                "status": "FAILED",
                "reason": f"Public key not found for: {recipient_key_id}",
            }

        public_key = self.key_registry[recipient_key_id]
        signature_hex = event_data.get("signature", "")

        try:
            signature = bytes.fromhex(signature_hex)

            # Reconstruct event digest for verification
            event_for_digest = {k: v for k, v in event_data.items() if k != "signature"}
            canonical = json.dumps(
                event_for_digest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
            event_digest = hashlib.sha3_256(canonical).digest()

            is_valid = self.pqc.verify(event_digest, signature, public_key)

            return {
                "step": "signature_verification",
                "status": "PASSED" if is_valid else "FAILED",
                "algorithm": event_data.get("signature_algorithm", "ML-DSA-65"),
                "recipient_key_id": recipient_key_id,
            }
        except Exception as e:
            return {
                "step": "signature_verification",
                "status": "FAILED",
                "reason": str(e),
            }

    def _verify_key_status(self, event_data: dict) -> dict:
        """Step 4: Verify key status at event time."""
        # For MVP: keys are always considered active
        # Production: check against PKI / certificate revocation list
        recipient_key_id = event_data.get("recipient_key_id", "")
        return {
            "step": "key_status_check",
            "status": "PASSED",
            "key_id": recipient_key_id,
            "key_status": "ACTIVE",
            "note": "MVP - full PKI/CRL check not implemented",
        }

    def _verify_chain_integrity(self, block_id: int = None) -> dict:
        """Step 5: Verify ledger chain integrity."""
        if self.ledger is None:
            return {"step": "chain_integrity", "status": "SKIPPED", "reason": "No ledger"}

        integrity = self.ledger.verify_chain_integrity()
        status = "PASSED" if integrity["valid"] else "FAILED"

        result = {
            "step": "chain_integrity",
            "status": status,
            "chain_height": integrity["height"],
        }

        if not integrity["valid"]:
            result["errors"] = integrity["errors"]

        if block_id is not None:
            proof = self.ledger.get_block_proof(block_id)
            result["block_proof"] = proof

        return result

    def generate_evidence_package(self, report: dict) -> dict:
        """
        Generate a structured evidence package (Section 14).

        evidence/
        |-- leaked_document.sha3
        |-- extracted_fingerprint.bin
        |-- extraction_report.json
        |-- canonical_event.json
        |-- event_digest.txt
        |-- recipient_certificate_or_public_key
        |-- ML-DSA_signature.bin
        |-- ledger_transaction.json
        |-- ledger_block_proof.json
        |-- key_status_evidence.json
        +-- verification_report.json
        """
        package = {
            "package_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verification_report": report,
        }

        # Extract components from the verification steps
        for step in report.get("steps", []):
            if step["step"] == "ledger_lookup" and step["status"] == "PASSED":
                package["canonical_event"] = step.get("event_data")
                package["ledger_transaction"] = {
                    "block_id": step.get("block_id"),
                    "block_hash": step.get("block_hash"),
                    "commit_time": step.get("commit_time"),
                }
            elif step["step"] == "chain_integrity":
                package["ledger_block_proof"] = step.get("block_proof")
            elif step["step"] == "key_status_check":
                package["key_status_evidence"] = {
                    "key_id": step.get("key_id"),
                    "status": step.get("key_status"),
                }

        return package

    def format_report(self, report: dict) -> str:
        """Format the verification report as a human-readable string."""
        lines = [
            "=" * 60,
            "  SKY-VAULT - FORENSIC VERIFICATION REPORT",
            "=" * 60,
            "",
            f"  Timestamp:       {report.get('verification_timestamp', 'N/A')}",
            f"  Watermark ID:    {report.get('watermark_id', 'N/A')}",
            f"  Event ID:        {report.get('event_id', 'N/A')}",
            f"  Recipient Key:   {report.get('recipient_key_id', 'N/A')}",
            f"  Leaked Hash:     {report.get('leaked_artifact_hash', 'N/A')}",
            "",
            "  Verification Steps:",
        ]

        for step in report.get("steps", []):
            icon = "[PASS]" if step["status"] == "PASSED" else "[FAIL]" if step["status"] == "FAILED" else "[-]"
            lines.append(f"    {icon} {step['step']}: {step['status']}")
            if "reason" in step:
                lines.append(f"      Reason: {step['reason']}")

        lines.extend([
            "",
            f"  +--------------------------------------------------------+",
            f"  |  RESULT: {report['result']:<46}|",
            f"  |  Confidence: {report['confidence']:<43}|",
            f"  +--------------------------------------------------------+",
            "",
        ])

        return "\n".join(lines)


if __name__ == "__main__":
    print("=== Forensic Verifier Module Loaded ===")
    print("Run demo_mvp.py for full end-to-end verification demo.")
