"""
SKY-VAULT Fingerprint Generator
=================================
Implements the two-layer fingerprint identity model (Section 7)
and Tardos-style collusion-resistant fingerprint codes (Section 7.2).

Layer 1: Long-lived recipient fingerprint code
Layer 2: Fresh per-decryption session nonce

session_id = H(document_id || recipient_code || session_nonce || event_nonce)
"""

import hashlib
import secrets
import math
import numpy as np
from typing import List, Tuple


class TardosCodeGenerator:
    """
    Simplified Tardos-style probabilistic fingerprint code generator.
    
    Reference: Tardos (2003) - Optimal Probabilistic Fingerprint Codes.
    
    The code provides collusion resistance up to 'c' colluding recipients
    with target false-positive probability epsilon.
    
    For MVP: We use a simplified version. Production would require
    the full Tardos construction with bias generation from Beta distribution.
    """

    def __init__(self, num_recipients: int, max_colluders: int = 3, epsilon: float = 1e-6):
        """
        Args:
            num_recipients: Total number of authorized recipients.
            max_colluders: Maximum number of colluding recipients to resist (c).
            epsilon: Target false-positive probability.
        """
        self.num_recipients = num_recipients
        self.max_colluders = max_colluders
        self.epsilon = epsilon
        # Code length: L = O(c^2 * log(n/epsilon)) for Tardos codes
        self.code_length = max(
            128,
            int(100 * max_colluders**2 * math.log(num_recipients / epsilon))
        )
        # Cap at reasonable length for MVP
        self.code_length = min(self.code_length, 4096)
        
        # Generate bias vector p_i ~ Beta(1/2, 1/2) clipped to [t, 1-t]
        # where t = 1/(300*c) per Tardos construction
        self._t = 1.0 / (300 * max_colluders) if max_colluders > 0 else 0.01
        self._bias = self._generate_bias()

    def _generate_bias(self) -> np.ndarray:
        """Generate the secret bias vector from Beta(0.5, 0.5) distribution."""
        rng = np.random.default_rng(secrets.randbits(128))
        bias = rng.beta(0.5, 0.5, size=self.code_length)
        # Clip to [t, 1-t]
        bias = np.clip(bias, self._t, 1.0 - self._t)
        return bias

    def generate_code(self, recipient_index: int) -> np.ndarray:
        """
        Generate a fingerprint codeword for a specific recipient.
        Each bit is independently sampled: P(bit_i = 1) = p_i.
        """
        rng = np.random.default_rng(secrets.randbits(128))
        code = (rng.random(self.code_length) < self._bias).astype(np.uint8)
        return code

    def accuse(self, suspicious_code: np.ndarray, all_codes: dict) -> List[Tuple[str, float]]:
        """
        Given a suspicious (potentially colluded) code, compute accusation
        scores for all recipients.
        
        Returns list of (recipient_id, score) sorted by score descending.
        """
        scores = []
        for recipient_id, code in all_codes.items():
            score = 0.0
            for i in range(self.code_length):
                if suspicious_code[i] == 1:
                    score += math.log((1.0 - self._bias[i]) / self._bias[i]) if code[i] == 1 else 0
                else:
                    score += math.log(self._bias[i] / (1.0 - self._bias[i])) if code[i] == 0 else 0
            scores.append((recipient_id, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    @property
    def params(self) -> dict:
        """Return code parameters for documentation/audit."""
        return {
            "num_recipients": self.num_recipients,
            "max_colluders": self.max_colluders,
            "epsilon": self.epsilon,
            "code_length": self.code_length,
        }


class FingerprintGenerator:
    """
    Two-layer fingerprint identity model (Section 7.1):
    
    Layer 1 - recipient_code: Long-lived, derived from recipient identity
              and distribution context. Optionally uses Tardos codes for
              collusion resistance.
    
    Layer 2 - session_nonce: Fresh per-decryption CSPRNG value.
    
    session_id = H(document_id || recipient_code || session_nonce || event_nonce)
    
    watermark_payload = Encode(recipient_code, session_id, document_version, integrity_binding)
    """

    def __init__(self, num_recipients: int = 10, max_colluders: int = 3):
        self.tardos = TardosCodeGenerator(num_recipients, max_colluders)

    def generate_recipient_code(
        self,
        recipient_id: str,
        distribution_id: str,
        policy_version: str = "1.0",
    ) -> str:
        """
        Long-lived recipient fingerprint component.
        Derived deterministically from recipient identity + distribution context.
        """
        data = f"{recipient_id}|{distribution_id}|{policy_version}".encode("utf-8")
        return hashlib.sha3_256(data).hexdigest()

    def generate_session_fingerprint(
        self, document_id: str, recipient_code: str
    ) -> dict:
        """
        Generates a fresh per-decryption session fingerprint.
        
        Returns:
            dict with session_nonce, event_nonce, session_id, watermark_id
        """
        session_nonce = secrets.token_hex(32)  # 256-bit
        event_nonce = secrets.token_hex(16)    # 128-bit

        # session_id = H(document_id || recipient_code || session_nonce || event_nonce)
        session_input = (
            f"{document_id}||{recipient_code}||{session_nonce}||{event_nonce}"
        ).encode("utf-8")
        session_id = hashlib.sha3_256(session_input).hexdigest()

        watermark_id = f"WM-{session_id[:16]}"

        return {
            "session_nonce": session_nonce,
            "event_nonce": event_nonce,
            "session_id": session_id,
            "watermark_id": watermark_id,
        }

    def build_watermark_payload(
        self,
        recipient_code: str,
        session_id: str,
        document_version: int,
        recipient_index: int = 0,
    ) -> bytes:
        """
        Construct the watermark payload to be embedded:
        
        watermark_payload = Encode(
            recipient_code,
            session_id,
            document_version,
            integrity_binding
        )
        
        Returns payload as bytes (to be ECC-encoded before embedding).
        """
        # Include Tardos code bits for collusion resistance
        tardos_code = self.tardos.generate_code(recipient_index)
        tardos_hex = bytes(tardos_code).hex()[:32]  # First 128 bits

        # Integrity binding: hash of all components
        integrity_data = f"{recipient_code}|{session_id}|{document_version}|{tardos_hex}"
        integrity_binding = hashlib.sha3_256(integrity_data.encode()).hexdigest()[:16]

        payload = {
            "rc": recipient_code[:16],      # Recipient code prefix
            "sid": session_id[:16],          # Session ID prefix
            "dv": document_version,          # Document version
            "tc": tardos_hex[:16],           # Tardos code prefix
            "ib": integrity_binding,         # Integrity binding
        }

        import json
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return payload_bytes


if __name__ == "__main__":
    print("=== Fingerprint Generator Test ===\n")

    fg = FingerprintGenerator(num_recipients=10, max_colluders=3)
    print(f"Tardos code params: {fg.tardos.params}\n")

    # Generate codes for 3 recipients
    for name in ["Alice", "Bob", "Charlie"]:
        rc = fg.generate_recipient_code(f"RID-{name}", "DIST-001")
        session = fg.generate_session_fingerprint("DOC-001", rc)
        payload = fg.build_watermark_payload(rc, session["session_id"], 17)

        print(f"{name}:")
        print(f"  Recipient Code: {rc[:32]}...")
        print(f"  Session ID:     {session['session_id'][:32]}...")
        print(f"  Watermark ID:   {session['watermark_id']}")
        print(f"  Payload size:   {len(payload)} bytes")
        print()
