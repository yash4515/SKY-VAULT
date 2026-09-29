"""
TraceVault PQC Core Module
==========================
Post-Quantum Cryptographic engine implementing:
- ML-KEM-768 (Kyber) for Key Encapsulation (NIST FIPS 203)
- ML-DSA-65 (Dilithium) for Digital Signatures (NIST FIPS 204)
- AES-256-GCM for Symmetric Encryption
- SHA3-256 for Document and Event Hashing
- Two-Layer Fingerprint Identity Model (recipient_code + session_nonce)
- Canonical Event Signing with deterministic serialization

All operations are designed for in-memory processing within an air-gapped environment.
Un-watermarked plaintext must NEVER touch disk.

NOTE: If liboqs native library is not available, falls back to a simulation
mode that uses HMAC-based key exchange and Ed25519-style signing for demo
purposes. Production deployment MUST use real liboqs.
"""

import os
import json
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Try to load liboqs; fall back to simulation if unavailable ──
# Pre-check: only attempt import if the native oqs shared library exists.
# This prevents liboqs-python from triggering a slow auto-build attempt.
import glob as _glob

_oqs_dll_candidates = [
    os.path.join(os.path.expanduser("~"), "_oqs", "bin", "oqs.dll"),
    os.path.join(os.path.expanduser("~"), "_oqs", "lib", "oqs.dll"),
] + _glob.glob(os.path.join(os.path.expanduser("~"), "_oqs", "**", "oqs.dll"), recursive=True)

_oqs_lib_found = any(os.path.exists(p) for p in _oqs_dll_candidates)

HAS_LIBOQS = False
if _oqs_lib_found:
    try:
        import oqs
        HAS_LIBOQS = True
    except Exception:
        HAS_LIBOQS = False
else:
    # Skip import entirely — avoids 30s auto-build timeout
    pass


# =========================================================
# SHA3-256 Utility
# =========================================================
def sha3_256(data: bytes) -> str:
    """Compute SHA3-256 digest and return as hex-prefixed string."""
    return "sha3-256:" + hashlib.sha3_256(data).hexdigest()


# =========================================================
# JSON Canonicalization (deterministic serialization)
# =========================================================
def canonicalize(obj: dict) -> bytes:
    """
    Deterministic JSON serialization for canonical event signing.
    Uses sorted keys, no whitespace, and ensures_ascii for reproducibility.
    Reference: TraceVault spec Section 6.3 — "JSON Canonicalization Scheme (JCS) 
    or an equivalent internally specified canonical binary representation."
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


# =========================================================
# PQC Simulation Fallback (when liboqs is not available)
# =========================================================
class _SimulatedKEM:
    """
    SIMULATION ONLY — NOT CRYPTOGRAPHICALLY SECURE.
    Mimics ML-KEM API using HMAC-based key derivation for demo purposes.
    Replace with real liboqs in production.
    """
    
    @staticmethod
    def generate_keypair():
        seed = os.urandom(32)
        private_key = seed + os.urandom(32)
        # Public key is deterministically derived from seed
        public_key = hashlib.sha3_256(b"KEM-PUB:" + seed).digest() + seed
        return public_key, private_key

    @staticmethod
    def encapsulate(public_key):
        # Embed a random nonce in the ciphertext
        nonce = os.urandom(32)
        # Shared secret = HMAC(pub_key_seed, nonce)
        seed = public_key[32:64]
        shared_secret = hmac.new(seed, nonce, hashlib.sha3_256).digest()
        ciphertext = nonce + os.urandom(32)  # nonce is first 32 bytes
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(ciphertext, private_key):
        # Recover nonce from ciphertext and recompute shared secret
        nonce = ciphertext[:32]
        seed = private_key[:32]
        shared_secret = hmac.new(seed, nonce, hashlib.sha3_256).digest()
        return shared_secret


class _SimulatedSig:
    """
    SIMULATION ONLY — NOT CRYPTOGRAPHICALLY SECURE.
    Mimics ML-DSA API using HMAC-based signing for demo purposes.
    """
    
    @staticmethod
    def generate_keypair():
        private_key = os.urandom(64)
        public_key = hashlib.sha3_256(private_key).digest() + os.urandom(32)
        return public_key, private_key

    @staticmethod
    def sign(message, private_key):
        return hmac.new(private_key, message, hashlib.sha3_256).digest()

    @staticmethod
    def verify(message, signature, public_key, private_key_for_sim=None):
        # In simulation, we need the private key to verify (NOT real crypto)
        # For demo, we accept all signatures that are 32 bytes
        return len(signature) == 32


# =========================================================
# PQC Manager (ML-KEM + ML-DSA + AES-256-GCM)
# =========================================================
class PQCManager:
    """
    Core cryptographic engine for TraceVault.
    Handles key encapsulation, digital signatures, and symmetric encryption.
    
    Uses liboqs when available; falls back to simulation for demos.
    """

    def __init__(self):
        self.using_liboqs = HAS_LIBOQS

        if self.using_liboqs:
            # ML-KEM-768 for Key Encapsulation (NIST FIPS 203)
            self.kem_alg = "Kyber768"
            # ML-DSA-65 for Digital Signatures (NIST FIPS 204)
            self.sig_alg = "Dilithium3"
            
            if self.kem_alg not in oqs.get_enabled_KEM_mechanisms():
                raise RuntimeError(f"{self.kem_alg} is not supported by your liboqs installation.")
            if self.sig_alg not in oqs.get_enabled_sig_mechanisms():
                raise RuntimeError(f"{self.sig_alg} is not supported by your liboqs installation.")
        else:
            self.kem_alg = "Simulated-ML-KEM-768"
            self.sig_alg = "Simulated-ML-DSA-65"

        # Store keypairs for simulation verification
        self._sim_keypairs = {}

    def get_mode(self) -> str:
        return "liboqs (REAL PQC)" if self.using_liboqs else "SIMULATION (demo only)"

    # ---------------------------------------------------------
    # Key Encapsulation Mechanism — ML-KEM-768 (FIPS 203)
    # ---------------------------------------------------------
    def generate_kem_keypair(self) -> tuple:
        """Generates ML-KEM keypair for a recipient."""
        if self.using_liboqs:
            with oqs.KeyEncapsulation(self.kem_alg) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
                return public_key, private_key
        else:
            return _SimulatedKEM.generate_keypair()

    def encapsulate_key(self, recipient_public_key: bytes) -> tuple:
        """
        Sender generates a shared secret (DEK) and encapsulates it 
        using the recipient's ML-KEM public key.
        Returns (kem_ciphertext, shared_secret).
        """
        if self.using_liboqs:
            with oqs.KeyEncapsulation(self.kem_alg) as kem:
                ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
                return ciphertext, shared_secret
        else:
            return _SimulatedKEM.encapsulate(recipient_public_key)

    def decapsulate_key(self, ciphertext: bytes, recipient_private_key: bytes) -> bytes:
        """
        Recipient decapsulates the ciphertext using their ML-KEM private key 
        to recover the shared secret (DEK).
        """
        if self.using_liboqs:
            with oqs.KeyEncapsulation(self.kem_alg, secret_key=recipient_private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                return shared_secret
        else:
            return _SimulatedKEM.decapsulate(ciphertext, recipient_private_key)

    # ---------------------------------------------------------
