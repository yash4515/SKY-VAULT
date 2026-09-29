# TRACEVAULT (SKY-VAULT)

## Air-Gapped Post-Quantum Forensic Fingerprinting and Immutable Attribution for Secure Document Distribution

> **Smart India Hackathon (SIH) Project**
> Version 1.0 • September 2026

| Property | Description |
|---|---|
| **Primary Problem** | Trace an individual authorized decryption event from a leaked document |
| **Environment** | 100% Offline and fully air-gapped |
| **Core Technologies** | Robust forensic watermarking, collusion-resistant fingerprinting, ML-KEM, ML-DSA, permissioned BFT DLT |
| **Primary Assurance Goal** | Cryptographically verifiable attribution of a leaked copy to an authenticated decryption event |

> **Important Scope Statement:** The system establishes a cryptographically verifiable relationship between a leaked copy and an authenticated decryption event. It does *not* claim that a human being physically leaked the file — only that the corresponding recipient-controlled credential authenticated the decryption event.

---

## 1. The Core Problem ("Decryption Attribution Void")

In a multi-recipient broadcast encryption model, a file is encrypted once and shared with many. When an authorized user decrypts it, they get an identical copy of the plaintext. If one of them leaks it, we cannot mathematically prove who leaked it because the decrypted files are identical. Server-side logs are insufficient as they can be tampered with by rogue admins. Static watermarks applied before distribution also fail because they are identical for all users.

## 2. Our Solution

TraceVault is a cryptographically linked evidence system. It ensures that plaintext is released **only after** a recipient-specific fingerprint has been generated, embedded, cryptographically bound to a signed decryption event, and committed to an immutable audit layer.

### Core Design Principle
```
ENCRYPTED DOCUMENT
       ↓
Authorized identity + policy decision
       ↓
Trusted decryption boundary
       ↓
Session-specific fingerprint
       ↓
Robust / redundant / error-corrected watermark
       ↓
Watermarked document hash
       ↓
Recipient ML-DSA signature over canonical event
       ↓
Permissioned BFT ledger commit
       ↓
Recipient receives ONLY the fingerprinted document
```

### Forensic Flow
```
LEAKED DOCUMENT
       ↓
Watermark extraction + error correction
       ↓
Fingerprint / event lookup
       ↓
Document hash + signature + key status + ledger proof verification
       ↓
Cryptographically verifiable forensic report
```

## 3. Strict Technical Constraints

- **100% Air-Gapped/Offline:** No external cloud KMS, no public blockchains, and no SaaS APIs.
- **Post-Quantum Cryptography (PQC):** NIST-standardized lattice-based cryptography replacing classical RSA/ECC.
- **In-Memory Processing:** Decryption and watermarking happen strictly in RAM; un-watermarked plaintext must never touch the disk.
- **No Public Blockchain:** Private permissioned ledger only.
- **No Cloud KMS:** Hardware-backed on-premise key custody.

## 4. Technology Stack

| Purpose | Primitive | Role |
|---|---|---|
| Key Establishment | **ML-KEM-768** (Kyber) via `liboqs` | Encapsulate/decapsulate document key material |
| Digital Signature | **ML-DSA-65** (Dilithium) via `liboqs` | Authenticate decryption events |
| Optional Signature Diversity | **SLH-DSA** | Hash-based PQ alternative |
| Hashing | **SHA3-256 / SHAKE** | Event, document and evidence digests |
| Bulk Document Encryption | **AES-256-GCM** | Efficient authenticated encryption |
| Immutable Ledger | **Hyperledger Fabric** (BFT / SmartBFT) | Permissioned tamper-evident audit history |
| Fingerprinting | **Tardos-style codes** + session nonce | Collusion-resistant recipient/session tracing |
| Watermarking | **DWT/DCT** + ECC + redundancy | Robust invisible forensic embedding |
| Core Languages | **Python**, **Rust/Go** | Depending on module |

## 5. System Architecture

```
AIR-GAPPED CORPORATE NETWORK
┌──────────────────┐
│  Offline Root CA  │
└────────┬─────────┘
         ├────────────── Identity / PKI
         │
         ▼
┌──────────────────┐    ┌─────────────────────┐
│  Authorization   │───▶│  Trusted Decryption  │
│  + Policy Engine │    │  / Rendering Zone    │
└──────────────────┘    └──────────┬──────────┘
                                   │
                                   ▼
                       ┌────────────────────┐
                       │    Fingerprint      │
                       │    Generator        │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │  Watermark Engine   │
                       │  + ECC + redundancy │
                       └─────────┬──────────┘
                                 │
                        ┌────────┴────────┐
                        │                 │
                        ▼                 ▼
                 Watermarked hash    Event record
                                         │
                                         ▼
                                  Recipient ML-DSA
                                    signature
                                         │
                                         ▼
                       ┌────────────────────────┐
                       │  Permissioned BFT DLT  │
                       │   Org A / B / C / D    │
                       └───────────┬────────────┘
                                   │
                                   ▼
                            Immutable evidence
```

## 6. Canonical Decryption Event Structure

```json
{
  "schema_version": "1.0",
  "event_id": "...",
  "document_id": "...",
  "document_version": 17,
  "document_hash": "sha3-256:...",
  "recipient_key_id": "RID-...",
  "session_id": "...",
  "session_nonce": "...",
  "event_timestamp": "...",
  "watermark_id": "WM-...",
  "watermark_profile": "digital|screen|print-secure|high-security",
  "output_hash": "sha3-256:..."
}
```
```
event_digest = SHA3-256(canonicalize(event))
signature   = ML-DSA.Sign(recipient_private_key, event_digest)
```

## 7. Two-Layer Fingerprint Identity Model

```python
recipient_code = F(recipient, distribution_population, fingerprint_policy)
session_nonce  = CSPRNG()
session_id     = H(document_id || recipient_code || session_nonce || event_nonce)
watermark_payload = Encode(
    recipient_code,
    session_id,
    document_version,
    integrity_binding
)
```

## 8. Secure Decryption Workflow

1. Authenticate the recipient using organizational identity and device policy.
2. Authorize access to the specific document version.
3. Recover the document key through ML-KEM within the trusted decryption service.
4. Decrypt the document inside the trusted boundary.
5. Generate a fresh cryptographically secure session nonce.
6. Generate recipient/session-specific fingerprint payload.
7. Embed the payload into the document using the configured watermark profile.
8. Compute the final watermarked-document hash (SHA3-256).
9. Create the canonical decryption event.
10. Request the recipient's hardware-protected signing key to sign the event digest.
11. Submit the signed event to the permissioned BFT ledger.
12. Wait for ledger-commit confirmation.
13. Release **only** the fingerprinted document to the recipient.

> **Critical control:** The un-watermarked plaintext must NEVER be released to the recipient before the fingerprinting step.

## 9. Forensic Investigation Result States

| Result | Meaning |
|---|---|
| `CRYPTOGRAPHICALLY VERIFIED` | Watermark, document binding, signature, key status and ledger evidence all validate |
| `VALID WATERMARK / MISSING EVENT` | A fingerprint is recoverable but no matching ledger evidence is available |
| `INCONCLUSIVE` | Watermark recovery is too weak or ambiguous |
| `SIGNATURE INVALID` | The event cannot be authenticated with the registered public key |
| `DOCUMENT HASH MISMATCH` | Recovered event does not bind to the submitted artifact/version |
| `KEY STATUS INVALID` | The credential was not valid under the organization's event-time policy |
| `MULTIPLE CANDIDATES` | Evidence requires further analysis; do not force attribution |

## 10. Recommended MVP (SIH Prototype)

1. Register Alice, Bob and Charlie.
2. Generate ML-DSA keys for each.
3. Encrypt one PDF using a random DEK.
4. Wrap the DEK for each recipient using ML-KEM.
5. Recipient requests decryption.
6. Generate a fresh session fingerprint.
7. Embed fingerprint into rendered PDF pages.
8. Hash final output.
9. Sign canonical event with recipient ML-DSA key.
10. Commit event to local permissioned ledger.
11. Leak one copy.
12. Extract fingerprint.
13. Find matching event.
14. Verify signature and hashes.
15. Produce forensic report.

> The MVP should first demonstrate **correctness**, not claim military-grade watermark robustness.

## 11. Implementation Roadmap

| Phase | Scope | Deliverable |
|---|---|---|
| 0 | Threat model + requirements | Security specification |
| 1 | Basic document pipeline | Encrypted PDF distribution + local identity |
| 2 | Fingerprinting | Recipient/session fingerprint generator |
| 3 | Watermark MVP | DWT/DCT + ECC prototype |
| 4 | PQC | ML-KEM + ML-DSA integration |
| 5 | Trusted decryption | Plaintext-to-watermarked-output security boundary |
| 6 | DLT | Permissioned Fabric network with BFT ordering |
| 7 | Forensics | Extraction + ledger lookup + verification |
| 8 | Hardening | HSM, RBAC, audit, key lifecycle, offline updates |
| 9 | Adversarial evaluation | Attack suite and performance benchmark |
| 10 | Corporate packaging | Deployment guide, SOPs, evidence verifier |

## 12. Project Structure

```
SKY-VAULT/
├── README.md                  # This file
├── requirements.txt           # Python dependencies
├── pqc_core.py               # PQC module (ML-KEM, ML-DSA, AES-256-GCM)
├── fingerprint/               # Fingerprint generator (Tardos codes + session nonce)
├── watermark/                 # Steganography engine (DWT/DCT + ECC)
├── ledger/                    # Hyperledger Fabric chaincode + gateway
├── forensics/                 # Extraction + verification pipeline
├── client/                    # Secure viewer / trusted decryption boundary
└── tests/                     # Test suite
```

## 13. References

1. Cox et al. (1997). Secure Spread Spectrum Watermarking. IEEE TIP.
2. NIST FIPS 203 (2024). ML-KEM Standard.
3. NIST FIPS 204 (2024). ML-DSA Standard.
4. NIST FIPS 205 (2024). SLH-DSA Standard.
5. Hyperledger Fabric: BFT / SmartBFT Ordering Service.
6. Castro & Liskov (1999). Practical Byzantine Fault Tolerance.
7. Tardos (2003). Optimal Probabilistic Fingerprint Codes.

## 14. License

This project is developed for the Smart India Hackathon (SIH) 2026.
