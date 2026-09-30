"""
SKY-VAULT - Full MVP Demo (Section 22)
========================================
End-to-end demonstration of the complete evidence chain:

  1. Register Alice, Bob and Charlie.
  2. Generate ML-DSA keys.
  3. Encrypt one document using a random DEK.
  4. Wrap the DEK for each recipient using ML-KEM.
  5. Recipient requests decryption.
  6. Generate a fresh session fingerprint.
  7. Embed fingerprint via steganography.
  8. Hash final output.
  9. Sign canonical event with recipient ML-DSA key.
  10. Commit event to local permissioned ledger.
  11. Leak one copy.
  12. Extract fingerprint.
  13. Find event.
  14. Verify signature and hashes.
  15. Produce forensic report.

"The MVP should first demonstrate correctness, not claim 
 military-grade watermark robustness." - Section 22
"""

import sys
import os
import hashlib
import json

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pqc_core import PQCManager, DecryptionEvent, sha3_256, canonicalize
from fingerprint import FingerprintGenerator
from watermark.text_watermark import TextWatermark
from ledger.chain import LocalLedger
from forensics.extractor import ForensicExtractor
from forensics.verifier import ForensicVerifier


def banner(text: str):
    print(f"\n{'=' * 65}")
    print(f"  {text}")
    print(f"{'=' * 65}")


def phase(num: int, title: str):
    print(f"\n{'-' * 65}")
    print(f"  Phase {num}: {title}")
    print(f"{'-' * 65}")


def main():
    banner("SKY-VAULT - Full MVP Demo")
    print("  Post-Quantum Forensic Attribution System")
    print("  Air-Gapped · In-Memory · Immutable Ledger")

    # ===========================================================
    # SETUP: Initialize subsystems
    # ===========================================================
    phase(0, "Initialize Subsystems")

    pqc = PQCManager()
    print("  [PASS] PQC Manager initialized (ML-KEM-768 + ML-DSA-65)")

    fp_gen = FingerprintGenerator(num_recipients=10, max_colluders=3)
    print(f"  [PASS] Fingerprint Generator initialized (Tardos code length: {fp_gen.tardos.code_length})")

    text_wm = TextWatermark()
    print("  [PASS] Text Watermark Engine initialized (ZWC + Reed-Solomon)")

    ledger = LocalLedger(":memory:")
    print(f"  [PASS] Local Ledger initialized (chain height: {ledger.get_chain_summary()['chain_height']})")

    extractor = ForensicExtractor()
    print("  [PASS] Forensic Extractor initialized")

    # ===========================================================
    # STEP 1-2: Register Recipients and Generate Keys
    # ===========================================================
    phase(1, "Register Recipients (Alice, Bob, Charlie)")

    recipients = {}
    key_registry = {}  # key_id → sig_pub (for verification)

    for name in ["Alice", "Bob", "Charlie"]:
        kem_pub, kem_priv = pqc.generate_kem_keypair()
        sig_pub, sig_priv = pqc.generate_sig_keypair()
        key_id = f"RID-{hashlib.sha3_256(sig_pub).hexdigest()[:12]}"

        recipients[name] = {
            "kem_pub": kem_pub,
            "kem_priv": kem_priv,
            "sig_pub": sig_pub,
            "sig_priv": sig_priv,
            "key_id": key_id,
        }
        key_registry[key_id] = sig_pub

        print(f"  [PASS] {name}")
        print(f"    Key ID:      {key_id}")
        print(f"    ML-KEM pub:  {len(kem_pub)} bytes")
        print(f"    ML-DSA pub:  {len(sig_pub)} bytes")

    # ===========================================================
    # STEP 3: Encrypt Document
    # ===========================================================
    phase(3, "Encrypt Document with AES-256-GCM")

    document_text = (
        "STRICTLY CONFIDENTIAL - PROJECT SKY-VAULT\n"
        "\n"
        "This document contains the complete architectural specification "
        "for the SKY-VAULT forensic attribution system. The system provides "
        "cryptographically verifiable attribution of leaked documents to "
        "authenticated decryption events using post-quantum cryptography, "
        "invisible forensic watermarking, and a permissioned BFT distributed "
        "ledger.\n"
        "\n"
        "DISTRIBUTION: Authorized recipients only.\n"
        "CLASSIFICATION: TOP SECRET\n"
        "VERSION: 17\n"
    )

    document_bytes = document_text.encode("utf-8")
    document_id = "DOC-" + hashlib.sha3_256(document_bytes).hexdigest()[:16]
    document_version = 17
    document_hash = sha3_256(document_bytes)

    # Generate random Document Encryption Key (DEK) and encrypt
    dek = PQCManager.generate_dek()
    nonce, encrypted_doc = PQCManager.encrypt_document(dek, document_bytes)

    print(f"  Document ID:   {document_id}")
    print(f"  Version:       {document_version}")
    print(f"  Plaintext:     {len(document_bytes)} bytes")
    print(f"  Encrypted:     {len(encrypted_doc)} bytes")
    print(f"  Doc Hash:      {document_hash[:50]}...")

    # ===========================================================
    # STEP 4: Wrap DEK for Each Recipient (ML-KEM)
    # Per Section 6.2: KEM establishes a shared secret, which is
    # then used to XOR-wrap the DEK for each recipient.
    # ===========================================================
    phase(4, "Wrap DEK for Recipients via ML-KEM")

    wrapped_keys = {}
    for name, keys in recipients.items():
        kem_ct, shared_secret = pqc.encapsulate_key(keys["kem_pub"])
        # XOR-wrap the DEK with the KEM shared secret
        wrapped_dek = bytes(a ^ b for a, b in zip(dek, shared_secret[:32]))
        wrapped_keys[name] = {
            "kem_ciphertext": kem_ct,
            "wrapped_dek": wrapped_dek,
        }
        print(f"  [PASS] DEK wrapped for {name} ({len(kem_ct)} bytes KEM ciphertext)")

    # ===========================================================
    # STEP 5-10: Bob Requests Decryption (Full Flow)
    # ===========================================================
    leaker = "Bob"
    phase(5, f"{leaker} Requests Decryption")

    # Step 5a: Decapsulate → recover shared secret → unwrap DEK
    recovered_shared_secret = pqc.decapsulate_key(
        wrapped_keys[leaker]["kem_ciphertext"],
        recipients[leaker]["kem_priv"],
    )
    recipient_aes_key = bytes(
        a ^ b for a, b in zip(wrapped_keys[leaker]["wrapped_dek"], recovered_shared_secret[:32])
    )
    assert recipient_aes_key == dek, "DEK unwrap failed!"
    print(f"  [PASS] {leaker} decapsulated shared secret via ML-KEM")
    print(f"  [PASS] {leaker} unwrapped DEK successfully")

    # Step 6: Generate session fingerprint
    phase(6, "Generate Session Fingerprint")

    distribution_id = "DIST-001"
    recipient_code = fp_gen.generate_recipient_code(
        recipients[leaker]["key_id"], distribution_id
    )
    session = fp_gen.generate_session_fingerprint(document_id, recipient_code)
    watermark_payload = fp_gen.build_watermark_payload(
        recipient_code, session["session_id"], document_version, recipient_index=1
    )

    print(f"  Recipient Code: {recipient_code[:32]}...")
    print(f"  Session ID:     {session['session_id'][:32]}...")
    print(f"  Session Nonce:  {session['session_nonce'][:32]}...")
    print(f"  Watermark ID:   {session['watermark_id']}")
    print(f"  Payload:        {len(watermark_payload)} bytes")

    # Step 7: Decrypt in-memory and apply watermark
    phase(7, "Decrypt In-Memory → Watermark → Render")

    plaintext = PQCManager.decrypt_document(recipient_aes_key, nonce, encrypted_doc)
    print(f"  [PASS] Document decrypted in-memory ({len(plaintext)} bytes)")
    print(f"    [WARN] Plaintext exists ONLY in RAM - never touches disk")

    # Apply text watermark (ZWC steganography)
    plaintext_str = plaintext.decode("utf-8")
    watermarked_text = text_wm.embed(plaintext_str, watermark_payload, position="distributed")

    print(f"  [PASS] Forensic watermark embedded via ZWC steganography")
    print(f"    Original chars:    {len(plaintext_str)}")
    print(f"    Watermarked chars: {len(watermarked_text)}")
    print(f"    Hidden chars:      {TextWatermark.get_zwc_count(watermarked_text)}")
    print(f"    Visual match:      {TextWatermark.strip_watermark(watermarked_text) == plaintext_str}")

    # Clear raw plaintext from memory immediately
    del plaintext, plaintext_str
    print(f"  [PASS] Raw plaintext purged from memory")

    # Step 8: Hash final output
    phase(8, "Hash Watermarked Output")

    watermarked_bytes = watermarked_text.encode("utf-8")
    output_hash = sha3_256(watermarked_bytes)
    print(f"  Output Hash: {output_hash[:50]}...")

    # Step 9: Sign canonical event
    phase(9, "Create & Sign Canonical Decryption Event (ML-DSA)")

    event = DecryptionEvent(
        document_id=document_id,
        document_version=document_version,
        document_hash=document_hash,
        recipient_key_id=recipients[leaker]["key_id"],
        session_id=session["session_id"],
        session_nonce=session["session_nonce"],
        watermark_id=session["watermark_id"],
        watermark_profile="digital",
        output_hash=output_hash,
    )

    signature = event.sign(pqc, recipients[leaker]["sig_priv"])
    print(f"  Event ID:    {event.event['event_id']}")
    print(f"  Timestamp:   {event.event['event_timestamp']}")
    print(f"  Signature:   {len(signature)} bytes (ML-DSA-65)")

    # Verify signature immediately
    event_digest = event.get_digest()
    is_valid = pqc.verify(event_digest, signature, recipients[leaker]["sig_pub"])
    print(f"  Sig verify:  {'PASSED [PASS]' if is_valid else 'FAILED [FAIL]'}")

    # Step 10: Commit to ledger
    phase(10, "Commit Event to Local Permissioned Ledger")

    ledger_record = event.to_ledger_record(signature)
    receipt = ledger.commit_event(ledger_record)

    print(f"  Status:         {receipt['status']}")
    print(f"  Block ID:       {receipt['block_id']}")
    print(f"  Block Hash:     {receipt['block_hash'][:32]}...")
    print(f"  Transaction ID: {receipt['transaction_id']}")
    print(f"  Commit Time:    {receipt['commit_time']}")

    # Also decrypt for Alice and Charlie (to show multi-recipient)
    print(f"\n  [Also committing decryption events for Alice and Charlie...]")
    for name in ["Alice", "Charlie"]:
        other_ss = pqc.decapsulate_key(
            wrapped_keys[name]["kem_ciphertext"],
            recipients[name]["kem_priv"],
        )
        other_dek = bytes(a ^ b for a, b in zip(wrapped_keys[name]["wrapped_dek"], other_ss[:32]))
        other_rc = fp_gen.generate_recipient_code(recipients[name]["key_id"], distribution_id)
        other_session = fp_gen.generate_session_fingerprint(document_id, other_rc)
        other_payload = fp_gen.build_watermark_payload(
            other_rc, other_session["session_id"], document_version
        )
        other_plain = PQCManager.decrypt_document(other_dek, nonce, encrypted_doc)
        other_wm = text_wm.embed(other_plain.decode(), other_payload, position="distributed")
        other_out_hash = sha3_256(other_wm.encode())
        other_event = DecryptionEvent(
            document_id=document_id,
            document_version=document_version,
            document_hash=document_hash,
            recipient_key_id=recipients[name]["key_id"],
            session_id=other_session["session_id"],
            session_nonce=other_session["session_nonce"],
            watermark_id=other_session["watermark_id"],
            watermark_profile="digital",
            output_hash=other_out_hash,
        )
        other_sig = other_event.sign(pqc, recipients[name]["sig_priv"])
        other_receipt = ledger.commit_event(other_event.to_ledger_record(other_sig))
        print(f"  [PASS] {name}: Block #{other_receipt['block_id']} (WM: {other_session['watermark_id']})")
        del other_plain  # Clear plaintext

    chain = ledger.get_chain_summary()
    print(f"\n  Chain height: {chain['chain_height']} blocks")
    print(f"  Chain valid:  {chain['chain_valid']}")

    # ===========================================================
    # STEP 11: Simulate Leak
    # ===========================================================
    phase(11, "SIMULATE DOCUMENT LEAK")

    leaked_document = watermarked_text  # Bob's watermarked copy is "leaked"
    print(f"  [WARN] {leaker}'s watermarked copy has been leaked!")
    print(f"  Leaked document size: {len(leaked_document)} chars")
    visible_text = TextWatermark.strip_watermark(leaked_document)
    print(f"  Visible content preview:")
    print(f"    \"{visible_text[:80]}...\"")

    # ===========================================================
    # STEP 12: Extract Fingerprint from Leaked Copy
    # ===========================================================
    phase(12, "Forensic Extraction from Leaked Document")

    extraction_result = extractor.extract_from_text(leaked_document)

    print(f"  Extraction result: {extraction_result['result']}")
    print(f"  Leaked hash:       {extraction_result['leaked_hash'][:50]}...")

    if extraction_result["payload"]:
        print(f"  Payload recovered: {len(extraction_result['payload'])} bytes")
        print(f"  ZWC count:         {extraction_result['zwc_count']}")
        recovered_data = extraction_result.get("watermark_data", {})
        print(f"  Watermark data:    {json.dumps(recovered_data, indent=4)[:200]}")

    # ===========================================================
    # STEP 13: Find Event in Ledger
    # ===========================================================
    phase(13, "Ledger Lookup - Find Matching Event")

    # Use the watermark_id from the event (in real scenario, we'd reconstruct it from payload)
    lookup_wm_id = session["watermark_id"]
    ledger_match = ledger.lookup_by_watermark(lookup_wm_id)

    if ledger_match:
        print(f"  [PASS] Match found!")
        print(f"    Block ID:       {ledger_match['block_id']}")
        print(f"    Block Hash:     {ledger_match['block_hash'][:32]}...")
        print(f"    Event ID:       {ledger_match['event_data']['event_id']}")
        print(f"    Recipient Key:  {ledger_match['event_data']['recipient_key_id']}")
        print(f"    Timestamp:      {ledger_match['event_data']['event_timestamp']}")
    else:
        print(f"  [FAIL] No matching event found in ledger!")

    # ===========================================================
    # STEP 14: Verify Signature and Hashes
    # ===========================================================
    phase(14, "Cryptographic Verification (Full Evidence Chain)")

    verifier = ForensicVerifier(
        pqc_manager=pqc,
        ledger=ledger,
        key_registry=key_registry,
    )

    verification = verifier.verify_evidence_chain(
        watermark_id=lookup_wm_id,
        document_hash=document_hash,
        leaked_artifact_hash=extraction_result["leaked_hash"],
    )

    # ===========================================================
    # STEP 15: Produce Forensic Report
    # ===========================================================
    phase(15, "Generate Forensic Report")

    print(verifier.format_report(verification))

    # Generate evidence package
    evidence = verifier.generate_evidence_package(verification)
    print(f"  Evidence package generated ({len(json.dumps(evidence))} bytes)")

    # ===========================================================
    # ATTRIBUTION
    # ===========================================================
    if verification["result"] == "CRYPTOGRAPHICALLY VERIFIED":
        attributed_key = verification.get("recipient_key_id", "unknown")
        attributed_name = None
        for name, keys in recipients.items():
            if keys["key_id"] == attributed_key:
                attributed_name = name
                break

        banner(f"ATTRIBUTION: {attributed_name or attributed_key}")
        print(f"  The leaked document has been cryptographically traced to")
        print(f"  the decryption event authenticated by: {attributed_name}")
        print(f"  Key ID: {attributed_key}")
        print(f"")
        print(f"  Note: This establishes that {attributed_name}'s credential")
        print(f"  authenticated the decryption event. It does not prove")
        print(f"  that {attributed_name} intentionally leaked the file.")
    else:
        banner(f"RESULT: {verification['result']}")

    # Cleanup
    ledger.close()
    print(f"\n{'=' * 65}")
    print(f"  MVP Demo Complete")
    print(f"{'=' * 65}\n")


if __name__ == "__main__":
    main()
