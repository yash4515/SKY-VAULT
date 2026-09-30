"""
SKY-VAULT : Flask Web Application
=================================
Provides a full web interface for the SKY-VAULT forensic attribution system.

Routes:
  GET  /                        -> Dashboard
  GET  /privacy                 -> Privacy Policy page
  GET  /terms                   -> Terms and Conditions page
  GET  /api/domain              -> Custom domain status
  POST /api/domain              -> Set custom domain configuration
  POST /api/register            -> Register a new recipient
  POST /api/encrypt             -> Encrypt a document
  POST /api/decrypt             -> Recipient decryption + watermark + ledger commit
  POST /api/forensic/extract    -> Extract watermark from leaked text
  POST /api/forensic/verify     -> Full forensic verification
  GET  /api/ledger/chain        -> Chain summary
  GET  /api/ledger/events       -> All ledger events
  GET  /api/status              -> System status
  POST /api/demo/run            -> Run the full MVP demo
"""

import sys
import os
import hashlib
import json
import secrets
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, session

from pqc_core import PQCManager, DecryptionEvent, sha3_256, canonicalize
from fingerprint import FingerprintGenerator
from watermark.text_watermark import TextWatermark
from ledger.chain import LocalLedger
from forensics.extractor import ForensicExtractor
from forensics.verifier import ForensicVerifier

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# --- Global in-memory state (single-session MVP) -----------------------------
_lock = threading.Lock()

_state = {
    "pqc": None,
    "fp_gen": None,
    "text_wm": None,
    "ledger": None,
    "extractor": None,
    "recipients": {},       # name -> {kem_pub, kem_priv, sig_pub, sig_priv, key_id}
    "key_registry": {},     # key_id -> sig_pub
    "documents": {},        # document_id -> {encrypted, nonce, dek, wrapped_keys, hash, version, original_text}
    "watermarked_docs": {}, # watermark_id -> watermarked_text (for forensic sim)
    "distribution_id": "DIST-001",
    "custom_domain": "skyvault.internal",
    "domain_status": "CONFIGURED",
    "initialized": False,
    "demo_log": [],
}


def _ensure_initialized():
    """Lazy-initialize all subsystems."""
    if _state["initialized"]:
        return
    _state["pqc"] = PQCManager()
    _state["fp_gen"] = FingerprintGenerator(num_recipients=20, max_colluders=3)
    _state["text_wm"] = TextWatermark()
    _state["ledger"] = LocalLedger(":memory:")
    _state["extractor"] = ForensicExtractor()
    _state["initialized"] = True


# --- Helper -------------------------------------------------------------------

def _ok(data: dict = None, **kwargs):
    payload = {"success": True}
    if data:
        payload.update(data)
    payload.update(kwargs)
    return jsonify(payload)


def _err(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg}), code


# --- Routes -------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/api/domain", methods=["GET", "POST"])
def api_domain():
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        domain = (data.get("domain") or "").strip()
        if not domain:
            return _err("Domain name is required")
        with _lock:
            _state["custom_domain"] = domain
            _state["domain_status"] = "CONFIGURED"
        return _ok(
            domain=_state["custom_domain"],
            status=_state["domain_status"],
            message=f"Custom domain successfully bound to {domain}",
        )
    with _lock:
        return _ok(
            domain=_state.get("custom_domain", "skyvault.internal"),
            status=_state.get("domain_status", "CONFIGURED"),
            host_header=request.host,
            tls_ready=True,
        )


@app.route("/api/status")
def api_status():
    with _lock:
        _ensure_initialized()
        pqc = _state["pqc"]
        ledger = _state["ledger"]
        chain = ledger.get_chain_summary()
        return _ok(
            mode=pqc.get_mode(),
            kem_algorithm=pqc.kem_alg,
            sig_algorithm=pqc.sig_alg,
            recipients=list(_state["recipients"].keys()),
            documents=list(_state["documents"].keys()),
            chain_height=chain["chain_height"],
            chain_valid=chain["chain_valid"],
            custom_domain=_state.get("custom_domain", "skyvault.internal"),
            domain_status=_state.get("domain_status", "CONFIGURED"),
            initialized=_state["initialized"],
        )


# ── Recipients ────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return _err("Recipient name is required")

    with _lock:
        _ensure_initialized()
        if name in _state["recipients"]:
            return _err(f"Recipient '{name}' is already registered")

        pqc = _state["pqc"]
        kem_pub, kem_priv = pqc.generate_kem_keypair()
        sig_pub, sig_priv = pqc.generate_sig_keypair()
        key_id = "RID-" + hashlib.sha3_256(sig_pub).hexdigest()[:12]

        _state["recipients"][name] = {
            "kem_pub": kem_pub,
            "kem_priv": kem_priv,
            "sig_pub": sig_pub,
            "sig_priv": sig_priv,
            "key_id": key_id,
        }
        _state["key_registry"][key_id] = sig_pub

    return _ok(
        name=name,
        key_id=key_id,
        kem_pub_bytes=len(kem_pub),
        sig_pub_bytes=len(sig_pub),
        message=f"Recipient '{name}' registered with ML-KEM + ML-DSA keypairs",
    )


@app.route("/api/recipients")
def api_recipients():
    with _lock:
        _ensure_initialized()
        result = []
        for name, keys in _state["recipients"].items():
            result.append({
                "name": name,
                "key_id": keys["key_id"],
                "kem_pub_bytes": len(keys["kem_pub"]),
                "sig_pub_bytes": len(keys["sig_pub"]),
            })
    return _ok(recipients=result)


# ── Documents ─────────────────────────────────────────────────────────────────

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    version = int(data.get("version", 1))
    if not text:
        return _err("Document text is required")

    with _lock:
        _ensure_initialized()
        if not _state["recipients"]:
            return _err("Register at least one recipient before encrypting")

        pqc = _state["pqc"]
        doc_bytes = text.encode("utf-8")
        doc_hash = sha3_256(doc_bytes)
        doc_id = "DOC-" + hashlib.sha3_256(doc_bytes).hexdigest()[:16]

        dek = PQCManager.generate_dek()
        nonce, encrypted = PQCManager.encrypt_document(dek, doc_bytes)

        # Wrap DEK for each registered recipient
        wrapped = {}
        for rname, rkeys in _state["recipients"].items():
            kem_ct, shared_secret = pqc.encapsulate_key(rkeys["kem_pub"])
            wrapped_dek = bytes(a ^ b for a, b in zip(dek, shared_secret[:32]))
            wrapped[rname] = {
                "kem_ciphertext": kem_ct,
                "wrapped_dek": wrapped_dek,
            }

        _state["documents"][doc_id] = {
            "encrypted": encrypted,
            "nonce": nonce,
            "dek": dek,
            "wrapped_keys": wrapped,
            "hash": doc_hash,
            "version": version,
            "original_text": text,
        }

    return _ok(
        document_id=doc_id,
        document_hash=doc_hash,
        version=version,
        plaintext_bytes=len(doc_bytes),
        encrypted_bytes=len(encrypted),
        recipients_wrapped=list(wrapped.keys()),
        message=f"Document encrypted with AES-256-GCM, DEK wrapped for {len(wrapped)} recipients",
    )


@app.route("/api/documents")
def api_documents():
    with _lock:
        _ensure_initialized()
        result = []
        for doc_id, doc in _state["documents"].items():
            result.append({
                "document_id": doc_id,
                "version": doc["version"],
                "hash": doc["hash"],
                "recipients": list(doc["wrapped_keys"].keys()),
                "plaintext_bytes": len(doc["original_text"].encode()),
            })
    return _ok(documents=result)


# ── Decryption + Watermark + Ledger ───────────────────────────────────────────

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(force=True) or {}
    recipient_name = (data.get("recipient") or "").strip()
    document_id = (data.get("document_id") or "").strip()
    profile = data.get("profile", "digital")

    with _lock:
        _ensure_initialized()

        if recipient_name not in _state["recipients"]:
            return _err(f"Unknown recipient: {recipient_name}")
        if document_id not in _state["documents"]:
            return _err(f"Unknown document: {document_id}")

        doc = _state["documents"][document_id]
        if recipient_name not in doc["wrapped_keys"]:
            return _err(f"Recipient '{recipient_name}' is not authorized for this document")

        pqc = _state["pqc"]
        rkeys = _state["recipients"][recipient_name]
        wk = doc["wrapped_keys"][recipient_name]

        # Decapsulate → recover shared secret → unwrap DEK
        shared_secret = pqc.decapsulate_key(wk["kem_ciphertext"], rkeys["kem_priv"])
        aes_key = bytes(a ^ b for a, b in zip(wk["wrapped_dek"], shared_secret[:32]))

        # Decrypt in-memory
        plaintext_bytes = PQCManager.decrypt_document(aes_key, doc["nonce"], doc["encrypted"])
        plaintext_str = plaintext_bytes.decode("utf-8")

        # Generate session fingerprint
        fp_gen = _state["fp_gen"]
        dist_id = _state["distribution_id"]
        recipient_code = fp_gen.generate_recipient_code(rkeys["key_id"], dist_id)
        session_data = fp_gen.generate_session_fingerprint(document_id, recipient_code)
        watermark_payload = fp_gen.build_watermark_payload(
            recipient_code, session_data["session_id"], doc["version"]
        )

        # Embed watermark
        wm_text = _state["text_wm"].embed(plaintext_str, watermark_payload, position="distributed")
        del plaintext_str  # purge from memory

        # Hash watermarked output
        wm_bytes = wm_text.encode("utf-8")
        output_hash = sha3_256(wm_bytes)

        # Create & sign canonical event
        event = DecryptionEvent(
            document_id=document_id,
            document_version=doc["version"],
            document_hash=doc["hash"],
            recipient_key_id=rkeys["key_id"],
            session_id=session_data["session_id"],
            session_nonce=session_data["session_nonce"],
            watermark_id=session_data["watermark_id"],
            watermark_profile=profile,
            output_hash=output_hash,
        )
        signature = event.sign(pqc, rkeys["sig_priv"])
        event_digest = event.get_digest()
        sig_valid = pqc.verify(event_digest, signature, rkeys["sig_pub"])

        # Commit to ledger
        ledger_record = event.to_ledger_record(signature)
        receipt = _state["ledger"].commit_event(ledger_record)

        # Store watermarked doc for forensic simulation
        _state["watermarked_docs"][session_data["watermark_id"]] = wm_text

        zwc_count = TextWatermark.get_zwc_count(wm_text)

    return _ok(
        recipient=recipient_name,
        document_id=document_id,
        watermark_id=session_data["watermark_id"],
        session_id=session_data["session_id"],
        output_hash=output_hash,
        zwc_count=zwc_count,
        signature_valid=sig_valid,
        signature_bytes=len(signature),
        block_id=receipt["block_id"],
        block_hash=receipt["block_hash"],
        transaction_id=receipt["transaction_id"],
        commit_time=receipt["commit_time"],
        watermarked_preview=TextWatermark.strip_watermark(wm_text)[:300],
        message=f"Document decrypted, watermarked (WM-ID: {session_data['watermark_id']}), and committed to ledger",
    )


# ── Ledger ────────────────────────────────────────────────────────────────────

@app.route("/api/ledger/chain")
def api_ledger_chain():
    with _lock:
        _ensure_initialized()
        summary = _state["ledger"].get_chain_summary()
        integrity = _state["ledger"].verify_chain_integrity()
    return _ok(**summary, errors=integrity.get("errors", []))


@app.route("/api/ledger/events")
def api_ledger_events():
    with _lock:
        _ensure_initialized()
        ledger = _state["ledger"]
        import sqlite3
        cursor = ledger.conn.cursor()
        cursor.execute(
            "SELECT b.block_id, b.block_hash, b.timestamp, b.event_data "
            "FROM blocks b WHERE b.block_id > 0 ORDER BY b.block_id DESC"
        )
        rows = cursor.fetchall()
        events = []
        for row in rows:
            ev = json.loads(row["event_data"])
            events.append({
                "block_id": row["block_id"],
                "block_hash": row["block_hash"][:32] + "...",
                "commit_time": row["timestamp"],
                "event_id": ev.get("event_id", ""),
                "document_id": ev.get("document_id", ""),
                "recipient_key_id": ev.get("recipient_key_id", ""),
                "watermark_id": ev.get("watermark_id", ""),
                "watermark_profile": ev.get("watermark_profile", ""),
                "document_version": ev.get("document_version", ""),
                "output_hash": (ev.get("output_hash") or "")[:40] + "...",
            })
    return _ok(events=events, count=len(events))


# ── Forensics ─────────────────────────────────────────────────────────────────

@app.route("/api/forensic/extract", methods=["POST"])
def api_forensic_extract():
    data = request.get_json(force=True) or {}
    leaked_text = data.get("text") or ""
    if not leaked_text:
        return _err("Leaked document text is required")

    with _lock:
        _ensure_initialized()
        result = _state["extractor"].extract_from_text(leaked_text)

    return _ok(
        result=result["result"],
        leaked_hash=result.get("leaked_hash", ""),
        payload_recovered=result.get("payload") is not None,
        watermark_id=result.get("watermark_id", ""),
        watermark_data=result.get("watermark_data", {}),
        zwc_count=result.get("zwc_count", 0),
        reason=result.get("reason", ""),
    )


@app.route("/api/forensic/verify", methods=["POST"])
def api_forensic_verify():
    data = request.get_json(force=True) or {}
    watermark_id = (data.get("watermark_id") or "").strip()
    document_hash = (data.get("document_hash") or "").strip() or None
    leaked_hash = (data.get("leaked_hash") or "").strip() or None

    if not watermark_id:
        return _err("watermark_id is required")

    with _lock:
        _ensure_initialized()
        verifier = ForensicVerifier(
            pqc_manager=_state["pqc"],
            ledger=_state["ledger"],
            key_registry=_state["key_registry"],
        )
        verification = verifier.verify_evidence_chain(
            watermark_id=watermark_id,
            document_hash=document_hash,
            leaked_artifact_hash=leaked_hash,
        )
        evidence = verifier.generate_evidence_package(verification)

        # Resolve recipient name from key_id
        attributed_key = verification.get("recipient_key_id", "")
        attributed_name = None
        for name, keys in _state["recipients"].items():
            if keys["key_id"] == attributed_key:
                attributed_name = name
                break

    return _ok(
        result=verification["result"],
        confidence=verification["confidence"],
        steps=verification["steps"],
        event_id=verification.get("event_id"),
        recipient_key_id=attributed_key,
        attributed_name=attributed_name,
        verification_timestamp=verification["verification_timestamp"],
        evidence_package_size=len(json.dumps(evidence)),
    )


@app.route("/api/forensic/simulate_leak", methods=["POST"])
def api_simulate_leak():
    """Return a stored watermarked document to simulate a leak scenario."""
    data = request.get_json(force=True) or {}
    watermark_id = (data.get("watermark_id") or "").strip()

    with _lock:
        _ensure_initialized()
        if watermark_id not in _state["watermarked_docs"]:
            # Return the most recently stored one
            if not _state["watermarked_docs"]:
                return _err("No decrypted documents available. Perform a decryption first.")
            watermark_id = list(_state["watermarked_docs"].keys())[-1]

        wm_text = _state["watermarked_docs"][watermark_id]
        visible = TextWatermark.strip_watermark(wm_text)
        zwc_count = TextWatermark.get_zwc_count(wm_text)

    return _ok(
        watermark_id=watermark_id,
        leaked_text=wm_text,
        visible_preview=visible[:400],
        zwc_count=zwc_count,
        char_count=len(wm_text),
    )


# ── Demo ──────────────────────────────────────────────────────────────────────

@app.route("/api/demo/run", methods=["POST"])
def api_demo_run():
    """Run the full automated MVP demo (registers Alice/Bob/Charlie, encrypts, leaks, traces)."""
    log = []

    def L(msg):
        log.append(msg)

    with _lock:
        _ensure_initialized()
        pqc = _state["pqc"]
        fp_gen = _state["fp_gen"]
        text_wm = _state["text_wm"]
        ledger = _state["ledger"]

        L(f"[INIT] Mode: {pqc.get_mode()}")

        # Register demo recipients
        demo_names = ["Alice", "Bob", "Charlie"]
        for name in demo_names:
            if name not in _state["recipients"]:
                kem_pub, kem_priv = pqc.generate_kem_keypair()
                sig_pub, sig_priv = pqc.generate_sig_keypair()
                key_id = "RID-" + hashlib.sha3_256(sig_pub).hexdigest()[:12]
                _state["recipients"][name] = {
                    "kem_pub": kem_pub, "kem_priv": kem_priv,
                    "sig_pub": sig_pub, "sig_priv": sig_priv,
                    "key_id": key_id,
                }
                _state["key_registry"][key_id] = sig_pub
                L(f"[REGISTER] {name} → {key_id}")
            else:
                L(f"[REGISTER] {name} already registered → {_state['recipients'][name]['key_id']}")

        # Encrypt document
        document_text = (
            "STRICTLY CONFIDENTIAL : PROJECT SKY-VAULT\n\n"
            "This document contains the complete architectural specification "
            "for the SKY-VAULT forensic attribution system. The system provides "
            "cryptographically verifiable attribution of leaked documents to "
            "authenticated decryption events using post-quantum cryptography, "
            "invisible forensic watermarking, and a permissioned BFT distributed "
            "ledger.\n\n"
            "DISTRIBUTION: Authorized recipients only.\n"
            "CLASSIFICATION: TOP SECRET\n"
            "VERSION: 17\n"
        )
        doc_bytes = document_text.encode("utf-8")
        doc_id = "DOC-" + hashlib.sha3_256(doc_bytes).hexdigest()[:16]
        doc_version = 17
        doc_hash = sha3_256(doc_bytes)

        dek = PQCManager.generate_dek()
        nonce, encrypted_doc = PQCManager.encrypt_document(dek, doc_bytes)
        L(f"[ENCRYPT] {doc_id} ({len(doc_bytes)} bytes plaintext → {len(encrypted_doc)} bytes encrypted)")

        # Wrap keys
        wrapped_keys = {}
        for name, rkeys in _state["recipients"].items():
            if name in demo_names:
                kem_ct, ss = pqc.encapsulate_key(rkeys["kem_pub"])
                wrapped_dek = bytes(a ^ b for a, b in zip(dek, ss[:32]))
                wrapped_keys[name] = {"kem_ciphertext": kem_ct, "wrapped_dek": wrapped_dek}
                L(f"[WRAP] DEK wrapped for {name}")

        _state["documents"][doc_id] = {
            "encrypted": encrypted_doc, "nonce": nonce, "dek": dek,
            "wrapped_keys": wrapped_keys, "hash": doc_hash,
            "version": doc_version, "original_text": document_text,
        }

        leaker = "Bob"
        leaker_keys = _state["recipients"][leaker]
        leaker_wk = wrapped_keys[leaker]

        # Decapsulate
        ss2 = pqc.decapsulate_key(leaker_wk["kem_ciphertext"], leaker_keys["kem_priv"])
        aes_key = bytes(a ^ b for a, b in zip(leaker_wk["wrapped_dek"], ss2[:32]))
        plaintext = PQCManager.decrypt_document(aes_key, nonce, encrypted_doc)
        L(f"[DECRYPT] {leaker} decrypted document in-memory ({len(plaintext)} bytes)")

        # Fingerprint
        dist_id = _state["distribution_id"]
        rc = fp_gen.generate_recipient_code(leaker_keys["key_id"], dist_id)
        sess = fp_gen.generate_session_fingerprint(doc_id, rc)
        wm_payload = fp_gen.build_watermark_payload(rc, sess["session_id"], doc_version, 1)
        L(f"[FINGERPRINT] Watermark ID: {sess['watermark_id']}")

        # Watermark
        plaintext_str = plaintext.decode("utf-8")
        wm_text = text_wm.embed(plaintext_str, wm_payload, position="distributed")
        del plaintext, plaintext_str
        wm_bytes = wm_text.encode("utf-8")
        output_hash = sha3_256(wm_bytes)
        L(f"[WATERMARK] Embedded ZWC watermark ({TextWatermark.get_zwc_count(wm_text)} hidden chars)")

        # Sign
        event = DecryptionEvent(
            document_id=doc_id, document_version=doc_version,
            document_hash=doc_hash, recipient_key_id=leaker_keys["key_id"],
            session_id=sess["session_id"], session_nonce=sess["session_nonce"],
            watermark_id=sess["watermark_id"], watermark_profile="digital",
            output_hash=output_hash,
        )
        sig = event.sign(pqc, leaker_keys["sig_priv"])
        ev_digest = event.get_digest()
        sig_ok = pqc.verify(ev_digest, sig, leaker_keys["sig_pub"])
        L(f"[SIGN] ML-DSA-65 signature: {len(sig)} bytes, valid={sig_ok}")

        # Commit
        ledger_record = event.to_ledger_record(sig)
        receipt = ledger.commit_event(ledger_record)
        L(f"[LEDGER] Block #{receipt['block_id']} → {receipt['transaction_id']}")

        _state["watermarked_docs"][sess["watermark_id"]] = wm_text

        # Commit Alice and Charlie too
        for name in ["Alice", "Charlie"]:
            if name not in wrapped_keys:
                continue
            rkeys = _state["recipients"][name]
            rk = wrapped_keys[name]
            other_ss = pqc.decapsulate_key(rk["kem_ciphertext"], rkeys["kem_priv"])
            other_dek = bytes(a ^ b for a, b in zip(rk["wrapped_dek"], other_ss[:32]))
            other_plain = PQCManager.decrypt_document(other_dek, nonce, encrypted_doc)
            other_rc = fp_gen.generate_recipient_code(rkeys["key_id"], dist_id)
            other_sess = fp_gen.generate_session_fingerprint(doc_id, other_rc)
            other_payload = fp_gen.build_watermark_payload(other_rc, other_sess["session_id"], doc_version)
            other_wm = text_wm.embed(other_plain.decode(), other_payload, position="distributed")
            del other_plain
            other_out_hash = sha3_256(other_wm.encode())
            other_event = DecryptionEvent(
                document_id=doc_id, document_version=doc_version,
                document_hash=doc_hash, recipient_key_id=rkeys["key_id"],
                session_id=other_sess["session_id"], session_nonce=other_sess["session_nonce"],
                watermark_id=other_sess["watermark_id"], watermark_profile="digital",
                output_hash=other_out_hash,
            )
            other_sig = other_event.sign(pqc, rkeys["sig_priv"])
            other_receipt = ledger.commit_event(other_event.to_ledger_record(other_sig))
            _state["watermarked_docs"][other_sess["watermark_id"]] = other_wm
            L(f"[LEDGER] {name}: Block #{other_receipt['block_id']} (WM: {other_sess['watermark_id']})")

        # Simulate leak
        leaked_document = wm_text
        L(f"[LEAK] Bob's copy leaked ({len(leaked_document)} chars)")

        # Extract
        extract_result = _state["extractor"].extract_from_text(leaked_document)
        L(f"[EXTRACT] Result: {extract_result['result']}, ZWC: {extract_result.get('zwc_count', 0)}")

        # Verify
        verifier = ForensicVerifier(
            pqc_manager=pqc, ledger=ledger, key_registry=_state["key_registry"]
        )
        verification = verifier.verify_evidence_chain(
            watermark_id=sess["watermark_id"],
            document_hash=doc_hash,
            leaked_artifact_hash=extract_result["leaked_hash"],
        )
        L(f"[VERIFY] Result: {verification['result']}, Confidence: {verification['confidence']}")

        chain = ledger.get_chain_summary()
        L(f"[CHAIN] Height: {chain['chain_height']}, Valid: {chain['chain_valid']}")

    return _ok(
        log=log,
        result=verification["result"],
        confidence=verification["confidence"],
        steps=verification["steps"],
        document_id=doc_id,
        watermark_id=sess["watermark_id"],
        leaker=leaker,
        attributed_key=leaker_keys["key_id"],
        chain_height=chain["chain_height"],
    )


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset all in-memory state (fresh session)."""
    with _lock:
        if _state["ledger"]:
            try:
                _state["ledger"].close()
            except Exception:
                pass
        _state.update({
            "pqc": None, "fp_gen": None, "text_wm": None, "ledger": None,
            "extractor": None, "recipients": {}, "key_registry": {},
            "documents": {}, "watermarked_docs": {}, "initialized": False,
            "demo_log": [],
        })
    return _ok(message="System reset. All in-memory state cleared.")


if __name__ == "__main__":
    print("  SKY-VAULT Web UI : http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
