"""
SKY-VAULT - Forensic Extractor
================================
Extracts forensic watermark payloads from leaked documents and
resolves them to ledger events.

Reference: SKY-VAULT spec Section 13 - Forensic Investigation Workflow.

Steps:
  1. Acquire leaked artifact.
  2. Hash the leaked file (preserve evidence).
  3. Normalize/render per extraction profile.
  4. Detect candidate watermark regions.
  5. Recover watermark symbols from multiple redundant regions.
  6. Perform synchronization and error correction.
  7. Calculate extraction confidence.
  8. Resolve recovered watermark ID to candidate ledger events.
"""

import hashlib
import json
from typing import Optional
from PIL import Image

from watermark.text_watermark import TextWatermark
from watermark.image_watermark import ImageWatermark

try:
    from watermark.pdf_watermark import PDFWatermark, HAS_PYMUPDF
except ImportError:
    HAS_PYMUPDF = False


def sha3_256_hex(data: bytes) -> str:
    return "sha3-256:" + hashlib.sha3_256(data).hexdigest()


class ForensicExtractor:
    """
    Extracts watermark payloads from leaked documents of various types.
    Supports text, image, and PDF extraction.
    """

    def __init__(self, seed_key: bytes = b"sky-vault-default-key"):
        self.seed_key = seed_key
        self.text_wm = TextWatermark()
        self.image_wm = ImageWatermark(seed_key=seed_key)

    def extract_from_text(self, leaked_text: str) -> dict:
        """
        Extract watermark from a leaked text document.
        
        Returns extraction report with result state.
        """
        leaked_hash = sha3_256_hex(leaked_text.encode("utf-8"))

        if not TextWatermark.has_watermark(leaked_text):
            return {
                "result": "INCONCLUSIVE",
                "reason": "No zero-width steganographic characters detected",
                "leaked_hash": leaked_hash,
                "payload": None,
            }

        payload = self.text_wm.extract(leaked_text)

        if payload is None:
            return {
                "result": "INCONCLUSIVE",
                "reason": "Zero-width characters found but payload extraction failed (ECC could not correct)",
                "leaked_hash": leaked_hash,
                "payload": None,
            }

        # Parse watermark payload
        try:
            wm_data = json.loads(payload.decode("utf-8"))
            watermark_id = f"WM-{wm_data.get('sid', 'unknown')}"
        except (json.JSONDecodeError, UnicodeDecodeError):
            watermark_id = f"WM-{payload[:16].hex()}"
            wm_data = {"raw": payload.hex()}

        return {
            "result": "WATERMARK_RECOVERED",
            "leaked_hash": leaked_hash,
            "payload": payload,
            "watermark_data": wm_data,
            "watermark_id": watermark_id,
            "zwc_count": TextWatermark.get_zwc_count(leaked_text),
        }

    def extract_from_image(
        self,
        original_image: Image.Image,
        leaked_image: Image.Image,
        payload_length: int,
    ) -> dict:
        """
        Extract watermark from a leaked image.
        Semi-blind detection (requires original).
        """
        leaked_hash = sha3_256_hex(leaked_image.tobytes())

        payload = self.image_wm.extract(original_image, leaked_image, payload_length)

        if payload is None:
            return {
                "result": "INCONCLUSIVE",
                "reason": "Image watermark extraction failed",
                "leaked_hash": leaked_hash,
                "payload": None,
            }

        try:
            wm_data = json.loads(payload.decode("utf-8"))
            watermark_id = f"WM-{wm_data.get('sid', 'unknown')}"
        except (json.JSONDecodeError, UnicodeDecodeError):
            watermark_id = f"WM-{payload[:16].hex()}"
            wm_data = {"raw": payload.hex()}

        # Quality assessment
        psnr = ImageWatermark.compute_psnr(original_image, leaked_image)

        return {
            "result": "WATERMARK_RECOVERED",
            "leaked_hash": leaked_hash,
            "payload": payload,
            "watermark_data": wm_data,
            "watermark_id": watermark_id,
            "psnr": psnr,
        }

    def extract_from_pdf(
        self,
        original_pdf: bytes,
        leaked_pdf: bytes,
        payload_length: int,
        profile: str = "digital",
    ) -> dict:
        """
        Extract watermark from a leaked PDF.
        """
        if not HAS_PYMUPDF:
            return {
                "result": "ERROR",
                "reason": "PyMuPDF not available for PDF extraction",
            }

        leaked_hash = sha3_256_hex(leaked_pdf)

        pdf_wm = PDFWatermark(profile=profile, seed_key=self.seed_key)
        payload = pdf_wm.extract_from_pdf(
            original_pdf, leaked_pdf, payload_length
        )

        if payload is None:
            return {
                "result": "INCONCLUSIVE",
                "reason": "PDF watermark extraction failed",
                "leaked_hash": leaked_hash,
                "payload": None,
            }

        try:
            wm_data = json.loads(payload.decode("utf-8"))
            watermark_id = f"WM-{wm_data.get('sid', 'unknown')}"
        except (json.JSONDecodeError, UnicodeDecodeError):
            watermark_id = f"WM-{payload[:16].hex()}"
            wm_data = {"raw": payload.hex()}

        return {
            "result": "WATERMARK_RECOVERED",
            "leaked_hash": leaked_hash,
            "payload": payload,
            "watermark_data": wm_data,
            "watermark_id": watermark_id,
        }


if __name__ == "__main__":
    print("=== Forensic Extractor Test ===\n")

    extractor = ForensicExtractor()

    # Test text extraction
    tw = TextWatermark()
    original = "This is a strictly confidential document."
    payload = b'{"sid":"abc123def456","rc":"xyz","dv":17}'
    watermarked = tw.embed(original, payload)

    result = extractor.extract_from_text(watermarked)
    print(f"Text extraction result: {result['result']}")
    if result['payload']:
        print(f"  Payload: {result['payload']}")
        print(f"  Watermark ID: {result['watermark_id']}")
    print()
