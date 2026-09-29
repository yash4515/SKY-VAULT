"""
TraceVault — PDF Watermark Engine
==================================
Renders PDF pages to images, applies DWT/DCT forensic watermark,
and reconstructs the watermarked PDF.

Strategy (Section 8.3):
  "Canonicalize and render PDF pages to a controlled representation,
   apply the forensic watermark at the page/image layer, and package
   the result back into a PDF."

Profiles (Section 8.3):
  - Digital:      Compression, resizing, re-encoding, moderate crop
  - Screen:       Screenshots, display capture, scaling
  - Print-secure: Print → scan, photocopy
  - High-security: Multiple attack classes
"""

import io
import hashlib
from typing import Optional
from PIL import Image

try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False

from watermark.image_watermark import ImageWatermark


# Rendering DPI per watermark profile
PROFILE_DPI = {
    "digital": 150,
    "screen": 200,
    "print-secure": 300,
    "high-security": 300,
}

# Embedding strength per profile
PROFILE_ALPHA = {
    "digital": 4.0,
    "screen": 6.0,
    "print-secure": 8.0,
    "high-security": 10.0,
}


class PDFWatermark:
    """
    Watermarks PDF documents by:
    1. Rendering each page to a raster image at configured DPI
    2. Applying DWT/DCT forensic watermark per page
    3. Reconstructing the PDF from watermarked page images
    
    The watermark payload is embedded redundantly across ALL pages.
    """

    def __init__(
        self,
        profile: str = "digital",
        seed_key: bytes = b"tracevault-default-key",
    ):
        """
        Args:
            profile: Watermark profile (digital, screen, print-secure, high-security)
            seed_key: Secret key for watermark spreading
        """
        if profile not in PROFILE_DPI:
            raise ValueError(f"Unknown profile: {profile}. Choose from {list(PROFILE_DPI.keys())}")

        self.profile = profile
        self.dpi = PROFILE_DPI[profile]
        self.alpha = PROFILE_ALPHA[profile]
        self.seed_key = seed_key
        self.image_wm = ImageWatermark(alpha=self.alpha, seed_key=seed_key)

    def watermark_pdf(self, pdf_bytes: bytes, payload: bytes) -> bytes:
        """
        Apply forensic watermark to a PDF document (in-memory).

        Args:
            pdf_bytes: Raw PDF file content.
            payload: Watermark payload bytes.

        Returns:
            Watermarked PDF as bytes.

        All processing happens in-memory. No temp files are created.
        """
        if not HAS_PYMUPDF:
            raise RuntimeError(
                "PyMuPDF (fitz) is required for PDF watermarking. "
                "Install with: pip install PyMuPDF"
            )

        # Open the PDF from memory
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        watermarked_pages = []

        for page_idx in range(len(doc)):
            page = doc[page_idx]

            # Render page to image at configured DPI
            mat = fitz.Matrix(self.dpi / 72, self.dpi / 72)
            pix = page.get_pixmap(matrix=mat)

            # Convert to PIL Image (in-memory)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

            # Apply DWT/DCT watermark with page-specific key derivation
            page_key = self.seed_key + f"-page-{page_idx}".encode()
            page_wm = ImageWatermark(
                alpha=self.alpha,
                seed_key=page_key,
            )
            watermarked_img = page_wm.embed(img, payload)
            watermarked_pages.append(watermarked_img)

        doc.close()

        # Reconstruct PDF from watermarked images
        output_pdf = self._images_to_pdf(watermarked_pages)
        return output_pdf

    def extract_from_pdf(
        self,
        original_pdf_bytes: bytes,
        watermarked_pdf_bytes: bytes,
        payload_length: int,
        page_index: int = 0,
    ) -> Optional[bytes]:
        """
        Extract watermark payload from a watermarked PDF.

        Args:
            original_pdf_bytes: Original (unwatermarked) PDF.
            watermarked_pdf_bytes: Watermarked PDF to extract from.
            payload_length: Expected payload length in bytes.
            page_index: Which page to extract from (default: 0).

        Returns:
            Extracted payload bytes, or None.
        """
        if not HAS_PYMUPDF:
            raise RuntimeError("PyMuPDF required for PDF extraction.")

        # Render both pages
        orig_doc = fitz.open(stream=original_pdf_bytes, filetype="pdf")
        wm_doc = fitz.open(stream=watermarked_pdf_bytes, filetype="pdf")

        mat = fitz.Matrix(self.dpi / 72, self.dpi / 72)

        orig_pix = orig_doc[page_index].get_pixmap(matrix=mat)
        orig_img = Image.frombytes("RGB", [orig_pix.width, orig_pix.height], orig_pix.samples)

        wm_pix = wm_doc[page_index].get_pixmap(matrix=mat)
        wm_img = Image.frombytes("RGB", [wm_pix.width, wm_pix.height], wm_pix.samples)

        orig_doc.close()
        wm_doc.close()

        # Extract using page-specific key
        page_key = self.seed_key + f"-page-{page_index}".encode()
        page_wm = ImageWatermark(alpha=self.alpha, seed_key=page_key)
        return page_wm.extract(orig_img, wm_img, payload_length)

    def _images_to_pdf(self, images: list) -> bytes:
        """Convert a list of PIL Images to a PDF in memory."""
        if not images:
            return b""

        # Convert all images to RGB mode
        rgb_images = [img.convert("RGB") for img in images]

        # Save to in-memory buffer
        buffer = io.BytesIO()
        if len(rgb_images) == 1:
            rgb_images[0].save(buffer, format="PDF", resolution=self.dpi)
        else:
            rgb_images[0].save(
                buffer,
                format="PDF",
                resolution=self.dpi,
                save_all=True,
                append_images=rgb_images[1:],
            )
        return buffer.getvalue()

    @staticmethod
    def compute_document_hash(pdf_bytes: bytes) -> str:
        """Compute SHA3-256 hash of PDF content."""
        return "sha3-256:" + hashlib.sha3_256(pdf_bytes).hexdigest()


if __name__ == "__main__":
    print("=== PDF Watermark Engine Test ===\n")

    if not HAS_PYMUPDF:
        print("PyMuPDF not installed. Install with: pip install PyMuPDF")
        print("Skipping PDF watermark test.")
    else:
        # Create a simple test PDF in memory
        from reportlab.pdfgen import canvas as rl_canvas
        from reportlab.lib.pagesizes import letter

        buf = io.BytesIO()
        c = rl_canvas.Canvas(buf, pagesize=letter)
        c.setFont("Helvetica", 24)
        c.drawString(100, 700, "CONFIDENTIAL - TraceVault Test Document")
        c.setFont("Helvetica", 14)
        c.drawString(100, 650, "This document is protected by forensic watermarking.")
        c.drawString(100, 620, "Any unauthorized distribution will be traced.")
        c.save()
        test_pdf = buf.getvalue()

        print(f"Test PDF size: {len(test_pdf)} bytes")

        pdf_wm = PDFWatermark(profile="digital")
        payload = b"WM-abc123def456"

        print(f"Profile: {pdf_wm.profile}")
        print(f"DPI: {pdf_wm.dpi}")
        print(f"Alpha: {pdf_wm.alpha}")
        print(f"Payload: {payload}\n")

        # Watermark
        watermarked_pdf = pdf_wm.watermark_pdf(test_pdf, payload)
        print(f"Watermarked PDF size: {len(watermarked_pdf)} bytes")

        orig_hash = PDFWatermark.compute_document_hash(test_pdf)
        wm_hash = PDFWatermark.compute_document_hash(watermarked_pdf)
        print(f"Original hash:    {orig_hash[:40]}...")
        print(f"Watermarked hash: {wm_hash[:40]}...")
        print(f"Hashes differ: {orig_hash != wm_hash}\n")

        # Extract
        extracted = pdf_wm.extract_from_pdf(test_pdf, watermarked_pdf, len(payload))
        print(f"Extracted payload: {extracted}")
        print(f"Match: {extracted == payload}")
        print(f"\n{'✓ PDF round-trip successful!' if extracted == payload else '✗ PDF round-trip FAILED!'}")
