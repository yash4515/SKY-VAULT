"""
TraceVault — Text Watermark Engine (Zero-Width Character Steganography)
=======================================================================
Embeds invisible fingerprint payload into text documents using
zero-width Unicode characters.

Encoding scheme:
  - U+200B (Zero-Width Space)        → bit '0'
  - U+200C (Zero-Width Non-Joiner)   → bit '1'
  - U+200D (Zero-Width Joiner)       → byte separator
  - U+FEFF (Zero-Width No-Break Space) → payload start/end marker

The payload is ECC-encoded (Reed-Solomon) before embedding for
robustness against partial text modification.

Reference: TraceVault spec Section 8 — Robust Invisible Watermarking.
"""

from reedsolo import RSCodec
from typing import Optional


# Zero-width Unicode characters
ZWS   = '\u200B'  # Zero-Width Space        → bit 0
ZWNJ  = '\u200C'  # Zero-Width Non-Joiner   → bit 1
ZWJ   = '\u200D'  # Zero-Width Joiner       → byte separator
MARKER = '\uFEFF' # BOM / Zero-Width NBSP   → payload boundary

# Set of all steganographic characters (for stripping/detection)
ZW_CHARS = {ZWS, ZWNJ, ZWJ, MARKER}

# Reed-Solomon error correction symbols (can correct up to nsym/2 byte errors)
RS_NSYM = 32


class TextWatermark:
    """
    Embed and extract invisible watermark payloads in text using
    zero-width Unicode steganography with Reed-Solomon ECC.
    """

    def __init__(self, ecc_symbols: int = RS_NSYM):
        """
        Args:
            ecc_symbols: Number of Reed-Solomon ECC symbols.
                         Can correct up to ecc_symbols//2 byte errors.
        """
        self.rs = RSCodec(ecc_symbols)

    # ─── Encoding ────────────────────────────────────────────

    def _bytes_to_zwc(self, data: bytes) -> str:
        """Convert raw bytes to a zero-width character sequence."""
        zwc_parts = []
        for byte in data:
            bits = format(byte, '08b')
            zwc_parts.append(''.join(ZWS if b == '0' else ZWNJ for b in bits))
        return ZWJ.join(zwc_parts)

    def _zwc_to_bytes(self, zwc: str) -> bytes:
        """Convert a zero-width character sequence back to bytes."""
        byte_groups = zwc.split(ZWJ)
        result = []
        for group in byte_groups:
            if len(group) != 8:
                continue  # skip malformed groups
            bits = ''
            for ch in group:
                if ch == ZWS:
                    bits += '0'
                elif ch == ZWNJ:
                    bits += '1'
                else:
                    continue
            if len(bits) == 8:
                result.append(int(bits, 2))
        return bytes(result)

    # ─── Embed ───────────────────────────────────────────────

    def embed(self, text: str, payload: bytes, position: str = "distributed") -> str:
        """
        Embed a watermark payload into text.

        Args:
            text: The original text content.
            payload: Raw payload bytes (will be ECC-encoded).
            position: Embedding strategy:
                - "start": Insert at beginning
                - "end": Insert at end
                - "distributed": Spread across word boundaries (more robust)

        Returns:
            Watermarked text (visually identical to original).
        """
        # Step 1: Apply Reed-Solomon ECC
        ecc_payload = bytes(self.rs.encode(payload))

        # Step 2: Convert to zero-width characters
        zwc_sequence = MARKER + self._bytes_to_zwc(ecc_payload) + MARKER

        if position == "start":
            return zwc_sequence + text
        elif position == "end":
            return text + zwc_sequence
        elif position == "distributed":
            return self._distribute_embed(text, zwc_sequence)
        else:
            raise ValueError(f"Unknown position strategy: {position}")

    def _distribute_embed(self, text: str, zwc_sequence: str) -> str:
        """
        Distribute the ZWC payload across word boundaries in the text.
        This makes the watermark more resilient to partial text deletion.
        """
        # Find word boundaries (spaces)
        spaces = [i for i, ch in enumerate(text) if ch == ' ']

        if not spaces:
            # Fallback: place at end
            return text + zwc_sequence

        # Strip markers for distribution
        payload_chars = zwc_sequence[1:-1]  # Remove MARKER bookends
        
        # Split payload into roughly equal chunks across word boundaries
        num_chunks = min(len(spaces), max(1, len(payload_chars) // 8))
        chunk_size = max(1, len(payload_chars) // num_chunks)

        chunks = []
        for i in range(0, len(payload_chars), chunk_size):
            chunks.append(payload_chars[i:i + chunk_size])

        # Select evenly spaced word boundaries
        if num_chunks <= len(spaces):
            step = len(spaces) // num_chunks
            selected_positions = [spaces[i * step] for i in range(num_chunks)]
        else:
            selected_positions = spaces[:num_chunks]

        # Insert chunks at selected positions (in reverse to preserve indices)
        result = list(text)
        # Start marker at first position
        first_marker_pos = selected_positions[0] if selected_positions else 0
        
        # Build result with embedded chunks
        watermarked = text[:first_marker_pos + 1] + MARKER
        
        chunk_idx = 0
        last_pos = first_marker_pos + 1
        
        for pos in selected_positions:
            if pos <= first_marker_pos:
                if chunk_idx < len(chunks):
                    watermarked += chunks[chunk_idx]
                    chunk_idx += 1
                continue
            watermarked += text[last_pos:pos + 1]
            if chunk_idx < len(chunks):
                watermarked += chunks[chunk_idx]
                chunk_idx += 1
            last_pos = pos + 1

        # Append remaining chunks and text
        while chunk_idx < len(chunks):
            watermarked += chunks[chunk_idx]
            chunk_idx += 1

        watermarked += text[last_pos:]
        watermarked += MARKER

        return watermarked

    # ─── Extract ─────────────────────────────────────────────

    def extract(self, watermarked_text: str) -> Optional[bytes]:
        """
        Extract the watermark payload from watermarked text.

        Returns:
            The original payload bytes if successfully extracted and ECC-decoded.
            None if no valid watermark is found.
        """
        # Collect all zero-width characters between MARKERs
        zwc_chars = []
        in_payload = False

        for ch in watermarked_text:
            if ch == MARKER:
                if in_payload:
                    # End of payload
                    break
                else:
                    in_payload = True
                    continue

            if in_payload and ch in ZW_CHARS:
                zwc_chars.append(ch)

        if not zwc_chars:
            return None

        zwc_string = ''.join(zwc_chars)

        try:
            # Convert ZWC back to bytes
            ecc_data = self._zwc_to_bytes(zwc_string)
            # Apply Reed-Solomon error correction
            decoded = self.rs.decode(ecc_data)
            return bytes(decoded)
        except Exception:
            return None

    # ─── Utility ─────────────────────────────────────────────

    @staticmethod
    def strip_watermark(text: str) -> str:
        """Remove all zero-width characters from text (for comparison)."""
        return ''.join(ch for ch in text if ch not in ZW_CHARS)

    @staticmethod
    def has_watermark(text: str) -> bool:
        """Check if text contains zero-width steganographic characters."""
        return any(ch in ZW_CHARS for ch in text)

    @staticmethod
    def get_zwc_count(text: str) -> int:
        """Count the number of zero-width characters in text."""
        return sum(1 for ch in text if ch in ZW_CHARS)


if __name__ == "__main__":
    print("=== Text Watermark Engine Test ===\n")

    tw = TextWatermark()

    original = "This is a strictly confidential document regarding Project TraceVault. Do not distribute."
    payload = b"WM-abc123def456"

    print(f"Original text ({len(original)} chars):")
    print(f"  \"{original}\"\n")

    # Embed watermark
    watermarked = tw.embed(original, payload, position="distributed")
    print(f"Watermarked text ({len(watermarked)} chars, +{len(watermarked) - len(original)} hidden):")
    print(f"  \"{TextWatermark.strip_watermark(watermarked)}\"\n")

    print(f"  ZWC count: {TextWatermark.get_zwc_count(watermarked)}")
    print(f"  Has watermark: {TextWatermark.has_watermark(watermarked)}")
    print(f"  Visual match: {TextWatermark.strip_watermark(watermarked) == original}\n")

    # Extract watermark
    extracted = tw.extract(watermarked)
    print(f"Extracted payload: {extracted}")
    print(f"Payload match: {extracted == payload}")
    print(f"\n✓ Round-trip successful!" if extracted == payload else "\n✗ Round-trip FAILED!")
