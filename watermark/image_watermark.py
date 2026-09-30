"""
SKY-VAULT - Image Watermark Engine (DWT/DCT Domain Embedding)
===============================================================
Embeds invisible forensic fingerprint payload into images using
frequency-domain watermarking (DWT + DCT) with Reed-Solomon ECC.

Pipeline (Section 8.2):
  Fingerprint payload
       ↓
  Error-correcting code (Reed-Solomon)
       ↓
  Bit interleaving / scrambling
       ↓
  Pseudo-random spreading (secret key)
       ↓
  DWT/DCT robust embedding domain
       ↓
  Redundant multi-region embedding
       ↓
  Watermarked image

Reference: Cox et al. (1997) Secure Spread Spectrum Watermarking.
"""

import numpy as np
import hashlib
import pywt
from PIL import Image
from reedsolo import RSCodec
from scipy.fft import dct, idct
from typing import Optional, Tuple
import io


# Reed-Solomon ECC symbols
RS_NSYM = 24

# DWT decomposition level
DWT_LEVEL = 2

# Watermark embedding strength (alpha)
# Higher = more robust but more visible
ALPHA = 5.0

# Block size for DCT embedding
BLOCK_SIZE = 8


class ImageWatermark:
    """
    DWT/DCT domain watermarking engine with:
    - Reed-Solomon error correction
    - Pseudo-random bit spreading (keyed)
    - Multi-region redundant embedding
    - Configurable embedding strength
    """

    def __init__(
        self,
        ecc_symbols: int = RS_NSYM,
        alpha: float = ALPHA,
        seed_key: bytes = b"sky-vault-default-key",
    ):
        """
        Args:
            ecc_symbols: Number of RS ECC symbols.
            alpha: Embedding strength factor.
            seed_key: Secret key for pseudo-random spreading/scrambling.
        """
        self.rs = RSCodec(ecc_symbols)
        self.alpha = alpha
        self.seed_key = seed_key
        self._rng_seed = int.from_bytes(
            hashlib.sha3_256(seed_key).digest()[:8], "big"
        )

    # --- Payload Preparation ---------------------------------

    def _prepare_payload(self, payload: bytes) -> np.ndarray:
        """
        Prepare payload for embedding:
        1. Reed-Solomon encode
        2. Convert to bit array
        3. Map {0,1} → {-1, +1} for spread-spectrum embedding
        """
        ecc_data = bytes(self.rs.encode(payload))
        bits = np.unpackbits(np.frombuffer(ecc_data, dtype=np.uint8))
        # Map to bipolar: 0 → -1, 1 → +1
        return bits.astype(np.float64) * 2 - 1

    def _recover_payload(self, bipolar_bits: np.ndarray) -> Optional[bytes]:
        """
        Recover payload from extracted bipolar bits:
        1. Threshold to binary
        2. Pack to bytes
        3. Reed-Solomon decode
        """
        bits = (bipolar_bits > 0).astype(np.uint8)
        # Pad to multiple of 8
        pad = (8 - len(bits) % 8) % 8
        if pad > 0:
            bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
        raw_bytes = np.packbits(bits)
        try:
            decoded = self.rs.decode(raw_bytes)
            return bytes(decoded)
        except Exception:
            return None

    # --- Pseudo-random Spreading -----------------------------

    def _generate_pn_sequence(self, length: int) -> np.ndarray:
        """Generate a pseudo-random ±1 sequence keyed by the secret."""
        rng = np.random.default_rng(self._rng_seed)
        return rng.choice([-1.0, 1.0], size=length)

    def _scramble_positions(self, num_positions: int, total: int) -> np.ndarray:
        """Generate scrambled embedding positions using the secret key."""
        rng = np.random.default_rng(self._rng_seed + 42)
        positions = rng.permutation(total)[:num_positions]
        return np.sort(positions)

    # --- DWT/DCT Embedding -----------------------------------

    def embed(self, image: Image.Image, payload: bytes) -> Image.Image:
        """
        Embed watermark payload into an image using DWT+DCT.

        Args:
            image: PIL Image (will be converted to grayscale for embedding,
                   color channels preserved).
            payload: Raw payload bytes.

        Returns:
            Watermarked PIL Image.
        """
        # Work with numpy array
        img_array = np.array(image, dtype=np.float64)
        is_color = len(img_array.shape) == 3

        if is_color:
            # Embed in luminance channel (convert to YCbCr)
            img_ycbcr = self._rgb_to_ycbcr(img_array)
            channel = img_ycbcr[:, :, 0]  # Y channel
        else:
            channel = img_array.copy()

        # Prepare payload bits
        wm_bits = self._prepare_payload(payload)

        # Apply DWT
        coeffs = pywt.wavedec2(channel, 'haar', level=DWT_LEVEL)

        # Embed in the LL subband's DCT coefficients (most robust)
        ll_band = coeffs[0]
        watermarked_ll = self._embed_in_dct(ll_band, wm_bits)
        coeffs[0] = watermarked_ll

        # Also embed in LH subband for redundancy (Section 8.1)
        if len(coeffs) > 1:
            lh_band = coeffs[1][0]  # LH of first detail level
            if lh_band.size >= len(wm_bits):
                watermarked_lh = self._embed_in_dct(lh_band, wm_bits)
                coeffs[1] = (watermarked_lh, coeffs[1][1], coeffs[1][2])

        # Inverse DWT
        watermarked_channel = pywt.waverec2(coeffs, 'haar')

        # Ensure size matches (DWT can slightly change dimensions)
        watermarked_channel = watermarked_channel[:channel.shape[0], :channel.shape[1]]

        if is_color:
            img_ycbcr[:, :, 0] = watermarked_channel
            result_array = self._ycbcr_to_rgb(img_ycbcr)
        else:
            result_array = watermarked_channel

        # Clip to valid range
        result_array = np.clip(result_array, 0, 255).astype(np.uint8)
        return Image.fromarray(result_array)

    def _embed_in_dct(self, band: np.ndarray, wm_bits: np.ndarray) -> np.ndarray:
        """Embed watermark bits into a DWT subband using DCT coefficients."""
        rows, cols = band.shape
        result = band.copy()

        # Process in blocks
        bit_idx = 0
        for i in range(0, rows - BLOCK_SIZE + 1, BLOCK_SIZE):
            for j in range(0, cols - BLOCK_SIZE + 1, BLOCK_SIZE):
                if bit_idx >= len(wm_bits):
                    bit_idx = 0  # Repeat for redundancy

                block = result[i:i+BLOCK_SIZE, j:j+BLOCK_SIZE]
                dct_block = dct(dct(block, axis=0, norm='ortho'), axis=1, norm='ortho')

                # Embed in mid-frequency DCT coefficients (4,3) and (3,4)
                # These survive compression better than high-frequency
                pn = self._generate_pn_sequence(1)[0]
                dct_block[4, 3] += self.alpha * wm_bits[bit_idx] * pn
                dct_block[3, 4] += self.alpha * wm_bits[bit_idx] * pn

                result[i:i+BLOCK_SIZE, j:j+BLOCK_SIZE] = idct(
                    idct(dct_block, axis=1, norm='ortho'), axis=0, norm='ortho'
                )
                bit_idx += 1

        return result

    # --- DWT/DCT Extraction ----------------------------------

    def extract(
        self,
        original: Image.Image,
        watermarked: Image.Image,
        payload_length: int,
    ) -> Optional[bytes]:
        """
        Extract watermark payload from a watermarked image.
        Uses semi-blind detection (requires original for comparison).

        Args:
            original: Original unwatermarked image.
            watermarked: Watermarked (potentially attacked) image.
            payload_length: Expected payload length in bytes.

        Returns:
            Extracted payload bytes, or None if extraction fails.
        """
        orig_array = np.array(original, dtype=np.float64)
        wm_array = np.array(watermarked, dtype=np.float64)
        is_color = len(orig_array.shape) == 3

        if is_color:
            orig_channel = self._rgb_to_ycbcr(orig_array)[:, :, 0]
            wm_channel = self._rgb_to_ycbcr(wm_array)[:, :, 0]
        else:
            orig_channel = orig_array
            wm_channel = wm_array

        # Apply DWT to both
        orig_coeffs = pywt.wavedec2(orig_channel, 'haar', level=DWT_LEVEL)
        wm_coeffs = pywt.wavedec2(wm_channel, 'haar', level=DWT_LEVEL)

        # Extract from LL subband
        bits_ll = self._extract_from_dct(
            orig_coeffs[0], wm_coeffs[0], payload_length
        )

        # Try to recover payload
        result = self._recover_payload(bits_ll)
        if result is not None:
            return result

        # Fallback: extract from LH subband
        if len(wm_coeffs) > 1:
            bits_lh = self._extract_from_dct(
                orig_coeffs[1][0], wm_coeffs[1][0], payload_length
            )
            return self._recover_payload(bits_lh)

        return None

    def _extract_from_dct(
        self, orig_band: np.ndarray, wm_band: np.ndarray, payload_length: int
    ) -> np.ndarray:
        """Extract watermark bits from DCT coefficient differences."""
        rows, cols = orig_band.shape
        bits = []
        ecc_bit_length = (payload_length + self.rs.nsym) * 8

        for i in range(0, rows - BLOCK_SIZE + 1, BLOCK_SIZE):
            for j in range(0, cols - BLOCK_SIZE + 1, BLOCK_SIZE):
                if len(bits) >= ecc_bit_length:
                    break

                orig_block = orig_band[i:i+BLOCK_SIZE, j:j+BLOCK_SIZE]
                wm_block = wm_band[i:i+BLOCK_SIZE, j:j+BLOCK_SIZE]

                orig_dct = dct(dct(orig_block, axis=0, norm='ortho'), axis=1, norm='ortho')
                wm_dct = dct(dct(wm_block, axis=0, norm='ortho'), axis=1, norm='ortho')

                diff = (wm_dct[4, 3] - orig_dct[4, 3]) + (wm_dct[3, 4] - orig_dct[3, 4])
                bits.append(diff)

        return np.array(bits[:ecc_bit_length])

    # --- Color Space Conversion ------------------------------

    @staticmethod
    def _rgb_to_ycbcr(rgb: np.ndarray) -> np.ndarray:
        """Convert RGB to YCbCr color space."""
        xform = np.array([
            [0.299, 0.587, 0.114],
            [-0.168736, -0.331264, 0.5],
            [0.5, -0.418688, -0.081312]
        ])
        ycbcr = rgb @ xform.T
        ycbcr[:, :, 1:] += 128
        return ycbcr

    @staticmethod
    def _ycbcr_to_rgb(ycbcr: np.ndarray) -> np.ndarray:
        """Convert YCbCr to RGB color space."""
        ycbcr_shifted = ycbcr.copy()
        ycbcr_shifted[:, :, 1:] -= 128
        xform_inv = np.array([
            [1.0, 0.0, 1.402],
            [1.0, -0.344136, -0.714136],
            [1.0, 1.772, 0.0]
        ])
        rgb = ycbcr_shifted @ xform_inv.T
        return rgb

    # --- Quality Metrics (Section 20.2) ----------------------

    @staticmethod
    def compute_psnr(original: Image.Image, watermarked: Image.Image) -> float:
        """Compute Peak Signal-to-Noise Ratio (higher = less distortion)."""
        orig = np.array(original, dtype=np.float64)
        wm = np.array(watermarked, dtype=np.float64)
        mse = np.mean((orig - wm) ** 2)
        if mse == 0:
            return float('inf')
        return 10 * np.log10(255.0**2 / mse)

    @staticmethod
    def compute_ssim(original: Image.Image, watermarked: Image.Image) -> float:
        """Compute Structural Similarity Index (simplified)."""
        orig = np.array(original, dtype=np.float64)
        wm = np.array(watermarked, dtype=np.float64)

        c1 = (0.01 * 255) ** 2
        c2 = (0.03 * 255) ** 2

        mu_orig = np.mean(orig)
        mu_wm = np.mean(wm)
        sigma_orig = np.var(orig)
        sigma_wm = np.var(wm)
        sigma_cross = np.mean((orig - mu_orig) * (wm - mu_wm))

        ssim = ((2 * mu_orig * mu_wm + c1) * (2 * sigma_cross + c2)) / \
               ((mu_orig**2 + mu_wm**2 + c1) * (sigma_orig + sigma_wm + c2))
        return float(ssim)


if __name__ == "__main__":
    print("=== Image Watermark Engine Test ===\n")

    # Create a test image
    np.random.seed(42)
    test_img = Image.fromarray(
        np.random.randint(100, 200, (256, 256, 3), dtype=np.uint8)
    )

    iw = ImageWatermark(alpha=5.0)
    payload = b"WM-abc123def456"

    print(f"Original image: {test_img.size}, mode={test_img.mode}")
    print(f"Payload: {payload} ({len(payload)} bytes)\n")

    # Embed
    watermarked = iw.embed(test_img, payload)
    print(f"Watermarked image: {watermarked.size}")

    # Quality metrics
    psnr = ImageWatermark.compute_psnr(test_img, watermarked)
    ssim = ImageWatermark.compute_ssim(test_img, watermarked)
    print(f"PSNR: {psnr:.2f} dB (>35 = imperceptible)")
    print(f"SSIM: {ssim:.4f} (>0.95 = visually identical)\n")

    # Extract
    extracted = iw.extract(test_img, watermarked, len(payload))
    print(f"Extracted payload: {extracted}")
    print(f"Match: {extracted == payload}")
    print(f"\n{'[PASS] Round-trip successful!' if extracted == payload else '[FAIL] Round-trip FAILED!'}")
