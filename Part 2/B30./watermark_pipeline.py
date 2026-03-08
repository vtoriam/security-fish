"""
Imperceptible Watermarking Pipeline
=====================================
Steps:
  1. Load or generate a base image
  2. Embed an invisible watermark (DWT+DCT method)
  3. Simulate img2img transformation (blur + noise attack)
  4. Detect & verify the watermark survived

Requirements:
  pip install invisible-watermark opencv-python pillow numpy
"""

import cv2
import numpy as np
from PIL import Image
from imwatermark import WatermarkEncoder, WatermarkDecoder
import os
import sys

# ─── Config ────────────────────────────────────────────────────────────────────

WATERMARK_TEXT = "mywatermark2026"   # must be <= 17 chars for 136-bit payload
INPUT_IMAGE    = "chatgpt_image"         # path to your image (or we'll generate one)
OUTPUT_DIR     = "watermark_output"  # folder where results are saved
METHOD         = "dwtDctSvd"         # options: 'dwtDct', 'dwtDctSvd', 'rivaGan'

# ─── Setup ─────────────────────────────────────────────────────────────────────

os.makedirs(OUTPUT_DIR, exist_ok=True)

def log(msg, status="INFO"):
    icons = {"INFO": "·", "OK": "✓", "FAIL": "✗", "STEP": "▶"}
    print(f"  {icons.get(status,'·')} {msg}")

# ─── Step 0: Create a sample image if none provided ────────────────────────────

def generate_sample_image(path):
    """Generate a simple landscape-style test image."""
    img = np.zeros((512, 512, 3), dtype=np.uint8)

    # Sky gradient
    for y in range(200):
        t = y / 200
        img[y, :] = [
            int(135 + t * 50),   # B
            int(180 + t * 30),   # G
            int(220 - t * 20),   # R
        ]

    # Ground
    img[200:, :] = [34, 100, 60]

    # Sun
    cv2.circle(img, (380, 80), 50, (50, 200, 255), -1)
    cv2.circle(img, (380, 80), 55, (30, 160, 220), 3)

    # Mountains
    pts = np.array([[0,300],[80,200],[160,260],[240,180],[320,250],[400,190],[512,300],[512,512],[0,512]])
    cv2.fillPoly(img, [pts], (60, 80, 70))

    # Water reflection
    for y in range(350, 512):
        alpha = (y - 350) / 162
        img[y, :] = (img[y, :] * (1 - alpha * 0.4)).astype(np.uint8)

    cv2.imwrite(path, img)
    log(f"Generated sample image → {path}", "OK")

if not os.path.exists(INPUT_IMAGE):
    log(f"'{INPUT_IMAGE}' not found — generating a sample image...", "INFO")
    generate_sample_image(INPUT_IMAGE)

# ─── Step 1: Load image ─────────────────────────────────────────────────────────

print("\n" + "═"*52)
print("  WATERMARKING PIPELINE")
print("═"*52)

print("\n[STEP 1] Loading image...")
bgr = cv2.imread(INPUT_IMAGE)
if bgr is None:
    log(f"Could not load '{INPUT_IMAGE}'. Check the path.", "FAIL")
    sys.exit(1)

h, w = bgr.shape[:2]
log(f"Loaded: {INPUT_IMAGE} ({w}×{h}px)", "OK")
cv2.imwrite(f"{OUTPUT_DIR}/1_original.png", bgr)

# ─── Step 2: Embed watermark ────────────────────────────────────────────────────

print("\n[STEP 2] Embedding watermark...")
log(f"Text: '{WATERMARK_TEXT}'", "INFO")
log(f"Method: {METHOD}", "INFO")

wm_bytes = WATERMARK_TEXT.encode('utf-8')
bit_length = len(wm_bytes) * 8
log(f"Payload: {bit_length} bits", "INFO")

encoder = WatermarkEncoder()
encoder.set_watermark('bytes', wm_bytes)
bgr_wm = encoder.encode(bgr, METHOD)

cv2.imwrite(f"{OUTPUT_DIR}/2_watermarked.png", bgr_wm)
log(f"Saved watermarked image → {OUTPUT_DIR}/2_watermarked.png", "OK")

# ─── Step 3: Measure imperceptibility (PSNR + SSIM) ────────────────────────────

print("\n[STEP 3] Measuring imperceptibility...")

psnr = cv2.PSNR(bgr, bgr_wm)
log(f"PSNR: {psnr:.2f} dB  (target: >40 dB = imperceptible)", "OK" if psnr > 40 else "FAIL")

# Compute residual (amplified difference)
diff = cv2.absdiff(bgr, bgr_wm)
diff_amplified = cv2.convertScaleAbs(diff, alpha=20)
cv2.imwrite(f"{OUTPUT_DIR}/3_residual_20x.png", diff_amplified)
log(f"Saved amplified residual → {OUTPUT_DIR}/3_residual_20x.png", "OK")

max_diff = diff.max()
mean_diff = diff.mean()
log(f"Max pixel delta: {max_diff}  |  Mean delta: {mean_diff:.4f}", "INFO")

# ─── Step 4: Simulate img2img attacks ──────────────────────────────────────────

print("\n[STEP 4] Simulating img2img / attack transformations...")

def apply_attack(image, attack_type):
    """Simulate different levels of image transformation."""
    if attack_type == "mild":
        # Slight Gaussian blur — like mild style transfer
        return cv2.GaussianBlur(image, (3, 3), 0.5)

    elif attack_type == "medium":
        # Blur + noise — moderate img2img equivalent
        blurred = cv2.GaussianBlur(image, (5, 5), 1.2)
        noise = np.random.normal(0, 8, image.shape).astype(np.int16)
        return np.clip(blurred.astype(np.int16) + noise, 0, 255).astype(np.uint8)

    elif attack_type == "strong":
        # Heavy blur + strong noise + JPEG compression
        blurred = cv2.GaussianBlur(image, (7, 7), 2.5)
        noise = np.random.normal(0, 20, image.shape).astype(np.int16)
        attacked = np.clip(blurred.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        # Simulate JPEG compression
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 70]
        _, enc = cv2.imencode('.jpg', attacked, encode_param)
        return cv2.imdecode(enc, 1)

    elif attack_type == "jpeg_only":
        # Just JPEG compression
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 85]
        _, enc = cv2.imencode('.jpg', image, encode_param)
        return cv2.imdecode(enc, 1)

attacks = ["mild", "medium", "strong", "jpeg_only"]
attacked_images = {}

for attack in attacks:
    attacked = apply_attack(bgr_wm, attack)
    path = f"{OUTPUT_DIR}/4_attacked_{attack}.png"
    cv2.imwrite(path, attacked)
    attacked_images[attack] = attacked
    log(f"Applied '{attack}' attack → {path}", "OK")

# ─── Step 5: Detect watermark in each attacked image ───────────────────────────

print("\n[STEP 5] Detecting watermark after each attack...")
print(f"  {'ATTACK':<12} {'DETECTED TEXT':<22} {'MATCH':<8} {'CONFIDENCE'}")
print("  " + "─"*60)

decoder = WatermarkDecoder('bytes', bit_length)
results = {}

def decode_watermark(image):
    try:
        decoded_bytes = decoder.decode(image, METHOD)
        text = decoded_bytes.decode('utf-8', errors='replace').rstrip('\x00')
        return text
    except Exception as e:
        return f"[error: {e}]"

# First check on clean watermarked image (baseline)
baseline = decode_watermark(bgr_wm)
baseline_match = baseline == WATERMARK_TEXT
log_line = f"  {'baseline':<12} {baseline:<22} {'✓' if baseline_match else '✗':<8} {'100% (reference)'}"
print(log_line)

# Check each attacked version
for attack, attacked_img in attacked_images.items():
    decoded = decode_watermark(attacked_img)
    match = decoded == WATERMARK_TEXT

    # Simple character-level confidence
    correct_chars = sum(a == b for a, b in zip(decoded, WATERMARK_TEXT))
    confidence = correct_chars / len(WATERMARK_TEXT) * 100 if WATERMARK_TEXT else 0

    results[attack] = {"decoded": decoded, "match": match, "confidence": confidence}
    print(f"  {attack:<12} {decoded:<22} {'✓' if match else '✗':<8} {confidence:.0f}%")

# ─── Step 6: Summary report ─────────────────────────────────────────────────────

print("\n" + "═"*52)
print("  RESULTS SUMMARY")
print("═"*52)
print(f"\n  Original watermark : '{WATERMARK_TEXT}'")
print(f"  Method             : {METHOD}")
print(f"  PSNR               : {psnr:.2f} dB ({'imperceptible ✓' if psnr > 40 else 'visible ✗'})")
print(f"\n  Survival after attacks:")

for attack, r in results.items():
    status = "SURVIVED ✓" if r['match'] else f"DEGRADED  ({r['confidence']:.0f}% chars correct)"
    print(f"    {attack:<14} → {status}")

print(f"\n  Output files saved to: ./{OUTPUT_DIR}/")
print("    1_original.png        — base image")
print("    2_watermarked.png     — with embedded watermark")
print("    3_residual_20x.png    — watermark signal amplified 20×")
print("    4_attacked_*.png      — post-attack versions")
print("\n" + "═"*52 + "\n")
