"""
Imperceptible Watermarking Pipeline - rivaGan Method
=====================================================
More robust than dwtDctSvd — uses a neural encoder
trained to survive image transformations.

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

WATERMARK_TEXT = "mywatermark2026"
INPUT_IMAGE    = "chatgpt_image.png"
OUTPUT_DIR     = "watermark_output_riva"
METHOD         = "rivaGan"               # more robust neural method

# rivaGan supports exactly 32 bits (4 characters)
# So we use a short 4-char code instead of full text
WATERMARK_CODE = "W026"                  # 4 chars = 32 bits exactly

# ─── Setup ─────────────────────────────────────────────────────────────────────

os.makedirs(OUTPUT_DIR, exist_ok=True)

def log(msg, status="INFO"):
    icons = {"INFO": "·", "OK": "✓", "FAIL": "✗", "STEP": "▶"}
    print(f"  {icons.get(status,'·')} {msg}")

# ─── Step 1: Load image ─────────────────────────────────────────────────────────

print("\n" + "═"*52)
print("  RIVAGAN WATERMARKING PIPELINE")
print("═"*52)

print("\n[STEP 1] Loading image...")

# Try to load user image, fall back to generating one
if not os.path.exists(INPUT_IMAGE):
    log(f"'{INPUT_IMAGE}' not found — generating sample image...", "INFO")
    img = np.zeros((512, 512, 3), dtype=np.uint8)
    for y in range(200):
        t = y / 200
        img[y, :] = [int(135 + t*50), int(180 + t*30), int(220 - t*20)]
    img[200:, :] = [34, 100, 60]
    cv2.circle(img, (380, 80), 50, (50, 200, 255), -1)
    pts = np.array([[0,300],[80,200],[160,260],[240,180],[320,250],[400,190],[512,300],[512,512],[0,512]])
    cv2.fillPoly(img, [pts], (60, 80, 70))
    cv2.imwrite(INPUT_IMAGE, img)
    log(f"Generated sample image → {INPUT_IMAGE}", "OK")

bgr = cv2.imread(INPUT_IMAGE)
if bgr is None:
    log(f"Could not load '{INPUT_IMAGE}'. Check the path.", "FAIL")
    sys.exit(1)

h, w = bgr.shape[:2]
log(f"Loaded: {INPUT_IMAGE} ({w}×{h}px)", "OK")
cv2.imwrite(f"{OUTPUT_DIR}/1_original.png", bgr)

# ─── Step 2: Embed watermark ────────────────────────────────────────────────────

print("\n[STEP 2] Embedding watermark...")
log(f"Code: '{WATERMARK_CODE}' (32-bit rivaGan payload)", "INFO")
log(f"Method: {METHOD}", "INFO")

wm_bytes = WATERMARK_CODE.encode('utf-8')

encoder = WatermarkEncoder()
encoder.set_watermark('bytes', wm_bytes)

try:
    bgr_wm = encoder.encode(bgr, METHOD)
    log("Watermark embedded successfully", "OK")
except Exception as e:
    log(f"rivaGan failed: {e}", "FAIL")
    log("Falling back to dwtDctSvd...", "INFO")
    METHOD = "dwtDctSvd"
    WATERMARK_CODE = WATERMARK_TEXT
    wm_bytes = WATERMARK_CODE.encode('utf-8')
    encoder.set_watermark('bytes', wm_bytes)
    bgr_wm = encoder.encode(bgr, METHOD)
    log("Embedded with dwtDctSvd fallback", "OK")

cv2.imwrite(f"{OUTPUT_DIR}/2_watermarked.png", bgr_wm)
log(f"Saved → {OUTPUT_DIR}/2_watermarked.png", "OK")

# ─── Step 3: Measure imperceptibility ──────────────────────────────────────────

print("\n[STEP 3] Measuring imperceptibility...")

psnr = cv2.PSNR(bgr, bgr_wm)
log(f"PSNR: {psnr:.2f} dB  ({'imperceptible ✓' if psnr > 40 else 'slightly visible — still usable'})", 
    "OK" if psnr > 40 else "INFO")

diff = cv2.absdiff(bgr, bgr_wm)
diff_amplified = cv2.convertScaleAbs(diff, alpha=20)
cv2.imwrite(f"{OUTPUT_DIR}/3_residual_20x.png", diff_amplified)
log(f"Saved residual → {OUTPUT_DIR}/3_residual_20x.png", "OK")
log(f"Max pixel delta: {diff.max()}  |  Mean delta: {diff.mean():.4f}", "INFO")

# ─── Step 4: Baseline detection check ──────────────────────────────────────────

print("\n[STEP 4] Baseline detection check...")

bit_length = len(wm_bytes) * 8
decoder = WatermarkDecoder('bytes', bit_length)

def decode_watermark(image):
    try:
        decoded_bytes = decoder.decode(image, METHOD)
        return decoded_bytes.decode('utf-8', errors='replace').rstrip('\x00')
    except Exception as e:
        return f"[error: {e}]"

baseline = decode_watermark(bgr_wm)
match = baseline == WATERMARK_CODE
log(f"Decoded: '{baseline}'", "OK" if match else "FAIL")
log(f"Match: {'✓ Watermark detected!' if match else '✗ Baseline detection failed'}", 
    "OK" if match else "FAIL")

# ─── Step 5: Detect in img2img result ──────────────────────────────────────────

print("\n[STEP 5] Detecting watermark in img2img result...")

img2img_path = "5_img2img_result.png"

if os.path.exists(img2img_path):
    img2img = cv2.imread(img2img_path)
    decoded = decode_watermark(img2img)
    match_i2i = decoded == WATERMARK_CODE
    log(f"Decoded from img2img: '{decoded}'", "OK" if match_i2i else "FAIL")
    log(f"Match: {'✓ WATERMARK SURVIVED img2img!' if match_i2i else '✗ Watermark did not survive'}", 
        "OK" if match_i2i else "FAIL")
else:
    log("No img2img result found yet.", "INFO")
    log("After running your img2img tool, save the output as:", "INFO")
    log(f"  5_img2img_result.png  (in this same folder)", "INFO")
    log("Then run this script again to check detection.", "INFO")

# ─── Summary ────────────────────────────────────────────────────────────────────

print("\n" + "═"*52)
print("  SUMMARY")
print("═"*52)
print(f"\n  Watermark code : '{WATERMARK_CODE}'")
print(f"  Method         : {METHOD}")
print(f"  PSNR           : {psnr:.2f} dB")
print(f"  Baseline det.  : {'✓ Detected' if match else '✗ Failed'}")
print(f"\n  Output files → ./{OUTPUT_DIR}/")
print("    1_original.png       — base image")
print("    2_watermarked.png    — embed this into your img2img tool")
print("    3_residual_20x.png   — watermark signal amplified 20x")
print("\n  Next step:")
print("    1. Upload 2_watermarked.png to your img2img tool (Dezgo etc)")
print("    2. Save result as 5_img2img_result.png in this folder")
print("    3. Run this script again to check if watermark survived")
print("\n" + "═"*52 + "\n")