import cv2
from imwatermark import WatermarkDecoder

decoder = WatermarkDecoder('bytes', 120)
img = cv2.imread("watermark_output(DCT)/5_img2img_result.png")
decoded = decoder.decode(img, 'dwtDctSvd')
text = decoded.decode('utf-8', errors='replace').rstrip('\x00')

print(f"Decoded: '{text}'")
print(f"Match: {'✓ WATERMARK SURVIVED' if text == 'mywatermark2026' else '✗ Not detected'}")