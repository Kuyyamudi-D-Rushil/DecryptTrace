import pytest
import cv2
import numpy as np
from app.watermark.core import embed, extract

def test_watermark_resilience():
    """
    Test resilience against compression, resize, and crop (screenshot simulation).
    """
    # Generate a dummy image
    img = np.ones((512, 512, 3), dtype=np.uint8) * 128
    
    seed = b"test_recipient_seed_resilience_01"
    
    # 1. Embed watermark
    watermarked = embed(img, seed, alpha=5.0)
    
    # 2. Test JPEG Compression
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 50]
    result, encimg = cv2.imencode('.jpg', watermarked, encode_param)
    compressed = cv2.imdecode(encimg, 1)
    
    score_compressed = extract(compressed, seed)
    assert score_compressed > 0.05, f"Watermark did not survive compression, score: {score_compressed}"
    
    # 3. Test Resize (scaling down and up)
    resized_down = cv2.resize(watermarked, (256, 256))
    resized_up = cv2.resize(resized_down, (512, 512))
    
    score_resized = extract(resized_up, seed)
    assert score_resized > 0.05, f"Watermark did not survive resize, score: {score_resized}"
    
    # 4. Test crop (e.g. screenshot crop, then padded back for correlation)
    # Crop center 400x400
    cropped = watermarked[56:456, 56:456]
    padded = np.ones_like(watermarked) * 128
    padded[56:456, 56:456] = cropped
    
    score_cropped = extract(padded, seed)
    assert score_cropped > 0.03, f"Watermark did not survive crop, score: {score_cropped}"
