import numpy as np

from app.watermark import derive_watermark_seed, embed, extract


def test_watermark_baseline_correlation():
    # Create a blank "page" (white background with some text-like features)
    h, w = 800, 600
    page_image = np.ones((h, w, 3), dtype=np.uint8) * 255
    # add some black lines to simulate text
    page_image[100:110, 50:550] = 0
    page_image[200:210, 50:550] = 0
    page_image[300:310, 50:400] = 0
    
    # Seeds
    seed_correct = derive_watermark_seed("doc_123", "fingerprint_ABC")
    seed_wrong = derive_watermark_seed("doc_123", "fingerprint_XYZ")
    
    # Embed
    watermarked_image = embed(page_image, seed_correct, alpha=5.0)
    
    # Extract
    score_correct = extract(watermarked_image, seed_correct)
    score_wrong = extract(watermarked_image, seed_wrong)
    
    print(f"\nMeasured Correlation (Correct Seed): {score_correct:.6f}")
    print(f"Measured Correlation (Wrong Seed):   {score_wrong:.6f}")
    
    assert score_correct > 0.10, f"Failed to detect correct watermark, score {score_correct}"
    assert abs(score_wrong) < 0.05, f"False positive detection on wrong seed, score {score_wrong}"
