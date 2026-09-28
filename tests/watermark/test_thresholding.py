import numpy as np

from app.watermark import (
    derive_watermark_seed,
    embed,
    estimate_document_threshold,
    extract,
)


def generate_receipt(h=1000, w=300):
    page = np.ones((h, w, 3), dtype=np.uint8) * 255
    # Add many rows of text
    for y in range(50, h - 50, 15):
        if np.random.rand() > 0.2:
            page[y:y+8, 20:w-20] = 0
    return page

def test_adaptive_threshold_held_out():
    # Generate the held-out document type
    page = generate_receipt()
    
    # Estimate its specific threshold
    threshold = estimate_document_threshold("held_out_doc", page)
    
    print(f"\nHeld-out document estimated threshold: {threshold:.6f}")
    
    # Now validate it against 50 real wrong-seed extractions
    np.random.seed(99)
    scores = []
    for i in range(50):
        seed_embed = derive_watermark_seed(f"doc_ho_{i}", f"fp_embed_ho_{i}")
        seed_extract = derive_watermark_seed(f"doc_ho_{i}", f"fp_wrong_ho_{i}")
        
        wm_img = embed(page, seed_embed, alpha=5.0)
        score = extract(wm_img, seed_extract)
        scores.append(score)
        
    scores_arr = np.array(scores)
    max_null = np.max(scores_arr)
    mean_null = np.mean(scores_arr)
    std_null = np.std(scores_arr)
    
    print(f"Validation Null Mean: {mean_null:.6f}")
    print(f"Validation Null Std : {std_null:.6f}")
    print(f"Validation Null Max : {max_null:.6f}")
    
    # Also check if a correct seed passes this threshold
    seed_correct = derive_watermark_seed("doc_correct", "fp_correct")
    wm_img = embed(page, seed_correct, alpha=5.0)
    score_correct = extract(wm_img, seed_correct)
    
    print(f"Correct Seed Score  : {score_correct:.6f}")
    
    assert max_null < threshold, "False positive occurred on held-out document!"
    assert score_correct > threshold, "False negative occurred on held-out document!"
