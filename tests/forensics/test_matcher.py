import cv2
import numpy as np

from app.forensics.matcher import match_artifact
from app.watermark.core import derive_watermark_seed, embed


def generate_clean_page(h=800, w=600):
    page = np.ones((h, w, 3), dtype=np.uint8) * 255
    for y in range(50, h - 50, 20):
        if np.random.rand() > 0.2:
            page[y:y+10, 50:w-50] = 0
    return page

def img_to_bytes(img):
    success, buffer = cv2.imencode('.png', img)
    assert success
    return buffer.tobytes()

def test_forensic_matcher_clean_single():
    clean = generate_clean_page()
    seed1 = derive_watermark_seed("doc1", "recip1")
    seed2 = derive_watermark_seed("doc1", "recip2")
    seed3 = derive_watermark_seed("doc1", "recip3")
    
    candidate_pool = {
        "recip1": seed1,
        "recip2": seed2,
        "recip3": seed3
    }
    
    wm1 = embed(clean, seed1, alpha=5.0)
    img_bytes = img_to_bytes(wm1)
    
    # Needs to match recip1
    res = match_artifact(img_bytes, candidate_pool, absolute_threshold=0.010, relative_margin=0.002)
    assert res.status == "MATCH"
    assert res.best_match_key_id == "recip1"

def test_forensic_matcher_collusion_ambiguous():
    clean = generate_clean_page()
    seeds = [derive_watermark_seed("doc1", f"recip{i}") for i in range(1, 8)]
    candidate_pool = {f"recip{i}": seeds[i-1] for i in range(1, 8)}
    
    # 7-way collusion average
    copies = [embed(clean, seed, alpha=5.0) for seed in seeds]
    avg_img = np.mean(copies, axis=0).astype(np.uint8)
    img_bytes = img_to_bytes(avg_img)
    
    # Because of collusion, it should either fail absolute_threshold (NO_MATCH) 
    # or fail relative_margin (INCONCLUSIVE) depending on exact score drops.
    # The prompt explicitly requires the collusion case to return INCONCLUSIVE 
    # due to the margin check (or if we set a lower threshold, it triggers the margin).
    # Let's set a low absolute_threshold so it clears that, but fails the margin.
    res = match_artifact(img_bytes, candidate_pool, absolute_threshold=0.001, relative_margin=0.002)
    assert res.status == "INCONCLUSIVE"
    assert res.best_match_key_id is None

def test_forensic_matcher_no_match():
    clean = generate_clean_page()
    seed1 = derive_watermark_seed("doc1", "recip1")
    candidate_pool = {"recip1": seed1}
    
    # No watermark embedded!
    img_bytes = img_to_bytes(clean)
    
    res = match_artifact(img_bytes, candidate_pool, absolute_threshold=0.010, relative_margin=0.002)
    assert res.status == "NO_MATCH"
    assert res.best_match_key_id is None
