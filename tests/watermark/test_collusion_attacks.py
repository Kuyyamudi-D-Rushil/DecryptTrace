import cv2
import numpy as np

from app.watermark.core import derive_watermark_seed, embed, extract, generate_watermark


def generate_clean_page(h=800, w=600):
    page = np.ones((h, w, 3), dtype=np.uint8) * 255
    # Add some text to make it realistic
    for y in range(50, h - 50, 20):
        if np.random.rand() > 0.2:
            page[y:y+10, 50:w-50] = 0
    return page

def test_self_differencing():
    np.random.seed(42)
    clean_img = generate_clean_page()
    seed = derive_watermark_seed("doc1", "recipient1")
    
    # Generate 10 identical requests (same document, same recipient)
    copies = []
    for _ in range(10):
        wm = embed(clean_img, seed, alpha=5.0)
        copies.append(wm)
        
    # Attack: average them
    avg_img = np.mean(copies, axis=0).astype(np.uint8)
    
    # Attack: difference with original
    # Extract the luminance from avg_img and clean_img
    avg_y = cv2.cvtColor(avg_img, cv2.COLOR_RGB2YCrCb)[:, :, 0].astype(np.float32)
    clean_y = cv2.cvtColor(clean_img, cv2.COLOR_RGB2YCrCb)[:, :, 0].astype(np.float32)
    
    est_pattern = avg_y - clean_y
    est_pattern -= np.mean(est_pattern)
    std_est = np.std(est_pattern)
    if std_est > 0:
        est_pattern /= std_est
        
    true_pattern = generate_watermark(clean_y.shape, seed)
    
    # Correlation between estimated pattern and true pattern
    corr_attack = np.mean(est_pattern * true_pattern)
    
    # Single copy correlation
    single_y = cv2.cvtColor(copies[0], cv2.COLOR_RGB2YCrCb)[:, :, 0].astype(np.float32)
    single_est = single_y - clean_y
    single_est -= np.mean(single_est)
    single_est /= np.std(single_est)
    corr_single = np.mean(single_est * true_pattern)
    
    print("\n--- Self-Differencing Attack ---")
    print(f"Single copy estimated correlation with true: {corr_single:.6f}")
    print(f"Averaged (10) copy estimated correlation with true: {corr_attack:.6f}")
    
    # Does averaging strengthen it?
    assert corr_attack <= corr_single + 0.01, "Self-differencing shouldn't leak more info than a single copy due to determinism"


def test_collusion():
    clean_img = generate_clean_page()
    threshold = 0.011012
    
    print("\n--- Collusion Attack ---")
    print(f"Using exact document threshold: {threshold:.6f}")
    
    for N in [5, 10, 15, 20, 25]:
        np.random.seed(43 + N)
        seeds_used = [derive_watermark_seed("doc1", f"recipient{i}") for i in range(N)]
        copies = [embed(clean_img, s, alpha=5.0) for s in seeds_used]
        avg_img = np.mean(copies, axis=0).astype(np.uint8)
        
        seeds_unused = [derive_watermark_seed("doc1", f"stranger{i}") for i in range(10)]
        scores_unused = [extract(avg_img, s) for s in seeds_unused]
        max_unused = np.max(scores_unused)
        
        print(f"N={N:2d} colluders | Max Unused Score: {max_unused:.6f} | Crosses threshold? {max_unused >= threshold}")
        
        # Test confirms it doesn't cross threshold
        assert max_unused < threshold, f"False positive occurred at N={N}"
