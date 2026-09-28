import cv2
import numpy as np
import uuid

from app.watermark.core import embed, extract, derive_watermark_seed, estimate_document_threshold
from app.forensics.matcher import match_artifact

def apply_transformations(img: np.ndarray):
    """Yields (name, transformed_image)"""
    yield "Original", img
    
    # 1. JPEG Compression Q95
    _, buf = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
    yield "JPEG Q95", cv2.imdecode(buf, cv2.IMREAD_COLOR)
    
    # 2. JPEG Compression Q75
    _, buf = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
    yield "JPEG Q75", cv2.imdecode(buf, cv2.IMREAD_COLOR)
    
    # 3. JPEG Compression Q50
    _, buf = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
    yield "JPEG Q50", cv2.imdecode(buf, cv2.IMREAD_COLOR)
    
    # 4. Resizing (80%)
    h, w = img.shape[:2]
    resized = cv2.resize(img, (int(w*0.8), int(h*0.8)))
    # We must resize it back to original shape for our watermark extractor to work seamlessly,
    # or the extractor handles scale. Our extractor requires same shape.
    restored = cv2.resize(resized, (w, h))
    yield "Resize 80%", restored
    
    # 5. Cropping (10% margins)
    cropped = img.copy()
    ch, cw = int(h*0.1), int(w*0.1)
    # Fill cropped edges with white
    cropped[:ch, :] = 255
    cropped[-ch:, :] = 255
    cropped[:, :cw] = 255
    cropped[:, -cw:] = 255
    yield "Crop 10% Margins", cropped
    
    # 6. Mild Rotation (1 degree)
    M = cv2.getRotationMatrix2D((w/2, h/2), 1, 1)
    rotated = cv2.warpAffine(img, M, (w, h), borderValue=(255,255,255))
    # Unrotate for extraction (simulating alignment)
    M_inv = cv2.getRotationMatrix2D((w/2, h/2), -1, 1)
    unrotated = cv2.warpAffine(rotated, M_inv, (w, h), borderValue=(255,255,255))
    yield "Rotation 1 deg (Aligned)", unrotated
    
    # 7. Screenshot / Re-encoding simulation (Downsample & slight color shift)
    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    rgb = cv2.convertScaleAbs(rgb, alpha=1.05, beta=-5)
    # resize down and up
    rgb_sm = cv2.resize(rgb, (int(w*0.9), int(h*0.9)))
    rgb_up = cv2.resize(rgb_sm, (w, h))
    bgr = cv2.cvtColor(rgb_up, cv2.COLOR_RGB2BGR)
    yield "Screenshot Sim", bgr
    
    # 8. Print/Scan simulation
    # Add blur, brightness/contrast changes, and slight noise
    blurred = cv2.GaussianBlur(img, (3,3), 0)
    gray = cv2.cvtColor(blurred, cv2.COLOR_BGR2GRAY)
    _, bw = cv2.threshold(gray, 200, 255, cv2.THRESH_TRUNC)
    scan = cv2.cvtColor(bw, cv2.COLOR_GRAY2BGR)
    yield "Print/Scan Sim", scan
    

def main():
    print("==================================================")
    print(" WATERMARK ROBUSTNESS TEST HARNESS")
    print("==================================================")
    
    # Generate test image
    page = np.ones((800, 600, 3), dtype=np.uint8) * 255
    cv2.putText(page, "CONFIDENTIAL", (150, 400), cv2.FONT_HERSHEY_SIMPLEX, 1.5, (0, 0, 0), 2)
    cv2.rectangle(page, (100, 100), (500, 700), (0, 0, 0), 5)
    
    doc_id = "robust_test_doc"
    target_recip = "target_A"
    
    # Setup candidate pool
    recipients = ["target_A", "target_B", "target_C", "target_D", "target_E"]
    pool = {r: derive_watermark_seed(doc_id, r) for r in recipients}
    
    # Embed watermark for target A
    target_seed = pool[target_recip]
    watermarked = embed(page, target_seed, alpha=5.0)
    
    # Evaluate Collusion
    print("\n[+] Testing Transformation Robustness (Target: target_A)")
    print(f"{'Transformation':<30} | {'Result':<10} | {'Best Match':<10}")
    print("-" * 55)
    
    for name, transformed_img in apply_transformations(watermarked):
        # Convert to bytes
        _, buf = cv2.imencode('.png', transformed_img)
        t_bytes = buf.tobytes()
        
        res = match_artifact(t_bytes, pool, absolute_threshold=0.005, relative_margin=0.002)
        status = "PASS" if res.status == "MATCH" and res.best_match_key_id == target_recip else "FAIL"
        
        print(f"{name:<30} | {status:<10} | {res.best_match_key_id if res.best_match_key_id else 'None':<10}")
        
    print("\n[+] Testing Collusion (Multi-recipient Average)")
    # Generate 5 distinct watermarks and average them
    wms = []
    for r in recipients:
        wms.append(embed(page, pool[r], alpha=5.0).astype(np.float32))
        
    avg_img = np.mean(wms, axis=0).astype(np.uint8)
    _, buf = cv2.imencode('.png', avg_img)
    avg_bytes = buf.tobytes()
    
    res = match_artifact(avg_bytes, pool, absolute_threshold=0.005, relative_margin=0.002)
    
    # Expected: FAIL to match anyone individually due to collusion washing out the signal below margin
    status = "PASS (Evasion Detected)" if res.status == "INCONCLUSIVE" else "FAIL"
    print(f"{'Collusion (5 recipients)':<30} | {status:<10} | {res.best_match_key_id if res.best_match_key_id else 'None':<10}")
    print("==================================================")

if __name__ == "__main__":
    main()
