import numpy as np

from app.watermark.attack_lab import (
    attack_binarization,
    attack_crop,
    attack_grayscale,
    attack_jpeg,
    attack_resize,
    attack_rotation,
)
from app.watermark.core import derive_watermark_seed, embed, extract

# Threshold derived from docs/phase4_watermark_thresholds.md baseline pilot:
# Null Mean: 0.000700, Null Std: 0.002914
# Target: +4.75 std -> 0.0145
DETECTION_THRESHOLD = 0.0145

def generate_random_page(h=800, w=600):
    page = np.ones((h, w, 3), dtype=np.uint8) * 255
    for _ in range(np.random.randint(5, 20)):
        y = np.random.randint(50, h - 50)
        x1 = np.random.randint(20, 100)
        x2 = np.random.randint(w//2, w - 20)
        thickness = np.random.randint(8, 15)
        page[y:y+thickness, x1:x2] = (0, 0, 0)
    return page

def run_attack_trials(attack_fn, name: str, num_trials: int = 50):
    scores = []
    np.random.seed(42) # deterministic pseudo-random for tests
    for i in range(num_trials):
        page = generate_random_page()
        seed = derive_watermark_seed(f"doc_{name}_{i}", f"fp_{name}_{i}")
        wm_img = embed(page, seed, alpha=5.0)
        
        attacked_img = attack_fn(wm_img)
        
        score = extract(attacked_img, seed)
        scores.append(score)
        
    scores_arr = np.array(scores)
    mean_val = np.mean(scores_arr)
    std_val = np.std(scores_arr)
    min_val = np.min(scores_arr)
    max_val = np.max(scores_arr)
    pass_rate = np.mean(scores_arr > DETECTION_THRESHOLD) * 100.0
    
    print(f"| {name.ljust(15)} | {mean_val:8.6f} | {std_val:8.6f} | {min_val:8.6f} | {max_val:8.6f} | {pass_rate:6.1f}% |")

def test_run_attack_lab():
    print("\n")
    print("| Transformation  | Mean     | Std      | Min      | Max      | Pass%  |")
    print("|:----------------|:---------|:---------|:---------|:---------|:-------|")
    
    run_attack_trials(lambda img: attack_jpeg(img, 95), "JPEG 95")
    run_attack_trials(lambda img: attack_jpeg(img, 80), "JPEG 80")
    run_attack_trials(lambda img: attack_jpeg(img, 60), "JPEG 60")
    run_attack_trials(lambda img: attack_jpeg(img, 40), "JPEG 40")
    run_attack_trials(lambda img: attack_resize(img, 0.5), "Resize (50%)")
    run_attack_trials(lambda img: attack_crop(img, 0.2), "Crop (20%)")
    run_attack_trials(lambda img: attack_rotation(img, 5.0), "Rotation")
    run_attack_trials(lambda img: attack_grayscale(img), "Grayscale")
    run_attack_trials(lambda img: attack_binarization(img), "Binarization")
