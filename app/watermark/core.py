import cv2
import numpy as np

from app.config.settings import settings
from app.crypto.kdf import derive_key


def derive_watermark_seed(document_id: str, fingerprint_id: str) -> bytes:
    # Use Authority-controlled key from config
    # In a real deployment, this would be loaded strictly from settings.
    k_wm = getattr(settings, "watermark_secret_key_hex", "00" * 32)
    if not k_wm:
        k_wm = "00" * 32
    k_wm_bytes = bytes.fromhex(k_wm)
        
    info = f"DecryptTrace/watermark/v1|{document_id}|{fingerprint_id}".encode()
    return derive_key(k_wm_bytes, None, info, 32)

def generate_watermark(shape: tuple[int, int], seed: bytes, tile_size: int = 128) -> np.ndarray:
    h, w = shape
    # Use seed to generate pseudo-random pattern
    seed_int = int.from_bytes(seed[:4], byteorder="little")
    np.random.seed(seed_int)
    
    # 1. Spread-spectrum noise (tiled for redundancy)
    pattern = np.random.randn(tile_size, tile_size)
    pattern -= np.mean(pattern)
    pattern /= np.std(pattern)
    
    tiled_h = (h // tile_size) + 1
    tiled_w = (w // tile_size) + 1
    tiled_noise = np.tile(pattern, (tiled_h, tiled_w))[:h, :w]
    
    # 2. Periodic synchronization component
    # A simple 2D sinusoidal grid that provides strong peaks in frequency domain
    y, x = np.mgrid[0:h, 0:w]
    fx = 20.0 / w
    fy = 20.0 / h
    sync_grid = np.sin(2 * np.pi * fx * x) + np.sin(2 * np.pi * fy * y)
    sync_grid -= np.mean(sync_grid)
    sync_grid /= np.std(sync_grid)
    
    # Combine noise and sync grid
    watermark = tiled_noise + 0.5 * sync_grid
    watermark -= np.mean(watermark)
    watermark /= np.std(watermark)
    
    return watermark

def embed(page_image: np.ndarray, seed: bytes, alpha: float = 3.0) -> np.ndarray:
    """
    Embed watermark into the luminance channel of the image.
    page_image should be an RGB or Grayscale uint8 numpy array.
    """
    is_rgb = len(page_image.shape) == 3 and page_image.shape[2] == 3
    
    if is_rgb:
        ycbcr = cv2.cvtColor(page_image, cv2.COLOR_RGB2YCrCb)
        Y = ycbcr[:, :, 0].astype(np.float32)
    else:
        Y = page_image.astype(np.float32)
        
    watermark = generate_watermark(Y.shape, seed)
    
    Y_watermarked = Y + alpha * watermark
    Y_watermarked = np.clip(Y_watermarked, 0, 255).astype(np.uint8)
    
    if is_rgb:
        ycbcr[:, :, 0] = Y_watermarked
        return cv2.cvtColor(ycbcr, cv2.COLOR_YCrCb2RGB)
    else:
        return Y_watermarked

def align_image(candidate_residual: np.ndarray, expected_watermark: np.ndarray) -> np.ndarray:
    """
    Use the periodic synchronization component to estimate and correct rotation/scale.
    """
    h, w = candidate_residual.shape
    center = (w // 2, h // 2)
    
    # 1. Brute-force rotation search (-5 to +5 degrees)
    best_score = -float('inf')
    best_aligned = candidate_residual
    
    expected_norm = expected_watermark - np.mean(expected_watermark)
    
    angles = np.arange(-5.0, 5.5, 0.5)
    for angle in angles:
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        rotated_residual = cv2.warpAffine(candidate_residual, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
        
        rotated_norm = rotated_residual - np.mean(rotated_residual)
        score = np.sum(rotated_norm * expected_norm)
        
        if score > best_score:
            best_score = score
            best_aligned = rotated_residual
            
    aligned_residual = best_aligned
    
    # Optional translation alignment (spatial phase correlation)
    shift2, response2 = cv2.phaseCorrelate(aligned_residual.astype(np.float32), expected_watermark.astype(np.float32))
    dx, dy = shift2
    if response2 > 0.05:
        M_trans = np.array([[1, 0, -dx], [0, 1, -dy]], dtype=np.float32)
        aligned_residual = cv2.warpAffine(aligned_residual, M_trans, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
        
    return aligned_residual

def extract(candidate_image: np.ndarray, seed: bytes) -> float:
    """
    Extract the watermark and return a correlation score [-1.0, 1.0].
    """
    is_rgb = len(candidate_image.shape) == 3 and candidate_image.shape[2] == 3
    if is_rgb:
        ycbcr = cv2.cvtColor(candidate_image, cv2.COLOR_RGB2YCrCb)
        Y = ycbcr[:, :, 0].astype(np.float32)
    else:
        Y = candidate_image.astype(np.float32)
        
    # High-pass filter to extract noise residual (Wiener filter approximation)
    blurred = cv2.GaussianBlur(Y, (5, 5), 0)
    residual = Y - blurred
    
    expected_watermark = generate_watermark(Y.shape, seed)
    
    # Align the candidate residual using the synchronization component
    aligned_residual = align_image(residual, expected_watermark)
    
    # Normalized Correlation
    aligned_residual -= np.mean(aligned_residual)
    expected_watermark -= np.mean(expected_watermark)
    
    std_res = np.std(aligned_residual)
    std_wm = np.std(expected_watermark)
    
    if std_res < 1e-6 or std_wm < 1e-6:
        return 0.0
        
    nc = np.mean(aligned_residual * expected_watermark) / (std_res * std_wm)
    return float(nc)


_threshold_cache: dict[str, float] = {}

def estimate_document_threshold(document_id: str, page_image: np.ndarray, num_trials: int = 100) -> float:
    """
    Estimates the null-distribution for a specific document page using wrong-seed extractions
    to derive an adaptive detection threshold. Caches the result per document_id.
    """
    if document_id in _threshold_cache:
        return _threshold_cache[document_id]

    import time
    start_t = time.perf_counter()

    scores = []
    # Use deterministic wrong seeds relative to the document content, but independent of correct seed
    for i in range(num_trials):
        wrong_seed = derive_watermark_seed(f"adaptive_thresh_{document_id}_doc_{i}", f"adaptive_thresh_{document_id}_fp_{i}")
        # Extract looking for the wrong seed
        score = extract(page_image, wrong_seed)
        scores.append(score)
        
    scores_arr = np.array(scores)
    mean_val = float(np.mean(scores_arr))
    std_val = float(np.std(scores_arr))
    
    # 4.75 std corresponds to roughly p < 10^-6 (provisional, pending EVT calibration)
    threshold = mean_val + 4.75 * std_val
    
    _threshold_cache[document_id] = float(threshold)
    
    end_t = time.perf_counter()
    print(f"DEBUG: estimate_document_threshold took {end_t - start_t:.3f}s for {num_trials} trials")
    
    return float(threshold)
