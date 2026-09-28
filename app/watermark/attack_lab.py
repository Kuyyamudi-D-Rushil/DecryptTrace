
import cv2
import numpy as np


def attack_jpeg(img: np.ndarray, quality: int) -> np.ndarray:
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
    _, encimg = cv2.imencode('.jpg', img, encode_param)
    decimg = cv2.imdecode(encimg, 1)
    assert decimg is not None, "JPEG decode failed"
    # Ensure shape matches original (RGB/Bayer)
    if len(img.shape) == 2 and len(decimg.shape) == 3:
        decimg = cv2.cvtColor(decimg, cv2.COLOR_BGR2GRAY)
    elif len(img.shape) == 3 and img.shape[2] == 3 and len(decimg.shape) == 3:
        pass # Decoded as BGR (OpenCV default for imdecode with 1)
    return decimg

def attack_resize(img: np.ndarray, scale: float = 0.5) -> np.ndarray:
    """Scale to 50%, then rescale back to native resolution for extraction."""
    h, w = img.shape[:2]
    new_w, new_h = int(w * scale), int(h * scale)
    small = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
    restored = cv2.resize(small, (w, h), interpolation=cv2.INTER_CUBIC)
    return restored

def attack_crop(img: np.ndarray, crop_area_fraction: float = 0.2) -> np.ndarray:
    """Remove a random block constituting crop_area_fraction of the image."""
    h, w = img.shape[:2]
    # To remove 20% area, side length fraction is sqrt(0.2) ~ 0.447
    side_frac = np.sqrt(crop_area_fraction)
    crop_h = int(h * side_frac)
    crop_w = int(w * side_frac)
    
    y = np.random.randint(0, h - crop_h + 1)
    x = np.random.randint(0, w - crop_w + 1)
    
    attacked = img.copy()
    # Replace cropped area with white
    if len(img.shape) == 3:
        attacked[y:y+crop_h, x:x+crop_w] = (255, 255, 255)
    else:
        attacked[y:y+crop_h, x:x+crop_w] = 255
    return attacked

def attack_rotation(img: np.ndarray, max_angle: float = 5.0) -> np.ndarray:
    h, w = img.shape[:2]
    angle = np.random.uniform(-max_angle, max_angle)
    M = cv2.getRotationMatrix2D((w/2, h/2), angle, 1.0)
    # Use borderMode=cv2.BORDER_CONSTANT with white background
    borderValue = (255, 255, 255) if len(img.shape) == 3 else 255
    rotated = cv2.warpAffine(img, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_CONSTANT, borderValue=borderValue)
    return rotated

def attack_grayscale(img: np.ndarray) -> np.ndarray:
    if len(img.shape) == 3 and img.shape[2] == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
        return cv2.cvtColor(gray, cv2.COLOR_GRAY2RGB)
    return img

def attack_binarization(img: np.ndarray) -> np.ndarray:
    if len(img.shape) == 3 and img.shape[2] == 3:
        gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    else:
        gray = img.copy()
    _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    if len(img.shape) == 3 and img.shape[2] == 3:
        return cv2.cvtColor(binary, cv2.COLOR_GRAY2RGB)
    return binary
