import typing

import numpy as np

from app.watermark.core import extract


class MatchResult(typing.NamedTuple):
    status: str
    best_match_key_id: str | None
    scores: dict[str, float]

def match_artifact(
    candidate_image_bytes: bytes, 
    candidate_pool: dict[str, bytes], 
    absolute_threshold: float = 0.011,
    relative_margin: float = 0.002
) -> MatchResult:
    """
    Forensic Matcher implementing relative-ranking-with-margin security control.
    
    candidate_pool: mapping of recipient_key_id -> watermark_seed
    """
    import cv2
    nparr = np.frombuffer(candidate_image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid image bytes")
        
    scores = {}
    for key_id, seed in candidate_pool.items():
        score = extract(img, seed)
        scores[key_id] = score
        
    if not scores:
        return MatchResult("INCONCLUSIVE", None, scores)
        
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_id, best_score = sorted_scores[0]
    
    # 1. Must clear absolute threshold
    if best_score < absolute_threshold:
        return MatchResult("NO_MATCH", None, scores)
        
    # 2. Must clear relative margin over second best
    if len(sorted_scores) > 1:
        _, second_best_score = sorted_scores[1]
        if (best_score - second_best_score) < relative_margin:
            return MatchResult("INCONCLUSIVE", None, scores)
            
    return MatchResult("MATCH", best_id, scores)
