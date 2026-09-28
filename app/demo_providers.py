import cv2
import numpy as np

from app.protocol.interfaces import (
    ManifestProvider, ShareBProvider, DocumentProvider, 
    ReleaseAuthorizer, ControlledPlaintextProcessor
)
from app.watermark.core import embed, derive_watermark_seed, estimate_document_threshold

from app.protocol.errors import RateLimitExceeded
from app.config.settings import settings

class StateAuthorizer(ReleaseAuthorizer):
    def __init__(self, rate_limit_repo=None):
        self.rate_limit_repo = rate_limit_repo

    def authorize(self, *, document_id: str, manifest_id: str, recipient_key_id: str, request_id: str) -> bool:
        if self.rate_limit_repo:
            count = self.rate_limit_repo.count_releases(document_id, recipient_key_id, settings.rate_limit_window_seconds)
            if count >= settings.rate_limit_max_releases:
                raise RateLimitExceeded(f"Rate limit exceeded: max {settings.rate_limit_max_releases} releases per {settings.rate_limit_window_seconds}s")
            self.rate_limit_repo.record_release(document_id, recipient_key_id)
        return True

class StateManifestProvider(ManifestProvider):
    def __init__(self, state):
        self.state = state
    def get_manifest(self, manifest_id: str):
        return self.state.manifests.get(manifest_id)

class StateShareBProvider(ShareBProvider):
    def __init__(self, state):
        self.state = state
    def get_share_b(self, document_id: str, recipient_key_id: str):
        # We store share_b generically by doc_id for dynamic recipients, or specifically by tuple
        if (document_id, recipient_key_id) in self.state.share_bs:
            return self.state.share_bs[(document_id, recipient_key_id)]
        return self.state.share_bs.get(document_id)

class StateDocumentProvider(DocumentProvider):
    def __init__(self, state):
        self.state = state
    def get_document_ciphertext(self, document_id: str):
        if document_id in self.state.documents:
            # state.documents[doc_id] = (ciphertext, nonce, aad, plaintext)
            return self.state.documents[document_id][:3]
        return None

class StatePlaintextProcessor(ControlledPlaintextProcessor):
    def __init__(self, state):
        self.state = state
        
    def process(self, *, document_id: str, session_id: str, recipient_key_id: str, plaintext: bytes, cached_threshold: float | None = None) -> tuple[bytes, float]:
        nparr = np.frombuffer(plaintext, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Uploaded document is not a valid image format for watermarking")
            
        # We need recipient ID. For demo purposes, we can derive it from the session mapping, but actually
        # the architecture states "watermarking is identity-bound". We should ideally pass recipient_id.
        # Since we don't have recipient_id in processor interface, we'll store a side-channel mapping in state for the demo.
        # Or just use the global current_recipient from state if set, else session_id (which isn't deterministic for evasion testing).
        # We will use the currently releasing recipient_id tracked in state.current_recipient.
        
        recip_id = getattr(self.state, "current_recipient", "unknown_recip")
        
        seed = derive_watermark_seed(document_id, recip_id) 
        wm = embed(img, seed, alpha=5.0)
        
        success, buffer = cv2.imencode('.png', wm)
        processed_bytes = buffer.tobytes()
        
        if not hasattr(self.state, "watermarked_images"):
            self.state.watermarked_images = {}
        self.state.watermarked_images[recip_id] = processed_bytes
        
        if cached_threshold is not None:
            return processed_bytes, cached_threshold
            
        thresh = estimate_document_threshold(document_id, img, num_trials=5) # Reduced for faster UI
        return processed_bytes, thresh
