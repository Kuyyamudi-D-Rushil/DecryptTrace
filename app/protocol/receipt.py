from typing import Literal

from pydantic import BaseModel

from app.crypto.signatures import SignatureWrapper
from app.protocol.serialization import canonicalize_for_signing


class RecipientReceipt(BaseModel):
    receipt_id: str
    release_id: str
    document_id: str
    recipient_key_id: str
    session_id: str
    artifact_hash_hex: str
    detection_threshold: float
    fingerprint_commitment: str
    fingerprint_commitment_salt: str
    timestamp: str
    receipt_version: str
    fpr_methodology_status: Literal["provisional", "final"] = "provisional"
    signature_hex: str | None = None

    def sign(self, secret_key: bytes, algorithm: str = "ML-DSA-65") -> None:
        """
        Canonicalizes the receipt, signs it with the provided ML-DSA secret key,
        and populates the signature_hex field.
        """
        canonical_bytes = canonicalize_for_signing(self)
        wrapper = SignatureWrapper(algorithm)
        context = b"DecryptTrace/RecipientReceipt/v1"
        signature = wrapper.sign(canonical_bytes, secret_key, context)
        self.signature_hex = signature.hex()

    def verify(self, public_key: bytes, algorithm: str = "ML-DSA-65") -> bool:
        """
        Verifies the signature on the receipt using the provided public key.
        """
        if not self.signature_hex:
            raise ValueError("Receipt is not signed.")
        
        canonical_bytes = canonicalize_for_signing(self)
        wrapper = SignatureWrapper(algorithm)
        context = b"DecryptTrace/RecipientReceipt/v1"
        return wrapper.verify(canonical_bytes, bytes.fromhex(self.signature_hex), public_key, context)
