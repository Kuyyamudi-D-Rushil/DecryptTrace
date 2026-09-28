import hashlib

from pydantic import BaseModel

from .canonical import canonical_serialize
from .signatures import SignatureWrapper

MANIFEST_SIGNATURE_CONTEXT = b"DecryptTrace/SenderManifest/v1"

class CryptoManifest(BaseModel):
    protocol_version: str
    document_id: str
    encryption_algorithm: str
    encryption_version: str
    kem_algorithm: str
    kem_version: str
    signature_algorithm: str
    signature_version: str
    ciphertext_hash: str
    recipient_share_reference: str
    sender_identity_reference: str
    manifest_id: str
    creation_timestamp: str

def manifest_digest(manifest: CryptoManifest) -> bytes:
    canonical_bytes = canonical_serialize(manifest.model_dump())
    hasher = hashlib.sha256()
    hasher.update(canonical_bytes)
    return hasher.digest()

def sign_manifest(manifest: CryptoManifest, secret_key: bytes, algorithm: str) -> bytes:
    canonical_bytes = canonical_serialize(manifest.model_dump())
    signer = SignatureWrapper(algorithm)
    return signer.sign(canonical_bytes, secret_key, MANIFEST_SIGNATURE_CONTEXT)

def verify_manifest(manifest: CryptoManifest, signature: bytes, public_key: bytes, algorithm: str) -> bool:
    canonical_bytes = canonical_serialize(manifest.model_dump())
    verifier = SignatureWrapper(algorithm)
    return verifier.verify(canonical_bytes, signature, public_key, MANIFEST_SIGNATURE_CONTEXT)
