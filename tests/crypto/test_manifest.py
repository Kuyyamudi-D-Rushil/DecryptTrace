import pytest

from app.crypto.errors import SignatureVerificationError
from app.crypto.manifest import (
    CryptoManifest,
    manifest_digest,
    sign_manifest,
    verify_manifest,
)
from app.crypto.signatures import SignatureWrapper


@pytest.fixture
def sample_manifest():
    return CryptoManifest(
        protocol_version="1.0",
        document_id="doc_123",
        encryption_algorithm="AES-GCM-256",
        encryption_version="1.0",
        kem_algorithm="ML-KEM-768",
        kem_version="1.0",
        signature_algorithm="ML-DSA-65",
        signature_version="1.0",
        ciphertext_hash="hash_abc",
        recipient_share_reference="share_ref_1",
        sender_identity_reference="sender_1",
        manifest_id="manifest_123",
        creation_timestamp="2026-01-01T00:00:00Z"
    )

def test_manifest_digest_deterministic(sample_manifest):
    digest1 = manifest_digest(sample_manifest)
    digest2 = manifest_digest(sample_manifest)
    assert digest1 == digest2

def test_manifest_signing(sample_manifest):
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    signature = sign_manifest(sample_manifest, sk, "ML-DSA-65")
    assert verify_manifest(sample_manifest, signature, pk, "ML-DSA-65")

def test_manifest_signing_modified_manifest(sample_manifest):
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    signature = sign_manifest(sample_manifest, sk, "ML-DSA-65")
    
    # Tamper with the manifest
    sample_manifest.document_id = "doc_999"
    
    with pytest.raises(SignatureVerificationError):
        verify_manifest(sample_manifest, signature, pk, "ML-DSA-65")
