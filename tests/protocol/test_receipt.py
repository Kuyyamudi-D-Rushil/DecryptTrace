from datetime import datetime, timezone

import pytest

from app.crypto.errors import SignatureVerificationError
from app.crypto.signatures import SignatureWrapper
from app.protocol.receipt import RecipientReceipt


@pytest.fixture
def recipient_keypair():
    wrapper = SignatureWrapper("ML-DSA-65")
    return wrapper.generate_keypair()

def test_receipt_construction_and_defaults():
    receipt = RecipientReceipt(
        receipt_id="rec_123",
        release_id="rel_456",
        document_id="doc_789",
        recipient_key_id="key_abc",
        session_id="sess_def",
        artifact_hash_hex="a1b2c3d4",
        detection_threshold=0.011012,
        fingerprint_commitment="commit_hash",
        fingerprint_commitment_salt="salt_123",
        timestamp=datetime.now(timezone.utc).isoformat(),
        receipt_version="1.0"
    )
    # Check default
    assert receipt.fpr_methodology_status == "provisional"
    assert receipt.signature_hex is None

def test_receipt_signing_and_verification(recipient_keypair):
    public_key, secret_key = recipient_keypair
    
    receipt = RecipientReceipt(
        receipt_id="rec_123",
        release_id="rel_456",
        document_id="doc_789",
        recipient_key_id="key_abc",
        session_id="sess_def",
        artifact_hash_hex="a1b2c3d4",
        detection_threshold=0.011012,
        fingerprint_commitment="commit_hash",
        fingerprint_commitment_salt="salt_123",
        timestamp="2026-09-23T00:00:00Z",
        receipt_version="1.0"
    )
    
    # Sign
    receipt.sign(secret_key)
    assert receipt.signature_hex is not None
    
    # Verify
    assert receipt.verify(public_key) is True

def test_receipt_canonical_serialization_round_trip(recipient_keypair):
    public_key, secret_key = recipient_keypair
    
    receipt = RecipientReceipt(
        receipt_id="rec_123",
        release_id="rel_456",
        document_id="doc_789",
        recipient_key_id="key_abc",
        session_id="sess_def",
        artifact_hash_hex="a1b2c3d4",
        detection_threshold=0.011012,
        fingerprint_commitment="commit_hash",
        fingerprint_commitment_salt="salt_123",
        timestamp="2026-09-23T00:00:00Z",
        receipt_version="1.0",
        fpr_methodology_status="provisional"
    )
    receipt.sign(secret_key)
    
    # Serialize to dict and back
    serialized = receipt.model_dump(mode="json")
    reconstructed = RecipientReceipt(**serialized)
    
    # Should still verify
    assert reconstructed.verify(public_key) is True

def test_receipt_tampering(recipient_keypair):
    public_key, secret_key = recipient_keypair
    
    receipt = RecipientReceipt(
        receipt_id="rec_123",
        release_id="rel_456",
        document_id="doc_789",
        recipient_key_id="key_abc",
        session_id="sess_def",
        artifact_hash_hex="a1b2c3d4",
        detection_threshold=0.011012,
        fingerprint_commitment="commit_hash",
        fingerprint_commitment_salt="salt_123",
        timestamp="2026-09-23T00:00:00Z",
        receipt_version="1.0"
    )
    receipt.sign(secret_key)
    
    # Tamper with document_id
    receipt.document_id = "doc_999"
    with pytest.raises(SignatureVerificationError):
        receipt.verify(public_key)
        
    # Reset
    receipt.document_id = "doc_789"
    assert receipt.verify(public_key) is True
    
    # Tamper with threshold
    receipt.detection_threshold = 0.005
    with pytest.raises(SignatureVerificationError):
        receipt.verify(public_key)

def test_unsigned_receipt_verify_fails(recipient_keypair):
    public_key, _ = recipient_keypair
    
    receipt = RecipientReceipt(
        receipt_id="rec_123",
        release_id="rel_456",
        document_id="doc_789",
        recipient_key_id="key_abc",
        session_id="sess_def",
        artifact_hash_hex="a1b2c3d4",
        detection_threshold=0.011012,
        fingerprint_commitment="commit_hash",
        fingerprint_commitment_salt="salt_123",
        timestamp="2026-09-23T00:00:00Z",
        receipt_version="1.0"
    )
    
    with pytest.raises(ValueError, match="Receipt is not signed"):
        receipt.verify(public_key)
