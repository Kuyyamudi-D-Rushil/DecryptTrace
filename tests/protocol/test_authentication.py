
import pytest

from app.crypto.signatures import SignatureWrapper
from app.protocol.authentication import AUTH_CONTEXT, ChallengeManager
from app.protocol.errors import AuthenticationError
from app.protocol.serialization import canonicalize_for_signing


@pytest.fixture
def keys():
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    return pk, sk

@pytest.fixture
def manager(challenge_repository):
    return ChallengeManager(repository=challenge_repository, expiration_seconds=60)

from app.protocol.models import ReleaseRequest


def create_mock_request(challenge, auth_signature_hex=""):
    return ReleaseRequest(
        request_id=challenge.request_id,
        document_id="doc1",
        manifest_id="man1",
        recipient_key_id=challenge.recipient_key_id,
        challenge_id=challenge.nonce_hex,
        auth_signature_hex=auth_signature_hex,
        share_a_hex="00" * 32,
        protocol_version="1.0"
    )

def test_auth_valid_challenge_response(manager, keys):
    pk, sk = keys
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, sk, AUTH_CONTEXT).hex()
    
    assert manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65") is True

def test_auth_wrong_signing_key(manager, keys):
    pk, _ = keys
    sig = SignatureWrapper("ML-DSA-65")
    _, wrong_sk = sig.generate_keypair()
    
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    request.auth_signature_hex = sig.sign(canonical_bytes, wrong_sk, AUTH_CONTEXT).hex()
    
    with pytest.raises(AuthenticationError):
        manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65")

def test_auth_expired_challenge(manager, keys):
    pk, sk = keys
    manager.expiration_seconds = -10
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, sk, AUTH_CONTEXT).hex()
    
    with pytest.raises(AuthenticationError, match="expired"):
        manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65")

def test_auth_replayed_challenge(manager, keys):
    pk, sk = keys
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, sk, AUTH_CONTEXT).hex()
    
    assert manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65") is True
    
    with pytest.raises(AuthenticationError, match="consumed"):
        manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65")

def test_auth_modified_challenge(manager, keys):
    pk, sk = keys
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, sk, AUTH_CONTEXT).hex()
    
    # Modify request after signing
    request.request_id = "req2"
    
    with pytest.raises(AuthenticationError, match="Request identifiers do not match challenge"):
        manager.verify_request_authentication(request, challenge, pk, "ML-DSA-65")

def test_auth_replay_after_restart(challenge_repository, keys):
    pk, sk = keys
    manager1 = ChallengeManager(repository=challenge_repository, expiration_seconds=60)
    
    challenge = manager1.create_challenge("req1", "recip1", "1.0")
    request = create_mock_request(challenge)
    
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, sk, AUTH_CONTEXT).hex()
    
    # Process it successfully once
    assert manager1.verify_request_authentication(request, challenge, pk, "ML-DSA-65") is True
    
    # "Restart" the service by creating a new manager with the SAME repository (which simulates
    # the same underlying DB connection)
    manager2 = ChallengeManager(repository=challenge_repository, expiration_seconds=60)
    
    # Attempt to replay the same request to the new manager instance
    with pytest.raises(AuthenticationError, match="consumed"):
        manager2.verify_request_authentication(request, challenge, pk, "ML-DSA-65")
