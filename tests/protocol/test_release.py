
import pytest

from app.crypto.kdf import derive_key
from app.crypto.kem import KEMWrapper
from app.crypto.signatures import SignatureWrapper
from app.crypto.symmetric import decrypt_document
from app.protocol.authentication import AUTH_CONTEXT, ChallengeManager
from app.protocol.errors import (
    AuthenticationError,
    AuthorizationError,
    ContractViolationError,
)
from app.protocol.models import ReleaseRequest
from app.protocol.release import STATEMENT_CONTEXT, ReleaseProtocol
from app.protocol.serialization import canonicalize_for_signing
from app.protocol.states import ProtocolState

from .conftest import (
    IdentityProcessor,
    MockAuthorityKEMKeyProvider,
    MockAuthorizer,
    MockDocumentProvider,
    MockManifestProvider,
    MockRecipientKeyProvider,
    MockShareBProvider,
)


@pytest.fixture
def protocol_setup(mock_crypto_state, challenge_repository, threshold_repository):
    authorizer = MockAuthorizer(allow=True)
    manifest_provider = MockManifestProvider(mock_crypto_state["manifest"])
    share_b_provider = MockShareBProvider(mock_crypto_state["share_b"])
    recipient_provider = MockRecipientKeyProvider(
        mock_crypto_state["recip_dsa_pk"],
        mock_crypto_state["recip_kem_pk"]
    )
    doc_provider = MockDocumentProvider(*mock_crypto_state["doc_data"])
    processor = IdentityProcessor()

    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")

    authority_kem_provider = MockAuthorityKEMKeyProvider(
        mock_crypto_state["auth_kem_pk"],
        mock_crypto_state["auth_kem_sk"],
    )

    protocol = ReleaseProtocol(
        authorizer=authorizer,
        manifest_provider=manifest_provider,
        share_b_provider=share_b_provider,
        recipient_key_provider=recipient_provider,
        document_provider=doc_provider,
        plaintext_processor=processor,
        challenge_manager=manager,
        threshold_repository=threshold_repository,
        authority_secret_key=mock_crypto_state["auth_dsa_sk"],
        authority_key_id="auth1",
        authority_kem_key_provider=authority_kem_provider,
        authority_sig_alg="ML-DSA-65",
    )

    request = ReleaseRequest(
        request_id="req1",
        document_id="doc1",
        manifest_id="man1",
        recipient_key_id="recip1",
        challenge_id=challenge.nonce_hex,
        auth_signature_hex="",  # Will be set below
        share_a_hex=mock_crypto_state["share_a"].hex(),
        protocol_version="1.0"
    )

    # Recipient signs request
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    signature = sig.sign(canonical_bytes, mock_crypto_state["recip_dsa_sk"], AUTH_CONTEXT)
    request.auth_signature_hex = signature.hex()

    return protocol, request, challenge, mock_crypto_state

def test_successful_release(protocol_setup):
    protocol, request, challenge, state_data = protocol_setup
    
    artifact, statement = protocol.process_release(request, challenge)
    
    assert protocol.state == ProtocolState.DELIVERED
    
    # Verify statement
    assert statement.processing_status == "WATERMARKED"
    assert statement.artifact_id == artifact.artifact_id
    assert statement.artifact_hash_hex == artifact.artifact_hash_hex
    assert statement.fingerprint_commitment == statement.fingerprint_commitment
    
    # Verify artifact can be decrypted by recipient
    kem = KEMWrapper("ML-KEM-768")
    shared_secret = kem.decapsulate(bytes.fromhex(artifact.kem_ciphertext_hex), state_data["recip_kem_sk"])
    
    hkdf_info = f"DecryptTrace/dek-transport|{request.protocol_version}|{request.document_id}|{request.manifest_id}|{request.recipient_key_id}|{statement.session_id}".encode()
    transport_dek = derive_key(shared_secret, None, hkdf_info, 32)
    
    from app.crypto.symmetric import build_canonical_aad
    aad_data = {
        "protocol_version": request.protocol_version,
        "document_id": request.document_id,
        "manifest_id": request.manifest_id,
        "recipient_key_id": request.recipient_key_id,
        "session_id": statement.session_id,
        "kem_algorithm": artifact.kem_algorithm,
        "encryption_algorithm": "AES-GCM-256",
        "encryption_version": "1.0"
    }
    artifact_aad = build_canonical_aad(aad_data)
    
    decrypted = decrypt_document(
        bytes.fromhex(artifact.ciphertext_hex),
        transport_dek,
        bytes.fromhex(artifact.nonce_hex),
        artifact_aad
    )
    
    assert decrypted == b"secret plaintext"
    
    # Verify statement signature
    stmt_canonical = canonicalize_for_signing(statement)
    auth_sig_verifier = SignatureWrapper("ML-DSA-65")
    assert auth_sig_verifier.verify(stmt_canonical, bytes.fromhex(statement.signature_hex), state_data["auth_dsa_pk"], STATEMENT_CONTEXT)

def test_request_binding_document_id(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    request.document_id = "doc_fake" # Modifying after signing
    with pytest.raises(AuthenticationError, match="Invalid signature"):
        protocol.process_release(request, challenge)

def test_request_binding_manifest_id(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    request.manifest_id = "man_fake" # Modifying after signing
    with pytest.raises(AuthenticationError, match="Invalid signature"):
        protocol.process_release(request, challenge)

def test_request_binding_share_a(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    request.share_a_hex = "00" * 32 # Modifying after signing
    with pytest.raises(AuthenticationError, match="Invalid signature"):
        protocol.process_release(request, challenge)

def test_request_binding_recipient(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    request.recipient_key_id = "recip_fake" # Modifying after signing
    with pytest.raises(AuthenticationError, match="Request identifiers do not match"):
        protocol.process_release(request, challenge)

def test_statement_binding_artifact_hash(protocol_setup):
    protocol, request, challenge, state_data = protocol_setup
    _artifact, statement = protocol.process_release(request, challenge)
    
    statement.artifact_hash_hex = "00" * 32
    stmt_canonical = canonicalize_for_signing(statement)
    auth_sig_verifier = SignatureWrapper("ML-DSA-65")
    from app.crypto.errors import SignatureVerificationError
    with pytest.raises(SignatureVerificationError):
        auth_sig_verifier.verify(stmt_canonical, bytes.fromhex(statement.signature_hex), state_data["auth_dsa_pk"], STATEMENT_CONTEXT)

def test_statement_binding_source_manifest(protocol_setup):
    protocol, request, challenge, state_data = protocol_setup
    _artifact, statement = protocol.process_release(request, challenge)
    
    statement.source_manifest_hash_hex = "00" * 32
    stmt_canonical = canonicalize_for_signing(statement)
    auth_sig_verifier = SignatureWrapper("ML-DSA-65")
    from app.crypto.errors import SignatureVerificationError
    with pytest.raises(SignatureVerificationError):
        auth_sig_verifier.verify(stmt_canonical, bytes.fromhex(statement.signature_hex), state_data["auth_dsa_pk"], STATEMENT_CONTEXT)

def test_statement_binding_session_id(protocol_setup):
    protocol, request, challenge, state_data = protocol_setup
    _artifact, statement = protocol.process_release(request, challenge)
    
    statement.session_id = "sess_fake"
    stmt_canonical = canonicalize_for_signing(statement)
    auth_sig_verifier = SignatureWrapper("ML-DSA-65")
    from app.crypto.errors import SignatureVerificationError
    with pytest.raises(SignatureVerificationError):
        auth_sig_verifier.verify(stmt_canonical, bytes.fromhex(statement.signature_hex), state_data["auth_dsa_pk"], STATEMENT_CONTEXT)

def test_transport_context_substitution(protocol_setup):
    protocol, request, challenge, state_data = protocol_setup
    artifact, statement = protocol.process_release(request, challenge)
    
    # Recipient attempts to decapsulate
    kem = KEMWrapper("ML-KEM-768")
    shared_secret = kem.decapsulate(bytes.fromhex(artifact.kem_ciphertext_hex), state_data["recip_kem_sk"])
    
    # Substitution: derive key with wrong document ID
    wrong_hkdf_info = f"DecryptTrace/dek-transport|{request.protocol_version}|wrong_doc|{request.manifest_id}|{request.recipient_key_id}|{statement.session_id}".encode()
    transport_dek = derive_key(shared_secret, None, wrong_hkdf_info, 32)
    
    from app.crypto.symmetric import build_canonical_aad
    aad_data = {
        "protocol_version": request.protocol_version,
        "document_id": request.document_id,
        "manifest_id": request.manifest_id,
        "recipient_key_id": request.recipient_key_id,
        "session_id": statement.session_id,
        "kem_algorithm": artifact.kem_algorithm,
        "encryption_algorithm": "AES-GCM-256",
        "encryption_version": "1.0"
    }
    artifact_aad = build_canonical_aad(aad_data)
    
    from app.crypto.errors import AuthenticationFailure
    with pytest.raises(AuthenticationFailure): # AES-GCM fails
        decrypt_document(
            bytes.fromhex(artifact.ciphertext_hex),
            transport_dek,
            bytes.fromhex(artifact.nonce_hex),
            artifact_aad
        )

@pytest.mark.parametrize("field_to_mutate", [
    "protocol_version", "document_id", "manifest_id", 
    "recipient_key_id", "session_id", "kem_algorithm", 
    "encryption_algorithm", "encryption_version"
])
def test_aad_binding_mutation(protocol_setup, field_to_mutate):
    protocol, request, challenge, state_data = protocol_setup
    artifact, statement = protocol.process_release(request, challenge)
    
    kem = KEMWrapper("ML-KEM-768")
    shared_secret = kem.decapsulate(bytes.fromhex(artifact.kem_ciphertext_hex), state_data["recip_kem_sk"])
    
    hkdf_info = f"DecryptTrace/dek-transport|{request.protocol_version}|{request.document_id}|{request.manifest_id}|{request.recipient_key_id}|{statement.session_id}".encode()
    transport_dek = derive_key(shared_secret, None, hkdf_info, 32)
    
    from app.crypto.symmetric import build_canonical_aad
    aad_data = {
        "protocol_version": request.protocol_version,
        "document_id": request.document_id,
        "manifest_id": request.manifest_id,
        "recipient_key_id": request.recipient_key_id,
        "session_id": statement.session_id,
        "kem_algorithm": artifact.kem_algorithm,
        "encryption_algorithm": "AES-GCM-256",
        "encryption_version": "1.0"
    }
    
    # Mutate the target field
    aad_data[field_to_mutate] = "MUTATED"
    
    wrong_aad = build_canonical_aad(aad_data)
    
    from app.crypto.errors import AuthenticationFailure
    with pytest.raises(AuthenticationFailure):
        decrypt_document(
            bytes.fromhex(artifact.ciphertext_hex),
            transport_dek,
            bytes.fromhex(artifact.nonce_hex),
            wrong_aad
        )

def test_artifact_hash_canonicalization(protocol_setup):
    protocol, request, challenge, _state_data = protocol_setup
    artifact, _statement = protocol.process_release(request, challenge)
    
    # 1. Changing an authenticated field changes the hash
    original_hash = artifact.artifact_hash_hex
    
    import hashlib

    from app.protocol.serialization import canonicalize_artifact
    
    artifact.nonce_hex = "00" * 12
    mutated_env = canonicalize_artifact(artifact)
    hasher = hashlib.sha256()
    hasher.update(mutated_env)
    assert hasher.digest().hex() != original_hash

def test_authorization_denied(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    protocol.authorizer.allow = False
    
    with pytest.raises(AuthorizationError):
        protocol.process_release(request, challenge)
        
    assert protocol.state == ProtocolState.FAILED

def test_manifest_mismatch(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    # To test manifest mismatch, we must bypass auth (re-sign) to hit manifest logic
    request.document_id = "doc_fake"
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(canonical_bytes, protocol_setup[3]["recip_dsa_sk"], AUTH_CONTEXT).hex()
    
    with pytest.raises(ContractViolationError, match="Manifest document ID mismatch"):
        protocol.process_release(request, challenge)
        
    assert protocol.state == ProtocolState.FAILED

def test_challenge_mismatch(protocol_setup):
    protocol, request, challenge, _ = protocol_setup
    request.request_id = "req_diff"
    
    with pytest.raises(AuthenticationError, match="identifiers do not match"):
        protocol.process_release(request, challenge)

def test_threshold_caching_after_restart(protocol_setup, db_session):
    protocol, request, challenge, _ = protocol_setup
    
    # Process release 1
    _artifact1, statement1 = protocol.process_release(request, challenge)
    
    # Simulate restart by creating a new repository with the SAME db_session
    from app.storage.repositories import ThresholdRepository
    repo2 = ThresholdRepository(db_session)
    
    # Check that the threshold is still in the database
    cached_thresh = repo2.get_threshold(request.document_id)
    assert cached_thresh is not None
    assert cached_thresh == statement1.detection_threshold

import pytest

from app.protocol.recipient import IntegrityMismatchError, RecipientProtocol


def test_recipient_detects_tampered_artifact(protocol_setup, mock_crypto_state):
    protocol, request, challenge, _ = protocol_setup
    
    # Authority processes release
    artifact, statement = protocol.process_release(request, challenge)
    
    # Simulate MITM / corruption of the artifact ciphertext
    original_ct = artifact.ciphertext_hex
    tampered_char = 'f' if original_ct[0] != 'f' else 'e'
    artifact.ciphertext_hex = tampered_char + original_ct[1:]
    
    # Recipient side
    recipient_dsa_sk = mock_crypto_state["recip_dsa_sk"]
    recipient = RecipientProtocol(request.recipient_key_id, recipient_dsa_sk)
    
    with pytest.raises(IntegrityMismatchError, match="Artifact hash mismatch! Integrity compromised."):
        recipient.acknowledge_delivery(artifact, statement)

def test_recipient_successful_acknowledge(protocol_setup, mock_crypto_state):
    protocol, request, challenge, _ = protocol_setup
    
    artifact, statement = protocol.process_release(request, challenge)
    
    recipient_dsa_sk = mock_crypto_state["recip_dsa_sk"]
    recipient = RecipientProtocol(request.recipient_key_id, recipient_dsa_sk)
    
    # Should succeed and return a signed receipt
    receipt = recipient.acknowledge_delivery(artifact, statement)
    
    assert receipt.artifact_hash_hex == statement.artifact_hash_hex
    assert receipt.signature_hex is not None
    assert receipt.fpr_methodology_status == "provisional"
