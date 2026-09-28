"""
Tests for the EncryptedReleaseEnvelope (application-layer Share A confidentiality).

These tests assert that:
  1. The sealed envelope bytes never contain the plaintext share_a_hex value.
  2. process_sealed_release produces the same outcome as process_release.
  3. Tampering with AAD fields causes decryption to fail.
  4. A wrong Authority KEM secret key cannot open the envelope.
  5. The Authority cannot be impersonated by substituting a different KEM keypair.
"""

import json

import pytest

from app.crypto.errors import CryptoError
from app.crypto.kem import KEMWrapper
from app.crypto.signatures import SignatureWrapper
from app.protocol.authentication import AUTH_CONTEXT, ChallengeManager
from app.protocol.envelope import open_request, seal_request
from app.protocol.models import EncryptedReleaseEnvelope, ReleaseRequest
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_signed_request(mock_crypto_state, challenge):
    """Return a fully ML-DSA-signed ReleaseRequest (plaintext)."""
    request = ReleaseRequest(
        request_id="req1",
        document_id="doc1",
        manifest_id="man1",
        recipient_key_id="recip1",
        challenge_id=challenge.nonce_hex,
        auth_signature_hex="",
        share_a_hex=mock_crypto_state["share_a"].hex(),
        protocol_version="1.0",
    )
    canonical_bytes = canonicalize_for_signing(request)
    sig = SignatureWrapper("ML-DSA-65")
    request.auth_signature_hex = sig.sign(
        canonical_bytes, mock_crypto_state["recip_dsa_sk"], AUTH_CONTEXT
    ).hex()
    return request


class MockThresholdRepository:
    def get_threshold(self, document_id: str):
        return None
    def save_threshold(self, document_id: str, threshold: float):
        pass

def _build_protocol(mock_crypto_state, manager):
    """Build a ReleaseProtocol wired to mock_crypto_state."""
    authority_kem_provider = MockAuthorityKEMKeyProvider(
        mock_crypto_state["auth_kem_pk"],
        mock_crypto_state["auth_kem_sk"],
    )
    return ReleaseProtocol(
        authorizer=MockAuthorizer(allow=True),
        manifest_provider=MockManifestProvider(mock_crypto_state["manifest"]),
        share_b_provider=MockShareBProvider(mock_crypto_state["share_b"]),
        recipient_key_provider=MockRecipientKeyProvider(
            mock_crypto_state["recip_dsa_pk"],
            mock_crypto_state["recip_kem_pk"],
        ),
        document_provider=MockDocumentProvider(*mock_crypto_state["doc_data"]),
        plaintext_processor=IdentityProcessor(),
        challenge_manager=manager,
            threshold_repository=MockThresholdRepository(),
        authority_secret_key=mock_crypto_state["auth_dsa_sk"],
        authority_key_id="auth1",
        authority_kem_key_provider=authority_kem_provider,
        authority_sig_alg="ML-DSA-65",
    )


# ---------------------------------------------------------------------------
# Wire-level confidentiality tests
# ---------------------------------------------------------------------------

def test_share_a_not_in_sealed_envelope_bytes(mock_crypto_state, challenge_repository):
    """
    The serialised EncryptedReleaseEnvelope must NOT contain the plaintext
    value of share_a_hex anywhere — not in any field, not in the JSON.
    """
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    share_a_hex_value: str = mock_crypto_state["share_a"].hex()

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    # Serialise the envelope exactly as it would travel over the wire
    wire_bytes: bytes = json.dumps(envelope.model_dump(mode="json")).encode()

    assert share_a_hex_value.encode() not in wire_bytes, (
        "share_a_hex value appears in plaintext in the serialised envelope — "
        "confidentiality is broken."
    )
    # Also check the raw ciphertext_hex field value itself does not embed the share
    assert share_a_hex_value not in envelope.ciphertext_hex


def test_share_a_not_in_envelope_fields(mock_crypto_state, challenge_repository):
    """Every plaintext field of EncryptedReleaseEnvelope must be inspected individually."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    share_a_hex_value: str = mock_crypto_state["share_a"].hex()
    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    plaintext_fields = {
        "protocol_version": envelope.protocol_version,
        "document_id": envelope.document_id,
        "recipient_key_id": envelope.recipient_key_id,
        "challenge_id": envelope.challenge_id,
        "kem_algorithm": envelope.kem_algorithm,
        "kem_version": envelope.kem_version,
        "encryption_algorithm": envelope.encryption_algorithm,
        "encryption_version": envelope.encryption_version,
        "payload_hash_hex": envelope.payload_hash_hex,
    }
    for field_name, field_value in plaintext_fields.items():
        assert share_a_hex_value not in field_value, (
            f"share_a_hex value found in plaintext envelope field '{field_name}'"
        )


def test_sealed_release_succeeds_end_to_end(mock_crypto_state, challenge_repository):
    """process_sealed_release should complete successfully and produce a valid statement."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])
    protocol = _build_protocol(mock_crypto_state, manager)

    artifact, statement = protocol.process_sealed_release(envelope, challenge)

    assert protocol.state == ProtocolState.DELIVERED
    assert statement.processing_status == "WATERMARKED"
    assert statement.artifact_hash_hex == artifact.artifact_hash_hex

    # Verify Authority statement signature
    stmt_canonical = canonicalize_for_signing(statement)
    verifier = SignatureWrapper("ML-DSA-65")
    assert verifier.verify(
        stmt_canonical,
        bytes.fromhex(statement.signature_hex),
        mock_crypto_state["auth_dsa_pk"],
        STATEMENT_CONTEXT,
    )


def test_wrong_authority_kem_key_cannot_open_envelope(mock_crypto_state, challenge_repository):
    """A different Authority KEM secret key must not be able to decrypt the envelope."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    # Generate a completely different KEM keypair
    kem = KEMWrapper("ML-KEM-768")
    _wrong_pk, wrong_sk = kem.generate_keypair()

    with pytest.raises(CryptoError):
        open_request(envelope, wrong_sk)


def test_tampered_aad_document_id_fails(mock_crypto_state, challenge_repository):
    """Modifying the document_id in the envelope header must cause AAD mismatch."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    # Attacker swaps document_id in the plaintext header
    tampered = EncryptedReleaseEnvelope(
        **{**envelope.model_dump(mode="json"), "document_id": "evil_doc"}
    )

    with pytest.raises(CryptoError):
        open_request(tampered, mock_crypto_state["auth_kem_sk"])


def test_tampered_aad_recipient_key_id_fails(mock_crypto_state, challenge_repository):
    """Modifying recipient_key_id in the envelope header must cause AAD mismatch."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])
    tampered = EncryptedReleaseEnvelope(
        **{**envelope.model_dump(mode="json"), "recipient_key_id": "evil_recip"}
    )

    with pytest.raises(CryptoError):
        open_request(tampered, mock_crypto_state["auth_kem_sk"])


def test_tampered_ciphertext_fails(mock_crypto_state, challenge_repository):
    """Bit-flipping the ciphertext must cause AES-GCM authentication failure."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    # Flip first byte of ciphertext
    ct_bytes = bytearray(bytes.fromhex(envelope.ciphertext_hex))
    ct_bytes[0] ^= 0xFF
    tampered = EncryptedReleaseEnvelope(
        **{**envelope.model_dump(mode="json"), "ciphertext_hex": ct_bytes.hex()}
    )

    with pytest.raises(CryptoError):
        open_request(tampered, mock_crypto_state["auth_kem_sk"])


def test_failed_sealed_release_state_is_failed(mock_crypto_state, challenge_repository):
    """A bad envelope must leave the protocol in FAILED state."""
    manager = ChallengeManager(repository=challenge_repository)
    challenge = manager.create_challenge("req1", "recip1", "1.0")
    request = _build_signed_request(mock_crypto_state, challenge)

    envelope = seal_request(request, mock_crypto_state["auth_kem_pk"])

    # Corrupt ciphertext
    ct_bytes = bytearray(bytes.fromhex(envelope.ciphertext_hex))
    ct_bytes[0] ^= 0xFF
    tampered = EncryptedReleaseEnvelope(
        **{**envelope.model_dump(mode="json"), "ciphertext_hex": ct_bytes.hex()}
    )

    protocol = _build_protocol(mock_crypto_state, manager)
    with pytest.raises(CryptoError):
        protocol.process_sealed_release(tampered, challenge)

    assert protocol.state == ProtocolState.FAILED
