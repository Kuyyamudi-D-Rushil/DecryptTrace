"""
ReleaseRequest transport envelope.

Provides application-layer confidentiality for the ReleaseRequest,
including Share A, before it is transmitted from the Recipient to the
Release Authority.

The ML-DSA signature on the plaintext ReleaseRequest continues to provide
integrity and authenticity.  This envelope adds confidentiality ON TOP — it
does not replace the signature.

Dependency direction:
    Recipient constructs ReleaseRequest  (ML-DSA signed)
            ↓
    seal_request()  ← Authority ML-KEM public key
            ↓
    EncryptedReleaseEnvelope  (Share A never visible in transit)
            ↓
    Authority calls open_request()
            ↓
    Plaintext ReleaseRequest recovered → normal protocol logic continues

Key-derivation label:
    b"DecryptTrace/ReleaseRequestTransport/v1"

AAD fields (preventing cross-context ciphertext substitution):
    - context label
    - protocol_version
    - document_id
    - recipient_key_id
    - challenge_id
    - encryption_algorithm
    - encryption_version

All sourced from the plaintext envelope header so the Authority can
reconstruct the exact same AAD without decrypting the payload first.

Best-effort zeroization is applied to transport DEK bytearrays.
This does not provide a language/runtime/OS-level guarantee that all
copies of sensitive material have been removed from memory.
"""

import json

from app.crypto.canonical import canonical_serialize
from app.crypto.errors import AuthenticationFailure, CryptoError
from app.crypto.kdf import derive_key
from app.crypto.kem import KEMWrapper
from app.crypto.randomness import generate_nonce
from app.crypto.symmetric import decrypt_document, encrypt_document
from app.crypto.zeroization import zeroize_bytearray
from app.protocol.models import EncryptedReleaseEnvelope, ReleaseRequest

_HKDF_LABEL: bytes = b"DecryptTrace/ReleaseRequestTransport/v1"
_ENCRYPTION_ALGORITHM = "AES-GCM-256"
_ENCRYPTION_VERSION = "1.0"


def _build_envelope_aad(
    protocol_version: str,
    document_id: str,
    recipient_key_id: str,
    challenge_id: str,
) -> bytes:
    """Canonical, structured AAD for the release-request envelope.

    All fields are taken from the envelope's plaintext header so the
    Authority can reconstruct an identical AAD without first decrypting
    the payload.
    """
    return canonical_serialize(
        {
            "context": "DecryptTrace/ReleaseRequestTransport/v1",
            "protocol_version": protocol_version,
            "document_id": document_id,
            "recipient_key_id": recipient_key_id,
            "challenge_id": challenge_id,
            "encryption_algorithm": _ENCRYPTION_ALGORITHM,
            "encryption_version": _ENCRYPTION_VERSION,
        }
    )


def seal_request(
    request: ReleaseRequest,
    authority_kem_public_key: bytes,
    kem_algorithm: str = "ML-KEM-768",
) -> EncryptedReleaseEnvelope:
    """Encrypt a ReleaseRequest for transmission to the Authority.

    The FULL payload, including share_a_hex and auth_signature_hex, is
    encrypted under a fresh AES-256-GCM key derived from an ML-KEM
    shared secret encapsulated against the Authority's public KEM key.

    Parameters
    ----------
    request:
        The fully constructed and ML-DSA-signed ReleaseRequest.
    authority_kem_public_key:
        The Authority's registered ML-KEM public key.
    kem_algorithm:
        KEM algorithm identifier (default: ML-KEM-768).

    Returns
    -------
    EncryptedReleaseEnvelope ready to be transmitted.
    """
    kem = KEMWrapper(kem_algorithm)
    kem_ciphertext, shared_secret = kem.encapsulate(authority_kem_public_key)

    transport_dek = bytearray(derive_key(shared_secret, None, _HKDF_LABEL, 32))

    aad = _build_envelope_aad(
        protocol_version=request.protocol_version,
        document_id=request.document_id,
        recipient_key_id=request.recipient_key_id,
        challenge_id=request.challenge_id,
    )

    nonce = generate_nonce()

    # Serialize the COMPLETE request (including auth_signature_hex and share_a_hex)
    plaintext_bytes: bytes = canonical_serialize(request.model_dump(mode="json"))

    try:
        ciphertext = encrypt_document(plaintext_bytes, bytes(transport_dek), nonce, aad)
    finally:
        zeroize_bytearray(transport_dek)

    import hashlib
    payload_hash = hashlib.sha256(ciphertext).hexdigest()

    return EncryptedReleaseEnvelope(
        protocol_version=request.protocol_version,
        document_id=request.document_id,
        recipient_key_id=request.recipient_key_id,
        challenge_id=request.challenge_id,
        kem_algorithm=kem_algorithm,
        kem_version="1.0",
        kem_ciphertext_hex=kem_ciphertext.hex(),
        encryption_algorithm=_ENCRYPTION_ALGORITHM,
        encryption_version=_ENCRYPTION_VERSION,
        nonce_hex=nonce.hex(),
        aad_hex=aad.hex(),
        ciphertext_hex=ciphertext.hex(),
        payload_hash_hex=payload_hash,
    )


def open_request(
    envelope: EncryptedReleaseEnvelope,
    authority_kem_secret_key: bytes,
) -> ReleaseRequest:
    """Decrypt an EncryptedReleaseEnvelope and return the ReleaseRequest.

    The Authority decapsulates the shared secret, derives the same
    transport DEK, reconstructs the AAD from the envelope's plaintext
    header fields, and decrypts the payload.  The recovered bytes are
    parsed into a ReleaseRequest for normal protocol processing.

    Raises
    ------
    CryptoError
        If decapsulation, AAD mismatch, or decryption fails.
    ValueError
        If the decrypted payload cannot be parsed as a ReleaseRequest.
    """
    kem = KEMWrapper(envelope.kem_algorithm)
    try:
        shared_secret = kem.decapsulate(
            bytes.fromhex(envelope.kem_ciphertext_hex),
            authority_kem_secret_key,
        )
    except CryptoError as exc:
        raise CryptoError("Envelope decapsulation failed.") from exc

    transport_dek = bytearray(derive_key(shared_secret, None, _HKDF_LABEL, 32))

    # Reconstruct AAD from envelope's plaintext header — must match what seal_request built
    expected_aad = _build_envelope_aad(
        protocol_version=envelope.protocol_version,
        document_id=envelope.document_id,
        recipient_key_id=envelope.recipient_key_id,
        challenge_id=envelope.challenge_id,
    )
    stored_aad = bytes.fromhex(envelope.aad_hex)
    if expected_aad != stored_aad:
        zeroize_bytearray(transport_dek)
        raise CryptoError(
            "Envelope AAD mismatch — possible header tampering or context substitution."
        )

    try:
        plaintext_bytes = decrypt_document(
            bytes.fromhex(envelope.ciphertext_hex),
            bytes(transport_dek),
            bytes.fromhex(envelope.nonce_hex),
            expected_aad,
        )
    except AuthenticationFailure as exc:
        raise CryptoError("Envelope decryption failed.") from exc
    finally:
        zeroize_bytearray(transport_dek)

    data = json.loads(plaintext_bytes)
    return ReleaseRequest(**data)
