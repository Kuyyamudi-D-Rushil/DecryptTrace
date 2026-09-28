from pydantic import BaseModel


class AuthChallenge(BaseModel):
    request_id: str
    recipient_key_id: str
    nonce_hex: str
    protocol_version: str
    expires_at: int

class ReleaseRequest(BaseModel):
    request_id: str
    document_id: str
    manifest_id: str
    recipient_key_id: str
    challenge_id: str
    auth_signature_hex: str
    share_a_hex: str
    protocol_version: str

class EncryptedReleaseEnvelope(BaseModel):
    """Application-layer encrypted wrapper for a ReleaseRequest.

    The entire ReleaseRequest payload (including share_a_hex) is encrypted
    with AES-256-GCM under a key derived from an ML-KEM shared secret
    encapsulated to the Authority's KEM public key.

    Fields in this envelope are plaintext and are used to reconstruct the
    AAD on the Authority side — they contain no sensitive material.
    """

    protocol_version: str
    document_id: str
    recipient_key_id: str
    challenge_id: str
    kem_algorithm: str
    kem_version: str
    kem_ciphertext_hex: str
    encryption_algorithm: str
    encryption_version: str
    nonce_hex: str
    aad_hex: str
    ciphertext_hex: str
    payload_hash_hex: str


class ReleaseArtifact(BaseModel):
    artifact_id: str
    protocol_version: str
    document_id: str
    manifest_id: str
    recipient_key_id: str
    session_id: str
    processing_status: str
    kem_algorithm: str
    kem_version: str
    kem_ciphertext_hex: str
    encryption_algorithm: str
    encryption_version: str
    nonce_hex: str
    aad_hex: str
    ciphertext_hex: str
    artifact_hash_hex: str

class AuthorityReleaseStatement(BaseModel):
    protocol_version: str
    release_id: str
    request_id: str
    document_id: str
    manifest_id: str
    source_manifest_hash_hex: str
    recipient_key_id: str
    session_id: str
    artifact_id: str
    artifact_hash_hex: str
    original_ciphertext_hash_hex: str
    processing_status: str
    fingerprint_commitment: str
    detection_threshold: float = 0.0
    algorithm_identifiers: dict[str, str]
    authority_key_id: str
    creation_timestamp: str
    schema_version: str
    signature_hex: str | None = None
