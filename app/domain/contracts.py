from pydantic import BaseModel

from .identifiers import DocumentID, FingerprintID, ManifestID, RecipientID, SessionID


class SenderManifest(BaseModel):
    manifest_id: ManifestID
    protocol_version: str
    document_id: DocumentID
    ciphertext_commitment: str
    recipient_authorization: str
    policy: str
    key_package_commitment: str
    cryptographic_algorithm_identifiers: str
    sender_identity_reference: str

class ReleaseRequest(BaseModel):
    session_id: SessionID
    document_id: DocumentID
    recipient_identity_reference: RecipientID
    fingerprint_id: FingerprintID
    recipient_share_reference: str
    request_nonce: str
    protocol_version: str

class AuthorityReleaseStatement(BaseModel):
    session_id: SessionID
    manifest_hash: str
    fingerprint_id: FingerprintID
    fingerprint_commitment: str
    watermarked_copy_hash: str
    release_event_information: str
    protocol_version: str
    authority_identity_reference: str

class RecipientReceipt(BaseModel):
    session_id: SessionID
    watermarked_copy_hash: str
    recipient_identity_reference: RecipientID
    protocol_version: str

class LedgerEntry(BaseModel):
    receipt_hash: str
    session_id: SessionID
    document_id: DocumentID
    recipient_pseudonym: str
    fingerprint_commitment: str
    manifest_hash: str
    algorithm_identifiers: str
    ledger_order_reference: str
