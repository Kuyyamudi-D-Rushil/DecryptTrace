from sqlalchemy import Column, Float, Integer, String, Boolean, ForeignKey, LargeBinary, Text
from sqlalchemy.orm import relationship
from .database import Base
import time

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    public_key = Column(String, nullable=True) # ML-DSA
    kem_public_key = Column(String, nullable=True) # ML-KEM
    created_at = Column(Float, default=time.time)

class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    aad = Column(LargeBinary, nullable=False)
    sender_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(Float, default=time.time)

class Manifest(Base):
    __tablename__ = "manifests"
    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False)
    protocol_version = Column(String, nullable=False)
    encryption_algorithm = Column(String, nullable=False)
    encryption_version = Column(String, nullable=False)
    kem_algorithm = Column(String, nullable=False)
    kem_version = Column(String, nullable=False)
    signature_algorithm = Column(String, nullable=False)
    signature_version = Column(String, nullable=False)
    ciphertext_hash = Column(String, nullable=False)
    recipient_share_reference = Column(String, nullable=False)
    sender_identity_reference = Column(String, nullable=False)
    creation_timestamp = Column(String, nullable=False)
    manifest_signature = Column(String, nullable=True) # Sender's signature over the manifest
    authorized_recipients = Column(Text, nullable=False) # JSON list
    created_at = Column(Float, default=time.time)

class KeyShare(Base):
    __tablename__ = "key_shares"
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False)
    recipient_id = Column(String, ForeignKey("users.id"), nullable=False)
    share_b_hex = Column(String, nullable=False)
    created_at = Column(Float, default=time.time)

class ConsumedChallenge(Base):
    __tablename__ = "consumed_challenges"
    id = Column(Integer, primary_key=True, index=True)
    challenge_id = Column(String, unique=True, index=True, nullable=False)

class DocumentThreshold(Base):
    __tablename__ = "document_thresholds"
    document_id = Column(String, primary_key=True, index=True)
    threshold_value = Column(Float, nullable=False)

class ReleaseEvent(Base):
    __tablename__ = "release_events"
    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(String, index=True, nullable=False)
    recipient_key_id = Column(String, index=True, nullable=False)
    timestamp = Column(Float, default=time.time, index=True, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    actor_id = Column(String, nullable=True)
    target_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(Float, default=time.time, index=True)

class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    nonce = Column(String, primary_key=True, index=True)
    username = Column(String, nullable=False, index=True)
    expires_at = Column(Float, nullable=False)

class Artifact(Base):
    __tablename__ = "artifacts"
    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False, index=True)
    recipient_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    payload = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time)

class Statement(Base):
    __tablename__ = "statements"
    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False, index=True)
    recipient_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time)

class Receipt(Base):
    __tablename__ = "receipts"
    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False, index=True)
    recipient_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time)

class EvidencePackage(Base):
    __tablename__ = "evidence_packages"
    id = Column(String, primary_key=True, index=True)
    document_id = Column(String, ForeignKey("documents.id"), nullable=False, index=True)
    recipient_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(Float, default=time.time)

class LedgerEntryRecord(Base):
    __tablename__ = "ledger_entries"
    seq = Column(Integer, primary_key=True, index=True)
    prev_hash = Column(String, nullable=False)
    payload_hash = Column(String, nullable=False)
    payload = Column(Text, nullable=False)
    entry_hash = Column(String, nullable=False, unique=True)
    created_at = Column(Float, default=time.time)

class ReleaseChallenge(Base):
    __tablename__ = "release_challenges"
    nonce = Column(String, primary_key=True, index=True)
    request_id = Column(String, nullable=False)
    recipient_id = Column(String, nullable=False)
    protocol_version = Column(String, nullable=False)
    expires_at = Column(Float, nullable=False)

class EncryptedKeyMaterial(Base):
    __tablename__ = "encrypted_key_material"
    id = Column(String, primary_key=True, index=True)
    encrypted_payload = Column(String, nullable=False)
    created_at = Column(Float, default=time.time)
