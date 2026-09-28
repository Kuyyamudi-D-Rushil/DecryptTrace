from app.protocol.interfaces import (
    ManifestProvider, ShareBProvider, DocumentProvider, 
    ReleaseAuthorizer, ControlledPlaintextProcessor, RecipientKeyProvider, AuthorityKEMKeyProvider
)
from app.storage.models import Manifest, KeyShare, Document, User
from app.crypto.manifest import CryptoManifest
from app.crypto.providers import get_key_provider
from app.watermark.core import embed, derive_watermark_seed, estimate_document_threshold
import cv2
import numpy as np

class DBManifestProvider(ManifestProvider):
    def __init__(self, db_session):
        self.db = db_session

    def get_manifest(self, manifest_id: str) -> CryptoManifest | None:
        record = self.db.query(Manifest).filter(Manifest.id == manifest_id).first()
        if not record:
            return None
        # We need to construct a CryptoManifest. 
        # In a complete implementation, Manifest model would store all these fields directly.
        # Here we mock the extra fields based on the document_id, assuming standard parameters.
        # But wait, our document upload created a full Manifest? No, we only saved a few fields in models.Manifest.
        # Let's rebuild it minimally. We will assume the signature_algorithm and kem_algorithm match.
        return CryptoManifest(
            protocol_version="1.0",
            document_id=record.document_id,
            encryption_algorithm="AES-GCM",
            encryption_version=record.encryption_version,
            kem_algorithm=record.kem_algorithm,
            kem_version=record.kem_version,
            signature_algorithm=record.signature_algorithm,
            signature_version=record.signature_version,
            ciphertext_hash=record.ciphertext_hash,
            recipient_share_reference=record.recipient_share_reference,
            sender_identity_reference=record.sender_identity_reference,
            manifest_id=record.id,
            creation_timestamp=record.creation_timestamp,
            manifest_signature=record.manifest_signature
        )

class DBShareBProvider(ShareBProvider):
    def __init__(self, db_session, keystore):
        self.db = db_session
        self.keystore = keystore
        
    def get_share_b(self, document_id: str, recipient_key_id: str) -> bytes | None:
        # Currently we store share_b for AUTHORITY. 
        # But the protocol interface asks for recipient_key_id.
        record = self.db.query(KeyShare).filter(
            KeyShare.document_id == document_id,
            KeyShare.recipient_id == "AUTHORITY" 
        ).first()
        if record:
            from app.config.settings import settings
            if settings.environment == "production":
                return self.keystore.decrypt_data(record.encrypted_share)
            return bytes.fromhex(record.encrypted_share)
        return None

class DBDocumentProvider(DocumentProvider):
    def __init__(self, db_session):
        self.db = db_session
        
    def get_document_ciphertext(self, document_id: str) -> tuple[bytes, bytes, bytes] | None:
        record = self.db.query(Document).filter(Document.id == document_id).first()
        if record:
            return record.ciphertext, record.nonce, record.aad
        return None

class DBRecipientKeyProvider(RecipientKeyProvider):
    def __init__(self, db_session):
        self.db = db_session
        
    def get_recipient_dsa_pubkey(self, recipient_key_id: str) -> bytes:
        user = self.db.query(User).filter(User.id == recipient_key_id).first()
        if not user:
            raise ValueError("Recipient not found")
        return bytes.fromhex(user.public_key)
        
    def get_recipient_kem_pubkey(self, recipient_key_id: str) -> bytes:
        user = self.db.query(User).filter(User.id == recipient_key_id).first()
        if not user or not user.kem_public_key:
            raise ValueError("Recipient KEM key not found")
        return bytes.fromhex(user.kem_public_key)

class DBPlaintextProcessor(ControlledPlaintextProcessor):
    def __init__(self, db_session):
        self.db = db_session
        
    def process(self, *, document_id: str, session_id: str, recipient_key_id: str, plaintext: bytes, cached_threshold: float | None = None) -> tuple[bytes, float]:
        nparr = np.frombuffer(plaintext, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Uploaded document is not a valid image format for watermarking")
            
        seed = derive_watermark_seed(document_id, recipient_key_id) 
        wm = embed(img, seed, alpha=5.0)
        
        success, buffer = cv2.imencode('.png', wm)
        processed_bytes = buffer.tobytes()
        
        if cached_threshold is not None:
            return processed_bytes, cached_threshold
            
        thresh = estimate_document_threshold(document_id, img, num_trials=5)
        return processed_bytes, thresh

class DBAuthorizer(ReleaseAuthorizer):
    def __init__(self, db_session):
        self.db = db_session

    def authorize(self, *, document_id: str, manifest_id: str, recipient_key_id: str, request_id: str) -> bool:
        manifest = self.db.query(Manifest).filter(Manifest.id == manifest_id, Manifest.document_id == document_id).first()
        if not manifest:
            return False
        import json
        recipients = json.loads(manifest.authorized_recipients)
        return recipient_key_id in recipients

class DBAuthorityKEMProvider(AuthorityKEMKeyProvider):
    def __init__(self, db_session, keystore):
        self.db = db_session
        self.keystore = keystore
        
    def _get_keypair(self):
        from app.storage.models import EncryptedKeyMaterial
        from app.config.settings import settings
        import json
        
        if settings.environment != "production":
            return self.keystore.get_kem_keypair("authority")
            
        record = self.db.query(EncryptedKeyMaterial).filter(EncryptedKeyMaterial.id == "authority_kem").first()
        if not record:
            from app.crypto.kem import KEMWrapper
            kem = KEMWrapper("ML-KEM-768")
            pk, sk = kem.generate_keypair()
            payload = json.dumps({"pk": pk.hex(), "sk": sk.hex()})
            enc_payload = self.keystore.encrypt_data(payload.encode())
            record = EncryptedKeyMaterial(id="authority_kem", encrypted_payload=enc_payload)
            self.db.add(record)
            self.db.commit()
            return pk, sk
            
        payload = json.loads(self.keystore.decrypt_data(record.encrypted_payload).decode())
        return bytes.fromhex(payload["pk"]), bytes.fromhex(payload["sk"])

    def get_authority_kem_public_key(self) -> bytes:
        return self._get_keypair()[0]
        
    def get_authority_kem_secret_key(self) -> bytes:
        return self._get_keypair()[1]
