from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from app.storage.database import SessionLocal
from app.storage.models import Document, User, Manifest, KeyShare, AuditLog
from app.domain.rbac import require_roles, Role
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.secret_split import split_dek
from app.crypto.symmetric import build_aad, encrypt_document
from app.crypto.manifest import CryptoManifest
import hashlib
import uuid
import time
import json

router = APIRouter(prefix="/documents", tags=["documents"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

ALLOWED_MIMES = ["image/jpeg", "image/png"]
MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB

@router.post("/")
def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.SENDER]))
):
    file_bytes = file.file.read()
    
    # 1. Validation
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
        
    mime_type = file.content_type
    if mime_type not in ALLOWED_MIMES:
        raise HTTPException(status_code=400, detail="Unsupported MIME type")
        
    # Basic magic bytes check
    if file_bytes.startswith(b"\xff\xd8\xff"):
        detected = "image/jpeg"
    elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "image/png"
    else:
        raise HTTPException(status_code=400, detail="Invalid file signature")
        
    if detected != mime_type:
        raise HTTPException(status_code=400, detail="MIME type mismatch with file signature")

    doc_id = f"doc_{uuid.uuid4().hex[:8]}"
    sender_id = current_user["sub"]
    
    # 2. Cryptographic processing
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    nonce = generate_nonce()
    aad = build_aad("1.0", doc_id, "AES-GCM-256")
    
    ciphertext = encrypt_document(file_bytes, dek, nonce, aad)
    ct_hash = hashlib.sha256(ciphertext).hexdigest()
    
    man_id = f"man_{uuid.uuid4().hex[:8]}"
    manifest_obj = CryptoManifest(
        protocol_version="1.0",
        document_id=doc_id,
        encryption_algorithm="AES-GCM",
        encryption_version="1.0",
        kem_algorithm="ML-KEM-768",
        kem_version="1.0",
        signature_algorithm="ML-DSA-65",
        signature_version="1.0",
        ciphertext_hash=ct_hash,
        recipient_share_reference="share_a",
        sender_identity_reference=sender_id,
        manifest_id=man_id,
        creation_timestamp=str(int(time.time()))
    )
    
    # 3. Persistence
    new_doc = Document(
        id=doc_id,
        filename=file.filename or "unknown",
        content_type=mime_type,
        ciphertext=ciphertext,
        nonce=nonce,
        aad=aad,
        sender_id=sender_id
    )
    db.add(new_doc)
    
    new_manifest = Manifest(
        id=man_id,
        document_id=doc_id,
        protocol_version="1.0",
        encryption_algorithm="AES-GCM",
        encryption_version="1.0",
        kem_algorithm="ML-KEM-768",
        kem_version="1.0",
        signature_algorithm="ML-DSA-65",
        signature_version="1.0",
        ciphertext_hash=ct_hash,
        recipient_share_reference="share_a",
        sender_identity_reference=sender_id,
        creation_timestamp=manifest_obj.creation_timestamp,
        authorized_recipients=json.dumps([]) # empty initially
    )
    db.add(new_manifest)
    
    # Store Share B for Authority
    # For MVP, we store a single share_b per document and give share_a out later,
    # or the recipient holds share_a.
    # We will use recipient_id = "AUTHORITY" or leave it generic.
    from app.state import state
    from app.config.settings import settings
    auth_share_val = share_b.hex()
    if settings.environment == "production":
        auth_share_val = state.keystore.encrypt_data(share_b)

    auth_share = KeyShare(
        document_id=doc_id,
        recipient_id="AUTHORITY",
        share_b_hex=auth_share_val
    )
    db.add(auth_share)
    
    audit_log = AuditLog(
        event_type="DOCUMENT_UPLOAD",
        actor_id=sender_id,
        target_id=doc_id,
        details=json.dumps({"manifest_id": man_id, "size": len(ciphertext)})
    )
    db.add(audit_log)
    
    # Store Share A for the Sender temporarily (or securely wrapped)
    # The Sender must authorize recipients using the /authorize endpoint, 
    # which will wrap this Share A for the recipient.
    sender_share_val = share_a.hex()
    if settings.environment == "production":
        sender_share_val = state.keystore.encrypt_data(share_a)

    sender_share = KeyShare(
        document_id=doc_id,
        recipient_id=sender_id,
        share_b_hex=sender_share_val # we use this column to store Share A for the sender
    )
    db.add(sender_share)
    
    db.commit()
    
    return {
        "status": "Document uploaded securely. Share A is held securely until authorization.", 
        "document_id": doc_id,
        "manifest_id": man_id
    }

from pydantic import BaseModel

class AuthorizeRecipientPayload(BaseModel):
    recipient_username: str

@router.post("/{document_id}/authorize")
def authorize_recipient(
    document_id: str,
    payload: AuthorizeRecipientPayload,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.SENDER]))
):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.sender_id != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Only the sender can authorize recipients")
        
    recipient = db.query(User).filter(User.username == payload.recipient_username, User.role == Role.RECIPIENT.value).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found or invalid role")
        
    manifest = db.query(Manifest).filter(Manifest.document_id == document_id).first()
    if not manifest:
        raise HTTPException(status_code=404, detail="Manifest not found")
        
    recipients = json.loads(manifest.authorized_recipients)
    if recipient.id not in recipients:
        recipients.append(recipient.id)
        manifest.authorized_recipients = json.dumps(recipients)
        
        # Provision Share A to the Recipient securely.
        # In this implementation, we simply copy the Sender's stored Share A 
        # and assign it to the Recipient in the DB, avoiding HTTP transmission.
        sender_share = db.query(KeyShare).filter(KeyShare.document_id == document_id, KeyShare.recipient_id == current_user["sub"]).first()
        if sender_share:
            recip_share = KeyShare(
                document_id=document_id,
                recipient_id=recipient.id,
                share_b_hex=sender_share.share_b_hex
            )
            db.add(recip_share)
            
        db.commit()
        
    return {"status": "Recipient authorized and Share A provisioned internally"}

