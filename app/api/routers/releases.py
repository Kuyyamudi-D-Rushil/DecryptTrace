from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.storage.database import SessionLocal
from app.storage.models import Document, AuthChallenge as DBAuthChallenge
from app.domain.rbac import require_roles, Role
from app.protocol.release import ReleaseProtocol
from app.protocol.models import ReleaseRequest, AuthChallenge
from app.protocol.authentication import ChallengeManager
from app.storage.repositories import ChallengeRepository, ThresholdRepository, RateLimitRepository
from app.storage.providers import (
    DBManifestProvider, DBShareBProvider, DBDocumentProvider, 
    DBRecipientKeyProvider, DBPlaintextProcessor, DBAuthorizer, DBAuthorityKEMProvider
)
from app.config.settings import settings
from app.ledger.core import Ledger
import uuid
import time
import json

router = APIRouter(prefix="/releases", tags=["releases"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# We need a shared Ledger instance for now, but in a real setup it should be DB-backed.
# Since we are implementing Milestone 4 later, we will initialize it here.
ledger = Ledger()

class ReleaseChallengeRequest(BaseModel):
    document_id: str

@router.post("/challenge", response_model=AuthChallenge)
def request_release_challenge(
    req: ReleaseChallengeRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.RECIPIENT]))
):
    recipient_id = current_user["sub"]
    req_id = f"req_{uuid.uuid4().hex[:8]}"
    
    chal_repo = ChallengeRepository(db)
    mgr = ChallengeManager(chal_repo)
    
    challenge = mgr.create_challenge(req_id, recipient_id, "1.0")
    
    # Store this challenge in DB temporarily
    db_chal = DBAuthChallenge(
        nonce=challenge.nonce_hex,
        username=recipient_id,
        expires_at=challenge.expires_at
    )
    # We misuse the DBAuthChallenge table for release challenges by packing it, 
    # but let's be careful. Actually, the Protocol verifies against a Pydantic AuthChallenge.
    # It's better to store it as JSON in a generic or specific table, or use Redis.
    # Since we have AuthChallenge table, we can serialize the extra fields.
    db_chal.username = f"release:{recipient_id}:{req_id}:{challenge.protocol_version}"
    db.add(db_chal)
    db.commit()
    
    return challenge

@router.post("/request")
def execute_release(
    request: ReleaseRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.RECIPIENT]))
):
    recipient_id = current_user["sub"]
    if request.recipient_key_id != recipient_id:
        raise HTTPException(status_code=403, detail="Recipient ID mismatch")
        
    # Reconstruct AuthChallenge from DB
    chal_record = db.query(DBAuthChallenge).filter(DBAuthChallenge.nonce == request.challenge_id).first()
    if not chal_record or chal_record.expires_at < time.time():
        raise HTTPException(status_code=401, detail="Challenge expired or invalid")
        
    parts = chal_record.username.split(":")
    if len(parts) != 4 or parts[0] != "release" or parts[1] != recipient_id:
        raise HTTPException(status_code=401, detail="Invalid challenge context")
        
    challenge = AuthChallenge(
        request_id=parts[2],
        recipient_key_id=parts[1],
        nonce_hex=chal_record.nonce,
        protocol_version=parts[3],
        expires_at=chal_record.expires_at
    )
        
    # Setup Release Protocol
    chal_repo = ChallengeRepository(db)
    thresh_repo = ThresholdRepository(db)
    rate_repo = RateLimitRepository(db)
    
    protocol = ReleaseProtocol(
        authorizer=DBAuthorizer(db),
        manifest_provider=DBManifestProvider(db),
        share_b_provider=DBShareBProvider(db),
        recipient_key_provider=DBRecipientKeyProvider(db),
        document_provider=DBDocumentProvider(db),
        plaintext_processor=DBPlaintextProcessor(db),
        challenge_manager=ChallengeManager(chal_repo),
        threshold_repository=thresh_repo,
        authority_secret_key=None, # In DBAuthorityKEMProvider we use provider
        authority_key_id="authority",
        authority_kem_key_provider=DBAuthorityKEMProvider(),
        authority_sig_alg=settings.signature_parameter
    )
    
    # We must patch authority_secret_key because ReleaseProtocol constructor expects bytes.
    # We will get it from provider for now.
    from app.crypto.providers import get_key_provider
    key_prov = get_key_provider()
    try:
        protocol.authority_secret_key = key_prov.get_dsa_keypair("authority")[1]
    except NotImplementedError:
        # In a real HSM setup, protocol.process_release would call HSM.
        pass

    # Idempotency check: if already processed, return existing
    from app.storage.models import Statement, Artifact, AuditLog
    existing_artifact = db.query(Artifact).filter(
        Artifact.document_id == request.document_id,
        Artifact.recipient_id == recipient_id
    ).first()
    if existing_artifact:
        existing_statement = db.query(Statement).filter(
            Statement.document_id == request.document_id,
            Statement.recipient_id == recipient_id
        ).first()
        if existing_statement:
            # Mark challenge consumed
            db.delete(chal_record)
            db.commit()
            return {
                "status": "Success",
                "artifact": json.loads(existing_artifact.payload),
                "statement": json.loads(existing_statement.content)
            }

    try:
        artifact, statement = protocol.process_release(request, challenge)
        
        db_stmt = Statement(
            id=statement.release_id,
            document_id=statement.document_id,
            recipient_id=statement.recipient_key_id,
            content=statement.model_dump_json()
        )
        db.add(db_stmt)
        
        db_artifact = Artifact(
            id=artifact.artifact_id,
            document_id=artifact.document_id,
            recipient_id=artifact.recipient_key_id,
            payload=artifact.model_dump_json()
        )
        db.add(db_artifact)
        
        # Mark challenge as consumed race-safe
        res = db.query(DBAuthChallenge).filter(DBAuthChallenge.nonce == chal_record.nonce).delete()
        if res == 0:
            raise ValueError("Challenge already consumed")
            
        audit_log = AuditLog(
            event_type="RELEASE_SUCCESS",
            actor_id=recipient_id,
            target_id=request.document_id,
            details=json.dumps({"artifact_id": artifact.artifact_id})
        )
        db.add(audit_log)
        
        db.commit()
    except Exception as e:
        db.rollback()
        # Fail closed
        audit_log = AuditLog(
            event_type="RELEASE_FAILED",
            actor_id=recipient_id,
            target_id=request.document_id,
            details=json.dumps({"error_type": type(e).__name__}) # Redacted internal text
        )
        db.add(audit_log)
        db.commit()
        raise HTTPException(status_code=400, detail="Release request failed")
        
    return {
        "status": "Success",
        "artifact": artifact.model_dump(mode="json"),
        "statement": statement.model_dump(mode="json")
    }

@router.get("/download/{artifact_id}")
def download_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.RECIPIENT]))
):
    from app.storage.models import Artifact
    
    artifact = db.query(Artifact).filter(Artifact.id == artifact_id).first()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
        
    if artifact.recipient_id != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Not authorized to download this artifact")
        
    return json.loads(artifact.payload)

