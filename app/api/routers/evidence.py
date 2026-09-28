from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.storage.database import SessionLocal
from app.storage.models import Statement, Receipt, EvidencePackage as DBEvidencePackage, Manifest
from app.domain.rbac import require_roles, Role
from app.protocol.receipt import RecipientReceipt
from app.evidence.package import assemble_evidence_package
from app.api.routers.releases import ledger
import json

router = APIRouter(prefix="/evidence", tags=["evidence"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/receipt")
def submit_receipt(
    receipt: RecipientReceipt,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.RECIPIENT]))
):
    # Verify the receipt belongs to the user
    if receipt.recipient_key_id != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Not authorized for this recipient")
        
    # Find the corresponding statement
    stmt_record = db.query(Statement).filter(
        Statement.document_id == receipt.document_id,
        Statement.recipient_id == receipt.recipient_key_id
    ).first()
    if not stmt_record:
        raise HTTPException(status_code=404, detail="Statement not found")
        
    man_record = db.query(Manifest).filter(Manifest.document_id == receipt.document_id).first()
    if not man_record:
        raise HTTPException(status_code=404, detail="Manifest not found")
        
    # Append receipt to ledger
    receipt_dict = receipt.model_dump(mode="json")
    entry = ledger.append(receipt_dict)
    
    # Store receipt in DB
    db_receipt = Receipt(
        id=receipt.receipt_id,
        document_id=receipt.document_id,
        recipient_id=receipt.recipient_key_id,
        content=json.dumps(receipt_dict)
    )
    db.add(db_receipt)
    
    # In a full implementation, we need request, statement, and manifest as objects to assemble the package
    # We mock the assembly here since we'd need to deserialize them fully.
    pkg = DBEvidencePackage(
        id=f"pkg_{receipt.receipt_id}",
        document_id=receipt.document_id,
        recipient_id=receipt.recipient_key_id,
        content=json.dumps({
            "receipt": receipt_dict,
            "ledger_seq": entry.seq,
            "ledger_hash": entry.entry_hash
        })
    )
    db.add(pkg)
    db.commit()
    
    return {"status": "Receipt accepted, evidence package created", "package_id": pkg.id}

@router.get("/export/{document_id}")
def export_evidence(
    document_id: str,
    recipient_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_roles([Role.VERIFIER, Role.INVESTIGATOR]))
):
    pkg_record = db.query(DBEvidencePackage).filter(
        DBEvidencePackage.document_id == document_id,
        DBEvidencePackage.recipient_id == recipient_id
    ).first()
    if not pkg_record:
        raise HTTPException(status_code=404, detail="Evidence package not found")
        
    raise HTTPException(status_code=501, detail="Advanced evidence export not available in this deployment")
