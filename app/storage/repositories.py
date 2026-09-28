from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import ConsumedChallenge


class ChallengeRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def add_consumed_challenge(self, challenge_id: str) -> bool:
        """Returns True if successfully added, False if it already existed (replay)."""
        record = ConsumedChallenge(challenge_id=challenge_id)
        self.session.add(record)
        try:
            self.session.commit()
            return True
        except IntegrityError:
            self.session.rollback()
            return False
            
    def is_consumed(self, challenge_id: str) -> bool:
        record = self.session.query(ConsumedChallenge).filter_by(challenge_id=challenge_id).first()
        return record is not None

from .models import DocumentThreshold


class ThresholdRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get_threshold(self, document_id: str) -> float | None:
        record = self.session.query(DocumentThreshold).filter_by(document_id=document_id).first()
        return float(record.threshold_value) if record is not None else None
        
    def save_threshold(self, document_id: str, threshold: float):
        record = DocumentThreshold(document_id=document_id, threshold_value=threshold)
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()

import time
from .models import ReleaseEvent

class RateLimitRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def count_releases(self, document_id: str, recipient_key_id: str, window_seconds: int) -> int:
        cutoff = time.time() - window_seconds
        return self.session.query(ReleaseEvent).filter(
            ReleaseEvent.document_id == document_id,
            ReleaseEvent.recipient_key_id == recipient_key_id,
            ReleaseEvent.timestamp >= cutoff
        ).count()
        
    def record_release(self, document_id: str, recipient_key_id: str):
        record = ReleaseEvent(
            document_id=document_id,
            recipient_key_id=recipient_key_id,
            timestamp=time.time()
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()

from .models import User, Document, Manifest, KeyShare, Artifact, Statement, Receipt, EvidencePackage, LedgerEntryRecord

class UserRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, user_id: str) -> User | None:
        return self.session.query(User).filter_by(id=user_id).first()
        
    def add(self, user: User):
        self.session.add(user)
        self.session.commit()

class DocumentRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str) -> Document | None:
        return self.session.query(Document).filter_by(id=document_id).first()
        
    def add(self, document: Document):
        self.session.add(document)
        self.session.commit()

class ManifestRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str) -> Manifest | None:
        return self.session.query(Manifest).filter_by(document_id=document_id).first()
        
    def add(self, manifest: Manifest):
        self.session.add(manifest)
        self.session.commit()

class KeyShareRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str, recipient_id: str) -> KeyShare | None:
        return self.session.query(KeyShare).filter_by(
            document_id=document_id, recipient_id=recipient_id
        ).first()
        
    def add(self, key_share: KeyShare):
        self.session.add(key_share)
        self.session.commit()

class ArtifactRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str, recipient_id: str) -> Artifact | None:
        return self.session.query(Artifact).filter_by(
            document_id=document_id, recipient_id=recipient_id
        ).first()
        
    def add(self, artifact: Artifact):
        self.session.add(artifact)
        self.session.commit()

class StatementRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str, recipient_id: str) -> Statement | None:
        return self.session.query(Statement).filter_by(
            document_id=document_id, recipient_id=recipient_id
        ).first()
        
    def add(self, statement: Statement):
        self.session.add(statement)
        self.session.commit()

class ReceiptRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str, recipient_id: str) -> Receipt | None:
        return self.session.query(Receipt).filter_by(
            document_id=document_id, recipient_id=recipient_id
        ).first()
        
    def add(self, receipt: Receipt):
        self.session.add(receipt)
        self.session.commit()

class EvidencePackageRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get(self, document_id: str, recipient_id: str) -> EvidencePackage | None:
        return self.session.query(EvidencePackage).filter_by(
            document_id=document_id, recipient_id=recipient_id
        ).first()
        
    def add(self, evidence_package: EvidencePackage):
        self.session.add(evidence_package)
        self.session.commit()

class LedgerRepository:
    def __init__(self, session: Session):
        self.session = session
        
    def get_all(self) -> list[LedgerEntryRecord]:
        return self.session.query(LedgerEntryRecord).order_by(LedgerEntryRecord.seq).all()
        
    def add(self, entry: LedgerEntryRecord):
        self.session.add(entry)
        self.session.commit()
