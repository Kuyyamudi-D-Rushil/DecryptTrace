from abc import ABC, abstractmethod

from ..domain.contracts import (
    AuthorityReleaseStatement,
    RecipientReceipt,
    ReleaseRequest,
    SenderManifest,
)
from ..domain.errors import NotImplementedSecurityFeature


class DocumentEncryptionService(ABC):
    @abstractmethod
    def encrypt_document(self, plaintext: bytes) -> bytes:
        raise NotImplementedSecurityFeature("Phase 1: Real encryption is not implemented.")

class KeySplitService(ABC):
    @abstractmethod
    def split_dek(self, dek: bytes):
        raise NotImplementedSecurityFeature("Phase 1: Real DEK split is not implemented.")

class RecipientAuthenticationService(ABC):
    @abstractmethod
    def authenticate(self, credentials):
        raise NotImplementedSecurityFeature("Phase 1: Auth not implemented.")

class ReleaseService(ABC):
    @abstractmethod
    def process_release(self, request: ReleaseRequest, manifest: SenderManifest) -> AuthorityReleaseStatement:
        raise NotImplementedSecurityFeature("Phase 1: Plaintext release is not implemented.")

class WatermarkService(ABC):
    @abstractmethod
    def embed_watermark(self, document: bytes, fingerprint: str) -> bytes:
        raise NotImplementedSecurityFeature("Phase 1: Watermarking not implemented.")

class ReceiptService(ABC):
    @abstractmethod
    def verify_receipt(self, receipt: RecipientReceipt):
        raise NotImplementedSecurityFeature("Phase 1: Receipt verification not implemented.")

class LedgerService(ABC):
    @abstractmethod
    def commit_entry(self, entry) -> str:
        raise NotImplementedSecurityFeature("Phase 1: Ledger not implemented.")

class EvidenceVerificationService(ABC):
    @abstractmethod
    def verify_evidence(self, artifact: bytes):
        raise NotImplementedSecurityFeature("Phase 1: Evidence verification not implemented.")
