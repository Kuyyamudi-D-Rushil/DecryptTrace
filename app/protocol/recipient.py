import hashlib
import time
import uuid

from app.protocol.models import AuthorityReleaseStatement, ReleaseArtifact
from app.protocol.receipt import RecipientReceipt
from app.protocol.serialization import canonicalize_artifact


class IntegrityMismatchError(Exception):
    pass


class RecipientProtocol:
    """
    Models the recipient-side protocol behavior.
    """
    def __init__(self, recipient_key_id: str, recipient_secret_key: bytes):
        self.recipient_key_id = recipient_key_id
        self.recipient_secret_key = recipient_secret_key
        
    def acknowledge_delivery(self, artifact: ReleaseArtifact, statement: AuthorityReleaseStatement) -> RecipientReceipt:
        """
        Receives an artifact and its associated release statement, verifies integrity,
        and generates a signed RecipientReceipt.
        """
        # 1. Independent hash computation
        canonical_env = canonicalize_artifact(artifact)
        hasher = hashlib.sha256()
        hasher.update(canonical_env)
        computed_hash = hasher.digest().hex()
        
        # 2. Compare against Authority-claimed hash
        if computed_hash != statement.artifact_hash_hex:
            raise IntegrityMismatchError("Artifact hash mismatch! Integrity compromised.")
            
        # 3. If matches, generate the receipt
        receipt = RecipientReceipt(
            receipt_id=uuid.uuid4().hex,
            release_id=statement.release_id,
            document_id=statement.document_id,
            recipient_key_id=self.recipient_key_id,
            session_id=statement.session_id,
            artifact_hash_hex=computed_hash,
            detection_threshold=statement.detection_threshold,
            fingerprint_commitment=statement.fingerprint_commitment,
            fingerprint_commitment_salt="TODO_PHASE4",  # Add salt generation/retrieval later
            timestamp=str(int(time.time())),
            receipt_version="1.0",
            fpr_methodology_status="provisional"
        )
        
        # 4. Sign and return
        receipt.sign(self.recipient_secret_key)
        return receipt

