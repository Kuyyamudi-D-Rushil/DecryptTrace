
from pydantic import BaseModel

from app.crypto.manifest import CryptoManifest
from app.protocol.models import AuthorityReleaseStatement, ReleaseRequest
from app.protocol.receipt import RecipientReceipt


class EvidencePackage(BaseModel):
    manifest: CryptoManifest
    request: ReleaseRequest
    statement: AuthorityReleaseStatement
    receipt: RecipientReceipt
    ledger_proof: list[tuple[str, bool]]
    ledger_seq: int
    ledger_entry_hash: str
    ledger_prev_hash: str
