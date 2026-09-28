
from app.crypto.manifest import CryptoManifest
from app.evidence.models import EvidencePackage
from app.protocol.models import AuthorityReleaseStatement, ReleaseRequest
from app.protocol.receipt import RecipientReceipt


def assemble_evidence_package(
    manifest: CryptoManifest,
    request: ReleaseRequest,
    statement: AuthorityReleaseStatement,
    receipt: RecipientReceipt,
    ledger_proof: list[tuple[str, bool]],
    ledger_seq: int,
    ledger_entry_hash: str,
    ledger_prev_hash: str
) -> EvidencePackage:
    return EvidencePackage(
        manifest=manifest,
        request=request,
        statement=statement,
        receipt=receipt,
        ledger_proof=ledger_proof,
        ledger_seq=ledger_seq,
        ledger_entry_hash=ledger_entry_hash,
        ledger_prev_hash=ledger_prev_hash
    )
