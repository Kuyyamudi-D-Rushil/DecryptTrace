import json

from app.crypto.signatures import SignatureWrapper
from app.evidence.models import EvidencePackage
from app.ledger.core import sha256, verify_proof
from app.protocol.serialization import canonicalize_for_signing


class VerificationError(Exception):
    pass

def verify_evidence_package(
    pkg: EvidencePackage,
    trusted_ledger_root: str,
    authority_public_key: bytes,
    recipient_public_key: bytes
) -> bool:
    # 1. Verify Manifest Hash matches what the Authority signed
    man_canonical = canonicalize_for_signing(pkg.manifest)
    man_hash = sha256(man_canonical).hex()
    if man_hash != pkg.statement.source_manifest_hash_hex:
        raise VerificationError("Manifest hash mismatch in Authority Statement.")
        
    # 2. Verify Recipient Receipt matches Authority Artifact
    if pkg.receipt.artifact_hash_hex != pkg.statement.artifact_hash_hex:
        raise VerificationError("Receipt artifact hash does not match Authority artifact hash.")
        
    # 3. Verify Authority Signature
    if not pkg.statement.signature_hex:
        raise VerificationError("Authority statement is missing signature.")
        
    stmt_canonical = canonicalize_for_signing(pkg.statement)
    auth_sig_wrapper = SignatureWrapper(pkg.statement.algorithm_identifiers.get("signature", "ML-DSA-65"))
    try:
        auth_sig_wrapper.verify(
            stmt_canonical, 
            bytes.fromhex(pkg.statement.signature_hex), 
            authority_public_key, 
            b"DecryptTrace/AuthorityReleaseStatement/v1"
        )
    except Exception as e:  # noqa: BLE001
        raise VerificationError(f"Authority signature verification failed: {e}")
        
    # 4. Verify Recipient Signature
    if not pkg.receipt.signature_hex:
        raise VerificationError("Recipient receipt is missing signature.")
        
    try:
        pkg.receipt.verify(recipient_public_key, algorithm="ML-DSA-65")
    except Exception as e:  # noqa: BLE001
        raise VerificationError(f"Recipient signature verification failed: {e}")
        
    # 5. Verify Ledger Inclusion Proof
    payload = pkg.statement.model_dump(mode="json")
    payload_str = json.dumps(payload, sort_keys=True)
    payload_hash = sha256(payload_str.encode()).hex()
    
    expected_entry_hash = sha256(pkg.ledger_prev_hash.encode() + payload_hash.encode()).hex()
    if pkg.ledger_entry_hash != expected_entry_hash:
        raise VerificationError("Ledger entry hash does not match statement payload and previous hash.")
        
    leaf_bytes = bytes.fromhex(pkg.ledger_entry_hash)
    binary_proof = [(bytes.fromhex(h), is_right) for h, is_right in pkg.ledger_proof]
    binary_root = bytes.fromhex(trusted_ledger_root)
    
    if not verify_proof(leaf_bytes, binary_proof, binary_root):
        raise VerificationError("Ledger inclusion proof failed verification.")
        
    return True
