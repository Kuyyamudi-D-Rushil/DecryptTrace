
import pytest

from app.crypto.manifest import CryptoManifest
from app.crypto.signatures import SignatureWrapper
from app.evidence.package import assemble_evidence_package
from app.evidence.verifier import VerificationError, verify_evidence_package
from app.ledger.core import Ledger
from app.protocol.models import AuthorityReleaseStatement, ReleaseRequest
from app.protocol.receipt import RecipientReceipt
from app.protocol.serialization import canonicalize_for_signing


@pytest.fixture
def evidence_setup():
    sig = SignatureWrapper("ML-DSA-65")
    auth_pk, auth_sk = sig.generate_keypair()
    recip_pk, recip_sk = sig.generate_keypair()
    
    manifest = CryptoManifest(
        protocol_version="1.0", document_id="doc", encryption_algorithm="AES-GCM",
        encryption_version="1.0", kem_algorithm="ML-KEM", kem_version="1.0",
        signature_algorithm="ML-DSA-65", signature_version="1.0",
        ciphertext_hash="c_hash", recipient_share_reference="ref",
        sender_identity_reference="ref", manifest_id="man", creation_timestamp="0"
    )
    
    from app.ledger.core import sha256
    man_hash = sha256(canonicalize_for_signing(manifest)).hex()
    
    request = ReleaseRequest(
        request_id="req", document_id="doc", manifest_id="man", 
        recipient_key_id="recip", challenge_id="chal", auth_signature_hex="asig",
        share_a_hex="share", protocol_version="1.0"
    )
    
    statement = AuthorityReleaseStatement(
        protocol_version="1.0", release_id="rel", request_id="req", document_id="doc",
        manifest_id="man", source_manifest_hash_hex=man_hash, recipient_key_id="recip",
        session_id="sess", artifact_id="art", artifact_hash_hex="a_hash", 
        original_ciphertext_hash_hex="o_hash", processing_status="DONE",
        fingerprint_commitment="commit", detection_threshold=0.01,
        algorithm_identifiers={"signature": "ML-DSA-65"},
        authority_key_id="auth_key", creation_timestamp="0", schema_version="1.0"
    )
    
    # Sign Statement
    stmt_can = canonicalize_for_signing(statement)
    statement.signature_hex = sig.sign(stmt_can, auth_sk, b"DecryptTrace/AuthorityReleaseStatement/v1").hex()
    
    receipt = RecipientReceipt(
        receipt_id="rec", release_id="rel", document_id="doc", recipient_key_id="recip",
        session_id="sess", artifact_hash_hex="a_hash", detection_threshold=0.01,
        fingerprint_commitment="commit", fingerprint_commitment_salt="salt",
        timestamp="0", receipt_version="1.0", fpr_methodology_status="provisional"
    )
    # Sign Receipt
    receipt.sign(recip_sk)
    
    ledger = Ledger()
    # Let's say we had a prior entry
    ledger.append({"init": True})
    
    entry = ledger.append(statement.model_dump(mode="json"))
    
    pkg = assemble_evidence_package(
        manifest, request, statement, receipt,
        ledger.get_inclusion_proof(entry.seq),
        entry.seq,
        entry.entry_hash,
        entry.prev_hash
    )
    
    return pkg, ledger.get_root(), auth_pk, recip_pk

def test_verify_evidence_package_valid(evidence_setup):
    pkg, root, auth_pk, recip_pk = evidence_setup
    assert verify_evidence_package(pkg, root, auth_pk, recip_pk) is True

def test_verify_evidence_package_tampered_artifact_hash(evidence_setup):
    pkg, root, auth_pk, recip_pk = evidence_setup
    
    # Tamper with the artifact_hash_hex in the receipt
    pkg.receipt.artifact_hash_hex = "tampered_hash"
    # But since it's signed, the verifier might catch the mismatch first or the signature first
    with pytest.raises(VerificationError, match="Receipt artifact hash does not match Authority artifact hash"):
        verify_evidence_package(pkg, root, auth_pk, recip_pk)
        
    # Let's tamper with it in the statement too
    pkg.statement.artifact_hash_hex = "tampered_hash"
    with pytest.raises(VerificationError, match="Authority signature verification failed"):
        verify_evidence_package(pkg, root, auth_pk, recip_pk)
        
def test_verify_evidence_package_tampered_ledger_payload(evidence_setup):
    pkg, root, auth_pk, recip_pk = evidence_setup
    # Change something in the statement without breaking its signature? 
    # Not possible, but say we just test if the ledger hash catches it if signature check were bypassed
    # Or just change the signature so it fails signature check, but let's tamper ledger_entry_hash
    pkg.ledger_entry_hash = "deadbeef"
    with pytest.raises(VerificationError, match="Ledger entry hash does not match"):
        verify_evidence_package(pkg, root, auth_pk, recip_pk)
