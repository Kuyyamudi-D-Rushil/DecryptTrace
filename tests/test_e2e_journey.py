import pytest
import os
import cv2
import numpy as np
import uuid
import hashlib

from app.state import AppState
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.secret_split import split_dek
from app.crypto.symmetric import build_aad, encrypt_document
from app.crypto.manifest import CryptoManifest
from app.protocol.serialization import canonicalize_for_signing
from app.crypto.signatures import SignatureWrapper
from app.protocol.release import ReleaseProtocol
from app.protocol.models import ReleaseRequest
from app.protocol.authentication import ChallengeManager
from app.storage.repositories import ChallengeRepository, ThresholdRepository
from app.storage.database import SessionLocal, Base, engine
from app.demo_providers import StateAuthorizer, StateManifestProvider, StateShareBProvider, StateDocumentProvider, StatePlaintextProcessor
from app.protocol.recipient import RecipientProtocol
from app.evidence.package import assemble_evidence_package
from app.evidence.verifier import verify_evidence_package, VerificationError

def test_full_dynamic_workflow():
    # Setup state
    state = AppState()
    
    # 1. Create 3 recipients dynamically
    recipients = ["A", "B", "C"]
    for r in recipients:
        state.keystore.get_dsa_keypair(r)
        state.keystore.get_kem_keypair(r)
        state.enrolled_recipients.append(r)
        
    # Generate Authority keys
    auth_kem_pk, auth_kem_sk = state.keystore.get_kem_keypair("authority")
    auth_dsa_pk, auth_dsa_sk = state.keystore.get_dsa_keypair("authority")

    class DynamicAuthKEMProvider:
        def get_authority_kem_public_key(self): return auth_kem_pk
        def get_authority_kem_secret_key(self): return auth_kem_sk

    class DynamicRecipientKeyProvider:
        def get_recipient_dsa_pubkey(self, r_id): return state.keystore.get_dsa_keypair(r_id)[0]
        def get_recipient_kem_pubkey(self, r_id): return state.keystore.get_kem_keypair(r_id)[0]
        
    # 2. Create a test document
    doc_id = "test_doc"
    man_id = "test_man"
    
    page = np.ones((500, 800, 3), dtype=np.uint8) * 255
    cv2.putText(page, "TOP SECRET", (150, 160), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
    _, buffer = cv2.imencode('.png', page)
    plaintext = buffer.tobytes()
    
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    nonce = generate_nonce()
    aad = build_aad("1.0", doc_id, "AES-GCM-256")
    ciphertext = encrypt_document(plaintext, dek, nonce, aad)
    
    state.documents[doc_id] = (ciphertext, nonce, aad, plaintext)
    ct_hash = hashlib.sha256(ciphertext).hexdigest()
    
    manifest = CryptoManifest(
        protocol_version="1.0", document_id=doc_id, encryption_algorithm="AES-GCM",
        encryption_version="1.0", kem_algorithm="ML-KEM-768", kem_version="1.0",
        signature_algorithm="ML-DSA-65", signature_version="1.0",
        ciphertext_hash=ct_hash, recipient_share_reference="share_ref",
        sender_identity_reference="sender", manifest_id=man_id, creation_timestamp="0"
    )
    
    state.manifests[man_id] = manifest
    state.share_bs[doc_id] = share_b 
    state.share_as = {doc_id: share_a}
    
    # 3. Release to all 3
    Base.metadata.create_all(engine)
    db_session = SessionLocal()
    chal_repo = ChallengeRepository(db_session)
    thresh_repo = ThresholdRepository(db_session)
    from app.storage.repositories import RateLimitRepository
    rate_limit_repo = RateLimitRepository(db_session)
    chal_mgr = ChallengeManager(chal_repo)
    
    protocol = ReleaseProtocol(
        authorizer=StateAuthorizer(rate_limit_repo),
        manifest_provider=StateManifestProvider(state),
        share_b_provider=StateShareBProvider(state),
        recipient_key_provider=DynamicRecipientKeyProvider(),
        document_provider=StateDocumentProvider(state),
        plaintext_processor=StatePlaintextProcessor(state),
        challenge_manager=chal_mgr,
        threshold_repository=thresh_repo,
        authority_secret_key=auth_dsa_sk,
        authority_key_id="auth1",
        authority_kem_key_provider=DynamicAuthKEMProvider(),
        authority_sig_alg="ML-DSA-65",
    )
    
    sig = SignatureWrapper("ML-DSA-65")
    
    packages = {}
    
    for recip_id in recipients:
        state.current_recipient = recip_id
        req_id = f"req_{recip_id}"
        chal = chal_mgr.create_challenge(req_id, recip_id, "1.0")
        req = ReleaseRequest(
            request_id=req_id, document_id=doc_id, manifest_id=man_id,
            recipient_key_id=recip_id, challenge_id=chal.nonce_hex,
            auth_signature_hex="", share_a_hex=share_a.hex(),
            protocol_version="1.0"
        )
        
        recip_dsa_sk = state.keystore.get_dsa_keypair(recip_id)[1]
        req.auth_signature_hex = sig.sign(canonicalize_for_signing(req), recip_dsa_sk, b"DecryptTrace/RecipientAuthentication/v1").hex()
        
        artifact, statement = protocol.process_release(req, chal)
        entry1 = state.ledger.append(statement.model_dump(mode="json"))
        
        recipient = RecipientProtocol(recip_id, recip_dsa_sk)
        receipt = recipient.acknowledge_delivery(artifact, statement)
        entry2 = state.ledger.append(receipt.model_dump(mode="json"))
        
        state.artifacts[(doc_id, recip_id)] = artifact
        
        
        packages[recip_id] = {
            'manifest': manifest, 'request': req, 'statement': statement, 'receipt': receipt, 'entry': entry1
        }

        
    # Assemble packages with final ledger proof
    final_packages = {}
    for r in recipients:
        data = packages[r]
        entry = data['entry']
        final_packages[r] = assemble_evidence_package(
            manifest=data['manifest'],
            request=data['request'],
            statement=data['statement'],
            receipt=data['receipt'],
            ledger_proof=state.ledger.get_inclusion_proof(entry.seq),
            ledger_seq=entry.seq,
            ledger_entry_hash=entry.entry_hash,
            ledger_prev_hash=entry.prev_hash
        )
        
    packages = final_packages

    # 4. Confirm 3 distinct artifacts generated
    assert len(state.artifacts) == 3
    assert state.watermarked_images["A"] != state.watermarked_images["B"]
    assert state.watermarked_images["B"] != state.watermarked_images["C"]
    
    # 5. Verify all 3 artifacts
    for r in recipients:
        assert verify_evidence_package(
            packages[r], state.ledger.get_root(), auth_dsa_pk, state.keystore.get_dsa_keypair(r)[0]
        ) is True
        
    # 6. Cross-recipient validation failure
    # Substitute A's artifact into B's evidence
    bad_pkg_b = packages["B"].model_copy(deep=True)
    h = hashlib.sha256(state.watermarked_images["A"]).hexdigest()
    bad_pkg_b.receipt.artifact_hash_hex = h
    # This tamper modifies the receipt, so signature check fails!
    with pytest.raises(VerificationError):
        verify_evidence_package(bad_pkg_b, state.ledger.get_root(), auth_dsa_pk, state.keystore.get_dsa_keypair("B")[0])
        
    # 7. Tamper with artifact A
    # If the artifact image changes, its hash won't match the receipt
    modified_img = state.watermarked_images["A"] + b"bad"
    mod_hash = hashlib.sha256(modified_img).hexdigest()
    assert mod_hash != packages["A"].receipt.artifact_hash_hex
    
    # 9. Tamper with evidence
    bad_pkg_a = packages["A"].model_copy(deep=True)
    bad_pkg_a.statement.signature_hex = "00" * 32
    with pytest.raises(VerificationError):
        verify_evidence_package(bad_pkg_a, state.ledger.get_root(), auth_dsa_pk, state.keystore.get_dsa_keypair("A")[0])
        
    # 11. Run watermark robustness tests
    from scripts.test_watermark_robustness import main as run_robustness
    run_robustness()
    
    # Check chain integrity (provenance records)
    assert state.ledger.verify_chain_integrity() is True
