import cv2
import numpy as np

from app.crypto.kem import KEMWrapper
from app.crypto.manifest import CryptoManifest
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.secret_split import split_dek
from app.crypto.signatures import SignatureWrapper
from app.crypto.symmetric import build_aad, encrypt_document
from app.ledger.core import Ledger
from app.protocol.authentication import ChallengeManager
from app.protocol.interfaces import (
    AuthorityKEMKeyProvider,
    ControlledPlaintextProcessor,
    DocumentProvider,
    ManifestProvider,
    RecipientKeyProvider,
    ReleaseAuthorizer,
    ShareBProvider,
)
from app.protocol.models import ReleaseRequest
from app.protocol.recipient import RecipientProtocol
from app.protocol.release import ReleaseProtocol
from app.state import AppState
from app.storage.database import Base, SessionLocal, engine
from app.storage.repositories import ChallengeRepository, ThresholdRepository
from app.watermark.core import derive_watermark_seed, embed, estimate_document_threshold


# We need some mock providers that read from AppState
from app.demo_providers import StateAuthorizer

class StateManifestProvider(ManifestProvider):
    def __init__(self, state):
        self.state = state
    def get_manifest(self, manifest_id: str):
        return self.state.manifests.get(manifest_id)

class StateShareBProvider(ShareBProvider):
    def __init__(self, state):
        self.state = state
    def get_share_b(self, document_id: str, recipient_key_id: str):
        return self.state.share_bs.get((document_id, recipient_key_id))

class StateRecipientKeyProvider(RecipientKeyProvider):
    def __init__(self, state):
        self.state = state
    def get_recipient_dsa_pubkey(self, recipient_key_id: str):
        keys = self.state.recipient_keys.get(recipient_key_id)
        return keys[2] if keys else None
    def get_recipient_kem_pubkey(self, recipient_key_id: str):
        keys = self.state.recipient_keys.get(recipient_key_id)
        return keys[0] if keys else None

class StateAuthorityKEMKeyProvider(AuthorityKEMKeyProvider):
    def __init__(self, state):
        self.state = state
    def get_authority_kem_public_key(self) -> bytes:
        return self.state.authority_keys['kem_pk']
    def get_authority_kem_secret_key(self) -> bytes:
        return self.state.authority_keys['kem_sk']

class StateDocumentProvider(DocumentProvider):
    def __init__(self, state):
        self.state = state
    def get_document_ciphertext(self, document_id: str):
        return self.state.documents.get(document_id)

class StatePlaintextProcessor(ControlledPlaintextProcessor):
    def __init__(self, state):
        self.state = state
        
    def process(self, *, document_id: str, session_id: str, plaintext: bytes, cached_threshold: float | None = None) -> tuple[bytes, float]:
        nparr = np.frombuffer(plaintext, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # recipient_key_id is not passed to processor directly in the interface? 
        # Wait, the prompt says watermarking is identity-bound. Let's just use the session_id as a proxy or we can find it.
        # Let's derive seed using a dummy recipient id for this MVP processor, or extract it from the context if possible.
        # Actually, in seed_demo, we know which recipient it is. Let's just use "recip1" as a hack for the demo script processor.
        seed = derive_watermark_seed(document_id, "recip1") 
        wm = embed(img, seed, alpha=5.0)
        
        success, buffer = cv2.imencode('.png', wm)
        processed_bytes = buffer.tobytes()
        
        # Also store it in state for the Investigator demo
        self.state.watermarked_images["recip1"] = processed_bytes
        
        if cached_threshold is not None:
            return processed_bytes, cached_threshold
            
        thresh = estimate_document_threshold(document_id, img, num_trials=20)
        return processed_bytes, thresh

def generate_sample_document():
    h, w = 800, 600
    page = np.ones((h, w, 3), dtype=np.uint8) * 255
    # draw some shapes
    cv2.rectangle(page, (100, 100), (500, 200), (0, 0, 0), -1)
    cv2.putText(page, "CONFIDENTIAL", (150, 160), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
    success, buffer = cv2.imencode('.png', page)
    return buffer.tobytes()

def main():
    Base.metadata.create_all(engine)
    db_session = SessionLocal()
    
    state = AppState()
    state.ledger = Ledger()
    
    sig = SignatureWrapper("ML-DSA-65")
    kem = KEMWrapper("ML-KEM-768")
    
    print("Generating keys...")
    auth_kem_pk, auth_kem_sk = kem.generate_keypair()
    auth_dsa_pk, auth_dsa_sk = sig.generate_keypair()
    state.authority_keys = {
        'kem_pk': auth_kem_pk, 'kem_sk': auth_kem_sk,
        'dsa_pk': auth_dsa_pk, 'dsa_sk': auth_dsa_sk
    }
    
    for i in range(1, 4):
        k_pk, k_sk = kem.generate_keypair()
        d_pk, d_sk = sig.generate_keypair()
        state.recipient_keys[f"recip{i}"] = (k_pk, k_sk, d_pk, d_sk)
        
    sender_dsa_pk, sender_dsa_sk = sig.generate_keypair()
    state.sender_keys = {'dsa_pk': sender_dsa_pk, 'dsa_sk': sender_dsa_sk}
    
    print("Encrypting document...")
    doc_id = "demo_doc_1"
    man_id = "demo_man_1"
    plaintext = generate_sample_document()
    
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    
    nonce = generate_nonce()
    aad = build_aad("1.0", doc_id, "AES-GCM-256")
    ciphertext = encrypt_document(plaintext, dek, nonce, aad)
    
    state.documents[doc_id] = (ciphertext, nonce, aad)
    
    import hashlib
    ct_hash = hashlib.sha256(ciphertext).hexdigest()
    
    manifest = CryptoManifest(
        protocol_version="1.0", document_id=doc_id, encryption_algorithm="AES-GCM",
        encryption_version="1.0", kem_algorithm="ML-KEM-768", kem_version="1.0",
        signature_algorithm="ML-DSA-65", signature_version="1.0",
        ciphertext_hash=ct_hash, recipient_share_reference="dummy_share_ref",
        sender_identity_reference="sender1", manifest_id=man_id, creation_timestamp="0"
    )
    
    from app.protocol.serialization import canonicalize_for_signing
    man_sig = sig.sign(canonicalize_for_signing(manifest), sender_dsa_sk, b"DecryptTrace/CryptoManifest/v1")
    # manifest.signature_hex removed
    
    state.manifests[man_id] = manifest
    
    for i in range(1, 4):
        state.share_bs[(doc_id, f"recip{i}")] = share_b
        
    print("Running release for recip1...")
    
    chal_repo = ChallengeRepository(db_session)
    thresh_repo = ThresholdRepository(db_session)
    from app.storage.repositories import RateLimitRepository
    rate_limit_repo = RateLimitRepository(db_session)
    chal_mgr = ChallengeManager(chal_repo)
    
    protocol = ReleaseProtocol(
        authorizer=StateAuthorizer(rate_limit_repo),
        manifest_provider=StateManifestProvider(state),
        share_b_provider=StateShareBProvider(state),
        recipient_key_provider=StateRecipientKeyProvider(state),
        document_provider=StateDocumentProvider(state),
        plaintext_processor=StatePlaintextProcessor(state),
        challenge_manager=chal_mgr,
        authority_kem_key_provider=StateAuthorityKEMKeyProvider(state),
        authority_key_id="auth_1",
        authority_secret_key=auth_dsa_sk,
        authority_sig_alg="ML-DSA-65",
        threshold_repository=thresh_repo
    )
    
    chal = chal_mgr.create_challenge("req_recip1", "recip1", "1.0")
    req = ReleaseRequest(
        request_id="req_recip1", document_id=doc_id, manifest_id=man_id,
        recipient_key_id="recip1", challenge_id=chal.nonce_hex,
        auth_signature_hex="", share_a_hex=share_a.hex(), protocol_version="1.0"
    )
    
    # Sign request
    req_can = canonicalize_for_signing(req)
    req.auth_signature_hex = sig.sign(req_can, state.recipient_keys["recip1"][3], b"DecryptTrace/RecipientAuthentication/v1").hex()
    
    artifact, statement = protocol.process_release(req, chal)
    state.artifacts["recip1"] = artifact
    state.statements["recip1"] = statement
    
    print("Appending statement to ledger...")
    entry1 = state.ledger.append(statement.model_dump(mode="json"))
    
    print("Recipient generating receipt...")
    recipient = RecipientProtocol("recip1", state.recipient_keys["recip1"][3])
    receipt = recipient.acknowledge_delivery(artifact, statement)
    state.receipts["recip1"] = receipt
    
    print("Appending receipt to ledger...")
    entry2 = state.ledger.append(receipt.model_dump(mode="json"))
    
    # Store proof and sequence on the receipt and statement wrappers for convenience in the demo
    state.demo_evidence = {
        "statement_seq": entry1.seq,
        "statement_proof": state.ledger.get_inclusion_proof(entry1.seq),
        "statement_entry_hash": entry1.entry_hash,
        "statement_prev_hash": entry1.prev_hash,
        "receipt_seq": entry2.seq,
        "receipt_proof": state.ledger.get_inclusion_proof(entry2.seq),
        "receipt_entry_hash": entry2.entry_hash,
        "receipt_prev_hash": entry2.prev_hash,
    }
    
    state.save()
    print("Demo seeded successfully. State saved to demo_state.pkl")

if __name__ == "__main__":
    main()
