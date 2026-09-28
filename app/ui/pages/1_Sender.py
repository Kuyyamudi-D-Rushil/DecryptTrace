import streamlit as st
import uuid
import cv2
import numpy as np

from app.state import AppState
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.secret_split import split_dek
from app.crypto.symmetric import build_aad, encrypt_document
from app.crypto.manifest import CryptoManifest
from app.protocol.serialization import canonicalize_for_signing
import hashlib

st.set_page_config(page_title="Sender | DecryptTrace", layout="wide")
st.title("Sender Workflow")

state = AppState.load()

# 1. Document Upload
st.header("1. Upload Document")
uploaded_file = st.file_uploader("Choose a document (Image)", type=["png", "jpg", "jpeg"])
if uploaded_file is not None:
    doc_id = st.text_input("Document ID", value=f"doc_{uuid.uuid4().hex[:8]}")
    if st.button("Encrypt & Store Document"):
        plaintext = uploaded_file.read()
        
        # PQC signature for sender
        sender_kem_pk, sender_kem_sk = state.keystore.get_kem_keypair("sender")
        sender_dsa_pk, sender_dsa_sk = state.keystore.get_dsa_keypair("sender")
        
        dek = generate_dek()
        share_a, share_b = split_dek(dek)
        nonce = generate_nonce()
        aad = build_aad("1.0", doc_id, "AES-GCM-256")
        ciphertext = encrypt_document(plaintext, dek, nonce, aad)
        
        # We store the plaintext_preview for the investigator demo only, normally it's discarded
        state.documents[doc_id] = (ciphertext, nonce, aad, plaintext)
        
        man_id = f"man_{uuid.uuid4().hex[:8]}"
        ct_hash = hashlib.sha256(ciphertext).hexdigest()
        
        manifest = CryptoManifest(
            protocol_version="1.0", document_id=doc_id, encryption_algorithm="AES-GCM",
            encryption_version="1.0", kem_algorithm="ML-KEM-768", kem_version="1.0",
            signature_algorithm="ML-DSA-65", signature_version="1.0",
            ciphertext_hash=ct_hash, recipient_share_reference="share_ref",
            sender_identity_reference="sender", manifest_id=man_id, creation_timestamp="0"
        )
        
        # Since manifest doesn't hold signature, we just save it. (In a real protocol it's signed & wrapped).
        state.manifests[man_id] = manifest
        # Store share_a and share_b for all future recipients for this doc
        state.share_bs[doc_id] = share_b 
        if not hasattr(state, "share_as"): state.share_as = {}
        state.share_as[doc_id] = share_a
        
        state.save()
        st.success(f"Document {doc_id} securely encrypted and stored!")

# 2. Recipient Enrollment
st.header("2. Enroll Recipients")
new_recip = st.text_input("New Recipient ID")
if st.button("Enroll Recipient"):
    if new_recip and new_recip not in state.enrolled_recipients:
        # Generate and store their PQC keys via provider
        state.keystore.get_dsa_keypair(new_recip)
        state.keystore.get_kem_keypair(new_recip)
        state.enrolled_recipients.append(new_recip)
        state.save()
        st.success(f"Recipient '{new_recip}' enrolled successfully with PQC identities.")
    elif new_recip in state.enrolled_recipients:
        st.warning("Recipient already enrolled.")
        
st.write("Current Recipients:", state.enrolled_recipients)

# 3. Execute Release
st.header("3. Execute Release")
if not state.documents:
    st.info("Upload a document first.")
else:
    selected_doc = st.selectbox("Select Document", list(state.documents.keys()))
    selected_recipients = st.multiselect("Select Recipients for Release", state.enrolled_recipients)
    
    if st.button("Execute Release to Selected Recipients"):
        if not selected_recipients:
            st.error("Select at least one recipient.")
        else:
            with st.spinner("Executing secure release pipeline..."):
                from app.protocol.release import ReleaseProtocol
                from app.protocol.models import ReleaseRequest
                from app.protocol.authentication import ChallengeManager
                from app.storage.repositories import ChallengeRepository, ThresholdRepository
                from app.storage.database import SessionLocal, Base, engine
                from app.demo_providers import StateAuthorizer, StateManifestProvider, StateShareBProvider, StateDocumentProvider, StatePlaintextProcessor
                from app.crypto.signatures import SignatureWrapper
                from app.protocol.recipient import RecipientProtocol
                from app.evidence.package import assemble_evidence_package

                Base.metadata.create_all(engine)
                db_session = SessionLocal()
                chal_repo = ChallengeRepository(db_session)
                thresh_repo = ThresholdRepository(db_session)
                from app.storage.repositories import RateLimitRepository
                rate_limit_repo = RateLimitRepository(db_session)
                chal_mgr = ChallengeManager(chal_repo)
                
                # Find manifest
                man_id = next(m_id for m_id, m in state.manifests.items() if m.document_id == selected_doc)
                share_b = state.share_bs[selected_doc]
                share_a = state.share_as[selected_doc]
                
                auth_kem_pk, auth_kem_sk = state.keystore.get_kem_keypair("authority")
                auth_dsa_pk, auth_dsa_sk = state.keystore.get_dsa_keypair("authority")
                
                # Wrap the authority provider
                class DynamicAuthKEMProvider:
                    def get_authority_kem_public_key(self): return auth_kem_pk
                    def get_authority_kem_secret_key(self): return auth_kem_sk

                # Wrap the recipient provider
                class DynamicRecipientKeyProvider:
                    def get_recipient_dsa_pubkey(self, r_id): return state.keystore.get_dsa_keypair(r_id)[0]
                    def get_recipient_kem_pubkey(self, r_id): return state.keystore.get_kem_keypair(r_id)[0]

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
                
                for recip_id in selected_recipients:
                    state.current_recipient = recip_id
                    # Create Request
                    req_id = f"req_{uuid.uuid4().hex[:8]}"
                    chal = chal_mgr.create_challenge(req_id, recip_id, "1.0")
                    req = ReleaseRequest(
                        request_id=req_id, document_id=selected_doc, manifest_id=man_id,
                        recipient_key_id=recip_id, challenge_id=chal.nonce_hex,
                        auth_signature_hex="", share_a_hex=share_a.hex(),
                        protocol_version="1.0"
                    )
                    
                    recip_dsa_sk = state.keystore.get_dsa_keypair(recip_id)[1]
                    req_can = canonicalize_for_signing(req)
                    req.auth_signature_hex = sig.sign(req_can, recip_dsa_sk, b"DecryptTrace/RecipientAuthentication/v1").hex()
                    
                    try:
                        artifact, statement = protocol.process_release(req, chal)
                        
                        # Ledger append Statement
                        entry1 = state.ledger.append(statement.model_dump(mode="json"))
                        
                        # Recipient receives and receipts
                        recipient = RecipientProtocol(recip_id, recip_dsa_sk)
                        receipt = recipient.acknowledge_delivery(artifact, statement)
                        
                        # Ledger append Receipt
                        entry2 = state.ledger.append(receipt.model_dump(mode="json"))
                        
                        state.artifacts[(selected_doc, recip_id)] = artifact
                        state.statements[(selected_doc, recip_id)] = statement
                        state.receipts[(selected_doc, recip_id)] = receipt
                        
                        # Assemble Evidence Package
                        pkg = assemble_evidence_package(
                            manifest=state.manifests[man_id],
                            request=req,
                            statement=statement,
                            receipt=receipt,
                            ledger_proof=state.ledger.get_inclusion_proof(entry1.seq),
                            ledger_seq=entry1.seq,
                            ledger_entry_hash=entry1.entry_hash,
                            ledger_prev_hash=entry1.prev_hash
                        )
                        state.evidence_packages[(selected_doc, recip_id)] = pkg.model_dump(mode="json")
                        
                        st.success(f"Released to {recip_id}. Artifact, watermark, and provenance generated.")
                        
                    except Exception as e:
                        st.error(f"Failed to release to {recip_id}: {e}")
                
                state.save()
