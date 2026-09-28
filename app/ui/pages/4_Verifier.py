import streamlit as st
import json
import hashlib
from app.evidence.package import EvidencePackage
from app.evidence.verifier import VerificationError, verify_evidence_package
from app.state import AppState

st.set_page_config(page_title="Verifier | DecryptTrace", layout="wide")
st.title("Standalone Offline Verifier")

state = AppState.load()

st.write("Independently verify cryptographic evidence packages.")

if not state.evidence_packages:
    st.warning("No evidence packages generated yet. Do a release on the Sender page.")
else:
    options = list(state.evidence_packages.keys())
    def format_opt(opt):
        return f"Document: {opt[0]} | Recipient: {opt[1]}"
        
    selected = st.selectbox("Select Evidence Package to Verify", options, format_func=format_opt)
    doc_id, recip_id = selected

    pkg_dict = state.evidence_packages[selected]
    pkg = EvidencePackage(**pkg_dict)
    
    st.subheader("Evidence Package contents")
    with st.expander("View JSON"):
        st.json(pkg.model_dump(mode="json"))
        
    tamper_mode = st.radio("Tamper Testing", [
        "Clean", 
        "Corrupt Artifact Hash in Receipt", 
        "Corrupt Authority Signature",
        "Corrupt Recipient Signature",
        "Corrupt Ledger Entry Hash"
    ])
    
    if st.button("Verify Evidence Package"):
        # We simulate the verifier having the trusted public material:
        trusted_ledger_root = state.ledger.get_root()
        auth_dsa_pk = state.keystore.get_dsa_keypair("authority")[0]
        recip_dsa_pk = state.keystore.get_dsa_keypair(recip_id)[0]
        
        test_pkg = pkg.model_copy(deep=True)
        
        if tamper_mode == "Corrupt Artifact Hash in Receipt":
            test_pkg.receipt.artifact_hash_hex = "deadbeef"
        elif tamper_mode == "Corrupt Authority Signature":
            test_pkg.statement.authority_signature_hex = "00" * 32
        elif tamper_mode == "Corrupt Recipient Signature":
            test_pkg.receipt.recipient_signature_hex = "00" * 32
        elif tamper_mode == "Corrupt Ledger Entry Hash":
            test_pkg.ledger_entry_hash = "deadbeef"
            
        try:
            verify_evidence_package(
                pkg=test_pkg,
                trusted_ledger_root=trusted_ledger_root,
                authority_public_key=auth_dsa_pk,
                recipient_public_key=recip_dsa_pk
            )
            st.success("Verification Passed! All cryptographic signatures, hashes, and inclusion proofs are valid.")
        except VerificationError as e:
            st.error(f"Verification Failed: {e}")
            
    # Also verify the artifact matches
    st.subheader("Verify Artifact File")
    artifact_file = st.file_uploader("Upload Artifact Image to verify against receipt", type=["png", "jpg", "jpeg"])
    if artifact_file:
        img_bytes = artifact_file.read()
        h = hashlib.sha256(img_bytes).hexdigest()
        if h == pkg.receipt.artifact_hash_hex:
            st.success("Artifact file hash MATCHES the Receipt!")
        else:
            st.error(f"Hash mismatch!\nExpected: {pkg.receipt.artifact_hash_hex}\nActual: {h}")
