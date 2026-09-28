import streamlit as st
import numpy as np

from app.forensics.matcher import match_artifact
from app.state import AppState
from app.watermark.core import derive_watermark_seed

st.set_page_config(page_title="Investigator | DecryptTrace", layout="wide")
st.title("Forensic Investigator")

state = AppState.load()

st.write("Upload a leaked document (image) to trace it back to the original recipient.")

if not state.documents:
    st.warning("No documents exist in state. Cannot trace.")
else:
    doc_id = st.selectbox("Select which document this leak belongs to:", list(state.documents.keys()))
    
    # We allow them to either pick a generated artifact or upload one (e.g. from watermark robustness test)
    leak_source = st.radio("Leak Source", ["Simulate from State", "Upload Leaked File"])
    
    leaked_bytes = None
    if leak_source == "Simulate from State":
        avail = [r for (d, r) in state.artifacts.keys() if d == doc_id]
        if avail:
            leaked_from = st.selectbox("Simulate leak from:", avail)
            leaked_bytes = state.watermarked_images.get(leaked_from)
        else:
            st.info("No artifacts available for this document.")
    else:
        uploaded_leak = st.file_uploader("Upload image", type=["png", "jpg", "jpeg"])
        if uploaded_leak:
            leaked_bytes = uploaded_leak.read()

    if leaked_bytes and st.button("Run Forensic Matcher"):
        st.image(leaked_bytes, caption="Leaked Document")
        
        with st.spinner("Extracting watermarks and computing correlations..."):
            # Build candidate pool from ALL enrolled recipients for this doc
            pool = {}
            for r_id in state.enrolled_recipients:
                pool[r_id] = derive_watermark_seed(doc_id, r_id)
                
            result = match_artifact(leaked_bytes, pool, absolute_threshold=0.005, relative_margin=0.002)
            
            st.subheader("Results")
            if result.status == "MATCH":
                st.success(f"Match found! Likely culprit: **{result.best_match_key_id}**")
            elif result.status == "INCONCLUSIVE":
                st.warning("Inconclusive. Collusion or high noise detected.")
            else:
                st.error("No Match.")
                
            st.write("Correlation Scores:")
            st.json(result.scores)
