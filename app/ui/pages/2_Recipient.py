import streamlit as st
import cv2
import numpy as np
from app.state import AppState

st.set_page_config(page_title="Recipient | DecryptTrace", layout="wide")
st.title("Recipient View")

state = AppState.load()

if not state.artifacts:
    st.warning("No releases processed yet. Complete a release on the Sender page first.")
else:
    # Build a list of available (doc, recip) combinations
    options = list(state.artifacts.keys())
    # Format options for selectbox
    def format_opt(opt):
        return f"Document: {opt[0]} | Recipient: {opt[1]}"
        
    selected = st.selectbox("Select Released Artifact", options, format_func=format_opt)
    doc_id, recipient_id = selected

    st.success(f"Document released and delivered to {recipient_id}.")
    st.subheader("Release Artifact")
    artifact = state.artifacts[selected]
    st.json(artifact.model_dump())
    
    st.subheader("Authority Release Statement")
    statement = state.statements[selected]
    st.json(statement.model_dump())
    
    st.subheader("Recipient Receipt")
    receipt = state.receipts[selected]
    st.json(receipt.model_dump())
    
    st.subheader("Watermarked Document")
    if recipient_id in state.watermarked_images:
        img_bytes = state.watermarked_images[recipient_id]
        st.image(img_bytes, caption=f"Watermarked copy for {recipient_id}")
