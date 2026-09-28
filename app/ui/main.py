import streamlit as st

st.set_page_config(page_title="DecryptTrace", layout="wide")

st.warning("⚠️ DEPRECATED: This Streamlit interface is for legacy demonstration only. Production deployments MUST use the secure REST API.", icon="⚠️")

# This demo uses mock implementations of providers that are no longer supported
# in the production backend.


st.title("DecryptTrace MVP Dashboard")

st.markdown("""
Welcome to the DecryptTrace interactive demo.

**DecryptTrace** is an enterprise-grade document release and tracking system designed to enforce accountability in sensitive document sharing using Post-Quantum Cryptography (PQC) and a permissioned ledger.

### Navigation
Please use the sidebar to navigate through the distinct operational roles:
1. **Sender:** Encrypts the document, splits the DEK, and provisions the release.
2. **Recipient:** Requests release and verifies the watermarked artifact delivery.
3. **Investigator:** Extracts watermarks from leaked documents to trace the source.
4. **Verifier:** Independently verifies cryptographic evidence packages.
""")
