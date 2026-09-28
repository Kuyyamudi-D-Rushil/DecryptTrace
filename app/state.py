from app.crypto.providers import DevelopmentSoftwareProvider
from app.ledger.core import Ledger

class AppState:
    def __init__(self):
        self.documents = {}
        self.manifests = {}
        self.share_bs = {}
        self.share_as = {}
        self.enrolled_recipients = []
        self.ledger = Ledger() 
        self.artifacts = {}
        self.statements = {}
        self.receipts = {}
        self.evidence_packages = {}
        from app.config.settings import settings
        if settings.environment == "production":
            from app.crypto.kms import ProductionKeystore
            self.keystore = ProductionKeystore(settings.master_key or "default") # Will fail fast at startup if missing
        else:
            self.keystore = DevelopmentSoftwareProvider()

    def save(self, path=None):
        """Keep legacy-demo state alive for the current Streamlit browser session.

        Streamlit reruns a page whenever a widget changes.  The old no-op
        implementation meant each rerun lost the uploaded document and every
        enrolled recipient before the release controls could be used.
        """
        try:
            import streamlit as st
            st.session_state["decrypttrace_demo_state"] = self
        except ModuleNotFoundError:
            # The production API does not use AppState.
            pass
        
    @classmethod
    def load(cls, path=None):
        """Return one state object per Streamlit browser session.

        This class is intentionally for the legacy local demonstration only;
        production state is handled by database repositories.
        """
        try:
            import streamlit as st
            key = "decrypttrace_demo_state"
            if key not in st.session_state:
                st.session_state[key] = cls()
            return st.session_state[key]
        except ModuleNotFoundError:
            return cls()

state = AppState()
