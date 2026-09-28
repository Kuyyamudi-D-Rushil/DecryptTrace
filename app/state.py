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
        # Deprecated: Persistence moved to database repositories in Milestone 1.
        pass
        
    @classmethod
    def load(cls, path=None):
        # Deprecated: Persistence moved to database repositories in Milestone 1.
        return cls()

state = AppState()
