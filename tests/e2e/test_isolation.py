import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.api.app import app
from app.storage.database import SessionLocal, Base, engine
from app.storage.models import KeyShare, AuditLog
from app.config.settings import settings

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    settings.environment = "production"
    # Ensure master key is set for production
    settings.master_key = "test_master_key_12345678901234567890"
    from app.state import state
    from app.crypto.kms import ProductionKeystore
    state.keystore = ProductionKeystore(settings.master_key)
    
    yield
    Base.metadata.drop_all(bind=engine)
    settings.environment = "development"

def test_shares_are_encrypted_in_db():
    from app.crypto.randomness import generate_dek
    from app.crypto.secret_split import split_dek
    
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    
    db = SessionLocal()
    from app.state import state
    
    # Simulate saving Share B
    auth_share_val = state.keystore.encrypt_data(share_b)
    auth_share = KeyShare(
        document_id="doc_123",
        recipient_id="AUTHORITY",
        share_b_hex=auth_share_val
    )
    db.add(auth_share)
    db.commit()
    
    # Retrieve from DB directly
    record = db.query(KeyShare).filter(KeyShare.recipient_id == "AUTHORITY").first()
    
    # Prove it's not raw hex
    assert record.share_b_hex != share_b.hex()
    
    # Prove it's decryptable
    decrypted = state.keystore.decrypt_data(record.share_b_hex)
    assert decrypted == share_b
    db.close()
