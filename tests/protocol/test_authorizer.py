import pytest
import time
from app.demo_providers import StateAuthorizer
from app.storage.repositories import RateLimitRepository
from app.storage.models import ReleaseEvent
from app.config.settings import settings
from app.protocol.errors import RateLimitExceeded
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.storage.database import Base

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_rate_limit_enforced_and_resets(db_session):
    repo = RateLimitRepository(db_session)
    authorizer = StateAuthorizer(rate_limit_repo=repo)
    
    doc_id = "doc_limit_1"
    recip_id = "recip_limit_1"
    
    # Save original settings
    orig_max = settings.rate_limit_max_releases
    orig_win = settings.rate_limit_window_seconds
    
    try:
        # Configure small limits for test
        settings.rate_limit_max_releases = 2
        settings.rate_limit_window_seconds = 60
        
        # Request 1: Succeeds
        assert authorizer.authorize(document_id=doc_id, manifest_id="man1", recipient_key_id=recip_id, request_id="req1") is True
        
        # Request 2: Succeeds
        assert authorizer.authorize(document_id=doc_id, manifest_id="man1", recipient_key_id=recip_id, request_id="req2") is True
        
        # Request 3: Fails (Limit Exceeded)
        with pytest.raises(RateLimitExceeded):
            authorizer.authorize(document_id=doc_id, manifest_id="man1", recipient_key_id=recip_id, request_id="req3")
            
        # Simulate time passing beyond the window
        # We can do this by modifying the timestamp of the stored events
        events = db_session.query(ReleaseEvent).all()
        for event in events:
            event.timestamp = time.time() - 100 # Put it in the past, outside the 60s window
        db_session.commit()
        
        # Request 4: Succeeds again after window reset
        assert authorizer.authorize(document_id=doc_id, manifest_id="man1", recipient_key_id=recip_id, request_id="req4") is True
        
    finally:
        # Restore settings
        settings.rate_limit_max_releases = orig_max
        settings.rate_limit_window_seconds = orig_win
