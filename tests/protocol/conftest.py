import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crypto.kem import KEMWrapper
from app.crypto.manifest import CryptoManifest
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.secret_split import split_dek
from app.crypto.signatures import SignatureWrapper
from app.crypto.symmetric import build_aad, encrypt_document
from app.protocol.interfaces import (
    AuthorityKEMKeyProvider,
    ControlledPlaintextProcessor,
    DocumentProvider,
    ManifestProvider,
    RecipientKeyProvider,
    ReleaseAuthorizer,
    ShareBProvider,
)
from app.storage.database import Base
from app.storage.repositories import ChallengeRepository


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.close()

@pytest.fixture
def challenge_repository(db_session):
    return ChallengeRepository(db_session)

from app.storage.repositories import ThresholdRepository


@pytest.fixture
def threshold_repository(db_session):
    return ThresholdRepository(db_session)

class MockAuthorizer(ReleaseAuthorizer):
    def __init__(self, allow=True):
        self.allow = allow
    def authorize(self, *, document_id: str, manifest_id: str, recipient_key_id: str, request_id: str) -> bool:
        return self.allow

class MockManifestProvider(ManifestProvider):
    def __init__(self, manifest):
        self.manifest = manifest
    def get_manifest(self, manifest_id: str):
        return self.manifest if self.manifest and self.manifest.manifest_id == manifest_id else None

class MockShareBProvider(ShareBProvider):
    def __init__(self, share_b):
        self.share_b = share_b
    def get_share_b(self, document_id: str, recipient_key_id: str):
        return self.share_b

class MockRecipientKeyProvider(RecipientKeyProvider):
    def __init__(self, dsa_pk, kem_pk):
        self.dsa_pk = dsa_pk
        self.kem_pk = kem_pk
    def get_recipient_dsa_pubkey(self, recipient_key_id: str):
        return self.dsa_pk
    def get_recipient_kem_pubkey(self, recipient_key_id: str):
        return self.kem_pk

class MockDocumentProvider(DocumentProvider):
    def __init__(self, ciphertext, nonce, aad):
        self.doc_data = (ciphertext, nonce, aad)
    def get_document_ciphertext(self, document_id: str):
        return self.doc_data

class IdentityProcessor(ControlledPlaintextProcessor):
    def process(self, *, document_id: str, session_id: str, recipient_key_id: str, plaintext: bytes, cached_threshold: float | None = None) -> tuple[bytes, float]:
        if cached_threshold is not None:
            return plaintext, cached_threshold
        
        import numpy as np

        from app.watermark import estimate_document_threshold
        # Dummy image for thresholding
        dummy_img = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
        thresh = estimate_document_threshold(document_id, dummy_img, num_trials=2)
        return plaintext, thresh

class MockAuthorityKEMKeyProvider(AuthorityKEMKeyProvider):
    def __init__(self, public_key: bytes, secret_key: bytes):
        self._pk = public_key
        self._sk = secret_key
    def get_authority_kem_public_key(self) -> bytes:
        return self._pk
    def get_authority_kem_secret_key(self) -> bytes:
        return self._sk

@pytest.fixture
def mock_crypto_state():
    # Setup recipient keys
    sig = SignatureWrapper("ML-DSA-65")
    recip_dsa_pk, recip_dsa_sk = sig.generate_keypair()

    kem = KEMWrapper("ML-KEM-768")
    recip_kem_pk, recip_kem_sk = kem.generate_keypair()

    auth_dsa_pk, auth_dsa_sk = sig.generate_keypair()
    auth_kem_pk, auth_kem_sk = kem.generate_keypair()

    dek = generate_dek()
    share_a, share_b = split_dek(dek)

    nonce = generate_nonce()
    aad = build_aad("1.0", "doc1", "AES-GCM-256")
    ciphertext = encrypt_document(b"secret plaintext", dek, nonce, aad)

    manifest = CryptoManifest(
        protocol_version="1.0",
        document_id="doc1",
        encryption_algorithm="AES-GCM-256",
        encryption_version="1.0",
        kem_algorithm="ML-KEM-768",
        kem_version="1.0",
        signature_algorithm="ML-DSA-65",
        signature_version="1.0",
        ciphertext_hash="hash",
        recipient_share_reference="ref",
        sender_identity_reference="sender",
        manifest_id="man1",
        creation_timestamp="0"
    )

    return {
        "recip_dsa_pk": recip_dsa_pk,
        "recip_dsa_sk": recip_dsa_sk,
        "recip_kem_pk": recip_kem_pk,
        "recip_kem_sk": recip_kem_sk,
        "auth_dsa_pk": auth_dsa_pk,
        "auth_dsa_sk": auth_dsa_sk,
        "auth_kem_pk": auth_kem_pk,
        "auth_kem_sk": auth_kem_sk,
        "dek": dek,
        "share_a": share_a,
        "share_b": share_b,
        "doc_data": (ciphertext, nonce, aad),
        "manifest": manifest,
    }
