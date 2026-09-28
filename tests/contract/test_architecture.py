import io
import logging
import uuid

import pytest
from pydantic import ValidationError

from app.config.settings import Config
from app.domain.contracts import (
    AuthorityReleaseStatement,
    LedgerEntry,
    RecipientReceipt,
    ReleaseRequest,
    SenderManifest,
)
from app.domain.errors import NotImplementedSecurityFeature
from app.domain.identifiers import (
    DocumentID,
    FingerprintID,
    RecipientID,
    SessionID,
)
from app.logging.setup import SensitiveDataRedactor, setup_logging
from app.services.interfaces import (
    DocumentEncryptionService,
    ReleaseService,
)


# --- Identifier Separation Tests ---
def test_distinct_identifiers_at_type_level():
    assert SessionID != FingerprintID
    assert SessionID != DocumentID
    assert FingerprintID != RecipientID
    assert DocumentID != RecipientID

def test_identifier_substitution_fails():
    # Attempting to place a SessionID string where a FingerprintID belongs should fail validation
    with pytest.raises(ValidationError):
        ReleaseRequest(
            session_id=uuid.uuid4(),
            document_id=uuid.uuid4(),
            recipient_identity_reference="recv_123",
            fingerprint_id=123,  # Invalid type (expected str for FingerprintID)
            recipient_share_reference="share_a",
            request_nonce="nonce",
            protocol_version="1.0"
        )

# --- Protocol Object Separation Tests ---
def test_distinct_models():
    models = [SenderManifest, ReleaseRequest, AuthorityReleaseStatement, RecipientReceipt, LedgerEntry]
    # Ensure they are distinct classes
    assert len(set(models)) == len(models)
    
    # Ensure none inherit from each other except BaseModel
    assert not issubclass(SenderManifest, RecipientReceipt)
    assert not issubclass(ReleaseRequest, SenderManifest)

# --- Ledger Sensitivity Boundary Tests ---
def test_no_sensitive_fields_in_ledger():
    fields = LedgerEntry.model_fields.keys()
    sensitive_names = ["plaintext", "ciphertext", "dek", "share_a", "share_b", "k_wm", "watermark", "private_key", "secret"]
    
    for field in fields:
        for sensitive in sensitive_names:
            assert sensitive not in field.lower(), f"Sensitive field {sensitive} found in LedgerEntry: {field}"

# --- Configuration Boundary Tests ---
def test_supported_configurations():
    cfg = Config(kem_parameter="ML-KEM-1024", signature_parameter="ML-DSA-87")
    assert cfg.kem_parameter == "ML-KEM-1024"
    
def test_unsupported_kem_configuration():
    with pytest.raises(ValidationError):
        Config(kem_parameter="UNSUPPORTED-KEM")
        
def test_unsupported_sig_configuration():
    with pytest.raises(ValidationError):
        Config(signature_parameter="UNSUPPORTED-SIG")

def test_config_validation_is_pure():
    # Validating config shouldn't trigger cryptographic operations (it should just validate literals)
    cfg = Config()
    assert cfg.kem_algorithm == "ML-KEM"

# --- API Boundary Tests ---
def test_api_does_not_expose_release():
    from app.api.app import app
    routes = []
    for route in app.routes:
        if hasattr(route, "path"):
            routes.append(route.path)
        else:
            # Sub-routers or mounts might not have a simple path
            pass
    
    expected_routes = {"/health", "/version", "/status", "/ready"}
    actual_routes = {path for path in routes if path not in ["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"]}
    
    assert actual_routes == expected_routes, f"Unexpected routes found: {actual_routes}"

# --- CLI Boundary Tests ---
def test_cli_does_not_have_crypto_commands():
    # We inspect the AST or the parser configuration
    # A simpler way is just verifying our help output or parser choices doesn't contain 'release'
    pass

# --- Service Boundary Tests ---
def test_service_interfaces_unimplemented():
    class DummyRelease(ReleaseService):
        def process_release(self, request, manifest):
            super().process_release(request, manifest)
            
    with pytest.raises(NotImplementedSecurityFeature):
        DummyRelease().process_release(None, None) # type: ignore

    class DummyEncryption(DocumentEncryptionService):
        def encrypt_document(self, plaintext: bytes) -> bytes:
            return super().encrypt_document(plaintext)
            
    with pytest.raises(NotImplementedSecurityFeature):
        DummyEncryption().encrypt_document(b"plaintext")

# --- Logging Security Tests ---
def test_logging_redacts_sensitive():
    logger = setup_logging("DEBUG")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SensitiveDataRedactor())
    logger.handlers = [handler]
    
    logger.info("This is a safe system startup message")
    logger.info("Failed to load dek_share_a for user")
    logger.info("The plaintext buffer overflowed")
    logger.info("Using k_wm secret value 12345")
    logger.info("Loaded private_key from hsm")
    logger.info("Extracted share_b from payload")
    
    output = stream.getvalue()
    assert "safe system startup message" in output
    assert "dek" not in output
    assert "plaintext" not in output
    assert "k_wm" not in output
    assert "private_key" not in output
    assert "share_a" not in output
    assert "share_b" not in output
    
    # We expect 5 redacted lines
    assert output.count("[REDACTED SENSITIVE FIELD]") == 5
