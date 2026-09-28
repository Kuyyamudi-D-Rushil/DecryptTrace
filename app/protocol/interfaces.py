from typing import Protocol

from app.crypto.manifest import CryptoManifest


class ReleaseAuthorizer(Protocol):
    """
    WARNING: No production implementation exists yet.
    A production implementation requires the offline CA / key-registration mechanism
    planned for the air-gap deployment phase. Until then, only test mocks should
    implement this interface. Wiring a mock or any non-CA-backed implementation
    into a reachable API endpoint is unsafe and must not happen.
    """
    def authorize(self, *, document_id: str, manifest_id: str, recipient_key_id: str, request_id: str) -> bool:
        ...

class ManifestProvider(Protocol):
    def get_manifest(self, manifest_id: str) -> CryptoManifest | None:
        ...

class ShareBProvider(Protocol):
    def get_share_b(self, document_id: str, recipient_key_id: str) -> bytes | None:
        ...

class RecipientKeyProvider(Protocol):
    """
    WARNING: No production implementation exists yet.
    A production implementation requires the offline CA / key-registration mechanism
    planned for the air-gap deployment phase. Until then, only test mocks should
    implement this interface. Wiring a mock or any non-CA-backed implementation
    into a reachable API endpoint is unsafe and must not happen.
    """
    def get_recipient_dsa_pubkey(self, recipient_key_id: str) -> bytes | None:
        ...
    def get_recipient_kem_pubkey(self, recipient_key_id: str) -> bytes | None:
        ...


class DocumentProvider(Protocol):
    def get_document_ciphertext(self, document_id: str) -> tuple[bytes, bytes, bytes] | None:
        ... # returns (ciphertext, nonce, aad)

class ControlledPlaintextProcessor(Protocol):
    def process(self, *, document_id: str, session_id: str, recipient_key_id: str, plaintext: bytes, cached_threshold: float | None = None) -> tuple[bytes, float]:
        ...

class AuthorityKEMKeyProvider(Protocol):
    """Provides the Authority's ML-KEM keypair for envelope operations."""

    def get_authority_kem_public_key(self) -> bytes:
        """Return the Authority's ML-KEM public key (for recipient use when sealing)."""
        ...

    def get_authority_kem_secret_key(self) -> bytes:
        """Return the Authority's ML-KEM secret key (for Authority use when opening)."""
        ...
