from typing import Protocol

class HardwareBackedProvider(Protocol):
    """
    Interface for integrating HSMs or KMS (e.g. AWS KMS, HashiCorp Vault)
    to perform cryptographic operations securely without exposing private keys.
    """
    def sign(self, data: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...
    def get_public_key(self) -> bytes: ...

class LocalDevKMS(HardwareBackedProvider):
    """
    A fallback implementation for local development simulating a KMS.
    DO NOT USE IN PRODUCTION.
    """
    def __init__(self, private_key: bytes, public_key: bytes):
        self._private_key = private_key
        self._public_key = public_key

    def sign(self, data: bytes) -> bytes:
        # Simulate signing operation
        return b"signature_over_" + data

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Simulate decryption operation
        return ciphertext.replace(b"encrypted_", b"")

    def get_public_key(self) -> bytes:
        return self._public_key
