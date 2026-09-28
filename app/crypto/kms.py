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
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ProductionKeystore:
    def __init__(self, master_key: str):
        # We assume master_key is passed as string from env
        import hashlib
        self.key = hashlib.sha256(master_key.encode()).digest()
        self.aesgcm = AESGCM(self.key)
        
    def encrypt_data(self, plaintext: bytes) -> str:
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext, None)
        return json.dumps({"n": nonce.hex(), "c": ct.hex()})
        
    def decrypt_data(self, encrypted_json: str) -> bytes:
        data = json.loads(encrypted_json)
        nonce = bytes.fromhex(data["n"])
        ct = bytes.fromhex(data["c"])
        return self.aesgcm.decrypt(nonce, ct, None)
