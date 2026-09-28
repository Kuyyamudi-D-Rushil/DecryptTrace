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
