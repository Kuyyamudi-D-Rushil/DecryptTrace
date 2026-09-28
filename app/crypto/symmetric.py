from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import AuthenticationFailure, InvalidKeyError, InvalidNonceError


def encrypt_document(plaintext: bytes, dek: bytes | bytearray, nonce: bytes, aad: bytes) -> bytes:
    if len(dek) != 32:
        raise InvalidKeyError("DEK must be exactly 256 bits (32 bytes).")
    if len(nonce) != 12:
        raise InvalidNonceError("Nonce must be exactly 96 bits (12 bytes).")
    
    aesgcm = AESGCM(bytes(dek))
    return aesgcm.encrypt(nonce, plaintext, aad)

def decrypt_document(ciphertext: bytes, dek: bytes | bytearray, nonce: bytes, aad: bytes) -> bytes:
    if len(dek) != 32:
        raise InvalidKeyError("DEK must be exactly 256 bits (32 bytes).")
    if len(nonce) != 12:
        raise InvalidNonceError("Nonce must be exactly 96 bits (12 bytes).")
        
    aesgcm = AESGCM(bytes(dek))
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as e:
        raise AuthenticationFailure("Ciphertext authentication failed.") from e

from .canonical import canonical_serialize


def build_aad(protocol_version: str, document_id: str, encryption_algorithm: str) -> bytes:
    """
    Explicit AAD construction. Binds protocol version, document ID, and algorithm.
    """
    return f"DecryptTrace|{protocol_version}|{document_id}|{encryption_algorithm}".encode()

def build_canonical_aad(aad_data: dict[str, str]) -> bytes:
    """
    Constructs an explicit canonical AAD using RFC 8785 JCS serialization.
    This replaces delimiter-based constructions with a formal structure.
    """
    return canonical_serialize(aad_data)
