from app.crypto.kdf import derive_key
from app.crypto.randomness import generate_dek


def test_hkdf_derivation():
    ikm = generate_dek()
    salt = b"test_salt_123"
    info = b"DecryptTrace/dek-transport"
    
    key1 = derive_key(ikm, salt, info, 32)
    key2 = derive_key(ikm, salt, info, 32)
    
    assert len(key1) == 32
    assert key1 == key2

def test_hkdf_domain_separation():
    ikm = generate_dek()
    salt = b"test_salt_123"
    
    key_transport = derive_key(ikm, salt, b"DecryptTrace/dek-transport", 32)
    key_watermark = derive_key(ikm, salt, b"DecryptTrace/watermark", 32)
    
    assert key_transport != key_watermark

def test_hkdf_different_ikm():
    salt = b"test_salt_123"
    info = b"DecryptTrace/session"
    
    key1 = derive_key(generate_dek(), salt, info, 32)
    key2 = derive_key(generate_dek(), salt, info, 32)
    
    assert key1 != key2
