import pytest

from app.crypto.errors import AuthenticationFailure, InvalidKeyError, InvalidNonceError
from app.crypto.randomness import generate_dek, generate_nonce
from app.crypto.symmetric import build_aad, decrypt_document, encrypt_document


def test_symmetric_round_trip():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    plaintext = b"Test Document"
    
    ciphertext = encrypt_document(plaintext, dek, nonce, aad)
    assert ciphertext != plaintext
    
    decrypted = decrypt_document(ciphertext, dek, nonce, aad)
    assert decrypted == plaintext

def test_symmetric_empty_plaintext():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    
    ciphertext = encrypt_document(b"", dek, nonce, aad)
    decrypted = decrypt_document(ciphertext, dek, nonce, aad)
    assert decrypted == b""

def test_symmetric_wrong_key():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    ciphertext = encrypt_document(b"Test", dek, nonce, aad)
    
    wrong_dek = generate_dek()
    with pytest.raises(AuthenticationFailure):
        decrypt_document(ciphertext, wrong_dek, nonce, aad)

def test_symmetric_wrong_nonce():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    ciphertext = encrypt_document(b"Test", dek, nonce, aad)
    
    wrong_nonce = generate_nonce()
    with pytest.raises(AuthenticationFailure):
        decrypt_document(ciphertext, dek, wrong_nonce, aad)

def test_symmetric_modified_ciphertext():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    ciphertext = bytearray(encrypt_document(b"Test", dek, nonce, aad))
    
    ciphertext[0] ^= 1 # modify first byte (ciphertext part)
    
    with pytest.raises(AuthenticationFailure):
        decrypt_document(bytes(ciphertext), dek, nonce, aad)

def test_symmetric_modified_tag():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    ciphertext = bytearray(encrypt_document(b"Test", dek, nonce, aad))
    
    ciphertext[-1] ^= 1 # modify last byte (tag part)
    
    with pytest.raises(AuthenticationFailure):
        decrypt_document(bytes(ciphertext), dek, nonce, aad)

def test_symmetric_modified_aad():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    ciphertext = encrypt_document(b"Test", dek, nonce, aad)
    
    wrong_aad = build_aad("1.0", "doc124", "AES-GCM-256")
    with pytest.raises(AuthenticationFailure):
        decrypt_document(ciphertext, dek, nonce, wrong_aad)

def test_invalid_lengths():
    dek = generate_dek()
    nonce = generate_nonce()
    aad = build_aad("1.0", "doc123", "AES-GCM-256")
    
    with pytest.raises(InvalidKeyError):
        encrypt_document(b"test", dek[:31], nonce, aad)
        
    with pytest.raises(InvalidNonceError):
        encrypt_document(b"test", dek, nonce[:11], aad)
