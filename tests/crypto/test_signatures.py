import pytest

from app.crypto.errors import SignatureVerificationError, UnsupportedAlgorithmError
from app.crypto.signatures import SignatureWrapper


def test_signature_round_trip():
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    message = b"Test Document Manifest"
    context = b"DecryptTrace/Test/v1"
    
    signature = sig.sign(message, sk, context)
    assert sig.verify(message, signature, pk, context)

def test_signature_wrong_public_key():
    sig = SignatureWrapper("ML-DSA-65")
    _pk, sk = sig.generate_keypair()
    wrong_pk, _ = sig.generate_keypair()
    
    message = b"Test Document Manifest"
    context = b"DecryptTrace/Test/v1"
    
    signature = sig.sign(message, sk, context)
    
    with pytest.raises(SignatureVerificationError):
        sig.verify(message, signature, wrong_pk, context)

def test_signature_modified_message():
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    message = b"Test Document Manifest"
    context = b"DecryptTrace/Test/v1"
    
    signature = sig.sign(message, sk, context)
    
    with pytest.raises(SignatureVerificationError):
        sig.verify(b"Test Document Manifest Mod", signature, pk, context)

def test_signature_modified_context():
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    message = b"Test Document Manifest"
    context = b"DecryptTrace/Test/v1"
    
    signature = sig.sign(message, sk, context)
    
    with pytest.raises(SignatureVerificationError):
        sig.verify(message, signature, pk, b"DecryptTrace/Test/v2")

def test_signature_modified_signature():
    sig = SignatureWrapper("ML-DSA-65")
    pk, sk = sig.generate_keypair()
    
    message = b"Test Document Manifest"
    context = b"DecryptTrace/Test/v1"
    
    signature = bytearray(sig.sign(message, sk, context))
    signature[10] ^= 1
    
    with pytest.raises(SignatureVerificationError):
        sig.verify(message, bytes(signature), pk, context)

def test_signature_unsupported_algorithm():
    with pytest.raises(UnsupportedAlgorithmError):
        SignatureWrapper("Dilithium2")
