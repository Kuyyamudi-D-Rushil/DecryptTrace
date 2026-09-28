import pytest

from app.crypto.errors import CryptoError, UnsupportedAlgorithmError
from app.crypto.kem import KEMWrapper


def test_kem_round_trip():
    kem = KEMWrapper("ML-KEM-768")
    pk, sk = kem.generate_keypair()
    
    ciphertext, shared_secret = kem.encapsulate(pk)
    decapsulated_secret = kem.decapsulate(ciphertext, sk)
    
    assert shared_secret == decapsulated_secret

def test_kem_wrong_private_key():
    kem = KEMWrapper("ML-KEM-768")
    pk, _sk = kem.generate_keypair()
    _, wrong_sk = kem.generate_keypair()
    
    ciphertext, shared_secret = kem.encapsulate(pk)
    
    # ML-KEM usually fails safely or returns a pseudorandom string rather than the right secret
    # If the oqs library explicitly rejects, it raises an exception.
    try:
        wrong_secret = kem.decapsulate(ciphertext, wrong_sk)
        assert wrong_secret != shared_secret
    except CryptoError:
        pass # Also acceptable

def test_kem_modified_ciphertext():
    kem = KEMWrapper("ML-KEM-768")
    pk, sk = kem.generate_keypair()
    
    ciphertext, shared_secret = kem.encapsulate(pk)
    modified = bytearray(ciphertext)
    modified[0] ^= 1
    
    try:
        wrong_secret = kem.decapsulate(bytes(modified), sk)
        assert wrong_secret != shared_secret
    except CryptoError:
        pass

def test_kem_unsupported_algorithm():
    with pytest.raises(UnsupportedAlgorithmError):
        KEMWrapper("Kyber512") # Old name or unsupported
        
def test_kem_repeated_encapsulations():
    kem = KEMWrapper("ML-KEM-768")
    pk, _ = kem.generate_keypair()
    
    ct1, ss1 = kem.encapsulate(pk)
    ct2, ss2 = kem.encapsulate(pk)
    
    assert ct1 != ct2
    assert ss1 != ss2
