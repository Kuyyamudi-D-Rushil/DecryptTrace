import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.crypto.errors import InvalidShareError
from app.crypto.randomness import generate_dek
from app.crypto.secret_split import reconstruct_dek, split_dek


def test_secret_split_roundtrip():
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    
    assert share_a != dek
    assert share_b != dek
    assert share_a != share_b
    
    reconstructed = reconstruct_dek(share_a, share_b)
    assert reconstructed == dek

def test_secret_split_mismatched_shares_produces_different_value():
    dek = generate_dek()
    share_a, _share_b = split_dek(dek)
    
    wrong_share = generate_dek() # just random 32 bytes
    reconstructed = reconstruct_dek(share_a, wrong_share)
    assert reconstructed != dek # Mismatched shares produce a different 256-bit value

def test_invalid_share_lengths():
    dek = generate_dek()
    share_a, share_b = split_dek(dek)
    
    with pytest.raises(InvalidShareError):
        reconstruct_dek(share_a[:31], share_b)
        
    with pytest.raises(InvalidShareError):
        split_dek(dek[:31])

def test_repeated_splits_are_different():
    dek = generate_dek()
    share_a1, share_b1 = split_dek(dek)
    share_a2, share_b2 = split_dek(dek)
    
    assert share_a1 != share_a2
    assert share_b1 != share_b2

@given(st.binary(min_size=32, max_size=32))
def test_property_based_reconstruction(dek_bytes):
    dek = bytearray(dek_bytes)
    share_a, share_b = split_dek(dek)
    assert reconstruct_dek(share_a, share_b) == dek

def test_statistical_sanity():
    """
    Sanity check for the information-theoretic property.
    We generate many DEKs and Share A's and verify the bit distribution of Share A.
    This is an implementation sanity check, not a formal security proof.
    """
    total_bits = 0
    set_bits = 0
    samples = 1000
    
    for _ in range(samples):
        dek = generate_dek()
        share_a, _ = split_dek(dek)
        
        for byte in share_a:
            set_bits += byte.bit_count()
            total_bits += 8
            
    # Share A should be uniformly random, meaning roughly 50% of bits are 1.
    ratio = set_bits / total_bits
    assert 0.48 < ratio < 0.52, f"Share A bit distribution biased: {ratio}"
