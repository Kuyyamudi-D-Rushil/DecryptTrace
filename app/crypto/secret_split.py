from .errors import InvalidShareError
from .randomness import generate_share_material


def split_dek(dek: bytes | bytearray) -> tuple[bytes, bytes]:
    """
    2-of-2 XOR split.
    Share A = CSPRNG(32 bytes)
    Share B = DEK XOR Share A
    
    Knowledge of either individual share alone provides no information about the DEK 
    under the random-share construction. Reconstruction requires both shares.
    """
    if len(dek) != 32:
        raise InvalidShareError("DEK must be exactly 32 bytes.")
        
    share_a = generate_share_material()
    share_b = bytes(a ^ b for a, b in zip(dek, share_a))
    return share_a, share_b

def reconstruct_dek(share_a: bytes, share_b: bytes) -> bytearray:
    """
    DEK = Share A XOR Share B.
    
    Note: XOR does not authenticate shares. Mismatched shares simply produce 
    a different 256-bit value. Correctness/authenticity of the reconstructed DEK 
    is established by the authenticated encryption layer when the DEK is subsequently used.
    
    Returns a mutable bytearray to allow best-effort zeroization.
    """
    if len(share_a) != 32 or len(share_b) != 32:
        raise InvalidShareError("Shares must be exactly 32 bytes.")
        
    return bytearray(a ^ b for a, b in zip(share_a, share_b))
