import secrets


def generate_dek() -> bytearray:
    """Generates a 256-bit AES-GCM Document Encryption Key using the OS CSPRNG."""
    return bytearray(secrets.token_bytes(32))

def generate_share_material() -> bytes:
    """Generates 256-bit uniformly random material for secret sharing."""
    return secrets.token_bytes(32)

def generate_nonce() -> bytes:
    """Generates a 96-bit random nonce for AES-GCM."""
    return secrets.token_bytes(12)

def generate_session_id_bytes() -> bytes:
    """Generates a 128-bit session identifier."""
    return secrets.token_bytes(16)
