from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Defined exact domain separation labels
HKDFDomain = Literal[
    b"DecryptTrace/dek-transport",
    b"DecryptTrace/watermark",
    b"DecryptTrace/manifest",
    b"DecryptTrace/session"
]

def derive_key(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    )
    return hkdf.derive(ikm)
