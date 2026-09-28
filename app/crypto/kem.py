import oqs  # type: ignore

from .errors import CryptoError, UnsupportedAlgorithmError

SUPPORTED_KEMS = {"ML-KEM-768", "ML-KEM-1024"}

class KEMWrapper:
    def __init__(self, algorithm: str):
        if algorithm not in SUPPORTED_KEMS:
            raise UnsupportedAlgorithmError(f"KEM algorithm {algorithm} is not supported.")
        self.algorithm = algorithm

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            with oqs.KeyEncapsulation(self.algorithm) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                return public_key, secret_key
        except Exception as e:
            raise CryptoError(f"Key generation failed: {e}") from e

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""
        try:
            with oqs.KeyEncapsulation(self.algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                return ciphertext, shared_secret
        except Exception as e:
            raise CryptoError("Encapsulation failed.") from e

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        try:
            with oqs.KeyEncapsulation(self.algorithm, secret_key=secret_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                return shared_secret
        except Exception as e:
            raise CryptoError("Decapsulation failed (invalid ciphertext or key).") from e
