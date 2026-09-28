import oqs  # type: ignore

from .errors import CryptoError, SignatureVerificationError, UnsupportedAlgorithmError

SUPPORTED_SIGS = {"ML-DSA-65", "ML-DSA-87"}

class SignatureWrapper:
    def __init__(self, algorithm: str):
        if algorithm not in SUPPORTED_SIGS:
            raise UnsupportedAlgorithmError(f"Signature algorithm {algorithm} is not supported.")
        self.algorithm = algorithm

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            with oqs.Signature(self.algorithm) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                return public_key, secret_key
        except Exception as e:
            raise CryptoError(f"Key generation failed: {e}") from e

    def sign(self, message: bytes, secret_key: bytes, context: bytes) -> bytes:
        domain_separated_message = context + b"|" + message
        try:
            with oqs.Signature(self.algorithm, secret_key=secret_key) as sig:
                return sig.sign(domain_separated_message)
        except Exception as e:
            raise CryptoError("Signing failed.") from e

    def verify(self, message: bytes, signature: bytes, public_key: bytes, context: bytes) -> bool:
        domain_separated_message = context + b"|" + message
        try:
            with oqs.Signature(self.algorithm) as sig:
                is_valid = sig.verify(domain_separated_message, signature, public_key)
                if not is_valid:
                    raise SignatureVerificationError("Signature verification failed.")
                return True
        except SignatureVerificationError:
            raise
        except Exception as e:
            raise SignatureVerificationError("Signature verification failed due to internal error.") from e
