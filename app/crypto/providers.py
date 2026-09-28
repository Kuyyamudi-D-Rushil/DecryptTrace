from abc import ABC, abstractmethod
from typing import Dict, Tuple

class KeyProvider(ABC):
    """
    Abstract interface for managing cryptographic keys.
    Production systems must implement a HardwareBackedProvider/HSMProvider.
    """
    @abstractmethod
    def get_kem_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        """Returns (public_key, secret_key) for ML-KEM."""
        pass
        
    @abstractmethod
    def get_dsa_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        """Returns (public_key, secret_key) for ML-DSA."""
        pass

    @abstractmethod
    def get_watermark_secret(self) -> bytes:
        """Returns the global/system watermark secret key."""
        pass

class DevelopmentSoftwareProvider(KeyProvider):
    """
    WARNING: NON-HARDWARE-BACKED SOFTWARE KEY STORE.
    For development and demo purposes only. Stores keys in memory.
    """
    def __init__(self):
        self._keys = {}
        self._watermark_secret = b"\x00" * 32
        
    def _generate_or_get(self, identity: str):
        if identity not in self._keys:
            from app.crypto.kem import KEMWrapper
            from app.crypto.signatures import SignatureWrapper
            kem = KEMWrapper("ML-KEM-768")
            sig = SignatureWrapper("ML-DSA-65")
            self._keys[identity] = {
                "kem": kem.generate_keypair(),
                "dsa": sig.generate_keypair()
            }
        return self._keys[identity]

    def get_kem_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        return self._generate_or_get(identity)["kem"]
        
    def get_dsa_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        return self._generate_or_get(identity)["dsa"]
        
    def get_watermark_secret(self) -> bytes:
        return self._watermark_secret

class ProductionKMSProvider(KeyProvider):
    """
    Production-ready KMS provider.
    Integration target: HashiCorp Vault or AWS KMS via Transit Secrets Engine.
    For this prototype deployment, we load the Authority's sealed root key from encrypted environment variables,
    but in a real deployment this would make RPCs to the HSM.
    """
    def __init__(self):
        from app.config.settings import settings
        if not settings.admin_bootstrap_key:
            raise RuntimeError("Production KMS requires secure bootstrap/secrets.")
        # In a real impl, connect to KMS API here.
        pass

    def get_kem_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Production KMS does not export private keys. Use remote crypto operations.")
        
    def get_dsa_keypair(self, identity: str) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Production KMS does not export private keys. Use remote crypto operations.")
        
    def get_watermark_secret(self) -> bytes:
        from app.config.settings import settings
        return bytes.fromhex(settings.watermark_secret_key_hex)

def get_key_provider() -> KeyProvider:
    from app.config.settings import settings
    if settings.environment == "production":
        return ProductionKMSProvider()
    return DevelopmentSoftwareProvider()
