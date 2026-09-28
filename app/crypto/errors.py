from app.domain.errors import DecryptTraceError


class CryptoError(DecryptTraceError):
    pass

class AuthenticationFailure(CryptoError):
    pass

class InvalidKeyError(CryptoError):
    pass

class InvalidNonceError(CryptoError):
    pass

class InvalidShareError(CryptoError):
    pass

class UnsupportedAlgorithmError(CryptoError):
    pass

class SignatureVerificationError(CryptoError):
    pass

class CanonicalizationError(CryptoError):
    pass
