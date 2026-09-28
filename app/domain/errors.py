class DecryptTraceError(Exception):
    """Base exception for DecryptTrace."""

class ConfigurationError(DecryptTraceError):
    pass

class ProtocolError(DecryptTraceError):
    pass

class AuthorizationError(DecryptTraceError):
    pass

class ValidationError(DecryptTraceError):
    pass

class StorageError(DecryptTraceError):
    pass

class SecurityContractViolation(DecryptTraceError):
    pass

class NotImplementedSecurityFeature(DecryptTraceError):
    pass
