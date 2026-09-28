from app.domain.errors import DecryptTraceError


class ProtocolError(DecryptTraceError):
    pass

class AuthenticationError(ProtocolError):
    pass

class AuthorizationError(ProtocolError):
    pass

class RateLimitExceeded(AuthorizationError):
    pass

class StateTransitionError(ProtocolError):
    pass

class ContractViolationError(ProtocolError):
    pass
