import time

from app.crypto.randomness import generate_nonce
from app.crypto.signatures import SignatureWrapper

from .errors import AuthenticationError
from .models import AuthChallenge, ReleaseRequest
from .serialization import canonicalize_for_signing

AUTH_CONTEXT = b"DecryptTrace/RecipientAuthentication/v1"

from app.storage.repositories import ChallengeRepository


class ChallengeManager:
    def __init__(self, repository: ChallengeRepository, expiration_seconds: int = 300):
        self.repository = repository
        self.expiration_seconds = expiration_seconds

    def create_challenge(self, request_id: str, recipient_key_id: str, protocol_version: str) -> AuthChallenge:
        nonce = generate_nonce()
        expires_at = int(time.time()) + self.expiration_seconds
        
        return AuthChallenge(
            request_id=request_id,
            recipient_key_id=recipient_key_id,
            nonce_hex=nonce.hex(),
            protocol_version=protocol_version,
            expires_at=expires_at
        )

    def verify_request_authentication(self, request: ReleaseRequest, challenge: AuthChallenge, public_key: bytes, algorithm: str) -> bool:
        """
        Verifies the request signature and limits replays.
        Returns True if valid, raises AuthenticationError if invalid or expired.
        """
        now = int(time.time())
        if challenge.expires_at < now:
            raise AuthenticationError("Challenge expired.")
            
        challenge_id = challenge.nonce_hex
        if request.challenge_id != challenge_id:
            raise AuthenticationError("Challenge ID mismatch in request.")
            
        if self.repository.is_consumed(challenge_id):
            raise AuthenticationError("Challenge already consumed.")
            
        if request.request_id != challenge.request_id or request.recipient_key_id != challenge.recipient_key_id:
            raise AuthenticationError("Request identifiers do not match challenge.")
            
        canonical_bytes = canonicalize_for_signing(request)
        
        try:
            verifier = SignatureWrapper(algorithm)
            verifier.verify(canonical_bytes, bytes.fromhex(request.auth_signature_hex), public_key, AUTH_CONTEXT)
        except Exception as e:
            raise AuthenticationError("Invalid signature.") from e
            
        if not self.repository.add_consumed_challenge(challenge_id):
            raise AuthenticationError("Challenge already consumed (concurrent replay).")
            
        return True
