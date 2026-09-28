from enum import Enum
from fastapi import HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import List, Optional
import time

class Role(str, Enum):
    ADMINISTRATOR = "administrator"
    SENDER = "sender"
    AUTHORITY = "authority"
    RECIPIENT = "recipient"
    INVESTIGATOR = "investigator"
    VERIFIER = "verifier"

# In a production system, this secret should be securely injected via KMS or env vars.
# We'll default to a secure environment variable or a strong default for the prototype.
import os
JWT_SECRET = os.environ.get("DT_JWT_SECRET", "super-secret-production-key-change-me")
JWT_ALGORITHM = "HS256"

security = HTTPBearer()

def create_access_token(user_id: str, role: Role, expires_delta_minutes: int = 60) -> str:
    payload = {
        "sub": user_id,
        "role": role.value,
        "exp": time.time() + (expires_delta_minutes * 60)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_roles(allowed_roles: List[Role]):
    def role_checker(current_user: dict = Security(get_current_user)):
        if current_user.get("role") not in [role.value for role in allowed_roles]:
            raise HTTPException(status_code=403, detail="Not authorized to perform this action")
        return current_user
    return role_checker
