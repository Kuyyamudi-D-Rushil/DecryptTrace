from fastapi import APIRouter, HTTPException, Depends, Security, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.storage.database import SessionLocal
from app.storage.models import User, AuthChallenge
from app.domain.rbac import create_access_token, Role, require_roles, get_current_user
from app.config.settings import settings
import uuid
import time
import os
from typing import Optional
from app.crypto.signatures import SignatureWrapper

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter(prefix="/auth", tags=["auth"])

class UserRegistration(BaseModel):
    username: str
    role: Role
    public_key: str  # ML-DSA public key hex
    kem_public_key: Optional[str] = None # ML-KEM public key hex

class ChallengeRequest(BaseModel):
    username: str

class ChallengeResponse(BaseModel):
    nonce: str

class TokenRequest(BaseModel):
    username: str
    signature_hex: str

@router.post("/register")
def register_user(
    registration: UserRegistration, 
    db: Session = Depends(get_db),
    x_admin_key: str = Header(None),
    authorization: str = Header(None)
):
    admin_exists = db.query(User).filter(User.role == Role.ADMINISTRATOR.value).first() is not None
    
    if not admin_exists:
        if not settings.admin_bootstrap_key or x_admin_key != settings.admin_bootstrap_key:
            raise HTTPException(status_code=403, detail="Bootstrap key required for first admin")
        if registration.role != Role.ADMINISTRATOR:
            raise HTTPException(status_code=400, detail="First user must be an administrator")
    else:
        # Require an authenticated Admin token
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            from fastapi.security import HTTPAuthorizationCredentials
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=authorization.split(" ")[1])
            current_user = get_current_user(creds)
            if current_user["role"] != Role.ADMINISTRATOR.value:
                raise HTTPException(status_code=403, detail="Only administrators can register users")
        except Exception as e:
            raise HTTPException(status_code=403, detail="Not authorized to perform this action")
        
    existing_user = db.query(User).filter(User.username == registration.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")
        
    user_id = str(uuid.uuid4())
    new_user = User(
        id=user_id,
        username=registration.username,
        role=registration.role.value,
        public_key=registration.public_key,
        kem_public_key=registration.kem_public_key,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    return {"status": "User registered", "id": user_id}

@router.post("/challenge", response_model=ChallengeResponse)
def request_challenge(req: ChallengeRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found or inactive")
        
    nonce = os.urandom(32).hex()
    challenge = AuthChallenge(
        nonce=nonce,
        username=req.username,
        expires_at=time.time() + 300 # 5 minutes expiry
    )
    db.add(challenge)
    db.commit()
    return {"nonce": nonce}

@router.post("/token")
def login(req: TokenRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid username or inactive")
        
    now = time.time()
    challenge = db.query(AuthChallenge).filter(
        AuthChallenge.username == req.username,
        AuthChallenge.expires_at > now
    ).order_by(AuthChallenge.expires_at.desc()).first()
    
    if not challenge:
        raise HTTPException(status_code=401, detail="No active challenge found")
        
    sig_wrapper = SignatureWrapper(settings.signature_parameter)
    try:
        pk_bytes = bytes.fromhex(user.public_key)
        sig_bytes = bytes.fromhex(req.signature_hex)
        nonce_bytes = bytes.fromhex(challenge.nonce)
        
        is_valid = sig_wrapper.verify(nonce_bytes, sig_bytes, pk_bytes, b"DecryptTrace/Login/v1")
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid signature")
    except Exception:
        raise HTTPException(status_code=401, detail="Signature verification failed")
        
    # Race-safe consumption
    res = db.query(AuthChallenge).filter(AuthChallenge.nonce == challenge.nonce).delete()
    db.commit()
    if res == 0:
        raise HTTPException(status_code=401, detail="Challenge already consumed")
        
    token = create_access_token(user_id=user.id, role=Role(user.role))
    return {"access_token": token, "token_type": "bearer"}
