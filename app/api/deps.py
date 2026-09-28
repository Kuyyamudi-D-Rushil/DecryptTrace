from fastapi import Depends, HTTPException
from typing import Generator
from sqlalchemy.orm import Session
from app.storage.database import SessionLocal
from app.config.settings import settings

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_symmetric_keystore():
    if settings.environment == "production":
        from app.crypto.kms import ProductionKeystore
        if not settings.master_key:
            raise RuntimeError("Production requires DT_MASTER_KEY")
        return ProductionKeystore(settings.master_key)
    else:
        class MockKeystore:
            def encrypt_data(self, data: bytes) -> str:
                return data.hex()
            def decrypt_data(self, data: str) -> bytes:
                return bytes.fromhex(data)
        return MockKeystore()
