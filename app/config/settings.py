import os
from typing import Literal

from pydantic import BaseModel, model_validator


class Config(BaseModel):
    app_name: str = "DecryptTrace"
    app_version: str = "0.1.0"
    environment: str = "development"
    protocol_version: str = "1.0"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    database_url: str = "sqlite:///./decrypttrace.db"
    
    jwt_secret: str | None = None
    admin_bootstrap_key: str | None = None
    master_key: str | None = None

    
    # PQC configuration
    kem_algorithm: str = "ML-KEM"
    kem_parameter: Literal["ML-KEM-768", "ML-KEM-1024"] = "ML-KEM-768"
    signature_algorithm: str = "ML-DSA"
    signature_parameter: Literal["ML-DSA-65", "ML-DSA-87"] = "ML-DSA-65"
    
    # Watermark configuration
    watermark_algorithm: str = "raster-spread-spectrum"
    watermark_version: str = "v1"
    watermark_secret_key_hex: str = "00" * 32
    
    air_gap_mode: bool = True
    logging_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    
    # Rate Limiting
    rate_limit_max_releases: int = 5
    rate_limit_window_seconds: int = 3600

    # TLS (defense-in-depth — application-layer encryption via ML-KEM envelope is the
    # primary protection; TLS provides an additional transport-layer guard).
    # Point to a self-signed cert for air-gapped LAN deployments.
    tls_cert_file: str | None = None  # e.g. "/etc/decrypttrace/server.crt"
    tls_key_file: str | None = None   # e.g. "/etc/decrypttrace/server.key"

    @model_validator(mode='after')
    def validate_pqc(self):
        if self.kem_algorithm != "ML-KEM":
            raise ValueError(f"Unsupported KEM algorithm: {self.kem_algorithm}")
        if self.signature_algorithm != "ML-DSA":
            raise ValueError(f"Unsupported Signature algorithm: {self.signature_algorithm}")
        if self.environment == "production":
            if not self.jwt_secret or len(self.jwt_secret.encode()) < 32:
                raise ValueError("DT_JWT_SECRET must be at least 32 bytes in production")
            if not getattr(self, 'master_key', None) or len(self.master_key.encode()) < 32:
                raise ValueError("DT_MASTER_KEY must be at least 32 bytes in production")
            if not getattr(self, 'admin_bootstrap_key', None) or len(self.admin_bootstrap_key) < 16:
                raise ValueError("DT_ADMIN_BOOTSTRAP_KEY is missing or too short")
            if "postgresql" not in self.database_url:
                raise ValueError("Production requires a PostgreSQL database url")
        return self

def load_config() -> Config:
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./decrypttrace.db")
    return Config(
        environment=os.environ.get("DT_ENV", "development"),
        database_url=db_url,
        air_gap_mode=os.environ.get("DT_AIR_GAP", "true").lower() == "true",
        kem_parameter=os.environ.get("DT_KEM_PARAM", "ML-KEM-768"), # type: ignore
        jwt_secret=os.environ.get("DT_JWT_SECRET"),
        admin_bootstrap_key=os.environ.get("DT_ADMIN_BOOTSTRAP_KEY"),
        master_key=os.environ.get("DT_MASTER_KEY")
    )

settings = load_config()
