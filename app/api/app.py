from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from ..config.settings import settings
from .auth import router as auth_router
from .routers.documents import router as documents_router
from .routers.releases import router as releases_router
from .routers.evidence import router as evidence_router

app = FastAPI(title=settings.app_name, version=settings.app_version)

# --- Security Hardening ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-frontend.local"] if settings.environment == "production" else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
# --------------------------

app.include_router(auth_router)
app.include_router(documents_router)
app.include_router(releases_router)
app.include_router(evidence_router)

@app.get("/health")
def health_check():
    tls_enabled = bool(settings.tls_cert_file and settings.tls_key_file)
    return {
        "status": "ok",
        "air_gap_mode": settings.air_gap_mode,
        "tls_configured": tls_enabled,
    }

@app.get("/version")
def version():
    return {"version": settings.app_version, "protocol_version": settings.protocol_version}

@app.get("/status")
def status():
    return {"status": "operational", "kem": settings.kem_parameter, "signature": settings.signature_parameter}

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
