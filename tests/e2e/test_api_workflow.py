import pytest
from fastapi.testclient import TestClient
from app.api.app import app
from app.storage.database import Base, engine, SessionLocal
from app.storage.models import User
from app.crypto.signatures import SignatureWrapper
from app.crypto.providers import get_key_provider
from app.protocol.serialization import canonicalize_for_signing
import time
import os

os.environ["DT_ADMIN_BOOTSTRAP_KEY"] = "test_admin_key"
os.environ["DT_JWT_SECRET"] = "test_secret_key_1234567890123456"
from app.config.settings import settings
settings.admin_bootstrap_key = "test_admin_key"
settings.jwt_secret = "test_secret_key_1234567890123456"

client = TestClient(app)
key_prov = get_key_provider()

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_full_api_workflow():
    sender_pk, sender_sk = key_prov.get_dsa_keypair("alice")
    recip_pk, recip_sk = key_prov.get_dsa_keypair("bob")
    recip_kem_pk, _ = key_prov.get_kem_keypair("bob")
    admin_pk, admin_sk = key_prov.get_dsa_keypair("admin")
    
    # 0. Register Admin
    resp = client.post("/auth/register", headers={"x-admin-key": "test_admin_key"}, json={
        "username": "admin",
        "role": "administrator",
        "public_key": admin_pk.hex()
    })
    assert resp.status_code == 200
    
    # 0b. Login Admin
    chal_resp = client.post("/auth/challenge", json={"username": "admin"})
    nonce_hex = chal_resp.json()["nonce"]
    sig = SignatureWrapper(settings.signature_parameter)
    signature = sig.sign(bytes.fromhex(nonce_hex), admin_sk, b"DecryptTrace/Login/v1")
    login_resp = client.post("/auth/token", json={"username": "admin", "signature_hex": signature.hex()})
    admin_token = login_resp.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    # 1. Register Sender
    resp = client.post("/auth/register", headers=admin_headers, json={
        "username": "alice",
        "role": "sender",
        "public_key": sender_pk.hex(),
        "kem_public_key": key_prov.get_kem_keypair("alice")[0].hex()
    })
    assert resp.status_code == 200
    
    # 1b. Register Recipient
    resp = client.post("/auth/register", headers=admin_headers, json={
        "username": "bob",
        "role": "recipient",
        "public_key": recip_pk.hex(),
        "kem_public_key": recip_kem_pk.hex()
    })
    assert resp.status_code == 200
    bob_id = resp.json()["id"]
    
    # 2. Login Sender
    chal_resp = client.post("/auth/challenge", json={"username": "alice"})
    assert chal_resp.status_code == 200
    nonce_hex = chal_resp.json()["nonce"]
    
    sig = SignatureWrapper(settings.signature_parameter)
    signature = sig.sign(bytes.fromhex(nonce_hex), sender_sk, b"DecryptTrace/Login/v1")
    
    login_resp = client.post("/auth/token", json={
        "username": "alice",
        "signature_hex": signature.hex()
    })
    assert login_resp.status_code == 200
    sender_token = login_resp.json()["access_token"]
    
    # 3. Upload Document
    headers = {"Authorization": f"Bearer {sender_token}"}
    import cv2, numpy as np
    img = np.zeros((64, 64, 3), dtype=np.uint8)
    _, buf = cv2.imencode(".png", img)
    valid_png = buf.tobytes()
    files = {"file": ("test.png", valid_png, "image/png")}
    resp = client.post("/documents/", headers=headers, files=files)
    assert resp.status_code == 200
    doc_data = resp.json()
    doc_id = doc_data["document_id"]
    man_id = doc_data["manifest_id"]
    
    # 3b. Authorize Recipient
    resp = client.post(f"/documents/{doc_id}/authorize", headers=headers, json={"recipient_username": "bob"})
    assert resp.status_code == 200
    
    # Grab Share A from the DB directly since it's not returned over HTTP for security
    from app.storage.models import KeyShare
    db = SessionLocal()
    recip_share = db.query(KeyShare).filter(KeyShare.document_id == doc_id, KeyShare.recipient_id == bob_id).first()
    share_a_hex = recip_share.encrypted_share
    db.close()
    
    # 4. Login Recipient
    chal_resp = client.post("/auth/challenge", json={"username": "bob"})
    nonce_hex = chal_resp.json()["nonce"]
    signature = sig.sign(bytes.fromhex(nonce_hex), recip_sk, b"DecryptTrace/Login/v1")
    login_resp = client.post("/auth/token", json={"username": "bob", "signature_hex": signature.hex()})
    recip_token = login_resp.json()["access_token"]
    recip_headers = {"Authorization": f"Bearer {recip_token}"}
    
    # 5. Request Release Challenge
    chal_resp = client.post("/releases/challenge", headers=recip_headers, json={"document_id": doc_id})
    assert chal_resp.status_code == 200
    chal_data = chal_resp.json()
    req_id = chal_data["request_id"]
    rel_nonce_hex = chal_data["nonce_hex"]
    
    # 6. Execute Release
    req_payload = {
        "request_id": req_id,
        "document_id": doc_id,
        "manifest_id": man_id,
        "recipient_key_id": bob_id,
        "challenge_id": rel_nonce_hex,
        "share_a_hex": share_a_hex,
        "protocol_version": "1.0",
        "auth_signature_hex": ""
    }
    
    from app.protocol.models import ReleaseRequest
    req_obj = ReleaseRequest(**req_payload)
    canon = canonicalize_for_signing(req_obj)
    req_sig = sig.sign(canon, recip_sk, b"DecryptTrace/RecipientAuthentication/v1")
    req_payload["auth_signature_hex"] = req_sig.hex()
    
    rel_resp = client.post("/releases/request", headers=recip_headers, json=req_payload)
    assert rel_resp.status_code == 200, rel_resp.json()
    rel_data = rel_resp.json()
    assert "artifact" in rel_data
    assert "statement" in rel_data
    
    receipt_payload = {
        "receipt_id": f"rec_{req_id}",
        "release_id": rel_data["statement"]["release_id"],
        "document_id": doc_id,
        "recipient_key_id": bob_id,
        "session_id": rel_data["statement"]["session_id"],
        "artifact_hash_hex": rel_data["artifact"]["artifact_hash_hex"],
        "detection_threshold": rel_data["statement"]["detection_threshold"],
        "fingerprint_commitment": rel_data["statement"]["fingerprint_commitment"],
        "fingerprint_commitment_salt": "dummy_salt",
        "timestamp": str(int(time.time())),
        "receipt_version": "1.0",
        "signature_hex": "dummy_sig"
    }
    ev_resp = client.post("/evidence/receipt", headers=recip_headers, json=receipt_payload)
    assert ev_resp.status_code == 200, ev_resp.json()
    pkg_id = ev_resp.json()["package_id"]
    
    # End of test
def test_negative_cases():
    import cv2, numpy as np
    from app.storage.database import SessionLocal
    from app.storage.models import Manifest
    from app.protocol.models import ReleaseRequest
    from app.protocol.serialization import canonicalize_for_signing
    from app.crypto.signatures import SignatureWrapper
    from app.config.settings import settings

    sender_pk, sender_sk = key_prov.get_dsa_keypair("alice2")
    recip_pk, recip_sk = key_prov.get_dsa_keypair("bob2")
    charlie_pk, charlie_sk = key_prov.get_dsa_keypair("charlie2")
    admin_pk, admin_sk = key_prov.get_dsa_keypair("admin2")
    
    # Register Admin
    client.post("/auth/register", headers={"x-admin-key": "test_admin_key"}, json={"username": "admin2", "role": "administrator", "public_key": admin_pk.hex()})
    chal = client.post("/auth/challenge", json={"username": "admin2"}).json()["nonce"]
    sig = SignatureWrapper(settings.signature_parameter).sign(bytes.fromhex(chal), admin_sk, b"DecryptTrace/Login/v1").hex()
    admin_token = client.post("/auth/token", json={"username": "admin2", "signature_hex": sig}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Register Alice2
    client.post("/auth/register", headers=admin_headers, json={"username": "alice2", "role": "sender", "public_key": sender_pk.hex(), "kem_public_key": key_prov.get_kem_keypair("alice2")[0].hex()})
    # Register Bob2
    resp = client.post("/auth/register", headers=admin_headers, json={"username": "bob2", "role": "recipient", "public_key": recip_pk.hex(), "kem_public_key": key_prov.get_kem_keypair("bob2")[0].hex()})
    bob_id = resp.json()["id"]
    # Register Charlie2
    resp = client.post("/auth/register", headers=admin_headers, json={"username": "charlie2", "role": "recipient", "public_key": charlie_pk.hex(), "kem_public_key": key_prov.get_kem_keypair("charlie2")[0].hex()})
    charlie_id = resp.json()["id"]

    # Logins
    alice_token = client.post("/auth/token", json={"username": "alice2", "signature_hex": SignatureWrapper(settings.signature_parameter).sign(bytes.fromhex(client.post("/auth/challenge", json={"username": "alice2"}).json()["nonce"]), sender_sk, b"DecryptTrace/Login/v1").hex()}).json()["access_token"]
    bob_token = client.post("/auth/token", json={"username": "bob2", "signature_hex": SignatureWrapper(settings.signature_parameter).sign(bytes.fromhex(client.post("/auth/challenge", json={"username": "bob2"}).json()["nonce"]), recip_sk, b"DecryptTrace/Login/v1").hex()}).json()["access_token"]
    charlie_token = client.post("/auth/token", json={"username": "charlie2", "signature_hex": SignatureWrapper(settings.signature_parameter).sign(bytes.fromhex(client.post("/auth/challenge", json={"username": "charlie2"}).json()["nonce"]), charlie_sk, b"DecryptTrace/Login/v1").hex()}).json()["access_token"]
    
    # Upload doc
    img = np.zeros((32, 32, 3), dtype=np.uint8)
    _, buf = cv2.imencode(".png", img)
    resp = client.post("/documents/", headers={"Authorization": f"Bearer {alice_token}"}, files={"file": ("test.png", buf.tobytes(), "image/png")})
    doc_id = resp.json()["document_id"]
    man_id = resp.json()["manifest_id"]
    
    # Auth Bob2
    client.post(f"/documents/{doc_id}/authorize", headers={"Authorization": f"Bearer {alice_token}"}, json={"recipient_username": "bob2"})

    # 1. Unauthorized recipient (Charlie2) tries to release
    chal_resp = client.post("/releases/challenge", headers={"Authorization": f"Bearer {charlie_token}"}, json={"document_id": doc_id})
    req_id = chal_resp.json()["request_id"]
    nonce = chal_resp.json()["nonce_hex"]
    req = ReleaseRequest(request_id=req_id, document_id=doc_id, manifest_id=man_id, recipient_key_id=charlie_id, challenge_id=nonce, share_a_hex="invalid", protocol_version="1.0", auth_signature_hex="")
    req.auth_signature_hex = SignatureWrapper(settings.signature_parameter).sign(canonicalize_for_signing(req), charlie_sk, b"DecryptTrace/RecipientAuthentication/v1").hex()
    resp = client.post("/releases/request", headers={"Authorization": f"Bearer {charlie_token}"}, json=req.dict())
    assert resp.status_code == 400
    
    # Bob2 requests challenge
    chal_resp = client.post("/releases/challenge", headers={"Authorization": f"Bearer {bob_token}"}, json={"document_id": doc_id})
    req_id = chal_resp.json()["request_id"]
    nonce = chal_resp.json()["nonce_hex"]
    
    # 2. Invalid Signature
    req = ReleaseRequest(request_id=req_id, document_id=doc_id, manifest_id=man_id, recipient_key_id=bob_id, challenge_id=nonce, share_a_hex="", protocol_version="1.0", auth_signature_hex="badsig")
    resp = client.post("/releases/request", headers={"Authorization": f"Bearer {bob_token}"}, json=req.dict())
    assert resp.status_code == 400

    # 3. Tampered Ciphertext Hash
    db = SessionLocal()
    manifest = db.query(Manifest).filter(Manifest.id == man_id).first()
    orig_hash = manifest.ciphertext_hash
    manifest.ciphertext_hash = "deadbeef"
    db.commit()
    
    req = ReleaseRequest(request_id=req_id, document_id=doc_id, manifest_id=man_id, recipient_key_id=bob_id, challenge_id=nonce, share_a_hex="", protocol_version="1.0", auth_signature_hex="")
    req.auth_signature_hex = SignatureWrapper(settings.signature_parameter).sign(canonicalize_for_signing(req), recip_sk, b"DecryptTrace/RecipientAuthentication/v1").hex()
    resp = client.post("/releases/request", headers={"Authorization": f"Bearer {bob_token}"}, json=req.dict())
    assert resp.status_code == 400 
    
    # Restore hash
    manifest.ciphertext_hash = orig_hash
    db.commit()
    db.close()
