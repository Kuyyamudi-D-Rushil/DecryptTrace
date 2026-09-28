with open('app/api/routers/releases.py', 'r') as f:
    c = f.read()

c = c.replace('from app.storage.models import Document, AuthChallenge as DBAuthChallenge', 'from app.storage.models import Document, ReleaseChallenge')

old_chal_creation = """    # Store this challenge in DB temporarily
    db_chal = DBAuthChallenge(
        nonce=challenge.nonce_hex,
        username=recipient_id,
        expires_at=challenge.expires_at
    )
    # We misuse the DBAuthChallenge table for release challenges by packing it, 
    # but let's be careful. Actually, the Protocol verifies against a Pydantic AuthChallenge.
    # It's better to store it as JSON in a generic or specific table, or use Redis.
    # Since we have AuthChallenge table, we can serialize the extra fields.
    db_chal.username = f"release:{recipient_id}:{req_id}:{challenge.protocol_version}"
    db.add(db_chal)"""

new_chal_creation = """    # Store this challenge in DB temporarily
    db_chal = ReleaseChallenge(
        nonce=challenge.nonce_hex,
        request_id=req_id,
        recipient_id=recipient_id,
        document_id=req.document_id,
        protocol_version="1.0",
        expires_at=challenge.expires_at
    )
    db.add(db_chal)"""
c = c.replace(old_chal_creation, new_chal_creation)

old_chal_fetch = """    # Reconstruct AuthChallenge from DB
    chal_record = db.query(DBAuthChallenge).filter(DBAuthChallenge.nonce == request.challenge_id).first()
    if not chal_record or chal_record.expires_at < time.time():
        raise HTTPException(status_code=401, detail="Challenge expired or invalid")
        
    parts = chal_record.username.split(":")
    if len(parts) != 4 or parts[0] != "release" or parts[1] != recipient_id:
        raise HTTPException(status_code=401, detail="Invalid challenge context")
        
    challenge = AuthChallenge(
        request_id=parts[2],
        recipient_key_id=parts[1],
        nonce_hex=chal_record.nonce,
        protocol_version=parts[3],
        expires_at=chal_record.expires_at
    )"""

new_chal_fetch = """    # Reconstruct ReleaseChallenge from DB
    chal_record = db.query(ReleaseChallenge).filter(ReleaseChallenge.nonce == request.challenge_id).first()
    if not chal_record or chal_record.expires_at < time.time():
        raise HTTPException(status_code=401, detail="Challenge expired or invalid")
        
    if chal_record.recipient_id != recipient_id or chal_record.document_id != request.document_id:
        raise HTTPException(status_code=401, detail="Invalid challenge context")
        
    challenge = AuthChallenge(
        request_id=chal_record.request_id,
        recipient_key_id=chal_record.recipient_id,
        nonce_hex=chal_record.nonce,
        protocol_version=chal_record.protocol_version,
        expires_at=chal_record.expires_at
    )"""
c = c.replace(old_chal_fetch, new_chal_fetch)

c = c.replace('res = db.query(DBAuthChallenge).filter(DBAuthChallenge.nonce == chal_record.nonce).delete()', 'res = db.query(ReleaseChallenge).filter(ReleaseChallenge.nonce == chal_record.nonce).delete()')

with open('app/api/routers/releases.py', 'w') as f:
    f.write(c)
