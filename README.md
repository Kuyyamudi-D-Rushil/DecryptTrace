# DecryptTrace

DecryptTrace is a securely deployable end-to-end platform for secure multi-recipient encrypted document distribution, enforcing accountability through Post-Quantum Cryptography (PQC), identity-bound forensic watermarking, and a cryptographic evidence ledger.

## DecryptTrace Minimum Production Release: Image-Only
**Notice:** This deployment is restricted to the validated Image-Only release path (PNG and JPEG). PDF processing, advanced evidence export, investigation pipelines, and incomplete HSM integrations have been explicitly disabled for security and boundary stability.

### Supported Workflow
1. **Bootstrap Initialization**: The first Administrator enrolls using the `DT_ADMIN_BOOTSTRAP_KEY`.
2. **Dynamic Enrollment**: The Administrator registers Senders and Recipients.
3. **Upload**: A Sender securely uploads a validated image. The document is encrypted with AES-256-GCM. 
4. **Authorization**: The Sender authorizes specific Recipients to the document. (Share A is provisioned internally off-HTTP).
5. **Release execution**: An authorized Recipient completes a race-safe, challenge-response ML-DSA authentication and issues a Release Request. The Authority decrypts the image in memory, applies a unique spread-spectrum forensic watermark, re-encrypts it, signs an Authority Release Statement, and durably persists the artifact.
6. **Delivery**: The Recipient securely downloads the customized artifact via an authenticated endpoint.

---

## Production Setup and Deployment

### 1. Required Environment Variables
You MUST configure a secure `.env` file before launching production. Default/fallback secrets have been aggressively removed. The system will crash on startup if these are omitted.

Create a `.env` file based on `.env.example`:
```env
DT_ENV=production
DT_JWT_SECRET=<STRONG_RANDOM_SECRET>
DT_ADMIN_BOOTSTRAP_KEY=<STRONG_BOOTSTRAP_KEY>
POSTGRES_USER=dt_user
POSTGRES_PASSWORD=<STRONG_DB_PASSWORD>
POSTGRES_DB=decrypttrace
```

### 2. Exact Deployment Commands
```bash
# 1. Bring up the PostgreSQL database and FastAPI backend
docker-compose -f docker-compose.prod.yml up -d

# 2. Execute the Alembic database migrations securely
docker-compose -f docker-compose.prod.yml exec api alembic upgrade head
```

### 3. Bootstrap Procedure
After the system starts, authenticate as the first Administrator using the bootstrap key:
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "x-admin-key: <STRONG_BOOTSTRAP_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin1", "role": "administrator", "public_key": "<YOUR_MLDSA_PK_HEX>"}'
```
Subsequent users must be registered by providing the `Authorization: Bearer <token>` of the Administrator.

---

## Backup Note
All cryptographic keys, document ciphertexts, manifests, and authority statements reside in the PostgreSQL `decrypttrace` database mapped to the `dt_pgdata` docker volume. **Ensure `dt_pgdata` is backed up regularly** via standard `pg_dump` protocols. Without this database, encrypted documents cannot be recovered or verified.

## Explicit Limitations & Known Risks
- **Image Only**: PDF documents are actively rejected.
- **Worker Node Memory**: During the watermarking step, the document is briefly in-memory unencrypted on the worker node. Direct physical hypervisor memory extraction could expose the image.
- **KMS Backend**: The production API utilizes software-provider isolation; the final HardwareBackedProvider HSM module integration is pending and currently bypassed.
- **Local Demo**: The Streamlit application (`app/ui/main.py`) is strictly for local demonstration and is not suitable for, nor exposed by, the production deployment.