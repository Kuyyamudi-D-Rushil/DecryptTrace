# Phase 1 Implementation Boundaries

## Implemented in Phase 1
- **Repository Structure:** A clean Python package layout reflecting standard DDD practices.
- **Configuration Layer:** A central, type-safe configuration system supporting PQC algorithm validation.
- **Domain Identifiers:** Strongly typed IDs to prevent mixing `session_id`, `fingerprint_id`, etc.
- **Protocol Object Schemas:** Separated data models for `SenderManifest`, `ReleaseRequest`, `AuthorityReleaseStatement`, `RecipientReceipt`, and `LedgerEntry`.
- **Service Interfaces:** Abstract base classes outlining future cryptographic and release workflows.
- **Storage Abstraction:** Basic key-value interface pending specific DB schema.
- **Logging Foundation:** Structured logging with automatic redaction of sensitive fields.
- **Error Foundation:** Typed domain exceptions.
- **FastAPI Skeleton:** `/health`, `/version`, and `/status` endpoints running successfully.
- **CLI Skeleton:** Commands to inspect version, health, and config validity.
- **Offline CI/Test Infrastructure:** Unit and contract tests protecting Phase 0 architecture constraints.

## Intentionally Not Implemented
- PQC cryptography (ML-KEM, ML-DSA)
- DEK split logic
- Watermarking engine
- Plaintext release protocol implementation
- Ledger Merkle tree or quorum consensus
- Forensics and evidence verification
- Recipient authentication
- UI
- TEE / HSM integration

## Interfaces Prepared for Phase 2+
- `DocumentEncryptionService`
- `KeySplitService`
- `RecipientAuthenticationService`
- `ReleaseService`
- `WatermarkService`
- `ReceiptService`
- `LedgerService`
- `EvidenceVerificationService`

## Security Assumptions and Boundaries
- Phase 1 establishes software structure, contracts, configuration, interfaces and test boundaries. It does not provide cryptographic security by itself.
- Static typing, Pydantic validation and interface separation are development controls, not substitutes for cryptographic enforcement.
- Phase 0 constraints remain firmly intact. 
- The Release Authority remains the sole controller of the controlled release operation.
- The 2-of-2 DEK authorization model dictates that the recipient cannot independently decrypt the document.
- Cryptographic configuration is decoupled from business logic and thoroughly validated before startup.
