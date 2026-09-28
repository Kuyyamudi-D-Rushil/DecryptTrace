# DecryptTrace Architecture

## Overview
DecryptTrace is an enterprise-grade document release and tracking system designed to enforce accountability in sensitive document sharing. It utilizes Post-Quantum Cryptography (PQC) for secure transmission and a permissioned quorum-attested Merkle ledger for tamper-evident audit trails.

## Core Components
- **Sender (Document Owner):** Encrypts the document, splits the Decryption Key (DEK) into shares, and authorizes the release.
- **Release Authority (RA):** Mediates the release process. Reconstructs the DEK only inside the controlled release operation, applies stable, identity-bound watermarks, and delivers the final decrypted/watermarked document to the receiver.
- **Receiver:** The authorized entity requesting and receiving the document. The receiver must never possess an independently usable decryption capability for the original unwatermarked document.
- **Permissioned Ledger:** A permissioned quorum-attested Merkle ledger with hash-linked blocks that records cryptographic commitments of all transactions (requests, authorizations, and deliveries).
- **Watermark & Fingerprint Engine:** A module designed for embedding tracing data. The specific mechanism (e.g., raster-based spread-spectrum) remains subject to an empirical go/no-go experiment. Structural watermarking is not adopted as a security assumption without testing.

## Architectural Security Controls
1. **2-of-2 DEK Reconstruction Model:**
   - The original document is encrypted with a symmetric DEK.
   - The Sender splits the DEK into Share A (encapsulated for the Recipient) and Share B (encapsulated for the RA).
   - During release, the Recipient authenticates and provides Share A to the RA.
   - The RA combines Share A and Share B to reconstruct the DEK, decrypts the document, embeds the watermark, and re-encrypts the watermarked copy for the Recipient.
2. **Stable Fingerprint Reuse:**
   - To mitigate self-differencing watermark attacks, repeated authorized accesses by the same recipient for the same document generate a new `session_id`, but reuse the exact same `fingerprint_id` (derived via HKDF). The delivered watermarked bytes remain stable across repeated accesses.
3. **AEAD Envelope Binding:**
   - The sender-signed manifest hash must be included in the AEAD Additional Authenticated Data (AAD) for the AES-256-GCM encrypted document.


## Production Updates

As of Phase 7, the architecture has migrated from an in-memory MVP state to a PostgreSQL-backed production deployment with durable Alembic migrations. API layers enforce strict Role-Based Access Control (RBAC) via stateless JWT tokens, delegating background watermark-processing to async task workers. A HardwareBackedProvider interface abstracts the key management system (KMS), and multi-stage Docker builds enforce air-gapped production dependencies.