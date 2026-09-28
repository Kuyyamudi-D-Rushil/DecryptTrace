# Security Boundaries

This document defines the strict security boundaries established during the DecryptTrace Phase 1 skeleton implementation.

## What can access plaintext?
At the MVP architecture level, **only the Release Authority** is permitted to access plaintext, and strictly only within the controlled release operation necessary for watermarking.

## What must never receive plaintext?
The following components must never be exposed to plaintext or decrypted unwatermarked artifacts:
- The provenance Ledger
- Validator nodes
- The audit database
- Evidence packages
- The Recipient (before the authorized release is fully executed and watermarked)

## What must never be logged?
The application logging framework includes built-in redaction to prevent accidental spillage of:
- `dek` (Document Encryption Key)
- `share_a` / `share_b` (DEK shares)
- `k_wm` (Watermark Secret)
- `private_key` (Cryptographic signing/decryption keys)
- `plaintext` (Raw sensitive documents)
- Recipient private key material

*Note: Application logs are specifically distinguished from the immutable audit ledger. The logging framework is designed for operational debugging, whereas the ledger is the cryptographic source of truth.*
