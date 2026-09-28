# Phase 2: Cryptographic Core and Manifest Boundary

## Implemented Primitives
- **DEK Encapsulation:** AES-256-GCM.
- **Secret Split:** 2-of-2 XOR split (Share A, Share B).
- **Key Derivation:** HKDF-SHA-256 with explicit labels.
- **KEM:** ML-KEM-768, ML-KEM-1024 (using liboqs).
- **Signatures:** ML-DSA-65, ML-DSA-87 (using liboqs).
- **Randomness:** System CSPRNG (`secrets` module).
- **Serialization:** Strict RFC 8785 JSON Canonicalization Scheme (JCS) provided by the `jcs` library. Ensures deterministic output conforming to the specification, avoiding circularity with the signature field.

## Algorithms and Identifiers
- Encryption: `AES-GCM-256`
- KEMs: `ML-KEM-768`, `ML-KEM-1024`
- Signatures: `ML-DSA-65`, `ML-DSA-87`
All other algorithm identifiers throw `UnsupportedAlgorithmError`.

## Nonce & AAD Construction
- Nonces (96-bit) must be generated freshly via CSPRNG per encryption.
- AAD string format: `DecryptTrace|<protocol_version>|<document_id>|<encryption_algorithm>`.
- Any mismatch in Nonce or AAD causes a hard AuthenticationFailure (fail-closed).

## HKDF Domains
- `DecryptTrace/dek-transport`
- `DecryptTrace/watermark`
- `DecryptTrace/manifest`
- `DecryptTrace/session`

## Zeroization Limitations
Python lacks hardware-backed or guaranteed secure memory deletion. Best-effort zeroization is provided by treating DEKs and Shares as mutable `bytearray` objects and overwriting them with `0`, but copies created by the interpreter, garbage collection, or OS memory swapping cannot be completely mitigated in this language runtime.

## Error Handling Principles
Cryptographic failures throw precise typed exceptions (`CryptoError`, `AuthenticationFailure`, `SignatureVerificationError`). Logs and exception strings strictly exclude sensitive state (e.g. they say "Authentication failed" instead of "Tag mismatch for DEK xxxx").

## Manifest Design
The Phase 2 `CryptoManifest` excludes all secrets (no DEKs, Shares, keys, or plaintext). Signatures are applied over the canonical bytes prefixed with `DecryptTrace/SenderManifest/v1|`. 
The exact signature byte construction is: `context || canonical_manifest_bytes`. The signature field itself is NOT part of the manifest object being signed.

## Explicitly Deferred Functionality
- The FastAPI endpoints (Release, Decrypt, Watermark).
- The actual watermarking engine.
- Ledger creation and commits.
- Forensic matching logic.
- UI.
