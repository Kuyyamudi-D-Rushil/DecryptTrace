# Phase 3: Controlled Release Protocol

## Protocol Sequence
1. **Challenge Issuance**: Authority generates an `AuthChallenge` containing a nonce, recipient key reference, protocol version, and expiration timestamp.
2. **Authentication**: Recipient signs the canonical bytes of `AuthChallenge` using their registered ML-DSA-65 key under the `DecryptTrace/RecipientAuthentication/v1|` domain context.
3. **Release Request**: Recipient submits a `ReleaseRequest` containing `share_a`, identifiers, and the authentication signature.
4. **Authorization**: `ReleaseAuthorizer` boundary performs policy checks (default deny, outside crypto boundary).
5. **Manifest Verification**: The `SenderManifest` is validated via an injected `ManifestProvider` to guarantee properties matching the request before secrets are materialized.
6. **DEK Reconstruction**: `Share A` from the request is XORed with `Share B` pulled securely from the internal `ShareBProvider`. DEK is reconstructed strictly within the Release boundary.
7. **Plaintext Processing**: Document is decrypted into an internal boundary utilizing a `ControlledPlaintextProcessor`. The `IdentityProcessor` test stub simulates this step, correctly marking the state as `"NOT_WATERMARKED_PHASE3"`.
8. **Artifact Re-encryption**: A fresh `transport_dek` is derived via HKDF utilizing an ML-KEM-768 shared secret encapsulated against the recipient's public transport key. The processed plaintext is re-encrypted with AES-256-GCM.
9. **Authority Release Statement**: Authority signs a statement asserting the release event, artifact mapping, and hashes, under the `DecryptTrace/AuthorityReleaseStatement/v1|` context.

## State Machine
The protocol dictates strict state transitions starting at `CREATED` and culminating at `DELIVERED` or `FAILED`.
Any internal failure or contract violation immediately locks the state to `FAILED`. A failed state prohibits terminal delivery. Sensitive intermediary states (e.g., `DEK_RECONSTRUCTED`) are solely internal markers.

## Authentication vs Authorization
- **Authentication**: Validation of identity (via ML-DSA) and temporal context (challenge nonce and expiry bounds).
- **Authorization**: Explicit business-logic validation via the `ReleaseAuthorizer`. Success of authentication does not imply authorization success.

## Separation of Concerns
- **Share B Security**: The recipient or caller cannot supply `Share B` or `Manifest`. They must be retrieved from the Authority's authoritative providers.
- **Watermarking Boundary**: The release protocol defines an injection point (`ControlledPlaintextProcessor`). No dummy fingerprints or derivation keys (`K_wm`) exist in this layer.
- **Ledger Independence**: Authority Statements and Recipient Receipts are decoupled from Ledger Submissions, avoiding circular claims.

## Canonicalization & Signature Bytes
All signed objects strip their optional `signature_hex` attribute and are routed through `jcs.canonicalize`.
The ML-DSA wrapper prefixes the respective context:
- Authentication: `DecryptTrace/RecipientAuthentication/v1|`
- Authority Statement: `DecryptTrace/AuthorityReleaseStatement/v1|`
- Recipient Receipt: `DecryptTrace/RecipientReceipt/v1|`

## Canonical AAD Construction
The AES-GCM transport encryption utilizes a structured canonical AAD representation generated via RFC 8785 JCS, ensuring rigorous cross-context binding. The canonicalized AAD dictionary includes:
- `protocol_version`
- `document_id`
- `manifest_id`
- `recipient_key_id`
- `session_id`
- `kem_algorithm`
- `encryption_algorithm`
- `encryption_version`

## Artifact Envelope and Hash
The `ReleaseArtifact` acts as the Artifact Envelope and is canonically hashed (excluding the hash field itself).
`artifact_hash_hex = SHA-256(JCS(ArtifactEnvelope excluding artifact_hash_hex))`
Fields included in the envelope:
- `artifact_id`
- `protocol_version`
- `document_id`
- `manifest_id`
- `recipient_key_id`
- `session_id`
- `processing_status`
- `kem_algorithm`
- `kem_version`
- `kem_ciphertext_hex`
- `encryption_algorithm`
- `encryption_version`
- `nonce_hex`
- `aad_hex`
- `ciphertext_hex`

## Limitations
- **Durable Persistence**: State machine transitions and challenge replays are handled in-memory. Persistent storage (DB) is deferred to Phase 5.
- **Python Zeroization**: The implementation performs best-effort zeroization of sensitive byte buffers when they are no longer required. This does not provide a language/runtime/OS-level guarantee that all copies of sensitive material have been removed from memory.
- **Identity Processor**: No traceability, attribution, or immutability is afforded to artifacts labeled `NOT_WATERMARKED_PHASE3`.
- **Recipient Identity/Key Registration**: NOT IMPLEMENTED. The protocol verifies signatures against public keys provided by the `RecipientKeyProvider` interface, but there is no production implementation or trust-anchor (CA) check yet. Real deployment is blocked pending the offline-CA/key-registration mechanism planned for the air-gap deployment phase.
- **Release Rate-Limiting / Idempotency**: NOT IMPLEMENTED. The authentication layer correctly prevents replay of an identical signed request (per-challenge-nonce, durably recorded in the database), but there is no check at the authorization layer preventing repeated legitimate re-requests for the same `(document_id, recipient_key_id)` pair. Each request triggers full DEK reconstruction and plaintext processing regardless of prior successful releases. This is tolerated under the current design because watermark identity is stable per document/recipient (repeated releases do not create a differencing signal), but it is a resource-exhaustion and unnecessary-plaintext-exposure concern. A production `ReleaseAuthorizer` implementation (planned alongside the offline-CA / key-registration work) must include a release-rate or already-delivered policy.
- **Share A Security**: Recipient authentication/signing provides integrity and proof of possession of the signing key, not confidentiality of the share. Share A confidentiality with respect to the DEK comes from the 2-of-2 XOR split construction. Under the specified construction, Share A alone reveals no information about the DEK when Share A is generated uniformly at random. Share A must still be protected in transit and at rest as a sensitive secret. Share B remains Authority-controlled and is never released to the recipient.
