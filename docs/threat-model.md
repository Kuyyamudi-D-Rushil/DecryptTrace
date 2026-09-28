# Threat Model

## Identified Threats & Mitigations

### 1. Unauthorized Plaintext Access by Receiver
- **Threat:** The receiver decrypts the original unwatermarked document directly.
- **Mitigation:** 2-of-2 DEK reconstruction. The Sender splits the DEK into two shares. The RA holds one, the Receiver holds the other. Neither can decrypt the document alone. The Receiver provides their share to the RA during a release session, ensuring the RA controls the decryption and watermarking process.

### 2. Self-Differencing Watermark Attacks
- **Threat:** A receiver obtains multiple differently watermarked copies of the same document and differences them to remove the watermark.
- **Mitigation:** Stable fingerprint reuse. The system derives a stable `fingerprint_id` via `HKDF(K_wm, doc_id || recipient_identity)`. Repeated accesses generate a new `session_id` for auditability but deliver the exact same watermarked bytes, preventing simple differencing.

### 3. Compromise of Watermark Secret (K_wm)
- **Threat:** An attacker compromises `K_wm` and generates valid watermark patterns, allowing them to frame innocent recipients by forging provenance.
- **Mitigation:** This is a **high-severity residual risk** for the MVP. The MVP does not have HSM protection. Production hardening will require HSMs, split custody, or dual control for `K_wm`.

### 4. Ledger Admin Attacks
- **Threat:** A malicious ledger administrator attempts to rewrite history.
- **Mitigation:** The ledger is a **permissioned quorum-attested Merkle ledger**. Tampering requires subverting the quorum threshold (e.g., 2-of-3 validators).

### 5. Replay Attacks
- **Threat:** An attacker replays a release request.
- **Mitigation:** Requests include strict `session_id` nonces. The ledger ordering determines the authoritative timeline.


## Production Threat Mitigation

The production release introduces strict TLS transport layers, structured redaction of sensitive telemetry logs, robust cross-origin isolation, and rate-limiting to prevent rapid brute-force decryption requests or DoS attacks against the heavy watermarking pipeline. Known deferred risks include direct physical memory compromise of the async workers.