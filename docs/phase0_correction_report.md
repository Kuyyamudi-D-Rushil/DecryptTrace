# Phase 0 Correction Report

## A. Corrections made
1. **Decryption Authorization Model:** Explicitly defined a 2-of-2 DEK reconstruction model. The Receiver cannot decrypt the unwatermarked document independently; the Sender splits the DEK into shares for the Receiver and RA, forcing RA mediation.
2. **Stable Fingerprint Reuse:** Distinguished `fingerprint_id` (derived via HKDF) from `session_id` (unique per access). Repeated authorized accesses deliver identically watermarked bytes to prevent self-differencing attacks.
3. **Evidence Semantics:** Removed claims of "immutable", "non-repudiation", and "proves who leaked". Replaced with precise terminology like "signed release evidence", "tamper-evident", and "consistency with a recorded release".
4. **Protocol Object Separation:** Separated the monolithic receipt into the Sender Manifest, Authority Release Statement, Recipient Receipt, and Ledger Entry.
5. **Ledger Quorum & Ordering:** Defined the MVP ledger as a 3-node network with a 2-of-3 quorum threshold. Clarified that authoritative ordering relies on ledger sequence/height, not participant timestamps.

## B. Security contradictions discovered
- **Previous Contradiction:** The previous design allowed the RA to receive an encapsulated symmetric key directly from the Sender, meaning the Receiver wasn't strictly required to participate in the decryption enablement, violating the principle that the Receiver must explicitly authorize the release via their own share. Fixed via 2-of-2 split.
- **Previous Contradiction:** Attempting to claim "non-repudiation of receipt" while acknowledging key theft in the threat model. Reconciled by clarifying that evidence binds to keys, not biological intent.

## C. Remaining unresolved decisions
- Exact 2-of-2 DEK splitting mechanism mathematically compatible with ML-KEM encapsulation (deferred to Phase 1 crypto implementation).
- The specific watermarking mechanism (e.g., raster spread-spectrum vs. structural) pending empirical testing.
- RA Trusted Execution Environment (TEE) operational enforcement.

## D. Residual risks
- **K_wm Compromise:** Framing of innocent recipients if the watermark secret is stolen (MVP lacks HSMs).
- **The Analog Hole:** Screen photography and transcription.
- **Compromised Receiver Endpoints:** Malware stealing the decrypted watermarked document directly from memory.

## E. MVP security boundary
- **Guarantees:** Post-quantum confidentiality in transit, tamper-evident auditability of release requests, and forensic consistency of watermarks (if intact).
- **Does NOT Guarantee:** Prevention of plaintext copying by authorized receivers, biological human attribution, or absolute watermark survival against aggressive structural degradation.

## F. Phase 1 prerequisites
- The implementation MUST enforce the 2-of-2 DEK split.
- The implementation MUST generate a stable `fingerprint_id` across repeated identical releases.
- The implementation MUST strictly separate Manifest, Release Statement, and Receipt objects.
