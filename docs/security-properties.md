# Security Properties

## Core Properties Achieved
1. **Post-Quantum Confidentiality In-Transit:** Data transmitted is protected against 'Store Now, Decrypt Later' (SNDL) using ML-KEM.
2. **Post-Quantum Authenticity & Integrity:** Manifests, release statements, and receipts are signed using ML-DSA.
3. **Cryptographically Verifiable Authorization:** Signed release evidence establishes that a sender authorized a transaction.
4. **Watermarked-Copy Provenance:** If an intact watermarked document is recovered, the embedded trace can be forensically correlated to a recorded release session.

## Security Contract Table

| Property                         | Contract | Assumption | Status       |
| -------------------------------- | -------- | ---------- | ------------ |
| Confidentiality                  | ML-KEM encapsulation protects data in transit | Quantum computers cannot break ML-KEM | DESIGNED |
| Recipient authorization          | ML-DSA Sender Manifest binds policy | Sender key is not compromised | DESIGNED |
| No unmarked recipient decryption | 2-of-2 DEK share split ensures RA mediation | RA does not leak unwatermarked DEK/plaintext | DESIGNED |
| Integrity                        | ML-DSA signatures on all protocol objects | Quantum computers cannot break ML-DSA | DESIGNED |
| PQC authenticity                 | ML-DSA keys bind to identities | Key custody is secure | DESIGNED |
| Release auditability             | Quorum-attested ledger records commitments | Ledger quorum is honest | DESIGNED |
| Stable fingerprint               | Fingerprint ID is deterministically derived | HKDF and K_wm are secure | DESIGNED |
| Watermark forensic correlation   | Extracted trace links to a ledger commitment | Trace survives degradation | TO BE TESTED |
| Ledger tamper evidence           | Hash-linked Merkle tree with quorum signatures | Quorum threshold maintained | DESIGNED |
| Human attribution                | Associates key usage, not biology | N/A | NOT PROVIDED |
| Intentional-leak attribution     | Indicates consistency with a release, not intent | N/A | NOT PROVIDED |

## Explicit Limitations
- **NO absolute attribution:** Evidence establishes cryptographic relationships; it does not establish biological identity or intent.
- **Untested Watermark Robustness:** Robustness to print-scan, photography, or cropping is TO BE TESTED.
