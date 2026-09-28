# Cryptographic Decision Record (CDR)

## Algorithm Selections
| Primitive | Standard | Parameter Set | Justification |
| :--- | :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | FIPS 203 | `ML-KEM-768` | MVP Default. |
| **Digital Signatures** | FIPS 204 | `ML-DSA-65` | MVP Default. |
| **Symmetric Encryption** | FIPS 197 / SP 800-38D | `AES-256-GCM` | Used for document encryption. |
| **Hashing** | FIPS 180-4 / 202 | `SHA-384` | Merkle trees, manifests. |
| **Key Derivation** | SP 800-56C | `HKDF-SHA-384` | Fingerprint derivation. |

## Decisions and Constraints
- **AEAD Binding:** Document ID, Protocol Version, and Algorithm are included in the AES-GCM AAD.
- **Protocol Versioning:** All signed objects must include explicit `protocol_version` and `algorithm_identifiers`.
- **No Certification Claims:** We do not claim government/defense approval or FIPS validation for this software module without authoritative certification.
- **2-of-2 DEK Split:** Implemented as a simple XOR split (Share A, Share B). Recipient authentication/signing provides integrity and proof of possession of the signing key, not confidentiality of the share. Share A confidentiality with respect to the DEK comes from the 2-of-2 XOR split construction. Under the specified construction, Share A alone reveals no information about the DEK when Share A is generated uniformly at random. Share A must still be protected in transit and at rest as a sensitive secret. Share B remains Authority-controlled and is never released to the recipient.
- **HKDF Contexts:** Separated into distinct domains (dek-transport, watermark, manifest, session).
- **Zeroization:** The implementation performs best-effort zeroization of sensitive byte buffers when they are no longer required. This does not provide a language/runtime/OS-level guarantee that all copies of sensitive material have been removed from memory.
- **Protocol Envelopes (Phase 3):** Re-encrypted release artifacts use a fresh AES-256-GCM key encapsulated via ML-KEM and HKDF-SHA-256. Plaintext processors and authorizers are securely separated behind internal Protocol interfaces.
