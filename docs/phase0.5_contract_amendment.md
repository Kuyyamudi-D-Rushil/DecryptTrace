# Phase 0.5 Contract Amendment: Detailed Release & DEK Mechanics

This document amends the Phase 0 architecture to explicitly define the mechanics of the 2-of-2 Document Encryption Key (DEK) reconstruction, its cryptographic transport, and the exact ordering of release events.

## 1. The DEK Shares
The original Document Encryption Key (DEK) used to encrypt the unwatermarked plaintext is mathematically split into two symmetric shares using a perfectly secure 2-of-2 secret sharing scheme.
- **Share A:** The Recipient Share.
- **Share B:** The Authority Share.

## 2. Security Properties of the Shares
Each individual share is cryptographically indistinguishable from random noise. Possession of a single share (whether A or B) reveals zero information about the original DEK. Both shares are strictly required to reconstruct the DEK.

## 3. Share Transport and Protection
- **Share A** is securely transported to the Recipient.
- **Share B** is securely transported to the Release Authority (RA).
Neither party has access to the other's share during the initial distribution phase.

## 4. The Role of ML-KEM
ML-KEM is used strictly for **share protection (transport security)**, not for the key splitting operation itself.
- The Sender mathematically splits the symmetric DEK into Share A and Share B first.
- The Sender uses ML-KEM to encapsulate a transit key for the Recipient to securely deliver Share A.
- The Sender uses ML-KEM to encapsulate a transit key for the RA to securely deliver Share B.

## 5. Timing of DEK Reconstruction
DEK reconstruction occurs **exclusively** inside the Release Authority's secure operational boundary (ideally a Trusted Execution Environment). It happens only after the Recipient has authenticated, decrypted their Share A, and actively submitted it to the RA within a signed release request.

## 6. Destruction of the Reconstructed DEK and Plaintext
The reconstructed DEK and plaintext/intermediate sensitive material are held ephemerally in the RA's volatile memory. They are **securely zeroized as soon as they are no longer required** for the controlled release operation (after decryption, watermarking, and re-encryption are complete), subject to the limitations of the implementation language/runtime and operating system memory management. They are never intentionally persisted to disk, logged, or cached.

## 7. Recipient Isolation from the DEK
The Recipient never receives Share B, and the RA never transmits the reconstructed DEK back to the Recipient. Therefore, **the Recipient never possesses the original DEK** and remains mathematically incapable of decrypting the original unwatermarked document independently.

## 8. Delivery of the Watermarked Artifact
The Recipient only ever receives the **post-watermark encrypted artifact**. After embedding the watermark, the RA generates a completely new symmetric key, encrypts the watermarked copy, and uses ML-KEM to encapsulate this new key for the Recipient.

## 9. Stable Fingerprint vs. Ciphertext Malleability
The stable fingerprint guarantee applies exclusively to the **watermarked artifact (plaintext bytes)**. Repeated authorized accesses for the same document by the same recipient will yield identical watermarked plaintext bytes. However, because each transmission uses unique nonces/IVs and fresh ML-KEM encapsulations, the **transport ciphertext** will always differ for every session. 

## 10. Ordered Event Ledger Commitments
The protocol strictly enforces the following chronological sequence of ledger commitments:
1. `ReleaseRequestCommitted`: The Recipient's signed request (containing their intent and authorization to use Share A) is committed.
2. `AuthorityRelease`: The RA performs the decryption, watermarking, and re-encryption, then commits its release statement asserting the operation.
3. `RecipientReceipt`: The Recipient receives the watermarked payload and commits a cryptographic acknowledgment of receipt.

## 11. Phase 1 Implementation Prerequisites (Secret Splitting)
The exact splitting mechanism (e.g., a simple 2-of-2 XOR split where `Share_A` is uniformly random and `Share_B = DEK XOR Share_A`) must be selected explicitly, specified, and tested during the Phase 1 crypto design phase. The implementation must not invent custom or ad-hoc secret-sharing constructions without prior formal specification and validation.
