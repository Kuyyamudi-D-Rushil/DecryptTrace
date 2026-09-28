# Protocol Contracts

## Distinct Protocol Objects

### A. Sender Manifest
Authorizes and binds the encrypted document.
- `doc_id`
- `ciphertext_hash`
- `recipient_authorization`
- `policy`
- `algorithm_identifiers`
- `key_share_B_commitment`
- `sender_signature` (ML-DSA)

### B. Authority Release Statement
Asserts what the Release Authority performed.
- `manifest_hash`
- `session_id` (CSPRNG unique per access)
- `fingerprint_id` (stable per doc/recipient)
- `watermarked_copy_hash`
- `release_event_info`
- `ra_signature` (ML-DSA)

### C. Recipient Receipt
Acknowledges what the recipient received.
- `session_id`
- `watermarked_copy_hash`
- `recipient_key_ref`
- `recipient_signature` (ML-DSA)

## Protocol Flow

1. **Initialization (Sender):** 
   - Sender generates DEK, encrypts document.
   - Splits DEK into Share A and Share B.
   - Encapsulates Share A for Recipient, Share B for RA.
   - Creates and signs the **Sender Manifest**.
2. **Request (Recipient):**
   - Recipient authenticates to RA via ML-DSA challenge-response.
   - Recipient submits signed request containing their encapsulated Share A.
3. **Release Operation (RA):**
   - RA validates the request and Sender Manifest.
   - RA decapsulates Share B, combines with Share A to reconstruct DEK.
   - RA decrypts document, derives stable `fingerprint_id`, and embeds watermark.
   - RA encrypts watermarked copy for Recipient.
   - RA creates **Authority Release Statement**.
4. **Delivery & Acknowledgment:**
   - RA delivers watermarked ciphertext.
   - Recipient decapsulates, decrypts, and signs **Recipient Receipt**.
   - RA/Recipient submit commitments to the Ledger.
