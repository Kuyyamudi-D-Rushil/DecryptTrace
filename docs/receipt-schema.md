# Ledger Entry and Commitments Schema

To ensure sensitive material remains off-chain, the permissioned ledger primarily stores commitments (hashes) and verifiable metadata.

## Ledger Entry Concept
```json
{
  "ledger_sequence": 1042,
  "session_id": "UUIDv4",
  "doc_id": "UUIDv4",
  "recipient_pseudonym": "SHA-384(ReceiverPubKey)",
  "commitments": {
    "manifest_hash": "SHA-384",
    "authority_release_hash": "SHA-384",
    "recipient_receipt_hash": "SHA-384",
    "fingerprint_commitment": "HMAC(fingerprint_id, Blind_Secret)"
  },
  "metadata": {
    "algorithm_identifiers": "ML-KEM-768:ML-DSA-65",
    "application_timestamp": "ISO-8601"
  },
  "validator_attestations": [
    "ML-DSA(Node1)",
    "ML-DSA(Node2)"
  ]
}
```

## Off-Chain Data
The ledger MUST NOT contain:
- Plaintext documents
- The watermark secret `K_wm`
- Unencrypted private keys or DEK shares
- Unnecessary real-world biological identities
