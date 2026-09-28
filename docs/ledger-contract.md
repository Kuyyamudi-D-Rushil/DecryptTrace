# Ledger Contract

## Definition
The DecryptTrace ledger is a **Permissioned quorum-attested Merkle ledger**. 
It is explicitly NOT a BFT consensus network, as it lacks leader election and view-change complexity in the MVP.

## MVP Quorum Definition
- **Number of Validators (N):** 3 independent nodes.
- **Quorum Threshold:** 2-of-3.
- **Valid Block/Entry:** A ledger entry is valid only if signed by at least 2 of the 3 validators.
- **Verification Offline:** An offline verifier with the validator public keys can independently verify the hash-linked history and the quorum signatures on any block.

## Ordering and Timestamps
### Application Timestamps
Participants provide timestamps in manifests and receipts. These are useful metadata but are NOT the authoritative source of event ordering.

### Ledger Ordering
Authoritative ordering is established strictly by the ledger's sequence/height and block position. 
To determine if a release request was committed *before* a release operation, a verifier checks the chronological block height of the respective commitments, rather than trusting participant-provided wall-clock times.
