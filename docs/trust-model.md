# Trust Model

## Trust Boundaries and Assumptions

| Entity | Trust Level | Justification / Limitation |
| :--- | :--- | :--- |
| **Sender** | Partially Trusted | Trusted to authorize releases. NOT trusted to refrain from leaking documents out of band before entering the system. |
| **Release Authority (RA)** | Highly Trusted (with caveat) | Trusted to apply watermarks and enforce policy. Must be trusted with ephemeral access to plaintext and both DEK shares during release. We do not assume the RA is perfectly secure. |
| **Receiver** | Untrusted | We explicitly **do not** claim the system prevents an authorized recipient from copying plaintext. |
| **Permissioned Ledger** | Quorum Trusted | Trusted to maintain tamper-evident history via consensus. Individual nodes are NOT trusted. |
| **Cryptographic Primitives** | Trusted | Assumed secure against quantum adversaries based on NIST ML-KEM/ML-DSA standardization. |
| **Key Pairs (Identity)** | Operationally Trusted | We **do not** assume possession of a signing key proves the physical identity of a human. |

## Core Trust Principle
The architecture enforces that the recipient must never possess an independently usable decryption capability for the original unwatermarked document. They rely entirely on the RA to perform the decryption and watermarking.

## Circular Trust Fallacies Addressed
- *Fallacy:* "A watermark match proves the authorized recipient intentionally leaked the material."
- *Correction:* A watermark match is evidence that a leaked artifact is consistent with a recorded release. It does not establish the biological identity or intent of the person who physically caused the leak.
