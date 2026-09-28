# Limitations & Hard Truths

DecryptTrace acknowledges the following absolute limitations to establish a rigorous security boundary:

1. **The Analog Hole:** The system cannot prevent a receiver from photographing their screen, printing, or re-typing plaintext.
2. **Identity Abstraction:** Cryptographic signatures establish evidence associated with a key, subject to custody assumptions, not a human's physical identity.
3. **Compromised Watermark Secret:** Compromise of `K_wm` allows an attacker to generate valid watermark patterns and frame recipients. This is a high-severity residual risk for the MVP, which lacks HSM protection.
4. **Untested Robustness:** Robustness against print-scan, phone photography, cropping, or JPEG compression remains TO BE TESTED. Structural watermarking is not assumed as a default solution without empirical validation.
5. **Release Authority Trust:** The RA is a single point of plaintext exposure during the watermarking process.


## Remaining Known Risks

- Celery/Worker Memory Protection: Memory introspection on the worker nodes during PDF watermarking could expose the decrypted symmetric DEK.
- KMS Provider Implementation: The current LocalDevKMS must be replaced with the targeted provider (e.g., AWS KMS or Vault) before true zero-trust operations can begin.
- Watermark Collusion: While isolated transforms (resize, crop, compression) are robust, collusion resistance remains probabilistic.