# Phase 4: Watermark Thresholds and Acceptance Criteria (PROPOSAL)

This document proposes the numerical thresholds for evaluating the robustness and reliability of the forensic watermarking scheme to be implemented in Phase 4. These criteria determine whether the chosen technique is viable for MVP release.

**Status:** PENDING TEAM REVIEW
**Note:** The numerical values below are proposals based on standard literature in digital image watermarking (such as DWT/DCT-based techniques). Numbers marked with `[ESTIMATE]` indicate pragmatic targets for this specific MVP rather than strict academic standards.

---

## 1. Baseline Performance (No Attack)

To establish that the watermark is fundamentally functional before adversarial conditions are introduced.

* **Blind Detection Justification:** The extractor performs blind detection (no clean host reference is available at extraction time). Because of this, the raw correlation magnitude is limited by host image content (e.g., high-contrast text edges in the residual) and bounded well below 1.0. Therefore, a strict raw magnitude threshold like `NC > 0.99` is an incorrect success metric for this implementation. As evidence, a pilot baseline measured on synthetic text documents yielded a correct-seed mean of $0.124297$ (std $0.023866$) and a null-seed mean of $0.000700$ (std $0.002914$). The correct metric is the statistical separation (Z $\approx 42.4$), not the raw correlation value itself.
* **Threshold for GO:**
  * **Detection Statistic Criterion:** The correct-seed correlation score must exceed a detection threshold independently derived from the target False Positive Rate (< 10⁻⁶), rather than an arbitrary empirical baseline.
  * **Preliminary Derivation:** Assuming a normal distribution for null scores, a one-tailed cutoff for $p < 10^{-6}$ requires a threshold approximately $4.75$ standard deviations above the null mean. *Note: This is a preliminary estimate pending the full 100,000-trial extreme-value-fit calibration already committed to in the FPR section.*
  * **Open Item - Null Distribution Stability:** Null-distribution statistics may vary significantly by document content (text density, image content, page layout). Before finalizing any threshold, the full robustness lab (Phase 4C) must confirm the null distribution is stable across a diverse sample of real document types—not just text-heavy synthetic pages. If the null variance shifts across layouts, an adaptive/per-document threshold will be required rather than a single fixed global cutoff.
  * **Bit Error Rate (BER):** < 1% (for any embedded payload bits beyond the spatial template)
  * **Extraction Success Rate:** 100% across a diverse test corpus of at least 100 document images.

## 2. Robustness to Digital Transformations

Watermarks must survive standard workflow operations and common attempts to strip metadata/noise. The criteria for a **GO** vary based on the severity of the transformation.

* **JPEG Compression:**
  * **JPEG 95/80:** GO requires BER < 5%, NC > 0.90. (Standard requirement for robust watermarking)
  * **JPEG 60:** GO requires BER < 10%, NC > 0.85. `[ESTIMATE]`
  * **JPEG 40 (Heavy compression):** GO requires BER < 15%, NC > 0.75. (Expect degradation, but payload should remain statistically distinguishable). `[ESTIMATE]`

* **Geometric Transformations:**
  * **Resize (Scaling down to 50%):** GO requires BER < 5%, NC > 0.90.
  * **Cropping (up to 20% of image area lost):** GO requires BER < 10%, NC > 0.80. (Highly dependent on spatial repetition of the watermark). `[ESTIMATE]`
  * **Rotation (Small angle < 5 degrees, common in scanning):** GO requires BER < 10%, NC > 0.80. (Requires affine-invariant techniques or pre-registration). `[ESTIMATE]`

* **Color & Intensity Transformations:**
  * **Grayscale Conversion:** GO requires BER < 2%, NC > 0.95. (Watermark must survive moving from RGB to Luma channels).
  * **Binarization (Black & White conversion):** GO requires BER < 20%, NC > 0.70. (Binarization destroys massive amounts of frequency data; surviving this is very difficult and is often a stretch goal for continuous-tone watermarks). `[ESTIMATE]`

### Verdict Mapping

The following table explicitly defines the impact on the MVP's viability if the watermark scheme fails to meet the GO thresholds for specific transformations:

| Transformation | Failure Impact |
| :--- | :--- |
| **JPEG 95/80** | **NO-GO-triggering** (Standard requirement for basic workflow survival) |
| **JPEG 60** | **CONDITIONAL GO** (Failure acceptable if explicitly documented) |
| **JPEG 40** | **CONDITIONAL GO** (Stretch goal; failure expected and acceptable) |
| **Resize (50%)** | **NO-GO-triggering** (Standard requirement for basic workflow survival) |
| **Cropping (20%)** | **CONDITIONAL GO** (Failure acceptable if explicitly documented) |
| **Rotation (< 5 deg)** | **CONDITIONAL GO** (Failure acceptable if explicitly documented) |
| **Grayscale** | **NO-GO-triggering** (Standard requirement for basic workflow survival) |
| **Binarization** | **CONDITIONAL GO** (Stretch goal; failure expected and acceptable) |

## 3. False Positive Rate (FPR)

FPR is the likelihood of extracting a valid fingerprint from an unwatermarked document, or misattributing a watermark to the wrong `fingerprint_id`. In a forensic context, false positives are catastrophic for non-repudiation.

* **Threshold for GO:**
  * **Maximum Acceptable FPR:** < 10^-6 (1 in 1,000,000) at a stated confidence interval (e.g., p < 0.001).
  * *Reasoning:* In a system managing thousands of sensitive documents, a single false attribution ruins trust in the audit layer. Error correction (e.g., Reed-Solomon) and cryptographic MACs over the payload are required to reject corrupted extractions rather than guess wrong identities.
  * *Methodology Note:* The false-positive rate target of < 10⁻⁶ will not be measured by direct trial counting. 100,000 null trials will be run, and a statistical distribution (extreme value theory, or an equivalent tail-fitting method appropriate to the observed null-score distribution) will be fit to the empirical null scores. The 10⁻⁶ point will be estimated by extrapolating this fitted distribution, not by directly observing a 1-in-a-million event. Any final report or demo claim referencing this false-positive rate must explicitly state it is a statistically estimated/extrapolated value from 100,000 trials, not a directly measured rate, and must report the fitted distribution's parameters and goodness-of-fit alongside the estimate.

## 4. Conditional Go

A **CONDITIONAL GO** indicates the watermarking scheme is viable for deployment but subject to strict, documented limitations regarding its robustness claims.

* **Definition:** The scheme passes the Baseline and False Positive Rate thresholds, and survives moderate digital transformations (JPEG 80, Grayscale, Resize), but *fails* against heavy attacks (JPEG 40, Binarization, Rotation, or physical Print/Scan cycles).
* **Implication:** The system can be deployed, but the Threat Model and System Limitations documentation must explicitly state: *"Digital-only robustness confirmed. Physical print/scan, heavy cropping, and binarization are explicitly out of scope for the MVP and may destroy the forensic tracing capability."*

## 5. No-Go and Fallback Plan

A **NO-GO** indicates the watermarking scheme is fundamentally unsuitable for forensic use.

* **Trigger Conditions:**
  * Baseline BER is > 5% without any attacks.
  * FPR exceeds the 10^-6 threshold (i.e., the system hallucinates fingerprints).
  * The watermark degrades unacceptable visual quality of the document text (failed PSNR/SSIM thresholds).
* **Fallback Plan:**
  * If the primary spatial/frequency domain watermark fails, simplify claims to purely cryptographic provenance (metadata wrapping) or visible overlay watermarking.
  * Pause Phase 4 implementation to research alternative specialized document watermarking techniques (e.g., line-shift, word-shift, or halftoning manipulation) rather than image-frequency techniques.
