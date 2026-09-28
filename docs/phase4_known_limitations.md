# Phase 4 Known Limitations

## Collusion Vulnerability — Measured

### Self-Differencing
Tested and confirmed **NOT exploitable**. Because the protocol uses stable per-recipient fingerprint seeds (`fingerprint_id`), multiple document releases requested by the same recipient produce byte-for-byte identical images. Averaging 10 copies and differencing the result against the clean host yields a correlation score identical to a single copy (`0.747170` vs `0.747170`).

### Collusion
Tested and confirmed that this vulnerability is primarily a **deniability/evasion attack**, not a false-accusation risk. By averaging multiple independently-watermarked copies of the same document, colluding recipients can successfully erase/wash out their own attribution marks so that their leaked copy evades detection entirely. 

Experimentation reveals that **evasion reliably occurs by N=7 colluding recipients, but may occur as early as N=6 depending on which specific recipients collude.** (In repeated trials, some $N=6$ combinations maintained scores just above the `0.011012` threshold, while others dropped into the `0.008` range and successfully evaded detection. By $N=7$ and beyond, all tested combinations resulted in false negatives).

Conversely, false-accusation risk (misattribution to an innocent bystander) was tested up to $N=25$ colluders and did *not* occur. This happens because the per-document adaptive threshold is calibrated against that document's own null distribution, and an averaged image of independent pseudo-random watermarks converges toward that exact null case as $N$ grows. Thus, the dynamic threshold calibration incidentally provides partial protection against false accusation even without being explicitly designed for collusion resistance.

This is an accepted, pre-declared MVP limitation. Full collusion resistance (e.g., Tardos codes or similar collusion-resistant coding) remains out of MVP scope, consistent with the original 10-day feasibility decision.

**Recommendation for Future Forensic Matcher (Phase 9/10):**
Matching must use relative ranking with a required margin over the next-best candidate score, rather than an independent per-candidate absolute-threshold check. This specific collusion result proves that independent thresholding alone is exploitable when multiple copies are averaged. 

Full collusion resistance (e.g., Tardos codes) remains out of MVP scope, consistent with the original 10-day feasibility decision.
