# GALIA 2.0 — DW5 candidate review (F22→F23)

Status: **CANDIDATE_BLOCKED / AUTHORITY_HOLD**. This is a review manifest, **not** an implementation merge, authority attestation, or promotion request.

- Source branch: `galia2/f22-f23-repro-candidate-20261012`
- Target branch: `galia2/dw5-review-base-20261012` (never `main`)
- Local synthetic reproducibility report: **67/67 PASS** (not remote CI).
- Local archive: `GALIA_DW5_F22_F23_REPRODUCIBLE_TEST_BUNDLE_2026-10-12.zip`
- Archive SHA-256: `178fb3d49ef4c24f010a872abd6d5354f217210ed52d72e68fd69a13a6eb05c3`
- Archive F22 file SHA-256: `3ee64a680b2bea191b9f31652bfd97829a77f6540aaa1ba5f4a29fb9762e4fc8`
- Repository F22 file Git blob SHA-1: `40cda0e5b1525b049c18a4e916ae49685cf0bea2`

## Required DW5 checks before code import

1. Independently reconcile repository F22 source bytes against the archived F22 source; do not treat Git blob SHA-1 as SHA-256.
2. Verify exact producer path, revision, provenance, and all archived file hashes; reproduce tests in clean CI against the exact intended source.
3. Validate F22/F23 cumulative patches against current branch, without replacing existing master code.
4. Recover and authenticate original raw trust-root artifacts and human decision bindings; no synthetic evidence as legal authority.
5. DW6 requires independently authenticated explicit human selection bound to exact candidate-set hash; DW7 may only report BLOCKED or PROMOTION_ELIGIBLE_FOR_HUMAN_EXECUTION and never executes a merge.

Invariants: `canonical_effect=NONE`; `BYTE_IDENTITY_OPEN`; `PROVIDER_HASH_DOMAIN_OPEN`; `READBACK_BLOCKED`; `AUTHORITY_HOLD`. Preserve all original evidence and append-only lineage. No master promotion authorized by this PR.
