# F23/P5 scope-boundary review — DW5 (2026-10-12)

Status: REVIEW ONLY; DW5 CANDIDATE_BLOCKED; DW7 BLOCKED; AUTHORITY_HOLD; canonical_effect=NONE.

## Verified remote interface
- galia2/reconciliation_authority_binding.py Git blob: 7a50eece4524d2f7817af07e9d2cceaa0c2bb359.
- galia2/authority.py Git blob: 247da6228f1e6d7c41ac3b1896409c2c5d459611.
- F23 binds p5_scope.token, but does not independently check p5_scope.case_id, target_type, target_ids against authenticated F22 case evidence.
- A P5 token is not an authenticated human selection or master promotion authority.

## Admission requirements
1. Define an evidence-backed, versioned mapping between F22 case/candidate/component identifiers and P5 AuthorityScope (case_id, target_type, target_ids). Never infer from token formatting alone.
2. Reject mismatched case, target type, target IDs, candidate-set hash, selected candidate and unauthenticated human selection.
3. Preserve exact F22 source evidence, candidate lineages, temporal windows and reconciliation hashes.
4. Execute negative functional tests and full repository regression against exact proposed bytes; attach immutable CI receipts.
5. Require DW5 provenance verification and independent DW6 human authorization before any DW7 eligibility review.

This document does not change runtime code, assert CI success, authenticate a trust root, or authorize promotion.
