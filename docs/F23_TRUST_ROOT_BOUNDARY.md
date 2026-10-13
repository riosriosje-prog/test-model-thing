# F23/P5 trust-root boundary (design only)

Status: **AUTHORITY_HOLD**. No policy file, signature, hash, or successful
unit test grants authority to bind evidence or write canonical records.

## Existing components

- `f23_attestation_crypto.py` verifies Ed25519 signatures over domain-separated
  canonical attestation bytes. Its public-key mapping is caller supplied.
- `f23_issuer_policy.py` validates a caller-supplied issuer policy including
  reviewer membership, UTC-normalized validity bounds and revocation.
- `f23_verified_scope_gate.py` intentionally denies all admission requests,
  even when attestation fields and reconciliation hashes agree.

## Missing authority prerequisites

1. A separately governed, authenticated and versioned trust-root distribution
   channel, independent of the request and the attestation under evaluation.
2. An issuer enrollment and key-rotation procedure with documented human
   approvals and a verifiable audit trail.
3. Reviewer identity proofing and scope-specific authorization, including
   delegation limits and separation of duties.
4. Signed revocation records, freshness requirements, replay protection and
   explicit fail-closed behavior when policy cannot be fetched or verified.
5. Independent policy evaluation that binds issuer, reviewer, decision,
   reconciliation, target IDs and effective time to the same signed context.
6. Adversarial tests for substituted roots, rollback, stale revocation,
   key replacement, cross-case replay and conflicting policy versions.

## Non-goals and invariants

Do not treat a self-hashed F22 decision as authenticated human approval.
Do not load a trust root from user-provided attestation fields or a caller
argument and then call that independent verification. Do not connect local
policy validation to the admission gate until all prerequisites are reviewed.

Keep `DW5 CANDIDATE_BLOCKED`, `DW7 BLOCKED`, `AUTHORITY_HOLD`,
`canonical_effect=NONE`, `auto_publish=false`, and no canonical writes.
Review branch changes must not be merged into `main` without explicit approval.
