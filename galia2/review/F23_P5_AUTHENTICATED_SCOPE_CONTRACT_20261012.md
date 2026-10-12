# F23/P5 authenticated scope contract (design gate, not implementation)

Status: DW5 CANDIDATE_BLOCKED / DW7 BLOCKED / AUTHORITY_HOLD / canonical_effect=NONE.

## Two independent checks

1. **Structural correspondence:** compare case_id, target_type and the exact ordered target_ids against a verified, versioned mapping to F22 candidate_set_sha256, conflict_component_sha256, selected_candidate_id and reconciliation_sha256. Do not infer case_id from a provider scope or derive a target type from token text.
2. **Human-decision authentication:** verify an externally authenticated human SELECT record and its signer/issuer authority, reviewer identity, decision id, policy version, decision timestamp, case/target scope and exact F22 hashes. A self-hashed reconciliation transcript is not a human signature. A P5 AuthorityScope object is not a decision.

## Fail-closed requirements

- Missing or unauthenticated decision -> reject.
- Valid decision for a different case, target type, target ids, selected candidate, component or candidate-set digest -> reject.
- Revoked/expired or otherwise unauthorized decision -> reject.
- Malformed or ambiguous scope mapping -> reject.
- Never mutate Claim, issue promotion authorization, lift AUTHORITY_HOLD, close byte identity/F5 or alter master.

## Testing gate

The synthetic positive control in PR #113 proves only that the function is reachable; it is **not** an authenticated-positive admission test. Add an authenticated-positive fixture using a verified issuer and independent negative tests changing one bound dimension at a time. Run repository CI on exact proposed code before considering merge.

No trusted issuer or mapping has been established by this document; implementation must remain blocked until one is available.
