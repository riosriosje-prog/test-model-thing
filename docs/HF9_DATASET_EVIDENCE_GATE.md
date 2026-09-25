# HF9 — dataset/evidence repository gate

Target: `Junitos/galia-2-evidence` (private Hugging Face dataset repository).

HF9 v0.1 establishes a schema-only distribution surface. It intentionally carries **zero historical evidence records** and **zero source images/raw captures**.

## Gate states

- HF9A destination namespace/repo creation: candidate workflow
- HF9B deterministic schema export: implemented
- HF9C remote upload as PR: candidate workflow
- HF9D remote manifest/hash verification: candidate workflow
- HF9E evidence-record migration: HOLD
- HF9F image/source-byte migration: HOLD
- HF9G dataset promotion: HUMAN DECISION REQUIRED

## Authority boundary

GitHub remains the source of truth. Hugging Face is a distribution surface only. No dataset PR merge transfers canonical authority.

## Exit criteria for actual evidence migration

1. Exact source package selected.
2. Every raw artifact has byte size + SHA-256.
3. Provenance/custodian/signatura/page metadata captured.
4. DOCUMENT_DATE and EVENT_DATE are independently populated.
5. Derivation lineage is explicit.
6. Image gate is VERIFIED or item remains QUARANTINED.
7. Authentication/admissibility and weight remain separate.
8. Discrepancies are not silently normalized away.
9. Remote snapshot is byte/hash verified.
10. Human promotion is recorded separately from technical verification.
