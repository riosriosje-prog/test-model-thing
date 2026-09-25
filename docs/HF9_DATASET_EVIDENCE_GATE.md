# HF9 — dataset/evidence repository gate

Target: `Junitos/galia-2-evidence` (private Hugging Face dataset repository).

HF9 v0.1 established and promoted a schema-only ML artifact surface. It intentionally carries **zero historical evidence records** and **zero source images/raw captures**.

## Current gate states

- HF9A destination namespace/repo creation: PASS
- HF9B deterministic schema export: PASS
- HF9C remote upload as PR: PASS
- HF9D remote manifest/hash verification: PASS
- HF9G dataset schema-surface promotion: PROMOTED
- HF9E evidence-record migration: HOLD
- HF9F image/source-byte migration: HOLD

Promoted schema surface:

- repo: `Junitos/galia-2-evidence`
- source SHA: `4a6b5862ae7b86f9db0d469e1a52b5a751de9a58`
- manifest SHA-256: `1a2545f83a3e6fc0c7f59fad11d7237c67781216123fd985fd56088cdfdc001e`
- verified files: 5
- evidence records: 0
- source images: 0
- raw evidence bytes: 0

## Authority boundary

```text
GitHub       = CONTROL PLANE
Hugging Face = ML ARTIFACT PLANE

source_of_truth                 = github
canonical_authority_transferred = false
```

Promotion of the HF9 schema surface did not authorize actual historical-evidence migration and did not transfer canonical authority.

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
