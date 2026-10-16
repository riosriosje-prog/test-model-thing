# GALIA 2.0 — Rust migration, shadow phase v0.2

**Status: DRAFT CANDIDATE / ADVISORY_ONLY / NOT_PROMOTED**

Additive Rust sidecar for **P1/P2** plus **P5 authority-envelope matching** and **P6 structural preflight diagnostics**. This is **not** a deployment, replacement for Python, a source of human authority, or a production cutover.

## Implemented and tested

- P1: Stage and SourceArtifact typed validation; document and event dates remain independent.
- P2: guarded, pure state transitions and explicit human boundaries; quarantines/recovery.
- P5 shadow: typed scope and supplied authorization **comparison**, without issuance, authentication or revocation.
- P6 shadow: 12 deterministic checks (lineage, schema, stages, discrepancy hold, decision, exact authorization binding, exact rollback parent and flags), all advisory. **No emitted preflight guards, no promotion guards and no receipts.**
- Two JSON stdin/stdout CLI diagnostics: galia-shadow (P2) and galia-preflight-shadow (P6).
- Unit tests and differential Rust/Python reference tests; CI runs original Python P2 and P6 suites.

### Security warning

JSON-supplied authorization, known_good and integrity_valid are **untrusted assertions**: exact matching is necessary but never sufficient. There is no cryptographic verification of author identity, rollback bytes or canonical manifests. This crate must NOT feed output back as approval to the Python orchestrator. A reporting passed=true means only that user-supplied P6 **structural inputs** match.

No canonical database writes, HEAD mutation, promotion, side effects, network, model/MLX invocation, DW8 graph writeback, human signature validation, validated receipts, or authority transfer.

## Local verification

~~~sh
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
cargo build --manifest-path rust/galia-core/Cargo.toml --bins
python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v
~~~

P2 one-shot input example:

~~~json
{
  "stage": {"stage_id":"s1","case_id":"c1","stage_type":"CORE","state":"DISCOVERED"},
  "event": "INGEST_CONFIRMED",
  "satisfied_guards": ["source_artifact_valid"]
}
~~~

P6 one-shot requires exact typed PreflightRequest JSON: config, candidate, rollback, optional authorization, expected_scope. Output is ADVISORY_ONLY or REJECTED, never a canonical receipt.

## Remaining migration

1. Add P4 Legacy/MLX shadow comparison with content-addressed captures and binary-safe hashes.
2. P3/P7 append-only generation store, integrity, canonical JSON, atomically verified HEAD CAS, replay/rollback, recoverability; match Python frozen fixtures.
3. P5/P6 authenticated and revocable authority provenance, target+scope binding, independent human approval and negative adversarial verification.
4. Evidence/discrepancy ledger, historical chronology, case-specific GIS/Legal Execution gates.
5. DW8 read-only retrieval/publisher ports, keep Python/MLX behind versioned interfaces until parity demonstrated.
6. Independent human review of safety/performance and separate production deployment/cutover approval.

**Constitutional invariants:** EVENT_DATE != DOCUMENT_DATE; PROMPT_VERSION != ENGINE_VERSION; HUMAN_PROMOTION_REQUIRED=true; CANONICAL_WRITEBACK_FROM_DW8=false; AUTHORITY_TRANSFER_FROM_LEGAL_EXECUTION=false.

Existing Python runtime, main, Supabase and DW8 are untouched; pending explicit review and authorization.
