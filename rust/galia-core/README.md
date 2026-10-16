# GALIA 2.0 — Rust migration, shadow phase v0.1

**Status: CANDIDATE / ADVISORY_ONLY / NOT_PROMOTED**

This is an additive, isolated Rust implementation of GALIA's **P1 Stage/SourceArtifact** validation and the **P2 state transition table**. It is a *conformance experiment*, not a replacement for the Python code or a deployed GALIA runtime.

## Scope actually implemented

- Strict Rust models for Stage, StageState and SourceArtifact (dates kept separate).
- Pure P2 transition decisions and immutable Stage replacement.
- Exact P2 guards, fail-closed rejection, human boundaries and failure isolation.
- JSON stdin/stdout diagnostic CLI (one request per process).
- Rust unit tests and Python↔Rust differential vectors.
- No TMT/MLX import, network, filesystem writes, Supabase, GitHub mutation, stage-persistence, GraphRAG writeback, human-authorization issuance or canonical promotion.

**Critical security boundary:** Strings like human_decision_present, preflight_passed and authorization_matches_target are *not verified by this crate*. They are merely P2 inputs. A caller cannot treat an advisory decision or a guard string as an authenticated approval. Until P5/P6/P7 integration validates signed or otherwise authenticated human authorizations, this engine MUST remain read-only.

## Local usage

From repository root:

~~~sh
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
cargo build --manifest-path rust/galia-core/Cargo.toml --bin galia-shadow
python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v
~~~

Example request (stdin JSON):

~~~json
{
  "stage": {"stage_id":"s1","case_id":"c1","stage_type":"CORE","state":"DISCOVERED"},
  "event": "INGEST_CONFIRMED",
  "satisfied_guards": ["source_artifact_valid"]
}
~~~

The CLI returns status ADVISORY_ONLY or REJECTED. It *never* writes a canonical commit or grants authority, even if the decision's to_state is CANONICAL.

## Migration sequencing (not yet implemented)

1. P1/P2: Rust shadow evaluation vs current Python fixtures. **This candidate.**
2. P4: binary-safe Legacy/MLX shadow capture and byte-level differential tests, with separate hash domains.
3. P3/P7: append-only persistence, atomic HEAD CAS, tamper/replay/recovery; byte-exact manifest/receipt canonical JSON conformance against frozen Python fixtures.
4. P5/P6: narrowly scoped human authority, revocation, exact target binding, preflight, rollback verification; negative gate tests and non-forgeable provenance.
5. Historical research: evidence/discrepancy ledger, temporal history, source acquisition, legal-execution adapter.
6. DW8 read-only projection and publisher; keep Python/MLX and other model tooling behind explicit interfaces until proven equivalent.
7. Production cutover only after Rust↔Python differential parity, adversarial checks, reproducible builds, independent human review and approved promotion receipt.

## Invariants

- EVENT_DATE != DOCUMENT_DATE.
- PROMPT_VERSION != ENGINE_VERSION.
- Generated images are never historical evidence.
- Canonical writes and authority transfer are **disabled** here.
- No automatic promotion, no DW8 writeback.
- Failed checks route to quarantine, discrepancy review or recovery; not to CANONICAL.
- Keep original Python code and repository main intact until separately reviewed.

Based on Python reference:
- galia2/core.py
- galia2/state_machine.py
- tests/test_galia2_state_machine.py

This candidate neither alters nor replaces those files.
