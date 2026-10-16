# GALIA 2.0 — Rust shadow migration v0.3

**Status: DRAFT CANDIDATE / ADVISORY_ONLY / NOT_PROMOTED**

Read-only, additive Rust sidecar for GALIA 2.0. It does not replace Python, write to canonical storage or grant human authority.

## Implemented

- **P1/P2** typed source/stage models, pure fail-closed state machine and human boundaries.
- **P5/P6** structural authority-envelope matching and 12 preflight checks. All supplied policy/authorization/rollback claims are untrusted. No executable guard output.
- **P7 shadow verifier (new)** supplied byte-exact Python-compatible generation manifests, promotion envelopes, HEAD pointers and payloads, SHA-256 hashes and sizes, exact file inventory, identity/policy links, canonical JSON, and optional full parent chain verification (sequence HEAD.seq+1, same case, correct parent).
- Three one-shot stdin/stdout CLI diagnostics: galia-shadow, galia-preflight-shadow, galia-persistence-shadow. The P7 request contains hex-encoded raw bytes for exact manifests, promotion, HEAD, payloads and optionally a parent snapshot.
- Pure Rust unit tests; Python↔Rust differential parity including original P7 disk validator in a temporary test directory. Previous P2/P6 original Python test suites remain in CI.

## Explicit limitations

- The Rust P7 module **does not stage or publish**. It is only a **read-only supplied-snapshot verifier**, not the production generation store.
- integrity_consistent=true proves internal byte consistency of supplied snapshots, **not provenance, author identity, trusted acquisition, anti-rollback freshness or canonical state**.
- A purported HEAD is input data, not a trusted live HEAD. No Compare-And-Swap, atomic fsync, power-loss recovery, authentic signatures, external witness/checkpoint or authoritative promotion occurs.
- This verifier enforces canonical UTF-8 JSON bytes to prevent malleability; that is deliberately stricter than the existing Python verify_generation, which accepts structurally valid noncanonical raw JSON.
- All payload paths are relative; Rust rejects path traversal, Windows separators and unsafe generation identifiers.
- published_at and created_at timestamps are parsed with explicit offsets but are not independent attestations.
- No MLX/model invocation, network, GitHub mutation, Supabase write, DW8 writeback, cross-plane authority transfer, receipt issuance, persistence writes or deployment.

## Verification

~~~sh
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
cargo build --manifest-path rust/galia-core/Cargo.toml --bins
python -m unittest discover -s tests -p 'test_galia2_state_machine.py' -v
python -m unittest discover -s tests -p 'test_galia2_preflight.py' -v
python -m unittest discover -s tests -p 'test_galia2_persistence.py' -v
python -m unittest discover -s rust/galia-core/tests -p 'test_*.py' -v
~~~

## Next gates

1. Independent byte-exact review and frozen fixture corpus for v0.3 SHA-256, manifest HEAD formats and Unicode.
2. P3/P7 **noncanonical scratch** immutable disk staging, locks and atomic CAS with adversarial concurrency, fsync and failure injection, recovery/orphan semantics. Keep disabled from canonical DB until signed human promotion policy integrated.
3. P5/P6 authenticated, revocable human authority; no caller-supplied guard strings as proof.
4. P4 Legacy/MLX capture and discrepancy ledger, legal/GIS projection, DW8 read-only adapters.

**Authority invariant:** A structural or hash PASS is not a human promotion receipt. AUTHORITY_HOLD remains. main, PostgreSQL/Supabase, Python P7 generation store and GitHub control plane are untouched.
