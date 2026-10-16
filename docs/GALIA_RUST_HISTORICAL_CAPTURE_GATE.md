# GALIA Rust — Historical Source-Capture HOLD (McLeary, 1915)

**Status:** Rust shadow candidate / no canonical writes / human review required.

## Purpose

`rust/galia-core/src/historical_capture.rs` accepts the exact proposed
`galia.research.primary_capture_gate.v0.1` manifest schema from the McLeary
1915 source-acquisition gate (Python candidate PR #118). It returns an advisory
`AUTHORITY_HOLD` assessment **only** when both documentary observations are
explicitly non-primary and unverified. This does **not** validate the
historical words printed in the issues, source authenticity or the identity
of a person after whom the road may have been named.

The fixture under `rust/galia-core/tests/fixtures/` is a **static snapshot**
mirroring the Python PR #118 candidate. It is not evidence itself and is not
an import from authoritative archival custody.

## Historical observations

| Issue | Reported page | Current evidentiary tier | Primary scan | SHA-256 |
|---|---|---|---|---|
| *El Tiempo*, 22 November 1915 | 4 | Prior project transcription | Not independently acquired | None |
| *El Tiempo*, 26 November 1915 | 4 | Search-index/OCR excerpt | Not independently acquired | None |

A search engine indexes the phrase `Avenida MacLeary. Parada 44` for the
26 November 1915 issue. The exact typeface and original page image have not
been independently checked. No first-ever mention, municipal naming act,
opening date, eponym, or 1915-to-1916 street-identity equivalence follows.

## API and acceptance

```rust
use galia_core_shadow::historical_capture::inspect_historical_capture_hold;

let assessment = inspect_historical_capture_hold(manifest_json)?;
assert_eq!(assessment.disposition, "AUTHORITY_HOLD");
assert_eq!(assessment.blocker, "RAW_CAPTURE_REQUIRED");
assert!(!assessment.canonical_write_authorized);
```

The parser denies unrecognized fields and rejects missing documentary limits,
invalid source dates, duplicate IDs, unrecognized OCR/provenance tiers, claims
that hashes/bytes or a scan were captured, assertions of human/typographic
review, and removal of required promotion prohibitions. It cannot issue
`RAW_CAPTURED`, `CANONICAL`, P5 review signatures or writes to historical
storage. This is a logical guard, **not** a secure original-source verifier,
file downloader, remote-custody attestation, immutable archive or cryptographic
receipt. The input itself must eventually be sourced from an authenticated
provenance workflow.

Tests:

```bash
cargo test --manifest-path rust/galia-core/Cargo.toml --test historical_capture
cargo test --manifest-path rust/galia-core/Cargo.toml --all-targets
```

## Approval and source-document requirements

1. Acquire independently attributable original newspaper bytes from UFDC or
   the responsible repository, preserving source locator and acquisition log.
2. Verify issue date/page physically, visually review typography, and record
   scanned-file SHA-256 and verified byte length from **locally retained** bytes.
3. Preserve transcription discrepancies and document-date/event-date separation.
4. Require independently recorded qualified human review; then consider new
   evidence state in a separately governed versioned gate. Never infer
   canonical authority from a passing Rust test.

Original PDF retrieval was unsuccessful in the review underlying PR #118;
there are therefore no captured primary image files or trusted hashes to
insert in this Rust candidate.
