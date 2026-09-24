# GALIA 2.0 P13 — Historical Shadow Operation Pilot

P13 is the first operational bridge from the existing `HistoricalStore` research
surface into the promoted GALIA 2.0 multistage core.

## Boundary

`HistoricalStore(PROPOSED/VALIDATED) -> deterministic snapshot -> GALIA2 stages -> AUTHORITY_HOLD`

P13 is read-only with respect to `HistoricalStore`. It consumes only
`claim_bundle()` and `claim_promotion_blockers()` and does not call human-review,
promotion, persistence, publish, rollback, or model-runtime APIs.

## Fail-closed behavior

- A source claim already marked `CANONICAL`, `REJECTED`, or `QUARANTINED` is not
  imported as authority.
- A claim without an evidence snapshot is routed to GALIA 2.0 `QUARANTINED`.
- HistoricalStore promotion blockers, including `RAW_CAPTURE_REQUIRED`, are
  preserved in the shadow result and do not disappear merely because the claim
  reaches `AUTHORITY_HOLD`.
- Every P13 receipt has `output_commit=None`.

## Pilot case

CI exercises the existing Finca El Condado shadow dataset. A provenance-anchored
claim reaches `AUTHORITY_HOLD` while the source claim remains `PROPOSED` and the
HistoricalStore audit/state fingerprint remains semantically unchanged.
