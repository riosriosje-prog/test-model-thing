# GALIA Acquisition Shadow Package v0.1

## Purpose

Validate the first low-coupling package surface without moving runtime authority.

## Design

- Legacy `historical_acquisition.py` remains authoritative.
- `galia.history.acquisition` re-exports the exact legacy objects.
- Object identity is tested, not merely equivalent behavior.
- No Historical Store schema or claim semantics change.
- No checkpoint behavior changes.
- No canonical historical data changes.

## Promotion sequence

1. Shadow package surface.
2. Validate editable package installation in CI.
3. Validate legacy/package object identity.
4. Human gate.
5. Only in a later, separate change may implementation authority move under
   `src/galia/`, with the root module becoming the compatibility shim.

`IMPLEMENTATION_AUTHORITY = LEGACY_ROOT`

`PACKAGE_SURFACE = SHADOW`

`CANONICAL_PROMOTION = FALSE`
