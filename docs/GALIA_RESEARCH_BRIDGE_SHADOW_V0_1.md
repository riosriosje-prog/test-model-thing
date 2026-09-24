# GALIA Research Bridge Shadow Package v0.1

## Purpose

Expose the research bridge under `galia.bridge.research` without moving
implementation authority or changing the boundary between engine output and
Historical Store claims.

## Design

- Legacy `galia_history_bridge.py` remains authoritative.
- `galia.bridge.research` re-exports the exact legacy objects.
- Object identity is tested.
- Engine outputs remain provenance-linked PROPOSED claims.
- Human review remains required for CANONICAL promotion.
- `engine_version` and `prompt_version` semantics are unchanged.
- No Historical Store schema changes.
- No checkpoint behavior changes.
- No canonical historical data changes.

## Invariants

`ENGINE_OUTPUT != CANONICAL_TRUTH`

`PROPOSED_CLAIM != CANONICAL_CLAIM`

`PROMPT_VERSION != ENGINE_VERSION`

`IMPLEMENTATION_AUTHORITY = LEGACY_ROOT`

`PACKAGE_SURFACE = SHADOW`

`CANONICAL_PROMOTION = FALSE`
