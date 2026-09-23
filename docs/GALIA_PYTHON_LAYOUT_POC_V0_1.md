# GALIA Python Package Layout POC v0.1

## Purpose

Introduce a reversible `src/` package boundary without moving or changing any
existing runtime module.

## Scope

This POC adds:

- `pyproject.toml`
- `src/galia/__init__.py`
- CI path coverage for `pyproject.toml` and `src/**`

It does **not** move, wrap, or modify:

- `main.py`
- `historical_store.py`
- `historical_artifacts.py`
- `historical_acquisition.py`
- `historical_store_bundle.py`
- `galia_history_bridge.py`

## Invariants

- Legacy import paths remain authoritative.
- Checkpoint byte identity must not change.
- Historical Store schema must not change.
- No canonical historical claim is promoted.
- No SQLite database or evidence artifact is versioned.
- Every later module move requires a separate compatibility shim, tests,
  preflight, and human gate.

## Promotion plan

1. Validate this inert package skeleton.
2. Move low-coupling modules one at a time behind compatibility shims.
3. Keep `main.py` last.
4. Require Python 3.12 and 3.13 CI at each step.
5. Treat packaging changes as structural refactors, never semantic promotion.

## Status

`SHADOW_POC = TRUE`

`CANONICAL_PROMOTION = FALSE`
