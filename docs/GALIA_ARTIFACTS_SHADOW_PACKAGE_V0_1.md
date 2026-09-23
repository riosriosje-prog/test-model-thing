# GALIA Artifacts Shadow Package v0.1

## Purpose

Expose the historical artifact store under `galia.history.artifacts` without
moving implementation authority or changing persistence behavior.

## Design

- Legacy `historical_artifacts.py` remains authoritative.
- `galia.history.artifacts` re-exports the exact legacy objects.
- Object identity is tested.
- Content-addressed storage behavior is unchanged.
- SHA-256 verification behavior is unchanged.
- Artifact locators and filesystem layout are unchanged.
- Historical Store bindings are unchanged.
- No artifact bytes are added to Git.
- No Historical Store schema or claim semantics change.
- No checkpoint behavior changes.

## Promotion sequence

1. Shadow package surface.
2. Validate editable package installation in CI.
3. Validate legacy/package object identity.
4. Human gate.
5. Only later may implementation authority move under `src/galia/`, with the
   root module becoming a compatibility shim.

`IMPLEMENTATION_AUTHORITY = LEGACY_ROOT`

`PACKAGE_SURFACE = SHADOW`

`ARTIFACT_FORMAT = UNCHANGED`

`CANONICAL_PROMOTION = FALSE`
