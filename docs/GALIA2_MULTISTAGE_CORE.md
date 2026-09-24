# GALIA 2.0 Multistage Core v1

This directory documents the add-only repository integration package for the promoted GALIA 2.0 P1-P10 baseline.

## Integration boundary

GALIA 2.0 is installed beside the Legacy runtime. The integration package does not modify `main.py`, `benchmark.py`, `requirements.txt`, `README.md`, `.gitignore`, or `LICENSE.md`.

The Legacy runtime remains authoritative for its existing execution behavior. GALIA 2.0 observes Legacy only through `galia2.runtime_integration.RuntimeShadowBridge`, which delegates exactly one `Runtime.call(...)` invocation and sends an observation to the read-only shadow adapter.

## Core pipeline

`Legacy -> shadow -> stages -> discrepancy/evidence -> AUTHORITY_HOLD -> human decision -> promotion preflight -> immutable generation -> explicit publish -> recovery/audit`

## Non-negotiable invariants

- `RUNTIME_OBSERVED != AUTHORITY_GRANTED`
- `STAGED != CANONICAL`
- `PREFLIGHT_PASS != CANONICAL`
- `RECOVERY != NEW_AUTHORITY`
- no automatic promotion
- no automatic recovery-target selection
- no writes to Legacy master from the GALIA 2.0 package

## Opt-in use

No Legacy behavior changes merely by adding the package. A caller must explicitly instantiate and invoke the GALIA 2.0 bridge or other components.
