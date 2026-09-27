# GALIA — Trust-root pointer reconciliation v3

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

The prior reconciliation design treated a GitHub `main` HEAD SHA as if it were a durable authority identity. That is self-invalidating: merging the pointer reconciliation itself advances `main`.

v3 fixes the model.

## Stable control-plane identity

The pointer now separates:

- tracked ref: `main` (moving);
- authority anchor commit: `25db17fa583d1561d746ee7d33407d3684ee561d` (immutable);
- authority anchor role: `CROSS_PLANE_INTEGRATION_PROMOTION_BASELINE`.

Later commits on `main` do **not** make the trust-root pointer stale. A new pointer is required only when GALIA intentionally promotes a new authority baseline, not for ordinary control-plane commits.

## Unchanged authority

- GLOBAL_MASTER: `RC-GALIA-2026-09-13-004`
- master SQLite SHA-256: `9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354`
- trust-root v8 SHA-256: `7aa0d35cdd6b3746c43f0cfd379fdb78e50347b32ff8fa0092fd7ded6956e778`
- G20/G22/G27 unchanged
- G28 remains `OPEN_UNPROVEN_FORENSIC_ONLY`
- SAFE_DELETE remains `HOLD`
- Santurce research scope remains separate
- HF artifacts remain unchanged

## Proposed pointer

SHA-256:
`ed6a18b96871209593f910afd9d3879eabb5fcc7c5af7c844e623e241281dbb6`

Predecessor pointer:
`ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9`

The pointer becomes effective only when an external human promotion receipt binds that exact SHA-256.

## Supabase

The reconciliation is fail-closed. It requires:

1. current binding revision = authority anchor `25db17fa...`;
2. current trust-root pointer SHA = predecessor `ceb60f75...`.

If either condition differs, the SQL aborts. Promotion updates only pointer metadata and revision semantics; it does not change the authority anchor revision.
