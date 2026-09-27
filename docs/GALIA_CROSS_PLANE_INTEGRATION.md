# GALIA 2.0 — GitHub / Hugging Face / Supabase integration

Status: **CANDIDATE — HUMAN PROMOTION REQUIRED**

This candidate closes the identity graph between GALIA's three operational planes without changing the authority model.

## Planes

- GitHub: canonical source/control plane.
- Hugging Face: ML/evidence artifact plane.
- Supabase: structured canonical/staging/audit data plane.

## GitHub merge-stable binding

Candidate base:
- repo: `riosriosje-prog/test-model-thing`
- ref: `main`
- pre-merge base: `384a1b1b2c804b6d7838cd301d61232dd6313895`

The candidate **does not** hard-code that base as the post-promotion authority identity.

At promotion time the exact resulting merge commit must replace:

`__PROMOTED_MAIN_COMMIT__`

in the Supabase binding template. The template fails closed unless the replacement is a lowercase 40-hex Git commit. The promotion receipt must bind that exact merge commit.

HF8 model:
- repo: `Junitos/galia-2`
- path: `weights/hf8-retrain-v0.2-4k`
- payload SHA-256: `3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c`
- manifest SHA-256: `a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2`

HF9 evidence schema:
- repo: `Junitos/galia-2-evidence`
- schema manifest SHA-256: `1a2545f83a3e6fc0c7f59fad11d7237c67781216123fd985fd56088cdfdc001e`
- evidence records: 0
- raw evidence bytes: 0

Supabase:
- project: `galia-cangrejos`
- project id: `nzoviwitcqmsacwiizhh`
- current schema: 1.3.2
- target schema after promotion: 1.4.0

## Additive design

The historical `audit.external_anchors` table remains unchanged. It is GitHub-specific and preserves its existing two historical anchors.

The candidate adds:
- `audit.cross_plane_bindings`
- `audit.cross_plane_binding_edges`

Both tables are RLS-enabled and deny `anon` / `authenticated` access by default.

## Authority boundary

```text
GitHub       = CONTROL PLANE / source of truth
Hugging Face = ML + evidence artifact plane
Supabase     = DATA PLANE

HF artifact presence != canonical authority transfer
Supabase row presence  != canonical authority transfer
```

This candidate does not migrate historical evidence records to HF, mutate Legacy, close G28, lift SAFE_DELETE, or transfer authority.
