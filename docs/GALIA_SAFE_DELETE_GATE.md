# GALIA SAFE_DELETE Gate v1 — Recovery v2 candidate

The SAFE_DELETE gate is already promoted on main. This recovery candidate updates
only the evidence state and preserved-byte inventory. It authorizes no deletion.

## Newly recovered and byte-verified

- OW02 package SHA-256: `4fade434491c8a4b345c576fffc7dc1a017a52bf00c86e6b2b53433e00df9907`
- OW02 SQLite SHA-256: `455f67ab608714af9cb2687fb567b600ed7730d386f6d2238bc62a68dde07948`
- OW10 package SHA-256: `bbd1188b3141b61a4d7738fdd1dba51244265456b5b0d7b759c2aee4e9ae4eda`
- OW10 SQLite SHA-256: `709099a1d695f0cb53983dfef6a7983b75aa5c1992a9d5c32061c611471d36b2`
- OW21 research-checkpoint package SHA-256: `960e3bb7f1c3aa943a65e20ea2f81fc298391c16f4fd2c2177c56226f2a4c73a`
- OW21 research worktree/freeze SQLite SHA-256: `7dbc8feca01a4f6623101c25b6aa1e07b09dda7c0370997b164f8fef70f63866`
- supplementary consolidated OW21 package SHA-256: `b1c90bf046439a97c3b6faa961fd44cc080ceebcd2109ec8dd0def7f7bc662f0`
- supplementary consolidated SQLite SHA-256: `9b4634df16377f006c92b09fca936296aaeb58e5620696181f24c5efbe8a14ab`

All inspected SQLite members pass `integrity_check=ok` and have zero foreign-key violations.

## Staging vault

Library path:

`/GALIA_FINAL_VAULT_STAGING_2026-09-26`

The staging vault contains verified server-side copies of master 1.0.1, Santurce
15-003, 14-003, cleanup 948d41, OW02, OW10, both recovered OW21 packages, and
recovery vault R6.

Staging-manifest SHA-256:

`22a32473f13028491c96f4e665e2a009e602b9bd15e06010dd73bd44c4d3e1e6`

This remains a staging vault, not the final vault, because one mandatory byte
object is still absent.

## Remaining raw-byte deficit

`5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`

The cleanup package identifies this value only as `source_v1_30_sha256`; its
filename remains unresolved. Exact-hash scans of accessible Library objects,
the R6 recovery vault, forward-development seed, v1.30 preservation bundle,
and standalone SQLite inventory did not recover those bytes.

A reverse reconstruction is not accepted as a substitute. The cleanup database
correctly enforces its append-only journal and blocked destructive rollback.

## Effective decision

`SAFE_DELETE = HOLD`

After this recovery candidate, remaining blockers are:
- upstream `5ed030...` raw bytes;
- final vault completion;
- final clean-room restore;
- exact deletion manifest;
- deletion-specific human authorization.

No deletion operation is added.
