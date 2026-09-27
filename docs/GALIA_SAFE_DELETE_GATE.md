# GALIA SAFE_DELETE Gate v1 — Recovery v2 candidate

The SAFE_DELETE gate is already promoted on main. This recovery candidate updates
only the evidence state and tightens preservation of a now-recovered OW21 package.

## Newly recovered and byte-verified

- OW02 package SHA-256: `4fade434491c8a4b345c576fffc7dc1a017a52bf00c86e6b2b53433e00df9907`
- OW02 SQLite SHA-256: `455f67ab608714af9cb2687fb567b600ed7730d386f6d2238bc62a68dde07948`
- OW10 package SHA-256: `bbd1188b3141b61a4d7738fdd1dba51244265456b5b0d7b759c2aee4e9ae4eda`
- OW10 SQLite SHA-256: `709099a1d695f0cb53983dfef6a7983b75aa5c1992a9d5c32061c611471d36b2`
- OW21 package SHA-256: `b1c90bf046439a97c3b6faa961fd44cc080ceebcd2109ec8dd0def7f7bc662f0`
- OW21 SQLite SHA-256: `9b4634df16377f006c92b09fca936296aaeb58e5620696181f24c5efbe8a14ab`

All inspected SQLite members pass `integrity_check=ok` and have zero foreign-key violations.

## Staging vault

Library path:

`/GALIA_FINAL_VAULT_STAGING_2026-09-26`

The staging vault contains verified server-side copies of master 1.0.1, Santurce
15-003, 14-003, cleanup 948d41, OW02, OW10, OW21 and recovery vault R6.

Staging manifest SHA-256:

`a4cfa473e33c5e9f5f869ece8a6100ddfd6c4a7f78d89348974e938f9923e19c`

This is **not** the final vault because one mandatory byte object remains absent.

## Remaining raw-byte deficit

`5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`

The cleanup package identifies that value only as `source_v1_30_sha256`; the
filename is unresolved. Exact-hash scans of the accessible Library, R6 recovery
vault, forward-development seed and v1.30 preservation bundle did not recover
those bytes.

A reverse reconstruction was not promoted as a substitute: the database's
append-only journal correctly blocks destructive rollback of the cleanup trace.

## Effective decision

`SAFE_DELETE = HOLD`

After this recovery candidate, the remaining blockers are:
- upstream `5ed030...` raw bytes;
- final vault completion;
- final clean-room restore;
- exact deletion manifest;
- deletion-specific human authorization.

No deletion operation is added.
