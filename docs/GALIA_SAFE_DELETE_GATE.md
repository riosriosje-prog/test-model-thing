# GALIA SAFE_DELETE Gate v1 — Recovery v4 candidate

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

Recovery v4 supersedes the Recovery v3 *loss-state assessment* with newly recovered raw bytes. Recovery v3 remains preserved as historical governance evidence.

## 5ed030 raw-byte recovery

Recovered target:

`GALIA_WORKING_v1_30_POSTPROMOTION.sqlite`

SHA-256:

`5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`

Size: `481763328` bytes.

Verification:

- two independent deterministic reproductions reached the exact target SHA;
- byte comparison: PASS;
- SQLite runtime: 3.46.1;
- recorded branch method: `sqlite3.Connection.backup`;
- `integrity_check = ok`;
- foreign-key violations: `0`;
- no destructive rollback was used;
- no normalized or patched hash substitutes the recovered bytes.

The byte-exact recovery package SHA-256 is:

`1f76d7198951ca47641e10ff653972102577dae966f9a25f633b6afc27abbdad`

## Final sealed vault

Library path:

`/GALIA_FINAL_VAULT_SEALED_2026-09-26`

Vault manifest SHA-256:

`53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf`

Vault receipt SHA-256:

`211e44cd3ae5951db8be9e75ee3bede17014ccc251db6faf83e96109189836bb`

Clean-room validation: **PASS**.

Sealed server-copy readback: **PASS**.

The historical v1.29 parent binary is also recovered and verified:

`3ed9a658665314d01f7448a0d6f040c07d8b0eab00986d8334589719f58037b6`

## Current gate state

All mandatory raw-byte preservation blockers are resolved.

`SAFE_DELETE = HOLD`

The remaining mandatory controls are now only:

1. an exact, hashed deletion manifest with explicit targets; and
2. deletion-specific human authorization bound to the exact deletion-manifest hash and final-vault manifest hash.

No deletion manifest has been created by Recovery v4.
No deletion authorization is inferred from any earlier promotion.
No deletion operation is added.
