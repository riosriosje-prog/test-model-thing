# GALIA SAFE_DELETE Gate — Recovery v4 candidate

Status: **READY FOR HUMAN PROMOTION / SAFE_DELETE STILL HOLD**

Recovery v4 records a material recovery after promoted Recovery v3.

## 5ed030 raw-byte recovery

The previously missing upstream object was reproduced from preserved evidence using:

1. the preserved promoted parent `RC-GALIA-2026-09-13-002` / v1.29;
2. SQLite **3.46.1**, matching the historical writer version;
3. the recorded `sqlite3.Connection.backup` branch method;
4. the exact v1.30 rows preserved in the v1.31 descendant;
5. two natural SQLite commits, with no manual header patch in the final replay.

The resulting file is 481,763,328 bytes and hashes exactly to:

`5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`

It passes `integrity_check=ok` and `foreign_key_check=0`.

Because the bytes now match the historically recorded SHA-256 exactly, the current evidence state is `RAW_BYTES_VERIFIED`. The Recovery v3 irrecoverable-transient path remains available as a fail-closed fallback policy but is **not used** by the current snapshot.

## Final vault

Library path:

`/GALIA_FINAL_VAULT_2026-09-26`

Final vault manifest SHA-256:

`2e964136234ebeccb091998c959ada549af878ea8908414be24889402ad36664`

Clean-room report SHA-256:

`fac245174cb9724271afd99fded3a1de6b3d21a377d65f841b8c90550577485a`

Clean-room restore was performed using readback copies from the final vault only. All package hashes passed; all inspected SQLite members passed integrity and foreign-key checks; the 15 stored v1.30 chunks reassembled to the exact `5ed030...` SHA-256.

Historical v1.29 (`3ed9a658...`) is also preserved, so its prior advisory is closed.

## Effective gate state

`SAFE_DELETE = HOLD`

The byte-preservation and final-vault blockers are closed. The remaining mandatory blockers are intentionally separate:

- exact deletion manifest: **ABSENT**;
- deletion-specific human authorization bound to that manifest and the final-vault SHA: **ABSENT**.

Recovery v4 adds no delete operation and does not authorize deletion.
