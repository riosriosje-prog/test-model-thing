# GALIA SAFE_DELETE Gate — Recovery v4 byte-exact recovery

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

## Recovered raw object

The previously missing upstream object has been recovered byte-exactly:

- raw SQLite SHA-256: `5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6`
- size: 481,763,328 bytes
- integrity_check: `ok`
- foreign_key_check: `0`
- SQLite writer/runtime used for reproduction: 3.46.1
- checkpoint: `CP-GALIA-WORKING-V1-30`
- checkpoint database_hash: `31727bf425f5dd52ed07570f5afbe679b21a84edb502139f70e8b58b2d2ebd04`

The exact parent v1.29 SQLite is also preserved:

`3ed9a658665314d01f7448a0d6f040c07d8b0eab00986d8334589719f58037b6`

The recorded v1.30 branch method is `sqlite3.Connection.backup`. Forward reproduction from the byte-exact v1.29 parent produced the exact target SHA independently. No destructive rollback, normalized-hash substitution, or manual SQLite-header patch was used.

## Vault preservation

Recovery package:

`/GALIA_FINAL_VAULT_STAGING_2026-09-26/5ED030_BYTE_EXACT_RECOVERY.zip`

Package SHA-256:

`1f76d7198951ca47641e10ff653972102577dae966f9a25f633b6afc27abbdad`

Server-side readback recovered the internal SQLite at the exact target SHA and passed SQLite integrity and foreign-key checks.

Historical v1.29 is also preserved in the staging vault. Its SQLite SHA-256 is `3ed9a658665314d01f7448a0d6f040c07d8b0eab00986d8334589719f58037b6`.

Staging vault manifest v3 SHA-256:

`f28ea1ca8b3b49ebca809cda00658cca29151c688568e346740b8f6d3aabe23f`

All mandatory raw-byte objects are now present. The staging vault is byte-complete but is **not yet the final sealed vault**.

## Policy

Recovery v4 restores the strict raw-byte SAFE_DELETE evaluator. The temporary irrecoverable-transient exception from Recovery v3 is not needed for this recovered object.

Current decision:

`SAFE_DELETE = HOLD`

Remaining blockers:
- final immutable vault seal;
- final clean-room restore from that vault alone;
- exact deletion manifest;
- deletion-specific human authorization bound to the final vault and manifest.

Recovery of the bytes does not authorize deletion.
