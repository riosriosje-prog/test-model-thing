# GALIA SAFE_DELETE v10 — Personal Library Batch Protocol

Status: **CANDIDATE / NO REAL DELETE EXECUTED**

v10 corrects a connector constraint in promoted v9.

The real personal Library mutation API accepts at most **20 operations per call**.
The promoted deletion manifest contains **27 exact targets**, therefore the only
approved execution shape is:

- BATCH-01: 20 targets
- BATCH-02: 7 targets

## Required behavior

Before **each** batch:

1. fresh live inventory revalidation;
2. exact target identity check;
3. sealed-vault survival/readback check;
4. exact human authorization remains valid.

BATCH-02 cannot begin unless BATCH-01 reports full success.

Any failed or mismatched item causes fail-stop. Because deletion is destructive,
v10 does not attempt a fake rollback. It records exactly which IDs were already
deleted and leaves all later batches untouched.

All generated delete operations use only:

```json
{"operation":"delete","target":{"kind":"file","library_file_id":"libfile_..."}}
```

Folder deletion, path-only deletion, recursive deletion, and scope expansion are
forbidden.

## Current governance state

`SAFE_DELETE = HOLD`

`DELETE_AUTHORIZED = NO`

`REAL_LIBRARY_DELETE = NOT EXECUTED`
