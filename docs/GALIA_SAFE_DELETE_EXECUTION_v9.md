# GALIA SAFE_DELETE v9 — Controlled Execution Core

Status: **CANDIDATE / NO REAL DELETION EXECUTED**

v9 adds the first mutation-capable execution core, but it is tool-agnostic and
does not import or call Library APIs directly.

Execution requires all of the following:

1. v7 exact human authorization receipt passes;
2. v8 plan is `AUTHORIZED_EXECUTION_ELIGIBLE`;
3. plan has exactly 27 targets;
4. caller sets an explicit `commit=True` flag;
5. injected deletion adapter returns success for every exact `library_file_id`.

The generated Library operation shape is deliberately minimal:

```json
{"operation":"delete","target":{"kind":"file","library_file_id":"libfile_..."}}
```

No path-based delete is generated.

If any adapter result fails, v9 returns
`PARTIAL_OR_FAILED_EXECUTION` and records the exact successfully deleted IDs.
It never converts partial execution into success.

A post-delete receipt verifier separately requires:

- all 27 deleted IDs absent from post-inventory;
- sealed-vault control IDs unchanged;
- exact deleted count = 27.

## Current state

`SAFE_DELETE = HOLD`

`DELETE_AUTHORIZED = NO`

`REAL_DELETION_EXECUTED = NO`

The actual Files/Library connector must only be invoked after a separate explicit
human destructive authorization bound to the exact manifest and vault hashes.
