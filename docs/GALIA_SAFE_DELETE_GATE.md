# GALIA SAFE_DELETE Gate v1

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

This replaces the old narrative SAFE_DELETE checklist with a deterministic,
target-scoped, fail-closed evaluator.

## Core rule

`SAFE_DELETE` is never global and never implicit.

A deletion certificate must bind:

1. an exact non-empty deletion manifest;
2. SHA-256 for every deletion target;
3. an immutable final vault and exact vault SHA-256;
4. proof that every deletion target exists byte-exactly inside the vault;
5. a clean-room restore PASS using only that vault;
6. an explicit human decision bound to both the deletion-manifest SHA-256 and
   final-vault SHA-256.

The evaluator contains **no deletion operation**. It can only report eligibility.

## Current blocking objects

Already byte-verified:
- GLOBAL_MASTER 1.0.1: `9e98bf9c...`
- Santurce research 15-003: `22865209...`
- v1.30 / 14-003 object: `85e61680...`
- cleanup object: `948d41f2...`

Still blocking:
- cleanup upstream `5ed03098...`: raw bytes not recovered;
- OW02 `455f67ab...`: report/hash exists, raw checkpoint bytes not located;
- OW10: report exists and old criteria reference package hash prefix `bbd1188...`,
  but raw package/checkpoint bytes are not located;
- OW21: discovery audit not complete;
- final immutable vault: not built;
- clean-room restore: not run;
- deletion manifest: absent;
- deletion-specific human authorization: absent.

## Non-blocking forensic matters

These remain important evidence, but they do not independently prevent
SAFE_DELETE once preservation is complete:

- G28 direct 14-003 → 15-003 lineage;
- exact SQLite 3.46.1 same-writer replay.

The historical v1.29 binary `3ed9a658...` is a **SHOULD**, matching the original
wording "preferably capture"; its absence generates an advisory, not a blocker.

## Separation from authority

`SAFE_DELETE` does not alter canonical authority, trust-root selection, G20/G22/G27,
G28, Legacy, Hugging Face, or Supabase authority. A SAFE_TO_DELETE certificate is
a separate human-governed object.
