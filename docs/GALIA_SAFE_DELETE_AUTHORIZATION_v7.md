# GALIA SAFE_DELETE v7 — Authorization Packet

Status: **CANDIDATE / NO DELETE AUTHORIZATION PRESENT**

This layer formalizes the only remaining blocker. It does not delete anything.

## Required exact bindings

Deletion manifest SHA-256:

`6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708`

Final vault manifest SHA-256:

`53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf`

Target count: `27`

Authorized scope:

`EXACT_27_TARGETS_IN_PROMOTED_DELETION_MANIFEST_ONLY`

## Human decision contract

A destructive authorization is valid only if the human decision is explicitly
bound to all four values above and the receipt contains:

- a non-empty decision ID;
- explicit decision text;
- state `EXPLICIT_HUMAN_APPROVAL_BOUND`;
- `delete_authorized = true`;
- `destructive_action_executed = false` at authorization time.

A generic promotion signal, any prior promotion, an ambiguous instruction, or a
hash mismatch fails closed.

## Current state

`SAFE_DELETE = HOLD`

`DELETE_AUTHORIZED = NO`

This candidate includes no file-removal primitive and no Library deletion action.
