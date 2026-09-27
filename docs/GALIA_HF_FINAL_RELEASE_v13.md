# GALIA 1.0.1 — Hugging Face Final Release Gate

Status: **CANDIDATE / NOT PROMOTED TO HUGGING FACE**

This gate binds the final byte-verified GALIA 1.0.1 release to the private
Hugging Face distribution repository `Junitos/galia-2`.

## Exact binary identity

- File: `GALIA_CANONICAL_KERNEL_1_0_1_MASTER_PROMOTED.sqlite`
- Bytes: `488689664`
- SHA-256: `9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354`

## Authority boundary

Hugging Face remains **DISTRIBUTION_MIRROR_ONLY**.

`canonical_authority_transferred = false`

GitHub remains the control plane for engineering authority, tests, receipts and
promotion history.

## Publication behavior

`tools/publish_hf_final_release.py`:

1. requires `HF_TOKEN`;
2. requires authenticated Hugging Face identity `Junitos`;
3. verifies local SQLite SHA-256 and byte size before upload;
4. uploads the four release files under `release/1.0.1/`;
5. downloads the promoted remote snapshot again;
6. recomputes the binary SHA-256 and byte size;
7. emits a receipt only after the post-upload verification passes.

The workflow is manual-only. It has no push or schedule trigger.

## Current blocker

The exact release payload is byte-verified and prepared, but the current
assistant Hugging Face OAuth session exposes read-only repository scope.
The existing GitHub `HF_TOKEN` write channel can be used once the exact payload
is staged into the workflow runner.

No partial promotion is considered success.
