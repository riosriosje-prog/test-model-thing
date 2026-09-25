# GALIA 2.0 — Hugging Face migration status

Status: **ACTIVE MIGRATION / GITHUB CANONICAL / NO AUTHORITY TRANSFER / NO LEGACY MUTATION**

Authoritative engineering source:
`riosriosje-prog/test-model-thing`

Authoritative GitHub `main` remains:
`a09c3e953ec1799b1704783c4c3d14a1a0017f62`

Migration branch:
`galia2/huggingface-migration-v0.1`

## Authority boundary

Hugging Face is a distribution / inspection surface only.

```text
source_of_truth                    = github
canonical_authority_transferred    = false
legacy_mutation_authorized         = false
```

No Hugging Face promotion in this migration changes GALIA Legacy or advances GitHub `main`.

## Current topology

```text
GitHub
  canonical engineering source / CI / receipts / rollback
        |
        +--> Junitos/galia-2
        |      private model/code distribution mirror
        |
        +--> Junitos/galia-2-evidence
        |      private schema-only evidence dataset surface
        |
        +--> Junitos/galia-2-diagnostic
               private static diagnostic Space surface
```

## Migration gates

```text
HF1_EXPORT_DETERMINISM            = PASS
HF2_SOURCE_SHA_BINDING            = PASS
HF3_PER_FILE_SHA256               = PASS
HF4_TOKEN_FAIL_CLOSED             = PASS

HF5_HUB_MODEL_REPO_CREATE         = PASS
HF6_HUB_MODEL_UPLOAD_AS_PR        = PASS
HF7_MODEL_REMOTE_MANIFEST_COMPARE = PASS
HF_MODEL_DISTRIBUTION_PROMOTION   = PASS

HF8_WEIGHT_ARTIFACT_GATE          = HOLD
  reason: no real versioned/promoted trained weight artifact exists

HF9_DATASET_SCHEMA_SURFACE        = PROMOTED
  evidence_record_count           = 0
  source_images                   = 0
  raw_source_bytes                = 0

HF10_LINUX_MLX_RUNTIME_PARITY     = PASS
  platform                        = Linux x86_64
  python                          = 3.13.15
  mlx                             = 0.32.2
  save_reload_exact               = true
  fallback_recovery_exact         = true

HF10B_STATIC_DIAGNOSTIC_SPACE     = HUMAN_REPORTED_MERGED
  independent_connector postverify = HOLD

HF10B_DYNAMIC_GRADIO_SPACE        = HOLD_TIER_CONSTRAINT
  remote reason                   = Gradio/Docker cpu-basic requires PRO on this account
```

## Model distribution mirror

Repository:
`Junitos/galia-2`

Promoted distribution source SHA:
`439500216fb7a27883bb007cbfa0c3cf2f07779e`

Promoted manifest SHA-256:
`6542c843b8bb7e27d38cea2cf6dd71708fe1cc443f21a23f3390ac1fc66ed932`

Verified files: **39**

Scope:
`DISTRIBUTION_MIRROR_ONLY`

The mirror was uploaded as a Hugging Face pull request, byte/hash verified, human-promoted, merged, and post-verified.

## Weight gate

HF8 remains **HOLD**.

Repository-tree inspection found no real versioned model weight/checkpoint artifact matching common formats such as:

- `.safetensors`
- `.ckpt`
- `.pt`
- `.pth`
- `.bin`
- `.npz`

GALIA will not create placeholder or synthetic weights to satisfy the gate.

HF8 exits HOLD only after a real trained artifact is available and bound to:

1. exact byte size;
2. SHA-256;
3. model/config/runtime provenance;
4. optimizer/recurrent state when required;
5. remote upload identity;
6. remote re-read/download hash verification;
7. a separate human promotion decision.

## Evidence dataset surface

Repository:
`Junitos/galia-2-evidence`

Promoted source SHA:
`4a6b5862ae7b86f9db0d469e1a52b5a751de9a58`

Promoted manifest SHA-256:
`1a2545f83a3e6fc0c7f59fad11d7237c67781216123fd985fd56088cdfdc001e`

Verified files: **5**

Scope:
`DATASET_SCHEMA_SURFACE_ONLY`

Current evidence payload:

```text
historical evidence records = 0
source images               = 0
raw source bytes            = 0
```

The dataset surface enforces the following governance boundaries:

- `DOCUMENT_DATE` remains distinct from `EVENT_DATE`;
- `PROMPT_VERSION` remains distinct from `ENGINE_VERSION`;
- authentication/admissibility remain distinct from evidentiary weight;
- image evidence requires provenance fields and gate status;
- discrepancies remain explicit and cannot be silently normalized away;
- human review remains explicit.

Actual historical evidence migration is a separate future gate.

## Linux MLX runtime parity

HF10 established that the GALIA runtime can execute on Linux CPU using:

```text
Ubuntu 24.04 x86_64
Python 3.13.15
mlx[cpu] 0.32.2
```

Validated:

- GALIA 2 regression suite;
- exact checkpoint save/reload;
- exact previous-generation fallback after corruption of the current generation;
- authoritative loads without legacy-unbound taint.

This proves Linux CPU runtime/checkpoint parity only. It does not itself authorize a production Space.

## Diagnostic Space

Candidate repository:
`Junitos/galia-2-diagnostic`

Static candidate source SHA:
`bb466a5cc6b41eeabd2ce9b8ade7ed563167a4af`

Static candidate manifest SHA-256:
`ec24987a453b75ecfc0f76849a4c191266294d24958125609cbf15f33713a705`

Verified candidate files: **2**

Scope:
`SPACE_STATIC_DIAGNOSTIC_CANDIDATE_ONLY`

The static surface contains no:

- model inference;
- trained weights;
- checkpoint writes;
- evidence mutation;
- source images;
- persistent session state;
- canonical authority transfer.

The human operator reported completing the Hugging Face merge for Space PR #1. Independent post-verification remains **HOLD** because the current Hugging Face connector can authenticate as `Junitos` with `read-repos`, but its Space lookup still returns `Not found or authentication required` for this private Space.

Therefore GALIA records this state as:

```text
human_merge_reported        = true
independent_remote_postverify = HOLD
production_runtime_promoted = false
```

No technical PASS is inferred from the human report alone.

## Dynamic Gradio Space

The Gradio 6.26.0 diagnostic surface passed local tests for:

- import/runtime;
- read-only boundary;
- session fingerprint isolation;
- no environment-secret access;
- no filesystem write surface.

Remote creation failed with HTTP **402 Payment Required**. Hugging Face reported that Gradio/Docker Spaces on free `cpu-basic` require a PRO subscription for this account.

GALIA does **not** require a subscription upgrade to continue the migration.

Dynamic Gradio remains:

`HOLD_TIER_CONSTRAINT`

The verified static Space is the no-cost diagnostic surface.

## Authentication path actually used

The successful remote publications in this migration used the GitHub Actions repository secret:

`HF_TOKEN`

The token value is never written into exports or receipts.

This supersedes the earlier planning text that described Trusted Publisher/OIDC as the active publication path. Trusted Publisher remains an optional future hardening path, not the path used for the successful model/dataset publications recorded here.

## Durable receipts

Relevant durable receipts on the migration branch include:

- `receipts/huggingface/hf-promotion-receipt-v0.1.json`
- `receipts/huggingface/hf8-weight-artifact-hold-v0.1.json`
- `receipts/huggingface/hf9-dataset-candidate-receipt-v0.1.json`
- `receipts/huggingface/hf9-dataset-promotion-receipt-v0.1.json`
- `receipts/huggingface/hf10-linux-runtime-parity-receipt-v0.1.json`
- `receipts/huggingface/hf10-space-deployment-hold-v0.1.json`
- `receipts/huggingface/hf10b-static-space-candidate-receipt-v0.1.json`
- `receipts/huggingface/hf10b-gradio-tier-hold-v0.1.json`

## Next gates

The next independent gates are:

1. **HF10B_REMOTE_POSTVERIFY** — independently read the merged private Static Space and re-check the exact manifest/hash.
2. **HF8_WEIGHT_ARTIFACT_GATE** — remains blocked until a real trained weight artifact exists.
3. **HF10_DYNAMIC_RUNTIME_GATE** — remains optional/HOLD unless a paid or otherwise suitable runtime surface is deliberately selected.
4. **SOURCE PR #18 review** — migration-branch integration into GitHub `main` remains a separate human-governed source promotion and is not implied by any Hugging Face promotion.
