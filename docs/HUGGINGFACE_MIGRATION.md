# GALIA 2.0 — Hugging Face integration status

Status: **ACTIVE / GITHUB CONTROL PLANE / HUGGING FACE ML ARTIFACT PLANE / NO AUTHORITY TRANSFER**

Authoritative engineering repository: `riosriosje-prog/test-model-thing`

Canonical control-plane ref: `main`

## Authority model

```text
GitHub       = CONTROL PLANE
Hugging Face = ML ARTIFACT PLANE

source_of_truth                 = github
canonical_authority_transferred = false
legacy_mutation_authorized      = false
```

Core invariant: `CODE_AUTHORITY != MODEL_ARTIFACT_AUTHORITY`.

A Hugging Face artifact promotion does not imply a GitHub source merge. A GitHub source merge does not imply a Hugging Face artifact promotion.

## Completed source integrations

- PR #18 — Hugging Face migration/tooling — PROMOTED
- PR #19 — HF8 weight-intake infrastructure — PROMOTED
- PR #22 — cleaned HF8 v0.2 retraining source — PROMOTED

PR #22 source-integration merge commit: `051f56789de99a8db0d4aa044eaf120ea1d67805`

## Model distribution

`Junitos/galia-2` remains the promoted model/code distribution repository.

Base distribution mirror:
- source SHA: `439500216fb7a27883bb007cbfa0c3cf2f07779e`
- manifest SHA-256: `6542c843b8bb7e27d38cea2cf6dd71708fe1cc443f21a23f3390ac1fc66ed932`
- verified files: 39
- scope: `DISTRIBUTION_MIRROR_ONLY`

## HF8 real trained weight

HF8 is no longer blocked on absence of a real trained artifact.

Promoted bootstrap:

```text
repo_id           = Junitos/galia-2
revision          = main
candidate_path    = weights/hf8-retrain-v0.2-4k
training_steps    = 4000
payload_sha256    = 3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c
payload_bytes     = 70716981
manifest_sha256   = a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2
classification    = GALIA_CURRENT_BOUND
authority_binding = CURRENT_BOUND
quality_gate      = PASS
promotion_scope   = HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY
```

Quality:
- random-init held-out BPC: `8.67977507595193`
- trained held-out BPC: `5.675106937451537`
- delta: `-3.004668138500393`

Promotion workflow run: `36188913806`

Durable receipt: `receipts/huggingface/hf8-v0-2-weight-promotion-receipt.json`

The older v0.1/20k experiment remains preserved as audit evidence and is not the promoted model.

## HF9 evidence dataset

`Junitos/galia-2-evidence` remains **PROMOTED — SCHEMA SURFACE ONLY**.

- source SHA: `4a6b5862ae7b86f9db0d469e1a52b5a751de9a58`
- manifest SHA-256: `1a2545f83a3e6fc0c7f59fad11d7237c67781216123fd985fd56088cdfdc001e`
- verified files: 5
- evidence records: 0
- source images: 0
- raw evidence bytes: 0

Actual historical evidence migration remains a separate gate.

## Runtime parity and backend diagnostics

HF10 Linux runtime parity remains PASS on Ubuntu 24.04 x86_64 / Python 3.13.15 / `mlx[cpu] 0.32.2`.

HF8 throughput probe:
- Linux x86_64: `16.34565835 steps/s`
- macOS arm64: `19.22950910 steps/s`

This benchmark is diagnostic only.

## Diagnostic Space

Static Space remains:

```text
human_merge_reported          = true
independent_remote_postverify = HOLD
production_runtime_promoted   = false
```

Dynamic Gradio remains `HOLD_TIER_CONSTRAINT`.

## Authentication

Successful Hugging Face publications use GitHub Actions secret `HF_TOKEN`. The token value is never written into exports or receipts.

## Remaining independent gates

1. `HF10B_REMOTE_POSTVERIFY` for the private static Space.
2. Actual historical evidence migration beyond the promoted HF9 schema.
3. Any longer HF8 training run: new quality, identity, remote-verification and human-promotion gates.
4. Any production dynamic runtime: separate optional gate.

Machine-readable control/artifact-plane policy: `huggingface/policy/control-artifact-plane.v1.json`.
