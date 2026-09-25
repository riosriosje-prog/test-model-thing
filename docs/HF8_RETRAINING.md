# HF8 Retraining

Status: **PROMOTED WEIGHT / SOURCE INTEGRATION PENDING**

## Promoted weight

The promoted HF8 real-weight bootstrap is:

- Hugging Face repo: `Junitos/galia-2`
- promoted revision: `main`
- candidate path: `weights/hf8-retrain-v0.2-4k`
- training steps: 4,000
- payload SHA-256: `3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c`
- payload bytes: `70,716,981`
- manifest SHA-256: `a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2`
- classification: `GALIA_CURRENT_BOUND`
- quality gate: `PASS`
- canonical authority transferred: `false`

Quality result:

- random-init held-out BPC: `8.67977507595193`
- trained held-out BPC: `5.675106937451537`
- delta: `-3.004668138500393`

## Current executable retraining surface

The source integration keeps only the current/reusable HF8 execution surfaces:

- `.github/workflows/hf8-backend-throughput-probe-v2.yml`
- `.github/workflows/hf8-retrain-v0-2-diagnostic.yml`
- `.github/workflows/hf8-weight-intake-validation.yml`
- `tools/hf8_prepare_simplewiki_v2.py`
- `tools/hf8_retrain_v2_diagnostic.py`
- `tools/hf8_weight_intake.py`

Superseded one-shot promotion workflows, v0.1 training workflows, recovery workflows,
and staging publishers are intentionally not integrated into `main`.

## Preserved evidence

Historical evidence remains in receipts, including:

- `receipts/huggingface/hf8-real-weight-candidate-v0.1.json`
- `receipts/huggingface/hf8-real-weight-candidate-v0.2.json`
- `receipts/huggingface/hf8-v0-2-weight-promotion-receipt.json`
- `receipts/huggingface/hf8-discovery-audit-v0.2.json`
- `receipts/huggingface/hf8-weight-artifact-hold-v0.1.json`

The v0.1/20k experiments remain audit evidence only. They are not the promoted model.

## Authority boundary

```text
source_of_truth = github
canonical_authority_transferred = false
legacy_mutation_authorized = false
promoted_weight_scope = HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY
```

Promotion of the weight does not itself merge the retraining source branch.
GitHub PR #22 remains a separate source-integration decision.
