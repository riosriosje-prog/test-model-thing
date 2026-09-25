# HF8 Retraining

Status: **WEIGHT PROMOTED / SOURCE INTEGRATION PROMOTED**

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
- authority binding: `CURRENT_BOUND`
- quality gate: `PASS`
- canonical authority transferred: `false`

Quality result:

- random-init held-out BPC: `8.67977507595193`
- trained held-out BPC: `5.675106937451537`
- delta: `-3.004668138500393`

## Source integration

The cleaned v0.2 retraining source was promoted through GitHub PR #22.

Promoted source head:
`c04b4bfdc15a7785e61881dc1c99b9b924539a42`

Merge commit/current GitHub `main`:
`051f56789de99a8db0d4aa044eaf120ea1d67805`

Integrated reusable execution surface:

- `.github/workflows/hf8-backend-throughput-probe-v2.yml`
- `.github/workflows/hf8-retrain-v0-2-diagnostic.yml`
- `tools/hf8_prepare_simplewiki_v2.py`
- `tools/hf8_retrain_v2_diagnostic.py`
- `tests/test_hf8_v02_governance.py`

Superseded v0.1 training/recovery/promotion workflows and obsolete staging publishers were deliberately excluded from the promoted source surface.

## Preserved evidence

- `receipts/huggingface/hf8-discovery-audit-v0.2.json`
- `receipts/huggingface/hf8-real-weight-candidate-v0.1.json`
- `receipts/huggingface/hf8-real-weight-candidate-v0.2.json`
- `receipts/huggingface/hf8-v0-2-weight-promotion-receipt.json`
- `receipts/huggingface/hf8-weight-artifact-hold-v0.1.json`

The old HOLD receipt is historical evidence of the gate before a real weight existed; it does not represent current HF8 status.

## Authority boundary

```text
GitHub       = CONTROL PLANE
Hugging Face = ML ARTIFACT PLANE

source_of_truth                 = github
canonical_authority_transferred = false
legacy_mutation_authorized      = false
promoted_weight_scope           = HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY
```

The weight promotion and source promotion were separate human decisions with separate receipts.

Any future longer training run creates a new artifact candidate and must pass independent quality, provenance, identity, remote-verification and human-promotion gates.

Machine-readable plane policy: `huggingface/policy/control-artifact-plane.v1.json`.
