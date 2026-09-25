# HF10 — Hugging Face Space parity gate

Status: **LINUX RUNTIME PARITY PASS / PRODUCTION SPACE NOT PROMOTED**

HF10 first established that promoted GALIA runtime semantics execute correctly on a Linux backend compatible with Hugging Face compute.

Validated runtime:

- Ubuntu 24.04 x86-64
- Python 3.13
- MLX 0.32.2 with Linux CPU backend (`mlx[cpu]`)
- exact checkpoint save/reload
- previous-generation fallback after current-generation corruption
- GALIA 2 regression suite
- authoritative loads without legacy-unbound taint
- no authority transfer

Therefore:

```text
HF10_LINUX_MLX_RUNTIME_PARITY = PASS
```

This PASS proves runtime/checkpoint parity only. It does not imply production UI/runtime promotion.

## Static diagnostic Space

Current recorded state:

```text
human_merge_reported          = true
independent_remote_postverify = HOLD
production_runtime_promoted   = false
```

The current connector still cannot independently post-verify the private static Space, so GALIA does not infer technical PASS from the human merge report alone.

## Dynamic Gradio Space

```text
HF10B_DYNAMIC_GRADIO_SPACE = HOLD_TIER_CONSTRAINT
```

The tested remote Gradio/Docker path required a paid tier. GALIA does not require a subscription upgrade.

## Authority boundary

```text
GitHub       = CONTROL PLANE
Hugging Face = ML ARTIFACT PLANE

source_of_truth                 = github
canonical_authority_transferred = false
legacy_mutation_authorized      = false
```

Any future production Space remains a separate human-governed promotion gate.
