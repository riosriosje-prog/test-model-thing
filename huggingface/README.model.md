---
license: mit
library_name: mlx
tags:
- mlx
- galia
- tmt
- recurrent
- byte-level
- research
---

# GALIA 2.0 / TMT — Reference Implementation Mirror

This Hugging Face repository is a **distribution mirror** of the GALIA 2.0 / Test-Model-Thing reference implementation.

**Authoritative engineering source:** `{{SOURCE_REPO}}`  
**Mirrored source commit:** `{{SOURCE_SHA}}`

## Authority boundary

This mirror does **not** transfer canonical authority from the GitHub repository.

- GitHub remains the source of truth for promoted architecture, implementation baselines, CI, human promotion receipts, and rollback history.
- Hugging Face is the distribution surface for model-oriented artifacts and later model weights.
- Historical evidence promotion remains subject to GALIA authority gates.
- A Hub upload is not a GALIA promotion event.

## Current contents

The mirror includes the executable TMT/GALIA code needed for reproducibility:

- `main.py` and `benchmark.py`;
- GALIA 2.0 orchestration, authority, persistence, recovery, and runtime modules;
- HistoricalStore integration modules;
- Python packaging metadata and runtime requirements.

The source repository currently does **not** publish trained model weights as part of this mirror. Weight publication will be handled as a separately hashed artifact gate.

## Runtime

Python 3.12+.

TMT uses MLX. Typical local setup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py <path> train
```

Platform-specific MLX installation may be required.

## Reproducibility

Every export contains `HF_EXPORT_MANIFEST.json`, which binds the mirror to:

- the exact GitHub source commit;
- file sizes;
- SHA-256 for every exported file;
- the authority scope `DISTRIBUTION_MIRROR_ONLY`.

Do not treat a mutable Hub branch as evidence of canonical GALIA promotion. Use the source commit and manifest hashes.

## License

MIT. See `LICENSE.md`.
