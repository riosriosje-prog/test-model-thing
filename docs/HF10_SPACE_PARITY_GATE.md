# HF10 — Hugging Face Space parity gate

HF10 does not begin by creating a Space. It first proves that the promoted GALIA runtime semantics execute correctly on a Linux backend compatible with Hugging Face compute.

Current target probe:

- Ubuntu 24.04 x86-64
- Python 3.13
- MLX 0.32.2 with the Linux CPU backend (`mlx[cpu]`)
- exact checkpoint save/reload
- previous-generation fallback after current-generation corruption
- GALIA 2 regression suite
- no authority transfer
- no Space deployment authorization

A PASS at this phase establishes **Linux CPU runtime parity only**. It does not establish UI parity, concurrency behavior, persistence under Space restarts, secrets handling, remote checkpoint storage, GPU/CUDA parity, or production readiness.

HF10 remains non-promoted until those later surfaces are explicitly validated and a human promotion decision is recorded.
