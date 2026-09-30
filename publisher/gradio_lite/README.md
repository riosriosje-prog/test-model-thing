---
title: GALIA
emoji: 📚
colorFrom: blue
colorTo: indigo
sdk: static
app_file: index.html
fullWidth: true
header: mini
pinned: false
short_description: Read-only GALIA research and authority dashboard
---

# GALIA — Gradio Lite Dashboard

Static, browser-executed GALIA dashboard.

- Runtime: Gradio Lite upstream patched `PINNED_HF_HUB` build + Pyodide.\n- Recovery: avoids the broken npm 5.45.0 `huggingface-hub` dependency path, applies the browser Starlette `query_string` compatibility shim, and redirects the upstream WASM worker to a local filelock-compatible worker where `os.link` accepts modern keyword arguments and fails safely as unsupported.
- Publication boundary: READ ONLY.
- Canonical authority remains in the GALIA control plane.
- This candidate performs no remote writes and cannot promote itself.
