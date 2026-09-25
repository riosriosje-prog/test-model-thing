---
title: GALIA 2 Diagnostic
emoji: 🧭
colorFrom: gray
colorTo: blue
sdk: gradio
sdk_version: 6.26.0
python_version: "3.13"
app_file: app.py
pinned: false
license: mit
short_description: Read-only GALIA 2 gate and session diagnostics
---

# GALIA 2 Diagnostic Surface

Status: **CANDIDATE / READ-ONLY / NO AUTHORITY TRANSFER**

This private Space candidate exposes only diagnostic state. It intentionally contains:

- no trained weights;
- no model inference endpoint;
- no checkpoint write path;
- no historical evidence;
- no source images;
- no mutable canonical state;
- no Hugging Face write credentials in application code.

Each page-load session receives an ephemeral session hash from Gradio. The UI exposes only a truncated SHA-256 fingerprint of that value and does not persist it.

GitHub remains the canonical engineering/source authority.
