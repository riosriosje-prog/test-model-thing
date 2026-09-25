---
title: GALIA 2 Diagnostic
emoji: 🧭
colorFrom: gray
colorTo: blue
sdk: static
app_file: index.html
pinned: false
license: mit
short_description: Read-only GALIA 2 gate diagnostics
---

# GALIA 2 Diagnostic Surface

Status: **STATIC CANDIDATE / READ-ONLY / NO AUTHORITY TRANSFER**

This private Space is intentionally static. It does not execute GALIA, load model
weights, write checkpoints, mutate evidence, access secrets, or transfer authority.

The dynamic Gradio candidate remains a separate gate because the authenticated
Hugging Face account currently cannot create Gradio/Docker cpu-basic Spaces without
a PRO subscription. GALIA does not require that subscription for this diagnostic
surface.
