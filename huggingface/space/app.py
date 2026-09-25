from __future__ import annotations

import gradio as gr

from diagnostics import diagnostic_payload


def inspect_session(request: gr.Request):
    return diagnostic_payload(getattr(request, "session_hash", None))


with gr.Blocks(title="GALIA 2 Diagnostic Surface") as demo:
    gr.Markdown(
        """
# GALIA 2 — Diagnostic Surface

**Read-only candidate.** No model inference, no checkpoint writes, no evidence mutation,
no authority transfer. GitHub remains canonical.
"""
    )
    status = gr.JSON(
        value=diagnostic_payload(None),
        label="GALIA gate status",
    )
    refresh = gr.Button("Inspect this session")
    refresh.click(fn=inspect_session, outputs=status)


if __name__ == "__main__":
    demo.launch()
