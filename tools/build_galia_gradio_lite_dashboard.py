#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import build_galia_dashboard as base

PINNED_GRADIO_LITE = "PINNED_HF_HUB"
PINNED_GRADIO_LITE_BASE = "runtime"

APP_PY = r"""
import json
from pathlib import Path

# Compatibility shim used by the current upstream Gradio Lite pinned runtime:
# Starlette may receive query_string as str inside Pyodide and expects bytes.
import starlette.datastructures as _sd
_original_url_init = _sd.URL.__init__

def _galia_starlette_url_init(self, url="", scope=None, **kwargs):
    if scope is not None:
        scope = dict(scope)
        qs = scope.get("query_string")
        if isinstance(qs, str):
            scope["query_string"] = qs.encode("latin-1")
    return _original_url_init(self, url=url, scope=scope, **kwargs)

_sd.URL.__init__ = _galia_starlette_url_init

import gradio as gr

GALIA_CSS = """
html, body, .gradio-container {
    background: #071a33 !important;
}
.gradio-container {
    color: #000000 !important;
}
.gradio-container .block,
.gradio-container .panel,
.gradio-container .form,
.gradio-container .prose,
.gradio-container .table-wrap,
.gradio-container [role="tabpanel"],
.gradio-container .wrap,
.gradio-container .dropdown {
    background: #ffffff !important;
    color: #000000 !important;
}
.gradio-container .prose,
.gradio-container .prose *,
.gradio-container label,
.gradio-container span,
.gradio-container p,
.gradio-container h1,
.gradio-container h2,
.gradio-container h3,
.gradio-container h4,
.gradio-container th,
.gradio-container td,
.gradio-container input,
.gradio-container textarea,
.gradio-container select,
.gradio-container button {
    color: #000000 !important;
}
.gradio-container input,
.gradio-container textarea,
.gradio-container select,
.gradio-container .dropdown,
.gradio-container .table-wrap {
    background: #ffffff !important;
}
.gradio-container button,
.gradio-container [role="tab"] {
    background: #f2f4f7 !important;
    color: #000000 !important;
}
.gradio-container button.selected,
.gradio-container [role="tab"][aria-selected="true"] {
    background: #ffffff !important;
    color: #000000 !important;
    font-weight: 700 !important;
}
"""

def load_json(name):
    return json.loads(Path(name).read_text(encoding="utf-8"))

authority_doc = load_json("authority.json")
registry = load_json("research_registry.json")
authority = authority_doc["authority"]
gates = authority_doc["gates"]
projects = registry.get("projects", [])

evidence_docs = {}
for p in Path(".").glob("evidence_*.json"):
    evidence_docs[p.stem.replace("evidence_", "")] = json.loads(
        p.read_text(encoding="utf-8")
    )

project_by_title = {p["title"]: p for p in projects}

def rows_for_project(title):
    project = project_by_title[title]
    evidence = evidence_docs.get(project["id"])
    summary = "### " + title + "\n\n**State:** " + project["state"] + "\n\n" + project.get("summary", "")
    if not evidence:
        return summary, [], []

    claims = []
    for c in evidence.get("claims", []):
        when = c.get("date") or c.get("date_range", "")
        source = c.get("source", {})
        source_label = source.get("publication", "")
        if source.get("page"):
            source_label += " · p. " + str(source["page"])
        if source.get("surrogate_url"):
            source_label += " · " + source["surrogate_url"]
        claims.append([
            when,
            c.get("status", ""),
            c.get("claim", ""),
            " | ".join(c.get("limits", [])),
            source_label,
        ])

    open_rows = [
        [
            g.get("id", ""),
            g.get("state", ""),
            g.get("target", ""),
            g.get("window", ""),
        ]
        for g in evidence.get("open_gates", [])
    ]
    return summary, claims, open_rows

default_title = projects[0]["title"] if projects else None
if default_title:
    initial_summary, initial_claims, initial_open = rows_for_project(default_title)
else:
    initial_summary, initial_claims, initial_open = ("No projects.", [], [])

gate_rows = [[k, v] for k, v in gates.items()]
registry_rows = [
    [p.get("title", ""), p.get("state", ""), p.get("summary", "")]
    for p in projects
]

with gr.Blocks(title="GALIA — Read-Only Dashboard", css=GALIA_CSS) as demo:
    gr.Markdown(
        "# 📚 GALIA\n"
        "**READ ONLY · authority mutation disabled · browser-executed Gradio Lite**"
    )

    with gr.Tab("Authority"):
        gr.Markdown(
            "**Global master:** "
            + authority["global_master_release"]
            + " · v"
            + authority["semantic_version"]
            + "\n\n**Authority hold:** "
            + authority["authority_hold"]
            + "\n\n**SQLite SHA-256:** "
            + authority["global_master_sqlite_sha256"]
        )
        gr.Dataframe(
            headers=["Gate", "State"],
            value=gate_rows,
            interactive=False,
            label="Authority gates",
        )

    with gr.Tab("Research"):
        gr.Dataframe(
            headers=["Dossier", "State", "Summary"],
            value=registry_rows,
            interactive=False,
            label="Research registry",
        )
        dossier = gr.Dropdown(
            choices=[p["title"] for p in projects],
            value=default_title,
            label="Dossier",
        )
        dossier_summary = gr.Markdown(initial_summary)
        claims_table = gr.Dataframe(
            headers=["Date", "Status", "Claim", "Limits", "Source"],
            value=initial_claims,
            interactive=False,
            label="Evidence ledger",
        )
        open_table = gr.Dataframe(
            headers=["Gate", "State", "Target", "Window"],
            value=initial_open,
            interactive=False,
            label="Open gates",
        )
        dossier.change(
            fn=rows_for_project,
            inputs=dossier,
            outputs=[dossier_summary, claims_table, open_table],
        )

    with gr.Tab("Scope"):
        gr.Markdown(
            "### Scope separation\n"
            "- RC-GALIA-2026-09-13-004 → GLOBAL_MASTER\n"
            "- RC-GALIA-2026-09-15-003 → SANTURCE_RESEARCH_CANONICAL_STATE\n\n"
            "Research evidence is presentation-only and cannot mutate release authority."
        )

demo.launch()
"""

def sanitize_authority(pointer):
    return {
        "schema_version": "galia.gradio_lite.authority_public.v1",
        "publication_mode": "READ_ONLY",
        "authority_mutation": False,
        "authority": pointer["authority"],
        "gates": pointer["gates"],
        "scope_bindings": pointer.get("scope_bindings", {}),
    }

def sanitize_evidence(evidence):
    allowed = (
        "schema_version",
        "project_id",
        "title",
        "state",
        "scope",
        "authority_mutation",
        "claims",
        "open_gates",
        "archival_routes",
    )
    return {k: evidence[k] for k in allowed if k in evidence}

def file_tag(name, content, entrypoint=False):
    marker = " entrypoint" if entrypoint else ""
    return (
        '<gradio-file name="'
        + html.escape(name, quote=True)
        + '"'
        + marker
        + ">\n"
        + html.escape(content)
        + "\n</gradio-file>"
    )

def render(pointer, registry, evidence_docs):
    authority_json = json.dumps(
        sanitize_authority(pointer),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    registry_json = json.dumps(
        registry,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"

    virtual_files = [
        file_tag("app.py", APP_PY, entrypoint=True),
        file_tag("authority.json", authority_json),
        file_tag("research_registry.json", registry_json),
    ]

    for project_id in sorted(evidence_docs):
        payload = json.dumps(
            sanitize_evidence(evidence_docs[project_id]),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        virtual_files.append(
            file_tag("evidence_" + project_id + ".json", payload)
        )

    files = "\n".join(virtual_files)
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GALIA — Gradio Lite</title>
<meta name="description" content="Read-only GALIA authority and research dashboard">
<script type="module" crossorigin src="RUNTIME_BASE/lite.js"></script>
<link rel="stylesheet" href="RUNTIME_BASE/lite.css">
<style>html,body{margin:0;padding:0;min-height:100%;background:#071a33}</style>
</head>
<body>
<gradio-lite theme="light">
FILES
</gradio-lite>
</body>
</html>
""".replace("RUNTIME_BASE", PINNED_GRADIO_LITE_BASE).replace("FILES", files)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="dist/gradio-lite/index.html")
    args = ap.parse_args()

    pointer = base.load(base.POINTER)
    registry = base.load(base.REGISTRY)
    base.validate_authority(pointer)
    evidence_docs = base.validate_research(registry)

    data = render(pointer, registry, evidence_docs)
    out = Path(args.output)
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(data, encoding="utf-8")

    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    print("GALIA_GRADIO_LITE_VALIDATION=PASS")
    print("GALIA_GRADIO_LITE_RUNTIME=" + PINNED_GRADIO_LITE)
    print("GALIA_GRADIO_LITE_RUNTIME_BASE=" + PINNED_GRADIO_LITE_BASE)
    print("GALIA_GRADIO_LITE_EVIDENCE_DOCS=" + str(len(evidence_docs)))
    print("GALIA_GRADIO_LITE_SHA256=" + digest)

if __name__ == "__main__":
    main()
