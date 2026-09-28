#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POINTER = ROOT / "governance/galia_dashboard_authority_pointer.v1.json"
REGISTRY = ROOT / "governance/galia_dashboard_research_registry.v1.json"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(msg: str):
    raise SystemExit("GALIA_DASHBOARD_FAIL_CLOSED: " + msg)


def validate_authority(pointer: dict):
    if pointer.get("state") != "ACTIVE":
        fail("authority pointer is not ACTIVE")
    pub = pointer.get("publication", {})
    if pub.get("mode") != "READ_ONLY" or pub.get("authority_mutation") is not False:
        fail("publication boundary is not read-only")

    authority = pointer["authority"]
    if authority.get("authority_hold") != "LIFTED":
        fail("GLOBAL_MASTER authority hold is not lifted")

    gates = pointer["gates"]
    for gate in ("G20", "G22", "G27"):
        if not str(gates.get(gate, "")).startswith("PASS"):
            fail(f"{gate} is not PASS")
    if gates.get("G28") != "OPEN_UNPROVEN_FORENSIC_ONLY":
        fail("G28 state changed unexpectedly")

    sd = pointer["safe_delete_binding"]
    receipt = load(ROOT / sd["path"])
    if receipt.get("execution_receipt_id") != sd["execution_receipt_id"]:
        fail("safe-delete execution receipt id mismatch")
    if receipt.get("authorization_decision_id") != sd["authorization_decision_id"]:
        fail("safe-delete authorization decision mismatch")
    if receipt.get("target_count") != sd["target_count"]:
        fail("safe-delete target count mismatch")
    final = receipt.get("final_state", {})
    if final.get("safe_delete") != sd["required_final_state"]:
        fail("safe-delete final state mismatch")
    if final.get("sealed_vault_intact") is not True:
        fail("sealed vault not intact")
    if receipt.get("post_delete_verification", {}).get("status") != "PASS":
        fail("safe-delete post-verification is not PASS")

    rb = pointer["release_identity_binding"]
    release = load(ROOT / rb["path"])
    artifacts = release.get("artifacts", [])
    binary = next((x for x in artifacts if x.get("role") == "canonical_binary_snapshot"), None)
    if not binary:
        fail("canonical binary snapshot missing")
    if binary.get("sha256") != rb["required_binary_sha256"]:
        fail("release binary hash mismatch")
    if binary.get("sha256") != authority["global_master_sqlite_sha256"]:
        fail("authority/release binary identity mismatch")
    if release.get("source_control_plane", {}).get("canonical_authority_transferred") is not False:
        fail("distribution artifact claims authority transfer")


def validate_research(registry: dict) -> dict[str, dict]:
    projects = registry.get("projects")
    if not isinstance(projects, list):
        fail("research registry projects must be a list")
    ids = [p.get("id") for p in projects]
    if None in ids or len(ids) != len(set(ids)):
        fail("research registry project ids must be unique and non-empty")

    evidence_docs: dict[str, dict] = {}
    for project in projects:
        state = project.get("state")
        path = project.get("evidence_path")
        if state == "EVIDENCE_EMBEDDED":
            if not path:
                fail(f"{project['id']} claims embedded evidence without evidence_path")
            evidence = load(ROOT / path)
            if evidence.get("project_id") != project["id"]:
                fail(f"{project['id']} evidence project_id mismatch")
            if evidence.get("state") != "EVIDENCE_EMBEDDED":
                fail(f"{project['id']} evidence state mismatch")
            if evidence.get("authority_mutation") is not False:
                fail(f"{project['id']} evidence crosses authority boundary")
            claims = evidence.get("claims", [])
            if not claims:
                fail(f"{project['id']} embedded evidence has no claims")
            evidence_docs[project["id"]] = evidence
        elif path:
            fail(f"{project['id']} has evidence_path but is not EVIDENCE_EMBEDDED")
    return evidence_docs


def esc(value) -> str:
    return html.escape(str(value))


def render_claims(evidence: dict) -> str:
    rows = []
    for claim in evidence.get("claims", []):
        when = claim.get("date") or claim.get("date_range", "")
        limits = "".join(f"<li>{esc(x)}</li>" for x in claim.get("limits", []))
        source = claim.get("source", {})
        src = esc(source.get("publication", ""))
        if source.get("page"):
            src += " · p. " + esc(source["page"])
        if source.get("surrogate_url"):
            src += f' · <a href="{esc(source["surrogate_url"])}" target="_blank" rel="noreferrer">primary surrogate</a>'
        rows.append(
            "<tr>"
            f"<td>{esc(when)}</td>"
            f"<td><strong>{esc(claim['status'])}</strong></td>"
            f"<td>{esc(claim['claim'])}{('<ul>'+limits+'</ul>') if limits else ''}</td>"
            f"<td>{src}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_open_gates(evidence: dict) -> str:
    return "".join(
        f"<li><strong>{esc(g['id'])}</strong> — {esc(g['state'])}: {esc(g['target'])}</li>"
        for g in evidence.get("open_gates", [])
    )


def render(pointer: dict, registry: dict, evidence_docs: dict[str, dict]) -> str:
    authority = pointer["authority"]
    gates = pointer["gates"]
    projects = registry["projects"]

    gate_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in gates.items()
    )
    project_rows = "".join(
        f"<tr><td>{esc(p['title'])}</td><td>{esc(p['state'])}</td><td>{esc(p.get('summary',''))}</td></tr>"
        for p in projects
    )

    evidence_sections = []
    for project in projects:
        evidence = evidence_docs.get(project["id"])
        if not evidence:
            continue
        evidence_sections.append(f"""
<div class="card">
<h2>{esc(project['title'])} — evidence ledger</h2>
<p>{esc(project.get('summary',''))}</p>
<table>
<thead><tr><th>Date</th><th>Status</th><th>Claim / limits</th><th>Source</th></tr></thead>
<tbody>{render_claims(evidence)}</tbody>
</table>
<h3>Open gates</h3>
<ul>{render_open_gates(evidence)}</ul>
<p class="muted">Research evidence is presentation-only and does not modify release authority.</p>
</div>
""")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GALIA Authority Dashboard</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b1020;color:#eef2ff}}
main{{max-width:1120px;margin:auto;padding:28px}}
.card{{background:#151c31;border:1px solid #2a3555;border-radius:14px;padding:18px;margin:16px 0;overflow:auto}}
h1,h2{{margin-top:0}} code{{word-break:break-all}} table{{width:100%;border-collapse:collapse}}
td,th{{padding:9px;border-bottom:1px solid #2a3555;text-align:left;vertical-align:top}}
.ok{{font-weight:700}} .muted,small{{color:#aeb9d6}} a{{color:#8bd5ff}}
ul{{line-height:1.55}}
</style>
</head>
<body><main>
<h1>GALIA — Read-Only Authority Dashboard</h1>
<p class="ok">READ ONLY · authority mutation disabled</p>
<div class="card">
<h2>Global authority</h2>
<p>Release: <strong>{esc(authority['global_master_release'])}</strong> · v{esc(authority['semantic_version'])}</p>
<p>SQLite SHA-256: <code>{esc(authority['global_master_sqlite_sha256'])}</code></p>
<p>Authority hold: <strong>{esc(authority['authority_hold'])}</strong></p>
</div>
<div class="card"><h2>Gates</h2><table><tbody>{gate_rows}</tbody></table></div>
<div class="card">
<h2>Research registry</h2>
<table><thead><tr><th>Dossier</th><th>State</th><th>Summary</th></tr></thead><tbody>{project_rows}</tbody></table>
</div>
{''.join(evidence_sections)}
<div class="card">
<h2>Scope separation</h2>
<p>RC-GALIA-2026-09-13-004 → GLOBAL_MASTER</p>
<p>RC-GALIA-2026-09-15-003 → SANTURCE_RESEARCH_CANONICAL_STATE</p>
<small>Built from explicit control-plane pointers and bound machine-readable receipts. No latest-file inference.</small>
</div>
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="dist/index.html")
    args = ap.parse_args()

    pointer = load(POINTER)
    registry = load(REGISTRY)
    validate_authority(pointer)
    evidence_docs = validate_research(registry)

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    data = render(pointer, registry, evidence_docs)
    out.write_text(data, encoding="utf-8")
    print("GALIA_DASHBOARD_VALIDATION=PASS")
    print("GALIA_RESEARCH_EVIDENCE_DOCS=" + str(len(evidence_docs)))
    print("GALIA_DASHBOARD_SHA256=" + hashlib.sha256(data.encode()).hexdigest())


if __name__ == "__main__":
    main()
