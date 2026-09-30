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
            promotion = evidence.get("promotion")
            if promotion:
                receipt_path = promotion.get("receipt_path")
                if promotion.get("state") != "PROMOTED" or not receipt_path:
                    fail(f"{project['id']} promotion metadata is incomplete")
                receipt = load(ROOT / receipt_path)
                if receipt.get("state") != "PROMOTED":
                    fail(f"{project['id']} promotion receipt is not PROMOTED")
                if receipt.get("promoted_object", {}).get("evidence_path") != path:
                    fail(f"{project['id']} promotion receipt evidence binding mismatch")
                scope = receipt.get("scope", {})
                if scope.get("global_master_mutation") is not False:
                    fail(f"{project['id']} promotion receipt crosses global-master authority")
                if scope.get("hypothesis_promoted_as_fact") is not False:
                    fail(f"{project['id']} promotion receipt elevates hypothesis to fact")
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
        status = claim.get("status", "")
        limits = "".join(f"<li>{esc(x)}</li>" for x in claim.get("limits", []))
        source = claim.get("source", {})
        src = esc(source.get("publication", ""))
        if source.get("page"):
            src += " · p. " + esc(source["page"])
        if source.get("surrogate_url"):
            src += f' · <a href="{esc(source["surrogate_url"])}" target="_blank" rel="noreferrer">primary surrogate</a>'
        rows.append(
            f'<tr class="claim-row" data-status="{esc(status)}">'
            f"<td>{esc(when)}</td>"
            f'<td><span class="status-pill">{esc(status)}</span></td>'
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
    promoted_dossiers = sum(
        1 for evidence in evidence_docs.values()
        if evidence.get("promotion", {}).get("state") == "PROMOTED"
    )
    open_research_gates = sum(
        len(evidence.get("open_gates", [])) for evidence in evidence_docs.values()
    )
    gate_pass = sum(1 for value in gates.values() if str(value).startswith("PASS"))
    gate_total = len(gates)
    gate_open = gate_total - gate_pass
    evidence_coverage = round((len(evidence_docs) / len(projects)) * 100) if projects else 0
    promotion_coverage = round((promoted_dossiers / len(projects)) * 100) if projects else 0
    claim_status_counts = {}
    for evidence in evidence_docs.values():
        for claim in evidence.get("claims", []):
            status = claim.get("status", "UNSPECIFIED")
            claim_status_counts[status] = claim_status_counts.get(status, 0) + 1
    fact_claims = claim_status_counts.get("FACT", 0)
    hypothesis_claims = claim_status_counts.get("STRONG_HYPOTHESIS", 0)
    total_claims = sum(claim_status_counts.values())

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
<details class="card dossier" open>
<summary><span>{esc(project['title'])}</span><span class="badge">{esc(evidence.get('promotion', {}).get('state', 'EVIDENCE'))}</span></summary>
<p>{esc(project.get('summary',''))}</p>
<p class="muted">Scope: {esc(evidence.get('scope',''))}</p>
<div class="table-scroll">
<table class="claims-table">
<thead><tr><th>Date</th><th>Status</th><th>Claim / limits</th><th>Source</th></tr></thead>
<tbody>{render_claims(evidence)}</tbody>
</table>
</div>
<h3>Open gates</h3>
<ul>{render_open_gates(evidence)}</ul>
<p class="muted">Research evidence is presentation-only and does not modify release authority.</p>
</details>
""")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GALIA Authority Dashboard</title>
<style>
:root{{--navy:#071a33;--paper:#ffffff;--ink:#000000;--rule:#d7dce5;--muted:#4d5666;--link:#003b7a;--soft:#eef1f5}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth}} html,body{{margin:0;min-height:100%;background:var(--navy)}}
body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);line-height:1.48}}
main{{max-width:1180px;margin:auto;padding:20px 14px 42px}}
.card,.hero,.progress-card{{background:var(--paper);color:var(--ink);border:1px solid var(--rule);border-radius:16px;padding:18px;margin:14px 0;overflow:auto;box-shadow:0 8px 24px rgba(0,0,0,.12)}}
.hero{{padding:22px;display:flex;justify-content:space-between;gap:18px;align-items:flex-end;flex-wrap:wrap}}
h1,h2,h3{{margin-top:0;color:var(--ink)}} h1{{font-size:clamp(1.8rem,5vw,2.6rem);margin-bottom:4px}}
code{{word-break:break-all;color:var(--ink);background:#f3f5f8;padding:2px 4px;border-radius:4px}}
table{{width:100%;border-collapse:collapse;color:var(--ink);background:var(--paper)}}
td,th{{padding:10px;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top;color:var(--ink)}}
th{{background:#f5f7fa;position:sticky;top:0}} .table-scroll{{overflow:auto;max-width:100%}}
.ok{{font-weight:800;color:var(--ink)}} .muted,small{{color:var(--muted)}} a{{color:var(--link);text-decoration-thickness:1.5px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:14px 0}}
.metric{{background:var(--paper);color:var(--ink);border:1px solid var(--rule);border-radius:14px;padding:14px;box-shadow:0 6px 18px rgba(0,0,0,.10)}}
.metric strong{{display:block;font-size:1.55rem;margin-top:4px;color:var(--ink)}}
.progress-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:14px 0}}
.progress-card{{margin:0;min-width:0}}
.progress-card .big{{font-size:1.8rem;font-weight:850;line-height:1}}
.progress-track{{height:11px;border-radius:999px;background:var(--soft);overflow:hidden;margin:12px 0 7px}}
.progress-fill{{height:100%;background:var(--navy);border-radius:inherit}}
.gate-ring{{width:108px;height:108px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--navy) 0 calc(var(--p)*1%),var(--soft) calc(var(--p)*1%) 100%);margin:8px auto}}
.gate-ring::after{{content:"";width:72px;height:72px;border-radius:50%;background:white;position:absolute}}
.gate-ring span{{position:relative;z-index:1;font-weight:850;font-size:1.15rem}}
.badge,.status-pill{{display:inline-block;padding:3px 8px;border:1px solid #9aa4b2;background:#f2f4f7;color:var(--ink);border-radius:999px;font-size:.76rem;font-weight:800;letter-spacing:.035em}}
.toolbar{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0}}
.filter-btn,.jump{{appearance:none;border:1px solid #a8b0bc;background:#fff;color:#000;border-radius:999px;padding:9px 13px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}}
.filter-btn[aria-pressed="true"]{{background:var(--navy);color:#fff;border-color:var(--navy)}}
summary{{display:flex;justify-content:space-between;align-items:center;gap:12px;cursor:pointer;font-size:1.15rem;font-weight:850;list-style:none}}
summary::-webkit-details-marker{{display:none}} summary::before{{content:"▸";margin-right:8px}} details[open] summary::before{{content:"▾"}}
summary span:first-of-type{{flex:1}}
ul{{line-height:1.55}}
.claim-row[hidden]{{display:none}}
.navline{{display:flex;gap:8px;flex-wrap:wrap}}
@media (max-width:760px){{main{{padding:10px 8px 30px}}.card,.hero,.progress-card{{padding:14px;border-radius:12px}}td,th{{padding:8px;font-size:.91rem}}.progress-grid{{grid-template-columns:1fr}}.hero{{align-items:flex-start}}.gate-ring{{margin-left:0}}}}
</style>
</head>
<body><main>
<section class="hero">
<div>
<h1>📚 GALIA</h1>
<p><strong>Read-Only Authority Dashboard</strong></p>
<p class="ok">READ ONLY · authority mutation disabled</p>
</div>
<nav class="navline" aria-label="Dashboard sections">
<a class="jump" href="#progress">Progress</a>
<a class="jump" href="#authority">Authority</a>
<a class="jump" href="#research">Research</a>
</nav>
</section>

<section class="metrics" aria-label="Summary metrics">
<div class="metric"><span class="muted">Registered dossiers</span><strong>{len(projects)}</strong></div>
<div class="metric"><span class="muted">Evidence ledgers</span><strong>{len(evidence_docs)}</strong></div>
<div class="metric"><span class="muted">Human-promoted dossiers</span><strong>{promoted_dossiers}</strong></div>
<div class="metric"><span class="muted">Open research gates</span><strong>{open_research_gates}</strong></div>
</section>

<section id="progress">
<div class="progress-grid">
<div class="progress-card">
<h2>Authority gates</h2>
<div class="gate-ring" style="--p:{round((gate_pass/gate_total)*100) if gate_total else 0}"><span>{gate_pass}/{gate_total}</span></div>
<p><strong>{gate_pass} PASS</strong> · {gate_open} OPEN/other</p>
<small>Distribution of currently tracked authority gate states.</small>
</div>
<div class="progress-card">
<h2>Research coverage</h2>
<div class="big">{evidence_coverage}%</div>
<div class="progress-track" aria-label="Research evidence coverage"><div class="progress-fill" style="width:{evidence_coverage}%"></div></div>
<p>{len(evidence_docs)} of {len(projects)} registered dossiers have embedded evidence.</p>
<small>{total_claims} claims · {fact_claims} FACT · {hypothesis_claims} STRONG_HYPOTHESIS</small>
</div>
<div class="progress-card">
<h2>Promotion coverage</h2>
<div class="big">{promotion_coverage}%</div>
<div class="progress-track" aria-label="Promotion coverage"><div class="progress-fill" style="width:{promotion_coverage}%"></div></div>
<p>{promoted_dossiers} of {len(projects)} research dossiers carry a human promotion receipt.</p>
<small>This is coverage, not a quality score.</small>
</div>
</div>
</section>

<section id="authority" class="card">
<h2>Global authority</h2>
<p>Release: <strong>{esc(authority['global_master_release'])}</strong> · v{esc(authority['semantic_version'])}</p>
<p>SQLite SHA-256: <code>{esc(authority['global_master_sqlite_sha256'])}</code></p>
<p>Authority hold: <strong>{esc(authority['authority_hold'])}</strong></p>
<h3>Gates</h3>
<div class="table-scroll"><table><tbody>{gate_rows}</tbody></table></div>
</section>

<section id="research" class="card">
<h2>Research registry</h2>
<div class="table-scroll"><table><thead><tr><th>Dossier</th><th>State</th><th>Summary</th></tr></thead><tbody>{project_rows}</tbody></table></div>
<div class="toolbar" role="group" aria-label="Filter evidence claims">
<strong>Claims:</strong>
<button class="filter-btn" type="button" data-filter="ALL" aria-pressed="true">All</button>
<button class="filter-btn" type="button" data-filter="FACT" aria-pressed="false">FACT</button>
<button class="filter-btn" type="button" data-filter="STRONG_HYPOTHESIS" aria-pressed="false">Hypotheses</button>
<button class="filter-btn" type="button" data-filter="OTHER" aria-pressed="false">Other</button>
<span id="filter-count" class="muted" aria-live="polite"></span>
</div>
</section>

<section aria-label="Research dossiers">
{''.join(evidence_sections)}
</section>

<section class="card">
<h2>Scope separation</h2>
<p>RC-GALIA-2026-09-13-004 → GLOBAL_MASTER</p>
<p>RC-GALIA-2026-09-15-003 → SANTURCE_RESEARCH_CANONICAL_STATE</p>
<small>Built from explicit control-plane pointers and bound machine-readable receipts. No latest-file inference.</small>
</section>

<script>
(() => {{
  const buttons = [...document.querySelectorAll('.filter-btn')];
  const rows = [...document.querySelectorAll('.claim-row')];
  const count = document.getElementById('filter-count');

  function applyFilter(filter) {{
    let visible = 0;
    rows.forEach(row => {{
      const status = row.dataset.status || '';
      const show = filter === 'ALL' ||
        status === filter ||
        (filter === 'OTHER' && status !== 'FACT' && status !== 'STRONG_HYPOTHESIS');
      row.hidden = !show;
      if (show) visible += 1;
    }});
    buttons.forEach(btn => btn.setAttribute('aria-pressed', String(btn.dataset.filter === filter)));
    count.textContent = visible + ' visible claim' + (visible === 1 ? '' : 's');
  }}

  buttons.forEach(btn => btn.addEventListener('click', () => applyFilter(btn.dataset.filter)));
  applyFilter('ALL');
}})();
</script>
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
