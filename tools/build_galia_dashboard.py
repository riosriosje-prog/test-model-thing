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
GEO = ROOT / "research/geospatial/santurce_georef_presentation.v1.json"


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


def validate_geo(geo: dict):
    if geo.get("state") != "READ_ONLY_PRESENTATION":
        fail("geospatial presentation snapshot is not read-only")
    if geo.get("authority_mutation") is not False:
        fail("geospatial presentation snapshot crosses authority boundary")
    source = geo.get("source", {})
    if source.get("repository") != "riosriosje-prog/galia-mlx-validation":
        fail("unexpected geospatial authority repository")
    if source.get("commit_sha") != "1f8d25d66188476d8bf376b644a1a222100828f7":
        fail("geospatial source commit binding changed")
    if source.get("south_base_gate_commit_sha") != "1f71e2c2fa66867953cbc53be8c2ba6e7d50a9cb":
        fail("South Base geodetic gate binding changed")
    controls = geo.get("geodetic_controls", [])
    if {x.get("id") for x in controls} != {"ngs-tv1051-san-juan-south-base", "ngs-tv1029-morro-lighthouse"}:
        fail("South Base/Morro geodetic control set changed")
    south = next(x for x in controls if x.get("id") == "ngs-tv1051-san-juan-south-base")
    if south.get("status") != "PASS_VERIFIED_NGS_PID" or south.get("datum") != "NAD83(1997)":
        fail("South Base control authority/datum changed")
    sheets = geo.get("sheets", [])
    if len(sheets) != 3:
        fail("expected three Santurce georeference sheets")
    promoted = [s for s in sheets if s.get("authority") == "PROMOTED_DERIVATION_BASELINE"]
    diagnostic = [s for s in sheets if "DIAGNOSTIC" in str(s.get("authority", ""))]
    if len(promoted) != 2 or len(diagnostic) != 1:
        fail("geospatial authority state separation changed")
    for sheet in sheets:
        if len(sheet.get("polygon", [])) != 4:
            fail(f"{sheet.get('id')} sheet footprint must have four corners")


def esc(value) -> str:
    return html.escape(str(value))


def progress_class(percent: int) -> str:
    if percent >= 70:
        return "progress-high"
    if percent >= 40:
        return "progress-mid"
    return "progress-low"


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


def render_claim_status_chart(fact: int, hypothesis: int, other: int) -> str:
    items = [
        ("FACT", fact, "chart-fact"),
        ("STRONG HYPOTHESIS", hypothesis, "chart-hypothesis"),
        ("OTHER / PARTIAL", other, "chart-other"),
    ]
    maximum = max([value for _, value, _ in items] + [1])
    rows = []
    y_values = [54, 118, 182]
    for (label, value, css_class), y in zip(items, y_values):
        width = round((value / maximum) * 420)
        rows.append(
            f'<text x="18" y="{y + 5}" class="chart-label">{esc(label)}</text>'
            f'<rect x="190" y="{y - 16}" width="420" height="28" rx="8" class="chart-track"/>'
            f'<rect x="190" y="{y - 16}" width="{width}" height="28" rx="8" class="chart-bar {css_class}"/>'
            f'<text x="650" y="{y + 5}" class="chart-value">{value}</text>'
        )
    return (
        '<svg class="status-chart" viewBox="0 0 680 220" role="img" '
        'aria-label="Current research claim status distribution">'
        + "".join(rows)
        + '</svg>'
    )

def render_dossier_progress(project: dict, evidence: dict) -> str:
    claims = evidence.get("claims", [])
    total = len(claims)
    facts = sum(1 for c in claims if c.get("status") == "FACT")
    hypotheses = sum(1 for c in claims if c.get("status") == "STRONG_HYPOTHESIS")
    other = total - facts - hypotheses
    open_gates = len(evidence.get("open_gates", []))
    fact_pct = round((facts / total) * 100) if total else 0
    hypothesis_pct = round((hypotheses / total) * 100) if total else 0
    other_pct = max(0, 100 - fact_pct - hypothesis_pct) if total else 0
    return f"""
    <article class="dossier-progress">
      <div class="dossier-head">
        <strong>{esc(project['title'])}</strong>
        <span>{total} claims · {open_gates} open gates</span>
      </div>
      <div class="stacked-chart" role="img" aria-label="{esc(project['title'])}: {facts} facts, {hypotheses} strong hypotheses, {other} other claims">
        <span class="seg fact" style="width:{fact_pct}%" title="FACT: {facts}"></span>
        <span class="seg hypothesis" style="width:{hypothesis_pct}%" title="STRONG_HYPOTHESIS: {hypotheses}"></span>
        <span class="seg other" style="width:{other_pct}%" title="Other: {other}"></span>
      </div>
      <div class="legend-row">
        <span><i class="key fact"></i>FACT {facts}</span>
        <span><i class="key hypothesis"></i>Hypothesis {hypotheses}</span>
        <span><i class="key other"></i>Other {other}</span>
      </div>
    </article>
    """


def render_geo_fallback_svg(geo: dict) -> str:
    points = []
    for sheet in geo.get("sheets", []):
        points.extend(sheet.get("polygon", []))
        for item in sheet.get("controls", []) + sheet.get("holdouts", []):
            points.append([item["lat"], item["lon"]])
    for item in geo.get("geodetic_controls", []):
        points.append([item["lat"], item["lon"]])
    if not points:
        return '<p class="muted">No geospatial display points available.</p>'
    lats = [p[0] for p in points]
    lons = [p[1] for p in points]
    min_lat, max_lat = min(lats), max(lats)
    min_lon, max_lon = min(lons), max(lons)
    pad = 28
    width, height = 760, 430

    def xy(lat, lon):
        x = pad + (lon - min_lon) / max(max_lon - min_lon, 1e-12) * (width - 2 * pad)
        y = pad + (max_lat - lat) / max(max_lat - min_lat, 1e-12) * (height - 2 * pad)
        return x, y

    elements = [
        f'<rect x="0" y="0" width="{width}" height="{height}" rx="12" fill="#f7f9fc"/>'
    ]
    for sheet in geo.get("sheets", []):
        coords = " ".join(
            f"{xy(lat, lon)[0]:.1f},{xy(lat, lon)[1]:.1f}"
            for lat, lon in sheet.get("polygon", [])
        )
        diagnostic = "DIAGNOSTIC" in str(sheet.get("authority", ""))
        stroke = "#d97706" if diagnostic else "#16803a"
        dash = ' stroke-dasharray="8 7"' if diagnostic else ""
        elements.append(
            f'<polygon points="{coords}" fill="{stroke}" fill-opacity="0.07" '
            f'stroke="{stroke}" stroke-width="3"{dash}/>'
        )
        for item in sheet.get("controls", []):
            x, y = xy(item["lat"], item["lon"])
            elements.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="#16803a" stroke="#fff" stroke-width="2"/>'
            )
        for item in sheet.get("holdouts", []):
            x, y = xy(item["lat"], item["lon"])
            elements.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="#c62828" stroke="#fff" stroke-width="2"/>'
            )

    control_by_id = {x["id"]: x for x in geo.get("geodetic_controls", [])}
    for rel in geo.get("geodetic_relationships", []):
        a = control_by_id.get(rel.get("from"))
        b = control_by_id.get(rel.get("to"))
        if a and b:
            x1, y1 = xy(a["lat"], a["lon"])
            x2, y2 = xy(b["lat"], b["lon"])
            elements.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                'stroke="#2563eb" stroke-width="2" stroke-dasharray="7 5"/>'
            )
    for item in geo.get("geodetic_controls", []):
        x, y = xy(item["lat"], item["lon"])
        elements.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="#2563eb" stroke="#fff" stroke-width="2"/>'
        )
    elements.append(
        '<text x="18" y="412" font-family="system-ui" font-size="13" fill="#4d5666">'
        'Static fallback control-network view · geographic display only'
        '</text>'
    )
    return (
        f'<svg class="geo-fallback" viewBox="0 0 {width} {height}" role="img" '
        'aria-label="Fallback Santurce georeference control network">'
        + "".join(elements)
        + "</svg>"
    )



def render_open_gates(evidence: dict) -> str:
    return "".join(
        f"<li><strong>{esc(g['id'])}</strong> — {esc(g['state'])}: {esc(g['target'])}</li>"
        for g in evidence.get("open_gates", [])
    )


def render(pointer: dict, registry: dict, evidence_docs: dict[str, dict], geo: dict) -> str:
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
    authority_coverage = round((gate_pass / gate_total) * 100) if gate_total else 0
    authority_progress_class = progress_class(authority_coverage)
    evidence_progress_class = progress_class(evidence_coverage)
    promotion_progress_class = progress_class(promotion_coverage)
    claim_status_counts = {}
    for evidence in evidence_docs.values():
        for claim in evidence.get("claims", []):
            status = claim.get("status", "UNSPECIFIED")
            claim_status_counts[status] = claim_status_counts.get(status, 0) + 1
    fact_claims = claim_status_counts.get("FACT", 0)
    hypothesis_claims = claim_status_counts.get("STRONG_HYPOTHESIS", 0)
    total_claims = sum(claim_status_counts.values())
    other_claims = total_claims - fact_claims - hypothesis_claims
    claim_status_chart = render_claim_status_chart(fact_claims, hypothesis_claims, other_claims)
    dossier_progress_html = "".join(
        render_dossier_progress(project, evidence_docs[project["id"]])
        for project in projects
        if project["id"] in evidence_docs
    )

    geo_payload = json.dumps(geo, separators=(",", ":")).replace("</", "<\\/")
    promoted_geo_sheets = sum(
        1 for sheet in geo.get("sheets", [])
        if sheet.get("authority") == "PROMOTED_DERIVATION_BASELINE"
    )
    promoted_gcps = sum(
        len(sheet.get("controls", []))
        for sheet in geo.get("sheets", [])
        if sheet.get("authority") == "PROMOTED_DERIVATION_BASELINE"
    )
    geo_sheet_rows = "".join(
        "<tr>"
        f"<td>{esc(sheet['title'])}</td>"
        f"<td>{esc(sheet['authority'])}</td>"
        f"<td>{esc(sheet.get('internal_rms_m', sheet.get('overlap_registration', {}).get('rms_px', '')))}</td>"
        f"<td>{len(sheet.get('controls', []))}</td>"
        "</tr>"
        for sheet in geo.get("sheets", [])
    )

    geo_fallback_svg = render_geo_fallback_svg(geo)

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
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
:root{{--navy:#071a33;--paper:#ffffff;--ink:#000000;--rule:#d7dce5;--muted:#4d5666;--link:#003b7a;--soft:#eef1f5;--green:#16803a;--amber:#d97706;--red:#c62828;--slate:#7a8493}}
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
.chart-grid{{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(280px,.8fr);gap:14px;margin:14px 0}}
.chart-card{{background:var(--paper);border:1px solid var(--rule);border-radius:16px;padding:18px;box-shadow:0 8px 24px rgba(0,0,0,.12);overflow:hidden}}
.map-card{{background:var(--paper);border:1px solid var(--rule);border-radius:16px;padding:18px;margin:14px 0;box-shadow:0 8px 24px rgba(0,0,0,.12);overflow:hidden}}
#geo-map{{height:520px;width:100%;border-radius:12px;border:1px solid var(--rule);background:#e9edf3}}
.geo-fallback{{width:100%;height:100%;display:block}}.map-fallback-note{{padding:8px 10px;background:#fff7ed;border-top:1px solid #f2c98b;font-size:.86rem}}
.geo-grid{{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(260px,.7fr);gap:14px;align-items:start}}
.geo-legend{{display:grid;gap:9px;margin:10px 0 16px}}.geo-legend span{{display:flex;align-items:center;gap:8px}}
.geo-dot{{width:12px;height:12px;border-radius:50%;display:inline-block}}.geo-dot.promoted{{background:var(--green)}}.geo-dot.holdout{{background:var(--red)}}.geo-dot.diagnostic{{background:var(--amber)}}.geo-dot.ngs{{background:#2563eb}}
.geo-note{{border-left:4px solid var(--amber);padding:10px 12px;background:#fff7ed;border-radius:8px}}
.leaflet-popup-content{{font-family:system-ui,-apple-system,sans-serif;line-height:1.35}}
.chart-card h2{{margin-bottom:4px}}
.status-chart{{width:100%;height:auto;display:block;margin-top:8px}}
.chart-track{{fill:#e8ecf2}}.chart-bar.chart-fact{{fill:var(--green)}}.chart-bar.chart-hypothesis{{fill:var(--amber)}}.chart-bar.chart-other{{fill:var(--slate)}}
.chart-label,.chart-value{{font-family:system-ui,-apple-system,sans-serif;fill:#000;font-size:16px;font-weight:750}}
.chart-value{{text-anchor:end;font-size:18px}}
.dossier-progress{{padding:12px 0;border-bottom:1px solid var(--rule)}}.dossier-progress:last-child{{border-bottom:0}}
.dossier-head{{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}}
.dossier-head span{{color:var(--muted);font-size:.9rem}}
.stacked-chart{{display:flex;width:100%;height:24px;border-radius:8px;overflow:hidden;background:#e8ecf2;margin:10px 0 8px}}
.seg{{height:100%;display:block}}.seg.fact{{background:var(--green)}}.seg.hypothesis{{background:var(--amber)}}.seg.other{{background:var(--slate)}}
.legend-row{{display:flex;gap:14px;flex-wrap:wrap;font-size:.82rem;color:var(--muted)}}
.key{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}}.key.fact{{background:var(--green)}}.key.hypothesis{{background:var(--amber)}}.key.other{{background:var(--slate)}}
.progress-card{{margin:0;min-width:0}}
.progress-card .big{{font-size:1.8rem;font-weight:850;line-height:1}}
.progress-track{{height:11px;border-radius:999px;background:var(--soft);overflow:hidden;margin:12px 0 7px}}
.progress-fill{{height:100%;background:var(--progress-color);border-radius:inherit;transition:width .45s ease,background-color .25s ease}}
.progress-high{{--progress-color:var(--green)}}.progress-mid{{--progress-color:var(--amber)}}.progress-low{{--progress-color:var(--red)}}
.gate-ring{{width:108px;height:108px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--progress-color) 0 calc(var(--p)*1%),var(--soft) calc(var(--p)*1%) 100%);margin:8px auto}}
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
@media (max-width:760px){{main{{padding:10px 8px 30px}}.card,.hero,.progress-card,.chart-card,.map-card{{padding:14px;border-radius:12px}}td,th{{padding:8px;font-size:.91rem}}.progress-grid,.chart-grid,.geo-grid{{grid-template-columns:1fr}}.hero{{align-items:flex-start}}.gate-ring{{margin-left:0}}#geo-map{{height:430px}}.chart-label{{font-size:14px}}.chart-value{{font-size:16px}}}}
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
<a class="jump" href="#map">Map</a>
<a class="jump" href="#charts">Charts</a>
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
<div class="metric"><span class="muted">Promoted geo sheets</span><strong>{promoted_geo_sheets}</strong></div>
<div class="metric"><span class="muted">Promoted GCPs</span><strong>{promoted_gcps}</strong></div>
</section>

<section id="map" class="map-card">
<h2>Georeferences & map control</h2>
<p>Promoted First/Second Section control geometry is shown on the modern basemap. Third Section is displayed only as a diagnostic chained footprint and is not an independently promoted absolute georeference.</p>
<div class="geo-grid">
<div>
<div id="geo-map" aria-label="Santurce georeference control map">{geo_fallback_svg}</div>
</div>
<div>
<h3>Map status</h3>
<div class="geo-legend">
<span><i class="geo-dot promoted"></i>Promoted fit control / promoted sheet footprint</span>
<span><i class="geo-dot holdout"></i>Failed temporal-alignment holdout — not a GCP</span>
<span><i class="geo-dot diagnostic"></i>Diagnostic-only Third Section footprint</span>
<span><i class="geo-dot ngs"></i>Verified NGS control / diagnostic bearing relation</span>
</div>
<div class="table-scroll">
<table><thead><tr><th>Sheet</th><th>Authority</th><th>RMS</th><th>GCPs</th></tr></thead><tbody>{geo_sheet_rows}</tbody></table>
</div>
<p class="geo-note"><strong>Third Section:</strong> 101 overlap-registration inliers; RMS 1.1859701 px. Its footprint is diagnostic only. Historical raster overlays are not yet embedded in this dashboard repository.</p>
<p class="geo-note"><strong>South Base:</strong> NGS PID TV1051 is plotted with MORRO LIGHTHOUSE TV1029. The dashed line is the independently corroborated bearing relationship; it does not represent the separate 1904/1909 magnetic observation points.</p>
<small>Geospatial source binding: <code>{esc(geo['source']['repository'])}@{esc(geo['source']['commit_sha'][:12])}</code></small>
</div>
</div>
</section>

<section id="charts" class="chart-grid" aria-label="Research charts">
<div class="chart-card">
<h2>Research status</h2>
<p class="muted">Current claim distribution across embedded dossiers.</p>
<div class="legend-row" aria-label="Chart color legend"><span><i class="key fact"></i>FACT</span><span><i class="key hypothesis"></i>Hypothesis</span><span><i class="key other"></i>Other / partial</span></div>
{claim_status_chart}
</div>
<div class="chart-card">
<h2>Dossier progress</h2>
<p class="muted">Claim mix and unresolved-gate count by dossier.</p>
{dossier_progress_html}
</div>
</section>

<section id="progress">
<div class="progress-grid">
<div class="progress-card">
<h2>Authority gates</h2>
<div class="gate-ring {authority_progress_class}" style="--p:{authority_coverage}"><span>{gate_pass}/{gate_total}</span></div>
<p><strong>{gate_pass} PASS</strong> · {gate_open} OPEN/other</p>
<small>Distribution of currently tracked authority gate states.</small>
</div>
<div class="progress-card">
<h2>Research coverage</h2>
<div class="big">{evidence_coverage}%</div>
<div class="progress-track" aria-label="Research evidence coverage"><div class="progress-fill {evidence_progress_class}" style="width:{evidence_coverage}%"></div></div>
<p>{len(evidence_docs)} of {len(projects)} registered dossiers have embedded evidence.</p>
<small>{total_claims} claims · {fact_claims} FACT · {hypothesis_claims} STRONG_HYPOTHESIS</small>
</div>
<div class="progress-card">
<h2>Promotion coverage</h2>
<div class="big">{promotion_coverage}%</div>
<div class="progress-track" aria-label="Promotion coverage"><div class="progress-fill {promotion_progress_class}" style="width:{promotion_coverage}%"></div></div>
<p>{promoted_dossiers} of {len(projects)} research dossiers carry a human promotion receipt.</p>
<small>This is coverage, not a quality score. Green ≥70% · amber 40–69% · red &lt;40%.</small>
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

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script id="galia-geo-data" type="application/json">{geo_payload}</script>
<script>
(() => {{
  const geo = JSON.parse(document.getElementById('galia-geo-data').textContent);
  const mapEl = document.getElementById('geo-map');
  if (window.L && mapEl) {{
    mapEl.innerHTML = '';
    const map = L.map('geo-map', {{scrollWheelZoom:false, zoomControl:true}});
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    maxZoom:19,
    attribution:'&copy; OpenStreetMap contributors'
  }}).addTo(map);

  const bounds = [];
  const styleForSheet = sheet => {{
    const diagnostic = String(sheet.authority).includes('DIAGNOSTIC');
    return {{
      color: diagnostic ? '#d97706' : '#16803a',
      weight: diagnostic ? 2 : 3,
      dashArray: diagnostic ? '8 7' : null,
      fillColor: diagnostic ? '#d97706' : '#16803a',
      fillOpacity: diagnostic ? 0.06 : 0.08
    }};
  }};

  geo.sheets.forEach(sheet => {{
    const poly = L.polygon(sheet.polygon, styleForSheet(sheet)).addTo(map);
    poly.bindPopup('<strong>'+sheet.title+'</strong><br>'+sheet.authority);
    sheet.polygon.forEach(p => bounds.push(p));

    (sheet.controls || []).forEach(gcp => {{
      L.circleMarker([gcp.lat,gcp.lon], {{
        radius:7, color:'#ffffff', weight:2, fillColor:'#16803a', fillOpacity:1
      }}).addTo(map).bindPopup(
        '<strong>'+gcp.label+'</strong><br>'+
        'PROMOTED FIT CONTROL<br>Residual: '+Number(gcp.residual_m).toFixed(3)+' m'
      );
      bounds.push([gcp.lat,gcp.lon]);
    }});

    (sheet.holdouts || []).forEach(gcp => {{
      L.circleMarker([gcp.lat,gcp.lon], {{
        radius:7, color:'#ffffff', weight:2, fillColor:'#c62828', fillOpacity:1
      }}).addTo(map).bindPopup(
        '<strong>'+gcp.label+'</strong><br>'+
        'FAILED HOLDOUT — NOT A GCP<br>Residual: '+Number(gcp.residual_m).toFixed(3)+' m'
      );
      bounds.push([gcp.lat,gcp.lon]);
    }});
  }});

  const geodeticById = Object.fromEntries((geo.geodetic_controls || []).map(x => [x.id, x]));
  (geo.geodetic_relationships || []).forEach(rel => {{
    const a = geodeticById[rel.from], b = geodeticById[rel.to];
    if (!a || !b) return;
    L.polyline([[a.lat,a.lon],[b.lat,b.lon]], {{
      color:'#2563eb', weight:2, dashArray:'7 5', opacity:.9
    }}).addTo(map).bindPopup(
      '<strong>South Base → Morro bearing check</strong><br>'+
      rel.status+'<br>Historical: '+rel.historical_bearing+
      '<br>Δ azimuth: '+Number(rel.angular_difference_arcsec).toFixed(2)+' arcsec'
    );
  }});
  (geo.geodetic_controls || []).forEach(ctrl => {{
    L.circleMarker([ctrl.lat,ctrl.lon], {{
      radius:8, color:'#ffffff', weight:2, fillColor:'#2563eb', fillOpacity:1
    }}).addTo(map).bindPopup(
      '<strong>'+ctrl.label+'</strong><br>'+ctrl.status+
      '<br>Datum: '+ctrl.datum+'<br>'+ctrl.history
    );
    bounds.push([ctrl.lat,ctrl.lon]);
  }});

    if (bounds.length) map.fitBounds(bounds, {{padding:[18,18]}});
    else map.setView([18.45,-66.07],14);
  }} else if (mapEl) {{
    mapEl.insertAdjacentHTML('beforeend','<div class="map-fallback-note">Interactive basemap unavailable; governed static control-network fallback shown.</div>');
  }}
}})();

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
    geo = load(GEO)
    validate_geo(geo)

    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    data = render(pointer, registry, evidence_docs, geo)
    out.write_text(data, encoding="utf-8")
    print("GALIA_DASHBOARD_VALIDATION=PASS")
    print("GALIA_RESEARCH_EVIDENCE_DOCS=" + str(len(evidence_docs)))
    print("GALIA_GEO_SHEETS=" + str(len(geo.get("sheets", []))))
    print("GALIA_DASHBOARD_SHA256=" + hashlib.sha256(data.encode()).hexdigest())


if __name__ == "__main__":
    main()
