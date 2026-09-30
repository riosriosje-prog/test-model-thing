import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_direct_dashboard_build(tmp_path):
    out = tmp_path / "index.html"
    p = subprocess.run(
        [sys.executable, "tools/build_galia_dashboard.py", "--output", str(out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "GALIA_DASHBOARD_VALIDATION=PASS" in p.stdout
    assert "GALIA_RESEARCH_EVIDENCE_DOCS=2" in p.stdout
    text = out.read_text(encoding="utf-8")
    assert "READ ONLY" in text
    assert "RC-GALIA-2026-09-13-004" in text
    assert "EXECUTED_27_OF_27" in text
    assert "Avenida MacLeary. Parada 44" in text
    assert "sale de Taft" in text
    assert "MCLEARY-NAMING-ACT-19140105-19151121" in text
    assert "South Base · San Juan" in text
    assert "2,572.6-meter base line" in text
    assert "SOUTHBASE-ORIGINAL-STATION-DESCRIPTION" in text
    assert "STRONG_HYPOTHESIS" in text
    assert "Human-promoted dossiers" in text
    assert "<script src=" not in text


def test_pointer_is_non_mutating():
    d = json.loads((ROOT / "governance/galia_dashboard_authority_pointer.v1.json").read_text())
    assert d["publication"]["mode"] == "READ_ONLY"
    assert d["publication"]["authority_mutation"] is False


def test_embedded_research_is_non_authoritative():
    registry = json.loads((ROOT / "governance/galia_dashboard_research_registry.v1.json").read_text())
    mcleary = next(p for p in registry["projects"] if p["id"] == "mcleary")
    evidence = json.loads((ROOT / mcleary["evidence_path"]).read_text())
    assert evidence["scope"] == "RESEARCH_PRESENTATION_ONLY"
    assert evidence["authority_mutation"] is False
    assert evidence["project_id"] == "mcleary"


def test_south_base_promotion_receipt_preserves_hypothesis_boundary():
    registry = json.loads((ROOT / "governance/galia_dashboard_research_registry.v1.json").read_text())
    project = next(p for p in registry["projects"] if p["id"] == "south-base")
    evidence = json.loads((ROOT / project["evidence_path"]).read_text())
    receipt = json.loads((ROOT / evidence["promotion"]["receipt_path"]).read_text())
    assert receipt["state"] == "PROMOTED"
    assert receipt["promoted_object"]["evidence_path"] == project["evidence_path"]
    assert receipt["scope"]["global_master_mutation"] is False
    assert receipt["scope"]["canonical_database_write"] is False
    assert receipt["scope"]["hypothesis_promoted_as_fact"] is False
    origin = next(c for c in evidence["claims"] if c["id"] == "SOUTHBASE-ORIGIN-1900")
    assert origin["status"] == "STRONG_HYPOTHESIS"


def test_static_site_is_mobile_readable(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [sys.executable, "tools/build_galia_dashboard.py", "--output", str(out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    text = out.read_text(encoding="utf-8")
    assert "📚 GALIA" in text
    assert "--navy:#071a33" in text
    assert "--paper:#ffffff" in text
    assert "--ink:#000000" in text
    assert "background:var(--paper);color:var(--ink)" in text
    assert "@media (max-width:760px)" in text
    assert "<script src=" not in text


def test_static_site_has_progress_and_filters(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [sys.executable, "tools/build_galia_dashboard.py", "--output", str(out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    text = out.read_text(encoding="utf-8")
    assert "Authority gates" in text
    assert "Research coverage" in text
    assert "Promotion coverage" in text
    assert 'class="gate-ring"' in text
    assert 'data-filter="FACT"' in text
    assert 'data-filter="STRONG_HYPOTHESIS"' in text
    assert "visible claim" in text
    assert 'class="card dossier"' in text
    assert "This is coverage, not a quality score." in text


def test_static_site_has_visible_svg_charts(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [sys.executable, "tools/build_galia_dashboard.py", "--output", str(out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    text = out.read_text(encoding="utf-8")
    assert 'id="charts"' in text
    assert 'class="status-chart"' in text
    assert "Research status" in text
    assert "Dossier progress" in text
    assert "STRONG HYPOTHESIS" in text
    assert 'class="stacked-chart"' in text
    assert 'href="#charts"' in text


def test_progress_colors_are_semantic_and_dynamic(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [sys.executable, "tools/build_galia_dashboard.py", "--output", str(out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    text = out.read_text(encoding="utf-8")
    assert "--green:#16803a" in text
    assert "--amber:#d97706" in text
    assert "--red:#c62828" in text
    assert "progress-high" in text
    assert "progress-mid" in text
    assert "progress-low" in text
    assert "chart-fact" in text
    assert "chart-hypothesis" in text
    assert "chart-other" in text
    assert "Green ≥70%" in text
