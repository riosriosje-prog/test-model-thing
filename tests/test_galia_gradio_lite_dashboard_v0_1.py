import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "governance/galia_gradio_lite_dashboard_candidate.v0_1.json"

def build(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [
            sys.executable,
            "tools/build_galia_gradio_lite_dashboard.py",
            "--output",
            str(out),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.read_text(encoding="utf-8")

def test_candidate_manifest_is_non_authoritative():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["state"] == "CANDIDATE_NOT_PROMOTED"
    assert data["scope"] == "READ_ONLY_PRESENTATION_PLANE_ONLY"
    assert data["publication_boundary"]["authority_mutation"] is False
    assert data["publication_boundary"]["canonical_writes"] is False
    assert data["publication_boundary"]["remote_write"] is False
    assert data["promotion"]["human_promotion_required"] is True
    assert data["promotion"]["auto_promote"] is False

def test_gradio_lite_build_is_pinned_and_read_only(tmp_path):
    text = build(tmp_path)
    assert "@gradio/lite@5.45.0/dist/lite.js" in text
    assert "@gradio/lite@5.45.0/dist/lite.css" in text
    assert "READ ONLY" in text
    assert "authority mutation disabled" in text
    assert "RC-GALIA-2026-09-13-004" in text
    assert "Avenida MacLeary. Parada 44" in text

def test_build_embeds_bound_data_and_no_remote_control_plane_fetch(tmp_path):
    text = build(tmp_path)
    assert "raw.githubusercontent.com" not in text
    assert "githubusercontent.com" not in text
    assert '<gradio-file name="authority.json">' in text
    assert '<gradio-file name="research_registry.json">' in text
    assert '<gradio-file name="evidence_mcleary.json">' in text

def test_builder_reuses_existing_fail_closed_authority_validation():
    source = (ROOT / "tools/build_galia_gradio_lite_dashboard.py").read_text(encoding="utf-8")
    assert "base.validate_authority(pointer)" in source
    assert "base.validate_research(registry)" in source
