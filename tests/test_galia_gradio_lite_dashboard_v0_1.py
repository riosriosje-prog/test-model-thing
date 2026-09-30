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

def test_promoted_manifest_is_read_only_and_deploy_bound():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data["state"] == "PROMOTED_DEPLOY_AUTHORIZED"
    assert data["scope"] == "READ_ONLY_PRESENTATION_PLANE_ONLY"
    assert data["publication_boundary"]["authority_mutation"] is False
    assert data["publication_boundary"]["canonical_writes"] is False
    assert data["publication_boundary"]["remote_write"] is False
    assert data["promotion"]["human_promotion_required"] is False
    assert data["promotion"]["auto_promote"] is False
    assert data["publication_boundary"]["target_space"] == "Junitos/GALIA"
    assert data["publication_boundary"]["deployment_authorized"] is True

def test_gradio_lite_build_is_pinned_and_read_only(tmp_path):
    text = build(tmp_path)
    assert "https://gradio-lite-previews.s3.amazonaws.com/PINNED_HF_HUB/dist/lite.js" in text
    assert "https://gradio-lite-previews.s3.amazonaws.com/PINNED_HF_HUB/dist/lite.css" in text
    assert "GALIA_GRADIO_LITE_WORKER_REDIRECT=ACTIVE" in text
    assert "galia-gradio-lite-webworker.js" in text
    assert "READ ONLY" in text
    assert "_galia_starlette_url_init" in text
    assert "query_string" in text
    assert "authority mutation disabled" in text
    assert "RC-GALIA-2026-09-13-004" in text
    assert "Avenida MacLeary. Parada 44" in text
    assert "South Base · San Juan" in text
    assert "SOUTHBASE-ORIGINAL-STATION-DESCRIPTION" in text

def test_build_embeds_bound_data_and_no_remote_control_plane_fetch(tmp_path):
    text = build(tmp_path)
    assert "raw.githubusercontent.com" not in text
    assert "githubusercontent.com" not in text
    assert "cdn.jsdelivr.net/npm/@gradio/lite@5.45.0" not in text
    assert '<gradio-file name="authority.json">' in text
    assert '<gradio-file name="research_registry.json">' in text
    assert '<gradio-file name="evidence_mcleary.json">' in text
    assert '<gradio-file name="evidence_south-base.json">' in text

def test_builder_reuses_existing_fail_closed_authority_validation():
    source = (ROOT / "tools/build_galia_gradio_lite_dashboard.py").read_text(encoding="utf-8")
    assert "base.validate_authority(pointer)" in source
    assert "base.validate_research(registry)" in source


def test_worker_redirect_is_scoped_to_pinned_runtime():
    source = (ROOT / "tools/build_galia_gradio_lite_dashboard.py").read_text(encoding="utf-8")
    assert 'PATCHED_WORKER_PATH = "./galia-gradio-lite-webworker.js"' in source
    assert 'class GaliaBlob extends NativeBlob' in source
    assert 'PINNED_HF_HUB' in source
    assert 'webworker-' in source
