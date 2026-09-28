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
    text = out.read_text(encoding="utf-8")
    assert "READ ONLY" in text
    assert "RC-GALIA-2026-09-13-004" in text
    assert "EXECUTED_27_OF_27" in text
    assert "<script src=" not in text


def test_pointer_is_non_mutating():
    d = json.loads((ROOT / "governance/galia_dashboard_authority_pointer.v1.json").read_text())
    assert d["publication"]["mode"] == "READ_ONLY"
    assert d["publication"]["authority_mutation"] is False
