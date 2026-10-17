"""Fail-closed audit for the real October 2026 Loíza IIIF network attempt.

A GitHub Actions job marked SUCCESS only means that its DIAGNOSTIC ran.
The two source JPEG requests timed out; no historical source bytes exist.
"""
import copy
import json
from pathlib import Path
import unittest


RECORD = (
    Path(__file__).resolve().parents[1]
    / "research/gates/loiza_1901_iiif_attempt_39036332243.v0_1.json"
)


def diagnostic_gate(receipt):
    if (
        receipt["schema"] != "galia.loiza.1901.iiif_network_attempt.v0.1"
        or receipt["state"] != "REMOTE_BLOCKED_NO_SOURCE_BYTES"
        or receipt["event_type"] !=
           "TECHNICAL_RETRIEVAL_ATTEMPT_NOT_HISTORICAL_EVENT"
        or receipt["attempt_date_utc"] != "2026-10-17"
    ):
        raise ValueError("network diagnostic not properly classified")
    git = receipt["git"]
    if (
        git["workflow_run_id"] != 39036332243
        or git["run_head_sha"] != "c54a79ec078f3de6acb23dbfaaafe91587678f84"
        or git["workflow_conclusion"] != "success"
        or "NOT" not in git["workflow_conclusion_scope"]
    ):
        raise ValueError("GitHub workflow provenance/meaning drift")
    artifact = receipt["artifact"]
    if (
        artifact["artifact_id"] != 12102535664
        or artifact["artifact_zip_sha256"] !=
           "9fe614bd4f4202c0ab8a3f139aba5a925057e7c660ad686b2566794b4a4c41af"
        or artifact["artifact_zip_bytes"] != 1098
        or artifact["artifact_zip_verified_after_download"] is not True
        or artifact["contained_source_image"] is not False
        or artifact["contains_original_page_pdf_or_jp2"] is not False
        or sorted(artifact["contained_files"]) != sorted([
            "CAPTURE_DIAGNOSTIC.json", "probe.ndjson", "probe.stderr.txt"
        ])
    ):
        raise ValueError("diagnostic ZIP misrepresented as an image")
    run = receipt["run_result"]
    if (
        run["probe_command_exit_code"] != 1
        or run["captured_candidate_document_ids"] != []
        or run["source_image_files_created"] != 0
        or run["source_sha256_digests_created"] != 0
        or len(run["requests"]) != 2
        or set(run["blocked_document_ids"]) != {
            "GACETA-1901-01-23-ED1-P3",
            "GACETA-1901-01-24-ED1-P3",
        }
    ):
        raise ValueError("unearned successful source fetch")
    for entry in run["requests"]:
        if (
            entry["document_id"] not in run["blocked_document_ids"]
            or entry["status"] != "REMOTE_BLOCKED_NO_SOURCE_BYTES"
            or entry["exception_text"] != "The read operation timed out"
            or entry["http_status_observed"] is not None
            or entry["jpeg_received"] is not False
            or entry["image_sha256"] is not None
            or entry["image_bytes"] is not None
        ):
            raise ValueError("timeout misrepresented as a retrieved source")
        assert entry["source_resource_id"] in entry["url"]
    history = receipt["historical_authority"]
    if (
        history["authority_state"] != "AUTHORITY_HOLD"
        or history["raw_capture_required"] is not True
        or history["historian_human_review_complete"] is not False
        or history["canonical_write_authorized"] is not False
        or history["custodial_source_bytes_received"] is not False
        or history["source_pages_visually_inspected"] is not False
        or history["gambaro_notices_legal_identity_verified"] is not False
        or history["historical_event_date"] is not None
        or history["geometry"] is not None
    ):
        raise ValueError("source timeout promoted to historical authority")
    escalation = receipt["next_escalation"]
    if (
        escalation["source_acquisition_request_sent"] is not False
        or escalation["source_material_received"] is not False
    ):
        raise ValueError("UPR request/receipt falsely recorded")
    return True


class Loiza1901LiveIiiifAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_live_diagnostic_distinguishes_workflow_pass_from_image_capture(self):
        self.assertTrue(diagnostic_gate(self.receipt))
        self.assertEqual(
            self.receipt["run_result"]["source_image_files_created"], 0,
        )
        self.assertEqual(
            self.receipt["git"]["workflow_conclusion"], "success",
        )

    def test_corrupt_custody_or_image_success_is_rejected(self):
        probes = [
            (("run_result", "source_image_files_created"), 2),
            (("run_result", "probe_command_exit_code"), 0),
            (("run_result", "requests", 0, "jpeg_received"), True),
            (("run_result", "requests", 1, "image_sha256"), "a" * 64),
            (("artifact", "contained_source_image"), True),
            (("artifact", "artifact_zip_bytes"), 7000000),
            (("historical_authority", "authority_state"), "PROMOTED"),
            (("historical_authority", "canonical_write_authorized"), True),
            (("historical_authority", "source_pages_visually_inspected"), True),
            (("next_escalation", "source_acquisition_request_sent"), True),
            (("git", "workflow_conclusion_scope"), "Source captured"),
        ]
        for loc, value in probes:
            with self.subTest(field=loc):
                altered = copy.deepcopy(self.receipt)
                target = altered
                for key in loc[:-1]:
                    target = target[key]
                target[loc[-1]] = value
                with self.assertRaises(ValueError):
                    diagnostic_gate(altered)


if __name__ == "__main__":
    unittest.main()
