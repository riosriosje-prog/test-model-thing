"""Offline acceptance tests for the optional 1901 LOC IIIF evidence probe."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/galia_1901_iiif_probe.py"
spec = importlib.util.spec_from_file_location("galia_1901_iiif_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeResponse:
    status = 200

    def __init__(self, url, payload, content_type="image/jpeg", redirect=None):
        self.url = redirect or (url.full_url if hasattr(url, "full_url") else url)
        self.payload = payload
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        return False

    def geturl(self):
        return self.url

    def read(self, count):
        return self.payload[:count]


VALID_JPEG = b"\xff\xd8\xff" + b"x" * 1040 + b"\xff\xd9"


class Loiza1901IIIFProbeTests(unittest.TestCase):
    def test_manifest_gates_remain_on_hold(self):
        record = probe.validate_manifest()
        self.assertEqual(record["state"], "AUTHORITY_HOLD")
        self.assertFalse(record["raw_capture_complete"])
        self.assertFalse(record["canonical_write_authorized"])
        self.assertEqual(
            record["archive_acquisition_plan_1901"]["request_submission_status"],
            "NOT_SENT",
        )

    def test_exact_date_to_iiif_page_locator_crosswalk(self):
        expected = {
            "1901-01-23": ("1901012301", "0077"),
            "1901-01-24": ("1901012401", "0080"),
        }
        for date, (issue, page) in expected.items():
            with self.subTest(date=date):
                url = probe.iiif_candidate_url(date)
                self.assertEqual(urlsplit(url).hostname, "tile.loc.gov")
                self.assertTrue(url.endswith("/full/pct:25/0/default.jpg"))
                self.assertNotIn("%3A", url.upper())
                self.assertEqual(
                    probe.iiif_candidate_info_url(date),
                    url.rsplit("/full/", 1)[0] + "/info.json",
                )
                resource = unquote(urlsplit(url).path.split("/")[3])
                self.assertEqual(
                    resource,
                    ":".join((
                        "service", "ndnp", "prru",
                        "batch_prru_galleta_ver01", "data",
                        "2013201074", "00415662968", issue, page,
                    )),
                )

    def test_offline_cli_has_no_network_or_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "should-not-exist"
            run = subprocess.run(
                [sys.executable, str(SCRIPT), "--output-dir", str(dest)],
                cwd=ROOT, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            output = json.loads(run.stdout)
            self.assertEqual(output["state"], "LOCATOR_ONLY")
            self.assertFalse(output["network_access_attempted"])
            self.assertFalse(output["filesystem_modified"])
            self.assertEqual(len(output["candidate_iiif_urls"]), 2)
            self.assertEqual(len(output["candidate_iiif_metadata_urls"]), 2)
            self.assertFalse(dest.exists())

    def test_mock_valid_jpeg_writes_bytes_and_hashed_unapproved_receipt(self):
        date = "1901-01-23"
        def fake_opener(url, timeout):
            self.assertEqual(timeout, 30)
            self.assertEqual(url.get_header("User-agent"), "GALIA-Historical-Research/0.1")
            self.assertEqual(url.get_header("Accept"), "image/jpeg")
            return FakeResponse(url, VALID_JPEG)

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            result = probe.capture_candidate(
                date, output_dir, opener=fake_opener,
            )
            image = output_dir / result["local_image_filename"]
            self.assertEqual(image.read_bytes(), VALID_JPEG)
            self.assertEqual(
                result["retrieved_jpeg_sha256"],
                hashlib.sha256(VALID_JPEG).hexdigest(),
            )
            receipt = output_dir / f"gaceta_{date}_page3_candidate.receipt.json"
            self.assertTrue(receipt.is_file())
            self.assertEqual(
                json.loads(receipt.read_text(encoding="utf-8")),
                result,
            )
            self.assertEqual(
                result["status"], "RAW_BYTES_RECEIVED_PENDING_VISUAL_REVIEW",
            )
            for key in (
                "original_source_custody_authenticated",
                "printed_issue_date_verified",
                "page_number_verified", "notice_columns_visually_reviewed",
                "historical_human_review_complete", "canonical_write_authorized",
                "legal_street_naming_act_verified",
            ):
                self.assertFalse(result[key])
            self.assertIsNone(result["geometry"])
            self.assertIsNone(result["source_document_event_date"])

    def test_html_redirect_short_and_oversized_payloads_fail_without_files(self):
        url = probe.iiif_candidate_url("1901-01-24")
        invalid_cases = (
            ("html", b"<html>Forbidden</html>", "text/html"),
            ("short", b"\xff\xd8\xff\xd9", "image/jpeg"),
            ("truncated", b"\xff\xd8\xff" + b"x" * 1040, "image/jpeg"),
        )
        for label, payload, mime in invalid_cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                def fake(url, timeout):
                    return FakeResponse(url, payload, content_type=mime)
                with self.assertRaises(ValueError):
                    probe.capture_candidate("1901-01-24", Path(tmp), opener=fake)
                self.assertEqual(list(Path(tmp).iterdir()), [])
        with tempfile.TemporaryDirectory() as tmp:
            def redirected(url, timeout):
                return FakeResponse(url, VALID_JPEG, redirect="https://example.com/scan.jpg")
            with self.assertRaises(ValueError):
                probe.capture_candidate("1901-01-24", Path(tmp), opener=redirected)
            self.assertEqual(list(Path(tmp).iterdir()), [])
        with self.assertRaises(ValueError):
            probe.read_jpeg(url, opener=lambda url, timeout: FakeResponse(
                url, VALID_JPEG), maximum=100)

    def test_default_transport_rejects_redirect_before_requesting_target(self):
        from urllib.error import HTTPError
        from urllib.request import HTTPRedirectHandler
        handler = probe.RejectRedirects()
        self.assertIsInstance(handler, HTTPRedirectHandler)
        request = probe.Request(probe.iiif_candidate_url("1901-01-23"))
        self.assertIsNone(handler.redirect_request(
            request, None, 302, "Found",
            {"Location": "https://example.com/untrusted-image"},
            "https://example.com/untrusted-image",
        ))
        class SimulatedOpener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 302, "Redirect blocked",
                                {"Location": "https://example.com/"}, None)
        with patch.object(probe, "build_opener", return_value=SimulatedOpener()) as factory:
            with self.assertRaises(HTTPError):
                probe.read_jpeg(probe.iiif_candidate_url("1901-01-23"))
            self.assertIsInstance(factory.call_args.args[0], probe.RejectRedirects)

    def test_wrong_domain_cannot_produce_raw_image(self):
        for url in (
            "http://tile.loc.gov/image-services/iiif/abc",
            "https://evil.example/image-services/iiif/abc",
            "https://tile.loc.gov@evil.example/image-services/iiif/abc",
            "https://tile.loc.gov:444/image-services/iiif/abc",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    probe.read_jpeg(url, opener=lambda url, timeout: None)

    def test_atomic_create_does_not_overwrite_competing_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "evidence.jpg"
            original_link = os.link
            def other_writer_arrives(src, dst):
                Path(dst).write_bytes(b"competing source image")
                return original_link(src, dst)
            with patch.object(probe.os, "link", side_effect=other_writer_arrives):
                with self.assertRaises(FileExistsError):
                    probe.atomic_write_bytes(destination, VALID_JPEG)
            self.assertEqual(destination.read_bytes(), b"competing source image")
            self.assertEqual(
                [p.name for p in Path(temp).iterdir()], ["evidence.jpg"]
            )

    def test_existing_image_or_receipt_prevents_overwrite(self):
        for kind in ("image", "receipt"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                date = "1901-01-23"
                base = Path(tmp)
                leaf = (
                    f"gaceta_{date}_page3_candidate.jpg"
                    if kind == "image" else
                    f"gaceta_{date}_page3_candidate.receipt.json"
                )
                expected = base / leaf
                expected.write_bytes(b"do not overwrite")
                def opener(url, timeout):
                    return FakeResponse(url, VALID_JPEG)
                with self.assertRaises(FileExistsError):
                    probe.capture_candidate(date, base, opener=opener)
                self.assertEqual(expected.read_bytes(), b"do not overwrite")
                self.assertEqual(len(list(base.iterdir())), 1)


if __name__ == "__main__":
    unittest.main()
