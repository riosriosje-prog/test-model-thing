import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.run_mcleary_taft_capture_pilot import run_pilot


class McLearyTaftRawCapturePilotTests(unittest.TestCase):
    def test_page_anchored_raw_capture_clears_only_relation_gate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pdf"
            source.write_bytes(b"%PDF-1.4\nfixture\n%%EOF\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()

            anchor = root / "anchor.json"
            anchor.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "anchor_type": "GALIA_MCLEARY_TAFT_1916_PAGE_ANCHOR",
                        "source_pdf_sha256": digest,
                        "page_number": 3,
                        "page_count_extracted": 8,
                        "extraction_method": "pdftotext-layout",
                        "matched_relation": "LEARY_NEAR_TAFT_WITH_SALE_DE",
                        "normalized_context": "calle mcleary sale de taft",
                        "normalized_transcription": "Calle Mc Leary (sale de Taft)",
                        "normalization_basis": "text-layer exact",
                        "page_text_sha256": hashlib.sha256(
                            b"fixture page text"
                        ).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )

            receipt = run_pilot(str(source), str(anchor), str(root / "out"))

            self.assertEqual(
                receipt["status"],
                "RAW_PRIMARY_SOURCE_PAGE_ANCHOR_PASS",
            )
            self.assertTrue(receipt["authority"]["raw_capture_verified"])
            self.assertTrue(receipt["authority"]["page_anchor_verified"])
            self.assertTrue(
                receipt["authority"]["relation_objective_gate_satisfied"]
            )
            self.assertFalse(
                receipt["authority"]["nominative_act_gate_satisfied"]
            )
            self.assertEqual(
                receipt["historical_store"][
                    "promotion_blockers_after_capture"
                ],
                [],
            )
            self.assertEqual(
                receipt["historical_store"][
                    "relation_claim_status_after_capture"
                ],
                "PROPOSED",
            )
            self.assertEqual(
                receipt["historical_store"][
                    "nominative_claim_status_after_capture"
                ],
                "PROPOSED",
            )
            self.assertFalse(
                receipt["authority"]["canonical_promotion_executed"]
            )

    def test_anchor_must_bind_exact_pdf_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pdf"
            source.write_bytes(b"%PDF-1.4\nfixture\n%%EOF\n")

            anchor = root / "anchor.json"
            anchor.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "anchor_type": "GALIA_MCLEARY_TAFT_1916_PAGE_ANCHOR",
                        "source_pdf_sha256": "0" * 64,
                        "page_number": 1,
                        "page_count_extracted": 1,
                        "extraction_method": "pdftotext-layout",
                        "matched_relation": "LEARY_NEAR_TAFT_WITH_SALE_DE",
                        "normalized_context": "calle mcleary sale de taft",
                        "page_text_sha256": "1" * 64,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "exact raw PDF bytes"):
                run_pilot(str(source), str(anchor), str(root / "out"))

    def test_anchor_requires_relation_tokens(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.pdf"
            source.write_bytes(b"%PDF-1.4\nfixture\n%%EOF\n")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()

            anchor = root / "anchor.json"
            anchor.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "anchor_type": "GALIA_MCLEARY_TAFT_1916_PAGE_ANCHOR",
                        "source_pdf_sha256": digest,
                        "page_number": 1,
                        "page_count_extracted": 1,
                        "extraction_method": "pdftotext-layout",
                        "matched_relation": "LEARY_NEAR_TAFT",
                        "normalized_context": "mcleary and taft appear separately",
                        "page_text_sha256": "1" * 64,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "expected street relation"):
                run_pilot(str(source), str(anchor), str(root / "out"))


if __name__ == "__main__":
    unittest.main()
