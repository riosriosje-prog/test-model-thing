import os
import tempfile
import unittest

from tools.run_condado_pica_pica_capture_pilot import run_pilot


class PicaPicaCapturePilotTests(unittest.TestCase):
    def test_full_raw_capture_is_semantically_reproducible_across_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "fixture.pdf")
            with open(source, "wb") as f:
                f.write(
                    b"%PDF-1.4\n"
                    b"test-only Pica-Pica raw capture fixture\n"
                    b"%%EOF\n"
                )

            first = run_pilot(source, os.path.join(tmp, "run-one"))
            second = run_pilot(source, os.path.join(tmp, "run-two"))

            self.assertEqual(
                first["historical_store"]["semantic_fingerprint_sha256"],
                second["historical_store"]["semantic_fingerprint_sha256"],
            )
            self.assertEqual(
                first["historical_store"]["claim_status_after_capture"],
                "PROPOSED",
            )
            self.assertEqual(
                second["historical_store"]["claim_status_after_capture"],
                "PROPOSED",
            )
            self.assertEqual(
                first["historical_store"]["promotion_blockers_after_capture"],
                [],
            )
            self.assertEqual(
                second["historical_store"]["promotion_blockers_after_capture"],
                [],
            )
            self.assertFalse(first["authority"]["canonical_promotion_executed"])
            self.assertFalse(second["authority"]["canonical_promotion_executed"])


if __name__ == "__main__":
    unittest.main()
