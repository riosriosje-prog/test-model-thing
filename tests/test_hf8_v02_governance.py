from __future__ import annotations

import bz2
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / "tools" / "hf8_prepare_simplewiki_v2.py"
CANDIDATE = ROOT / "receipts" / "huggingface" / "hf8-real-weight-candidate-v0.2.json"
PROMOTION = ROOT / "receipts" / "huggingface" / "hf8-v0-2-weight-promotion-receipt.json"


def split_key(title: str) -> int:
    return hashlib.sha256(title.encode("utf-8")).digest()[0]


def find_title(predicate, prefix: str) -> str:
    for i in range(100000):
        title = f"{prefix}-{i}"
        if predicate(split_key(title)):
            return title
    raise AssertionError("could not find deterministic title for requested split")


def page_xml(title: str, text: str) -> str:
    return (
        "<page>"
        f"<title>{escape(title)}</title>"
        "<revision>"
        f"<text>{escape(text)}</text>"
        "</revision>"
        "</page>"
    )


class HF8V02CorpusGovernanceTests(unittest.TestCase):
    def _run_prepare(self, dump: Path, root: Path, suffix: str):
        train = root / f"train-{suffix}.txt"
        ev = root / f"eval-{suffix}.txt"
        receipt = root / f"receipt-{suffix}.json"
        subprocess.run(
            [
                sys.executable,
                str(PREP),
                "--dump", str(dump),
                "--train-output", str(train),
                "--eval-output", str(ev),
                "--receipt", str(receipt),
                "--source-url", "fixture://hf8-v0.2-mini",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return train, ev, json.loads(receipt.read_text(encoding="utf-8"))

    def test_full_dump_split_is_deterministic_and_disjoint(self):
        train_title = find_title(lambda k: k < 32, "train")
        eval_title = find_title(lambda k: 32 <= k < 36, "eval")
        ignored_title = find_title(lambda k: k >= 36, "ignored")

        self.assertNotEqual(train_title, eval_title)
        self.assertLess(split_key(train_title), 32)
        self.assertGreaterEqual(split_key(eval_title), 32)
        self.assertLess(split_key(eval_title), 36)
        self.assertGreaterEqual(split_key(ignored_title), 36)

        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            "<mediawiki>"
            + page_xml(train_title, "Train line alpha with [[Link|display text]].\nSecond train sentence.")
            + page_xml(eval_title, "Evaluation line beta with {{template}} and <ref>citation</ref>.\nSecond eval sentence.")
            + page_xml(ignored_title, "Ignored page content that must not enter either corpus.")
            + "</mediawiki>"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dump = root / "mini.xml.bz2"
            dump.write_bytes(bz2.compress(xml))

            train1, eval1, receipt1 = self._run_prepare(dump, root, "a")
            train2, eval2, receipt2 = self._run_prepare(dump, root, "b")

            self.assertEqual(train1.read_bytes(), train2.read_bytes())
            self.assertEqual(eval1.read_bytes(), eval2.read_bytes())
            self.assertEqual(receipt1["train_sha256"], receipt2["train_sha256"])
            self.assertEqual(receipt1["eval_sha256"], receipt2["eval_sha256"])

            self.assertEqual(receipt1["pages_seen"], 3)
            self.assertEqual(receipt1["pages_train"], 1)
            self.assertEqual(receipt1["pages_eval"], 1)
            self.assertFalse(receipt1["upstream_exact_cleaning_claimed"])

            train_bytes = train1.read_bytes()
            eval_bytes = eval1.read_bytes()
            self.assertTrue(train_bytes)
            self.assertTrue(eval_bytes)
            self.assertNotEqual(train_bytes, eval_bytes)
            self.assertIn(b"Train line alpha", train_bytes)
            self.assertIn(b"Evaluation line beta", eval_bytes)
            self.assertNotIn(b"Ignored page content", train_bytes)
            self.assertNotIn(b"Ignored page content", eval_bytes)


class HF8V02ReceiptConsistencyTests(unittest.TestCase):
    def test_candidate_and_promotion_receipts_bind_same_exact_weight(self):
        candidate = json.loads(CANDIDATE.read_text(encoding="utf-8"))
        promotion = json.loads(PROMOTION.read_text(encoding="utf-8"))

        self.assertEqual(candidate["weight"]["payload_sha256"], promotion["payload_sha256"])
        self.assertEqual(candidate["weight"]["payload_bytes"], promotion["payload_bytes"])
        self.assertEqual(
            candidate["huggingface_candidate"]["manifest_sha256"],
            promotion["manifest_sha256"],
        )
        self.assertEqual(candidate["huggingface_candidate"]["pr_number"], promotion["pr_number"])
        self.assertEqual(candidate["promotion_scope"], promotion["promotion_scope"])

        self.assertEqual(candidate["weight"]["classification"], "GALIA_CURRENT_BOUND")
        self.assertEqual(candidate["weight"]["authority_binding"], "CURRENT_BOUND")
        self.assertEqual(candidate["weight"]["provenance_status"], "COMPLETE")
        self.assertTrue(candidate["weight"]["technical_upload_eligible"])
        self.assertTrue(candidate["weight"]["promotion_preflight_eligible"])
        self.assertEqual(candidate["quality"]["promotion_quality_gate"], "PASS")
        self.assertLess(
            candidate["quality"]["trained_bpc"],
            candidate["quality"]["random_init_baseline_bpc"],
        )

        self.assertEqual(promotion["gate"], "HF8_V0_2_WEIGHT_PROMOTION")
        self.assertEqual(promotion["status"], "PASS")
        self.assertEqual(promotion["pr_status"], "merged")
        self.assertTrue(promotion["promoted"])
        self.assertTrue(promotion["human_promotion_authorized"])
        self.assertFalse(promotion["canonical_authority_transferred"])
        self.assertFalse(promotion["legacy_mutation_authorized"])
        self.assertFalse(promotion["github_pr_22_merged"])
        self.assertEqual(promotion["source_of_truth"], "github")


if __name__ == "__main__":
    unittest.main()
