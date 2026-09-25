from __future__ import annotations

from pathlib import Path
import unittest


class HuggingFaceWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.workflow = (
            cls.root / ".github" / "workflows" / "huggingface-export.yml"
        ).read_text(encoding="utf-8")

    def test_oidc_write_identity_is_required(self) -> None:
        self.assertIn("id-token: write", self.workflow)
        self.assertIn("contents: read", self.workflow)

    def test_no_long_lived_hf_secret_is_used(self) -> None:
        self.assertNotIn("secrets.HF_TOKEN", self.workflow)
        self.assertNotIn("HF_TOKEN: ${{ secrets.", self.workflow)

    def test_destination_is_pinned(self) -> None:
        self.assertIn("HF_REPO_ID: Junitos/galia-2", self.workflow)
        self.assertIn("HF_OIDC_RESOURCE: Junitos/galia-2", self.workflow)

    def test_publish_is_existing_repo_only_and_pr_scoped(self) -> None:
        self.assertIn("--existing-repo-only", self.workflow)
        self.assertIn("--create-pr", self.workflow)

    def test_push_trigger_is_explicit_publish_request_only(self) -> None:
        self.assertIn(".hf/publish-request.json", self.workflow)


if __name__ == "__main__":
    unittest.main()
