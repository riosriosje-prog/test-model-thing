from pathlib import Path
import re
import unittest

MIGRATION = Path("supabase/migrations/20260929180000_galia_search_retrieval_plane_v1.sql")


class GaliaSearchCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.lower = cls.sql.lower()

    def test_candidate_is_additive_and_derived_only(self):
        forbidden = [
            r"\\binsert\\s+into\\s+canonical\\.",
            r"\\bupdate\\s+canonical\\.",
            r"\\bdelete\\s+from\\s+canonical\\.",
            r"\\balter\\s+table\\s+canonical\\.",
            r"\\bdrop\\s+(table|view|schema)\\s+(if\\s+exists\\s+)?canonical\\.",
            r"\\btruncate\\s+(table\\s+)?canonical\\.",
        ]
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, self.lower), pattern)

        self.assertIn("derived.search_chunks", self.lower)
        self.assertIn("derived.search_embeddings", self.lower)
        self.assertIn("derived.embedding_jobs", self.lower)
        self.assertIn("derived.hybrid_search_v1", self.lower)

    def test_extensions_are_unpinned(self):
        self.assertIn("create extension if not exists vector", self.lower)
        self.assertIn("create extension if not exists pg_trgm", self.lower)
        self.assertIsNone(
            re.search(r"create\\s+extension[^;]+\\bversion\\b", self.lower)
        )

    def test_fail_closed_rls_and_no_security_definer(self):
        for table in (
            "derived.embedding_profiles",
            "derived.search_chunks",
            "derived.search_chunk_supersessions",
            "derived.search_embeddings",
            "derived.embedding_jobs",
        ):
            self.assertIn(
                f"alter table {table} enable row level security", self.lower
            )
            self.assertIn(
                f"revoke all on table {table} from anon, authenticated", self.lower
            )

        self.assertNotIn("security definer", self.lower)
        self.assertIn("security invoker", self.lower)

    def test_embedding_is_content_hash_bound(self):
        self.assertIn("foreign key (chunk_id, content_sha256)", self.lower)
        self.assertIn(
            "references derived.search_chunks(id, content_sha256)", self.lower
        )
        self.assertIn(
            "check (embedding_input_sha256 = content_sha256)", self.lower
        )

    def test_search_chunks_and_embeddings_are_append_only(self):
        self.assertIn("search_chunks_immutable_v1", self.lower)
        self.assertIn("search_embeddings_immutable_v1", self.lower)
        self.assertIn("search_chunk_supersessions_immutable_v1", self.lower)
        self.assertIn(
            "derived.reject_immutable_retrieval_row_v1", self.lower
        )

    def test_hybrid_search_has_three_retrieval_channels(self):
        self.assertIn("lexical as (", self.lower)
        self.assertIn("semantic as (", self.lower)
        self.assertIn("exact_match as (", self.lower)
        self.assertIn("websearch_to_tsquery", self.lower)
        self.assertIn("<=> p_query_embedding", self.lower)
        self.assertIn("rrf_score", self.lower)

    def test_schema_version_advances_from_1_5_to_1_6(self):
        self.assertIn("'1.6.0'", self.sql)
        self.assertIn("'base_schema', '1.5.0'", self.sql)
        self.assertIn("'canonical_writes', false", self.sql)
        self.assertIn("'retrieval_authority', false", self.sql)

    def test_no_automatic_promotion_surface(self):
        self.assertNotIn("audit.human_decisions", self.lower)
        self.assertNotIn("audit.promotion_receipts", self.lower)
        self.assertNotIn(
            "promote",
            self.lower.replace("automatic promotion", ""),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
