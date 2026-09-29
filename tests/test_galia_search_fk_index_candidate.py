from pathlib import Path
import re
import unittest

MIGRATION = Path("supabase/migrations/20260929191500_galia_search_fk_index_hardening_v1.sql")

EXPECTED_INDEXES = (
    "search_chunks_document_page_fk_idx",
    "search_chunks_claim_fk_idx",
    "search_chunks_event_fk_idx",
    "search_chunks_entity_fk_idx",
    "search_chunks_entity_alias_fk_idx",
    "search_chunks_evidence_item_fk_idx",
    "search_chunks_source_fk_idx",
    "search_chunks_document_fk_idx",
    "search_chunk_supersessions_new_chunk_fk_idx",
    "search_embeddings_chunk_hash_fk_idx",
    "search_embeddings_profile_fk_idx",
    "embedding_jobs_chunk_hash_fk_idx",
    "embedding_jobs_profile_fk_idx",
)


class SearchFkIndexCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.lower = cls.sql.lower()

    def test_exactly_thirteen_expected_indexes(self):
        self.assertEqual(self.lower.count("create index if not exists "), 13)
        for name in EXPECTED_INDEXES:
            self.assertIn(name, self.lower)

    def test_fail_closed_on_base_schema(self):
        self.assertIn("schema_version = '1.6.0'", self.sql)
        self.assertIn("status = 'APPLIED'", self.sql)
        self.assertIn(
            "GALIA search FK index hardening requires base schema 1.6.0/APPLIED",
            self.sql,
        )

    def test_advances_only_to_1_6_1(self):
        self.assertIn("'1.6.1'", self.sql)
        self.assertIn("'galia_search_fk_index_hardening_v1'", self.sql)
        self.assertIn("'foreign_key_indexes_added', 13", self.sql)

    def test_no_canonical_mutation_or_ddl(self):
        forbidden = (
            r"\binsert\s+into\s+canonical\.",
            r"\bupdate\s+canonical\.",
            r"\bdelete\s+from\s+canonical\.",
            r"\balter\s+table\s+canonical\.",
            r"\bcreate\s+index[^;]+\bon\s+canonical\.",
            r"\bdrop\s+(table|index|schema|view)",
            r"\btruncate\b",
        )
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, self.lower), pattern)

    def test_performance_only_surface(self):
        self.assertNotIn("create extension", self.lower)
        self.assertNotIn("create or replace function", self.lower)
        self.assertNotIn("create table", self.lower)
        self.assertNotIn("alter table", self.lower)
        self.assertNotIn("grant ", self.lower)
        self.assertNotIn("revoke ", self.lower)
        self.assertNotIn(" concurrently", self.lower)
        self.assertIn("'performance_only', true", self.sql)
        self.assertIn("'retrieval_semantics_changed', false", self.sql)
        self.assertIn("'canonical_writes', false", self.sql)


if __name__ == "__main__":
    unittest.main(verbosity=2)
