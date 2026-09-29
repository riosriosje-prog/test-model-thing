from pathlib import Path
import re

MIGRATION = Path("supabase/migrations/20260929180000_galia_search_retrieval_plane_v1.sql")


def sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_candidate_is_additive_and_derived_only():
    s = sql().lower()
    forbidden = [
        r"\\binsert\\s+into\\s+canonical\\.",
        r"\\bupdate\\s+canonical\\.",
        r"\\bdelete\\s+from\\s+canonical\\.",
        r"\\balter\\s+table\\s+canonical\\.",
        r"\\bdrop\\s+(table|view|schema)\\s+(if\\s+exists\\s+)?canonical\\.",
        r"\\btruncate\\s+(table\\s+)?canonical\\.",
    ]
    for pattern in forbidden:
        assert re.search(pattern, s) is None, pattern

    assert "derived.search_chunks" in s
    assert "derived.search_embeddings" in s
    assert "derived.embedding_jobs" in s
    assert "derived.hybrid_search_v1" in s


def test_extensions_are_unpinned():
    s = sql().lower()
    assert "create extension if not exists vector" in s
    assert "create extension if not exists pg_trgm" in s
    assert re.search(r"create\\s+extension[^;]+\\bversion\\b", s) is None


def test_fail_closed_rls_and_no_security_definer():
    s = sql().lower()
    for table in (
        "derived.embedding_profiles",
        "derived.search_chunks",
        "derived.search_chunk_supersessions",
        "derived.search_embeddings",
        "derived.embedding_jobs",
    ):
        assert f"alter table {table} enable row level security" in s
        assert f"revoke all on table {table} from anon, authenticated" in s

    assert "security definer" not in s
    assert "security invoker" in s


def test_embedding_is_content_hash_bound():
    s = sql().lower()
    assert "foreign key (chunk_id, content_sha256)" in s
    assert "references derived.search_chunks(id, content_sha256)" in s
    assert "check (embedding_input_sha256 = content_sha256)" in s


def test_search_chunks_and_embeddings_are_append_only():
    s = sql().lower()
    assert "search_chunks_immutable_v1" in s
    assert "search_embeddings_immutable_v1" in s
    assert "search_chunk_supersessions_immutable_v1" in s
    assert "derived.reject_immutable_retrieval_row_v1" in s


def test_hybrid_search_has_three_retrieval_channels():
    s = sql().lower()
    assert "lexical as (" in s
    assert "semantic as (" in s
    assert "exact_match as (" in s
    assert "websearch_to_tsquery" in s
    assert "<=> p_query_embedding" in s
    assert "rrf_score" in s


def test_schema_version_advances_from_1_5_to_1_6():
    s = sql()
    assert "'1.6.0'" in s
    assert "'base_schema', '1.5.0'" in s
    assert "'canonical_writes', false" in s
    assert "'retrieval_authority', false" in s


def test_no_automatic_promotion_surface():
    s = sql().lower()
    assert "audit.human_decisions" not in s
    assert "audit.promotion_receipts" not in s
    assert "promote" not in s.replace("automatic promotion", "")
