-- GALIA Search FK Index Hardening v0.2
-- Candidate schema migration targeting GALIA schema 1.6.0 -> 1.6.1.
-- ADDITIVE PERFORMANCE ONLY. No canonical writes. No retrieval semantic changes.

do $galia$
begin
    if not exists (
        select 1
        from audit.schema_versions
        where schema_version = '1.6.0'
          and status = 'APPLIED'
    ) then
        raise exception
            'GALIA search FK index hardening requires base schema 1.6.0/APPLIED';
    end if;
end;
$galia$;

create index if not exists search_chunks_document_page_fk_idx
on derived.search_chunks (document_page_id);

create index if not exists search_chunks_claim_fk_idx
on derived.search_chunks (claim_id);

create index if not exists search_chunks_event_fk_idx
on derived.search_chunks (event_id);

create index if not exists search_chunks_entity_fk_idx
on derived.search_chunks (entity_id);

create index if not exists search_chunks_entity_alias_fk_idx
on derived.search_chunks (entity_alias_id);

create index if not exists search_chunks_evidence_item_fk_idx
on derived.search_chunks (evidence_item_id);

create index if not exists search_chunks_source_fk_idx
on derived.search_chunks (source_id);

create index if not exists search_chunks_document_fk_idx
on derived.search_chunks (document_id);

create index if not exists search_chunk_supersessions_new_chunk_fk_idx
on derived.search_chunk_supersessions (new_chunk_id);

create index if not exists search_embeddings_chunk_hash_fk_idx
on derived.search_embeddings (chunk_id, content_sha256);

create index if not exists search_embeddings_profile_fk_idx
on derived.search_embeddings (profile_key);

create index if not exists embedding_jobs_chunk_hash_fk_idx
on derived.embedding_jobs (chunk_id, content_sha256);

create index if not exists embedding_jobs_profile_fk_idx
on derived.embedding_jobs (profile_key);

insert into audit.schema_versions (
    schema_version,
    migration_name,
    status,
    migration_hash,
    metadata,
    applied_at
)
values (
    '1.6.1',
    'galia_search_fk_index_hardening_v1',
    'APPLIED',
    null,
    jsonb_build_object(
        'additive', true,
        'performance_only', true,
        'canonical_writes', false,
        'retrieval_semantics_changed', false,
        'base_schema', '1.6.0',
        'foreign_key_indexes_added', 13
    ),
    now()
)
on conflict (schema_version) do nothing;
