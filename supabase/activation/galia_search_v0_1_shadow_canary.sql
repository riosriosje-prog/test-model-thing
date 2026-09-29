-- GALIA Search v0.1 shadow canary
-- Run ONLY after the candidate migration on an isolated/shadow database.
-- Entire fixture is transactional and rolls back.
-- No production execution is authorized by this file.

begin;

do $$
declare
    v_schema text;
begin
    select schema_version into v_schema
    from audit.schema_versions
    where schema_version = '1.6.0'
      and migration_name = 'galia_search_retrieval_plane_v1'
      and status = 'APPLIED';

    if v_schema is null then
        raise exception 'CANARY FAIL: schema 1.6.0 candidate not applied';
    end if;
end;
$$;

insert into audit.human_decisions (
    id, decision_type, actor, object_type, object_ref, rationale, authority_context
)
values (
    '00000000-0000-4000-8000-000000000001'::uuid,
    'OTHER',
    'galia-search-shadow-canary',
    'CANARY_FIXTURE',
    'search-v0.1',
    'Ephemeral shadow fixture only; transaction rolls back',
    '{"canary":true}'::jsonb
);

insert into canonical.sources (
    id, source_key, institution, repository, title,
    document_date, event_date_start, event_date_end,
    document_type, provenance_chain, promotion_decision_id
)
values (
    '10000000-0000-4000-8000-000000000001'::uuid,
    'CANARY-MCLEARY-1915',
    'GALIA CANARY',
    'SHADOW',
    'Canary McLeary-Taft-Parada 44 corpus',
    '1915-11-22',
    '1915-11-22',
    '1915-11-22',
    'CANARY',
    '{"ephemeral":true}'::jsonb,
    '00000000-0000-4000-8000-000000000001'::uuid
);

insert into canonical.documents (
    id, source_id, title, document_type, document_date,
    metadata, promotion_decision_id
)
values (
    '20000000-0000-4000-8000-000000000001'::uuid,
    '10000000-0000-4000-8000-000000000001'::uuid,
    'Canary Santurce 1915',
    'CANARY',
    '1915-11-22',
    '{"ephemeral":true}'::jsonb,
    '00000000-0000-4000-8000-000000000001'::uuid
);

insert into canonical.document_pages (
    id, document_id, page_key, page_number, extracted_text,
    extraction_method, extraction_version, metadata, promotion_decision_id
)
values
(
    '30000000-0000-4000-8000-000000000001'::uuid,
    '20000000-0000-4000-8000-000000000001'::uuid,
    'canary-page-1',
    1,
    '22 noviembre 1915 Avenida MacLeary Parada 44 frente al mar.',
    'CANARY',
    'v1',
    '{"ephemeral":true}'::jsonb,
    '00000000-0000-4000-8000-000000000001'::uuid
),
(
    '30000000-0000-4000-8000-000000000002'::uuid,
    '20000000-0000-4000-8000-000000000001'::uuid,
    'canary-page-2',
    2,
    'El Palmarito, 13 Taft Avenue, residencia de Mary King McLeary.',
    'CANARY',
    'v1',
    '{"ephemeral":true}'::jsonb,
    '00000000-0000-4000-8000-000000000001'::uuid
),
(
    '30000000-0000-4000-8000-000000000003'::uuid,
    '20000000-0000-4000-8000-000000000001'::uuid,
    'canary-page-3',
    3,
    'Camino de Loíza y otra infraestructura de Santurce.',
    'CANARY',
    'v1',
    '{"ephemeral":true}'::jsonb,
    '00000000-0000-4000-8000-000000000001'::uuid
);

insert into derived.embedding_profiles (
    profile_key, provider, model_name, model_revision, dimensions,
    distance_metric, status, metadata, created_by
)
values (
    'CANARY-512',
    'CANARY',
    'deterministic-one-hot',
    'v1',
    512,
    'COSINE',
    'ACTIVE',
    '{"ephemeral":true}'::jsonb,
    'galia-search-shadow-canary'
);

insert into derived.search_chunks (
    id, derivation_key, canonical_object_type, document_page_id,
    source_id, document_id, chunk_ordinal, content,
    document_date, event_date_start, event_date_end, document_type,
    derivation_version, source_snapshot_sha256, metadata, created_by
)
select
    p.chunk_id,
    p.derivation_key,
    'DOCUMENT_PAGE',
    p.page_id,
    '10000000-0000-4000-8000-000000000001'::uuid,
    '20000000-0000-4000-8000-000000000001'::uuid,
    0,
    dp.extracted_text,
    '1915-11-22'::date,
    '1915-11-22'::date,
    '1915-11-22'::date,
    'CANARY',
    'CANARY-DERIVATION-v1',
    repeat('a', 64),
    '{"ephemeral":true}'::jsonb,
    'galia-search-shadow-canary'
from (
    values
      (
        '40000000-0000-4000-8000-000000000001'::uuid,
        'canary:page:1',
        '30000000-0000-4000-8000-000000000001'::uuid
      ),
      (
        '40000000-0000-4000-8000-000000000002'::uuid,
        'canary:page:2',
        '30000000-0000-4000-8000-000000000002'::uuid
      ),
      (
        '40000000-0000-4000-8000-000000000003'::uuid,
        'canary:page:3',
        '30000000-0000-4000-8000-000000000003'::uuid
      )
) as p(chunk_id, derivation_key, page_id)
join canonical.document_pages dp on dp.id = p.page_id;

insert into derived.search_embeddings (
    chunk_id, content_sha256, profile_key, embedding,
    embedding_input_sha256, metadata, created_by
)
select
    c.id,
    c.content_sha256,
    'CANARY-512',
    case c.id
      when '40000000-0000-4000-8000-000000000001'::uuid
        then (array[1.0::real] || array_fill(0.0::real, array[511]))::extensions.vector
      when '40000000-0000-4000-8000-000000000002'::uuid
        then (array[0.0::real, 1.0::real] || array_fill(0.0::real, array[510]))::extensions.vector
      else
        (array[0.0::real, 0.0::real, 1.0::real] || array_fill(0.0::real, array[509]))::extensions.vector
    end,
    c.content_sha256,
    '{"ephemeral":true}'::jsonb,
    'galia-search-shadow-canary'
from derived.search_chunks c
where c.id in (
    '40000000-0000-4000-8000-000000000001'::uuid,
    '40000000-0000-4000-8000-000000000002'::uuid,
    '40000000-0000-4000-8000-000000000003'::uuid
);

do $$
declare
    v_first uuid;
begin
    select chunk_id into v_first
    from derived.hybrid_search_v1(
        'MacLeary Parada 44',
        (array[1.0::real] || array_fill(0.0::real, array[511]))::extensions.vector,
        'CANARY-512',
        3
    )
    limit 1;

    if v_first is distinct from '40000000-0000-4000-8000-000000000001'::uuid then
        raise exception 'CANARY FAIL: expected MacLeary/Parada 44 chunk first, got %', v_first;
    end if;
end;
$$;

do $$
declare
    v_count integer;
begin
    select count(*) into v_count
    from derived.hybrid_search_v1(
        'McLeary',
        null,
        'CANARY-512',
        10
    )
    where chunk_id = '40000000-0000-4000-8000-000000000002'::uuid;

    if v_count <> 1 then
        raise exception 'CANARY FAIL: lexical McLeary retrieval missing';
    end if;
end;
$$;

do $$
declare
    v_blocked boolean := false;
begin
    begin
        update derived.search_chunks
        set content = 'MUTATION SHOULD FAIL'
        where id = '40000000-0000-4000-8000-000000000001'::uuid;
    exception
        when others then
            if position(
                'GALIA derived retrieval row is immutable'
                in sqlerrm
            ) > 0 then
                v_blocked := true;
            else
                raise;
            end if;
    end;

    if not v_blocked then
        raise exception
            'CANARY FAIL: immutable search chunk accepted update';
    end if;
end;
$$;

insert into derived.search_chunks (
    id, derivation_key, canonical_object_type, document_page_id,
    source_id, document_id, chunk_ordinal, content,
    document_date, event_date_start, event_date_end, document_type,
    derivation_version, source_snapshot_sha256, metadata, created_by
)
values (
    '40000000-0000-4000-8000-000000000004'::uuid,
    'canary:page:1:v2',
    'DOCUMENT_PAGE',
    '30000000-0000-4000-8000-000000000001'::uuid,
    '10000000-0000-4000-8000-000000000001'::uuid,
    '20000000-0000-4000-8000-000000000001'::uuid,
    0,
    '22 noviembre 1915 Avenida MacLeary, Parada 44, frente al mar. Superseding derivation.',
    '1915-11-22',
    '1915-11-22',
    '1915-11-22',
    'CANARY',
    'CANARY-DERIVATION-v2',
    repeat('b', 64),
    '{"ephemeral":true}'::jsonb,
    'galia-search-shadow-canary'
);

insert into derived.search_chunk_supersessions (
    old_chunk_id, new_chunk_id, reason, created_by
)
values (
    '40000000-0000-4000-8000-000000000001'::uuid,
    '40000000-0000-4000-8000-000000000004'::uuid,
    'CANARY supersession',
    'galia-search-shadow-canary'
);

do $$
declare
    v_count integer;
begin
    select count(*) into v_count
    from derived.hybrid_search_v1(
        'MacLeary Parada 44',
        null,
        'CANARY-512',
        10
    )
    where chunk_id = '40000000-0000-4000-8000-000000000001'::uuid;

    if v_count <> 0 then
        raise exception 'CANARY FAIL: superseded chunk remained retrievable';
    end if;
end;
$$;

rollback;
