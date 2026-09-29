-- GALIA Search / Retrieval Plane v0.1
-- Candidate schema migration targeting GALIA schema 1.5.0 -> 1.6.0.
-- ADDITIVE ONLY. No writes to canonical.*. No automatic promotion.
-- Derived retrieval artifacts are never canonical authority.

create extension if not exists vector with schema extensions;
create extension if not exists pg_trgm with schema extensions;

create or replace function derived.search_fold_v1(input_text text)
returns text
language sql
immutable
parallel safe
returns null on null input
set search_path = ''
as $$
    select translate(lower(input_text), 'áéíóúüñ', 'aeiouun')
$$;

create table if not exists derived.embedding_profiles (
    profile_key text primary key,
    provider text not null,
    model_name text not null,
    model_revision text not null,
    dimensions integer not null check (dimensions = 512),
    distance_metric text not null default 'COSINE'
        check (distance_metric = 'COSINE'),
    status text not null default 'ACTIVE'
        check (status in ('ACTIVE', 'DEPRECATED', 'HOLD')),
    metadata jsonb not null default '{}'::jsonb,
    created_by text not null,
    created_at timestamptz not null default now(),
    unique (provider, model_name, model_revision, dimensions, distance_metric)
);

create table if not exists derived.search_chunks (
    id uuid primary key default gen_random_uuid(),
    derivation_key text not null unique,
    canonical_object_type text not null
        check (canonical_object_type in (
            'DOCUMENT_PAGE',
            'CLAIM',
            'EVENT',
            'ENTITY',
            'ENTITY_ALIAS',
            'EVIDENCE_ITEM'
        )),
    document_page_id uuid references canonical.document_pages(id),
    claim_id uuid references canonical.claims(id),
    event_id uuid references canonical.events(id),
    entity_id uuid references canonical.entities(id),
    entity_alias_id uuid references canonical.entity_aliases(id),
    evidence_item_id uuid references canonical.evidence_items(id),

    source_id uuid references canonical.sources(id),
    document_id uuid references canonical.documents(id),

    chunk_ordinal integer not null check (chunk_ordinal >= 0),
    content text not null check (length(btrim(content)) > 0),
    normalized_content text generated always as (
        derived.search_fold_v1(content)
    ) stored,
    fts_simple tsvector generated always as (
        to_tsvector('simple'::regconfig, content)
    ) stored,
    content_sha256 text generated always as (
        encode(extensions.digest(content, 'sha256'), 'hex')
    ) stored,

    document_date date,
    event_date_start date,
    event_date_end date,
    document_type text,

    derivation_version text not null,
    source_snapshot_sha256 text
        check (
            source_snapshot_sha256 is null
            or source_snapshot_sha256 ~ '^[0-9a-f]{64}$'
        ),
    metadata jsonb not null default '{}'::jsonb,
    created_by text not null,
    created_at timestamptz not null default now(),

    check (
        num_nonnulls(
            document_page_id,
            claim_id,
            event_id,
            entity_id,
            entity_alias_id,
            evidence_item_id
        ) = 1
    ),
    check (
        (canonical_object_type = 'DOCUMENT_PAGE' and document_page_id is not null)
        or (canonical_object_type = 'CLAIM' and claim_id is not null)
        or (canonical_object_type = 'EVENT' and event_id is not null)
        or (canonical_object_type = 'ENTITY' and entity_id is not null)
        or (canonical_object_type = 'ENTITY_ALIAS' and entity_alias_id is not null)
        or (canonical_object_type = 'EVIDENCE_ITEM' and evidence_item_id is not null)
    ),
    check (
        event_date_end is null
        or event_date_start is null
        or event_date_end >= event_date_start
    ),
    unique (id, content_sha256)
);

create table if not exists derived.search_chunk_supersessions (
    old_chunk_id uuid primary key
        references derived.search_chunks(id),
    new_chunk_id uuid not null
        references derived.search_chunks(id),
    reason text not null,
    created_by text not null,
    created_at timestamptz not null default now(),
    check (old_chunk_id <> new_chunk_id)
);

create table if not exists derived.search_embeddings (
    chunk_id uuid not null,
    content_sha256 text not null
        check (content_sha256 ~ '^[0-9a-f]{64}$'),
    profile_key text not null
        references derived.embedding_profiles(profile_key),
    embedding extensions.vector(512) not null,
    embedding_input_sha256 text not null
        check (embedding_input_sha256 ~ '^[0-9a-f]{64}$'),
    metadata jsonb not null default '{}'::jsonb,
    created_by text not null,
    created_at timestamptz not null default now(),
    primary key (chunk_id, profile_key),
    foreign key (chunk_id, content_sha256)
        references derived.search_chunks(id, content_sha256),
    check (embedding_input_sha256 = content_sha256)
);

create table if not exists derived.embedding_jobs (
    id uuid primary key default gen_random_uuid(),
    chunk_id uuid not null,
    content_sha256 text not null
        check (content_sha256 ~ '^[0-9a-f]{64}$'),
    profile_key text not null
        references derived.embedding_profiles(profile_key),
    status text not null default 'PENDING'
        check (status in ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'DEAD')),
    attempt_count integer not null default 0
        check (attempt_count >= 0),
    available_at timestamptz not null default now(),
    locked_at timestamptz,
    finished_at timestamptz,
    last_error text,
    metadata jsonb not null default '{}'::jsonb,
    created_by text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    foreign key (chunk_id, content_sha256)
        references derived.search_chunks(id, content_sha256),
    unique (chunk_id, profile_key, content_sha256),
    check (
        (status = 'SUCCEEDED' and finished_at is not null)
        or status <> 'SUCCEEDED'
    )
);

create index if not exists search_chunks_fts_simple_gin
on derived.search_chunks using gin (fts_simple);

create index if not exists search_chunks_normalized_trgm_gin
on derived.search_chunks using gin (normalized_content extensions.gin_trgm_ops);

create index if not exists search_chunks_document_date_idx
on derived.search_chunks (document_date);

create index if not exists search_chunks_event_dates_idx
on derived.search_chunks (event_date_start, event_date_end);

create index if not exists search_chunks_object_type_idx
on derived.search_chunks (canonical_object_type);

create index if not exists search_embeddings_hnsw_cosine
on derived.search_embeddings
using hnsw (embedding extensions.vector_cosine_ops);

create index if not exists embedding_jobs_dispatch_idx
on derived.embedding_jobs (status, available_at, created_at)
where status in ('PENDING', 'FAILED');

create or replace function derived.reject_immutable_retrieval_row_v1()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
    raise exception
        'GALIA derived retrieval row is immutable; append/supersede instead (% %)',
        tg_op,
        tg_table_name;
end;
$$;

drop trigger if exists search_chunks_immutable_v1 on derived.search_chunks;
create trigger search_chunks_immutable_v1
before update or delete on derived.search_chunks
for each row execute function derived.reject_immutable_retrieval_row_v1();

drop trigger if exists search_embeddings_immutable_v1 on derived.search_embeddings;
create trigger search_embeddings_immutable_v1
before update or delete on derived.search_embeddings
for each row execute function derived.reject_immutable_retrieval_row_v1();

drop trigger if exists search_chunk_supersessions_immutable_v1
on derived.search_chunk_supersessions;
create trigger search_chunk_supersessions_immutable_v1
before update or delete on derived.search_chunk_supersessions
for each row execute function derived.reject_immutable_retrieval_row_v1();

create or replace function derived.protect_embedding_profile_identity_v1()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
    if row(
        old.provider,
        old.model_name,
        old.model_revision,
        old.dimensions,
        old.distance_metric
    ) is distinct from row(
        new.provider,
        new.model_name,
        new.model_revision,
        new.dimensions,
        new.distance_metric
    ) then
        raise exception
            'GALIA embedding profile identity is immutable; create a new profile';
    end if;
    return new;
end;
$$;

drop trigger if exists embedding_profile_identity_v1
on derived.embedding_profiles;
create trigger embedding_profile_identity_v1
before update on derived.embedding_profiles
for each row execute function derived.protect_embedding_profile_identity_v1();

create or replace function derived.hybrid_search_v1(
    p_query_text text,
    p_query_embedding extensions.vector(512),
    p_profile_key text,
    p_match_count integer default 20,
    p_object_type text default null,
    p_document_type text default null,
    p_document_from date default null,
    p_document_to date default null,
    p_event_from date default null,
    p_event_to date default null,
    p_rrf_k integer default 50,
    p_lexical_weight double precision default 1.0,
    p_semantic_weight double precision default 1.0,
    p_exact_weight double precision default 0.35
)
returns table (
    chunk_id uuid,
    canonical_object_type text,
    content text,
    content_sha256 text,
    source_id uuid,
    document_id uuid,
    document_page_id uuid,
    claim_id uuid,
    event_id uuid,
    entity_id uuid,
    entity_alias_id uuid,
    evidence_item_id uuid,
    document_date date,
    event_date_start date,
    event_date_end date,
    document_type text,
    lexical_rank bigint,
    semantic_rank bigint,
    exact_rank bigint,
    rrf_score double precision
)
language sql
stable
security invoker
set search_path = ''
as $$
with params as (
    select
        nullif(btrim(p_query_text), '') as q,
        derived.search_fold_v1(nullif(btrim(p_query_text), '')) as q_fold,
        greatest(1, least(coalesce(p_match_count, 20), 100)) as match_count,
        greatest(1, coalesce(p_rrf_k, 50)) as rrf_k
),
eligible as (
    select c.*
    from derived.search_chunks c
    where not exists (
        select 1
        from derived.search_chunk_supersessions s
        where s.old_chunk_id = c.id
    )
      and (p_object_type is null or c.canonical_object_type = p_object_type)
      and (p_document_type is null or c.document_type = p_document_type)
      and (p_document_from is null or c.document_date >= p_document_from)
      and (p_document_to is null or c.document_date <= p_document_to)
      and (
          p_event_from is null
          or coalesce(c.event_date_end, c.event_date_start) >= p_event_from
      )
      and (
          p_event_to is null
          or coalesce(c.event_date_start, c.event_date_end) <= p_event_to
      )
),
lexical as (
    select
        e.id,
        row_number() over (
            order by
                ts_rank_cd(
                    e.fts_simple,
                    websearch_to_tsquery('simple'::regconfig, p.q)
                ) desc,
                e.id
        ) as rank_ix
    from eligible e
    cross join params p
    where p.q is not null
      and e.fts_simple @@ websearch_to_tsquery('simple'::regconfig, p.q)
    order by rank_ix
    limit (select least(match_count * 3, 300) from params)
),
semantic as (
    select
        e.id,
        row_number() over (
            order by se.embedding OPERATOR(extensions.<=>) p_query_embedding, e.id
        ) as rank_ix
    from eligible e
    join derived.search_embeddings se
      on se.chunk_id = e.id
     and se.content_sha256 = e.content_sha256
     and se.profile_key = p_profile_key
    where p_query_embedding is not null
    order by se.embedding OPERATOR(extensions.<=>) p_query_embedding, e.id
    limit (select least(match_count * 3, 300) from params)
),
exact_match as (
    select
        e.id,
        row_number() over (
            order by
                position(p.q_fold in e.normalized_content),
                length(e.normalized_content),
                e.id
        ) as rank_ix
    from eligible e
    cross join params p
    where p.q_fold is not null
      and e.normalized_content like ('%' || p.q_fold || '%')
    order by rank_ix
    limit (select least(match_count * 3, 300) from params)
),
candidate_ids as (
    select id from lexical
    union
    select id from semantic
    union
    select id from exact_match
),
scored as (
    select
        e.*,
        l.rank_ix as lexical_rank,
        s.rank_ix as semantic_rank,
        x.rank_ix as exact_rank,
        (
            coalesce(
                p_lexical_weight / ((select rrf_k from params) + l.rank_ix),
                0.0
            )
            +
            coalesce(
                p_semantic_weight / ((select rrf_k from params) + s.rank_ix),
                0.0
            )
            +
            coalesce(
                p_exact_weight / ((select rrf_k from params) + x.rank_ix),
                0.0
            )
        )::double precision as rrf_score
    from candidate_ids ids
    join eligible e on e.id = ids.id
    left join lexical l on l.id = e.id
    left join semantic s on s.id = e.id
    left join exact_match x on x.id = e.id
)
select
    id as chunk_id,
    canonical_object_type,
    content,
    content_sha256,
    source_id,
    document_id,
    document_page_id,
    claim_id,
    event_id,
    entity_id,
    entity_alias_id,
    evidence_item_id,
    document_date,
    event_date_start,
    event_date_end,
    document_type,
    lexical_rank,
    semantic_rank,
    exact_rank,
    rrf_score
from scored
order by rrf_score desc, chunk_id
limit (select match_count from params)
$$;

alter table derived.embedding_profiles enable row level security;
alter table derived.search_chunks enable row level security;
alter table derived.search_chunk_supersessions enable row level security;
alter table derived.search_embeddings enable row level security;
alter table derived.embedding_jobs enable row level security;

revoke all on table derived.embedding_profiles from anon, authenticated;
revoke all on table derived.search_chunks from anon, authenticated;
revoke all on table derived.search_chunk_supersessions from anon, authenticated;
revoke all on table derived.search_embeddings from anon, authenticated;
revoke all on table derived.embedding_jobs from anon, authenticated;

revoke all on function derived.search_fold_v1(text)
from public, anon, authenticated;
revoke all on function derived.reject_immutable_retrieval_row_v1()
from public, anon, authenticated;
revoke all on function derived.protect_embedding_profile_identity_v1()
from public, anon, authenticated;
revoke all on function derived.hybrid_search_v1(
    text,
    extensions.vector,
    text,
    integer,
    text,
    text,
    date,
    date,
    date,
    date,
    integer,
    double precision,
    double precision,
    double precision
) from public, anon, authenticated;

grant usage on schema derived to service_role;

grant select, insert on table derived.search_chunks to service_role;
grant select, insert on table derived.search_chunk_supersessions to service_role;
grant select, insert on table derived.search_embeddings to service_role;
grant select, insert, update on table derived.embedding_profiles to service_role;
grant select, insert, update on table derived.embedding_jobs to service_role;

grant execute on function derived.hybrid_search_v1(
    text,
    extensions.vector,
    text,
    integer,
    text,
    text,
    date,
    date,
    date,
    date,
    integer,
    double precision,
    double precision,
    double precision
) to service_role;

comment on table derived.search_chunks is
'GALIA derived retrieval chunks. Non-canonical, append-only, reproducible search artifacts bound to canonical objects.';

comment on table derived.search_embeddings is
'GALIA derived embeddings. Vector similarity is retrieval metadata only and never evidence, corroboration, or canonical authority.';

comment on table derived.embedding_jobs is
'GALIA embedding queue boundary. Jobs may update operational state but may not write canonical.*.';

comment on function derived.hybrid_search_v1 is
'GALIA hybrid retrieval: exact/fuzzy lexical + full text + semantic RRF. Retrieval score is not evidentiary weight.';

insert into audit.schema_versions (
    schema_version,
    migration_name,
    status,
    migration_hash,
    metadata,
    applied_at
)
values (
    '1.6.0',
    'galia_search_retrieval_plane_v1',
    'APPLIED',
    null,
    jsonb_build_object(
        'additive', true,
        'canonical_writes', false,
        'derived_only', true,
        'retrieval_authority', false,
        'embedding_dimensions', 512,
        'hybrid_search', 'RRF',
        'base_schema', '1.5.0'
    ),
    now()
)
on conflict (schema_version) do nothing;
