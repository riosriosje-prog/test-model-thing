-- GALIA schema 1.5.0 SEARCH CONTRACT fixture
-- Purpose: ephemeral CI only.
-- Source: read-only catalog introspection of galia-cangrejos schema 1.5.0 on 2026-09-29.
-- Scope: exact table/column/constraint surface required to compile and canary-test
--       galia_search_retrieval_plane_v1. This is NOT a full database dump.
-- Contains no production data.

create schema if not exists extensions;
create schema if not exists audit;
create schema if not exists canonical;
create schema if not exists derived;

create extension if not exists pgcrypto with schema extensions;

do $$
begin
    create role anon nologin;
exception when duplicate_object then null;
end $$;

do $$
begin
    create role authenticated nologin;
exception when duplicate_object then null;
end $$;

do $$
begin
    create role service_role nologin;
exception when duplicate_object then null;
end $$;

create table audit.human_decisions (
    id uuid primary key default gen_random_uuid(),
    decision_type text not null
        check (decision_type = any (array[
            'PROMOTE'::text,
            'REJECT'::text,
            'SUPERSEDE'::text,
            'ROLLBACK'::text,
            'APPROVE_MIGRATION'::text,
            'OTHER'::text
        ])),
    actor text not null,
    object_type text,
    object_ref text,
    rationale text,
    authority_context jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create table audit.schema_versions (
    id uuid primary key default gen_random_uuid(),
    schema_version text not null unique,
    migration_name text not null,
    status text not null
        check (status = any (array[
            'CANDIDATE'::text,
            'APPLIED'::text,
            'SUPERSEDED'::text,
            'ROLLED_BACK'::text
        ])),
    applied_at timestamptz,
    migration_hash text
        check (
            migration_hash is null
            or migration_hash ~ '^[0-9a-fA-F]{64}$'::text
        ),
    metadata jsonb not null default '{}'::jsonb
);

create table canonical.sources (
    id uuid primary key default gen_random_uuid(),
    source_key text not null unique,
    institution text,
    repository text,
    title text not null,
    author text,
    document_date date,
    event_date_start date,
    event_date_end date,
    page text,
    folio text,
    collection text,
    fondo text,
    serie text,
    signatura text,
    document_type text,
    source_uri text,
    acquired_at timestamptz,
    raw_sha256 text
        check (
            raw_sha256 is null
            or raw_sha256 ~ '^[0-9a-fA-F]{64}$'::text
        ),
    byte_size bigint
        check (byte_size is null or byte_size >= 0),
    mime_type text,
    custodian text,
    provenance_chain jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    constraint source_event_date_order
        check (
            event_date_end is null
            or event_date_start is null
            or event_date_end >= event_date_start
        )
);

create table canonical.entities (
    id uuid primary key default gen_random_uuid(),
    entity_type text not null,
    canonical_name text not null,
    valid_from date,
    valid_to date,
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    constraint entity_valid_date_order
        check (
            valid_to is null
            or valid_from is null
            or valid_to >= valid_from
        )
);

create table canonical.events (
    id uuid primary key default gen_random_uuid(),
    event_type text not null,
    title text not null,
    event_date_start date,
    event_date_end date,
    place_entity_id uuid
        references canonical.entities(id),
    description text,
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    constraint event_date_order
        check (
            event_date_end is null
            or event_date_start is null
            or event_date_end >= event_date_start
        )
);

create table canonical.claims (
    id uuid primary key default gen_random_uuid(),
    claim_kind text not null
        check (claim_kind = any (array[
            'FACT'::text,
            'SOURCE_CLAIM'::text,
            'INFERENCE'::text,
            'HYPOTHESIS'::text,
            'OPEN_QUESTION'::text
        ])),
    proposition text not null,
    event_id uuid references canonical.events(id),
    event_date_start date,
    event_date_end date,
    confidence numeric(4,3)
        check (
            confidence is null
            or (confidence >= 0::numeric and confidence <= 1::numeric)
        ),
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    constraint claim_event_date_order
        check (
            event_date_end is null
            or event_date_start is null
            or event_date_end >= event_date_start
        )
);

create table canonical.documents (
    id uuid primary key default gen_random_uuid(),
    source_id uuid not null
        references canonical.sources(id),
    title text not null,
    document_type text,
    document_date date,
    storage_uri text,
    raw_sha256 text
        check (
            raw_sha256 is null
            or raw_sha256 ~ '^[0-9a-fA-F]{64}$'::text
        ),
    byte_size bigint
        check (byte_size is null or byte_size >= 0),
    mime_type text,
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now()
);

create table canonical.document_pages (
    id uuid primary key default gen_random_uuid(),
    document_id uuid not null
        references canonical.documents(id) on delete restrict,
    page_key text not null,
    page_number integer
        check (page_number is null or page_number > 0),
    folio text,
    extracted_text text,
    extraction_method text,
    extraction_version text,
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    unique (document_id, page_key)
);

create table canonical.entity_aliases (
    id uuid primary key default gen_random_uuid(),
    entity_id uuid not null
        references canonical.entities(id) on delete restrict,
    alias text not null,
    valid_from date,
    valid_to date,
    source_id uuid references canonical.sources(id),
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now(),
    constraint alias_valid_date_order
        check (
            valid_to is null
            or valid_from is null
            or valid_to >= valid_from
        )
);

create table canonical.evidence_items (
    id uuid primary key default gen_random_uuid(),
    claim_id uuid not null
        references canonical.claims(id) on delete restrict,
    source_id uuid not null
        references canonical.sources(id) on delete restrict,
    document_page_id uuid
        references canonical.document_pages(id) on delete restrict,
    support_type text not null
        check (support_type = any (array[
            'SUPPORTS'::text,
            'REFUTES'::text,
            'CONTEXT'::text
        ])),
    evidentiary_role text,
    location_note text,
    notes text,
    metadata jsonb not null default '{}'::jsonb,
    promotion_decision_id uuid not null
        references audit.human_decisions(id),
    created_at timestamptz not null default now()
);

insert into audit.schema_versions (
    schema_version,
    migration_name,
    status,
    migration_hash,
    metadata,
    applied_at
)
values (
    '1.5.0',
    'galia_monitoring_surface_v1',
    'APPLIED',
    null,
    '{"ci_contract_fixture":true,"production_data":false}'::jsonb,
    now()
);
