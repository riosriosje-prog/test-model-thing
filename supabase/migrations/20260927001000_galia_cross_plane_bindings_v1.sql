-- GALIA 2.0 cross-plane integration registry v1
-- Additive only. Preserves audit.external_anchors and all historical anchors.

create table if not exists audit.cross_plane_bindings (
    id uuid primary key default gen_random_uuid(),
    integration_set_id text not null,
    binding_key text not null unique,
    provider text not null
        check (provider in ('GITHUB', 'HUGGING_FACE', 'SUPABASE')),
    authority_role text not null
        check (authority_role in (
            'CONTROL_PLANE',
            'ML_ARTIFACT_PLANE',
            'EVIDENCE_ARTIFACT_PLANE',
            'DATA_PLANE'
        )),
    object_ref text not null,
    revision text not null,
    object_path text,
    identity_sha256 text
        check (identity_sha256 is null or identity_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_authority boolean not null default false,
    source_of_truth boolean not null default false,
    status text not null default 'ACTIVE'
        check (status in ('ACTIVE', 'HOLD', 'HISTORICAL', 'SUPERSEDED')),
    metadata jsonb not null default '{}'::jsonb,
    supersedes_binding_id uuid
        references audit.cross_plane_bindings(id),
    created_by text not null,
    created_at timestamptz not null default now(),
    check (
        not canonical_authority
        or (provider = 'GITHUB' and authority_role = 'CONTROL_PLANE')
    ),
    check (
        not source_of_truth
        or (provider = 'GITHUB' and authority_role = 'CONTROL_PLANE')
    )
);

create unique index if not exists cross_plane_bindings_exact_identity_uq
on audit.cross_plane_bindings (
    integration_set_id,
    provider,
    object_ref,
    revision,
    coalesce(object_path, '')
);

create table if not exists audit.cross_plane_binding_edges (
    id uuid primary key default gen_random_uuid(),
    integration_set_id text not null,
    from_binding_id uuid not null
        references audit.cross_plane_bindings(id),
    to_binding_id uuid not null
        references audit.cross_plane_bindings(id),
    relation text not null
        check (relation in (
            'CONTROLS',
            'BINDS_ARTIFACT',
            'BINDS_DATA_PLANE',
            'DISTRIBUTES_SCHEMA_TO'
        )),
    metadata jsonb not null default '{}'::jsonb,
    created_by text not null,
    created_at timestamptz not null default now(),
    unique (integration_set_id, from_binding_id, to_binding_id, relation),
    check (from_binding_id <> to_binding_id)
);

alter table audit.cross_plane_bindings enable row level security;
alter table audit.cross_plane_binding_edges enable row level security;

revoke all on table audit.cross_plane_bindings from anon, authenticated;
revoke all on table audit.cross_plane_binding_edges from anon, authenticated;

comment on table audit.cross_plane_bindings is
'GALIA cross-plane identity registry. Records exact GitHub, Hugging Face, and Supabase identities without transferring canonical authority away from GitHub.';

comment on table audit.cross_plane_binding_edges is
'GALIA cross-plane relationship registry. Edges express control/artifact/data-plane bindings only; they do not promote or transfer authority.';

insert into audit.schema_versions (
    schema_version,
    migration_name,
    status,
    migration_hash,
    metadata,
    applied_at
)
values (
    '1.4.0',
    'galia_cross_plane_bindings_v1',
    'APPLIED',
    null,
    jsonb_build_object(
        'additive', true,
        'preserves_external_anchors', true,
        'canonical_authority_provider', 'GITHUB'
    ),
    now()
)
on conflict (schema_version) do nothing;
