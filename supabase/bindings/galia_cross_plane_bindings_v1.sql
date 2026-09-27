-- GALIA 2.0 cross-plane bindings v1
-- DML is intentionally separate from schema migration.
-- No generated UUID is hard-coded; IDs are resolved by binding_key.
-- IMPORTANT: promotion tooling MUST replace __PROMOTED_MAIN_COMMIT__
-- with the exact 40-hex GitHub merge commit before execution.

do $$
begin
    if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$' then
        raise exception 'GALIA cross-plane binding template must be rendered with the exact promoted GitHub main commit';
    end if;
end
$$;

insert into audit.human_decisions (
    decision_type,
    actor,
    object_type,
    object_ref,
    rationale,
    authority_context
)
values (
    'APPROVE_MIGRATION',
    'human:user',
    'CROSS_PLANE_INTEGRATION',
    'GALIA-CROSS-PLANE-2026-09-26-001',
    'Human promotion authorizes the GitHub/Hugging Face/Supabase integration fix only and does not transfer canonical authority.',
    jsonb_build_object(
        'canonical_authority_provider', 'GITHUB',
        'github_repository', 'riosriosje-prog/test-model-thing',
        'github_main_commit', '__PROMOTED_MAIN_COMMIT__',
        'trust_root_pointer_sha256', 'ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9'
    )
);

insert into audit.cross_plane_bindings (
    integration_set_id,
    binding_key,
    provider,
    authority_role,
    object_ref,
    revision,
    object_path,
    identity_sha256,
    canonical_authority,
    source_of_truth,
    status,
    metadata,
    created_by
)
values
(
    'GALIA-CROSS-PLANE-2026-09-26-001',
    'github-control-plane-main',
    'GITHUB',
    'CONTROL_PLANE',
    'riosriosje-prog/test-model-thing',
    '__PROMOTED_MAIN_COMMIT__',
    'main',
    null,
    true,
    true,
    'ACTIVE',
    jsonb_build_object(
        'promotion_receipt_must_bind_merge_commit', true,
        'release_authority_module_blob', '50e76bc36a5a77e71eb11ed70724973c5ffc62f2',
        'release_authority_test_blob', '9b73e0497f58f45e04668fc5650db0fd34642628',
        'trust_root_pointer_sha256', 'ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9',
        'trust_root_v8_sha256', '7aa0d35cdd6b3746c43f0cfd379fdb78e50347b32ff8fa0092fd7ded6956e778',
        'global_master_sqlite_sha256', '9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354'
    ),
    'galia-integration-fix'
),
(
    'GALIA-CROSS-PLANE-2026-09-26-001',
    'hf8-model-artifact',
    'HUGGING_FACE',
    'ML_ARTIFACT_PLANE',
    'Junitos/galia-2',
    'main',
    'weights/hf8-retrain-v0.2-4k',
    '3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c',
    false,
    false,
    'ACTIVE',
    jsonb_build_object(
        'payload_bytes', 70716981,
        'manifest_sha256', 'a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2',
        'promotion_scope', 'HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY',
        'classification', 'GALIA_CURRENT_BOUND',
        'quality_gate', 'PASS',
        'live_repo_verified', true
    ),
    'galia-integration-fix'
),
(
    'GALIA-CROSS-PLANE-2026-09-26-001',
    'hf9-evidence-schema',
    'HUGGING_FACE',
    'EVIDENCE_ARTIFACT_PLANE',
    'Junitos/galia-2-evidence',
    'main',
    '/',
    '1a2545f83a3e6fc0c7f59fad11d7237c67781216123fd985fd56088cdfdc001e',
    false,
    false,
    'ACTIVE',
    jsonb_build_object(
        'source_sha', '4a6b5862ae7b86f9db0d469e1a52b5a751de9a58',
        'schema_surface', 'PROMOTED',
        'evidence_records', 0,
        'source_images', 0,
        'raw_evidence_bytes', 0,
        'live_repo_verified', true
    ),
    'galia-integration-fix'
),
(
    'GALIA-CROSS-PLANE-2026-09-26-001',
    'supabase-data-plane',
    'SUPABASE',
    'DATA_PLANE',
    'galia-cangrejos:nzoviwitcqmsacwiizhh',
    'schema:1.4.0',
    null,
    null,
    false,
    false,
    'ACTIVE',
    jsonb_build_object(
        'project_id', 'nzoviwitcqmsacwiizhh',
        'project_name', 'galia-cangrejos',
        'region', 'us-east-1',
        'postgres_version', '17.6.1.166',
        'pre_fix_schema_version', '1.3.2',
        'pre_fix_migration_set_sha256', 'dfb2dbc9edd5881c2d4956ea5694a7629e1e7b68ebff57df3888974d3a7bd374'
    ),
    'galia-integration-fix'
)
on conflict (binding_key) do update
set
    integration_set_id = excluded.integration_set_id,
    provider = excluded.provider,
    authority_role = excluded.authority_role,
    object_ref = excluded.object_ref,
    revision = excluded.revision,
    object_path = excluded.object_path,
    identity_sha256 = excluded.identity_sha256,
    canonical_authority = excluded.canonical_authority,
    source_of_truth = excluded.source_of_truth,
    status = excluded.status,
    metadata = excluded.metadata;

insert into audit.cross_plane_binding_edges (
    integration_set_id,
    from_binding_id,
    to_binding_id,
    relation,
    metadata,
    created_by
)
select
    'GALIA-CROSS-PLANE-2026-09-26-001',
    source.id,
    target.id,
    edge.relation,
    edge.metadata,
    'galia-integration-fix'
from (
    values
      ('github-control-plane-main', 'hf8-model-artifact', 'BINDS_ARTIFACT',
       jsonb_build_object('authority_transfer', false)),
      ('github-control-plane-main', 'hf9-evidence-schema', 'BINDS_ARTIFACT',
       jsonb_build_object('authority_transfer', false)),
      ('github-control-plane-main', 'supabase-data-plane', 'BINDS_DATA_PLANE',
       jsonb_build_object('authority_transfer', false)),
      ('supabase-data-plane', 'hf9-evidence-schema', 'DISTRIBUTES_SCHEMA_TO',
       jsonb_build_object('evidence_data_migration', false, 'schema_surface_only', true))
) as edge(from_key, to_key, relation, metadata)
join audit.cross_plane_bindings source on source.binding_key = edge.from_key
join audit.cross_plane_bindings target on target.binding_key = edge.to_key
on conflict (integration_set_id, from_binding_id, to_binding_id, relation)
do update set metadata = excluded.metadata;
