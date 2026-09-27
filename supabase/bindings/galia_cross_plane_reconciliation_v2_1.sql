-- GALIA cross-plane reconciliation v2.1
-- DML-only reconciliation. No schema DDL and no authority transfer.
-- Promotion tooling MUST replace __PROMOTED_MAIN_COMMIT__ with the exact
-- 40-lower-hex GitHub merge commit created by the promotion PR.

begin;

do $$
begin
    if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$' then
        raise exception 'GALIA reconciliation template must be rendered with exact promoted main commit';
    end if;
end
$$;

do $$
declare
    v_latest_schema text;
    v_authorities bigint;
    v_source_truth bigint;
    v_edges bigint;
begin
    select schema_version into v_latest_schema
    from audit.schema_versions
    where status = 'APPLIED'
    order by applied_at desc nulls last
    limit 1;

    if v_latest_schema <> '1.5.0' then
        raise exception 'FAIL_CLOSED latest schema % != 1.5.0', v_latest_schema;
    end if;

    select count(*) into v_authorities
    from audit.cross_plane_bindings
    where status = 'ACTIVE' and canonical_authority;

    select count(*) into v_source_truth
    from audit.cross_plane_bindings
    where status = 'ACTIVE' and source_of_truth;

    if v_authorities <> 1 or v_source_truth <> 1 then
        raise exception 'FAIL_CLOSED authority count % source-of-truth count %', v_authorities, v_source_truth;
    end if;

    select count(*) into v_edges
    from audit.cross_plane_binding_edges
    where integration_set_id = 'GALIA-CROSS-PLANE-2026-09-26-001';

    if v_edges <> 4 then
        raise exception 'FAIL_CLOSED edge count % != 4', v_edges;
    end if;

    if not exists (
        select 1
        from information_schema.views
        where table_schema = 'monitor'
          and table_name = 'galia_overview_v1'
    ) then
        raise exception 'FAIL_CLOSED monitoring surface absent';
    end if;

    if not exists (
        select 1
        from audit.cross_plane_bindings
        where binding_key = 'hf8-model-artifact'
          and provider = 'HUGGING_FACE'
          and authority_role = 'ML_ARTIFACT_PLANE'
          and object_ref = 'Junitos/galia-2'
          and revision = 'main'
          and status = 'ACTIVE'
    ) then
        raise exception 'FAIL_CLOSED HF8 binding drift';
    end if;

    if not exists (
        select 1
        from audit.cross_plane_bindings
        where binding_key = 'hf9-evidence-schema'
          and provider = 'HUGGING_FACE'
          and authority_role = 'EVIDENCE_ARTIFACT_PLANE'
          and object_ref = 'Junitos/galia-2-evidence'
          and revision = 'main'
          and status = 'ACTIVE'
    ) then
        raise exception 'FAIL_CLOSED HF9 binding drift';
    end if;
end
$$;

do $$
declare
    n bigint;
begin
    update audit.cross_plane_bindings
    set
        revision = '__PROMOTED_MAIN_COMMIT__',
        metadata = metadata || jsonb_build_object(
            'previous_revision', revision,
            'reconciliation_id', 'GALIA-CROSS-PLANE-RECONCILIATION-2026-09-27-001',
            'reconciled_schema_version', '1.5.0',
            'authority_transfer', false,
            'promotion_receipt_must_bind_merge_commit', true
        )
    where binding_key = 'github-control-plane-main'
      and provider = 'GITHUB'
      and authority_role = 'CONTROL_PLANE'
      and canonical_authority
      and source_of_truth
      and status = 'ACTIVE'
      and revision = '25db17fa583d1561d746ee7d33407d3684ee561d';

    get diagnostics n = row_count;
    if n <> 1 then
        raise exception 'FAIL_CLOSED github binding rows updated % != 1', n;
    end if;

    update audit.cross_plane_bindings
    set
        revision = 'schema:1.5.0',
        metadata = metadata || jsonb_build_object(
            'previous_revision', revision,
            'reconciliation_id', 'GALIA-CROSS-PLANE-RECONCILIATION-2026-09-27-001',
            'monitoring_candidate_id', 'GALIA-MONITORING-CANDIDATE-v1.6',
            'monitoring_merge_commit', 'cf7a935c24729eba0b23dbf8c6f8cc61c43005be',
            'authority_transfer', false
        )
    where binding_key = 'supabase-data-plane'
      and provider = 'SUPABASE'
      and authority_role = 'DATA_PLANE'
      and object_ref = 'galia-cangrejos:nzoviwitcqmsacwiizhh'
      and not canonical_authority
      and not source_of_truth
      and status = 'ACTIVE'
      and revision = 'schema:1.4.0';

    get diagnostics n = row_count;
    if n <> 1 then
        raise exception 'FAIL_CLOSED supabase binding rows updated % != 1', n;
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
    'PROMOTE',
    'human:user',
    'CROSS_PLANE_RECONCILIATION',
    'GALIA-CROSS-PLANE-RECONCILIATION-2026-09-27-001',
    'Human promotion reconciles live GitHub control-plane revision and Supabase schema binding without transferring authority.',
    jsonb_build_object(
        'candidate_id', 'GALIA-CROSS-PLANE-RECONCILIATION-v2.1',
        'canonical_authority_provider', 'GITHUB',
        'github_repository', 'riosriosje-prog/test-model-thing',
        'github_promoted_main_commit', '__PROMOTED_MAIN_COMMIT__',
        'supabase_project_id', 'nzoviwitcqmsacwiizhh',
        'supabase_schema_revision', 'schema:1.5.0',
        'integration_set_id', 'GALIA-CROSS-PLANE-2026-09-26-001',
        'authority_transfer', false,
        'hf_bindings_changed', false,
        'edge_graph_changed', false,
        'schema_ddl', false
    )
);

do $$
declare
    v_authorities bigint;
    v_source_truth bigint;
    v_edges bigint;
begin
    if not exists (
        select 1
        from audit.cross_plane_bindings
        where binding_key = 'github-control-plane-main'
          and provider = 'GITHUB'
          and authority_role = 'CONTROL_PLANE'
          and revision = '__PROMOTED_MAIN_COMMIT__'
          and canonical_authority
          and source_of_truth
          and status = 'ACTIVE'
    ) then
        raise exception 'FAIL_CLOSED reconciled GitHub binding absent';
    end if;

    if not exists (
        select 1
        from audit.cross_plane_bindings
        where binding_key = 'supabase-data-plane'
          and provider = 'SUPABASE'
          and authority_role = 'DATA_PLANE'
          and object_ref = 'galia-cangrejos:nzoviwitcqmsacwiizhh'
          and revision = 'schema:1.5.0'
          and not canonical_authority
          and not source_of_truth
          and status = 'ACTIVE'
    ) then
        raise exception 'FAIL_CLOSED reconciled Supabase binding absent';
    end if;

    select count(*) into v_authorities
    from audit.cross_plane_bindings
    where status = 'ACTIVE' and canonical_authority;

    select count(*) into v_source_truth
    from audit.cross_plane_bindings
    where status = 'ACTIVE' and source_of_truth;

    select count(*) into v_edges
    from audit.cross_plane_binding_edges
    where integration_set_id = 'GALIA-CROSS-PLANE-2026-09-26-001';

    if v_authorities <> 1 or v_source_truth <> 1 or v_edges <> 4 then
        raise exception 'FAIL_CLOSED postcondition authority=% source_truth=% edges=%',
            v_authorities, v_source_truth, v_edges;
    end if;
end
$$;

commit;
