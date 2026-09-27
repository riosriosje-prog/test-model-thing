-- GALIA Grafana LOGIN activation v1.0
-- Runtime secret token __GRAFANA_PASSWORD__ MUST be substituted in memory only.
-- Allowed secret alphabet: [A-Za-z0-9_-], length 32..64.
-- The secret MUST NOT be written to Git, receipts, comments, or logs.

begin;

do $$
declare
  v_latest_schema text;
  v_authorities bigint;
  v_source_truth bigint;
  v_edges bigint;
  v_role record;
  v_setting_count bigint;
begin
  if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$' then
    raise exception 'FAIL_CLOSED promoted main commit token is unresolved or invalid';
  end if;

  if '__CANDIDATE_HEAD__' !~ '^[0-9a-f]{40}$' then
    raise exception 'FAIL_CLOSED candidate head token is unresolved or invalid';
  end if;

  if '__CANDIDATE_SET_SHA256__' !~ '^[0-9a-f]{64}$' then
    raise exception 'FAIL_CLOSED candidate-set SHA-256 token is unresolved or invalid';
  end if;

  if '__GRAFANA_PASSWORD__' !~ '^[A-Za-z0-9_-]{32,64}$' then
    raise exception 'FAIL_CLOSED Grafana password token is unresolved or violates secret contract';
  end if;

  select schema_version into v_latest_schema
  from audit.schema_versions
  where status='APPLIED'
  order by applied_at desc nulls last
  limit 1;

  if v_latest_schema <> '1.5.0' then
    raise exception 'FAIL_CLOSED latest schema % != 1.5.0', v_latest_schema;
  end if;

  if not exists (
    select 1
    from audit.human_decisions
    where decision_type='PROMOTE'
      and object_type='EXTERNAL_SERVICE_IDENTITY'
      and object_ref='GALIA-GRAFANA-READER-IDENTITY-2026-09-27-001'
      and authority_context->>'candidate_id'='GALIA-GRAFANA-READER-CANDIDATE-v1.3'
      and authority_context->>'promoted_main_commit'='b072f20362ad753375f3f4291c7b8607fe451a12'
      and authority_context->>'database_role'='galia_grafana_ro'
      and authority_context->>'login_enabled'='false'
      and authority_context->>'secret_material_persisted'='false'
  ) then
    raise exception 'FAIL_CLOSED predecessor identity receipt mismatch';
  end if;

  if exists (
    select 1
    from audit.human_decisions
    where object_ref='GALIA-GRAFANA-LOGIN-ACTIVATION-2026-09-27-001'
  ) then
    raise exception 'FAIL_CLOSED activation receipt already exists';
  end if;

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
      and provider='GITHUB'
      and authority_role='CONTROL_PLANE'
      and revision='b072f20362ad753375f3f4291c7b8607fe451a12'
      and canonical_authority
      and source_of_truth
      and status='ACTIVE'
  ) then
    raise exception 'FAIL_CLOSED GitHub control-plane baseline mismatch';
  end if;

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='supabase-data-plane'
      and provider='SUPABASE'
      and authority_role='DATA_PLANE'
      and revision='schema:1.5.0'
      and not canonical_authority
      and not source_of_truth
      and status='ACTIVE'
  ) then
    raise exception 'FAIL_CLOSED Supabase data-plane baseline mismatch';
  end if;

  select count(*) into v_authorities
  from audit.cross_plane_bindings
  where status='ACTIVE' and canonical_authority;

  select count(*) into v_source_truth
  from audit.cross_plane_bindings
  where status='ACTIVE' and source_of_truth;

  select count(*) into v_edges
  from audit.cross_plane_binding_edges
  where integration_set_id='GALIA-CROSS-PLANE-2026-09-26-001';

  if v_authorities <> 1 or v_source_truth <> 1 or v_edges <> 4 then
    raise exception 'FAIL_CLOSED control-plane invariants authority=% source_truth=% edges=%',
      v_authorities, v_source_truth, v_edges;
  end if;

  select
    rolcanlogin,
    rolinherit,
    rolsuper,
    rolcreatedb,
    rolcreaterole,
    rolbypassrls,
    rolconnlimit
  into v_role
  from pg_roles
  where rolname='galia_grafana_ro';

  if not found then
    raise exception 'FAIL_CLOSED galia_grafana_ro missing';
  end if;

  if v_role.rolcanlogin
     or not v_role.rolinherit
     or v_role.rolsuper
     or v_role.rolcreatedb
     or v_role.rolcreaterole
     or v_role.rolbypassrls
     or v_role.rolconnlimit <> 5 then
    raise exception 'FAIL_CLOSED pre-activation role contract mismatch';
  end if;

  if (
    select count(*)
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    where parent.rolname='galia_grafana_ro'
       or member.rolname='galia_grafana_ro'
  ) <> 2 then
    raise exception 'FAIL_CLOSED unexpected Grafana membership count';
  end if;

  if not exists (
    select 1
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    join pg_roles grantor on grantor.oid=m.grantor
    where parent.rolname='galia_grafana_ro'
      and member.rolname='postgres'
      and grantor.rolname='supabase_admin'
      and m.admin_option
      and not m.inherit_option
      and not m.set_option
  ) then
    raise exception 'FAIL_CLOSED platform admin membership contract mismatch';
  end if;

  if not exists (
    select 1
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    where parent.rolname='galia_monitor_ro'
      and member.rolname='galia_grafana_ro'
      and not m.admin_option
      and m.inherit_option
      and not m.set_option
  ) then
    raise exception 'FAIL_CLOSED monitor inheritance membership contract mismatch';
  end if;

  select count(*) into v_setting_count
  from pg_db_role_setting s
  join pg_roles r on r.oid=s.setrole
  cross join lateral unnest(s.setconfig) cfg
  where r.rolname='galia_grafana_ro'
    and cfg in (
      'default_transaction_read_only=on',
      'idle_in_transaction_session_timeout=30s',
      'lock_timeout=5s',
      'search_path=monitor, pg_catalog',
      'statement_timeout=30s'
    );

  if v_setting_count <> 5 then
    raise exception 'FAIL_CLOSED Grafana role settings mismatch count=%', v_setting_count;
  end if;

  if not has_schema_privilege('galia_grafana_ro','monitor','USAGE')
     or not has_table_privilege('galia_grafana_ro','monitor.galia_overview_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.ingest_health_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.authority_chain_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.research_pipeline_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.control_plane_topology_v1','SELECT') then
    raise exception 'FAIL_CLOSED Grafana monitor access incomplete';
  end if;

  if has_schema_privilege('galia_grafana_ro','audit','USAGE')
     or has_schema_privilege('galia_grafana_ro','staging','USAGE')
     or has_schema_privilege('galia_grafana_ro','canonical','USAGE')
     or has_table_privilege('galia_grafana_ro','audit.schema_versions','SELECT')
     or has_table_privilege('galia_grafana_ro','staging.ingest_batches','SELECT')
     or has_table_privilege('galia_grafana_ro','canonical.sources','SELECT') then
    raise exception 'FAIL_CLOSED Grafana source-plane access leakage';
  end if;
end $$;

alter role galia_grafana_ro
  login
  password '__GRAFANA_PASSWORD__';

do $$
declare
  n bigint;
begin
  update audit.cross_plane_bindings
  set
    revision='__PROMOTED_MAIN_COMMIT__',
    metadata=metadata || jsonb_build_object(
      'previous_revision', revision,
      'refresh_reason', 'GALIA_GRAFANA_LOGIN_ACTIVATION',
      'grafana_activation_candidate_id', 'GALIA-GRAFANA-ACTIVATION-CANDIDATE-v1.0',
      'authority_transfer', false
    )
  where binding_key='github-control-plane-main'
    and provider='GITHUB'
    and authority_role='CONTROL_PLANE'
    and revision='b072f20362ad753375f3f4291c7b8607fe451a12'
    and canonical_authority
    and source_of_truth
    and status='ACTIVE';

  get diagnostics n = row_count;
  if n <> 1 then
    raise exception 'FAIL_CLOSED GitHub binding rows updated % != 1', n;
  end if;
end $$;

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
  'EXTERNAL_SERVICE_CREDENTIAL_ACTIVATION',
  'GALIA-GRAFANA-LOGIN-ACTIVATION-2026-09-27-001',
  'Human promotion activates LOGIN for the pre-existing read-only Grafana identity. Secret material is supplied at runtime and omitted from persistent receipts.',
  jsonb_build_object(
    'candidate_id','GALIA-GRAFANA-ACTIVATION-CANDIDATE-v1.0',
    'candidate_base_commit','b072f20362ad753375f3f4291c7b8607fe451a12',
    'candidate_head','__CANDIDATE_HEAD__',
    'candidate_set_sha256','__CANDIDATE_SET_SHA256__',
    'promoted_main_commit','__PROMOTED_MAIN_COMMIT__',
    'service','GRAFANA',
    'database_role','galia_grafana_ro',
    'login_enabled',true,
    'secret_source','RUNTIME_ONLY',
    'secret_material_persisted',false,
    'secret_derived_hash_persisted',false,
    'grafana_datasource_configured',false,
    'github_binding_refreshed',true,
    'grafana_write_authority',false,
    'authority_transfer',false
  )
);

do $$
declare
  v_role record;
  v_setting_count bigint;
  v_authorities bigint;
  v_source_truth bigint;
  v_edges bigint;
begin
  select
    rolcanlogin,
    rolinherit,
    rolsuper,
    rolcreatedb,
    rolcreaterole,
    rolbypassrls,
    rolconnlimit
  into v_role
  from pg_roles
  where rolname='galia_grafana_ro';

  if not v_role.rolcanlogin
     or not v_role.rolinherit
     or v_role.rolsuper
     or v_role.rolcreatedb
     or v_role.rolcreaterole
     or v_role.rolbypassrls
     or v_role.rolconnlimit <> 5 then
    raise exception 'FAIL_CLOSED post-activation role contract mismatch';
  end if;

  if (
    select count(*)
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    where parent.rolname='galia_grafana_ro'
       or member.rolname='galia_grafana_ro'
  ) <> 2 then
    raise exception 'FAIL_CLOSED post-activation membership count mismatch';
  end if;

  select count(*) into v_setting_count
  from pg_db_role_setting s
  join pg_roles r on r.oid=s.setrole
  cross join lateral unnest(s.setconfig) cfg
  where r.rolname='galia_grafana_ro'
    and cfg in (
      'default_transaction_read_only=on',
      'idle_in_transaction_session_timeout=30s',
      'lock_timeout=5s',
      'search_path=monitor, pg_catalog',
      'statement_timeout=30s'
    );

  if v_setting_count <> 5 then
    raise exception 'FAIL_CLOSED post-activation role settings mismatch count=%', v_setting_count;
  end if;

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
      and revision='__PROMOTED_MAIN_COMMIT__'
      and canonical_authority
      and source_of_truth
      and status='ACTIVE'
  ) then
    raise exception 'FAIL_CLOSED GitHub binding refresh absent';
  end if;

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='supabase-data-plane'
      and revision='schema:1.5.0'
      and not canonical_authority
      and not source_of_truth
      and status='ACTIVE'
  ) then
    raise exception 'FAIL_CLOSED Supabase binding changed unexpectedly';
  end if;

  select count(*) into v_authorities
  from audit.cross_plane_bindings
  where status='ACTIVE' and canonical_authority;

  select count(*) into v_source_truth
  from audit.cross_plane_bindings
  where status='ACTIVE' and source_of_truth;

  select count(*) into v_edges
  from audit.cross_plane_binding_edges
  where integration_set_id='GALIA-CROSS-PLANE-2026-09-26-001';

  if v_authorities <> 1 or v_source_truth <> 1 or v_edges <> 4 then
    raise exception 'FAIL_CLOSED postcondition authority=% source_truth=% edges=%',
      v_authorities, v_source_truth, v_edges;
  end if;

  if not has_schema_privilege('galia_grafana_ro','monitor','USAGE')
     or has_schema_privilege('galia_grafana_ro','audit','USAGE')
     or has_schema_privilege('galia_grafana_ro','staging','USAGE')
     or has_schema_privilege('galia_grafana_ro','canonical','USAGE') then
    raise exception 'FAIL_CLOSED post-activation privilege drift';
  end if;
end $$;

commit;
