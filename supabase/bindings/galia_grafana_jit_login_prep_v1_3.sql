-- GALIA Grafana JIT LOGIN preparation v1.3
-- Scope: enable LOGIN on galia_grafana_ro WITHOUT a persistent Postgres password.
-- Temporary Access/JIT mapping is external and remains required after this transaction.
-- Promotion tooling MUST render:
--   __PROMOTED_MAIN_COMMIT__  exact resulting main merge commit
--   __CANDIDATE_HEAD__        exact human-authorized candidate head
--   __CANDIDATE_SET_SHA256__  exact remote candidate-set SHA-256

begin;

do $$
declare
  v_latest_schema text;
  v_authorities bigint;
  v_source_truth bigint;
  v_edges bigint;
  v_monitor_views bigint;
  v_security_barrier_views bigint;
  v_settings bigint;
  v_unexpected_usable_schemas bigint;
  v_public_selectable_relations bigint;
  v_monitor_selectable_relations bigint;
  v_role record;
begin
  if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$' then
    raise exception 'FAIL_CLOSED promoted main commit token unresolved or invalid';
  end if;

  if '__CANDIDATE_HEAD__' !~ '^[0-9a-f]{40}$' then
    raise exception 'FAIL_CLOSED candidate head token unresolved or invalid';
  end if;

  if '__CANDIDATE_SET_SHA256__' !~ '^[0-9a-f]{64}$' then
    raise exception 'FAIL_CLOSED candidate-set SHA-256 token unresolved or invalid';
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
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
      and provider='GITHUB'
      and authority_role='CONTROL_PLANE'
      and revision='da889048edb339b8e9995a7c27edafb53e0221ee'
      and canonical_authority
      and source_of_truth
      and status='ACTIVE'
      and metadata->>'credential_activation_state'='HOLD'
  ) then
    raise exception 'FAIL_CLOSED GitHub control-plane/HOLD baseline mismatch';
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

  if exists (
    select 1 from audit.human_decisions
    where object_ref='GALIA-GRAFANA-JIT-LOGIN-PREP-2026-09-27-001'
  ) then
    raise exception 'FAIL_CLOSED JIT LOGIN preparation receipt already exists';
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
    raise exception 'FAIL_CLOSED pre-JIT role contract mismatch';
  end if;

  if not exists (
    select 1 from pg_authid
    where rolname='galia_grafana_ro'
      and rolpassword is null
  ) then
    raise exception 'FAIL_CLOSED pre-JIT persistent password is present';
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

  select count(*) into v_settings
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

  if v_settings <> 5 then
    raise exception 'FAIL_CLOSED Grafana role settings mismatch count=%', v_settings;
  end if;

  select count(*) into v_monitor_views
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='monitor' and c.relkind='v';

  select count(*) into v_security_barrier_views
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='monitor'
    and c.relkind='v'
    and coalesce(c.reloptions, '{}'::text[]) @> array['security_barrier=true'];

  if v_monitor_views <> 5 or v_security_barrier_views <> 5 then
    raise exception 'FAIL_CLOSED monitor surface drift views=% security_barrier=%',
      v_monitor_views, v_security_barrier_views;
  end if;

  if not has_schema_privilege('galia_grafana_ro','monitor','USAGE')
     or not has_table_privilege('galia_grafana_ro','monitor.galia_overview_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.ingest_health_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.authority_chain_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.research_pipeline_v1','SELECT')
     or not has_table_privilege('galia_grafana_ro','monitor.control_plane_topology_v1','SELECT') then
    raise exception 'FAIL_CLOSED Grafana monitor access incomplete';
  end if;

  select count(*) into v_unexpected_usable_schemas
  from pg_namespace
  where nspname not like 'pg_%'
    and nspname <> 'information_schema'
    and nspname not in ('monitor','public')
    and has_schema_privilege('galia_grafana_ro', nspname, 'USAGE');

  select count(*) into v_public_selectable_relations
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='public'
    and c.relkind in ('r','p','v','m','f')
    and has_table_privilege('galia_grafana_ro', c.oid, 'SELECT');

  select count(*) into v_monitor_selectable_relations
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='monitor'
    and c.relkind in ('r','p','v','m','f')
    and has_table_privilege('galia_grafana_ro', c.oid, 'SELECT');

  if v_unexpected_usable_schemas <> 0
     or v_public_selectable_relations <> 0
     or v_monitor_selectable_relations <> 5 then
    raise exception 'FAIL_CLOSED Grafana effective schema surface drift unexpected_schemas=% public_selectable=% monitor_selectable=%',
      v_unexpected_usable_schemas, v_public_selectable_relations, v_monitor_selectable_relations;
  end if;

  if has_schema_privilege('galia_grafana_ro','audit','USAGE')
     or has_schema_privilege('galia_grafana_ro','staging','USAGE')
     or has_schema_privilege('galia_grafana_ro','canonical','USAGE')
     or has_schema_privilege('galia_grafana_ro','derived','USAGE')
     or has_table_privilege('galia_grafana_ro','audit.schema_versions','SELECT')
     or has_table_privilege('galia_grafana_ro','staging.ingest_batches','SELECT')
     or has_table_privilege('galia_grafana_ro','canonical.sources','SELECT')
     or has_table_privilege('galia_grafana_ro','derived.artifacts','SELECT') then
    raise exception 'FAIL_CLOSED Grafana GALIA data-plane access leakage';
  end if;
end $$;

alter role galia_grafana_ro login;

do $$
declare
  n bigint;
begin
  update audit.cross_plane_bindings
  set
    revision='__PROMOTED_MAIN_COMMIT__',
    metadata=metadata || jsonb_build_object(
      'previous_revision', revision,
      'refresh_reason', 'GALIA_GRAFANA_JIT_LOGIN_PREPARATION',
      'credential_activation_state', 'JIT_MAPPING_REQUIRED',
      'credential_mode', 'TEMPORARY_ACCESS_JIT',
      'persistent_password', false,
      'jit_mapping_configured', false,
      'ssl_enforcement_verified', false,
      'ssl_enforcement_required_before_jit_mapping', true,
      'grafana_datasource_configured', false,
      'authority_transfer', false
    )
  where binding_key='github-control-plane-main'
    and provider='GITHUB'
    and authority_role='CONTROL_PLANE'
    and revision='da889048edb339b8e9995a7c27edafb53e0221ee'
    and canonical_authority
    and source_of_truth
    and status='ACTIVE'
    and metadata->>'credential_activation_state'='HOLD';

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
  'EXTERNAL_SERVICE_JIT_LOGIN_PREPARATION',
  'GALIA-GRAFANA-JIT-LOGIN-PREP-2026-09-27-001',
  'Human promotion enables LOGIN without a persistent Postgres password for the existing read-only Grafana identity. Temporary Access/JIT mapping and Grafana datasource configuration remain external gates.',
  jsonb_build_object(
    'candidate_id','GALIA-GRAFANA-JIT-LOGIN-CANDIDATE-v1.3',
    'candidate_base_commit','da889048edb339b8e9995a7c27edafb53e0221ee',
    'candidate_head','__CANDIDATE_HEAD__',
    'candidate_set_sha256','__CANDIDATE_SET_SHA256__',
    'promoted_main_commit','__PROMOTED_MAIN_COMMIT__',
    'service','GRAFANA',
    'database_role','galia_grafana_ro',
    'login_enabled',true,
    'persistent_password',false,
    'credential_mode','TEMPORARY_ACCESS_JIT',
    'jit_mapping_configured',false,
    'jit_mapping_required',true,
    'jit_option','true',
    'ssl_enforcement_verified',false,
    'ssl_enforcement_required_before_jit_mapping',true,
    'grafana_datasource_configured',false,
    'activation_complete',false,
    'github_binding_refreshed',true,
    'authority_transfer',false
  )
);

do $$
declare
  v_role record;
  v_settings bigint;
  v_unexpected_usable_schemas bigint;
  v_public_selectable_relations bigint;
  v_monitor_selectable_relations bigint;
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
    raise exception 'FAIL_CLOSED post-JIT role contract mismatch';
  end if;

  if not exists (
    select 1 from pg_authid
    where rolname='galia_grafana_ro'
      and rolpassword is null
  ) then
    raise exception 'FAIL_CLOSED post-JIT persistent password is present';
  end if;

  if (
    select count(*)
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    where parent.rolname='galia_grafana_ro'
       or member.rolname='galia_grafana_ro'
  ) <> 2 then
    raise exception 'FAIL_CLOSED post-JIT membership count mismatch';
  end if;

  select count(*) into v_settings
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

  if v_settings <> 5 then
    raise exception 'FAIL_CLOSED post-JIT role settings mismatch count=%', v_settings;
  end if;

  select count(*) into v_unexpected_usable_schemas
  from pg_namespace
  where nspname not like 'pg_%'
    and nspname <> 'information_schema'
    and nspname not in ('monitor','public')
    and has_schema_privilege('galia_grafana_ro', nspname, 'USAGE');

  select count(*) into v_public_selectable_relations
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='public'
    and c.relkind in ('r','p','v','m','f')
    and has_table_privilege('galia_grafana_ro', c.oid, 'SELECT');

  select count(*) into v_monitor_selectable_relations
  from pg_class c
  join pg_namespace n on n.oid=c.relnamespace
  where n.nspname='monitor'
    and c.relkind in ('r','p','v','m','f')
    and has_table_privilege('galia_grafana_ro', c.oid, 'SELECT');

  if not has_schema_privilege('galia_grafana_ro','monitor','USAGE')
     or v_unexpected_usable_schemas <> 0
     or v_public_selectable_relations <> 0
     or v_monitor_selectable_relations <> 5
     or has_schema_privilege('galia_grafana_ro','audit','USAGE')
     or has_schema_privilege('galia_grafana_ro','staging','USAGE')
     or has_schema_privilege('galia_grafana_ro','canonical','USAGE')
     or has_schema_privilege('galia_grafana_ro','derived','USAGE') then
    raise exception 'FAIL_CLOSED post-JIT effective schema surface drift';
  end if;

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
      and revision='__PROMOTED_MAIN_COMMIT__'
      and canonical_authority
      and source_of_truth
      and status='ACTIVE'
      and metadata->>'credential_activation_state'='JIT_MAPPING_REQUIRED'
      and metadata->>'credential_mode'='TEMPORARY_ACCESS_JIT'
      and metadata->>'persistent_password'='false'
      and metadata->>'jit_mapping_configured'='false'
  ) then
    raise exception 'FAIL_CLOSED GitHub binding/JIT state refresh absent';
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
end $$;

commit;
