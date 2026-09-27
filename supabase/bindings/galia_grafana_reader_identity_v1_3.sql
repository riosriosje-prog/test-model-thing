-- GALIA Grafana reader identity v1.3
-- Creates a NOLOGIN read-only service identity only.
-- External LOGIN activation and secret material remain separate.
-- Promotion tooling MUST render:
--   __PROMOTED_MAIN_COMMIT__  exact resulting main merge commit
--   __CANDIDATE_HEAD__        exact human-authorized candidate head
--   __CANDIDATE_SET_SHA256__  exact remote candidate-set SHA-256

begin;

do $$
declare
  v_latest_schema text;
  v_monitor_views bigint;
  v_security_barrier_views bigint;
  v_authorities bigint;
  v_source_truth bigint;
  v_edges bigint;
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
      and revision='1f82fe94deb9778194c9166e1ee063f6eab52657'
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

  if exists (select 1 from pg_roles where rolname='galia_grafana_ro') then
    raise exception 'FAIL_CLOSED galia_grafana_ro already exists';
  end if;

  if not exists (
    select 1
    from pg_roles
    where rolname='galia_monitor_ro'
      and not rolcanlogin
      and not rolinherit
      and not rolsuper
      and not rolcreatedb
      and not rolcreaterole
      and not rolbypassrls
  ) then
    raise exception 'FAIL_CLOSED galia_monitor_ro role contract mismatch';
  end if;

  if not has_schema_privilege('galia_monitor_ro','monitor','USAGE') then
    raise exception 'FAIL_CLOSED galia_monitor_ro lacks monitor USAGE';
  end if;

  if has_schema_privilege('galia_monitor_ro','audit','USAGE')
     or has_schema_privilege('galia_monitor_ro','staging','USAGE')
     or has_schema_privilege('galia_monitor_ro','canonical','USAGE') then
    raise exception 'FAIL_CLOSED galia_monitor_ro source-schema leakage';
  end if;

  if has_schema_privilege('public','monitor','USAGE')
     or has_schema_privilege('public','audit','USAGE')
     or has_schema_privilege('public','staging','USAGE')
     or has_schema_privilege('public','canonical','USAGE') then
    raise exception 'FAIL_CLOSED PUBLIC schema leakage';
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
    raise exception 'FAIL_CLOSED monitor view contract views=% security_barrier=%',
      v_monitor_views, v_security_barrier_views;
  end if;
end $$;

create role galia_grafana_ro
  nologin
  inherit
  nosuperuser
  nocreatedb
  nocreaterole
  nobypassrls
  connection limit 5;

grant galia_monitor_ro to galia_grafana_ro
  with inherit true, set false;

alter role galia_grafana_ro set search_path = monitor, pg_catalog;
alter role galia_grafana_ro set statement_timeout = '30s';
alter role galia_grafana_ro set lock_timeout = '5s';
alter role galia_grafana_ro set idle_in_transaction_session_timeout = '30s';
alter role galia_grafana_ro set default_transaction_read_only = on;

do $$
declare
  n bigint;
begin
  update audit.cross_plane_bindings
  set
    revision='__PROMOTED_MAIN_COMMIT__',
    metadata=metadata || jsonb_build_object(
      'previous_revision', revision,
      'refresh_reason', 'GALIA_GRAFANA_READER_IDENTITY_PROMOTION',
      'grafana_reader_candidate_id', 'GALIA-GRAFANA-READER-CANDIDATE-v1.3',
      'authority_transfer', false
    )
  where binding_key='github-control-plane-main'
    and provider='GITHUB'
    and authority_role='CONTROL_PLANE'
    and revision='1f82fe94deb9778194c9166e1ee063f6eab52657'
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
  'EXTERNAL_SERVICE_IDENTITY',
  'GALIA-GRAFANA-READER-IDENTITY-2026-09-27-001',
  'Human promotion authorizes creation of the NOLOGIN Grafana read-only database identity and refresh of the GitHub control-plane revision only. External activation remains separate.',
  jsonb_build_object(
    'candidate_id','GALIA-GRAFANA-READER-CANDIDATE-v1.3',
    'candidate_base_commit','1f82fe94deb9778194c9166e1ee063f6eab52657',
    'candidate_head','__CANDIDATE_HEAD__',
    'candidate_set_sha256','__CANDIDATE_SET_SHA256__',
    'promoted_main_commit','__PROMOTED_MAIN_COMMIT__',
    'service','GRAFANA',
    'database_role','galia_grafana_ro',
    'parent_role','galia_monitor_ro',
    'login_enabled',false,
    'secret_material_persisted',false,
    'activation_separate',true,
    'github_binding_refreshed',true,
    'grafana_write_authority',false,
    'authority_transfer',false
  )
);

do $$
declare
  v_role record;
  v_membership record;
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

  if v_role.rolcanlogin
     or not v_role.rolinherit
     or v_role.rolsuper
     or v_role.rolcreatedb
     or v_role.rolcreaterole
     or v_role.rolbypassrls
     or v_role.rolconnlimit <> 5 then
    raise exception 'FAIL_CLOSED Grafana role attribute mismatch';
  end if;

  select m.inherit_option, m.set_option
  into v_membership
  from pg_auth_members m
  join pg_roles r on r.oid=m.roleid
  join pg_roles u on u.oid=m.member
  where r.rolname='galia_monitor_ro'
    and u.rolname='galia_grafana_ro';

  if not v_membership.inherit_option or v_membership.set_option then
    raise exception 'FAIL_CLOSED Grafana membership options mismatch';
  end if;

  if (
    select count(*)
    from pg_auth_members m
    join pg_roles parent on parent.oid=m.roleid
    join pg_roles member on member.oid=m.member
    where parent.rolname='galia_grafana_ro'
       or member.rolname='galia_grafana_ro'
  ) <> 2 then
    raise exception 'FAIL_CLOSED unexpected Grafana role membership count';
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

  if not exists (
    select 1
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
      and revision='__PROMOTED_MAIN_COMMIT__'
      and canonical_authority
      and source_of_truth
      and status='ACTIVE'
  ) then
    raise exception 'FAIL_CLOSED GitHub control-plane refresh absent';
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
