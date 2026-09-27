-- GALIA Grafana PostgreSQL datasource runtime acceptance v0.6
-- Run only through the galia_grafana_ro datasource/session after JIT activation.

select current_user = 'galia_grafana_ro' as role_is_expected;
select current_setting('default_transaction_read_only') = 'on' as default_read_only;
select current_setting('statement_timeout') = '30s' as statement_timeout_is_expected;
select current_setting('lock_timeout') = '5s' as lock_timeout_is_expected;

select count(*) >= 0 as overview_readable from monitor.galia_overview_v1;
select count(*) >= 0 as ingest_health_readable from monitor.ingest_health_v1;
select count(*) >= 0 as authority_chain_readable from monitor.authority_chain_v1;
select count(*) >= 0 as research_pipeline_readable from monitor.research_pipeline_v1;
select count(*) >= 0 as control_plane_topology_readable from monitor.control_plane_topology_v1;

select
  not has_schema_privilege(current_user,'audit','USAGE') as audit_denied,
  not has_schema_privilege(current_user,'staging','USAGE') as staging_denied,
  not has_schema_privilege(current_user,'canonical','USAGE') as canonical_denied,
  not has_schema_privilege(current_user,'derived','USAGE') as derived_denied;

select count(*) = 0 as public_selectable_relations_zero
from pg_class c
join pg_namespace n on n.oid=c.relnamespace
where n.nspname='public'
  and c.relkind in ('r','p','v','m','f')
  and has_table_privilege(current_user,c.oid,'SELECT');
