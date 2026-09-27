-- GALIA monitoring surface v1
-- Additive operational observability only.
-- Does not mutate canonical research rows and does not authorize promotion.

create role galia_monitor_owner
  nologin nosuperuser nocreatedb nocreaterole noinherit nobypassrls;

create role galia_monitor_ro
  nologin nosuperuser nocreatedb nocreaterole noinherit nobypassrls;

create schema monitor authorization galia_monitor_owner;
revoke all on schema monitor from public, anon, authenticated;
grant usage on schema monitor to galia_monitor_ro;

alter default privileges for role galia_monitor_owner in schema monitor
  revoke all on tables from public;
alter default privileges for role galia_monitor_owner in schema monitor
  grant select on tables to galia_monitor_ro;

grant usage on schema audit, staging, canonical to galia_monitor_owner;

grant select on
  audit.schema_versions,
  audit.cross_plane_bindings,
  audit.cross_plane_binding_edges,
  audit.promotion_receipts,
  audit.external_anchors,
  audit.ingest_closure_receipts,
  audit.ingest_candidate_seals,
  audit.ingest_rejection_receipts,
  staging.ingest_batches,
  staging.ingest_batch_transitions,
  staging.candidate_objects,
  canonical.sources,
  canonical.documents,
  canonical.entities,
  canonical.events,
  canonical.claims,
  canonical.evidence_items,
  canonical.discrepancies
to galia_monitor_owner;

create policy galia_monitor_select_schema_versions on audit.schema_versions for select to galia_monitor_owner using (true);
create policy galia_monitor_select_cross_plane_bindings on audit.cross_plane_bindings for select to galia_monitor_owner using (true);
create policy galia_monitor_select_cross_plane_binding_edges on audit.cross_plane_binding_edges for select to galia_monitor_owner using (true);
create policy galia_monitor_select_promotion_receipts on audit.promotion_receipts for select to galia_monitor_owner using (true);
create policy galia_monitor_select_external_anchors on audit.external_anchors for select to galia_monitor_owner using (true);
create policy galia_monitor_select_ingest_closure_receipts on audit.ingest_closure_receipts for select to galia_monitor_owner using (true);
create policy galia_monitor_select_ingest_candidate_seals on audit.ingest_candidate_seals for select to galia_monitor_owner using (true);
create policy galia_monitor_select_ingest_rejection_receipts on audit.ingest_rejection_receipts for select to galia_monitor_owner using (true);
create policy galia_monitor_select_ingest_batches on staging.ingest_batches for select to galia_monitor_owner using (true);
create policy galia_monitor_select_ingest_batch_transitions on staging.ingest_batch_transitions for select to galia_monitor_owner using (true);
create policy galia_monitor_select_candidate_objects on staging.candidate_objects for select to galia_monitor_owner using (true);
create policy galia_monitor_select_sources on canonical.sources for select to galia_monitor_owner using (true);
create policy galia_monitor_select_documents on canonical.documents for select to galia_monitor_owner using (true);
create policy galia_monitor_select_entities on canonical.entities for select to galia_monitor_owner using (true);
create policy galia_monitor_select_events on canonical.events for select to galia_monitor_owner using (true);
create policy galia_monitor_select_claims on canonical.claims for select to galia_monitor_owner using (true);
create policy galia_monitor_select_evidence_items on canonical.evidence_items for select to galia_monitor_owner using (true);
create policy galia_monitor_select_discrepancies on canonical.discrepancies for select to galia_monitor_owner using (true);

set local role galia_monitor_owner;

create view monitor.ingest_health_v1 with (security_barrier=true) as
select
  b.id as batch_id,
  b.batch_key,
  b.schema_version,
  b.expected_count,
  b.ingested_count,
  b.rejected_count,
  co.candidate_count,
  ss.seal_count,
  cr.sealed_candidate_count,
  lt.latest_seq,
  lt.latest_status,
  (cr.id is not null) as closure_receipt_present,
  (rr.id is not null) as rejection_receipt_present,
  (ea.id is not null) as closure_anchor_present,
  (ea.object_hash = cr.terminal_receipt_hash_v2) as closure_anchor_object_match,
  chain.transition_chain_valid,
  (
    b.expected_count = b.ingested_count
    and b.rejected_count = 0
    and co.candidate_count = ss.seal_count
    and ss.seal_count = coalesce(cr.sealed_candidate_count, ss.seal_count)
    and lt.latest_status = 'CLOSED'
    and cr.id is not null
    and ea.id is not null
    and ea.object_hash = cr.terminal_receipt_hash_v2
    and chain.transition_chain_valid
  ) as integrity_pass
from staging.ingest_batches b
left join lateral (
  select count(*)::bigint as candidate_count
  from staging.candidate_objects x
  where x.ingest_batch_id = b.id
) co on true
left join lateral (
  select count(*)::bigint as seal_count
  from audit.ingest_candidate_seals x
  where x.batch_id = b.id
) ss on true
left join audit.ingest_closure_receipts cr on cr.batch_id = b.id
left join audit.ingest_rejection_receipts rr on rr.batch_id = b.id
left join lateral (
  select x.seq as latest_seq, x.to_status as latest_status
  from staging.ingest_batch_transitions x
  where x.batch_id = b.id
  order by x.seq desc
  limit 1
) lt on true
left join lateral (
  select coalesce(bool_and(
    x.prev_seq is null or exists (
      select 1
      from staging.ingest_batch_transitions p
      where p.batch_id = x.batch_id
        and p.seq = x.prev_seq
        and p.to_status = x.from_status
        and p.transition_hash_v2 = x.prev_transition_hash_v2
    )
  ), false) as transition_chain_valid
  from staging.ingest_batch_transitions x
  where x.batch_id = b.id
) chain on true
left join audit.external_anchors ea
  on ea.anchor_type = 'INGEST_CLOSURE'
 and ea.object_ref = ('ingest:' || b.batch_key || ':closure');

create view monitor.authority_chain_v1 with (security_barrier=true) as
select
  integration_set_id,
  binding_key,
  provider,
  authority_role,
  object_ref,
  revision,
  canonical_authority,
  source_of_truth,
  status
from audit.cross_plane_bindings;

create view monitor.research_pipeline_v1 with (security_barrier=true) as
select
  (select count(*) from staging.candidate_objects where status='DRAFT') as draft_candidates,
  (select count(*) from staging.candidate_objects where status='REVIEW') as review_candidates,
  (select count(*) from staging.candidate_objects where status='READY') as ready_candidates,
  (select count(*) from staging.candidate_objects where status='REJECTED') as rejected_candidates,
  (select count(*) from staging.candidate_objects where status='PROMOTED') as promoted_candidates,
  (select count(*) from audit.promotion_receipts) as promotion_receipts,
  (select count(*) from canonical.sources) as canonical_sources,
  (select count(*) from canonical.documents) as canonical_documents,
  (select count(*) from canonical.entities) as canonical_entities,
  (select count(*) from canonical.events) as canonical_events,
  (select count(*) from canonical.claims) as canonical_claims,
  (select count(*) from canonical.evidence_items) as canonical_evidence_items,
  (select count(*) from canonical.discrepancies) as canonical_discrepancies;

create view monitor.control_plane_topology_v1 with (security_barrier=true) as
select
  e.integration_set_id,
  fb.binding_key as from_binding,
  fb.provider as from_provider,
  fb.authority_role as from_role,
  e.relation,
  tb.binding_key as to_binding,
  tb.provider as to_provider,
  tb.authority_role as to_role
from audit.cross_plane_binding_edges e
join audit.cross_plane_bindings fb on fb.id = e.from_binding_id
join audit.cross_plane_bindings tb on tb.id = e.to_binding_id;

create view monitor.galia_overview_v1 with (security_barrier=true) as
with metrics as (
  select
    (select sv.schema_version
       from audit.schema_versions sv
      where sv.status='APPLIED'
      order by sv.applied_at desc nulls last, sv.schema_version desc
      limit 1) as active_schema,
    (select count(*) from audit.cross_plane_bindings where status='HOLD') as cross_plane_hold_count,
    (select count(*) from audit.cross_plane_bindings where status='ACTIVE') as active_binding_count,
    (select count(*) from audit.cross_plane_bindings where canonical_authority and status='ACTIVE') as active_canonical_authority_count,
    (select count(*) from staging.candidate_objects where status='READY') as ready_candidates,
    (select count(*) from staging.candidate_objects where status='REVIEW') as review_candidates,
    (select count(*) from audit.promotion_receipts) as promotion_receipts,
    (
      (select count(*) from canonical.sources) +
      (select count(*) from canonical.documents) +
      (select count(*) from canonical.entities) +
      (select count(*) from canonical.events) +
      (select count(*) from canonical.claims) +
      (select count(*) from canonical.evidence_items) +
      (select count(*) from canonical.discrepancies)
    ) as canonical_object_count,
    (select count(*) from monitor.ingest_health_v1 where latest_status='CLOSED' and not integrity_pass) as closed_ingest_integrity_failures
)
select *,
  case
    when active_canonical_authority_count <> 1 then 'CRITICAL'
    when closed_ingest_integrity_failures > 0 then 'CRITICAL'
    when cross_plane_hold_count > 0 then 'HOLD'
    when ready_candidates > 0 then 'AWAITING_HUMAN_PROMOTION'
    else 'HEALTHY'
  end as system_state,
  'NOT_MODELED'::text as global_authority_hold_state,
  'GITHUB_GOVERNANCE_REQUIRED'::text as safe_delete_state_source
from metrics;

reset role;

grant select on all tables in schema monitor to galia_monitor_ro;

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
  jsonb_build_object(
    'additive', true,
    'destructive', false,
    'canonical_data_mutation', false,
    'canonical_authorization_metadata_touched', true,
    'monitor_schema_private', true,
    'monitor_views_security_barrier', true,
    'grafana_write_authority', false,
    'human_promotion_required', true,
    'global_authority_hold_modeled', false,
    'safe_delete_state_external_to_supabase', true
  ),
  now()
)
on conflict (schema_version) do nothing;
