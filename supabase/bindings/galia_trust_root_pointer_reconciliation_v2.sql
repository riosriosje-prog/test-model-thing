-- GALIA trust-root pointer reconciliation v2
-- Candidate only. Execute only after explicit human promotion of the exact pointer SHA.
do $$
declare
    current_revision text;
    current_pointer_sha text;
begin
    select revision, metadata->>'trust_root_pointer_sha256'
      into current_revision, current_pointer_sha
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
    for update;

    if current_revision is distinct from '25db17fa583d1561d746ee7d33407d3684ee561d' then
        raise exception 'GALIA pointer reconciliation blocked: unexpected GitHub binding revision %', current_revision;
    end if;

    if current_pointer_sha is distinct from 'ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9' then
        raise exception 'GALIA pointer reconciliation blocked: unexpected predecessor pointer SHA %', current_pointer_sha;
    end if;
end
$$;

update audit.cross_plane_bindings
set metadata =
    metadata
    || jsonb_build_object(
        'trust_root_pointer_sha256', 'eac0b7af19823a588f8d9a188592f0667af6d73c442aaff4d4096bc16030647c',
        'trust_root_pointer_predecessor_sha256', 'ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9',
        'trust_root_pointer_reconciliation_id', 'GALIA-TRUST-ROOT-ACTIVATION-RECONCILIATION-2026-09-26-022'
    )
where binding_key='github-control-plane-main'
  and revision='25db17fa583d1561d746ee7d33407d3684ee561d';
