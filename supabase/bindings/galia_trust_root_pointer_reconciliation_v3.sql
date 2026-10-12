-- GALIA trust-root pointer reconciliation v3
-- Candidate only. Execute only after explicit human promotion of exact pointer SHA ed6a18b96871209593f910afd9d3879eabb5fcc7c5af7c844e623e241281dbb6.
do $$
declare
    anchor_revision text;
    current_pointer_sha text;
begin
    select revision, metadata->>'trust_root_pointer_sha256'
      into anchor_revision, current_pointer_sha
    from audit.cross_plane_bindings
    where binding_key='github-control-plane-main'
    for update;

    if anchor_revision is distinct from '25db17fa583d1561d746ee7d33407d3684ee561d' then
        raise exception 'GALIA pointer reconciliation blocked: unexpected authority anchor revision %', anchor_revision;
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
        'trust_root_pointer_sha256', 'ed6a18b96871209593f910afd9d3879eabb5fcc7c5af7c844e623e241281dbb6',
        'trust_root_pointer_predecessor_sha256', 'ceb60f75e5fdf38dbe743d0d6560f58bb359ebbeaa322d501460e5eb579a02b9',
        'trust_root_pointer_reconciliation_id', 'GALIA-TRUST-ROOT-ACTIVATION-RECONCILIATION-2026-09-26-023',
        'revision_semantics', 'AUTHORITY_ANCHOR_COMMIT_NOT_MOVING_HEAD',
        'tracked_ref', 'main'
    )
where binding_key='github-control-plane-main'
  and revision='25db17fa583d1561d746ee7d33407d3684ee561d';
