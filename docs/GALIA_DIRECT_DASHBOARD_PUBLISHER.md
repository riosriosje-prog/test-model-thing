# GALIA direct dashboard publisher

This candidate moves dashboard publication into the GALIA control-plane repository.

The build is fail-closed and reads only explicit machine-readable bindings:

- `governance/galia_dashboard_authority_pointer.v1.json`
- `governance/safe_delete_execution_receipt.v1.json`
- `governance/hf_final_release_candidate.v1.json`
- `governance/galia_dashboard_research_registry.v1.json`

It never discovers a "latest" authority object by filename or timestamp. Authority changes must first update the explicit pointer under normal human-governed GALIA promotion rules.

On pull requests the workflow validates and builds only. On `main`, validated source changes publish the static read-only dashboard to `Junitos/GALIA`.

The existing publisher in `riosriosje-prog/galia-mlx-validation` should remain enabled until this direct publisher is separately validated and human-promoted. It can then be retired to avoid two independent writers to the same Space.
