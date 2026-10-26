# GALIA Grafana live execution runbook v0.9

Status: AUTHORITY_HOLD_DEPENDENT_NOT_PROMOTABLE

This runbook defines two mutually exclusive execution adapters. It does not authorize either adapter.

## Global gate

Do not perform live Grafana or Supabase mutations until:

1. `GALIA-GRAFANA-AUTHORITY-RATIFICATION-CANDIDATE-v0.3` has been explicitly promoted by a human decision.
2. A subsequent live-execution candidate is built from verified external evidence.
3. That exact live-execution candidate reaches `READY_FOR_HUMAN_PROMOTION`.
4. A separate human promotion/activation decision is recorded.

## Profile A — SELF_HOSTED_IPV6

Use only when the Grafana server is controlled by GALIA's operator and has verified IPv6 egress to:

`db.nzoviwitcqmsacwiizhh.supabase.co:5432`

Execution surface:
- file provisioning YAML
- out-of-band environment variables for secrets
- local `psql` verify-full acceptance
- Grafana datasource health/query verification

The existing v0.7 provisioning YAML remains applicable to this profile.

## Profile B — GRAFANA_CLOUD_PDC_IPV6

Grafana Cloud must not be treated as a direct-IPv6 client. Current Grafana Cloud documentation states that external data source connections over IPv6 are not supported.

Required path:

`Grafana Cloud -> bound PDC network -> connected PDC agent with IPv6 egress -> Supabase direct endpoint :5432`

Requirements:
- identify the Grafana Cloud stack
- identify the exact PDC network
- verify at least one agent is connected
- verify the agent can resolve/reach the Supabase direct host over IPv6 on port 5432
- restrict PDC with `PermitRemoteOpen=db.nzoviwitcqmsacwiizhh.supabase.co:5432`
- bind the datasource to the exact PDC network
- use TLS `verify-full` with the verified Supabase server-root CA
- keep PostgreSQL max connection lifetime at 240 seconds (<300 seconds)
- verify datasource health / Save & test
- query all five monitor views
- run negative permission tests

### Cloud configuration surface

The ordinary Grafana HTTP API documents datasource create/update/read/health operations. It does not, in the public datasource API contract reviewed for v0.9, expose a documented field that GALIA can safely invent for choosing a Grafana Cloud PDC network.

Therefore:

- `enableSecureSocksProxy=true` is necessary proxy-routing state but is not sufficient proof of PDC network binding.
- Do not invent a PDC network JSON field.
- A Cloud datasource may be configured through the Grafana UI, or through an API only after the exact PDC-binding contract has been observed/verified.
- File provisioning YAML is reference material for this Cloud profile; do not assume a Grafana Cloud user can deploy it to the hosted server filesystem.

## Credential separation

Three credentials have different trust domains and must never be conflated:

1. Supabase scoped PAT — PostgreSQL password under Temporary Access.
2. Grafana service-account token — Grafana HTTP API authentication if API automation is used.
3. Grafana PDC signing token — PDC agent authentication; requires `pdc-signing:write`.

No secret value belongs in Git, receipts, test fixtures, logs, or chat transcripts.

## Supabase prerequisites

Before either profile:
- SSL Enforcement = enabled
- Temporary Access = enabled
- dedicated Supabase identity mapped to `galia_grafana_ro`
- JIT mapping current and unexpired
- source IP restrictions match the selected execution profile
- scoped PAT belongs to the mapped Supabase identity
- server-root CA bytes verified out-of-band and only SHA-256 recorded

## Fail-closed rules

Reject execution if:
- the deployment profile is unknown
- Grafana Cloud direct IPv6 is proposed
- PDC is enabled but no exact PDC network identity is evidenced
- a PDC agent is not connected
- the PDC agent's IPv6 route to Supabase is unverified
- `PermitRemoteOpen` is broader than the approved target without separate review
- a secret appears in a receipt or repository
- authority ratification v0.3 has not been promoted
