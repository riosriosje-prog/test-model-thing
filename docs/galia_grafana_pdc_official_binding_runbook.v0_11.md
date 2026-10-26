# GALIA Grafana PDC official binding runbook v0.11

Status: EXTERNAL_FACTS_BLOCKED_NOT_PROMOTABLE

## Authority state after v0.3 ratification

The preparation-baseline authority hold is released by PR #57 / v0.3. This does **not** authorize live execution. The remaining block is external-fact completeness plus a separate future live-execution candidate and human decision.

## What changed from v0.10

v0.10 correctly refused to invent a PDC binding field. Subsequent review of Grafana's official Terraform provider resolves that uncertainty.

For Grafana Cloud data sources, the provider exposes:

`private_data_source_connect_network_id`

When non-empty, the official provider writes:

```json
{
  "enableSecureSocksProxy": true,
  "secureSocksProxyUsername": "<PDC_NETWORK_ID>"
}
```

into the datasource `JSONData`.

The same provider then uses the ordinary Grafana datasource create/update path. Therefore the binding representation is no longer treated as unknown.

## Resolve the exact PDC network ID

Use an official Grafana Cloud surface.

The official Terraform data source:

`grafana_cloud_private_data_source_connect_networks`

requires only:

`accesspolicies:read`

for listing existing PDC networks and returns:

- `id`
- `region`
- `name`
- `display_name`
- `status`

The network `id` is the underlying Grafana Cloud access-policy ID.

Modern PDC networks are identified by scope:

`set:pdc-signing`

Older networks may still carry:

`pdc-signing:write`

Do not create a new network if a suitable existing network is available.

## Credential separation

### Grafana Cloud access-policy token

Purpose:
- list existing PDC networks;
- resolve the exact PDC network ID.

Minimum scope for discovery:

`accesspolicies:read`

### Grafana stack service-account token

Purpose:
- create/update/read/test the datasource in the hosted Grafana stack.

Keep this credential distinct from the Grafana Cloud access-policy token.

### PDC agent signing token

Purpose:
- authenticate the PDC agent.

Modern scope:

`set:pdc-signing`

Legacy scope:

`pdc-signing:write`

### Supabase scoped PAT

Purpose:
- PostgreSQL password under Supabase Temporary Access.

It is not a Grafana API token and not a PDC token.

## Legacy connection-path disposition

A historical artifact on `main`, `governance/galia_grafana_activation_candidate.v1_0.json`, is explicitly `CANDIDATE_NOT_PROMOTED` but recommends `SHARED_POOLER_SESSION`.

That recommendation is **superseded for Temporary Access/JIT**. The current contract is:

```text
Temporary Access / JIT + stock Grafana PostgreSQL datasource
    -> DIRECT
    -> db.nzoviwitcqmsacwiizhh.supabase.co:5432
    -> PDC for Grafana Cloud IPv6 reachability
```

Do not use the shared pooler for this flow. The JIT preparation v1.4 records that the shared pooler requires the Supavisor `jit=true` connection option, which the stock Grafana PostgreSQL datasource does not expose as an arbitrary PostgreSQL connection option.

## Binding contract

For the Cloud PDC profile, the datasource must contain:

```text
jsonData.enableSecureSocksProxy = true
jsonData.secureSocksProxyUsername = <EXACT_PDC_NETWORK_ID>
```

For GALIA Cangrejos the remaining expected datasource settings stay:

```text
host                = db.nzoviwitcqmsacwiizhh.supabase.co:5432
user                = galia_grafana_ro
database            = postgres
sslmode             = verify-full
tlsConfigurationMethod = file-content
maxOpenConns        = 2
maxIdleConns        = 1
connMaxLifetime     = 240
postgresVersion     = 1700
timescaledb         = false
```

Secrets remain out-of-band:
- PostgreSQL password / Supabase PAT;
- CA PEM;
- Grafana tokens;
- PDC token.

## Preconditions before any live write

All must pass:

1. **SATISFIED** — PR #57 / authority ratification v0.3 was human-promoted as merge `82e5b8e6642d1475ebcee9183b401b1fd010e63b`.
2. Exact Grafana Cloud stack URL and stack ID are verified.
3. Existing PDC network is resolved from an official Grafana Cloud surface.
4. PDC network `status` is acceptable.
5. Connected-agent count for that exact network is > 0.
6. PDC agent has verified IPv6 route to Supabase direct endpoint port 5432.
7. Supabase SSL Enforcement is enabled.
8. Temporary Access is enabled.
9. JIT mapping to `galia_grafana_ro` is current and unexpired.
10. Supabase server-root CA SHA-256 is verified.
11. A separate live-execution candidate reaches `READY_FOR_HUMAN_PROMOTION`.
12. A new human decision authorizes that exact live-execution candidate.

## Post-write acceptance

After an authorized datasource create/update:

- read datasource by UID;
- require `enableSecureSocksProxy=true`;
- require `secureSocksProxyUsername == expected PDC network ID`;
- datasource health must pass;
- TLS `verify-full` must pass;
- all five monitor views must be queryable;
- negative permission tests must still fail as expected;
- no secret values may be emitted into receipts, Git, logs, or chat.

## v0.10 disposition

The v0.10 before/after observation protocol remains useful diagnostically, but it is no longer required to discover the binding field. Official Grafana code establishes the mapping directly.
