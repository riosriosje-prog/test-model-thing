# GALIA Grafana PDC binding discovery protocol v0.10

Status: AUTHORITY_HOLD_DEPENDENT_NOT_PROMOTABLE

## Objective

Discover, from the real Grafana Cloud stack, the exact persisted representation that links a PostgreSQL datasource to a selected PDC network.

This protocol exists because the public Grafana datasource HTTP API documents datasource read/write/health, while the public PDC documentation requires selecting a PDC network in the UI but does not document a stable datasource API field that GALIA can safely assume.

## Preconditions

Do not execute this protocol unless all are true:

- authority ratification candidate v0.3 has been promoted;
- a separate live-discovery authorization has been granted;
- the exact Grafana stack is identified;
- the exact PDC network is identified;
- at least one PDC agent for that network is connected;
- no secret values will be copied into receipts, Git, logs, or chat.

## Least privilege

For observation:
- datasource read permission scoped to the target datasource when feasible;
- PDC plugin role `plugins:grafana-pdc-app:private-networks-read`.

For the one controlled binding mutation:
- datasource write permission scoped to the target datasource when feasible.

Do not grant `plugins:grafana-pdc-app:private-networks-write` merely to select an existing PDC network unless the product contract later proves that permission is required.

## Network identity

Use the Grafana Cloud usage metric:

`grafanacloud_grafana_pdc_connected_agents{stack_id="<STACK_ID>"}`

The metric is documented as reporting connected agents per PDC network. Record:
- stack ID;
- target `tunnelID`;
- connected-agent count;
- observation timestamp.

Require count > 0 for the exact target tunnel.

## Before snapshot

Read:

`GET /api/datasources/uid/<UID>`

Persist only a sanitized observation:
- datasource UID;
- version;
- safe `jsonData`;
- names of fields present in `secureJsonFields`;
- timestamp.

Never persist:
- `secureJsonData`;
- passwords;
- Supabase PAT;
- Grafana service-account token;
- PDC signing token;
- CA PEM;
- primary email.

## Controlled UI binding

In Grafana Cloud:
1. Open the target PostgreSQL datasource.
2. Under **Private data source connection**, select the exact target network.
3. Confirm the selected network has a connected agent.
4. Click **Save & test**.
5. Require `Database Connection OK`.

This is the only mutation in the discovery protocol.

## After snapshot

Read the same datasource again with:

`GET /api/datasources/uid/<UID>`

Also check:

`GET /api/datasources/uid/<UID>/health`

Persist only the same sanitized fields as the before snapshot plus:
- Save & test result;
- health result.

## Diff

Compare only safe, non-secret fields:
- `jsonData` paths;
- safe top-level paths;
- version.

Any changed path plausibly representing the PDC binding becomes a **candidate binding path**, not yet an API contract.

Do not treat:
- `pdcInjected`;
- `enableSecureSocksProxy`;
- any undocumented field

as the network-binding identifier unless the real before/after observation proves it.

## Repeatability gate

A single observation is insufficient for automation.

Preferred confirmation:
- repeat the same process on a disposable/fresh datasource using the same PDC network;
- confirm the same path/value semantics recur;
- if feasible, bind to a second PDC network and verify the candidate field changes accordingly.

Only a repeated match may feed a later automation candidate.

## Outcome classes

- `NO_BINDING_FIELD_OBSERVED`: UI/plugin may manage binding outside the ordinary datasource JSON surface. Keep UI binding manual.
- `SINGLE_CANDIDATE_FIELD`: field observed once; quarantine from automation.
- `REPEATED_STABLE_BINDING_FIELD`: field/path semantics repeated; eligible for a new engineering candidate.
- `INCONSISTENT`: fail closed.

No outcome from this protocol authorizes live production activation.
