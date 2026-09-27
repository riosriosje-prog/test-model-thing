# GALIA Grafana external facts intake v0.13

Status: EXTERNAL_FACTS_INTAKE_READY_NOT_PROMOTABLE

This layer sits on top of PDC Official Binding v0.11. It performs no network calls and accepts no credentials. Its sole purpose is to validate a non-secret snapshot of the external facts that v0.11 requires before a future live-execution candidate can be constructed.

## Input packet

The actual packet must remain out of Git. It may contain non-secret identifiers such as stack ID, PDC network ID, gotrue_id, public IPv6 CIDRs, and the SHA-256 of the Supabase server-root CA. It must not contain tokens, passwords, primary email, CA PEM, signing tokens, service-account tokens, or other secret values.

The packet is freshness-bounded. By policy, v0.13 rejects snapshots older than 900 seconds and requires at least 300 seconds of remaining JIT lifetime.

v0.13 also enforces strict validator/schema parity. Every object must contain exactly the keys declared by the schema. Missing keys and unknown extra keys, including non-secret extras, fail closed.

## Required evidence

1. Authority ratification merge is exactly `82e5b8e6642d1475ebcee9183b401b1fd010e63b`.
2. PDC Official Binding contract is exactly v0.11 head `ce4d638f11d5e63461ec5a2bd99155146c806ec4` with candidate-set `ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc`.
3. Grafana stack URL/ID are verified.
4. PDC network identity is resolved from an official Grafana Cloud surface.
5. Connected agents for that exact network are >= 1.
6. PDC-agent externally routable IPv6 egress CIDR(s) are observed.
7. Route from PDC agent to `db.nzoviwitcqmsacwiizhh.supabase.co:5432` is verified.
8. `PermitRemoteOpen` is constrained to that exact endpoint.
9. Credential domains are available and verified distinct; no credential values enter the packet.
10. Supabase SSL Enforcement is enabled.
11. Supabase Temporary Access is enabled.
12. JIT mapping to `galia_grafana_ro` is verified and has at least 300 seconds remaining.
13. gotrue_id binding is verified.
14. Supabase server-root CA SHA-256 is recorded.
15. No secret material is persisted.

## Output

A passing validator emits:

`FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE`

This is not authorization. It only means the facts are sufficient to build the next candidate. A separate future live-execution candidate and an explicit human decision remain mandatory.
