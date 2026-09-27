# GALIA Grafana external facts intake v0.14

Status: EXTERNAL_FACTS_INTAKE_HARDENED_NOT_PROMOTABLE

v0.14 is stacked on PR #62 / v0.13. It preserves v0.13 strict shape handling and closes the remaining audit findings before any real external-facts packet can be accepted.

## Hardening

- Execute the Draft 2020-12 JSON Schema at runtime with format checking.
- Represent Supabase JIT expiry as `jit_expires_at_ms` and enforce at least 300000 ms remaining.
- Require PDC IPv6 evidence to be global-unicast; reject multicast, private, link-local, loopback, reserved, unspecified and `::/0`.
- Require sanitized provenance receipts for every external fact domain.
- Keep packet and every receipt freshness-bounded to 900 seconds.
- Keep the secret-field denylist as defense in depth; actual credential values remain forbidden.

## Provenance domains

Authority binding; Grafana stack identity; PDC network identity; connected-agent state; PDC IPv6 route; credential-domain availability/separation; Supabase SSL state; Temporary Access state; JIT mapping state; server-root CA SHA-256.

Each receipt records only `observed_at_utc`, `method`, `source_ref` and `receipt_sha256`. Sanitized receipts themselves remain outside Git.

## Output

A PASS emits only `FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE`.

It does not authorize execution, does not create the live candidate, and performs no Grafana, PDC, Supabase, SSL, Temporary Access, JIT, datasource or credential mutation.
