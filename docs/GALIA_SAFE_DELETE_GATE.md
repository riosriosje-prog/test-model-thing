# GALIA SAFE_DELETE Gate v1 — Recovery v5 candidate

Status: **CANDIDATE / HUMAN PROMOTION REQUIRED**

Recovery v5 prepares an exact deletion manifest. It does **not** delete anything and does **not** contain human deletion authorization.

## Preserved authority state

Recovery v4 remains the promoted byte-complete preservation baseline:

- `5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6` = RAW_BYTES_VERIFIED;
- final sealed vault = PASS;
- clean-room restore = PASS;
- raw-byte blockers = 0;
- final vault manifest SHA-256 = `53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf`.

## Exact deletion-manifest candidate

Path:

`governance/safe_delete_deletion_manifest.v1.json`

SHA-256:

`6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708`

Targets: **27** exact Library objects.

Every target is bound to:

- exact Library `library_file_id`;
- exact backing `file_id`;
- exact Library path;
- exact byte size;
- exact SHA-256;
- exact preserved counterpart in `/GALIA_FINAL_VAULT_SEALED_2026-09-26`;
- identical preservation SHA-256.

The candidate is deliberately narrow. It includes only byte-identical duplicates from staging, the intermediate final-vault workspace, and one recovery-work copy.

Explicitly excluded:

- the sealed final vault itself;
- the complete `/GALIA_RECOVERY` folder;
- the known corrupt/partial 49.6 MB recovery ZIP;
- reconstruction chunks and their chunk manifest;
- every file not individually enumerated.

## Gate result

With this exact manifest present and hashed:

`SAFE_DELETE = HOLD`

The only remaining mandatory blocker is:

`human_authorization:ABSENT`

A later human deletion authorization must bind both:

- deletion-manifest SHA-256 `6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708`; and
- final-vault manifest SHA-256 `53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf`.

Promotion of Recovery v5 would promote only the manifest/policy evidence state. It would **not** itself authorize or execute deletion.
