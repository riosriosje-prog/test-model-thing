# GALIA 2.0 — Control Plane / ML Artifact Plane

Status: **ARCHITECTURE CANDIDATE / HUMAN PROMOTION REQUIRED**

## Core invariant

```text
CODE_AUTHORITY != MODEL_ARTIFACT_AUTHORITY

GitHub       = CONTROL PLANE
Hugging Face = ML ARTIFACT PLANE
```

GitHub is canonical for source code, architecture, tests, CI, governance policy, receipts, promotion decisions, lineage and rollback.

Hugging Face is the specialized ML artifact plane for trained weights, model cards, dataset surfaces, Spaces/demos, artifact pull requests, storage and remote byte verification.

Artifact presence or promotion in Hugging Face does not transfer canonical engineering authority.

## Cross-plane contract

Every promoted ML artifact must remain bound to:

1. GitHub source SHA;
2. artifact manifest SHA-256;
3. payload SHA-256;
4. exact byte size;
5. promotion scope;
6. remote byte re-read verification;
7. explicit human promotion.

```text
GITHUB_SOURCE_MERGED != HF_ARTIFACT_PROMOTED
HF_ARTIFACT_PROMOTED != GITHUB_SOURCE_MERGED
HF_ARTIFACT_PRESENT  != CANONICAL_AUTHORITY_TRANSFER
PREFLIGHT_PASS       != PROMOTED
REMOTE_UPLOAD        != PROMOTED
```

## Current promoted HF8 binding

```text
repo_id           = Junitos/galia-2
revision          = main
candidate_path    = weights/hf8-retrain-v0.2-4k
payload_sha256    = 3bc46a281bdb6a031f7399d46e50612b622527bcc2528fd2f0e6220694971b3c
payload_bytes     = 70716981
manifest_sha256   = a41110548ced010da6d1462d4c0822dd527ac7411421540bdaf817d7d3b4cbb2
promotion_scope   = HF8_REAL_WEIGHT_V0_2_4K_BOOTSTRAP_ONLY
authority_binding = CURRENT_BOUND
quality_gate      = PASS
```

The corresponding source integration was promoted independently through GitHub PR #22.

## Failure semantics

GALIA fails closed on any cross-plane identity mismatch: source SHA, payload hash, manifest hash, byte count, promotion scope, provenance, or missing human authorization.

## Legacy boundary

```text
source_of_truth                 = github
canonical_authority_transferred = false
legacy_mutation_authorized      = false
```

## Machine-readable policy

Normative candidate policy:

`huggingface/policy/control-artifact-plane.v1.json`
