# GALIA 2.0 — Hugging Face migration candidate v0.1

Status: **CANDIDATE / NO AUTHORITY TRANSFER / NO LEGACY MUTATION**

Base GitHub commit:
`a09c3e953ec1799b1704783c4c3d14a1a0017f62`

## Objective

Add Hugging Face as GALIA's model-distribution surface without replacing
GitHub as engineering authority.

The first migration stage intentionally publishes only a **model repository
mirror** of the reproducible code surface. Trained weights, historical
datasets/evidence, and an interactive Space are separate gates.

## Target topology

```text
GitHub
  authoritative source / CI / promotion receipts / rollback
        |
        | deterministic export
        v
Hugging Face model repo
  code + model card + future weight artifacts
        |
        +--> future dataset repo
        |      versioned research/evidence distributions
        |
        +--> future Space
               UI / demo / inspection surface
```

Mutable training checkpoints, logs, and intermediate large objects should not
be mixed into the versioned evidence/model repo. If GALIA later needs that
class of storage on Hugging Face, use a Storage Bucket and preserve the
canonical manifest/lineage elsewhere.

## Migration gates

```text
HF1_EXPORT_DETERMINISM       = IMPLEMENTED
HF2_SOURCE_SHA_BINDING       = IMPLEMENTED
HF3_PER_FILE_SHA256          = IMPLEMENTED
HF4_TOKEN_FAIL_CLOSED        = IMPLEMENTED
HF5_HUB_REPO_CREATE          = NOT_RUN
HF6_HUB_UPLOAD_AS_PR         = NOT_RUN
HF7_REMOTE_MANIFEST_COMPARE  = NOT_RUN
HF8_WEIGHT_ARTIFACT_GATE     = NOT_RUN
HF9_DATASET_REPO_GATE        = NOT_RUN
HF10_SPACE_PARITY_GATE       = NOT_RUN
```

## Authentication

The GitHub workflow requires a repository Actions secret named
`HF_TOKEN`. The token is consumed through the standard Hugging Face
`HF_TOKEN` environment variable and is never written into the export.

The exact destination is supplied manually as workflow input
`hf_repo_id` in `owner-or-org/repo-name` form. GALIA does not infer a
Hugging Face account name from the GitHub owner.

## Safe first publish

The workflow defaults to:

- repository type: `model`;
- visibility: `private`;
- upload mode: Hugging Face **pull request**.

That means the first authenticated run creates/uses the private model repo and
stages the exported mirror for review instead of treating the Hub upload as
canonical.

## Weight migration

When weights are introduced:

1. capture exact `.safetensors` bytes;
2. record byte size and SHA-256;
3. bind weights to model/config/runtime versions;
4. upload through Hugging Face/Xet;
5. re-download or query the remote file and verify identity;
6. only then issue a GALIA distribution receipt.

Hub/Xet storage is appropriate for large binary model artifacts. Canonical
promotion remains a separate human-governed event.

## Dataset/evidence migration

Historical evidence should use a dedicated **dataset repository**, not the
model repo. Raw source captures, transcriptions, normalized assertions,
provenance, and receipts must keep their existing GALIA authority separation.

Large mutable scratch data belongs in a storage bucket, not the versioned
dataset repo.

## Space migration

A Hugging Face Space is intentionally deferred. The present TMT runtime uses
MLX and the target Linux/accelerator runtime must be validated before a Space
can be considered parity-safe. No Space should be designated production until
runtime, persistence, rollback, and authority-gate behavior match the promoted
reference implementation.


## Current weight inventory

A recursive repository-tree inspection of the current authoritative GitHub
baseline found **no versioned model-weight/checkpoint files** matching common
weight formats such as:

- `.safetensors`
- `.ckpt`
- `.pt`
- `.pth`
- `.npz`
- model-weight `.bin` files

Therefore the present Hugging Face migration candidate is intentionally a
**code/reference-implementation mirror only**.

No placeholder or synthetic weights will be created. The future weight gate
starts only when an exact trained artifact is supplied, at which point GALIA
will require byte size, SHA-256, runtime/config binding, upload verification,
and a separate distribution receipt.


## Live Hugging Face connector state

ChatGPT's Hugging Face connector is authenticated as:

- account: `Junitos`;
- account type: user;
- app permission in ChatGPT: **Allow all actions**;
- OAuth scopes exposed by Hugging Face:
  `jobs`, `openid`, `profile`, `read-mcp`, `read-repos`.

Important distinction:

```text
CHATGPT_APP_PERMISSION = FULL_ACTIONS
HUGGING_FACE_OAUTH_SCOPE = READ_REPOS_ONLY
```

The ChatGPT permission setting governs whether ChatGPT may invoke connected
actions without asking. It does **not** add missing Hugging Face OAuth scopes.

Repository discovery confirmed that none of the following model repositories
currently exists under the authenticated namespace:

- `Junitos/galia-2`
- `Junitos/galia2`
- `Junitos/GALIA-2`

Therefore the next remote operation is necessarily repository creation, which
requires a Hugging Face credential with repository-write scope.

Current gate state:

```text
HF_REMOTE_CONNECTOR_AUTHENTICATED = PASS
HF_REMOTE_NAMESPACE               = Junitos
HF_REMOTE_TARGET_EXISTS           = NO
HF_REMOTE_WRITE_SCOPE             = HOLD
HF5_HUB_REPO_CREATE               = HOLD_AUTH_SCOPE
HF6_HUB_UPLOAD_AS_PR              = HOLD_AUTH_SCOPE
HF7_REMOTE_MANIFEST_COMPARE       = NOT_RUN
```

No token value is required from the user. The existing Hugging Face connection
must be re-authorized with repository-write scope; after that, the prepared
publisher can create the private model repo and verify the remote snapshot.
