# HF8 Reproducible Retraining v0.2

Status: **EXPERIMENTAL / STAGING ONLY / NO PROMOTION**

v0.2 replaces the v0.1 corpus approximation with a training regime that matches
the upstream TMT runtime much more closely.

## Upstream behavior reproduced

The upstream `Runtime.train()`:

1. reads `wikipedia_clean/**/wiki_*`;
2. performs one `random.shuffle(files)`;
3. cycles through those files indefinitely;
4. opens each file as UTF-8 with `errors="ignore"`;
5. trains line by line;
6. trains byte-by-byte using adjacent byte pairs;
7. keeps recurrent state across line and file boundaries;
8. marks only the last byte pair of each line with `end=True`.

v0.2 implements those semantics explicitly.

## Dataset preparation

Source dump:

`simplewiki-20260801-pages-articles.xml.bz2`

Expected source SHA-256:

`441fb855b3d907afe605b00482968e894b94798ffbe870c24be09c4e500edacb`

Cleaner:

`WikiExtractor==3.1.0`

Pinned wheel SHA-256:

`de6585ecac14fe290dd64feadfa3dec01e11052bce545a5d201aecd55ab6d09e`

WikiExtractor is run in its normal text-document output mode, creating the
`wiki_*` file layout expected by the upstream TMT training loop.

## Deterministic split

A single deterministic file shuffle uses seed `1976`.

- 90% of shuffled `wiki_*` files: training
- 10%: held-out evaluation

The held-out files are never passed to the optimizer.

The file lists and every extracted `wiki_*` file are SHA-256 recorded in the
dataset manifest.

## Compute backend

A direct 1,000-step probe on the exact 4.5M-class model measured:

- macOS arm64: about 27.85 steps/s
- Linux x86_64 CPU: about 22.30 steps/s

Therefore v0.2 uses the GitHub-hosted `macos-14` arm64 runner for model
training.

The throughput probe is benchmark-only and its temporary model is never
eligible for HF8 promotion.

## Initial v0.2 bootstrap

The first v0.2 run performs:

- 4,000 optimizer steps from fresh initialization;
- authoritative GALIA checkpoint save;
- `CURRENT_BOUND` verification;
- held-out frozen evaluation on 4,096 byte pairs;
- trainable-parameter identity verification;
- checkpoint-file identity verification;
- staging to `Junitos/galia-2@hf8-retrain-v0.2`;
- independent remote byte/hash reread.

No v0.2 artifact is promoted automatically.

## v0.1 status

The v0.1 4k and 20k checkpoints remain valid historical experiment artifacts,
but they are **not quality candidates** because v0.1 trained on a deterministic
prefix extracted by a custom XML normalizer rather than the upstream-style
`wiki_*` file stream.

The verified v0.1 20k artifact remains preserved with payload SHA-256:

`fbc7d18bdfd2f9c68c630c77e8123d4eb941acc7878bef87fbff5496a268f23b`

It must not be promoted as the HF8 production weight candidate.
