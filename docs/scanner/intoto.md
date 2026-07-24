---
title: DevGuard-Scanner intoto — Record and verify supply chain steps
description: Record and verify software supply chain steps with in-toto, capturing signed cryptographic evidence at each stage of your CI pipeline and uploading it to DevGuard.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner intoto
lang: en-US
ignoreChecks: null
---

## intoto

Record and verify software supply chain steps using in-toto

### Synopsis

In-toto is an open standard for proving that your software was built the way you claim.
It works by recording cryptographic evidence (called "links") at each step of your pipeline —
for example: checkout, build, test, package. Each link is signed with the DevGuard token and
uploaded to DevGuard automatically.

DevGuard collects all links for a supply chain ID (typically the git commit hash) and can verify
that all required steps actually ran, in the right order, by the right actor, on the right files.
DevGuard knows all links are present when it receives the deploy link with a
--supplyChainOutputDigest attached. The verification result is then queryable by automated
deployment gates (OPA, admission webhooks, CI quality gates) via:

  GET /api/v1/organizations/<assetName>/in-toto/verify?supplyChainId=<commitHash>&supplyChainOutputDigest=<imageDigest>

NOTE: These commands are intended to be used by devguard-ci-components, not directly by end users.
The devguard-ci-components project provides pre-built CI templates (GitLab CI, GitHub Actions) that
chain the start/run/stop/verify steps correctly, including the pre-commit hook integration.
End users should never need to call these commands manually.

Typical pipeline usage:
  1. devguard-scanner intoto start  — snapshot input files at the beginning of a step
  2. <run your actual build/test/etc command>
  3. devguard-scanner intoto stop   — snapshot output files and upload the signed link to DevGuard
  4. On the final step, pass --supplyChainOutputDigest=<imageDigest> — this signals to DevGuard
     that all links for this supply chain ID are complete and triggers automatic verification.

DevGuard enforces a fixed three-step pipeline layout:
  post-commit  triggered by a git post-commit hook on the developer's machine; records the
               committed source files and proves which code actually entered the pipeline
  build        CI step; inputs must match post-commit output (proving the build used the
               exact committed source), records which artifacts came out
  deploy       CI step; inputs must match build output, requires image-digest.txt to be present

The layout enforces that each step's inputs match the previous step's outputs, so any tampering
between steps is detectable. DevGuard knows all links are present when it receives the deploy
link with a --supplyChainOutputDigest attached.

### Options

```shell
      --apiUrl string            The devguard api url
      --assetName string         The asset name to use
      --generateSlsaProvenance   Generate SLSA provenance for the in-toto link. The provenance will be stored in <stepname>.provenance.json. It will be signed using the intoto token.
  -h, --help                     help for intoto
      --ignore stringArray       The ignore patterns for the in-toto link (default [.git/**/*])
      --materials stringArray    The materials to include in the in-toto link. Default is the current directory (default [.])
      --products stringArray     The products to include in the in-toto link. Default is the current directory (default [.])
      --step string              The name of the in-toto link
      --supplyChainId string     The supply chain id to use. If empty, tries to extract the current commit hash.
      --token string             The token to use for in-toto
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
