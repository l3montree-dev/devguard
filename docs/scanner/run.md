---
title: DevGuard-Scanner intoto run — Record a single-command step
description: Run a pipeline step as a single command, snapshot input and output file hashes around it, sign the resulting in-toto link and upload it to DevGuard.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner intoto run
lang: en-US
ignoreChecks: null
---

## intoto run

Record a single-command pipeline step and upload the signed link

### Synopsis

Run a pipeline step as a single command, snapshot input and output file hashes around it,
sign the resulting link with the DevGuard token, and upload it to DevGuard.

Use this when your entire step is one command (e.g. 'make build'). If your step involves
multiple commands, use 'intoto start' + 'intoto stop' instead.

```shell
devguard-scanner intoto run [flags]
```

### Examples

```shell
  # Record a build step that runs 'make build'
  devguard-scanner intoto run --step build --apiUrl https://api.devguard.org --assetName org/project/app --token $TOKEN
```

### Options

```shell
      --apiUrl string                    The URL of the devguard API
      --defaultRef string                The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                             help for run
      --isTag                            If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --ref string                       The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --step string                      The step to run
      --supplyChainOutputDigest string   If defined, sends this digest to devguard. This should be the digest of the whole supply chain.
```

### Options inherited from parent commands

```shell
      --assetName string         The asset name to use
      --generateSlsaProvenance   Generate SLSA provenance for the in-toto link. The provenance will be stored in <stepname>.provenance.json. It will be signed using the intoto token.
      --ignore stringArray       The ignore patterns for the in-toto link (default [.git/**/*])
  -l, --logLevel string          Set the log level. Options: debug, info, warn, error (default "info")
      --materials stringArray    The materials to include in the in-toto link. Default is the current directory (default [.])
      --products stringArray     The products to include in the in-toto link. Default is the current directory (default [.])
      --supplyChainId string     The supply chain id to use. If empty, tries to extract the current commit hash.
      --token string             The token to use for in-toto
```
