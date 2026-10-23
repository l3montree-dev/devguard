---
title: DevGuard-Scanner intoto start — Snapshot pipeline step inputs
description: Record the cryptographic hashes of all input files at the beginning of a pipeline step, to be paired with intoto stop into a signed in-toto link.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner intoto start
lang: en-US
ignoreChecks: null
---

## intoto start

Snapshot input files at the beginning of a pipeline step

### Synopsis

Record the cryptographic hashes of all input files (materials) before a pipeline step runs.

Use this when your step is not a single command — for example, a multi-line build script. Call
'intoto start' before the step and 'intoto stop' after it. The pair together produce a signed
in-toto link that proves which files went in and which came out.

If your entire step is a single command, use 'intoto run' instead.

```shell
devguard-scanner intoto start [flags]
```

### Examples

```shell
  # In a CI job: snapshot inputs before the build
  devguard-scanner intoto start --step build --apiUrl https://api.devguard.org --assetName org/project/app --token $TOKEN
```

### Options

```shell
  -h, --help   help for start
```

### Options inherited from parent commands

```shell
      --apiUrl string            The devguard api url
      --assetName string         The asset name to use
      --generateSlsaProvenance   Generate SLSA provenance for the in-toto link. The provenance will be stored in <stepname>.provenance.json. It will be signed using the intoto token.
      --ignore stringArray       The ignore patterns for the in-toto link (default [.git/**/*])
  -l, --logLevel string          Set the log level. Options: debug, info, warn, error (default "info")
      --materials stringArray    The materials to include in the in-toto link. Default is the current directory (default [.])
      --products stringArray     The products to include in the in-toto link. Default is the current directory (default [.])
      --step string              The name of the in-toto link
      --supplyChainId string     The supply chain id to use. If empty, tries to extract the current commit hash.
      --token string             The token to use for in-toto
```
