---
title: DevGuard-Scanner intoto stop — Snapshot outputs and upload the link
description: Record the cryptographic hashes of all output files at the end of a pipeline step, sign the in-toto link with the DevGuard token and upload it to DevGuard.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner intoto stop
lang: en-US
ignoreChecks: null
---

## intoto stop

Snapshot output files at the end of a pipeline step and upload the signed link

### Synopsis

Record the cryptographic hashes of all output files (products) after a pipeline step finishes,
sign the link with the DevGuard token, and upload it to DevGuard.

This is the second half of the start/stop pair. The signed link proves which files existed before
and after this step, and that this specific token (CI identity) performed it.

```shell
devguard-scanner intoto stop [flags]
```

### Examples

```shell
  # In a CI job: snapshot outputs and upload after the build
  devguard-scanner intoto stop --step build --apiUrl https://api.devguard.org --assetName org/project/app --token $TOKEN
```

### Options

```shell
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                help for stop
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --output string       The output file name. Default is the <step>.link.json name
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
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
