---
title: DevGuard-Scanner merge-sboms — combine multiple SBOMs into one
description: Merge multiple CycloneDX SBOMs from independently scanned components into a single combined SBOM ready to upload to DevGuard with devguard-scanner.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner merge-sboms
lang: en-US
ignoreChecks: null
---

## merge-sboms

Merge multiple SBOMs into one SBOM

### Synopsis

Merge multiple CycloneDX SBOMs into a single combined SBOM.

If you are building a product that consists of several independently scanned components
(for example a frontend, a backend, and a set of shared libraries each with their own SBOM),
use this command to combine them into one SBOM before uploading to DevGuard.

The command reads a JSON config file that lists the component PURLs and SBOM file paths,
and writes the merged SBOM to stdout. Pipe the output directly into 'devguard-scanner sbom'.

Config file format:
  { "purl": "pkg:oci/my-app@1.2.3", "sboms": ["frontend.sbom.json", "backend.sbom.json"] }

```shell
devguard-scanner merge-sboms <config file> [flags]
```

### Examples

```shell
  # Merge SBOMs using config file
  devguard-scanner merge-sboms config.json

  # Redirect output to file
  devguard-scanner merge-sboms config.json > merged-sbom.json
```

### Options

```shell
  -h, --help   help for merge-sboms
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
