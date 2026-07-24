---
title: DevGuard-Scanner discover-baseimage-attestations — fetch base image attestations
description: Read a Dockerfile's FROM line and download attestations such as SBOM and VEX documents attached to the base image using devguard-scanner.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner discover-baseimage-attestations
lang: en-US
ignoreChecks: null
---

## discover-baseimage-attestations

Download attestations (SBOM, VEX, …) for the base image used in a Dockerfile

### Synopsis

Read a Dockerfile or Containerfile, extract the FROM line (the base image), and download any
attestations attached to that base image.

This is the same operation as 'devguard-scanner attestations <image>' but instead of providing
the image reference manually, the command reads it from the FROM line of your Containerfile.

Use this when you want to inherit upstream security metadata from your base image as part of
your own build pipeline. For example, if your base image ships a VEX document that suppresses
a CVE, you can re-use it via 'devguard-scanner attest' instead of triaging the vulnerability
yourself. Each discovered attestation is saved as a separate JSON file in the output directory.

```shell
devguard-scanner discover-baseimage-attestations <path to containerfile> [flags]
```

### Examples

```shell
  # Download attestations for the base image of a Containerfile
  devguard-scanner discover-baseimage-attestations ./Containerfile

  # Filter to a specific predicate type (e.g. only VEX documents)
  devguard-scanner discover-baseimage-attestations ./Containerfile --predicateType https://cyclonedx.org/vex

  # Save to a custom output directory
  devguard-scanner discover-baseimage-attestations ./Containerfile --output ./attestations/
```

### Options

```shell
  -h, --help                   help for discover-baseimage-attestations
      --output string          Output directory to save the discovered attestations. (default ".")
      --predicateType string   Predicate type to filter attestations (e.g. 'https://cyclonedx.org/vex'). If empty, all predicate types are retrieved.
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
