---
title: DevGuard-Scanner provenance generate — Generate SLSA build provenance
description: Generate unsigned SLSA v1 build provenance for the artifacts of a CI run with devguard-scanner provenance generate.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner provenance generate
lang: en-US
ignoreChecks: null
---

## provenance generate

Generate unsigned SLSA build provenance for 'devguard-scanner provenance sign'

### Synopsis

Generate an in-toto statement with a SLSA v1 provenance predicate for the artifacts a CI run built.

The statement only contains what the CI job knows itself: the built artifacts (subjects), the inputs
the workflow was called with and when the build ran. Everything describing the build platform - the
builder, the workflow, the source commit - is set by DevGuard from the verified workload identity
token when signing with 'devguard-scanner provenance sign'.

Container images are passed with --image as image references with their manifest digest, so the
provenance matches the image it is attached to. Files, e.g. release tarballs, are passed with --path,
hashed and recorded under their file name. Both take a comma separated list.

```shell
devguard-scanner provenance generate [flags]
```

### Examples

```shell
  # Generate, sign and attach provenance for an image
  IMAGE_DIGEST=$(crane digest ghcr.io/org/image:1.2.3)
  devguard-scanner provenance generate --image ghcr.io/org/image@$IMAGE_DIGEST \
    --input target=ociImage \
    --startedOn "$BUILD_STARTED_ON" --finishedOn "$BUILD_FINISHED_ON" \
    | devguard-scanner provenance sign - --output provenance.dsse.json
  devguard-scanner attest provenance.dsse.json ghcr.io/org/image@$IMAGE_DIGEST --predicateType https://slsa.dev/provenance/v1

  # Generate provenance for release tarballs
  devguard-scanner provenance generate --path dist/app-linux-amd64.tar.gz,dist/app-darwin-arm64.tar.gz -o provenance.json
```

### Options

```shell
      --finishedOn string   When the build finished, as RFC3339 timestamp.
  -h, --help                help for generate
      --image string        Comma separated built images as references with digest, e.g. ghcr.io/org/image@sha256:<digest>.
      --input stringArray   An input the workflow was called with as key=value. Recorded at predicate.buildDefinition.externalParameters.inputs. Can be repeated.
  -o, --output string       File to write the provenance to. Defaults to stdout.
      --path string         Comma separated built files to hash, e.g. release tarballs. Recorded under their file name.
      --startedOn string    When the build started, as RFC3339 timestamp.
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
