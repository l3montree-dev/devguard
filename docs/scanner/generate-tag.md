---
title: DevGuard-Scanner generate-tag — build a container image tag from metadata
description: Generate a container image tag, artifact name, and URL-encoded artifact name from build parameters like version, ref, and architecture with devguard-scanner.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner generate-tag
lang: en-US
ignoreChecks: null
---

## generate-tag

Generate a tag for an image based on its contents

### Synopsis

Generate a container image tag, artifact name, and URL-encoded artifact name.

The tag is assembled from the provided parameters in the following order:
  [<upstreamVersion>-][<ref>-][<imageVariant>-][<architecture>]

All parts are optional. Omit --architecture to get a plain version tag (e.g. "21" instead of "21-amd64").
Use --imageSuffix to produce multiple images from a single build (e.g. java-base and java-debian).
The ref flag is typically set from $CI_COMMIT_REF_SLUG; forward slashes are replaced with hyphens.

The command prints three lines to stdout:
  IMAGE_TAG=<full image reference including tag>
  ARTIFACT_NAME=<purl>
  ARTIFACT_URL_ENCODED=<url-encoded purl>

```shell
devguard-scanner generate-tag [flags]
```

### Examples

```shell
  # If you want to tag an image with its upstream version and the target architecture:
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/org/app
  # → registry.io/org/app:1.2.3-amd64

  # If you want the current branch or ref included in the tag (e.g. to distinguish nightly builds):
  devguard-scanner generate-tag --upstreamVersion 1.2.3 --architecture amd64 --imagePath registry.io/org/app --ref main
  # → registry.io/org/app:1.2.3-main-amd64

  # If you are building multiple images in a single repository (e.g. different base OS flavours),
  # call generate-tag once per image and vary --imageSuffix to give each image a unique name:
  devguard-scanner generate-tag --upstreamVersion 21 --imagePath registry.io/org --imageSuffix java-base
  devguard-scanner generate-tag --upstreamVersion 21 --imagePath registry.io/org --imageSuffix java-debian
  # → registry.io/org/java-base:21
  # → registry.io/org/java-debian:21

  # If you want to distinguish image flavours within the same image (e.g. alpine vs. full):
  devguard-scanner generate-tag --upstreamVersion 2.0.0 --architecture arm64 --imageVariant alpine --imagePath registry.io/org/app
  # → registry.io/org/app:2.0.0-alpine-arm64
```

### Options

```shell
      --architecture string      Target architecture(s) for the image (required). Can be specified multiple times or as comma-separated values. (default "amd64")
      --defaultRef string        The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                     help for generate-tag
      --imagePath string         Path to the image file (required)
      --imageSuffix string       Suffix to append to the image tag
      --imageVariant string      Type of the image (e.g., minimal, full, alpine)
      --isTag                    If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --ref string               The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --upstreamVersion string   Upstream version of the software
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
