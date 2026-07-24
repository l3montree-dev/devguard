---
title: DevGuard-Scanner auth — Verify and store a token
description: Verify a DevGuard personal access token and store it in the OS keyring with devguard-scanner auth so you no longer need to pass --token on every command.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner auth
lang: en-US
ignoreChecks: null
---

## auth

Verify a DevGuard token and store it in the system keyring

### Synopsis

Verify a DevGuard personal access token and store it in the OS keyring so you do not have to
pass --token on every command.

This is the recommended setup for developer machines and git hooks. In CI pipelines, prefer the
DEVGUARD_TOKEN environment variable instead so the token is not written to disk.

Once stored, all devguard-scanner commands will automatically pick up the token from the keyring.

```shell
devguard-scanner auth [flags]
```

### Examples

```shell
  # One-time setup on a developer machine
  devguard-scanner auth --token <hex-token> --assetName org/project/asset --apiUrl https://api.devguard.org

  # Print a previously stored token, e.g. to forward it into a Docker container
  docker run --rm -e DEVGUARD_TOKEN="$(devguard-scanner auth --print-token --assetName org/project/asset --apiUrl https://api.devguard.org)" your-image scan
```

### Options

```shell
      --apiUrl string      The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string   The id of the asset which is scanned (required)
  -h, --help               help for auth
      --print-token        Print a previously stored token from the keyring instead of storing a new one
      --token string       The personal access token to authenticate the request (required unless --print-token is set)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
