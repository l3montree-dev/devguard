---
title: DevGuard-Scanner sarif — Upload a SARIF report
description: Upload an existing SARIF report to DevGuard with devguard-scanner sarif to store findings from your own scanners without re-scanning the source files.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner sarif
lang: en-US
ignoreChecks: null
---

## sarif

Scan a SARIF report and upload results to DevGuard

### Synopsis

Upload a SARIF report to DevGuard. DevGuard reads the report and stores the findings —
it does NOT re-scan the files.

Use this if you already run your own static analysis scanner (e.g. CodeQL, Semgrep, Trivy, or
any other SARIF-producing tool) and just want to feed the results into DevGuard without using
the built-in 'sast' or 'iac' commands.

DevGuard compares the uploaded report against previous runs to detect new or resolved findings
and makes them visible in the DevGuard UI. The command returns the processed SARIF report on
stdout so you can chain it into other tools (e.g. 'sarif2markdown').

```shell
devguard-scanner sarif <sarif.json> [flags]
```

### Examples

```shell
  # Upload a SARIF report
  devguard-scanner sarif results.sarif.json

  # Upload and save the processed report
  devguard-scanner sarif results.sarif.json --outputPath uploaded-results.sarif.json

  # Upload with custom scanner ID for result tracking
  devguard-scanner sarif results.sarif.json --scannerID custom-scanner-v1
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                help for sarif
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --noWrite             Run the scan and display results without persisting anything to DevGuard.
      --output string       Output format for scan results. Options: 'table' (default), 'sarif' (enriched SARIF JSON). (default "table")
      --outputPath string   Path to save the SARIF report. If not specified, the report will only be uploaded to DevGuard.
      --path string         The path to the project to scan. Defaults to the current directory. (default ".")
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --scannerID string    Name of the scanner. DevGuard will compare new and old results based on the scannerID. (default "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sarif")
      --timeout int         Set the timeout for scanner operations in seconds (default 300)
      --token string        The personal access token to authenticate the request
      --webUI string        The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'. (default "https://app.devguard.org")
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
