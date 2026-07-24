---
title: DevGuard-Scanner secret-scanning — detect leaked secrets in source code
description: Scan a repository or directory for accidentally committed secrets using gitleaks and upload the SARIF results to DevGuard with devguard-scanner.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner secret-scanning
lang: en-US
ignoreChecks: null
---

## secret-scanning

Detect leaked secrets in source code

### Synopsis

Scan a repository or directory for accidentally committed secrets and produce a SARIF report.

This command runs the configured secret-scanning tool (gitleaks) and uploads the
SARIF results to DevGuard for analysis and issue creation. The command signs the
request using the configured token before uploading the SARIF results.

You may pass the target as the first positional argument instead of using --path.

Any flags after a "--" separator are forwarded verbatim to the underlying gitleaks invocation.
See the gitleaks CLI reference for available flags: https://github.com/gitleaks/gitleaks#usage

```shell
devguard-scanner secret-scanning [path] [flags]
```

### Examples

```shell
  # Scan current repository for secrets
  devguard-scanner secret-scanning ./my-repo

  # Scan with custom path flag
  devguard-scanner secret-scanning --path ./my-repo

  # Scan and save output locally
  devguard-scanner secret-scanning ./my-repo --outputPath secrets.sarif.json

  # Forward extra flags to gitleaks
  devguard-scanner secret-scanning ./my-repo -- --max-target-megabytes 50
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
      --dir                 Scan a directory instead of the git history.
  -h, --help                help for secret-scanning
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --noWrite             Run the scan and display results without persisting anything to DevGuard.
      --output string       Output format for scan results. Options: 'table' (default), 'sarif' (enriched SARIF JSON). (default "table")
      --outputPath string   Path to save the SARIF report. If not specified, the report will only be uploaded to DevGuard.
      --path string         The path to the project to scan. Defaults to the current directory. (default ".")
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --timeout int         Set the timeout for scanner operations in seconds (default 300)
      --token string        The personal access token to authenticate the request
      --webUI string        The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'. (default "https://app.devguard.org")
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
