---
title: DevGuard-Scanner iac — Infrastructure-as-Code scan
description: Run an Infrastructure-as-Code scan with devguard-scanner iac to check Terraform, CloudFormation, and Kubernetes manifests for misconfigurations and upload SARIF results to DevGuard.
seo:
    robots: index,follow
    og:
        image: /og-image.png
        type: article
    schema:
        type: TechArticle
    keyword_primary: devguard-scanner iac
lang: en-US
ignoreChecks: null
---

## iac

Run an Infrastructure-as-Code (IaC) scan

### Synopsis

Run an Infrastructure-as-Code scan (e.g. checkov) against a repository or path and upload SARIF results to DevGuard.

This command scans Terraform, CloudFormation, Kubernetes manifests, and other IaC
files for security issues and misconfigurations.

Any flags after a "--" separator are forwarded verbatim to the underlying checkov invocation.
See the checkov CLI reference for available flags: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html

```shell
devguard-scanner iac [path] [flags]
```

### Examples

```shell
  # Scan Terraform directory
  devguard-scanner iac ./terraform

  # Scan with custom path flag
  devguard-scanner iac --path ./terraform

  # Scan and save results locally
  devguard-scanner iac ./terraform --outputPath iac-results.sarif.json

  # Forward extra flags to checkov
  devguard-scanner iac ./terraform -- --skip-check CKV_AWS_20
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                help for iac
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
