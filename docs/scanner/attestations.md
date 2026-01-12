## attestations

Discover attestations for an image and optionally evaluate a rego policy

### Synopsis

Retrieve and validate security attestations for container images used in Helm charts or other deployment workflows.

It automates what is normally a manual, time-consuming process of verifying that each image is properly hardened and accompanied by essential metadata such as SBOM, VEX, and SARIF.

```shell
devguard-scanner attestations <oci@SHA> [flags]
```

### Examples

```shell
  # Discover attestations for an image
  devguard-scanner attestations ghcr.io/org/image:tag

  # Evaluate against a rego policy
  devguard-scanner attestations ghcr.io/org/image:tag --policy path/to/file.rego

  # Save policy evaluation results as SARIF
  devguard-scanner attestations ghcr.io/org/image:tag --policy path/to/file.rego --outputPath report.sarif.json
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                help for attestations
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --outputPath string   Path to save the generated SARIF report. If not provided, the report is only printed.
  -p, --policy string       check the images attestations against policy
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --token string        The personal access token to authenticate the request
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
