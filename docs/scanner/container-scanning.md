---
title: DevGuard-Scanner container-scanning — Container image SCA
description: Run software composition analysis on a container image with devguard-scanner container-scanning, generating or uploading an SBOM that DevGuard analyzes for vulnerabilities.
seo:
  robots: index,follow
  og:
    image: /og-image.png
    type: article
  schema:
    type: TechArticle
  keyword_primary: devguard-scanner container-scanning
lang: en-US
ignoreChecks: null
---

## container-scanning

Software composition analysis of a container image

### Synopsis

Scan a container image for vulnerabilities. The image must either be a tar file (--path)
or be available for download via a container registry (--image). The command generates or
uploads an SBOM which is then analyzed by DevGuard. The request is signed using the
configured token before upload.

```shell
devguard-scanner container-scanning [flags]
```

### Examples

```shell
  # Scan a container image from registry
  devguard-scanner container-scanning --image ghcr.io/org/image:tag

  # Scan a container image tar file
  devguard-scanner container-scanning --path image.tar

  # Scan and ignore upstream attestations
  devguard-scanner container-scanning --image ghcr.io/org/image:tag --ignoreUpstreamAttestations
```

### Options

```shell
      --apiUrl string                   The url of the API to send the scan request to (default "https://api.devguard.org")
      --artifactName string             The name of the artifact which was scanned. If not specified, it will default to the empty artifact name ''.
      --assetName string                The id of the asset which is scanned
      --defaultRef string               The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
      --failOnCVSS string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
      --failOnRisk string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
  -h, --help                            help for container-scanning
      --ignoreExternalReferences        If an attestation does contain a external reference to an sbom or vex, this will be ignored. Useful when scanning your own image from the registry where your own attestations are attached.
      --ignoreUpstreamAttestations      Ignores attestations from the scanned container image - if they exists
      --image string                    OCI image reference to scan (e.g. ghcr.io/org/image:tag). If empty, --path or the first argument may be used to provide a tar or local files.
      --isTag                           If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --keepOriginalSbomRootComponent   Deprecated, does nothing: the original SBOM root component is now always kept when it has a valid PackageURL.
      --noWrite                         Run the scan and display results (including VEX/false-positive assessments) without persisting anything to DevGuard.
      --origin string                   Origin of the SBOM (how it was generated). Examples: 'source-scanning', 'container-scanning', 'base-image'. Default: 'container-scanning'. (default "DEFAULT")
      --output string                   Output format for scan results. Options: 'table' (default), 'cyclonedx' (CycloneDX VEX JSON). (default "table")
      --path string                     Path to a tar file or directory containing the container image to scan. If empty, --image must be provided or an argument.
      --ref string                      The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --sbomOutputPath string           If set, write the final (merged) SBOM to this file path in addition to uploading it.
      --sbomPath string                 Path to scan for supplementary SBOM json files to merge into the scan results. A directory when scanning a path, an absolute path inside the image filesystem when scanning a container image. Each supplementary SBOM's root component name must match the exact in-image/in-project path of the application it describes, so that DevGuard can attach it under the right node and silence the 'unresolved application' warning for it. (default "/sboms")
      --timeout int                     Set the timeout for scanner operations in seconds (default 300)
      --token string                    The personal access token to authenticate the request
      --webUI string                    The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'. (default "https://app.devguard.org")
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
