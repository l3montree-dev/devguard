## sca

Run Software Composition Analysis (SCA)

### Synopsis

Run a Software Composition Analysis (SCA) for a project or container image.

This command can accept either an OCI image reference (e.g. ghcr.io/org/image:tag) via
--image or as the first positional argument, or a local path/tar file via --path or as
the first positional argument. The command will generate or accept an SBOM, upload it to
DevGuard and return vulnerability results.

Any flags after a "--" separator are forwarded verbatim to the underlying trivy invocation.
See the trivy CLI reference for available flags: https://trivy.dev/docs/latest/guide/references/configuration/cli/trivy/

```shell
devguard-scanner sca [image|path] [flags]
```

### Examples

```shell
  # Scan a container image
  devguard-scanner sca ghcr.io/org/image:tag

  # Scan a local project directory
  devguard-scanner sca ./path/to/project

  # Scan with custom asset name
  devguard-scanner sca --image ghcr.io/org/image:tag --assetName my-app --token YOUR_TOKEN

  # Scan and fail on high risk vulnerabilities
  devguard-scanner sca ./project --failOnRisk high

  # Forward extra flags to trivy
  devguard-scanner sca ./project -- --skip-dirs vendor --timeout 10m
```

### Options

```shell
      --apiUrl string                   The url of the API to send the scan request to (default "https://api.devguard.org")
      --artifactName string             The name of the artifact which was scanned. If not specified, it will default to the empty artifact name ''.
      --assetName string                The id of the asset which is scanned
      --defaultRef string               The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
      --failOnCVSS string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
      --failOnRisk string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
  -h, --help                            help for sca
      --ignoreExternalReferences        If an attestation does contain a external reference to an sbom or vex, this will be ignored. Useful when scanning your own image from the registry where your own attestations are attached.
      --isTag                           If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --keepOriginalSbomRootComponent   Deprecated, does nothing: the original SBOM root component is now always kept when it has a valid PackageURL.
      --noWrite                         Run the scan and display results (including VEX/false-positive assessments) without persisting anything to DevGuard.
      --origin string                   Origin of the SBOM (how it was generated). Examples: 'source-scanning', 'container-scanning', 'base-image'. Default: 'container-scanning'. (default "DEFAULT")
      --output string                   Output format for scan results. Options: 'table' (default), 'cyclonedx' (CycloneDX VEX JSON). (default "table")
      --path string                     Path to the project directory or tar file to scan. If empty, the first argument must be provided.
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
