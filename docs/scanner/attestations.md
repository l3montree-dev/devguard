## attestations

Discover attestations for an image and optionally evaluate a rego policy

### Synopsis

Retrieve all attestations (metadata documents) attached to a container image and optionally evaluate them against a Rego policy.

Attestations are documents attached to the image during its build pipeline — for example an SBOM,
a VEX document (vulnerability exceptions), or SARIF security scan results. Each attestation has a
predicate type (a URI) that identifies its kind. The policy receives all discovered attestations
and can match against specific predicate types to check that required metadata is present.

Example Rego policy that requires an SBOM and a VEX document:

  package devguard

  import future.keywords.if
  import future.keywords.in

  deny[msg] if {
    not has_attestation("https://cyclonedx.org/bom")
    msg := "Image is missing a CycloneDX SBOM attestation"
  }

  deny[msg] if {
    not has_attestation("https://cyclonedx.org/vex")
    msg := "Image is missing a VEX document"
  }

  has_attestation(predicate_type) if {
    some att in input.attestations
    att.predicateType == predicate_type
  }

The command exits with code 1 if any deny rule fires — making it suitable as a deployment gate.

```shell
devguard-scanner attestations <oci@SHA> [flags]
```

### Examples

```shell
  # List all attestations attached to an image
  devguard-scanner attestations ghcr.io/org/image:tag

  # Evaluate against a Rego policy (exits 1 if policy fails)
  devguard-scanner attestations ghcr.io/org/image:tag --policy policy.rego

  # Save evaluation results as SARIF for upload to DevGuard
  devguard-scanner attestations ghcr.io/org/image:tag --policy policy.rego --format sarif --outputPath report.sarif.json
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
      --format string       Format of the report to generate (plain, sarif). Default is plain (default "plain")
  -h, --help                help for attestations
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --outputPath string   Path to save the generated report. If not provided, the report is only printed.
  -p, --policy string       check the images attestations against policy
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --token string        The personal access token to authenticate the request
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
