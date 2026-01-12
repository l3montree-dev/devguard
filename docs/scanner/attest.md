## attest

Create and upload an attestation for an image or artifact

### Synopsis

Create and upload an attestation for an OCI image or a local predicate file.

The first argument is a path to a local predicate JSON file that will be used as
the attestation payload. Optionally provide a container image reference as the
second argument to attach the attestation to that image.

This command validates the predicate file exists, signs the upload using the
configured token, and sends it to the DevGuard backend. The HTTP header
X-Predicate-Type is populated from the --predicateType flag (required).

```shell
devguard-scanner attest <predicate> [container-image] [flags]
```

### Examples

```shell
  # Attest a container image with a VEX predicate
  devguard-scanner attest vex.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Attest with SLSA provenance
  devguard-scanner attest provenance.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Upload attestation without attaching to an image
  devguard-scanner attest predicate.json --predicateType https://example.com/custom/v1
```

### Options

```shell
      --apiUrl string          The url of the API to send the scan request to (default "https://api.devguard.org")
      --artifactName string    The name of the artifact which was scanned. If empty, a name will be generated from the asset name.
      --assetName string       The id of the asset which is scanned
      --defaultRef string      The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                   help for attest
      --isTag                  If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
  -p, --password string        The password to authenticate to the container registry (if required)
  -a, --predicateType string   The predicate type (URI) for the attestation, e.g. https://slsa.dev/provenance/v1 or https://cyclonedx.org/vex/1.0
      --ref string             The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
  -r, --registry string        The registry to authenticate to (optional)
      --token string           The personal access token to authenticate the request
  -u, --username string        The username to authenticate to the container registry (if required)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
