## clean

Remove attestations or signatures using cosign

### Synopsis

Run cosign remove on an image or signature object to clean attestations/signatures.

This command wraps the cosign CLI. If registry credentials are provided they will
be used for authentication. The command converts your configured token into a key
and uses it where appropriate. Use --type to limit the cleanup to signatures,
attestations, SBOMs, or all.

```shell
devguard-scanner clean <image | signature-file> [flags]
```

### Examples

```shell
  # Remove all attestations and signatures from an image
  devguard-scanner clean ghcr.io/org/image:tag

  # Remove only attestations
  devguard-scanner clean --type attestation ghcr.io/org/image:tag

  # Remove only signatures
  devguard-scanner clean --type signature ghcr.io/org/image:tag
```

### Options

```shell
      --apiUrl string      The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string   The id of the asset which is scanned
  -h, --help               help for clean
  -p, --password string    The password to authenticate to the container registry (if required)
  -r, --registry string    The registry to authenticate to (optional)
      --token string       The personal access token to authenticate the request
      --type string        Type of clean to perform: signature|attestation|sbom|all (default "all")
  -u, --username string    The username to authenticate to the container registry (if required)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
