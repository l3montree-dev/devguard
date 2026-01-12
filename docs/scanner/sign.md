## sign

Sign a file or image

### Synopsis

Sign a file or OCI image using cosign.

When not run with --offline the command will upload the public key to DevGuard
before creating the signature. The public key upload is signed using the
configured token. The actual signing is performed by the cosign CLI.

```shell
devguard-scanner sign <file | image> [flags]
```

### Examples

```shell
  # Sign a local file
  devguard-scanner sign ./artifact.bin

  # Sign a container image
  devguard-scanner sign ghcr.io/org/image:tag

  # Sign without uploading public key to DevGuard
  devguard-scanner sign ./artifact.bin --offline
```

### Options

```shell
      --apiUrl string      The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string   The id of the asset which is scanned
  -h, --help               help for sign
  -o, --offline            If set, the scanner will not attempt to upload the signing key to devguard
  -p, --password string    The password to authenticate to the container registry (if required)
  -r, --registry string    The registry to authenticate to (optional)
      --token string       The personal access token to authenticate the request
  -u, --username string    The username to authenticate to the container registry (if required)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
