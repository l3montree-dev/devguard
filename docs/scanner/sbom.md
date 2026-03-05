## sbom

Scan a CycloneDX SBOM for vulnerabilities

### Synopsis

Scan a CycloneDX Software Bill of Materials (SBOM) and upload it to DevGuard for vulnerability analysis.

Only CycloneDX-formatted SBOMs are supported. Pass a file path, '-' to read from stdin, or omit the argument to read from stdin.

```shell
devguard-scanner sbom [sbom.json|-] [flags]
```

### Examples

```shell
  # Scan a CycloneDX SBOM from a file
  devguard-scanner sbom my-bom.json

  # Scan from stdin (pipe from merge-sboms)
  devguard-scanner merge-sboms config.json | devguard-scanner sbom -

  # Scan with custom asset name
  devguard-scanner sbom my-bom.json --assetName my-app --token YOUR_TOKEN

  # Fail on high risk vulnerabilities
  devguard-scanner sbom my-bom.json --failOnRisk high
```

### Options

```shell
      --apiUrl string                   The url of the API to send the scan request to (default "https://api.devguard.org")
      --artifactName string             The name of the artifact which was scanned. If not specified, it will default to the empty artifact name ''.
      --assetName string                The id of the asset which is scanned
      --defaultRef string               The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
      --failOnCVSS string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
      --failOnRisk string               The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'. (default "critical")
  -h, --help                            help for sbom
      --ignoreExternalReferences        If an attestation does contain a external reference to an sbom or vex, this will be ignored. Useful when scanning your own image from the registry where your own attestations are attached.
      --isTag                           If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --keepOriginalSbomRootComponent   Use this flag if you get software from a supplier and you want to identify vulnerabilities in the root component itself, not only in the dependencies
      --origin string                   Origin of the SBOM (how it was generated). Examples: 'source-scanning', 'container-scanning', 'base-image'. Default: 'container-scanning'. (default "DEFAULT")
      --ref string                      The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --timeout int                     Set the timeout for scanner operations in seconds (default 300)
      --token string                    The personal access token to authenticate the request
      --webUI string                    The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'. (default "https://app.devguard.org")
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
