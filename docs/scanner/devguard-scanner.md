## devguard-scanner

Secure your Software Supply Chain

### Synopsis

Secure your Software Supply Chain

DevGuard Scanner is a small CLI to help generate, sign and upload SBOMs, SARIF
reports and attestations to a DevGuard backend. Use commands like 'sca', 'sarif',
and 'attest' to interact with the platform. Configuration can be provided via a
./.devguard config file or environment variables (prefix DEVGUARD_).

### Examples

```shell
  # Run Software Composition Analysis on a container image
  devguard-scanner sca ghcr.io/org/image:tag

  # Run SCA on a local project directory
  devguard-scanner sca ./path/to/project

  # Create and upload an attestation
  devguard-scanner attest predicate.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Upload a SARIF report
  devguard-scanner sarif results.sarif.json
```

### Options

```shell
  -h, --help              help for devguard-scanner
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
  -t, --toggle            Help message for toggle
```
