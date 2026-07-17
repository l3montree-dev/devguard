## kyverno2sarif

Convert Kyverno test output to SARIF

### Synopsis

Convert the JSON output of 'kyverno test' into SARIF format so it can be uploaded to DevGuard
or consumed by any tool that understands SARIF (GitHub Code Scanning, VS Code, etc.).

Kyverno is a Kubernetes policy engine. Running 'kyverno test' validates your Kubernetes manifests
against your policies but only outputs results as JSON. This command bridges that gap by converting
those results into the standard SARIF format, which DevGuard (and most CI/CD platforms) can ingest.

Typical pipeline usage:
  kyverno test . --output-format json > kyverno-results.json
  devguard-scanner kyverno2sarif -i kyverno-results.json | devguard-scanner sarif -

```shell
devguard-scanner kyverno2sarif [flags]
```

### Examples

```shell
  # Convert Kyverno output to SARIF
  devguard-scanner kyverno2sarif -i kyverno-results.json

  # Save to file
  devguard-scanner kyverno2sarif -i kyverno-results.json -o sarif.json
```

### Options

```shell
  -h, --help            help for kyverno2sarif
  -i, --input string    Input file containing Kyverno test output (must be json format)
  -o, --output string   Output SARIF file (default: stdout)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
