## kyverno2sarif

Convert Kyverno test output to SARIF

### Synopsis

Convert Kyverno policy test output to SARIF format.

This allows Kyverno test results to be uploaded to DevGuard and integrated with other security scanning tools.

```shell
devguard-scanner kyverno2sarif [flags]
```

### Examples

```shell
  # Convert Kyverno output to SARIF
  devguard-scanner kyverno2sarif -i kyverno-results.txt

  # Save to file
  devguard-scanner kyverno2sarif -i kyverno-results.txt -o results.sarif.json
```

### Options

```shell
  -h, --help            help for kyverno2sarif
  -i, --input string    Input file containing Kyverno test output
  -o, --output string   Output SARIF file (default: stdout)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
