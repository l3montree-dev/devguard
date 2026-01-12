## sarif

Scan a SARIF report and upload results to DevGuard

### Synopsis

Upload a SARIF-formatted static analysis report to DevGuard for processing and result comparison.

The command signs the request using the configured token and returns scan results.

```shell
devguard-scanner sarif <sarif.json> [flags]
```

### Examples

```shell
  # Upload a SARIF report
  devguard-scanner sarif results.sarif.json

  # Upload and save the processed report
  devguard-scanner sarif results.sarif.json --outputPath uploaded-results.sarif.json

  # Upload with custom scanner ID for result tracking
  devguard-scanner sarif results.sarif.json --scannerID custom-scanner-v1
```

### Options

```shell
      --apiUrl string       The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string    The id of the asset which is scanned
      --defaultRef string   The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.
  -h, --help                help for sarif
      --isTag               If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.
      --outputPath string   Path to save the SARIF report. If not specified, the report will only be uploaded to DevGuard.
      --path string         The path to the project to scan. Defaults to the current directory. (default ".")
      --ref string          The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.
      --scannerID string    Name of the scanner. DevGuard will compare new and old results based on the scannerID. (default "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sarif")
      --timeout int         Set the timeout for scanner operations in seconds (default 300)
      --token string        The personal access token to authenticate the request
      --webUI string        The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'. (default "https://app.devguard.org")
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
