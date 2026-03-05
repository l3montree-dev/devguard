## inspect

Inspect PURL for matching CVEs and vulnerabilities

### Synopsis

Inspects a Package URL (PURL) against the vulnerability database and displays
detailed information about matching CVEs, affected components, and relationships.

Shows both raw matches and deduplicated results (after alias resolution).

Examples:
  devguard-cli vulndb inspect "pkg:npm/lodash@4.17.20"
  devguard-cli vulndb inspect "pkg:deb/debian/libc6@2.31-1"
  devguard-cli vulndb inspect "pkg:pypi/requests@2.25.0"

```shell
devguard-scanner inspect <purl> [flags]
```

### Options

```shell
      --apiUrl string       The url of the API to send the request to (default "https://api.devguard.org")
  -h, --help                help for inspect
      --outputPath string   Path to save the inspection result as JSON file (optional)
      --timeout int         Set the timeout for scanner operations in seconds (default 300)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
