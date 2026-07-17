## purl-inspect

Inspect PURL for matching CVEs and vulnerabilities

### Synopsis

Look up a specific package version in the DevGuard vulnerability database and display all
known CVEs, their CVSS scores, EPSS exploit probability, and whether a fix is available.

A PURL (Package URL) is a standard way to identify a software package across ecosystems.
The format is: pkg:<type>/<namespace>/<name>@<version>

For example:
  pkg:npm/lodash@4.17.20          (npm package)
  pkg:deb/debian/libc6@2.31-1    (Debian package)
  pkg:pypi/requests@2.25.0       (Python package)

The output also shows alias deduplication — when two CVE IDs refer to the same underlying
vulnerability, DevGuard keeps only the canonical one and tells you which were removed.

```shell
devguard-scanner purl-inspect <purl> [flags]
```

### Examples

```shell
  # Inspect an npm package
  devguard-scanner purl-inspect "pkg:npm/lodash@4.17.20"

  # Inspect a Python package and save the raw JSON
  devguard-scanner purl-inspect "pkg:pypi/requests@2.25.0" --outputPath result.json

  # Inspect a Debian system package
  devguard-scanner purl-inspect "pkg:deb/debian/libc6@2.31-1"
```

### Options

```shell
      --apiUrl string       The url of the API to send the request to (default "https://api.devguard.org")
  -h, --help                help for purl-inspect
      --outputPath string   Path to save the inspection result as JSON file (optional)
      --timeout int         Set the timeout for scanner operations in seconds (default 300)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
