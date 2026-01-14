## merge-sboms

Merge multiple SBOMs into one SBOM

### Synopsis

Merge multiple CycloneDX SBOMs into a single SBOM.

The command expects a JSON configuration file with the target purl and a list
of SBOM file paths to merge. The merged SBOM is written to stdout in pretty JSON.

Example config file:
  { "purl": "pkg:foo/bar@1.2.3", "sboms": ["a.json", "b.json"] }

```shell
devguard-scanner merge-sboms <config file> [flags]
```

### Examples

```shell
  # Merge SBOMs using config file
  devguard-scanner merge-sboms config.json

  # Redirect output to file
  devguard-scanner merge-sboms config.json > merged-sbom.json
```

### Options

```shell
  -h, --help   help for merge-sboms
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
