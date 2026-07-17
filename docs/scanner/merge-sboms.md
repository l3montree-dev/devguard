## merge-sboms

Merge multiple SBOMs into one SBOM

### Synopsis

Merge multiple CycloneDX SBOMs into a single combined SBOM.

If you are building a product that consists of several independently scanned components
(for example a frontend, a backend, and a set of shared libraries each with their own SBOM),
use this command to combine them into one SBOM before uploading to DevGuard.

The command reads a JSON config file that lists the component PURLs and SBOM file paths,
and writes the merged SBOM to stdout. Pipe the output directly into 'devguard-scanner sbom'.

Config file format:
  { "purl": "pkg:oci/my-app@1.2.3", "sboms": ["frontend.sbom.json", "backend.sbom.json"] }

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
