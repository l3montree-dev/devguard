## sarif2markdown

Convert a SARIF JSON file into a markdown report

### Synopsis

Convert a SARIF JSON file into a human-readable markdown report.

Supports both summary and detailed output formats.

```shell
devguard-scanner sarif2markdown [flags]
```

### Examples

```shell
  # Convert SARIF to markdown summary
  devguard-scanner sarif2markdown -i results.sarif.json

  # Generate detailed markdown report
  devguard-scanner sarif2markdown -i results.sarif.json --detailed

  # Save to file
  devguard-scanner sarif2markdown -i results.sarif.json -o report.md
```

### Options

```shell
      --detailed        Show detailed results per resource
  -h, --help            help for sarif2markdown
  -i, --input string    Input SARIF JSON file
  -o, --output string   Output markdown file (default: stdout)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
