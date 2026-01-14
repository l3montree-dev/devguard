## slug

Create a URL-friendly slug from text

### Synopsis

Create a URL-friendly slug from the provided text.

Useful for generating artifact names or identifiers. The slug is printed to stdout.

```shell
devguard-scanner slug <text> [flags]
```

### Examples

```shell
  # Generate a slug from text
  devguard-scanner slug "My Project Name"

  # Use in shell script
  SLUG=$(devguard-scanner slug "My App v1.2.3")
```

### Options

```shell
  -h, --help   help for slug
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
