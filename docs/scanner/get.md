## get

Do a simple authenticated GET request. Deprecated in favor of 'curl' command.

### Synopsis

Perform a simple authenticated GET request signed with a DevGuard Personal Access Token.

This command is deprecated in favor of the more feature-rich 'curl' command but remains
for quick authenticated GET requests. The outgoing HTTP request is signed using the
provided token or the DEVGUARD_TOKEN environment variable.

```shell
devguard-scanner get <url> [flags]
```

### Examples

```shell
  # Simple GET request with token
  devguard-scanner get https://example.com/api/health -t <token>

  # Use environment variable for token
  export DEVGUARD_TOKEN=<your-token>
  devguard-scanner get https://example.com/api/data
```

### Options

```shell
  -h, --help           help for get
  -t, --token string   DevGuard Personal Access Token (or set DEVGUARD_TOKEN env var). Used to sign the outgoing request. If empty, command will print help.
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
