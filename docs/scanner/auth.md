## auth

Verify a DevGuard token and store it in the system keyring

### Synopsis

Verify a DevGuard personal access token and store it in the OS keyring so you do not have to
pass --token on every command.

This is the recommended setup for developer machines and git hooks. In CI pipelines, prefer the
DEVGUARD_TOKEN environment variable instead so the token is not written to disk.

Once stored, all devguard-scanner commands will automatically pick up the token from the keyring.

```shell
devguard-scanner auth [flags]
```

### Examples

```shell
  # One-time setup on a developer machine
  devguard-scanner auth --token <hex-token> --assetName org/project/asset --apiUrl https://api.devguard.org
```

### Options

```shell
      --apiUrl string      The url of the API to send the scan request to (default "https://api.devguard.org")
      --assetName string   The id of the asset which is scanned (required)
  -h, --help               help for auth
      --token string       The personal access token to authenticate the request (required)
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
