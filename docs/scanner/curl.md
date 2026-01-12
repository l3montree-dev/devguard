## curl

Make HTTP requests with DevGuard PAT signing (curl-compatible)

### Synopsis

Make HTTP requests with DevGuard Personal Access Token signing.
This command provides curl-compatible syntax while automatically signing requests
for authentication.

```shell
devguard-scanner curl [flags] <url>
```

### Examples

```shell
  # Simple GET request
  devguard-scanner curl https://api.example.com/users

  # POST request with JSON data
  devguard-scanner curl -X POST -d '{"name":"test"}' -H "Content-Type: application/json" https://api.example.com/users

  # Verbose request with custom headers
  devguard-scanner curl -v -H "Accept: application/json" https://api.example.com/data

  # Request with explicit token
  devguard-scanner curl --token <your-pat-token> -X GET https://api.example.com/protected
```

### Options

```shell
  -d, --data string          HTTP POST data
  -I, --head                 Fetch headers only
  -H, --header stringArray   Pass custom header(s) to server
  -h, --help                 help for curl
  -i, --include              Include response headers in output
  -k, --insecure             Allow insecure server connections
  -L, --location             Follow redirects
      --max-redirs int       Maximum number of redirects to follow (default 50)
      --max-time duration    Maximum time allowed for transfer
  -o, --output string        Write output to file instead of stdout
  -X, --request string       HTTP method (GET, POST, PUT, DELETE, etc.) (default "GET")
  -s, --silent               Silent mode
      --token string         DevGuard Personal Access Token (can also be set via DEVGUARD_TOKEN env var). Used to sign requests.
  -A, --user-agent string    User-Agent to send to server
  -v, --verbose              Verbose output
```

### Options inherited from parent commands

```shell
  -l, --logLevel string   Set the log level. Options: debug, info, warn, error (default "info")
```
