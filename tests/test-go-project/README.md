# Test Go Project for Dependency Proxy

This is a simple Go project to test the DevGuard dependency proxy for Go modules.

## Setup

1. Make sure DevGuard is running with the dependency proxy enabled:
   ```bash
   cd /Users/timbastin/Desktop/l3montree/devguard
   go run cmd/devguard/main.go
   ```

2. The dependency proxy should be available at: `http://localhost:8080/dependency-proxy/go`

## Testing

### Option 1: Using the test script

```bash
chmod +x test-proxy.sh
./test-proxy.sh
```

### Option 2: Manual testing

```bash
# Clear module cache
go clean -modcache

# Set proxy
export GOPROXY=http://localhost:8080/dependency-proxy/go

# Download dependencies
go mod download

# Or build the project
go build
```

### Option 3: Test specific module

```bash
# List available versions
curl http://localhost:8080/dependency-proxy/go/github.com/gin-gonic/gin/@v/list

# Get module info
curl http://localhost:8080/dependency-proxy/go/github.com/gin-gonic/gin/@v/v1.9.1.info

# Download module
curl http://localhost:8080/dependency-proxy/go/github.com/gin-gonic/gin/@v/v1.9.1.mod
```

## What to expect

1. **Successful proxy**: Modules are downloaded through the proxy and cached
2. **Malicious package detection**: If a known malicious Go package is requested, it will be blocked with HTTP 403
3. **Cache headers**: Response includes `X-Cache: HIT` or `X-Cache: MISS` and `X-Proxy-Type: go`

## Checking logs

Watch DevGuard logs for:
- `Proxy request` entries showing Go module requests
- `Cache hit` or fetching from upstream
- `Blocked malicious package` if any malicious packages are detected
