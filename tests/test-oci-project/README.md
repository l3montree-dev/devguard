# Test OCI Project for Dependency Proxy

This project tests the DevGuard dependency proxy for OCI/Docker images.

## Setup

1. Make sure DevGuard is running with the dependency proxy enabled:
   ```bash
   cd /Users/timbastin/Desktop/l3montree/devguard
   go run cmd/devguard/main.go
   ```

2. The OCI proxy should be available at: `http://localhost:8080/dependency-proxy/oci`

## Testing

### Option 1: Using the test script

```bash
chmod +x test-proxy.sh
./test-proxy.sh
```

### Option 2: Manual curl tests

```bash
# Check registry API endpoint
curl http://localhost:8080/dependency-proxy/oci/v2/

# Get manifest for Alpine Linux
curl -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  http://localhost:8080/dependency-proxy/oci/v2/library/alpine/manifests/latest

# Get manifest for a specific tag
curl -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  http://localhost:8080/dependency-proxy/oci/v2/library/nginx/manifests/1.25

# List tags (note: this endpoint may not be fully implemented)
curl http://localhost:8080/dependency-proxy/oci/v2/library/alpine/tags/list
```

## Docker Configuration (Advanced)

To use Docker with this proxy, you would need to configure Docker to use it as a registry mirror:

1. Edit Docker daemon configuration (`/etc/docker/daemon.json` or Docker Desktop settings):
   ```json
   {
     "insecure-registries": ["localhost:8080"],
     "registry-mirrors": ["http://localhost:8080/dependency-proxy/oci"]
   }
   ```

2. Restart Docker daemon

3. Try pulling an image:
   ```bash
   docker pull alpine:latest
   ```

**Note**: Full Docker registry mirroring requires proper implementation of the Docker Registry HTTP API V2, including authentication tokens, blob uploads, and proper manifest handling. This test proxy provides basic manifest and blob fetching for demonstration purposes.

## What to expect

1. **Successful proxy**: Registry API calls return proper manifests and blobs
2. **Cache headers**: Response includes `X-Cache: HIT` or `X-Cache: MISS` and `X-Proxy-Type: oci`
3. **Proper content types**: Manifests return `application/vnd.docker.distribution.manifest.v2+json`

## Checking logs

Watch DevGuard logs for:
- `Proxy request` entries showing OCI registry requests
- `Cache hit` or fetching from upstream (registry-1.docker.io)
- Manifest and blob requests

## Limitations

This is a simplified OCI proxy for testing and demonstration. A production-ready Docker registry proxy would need:
- Full Docker Registry HTTP API V2 implementation
- Authentication and token handling
- Blob upload support
- Catalog and tag list endpoints
- Proper error handling for Docker clients
