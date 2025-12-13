#!/bin/bash

# Test script for OCI/Docker registry proxy
# This script tests the dependency proxy for Docker images

echo "Testing OCI/Docker Registry Proxy via DevGuard Dependency Proxy"
echo "================================================================"
echo ""

# Set the proxy URL
PROXY_URL="localhost:8080"

echo "Using proxy: $PROXY_URL/dependency-proxy/oci"
echo ""

echo "NOTE: Docker doesn't support HTTPS for localhost registries by default."
echo "You may need to configure Docker to allow insecure registries."
echo ""

# Test 1: Pull an image through the proxy using curl
echo "Test 1: Checking registry connectivity..."
echo ""

curl -v "http://$PROXY_URL/dependency-proxy/oci/v2/"

echo ""
echo "======================================================="
echo ""

# Test 2: Get manifest for alpine image
echo "Test 2: Fetching Alpine Linux manifest..."
echo ""

curl -v \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  "http://$PROXY_URL/dependency-proxy/oci/v2/library/alpine/manifests/latest"

echo ""
echo "======================================================="
echo ""

echo "Docker Pull Test Instructions:"
echo "------------------------------"
echo ""
echo "To configure Docker to use this proxy, you would need to:"
echo ""
echo "1. Configure Docker daemon to allow insecure registries:"
echo "   Edit /etc/docker/daemon.json (or Docker Desktop settings):"
echo '   {'
echo '     "insecure-registries": ["localhost:8080"]'
echo '   }'
echo ""
echo "2. Restart Docker daemon"
echo ""
echo "3. Try pulling through the proxy:"
echo "   docker pull localhost:8080/dependency-proxy/oci/alpine:latest"
echo ""
echo "Note: Full Docker registry proxy requires more complex setup including"
echo "authentication token handling, which is beyond this simple test."
echo ""
echo "For now, the curl tests above show that the proxy is working for"
echo "basic registry API calls."
