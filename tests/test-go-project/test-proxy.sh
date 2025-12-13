#!/bin/bash

# Test script for Go module proxy
# This script tests the dependency proxy by setting GOPROXY and running go commands

echo "Testing Go Module Proxy via DevGuard Dependency Proxy"
echo "======================================================="
echo ""

# Set the proxy URL
PROXY_URL="http://localhost:8080/api/v1/dependency-proxy/go"

echo "Using proxy: $PROXY_URL"
echo ""

# Clear Go module cache to force fetching from proxy
echo "Cleaning Go module cache..."
# go clean -modcache

# Set GOPROXY environment variable
export GOPROXY=$PROXY_URL

echo ""
echo "Attempting to download modules via proxy..."
echo ""

# Try to download dependencies
go mod download

echo ""
echo "======================================================="
echo "Test complete!"
echo ""
echo "Check the DevGuard logs to see if packages were proxied."
echo "You should see log entries for requests to packages like:"
echo "  - github.com/gin-gonic/gin"
echo "  - github.com/sirupsen/logrus"
echo ""
echo "If malicious packages are detected, they will be blocked."
