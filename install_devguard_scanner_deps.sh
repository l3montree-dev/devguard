#!/bin/bash
CRANE_VERSION=v0.19.1

set -e

# Check if the TARGETPLATFORM argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGETPLATFORM>"
    exit 1
fi

TARGETPLATFORM="$1"

# Define variables based on TARGETPLATFORM
case "$TARGETPLATFORM" in
    "linux/amd64")
        OS="Linux"
        ARCH="x86_64"
        ARCH_COSIGN="amd64"
        ;;
    "linux/arm64")
        OS="Linux"
        ARCH="arm64"
        ARCH_COSIGN="arm64"
        ;;
    "linux/arm/v7")
        OS="Linux"
        ARCH="armv7"
        ARCH_COSIGN="armv7"
        ;;
    "darwin/amd64")
        OS="Darwin"
        ARCH="x86_64"
        ARCH_COSIGN="amd64"
        ;;
    "darwin/arm64")
        OS="Darwin"
        ARCH="arm64"
        ARCH_COSIGN="arm64"
        ;;
    *)
        echo "Unsupported TARGETPLATFORM: $TARGETPLATFORM"
        exit 1
        ;;
esac

echo "Installing dependencies for OS: $OS, ARCH: $ARCH"

# install crane
curl -sL "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_${OS}_${ARCH}.tar.gz" > go-containerregistry.tar.gz && \
    tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane

# install trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.54.1

# inastall cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-${ARCH_COSIGN}" && mv cosign-linux-${ARCH_COSIGN} /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

echo "Dependencies installed successfully for $TARGETPLATFORM."