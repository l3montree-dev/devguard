#!/bin/zsh
set -euo pipefail

# Configuration
CHANGES_FILE="/tmp/release_helm_changes_${RANDOM}.log"
ERRORS_FILE="/tmp/release_helm_errors_${RANDOM}.log"
TOTAL_CHANGES=0

# Cleanup on exit
trap "rm -f $CHANGES_FILE $ERRORS_FILE" EXIT

log_change() {
    echo "  ✓ $1" >> "$CHANGES_FILE"
    (( ++TOTAL_CHANGES ))
}

log_error() {
    echo "  ✗ $1" >> "$ERRORS_FILE"
}

# Function to update docker-compose-try-it.yaml with new tags
update_docker_compose_tags() {
    local tag=$1
    local compose_file="devguard/docker-compose-try-it.yaml"

    echo "Updating $compose_file with tag $tag..."

    sed -i "s|ghcr.io/l3montree-dev/devguard:.*|ghcr.io/l3montree-dev/devguard:$tag|g" "$compose_file"
    sed -i "s|ghcr.io/l3montree-dev/devguard-web:.*|ghcr.io/l3montree-dev/devguard-web:$tag|g" "$compose_file"
    sed -i "s|ghcr.io/l3montree-dev/devguard/postgresql:.*|ghcr.io/l3montree-dev/devguard/postgresql:$tag|g" "$compose_file"

    if grep -q "ghcr.io/l3montree-dev/devguard:$tag" "$compose_file" && \
       grep -q "ghcr.io/l3montree-dev/devguard-web:$tag" "$compose_file"; then
        log_change "Updated docker-compose-try-it.yaml to $tag"
    else
        echo "❌ Failed to update docker-compose-try-it.yaml properly"
        exit 1
    fi
}

# Function to update Helm chart Chart.yaml with new tags
update_helm_chart_tags() {
    local tag=$1
    local chart_file="devguard-helm-chart/Chart.yaml"
    local values_file="devguard-helm-chart/values.yaml"
    local semver="${tag#v}"

    echo "Updating Helm chart with tag $tag..."

    sed -i "s|^version: .*|version: $semver|g" "$chart_file"
    sed -i "s|^appVersion: .*|appVersion: $tag|g" "$chart_file"

    if grep -q "^version: $semver" "$chart_file" && grep -q "^appVersion: $tag" "$chart_file"; then
        log_change "Updated Chart.yaml version to $semver, appVersion to $tag"
    else
        echo "❌ Failed to update Helm chart properly"
        exit 1
    fi

    echo "Updating values.yaml image tags to $tag..."

    sed -i "s|tag: v[0-9]\+\.[0-9]\+\.[0-9]\+$|tag: $tag|g" "$values_file"

    if grep -q "tag: $tag" "$values_file"; then
        log_change "Updated values.yaml image tags to $tag"
    else
        echo "❌ Failed to update values.yaml image tags"
        exit 1
    fi

    sed -i "s|gitlab.com/l3montree/devguard/-/raw/[^\"]*|gitlab.com/l3montree/devguard/-/raw/$tag|g" "$values_file"

    if grep -q "gitlab.com/l3montree/devguard/-/raw/$tag" "$values_file"; then
        log_change "Updated values.yaml ciComponentBase (api + web) to $tag"
    else
        echo "❌ Failed to update values.yaml ciComponentBase"
        exit 1
    fi
}

TAG=$1

if [[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    SEMVER="${TAG#v}"
elif [[ $TAG =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    echo "Error: Version number must be prefixed with 'v' (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
else
    echo "Error: Invalid version number. Please use semantic versioning with 'v' prefix (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
fi

if [ ! -d "devguard" ]; then
    echo "Error: Directory devguard does not exist."
    exit 1
fi

if [ ! -f "devguard/docker-compose-try-it.yaml" ]; then
    echo "Error: devguard/docker-compose-try-it.yaml does not exist."
    exit 1
fi

if [ ! -f "devguard-helm-chart/Chart.yaml" ]; then
    echo "Error: devguard-helm-chart/Chart.yaml does not exist."
    exit 1
fi

# Make sure devguard is on main and clean
if [ -d "devguard/.git" ]; then
    (cd devguard && git checkout main)
    if (cd devguard && git status --porcelain) | grep -q .; then
        echo "Error: Working directory in devguard is not clean. Please commit or stash your changes."
        exit 1
    fi
fi

update_docker_compose_tags "$TAG"
update_helm_chart_tags "$TAG"

# Display summary and prompt before committing
echo ""
echo "╔═════════════════════════════════════════╗"
echo "║  CHANGE SUMMARY - READY FOR APPROVAL    ║"
echo "╚═════════════════════════════════════════╝"
echo ""
echo "Total changes: $TOTAL_CHANGES"
echo ""

if [[ -f "$CHANGES_FILE" ]] && [[ -s "$CHANGES_FILE" ]]; then
    echo "✓ Changes made:"
    cat "$CHANGES_FILE"
    echo ""
fi

if [[ -f "$ERRORS_FILE" ]] && [[ -s "$ERRORS_FILE" ]]; then
    echo "✗ Issues detected:"
    cat "$ERRORS_FILE"
    echo ""
    echo "WARNING: Some changes may not have been applied correctly."
    echo "Please review the files manually before continuing."
    echo ""
fi

read -q "CONFIRM?Continue with commit, push and tagging? (y/n) " -n 1; echo ""
if [[ "$CONFIRM" != "y" ]]; then
    echo "Operation cancelled by user."
    exit 1
fi

(cd devguard && git add docker-compose-try-it.yaml && git commit -m "chore: update docker-compose-try-it.yaml to $TAG" && git push)
log_change "Committed and pushed docker-compose-try-it.yaml"

(cd devguard-helm-chart && git add Chart.yaml && git commit -m "chore: update Helm chart to $TAG

- Updated devguard image to $TAG
- Updated devguard-web image to $TAG
- Updated devguard-postgresql image to $TAG
- Updated Helm chart version to $SEMVER, appVersion to $TAG" && git push)
log_change "Committed and pushed Chart.yaml"

(cd devguard-helm-chart && git tag -s -a "$TAG" -m "chore: release Helm chart version $TAG" && git push origin "$TAG" || true)
log_change "Tagged devguard-helm-chart with $TAG"

# Final summary
echo ""
echo "╔═════════════════════════════════════════╗"
echo "║  FINAL SUMMARY                          ║"
echo "╚═════════════════════════════════════════╝"
echo ""
echo "Total operations: $TOTAL_CHANGES"
if [[ -f "$CHANGES_FILE" ]] && [[ -s "$CHANGES_FILE" ]]; then
    cat "$CHANGES_FILE"
fi

if [[ -f "$ERRORS_FILE" ]] && [[ -s "$ERRORS_FILE" ]]; then
    echo ""
    echo "⚠ Issues encountered:"
    cat "$ERRORS_FILE"
fi

echo ""
echo "✓ Script completed successfully!"
