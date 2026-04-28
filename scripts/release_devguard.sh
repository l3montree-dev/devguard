#!/bin/zsh
set -euo pipefail

# Configuration
CHANGES_FILE="/tmp/release_devguard_changes_${RANDOM}.log"
ERRORS_FILE="/tmp/release_devguard_errors_${RANDOM}.log"
TOTAL_CHANGES=0
EXIT_CODE=0

# Cleanup on exit
trap "rm -f $CHANGES_FILE $ERRORS_FILE" EXIT

# Logging functions
log_change() {
    echo "  ✓ $1" >> "$CHANGES_FILE"
    (( ++TOTAL_CHANGES ))
}

log_error() {
    echo "  ✗ $1" >> "$ERRORS_FILE"
    EXIT_CODE=1
}

TAG=$1

# check if TAG starts with 'v' and strip it for semver validation
if [[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    SEMVER="${TAG#v}"  # Remove 'v' prefix for validation
elif [[ $TAG =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    echo "Error: Version number must be prefixed with 'v' (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
else
    echo "Error: Invalid version number. Please use semantic versioning with 'v' prefix (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
fi

# great its a valid semver - lets check if the directories exist
dirlist=(devguard devguard-action devguard-ci-component devguard-web)
for dir in "${dirlist[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Error: Directory $dir does not exist."
        exit 1
    fi
done

# check if the tag does already exist
for dir in "${dirlist[@]}"; do
    if [ -d "$dir/.git" ]; then
        if (cd "$dir" && git tag) | grep -q "$TAG"; then
            echo "Error: Tag $TAG already exists in $dir."
            exit 1
        fi
    fi
done

# make sure every dir is on the main branch
for dir in "${dirlist[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git checkout main)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to checkout main branch in $dir."
            exit 1
        fi
    fi
done

# make sure workdir is clean
for dir in "${dirlist[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git status --porcelain) | grep -q . && {
            echo "Error: Working directory in $dir is not clean. Please commit or stash your changes."
            exit 1
        }
    fi
done

firsttrain=(devguard devguard-web)

# Display summary and prompt before tagging
echo ""
echo "╔═════════════════════════════════════════╗"
echo "║  TAGGING SUMMARY - READY FOR APPROVAL    ║"
echo "╚═════════════════════════════════════════╝"
echo ""
echo "Tag: $TAG"
echo "Directories to tag:"
for dir in "${firsttrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        echo "  • $dir"
    fi
done
echo ""

# Prompt for confirmation before tagging
read -q "CONFIRM?Continue with tagging? (y/n) " -n 1; echo ""
if [[ "$CONFIRM" != "y" ]]; then
    echo "Operation cancelled by user."
    exit 1
fi

echo ""

# great lets do the tagging
for dir in "${firsttrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        if (cd "$dir" && git tag -s "$TAG" -m "$TAG" && git push && (git push --tags || true)); then
            log_change "Tagged $dir with $TAG and pushed"
        else
            log_error "Failed to tag $dir with $TAG."
            EXIT_CODE=1
        fi
    fi
done

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
if [[ $EXIT_CODE -eq 0 ]]; then
    echo "✓ Script completed successfully!"
else
    echo "✗ Script completed with errors. Please review the output above."
fi

exit $EXIT_CODE