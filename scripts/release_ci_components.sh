#!/bin/zsh
set -euo pipefail

# Configuration
CHANGES_FILE="/tmp/release_ci_changes_${RANDOM}.log"
ERRORS_FILE="/tmp/release_ci_errors_${RANDOM}.log"
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
}

# check if the folder structure is correct
# expect the follwing structure:

# - devguard (this repo)
# - devguard-action
# - devguard-ci-component
# - devguard-web

TAG=$1

# check if TAG starts with 'v' and strip it for semver validation
if [[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    SEMVER="${TAG#v}"  # Remove 'v' prefix for validation
elif [[ $TAG =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$ ]]; then
    echo "Error: Version number must be prefixed with 'v' (e.g., v1.0.0 or main)."
    exit 1
else
    echo "Error: Invalid version number. Please use semantic versioning with 'v' prefix (e.g., v1.0.0 or main)."
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


firsttrain=(devguard devguard-web)
# check if the tag does already exist
for dir in "${firsttrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        if (cd "$dir" && git tag) | grep -q "$TAG"; then
            echo "Great! Tag $TAG exists in $dir."
        else
            echo "Tag $TAG does not exist in $dir."
            exit 1
        fi
    fi
done


secondtrain=(devguard-action)
# check if we need to pull the latest changes
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git pull origin main)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to pull latest changes in $dir."
            exit 1
        fi
    fi
done



# replace "main" with the tag-name in the devguard-ci-component and devguard-action dir
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir" ]; then
        for file in $dir/**/*.yml(D); do
            if [[ -f $file ]]; then
                local original_hash=$(md5sum "$file" | awk '{print $1}')
                echo "Replacing in $file"
                sed -i "s|ghcr.io/l3montree-dev/devguard/scanner:main|ghcr.io/l3montree-dev/devguard/scanner:$TAG|g" "$file"
                local new_hash=$(md5sum "$file" | awk '{print $1}')
                
                if [[ "$original_hash" != "$new_hash" ]]; then
                    log_change "Replaced scanner image in $file"
                else
                    log_error "No changes made in $file - verify the pattern matches"
                fi
            fi
        done

        # Replace version default in all full.yml files (at any depth)
        for fullfile in $dir/**/full.yml(D); do
            if [[ -f $fullfile ]]; then
                local original_hash=$(md5sum "$fullfile" | awk '{print $1}')
                echo "Replacing version default in $fullfile"
                sed -i "/version:/,/default:/ s/default: \"main\"/default: \"$TAG\"/" "$fullfile"
                local new_hash=$(md5sum "$fullfile" | awk '{print $1}')
                
                if [[ "$original_hash" != "$new_hash" ]]; then
                    log_change "Updated version default in $fullfile"
                else
                    log_error "No version default changes made in $fullfile - verify the pattern matches"
                fi
            fi
        done
    fi
done

# stage changes in the "secondtrain" directories (commit and push happen after confirmation)
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git add .)
        log_change "Staged changes in $dir"
    fi
done

# Display summary and prompt before tagging
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

# Prompt for confirmation before tagging
read -q "CONFIRM?Continue with tagging? (y/n) " -n 1; echo ""
if [[ "$CONFIRM" != "y" ]]; then
    echo "Operation cancelled by user."
    exit 1
fi

# commit and push in the "secondtrain" directories
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git commit -m "chore: updates devguard scanner to $TAG" && git push)
        log_change "Committed and pushed changes in $dir"
    fi
done

# great lets do the tagging
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git tag -s "$TAG" -m "$TAG" && git push --tags || true)
        log_change "Tagged $dir with $TAG"
    fi
done

# replace back the tag-name with "main" in the devguard-ci-component and devguard-action dir
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir" ]; then
        for file in $dir/**/*.yml(D); do
            if [[ -f $file ]]; then
                local original_hash=$(md5sum "$file" | awk '{print $1}')
                echo "Replacing back in $file"
                sed -i "s|ghcr.io/l3montree-dev/devguard/scanner:$TAG|ghcr.io/l3montree-dev/devguard/scanner:main|g" "$file"
                local new_hash=$(md5sum "$file" | awk '{print $1}')
                
                if [[ "$original_hash" != "$new_hash" ]]; then
                    log_change "Reverted scanner image in $file"
                fi
            fi
        done

        # Replace version default back to "main" in all full.yml files (at any depth)
        for fullfile in $dir/**/full.yml(D); do
            if [[ -f $fullfile ]]; then
                local original_hash=$(md5sum "$fullfile" | awk '{print $1}')
                echo "Replacing version default back in $fullfile"
                sed -i "/version:/,/default:/ s/default: \"$TAG\"/default: \"main\"/" "$fullfile"
                local new_hash=$(md5sum "$fullfile" | awk '{print $1}')
                
                if [[ "$original_hash" != "$new_hash" ]]; then
                    log_change "Reverted version default in $fullfile"
                fi
            fi
        done
    fi
done

# do a commit in the "secondtrain" directories
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git add . && git commit -m "chore: using main devguard scanner" && git push)
        log_change "Committed final revert in $dir"
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