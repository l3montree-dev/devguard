#!/bin/zsh

# Function to update docker-compose-try-it.yaml with new tags
update_docker_compose_tags() {
    local tag=$1
    local compose_file="devguard/docker-compose-try-it.yaml"
    
    echo "Updating $compose_file with tag $tag..."
    
    # Backup the original file
    cp "$compose_file" "$compose_file.backup"
    
    # Update devguard API image tag
    sed -i '' "s|ghcr.io/l3montree-dev/devguard:.*|ghcr.io/l3montree-dev/devguard:$tag|g" "$compose_file"
    
    # Update devguard-web image tag
    sed -i '' "s|ghcr.io/l3montree-dev/devguard-web:.*|ghcr.io/l3montree-dev/devguard-web:$tag|g" "$compose_file"
    
    # Update devguard-postgresql image tag
    sed -i '' "s|ghcr.io/l3montree-dev/devguard/postgresql:.*|ghcr.io/l3montree-dev/devguard/postgresql:$tag|g" "$compose_file"
    
    # Verify the changes were made
    if grep -q "ghcr.io/l3montree-dev/devguard:$tag" "$compose_file" && \
       grep -q "ghcr.io/l3montree-dev/devguard-web:$tag" "$compose_file"; then
        echo "✅ Successfully updated docker-compose-try-it.yaml with version $tag"
        rm "$compose_file.backup"
    else
        echo "❌ Failed to update docker-compose-try-it.yaml properly"
        mv "$compose_file.backup" "$compose_file"
        exit 1
    fi
}

# Function to update Helm chart values.yaml with new tags
update_helm_chart_tags() {
    local tag=$1
    local chart_file="devguard-helm-chart/Chart.yaml"
    
    echo "Updating Helm chart with tag $tag..."
    
    # Backup the original file
    cp "$chart_file" "$chart_file.backup"
    
    # Update appVersion in Chart.yaml
    sed -i '' "s|appVersion: .*|appVersion: $tag|g" "$chart_file"
    
    # Verify the changes were made
    if grep -q "appVersion: $tag" "$chart_file"; then
        echo "✅ Successfully updated Helm chart with version $tag"
        rm "$chart_file.backup"
    else
        echo "❌ Failed to update Helm chart properly"
        mv "$chart_file.backup" "$chart_file"
        exit 1
    fi
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
    echo "Error: Version number must be prefixed with 'v' (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
else
    echo "Error: Invalid version number. Please use semantic versioning with 'v' prefix (e.g., v1.0.0 or v1.0.0-rc.1)."
    exit 1
fi

# great its a valid semver - lets check if the directories exist
dirlist=(devguard)
for dir in "${dirlist[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Error: Directory $dir does not exist."
        exit 1
    fi
done

# Check if docker-compose-try-it.yaml exists
if [ ! -f "devguard/docker-compose-try-it.yaml" ]; then
    echo "Error: devguard/docker-compose-try-it.yaml does not exist."
    exit 1
fi

# Check if Helm chart Chart.yaml exists
if [ ! -f "devguard-helm-chart/Chart.yaml" ]; then
    echo "Error: devguard-helm-chart/Chart.yaml does not exist."
    exit 1
fi


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

# Update docker-compose-try-it.yaml with new tags
echo "📝 Updating docker-compose-try-it.yaml with new release tags..."
update_docker_compose_tags "$TAG"

# Update Helm chart values.yaml with new tags
echo "⎈ Updating Helm chart values.yaml with new release tags..."
update_helm_chart_tags "$TAG"

# commit docker compose
echo "💾 Committing docker-compose"
(cd devguard && git add docker-compose-try-it.yaml && git commit -m "chore: update docker-compose-try-it.yaml to $TAG" && git push)
if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to commit docker-compose changes."
    exit 1
fi

# Commit the docker-compose and Helm chart changes
echo "💾 Committing Helm chart changes..."
(cd devguard-helm-chart && git add Chart.yaml && git commit -m "chore: update docker-compose-try-it.yaml and Helm chart to $TAG

- Updated devguard image to $TAG
- Updated devguard-web image to $TAG
- Updated devguard-postgresql image to $TAG
- Updated Helm chart appVersion to $TAG" && git push)
if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to commit docker-compose and Helm chart changes."
    exit 1
fi
echo "✅ Successfully committed and pushed docker-compose and Helm chart changes"

# tag the helm chart repo
echo "🏷️ Tagging Helm chart repository with $TAG..."
(cd devguard-helm-chart && git tag -s -a "$TAG" -m "chore: release Helm chart version $TAG" && git push origin "$TAG")

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to tag Helm chart repository."
    exit 1
fi
