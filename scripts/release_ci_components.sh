#!/bin/zsh

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


secondtrain=(devguard-ci-component devguard-action)
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



# replace "main-latest" with the tag-name in the devguard-ci-component and devguard-action dir
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir" ]; then
        for file in $dir/**/*.yml(D); do
            echo "Replacing in $file"
            if [[ -f $file ]]; then
                sed -i '' "s|ghcr.io/l3montree-dev/devguard/scanner:main-latest|ghcr.io/l3montree-dev/devguard/scanner:$TAG|g" "$file"
            fi
        done
        
        # Replace version default in all full.yml files (at any depth)
        for fullfile in $dir/**/full.yml(D); do
            if [[ -f $fullfile ]]; then
                echo "Replacing version default in $fullfile"
                sed -i '' "/version:/,/default:/ s/default: \"main\"/default: \"$TAG\"/" "$fullfile"
            fi
        done
    fi
done


# do a commit in the "secondtrain" directories
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git add . && git commit -m "chore: updates devguard scanner to $TAG" && git push)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to commit changes in $dir."
            exit 1
        fi
    fi
done

# great lets do the tagging
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git tag -s "$TAG" -m "$TAG" && (git push --tags || true))
        if [ $? -ne 0 ]; then
            echo "Error: Failed to tag $dir with $TAG."
            exit 1
        fi
    fi
done

# replace back the tag-name with "main-latest" in the devguard-ci-component and devguard-action dir
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir" ]; then
        for file in $dir/**/*.yml(D); do
            echo "Replacing back in $file"
            if [[ -f $file ]]; then
                sed -i '' "s|ghcr.io/l3montree-dev/devguard/scanner:$TAG|ghcr.io/l3montree-dev/devguard/scanner:main-latest-latest|g" "$file"
            fi
        done
        
        # Replace version default back to "main" in all full.yml files (at any depth)
        for fullfile in $dir/**/full.yml(D); do
            if [[ -f $fullfile ]]; then
                echo "Replacing version default back in $fullfile"
                sed -i '' "/version:/,/default:/ s/default: \"$TAG\"/default: \"main\"/" "$fullfile"
            fi
        done
    fi
done

# do a commit in the "secondtrain" directories
for dir in "${secondtrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git add . && git commit -m "chore: using main-latest devguard scanner" && git push)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to commit changes in $dir."
            exit 1
        fi
    fi
done