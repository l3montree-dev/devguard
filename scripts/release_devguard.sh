#!/bin/zsh
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

# great lets do the tagging
for dir in "${firsttrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git tag -s "$TAG" -m "$TAG" && git push && git push --tags)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to tag $dir with $TAG."
            exit 1
        fi
    fi
done