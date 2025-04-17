#!/bin/zsh

# check if the folder structure is correct
# expect the follwing structure:

# - devguard (this repo)
# - devguard-action
# - devguard-ci-component
# - devguard-web

TAG=$1

# check if valid semver
if ! [[ $TAG =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Invalid version number. Please use semantic versioning (e.g., 1.0.0)."
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

firsttrain=(devguard devguard-web)

# great lets do the tagging
for dir in "${firsttrain[@]}"; do
    if [ -d "$dir/.git" ]; then
        (cd "$dir" && git tag -s "$TAG" -m "$TAG" && git push --tags)
        if [ $? -ne 0 ]; then
            echo "Error: Failed to tag $dir with $TAG."
            exit 1
        fi
    fi
done