#!/bin/bash

# list count of open issues with "devguard" label per repo in a GitLab group
# usage: ./count_devguard_issues.sh <group_id> <gitlab_api_url>
# example: ./count_devguard_issues.sh 42 https://gitlab.example.com/api/v4

set -e

GROUP_ID="$1"
GITLAB_API_URL="$2"
LABEL="devguard"
PER_PAGE=100

if [[ -z "$GROUP_ID" || -z "$GITLAB_API_URL" ]]; then
    echo "Usage: $0 <group_id> <gitlab_api_url>"
    echo ""
    echo "Example: $0 42 https://gitlab.example.com/api/v4"
    exit 1
fi

if [[ -z "$PRIVATE_TOKEN" ]]; then
    echo "Error: PRIVATE_TOKEN environment variable must be set"
    exit 1
fi

echo "Fetching projects from group $GROUP_ID (including subgroups)..."
echo ""

PAGE=1
ALL_PROJECTS="[]"

while true; do
    PROJECTS=$(curl --silent --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
        --url "$GITLAB_API_URL/groups/$GROUP_ID/projects?include_subgroups=true&per_page=$PER_PAGE&page=$PAGE")
    
    PROJECT_COUNT=$(echo "$PROJECTS" | jq 'length')
    
    if [[ "$PROJECT_COUNT" -eq 0 ]]; then
        break
    fi
    
    ALL_PROJECTS=$(echo "$ALL_PROJECTS $PROJECTS" | jq -s 'add')
    
    if [[ "$PROJECT_COUNT" -lt "$PER_PAGE" ]]; then
        break
    fi
    
    PAGE=$((PAGE + 1))
done

TOTAL_PROJECTS=$(echo "$ALL_PROJECTS" | jq 'length')

if [[ "$TOTAL_PROJECTS" -eq 0 ]]; then
    echo "No projects found in group $GROUP_ID."
    exit 0
fi

echo "Found $TOTAL_PROJECTS project(s). Counting open issues with label '$LABEL'..."
echo ""

count_issues() {
    local PROJECT_ID=$1
    local TOTAL_COUNT=0
    local PAGE=1
    
    while true; do
        ISSUES=$(curl --silent --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
            --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues?labels=$LABEL&state=opened&per_page=$PER_PAGE&page=$PAGE")
        
        ISSUE_COUNT=$(echo "$ISSUES" | jq 'length')
        TOTAL_COUNT=$((TOTAL_COUNT + ISSUE_COUNT))
        
        if [[ "$ISSUE_COUNT" -lt "$PER_PAGE" ]]; then
            break
        fi
        
        PAGE=$((PAGE + 1))
    done
    
    echo "$TOTAL_COUNT"
}

echo "=========================================="
printf "%-60s %s\n" "REPOSITORY" "COUNT"
echo "=========================================="

TOTAL_ISSUES=0
REPOS_WITH_ISSUES=0

while IFS='|' read -r PROJECT_ID PROJECT_PATH; do
    ISSUE_COUNT=$(count_issues "$PROJECT_ID")
    
    if [[ "$ISSUE_COUNT" -gt 0 ]]; then
        printf "%-60s %s\n" "$PROJECT_PATH" "$ISSUE_COUNT"
        TOTAL_ISSUES=$((TOTAL_ISSUES + ISSUE_COUNT))
        REPOS_WITH_ISSUES=$((REPOS_WITH_ISSUES + 1))
    fi
done <<< "$(echo "$ALL_PROJECTS" | jq -r '.[] | "\(.id)|\(.path_with_namespace)"')"

echo "=========================================="
echo ""
echo "Summary:"
echo "  Total repositories scanned: $TOTAL_PROJECTS"
echo "  Repositories with '$LABEL' issues: $REPOS_WITH_ISSUES"
echo "  Total open '$LABEL' issues: $TOTAL_ISSUES"