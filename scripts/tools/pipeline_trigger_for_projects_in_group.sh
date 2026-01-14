#!/bin/bash

# Trigger background jobs pipeline for all assets in a DevGuard organization or specific project (group)
# This script uses the devguard-scanner curl command for authentication.
# It recursively finds all subgroups (nested projects) and triggers pipelines for all their assets.
#
# Requirements:
# - devguard-scanner CLI installed and in PATH
# - DEVGUARD_TOKEN environment variable set with a valid Personal Access Token
# - jq installed for JSON parsing
#
# Usage: ./pipeline_trigger_for_projects_in_group.sh <organization_slug> <devguard_api_url> [project_slug]
# Example: ./pipeline_trigger_for_projects_in_group.sh my-org https://api.devguard.dev/api/v1
# Example: ./pipeline_trigger_for_projects_in_group.sh my-org https://api.devguard.dev/api/v1 my-project
# Example: ./pipeline_trigger_for_projects_in_group.sh my-org/projects/my-project https://api.devguard.dev/api/v1

set -e

INPUT_PATH="$1"
API_URL="$2"
PROJECT_FILTER="$3"
PER_PAGE=100

# Parse input path - handle formats like "org/projects/group" or just "org"
if [[ "$INPUT_PATH" == *"/projects/"* ]]; then
    # Extract org and project from path like "my-org/projects/a-test-group"
    ORG_SLUG="${INPUT_PATH%%/projects/*}"
    PROJECT_FILTER="${INPUT_PATH##*/projects/}"
    echo "Detected path format: organization='$ORG_SLUG', project filter='$PROJECT_FILTER'"
else
    ORG_SLUG="$INPUT_PATH"
fi

if [[ -z "$ORG_SLUG" || -z "$API_URL" ]]; then
    echo "Usage: $0 <organization_slug> <devguard_api_url> [project_slug]"
    echo ""
    echo "Examples:"
    echo "  $0 my-org https://api.devguard.dev/api/v1                     # All projects in org"
    echo "  $0 my-org https://api.devguard.dev/api/v1 my-project          # Specific project and subgroups"
    echo "  $0 my-org/projects/my-project https://api.devguard.dev/api/v1 # Alternative format"
    echo ""
    echo "Environment variables required:"
    echo "  DEVGUARD_TOKEN  - DevGuard Personal Access Token"
    exit 1
fi

if [[ -z "$DEVGUARD_TOKEN" ]]; then
    echo "Error: DEVGUARD_TOKEN environment variable must be set with a valid DevGuard Personal Access Token."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq first."
    exit 1
fi

if ! command -v devguard-scanner &> /dev/null; then
    echo "Error: devguard-scanner CLI is required but not installed."
    exit 1
fi

# Helper function to make authenticated API requests
devguard_curl() {
    local URL="$1"
    local METHOD="${2:-GET}"
    local RESPONSE
    
    if [[ "$METHOD" == "GET" ]]; then
        RESPONSE=$(devguard-scanner curl -s "$URL" 2>/dev/null)
    else
        RESPONSE=$(devguard-scanner curl -s -X "$METHOD" "$URL" 2>/dev/null)
    fi
    
    CURL_EXIT_CODE=$?
    
    if [[ $CURL_EXIT_CODE -ne 0 ]]; then
        echo "Error: Failed to fetch from DevGuard API (exit code $CURL_EXIT_CODE)." >&2
        echo "URL: $URL" >&2
        return 2
    fi
    
    # Check if response is valid JSON or empty success response
    if ! echo "$RESPONSE" | jq empty >/dev/null 2>&1; then
        if [[ -z "$RESPONSE" || "$RESPONSE" == *"success"* ]]; then
            echo "$RESPONSE"
            return 0
        fi
        echo "Error: Response from DevGuard API is not valid JSON:" >&2
        echo "$RESPONSE" >&2
        return 3
    fi
    
    echo "$RESPONSE"
}

# Recursive function to get all child projects (subgroups)
get_child_projects_recursive() {
    local PARENT_ID="$1"
    local ALL_CHILDREN="[]"
    local PAGE=1
    
    while true; do
        local CHILDREN_RESPONSE
        CHILDREN_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/?parentId=$PARENT_ID&page=$PAGE&pageSize=$PER_PAGE")
        
        local CHILDREN
        if echo "$CHILDREN_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
            CHILDREN=$(echo "$CHILDREN_RESPONSE" | jq '.data')
        else
            CHILDREN="$CHILDREN_RESPONSE"
        fi
        
        local COUNT
        COUNT=$(echo "$CHILDREN" | jq 'if type == "array" then length else 0 end')
        
        if [[ "$COUNT" -eq 0 ]]; then
            break
        fi
        
        ALL_CHILDREN=$(jq -s '.[0] + .[1]' <(echo "$ALL_CHILDREN") <(echo "$CHILDREN"))
        
        for i in $(seq 0 $((COUNT - 1))); do
            local CHILD_ID
            CHILD_ID=$(echo "$CHILDREN" | jq -r ".[$i].id")
            local GRANDCHILDREN
            GRANDCHILDREN=$(get_child_projects_recursive "$CHILD_ID")
            ALL_CHILDREN=$(jq -s '.[0] + .[1]' <(echo "$ALL_CHILDREN") <(echo "$GRANDCHILDREN"))
        done
        
        if [[ "$COUNT" -lt "$PER_PAGE" ]]; then
            break
        fi
        
        PAGE=$((PAGE + 1))
    done
    
    echo "$ALL_CHILDREN"
}

echo "=============================================="
echo "DevGuard Pipeline Trigger Tool"
echo "=============================================="
echo ""
echo "Organization: $ORG_SLUG"
echo "API URL: $API_URL"
if [[ -n "$PROJECT_FILTER" ]]; then
    echo "Project filter: $PROJECT_FILTER (including subgroups)"
fi
echo ""

# Fetch projects
ALL_PROJECTS="[]"

if [[ -n "$PROJECT_FILTER" ]]; then
    echo "Fetching project '$PROJECT_FILTER' from organization '$ORG_SLUG'..."
    
    PROJECT_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_FILTER/")
    
    if [[ $? -ne 0 ]] || echo "$PROJECT_RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
        echo "Error: Could not fetch project '$PROJECT_FILTER'. Response:"
        echo "$PROJECT_RESPONSE"
        exit 2
    fi
    
    ROOT_PROJECT_ID=$(echo "$PROJECT_RESPONSE" | jq -r '.id')
    
    if [[ -z "$ROOT_PROJECT_ID" || "$ROOT_PROJECT_ID" == "null" ]]; then
        echo "Error: Could not get project ID from response"
        exit 2
    fi
    
    ALL_PROJECTS=$(echo "[$PROJECT_RESPONSE]" | jq '.')
    
    echo "Fetching subgroups recursively..."
    CHILD_PROJECTS=$(get_child_projects_recursive "$ROOT_PROJECT_ID")
    
    CHILD_COUNT=$(echo "$CHILD_PROJECTS" | jq 'length')
    if [[ "$CHILD_COUNT" -gt 0 ]]; then
        echo "Found $CHILD_COUNT subgroup(s)"
        ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$CHILD_PROJECTS"))
    fi
else
    echo "Fetching all projects from organization '$ORG_SLUG' (including subgroups)..."
    
    PAGE=1
    
    while true; do
        PROJECTS_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/?page=$PAGE&pageSize=$PER_PAGE")
        
        if echo "$PROJECTS_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
            PROJECTS=$(echo "$PROJECTS_RESPONSE" | jq '.data')
        else
            PROJECTS="$PROJECTS_RESPONSE"
        fi
        
        PROJECT_COUNT=$(echo "$PROJECTS" | jq 'if type == "array" then length else 0 end')
        
        if [[ "$PROJECT_COUNT" -eq 0 ]]; then
            break
        fi
        
        ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$PROJECTS"))
        
        for i in $(seq 0 $((PROJECT_COUNT - 1))); do
            PROJECT_ID=$(echo "$PROJECTS" | jq -r ".[$i].id")
            CHILD_PROJECTS=$(get_child_projects_recursive "$PROJECT_ID")
            CHILD_COUNT=$(echo "$CHILD_PROJECTS" | jq 'length')
            if [[ "$CHILD_COUNT" -gt 0 ]]; then
                ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$CHILD_PROJECTS"))
            fi
        done
        
        if [[ "$PROJECT_COUNT" -lt "$PER_PAGE" ]]; then
            break
        fi
        
        PAGE=$((PAGE + 1))
    done
fi

TOTAL_PROJECTS=$(echo "$ALL_PROJECTS" | jq 'length')

if [[ "$TOTAL_PROJECTS" -eq 0 ]]; then
    echo "No projects found."
    exit 0
fi

echo "Found $TOTAL_PROJECTS project(s) total (including subgroups)."
echo ""

# Collect all assets for pipeline trigger
declare -a ALL_ASSETS_TO_TRIGGER
TOTAL_ASSETS=0

echo "Scanning projects for assets..."
echo ""

for i in $(seq 0 $((TOTAL_PROJECTS - 1))); do
    PROJECT=$(echo "$ALL_PROJECTS" | jq ".[$i]")
    PROJECT_SLUG=$(echo "$PROJECT" | jq -r '.slug')
    PROJECT_NAME=$(echo "$PROJECT" | jq -r '.name // .slug')
    PROJECT_PARENT_ID=$(echo "$PROJECT" | jq -r '.parentId // "null"')
    
    PARENT_INFO=""
    if [[ "$PROJECT_PARENT_ID" != "null" ]]; then
        PARENT_INFO=" (subgroup)"
    fi
    
    echo "Project: $PROJECT_NAME ($PROJECT_SLUG)$PARENT_INFO"
    
    # Get assets for this project
    ASSETS=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_SLUG/assets/")
    ASSET_COUNT=$(echo "$ASSETS" | jq 'if type == "array" then length else 0 end')
    
    if [[ "$ASSET_COUNT" -eq 0 ]]; then
        echo "  No assets found."
        continue
    fi
    
    echo "  Assets: $ASSET_COUNT"
    for j in $(seq 0 $((ASSET_COUNT - 1))); do
        ASSET=$(echo "$ASSETS" | jq ".[$j]")
        ASSET_SLUG=$(echo "$ASSET" | jq -r '.slug')
        ASSET_NAME=$(echo "$ASSET" | jq -r '.name // .slug')
        
        echo "    - $ASSET_NAME ($ASSET_SLUG)"
        ALL_ASSETS_TO_TRIGGER+=("$ORG_SLUG|$PROJECT_SLUG|$ASSET_SLUG|$ASSET_NAME")
        TOTAL_ASSETS=$((TOTAL_ASSETS + 1))
    done
    
    echo ""
done

# Summary
echo "=============================================="
echo "Summary"
echo "=============================================="
echo "Total projects scanned: $TOTAL_PROJECTS"
echo "Total assets to trigger: $TOTAL_ASSETS"
echo ""

if [[ "$TOTAL_ASSETS" -eq 0 ]]; then
    echo "No assets found. Nothing to trigger."
    exit 0
fi

# List what will be triggered
echo "Pipelines to be triggered:"
for asset_entry in "${ALL_ASSETS_TO_TRIGGER[@]}"; do
    IFS='|' read -r org proj asset_slug asset_name <<< "$asset_entry"
    echo "  - $org/$proj/$asset_slug"
done
echo ""

# Confirmation
echo "=============================================="
echo "This will trigger background jobs for all listed assets."
echo "=============================================="
echo ""
read -p "Are you sure you want to trigger pipelines for all $TOTAL_ASSETS asset(s)? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Starting pipeline triggers..."
echo ""

# Trigger pipelines
TRIGGERED=0
FAILED=0

for asset_entry in "${ALL_ASSETS_TO_TRIGGER[@]}"; do
    IFS='|' read -r org proj asset_slug asset_name <<< "$asset_entry"
    
    echo -n "  Triggering pipeline: $org/$proj/$asset_slug... "
    
    TRIGGER_RESPONSE=$(devguard_curl "$API_URL/organizations/$org/projects/$proj/assets/$asset_slug/pipeline-trigger/" "POST" 2>&1) || true
    
    if [[ "$TRIGGER_RESPONSE" == *"error"* ]] || [[ "$TRIGGER_RESPONSE" == *"Error"* ]]; then
        echo "FAILED"
        echo "    Error: $TRIGGER_RESPONSE"
        FAILED=$((FAILED + 1))
    else
        echo "OK"
        TRIGGERED=$((TRIGGERED + 1))
    fi
done

echo ""

# Final summary
echo "=============================================="
echo "Pipeline Trigger Complete"
echo "=============================================="
echo "Triggered: $TRIGGERED"
echo "Failed: $FAILED"
echo ""

if [[ "$FAILED" -gt 0 ]]; then
    echo "Some triggers failed. Please check the errors above."
    exit 1
fi

echo "All pipelines have been successfully triggered."
