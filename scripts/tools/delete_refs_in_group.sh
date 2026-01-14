#!/bin/bash

# Delete all refs (branches and tags) and releases in a DevGuard organization or specific project
# This script uses the devguard-scanner curl command for authentication.
#
# Requirements:
# - devguard-scanner CLI installed and in PATH
# - DEVGUARD_TOKEN environment variable set with a valid Personal Access Token
# - jq installed for JSON parsing
#
# Usage: ./delete_refs_in_group.sh <organization_slug> <devguard_api_url>
# Example: DEVGUARD_TOKEN="..." ./scripts/tools/delete_refs_in_group.sh @opencode/projects/components-1 https://api.devguard.opencode.de/api/v1
#
# The organization_slug can also be a path like "org/projects/project-group" which will
# be automatically parsed as organization "org" with project filter "project-group"

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
    echo "  $0 my-org https://api.devguard.dev/api/v1 my-project          # Specific project"
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
    
    # Check if response is valid JSON
    if ! echo "$RESPONSE" | jq empty >/dev/null 2>&1; then
        # It might be a success message or empty response for DELETE
        if [[ -z "$RESPONSE" || "$RESPONSE" == *"deleted"* || "$RESPONSE" == *"success"* ]]; then
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
# Arguments: parent_id (UUID)
# Output: JSON array of projects
get_child_projects_recursive() {
    local PARENT_ID="$1"
    local ALL_CHILDREN="[]"
    local PAGE=1
    
    while true; do
        local CHILDREN_RESPONSE
        CHILDREN_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/?parentId=$PARENT_ID&page=$PAGE&pageSize=$PER_PAGE")
        
        # Handle paged response format
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
        
        # Add direct children to result
        ALL_CHILDREN=$(jq -s '.[0] + .[1]' <(echo "$ALL_CHILDREN") <(echo "$CHILDREN"))
        
        # Recursively get grandchildren
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
echo "DevGuard Refs and Releases Deletion Tool"
echo "=============================================="
echo ""
echo "Organization: $ORG_SLUG"
echo "API URL: $API_URL"
if [[ -n "$PROJECT_FILTER" ]]; then
    echo "Project filter: $PROJECT_FILTER (including subgroups)"
fi
echo ""

# Step 1: Fetch projects
ALL_PROJECTS="[]"

if [[ -n "$PROJECT_FILTER" ]]; then
    # Fetch specific project first
    echo "Fetching project '$PROJECT_FILTER' from organization '$ORG_SLUG'..."
    
    PROJECT_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_FILTER/")
    
    if [[ $? -ne 0 ]] || echo "$PROJECT_RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
        echo "Error: Could not fetch project '$PROJECT_FILTER'. Response:"
        echo "$PROJECT_RESPONSE"
        exit 2
    fi
    
    # Get project ID for recursive child fetch
    ROOT_PROJECT_ID=$(echo "$PROJECT_RESPONSE" | jq -r '.id')
    
    if [[ -z "$ROOT_PROJECT_ID" || "$ROOT_PROJECT_ID" == "null" ]]; then
        echo "Error: Could not get project ID from response"
        exit 2
    fi
    
    # Add the root project
    ALL_PROJECTS=$(echo "[$PROJECT_RESPONSE]" | jq '.')
    
    # Recursively get all child projects (subgroups)
    echo "Fetching subgroups recursively..."
    CHILD_PROJECTS=$(get_child_projects_recursive "$ROOT_PROJECT_ID")
    
    CHILD_COUNT=$(echo "$CHILD_PROJECTS" | jq 'length')
    if [[ "$CHILD_COUNT" -gt 0 ]]; then
        echo "Found $CHILD_COUNT subgroup(s)"
        ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$CHILD_PROJECTS"))
    fi
else
    # Fetch all projects in the organization (including subgroups)
    echo "Fetching all projects from organization '$ORG_SLUG' (including subgroups)..."
    
    PAGE=1
    
    while true; do
        PROJECTS_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/?page=$PAGE&pageSize=$PER_PAGE")
        
        # Handle paged response format (data array)
        if echo "$PROJECTS_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
            PROJECTS=$(echo "$PROJECTS_RESPONSE" | jq '.data')
        else
            PROJECTS="$PROJECTS_RESPONSE"
        fi
        
        PROJECT_COUNT=$(echo "$PROJECTS" | jq 'if type == "array" then length else 0 end')
        
        if [[ "$PROJECT_COUNT" -eq 0 ]]; then
            break
        fi
        
        # Add root projects
        ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$PROJECTS"))
        
        # Recursively get children for each root project
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

# Collect all refs and releases for summary
declare -a ALL_REFS_TO_DELETE
declare -a ALL_RELEASES_TO_DELETE
TOTAL_REFS=0
TOTAL_RELEASES=0

# Step 2: For each project, get all assets and their refs, plus releases
echo "Scanning projects for refs and releases..."
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
    
    # Get releases for this project
    RELEASES_RESPONSE=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_SLUG/releases/")
    
    if echo "$RELEASES_RESPONSE" | jq -e '.data' >/dev/null 2>&1; then
        RELEASES=$(echo "$RELEASES_RESPONSE" | jq '.data')
    else
        RELEASES="$RELEASES_RESPONSE"
    fi
    
    RELEASE_COUNT=$(echo "$RELEASES" | jq 'if type == "array" then length else 0 end')
    
    if [[ "$RELEASE_COUNT" -gt 0 ]]; then
        echo "  Releases: $RELEASE_COUNT"
        for j in $(seq 0 $((RELEASE_COUNT - 1))); do
            RELEASE=$(echo "$RELEASES" | jq ".[$j]")
            RELEASE_ID=$(echo "$RELEASE" | jq -r '.id')
            RELEASE_VERSION=$(echo "$RELEASE" | jq -r '.version // .name // .id')
            echo "    - $RELEASE_VERSION (ID: $RELEASE_ID)"
            ALL_RELEASES_TO_DELETE+=("$ORG_SLUG|$PROJECT_SLUG|$RELEASE_ID|$RELEASE_VERSION")
            TOTAL_RELEASES=$((TOTAL_RELEASES + 1))
        done
    fi
    
    # Get assets for this project
    ASSETS=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_SLUG/assets/")
    ASSET_COUNT=$(echo "$ASSETS" | jq 'if type == "array" then length else 0 end')
    
    if [[ "$ASSET_COUNT" -eq 0 ]]; then
        echo "  No assets found."
        continue
    fi
    
    for j in $(seq 0 $((ASSET_COUNT - 1))); do
        ASSET=$(echo "$ASSETS" | jq ".[$j]")
        ASSET_SLUG=$(echo "$ASSET" | jq -r '.slug')
        ASSET_NAME=$(echo "$ASSET" | jq -r '.name // .slug')
        
        # Get refs (asset versions) for this asset
        REFS=$(devguard_curl "$API_URL/organizations/$ORG_SLUG/projects/$PROJECT_SLUG/assets/$ASSET_SLUG/refs/")
        REF_COUNT=$(echo "$REFS" | jq 'if type == "array" then length else 0 end')
        
        if [[ "$REF_COUNT" -gt 0 ]]; then
            echo "  Asset: $ASSET_NAME ($ASSET_SLUG)"
            echo "    Refs: $REF_COUNT"
            for k in $(seq 0 $((REF_COUNT - 1))); do
                REF=$(echo "$REFS" | jq ".[$k]")
                REF_NAME=$(echo "$REF" | jq -r '.name')
                REF_SLUG=$(echo "$REF" | jq -r '.slug // .name')
                REF_TYPE_RAW=$(echo "$REF" | jq -r '.type // "branch"')
                REF_IS_TAG=$(echo "$REF" | jq -r '.tag // false')
                REF_TYPE="branch"
                if [[ "$REF_TYPE_RAW" == "tag" ]] || [[ "$REF_IS_TAG" == "true" ]]; then
                    REF_TYPE="tag"
                fi
                echo "      - $REF_NAME (slug: $REF_SLUG, $REF_TYPE)"
                # Store both name (for display) and slug (for URL)
                ALL_REFS_TO_DELETE+=("$ORG_SLUG|$PROJECT_SLUG|$ASSET_SLUG|$REF_NAME|$REF_SLUG|$REF_TYPE")
                TOTAL_REFS=$((TOTAL_REFS + 1))
            done
        fi
    done
    
    echo ""
done

# Summary
echo "=============================================="
echo "Summary"
echo "=============================================="
echo "Total projects: $TOTAL_PROJECTS"
echo "Total refs to delete: $TOTAL_REFS"
echo "Total releases to delete: $TOTAL_RELEASES"
echo ""

if [[ "$TOTAL_REFS" -eq 0 && "$TOTAL_RELEASES" -eq 0 ]]; then
    echo "Nothing to delete."
    exit 0
fi

# List what will be deleted
if [[ "$TOTAL_REFS" -gt 0 ]]; then
    echo "Refs to be deleted:"
    for ref_entry in "${ALL_REFS_TO_DELETE[@]}"; do
        IFS='|' read -r org proj asset ref_name ref_slug ref_type <<< "$ref_entry"
        echo "  - $org/$proj/$asset/$ref_name ($ref_type, slug: $ref_slug)"
    done
    echo ""
fi

if [[ "$TOTAL_RELEASES" -gt 0 ]]; then
    echo "Releases to be deleted:"
    for release_entry in "${ALL_RELEASES_TO_DELETE[@]}"; do
        IFS='|' read -r org proj release_id version <<< "$release_entry"
        echo "  - $org/$proj: $version (ID: $release_id)"
    done
    echo ""
fi

# Confirmation
echo "=============================================="
echo "WARNING: This action is IRREVERSIBLE!"
echo "=============================================="
echo ""
read -p "Are you sure you want to delete ALL refs and releases listed above? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "Starting deletion..."
echo ""

# Delete refs
DELETED_REFS=0
FAILED_REFS=0

if [[ "$TOTAL_REFS" -gt 0 ]]; then
    echo "Deleting refs..."
    for ref_entry in "${ALL_REFS_TO_DELETE[@]}"; do
        IFS='|' read -r org proj asset ref_name ref_slug ref_type <<< "$ref_entry"
        
        # URL encode the ref slug (use slug for URL, name for display)
        ENCODED_REF=$(echo -n "$ref_slug" | jq -sRr @uri)
        
        echo -n "  Deleting ref: $org/$proj/$asset/$ref_name ($ref_type, slug: $ref_slug)... "
        
        DELETE_RESPONSE=$(devguard_curl "$API_URL/organizations/$org/projects/$proj/assets/$asset/refs/$ENCODED_REF/" "DELETE" 2>&1) || true
        
        if [[ "$DELETE_RESPONSE" == *"error"* ]] || [[ "$DELETE_RESPONSE" == *"Error"* ]]; then
            echo "FAILED"
            echo "    Error: $DELETE_RESPONSE"
            FAILED_REFS=$((FAILED_REFS + 1))
        else
            echo "OK"
            DELETED_REFS=$((DELETED_REFS + 1))
        fi
    done
    echo ""
fi

# Delete releases
DELETED_RELEASES=0
FAILED_RELEASES=0

if [[ "$TOTAL_RELEASES" -gt 0 ]]; then
    echo "Deleting releases..."
    for release_entry in "${ALL_RELEASES_TO_DELETE[@]}"; do
        IFS='|' read -r org proj release_id version <<< "$release_entry"
        
        echo -n "  Deleting release: $org/$proj: $version (ID: $release_id)... "
        
        DELETE_RESPONSE=$(devguard_curl "$API_URL/organizations/$org/projects/$proj/releases/$release_id/" "DELETE" 2>&1) || true
        
        if [[ "$DELETE_RESPONSE" == *"error"* ]] || [[ "$DELETE_RESPONSE" == *"Error"* ]]; then
            echo "FAILED"
            echo "    Error: $DELETE_RESPONSE"
            FAILED_RELEASES=$((FAILED_RELEASES + 1))
        else
            echo "OK"
            DELETED_RELEASES=$((DELETED_RELEASES + 1))
        fi
    done
    echo ""
fi

# Final summary
echo "=============================================="
echo "Deletion Complete"
echo "=============================================="
echo "Refs:"
echo "  Deleted: $DELETED_REFS"
echo "  Failed: $FAILED_REFS"
echo ""
echo "Releases:"
echo "  Deleted: $DELETED_RELEASES"
echo "  Failed: $FAILED_RELEASES"
echo ""

if [[ "$FAILED_REFS" -gt 0 || "$FAILED_RELEASES" -gt 0 ]]; then
    echo "Some deletions failed. Please check the errors above."
    exit 1
fi

echo "All refs and releases have been successfully deleted."
