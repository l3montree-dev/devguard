#!/bin/bash

# Delete or close GitLab issues with the "devguard" label across all projects in a group.
# Requires the PRIVATE_TOKEN environment variable to be set with a valid GitLab API token.
#
# Usage: ./delete_gitlab_issues_by_group.sh <group_id> <gitlab_api_url> [state] [action]
#
# Arguments:
#   group_id       - GitLab group ID
#   gitlab_api_url - GitLab API URL (e.g., https://gitlab.example.com/api/v4)
#   state          - 'open' (default), 'closed', or 'all'
#   action         - 'delete' (default) or 'close'
#
# Examples:
#   ./delete_gitlab_issues_by_group.sh 42 https://gitlab.example.com/api/v4
#   ./delete_gitlab_issues_by_group.sh 42 https://gitlab.example.com/api/v4 open close
#   ./delete_gitlab_issues_by_group.sh 42 https://gitlab.example.com/api/v4 all delete

set -e

GROUP_ID="$1"
GITLAB_API_URL="$2"
STATE="${3:-open}"
ACTION="${4:-delete}"
LABEL="devguard"
PER_PAGE=100

if [[ -z "$GROUP_ID" || -z "$GITLAB_API_URL" ]]; then
    echo "Usage: $0 <group_id> <gitlab_api_url> [state] [action]"
    echo ""
    echo "Arguments:"
    echo "  group_id       - GitLab group ID"
    echo "  gitlab_api_url - GitLab API URL"
    echo "  state          - 'open' (default), 'closed', or 'all'"
    echo "  action         - 'delete' (default) or 'close'"
    echo ""
    echo "Examples:"
    echo "  $0 42 https://gitlab.example.com/api/v4                 # delete open issues"
    echo "  $0 42 https://gitlab.example.com/api/v4 open close      # close open issues"
    echo "  $0 42 https://gitlab.example.com/api/v4 all delete      # delete all issues"
    exit 1
fi

if [[ "$STATE" != "open" && "$STATE" != "closed" && "$STATE" != "all" ]]; then
    echo "Error: state must be 'open', 'closed', or 'all'"
    exit 1
fi

if [[ "$ACTION" != "delete" && "$ACTION" != "close" ]]; then
    echo "Error: action must be 'delete' or 'close'"
    exit 1
fi

if [[ -z "$PRIVATE_TOKEN" ]]; then
    BASE_URL="${GITLAB_API_URL%%/api/*}"
    if [[ -z "$BASE_URL" ]]; then
        BASE_URL="https://gitlab.example.com"
    fi
    echo "Error: PRIVATE_TOKEN environment variable must be set with a valid GitLab API token."
    echo "Create one at: ${BASE_URL}/-/profile/personal_access_tokens"
    exit 1
fi

# Set up state parameter for API calls
case "$STATE" in
    open)
        API_STATE_PARAM="&state=opened"
        STATE_DISPLAY="open"
        ;;
    closed)
        API_STATE_PARAM="&state=closed"
        STATE_DISPLAY="closed"
        ;;
    all)
        API_STATE_PARAM=""
        STATE_DISPLAY="all"
        ;;
esac

# Set up action verbs for display
if [[ "$ACTION" == "delete" ]]; then
    ACTION_VERB="DELETED"
    ACTION_VERB_LOWER="deleted"
    ACTION_ING="Deleting"
else
    ACTION_VERB="CLOSED"
    ACTION_VERB_LOWER="closed"
    ACTION_ING="Closing"
fi

# Helper function to make GitLab API calls
curl_gitlab() {
    local URL="$1"
    local RESPONSE

    RESPONSE=$(curl --silent --show-error --fail --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" --url "$URL")
    CURL_EXIT_CODE=$?

    if [[ $CURL_EXIT_CODE -ne 0 ]]; then
        echo "Error: Failed to fetch from GitLab API (curl exit code $CURL_EXIT_CODE)." >&2
        echo "URL: $URL" >&2
        exit 2
    fi

    if ! echo "$RESPONSE" | jq empty >/dev/null 2>&1; then
        echo "Error: Response from GitLab API is not valid JSON:" >&2
        echo "$RESPONSE" >&2
        exit 3
    fi

    echo "$RESPONSE"
}

# Fetch all projects in the group (including subgroups)
echo "Fetching projects from group $GROUP_ID (including subgroups)..."

PAGE=1
ALL_PROJECTS="[]"

while true; do
    PROJECTS=$(curl_gitlab "$GITLAB_API_URL/groups/$GROUP_ID/projects?include_subgroups=true&per_page=$PER_PAGE&page=$PAGE")

    PROJECT_COUNT=$(echo "$PROJECTS" | jq 'length')

    if [[ "$PROJECT_COUNT" -eq 0 ]]; then
        break
    fi

    ALL_PROJECTS=$(jq -s '.[0] + .[1]' <(echo "$ALL_PROJECTS") <(echo "$PROJECTS"))

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

echo "Found $TOTAL_PROJECTS project(s). Fetching $STATE_DISPLAY issues with label '$LABEL'..."
echo ""

# Fetch all issues with the devguard label across all projects
# Store as array of objects with project info included
ALL_ISSUES="[]"

while IFS='|' read -r PROJECT_ID PROJECT_PATH; do
    PAGE=1

    while true; do
        ISSUES=$(curl_gitlab "$GITLAB_API_URL/projects/$PROJECT_ID/issues?labels=$LABEL&per_page=$PER_PAGE&page=$PAGE$API_STATE_PARAM")

        ISSUE_COUNT=$(echo "$ISSUES" | jq 'length')

        if [[ "$ISSUE_COUNT" -eq 0 ]]; then
            break
        fi

        # Add project_path to each issue for display purposes
        ISSUES_WITH_PATH=$(echo "$ISSUES" | jq --arg path "$PROJECT_PATH" '[.[] | . + {project_path: $path}]')
        ALL_ISSUES=$(jq -s '.[0] + .[1]' <(echo "$ALL_ISSUES") <(echo "$ISSUES_WITH_PATH"))

        if [[ "$ISSUE_COUNT" -lt "$PER_PAGE" ]]; then
            break
        fi

        PAGE=$((PAGE + 1))
    done
done <<< "$(echo "$ALL_PROJECTS" | jq -r '.[] | "\(.id)|\(.path_with_namespace)"')"

TOTAL_ISSUES=$(echo "$ALL_ISSUES" | jq 'length')

if [[ "$TOTAL_ISSUES" -eq 0 ]]; then
    echo "No $STATE_DISPLAY issues found with label '$LABEL' in group $GROUP_ID. Nothing to $ACTION."
    exit 0
fi

# Display issues grouped by project
echo "=========================================="
echo "WARNING: The following $TOTAL_ISSUES $STATE_DISPLAY issue(s) will be $ACTION_VERB:"
echo "=========================================="

CURRENT_PROJECT=""
while IFS='|' read -r PROJECT_PATH PROJECT_ID IID STATE TITLE; do
    if [[ "$CURRENT_PROJECT" != "$PROJECT_PATH" ]]; then
        if [[ -n "$CURRENT_PROJECT" ]]; then
            echo ""
        fi
        echo "$PROJECT_PATH:"
        CURRENT_PROJECT="$PROJECT_PATH"
    fi
    printf "  #%-6s [%-6s] %s\n" "$IID" "$STATE" "$TITLE"
done <<< "$(echo "$ALL_ISSUES" | jq -r 'sort_by(.project_path, .iid) | .[] | "\(.project_path)|\(.project_id)|\(.iid)|\(.state)|\(.title)"')"

echo ""
echo "=========================================="
echo ""

read -p "Are you sure you want to $ACTION these $TOTAL_ISSUES issue(s)? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted. No issues were ${ACTION_VERB_LOWER}."
    exit 0
fi

echo ""
echo "$ACTION_ING issues..."

SUCCESS_COUNT=0
FAIL_COUNT=0

while IFS='|' read -r PROJECT_PATH PROJECT_ID IID; do
    echo "$ACTION_ING $PROJECT_PATH #$IID..."

    RESPONSE_FILE=$(mktemp)
    
    if [[ "$ACTION" == "delete" ]]; then
        HTTP_STATUS=$(curl --silent --output "$RESPONSE_FILE" --write-out "%{http_code}" \
            --request DELETE \
            --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
            --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues/$IID")
        EXPECTED_STATUS=204
    else
        HTTP_STATUS=$(curl --silent --output "$RESPONSE_FILE" --write-out "%{http_code}" \
            --request PUT \
            --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
            --header "Content-Type: application/json" \
            --data '{"state_event":"close"}' \
            --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues/$IID")
        EXPECTED_STATUS=200
    fi

    if [[ "$HTTP_STATUS" -eq "$EXPECTED_STATUS" ]]; then
        echo "  ✓ ${ACTION_VERB_LOWER} successfully"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        ERROR_MSG=$(cat "$RESPONSE_FILE" | jq -r '.message // .error // "Unknown error"' 2>/dev/null || cat "$RESPONSE_FILE")
        echo "  ✗ Failed (HTTP $HTTP_STATUS): $ERROR_MSG"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    rm -f "$RESPONSE_FILE"
done <<< "$(echo "$ALL_ISSUES" | jq -r '.[] | "\(.project_path)|\(.project_id)|\(.iid)"')"

echo ""
echo "=========================================="
echo "Summary:"
echo "  Successfully ${ACTION_VERB_LOWER}: $SUCCESS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo "=========================================="
echo "Done."