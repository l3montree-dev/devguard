#!/bin/bash

# delete or close GitLab issues with the "devguard" label in a specified project.
# requires the PRIVATE_TOKEN environment variable to be set with a valid GitLab API token.
# action can be "delete" or "close"
# state can be "open", "closed", or "all"
# usage: ./delete_gitlab_tickets_by_devguard_label.sh <project_id> <gitlab_api_url> [state] [action]
# example: ./delete_gitlab_tickets_by_devguard_label.sh 123 https://gitlab.example.com/api/v4 open close

set -e

PROJECT_ID="$1"
GITLAB_API_URL="$2"
STATE="${3:-open}"    # Default to "open"
ACTION="${4:-delete}" # Default to "delete"
LABEL="devguard"

if [[ -z "$PROJECT_ID" || -z "$GITLAB_API_URL" ]]; then
    echo "Usage: $0 <project_id> <gitlab_api_url> [state] [action]"
    echo "  state:  'open' (default), 'closed', or 'all'"
    echo "  action: 'delete' (default) or 'close'"
    echo ""
    echo "Examples:"
    echo "  $0 123 https://gitlab.example.com/api/v4                 # delete open issues"
    echo "  $0 123 https://gitlab.example.com/api/v4 open close      # close open issues"
    echo "  $0 123 https://gitlab.example.com/api/v4 closed delete   # delete closed issues"
    echo "  $0 123 https://gitlab.example.com/api/v4 all delete      # delete all issues"
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
    echo "Error: PRIVATE_TOKEN environment variable must be set"
    exit 1
fi

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

if [[ "$ACTION" == "delete" ]]; then
    ACTION_VERB="DELETED"
    ACTION_VERB_LOWER="deleted"
    ACTION_ING="Deleting"
else
    ACTION_VERB="CLOSED"
    ACTION_VERB_LOWER="closed"
    ACTION_ING="Closing"
fi

echo "Fetching $STATE_DISPLAY issues with label '$LABEL' from project $PROJECT_ID..."

ISSUES=$(curl --silent --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
    --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues?labels=$LABEL&per_page=100$API_STATE_PARAM")

ISSUE_IIDS=$(echo "$ISSUES" | jq -r '.[].iid')
ISSUE_COUNT=$(echo "$ISSUES" | jq 'length')

if [[ "$ISSUE_COUNT" -eq 0 ]]; then
    echo "No $STATE_DISPLAY issues found with label '$LABEL'. Nothing to $ACTION."
    exit 0
fi

echo ""
echo "=========================================="
echo "WARNING: The following $ISSUE_COUNT $STATE_DISPLAY issue(s) will be $ACTION_VERB:"
echo "=========================================="
echo "$ISSUES" | jq -r '.[] | "  #\(.iid) [\(.state)]: \(.title)"'
echo "=========================================="
echo ""

read -p "Are you sure you want to $ACTION these $ISSUE_COUNT issue(s)? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted. No issues were ${ACTION_VERB_LOWER}."
    exit 0
fi

echo ""
echo "$ACTION_ING issues..."
for IID in $ISSUE_IIDS; do
    echo "$ACTION_ING issue #$IID..."
    
    if [[ "$ACTION" == "delete" ]]; then
        HTTP_STATUS=$(curl --silent --output /dev/null --write-out "%{http_code}" \
            --request DELETE \
            --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
            --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues/$IID")
        EXPECTED_STATUS=204
    else
        HTTP_STATUS=$(curl --silent --output /dev/null --write-out "%{http_code}" \
            --request PUT \
            --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
            --header "Content-Type: application/json" \
            --data '{"state_event":"close"}' \
            --url "$GITLAB_API_URL/projects/$PROJECT_ID/issues/$IID")
        EXPECTED_STATUS=200
    fi
    
    if [[ "$HTTP_STATUS" -eq "$EXPECTED_STATUS" ]]; then
        echo "  ✓ Issue #$IID ${ACTION_VERB_LOWER} successfully"
    else
        echo "  ✗ Failed to $ACTION issue #$IID (HTTP status: $HTTP_STATUS)"
    fi
done

echo ""
echo "Done."