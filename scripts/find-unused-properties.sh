#!/bin/bash

# Find unused unexported (private) struct fields in Go code
# Optimized for speed using ripgrep and parallel processing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔍 Finding unused unexported struct fields (controllers & services only)...${NC}\n"

# Check if ripgrep is available (much faster than grep)
if command -v rg &> /dev/null; then
    GREP_CMD="rg"
    GREP_OPTS="--no-heading --line-number"
else
    GREP_CMD="grep"
    GREP_OPTS="-rn"
    echo -e "${YELLOW}⚡ Tip: Install ripgrep (rg) for 10-100x faster searches!${NC}\n"
fi

# Create temp files for intermediate results
FIELDS_FILE=$(mktemp)
DEAD_FIELDS_FILE=$(mktemp)
trap "rm -f $FIELDS_FILE $DEAD_FIELDS_FILE" EXIT

# Step 1: Collect all unexported fields in one pass (controllers & services only)
echo -e "${YELLOW}📋 Step 1/3: Collecting struct fields from controllers/ and services/...${NC}"
if [ "$GREP_CMD" = "rg" ]; then
    # Only match lines that look like struct fields (not comments or strings)
    # Pattern: whitespace, lowercase letter start, identifier, whitespace, type
    # Excludes lines starting with // or inside /* */ or backtick strings
    rg --type go --no-ignore-vcs \
       --glob '!*_test.go' --glob '!*.pb.go' --glob '!mock_*.go' \
       '^\s+[a-z][a-zA-Z0-9_]*\s+\**[A-Z\[\]{}*a-z]' \
       controllers/ services/ \
       --line-number --with-filename | \
       grep -v '^\s*//' | \
       sed -E 's/^([^:]+):([0-9]+):(.*)/\1:\2:\3/' > "$FIELDS_FILE"
else
    find controllers/ services/ -name "*.go" \
      -not -name "*_test.go" \
      -not -name "*.pb.go" \
      -not -name "mock_*.go" \
      -exec grep -Hn '^\s\+[a-z][a-zA-Z0-9_]*\s\+\**[A-Z\[\]{}*a-z]' {} \; | \
      grep -v '^\s*//' > "$FIELDS_FILE"
fi

TOTAL_COUNT=$(wc -l < "$FIELDS_FILE")
echo -e "${GREEN}✓ Found ${TOTAL_COUNT} unexported fields${NC}\n"

# Step 2: Build regex pattern for all field names
echo -e "${YELLOW}🔨 Step 2/3: Building search pattern...${NC}"
FIELD_NAMES=$(sed -E 's/^[^:]+:[0-9]+:[[:space:]]*([a-z][a-zA-Z0-9_]*).*/\1/' "$FIELDS_FILE" | \
    grep -v -E '^(if|for|func|return|var|const|type|package|import|case|default|switch|defer)$' | \
    grep -E '^[a-z][a-zA-Z0-9_]{1,}$' | \
    sort -u)

# Step 3: Search for all fields at once
echo -e "${YELLOW}🔍 Step 3/3: Searching for field usage...${NC}"
if [ "$GREP_CMD" = "rg" ]; then
    # Build pattern: (field1|field2|field3)
    PATTERN=$(echo "$FIELD_NAMES" | tr '\n' '|' | sed 's/|$//')
    if [ -n "$PATTERN" ]; then
        REFERENCES=$(rg --type go --no-ignore-vcs -w "($PATTERN)" \
            --glob '!vendor/' \
            -o -r '$0' 2>/dev/null || true)
    else
        REFERENCES=""
    fi
else
    PATTERN=$(echo "$FIELD_NAMES" | tr '\n' '|' | sed 's/|$//')
    if [ -n "$PATTERN" ]; then
        REFERENCES=$(grep -roE "\b($PATTERN)\b" \
            --include="*.go" \
            --exclude-dir=vendor \
            . 2>/dev/null || true)
    else
        REFERENCES=""
    fi
fi

# Build a set of referenced fields
REFERENCED_FIELDS=$(echo "$REFERENCES" | sort -u)

# Step 4: Find fields that were never referenced
DEAD_COUNT=0
while IFS=: read -r file line_num content; do
    FIELD_NAME=$(echo "$content" | sed -E 's/^[[:space:]]*([a-z][a-zA-Z0-9_]*).*/\1/')
    
    # Skip invalid names
    if [[ ${#FIELD_NAME} -lt 2 ]] || [[ "$FIELD_NAME" =~ ^(if|for|func|return|var|const|type|package|import|case|default|switch|defer)$ ]]; then
        continue
    fi
    
    # Check if field is in the referenced set
    if ! echo "$REFERENCED_FIELDS" | grep -q "^${FIELD_NAME}$"; then
        # Also verify it's not used in the same file (definition doesn't count as usage)
        # Exclude constructor initialization lines like: fieldName: fieldName,
        if ! grep -E "\\.${FIELD_NAME}\b" "${file}" 2>/dev/null | grep -v -E "^\s+${FIELD_NAME}:\s+${FIELD_NAME},?\s*$" | grep -q .; then
            echo -e "${RED}❌ Unused field:${NC} ${YELLOW}${FIELD_NAME}${NC} in ${file}:${line_num}"
            echo "   ${content}"
            echo
            DEAD_COUNT=$((DEAD_COUNT + 1))
        fi
    fi
done < "$FIELDS_FILE"

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}Summary:${NC}"
echo -e "  Total unexported fields: ${TOTAL_COUNT}"
echo -e "  Unused fields found: ${RED}${DEAD_COUNT}${NC}"
echo -e "  Used fields: ${GREEN}$((TOTAL_COUNT - DEAD_COUNT))${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"

if [ $DEAD_COUNT -gt 0 ]; then
    echo -e "\n${YELLOW}⚠️  Note: Some fields may be used via reflection, JSON tags, or database mapping${NC}"
    exit 1
else
    echo -e "\n${GREEN}✅ No unused fields found!${NC}"
    exit 0
fi
