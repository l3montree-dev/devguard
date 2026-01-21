#!/bin/bash

# Find dead (unused) exported functions in Go code
# Based on: https://www.codestudy.net/blog/find-dead-code-in-golang-monorepo/

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔍 Finding dead exported functions...${NC}\n"

# Find all exported functions (starting with capital letter)
# Exclude test files and generated files
EXPORTED_FUNCS=$(grep -rn "^func [A-Z]" \
  --include="*.go" \
  --exclude="*_test.go" \
  --exclude="*.pb.go" \
  --exclude="mock_*.go" \
  . | grep -v "/vendor/" | grep -v "/mocks/")

DEAD_COUNT=0
TOTAL_COUNT=0

# Check each exported function
while IFS= read -r line; do
  # Extract file path, line number, and function name
  FILE=$(echo "$line" | cut -d':' -f1)
  LINE_NUM=$(echo "$line" | cut -d':' -f2)
  FUNC_NAME=$(echo "$line" | sed 's/.*func \([A-Z][a-zA-Z0-9_]*\).*/\1/')
  
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  
  # Search for references to this function (exclude the definition itself)
  # Look for the function name as a word boundary (used in any context)
  REFERENCES=$(grep -rn "\b${FUNC_NAME}\b" \
    --include="*.go" \
    . 2>/dev/null | \
    grep -v "${FILE}:${LINE_NUM}:" | \
    grep -v "/vendor/" || true)
  
  # If no references found, it's potentially dead code
  if [ -z "$REFERENCES" ]; then
    echo -e "${RED}❌ Dead function found:${NC}"
    echo -e "   ${YELLOW}Function:${NC} ${FUNC_NAME}"
    echo -e "   ${YELLOW}Location:${NC} ${FILE}:${LINE_NUM}"
    echo
    DEAD_COUNT=$((DEAD_COUNT + 1))
  fi
done <<< "$EXPORTED_FUNCS"

echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}Summary:${NC}"
echo -e "  Total exported functions: ${TOTAL_COUNT}"
echo -e "  Dead functions found: ${RED}${DEAD_COUNT}${NC}"
echo -e "  Active functions: ${GREEN}$((TOTAL_COUNT - DEAD_COUNT))${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"

if [ $DEAD_COUNT -gt 0 ]; then
  exit 1
else
  echo -e "\n${GREEN}✅ No dead code found!${NC}"
  exit 0
fi
