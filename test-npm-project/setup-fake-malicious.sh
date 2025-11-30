#!/bin/bash

echo "Creating FAKE malicious package entry for safe testing..."

MALICIOUS_DIR="../malicious-packages/osv/malicious/npm/test-fake-malicious-npm-package"
mkdir -p "$MALICIOUS_DIR"

cat > "$MALICIOUS_DIR/MAL-FAKE-TEST.json" << 'EOF'
{
  "id": "MAL-FAKE-TEST-001",
  "summary": "FAKE malicious package for testing proxy (NOT REAL)",
  "details": "This is a FAKE test entry that does NOT correspond to any real package.\nIt is used purely for testing the proxy's blocking functionality.\nThis package does not exist on npm and contains no actual code.",
  "published": "2025-11-30T00:00:00Z",
  "affected": [
    {
      "package": {
        "ecosystem": "npm",
        "name": "test-fake-malicious-npm-package"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {
              "introduced": "0"
            }
          ]
        }
      ]
    }
  ]
}
EOF

echo "Created fake malicious package entry at:"
echo "  $MALICIOUS_DIR/MAL-FAKE-TEST.json"
echo ""
echo "This fake package will NEVER install because:"
echo "  1. It doesn't exist on npm"
echo "  2. The proxy will block it with HTTP 403"
echo ""
echo "Next steps:"
echo "  1. Restart the proxy to load the new entry: go run main.go"
echo "  2. Run npm install"
