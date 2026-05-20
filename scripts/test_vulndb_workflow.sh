#!/usr/bin/env bash
# Test the full vulndb export/quickdiff/import workflow locally.
#
# Steps:
#   1. Export a full vulndb archive (no diff) — establishes the baseline
#   2. Import step-1 archive locally — sets lastRCImport to step-1's timestamp
#   3. Export again WITH --diff-to-previous — quickdiff.FromVersion = step-1's timestamp
#   4. Reset lastRCImport to step-1's timestamp, then import step-3 archive
#      — importer must take the quickdiff path, not full sync
#
# Prerequisites:
#   - Postgres running with the devguard schema migrated
#   - Standard POSTGRES_* env vars set (or .env loaded)

set -euo pipefail

CLI="go run ./cmd/devguard-cli/main.go"
WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

STEP1_ARCHIVE="vulndb_step1.tar.zst"
STEP2_ARCHIVE="vulndb_step2.tar.zst"

: "${POSTGRES_HOST:=localhost}"
: "${POSTGRES_USER:=devguard}"
: "${POSTGRES_PASSWORD:=devguard}"
: "${POSTGRES_DB:=devguard}"

PSQL="psql -h $POSTGRES_HOST -U $POSTGRES_USER $POSTGRES_DB"

log()  { echo ""; echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

extract_integrity_timestamp() {
    local archive="$1"
    local tmpd
    tmpd=$(mktemp -d)
    zstd -d --memory=512MB "$archive" -o "$tmpd/vulndb.tar" --quiet
    tar -xf "$tmpd/vulndb.tar" -C "$tmpd" integrity_checks.json
    python3 -c "import json,sys; d=json.load(open('$tmpd/integrity_checks.json')); print(d.get('ImportTimestamp') or d.get('import_timestamp'))"
    rm -rf "$tmpd"
}

# ── Step 1: full export ────────────────────────────────────────────────────────
log "STEP 1: full export (no diff)"
$CLI vulndb export
[[ -f vulndb.tar.zst ]] || fail "vulndb.tar.zst not produced"
cp vulndb.tar.zst "$STEP1_ARCHIVE"

STEP1_TS=$(extract_integrity_timestamp "$STEP1_ARCHIVE")
echo "  saved as $STEP1_ARCHIVE  (timestamp: $STEP1_TS)"

# ── Step 2: import step-1 locally to set lastRCImport ─────────────────────────
log "STEP 2: import step-1 locally (sets lastRCImport = step-1 timestamp)"
# vulndb.tar.zst is already the step-1 archive
$CLI vulndb import --local-archive
PGPASSWORD="$POSTGRES_PASSWORD" $PSQL -t -c \
    "SELECT val FROM config WHERE key = 'vulndb.lastRCImport';" | grep -q "$STEP1_TS" \
    || fail "lastRCImport was not set to step-1 timestamp after import"
echo "  lastRCImport confirmed = $STEP1_TS"

# ── Step 3: export with quickdiff ─────────────────────────────────────────────
log "STEP 3: export --diff-to-previous --local-archive (FromVersion will be step-1 timestamp)"
# vulndb.tar.zst is still step-1 archive; internal ImportRC will use it, setting lastRCImport = step-1 timestamp
cp "$STEP1_ARCHIVE" vulndb.tar.zst
$CLI vulndb export --diff-to-previous --local-archive
[[ -f vulndb.tar.zst ]] || fail "vulndb.tar.zst not produced"
cp vulndb.tar.zst "$STEP2_ARCHIVE"

# Verify quickdiff.gob is in the archive
TMPDIR_CHECK=$(mktemp -d)
zstd -d --memory=512MB "$STEP2_ARCHIVE" -o "$TMPDIR_CHECK/vulndb.tar" --quiet
tar -xf "$TMPDIR_CHECK/vulndb.tar" -C "$TMPDIR_CHECK"
if [[ -f "$TMPDIR_CHECK/quickdiff.gob" ]]; then
    QDSIZE=$(du -h "$TMPDIR_CHECK/quickdiff.gob" | cut -f1)
    echo "  quickdiff.gob present (${QDSIZE})"
else
    rm -rf "$TMPDIR_CHECK"
    fail "quickdiff.gob missing from $STEP2_ARCHIVE"
fi
rm -rf "$TMPDIR_CHECK"

STEP2_TS=$(extract_integrity_timestamp "$STEP2_ARCHIVE")
echo "  saved as $STEP2_ARCHIVE  (timestamp: $STEP2_TS)"

# ── Step 4: reset DB to step-1 state, then import step-2 via quickdiff ────────
# The export in step 3 also synced fresh data into the live DB. Reset it back to
# step-1 state so the quickdiff patch can be applied cleanly.
log "STEP 4: reset DB to step-1 state"
cp "$STEP1_ARCHIVE" vulndb.tar.zst
# Clear lastRCImport so the import doesn't skip as "up to date"
PGPASSWORD="$POSTGRES_PASSWORD" $PSQL -c \
    "DELETE FROM config WHERE key = 'vulndb.lastRCImport';" > /dev/null
$CLI vulndb import --local-archive
echo "  DB reset to step-1 state"

log "STEP 5: import via quickdiff path"

STEP1_TS_JSON="\"${STEP1_TS}\""
echo "  resetting lastRCImport → $STEP1_TS"
PGPASSWORD="$POSTGRES_PASSWORD" $PSQL -c \
    "INSERT INTO config (key, val) VALUES ('vulndb.lastRCImport', '$STEP1_TS_JSON') ON CONFLICT (key) DO UPDATE SET val = EXCLUDED.val;" \
    > /dev/null

cp "$STEP2_ARCHIVE" vulndb.tar.zst

IMPORT_LOG=$(mktemp)
$CLI vulndb import --local-archive 2>&1 | tee "$IMPORT_LOG"

echo ""
if grep -q "quick-diff: version matches, applying patch" "$IMPORT_LOG"; then
    echo "  quickdiff path taken"
elif grep -q "quick-diff not applicable" "$IMPORT_LOG"; then
    rm -f "$IMPORT_LOG"
    fail "quickdiff was NOT applied — version mismatch or missing quickdiff.gob"
elif grep -q "up to date, skipping" "$IMPORT_LOG"; then
    rm -f "$IMPORT_LOG"
    fail "import skipped — lastRCImport reset may not have worked"
else
    echo "  WARNING: could not confirm quickdiff path from log"
fi

if grep -q "integrity validation failed" "$IMPORT_LOG"; then
    rm -f "$IMPORT_LOG"
    fail "integrity check failed after quickdiff import"
else
    echo "  integrity check passed"
fi

rm -f "$IMPORT_LOG"

log "ALL STEPS PASSED"
echo "  step1 archive : $STEP1_ARCHIVE  ($STEP1_TS)"
echo "  step2 archive : $STEP2_ARCHIVE  ($STEP2_TS, contains quickdiff.gob)"
