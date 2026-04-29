#!/usr/bin/env bash
# Automated end-to-end column-awareness integration test.
#
# Exercises:
#   * Container bring-up + healthcheck
#   * CREATE / ALTER ADD COLUMN / RENAME TABLE mid-run
#   * Connector bounded by SHOW MASTER STATUS position
#   * Named columns + ENUM label resolution in stdout output
#   * Schema cache persistence (write on cold parquet run → load on resume run via checkpoint key)
#   * Resume from `last_checkpoint.json` after a clean shutdown — second run skips already-processed events and picks up exactly where the prior run stopped.
#
# Usage:
#   ./docker/integration_test.sh            # run then tear down
#   ./docker/integration_test.sh --keep     # leave container + temp files for inspection
#
# Exit codes:
#   0  — all assertions passed
#   1  — assertion failure
#   2  — setup failure (docker, mysql, build)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

KEEP=false
for arg in "${@:-}"; do
  case "$arg" in
  "" | --) : ;;
  --keep) KEEP=true ;;
  *)
    echo "unknown arg: $arg" >&2
    exit 2
    ;;
  esac
done

TMPDIR=$(mktemp -d -t myzql-integration.XXXXXX)

# Detect pre-existing container so we don't tear down something the user
# was running independently (common case: developer already has the test
# MySQL up from a prior session).
CONTAINER_WAS_RUNNING=false
if docker inspect myzql-ssl-test >/dev/null 2>&1; then
  existing_status=$(docker inspect --format='{{.State.Status}}' myzql-ssl-test 2>/dev/null || echo "")
  if [ "$existing_status" = "running" ]; then
    CONTAINER_WAS_RUNNING=true
  fi
fi

cleanup() {
  local rc=$?
  if [ "$KEEP" = "true" ]; then
    echo "==> --keep: leaving container + $TMPDIR"
  elif [ "$CONTAINER_WAS_RUNNING" = "true" ]; then
    echo "==> Container was pre-existing; leaving it running. Removing $TMPDIR"
    rm -rf "$TMPDIR"
  else
    echo "==> Cleaning up..."
    (cd "$SCRIPT_DIR" && docker compose down -v >/dev/null 2>&1) || true
    rm -rf "$TMPDIR"
  fi
  exit $rc
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# ----------------------------------------------------------------
# 1. Bring up MySQL (idempotent — reuses any pre-existing container)
# ----------------------------------------------------------------
if [ "$CONTAINER_WAS_RUNNING" = "true" ]; then
  echo "==> Reusing already-running myzql-ssl-test container"
else
  echo "==> Starting MySQL (docker compose)..."
  (cd "$SCRIPT_DIR" && docker compose up -d --build) >/dev/null
fi

echo "==> Waiting for healthcheck..."
status=""
for i in $(seq 1 40); do
  status=$(docker inspect --format='{{.State.Health.Status}}' myzql-ssl-test 2>/dev/null || echo "")
  [ "$status" = "healthy" ] && break
  sleep 3
done
[ "$status" = "healthy" ] || {
  docker logs myzql-ssl-test --tail 50 >&2
  exit 2
}

MYSQL_EXEC=(docker exec -i myzql-ssl-test mysql
  -u root -prootpass
  --ssl-mode=REQUIRED
  --default-character-set=utf8mb4
  testdb)

# ----------------------------------------------------------------
# 2. DDL + DML scenario — must include table that didn't exist in
#    init.sql so we can verify CREATE was handled from binlog.
# ----------------------------------------------------------------
echo "==> Seeding DDL/DML scenario..."
"${MYSQL_EXEC[@]}" <<'SQL' >/dev/null
DROP TABLE IF EXISTS itest_t1;
DROP TABLE IF EXISTS itest_renamed;

CREATE TABLE itest_t1 (
    id    INT PRIMARY KEY,
    label VARCHAR(100),
    kind  ENUM('alpha','beta','gamma') DEFAULT 'alpha'
) ENGINE=InnoDB;

INSERT INTO itest_t1 (id, label, kind) VALUES (1, 'first', 'alpha'), (2, 'second', 'beta');

ALTER TABLE itest_t1 ADD COLUMN note TEXT AFTER label;

INSERT INTO itest_t1 (id, label, note, kind) VALUES (3, 'third', 'with note', 'gamma');

RENAME TABLE itest_t1 TO itest_renamed;

INSERT INTO itest_renamed (id, label, note, kind) VALUES (4, 'fourth', 'after rename', 'alpha');

-- ============================================================
-- Canary events: a single table that exercises every type the
-- connector has had regressions on — bool coercion, enum/set
-- label resolution, decimal string precision, DATETIME(3)
-- fractional seconds, JSON passthrough, BIT(1), BLOB with NULL,
-- and tinyint(10) (prefix-match regression guard).
-- Read back through DuckDB after the parquet run to catch
-- per-type serialization regressions end-to-end.
-- ============================================================
DROP TABLE IF EXISTS canary_events;
CREATE TABLE canary_events (
    id          INT PRIMARY KEY,
    is_active   TINYINT(1),
    flag_bit    BIT(1),
    counter     TINYINT(10),
    status      ENUM('pending','done','cancelled'),
    perms       SET('r','w','x'),
    amount      DECIMAL(12,4),
    payload     JSON,
    body        BLOB,
    created_at  DATETIME(3),
    note        VARCHAR(100)
) ENGINE=InnoDB;

INSERT INTO canary_events VALUES
    (1, 1, b'1', 7,  'pending',   'r,w',   '1234.5678', '{"k":"v"}',  X'DEADBEEF', '2026-04-24 10:00:00.123', 'first'),
    (2, 0, b'0', 99, 'done',      'r,w,x', '-99.0001',  '[1,2,3]',    X'00',       '2026-04-24 10:00:01.000', NULL),
    (3, 1, b'1', 0,  'cancelled', '',      '0.0000',    'null',       NULL,        '2026-04-24 10:00:02.999', 'null blob'),
    (4, 0, b'0', 42, 'pending',   'x',     '0.0001',    '{"nested":{"a":1,"b":[true,false,null]}}', X'48656C6C6F', '2026-04-24 10:00:03.500', 'nested json'),
    (5, 1, b'1', 10, 'done',      'r,x',   '99999999.9999', 'true',  X'', '2026-04-24 10:00:04.001', 'max decimal');
SQL

# ----------------------------------------------------------------
# 3. Capture master position to bound the connector run.
# ----------------------------------------------------------------
# MySQL 8.4 renamed the command; try SHOW BINARY LOG STATUS first.
if POS=$("${MYSQL_EXEC[@]}" -N -B -e "SHOW BINARY LOG STATUS" 2>/dev/null); then
  :
else POS=$("${MYSQL_EXEC[@]}" -N -B -e "SHOW MASTER STATUS"); fi
BINLOG_FILE=$(echo "$POS" | head -1 | awk '{print $1}')
BINLOG_POS=$(echo "$POS" | head -1 | awk '{print $2}')
[ -n "$BINLOG_FILE" ] && [ -n "$BINLOG_POS" ] || fail "could not read master status: '$POS'"
echo "==> Bounded stop at $BINLOG_FILE:$BINLOG_POS"

# Find the oldest available binlog to start from (binlogs roll; the
# original mysql-bin.000001 may have been purged by container restarts).
FIRST_BINLOG=$("${MYSQL_EXEC[@]}" -N -B -e "SHOW BINARY LOGS" | head -1 | awk '{print $1}')
[ -n "$FIRST_BINLOG" ] || fail "no binlog files found"
echo "==> Starting from $FIRST_BINLOG:4"

# ----------------------------------------------------------------
# 4. Build + run1 (cold stdout, no output_dir = no state files).
#    Tests stdout column-name and ENUM-label rendering only — the
#    state-file path is exercised in run2 + run3 below.
# ----------------------------------------------------------------
CONFIG="$TMPDIR/integration.config.json"
cat >"$CONFIG" <<EOF
{
  "host": "127.0.0.1",
  "port": 23306,
  "user": "myzql_repl_user",
  "password": "ReplPass2025",
  "database": "testdb",
  "ssl": true,
  "from_binlog_file": "$FIRST_BINLOG",
  "from_binlog_position": 4,
  "to_binlog_file": "$BINLOG_FILE",
  "to_binlog_position": $BINLOG_POS,
  "output_mode": "stdout",
  "log_level": "info"
}
EOF

echo "==> Building connector..."
(cd "$REPO_DIR" && zig build) >/dev/null

RUN1="$TMPDIR/run1.log"
echo "==> Running connector run1 (cold stdout, no output_dir)..."
"$REPO_DIR/zig-out/bin/myzql_binlog_connector" "$CONFIG" >"$RUN1" 2>&1 || {
  echo "connector exited non-zero; tail of output:" >&2
  tail -40 "$RUN1" >&2
  exit 1
}

# ----------------------------------------------------------------
# 5. Assertions on run1 (stdout).
# ----------------------------------------------------------------
echo "==> Asserting column names appear by name (not c0/c1)..."
grep -q "label:" "$RUN1" || fail "column 'label' not found in output"
grep -q "kind:" "$RUN1" || fail "column 'kind' not found in output"
grep -q "note:" "$RUN1" || fail "column 'note' not found (did ALTER ADD COLUMN propagate?)"

echo "==> Asserting ENUM labels resolved (not raw integers)..."
grep -qE 'kind:\s*"(alpha|beta|gamma)"' "$RUN1" || {
  echo "  last 20 'kind:' lines:" >&2
  grep 'kind:' "$RUN1" | tail -20 >&2
  fail "ENUM label not rendered"
}

# ----------------------------------------------------------------
# 6. run2 — cold parquet with output_dir set. Writes parquet output
#    AND state/cache so run3 below can resume.
# ----------------------------------------------------------------
OUTPUT_DIR="$TMPDIR/output"
mkdir -p "$OUTPUT_DIR"
PARQUET_CONFIG="$TMPDIR/integration.parquet.config.json"
cat >"$PARQUET_CONFIG" <<EOF
{
  "host": "127.0.0.1",
  "port": 23306,
  "user": "myzql_repl_user",
  "password": "ReplPass2025",
  "database": "testdb",
  "ssl": true,
  "from_binlog_file": "$FIRST_BINLOG",
  "from_binlog_position": 4,
  "to_binlog_file": "$BINLOG_FILE",
  "to_binlog_position": $BINLOG_POS,
  "output_mode": "parquet",
  "output_dir": "$OUTPUT_DIR",
  "parquet_batch_size": 100,
  "log_level": "info"
}
EOF

RUN2="$TMPDIR/run2.log"
echo "==> Running connector run2 (cold parquet with output_dir)..."
"$REPO_DIR/zig-out/bin/myzql_binlog_connector" "$PARQUET_CONFIG" >"$RUN2" 2>&1 || {
  echo "run2 exited non-zero; tail:" >&2
  tail -40 "$RUN2" >&2
  exit 1
}

# ----------------------------------------------------------------
# 6a. Schema cache + state file assertions on run2.
# ----------------------------------------------------------------
echo "==> Asserting schema cache was written..."
# Content-addressable layout: <output_dir>/ddl-cache/<16-hex-hash>.json.gz.
# The latest-pointer file was retired in Step 4 (the binlog checkpoint
# carries the cache key now), and the inner schema-cache/ prefix was
# dropped as a Step 4 follow-up since output_dir/ddl-cache/ already
# carries the namespace.
shopt -s nullglob
caches=("$OUTPUT_DIR"/ddl-cache/*.json.gz)
shopt -u nullglob
[ ${#caches[@]} -gt 0 ] || fail "no ddl-cache/*.json.gz files in $OUTPUT_DIR"
[ ! -f "$OUTPUT_DIR/ddl-cache/.schema_cache_latest" ] || fail ".schema_cache_latest pointer should not exist after Step 4 (latest pointer retired)"

# Verify the cache file really is gzipped (first two bytes = 1f 8b).
hdr=$(xxd -p -l 2 "${caches[0]}")
[ "$hdr" = "1f8b" ] || fail "cache file doesn't start with gzip magic (got $hdr)"

echo "==> Asserting last_checkpoint.json was written..."
CHECKPOINT="$OUTPUT_DIR/state/last_checkpoint.json"
[ -f "$CHECKPOINT" ] || fail "checkpoint not written at $CHECKPOINT"

# Sanity-check the checkpoint contents — final position should match
# our bounded stop, and is_in_progress must be false.
python3 -c "
import json, sys
with open('$CHECKPOINT') as f: s = json.load(f)
assert s['binlog_file'] == '$BINLOG_FILE', f\"checkpoint file: {s['binlog_file']} != $BINLOG_FILE\"
assert int(s['binlog_position']) == $BINLOG_POS, f\"checkpoint pos: {s['binlog_position']} != $BINLOG_POS\"
assert s['is_in_progress'] is False, 'is_in_progress should be false on clean shutdown'
assert s['schema_cache_key'], 'checkpoint should reference a cache key'
assert s['schema_cache_key'].endswith('.json.gz'), f\"unexpected key: {s['schema_cache_key']}\"
assert '/' not in s['schema_cache_key'], f\"key should be flat (no inner prefix): {s['schema_cache_key']}\"
print('  OK: checkpoint =', s['binlog_file'] + ':' + str(s['binlog_position']), 'cache_key =', s['schema_cache_key'])
" || fail "checkpoint contents did not validate"

echo "==> Asserting current.json was deleted on clean shutdown..."
[ ! -f "$OUTPUT_DIR/state/current.json" ] || fail "current.json should not exist after clean shutdown"

# Assert the parquet writer produced non-empty files.
shopt -s nullglob
parquets=("$OUTPUT_DIR/data"/*.parquet)
shopt -u nullglob
[ ${#parquets[@]} -gt 0 ] || fail "no *.parquet files in $OUTPUT_DIR/data"
for pq in "${parquets[@]}"; do
  [ -s "$pq" ] || fail "empty parquet file: $pq"
done
echo "==> Parquet output: ${#parquets[@]} file(s)"

# Step 6a — flush gates: with bounded run-1 spanning multiple binlog
# files, the ROTATE gate alone produces one parquet per non-empty
# binlog. Assert at least 2 files exist so a regression that drops
# back to "single file per run" is caught.
[ ${#parquets[@]} -ge 2 ] || fail "expected >=2 parquet files (Step 6a flush gates), got ${#parquets[@]}"

# Filename contract: {from_file}.{from_pos}_{to_file}.{to_pos}_{uuid7}.parquet
# Lightweight regex check on the first file — guards against accidental
# regression to the pre-Step-6a `{binlog_file}.parquet` shape.
first_pq_basename=$(basename "${parquets[0]}")
echo "$first_pq_basename" | grep -qE '^mysql-bin\.[0-9]+\.[0-9]+_mysql-bin\.[0-9]+\.[0-9]+_[0-9a-f]+(-[0-9a-f]+)+\.parquet$' ||
  fail "filename does not match Step 6a contract: $first_pq_basename"

# No leftover .partial sidecars (orphans from a mid-write crash).
shopt -s nullglob
partials=("$OUTPUT_DIR/data"/.partial-*.parquet*)
shopt -u nullglob
[ ${#partials[@]} -eq 0 ] || fail "leftover .partial sidecars after clean shutdown: ${partials[*]}"

# ----------------------------------------------------------------
# 7. DuckDB-gated canary assertions. Optional: if duckdb isn't on
#    PATH, skip cleanly (the rest of the test still covers the
#    column-awareness + gzip-cache contract).
# ----------------------------------------------------------------
if ! command -v duckdb >/dev/null 2>&1; then
  echo "==> SKIP: duckdb not installed; canary parquet read-back skipped"
  echo "    install via: brew install duckdb"
else
  echo "==> Reading canary rows back through DuckDB..."

  # Single query batch: count canary inserts, then a spot-check
  # of enum / bool / decimal / json / datetime on row id=1 and
  # the null-blob / bitmask-full cases.
  #
  # `-list` + `-noheader` strip DuckDB's default box-drawing
  # formatting — without them every row comes out as `│ OK row1_types │`,
  # breaking the `^OK `/`^FAIL ` greps below.
  DUCK_OUT="$TMPDIR/duck.out"
  duckdb -list -noheader -c "
        -- canary_events must have 5 INSERT events per parquet file.
        -- Using DISTINCT on (id, log_pos) to dedupe across the 4
        -- parquet files, which all contain the same seed INSERTs
        -- (one parquet per binlog file; seed runs in binlog N but
        -- row groups are scanned from binlog N-3..N via the glob).
        SELECT CASE WHEN c = 5 THEN 'OK canary_count=5'
                    ELSE 'FAIL canary_count=' || c END
        FROM (
          SELECT COUNT(DISTINCT json_extract_string(after_values, '\$.id')) AS c
          FROM read_parquet('$OUTPUT_DIR/data/*.parquet')
          WHERE table_name = 'canary_events' AND dml_type = 'INSERT'
        );

        -- Row 1: enum 'pending', bools tinyint(1) and bit(1) both true,
        -- tinyint(10) NOT bool-coerced (stays integer 7), decimal exact,
        -- DATETIME(3) fractional seconds preserved.
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.status')   = 'pending'
             AND json_extract(after_values, '\$.is_active')::TEXT = 'true'
             AND json_extract(after_values, '\$.flag_bit')::TEXT  = 'true'
             AND json_extract(after_values, '\$.counter')::TEXT   = '7'
             AND json_extract_string(after_values, '\$.amount')   = '1234.5678'
             AND json_extract_string(after_values, '\$.note')     = 'first'
             AND json_extract_string(after_values, '\$.created_at') LIKE '2026-04-24 10:00:00.123%'
            THEN 'OK row1_types'
            ELSE 'FAIL row1_types: ' || after_values END
        FROM read_parquet('$OUTPUT_DIR/data/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '1';

        -- Row 2: NULL note, perms full bitmask 'r,w,x', bools both false,
        -- tinyint(10)=99 stays integer (regression guard for prefix-match bug).
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.perms')     = 'r,w,x'
             AND json_extract(after_values, '\$.is_active')::TEXT  = 'false'
             AND json_extract(after_values, '\$.flag_bit')::TEXT   = 'false'
             AND json_extract(after_values, '\$.counter')::TEXT    = '99'
             AND json_extract(after_values, '\$.note')::TEXT       = 'null'
            THEN 'OK row2_types'
            ELSE 'FAIL row2_types: ' || after_values END
        FROM read_parquet('$OUTPUT_DIR/data/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '2';

        -- Row 3: enum 'cancelled', empty set '', NULL blob
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.status')  = 'cancelled'
             AND json_extract_string(after_values, '\$.perms')   = ''
             AND json_extract(after_values, '\$.body')::TEXT     = 'null'
            THEN 'OK row3_types'
            ELSE 'FAIL row3_types: ' || after_values END
        FROM read_parquet('$OUTPUT_DIR/data/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '3';

        -- Row 4: nested JSON structure must round-trip bit-exact
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.payload.nested.a') = '1'
             AND json_extract_string(after_values, '\$.payload.nested.b[0]') = 'true'
            THEN 'OK row4_nested_json'
            ELSE 'FAIL row4_nested_json: ' || after_values END
        FROM read_parquet('$OUTPUT_DIR/data/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '4';
    " >"$DUCK_OUT" 2>&1 || {
    cat "$DUCK_OUT" >&2
    fail "duckdb query failed"
  }

  # Any 'FAIL ' line in duck output is an assertion failure.
  if grep -q '^FAIL ' "$DUCK_OUT"; then
    echo "DuckDB canary output:" >&2
    cat "$DUCK_OUT" >&2
    fail "canary type assertions did not match"
  fi

  # If neither OK nor FAIL appeared, DuckDB probably matched zero rows
  # (silent empty result) — dump the raw output so the user can see what
  # actually came back instead of failing opaquely on the pipefail.
  ok_count=$(grep -c '^OK ' "$DUCK_OUT" || true)
  if [ "$ok_count" -eq 0 ]; then
    echo "DuckDB canary output was empty or unrecognized:" >&2
    cat "$DUCK_OUT" >&2
    echo "  (expected lines starting with 'OK ' or 'FAIL '; got $(wc -l <"$DUCK_OUT") lines total)" >&2
    fail "no canary assertions emitted — check parquet schema / WHERE clauses"
  fi

  echo "==> Canary DuckDB assertions passed ($ok_count checks):"
  grep '^OK ' "$DUCK_OUT" | sed 's/^/    /' || true
fi

# ----------------------------------------------------------------
# 8. run3 — resume from checkpoint. Insert one fresh event, capture
#    the new master position, run the connector again with no
#    `from_binlog_*` set: it should resume from run2's checkpoint,
#    process the single new event, and update the checkpoint.
# ----------------------------------------------------------------
echo "==> Inserting one event past run2's stop position to test resume..."
"${MYSQL_EXEC[@]}" <<'SQL' >/dev/null
INSERT INTO itest_renamed (id, label, note, kind) VALUES (5, 'fifth', 'after run2', 'beta');
SQL

# Capture the new master position so run3 has something to bound against.
if NEW_POS=$("${MYSQL_EXEC[@]}" -N -B -e "SHOW BINARY LOG STATUS" 2>/dev/null); then
  :
else NEW_POS=$("${MYSQL_EXEC[@]}" -N -B -e "SHOW MASTER STATUS"); fi
NEW_BINLOG_FILE=$(echo "$NEW_POS" | head -1 | awk '{print $1}')
NEW_BINLOG_POS=$(echo "$NEW_POS" | head -1 | awk '{print $2}')
[ -n "$NEW_BINLOG_FILE" ] && [ -n "$NEW_BINLOG_POS" ] || fail "could not capture post-run2 master status"

# Sanity: the new position should be strictly past run2's stop.
if [ "$NEW_BINLOG_FILE" = "$BINLOG_FILE" ]; then
  [ "$NEW_BINLOG_POS" -gt "$BINLOG_POS" ] || fail "new pos ($NEW_BINLOG_POS) is not past run2 stop ($BINLOG_POS)"
fi
echo "==> run2 stop: $BINLOG_FILE:$BINLOG_POS  ->  run3 stop: $NEW_BINLOG_FILE:$NEW_BINLOG_POS"

# run3 config: no from_binlog_*; checkpoint must drive the start.
RESUME_CONFIG="$TMPDIR/integration.resume.config.json"
cat >"$RESUME_CONFIG" <<EOF
{
  "host": "127.0.0.1",
  "port": 23306,
  "user": "myzql_repl_user",
  "password": "ReplPass2025",
  "database": "testdb",
  "ssl": true,
  "to_binlog_file": "$NEW_BINLOG_FILE",
  "to_binlog_position": $NEW_BINLOG_POS,
  "output_mode": "stdout",
  "output_dir": "$OUTPUT_DIR",
  "log_level": "info"
}
EOF

RUN3="$TMPDIR/run3.log"
echo "==> Running connector run3 (resume from checkpoint)..."
"$REPO_DIR/zig-out/bin/myzql_binlog_connector" "$RESUME_CONFIG" >"$RUN3" 2>&1 || {
  echo "run3 exited non-zero; tail:" >&2
  tail -40 "$RUN3" >&2
  exit 1
}

echo "==> Asserting resume from checkpoint log line..."
grep -q "found last checkpoint: $BINLOG_FILE:$BINLOG_POS" "$RUN3" || {
  echo "  relevant lines:" >&2
  grep -E "checkpoint|MISSING_START_POSITION|bootstrap" "$RUN3" | tail -10 >&2
  fail "run3 did not resume from checkpoint at $BINLOG_FILE:$BINLOG_POS"
}

echo "==> Asserting warm cache load via checkpoint key..."
grep -q "loaded .* table schemas from cache" "$RUN3" || {
  echo "  relevant lines:" >&2
  grep -E "(schema_cache|loaded|cache)" "$RUN3" | tail -10 >&2
  fail "run3 did not load schemas from cache"
}

echo "==> Asserting new event was processed in stdout..."
grep -qE 'kind:\s*"beta"' "$RUN3" || {
  echo "  last 20 stdout lines:" >&2
  tail -20 "$RUN3" >&2
  fail "run3 did not render the post-run2 event"
}

echo "==> Asserting checkpoint advanced to new position..."
python3 -c "
import json
with open('$CHECKPOINT') as f: s = json.load(f)
assert s['binlog_file'] == '$NEW_BINLOG_FILE', f\"file: {s['binlog_file']} != $NEW_BINLOG_FILE\"
assert int(s['binlog_position']) == $NEW_BINLOG_POS, f\"pos: {s['binlog_position']} != $NEW_BINLOG_POS\"
assert s['is_in_progress'] is False
print('  OK: checkpoint advanced to', s['binlog_file'] + ':' + str(s['binlog_position']))
" || fail "checkpoint did not advance to run3 stop position"

echo ""
echo "==============================================="
echo "  Integration test PASSED"
echo "  run1 (cold stdout) log:        $RUN1"
echo "  run2 (cold parquet) log:       $RUN2"
echo "  run3 (warm resume) log:        $RUN3"
echo "  output_dir (state+cache+data): $OUTPUT_DIR"
echo "==============================================="
