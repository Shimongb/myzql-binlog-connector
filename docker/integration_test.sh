#!/usr/bin/env bash
# Automated end-to-end column-awareness integration test.
#
# Exercises:
#   * Container bring-up + healthcheck
#   * CREATE / ALTER ADD COLUMN / RENAME TABLE mid-run
#   * Connector bounded by SHOW MASTER STATUS position
#   * Named columns + ENUM label resolution in stdout output
#   * Schema cache persistence (cold write → warm load)
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
# 4. Build + run connector (cold — no prior cache).
# ----------------------------------------------------------------
CACHE_DIR="$TMPDIR/cache"
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
  "schema_cache_dir": "$CACHE_DIR",
  "log_level": "info"
}
EOF

echo "==> Building connector..."
(cd "$REPO_DIR" && zig build) >/dev/null

RUN1="$TMPDIR/run1.log"
echo "==> Running connector (cold)..."
"$REPO_DIR/zig-out/bin/myzql_binlog_connector" "$CONFIG" >"$RUN1" 2>&1 || {
  echo "connector exited non-zero; tail of output:" >&2
  tail -40 "$RUN1" >&2
  exit 1
}

# ----------------------------------------------------------------
# 5. Assertions on cold run.
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

echo "==> Asserting schema cache was written..."
shopt -s nullglob
caches=("$CACHE_DIR"/schema_cache_*.json.gz)
shopt -u nullglob
[ ${#caches[@]} -gt 0 ] || fail "no schema_cache_*.json.gz files in $CACHE_DIR"
[ -f "$CACHE_DIR/.schema_cache_latest" ] || fail ".schema_cache_latest pointer missing"

# Verify the cache file really is gzipped (first two bytes = 1f 8b).
hdr=$(xxd -p -l 2 "${caches[0]}")
[ "$hdr" = "1f8b" ] || fail "cache file doesn't start with gzip magic (got $hdr)"

# ----------------------------------------------------------------
# 6. Warm run in parquet mode — exercises both (a) warm cache load
#    and (b) the parquet-serialization path end-to-end, including
#    the canary table above. The connector writes `.parquet` files
#    per binlog file into `$PARQUET_DIR`; we read them back with
#    DuckDB and assert per-type round-trips.
# ----------------------------------------------------------------
PARQUET_DIR="$TMPDIR/parquet"
mkdir -p "$PARQUET_DIR"
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
  "parquet_output_dir": "$PARQUET_DIR",
  "parquet_batch_size": 100,
  "schema_cache_dir": "$CACHE_DIR",
  "log_level": "info"
}
EOF

RUN2="$TMPDIR/run2.log"
echo "==> Running connector (warm + parquet)..."
"$REPO_DIR/zig-out/bin/myzql_binlog_connector" "$PARQUET_CONFIG" >"$RUN2" 2>&1 || {
  echo "warm connector exited non-zero; tail:" >&2
  tail -40 "$RUN2" >&2
  exit 1
}
grep -q "loaded .* table schemas from cache" "$RUN2" || {
  echo "  relevant lines:" >&2
  grep -E "(schema_cache|loaded)" "$RUN2" | tail -10 >&2
  fail "warm run did not load schemas from cache"
}

# Assert the parquet writer produced a non-empty file.
shopt -s nullglob
parquets=("$PARQUET_DIR"/*.parquet)
shopt -u nullglob
[ ${#parquets[@]} -gt 0 ] || fail "no *.parquet files in $PARQUET_DIR"
for pq in "${parquets[@]}"; do
  [ -s "$pq" ] || fail "empty parquet file: $pq"
done
echo "==> Parquet output: ${#parquets[@]} file(s)"

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
          FROM read_parquet('$PARQUET_DIR/*.parquet')
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
        FROM read_parquet('$PARQUET_DIR/*.parquet')
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
        FROM read_parquet('$PARQUET_DIR/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '2';

        -- Row 3: enum 'cancelled', empty set '', NULL blob
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.status')  = 'cancelled'
             AND json_extract_string(after_values, '\$.perms')   = ''
             AND json_extract(after_values, '\$.body')::TEXT     = 'null'
            THEN 'OK row3_types'
            ELSE 'FAIL row3_types: ' || after_values END
        FROM read_parquet('$PARQUET_DIR/*.parquet')
        WHERE table_name = 'canary_events'
          AND json_extract_string(after_values, '\$.id') = '3';

        -- Row 4: nested JSON structure must round-trip bit-exact
        SELECT CASE
            WHEN json_extract_string(after_values, '\$.payload.nested.a') = '1'
             AND json_extract_string(after_values, '\$.payload.nested.b[0]') = 'true'
            THEN 'OK row4_nested_json'
            ELSE 'FAIL row4_nested_json: ' || after_values END
        FROM read_parquet('$PARQUET_DIR/*.parquet')
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

echo ""
echo "==============================================="
echo "  Integration test PASSED"
echo "  Cold stdout run log: $RUN1"
echo "  Warm parquet run log: $RUN2"
echo "  Cache dir:    $CACHE_DIR"
echo "  Parquet dir:  $PARQUET_DIR"
echo "==============================================="
