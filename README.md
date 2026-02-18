# MySQL Binlog Connector (Zig)

A high-performance MySQL binary log reader implemented in pure Zig. No C FFI, no libmysqlclient - the entire MySQL wire protocol, binlog event parsing, and Parquet output are native Zig code compiled into a single static binary.

# Overview

This tool reads MySQL/MariaDB binary logs over TCP using the replication protocol, parses row-level change events (INSERT, UPDATE, DELETE), and outputs them either as human-readable text to stdout or as columnar Parquet files for downstream analytics.

It is built for Change Data Capture (CDC) pipelines, real-time replication monitoring, and binlog-to-data-lake ingestion workflows.

### Core Capabilities

- Pure Zig implementation of the MySQL client protocol and COM_BINLOG_DUMP command
- Native Parquet file writer with GZIP compression (no external libraries)
- Two-worker concurrent pipeline for high-throughput Parquet output
- Binlog position control: start and stop at specific file/position pairs
- Table filtering: include/exclude schemas and tables with specificity-based pattern matching
- Complete column type support: JSON (binary format), DECIMAL(65,30), BIT, BLOB, DATETIME with microseconds, and 15+ other types
- Single static binary with no runtime dependencies
- Cross-compilation to aarch64-linux-gnu (AWS Lambda AL2023) from any host

### Supported Event Types

| Event | Operation | Versions |
|-------|-----------|----------|
| `WRITE_ROWS_EVENT` | INSERT | v0, v1, v2 |
| `UPDATE_ROWS_EVENT` | UPDATE (before + after) | v0, v1, v2 |
| `DELETE_ROWS_EVENT` | DELETE | v0, v1, v2 |
| `ROTATE_EVENT` | Binlog file rotation | -- |
| `TABLE_MAP_EVENT` | Table metadata / column types | -- |
| `FORMAT_DESCRIPTION_EVENT` | Binlog format metadata | -- |

## End-to-End Flow

The following diagram shows the complete data path from MySQL to output, including the responsibilities of each stage and the concurrent worker architecture used in Parquet mode.

```
                          MySQL Binlog Connector - End-to-End Flow
 ========================================================================================

  ┌──────────────────────────────────────────────────────────────────────────────────────┐
  │  MySQL Server                                                                        │
  │                                                                                      │
  │  binlog.000001  binlog.000002  binlog.000003  ...                                    │
  │  ROW-based binary log files with checksums (CRC32)                                   │
  └─────────────────────────────┬────────────────────────────────────────────────────────┘
                                │
                                │ TCP (MySQL wire protocol)
                                │ COM_BINLOG_DUMP command
                                │
  ┌─────────────────────────────▼────────────────────────────────────────────────────────┐
  │  Connection Layer                                                    connection.zig  │
  │                                                                                      │
  │  - TCP socket via native Zig MySQL client (src/mysql/)                               │
  │  - Authentication handshake (caching_sha2, native_password, sha256)                  │
  │  - SET @master_binlog_checksum='CRC32'                                               │
  │  - Manual COM_BINLOG_DUMP packet construction                                        │
  └─────────────────────────────┬────────────────────────────────────────────────────────┘
                                │
                                │ Raw event byte buffers
                                │ (skip 0x00 OK prefix byte)
                                │
  ┌─────────────────────────────▼────────────────────────────────────────────────────────┐
  │  Event Parsing Layer                                                                 │
  │                                                                                      │
  │  binlog_reader.zig      Read events, track position, cache TABLE_MAP metadata        │
  │  event_parser.zig       Parse 19-byte headers, row data, column values (1690 lines)  │
  │  json_decoder.zig       Decode MySQL binary JSON format (nested objects/arrays)      │
  │  decimal_parser.zig     High-precision DECIMAL parsing up to DECIMAL(65,30)          │
  └──────────┬──────────────────────────────────────────────┬────────────────────────────┘
             │                                              │
             │ output_mode = "stdout"                       │ output_mode = "parquet"
             │                                              │
  ┌──────────▼───────────────┐           ┌──────────────────▼────────────────────────────┐
  │  Stdout Output           │           │  Concurrent Parquet Pipeline     pipeline.zig │
  │  output.zig              │           │                                               │
  │                          │           │   Main Thread                                 │
  │  Human-readable text     │           │       │                                       │
  │  to stdout:              │           │       │ PipelineMessage (row/rotate/shutdown) │
  │                          │           │       ▼                                       │
  │  - Event type            │           │   ┌──────────────────────────┐                │
  │  - Timestamp             │           │   │  event_queue (MPSC)      │                │
  │  - Server ID             │           │   │  bounded ring buffer     │                │
  │  - Log position          │           │   │  capacity: 32 (default)  │                │
  │  - DML type              │           │   └────────────┬─────────────┘                │
  │  - Row values            │           │                │                              │
  │                          │           │                ▼                              │
  └──────────────────────────┘           │   ┌──────────────────────────┐                │
                                         │   │  Processing Worker       │                │
                                         │   │  (dedicated thread)      │                │
                                         │   │                          │                │
                                         │   │  - Deserialize rows      │                │
                                         │   │  - Serialize to JSON     │                │
                                         │   │  - Batch into columns    │                │
                                         │   │  - 8192 rows/batch       │                │
                                         │   └────────────┬─────────────┘                │
                                         │                │                              │
                                         │                │ FlushMessage (batch/rotate)  │
                                         │                ▼                              │
                                         │   ┌──────────────────────────┐                │
                                         │   │  flush_queue (MPSC)      │                │
                                         │   │  capacity: 4             │                │
                                         │   └────────────┬─────────────┘                │
                                         │                │                              │
                                         │                ▼                              │
                                         │   ┌──────────────────────────┐                │
                                         │   │  Flush Worker            │                │
                                         │   │  (dedicated thread)      │                │
                                         │   │                          │                │
                                         │   │  - Write Parquet pages   │                │
                                         │   │  - GZIP compression      │                │
                                         │   │  - Thrift metadata       │                │
                                         │   │  - File rotation         │                │
                                         │   └────────────┬─────────────┘                │
                                         │                │                              │
                                         └────────────────┼──────────────────────────────┘
                                                          │
                                                          ▼
                                         ┌────────────────────────────────────────────┐
                                         │  Parquet Output Directory                  │
                                         │                                            │
                                         │  parquet_output/                           │
                                         │    binlog.000001.parquet                   │
                                         │    binlog.000002.parquet                   │
                                         │    ...                                     │
                                         │                                            │
                                         │  Schema (9 columns):                       │
                                         │    timestamp       INT64                   │
                                         │    server_id       INT32                   │
                                         │    log_pos         INT64                   │
                                         │    event_row_index INT64                   │
                                         │    database        BYTE_ARRAY (UTF8, opt)  │
                                         │    table_name      BYTE_ARRAY (UTF8, opt)  │
                                         │    dml_type        BYTE_ARRAY (UTF8)       │
                                         │    before_values   BYTE_ARRAY (JSON, opt)  │
                                         │    after_values    BYTE_ARRAY (JSON, opt)  │
                                         └────────────────────────────────────────────┘
```

### Stage Responsibilities

| Stage | Module(s) | Responsibility |
|-------|-----------|----------------|
| Connection | `connection.zig`, `mysql/` | TCP transport, MySQL authentication, COM_BINLOG_DUMP |
| Parsing | `binlog_reader.zig`, `event_parser.zig` | 19-byte event headers, row deserialization, TABLE_MAP cache |
| Type Decoding | `json_decoder.zig`, `decimal_parser.zig` | MySQL binary JSON, high-precision DECIMAL, complex column types |
| Stdout Output | `output.zig` | Human-readable event display |
| Pipeline | `pipeline.zig`, `mpsc_queue.zig` | Two-worker concurrency, bounded queues, batching |
| Parquet Writer | `parquet_writer.zig`, `thrift_compact.zig` | Native Parquet format, Thrift compact protocol, GZIP compression |
| Table Filtering | `table_filter.zig` | Schema/table include-exclude patterns, specificity-based evaluation |
| Configuration | `config.zig` | JSON config parsing, validation, output mode selection |
| Metrics | `metrics.zig` | Pipeline throughput, timing, row/batch counters |

## Prerequisites

- **Zig**: 0.16 ([download](https://ziglang.org/download/))
- **MySQL Server**: 5.7+ or 8.0+ with `ROW`-based binary logging enabled
- **User Permissions**: `REPLICATION SLAVE` and `REPLICATION CLIENT` privileges

No MySQL client library installation is required. The connector implements the MySQL wire protocol natively.

## Building

```bash
# Debug build (native target)
zig build

# Optimized release build
zig build -Doptimize=ReleaseFast

# Cross-compile for ARM64 Linux (AWS Lambda AL2023)
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe

# Cross-compile for x86-64 Linux
zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe

# Run tests
zig build test
```

The output binary is placed at `zig-out/bin/myzql_binlog_connector`.

## Configuration

The connector reads a JSON configuration file passed as the sole CLI argument.

### Stdout Mode

```json
{
  "host": "127.0.0.1",
  "port": 3306,
  "user": "repl_user",
  "password": "password",
  "database": "mydb",
  "from_binlog_file": "binlog.000001",
  "from_binlog_position": 4,
  "to_binlog_file": null,
  "to_binlog_position": null
}
```

### Parquet Mode

```json
{
  "host": "127.0.0.1",
  "port": 3306,
  "user": "repl_user",
  "password": "password",
  "database": "mydb",
  "from_binlog_file": "binlog.000002",
  "from_binlog_position": 4,
  "to_binlog_file": "binlog.000002",
  "to_binlog_position": 39309137,
  "output_mode": "parquet",
  "parquet_output_dir": "./parquet_output",
  "parquet_batch_size": 8192,
  "include": ["prod_db.*", "analytics_db.events"],
  "exclude": ["prod_db.debug_log", "*.tmp_data"],
  "log_level": "info",
  "log_file": "connector.log"
}
```

### Configuration Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `host` | string | yes | -- | MySQL server hostname or IP |
| `port` | integer | yes | -- | MySQL server port |
| `user` | string | no | -- | MySQL username (must have REPLICATION SLAVE) |
| `password` | string | no | -- | MySQL password (use `""` for no password) |
| `database` | string | no | `null` | Initial database for the connection |
| `from_binlog_file` | string | yes | -- | Binlog file to start reading from |
| `from_binlog_position` | integer | yes | -- | Byte offset to start at (4 = file start) |
| `to_binlog_file` | string | no | `null` | Binlog file to stop at (`null` = read indefinitely) |
| `to_binlog_position` | integer | no | `null` | Byte offset to stop at (`null` = end of file) |
| `output_mode` | string | no | `"stdout"` | `"stdout"` or `"parquet"` |
| `parquet_output_dir` | string | no | `"./parquet_output"` | Directory for Parquet files |
| `parquet_batch_size` | integer | no | `8192` | Rows per Parquet batch / row group |
| `include` | string[] | no | `null` | Table filter include patterns (see [Table Filtering](#table-filtering)) |
| `exclude` | string[] | no | `null` | Table filter exclude patterns (see [Table Filtering](#table-filtering)) |
| `log_level` | string | no | `"info"` | Log verbosity: `"debug"`, `"info"`, `"warn"`, `"err"` |
| `log_file` | string | no | `null` | Write logs to file instead of stderr (plain text, no color) |

### Validation Rules

- `host` must not be empty
- `port` must be greater than 0
- `from_binlog_position` must be >= 4 (binlog header size)
- If `to_binlog_file` is specified and matches `from_binlog_file`, then `to_binlog_position` must be greater than `from_binlog_position`
- Filter patterns must contain exactly one `.` and match one of: `schema.table`, `schema.*`, `*.table`
- The same pattern cannot appear in both `include` and `exclude` (startup error)
- `*.*` is not a valid pattern

## Table Filtering

The connector supports optional `include` and `exclude` filters to control which tables are processed. Filtering is applied at the earliest possible point in the pipeline - at `TABLE_MAP_EVENT` processing - so excluded tables skip all downstream work: no row parsing, no JSON serialization, no Parquet output.

### Pattern Format

Every filter entry uses `schema.table` dot notation with optional wildcards:

| Pattern | Meaning | Example |
|---------|---------|---------|
| `schema.table` | Exact match | `"prod_db.users"` |
| `schema.*` | All tables in a schema | `"prod_db.*"` |
| `*.table` | A table name in any schema | `"*.audit_log"` |

Each entry **must** contain exactly one dot. Embedded wildcards (e.g., `prod*.users` or `db.user*`) and `*.*` are not allowed.

### Specificity Rules

When a table matches rules in both `include` and `exclude`, the **more specific rule wins**:

| Priority | Pattern type | Example |
|----------|-------------|---------|
| 1 (highest) | Exact match | `prod_db.users` |
| 2 | Wildcard schema | `*.users` |
| 3 (lowest) | Wildcard table | `prod_db.*` |

If no rule matches at any level, the **default behavior** depends on whether `include` rules exist:

- **Include rules present** (whitelist mode): unmatched tables are **excluded**
- **Only exclude rules** (blacklist mode): unmatched tables are **included**
- **No rules**: all tables are included

### Examples

**Blacklist mode** - exclude specific schemas/tables, include everything else:

```json
{
  "exclude": ["tmp_db.*", "dba.*", "*.noisy_log_table", "prod_db.debug_events"]
}
```

**Whitelist mode** - include only specific schemas/tables:

```json
{
  "include": ["prod_db.*", "analytics_db.events", "analytics_db.clicks"]
}
```

**Mixed mode** - include a schema but exclude specific tables from it:

```json
{
  "include": ["prod_db.*"],
  "exclude": ["prod_db.debug_log", "prod_db.tmp_cache"]
}
```

Result: all `prod_db` tables are included **except** `debug_log` and `tmp_cache`. Tables in other schemas are excluded (whitelist mode).

**Schema exclude with table override** - exclude a schema but keep one table from it:

```json
{
  "exclude": ["staging_db.*"],
  "include": ["staging_db.important_table"]
}
```

Result: `staging_db.important_table` is included (exact match overrides schema wildcard). All other `staging_db` tables are excluded. Tables in other schemas are excluded (whitelist mode, since `include` rules exist).

**Cross-schema table exclude with override** - exclude a table everywhere but keep it in one schema:

```json
{
  "exclude": ["*.audit_log"],
  "include": ["compliance_db.audit_log"]
}
```

Result: `audit_log` is excluded from all schemas except `compliance_db`. Tables in other schemas are excluded (whitelist mode).

### Conflict Detection

The connector rejects configurations where the **exact same pattern** appears in both `include` and `exclude`:

```json
{
  "include": ["prod_db.users"],
  "exclude": ["prod_db.users"]
}
```

This produces a startup error: `ConflictingPattern`. Patterns at **different specificity levels** (e.g., `include: prod_db.users` + `exclude: prod_db.*`) are allowed - the more specific rule wins at runtime.

## Running

```bash
# Stdout mode (default info-level logs on stderr)
./zig-out/bin/myzql_binlog_connector config.json

# Verbose mode (debug-level logs, per-column parsing details)
./zig-out/bin/myzql_binlog_connector config.json -v

# Write logs to file instead of stderr (plain text, no ANSI color)
./zig-out/bin/myzql_binlog_connector config.json --log-file /var/log/connector.log

# Combined: verbose logs to file
./zig-out/bin/myzql_binlog_connector config.json -v --log-file /var/log/connector.log

# Or via the build system
zig build run -- config.json
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `-v` | Enable debug-level logging (overrides config `log_level`) |
| `--log-file <path>` | Write logs to file instead of stderr (overrides config `log_file`) |

CLI flags take precedence over JSON config values. When no `--log-file` is specified, logs are written to stderr with colored output using Zig's built-in terminal formatting.

### Logging

The connector uses Zig's `std.log` with scoped module names. Log levels control verbosity:

| Level | Content |
|-------|---------|
| `err` | Column parsing failures, connection errors |
| `warn` | Data format anomalies (invalid DATETIME, DECIMAL overflow, unknown column types) |
| `info` | Startup, config summary, periodic progress (every 10,000 rows/events), pipeline metrics |
| `debug` | Per-column parsing, TABLE_MAP events, null bitmaps, DATETIME hex details |

At `info` level (the default), progress is reported periodically to avoid flooding:

```
info(main): MySQL Binlog Connector v0.5.0
info(main): loading configuration from: config.parquet.json
info(config): connection: host=127.0.0.1 port=3306 user=root database=mysql
info(config): binlog range: binlog.000002:3758408 -> binlog.000002:39309137
info(config): output mode: parquet
info(config): parquet: dir=./parquet_output batch_size=8192 queue_capacity=32
info(main): connecting to MySQL server at 127.0.0.1:3306
info(main): connected successfully
info(main): starting binlog reader
info(binlog_reader): opening binlog stream: binlog.000002:3758408
info(binlog_reader): binlog stream opened successfully
info(main): pipeline started: batch_size=8192 queue_capacity=32
info(pipeline): opening parquet file: ./parquet_output/binlog.000002.parquet
info(binlog_reader): binlog rotation: next_file=binlog.000002
info(binlog_reader): format description: binlog_version=4
info(main): sent 10000 row events to pipeline
info(pipeline): processing_worker: processed 10000 rows
info(main): sent 20000 row events to pipeline
info(pipeline): processing_worker: processed 20000 rows
...
info(pipeline): flush_worker: flushed 10 batches (81920 rows, 1350485 bytes written)
...
info(metrics): pipeline metrics: rows_processed=410100 batches_flushed=26 bytes_written=3423825
info(metrics): pipeline timing: processing=219.85ms
info(metrics): pipeline timing: flush=653.47ms
info(metrics): pipeline timing: end_to_end=690.12ms
info(metrics): pipeline throughput: 594249 rows/sec
info(main): total events processed: 4806
```

### Parquet Output

In Parquet mode, the connector writes one file per binlog file (e.g., `binlog.000002.parquet`) to the configured output directory. On shutdown, it prints pipeline metrics including total rows processed, batches written, bytes written, and throughput.

## MySQL Setup

### Enable Binary Logging

Add to `my.cnf` or `my.ini`:

```ini
[mysqld]
server-id = 1
log-bin = mysql-bin
binlog-format = ROW
binlog-row-image = FULL
```

Restart MySQL and verify:

```sql
SHOW VARIABLES LIKE 'log_bin';
SHOW VARIABLES LIKE 'binlog_format';
```

### Create Replication User

```sql
CREATE USER 'repl_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'repl_user'@'%';
FLUSH PRIVILEGES;
```

### Find Current Binlog Position

```sql
SHOW MASTER STATUS;
```

## Project Structure

```
myzql-binlog-connector/
├── src/
│   ├── main.zig                  Entry point, CLI argument parsing, mode dispatch
│   ├── config.zig                JSON configuration parsing and validation
│   ├── table_filter.zig          Table/schema inclusion-exclusion filter
│   ├── log_config.zig            Logging subsystem (custom logFn, file output, runtime level)
│   ├── connection.zig            MySQL connection lifecycle
│   ├── binlog_reader.zig         Binlog streaming, position tracking, TABLE_MAP cache
│   ├── event_parser.zig          Row event parsing, column type deserialization
│   ├── json_decoder.zig          MySQL binary JSON format decoder
│   ├── decimal_parser.zig        DECIMAL(M,D) high-precision parser
│   ├── pipeline.zig              Two-worker concurrent pipeline (parquet mode)
│   ├── mpsc_queue.zig            Bounded MPSC ring buffer with mutex/condvar
│   ├── parquet_writer.zig        Native Parquet file writer
│   ├── thrift_compact.zig        Thrift compact protocol encoder (for Parquet metadata)
│   ├── row_json_serializer.zig   Row-to-JSON serializer with scratch buffer
│   ├── output.zig                Human-readable stdout formatter
│   ├── metrics.zig               Pipeline timing and throughput counters
│   ├── array_writer.zig          ArrayList-based writer utility
│   ├── root.zig                  Library root module
│   └── mysql/                    Absorbed MySQL wire protocol (from myzql)
│       ├── conn.zig              Connection handler, auth exchange
│       ├── auth.zig              Authentication (native, sha256, caching_sha2)
│       ├── compat.zig            Zig 0.16 stream/socket compatibility
│       ├── config.zig            Connection config struct
│       ├── constants.zig         Protocol constants and field types
│       ├── result.zig            Query result types
│       ├── result_meta.zig       Result metadata buffer
│       └── protocol/             Packet-level protocol implementation
├── build.zig                     Zig build configuration
├── build.zig.zon                 Package manifest
├── config.example.json           Example configuration (stdout mode)
├── config.parquet.json           Example configuration (parquet mode)
└── README.md
```

## Technical Notes

### Binlog Event Header (19 bytes)

```
Offset  Size  Field
──────  ────  ─────────────
0       4     timestamp      (little-endian u32, Unix epoch)
4       1     event_type     (enum: WRITE_ROWS=30, UPDATE_ROWS=31, DELETE_ROWS=32, ...)
5       4     server_id      (little-endian u32)
9       4     event_size     (little-endian u32, total bytes including header)
13      4     log_pos        (little-endian u32, position of next event)
17      2     flags          (little-endian u16)
```

### OK Packet Prefix

The MySQL replication protocol prepends a `0x00` OK byte to every event buffer. All event parsing skips this first byte before reading the 19-byte header. This is a common source of off-by-one errors in binlog client implementations.

### Parquet File Format

Each output file follows the Apache Parquet specification:

- Magic bytes `PAR1` (header and footer)
- Data pages with GZIP compression per column
- Page headers and file metadata encoded using Thrift compact protocol
- RLE-encoded definition levels for nullable columns
- One row group per batch (configurable, default 8192 rows)

### Concurrency Model

The Parquet pipeline uses two dedicated worker threads connected by bounded MPSC queues:

1. **Processing worker** - deserializes row events, serializes column values to JSON, accumulates rows into columnar batches
2. **Flush worker** - writes Parquet pages to disk, handles GZIP compression, manages file rotation on binlog ROTATE events

Both workers shut down gracefully via poison-pill messages propagated through the queues.

## Cross-Compilation (AWS Lambda)

Zig's built-in cross-compilation support makes it straightforward to produce ARM64 Linux binaries from any development host:

```bash
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe
```

The resulting binary at `zig-out/bin/myzql_binlog_connector` is a fully static executable with no runtime dependencies, suitable for deployment to AWS Lambda AL2023 or any Linux environment.

A Docker-based build environment (`Dockerfile.al2023`, `build-al2023.sh`) is also available for CI/CD integration.

## Troubleshooting

### Connection Failures

```bash
# Verify MySQL is reachable
mysql -u repl_user -p -h 127.0.0.1 -P 3306

# Verify user privileges
SHOW GRANTS FOR 'repl_user'@'%';
```

### Binlog Not Found

```sql
-- List available binlog files
SHOW BINARY LOGS;

-- Verify binlog is enabled
SHOW VARIABLES LIKE 'log_bin%';
```

### Checksum Error 1236

The connector automatically sets `@master_binlog_checksum='CRC32'` before opening the binlog stream. If this error persists, verify the server supports checksums:

```sql
SHOW VARIABLES LIKE 'binlog_checksum';
```

## References

- [MySQL Replication Protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_replication.html)
- [MySQL Binlog Event Format](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_replication_binlog_event.html)
- [Apache Parquet Format Specification](https://parquet.apache.org/documentation/latest/)
- [Zig Language Reference](https://ziglang.org/documentation/master/)
- [Zig 0.16 Release Notes](https://ziglang.org/download/)

## Acknowledgements

The MySQL wire protocol implementation in `src/mysql/` is derived from [myzql](https://github.com/Cloudef/myzql), a pure-Zig MySQL/MariaDB client library by Zack, licensed under the MIT License (Copyright (c) 2023 Zack). The original library has been trimmed to only the code paths used by this project (connection, authentication, packet framing, and query execution) and modified for Zig 0.16 compatibility.
