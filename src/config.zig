//! Configuration Module
//!
//! This module handles loading and parsing configuration from JSON files.
//! It uses Zig's built-in `std.json` for zero-dependency parsing.
//!
//! === JSON CONFIGURATION FORMAT ===
//!
//! {
//!   "host": "127.0.0.1",                          // MySQL server host
//!   "port": 15010,                                 // MySQL server port
//!   "user": "dba",                                 // Optional: MySQL username
//!   "password": "",                                // Optional: MySQL password
//!   "database": "dba",                             // Optional: Initial database
//!   "from_binlog_file": "mysql-bin.000001",        // Optional: start file (genesis)
//!   "from_binlog_position": 4,                     // Optional: start position
//!   "to_binlog_file": null,                        // Optional: Stop at this file
//!   "to_binlog_position": null,                    // Optional: Stop at this position
//!   "output_dir": "./output"                       // Optional: state + cache + parquet root
//! }
//!
//! `output_dir` layout (when set):
//!   {output_dir}/state/        - current.json + last_checkpoint.json
//!   {output_dir}/ddl-cache/    - schema cache (gzipped JSON, content-addressable)
//!   {output_dir}/data/         - parquet output (when output_mode = parquet)
//!
//! `from_binlog_*` is the genesis position used only when no checkpoint
//! exists. Once a `last_checkpoint.json` is written, subsequent runs
//! resume from it and ignore `from_binlog_*`. To force a restart from
//! config, delete `{output_dir}/state/last_checkpoint.json`.
//!
//! === CONFIG PRECEDENCE CHAIN ===
//!
//! The same `Config` struct serves both the local CLI and the future
//! Lambda handler. Fields are filled in this order (first-wins):
//!
//!   1. **Explicit source** - for CLI: `config.json` parsed via
//!      `loadFromFile`. For Lambda: `event.detail` payload parsed via
//!      `loadFromJson`. This is the per-invocation source of truth and
//!      should carry whatever the operator means to override.
//!   2. **Environment variables** - `mergeFromEnv` fills in any field
//!      still at its `?T = null` default from the corresponding env var.
//!      Env vars exist for things that are reasonable to set once per
//!      Lambda function (or shell session) rather than per invocation:
//!      `SSM_PARAMETER_PREFIX`, `S3_URI`, `FLUSH_BYTES_THRESHOLD`.
//!   3. **Compile-time defaults** - the `?T = null` left at this stage
//!      either uses the constant default (for fields with one) or stays
//!      null where "absent" is itself meaningful (e.g. `server_name`
//!      null means "single-tenant CLI dev mode, don't use the
//!      <server_name> path segment").
//!
//! Per-lane (per-invocation) values like `server_name`, `from_binlog_*`,
//! `to_binlog_*`, `include`/`exclude` are payload-only - they don't
//! make sense as Lambda-function-wide env vars, so `mergeFromEnv`
//! ignores them.
//!
//! === MEMORY MANAGEMENT ===
//!
//! The Config struct contains slices that point to memory allocated by the JSON parser.
//! Use an arena allocator for convenience - it will free all memory at once:
//!
//! ```zig
//! var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
//! defer arena.deinit();
//! const config = try Config.loadFromFile(arena.allocator(), "config.json");
//! // No need to manually free - arena.deinit() handles it
//! ```

const std = @import("std");
pub const table_filter = @import("table_filter.zig");

const log = std.log.scoped(.config);

/// Subdirectory layout under `output_dir`. Constants (not configurable)
/// so all three concerns share a single root and stay coupled - losing
/// one without the others would corrupt the resume contract (e.g. cache
/// files orphaned without their checkpoint key).
pub const STATE_SUBDIR = "state";
pub const DDL_CACHE_SUBDIR = "ddl-cache";
pub const DATA_SUBDIR = "data";

/// Default lock-staleness threshold in milliseconds. 90s matches the
/// Lambda-cadence design point: an invocation that hasn't refreshed
/// `current.json` within 90s is presumed crashed. Configurable via
/// `current_state_staleness_ms`.
pub const DEFAULT_CURRENT_STATE_STALENESS_MS: i64 = 90_000;

/// Default flush-size gate.
/// Above this many buffered binlog bytes (summed from event
/// header `event_size`), the parquet writer flushes and starts a new file.
pub const DEFAULT_FLUSH_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100MB

/// Lower bound for `flush_size_bytes` - prevents excessive flush
/// thrashing on misconfigured deployments.
pub const MIN_FLUSH_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10MB

/// Upper bound for `flush_size_bytes` - defence-in-depth against OOM.
/// 1GB is generous enough for any reasonable Lambda memory tier and
/// any local-CLI workflow. Tightening per-run via "25% of process
/// memory budget" is a follow-up once we have a memory-budget config.
pub const MAX_FLUSH_SIZE_BYTES: u64 = 1024 * 1024 * 1024; // 1GB

/// Default time-gate: flush a non-empty buffer after this many ms of
/// inactivity, even if the size gate hasn't triggered. Keeps low-
/// traffic streams from sitting in memory indefinitely.
pub const DEFAULT_FLUSH_TIME_GATE_MS: i64 = 10_000; // 10s

/// Default soft deadline
pub const DEFAULT_SOFT_DEADLINE_MS: i64 = 90_000; // 90s

/// Result of `parseS3Uri`. Slices point into the input string; caller
/// must keep that buffer alive for the lifetime of the parsed value.
/// `prefix` is the empty string when the URI is bucket-only (no path)
/// - meaning "write directly under bucket root, with subdir constants
/// (`state/`, `ddl-cache/`, `data/`) as the only key prefix."
pub const ParsedS3Uri = struct {
    bucket: []const u8,
    prefix: []const u8,
};

pub const S3UriError = error{
    InvalidS3Uri,
    BucketNameInvalid,
};

/// Parse an `s3://bucket[/prefix]` URI. Returns slices into `uri`.
/// Trims a trailing `/` on the prefix so callers don't end up with
/// a `//` join when concatenating with the subdir constants.
///
/// Bucket-name validation is deliberately loose (length 3..63, the
/// only constraint that would cause z3's URL construction to misfire);
/// AWS's full DNS-style rules are enforced server-side and the wrong
/// shape produces a clear S3 error rather than a silent failure.
pub fn parseS3Uri(uri: []const u8) S3UriError!ParsedS3Uri {
    const scheme = "s3://";
    if (!std.mem.startsWith(u8, uri, scheme)) return S3UriError.InvalidS3Uri;
    const rest = uri[scheme.len..];
    if (rest.len == 0) return S3UriError.BucketNameInvalid;

    const slash_at = std.mem.indexOfScalar(u8, rest, '/');
    const bucket = if (slash_at) |i| rest[0..i] else rest;
    const prefix_raw = if (slash_at) |i| rest[i + 1 ..] else "";
    // Trim a trailing slash so `s3://b/p/` and `s3://b/p` parse the same.
    const prefix = std.mem.trimEnd(u8, prefix_raw, "/");

    if (bucket.len < 3 or bucket.len > 63) return S3UriError.BucketNameInvalid;

    return .{ .bucket = bucket, .prefix = prefix };
}

/// Output mode for the connector
pub const OutputMode = enum {
    stdout,
    parquet,
};

/// How to serialize MySQL's boolean-ish column types (tinyint(1) / bit(1))
/// in the before/after JSON that lands in Parquet.
///
/// - auto_bool (default): tinyint(1) and bit(1) → `true` / `false`
/// - auto_int:            tinyint(1) stays integer (unchanged); bit(1) → 1 / 0 integer
/// - raw:                 preserve legacy behavior - bit columns serialize as hex strings ("0x01")
///
/// Only columns whose DESCRIBE-reported type is exactly `tinyint(1)` (optionally
/// followed by ` unsigned`) or `bit(1)` are coerced. Wider tinyint/bit columns
/// are left alone so non-boolean values aren't misrepresented.
pub const BooleanEncoding = enum {
    auto_bool,
    auto_int,
    raw,
};

/// Log level (maps to std.log.Level at runtime)
pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,

    pub fn toStdLevel(self: LogLevel) std.log.Level {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
    }
};

/// Configuration errors
pub const ConfigError = error{
    InvalidHost,
    InvalidPort,
    InvalidBinlogFile,
    InvalidBinlogPosition,
    InvalidFilter,
    FileNotFound,
    ParseError,
};

/// Extract the numeric suffix from a binlog filename
/// Examples:
///   "mysql-bin-changelog.202614" -> 202614
///   "mysql-bin.000123" -> 123
/// Returns null if no number found after last dot
fn extractBinlogFileNumber(filename: []const u8) ?u64 {
    // Find the last dot in the filename
    var last_dot_idx: ?usize = null;
    for (filename, 0..) |char, i| {
        if (char == '.') {
            last_dot_idx = i;
        }
    }

    // If no dot found, return null
    const dot_idx = last_dot_idx orelse return null;

    // Extract the part after the last dot
    if (dot_idx + 1 >= filename.len) return null;
    const number_part = filename[dot_idx + 1 ..];

    // Parse as integer
    return std.fmt.parseInt(u64, number_part, 10) catch null;
}

/// Configuration for MySQL binlog connection and reading
pub const Config = struct {
    // === Connection Settings ===
    /// MySQL host. Defaulted to empty so payload-then-SSM precedence
    /// works for Lambda (handler parses payload, then stamps SSM
    /// creds via `fillDbCredsFromSsm` if `host == ""`). `validate()`
    /// rejects empty values, so CLI users still get the same hard
    /// error if they forget to set host.
    host: []const u8 = "",
    /// MySQL port. Defaulted to 0 (sentinel for "unset") for the same
    /// reason as host. `validate()` rejects port == 0.
    port: u16 = 0,
    user: ?[]const u8 = null,
    password: ?[]const u8 = null,
    database: ?[]const u8 = null,

    // === Binlog Position Settings ===
    /// Genesis start file. Used only when no checkpoint exists at runtime.
    /// Once `{output_dir}/state/last_checkpoint.json` is written, this is
    /// ignored on subsequent runs.
    from_binlog_file: ?[]const u8 = null,
    /// Genesis start position. Same caveat as `from_binlog_file`.
    from_binlog_position: ?u64 = null,
    to_binlog_file: ?[]const u8 = null,
    to_binlog_position: ?u64 = null,
    /// Auto-bound the run when `to_binlog_*` is unset: query master
    /// position at init and use it as the ceiling. Default `true` -
    /// matches the Lambda-shape "catch up to where master was when we
    /// started, then exit cleanly" model. Local-CLI users who want
    /// forever-streaming should set this to `false`. When `to_binlog_*`
    /// is explicitly set in config, this flag has no effect.
    bound_to_master_at_init: bool = true,

    // === Multi-Lane Settings (Lambda payload + CLI optional) ===
    /// Lane key - a stable identifier for the upstream MySQL cluster
    /// being captured. When set, two things change:
    ///   - SSM parameter path becomes `{ssm_parameter_prefix}/{server_name}/db/...`
    ///     (the per-server-name segment that was deferred from
    ///     `feat/ssm-client`). When null, falls back to
    ///     `{ssm_parameter_prefix}/db/...` - the v1 single-tenant shape.
    ///   - State + cache + data S3 key prefixes get a `{server_name}/`
    ///     segment so multiple lanes in the same bucket don't stomp.
    /// Payload-only (per-invocation). Env-var override is intentionally
    /// not supported - env vars are Lambda-function-wide, and a
    /// function-wide server_name would defeat the multi-lane pattern.
    server_name: ?[]const u8 = null,
    /// SSM Parameter Store path prefix for DB credentials.
    /// Effective lookup: `{ssm_parameter_prefix}/[{server_name}/]db/{host,port,user,password}`.
    /// Precedence: payload > `SSM_PARAMETER_PREFIX` env var > null
    /// (no SSM lookup; rely on Config.{user,password,host,port}).
    ssm_parameter_prefix: ?[]const u8 = null,

    // === Output Settings ===
    output_mode: OutputMode = .stdout,
    /// Root directory for state files, schema cache, and (when output_mode
    /// = parquet) parquet output. See `STATE_SUBDIR`/`DDL_CACHE_SUBDIR`/
    /// `DATA_SUBDIR` for the layout.
    /// - Required when `output_mode = parquet`.
    /// - Optional when `output_mode = stdout`. If null, no state files
    ///   and no schema cache are persisted (every run is a cold start).
    output_dir: ?[]const u8 = null,
    /// S3 destination URI of the form `s3://bucket[/prefix]`. When set,
    /// the connector uses the S3 ObjectStore backend instead of the
    /// local filesystem; subdir layout (state/, ddl-cache/, data/) is
    /// applied as key prefixes under the bucket prefix.
    /// - Mutually exclusive with `output_dir` (validation rejects both).
    /// - Required when `output_mode = parquet` if `output_dir` is unset.
    /// - AWS credentials read from `AWS_ACCESS_KEY_ID` /
    ///   `AWS_SECRET_ACCESS_KEY` / optional `AWS_SESSION_TOKEN` /
    ///   optional `AWS_REGION` env vars.
    s3_uri: ?[]const u8 = null,
    parquet_batch_size: u32 = 8192,
    pipeline_queue_capacity: u32 = 32,
    boolean_encoding: BooleanEncoding = .auto_bool,

    // === Table Filter Settings ===
    // Patterns: "schema.table", "schema.*", "*.table"
    include: ?[]const []const u8 = null,
    exclude: ?[]const []const u8 = null,

    // === Schema Cache Settings ===
    /// Staleness threshold for the persisted schema cache, in seconds.
    /// Checked once at bootstrap against the cache file's storage-layer
    /// mtime (local fstat now; S3 HEAD Last-Modified when that backend
    /// lands). Null (the default) disables the check - any non-empty cache
    /// is trusted. A recommended starting value is ~6h; shorter for
    /// DDL-heavy sources, longer for stable schemas.
    schema_cache_ttl_seconds: ?u64 = null,

    // === State File Settings ===
    /// Lock-staleness threshold for `current.json`, in milliseconds.
    /// `current.json` older than this is presumed-crashed and the next
    /// run resumes from `last_checkpoint.json`.
    current_state_staleness_ms: i64 = DEFAULT_CURRENT_STATE_STALENESS_MS,

    // === Parquet Flush Gate Settings ===
    /// Size gate. Buffered binlog bytes (sum of event_size) above this
    /// trigger a flush. Bounds-clamped at config load - out-of-range
    /// values are clamped with a WARN, not a hard fail.
    flush_size_bytes: u64 = DEFAULT_FLUSH_SIZE_BYTES,
    /// Time gate. Flushes a non-empty buffer after this many ms of
    /// inactivity. Doesn't fire on an empty buffer.
    flush_time_gate_ms: i64 = DEFAULT_FLUSH_TIME_GATE_MS,
    /// Soft deadline (wired once Lambda invocation timeouts matter).
    /// Declared now so configs are forward-compatible.
    soft_deadline_ms: i64 = DEFAULT_SOFT_DEADLINE_MS,

    // === SSL/TLS Settings ===
    ssl: bool = true,

    // === Logging Settings ===
    log_level: LogLevel = .info,
    log_file: ?[]const u8 = null,

    /// Load configuration from a JSON file
    /// Memory is allocated using the provided allocator
    /// The caller owns the returned Config and must keep the allocator alive
    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        // Read the config file using posix
        const path_z = allocator.dupeZ(u8, path) catch return ConfigError.ParseError;
        defer allocator.free(path_z);

        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch |err| {
            log.err("failed to open config file '{s}': {}", .{ path, err });
            return ConfigError.FileNotFound;
        };
        defer _ = std.posix.system.close(fd);

        // Get file size
        const file_size: u64 = blk: {
            if (comptime @import("builtin").os.tag == .linux) {
                const linux = std.os.linux;
                var stx = std.mem.zeroes(linux.Statx);
                const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &stx);
                if (linux.errno(rc) != .SUCCESS) return ConfigError.ParseError;
                if (!stx.mask.SIZE) return ConfigError.ParseError;
                break :blk stx.size;
            } else {
                // macOS/BSD: fstat via posix.system (routes to libc)
                var stat: std.posix.system.Stat = undefined;
                if (std.posix.system.fstat(fd, &stat) != 0) return ConfigError.ParseError;
                break :blk @intCast(stat.size);
            }
        };
        if (file_size == 0) {
            log.err("config file '{s}' is empty", .{path});
            return ConfigError.ParseError;
        }

        // Read file contents
        const contents = try allocator.alloc(u8, file_size);
        var total_read: usize = 0;
        while (total_read < file_size) {
            const n = try std.posix.read(fd, contents[total_read..]);
            if (n == 0) break;
            total_read += n;
        }
        defer allocator.free(contents);

        // Parse JSON with detailed error handling
        const parsed = std.json.parseFromSlice(Config, allocator, contents, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        }) catch |err| {
            log.err("failed to parse config file '{s}': {}", .{ path, err });
            log.err("ensure the file is valid JSON format", .{});
            return ConfigError.ParseError;
        };

        // Validate the loaded configuration
        try parsed.value.validate();

        // Bounds-clamping happens after validation so a misconfigured
        // value gets a clear WARN instead of a hard fail. Mutates the
        // value in place; the parser's arena owns the new defaults.
        var clamped = parsed.value;
        clamped.applyClamps();
        return clamped;
    }

    /// Stamp DB credentials from a SSM ParamSet into this Config.
    /// Only fills fields that are still at their unset default -
    /// payload-supplied values win (precedence chain: explicit >
    /// SSM > defaults).
    ///
    /// Looks for these suffixes (matches `Config.ssmDbPath` output):
    ///   - `/db/host`     -> `host`     (parses as string)
    ///   - `/db/port`     -> `port`     (parses as u16)
    ///   - `/db/user`     -> `user`
    ///   - `/db/password` -> `password`
    ///
    /// Values are duplicated using the supplied allocator since the
    /// ParamSet may have a shorter lifetime than this Config (e.g.
    /// the handler deinits the ParamSet right after stamping). Caller
    /// is responsible for `allocator` outliving Config use.
    ///
    /// Returns `error.InvalidPort` if SSM has a port value that
    /// doesn't parse as u16. Other parse failures are reported via
    /// the returned error; partial state may have been stamped (the
    /// next call to `validate()` will catch it).
    ///
    /// Structural typing on `params` (`anytype`) avoids forcing
    /// `config.zig` to import `ssm_client.zig`. Caller passes a
    /// `ssm.ParamSet` (which has `findBySuffix`); tests can pass a
    /// fake.
    pub fn fillDbCredsFromSsm(
        self: *Config,
        allocator: std.mem.Allocator,
        params: anytype,
    ) !void {
        if (self.host.len == 0) {
            if (params.findBySuffix("/db/host")) |p| {
                self.host = try allocator.dupe(u8, p.value);
            }
        }
        if (self.port == 0) {
            if (params.findBySuffix("/db/port")) |p| {
                self.port = std.fmt.parseInt(u16, p.value, 10) catch |err| {
                    log.err("[BAD_SSM_PORT] /db/port='{s}' failed to parse: {}", .{ p.value, err });
                    return ConfigError.InvalidPort;
                };
            }
        }
        if (self.user == null) {
            if (params.findBySuffix("/db/user")) |p| {
                self.user = try allocator.dupe(u8, p.value);
            }
        }
        if (self.password == null) {
            if (params.findBySuffix("/db/password")) |p| {
                self.password = try allocator.dupe(u8, p.value);
            }
        }
    }

    /// Compose the SSM path prefix for DB credentials lookup. Returns
    /// allocator-owned `prefix` + (optional) `server_name` segment +
    /// trailing `/db/`. Caller frees.
    ///
    /// Layout:
    ///   - server_name = null: `{ssm_parameter_prefix}/db/`
    ///     (single-tenant shape - matches the user's deployed dev
    ///     account at `/config/myzql-binlog-connector/dev/db/...`)
    ///   - server_name = set:  `{ssm_parameter_prefix}/{server_name}/db/`
    ///     (multi-lane shape - different SSM creds per upstream cluster
    ///     under one Lambda function)
    ///
    /// Returns `error.MissingSsmPrefix` if `ssm_parameter_prefix` is
    /// null - caller should validate this is set before calling, since
    /// the path layout is meaningless without a prefix.
    ///
    /// Trailing slash is included so callers can append leaf names
    /// (`host`, `port`, `user`, `password`) without managing separators.
    pub fn ssmDbPath(self: Config, allocator: std.mem.Allocator) ![]u8 {
        const prefix = self.ssm_parameter_prefix orelse return error.MissingSsmPrefix;
        const trimmed = std.mem.trimEnd(u8, prefix, "/");
        if (self.server_name) |name| {
            return std.fmt.allocPrint(allocator, "{s}/{s}/db/", .{ trimmed, name });
        }
        return std.fmt.allocPrint(allocator, "{s}/db/", .{trimmed});
    }

    /// Fill in unset fields from environment variables. The precedence
    /// chain is: explicit (payload/file) > env > defaults - so this
    /// only mutates fields whose source value is `null`. Idempotent.
    ///
    /// Recognised env vars (Lambda-function-wide knobs only - per-lane
    /// values like `server_name` stay payload-only):
    ///   - `SSM_PARAMETER_PREFIX` -> `ssm_parameter_prefix`
    ///   - `S3_URI`               -> `s3_uri` (must parse)
    ///   - `OUTPUT_DIR`           -> `output_dir`
    ///   - `FLUSH_BYTES_THRESHOLD` -> `flush_size_bytes`  (binlogdumper-compatible name)
    ///
    /// `FLUSH_BYTES_THRESHOLD` parse failures log a WARN and leave the
    /// existing default in place rather than failing - bad env config
    /// shouldn't take down the connector when a sensible default exists.
    /// Bounds clamping for `flush_size_bytes` happens via
    /// `applyClamps()`; call it after `mergeFromEnv` if you want the
    /// env-supplied value clamped.
    pub fn mergeFromEnv(self: *Config, env_map: *const std.process.Environ.Map) void {
        if (self.ssm_parameter_prefix == null) {
            if (env_map.get("SSM_PARAMETER_PREFIX")) |v| {
                self.ssm_parameter_prefix = v;
            }
        }
        if (self.s3_uri == null) {
            if (env_map.get("S3_URI")) |v| {
                self.s3_uri = v;
            }
        }
        if (self.output_dir == null) {
            if (env_map.get("OUTPUT_DIR")) |v| {
                self.output_dir = v;
            }
        }
        // Numeric: only override if the env var is set AND the field is
        // still at its default. (We can't tell "default" vs "explicit
        // matching default" without sentinel; treat any explicit
        // non-default as wins.)
        if (self.flush_size_bytes == DEFAULT_FLUSH_SIZE_BYTES) {
            if (env_map.get("FLUSH_BYTES_THRESHOLD")) |v| {
                if (std.fmt.parseInt(u64, v, 10)) |parsed| {
                    self.flush_size_bytes = parsed;
                } else |err| {
                    log.warn(
                        "FLUSH_BYTES_THRESHOLD='{s}' failed to parse ({}); keeping default {d}",
                        .{ v, err, DEFAULT_FLUSH_SIZE_BYTES },
                    );
                }
            }
        }
    }

    /// Clamp out-of-range numeric settings to their bounds, logging a
    /// WARN per field. Called from `loadFromFile` post-validation.
    pub fn applyClamps(self: *Config) void {
        if (self.flush_size_bytes < MIN_FLUSH_SIZE_BYTES) {
            log.warn(
                "flush_size_bytes={d} below min ({d}); clamping",
                .{ self.flush_size_bytes, MIN_FLUSH_SIZE_BYTES },
            );
            self.flush_size_bytes = MIN_FLUSH_SIZE_BYTES;
        } else if (self.flush_size_bytes > MAX_FLUSH_SIZE_BYTES) {
            log.warn(
                "flush_size_bytes={d} above max ({d}); clamping",
                .{ self.flush_size_bytes, MAX_FLUSH_SIZE_BYTES },
            );
            self.flush_size_bytes = MAX_FLUSH_SIZE_BYTES;
        }
    }

    /// Validate configuration values
    /// Returns error if any required field is invalid
    pub fn validate(self: Config) !void {
        // Validate connection settings
        if (self.host.len == 0) {
            log.err("validation: host cannot be empty", .{});
            return ConfigError.InvalidHost;
        }
        if (self.port == 0) {
            log.err("validation: port must be greater than 0", .{});
            return ConfigError.InvalidPort;
        }

        // Validate binlog start position - both-or-neither, since either alone
        // is ambiguous (file without position vs position without file).
        if ((self.from_binlog_file == null) != (self.from_binlog_position == null)) {
            log.err("validation: from_binlog_file and from_binlog_position must be set together (or both omitted)", .{});
            return ConfigError.InvalidBinlogFile;
        }
        if (self.from_binlog_file) |f| {
            if (f.len == 0) {
                log.err("validation: from_binlog_file cannot be empty when set", .{});
                return ConfigError.InvalidBinlogFile;
            }
        }
        if (self.from_binlog_position) |p| {
            // MySQL binlog format: first 4 bytes are magic (0xfe 0x62 0x69 0x6e).
            // Position 4 is the first byte of the first real event.
            if (p < 4) {
                log.err("validation: from_binlog_position must be >= 4 (binlog header size)", .{});
                return ConfigError.InvalidBinlogPosition;
            }
        }

        // If end position is specified, validate it makes sense relative to
        // any genesis start. (We can't validate against a runtime-resolved
        // position; the connector does another sanity pass at init.)
        if (self.to_binlog_position) |end_pos| {
            if (self.from_binlog_file) |from_file| {
                const from_pos = self.from_binlog_position.?;
                if (self.to_binlog_file) |to_file| {
                    if (std.mem.eql(u8, to_file, from_file)) {
                        if (end_pos <= from_pos) {
                            log.err("validation: to_binlog_position must be greater than from_binlog_position when using the same file", .{});
                            return ConfigError.InvalidBinlogPosition;
                        }
                    } else {
                        const from_num = extractBinlogFileNumber(from_file) orelse {
                            log.err("validation: cannot extract file number from '{s}'", .{from_file});
                            return ConfigError.InvalidBinlogFile;
                        };
                        const to_num = extractBinlogFileNumber(to_file) orelse {
                            log.err("validation: cannot extract file number from '{s}'", .{to_file});
                            return ConfigError.InvalidBinlogFile;
                        };
                        if (to_num < from_num) {
                            log.err("validation: to_binlog_file number ({d}) must be >= from_binlog_file number ({d})", .{ to_num, from_num });
                            return ConfigError.InvalidBinlogFile;
                        }
                        if (to_num == from_num) {
                            log.err("validation: file numbers are the same ({d}) but filenames differ", .{from_num});
                            return ConfigError.InvalidBinlogFile;
                        }
                    }
                } else {
                    if (end_pos <= from_pos) {
                        log.err("validation: to_binlog_position must be greater than from_binlog_position", .{});
                        return ConfigError.InvalidBinlogPosition;
                    }
                }
            }
        }

        // Output destinations are mutually exclusive.
        if (self.output_dir != null and self.s3_uri != null) {
            log.err(
                "validation: output_dir and s3_uri are mutually exclusive (set exactly one)",
                .{},
            );
            return ConfigError.InvalidFilter;
        }
        // s3_uri must parse cleanly when set.
        if (self.s3_uri) |uri| {
            _ = parseS3Uri(uri) catch |err| {
                log.err("validation: s3_uri='{s}' is invalid: {}", .{ uri, err });
                return ConfigError.InvalidFilter;
            };
        }
        // Parquet mode requires *some* persistent destination; stdout
        // mode tolerates neither being set.
        if (self.output_mode == .parquet and self.output_dir == null and self.s3_uri == null) {
            log.err("validation: output_mode=parquet requires output_dir or s3_uri", .{});
            return ConfigError.InvalidFilter;
        }

        // Validate table filter patterns (if any)
        if (self.include != null or self.exclude != null) {
            var filter = table_filter.TableFilter.init(
                // Use a throwaway allocator - we only care about validation here.
                // The real filter is built in BinlogReader.init().
                std.heap.page_allocator,
                self.include,
                self.exclude,
            ) catch |err| {
                log.err("validation: invalid table filter configuration: {}", .{err});
                return ConfigError.InvalidFilter;
            };
            filter.deinit();
        }
    }

    /// Log the loaded configuration summary
    pub fn logSummary(self: Config) void {
        log.info("connection: host={s} port={d} user={s} database={s}", .{
            self.host,
            self.port,
            if (self.user) |u| u else "(none)",
            if (self.database) |db| db else "(none)",
        });

        const from_label: []const u8 = if (self.from_binlog_file) |f| f else "(unset - resolved at runtime)";
        if (self.from_binlog_file != null) {
            const from_pos = self.from_binlog_position.?;
            if (self.to_binlog_file) |to_file| {
                if (self.to_binlog_position) |to_pos| {
                    log.info("genesis binlog range: {s}:{d} -> {s}:{d}", .{ from_label, from_pos, to_file, to_pos });
                } else {
                    log.info("genesis binlog range: {s}:{d} -> {s}:END", .{ from_label, from_pos, to_file });
                }
            } else {
                log.info("genesis binlog range: {s}:{d} -> (latest)", .{ from_label, from_pos });
            }
        } else {
            log.info("genesis binlog range: {s} (will resume from checkpoint or query master)", .{from_label});
        }

        log.info("output mode: {s}", .{@tagName(self.output_mode)});
        if (self.s3_uri) |uri| {
            log.info("output destination: s3 ({s})", .{uri});
        } else {
            log.info("output destination: posix ({s})", .{self.output_dir orelse "(none - no state, no cache)"});
        }
        if (self.output_mode == .parquet) {
            log.info("parquet: batch_size={d} queue_capacity={d} boolean_encoding={s}", .{
                self.parquet_batch_size,
                self.pipeline_queue_capacity,
                @tagName(self.boolean_encoding),
            });
        }

        if (self.include) |patterns| {
            for (patterns) |p| {
                log.info("filter include: {s}", .{p});
            }
        }
        if (self.exclude) |patterns| {
            for (patterns) |p| {
                log.info("filter exclude: {s}", .{p});
            }
        }
    }
};

test "config parsing with from_binlog_* set" {
    const allocator = std.testing.allocator;

    const json_data =
        \\{
        \\  "host": "127.0.0.1",
        \\  "port": 15010,
        \\  "user": "dba",
        \\  "password": "",
        \\  "database": "dba",
        \\  "from_binlog_file": "mysql-bin-changelog.202341",
        \\  "from_binlog_position": 4
        \\}
    ;

    const parsed = try std.json.parseFromSlice(Config, allocator, json_data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const config = parsed.value;
    try std.testing.expectEqualStrings("127.0.0.1", config.host);
    try std.testing.expectEqual(@as(u16, 15010), config.port);
    try std.testing.expectEqualStrings("mysql-bin-changelog.202341", config.from_binlog_file.?);
    try std.testing.expectEqual(@as(u64, 4), config.from_binlog_position.?);
    try config.validate();
}

test "config parsing without from_binlog_* (resolved at runtime)" {
    const allocator = std.testing.allocator;

    const json_data =
        \\{
        \\  "host": "127.0.0.1",
        \\  "port": 15010
        \\}
    ;

    const parsed = try std.json.parseFromSlice(Config, allocator, json_data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const config = parsed.value;
    try std.testing.expectEqual(@as(?[]const u8, null), config.from_binlog_file);
    try std.testing.expectEqual(@as(?u64, null), config.from_binlog_position);
    try config.validate();
}

// Validation error-path coverage (from_*-both-or-neither, parquet-without-
// output_dir) is exercised by the integration test rather than unit tests
// - those rules `log.err` for operators, and Zig 0.16's test runner flags
// any `err`-level log as a test failure. Lowering the log level would
// change operator-facing UX, so the rejection paths live with the
// integration test instead.

test "parseS3Uri: bucket only" {
    const got = try parseS3Uri("s3://my-bucket");
    try std.testing.expectEqualStrings("my-bucket", got.bucket);
    try std.testing.expectEqualStrings("", got.prefix);
}

test "parseS3Uri: bucket + prefix" {
    const got = try parseS3Uri("s3://my-bucket/connector/dev1");
    try std.testing.expectEqualStrings("my-bucket", got.bucket);
    try std.testing.expectEqualStrings("connector/dev1", got.prefix);
}

test "parseS3Uri: trailing slash on prefix is trimmed" {
    const got = try parseS3Uri("s3://my-bucket/connector/");
    try std.testing.expectEqualStrings("my-bucket", got.bucket);
    try std.testing.expectEqualStrings("connector", got.prefix);
}

test "parseS3Uri: bucket-only with trailing slash" {
    const got = try parseS3Uri("s3://my-bucket/");
    try std.testing.expectEqualStrings("my-bucket", got.bucket);
    try std.testing.expectEqualStrings("", got.prefix);
}

test "parseS3Uri: rejects wrong scheme" {
    try std.testing.expectError(S3UriError.InvalidS3Uri, parseS3Uri("https://my-bucket"));
    try std.testing.expectError(S3UriError.InvalidS3Uri, parseS3Uri("my-bucket"));
    try std.testing.expectError(S3UriError.InvalidS3Uri, parseS3Uri(""));
}

test "parseS3Uri: rejects empty bucket" {
    try std.testing.expectError(S3UriError.BucketNameInvalid, parseS3Uri("s3://"));
    try std.testing.expectError(S3UriError.BucketNameInvalid, parseS3Uri("s3:///prefix"));
}

test "parseS3Uri: rejects too-short bucket name" {
    try std.testing.expectError(S3UriError.BucketNameInvalid, parseS3Uri("s3://ab"));
    try std.testing.expectError(S3UriError.BucketNameInvalid, parseS3Uri("s3://a"));
}

test "parseS3Uri: rejects too-long bucket name" {
    // 64 'a's
    try std.testing.expectError(
        S3UriError.BucketNameInvalid,
        parseS3Uri("s3://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );
}

// ============================================================
// mergeFromEnv tests
// ============================================================

test "mergeFromEnv: fills ssm_parameter_prefix when unset" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("SSM_PARAMETER_PREFIX", "/config/svc/dev");

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqualStrings("/config/svc/dev", cfg.ssm_parameter_prefix.?);
}

test "mergeFromEnv: explicit value wins over env" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("SSM_PARAMETER_PREFIX", "/from/env");

    var cfg: Config = .{
        .host = "h",
        .port = 3306,
        .ssm_parameter_prefix = "/from/payload",
    };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqualStrings("/from/payload", cfg.ssm_parameter_prefix.?);
}

test "mergeFromEnv: missing env var leaves field null" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expect(cfg.ssm_parameter_prefix == null);
    try std.testing.expect(cfg.s3_uri == null);
    try std.testing.expect(cfg.output_dir == null);
}

test "mergeFromEnv: S3_URI fills s3_uri" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("S3_URI", "s3://my-bucket/some/prefix");

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqualStrings("s3://my-bucket/some/prefix", cfg.s3_uri.?);
}

test "mergeFromEnv: OUTPUT_DIR fills output_dir" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("OUTPUT_DIR", "/var/lib/connector");

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqualStrings("/var/lib/connector", cfg.output_dir.?);
}

test "mergeFromEnv: FLUSH_BYTES_THRESHOLD overrides default" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("FLUSH_BYTES_THRESHOLD", "26214400"); // 25 MB (binlogdumper prod default)

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqual(@as(u64, 26_214_400), cfg.flush_size_bytes);
}

test "mergeFromEnv: explicit non-default flush_size_bytes survives env" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("FLUSH_BYTES_THRESHOLD", "26214400");

    var cfg: Config = .{
        .host = "h",
        .port = 3306,
        .flush_size_bytes = 50 * 1024 * 1024, // explicit
    };
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqual(@as(u64, 50 * 1024 * 1024), cfg.flush_size_bytes);
}

test "mergeFromEnv: server_name is NOT taken from env (payload-only)" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("SERVER_NAME", "leaked-from-env");

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    try std.testing.expect(cfg.server_name == null);
}

// ============================================================
// fillDbCredsFromSsm tests - use a fake ParamSet shaped like
// ssm_client.ParamSet (with findBySuffix). Real ParamSet lookup
// happens in lambda_handler.zig.
// ============================================================

const FakeParam = struct {
    name: []const u8,
    value: []const u8,
};

const FakeParamSet = struct {
    parameters: []const FakeParam,

    pub fn findBySuffix(self: FakeParamSet, suffix: []const u8) ?FakeParam {
        for (self.parameters) |p| {
            if (std.mem.endsWith(u8, p.name, suffix)) return p;
        }
        return null;
    }
};

test "fillDbCredsFromSsm: empty Config gets all four creds stamped" {
    const params: FakeParamSet = .{ .parameters = &.{
        .{ .name = "/p/db/host", .value = "db.example.com" },
        .{ .name = "/p/db/port", .value = "3306" },
        .{ .name = "/p/db/user", .value = "repl_user" },
        .{ .name = "/p/db/password", .value = "secret" },
    } };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg: Config = .{};
    try cfg.fillDbCredsFromSsm(arena.allocator(), params);

    try std.testing.expectEqualStrings("db.example.com", cfg.host);
    try std.testing.expectEqual(@as(u16, 3306), cfg.port);
    try std.testing.expectEqualStrings("repl_user", cfg.user.?);
    try std.testing.expectEqualStrings("secret", cfg.password.?);
}

test "fillDbCredsFromSsm: payload-supplied host wins over SSM" {
    const params: FakeParamSet = .{ .parameters = &.{
        .{ .name = "/p/db/host", .value = "from-ssm" },
    } };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg: Config = .{ .host = "from-payload" };
    try cfg.fillDbCredsFromSsm(arena.allocator(), params);

    try std.testing.expectEqualStrings("from-payload", cfg.host);
}

test "fillDbCredsFromSsm: payload-supplied port wins over SSM" {
    const params: FakeParamSet = .{ .parameters = &.{
        .{ .name = "/p/db/port", .value = "3306" },
    } };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg: Config = .{ .port = 15010 };
    try cfg.fillDbCredsFromSsm(arena.allocator(), params);

    try std.testing.expectEqual(@as(u16, 15010), cfg.port);
}

test "fillDbCredsFromSsm: missing SSM params leave fields unset" {
    const params: FakeParamSet = .{
        .parameters = &.{
            .{ .name = "/p/db/host", .value = "h" },
            // user, password, port all absent
        },
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg: Config = .{};
    try cfg.fillDbCredsFromSsm(arena.allocator(), params);

    try std.testing.expectEqualStrings("h", cfg.host);
    try std.testing.expectEqual(@as(u16, 0), cfg.port);
    try std.testing.expect(cfg.user == null);
    try std.testing.expect(cfg.password == null);
}

test "fillDbCredsFromSsm: values are duped (ParamSet can be deinit'd)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var cfg: Config = .{};

    // Borrowed slice that we'll free to prove the dupe.
    const ssm_value = try std.testing.allocator.dupe(u8, "transient.example");
    defer std.testing.allocator.free(ssm_value);
    {
        const params: FakeParamSet = .{ .parameters = &.{
            .{ .name = "/p/db/host", .value = ssm_value },
        } };
        try cfg.fillDbCredsFromSsm(arena.allocator(), params);
    }
    // ssm_value is still alive (deferred free) but cfg.host has its own copy.
    try std.testing.expectEqualStrings("transient.example", cfg.host);
    try std.testing.expect(cfg.host.ptr != ssm_value.ptr);
}

// ============================================================
// ssmDbPath tests
// ============================================================

test "ssmDbPath: single-tenant (no server_name) - matches deployed dev shape" {
    const cfg: Config = .{
        .host = "h",
        .port = 3306,
        .ssm_parameter_prefix = "/config/myzql-binlog-connector/dev",
    };
    const got = try cfg.ssmDbPath(std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("/config/myzql-binlog-connector/dev/db/", got);
}

test "ssmDbPath: multi-lane (server_name set) - adds segment" {
    const cfg: Config = .{
        .host = "h",
        .port = 3306,
        .ssm_parameter_prefix = "/config/myzql-binlog-connector/prod",
        .server_name = "app-server-a",
    };
    const got = try cfg.ssmDbPath(std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(
        "/config/myzql-binlog-connector/prod/app-server-a/db/",
        got,
    );
}

test "ssmDbPath: trailing slash on prefix is normalized" {
    const cfg: Config = .{
        .host = "h",
        .port = 3306,
        .ssm_parameter_prefix = "/config/svc/dev/",
    };
    const got = try cfg.ssmDbPath(std.testing.allocator);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("/config/svc/dev/db/", got);
}

test "ssmDbPath: missing ssm_parameter_prefix is an error" {
    const cfg: Config = .{ .host = "h", .port = 3306 };
    try std.testing.expectError(error.MissingSsmPrefix, cfg.ssmDbPath(std.testing.allocator));
}

test "mergeFromEnv: idempotent - second call is a no-op" {
    var em = std.process.Environ.Map.init(std.testing.allocator);
    defer em.deinit();
    try em.put("SSM_PARAMETER_PREFIX", "/from/env");

    var cfg: Config = .{ .host = "h", .port = 3306 };
    cfg.mergeFromEnv(&em);
    const first = cfg.ssm_parameter_prefix.?;
    cfg.mergeFromEnv(&em);
    try std.testing.expectEqual(first.ptr, cfg.ssm_parameter_prefix.?.ptr);
}
