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
//!   {output_dir}/state/        — current.json + last_checkpoint.json
//!   {output_dir}/ddl-cache/    — schema cache (gzipped JSON, content-addressable)
//!   {output_dir}/data/         — parquet output (when output_mode = parquet)
//!
//! `from_binlog_*` is the genesis position used only when no checkpoint
//! exists. Once a `last_checkpoint.json` is written, subsequent runs
//! resume from it and ignore `from_binlog_*`. To force a restart from
//! config, delete `{output_dir}/state/last_checkpoint.json`.
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
/// so all three concerns share a single root and stay coupled — losing
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

/// Default flush-size gate. Matches the Rust predecessor's production
/// default. Above this many buffered binlog bytes (summed from event
/// header `event_size`), the parquet writer flushes and starts a new
/// file.
pub const DEFAULT_FLUSH_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100MB

/// Lower bound for `flush_size_bytes` — prevents excessive flush
/// thrashing on misconfigured deployments.
pub const MIN_FLUSH_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10MB

/// Upper bound for `flush_size_bytes` — defence-in-depth against OOM.
/// 1GB is generous enough for any reasonable Lambda memory tier and
/// any local-CLI workflow. Tightening per-run via "25% of process
/// memory budget" is a follow-up once we have a memory-budget config.
pub const MAX_FLUSH_SIZE_BYTES: u64 = 1024 * 1024 * 1024; // 1GB

/// Default time-gate: flush a non-empty buffer after this many ms of
/// inactivity, even if the size gate hasn't triggered. Keeps low-
/// traffic streams from sitting in memory indefinitely.
pub const DEFAULT_FLUSH_TIME_GATE_MS: i64 = 10_000; // 10s

/// Default soft deadline (Step 6b — wired in once Lambda lands).
/// Declared now so configs are forward-compatible.
pub const DEFAULT_SOFT_DEADLINE_MS: i64 = 90_000; // 90s

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
/// - raw:                 preserve legacy behavior — bit columns serialize as hex strings ("0x01")
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
    host: []const u8,
    port: u16,
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
    /// position at init and use it as the ceiling. Default `true` —
    /// matches the Lambda-shape "catch up to where master was when we
    /// started, then exit cleanly" model. Local-CLI users who want
    /// forever-streaming should set this to `false`. When `to_binlog_*`
    /// is explicitly set in config, this flag has no effect.
    bound_to_master_at_init: bool = true,

    // === Output Settings ===
    output_mode: OutputMode = .stdout,
    /// Root directory for state files, schema cache, and (when output_mode
    /// = parquet) parquet output. See `STATE_SUBDIR`/`DDL_CACHE_SUBDIR`/
    /// `DATA_SUBDIR` for the layout.
    /// - Required when `output_mode = parquet`.
    /// - Optional when `output_mode = stdout`. If null, no state files
    ///   and no schema cache are persisted (every run is a cold start).
    output_dir: ?[]const u8 = null,
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
    /// lands). Null (the default) disables the check — any non-empty cache
    /// is trusted. A recommended starting value is ~6h; shorter for
    /// DDL-heavy sources, longer for stable schemas.
    schema_cache_ttl_seconds: ?u64 = null,

    // === State File Settings ===
    /// Lock-staleness threshold for `current.json`, in milliseconds.
    /// `current.json` older than this is presumed-crashed and the next
    /// run resumes from `last_checkpoint.json`. See plans/01 Step 4.
    current_state_staleness_ms: i64 = DEFAULT_CURRENT_STATE_STALENESS_MS,

    // === Parquet Flush Gate Settings (Step 6a) ===
    /// Size gate. Buffered binlog bytes (sum of event_size) above this
    /// trigger a flush. Bounds-clamped at config load — out-of-range
    /// values are clamped with a WARN, not a hard fail.
    flush_size_bytes: u64 = DEFAULT_FLUSH_SIZE_BYTES,
    /// Time gate. Flushes a non-empty buffer after this many ms of
    /// inactivity. Doesn't fire on an empty buffer.
    flush_time_gate_ms: i64 = DEFAULT_FLUSH_TIME_GATE_MS,
    /// Soft deadline (Step 6b — wired once Lambda invocation timeouts
    /// matter). Declared now so configs are forward-compatible.
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

        // Validate binlog start position — both-or-neither, since either alone
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

        // Parquet mode requires output_dir; stdout mode allows it to be null.
        if (self.output_mode == .parquet and self.output_dir == null) {
            log.err("validation: output_mode=parquet requires output_dir", .{});
            return ConfigError.InvalidFilter;
        }

        // Validate table filter patterns (if any)
        if (self.include != null or self.exclude != null) {
            var filter = table_filter.TableFilter.init(
                // Use a throwaway allocator — we only care about validation here.
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

        const from_label: []const u8 = if (self.from_binlog_file) |f| f else "(unset — resolved at runtime)";
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
        log.info("output_dir: {s}", .{self.output_dir orelse "(none — no state, no cache)"});
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
// — those rules `log.err` for operators, and Zig 0.16's test runner flags
// any `err`-level log as a test failure. Lowering the log level would
// change operator-facing UX, so the rejection paths live with the
// integration test instead.
