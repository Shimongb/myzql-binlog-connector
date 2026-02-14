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
//!   "from_binlog_file": "mysql-bin-changelog.202341",
//!   "from_binlog_position": 4,                     // Start position (4 = beginning)
//!   "to_binlog_file": null,                        // Optional: Stop at this file
//!   "to_binlog_position": null                     // Optional: Stop at this position
//! }
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

/// Output mode for the connector
pub const OutputMode = enum {
    stdout,
    parquet,
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
    user: ?[]const u8,
    password: ?[]const u8,
    database: ?[]const u8,

    // === Binlog Position Settings ===
    from_binlog_file: []const u8,
    from_binlog_position: u64,
    to_binlog_file: ?[]const u8,
    to_binlog_position: ?u64,

    // === Output Settings ===
    output_mode: OutputMode = .stdout,
    parquet_output_dir: ?[]const u8 = null,
    parquet_batch_size: u32 = 8192,
    pipeline_queue_capacity: u32 = 32,

    // === Table Filter Settings ===
    // Patterns: "schema.table", "schema.*", "*.table"
    include: ?[]const []const u8 = null,
    exclude: ?[]const []const u8 = null,

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
        defer std.posix.close(fd);

        // Get file size (fstat is void on Linux in Zig 0.16, use statx instead)
        const file_size: u64 = blk: {
            if (comptime @import("builtin").os.tag == .linux) {
                const linux = std.os.linux;
                var stx = std.mem.zeroes(linux.Statx);
                const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &stx);
                if (linux.errno(rc) != .SUCCESS) return ConfigError.ParseError;
                if (!stx.mask.SIZE) return ConfigError.ParseError;
                break :blk stx.size;
            } else {
                const stat = try std.posix.fstat(fd);
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

        return parsed.value;
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

        // Validate binlog settings
        if (self.from_binlog_file.len == 0) {
            log.err("validation: from_binlog_file cannot be empty", .{});
            return ConfigError.InvalidBinlogFile;
        }

        // MySQL binlog format: first 4 bytes are magic number (0xfe 0x62 0x69 0x6e)
        // Position 4 is the start of actual binlog events
        if (self.from_binlog_position < 4) {
            log.err("validation: from_binlog_position must be >= 4 (binlog header size)", .{});
            return ConfigError.InvalidBinlogPosition;
        }

        // If end position is specified, validate it makes sense
        if (self.to_binlog_position) |end_pos| {
            // If we have a to_binlog_file, check if it's different from from_binlog_file
            if (self.to_binlog_file) |to_file| {
                if (std.mem.eql(u8, to_file, self.from_binlog_file)) {
                    // Same file: position must be greater
                    if (end_pos <= self.from_binlog_position) {
                        log.err("validation: to_binlog_position must be greater than from_binlog_position when using the same file", .{});
                        return ConfigError.InvalidBinlogPosition;
                    }
                } else {
                    // Different files: extract file numbers and compare
                    const from_num = extractBinlogFileNumber(self.from_binlog_file) orelse {
                        log.err("validation: cannot extract file number from '{s}'", .{self.from_binlog_file});
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
                // No to_file specified but has position - this means same file
                if (end_pos <= self.from_binlog_position) {
                    log.err("validation: to_binlog_position must be greater than from_binlog_position", .{});
                    return ConfigError.InvalidBinlogPosition;
                }
            }
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

        if (self.to_binlog_file) |to_file| {
            if (self.to_binlog_position) |to_pos| {
                log.info("binlog range: {s}:{d} -> {s}:{d}", .{ self.from_binlog_file, self.from_binlog_position, to_file, to_pos });
            } else {
                log.info("binlog range: {s}:{d} -> {s}:END", .{ self.from_binlog_file, self.from_binlog_position, to_file });
            }
        } else {
            log.info("binlog range: {s}:{d} -> (latest)", .{ self.from_binlog_file, self.from_binlog_position });
        }

        log.info("output mode: {s}", .{@tagName(self.output_mode)});
        if (self.output_mode == .parquet) {
            log.info("parquet: dir={s} batch_size={d} queue_capacity={d}", .{
                self.parquet_output_dir orelse "(default)",
                self.parquet_batch_size,
                self.pipeline_queue_capacity,
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

test "config parsing" {
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
    try std.testing.expectEqual(@as(u64, 4), config.from_binlog_position);
}
