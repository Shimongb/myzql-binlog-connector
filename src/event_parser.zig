//! Binlog Event Parser
//!
//! Production-ready parser for MySQL binlog events with complete column type support.
//!
//! This module provides comprehensive binlog event parsing including:
//! - Event type detection and filtering
//! - TABLE_MAP caching for column metadata
//! - Row event parsing (INSERT, UPDATE, DELETE) with before/after values
//! - Complete column type support: VARCHAR, INT, DECIMAL(65,30), JSON, DATETIME, TIMESTAMP, BIT, BLOB, etc.
//! - Proper fractional seconds handling (microsecond precision)
//! - Binary format decoding for complex types
//!
//! Supported Event Types:
//! - ROTATE_EVENT: Binlog rotation (file change detection)
//! - FORMAT_DESCRIPTION_EVENT: Binlog format version and capabilities
//! - TABLE_MAP_EVENT: Table metadata (column types, names, database)
//! - WRITE_ROWS_EVENT (v0/v1/v2): INSERT operations with after-values
//! - UPDATE_ROWS_EVENT (v0/v1/v2): UPDATE operations with before AND after-values
//! - DELETE_ROWS_EVENT (v0/v1/v2): DELETE operations with before-values
//!
//! Key Bug Fixes:
//! - BIT column parsing: Now correctly reads metadata as byte count (not length prefix)
//!   This fix resolved DECIMAL corruption that occurred when BIT columns appeared before DECIMAL columns
//! - UPDATE events: Both before and after values are now parsed for complete CDC capability
//! - DECIMAL parsing: Full precision up to DECIMAL(65,30) with proper sign handling
//! - JSON decoding: Production-ready decoder with offset tables and nested object support
//!
//! References:
//! - MySQL Protocol: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_replication_binlog_event.html
//! - Column Types: https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__column__definition__flags.html

const std = @import("std");
const decimal_parser = @import("decimal_parser.zig");
const json_decoder = @import("json_decoder.zig");

const log = std.log.scoped(.event_parser);

/// MySQL Binlog Event Types
/// These correspond to enum_event_type in mysql.h
pub const EventType = enum(u8) {
    UNKNOWN_EVENT = 0,
    START_EVENT_V3 = 1,
    QUERY_EVENT = 2,
    STOP_EVENT = 3,
    ROTATE_EVENT = 4,
    INTVAR_EVENT = 5,
    SLAVE_EVENT = 7,
    APPEND_BLOCK_EVENT = 9,
    DELETE_FILE_EVENT = 11,
    RAND_EVENT = 13,
    USER_VAR_EVENT = 14,
    FORMAT_DESCRIPTION_EVENT = 15,
    XID_EVENT = 16,
    BEGIN_LOAD_QUERY_EVENT = 17,
    EXECUTE_LOAD_QUERY_EVENT = 18,
    TABLE_MAP_EVENT = 19,

    // Row events - these are what we care about!
    // V0 events (obsolete, pre-5.1.15)
    WRITE_ROWS_EVENT_V0 = 23,
    UPDATE_ROWS_EVENT_V0 = 24,
    DELETE_ROWS_EVENT_V0 = 25,
    INCIDENT_EVENT = 26,
    HEARTBEAT_EVENT = 27,
    IGNORABLE_EVENT = 28,
    ROWS_QUERY_EVENT = 29,
    // Current row events (5.1.15+)
    // V1 vs V2 format is determined by post_header_len, not event type!
    // post_header_len == 8 -> V1 format (no extra data)
    // post_header_len == 10 -> V2 format (has extra data section)
    WRITE_ROWS_EVENT = 30,
    UPDATE_ROWS_EVENT = 31,
    DELETE_ROWS_EVENT = 32,
    GTID_EVENT = 36,
    ANONYMOUS_GTID_EVENT = 37,
    PREVIOUS_GTIDS_EVENT = 38,
    PARTIAL_UPDATE_ROWS_EVENT = 39,
    _,
};

/// Parsed Event Information
pub const Event = struct {
    event_type: EventType,
    timestamp: u32,
    server_id: u32,
    log_pos: u64,
    flags: u16,

    // Payload will be interpreted based on event_type
    // For now, we store raw data
    data: []const u8,
};

/// Format Description Event Information
/// This is parsed from FORMAT_DESCRIPTION_EVENT (event type 15)
/// and contains critical metadata about how to parse row events.
pub const FormatDescriptionInfo = struct {
    binlog_version: u16,
    server_version: [50]u8,
    create_timestamp: u32,
    common_header_len: u8,
    // post_header_len[event_type - 1] gives the post-header length for that event
    // For row events (30-32), this tells us V1 (8 bytes) vs V2 (10 bytes) format
    post_header_len: [256]u8,
};

/// MySQL Column Types (subset of most common types)
/// Full list: https://dev.mysql.com/doc/dev/mysql-server/latest/field__types_8h.html
pub const ColumnType = enum(u8) {
    MYSQL_TYPE_DECIMAL = 0,
    MYSQL_TYPE_TINY = 1,
    MYSQL_TYPE_SHORT = 2,
    MYSQL_TYPE_LONG = 3,
    MYSQL_TYPE_FLOAT = 4,
    MYSQL_TYPE_DOUBLE = 5,
    MYSQL_TYPE_NULL = 6,
    MYSQL_TYPE_TIMESTAMP = 7,
    MYSQL_TYPE_LONGLONG = 8,
    MYSQL_TYPE_INT24 = 9,
    MYSQL_TYPE_DATE = 10,
    MYSQL_TYPE_TIME = 11,
    MYSQL_TYPE_DATETIME = 12,
    MYSQL_TYPE_YEAR = 13,
    MYSQL_TYPE_NEWDATE = 14,
    MYSQL_TYPE_VARCHAR = 15,
    MYSQL_TYPE_BIT = 16,
    MYSQL_TYPE_TIMESTAMP2 = 17,
    MYSQL_TYPE_DATETIME2 = 18,
    MYSQL_TYPE_TIME2 = 19,
    MYSQL_TYPE_JSON = 245,
    MYSQL_TYPE_NEWDECIMAL = 246,
    MYSQL_TYPE_ENUM = 247,
    MYSQL_TYPE_SET = 248,
    MYSQL_TYPE_TINY_BLOB = 249,
    MYSQL_TYPE_MEDIUM_BLOB = 250,
    MYSQL_TYPE_LONG_BLOB = 251,
    MYSQL_TYPE_BLOB = 252,
    MYSQL_TYPE_VAR_STRING = 253,
    MYSQL_TYPE_STRING = 254,
    MYSQL_TYPE_GEOMETRY = 255,
    _,

    pub fn name(self: ColumnType) []const u8 {
        return switch (self) {
            .MYSQL_TYPE_TINY => "TINYINT",
            .MYSQL_TYPE_SHORT => "SMALLINT",
            .MYSQL_TYPE_LONG => "INT",
            .MYSQL_TYPE_LONGLONG => "BIGINT",
            .MYSQL_TYPE_FLOAT => "FLOAT",
            .MYSQL_TYPE_DOUBLE => "DOUBLE",
            .MYSQL_TYPE_DECIMAL, .MYSQL_TYPE_NEWDECIMAL => "DECIMAL",
            .MYSQL_TYPE_DATE => "DATE",
            .MYSQL_TYPE_TIME, .MYSQL_TYPE_TIME2 => "TIME",
            .MYSQL_TYPE_DATETIME, .MYSQL_TYPE_DATETIME2 => "DATETIME",
            .MYSQL_TYPE_TIMESTAMP, .MYSQL_TYPE_TIMESTAMP2 => "TIMESTAMP",
            .MYSQL_TYPE_YEAR => "YEAR",
            .MYSQL_TYPE_VARCHAR, .MYSQL_TYPE_VAR_STRING => "VARCHAR",
            .MYSQL_TYPE_STRING => "CHAR",
            .MYSQL_TYPE_BLOB => "BLOB",
            .MYSQL_TYPE_TINY_BLOB => "TINYBLOB",
            .MYSQL_TYPE_MEDIUM_BLOB => "MEDIUMBLOB",
            .MYSQL_TYPE_LONG_BLOB => "LONGBLOB",
            .MYSQL_TYPE_JSON => "JSON",
            .MYSQL_TYPE_ENUM => "ENUM",
            .MYSQL_TYPE_SET => "SET",
            .MYSQL_TYPE_BIT => "BIT",
            .MYSQL_TYPE_GEOMETRY => "GEOMETRY",
            else => "UNKNOWN",
        };
    }
};

/// Temporal types (inspired by reference code)
pub const DateTime = struct {
    year: u16 = 0,
    month: u8 = 0,
    day: u8 = 0,
    hour: u8 = 0,
    minute: u8 = 0,
    second: u8 = 0,
    microsecond: u32 = 0,

    pub fn format(self: DateTime, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.year == 0 and self.month == 0 and self.day == 0) {
            try writer.writeAll("0000-00-00");
        } else if (self.hour == 0 and self.minute == 0 and self.second == 0 and self.microsecond == 0) {
            try writer.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ self.year, self.month, self.day });
        } else if (self.microsecond == 0) {
            try writer.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
                self.year, self.month, self.day, self.hour, self.minute, self.second,
            });
        } else {
            try writer.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{
                self.year, self.month, self.day, self.hour, self.minute, self.second, self.microsecond,
            });
        }
    }
};

pub const Duration = struct {
    is_negative: u8 = 0, // 1 if minus, 0 for plus
    days: u32 = 0,
    hours: u8 = 0,
    minutes: u8 = 0,
    seconds: u8 = 0,
    microseconds: u32 = 0,

    pub fn format(self: Duration, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        if (self.is_negative == 1) {
            try writer.writeAll("-");
        }
        if (self.days > 0) {
            try writer.print("{d} days ", .{self.days});
        }
        if (self.microseconds == 0) {
            try writer.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ self.hours, self.minutes, self.seconds });
        } else {
            try writer.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{ self.hours, self.minutes, self.seconds, self.microseconds });
        }
    }
};

/// Table metadata from TABLE_MAP events
pub const TableMetadata = struct {
    table_id: u64,
    database_name: []const u8,
    table_name: []const u8,
    column_count: u64,
    column_types: []u8, // Array of ColumnType values
    column_meta: []u16, // Array of column metadata (precision, length, etc.)

    pub fn deinit(self: *const TableMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.database_name);
        allocator.free(self.table_name);
        allocator.free(self.column_types);
        allocator.free(self.column_meta);
    }
};

/// DML operation type
pub const DmlType = enum {
    Insert, // WRITE_ROWS
    Update, // UPDATE_ROWS
    Delete, // DELETE_ROWS
};

/// Unified row event structure for all DML types
/// - INSERT: before_values = null, after_values = <data>
/// - UPDATE: before_values = <old data>, after_values = <new data>
/// - DELETE: before_values = <data>, after_values = null
pub const RowEvent = struct {
    dml_type: DmlType,
    table_metadata: *const TableMetadata, // Reference to cached metadata
    column_count: u64,
    before_values: ?[]RowValue, // Parsed old values (null for INSERT)
    after_values: ?[]RowValue, // Parsed new values (null for DELETE)

    /// Get human-readable DML type name
    pub fn dmlTypeName(self: RowEvent) []const u8 {
        return switch (self.dml_type) {
            .Insert => "INSERT",
            .Update => "UPDATE",
            .Delete => "DELETE",
        };
    }

    /// Free allocated values
    pub fn deinit(self: *const RowEvent, allocator: std.mem.Allocator) void {
        if (self.before_values) |values| {
            // Free decimal and json strings before freeing the array
            for (values) |value| {
                switch (value) {
                    .decimal => |str| allocator.free(str),
                    .json => |str| allocator.free(str),
                    else => {},
                }
            }
            allocator.free(values);
        }
        if (self.after_values) |values| {
            // Free decimal and json strings before freeing the array
            for (values) |value| {
                switch (value) {
                    .decimal => |str| allocator.free(str),
                    .json => |str| allocator.free(str),
                    else => {},
                }
            }
            allocator.free(values);
        }
    }
};

/// ROTATE event data
pub const RotateEvent = struct {
    next_binlog_file: []const u8,
    next_position: u64,

    /// Check if this is an artificial ROTATE event
    /// Artificial ROTATEs occur at position 0 or 4 (fake/informational)
    pub fn isArtificial(self: RotateEvent) bool {
        return self.next_position == 0 or self.next_position == 4;
    }
};

/// Represents a single MySQL column value
/// Inspired by reference code's conversion patterns
pub const RowValue = union(enum) {
    null_value,
    tiny: i8,
    short: i16,
    long: i32,
    longlong: i64,
    float: f32,
    double: f64,
    year: u16,
    datetime: DateTime,
    timestamp: i64, // Microseconds since epoch
    duration: Duration,
    string: []const u8,
    blob: []const u8,
    decimal: []const u8, // DECIMAL as human-readable string (allocated, must be freed)
    json: []const u8, // JSON as human-readable string (allocated, must be freed)

    pub fn format(self: RowValue, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .null_value => try writer.writeAll("NULL"),
            .tiny => |v| try writer.print("{d}", .{v}),
            .short => |v| try writer.print("{d}", .{v}),
            .long => |v| try writer.print("{d}", .{v}),
            .longlong => |v| try writer.print("{d}", .{v}),
            .float => |v| try writer.print("{d}", .{v}),
            .double => |v| try writer.print("{d}", .{v}),
            .year => |v| try writer.print("{d}", .{v}),
            .datetime => |v| try writer.print("{}", .{v}),
            .timestamp => |v| {
                // Format as microseconds since epoch
                const seconds = @divFloor(v, 1_000_000);
                const micros = @mod(v, 1_000_000);
                if (micros == 0) {
                    try writer.print("{d}", .{seconds});
                } else {
                    try writer.print("{d}.{d:0>6}", .{ seconds, micros });
                }
            },
            .duration => |v| try writer.print("{}", .{v}),
            .string => |v| try writer.print("\"{s}\"", .{v}),
            .blob => |v| {
                // Always show hex for reasonable-sized blobs (up to 256 bytes)
                // This covers hashes, UUIDs, and most structured binary data
                if (v.len <= 256) {
                    try writer.print("0x", .{});
                    for (v) |b| {
                        try writer.print("{x:0>2}", .{b});
                    }
                } else {
                    // For very large blobs, show size + first 32 bytes as hex
                    try writer.print("<blob {d} bytes: 0x", .{v.len});
                    const preview_len = @min(v.len, 32);
                    for (v[0..preview_len]) |b| {
                        try writer.print("{x:0>2}", .{b});
                    }
                    if (v.len > 32) {
                        try writer.print("...", .{});
                    }
                    try writer.print(">", .{});
                }
            },
            .decimal => |v| try writer.print("\"{s}\"", .{v}),
            .json => |v| try writer.print("{s}", .{v}), // JSON already formatted as string
        }
    }
};

/// Simple binary data reader for row parsing
/// Inspired by reference code's PayloadReader
const DataReader = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) DataReader {
        return .{ .data = data, .pos = 0 };
    }

    fn readByte(self: *DataReader) u8 {
        if (self.pos >= self.data.len) return 0; // Bounds check
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    fn readInt(self: *DataReader, comptime T: type) T {
        const size = @sizeOf(T);
        if (self.pos + size > self.data.len) return 0; // Bounds check
        const bytes = self.data[self.pos .. self.pos + size];
        self.pos += size;
        const arr: *const [size]u8 = bytes[0..size];
        return std.mem.readInt(T, arr, .little);
    }

    /// Read 3-byte signed integer (INT24)
    fn readInt24(self: *DataReader) i32 {
        if (self.pos + 3 > self.data.len) return 0;
        const b0: i32 = self.data[self.pos];
        const b1: i32 = self.data[self.pos + 1];
        const b2: i32 = self.data[self.pos + 2];
        self.pos += 3;

        // Combine bytes into 24-bit value
        var val: i32 = b0 | (b1 << 8) | (b2 << 16);

        // Sign extend from 24-bit to 32-bit
        if ((val & 0x800000) != 0) {
            val |= @as(i32, @bitCast(@as(u32, 0xFF000000)));
        }

        return val;
    }

    /// Read a string with metadata-determined length (binlog format)
    /// For VARCHAR/VAR_STRING/STRING: metadata determines if length is 1 or 2 bytes
    fn readString(self: *DataReader, column_meta: u16) []const u8 {
        // If metadata < 256, length is stored in 1 byte; otherwise 2 bytes
        const len: usize = if (column_meta < 256)
            self.readByte()
        else
            self.readInt(u16);

        if (self.pos + len > self.data.len) {
            return &.{}; // Bounds check
        }

        const str = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return str;
    }

    /// Read a blob with metadata-determined length prefix (binlog format)
    /// For BLOB types: metadata indicates number of bytes for length (1, 2, 3, or 4)
    fn readBlob(self: *DataReader, column_meta: u16) []const u8 {
        const len_bytes = column_meta & 0xFF; // Number of bytes for length field

        // Safety check: BLOB length prefix can be at most 4 bytes
        if (len_bytes > 4 or len_bytes == 0) {
            log.warn("invalid BLOB length prefix size: {d}", .{len_bytes});
            return &.{};
        }

        // Read length based on len_bytes (little-endian)
        var len: usize = 0;
        var i: usize = 0;
        while (i < len_bytes) : (i += 1) {
            const byte_val: usize = self.readByte();
            // Cast shift amount to appropriate type to avoid overflow
            // Maximum shift is 3 * 8 = 24, which fits in u6 (max 63)
            const shift_amount: u6 = @intCast(i * 8);
            len |= byte_val << shift_amount;
        }

        if (self.pos + len > self.data.len) {
            return &.{}; // Bounds check
        }

        const blob = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return blob;
    }

    /// Read BIT value from binlog
    ///
    /// BIT Metadata (2 bytes, little-endian):
    ///   byte0 = bit_length % 8  (bits in the last partial byte)
    ///   byte1 = bit_length / 8  (number of full bytes)
    ///
    /// As u16 LE: column_meta = (full_bytes << 8) | bits_in_last_byte
    ///
    /// Total storage bytes = full_bytes + (1 if bits_in_last_byte > 0 else 0)
    ///
    /// Examples:
    /// - BIT(1):  meta=[1,0] → 0x0001 → full=0, partial=1 → 1 byte
    /// - BIT(7):  meta=[7,0] → 0x0007 → full=0, partial=7 → 1 byte
    /// - BIT(8):  meta=[0,1] → 0x0100 → full=1, partial=0 → 1 byte
    /// - BIT(9):  meta=[1,1] → 0x0101 → full=1, partial=1 → 2 bytes
    /// - BIT(16): meta=[0,2] → 0x0200 → full=2, partial=0 → 2 bytes
    fn readBit(self: *DataReader, column_meta: u16) []const u8 {
        const bits_in_last_byte = column_meta & 0xFF;
        const full_bytes = column_meta >> 8;
        const total_bytes: usize = full_bytes + @as(usize, if (bits_in_last_byte > 0) 1 else 0);

        if (total_bytes == 0) {
            return &.{};
        }

        if (self.pos + total_bytes > self.data.len) {
            log.warn("BIT needs {d} bytes but only {d} available", .{ total_bytes, self.data.len - self.pos });
            return &.{};
        }

        const bit_data = self.data[self.pos .. self.pos + total_bytes];
        self.pos += total_bytes;
        return bit_data;
    }

    /// Read DECIMAL/NEWDECIMAL value from binlog
    /// MySQL stores DECIMAL in packed binary format
    /// Metadata format: precision = metadata & 0xFF, decimals = (metadata >> 8)
    ///
    /// Storage format: Groups of up to 9 digits stored as integers
    /// Bytes per digit group: 0→0, 1-2→1, 3-4→2, 5-6→3, 7-9→4
    fn readDecimal(self: *DataReader, column_meta: u16) []const u8 {
        const precision = column_meta & 0xFF; // Total digits
        const decimals = (column_meta >> 8) & 0xFF; // Fractional digits
        const integral = precision - decimals; // Integral digits

        // Helper: Calculate bytes needed for N digits
        const digits_to_bytes = struct {
            fn calc(digits: u8) u8 {
                return switch (digits) {
                    0 => 0,
                    1, 2 => 1,
                    3, 4 => 2,
                    5, 6 => 3,
                    7, 8, 9 => 4,
                    else => 0,
                };
            }
        }.calc;

        // Split into groups of 9 digits
        const integral_full_groups = integral / 9; // Complete 9-digit groups
        const integral_remaining = integral % 9; // Remaining digits
        const decimal_full_groups = decimals / 9; // Complete 9-digit groups
        const decimal_remaining = decimals % 9; // Remaining digits

        // Calculate total bytes needed
        var total_bytes: usize = 0;
        total_bytes += digits_to_bytes(@intCast(integral_remaining)); // Leading integral digits
        total_bytes += integral_full_groups * 4; // 9 digits = 4 bytes each
        total_bytes += decimal_full_groups * 4; // 9 digits = 4 bytes each
        total_bytes += digits_to_bytes(@intCast(decimal_remaining)); // Trailing decimal digits

        // Read the DECIMAL binary data (we'll parse it below using decimal_parser.zig)
        if (self.pos + total_bytes > self.data.len) {
            log.warn("DECIMAL({d},{d}) needs {d} bytes but only {d} available", .{ precision, decimals, total_bytes, self.data.len - self.pos });
            return &.{};
        }

        const decimal_bytes = self.data[self.pos .. self.pos + total_bytes];
        self.pos += total_bytes;
        return decimal_bytes;
    }

    /// Read fixed number of bytes
    fn readBytes(self: *DataReader, count: usize) []const u8 {
        if (self.pos + count > self.data.len) {
            return &.{}; // Bounds check
        }

        const bytes = self.data[self.pos .. self.pos + count];
        self.pos += count;
        return bytes;
    }

    fn remaining(self: *const DataReader) usize {
        return self.data.len - self.pos;
    }
};

/// Parse old DATETIME format from binlog (8 bytes, not length-prefixed)
/// Reference: Rust parse_datetime
fn parseDateTimeOld(reader: *DataReader) DateTime {
    // Read as 8-byte little-endian integer
    var datetime_val = reader.readInt(u64);

    if (datetime_val == 0) {
        return DateTime{}; // Zero datetime
    }

    datetime_val = datetime_val * 1000; // Multiply by 1000
    const date_val = datetime_val / 1000000;
    const time_val = datetime_val % 1000000;

    const year: u16 = @intCast(((date_val / 100) / 100));
    const month: u8 = @intCast(((date_val / 100) % 100));
    const day: u8 = @intCast((date_val % 100));

    const hour: u8 = @intCast(((time_val / 100) / 100));
    const minute: u8 = @intCast(((time_val / 100) % 100));
    const second: u8 = @intCast((time_val % 100));

    return DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .microsecond = 0,
    };
}

/// Parse old TIMESTAMP format from binlog (4 bytes, not length-prefixed)
/// Reference: Rust parse_timestamp
fn parseTimestampOld(reader: *DataReader) i64 {
    // Stored as a 4 byte UNIX timestamp (number of seconds since 00:00, Jan 1 1970 UTC).
    const seconds = reader.readInt(u32);
    return @as(i64, seconds) * 1_000_000; // Convert to microseconds
}

/// Parse old TIME format from binlog (3 bytes, not length-prefixed)
/// Reference: Rust parse_time
fn parseTimeOld(reader: *DataReader) Duration {
    // Read 3-byte little-endian value
    const time_val_low = reader.readByte();
    const time_val_mid = reader.readByte();
    const time_val_high = reader.readByte();
    const time_val: u32 = @as(u32, time_val_low) |
        (@as(u32, time_val_mid) << 8) |
        (@as(u32, time_val_high) << 16);

    const hour: u8 = @intCast((time_val / 100) / 100);
    const minute: u8 = @intCast((time_val / 100) % 100);
    const second: u8 = @intCast(time_val % 100);

    return Duration{
        .is_negative = 0,
        .days = 0,
        .hours = hour,
        .minutes = minute,
        .seconds = second,
        .microseconds = 0,
    };
}

/// Parse DATE from binlog (3 bytes, not length-prefixed)
/// Reference: Rust parse_date
fn parseDate(reader: *DataReader) DateTime {
    // Read 3-byte little-endian value
    const date_low = reader.readByte();
    const date_mid = reader.readByte();
    const date_high = reader.readByte();
    const date_val: u32 = @as(u32, date_low) |
        (@as(u32, date_mid) << 8) |
        (@as(u32, date_high) << 16);

    if (date_val == 0) {
        return DateTime{}; // Zero date
    }

    // Stored as a 3 byte value where bits 1 to 5 store the day,
    // bits 6 to 9 store the month and the remaining bits store the year.
    const day: u8 = @intCast(date_val & 31); // 5 bits
    const month: u8 = @intCast((date_val >> 5) & 15); // 4 bits
    const year: u16 = @intCast(date_val >> 9); // Remaining bits

    return DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = 0,
        .minute = 0,
        .second = 0,
        .microsecond = 0,
    };
}

/// Parse fractional seconds based on column_meta precision
/// column_meta represents precision (0-6), which determines storage size:
/// - precision 0: 0 bytes
/// - precision 1-2: 1 byte
/// - precision 3-4: 2 bytes
/// - precision 5-6: 3 bytes
fn parseFraction(reader: *DataReader, column_meta: u16) u32 {
    const fsp = column_meta & 0xFF; // Fractional seconds precision

    // Clamp fsp to valid range (0-6)
    const clamped_fsp = if (fsp > 6) 0 else fsp;
    const length: usize = (clamped_fsp + 1) / 2;

    if (length == 0 or length > 3) return 0;

    // Read big-endian integer of variable length
    var fraction: u32 = 0;
    var i: usize = 0;
    while (i < length) : (i += 1) {
        fraction = (fraction << 8) | reader.readByte();
    }

    // Convert to microseconds based on length
    // The stored value needs to be scaled up to microseconds
    const scale_factor: u32 = switch (length) {
        1 => 10_000, // 1 byte = 10ms precision -> multiply by 10,000
        2 => 100, // 2 bytes = 100μs precision -> multiply by 100
        3 => 1, // 3 bytes = 1μs precision -> multiply by 1
        else => 1,
    };

    return fraction * scale_factor;
}

/// Parse DATETIME2 from binary binlog format
/// Format: 5 bytes packed + optional fractional seconds
/// Reference: Rust implementation parse_datetime2
fn parseDateTime2(reader: *DataReader, column_meta: u16) DateTime {
    // Check if we have enough bytes
    if (reader.remaining() < 5) {
        log.warn("not enough bytes for DATETIME2 (need 5, have {d})", .{reader.remaining()});
        return DateTime{};
    }

    log.debug("DATETIME2: reading 5 bytes from pos {d}, metadata={d}", .{ reader.pos, column_meta });

    // Read 5-byte packed datetime value (big-endian)
    var packed_val: u64 = 0;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        packed_val = (packed_val << 8) | reader.readByte();
    }

    // Check for null/zero value (0x8000000000 is the "zero" offset for MySQL)
    if (packed_val == 0) {
        log.debug("DATETIME2 is zero value", .{});
        return DateTime{}; // Return zero datetime
    }

    // Subtract offset to handle sign bit - handle underflow
    if (packed_val < 0x8000000000) {
        log.warn("DATETIME2 value {x} is less than offset, possible data misalignment (metadata={d}, remaining bytes before={d})", .{ packed_val, column_meta, reader.remaining() + 5 });
        return DateTime{};
    }
    const val = packed_val - 0x8000000000;

    // Parse fractional seconds
    const micros = parseFraction(reader, column_meta);

    // Extract date and time components using bit manipulation
    const d_val = val >> 17;
    const t_val = val & ((1 << 17) - 1);

    const year_month = d_val >> 5;
    const year_raw = year_month / 13;
    const month_raw = year_month % 13;

    // Safety checks for reasonable values
    if (year_raw > 9999 or month_raw > 12 or month_raw == 0) {
        log.warn("invalid DATETIME2 components: year={d}, month={d}", .{ year_raw, month_raw });
        return DateTime{};
    }

    const year: u16 = @intCast(year_raw);
    const month: u8 = @intCast(month_raw);
    const day: u8 = @intCast(d_val & ((1 << 5) - 1));

    const hour: u8 = @intCast((val >> 12) & ((1 << 5) - 1));
    const minute: u8 = @intCast((t_val >> 6) & ((1 << 6) - 1));
    const second: u8 = @intCast(t_val & ((1 << 6) - 1));

    return DateTime{
        .year = year,
        .month = month,
        .day = day,
        .hour = hour,
        .minute = minute,
        .second = second,
        .microsecond = micros,
    };
}

/// Parse TIMESTAMP2 from binary binlog format
/// Format: 4 bytes (big-endian) seconds since epoch + optional fractional seconds
/// Reference: Rust implementation parse_timestamp2
/// Returns microseconds since epoch
fn parseTimestamp2(reader: *DataReader, column_meta: u16) i64 {
    // Read 4-byte timestamp (big-endian) - seconds since epoch
    var seconds: u32 = 0;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        seconds = (seconds << 8) | reader.readByte();
    }

    // Parse fractional seconds
    const micros = parseFraction(reader, column_meta);

    // Convert to microseconds since epoch
    return @as(i64, seconds) * 1_000_000 + @as(i64, micros);
}

/// Parse TIME2 from binary binlog format
/// Format: 3 bytes packed + optional fractional seconds
fn parseTime2(reader: *DataReader, column_meta: u16) Duration {
    const fraction_bytes: usize = (column_meta + 1) / 2;
    const payload_bytes: usize = 3 + fraction_bytes;

    // Read variable-length big-endian integer
    var time_val: u64 = 0;
    var i: usize = 0;
    while (i < payload_bytes) : (i += 1) {
        time_val = (time_val << 8) | reader.readByte();
    }

    // Check sign bit
    const payload_bits = payload_bytes * 8;
    const negative = (time_val >> @intCast(payload_bits - 1)) == 0;

    if (negative) {
        // Invert bits and add 1 for negative time
        time_val = ~time_val + 1;
    }

    // Extract components using bit slicing
    const hour: u8 = @intCast((time_val >> @intCast(payload_bits - 12)) & 0x3FF); // 10 bits
    const minute: u8 = @intCast((time_val >> @intCast(payload_bits - 18)) & 0x3F); // 6 bits
    const second: u8 = @intCast((time_val >> @intCast(payload_bits - 24)) & 0x3F); // 6 bits

    var microseconds: u32 = 0;
    if (fraction_bytes > 0) {
        const shift_amount: u6 = @intCast(fraction_bytes * 8);
        const fraction = time_val & ((@as(u64, 1) << shift_amount) - 1);
        microseconds = @intCast(fraction * 10_000 / std.math.pow(u64, 100, @as(u32, @intCast(fraction_bytes)) - 1));
    }

    return Duration{
        .is_negative = if (negative) 1 else 0,
        .days = 0,
        .hours = hour,
        .minutes = minute,
        .seconds = second,
        .microseconds = microseconds,
    };
}

/// Parse STRING column metadata to get real column type and length
/// Reference: https://github.com/mysql/mysql-server/blob/5.7/sql/log_event.cc#L2047
/// Returns: (real_column_type, column_length)
fn parseStringColumnMeta(column_meta: u16, column_type: u8) struct { real_type: u8, length: u16 } {
    var real_column_type = column_type;
    var column_length = column_meta;

    if (column_type == @intFromEnum(ColumnType.MYSQL_TYPE_STRING) and column_meta >= 256) {
        const byte0 = column_meta >> 8;
        const byte1 = column_meta & 0xFF;

        if ((byte0 & 0x30) != 0x30) {
            // CHAR or BINARY type
            real_column_type = @intCast(byte0 | 0x30);
            column_length = byte1 | (((byte0 & 0x30) ^ 0x30) << 4);
        } else {
            // ENUM or SET type (values 247 or 248)
            if (byte0 == @intFromEnum(ColumnType.MYSQL_TYPE_ENUM) or
                byte0 == @intFromEnum(ColumnType.MYSQL_TYPE_SET))
            {
                real_column_type = @intCast(byte0);
            }
            column_length = byte1;
        }
    }

    return .{ .real_type = real_column_type, .length = column_length };
}

/// Parse a single column value based on column type (BINLOG FORMAT)
/// Reference: Rust column_value.rs parse() function
/// IMPORTANT: Binlog format is different from MySQL client protocol - no length encoding!
fn parseColumnValue(allocator: std.mem.Allocator, reader: *DataReader, col_type: ColumnType, col_meta: u16) !RowValue {
    const ct: ColumnType = @enumFromInt(@intFromEnum(col_type));

    return switch (ct) {
        // Fixed-size integer types
        .MYSQL_TYPE_TINY => .{ .tiny = @bitCast(reader.readByte()) },
        .MYSQL_TYPE_SHORT => .{ .short = @bitCast(reader.readInt(u16)) },
        .MYSQL_TYPE_INT24 => .{ .long = reader.readInt24() }, // 3 bytes
        .MYSQL_TYPE_LONG => .{ .long = @bitCast(reader.readInt(u32)) },
        .MYSQL_TYPE_LONGLONG => .{ .longlong = @bitCast(reader.readInt(u64)) },

        // Floating point types
        .MYSQL_TYPE_FLOAT => .{ .float = @bitCast(reader.readInt(u32)) },
        .MYSQL_TYPE_DOUBLE => .{ .double = @bitCast(reader.readInt(u64)) },

        // Year type (1 byte, offset by 1900)
        .MYSQL_TYPE_YEAR => .{ .short = @as(i16, reader.readByte()) + 1900 },

        // Date type (3 bytes, no length prefix)
        .MYSQL_TYPE_DATE => .{ .datetime = parseDate(reader) },

        // Old datetime format (8 bytes, no length prefix)
        .MYSQL_TYPE_DATETIME => .{ .datetime = parseDateTimeOld(reader) },

        // New datetime format (5 bytes + fractional)
        .MYSQL_TYPE_DATETIME2 => .{ .datetime = parseDateTime2(reader, col_meta) },

        // Old timestamp format (4 bytes, no length prefix)
        .MYSQL_TYPE_TIMESTAMP => .{ .timestamp = parseTimestampOld(reader) },

        // New timestamp format (4 bytes + fractional)
        .MYSQL_TYPE_TIMESTAMP2 => .{ .timestamp = parseTimestamp2(reader, col_meta) },

        // Old time format (3 bytes, no length prefix)
        .MYSQL_TYPE_TIME => .{ .duration = parseTimeOld(reader) },

        // New time format (3 bytes + fractional)
        .MYSQL_TYPE_TIME2 => .{ .duration = parseTime2(reader, col_meta) },

        // String types - VARCHAR and VAR_STRING use length prefix
        .MYSQL_TYPE_VARCHAR, .MYSQL_TYPE_VAR_STRING => .{
            .string = reader.readString(col_meta),
        },

        // STRING type can be CHAR, BINARY, ENUM, or SET
        // Metadata encoding (MySQL field.cc:6299-6306) - stored BIG-ENDIAN:
        //   metadata[0] = real_type() XOR ((field_length & 0x300) >> 4)
        //   metadata[1] = field_length & 0xFF
        // When read as big-endian u16: (metadata[0] << 8) | metadata[1]
        //
        // Decoding formula (field.cc:6245-6246):
        //   byte0 = (col_meta >> 8) & 0xFF  // high byte = metadata[0]
        //   byte1 = col_meta & 0xFF         // low byte = metadata[1]
        //   field_length = (((real_type() XOR byte0) & 0x30) << 4) | byte1
        //
        // STRING type (CHAR/BINARY/ENUM/SET)
        // Reference: Field_string::unpack() in sql/field.cc:6237-6267
        // ENUM and SET are stored with type STRING in binlog; decode metadata to detect them.
        .MYSQL_TYPE_STRING => blk: {
            // Decode metadata to get the real column type and field_length
            const parsed = parseStringColumnMeta(col_meta, @intFromEnum(ColumnType.MYSQL_TYPE_STRING));
            const real_type: ColumnType = @enumFromInt(parsed.real_type);
            const field_length = parsed.length;

            // Handle ENUM sub-type: stored as 1 or 2 byte index
            if (real_type == .MYSQL_TYPE_ENUM) {
                const val: u16 = if (field_length == 1)
                    reader.readByte()
                else
                    reader.readInt(u16);
                break :blk .{ .short = @intCast(val) };
            }

            // Handle SET sub-type: stored as N bytes (1-8)
            if (real_type == .MYSQL_TYPE_SET) {
                var val: u64 = 0;
                var j: usize = 0;
                while (j < field_length) : (j += 1) {
                    val |= @as(u64, reader.readByte()) << @intCast(j * 8);
                }
                break :blk .{ .longlong = @intCast(val) };
            }

            // Regular CHAR/BINARY: length prefix followed by data
            const actual_length: usize = if (field_length > 255)
                reader.readInt(u16) // 2-byte length prefix (little-endian)
            else
                reader.readByte(); // 1-byte length prefix

            // Read only the actual data bytes (not the full field_length)
            break :blk .{ .string = reader.readBytes(actual_length) };
        },

        // BLOB types - metadata indicates number of length bytes
        .MYSQL_TYPE_BLOB, .MYSQL_TYPE_TINY_BLOB, .MYSQL_TYPE_MEDIUM_BLOB, .MYSQL_TYPE_LONG_BLOB, .MYSQL_TYPE_GEOMETRY => .{
            .blob = reader.readBlob(col_meta),
        },

        // JSON - stored as blob in binlog
        .MYSQL_TYPE_JSON => blk: {
            // Read JSON binary data
            const binary = reader.readBlob(col_meta);

            // Try to decode JSON binary format to human-readable string
            const json_str = json_decoder.decodeJson(allocator, binary) catch |err| {
                log.warn("failed to decode JSON: {}", .{err});
                break :blk .{ .blob = binary }; // Fallback to raw bytes
            };

            break :blk .{ .json = json_str };
        },

        // ENUM and SET - stored as integer based on metadata
        .MYSQL_TYPE_ENUM => blk: {
            const val = if (col_meta == 1)
                reader.readByte()
            else
                reader.readInt(u16);
            break :blk .{ .short = @intCast(val) };
        },

        .MYSQL_TYPE_SET => blk: {
            // Read based on number of bytes in metadata
            const bytes = col_meta & 0xFF;
            var val: u64 = 0;
            var i: usize = 0;
            while (i < bytes) : (i += 1) {
                val |= @as(u64, reader.readByte()) << @intCast(i * 8);
            }
            break :blk .{ .longlong = @intCast(val) };
        },

        // BIT type - stored as bytes
        .MYSQL_TYPE_BIT => .{
            .blob = reader.readBit(col_meta),
        },

        // Decimal types - stored as binary with precision/scale in metadata
        .MYSQL_TYPE_DECIMAL, .MYSQL_TYPE_NEWDECIMAL => blk: {
            // Read DECIMAL binary data
            const binary = reader.readDecimal(col_meta);

            // Extract precision/decimals from metadata
            const precision: u8 = @intCast(col_meta & 0xFF);
            const decimals: u8 = @intCast((col_meta >> 8) & 0xFF);

            log.debug("DECIMAL({d},{d}): read {d} bytes", .{ precision, decimals, binary.len });

            // Convert to human-readable string
            const decimal_str = decimal_parser.decimalToString(
                allocator,
                binary,
                precision,
                decimals,
            ) catch |err| {
                log.warn("failed to parse DECIMAL({d},{d}): {}", .{ precision, decimals, err });
                // Fallback to raw bytes on error
                break :blk .{ .blob = binary };
            };

            break :blk .{ .decimal = decimal_str };
        },

        else => {
            // Unknown type
            log.warn("unknown column type {d}", .{@intFromEnum(col_type)});
            return .{ .blob = &.{} };
        },
    };
}

/// Check if column is NULL in the null bitmap
/// Binlog null bitmap format: (column_count + 7) / 8 bytes
/// Bit position for column i is: (i % 8) in byte (i / 8)
fn isColumnNull(null_bitmap: []const u8, col_idx: usize) bool {
    const byte_idx = col_idx / 8;
    const bit_idx: u3 = @intCast(col_idx % 8);
    if (byte_idx >= null_bitmap.len) return false;
    const byte = null_bitmap[byte_idx];
    return (byte & (@as(u8, 1) << bit_idx)) != 0;
}

/// Parse row values from binary row data (internal version with DataReader)
///
/// This internal function accepts an existing DataReader to track byte consumption.
/// This is CRITICAL for parsing UPDATE events which contain both before-image and
/// after-image data sequentially in the same buffer.
///
/// How UPDATE Event Parsing Works:
/// 1. UPDATE events have two column bitmaps: columns_before and columns_after
/// 2. Binary data layout: [before-image bytes][after-image bytes]
/// 3. Parse before-image first using this function, tracking bytes consumed via reader.pos
/// 4. Use reader.pos to determine where after-image starts in the buffer
/// 5. Parse after-image from remaining data using the same function
///
/// This approach enables full CDC capability for UPDATE operations by providing
/// both the old values (before) and new values (after) for changed rows.
///
/// Parameters:
/// - allocator: Memory allocator for dynamically-sized values (DECIMAL, JSON strings)
/// - reader: DataReader tracking current position in binary data (MODIFIED by this function)
/// - column_types: Array of MySQL column type codes (from TABLE_MAP)
/// - column_meta: Array of column metadata, interpretation depends on type
/// - columns_present: Bitmap indicating which columns are included in this row
///
/// Returns: Array of RowValue structs (one per column, NULL for columns not present)
/// Caller owns the returned memory and must call RowEvent.deinit() to free it.
fn parseRowValuesWithReader(
    allocator: std.mem.Allocator,
    reader: *DataReader,
    column_types: []const u8,
    column_meta: []const u16,
    columns_present: []const bool,
) ![]RowValue {

    // Count present columns for null bitmap size
    var present_count: usize = 0;
    for (columns_present) |present| {
        if (present) present_count += 1;
    }

    // Read null bitmap (sized for PRESENT columns only!)
    const null_bitmap_len = (present_count + 7) / 8;
    if (reader.remaining() < null_bitmap_len) {
        return error.InvalidRowData;
    }

    const null_bitmap = reader.data[reader.pos .. reader.pos + null_bitmap_len];
    reader.pos += null_bitmap_len;

    log.debug("null bitmap for {d} present cols ({d} bytes)", .{ present_count, null_bitmap_len });

    // Parse each column value
    const values = try allocator.alloc(RowValue, column_types.len);
    errdefer allocator.free(values);

    var present_col_idx: usize = 0; // Index in the null bitmap (only counts present columns)
    for (column_types, 0..) |col_type_byte, i| {
        // Skip non-present columns
        if (!columns_present[i]) {
            log.debug("col {d} not present, skipping", .{i});
            values[i] = .null_value;
            continue;
        }

        // Check if this present column is NULL
        const is_null = isColumnNull(null_bitmap, present_col_idx);
        const col_type: ColumnType = @enumFromInt(col_type_byte);
        const col_meta = if (i < column_meta.len) column_meta[i] else 0;

        if (is_null) {
            log.debug("col {d} ({s}, meta={d}): NULL", .{ i, col_type.name(), col_meta });
            values[i] = .null_value;
        } else {
            log.debug("col {d} ({s}, meta={d}): parsing at pos {d}", .{ i, col_type.name(), col_meta, reader.pos });
            values[i] = parseColumnValue(allocator, reader, col_type, col_meta) catch |err| {
                log.err("failed to parse column {d} (type {s}): {}", .{ i, col_type.name(), err });
                values[i] = .null_value;
            };
        }

        present_col_idx += 1; // Increment index for next present column
    }

    return values;
}

/// Parse row values from binary data (public wrapper)
/// Returns array of RowValue (caller owns memory)
/// @param columns_present Bitmap indicating which columns are present in this row
pub fn parseRowValues(
    allocator: std.mem.Allocator,
    data: []const u8,
    column_types: []const u8,
    column_meta: []const u16,
    columns_present: []const bool,
) ![]RowValue {
    if (data.len == 0) {
        return &.{};
    }

    var reader = DataReader.init(data);
    return parseRowValuesWithReader(allocator, &reader, column_types, column_meta, columns_present);
}

/// Check if event type should be processed (includes TABLE_MAP for metadata)
pub fn shouldProcessEvent(event_type: EventType) bool {
    return switch (event_type) {
        .ROTATE_EVENT,
        .FORMAT_DESCRIPTION_EVENT, // Need for post_header_len info
        .TABLE_MAP_EVENT, // Need to process for metadata
        .WRITE_ROWS_EVENT_V0,
        .WRITE_ROWS_EVENT,
        .UPDATE_ROWS_EVENT_V0,
        .UPDATE_ROWS_EVENT,
        .DELETE_ROWS_EVENT_V0,
        .DELETE_ROWS_EVENT,
        .PARTIAL_UPDATE_ROWS_EVENT,
        => true,
        else => false,
    };
}

/// Get human-readable event type name
pub fn eventTypeName(event_type: EventType) []const u8 {
    return switch (event_type) {
        .ROTATE_EVENT => "ROTATE",
        .WRITE_ROWS_EVENT_V0 => "WRITE_ROWS_V0",
        .WRITE_ROWS_EVENT => "WRITE_ROWS",
        .UPDATE_ROWS_EVENT_V0 => "UPDATE_ROWS_V0",
        .UPDATE_ROWS_EVENT => "UPDATE_ROWS",
        .DELETE_ROWS_EVENT_V0 => "DELETE_ROWS_V0",
        .DELETE_ROWS_EVENT => "DELETE_ROWS",
        .PARTIAL_UPDATE_ROWS_EVENT => "PARTIAL_UPDATE_ROWS",
        .QUERY_EVENT => "QUERY",
        .FORMAT_DESCRIPTION_EVENT => "FORMAT_DESCRIPTION",
        .TABLE_MAP_EVENT => "TABLE_MAP",
        else => "UNKNOWN",
    };
}

/// Parse binlog event header (19 bytes)
///
/// MySQL Binlog Event Header Structure (19 bytes):
/// ```
/// +=====================================+
/// | timestamp (4 bytes)      | offset 0 |
/// +-------------------------------------+
/// | event_type (1 byte)      | offset 4 |
/// +-------------------------------------+
/// | server_id (4 bytes)      | offset 5 |
/// +-------------------------------------+
/// | event_size (4 bytes)     | offset 9 |
/// +-------------------------------------+
/// | log_pos (4 bytes)        | offset 13|
/// +-------------------------------------+
/// | flags (2 bytes)          | offset 17|
/// +=====================================+
/// ```
///
/// Pattern: Binary parsing with little-endian byte order
/// MySQL stores integers in little-endian format
pub fn parseEventHeader(buffer: []const u8) !Event {
    // Validate buffer size
    if (buffer.len < 19) {
        return error.BufferTooSmall;
    }

    // Parse header fields using little-endian byte order
    // std.mem.readInt reads integers from byte slices
    const timestamp = std.mem.readInt(u32, buffer[0..4], .little);
    const event_type_raw = buffer[4];
    const server_id = std.mem.readInt(u32, buffer[5..9], .little);
    // event_size at offset 9-13 is total event size (we use buffer.len instead)
    const log_pos = std.mem.readInt(u32, buffer[13..17], .little);
    const flags = std.mem.readInt(u16, buffer[17..19], .little);

    // Convert raw event type to enum
    // @enumFromInt converts integer to enum, using catch for unknown values
    const event_type: EventType = @enumFromInt(event_type_raw);

    // Calculate data section: skip header (19 bytes) and checksum (last 4 bytes if present)
    // MySQL binlogs typically have a 4-byte checksum at the end
    const header_size: usize = 19;
    const checksum_size: usize = 4;
    const data_start = header_size;
    const data_end = if (buffer.len >= header_size + checksum_size)
        buffer.len - checksum_size
    else
        buffer.len;

    const data = if (data_end > data_start) buffer[data_start..data_end] else buffer[0..0];

    return Event{
        .event_type = event_type,
        .timestamp = timestamp,
        .server_id = server_id,
        .log_pos = log_pos,
        .flags = flags,
        .data = data,
    };
}

/// Parse FORMAT_DESCRIPTION_EVENT (event type 15)
/// This event contains critical metadata including post_header_len array
/// which tells us how to parse row events (V1 vs V2 format).
///
/// Structure:
///   [0-1]   binlog_version (u16, little-endian)
///   [2-51]  server_version (50 bytes, null-terminated string)
///   [52-55] create_timestamp (u32, little-endian)
///   [56]    common_header_len (u8, always 19 for MySQL 5.0+)
///   [57+]   post_header_len (array of u8, one per event type)
pub fn parseFormatDescriptionEvent(data: []const u8) !FormatDescriptionInfo {
    if (data.len < 57) {
        return error.InvalidFormatDescriptionEvent;
    }

    var info: FormatDescriptionInfo = undefined;

    // Parse binlog version (2 bytes)
    info.binlog_version = std.mem.readInt(u16, data[0..2], .little);

    // Parse server version (50 bytes, null-terminated)
    @memcpy(&info.server_version, data[2..52]);

    // Parse create timestamp (4 bytes)
    info.create_timestamp = std.mem.readInt(u32, data[52..56], .little);

    // Parse common header length (1 byte)
    info.common_header_len = data[56];

    // Parse post_header_len array
    // The number of event types is determined by remaining data
    const post_header_data = data[57..];
    const num_event_types = @min(post_header_data.len, 256);

    // Initialize all to 0
    @memset(&info.post_header_len, 0);

    // Copy the actual post_header_len values
    @memcpy(info.post_header_len[0..num_event_types], post_header_data[0..num_event_types]);

    return info;
}

/// Parse ROTATE event to get next binlog file information
/// ROTATE event format:
/// - position (8 bytes) - position of first event in next file
/// - binlog filename (variable, null-terminated)
pub fn parseRotateEvent(allocator: std.mem.Allocator, data: []const u8) !RotateEvent {
    if (data.len < 8) {
        return error.InvalidRotateEvent;
    }

    // Parse next position (8 bytes, little-endian)
    const next_position = std.mem.readInt(u64, data[0..8], .little);

    // Rest is filename (not null-terminated in the event, just length-based)
    const filename = data[8..];

    // Allocate and copy filename
    const filename_copy = try allocator.dupe(u8, filename);

    return RotateEvent{
        .next_binlog_file = filename_copy,
        .next_position = next_position,
    };
}

/// Parse TABLE_MAP event to extract table metadata
/// TABLE_MAP format:
/// - table_id (6 bytes)
/// - flags (2 bytes)
/// - schema name length (1 byte)
/// - schema name (variable)
/// - 0x00 (1 byte separator)
/// - table name length (1 byte)
/// - table name (variable)
/// - 0x00 (1 byte separator)
/// - column count (packed integer, 1-9 bytes)
/// - column types (variable)
/// - ... (metadata and null bitmap follow)
pub fn parseTableMapEvent(allocator: std.mem.Allocator, data: []const u8) !TableMetadata {
    if (data.len < 10) { // Minimum: 6 (table_id) + 2 (flags) + 1 (schema len) + 1 (name)
        return error.InvalidTableMapEvent;
    }

    var offset: usize = 0;

    // Parse table ID (6 bytes, little-endian)
    // Note: We read 8 bytes but only use 6
    const table_id_bytes = [_]u8{
        data[offset],     data[offset + 1], data[offset + 2],
        data[offset + 3], data[offset + 4], data[offset + 5],
        0,                0,
    };
    const table_id = std.mem.readInt(u64, &table_id_bytes, .little);
    offset += 6;

    // Skip flags (2 bytes)
    offset += 2;

    // Parse schema name
    const schema_len = data[offset];
    offset += 1;

    if (offset + schema_len >= data.len) {
        return error.InvalidTableMapEvent;
    }

    const schema_name = try allocator.dupe(u8, data[offset .. offset + schema_len]);
    offset += schema_len;

    // Skip null terminator
    offset += 1;

    // Parse table name
    if (offset >= data.len) {
        allocator.free(schema_name);
        return error.InvalidTableMapEvent;
    }

    const table_len = data[offset];
    offset += 1;

    if (offset + table_len >= data.len) {
        allocator.free(schema_name);
        return error.InvalidTableMapEvent;
    }

    const table_name = try allocator.dupe(u8, data[offset .. offset + table_len]);
    offset += table_len;

    // Skip null terminator
    offset += 1;

    // Parse column count (length-encoded integer)
    const column_count = try readLengthEncodedInteger(data, &offset);

    // Parse column types (one byte per column)
    if (offset + column_count > data.len) {
        allocator.free(schema_name);
        allocator.free(table_name);
        return error.InvalidTableMapEvent;
    }

    const column_types = try allocator.alloc(u8, column_count);
    errdefer allocator.free(column_types);

    for (0..column_count) |i| {
        column_types[i] = data[offset + i];
    }
    offset += column_count;

    // Parse column metadata section
    // The metadata section starts with a length-encoded integer indicating its size
    const metadata_length = try readLengthEncodedInteger(data, &offset);
    const metadata_start = offset;

    // Allocate column_meta array
    const column_meta = try allocator.alloc(u16, column_count);
    errdefer allocator.free(column_meta);

    // Parse metadata for each column based on its type
    // Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/classbinary__log_1_1Table__map__event.html
    for (0..column_count) |i| {
        const col_type: ColumnType = @enumFromInt(column_types[i]);
        column_meta[i] = switch (col_type) {
            // STRING/ENUM/SET use BIG-ENDIAN metadata (MySQL quirk)
            .MYSQL_TYPE_STRING, .MYSQL_TYPE_ENUM, .MYSQL_TYPE_SET => blk: {
                if (offset + 2 > data.len) break :blk 0;
                const meta_bytes = [_]u8{ data[offset], data[offset + 1] };
                offset += 2;
                break :blk std.mem.readInt(u16, &meta_bytes, .big);
            },

            // Other types with 2-byte LITTLE-ENDIAN metadata
            .MYSQL_TYPE_VARCHAR, .MYSQL_TYPE_VAR_STRING, .MYSQL_TYPE_DECIMAL, .MYSQL_TYPE_NEWDECIMAL, .MYSQL_TYPE_BIT => blk: {
                if (offset + 2 > data.len) break :blk 0;
                const meta_bytes = [_]u8{ data[offset], data[offset + 1] };
                offset += 2;
                break :blk std.mem.readInt(u16, &meta_bytes, .little);
            },

            // Types with 1-byte metadata
            .MYSQL_TYPE_BLOB, .MYSQL_TYPE_TINY_BLOB, .MYSQL_TYPE_MEDIUM_BLOB, .MYSQL_TYPE_LONG_BLOB, .MYSQL_TYPE_FLOAT, .MYSQL_TYPE_DOUBLE, .MYSQL_TYPE_GEOMETRY, .MYSQL_TYPE_JSON, .MYSQL_TYPE_DATETIME2, .MYSQL_TYPE_TIMESTAMP2, .MYSQL_TYPE_TIME2 => blk: {
                if (offset >= data.len) break :blk 0;
                const meta = data[offset];
                offset += 1;
                break :blk meta;
            },

            // Types with no metadata
            else => 0,
        };
    }

    // Verify we consumed the expected amount of metadata
    if (offset != metadata_start + metadata_length) {
        log.warn("metadata parsing mismatch: expected {d} bytes, consumed {d} bytes", .{ metadata_length, offset - metadata_start });
    }

    return TableMetadata{
        .table_id = table_id,
        .database_name = schema_name,
        .table_name = table_name,
        .column_count = column_count,
        .column_types = column_types,
        .column_meta = column_meta,
    };
}

/// Parse ROW event (WRITE/UPDATE/DELETE) to extract ALL rows from the event.
/// A single binlog row event can contain multiple rows. This function returns
/// a slice of RowEvent, one per row in the event.
///
/// Row event format:
/// - table_id (6 bytes)
/// - flags (2 bytes)
/// - [V2] extra_data_len (2 bytes) + extra_data
/// - [V2] column_count (length-encoded integer)
/// - columns_present bitmap
/// - [UPDATE only] columns_present_update bitmap
/// - FOR EACH ROW:
///   - NULL bitmap for present columns
///   - Row data (variable, column by column)
///   - [UPDATE only] NULL bitmap for after-image
///   - [UPDATE only] Row data for after-image
pub fn parseRowEvent(
    allocator: std.mem.Allocator,
    event_type: EventType,
    data: []const u8,
    table_metadata: *const TableMetadata,
    format_description: ?FormatDescriptionInfo,
) ![]RowEvent {
    if (data.len < 8) { // Minimum: 6 (table_id) + 2 (flags)
        return error.InvalidRowEvent;
    }

    var offset: usize = 0;

    // Parse table ID (6 bytes) - already validated by TABLE_MAP
    offset += 6;

    // Skip flags (2 bytes)
    offset += 2;

    // Determine V1 vs V2 format using post_header_len from FORMAT_DESCRIPTION_EVENT
    const is_v2 = if (format_description) |fmt_desc| blk: {
        const event_type_code = @intFromEnum(event_type);
        if (event_type_code > 0 and event_type_code <= fmt_desc.post_header_len.len) {
            const post_header_len = fmt_desc.post_header_len[event_type_code - 1];
            break :blk (post_header_len == 10); // ROWS_HEADER_LEN_V2
        }
        break :blk false;
    } else false;

    if (is_v2) {
        if (offset + 2 > data.len) {
            return error.InvalidRowEvent;
        }
        const var_header_len_bytes = [_]u8{ data[offset], data[offset + 1] };
        const var_header_len = std.mem.readInt(u16, &var_header_len_bytes, .little);

        if (var_header_len >= 2) {
            const actual_extra = var_header_len - 2;
            if (offset + 2 + actual_extra > data.len) {
                return error.InvalidRowEvent;
            }
            offset += 2 + actual_extra;
        } else {
            offset += 2;
        }
    }

    const column_count = table_metadata.column_count;

    if (is_v2) {
        _ = readLengthEncodedInteger(data, &offset) catch {
            return error.InvalidRowEvent;
        };
    }

    // Determine DML type
    const dml_type: DmlType = switch (event_type) {
        .WRITE_ROWS_EVENT_V0, .WRITE_ROWS_EVENT => .Insert,
        .UPDATE_ROWS_EVENT_V0, .UPDATE_ROWS_EVENT, .PARTIAL_UPDATE_ROWS_EVENT => .Update,
        .DELETE_ROWS_EVENT_V0, .DELETE_ROWS_EVENT => .Delete,
        else => return error.InvalidRowEventType,
    };

    // Read columns-present bitmap for BEFORE image
    const bitmap_size_before = (column_count + 7) / 8;
    if (offset + bitmap_size_before > data.len) {
        return error.InvalidRowEvent;
    }

    const columns_present = try allocator.alloc(bool, column_count);
    defer allocator.free(columns_present);

    for (0..column_count) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        const bitmap_byte = data[offset + byte_idx];
        columns_present[i] = (bitmap_byte & (@as(u8, 1) << bit_idx)) != 0;
    }
    offset += bitmap_size_before;

    // For UPDATE events, read the second columns-present bitmap (after image)
    var columns_present_after: ?[]bool = null;
    defer if (columns_present_after) |cpa| allocator.free(cpa);

    if (dml_type == .Update) {
        const bitmap_size_after = bitmap_size_before;
        if (offset + bitmap_size_after > data.len) {
            return error.InvalidRowEvent;
        }

        columns_present_after = try allocator.alloc(bool, column_count);

        for (0..column_count) |i| {
            const byte_idx = i / 8;
            const bit_idx: u3 = @intCast(i % 8);
            const bitmap_byte = data[offset + byte_idx];
            columns_present_after.?[i] = (bitmap_byte & (@as(u8, 1) << bit_idx)) != 0;
        }
        offset += bitmap_size_after;
    }

    // Now parse ALL rows from the remaining data
    const remaining_data = if (offset < data.len) data[offset..] else data[0..0];
    var reader = DataReader.init(remaining_data);

    var rows: std.ArrayList(RowEvent) = .empty;
    errdefer {
        for (rows.items) |*row| {
            row.deinit(allocator);
        }
        rows.deinit(allocator);
    }

    while (reader.remaining() > 0) {
        var before_values: ?[]RowValue = null;
        var after_values: ?[]RowValue = null;

        const parse_ok = switch (dml_type) {
            .Insert => blk: {
                after_values = parseRowValuesWithReader(allocator, &reader, table_metadata.column_types, table_metadata.column_meta, columns_present) catch {
                    break :blk false;
                };
                break :blk true;
            },
            .Delete => blk: {
                before_values = parseRowValuesWithReader(allocator, &reader, table_metadata.column_types, table_metadata.column_meta, columns_present) catch {
                    break :blk false;
                };
                break :blk true;
            },
            .Update => blk: {
                const columns_present_before = columns_present;
                const columns_present_after_bitmap = columns_present_after orelse columns_present;

                before_values = parseRowValuesWithReader(allocator, &reader, table_metadata.column_types, table_metadata.column_meta, columns_present_before) catch {
                    break :blk false;
                };
                after_values = parseRowValuesWithReader(allocator, &reader, table_metadata.column_types, table_metadata.column_meta, columns_present_after_bitmap) catch {
                    // Free before_values since we failed on after
                    if (before_values) |bv| {
                        for (bv) |v| switch (v) {
                            .decimal => |s| allocator.free(s),
                            .json => |s| allocator.free(s),
                            .string => |s| allocator.free(s),
                            .blob => |b| allocator.free(b),
                            else => {},
                        };
                        allocator.free(bv);
                    }
                    before_values = null;
                    break :blk false;
                };
                break :blk true;
            },
        };

        if (!parse_ok) break;

        try rows.append(allocator, RowEvent{
            .dml_type = dml_type,
            .table_metadata = table_metadata,
            .column_count = column_count,
            .before_values = before_values,
            .after_values = after_values,
        });
    }

    return rows.toOwnedSlice(allocator);
}

/// Read MySQL length-encoded integer
/// Format:
/// - If < 251: 1 byte
/// - If 252: 2 bytes following
/// - If 253: 3 bytes following
/// - If 254: 8 bytes following
fn readLengthEncodedInteger(data: []const u8, offset: *usize) !u64 {
    if (offset.* >= data.len) {
        return error.BufferTooSmall;
    }

    const first_byte = data[offset.*];
    offset.* += 1;

    if (first_byte < 251) {
        return first_byte;
    } else if (first_byte == 252) {
        if (offset.* + 2 > data.len) return error.BufferTooSmall;
        const bytes = [_]u8{ data[offset.*], data[offset.* + 1] };
        const value = std.mem.readInt(u16, &bytes, .little);
        offset.* += 2;
        return value;
    } else if (first_byte == 253) {
        if (offset.* + 3 > data.len) return error.BufferTooSmall;
        const bytes = [_]u8{ data[offset.*], data[offset.* + 1], data[offset.* + 2], 0, 0, 0, 0, 0 };
        const value = std.mem.readInt(u64, &bytes, .little);
        offset.* += 3;
        return value;
    } else if (first_byte == 254) {
        if (offset.* + 8 > data.len) return error.BufferTooSmall;
        const bytes = [_]u8{
            data[offset.*],     data[offset.* + 1], data[offset.* + 2], data[offset.* + 3],
            data[offset.* + 4], data[offset.* + 5], data[offset.* + 6], data[offset.* + 7],
        };
        const value = std.mem.readInt(u64, &bytes, .little);
        offset.* += 8;
        return value;
    }

    return error.InvalidLengthEncodedInteger;
}
