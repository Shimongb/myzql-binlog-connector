//! Row JSON Serializer
//!
//! Converts []RowValue arrays to JSON strings for Parquet storage.
//! Uses a reusable scratch buffer with ArrayList fallback for overflow.

const std = @import("std");
const event_parser = @import("event_parser.zig");
const ArrayListWriter = @import("array_writer.zig").ArrayListWriter;
const schema_cache_mod = @import("schema_cache.zig");
const ColumnInfo = schema_cache_mod.ColumnInfo;
const config_mod = @import("config.zig");
pub const BooleanEncoding = config_mod.BooleanEncoding;

/// A simple writer that writes to a fixed buffer, returning error.NoSpaceLeft on overflow.
const FixedBufWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeByte(self: *FixedBufWriter, byte: u8) !void {
        if (self.pos >= self.buf.len) return error.NoSpaceLeft;
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    fn writeAll(self: *FixedBufWriter, bytes: []const u8) !void {
        if (self.pos + bytes.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn print(self: *FixedBufWriter, comptime fmt: []const u8, args: anytype) !void {
        const remaining = self.buf[self.pos..];
        const result = std.fmt.bufPrint(remaining, fmt, args) catch return error.NoSpaceLeft;
        self.pos += result.len;
    }

    fn getWritten(self: *const FixedBufWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

pub const RowJsonSerializer = struct {
    scratch: [8192]u8 = undefined,
    overflow: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    boolean_encoding: BooleanEncoding,

    pub fn init(allocator: std.mem.Allocator, boolean_encoding: BooleanEncoding) RowJsonSerializer {
        return .{
            .overflow = .empty,
            .allocator = allocator,
            .boolean_encoding = boolean_encoding,
        };
    }

    pub fn deinit(self: *RowJsonSerializer) void {
        self.overflow.deinit(self.allocator);
    }

    /// Serialize a row of values to a JSON object string.
    /// If resolved_columns is provided, uses actual column names and resolves
    /// enum/set integer values to their string labels.
    /// Otherwise, falls back to positional names "c0", "c1", etc.
    /// Returns a slice valid until the next call to serialize.
    pub fn serialize(self: *RowJsonSerializer, values: []const event_parser.RowValue) ![]const u8 {
        return self.serializeWithColumns(values, null);
    }

    /// Serialize with optional column info for named columns and enum/set resolution.
    pub fn serializeWithColumns(self: *RowJsonSerializer, values: []const event_parser.RowValue, columns: ?[]const ColumnInfo) ![]const u8 {
        // Try scratch buffer first
        var fbw = FixedBufWriter{ .buf = &self.scratch };

        if (self.writeJson(&fbw, values, columns)) {
            return fbw.getWritten();
        } else |_| {
            // Overflow: use ArrayList
            self.overflow.clearRetainingCapacity();
            var alw = ArrayListWriter.init(&self.overflow, self.allocator);
            try self.writeJson(&alw, values, columns);
            return self.overflow.items;
        }
    }

    fn writeJson(self: *RowJsonSerializer, writer: anytype, values: []const event_parser.RowValue, columns: ?[]const ColumnInfo) !void {
        try writer.writeByte('{');

        var first = true;
        for (values, 0..) |value, i| {
            if (!first) try writer.writeAll(",");
            first = false;

            // Write key: use column name if available, otherwise positional
            if (columns) |cols| {
                if (i < cols.len) {
                    try writer.writeByte('"');
                    try writer.writeAll(cols[i].column_name);
                    try writer.writeAll("\":");
                } else {
                    try writer.print("\"c{d}\":", .{i});
                }
            } else {
                try writer.print("\"c{d}\":", .{i});
            }

            // Write value with enum/set resolution if available
            if (columns) |cols| {
                if (i < cols.len) {
                    if (try self.writeResolvedValue(writer, value, cols[i])) continue;
                }
            }
            try writeValue(writer, value);
        }

        try writer.writeByte('}');
    }

    /// Try to resolve enum/set values. Returns true if the value was written.
    fn writeResolvedValue(self: *RowJsonSerializer, writer: anytype, value: event_parser.RowValue, col: ColumnInfo) !bool {
        // Boolean coercion for MySQL's canonical BOOL signals:
        //   - tinyint(1): BOOL/BOOLEAN are SQL-level aliases for this exact type.
        //                 MySQL 8.0.17+ retains the (1) display width specifically
        //                 to convey boolean intent after removing it for other widths.
        //   - bit(1): literally a 1-bit value, stored as a single byte.
        //
        // Wider tinyint(N)/bit(N) are deliberately left alone so non-boolean
        // integers aren't misrepresented as true/false.
        if (self.boolean_encoding != .raw) {
            if (columnTypeIsBool1(col.column_type)) {
                const truthy: ?bool = switch (value) {
                    .tiny => |v| v != 0,
                    .blob => |b| blk: {
                        for (b) |byte| if (byte != 0) break :blk true;
                        break :blk false;
                    },
                    else => null,
                };
                if (truthy) |t| {
                    switch (self.boolean_encoding) {
                        .auto_bool => try writer.writeAll(if (t) "true" else "false"),
                        .auto_int => try writer.writeAll(if (t) "1" else "0"),
                        .raw => unreachable,
                    }
                    return true;
                }
            }
        }

        // Only resolve integer types that might be enum/set
        const int_val: i64 = switch (value) {
            .tiny => |v| v,
            .short => |v| v,
            .long => |v| v,
            .longlong => |v| v,
            else => return false,
        };

        // Guard against negative values (corrupted data or unsigned interpretation)
        if (int_val < 0) return false;

        // Use the cached parse from ColumnInfo. Populated once at schema
        // resolution time (DESCRIBE / DDL / cache load); no per-row alloc.
        const def = col.parsed_enum_set orelse return false;

        switch (def) {
            .enum_def => |members| {
                if (schema_cache_mod.resolveEnumValue(members, int_val)) |label| {
                    try writer.writeByte('"');
                    try writer.writeAll(label);
                    try writer.writeByte('"');
                    return true;
                }
            },
            .set_def => |members| {
                const result = schema_cache_mod.resolveSetValue(self.allocator, members, int_val) catch return false;
                defer self.allocator.free(result);
                try writer.writeByte('"');
                try writer.writeAll(result);
                try writer.writeByte('"');
                return true;
            },
        }
        return false;
    }

    /// Matches `tinyint(1)` (optionally followed by ` unsigned` / ` zerofill`)
    /// and `bit(1)` - the two MySQL column types that canonically mean BOOL.
    /// Deliberately does NOT match `tinyint(10)`, `tinyint(11)`, etc.
    fn columnTypeIsBool1(column_type: []const u8) bool {
        const tinyint1 = "tinyint(1)";
        const bit1 = "bit(1)";
        if (std.mem.startsWith(u8, column_type, tinyint1)) {
            if (column_type.len == tinyint1.len) return true;
            // Accept trailing modifiers like " unsigned" but reject "tinyint(10)"
            return column_type[tinyint1.len] == ' ';
        }
        return std.mem.eql(u8, column_type, bit1);
    }

    fn writeValue(writer: anytype, value: event_parser.RowValue) !void {
        switch (value) {
            .null_value => try writer.writeAll("null"),
            .tiny => |v| try writer.print("{d}", .{v}),
            .short => |v| try writer.print("{d}", .{v}),
            .long => |v| try writer.print("{d}", .{v}),
            .longlong => |v| try writer.print("{d}", .{v}),
            .float => |v| try writer.print("{d}", .{v}),
            .double => |v| try writer.print("{d}", .{v}),
            .year => |v| try writer.print("{d}", .{v}),
            .datetime => |dt| {
                if (dt.microsecond == 0) {
                    try writer.print("\"{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}\"", .{
                        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second,
                    });
                } else {
                    try writer.print("\"{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}\"", .{
                        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond,
                    });
                }
            },
            .timestamp => |v| {
                const seconds = @divFloor(v, 1_000_000);
                const micros_signed = @mod(v, 1_000_000);
                const micros: u32 = @intCast(@abs(micros_signed));

                const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
                const epoch_day = epoch_seconds.getEpochDay();
                const year_day = epoch_day.calculateYearDay();
                const month_day = year_day.calculateMonthDay();
                const day_seconds = epoch_seconds.getDaySeconds();

                if (micros == 0) {
                    try writer.print("\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\"", .{
                        year_day.year,                 month_day.month.numeric(),        month_day.day_index + 1,
                        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
                    });
                } else {
                    try writer.print("\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z\"", .{
                        year_day.year,                 month_day.month.numeric(),        month_day.day_index + 1,
                        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
                        micros,
                    });
                }
            },
            .duration => |dur| {
                if (dur.microseconds == 0) {
                    try writer.print("\"{s}{d:0>2}:{d:0>2}:{d:0>2}\"", .{
                        if (dur.is_negative == 1) "-" else "",
                        dur.hours,
                        dur.minutes,
                        dur.seconds,
                    });
                } else {
                    try writer.print("\"{s}{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}\"", .{
                        if (dur.is_negative == 1) "-" else "",
                        dur.hours,
                        dur.minutes,
                        dur.seconds,
                        dur.microseconds,
                    });
                }
            },
            .string => |v| try writeJsonString(writer, v),
            .blob => |v| {
                try writer.writeAll("\"0x");
                for (v) |b| {
                    try writer.print("{x:0>2}", .{b});
                }
                try writer.writeByte('"');
            },
            .decimal => |v| {
                try writer.writeByte('"');
                try writer.writeAll(v);
                try writer.writeByte('"');
            },
            .json => |v| {
                try writer.writeAll(v);
            },
        }
    }

    /// Write a JSON-escaped string, ensuring valid UTF-8 output.
    /// Valid UTF-8 multi-byte sequences are passed through; invalid bytes are
    /// escaped as \u00XX to prevent producing invalid UTF-8 in the output.
    fn writeJsonString(writer: anytype, str: []const u8) !void {
        try writer.writeByte('"');
        var i: usize = 0;
        while (i < str.len) {
            const c = str[i];
            switch (c) {
                '"' => {
                    try writer.writeAll("\\\"");
                    i += 1;
                },
                '\\' => {
                    try writer.writeAll("\\\\");
                    i += 1;
                },
                '\n' => {
                    try writer.writeAll("\\n");
                    i += 1;
                },
                '\r' => {
                    try writer.writeAll("\\r");
                    i += 1;
                },
                '\t' => {
                    try writer.writeAll("\\t");
                    i += 1;
                },
                else => {
                    if (c < 0x20) {
                        try writer.print("\\u{x:0>4}", .{@as(u16, c)});
                        i += 1;
                    } else if (c < 0x80) {
                        // ASCII printable
                        try writer.writeByte(c);
                        i += 1;
                    } else {
                        // Determine expected UTF-8 sequence length from start
                        // byte. Upper bounds matter: 0xF5..=0xFF and 0xC0..=0xC1
                        // are never valid lead bytes per RFC 3629, and
                        // historically this branch let 0xF5..=0xFF fall through
                        // the 4-byte test and get accepted as a 3-byte lead -
                        // which then passed the continuation-bits check for
                        // arbitrary MySQL binary bytes, producing parquet
                        // strings that claim UTF-8 but aren't.
                        const seq_len: usize = if (c >= 0xF0 and c <= 0xF4) 4 //
                            else if (c >= 0xE0 and c < 0xF0) 3 //
                            else if (c >= 0xC2 and c < 0xE0) 2 //
                            else 0; // 0x80-0xBF (continuation), 0xC0-0xC1
                        // (overlong), or 0xF5-0xFF (out of range)

                        if (seq_len >= 2 and i + seq_len <= str.len) {
                            // Validate continuation bytes (must be 0x80-0xBF)
                            var valid = true;
                            for (1..seq_len) |j| {
                                if ((str[i + j] & 0xC0) != 0x80) {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid) {
                                // Valid UTF-8 sequence, pass through
                                try writer.writeAll(str[i .. i + seq_len]);
                                i += seq_len;
                                continue;
                            }
                        }
                        // Invalid or truncated UTF-8: escape individual byte
                        try writer.print("\\u00{x:0>2}", .{c});
                        i += 1;
                    }
                },
            }
        }
        try writer.writeByte('"');
    }
};

test "serialize null values" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const values = [_]event_parser.RowValue{.null_value};
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":null}", result);
}

test "serialize integer values" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .tiny = 42 },
        .{ .long = -100 },
        .{ .longlong = 9999999 },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":42,\"c1\":-100,\"c2\":9999999}", result);
}

test "serialize string with escaping" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .string = "hello \"world\"\n" },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":\"hello \\\"world\\\"\\n\"}", result);
}

test "serialize string: invalid UTF-8 leads get escaped, not passed through" {
    // Regression: MySQL binary(16) columns arrive as .string with arbitrary
    // bytes. A prior version's seq-len cascade accepted 0xF5-0xFF as 3-byte
    // UTF-8 leads, which let parquet writers emit "UTF8" strings that weren't.
    // DuckDB rejects those on read with "Invalid string encoding found in
    // Parquet file ... not valid UTF8".
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .string = &[_]u8{ 0xF9, 0x8D, 0xAD } },
    };
    const result = try s.serialize(&values);
    // Each byte should be escaped as \u00xx individually; no raw byte
    // should leak through into the output.
    try std.testing.expectEqualStrings(
        "{\"c0\":\"\\u00f9\\u008d\\u00ad\"}",
        result,
    );
}

test "serialize string: valid UTF-8 still passes through untouched" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    // "héllo" - valid 2-byte UTF-8 (é = 0xC3 0xA9). Guards against the
    // regression fix over-escaping and breaking real UTF-8.
    const values = [_]event_parser.RowValue{
        .{ .string = "h\xC3\xA9llo" },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":\"h\xC3\xA9llo\"}", result);
}

test "serialize json passthrough" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .json = "{\"key\":true}" },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":{\"key\":true}}", result);
}

fn makeBoolCol(name: []const u8, column_type: []const u8) ColumnInfo {
    return .{
        .column_name = name,
        .column_type = column_type,
        .is_nullable = true,
        .column_key = "",
        .column_default = null,
        .column_extra = "",
        .ordinal_position = 1,
    };
}

test "bool coercion: tinyint(1) auto_bool" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{
        makeBoolCol("is_foo", "tinyint(1)"),
        makeBoolCol("is_bar", "tinyint(1)"),
        makeBoolCol("is_baz", "tinyint(1) unsigned"),
    };
    const values = [_]event_parser.RowValue{
        .{ .tiny = 0 },
        .{ .tiny = 1 },
        .{ .tiny = 42 }, // any non-zero is true
    };
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings(
        "{\"is_foo\":false,\"is_bar\":true,\"is_baz\":true}",
        result,
    );
}

test "bool coercion: bit(1) auto_bool" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{
        makeBoolCol("a", "bit(1)"),
        makeBoolCol("b", "bit(1)"),
    };
    const values = [_]event_parser.RowValue{
        .{ .blob = &[_]u8{0x00} },
        .{ .blob = &[_]u8{0x01} },
    };
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"a\":false,\"b\":true}", result);
}

test "bool coercion: auto_int emits 1/0 for bit(1) and tinyint(1)" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_int);
    defer s.deinit();

    const cols = [_]ColumnInfo{
        makeBoolCol("ti", "tinyint(1)"),
        makeBoolCol("bi", "bit(1)"),
    };
    const values = [_]event_parser.RowValue{
        .{ .tiny = 0 },
        .{ .blob = &[_]u8{0x01} },
    };
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"ti\":0,\"bi\":1}", result);
}

test "bool coercion: raw mode preserves legacy hex blob for bit(1)" {
    var s = RowJsonSerializer.init(std.testing.allocator, .raw);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeBoolCol("a", "bit(1)")};
    const values = [_]event_parser.RowValue{.{ .blob = &[_]u8{0x01} }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"a\":\"0x01\"}", result);
}

test "bool coercion: wider types are NOT coerced" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{
        makeBoolCol("flags", "tinyint(4)"), // display width != 1 → not boolean
        makeBoolCol("mask", "bit(8)"), // bit(N>1) → not boolean
    };
    const values = [_]event_parser.RowValue{
        .{ .tiny = 5 },
        .{ .blob = &[_]u8{0x05} },
    };
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"flags\":5,\"mask\":\"0x05\"}", result);
}

test "bool coercion: tinyint(10) must not match tinyint(1) prefix" {
    // Regression guard: a naive startsWith(\"tinyint(1)\") would eat tinyint(10).
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeBoolCol("n", "tinyint(10)")};
    const values = [_]event_parser.RowValue{.{ .tiny = 7 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"n\":7}", result);
}

// ------------------------------------------------------------
// Enum/Set resolution via cached ColumnInfo.parsed_enum_set
// ------------------------------------------------------------
//
// These tests verify that the serializer reads the pre-parsed EnumSetDef
// from ColumnInfo rather than re-parsing on every row (the hot-path fix
// from the column-awareness performance follow-up). All defs below are
// constructed statically so no allocator ownership is involved.

const enum_status_members = [_][]const u8{ "active", "inactive", "pending" };
const set_perms_members = [_][]const u8{ "read", "write", "exec" };

fn makeEnumCol(name: []const u8, column_type: []const u8, members: []const []const u8) ColumnInfo {
    return .{
        .column_name = name,
        .column_type = column_type,
        .is_nullable = true,
        .column_key = "",
        .column_default = null,
        .column_extra = "",
        .ordinal_position = 1,
        .parsed_enum_set = .{ .enum_def = members },
    };
}

fn makeSetCol(name: []const u8, column_type: []const u8, members: []const []const u8) ColumnInfo {
    return .{
        .column_name = name,
        .column_type = column_type,
        .is_nullable = true,
        .column_key = "",
        .column_default = null,
        .column_extra = "",
        .ordinal_position = 1,
        .parsed_enum_set = .{ .set_def = members },
    };
}

test "enum resolution: cached def renders label" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeEnumCol("status", "enum('active','inactive','pending')", &enum_status_members)};
    const values = [_]event_parser.RowValue{.{ .tiny = 2 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"status\":\"inactive\"}", result);
}

test "enum resolution: zero encodes as empty string (MySQL semantics)" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeEnumCol("status", "enum('active','inactive')", enum_status_members[0..2])};
    const values = [_]event_parser.RowValue{.{ .tiny = 0 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"status\":\"\"}", result);
}

test "enum resolution: out-of-range value falls through to integer" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeEnumCol("status", "enum('active','inactive','pending')", &enum_status_members)};
    const values = [_]event_parser.RowValue{.{ .tiny = 99 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"status\":99}", result);
}

test "set resolution: bitmask renders comma-joined labels" {
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{makeSetCol("perms", "set('read','write','exec')", &set_perms_members)};
    // 0b101 = read + exec
    const values = [_]event_parser.RowValue{.{ .long = 5 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"perms\":\"read,exec\"}", result);
}

test "enum resolution: missing parsed_enum_set falls through to integer" {
    // Guards against regression where a stale cache entry or un-refreshed
    // column would cause enum values to be silently rendered as numbers.
    // The serializer MUST NOT re-parse column_type to rescue this case.
    var s = RowJsonSerializer.init(std.testing.allocator, .auto_bool);
    defer s.deinit();

    const cols = [_]ColumnInfo{.{
        .column_name = "status",
        .column_type = "enum('active','inactive')",
        .is_nullable = true,
        .column_key = "",
        .column_default = null,
        .column_extra = "",
        .ordinal_position = 1,
        .parsed_enum_set = null,
    }};
    const values = [_]event_parser.RowValue{.{ .tiny = 1 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"status\":1}", result);
}

test "enum resolution: refreshParsedEnumSet populates cache for serializer" {
    // End-to-end: start from a raw ColumnInfo (as if just built from a
    // DESCRIBE row before refresh), call refreshParsedEnumSet, and confirm
    // the serializer picks up the cached def.
    const allocator = std.testing.allocator;
    var s = RowJsonSerializer.init(allocator, .auto_bool);
    defer s.deinit();

    var col = ColumnInfo{
        .column_name = try allocator.dupe(u8, "status"),
        .column_type = try allocator.dupe(u8, "enum('a','b','c')"),
        .is_nullable = true,
        .column_key = try allocator.dupe(u8, ""),
        .column_default = null,
        .column_extra = try allocator.dupe(u8, ""),
        .ordinal_position = 1,
    };
    defer col.deinit(allocator);
    try col.refreshParsedEnumSet(allocator);

    const cols = [_]ColumnInfo{col};
    const values = [_]event_parser.RowValue{.{ .tiny = 3 }};
    const result = try s.serializeWithColumns(&values, &cols);
    try std.testing.expectEqualStrings("{\"status\":\"c\"}", result);
}
