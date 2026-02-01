//! Row JSON Serializer
//!
//! Converts []RowValue arrays to JSON strings for Parquet storage.
//! Uses a reusable scratch buffer with ArrayList fallback for overflow.

const std = @import("std");
const event_parser = @import("event_parser.zig");
const ArrayListWriter = @import("array_writer.zig").ArrayListWriter;

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

    pub fn init(allocator: std.mem.Allocator) RowJsonSerializer {
        return .{
            .overflow = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RowJsonSerializer) void {
        self.overflow.deinit(self.allocator);
    }

    /// Serialize a row of values to a JSON object string.
    /// Column names are "c0", "c1", etc. since TABLE_MAP doesn't provide column names.
    /// Returns a slice valid until the next call to serialize.
    pub fn serialize(self: *RowJsonSerializer, values: []const event_parser.RowValue) ![]const u8 {
        // Try scratch buffer first
        var fbw = FixedBufWriter{ .buf = &self.scratch };

        if (self.writeJson(&fbw, values)) {
            return fbw.getWritten();
        } else |_| {
            // Overflow: use ArrayList
            self.overflow.clearRetainingCapacity();
            var alw = ArrayListWriter.init(&self.overflow, self.allocator);
            try self.writeJson(&alw, values);
            return self.overflow.items;
        }
    }

    fn writeJson(self: *RowJsonSerializer, writer: anytype, values: []const event_parser.RowValue) !void {
        _ = self;
        try writer.writeByte('{');

        var first = true;
        for (values, 0..) |value, i| {
            if (!first) try writer.writeAll(",");
            first = false;

            // Write key
            try writer.print("\"c{d}\":", .{i});

            // Write value
            try writeValue(writer, value);
        }

        try writer.writeByte('}');
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
                        year_day.year, month_day.month.numeric(), month_day.day_index + 1,
                        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
                    });
                } else {
                    try writer.print("\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z\"", .{
                        year_day.year, month_day.month.numeric(), month_day.day_index + 1,
                        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(), micros,
                    });
                }
            },
            .duration => |dur| {
                if (dur.microseconds == 0) {
                    try writer.print("\"{s}{d:0>2}:{d:0>2}:{d:0>2}\"", .{
                        if (dur.is_negative == 1) "-" else "",
                        dur.hours, dur.minutes, dur.seconds,
                    });
                } else {
                    try writer.print("\"{s}{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}\"", .{
                        if (dur.is_negative == 1) "-" else "",
                        dur.hours, dur.minutes, dur.seconds, dur.microseconds,
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

    fn writeJsonString(writer: anytype, str: []const u8) !void {
        try writer.writeByte('"');
        for (str) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                else => {
                    if (c < 0x20) {
                        try writer.print("\\u{x:0>4}", .{c});
                    } else {
                        try writer.writeByte(c);
                    }
                },
            }
        }
        try writer.writeByte('"');
    }
};

test "serialize null values" {
    var s = RowJsonSerializer.init(std.testing.allocator);
    defer s.deinit();

    const values = [_]event_parser.RowValue{.null_value};
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":null}", result);
}

test "serialize integer values" {
    var s = RowJsonSerializer.init(std.testing.allocator);
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
    var s = RowJsonSerializer.init(std.testing.allocator);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .string = "hello \"world\"\n" },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":\"hello \\\"world\\\"\\n\"}", result);
}

test "serialize json passthrough" {
    var s = RowJsonSerializer.init(std.testing.allocator);
    defer s.deinit();

    const values = [_]event_parser.RowValue{
        .{ .json = "{\"key\":true}" },
    };
    const result = try s.serialize(&values);
    try std.testing.expectEqualStrings("{\"c0\":{\"key\":true}}", result);
}
