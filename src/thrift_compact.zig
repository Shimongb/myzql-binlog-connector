//! Thrift Compact Protocol Encoder
//!
//! Implements the Thrift compact protocol encoding used by Apache Parquet
//! for serializing file metadata (FileMetaData, RowGroup, ColumnChunk, etc.).
//!
//! Compact protocol reference:
//! https://github.com/apache/thrift/blob/master/doc/specs/thrift-compact-protocol.md

const std = @import("std");

/// Thrift compact protocol type IDs
pub const CompactType = enum(u4) {
    stop = 0,
    boolean_true = 1,
    boolean_false = 2,
    i8 = 3,
    i16 = 4,
    i32 = 5,
    i64 = 6,
    double = 7,
    binary = 8,
    list = 9,
    set = 10,
    map = 11,
    struct_ = 12,
};

pub const ThriftCompactWriter = struct {
    buffer: std.ArrayList(u8),
    field_id_stack: std.ArrayList(i16),
    last_field_id: i16,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ThriftCompactWriter {
        return .{
            .buffer = .empty,
            .field_id_stack = .empty,
            .last_field_id = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ThriftCompactWriter) void {
        self.buffer.deinit(self.allocator);
        self.field_id_stack.deinit(self.allocator);
    }

    pub fn getWritten(self: *const ThriftCompactWriter) []const u8 {
        return self.buffer.items;
    }

    pub fn reset(self: *ThriftCompactWriter) void {
        self.buffer.clearRetainingCapacity();
        self.field_id_stack.clearRetainingCapacity();
        self.last_field_id = 0;
    }

    // === Low-level encoding ===

    pub fn writeVarint(self: *ThriftCompactWriter, value: u64) !void {
        var v = value;
        while (v >= 0x80) {
            try self.buffer.append(self.allocator, @intCast((v & 0x7F) | 0x80));
            v >>= 7;
        }
        try self.buffer.append(self.allocator, @intCast(v & 0x7F));
    }

    fn zigzagEncode(n: i64) u64 {
        const v: u64 = @bitCast(n);
        return (v << 1) ^ @as(u64, @bitCast(n >> 63));
    }

    fn zigzagEncode32(n: i32) u64 {
        const v: u64 = @intCast(@as(u32, @bitCast(n)));
        return (v << 1) ^ @as(u64, @bitCast(@as(i64, n) >> 63));
    }

    // === Field headers ===

    fn writeFieldHeader(self: *ThriftCompactWriter, field_id: i16, compact_type: CompactType) !void {
        const delta = field_id - self.last_field_id;
        if (delta > 0 and delta <= 15) {
            try self.buffer.append(self.allocator, @as(u8, @intCast(delta)) << 4 | @as(u8, @intFromEnum(compact_type)));
        } else {
            try self.buffer.append(self.allocator, @as(u8, @intFromEnum(compact_type)));
            try self.writeVarint(zigzagEncode(@as(i64, field_id)));
        }
        self.last_field_id = field_id;
    }

    pub fn writeStop(self: *ThriftCompactWriter) !void {
        try self.buffer.append(self.allocator, 0x00);
    }

    // === Typed field writers ===

    pub fn writeBool(self: *ThriftCompactWriter, field_id: i16, value: bool) !void {
        const ct: CompactType = if (value) .boolean_true else .boolean_false;
        try self.writeFieldHeader(field_id, ct);
    }

    pub fn writeI32(self: *ThriftCompactWriter, field_id: i16, value: i32) !void {
        try self.writeFieldHeader(field_id, .i32);
        try self.writeVarint(zigzagEncode32(value));
    }

    pub fn writeI64(self: *ThriftCompactWriter, field_id: i16, value: i64) !void {
        try self.writeFieldHeader(field_id, .i64);
        try self.writeVarint(zigzagEncode(value));
    }

    pub fn writeBinary(self: *ThriftCompactWriter, field_id: i16, data: []const u8) !void {
        try self.writeFieldHeader(field_id, .binary);
        try self.writeVarint(data.len);
        try self.buffer.appendSlice(self.allocator, data);
    }

    pub fn writeString(self: *ThriftCompactWriter, field_id: i16, str: []const u8) !void {
        try self.writeBinary(field_id, str);
    }

    // === Struct support ===

    pub fn beginStruct(self: *ThriftCompactWriter, field_id: i16) !void {
        try self.writeFieldHeader(field_id, .struct_);
        try self.field_id_stack.append(self.allocator, self.last_field_id);
        self.last_field_id = 0;
    }

    pub fn endStruct(self: *ThriftCompactWriter) !void {
        try self.writeStop();
        self.last_field_id = self.field_id_stack.pop().?;
    }

    pub fn beginRootStruct(self: *ThriftCompactWriter) void {
        self.last_field_id = 0;
    }

    pub fn endRootStruct(self: *ThriftCompactWriter) !void {
        try self.writeStop();
    }

    // === List support ===

    pub fn beginList(self: *ThriftCompactWriter, field_id: i16, elem_type: CompactType, count: usize) !void {
        try self.writeFieldHeader(field_id, .list);
        if (count <= 14) {
            try self.buffer.append(self.allocator, @as(u8, @intCast(count)) << 4 | @as(u8, @intFromEnum(elem_type)));
        } else {
            try self.buffer.append(self.allocator, 0xF0 | @as(u8, @intFromEnum(elem_type)));
            try self.writeVarint(count);
        }
    }

    /// Begin writing an inline list element that is a struct.
    pub fn beginListStructElement(self: *ThriftCompactWriter) !void {
        try self.field_id_stack.append(self.allocator, self.last_field_id);
        self.last_field_id = 0;
    }

    /// End an inline list struct element.
    pub fn endListStructElement(self: *ThriftCompactWriter) !void {
        try self.writeStop();
        self.last_field_id = self.field_id_stack.pop().?;
    }

    /// Write a list of i32 values
    pub fn writeI32List(self: *ThriftCompactWriter, field_id: i16, values: []const i32) !void {
        try self.beginList(field_id, .i32, values.len);
        for (values) |v| {
            try self.writeVarint(zigzagEncode32(v));
        }
    }

    /// Direct append to buffer (used by parquet_writer for inline binary data in lists)
    pub fn appendRawSlice(self: *ThriftCompactWriter, data: []const u8) !void {
        try self.buffer.appendSlice(self.allocator, data);
    }
};

// === Tests ===

test "varint encoding" {
    var writer = ThriftCompactWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeVarint(0);
    try std.testing.expectEqualSlices(u8, &.{0x00}, writer.getWritten());

    writer.reset();
    try writer.writeVarint(1);
    try std.testing.expectEqualSlices(u8, &.{0x01}, writer.getWritten());

    writer.reset();
    try writer.writeVarint(127);
    try std.testing.expectEqualSlices(u8, &.{0x7F}, writer.getWritten());

    writer.reset();
    try writer.writeVarint(128);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x01 }, writer.getWritten());

    writer.reset();
    try writer.writeVarint(300);
    try std.testing.expectEqualSlices(u8, &.{ 0xAC, 0x02 }, writer.getWritten());
}

test "zigzag encoding" {
    try std.testing.expectEqual(@as(u64, 0), ThriftCompactWriter.zigzagEncode(0));
    try std.testing.expectEqual(@as(u64, 1), ThriftCompactWriter.zigzagEncode(-1));
    try std.testing.expectEqual(@as(u64, 2), ThriftCompactWriter.zigzagEncode(1));
    try std.testing.expectEqual(@as(u64, 3), ThriftCompactWriter.zigzagEncode(-2));
    try std.testing.expectEqual(@as(u64, 4), ThriftCompactWriter.zigzagEncode(2));
}

test "field header delta encoding" {
    var writer = ThriftCompactWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeI32(1, 42);
    try std.testing.expectEqual(@as(u8, 0x15), writer.getWritten()[0]);
}

test "binary/string encoding" {
    var writer = ThriftCompactWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeString(1, "hello");
    const data = writer.getWritten();
    try std.testing.expectEqual(@as(u8, 0x18), data[0]);
    try std.testing.expectEqual(@as(u8, 5), data[1]);
    try std.testing.expectEqualStrings("hello", data[2..7]);
}

test "list encoding small" {
    var writer = ThriftCompactWriter.init(std.testing.allocator);
    defer writer.deinit();

    try writer.writeI32List(1, &.{ 0, 2 });
    const data = writer.getWritten();
    try std.testing.expectEqual(@as(u8, 0x19), data[0]);
    try std.testing.expectEqual(@as(u8, 0x25), data[1]);
}

test "struct nesting" {
    var writer = ThriftCompactWriter.init(std.testing.allocator);
    defer writer.deinit();

    writer.beginRootStruct();
    try writer.writeI32(1, 10);
    try writer.beginStruct(2);
    try writer.writeI32(1, 20);
    try writer.endStruct();
    try writer.writeI32(3, 30);
    try writer.endRootStruct();

    try std.testing.expect(writer.getWritten().len > 0);
}
