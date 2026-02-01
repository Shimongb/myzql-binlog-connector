const std = @import("std");

/// Writer adapter for ArrayListUnmanaged(u8) that captures an allocator,
/// providing the same interface as the removed ArrayList.writer() in Zig 0.16.
pub const ArrayListWriter = struct {
    list: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    pub fn init(list: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator) ArrayListWriter {
        return .{ .list = list, .allocator = allocator };
    }

    pub fn writeByte(self: *ArrayListWriter, byte: u8) !void {
        try self.list.append(self.allocator, byte);
    }

    pub fn writeAll(self: *ArrayListWriter, bytes: []const u8) !void {
        try self.list.appendSlice(self.allocator, bytes);
    }

    pub fn writeInt(self: *ArrayListWriter, comptime T: type, value: T, endian: std.builtin.Endian) !void {
        const bytes = std.mem.toBytes(if (endian == .little) std.mem.nativeToLittle(T, value) else std.mem.nativeToBig(T, value));
        try self.list.appendSlice(self.allocator, &bytes);
    }

    pub fn print(self: *ArrayListWriter, comptime fmt: []const u8, args: anytype) !void {
        // Use allocPrint then append
        const str = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(str);
        try self.list.appendSlice(self.allocator, str);
    }
};
