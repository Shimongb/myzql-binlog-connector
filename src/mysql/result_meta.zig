// MySQL result set metadata buffer.
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const ColumnDefinition41 = @import("protocol/column_definition.zig").ColumnDefinition41;
const Conn = @import("conn.zig").Conn;
const Packet = @import("protocol/packet.zig").Packet;

pub const ResultMeta = struct {
    raw: std.ArrayList(u8),
    col_defs: std.ArrayList(ColumnDefinition41),

    pub fn init() ResultMeta {
        return ResultMeta{
            .raw = std.ArrayList(u8).empty,
            .col_defs = std.ArrayList(ColumnDefinition41).empty,
        };
    }

    pub fn deinit(r: *ResultMeta, allocator: std.mem.Allocator) void {
        r.raw.deinit(allocator);
        r.col_defs.deinit(allocator);
    }

    pub inline fn readPutResultColumns(r: *ResultMeta, allocator: std.mem.Allocator, c: *Conn, n: usize) !void {
        r.raw.clearRetainingCapacity();
        r.col_defs.clearRetainingCapacity();

        const col_defs = try r.col_defs.addManyAsSlice(allocator, n);
        for (col_defs) |*col_def| {
            var packet = try c.readPacket();
            const payload_owned = try r.raw.addManyAsSlice(allocator, packet.payload.len);
            @memcpy(payload_owned, packet.payload);
            packet.payload = payload_owned;
            col_def.init2(&packet);
        }
    }
};
