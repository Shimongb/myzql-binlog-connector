// MySQL query result types (trimmed to only what's used).
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const constants = @import("constants.zig");
const Packet = @import("protocol/packet.zig").Packet;
const OkPacket = @import("protocol/generic_response.zig").OkPacket;
const ErrorPacket = @import("protocol/generic_response.zig").ErrorPacket;

pub const QueryResult = union(enum) {
    ok: OkPacket,
    err: ErrorPacket,

    pub fn init(packet: *const Packet, capabilities: u32) !QueryResult {
        return switch (packet.payload[0]) {
            constants.OK => .{ .ok = OkPacket.init(packet, capabilities) },
            constants.ERR => .{ .err = ErrorPacket.init(packet) },
            constants.LOCAL_INFILE_REQUEST => _ = @panic("not implemented"),
            else => {
                std.log.warn(
                    \\Unexpected packet: {any}\n,
                    \\Are you expecting a result set? If so, use QueryResultRows instead.
                    \\This is unrecoverable error.
                , .{packet});
                return error.UnrecoverableError;
            },
        };
    }
};
