// MySQL text protocol query command.
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const PacketWriter = @import("packet_writer.zig").PacketWriter;
const constants = @import("../constants.zig");

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
pub const QueryRequest = struct {
    query: []const u8,

    pub fn write(q: *const QueryRequest, writer: *PacketWriter) !void {
        try writer.writeInt(u8, constants.COM_QUERY);
        try writer.write(q.query);
    }
};
