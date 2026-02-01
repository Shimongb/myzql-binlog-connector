// MySQL connection handler (trimmed to used code paths only).
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");

const auth = @import("auth.zig");
const Config = @import("config.zig").Config;
const compat = @import("compat.zig");
const constants = @import("constants.zig");
const HandshakeV10 = @import("protocol/handshake_v10.zig").HandshakeV10;
const ErrorPacket = @import("protocol/generic_response.zig").ErrorPacket;
const OkPacket = @import("protocol/generic_response.zig").OkPacket;
const HandshakeResponse41 = @import("protocol/handshake_response.zig").HandshakeResponse41;
const QueryRequest = @import("protocol/text_command.zig").QueryRequest;
const Packet = @import("protocol/packet.zig").Packet;
const PacketReader = @import("protocol/packet_reader.zig").PacketReader;
const PacketWriter = @import("protocol/packet_writer.zig").PacketWriter;
const QueryResult = @import("result.zig").QueryResult;
const ResultMeta = @import("result_meta.zig").ResultMeta;

pub const Conn = struct {
    connected: bool,
    stream: compat.Stream,
    reader: PacketReader,
    writer: PacketWriter,
    capabilities: u32,
    sequence_id: u8,

    // Buffer to store metadata of the result set
    result_meta: ResultMeta,

    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
    pub fn init(allocator: std.mem.Allocator, config: *const Config) !Conn {
        var conn: Conn = blk: {
            const stream = try compat.tcpConnectToAddress(config.address);
            break :blk .{
                .connected = true,
                .stream = stream,
                .reader = try PacketReader.init(stream, allocator),
                .writer = try PacketWriter.init(stream, allocator),
                .capabilities = undefined, // not known until we get the first packet
                .sequence_id = undefined, // not known until we get the first packet

                .result_meta = ResultMeta.init(),
            };
        };
        errdefer conn.deinit(allocator);

        const auth_plugin, const auth_data = blk: {
            const packet = try conn.readPacket();
            const handshake_v10 = switch (packet.payload[0]) {
                constants.HANDSHAKE_V10 => HandshakeV10.init(&packet),
                constants.ERR => return ErrorPacket.initFirst(&packet).asError(),
                else => return packet.asError(),
            };
            conn.capabilities = handshake_v10.capability_flags() & config.capability_flags();

            if (conn.capabilities & constants.CLIENT_PROTOCOL_41 == 0) {
                std.log.err("protocol older than 4.1 is not supported\n", .{});
                return error.UnsupportedProtocol;
            }

            break :blk .{ handshake_v10.get_auth_plugin(), handshake_v10.get_auth_data() };
        };

        // more auth exchange based on auth_method
        switch (auth_plugin) {
            .caching_sha2_password => try conn.auth_caching_sha2_password(allocator, &auth_data, config),
            .mysql_native_password => try conn.auth_mysql_native_password(&auth_data, config),
            .sha256_password => try conn.auth_sha256_password(allocator, &auth_data, config),
            else => {
                std.log.warn("Unsupported auth plugin: {any}\n", .{auth_plugin});
                return error.UnsupportedAuthPlugin;
            },
        }

        return conn;
    }

    pub fn deinit(c: *Conn, allocator: std.mem.Allocator) void {
        c.quit() catch {};
        c.stream.close();
        c.reader.deinit();
        c.writer.deinit();
        c.result_meta.deinit(allocator);
    }

    pub fn ping(c: *Conn) !void {
        c.ready();
        try c.writeBytesAsPacket(&[_]u8{constants.COM_PING});
        try c.writer.flush();
        const packet = try c.readPacket();

        switch (packet.payload[0]) {
            constants.OK => _ = OkPacket.init(&packet, c.capabilities),
            else => return packet.asError(),
        }
    }

    // query that doesn't return any rows
    pub fn query(c: *Conn, query_string: []const u8) !QueryResult {
        c.ready();
        const query_req: QueryRequest = .{ .query = query_string };
        try c.writePacket(query_req);
        try c.writer.flush();
        const packet = try c.readPacket();
        return c.queryResult(&packet);
    }

    fn quit(c: *Conn) !void {
        c.ready();
        try c.writeBytesAsPacket(&[_]u8{constants.COM_QUIT});
        try c.writer.flush();
        const packet = c.readPacket() catch |err| switch (err) {
            error.UnexpectedEndOfStream => {
                c.connected = false;
                return;
            },
            else => return err,
        };
        return packet.asError();
    }

    fn auth_mysql_native_password(c: *Conn, auth_data: *const [20]u8, config: *const Config) !void {
        const auth_resp = auth.scramblePassword(auth_data, config.password);
        const response = HandshakeResponse41.init(.mysql_native_password, config, if (config.password.len > 0) &auth_resp else &[_]u8{});
        try c.writePacket(response);
        try c.writer.flush();

        const packet = try c.readPacket();
        return switch (packet.payload[0]) {
            constants.OK => {},
            else => packet.asError(),
        };
    }

    fn auth_sha256_password(c: *Conn, allocator: std.mem.Allocator, auth_data: *const [20]u8, config: *const Config) !void {
        const response = HandshakeResponse41.init(.sha256_password, config, &[_]u8{auth.sha256_password_public_key_request});
        try c.writePacket(response);
        try c.writer.flush();

        const pk_packet = try c.readPacket();

        // Decode public key
        const decoded_pk = try auth.decodePublicKey(pk_packet.payload, allocator);
        defer decoded_pk.deinit(allocator);

        const enc_pw = try auth.encryptPassword(allocator, config.password, auth_data, &decoded_pk.value);
        defer allocator.free(enc_pw);

        try c.writeBytesAsPacket(enc_pw);
        try c.writer.flush();

        const resp_packet = try c.readPacket();
        return switch (resp_packet.payload[0]) {
            constants.OK => {},
            else => resp_packet.asError(),
        };
    }

    fn auth_caching_sha2_password(c: *Conn, allocator: std.mem.Allocator, auth_data: *const [20]u8, config: *const Config) !void {
        const auth_resp = auth.scrambleSHA256Password(auth_data, config.password);
        const response = HandshakeResponse41.init(.caching_sha2_password, config, &auth_resp);
        try c.writePacket(&response);
        try c.writer.flush();

        while (true) {
            const packet = try c.readPacket();
            switch (packet.payload[0]) {
                constants.OK => return,
                constants.AUTH_MORE_DATA => {
                    const more_data = packet.payload[1..];
                    switch (more_data[0]) {
                        auth.caching_sha2_password_fast_auth_success => {}, // success (do nothing, wait for next packet)
                        auth.caching_sha2_password_full_authentication_start => {
                            try c.writeBytesAsPacket(&[_]u8{auth.caching_sha2_password_public_key_request});
                            try c.writer.flush();
                            const pk_packet = try c.readPacket();

                            // Decode public key
                            const decoded_pk = try auth.decodePublicKey(pk_packet.payload, allocator);
                            defer decoded_pk.deinit(allocator);

                            // Encrypt password
                            const enc_pw = try auth.encryptPassword(allocator, config.password, auth_data, &decoded_pk.value);
                            defer allocator.free(enc_pw);

                            try c.writeBytesAsPacket(enc_pw);
                            try c.writer.flush();
                        },
                        else => return error.UnsupportedCachingSha2PasswordMoreData,
                    }
                },
                else => return packet.asError(),
            }
        }
    }

    pub inline fn readPacket(c: *Conn) !Packet {
        const packet = try c.reader.readPacket();
        c.sequence_id = packet.sequence_id +% 1;
        return packet;
    }

    inline fn writePacket(c: *Conn, packet: anytype) !void {
        try c.writer.writePacket(c.generateSequenceId(), packet);
    }

    inline fn writeBytesAsPacket(c: *Conn, packet: anytype) !void {
        try c.writer.writeBytesAsPacket(c.generateSequenceId(), packet);
    }

    inline fn generateSequenceId(c: *Conn) u8 {
        const sequence_id = c.sequence_id;
        c.sequence_id +%= 1;
        return sequence_id;
    }

    inline fn queryResult(c: *Conn, packet: *const Packet) !QueryResult {
        const res = QueryResult.init(packet, c.capabilities) catch |err| {
            switch (err) {
                error.UnrecoverableError => {
                    c.stream.close();
                    c.connected = false;
                },
            }
            return err;
        };
        return res;
    }

    inline fn ready(c: *Conn) void {
        std.debug.assert(c.connected);
        std.debug.assert(c.writer.pos == 0);
        c.sequence_id = 0;
    }
};
