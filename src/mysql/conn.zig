// MySQL connection handler (trimmed to used code paths only).
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const builtin = @import("builtin");
const tls = std.crypto.tls;

const auth = @import("auth.zig");
const AuthPlugin = auth.AuthPlugin;
const Config = @import("config.zig").Config;
const compat = @import("compat.zig");
const constants = @import("constants.zig");
const SocketIo = @import("socket_io.zig").SocketIo;
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

    // TLS resources (heap-allocated, null when not using TLS)
    socket_io: ?*SocketIo = null,
    tls_client: ?*tls.Client = null,
    tls_read_buf: ?[]u8 = null,
    tls_write_buf: ?[]u8 = null,
    tls_app_read_buf: ?[]u8 = null,
    tls_app_write_buf: ?[]u8 = null,

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

        var auth_plugin: AuthPlugin = undefined;
        var auth_data: [20]u8 = undefined;
        {
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

            auth_plugin = handshake_v10.get_auth_plugin();
            auth_data = handshake_v10.get_auth_data();

            std.log.debug("capabilities: server=0x{x:0>8} client=0x{x:0>8} negotiated=0x{x:0>8}", .{
                handshake_v10.capability_flags(),
                config.capability_flags(),
                conn.capabilities,
            });
        }

        // TLS upgrade: after handshake, before auth
        if (config.ssl and (conn.capabilities & constants.CLIENT_SSL != 0)) {
            try conn.upgradeTLS(allocator, config);
        }

        // Send initial auth using the server's advertised plugin.
        std.log.info("using auth plugin: {any}", .{auth_plugin});
        try conn.sendAuth(auth_plugin, &auth_data, config);

        // Read auth response — may be OK, Error, or AuthSwitch.
        // std.log.err("TRACE: about to readPacket for auth response", .{});
        const packet = try conn.readPacket();
        // std.log.err("TRACE: auth response received, first_byte=0x{x:0>2} len={d}", .{ packet.payload[0], packet.payload.len });
        // std.log.debug("auth response: first_byte=0x{x:0>2} len={d} seq={d} raw={any}", .{
        //     packet.payload[0],
        //     packet.payload.len,
        //     packet.sequence_id,
        //     packet.payload[0..@min(packet.payload.len, 40)],
        // });
        switch (packet.payload[0]) {
            constants.OK => return conn,
            constants.ERR => return ErrorPacket.init(&packet).asError(),
            constants.AUTH_MORE_DATA => {
                // caching_sha2_password multi-round exchange after initial auth.
                const more_data = packet.payload[1..];
                switch (more_data[0]) {
                    auth.caching_sha2_password_fast_auth_success => {
                        // Fast auth succeeded – server will send OK next.
                        const ok_pkt = try conn.readPacket();
                        return switch (ok_pkt.payload[0]) {
                            constants.OK => conn,
                            constants.ERR => ErrorPacket.init(&ok_pkt).asError(),
                            else => ok_pkt.asError(),
                        };
                    },
                    auth.caching_sha2_password_full_authentication_start => {
                        // Full auth required.  Over TLS send cleartext password.
                        if (conn.stream.tls_reader != null) {
                            const pw = config.password;
                            var pw_buf: [256]u8 = undefined;
                            @memcpy(pw_buf[0..pw.len], pw);
                            pw_buf[pw.len] = 0;
                            try conn.writeBytesAsPacket(pw_buf[0 .. pw.len + 1]);
                            try conn.writer.flush();
                        } else {
                            return error.FullAuthRequiredWithoutTLS;
                        }
                        const ok_pkt = try conn.readPacket();
                        return switch (ok_pkt.payload[0]) {
                            constants.OK => conn,
                            constants.ERR => ErrorPacket.init(&ok_pkt).asError(),
                            else => ok_pkt.asError(),
                        };
                    },
                    else => return error.UnsupportedCachingSha2PasswordMoreData,
                }
            },
            constants.AUTH_SWITCH => {
                // Parse auth switch: 0xFE + plugin_name\0 + auth_data
                const rest = packet.payload[1..];
                const null_idx = std.mem.indexOfScalar(u8, rest, 0) orelse return error.UnexpectedPacket;
                const new_plugin_name = rest[0..null_idx];
                const new_plugin = AuthPlugin.fromName(new_plugin_name);
                std.log.info("auth switch to: {s}", .{new_plugin_name});

                // New auth data follows the null terminator (20 bytes for most plugins).
                const new_auth_data_raw = rest[null_idx + 1 ..];
                if (new_auth_data_raw.len >= 20) {
                    @memcpy(&auth_data, new_auth_data_raw[0..20]);
                } else if (new_auth_data_raw.len > 0) {
                    @memset(&auth_data, 0);
                    @memcpy(auth_data[0..new_auth_data_raw.len], new_auth_data_raw);
                }

                // Respond to auth switch
                try conn.handleAuthSwitch(allocator, new_plugin, &auth_data, config);
                return conn;
            },
            else => return packet.asError(),
        }
    }

    /// Send the initial HandshakeResponse41 with auth data for the given plugin.
    fn sendAuth(c: *Conn, plugin: AuthPlugin, auth_data: *const [20]u8, config: *const Config) !void {
        // Compute auth response based on plugin type
        var native_resp: [20]u8 = undefined;
        var sha256_resp: [32]u8 = undefined;
        const auth_resp_data: []const u8 = switch (plugin) {
            .mysql_native_password => blk: {
                if (config.password.len == 0) break :blk &[_]u8{};
                native_resp = auth.scramblePassword(auth_data, config.password);
                break :blk &native_resp;
            },
            .caching_sha2_password => blk: {
                if (config.password.len == 0) break :blk &[_]u8{};
                sha256_resp = auth.scrambleSHA256Password(auth_data, config.password);
                break :blk &sha256_resp;
            },
            .sha256_password => &[_]u8{auth.sha256_password_public_key_request},
            else => return error.UnsupportedAuthPlugin,
        };

        // Get plugin name as null-terminated string
        const plugin_name: [:0]const u8 = switch (plugin) {
            .mysql_native_password => "mysql_native_password",
            .caching_sha2_password => "caching_sha2_password",
            .sha256_password => "sha256_password",
            else => return error.UnsupportedAuthPlugin,
        };

        const response: HandshakeResponse41 = .{
            .database = config.database,
            .client_flag = c.capabilities,
            .character_set = config.collation,
            .username = config.username,
            .auth_response = auth_resp_data,
            .client_plugin_name = plugin_name,
        };
        try c.writePacket(response);
        try c.writer.flush();
    }

    /// Handle auth switch: re-authenticate with the new plugin, then read OK/Error.
    fn handleAuthSwitch(c: *Conn, allocator: std.mem.Allocator, plugin: AuthPlugin, auth_data: *const [20]u8, config: *const Config) !void {
        switch (plugin) {
            .mysql_native_password => {
                const resp = if (config.password.len > 0) &auth.scramblePassword(auth_data, config.password) else &[_]u8{};
                try c.writeBytesAsPacket(resp);
                try c.writer.flush();
                const pkt = try c.readPacket();
                return switch (pkt.payload[0]) {
                    constants.OK => {},
                    constants.ERR => ErrorPacket.init(&pkt).asError(),
                    else => pkt.asError(),
                };
            },
            .caching_sha2_password => {
                // Send scrambled password
                const resp = if (config.password.len > 0) &auth.scrambleSHA256Password(auth_data, config.password) else &[_]u8{};
                try c.writeBytesAsPacket(resp);
                try c.writer.flush();

                // Process caching_sha2 multi-round exchange
                while (true) {
                    const pkt = try c.readPacket();
                    switch (pkt.payload[0]) {
                        constants.OK => return,
                        constants.ERR => return ErrorPacket.init(&pkt).asError(),
                        constants.AUTH_MORE_DATA => {
                            const more_data = pkt.payload[1..];
                            switch (more_data[0]) {
                                auth.caching_sha2_password_fast_auth_success => {},
                                auth.caching_sha2_password_full_authentication_start => {
                                    // Over TLS we can send the password in cleartext.
                                    // Append a null terminator as MySQL expects.
                                    const pw = config.password;
                                    var pw_buf: [256]u8 = undefined;
                                    if (pw.len < pw_buf.len) {
                                        @memcpy(pw_buf[0..pw.len], pw);
                                        pw_buf[pw.len] = 0;
                                        try c.writeBytesAsPacket(pw_buf[0 .. pw.len + 1]);
                                        try c.writer.flush();
                                    } else {
                                        // Fallback: request public key and encrypt
                                        try c.writeBytesAsPacket(&[_]u8{auth.caching_sha2_password_public_key_request});
                                        try c.writer.flush();
                                        const pk_pkt = try c.readPacket();
                                        const decoded_pk = try auth.decodePublicKey(pk_pkt.payload, allocator);
                                        defer decoded_pk.deinit(allocator);
                                        const enc_pw = try auth.encryptPassword(allocator, config.password, auth_data, &decoded_pk.value);
                                        defer allocator.free(enc_pw);
                                        try c.writeBytesAsPacket(enc_pw);
                                        try c.writer.flush();
                                    }
                                },
                                else => return error.UnsupportedCachingSha2PasswordMoreData,
                            }
                        },
                        else => return pkt.asError(),
                    }
                }
            },
            .sha256_password => {
                try c.writeBytesAsPacket(&[_]u8{auth.sha256_password_public_key_request});
                try c.writer.flush();
                const pk_pkt = try c.readPacket();
                const decoded_pk = try auth.decodePublicKey(pk_pkt.payload, allocator);
                defer decoded_pk.deinit(allocator);
                const enc_pw = try auth.encryptPassword(allocator, config.password, auth_data, &decoded_pk.value);
                defer allocator.free(enc_pw);
                try c.writeBytesAsPacket(enc_pw);
                try c.writer.flush();
                const pkt = try c.readPacket();
                return switch (pkt.payload[0]) {
                    constants.OK => {},
                    constants.ERR => ErrorPacket.init(&pkt).asError(),
                    else => pkt.asError(),
                };
            },
            else => {
                std.log.err("unsupported auth switch plugin: {any}", .{plugin});
                return error.UnsupportedAuthPlugin;
            },
        }
    }

    /// Send SSL Request packet, perform TLS handshake using Zig std.crypto.tls,
    /// and switch stream to TLS.
    fn upgradeTLS(conn: *Conn, allocator: std.mem.Allocator, config: *const Config) !void {
        // Step 1: Send SSL Request packet (capabilities + max_packet_size + charset + 23 fillers)
        // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html
        // Must use negotiated capabilities (same as HandshakeResponse41) per MySQL protocol spec.
        var ssl_request: [32]u8 = undefined;
        const cap_flags = conn.capabilities;
        std.mem.writeInt(u32, ssl_request[0..4], cap_flags, .little);
        std.mem.writeInt(u32, ssl_request[4..8], 1 << 24, .little); // max_packet_size (16 MiB)
        ssl_request[8] = config.collation; // character_set
        @memset(ssl_request[9..32], 0); // 23 bytes filler
        try conn.writeBytesAsPacket(&ssl_request);
        try conn.writer.flush();

        // Step 2: Allocate TLS resources
        const buf_len = tls.Client.min_buffer_len;

        const socket_io = try allocator.create(SocketIo);
        errdefer allocator.destroy(socket_io);

        const tls_read_buf = try allocator.alloc(u8, buf_len);
        errdefer allocator.free(tls_read_buf);

        const tls_write_buf = try allocator.alloc(u8, buf_len);
        errdefer allocator.free(tls_write_buf);

        const tls_app_read_buf = try allocator.alloc(u8, buf_len);
        errdefer allocator.free(tls_app_read_buf);

        const tls_app_write_buf = try allocator.alloc(u8, buf_len);
        errdefer allocator.free(tls_app_write_buf);

        // Initialize the socket I/O bridge (raw fd -> Io.Reader/Writer vtables)
        socket_io.init(conn.stream.handle, tls_read_buf, tls_write_buf);

        // Step 3: Generate entropy
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        fillRandomBytes(&entropy);

        // Step 4: Perform TLS handshake
        var tls_alert: tls.Alert = undefined;
        const tls_client_val = tls.Client.init(
            &socket_io.reader_iface,
            &socket_io.writer_iface,
            .{
                .host = .no_verification,
                .ca = .no_verification,
                .read_buffer = tls_app_read_buf,
                .write_buffer = tls_app_write_buf,
                .entropy = &entropy,
                .realtime_now_seconds = realtimeSeconds(),
                .allow_truncation_attacks = true,
                .alert = &tls_alert,
            },
        ) catch |err| {
            std.log.err("TLS handshake failed: {} alert={any}", .{ err, tls_alert });
            return error.TlsHandshakeFailed;
        };

        // Step 5: Heap-allocate the TLS Client (must not move — uses @fieldParentPtr internally)
        const tls_client = try allocator.create(tls.Client);
        errdefer allocator.destroy(tls_client);
        tls_client.* = tls_client_val;

        // Step 6: Switch stream to use TLS
        conn.stream.tls_reader = &tls_client.reader;
        conn.stream.tls_writer = &tls_client.writer;
        conn.stream.tls_underlying_writer = &socket_io.writer_iface;

        // Step 7: Update reader/writer (they store stream by value)
        conn.reader.stream = conn.stream;
        conn.writer.stream = conn.stream;

        // Step 8: Store TLS resources for cleanup
        conn.socket_io = socket_io;
        conn.tls_client = tls_client;
        conn.tls_read_buf = tls_read_buf;
        conn.tls_write_buf = tls_write_buf;
        conn.tls_app_read_buf = tls_app_read_buf;
        conn.tls_app_write_buf = tls_app_write_buf;

        std.log.info("TLS connection established", .{});
    }

    fn realtimeSeconds() i64 {
        if (comptime builtin.os.tag == .linux) {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(.REALTIME, &ts);
            return ts.sec;
        } else {
            // macOS / BSD
            var tv: std.c.timeval = undefined;
            _ = std.c.gettimeofday(&tv, null);
            return tv.sec;
        }
    }

    fn fillRandomBytes(buf: []u8) void {
        if (comptime builtin.os.tag == .linux) {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(buf[filled..].ptr, buf.len - filled, 0);
                const errno = std.posix.errno(rc);
                if (errno == .SUCCESS) {
                    filled += rc;
                } else if (errno == .INTR) {
                    continue;
                } else {
                    @panic("getrandom failed");
                }
            }
        } else {
            std.c.arc4random_buf(buf.ptr, buf.len);
        }
    }

    pub fn deinit(c: *Conn, allocator: std.mem.Allocator) void {
        c.quit() catch {};
        c.stream.close();
        c.reader.deinit();
        c.writer.deinit();
        c.result_meta.deinit(allocator);

        // Free TLS resources
        if (c.tls_client) |tc| allocator.destroy(tc);
        if (c.socket_io) |sio| allocator.destroy(sio);
        if (c.tls_read_buf) |buf| allocator.free(buf);
        if (c.tls_write_buf) |buf| allocator.free(buf);
        if (c.tls_app_read_buf) |buf| allocator.free(buf);
        if (c.tls_app_write_buf) |buf| allocator.free(buf);
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
