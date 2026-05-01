// MySQL connection handler (trimmed to used code paths only).
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const builtin = @import("builtin");
const tls = @import("tls");

/// Heap-allocated container for the ianic/tls.zig handles.
/// The Connection, Reader, and Writer all store pointers at each other
/// (Reader/Writer use @fieldParentPtr on their .interface field), so they
/// must live at stable addresses for the lifetime of the TLS session.
const TlsHandles = struct {
    conn: tls.Connection,
    reader: tls.Connection.Reader,
    writer: tls.Connection.Writer,
};

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
    tls_handles: ?*TlsHandles = null,
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

        // Read auth response - may be OK, Error, or AuthSwitch.
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

        // Step 2: Allocate transport + cleartext buffers.
        // ianic/tls.zig requires the underlying Reader buffer to be >=
        // input_buffer_len (max ciphertext record = 16645 B) and the
        // underlying Writer buffer to be >= 2048 B. Using a single size
        // keeps things simple.
        const buf_len = tls.input_buffer_len;

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

        // Step 3: Allocate the TLS handles container at a stable address -
        // Reader and Writer use @fieldParentPtr on their .interface field, so
        // none of these values may be moved after init.
        const handles = try allocator.create(TlsHandles);
        errdefer allocator.destroy(handles);

        // Step 4: Seed a CSPRNG for the handshake. ianic wants a std.Random
        // instance; its examples use std.Random.IoSource which requires an
        // Io dispatch instance (juicy main). We don't plumb Io down today,
        // so we seed a ChaCha-based CSPRNG from our libc-free entropy source.
        var prng_seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        fillRandomBytes(&prng_seed);
        var prng = std.Random.DefaultCsprng.init(prng_seed);

        // Step 5: Perform TLS handshake.
        // MySQL 8.0 sends a TLS 1.3 CertificateRequest by default; ianic's
        // client responds with an empty Certificate message automatically
        // when no `auth` is supplied.
        handles.conn = tls.client(
            &socket_io.reader_iface,
            &socket_io.writer_iface,
            .{
                .rng = prng.random(),
                .now = realtimeTimestamp(),
                // We don't validate the server cert (insecure_skip_verify),
                // so `host` is only used as the SNI extension value. Config
                // resolves the hostname into sockaddr.in before reaching us
                // and doesn't retain the string. A literal placeholder keeps
                // the SNI well-formed (some servers reject empty SNI).
                .host = "mysql",
                .root_ca = .empty,
                .insecure_skip_verify = true,
            },
        ) catch |err| {
            std.log.err("TLS handshake failed: {}", .{err});
            return error.TlsHandshakeFailed;
        };

        // Step 6: Build the cleartext Reader/Writer over the Connection.
        handles.reader = handles.conn.reader(tls_app_read_buf);
        handles.writer = handles.conn.writer(tls_app_write_buf);

        // Step 7: Switch stream to use TLS (point at the Io.Reader/Writer
        // interfaces that ianic's Reader/Writer expose).
        conn.stream.tls_reader = &handles.reader.interface;
        conn.stream.tls_writer = &handles.writer.interface;
        conn.stream.tls_underlying_writer = &socket_io.writer_iface;

        // Step 8: Update reader/writer (they store stream by value)
        conn.reader.stream = conn.stream;
        conn.writer.stream = conn.stream;

        // Step 9: Store TLS resources for cleanup
        conn.socket_io = socket_io;
        conn.tls_handles = handles;
        conn.tls_read_buf = tls_read_buf;
        conn.tls_write_buf = tls_write_buf;
        conn.tls_app_read_buf = tls_app_read_buf;
        conn.tls_app_write_buf = tls_app_write_buf;

        std.log.info("TLS connection established", .{});
    }

    fn realtimeTimestamp() std.Io.Timestamp {
        if (comptime builtin.os.tag == .linux) {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(.REALTIME, &ts);
            return .{ .nanoseconds = @as(i96, ts.sec) * std.time.ns_per_s + ts.nsec };
        } else {
            // macOS/BSD: clock_gettime via posix.system (routes to libc)
            var ts: std.posix.system.timespec = undefined;
            if (std.posix.system.clock_gettime(.REALTIME, &ts) != 0) return .{ .nanoseconds = 0 };
            return .{ .nanoseconds = @as(i96, ts.sec) * std.time.ns_per_s + ts.nsec };
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
            // macOS/BSD: arc4random_buf via posix.system (routes to libc)
            std.posix.system.arc4random_buf(buf.ptr, buf.len);
        }
    }

    pub fn deinit(c: *Conn, allocator: std.mem.Allocator) void {
        c.quit() catch {};
        c.stream.close();
        c.reader.deinit();
        c.writer.deinit();
        c.result_meta.deinit(allocator);

        // Free TLS resources
        if (c.tls_handles) |th| allocator.destroy(th);
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

    /// A single row from a text protocol result set.
    /// Each element is either a column value (string) or null.
    pub const TextRow = struct {
        values: []?[]const u8,

        pub fn deinit(self: *TextRow, allocator: std.mem.Allocator) void {
            if (self.values.len > 0) {
                allocator.free(self.values);
            }
        }
    };

    /// Result of a query that returns rows (text protocol).
    pub const TextResultSet = struct {
        column_count: usize,
        rows: []TextRow,
        /// Arena that owns all the string data in rows
        arena: std.heap.ArenaAllocator,

        pub fn deinit(self: *TextResultSet) void {
            // The arena owns all row data and value slices
            self.arena.deinit();
        }
    };

    /// Execute a query and read the full text protocol result set.
    /// Returns rows with string values. Caller must call deinit() on the result.
    pub fn queryRows(c: *Conn, allocator: std.mem.Allocator, query_string: []const u8) !TextResultSet {
        c.ready();
        const query_req: QueryRequest = .{ .query = query_string };
        try c.writePacket(query_req);
        try c.writer.flush();

        // Read first packet - could be OK, ERR, or column count
        const first_packet = try c.readPacket();

        if (first_packet.payload.len == 0) return error.EmptyPacket;

        // Check for error
        if (first_packet.payload[0] == constants.ERR) {
            const err_pkt = ErrorPacket.init(&first_packet);
            std.log.err("query error: {s}", .{err_pkt.error_message});
            return error.QueryError;
        }

        // Check for OK (no result set)
        if (first_packet.payload[0] == constants.OK) {
            return error.NoResultSet;
        }

        // First byte is the column count (length-encoded integer)
        var reader = first_packet.reader();
        const column_count = reader.readLengthEncodedInteger();

        // Use an arena for all result data
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        // Read column definition packets
        for (0..column_count) |_| {
            _ = try c.readPacket(); // Skip column definitions, we don't need them
        }

        // Read EOF packet after column definitions (if not CLIENT_DEPRECATE_EOF)
        if (c.capabilities & constants.CLIENT_DEPRECATE_EOF == 0) {
            const eof_packet = try c.readPacket();
            if (eof_packet.payload.len > 0 and eof_packet.payload[0] != constants.EOF) {
                return error.ExpectedEof;
            }
        }

        // Read rows until EOF
        var rows: std.ArrayList(TextRow) = .empty;

        while (true) {
            const row_packet = try c.readPacket();

            if (row_packet.payload.len == 0) break;

            // Check for EOF
            if (row_packet.payload[0] == constants.EOF and row_packet.payload.len < 9) {
                break;
            }

            // Check for error
            if (row_packet.payload[0] == constants.ERR) {
                return error.QueryError;
            }

            // Parse text protocol row
            var row_reader = row_packet.reader();
            const values = try arena_alloc.alloc(?[]const u8, @intCast(column_count));

            for (0..@intCast(column_count)) |col_idx| {
                // Check for NULL (0xFB)
                if (row_reader.pos < row_reader.payload.len and row_reader.payload[row_reader.pos] == constants.TEXT_RESULT_ROW_NULL) {
                    row_reader.pos += 1;
                    values[col_idx] = null;
                } else {
                    const val = row_reader.readLengthEncodedString();
                    values[col_idx] = try arena_alloc.dupe(u8, val);
                }
            }

            try rows.append(arena_alloc, .{ .values = values });
        }

        return .{
            .column_count = @intCast(column_count),
            .rows = try rows.toOwnedSlice(arena_alloc),
            .arena = arena,
        };
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
