//! MySQL Connection Management
//!
//! This module handles establishing and managing MySQL connections.
//! It wraps the MySQL protocol implementation in src/mysql/.

const std = @import("std");
const mysql = struct {
    const conn = @import("mysql/conn.zig");
    const config = @import("mysql/config.zig");
};

const log = std.log.scoped(.connection);

/// MySQL Connection Manager
pub const Connection = struct {
    conn: mysql.conn.Conn,
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,

    /// Connect to MySQL server
    pub fn connect(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        user: ?[]const u8,
        password: ?[]const u8,
        database: ?[]const u8,
    ) !Connection {
        // Resolve IP address via getaddrinfo
        const host_z = try allocator.dupeZ(u8, host);
        defer allocator.free(host_z);

        var port_buf: [6]u8 = undefined;
        const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;
        const port_z = try allocator.dupeZ(u8, port_str);
        defer allocator.free(port_z);

        var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
        hints.socktype = std.posix.SOCK.STREAM;

        var ai_result: ?*std.c.addrinfo = null;
        const rc = std.c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &ai_result);
        if (@intFromEnum(rc) != 0 or ai_result == null) return error.HostNotFound;
        defer std.c.freeaddrinfo(ai_result.?);

        const ai = ai_result.?;

        // Build sockaddr.in from resolved address
        const address: std.posix.sockaddr.in = @bitCast(@as(
            [@sizeOf(std.posix.sockaddr.in)]u8,
            @as(*const [@sizeOf(std.posix.sockaddr.in)]u8, @ptrCast(ai.addr.?)).*,
        ));

        // Create null-terminated strings for myzql
        const user_z = try allocator.dupeZ(u8, user orelse "root");
        defer allocator.free(user_z);
        const pass_z = try allocator.dupeZ(u8, password orelse "");
        defer allocator.free(pass_z);
        const db_z = try allocator.dupeZ(u8, database orelse "");
        defer allocator.free(db_z);

        const conn = try mysql.conn.Conn.init(allocator, &.{
            .address = address,
            .username = user_z,
            .password = pass_z,
            .database = db_z,
        });

        return Connection{
            .conn = conn,
            .allocator = allocator,
            .host = host,
            .port = port,
        };
    }

    /// Close connection and cleanup resources
    pub fn disconnect(self: *Connection) void {
        self.conn.deinit(self.allocator);
    }

    /// Test if connection is alive
    pub fn ping(self: *Connection) !void {
        return self.conn.ping();
    }

    /// Get MySQL server version string
    /// Note: myzql might not expose this directly in the same way,
    /// returning a placeholder or querying it if needed.
    pub fn getServerVersion(self: *Connection) []const u8 {
        _ = self;
        return "Unknown";
    }

    /// Get client library version string
    pub fn getClientVersion() []const u8 {
        return "native";
    }

    /// Execute a SQL query (no result set expected)
    pub fn executeQuery(self: *Connection, sql: []const u8) !void {
        _ = try self.conn.query(sql);
    }

    /// Get last error information
    pub fn getLastError(self: *Connection) struct { code: c_uint, message: []const u8 } {
        _ = self;
        return .{
            .code = 0,
            .message = "Check return values for errors",
        };
    }
};
