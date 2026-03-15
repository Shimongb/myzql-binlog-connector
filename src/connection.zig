//! MySQL Connection Management
//!
//! This module handles establishing and managing MySQL connections.
//! It wraps the MySQL protocol implementation in src/mysql/.

const std = @import("std");
const posix = std.posix;
const dns = @import("dns.zig");
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
        ssl: bool,
    ) !Connection {
        // Resolve host to IPv4 address (supports literal IPs, /etc/hosts, and DNS)
        const address = resolveHost(host, port) catch |err| {
            log.err("failed to resolve host '{s}': {}", .{ host, err });
            return error.HostNotFound;
        };

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
            .ssl = ssl,
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

/// Resolve a hostname or IP address to a sockaddr.in.
/// Supports literal IPv4 addresses, /etc/hosts lookups, and DNS resolution.
fn resolveHost(host: []const u8, port: u16) !posix.sockaddr.in {
    const octets = dns.resolveHostToIpv4(host) catch |err| {
        log.err("DNS resolution failed for '{s}': {}", .{ host, err });
        return error.HostNotFound;
    };
    log.info("resolved '{s}' -> {d}.{d}.{d}.{d}", .{ host, octets[0], octets[1], octets[2], octets[3] });
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(octets),
    };
}

test "resolveHost literal IP" {
    const addr = try resolveHost("127.0.0.1", 3306);
    const octets: [4]u8 = @bitCast(addr.addr);
    try std.testing.expectEqual(@as(u8, 127), octets[0]);
    try std.testing.expectEqual(@as(u8, 0), octets[1]);
    try std.testing.expectEqual(@as(u8, 0), octets[2]);
    try std.testing.expectEqual(@as(u8, 1), octets[3]);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 3306), addr.port);
}

test "resolveHost localhost" {
    const addr = resolveHost("localhost", 3306) catch return; // skip if no /etc/hosts
    const octets: [4]u8 = @bitCast(addr.addr);
    try std.testing.expectEqual(@as(u8, 127), octets[0]);
    try std.testing.expectEqual(@as(u8, 0), octets[1]);
    try std.testing.expectEqual(@as(u8, 0), octets[2]);
    try std.testing.expectEqual(@as(u8, 1), octets[3]);
}
