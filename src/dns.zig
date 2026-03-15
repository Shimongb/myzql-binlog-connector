// Minimal DNS A-record resolver for hostname -> IPv4 resolution.
// Protocol logic adapted from zigdig (MIT License).
// Zero external dependencies; uses raw POSIX/Linux syscalls.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const log = std.log.scoped(.dns);

pub const ResolveError = error{
    HostNotFound,
    DnsServerError,
    InvalidResponse,
    OutOfMemory,
    NetworkError,
};

/// Resolve a hostname to an IPv4 address (4-byte array).
/// Tries in order: literal IPv4, /etc/hosts, DNS query.
pub fn resolveHostToIpv4(host: []const u8) ResolveError![4]u8 {
    // 1. Try parsing as literal IPv4
    if (parseIpv4(host)) |octets| return octets;

    // 2. Check /etc/hosts
    if (lookupInHosts(host)) |octets| return octets;

    // 3. DNS query
    return dnsLookupA(host);
}

/// Parse a dotted-decimal IPv4 string into 4 bytes.
fn parseIpv4(host: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current: u16 = 0;
    var has_digit: bool = false;

    for (host) |c| {
        if (c >= '0' and c <= '9') {
            current = current * 10 + @as(u16, c - '0');
            if (current > 255) return null;
            has_digit = true;
        } else if (c == '.') {
            if (!has_digit or octet_idx >= 3) return null;
            octets[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
            has_digit = false;
        } else {
            return null;
        }
    }
    if (!has_digit or octet_idx != 3) return null;
    octets[3] = @intCast(current);
    return octets;
}

/// Search /etc/hosts for a hostname -> IPv4 mapping.
fn lookupInHosts(hostname: []const u8) ?[4]u8 {
    const fd = openFileRaw("/etc/hosts") orelse return null;
    defer closeRaw(fd);

    var buf: [4096]u8 = undefined;
    var line_buf: [512]u8 = undefined;
    var line_len: usize = 0;
    var buf_pos: usize = 0;
    var buf_end: usize = 0;

    while (true) {
        // Fill buffer if needed
        if (buf_pos >= buf_end) {
            buf_end = readRaw(fd, &buf) orelse return null;
            if (buf_end == 0) break;
            buf_pos = 0;
        }

        // Read one line
        line_len = 0;
        while (buf_pos < buf_end) {
            const c = buf[buf_pos];
            buf_pos += 1;
            if (c == '\n') break;
            if (line_len < line_buf.len) {
                line_buf[line_len] = c;
                line_len += 1;
            }
        } else {
            // Buffer exhausted mid-line, refill
            buf_end = readRaw(fd, &buf) orelse break;
            if (buf_end == 0) break;
            buf_pos = 0;
            // Continue reading the line
            while (buf_pos < buf_end) {
                const c = buf[buf_pos];
                buf_pos += 1;
                if (c == '\n') break;
                if (line_len < line_buf.len) {
                    line_buf[line_len] = c;
                    line_len += 1;
                }
            }
        }

        const line = line_buf[0..line_len];

        // Strip comments
        var effective_len: usize = 0;
        for (line) |c| {
            if (c == '#') break;
            effective_len += 1;
        }
        const effective = line[0..effective_len];

        // Parse: <ip> <name1> [name2] ...
        var it = std.mem.tokenizeAny(u8, effective, " \t");
        const ip_text = it.next() orelse continue;

        while (it.next()) |name| {
            if (std.mem.eql(u8, name, hostname)) {
                if (parseIpv4(ip_text)) |octets| return octets;
            }
        }
    }

    return null;
}

/// Perform a DNS A record query for the given hostname.
fn dnsLookupA(hostname: []const u8) ResolveError![4]u8 {
    // Find nameserver from /etc/resolv.conf
    var ns_buf: [64]u8 = undefined;
    const nameserver = findNameserver(&ns_buf) orelse {
        log.err("no nameserver found in /etc/resolv.conf", .{});
        return error.DnsServerError;
    };

    // Parse nameserver IP
    const ns_octets = parseIpv4(nameserver) orelse {
        log.err("invalid nameserver IP: {s}", .{nameserver});
        return error.DnsServerError;
    };

    // Build query packet
    var pkt_buf: [512]u8 = undefined;
    const query_len = buildAQuery(hostname, &pkt_buf) catch {
        log.err("hostname too long for DNS query: {s}", .{hostname});
        return error.HostNotFound;
    };

    // Send UDP query and receive response
    var resp_buf: [512]u8 = undefined;
    const resp_len = udpExchange(ns_octets, 53, pkt_buf[0..query_len], &resp_buf) catch {
        log.err("DNS query failed for: {s}", .{hostname});
        return error.NetworkError;
    };

    // Parse response for A record
    return parseAResponse(resp_buf[0..resp_len], pkt_buf[0..2]) catch {
        log.err("no A record found for: {s}", .{hostname});
        return error.HostNotFound;
    };
}

/// Read the first nameserver from /etc/resolv.conf.
fn findNameserver(out: []u8) ?[]const u8 {
    const fd = openFileRaw("/etc/resolv.conf") orelse return null;
    defer closeRaw(fd);

    var buf: [2048]u8 = undefined;
    var line_buf: [256]u8 = undefined;
    var line_len: usize = 0;
    var buf_pos: usize = 0;
    var buf_end: usize = 0;

    while (true) {
        if (buf_pos >= buf_end) {
            buf_end = readRaw(fd, &buf) orelse return null;
            if (buf_end == 0) return null;
            buf_pos = 0;
        }

        line_len = 0;
        while (buf_pos < buf_end) {
            const c = buf[buf_pos];
            buf_pos += 1;
            if (c == '\n') break;
            if (line_len < line_buf.len) {
                line_buf[line_len] = c;
                line_len += 1;
            }
        }

        const line = line_buf[0..line_len];
        if (std.mem.startsWith(u8, line, "#")) continue;

        var it = std.mem.tokenizeAny(u8, line, " \t");
        const keyword = it.next() orelse continue;
        if (std.mem.eql(u8, keyword, "nameserver")) {
            const addr = it.next() orelse continue;
            if (addr.len > out.len) continue;
            @memcpy(out[0..addr.len], addr);
            return out[0..addr.len];
        }
    }
}

/// Build a DNS A record query packet. Returns the packet length.
fn buildAQuery(hostname: []const u8, buf: []u8) !usize {
    if (hostname.len > 253) return error.Overflow;
    var pos: usize = 0;

    // Header (12 bytes)
    // Transaction ID - use first 2 bytes of a simple counter/timestamp
    const id = getQueryId();
    buf[pos] = @intCast(id >> 8);
    buf[pos + 1] = @intCast(id & 0xFF);
    pos += 2;
    // Flags: standard query, recursion desired
    buf[pos] = 0x01; // RD=1
    buf[pos + 1] = 0x00;
    pos += 2;
    // QDCOUNT=1
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;
    // ANCOUNT=0
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2;
    // NSCOUNT=0
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2;
    // ARCOUNT=0
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2;

    // Question section: encode hostname as DNS labels
    var it = std.mem.splitSequence(u8, hostname, ".");
    while (it.next()) |label| {
        if (label.len == 0) continue; // trailing dot
        if (label.len > 63) return error.Overflow;
        if (pos + 1 + label.len >= buf.len) return error.Overflow;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }
    // Null terminator for name
    buf[pos] = 0x00;
    pos += 1;

    // QTYPE = A (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;
    // QCLASS = IN (1)
    buf[pos] = 0x00;
    buf[pos + 1] = 0x01;
    pos += 2;

    return pos;
}

/// Parse a DNS response and extract the first A record.
fn parseAResponse(resp: []const u8, query_id: []const u8) ![4]u8 {
    if (resp.len < 12) return error.InvalidResponse;

    // Verify transaction ID
    if (resp[0] != query_id[0] or resp[1] != query_id[1])
        return error.InvalidResponse;

    // Check QR bit (response flag)
    if (resp[2] & 0x80 == 0) return error.InvalidResponse;

    // Check RCODE
    const rcode = resp[3] & 0x0F;
    if (rcode != 0) return error.HostNotFound;

    // Answer count
    const ancount = (@as(u16, resp[6]) << 8) | @as(u16, resp[7]);
    if (ancount == 0) return error.HostNotFound;

    // Skip question section
    var pos: usize = 12;
    const qdcount = (@as(u16, resp[4]) << 8) | @as(u16, resp[5]);
    var i: u16 = 0;
    while (i < qdcount) : (i += 1) {
        pos = skipName(resp, pos) orelse return error.InvalidResponse;
        pos += 4; // QTYPE + QCLASS
        if (pos > resp.len) return error.InvalidResponse;
    }

    // Parse answer section
    i = 0;
    while (i < ancount) : (i += 1) {
        pos = skipName(resp, pos) orelse return error.InvalidResponse;
        if (pos + 10 > resp.len) return error.InvalidResponse;

        const rtype = (@as(u16, resp[pos]) << 8) | @as(u16, resp[pos + 1]);
        pos += 2;
        // class
        pos += 2;
        // TTL
        pos += 4;
        const rdlength = (@as(u16, resp[pos]) << 8) | @as(u16, resp[pos + 1]);
        pos += 2;

        if (rtype == 1 and rdlength == 4) {
            // A record
            if (pos + 4 > resp.len) return error.InvalidResponse;
            return .{ resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3] };
        }

        // Skip RDATA for non-A records (including CNAME etc.)
        pos += rdlength;
        if (pos > resp.len) return error.InvalidResponse;
    }

    return error.HostNotFound;
}

/// Skip a DNS name in a packet (handles both labels and compression pointers).
fn skipName(pkt: []const u8, start: usize) ?usize {
    var pos = start;
    while (pos < pkt.len) {
        const len_or_ptr = pkt[pos];
        if (len_or_ptr == 0) {
            // Null terminator
            return pos + 1;
        } else if (len_or_ptr & 0xC0 == 0xC0) {
            // Compression pointer (2 bytes)
            return pos + 2;
        } else {
            // Label
            pos += 1 + @as(usize, len_or_ptr);
        }
    }
    return null;
}

/// Generate a simple query ID from timestamp.
fn getQueryId() u16 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @truncate(@as(u64, @bitCast(ts.nsec)));
    } else {
        var ts: posix.system.timespec = undefined;
        _ = posix.system.clock_gettime(.REALTIME, &ts);
        return @truncate(@as(u64, @bitCast(ts.nsec)));
    }
}

// === Platform-agnostic raw I/O ===

fn openFileRaw(path: [*:0]const u8) ?posix.fd_t {
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.openat(
            @bitCast(@as(i32, -100)), // AT_FDCWD
            path,
            .{},
            0,
        );
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    } else {
        const rc = posix.system.openat(
            posix.AT.FDCWD,
            path,
            .{},
            @as(posix.mode_t, 0),
        );
        if (posix.errno(rc) != .SUCCESS) return null;
        return @intCast(rc);
    }
}

fn closeRaw(fd: posix.fd_t) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = posix.system.close(fd);
    }
}

fn readRaw(fd: posix.fd_t, buf: []u8) ?usize {
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.read(fd, buf.ptr, buf.len);
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return rc;
    } else {
        return posix.read(fd, buf) catch null;
    }
}

/// Send a UDP datagram and receive the response.
fn udpExchange(server_ip: [4]u8, port: u16, query: []const u8, resp_buf: []u8) !usize {
    // Create UDP socket
    const sock_fd = blk: {
        if (comptime builtin.os.tag == .linux) {
            const rc = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.DGRAM, std.os.linux.IPPROTO.UDP);
            if (std.os.linux.errno(rc) != .SUCCESS) return error.NetworkError;
            break :blk @as(posix.fd_t, @intCast(rc));
        } else {
            const rc = posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
            if (posix.errno(rc) != .SUCCESS) return error.NetworkError;
            break :blk @as(posix.fd_t, @intCast(rc));
        }
    };
    defer closeRaw(sock_fd);

    // Set receive timeout (5 seconds)
    setSocketTimeout(sock_fd);

    // Build destination address
    var dest_addr: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(server_ip),
    };

    // Send query
    const addr_ptr: *const posix.sockaddr = @ptrCast(&dest_addr);
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.sendto(
            sock_fd,
            query.ptr,
            query.len,
            0,
            @ptrCast(addr_ptr),
            @sizeOf(posix.sockaddr.in),
        );
        if (std.os.linux.errno(rc) != .SUCCESS) return error.NetworkError;
    } else {
        const rc = posix.system.sendto(
            sock_fd,
            query.ptr,
            query.len,
            0,
            addr_ptr,
            @sizeOf(posix.sockaddr.in),
        );
        if (posix.errno(rc) != .SUCCESS) return error.NetworkError;
    }

    // Receive response
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.recvfrom(
            sock_fd,
            resp_buf.ptr,
            resp_buf.len,
            0,
            null,
            null,
        );
        if (std.os.linux.errno(rc) != .SUCCESS) return error.NetworkError;
        return rc;
    } else {
        const rc = posix.system.recvfrom(
            sock_fd,
            resp_buf.ptr,
            resp_buf.len,
            0,
            null,
            null,
        );
        if (posix.errno(rc) != .SUCCESS) return error.NetworkError;
        return @intCast(rc);
    }
}

fn setSocketTimeout(fd: posix.fd_t) void {
    if (comptime builtin.os.tag == .linux) {
        const tv = std.os.linux.timeval{ .sec = 5, .usec = 0 };
        _ = std.os.linux.setsockopt(
            fd,
            std.os.linux.SOL.SOCKET,
            std.os.linux.SO.RCVTIMEO,
            std.mem.asBytes(&tv),
            @sizeOf(@TypeOf(tv)),
        );
    } else {
        const tv = posix.system.timeval{ .sec = 5, .usec = 0 };
        _ = posix.system.setsockopt(
            fd,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            std.mem.asBytes(&tv),
            @sizeOf(@TypeOf(tv)),
        );
    }
}

// === Tests ===

test "parseIpv4 valid" {
    const result = parseIpv4("127.0.0.1").?;
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, result);
}

test "parseIpv4 invalid" {
    try std.testing.expect(parseIpv4("not.an.ip.addr") == null);
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("") == null);
    try std.testing.expect(parseIpv4("example.com") == null);
}

test "buildAQuery" {
    var buf: [512]u8 = undefined;
    const len = try buildAQuery("example.com", &buf);

    // Header is 12 bytes + question
    try std.testing.expect(len > 12);

    // Check flags: RD=1
    try std.testing.expectEqual(@as(u8, 0x01), buf[2]);
    // QDCOUNT=1
    try std.testing.expectEqual(@as(u8, 0x01), buf[5]);

    // First label: "example" (7 bytes)
    try std.testing.expectEqual(@as(u8, 7), buf[12]);
    try std.testing.expectEqualStrings("example", buf[13..20]);
    // Second label: "com" (3 bytes)
    try std.testing.expectEqual(@as(u8, 3), buf[20]);
    try std.testing.expectEqualStrings("com", buf[21..24]);
    // Null terminator
    try std.testing.expectEqual(@as(u8, 0), buf[24]);
    // QTYPE=A
    try std.testing.expectEqual(@as(u8, 0x01), buf[26]);
    // QCLASS=IN
    try std.testing.expectEqual(@as(u8, 0x01), buf[28]);
}

test "parseAResponse valid" {
    // Minimal DNS response with one A record for 1.2.3.4
    const resp = [_]u8{
        0xAB, 0xCD, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x01, // ANCOUNT=1
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
        // Question: example.com A IN
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00, // null terminator
        0x00, 0x01, // QTYPE=A
        0x00, 0x01, // QCLASS=IN
        // Answer: pointer to name, A record, 1.2.3.4
        0xC0, 0x0C, // Name pointer to offset 12
        0x00, 0x01, // TYPE=A
        0x00, 0x01, // CLASS=IN
        0x00, 0x00, 0x01, 0x00, // TTL=256
        0x00, 0x04, // RDLENGTH=4
        0x01, 0x02, 0x03, 0x04, // RDATA=1.2.3.4
    };
    const query_id = [_]u8{ 0xAB, 0xCD };
    const result = try parseAResponse(&resp, &query_id);
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, result);
}

test "skipName label" {
    const pkt = [_]u8{ 0x03, 'f', 'o', 'o', 0x00 };
    try std.testing.expectEqual(@as(?usize, 5), skipName(&pkt, 0));
}

test "skipName pointer" {
    const pkt = [_]u8{ 0xC0, 0x0C };
    try std.testing.expectEqual(@as(?usize, 2), skipName(&pkt, 0));
}

test "lookupInHosts localhost" {
    // /etc/hosts should have localhost -> 127.0.0.1 on any Unix system
    const result = lookupInHosts("localhost");
    if (result) |octets| {
        try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, octets);
    }
    // If /etc/hosts doesn't have it, that's OK for the test
}

test "resolveHostToIpv4 literal IP" {
    const result = try resolveHostToIpv4("10.0.0.1");
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result);
}
