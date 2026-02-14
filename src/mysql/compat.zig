/// Compatibility layer for Zig 0.15 -> 0.16 migration.
/// Replaces removed std.net types (Stream, Address, tcpConnectToAddress, etc.)
/// using raw POSIX system calls.
///
/// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const posix = std.posix;
const Io = std.Io;

pub const Stream = struct {
    handle: posix.fd_t,

    // When non-null, read/write go through TLS.
    tls_reader: ?*Io.Reader = null,
    tls_writer: ?*Io.Writer = null,

    // The underlying transport writer that the TLS layer writes encrypted
    // records into.  After flushing the TLS writer we must also flush this
    // so ciphertext actually reaches the socket.
    tls_underlying_writer: ?*Io.Writer = null,

    pub fn close(s: Stream) void {
        posix.close(s.handle);
    }

    pub fn read(s: *Stream, buffer: []u8) ReadError!usize {
        if (s.tls_reader) |r| {
            // First check if the TLS reader already has buffered decrypted data.
            const buffered = r.buffer[r.seek..r.end];
            if (buffered.len > 0) {
                const n = @min(buffered.len, buffer.len);
                @memcpy(buffer[0..n], buffered[0..n]);
                r.seek += n;
                return n;
            }
            // No buffered data – read exactly 1 byte (blocks until the TLS
            // layer has decrypted at least one application-data record, which
            // may involve silently consuming handshake records like
            // new_session_ticket first).
            _ = r.readSliceShort(buffer[0..1]) catch |err| {
                std.log.err("TLS read error: {} (buffer.len={d})", .{ err, buffer.len });
                return error.ConnectionResetByPeer;
            };
            // Now drain whatever else the TLS layer buffered in that same
            // decryption pass, so the caller gets a full short-read.
            const extra_avail = r.buffer[r.seek..r.end];
            const extra = @min(extra_avail.len, buffer.len - 1);
            @memcpy(buffer[1 .. 1 + extra], extra_avail[0..extra]);
            r.seek += extra;
            return 1 + extra;
        }
        return posix.read(s.handle, buffer);
    }

    pub fn readAtLeast(s: *Stream, buffer: []u8, len: usize) ReadError!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub fn writeAll(s: *Stream, bytes: []const u8) WriteError!void {
        if (s.tls_writer) |w| {
            std.log.debug("stream.writeAll: TLS {d}B, has_uw={}", .{ bytes.len, s.tls_underlying_writer != null });
            w.writeAll(bytes) catch return error.BrokenPipe;
            w.flush() catch return error.BrokenPipe;
            // The TLS flush only pushes ciphertext into the underlying
            // Io.Writer buffer.  We must drain that buffer to the socket.
            if (s.tls_underlying_writer) |uw| {
                std.log.debug("stream.writeAll: flushing underlying writer", .{});
                uw.flush() catch return error.BrokenPipe;
                std.log.debug("stream.writeAll: underlying flush done", .{});
            }
            return;
        }
        var index: usize = 0;
        while (index < bytes.len) {
            const remaining = bytes[index..];
            const rc = posix.system.write(s.handle, remaining.ptr, remaining.len);
            const errno = posix.errno(rc);
            if (errno != .SUCCESS) {
                return switch (errno) {
                    .INTR => continue,
                    .AGAIN => continue,
                    .PIPE => error.BrokenPipe,
                    .CONNRESET => error.ConnectionResetByPeer,
                    .BADF => error.NotOpenForWriting,
                    .IO => error.InputOutput,
                    .NOSPC => error.NoSpaceLeft,
                    else => std.posix.unexpectedErrno(errno),
                };
            }
            const written: usize = @intCast(rc);
            if (written == 0) return error.Unexpected;
            index += written;
        }
    }

    pub const ReadError = posix.ReadError;
    pub const WriteError = error{
        BrokenPipe,
        ConnectionResetByPeer,
        NotOpenForWriting,
        InputOutput,
        NoSpaceLeft,
        Unexpected,
    } || posix.UnexpectedError;
};

pub fn tcpConnectToAddress(address: posix.sockaddr.in) !Stream {
    // Create socket
    const sock_fd = posix.system.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    const errno = posix.errno(sock_fd);
    if (errno != .SUCCESS) {
        return posix.unexpectedErrno(errno);
    }
    const fd: posix.fd_t = @intCast(sock_fd);
    errdefer posix.close(fd);

    // Set TCP_NODELAY to disable Nagle's algorithm
    const one: c_int = 1;
    _ = posix.system.setsockopt(fd, posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));

    // Connect
    const addr_ptr: *const posix.sockaddr = @ptrCast(&address);
    try posix.connect(fd, addr_ptr, @sizeOf(posix.sockaddr.in));

    return .{ .handle = fd };
}
