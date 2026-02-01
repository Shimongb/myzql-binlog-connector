/// Compatibility layer for Zig 0.15 -> 0.16 migration.
/// Replaces removed std.net types (Stream, Address, tcpConnectToAddress, etc.)
/// using raw POSIX system calls.
///
/// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const posix = std.posix;

pub const Stream = struct {
    handle: posix.fd_t,

    pub fn close(s: Stream) void {
        posix.close(s.handle);
    }

    pub fn read(s: Stream, buffer: []u8) ReadError!usize {
        return posix.read(s.handle, buffer);
    }

    pub fn readAtLeast(s: Stream, buffer: []u8, len: usize) ReadError!usize {
        std.debug.assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub fn writeAll(s: Stream, bytes: []const u8) WriteError!void {
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

    // Connect
    const addr_ptr: *const posix.sockaddr = @ptrCast(&address);
    try posix.connect(fd, addr_ptr, @sizeOf(posix.sockaddr.in));

    return .{ .handle = fd };
}
