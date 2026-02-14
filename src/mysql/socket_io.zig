/// Bridge between a raw POSIX socket fd and the std.Io.Reader / std.Io.Writer
/// vtable interfaces required by std.crypto.tls.Client.
///
/// Must be heap-allocated (allocator.create) because the TLS Client stores
/// pointers to the reader_iface and writer_iface fields.
const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const tls = std.crypto.tls;

pub const SocketIo = struct {
    handle: posix.fd_t,

    // Io.Reader interface for the TLS Client to read encrypted data from the socket.
    reader_iface: Io.Reader,
    // Io.Writer interface for the TLS Client to write encrypted data to the socket.
    writer_iface: Io.Writer,

    // Buffers owned by the caller (passed at init, freed externally).
    // Must be at least tls.Client.min_buffer_len each.
    read_buf: []u8,
    write_buf: []u8,

    pub fn init(self: *SocketIo, handle: posix.fd_t, read_buf: []u8, write_buf: []u8) void {
        std.debug.assert(read_buf.len >= tls.Client.min_buffer_len);
        std.debug.assert(write_buf.len >= tls.Client.min_buffer_len);

        self.* = .{
            .handle = handle,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .reader_iface = .{
                .vtable = &reader_vtable,
                .buffer = read_buf,
                .seek = 0,
                .end = 0,
            },
            .writer_iface = .{
                .vtable = &writer_vtable,
                .buffer = write_buf,
            },
        };
    }

    // -- Reader vtable --

    const reader_vtable: Io.Reader.VTable = .{
        .stream = readerStream,
    };

    /// Reads from the socket into the Writer's writable slice.
    fn readerStream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *SocketIo = @alignCast(@fieldParentPtr("reader_iface", io_r));

        // Get a writable destination from the writer.
        const dest = limit.slice(io_w.writableSliceGreedy(1) catch return error.WriteFailed);
        if (dest.len == 0) return 0;

        const n = posix.read(self.handle, dest) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;

        // Debug: log first bytes and record boundaries from each socket read
        std.log.debug("socketio.read: {d} bytes, first={any}", .{
            n,
            dest[0..@min(n, 32)],
        });
        // Dump TLS record type bytes at known offsets to identify record boundaries
        if (n > 160) {
            std.log.debug("socketio.read: byte[160..176]={any}", .{
                dest[160..@min(n, 176)],
            });
        }

        io_w.advance(n);
        return n;
    }

    // -- Writer vtable --

    const writer_vtable: Io.Writer.VTable = .{
        .drain = writerDrain,
    };

    /// Writes buffered data + provided data slices to the socket.
    fn writerDrain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *SocketIo = @alignCast(@fieldParentPtr("writer_iface", io_w));

        // First, flush any buffered data.
        const buffered = io_w.buffered();
        if (buffered.len > 0) {
            std.log.debug("socketio.write: buffered {d} bytes, first={any}", .{
                buffered.len,
                buffered[0..@min(buffered.len, 16)],
            });
            writeAllToSocket(self.handle, buffered) catch return error.WriteFailed;
        }

        // Write each data slice.
        var total: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            if (slice.len > 0) {
                writeAllToSocket(self.handle, slice) catch return error.WriteFailed;
                total += slice.len;
            }
        }

        // Handle the last slice which may be repeated `splat` times.
        const pattern = data[data.len - 1];
        if (pattern.len > 0) {
            var remaining = splat;
            while (remaining > 0) : (remaining -= 1) {
                writeAllToSocket(self.handle, pattern) catch return error.WriteFailed;
                total += pattern.len;
            }
        }

        return io_w.consume(buffered.len + total);
    }

    fn writeAllToSocket(handle: posix.fd_t, bytes: []const u8) !void {
        var index: usize = 0;
        while (index < bytes.len) {
            const rc = posix.system.write(handle, bytes[index..].ptr, bytes[index..].len);
            const errno = posix.errno(rc);
            if (errno != .SUCCESS) {
                return switch (errno) {
                    .INTR => continue,
                    .AGAIN => continue,
                    else => error.WriteFailed,
                };
            }
            const written: usize = @intCast(rc);
            if (written == 0) return error.WriteFailed;
            index += written;
        }
    }
};
