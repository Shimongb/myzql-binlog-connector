// MySQL network packet writer.
// Originally from myzql library (MIT License, Copyright (c) 2023 Zack).
const std = @import("std");
const utils = @import("utils.zig");
const compat = @import("../compat.zig");

pub const PacketWriter = struct {
    buf: []u8,
    pos: usize, // buf[0..pos]: buffer is written but not flushed
    stream: compat.Stream,
    allocator: std.mem.Allocator,

    pub fn init(s: compat.Stream, allocator: std.mem.Allocator) !PacketWriter {
        return .{
            .stream = s,
            .buf = &.{},
            .pos = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(w: *const PacketWriter) void {
        w.allocator.free(w.buf);
    }

    pub fn write(w: *PacketWriter, src: []const u8) !void {
        try w.expandIfNeeded(src.len);
        const n = utils.copy(w.buf[w.pos..], src);
        std.debug.assert(n == src.len);
        w.pos += n;
    }

    // increase the length of the buffer as if it was written to
    fn skip(w: *PacketWriter, n: usize) !void {
        try w.expandIfNeeded(n);
        w.pos += n;
    }

    // increase the length of the buffer as if it was written to
    // returns a slice of the buffer that can be written to
    fn advance(w: *PacketWriter, n: usize) ![]u8 {
        try w.expandIfNeeded(n);
        const res = w.buf[w.pos .. w.pos + n];
        w.pos += n;
        return res;
    }

    fn advanceComptime(w: *PacketWriter, comptime n: usize) !*[n]u8 {
        try w.expandIfNeeded(n);
        const res = w.buf[w.pos..][0..n];
        w.pos += n;
        return res;
    }

    // flush the buffer to the stream
    pub inline fn flush(p: *PacketWriter) !void {
        try p.stream.writeAll(p.buf[0..p.pos]);
        p.pos = 0;
    }

    pub fn writeBytesAsPacket(p: *PacketWriter, sequence_id: u8, buffer: []const u8) !void {
        try p.writeInt(u24, @intCast(buffer.len));
        try p.writeInt(u8, sequence_id);
        try p.write(buffer);
    }

    pub fn writePacket(p: *PacketWriter, sequence_id: u8, packet: anytype) !void {
        const start = p.pos;
        try p.skip(4);

        try packet.write(p);

        const written = p.pos - start - 4;
        const written_buf = p.buf[start..][0..3];
        std.mem.writeInt(u24, written_buf, @intCast(written), .little);
        p.buf[start + 3] = sequence_id;
    }

    pub fn writeInt(p: *PacketWriter, comptime Int: type, int: Int) !void {
        const bytes = try p.advanceComptime(@divExact(@typeInfo(Int).int.bits, 8));
        std.mem.writeInt(Int, bytes, int, .little);
    }

    pub fn writeNullTerminatedString(p: *PacketWriter, v: [:0]const u8) !void {
        try p.write(v[0 .. v.len + 1]);
    }

    pub fn writeFillers(p: *PacketWriter, comptime n: comptime_int) !void {
        _ = try p.advance(n);
    }

    pub fn writeLengthEncodedString(p: *PacketWriter, s: []const u8) !void {
        try p.writeLengthEncodedInteger(s.len);
        try p.write(s);
    }

    pub fn writeLengthEncodedInteger(p: *PacketWriter, v: u64) !void {
        if (v < 251) {
            try p.writeInt(u8, @intCast(v));
        } else if (v < 1 << 16) {
            try p.writeInt(u8, 0xFC);
            try p.writeInt(u16, @intCast(v));
        } else if (v < 1 << 24) {
            try p.writeInt(u8, 0xFD);
            try p.writeInt(u24, @intCast(v));
        } else if (v < 1 << 64) {
            try p.writeInt(u8, 0xFE);
            try p.writeInt(u64, v);
        } else {
            std.log.warn("Invalid length encoded integer: {any}\n", .{v});
            return error.InvalidLengthEncodedInteger;
        }
    }

    // invalidates all futures writes returned by `advance`
    fn expandIfNeeded(w: *PacketWriter, req_n: usize) !void {
        if (req_n <= w.buf.len - w.pos) {
            return;
        }

        const target_len = w.buf.len + req_n;
        const new_len = utils.nextPowerOf2(@truncate(target_len));

        // try resize
        if (w.allocator.resize(w.buf, new_len)) {
            w.buf = w.buf.ptr[0..new_len];
            return;
        }

        // if resize failed, try to allocate a new buffer
        const new_buf = try w.allocator.alloc(u8, new_len);
        @memcpy(new_buf[0..w.buf.len], w.buf);
        w.allocator.free(w.buf);
        w.buf = new_buf;
    }
};
