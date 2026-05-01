//! Logging Configuration
//!
//! Provides a custom logFn for std.log that supports:
//! - Runtime log level filtering (debug, info, warn, err)
//! - File output (plain text, no ANSI color)
//! - Colored stderr output (text mode only)
//! - JSON output (one object per line) for CloudWatch Insights when
//!   running in Lambda with `LoggingConfig.LogFormat = JSON`

const std = @import("std");
const posix = std.posix;
const clock = @import("clock.zig");

/// Output format. Text is the CLI default (with ANSI color on stderr).
/// JSON is what the Lambda handler selects so each line is queryable
/// in CloudWatch Insights as structured fields.
pub const LogFormat = enum { text, json };

/// Runtime log level threshold. Messages above this level are suppressed.
/// Set before any logging occurs via init().
var runtime_level: std.log.Level = .info;

/// Output format. Set via init().
var log_format: LogFormat = .text;

/// File descriptor for log output. When null, logs go to stderr.
var log_fd: ?posix.fd_t = null;

/// Initialize the logging subsystem.
/// Call once at startup, before any log statements execute.
pub fn init(level: std.log.Level, log_file_path: ?[]const u8, format: LogFormat) void {
    runtime_level = level;
    log_format = format;

    if (log_file_path) |path| {
        log_fd = posix.openat(posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
        }, 0o644) catch null;
    }
}

/// Close the log file if one was opened.
pub fn deinit() void {
    if (log_fd) |fd| {
        _ = posix.system.close(fd);
        log_fd = null;
    }
}

/// Custom log function installed via std_options.
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(runtime_level)) return;

    if (log_format == .json) {
        // JSON output goes to log_fd (when set) or stderr.
        const fd: posix.fd_t = log_fd orelse posix.STDERR_FILENO;
        writeJsonLine(fd, level, scope, format, args);
        return;
    }

    // Text mode.
    if (log_fd) |fd| {
        writeTextLine(fd, level, scope, format, args);
    } else {
        // Stderr with color (Zig's default behavior).
        std.log.defaultLog(level, scope, format, args);
    }
}

fn writeTextLine(
    fd: posix.fd_t,
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    const level_text = level.asText();
    if (pos + level_text.len <= buf.len) {
        @memcpy(buf[pos..][0..level_text.len], level_text);
        pos += level_text.len;
    }

    if (scope != .default) {
        const scope_prefix = comptime std.fmt.comptimePrint("({t})", .{scope});
        if (pos + scope_prefix.len <= buf.len) {
            @memcpy(buf[pos..][0..scope_prefix.len], scope_prefix);
            pos += scope_prefix.len;
        }
    }

    if (pos + 2 <= buf.len) {
        buf[pos] = ':';
        buf[pos + 1] = ' ';
        pos += 2;
    }

    const remaining = buf[pos..];
    const formatted = std.fmt.bufPrint(remaining, format, args) catch remaining[0..0];
    pos += formatted.len;

    if (pos < buf.len) {
        buf[pos] = '\n';
        pos += 1;
    }

    _ = posix.system.write(fd, buf[0..pos].ptr, pos);
}

/// Emit one JSON line of the shape:
///   {"time":1714588800123,"level":"info","scope":"connector","message":"..."}
///
/// `time` is unix epoch milliseconds (matches CloudWatch's @timestamp
/// field convention). `message` is the formatted+escaped output of
/// `format` + `args`. `scope` is omitted when it's `.default`.
///
/// The whole line lives in a stack buffer; truncates silently if the
/// formatted message exceeds capacity (better a truncated log than a
/// missing one).
fn writeJsonLine(
    fd: posix.fd_t,
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    // Open + time
    pos += writeRaw(&buf, pos, "{\"time\":");
    var ts_buf: [24]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{clock.nowMs()}) catch "0";
    pos += writeRaw(&buf, pos, ts_str);

    // Level
    pos += writeRaw(&buf, pos, ",\"level\":\"");
    pos += writeRaw(&buf, pos, level.asText());
    pos += writeRaw(&buf, pos, "\"");

    // Scope (only when non-default)
    if (scope != .default) {
        pos += writeRaw(&buf, pos, ",\"scope\":\"");
        const scope_str = comptime std.fmt.comptimePrint("{t}", .{scope});
        pos += writeRaw(&buf, pos, scope_str);
        pos += writeRaw(&buf, pos, "\"");
    }

    // Message - format into a side buffer, then JSON-escape into the main buf.
    pos += writeRaw(&buf, pos, ",\"message\":\"");
    var msg_buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, format, args) catch msg_buf[0..0];
    pos += writeJsonEscaped(&buf, pos, msg);
    pos += writeRaw(&buf, pos, "\"");

    // Close + newline
    pos += writeRaw(&buf, pos, "}\n");

    _ = posix.system.write(fd, buf[0..pos].ptr, pos);
}

fn writeRaw(buf: *[8192]u8, pos: usize, s: []const u8) usize {
    const room = buf.len - pos;
    const n = @min(s.len, room);
    @memcpy(buf[pos..][0..n], s[0..n]);
    return n;
}

test "writeJsonEscaped: passes through plain ASCII" {
    var buf: [8192]u8 = undefined;
    const n = writeJsonEscaped(&buf, 0, "hello world");
    try std.testing.expectEqualStrings("hello world", buf[0..n]);
}

test "writeJsonEscaped: escapes quotes, backslash, control chars" {
    var buf: [8192]u8 = undefined;
    const n = writeJsonEscaped(&buf, 0, "a\"b\\c\nd\te");
    try std.testing.expectEqualStrings("a\\\"b\\\\c\\nd\\te", buf[0..n]);
}

test "writeJsonEscaped: \\uXXXX for low control chars" {
    var buf: [8192]u8 = undefined;
    const n = writeJsonEscaped(&buf, 0, &[_]u8{ 'a', 0x01, 'b' });
    try std.testing.expectEqualStrings("a\\u0001b", buf[0..n]);
}

fn writeJsonEscaped(buf: *[8192]u8, start: usize, s: []const u8) usize {
    var pos = start;
    for (s) |c| {
        if (pos >= buf.len) return pos - start;
        switch (c) {
            '"' => pos += writeRaw(buf, pos, "\\\""),
            '\\' => pos += writeRaw(buf, pos, "\\\\"),
            '\n' => pos += writeRaw(buf, pos, "\\n"),
            '\r' => pos += writeRaw(buf, pos, "\\r"),
            '\t' => pos += writeRaw(buf, pos, "\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                var hex_buf: [6]u8 = undefined;
                const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{c}) catch unreachable;
                pos += writeRaw(buf, pos, hex);
            },
            else => {
                buf[pos] = c;
                pos += 1;
            },
        }
    }
    return pos - start;
}
