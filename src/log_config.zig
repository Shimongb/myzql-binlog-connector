//! Logging Configuration
//!
//! Provides a custom logFn for std.log that supports:
//! - Runtime log level filtering (debug, info, warn, err)
//! - File output (plain text, no ANSI color)
//! - Colored stderr output (default, via std.log.defaultLog)

const std = @import("std");

/// Runtime log level threshold. Messages above this level are suppressed.
/// Set before any logging occurs via init().
var runtime_level: std.log.Level = .info;

/// File descriptor for log output. When null, logs go to stderr with color.
var log_fd: ?std.posix.fd_t = null;

/// Initialize the logging subsystem.
/// Call once at startup, before any log statements execute.
pub fn init(level: std.log.Level, log_file_path: ?[]const u8) void {
    runtime_level = level;

    if (log_file_path) |path| {
        log_fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
        }, 0o644) catch null;
    }
}

/// Close the log file if one was opened.
pub fn deinit() void {
    if (log_fd) |fd| {
        std.posix.close(fd);
        log_fd = null;
    }
}

/// Custom log function installed via std_options.
/// Routes to file (plain text) or stderr (colored) based on init() configuration.
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    // Runtime level check
    if (@intFromEnum(level) > @intFromEnum(runtime_level)) return;

    if (log_fd) |fd| {
        // File output: plain text, no color.
        // Format into a stack buffer and write to the fd.
        var buf: [8192]u8 = undefined;
        var pos: usize = 0;

        // Write level prefix
        const level_text = level.asText();
        if (pos + level_text.len <= buf.len) {
            @memcpy(buf[pos..][0..level_text.len], level_text);
            pos += level_text.len;
        }

        // Write scope if non-default
        if (scope != .default) {
            const scope_prefix = comptime std.fmt.comptimePrint("({t})", .{scope});
            if (pos + scope_prefix.len <= buf.len) {
                @memcpy(buf[pos..][0..scope_prefix.len], scope_prefix);
                pos += scope_prefix.len;
            }
        }

        // Write separator
        if (pos + 2 <= buf.len) {
            buf[pos] = ':';
            buf[pos + 1] = ' ';
            pos += 2;
        }

        // Format the message into remaining buffer
        const remaining = buf[pos..];
        const formatted = std.fmt.bufPrint(remaining, format, args) catch remaining[0..0];
        pos += formatted.len;

        // Newline
        if (pos < buf.len) {
            buf[pos] = '\n';
            pos += 1;
        }

        _ = std.c.write(fd, buf[0..pos].ptr, pos);
    } else {
        // Stderr with color (Zig's default behavior)
        std.log.defaultLog(level, scope, format, args);
    }
}
