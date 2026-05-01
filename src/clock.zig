//! Wall-clock helpers - single source of truth for "what time is it".
//!
//! Both `main.zig` and `pipeline.zig` previously carried their own
//! `nowMs` helpers (one routed through `std.Io.Clock`, one through
//! `metrics.nanoTimestamp`). Both ended up at the same
//! `clock_gettime(REALTIME)` syscall; the io-plumbed variant added
//! ceremony without changing semantics. This module consolidates
//! them. `metrics.zig` re-exports `nanoTimestamp` from here for
//! callers (`PipelineMetrics`) that want nanosecond precision.
//!
//! No `std.Io` plumbing - `std.Io` exists for *I/O* (network, file),
//! not for clock reads. A pure local syscall is the right tool.
//!
//! No `std.c` (per project policy): on Linux we go through
//! `std.os.linux.clock_gettime` (direct syscall, no libc); on macOS
//! we go through `std.posix.system.clock_gettime` (which routes to
//! libc on darwin, the only platform where we need libc at all).

const std = @import("std");
const builtin = @import("builtin");

/// Current wall-clock time as nanoseconds since the Unix epoch.
/// Returns 0 on error (only possible on macOS - Linux's syscall
/// is infallible for `CLOCK_REALTIME`). Callers that care about
/// the failure case should use `std.Io.Clock` instead.
pub fn nanoTimestamp() i128 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
    } else {
        var ts: std.posix.system.timespec = undefined;
        if (std.posix.system.clock_gettime(.REALTIME, &ts) != 0) return 0;
        return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
    }
}

/// Current wall-clock time as milliseconds since the Unix epoch.
/// Just `nanoTimestamp() / 1_000_000`, narrowed to `i64` (which
/// suits everything we persist or compare in this project - state
/// files, lock staleness, flush gates).
pub fn nowMs() i64 {
    return @intCast(@divFloor(nanoTimestamp(), std.time.ns_per_ms));
}

test "nanoTimestamp returns a plausible value" {
    const t = nanoTimestamp();
    // Must be after Jan 1, 2020 (1577836800 unix seconds * 1e9 ns).
    try std.testing.expect(t > 1577836800 * std.time.ns_per_s);
}

test "nowMs returns ms, equals nanoTimestamp / 1e6 modulo a few ms" {
    const ns = nanoTimestamp();
    const ms = nowMs();
    const ns_to_ms: i64 = @intCast(@divFloor(ns, std.time.ns_per_ms));
    // Allow ±5ms drift between the two reads.
    try std.testing.expect(@abs(ms - ns_to_ms) < 5);
}
