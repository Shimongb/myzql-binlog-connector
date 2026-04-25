//! Binlog state files
//!
//! Two-file pattern, agnostic of FS vs S3 via ObjectStore:
//!   - current.json          — the lock; written at init, deleted at clean exit.
//!   - last_checkpoint.json  — durable truth; written at clean shutdown.
//!
//! `current.json` aging past `staleness_ms` means the previous owner crashed.
//! `last_checkpoint.json` is what new runs read to decide where to resume.
//!
//! Time is passed in explicitly (`now_ms`) so callers control clock source
//! and tests don't need to mock `std.Io.Clock`.

const std = @import("std");
const builtin = @import("builtin");
const object_store = @import("object_store.zig");

const log = std.log.scoped(.state);

/// Fill buffer with cryptographically-secure random bytes.
/// Linux: getrandom syscall directly; macOS/BSD: arc4random_buf via
/// std.posix.system. Mirrors the helper in src/mysql/auth.zig — kept
/// local to avoid pulling auth.zig into the state module's import graph.
fn fillRandomBytes(buf: []u8) void {
    if (comptime builtin.os.tag == .linux) {
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = std.os.linux.getrandom(buf[filled..].ptr, buf.len - filled, 0);
            const errno = std.posix.errno(rc);
            if (errno == .SUCCESS) {
                filled += rc;
            } else if (errno == .INTR) {
                continue;
            } else {
                @panic("getrandom failed");
            }
        }
    } else {
        std.posix.system.arc4random_buf(buf.ptr, buf.len);
    }
}

/// State payload for both `current.json` and `last_checkpoint.json`.
/// `is_in_progress` is `true` in current.json (lock) and `false` in
/// last_checkpoint.json (durable resume point).
///
/// String fields are owned by the allocator passed to the function that
/// produced the value. Use `deinit(allocator)` to free.
pub const BinlogState = struct {
    binlog_file: []const u8,
    binlog_position: u64,
    updated_at_ms: i64,
    run_id: []const u8,
    schema_cache_key: ?[]const u8,
    is_in_progress: bool,

    pub fn deinit(self: BinlogState, allocator: std.mem.Allocator) void {
        allocator.free(self.binlog_file);
        allocator.free(self.run_id);
        if (self.schema_cache_key) |k| allocator.free(k);
    }
};

pub const LockOutcome = enum {
    /// No prior current.json existed — fresh first run.
    acquired_fresh,
    /// Prior current.json was stale (older than staleness_ms); previous
    /// owner is presumed crashed. Caller should resume from checkpoint.
    acquired_stale_predecessor,
    /// Prior current.json is fresh — another owner is active.
    /// Caller should exit gracefully (idempotency).
    skip_live_owner,
};

/// Outcome of a `checkLock` call.
pub const LockResult = struct {
    outcome: LockOutcome,
    /// Owned by the caller (allocated from the allocator passed to checkLock).
    /// Present iff outcome != acquired_fresh AND prior payload parsed cleanly.
    /// Even on `skip_live_owner` you get the prior state for diagnostic logging.
    prior_state: ?BinlogState,
};

/// Inspect current.json and decide acquire/skip. Does NOT write the new
/// lock — caller composes a fresh BinlogState (with their own run_id and
/// timestamp) and calls `writeCurrentLock`.
///
/// Decision tree:
///   - current.json missing → acquired_fresh
///   - current.json present, parses, age within staleness_ms → skip_live_owner
///   - current.json present, parses, age beyond staleness_ms → acquired_stale_predecessor
///   - current.json present but malformed → log WARN, treat as acquired_stale_predecessor
///     (predecessor wrote a corrupt file — that's still a crash signal)
///
/// Negative age (now_ms < updated_at_ms) is treated as live-owner; that's
/// clock skew on a foreign writer, safer to back off than barge in.
pub fn checkLock(
    allocator: std.mem.Allocator,
    store: *object_store.ObjectStore,
    current_key: []const u8,
    staleness_ms: i64,
    now_ms: i64,
) !LockResult {
    const raw = store.read(allocator, current_key) catch |err| switch (err) {
        object_store.Error.NotFound => return .{ .outcome = .acquired_fresh, .prior_state = null },
        else => return err,
    };
    defer allocator.free(raw);

    const parsed = parseState(allocator, raw) catch |err| {
        if (err == error.OutOfMemory) return err;
        log.warn("current.json malformed ({}); treating as stale predecessor", .{err});
        return .{ .outcome = .acquired_stale_predecessor, .prior_state = null };
    };

    const age_ms = now_ms - parsed.updated_at_ms;
    if (age_ms <= staleness_ms) {
        return .{ .outcome = .skip_live_owner, .prior_state = parsed };
    }
    return .{ .outcome = .acquired_stale_predecessor, .prior_state = parsed };
}

/// Write current.json atomically (sidecar+rename via ObjectStore).
pub fn writeCurrentLock(
    allocator: std.mem.Allocator,
    store: *object_store.ObjectStore,
    current_key: []const u8,
    state: BinlogState,
) !void {
    std.debug.assert(state.is_in_progress);
    try writeStateAtomic(allocator, store, current_key, state);
}

/// Read last_checkpoint.json. Returns null on missing or malformed.
/// Strings in the returned state are allocated from `allocator`; caller
/// must `deinit` them.
pub fn loadCheckpoint(
    allocator: std.mem.Allocator,
    store: *object_store.ObjectStore,
    checkpoint_key: []const u8,
) !?BinlogState {
    const raw = store.read(allocator, checkpoint_key) catch |err| switch (err) {
        object_store.Error.NotFound => {
            log.debug("checkpoint key '{s}' not found", .{checkpoint_key});
            return null;
        },
        else => return err,
    };
    defer allocator.free(raw);

    const parsed = parseState(allocator, raw) catch |err| {
        if (err == error.OutOfMemory) return err;
        log.warn("checkpoint '{s}' malformed ({}); cold-starting", .{ checkpoint_key, err });
        return null;
    };
    return parsed;
}

/// Write last_checkpoint.json atomically.
pub fn writeCheckpoint(
    allocator: std.mem.Allocator,
    store: *object_store.ObjectStore,
    checkpoint_key: []const u8,
    state: BinlogState,
) !void {
    std.debug.assert(!state.is_in_progress);
    try writeStateAtomic(allocator, store, checkpoint_key, state);
}

/// Best-effort delete of current.json. Failures are logged but never
/// propagated — the next run's stale-detection handles a leftover lock.
pub fn releaseLock(store: *object_store.ObjectStore, current_key: []const u8) void {
    store.delete(current_key) catch |err| switch (err) {
        object_store.Error.NotFound => {},
        else => log.warn("failed to delete current.json: {}", .{err}),
    };
}

/// Generate a UUIDv4 string ("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx").
/// Owned by `allocator`.
pub fn generateRunId(allocator: std.mem.Allocator) ![]u8 {
    var bytes: [16]u8 = undefined;
    fillRandomBytes(&bytes);
    // RFC 4122 v4: top 4 bits of byte 6 = 0100
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // RFC 4122 variant: top 2 bits of byte 8 = 10
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex_chars = "0123456789abcdef";
    const out = try allocator.alloc(u8, 36);
    var oi: usize = 0;
    for (bytes, 0..) |b, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            out[oi] = '-';
            oi += 1;
        }
        out[oi] = hex_chars[b >> 4];
        out[oi + 1] = hex_chars[b & 0x0f];
        oi += 2;
    }
    return out;
}

// ============================================================
// JSON serde (manual; matches cache_persistence style).
// ============================================================

const StateJson = struct {
    binlog_file: []const u8,
    binlog_position: u64,
    updated_at_ms: i64,
    run_id: []const u8,
    schema_cache_key: ?[]const u8 = null,
    is_in_progress: bool,
};

fn parseState(allocator: std.mem.Allocator, raw: []const u8) !BinlogState {
    const parsed = try std.json.parseFromSlice(StateJson, allocator, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    const v = parsed.value;
    const file = try allocator.dupe(u8, v.binlog_file);
    errdefer allocator.free(file);
    const run = try allocator.dupe(u8, v.run_id);
    errdefer allocator.free(run);
    const cache: ?[]const u8 = if (v.schema_cache_key) |k| try allocator.dupe(u8, k) else null;

    return .{
        .binlog_file = file,
        .binlog_position = v.binlog_position,
        .updated_at_ms = v.updated_at_ms,
        .run_id = run,
        .schema_cache_key = cache,
        .is_in_progress = v.is_in_progress,
    };
}

fn writeStateAtomic(
    allocator: std.mem.Allocator,
    store: *object_store.ObjectStore,
    key: []const u8,
    state: BinlogState,
) !void {
    const json = try serializeState(allocator, state);
    defer allocator.free(json);

    var h = try store.create(key);
    errdefer h.abort();
    try h.write(json);
    try h.commit();
}

fn serializeState(allocator: std.mem.Allocator, state: BinlogState) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, '{');

    try buf.appendSlice(allocator, "\"binlog_file\":\"");
    try appendJsonEscaped(&buf, allocator, state.binlog_file);
    try buf.append(allocator, '"');

    try buf.appendSlice(allocator, ",\"binlog_position\":");
    try appendInt(&buf, allocator, state.binlog_position);

    try buf.appendSlice(allocator, ",\"updated_at_ms\":");
    try appendInt(&buf, allocator, state.updated_at_ms);

    try buf.appendSlice(allocator, ",\"run_id\":\"");
    try appendJsonEscaped(&buf, allocator, state.run_id);
    try buf.append(allocator, '"');

    if (state.schema_cache_key) |k| {
        try buf.appendSlice(allocator, ",\"schema_cache_key\":\"");
        try appendJsonEscaped(&buf, allocator, k);
        try buf.append(allocator, '"');
    } else {
        try buf.appendSlice(allocator, ",\"schema_cache_key\":null");
    }

    try buf.appendSlice(allocator, ",\"is_in_progress\":");
    try buf.appendSlice(allocator, if (state.is_in_progress) "true" else "false");

    try buf.append(allocator, '}');
    return try buf.toOwnedSlice(allocator);
}

fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const str = try std.fmt.bufPrint(&tmp, "{d}", .{value});
    try buf.appendSlice(allocator, str);
}

fn appendJsonEscaped(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => try buf.append(allocator, c),
        }
    }
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "BinlogState round-trip via serializeState/parseState" {
    const allocator = testing.allocator;

    const original: BinlogState = .{
        .binlog_file = "binlog.000042",
        .binlog_position = 12345,
        .updated_at_ms = 1_700_000_000_000,
        .run_id = "abcdef01-2345-4678-9abc-def012345678",
        .schema_cache_key = "schema-cache/feedface12345678.json.gz",
        .is_in_progress = true,
    };

    const json = try serializeState(allocator, original);
    defer allocator.free(json);

    const parsed = try parseState(allocator, json);
    defer parsed.deinit(allocator);

    try testing.expectEqualStrings(original.binlog_file, parsed.binlog_file);
    try testing.expectEqual(original.binlog_position, parsed.binlog_position);
    try testing.expectEqual(original.updated_at_ms, parsed.updated_at_ms);
    try testing.expectEqualStrings(original.run_id, parsed.run_id);
    try testing.expectEqualStrings(original.schema_cache_key.?, parsed.schema_cache_key.?);
    try testing.expectEqual(original.is_in_progress, parsed.is_in_progress);
}

test "BinlogState round-trip with null schema_cache_key" {
    const allocator = testing.allocator;

    const original: BinlogState = .{
        .binlog_file = "binlog.000001",
        .binlog_position = 4,
        .updated_at_ms = 0,
        .run_id = "00000000-0000-4000-8000-000000000000",
        .schema_cache_key = null,
        .is_in_progress = false,
    };

    const json = try serializeState(allocator, original);
    defer allocator.free(json);

    const parsed = try parseState(allocator, json);
    defer parsed.deinit(allocator);

    try testing.expectEqual(@as(?[]const u8, null), parsed.schema_cache_key);
    try testing.expect(!parsed.is_in_progress);
}

test "checkLock: missing current.json returns acquired_fresh" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const result = try checkLock(allocator, &store, "current.json", 90_000, 1_000_000);
    try testing.expectEqual(LockOutcome.acquired_fresh, result.outcome);
    try testing.expectEqual(@as(?BinlogState, null), result.prior_state);
}

test "checkLock: fresh current.json returns skip_live_owner" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const lock: BinlogState = .{
        .binlog_file = "binlog.000001",
        .binlog_position = 4,
        .updated_at_ms = 1_000_000,
        .run_id = "owner-1",
        .schema_cache_key = null,
        .is_in_progress = true,
    };
    try writeCurrentLock(allocator, &store, "current.json", lock);

    // 60s after owner wrote — still within 90s staleness.
    const result = try checkLock(allocator, &store, "current.json", 90_000, 1_060_000);
    defer if (result.prior_state) |s| s.deinit(allocator);

    try testing.expectEqual(LockOutcome.skip_live_owner, result.outcome);
    try testing.expect(result.prior_state != null);
    try testing.expectEqualStrings("owner-1", result.prior_state.?.run_id);
}

test "checkLock: stale current.json returns acquired_stale_predecessor" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const lock: BinlogState = .{
        .binlog_file = "binlog.000001",
        .binlog_position = 4,
        .updated_at_ms = 1_000_000,
        .run_id = "ghost",
        .schema_cache_key = null,
        .is_in_progress = true,
    };
    try writeCurrentLock(allocator, &store, "current.json", lock);

    // 5min after — well past 90s staleness.
    const result = try checkLock(allocator, &store, "current.json", 90_000, 1_300_000);
    defer if (result.prior_state) |s| s.deinit(allocator);

    try testing.expectEqual(LockOutcome.acquired_stale_predecessor, result.outcome);
    try testing.expectEqualStrings("ghost", result.prior_state.?.run_id);
}

test "checkLock: malformed current.json treated as stale predecessor" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    {
        var h = try store.create("current.json");
        errdefer h.abort();
        try h.write("not valid json {{{");
        try h.commit();
    }

    const result = try checkLock(allocator, &store, "current.json", 90_000, 1_000_000);
    defer if (result.prior_state) |s| s.deinit(allocator);

    try testing.expectEqual(LockOutcome.acquired_stale_predecessor, result.outcome);
    try testing.expectEqual(@as(?BinlogState, null), result.prior_state);
}

test "loadCheckpoint: missing returns null" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const got = try loadCheckpoint(allocator, &store, "checkpoint.json");
    try testing.expectEqual(@as(?BinlogState, null), got);
}

test "loadCheckpoint: malformed returns null (cold-start path)" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    {
        var h = try store.create("checkpoint.json");
        errdefer h.abort();
        try h.write("garbage");
        try h.commit();
    }

    const got = try loadCheckpoint(allocator, &store, "checkpoint.json");
    try testing.expectEqual(@as(?BinlogState, null), got);
}

test "writeCheckpoint + loadCheckpoint round-trip" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const expected: BinlogState = .{
        .binlog_file = "binlog.000007",
        .binlog_position = 9999,
        .updated_at_ms = 1_700_000_000_000,
        .run_id = "11111111-2222-4333-8444-555555555555",
        .schema_cache_key = "schema-cache/cafebabe12345678.json.gz",
        .is_in_progress = false,
    };
    try writeCheckpoint(allocator, &store, "checkpoint.json", expected);

    const got = (try loadCheckpoint(allocator, &store, "checkpoint.json")).?;
    defer got.deinit(allocator);

    try testing.expectEqualStrings(expected.binlog_file, got.binlog_file);
    try testing.expectEqual(expected.binlog_position, got.binlog_position);
    try testing.expectEqualStrings(expected.run_id, got.run_id);
    try testing.expectEqualStrings(expected.schema_cache_key.?, got.schema_cache_key.?);
    try testing.expect(!got.is_in_progress);
}

test "releaseLock removes current.json; idempotent on missing" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = path_buf[0..path_len];

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    const lock: BinlogState = .{
        .binlog_file = "x",
        .binlog_position = 4,
        .updated_at_ms = 0,
        .run_id = "r",
        .schema_cache_key = null,
        .is_in_progress = true,
    };
    try writeCurrentLock(allocator, &store, "current.json", lock);
    _ = try store.head("current.json");

    releaseLock(&store, "current.json");
    try testing.expectError(object_store.Error.NotFound, store.head("current.json"));

    // Idempotent — calling again on a missing file must not crash or error.
    releaseLock(&store, "current.json");
}

test "generateRunId produces RFC4122 v4 format" {
    const allocator = testing.allocator;

    const id = try generateRunId(allocator);
    defer allocator.free(id);

    try testing.expectEqual(@as(usize, 36), id.len);
    // 8-4-4-4-12 hyphen layout
    try testing.expectEqual(@as(u8, '-'), id[8]);
    try testing.expectEqual(@as(u8, '-'), id[13]);
    try testing.expectEqual(@as(u8, '-'), id[18]);
    try testing.expectEqual(@as(u8, '-'), id[23]);
    // Version nibble: char index 14 must be '4'
    try testing.expectEqual(@as(u8, '4'), id[14]);
    // Variant nibble: char index 19 must be 8/9/a/b
    try testing.expect(id[19] == '8' or id[19] == '9' or id[19] == 'a' or id[19] == 'b');
}

test "generateRunId produces unique values" {
    const allocator = testing.allocator;
    const a = try generateRunId(allocator);
    defer allocator.free(a);
    const b = try generateRunId(allocator);
    defer allocator.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
}
