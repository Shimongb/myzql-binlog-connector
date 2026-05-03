//! S3 backend for `ObjectStore`.
//!
//! Wraps z3's `S3Client` with three responsibilities our use cases
//! demand and z3 doesn't provide on its own:
//!
//! 1. **`x-amz-security-token` injection** for STS-vended creds. z3
//!    doesn't have a `session_token` field on `Config`; instead, every
//!    op gets the header through `RequestOptions.custom_header`. The
//!    signer signs whatever's in the array (s3_signing.zig:11-94).
//!
//! 2. **Mandatory status check** after every z3 raw-response op
//!    (`putObject`, `headObject`, `deleteObject`, `getObject`).
//!    All four skip the status check internally
//!    they hand back the Response on any HTTP code, including 4xx/5xx.
//!
//! 3. **Buffer-then-put writes**. `WriteHandle.write` appends to an
//!    in-memory ArrayList; `commit` (or `commitAs`) issues a single
//!    `putObject`. The S3 PUT itself is atomic, so we don't need
//!    PosixStore's sidecar+rename. For files larger than the
//!    connector's `flush_size_bytes` default (100 MB) this means
//!    100 MB held in memory until commit; Lambda 256 MB+ tier
//!    handles that fine. Multipart streaming is a v2 follow-up.

const std = @import("std");
const s3 = @import("s3");
const object_store = @import("object_store.zig");
const aws_creds = @import("aws_creds.zig");
const clock = @import("clock.zig");

const log = std.log.scoped(.s3_store);

/// Full-request retry budget for mutating calls (PUT/DELETE). z3's
/// internal retry only covers connection establishment; once a request
/// is in flight, transport-layer failures (SendFailed, WriteFailed,
/// ReceiveFailed, FlushFailed) are terminal. In practice these fire
/// when a pooled keep-alive socket was silently half-closed - common
/// across the ~10s gaps between parquet flushes - so the retry loop
/// needs to wrap the whole lifecycle and reset the http pool between
/// attempts (see `rebuildClient`), not just the TCP connect.
const MAX_ATTEMPTS: u8 = 3;
/// Initial backoff. A fast retry (100-200ms) just hits the same dead
/// socket; something in the high hundreds gives NAT/idle-reaper time
/// to actually drop it and lets a transient S3 blip clear.
const INITIAL_BACKOFF_MS: u64 = 500;

/// Classify z3 errors into "retry makes sense" vs "don't bother". The
/// transport-layer bucket is what bites us on flaky keep-alive pools;
/// connection-setup failures are also worth retrying (DNS blip, TLS
/// handshake race). Auth, URI parsing, body-size contract violations
/// never get better by retrying.
fn isRetryableIoErr(err: anyerror) bool {
    return switch (err) {
        error.ConnectionFailed,
        error.SendFailed,
        error.WriteFailed,
        error.ReceiveFailed,
        error.FlushFailed,
        error.ReadFailed,
        => true,
        else => false,
    };
}

/// Build a `RequestOptions` that preserves the caller's custom headers
/// but forces z3's own connection-establish retry off (`max_attempts=1`).
/// Used on read-only paths where a 404 or an immediate connection error
/// is the exact signal we want - retrying twice internally just pads
/// the cold-start and hides what actually happened.
fn singleAttemptOptions(base: s3.S3Client.RequestOptions) s3.S3Client.RequestOptions {
    return .{
        .custom_header = base.custom_header,
        .max_attempts = 1,
    };
}

/// Sleep with jittered exponential backoff. Jitter is a best-effort
/// tweak to avoid thundering-herd across concurrent lanes; it's cheap
/// to compute and doesn't need a real PRNG. Uses the posix nanosleep
/// syscall directly (same pattern as pipeline.zig's ticker) to match
/// the project's no-libc-sleep policy.
fn backoffSleep(attempt: u8) void {
    const base_ms: u64 = INITIAL_BACKOFF_MS << @intCast(@min(attempt, 5));
    const jitter_ms: u64 = @intCast(@mod(clock.nanoTimestamp(), 50));
    const total_ns: u64 = (base_ms + jitter_ms) * std.time.ns_per_ms;
    const ts: std.posix.timespec = .{
        .sec = @intCast(@divTrunc(total_ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(total_ns, std.time.ns_per_s)),
    };
    _ = std.posix.system.nanosleep(&ts, null);
}

/// Reuse the canonical Error set + HeadInfo from object_store so the
/// dispatch through the tagged union in object_store.zig doesn't need
/// per-arm type conversion. (Zig handles the circular @import between
/// the two files cleanly - both compile-time-resolved, no init order.)
pub const Error = object_store.Error;
pub const HeadInfo = object_store.HeadInfo;

// HeadInfo doc reminder: `size` will be 0 for S3 (z3's S3Head doesn't
// capture `Content-Length`); `last_modified_ms` is parsed from the
// `Last-Modified` header. 0 on parse failure is safe - the
// connector's `isStaleByTtl` treats 0 as "always stale".

/// Re-export so existing callers (`main.zig` etc.) can still write
/// `s3_store.Creds`. The struct itself lives in `aws_creds.zig`
/// since SSM and any future AWS client share the same shape.
pub const Creds = aws_creds.Creds;

pub const S3Store = struct {
    allocator: std.mem.Allocator,
    /// Owned by the store; deinit'd on `S3Store.deinit`. Mutable - the
    /// retry path rebuilds it when a prior request left the http pool
    /// holding a dead keep-alive socket (see `rebuildClient`).
    client: s3.S3Client,
    /// Borrowed; lifetime >= store. Caller owns these strings.
    bucket: []const u8,
    /// Borrowed. Empty string means "no prefix" - keys are written
    /// directly under the bucket root.
    key_prefix: []const u8,
    /// Borrowed.
    creds: Creds,
    /// Kept so we can reinitialise the client on retry without asking
    /// callers to re-plumb it through. Borrowed (z3 stores a copy).
    io: std.Io,

    pub fn init(
        allocator: std.mem.Allocator,
        bucket: []const u8,
        key_prefix: []const u8,
        creds: Creds,
        io: std.Io,
    ) !S3Store {
        const client = try s3.S3Client.init(
            allocator,
            .{
                .access_key_id = creds.access_key_id,
                .secret_access_key = creds.secret_access_key,
                .region = creds.region,
                // endpoint = null → z3 auto-constructs
                // {bucket}.s3.{region}.amazonaws.com.
            },
            .{ .io = io },
        );
        return .{
            .allocator = allocator,
            .client = client,
            .bucket = bucket,
            .key_prefix = key_prefix,
            .creds = creds,
            .io = io,
        };
    }

    pub fn deinit(self: *S3Store) void {
        self.client.deinit();
    }

    /// Drop the current S3 client (including its http keep-alive pool)
    /// and spin up a fresh one. Used by the PUT/DELETE retry path when
    /// the prior attempt failed with a transport-class error - those
    /// almost always mean the pooled socket is half-closed, and z3
    /// would otherwise hand us the same dead socket on the next call.
    /// Failures here are logged and swallowed: the next request will
    /// try the stale client, which at worst just repeats the original
    /// failure without masking it.
    fn rebuildClient(self: *S3Store) void {
        self.client.deinit();
        self.client = s3.S3Client.init(
            self.allocator,
            .{
                .access_key_id = self.creds.access_key_id,
                .secret_access_key = self.creds.secret_access_key,
                .region = self.creds.region,
            },
            .{ .io = self.io },
        ) catch |err| {
            log.err("S3Client rebuild failed: {} - subsequent requests may reuse stale state", .{err});
            return;
        };
    }

    /// Compose the full S3 key from the store's prefix + caller-supplied
    /// relative key. Caller-allocated; freed by caller. Empty prefix
    /// case avoids leading `/` in the key.
    fn composeKey(self: *S3Store, allocator: std.mem.Allocator, key: []const u8) Error![]u8 {
        if (self.key_prefix.len == 0) {
            return allocator.dupe(u8, key) catch Error.OutOfMemory;
        }
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.key_prefix, key }) catch
            Error.OutOfMemory;
    }

    /// Build an `RequestOptions` populated with the session-token
    /// custom header when `creds.session_token != null`. The header
    /// slice is returned by-value via the second out-param - caller
    /// must keep that slice alive for the request's duration. (z3
    /// dupes the header bytes internally - `s3_request.zig:42-66` -
    /// so a stack-local slice is safe in practice; we still keep the
    /// pattern explicit.)
    fn requestOptionsWithToken(self: *S3Store, headers_slot: *[1]std.http.Header) s3.S3Client.RequestOptions {
        if (self.creds.session_token) |tok| {
            headers_slot[0] = .{ .name = "x-amz-security-token", .value = tok };
            return .{ .custom_header = headers_slot[0..1] };
        }
        return .{};
    }

    pub fn create(self: *S3Store, key: []const u8) Error!S3WriteHandle {
        if (!isValidKey(key)) return Error.InvalidKey;
        const final_key = try self.composeKey(self.allocator, key);
        return .{
            .store = self,
            .final_key = final_key,
            .buffer = .empty,
            .closed = false,
        };
    }

    pub fn read(self: *S3Store, allocator: std.mem.Allocator, key: []const u8) Error![]u8 {
        if (!isValidKey(key)) return Error.InvalidKey;
        const composed = try self.composeKey(allocator, key);
        defer allocator.free(composed);

        var headers_slot: [1]std.http.Header = undefined;
        // GETs today only hit the state path (current.json /
        // last_checkpoint.json) and cache entries. A cold-start 404 is
        // a routine "file not there" signal, not a network fault, and
        // the ~300ms z3 spends on two connection-retry attempts before
        // giving up on real transport errors isn't worth it here.
        const opts: s3.S3Client.GetObjectOptions = .{
            .request = singleAttemptOptions(self.requestOptionsWithToken(&headers_slot)),
        };
        var resp = self.client.getObject(self.bucket, composed, opts) catch |err| {
            log.err("S3 getObject '{s}' returned error: {}", .{ composed, err });
            return Error.Io;
        };
        defer resp.deinit();

        // 404 on GET is an expected signal on cold-start state reads
        // (current.json / last_checkpoint.json on first run). Surface
        // it as NotFound without the alarming error log that
        // checkStatus emits.
        if (resp.http_head.status == .not_found) return Error.NotFound;
        try checkStatus("get", composed, &resp);

        // resp.body is owned by resp.allocator; dupe into caller's allocator
        // before resp.deinit runs.
        return allocator.dupe(u8, resp.body) catch Error.OutOfMemory;
    }

    pub fn head(self: *S3Store, key: []const u8) Error!HeadInfo {
        if (!isValidKey(key)) return Error.InvalidKey;
        const composed = try self.composeKey(self.allocator, key);
        defer self.allocator.free(composed);

        var headers_slot: [1]std.http.Header = undefined;
        // Same rationale as `read`: a HEAD that 404s (cache TTL probe
        // on a cold cache) is expected, and the retry latency would
        // just push back the cold-start.
        const opts = singleAttemptOptions(self.requestOptionsWithToken(&headers_slot));
        var resp = self.client.headObject(self.bucket, composed, opts) catch |err| {
            log.err("S3 headObject '{s}' returned error: {}", .{ composed, err });
            return Error.Io;
        };
        defer resp.deinit();

        // 404 is "not found" - distinguished from other failures so
        // callers (cache TTL, probe, etc.) can react cleanly.
        if (resp.http_head.status == .not_found) return Error.NotFound;
        try checkStatus("head", composed, &resp);

        const lm_ms: i64 = if (resp.s3_head.last_modified) |raw| parseHttpDateMs(raw) else 0;
        return .{
            // Content-Length not exposed by z3's S3Head; default to 0
            // until a consumer needs it (see HeadInfo.size doc).
            .size = 0,
            .last_modified_ms = lm_ms,
        };
    }

    pub fn delete(self: *S3Store, key: []const u8) Error!void {
        if (!isValidKey(key)) return Error.InvalidKey;
        const composed = try self.composeKey(self.allocator, key);
        defer self.allocator.free(composed);

        var attempt: u8 = 1;
        while (true) : (attempt += 1) {
            var headers_slot: [1]std.http.Header = undefined;
            const opts = self.requestOptionsWithToken(&headers_slot);

            if (self.client.deleteObject(self.bucket, composed, opts)) |resp_val| {
                var resp = resp_val;
                defer resp.deinit();
                // S3 returns 204 No Content on successful delete (and
                // 204 also when the object didn't exist - DELETE is
                // idempotent). Treat either as success; only non-2xx
                // is an error.
                if (statusOk(resp.http_head.status)) return;
                try checkStatus("delete", composed, &resp);
                return;
            } else |err| {
                if (attempt < MAX_ATTEMPTS and isRetryableIoErr(err)) {
                    log.warn(
                        "S3 deleteObject '{s}' failed (attempt {d}/{d}): {} - rebuilding client and retrying",
                        .{ composed, attempt, MAX_ATTEMPTS, err },
                    );
                    backoffSleep(attempt);
                    self.rebuildClient();
                    continue;
                }
                log.err("S3 deleteObject '{s}' returned error: {}", .{ composed, err });
                return Error.Io;
            }
        }
    }
};

/// In-memory write buffer. Lifetime: created by `S3Store.create`,
/// either committed (PUT to final_key) or aborted (buffer freed).
pub const S3WriteHandle = struct {
    store: *S3Store,
    /// Owned by `store.allocator`. Mutable - `commitAs` replaces it.
    final_key: []u8,
    buffer: std.ArrayList(u8),
    closed: bool = false,

    pub fn write(self: *S3WriteHandle, data: []const u8) Error!void {
        std.debug.assert(!self.closed);
        self.buffer.appendSlice(self.store.allocator, data) catch return Error.OutOfMemory;
    }

    pub fn commit(self: *S3WriteHandle) Error!void {
        return self.commitInner(null);
    }

    /// Variant of `commit` where the destination key is supplied at
    /// close time rather than open time. Mirrors the PosixWriteHandle
    /// path used by the parquet flush worker (key includes to_pos that
    /// isn't known when the handle was opened).
    pub fn commitAs(
        self: *S3WriteHandle,
        store_root_unused: []const u8,
        new_key: []const u8,
    ) Error!void {
        // store_root is a posix-only concept; ignore it here. Same
        // signature as PosixWriteHandle.commitAs so the dispatch on
        // the union can be uniform.
        _ = store_root_unused;
        return self.commitInner(new_key);
    }

    fn commitInner(self: *S3WriteHandle, new_relative_key: ?[]const u8) Error!void {
        std.debug.assert(!self.closed);
        defer self.cleanup();

        if (new_relative_key) |new_rel| {
            if (!isValidKey(new_rel)) return Error.InvalidKey;
            const new_full = try self.store.composeKey(self.store.allocator, new_rel);
            self.store.allocator.free(self.final_key);
            self.final_key = new_full;
        }

        var attempt: u8 = 1;
        while (true) : (attempt += 1) {
            var headers_slot: [1]std.http.Header = undefined;
            const opts: s3.S3Client.PutObjectOptions = .{
                .request = self.store.requestOptionsWithToken(&headers_slot),
            };

            if (self.store.client.putObject(
                self.store.bucket,
                self.final_key,
                self.buffer.items,
                opts,
            )) |resp_val| {
                var resp = resp_val;
                defer resp.deinit();
                try checkStatus("put", self.final_key, &resp);
                return;
            } else |err| {
                if (attempt < MAX_ATTEMPTS and isRetryableIoErr(err)) {
                    log.warn(
                        "S3 putObject '{s}' failed (attempt {d}/{d}): {} - rebuilding client and retrying",
                        .{ self.final_key, attempt, MAX_ATTEMPTS, err },
                    );
                    backoffSleep(attempt);
                    self.store.rebuildClient();
                    continue;
                }
                log.err("S3 putObject '{s}' returned error: {}", .{ self.final_key, err });
                return Error.Io;
            }
        }
    }

    pub fn abort(self: *S3WriteHandle) void {
        if (self.closed) return;
        self.cleanup();
    }

    fn cleanup(self: *S3WriteHandle) void {
        self.buffer.deinit(self.store.allocator);
        self.store.allocator.free(self.final_key);
        self.closed = true;
    }
};

// ============================================================
// Helpers
// ============================================================

fn statusOk(status: std.http.Status) bool {
    const n: u16 = @intFromEnum(status);
    return n >= 200 and n < 300;
}

/// Mandatory status check - z3's raw-response ops (put/head/delete/
/// get) don't check internally. On non-2xx we log the diagnostic
/// payload (status + body preview) and map to a connector-side error.
fn checkStatus(op: []const u8, key: []const u8, resp: *const s3.S3Client.Response) Error!void {
    if (statusOk(resp.http_head.status)) return;

    const status_int: u16 = @intFromEnum(resp.http_head.status);
    const body_preview_end = @min(resp.body.len, 512);

    log.err(
        "S3 {s} '{s}' failed: status={d} body={s}",
        .{ op, key, status_int, resp.body[0..body_preview_end] },
    );

    if (status_int == 404) return Error.NotFound;
    if (status_int == 403 or status_int == 401) return Error.Unauthorized;
    return Error.Io;
}

/// Same key-validation as PosixStore: reject empty, absolute, or
/// `..`-containing keys; reject embedded NUL.
fn isValidKey(key: []const u8) bool {
    if (key.len == 0) return false;
    if (key[0] == '/') return false;
    if (std.mem.indexOf(u8, key, "..") != null) return false;
    for (key) |c| if (c == 0) return false;
    return true;
}

/// Parse RFC 1123 HTTP date ("Sun, 28 Apr 2026 13:39:15 GMT") to
/// Unix milliseconds. Returns 0 on any parse failure - the
/// connector's stale-cache predicate treats 0 as "always stale",
/// so failure is safe (cold-start) rather than wrong (false fresh).
fn parseHttpDateMs(raw: []const u8) i64 {
    // Format: "Sun, 28 Apr 2026 13:39:15 GMT"
    //          0000111111111122222222223333
    //          0123456789012345678901234567 (offsets)
    if (raw.len < 25) return 0;
    if (raw[3] != ',' or raw[4] != ' ') return 0;

    const day = std.fmt.parseInt(u8, raw[5..7], 10) catch return 0;
    const month: u8 = blk: {
        const m = raw[8..11];
        if (std.mem.eql(u8, m, "Jan")) break :blk 1;
        if (std.mem.eql(u8, m, "Feb")) break :blk 2;
        if (std.mem.eql(u8, m, "Mar")) break :blk 3;
        if (std.mem.eql(u8, m, "Apr")) break :blk 4;
        if (std.mem.eql(u8, m, "May")) break :blk 5;
        if (std.mem.eql(u8, m, "Jun")) break :blk 6;
        if (std.mem.eql(u8, m, "Jul")) break :blk 7;
        if (std.mem.eql(u8, m, "Aug")) break :blk 8;
        if (std.mem.eql(u8, m, "Sep")) break :blk 9;
        if (std.mem.eql(u8, m, "Oct")) break :blk 10;
        if (std.mem.eql(u8, m, "Nov")) break :blk 11;
        if (std.mem.eql(u8, m, "Dec")) break :blk 12;
        return 0;
    };
    const year = std.fmt.parseInt(u16, raw[12..16], 10) catch return 0;
    const hour = std.fmt.parseInt(u8, raw[17..19], 10) catch return 0;
    const minute = std.fmt.parseInt(u8, raw[20..22], 10) catch return 0;
    const second = std.fmt.parseInt(u8, raw[23..25], 10) catch return 0;

    // Unix-epoch days for given Y-M-D, civil_from_days style. Algorithm
    // is the standard one (Howard Hinnant's date.h derivation).
    const y: i32 = @as(i32, year) - @intFromBool(month <= 2);
    const era: i32 = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe: u32 = @intCast(y - era * 400);
    const m: u32 = if (month > 2) month - 3 else month + 9;
    const doy: u32 = (153 * m + 2) / 5 + day - 1;
    const doe: u32 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const days_since_epoch: i64 = @as(i64, era) * 146097 + @as(i64, doe) - 719468;

    const total_seconds: i64 = days_since_epoch * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
    return total_seconds * std.time.ms_per_s;
}

// ============================================================
// Tests - pure helpers only. Live S3 ops are exercised by the
// integration test additions in this branch.
// ============================================================

const testing = std.testing;

test "isValidKey: rejects bad keys" {
    try testing.expect(!isValidKey(""));
    try testing.expect(!isValidKey("/abs/path"));
    try testing.expect(!isValidKey("a/../b"));
    try testing.expect(!isValidKey("with\x00nul"));
}

test "isValidKey: accepts good keys" {
    try testing.expect(isValidKey("a"));
    try testing.expect(isValidKey("data/foo.parquet"));
    try testing.expect(isValidKey("state/current.json"));
    try testing.expect(isValidKey("ddl-cache/abc123.json.gz"));
}

test "parseHttpDateMs: known timestamp" {
    // 2026-04-28 13:39:15 UTC ≈ Unix 1777383555 s
    const got = parseHttpDateMs("Tue, 28 Apr 2026 13:39:15 GMT");
    try testing.expectEqual(@as(i64, 1777383555_000), got);
}

test "parseHttpDateMs: invalid input → 0" {
    try testing.expectEqual(@as(i64, 0), parseHttpDateMs(""));
    try testing.expectEqual(@as(i64, 0), parseHttpDateMs("not a date"));
    try testing.expectEqual(@as(i64, 0), parseHttpDateMs("Tue, 28 Xyz 2026 13:39:15 GMT"));
}

test "statusOk: 2xx is ok, others are not" {
    try testing.expect(statusOk(.ok));
    try testing.expect(statusOk(.no_content));
    try testing.expect(statusOk(.created));
    try testing.expect(!statusOk(.not_found));
    try testing.expect(!statusOk(.forbidden));
    try testing.expect(!statusOk(.internal_server_error));
}

test "isRetryableIoErr: transport-layer errors retry, contract errors do not" {
    // These match the z3 error set a flaky keep-alive pool produces.
    try testing.expect(isRetryableIoErr(error.ConnectionFailed));
    try testing.expect(isRetryableIoErr(error.SendFailed));
    try testing.expect(isRetryableIoErr(error.WriteFailed));
    try testing.expect(isRetryableIoErr(error.ReceiveFailed));
    try testing.expect(isRetryableIoErr(error.FlushFailed));
    try testing.expect(isRetryableIoErr(error.ReadFailed));

    // Contract / auth / programmer errors: retry never helps.
    try testing.expect(!isRetryableIoErr(error.InvalidUri));
    try testing.expect(!isRetryableIoErr(error.ConflictingCustomHeader));
    try testing.expect(!isRetryableIoErr(error.BodyLengthMismatch));
    try testing.expect(!isRetryableIoErr(error.OutOfMemory));
}
