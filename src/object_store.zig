//! Storage-backend abstraction.
//!
//! Today: `PosixStore` - filesystem-backed, wraps the raw `std.posix` calls
//! the rest of the codebase already uses. Later (Track 3 of the Lambda
//! vision doc): `S3Store` - HTTPS via the forked z3 SDK. Both implement
//! the same small surface so parquet-writer and schema-cache can be
//! migrated once and run unchanged against either backend.
//!
//! Surface:
//! - `create(key) -> WriteHandle` - streaming writer, commits on close
//! - `read(key) -> []u8`          - full read; fine for cache/state
//! - `head(key) -> HeadInfo`      - size + last-modified
//! - `delete(key)`                - best-effort remove
//!
//! Not part of the interface:
//! - Directory semantics, random-access seek, rename, file modes.
//! - `list(prefix)` - schema-cache pruning used to motivate it, but
//!   content-addressable naming retires that use case.
//!
//! Write atomicity: PosixStore writes to a `<key>.<pid>.<ns>.tmp` sidecar
//! and `rename(2)`s on `commit()`. A partial write or a process crash
//! leaves the sidecar behind (and the final key unchanged), not a
//! half-written visible file. `abort()` cleans up the sidecar.
//!
//! Parent directories are created lazily (`mkdir -p`-style) on the first
//! `create()` for a given subtree, keeping the interface symmetrical with
//! S3 where directories don't exist at all.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const s3_store = @import("s3_store.zig");
const clock = @import("clock.zig");

const log = std.log.scoped(.object_store);

/// Canonical error set. Narrow on purpose - callers want "did it work"
/// first and "why" second; mapping POSIX errno and S3 HTTP status families
/// into this small set gives us a common vocabulary.
pub const Error = error{
    NotFound,
    AlreadyExists,
    Unauthorized,
    InvalidKey,
    OutOfMemory,
    Io,
};

pub const HeadInfo = struct {
    size: u64,
    /// Unix milliseconds since epoch, UTC. Matches S3 `LastModified`
    /// granularity; POSIX mtime supplies the value.
    last_modified_ms: i64,
};

/// In-flight write. Data goes through `write()`; `commit()` makes it
/// visible atomically; `abort()` discards the sidecar. Not thread-safe.
pub const WriteHandle = union(enum) {
    posix: PosixWriteHandle,
    s3: s3_store.S3WriteHandle,

    pub fn write(self: *WriteHandle, data: []const u8) Error!void {
        return switch (self.*) {
            .posix => |*h| h.write(data),
            .s3 => |*h| h.write(data),
        };
    }

    pub fn commit(self: *WriteHandle) Error!void {
        return switch (self.*) {
            .posix => |*h| h.commit(),
            .s3 => |*h| h.commit(),
        };
    }

    pub fn abort(self: *WriteHandle) void {
        switch (self.*) {
            .posix => |*h| h.abort(),
            .s3 => |*h| h.abort(),
        }
    }
};

/// Dispatch wrapper. Tagged union: posix (filesystem) or s3 (HTTPS via
/// the z3 SDK). Adding backends is additive - extend the union and add
/// switch arms here.
pub const ObjectStore = union(enum) {
    posix: PosixStore,
    s3: s3_store.S3Store,

    pub fn create(self: *ObjectStore, key: []const u8) Error!WriteHandle {
        return switch (self.*) {
            .posix => |*s| .{ .posix = try s.create(key) },
            .s3 => |*s| .{ .s3 = try s.create(key) },
        };
    }

    pub fn read(self: *ObjectStore, allocator: std.mem.Allocator, key: []const u8) Error![]u8 {
        return switch (self.*) {
            .posix => |*s| s.read(allocator, key),
            .s3 => |*s| s.read(allocator, key),
        };
    }

    pub fn head(self: *ObjectStore, key: []const u8) Error!HeadInfo {
        return switch (self.*) {
            .posix => |*s| s.head(key),
            .s3 => |*s| s.head(key),
        };
    }

    pub fn delete(self: *ObjectStore, key: []const u8) Error!void {
        return switch (self.*) {
            .posix => |*s| s.delete(key),
            .s3 => |*s| s.delete(key),
        };
    }

    /// Commit a streaming write under a destination key that can only
    /// be computed at close time (e.g. parquet filenames whose to_pos
    /// component isn't known until the last batch is written). Overrides
    /// the handle's final key, ensures the new parent dir exists (posix)
    /// or composes the new key under the S3 prefix (s3), then commits.
    /// The handle becomes unusable after the call - same lifecycle as
    /// `commit`/`abort`.
    ///
    /// Cross-backend handle/store pairs (e.g. posix handle with s3
    /// store) are programmer errors - the handle was created by the
    /// store, so they always match. We `unreachable` rather than
    /// converting at runtime.
    pub fn commitHandleAs(self: *ObjectStore, handle: *WriteHandle, new_key: []const u8) Error!void {
        return switch (handle.*) {
            .posix => |*h| switch (self.*) {
                .posix => |*s| h.commitAs(s.root_dir, new_key),
                .s3 => unreachable,
            },
            .s3 => |*h| switch (self.*) {
                // S3WriteHandle.commitAs ignores its first arg (posix-only
                // concept). Pass the bucket for symmetry; it's not used.
                .s3 => |*s| h.commitAs(s.bucket, new_key),
                .posix => unreachable,
            },
        };
    }

    /// Writability probe - round-trips a tiny self-deleting object to
    /// catch permission / route / IAM-policy gaps at startup, before
    /// any real state-touching writes happen. Cheap (one create+commit+
    /// delete cycle, ~ms posix / sub-second S3) and worth it: a
    /// state-lock failure 30s later is much harder to debug than an
    /// `[OUTPUT_NOT_WRITABLE]` line at startup.
    pub fn probeWritable(self: *ObjectStore, allocator: std.mem.Allocator) Error!void {
        var key_buf: [64]u8 = undefined;
        const probe_key = std.fmt.bufPrint(
            &key_buf,
            ".probe-{d}",
            .{clock.nowMs()},
        ) catch return Error.Io;

        var h = try self.create(probe_key);
        errdefer h.abort();
        try h.write("probe");
        try h.commit();

        self.delete(probe_key) catch |err| {
            log.warn(
                "probe-write succeeded but delete failed (orphan key '{s}' may need manual cleanup): {}",
                .{ probe_key, err },
            );
        };
        _ = allocator; // currently unused; kept on signature for future per-call alloc needs
    }
};

// =================================================================
// PosixStore
// =================================================================

pub const PosixStore = struct {
    allocator: std.mem.Allocator,
    /// Caller-owned; lifetime >= store. Must be absolute or valid relative
    /// path; keys are resolved as `root_dir/key`.
    root_dir: []const u8,

    pub fn init(allocator: std.mem.Allocator, root_dir: []const u8) PosixStore {
        return .{ .allocator = allocator, .root_dir = root_dir };
    }

    pub fn create(self: *PosixStore, key: []const u8) Error!PosixWriteHandle {
        if (!isValidKey(key)) return Error.InvalidKey;

        const final_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.root_dir, key }) catch
            return Error.OutOfMemory;
        errdefer self.allocator.free(final_path);

        try ensureParentDir(self.allocator, final_path);

        // Sidecar name: <final>.<pid>.<nanos>.tmp - collision-free under
        // concurrent writers from multiple processes on the same key.
        const pid: i32 = @intCast(posix.system.getpid());
        const temp_path = std.fmt.allocPrint(
            self.allocator,
            "{s}.{d}.{d}.tmp",
            .{ final_path, pid, clock.nanoTimestamp() },
        ) catch return Error.OutOfMemory;
        errdefer self.allocator.free(temp_path);

        const temp_path_z = self.allocator.dupeZ(u8, temp_path) catch return Error.OutOfMemory;
        defer self.allocator.free(temp_path_z);

        const fd = posix.openat(posix.AT.FDCWD, temp_path_z, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
        }, 0o644) catch |err| return mapOpenErr(err);

        return .{
            .fd = fd,
            .temp_path = temp_path,
            .final_path = final_path,
            .allocator = self.allocator,
        };
    }

    pub fn read(self: *PosixStore, allocator: std.mem.Allocator, key: []const u8) Error![]u8 {
        if (!isValidKey(key)) return Error.InvalidKey;

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.root_dir, key }) catch
            return Error.InvalidKey;
        path_buf[full.len] = 0;
        const path_z: [:0]const u8 = @ptrCast(path_buf[0..full.len :0]);

        const fd = posix.openat(posix.AT.FDCWD, path_z, .{
            .ACCMODE = .RDONLY,
        }, 0) catch |err| return mapOpenErr(err);
        defer _ = posix.system.close(fd);

        const size = statSize(fd) catch return Error.Io;
        const buf = allocator.alloc(u8, size) catch return Error.OutOfMemory;
        errdefer allocator.free(buf);

        var total: usize = 0;
        while (total < buf.len) {
            const n = posix.read(fd, buf[total..]) catch return Error.Io;
            if (n == 0) break; // unexpected EOF - return what we have
            total += n;
        }
        if (total != buf.len) {
            // File size changed mid-read; truncate to what we got so the
            // caller sees a coherent slice.
            const shrunk = allocator.realloc(buf, total) catch buf[0..total];
            return shrunk;
        }
        return buf;
    }

    pub fn head(self: *PosixStore, key: []const u8) Error!HeadInfo {
        if (!isValidKey(key)) return Error.InvalidKey;

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.root_dir, key }) catch
            return Error.InvalidKey;
        path_buf[full.len] = 0;
        const path_z: [:0]const u8 = @ptrCast(path_buf[0..full.len :0]);

        const fd = posix.openat(posix.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0) catch |err|
            return mapOpenErr(err);
        defer _ = posix.system.close(fd);

        return statHead(fd);
    }

    pub fn delete(self: *PosixStore, key: []const u8) Error!void {
        if (!isValidKey(key)) return Error.InvalidKey;

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.root_dir, key }) catch
            return Error.InvalidKey;
        path_buf[full.len] = 0;
        const path_z: [:0]const u8 = @ptrCast(path_buf[0..full.len :0]);

        const rc = posix.system.unlink(path_z);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return Error.NotFound,
            .ACCES, .PERM => return Error.Unauthorized,
            else => return Error.Io,
        }
    }
};

pub const PosixWriteHandle = struct {
    fd: posix.fd_t,
    temp_path: []u8, // allocator-owned; freed on commit/abort
    final_path: []u8, // allocator-owned; freed on commit/abort
    allocator: std.mem.Allocator,
    closed: bool = false,

    pub fn write(self: *PosixWriteHandle, data: []const u8) Error!void {
        std.debug.assert(!self.closed);
        var index: usize = 0;
        while (index < data.len) {
            const rc = posix.system.write(self.fd, data.ptr + index, data.len - index);
            const errno = posix.errno(rc);
            if (errno != .SUCCESS) {
                switch (errno) {
                    .INTR, .AGAIN => continue,
                    .NOSPC, .IO => return Error.Io,
                    else => return Error.Io,
                }
            }
            const written: usize = @intCast(rc);
            if (written == 0) return Error.Io;
            index += written;
        }
    }

    pub fn commit(self: *PosixWriteHandle) Error!void {
        std.debug.assert(!self.closed);
        _ = posix.system.close(self.fd);
        self.closed = true;

        // rename(2) is atomic when source and destination are on the same
        // filesystem - which they always are here since both live under
        // the store's root_dir.
        const temp_z = self.allocator.dupeZ(u8, self.temp_path) catch {
            self.cleanupPaths();
            return Error.OutOfMemory;
        };
        defer self.allocator.free(temp_z);
        const final_z = self.allocator.dupeZ(u8, self.final_path) catch {
            self.cleanupPaths();
            return Error.OutOfMemory;
        };
        defer self.allocator.free(final_z);

        const rename_rc = posix.system.rename(temp_z, final_z);
        const rename_errno = posix.errno(rename_rc);
        if (rename_errno != .SUCCESS) {
            // Attempt to clean up the orphaned sidecar so we don't leave
            // littered temp files on repeated failures.
            _ = posix.system.unlink(temp_z);
            self.cleanupPaths();
            return switch (rename_errno) {
                .ACCES, .PERM => Error.Unauthorized,
                else => Error.Io,
            };
        }

        self.cleanupPaths();
    }

    pub fn abort(self: *PosixWriteHandle) void {
        if (!self.closed) {
            _ = posix.system.close(self.fd);
            self.closed = true;
        }
        const temp_z = self.allocator.dupeZ(u8, self.temp_path) catch {
            self.cleanupPaths();
            return;
        };
        defer self.allocator.free(temp_z);
        _ = posix.system.unlink(temp_z);
        self.cleanupPaths();
    }

    /// Variant of `commit` where the destination key is supplied at
    /// close time rather than open time. Used when the final filename
    /// depends on data not known when the handle was created (e.g.
    /// parquet flush boundaries that include `to_pos`).
    ///
    /// Mutates `final_path` in place to point at `{store_root}/{new_key}`,
    /// ensures the new parent directory exists, then performs the same
    /// atomic rename as `commit`.
    pub fn commitAs(
        self: *PosixWriteHandle,
        store_root: []const u8,
        new_key: []const u8,
    ) Error!void {
        if (!isValidKey(new_key)) return Error.InvalidKey;

        const new_final = std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ store_root, new_key },
        ) catch return Error.OutOfMemory;
        // Free the old final_path now and replace it; commit() reads
        // self.final_path so the swap must happen first.
        self.allocator.free(self.final_path);
        self.final_path = new_final;

        // The new key may live under a different subdir than the original
        // (e.g. `data/...` vs the original placeholder dir). Lazy-mkdir
        // matches the behaviour of `create()`.
        try ensureParentDir(self.allocator, self.final_path);

        return self.commit();
    }

    fn cleanupPaths(self: *PosixWriteHandle) void {
        self.allocator.free(self.temp_path);
        self.allocator.free(self.final_path);
    }
};

// =================================================================
// Helpers
// =================================================================

fn isValidKey(key: []const u8) bool {
    if (key.len == 0) return false;
    if (key[0] == '/') return false; // keys are relative to root_dir
    if (std.mem.indexOf(u8, key, "..") != null) return false; // no parent escape
    for (key) |c| {
        if (c == 0) return false; // NULs would break c-string conversion
    }
    return true;
}

fn ensureParentDir(allocator: std.mem.Allocator, full_path: []const u8) Error!void {
    const parent = std.fs.path.dirname(full_path) orelse return;
    if (parent.len == 0) return;

    // mkdir -p, walking from root toward the leaf. Errors on PathAlreadyExists
    // are benign; anything else is bubbled.
    var i: usize = 0;
    while (i < parent.len) {
        // Advance i to the next '/' (or end) to create progressively deeper paths.
        const next_slash = std.mem.indexOfScalarPos(u8, parent, i + 1, '/') orelse parent.len;
        const segment = parent[0..next_slash];
        i = next_slash;

        if (segment.len == 0) continue;

        const segment_z = allocator.dupeZ(u8, segment) catch return Error.OutOfMemory;
        defer allocator.free(segment_z);

        const rc = posix.system.mkdir(segment_z, 0o755);
        const errno = posix.errno(rc);
        switch (errno) {
            .SUCCESS, .EXIST => {},
            .ACCES, .PERM => return Error.Unauthorized,
            else => return Error.Io,
        }
    }
}

fn mapOpenErr(err: anyerror) Error {
    return switch (err) {
        error.FileNotFound => Error.NotFound,
        error.PathAlreadyExists => Error.AlreadyExists,
        error.AccessDenied => Error.Unauthorized,
        else => Error.Io,
    };
}

/// Return `{size, mtime_ms}` for an already-open fd, portably.
fn statHead(fd: posix.fd_t) Error!HeadInfo {
    if (comptime @import("builtin").os.tag == .linux) {
        const linux = std.os.linux;
        var stx = std.mem.zeroes(linux.Statx);
        const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true, .MTIME = true }, &stx);
        if (linux.errno(rc) != .SUCCESS) return Error.Io;
        const mtime_ms: i64 = @as(i64, stx.mtime.sec) * std.time.ms_per_s +
            @divTrunc(@as(i64, stx.mtime.nsec), std.time.ns_per_ms);
        return .{ .size = stx.size, .last_modified_ms = mtime_ms };
    } else {
        var stat: posix.system.Stat = undefined;
        if (posix.system.fstat(fd, &stat) != 0) return Error.Io;
        // Darwin exposes mtimespec/sec + nsec; posix.system.Stat is the
        // portable wrapper with `.mtime()` returning a timespec-like pair.
        const ts = stat.mtime();
        const mtime_ms: i64 = @as(i64, ts.sec) * std.time.ms_per_s +
            @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
        const size: u64 = @intCast(stat.size);
        return .{ .size = size, .last_modified_ms = mtime_ms };
    }
}

fn statSize(fd: posix.fd_t) !usize {
    const info = try statHead(fd);
    return @intCast(info.size);
}

// =================================================================
// Tests
// =================================================================

test "isValidKey rejects absolute paths and parent escapes" {
    try std.testing.expect(isValidKey("foo/bar.json"));
    try std.testing.expect(isValidKey("schema-cache/abcd.json.gz"));
    try std.testing.expect(!isValidKey(""));
    try std.testing.expect(!isValidKey("/etc/passwd"));
    try std.testing.expect(!isValidKey("../escape"));
    try std.testing.expect(!isValidKey("ok/../also-escape"));
    try std.testing.expect(!isValidKey("contains\x00nul"));
}

test "PosixStore: create + write + commit roundtrip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    var h = try store.create("hello.txt");
    try h.write("hello, ");
    try h.write("world");
    try h.commit();

    const got = try store.read(allocator, "hello.txt");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("hello, world", got);
}

test "PosixStore: abort leaves no visible file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    var h = try store.create("transient.txt");
    try h.write("some bytes");
    h.abort();

    try std.testing.expectError(Error.NotFound, store.read(allocator, "transient.txt"));
}

test "PosixStore: lazy mkdir -p on nested keys" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    var h = try store.create("a/b/c/deep.json");
    try h.write("{}");
    try h.commit();

    const got = try store.read(allocator, "a/b/c/deep.json");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("{}", got);
}

test "PosixStore: head returns size and mtime" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    const payload = "0123456789";
    var h = try store.create("meta.bin");
    try h.write(payload);
    try h.commit();

    const info = try store.head("meta.bin");
    try std.testing.expectEqual(@as(u64, payload.len), info.size);
    // mtime_ms should be within a reasonable window of now.
    const now_ms = clock.nowMs();
    try std.testing.expect(info.last_modified_ms > now_ms - 60_000);
    try std.testing.expect(info.last_modified_ms <= now_ms + 60_000);
}

test "PosixStore: delete removes existing key and errors on missing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    var h = try store.create("gone.txt");
    try h.write("x");
    try h.commit();

    try store.delete("gone.txt");
    try std.testing.expectError(Error.NotFound, store.head("gone.txt"));
    try std.testing.expectError(Error.NotFound, store.delete("gone.txt"));
}

test "PosixStore: read of missing key returns NotFound" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store = PosixStore.init(allocator, root_owned);

    try std.testing.expectError(Error.NotFound, store.read(allocator, "never-written.bin"));
    try std.testing.expectError(Error.NotFound, store.head("never-written.bin"));
}

test "PosixStore: invalid key rejected" {
    const allocator = std.testing.allocator;

    var store = PosixStore.init(allocator, "/tmp");

    try std.testing.expectError(Error.InvalidKey, store.read(allocator, "/absolute"));
    try std.testing.expectError(Error.InvalidKey, store.head("../escape"));
    try std.testing.expectError(Error.InvalidKey, store.delete(""));
}

test "ObjectStore: dispatches through tagged union" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store: ObjectStore = .{ .posix = PosixStore.init(allocator, root_owned) };

    var h = try store.create("via-union.txt");
    try h.write("union dispatch works");
    try h.commit();

    const got = try store.read(allocator, "via-union.txt");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("union dispatch works", got);

    const info = try store.head("via-union.txt");
    try std.testing.expectEqual(@as(u64, "union dispatch works".len), info.size);

    try store.delete("via-union.txt");
    try std.testing.expectError(Error.NotFound, store.head("via-union.txt"));
}

test "ObjectStore: commitHandleAs renames to a different final key on commit" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store: ObjectStore = .{ .posix = PosixStore.init(allocator, root_owned) };

    // Open with a placeholder key, then commit to a different one - the
    // exact pattern the parquet flush worker uses when to_pos is unknown
    // at file-open time.
    var h = try store.create("placeholder.partial");
    try h.write("body");
    try store.commitHandleAs(&h, "data/final.parquet");

    // The committed-to key exists with the right content...
    const got = try store.read(allocator, "data/final.parquet");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("body", got);

    // ...and the placeholder is NOT visible (the temp file was renamed,
    // not duplicated).
    try std.testing.expectError(Error.NotFound, store.head("placeholder.partial"));
}

test "ObjectStore: commitHandleAs rejects an invalid destination key" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store: ObjectStore = .{ .posix = PosixStore.init(allocator, root_owned) };

    var h = try store.create("good.partial");
    try h.write("body");
    // Path-traversal attempt rejected just like at create-time.
    try std.testing.expectError(Error.InvalidKey, store.commitHandleAs(&h, "../bad.parquet"));
    // Handle is unusable after a failed commit attempt; clean up the
    // sidecar so we don't leak a temp file.
    h.abort();
}

test "ObjectStore: probeWritable round-trips on PosixStore" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root_owned = try allocator.dupe(u8, path_buf[0..root_len]);
    defer allocator.free(root_owned);

    var store: ObjectStore = .{ .posix = PosixStore.init(allocator, root_owned) };

    // Round-trip without error: create, write, commit, delete.
    try store.probeWritable(allocator);

    // Repeat probes use unique timestamped keys; two in a row should
    // both succeed independently.
    try store.probeWritable(allocator);
}
