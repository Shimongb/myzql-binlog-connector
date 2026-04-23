//! Cache Persistence Module
//!
//! Saves and loads the SchemaCache to/from local JSON files with
//! content-addressable filenames (SHA-256 based).
//!
//! File format: schema_cache_{checksum}.json
//! Where checksum = first 8 bytes of SHA-256, formatted as 16-char hex.

const std = @import("std");
const schema_cache_mod = @import("schema_cache.zig");
const SchemaCache = schema_cache_mod.SchemaCache;
const TableSchema = schema_cache_mod.TableSchema;
const ColumnInfo = schema_cache_mod.ColumnInfo;

const log = std.log.scoped(.cache_persistence);

/// Bumped from 1 → 2 when `saved_at_unix` was added to the top-level JSON.
/// v1 files are rejected by `deserializeCacheFromJson` (logged and skipped).
const CACHE_VERSION: u32 = 2;

/// Save the schema cache to a JSON file in the given directory.
/// Returns the filename used (content-addressable).
///
/// Filename hash is computed over the stable body (version + schemas)
/// only — `saved_at_unix` is wrapped on top for disk writes but excluded
/// from the hash so identical schemas produce identical filenames across
/// runs, enabling deduplication and predictable cleanup.
pub fn saveCache(allocator: std.mem.Allocator, cache: *SchemaCache, dir: []const u8, io: std.Io) ![]const u8 {
    // Serialize the stable (hashable) body.
    const stable_json = try serializeCacheToJson(allocator, cache);
    defer allocator.free(stable_json);

    // Checksum over the stable body only.
    const checksum = computeChecksum(stable_json);
    var checksum_hex: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (checksum[0..8], 0..) |byte, i| {
        checksum_hex[i * 2] = hex_chars[byte >> 4];
        checksum_hex[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    // Wrap with saved_at_unix for the on-disk payload, then gzip.
    const now_ts = std.Io.Clock.now(.real, io);
    const now_secs: i64 = @intCast(@divFloor(now_ts.nanoseconds, std.time.ns_per_s));
    const disk_json = try wrapWithSavedAt(allocator, stable_json, now_secs);
    defer allocator.free(disk_json);
    const disk_payload = try gzipCompress(allocator, disk_json);
    defer allocator.free(disk_payload);

    // Build full path — gzipped JSON going forward. Plain `.json` files
    // from older runs remain readable (magic-byte detection in loader).
    const full_path = try std.fmt.allocPrint(allocator, "{s}/schema_cache_{s}.json.gz", .{ dir, checksum_hex });
    errdefer allocator.free(full_path);

    // Ensure directory exists (best-effort mkdir -p via posix)
    makeDirPath(allocator, dir);

    // Write file using posix
    const path_z = try allocator.dupeZ(u8, full_path);
    defer allocator.free(path_z);

    const fd = std.posix.openat(std.posix.AT.FDCWD, path_z, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch |err| {
        log.err("failed to create cache file '{s}': {}", .{ full_path, err });
        return err;
    };
    defer _ = std.posix.system.close(fd);

    var written: usize = 0;
    while (written < disk_payload.len) {
        const rc = std.posix.system.write(fd, disk_payload[written..].ptr, disk_payload[written..].len);
        const signed_rc: isize = @bitCast(rc);
        if (signed_rc < 0) {
            log.err("failed to write cache file", .{});
            return error.WriteError;
        }
        written += @intCast(signed_rc);
    }

    // Write a pointer file so loadCache knows which file to load
    const latest_path = try std.fmt.allocPrint(allocator, "{s}/.schema_cache_latest", .{dir});
    defer allocator.free(latest_path);
    const latest_z = try allocator.dupeZ(u8, latest_path);
    defer allocator.free(latest_z);

    const latest_fd = std.posix.openat(std.posix.AT.FDCWD, latest_z, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch |err| {
        log.warn("failed to write .schema_cache_latest: {}", .{err});
        return full_path; // Non-fatal, cache was still saved
    };
    defer _ = std.posix.system.close(latest_fd);
    _ = std.posix.system.write(latest_fd, full_path.ptr, full_path.len);

    log.info("schema cache saved: {s} ({d} bytes gzip / {d} bytes raw, {d} tables)", .{ full_path, disk_payload.len, disk_json.len, cache.count() });

    // Best-effort cleanup of older content-addressable files. Runs AFTER
    // the new file + latest pointer are durably written, so a crash here
    // never leaves us without a usable cache.
    pruneOldCacheFiles(allocator, dir, DEFAULT_KEEP_N, io);

    return full_path;
}

/// How many historical cache files to retain per directory.
/// The most recent N (by mtime) survive a prune pass; the rest are
/// deleted. The file currently referenced by `.schema_cache_latest` is
/// additionally protected as a belt-and-suspenders guard.
const DEFAULT_KEEP_N: usize = 3;

/// Delete stale `schema_cache_*.json(.gz)` files in `dir`, keeping the
/// `keep_n` most recently modified and always preserving the file
/// referenced by `.schema_cache_latest`.
///
/// Best-effort: all errors are logged at debug level and swallowed, since
/// failing to prune old files must never break a successful save.
pub fn pruneOldCacheFiles(allocator: std.mem.Allocator, dir: []const u8, keep_n: usize, io: std.Io) void {
    var dir_handle = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |err| {
        log.debug("prune: couldn't open cache dir '{s}': {}", .{ dir, err });
        return;
    };
    defer dir_handle.close(io);

    const CacheFile = struct {
        name: []u8,
        mtime_ns: i96,
    };

    var files: std.ArrayList(CacheFile) = .empty;
    defer {
        for (files.items) |f| allocator.free(f.name);
        files.deinit(allocator);
    }

    var iter = dir_handle.iterate();
    while (iter.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "schema_cache_")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json") and
            !std.mem.endsWith(u8, entry.name, ".json.gz")) continue;

        const stat = dir_handle.statFile(io, entry.name, .{}) catch continue;

        const name_dup = allocator.dupe(u8, entry.name) catch continue;
        files.append(allocator, .{ .name = name_dup, .mtime_ns = stat.mtime.nanoseconds }) catch {
            allocator.free(name_dup);
            continue;
        };
    }

    if (files.items.len <= keep_n) return;

    std.mem.sort(CacheFile, files.items, {}, struct {
        fn lt(_: void, a: CacheFile, b: CacheFile) bool {
            return a.mtime_ns > b.mtime_ns; // newest first
        }
    }.lt);

    const latest_path_opt = readLatestPointer(allocator, dir) catch null;
    defer if (latest_path_opt) |p| allocator.free(p);
    const latest_basename: ?[]const u8 = if (latest_path_opt) |p|
        std.fs.path.basename(p)
    else
        null;

    var deleted: usize = 0;
    for (files.items[keep_n..]) |f| {
        if (latest_basename) |lb| {
            if (std.mem.eql(u8, f.name, lb)) continue;
        }
        dir_handle.deleteFile(io, f.name) catch |err| {
            log.debug("prune: failed to delete '{s}': {}", .{ f.name, err });
            continue;
        };
        deleted += 1;
    }

    if (deleted > 0) {
        log.info("prune: removed {d} stale schema cache file(s) from '{s}'", .{ deleted, dir });
    }
}

/// Load the schema cache from a specific file path.
pub fn loadCacheFromFile(allocator: std.mem.Allocator, cache: *SchemaCache, path: []const u8) !usize {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fd = std.posix.openat(std.posix.AT.FDCWD, path_z, .{}, 0) catch |err| {
        log.debug("cache file '{s}' not accessible: {}", .{ path, err });
        return 0;
    };
    defer _ = std.posix.system.close(fd);

    // Get file size
    const file_size: u64 = blk: {
        if (comptime @import("builtin").os.tag == .linux) {
            const linux = std.os.linux;
            var stx = std.mem.zeroes(linux.Statx);
            const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &stx);
            if (linux.errno(rc) != .SUCCESS) return 0;
            if (!stx.mask.SIZE) return 0;
            break :blk stx.size;
        } else {
            var stat: std.posix.system.Stat = undefined;
            if (std.posix.system.fstat(fd, &stat) != 0) return 0;
            break :blk @intCast(stat.size);
        }
    };

    if (file_size == 0 or file_size > 100 * 1024 * 1024) return 0;

    const json_data = try allocator.alloc(u8, file_size);
    defer allocator.free(json_data);

    var total_read: usize = 0;
    while (total_read < file_size) {
        const n = std.posix.read(fd, json_data[total_read..]) catch return 0;
        if (n == 0) break;
        total_read += n;
    }

    const raw_bytes = json_data[0..total_read];
    // Detect on-disk compression via magic bytes rather than filename so
    // that moving/renaming files (or legacy plain `.json` files written
    // before gzip landed) still round-trip correctly.
    var decoded: ?[]u8 = null;
    defer if (decoded) |d| allocator.free(d);
    const body: []const u8 = if (looksLikeGzip(raw_bytes)) blk: {
        decoded = gzipDecompress(allocator, raw_bytes) catch |err| {
            log.warn("gzip decompress failed for '{s}': {}", .{ path, err });
            return 0;
        };
        break :blk decoded.?;
    } else raw_bytes;

    const tables_loaded = deserializeCacheFromJson(allocator, cache, body) catch |err| {
        log.warn("failed to deserialize cache from '{s}': {}", .{ path, err });
        return 0;
    };

    log.info("schema cache loaded: {s} ({d} tables)", .{ path, tables_loaded });
    return tables_loaded;
}

/// Load the most recent schema cache from the given directory.
/// Reads the `.schema_cache_latest` pointer file to find the cache file.
/// `ttl_seconds` (opt-in): if non-null, the file's storage-layer mtime is
/// checked at bootstrap; anything older than `now - ttl` is treated as
/// stale and skipped (caller proceeds as a cold run). Null disables the
/// check.
pub fn loadCache(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    dir: []const u8,
    ttl_seconds: ?u64,
    io: std.Io,
) !usize {
    const cache_path = (try readLatestPointer(allocator, dir)) orelse {
        log.debug("no .schema_cache_latest in '{s}'", .{dir});
        return 0;
    };
    defer allocator.free(cache_path);

    // Staleness check — bootstrap-only. Uses storage-layer mtime so a
    // future S3 backend can answer the question with HEAD alone, no GET.
    if (ttl_seconds) |ttl| {
        if (try getFileMtime(io, cache_path)) |mtime| {
            const now_ts = std.Io.Clock.now(.real, io);
            const now: i64 = @intCast(@divFloor(now_ts.nanoseconds, std.time.ns_per_s));
            if (isStaleByTtl(mtime, now, ttl)) {
                log.warn(
                    "schema cache '{s}' is stale (age {d}s, TTL {d}s); cold-starting",
                    .{ cache_path, now - mtime, ttl },
                );
                return 0;
            }
        } else {
            // Backend didn't report mtime. Fallback path (saved_at_unix
            // inside the JSON) isn't wired up yet — see item 4 in
            // ROADMAP_COLUMN_AWARENESS.md. For now we accept the cache
            // rather than forcing a cold start on every run.
            log.debug("cache mtime unavailable; TTL check skipped for '{s}'", .{cache_path});
        }
    }

    return try loadCacheFromFile(allocator, cache, cache_path);
}

/// Read `.schema_cache_latest` and return the cache file path it points
/// to. Caller owns the returned slice. Returns null if the pointer file
/// is missing or empty.
fn readLatestPointer(allocator: std.mem.Allocator, dir: []const u8) !?[]u8 {
    const latest_path = try std.fmt.allocPrint(allocator, "{s}/.schema_cache_latest", .{dir});
    defer allocator.free(latest_path);

    const latest_z = try allocator.dupeZ(u8, latest_path);
    defer allocator.free(latest_z);

    const fd = std.posix.openat(std.posix.AT.FDCWD, latest_z, .{}, 0) catch return null;
    defer _ = std.posix.system.close(fd);

    var path_buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &path_buf) catch return null;
    if (n == 0) return null;

    const trimmed = std.mem.trim(u8, path_buf[0..n], "\n\r \t");
    if (trimmed.len == 0) return null;

    return try allocator.dupe(u8, trimmed);
}

/// Return the mtime (Unix seconds) of the file at `path`, or null if it
/// can't be determined. Isolated helper so a future S3 backend can swap
/// in a HEAD-based implementation without touching the TTL check itself.
fn getFileMtime(io: std.Io, path: []const u8) !?i64 {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    // stat.mtime.nanoseconds is i96 nanoseconds since the Unix epoch.
    return @intCast(@divFloor(stat.mtime.nanoseconds, std.time.ns_per_s));
}

/// Pure predicate — exposed for unit testing. `mtime` and `now` are Unix
/// seconds; returns true if the cache should be treated as stale.
pub fn isStaleByTtl(mtime: i64, now: i64, ttl_seconds: u64) bool {
    if (now <= mtime) return false; // clock skew: trust the cache
    const age: u64 = @intCast(now - mtime);
    return age > ttl_seconds;
}

/// Best-effort mkdir -p using posix.
fn makeDirPath(allocator: std.mem.Allocator, path: []const u8) void {
    const path_z = allocator.dupeZ(u8, path) catch return;
    defer allocator.free(path_z);

    if (comptime @import("builtin").os.tag == .linux) {
        _ = std.os.linux.mkdir(path_z, 0o755);
    } else {
        _ = std.posix.system.mkdir(path_z, 0o755);
    }
}

/// Serialize the cache to a JSON string.
fn serializeCacheToJson(allocator: std.mem.Allocator, cache: *SchemaCache) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Stable body — version + schemas only. `saved_at_unix` is wrapped on
    // top at write time by `wrapWithSavedAt`, so the content-addressable
    // checksum doesn't churn every save when schemas are unchanged.
    try buf.appendSlice(allocator, "{\"version\":");
    try appendInt(&buf, allocator, CACHE_VERSION);
    try buf.appendSlice(allocator, ",\"schemas\":{");

    var first_table = true;
    var iter = cache.iterator();
    while (iter.next()) |entry| {
        if (!first_table) try buf.append(allocator, ',');
        first_table = false;

        // Key: "db.table"
        try buf.append(allocator, '"');
        try appendJsonEscaped(&buf, allocator, entry.key_ptr.*);
        try buf.appendSlice(allocator, "\":{");

        const schema = entry.value_ptr;

        // columns_count
        try buf.appendSlice(allocator, "\"columns_count\":");
        try appendInt(&buf, allocator, schema.columns_count);

        // columns_types
        try buf.appendSlice(allocator, ",\"columns_types\":[");
        for (schema.columns_types, 0..) |t, i| {
            if (i > 0) try buf.append(allocator, ',');
            try appendInt(&buf, allocator, t);
        }
        try buf.append(allocator, ']');

        // schema_version
        try buf.appendSlice(allocator, ",\"schema_version\":\"");
        try appendJsonEscaped(&buf, allocator, schema.schema_version);
        try buf.append(allocator, '"');

        // resolved_columns
        if (schema.resolved_columns) |cols| {
            try buf.appendSlice(allocator, ",\"resolved_columns\":[");
            for (cols, 0..) |col, i| {
                if (i > 0) try buf.append(allocator, ',');
                try buf.append(allocator, '{');

                try buf.appendSlice(allocator, "\"column_name\":\"");
                try appendJsonEscaped(&buf, allocator, col.column_name);
                try buf.appendSlice(allocator, "\",\"column_type\":\"");
                try appendJsonEscaped(&buf, allocator, col.column_type);
                try buf.appendSlice(allocator, "\",\"is_nullable\":");
                try buf.appendSlice(allocator, if (col.is_nullable) "true" else "false");
                try buf.appendSlice(allocator, ",\"column_key\":\"");
                try appendJsonEscaped(&buf, allocator, col.column_key);
                try buf.append(allocator, '"');
                if (col.column_default) |d| {
                    try buf.appendSlice(allocator, ",\"column_default\":\"");
                    try appendJsonEscaped(&buf, allocator, d);
                    try buf.append(allocator, '"');
                } else {
                    try buf.appendSlice(allocator, ",\"column_default\":null");
                }
                try buf.appendSlice(allocator, ",\"column_extra\":\"");
                try appendJsonEscaped(&buf, allocator, col.column_extra);
                try buf.appendSlice(allocator, "\",\"ordinal_position\":");
                try appendInt(&buf, allocator, col.ordinal_position);

                try buf.append(allocator, '}');
            }
            try buf.append(allocator, ']');
        } else {
            try buf.appendSlice(allocator, ",\"resolved_columns\":null");
        }

        try buf.append(allocator, '}');
    }

    try buf.appendSlice(allocator, "}}");
    return try buf.toOwnedSlice(allocator);
}

/// Deserialize cache from JSON. Returns number of tables loaded.
fn deserializeCacheFromJson(allocator: std.mem.Allocator, cache: *SchemaCache, json_data: []const u8) !usize {
    // Use std.json for parsing
    const parsed = std.json.parseFromSlice(CacheJson, allocator, json_data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return error.ParseError;
    defer parsed.deinit();

    const root = parsed.value;

    // Version check
    if (root.version != CACHE_VERSION) {
        log.warn("cache version mismatch: expected {d}, got {d}", .{ CACHE_VERSION, root.version });
        return error.VersionMismatch;
    }

    var count: usize = 0;
    const keys = root.schemas.map.keys();
    const values = root.schemas.map.values();
    for (keys, values) |key, schema_json| {
        // Split key into db.table
        const dot_idx = std.mem.indexOf(u8, key, ".") orelse continue;
        const db = key[0..dot_idx];
        const table = key[dot_idx + 1 ..];

        // Build TableSchema
        const col_types = try allocator.alloc(u8, schema_json.columns_types.len);
        errdefer allocator.free(col_types);
        for (schema_json.columns_types, 0..) |t, i| {
            col_types[i] = @intCast(t);
        }

        const version = try allocator.dupe(u8, schema_json.schema_version);
        errdefer allocator.free(version);

        var resolved: ?[]ColumnInfo = null;
        if (schema_json.resolved_columns) |json_cols| {
            const cols = try allocator.alloc(ColumnInfo, json_cols.len);
            var initialized: usize = 0;
            errdefer {
                for (cols[0..initialized]) |*c| c.deinit(allocator);
                allocator.free(cols);
            }
            for (json_cols) |jc| {
                var col: ColumnInfo = .{
                    .column_name = try allocator.dupe(u8, jc.column_name),
                    .column_type = try allocator.dupe(u8, jc.column_type),
                    .is_nullable = jc.is_nullable,
                    .column_key = try allocator.dupe(u8, jc.column_key),
                    .column_default = if (jc.column_default) |d| try allocator.dupe(u8, d) else null,
                    .column_extra = try allocator.dupe(u8, jc.column_extra),
                    .ordinal_position = jc.ordinal_position,
                };
                errdefer col.deinit(allocator);
                try col.refreshParsedEnumSet(allocator);
                cols[initialized] = col;
                initialized += 1;
            }
            resolved = cols;
        }

        try cache.put(db, table, .{
            .columns_count = schema_json.columns_count,
            .columns_types = col_types,
            .schema_version = version,
            .resolved_columns = resolved,
        });
        count += 1;
    }

    return count;
}

/// Gzip-compress `data`. Caller owns the returned slice.
fn gzipCompress(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = try .initCapacity(allocator, data.len / 2 + 1024);
    errdefer output.deinit();

    var compress_window: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &output.writer,
        &compress_window,
        .gzip,
        .default,
    );
    // See parquet_writer.zig for the rationale on `finish` vs `flush`:
    // `flush` produces truncated streams that downstream readers reject.
    try compressor.writer.writeAll(data);
    try compressor.finish();

    return try output.toOwnedSlice();
}

/// Gzip-decompress `data`. Caller owns the returned slice. Caller should
/// pre-verify the gzip magic (`1f 8b`) at `data[0..2]`.
fn gzipDecompress(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var input_reader: std.Io.Reader = .fixed(data);
    var decompress_window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(
        &input_reader,
        .gzip,
        &decompress_window,
    );
    return try decompressor.reader.allocRemaining(allocator, .unlimited);
}

/// True if `data` starts with the gzip magic bytes (0x1f 0x8b).
fn looksLikeGzip(data: []const u8) bool {
    return data.len >= 2 and data[0] == 0x1f and data[1] == 0x8b;
}

/// Wrap a stable cache body with the current `saved_at_unix` timestamp.
/// The stable body is `{"version":N,"schemas":...}`; we splice in
/// `"saved_at_unix":T,` right after the opening brace so the final JSON
/// is `{"saved_at_unix":T,"version":N,"schemas":...}`.
///
/// `saved_at_unix` is deliberately kept OUT of the stable body so the
/// content-addressable filename hash doesn't churn on every save.
fn wrapWithSavedAt(allocator: std.mem.Allocator, stable_body: []const u8, saved_at: i64) ![]u8 {
    std.debug.assert(stable_body.len > 0 and stable_body[0] == '{');

    const inject = try std.fmt.allocPrint(allocator, "{{\"saved_at_unix\":{d},", .{saved_at});
    defer allocator.free(inject);

    const out = try allocator.alloc(u8, inject.len + stable_body.len - 1);
    @memcpy(out[0..inject.len], inject);
    @memcpy(out[inject.len..], stable_body[1..]);
    return out;
}

/// Compute SHA-256 checksum of data.
fn computeChecksum(data: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return hash;
}

/// Append an integer as decimal string.
fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const str = std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return;
    try buf.appendSlice(allocator, str);
}

/// Append a JSON-escaped string (escapes quotes and backslashes).
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

// JSON types for deserialization
const ColumnInfoJson = struct {
    column_name: []const u8,
    column_type: []const u8,
    is_nullable: bool,
    column_key: []const u8,
    column_default: ?[]const u8,
    column_extra: []const u8,
    ordinal_position: usize,
};

const TableSchemaJson = struct {
    columns_count: u64,
    columns_types: []const u64,
    schema_version: []const u8,
    resolved_columns: ?[]const ColumnInfoJson,
};

const CacheJson = struct {
    version: u32,
    /// Unix seconds when `saveCache` wrote this file. Fallback for
    /// staleness checks when the storage backend can't report mtime.
    /// Defaults to 0 when reading pre-v2 content via a compatibility path.
    saved_at_unix: i64 = 0,
    schemas: std.json.ArrayHashMap(TableSchemaJson),
};

// ============================================================
// Tests
// ============================================================

test "cache persistence round-trip" {
    const allocator = std.testing.allocator;

    // Create a cache with some data
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    // Add a table with resolved columns
    const col1 = ColumnInfo{
        .column_name = try allocator.dupe(u8, "id"),
        .column_type = try allocator.dupe(u8, "int"),
        .is_nullable = false,
        .column_key = try allocator.dupe(u8, "PRI"),
        .column_default = null,
        .column_extra = try allocator.dupe(u8, "auto_increment"),
        .ordinal_position = 1,
    };
    const col2 = ColumnInfo{
        .column_name = try allocator.dupe(u8, "status"),
        .column_type = try allocator.dupe(u8, "enum('active','inactive')"),
        .is_nullable = false,
        .column_key = try allocator.dupe(u8, ""),
        .column_default = try allocator.dupe(u8, "active"),
        .column_extra = try allocator.dupe(u8, ""),
        .ordinal_position = 2,
    };

    const cols = try allocator.alloc(ColumnInfo, 2);
    cols[0] = col1;
    cols[1] = col2;

    const types = try allocator.dupe(u8, &[_]u8{ 3, 254 });
    const version = try allocator.dupe(u8, "binlog.000001:100");

    try cache.put("testdb", "users", .{
        .columns_count = 2,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = cols,
    });

    // Serialize
    const json = try serializeCacheToJson(allocator, &cache);
    defer allocator.free(json);

    // Verify JSON is valid
    try std.testing.expect(json.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"testdb.users\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\"") != null);

    // Deserialize into a new cache
    var cache2 = SchemaCache.init(allocator, null);
    defer cache2.deinit();

    const count = try deserializeCacheFromJson(allocator, &cache2, json);
    try std.testing.expectEqual(@as(usize, 1), count);

    // Verify contents
    const loaded = cache2.get("testdb", "users");
    try std.testing.expect(loaded != null);
    try std.testing.expectEqual(@as(u64, 2), loaded.?.columns_count);

    const loaded_cols = loaded.?.resolved_columns.?;
    try std.testing.expectEqualStrings("id", loaded_cols[0].column_name);
    try std.testing.expectEqualStrings("enum('active','inactive')", loaded_cols[1].column_type);
    try std.testing.expect(!loaded_cols[0].is_nullable);
    try std.testing.expectEqualStrings("PRI", loaded_cols[0].column_key);
    try std.testing.expectEqualStrings("auto_increment", loaded_cols[0].column_extra);
    try std.testing.expectEqualStrings("active", loaded_cols[1].column_default.?);
}

test "computeChecksum" {
    const hash = computeChecksum("hello world");
    // SHA-256 of "hello world" starts with b94d27b9...
    try std.testing.expectEqual(@as(u8, 0xb9), hash[0]);
    try std.testing.expectEqual(@as(u8, 0x4d), hash[1]);
}

test "isStaleByTtl: fresh cache is not stale" {
    const mtime: i64 = 1_000_000_000;
    const now: i64 = 1_000_000_060; // 60s later
    try std.testing.expect(!isStaleByTtl(mtime, now, 3600));
}

test "isStaleByTtl: aged cache past TTL is stale" {
    const mtime: i64 = 1_000_000_000;
    const now: i64 = 1_000_007_200; // 2h later
    try std.testing.expect(isStaleByTtl(mtime, now, 3600)); // 1h TTL
}

test "isStaleByTtl: exactly at TTL is NOT stale (strict > semantics)" {
    const mtime: i64 = 1_000_000_000;
    const now: i64 = 1_000_003_600; // +3600s
    try std.testing.expect(!isStaleByTtl(mtime, now, 3600));
}

test "isStaleByTtl: clock skew (now < mtime) trusts the cache" {
    const mtime: i64 = 1_000_000_100;
    const now: i64 = 1_000_000_000;
    try std.testing.expect(!isStaleByTtl(mtime, now, 60));
}

test "stable body excludes saved_at_unix (hash stability)" {
    // The content-addressable filename hash is computed over the stable
    // body. saved_at_unix MUST NOT appear there, or identical schemas
    // would produce different filenames on every save.
    const allocator = std.testing.allocator;

    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    const types = try allocator.dupe(u8, &[_]u8{3});
    const version = try allocator.dupe(u8, "binlog.000001:100");
    try cache.put("testdb", "t1", .{
        .columns_count = 1,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = null,
    });

    const stable = try serializeCacheToJson(allocator, &cache);
    defer allocator.free(stable);

    try std.testing.expect(std.mem.indexOf(u8, stable, "\"saved_at_unix\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, stable, "\"version\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, stable, "\"schemas\":") != null);
}

test "checksum is stable across saves when schemas don't change" {
    const allocator = std.testing.allocator;

    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    const types = try allocator.dupe(u8, &[_]u8{3});
    const version = try allocator.dupe(u8, "binlog.000001:100");
    try cache.put("testdb", "t1", .{
        .columns_count = 1,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = null,
    });

    const stable_a = try serializeCacheToJson(allocator, &cache);
    defer allocator.free(stable_a);
    const stable_b = try serializeCacheToJson(allocator, &cache);
    defer allocator.free(stable_b);

    try std.testing.expectEqualSlices(u8, stable_a, stable_b);
    try std.testing.expectEqualSlices(u8, &computeChecksum(stable_a), &computeChecksum(stable_b));
}

test "pruneOldCacheFiles keeps the N newest and protects the latest pointer" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Create a temp dir with 5 cache files of increasing mtime.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try allocator.dupe(u8, path_buf[0..path_len]);
    defer allocator.free(dir_path);

    const names = [_][]const u8{
        "schema_cache_aaaaaaaaaaaaaaaa.json",
        "schema_cache_bbbbbbbbbbbbbbbb.json",
        "schema_cache_cccccccccccccccc.json",
        "schema_cache_dddddddddddddddd.json",
        "schema_cache_eeeeeeeeeeeeeeee.json",
    };
    for (names) |n| {
        const f = try tmp.dir.createFile(io, n, .{});
        try f.writePositionalAll(io, "{}", 0);
        f.close(io);
        // Nudge mtime ordering — sleep a bit so newer files really are newer.
        try std.Io.sleep(io, .fromMilliseconds(10), .real);
    }

    // Point `.schema_cache_latest` at the OLDEST file to verify the prune
    // guard protects it even though it's not in the "newest N" set.
    const latest_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, names[0] });
    defer allocator.free(latest_path);
    const latest_file = try tmp.dir.createFile(io, ".schema_cache_latest", .{});
    try latest_file.writePositionalAll(io, latest_path, 0);
    latest_file.close(io);

    // Keep the 2 newest; expect the 2 oldest NON-protected to be deleted.
    pruneOldCacheFiles(allocator, dir_path, 2, io);

    // The 2 newest (names[3], names[4]) must still exist.
    _ = try tmp.dir.statFile(io, names[3], .{});
    _ = try tmp.dir.statFile(io, names[4], .{});
    // The protected (oldest but pointed to by latest) must still exist.
    _ = try tmp.dir.statFile(io, names[0], .{});
    // The middle two should be gone.
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, names[1], .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, names[2], .{}));
}

test "gzip round-trip preserves JSON content" {
    const allocator = std.testing.allocator;

    const original = "{\"version\":2,\"saved_at_unix\":1000,\"schemas\":{\"db.t\":{\"columns_count\":1}}}";

    const compressed = try gzipCompress(allocator, original);
    defer allocator.free(compressed);

    try std.testing.expect(looksLikeGzip(compressed));

    const roundtrip = try gzipDecompress(allocator, compressed);
    defer allocator.free(roundtrip);

    try std.testing.expectEqualStrings(original, roundtrip);
}

test "looksLikeGzip accepts magic and rejects plain JSON" {
    try std.testing.expect(looksLikeGzip(&[_]u8{ 0x1f, 0x8b, 0x08, 0x00 }));
    try std.testing.expect(!looksLikeGzip("{\"version\":2}"));
    try std.testing.expect(!looksLikeGzip(&[_]u8{0x1f})); // too short
    try std.testing.expect(!looksLikeGzip(""));
}

test "loader transparently decodes gzipped payload" {
    // End-to-end: save via saveCache (which gzips), then load via
    // loadCache (which detects gzip via magic bytes and decompresses).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try allocator.dupe(u8, path_buf[0..path_len]);
    defer allocator.free(dir_path);

    // Build a minimal but valid cache and save it — this exercises the
    // gzip-write path end-to-end.
    var cache_out = SchemaCache.init(allocator, null);
    defer cache_out.deinit();
    const types = try allocator.dupe(u8, &[_]u8{3});
    const version = try allocator.dupe(u8, "binlog.000001:100");
    try cache_out.put("testdb", "t1", .{
        .columns_count = 1,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = null,
    });
    const saved_path = try saveCache(allocator, &cache_out, dir_path, io);
    defer allocator.free(saved_path);

    // Filename suffix is the contract consumers rely on.
    try std.testing.expect(std.mem.endsWith(u8, saved_path, ".json.gz"));

    // Now load it back — loader must detect gzip via magic bytes and
    // decompress. If this succeeds the on-disk payload really is gzip.
    var cache_in = SchemaCache.init(allocator, null);
    defer cache_in.deinit();
    const loaded = try loadCache(allocator, &cache_in, dir_path, null, io);
    try std.testing.expectEqual(@as(usize, 1), loaded);
    try std.testing.expect(cache_in.get("testdb", "t1") != null);
}

test "pruneOldCacheFiles is a no-op when files <= keep_n" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try allocator.dupe(u8, path_buf[0..path_len]);
    defer allocator.free(dir_path);

    const f = try tmp.dir.createFile(io, "schema_cache_0000000000000000.json", .{});
    try f.writePositionalAll(io, "{}", 0);
    f.close(io);

    pruneOldCacheFiles(allocator, dir_path, 3, io);

    _ = try tmp.dir.statFile(io, "schema_cache_0000000000000000.json", .{});
}

test "wrapWithSavedAt injects field without disturbing schema body" {
    const allocator = std.testing.allocator;

    const stable = "{\"version\":2,\"schemas\":{}}";
    const wrapped = try wrapWithSavedAt(allocator, stable, 1234567890);
    defer allocator.free(wrapped);

    try std.testing.expectEqualStrings(
        "{\"saved_at_unix\":1234567890,\"version\":2,\"schemas\":{}}",
        wrapped,
    );

    // And it must parse back cleanly through the CacheJson schema.
    const parsed = try std.json.parseFromSlice(CacheJson, allocator, wrapped, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1234567890), parsed.value.saved_at_unix);
    try std.testing.expectEqual(@as(u32, 2), parsed.value.version);
}
