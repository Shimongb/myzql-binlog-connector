//! Cache Persistence Module
//!
//! Saves and loads the SchemaCache through the ObjectStore abstraction.
//! Content-addressable: the filename is the first 16 hex chars of SHA-256
//! over the stable JSON body (version + schemas only; `saved_at_unix` is
//! wrapped on top but excluded from the hash so identical schemas produce
//! identical keys across runs).
//!
//! Key layout under the store's root:
//!   {16-hex-hash}.json.gz   — the cache payload
//!
//! Identical schemas → identical keys → overwrite (not a new file); on S3
//! that's ~90-99% fewer writes. Different schemas → new key; no separate
//! index file is maintained because the content *is* the index. Stale
//! keys orphan naturally on schema change — S3 lifecycle sweeps them
//! downstream; on PosixStore a handful of stale files accumulates, which
//! is fine.
//!
//! The cache key for the current run is recorded in the binlog checkpoint
//! (`{output_dir}/state/last_checkpoint.json`); see `src/state.zig`. There
//! is no longer a free-standing latest-pointer file — load callers receive
//! the key from the checkpoint and pass it to `loadCacheFromKey`.

const std = @import("std");
const object_store = @import("object_store.zig");
const schema_cache_mod = @import("schema_cache.zig");
const SchemaCache = schema_cache_mod.SchemaCache;
const TableSchema = schema_cache_mod.TableSchema;
const ColumnInfo = schema_cache_mod.ColumnInfo;

const log = std.log.scoped(.cache_persistence);

/// Bumped when the stable body format changes.
/// v1: initial
/// v2: added top-level `saved_at_unix` (wrapped; not part of the hash)
/// On load, older versions are rejected by `deserializeCacheFromJson` and
/// the connector cold-starts.
const CACHE_VERSION: u32 = 2;

/// Save the schema cache through the `ObjectStore`. Returns the key
/// used (content-addressable). Caller owns the returned slice.
///
/// Filename hash is computed over the stable body (version + schemas)
/// only — `saved_at_unix` is wrapped on top for disk writes but excluded
/// from the hash so identical schemas produce identical keys across
/// runs, enabling overwrite-on-unchanged (dedup) semantics.
///
/// Writes are atomic at the ObjectStore layer (sidecar + rename for
/// PosixStore; single PUT / multipart for S3Store later). The returned
/// key is recorded by the caller in the binlog checkpoint so the next
/// run can find the cache without a free-standing pointer file.
pub fn saveCache(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    store: *object_store.ObjectStore,
    io: std.Io,
) ![]const u8 {
    // Serialize the stable (hashable) body. Table keys are sorted inside
    // `serializeCacheToJson` so the hash is deterministic across runs.
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

    // Key under the store: {hash}.json.gz (the store root is already
    // the ddl-cache subdir of output_dir; no inner namespace needed).
    const cache_key = try std.fmt.allocPrint(
        allocator,
        "{s}.json.gz",
        .{checksum_hex},
    );
    errdefer allocator.free(cache_key);

    // Write the cache file via ObjectStore (atomic).
    {
        var h = store.create(cache_key) catch |err| {
            log.err("failed to create cache key '{s}': {}", .{ cache_key, err });
            return err;
        };
        errdefer h.abort();
        try h.write(disk_payload);
        try h.commit();
    }

    log.info(
        "schema cache saved: {s} ({d} bytes gzip / {d} bytes raw, {d} tables)",
        .{ cache_key, disk_payload.len, disk_json.len, cache.count() },
    );

    return cache_key;
}

// Pruning is intentionally removed. Content-addressable naming means
// stable schemas produce stable keys — `create(key)` overwrites on a
// repeat save instead of generating a new file — so no dir-wide sweep
// is needed. Stale keys from past schema revisions orphan naturally on
// change; on S3 they're swept by lifecycle; on PosixStore a handful
// accumulates and is fine.
//
// The old `pruneOldCacheFiles + DEFAULT_KEEP_N + list + latest-pointer
// protection` machinery was removed wholesale (Step 3); the latest-pointer
// itself was retired in Step 4 — the binlog checkpoint carries the key.

/// Load the schema cache by its ObjectStore key.
pub fn loadCacheFromKey(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    store: *object_store.ObjectStore,
    key: []const u8,
) !usize {
    const raw_bytes = store.read(allocator, key) catch |err| switch (err) {
        object_store.Error.NotFound => {
            log.debug("cache key '{s}' not found", .{key});
            return 0;
        },
        else => {
            log.warn("cache key '{s}' read failed: {}", .{ key, err });
            return 0;
        },
    };
    defer allocator.free(raw_bytes);

    if (raw_bytes.len == 0 or raw_bytes.len > 100 * 1024 * 1024) return 0;

    // Detect on-disk compression via magic bytes rather than filename so
    // that moving/renaming files (or legacy plain `.json` files written
    // before gzip landed) still round-trip correctly.
    var decoded: ?[]u8 = null;
    defer if (decoded) |d| allocator.free(d);
    const body: []const u8 = if (looksLikeGzip(raw_bytes)) blk: {
        decoded = gzipDecompress(allocator, raw_bytes) catch |err| {
            log.warn("gzip decompress failed for '{s}': {}", .{ key, err });
            return 0;
        };
        break :blk decoded.?;
    } else raw_bytes;

    const tables_loaded = deserializeCacheFromJson(allocator, cache, body) catch |err| {
        log.warn("failed to deserialize cache from '{s}': {}", .{ key, err });
        return 0;
    };

    log.info("schema cache loaded: {s} ({d} tables)", .{ key, tables_loaded });
    return tables_loaded;
}

/// Pure predicate — exposed for unit testing. `mtime` and `now` are Unix
/// seconds; returns true if the cache should be treated as stale.
pub fn isStaleByTtl(mtime: i64, now: i64, ttl_seconds: u64) bool {
    if (now <= mtime) return false; // clock skew: trust the cache
    const age: u64 = @intCast(now - mtime);
    return age > ttl_seconds;
}

// (`makeDirPath`, `readLatestPointer`, `getFileMtime` removed: the
// ObjectStore handles directory creation lazily and mtime via head(),
// and the pointer is a first-class key read through store.read.)

/// Serialize the cache to a JSON string with deterministic key order.
///
/// HashMap iteration order is undefined; without the sort below, two
/// runs with identical schemas would produce different JSON bytes and
/// therefore different content-addressable filenames. The sort is what
/// makes "same schema → same key → overwrite, not new file" hold.
fn serializeCacheToJson(allocator: std.mem.Allocator, cache: *SchemaCache) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Collect and sort table keys for deterministic output.
    const Entry = struct { key: []const u8, value: *TableSchema };
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(allocator);

    var iter = cache.iterator();
    while (iter.next()) |e| {
        try entries.append(allocator, .{ .key = e.key_ptr.*, .value = e.value_ptr });
    }

    std.mem.sort(Entry, entries.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lt);

    // Stable body — version + schemas only. `saved_at_unix` is wrapped on
    // top at write time by `wrapWithSavedAt`, so the content-addressable
    // checksum doesn't churn every save when schemas are unchanged.
    try buf.appendSlice(allocator, "{\"version\":");
    try appendInt(&buf, allocator, CACHE_VERSION);
    try buf.appendSlice(allocator, ",\"schemas\":{");

    for (entries.items, 0..) |entry, idx| {
        if (idx > 0) try buf.append(allocator, ',');

        // Key: "db.table"
        try buf.append(allocator, '"');
        try appendJsonEscaped(&buf, allocator, entry.key);
        try buf.appendSlice(allocator, "\":{");

        const schema = entry.value;

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

// (Prune tests removed: content-addressable naming makes them moot —
// identical schemas overwrite in place, different schemas orphan old
// keys; ObjectStore has no list() and we no longer sweep the dir.)

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
    // End-to-end: save via saveCache (which gzips), capture the returned
    // content-addressable key, then load via loadCacheFromKey (which
    // detects gzip via magic bytes and decompresses).
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try allocator.dupe(u8, path_buf[0..path_len]);
    defer allocator.free(dir_path);

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

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
    const saved_key = try saveCache(allocator, &cache_out, &store, io);
    defer allocator.free(saved_key);

    // Key contract: {hash}.json.gz (no inner namespace prefix — the store
    // root is already the ddl-cache subdir of output_dir).
    try std.testing.expect(std.mem.endsWith(u8, saved_key, ".json.gz"));
    try std.testing.expect(std.mem.indexOfScalar(u8, saved_key, '/') == null);

    // Load via the returned key — gzip detection + decompress is internal.
    var cache_in = SchemaCache.init(allocator, null);
    defer cache_in.deinit();
    const loaded = try loadCacheFromKey(allocator, &cache_in, &store, saved_key);
    try std.testing.expectEqual(@as(usize, 1), loaded);
    try std.testing.expect(cache_in.get("testdb", "t1") != null);
}

test "identical schemas produce identical cache keys (overwrite, not churn)" {
    // Content-addressable property: saving the same cache twice must
    // land on the same key, so we overwrite instead of creating a new
    // file. This guards against regressions in the key-sort
    // determinism inside serializeCacheToJson.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const dir_path = try allocator.dupe(u8, path_buf[0..path_len]);
    defer allocator.free(dir_path);

    var store: object_store.ObjectStore = .{ .posix = object_store.PosixStore.init(allocator, dir_path) };

    // Use multiple tables to exercise the HashMap-iteration-order path;
    // pre-fix, these would hash differently across runs.
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();
    inline for (.{ "alpha", "bravo", "charlie" }) |name| {
        const types = try allocator.dupe(u8, &[_]u8{3});
        const version = try allocator.dupe(u8, "binlog.000001:100");
        try cache.put("db", name, .{
            .columns_count = 1,
            .columns_types = types,
            .schema_version = version,
            .resolved_columns = null,
        });
    }

    const key1 = try saveCache(allocator, &cache, &store, io);
    defer allocator.free(key1);
    const key2 = try saveCache(allocator, &cache, &store, io);
    defer allocator.free(key2);

    try std.testing.expectEqualStrings(key1, key2);
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
