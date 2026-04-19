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

const CACHE_VERSION: u32 = 1;

/// Save the schema cache to a JSON file in the given directory.
/// Returns the filename used (content-addressable).
pub fn saveCache(allocator: std.mem.Allocator, cache: *SchemaCache, dir: []const u8) ![]const u8 {
    // Serialize to JSON
    const json_data = try serializeCacheToJson(allocator, cache);
    defer allocator.free(json_data);

    // Compute checksum
    const checksum = computeChecksum(json_data);
    var checksum_hex: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (checksum[0..8], 0..) |byte, i| {
        checksum_hex[i * 2] = hex_chars[byte >> 4];
        checksum_hex[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    // Build full path
    const full_path = try std.fmt.allocPrint(allocator, "{s}/schema_cache_{s}.json", .{ dir, checksum_hex });
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
    while (written < json_data.len) {
        const rc = std.posix.system.write(fd, json_data[written..].ptr, json_data[written..].len);
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

    log.info("schema cache saved: {s} ({d} bytes, {d} tables)", .{ full_path, json_data.len, cache.count() });

    return full_path;
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

    const tables_loaded = deserializeCacheFromJson(allocator, cache, json_data[0..total_read]) catch |err| {
        log.warn("failed to deserialize cache from '{s}': {}", .{ path, err });
        return 0;
    };

    log.info("schema cache loaded: {s} ({d} tables)", .{ path, tables_loaded });
    return tables_loaded;
}

/// Load the most recent schema cache from the given directory.
/// Reads the `.schema_cache_latest` pointer file to find the cache file.
pub fn loadCache(allocator: std.mem.Allocator, cache: *SchemaCache, dir: []const u8) !usize {
    // Read the pointer file
    const latest_path = try std.fmt.allocPrint(allocator, "{s}/.schema_cache_latest", .{dir});
    defer allocator.free(latest_path);

    const latest_z = try allocator.dupeZ(u8, latest_path);
    defer allocator.free(latest_z);

    const fd = std.posix.openat(std.posix.AT.FDCWD, latest_z, .{}, 0) catch {
        log.debug("no .schema_cache_latest in '{s}'", .{dir});
        return 0;
    };
    defer _ = std.posix.system.close(fd);

    var path_buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &path_buf) catch return 0;
    if (n == 0) return 0;

    const cache_path = std.mem.trim(u8, path_buf[0..n], "\n\r \t");
    if (cache_path.len == 0) return 0;

    return try loadCacheFromFile(allocator, cache, cache_path);
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
                cols[initialized] = .{
                    .column_name = try allocator.dupe(u8, jc.column_name),
                    .column_type = try allocator.dupe(u8, jc.column_type),
                    .is_nullable = jc.is_nullable,
                    .column_key = try allocator.dupe(u8, jc.column_key),
                    .column_default = if (jc.column_default) |d| try allocator.dupe(u8, d) else null,
                    .column_extra = try allocator.dupe(u8, jc.column_extra),
                    .ordinal_position = jc.ordinal_position,
                };
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
