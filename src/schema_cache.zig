//! Schema Cache Module
//!
//! Maintains a mapping of "database.table" -> TableSchema with resolved column names.
//! Column names come from either DDL parsing (CREATE/ALTER TABLE) or DESCRIBE queries.
//!
//! The MySQL binlog TABLE_MAP event only provides column types and metadata,
//! not column names. This module bridges that gap by maintaining schema state
//! derived from DDL events and DESCRIBE fallback queries.

const std = @import("std");
const connection = @import("connection.zig");
const event_parser = @import("event_parser.zig");

const log = std.log.scoped(.schema_cache);

/// Information about a single column, matching MySQL DESCRIBE output.
pub const ColumnInfo = struct {
    column_name: []const u8,
    column_type: []const u8, // e.g. "enum('A','B')", "varchar(255)", "int"
    is_nullable: bool,
    column_key: []const u8, // "PRI", "UNI", "MUL", ""
    column_default: ?[]const u8,
    column_extra: []const u8, // "auto_increment", "on update CURRENT_TIMESTAMP", ""
    ordinal_position: usize, // 1-based
    /// Parsed enum/set members, derived from `column_type` at construction
    /// time. Populated via `refreshParsedEnumSet` so the row-serialization
    /// hot path doesn't re-parse on every value.
    parsed_enum_set: ?EnumSetDef = null,

    pub fn deinit(self: *const ColumnInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.column_name);
        allocator.free(self.column_type);
        allocator.free(self.column_key);
        if (self.column_default) |d| allocator.free(d);
        allocator.free(self.column_extra);
        if (self.parsed_enum_set) |def| freeEnumSetDef(allocator, def);
    }

    pub fn dupe(self: *const ColumnInfo, allocator: std.mem.Allocator) !ColumnInfo {
        const name = try allocator.dupe(u8, self.column_name);
        errdefer allocator.free(name);
        const ctype = try allocator.dupe(u8, self.column_type);
        errdefer allocator.free(ctype);
        const key = try allocator.dupe(u8, self.column_key);
        errdefer allocator.free(key);
        const default_ = if (self.column_default) |d| try allocator.dupe(u8, d) else null;
        errdefer if (default_) |d| allocator.free(d);
        const extra = try allocator.dupe(u8, self.column_extra);
        errdefer allocator.free(extra);
        const parsed: ?EnumSetDef = if (self.parsed_enum_set) |def| try dupeEnumSetDef(allocator, def) else null;

        return .{
            .column_name = name,
            .column_type = ctype,
            .is_nullable = self.is_nullable,
            .column_key = key,
            .column_default = default_,
            .column_extra = extra,
            .ordinal_position = self.ordinal_position,
            .parsed_enum_set = parsed,
        };
    }

    /// Reparse `column_type` into `parsed_enum_set`, freeing any prior value.
    /// Call this after mutating `column_type` (e.g. ALTER MODIFY/CHANGE).
    pub fn refreshParsedEnumSet(self: *ColumnInfo, allocator: std.mem.Allocator) !void {
        if (self.parsed_enum_set) |def| {
            freeEnumSetDef(allocator, def);
            self.parsed_enum_set = null;
        }
        self.parsed_enum_set = try parseEnumSetDef(allocator, self.column_type);
    }
};

/// Schema for a table, with optional resolved column info.
pub const TableSchema = struct {
    columns_count: u64,
    columns_types: []u8, // MySQL protocol column type IDs from TABLE_MAP
    schema_version: []const u8, // "binlog_file:position"
    resolved_columns: ?[]ColumnInfo, // null if DESCRIBE failed and no DDL info

    pub fn deinit(self: *const TableSchema, allocator: std.mem.Allocator) void {
        allocator.free(self.columns_types);
        allocator.free(self.schema_version);
        if (self.resolved_columns) |cols| {
            for (cols) |*col| {
                col.deinit(allocator);
            }
            allocator.free(cols);
        }
    }

    pub fn dupe(self: *const TableSchema, allocator: std.mem.Allocator) !TableSchema {
        const types = try allocator.dupe(u8, self.columns_types);
        errdefer allocator.free(types);
        const version = try allocator.dupe(u8, self.schema_version);
        errdefer allocator.free(version);

        var resolved: ?[]ColumnInfo = null;
        if (self.resolved_columns) |cols| {
            const duped = try allocator.alloc(ColumnInfo, cols.len);
            var i: usize = 0;
            errdefer {
                for (duped[0..i]) |*c| c.deinit(allocator);
                allocator.free(duped);
            }
            for (cols) |*col| {
                duped[i] = try col.dupe(allocator);
                i += 1;
            }
            resolved = duped;
        }

        return .{
            .columns_count = self.columns_count,
            .columns_types = types,
            .schema_version = version,
            .resolved_columns = resolved,
        };
    }

    /// Check if column types match (used to detect schema changes from TABLE_MAP).
    /// Uses normalized type IDs to avoid false mismatches between binlog internal
    /// types (TIMESTAMP2=17, DATETIME2=18, TIME2=19) and DDL/DESCRIBE types
    /// (TIMESTAMP=7, DATETIME=12, TIME=11).
    pub fn typesMatch(self: *const TableSchema, other_count: u64, other_types: []const u8) bool {
        if (self.columns_count != other_count) return false;
        if (self.columns_types.len != other_types.len) return false;
        for (self.columns_types, other_types) |a, b| {
            if (normalizeColumnType(a) != normalizeColumnType(b)) return false;
        }
        return true;
    }

    /// Get column names as a slice (returns null if no resolved columns).
    pub fn getColumnNames(self: *const TableSchema, allocator: std.mem.Allocator) !?[][]const u8 {
        const cols = self.resolved_columns orelse return null;
        const names = try allocator.alloc([]const u8, cols.len);
        for (cols, 0..) |col, i| {
            names[i] = col.column_name;
        }
        return names;
    }
};

/// Normalize MySQL column type IDs to canonical forms for comparison.
/// The binlog TABLE_MAP uses internal v2 types (TIMESTAMP2=17, DATETIME2=18,
/// TIME2=19) while DDL-derived or DESCRIBE-derived schemas may use the
/// original type IDs (TIMESTAMP=7, DATETIME=12, TIME=11). Additionally,
/// DECIMAL(0) and NEWDECIMAL(246) are equivalent, and DATE(10) and NEWDATE(14)
/// are equivalent. Normalizing prevents false-positive schema change detection.
pub fn normalizeColumnType(type_id: u8) u8 {
    return switch (type_id) {
        7 => 17, // TIMESTAMP -> TIMESTAMP2
        11 => 19, // TIME -> TIME2
        12 => 18, // DATETIME -> DATETIME2
        14 => 10, // NEWDATE -> DATE
        0 => 246, // DECIMAL -> NEWDECIMAL
        else => type_id,
    };
}

/// Enum/Set definition parsed from a column_type string.
pub const EnumSetDef = union(enum) {
    enum_def: []const []const u8,
    set_def: []const []const u8,
};

/// Parse enum/set member values from a DESCRIBE-style column_type string.
/// Examples: "enum('active','inactive')" -> ["active", "inactive"]
///           "set('read','write')" -> ["read", "write"]
/// Returns null if not an enum/set type.
pub fn parseEnumSetDef(allocator: std.mem.Allocator, column_type: []const u8) !?EnumSetDef {
    const is_enum = std.mem.startsWith(u8, column_type, "enum(");
    const is_set = std.mem.startsWith(u8, column_type, "set(");

    if (!is_enum and !is_set) return null;

    const prefix_len: usize = if (is_enum) 5 else 4; // "enum(" or "set("
    if (column_type.len <= prefix_len + 1) return null; // need at least "enum()" or "set()"

    // Strip prefix and trailing ')'
    const inner = column_type[prefix_len .. column_type.len - 1];

    var values: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }

    var i: usize = 0;
    while (i < inner.len) {
        // Skip whitespace
        while (i < inner.len and inner[i] == ' ') i += 1;
        if (i >= inner.len) break;

        // Expect opening quote
        if (inner[i] != '\'') {
            i += 1;
            continue;
        }
        i += 1; // skip opening quote

        // Read until closing quote (handle escaped quotes '')
        var val: std.ArrayList(u8) = .empty;
        errdefer val.deinit(allocator);

        while (i < inner.len) {
            if (inner[i] == '\'') {
                if (i + 1 < inner.len and inner[i + 1] == '\'') {
                    // Escaped quote
                    try val.append(allocator, '\'');
                    i += 2;
                } else {
                    // End of value
                    i += 1;
                    break;
                }
            } else {
                try val.append(allocator, inner[i]);
                i += 1;
            }
        }

        try values.append(allocator, try val.toOwnedSlice(allocator));

        // Skip comma
        while (i < inner.len and (inner[i] == ',' or inner[i] == ' ')) i += 1;
    }

    const vals = try values.toOwnedSlice(allocator);
    if (is_enum) {
        return .{ .enum_def = vals };
    } else {
        return .{ .set_def = vals };
    }
}

/// Free an EnumSetDef's members.
pub fn freeEnumSetDef(allocator: std.mem.Allocator, def: EnumSetDef) void {
    const vals = switch (def) {
        .enum_def => |v| v,
        .set_def => |v| v,
    };
    for (vals) |v| allocator.free(v);
    allocator.free(vals);
}

/// Deep-copy an EnumSetDef (duplicating each member string).
pub fn dupeEnumSetDef(allocator: std.mem.Allocator, def: EnumSetDef) !EnumSetDef {
    const src_vals = switch (def) {
        .enum_def => |v| v,
        .set_def => |v| v,
    };
    const new_vals = try allocator.alloc([]const u8, src_vals.len);
    var initialized: usize = 0;
    errdefer {
        for (new_vals[0..initialized]) |v| allocator.free(v);
        allocator.free(new_vals);
    }
    for (src_vals) |v| {
        new_vals[initialized] = try allocator.dupe(u8, v);
        initialized += 1;
    }
    return switch (def) {
        .enum_def => .{ .enum_def = new_vals },
        .set_def => .{ .set_def = new_vals },
    };
}

/// Resolve an enum integer value to its string label.
/// MySQL enums are 1-indexed (0 = empty string, 1 = first member).
pub fn resolveEnumValue(members: []const []const u8, int_val: i64) ?[]const u8 {
    if (int_val < 0) return null;
    if (int_val == 0) return "";
    const idx = @as(usize, @intCast(int_val)) - 1;
    if (idx < members.len) return members[idx];
    return null; // out of range
}

/// Resolve a set bitmask to a comma-separated string of member names.
/// MySQL sets are bitmask-based (bit 0 = first member, bit 1 = second, etc.).
pub fn resolveSetValue(allocator: std.mem.Allocator, members: []const []const u8, bitmask: i64) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var first = true;
    for (members, 0..) |member, i| {
        if (i >= 64) break;
        if (bitmask & (@as(i64, 1) << @intCast(i)) != 0) {
            if (!first) try result.appendSlice(allocator, ",");
            try result.appendSlice(allocator, member);
            first = false;
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// The main schema cache: maps "database.table" -> TableSchema.
pub const SchemaCache = struct {
    allocator: std.mem.Allocator,
    cache: std.StringHashMap(TableSchema),
    /// Secondary connection for DESCRIBE queries (may be null if not available).
    describe_conn: ?*connection.Connection,

    pub fn init(allocator: std.mem.Allocator, describe_conn: ?*connection.Connection) SchemaCache {
        return .{
            .allocator = allocator,
            .cache = std.StringHashMap(TableSchema).init(allocator),
            .describe_conn = describe_conn,
        };
    }

    pub fn deinit(self: *SchemaCache) void {
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.deinit();
    }

    /// Build a cache key from database and table name.
    pub fn makeKey(self: *SchemaCache, database: []const u8, table: []const u8) ![]u8 {
        return try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ database, table });
    }

    /// Get the cached schema for a table (if any).
    pub fn get(self: *SchemaCache, database: []const u8, table: []const u8) ?*TableSchema {
        // Build key on stack to avoid allocation for lookups
        var key_buf: [512]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ database, table }) catch return null;
        return self.cache.getPtr(key);
    }

    /// Put a schema into the cache, replacing any existing entry.
    pub fn put(self: *SchemaCache, database: []const u8, table: []const u8, schema: TableSchema) !void {
        var key_buf: [512]u8 = undefined;
        const lookup_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ database, table }) catch return;

        if (self.cache.fetchRemove(lookup_key)) |old| {
            old.value.deinit(self.allocator);
            self.allocator.free(old.key);
        }

        const key = try self.makeKey(database, table);
        errdefer self.allocator.free(key);
        try self.cache.put(key, schema);
    }

    /// Remove a table from the cache.
    pub fn remove(self: *SchemaCache, database: []const u8, table: []const u8) void {
        var key_buf: [512]u8 = undefined;
        const lookup_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ database, table }) catch return;

        if (self.cache.fetchRemove(lookup_key)) |old| {
            old.value.deinit(self.allocator);
            self.allocator.free(old.key);
        }
    }

    /// Rename a table in the cache.
    pub fn rename(self: *SchemaCache, database: []const u8, old_table: []const u8, new_table: []const u8) !void {
        var key_buf: [512]u8 = undefined;
        const old_key = std.fmt.bufPrint(&key_buf, "{s}.{s}", .{ database, old_table }) catch return;

        if (self.cache.fetchRemove(old_key)) |old| {
            self.allocator.free(old.key);
            const new_key = try self.makeKey(database, new_table);
            errdefer self.allocator.free(new_key);
            try self.cache.put(new_key, old.value);
        }
    }

    /// Resolve column names for a table.
    /// Strategy:
    /// 1. Check if cached schema has resolved_columns with matching column count
    /// 2. If not, try DESCRIBE query via secondary connection
    /// 3. If DESCRIBE fails, return null (caller uses generic names)
    pub fn resolveColumns(
        self: *SchemaCache,
        database: []const u8,
        table: []const u8,
        column_count: u64,
        column_types: []const u8,
        schema_version: []const u8,
    ) !?[]ColumnInfo {
        // Check cache first
        if (self.get(database, table)) |cached| {
            if (cached.resolved_columns) |cols| {
                if (cols.len == column_count) {
                    return cols;
                }
            }
        }

        // Try DESCRIBE
        const columns = self.describeTable(database, table) catch |err| {
            log.warn("DESCRIBE {s}.{s} failed: {}, using generic column names", .{ database, table, err });
            // Store schema without resolved columns so we don't retry DESCRIBE on every event
            const types_copy = try self.allocator.dupe(u8, column_types);
            errdefer self.allocator.free(types_copy);
            const version_copy = try self.allocator.dupe(u8, schema_version);
            errdefer self.allocator.free(version_copy);
            try self.put(database, table, .{
                .columns_count = column_count,
                .columns_types = types_copy,
                .schema_version = version_copy,
                .resolved_columns = null,
            });
            return null;
        };

        // Store resolved schema
        const types_copy = try self.allocator.dupe(u8, column_types);
        errdefer self.allocator.free(types_copy);
        const version_copy = try self.allocator.dupe(u8, schema_version);
        errdefer self.allocator.free(version_copy);

        try self.put(database, table, .{
            .columns_count = column_count,
            .columns_types = types_copy,
            .schema_version = version_copy,
            .resolved_columns = columns,
        });

        return columns;
    }

    /// Execute DESCRIBE query via secondary connection.
    fn describeTable(self: *SchemaCache, database: []const u8, table: []const u8) ![]ColumnInfo {
        const conn = self.describe_conn orelse return error.NoDescribeConnection;

        // Build DESCRIBE query
        var query_buf: [512]u8 = undefined;
        const sql = std.fmt.bufPrint(&query_buf, "DESCRIBE `{s}`.`{s}`", .{ database, table }) catch
            return error.QueryTooLong;

        log.debug("executing: {s}", .{sql});

        var result_set = try conn.queryRows(sql);
        defer result_set.deinit();

        // DESCRIBE returns 6 columns: Field, Type, Null, Key, Default, Extra
        var columns: std.ArrayList(ColumnInfo) = .empty;
        errdefer {
            for (columns.items) |*col| col.deinit(self.allocator);
            columns.deinit(self.allocator);
        }

        for (result_set.rows, 0..) |row, idx| {
            if (row.values.len < 6) continue;

            var col = ColumnInfo{
                .column_name = try self.allocator.dupe(u8, row.values[0] orelse ""),
                .column_type = try self.allocator.dupe(u8, row.values[1] orelse ""),
                .is_nullable = if (row.values[2]) |v| std.mem.eql(u8, v, "YES") else false,
                .column_key = try self.allocator.dupe(u8, row.values[3] orelse ""),
                .column_default = if (row.values[4]) |v| try self.allocator.dupe(u8, v) else null,
                .column_extra = try self.allocator.dupe(u8, row.values[5] orelse ""),
                .ordinal_position = idx + 1,
            };
            errdefer col.deinit(self.allocator);
            try col.refreshParsedEnumSet(self.allocator);

            try columns.append(self.allocator, col);
        }

        log.info("DESCRIBE {s}.{s}: {d} columns resolved", .{ database, table, columns.items.len });

        return try columns.toOwnedSlice(self.allocator);
    }

    /// Get the number of cached tables.
    pub fn count(self: *const SchemaCache) usize {
        return self.cache.count();
    }

    /// Iterator over all cached schemas.
    pub fn iterator(self: *SchemaCache) std.StringHashMap(TableSchema).Iterator {
        return self.cache.iterator();
    }
};

// ============================================================
// Tests
// ============================================================

test "parseEnumSetDef enum" {
    const allocator = std.testing.allocator;
    const def = (try parseEnumSetDef(allocator, "enum('active','inactive','pending')")).?;
    defer freeEnumSetDef(allocator, def);

    switch (def) {
        .enum_def => |vals| {
            try std.testing.expectEqual(@as(usize, 3), vals.len);
            try std.testing.expectEqualStrings("active", vals[0]);
            try std.testing.expectEqualStrings("inactive", vals[1]);
            try std.testing.expectEqualStrings("pending", vals[2]);
        },
        else => return error.UnexpectedDefType,
    }
}

test "parseEnumSetDef set" {
    const allocator = std.testing.allocator;
    const def = (try parseEnumSetDef(allocator, "set('read','write','exec')")).?;
    defer freeEnumSetDef(allocator, def);

    switch (def) {
        .set_def => |vals| {
            try std.testing.expectEqual(@as(usize, 3), vals.len);
            try std.testing.expectEqualStrings("read", vals[0]);
            try std.testing.expectEqualStrings("write", vals[1]);
            try std.testing.expectEqualStrings("exec", vals[2]);
        },
        else => return error.UnexpectedDefType,
    }
}

test "parseEnumSetDef not enum/set" {
    const allocator = std.testing.allocator;
    const result = try parseEnumSetDef(allocator, "varchar(255)");
    try std.testing.expect(result == null);
}

test "parseEnumSetDef escaped quotes" {
    const allocator = std.testing.allocator;
    const def = (try parseEnumSetDef(allocator, "enum('it''s','ok')")).?;
    defer freeEnumSetDef(allocator, def);

    switch (def) {
        .enum_def => |vals| {
            try std.testing.expectEqual(@as(usize, 2), vals.len);
            try std.testing.expectEqualStrings("it's", vals[0]);
            try std.testing.expectEqualStrings("ok", vals[1]);
        },
        else => return error.UnexpectedDefType,
    }
}

test "resolveEnumValue" {
    const members = &[_][]const u8{ "active", "inactive", "pending" };
    try std.testing.expectEqualStrings("", resolveEnumValue(members, 0).?);
    try std.testing.expectEqualStrings("active", resolveEnumValue(members, 1).?);
    try std.testing.expectEqualStrings("inactive", resolveEnumValue(members, 2).?);
    try std.testing.expectEqualStrings("pending", resolveEnumValue(members, 3).?);
    try std.testing.expect(resolveEnumValue(members, 4) == null);
}

test "resolveEnumValue negative" {
    const members = &[_][]const u8{ "active", "inactive" };
    try std.testing.expect(resolveEnumValue(members, -1) == null);
    try std.testing.expect(resolveEnumValue(members, -999) == null);
}

test "resolveSetValue" {
    const allocator = std.testing.allocator;
    const members = &[_][]const u8{ "read", "write", "exec" };

    // bitmask 0b101 = read,exec
    const result = try resolveSetValue(allocator, members, 5);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("read,exec", result);
}

test "resolveSetValue single" {
    const allocator = std.testing.allocator;
    const members = &[_][]const u8{ "a", "b", "c" };

    const result = try resolveSetValue(allocator, members, 2);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("b", result);
}

test "SchemaCache basic operations" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    // Put a schema
    const types = try allocator.dupe(u8, &[_]u8{ 3, 15, 254 });
    const version = try allocator.dupe(u8, "binlog.000001:100");
    try cache.put("testdb", "users", .{
        .columns_count = 3,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = null,
    });

    // Get it back
    const schema = cache.get("testdb", "users");
    try std.testing.expect(schema != null);
    try std.testing.expectEqual(@as(u64, 3), schema.?.columns_count);

    // Remove it
    cache.remove("testdb", "users");
    try std.testing.expect(cache.get("testdb", "users") == null);
}

test "normalizeColumnType" {
    // TIMESTAMP -> TIMESTAMP2
    try std.testing.expectEqual(@as(u8, 17), normalizeColumnType(7));
    try std.testing.expectEqual(@as(u8, 17), normalizeColumnType(17));
    // DATETIME -> DATETIME2
    try std.testing.expectEqual(@as(u8, 18), normalizeColumnType(12));
    try std.testing.expectEqual(@as(u8, 18), normalizeColumnType(18));
    // TIME -> TIME2
    try std.testing.expectEqual(@as(u8, 19), normalizeColumnType(11));
    try std.testing.expectEqual(@as(u8, 19), normalizeColumnType(19));
    // DECIMAL -> NEWDECIMAL
    try std.testing.expectEqual(@as(u8, 246), normalizeColumnType(0));
    try std.testing.expectEqual(@as(u8, 246), normalizeColumnType(246));
    // NEWDATE -> DATE
    try std.testing.expectEqual(@as(u8, 10), normalizeColumnType(14));
    // Other types pass through
    try std.testing.expectEqual(@as(u8, 3), normalizeColumnType(3)); // INT
    try std.testing.expectEqual(@as(u8, 254), normalizeColumnType(254)); // STRING
}

test "TableSchema typesMatch with normalization" {
    const allocator = std.testing.allocator;
    // Simulate binlog types using v2 temporal codes
    const binlog_types = try allocator.dupe(u8, &[_]u8{ 3, 17, 18, 254 }); // INT, TIMESTAMP2, DATETIME2, STRING
    const version = try allocator.dupe(u8, "binlog:100");
    const schema = TableSchema{
        .columns_count = 4,
        .columns_types = binlog_types,
        .schema_version = version,
        .resolved_columns = null,
    };
    defer schema.deinit(allocator);

    // DDL-derived types might use old codes
    const ddl_types = [_]u8{ 3, 7, 12, 254 }; // INT, TIMESTAMP(old), DATETIME(old), STRING
    try std.testing.expect(schema.typesMatch(4, &ddl_types));

    // Different column count should not match
    try std.testing.expect(!schema.typesMatch(3, &ddl_types));

    // Actually different type should not match
    const diff_types = [_]u8{ 3, 17, 18, 252 }; // BLOB instead of STRING
    try std.testing.expect(!schema.typesMatch(4, &diff_types));
}

test "SchemaCache rename" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    const types = try allocator.dupe(u8, &[_]u8{3});
    const version = try allocator.dupe(u8, "binlog.000001:100");
    try cache.put("testdb", "old_name", .{
        .columns_count = 1,
        .columns_types = types,
        .schema_version = version,
        .resolved_columns = null,
    });

    try cache.rename("testdb", "old_name", "new_name");
    try std.testing.expect(cache.get("testdb", "old_name") == null);
    try std.testing.expect(cache.get("testdb", "new_name") != null);
}
