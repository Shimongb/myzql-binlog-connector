//! DDL Handler Module
//!
//! Detects and applies DDL changes (CREATE TABLE, ALTER TABLE, DROP TABLE,
//! RENAME TABLE) from binlog QUERY_EVENTs to the SchemaCache.
//!
//! Uses myzqlparser to parse SQL statements and extract column definitions,
//! which are then mapped to ColumnInfo structs for the schema cache.

const std = @import("std");
const myzqlparser = @import("myzqlparser");
const schema_cache = @import("schema_cache.zig");
const ColumnInfo = schema_cache.ColumnInfo;
const TableSchema = schema_cache.TableSchema;
const SchemaCache = schema_cache.SchemaCache;

const log = std.log.scoped(.ddl_handler);

/// Result of DDL detection: what kind of DDL was found and what to do.
pub const DdlEvent = union(enum) {
    create_table: struct {
        schema: []const u8,
        table: []const u8,
        columns: []ColumnInfo,
    },
    alter_table: struct {
        schema: []const u8,
        table: []const u8,
    },
    drop_table: struct {
        schema: []const u8,
        table: []const u8,
    },
    rename_table: struct {
        schema: []const u8,
        old_table: []const u8,
        new_table: []const u8,
    },
};

/// Detect and apply DDL from a QUERY_EVENT's SQL text.
/// `event_schema` is the default database from the QUERY_EVENT header.
/// `binlog_file` and `binlog_pos` form the schema version string.
pub fn handleDdl(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    sql: []const u8,
    event_schema: []const u8,
    binlog_file: []const u8,
    binlog_pos: u64,
) void {
    // Skip transaction control statements
    if (isTransactionControl(sql)) return;

    // Use a temporary arena for SQL parsing — the AST is only needed
    // during this function; column info is duped to the cache allocator.
    var parse_arena = std.heap.ArenaAllocator.init(allocator);
    defer parse_arena.deinit();

    // Parse the SQL
    const stmts = myzqlparser.parse(parse_arena.allocator(), sql, .MySQL, .mysql) catch |err| {
        // DDL parsing failure is non-fatal: we'll fall back to DESCRIBE on next DML
        log.debug("SQL parse failed (non-fatal): {} for: {s}", .{ err, truncateSql(sql) });
        return;
    };

    for (stmts) |stmt| {
        applyStatement(allocator, cache, stmt, event_schema, binlog_file, binlog_pos) catch |err| {
            log.warn("DDL apply failed (non-fatal): {} for: {s}", .{ err, truncateSql(sql) });
        };
    }
}

/// Apply a single parsed statement to the cache.
fn applyStatement(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    stmt: myzqlparser.Statement,
    event_schema: []const u8,
    binlog_file: []const u8,
    binlog_pos: u64,
) !void {
    switch (stmt) {
        .create_table => |ct| {
            const resolved = resolveSchemaAndTable(ct.name, event_schema);
            const db = resolved.schema;
            const table = resolved.table;

            log.info("DDL CREATE TABLE {s}.{s} ({d} columns)", .{ db, table, ct.columns.len });

            const version = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ binlog_file, binlog_pos });
            errdefer allocator.free(version);

            const columns = try buildColumnsFromCreate(allocator, ct.columns, ct.constraints);
            errdefer {
                for (columns) |*c| c.deinit(allocator);
                allocator.free(columns);
            }

            // Build column types array
            const col_types = try allocator.alloc(u8, columns.len);
            errdefer allocator.free(col_types);
            for (columns, 0..) |col, i| {
                col_types[i] = datatypeToColumnTypeId(col.column_type);
            }

            try cache.put(db, table, .{
                .columns_count = columns.len,
                .columns_types = col_types,
                .schema_version = version,
                .resolved_columns = columns,
            });
        },
        .alter_table => |alt| {
            const resolved = resolveSchemaAndTable(alt.name, event_schema);
            const db = resolved.schema;
            const table = resolved.table;

            log.info("DDL ALTER TABLE {s}.{s} ({d} operations)", .{ db, table, alt.operations.len });

            try applyAlterTable(allocator, cache, db, table, alt.operations, binlog_file, binlog_pos);
        },
        .rename_table => |pairs| {
            for (pairs) |pair| {
                const old = resolveSchemaAndTable(pair.old_name, event_schema);
                const new = resolveSchemaAndTable(pair.new_name, event_schema);
                log.info("DDL RENAME TABLE {s}.{s} -> {s}.{s}", .{ old.schema, old.table, new.schema, new.table });
                if (std.mem.eql(u8, old.schema, new.schema)) {
                    cache.rename(old.schema, old.table, new.table) catch |err| {
                        log.warn("cache rename failed (non-fatal): {}", .{err});
                    };
                } else {
                    // Cross-database rename: cache is keyed by "db.table" so we cannot
                    // re-key in place. Invalidate the old entry; DESCRIBE will resolve
                    // the new one on first DML.
                    cache.remove(old.schema, old.table);
                }
            }
        },
        .drop => |drop| {
            if (drop.object_type != .table) return;
            for (drop.names) |name| {
                const resolved = resolveSchemaAndTable(name, event_schema);
                log.info("DDL DROP TABLE {s}.{s}", .{ resolved.schema, resolved.table });
                cache.remove(resolved.schema, resolved.table);
            }
        },
        else => {},
    }
}

/// Apply ALTER TABLE operations to a cached schema.
fn applyAlterTable(
    allocator: std.mem.Allocator,
    cache: *SchemaCache,
    database: []const u8,
    table: []const u8,
    operations: []const myzqlparser.AlterTableOperation,
    binlog_file: []const u8,
    binlog_pos: u64,
) !void {
    // Get existing columns (if cached)
    var columns: std.ArrayList(ColumnInfo) = blk: {
        if (cache.get(database, table)) |existing| {
            if (existing.resolved_columns) |cols| {
                var list: std.ArrayList(ColumnInfo) = .empty;
                for (cols) |*col| {
                    try list.append(allocator, try col.dupe(allocator));
                }
                break :blk list;
            }
        }
        // No existing schema - can't apply ALTER without base
        log.warn("ALTER TABLE {s}.{s}: no cached schema to apply to, will use DESCRIBE on next DML", .{ database, table });
        cache.remove(database, table);
        return;
    };
    errdefer {
        for (columns.items) |*c| c.deinit(allocator);
        columns.deinit(allocator);
    }

    for (operations) |op| {
        switch (op) {
            .add_column => |ac| {
                const new_col = try buildColumnInfo(allocator, ac.column_def, columns.items.len + 1);
                errdefer {
                    var c = new_col;
                    c.deinit(allocator);
                }

                // Determine position
                if (ac.column_position) |pos| {
                    switch (pos) {
                        .first => try columns.insert(allocator, 0, new_col),
                        .after => |after_ident| {
                            const idx = findColumnIndex(columns.items, after_ident.value);
                            if (idx) |i| {
                                try columns.insert(allocator, i + 1, new_col);
                            } else {
                                try columns.append(allocator, new_col);
                            }
                        },
                    }
                } else {
                    try columns.append(allocator, new_col);
                }
                recomputeOrdinals(columns.items);
            },
            .drop_column => |dc| {
                const idx = findColumnIndex(columns.items, dc.column_name.value);
                if (idx) |i| {
                    var removed = columns.orderedRemove(i);
                    removed.deinit(allocator);
                    recomputeOrdinals(columns.items);
                }
            },
            .modify_column => |mc| {
                const idx = findColumnIndex(columns.items, mc.col_name.value);
                if (idx) |i| {
                    // Update type and options in place
                    const type_str = try datatypeToString(allocator, mc.data_type);
                    allocator.free(columns.items[i].column_type);
                    columns.items[i].column_type = type_str;
                    try columns.items[i].refreshParsedEnumSet(allocator);
                    updateColumnOptions(&columns.items[i], mc.options);

                    // Handle repositioning
                    if (mc.column_position) |pos| {
                        const col = columns.orderedRemove(i);
                        switch (pos) {
                            .first => try columns.insert(allocator, 0, col),
                            .after => |after_ident| {
                                const new_idx = findColumnIndex(columns.items, after_ident.value);
                                if (new_idx) |ni| {
                                    try columns.insert(allocator, ni + 1, col);
                                } else {
                                    try columns.append(allocator, col);
                                }
                            },
                        }
                        recomputeOrdinals(columns.items);
                    }
                }
            },
            .change_column => |cc| {
                const idx = findColumnIndex(columns.items, cc.old_name.value);
                if (idx) |i| {
                    // Rename
                    allocator.free(columns.items[i].column_name);
                    columns.items[i].column_name = try allocator.dupe(u8, cc.new_name.value);

                    // Update type
                    const type_str = try datatypeToString(allocator, cc.data_type);
                    allocator.free(columns.items[i].column_type);
                    columns.items[i].column_type = type_str;
                    try columns.items[i].refreshParsedEnumSet(allocator);
                    updateColumnOptions(&columns.items[i], cc.options);

                    // Handle repositioning
                    if (cc.column_position) |pos| {
                        const col = columns.orderedRemove(i);
                        switch (pos) {
                            .first => try columns.insert(allocator, 0, col),
                            .after => |after_ident| {
                                const new_idx = findColumnIndex(columns.items, after_ident.value);
                                if (new_idx) |ni| {
                                    try columns.insert(allocator, ni + 1, col);
                                } else {
                                    try columns.append(allocator, col);
                                }
                            },
                        }
                        recomputeOrdinals(columns.items);
                    }
                }
            },
            .rename_column => |rc| {
                const idx = findColumnIndex(columns.items, rc.old_column_name.value);
                if (idx) |i| {
                    allocator.free(columns.items[i].column_name);
                    columns.items[i].column_name = try allocator.dupe(u8, rc.new_column_name.value);
                }
            },
            .rename_table => |new_name| {
                const resolved = resolveSchemaAndTable(new_name, database);
                try cache.rename(database, table, resolved.table);
                return; // Table has been renamed, further ops use the new name
            },
            else => {
                // Other ALTER operations (add_constraint, drop_constraint, etc.) don't affect columns
            },
        }
    }

    // Update cache with modified columns
    const version = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ binlog_file, binlog_pos });
    errdefer allocator.free(version);

    const col_types = try allocator.alloc(u8, columns.items.len);
    errdefer allocator.free(col_types);
    for (columns.items, 0..) |col, i| {
        col_types[i] = datatypeToColumnTypeId(col.column_type);
    }

    const owned_columns = try columns.toOwnedSlice(allocator);

    try cache.put(database, table, .{
        .columns_count = owned_columns.len,
        .columns_types = col_types,
        .schema_version = version,
        .resolved_columns = owned_columns,
    });
}

// ============================================================
// Helper Functions
// ============================================================

const SchemaAndTable = struct {
    schema: []const u8,
    table: []const u8,
};

/// Resolve schema and table from an ObjectName, falling back to event_schema.
fn resolveSchemaAndTable(name: myzqlparser.ObjectName, event_schema: []const u8) SchemaAndTable {
    if (name.parts.len >= 2) {
        return .{
            .schema = name.parts[0].value,
            .table = name.parts[1].value,
        };
    } else if (name.parts.len == 1) {
        return .{
            .schema = event_schema,
            .table = name.parts[0].value,
        };
    }
    return .{ .schema = event_schema, .table = "" };
}

/// Build ColumnInfo array from CREATE TABLE columns and constraints.
fn buildColumnsFromCreate(
    allocator: std.mem.Allocator,
    ast_columns: []const myzqlparser.ColumnDef,
    constraints: []const myzqlparser.TableConstraint,
) ![]ColumnInfo {
    var columns = try allocator.alloc(ColumnInfo, ast_columns.len);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |*c| c.deinit(allocator);
        allocator.free(columns);
    }

    // Collect primary key columns from table-level constraints
    var pk_columns = std.StringHashMap(void).init(allocator);
    defer pk_columns.deinit();

    for (constraints) |constraint| {
        switch (constraint) {
            .primary_key => |pk| {
                for (pk.columns) |pk_col| {
                    try pk_columns.put(pk_col.value, {});
                }
            },
            else => {},
        }
    }

    for (ast_columns, 0..) |col_def, i| {
        columns[i] = try buildColumnInfo(allocator, col_def, i + 1);
        initialized += 1;

        // Check table-level PK
        if (pk_columns.contains(col_def.name.value)) {
            if (columns[i].column_key.len == 0) {
                allocator.free(columns[i].column_key);
                columns[i].column_key = try allocator.dupe(u8, "PRI");
            }
        }
    }

    return columns;
}

/// Build a single ColumnInfo from a parsed ColumnDef.
fn buildColumnInfo(allocator: std.mem.Allocator, col_def: myzqlparser.ColumnDef, ordinal: usize) !ColumnInfo {
    const col_name = try allocator.dupe(u8, col_def.name.value);
    errdefer allocator.free(col_name);
    const col_type = try datatypeToString(allocator, col_def.data_type);
    errdefer allocator.free(col_type);

    var is_nullable = true; // default: nullable
    var column_key: []const u8 = "";
    var column_default: ?[]const u8 = null;
    var column_extra: []const u8 = "";

    for (col_def.options) |opt_def| {
        switch (opt_def.option) {
            .not_null => is_nullable = false,
            .null => is_nullable = true,
            .primary_key => column_key = "PRI",
            .unique => column_key = "UNI",
            .auto_increment => column_extra = "auto_increment",
            .default => column_default = "DEFAULT", // simplified
            else => {},
        }
    }

    const parsed_def: ?schema_cache.EnumSetDef = try schema_cache.parseEnumSetDef(allocator, col_type);
    errdefer if (parsed_def) |d| schema_cache.freeEnumSetDef(allocator, d);

    return .{
        .column_name = col_name,
        .column_type = col_type,
        .is_nullable = is_nullable,
        .column_key = try allocator.dupe(u8, column_key),
        .column_default = if (column_default) |d| try allocator.dupe(u8, d) else null,
        .column_extra = try allocator.dupe(u8, column_extra),
        .ordinal_position = ordinal,
        .parsed_enum_set = parsed_def,
    };
}

/// Update column options from ALTER TABLE MODIFY/CHANGE options.
fn updateColumnOptions(col: *ColumnInfo, options: []const myzqlparser.ColumnOptionDef) void {
    for (options) |opt_def| {
        switch (opt_def.option) {
            .not_null => col.is_nullable = false,
            .null => col.is_nullable = true,
            else => {},
        }
    }
}

/// Find a column by name (case-insensitive).
fn findColumnIndex(columns: []const ColumnInfo, name: []const u8) ?usize {
    for (columns, 0..) |col, i| {
        if (std.ascii.eqlIgnoreCase(col.column_name, name)) return i;
    }
    return null;
}

/// Recompute ordinal_position to be sequential 1..N.
fn recomputeOrdinals(columns: []ColumnInfo) void {
    for (columns, 0..) |*col, i| {
        col.ordinal_position = i + 1;
    }
}

/// Check if SQL is a transaction control statement (BEGIN, COMMIT, etc.).
fn isTransactionControl(sql: []const u8) bool {
    // Quick prefix check (case-insensitive)
    if (sql.len < 3) return false;

    var buf: [10]u8 = undefined;
    const check_len = @min(sql.len, 10);
    for (sql[0..check_len], 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    const prefix = buf[0..check_len];

    return std.mem.startsWith(u8, prefix, "begin") or
        std.mem.startsWith(u8, prefix, "commit") or
        std.mem.startsWith(u8, prefix, "rollback") or
        std.mem.startsWith(u8, prefix, "savepoint") or
        std.mem.startsWith(u8, prefix, "xa ");
}

/// Convert a myzqlparser DataType to a DESCRIBE-style type string.
fn datatypeToString(allocator: std.mem.Allocator, data_type: myzqlparser.DataType) ![]const u8 {
    return switch (data_type) {
        // tinyint / bit MUST carry their display width when set — that's
        // how `tinyint(1)` / `bit(1)` signal BOOL intent for downstream
        // coercion in row_json_serializer (`columnTypeIsBool1`). Dropping
        // the width here meant bool columns silently shipped as integers
        // (regression caught by docker/integration_test.sh canary row).
        .tiny_int => |w| if (w) |n|
            try std.fmt.allocPrint(allocator, "tinyint({d})", .{n})
        else
            try allocator.dupe(u8, "tinyint"),
        .tiny_int_unsigned => |w| if (w) |n|
            try std.fmt.allocPrint(allocator, "tinyint({d}) unsigned", .{n})
        else
            try allocator.dupe(u8, "tinyint unsigned"),
        .small_int => try allocator.dupe(u8, "smallint"),
        .small_int_unsigned => try allocator.dupe(u8, "smallint unsigned"),
        .medium_int => try allocator.dupe(u8, "mediumint"),
        .medium_int_unsigned => try allocator.dupe(u8, "mediumint unsigned"),
        .int, .integer => try allocator.dupe(u8, "int"),
        .int_unsigned, .integer_unsigned => try allocator.dupe(u8, "int unsigned"),
        .big_int => try allocator.dupe(u8, "bigint"),
        .big_int_unsigned => try allocator.dupe(u8, "bigint unsigned"),
        .float, .float_unsigned => try allocator.dupe(u8, "float"),
        .double, .double_unsigned, .double_precision, .double_precision_unsigned => try allocator.dupe(u8, "double"),
        .real, .real_unsigned => try allocator.dupe(u8, "double"),
        .decimal, .decimal_unsigned, .dec, .dec_unsigned, .numeric => try allocator.dupe(u8, "decimal"),
        .boolean, .bool => try allocator.dupe(u8, "tinyint(1)"),
        .date => try allocator.dupe(u8, "date"),
        .time => try allocator.dupe(u8, "time"),
        .datetime => try allocator.dupe(u8, "datetime"),
        .timestamp => try allocator.dupe(u8, "timestamp"),
        .char => try allocator.dupe(u8, "char"),
        .varchar, .char_varying => try allocator.dupe(u8, "varchar"),
        .text => try allocator.dupe(u8, "text"),
        .tiny_text => try allocator.dupe(u8, "tinytext"),
        .medium_text => try allocator.dupe(u8, "mediumtext"),
        .long_text => try allocator.dupe(u8, "longtext"),
        .binary => try allocator.dupe(u8, "binary"),
        .varbinary => try allocator.dupe(u8, "varbinary"),
        .blob => try allocator.dupe(u8, "blob"),
        .tiny_blob => try allocator.dupe(u8, "tinyblob"),
        .medium_blob => try allocator.dupe(u8, "mediumblob"),
        .long_blob => try allocator.dupe(u8, "longblob"),
        .json => try allocator.dupe(u8, "json"),
        .bit => |w| if (w) |n|
            try std.fmt.allocPrint(allocator, "bit({d})", .{n})
        else
            try allocator.dupe(u8, "bit"),
        .@"enum" => |values| try buildEnumSetString(allocator, "enum", values),
        .set => |values| try buildEnumSetString(allocator, "set", values),
        else => try allocator.dupe(u8, "unknown"),
    };
}

/// Build "enum('a','b','c')" or "set('a','b','c')" string.
fn buildEnumSetString(allocator: std.mem.Allocator, prefix: []const u8, values: []const []const u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, prefix);
    try buf.append(allocator, '(');

    for (values, 0..) |val, i| {
        if (i > 0) try buf.append(allocator, ',');
        try buf.append(allocator, '\'');
        // Escape single quotes in values
        for (val) |c| {
            if (c == '\'') {
                try buf.appendSlice(allocator, "''");
            } else {
                try buf.append(allocator, c);
            }
        }
        try buf.append(allocator, '\'');
    }

    try buf.append(allocator, ')');
    return try buf.toOwnedSlice(allocator);
}

/// Map a DESCRIBE-style type string to a MySQL protocol ColumnType ID.
/// This is a best-effort mapping used when building schemas from DDL.
fn datatypeToColumnTypeId(type_str: []const u8) u8 {
    // Lowercase prefix matching
    if (type_str.len == 0) return 253; // VAR_STRING default

    // Check common prefixes
    if (std.mem.startsWith(u8, type_str, "tinyint")) return 1;
    if (std.mem.startsWith(u8, type_str, "smallint")) return 2;
    if (std.mem.startsWith(u8, type_str, "mediumint")) return 9;
    if (std.mem.startsWith(u8, type_str, "bigint")) return 8;
    if (std.mem.startsWith(u8, type_str, "int")) return 3;
    if (std.mem.startsWith(u8, type_str, "float")) return 4;
    if (std.mem.startsWith(u8, type_str, "double")) return 5;
    if (std.mem.startsWith(u8, type_str, "decimal")) return 246;
    if (std.mem.startsWith(u8, type_str, "date")) {
        if (std.mem.startsWith(u8, type_str, "datetime")) return 18; // DATETIME2
        return 10;
    }
    if (std.mem.startsWith(u8, type_str, "timestamp")) return 17; // TIMESTAMP2
    if (std.mem.startsWith(u8, type_str, "time")) return 19; // TIME2
    if (std.mem.startsWith(u8, type_str, "year")) return 13;
    if (std.mem.startsWith(u8, type_str, "char")) return 254;
    if (std.mem.startsWith(u8, type_str, "varchar")) return 15;
    if (std.mem.startsWith(u8, type_str, "binary")) return 254;
    if (std.mem.startsWith(u8, type_str, "varbinary")) return 15;
    if (std.mem.startsWith(u8, type_str, "tinytext")) return 249;
    if (std.mem.startsWith(u8, type_str, "text")) return 252;
    if (std.mem.startsWith(u8, type_str, "mediumtext")) return 250;
    if (std.mem.startsWith(u8, type_str, "longtext")) return 251;
    if (std.mem.startsWith(u8, type_str, "tinyblob")) return 249;
    if (std.mem.startsWith(u8, type_str, "blob")) return 252;
    if (std.mem.startsWith(u8, type_str, "mediumblob")) return 250;
    if (std.mem.startsWith(u8, type_str, "longblob")) return 251;
    if (std.mem.startsWith(u8, type_str, "json")) return 245;
    if (std.mem.startsWith(u8, type_str, "bit")) return 16;
    if (std.mem.startsWith(u8, type_str, "enum")) return 254; // STRING
    if (std.mem.startsWith(u8, type_str, "set")) return 254; // STRING
    if (std.mem.startsWith(u8, type_str, "boolean")) return 1;

    return 253; // VAR_STRING default
}

/// Truncate SQL for log messages.
fn truncateSql(sql: []const u8) []const u8 {
    return sql[0..@min(sql.len, 120)];
}

/// Parse the QUERY_EVENT body to extract the schema (database) and SQL statement.
/// QUERY_EVENT format (after event header):
///   4 bytes: thread_id
///   4 bytes: execution_time
///   1 byte:  schema_length
///   2 bytes: error_code
///   2 bytes: status_vars_length
///   N bytes: status_vars
///   M bytes: schema (schema_length bytes)
///   1 byte:  0x00 (null terminator)
///   rest:    SQL statement
pub fn parseQueryEvent(data: []const u8) ?struct { schema: []const u8, sql: []const u8 } {
    if (data.len < 13) return null;

    const schema_length = data[8];
    const status_vars_length = std.mem.readInt(u16, data[11..13], .little);

    const status_vars_end: usize = 13 + status_vars_length;
    if (status_vars_end >= data.len) return null;

    const schema_start = status_vars_end;
    const schema_end = schema_start + schema_length;
    if (schema_end + 1 >= data.len) return null;

    const schema = data[schema_start..schema_end];

    // Skip null terminator after schema
    const sql_start = schema_end + 1;
    if (sql_start >= data.len) return null;

    // SQL goes to end, but may have trailing CRC32 (4 bytes)
    // The event data already has CRC stripped by event_parser, so use all remaining
    const sql = data[sql_start..];

    return .{ .schema = schema, .sql = sql };
}

// ============================================================
// Tests
// ============================================================

test "isTransactionControl" {
    try std.testing.expect(isTransactionControl("BEGIN"));
    try std.testing.expect(isTransactionControl("begin"));
    try std.testing.expect(isTransactionControl("COMMIT"));
    try std.testing.expect(isTransactionControl("ROLLBACK"));
    try std.testing.expect(isTransactionControl("SAVEPOINT sp1"));
    try std.testing.expect(isTransactionControl("XA START"));
    try std.testing.expect(!isTransactionControl("CREATE TABLE t1 (id INT)"));
    try std.testing.expect(!isTransactionControl("ALTER TABLE t1 ADD col INT"));
}

test "datatypeToColumnTypeId" {
    try std.testing.expectEqual(@as(u8, 3), datatypeToColumnTypeId("int"));
    try std.testing.expectEqual(@as(u8, 1), datatypeToColumnTypeId("tinyint"));
    try std.testing.expectEqual(@as(u8, 8), datatypeToColumnTypeId("bigint"));
    try std.testing.expectEqual(@as(u8, 15), datatypeToColumnTypeId("varchar"));
    try std.testing.expectEqual(@as(u8, 254), datatypeToColumnTypeId("enum('a','b')"));
    try std.testing.expectEqual(@as(u8, 254), datatypeToColumnTypeId("set('x','y')"));
    try std.testing.expectEqual(@as(u8, 245), datatypeToColumnTypeId("json"));
    try std.testing.expectEqual(@as(u8, 246), datatypeToColumnTypeId("decimal"));
}

test "buildEnumSetString" {
    const allocator = std.testing.allocator;
    const result = try buildEnumSetString(allocator, "enum", &.{ "active", "inactive" });
    defer allocator.free(result);
    try std.testing.expectEqualStrings("enum('active','inactive')", result);
}

test "parseQueryEvent" {
    // Minimal QUERY_EVENT: thread_id(4) + exec_time(4) + schema_len(1) + error_code(2) + status_vars_len(2) + schema + \0 + sql
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    buf[8] = 6; // schema_length = 6
    // status_vars_length = 0 (bytes 11-12)
    // schema starts at 13: "testdb"
    @memcpy(buf[13..19], "testdb");
    buf[19] = 0; // null terminator
    // SQL starts at 20
    const sql_text = "CREATE TABLE t1 (id INT)";
    @memcpy(buf[20 .. 20 + sql_text.len], sql_text);

    const result = parseQueryEvent(buf[0 .. 20 + sql_text.len]);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("testdb", result.?.schema);
    try std.testing.expectEqualStrings(sql_text, result.?.sql);
}

test "DDL handler CREATE TABLE integration" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(
        allocator,
        &cache,
        "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100), status ENUM('active','inactive') DEFAULT 'active')",
        "testdb",
        "binlog.000001",
        100,
    );

    const schema = cache.get("testdb", "users");
    try std.testing.expect(schema != null);
    try std.testing.expectEqual(@as(u64, 3), schema.?.columns_count);

    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("id", cols[0].column_name);
    try std.testing.expectEqualStrings("name", cols[1].column_name);
    try std.testing.expectEqualStrings("status", cols[2].column_name);
    try std.testing.expectEqualStrings("enum('active','inactive')", cols[2].column_type);
}

test "DDL handler ALTER TABLE add column" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    // First create the table
    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT, name VARCHAR(100))", "testdb", "binlog.000001", 100);

    // Then alter it
    handleDdl(allocator, &cache, "ALTER TABLE t1 ADD COLUMN email VARCHAR(255) AFTER name", "testdb", "binlog.000001", 200);

    const schema = cache.get("testdb", "t1");
    try std.testing.expect(schema != null);
    try std.testing.expectEqual(@as(u64, 3), schema.?.columns_count);

    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("id", cols[0].column_name);
    try std.testing.expectEqualStrings("name", cols[1].column_name);
    try std.testing.expectEqualStrings("email", cols[2].column_name);
}

test "DDL handler ALTER TABLE drop column" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT, name VARCHAR(100), email VARCHAR(255))", "testdb", "binlog.000001", 100);
    handleDdl(allocator, &cache, "ALTER TABLE t1 DROP COLUMN email", "testdb", "binlog.000001", 200);

    const schema = cache.get("testdb", "t1");
    try std.testing.expect(schema != null);
    try std.testing.expectEqual(@as(u64, 2), schema.?.columns_count);

    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("id", cols[0].column_name);
    try std.testing.expectEqualStrings("name", cols[1].column_name);
}

test "DDL handler ALTER TABLE rename column" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT, name VARCHAR(100))", "testdb", "binlog.000001", 100);
    handleDdl(allocator, &cache, "ALTER TABLE t1 RENAME COLUMN name TO full_name", "testdb", "binlog.000001", 200);

    const schema = cache.get("testdb", "t1");
    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("full_name", cols[1].column_name);
}

test "DDL handler ALTER TABLE change column" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT, name VARCHAR(100), age INT)", "testdb", "binlog.000001", 100);
    handleDdl(allocator, &cache, "ALTER TABLE t1 CHANGE COLUMN name full_name VARCHAR(200) FIRST", "testdb", "binlog.000001", 200);

    const schema = cache.get("testdb", "t1");
    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("full_name", cols[0].column_name);
    try std.testing.expectEqualStrings("id", cols[1].column_name);
    try std.testing.expectEqualStrings("age", cols[2].column_name);
}

test "DDL handler DROP TABLE" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT)", "testdb", "binlog.000001", 100);
    try std.testing.expect(cache.get("testdb", "t1") != null);

    handleDdl(allocator, &cache, "DROP TABLE t1", "testdb", "binlog.000001", 200);
    try std.testing.expect(cache.get("testdb", "t1") == null);
}

test "DDL handler RENAME TABLE (standalone, same database)" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT, name VARCHAR(50))", "testdb", "binlog.000001", 100);
    try std.testing.expect(cache.get("testdb", "t1") != null);

    handleDdl(allocator, &cache, "RENAME TABLE t1 TO t1_new", "testdb", "binlog.000001", 200);
    try std.testing.expect(cache.get("testdb", "t1") == null);
    const schema = cache.get("testdb", "t1_new");
    try std.testing.expect(schema != null);
    try std.testing.expectEqual(@as(u64, 2), schema.?.columns_count);
    const cols = schema.?.resolved_columns.?;
    try std.testing.expectEqualStrings("id", cols[0].column_name);
    try std.testing.expectEqualStrings("name", cols[1].column_name);
}

test "DDL handler RENAME TABLE (standalone, multiple pairs)" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE a (id INT)", "testdb", "binlog.000001", 100);
    handleDdl(allocator, &cache, "CREATE TABLE b (id INT)", "testdb", "binlog.000001", 150);

    handleDdl(allocator, &cache, "RENAME TABLE a TO a2, b TO b2", "testdb", "binlog.000001", 200);
    try std.testing.expect(cache.get("testdb", "a") == null);
    try std.testing.expect(cache.get("testdb", "b") == null);
    try std.testing.expect(cache.get("testdb", "a2") != null);
    try std.testing.expect(cache.get("testdb", "b2") != null);
}

test "DDL handler RENAME TABLE (cross database invalidates old)" {
    const allocator = std.testing.allocator;
    var cache = SchemaCache.init(allocator, null);
    defer cache.deinit();

    handleDdl(allocator, &cache, "CREATE TABLE t1 (id INT)", "db_a", "binlog.000001", 100);
    try std.testing.expect(cache.get("db_a", "t1") != null);

    handleDdl(allocator, &cache, "RENAME TABLE db_a.t1 TO db_b.t1", "db_a", "binlog.000001", 200);
    try std.testing.expect(cache.get("db_a", "t1") == null);
    // Cross-db new side is intentionally not pre-cached; DESCRIBE resolves it lazily.
    try std.testing.expect(cache.get("db_b", "t1") == null);
}
