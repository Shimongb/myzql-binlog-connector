//! Table/Schema Inclusion-Exclusion Filter
//!
//! Filters binlog events by schema and table name using a specificity-based
//! evaluation algorithm. Patterns use "schema.table" notation with wildcards:
//!
//!   - "mydb.users"     → exact match (most specific)
//!   - "*.users"        → match table "users" in any schema
//!   - "mydb.*"         → match all tables in schema "mydb"
//!
//! Specificity hierarchy (most specific wins):
//!   1. Exact match:      schema.table
//!   2. Wildcard schema:  *.table
//!   3. Wildcard table:   schema.*
//!   4. Default:          if include rules exist → exclude (whitelist mode)
//!                        otherwise → include (blacklist mode)
//!
//! Conflict detection: the same pattern cannot appear in both include and exclude.

const std = @import("std");

const log = std.log.scoped(.table_filter);

pub const FilterError = error{
    InvalidPattern,
    ConflictingPattern,
};

/// Parsed and indexed table filter for O(1) evaluation.
pub const TableFilter = struct {
    /// Exact "schema.table" patterns
    include_exact: std.StringHashMap(void),
    exclude_exact: std.StringHashMap(void),

    /// Wildcard schema patterns: table name from "*.table"
    include_wildcard_schema: std.StringHashMap(void),
    exclude_wildcard_schema: std.StringHashMap(void),

    /// Wildcard table patterns: schema name from "schema.*"
    include_wildcard_table: std.StringHashMap(void),
    exclude_wildcard_table: std.StringHashMap(void),

    /// Whether any include rules exist (determines default behavior)
    has_include_rules: bool,

    allocator: std.mem.Allocator,

    /// Total number of filter rules
    rule_count: u32,

    /// Initialize the filter from raw include/exclude pattern arrays.
    /// Validates all patterns and checks for conflicts.
    /// The pattern strings are NOT owned by the filter — they must outlive it
    /// (typically owned by the config arena allocator).
    pub fn init(
        allocator: std.mem.Allocator,
        include_patterns: ?[]const []const u8,
        exclude_patterns: ?[]const []const u8,
    ) (FilterError || std.mem.Allocator.Error)!TableFilter {
        var self = TableFilter{
            .include_exact = std.StringHashMap(void).init(allocator),
            .exclude_exact = std.StringHashMap(void).init(allocator),
            .include_wildcard_schema = std.StringHashMap(void).init(allocator),
            .exclude_wildcard_schema = std.StringHashMap(void).init(allocator),
            .include_wildcard_table = std.StringHashMap(void).init(allocator),
            .exclude_wildcard_table = std.StringHashMap(void).init(allocator),
            .has_include_rules = false,
            .allocator = allocator,
            .rule_count = 0,
        };
        errdefer self.deinit();

        // Parse include patterns
        if (include_patterns) |patterns| {
            for (patterns) |pattern| {
                const parsed = try parsePattern(pattern);
                try addRule(&self, parsed, .include);
                self.rule_count += 1;
            }
            if (patterns.len > 0) {
                self.has_include_rules = true;
            }
        }

        // Parse exclude patterns
        if (exclude_patterns) |patterns| {
            for (patterns) |pattern| {
                const parsed = try parsePattern(pattern);
                try addRule(&self, parsed, .exclude);
                self.rule_count += 1;
            }
        }

        // Check for conflicts: same pattern in both include and exclude
        try checkConflicts(&self);

        return self;
    }

    pub fn deinit(self: *TableFilter) void {
        self.include_exact.deinit();
        self.exclude_exact.deinit();
        self.include_wildcard_schema.deinit();
        self.exclude_wildcard_schema.deinit();
        self.include_wildcard_table.deinit();
        self.exclude_wildcard_table.deinit();
    }

    /// Evaluate whether a table should be included in processing.
    /// Uses specificity-based evaluation: more specific rules override less specific ones.
    pub fn shouldInclude(self: *const TableFilter, schema: []const u8, table: []const u8) bool {
        // Level 1: exact match (schema.table) — most specific
        var buf: [512]u8 = undefined;
        const fqn = std.fmt.bufPrint(&buf, "{s}.{s}", .{ schema, table }) catch {
            // Schema + table name exceeds 512 chars — include by default
            log.warn("schema.table name exceeds buffer: {s}.{s}", .{ schema, table });
            return true;
        };

        if (self.include_exact.contains(fqn)) return true;
        if (self.exclude_exact.contains(fqn)) return false;

        // Level 2: wildcard schema (*.table)
        if (self.include_wildcard_schema.contains(table)) return true;
        if (self.exclude_wildcard_schema.contains(table)) return false;

        // Level 3: wildcard table (schema.*)
        if (self.include_wildcard_table.contains(schema)) return true;
        if (self.exclude_wildcard_table.contains(schema)) return false;

        // Level 4: default behavior
        // If include rules exist → whitelist mode (exclude by default)
        // Otherwise → blacklist mode (include by default)
        if (self.has_include_rules) return false;
        return true;
    }

    /// Returns true if this filter has any rules configured.
    pub fn isActive(self: *const TableFilter) bool {
        return self.rule_count > 0;
    }

    /// Log a summary of active filter rules.
    pub fn logSummary(self: *const TableFilter) void {
        if (!self.isActive()) {
            log.info("table filter: disabled (no rules)", .{});
            return;
        }

        const include_count = self.include_exact.count() +
            self.include_wildcard_schema.count() +
            self.include_wildcard_table.count();
        const exclude_count = self.exclude_exact.count() +
            self.exclude_wildcard_schema.count() +
            self.exclude_wildcard_table.count();

        log.info("table filter: {d} include rules, {d} exclude rules", .{ include_count, exclude_count });

        // Log individual rules
        var iter = self.include_exact.keyIterator();
        while (iter.next()) |key| {
            log.info("  include: {s}", .{key.*});
        }
        iter = self.include_wildcard_schema.keyIterator();
        while (iter.next()) |key| {
            log.info("  include: *.{s}", .{key.*});
        }
        iter = self.include_wildcard_table.keyIterator();
        while (iter.next()) |key| {
            log.info("  include: {s}.*", .{key.*});
        }
        iter = self.exclude_exact.keyIterator();
        while (iter.next()) |key| {
            log.info("  exclude: {s}", .{key.*});
        }
        iter = self.exclude_wildcard_schema.keyIterator();
        while (iter.next()) |key| {
            log.info("  exclude: *.{s}", .{key.*});
        }
        iter = self.exclude_wildcard_table.keyIterator();
        while (iter.next()) |key| {
            log.info("  exclude: {s}.*", .{key.*});
        }
    }
};

/// Pattern type after parsing
const PatternType = enum {
    exact, // schema.table
    wildcard_schema, // *.table
    wildcard_table, // schema.*
};

const ParsedPattern = struct {
    pattern_type: PatternType,
    /// For exact: full "schema.table" string. For wildcard_schema: table name. For wildcard_table: schema name.
    key: []const u8,
};

const RuleKind = enum { include, exclude };

/// Parse a pattern string and validate its format.
/// Returns InvalidPattern if the pattern doesn't match "schema.table", "schema.*", or "*.table".
fn parsePattern(pattern: []const u8) FilterError!ParsedPattern {
    // Find the dot separator
    const dot_idx = std.mem.indexOfScalar(u8, pattern, '.') orelse {
        return FilterError.InvalidPattern;
    };

    // Check for multiple dots
    if (std.mem.indexOfScalarPos(u8, pattern, dot_idx + 1, '.') != null) {
        return FilterError.InvalidPattern;
    }

    const schema_part = pattern[0..dot_idx];
    const table_part = pattern[dot_idx + 1 ..];

    // Validate parts are non-empty
    if (schema_part.len == 0 or table_part.len == 0) {
        return FilterError.InvalidPattern;
    }

    const schema_is_wildcard = std.mem.eql(u8, schema_part, "*");
    const table_is_wildcard = std.mem.eql(u8, table_part, "*");

    // Reject *.*
    if (schema_is_wildcard and table_is_wildcard) {
        return FilterError.InvalidPattern;
    }

    // Reject embedded wildcards (e.g., "my*db.table" or "schema.tab*")
    if (!schema_is_wildcard and std.mem.indexOfScalar(u8, schema_part, '*') != null) {
        return FilterError.InvalidPattern;
    }
    if (!table_is_wildcard and std.mem.indexOfScalar(u8, table_part, '*') != null) {
        return FilterError.InvalidPattern;
    }

    if (schema_is_wildcard) {
        return .{ .pattern_type = .wildcard_schema, .key = table_part };
    } else if (table_is_wildcard) {
        return .{ .pattern_type = .wildcard_table, .key = schema_part };
    } else {
        return .{ .pattern_type = .exact, .key = pattern };
    }
}

/// Add a parsed rule to the appropriate map.
fn addRule(self: *TableFilter, parsed: ParsedPattern, kind: RuleKind) std.mem.Allocator.Error!void {
    const map = switch (parsed.pattern_type) {
        .exact => switch (kind) {
            .include => &self.include_exact,
            .exclude => &self.exclude_exact,
        },
        .wildcard_schema => switch (kind) {
            .include => &self.include_wildcard_schema,
            .exclude => &self.exclude_wildcard_schema,
        },
        .wildcard_table => switch (kind) {
            .include => &self.include_wildcard_table,
            .exclude => &self.exclude_wildcard_table,
        },
    };
    try map.put(parsed.key, {});
}

/// Check for conflicting patterns (same pattern in both include and exclude).
fn checkConflicts(self: *const TableFilter) FilterError!void {
    // Check exact patterns
    var iter = self.include_exact.keyIterator();
    while (iter.next()) |key| {
        if (self.exclude_exact.contains(key.*)) {
            return FilterError.ConflictingPattern;
        }
    }

    // Check wildcard schema patterns (*.table)
    iter = self.include_wildcard_schema.keyIterator();
    while (iter.next()) |key| {
        if (self.exclude_wildcard_schema.contains(key.*)) {
            return FilterError.ConflictingPattern;
        }
    }

    // Check wildcard table patterns (schema.*)
    iter = self.include_wildcard_table.keyIterator();
    while (iter.next()) |key| {
        if (self.exclude_wildcard_table.contains(key.*)) {
            return FilterError.ConflictingPattern;
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

test "no filters — include everything" {
    var filter = try TableFilter.init(std.testing.allocator, null, null);
    defer filter.deinit();

    try std.testing.expect(filter.shouldInclude("any_db", "any_table"));
    try std.testing.expect(!filter.isActive());
}

test "include exact — whitelist mode" {
    const include = [_][]const u8{ "db1.t1", "db2.t2" };
    var filter = try TableFilter.init(std.testing.allocator, &include, null);
    defer filter.deinit();

    try std.testing.expect(filter.shouldInclude("db1", "t1"));
    try std.testing.expect(filter.shouldInclude("db2", "t2"));
    // Not included → whitelist mode excludes by default
    try std.testing.expect(!filter.shouldInclude("db1", "t2"));
    try std.testing.expect(!filter.shouldInclude("db3", "t1"));
}

test "exclude exact — blacklist mode" {
    const exclude = [_][]const u8{"db1.t1"};
    var filter = try TableFilter.init(std.testing.allocator, null, &exclude);
    defer filter.deinit();

    try std.testing.expect(!filter.shouldInclude("db1", "t1"));
    // Everything else included
    try std.testing.expect(filter.shouldInclude("db1", "t2"));
    try std.testing.expect(filter.shouldInclude("db2", "t1"));
}

test "exclude schema wildcard (schema.*)" {
    const exclude = [_][]const u8{"trash_db.*"};
    var filter = try TableFilter.init(std.testing.allocator, null, &exclude);
    defer filter.deinit();

    try std.testing.expect(!filter.shouldInclude("trash_db", "any_table"));
    try std.testing.expect(!filter.shouldInclude("trash_db", "another_table"));
    try std.testing.expect(filter.shouldInclude("good_db", "any_table"));
}

test "include schema wildcard (schema.*) — whitelist" {
    const include = [_][]const u8{"prod_db.*"};
    var filter = try TableFilter.init(std.testing.allocator, &include, null);
    defer filter.deinit();

    try std.testing.expect(filter.shouldInclude("prod_db", "users"));
    try std.testing.expect(filter.shouldInclude("prod_db", "orders"));
    // Whitelist mode: other schemas excluded
    try std.testing.expect(!filter.shouldInclude("dev_db", "users"));
}

test "exclude wildcard schema (*.table)" {
    const exclude = [_][]const u8{"*.noisy_log"};
    var filter = try TableFilter.init(std.testing.allocator, null, &exclude);
    defer filter.deinit();

    try std.testing.expect(!filter.shouldInclude("db1", "noisy_log"));
    try std.testing.expect(!filter.shouldInclude("db2", "noisy_log"));
    try std.testing.expect(filter.shouldInclude("db1", "users"));
}

test "specificity: exact include overrides schema exclude" {
    // Point 6: exclude test_schema.* but include test_schema.specific_table
    const include = [_][]const u8{"test_schema.specific_table"};
    const exclude = [_][]const u8{"test_schema.*"};
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    // Exact include (level 1) wins over schema exclude (level 3)
    try std.testing.expect(filter.shouldInclude("test_schema", "specific_table"));
    // Schema exclude applies to other tables
    try std.testing.expect(!filter.shouldInclude("test_schema", "other_table"));
    // Whitelist mode: other schemas excluded by default
    try std.testing.expect(!filter.shouldInclude("other_schema", "any_table"));
}

test "specificity: exact exclude overrides schema include" {
    // Point 6: include test_schema.* but exclude test_schema.error_log
    const include = [_][]const u8{"test_schema.*"};
    const exclude = [_][]const u8{"test_schema.error_log"};
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    // Exact exclude (level 1) wins over schema include (level 3)
    try std.testing.expect(!filter.shouldInclude("test_schema", "error_log"));
    // Schema include applies to other tables
    try std.testing.expect(filter.shouldInclude("test_schema", "users"));
    // Whitelist mode: other schemas excluded
    try std.testing.expect(!filter.shouldInclude("other_schema", "any_table"));
}

test "specificity: wildcard schema include overrides wildcard table exclude" {
    // include *.special_table, exclude some_db.*
    const include = [_][]const u8{"*.special_table"};
    const exclude = [_][]const u8{"some_db.*"};
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    // *.special_table (level 2) wins over some_db.* (level 3)
    try std.testing.expect(filter.shouldInclude("some_db", "special_table"));
    // some_db.* excludes other tables
    try std.testing.expect(!filter.shouldInclude("some_db", "other_table"));
    // Whitelist default: other combinations excluded
    try std.testing.expect(!filter.shouldInclude("other_db", "other_table"));
    // *.special_table includes from other schemas too
    try std.testing.expect(filter.shouldInclude("other_db", "special_table"));
}

test "conflict detection: same exact pattern" {
    const include = [_][]const u8{"db.table"};
    const exclude = [_][]const u8{"db.table"};
    const result = TableFilter.init(std.testing.allocator, &include, &exclude);
    try std.testing.expectError(FilterError.ConflictingPattern, result);
}

test "conflict detection: same wildcard schema pattern" {
    const include = [_][]const u8{"*.my_table"};
    const exclude = [_][]const u8{"*.my_table"};
    const result = TableFilter.init(std.testing.allocator, &include, &exclude);
    try std.testing.expectError(FilterError.ConflictingPattern, result);
}

test "conflict detection: same wildcard table pattern" {
    const include = [_][]const u8{"my_db.*"};
    const exclude = [_][]const u8{"my_db.*"};
    const result = TableFilter.init(std.testing.allocator, &include, &exclude);
    try std.testing.expectError(FilterError.ConflictingPattern, result);
}

test "validation: reject missing dot" {
    const bad = [_][]const u8{"nodot"};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "validation: reject *.*" {
    const bad = [_][]const u8{"*.*"};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "validation: reject empty schema" {
    const bad = [_][]const u8{".table"};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "validation: reject empty table" {
    const bad = [_][]const u8{"schema."};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "validation: reject embedded wildcard" {
    const bad = [_][]const u8{"my*db.table"};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "validation: reject multiple dots" {
    const bad = [_][]const u8{"a.b.c"};
    const result = TableFilter.init(std.testing.allocator, &bad, null);
    try std.testing.expectError(FilterError.InvalidPattern, result);
}

test "mixed rules: include schemas + exclude specific tables" {
    const include = [_][]const u8{ "prod.*", "staging.*" };
    const exclude = [_][]const u8{ "prod.debug_log", "staging.tmp_data" };
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    try std.testing.expect(filter.shouldInclude("prod", "users"));
    try std.testing.expect(!filter.shouldInclude("prod", "debug_log"));
    try std.testing.expect(filter.shouldInclude("staging", "orders"));
    try std.testing.expect(!filter.shouldInclude("staging", "tmp_data"));
    try std.testing.expect(!filter.shouldInclude("dev", "users"));
}

test "cross-schema exclude + specific include" {
    // Exclude noisy_log everywhere, but include it from audit_db
    const include = [_][]const u8{"audit_db.noisy_log"};
    const exclude = [_][]const u8{"*.noisy_log"};
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    // Exact include (level 1) overrides wildcard schema exclude (level 2)
    try std.testing.expect(filter.shouldInclude("audit_db", "noisy_log"));
    // Wildcard exclude applies elsewhere
    try std.testing.expect(!filter.shouldInclude("app_db", "noisy_log"));
    // Whitelist mode: other tables excluded by default
    try std.testing.expect(!filter.shouldInclude("app_db", "users"));
}

test "no conflict: different specificity levels allowed" {
    // exclude schema.*, include schema.table — different specificity, no conflict
    const include = [_][]const u8{"db.table"};
    const exclude = [_][]const u8{"db.*"};
    var filter = try TableFilter.init(std.testing.allocator, &include, &exclude);
    defer filter.deinit();

    try std.testing.expect(filter.shouldInclude("db", "table"));
    try std.testing.expect(!filter.shouldInclude("db", "other"));
}
