//! Cold-start prerequisite checks.
//!
//! Runs at init, after connection/ping but before opening the replication
//! stream. Covers:
//!
//! - **Hard fail** if `binlog_format` != `ROW` or `binlog_row_image` != `FULL`.
//!   These server settings are load-bearing for CDC/PITR; silently degraded
//!   output is worse than a crash at init.
//! - **Soft warn** if `REPLICATION SLAVE`/`CLIENT` grants aren't visibly
//!   present. Grant output format varies across MySQL/MariaDB versions, so
//!   a false negative here is worse than a false positive. Binlog open
//!   itself will fail loudly if grants are actually missing.
//! - **Graceful adjust** if the requested binlog position is missing on the
//!   server (expired by `PURGE BINARY LOGS`, failover reset, gap in chain).
//!   Adjust to the *oldest* available binlog (not latest) — minimizes data
//!   loss, allows ops to backfill the gap later.

const std = @import("std");
const connection = @import("connection.zig");

const log = std.log.scoped(.prereq);

pub const Error = error{
    BinlogFormatNotRow,
    BinlogRowImageNotFull,
    NoBinlogsAvailable,
    /// `SHOW MASTER STATUS` returned zero rows or unparseable data —
    /// usually means binlog is disabled on the server.
    NoMasterPosition,
};

/// Result of `getMasterPosition`. `file` is allocated from the caller's
/// allocator; the caller owns it.
pub const MasterPosition = struct {
    file: []const u8,
    position: u64,
};

/// Effective binlog start position after all checks run. Either the
/// requested position (valid) or the adjusted one (oldest available).
pub const Outcome = struct {
    /// Caller owns this memory (allocated from the passed-in allocator).
    file: []const u8,
    position: u64,
    /// True when the server was missing the requested file and we moved
    /// the start position to the oldest available binlog.
    adjusted: bool,
};

/// Run all prerequisite checks. Returns the effective start position.
pub fn run(
    allocator: std.mem.Allocator,
    conn: *connection.Connection,
    requested_file: []const u8,
    requested_position: u64,
) !Outcome {
    try checkServerConfig(conn);

    // Grants check is best-effort; failures here never abort startup.
    checkReplicationGrants(conn) catch |err| {
        log.warn("grants check skipped: {} (non-fatal)", .{err});
    };

    return validateBinlogPosition(allocator, conn, requested_file, requested_position);
}

/// Hard-fail if `binlog_format` != ROW or `binlog_row_image` != FULL.
fn checkServerConfig(conn: *connection.Connection) !void {
    const sql =
        "SHOW VARIABLES WHERE Variable_name IN ('binlog_format','binlog_row_image')";
    var rs = try conn.queryRows(sql);
    defer rs.deinit();

    var format_seen = false;
    var row_image_seen = false;

    for (rs.rows) |row| {
        if (row.values.len < 2) continue;
        const name = row.values[0] orelse continue;
        const value = row.values[1] orelse continue;

        if (std.ascii.eqlIgnoreCase(name, "binlog_format")) {
            format_seen = true;
            if (!std.ascii.eqlIgnoreCase(value, "ROW")) {
                log.err(
                    "binlog_format={s}, required ROW. Row-based events are mandatory for CDC; STATEMENT/MIXED yields SQL text instead of row data.",
                    .{value},
                );
                return Error.BinlogFormatNotRow;
            }
            log.info("binlog_format={s} [OK]", .{value});
        } else if (std.ascii.eqlIgnoreCase(name, "binlog_row_image")) {
            row_image_seen = true;
            if (!std.ascii.eqlIgnoreCase(value, "FULL")) {
                log.err(
                    "binlog_row_image={s}, required FULL. Partial images break UPDATE/DELETE before-value capture and PITR.",
                    .{value},
                );
                return Error.BinlogRowImageNotFull;
            }
            log.info("binlog_row_image={s} [OK]", .{value});
        }
    }

    if (!format_seen) {
        log.warn("SHOW VARIABLES did not return binlog_format — cannot verify", .{});
    }
    if (!row_image_seen) {
        log.warn("SHOW VARIABLES did not return binlog_row_image — cannot verify", .{});
    }
}

/// Best-effort grants check. Emits WARN on missing or unparseable grants;
/// never returns an error that blocks startup.
fn checkReplicationGrants(conn: *connection.Connection) !void {
    var rs = try conn.queryRows("SHOW GRANTS FOR CURRENT_USER()");
    defer rs.deinit();

    var has_slave = false;
    var has_client = false;

    for (rs.rows) |row| {
        if (row.values.len < 1) continue;
        const grant = row.values[0] orelse continue;

        if (containsAsciiIgnoreCase(grant, "ALL PRIVILEGES")) {
            log.info("replication grants: ALL PRIVILEGES detected [OK]", .{});
            return;
        }
        if (containsAsciiIgnoreCase(grant, "REPLICATION SLAVE")) has_slave = true;
        if (containsAsciiIgnoreCase(grant, "REPLICATION CLIENT")) has_client = true;
    }

    if (has_slave and has_client) {
        log.info("replication grants: SLAVE + CLIENT detected [OK]", .{});
    } else {
        log.warn(
            "replication grants not visible (SLAVE={}, CLIENT={}). May be a false negative — grant formats vary across MySQL/MariaDB versions. Binlog open will fail loudly if grants are actually missing.",
            .{ has_slave, has_client },
        );
    }
}

/// Three-way validation of the requested binlog position.
///
/// - If the file exists on the server, return the requested position as-is.
/// - If missing, return the oldest-available file at position 4, with a loud
///   WARN and `adjusted = true`. Position 4 is the standard start offset
///   (just past the magic header).
/// - If the server has zero binlog files, return `NoBinlogsAvailable` —
///   critical infrastructure issue, cannot proceed.
fn validateBinlogPosition(
    allocator: std.mem.Allocator,
    conn: *connection.Connection,
    requested_file: []const u8,
    requested_position: u64,
) !Outcome {
    var rs = try conn.queryRows("SHOW BINARY LOGS");
    defer rs.deinit();

    if (rs.rows.len == 0) {
        log.err("SHOW BINARY LOGS returned zero rows — server has no binlog files", .{});
        return Error.NoBinlogsAvailable;
    }

    // SHOW BINARY LOGS columns: Log_name, File_size[, Encrypted]. Server
    // returns rows in on-disk (chronological) order; we rely on that instead
    // of re-sorting, since numeric-suffix sort on the filename would have
    // its own edge cases (rollover at .999999 etc).
    var oldest: ?[]const u8 = null;
    var latest: ?[]const u8 = null;
    var exists = false;

    for (rs.rows) |row| {
        if (row.values.len < 1) continue;
        const name = row.values[0] orelse continue;
        if (oldest == null) oldest = name;
        latest = name;
        if (std.mem.eql(u8, name, requested_file)) exists = true;
    }

    if (exists) {
        log.info(
            "binlog position {s}:{d} [VALID]",
            .{ requested_file, requested_position },
        );
        return .{
            .file = try allocator.dupe(u8, requested_file),
            .position = requested_position,
            .adjusted = false,
        };
    }

    // File missing — classify the gap for operator diagnosis, then adjust.
    const oldest_name = oldest orelse return Error.NoBinlogsAvailable;

    const gap_type: []const u8 = blk: {
        if (std.mem.order(u8, requested_file, oldest_name) == .lt) {
            break :blk "expired (older than oldest available)";
        }
        if (latest) |lat| {
            if (std.mem.order(u8, requested_file, lat) == .gt) {
                break :blk "not yet created (newer than latest available)";
            }
        }
        break :blk "missing (gap in binlog chain)";
    };

    log.warn(
        "requested binlog position {s}:{d} NOT FOUND — {s}. Oldest available: {s}, latest: {s}.",
        .{
            requested_file,
            requested_position,
            gap_type,
            oldest_name,
            latest orelse "<none>",
        },
    );
    log.warn(
        "adjusting to oldest available {s}:4 — minimizes data loss; operators can backfill the gap from upstream if needed.",
        .{oldest_name},
    );

    return .{
        .file = try allocator.dupe(u8, oldest_name),
        .position = 4,
        .adjusted = true,
    };
}

/// Query the server's current binlog write head. Used as the bootstrap-of-
/// last-resort by the connector's init flow (when neither a checkpoint nor
/// `from_binlog_*` config is available), and again at init when
/// `bound_to_master_at_init` sets the run's ceiling.
///
/// Tries `SHOW BINARY LOG STATUS` first (MySQL 8.4+); falls back to
/// `SHOW MASTER STATUS` (5.7 / 8.0 / 8.4-deprecated, MariaDB) on any
/// query error. If both fail, surfaces the second error so the operator
/// sees the most likely diagnostic.
pub fn getMasterPosition(
    allocator: std.mem.Allocator,
    conn: *connection.Connection,
) !MasterPosition {
    var rs = blk: {
        if (conn.queryRows("SHOW BINARY LOG STATUS")) |rs| {
            break :blk rs;
        } else |err| {
            log.debug("SHOW BINARY LOG STATUS not supported ({}); falling back to SHOW MASTER STATUS", .{err});
            break :blk try conn.queryRows("SHOW MASTER STATUS");
        }
    };
    defer rs.deinit();

    if (rs.rows.len == 0) {
        log.err("master-status query returned zero rows — binlog is likely disabled on this server", .{});
        return Error.NoMasterPosition;
    }

    const row = rs.rows[0];
    if (row.values.len < 2) {
        log.err("master-status row has fewer than 2 columns ({d})", .{row.values.len});
        return Error.NoMasterPosition;
    }

    const file = row.values[0] orelse {
        log.err("master-status file column is NULL", .{});
        return Error.NoMasterPosition;
    };
    const pos_str = row.values[1] orelse {
        log.err("master-status position column is NULL", .{});
        return Error.NoMasterPosition;
    };

    const position = std.fmt.parseInt(u64, pos_str, 10) catch |err| {
        log.err("master-status position '{s}' is not numeric: {}", .{ pos_str, err });
        return Error.NoMasterPosition;
    };

    return .{
        .file = try allocator.dupe(u8, file),
        .position = position,
    };
}

/// ASCII-only case-insensitive substring check.
fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

// ============================================================
// Tests — pure helpers only. Query wrappers need a live MySQL
// connection and are exercised by the Docker integration test.
// ============================================================

test "containsAsciiIgnoreCase basic hits and misses" {
    try std.testing.expect(containsAsciiIgnoreCase("foo BAR baz", "bar"));
    try std.testing.expect(containsAsciiIgnoreCase("GRANT REPLICATION SLAVE ON", "replication slave"));
    try std.testing.expect(containsAsciiIgnoreCase("REPLICATION CLIENT", "REPLICATION CLIENT"));
    try std.testing.expect(!containsAsciiIgnoreCase("foo", "bar"));
    try std.testing.expect(!containsAsciiIgnoreCase("replication slav", "replication slave"));
}

test "containsAsciiIgnoreCase edge cases" {
    try std.testing.expect(containsAsciiIgnoreCase("anything", ""));
    try std.testing.expect(!containsAsciiIgnoreCase("", "x"));
    try std.testing.expect(containsAsciiIgnoreCase("xx", "xx"));
}
