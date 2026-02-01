//! Output Formatting
//!
//! This module provides production-ready formatting of binlog events for human-readable output.
//! All output is sent to stdout using std.debug.print for simplicity.
//!
//! Key Features:
//! - Consistent datetime formatting for both DATETIME and TIMESTAMP columns
//! - Human-readable timestamps in UTC (matches MySQL client output: 2025-10-24 19:12:54.798138)
//! - Proper microsecond precision handling (displays .000000 when precision is present)
//! - JSON values displayed as formatted strings (not binary blobs)
//! - DECIMAL values with full precision up to DECIMAL(65,30)
//! - Binary data displayed as hex strings (or size summary for large blobs)
//!
//! CDC-Ready Output:
//! The consistent formatting makes this output ideal for downstream processing:
//! - Arrow schema generation
//! - JSON serialization
//! - Data warehouse ingestion
//! - Real-time analytics pipelines

const std = @import("std");
const event_parser = @import("event_parser.zig");

/// Helper to format a RowValue for human-readable output
fn formatRowValue(value: event_parser.RowValue) void {
    switch (value) {
        .null_value => std.debug.print("NULL", .{}),
        .tiny => |v| std.debug.print("{d}", .{v}),
        .short => |v| std.debug.print("{d}", .{v}),
        .long => |v| std.debug.print("{d}", .{v}),
        .longlong => |v| std.debug.print("{d}", .{v}),
        .float => |v| std.debug.print("{d}", .{v}),
        .double => |v| std.debug.print("{d}", .{v}),
        .year => |v| std.debug.print("{d}", .{v}),
        .datetime => |v| {
            if (v.year == 0 and v.month == 0 and v.day == 0) {
                std.debug.print("0000-00-00", .{});
            } else if (v.hour == 0 and v.minute == 0 and v.second == 0 and v.microsecond == 0) {
                std.debug.print("{d:0>4}-{d:0>2}-{d:0>2}", .{ v.year, v.month, v.day });
            } else if (v.microsecond == 0) {
                std.debug.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
                    v.year, v.month, v.day, v.hour, v.minute, v.second,
                });
            } else {
                std.debug.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{
                    v.year, v.month, v.day, v.hour, v.minute, v.second, v.microsecond,
                });
            }
        },
        .timestamp => |v| {
            // Convert microseconds since epoch to datetime (UTC)
            // MySQL TIMESTAMPs are always stored in UTC, so no timezone conversion needed
            const seconds = @divFloor(v, 1_000_000);
            const micros_signed = @mod(v, 1_000_000);
            const micros: u32 = @intCast(@abs(micros_signed)); // Ensure positive microseconds

            // Convert Unix timestamp to datetime components using Zig's std.time
            const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(seconds) };
            const epoch_day = epoch_seconds.getEpochDay();
            const year_day = epoch_day.calculateYearDay();
            const month_day = year_day.calculateMonthDay();
            const day_seconds = epoch_seconds.getDaySeconds();

            const year = year_day.year;
            const month = month_day.month.numeric();
            const day = month_day.day_index + 1;
            const hour = day_seconds.getHoursIntoDay();
            const minute = day_seconds.getMinutesIntoHour();
            const second = day_seconds.getSecondsIntoMinute();

            // Format as datetime (UTC) - matches DATETIME formatting for consistency
            // This matches MySQL's NOW() and CURRENT_TIMESTAMP output format
            // Examples: "2025-10-24 19:12:54" or "2025-10-24 19:12:54.798138"
            if (micros == 0) {
                std.debug.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
                    year, month, day, hour, minute, second,
                });
            } else {
                std.debug.print("{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{
                    year, month, day, hour, minute, second, micros,
                });
            }
        },
        .duration => |v| {
            if (v.is_negative == 1) std.debug.print("-", .{});
            if (v.days > 0) std.debug.print("{d} days ", .{v.days});
            if (v.microseconds == 0) {
                std.debug.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ v.hours, v.minutes, v.seconds });
            } else {
                std.debug.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}", .{ v.hours, v.minutes, v.seconds, v.microseconds });
            }
        },
        .string => |v| std.debug.print("\"{s}\"", .{v}),
        .blob => |v| {
            // Always show hex for reasonable-sized blobs (up to 256 bytes)
            // This covers hashes, UUIDs, and most structured binary data
            if (v.len <= 256) {
                std.debug.print("0x", .{});
                for (v) |b| {
                    std.debug.print("{x:0>2}", .{b});
                }
            } else {
                // For very large blobs, show size + first 32 bytes as hex
                std.debug.print("<blob {d} bytes: 0x", .{v.len});
                const preview_len = @min(v.len, 32);
                for (v[0..preview_len]) |b| {
                    std.debug.print("{x:0>2}", .{b});
                }
                if (v.len > 32) {
                    std.debug.print("...", .{});
                }
                std.debug.print(">", .{});
            }
        },
        .decimal => |v| std.debug.print("\"{s}\"", .{v}),
        .json => |v| std.debug.print("{s}", .{v}), // JSON already formatted
    }
}

/// Format and print an event to stdout
pub fn printEvent(event: event_parser.Event) void {
    std.debug.print("=== Binlog Event ===\n", .{});
    std.debug.print("Type:      {s}\n", .{event_parser.eventTypeName(event.event_type)});
    std.debug.print("Timestamp: {d} (Unix timestamp)\n", .{event.timestamp});
    std.debug.print("Server ID: {d}\n", .{event.server_id});
    std.debug.print("Log Pos:   {d}\n", .{event.log_pos});
    std.debug.print("Flags:     0x{x:0>4}\n", .{event.flags});
    std.debug.print("Data Size: {d} bytes\n", .{event.data.len});
    std.debug.print("===================\n\n", .{});
}

/// Print connection summary
pub fn printConnectionInfo(host: []const u8, port: u16, user: ?[]const u8) void {
    std.debug.print("Connection Info:\n", .{});
    std.debug.print("  Host: {s}\n", .{host});
    std.debug.print("  Port: {d}\n", .{port});
    if (user) |u| {
        std.debug.print("  User: {s}\n", .{u});
    } else {
        std.debug.print("  User: (anonymous)\n", .{});
    }
    std.debug.print("\n", .{});
}

/// Print binlog position info
pub fn printBinlogPosition(filename: []const u8, position: u64) void {
    std.debug.print("Binlog Position:\n", .{});
    std.debug.print("  File:     {s}\n", .{filename});
    std.debug.print("  Position: {d}\n", .{position});
    std.debug.print("\n", .{});
}

/// Print detailed ROW event (DML operations)
pub fn printRowEvent(event: event_parser.Event, row_event: event_parser.RowEvent) void {
    std.debug.print("=== DML Event ({s}) ===\n", .{row_event.dmlTypeName()});
    std.debug.print("Table:     {s}.{s}\n", .{
        row_event.table_metadata.database_name,
        row_event.table_metadata.table_name,
    });
    std.debug.print("Type:      {s}\n", .{event_parser.eventTypeName(event.event_type)});
    std.debug.print("DML:       {s}\n", .{row_event.dmlTypeName()});
    std.debug.print("Timestamp: {d} (Unix timestamp)\n", .{event.timestamp});
    std.debug.print("Server ID: {d}\n", .{event.server_id});
    std.debug.print("Log Pos:   {d}\n", .{event.log_pos});
    std.debug.print("Flags:     0x{x:0>4}\n", .{event.flags});
    std.debug.print("Columns:   {d}\n", .{row_event.column_count});

    // Print column types for reference
    std.debug.print("Column Types: ", .{});
    for (row_event.table_metadata.column_types, 0..) |col_type_byte, i| {
        const col_type: event_parser.ColumnType = @enumFromInt(col_type_byte);
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}", .{col_type.name()});
    }
    std.debug.print("\n", .{});

    // Show before row values (for DELETE and UPDATE)
    if (row_event.before_values) |before| {
        std.debug.print("\nBefore Values ({d} columns):\n", .{before.len});
        for (before, 0..) |value, i| {
            std.debug.print("  [{d}] ", .{i});
            formatRowValue(value);
            std.debug.print("\n", .{});
        }
    }

    // Show after row values (for INSERT and UPDATE)
    if (row_event.after_values) |after| {
        std.debug.print("\nAfter Values ({d} columns):\n", .{after.len});
        for (after, 0..) |value, i| {
            std.debug.print("  [{d}] ", .{i});
            formatRowValue(value);
            std.debug.print("\n", .{});
        }
    }

    // If no values parsed
    if (row_event.before_values == null and row_event.after_values == null) {
        std.debug.print("\n(Row values could not be parsed)\n", .{});
    }

    std.debug.print("==========================\n\n", .{});
}
