//! MySQL DECIMAL Binary Format Parser
//!
//! Converts MySQL DECIMAL/NEWDECIMAL binary representation to human-readable strings.
//!
//! MySQL stores DECIMAL values in a packed binary format:
//! - Sign bit in first byte (0x80 = positive, inverted for negative)
//! - Digits grouped by 9s, stored as big-endian integers
//! - Bytes per group: 0→0, 1-2→1, 3-4→2, 5-6→3, 7-9→4
//!
//! Example: DECIMAL(21,4) = 1340.4000
//!   Metadata: 1045 → precision=21, decimals=4
//!   Binary: 0x800000000000053c0fa0 (10 bytes)
//!   Parsed: integral=1340 (0x53c), fractional=4000 (0x0fa0)
//!   Output: "1340.4000"

const std = @import("std");
const ArrayListWriter = @import("array_writer.zig").ArrayListWriter;

/// Calculate bytes needed for N digits in MySQL decimal format
fn digitsToBytes(digits: u8) u8 {
    return switch (digits) {
        0 => 0,
        1, 2 => 1,
        3, 4 => 2,
        5, 6 => 3,
        7, 8, 9 => 4,
        else => 0,
    };
}

/// Parse a big-endian integer from bytes
fn parseBigEndianInt(bytes: []const u8) u32 {
    var value: u32 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

/// Sign and adjusted data after extracting sign bit
const SignInfo = struct {
    is_positive: bool,
    adjusted_data: []u8,

    pub fn deinit(self: *SignInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.adjusted_data);
    }
};

/// Extract sign bit and adjust bytes for negative numbers
/// MySQL stores negative decimals with all bytes inverted
fn extractSign(allocator: std.mem.Allocator, data: []const u8) !SignInfo {
    if (data.len == 0) return error.InvalidDecimalData;

    const first_byte = data[0];
    const is_positive = (first_byte & 0x80) != 0;

    // Create mutable copy
    var adjusted = try allocator.dupe(u8, data);
    errdefer allocator.free(adjusted);

    if (!is_positive) {
        // Invert all bytes for negative numbers
        for (adjusted) |*byte| {
            byte.* = ~byte.*;
        }
    }

    // Clear sign bit (keep remaining 7 bits)
    adjusted[0] &= 0x7F;

    return SignInfo{
        .is_positive = is_positive,
        .adjusted_data = adjusted,
    };
}

/// Parsed digit groups from DECIMAL binary
const DigitGroups = struct {
    integral_leading: u32,      // Leading integral digits (< 9)
    integral_groups: []u32,     // Full 9-digit integral groups
    fractional_groups: []u32,   // Full 9-digit fractional groups
    fractional_trailing: u32,   // Trailing fractional digits (< 9)

    integral_leading_digits: u8,
    fractional_trailing_digits: u8,

    pub fn deinit(self: *DigitGroups, allocator: std.mem.Allocator) void {
        allocator.free(self.integral_groups);
        allocator.free(self.fractional_groups);
    }
};

/// Extract digit groups from adjusted binary data
fn extractDigitGroups(
    allocator: std.mem.Allocator,
    data: []const u8,
    precision: u8,
    decimals: u8,
) !DigitGroups {
    const integral = precision - decimals;
    const integral_full_groups = integral / 9;
    const integral_remaining = integral % 9;
    const fractional_full_groups = decimals / 9;
    const fractional_remaining = decimals % 9;

    var groups: DigitGroups = .{
        .integral_leading = 0,
        .integral_groups = &.{},
        .fractional_groups = &.{},
        .fractional_trailing = 0,
        .integral_leading_digits = @intCast(integral_remaining),
        .fractional_trailing_digits = @intCast(fractional_remaining),
    };

    var offset: usize = 0;

    // Parse leading integral digits (< 9)
    if (integral_remaining > 0) {
        const bytes_needed = digitsToBytes(@intCast(integral_remaining));
        if (offset + bytes_needed > data.len) return error.InvalidDecimalData;

        groups.integral_leading = parseBigEndianInt(data[offset .. offset + bytes_needed]);
        offset += bytes_needed;
    }

    // Parse full 9-digit integral groups
    if (integral_full_groups > 0) {
        groups.integral_groups = try allocator.alloc(u32, integral_full_groups);
        errdefer allocator.free(groups.integral_groups);

        for (0..integral_full_groups) |i| {
            if (offset + 4 > data.len) return error.InvalidDecimalData;
            groups.integral_groups[i] = parseBigEndianInt(data[offset .. offset + 4]);
            offset += 4;
        }
    }

    // Parse full 9-digit fractional groups
    if (fractional_full_groups > 0) {
        groups.fractional_groups = try allocator.alloc(u32, fractional_full_groups);
        errdefer allocator.free(groups.fractional_groups);

        for (0..fractional_full_groups) |i| {
            if (offset + 4 > data.len) return error.InvalidDecimalData;
            groups.fractional_groups[i] = parseBigEndianInt(data[offset .. offset + 4]);
            offset += 4;
        }
    }

    // Parse trailing fractional digits (< 9)
    if (fractional_remaining > 0) {
        const bytes_needed = digitsToBytes(@intCast(fractional_remaining));
        if (offset + bytes_needed > data.len) return error.InvalidDecimalData;

        groups.fractional_trailing = parseBigEndianInt(data[offset .. offset + bytes_needed]);
        offset += bytes_needed;
    }

    return groups;
}

/// Convert digit groups to a decimal string
fn groupsToString(
    allocator: std.mem.Allocator,
    groups: DigitGroups,
    is_positive: bool,
    decimals: u8,
) ![]const u8 {
    var buffer = try std.ArrayList(u8).initCapacity(allocator, 32);
    errdefer buffer.deinit(allocator);
    var w = ArrayListWriter.init(&buffer, allocator);

    // Add sign for negative numbers
    if (!is_positive) {
        try buffer.append(allocator, '-');
    }

    // Integral part
    var has_integral = false;

    // Leading integral digits (no padding, skip if zero)
    if (groups.integral_leading_digits > 0 and groups.integral_leading > 0) {
        try w.print("{d}", .{groups.integral_leading});
        has_integral = true;
    }

    // Full 9-digit integral groups (pad to 9 digits)
    for (groups.integral_groups) |group| {
        if (has_integral) {
            // Pad to 9 digits
            try w.print("{d:0>9}", .{group});
        } else {
            // First non-zero group - no padding
            if (group > 0) {
                try w.print("{d}", .{group});
                has_integral = true;
            }
        }
    }

    // If no integral part (all zeros), add "0"
    if (!has_integral) {
        try buffer.append(allocator, '0');
    }

    // Decimal point and fractional part
    if (decimals > 0) {
        try buffer.append(allocator, '.');

        // Full 9-digit fractional groups (always pad to 9)
        for (groups.fractional_groups) |group| {
            try w.print("{d:0>9}", .{group});
        }

        // Trailing fractional digits (pad to exact digit count)
        if (groups.fractional_trailing_digits > 0) {
            const width = groups.fractional_trailing_digits;
            try w.print("{d:0>[1]}", .{ groups.fractional_trailing, width });
        }
    }

    return buffer.toOwnedSlice(allocator);
}

/// Convert MySQL DECIMAL binary format to human-readable string
///
/// Parameters:
///   - allocator: Memory allocator for string allocation
///   - binary_data: Raw bytes from binlog (includes sign bit)
///   - precision: Total number of digits (from metadata & 0xFF)
///   - decimals: Number of fractional digits (from metadata >> 8)
///
/// Returns: Allocated string (caller must free)
///
/// Example:
///   binary: 0x800000000000053c0fa0
///   precision: 21, decimals: 4
///   Returns: "1340.4000"
pub fn decimalToString(
    allocator: std.mem.Allocator,
    binary_data: []const u8,
    precision: u8,
    decimals: u8,
) ![]const u8 {
    if (binary_data.len == 0) {
        return allocator.dupe(u8, "0");
    }

    // Step 1: Extract sign and adjust bytes for negative numbers
    var sign_info = try extractSign(allocator, binary_data);
    defer sign_info.deinit(allocator);

    // Step 2: Parse digit groups from binary
    var groups = try extractDigitGroups(
        allocator,
        sign_info.adjusted_data,
        precision,
        decimals,
    );
    defer groups.deinit(allocator);

    // Step 3: Convert to string
    return try groupsToString(
        allocator,
        groups,
        sign_info.is_positive,
        decimals,
    );
}

// ============================================================================
// TESTS
// ============================================================================

test "digitsToBytes" {
    const testing = std.testing;
    try testing.expectEqual(@as(u8, 0), digitsToBytes(0));
    try testing.expectEqual(@as(u8, 1), digitsToBytes(1));
    try testing.expectEqual(@as(u8, 1), digitsToBytes(2));
    try testing.expectEqual(@as(u8, 2), digitsToBytes(3));
    try testing.expectEqual(@as(u8, 2), digitsToBytes(4));
    try testing.expectEqual(@as(u8, 3), digitsToBytes(5));
    try testing.expectEqual(@as(u8, 3), digitsToBytes(6));
    try testing.expectEqual(@as(u8, 4), digitsToBytes(7));
    try testing.expectEqual(@as(u8, 4), digitsToBytes(8));
    try testing.expectEqual(@as(u8, 4), digitsToBytes(9));
}

test "parseBigEndianInt" {
    const testing = std.testing;

    // 1 byte
    try testing.expectEqual(@as(u32, 0x12), parseBigEndianInt(&[_]u8{0x12}));

    // 2 bytes
    try testing.expectEqual(@as(u32, 0x1234), parseBigEndianInt(&[_]u8{0x12, 0x34}));

    // 4 bytes
    try testing.expectEqual(@as(u32, 0x12345678), parseBigEndianInt(&[_]u8{0x12, 0x34, 0x56, 0x78}));
}

test "decimalToString - positive simple" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // DECIMAL(5,2) = 123.45
    // Integral: 3 digits = 2 bytes
    // Fractional: 2 digits = 1 byte
    // Total: 3 bytes
    // Binary WITHOUT sign: 0x007B (123) + 0x2D (45)
    // Binary WITH sign bit: 0x807B2D
    const binary = [_]u8{ 0x80, 0x7B, 0x2D };
    const result = try decimalToString(allocator, &binary, 5, 2);
    defer allocator.free(result);

    try testing.expectEqualStrings("123.45", result);
}

test "decimalToString - real world example DECIMAL(21,4) = 1340.4000" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // From the user's example
    // DECIMAL(21,4) = 1340.4000
    // Binary: 0x800000000000053c0fa0 (10 bytes)
    const binary = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x3c, 0x0f, 0xa0 };
    const result = try decimalToString(allocator, &binary, 21, 4);
    defer allocator.free(result);

    try testing.expectEqualStrings("1340.4000", result);
}

test "decimalToString - zero" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // DECIMAL(10,2) = 0.00
    // All zeros with sign bit set
    const binary = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x00 };
    const result = try decimalToString(allocator, &binary, 10, 2);
    defer allocator.free(result);

    try testing.expectEqualStrings("0.00", result);
}

test "decimalToString - negative" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // DECIMAL(5,2) = -123.45
    // Positive binary: 0x807B2D
    // Negative: invert all bits
    // ~0x80 = 0x7F, ~0x7B = 0x84, ~0x2D = 0xD2
    const binary = [_]u8{ 0x7F, 0x84, 0xD2 };
    const result = try decimalToString(allocator, &binary, 5, 2);
    defer allocator.free(result);

    try testing.expectEqualStrings("-123.45", result);
}

test "decimalToString - no fractional part" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // DECIMAL(10,0) = 1000000
    // Integral: 10 digits, split as 1 leading + 9 full
    // To store 1000000 (0001000000 in 10 digits):
    //   Leading 1 digit: 0
    //   Full 9 digits: 001000000 = 1000000 = 0x000F4240
    // Bytes: 1 (leading) + 4 (full) = 5 bytes
    // Binary: [0x00, 0x00, 0x0F, 0x42, 0x40]
    // With sign: [0x80, 0x00, 0x0F, 0x42, 0x40]
    const binary = [_]u8{ 0x80, 0x00, 0x0F, 0x42, 0x40 };
    const result = try decimalToString(allocator, &binary, 10, 0);
    defer allocator.free(result);

    try testing.expectEqualStrings("1000000", result);
}

test "decimalToString - small fraction" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // DECIMAL(10,4) = 0.0001
    // Integral: 6 digits, 0 full + 6 remaining → 3 bytes → value=0
    // Fractional: 4 digits, 0 full + 4 remaining → 2 bytes → value=1 (0001)
    // Total: 3 + 2 = 5 bytes
    // Binary: [0x00, 0x00, 0x00, 0x00, 0x01]
    // With sign: [0x80, 0x00, 0x00, 0x00, 0x01]
    const binary = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x01 };
    const result = try decimalToString(allocator, &binary, 10, 4);
    defer allocator.free(result);

    try testing.expectEqualStrings("0.0001", result);
}
