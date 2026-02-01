//! Pipeline Metrics
//!
//! Tracks timing and throughput for the parquet pipeline workers.

const std = @import("std");

const log = std.log.scoped(.metrics);

/// Get current wall-clock time in nanoseconds (replacement for removed std.time.nanoTimestamp)
pub fn nanoTimestamp() i128 {
    const ts = std.posix.clock_gettime(.REALTIME) catch return 0;
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}

pub const PipelineMetrics = struct {
    start_ns: i128 = 0,
    end_ns: i128 = 0,
    total_processing_ns: i128 = 0,
    total_flush_ns: i128 = 0,
    rows_processed: u64 = 0,
    batches_flushed: u64 = 0,
    bytes_written: u64 = 0,

    pub fn merge(self: *PipelineMetrics, other: PipelineMetrics) void {
        self.total_processing_ns += other.total_processing_ns;
        self.total_flush_ns += other.total_flush_ns;
        self.rows_processed += other.rows_processed;
        self.batches_flushed += other.batches_flushed;
        self.bytes_written += other.bytes_written;
        if (other.start_ns != 0 and (self.start_ns == 0 or other.start_ns < self.start_ns)) {
            self.start_ns = other.start_ns;
        }
        if (other.end_ns > self.end_ns) {
            self.end_ns = other.end_ns;
        }
    }

    pub fn printSummary(self: PipelineMetrics) void {
        log.info("pipeline metrics: rows_processed={d} batches_flushed={d} bytes_written={d}", .{
            self.rows_processed, self.batches_flushed, self.bytes_written,
        });

        if (self.total_processing_ns > 0) {
            const proc_ms = @as(f64, @floatFromInt(self.total_processing_ns)) / 1_000_000.0;
            log.info("pipeline timing: processing={d:.2}ms", .{proc_ms});
        }
        if (self.total_flush_ns > 0) {
            const flush_ms = @as(f64, @floatFromInt(self.total_flush_ns)) / 1_000_000.0;
            log.info("pipeline timing: flush={d:.2}ms", .{flush_ms});
        }
        if (self.end_ns > self.start_ns and self.start_ns != 0) {
            const total_ms = @as(f64, @floatFromInt(self.end_ns - self.start_ns)) / 1_000_000.0;
            log.info("pipeline timing: end_to_end={d:.2}ms", .{total_ms});

            if (self.rows_processed > 0) {
                const rows_per_sec = @as(f64, @floatFromInt(self.rows_processed)) / (total_ms / 1000.0);
                log.info("pipeline throughput: {d:.0} rows/sec", .{rows_per_sec});
            }
        }
    }
};

test "metrics merge" {
    var a = PipelineMetrics{
        .start_ns = 100,
        .end_ns = 500,
        .rows_processed = 10,
        .batches_flushed = 1,
    };
    const b = PipelineMetrics{
        .start_ns = 50,
        .end_ns = 600,
        .rows_processed = 20,
        .batches_flushed = 2,
        .bytes_written = 1024,
    };
    a.merge(b);

    try std.testing.expectEqual(@as(u64, 30), a.rows_processed);
    try std.testing.expectEqual(@as(u64, 3), a.batches_flushed);
    try std.testing.expectEqual(@as(u64, 1024), a.bytes_written);
    try std.testing.expectEqual(@as(i128, 50), a.start_ns);
    try std.testing.expectEqual(@as(i128, 600), a.end_ns);
}
