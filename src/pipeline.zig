//! Two-Worker Pipeline
//!
//! Orchestrates concurrent event processing and Parquet flushing.
//!
//! Architecture:
//!   Main Thread → [event_queue] → Processing Worker → [flush_queue] → Flush Worker
//!
//! The processing worker serializes row values to JSON and accumulates batches.
//! The flush worker writes batches as Parquet row groups.

const std = @import("std");
const MpscQueue = @import("mpsc_queue.zig").MpscQueue;
const ParquetWriter = @import("parquet_writer.zig").ParquetWriter;
const parquet_writer = @import("parquet_writer.zig");
const RowJsonSerializer = @import("row_json_serializer.zig").RowJsonSerializer;
const event_parser = @import("event_parser.zig");
const metrics = @import("metrics.zig");
const PipelineMetrics = metrics.PipelineMetrics;

const log = std.log.scoped(.pipeline);

/// Data for a single row event, with ownership of all string data
pub const RowEventData = struct {
    timestamp: i64,
    server_id: u32,
    log_pos: u64,
    event_row_index: u64,
    database: ?[]const u8,
    table_name: ?[]const u8,
    dml_type: event_parser.DmlType,
    before_values: ?[]event_parser.RowValue,
    after_values: ?[]event_parser.RowValue,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RowEventData) void {
        if (self.database) |d| self.allocator.free(d);
        if (self.table_name) |t| self.allocator.free(t);
        freeRowValues(self.allocator, self.before_values);
        freeRowValues(self.allocator, self.after_values);
    }

    fn freeRowValues(allocator: std.mem.Allocator, values: ?[]event_parser.RowValue) void {
        if (values) |vals| {
            for (vals) |v| {
                switch (v) {
                    .decimal => |str| allocator.free(str),
                    .json => |str| allocator.free(str),
                    .string => |str| allocator.free(str),
                    .blob => |b| allocator.free(b),
                    else => {},
                }
            }
            allocator.free(vals);
        }
    }
};

pub const RotateData = struct {
    next_binlog_file: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RotateData) void {
        self.allocator.free(self.next_binlog_file);
    }
};

pub const PipelineMessage = union(enum) {
    row_event: RowEventData,
    rotate: RotateData,
    shutdown: void,
};

pub const FlushMessage = union(enum) {
    batch: *ColumnBatch,
    rotate: RotateData,
    shutdown: void,
};

/// Columnar batch for efficient Parquet writing
pub const ColumnBatch = struct {
    capacity: usize,
    count: usize,
    timestamps: []i64,
    server_ids: []i32,
    log_positions: []i64,
    event_row_indices: []i64,
    databases: []?[]const u8,
    table_names: []?[]const u8,
    dml_types: [][]const u8,
    before_values_json: []?[]const u8,
    after_values_json: []?[]const u8,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !*ColumnBatch {
        const batch = try allocator.create(ColumnBatch);
        errdefer allocator.destroy(batch);

        batch.* = .{
            .capacity = capacity,
            .count = 0,
            .timestamps = undefined,
            .server_ids = undefined,
            .log_positions = undefined,
            .event_row_indices = undefined,
            .databases = undefined,
            .table_names = undefined,
            .dml_types = undefined,
            .before_values_json = undefined,
            .after_values_json = undefined,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };

        const arena_alloc = batch.arena.allocator();
        batch.timestamps = try arena_alloc.alloc(i64, capacity);
        batch.server_ids = try arena_alloc.alloc(i32, capacity);
        batch.log_positions = try arena_alloc.alloc(i64, capacity);
        batch.event_row_indices = try arena_alloc.alloc(i64, capacity);
        batch.databases = try arena_alloc.alloc(?[]const u8, capacity);
        batch.table_names = try arena_alloc.alloc(?[]const u8, capacity);
        batch.dml_types = try arena_alloc.alloc([]const u8, capacity);
        batch.before_values_json = try arena_alloc.alloc(?[]const u8, capacity);
        batch.after_values_json = try arena_alloc.alloc(?[]const u8, capacity);

        return batch;
    }

    pub fn appendRow(
        self: *ColumnBatch,
        timestamp: i64,
        server_id: i32,
        log_pos: i64,
        event_row_index: i64,
        database: ?[]const u8,
        table_name: ?[]const u8,
        dml_type: []const u8,
        before_json: ?[]const u8,
        after_json: ?[]const u8,
    ) !void {
        const idx = self.count;
        const arena_alloc = self.arena.allocator();

        self.timestamps[idx] = timestamp;
        self.server_ids[idx] = server_id;
        self.log_positions[idx] = log_pos;
        self.event_row_indices[idx] = event_row_index;
        self.databases[idx] = if (database) |d| try arena_alloc.dupe(u8, d) else null;
        self.table_names[idx] = if (table_name) |t| try arena_alloc.dupe(u8, t) else null;
        self.dml_types[idx] = try arena_alloc.dupe(u8, dml_type);
        self.before_values_json[idx] = if (before_json) |b| try arena_alloc.dupe(u8, b) else null;
        self.after_values_json[idx] = if (after_json) |a| try arena_alloc.dupe(u8, a) else null;

        self.count += 1;
    }

    pub fn isFull(self: *const ColumnBatch) bool {
        return self.count >= self.capacity;
    }

    pub fn toRowBatch(self: *const ColumnBatch) parquet_writer.RowBatch {
        return .{
            .count = self.count,
            .timestamps = self.timestamps,
            .server_ids = self.server_ids,
            .log_positions = self.log_positions,
            .event_row_indices = self.event_row_indices,
            .databases = self.databases,
            .table_names = self.table_names,
            .dml_types = self.dml_types,
            .before_values_json = self.before_values_json,
            .after_values_json = self.after_values_json,
        };
    }

    pub fn deinit(self: *ColumnBatch) void {
        const backing_allocator = self.arena.child_allocator;
        self.arena.deinit();
        backing_allocator.destroy(self);
    }
};

pub const Pipeline = struct {
    allocator: std.mem.Allocator,
    event_queue: MpscQueue(PipelineMessage),
    flush_queue: MpscQueue(FlushMessage),
    processing_thread: ?std.Thread,
    flush_thread: ?std.Thread,
    batch_size: usize,
    output_dir: []const u8,
    current_binlog_file: []const u8,
    processing_metrics: PipelineMetrics,
    flush_metrics: PipelineMetrics,

    pub fn init(
        allocator: std.mem.Allocator,
        output_dir: []const u8,
        initial_binlog_file: []const u8,
        batch_size: usize,
        event_queue_capacity: usize,
    ) !*Pipeline {
        const self = try allocator.create(Pipeline);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .event_queue = try MpscQueue(PipelineMessage).init(allocator, event_queue_capacity),
            .flush_queue = try MpscQueue(FlushMessage).init(allocator, 4),
            .processing_thread = null,
            .flush_thread = null,
            .batch_size = batch_size,
            .output_dir = try allocator.dupe(u8, output_dir),
            .current_binlog_file = try allocator.dupe(u8, initial_binlog_file),
            .processing_metrics = .{},
            .flush_metrics = .{},
        };

        // Ensure output directory exists (use posix mkdir)
        const dir_z = allocator.dupeZ(u8, output_dir) catch |err| {
            log.warn("could not alloc dir path '{s}': {}", .{ output_dir, err });
            return err;
        };
        defer allocator.free(dir_z);
        _ = std.c.mkdir(dir_z.ptr, 0o755);

        // Spawn workers
        self.flush_thread = try std.Thread.spawn(.{}, flushWorker, .{self});
        self.processing_thread = try std.Thread.spawn(.{}, processingWorker, .{self});

        return self;
    }

    pub fn send(self: *Pipeline, msg: PipelineMessage) bool {
        return self.event_queue.push(msg);
    }

    pub fn shutdown(self: *Pipeline) void {
        _ = self.event_queue.push(.shutdown);
    }

    pub fn join(self: *Pipeline) PipelineMetrics {
        if (self.processing_thread) |t| {
            t.join();
            self.processing_thread = null;
        }
        if (self.flush_thread) |t| {
            t.join();
            self.flush_thread = null;
        }

        var combined = PipelineMetrics{};
        combined.merge(self.processing_metrics);
        combined.merge(self.flush_metrics);
        return combined;
    }

    pub fn deinit(self: *Pipeline) void {
        self.event_queue.deinit();
        self.flush_queue.deinit();
        self.allocator.free(self.output_dir);
        self.allocator.free(self.current_binlog_file);
        self.allocator.destroy(self);
    }

    fn processingWorker(self: *Pipeline) void {
        var serializer = RowJsonSerializer.init(self.allocator);
        defer serializer.deinit();

        var current_batch: ?*ColumnBatch = ColumnBatch.init(self.allocator, self.batch_size) catch {
            log.err("processing_worker: failed to allocate initial batch", .{});
            return;
        };

        while (true) {
            const msg = self.event_queue.pop() orelse break;

            switch (msg) {
                .row_event => |row_data_const| {
                    var row_data = row_data_const;
                    defer row_data.deinit();

                    const start = metrics.nanoTimestamp();

                    // Serialize before/after values to JSON.
                    // IMPORTANT: serialize() returns a slice into an internal reusable buffer,
                    // so we must copy before_json before calling serialize() again for after_json,
                    // otherwise before_json becomes a dangling reference to overwritten memory.
                    var before_json: ?[]const u8 = null;
                    var before_json_copy: ?[]u8 = null;
                    var after_json: ?[]const u8 = null;
                    defer if (before_json_copy) |b| self.allocator.free(b);

                    if (row_data.before_values) |vals| {
                        if (serializer.serialize(vals)) |json| {
                            before_json_copy = self.allocator.dupe(u8, json) catch null;
                            before_json = before_json_copy;
                        } else |_| {}
                    }
                    if (row_data.after_values) |vals| {
                        after_json = serializer.serialize(vals) catch null;
                    }

                    const dml_str: []const u8 = switch (row_data.dml_type) {
                        .Insert => "INSERT",
                        .Update => "UPDATE",
                        .Delete => "DELETE",
                    };

                    if (current_batch) |batch| {
                        batch.appendRow(
                            @intCast(row_data.timestamp),
                            @intCast(row_data.server_id),
                            @intCast(row_data.log_pos),
                            @intCast(row_data.event_row_index),
                            row_data.database,
                            row_data.table_name,
                            dml_str,
                            before_json,
                            after_json,
                        ) catch {
                            log.err("processing_worker: failed to append row to batch", .{});
                            continue;
                        };

                        self.processing_metrics.rows_processed += 1;

                        if (self.processing_metrics.rows_processed % 10_000 == 0) {
                            log.info("processing_worker: processed {d} rows", .{self.processing_metrics.rows_processed});
                        }

                        if (batch.isFull()) {
                            _ = self.flush_queue.push(.{ .batch = batch });
                            current_batch = ColumnBatch.init(self.allocator, self.batch_size) catch {
                                log.err("processing_worker: failed to allocate new batch", .{});
                                current_batch = null;
                                continue;
                            };
                        }
                    }

                    const elapsed = metrics.nanoTimestamp() - start;
                    self.processing_metrics.total_processing_ns += elapsed;
                },
                .rotate => |rotate_data| {
                    // Flush current batch before rotation
                    if (current_batch) |batch| {
                        if (batch.count > 0) {
                            _ = self.flush_queue.push(.{ .batch = batch });
                        } else {
                            batch.deinit();
                        }
                        current_batch = null;
                    }

                    // Forward rotate to flush worker
                    _ = self.flush_queue.push(.{ .rotate = rotate_data });

                    // Allocate new batch
                    current_batch = ColumnBatch.init(self.allocator, self.batch_size) catch |err| {
                        log.err("processing_worker: failed to allocate batch after rotate: {}", .{err});
                        continue;
                    };
                },
                .shutdown => {
                    // Flush remaining batch
                    if (current_batch) |batch| {
                        if (batch.count > 0) {
                            _ = self.flush_queue.push(.{ .batch = batch });
                        } else {
                            batch.deinit();
                        }
                        current_batch = null;
                    }
                    _ = self.flush_queue.push(.shutdown);
                    break;
                },
            }
        }

        // Clean up unflushed batch
        if (current_batch) |batch| {
            batch.deinit();
        }

        self.processing_metrics.end_ns = metrics.nanoTimestamp();
    }

    fn flushWorker(self: *Pipeline) void {
        self.flush_metrics.start_ns = metrics.nanoTimestamp();

        var pw: ?ParquetWriter = null;
        defer {
            if (pw) |*w| {
                w.finish() catch |err| {
                    log.err("flush_worker: failed to finish parquet file: {}", .{err});
                };
                self.flush_metrics.bytes_written += w.getBytesWritten();
                w.deinit();
            }
        }

        // Open initial parquet file
        pw = self.openParquetFile() catch |err| blk: {
            log.err("flush_worker: failed to open initial parquet file: {}", .{err});
            break :blk null;
        };

        while (true) {
            const msg = self.flush_queue.pop() orelse break;

            switch (msg) {
                .batch => |batch_ptr| {
                    const start = metrics.nanoTimestamp();
                    defer batch_ptr.deinit();

                    if (pw) |*w| {
                        const rb = batch_ptr.toRowBatch();
                        w.writeRowGroup(&rb) catch |err| {
                            log.err("flush_worker: failed to write row group: {}", .{err});
                        };
                        self.flush_metrics.batches_flushed += 1;
                        self.flush_metrics.rows_processed += @intCast(batch_ptr.count);

                        if (self.flush_metrics.batches_flushed % 10 == 0) {
                            log.info("flush_worker: flushed {d} batches ({d} rows, {d} bytes written)", .{
                                self.flush_metrics.batches_flushed,
                                self.flush_metrics.rows_processed,
                                self.flush_metrics.bytes_written + w.getBytesWritten(),
                            });
                        }
                    }

                    const elapsed = metrics.nanoTimestamp() - start;
                    self.flush_metrics.total_flush_ns += elapsed;
                },
                .rotate => |rotate_data_const| {
                    var rotate_data = rotate_data_const;
                    defer rotate_data.deinit();

                    // Finish current file
                    if (pw) |*w| {
                        w.finish() catch |err| {
                            log.err("flush_worker: failed to finish parquet file: {}", .{err});
                        };
                        self.flush_metrics.bytes_written += w.getBytesWritten();
                        w.deinit();
                        pw = null;
                    }

                    // Update current binlog file
                    self.allocator.free(self.current_binlog_file);
                    self.current_binlog_file = self.allocator.dupe(u8, rotate_data.next_binlog_file) catch {
                        log.err("flush_worker: failed to dupe binlog filename", .{});
                        continue;
                    };

                    // Open new file
                    pw = self.openParquetFile() catch |err| blk: {
                        log.err("flush_worker: failed to open new parquet file: {}", .{err});
                        break :blk null;
                    };
                },
                .shutdown => {
                    break;
                },
            }
        }

        self.flush_metrics.end_ns = metrics.nanoTimestamp();
    }

    fn openParquetFile(self: *Pipeline) !ParquetWriter {
        // Build path: output_dir/binlog_file.parquet
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.parquet", .{
            self.output_dir, self.current_binlog_file,
        });
        defer self.allocator.free(path);

        log.info("opening parquet file: {s}", .{path});
        return ParquetWriter.init(self.allocator, path);
    }
};
