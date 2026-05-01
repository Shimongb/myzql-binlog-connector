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
const builtin = @import("builtin");
const MpscQueue = @import("mpsc_queue.zig").MpscQueue;
const ParquetWriter = @import("parquet_writer.zig").ParquetWriter;
const parquet_writer = @import("parquet_writer.zig");
const object_store = @import("object_store.zig");
const RowJsonSerializer = @import("row_json_serializer.zig").RowJsonSerializer;
const event_parser = @import("event_parser.zig");
const metrics = @import("metrics.zig");
const PipelineMetrics = metrics.PipelineMetrics;
const clock = @import("clock.zig");
const schema_cache_mod = @import("schema_cache.zig");
const ColumnInfo = schema_cache_mod.ColumnInfo;
const config_mod = @import("config.zig");
const BooleanEncoding = config_mod.BooleanEncoding;
const state_mod = @import("state.zig");

const log = std.log.scoped(.pipeline);

/// Sleep for `ns` nanoseconds via std.posix.system.nanosleep - routes
/// to the Linux syscall (no libc) and to macOS libc, matching the
/// project's no-std.c policy. The signature differs slightly between
/// platforms (`usize` return on Linux vs `c_int` on macOS), so we
/// discard the result and don't retry on EINTR - for the ticker
/// thread, an early return just produces an extra wake-up which
/// `ticker_should_stop` handles cleanly.
fn sleepNs(ns: u64) void {
    const ts: std.posix.timespec = .{
        .sec = @intCast(@divTrunc(ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(ns, std.time.ns_per_s)),
    };
    _ = std.posix.system.nanosleep(&ts, null);
}

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
    resolved_columns: ?[]ColumnInfo,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RowEventData) void {
        if (self.database) |d| self.allocator.free(d);
        if (self.table_name) |t| self.allocator.free(t);
        freeRowValues(self.allocator, self.before_values);
        freeRowValues(self.allocator, self.after_values);
        if (self.resolved_columns) |cols| {
            for (cols) |*col| col.deinit(self.allocator);
            self.allocator.free(cols);
        }
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
    /// Periodic wake-up from the ticker thread; processing worker uses
    /// it to evaluate the time gate.
    tick: void,
    shutdown: void,
};

/// Boundary marker passed to the flush worker. `kind` distinguishes
/// soft flushes (size/time gate - same binlog file) from rotates
/// (binlog file change). The uuid7 tail is owned by the flush worker
/// per-file, generated at file open, so the boundary message itself
/// carries no allocations beyond `next_binlog_file` (rotate only).
pub const FlushBoundary = struct {
    kind: Kind,
    /// Set only when `kind == .rotate`. Owned by `allocator` when set.
    next_binlog_file: ?[]const u8 = null,
    allocator: std.mem.Allocator,

    pub const Kind = enum { soft, rotate };

    pub fn deinit(self: *FlushBoundary) void {
        if (self.next_binlog_file) |nf| self.allocator.free(nf);
    }
};

pub const FlushMessage = union(enum) {
    batch: *ColumnBatch,
    boundary: FlushBoundary,
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

/// Pipeline construction options. Bundled into a struct because the
/// arg list grew long enough that positional confusion was a real risk.
pub const Config = struct {
    allocator: std.mem.Allocator,
    /// Externally-owned storage backend for parquet writes. Lifetime
    /// must span pipeline init..join. Either `PosixStore` (when config
    /// `output_dir` is set) or `S3Store` (when `s3_uri` is set);
    /// constructed by main.zig along with the state and cache stores.
    data_store: *object_store.ObjectStore,
    /// Human-readable label for log lines - typically the local path
    /// or `s3://bucket/prefix/data`. Owned by caller; pipeline dupes
    /// at init for self-contained log strings.
    data_label: []const u8,
    initial_binlog_file: []const u8,
    batch_size: usize,
    event_queue_capacity: usize,
    boolean_encoding: BooleanEncoding,

    // Flush gates - values come from config.zig.
    flush_size_bytes: u64,
    flush_time_gate_ms: i64,
    /// soft deadline for graceful shutdown.
    /// Pipeline records `start_ms` at init;
    /// the ticker thread fires `deadline_fired` when `now - start_ms >= soft_deadline_ms`,
    /// and main's event loop polls `shouldStop()` to wind down between events.
    /// `0` (or negative) disables the gate entirely - typical for forever-streaming local
    /// CLI; Lambda sets it from `lambda_ctx.deadline_ms - safety_margin`.
    soft_deadline_ms: i64,

    // Mid-run checkpoint hook. When supplied, the flush worker writes
    // `last_checkpoint.json` after each successful flush so a crash
    // mid-run loses at most one flush window of progress. `null` means
    // no mid-run checkpoint (e.g. when output_dir state files aren't
    // configured) - the run still writes a final checkpoint at clean
    // shutdown via main.
    state_store: ?*object_store.ObjectStore,
    /// Pre-existing schema cache key carried into mid-run checkpoints
    /// the new key, if any, is only written by main at clean shutdown
    /// Borrowed; pipeline does not own.
    predecessor_cache_key: ?[]const u8,
    /// Run identifier propagated into mid-run checkpoints. Borrowed.
    run_id: []const u8,
};

pub const Pipeline = struct {
    allocator: std.mem.Allocator,
    event_queue: MpscQueue(PipelineMessage),
    flush_queue: MpscQueue(FlushMessage),
    processing_thread: ?std.Thread,
    flush_thread: ?std.Thread,
    ticker_thread: ?std.Thread,
    /// Set by `shutdown`, polled by the ticker thread. Atomic so the
    /// ticker can exit promptly when the pipeline is winding down.
    ticker_should_stop: std.atomic.Value(bool),
    batch_size: usize,
    /// Storage backend for parquet writes - borrowed from caller (main).
    /// Either PosixStore or S3Store; pipeline doesn't care which. Caller
    /// owns lifetime; pipeline only holds the pointer.
    data_store: *object_store.ObjectStore,
    /// Human-readable label for log lines. Owned (duped at init).
    data_label: []u8,
    /// Initial binlog file at pipeline init. After init, the
    /// authoritative binlog-file tracker lives in the flush worker's
    /// local state (see `flushWorker`) so that boundary-time updates
    /// are not racy with batch consumers.
    initial_binlog_file: []const u8,
    /// Per-flush size-gate accumulator. JSON byte sum (before+after) of
    /// every event since the last boundary. Reset to 0 at boundary.
    bytes_since_boundary: u64,
    /// Time gate state - ms timestamp of the last boundary emit, used
    /// by the tick handler to decide whether the time gate fires.
    last_boundary_ms: i64,
    flush_size_bytes: u64,
    flush_time_gate_ms: i64,
    /// `start_ms` is captured at init; `soft_deadline_ms` is the configured budget (≤0 disables);
    /// `deadline_fired` is set by the ticker when budget elapses.
    /// Atomic so the producer (main's event loop) can poll without locking.
    start_ms: i64,
    soft_deadline_ms: i64,
    deadline_fired: std.atomic.Value(bool),
    state_store: ?*object_store.ObjectStore,
    predecessor_cache_key: ?[]const u8,
    run_id: []const u8,
    processing_metrics: PipelineMetrics,
    flush_metrics: PipelineMetrics,
    boolean_encoding: BooleanEncoding,

    pub fn init(opts: Config) !*Pipeline {
        const allocator = opts.allocator;
        const self = try allocator.create(Pipeline);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .event_queue = try MpscQueue(PipelineMessage).init(allocator, opts.event_queue_capacity),
            .flush_queue = try MpscQueue(FlushMessage).init(allocator, 4),
            .processing_thread = null,
            .flush_thread = null,
            .ticker_thread = null,
            .ticker_should_stop = std.atomic.Value(bool).init(false),
            .batch_size = opts.batch_size,
            .data_store = opts.data_store,
            .data_label = try allocator.dupe(u8, opts.data_label),
            .initial_binlog_file = try allocator.dupe(u8, opts.initial_binlog_file),
            .bytes_since_boundary = 0,
            .last_boundary_ms = clock.nowMs(),
            .flush_size_bytes = opts.flush_size_bytes,
            .flush_time_gate_ms = opts.flush_time_gate_ms,
            .start_ms = clock.nowMs(),
            .soft_deadline_ms = opts.soft_deadline_ms,
            .deadline_fired = std.atomic.Value(bool).init(false),
            .state_store = opts.state_store,
            .predecessor_cache_key = opts.predecessor_cache_key,
            .run_id = opts.run_id,
            .processing_metrics = .{},
            .flush_metrics = .{},
            .boolean_encoding = opts.boolean_encoding,
        };
        // The data store is borrowed from the caller (main); already
        // probed-writable by the time the pipeline is constructed, so
        // we don't repeat the probe here. PosixStore lazy-mkdirs parent
        // dirs at first write - operator UX delta vs the old eager
        // mkdir is "data dir appears 1-2s later instead of immediately".

        // Spawn workers + ticker
        self.flush_thread = try std.Thread.spawn(.{}, flushWorker, .{self});
        self.processing_thread = try std.Thread.spawn(.{}, processingWorker, .{self});
        self.ticker_thread = try std.Thread.spawn(.{}, tickerWorker, .{self});

        return self;
    }

    pub fn send(self: *Pipeline, msg: PipelineMessage) bool {
        return self.event_queue.push(msg);
    }

    /// True once the soft deadline has elapsed.
    /// Producers (main's event loop) poll this between events to wind down gracefully
    /// at that point they should stop pumping new events and call `shutdown` + `join`.
    /// The flush worker drains the rest of the queue and writes
    /// the final checkpoint via the existing shutdown path.
    pub fn shouldStop(self: *const Pipeline) bool {
        return self.deadline_fired.load(.acquire);
    }

    pub fn shutdown(self: *Pipeline) void {
        // Ticker thread exits at its next wake; no flush ordering needed
        // since the queue itself drains on shutdown.
        self.ticker_should_stop.store(true, .release);
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
        if (self.ticker_thread) |t| {
            t.join();
            self.ticker_thread = null;
        }

        var combined = PipelineMetrics{};
        combined.merge(self.processing_metrics);
        combined.merge(self.flush_metrics);
        return combined;
    }

    pub fn deinit(self: *Pipeline) void {
        self.event_queue.deinit();
        self.flush_queue.deinit();
        self.allocator.free(self.data_label);
        self.allocator.free(self.initial_binlog_file);
        self.allocator.destroy(self);
    }

    /// Wakes up every `flush_time_gate_ms / 4` ms and pushes a
    /// `.tick` to the event queue. Lets the time gate fire on idle
    /// streams (where no new events would otherwise wake the
    /// processing worker). Quarter-period cadence is a coarse
    /// trade-off: latency to fire the gate is at most 25% past the
    /// configured threshold, while burning roughly 4 wakeups per gate
    /// window - cheap enough.
    fn tickerWorker(self: *Pipeline) void {
        const period_ns: u64 = blk: {
            const quarter_ms = @divTrunc(self.flush_time_gate_ms, 4);
            const min_ms: i64 = 100; // sanity floor
            const eff_ms: i64 = @max(quarter_ms, min_ms);
            break :blk @intCast(eff_ms * std.time.ns_per_ms);
        };
        while (!self.ticker_should_stop.load(.acquire)) {
            sleepNs(period_ns);
            if (self.ticker_should_stop.load(.acquire)) break;

            // soft deadline.
            // Fires once: subsequent ticks are no-ops because `deadline_fired` is sticky.
            // Producers see the signal via `shouldStop()` and wind down at the next event boundary.
            if (self.soft_deadline_ms > 0 and !self.deadline_fired.load(.acquire)) {
                const elapsed = clock.nowMs() - self.start_ms;
                if (elapsed >= self.soft_deadline_ms) {
                    log.info(
                        "soft deadline reached after {d}ms (configured {d}ms); requesting graceful shutdown",
                        .{ elapsed, self.soft_deadline_ms },
                    );
                    self.deadline_fired.store(true, .release);
                }
            }

            // The push is best-effort: if the event queue happens to
            // be full, dropping a tick is fine - the next one will
            // arrive in another period.
            _ = self.event_queue.push(.tick);
        }
    }

    fn processingWorker(self: *Pipeline) void {
        var serializer = RowJsonSerializer.init(self.allocator, self.boolean_encoding);
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
                        if (serializer.serializeWithColumns(vals, row_data.resolved_columns)) |json| {
                            before_json_copy = self.allocator.dupe(u8, json) catch null;
                            before_json = before_json_copy;
                        } else |_| {}
                    }
                    if (row_data.after_values) |vals| {
                        after_json = serializer.serializeWithColumns(vals, row_data.resolved_columns) catch null;
                    }

                    // Size-gate accounting: sum the JSON byte length of
                    // both directions. JSON bytes are the right signal
                    // for "memory we're holding before flush"
                    // (the ColumnBatch arena dupes these strings)
                    // and track parquet input size more directly than binlog wire bytes would.
                    const row_size: u64 = (if (before_json) |b| b.len else 0) +
                        (if (after_json) |a| a.len else 0);

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
                        self.bytes_since_boundary += row_size;

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

                    // Size gate: flush boundary if we've buffered too
                    // much since the last boundary. Evaluated *after*
                    // appending so the triggering event ends up in the
                    // file we're about to close, not the next one.
                    if (self.bytes_since_boundary >= self.flush_size_bytes) {
                        log.info(
                            "size gate fired: {d} bytes since last boundary >= {d}",
                            .{ self.bytes_since_boundary, self.flush_size_bytes },
                        );
                        self.emitBoundary(&current_batch, .soft, null);
                    }
                },
                .rotate => |rotate_data_const| {
                    var rotate_data = rotate_data_const;
                    // The next_binlog_file is ownership-transferred into
                    // the boundary; we must NOT call rotate_data.deinit()
                    // here (that would free the slice the boundary now
                    // points at). Instead, hand the alloc'd slice off and
                    // let FlushBoundary own it.
                    const next_owned = self.allocator.dupe(u8, rotate_data.next_binlog_file) catch |err| {
                        log.err("processing_worker: failed to dupe rotate filename: {}", .{err});
                        rotate_data.deinit();
                        continue;
                    };
                    rotate_data.deinit();
                    self.emitBoundary(&current_batch, .rotate, next_owned);
                },
                .tick => {
                    // Time gate: flush if buffer non-empty and quiet for
                    // longer than the configured threshold. Doesn't fire
                    // on an empty buffer (no events to lose).
                    if (self.bytes_since_boundary == 0) continue;
                    const elapsed_ms = clock.nowMs() - self.last_boundary_ms;
                    if (elapsed_ms < self.flush_time_gate_ms) continue;
                    log.info(
                        "time gate fired: {d}ms since last boundary >= {d}ms",
                        .{ elapsed_ms, self.flush_time_gate_ms },
                    );
                    self.emitBoundary(&current_batch, .soft, null);
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

    /// Push the current batch (if any), then a boundary marker, then
    /// allocate a fresh batch. Resets the size + time gate counters.
    /// On `.rotate`, also updates `current_binlog_file` so the next
    /// file's from_file reflects the new binlog. Caller passes ownership
    /// of `next_binlog_file` (rotate only); the boundary takes it.
    fn emitBoundary(
        self: *Pipeline,
        current_batch: *?*ColumnBatch,
        kind: FlushBoundary.Kind,
        next_binlog_file: ?[]const u8,
    ) void {
        log.debug(
            "emitBoundary kind={s} next_binlog={s} bytes_since_boundary={d}",
            .{ @tagName(kind), next_binlog_file orelse "(none)", self.bytes_since_boundary },
        );
        if (current_batch.*) |batch| {
            if (batch.count > 0) {
                _ = self.flush_queue.push(.{ .batch = batch });
            } else {
                batch.deinit();
            }
            current_batch.* = null;
        }

        _ = self.flush_queue.push(.{ .boundary = .{
            .kind = kind,
            .next_binlog_file = next_binlog_file,
            .allocator = self.allocator,
        } });

        // Note: we deliberately do NOT update any shared `current_binlog_file`
        // here. The flush worker owns its own copy and updates it when it
        // processes the boundary, so the new from_file lines up with the
        // file the new batches actually came from. (An earlier version
        // mutated a Pipeline-level field, which raced with the flush
        // worker's lazy openFile and produced files mis-tagged with the
        // *next* binlog name.)

        current_batch.* = ColumnBatch.init(self.allocator, self.batch_size) catch |err| blk: {
            log.err("processing_worker: failed to allocate post-boundary batch: {}", .{err});
            break :blk null;
        };

        self.bytes_since_boundary = 0;
        self.last_boundary_ms = clock.nowMs();
    }

    /// Per-file state tracked by the flush worker between boundaries.
    /// All owned strings are freed at file close (just before the
    /// finishAs commit) or in the deferred deinit on shutdown error.
    const FileState = struct {
        pw: ?ParquetWriter,
        uuid7: ?[]u8, // owned, set at file open (lazy)
        from_file: ?[]u8, // owned, captured at file open (lazy)
        from_pos: ?u64, // set on first batch
        to_file: ?[]u8, // owned, updated on each batch
        to_pos: u64, // updated on each batch
    };

    fn flushWorker(self: *Pipeline) void {
        self.flush_metrics.start_ns = metrics.nanoTimestamp();

        // The authoritative binlog-file pointer for the parquet writer
        // lives here, in the flush worker's local frame. Updated only
        // when this worker processes a `.rotate` boundary. The
        // processing worker doesn't touch it - see emitBoundary's
        // commentary for the race that motivated this split.
        var current_binlog_file: []u8 = self.allocator.dupe(u8, self.initial_binlog_file) catch {
            log.err("flush_worker: failed to alloc binlog file tracker", .{});
            return;
        };
        defer self.allocator.free(current_binlog_file);

        var fs: FileState = .{
            .pw = null,
            .uuid7 = null,
            .from_file = null,
            .from_pos = null,
            .to_file = null,
            .to_pos = 0,
        };
        defer {
            // Last-resort cleanup for an unfinished writer (only reached
            // on outer break / unexpected exit). Discards any in-flight
            // sidecar via deinit's abort path.
            if (fs.pw) |*w| {
                self.flush_metrics.bytes_written += w.getBytesWritten();
                w.deinit();
            }
            if (fs.uuid7) |s| self.allocator.free(s);
            if (fs.from_file) |s| self.allocator.free(s);
            if (fs.to_file) |s| self.allocator.free(s);
        }

        while (true) {
            const msg = self.flush_queue.pop() orelse break;

            switch (msg) {
                .batch => |batch_ptr| {
                    const start = metrics.nanoTimestamp();
                    defer batch_ptr.deinit();

                    // Lazy file open on first batch since last boundary.
                    if (fs.pw == null) {
                        self.openFile(&fs, current_binlog_file) catch |err| {
                            log.err("flush_worker: failed to open parquet file: {}", .{err});
                            continue;
                        };
                    }

                    if (fs.pw) |*w| {
                        const rb = batch_ptr.toRowBatch();
                        w.writeRowGroup(&rb) catch |err| {
                            log.err("flush_worker: failed to write row group: {}", .{err});
                        };
                        self.flush_metrics.batches_flushed += 1;
                        self.flush_metrics.rows_processed += @intCast(batch_ptr.count);

                        // First batch in this file → record from_pos.
                        if (fs.from_pos == null and batch_ptr.count > 0) {
                            fs.from_pos = @intCast(batch_ptr.log_positions[0]);
                        }
                        // Update to_file (in case binlog file changed
                        // mid-file via concurrent rotate, though our
                        // boundary semantics make that unlikely) and
                        // to_pos (always the most recent log_pos).
                        if (batch_ptr.count > 0) {
                            fs.to_pos = @intCast(batch_ptr.log_positions[batch_ptr.count - 1]);
                            self.allocator.free(fs.to_file orelse &[_]u8{});
                            fs.to_file = self.allocator.dupe(u8, fs.from_file.?) catch null;
                        }

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
                .boundary => |boundary_const| {
                    var boundary = boundary_const;
                    // Close the current file if it has content; emit a
                    // mid-run checkpoint after a successful commit.
                    self.closeFile(&fs);
                    // On rotate, swap our local binlog-file tracker
                    // BEFORE the next batch arrives - that's the from_file
                    // the next openFile will record.
                    if (boundary.kind == .rotate) {
                        if (boundary.next_binlog_file) |nf| {
                            const new_owned = self.allocator.dupe(u8, nf) catch null;
                            if (new_owned) |new_name| {
                                self.allocator.free(current_binlog_file);
                                current_binlog_file = new_name;
                            } else {
                                log.err("flush_worker: dupe(next_binlog_file) failed; keeping previous", .{});
                            }
                        }
                    }
                    boundary.deinit();
                },
                .shutdown => {
                    self.closeFile(&fs);
                    break;
                },
            }
        }

        self.flush_metrics.end_ns = metrics.nanoTimestamp();
    }

    /// Lazy file open. `current_binlog_file` is the flush worker's
    /// local pointer (passed in to avoid a race with the processing
    /// worker - see `flushWorker`). Mints a fresh UUIDv7 for the
    /// file's tail. The underlying ObjectStore handle opens with a
    /// placeholder key - the final filename (with from/to positions)
    /// is computed at close time and passed to `finishAs`.
    fn openFile(self: *Pipeline, fs: *FileState, current_binlog_file: []const u8) !void {
        std.debug.assert(fs.pw == null);

        const uuid = try state_mod.generateUuidV7(self.allocator, clock.nowMs());
        errdefer self.allocator.free(uuid);

        // Placeholder key: a leading dot keeps it out of the
        // `*.parquet` glob until commit, and the .partial tag makes
        // crash-orphans trivially identifiable for ops cleanup.
        // No `data/` prefix: the store root is already the data subdir
        // (main.zig wires `{output_dir}/data` as the pipeline's
        // `output_dir`), so adding another `data/` would double-nest.
        const placeholder = try std.fmt.allocPrint(
            self.allocator,
            ".partial-{s}.parquet",
            .{uuid},
        );
        defer self.allocator.free(placeholder);

        const from_file = try self.allocator.dupe(u8, current_binlog_file);
        errdefer self.allocator.free(from_file);

        log.info("opening parquet file (placeholder): {s}/{s}", .{ self.data_label, placeholder });
        fs.pw = try ParquetWriter.init(self.allocator, self.data_store, placeholder);
        fs.uuid7 = uuid;
        fs.from_file = from_file;
        fs.from_pos = null;
        fs.to_file = null;
        fs.to_pos = 0;
    }

    /// Close the current parquet file (if any), commit it under the
    /// computed final key, then write a mid-run checkpoint pointing at
    /// the new {to_file, to_pos}. All per-file allocations are freed
    /// here; on success `fs.pw` is null and the next batch will trigger
    /// a fresh `openFile`.
    fn closeFile(self: *Pipeline, fs: *FileState) void {
        if (fs.pw == null) return;

        // No rows since last boundary → discard the placeholder. The
        // ParquetWriter's finish() handles the empty-file case by
        // aborting the sidecar (no committed file appears on disk).
        if (fs.from_pos == null) {
            var w = fs.pw.?;
            w.finish() catch |err| {
                log.err("flush_worker: failed to abort empty parquet: {}", .{err});
            };
            w.deinit();
            self.cleanupFileState(fs);
            return;
        }

        // Build final key: {from_file}.{from_pos}_{to_file}.{to_pos}_{uuid7}.parquet
        // (no `data/` prefix - store root is already the data subdir).
        const final_key = std.fmt.allocPrint(
            self.allocator,
            "{s}.{d}_{s}.{d}_{s}.parquet",
            .{
                fs.from_file.?,
                fs.from_pos.?,
                fs.to_file orelse fs.from_file.?,
                fs.to_pos,
                fs.uuid7.?,
            },
        ) catch |err| {
            log.err("flush_worker: failed to format final key: {}", .{err});
            // Fall back to plain finish at placeholder; the file
            // remains on disk under the .partial name. Next run can
            // reprocess via the checkpoint position chain.
            var w = fs.pw.?;
            w.finish() catch {};
            self.flush_metrics.bytes_written += w.getBytesWritten();
            w.deinit();
            self.cleanupFileState(fs);
            return;
        };
        defer self.allocator.free(final_key);

        var w = fs.pw.?;
        w.finishAs(self.data_store, final_key) catch |err| {
            log.err("flush_worker: failed to commit parquet '{s}': {}", .{ final_key, err });
            self.flush_metrics.bytes_written += w.getBytesWritten();
            w.deinit();
            self.cleanupFileState(fs);
            return;
        };
        self.flush_metrics.bytes_written += w.getBytesWritten();
        w.deinit();
        log.info("flushed parquet: {s}", .{final_key});

        // Mid-run checkpoint write - the durable resume point now
        // includes the position of the last event we committed to disk.
        // Failures here are non-fatal: a missing checkpoint just means
        // the next run resumes from an older one.
        self.writeMidRunCheckpoint(fs.to_file orelse fs.from_file.?, fs.to_pos);

        self.cleanupFileState(fs);
    }

    fn cleanupFileState(self: *Pipeline, fs: *FileState) void {
        if (fs.uuid7) |s| self.allocator.free(s);
        if (fs.from_file) |s| self.allocator.free(s);
        if (fs.to_file) |s| self.allocator.free(s);
        fs.* = .{
            .pw = null,
            .uuid7 = null,
            .from_file = null,
            .from_pos = null,
            .to_file = null,
            .to_pos = 0,
        };
    }

    fn writeMidRunCheckpoint(self: *Pipeline, file: []const u8, pos: u64) void {
        const store = self.state_store orelse return;

        const checkpoint: state_mod.BinlogState = .{
            .binlog_file = file,
            .binlog_position = pos,
            .updated_at_ms = clock.nowMs(),
            .run_id = self.run_id,
            // Pipeline only knows the predecessor's cache key; main
            // writes the new key in the post-shutdown final checkpoint.
            // A mid-run-crash-resume cold-starts the cache (correct
            // position is preserved; cache repopulates on demand).
            .schema_cache_key = self.predecessor_cache_key,
            .is_in_progress = false,
        };
        state_mod.writeCheckpoint(self.allocator, store, "last_checkpoint.json", checkpoint) catch |err| {
            log.warn("flush_worker: mid-run checkpoint write failed: {}", .{err});
        };
    }
};
