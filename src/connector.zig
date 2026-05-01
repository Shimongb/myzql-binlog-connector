//! Connector orchestration - one bounded MySQL → S3 invocation.
//!
//! This module is the entry point both the local CLI (`main.zig`) and
//! the future Lambda handler will call into. It owns the full
//! execution flow:
//!
//!   1. Connect to MySQL (primary stream connection + secondary
//!      describe connection)
//!   2. Build state / cache / data ObjectStores from `config.s3_uri`
//!      or `config.output_dir`, probeWritable each
//!   3. Inspect `current.json` lock - skip silently if a fresh owner
//!      is detected; resume from checkpoint if stale predecessor
//!   4. Resolve effective start position (checkpoint > config > master)
//!   5. Run prereq checks (binlog format / row image / position
//!      validity, may adjust to oldest available)
//!   6. Apply `bound_to_master_at_init` ceiling (auto "catch up + exit")
//!   7. Claim the lock (`current.json`) with a fresh run_id
//!   8. Init `BinlogReader` + load schema cache by checkpoint key
//!   9. Open binlog stream + drain to stdout or parquet pipeline
//!  10. On clean exit: saveCache → writeCheckpoint → releaseLock
//!
//! The boundary between caller (`main`) and `run`:
//!
//! - **Caller responsibilities (CLI / Lambda handler):**
//!   - Allocator setup (arena for short-lived state, gpa for long-lived
//!     pipeline workers)
//!   - Logging init (CLI argv flags vs Lambda env vars / context)
//!   - Config sourcing (file vs payload), `mergeFromEnv`, `applyClamps`,
//!     `validate`
//!   - SSM lookup for DB credentials (Lambda only - fills in
//!     `config.user`/`password`/`host`/`port` before calling run)
//!
//! - **`run` responsibilities (this module):**
//!   - Everything else above. Returns when the run terminates for any
//!     reason (clean exit, soft-deadline exit, live-owner skip,
//!     to_binlog_position reached, fatal error). On fatal error,
//!     `current.json` is deliberately left in place as the crash signal
//!     for the next run.

const std = @import("std");
const connection = @import("connection.zig");
const config_mod = @import("config.zig");
const binlog_reader = @import("binlog_reader.zig");
const pipeline_mod = @import("pipeline.zig");
const event_parser = @import("event_parser.zig");
const prereq_check = @import("prereq_check.zig");
const object_store = @import("object_store.zig");
const s3_store = @import("s3_store.zig");
const aws_creds = @import("aws_creds.zig");
const clock = @import("clock.zig");
const state_mod = @import("state.zig");
const schema_cache_mod = @import("schema_cache.zig");
const cache_persistence = @import("cache_persistence.zig");

const log = std.log.scoped(.connector);

pub const CURRENT_KEY = "current.json";
pub const CHECKPOINT_KEY = "last_checkpoint.json";

/// The parts of `std.process.Init` the connector orchestration needs.
/// Pulled out as an explicit struct so the Lambda handler can build
/// it from saved values (Lambda's `Context` doesn't expose
/// `process.Environ` directly), while the CLI still constructs it
/// trivially from the `init` it receives in main.
///
/// CLI:    `.{ .io = init.io, .environ_map = init.environ_map, .environ = init.minimal.environ }`
/// Lambda: same shape, sourced from values saved at process startup
///         (lambda_handler.zig grabs them from `init` before calling
///         `lambda.handle`, since the per-invocation `Context` doesn't
///         expose `process.Environ`).
pub const RunContext = struct {
    /// `std.Io` for HTTP client (z3), clock, std.fs operations.
    io: std.Io,
    /// Process environment map. Used by `aws_creds.fromEnv` to read
    /// `AWS_*` env vars for S3 store creds. Lambda also injects these
    /// vars, so the same code path works in both modes.
    environ_map: *const std.process.Environ.Map,
    /// Process `Environ`. Required by `std.Io.Threaded.init` for
    /// scanning env-driven runtime config (cert paths, proxy, etc.).
    environ: std.process.Environ,
};

/// Compose `{user_prefix}/{subdir}` for an S3 key prefix. When the
/// user supplied no prefix in the s3_uri, returns just the subdir
/// alone (no leading `/`).
fn composePrefix(allocator: std.mem.Allocator, user_prefix: []const u8, subdir: []const u8) ![]u8 {
    if (user_prefix.len == 0) return allocator.dupe(u8, subdir);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ user_prefix, subdir });
}

/// Duplicate row event data into a PipelineMessage with owned memory.
fn dupeRowEventForPipeline(
    alloc: std.mem.Allocator,
    ev: event_parser.Event,
    re: event_parser.RowEvent,
    meta: event_parser.TableMetadata,
    event_row_index: u64,
    resolved_columns: ?[]const schema_cache_mod.ColumnInfo,
) !pipeline_mod.PipelineMessage {
    var duped_cols: ?[]schema_cache_mod.ColumnInfo = null;
    if (resolved_columns) |cols| {
        const duped = try alloc.alloc(schema_cache_mod.ColumnInfo, cols.len);
        var initialized: usize = 0;
        errdefer {
            for (duped[0..initialized]) |*c| c.deinit(alloc);
            alloc.free(duped);
        }
        for (cols) |*col| {
            duped[initialized] = try col.dupe(alloc);
            initialized += 1;
        }
        duped_cols = duped;
    }

    return .{ .row_event = .{
        .timestamp = @intCast(ev.timestamp),
        .server_id = ev.server_id,
        .log_pos = ev.log_pos,
        .event_row_index = event_row_index,
        .database = try alloc.dupe(u8, meta.database_name),
        .table_name = try alloc.dupe(u8, meta.table_name),
        .dml_type = re.dml_type,
        .before_values = try dupeRowValues(alloc, re.before_values),
        .after_values = try dupeRowValues(alloc, re.after_values),
        .resolved_columns = duped_cols,
        .allocator = alloc,
    } };
}

fn dupeRowValues(alloc: std.mem.Allocator, values: ?[]const event_parser.RowValue) !?[]event_parser.RowValue {
    const vals = values orelse return null;
    const duped = try alloc.alloc(event_parser.RowValue, vals.len);
    for (vals, 0..) |v, i| {
        duped[i] = switch (v) {
            .string => |s| .{ .string = try alloc.dupe(u8, s) },
            .blob => |b| .{ .blob = try alloc.dupe(u8, b) },
            .decimal => |d| .{ .decimal = try alloc.dupe(u8, d) },
            .json => |j| .{ .json = try alloc.dupe(u8, j) },
            else => v,
        };
    }
    return duped;
}

/// Run one bounded connector invocation.
///
/// `run_ctx`: the IO + environ + environ_map the orchestration needs
///   (was previously taken as a whole `std.process.Init`; now an
///   explicit struct so the Lambda handler can synthesize it from
///   saved-at-startup values without needing the full Init).
/// `allocator`: short-lived state (paths, prefixes, run_id, intermediate
///   state structs). Caller's arena is the typical choice.
/// `pipeline_allocator`: pipeline worker threads - must outlive the
///   pipeline's lifetime (which spans the whole `run`). gpa is
///   typical; arena works too since it's bounded by `run`.
/// `config`: pointer because `bound_to_master_at_init` may mutate
///   `to_binlog_*` in place. Caller-owned.
pub fn run(
    run_ctx: RunContext,
    allocator: std.mem.Allocator,
    pipeline_allocator: std.mem.Allocator,
    config: *config_mod.Config,
) !void {
    // Connect to MySQL (primary)
    log.info("connecting to MySQL server at {s}:{d}", .{ config.host, config.port });
    var conn = connection.Connection.connect(
        allocator,
        config.host,
        config.port,
        config.user,
        config.password,
        config.database,
        config.ssl,
    ) catch |err| {
        log.err("connection failed: {}", .{err});
        log.err("troubleshooting: verify MySQL is running at {s}:{d}, check credentials and firewall", .{ config.host, config.port });
        return err;
    };
    defer conn.disconnect();

    log.info("connected successfully", .{});

    const server_version = conn.getServerVersion();
    log.info("MySQL server version: {s}", .{server_version});

    log.debug("testing connection (ping)", .{});
    conn.ping() catch |err| {
        log.err("ping failed: {}", .{err});
        return err;
    };
    log.debug("connection is alive", .{});

    // === Output destination - posix or S3 ===
    var state_label_opt: ?[]const u8 = null;
    var cache_label_opt: ?[]const u8 = null;
    var data_label_opt: ?[]const u8 = null;
    var state_store_opt: ?object_store.ObjectStore = null;
    var cache_store_opt: ?object_store.ObjectStore = null;
    var data_store_opt: ?object_store.ObjectStore = null;

    var threaded_io: std.Io.Threaded = undefined;
    var threaded_io_initialized = false;
    defer if (threaded_io_initialized) threaded_io.deinit();

    if (config.s3_uri) |uri| {
        const parsed = config_mod.parseS3Uri(uri) catch |err| {
            log.err("[BAD_S3_URI] config s3_uri='{s}' failed to parse: {}", .{ uri, err });
            return err;
        };
        const bucket_owned = try allocator.dupe(u8, parsed.bucket);

        const creds = try aws_creds.fromEnv(run_ctx.environ_map);

        const state_prefix = try composePrefix(allocator, parsed.prefix, config_mod.STATE_SUBDIR);
        const cache_prefix = try composePrefix(allocator, parsed.prefix, config_mod.DDL_CACHE_SUBDIR);
        const data_prefix = try composePrefix(allocator, parsed.prefix, config_mod.DATA_SUBDIR);

        threaded_io = std.Io.Threaded.init(pipeline_allocator, .{ .environ = run_ctx.environ });
        threaded_io_initialized = true;
        const io = threaded_io.io();

        state_store_opt = .{ .s3 = try s3_store.S3Store.init(allocator, bucket_owned, state_prefix, creds, io) };
        cache_store_opt = .{ .s3 = try s3_store.S3Store.init(allocator, bucket_owned, cache_prefix, creds, io) };
        data_store_opt = .{ .s3 = try s3_store.S3Store.init(allocator, bucket_owned, data_prefix, creds, io) };

        state_label_opt = try std.fmt.allocPrint(allocator, "s3://{s}/{s}", .{ bucket_owned, state_prefix });
        cache_label_opt = try std.fmt.allocPrint(allocator, "s3://{s}/{s}", .{ bucket_owned, cache_prefix });
        data_label_opt = try std.fmt.allocPrint(allocator, "s3://{s}/{s}", .{ bucket_owned, data_prefix });
    } else if (config.output_dir) |od| {
        state_label_opt = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.STATE_SUBDIR });
        cache_label_opt = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.DDL_CACHE_SUBDIR });
        data_label_opt = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.DATA_SUBDIR });
        state_store_opt = .{ .posix = object_store.PosixStore.init(allocator, state_label_opt.?) };
        cache_store_opt = .{ .posix = object_store.PosixStore.init(allocator, cache_label_opt.?) };
        data_store_opt = .{ .posix = object_store.PosixStore.init(allocator, data_label_opt.?) };
    }

    if (state_store_opt) |*ss| {
        ss.probeWritable(allocator) catch |err| {
            log.err("[OUTPUT_NOT_WRITABLE] state store probe failed at '{s}': {}", .{ state_label_opt.?, err });
            return err;
        };
    }
    if (cache_store_opt) |*ss| {
        ss.probeWritable(allocator) catch |err| {
            log.err("[OUTPUT_NOT_WRITABLE] cache store probe failed at '{s}': {}", .{ cache_label_opt.?, err });
            return err;
        };
    }
    if (data_store_opt) |*ss| {
        ss.probeWritable(allocator) catch |err| {
            log.err("[OUTPUT_NOT_WRITABLE] data store probe failed at '{s}': {}", .{ data_label_opt.?, err });
            return err;
        };
    }

    // Inspect current.json. Skip the run if a live owner is detected.
    var maybe_checkpoint: ?state_mod.BinlogState = null;
    defer if (maybe_checkpoint) |s| s.deinit(allocator);

    if (state_store_opt) |*store| {
        log.info("checking for existing execution state at {s}/{s}", .{ state_label_opt.?, CURRENT_KEY });
        const lock_check = state_mod.checkLock(
            allocator,
            store,
            CURRENT_KEY,
            config.current_state_staleness_ms,
            clock.nowMs(),
        ) catch |err| {
            log.err("state checkLock failed: {}", .{err});
            return err;
        };
        defer if (lock_check.prior_state) |s| s.deinit(allocator);

        switch (lock_check.outcome) {
            .acquired_fresh => log.info("no prior state - fresh execution", .{}),
            .acquired_stale_predecessor => {
                if (lock_check.prior_state) |s| {
                    const age_s = @divFloor(clock.nowMs() - s.updated_at_ms, std.time.ms_per_s);
                    log.warn(
                        "found stale state (run_id: {s}, age: {d}s); assuming crashed predecessor - will resume from checkpoint",
                        .{ s.run_id, age_s },
                    );
                } else {
                    log.warn("found malformed state file; assuming crashed predecessor - will resume from checkpoint", .{});
                }
            },
            .skip_live_owner => {
                if (lock_check.prior_state) |s| {
                    const age_s = @divFloor(clock.nowMs() - s.updated_at_ms, std.time.ms_per_s);
                    log.warn(
                        "found recent in-progress state (run_id: {s}, age: {d}s) - skipping execution to avoid duplication",
                        .{ s.run_id, age_s },
                    );
                }
                return;
            },
        }

        maybe_checkpoint = state_mod.loadCheckpoint(allocator, store, CHECKPOINT_KEY) catch null;
    }

    // Resolve effective start position.
    var effective_file: []const u8 = undefined;
    var effective_pos: u64 = undefined;
    if (maybe_checkpoint) |cp| {
        effective_file = cp.binlog_file;
        effective_pos = cp.binlog_position;
        log.info(
            "found last checkpoint: {s}:{d} - config.from_binlog_* values are ignored. Delete {s}/{s} to force restart from config.",
            .{ cp.binlog_file, cp.binlog_position, state_label_opt.?, CHECKPOINT_KEY },
        );
    } else if (config.from_binlog_file) |cf| {
        effective_file = cf;
        effective_pos = config.from_binlog_position.?;
        log.info("no checkpoint - bootstrapping from config: {s}:{d}", .{ effective_file, effective_pos });
    } else {
        log.info("no checkpoint and no config.from_binlog_*; querying master position", .{});
        const mp = prereq_check.getMasterPosition(allocator, &conn) catch |err| {
            log.err(
                "[MISSING_START_POSITION] cannot determine binlog start position. Tried: (1) {s}/{s} (not found), (2) config.from_binlog_* (not set), (3) SHOW MASTER STATUS ({}). Set config.from_binlog_file/position or ensure binlog is enabled on the server.",
                .{
                    state_label_opt orelse "(state files disabled - set output_dir to enable resume)",
                    CHECKPOINT_KEY,
                    err,
                },
            );
            return err;
        };
        log.info("bootstrapped from master position: {s}:{d}", .{ mp.file, mp.position });
        effective_file = mp.file;
        effective_pos = mp.position;
    }

    log.info("running prerequisite checks", .{});
    const prereq = prereq_check.run(
        allocator,
        &conn,
        effective_file,
        effective_pos,
    ) catch |err| {
        log.err("prerequisite check failed: {}", .{err});
        return err;
    };
    if (prereq.adjusted) {
        log.warn(
            "start position adjusted: {s}:{d} -> {s}:{d}",
            .{ effective_file, effective_pos, prereq.file, prereq.position },
        );
    }

    if (config.bound_to_master_at_init and config.to_binlog_file == null and config.to_binlog_position == null) {
        const ceiling = prereq_check.getMasterPosition(allocator, &conn) catch |err| blk: {
            log.warn("bound_to_master_at_init: master query failed ({}); leaving run unbounded", .{err});
            break :blk null;
        };
        if (ceiling) |c| {
            log.info(
                "bound_to_master_at_init: setting run ceiling to {s}:{d} (catch up + exit)",
                .{ c.file, c.position },
            );
            config.to_binlog_file = c.file;
            config.to_binlog_position = c.position;
        }
    }

    var run_id: ?[]u8 = null;
    if (state_store_opt) |*store| {
        const id = try state_mod.generateRunId(allocator);
        run_id = id;
        const lock_state: state_mod.BinlogState = .{
            .binlog_file = prereq.file,
            .binlog_position = prereq.position,
            .updated_at_ms = clock.nowMs(),
            .run_id = id,
            .schema_cache_key = if (maybe_checkpoint) |cp| cp.schema_cache_key else null,
            .is_in_progress = true,
        };
        try state_mod.writeCurrentLock(allocator, store, CURRENT_KEY, lock_state);
        log.info("claimed lock at {s}/{s} (run_id: {s})", .{ state_label_opt.?, CURRENT_KEY, id });
    }

    var describe_conn_opt: ?connection.Connection = blk: {
        log.info("opening secondary connection for schema queries", .{});
        break :blk connection.Connection.connect(
            allocator,
            config.host,
            config.port,
            config.user,
            config.password,
            config.database,
            config.ssl,
        ) catch |err| {
            log.warn("secondary connection failed: {}, column names will not be available", .{err});
            break :blk null;
        };
    };
    defer if (describe_conn_opt) |*dc| dc.disconnect();

    log.info("starting binlog reader", .{});
    const describe_conn_ptr: ?*connection.Connection = if (describe_conn_opt) |*dc| dc else null;
    var reader = try binlog_reader.BinlogReader.init(
        allocator,
        &conn,
        config.*,
        describe_conn_ptr,
        prereq.file,
        prereq.position,
    );
    defer reader.deinit();

    if (cache_store_opt) |*store| {
        if (maybe_checkpoint) |cp| {
            if (cp.schema_cache_key) |key| {
                var skip_load = false;
                if (config.schema_cache_ttl_seconds) |ttl| {
                    if (store.head(key)) |info| {
                        const now_secs = @divFloor(clock.nowMs(), std.time.ms_per_s);
                        const mtime = @divFloor(info.last_modified_ms, std.time.ms_per_s);
                        if (cache_persistence.isStaleByTtl(mtime, now_secs, ttl)) {
                            log.warn(
                                "schema cache key '{s}' is stale (age {d}s, TTL {d}s); cold-starting cache",
                                .{ key, now_secs - mtime, ttl },
                            );
                            skip_load = true;
                        }
                    } else |err| switch (err) {
                        object_store.Error.NotFound => {
                            log.warn("checkpoint refers to missing cache key '{s}'; cold-starting cache", .{key});
                            skip_load = true;
                        },
                        else => log.debug("store.head failed for '{s}' ({}); TTL check skipped", .{ key, err }),
                    }
                }
                if (!skip_load) {
                    const loaded = cache_persistence.loadCacheFromKey(allocator, &reader.schema_cache, store, key) catch 0;
                    if (loaded > 0) log.info("loaded {d} table schemas from cache", .{loaded});
                }
            }
        }
    }

    if (reader.table_filter) |*filter| {
        filter.logSummary();
    }

    reader.open() catch |err| {
        log.err("failed to open binlog stream: {}", .{err});
        log.err("troubleshooting: verify binlog file '{s}' exists, binlog is enabled, user has REPLICATION SLAVE privileges", .{prereq.file});
        return err;
    };
    defer reader.close();

    switch (config.output_mode) {
        .stdout => {
            reader.readAll() catch |err| {
                log.err("error during binlog reading: {}", .{err});
                return err;
            };
        },
        .parquet => {
            const parquet_label = data_label_opt.?;
            const state_store_ptr: ?*object_store.ObjectStore =
                if (state_store_opt) |*s| s else null;
            const predecessor_cache_key: ?[]const u8 =
                if (maybe_checkpoint) |cp| cp.schema_cache_key else null;

            var pipe = pipeline_mod.Pipeline.init(.{
                .allocator = pipeline_allocator,
                .data_store = &data_store_opt.?,
                .data_label = parquet_label,
                .initial_binlog_file = prereq.file,
                .batch_size = config.parquet_batch_size,
                .event_queue_capacity = config.pipeline_queue_capacity,
                .boolean_encoding = config.boolean_encoding,
                .flush_size_bytes = config.flush_size_bytes,
                .flush_time_gate_ms = config.flush_time_gate_ms,
                .soft_deadline_ms = config.soft_deadline_ms,
                .state_store = state_store_ptr,
                .predecessor_cache_key = predecessor_cache_key,
                .run_id = run_id.?,
            }) catch |err| {
                log.err("failed to initialize pipeline: {}", .{err});
                return err;
            };
            defer pipe.deinit();

            log.info(
                "pipeline started: batch_size={d} queue_capacity={d} flush_size={d}MB time_gate={d}ms soft_deadline={d}ms",
                .{
                    config.parquet_batch_size,
                    config.pipeline_queue_capacity,
                    @divTrunc(config.flush_size_bytes, 1024 * 1024),
                    config.flush_time_gate_ms,
                    config.soft_deadline_ms,
                },
            );

            var running = true;
            var events_sent: u64 = 0;
            while (running) {
                if (pipe.shouldStop()) {
                    log.info("graceful shutdown requested by soft deadline; stopping event pump", .{});
                    running = false;
                    break;
                }

                const fetched = reader.fetchEvent() catch |err| {
                    log.err("error fetching event: {}", .{err});
                    break;
                };

                if (fetched) |ev| {
                    switch (ev) {
                        .rows => |row_data| {
                            var send_failed = false;
                            for (row_data.row_events, 0..) |row_event, row_idx| {
                                var msg = dupeRowEventForPipeline(
                                    pipeline_allocator,
                                    row_data.event,
                                    row_event,
                                    row_data.table_metadata,
                                    row_idx + 1,
                                    row_data.resolved_columns,
                                ) catch |err| {
                                    log.err("failed to dupe row event: {}", .{err});
                                    continue;
                                };
                                _ = &msg;

                                if (!pipe.send(msg)) {
                                    var m = msg;
                                    switch (m) {
                                        .row_event => |*r| r.deinit(),
                                        else => {},
                                    }
                                    send_failed = true;
                                    break;
                                }
                                events_sent += 1;
                                if (events_sent % 10_000 == 0) {
                                    log.info("sent {d} row events to pipeline", .{events_sent});
                                }
                            }
                            if (send_failed) break;
                        },
                        .rotate => |rot| {
                            const duped_file = pipeline_allocator.dupe(u8, rot.next_binlog_file) catch {
                                log.err("failed to dupe rotate filename", .{});
                                continue;
                            };
                            const msg = pipeline_mod.PipelineMessage{
                                .rotate = .{
                                    .next_binlog_file = duped_file,
                                    .allocator = pipeline_allocator,
                                },
                            };
                            if (!pipe.send(msg)) {
                                pipeline_allocator.free(duped_file);
                                break;
                            }
                        },
                        .eof => {
                            running = false;
                        },
                        .format_description, .skip => {},
                    }
                } else {
                    running = false;
                }
            }

            pipe.shutdown();
            const metrics = pipe.join();
            metrics.printSummary();
        },
    }

    // ====== CLEAN SHUTDOWN ======
    var saved_cache_key: ?[]const u8 = null;
    if (cache_store_opt) |*store| {
        if (reader.schema_cache.count() > 0) {
            saved_cache_key = cache_persistence.saveCache(allocator, &reader.schema_cache, store, run_ctx.io) catch |err| blk: {
                log.warn("failed to save schema cache: {} - checkpoint will not reference a cache", .{err});
                break :blk null;
            };
        }
    }

    if (state_store_opt) |*store| {
        const final_state: state_mod.BinlogState = .{
            .binlog_file = reader.current_binlog_file,
            .binlog_position = reader.current_position,
            .updated_at_ms = clock.nowMs(),
            .run_id = run_id.?,
            .schema_cache_key = saved_cache_key,
            .is_in_progress = false,
        };
        state_mod.writeCheckpoint(allocator, store, CHECKPOINT_KEY, final_state) catch |err| {
            log.err("failed to write checkpoint: {}", .{err});
            return err;
        };
        log.info(
            "wrote checkpoint at {s}/{s}: {s}:{d}",
            .{ state_label_opt.?, CHECKPOINT_KEY, reader.current_binlog_file, reader.current_position },
        );

        state_mod.releaseLock(store, CURRENT_KEY);
    }

    log.info("total events processed: {d}", .{reader.events_read});
    if (reader.tables_filtered > 0) {
        log.info("table map events filtered: {d}", .{reader.tables_filtered});
    }
}
