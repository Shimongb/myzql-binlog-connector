//! MySQL Binlog Connector - Entry Point
//!
//! MySQL binlog reader for Change Data Capture (CDC) applications.
//!
//! This is the main entry point for the MySQL binlog reader application.
//! It handles:
//! - Command-line argument parsing
//! - Configuration file loading (JSON format)
//! - MySQL connection establishment with health checks
//! - Binlog reader initialization and execution
//! - Error handling and graceful shutdown
//!
//! Architecture:
//! The application follows a modular design where each component has a single responsibility:
//! - config.zig: Configuration parsing and validation
//! - connection.zig: MySQL connection management with health monitoring
//! - binlog_reader.zig: Core binlog streaming with event reading
//! - event_parser.zig: Complete event parsing for all column types (JSON, DECIMAL, BIT, etc.)
//! - json_decoder.zig: Production MySQL JSON binary format decoder with MariaDB support
//! - output.zig: Human-readable output with consistent datetime formatting
//!
//! Key Features:
//! - Full support for MySQL 5.7+ and 8.0+ binlog formats
//! - Complete column type coverage including complex types (JSON, DECIMAL(65,30), BIT)
//! - UPDATE events with both before and after values for full CDC capability
//! - Production-ready JSON decoding with offset tables and nested object support
//! - Human-readable timestamp formatting (UTC) matching MySQL client output
//! - MariaDB compatibility with automatic format detection

const std = @import("std");
const connection = @import("connection.zig");
const config_mod = @import("config.zig");
const binlog_reader = @import("binlog_reader.zig");
const pipeline_mod = @import("pipeline.zig");
const event_parser = @import("event_parser.zig");
const log_config = @import("log_config.zig");
const prereq_check = @import("prereq_check.zig");
const object_store = @import("object_store.zig");
const state_mod = @import("state.zig");

const schema_cache_mod = @import("schema_cache.zig");
const cache_persistence = @import("cache_persistence.zig");

const log = std.log.scoped(.main);

const CURRENT_KEY = "current.json";
const CHECKPOINT_KEY = "last_checkpoint.json";

/// Current Unix milliseconds via the project's std.Io clock.
fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.now(.real, io);
    return @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_ms));
}

/// Install custom log function with runtime level filtering.
/// Set compile-time level to .debug so all levels pass through to our logFn,
/// which handles runtime filtering based on CLI flags and config.
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = log_config.logFn,
};

/// Duplicate row event data into a PipelineMessage with owned memory.
fn dupeRowEventForPipeline(
    alloc: std.mem.Allocator,
    ev: event_parser.Event,
    re: event_parser.RowEvent,
    meta: event_parser.TableMetadata,
    event_row_index: u64,
    resolved_columns: ?[]const schema_cache_mod.ColumnInfo,
) !pipeline_mod.PipelineMessage {
    // Dupe resolved columns if available
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

pub fn main(init: std.process.Init) !void {
    // Set up allocator with arena for config memory
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const allocator = arena.allocator();

    // Parse CLI arguments: [-v] [--log-file <path>] <config.json>
    var arg_iter = init.minimal.args.iterate();
    const prog_name = arg_iter.next() orelse "myzql_binlog_connector";

    var cli_verbose = false;
    var cli_log_file: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;

    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-v")) {
            cli_verbose = true;
        } else if (std.mem.eql(u8, arg, "--log-file")) {
            cli_log_file = arg_iter.next();
        } else if (arg.len > 0 and arg[0] == '-') {
            std.debug.print("Unknown option: {s}\n", .{arg});
            printUsage(prog_name);
            std.process.exit(1);
        } else {
            config_path = arg;
        }
    }

    // env-var override. `CONFIG_PATH` wins over the positional
    // CLI arg when both are set; this is how the Lambda invocation path
    // will pass the config (no CLI args available there).
    // Local CLI users can also use it to override a hardcoded path (alias / wrapper script).
    // Per-field env overrides are deliberately NOT supported here
    // SSM-sourced config happens in the Lambda
    const env_config_path = init.environ_map.get("CONFIG_PATH");
    const cfg_path = env_config_path orelse config_path orelse {
        printUsage(prog_name);
        std.process.exit(1);
    };

    // Initialize logging with CLI overrides (before config load so errors are logged).
    // Default to info; -v promotes to debug. Will re-initialize after config load
    // if config specifies different settings.
    log_config.init(if (cli_verbose) .debug else .info, cli_log_file);

    log.info("MySQL Binlog Connector v0.5.0", .{});

    // Surface where the config path came from — helps ops debug when
    // an env var unexpectedly shadows the CLI arg.
    if (env_config_path != null and config_path != null) {
        log.warn("CONFIG_PATH env var overrides CLI arg ('{s}' wins over '{s}')", .{ cfg_path, config_path.? });
    } else if (env_config_path != null) {
        log.info("config path from env CONFIG_PATH: {s}", .{cfg_path});
    } else {
        log.info("config path from CLI arg: {s}", .{cfg_path});
    }

    // Load configuration
    log.info("loading configuration from: {s}", .{cfg_path});
    var config = config_mod.Config.loadFromFile(allocator, cfg_path) catch |err| {
        log.err("failed to load configuration: {}", .{err});
        return err;
    };

    // Re-initialize logging with config values, unless CLI already overrode
    const effective_level = if (cli_verbose) std.log.Level.debug else config.log_level.toStdLevel();
    const effective_log_file = cli_log_file orelse config.log_file;
    log_config.deinit();
    log_config.init(effective_level, effective_log_file);
    defer log_config.deinit();

    // Display loaded configuration
    config.logSummary();

    // Attempt to connect using config
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

    // Get server version
    const server_version = conn.getServerVersion();
    log.info("MySQL server version: {s}", .{server_version});

    // Test connection health
    log.debug("testing connection (ping)", .{});
    conn.ping() catch |err| {
        log.err("ping failed: {}", .{err});
        return err;
    };
    log.debug("connection is alive", .{});

    // ====================================================================
    // State init.
    //
    // Order:
    //   1. Resolve `state_dir` and `cache_dir` paths from config.output_dir.
    //   2. checkLock(current.json) — exit gracefully if a fresh owner is live.
    //   3. loadCheckpoint(last_checkpoint.json) — `?BinlogState`.
    //   4. Resolve effective start position: checkpoint > config > master.
    //   5. prereq_check on effective position (may adjust to oldest).
    //   6. writeCurrentLock with adjusted position + new run_id.
    //   7. BinlogReader.init with start_file/start_position.
    //   8. loadCacheFromKey(checkpoint.schema_cache_key) if present + fresh.
    // ====================================================================

    var state_dir_path: ?[]const u8 = null;
    var cache_dir_path: ?[]const u8 = null;
    var data_dir_path: ?[]const u8 = null;
    if (config.output_dir) |od| {
        state_dir_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.STATE_SUBDIR });
        cache_dir_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.DDL_CACHE_SUBDIR });
        data_dir_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ od, config_mod.DATA_SUBDIR });
    }

    var state_store_opt: ?object_store.ObjectStore = null;
    if (state_dir_path) |sdp| {
        state_store_opt = .{ .posix = object_store.PosixStore.init(allocator, sdp) };
    }

    var cache_store_opt: ?object_store.ObjectStore = null;
    if (cache_dir_path) |cdp| {
        cache_store_opt = .{ .posix = object_store.PosixStore.init(allocator, cdp) };
    }

    // Inspect current.json. Skip the run if a live owner is detected.
    var maybe_checkpoint: ?state_mod.BinlogState = null;
    defer if (maybe_checkpoint) |s| s.deinit(allocator);

    if (state_store_opt) |*store| {
        log.info("checking for existing execution state at {s}/{s}", .{ state_dir_path.?, CURRENT_KEY });
        const lock_check = state_mod.checkLock(
            allocator,
            store,
            CURRENT_KEY,
            config.current_state_staleness_ms,
            nowMs(init.io),
        ) catch |err| {
            log.err("state checkLock failed: {}", .{err});
            return err;
        };
        defer if (lock_check.prior_state) |s| s.deinit(allocator);

        switch (lock_check.outcome) {
            .acquired_fresh => log.info("no prior state — fresh execution", .{}),
            .acquired_stale_predecessor => {
                if (lock_check.prior_state) |s| {
                    const age_s = @divFloor(nowMs(init.io) - s.updated_at_ms, std.time.ms_per_s);
                    log.warn(
                        "found stale state (run_id: {s}, age: {d}s); assuming crashed predecessor — will resume from checkpoint",
                        .{ s.run_id, age_s },
                    );
                } else {
                    log.warn("found malformed state file; assuming crashed predecessor — will resume from checkpoint", .{});
                }
            },
            .skip_live_owner => {
                if (lock_check.prior_state) |s| {
                    const age_s = @divFloor(nowMs(init.io) - s.updated_at_ms, std.time.ms_per_s);
                    log.warn(
                        "found recent in-progress state (run_id: {s}, age: {d}s) — skipping execution to avoid duplication",
                        .{ s.run_id, age_s },
                    );
                }
                return;
            },
        }

        // Load the durable checkpoint (independent of current.json).
        maybe_checkpoint = state_mod.loadCheckpoint(allocator, store, CHECKPOINT_KEY) catch null;
    }

    // Resolve effective start position.
    var effective_file: []const u8 = undefined;
    var effective_pos: u64 = undefined;
    if (maybe_checkpoint) |cp| {
        effective_file = cp.binlog_file;
        effective_pos = cp.binlog_position;
        log.info(
            "found last checkpoint: {s}:{d} — config.from_binlog_* values are ignored. Delete {s}/{s} to force restart from config.",
            .{ cp.binlog_file, cp.binlog_position, state_dir_path.?, CHECKPOINT_KEY },
        );
    } else if (config.from_binlog_file) |cf| {
        effective_file = cf;
        effective_pos = config.from_binlog_position.?;
        log.info("no checkpoint — bootstrapping from config: {s}:{d}", .{ effective_file, effective_pos });
    } else {
        log.info("no checkpoint and no config.from_binlog_*; querying master position", .{});
        const mp = prereq_check.getMasterPosition(allocator, &conn) catch |err| {
            log.err(
                "[MISSING_START_POSITION] cannot determine binlog start position. Tried: (1) {s}/{s} (not found), (2) config.from_binlog_* (not set), (3) SHOW MASTER STATUS ({}). Set config.from_binlog_file/position or ensure binlog is enabled on the server.",
                .{
                    state_dir_path orelse "(state files disabled — set output_dir to enable resume)",
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

    // Cold-start prerequisite checks:
    // server config (hard fail on bad binlog_format/row_image),
    // grants (soft warn),
    // and binlog position validation (graceful adjust to oldest available if the requested file is missing).
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

    // Auto-bound the run with master pos as the ceiling, when:
    //   * `bound_to_master_at_init` is true (default), AND
    //   * neither `to_binlog_file` nor `to_binlog_position` is set in config.
    // Hedges against accidental concurrent runs (a stale-lock-misread-as-crashed scenario only re-replays the already-captured range)
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

    // Claim the lock with the post-adjust position. Only happens after
    // we've committed to running — prereq failures leave no stale lock.
    var run_id: ?[]u8 = null;
    if (state_store_opt) |*store| {
        const id = try state_mod.generateRunId(allocator);
        run_id = id;
        const lock_state: state_mod.BinlogState = .{
            .binlog_file = prereq.file,
            .binlog_position = prereq.position,
            .updated_at_ms = nowMs(init.io),
            .run_id = id,
            // Carry the predecessor's cache key forward — if we crash
            // before writing a new cache, the next run still has a key.
            .schema_cache_key = if (maybe_checkpoint) |cp| cp.schema_cache_key else null,
            .is_in_progress = true,
        };
        try state_mod.writeCurrentLock(allocator, store, CURRENT_KEY, lock_state);
        log.info("claimed lock at {s}/{s} (run_id: {s})", .{ state_dir_path.?, CURRENT_KEY, id });
    }

    // Create secondary connection for DESCRIBE queries (column name resolution)
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

    // Initialize binlog reader with the resolved start position.
    log.info("starting binlog reader", .{});
    const describe_conn_ptr: ?*connection.Connection = if (describe_conn_opt) |*dc| dc else null;
    var reader = try binlog_reader.BinlogReader.init(
        allocator,
        &conn,
        config,
        describe_conn_ptr,
        prereq.file,
        prereq.position,
    );
    defer reader.deinit();

    // Load schema cache by the key from the checkpoint (if any). TTL check
    // is opt-in — if the cache key has aged past `schema_cache_ttl_seconds`,
    // skip the load and cold-start the cache (position still resumes).
    if (cache_store_opt) |*store| {
        if (maybe_checkpoint) |cp| {
            if (cp.schema_cache_key) |key| {
                var skip_load = false;
                if (config.schema_cache_ttl_seconds) |ttl| {
                    if (store.head(key)) |info| {
                        const now_secs = @divFloor(nowMs(init.io), std.time.ms_per_s);
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

    // Log table filter summary
    if (reader.table_filter) |*filter| {
        filter.logSummary();
    }

    // Open binlog stream at the resolved position.
    reader.open() catch |err| {
        log.err("failed to open binlog stream: {}", .{err});
        log.err("troubleshooting: verify binlog file '{s}' exists, binlog is enabled, user has REPLICATION SLAVE privileges", .{prereq.file});
        return err;
    };
    defer reader.close();

    // Branch on output mode
    switch (config.output_mode) {
        .stdout => {
            reader.readAll() catch |err| {
                log.err("error during binlog reading: {}", .{err});
                return err;
            };
        },
        .parquet => {
            // Validation guarantees output_dir is set when output_mode = parquet.
            const parquet_dir = data_dir_path.?;

            // State store + run_id pointers for the pipeline's mid-run
            // checkpoint hook. Both are guaranteed non-null in parquet
            // mode (parquet → output_dir set → lock claimed → run_id).
            const state_store_ptr: ?*object_store.ObjectStore =
                if (state_store_opt) |*s| s else null;
            const predecessor_cache_key: ?[]const u8 =
                if (maybe_checkpoint) |cp| cp.schema_cache_key else null;

            var pipe = pipeline_mod.Pipeline.init(.{
                .allocator = gpa.allocator(),
                .output_dir = parquet_dir,
                .initial_binlog_file = prereq.file,
                .batch_size = config.parquet_batch_size,
                .event_queue_capacity = config.pipeline_queue_capacity,
                .boolean_encoding = config.boolean_encoding,
                .flush_size_bytes = config.flush_size_bytes,
                .flush_time_gate_ms = config.flush_time_gate_ms,
                .state_store = state_store_ptr,
                .predecessor_cache_key = predecessor_cache_key,
                .run_id = run_id.?,
            }) catch |err| {
                log.err("failed to initialize pipeline: {}", .{err});
                return err;
            };
            defer pipe.deinit();

            log.info(
                "pipeline started: batch_size={d} queue_capacity={d} flush_size={d}MB time_gate={d}ms",
                .{
                    config.parquet_batch_size,
                    config.pipeline_queue_capacity,
                    @divTrunc(config.flush_size_bytes, 1024 * 1024),
                    config.flush_time_gate_ms,
                },
            );

            // Event loop: fetch events and push to pipeline
            var running = true;
            var events_sent: u64 = 0;
            while (running) {
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
                                    gpa.allocator(),
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
                            const duped_file = gpa.allocator().dupe(u8, rot.next_binlog_file) catch {
                                log.err("failed to dupe rotate filename", .{});
                                continue;
                            };
                            const msg = pipeline_mod.PipelineMessage{
                                .rotate = .{
                                    .next_binlog_file = duped_file,
                                    .allocator = gpa.allocator(),
                                },
                            };
                            if (!pipe.send(msg)) {
                                gpa.allocator().free(duped_file);
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

    // ====== CLEAN SHUTDOWN — Step 4 ======
    // Order matters:
    //   1. saveCache → returns the content-addressable cache key.
    //   2. writeCheckpoint with final {file, position, cache_key}.
    //   3. releaseLock (best-effort — failures are non-fatal).
    //
    // Failures in (1) or (2) propagate. (3) is best-effort because the
    // next run's stale-detection handles a leftover lock anyway.
    //
    // Error paths above (any `return err`) deliberately skip both (2)
    // and (3) — leaving current.json in place is the crash signal that
    // tells the next run "predecessor died, resume from checkpoint."

    var saved_cache_key: ?[]const u8 = null;
    if (cache_store_opt) |*store| {
        if (reader.schema_cache.count() > 0) {
            saved_cache_key = cache_persistence.saveCache(allocator, &reader.schema_cache, store, init.io) catch |err| blk: {
                log.warn("failed to save schema cache: {} — checkpoint will not reference a cache", .{err});
                break :blk null;
            };
        }
    }

    if (state_store_opt) |*store| {
        const final_state: state_mod.BinlogState = .{
            .binlog_file = reader.current_binlog_file,
            .binlog_position = reader.current_position,
            .updated_at_ms = nowMs(init.io),
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
            .{ state_dir_path.?, CHECKPOINT_KEY, reader.current_binlog_file, reader.current_position },
        );

        state_mod.releaseLock(store, CURRENT_KEY);
    }

    // Summary
    log.info("total events processed: {d}", .{reader.events_read});
    if (reader.tables_filtered > 0) {
        log.info("table map events filtered: {d}", .{reader.tables_filtered});
    }
}

fn printUsage(prog_name: []const u8) void {
    std.debug.print(
        \\Usage: {s} [-v] [--log-file <path>] <config.json>
        \\
        \\Options:
        \\  -v              Enable debug-level logging
        \\  --log-file <p>  Write logs to file instead of stderr
        \\
        \\Config file format (JSON):
        \\  {{
        \\    "host": "127.0.0.1",
        \\    "port": 3306,
        \\    "user": "repl_user",
        \\    "password": "",
        \\    "database": "mydb",
        \\    "from_binlog_file": "binlog.000001",
        \\    "from_binlog_position": 4,
        \\    "log_level": "info",
        \\    "log_file": null
        \\  }}
        \\
    , .{prog_name});
}
