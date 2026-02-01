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

const log = std.log.scoped(.main);

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
) !pipeline_mod.PipelineMessage {
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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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

    const cfg_path = config_path orelse {
        printUsage(prog_name);
        std.process.exit(1);
    };

    // Initialize logging with CLI overrides (before config load so errors are logged).
    // Default to info; -v promotes to debug. Will re-initialize after config load
    // if config specifies different settings.
    log_config.init(if (cli_verbose) .debug else .info, cli_log_file);

    log.info("MySQL Binlog Connector v0.5.0", .{});

    // Load configuration
    log.info("loading configuration from: {s}", .{cfg_path});
    const config = config_mod.Config.loadFromFile(allocator, cfg_path) catch |err| {
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

    // Initialize binlog reader with connection and config
    log.info("starting binlog reader", .{});
    var reader = try binlog_reader.BinlogReader.init(allocator, &conn, config);
    defer reader.deinit();

    // Log table filter summary
    if (reader.table_filter) |*filter| {
        filter.logSummary();
    }

    // Open binlog stream at configured position
    reader.open() catch |err| {
        log.err("failed to open binlog stream: {}", .{err});
        log.err("troubleshooting: verify binlog file '{s}' exists, binlog is enabled, user has REPLICATION SLAVE privileges", .{config.from_binlog_file});
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
            const output_dir = config.parquet_output_dir orelse "./parquet_output";

            var pipe = pipeline_mod.Pipeline.init(
                gpa.allocator(),
                output_dir,
                config.from_binlog_file,
                config.parquet_batch_size,
                config.pipeline_queue_capacity,
            ) catch |err| {
                log.err("failed to initialize pipeline: {}", .{err});
                return err;
            };
            defer pipe.deinit();

            log.info("pipeline started: batch_size={d} queue_capacity={d}", .{
                config.parquet_batch_size, config.pipeline_queue_capacity,
            });

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
