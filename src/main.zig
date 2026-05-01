//! MySQL Binlog Connector - CLI Entry Point
//!
//! This file owns CLI-specific concerns: arg parsing, `CONFIG_PATH` env
//! override, log subsystem init, config-file loading. The actual
//! orchestration (connect → state → drain → checkpoint → release lock)
//! lives in `connector.zig` so the future Lambda handler
//! (`feat/lambda-adapter`) can call into the same `connector.run`
//! without duplicating ~500 lines.
//!
//! Architecture:
//!   - config.zig:     parsing + validation + env-precedence merge
//!   - connector.zig:  bounded-invocation orchestration (the meat)
//!   - log_config.zig: runtime log-level routing for std.log

const std = @import("std");
const config_mod = @import("config.zig");
const log_config = @import("log_config.zig");
const connector = @import("connector.zig");

const log = std.log.scoped(.main);

/// Install custom log function with runtime level filtering.
/// Set compile-time level to .debug so all levels pass through to our logFn,
/// which handles runtime filtering based on CLI flags and config.
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = log_config.logFn,
};

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
    // will pass the config (no CLI args available there). Local CLI
    // users can also use it to override a hardcoded path (alias /
    // wrapper script). Per-field env overrides for SSM-sourced creds
    // happen in the Lambda adapter, not here.
    const env_config_path = init.environ_map.get("CONFIG_PATH");
    const cfg_path = env_config_path orelse config_path orelse {
        printUsage(prog_name);
        std.process.exit(1);
    };

    // Initialize logging with CLI overrides (before config load so errors are logged).
    log_config.init(if (cli_verbose) .debug else .info, cli_log_file, .text);

    log.info("MySQL Binlog Connector v0.5.0", .{});

    // Surface where the config path came from - helps ops debug when
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

    // Apply the precedence chain: file > env > defaults. Idempotent;
    // only fills in fields the file left at their `?T = null` default.
    config.mergeFromEnv(init.environ_map);

    // Re-initialize logging with config values, unless CLI already overrode
    const effective_level = if (cli_verbose) std.log.Level.debug else config.log_level.toStdLevel();
    const effective_log_file = cli_log_file orelse config.log_file;
    log_config.deinit();
    log_config.init(effective_level, effective_log_file, .text);
    defer log_config.deinit();

    // Display loaded configuration
    config.logSummary();

    // Hand off to the orchestration. `connector.run` returns when the
    // run terminates (clean exit, soft-deadline exit, live-owner skip,
    // to_binlog_position reached). Errors propagate; on error,
    // current.json is deliberately left as the crash signal for the
    // next run.
    return connector.run(.{
        .io = init.io,
        .environ_map = init.environ_map,
        .environ = init.minimal.environ,
    }, allocator, gpa.allocator(), &config);
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
