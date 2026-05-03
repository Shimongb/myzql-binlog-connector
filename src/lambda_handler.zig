//! AWS Lambda handler - wraps `connector.run` for per-invocation
//! execution under aws-lambda-zig's `provided.al2023` runtime.
//!
//! Per-invocation everything (no static AppContext guard):
//!   - Fresh SSM fetch
//!   - Fresh MySQL connect
//!   - Fresh S3Store
//!
//! Eliminates the cross-lane contamination class of bug + dodges freeze/thaw connection death.
//! ~100-150ms cold setup per invoke is dwarfed by 90-180s of binlog draining.
//!
//! Shape:
//!   1. Parse EventBridge envelope; extract `detail`
//!   2. Deserialize `detail` into Config
//!   3. mergeFromEnv (env-var precedence: payload > env > defaults)
//!   4. Build Creds from Lambda Context (aws_access_id/secret/token/region)
//!   5. SSM lookup if `ssm_parameter_prefix` set; fill DB creds
//!   6. Compute soft_deadline_ms from `request.deadline_ms` minus
//!      a safety buffer for the post-drain checkpoint write
//!   7. Validate; logSummary
//!   8. Hand off to `connector.run`
//!   9. Return small JSON status (CloudWatch logs it; EventBridge
//!      ignores it)

const std = @import("std");
const lambda = @import("lambda");
const config_mod = @import("config.zig");
const aws_creds = @import("aws_creds.zig");
const ssm = @import("ssm_client.zig");
const connector = @import("connector.zig");
const log_config = @import("log_config.zig");
const clock = @import("clock.zig");

const log = std.log.scoped(.handler);

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = log_config.logFn,
};

/// Safety buffer between Lambda's hard kill (`request.deadline_ms`)
/// and our soft deadline. The connector spends this time post-drain
/// flushing parquets, writing the checkpoint, and releasing the
/// lock. Empirically a clean shutdown completes in <2s; 5s gives
/// generous headroom for slow S3 PUTs near deadline.
const SAFETY_BUFFER_MS: i64 = 5_000;

/// Floor on `soft_deadline_ms`. If Lambda's `deadline_ms` minus
/// the safety buffer leaves us less than this, the connector is
/// going to barely run anyway - but we still hand it some budget
/// so init / connect / first-flush get a chance.
const MIN_SOFT_DEADLINE_MS: i64 = 1_000;

/// Saved at process startup so the per-invocation handler can hand
/// them to `connector.run`. Lambda's `Context` exposes `io` and
/// `__kv__` but NOT `process.Environ` (the raw struct, distinct
/// from `Environ.Map`), and `connector.run` needs the raw Environ
/// to plug into `Io.Threaded.init`.
///
/// These are per-process, not per-lane - same Lambda function
/// container, same env regardless of which schedule fires us.
/// No cross-lane contamination concern.
var saved_io: std.Io = undefined;
var saved_environ: std.process.Environ = undefined;
var saved_environ_map: *const std.process.Environ.Map = undefined;

pub fn main(init: std.process.Init) void {
    saved_io = init.io;
    saved_environ = init.minimal.environ;
    saved_environ_map = init.environ_map;

    // JSON-formatted logs for CloudWatch Insights. Matches the
    // function's `LoggingConfig.LogFormat = JSON` setting - each
    // log line is a queryable structured object.
    log_config.init(.info, null, .json);

    log.info("lambda runtime starting; entering serve loop", .{});
    lambda.handle(init, handler, .{});
}

fn handler(ctx: lambda.Context, event: []const u8) ![]const u8 {
    // Per-invocation arena, deinit'd at handler return. ctx.gpa
    // is a "user owns + must free by end of invocation" allocator,
    // ctx.arena would also work but having our own scope is clearer.
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const alloc = arena.allocator();

    log.info(
        "invocation start: request_id={s} func_name={s} memory_mb={d}",
        .{ ctx.request.id, ctx.config.func_name, ctx.config.func_size },
    );

    // 1. Parse EventBridge envelope; extract `detail`.
    const Envelope = struct {
        detail: std.json.Value = .{ .null = {} },
    };
    const env = std.json.parseFromSliceLeaky(Envelope, alloc, event, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        log.err("[BAD_PAYLOAD] failed to parse EventBridge envelope: {}", .{err});
        return err;
    };

    // 2. Deserialize `detail` into Config.
    var config = std.json.parseFromValueLeaky(config_mod.Config, alloc, env.detail, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        log.err("[BAD_PAYLOAD] failed to parse Config from event.detail: {}", .{err});
        return err;
    };

    // 3. Apply env-var precedence - payload > env > defaults.
    config.mergeFromEnv(saved_environ_map);
    config.applyClamps();

    // 4. Build creds from Lambda Context. ctx.config has
    //    aws_access_id / aws_access_secret / aws_session_token /
    //    aws_region populated by the runtime at cold start from
    //    AWS_* env vars. Same shape `fromEnv` reads, just sourced
    //    via the typed Context.
    const creds = aws_creds.fromContext(ctx.config) catch |err| {
        log.err("[BAD_AWS_CREDS] {}", .{err});
        return err;
    };

    // 5. SSM lookup if configured. The composed path is
    //    `{ssm_parameter_prefix}/[{server_name}/]db/` - with
    //    server_name from the payload, this is how multi-lane
    //    invocations differentiate which credentials to pull.
    if (config.ssm_parameter_prefix != null) {
        var ssm_client = ssm.SsmClient.init(alloc, ctx.io.*, creds);
        defer ssm_client.deinit();

        const ssm_path = try config.ssmDbPath(alloc);
        log.info("fetching DB credentials from SSM: {s}", .{ssm_path});
        var params = ssm_client.getParametersByPath(ssm_path, true) catch |err| {
            log.err("[SSM_FETCH_FAIL] path={s} err={}", .{ ssm_path, err });
            return err;
        };
        defer params.deinit();

        try config.fillDbCredsFromSsm(alloc, params);
    }

    // 6. Compute soft_deadline_ms from Lambda's hard deadline.
    //    Lambda's request.deadline_ms is unix-epoch-ms when the
    //    container will be hard-killed. Subtract now() and the
    //    safety buffer to get how long we'll drain. If the payload
    //    set a smaller soft_deadline_ms explicitly, honor it (caps
    //    the run shorter than Lambda would, useful for local repro
    //    and for forcing an earlier clean shutdown during testing).
    const deadline_ms_i64: i64 = @intCast(ctx.request.deadline_ms);
    const remaining_ms = deadline_ms_i64 - clock.nowMs();
    const drain_budget = @max(remaining_ms - SAFETY_BUFFER_MS, MIN_SOFT_DEADLINE_MS);
    const payload_deadline = config.soft_deadline_ms;
    config.soft_deadline_ms = if (payload_deadline > 0)
        @min(payload_deadline, drain_budget)
    else
        drain_budget;
    log.info(
        "deadline math: remaining={d}ms safety={d}ms payload={d}ms soft_deadline={d}ms",
        .{ remaining_ms, SAFETY_BUFFER_MS, payload_deadline, config.soft_deadline_ms },
    );

    // 7. Validate after merging is complete.
    config.validate() catch |err| {
        log.err("[INVALID_CONFIG] {}", .{err});
        return err;
    };
    config.logSummary();

    // 8. Hand off to the same connector.run the CLI uses.
    log.info(
        "starting connector run: server_name={s} s3_uri={s}",
        .{
            config.server_name orelse "(none)",
            config.s3_uri orelse config.output_dir orelse "(none)",
        },
    );
    connector.run(.{
        .io = saved_io,
        .environ_map = saved_environ_map,
        .environ = saved_environ,
    }, alloc, ctx.gpa, &config) catch |err| {
        log.err("[CONNECTOR_ERROR] request_id={s} err={}", .{ ctx.request.id, err });
        return err;
    };

    log.info("invocation done: request_id={s}", .{ctx.request.id});
    return "{\"status\":\"ok\"}";
}
