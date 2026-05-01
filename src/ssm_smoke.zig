//! Standalone smoke binary for `feat/ssm-client`.
//!
//! Calls `getParametersByPath` against AWS SSM with whatever credentials
//! are in the env, prints a tiny JSON line per parameter, exits non-zero
//! if anything fails. Used by `docker/integration_test.sh run_ssm`.
//!
//! Why a separate binary instead of a flag on the main connector:
//! - The connector's startup is opinionated (probeWritable, lock claim,
//!   master-pos resolution, etc.). For an SSM round-trip we want a tight
//!   "did the SDK + creds + IAM + KMS path work" smoke with nothing
//!   between us and the wire.
//! - Keeps `feat/lambda-adapter`'s wiring decisions out of this branch.
//!
//! Env vars (read via `aws_creds.fromEnv`):
//!   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
//!   AWS_SESSION_TOKEN (optional).
//!
//! Plus:
//!   SSM_PARAMETER_PREFIX - defaults to `/config/myzql-binlog-connector/dev/`.
//!     Trailing slash matters (SSM treats prefixes as path-prefix-with-slash).

const std = @import("std");
const aws_creds = @import("aws_creds.zig");
const ssm = @import("ssm_client.zig");

const log = std.log.scoped(.ssm_smoke);

const DEFAULT_PREFIX = "/config/myzql-binlog-connector/dev/";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const creds = try aws_creds.fromEnv(init.environ_map);
    const prefix = init.environ_map.get("SSM_PARAMETER_PREFIX") orelse DEFAULT_PREFIX;

    log.info("calling SSM GetParametersByPath path={s} region={s}", .{ prefix, creds.region });

    var client = ssm.SsmClient.init(allocator, init.io, creds);
    defer client.deinit();

    var set = client.getParametersByPath(prefix, true) catch |err| {
        log.err("[SSM_SMOKE_FAIL] {}", .{err});
        return err;
    };
    defer set.deinit();

    log.info("got {d} parameters", .{set.parameters.len});

    // Print one JSON object per param for the bash assertion side.
    // Values redacted for SecureString - the integration test asserts
    // on type + non-empty length, not on the literal secret.
    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;
    for (set.parameters) |p| {
        const type_str = switch (p.type) {
            .String => "String",
            .SecureString => "SecureString",
            .StringList => "StringList",
        };
        const display_value = if (p.type == .SecureString) "***REDACTED***" else p.value;
        try stdout.print(
            "{{\"name\":\"{s}\",\"type\":\"{s}\",\"value\":\"{s}\",\"value_len\":{d}}}\n",
            .{ p.name, type_str, display_value, p.value.len },
        );
    }
    try stdout.flush();
}
