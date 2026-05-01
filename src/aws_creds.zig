//! AWS credentials struct + env-var loader.
//!
//! Shared by every AWS client in this repo. The shape is:
//!
//! ```
//! Creds { access_key_id, secret_access_key, session_token?, region }
//! ```
//!
//! `session_token` is `?[]const u8` so static IAM users (no STS) can
//! pass `null`. Lambda always supplies one, so does
//! `aws sts get-session-token` for local dev.
//!
//! ## Constructors
//!
//! - `fromEnv(env_map)` - reads `AWS_ACCESS_KEY_ID` /
//!   `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` (optional) /
//!   `AWS_REGION` (optional, defaults `us-east-1`). The values are
//!   borrowed from the env_map; the caller keeps the env_map alive
//!   for the whole process.
//!
//! - **Future:** `fromContext(lambda_ctx)` once `feat/lambda-adapter`
//!   lands. aws-lambda-zig exposes the same `AWS_*` values via its
//!   `Context.config.*` fields, so the constructor will be a 1:1
//!   field copy with no env lookup. Both constructors will return
//!   the same shape and either S3 or SSM client can take it.
//!
//! ## Lifetime
//!
//! `Creds` does not own its strings. The env_map (or future Lambda
//! context) is the source of truth and outlives every client that
//! borrows from it.

const std = @import("std");

const log = std.log.scoped(.aws_creds);

const DEFAULT_REGION = "us-east-1";

pub const Error = error{MissingAwsCredentials};

pub const Creds = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8 = null,
    region: []const u8,
};

/// Build `Creds` from an aws-lambda-zig Context's `config` struct (or
/// any struct shaped like it). The Lambda runtime calls `loadMeta`
/// once per cold start to populate these fields from the
/// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN /
/// AWS_REGION env vars Lambda injects - by the time our handler
/// runs, the Context has them.
///
/// Structural typing (`anytype`) keeps `aws_creds.zig` free of the
/// `lambda` package import, so the lib module + tests don't drag in
/// aws-lambda-zig source. Caller is expected to pass
/// `lambda_ctx.config` (the `ConfigMeta` substruct).
///
/// Required fields on the input struct:
///   - `aws_access_id: []const u8`
///   - `aws_access_secret: []const u8`
///   - `aws_session_token: []const u8`  (empty string treated as null)
///   - `aws_region: []const u8`
///
/// aws-lambda-zig defaults empty strings rather than null - we map
/// `aws_session_token == ""` to `session_token = null` so static
/// IAM users (no STS) get the correct shape.
pub fn fromContext(ctx_config: anytype) Error!Creds {
    if (ctx_config.aws_access_id.len == 0) {
        log.err("[MISSING_AWS_CREDS] ctx.config.aws_access_id is empty", .{});
        return error.MissingAwsCredentials;
    }
    if (ctx_config.aws_access_secret.len == 0) {
        log.err("[MISSING_AWS_CREDS] ctx.config.aws_access_secret is empty", .{});
        return error.MissingAwsCredentials;
    }
    return .{
        .access_key_id = ctx_config.aws_access_id,
        .secret_access_key = ctx_config.aws_access_secret,
        .session_token = if (ctx_config.aws_session_token.len > 0) ctx_config.aws_session_token else null,
        .region = ctx_config.aws_region,
    };
}

/// Build `Creds` from a process env map. Returns
/// `error.MissingAwsCredentials` when `AWS_ACCESS_KEY_ID` or
/// `AWS_SECRET_ACCESS_KEY` is unset (we treat both as required -
/// neither has a sensible default and silently producing an
/// invalid Creds would just defer the error to a 403 from AWS).
pub fn fromEnv(env_map: *const std.process.Environ.Map) Error!Creds {
    const access_id = env_map.get("AWS_ACCESS_KEY_ID") orelse {
        log.err("[MISSING_AWS_CREDS] AWS_ACCESS_KEY_ID env var is required", .{});
        return error.MissingAwsCredentials;
    };
    const secret = env_map.get("AWS_SECRET_ACCESS_KEY") orelse {
        log.err("[MISSING_AWS_CREDS] AWS_SECRET_ACCESS_KEY env var is required", .{});
        return error.MissingAwsCredentials;
    };
    return .{
        .access_key_id = access_id,
        .secret_access_key = secret,
        .session_token = env_map.get("AWS_SESSION_TOKEN"),
        .region = env_map.get("AWS_REGION") orelse DEFAULT_REGION,
    };
}

test "fromEnv: full set including session token" {
    const allocator = std.testing.allocator;
    var em = std.process.Environ.Map.init(allocator);
    defer em.deinit();
    try em.put("AWS_ACCESS_KEY_ID", "AKIATEST");
    try em.put("AWS_SECRET_ACCESS_KEY", "secret");
    try em.put("AWS_SESSION_TOKEN", "token");
    try em.put("AWS_REGION", "us-west-2");

    const c = try fromEnv(&em);
    try std.testing.expectEqualStrings("AKIATEST", c.access_key_id);
    try std.testing.expectEqualStrings("secret", c.secret_access_key);
    try std.testing.expectEqualStrings("token", c.session_token.?);
    try std.testing.expectEqualStrings("us-west-2", c.region);
}

test "fromEnv: minimal (no session token, default region)" {
    const allocator = std.testing.allocator;
    var em = std.process.Environ.Map.init(allocator);
    defer em.deinit();
    try em.put("AWS_ACCESS_KEY_ID", "AKIATEST");
    try em.put("AWS_SECRET_ACCESS_KEY", "secret");

    const c = try fromEnv(&em);
    try std.testing.expect(c.session_token == null);
    try std.testing.expectEqualStrings("us-east-1", c.region);
}

// Note: negative tests (missing AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
// are intentionally not unit-tested. Zig 0.16's test runner treats
// `log.err` calls as test failures; the err-log is the whole point of
// the missing-creds path, so we leave that to the integration test
// (`docker/integration_test.sh` run_s3 + run_ssm fail loud and visibly
// when env vars are absent - by design).

// ============================================================
// fromContext tests - use a fake struct shaped like aws-lambda-zig's
// Context.config. Real Context lookup happens in lambda_handler.zig.
// ============================================================

const FakeCtxConfig = struct {
    aws_access_id: []const u8,
    aws_access_secret: []const u8,
    aws_session_token: []const u8,
    aws_region: []const u8,
};

test "fromContext: full STS-vended creds via Lambda runtime" {
    const cfg: FakeCtxConfig = .{
        .aws_access_id = "ASIATEST",
        .aws_access_secret = "secret",
        .aws_session_token = "token",
        .aws_region = "us-west-2",
    };
    const c = try fromContext(cfg);
    try std.testing.expectEqualStrings("ASIATEST", c.access_key_id);
    try std.testing.expectEqualStrings("secret", c.secret_access_key);
    try std.testing.expectEqualStrings("token", c.session_token.?);
    try std.testing.expectEqualStrings("us-west-2", c.region);
}

test "fromContext: empty session_token maps to null (static IAM user)" {
    const cfg: FakeCtxConfig = .{
        .aws_access_id = "AKIATEST",
        .aws_access_secret = "secret",
        .aws_session_token = "",
        .aws_region = "us-east-1",
    };
    const c = try fromContext(cfg);
    try std.testing.expect(c.session_token == null);
}

// Negative paths (empty access_id / access_secret) skipped for the
// same Zig 0.16 log.err-as-failure reason as fromEnv; integration
// test surfaces the failure when the lambda runtime hands us empty
// fields (which would itself be a Lambda misconfiguration).
