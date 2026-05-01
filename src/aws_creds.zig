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
