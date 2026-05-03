//! SSM client - `GetParametersByPath` with KMS decryption + pagination.
//!
//! v1 covers exactly one operation: GetParametersByPath. The connector
//! + Lambda handler use case is "load DB credentials at cold start"
//! and that's all this op needs to satisfy. GetParameter,
//! PutParameter, DescribeParameters can be added later if a real
//! call site shows up.
//!
//! Talks AWS JSON 1.1 (POST, content-type: application/x-amz-json-1.1,
//! X-Amz-Target: AmazonSSM.GetParametersByPath) - different protocol
//! from S3's REST-XML, hence a separate client rather than reusing z3.
//!
//! Signing goes through our slim `aws_sigv4.zig` module. z3 has its
//! own internal signer but doesn't expose it through the public `s3`
//! module, so we carry our own.
//!
//! ## Mandatory status check
//!
//! Same lesson as `s3_store.zig`: never trust the transport to flag
//! 4xx/5xx as errors. Every response is checked, status mapped to a
//! typed `Error`, body preview logged on failure for quick triage.
//!
//! ## Pagination
//!
//! SSM caps responses at 10 parameters. We loop on `NextToken`
//! transparently and return the full set in one `ParamSet`.

const std = @import("std");
const aws_creds = @import("aws_creds.zig");
const aws_sigv4 = @import("aws_sigv4.zig");
const clock = @import("clock.zig");

const log = std.log.scoped(.ssm);

const SERVICE = "ssm";
const TARGET = "AmazonSSM.GetParametersByPath";
const CONTENT_TYPE = "application/x-amz-json-1.1";
/// Max response body per page. SSM responses are bounded at 10
/// parameters per call; even with large `SecureString` values we
/// shouldn't hit this. If we do, parse will fail loudly.
const MAX_BODY_PER_PAGE: u64 = 1 * 1024 * 1024;

pub const Error = error{
    /// 401 / 403 - bad creds, missing IAM permission, or missing
    /// `kms:Decrypt` on the SecureString CMK.
    Unauthorized,
    /// 400 with `ValidationException` / `InvalidParameters`.
    InvalidArgument,
    /// 429 / 503 - caller can retry with backoff. v1 doesn't auto-retry.
    Throttled,
    /// Network / parse / unexpected status - non-recoverable for v1.
    Io,
    OutOfMemory,
};

pub const ParamType = enum { String, SecureString, StringList };

pub const Parameter = struct {
    /// Full path, e.g. "/config/myzql-binlog-connector/dev/db/host".
    /// Arena-owned by the enclosing `ParamSet`.
    name: []const u8,
    /// Decrypted value (when `with_decryption=true` and type is
    /// SecureString). Arena-owned.
    value: []const u8,
    type: ParamType,
};

/// Owned set of parameters returned by `getParametersByPath`. All
/// strings (`name`, `value`) live in the embedded arena; calling
/// `deinit()` invalidates them.
pub const ParamSet = struct {
    parameters: []Parameter,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *ParamSet) void {
        self.arena.deinit();
    }

    /// Find a parameter whose `name` ends with `suffix`. Useful for
    /// callers that know the leaf path without rebuilding the full
    /// SSM path: `set.findBySuffix("/db/host")` works regardless of
    /// `SSM_PARAMETER_PREFIX`.
    pub fn findBySuffix(self: ParamSet, suffix: []const u8) ?Parameter {
        for (self.parameters) |p| {
            if (std.mem.endsWith(u8, p.name, suffix)) return p;
        }
        return null;
    }
};

pub const SsmClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Owned. `deinit()` cleans up.
    http: std.http.Client,
    /// Borrowed. Caller (process env-map / Lambda context) outlives
    /// this client.
    creds: aws_creds.Creds,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, creds: aws_creds.Creds) SsmClient {
        return .{
            .allocator = allocator,
            .io = io,
            .http = .{ .allocator = allocator, .io = io },
            .creds = creds,
        };
    }

    pub fn deinit(self: *SsmClient) void {
        self.http.deinit();
    }

    /// Drop the embedded `std.http.Client` (including any cached TLS
    /// session state) and spin up a fresh one. Targets the exact same
    /// freeze/thaw failure class that `S3Store.rebuildClient` covers:
    /// a Lambda container resumed from frozen holds onto TLS handshake
    /// state that AWS has since expired, so the first post-thaw call
    /// dies with `error.TlsInitializationFailed` - subsequent calls
    /// against a fresh client succeed.
    fn rebuildHttp(self: *SsmClient) void {
        self.http.deinit();
        self.http = .{ .allocator = self.allocator, .io = self.io };
    }

    /// Fetch all parameters under `path`, recursively, optionally
    /// decrypting `SecureString`s. Pagination is handled transparently.
    ///
    /// Returns `error.Unauthorized` for 401/403 (incl. missing
    /// `kms:Decrypt` for SecureString keys), `error.InvalidArgument`
    /// for malformed paths, `error.Throttled` for 429/503, and
    /// `error.Io` for any other unexpected response.
    pub fn getParametersByPath(
        self: *SsmClient,
        path: []const u8,
        with_decryption: bool,
    ) Error!ParamSet {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        var collected: std.ArrayList(Parameter) = .empty;
        var next_token: ?[]const u8 = null;
        var first_call = true;

        while (true) {
            const body = try buildRequestBody(arena_alloc, path, with_decryption, next_token);

            // First call of the invocation gets one retry on transport
            // failure: post-thaw Lambda containers frequently die on
            // `TlsInitializationFailed` before recovering on the next
            // attempt. Scoped to the first iteration because subsequent
            // pagination hops reuse the already-warm connection, so
            // failures there are genuinely exceptional.
            const page = if (first_call) blk: {
                if (self.callOnce(arena_alloc, body)) |p| {
                    break :blk p;
                } else |err| {
                    if (err != error.Io) return err;
                    log.warn(
                        "[SSM_RETRY] first call failed with {} - rebuilding http client and retrying once",
                        .{err},
                    );
                    self.rebuildHttp();
                    break :blk try self.callOnce(arena_alloc, body);
                }
            } else try self.callOnce(arena_alloc, body);
            first_call = false;

            // page.params is arena-allocated; safe to retain.
            try collected.appendSlice(arena_alloc, page.parameters);

            if (page.next_token) |tok| {
                next_token = tok; // arena-owned
            } else {
                break;
            }
        }

        return .{
            .parameters = try collected.toOwnedSlice(arena_alloc),
            .arena = arena,
        };
    }

    const Page = struct {
        parameters: []Parameter,
        next_token: ?[]const u8,
    };

    fn callOnce(self: *SsmClient, arena_alloc: std.mem.Allocator, body: []const u8) Error!Page {
        const host = try std.fmt.allocPrint(
            arena_alloc,
            "ssm.{s}.amazonaws.com",
            .{self.creds.region},
        );
        const url = try std.fmt.allocPrint(arena_alloc, "https://{s}/", .{host});

        // Sign - pass content-type + x-amz-target as extra signed
        // headers; signer adds host, x-amz-date, x-amz-content-sha256,
        // and (when applicable) x-amz-security-token.
        const extra = [_]aws_sigv4.Header{
            .{ .name = "content-type", .value = CONTENT_TYPE },
            .{ .name = "x-amz-target", .value = TARGET },
        };
        const signed = aws_sigv4.sign(arena_alloc, .{
            .creds = self.creds,
            .service = SERVICE,
            .method = "POST",
            .host = host,
            .extra_signed = &extra,
            .body = body,
            .now_unix_seconds = @divFloor(clock.nowMs(), std.time.ms_per_s),
        }) catch |err| {
            log.err("[SSM_SIGN_FAIL] sigv4 signing failed: {}", .{err});
            return error.Io;
        };

        // Build header set for the http request. Order doesn't matter
        // (the signer already determined SignedHeaders); the http
        // client will send all of them.
        var headers: std.ArrayList(std.http.Header) = .empty;
        try headers.appendSlice(arena_alloc, &.{
            .{ .name = "content-type", .value = CONTENT_TYPE },
            .{ .name = "x-amz-target", .value = TARGET },
            .{ .name = "x-amz-date", .value = signed.amz_date },
            .{ .name = "x-amz-content-sha256", .value = signed.amz_content_sha256 },
            .{ .name = "authorization", .value = signed.authorization },
        });
        if (signed.amz_security_token) |tok| {
            try headers.append(arena_alloc, .{ .name = "x-amz-security-token", .value = tok });
        }

        const uri = std.Uri.parse(url) catch return error.Io;
        var http_req = self.http.request(.POST, uri, .{
            .extra_headers = headers.items,
        }) catch |err| {
            log.err("[SSM_CONNECT_FAIL] connecting to {s}: {}", .{ host, err });
            return error.Io;
        };
        defer http_req.deinit();

        http_req.transfer_encoding = .{ .content_length = body.len };
        var body_writer = http_req.sendBody(&.{}) catch return error.Io;
        body_writer.writer.writeAll(body) catch return error.Io;
        body_writer.end() catch return error.Io;
        http_req.connection.?.flush() catch return error.Io;

        var redirect_buffer: [8 * 1024]u8 = undefined;
        var response = http_req.receiveHead(&redirect_buffer) catch return error.Io;

        const status = response.head.status;
        // SSM returns `Content-Encoding: gzip` for AWS JSON-1.1 responses;
        // use the decompressing reader so the JSON body comes through
        // already inflated. Same pattern as z3's `executeRequest`.
        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        var decompress_buffer: [std.compress.flate.max_window_len]u8 = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, &decompress_buffer);
        const resp_body = reader.allocRemaining(arena_alloc, .limited(MAX_BODY_PER_PAGE)) catch
            return error.Io;

        if (status != .ok) {
            const preview_len = @min(resp_body.len, 512);
            log.err(
                "[SSM_HTTP_FAIL] status={d} body={s}",
                .{ @intFromEnum(status), resp_body[0..preview_len] },
            );
            return mapStatus(status);
        }

        return parseResponse(arena_alloc, resp_body) catch |err| {
            log.err("[SSM_PARSE_FAIL] {}: body_preview={s}", .{
                err,
                resp_body[0..@min(resp_body.len, 256)],
            });
            return error.Io;
        };
    }
};

fn mapStatus(s: std.http.Status) Error {
    return switch (@intFromEnum(s)) {
        400 => error.InvalidArgument,
        401, 403 => error.Unauthorized,
        429, 503 => error.Throttled,
        else => error.Io,
    };
}

/// Build the JSON request body for `GetParametersByPath`.
/// Shape: {"Path":"...","Recursive":true,"WithDecryption":true,"MaxResults":10[,"NextToken":"..."]}
fn buildRequestBody(
    allocator: std.mem.Allocator,
    path: []const u8,
    with_decryption: bool,
    next_token: ?[]const u8,
) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"Path\":\"");
    try appendJsonEscaped(&buf, allocator, path);
    try buf.appendSlice(allocator, "\",\"Recursive\":true,\"WithDecryption\":");
    try buf.appendSlice(allocator, if (with_decryption) "true" else "false");
    try buf.appendSlice(allocator, ",\"MaxResults\":10");
    if (next_token) |tok| {
        try buf.appendSlice(allocator, ",\"NextToken\":\"");
        try appendJsonEscaped(&buf, allocator, tok);
        try buf.append(allocator, '"');
    }
    try buf.append(allocator, '}');
    return buf.toOwnedSlice(allocator);
}

fn appendJsonEscaped(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) Error!void {
    for (s) |c| switch (c) {
        '"' => try buf.appendSlice(allocator, "\\\""),
        '\\' => try buf.appendSlice(allocator, "\\\\"),
        0x00...0x1f => {
            // \uXXXX form covers \n, \r, \t and friends in one branch.
            // SSM paths shouldn't contain control chars, but escape
            // defensively rather than emit invalid JSON.
            var hex_buf: [6]u8 = undefined;
            const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{c}) catch unreachable;
            try buf.appendSlice(allocator, hex);
        },
        else => try buf.append(allocator, c),
    };
}

const RawParameter = struct {
    Name: []const u8,
    Type: []const u8,
    Value: []const u8,
};

const RawResponse = struct {
    Parameters: []RawParameter,
    NextToken: ?[]const u8 = null,
};

fn parseResponse(arena_alloc: std.mem.Allocator, body: []const u8) !SsmClient.Page {
    const parsed = try std.json.parseFromSliceLeaky(
        RawResponse,
        arena_alloc,
        body,
        .{ .ignore_unknown_fields = true },
    );

    var out = try arena_alloc.alloc(Parameter, parsed.Parameters.len);
    for (parsed.Parameters, 0..) |raw, i| {
        out[i] = .{
            .name = raw.Name,
            .value = raw.Value,
            .type = parseParamType(raw.Type),
        };
    }
    return .{
        .parameters = out,
        .next_token = parsed.NextToken,
    };
}

fn parseParamType(s: []const u8) ParamType {
    if (std.mem.eql(u8, s, "SecureString")) return .SecureString;
    if (std.mem.eql(u8, s, "StringList")) return .StringList;
    return .String;
}

// ============================================================
// Tests - pure-function tests only; the integration test
// (docker/integration_test.sh run_ssm) covers the live AWS path.
// ============================================================

test "buildRequestBody: minimal" {
    const body = try buildRequestBody(std.testing.allocator, "/config/svc/env/", true, null);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "{\"Path\":\"/config/svc/env/\",\"Recursive\":true,\"WithDecryption\":true,\"MaxResults\":10}",
        body,
    );
}

test "buildRequestBody: with NextToken" {
    const body = try buildRequestBody(std.testing.allocator, "/p/", false, "abc123");
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "{\"Path\":\"/p/\",\"Recursive\":true,\"WithDecryption\":false,\"MaxResults\":10,\"NextToken\":\"abc123\"}",
        body,
    );
}

test "buildRequestBody: escapes quotes in path" {
    const body = try buildRequestBody(std.testing.allocator, "/a\"b/", true, null);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "{\"Path\":\"/a\\\"b/\",\"Recursive\":true,\"WithDecryption\":true,\"MaxResults\":10}",
        body,
    );
}

test "parseResponse: single page, mixed types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const body =
        \\{"Parameters":[
        \\  {"Name":"/p/host","Type":"String","Value":"db.example","Version":1,"ARN":"arn:..."},
        \\  {"Name":"/p/password","Type":"SecureString","Value":"hunter2"}
        \\]}
    ;
    const page = try parseResponse(arena.allocator(), body);
    try std.testing.expectEqual(@as(usize, 2), page.parameters.len);
    try std.testing.expect(page.next_token == null);
    try std.testing.expectEqualStrings("/p/host", page.parameters[0].name);
    try std.testing.expectEqual(ParamType.String, page.parameters[0].type);
    try std.testing.expectEqualStrings("hunter2", page.parameters[1].value);
    try std.testing.expectEqual(ParamType.SecureString, page.parameters[1].type);
}

test "parseResponse: paginated with NextToken" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const body =
        \\{"Parameters":[{"Name":"/p/x","Type":"String","Value":"v"}],"NextToken":"page2"}
    ;
    const page = try parseResponse(arena.allocator(), body);
    try std.testing.expectEqual(@as(usize, 1), page.parameters.len);
    try std.testing.expectEqualStrings("page2", page.next_token.?);
}

test "ParamSet.findBySuffix: matches the leaf, even with deep prefix" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const params = try arena.allocator().alloc(Parameter, 2);
    params[0] = .{ .name = "/config/svc/env/db/host", .value = "h", .type = .String };
    params[1] = .{ .name = "/config/svc/env/db/password", .value = "p", .type = .SecureString };

    const set: ParamSet = .{ .parameters = params, .arena = .init(std.testing.allocator) };
    // Note: we constructed set.arena separately so we can avoid double-free
    // here. Real ParamSets always own their arena.
    var s = set;
    defer s.arena.deinit();

    try std.testing.expectEqualStrings("h", set.findBySuffix("/db/host").?.value);
    try std.testing.expectEqualStrings("p", set.findBySuffix("/db/password").?.value);
    try std.testing.expect(set.findBySuffix("/missing") == null);
}

test "mapStatus: 401/403 → Unauthorized; 429/503 → Throttled" {
    try std.testing.expectError(error.Unauthorized, blk: {
        const e: Error = mapStatus(@enumFromInt(403));
        break :blk @as(Error!void, e);
    });
    try std.testing.expectError(error.Throttled, blk: {
        const e: Error = mapStatus(@enumFromInt(429));
        break :blk @as(Error!void, e);
    });
    try std.testing.expectError(error.InvalidArgument, blk: {
        const e: Error = mapStatus(@enumFromInt(400));
        break :blk @as(Error!void, e);
    });
    try std.testing.expectError(error.Io, blk: {
        const e: Error = mapStatus(@enumFromInt(500));
        break :blk @as(Error!void, e);
    });
}
