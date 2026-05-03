//! MySQL Binlog Connector - Library Root (Optional)
//!
//! This file exists to satisfy the build.zig module structure.
//! Since this project is primarily an executable application,
//! we keep this minimal. If you want to use this as a library
//! in other Zig projects, you can export public APIs here.

const std = @import("std");

// Re-export modules that might be useful as a library
pub const schema_cache = @import("schema_cache.zig");
pub const ddl_handler = @import("ddl_handler.zig");
pub const cache_persistence = @import("cache_persistence.zig");
pub const prereq_check = @import("prereq_check.zig");
pub const object_store = @import("object_store.zig");
pub const state = @import("state.zig");
pub const config = @import("config.zig");
pub const aws_creds = @import("aws_creds.zig");
pub const aws_sigv4 = @import("aws_sigv4.zig");
pub const clock = @import("clock.zig");
pub const log_config = @import("log_config.zig");
pub const s3_store = @import("s3_store.zig");
pub const ssm_client = @import("ssm_client.zig");
pub const row_json_serializer = @import("row_json_serializer.zig");

test "root module" {
    // Placeholder test
    try std.testing.expect(true);
}

// Pull in tests from submodules
comptime {
    _ = schema_cache;
    _ = ddl_handler;
    _ = cache_persistence;
    _ = prereq_check;
    _ = object_store;
    _ = state;
    _ = config;
    _ = aws_creds;
    _ = aws_sigv4;
    _ = clock;
    _ = log_config;
    _ = s3_store;
    _ = ssm_client;
    _ = row_json_serializer;
}
