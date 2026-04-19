//! MySQL Binlog Connector - Library Root (Optional)
//!
//! This file exists to satisfy the build.zig module structure.
//! Since this project is primarily an executable application,
//! we keep this minimal. If you want to use this as a library
//! in other Zig projects, you can export public APIs here.

const std = @import("std");

// Re-export modules that might be useful as a library
// NOTE: These will be uncommented as we implement each phase
// pub const config = @import("config.zig");
// pub const connection = @import("connection.zig");
// pub const binlog = @import("binlog_reader.zig");
pub const schema_cache = @import("schema_cache.zig");
pub const ddl_handler = @import("ddl_handler.zig");
pub const cache_persistence = @import("cache_persistence.zig");

test "root module" {
    // Placeholder test
    try std.testing.expect(true);
}

// Pull in tests from submodules
comptime {
    _ = schema_cache;
    _ = ddl_handler;
    _ = cache_persistence;
}
