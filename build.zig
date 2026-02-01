//! Build Configuration for MySQL Binlog Connector
//!
//! This build script configures:
//! - Native Zig MySQL client (absorbed from myzql)
//! - Static linking for single-binary distribution
//! - Cross-compilation support
//!
//! Usage:
//!   zig build                              # Build for native target
//!   zig build run -- config.json           # Build and run
//!   zig build -Dtarget=aarch64-linux-gnu   # Cross-compile for aarch64 Linux
//!   zig build -Doptimize=ReleaseFast       # Optimized build

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Target configuration
    const target = b.standardTargetOptions(.{});

    // Optimization level
    const optimize = b.standardOptimizeOption(.{});

    // Create library module (optional - for reuse in other Zig projects)
    const mod = b.addModule("myzql_binlog_connector", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // === EXECUTABLE DEFINITION ===
    const exe = b.addExecutable(.{
        .name = "myzql_binlog_connector",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "myzql_binlog_connector", .module = mod },
            },
        }),
    });

    // === INSTALLATION ===
    // Install the executable to zig-out/bin/
    b.installArtifact(exe);

    // === RUN STEP ===
    // `zig build run -- config.json`
    const run_step = b.step("run", "Run the binlog connector");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    // Allow passing arguments: `zig build run -- config.json`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // === TESTING ===
    // Test the library module
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Test the executable module
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    // `zig build test` runs all tests
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
