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

    // Link libc only on platforms that require it (macOS has no stable syscall ABI).
    // On Linux, we use direct syscalls via std.os.linux - no libc needed.
    const needs_libc = target.result.os.tag.isDarwin();

    // === LAMBDA BUILD SWITCH ===
    // `-Dlambda=true` adds the `bootstrap` exe target (the AWS Lambda
    // handler binary). Off by default - local builds don't compile
    // aws-lambda-zig source unless explicitly requested.
    //
    // For deploy: `zig build -Dlambda=true -Dtarget=aarch64-linux-gnu \
    //              -Doptimize=ReleaseSafe`
    // Output: `zig-out/bin/bootstrap` (Lambda's `provided.al2023`
    //         runtime requires the binary at zip root named `bootstrap`).
    const build_lambda = b.option(
        bool,
        "lambda",
        "Build the Lambda bootstrap exe (default: false)",
    ) orelse false;

    // === SQL PARSER DEPENDENCY ===
    const myzqlparser_dep = b.dependency("myzqlparser", .{ .target = target });
    const myzqlparser_mod = myzqlparser_dep.module("myzqlparser");

    // === TLS DEPENDENCY (ianic/tls.zig) ===
    // Replaces the previous std.crypto.tls + local CertificateRequest patch
    // with a maintained external implementation that handles TLS 1.3
    // CertificateRequest → empty Certificate response natively.
    const tls_dep = b.dependency("tls", .{ .target = target, .optimize = optimize });
    const tls_mod = tls_dep.module("tls");

    // === S3 DEPENDENCY (codeberg.org/fellowtraveler/z3) ===
    // Async S3 client built on std.http.Client + std.Io.
    const z3_dep = b.dependency("z3", .{ .target = target, .optimize = optimize });
    const z3_mod = z3_dep.module("s3");

    // === LAMBDA RUNTIME DEPENDENCY (github.com/by-nir/aws-lambda-zig) ===
    // Pinned via `zig fetch --save` at d9167a4 (= upstream tip "Release 0.5.0").
    // Module name "lambda" once consumed.
    //
    // Declared here so build.zig and build.zig.zon stay in sync; not yet
    // wired into any target's imports - that happens in the
    // `-Dlambda=true bootstrap exe` step.
    // Until then, `zig build` doesn't compile aws-lambda-zig source.

    // Create library module (optional - for reuse in other Zig projects)
    const mod = b.addModule("myzql_binlog_connector", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = needs_libc,
        .imports = &.{
            .{ .name = "myzqlparser", .module = myzqlparser_mod },
            .{ .name = "tls", .module = tls_mod },
            .{ .name = "s3", .module = z3_mod },
        },
    });

    // === EXECUTABLE DEFINITION ===
    const exe = b.addExecutable(.{
        .name = "myzql_binlog_connector",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{
                .{ .name = "myzql_binlog_connector", .module = mod },
                .{ .name = "myzqlparser", .module = myzqlparser_mod },
                .{ .name = "tls", .module = tls_mod },
                .{ .name = "s3", .module = z3_mod },
            },
        }),
    });

    // === INSTALLATION ===
    // Install the executable to zig-out/bin/
    b.installArtifact(exe);

    // === SSM SMOKE BINARY ===
    // Tiny exe that calls getParametersByPath and prints results
    // used by docker/integration_test.sh's `run_ssm` step.
    // Lives here so `zig build` produces both `myzql_binlog_connector` and `ssm_smoke` side-by-side
    // without needing a separate `zig build ssm-smoke` invocation.
    const ssm_smoke = b.addExecutable(.{
        .name = "ssm_smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ssm_smoke.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{
                .{ .name = "myzql_binlog_connector", .module = mod },
                .{ .name = "tls", .module = tls_mod },
            },
        }),
    });
    b.installArtifact(ssm_smoke);

    // === LAMBDA BOOTSTRAP EXE (gated on -Dlambda=true) ===
    // Built when `-Dlambda=true` is set. Pull in aws-lambda-zig
    // here (rather than at the top-level dep block) so the default
    // build doesn't compile its source.
    //
    // Cross-compile invocation:
    //   zig build -Dlambda=true -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseSafe
    //
    // The binary MUST be named `bootstrap` for Lambda's
    // `provided.al2023` runtime - that's the entry-point convention
    // for OS-only / custom runtimes.
    if (build_lambda) {
        // aws-lambda-zig's build.zig has multiple `addModule("lambda", ...)`
        // calls - passing `.optimize` as a dep arg trips it up
        // ("invalid option: -Doptimize" from the dep's option-table
        // validation). Pass target only; optimize gets inherited via
        // the parent build's compile flags.
        const aws_lambda_dep = b.dependency("aws_lambda", .{
            .target = target,
        });
        const lambda_mod = aws_lambda_dep.module("lambda");

        const bootstrap = b.addExecutable(.{
            .name = "bootstrap",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/lambda_handler.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = needs_libc,
                .imports = &.{
                    .{ .name = "myzql_binlog_connector", .module = mod },
                    .{ .name = "myzqlparser", .module = myzqlparser_mod },
                    .{ .name = "tls", .module = tls_mod },
                    .{ .name = "s3", .module = z3_mod },
                    .{ .name = "lambda", .module = lambda_mod },
                },
            }),
        });
        b.installArtifact(bootstrap);

        // === LAMBDA-ZIP STEP ===
        // `zig build lambda-zip` → `zig-out/lambda.zip` ready for
        // `aws lambda update-function-code --zip-file fileb://...`.
        // Uses `-j` (junk paths) so `bootstrap` lands at the zip root,
        // not under `bin/` - Lambda's runtime looks for it there.
        const zip_cmd = b.addSystemCommand(&.{
            "zip", "-q", "-j",
        });
        zip_cmd.addFileArg(b.path("zig-out/lambda.zip"));
        zip_cmd.addArtifactArg(bootstrap);
        zip_cmd.step.dependOn(b.getInstallStep());

        const zip_step = b.step("lambda-zip", "Package the bootstrap exe into zig-out/lambda.zip for AWS Lambda deploy");
        zip_step.dependOn(&zip_cmd.step);
    }

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

    // === INTEGRATION TEST ===
    // `zig build integration-test` boots the docker MySQL container,
    // runs a scripted DDL/DML scenario, exercises the connector end-to-
    // end, and asserts on column-name resolution, ENUM labels, and
    // schema-cache persistence. Requires Docker to be available on the
    // host. Skipped silently in environments without docker.
    const integration_cmd = b.addSystemCommand(&.{"./docker/integration_test.sh"});
    integration_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| integration_cmd.addArgs(args); // e.g. --keep
    const integration_step = b.step("integration-test", "Run docker-based end-to-end integration test");
    integration_step.dependOn(&integration_cmd.step);
}
