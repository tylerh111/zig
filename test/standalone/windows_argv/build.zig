const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    if (builtin.os.tag != .windows) return;

    const optimize: std.builtin.OptimizeMode = .Debug;

    const lib_gnu = b.add_static_library(.{
        .name = "toargv-gnu",
        .root_source_file = b.path("lib.zig"),
        .target = b.resolve_target_query(.{
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    const verify_gnu = b.add_executable(.{
        .name = "verify-gnu",
        .target = b.resolve_target_query(.{
            .abi = .gnu,
        }),
        .optimize = optimize,
    });
    verify_gnu.add_csource_file(.{
        .file = b.path("verify.c"),
        .flags = &.{ "-DUNICODE", "-D_UNICODE" },
    });
    verify_gnu.mingw_unicode_entry_point = true;
    verify_gnu.link_library(lib_gnu);
    verify_gnu.link_lib_c();

    const fuzz = b.add_executable(.{
        .name = "fuzz",
        .root_source_file = b.path("fuzz.zig"),
        .target = b.host,
        .optimize = optimize,
    });

    const fuzz_max_iterations = b.option(u64, "iterations", "The max fuzz iterations (default: 100)") orelse 100;
    const fuzz_iterations_arg = std.fmt.alloc_print(b.allocator, "{}", .{fuzz_max_iterations}) catch @panic("oom");

    const fuzz_seed = b.option(u64, "seed", "Seed to use for the PRNG (default: random)") orelse seed: {
        var buf: [8]u8 = undefined;
        try std.posix.getrandom(&buf);
        break :seed std.mem.read_int(u64, &buf, builtin.cpu.arch.endian());
    };
    const fuzz_seed_arg = std.fmt.alloc_print(b.allocator, "{}", .{fuzz_seed}) catch @panic("oom");

    const run_gnu = b.add_run_artifact(fuzz);
    run_gnu.set_name("fuzz-gnu");
    run_gnu.add_artifact_arg(verify_gnu);
    run_gnu.add_args(&.{ fuzz_iterations_arg, fuzz_seed_arg });
    run_gnu.expect_exit_code(0);

    test_step.depend_on(&run_gnu.step);

    // Only target the MSVC ABI if MSVC/Windows SDK is available
    const has_msvc = has_msvc: {
        const sdk = std.zig.WindowsSdk.find(b.allocator) catch |err| switch (err) {
            error.OutOfMemory => @panic("oom"),
            else => break :has_msvc false,
        };
        defer sdk.free(b.allocator);
        break :has_msvc true;
    };
    if (has_msvc) {
        const lib_msvc = b.add_static_library(.{
            .name = "toargv-msvc",
            .root_source_file = b.path("lib.zig"),
            .target = b.resolve_target_query(.{
                .abi = .msvc,
            }),
            .optimize = optimize,
        });
        const verify_msvc = b.add_executable(.{
            .name = "verify-msvc",
            .target = b.resolve_target_query(.{
                .abi = .msvc,
            }),
            .optimize = optimize,
        });
        verify_msvc.add_csource_file(.{
            .file = b.path("verify.c"),
            .flags = &.{ "-DUNICODE", "-D_UNICODE" },
        });
        verify_msvc.link_library(lib_msvc);
        verify_msvc.link_lib_c();

        const run_msvc = b.add_run_artifact(fuzz);
        run_msvc.set_name("fuzz-msvc");
        run_msvc.add_artifact_arg(verify_msvc);
        run_msvc.add_args(&.{ fuzz_iterations_arg, fuzz_seed_arg });
        run_msvc.expect_exit_code(0);

        test_step.depend_on(&run_msvc.step);
    }
}
