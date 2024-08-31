const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    if (builtin.os.tag != .windows) return;

    const echo_args = b.add_executable(.{
        .name = "echo-args",
        .root_source_file = b.path("echo-args.zig"),
        .optimize = optimize,
        .target = target,
    });

    const test_exe = b.add_executable(.{
        .name = "test",
        .root_source_file = b.path("test.zig"),
        .optimize = optimize,
        .target = target,
    });

    const run = b.add_run_artifact(test_exe);
    run.add_artifact_arg(echo_args);
    run.expect_exit_code(0);
    run.skip_foreign_checks = true;

    test_step.depend_on(&run.step);

    const fuzz = b.add_executable(.{
        .name = "fuzz",
        .root_source_file = b.path("fuzz.zig"),
        .optimize = optimize,
        .target = target,
    });

    const fuzz_max_iterations = b.option(u64, "iterations", "The max fuzz iterations (default: 100)") orelse 100;
    const fuzz_iterations_arg = std.fmt.alloc_print(b.allocator, "{}", .{fuzz_max_iterations}) catch @panic("oom");

    const fuzz_seed = b.option(u64, "seed", "Seed to use for the PRNG (default: random)") orelse seed: {
        var buf: [8]u8 = undefined;
        try std.posix.getrandom(&buf);
        break :seed std.mem.read_int(u64, &buf, builtin.cpu.arch.endian());
    };
    const fuzz_seed_arg = std.fmt.alloc_print(b.allocator, "{}", .{fuzz_seed}) catch @panic("oom");

    const fuzz_run = b.add_run_artifact(fuzz);
    fuzz_run.add_artifact_arg(echo_args);
    fuzz_run.add_args(&.{ fuzz_iterations_arg, fuzz_seed_arg });
    fuzz_run.expect_exit_code(0);
    fuzz_run.skip_foreign_checks = true;

    test_step.depend_on(&fuzz_run.step);
}
