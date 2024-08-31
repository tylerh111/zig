const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    if (builtin.os.tag != .windows) return;

    const hello = b.add_executable(.{
        .name = "hello",
        .root_source_file = b.path("hello.zig"),
        .optimize = optimize,
        .target = target,
    });

    const main = b.add_executable(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = target,
    });

    const run = b.add_run_artifact(main);
    run.add_artifact_arg(hello);
    run.expect_exit_code(0);
    run.skip_foreign_checks = true;

    test_step.depend_on(&run.step);
}
