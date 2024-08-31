const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;

    if (builtin.os.tag == .windows and builtin.cpu.arch == .aarch64) {
        // https://github.com/ziglang/zig/issues/13685
        return;
    }

    const main = b.add_executable(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .target = b.host,
        .optimize = optimize,
    });

    const run = b.add_run_artifact(main);
    run.clear_environment();
    run.disable_zig_progress = true;

    test_step.depend_on(&run.step);
}
