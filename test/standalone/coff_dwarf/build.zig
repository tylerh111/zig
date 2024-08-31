const std = @import("std");
const builtin = @import("builtin");

/// This tests the path where DWARF information is embedded in a COFF binary
pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.standard_target_options(.{});

    if (builtin.os.tag != .windows) return;

    if (builtin.cpu.arch == .aarch64) {
        // https://github.com/ziglang/zig/issues/18427
        return;
    }

    const exe = b.add_executable(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = target,
    });

    const lib = b.add_shared_library(.{
        .name = "shared_lib",
        .optimize = optimize,
        .target = target,
    });
    lib.add_csource_file(.{ .file = b.path("shared_lib.c"), .flags = &.{"-gdwarf"} });
    lib.link_lib_c();
    exe.link_library(lib);

    const run = b.add_run_artifact(exe);
    run.expect_exit_code(0);
    run.skip_foreign_checks = true;

    test_step.depend_on(&run.step);
}
