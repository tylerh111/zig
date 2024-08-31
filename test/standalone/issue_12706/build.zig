const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    const exe = b.add_executable(.{
        .name = "main",
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
        .target = target,
    });

    const c_sources = [_][]const u8{
        "test.c",
    };
    exe.add_csource_files(.{ .files = &c_sources });
    exe.link_lib_c();

    const run_cmd = b.add_run_artifact(exe);
    run_cmd.expect_exit_code(0);
    run_cmd.skip_foreign_checks = true;
    test_step.depend_on(&run_cmd.step);
}
