const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    if (@import("builtin").os.tag == .windows) {
        // https://github.com/ziglang/zig/issues/16959
        return;
    }

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;
    const lib = b.add_shared_library(.{
        .name = "mathtest",
        .root_source_file = b.path("mathtest.zig"),
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .target = target,
        .optimize = optimize,
    });

    const exe = b.add_executable(.{
        .name = "test",
        .target = target,
        .optimize = optimize,
    });
    exe.add_csource_file(.{
        .file = b.path("test.c"),
        .flags = &[_][]const u8{"-std=c99"},
    });
    exe.link_library(lib);
    exe.link_system_library("c");

    const run_cmd = b.add_run_artifact(exe);
    test_step.depend_on(&run_cmd.step);
}
