const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    const obj = b.add_object(.{
        .name = "base64",
        .root_source_file = b.path("base64.zig"),
        .optimize = optimize,
        .target = target,
    });

    const exe = b.add_executable(.{
        .name = "test",
        .optimize = optimize,
        .target = target,
    });
    exe.add_csource_file(.{
        .file = b.path("test.c"),
        .flags = &[_][]const u8{"-std=c99"},
    });
    exe.add_object(obj);
    exe.link_system_library("c");

    b.default_step.depend_on(&exe.step);

    const run_cmd = b.add_run_artifact(exe);
    test_step.depend_on(&run_cmd.step);
}
