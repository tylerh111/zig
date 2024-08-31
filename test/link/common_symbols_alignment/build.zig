const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    add(b, test_step, .Debug);
    add(b, test_step, .ReleaseFast);
    add(b, test_step, .ReleaseSmall);
    add(b, test_step, .ReleaseSafe);
}

fn add(b: *std.Build, test_step: *std.Build.Step, optimize: std.builtin.OptimizeMode) void {
    const lib_a = b.add_static_library(.{
        .name = "a",
        .optimize = optimize,
        .target = b.host,
    });
    lib_a.add_csource_files(.{
        .files = &.{"a.c"},
        .flags = &.{"-fcommon"},
    });

    const test_exe = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
    });
    test_exe.link_library(lib_a);

    test_step.depend_on(&b.add_run_artifact(test_exe).step);
}
