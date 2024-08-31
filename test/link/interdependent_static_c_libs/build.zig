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
    lib_a.add_csource_file(.{ .file = b.path("a.c"), .flags = &[_][]const u8{} });
    lib_a.add_include_path(b.path("."));

    const lib_b = b.add_static_library(.{
        .name = "b",
        .optimize = optimize,
        .target = b.host,
    });
    lib_b.add_csource_file(.{ .file = b.path("b.c"), .flags = &[_][]const u8{} });
    lib_b.add_include_path(b.path("."));

    const test_exe = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
    });
    test_exe.link_library(lib_a);
    test_exe.link_library(lib_b);
    test_exe.add_include_path(b.path("."));

    test_step.depend_on(&b.add_run_artifact(test_exe).step);
}
