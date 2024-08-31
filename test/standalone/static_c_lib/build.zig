const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;

    const foo = b.add_static_library(.{
        .name = "foo",
        .optimize = optimize,
        .target = b.host,
    });
    foo.add_csource_file(.{ .file = b.path("foo.c"), .flags = &[_][]const u8{} });
    foo.add_include_path(b.path("."));

    const test_exe = b.add_test(.{
        .root_source_file = b.path("foo.zig"),
        .optimize = optimize,
    });
    test_exe.link_library(foo);
    test_exe.add_include_path(b.path("."));

    test_step.depend_on(&b.add_run_artifact(test_exe).step);
}
