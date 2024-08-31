const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test the program");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;
    const target = b.host;

    const obj1 = b.add_static_library(.{
        .name = "obj1",
        .root_source_file = b.path("obj1.zig"),
        .optimize = optimize,
        .target = target,
    });

    const obj2 = b.add_static_library(.{
        .name = "obj2",
        .root_source_file = b.path("obj2.zig"),
        .optimize = optimize,
        .target = target,
    });

    const main = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
    });
    main.link_library(obj1);
    main.link_library(obj2);

    test_step.depend_on(&b.add_run_artifact(main).step);
}
