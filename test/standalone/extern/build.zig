const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize: std.builtin.OptimizeMode = .Debug;

    const obj = b.add_object(.{
        .name = "exports",
        .root_source_file = b.path("exports.zig"),
        .target = b.host,
        .optimize = optimize,
    });
    const main = b.add_test(.{
        .root_source_file = b.path("main.zig"),
        .optimize = optimize,
    });
    main.add_object(obj);

    const test_step = b.step("test", "Test it");
    test_step.depend_on(&main.step);
}
