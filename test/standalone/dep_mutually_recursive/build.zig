const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const optimize: std.builtin.OptimizeMode = .Debug;

    const foo = b.create_module(.{
        .root_source_file = b.path("foo.zig"),
    });
    const bar = b.create_module(.{
        .root_source_file = b.path("bar.zig"),
    });
    foo.add_import("bar", bar);
    bar.add_import("foo", foo);

    const exe = b.add_executable(.{
        .name = "test",
        .root_source_file = b.path("test.zig"),
        .target = b.host,
        .optimize = optimize,
    });
    exe.root_module.add_import("foo", foo);

    const run = b.add_run_artifact(exe);
    test_step.depend_on(&run.step);
}
