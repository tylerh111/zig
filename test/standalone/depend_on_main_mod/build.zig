const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const target = b.standard_target_options(.{});
    const optimize = b.standard_optimize_option(.{});

    const exe = b.add_executable(.{
        .name = "depend_on_main_mod",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const foo_module = b.add_module("foo", .{
        .root_source_file = b.path("src/foo.zig"),
    });

    foo_module.add_import("root2", &exe.root_module);
    exe.root_module.add_import("foo", foo_module);

    const run_cmd = b.add_run_artifact(exe);
    run_cmd.expect_exit_code(0);

    test_step.depend_on(&run_cmd.step);
}
