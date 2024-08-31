const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test");
    b.default_step = test_step;

    const exe = b.add_executable(.{
        .name = "bss",
        .root_source_file = b.path("main.zig"),
        .target = b.host,
        .optimize = .Debug,
    });

    const run = b.add_run_artifact(exe);
    run.expect_std_out_equal("0, 1, 0\n");

    test_step.depend_on(&run.step);
}
