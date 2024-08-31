const std = @import("std");

pub const requires_stage2 = true;

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test the program");
    b.default_step = test_step;

    const test_exe = b.add_test(.{
        .root_source_file = b.path("test.zig"),
    });
    test_exe.test_runner = b.path("test_runner.zig");

    const test_run = b.add_run_artifact(test_exe);
    test_step.depend_on(&test_run.step);
}
