const std = @import("std");

pub fn build(b: *std.Build) void {
    const test_step = b.step("test", "Test it");
    b.default_step = test_step;

    const test1 = b.add_test(.{
        .root_source_file = b.path("test_root/empty.zig"),
        .test_runner = "src/main.zig",
    });
    const test2 = b.add_test(.{
        .root_source_file = b.path("src/empty.zig"),
        .test_runner = "src/main.zig",
    });
    const test3 = b.add_test(.{
        .root_source_file = b.path("empty.zig"),
        .test_runner = "src/main.zig",
    });

    test_step.depend_on(&b.add_run_artifact(test1).step);
    test_step.depend_on(&b.add_run_artifact(test2).step);
    test_step.depend_on(&b.add_run_artifact(test3).step);
}
