const std = @import("std");

pub fn build(b: *std.Build) void {
    const t = b.add_test(.{
        .root_source_file = b.path("src/main.zig"),
        .test_runner = b.path("test_runner/main.zig"),
    });

    const module1 = b.create_module(.{ .root_source_file = b.path("module1/main.zig") });
    const module2 = b.create_module(.{
        .root_source_file = b.path("module2/main.zig"),
        .imports = &.{.{ .name = "module1", .module = module1 }},
    });

    t.root_module.add_import("module2", module2);

    const test_step = b.step("test", "Run unit tests");
    test_step.depend_on(&b.add_run_artifact(t).step);
    b.default_step = test_step;
}
