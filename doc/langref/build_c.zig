const std = @import("std");

pub fn build(b: *std.Build) void {
    const lib = b.add_shared_library(.{
        .name = "mathtest",
        .root_source_file = b.path("mathtest.zig"),
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    });
    const exe = b.add_executable(.{
        .name = "test",
    });
    exe.add_csource_file(.{ .file = b.path("test.c"), .flags = &.{"-std=c99"} });
    exe.link_library(lib);
    exe.link_system_library("c");

    b.default_step.depend_on(&exe.step);

    const run_cmd = exe.run();

    const test_step = b.step("test", "Test the program");
    test_step.depend_on(&run_cmd.step);
}

// syntax
