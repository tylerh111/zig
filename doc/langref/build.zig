const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standard_optimize_option(.{});
    const exe = b.add_executable(.{
        .name = "example",
        .root_source_file = b.path("example.zig"),
        .optimize = optimize,
    });
    b.default_step.depend_on(&exe.step);
}

// syntax
