const std = @import("std");

pub fn build(b: *std.Build) void {
    const obj = b.add_object(.{
        .name = "base64",
        .root_source_file = b.path("base64.zig"),
    });

    const exe = b.add_executable(.{
        .name = "test",
    });
    exe.add_csource_file(.{ .file = b.path("test.c"), .flags = &.{"-std=c99"} });
    exe.add_object(obj);
    exe.link_system_library("c");
    b.install_artifact(exe);
}

// syntax
