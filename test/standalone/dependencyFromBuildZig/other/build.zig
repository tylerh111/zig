const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.add_module("add", .{
        .root_source_file = b.path("add.add.zig"),
    });
}
