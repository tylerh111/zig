comptime {
    @export(internalName, .{ .name = "foo", .linkage = .strong });
}

fn internal_name() callconv(.C) void {}

// obj
