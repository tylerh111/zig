comptime {
    @export(internal_name, .{ .name = "foo", .linkage = .strong });
}

fn internal_name() callconv(.C) void {}

// obj
