const std = @import("std");

pub fn main() void {
    const Foo = struct {};
    std.debug.print("variable: {s}\n", .{@type_name(Foo)});
    std.debug.print("anonymous: {s}\n", .{@type_name(struct {})});
    std.debug.print("function: {s}\n", .{@type_name(List(i32))});
}

fn List(comptime T: type) type {
    return struct {
        x: T,
    };
}

// exe=succeed
