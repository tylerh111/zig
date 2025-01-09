const std = @import("std");

pub fn main() void {
    const Foo = struct {};
    std.debug.print("variable: {s}\n", .{@typename(Foo)});
    std.debug.print("anonymous: {s}\n", .{@typename(struct {})});
    std.debug.print("function: {s}\n", .{@typename(List(i32))});
}

fn List(comptime T: type) type {
    return struct {
        x: T,
    };
}

// exe=succeed
