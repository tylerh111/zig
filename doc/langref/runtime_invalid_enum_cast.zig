const std = @import("std");

const Foo = enum {
    a,
    b,
    c,
};

pub fn main() void {
    var a: u2 = 3;
    _ = &a;
    const b: Foo = @enumfromint(a);
    std.debug.print("value: {s}\n", .{@tagname(b)});
}

// exe=fail
