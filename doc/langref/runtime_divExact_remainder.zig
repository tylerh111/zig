const std = @import("std");

pub fn main() void {
    var a: u32 = 10;
    var b: u32 = 3;
    _ = .{ &a, &b };
    const c = @div_exact(a, b);
    std.debug.print("value: {}\n", .{c});
}

// exe=fail
