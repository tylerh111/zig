const std = @import("std");

extern const foo: u32;

pub fn main() void {
    const std_out = std.io.get_std_out();
    std_out.writer().print("Result: {d}", .{foo}) catch {};
}
