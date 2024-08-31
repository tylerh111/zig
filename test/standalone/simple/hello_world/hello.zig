const std = @import("std");

pub fn main() !void {
    try std.io.get_std_out().write_all("Hello, World!\n");
}
