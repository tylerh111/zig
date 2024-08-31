const std = @import("std");

pub fn main() !void {
    const stdout = std.io.get_std_out().writer();
    try stdout.write_all("hello from exe\n");
}
