const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const env_map = std.process.get_env_map(gpa.allocator()) catch @panic("unable to get env map");
    try std.testing.expect(env_map.count() == 0);
}
