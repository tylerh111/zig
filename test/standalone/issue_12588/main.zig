const std = @import("std");

export fn str_from_float_help(float: f64) void {
    var buf: [400]u8 = undefined;
    _ = std.fmt.buf_print(&buf, "{d}", .{float}) catch unreachable;
}
