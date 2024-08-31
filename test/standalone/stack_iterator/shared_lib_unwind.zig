const std = @import("std");
const builtin = @import("builtin");
const debug = std.debug;
const testing = std.testing;

noinline fn frame4(expected: *[5]usize, unwound: *[5]usize) void {
    expected[0] = @returnAddress();

    var context: debug.ThreadContext = undefined;
    testing.expect(debug.get_context(&context)) catch @panic("failed to get_context");

    const debug_info = debug.get_self_debug_info() catch @panic("failed to open_self_debug_info");
    var it = debug.StackIterator.init_with_context(expected[0], debug_info, &context) catch @panic("failed to init_with_context");
    defer it.deinit();

    for (unwound) |*addr| {
        if (it.next()) |return_address| addr.* = return_address;
    }
}

noinline fn frame3(expected: *[5]usize, unwound: *[5]usize) void {
    expected[1] = @returnAddress();
    frame4(expected, unwound);
}

fn frame2(expected: *[5]usize, unwound: *[5]usize) callconv(.C) void {
    expected[2] = @returnAddress();
    frame3(expected, unwound);
}

extern fn frame0(
    expected: *[5]usize,
    unwound: *[5]usize,
    frame_2: *const fn (expected: *[5]usize, unwound: *[5]usize) callconv(.C) void,
) void;

pub fn main() !void {
    // Disabled until the DWARF unwinder bugs on .aarch64 are solved
    if (builtin.omit_frame_pointer and comptime builtin.target.is_darwin() and builtin.cpu.arch == .aarch64) return;

    if (!std.debug.have_ucontext or !std.debug.have_getcontext) return;

    var expected: [5]usize = undefined;
    var unwound: [5]usize = undefined;
    frame0(&expected, &unwound, &frame2);
    try testing.expect_equal(expected, unwound);
}
