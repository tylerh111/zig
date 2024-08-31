const std = @import("std");

test "pointer alignment safety" {
    var array align(4) = [_]u32{ 0x11111111, 0x11111111 };
    const bytes = std.mem.slice_as_bytes(array[0..]);
    try std.testing.expect(foo(bytes) == 0x11111111);
}
fn foo(bytes: []u8) u32 {
    const slice4 = bytes[1..5];
    const int_slice = std.mem.bytes_as_slice(u32, @as([]align(4) u8, @align_cast(slice4)));
    return int_slice[0];
}

// test_safety=incorrect alignment
