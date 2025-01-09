const std = @import("std");
const builtin = @import("builtin");
const expectEqual = std.testing.expectEqual;
const c = @cimport({
    @cinclude("limits.h");
});

test "c_char signedness" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    try expectEqual(@as(c_char, c.CHAR_MIN), std.math.minInt(c_char));
    try expectEqual(@as(c_char, c.CHAR_MAX), std.math.maxInt(c_char));
}
