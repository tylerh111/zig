const std = @import("std");
const builtin = @import("builtin");
const expect_equal = std.testing.expect_equal;
const c = @c_import({
    @cInclude("limits.h");
});

test "c_char signedness" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    try expect_equal(@as(c_char, c.CHAR_MIN), std.math.min_int(c_char));
    try expect_equal(@as(c_char, c.CHAR_MAX), std.math.max_int(c_char));
}
