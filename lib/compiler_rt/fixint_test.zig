const is_test = @import("builtin").is_test;
const std = @import("std");
const math = std.math;
const testing = std.testing;

const fixint = @import("fixint.zig").fixint;

fn test__fixint(comptime fp_t: type, comptime fixint_t: type, a: fp_t, expected: fixint_t) !void {
    const x = fixint(fp_t, fixint_t, a);
    try testing.expect(x == expected);
}

test "fixint.i1" {
    try test__fixint(f32, i1, -math.inf(f32), -1);
    try test__fixint(f32, i1, -math.float_max(f32), -1);
    try test__fixint(f32, i1, -2.0, -1);
    try test__fixint(f32, i1, -1.1, -1);
    try test__fixint(f32, i1, -1.0, -1);
    try test__fixint(f32, i1, -0.9, 0);
    try test__fixint(f32, i1, -0.1, 0);
    try test__fixint(f32, i1, -math.float_min(f32), 0);
    try test__fixint(f32, i1, -0.0, 0);
    try test__fixint(f32, i1, 0.0, 0);
    try test__fixint(f32, i1, math.float_min(f32), 0);
    try test__fixint(f32, i1, 0.1, 0);
    try test__fixint(f32, i1, 0.9, 0);
    try test__fixint(f32, i1, 1.0, 0);
    try test__fixint(f32, i1, 2.0, 0);
    try test__fixint(f32, i1, math.float_max(f32), 0);
    try test__fixint(f32, i1, math.inf(f32), 0);
}

test "fixint.i2" {
    try test__fixint(f32, i2, -math.inf(f32), -2);
    try test__fixint(f32, i2, -math.float_max(f32), -2);
    try test__fixint(f32, i2, -2.0, -2);
    try test__fixint(f32, i2, -1.9, -1);
    try test__fixint(f32, i2, -1.1, -1);
    try test__fixint(f32, i2, -1.0, -1);
    try test__fixint(f32, i2, -0.9, 0);
    try test__fixint(f32, i2, -0.1, 0);
    try test__fixint(f32, i2, -math.float_min(f32), 0);
    try test__fixint(f32, i2, -0.0, 0);
    try test__fixint(f32, i2, 0.0, 0);
    try test__fixint(f32, i2, math.float_min(f32), 0);
    try test__fixint(f32, i2, 0.1, 0);
    try test__fixint(f32, i2, 0.9, 0);
    try test__fixint(f32, i2, 1.0, 1);
    try test__fixint(f32, i2, 2.0, 1);
    try test__fixint(f32, i2, math.float_max(f32), 1);
    try test__fixint(f32, i2, math.inf(f32), 1);
}

test "fixint.i3" {
    try test__fixint(f32, i3, -math.inf(f32), -4);
    try test__fixint(f32, i3, -math.float_max(f32), -4);
    try test__fixint(f32, i3, -4.0, -4);
    try test__fixint(f32, i3, -3.0, -3);
    try test__fixint(f32, i3, -2.0, -2);
    try test__fixint(f32, i3, -1.9, -1);
    try test__fixint(f32, i3, -1.1, -1);
    try test__fixint(f32, i3, -1.0, -1);
    try test__fixint(f32, i3, -0.9, 0);
    try test__fixint(f32, i3, -0.1, 0);
    try test__fixint(f32, i3, -math.float_min(f32), 0);
    try test__fixint(f32, i3, -0.0, 0);
    try test__fixint(f32, i3, 0.0, 0);
    try test__fixint(f32, i3, math.float_min(f32), 0);
    try test__fixint(f32, i3, 0.1, 0);
    try test__fixint(f32, i3, 0.9, 0);
    try test__fixint(f32, i3, 1.0, 1);
    try test__fixint(f32, i3, 2.0, 2);
    try test__fixint(f32, i3, 3.0, 3);
    try test__fixint(f32, i3, 4.0, 3);
    try test__fixint(f32, i3, math.float_max(f32), 3);
    try test__fixint(f32, i3, math.inf(f32), 3);
}

test "fixint.i32" {
    try test__fixint(f64, i32, -math.inf(f64), math.min_int(i32));
    try test__fixint(f64, i32, -math.float_max(f64), math.min_int(i32));
    try test__fixint(f64, i32, @as(f64, math.min_int(i32)), math.min_int(i32));
    try test__fixint(f64, i32, @as(f64, math.min_int(i32)) + 1, math.min_int(i32) + 1);
    try test__fixint(f64, i32, -2.0, -2);
    try test__fixint(f64, i32, -1.9, -1);
    try test__fixint(f64, i32, -1.1, -1);
    try test__fixint(f64, i32, -1.0, -1);
    try test__fixint(f64, i32, -0.9, 0);
    try test__fixint(f64, i32, -0.1, 0);
    try test__fixint(f64, i32, -@as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i32, -0.0, 0);
    try test__fixint(f64, i32, 0.0, 0);
    try test__fixint(f64, i32, @as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i32, 0.1, 0);
    try test__fixint(f64, i32, 0.9, 0);
    try test__fixint(f64, i32, 1.0, 1);
    try test__fixint(f64, i32, @as(f64, math.max_int(i32)) - 1, math.max_int(i32) - 1);
    try test__fixint(f64, i32, @as(f64, math.max_int(i32)), math.max_int(i32));
    try test__fixint(f64, i32, math.float_max(f64), math.max_int(i32));
    try test__fixint(f64, i32, math.inf(f64), math.max_int(i32));
}

test "fixint.i64" {
    try test__fixint(f64, i64, -math.inf(f64), math.min_int(i64));
    try test__fixint(f64, i64, -math.float_max(f64), math.min_int(i64));
    try test__fixint(f64, i64, @as(f64, math.min_int(i64)), math.min_int(i64));
    try test__fixint(f64, i64, @as(f64, math.min_int(i64)) + 1, math.min_int(i64));
    try test__fixint(f64, i64, @as(f64, math.min_int(i64) / 2), math.min_int(i64) / 2);
    try test__fixint(f64, i64, -2.0, -2);
    try test__fixint(f64, i64, -1.9, -1);
    try test__fixint(f64, i64, -1.1, -1);
    try test__fixint(f64, i64, -1.0, -1);
    try test__fixint(f64, i64, -0.9, 0);
    try test__fixint(f64, i64, -0.1, 0);
    try test__fixint(f64, i64, -@as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i64, -0.0, 0);
    try test__fixint(f64, i64, 0.0, 0);
    try test__fixint(f64, i64, @as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i64, 0.1, 0);
    try test__fixint(f64, i64, 0.9, 0);
    try test__fixint(f64, i64, 1.0, 1);
    try test__fixint(f64, i64, @as(f64, math.max_int(i64)) - 1, math.max_int(i64));
    try test__fixint(f64, i64, @as(f64, math.max_int(i64)), math.max_int(i64));
    try test__fixint(f64, i64, math.float_max(f64), math.max_int(i64));
    try test__fixint(f64, i64, math.inf(f64), math.max_int(i64));
}

test "fixint.i128" {
    try test__fixint(f64, i128, -math.inf(f64), math.min_int(i128));
    try test__fixint(f64, i128, -math.float_max(f64), math.min_int(i128));
    try test__fixint(f64, i128, @as(f64, math.min_int(i128)), math.min_int(i128));
    try test__fixint(f64, i128, @as(f64, math.min_int(i128)) + 1, math.min_int(i128));
    try test__fixint(f64, i128, -2.0, -2);
    try test__fixint(f64, i128, -1.9, -1);
    try test__fixint(f64, i128, -1.1, -1);
    try test__fixint(f64, i128, -1.0, -1);
    try test__fixint(f64, i128, -0.9, 0);
    try test__fixint(f64, i128, -0.1, 0);
    try test__fixint(f64, i128, -@as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i128, -0.0, 0);
    try test__fixint(f64, i128, 0.0, 0);
    try test__fixint(f64, i128, @as(f64, math.float_min(f32)), 0);
    try test__fixint(f64, i128, 0.1, 0);
    try test__fixint(f64, i128, 0.9, 0);
    try test__fixint(f64, i128, 1.0, 1);
    try test__fixint(f64, i128, @as(f64, math.max_int(i128)) - 1, math.max_int(i128));
    try test__fixint(f64, i128, @as(f64, math.max_int(i128)), math.max_int(i128));
    try test__fixint(f64, i128, math.float_max(f64), math.max_int(i128));
    try test__fixint(f64, i128, math.inf(f64), math.max_int(i128));
}
