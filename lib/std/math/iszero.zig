const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is positive zero.
pub inline fn is_positive_zero(x: anytype) bool {
    const T = @TypeOf(x);
    const bit_count = @typeInfo(T).Float.bits;
    const TBits = std.meta.Int(.unsigned, bit_count);
    return @as(TBits, @bit_cast(x)) == @as(TBits, 0);
}

/// Returns whether x is negative zero.
pub inline fn is_negative_zero(x: anytype) bool {
    const T = @TypeOf(x);
    const bit_count = @typeInfo(T).Float.bits;
    const TBits = std.meta.Int(.unsigned, bit_count);
    return @as(TBits, @bit_cast(x)) == @as(TBits, 1) << (bit_count - 1);
}

test is_positive_zero {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(is_positive_zero(@as(T, 0.0)));
        try expect(!is_positive_zero(@as(T, -0.0)));
        try expect(!is_positive_zero(math.float_min(T)));
        try expect(!is_positive_zero(math.float_max(T)));
        try expect(!is_positive_zero(math.inf(T)));
        try expect(!is_positive_zero(-math.inf(T)));
    }
}

test is_negative_zero {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(is_negative_zero(@as(T, -0.0)));
        try expect(!is_negative_zero(@as(T, 0.0)));
        try expect(!is_negative_zero(math.float_min(T)));
        try expect(!is_negative_zero(math.float_max(T)));
        try expect(!is_negative_zero(math.inf(T)));
        try expect(!is_negative_zero(-math.inf(T)));
    }
}
