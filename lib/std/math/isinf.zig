const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is an infinity, ignoring sign.
pub inline fn is_inf(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);
    const remove_sign = ~@as(TBits, 0) >> 1;
    return @as(TBits, @bit_cast(x)) & remove_sign == @as(TBits, @bit_cast(math.inf(T)));
}

/// Returns whether x is an infinity with a positive sign.
pub inline fn is_positive_inf(x: anytype) bool {
    return x == math.inf(@TypeOf(x));
}

/// Returns whether x is an infinity with a negative sign.
pub inline fn is_negative_inf(x: anytype) bool {
    return x == -math.inf(@TypeOf(x));
}

test is_inf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!is_inf(@as(T, 0.0)));
        try expect(!is_inf(@as(T, -0.0)));
        try expect(is_inf(math.inf(T)));
        try expect(is_inf(-math.inf(T)));
        try expect(!is_inf(math.nan(T)));
        try expect(!is_inf(-math.nan(T)));
    }
}

test is_positive_inf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!is_positive_inf(@as(T, 0.0)));
        try expect(!is_positive_inf(@as(T, -0.0)));
        try expect(is_positive_inf(math.inf(T)));
        try expect(!is_positive_inf(-math.inf(T)));
        try expect(!is_inf(math.nan(T)));
        try expect(!is_inf(-math.nan(T)));
    }
}

test is_negative_inf {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        try expect(!is_negative_inf(@as(T, 0.0)));
        try expect(!is_negative_inf(@as(T, -0.0)));
        try expect(!is_negative_inf(math.inf(T)));
        try expect(is_negative_inf(-math.inf(T)));
        try expect(!is_inf(math.nan(T)));
        try expect(!is_inf(-math.nan(T)));
    }
}
