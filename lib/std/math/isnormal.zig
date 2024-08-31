const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is neither zero, subnormal, infinity, or NaN.
pub fn is_normal(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);

    const increment_exp = 1 << math.float_mantissa_bits(T);
    const remove_sign = ~@as(TBits, 0) >> 1;

    // We add 1 to the exponent, and if it overflows to 0 or becomes 1,
    // then it was all zeroes (subnormal) or all ones (special, inf/nan).
    // The sign bit is removed because all ones would overflow into it.
    // For f80, even though it has an explicit integer part stored,
    // the exponent effectively takes priority if mismatching.
    const value = @as(TBits, @bit_cast(x)) +% increment_exp;
    return value & remove_sign >= (increment_exp << 1);
}

test is_normal {
    // TODO add `c_longdouble' when math.inf(T) supports it
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const TBits = std.meta.Int(.unsigned, @bitSizeOf(T));

        // normals
        try expect(is_normal(@as(T, 1.0)));
        try expect(is_normal(math.float_min(T)));
        try expect(is_normal(math.float_max(T)));

        // subnormals
        try expect(!is_normal(@as(T, -0.0)));
        try expect(!is_normal(@as(T, 0.0)));
        try expect(!is_normal(@as(T, math.float_true_min(T))));

        // largest subnormal
        try expect(!is_normal(@as(T, @bit_cast(~(~@as(TBits, 0) << math.float_fractional_bits(T))))));

        // non-finite numbers
        try expect(!is_normal(-math.inf(T)));
        try expect(!is_normal(math.inf(T)));
        try expect(!is_normal(math.nan(T)));

        // overflow edge-case (described in implementation, also see #10133)
        try expect(!is_normal(@as(T, @bit_cast(~@as(TBits, 0)))));
    }
}
