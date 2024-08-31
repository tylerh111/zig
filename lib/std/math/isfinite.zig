const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;

/// Returns whether x is a finite value.
pub fn is_finite(x: anytype) bool {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);
    const remove_sign = ~@as(TBits, 0) >> 1;
    return @as(TBits, @bit_cast(x)) & remove_sign < @as(TBits, @bit_cast(math.inf(T)));
}

test is_finite {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        // normals
        try expect(is_finite(@as(T, 1.0)));
        try expect(is_finite(-@as(T, 1.0)));

        // zero & subnormals
        try expect(is_finite(@as(T, 0.0)));
        try expect(is_finite(@as(T, -0.0)));
        try expect(is_finite(math.float_true_min(T)));

        // other float limits
        try expect(is_finite(math.float_min(T)));
        try expect(is_finite(math.float_max(T)));

        // inf & nan
        try expect(!is_finite(math.inf(T)));
        try expect(!is_finite(-math.inf(T)));
        try expect(!is_finite(math.nan(T)));
        try expect(!is_finite(-math.nan(T)));
    }
}
