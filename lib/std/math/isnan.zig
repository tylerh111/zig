const std = @import("../std.zig");
const builtin = @import("builtin");
const math = std.math;
const meta = std.meta;
const expect = std.testing.expect;

pub fn is_nan(x: anytype) bool {
    return x != x;
}

/// TODO: LLVM is known to miscompile on some architectures to quiet NaN -
///       this is tracked by https://github.com/ziglang/zig/issues/14366
pub fn is_signal_nan(x: anytype) bool {
    const T = @TypeOf(x);
    const U = meta.Int(.unsigned, @bitSizeOf(T));
    const quiet_signal_bit_mask = 1 << (math.float_fractional_bits(T) - 1);
    return is_nan(x) and (@as(U, @bit_cast(x)) & quiet_signal_bit_mask == 0);
}

test is_nan {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        try expect(is_nan(math.nan(T)));
        try expect(is_nan(-math.nan(T)));
        try expect(is_nan(math.snan(T)));
        try expect(!is_nan(@as(T, 1.0)));
        try expect(!is_nan(@as(T, math.inf(T))));
    }
}

test is_signal_nan {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        // TODO: Signalling NaN values get converted to quiet NaN values in
        //       some cases where they shouldn't such that this can fail.
        //       See https://github.com/ziglang/zig/issues/14366
        // try expect(is_signal_nan(math.snan(T)));
        try expect(!is_signal_nan(math.nan(T)));
        try expect(!is_signal_nan(@as(T, 1.0)));
        try expect(!is_signal_nan(math.inf(T)));
    }
}
