const std = @import("std");
const math = std.math;
const Log2Int = std.math.Log2Int;
const assert = std.debug.assert;
const expect = std.testing.expect;

/// Returns x * 2^n.
pub fn ldexp(x: anytype, n: i32) @TypeOf(x) {
    const T = @TypeOf(x);
    const TBits = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);

    const exponent_bits = math.float_exponent_bits(T);
    const mantissa_bits = math.float_mantissa_bits(T);
    const fractional_bits = math.float_fractional_bits(T);

    const max_biased_exponent = 2 * math.float_exponent_max(T);
    const mantissa_mask = @as(TBits, (1 << mantissa_bits) - 1);

    const repr = @as(TBits, @bit_cast(x));
    const sign_bit = repr & (1 << (exponent_bits + mantissa_bits));

    if (math.is_nan(x) or !math.is_finite(x))
        return x;

    var exponent: i32 = @as(i32, @int_cast((repr << 1) >> (mantissa_bits + 1)));
    if (exponent == 0)
        exponent += (@as(i32, exponent_bits) + @int_from_bool(T == f80)) - @clz(repr << 1);

    if (n >= 0) {
        if (n > max_biased_exponent - exponent) {
            // Overflow. Return +/- inf
            return @as(T, @bit_cast(@as(TBits, @bit_cast(math.inf(T))) | sign_bit));
        } else if (exponent + n <= 0) {
            // Result is subnormal
            return @as(T, @bit_cast((repr << @as(Log2Int(TBits), @int_cast(n))) | sign_bit));
        } else if (exponent <= 0) {
            // Result is normal, but needs shifting
            var result = @as(TBits, @int_cast(n + exponent)) << mantissa_bits;
            result |= (repr << @as(Log2Int(TBits), @int_cast(1 - exponent))) & mantissa_mask;
            return @as(T, @bit_cast(result | sign_bit));
        }

        // Result needs no shifting
        return @as(T, @bit_cast(repr + (@as(TBits, @int_cast(n)) << mantissa_bits)));
    } else {
        if (n <= -exponent) {
            if (n < -(mantissa_bits + exponent))
                return @as(T, @bit_cast(sign_bit)); // Severe underflow. Return +/- 0

            // Result underflowed, we need to shift and round
            const shift = @as(Log2Int(TBits), @int_cast(@min(-n, -(exponent + n) + 1)));
            const exact_tie: bool = @ctz(repr) == shift - 1;
            var result = repr & mantissa_mask;

            if (T != f80) // Include integer bit
                result |= @as(TBits, @int_from_bool(exponent > 0)) << fractional_bits;
            result = @as(TBits, @int_cast((result >> (shift - 1))));

            // Round result, including round-to-even for exact ties
            result = ((result + 1) >> 1) & ~@as(TBits, @int_from_bool(exact_tie));
            return @as(T, @bit_cast(result | sign_bit));
        }

        // Result is exact, and needs no shifting
        return @as(T, @bit_cast(repr - (@as(TBits, @int_cast(-n)) << mantissa_bits)));
    }
}

test ldexp {
    // subnormals
    try expect(ldexp(@as(f16, 0x1.1FFp14), -14 - 9 - 15) == math.float_true_min(f16));
    try expect(ldexp(@as(f32, 0x1.3FFFFFp-1), -126 - 22) == math.float_true_min(f32));
    try expect(ldexp(@as(f64, 0x1.7FFFFFFFFFFFFp-1), -1022 - 51) == math.float_true_min(f64));
    try expect(ldexp(@as(f80, 0x1.7FFFFFFFFFFFFFFEp-1), -16382 - 62) == math.float_true_min(f80));
    try expect(ldexp(@as(f128, 0x1.7FFFFFFFFFFFFFFFFFFFFFFFFFFFp-1), -16382 - 111) == math.float_true_min(f128));

    try expect(ldexp(math.float_max(f32), -128 - 149) > 0.0);
    try expect(ldexp(math.float_max(f32), -128 - 149 - 1) == 0.0);

    @setEvalBranchQuota(10_000);

    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const fractional_bits = math.float_fractional_bits(T);

        const min_exponent = math.float_exponent_min(T);
        const max_exponent = math.float_exponent_max(T);
        const exponent_bias = max_exponent;

        // basic usage
        try expect(ldexp(@as(T, 1.5), 4) == 24.0);

        // normals -> subnormals
        try expect(math.is_normal(ldexp(@as(T, 1.0), min_exponent)));
        try expect(!math.is_normal(ldexp(@as(T, 1.0), min_exponent - 1)));

        // normals -> zero
        try expect(ldexp(@as(T, 1.0), min_exponent - fractional_bits) > 0.0);
        try expect(ldexp(@as(T, 1.0), min_exponent - fractional_bits - 1) == 0.0);

        // subnormals -> zero
        try expect(ldexp(math.float_true_min(T), 0) > 0.0);
        try expect(ldexp(math.float_true_min(T), -1) == 0.0);

        // Multiplications might flush the denormals to zero, esp. at
        // runtime, so we manually construct the constants here instead.
        const Z = std.meta.Int(.unsigned, @bitSizeOf(T));
        const EightTimesTrueMin = @as(T, @bit_cast(@as(Z, 8)));
        const TwoTimesTrueMin = @as(T, @bit_cast(@as(Z, 2)));

        // subnormals -> subnormals
        try expect(ldexp(math.float_true_min(T), 3) == EightTimesTrueMin);
        try expect(ldexp(EightTimesTrueMin, -2) == TwoTimesTrueMin);
        try expect(ldexp(EightTimesTrueMin, -3) == math.float_true_min(T));

        // subnormals -> normals (+)
        try expect(ldexp(math.float_true_min(T), fractional_bits) == math.float_min(T));
        try expect(ldexp(math.float_true_min(T), fractional_bits - 1) == math.float_min(T) * 0.5);

        // subnormals -> normals (-)
        try expect(ldexp(-math.float_true_min(T), fractional_bits) == -math.float_min(T));
        try expect(ldexp(-math.float_true_min(T), fractional_bits - 1) == -math.float_min(T) * 0.5);

        // subnormals -> float limits (+inf)
        try expect(math.is_finite(ldexp(math.float_true_min(T), max_exponent + exponent_bias + fractional_bits - 1)));
        try expect(ldexp(math.float_true_min(T), max_exponent + exponent_bias + fractional_bits) == math.inf(T));

        // subnormals -> float limits (-inf)
        try expect(math.is_finite(ldexp(-math.float_true_min(T), max_exponent + exponent_bias + fractional_bits - 1)));
        try expect(ldexp(-math.float_true_min(T), max_exponent + exponent_bias + fractional_bits) == -math.inf(T));

        // infinity -> infinity
        try expect(ldexp(math.inf(T), math.max_int(i32)) == math.inf(T));
        try expect(ldexp(math.inf(T), math.min_int(i32)) == math.inf(T));
        try expect(ldexp(math.inf(T), max_exponent) == math.inf(T));
        try expect(ldexp(math.inf(T), min_exponent) == math.inf(T));
        try expect(ldexp(-math.inf(T), math.max_int(i32)) == -math.inf(T));
        try expect(ldexp(-math.inf(T), math.min_int(i32)) == -math.inf(T));

        // extremely large n
        try expect(ldexp(math.float_max(T), math.max_int(i32)) == math.inf(T));
        try expect(ldexp(math.float_max(T), -math.max_int(i32)) == 0.0);
        try expect(ldexp(math.float_max(T), math.min_int(i32)) == 0.0);
        try expect(ldexp(math.float_true_min(T), math.max_int(i32)) == math.inf(T));
        try expect(ldexp(math.float_true_min(T), -math.max_int(i32)) == 0.0);
        try expect(ldexp(math.float_true_min(T), math.min_int(i32)) == 0.0);
    }
}
