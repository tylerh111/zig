const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const expect_approx_eq_abs = std.testing.expect_approx_eq_abs;

pub fn Frexp(comptime T: type) type {
    return struct {
        significand: T,
        exponent: i32,
    };
}

/// Breaks x into a normalized fraction and an integral power of two.
/// f == frac * 2^exp, with |frac| in the interval [0.5, 1).
///
/// Special Cases:
///  - frexp(+-0)   = +-0, 0
///  - frexp(+-inf) = +-inf, 0
///  - frexp(nan)   = nan, undefined
pub fn frexp(x: anytype) Frexp(@TypeOf(x)) {
    const T: type = @TypeOf(x);

    const bits: comptime_int = @typeInfo(T).Float.bits;
    const Int: type = std.meta.Int(.unsigned, bits);

    const exp_bits: comptime_int = math.float_exponent_bits(T);
    const mant_bits: comptime_int = math.float_mantissa_bits(T);
    const frac_bits: comptime_int = math.float_fractional_bits(T);
    const exp_min: comptime_int = math.float_exponent_min(T);

    const ExpInt: type = std.meta.Int(.unsigned, exp_bits);
    const MantInt: type = std.meta.Int(.unsigned, mant_bits);
    const FracInt: type = std.meta.Int(.unsigned, frac_bits);

    const unreal_exponent: comptime_int = (1 << exp_bits) - 1;
    const bias: comptime_int = (1 << (exp_bits - 1)) - 2;
    const exp_mask: comptime_int = unreal_exponent << mant_bits;
    const zero_exponent: comptime_int = bias << mant_bits;
    const sign_mask: comptime_int = 1 << (bits - 1);
    const not_exp: comptime_int = ~@as(Int, exp_mask);
    const ones_place: comptime_int = mant_bits - frac_bits;
    const extra_denorm_shift: comptime_int = 1 - ones_place;

    var result: Frexp(T) = undefined;
    var v: Int = @bit_cast(x);

    const m: MantInt = @truncate(v);
    const e: ExpInt = @truncate(v >> mant_bits);

    switch (e) {
        0 => {
            if (m != 0) {
                // subnormal
                const offset = @clz(m);
                const shift = offset + extra_denorm_shift;

                v &= sign_mask;
                v |= zero_exponent;
                v |= math.shl(MantInt, m, shift);

                result.exponent = exp_min - @as(i32, offset) + ones_place;
            } else {
                // +-0 = (+-0, 0)
                result.exponent = 0;
            }
        },
        unreal_exponent => {
            // +-nan -> {+-nan, undefined}
            result.exponent = undefined;

            // +-inf -> {+-inf, 0}
            if (@as(FracInt, @truncate(v)) == 0)
                result.exponent = 0;
        },
        else => {
            // normal
            v &= not_exp;
            v |= zero_exponent;
            result.exponent = @as(i32, e) - bias;
        },
    }

    result.significand = @bit_cast(v);
    return result;
}

/// Generate a namespace of tests for frexp on values of the given type
fn FrexpTests(comptime Float: type) type {
    return struct {
        const T = Float;
        test "normal" {
            const epsilon = 1e-6;
            var r: Frexp(T) = undefined;

            r = frexp(@as(T, 1.3));
            try expect_approx_eq_abs(0.65, r.significand, epsilon);
            try expect_equal(1, r.exponent);

            r = frexp(@as(T, 78.0234));
            try expect_approx_eq_abs(0.609558, r.significand, epsilon);
            try expect_equal(7, r.exponent);

            r = frexp(@as(T, -1234.5678));
            try expect_equal(11, r.exponent);
            try expect_approx_eq_abs(-0.602816, r.significand, epsilon);
        }
        test "max" {
            const exponent = math.float_exponent_max(T) + 1;
            const significand = 1.0 - math.float_eps(T) / 2;
            const r: Frexp(T) = frexp(math.float_max(T));
            try expect_equal(exponent, r.exponent);
            try expect_equal(significand, r.significand);
        }
        test "min" {
            const exponent = math.float_exponent_min(T) + 1;
            const r: Frexp(T) = frexp(math.float_min(T));
            try expect_equal(exponent, r.exponent);
            try expect_equal(0.5, r.significand);
        }
        test "subnormal" {
            const normal_min_exponent = math.float_exponent_min(T) + 1;
            const exponent = normal_min_exponent - math.float_fractional_bits(T);
            const r: Frexp(T) = frexp(math.float_true_min(T));
            try expect_equal(exponent, r.exponent);
            try expect_equal(0.5, r.significand);
        }
        test "zero" {
            var r: Frexp(T) = undefined;

            r = frexp(@as(T, 0.0));
            try expect_equal(0, r.exponent);
            try expect(math.is_positive_zero(r.significand));

            r = frexp(@as(T, -0.0));
            try expect_equal(0, r.exponent);
            try expect(math.is_negative_zero(r.significand));
        }
        test "inf" {
            var r: Frexp(T) = undefined;

            r = frexp(math.inf(T));
            try expect_equal(0, r.exponent);
            try expect(math.is_positive_inf(r.significand));

            r = frexp(-math.inf(T));
            try expect_equal(0, r.exponent);
            try expect(math.is_negative_inf(r.significand));
        }
        test "nan" {
            const r: Frexp(T) = frexp(math.nan(T));
            try expect(math.is_nan(r.significand));
        }
    };
}

// Generate tests for each floating point type
comptime {
    for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        _ = FrexpTests(T);
    }
}

test frexp {
    inline for ([_]type{ f16, f32, f64, f80, f128 }) |T| {
        const max_exponent = math.float_exponent_max(T) + 1;
        const min_exponent = math.float_exponent_min(T) + 1;
        const truemin_exponent = min_exponent - math.float_fractional_bits(T);

        var result: Frexp(T) = undefined;
        comptime var x: T = undefined;

        // basic usage
        // value -> {significand, exponent},
        // value == significand * (2 ^ exponent)
        x = 1234.5678;
        result = frexp(x);
        try expect_equal(11, result.exponent);
        try expect_approx_eq_abs(0.602816, result.significand, 1e-6);
        try expect_equal(x, math.ldexp(result.significand, result.exponent));

        // float maximum
        x = math.float_max(T);
        result = frexp(x);
        try expect_equal(max_exponent, result.exponent);
        try expect_equal(1.0 - math.float_eps(T) / 2, result.significand);
        try expect_equal(x, math.ldexp(result.significand, result.exponent));

        // float minimum
        x = math.float_min(T);
        result = frexp(x);
        try expect_equal(min_exponent, result.exponent);
        try expect_equal(0.5, result.significand);
        try expect_equal(x, math.ldexp(result.significand, result.exponent));

        // float true minimum
        // subnormal -> {normal, exponent}
        x = math.float_true_min(T);
        result = frexp(x);
        try expect_equal(truemin_exponent, result.exponent);
        try expect_equal(0.5, result.significand);
        try expect_equal(x, math.ldexp(result.significand, result.exponent));

        // infinity -> {infinity, zero} (+)
        result = frexp(math.inf(T));
        try expect_equal(0, result.exponent);
        try expect(math.is_positive_inf(result.significand));

        // infinity -> {infinity, zero} (-)
        result = frexp(-math.inf(T));
        try expect_equal(0, result.exponent);
        try expect(math.is_negative_inf(result.significand));

        // zero -> {zero, zero} (+)
        result = frexp(@as(T, 0.0));
        try expect_equal(0, result.exponent);
        try expect(math.is_positive_zero(result.significand));

        // zero -> {zero, zero} (-)
        result = frexp(@as(T, -0.0));
        try expect_equal(0, result.exponent);
        try expect(math.is_negative_zero(result.significand));

        // nan -> {nan, undefined}
        result = frexp(math.nan(T));
        try expect(math.is_nan(result.significand));
    }
}
