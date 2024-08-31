// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/tanhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/tanh.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;
const expo2 = @import("expo2.zig").expo2;
const max_int = std.math.max_int;

/// Returns the hyperbolic tangent of x.
///
/// Special Cases:
///  - sinh(+-0)   = +-0
///  - sinh(+-inf) = +-1
///  - sinh(nan)   = nan
pub fn tanh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => tanh32(x),
        f64 => tanh64(x),
        else => @compile_error("tanh not implemented for " ++ @type_name(T)),
    };
}

// tanh(x) = (exp(x) - exp(-x)) / (exp(x) + exp(-x))
//         = (exp(2x) - 1) / (exp(2x) - 1 + 2)
//         = (1 - exp(-2x)) / (exp(-2x) - 1 + 2)
fn tanh32(x: f32) f32 {
    const u = @as(u32, @bit_cast(x));
    const ux = u & 0x7FFFFFFF;
    const ax = @as(f32, @bit_cast(ux));
    const sign = (u >> 31) != 0;

    var t: f32 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (ux > 0x3F0C9F54) {
        // |x| > 10
        if (ux > 0x41200000) {
            t = 1.0 + 0 / x;
        } else {
            t = math.expm1(2 * ax);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (ux > 0x3E82C578) {
        t = math.expm1(2 * ax);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-126
    else if (ux >= 0x00800000) {
        t = math.expm1(-2 * ax);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        mem.do_not_optimize_away(ax * ax);
        t = ax;
    }

    return if (sign) -t else t;
}

fn tanh64(x: f64) f64 {
    const u = @as(u64, @bit_cast(x));
    const ux = u & 0x7FFFFFFFFFFFFFFF;
    const w = @as(u32, @int_cast(ux >> 32));
    const ax = @as(f64, @bit_cast(ux));
    const sign = (u >> 63) != 0;

    var t: f64 = undefined;

    // |x| < log(3) / 2 ~= 0.5493 or nan
    if (w > 0x3FE193EA) {
        // |x| > 20 or nan
        if (w > 0x40340000) {
            t = 1.0 - 0 / ax;
        } else {
            t = math.expm1(2 * ax);
            t = 1 - 2 / (t + 2);
        }
    }
    // |x| > log(5 / 3) / 2 ~= 0.2554
    else if (w > 0x3FD058AE) {
        t = math.expm1(2 * ax);
        t = t / (t + 2);
    }
    // |x| >= 0x1.0p-1022
    else if (w >= 0x00100000) {
        t = math.expm1(-2 * ax);
        t = -t / (t + 2);
    }
    // |x| is subnormal
    else {
        mem.do_not_optimize_away(@as(f32, @float_cast(ax)));
        t = ax;
    }

    return if (sign) -t else t;
}

test tanh {
    try expect(tanh(@as(f32, 1.5)) == tanh32(1.5));
    try expect(tanh(@as(f64, 1.5)) == tanh64(1.5));
}

test tanh32 {
    const epsilon = 0.000001;

    try expect(math.approx_eq_abs(f32, tanh32(0.0), 0.0, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(0.2), 0.197375, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(0.8923), 0.712528, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(1.5), 0.905148, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(37.45), 1.0, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(-0.8923), -0.712528, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(-1.5), -0.905148, epsilon));
    try expect(math.approx_eq_abs(f32, tanh32(-37.45), -1.0, epsilon));
}

test tanh64 {
    const epsilon = 0.000001;

    try expect(math.approx_eq_abs(f64, tanh64(0.0), 0.0, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(0.2), 0.197375, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(0.8923), 0.712528, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(1.5), 0.905148, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(37.45), 1.0, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(-0.8923), -0.712528, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(-1.5), -0.905148, epsilon));
    try expect(math.approx_eq_abs(f64, tanh64(-37.45), -1.0, epsilon));
}

test "tanh32.special" {
    try expect(math.is_positive_zero(tanh32(0.0)));
    try expect(math.is_negative_zero(tanh32(-0.0)));
    try expect(tanh32(math.inf(f32)) == 1.0);
    try expect(tanh32(-math.inf(f32)) == -1.0);
    try expect(math.is_nan(tanh32(math.nan(f32))));
}

test "tanh64.special" {
    try expect(math.is_positive_zero(tanh64(0.0)));
    try expect(math.is_negative_zero(tanh64(-0.0)));
    try expect(tanh64(math.inf(f64)) == 1.0);
    try expect(tanh64(-math.inf(f64)) == -1.0);
    try expect(math.is_nan(tanh64(math.nan(f64))));
}
