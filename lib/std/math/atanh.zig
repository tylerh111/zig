// Ported from musl, which is licensed under the MIT license:
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/atanhf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/atanh.c

const std = @import("../std.zig");
const math = std.math;
const mem = std.mem;
const expect = std.testing.expect;
const max_int = std.math.max_int;

/// Returns the hyperbolic arc-tangent of x.
///
/// Special Cases:
///  - atanh(+-1) = +-inf with signal
///  - atanh(x)   = nan if |x| > 1 with signal
///  - atanh(nan) = nan
pub fn atanh(x: anytype) @TypeOf(x) {
    const T = @TypeOf(x);
    return switch (T) {
        f32 => atanh_32(x),
        f64 => atanh_64(x),
        else => @compile_error("atanh not implemented for " ++ @type_name(T)),
    };
}

// atanh(x) = log((1 + x) / (1 - x)) / 2 = log1p(2x / (1 - x)) / 2 ~= x + x^3 / 3 + o(x^5)
fn atanh_32(x: f32) f32 {
    const u = @as(u32, @bit_cast(x));
    const i = u & 0x7FFFFFFF;
    const s = u >> 31;

    var y = @as(f32, @bit_cast(i)); // |x|

    if (y == 1.0) {
        return math.copysign(math.inf(f32), x);
    }

    if (u < 0x3F800000 - (1 << 23)) {
        if (u < 0x3F800000 - (32 << 23)) {
            // underflow
            if (u < (1 << 23)) {
                mem.do_not_optimize_away(y * y);
            }
        }
        // |x| < 0.5
        else {
            y = 0.5 * math.log1p(2 * y + 2 * y * y / (1 - y));
        }
    } else {
        y = 0.5 * math.log1p(2 * (y / (1 - y)));
    }

    return if (s != 0) -y else y;
}

fn atanh_64(x: f64) f64 {
    const u: u64 = @bit_cast(x);
    const e = (u >> 52) & 0x7FF;
    const s = u >> 63;

    var y: f64 = @bit_cast(u & (max_int(u64) >> 1)); // |x|

    if (y == 1.0) {
        return math.copysign(math.inf(f64), x);
    }

    if (e < 0x3FF - 1) {
        if (e < 0x3FF - 32) {
            // underflow
            if (e == 0) {
                mem.do_not_optimize_away(@as(f32, @float_cast(y)));
            }
        }
        // |x| < 0.5
        else {
            y = 0.5 * math.log1p(2 * y + 2 * y * y / (1 - y));
        }
    } else {
        y = 0.5 * math.log1p(2 * (y / (1 - y)));
    }

    return if (s != 0) -y else y;
}

test atanh {
    try expect(atanh(@as(f32, 0.0)) == atanh_32(0.0));
    try expect(atanh(@as(f64, 0.0)) == atanh_64(0.0));
}

test atanh_32 {
    const epsilon = 0.000001;

    try expect(math.approx_eq_abs(f32, atanh_32(0.0), 0.0, epsilon));
    try expect(math.approx_eq_abs(f32, atanh_32(0.2), 0.202733, epsilon));
    try expect(math.approx_eq_abs(f32, atanh_32(0.8923), 1.433099, epsilon));
}

test atanh_64 {
    const epsilon = 0.000001;

    try expect(math.approx_eq_abs(f64, atanh_64(0.0), 0.0, epsilon));
    try expect(math.approx_eq_abs(f64, atanh_64(0.2), 0.202733, epsilon));
    try expect(math.approx_eq_abs(f64, atanh_64(0.8923), 1.433099, epsilon));
}

test "atanh32.special" {
    try expect(math.is_positive_inf(atanh_32(1)));
    try expect(math.is_negative_inf(atanh_32(-1)));
    try expect(math.is_nan(atanh_32(1.5)));
    try expect(math.is_nan(atanh_32(-1.5)));
    try expect(math.is_nan(atanh_32(math.nan(f32))));
}

test "atanh64.special" {
    try expect(math.is_positive_inf(atanh_64(1)));
    try expect(math.is_negative_inf(atanh_64(-1)));
    try expect(math.is_nan(atanh_64(1.5)));
    try expect(math.is_nan(atanh_64(-1.5)));
    try expect(math.is_nan(atanh_64(math.nan(f64))));
}
