// Ported from musl, which is MIT licensed.
// https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
//
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogbl.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogbf.c
// https://git.musl-libc.org/cgit/musl/tree/src/math/ilogb.c

const std = @import("../std.zig");
const math = std.math;
const expect = std.testing.expect;
const max_int = std.math.max_int;
const min_int = std.math.min_int;

/// Returns the binary exponent of x as an integer.
///
/// Special Cases:
///  - ilogb(+-inf) = max_int(i32)
///  - ilogb(+-0)   = min_int(i32)
///  - ilogb(nan)   = min_int(i32)
pub fn ilogb(x: anytype) i32 {
    const T = @TypeOf(x);
    return ilogb_x(T, x);
}

pub const fp_ilogbnan = min_int(i32);
pub const fp_ilogb0 = min_int(i32);

fn ilogb_x(comptime T: type, x: T) i32 {
    const typeWidth = @typeInfo(T).Float.bits;
    const significandBits = math.float_mantissa_bits(T);
    const exponentBits = math.float_exponent_bits(T);

    const Z = std.meta.Int(.unsigned, typeWidth);

    const signBit = (@as(Z, 1) << (significandBits + exponentBits));
    const maxExponent = ((1 << exponentBits) - 1);
    const exponentBias = (maxExponent >> 1);

    const absMask = signBit - 1;

    const u = @as(Z, @bit_cast(x)) & absMask;
    const e: i32 = @int_cast(u >> significandBits);

    if (e == 0) {
        if (u == 0) {
            math.raise_invalid();
            return fp_ilogb0;
        }

        // offset sign bit, exponent bits, and integer bit (if present) + bias
        const offset = 1 + exponentBits + @as(comptime_int, @int_from_bool(T == f80)) - exponentBias;
        return offset - @as(i32, @int_cast(@clz(u)));
    }

    if (e == maxExponent) {
        math.raise_invalid();
        if (u > @as(Z, @bit_cast(math.inf(T)))) {
            return fp_ilogbnan; // u is a NaN
        } else return max_int(i32);
    }

    return e - exponentBias;
}

test "type dispatch" {
    try expect(ilogb(@as(f32, 0.2)) == ilogb_x(f32, 0.2));
    try expect(ilogb(@as(f64, 0.2)) == ilogb_x(f64, 0.2));
}

test "16" {
    try expect(ilogb_x(f16, 0.0) == fp_ilogb0);
    try expect(ilogb_x(f16, 0.5) == -1);
    try expect(ilogb_x(f16, 0.8923) == -1);
    try expect(ilogb_x(f16, 10.0) == 3);
    try expect(ilogb_x(f16, -65504) == 15);
    try expect(ilogb_x(f16, 2398.23) == 11);

    try expect(ilogb_x(f16, 0x1p-1) == -1);
    try expect(ilogb_x(f16, 0x1p-17) == -17);
    try expect(ilogb_x(f16, 0x1p-24) == -24);
}

test "32" {
    try expect(ilogb_x(f32, 0.0) == fp_ilogb0);
    try expect(ilogb_x(f32, 0.5) == -1);
    try expect(ilogb_x(f32, 0.8923) == -1);
    try expect(ilogb_x(f32, 10.0) == 3);
    try expect(ilogb_x(f32, -123984) == 16);
    try expect(ilogb_x(f32, 2398.23) == 11);

    try expect(ilogb_x(f32, 0x1p-1) == -1);
    try expect(ilogb_x(f32, 0x1p-122) == -122);
    try expect(ilogb_x(f32, 0x1p-127) == -127);
}

test "64" {
    try expect(ilogb_x(f64, 0.0) == fp_ilogb0);
    try expect(ilogb_x(f64, 0.5) == -1);
    try expect(ilogb_x(f64, 0.8923) == -1);
    try expect(ilogb_x(f64, 10.0) == 3);
    try expect(ilogb_x(f64, -123984) == 16);
    try expect(ilogb_x(f64, 2398.23) == 11);

    try expect(ilogb_x(f64, 0x1p-1) == -1);
    try expect(ilogb_x(f64, 0x1p-127) == -127);
    try expect(ilogb_x(f64, 0x1p-1012) == -1012);
    try expect(ilogb_x(f64, 0x1p-1023) == -1023);
}

test "80" {
    try expect(ilogb_x(f80, 0.0) == fp_ilogb0);
    try expect(ilogb_x(f80, 0.5) == -1);
    try expect(ilogb_x(f80, 0.8923) == -1);
    try expect(ilogb_x(f80, 10.0) == 3);
    try expect(ilogb_x(f80, -123984) == 16);
    try expect(ilogb_x(f80, 2398.23) == 11);

    try expect(ilogb_x(f80, 0x1p-1) == -1);
    try expect(ilogb_x(f80, 0x1p-127) == -127);
    try expect(ilogb_x(f80, 0x1p-1023) == -1023);
    try expect(ilogb_x(f80, 0x1p-16383) == -16383);
}

test "128" {
    try expect(ilogb_x(f128, 0.0) == fp_ilogb0);
    try expect(ilogb_x(f128, 0.5) == -1);
    try expect(ilogb_x(f128, 0.8923) == -1);
    try expect(ilogb_x(f128, 10.0) == 3);
    try expect(ilogb_x(f128, -123984) == 16);
    try expect(ilogb_x(f128, 2398.23) == 11);

    try expect(ilogb_x(f128, 0x1p-1) == -1);
    try expect(ilogb_x(f128, 0x1p-127) == -127);
    try expect(ilogb_x(f128, 0x1p-1023) == -1023);
    try expect(ilogb_x(f128, 0x1p-16383) == -16383);
}

test "16 special" {
    try expect(ilogb_x(f16, math.inf(f16)) == max_int(i32));
    try expect(ilogb_x(f16, -math.inf(f16)) == max_int(i32));
    try expect(ilogb_x(f16, 0.0) == min_int(i32));
    try expect(ilogb_x(f16, math.nan(f16)) == fp_ilogbnan);
}

test "32 special" {
    try expect(ilogb_x(f32, math.inf(f32)) == max_int(i32));
    try expect(ilogb_x(f32, -math.inf(f32)) == max_int(i32));
    try expect(ilogb_x(f32, 0.0) == min_int(i32));
    try expect(ilogb_x(f32, math.nan(f32)) == fp_ilogbnan);
}

test "64 special" {
    try expect(ilogb_x(f64, math.inf(f64)) == max_int(i32));
    try expect(ilogb_x(f64, -math.inf(f64)) == max_int(i32));
    try expect(ilogb_x(f64, 0.0) == min_int(i32));
    try expect(ilogb_x(f64, math.nan(f64)) == fp_ilogbnan);
}

test "80 special" {
    try expect(ilogb_x(f80, math.inf(f80)) == max_int(i32));
    try expect(ilogb_x(f80, -math.inf(f80)) == max_int(i32));
    try expect(ilogb_x(f80, 0.0) == min_int(i32));
    try expect(ilogb_x(f80, math.nan(f80)) == fp_ilogbnan);
}

test "128 special" {
    try expect(ilogb_x(f128, math.inf(f128)) == max_int(i32));
    try expect(ilogb_x(f128, -math.inf(f128)) == max_int(i32));
    try expect(ilogb_x(f128, 0.0) == min_int(i32));
    try expect(ilogb_x(f128, math.nan(f128)) == fp_ilogbnan);
}
