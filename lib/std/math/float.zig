const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;

/// Creates a raw "1.0" mantissa for floating point type T. Used to dedupe f80 logic.
inline fn mantissa_one(comptime T: type) comptime_int {
    return if (@typeInfo(T).Float.bits == 80) 1 << float_fractional_bits(T) else 0;
}

/// Creates floating point type T from an unbiased exponent and raw mantissa.
inline fn reconstruct_float(comptime T: type, comptime exponent: comptime_int, comptime mantissa: comptime_int) T {
    const TBits = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = @bitSizeOf(T) } });
    const biased_exponent = @as(TBits, exponent + float_exponent_max(T));
    return @as(T, @bit_cast((biased_exponent << float_mantissa_bits(T)) | @as(TBits, mantissa)));
}

/// Returns the number of bits in the exponent of floating point type T.
pub inline fn float_exponent_bits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .Float);

    return switch (@typeInfo(T).Float.bits) {
        16 => 5,
        32 => 8,
        64 => 11,
        80 => 15,
        128 => 15,
        else => @compile_error("unknown floating point type " ++ @type_name(T)),
    };
}

/// Returns the number of bits in the mantissa of floating point type T.
pub inline fn float_mantissa_bits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .Float);

    return switch (@typeInfo(T).Float.bits) {
        16 => 10,
        32 => 23,
        64 => 52,
        80 => 64,
        128 => 112,
        else => @compile_error("unknown floating point type " ++ @type_name(T)),
    };
}

/// Returns the number of fractional bits in the mantissa of floating point type T.
pub inline fn float_fractional_bits(comptime T: type) comptime_int {
    comptime assert(@typeInfo(T) == .Float);

    // standard IEEE floats have an implicit 0.m or 1.m integer part
    // f80 is special and has an explicitly stored bit in the MSB
    // this function corresponds to `MANT_DIG - 1' from C
    return switch (@typeInfo(T).Float.bits) {
        16 => 10,
        32 => 23,
        64 => 52,
        80 => 63,
        128 => 112,
        else => @compile_error("unknown floating point type " ++ @type_name(T)),
    };
}

/// Returns the minimum exponent that can represent
/// a normalised value in floating point type T.
pub inline fn float_exponent_min(comptime T: type) comptime_int {
    return -float_exponent_max(T) + 1;
}

/// Returns the maximum exponent that can represent
/// a normalised value in floating point type T.
pub inline fn float_exponent_max(comptime T: type) comptime_int {
    return (1 << (float_exponent_bits(T) - 1)) - 1;
}

/// Returns the smallest subnormal number representable in floating point type T.
pub inline fn float_true_min(comptime T: type) T {
    return reconstruct_float(T, float_exponent_min(T) - 1, 1);
}

/// Returns the smallest normal number representable in floating point type T.
pub inline fn float_min(comptime T: type) T {
    return reconstruct_float(T, float_exponent_min(T), mantissa_one(T));
}

/// Returns the largest normal number representable in floating point type T.
pub inline fn float_max(comptime T: type) T {
    const all1s_mantissa = (1 << float_mantissa_bits(T)) - 1;
    return reconstruct_float(T, float_exponent_max(T), all1s_mantissa);
}

/// Returns the machine epsilon of floating point type T.
pub inline fn float_eps(comptime T: type) T {
    return reconstruct_float(T, -float_fractional_bits(T), mantissa_one(T));
}

/// Returns the local epsilon of floating point type T.
pub inline fn float_eps_at(comptime T: type, x: T) T {
    switch (@typeInfo(T)) {
        .Float => |F| {
            const U: type = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = F.bits } });
            const u: U = @bit_cast(x);
            const y: T = @bit_cast(u ^ 1);
            return @abs(x - y);
        },
        else => @compile_error("float_eps_at only supports floats"),
    }
}

/// Returns the value inf for floating point type T.
pub inline fn inf(comptime T: type) T {
    return reconstruct_float(T, float_exponent_max(T) + 1, mantissa_one(T));
}

/// Returns the canonical quiet NaN representation for floating point type T.
pub inline fn nan(comptime T: type) T {
    return reconstruct_float(
        T,
        float_exponent_max(T) + 1,
        mantissa_one(T) | 1 << (float_fractional_bits(T) - 1),
    );
}

/// Returns a signalling NaN representation for floating point type T.
///
/// TODO: LLVM is known to miscompile on some architectures to quiet NaN -
///       this is tracked by https://github.com/ziglang/zig/issues/14366
pub inline fn snan(comptime T: type) T {
    return reconstruct_float(
        T,
        float_exponent_max(T) + 1,
        mantissa_one(T) | 1 << (float_fractional_bits(T) - 2),
    );
}

test "float bits" {
    inline for ([_]type{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        // (1 +) for the sign bit, since it is separate from the other bits
        const size = 1 + float_exponent_bits(T) + float_mantissa_bits(T);
        try expect(@bitSizeOf(T) == size);

        // for machine epsilon, assert expmin <= -prec <= expmax
        try expect(float_exponent_min(T) <= -float_fractional_bits(T));
        try expect(-float_fractional_bits(T) <= float_exponent_max(T));
    }
}

test inf {
    const inf_u16: u16 = 0x7C00;
    const inf_u32: u32 = 0x7F800000;
    const inf_u64: u64 = 0x7FF0000000000000;
    const inf_u80: u80 = 0x7FFF8000000000000000;
    const inf_u128: u128 = 0x7FFF0000000000000000000000000000;
    try expect_equal(inf_u16, @as(u16, @bit_cast(inf(f16))));
    try expect_equal(inf_u32, @as(u32, @bit_cast(inf(f32))));
    try expect_equal(inf_u64, @as(u64, @bit_cast(inf(f64))));
    try expect_equal(inf_u80, @as(u80, @bit_cast(inf(f80))));
    try expect_equal(inf_u128, @as(u128, @bit_cast(inf(f128))));
}

test nan {
    const qnan_u16: u16 = 0x7E00;
    const qnan_u32: u32 = 0x7FC00000;
    const qnan_u64: u64 = 0x7FF8000000000000;
    const qnan_u80: u80 = 0x7FFFC000000000000000;
    const qnan_u128: u128 = 0x7FFF8000000000000000000000000000;
    try expect_equal(qnan_u16, @as(u16, @bit_cast(nan(f16))));
    try expect_equal(qnan_u32, @as(u32, @bit_cast(nan(f32))));
    try expect_equal(qnan_u64, @as(u64, @bit_cast(nan(f64))));
    try expect_equal(qnan_u80, @as(u80, @bit_cast(nan(f80))));
    try expect_equal(qnan_u128, @as(u128, @bit_cast(nan(f128))));
}

test snan {
    // TODO: https://github.com/ziglang/zig/issues/14366
    if (builtin.zig_backend == .stage2_llvm and comptime builtin.cpu.arch.is_arm_or_thumb()) return error.SkipZigTest;

    const snan_u16: u16 = 0x7D00;
    const snan_u32: u32 = 0x7FA00000;
    const snan_u64: u64 = 0x7FF4000000000000;
    const snan_u80: u80 = 0x7FFFA000000000000000;
    const snan_u128: u128 = 0x7FFF4000000000000000000000000000;
    try expect_equal(snan_u16, @as(u16, @bit_cast(snan(f16))));
    try expect_equal(snan_u32, @as(u32, @bit_cast(snan(f32))));
    try expect_equal(snan_u64, @as(u64, @bit_cast(snan(f64))));
    try expect_equal(snan_u80, @as(u80, @bit_cast(snan(f80))));
    try expect_equal(snan_u128, @as(u128, @bit_cast(snan(f128))));
}
