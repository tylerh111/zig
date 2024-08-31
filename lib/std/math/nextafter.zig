const std = @import("../std.zig");
const math = std.math;
const assert = std.debug.assert;
const expect = std.testing.expect;

/// Returns the next representable value after `x` in the direction of `y`.
///
/// Special cases:
///
/// - If `x == y`, `y` is returned.
/// - For floats, if either `x` or `y` is a NaN, a NaN is returned.
/// - For floats, if `x == 0.0` and `@abs(y) > 0.0`, the smallest subnormal number with the sign of
///   `y` is returned.
///
pub fn next_after(comptime T: type, x: T, y: T) T {
    return switch (@typeInfo(T)) {
        .Int, .ComptimeInt => next_after_int(T, x, y),
        .Float => next_after_float(T, x, y),
        else => @compile_error("expected int or non-comptime float, found '" ++ @type_name(T) ++ "'"),
    };
}

fn next_after_int(comptime T: type, x: T, y: T) T {
    comptime assert(@typeInfo(T) == .Int or @typeInfo(T) == .ComptimeInt);
    return if (@typeInfo(T) == .Int and @bitSizeOf(T) < 2)
        // Special case for `i0`, `u0`, `i1`, and `u1`.
        y
    else if (y > x)
        x + 1
    else if (y < x)
        x - 1
    else
        y;
}

// Based on nextafterf/nextafterl from mingw-w64 which are both public domain.
// <https://github.com/mingw-w64/mingw-w64/blob/e89de847dd3e05bb8e46344378ce3e124f4e7d1c/mingw-w64-crt/math/nextafterf.c>
// <https://github.com/mingw-w64/mingw-w64/blob/e89de847dd3e05bb8e46344378ce3e124f4e7d1c/mingw-w64-crt/math/nextafterl.c>

fn next_after_float(comptime T: type, x: T, y: T) T {
    comptime assert(@typeInfo(T) == .Float);
    if (x == y) {
        // Returning `y` ensures that (0.0, -0.0) returns -0.0 and that (-0.0, 0.0) returns 0.0.
        return y;
    }
    if (math.is_nan(x) or math.is_nan(y)) {
        return math.nan(T);
    }
    if (x == 0.0) {
        return if (y > 0.0)
            math.float_true_min(T)
        else
            -math.float_true_min(T);
    }
    if (@bitSizeOf(T) == 80) {
        // Unlike other floats, `f80` has an explicitly stored integer bit between the fractional
        // part and the exponent and thus requires special handling. This integer bit *must* be set
        // when the value is normal, an infinity or a NaN and *should* be cleared otherwise.

        const fractional_bits_mask = (1 << math.float_fractional_bits(f80)) - 1;
        const integer_bit_mask = 1 << math.float_fractional_bits(f80);
        const exponent_bits_mask = (1 << math.float_exponent_bits(f80)) - 1;

        var x_parts = math.break_f80(x);

        // Bitwise increment/decrement the fractional part while also taking care to update the
        // exponent if we overflow the fractional part. This might flip the integer bit; this is
        // intentional.
        if ((x > 0.0) == (y > x)) {
            x_parts.fraction +%= 1;
            if (x_parts.fraction & fractional_bits_mask == 0) {
                x_parts.exp += 1;
            }
        } else {
            if (x_parts.fraction & fractional_bits_mask == 0) {
                x_parts.exp -= 1;
            }
            x_parts.fraction -%= 1;
        }

        // If the new value is normal or an infinity (indicated by at least one bit in the exponent
        // being set), the integer bit might have been cleared from an overflow, so we must ensure
        // that it remains set.
        if (x_parts.exp & exponent_bits_mask != 0) {
            x_parts.fraction |= integer_bit_mask;
        }
        // Otherwise, the new value is subnormal and the integer bit will have either flipped from
        // set to cleared (if the old value was normal) or remained cleared (if the old value was
        // subnormal), both of which are the outcomes we want.

        return math.make_f80(x_parts);
    } else {
        const Bits = std.meta.Int(.unsigned, @bitSizeOf(T));
        var x_bits: Bits = @bit_cast(x);
        if ((x > 0.0) == (y > x)) {
            x_bits += 1;
        } else {
            x_bits -= 1;
        }
        return @bit_cast(x_bits);
    }
}

test "int" {
    try expect(next_after(i0, 0, 0) == 0);
    try expect(next_after(u0, 0, 0) == 0);
    try expect(next_after(i1, 0, 0) == 0);
    try expect(next_after(i1, 0, -1) == -1);
    try expect(next_after(i1, -1, -1) == -1);
    try expect(next_after(i1, -1, 0) == 0);
    try expect(next_after(u1, 0, 0) == 0);
    try expect(next_after(u1, 0, 1) == 1);
    try expect(next_after(u1, 1, 1) == 1);
    try expect(next_after(u1, 1, 0) == 0);
    inline for (.{ i8, i16, i32, i64, i128, i333 }) |T| {
        try expect(next_after(T, 3, 7) == 4);
        try expect(next_after(T, 3, -7) == 2);
        try expect(next_after(T, -3, -7) == -4);
        try expect(next_after(T, -3, 7) == -2);
        try expect(next_after(T, 5, 5) == 5);
        try expect(next_after(T, -5, -5) == -5);
        try expect(next_after(T, 0, 0) == 0);
        try expect(next_after(T, math.min_int(T), math.min_int(T)) == math.min_int(T));
        try expect(next_after(T, math.max_int(T), math.max_int(T)) == math.max_int(T));
    }
    inline for (.{ u8, u16, u32, u64, u128, u333 }) |T| {
        try expect(next_after(T, 3, 7) == 4);
        try expect(next_after(T, 7, 3) == 6);
        try expect(next_after(T, 5, 5) == 5);
        try expect(next_after(T, 0, 0) == 0);
        try expect(next_after(T, math.min_int(T), math.min_int(T)) == math.min_int(T));
        try expect(next_after(T, math.max_int(T), math.max_int(T)) == math.max_int(T));
    }
    comptime {
        try expect(next_after(comptime_int, 3, 7) == 4);
        try expect(next_after(comptime_int, 3, -7) == 2);
        try expect(next_after(comptime_int, -3, -7) == -4);
        try expect(next_after(comptime_int, -3, 7) == -2);
        try expect(next_after(comptime_int, 5, 5) == 5);
        try expect(next_after(comptime_int, -5, -5) == -5);
        try expect(next_after(comptime_int, 0, 0) == 0);
        try expect(next_after(comptime_int, math.max_int(u512), math.max_int(u512)) == math.max_int(u512));
    }
}

test "float" {
    @setEvalBranchQuota(3000);

    // normal -> normal
    try expect(next_after(f16, 0x1.234p0, 2.0) == 0x1.238p0);
    try expect(next_after(f16, 0x1.234p0, -2.0) == 0x1.230p0);
    try expect(next_after(f16, 0x1.234p0, 0x1.234p0) == 0x1.234p0);
    try expect(next_after(f16, -0x1.234p0, -2.0) == -0x1.238p0);
    try expect(next_after(f16, -0x1.234p0, 2.0) == -0x1.230p0);
    try expect(next_after(f16, -0x1.234p0, -0x1.234p0) == -0x1.234p0);
    try expect(next_after(f32, 0x1.001234p0, 2.0) == 0x1.001236p0);
    try expect(next_after(f32, 0x1.001234p0, -2.0) == 0x1.001232p0);
    try expect(next_after(f32, 0x1.001234p0, 0x1.001234p0) == 0x1.001234p0);
    try expect(next_after(f32, -0x1.001234p0, -2.0) == -0x1.001236p0);
    try expect(next_after(f32, -0x1.001234p0, 2.0) == -0x1.001232p0);
    try expect(next_after(f32, -0x1.001234p0, -0x1.001234p0) == -0x1.001234p0);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(next_after(T64, 0x1.0000000001234p0, 2.0) == 0x1.0000000001235p0);
        try expect(next_after(T64, 0x1.0000000001234p0, -2.0) == 0x1.0000000001233p0);
        try expect(next_after(T64, 0x1.0000000001234p0, 0x1.0000000001234p0) == 0x1.0000000001234p0);
        try expect(next_after(T64, -0x1.0000000001234p0, -2.0) == -0x1.0000000001235p0);
        try expect(next_after(T64, -0x1.0000000001234p0, 2.0) == -0x1.0000000001233p0);
        try expect(next_after(T64, -0x1.0000000001234p0, -0x1.0000000001234p0) == -0x1.0000000001234p0);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(next_after(T80, 0x1.0000000000001234p0, 2.0) == 0x1.0000000000001236p0);
        try expect(next_after(T80, 0x1.0000000000001234p0, -2.0) == 0x1.0000000000001232p0);
        try expect(next_after(T80, 0x1.0000000000001234p0, 0x1.0000000000001234p0) == 0x1.0000000000001234p0);
        try expect(next_after(T80, -0x1.0000000000001234p0, -2.0) == -0x1.0000000000001236p0);
        try expect(next_after(T80, -0x1.0000000000001234p0, 2.0) == -0x1.0000000000001232p0);
        try expect(next_after(T80, -0x1.0000000000001234p0, -0x1.0000000000001234p0) == -0x1.0000000000001234p0);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(next_after(T128, 0x1.0000000000000000000000001234p0, 2.0) == 0x1.0000000000000000000000001235p0);
        try expect(next_after(T128, 0x1.0000000000000000000000001234p0, -2.0) == 0x1.0000000000000000000000001233p0);
        try expect(next_after(T128, 0x1.0000000000000000000000001234p0, 0x1.0000000000000000000000001234p0) == 0x1.0000000000000000000000001234p0);
        try expect(next_after(T128, -0x1.0000000000000000000000001234p0, -2.0) == -0x1.0000000000000000000000001235p0);
        try expect(next_after(T128, -0x1.0000000000000000000000001234p0, 2.0) == -0x1.0000000000000000000000001233p0);
        try expect(next_after(T128, -0x1.0000000000000000000000001234p0, -0x1.0000000000000000000000001234p0) == -0x1.0000000000000000000000001234p0);
    }

    // subnormal -> subnormal
    try expect(next_after(f16, 0x0.234p-14, 1.0) == 0x0.238p-14);
    try expect(next_after(f16, 0x0.234p-14, -1.0) == 0x0.230p-14);
    try expect(next_after(f16, 0x0.234p-14, 0x0.234p-14) == 0x0.234p-14);
    try expect(next_after(f16, -0x0.234p-14, -1.0) == -0x0.238p-14);
    try expect(next_after(f16, -0x0.234p-14, 1.0) == -0x0.230p-14);
    try expect(next_after(f16, -0x0.234p-14, -0x0.234p-14) == -0x0.234p-14);
    try expect(next_after(f32, 0x0.001234p-126, 1.0) == 0x0.001236p-126);
    try expect(next_after(f32, 0x0.001234p-126, -1.0) == 0x0.001232p-126);
    try expect(next_after(f32, 0x0.001234p-126, 0x0.001234p-126) == 0x0.001234p-126);
    try expect(next_after(f32, -0x0.001234p-126, -1.0) == -0x0.001236p-126);
    try expect(next_after(f32, -0x0.001234p-126, 1.0) == -0x0.001232p-126);
    try expect(next_after(f32, -0x0.001234p-126, -0x0.001234p-126) == -0x0.001234p-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(next_after(T64, 0x0.0000000001234p-1022, 1.0) == 0x0.0000000001235p-1022);
        try expect(next_after(T64, 0x0.0000000001234p-1022, -1.0) == 0x0.0000000001233p-1022);
        try expect(next_after(T64, 0x0.0000000001234p-1022, 0x0.0000000001234p-1022) == 0x0.0000000001234p-1022);
        try expect(next_after(T64, -0x0.0000000001234p-1022, -1.0) == -0x0.0000000001235p-1022);
        try expect(next_after(T64, -0x0.0000000001234p-1022, 1.0) == -0x0.0000000001233p-1022);
        try expect(next_after(T64, -0x0.0000000001234p-1022, -0x0.0000000001234p-1022) == -0x0.0000000001234p-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(next_after(T80, 0x0.0000000000001234p-16382, 1.0) == 0x0.0000000000001236p-16382);
        try expect(next_after(T80, 0x0.0000000000001234p-16382, -1.0) == 0x0.0000000000001232p-16382);
        try expect(next_after(T80, 0x0.0000000000001234p-16382, 0x0.0000000000001234p-16382) == 0x0.0000000000001234p-16382);
        try expect(next_after(T80, -0x0.0000000000001234p-16382, -1.0) == -0x0.0000000000001236p-16382);
        try expect(next_after(T80, -0x0.0000000000001234p-16382, 1.0) == -0x0.0000000000001232p-16382);
        try expect(next_after(T80, -0x0.0000000000001234p-16382, -0x0.0000000000001234p-16382) == -0x0.0000000000001234p-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(next_after(T128, 0x0.0000000000000000000000001234p-16382, 1.0) == 0x0.0000000000000000000000001235p-16382);
        try expect(next_after(T128, 0x0.0000000000000000000000001234p-16382, -1.0) == 0x0.0000000000000000000000001233p-16382);
        try expect(next_after(T128, 0x0.0000000000000000000000001234p-16382, 0x0.0000000000000000000000001234p-16382) == 0x0.0000000000000000000000001234p-16382);
        try expect(next_after(T128, -0x0.0000000000000000000000001234p-16382, -1.0) == -0x0.0000000000000000000000001235p-16382);
        try expect(next_after(T128, -0x0.0000000000000000000000001234p-16382, 1.0) == -0x0.0000000000000000000000001233p-16382);
        try expect(next_after(T128, -0x0.0000000000000000000000001234p-16382, -0x0.0000000000000000000000001234p-16382) == -0x0.0000000000000000000000001234p-16382);
    }

    // normal -> normal (change in exponent)
    try expect(next_after(f16, 0x1.FFCp3, math.inf(f16)) == 0x1p4);
    try expect(next_after(f16, 0x1p4, -math.inf(f16)) == 0x1.FFCp3);
    try expect(next_after(f16, -0x1.FFCp3, -math.inf(f16)) == -0x1p4);
    try expect(next_after(f16, -0x1p4, math.inf(f16)) == -0x1.FFCp3);
    try expect(next_after(f32, 0x1.FFFFFEp3, math.inf(f32)) == 0x1p4);
    try expect(next_after(f32, 0x1p4, -math.inf(f32)) == 0x1.FFFFFEp3);
    try expect(next_after(f32, -0x1.FFFFFEp3, -math.inf(f32)) == -0x1p4);
    try expect(next_after(f32, -0x1p4, math.inf(f32)) == -0x1.FFFFFEp3);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(next_after(T64, 0x1.FFFFFFFFFFFFFp3, math.inf(T64)) == 0x1p4);
        try expect(next_after(T64, 0x1p4, -math.inf(T64)) == 0x1.FFFFFFFFFFFFFp3);
        try expect(next_after(T64, -0x1.FFFFFFFFFFFFFp3, -math.inf(T64)) == -0x1p4);
        try expect(next_after(T64, -0x1p4, math.inf(T64)) == -0x1.FFFFFFFFFFFFFp3);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(next_after(T80, 0x1.FFFFFFFFFFFFFFFEp3, math.inf(T80)) == 0x1p4);
        try expect(next_after(T80, 0x1p4, -math.inf(T80)) == 0x1.FFFFFFFFFFFFFFFEp3);
        try expect(next_after(T80, -0x1.FFFFFFFFFFFFFFFEp3, -math.inf(T80)) == -0x1p4);
        try expect(next_after(T80, -0x1p4, math.inf(T80)) == -0x1.FFFFFFFFFFFFFFFEp3);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(next_after(T128, 0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3, math.inf(T128)) == 0x1p4);
        try expect(next_after(T128, 0x1p4, -math.inf(T128)) == 0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3);
        try expect(next_after(T128, -0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3, -math.inf(T128)) == -0x1p4);
        try expect(next_after(T128, -0x1p4, math.inf(T128)) == -0x1.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp3);
    }

    // normal -> subnormal
    try expect(next_after(f16, 0x1p-14, -math.inf(f16)) == 0x0.FFCp-14);
    try expect(next_after(f16, -0x1p-14, math.inf(f16)) == -0x0.FFCp-14);
    try expect(next_after(f32, 0x1p-126, -math.inf(f32)) == 0x0.FFFFFEp-126);
    try expect(next_after(f32, -0x1p-126, math.inf(f32)) == -0x0.FFFFFEp-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(next_after(T64, 0x1p-1022, -math.inf(T64)) == 0x0.FFFFFFFFFFFFFp-1022);
        try expect(next_after(T64, -0x1p-1022, math.inf(T64)) == -0x0.FFFFFFFFFFFFFp-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(next_after(T80, 0x1p-16382, -math.inf(T80)) == 0x0.FFFFFFFFFFFFFFFEp-16382);
        try expect(next_after(T80, -0x1p-16382, math.inf(T80)) == -0x0.FFFFFFFFFFFFFFFEp-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(next_after(T128, 0x1p-16382, -math.inf(T128)) == 0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382);
        try expect(next_after(T128, -0x1p-16382, math.inf(T128)) == -0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382);
    }

    // subnormal -> normal
    try expect(next_after(f16, 0x0.FFCp-14, math.inf(f16)) == 0x1p-14);
    try expect(next_after(f16, -0x0.FFCp-14, -math.inf(f16)) == -0x1p-14);
    try expect(next_after(f32, 0x0.FFFFFEp-126, math.inf(f32)) == 0x1p-126);
    try expect(next_after(f32, -0x0.FFFFFEp-126, -math.inf(f32)) == -0x1p-126);
    inline for (.{f64} ++ if (@bitSizeOf(c_longdouble) == 64) .{c_longdouble} else .{}) |T64| {
        try expect(next_after(T64, 0x0.FFFFFFFFFFFFFp-1022, math.inf(T64)) == 0x1p-1022);
        try expect(next_after(T64, -0x0.FFFFFFFFFFFFFp-1022, -math.inf(T64)) == -0x1p-1022);
    }
    inline for (.{f80} ++ if (@bitSizeOf(c_longdouble) == 80) .{c_longdouble} else .{}) |T80| {
        try expect(next_after(T80, 0x0.FFFFFFFFFFFFFFFEp-16382, math.inf(T80)) == 0x1p-16382);
        try expect(next_after(T80, -0x0.FFFFFFFFFFFFFFFEp-16382, -math.inf(T80)) == -0x1p-16382);
    }
    inline for (.{f128} ++ if (@bitSizeOf(c_longdouble) == 128) .{c_longdouble} else .{}) |T128| {
        try expect(next_after(T128, 0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382, math.inf(T128)) == 0x1p-16382);
        try expect(next_after(T128, -0x0.FFFFFFFFFFFFFFFFFFFFFFFFFFFFp-16382, -math.inf(T128)) == -0x1p-16382);
    }

    // special values
    inline for (.{ f16, f32, f64, f80, f128, c_longdouble }) |T| {
        try expect(bitwise_equal(T, next_after(T, 0.0, 0.0), 0.0));
        try expect(bitwise_equal(T, next_after(T, 0.0, -0.0), -0.0));
        try expect(bitwise_equal(T, next_after(T, -0.0, -0.0), -0.0));
        try expect(bitwise_equal(T, next_after(T, -0.0, 0.0), 0.0));
        try expect(next_after(T, 0.0, math.inf(T)) == math.float_true_min(T));
        try expect(next_after(T, 0.0, -math.inf(T)) == -math.float_true_min(T));
        try expect(next_after(T, -0.0, -math.inf(T)) == -math.float_true_min(T));
        try expect(next_after(T, -0.0, math.inf(T)) == math.float_true_min(T));
        try expect(bitwise_equal(T, next_after(T, math.float_true_min(T), 0.0), 0.0));
        try expect(bitwise_equal(T, next_after(T, math.float_true_min(T), -0.0), 0.0));
        try expect(bitwise_equal(T, next_after(T, math.float_true_min(T), -math.inf(T)), 0.0));
        try expect(bitwise_equal(T, next_after(T, -math.float_true_min(T), -0.0), -0.0));
        try expect(bitwise_equal(T, next_after(T, -math.float_true_min(T), 0.0), -0.0));
        try expect(bitwise_equal(T, next_after(T, -math.float_true_min(T), math.inf(T)), -0.0));
        try expect(next_after(T, math.inf(T), math.inf(T)) == math.inf(T));
        try expect(next_after(T, math.inf(T), -math.inf(T)) == math.float_max(T));
        try expect(next_after(T, math.float_max(T), math.inf(T)) == math.inf(T));
        try expect(next_after(T, -math.inf(T), -math.inf(T)) == -math.inf(T));
        try expect(next_after(T, -math.inf(T), math.inf(T)) == -math.float_max(T));
        try expect(next_after(T, -math.float_max(T), -math.inf(T)) == -math.inf(T));
        try expect(math.is_nan(next_after(T, 1.0, math.nan(T))));
        try expect(math.is_nan(next_after(T, math.nan(T), 1.0)));
        try expect(math.is_nan(next_after(T, math.nan(T), math.nan(T))));
        try expect(math.is_nan(next_after(T, math.inf(T), math.nan(T))));
        try expect(math.is_nan(next_after(T, -math.inf(T), math.nan(T))));
        try expect(math.is_nan(next_after(T, math.nan(T), math.inf(T))));
        try expect(math.is_nan(next_after(T, math.nan(T), -math.inf(T))));
    }
}

/// Helps ensure that 0.0 doesn't compare equal to -0.0.
fn bitwise_equal(comptime T: type, x: T, y: T) bool {
    comptime assert(@typeInfo(T) == .Float);
    const Bits = std.meta.Int(.unsigned, @bitSizeOf(T));
    return @as(Bits, @bit_cast(x)) == @as(Bits, @bit_cast(y));
}
