const Int = @import("std").meta.Int;
const math = @import("std").math;
const Log2Int = math.Log2Int;

pub inline fn int_from_float(comptime I: type, a: anytype) I {
    const F = @TypeOf(a);
    const float_bits = @typeInfo(F).Float.bits;
    const int_bits = @typeInfo(I).Int.bits;
    const rep_t = Int(.unsigned, float_bits);
    const sig_bits = math.float_mantissa_bits(F);
    const exp_bits = math.float_exponent_bits(F);
    const fractional_bits = math.float_fractional_bits(F);

    const implicit_bit = if (F != f80) (@as(rep_t, 1) << sig_bits) else 0;
    const max_exp = (1 << (exp_bits - 1));
    const exp_bias = max_exp - 1;
    const sig_mask = (@as(rep_t, 1) << sig_bits) - 1;

    // Break a into sign, exponent, significand
    const a_rep: rep_t = @bit_cast(a);
    const negative = (a_rep >> (float_bits - 1)) != 0;
    const exponent = @as(i32, @int_cast((a_rep << 1) >> (sig_bits + 1))) - exp_bias;
    const significand: rep_t = (a_rep & sig_mask) | implicit_bit;

    // If the exponent is negative, the result rounds to zero.
    if (exponent < 0) return 0;

    // If the value is too large for the integer type, saturate.
    switch (@typeInfo(I).Int.signedness) {
        .unsigned => {
            if (negative) return 0;
            if (@as(c_uint, @int_cast(exponent)) >= @min(int_bits, max_exp)) return math.max_int(I);
        },
        .signed => if (@as(c_uint, @int_cast(exponent)) >= @min(int_bits - 1, max_exp)) {
            return if (negative) math.min_int(I) else math.max_int(I);
        },
    }

    // If 0 <= exponent < sig_bits, right shift to get the result.
    // Otherwise, shift left.
    var result: I = undefined;
    if (exponent < fractional_bits) {
        result = @int_cast(significand >> @int_cast(fractional_bits - exponent));
    } else {
        result = @as(I, @int_cast(significand)) << @int_cast(exponent - fractional_bits);
    }

    if ((@typeInfo(I).Int.signedness == .signed) and negative)
        return ~result +% 1;
    return result;
}

test {
    _ = @import("int_from_float_test.zig");
}
