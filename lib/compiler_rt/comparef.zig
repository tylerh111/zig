const std = @import("std");

pub const LE = enum(i32) {
    Less = -1,
    Equal = 0,
    Greater = 1,

    const Unordered: LE = .Greater;
};

pub const GE = enum(i32) {
    Less = -1,
    Equal = 0,
    Greater = 1,

    const Unordered: GE = .Less;
};

pub inline fn cmpf2(comptime T: type, comptime RT: type, a: T, b: T) RT {
    const bits = @typeInfo(T).Float.bits;
    const srep_t = std.meta.Int(.signed, bits);
    const rep_t = std.meta.Int(.unsigned, bits);

    const significandBits = std.math.float_mantissa_bits(T);
    const exponentBits = std.math.float_exponent_bits(T);
    const signBit = (@as(rep_t, 1) << (significandBits + exponentBits));
    const absMask = signBit - 1;
    const infT = comptime std.math.inf(T);
    const infRep = @as(rep_t, @bit_cast(infT));

    const aInt = @as(srep_t, @bit_cast(a));
    const bInt = @as(srep_t, @bit_cast(b));
    const aAbs = @as(rep_t, @bit_cast(aInt)) & absMask;
    const bAbs = @as(rep_t, @bit_cast(bInt)) & absMask;

    // If either a or b is NaN, they are unordered.
    if (aAbs > infRep or bAbs > infRep) return RT.Unordered;

    // If a and b are both zeros, they are equal.
    if ((aAbs | bAbs) == 0) return .Equal;

    // If at least one of a and b is positive, we get the same result comparing
    // a and b as signed integers as we would with a floating-point compare.
    if ((aInt & bInt) >= 0) {
        if (aInt < bInt) {
            return .Less;
        } else if (aInt == bInt) {
            return .Equal;
        } else return .Greater;
    } else {
        // Otherwise, both are negative, so we need to flip the sense of the
        // comparison to get the correct result.  (This assumes a twos- or ones-
        // complement integer representation; if integers are represented in a
        // sign-magnitude representation, then this flip is incorrect).
        if (aInt > bInt) {
            return .Less;
        } else if (aInt == bInt) {
            return .Equal;
        } else return .Greater;
    }
}

pub inline fn cmp_f80(comptime RT: type, a: f80, b: f80) RT {
    const a_rep = std.math.break_f80(a);
    const b_rep = std.math.break_f80(b);
    const sig_bits = std.math.float_mantissa_bits(f80);
    const int_bit = 0x8000000000000000;
    const sign_bit = 0x8000;
    const special_exp = 0x7FFF;

    // If either a or b is NaN, they are unordered.
    if ((a_rep.exp & special_exp == special_exp and a_rep.fraction ^ int_bit != 0) or
        (b_rep.exp & special_exp == special_exp and b_rep.fraction ^ int_bit != 0))
        return RT.Unordered;

    // If a and b are both zeros, they are equal.
    if ((a_rep.fraction | b_rep.fraction) | ((a_rep.exp | b_rep.exp) & special_exp) == 0)
        return .Equal;

    if (@int_from_bool(a_rep.exp == b_rep.exp) & @int_from_bool(a_rep.fraction == b_rep.fraction) != 0) {
        return .Equal;
    } else if (a_rep.exp & sign_bit != b_rep.exp & sign_bit) {
        // signs are different
        if (@as(i16, @bit_cast(a_rep.exp)) < @as(i16, @bit_cast(b_rep.exp))) {
            return .Less;
        } else {
            return .Greater;
        }
    } else {
        const a_fraction = a_rep.fraction | (@as(u80, a_rep.exp) << sig_bits);
        const b_fraction = b_rep.fraction | (@as(u80, b_rep.exp) << sig_bits);
        if ((a_fraction < b_fraction) == (a_rep.exp & sign_bit == 0)) {
            return .Less;
        } else {
            return .Greater;
        }
    }
}

test "cmp_f80" {
    inline for (.{ LE, GE }) |RT| {
        try std.testing.expect(cmp_f80(RT, 1.0, 1.0) == RT.Equal);
        try std.testing.expect(cmp_f80(RT, 0.0, -0.0) == RT.Equal);
        try std.testing.expect(cmp_f80(RT, 2.0, 4.0) == RT.Less);
        try std.testing.expect(cmp_f80(RT, 2.0, -4.0) == RT.Greater);
        try std.testing.expect(cmp_f80(RT, -2.0, -4.0) == RT.Greater);
        try std.testing.expect(cmp_f80(RT, -2.0, 4.0) == RT.Less);
    }
}

pub inline fn unordcmp(comptime T: type, a: T, b: T) i32 {
    const rep_t = std.meta.Int(.unsigned, @typeInfo(T).Float.bits);

    const significandBits = std.math.float_mantissa_bits(T);
    const exponentBits = std.math.float_exponent_bits(T);
    const signBit = (@as(rep_t, 1) << (significandBits + exponentBits));
    const absMask = signBit - 1;
    const infRep = @as(rep_t, @bit_cast(std.math.inf(T)));

    const aAbs: rep_t = @as(rep_t, @bit_cast(a)) & absMask;
    const bAbs: rep_t = @as(rep_t, @bit_cast(b)) & absMask;

    return @int_from_bool(aAbs > infRep or bAbs > infRep);
}

test {
    _ = @import("comparesf2_test.zig");
    _ = @import("comparedf2_test.zig");
}
