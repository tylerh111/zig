const std = @import("std");
const assert = std.debug.assert;
const BigIntConst = std.math.big.int.Const;
const BigIntMutable = std.math.big.int.Mutable;
const backend = @import("../backend.zig");
const Interner = backend.Interner;
const BigIntSpace = Interner.Tag.Int.BigIntSpace;
const Compilation = @import("Compilation.zig");
const Type = @import("Type.zig");
const target_util = @import("target.zig");

const Value = @This();

opt_ref: Interner.OptRef = .none,

pub const zero = Value{ .opt_ref = .zero };
pub const one = Value{ .opt_ref = .one };
pub const @"null" = Value{ .opt_ref = .null };

pub fn intern(comp: *Compilation, k: Interner.Key) !Value {
    const r = try comp.interner.put(comp.gpa, k);
    return .{ .opt_ref = @enumFromInt(@int_from_enum(r)) };
}

pub fn int(i: anytype, comp: *Compilation) !Value {
    const info = @typeInfo(@TypeOf(i));
    if (info == .ComptimeInt or info.Int.signedness == .unsigned) {
        return intern(comp, .{ .int = .{ .u64 = i } });
    } else {
        return intern(comp, .{ .int = .{ .i64 = i } });
    }
}

pub fn ref(v: Value) Interner.Ref {
    std.debug.assert(v.opt_ref != .none);
    return @enumFromInt(@int_from_enum(v.opt_ref));
}

pub fn is(v: Value, tag: std.meta.Tag(Interner.Key), comp: *const Compilation) bool {
    if (v.opt_ref == .none) return false;
    return comp.interner.get(v.ref()) == tag;
}

/// Number of bits needed to hold `v`.
/// Asserts that `v` is not negative
pub fn min_unsigned_bits(v: Value, comp: *const Compilation) usize {
    var space: BigIntSpace = undefined;
    const big = v.to_big_int(&space, comp);
    assert(big.positive);
    return big.bit_count_abs();
}

test "min_unsigned_bits" {
    const Test = struct {
        fn check_int_bits(comp: *Compilation, v: u64, expected: usize) !void {
            const val = try intern(comp, .{ .int = .{ .u64 = v } });
            try std.testing.expect_equal(expected, val.min_unsigned_bits(comp));
        }
    };

    var comp = Compilation.init(std.testing.allocator);
    defer comp.deinit();
    const target_query = try std.Target.Query.parse(.{ .arch_os_abi = "x86_64-linux-gnu" });
    comp.target = try std.zig.system.resolve_target_query(target_query);

    try Test.check_int_bits(&comp, 0, 0);
    try Test.check_int_bits(&comp, 1, 1);
    try Test.check_int_bits(&comp, 2, 2);
    try Test.check_int_bits(&comp, std.math.max_int(i8), 7);
    try Test.check_int_bits(&comp, std.math.max_int(u8), 8);
    try Test.check_int_bits(&comp, std.math.max_int(i16), 15);
    try Test.check_int_bits(&comp, std.math.max_int(u16), 16);
    try Test.check_int_bits(&comp, std.math.max_int(i32), 31);
    try Test.check_int_bits(&comp, std.math.max_int(u32), 32);
    try Test.check_int_bits(&comp, std.math.max_int(i64), 63);
    try Test.check_int_bits(&comp, std.math.max_int(u64), 64);
}

/// Minimum number of bits needed to represent `v` in 2's complement notation
/// Asserts that `v` is negative.
pub fn min_signed_bits(v: Value, comp: *const Compilation) usize {
    var space: BigIntSpace = undefined;
    const big = v.to_big_int(&space, comp);
    assert(!big.positive);
    return big.bit_count_twos_comp();
}

test "min_signed_bits" {
    const Test = struct {
        fn check_int_bits(comp: *Compilation, v: i64, expected: usize) !void {
            const val = try intern(comp, .{ .int = .{ .i64 = v } });
            try std.testing.expect_equal(expected, val.min_signed_bits(comp));
        }
    };

    var comp = Compilation.init(std.testing.allocator);
    defer comp.deinit();
    const target_query = try std.Target.Query.parse(.{ .arch_os_abi = "x86_64-linux-gnu" });
    comp.target = try std.zig.system.resolve_target_query(target_query);

    try Test.check_int_bits(&comp, -1, 1);
    try Test.check_int_bits(&comp, -2, 2);
    try Test.check_int_bits(&comp, -10, 5);
    try Test.check_int_bits(&comp, -101, 8);
    try Test.check_int_bits(&comp, std.math.min_int(i8), 8);
    try Test.check_int_bits(&comp, std.math.min_int(i16), 16);
    try Test.check_int_bits(&comp, std.math.min_int(i32), 32);
    try Test.check_int_bits(&comp, std.math.min_int(i64), 64);
}

pub const FloatToIntChangeKind = enum {
    /// value did not change
    none,
    /// floating point number too small or large for destination integer type
    out_of_range,
    /// tried to convert a NaN or Infinity
    overflow,
    /// fractional value was converted to zero
    nonzero_to_zero,
    /// fractional part truncated
    value_changed,
};

/// Converts the stored value from a float to an integer.
/// `.none` value remains unchanged.
pub fn float_to_int(v: *Value, dest_ty: Type, comp: *Compilation) !FloatToIntChangeKind {
    if (v.opt_ref == .none) return .none;

    const float_val = v.to_float(f128, comp);
    const was_zero = float_val == 0;

    if (dest_ty.is(.bool)) {
        const was_one = float_val == 1.0;
        v.* = from_bool(!was_zero);
        if (was_zero or was_one) return .none;
        return .value_changed;
    } else if (dest_ty.is_unsigned_int(comp) and v.compare(.lt, zero, comp)) {
        v.* = zero;
        return .out_of_range;
    }

    const had_fraction = @rem(float_val, 1) != 0;
    const is_negative = std.math.signbit(float_val);
    const floored = @floor(@abs(float_val));

    var rational = try std.math.big.Rational.init(comp.gpa);
    defer rational.deinit();
    rational.set_float(f128, floored) catch |err| switch (err) {
        error.NonFiniteFloat => {
            v.* = .{};
            return .overflow;
        },
        error.OutOfMemory => return error.OutOfMemory,
    };

    // The float is reduced in rational.set_float, so we assert that denominator is equal to one
    const big_one = std.math.big.int.Const{ .limbs = &.{1}, .positive = true };
    assert(rational.q.to_const().eql_abs(big_one));

    if (is_negative) {
        rational.negate();
    }

    const signedness = dest_ty.signedness(comp);
    const bits: usize = @int_cast(dest_ty.bit_sizeof(comp).?);

    // rational.p.truncate(rational.p.to_const(), signedness: Signedness, bit_count: usize)
    const fits = rational.p.fits_in_twos_comp(signedness, bits);
    v.* = try intern(comp, .{ .int = .{ .big_int = rational.p.to_const() } });
    try rational.p.truncate(&rational.p, signedness, bits);

    if (!was_zero and v.is_zero(comp)) return .nonzero_to_zero;
    if (!fits) return .out_of_range;
    if (had_fraction) return .value_changed;
    return .none;
}

/// Converts the stored value from an integer to a float.
/// `.none` value remains unchanged.
pub fn int_to_float(v: *Value, dest_ty: Type, comp: *Compilation) !void {
    if (v.opt_ref == .none) return;
    const bits = dest_ty.bit_sizeof(comp).?;
    return switch (comp.interner.get(v.ref()).int) {
        inline .u64, .i64 => |data| {
            const f: Interner.Key.Float = switch (bits) {
                16 => .{ .f16 = @float_from_int(data) },
                32 => .{ .f32 = @float_from_int(data) },
                64 => .{ .f64 = @float_from_int(data) },
                80 => .{ .f80 = @float_from_int(data) },
                128 => .{ .f128 = @float_from_int(data) },
                else => unreachable,
            };
            v.* = try intern(comp, .{ .float = f });
        },
        .big_int => |data| {
            const big_f = big_int_to_float(data.limbs, data.positive);
            const f: Interner.Key.Float = switch (bits) {
                16 => .{ .f16 = @float_cast(big_f) },
                32 => .{ .f32 = @float_cast(big_f) },
                64 => .{ .f64 = @float_cast(big_f) },
                80 => .{ .f80 = @float_cast(big_f) },
                128 => .{ .f128 = @float_cast(big_f) },
                else => unreachable,
            };
            v.* = try intern(comp, .{ .float = f });
        },
    };
}

/// Truncates or extends bits based on type.
/// `.none` value remains unchanged.
pub fn int_cast(v: *Value, dest_ty: Type, comp: *Compilation) !void {
    if (v.opt_ref == .none) return;
    const bits: usize = @int_cast(dest_ty.bit_sizeof(comp).?);
    var space: BigIntSpace = undefined;
    const big = v.to_big_int(&space, comp);

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(@max(big.bit_count_twos_comp(), bits)),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.truncate(big, dest_ty.signedness(comp), bits);

    v.* = try intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

/// Converts the stored value to a float of the specified type
/// `.none` value remains unchanged.
pub fn float_cast(v: *Value, dest_ty: Type, comp: *Compilation) !void {
    if (v.opt_ref == .none) return;
    // TODO complex values
    const bits = dest_ty.make_real().bit_sizeof(comp).?;
    const f: Interner.Key.Float = switch (bits) {
        16 => .{ .f16 = v.to_float(f16, comp) },
        32 => .{ .f32 = v.to_float(f32, comp) },
        64 => .{ .f64 = v.to_float(f64, comp) },
        80 => .{ .f80 = v.to_float(f80, comp) },
        128 => .{ .f128 = v.to_float(f128, comp) },
        else => unreachable,
    };
    v.* = try intern(comp, .{ .float = f });
}

pub fn to_float(v: Value, comptime T: type, comp: *const Compilation) T {
    return switch (comp.interner.get(v.ref())) {
        .int => |repr| switch (repr) {
            inline .u64, .i64 => |data| @float_from_int(data),
            .big_int => |data| @float_cast(big_int_to_float(data.limbs, data.positive)),
        },
        .float => |repr| switch (repr) {
            inline else => |data| @float_cast(data),
        },
        else => unreachable,
    };
}

fn big_int_to_float(limbs: []const std.math.big.Limb, positive: bool) f128 {
    if (limbs.len == 0) return 0;

    const base = std.math.max_int(std.math.big.Limb) + 1;
    var result: f128 = 0;
    var i: usize = limbs.len;
    while (i != 0) {
        i -= 1;
        const limb: f128 = @as(f128, @float_from_int(limbs[i]));
        result = @mul_add(f128, base, result, limb);
    }
    if (positive) {
        return result;
    } else {
        return -result;
    }
}

pub fn to_big_int(val: Value, space: *BigIntSpace, comp: *const Compilation) BigIntConst {
    return switch (comp.interner.get(val.ref()).int) {
        inline .u64, .i64 => |x| BigIntMutable.init(&space.limbs, x).to_const(),
        .big_int => |b| b,
    };
}

pub fn is_zero(v: Value, comp: *const Compilation) bool {
    if (v.opt_ref == .none) return false;
    switch (v.ref()) {
        .zero => return true,
        .one => return false,
        .null => return target_util.null_repr(comp.target) == 0,
        else => {},
    }
    const key = comp.interner.get(v.ref());
    switch (key) {
        .float => |repr| switch (repr) {
            inline else => |data| return data == 0,
        },
        .int => |repr| switch (repr) {
            inline .i64, .u64 => |data| return data == 0,
            .big_int => |data| return data.eql_zero(),
        },
        .bytes => return false,
        else => unreachable,
    }
}

/// Converts value to zero or one;
/// `.none` value remains unchanged.
pub fn bool_cast(v: *Value, comp: *const Compilation) void {
    if (v.opt_ref == .none) return;
    v.* = from_bool(v.to_bool(comp));
}

pub fn from_bool(b: bool) Value {
    return if (b) one else zero;
}

pub fn to_bool(v: Value, comp: *const Compilation) bool {
    return !v.is_zero(comp);
}

pub fn to_int(v: Value, comptime T: type, comp: *const Compilation) ?T {
    if (v.opt_ref == .none) return null;
    if (comp.interner.get(v.ref()) != .int) return null;
    var space: BigIntSpace = undefined;
    const big_int = v.to_big_int(&space, comp);
    return big_int.to(T) catch null;
}

pub fn add(res: *Value, lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !bool {
    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    if (ty.is_float()) {
        const f: Interner.Key.Float = switch (bits) {
            16 => .{ .f16 = lhs.to_float(f16, comp) + rhs.to_float(f16, comp) },
            32 => .{ .f32 = lhs.to_float(f32, comp) + rhs.to_float(f32, comp) },
            64 => .{ .f64 = lhs.to_float(f64, comp) + rhs.to_float(f64, comp) },
            80 => .{ .f80 = lhs.to_float(f80, comp) + rhs.to_float(f80, comp) },
            128 => .{ .f128 = lhs.to_float(f128, comp) + rhs.to_float(f128, comp) },
            else => unreachable,
        };
        res.* = try intern(comp, .{ .float = f });
        return false;
    } else {
        var lhs_space: BigIntSpace = undefined;
        var rhs_space: BigIntSpace = undefined;
        const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
        const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

        const limbs = try comp.gpa.alloc(
            std.math.big.Limb,
            std.math.big.int.calc_twos_comp_limb_count(bits),
        );
        defer comp.gpa.free(limbs);
        var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

        const overflowed = result_bigint.add_wrap(lhs_bigint, rhs_bigint, ty.signedness(comp), bits);
        res.* = try intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
        return overflowed;
    }
}

pub fn sub(res: *Value, lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !bool {
    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    if (ty.is_float()) {
        const f: Interner.Key.Float = switch (bits) {
            16 => .{ .f16 = lhs.to_float(f16, comp) - rhs.to_float(f16, comp) },
            32 => .{ .f32 = lhs.to_float(f32, comp) - rhs.to_float(f32, comp) },
            64 => .{ .f64 = lhs.to_float(f64, comp) - rhs.to_float(f64, comp) },
            80 => .{ .f80 = lhs.to_float(f80, comp) - rhs.to_float(f80, comp) },
            128 => .{ .f128 = lhs.to_float(f128, comp) - rhs.to_float(f128, comp) },
            else => unreachable,
        };
        res.* = try intern(comp, .{ .float = f });
        return false;
    } else {
        var lhs_space: BigIntSpace = undefined;
        var rhs_space: BigIntSpace = undefined;
        const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
        const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

        const limbs = try comp.gpa.alloc(
            std.math.big.Limb,
            std.math.big.int.calc_twos_comp_limb_count(bits),
        );
        defer comp.gpa.free(limbs);
        var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

        const overflowed = result_bigint.sub_wrap(lhs_bigint, rhs_bigint, ty.signedness(comp), bits);
        res.* = try intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
        return overflowed;
    }
}

pub fn mul(res: *Value, lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !bool {
    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    if (ty.is_float()) {
        const f: Interner.Key.Float = switch (bits) {
            16 => .{ .f16 = lhs.to_float(f16, comp) * rhs.to_float(f16, comp) },
            32 => .{ .f32 = lhs.to_float(f32, comp) * rhs.to_float(f32, comp) },
            64 => .{ .f64 = lhs.to_float(f64, comp) * rhs.to_float(f64, comp) },
            80 => .{ .f80 = lhs.to_float(f80, comp) * rhs.to_float(f80, comp) },
            128 => .{ .f128 = lhs.to_float(f128, comp) * rhs.to_float(f128, comp) },
            else => unreachable,
        };
        res.* = try intern(comp, .{ .float = f });
        return false;
    } else {
        var lhs_space: BigIntSpace = undefined;
        var rhs_space: BigIntSpace = undefined;
        const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
        const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

        const limbs = try comp.gpa.alloc(
            std.math.big.Limb,
            lhs_bigint.limbs.len + rhs_bigint.limbs.len,
        );
        defer comp.gpa.free(limbs);
        var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };

        const limbs_buffer = try comp.gpa.alloc(
            std.math.big.Limb,
            std.math.big.int.calc_mul_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len, 1),
        );
        defer comp.gpa.free(limbs_buffer);

        result_bigint.mul(lhs_bigint, rhs_bigint, limbs_buffer, comp.gpa);

        const signedness = ty.signedness(comp);
        const overflowed = !result_bigint.to_const().fits_in_twos_comp(signedness, bits);
        if (overflowed) {
            result_bigint.truncate(result_bigint.to_const(), signedness, bits);
        }
        res.* = try intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
        return overflowed;
    }
}

/// caller guarantees rhs != 0
pub fn div(res: *Value, lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !bool {
    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    if (ty.is_float()) {
        const f: Interner.Key.Float = switch (bits) {
            16 => .{ .f16 = lhs.to_float(f16, comp) / rhs.to_float(f16, comp) },
            32 => .{ .f32 = lhs.to_float(f32, comp) / rhs.to_float(f32, comp) },
            64 => .{ .f64 = lhs.to_float(f64, comp) / rhs.to_float(f64, comp) },
            80 => .{ .f80 = lhs.to_float(f80, comp) / rhs.to_float(f80, comp) },
            128 => .{ .f128 = lhs.to_float(f128, comp) / rhs.to_float(f128, comp) },
            else => unreachable,
        };
        res.* = try intern(comp, .{ .float = f });
        return false;
    } else {
        var lhs_space: BigIntSpace = undefined;
        var rhs_space: BigIntSpace = undefined;
        const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
        const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

        const limbs_q = try comp.gpa.alloc(
            std.math.big.Limb,
            lhs_bigint.limbs.len,
        );
        defer comp.gpa.free(limbs_q);
        var result_q = BigIntMutable{ .limbs = limbs_q, .positive = undefined, .len = undefined };

        const limbs_r = try comp.gpa.alloc(
            std.math.big.Limb,
            rhs_bigint.limbs.len,
        );
        defer comp.gpa.free(limbs_r);
        var result_r = BigIntMutable{ .limbs = limbs_r, .positive = undefined, .len = undefined };

        const limbs_buffer = try comp.gpa.alloc(
            std.math.big.Limb,
            std.math.big.int.calc_div_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
        );
        defer comp.gpa.free(limbs_buffer);

        result_q.div_trunc(&result_r, lhs_bigint, rhs_bigint, limbs_buffer);

        res.* = try intern(comp, .{ .int = .{ .big_int = result_q.to_const() } });
        return !result_q.to_const().fits_in_twos_comp(ty.signedness(comp), bits);
    }
}

/// caller guarantees rhs != 0
/// caller guarantees lhs != std.math.min_int(T) OR rhs != -1
pub fn rem(lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !Value {
    var lhs_space: BigIntSpace = undefined;
    var rhs_space: BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

    const signedness = ty.signedness(comp);
    if (signedness == .signed) {
        var spaces: [3]BigIntSpace = undefined;
        const min_val = BigIntMutable.init(&spaces[0].limbs, ty.min_int(comp)).to_const();
        const negative = BigIntMutable.init(&spaces[1].limbs, -1).to_const();
        const big_one = BigIntMutable.init(&spaces[2].limbs, 1).to_const();
        if (lhs_bigint.eql(min_val) and rhs_bigint.eql(negative)) {
            return .{};
        } else if (rhs_bigint.order(big_one).compare(.lt)) {
            // lhs - @div_trunc(lhs, rhs) * rhs
            var tmp: Value = undefined;
            _ = try tmp.div(lhs, rhs, ty, comp);
            _ = try tmp.mul(tmp, rhs, ty, comp);
            _ = try tmp.sub(lhs, tmp, ty, comp);
            return tmp;
        }
    }

    const limbs_q = try comp.gpa.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len,
    );
    defer comp.gpa.free(limbs_q);
    var result_q = BigIntMutable{ .limbs = limbs_q, .positive = undefined, .len = undefined };

    const limbs_r = try comp.gpa.alloc(
        std.math.big.Limb,
        rhs_bigint.limbs.len,
    );
    defer comp.gpa.free(limbs_r);
    var result_r = BigIntMutable{ .limbs = limbs_r, .positive = undefined, .len = undefined };

    const limbs_buffer = try comp.gpa.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_div_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    defer comp.gpa.free(limbs_buffer);

    result_q.div_trunc(&result_r, lhs_bigint, rhs_bigint, limbs_buffer);
    return intern(comp, .{ .int = .{ .big_int = result_r.to_const() } });
}

pub fn bit_or(lhs: Value, rhs: Value, comp: *Compilation) !Value {
    var lhs_space: BigIntSpace = undefined;
    var rhs_space: BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.bit_or(lhs_bigint, rhs_bigint);
    return intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

pub fn bit_xor(lhs: Value, rhs: Value, comp: *Compilation) !Value {
    var lhs_space: BigIntSpace = undefined;
    var rhs_space: BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.bit_xor(lhs_bigint, rhs_bigint);
    return intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

pub fn bit_and(lhs: Value, rhs: Value, comp: *Compilation) !Value {
    var lhs_space: BigIntSpace = undefined;
    var rhs_space: BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const rhs_bigint = rhs.to_big_int(&rhs_space, comp);

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.bit_and(lhs_bigint, rhs_bigint);
    return intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

pub fn bit_not(val: Value, ty: Type, comp: *Compilation) !Value {
    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    var val_space: Value.BigIntSpace = undefined;
    const val_bigint = val.to_big_int(&val_space, comp);

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(bits),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.bit_not_wrap(val_bigint, ty.signedness(comp), bits);
    return intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

pub fn shl(res: *Value, lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !bool {
    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const shift = rhs.to_int(usize, comp) orelse std.math.max_int(usize);

    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    if (shift > bits) {
        if (lhs_bigint.positive) {
            res.* = try intern(comp, .{ .int = .{ .u64 = ty.max_int(comp) } });
        } else {
            res.* = try intern(comp, .{ .int = .{ .i64 = ty.min_int(comp) } });
        }
        return true;
    }

    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len + (shift / (@size_of(std.math.big.Limb) * 8)) + 1,
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.shift_left(lhs_bigint, shift);
    const signedness = ty.signedness(comp);
    const overflowed = !result_bigint.to_const().fits_in_twos_comp(signedness, bits);
    if (overflowed) {
        result_bigint.truncate(result_bigint.to_const(), signedness, bits);
    }
    res.* = try intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
    return overflowed;
}

pub fn shr(lhs: Value, rhs: Value, ty: Type, comp: *Compilation) !Value {
    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, comp);
    const shift = rhs.to_int(usize, comp) orelse return zero;

    const result_limbs = lhs_bigint.limbs.len -| (shift / (@size_of(std.math.big.Limb) * 8));
    if (result_limbs == 0) {
        // The shift is enough to remove all the bits from the number, which means the
        // result is 0 or -1 depending on the sign.
        if (lhs_bigint.positive) {
            return zero;
        } else {
            return intern(comp, .{ .int = .{ .i64 = -1 } });
        }
    }

    const bits: usize = @int_cast(ty.bit_sizeof(comp).?);
    const limbs = try comp.gpa.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(bits),
    );
    defer comp.gpa.free(limbs);
    var result_bigint = std.math.big.int.Mutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.shift_right(lhs_bigint, shift);
    return intern(comp, .{ .int = .{ .big_int = result_bigint.to_const() } });
}

pub fn compare(lhs: Value, op: std.math.CompareOperator, rhs: Value, comp: *const Compilation) bool {
    if (op == .eq) {
        return lhs.opt_ref == rhs.opt_ref;
    } else if (lhs.opt_ref == rhs.opt_ref) {
        return std.math.Order.eq.compare(op);
    }

    const lhs_key = comp.interner.get(lhs.ref());
    const rhs_key = comp.interner.get(rhs.ref());
    if (lhs_key == .float or rhs_key == .float) {
        const lhs_f128 = lhs.to_float(f128, comp);
        const rhs_f128 = rhs.to_float(f128, comp);
        return std.math.compare(lhs_f128, op, rhs_f128);
    }

    var lhs_bigint_space: BigIntSpace = undefined;
    var rhs_bigint_space: BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_bigint_space, comp);
    const rhs_bigint = rhs.to_big_int(&rhs_bigint_space, comp);
    return lhs_bigint.order(rhs_bigint).compare(op);
}

pub fn print(v: Value, ty: Type, comp: *const Compilation, w: anytype) @TypeOf(w).Error!void {
    if (ty.is(.bool)) {
        return w.write_all(if (v.is_zero(comp)) "false" else "true");
    }
    const key = comp.interner.get(v.ref());
    switch (key) {
        .null => return w.write_all("nullptr_t"),
        .int => |repr| switch (repr) {
            inline else => |x| return w.print("{d}", .{x}),
        },
        .float => |repr| switch (repr) {
            .f16 => |x| return w.print("{d}", .{@round(@as(f64, @float_cast(x)) * 1000) / 1000}),
            .f32 => |x| return w.print("{d}", .{@round(@as(f64, @float_cast(x)) * 1000000) / 1000000}),
            inline else => |x| return w.print("{d}", .{@as(f64, @float_cast(x))}),
        },
        .bytes => |b| return print_string(b, ty, comp, w),
        else => unreachable, // not a value
    }
}

pub fn print_string(bytes: []const u8, ty: Type, comp: *const Compilation, w: anytype) @TypeOf(w).Error!void {
    const size: Compilation.CharUnitSize = @enumFromInt(ty.elem_type().sizeof(comp).?);
    const without_null = bytes[0 .. bytes.len - @int_from_enum(size)];
    switch (size) {
        inline .@"1", .@"2" => |sz| {
            const data_slice: []const sz.Type() = @align_cast(std.mem.bytes_as_slice(sz.Type(), without_null));
            const formatter = if (sz == .@"1") std.zig.fmt_escapes(data_slice) else std.unicode.fmtUtf16le(data_slice);
            try w.print("\"{}\"", .{formatter});
        },
        .@"4" => {
            try w.write_byte('"');
            const data_slice = std.mem.bytes_as_slice(u32, without_null);
            var buf: [4]u8 = undefined;
            for (data_slice) |item| {
                if (item <= std.math.max_int(u21) and std.unicode.utf8_valid_codepoint(@int_cast(item))) {
                    const codepoint: u21 = @int_cast(item);
                    const written = std.unicode.utf8_encode(codepoint, &buf) catch unreachable;
                    try w.print("{s}", .{buf[0..written]});
                } else {
                    try w.print("\\x{x}", .{item});
                }
            }
            try w.write_byte('"');
        },
    }
}
