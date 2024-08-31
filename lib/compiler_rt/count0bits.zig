const std = @import("std");
const builtin = @import("builtin");
const is_test = builtin.is_test;
const common = @import("common.zig");

pub const panic = common.panic;

comptime {
    @export(__clzsi2, .{ .name = "__clzsi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__clzdi2, .{ .name = "__clzdi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__clzti2, .{ .name = "__clzti2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ctzsi2, .{ .name = "__ctzsi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ctzdi2, .{ .name = "__ctzdi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ctzti2, .{ .name = "__ctzti2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ffssi2, .{ .name = "__ffssi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ffsdi2, .{ .name = "__ffsdi2", .linkage = common.linkage, .visibility = common.visibility });
    @export(__ffsti2, .{ .name = "__ffsti2", .linkage = common.linkage, .visibility = common.visibility });
}

// clz - count leading zeroes
// - clz_xi2 for unoptimized little and big endian
// - __clzsi2_thumb1: assume a != 0
// - __clzsi2_arm32: assume a != 0

// ctz - count trailing zeroes
// - ctz_xi2 for unoptimized little and big endian

// ffs - find first set
// * ffs = (a == 0) => 0, (a != 0) => ctz + 1
// * dont pay for `if (x == 0) return shift;` inside ctz
// - ffs_xi2 for unoptimized little and big endian

inline fn clz_xi2(comptime T: type, a: T) i32 {
    var x = switch (@bitSizeOf(T)) {
        32 => @as(u32, @bit_cast(a)),
        64 => @as(u64, @bit_cast(a)),
        128 => @as(u128, @bit_cast(a)),
        else => unreachable,
    };
    var n: T = @bitSizeOf(T);
    // Count first bit set using binary search, from Hacker's Delight
    var y: @TypeOf(x) = 0;
    comptime var shift: u8 = @bitSizeOf(T);
    inline while (shift > 0) {
        shift = shift >> 1;
        y = x >> shift;
        if (y != 0) {
            n = n - shift;
            x = y;
        }
    }
    return @int_cast(n - @as(T, @bit_cast(x)));
}

fn __clzsi2_thumb1() callconv(.Naked) void {
    @setRuntimeSafety(false);

    // Similar to the generic version with the last two rounds replaced by a LUT
    asm volatile (
        \\ movs r1, #32
        \\ lsrs r2, r0, #16
        \\ beq 1f
        \\ subs r1, #16
        \\ movs r0, r2
        \\ 1:
        \\ lsrs r2, r0, #8
        \\ beq 1f
        \\ subs r1, #8
        \\ movs r0, r2
        \\ 1:
        \\ lsrs r2, r0, #4
        \\ beq 1f
        \\ subs r1, #4
        \\ movs r0, r2
        \\ 1:
        \\ ldr r3, =LUT
        \\ ldrb r0, [r3, r0]
        \\ subs r0, r1, r0
        \\ bx lr
        \\ .p2align 2
        \\ // Number of bits set in the 0-15 range
        \\ LUT:
        \\ .byte 0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4
    );

    unreachable;
}

fn __clzsi2_arm32() callconv(.Naked) void {
    @setRuntimeSafety(false);

    asm volatile (
        \\ // Assumption: n != 0
        \\ // r0: n
        \\ // r1: count of leading zeros in n + 1
        \\ // r2: scratch register for shifted r0
        \\ mov r1, #1
        \\
        \\ // Basic block:
        \\ // if ((r0 >> SHIFT) == 0)
        \\ //   r1 += SHIFT;
        \\ // else
        \\ //   r0 >>= SHIFT;
        \\ // for descending powers of two as SHIFT.
        \\ lsrs r2, r0, #16
        \\ movne r0, r2
        \\ addeq r1, #16
        \\
        \\ lsrs r2, r0, #8
        \\ movne r0, r2
        \\ addeq r1, #8
        \\
        \\ lsrs r2, r0, #4
        \\ movne r0, r2
        \\ addeq r1, #4
        \\
        \\ lsrs r2, r0, #2
        \\ movne r0, r2
        \\ addeq r1, #2
        \\
        \\ // The basic block invariants at this point are (r0 >> 2) == 0 and
        \\ // r0 != 0. This means 1 <= r0 <= 3 and 0 <= (r0 >> 1) <= 1.
        \\ //
        \\ // r0 | (r0 >> 1) == 0 | (r0 >> 1) == 1 | -(r0 >> 1) | 1 - (r0 >> 1)f
        \\ // ---+----------------+----------------+------------+--------------
        \\ // 1  | 1              | 0              | 0          | 1
        \\ // 2  | 0              | 1              | -1         | 0
        \\ // 3  | 0              | 1              | -1         | 0
        \\ //
        \\ // The r1's initial value of 1 compensates for the 1 here.
        \\ sub r0, r1, r0, lsr #1
        \\ bx lr
    );

    unreachable;
}

fn clzsi2_generic(a: i32) callconv(.C) i32 {
    return clz_xi2(i32, a);
}

pub const __clzsi2 = switch (builtin.cpu.arch) {
    .arm, .armeb, .thumb, .thumbeb => impl: {
        const use_thumb1 =
            (builtin.cpu.arch.is_thumb() or
            std.Target.arm.feature_set_has(builtin.cpu.features, .noarm)) and
            !std.Target.arm.feature_set_has(builtin.cpu.features, .thumb2);

        if (use_thumb1) {
            break :impl __clzsi2_thumb1;
        }
        // From here on we're either targeting Thumb2 or ARM.
        else if (!builtin.cpu.arch.is_thumb()) {
            break :impl __clzsi2_arm32;
        }
        // Use the generic implementation otherwise.
        else break :impl clzsi2_generic;
    },
    else => clzsi2_generic,
};

pub fn __clzdi2(a: i64) callconv(.C) i32 {
    return clz_xi2(i64, a);
}

pub fn __clzti2(a: i128) callconv(.C) i32 {
    return clz_xi2(i128, a);
}

inline fn ctz_xi2(comptime T: type, a: T) i32 {
    var x = switch (@bitSizeOf(T)) {
        32 => @as(u32, @bit_cast(a)),
        64 => @as(u64, @bit_cast(a)),
        128 => @as(u128, @bit_cast(a)),
        else => unreachable,
    };
    var n: T = 1;
    // Number of trailing zeroes as binary search, from Hacker's Delight
    var mask: @TypeOf(x) = std.math.max_int(@TypeOf(x));
    comptime var shift = @bitSizeOf(T);
    if (x == 0) return shift;
    inline while (shift > 1) {
        shift = shift >> 1;
        mask = mask >> shift;
        if ((x & mask) == 0) {
            n = n + shift;
            x = x >> shift;
        }
    }
    return @int_cast(n - @as(T, @bit_cast((x & 1))));
}

pub fn __ctzsi2(a: i32) callconv(.C) i32 {
    return ctz_xi2(i32, a);
}

pub fn __ctzdi2(a: i64) callconv(.C) i32 {
    return ctz_xi2(i64, a);
}

pub fn __ctzti2(a: i128) callconv(.C) i32 {
    return ctz_xi2(i128, a);
}

inline fn ffs_xi2(comptime T: type, a: T) i32 {
    var x: std.meta.Int(.unsigned, @typeInfo(T).Int.bits) = @bit_cast(a);
    var n: T = 1;
    // adapted from Number of trailing zeroes (see ctz_xi2)
    var mask: @TypeOf(x) = std.math.max_int(@TypeOf(x));
    comptime var shift = @bitSizeOf(T);
    // In contrast to ctz return 0
    if (x == 0) return 0;
    inline while (shift > 1) {
        shift = shift >> 1;
        mask = mask >> shift;
        if ((x & mask) == 0) {
            n = n + shift;
            x = x >> shift;
        }
    }
    // return ctz + 1
    return @as(i32, @int_cast(n - @as(T, @bit_cast((x & 1))))) + 1;
}

pub fn __ffssi2(a: i32) callconv(.C) i32 {
    return ffs_xi2(i32, a);
}

pub fn __ffsdi2(a: i64) callconv(.C) i32 {
    return ffs_xi2(i64, a);
}

pub fn __ffsti2(a: i128) callconv(.C) i32 {
    return ffs_xi2(i128, a);
}

test {
    _ = @import("clzsi2_test.zig");
    _ = @import("clzdi2_test.zig");
    _ = @import("clzti2_test.zig");

    _ = @import("ctzsi2_test.zig");
    _ = @import("ctzdi2_test.zig");
    _ = @import("ctzti2_test.zig");

    _ = @import("ffssi2_test.zig");
    _ = @import("ffsdi2_test.zig");
    _ = @import("ffsti2_test.zig");
}
