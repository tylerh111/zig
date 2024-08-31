const std = @import("std");
const builtin = @import("builtin");
const min_int = std.math.min_int;
const max_int = std.math.max_int;
const expect = std.testing.expect;

test "saturating add" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_sat_add(i8, -3, 10, 7);
            try test_sat_add(i8, 3, -10, -7);
            try test_sat_add(i8, -128, -128, -128);
            try test_sat_add(i2, 1, 1, 1);
            try test_sat_add(i2, 1, -1, 0);
            try test_sat_add(i2, -1, -1, -2);
            try test_sat_add(i64, max_int(i64), 1, max_int(i64));
            try test_sat_add(i8, 127, 127, 127);
            try test_sat_add(u2, 0, 0, 0);
            try test_sat_add(u2, 0, 1, 1);
            try test_sat_add(u8, 3, 10, 13);
            try test_sat_add(u8, 255, 255, 255);
            try test_sat_add(u2, 3, 2, 3);
            try test_sat_add(u3, 7, 1, 7);
        }

        fn test_sat_add(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs +| rhs) == expected);

            var x = lhs;
            x +|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_sat_add(comptime_int, 0, 0, 0);
    try comptime S.test_sat_add(comptime_int, -1, 1, 0);
    try comptime S.test_sat_add(comptime_int, 3, 2, 5);
    try comptime S.test_sat_add(comptime_int, -3, -2, -5);
    try comptime S.test_sat_add(comptime_int, 3, -2, 1);
    try comptime S.test_sat_add(comptime_int, -3, 2, -1);
    try comptime S.test_sat_add(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 1119305249183743626545271163355074748512);
    try comptime S.test_sat_add(comptime_int, 7, -593423721213448152027139550640105366508, -593423721213448152027139550640105366501);
}

test "saturating add 128bit" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_sat_add(i128, max_int(i128), -max_int(i128), 0);
            try test_sat_add(i128, min_int(i128), max_int(i128), -1);
            try test_sat_add(u128, max_int(u128), 1, max_int(u128));
        }
        fn test_sat_add(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs +| rhs) == expected);

            var x = lhs;
            x +|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}

test "saturating subtraction" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_sat_sub(i8, -3, 10, -13);
            try test_sat_sub(i8, -3, -10, 7);
            try test_sat_sub(i8, -128, -128, 0);
            try test_sat_sub(i8, -1, 127, -128);
            try test_sat_sub(i2, 1, 1, 0);
            try test_sat_sub(i2, 1, -1, 1);
            try test_sat_sub(i2, -2, -2, 0);
            try test_sat_sub(i64, min_int(i64), 1, min_int(i64));
            try test_sat_sub(u2, 0, 0, 0);
            try test_sat_sub(u2, 0, 1, 0);
            try test_sat_sub(u5, 0, 31, 0);
            try test_sat_sub(u8, 10, 3, 7);
            try test_sat_sub(u8, 0, 255, 0);
        }

        fn test_sat_sub(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs -| rhs) == expected);

            var x = lhs;
            x -|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_sat_sub(comptime_int, 0, 0, 0);
    try comptime S.test_sat_sub(comptime_int, 1, 1, 0);
    try comptime S.test_sat_sub(comptime_int, 3, 2, 1);
    try comptime S.test_sat_sub(comptime_int, -3, -2, -1);
    try comptime S.test_sat_sub(comptime_int, 3, -2, 5);
    try comptime S.test_sat_sub(comptime_int, -3, 2, -5);
    try comptime S.test_sat_sub(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 182846383813587550256162760261375991602);
    try comptime S.test_sat_sub(comptime_int, 7, -593423721213448152027139550640105366508, 593423721213448152027139550640105366515);
}

test "saturating subtraction 128bit" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_sat_sub(i128, max_int(i128), -1, max_int(i128));
            try test_sat_sub(i128, min_int(i128), -max_int(i128), -1);
            try test_sat_sub(u128, 0, max_int(u128), 0);
        }

        fn test_sat_sub(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs -| rhs) == expected);

            var x = lhs;
            x -|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}

test "saturating multiplication" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c and comptime builtin.cpu.arch.is_arm_or_thumb()) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .wasm32) {
        // https://github.com/ziglang/zig/issues/9660
        return error.SkipZigTest;
    }

    const S = struct {
        fn do_the_test() !void {
            try test_sat_mul(i8, -3, 10, -30);
            try test_sat_mul(i4, 2, 4, 7);
            try test_sat_mul(i8, 2, 127, 127);
            try test_sat_mul(i8, -128, -128, 127);
            try test_sat_mul(i8, max_int(i8), max_int(i8), max_int(i8));
            try test_sat_mul(i16, max_int(i16), -1, min_int(i16) + 1);
            try test_sat_mul(i128, max_int(i128), -1, min_int(i128) + 1);
            try test_sat_mul(i128, min_int(i128), -1, max_int(i128));
            try test_sat_mul(u8, 10, 3, 30);
            try test_sat_mul(u8, 2, 255, 255);
            try test_sat_mul(u128, max_int(u128), max_int(u128), max_int(u128));
        }

        fn test_sat_mul(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs *| rhs) == expected);

            var x = lhs;
            x *|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_sat_mul(comptime_int, 0, 0, 0);
    try comptime S.test_sat_mul(comptime_int, 3, 2, 6);
    try comptime S.test_sat_mul(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 304852860194144160265083087140337419215516305999637969803722975979232817921935);
    try comptime S.test_sat_mul(comptime_int, 7, -593423721213448152027139550640105366508, -4153966048494137064189976854480737565556);
}

test "saturating shift-left" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_sat_shl(i8, 1, 2, 4);
            try test_sat_shl(i8, 127, 1, 127);
            try test_sat_shl(i8, -128, 1, -128);
            // TODO: remove this check once #9668 is completed
            if (builtin.cpu.arch != .wasm32) {
                // skip testing ints > 64 bits on wasm due to miscompilation / wasmtime ci error
                try test_sat_shl(i128, max_int(i128), 64, max_int(i128));
                try test_sat_shl(u128, max_int(u128), 64, max_int(u128));
            }
            try test_sat_shl(u8, 1, 2, 4);
            try test_sat_shl(u8, 255, 1, 255);
        }

        fn test_sat_shl(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs <<| rhs) == expected);

            var x = lhs;
            x <<|= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_sat_shl(comptime_int, 0, 0, 0);
    try comptime S.test_sat_shl(comptime_int, 1, 2, 4);
    try comptime S.test_sat_shl(comptime_int, 13, 150, 18554220005177478453757717602843436772975706112);
    try comptime S.test_sat_shl(comptime_int, -582769, 180, -893090893854873184096635538665358532628308979495815656505344);
}

test "saturating shl uses the LHS type" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const lhs_const: u8 = 1;
    var lhs_var: u8 = 1;
    _ = &lhs_var;

    const rhs_const: usize = 8;
    var rhs_var: usize = 8;
    _ = &rhs_var;

    try expect((lhs_const <<| 8) == 255);
    try expect((lhs_const <<| rhs_const) == 255);
    try expect((lhs_const <<| rhs_var) == 255);

    try expect((lhs_var <<| 8) == 255);
    try expect((lhs_var <<| rhs_const) == 255);
    try expect((lhs_var <<| rhs_var) == 255);

    try expect((@as(u8, 1) <<| 8) == 255);
    try expect((@as(u8, 1) <<| rhs_const) == 255);
    try expect((@as(u8, 1) <<| rhs_var) == 255);

    try expect((1 <<| @as(u8, 200)) == 1606938044258990275541962092341162602522202993782792835301376);
}
