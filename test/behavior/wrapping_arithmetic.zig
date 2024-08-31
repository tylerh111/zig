const std = @import("std");
const builtin = @import("builtin");
const min_int = std.math.min_int;
const max_int = std.math.max_int;
const expect = std.testing.expect;

test "wrapping add" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_wrap_add(i8, -3, 10, 7);
            try test_wrap_add(i8, -128, -128, 0);
            try test_wrap_add(i2, 1, 1, -2);
            try test_wrap_add(i64, max_int(i64), 1, min_int(i64));
            try test_wrap_add(i128, max_int(i128), -max_int(i128), 0);
            try test_wrap_add(i128, min_int(i128), max_int(i128), -1);
            try test_wrap_add(i8, 127, 127, -2);
            try test_wrap_add(u8, 3, 10, 13);
            try test_wrap_add(u8, 255, 255, 254);
            try test_wrap_add(u2, 3, 2, 1);
            try test_wrap_add(u3, 7, 1, 0);
            try test_wrap_add(u128, max_int(u128), 1, min_int(u128));
        }

        fn test_wrap_add(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs +% rhs) == expected);

            var x = lhs;
            x +%= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_wrap_add(comptime_int, 0, 0, 0);
    try comptime S.test_wrap_add(comptime_int, 3, 2, 5);
    try comptime S.test_wrap_add(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 1119305249183743626545271163355074748512);
    try comptime S.test_wrap_add(comptime_int, 7, -593423721213448152027139550640105366508, -593423721213448152027139550640105366501);
}

test "wrapping subtraction" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_wrap_sub(i8, -3, 10, -13);
            try test_wrap_sub(i8, -128, -128, 0);
            try test_wrap_sub(i8, -1, 127, -128);
            try test_wrap_sub(i64, min_int(i64), 1, max_int(i64));
            try test_wrap_sub(i128, max_int(i128), -1, min_int(i128));
            try test_wrap_sub(i128, min_int(i128), -max_int(i128), -1);
            try test_wrap_sub(u8, 10, 3, 7);
            try test_wrap_sub(u8, 0, 255, 1);
            try test_wrap_sub(u5, 0, 31, 1);
            try test_wrap_sub(u128, 0, max_int(u128), 1);
        }

        fn test_wrap_sub(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs -% rhs) == expected);

            var x = lhs;
            x -%= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_wrap_sub(comptime_int, 0, 0, 0);
    try comptime S.test_wrap_sub(comptime_int, 3, 2, 1);
    try comptime S.test_wrap_sub(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 182846383813587550256162760261375991602);
    try comptime S.test_wrap_sub(comptime_int, 7, -593423721213448152027139550640105366508, 593423721213448152027139550640105366515);
}

test "wrapping multiplication" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // TODO: once #9660 has been solved, remove this line
    if (builtin.cpu.arch == .wasm32) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try test_wrap_mul(i8, -3, 10, -30);
            try test_wrap_mul(i4, 2, 4, -8);
            try test_wrap_mul(i8, 2, 127, -2);
            try test_wrap_mul(i8, -128, -128, 0);
            try test_wrap_mul(i8, max_int(i8), max_int(i8), 1);
            try test_wrap_mul(i16, max_int(i16), -1, min_int(i16) + 1);
            try test_wrap_mul(i128, max_int(i128), -1, min_int(i128) + 1);
            try test_wrap_mul(i128, min_int(i128), -1, min_int(i128));
            try test_wrap_mul(u8, 10, 3, 30);
            try test_wrap_mul(u8, 2, 255, 254);
            try test_wrap_mul(u128, max_int(u128), max_int(u128), 1);
        }

        fn test_wrap_mul(comptime T: type, lhs: T, rhs: T, expected: T) !void {
            try expect((lhs *% rhs) == expected);

            var x = lhs;
            x *%= rhs;
            try expect(x == expected);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();

    try comptime S.test_wrap_mul(comptime_int, 0, 0, 0);
    try comptime S.test_wrap_mul(comptime_int, 3, 2, 6);
    try comptime S.test_wrap_mul(comptime_int, 651075816498665588400716961808225370057, 468229432685078038144554201546849378455, 304852860194144160265083087140337419215516305999637969803722975979232817921935);
    try comptime S.test_wrap_mul(comptime_int, 7, -593423721213448152027139550640105366508, -4153966048494137064189976854480737565556);
}
