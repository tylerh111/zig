const std = @import("std");
const testing = std.testing;
const mulXi3 = @import("mulXi3.zig");
const max_int = std.math.max_int;
const min_int = std.math.min_int;

fn test_one_mulsi3(a: i32, b: i32, result: i32) !void {
    try testing.expect_equal(result, mulXi3.__mulsi3(a, b));
}

fn test__muldi3(a: i64, b: i64, expected: i64) !void {
    const x = mulXi3.__muldi3(a, b);
    try testing.expect(x == expected);
}

fn test__multi3(a: i128, b: i128, expected: i128) !void {
    const x = mulXi3.__multi3(a, b);
    try testing.expect(x == expected);
}

test "mulsi3" {
    try test_one_mulsi3(0, 0, 0);
    try test_one_mulsi3(0, 1, 0);
    try test_one_mulsi3(1, 0, 0);
    try test_one_mulsi3(0, 10, 0);
    try test_one_mulsi3(10, 0, 0);
    try test_one_mulsi3(0, max_int(i32), 0);
    try test_one_mulsi3(max_int(i32), 0, 0);
    try test_one_mulsi3(0, -1, 0);
    try test_one_mulsi3(-1, 0, 0);
    try test_one_mulsi3(0, -10, 0);
    try test_one_mulsi3(-10, 0, 0);
    try test_one_mulsi3(0, min_int(i32), 0);
    try test_one_mulsi3(min_int(i32), 0, 0);
    try test_one_mulsi3(1, 1, 1);
    try test_one_mulsi3(1, 10, 10);
    try test_one_mulsi3(10, 1, 10);
    try test_one_mulsi3(1, max_int(i32), max_int(i32));
    try test_one_mulsi3(max_int(i32), 1, max_int(i32));
    try test_one_mulsi3(1, -1, -1);
    try test_one_mulsi3(1, -10, -10);
    try test_one_mulsi3(-10, 1, -10);
    try test_one_mulsi3(1, min_int(i32), min_int(i32));
    try test_one_mulsi3(min_int(i32), 1, min_int(i32));
    try test_one_mulsi3(46340, 46340, 2147395600);
    try test_one_mulsi3(-46340, 46340, -2147395600);
    try test_one_mulsi3(46340, -46340, -2147395600);
    try test_one_mulsi3(-46340, -46340, 2147395600);
    try test_one_mulsi3(4194303, 8192, @as(i32, @truncate(34359730176)));
    try test_one_mulsi3(-4194303, 8192, @as(i32, @truncate(-34359730176)));
    try test_one_mulsi3(4194303, -8192, @as(i32, @truncate(-34359730176)));
    try test_one_mulsi3(-4194303, -8192, @as(i32, @truncate(34359730176)));
    try test_one_mulsi3(8192, 4194303, @as(i32, @truncate(34359730176)));
    try test_one_mulsi3(-8192, 4194303, @as(i32, @truncate(-34359730176)));
    try test_one_mulsi3(8192, -4194303, @as(i32, @truncate(-34359730176)));
    try test_one_mulsi3(-8192, -4194303, @as(i32, @truncate(34359730176)));
}

test "muldi3" {
    try test__muldi3(0, 0, 0);
    try test__muldi3(0, 1, 0);
    try test__muldi3(1, 0, 0);
    try test__muldi3(0, 10, 0);
    try test__muldi3(10, 0, 0);
    try test__muldi3(0, 81985529216486895, 0);
    try test__muldi3(81985529216486895, 0, 0);

    try test__muldi3(0, -1, 0);
    try test__muldi3(-1, 0, 0);
    try test__muldi3(0, -10, 0);
    try test__muldi3(-10, 0, 0);
    try test__muldi3(0, -81985529216486895, 0);
    try test__muldi3(-81985529216486895, 0, 0);

    try test__muldi3(1, 1, 1);
    try test__muldi3(1, 10, 10);
    try test__muldi3(10, 1, 10);
    try test__muldi3(1, 81985529216486895, 81985529216486895);
    try test__muldi3(81985529216486895, 1, 81985529216486895);

    try test__muldi3(1, -1, -1);
    try test__muldi3(1, -10, -10);
    try test__muldi3(-10, 1, -10);
    try test__muldi3(1, -81985529216486895, -81985529216486895);
    try test__muldi3(-81985529216486895, 1, -81985529216486895);

    try test__muldi3(3037000499, 3037000499, 9223372030926249001);
    try test__muldi3(-3037000499, 3037000499, -9223372030926249001);
    try test__muldi3(3037000499, -3037000499, -9223372030926249001);
    try test__muldi3(-3037000499, -3037000499, 9223372030926249001);

    try test__muldi3(4398046511103, 2097152, 9223372036852678656);
    try test__muldi3(-4398046511103, 2097152, -9223372036852678656);
    try test__muldi3(4398046511103, -2097152, -9223372036852678656);
    try test__muldi3(-4398046511103, -2097152, 9223372036852678656);

    try test__muldi3(2097152, 4398046511103, 9223372036852678656);
    try test__muldi3(-2097152, 4398046511103, -9223372036852678656);
    try test__muldi3(2097152, -4398046511103, -9223372036852678656);
    try test__muldi3(-2097152, -4398046511103, 9223372036852678656);
}

test "multi3" {
    try test__multi3(0, 0, 0);
    try test__multi3(0, 1, 0);
    try test__multi3(1, 0, 0);
    try test__multi3(0, 10, 0);
    try test__multi3(10, 0, 0);
    try test__multi3(0, 81985529216486895, 0);
    try test__multi3(81985529216486895, 0, 0);

    try test__multi3(0, -1, 0);
    try test__multi3(-1, 0, 0);
    try test__multi3(0, -10, 0);
    try test__multi3(-10, 0, 0);
    try test__multi3(0, -81985529216486895, 0);
    try test__multi3(-81985529216486895, 0, 0);

    try test__multi3(1, 1, 1);
    try test__multi3(1, 10, 10);
    try test__multi3(10, 1, 10);
    try test__multi3(1, 81985529216486895, 81985529216486895);
    try test__multi3(81985529216486895, 1, 81985529216486895);

    try test__multi3(1, -1, -1);
    try test__multi3(1, -10, -10);
    try test__multi3(-10, 1, -10);
    try test__multi3(1, -81985529216486895, -81985529216486895);
    try test__multi3(-81985529216486895, 1, -81985529216486895);

    try test__multi3(3037000499, 3037000499, 9223372030926249001);
    try test__multi3(-3037000499, 3037000499, -9223372030926249001);
    try test__multi3(3037000499, -3037000499, -9223372030926249001);
    try test__multi3(-3037000499, -3037000499, 9223372030926249001);

    try test__multi3(4398046511103, 2097152, 9223372036852678656);
    try test__multi3(-4398046511103, 2097152, -9223372036852678656);
    try test__multi3(4398046511103, -2097152, -9223372036852678656);
    try test__multi3(-4398046511103, -2097152, 9223372036852678656);

    try test__multi3(2097152, 4398046511103, 9223372036852678656);
    try test__multi3(-2097152, 4398046511103, -9223372036852678656);
    try test__multi3(2097152, -4398046511103, -9223372036852678656);
    try test__multi3(-2097152, -4398046511103, 9223372036852678656);

    try test__multi3(0x00000000000000B504F333F9DE5BE000, 0x000000000000000000B504F333F9DE5B, 0x7FFFFFFFFFFFF328DF915DA296E8A000);
}
