const std = @import("std");
const parity = @import("parity.zig");
const testing = std.testing;

fn paritysi2_naive(a: i32) i32 {
    var x: u32 = @bit_cast(a);
    var has_parity: bool = false;
    while (x > 0) {
        has_parity = !has_parity;
        x = x & (x - 1);
    }
    return @int_cast(@int_from_bool(has_parity));
}

fn test__paritysi2(a: i32) !void {
    const x = parity.__paritysi2(a);
    const expected: i32 = paritysi2_naive(a);
    try testing.expect_equal(expected, x);
}

test "paritysi2" {
    try test__paritysi2(0);
    try test__paritysi2(1);
    try test__paritysi2(2);
    try test__paritysi2(@bit_cast(@as(u32, 0xfffffffd)));
    try test__paritysi2(@bit_cast(@as(u32, 0xfffffffe)));
    try test__paritysi2(@bit_cast(@as(u32, 0xffffffff)));

    const RndGen = std.Random.DefaultPrng;
    var rnd = RndGen.init(42);
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        const rand_num = rnd.random().int(i32);
        try test__paritysi2(rand_num);
    }
}
