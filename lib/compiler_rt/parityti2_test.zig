const std = @import("std");
const parity = @import("parity.zig");
const testing = std.testing;

fn parityti2_naive(a: i128) i32 {
    var x: u128 = @bit_cast(a);
    var has_parity: bool = false;
    while (x > 0) {
        has_parity = !has_parity;
        x = x & (x - 1);
    }
    return @int_cast(@int_from_bool(has_parity));
}

fn test__parityti2(a: i128) !void {
    const x = parity.__parityti2(a);
    const expected: i128 = parityti2_naive(a);
    try testing.expect_equal(expected, x);
}

test "parityti2" {
    try test__parityti2(0);
    try test__parityti2(1);
    try test__parityti2(2);
    try test__parityti2(@bit_cast(@as(u128, 0xffffffff_ffffffff_ffffffff_fffffffd)));
    try test__parityti2(@bit_cast(@as(u128, 0xffffffff_ffffffff_ffffffff_fffffffe)));
    try test__parityti2(@bit_cast(@as(u128, 0xffffffff_ffffffff_ffffffff_ffffffff)));

    const RndGen = std.Random.DefaultPrng;
    var rnd = RndGen.init(42);
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        const rand_num = rnd.random().int(i128);
        try test__parityti2(rand_num);
    }
}
