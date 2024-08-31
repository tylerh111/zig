const cmp = @import("cmp.zig");
const testing = @import("std").testing;

fn test__cmpsi2(a: i32, b: i32, expected: i32) !void {
    const result = cmp.__cmpsi2(a, b);
    try testing.expect_equal(expected, result);
}

test "cmpsi2" {
    // min_int == -2147483648
    // max_int == 2147483647
    // min_int/2 == -1073741824
    // max_int/2 == 1073741823
    // 1. equality min_int, min_int+1, min_int/2, -1, 0, 1, max_int/2, max_int-1, max_int
    try test__cmpsi2(-2147483648, -2147483648, 1);
    try test__cmpsi2(-2147483647, -2147483647, 1);
    try test__cmpsi2(-1073741824, -1073741824, 1);
    try test__cmpsi2(-1, -1, 1);
    try test__cmpsi2(0, 0, 1);
    try test__cmpsi2(1, 1, 1);
    try test__cmpsi2(1073741823, 1073741823, 1);
    try test__cmpsi2(2147483646, 2147483646, 1);
    try test__cmpsi2(2147483647, 2147483647, 1);
    // 2. cmp min_int,   {        min_int + 1, min_int/2, -1,0,1, max_int/2, max_int-1, max_int}
    try test__cmpsi2(-2147483648, -2147483647, 0);
    try test__cmpsi2(-2147483648, -1073741824, 0);
    try test__cmpsi2(-2147483648, -1, 0);
    try test__cmpsi2(-2147483648, 0, 0);
    try test__cmpsi2(-2147483648, 1, 0);
    try test__cmpsi2(-2147483648, 1073741823, 0);
    try test__cmpsi2(-2147483648, 2147483646, 0);
    try test__cmpsi2(-2147483648, 2147483647, 0);
    // 3. cmp min_int+1, {min_int,             min_int/2, -1,0,1, max_int/2, max_int-1, max_int}
    try test__cmpsi2(-2147483647, -2147483648, 2);
    try test__cmpsi2(-2147483647, -1073741824, 0);
    try test__cmpsi2(-2147483647, -1, 0);
    try test__cmpsi2(-2147483647, 0, 0);
    try test__cmpsi2(-2147483647, 1, 0);
    try test__cmpsi2(-2147483647, 1073741823, 0);
    try test__cmpsi2(-2147483647, 2147483646, 0);
    try test__cmpsi2(-2147483647, 2147483647, 0);
    // 4. cmp min_int/2, {min_int, min_int + 1,           -1,0,1, max_int/2, max_int-1, max_int}
    try test__cmpsi2(-1073741824, -2147483648, 2);
    try test__cmpsi2(-1073741824, -2147483647, 2);
    try test__cmpsi2(-1073741824, -1, 0);
    try test__cmpsi2(-1073741824, 0, 0);
    try test__cmpsi2(-1073741824, 1, 0);
    try test__cmpsi2(-1073741824, 1073741823, 0);
    try test__cmpsi2(-1073741824, 2147483646, 0);
    try test__cmpsi2(-1073741824, 2147483647, 0);
    // 5. cmp -1,       {min_int, min_int + 1, min_int/2,    0,1, max_int/2, max_int-1, max_int}
    try test__cmpsi2(-1, -2147483648, 2);
    try test__cmpsi2(-1, -2147483647, 2);
    try test__cmpsi2(-1, -1073741824, 2);
    try test__cmpsi2(-1, 0, 0);
    try test__cmpsi2(-1, 1, 0);
    try test__cmpsi2(-1, 1073741823, 0);
    try test__cmpsi2(-1, 2147483646, 0);
    try test__cmpsi2(-1, 2147483647, 0);
    // 6. cmp 0,        {min_int, min_int + 1, min_int/2, -1,  1, max_int/2, max_int-1, max_int}
    try test__cmpsi2(0, -2147483648, 2);
    try test__cmpsi2(0, -2147483647, 2);
    try test__cmpsi2(0, -1073741824, 2);
    try test__cmpsi2(0, -1, 2);
    try test__cmpsi2(0, 1, 0);
    try test__cmpsi2(0, 1073741823, 0);
    try test__cmpsi2(0, 2147483646, 0);
    try test__cmpsi2(0, 2147483647, 0);
    // 7. cmp 1,        {min_int, min_int + 1, min_int/2, -1,0,  max_int/2, max_int-1, max_int}
    try test__cmpsi2(1, -2147483648, 2);
    try test__cmpsi2(1, -2147483647, 2);
    try test__cmpsi2(1, -1073741824, 2);
    try test__cmpsi2(1, -1, 2);
    try test__cmpsi2(1, 0, 2);
    try test__cmpsi2(1, 1073741823, 0);
    try test__cmpsi2(1, 2147483646, 0);
    try test__cmpsi2(1, 2147483647, 0);
    // 8. cmp max_int/2, {min_int, min_int + 1, min_int/2, -1, 0, 1,          max_int-1, max_int}
    try test__cmpsi2(1073741823, -2147483648, 2);
    try test__cmpsi2(1073741823, -2147483647, 2);
    try test__cmpsi2(1073741823, -1073741824, 2);
    try test__cmpsi2(1073741823, -1, 2);
    try test__cmpsi2(1073741823, 0, 2);
    try test__cmpsi2(1073741823, 1, 2);
    try test__cmpsi2(1073741823, 2147483646, 0);
    try test__cmpsi2(1073741823, 2147483647, 0);
    // 9. cmp max_int-1, {min_int, min_int + 1, min_int/2, -1, 0, 1, max_int/2,           max_int}
    try test__cmpsi2(2147483646, -2147483648, 2);
    try test__cmpsi2(2147483646, -2147483647, 2);
    try test__cmpsi2(2147483646, -1073741824, 2);
    try test__cmpsi2(2147483646, -1, 2);
    try test__cmpsi2(2147483646, 0, 2);
    try test__cmpsi2(2147483646, 1, 2);
    try test__cmpsi2(2147483646, 1073741823, 2);
    try test__cmpsi2(2147483646, 2147483647, 0);
    // 10.cmp max_int,   {min_int, min_int + 1, min_int/2, -1, 0, 1, max_int/2, max_int-1,       }
    try test__cmpsi2(2147483647, -2147483648, 2);
    try test__cmpsi2(2147483647, -2147483647, 2);
    try test__cmpsi2(2147483647, -1073741824, 2);
    try test__cmpsi2(2147483647, -1, 2);
    try test__cmpsi2(2147483647, 0, 2);
    try test__cmpsi2(2147483647, 1, 2);
    try test__cmpsi2(2147483647, 1073741823, 2);
    try test__cmpsi2(2147483647, 2147483646, 2);
}
