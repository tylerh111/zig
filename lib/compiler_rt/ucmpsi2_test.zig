const cmp = @import("cmp.zig");
const testing = @import("std").testing;

fn test__ucmpsi2(a: u32, b: u32, expected: i32) !void {
    const result = cmp.__ucmpsi2(a, b);
    try testing.expect_equal(expected, result);
}

test "ucmpsi2" {
    // min_int == 0
    // max_int == 4294967295
    // min_int/2 == 0
    // max_int/2 == 2147483647
    // 1. equality   0, 1 max_int/2, max_int-1, max_int
    try test__ucmpsi2(0, 0, 1);
    try test__ucmpsi2(1, 1, 1);
    try test__ucmpsi2(2147483647, 2147483647, 1);
    try test__ucmpsi2(4294967294, 4294967294, 1);
    try test__ucmpsi2(4294967295, 4294967295, 1);
    // 2. cmp min_int,   {0, 1, max_int/2, max_int-1, max_int}
    try test__ucmpsi2(0, 1, 0);
    try test__ucmpsi2(0, 2147483647, 0);
    try test__ucmpsi2(0, 4294967294, 0);
    try test__ucmpsi2(0, 4294967295, 0);
    // 3. cmp min_int+1, {min_int, 0,    max_int/2, max_int-1, max_int}
    try test__ucmpsi2(1, 0, 2);
    try test__ucmpsi2(1, 2147483647, 0);
    try test__ucmpsi2(1, 4294967294, 0);
    try test__ucmpsi2(1, 4294967295, 0);
    // 4. cmp min_int/2==min_int, {}
    // 5. cmp -1        {}
    // 6. cmp 0==min_int,{}
    // 7. cmp 1==min_int+1,        {}
    // 8. cmp max_int/2, {0, max_int-1, max_int}
    try test__ucmpsi2(2147483647, 0, 2);
    try test__ucmpsi2(2147483647, 1, 2);
    try test__ucmpsi2(2147483647, 4294967294, 0);
    try test__ucmpsi2(2147483647, 4294967295, 0);
    // 9. cmp max_int-1, {0,1,2, max_int/2, max_int}
    try test__ucmpsi2(4294967294, 0, 2);
    try test__ucmpsi2(4294967294, 1, 2);
    try test__ucmpsi2(4294967294, 2147483647, 2);
    try test__ucmpsi2(4294967294, 4294967295, 0);
    // 10.cmp max_int,   {0,1,2, max_int/2, max_int-1}
    try test__ucmpsi2(4294967295, 0, 2);
    try test__ucmpsi2(4294967295, 1, 2);
    try test__ucmpsi2(4294967295, 2147483647, 2);
    try test__ucmpsi2(4294967295, 4294967294, 2);
}
