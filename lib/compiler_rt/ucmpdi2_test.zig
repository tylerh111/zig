const cmp = @import("cmp.zig");
const testing = @import("std").testing;

fn test__ucmpdi2(a: u64, b: u64, expected: i32) !void {
    const result = cmp.__ucmpdi2(a, b);
    try testing.expect_equal(expected, result);
}

test "ucmpdi2" {
    // min_int == 0
    // max_int == 18446744073709551615
    // min_int/2 == 0
    // max_int/2 == 9223372036854775807
    // 1. equality min_int, min_int/2, 0, max_int/2, max_int
    try test__ucmpdi2(0, 0, 1);
    try test__ucmpdi2(1, 1, 1);
    try test__ucmpdi2(9223372036854775807, 9223372036854775807, 1);
    try test__ucmpdi2(18446744073709551614, 18446744073709551614, 1);
    try test__ucmpdi2(18446744073709551615, 18446744073709551615, 1);
    // 2. cmp min_int,   {min_int + 1, max_int/2, max_int-1, max_int}
    try test__ucmpdi2(0, 1, 0);
    try test__ucmpdi2(0, 9223372036854775807, 0);
    try test__ucmpdi2(0, 18446744073709551614, 0);
    try test__ucmpdi2(0, 18446744073709551615, 0);
    // 3. cmp min_int+1, {min_int, max_int/2, max_int-1, max_int}
    try test__ucmpdi2(1, 0, 2);
    try test__ucmpdi2(1, 9223372036854775807, 0);
    try test__ucmpdi2(1, 18446744073709551614, 0);
    try test__ucmpdi2(1, 18446744073709551615, 0);
    // 4. cmp min_int/2, {}
    // 5. cmp -1,       {}
    // 6. cmp 0,        {}
    // 7. cmp 1,        {}
    // 8. cmp max_int/2, {min_int, min_int+1, max_int-1, max_int}
    try test__ucmpdi2(9223372036854775807, 0, 2);
    try test__ucmpdi2(9223372036854775807, 1, 2);
    try test__ucmpdi2(9223372036854775807, 18446744073709551614, 0);
    try test__ucmpdi2(9223372036854775807, 18446744073709551615, 0);
    // 9. cmp max_int-1, {min_int, min_int + 1, max_int/2, max_int}
    try test__ucmpdi2(18446744073709551614, 0, 2);
    try test__ucmpdi2(18446744073709551614, 1, 2);
    try test__ucmpdi2(18446744073709551614, 9223372036854775807, 2);
    try test__ucmpdi2(18446744073709551614, 18446744073709551615, 0);
    // 10.cmp max_int,   {min_int, 1, max_int/2, max_int-1}
    try test__ucmpdi2(18446744073709551615, 0, 2);
    try test__ucmpdi2(18446744073709551615, 1, 2);
    try test__ucmpdi2(18446744073709551615, 9223372036854775807, 2);
    try test__ucmpdi2(18446744073709551615, 18446744073709551614, 2);
}
