const std = @import("std");
const expect = std.testing.expect;
const min_int = std.math.min_int;
const max_int = std.math.max_int;

test "wraparound addition and subtraction" {
    const x: i32 = max_int(i32);
    const min_val = x +% 1;
    try expect(min_val == min_int(i32));
    const max_val = min_val -% 1;
    try expect(max_val == max_int(i32));
}

// test
