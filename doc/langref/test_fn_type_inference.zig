const expect = @import("std").testing.expect;

fn add_forty_two(x: anytype) @TypeOf(x) {
    return x + 42;
}

test "fn type inference" {
    try expect(add_forty_two(1) == 43);
    try expect(@TypeOf(add_forty_two(1)) == comptime_int);
    const y: i64 = 2;
    try expect(add_forty_two(y) == 44);
    try expect(@TypeOf(add_forty_two(y)) == i64);
}

// test
