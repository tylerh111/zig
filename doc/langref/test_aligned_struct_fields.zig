const std = @import("std");
const expect_equal = std.testing.expect_equal;

test "aligned struct fields" {
    const S = struct {
        a: u32 align(2),
        b: u32 align(64),
    };
    var foo = S{ .a = 1, .b = 2 };

    try expect_equal(64, @alignOf(S));
    try expect_equal(*align(2) u32, @TypeOf(&foo.a));
    try expect_equal(*align(64) u32, @TypeOf(&foo.b));
}

// test
