const std = @import("std");
const expect = std.testing.expect;

const Number = union {
    int: i32,
    float: f64,
};

test "anonymous union literal syntax" {
    const i: Number = .{ .int = 42 };
    const f = make_number();
    try expect(i.int == 42);
    try expect(f.float == 12.34);
}

fn make_number() Number {
    return .{ .float = 12.34 };
}

// test
