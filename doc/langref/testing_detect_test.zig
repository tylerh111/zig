const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;

test "builtin.is_test" {
    try expect(is_atest());
}

fn is_atest() bool {
    return builtin.is_test;
}

// test
