const std = @import("std");
const expect = std.testing.expect;
const print = std.debug.print;

fn defer_example() !usize {
    var a: usize = 1;

    {
        defer a = 2;
        a = 1;
    }
    try expect(a == 2);

    a = 5;
    return a;
}

test "defer basics" {
    try expect((try deferExample()) == 5);
}

// test
