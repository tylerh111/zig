const std = @import("std");
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

var bit_field = BitField{
    .a = 1,
    .b = 2,
    .c = 3,
};

test "pointers of sub-byte-aligned fields share addresses" {
    try expect(@intfromptr(&bit_field.a) == @intfromptr(&bit_field.b));
    try expect(@intfromptr(&bit_field.a) == @intfromptr(&bit_field.c));
}

// test
