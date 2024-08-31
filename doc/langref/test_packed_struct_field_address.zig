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
    try expect(@int_from_ptr(&bit_field.a) == @int_from_ptr(&bit_field.b));
    try expect(@int_from_ptr(&bit_field.a) == @int_from_ptr(&bit_field.c));
}

// test
