const std = @import("std");
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

test "offsets of non-byte-aligned fields" {
    comptime {
        try expect(@bit_offset_of(BitField, "a") == 0);
        try expect(@bit_offset_of(BitField, "b") == 3);
        try expect(@bit_offset_of(BitField, "c") == 6);

        try expect(@offset_of(BitField, "a") == 0);
        try expect(@offset_of(BitField, "b") == 0);
        try expect(@offset_of(BitField, "c") == 0);
    }
}

// test
