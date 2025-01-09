const std = @import("std");
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

test "offsets of non-byte-aligned fields" {
    comptime {
        try expect(@bitoffsetof(BitField, "a") == 0);
        try expect(@bitoffsetof(BitField, "b") == 3);
        try expect(@bitoffsetof(BitField, "c") == 6);

        try expect(@offsetof(BitField, "a") == 0);
        try expect(@offsetof(BitField, "b") == 0);
        try expect(@offsetof(BitField, "c") == 0);
    }
}

// test
