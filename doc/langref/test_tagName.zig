const std = @import("std");
const expect = std.testing.expect;

const Small2 = union(enum) {
    a: i32,
    b: bool,
    c: u8,
};
test "@tag_name" {
    try expect(std.mem.eql(u8, @tag_name(Small2.a), "a"));
}

// test
