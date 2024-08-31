const expect = @import("std").testing.expect;
const builtin = @import("builtin");

test "@has_field" {
    const struc = struct {
        a: i32,
        b: []u8,

        pub const nope = 1;
    };
    try expect(@has_field(struc, "a") == true);
    try expect(@has_field(struc, "b") == true);
    try expect(@has_field(struc, "non-existant") == false);
    try expect(@has_field(struc, "nope") == false);

    const unin = union {
        a: u64,
        b: []u16,

        pub const nope = 1;
    };
    try expect(@has_field(unin, "a") == true);
    try expect(@has_field(unin, "b") == true);
    try expect(@has_field(unin, "non-existant") == false);
    try expect(@has_field(unin, "nope") == false);

    const enm = enum {
        a,
        b,

        pub const nope = 1;
    };
    try expect(@has_field(enm, "a") == true);
    try expect(@has_field(enm, "b") == true);
    try expect(@has_field(enm, "non-existant") == false);
    try expect(@has_field(enm, "nope") == false);

    const anon = @TypeOf(.{ .a = 1 });
    try expect(@has_field(anon, "a") == true);
    try expect(@has_field(anon, "b") == false);

    const tuple = @TypeOf(.{ 1, 2 });
    try expect(@has_field(tuple, "a") == false);
    try expect(@has_field(tuple, "b") == false);
    try expect(@has_field(tuple, "0") == true);
    try expect(@has_field(tuple, "1") == true);
    try expect(@has_field(tuple, "2") == false);
    try expect(@has_field(tuple, "9999999999999999999999999") == false);
}
