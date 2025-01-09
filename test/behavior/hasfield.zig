const expect = @import("std").testing.expect;
const builtin = @import("builtin");

test "@hasfield" {
    const struc = struct {
        a: i32,
        b: []u8,

        pub const nope = 1;
    };
    try expect(@hasfield(struc, "a") == true);
    try expect(@hasfield(struc, "b") == true);
    try expect(@hasfield(struc, "non-existant") == false);
    try expect(@hasfield(struc, "nope") == false);

    const unin = union {
        a: u64,
        b: []u16,

        pub const nope = 1;
    };
    try expect(@hasfield(unin, "a") == true);
    try expect(@hasfield(unin, "b") == true);
    try expect(@hasfield(unin, "non-existant") == false);
    try expect(@hasfield(unin, "nope") == false);

    const enm = enum {
        a,
        b,

        pub const nope = 1;
    };
    try expect(@hasfield(enm, "a") == true);
    try expect(@hasfield(enm, "b") == true);
    try expect(@hasfield(enm, "non-existant") == false);
    try expect(@hasfield(enm, "nope") == false);

    const anon = @TypeOf(.{ .a = 1 });
    try expect(@hasfield(anon, "a") == true);
    try expect(@hasfield(anon, "b") == false);

    const tuple = @TypeOf(.{ 1, 2 });
    try expect(@hasfield(tuple, "a") == false);
    try expect(@hasfield(tuple, "b") == false);
    try expect(@hasfield(tuple, "0") == true);
    try expect(@hasfield(tuple, "1") == true);
    try expect(@hasfield(tuple, "2") == false);
    try expect(@hasfield(tuple, "9999999999999999999999999") == false);
}
