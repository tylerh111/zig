const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;

const Foo = @import("hasdecl/foo.zig");

const Bar = struct {
    nope: i32,

    const hi = 1;
    pub var blah = "xxx";
};

test "@hasdecl" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(@hasdecl(Foo, "public_thing"));
    try expect(!@hasdecl(Foo, "private_thing"));
    try expect(!@hasdecl(Foo, "no_thing"));

    try expect(@hasdecl(Bar, "hi"));
    try expect(@hasdecl(Bar, "blah"));
    try expect(!@hasdecl(Bar, "nope"));
}

test "@hasdecl using a sliced string literal" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(@hasdecl(@This(), "std") == true);
    try expect(@hasdecl(@This(), "std"[0..0]) == false);
    try expect(@hasdecl(@This(), "std"[0..1]) == false);
    try expect(@hasdecl(@This(), "std"[0..2]) == false);
    try expect(@hasdecl(@This(), "std"[0..3]) == true);
    try expect(@hasdecl(@This(), "std"[0..]) == true);
}
