const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const builtin = @import("builtin");
const native_arch = builtin.target.cpu.arch;
const maxInt = std.math.maxInt;

const Foo = struct {
    x: u32,
    y: u32,
    z: u32,
};

test "@alignof(T) before referencing T" {
    comptime assert(@alignof(Foo) != maxInt(usize));
    if (native_arch == .x86_64) {
        comptime assert(@alignof(Foo) == 4);
    }
}

test "comparison of @alignof(T) against zero" {
    const T = struct { x: u32 };
    try expect(!(@alignof(T) == 0));
    try expect(@alignof(T) != 0);
    try expect(!(@alignof(T) < 0));
    try expect(!(@alignof(T) <= 0));
    try expect(@alignof(T) > 0);
    try expect(@alignof(T) >= 0);
}

test "correct alignment for elements and slices of aligned array" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var buf: [1024]u8 align(64) = undefined;
    var start: usize = 1;
    var end: usize = undefined;
    _ = .{ &start, &end };
    try expect(@alignof(@TypeOf(buf[start..end])) == @alignof(*u8));
    try expect(@alignof(@TypeOf(&buf[start..end])) == @alignof(*u8));
    try expect(@alignof(@TypeOf(&buf[start])) == @alignof(*u8));
}
