const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;
const minInt = std.math.minInt;

test "@bitreverse large exotic integer" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;

    try expect(@bitreverse(@as(u95, 0x123456789abcdef111213141)) == 0x4146424447bd9eac8f351624);
}

test "@bitreverse" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime testBitReverse();
    try testBitReverse();
}

fn testBitReverse() !void {
    // using comptime_ints, unsigned
    try expect(@bitreverse(@as(u0, 0)) == 0);
    try expect(@bitreverse(@as(u5, 0x12)) == 0x9);
    try expect(@bitreverse(@as(u8, 0x12)) == 0x48);
    try expect(@bitreverse(@as(u16, 0x1234)) == 0x2c48);
    try expect(@bitreverse(@as(u24, 0x123456)) == 0x6a2c48);
    try expect(@bitreverse(@as(u32, 0x12345678)) == 0x1e6a2c48);
    try expect(@bitreverse(@as(u40, 0x123456789a)) == 0x591e6a2c48);
    try expect(@bitreverse(@as(u48, 0x123456789abc)) == 0x3d591e6a2c48);
    try expect(@bitreverse(@as(u56, 0x123456789abcde)) == 0x7b3d591e6a2c48);
    try expect(@bitreverse(@as(u64, 0x123456789abcdef1)) == 0x8f7b3d591e6a2c48);
    try expect(@bitreverse(@as(u96, 0x123456789abcdef111213141)) == 0x828c84888f7b3d591e6a2c48);
    try expect(@bitreverse(@as(u128, 0x123456789abcdef11121314151617181)) == 0x818e868a828c84888f7b3d591e6a2c48);

    // using runtime uints, unsigned
    var num0: u0 = 0;
    try expect(@bitreverse(num0) == 0);
    var num5: u5 = 0x12;
    try expect(@bitreverse(num5) == 0x9);
    var num8: u8 = 0x12;
    try expect(@bitreverse(num8) == 0x48);
    var num16: u16 = 0x1234;
    try expect(@bitreverse(num16) == 0x2c48);
    var num24: u24 = 0x123456;
    try expect(@bitreverse(num24) == 0x6a2c48);
    var num32: u32 = 0x12345678;
    try expect(@bitreverse(num32) == 0x1e6a2c48);
    var num40: u40 = 0x123456789a;
    try expect(@bitreverse(num40) == 0x591e6a2c48);
    var num48: u48 = 0x123456789abc;
    try expect(@bitreverse(num48) == 0x3d591e6a2c48);
    var num56: u56 = 0x123456789abcde;
    try expect(@bitreverse(num56) == 0x7b3d591e6a2c48);
    var num64: u64 = 0x123456789abcdef1;
    try expect(@bitreverse(num64) == 0x8f7b3d591e6a2c48);
    var num128: u128 = 0x123456789abcdef11121314151617181;
    try expect(@bitreverse(num128) == 0x818e868a828c84888f7b3d591e6a2c48);

    // using comptime_ints, signed, positive
    try expect(@bitreverse(@as(u8, 0)) == 0);
    try expect(@bitreverse(@as(i8, @bitcast(@as(u8, 0x92)))) == @as(i8, @bitcast(@as(u8, 0x49))));
    try expect(@bitreverse(@as(i16, @bitcast(@as(u16, 0x1234)))) == @as(i16, @bitcast(@as(u16, 0x2c48))));
    try expect(@bitreverse(@as(i24, @bitcast(@as(u24, 0x123456)))) == @as(i24, @bitcast(@as(u24, 0x6a2c48))));
    try expect(@bitreverse(@as(i24, @bitcast(@as(u24, 0x12345f)))) == @as(i24, @bitcast(@as(u24, 0xfa2c48))));
    try expect(@bitreverse(@as(i24, @bitcast(@as(u24, 0xf23456)))) == @as(i24, @bitcast(@as(u24, 0x6a2c4f))));
    try expect(@bitreverse(@as(i32, @bitcast(@as(u32, 0x12345678)))) == @as(i32, @bitcast(@as(u32, 0x1e6a2c48))));
    try expect(@bitreverse(@as(i32, @bitcast(@as(u32, 0xf2345678)))) == @as(i32, @bitcast(@as(u32, 0x1e6a2c4f))));
    try expect(@bitreverse(@as(i32, @bitcast(@as(u32, 0x1234567f)))) == @as(i32, @bitcast(@as(u32, 0xfe6a2c48))));
    try expect(@bitreverse(@as(i40, @bitcast(@as(u40, 0x123456789a)))) == @as(i40, @bitcast(@as(u40, 0x591e6a2c48))));
    try expect(@bitreverse(@as(i48, @bitcast(@as(u48, 0x123456789abc)))) == @as(i48, @bitcast(@as(u48, 0x3d591e6a2c48))));
    try expect(@bitreverse(@as(i56, @bitcast(@as(u56, 0x123456789abcde)))) == @as(i56, @bitcast(@as(u56, 0x7b3d591e6a2c48))));
    try expect(@bitreverse(@as(i64, @bitcast(@as(u64, 0x123456789abcdef1)))) == @as(i64, @bitcast(@as(u64, 0x8f7b3d591e6a2c48))));
    try expect(@bitreverse(@as(i96, @bitcast(@as(u96, 0x123456789abcdef111213141)))) == @as(i96, @bitcast(@as(u96, 0x828c84888f7b3d591e6a2c48))));
    try expect(@bitreverse(@as(i128, @bitcast(@as(u128, 0x123456789abcdef11121314151617181)))) == @as(i128, @bitcast(@as(u128, 0x818e868a828c84888f7b3d591e6a2c48))));

    // using signed, negative. Compare to runtime ints returned from llvm.
    var neg8: i8 = -18;
    try expect(@bitreverse(@as(i8, -18)) == @bitreverse(neg8));
    var neg16: i16 = -32694;
    try expect(@bitreverse(@as(i16, -32694)) == @bitreverse(neg16));
    var neg24: i24 = -6773785;
    try expect(@bitreverse(@as(i24, -6773785)) == @bitreverse(neg24));
    var neg32: i32 = -16773785;
    try expect(@bitreverse(@as(i32, -16773785)) == @bitreverse(neg32));

    _ = .{
        &num0,
        &num5,
        &num8,
        &num16,
        &num24,
        &num32,
        &num40,
        &num48,
        &num56,
        &num64,
        &num128,
        &neg8,
        &neg16,
        &neg24,
        &neg32,
    };
}

fn vector8() !void {
    var v = @Vector(2, u8){ 0x12, 0x23 };
    _ = &v;
    const result = @bitreverse(v);
    try expect(result[0] == 0x48);
    try expect(result[1] == 0xc4);
}

test "bitreverse vectors u8" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime vector8();
    try vector8();
}

fn vector16() !void {
    var v = @Vector(2, u16){ 0x1234, 0x2345 };
    _ = &v;
    const result = @bitreverse(v);
    try expect(result[0] == 0x2c48);
    try expect(result[1] == 0xa2c4);
}

test "bitreverse vectors u16" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime vector16();
    try vector16();
}

fn vector24() !void {
    var v = @Vector(2, u24){ 0x123456, 0x234567 };
    _ = &v;
    const result = @bitreverse(v);
    try expect(result[0] == 0x6a2c48);
    try expect(result[1] == 0xe6a2c4);
}

test "bitreverse vectors u24" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime vector24();
    try vector24();
}

fn vector0() !void {
    var v = @Vector(2, u0){ 0, 0 };
    _ = &v;
    const result = @bitreverse(v);
    try expect(result[0] == 0);
    try expect(result[1] == 0);
}

test "bitreverse vectors u0" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;

    try comptime vector0();
    try vector0();
}
