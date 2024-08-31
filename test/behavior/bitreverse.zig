const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;
const min_int = std.math.min_int;

test "@bit_reverse large exotic integer" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;

    try expect(@bit_reverse(@as(u95, 0x123456789abcdef111213141)) == 0x4146424447bd9eac8f351624);
}

test "@bit_reverse" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_bit_reverse();
    try test_bit_reverse();
}

fn test_bit_reverse() !void {
    // using comptime_ints, unsigned
    try expect(@bit_reverse(@as(u0, 0)) == 0);
    try expect(@bit_reverse(@as(u5, 0x12)) == 0x9);
    try expect(@bit_reverse(@as(u8, 0x12)) == 0x48);
    try expect(@bit_reverse(@as(u16, 0x1234)) == 0x2c48);
    try expect(@bit_reverse(@as(u24, 0x123456)) == 0x6a2c48);
    try expect(@bit_reverse(@as(u32, 0x12345678)) == 0x1e6a2c48);
    try expect(@bit_reverse(@as(u40, 0x123456789a)) == 0x591e6a2c48);
    try expect(@bit_reverse(@as(u48, 0x123456789abc)) == 0x3d591e6a2c48);
    try expect(@bit_reverse(@as(u56, 0x123456789abcde)) == 0x7b3d591e6a2c48);
    try expect(@bit_reverse(@as(u64, 0x123456789abcdef1)) == 0x8f7b3d591e6a2c48);
    try expect(@bit_reverse(@as(u96, 0x123456789abcdef111213141)) == 0x828c84888f7b3d591e6a2c48);
    try expect(@bit_reverse(@as(u128, 0x123456789abcdef11121314151617181)) == 0x818e868a828c84888f7b3d591e6a2c48);

    // using runtime uints, unsigned
    var num0: u0 = 0;
    try expect(@bit_reverse(num0) == 0);
    var num5: u5 = 0x12;
    try expect(@bit_reverse(num5) == 0x9);
    var num8: u8 = 0x12;
    try expect(@bit_reverse(num8) == 0x48);
    var num16: u16 = 0x1234;
    try expect(@bit_reverse(num16) == 0x2c48);
    var num24: u24 = 0x123456;
    try expect(@bit_reverse(num24) == 0x6a2c48);
    var num32: u32 = 0x12345678;
    try expect(@bit_reverse(num32) == 0x1e6a2c48);
    var num40: u40 = 0x123456789a;
    try expect(@bit_reverse(num40) == 0x591e6a2c48);
    var num48: u48 = 0x123456789abc;
    try expect(@bit_reverse(num48) == 0x3d591e6a2c48);
    var num56: u56 = 0x123456789abcde;
    try expect(@bit_reverse(num56) == 0x7b3d591e6a2c48);
    var num64: u64 = 0x123456789abcdef1;
    try expect(@bit_reverse(num64) == 0x8f7b3d591e6a2c48);
    var num128: u128 = 0x123456789abcdef11121314151617181;
    try expect(@bit_reverse(num128) == 0x818e868a828c84888f7b3d591e6a2c48);

    // using comptime_ints, signed, positive
    try expect(@bit_reverse(@as(u8, 0)) == 0);
    try expect(@bit_reverse(@as(i8, @bit_cast(@as(u8, 0x92)))) == @as(i8, @bit_cast(@as(u8, 0x49))));
    try expect(@bit_reverse(@as(i16, @bit_cast(@as(u16, 0x1234)))) == @as(i16, @bit_cast(@as(u16, 0x2c48))));
    try expect(@bit_reverse(@as(i24, @bit_cast(@as(u24, 0x123456)))) == @as(i24, @bit_cast(@as(u24, 0x6a2c48))));
    try expect(@bit_reverse(@as(i24, @bit_cast(@as(u24, 0x12345f)))) == @as(i24, @bit_cast(@as(u24, 0xfa2c48))));
    try expect(@bit_reverse(@as(i24, @bit_cast(@as(u24, 0xf23456)))) == @as(i24, @bit_cast(@as(u24, 0x6a2c4f))));
    try expect(@bit_reverse(@as(i32, @bit_cast(@as(u32, 0x12345678)))) == @as(i32, @bit_cast(@as(u32, 0x1e6a2c48))));
    try expect(@bit_reverse(@as(i32, @bit_cast(@as(u32, 0xf2345678)))) == @as(i32, @bit_cast(@as(u32, 0x1e6a2c4f))));
    try expect(@bit_reverse(@as(i32, @bit_cast(@as(u32, 0x1234567f)))) == @as(i32, @bit_cast(@as(u32, 0xfe6a2c48))));
    try expect(@bit_reverse(@as(i40, @bit_cast(@as(u40, 0x123456789a)))) == @as(i40, @bit_cast(@as(u40, 0x591e6a2c48))));
    try expect(@bit_reverse(@as(i48, @bit_cast(@as(u48, 0x123456789abc)))) == @as(i48, @bit_cast(@as(u48, 0x3d591e6a2c48))));
    try expect(@bit_reverse(@as(i56, @bit_cast(@as(u56, 0x123456789abcde)))) == @as(i56, @bit_cast(@as(u56, 0x7b3d591e6a2c48))));
    try expect(@bit_reverse(@as(i64, @bit_cast(@as(u64, 0x123456789abcdef1)))) == @as(i64, @bit_cast(@as(u64, 0x8f7b3d591e6a2c48))));
    try expect(@bit_reverse(@as(i96, @bit_cast(@as(u96, 0x123456789abcdef111213141)))) == @as(i96, @bit_cast(@as(u96, 0x828c84888f7b3d591e6a2c48))));
    try expect(@bit_reverse(@as(i128, @bit_cast(@as(u128, 0x123456789abcdef11121314151617181)))) == @as(i128, @bit_cast(@as(u128, 0x818e868a828c84888f7b3d591e6a2c48))));

    // using signed, negative. Compare to runtime ints returned from llvm.
    var neg8: i8 = -18;
    try expect(@bit_reverse(@as(i8, -18)) == @bit_reverse(neg8));
    var neg16: i16 = -32694;
    try expect(@bit_reverse(@as(i16, -32694)) == @bit_reverse(neg16));
    var neg24: i24 = -6773785;
    try expect(@bit_reverse(@as(i24, -6773785)) == @bit_reverse(neg24));
    var neg32: i32 = -16773785;
    try expect(@bit_reverse(@as(i32, -16773785)) == @bit_reverse(neg32));

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
    const result = @bit_reverse(v);
    try expect(result[0] == 0x48);
    try expect(result[1] == 0xc4);
}

test "bit_reverse vectors u8" {
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
    const result = @bit_reverse(v);
    try expect(result[0] == 0x2c48);
    try expect(result[1] == 0xa2c4);
}

test "bit_reverse vectors u16" {
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
    const result = @bit_reverse(v);
    try expect(result[0] == 0x6a2c48);
    try expect(result[1] == 0xe6a2c4);
}

test "bit_reverse vectors u24" {
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
    const result = @bit_reverse(v);
    try expect(result[0] == 0);
    try expect(result[1] == 0);
}

test "bit_reverse vectors u0" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;

    try comptime vector0();
    try vector0();
}
