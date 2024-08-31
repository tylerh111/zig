const builtin = @import("builtin");
const std = @import("std");
const expect = std.testing.expect;

test "@abs integers" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_abs_integers();
    try test_abs_integers();
}

fn test_abs_integers() !void {
    {
        var x: i32 = -1000;
        _ = &x;
        try expect(@abs(x) == 1000);
    }
    {
        var x: i32 = 0;
        _ = &x;
        try expect(@abs(x) == 0);
    }
    {
        var x: i32 = 1000;
        _ = &x;
        try expect(@abs(x) == 1000);
    }
    {
        var x: i64 = std.math.min_int(i64);
        _ = &x;
        try expect(@abs(x) == @as(u64, -std.math.min_int(i64)));
    }
    {
        var x: i5 = -1;
        _ = &x;
        try expect(@abs(x) == 1);
    }
    {
        var x: i5 = -5;
        _ = &x;
        try expect(@abs(x) == 5);
    }
    comptime {
        try expect(@abs(@as(i2, -2)) == 2);
    }
}

test "@abs unsigned integers" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    try comptime test_abs_unsigned_integers();
    try test_abs_unsigned_integers();
}

fn test_abs_unsigned_integers() !void {
    {
        var x: u32 = 1000;
        _ = &x;
        try expect(@abs(x) == 1000);
    }
    {
        var x: u32 = 0;
        _ = &x;
        try expect(@abs(x) == 0);
    }
    {
        var x: u32 = 1000;
        _ = &x;
        try expect(@abs(x) == 1000);
    }
    {
        var x: u5 = 1;
        _ = &x;
        try expect(@abs(x) == 1);
    }
    {
        var x: u5 = 5;
        _ = &x;
        try expect(@abs(x) == 5);
    }
    comptime {
        try expect(@abs(@as(u2, 2)) == 2);
    }
}

test "@abs floats" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_abs_floats(f16);
    try test_abs_floats(f16);
    try comptime test_abs_floats(f32);
    try test_abs_floats(f32);
    try comptime test_abs_floats(f64);
    try test_abs_floats(f64);
    try comptime test_abs_floats(f80);
    if (builtin.zig_backend != .stage2_wasm and builtin.zig_backend != .stage2_spirv64) try test_abs_floats(f80);
    try comptime test_abs_floats(f128);
    if (builtin.zig_backend != .stage2_wasm and builtin.zig_backend != .stage2_spirv64) try test_abs_floats(f128);
}

fn test_abs_floats(comptime T: type) !void {
    {
        var x: T = -2.62;
        _ = &x;
        try expect(@abs(x) == 2.62);
    }
    {
        var x: T = 2.62;
        _ = &x;
        try expect(@abs(x) == 2.62);
    }
    {
        var x: T = 0.0;
        _ = &x;
        try expect(@abs(x) == 0.0);
    }
    {
        var x: T = -std.math.pi;
        _ = &x;
        try expect(@abs(x) == std.math.pi);
    }

    {
        var x: T = -std.math.inf(T);
        _ = &x;
        try expect(@abs(x) == std.math.inf(T));
    }
    {
        var x: T = std.math.inf(T);
        _ = &x;
        try expect(@abs(x) == std.math.inf(T));
    }
    comptime {
        try expect(@abs(@as(T, -std.math.e)) == std.math.e);
    }
}

test "@abs int vectors" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_abs_int_vectors(1);
    try test_abs_int_vectors(1);
    try comptime test_abs_int_vectors(2);
    try test_abs_int_vectors(2);
    try comptime test_abs_int_vectors(3);
    try test_abs_int_vectors(3);
    try comptime test_abs_int_vectors(4);
    try test_abs_int_vectors(4);
    try comptime test_abs_int_vectors(8);
    try test_abs_int_vectors(8);
    try comptime test_abs_int_vectors(16);
    try test_abs_int_vectors(16);
    try comptime test_abs_int_vectors(17);
    try test_abs_int_vectors(17);
}

fn test_abs_int_vectors(comptime len: comptime_int) !void {
    const I32 = @Vector(len, i32);
    const U32 = @Vector(len, u32);
    const I64 = @Vector(len, i64);
    const U64 = @Vector(len, u64);
    {
        var x: I32 = @splat(-10);
        var y: U32 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: I32 = @splat(10);
        var y: U32 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: I32 = @splat(0);
        var y: U32 = @splat(0);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: I64 = @splat(-10);
        var y: U64 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u64, &@as([len]u64, y), &@as([len]u64, @abs(x))));
    }
    {
        var x: I64 = @splat(std.math.min_int(i64));
        var y: U64 = @splat(-std.math.min_int(i64));
        _ = .{ &x, &y };
        try expect(std.mem.eql(u64, &@as([len]u64, y), &@as([len]u64, @abs(x))));
    }
    {
        var x = std.simd.repeat(len, @Vector(4, i32){ -2, 5, std.math.min_int(i32), -7 });
        var y = std.simd.repeat(len, @Vector(4, u32){ 2, 5, -std.math.min_int(i32), 7 });
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
}

test "@abs unsigned int vectors" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_abs_unsigned_int_vectors(1);
    try test_abs_unsigned_int_vectors(1);
    try comptime test_abs_unsigned_int_vectors(2);
    try test_abs_unsigned_int_vectors(2);
    try comptime test_abs_unsigned_int_vectors(3);
    try test_abs_unsigned_int_vectors(3);
    try comptime test_abs_unsigned_int_vectors(4);
    try test_abs_unsigned_int_vectors(4);
    try comptime test_abs_unsigned_int_vectors(8);
    try test_abs_unsigned_int_vectors(8);
    try comptime test_abs_unsigned_int_vectors(16);
    try test_abs_unsigned_int_vectors(16);
    try comptime test_abs_unsigned_int_vectors(17);
    try test_abs_unsigned_int_vectors(17);
}

fn test_abs_unsigned_int_vectors(comptime len: comptime_int) !void {
    const U32 = @Vector(len, u32);
    const U64 = @Vector(len, u64);
    {
        var x: U32 = @splat(10);
        var y: U32 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: U32 = @splat(10);
        var y: U32 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: U32 = @splat(0);
        var y: U32 = @splat(0);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
    {
        var x: U64 = @splat(10);
        var y: U64 = @splat(10);
        _ = .{ &x, &y };
        try expect(std.mem.eql(u64, &@as([len]u64, y), &@as([len]u64, @abs(x))));
    }
    {
        var x = std.simd.repeat(len, @Vector(3, u32){ 2, 5, 7 });
        var y = std.simd.repeat(len, @Vector(3, u32){ 2, 5, 7 });
        _ = .{ &x, &y };
        try expect(std.mem.eql(u32, &@as([len]u32, y), &@as([len]u32, @abs(x))));
    }
}

test "@abs float vectors" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/12827
    if (builtin.zig_backend == .stage2_llvm and
        builtin.os.tag == .macos and
        builtin.target.cpu.arch == .x86_64) return error.SkipZigTest;

    @setEvalBranchQuota(2000);
    try comptime test_abs_float_vectors(f16, 1);
    try test_abs_float_vectors(f16, 1);
    try comptime test_abs_float_vectors(f16, 2);
    try test_abs_float_vectors(f16, 2);
    try comptime test_abs_float_vectors(f16, 3);
    try test_abs_float_vectors(f16, 3);
    try comptime test_abs_float_vectors(f16, 4);
    try test_abs_float_vectors(f16, 4);
    try comptime test_abs_float_vectors(f16, 8);
    try test_abs_float_vectors(f16, 8);
    try comptime test_abs_float_vectors(f16, 16);
    try test_abs_float_vectors(f16, 16);
    try comptime test_abs_float_vectors(f16, 17);

    try test_abs_float_vectors(f32, 1);
    try comptime test_abs_float_vectors(f32, 1);
    try test_abs_float_vectors(f32, 1);
    try comptime test_abs_float_vectors(f32, 2);
    try test_abs_float_vectors(f32, 2);
    try comptime test_abs_float_vectors(f32, 3);
    try test_abs_float_vectors(f32, 3);
    try comptime test_abs_float_vectors(f32, 4);
    try test_abs_float_vectors(f32, 4);
    try comptime test_abs_float_vectors(f32, 8);
    try test_abs_float_vectors(f32, 8);
    try comptime test_abs_float_vectors(f32, 16);
    try test_abs_float_vectors(f32, 16);
    try comptime test_abs_float_vectors(f32, 17);
    try test_abs_float_vectors(f32, 17);

    try comptime test_abs_float_vectors(f64, 1);
    try test_abs_float_vectors(f64, 1);
    try comptime test_abs_float_vectors(f64, 2);
    try test_abs_float_vectors(f64, 2);
    try comptime test_abs_float_vectors(f64, 3);
    try test_abs_float_vectors(f64, 3);
    try comptime test_abs_float_vectors(f64, 4);
    try test_abs_float_vectors(f64, 4);
    try comptime test_abs_float_vectors(f64, 8);
    try test_abs_float_vectors(f64, 8);
    try comptime test_abs_float_vectors(f64, 16);
    try test_abs_float_vectors(f64, 16);
    try comptime test_abs_float_vectors(f64, 17);
    try test_abs_float_vectors(f64, 17);

    try comptime test_abs_float_vectors(f80, 1);
    try test_abs_float_vectors(f80, 1);
    try comptime test_abs_float_vectors(f80, 2);
    try test_abs_float_vectors(f80, 2);
    try comptime test_abs_float_vectors(f80, 3);
    try test_abs_float_vectors(f80, 3);
    try comptime test_abs_float_vectors(f80, 4);
    try test_abs_float_vectors(f80, 4);
    try comptime test_abs_float_vectors(f80, 8);
    try test_abs_float_vectors(f80, 8);
    try comptime test_abs_float_vectors(f80, 16);
    try test_abs_float_vectors(f80, 16);
    try comptime test_abs_float_vectors(f80, 17);
    try test_abs_float_vectors(f80, 17);

    try comptime test_abs_float_vectors(f128, 1);
    try test_abs_float_vectors(f128, 1);
    try comptime test_abs_float_vectors(f128, 2);
    try test_abs_float_vectors(f128, 2);
    try comptime test_abs_float_vectors(f128, 3);
    try test_abs_float_vectors(f128, 3);
    try comptime test_abs_float_vectors(f128, 4);
    try test_abs_float_vectors(f128, 4);
    try comptime test_abs_float_vectors(f128, 8);
    try test_abs_float_vectors(f128, 8);
    try comptime test_abs_float_vectors(f128, 16);
    try test_abs_float_vectors(f128, 16);
    try comptime test_abs_float_vectors(f128, 17);
    try test_abs_float_vectors(f128, 17);
}

fn test_abs_float_vectors(comptime T: type, comptime len: comptime_int) !void {
    const V = @Vector(len, T);
    {
        var x: V = @splat(-7.5);
        var y: V = @splat(7.5);
        _ = .{ &x, &y };
        try expect(std.mem.eql(T, &@as([len]T, y), &@as([len]T, @abs(x))));
    }
    {
        var x: V = @splat(7.5);
        var y: V = @splat(7.5);
        _ = .{ &x, &y };
        try expect(std.mem.eql(T, &@as([len]T, y), &@as([len]T, @abs(x))));
    }
    {
        var x: V = @splat(0.0);
        var y: V = @splat(0.0);
        _ = .{ &x, &y };
        try expect(std.mem.eql(T, &@as([len]T, y), &@as([len]T, @abs(x))));
    }
    {
        var x: V = @splat(-std.math.pi);
        var y: V = @splat(std.math.pi);
        _ = .{ &x, &y };
        try expect(std.mem.eql(T, &@as([len]T, y), &@as([len]T, @abs(x))));
    }
    {
        var x: V = @splat(std.math.pi);
        var y: V = @splat(std.math.pi);
        _ = .{ &x, &y };
        try expect(std.mem.eql(T, &@as([len]T, y), &@as([len]T, @abs(x))));
    }
}
