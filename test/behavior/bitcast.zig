const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const math = std.math;
const max_int = std.math.max_int;
const min_int = std.math.min_int;
const native_endian = builtin.target.cpu.arch.endian();

test "@bit_cast iX -> uX (32, 64)" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const bit_values = [_]usize{ 32, 64 };

    inline for (bit_values) |bits| {
        try test_bit_cast(bits);
        try comptime test_bit_cast(bits);
    }
}

test "@bit_cast iX -> uX (8, 16, 128)" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const bit_values = [_]usize{ 8, 16, 128 };

    inline for (bit_values) |bits| {
        try test_bit_cast(bits);
        try comptime test_bit_cast(bits);
    }
}

test "@bit_cast iX -> uX exotic integers" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const bit_values = [_]usize{ 1, 48, 27, 512, 493, 293, 125, 204, 112 };

    inline for (bit_values) |bits| {
        try test_bit_cast(bits);
        try comptime test_bit_cast(bits);
    }
}

fn test_bit_cast(comptime N: usize) !void {
    const iN = std.meta.Int(.signed, N);
    const uN = std.meta.Int(.unsigned, N);

    try expect(conv_i_n(N, -1) == max_int(uN));
    try expect(conv_u_n(N, max_int(uN)) == -1);

    try expect(conv_i_n(N, max_int(iN)) == max_int(iN));
    try expect(conv_u_n(N, max_int(iN)) == max_int(iN));

    try expect(conv_u_n(N, 1 << (N - 1)) == min_int(iN));
    try expect(conv_i_n(N, min_int(iN)) == (1 << (N - 1)));

    try expect(conv_u_n(N, 0) == 0);
    try expect(conv_i_n(N, 0) == 0);

    if (N > 24) {
        try expect(conv_u_n(N, 0xf23456) == 0xf23456);
    }
}

fn conv_i_n(comptime N: usize, x: std.meta.Int(.signed, N)) std.meta.Int(.unsigned, N) {
    return @as(std.meta.Int(.unsigned, N), @bit_cast(x));
}

fn conv_u_n(comptime N: usize, x: std.meta.Int(.unsigned, N)) std.meta.Int(.signed, N) {
    return @as(std.meta.Int(.signed, N), @bit_cast(x));
}

test "bitcast uX to bytes" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const bit_values = [_]usize{ 1, 48, 27, 512, 493, 293, 125, 204, 112 };
    inline for (bit_values) |bits| {
        try test_bit_cast(bits);
        try comptime test_bit_cast(bits);
    }
}

fn test_bit_castu_xto_bytes(comptime N: usize) !void {

    // The location of padding bits in these layouts are technically not defined
    // by LLVM, but we currently allow exotic integers to be cast (at comptime)
    // to types that expose their padding bits anyway.
    //
    // This test at least makes sure those bits are matched by the runtime behavior
    // on the platforms we target. If the above behavior is restricted after all,
    // this test should be deleted.

    const T = std.meta.Int(.unsigned, N);
    for ([_]T{ 0, ~@as(T, 0) }) |init_value| {
        var x: T = init_value;
        const bytes = std.mem.as_bytes(&x);

        const byte_count = (N + 7) / 8;
        switch (native_endian) {
            .little => {
                var byte_i = 0;
                while (byte_i < (byte_count - 1)) : (byte_i += 1) {
                    try expect(bytes[byte_i] == 0xff);
                }
                try expect(((bytes[byte_i] ^ 0xff) << -%@as(u3, @truncate(N))) == 0);
            },
            .big => {
                var byte_i = byte_count - 1;
                while (byte_i > 0) : (byte_i -= 1) {
                    try expect(bytes[byte_i] == 0xff);
                }
                try expect(((bytes[byte_i] ^ 0xff) << -%@as(u3, @truncate(N))) == 0);
            },
        }
    }
}

test "nested bitcast" {
    const S = struct {
        fn moo(x: isize) !void {
            try expect(@as(isize, @int_cast(42)) == x);
        }

        fn foo(x: isize) !void {
            try @This().moo(
                @as(isize, @bit_cast(if (x != 0) @as(usize, @bit_cast(x)) else @as(usize, @bit_cast(x)))),
            );
        }
    };

    try S.foo(42);
    try comptime S.foo(42);
}

// issue #3010: compiler segfault
test "bitcast literal [4]u8 param to u32" {
    const ip = @as(u32, @bit_cast([_]u8{ 255, 255, 255, 255 }));
    try expect(ip == max_int(u32));
}

test "bitcast generates a temporary value" {
    var y: u16 = 0x55AA;
    _ = &y;
    const x: u16 = @bit_cast(@as([2]u8, @bit_cast(y)));
    try expect(y == x);
}

test "@bit_cast packed structs at runtime and comptime" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Full = packed struct {
        number: u16,
    };
    const Divided = packed struct {
        half1: u8,
        quarter3: u4,
        quarter4: u4,
    };
    const S = struct {
        fn do_the_test() !void {
            var full = Full{ .number = 0x1234 };
            _ = &full;
            const two_halves: Divided = @bit_cast(full);
            try expect(two_halves.half1 == 0x34);
            try expect(two_halves.quarter3 == 0x2);
            try expect(two_halves.quarter4 == 0x1);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "@bit_cast extern structs at runtime and comptime" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Full = extern struct {
        number: u16,
    };
    const TwoHalves = extern struct {
        half1: u8,
        half2: u8,
    };
    const S = struct {
        fn do_the_test() !void {
            var full = Full{ .number = 0x1234 };
            _ = &full;
            const two_halves: TwoHalves = @bit_cast(full);
            switch (native_endian) {
                .big => {
                    try expect(two_halves.half1 == 0x12);
                    try expect(two_halves.half2 == 0x34);
                },
                .little => {
                    try expect(two_halves.half1 == 0x34);
                    try expect(two_halves.half2 == 0x12);
                },
            }
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "bitcast packed struct to integer and back" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const LevelUpMove = packed struct {
        move_id: u9,
        level: u7,
    };
    const S = struct {
        fn do_the_test() !void {
            var move = LevelUpMove{ .move_id = 1, .level = 2 };
            _ = &move;
            const v: u16 = @bit_cast(move);
            const back_to_a_move: LevelUpMove = @bit_cast(v);
            try expect(back_to_a_move.move_id == 1);
            try expect(back_to_a_move.level == 2);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "implicit cast to error union by returning" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn entry() !void {
            try expect((func(-1) catch unreachable) == max_int(u64));
        }
        pub fn func(sz: i64) anyerror!u64 {
            return @as(u64, @bit_cast(sz));
        }
    };
    try S.entry();
    try comptime S.entry();
}

test "bitcast packed struct literal to byte" {
    const Foo = packed struct {
        value: u8,
    };
    const casted = @as(u8, @bit_cast(Foo{ .value = 0xF }));
    try expect(casted == 0xf);
}

test "comptime bitcast used in expression has the correct type" {
    const Foo = packed struct {
        value: u8,
    };
    try expect(@as(u8, @bit_cast(Foo{ .value = 0xF })) == 0xf);
}

test "bitcast passed as tuple element" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn foo(args: anytype) !void {
            comptime assert(@TypeOf(args[0]) == f32);
            try expect(args[0] == 12.34);
        }
    };
    try S.foo(.{@as(f32, @bit_cast(@as(u32, 0x414570A4)))});
}

test "triple level result location with bitcast sandwich passed as tuple element" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn foo(args: anytype) !void {
            comptime assert(@TypeOf(args[0]) == f64);
            try expect(args[0] > 12.33 and args[0] < 12.35);
        }
    };
    try S.foo(.{@as(f64, @as(f32, @bit_cast(@as(u32, 0x414570A4))))});
}

test "@bit_cast packed struct of floats" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Foo = packed struct {
        a: f16 = 0,
        b: f32 = 1,
        c: f64 = 2,
        d: f128 = 3,
    };

    const Foo2 = packed struct {
        a: f16 = 0,
        b: f32 = 1,
        c: f64 = 2,
        d: f128 = 3,
    };

    const S = struct {
        fn do_the_test() !void {
            var foo = Foo{};
            _ = &foo;
            const v: Foo2 = @bit_cast(foo);
            try expect(v.a == foo.a);
            try expect(v.b == foo.b);
            try expect(v.c == foo.c);
            try expect(v.d == foo.d);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "comptime @bit_cast packed struct to int and back" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_llvm and native_endian == .big) {
        // https://github.com/ziglang/zig/issues/13782
        return error.SkipZigTest;
    }

    const S = packed struct {
        void: void = {},
        uint: u8 = 13,
        uint_bit_aligned: u3 = 2,
        iint_pos: i4 = 1,
        iint_neg4: i3 = -4,
        iint_neg2: i3 = -2,
        float: f32 = 3.14,
        @"enum": enum(u2) { A, B = 1, C, D } = .B,
        vectorb: @Vector(3, bool) = .{ true, false, true },
        vectori: @Vector(2, u8) = .{ 127, 42 },
        vectorf: @Vector(2, f16) = .{ 3.14, 2.71 },
    };
    const Int = @typeInfo(S).Struct.backing_integer.?;

    // S -> Int
    var s: S = .{};
    _ = &s;
    try expect_equal(@as(Int, @bit_cast(s)), comptime @as(Int, @bit_cast(S{})));

    // Int -> S
    var i: Int = 0;
    _ = &i;
    const rt_cast = @as(S, @bit_cast(i));
    const ct_cast = comptime @as(S, @bit_cast(@as(Int, 0)));
    inline for (@typeInfo(S).Struct.fields) |field| {
        try expect_equal(@field(rt_cast, field.name), @field(ct_cast, field.name));
    }
}

test "comptime bitcast with fields following f80" {
    if (true) {
        // https://github.com/ziglang/zig/issues/19387
        return error.SkipZigTest;
    }

    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;

    const FloatT = extern struct { f: f80, x: u128 align(16) };
    const x: FloatT = .{ .f = 0.5, .x = 123 };
    var x_as_uint: u256 = comptime @as(u256, @bit_cast(x));
    _ = &x_as_uint;

    try expect(x.f == @as(FloatT, @bit_cast(x_as_uint)).f);
    try expect(x.x == @as(FloatT, @bit_cast(x_as_uint)).x);
}

test "bitcast vector to integer and back" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const arr: [16]bool = [_]bool{ true, false } ++ [_]bool{true} ** 14;
    var x: @Vector(16, bool) = @splat(true);
    x[1] = false;
    try expect(@as(u16, @bit_cast(x)) == comptime @as(u16, @bit_cast(@as(@Vector(16, bool), arr))));
}

fn bit_cast_wrapper16(x: f16) u16 {
    return @as(u16, @bit_cast(x));
}
fn bit_cast_wrapper32(x: f32) u32 {
    return @as(u32, @bit_cast(x));
}
fn bit_cast_wrapper64(x: f64) u64 {
    return @as(u64, @bit_cast(x));
}
fn bit_cast_wrapper128(x: f128) u128 {
    return @as(u128, @bit_cast(x));
}
test "bitcast nan float does not modify signaling bit" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // TODO: https://github.com/ziglang/zig/issues/14366
    if (builtin.zig_backend == .stage2_llvm and comptime builtin.cpu.arch.is_arm_or_thumb()) return error.SkipZigTest;

    const snan_u16: u16 = 0x7D00;
    const snan_u32: u32 = 0x7FA00000;
    const snan_u64: u64 = 0x7FF4000000000000;
    const snan_u128: u128 = 0x7FFF4000000000000000000000000000;

    // 16 bit
    const snan_f16_const = math.snan(f16);
    try expect_equal(snan_u16, @as(u16, @bit_cast(snan_f16_const)));
    try expect_equal(snan_u16, bit_cast_wrapper16(snan_f16_const));

    var snan_f16_var = math.snan(f16);
    _ = &snan_f16_var;
    try expect_equal(snan_u16, @as(u16, @bit_cast(snan_f16_var)));
    try expect_equal(snan_u16, bit_cast_wrapper16(snan_f16_var));

    // 32 bit
    const snan_f32_const = math.snan(f32);
    try expect_equal(snan_u32, @as(u32, @bit_cast(snan_f32_const)));
    try expect_equal(snan_u32, bit_cast_wrapper32(snan_f32_const));

    var snan_f32_var = math.snan(f32);
    _ = &snan_f32_var;
    try expect_equal(snan_u32, @as(u32, @bit_cast(snan_f32_var)));
    try expect_equal(snan_u32, bit_cast_wrapper32(snan_f32_var));

    // 64 bit
    const snan_f64_const = math.snan(f64);
    try expect_equal(snan_u64, @as(u64, @bit_cast(snan_f64_const)));
    try expect_equal(snan_u64, bit_cast_wrapper64(snan_f64_const));

    var snan_f64_var = math.snan(f64);
    _ = &snan_f64_var;
    try expect_equal(snan_u64, @as(u64, @bit_cast(snan_f64_var)));
    try expect_equal(snan_u64, bit_cast_wrapper64(snan_f64_var));

    // 128 bit
    const snan_f128_const = math.snan(f128);
    try expect_equal(snan_u128, @as(u128, @bit_cast(snan_f128_const)));
    try expect_equal(snan_u128, bit_cast_wrapper128(snan_f128_const));

    var snan_f128_var = math.snan(f128);
    _ = &snan_f128_var;
    try expect_equal(snan_u128, @as(u128, @bit_cast(snan_f128_var)));
    try expect_equal(snan_u128, bit_cast_wrapper128(snan_f128_var));
}

test "@bit_cast of packed struct of bools all true" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const P = packed struct {
        b0: bool,
        b1: bool,
        b2: bool,
        b3: bool,
    };
    var p = std.mem.zeroes(P);
    p.b0 = true;
    p.b1 = true;
    p.b2 = true;
    p.b3 = true;
    try expect(@as(u8, @as(u4, @bit_cast(p))) == 15);
}

test "@bit_cast of packed struct of bools all false" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest; // TODO

    const P = packed struct {
        b0: bool,
        b1: bool,
        b2: bool,
        b3: bool,
    };
    var p = std.mem.zeroes(P);
    p.b0 = false;
    p.b1 = false;
    p.b2 = false;
    p.b3 = false;
    try expect(@as(u8, @as(u4, @bit_cast(p))) == 0);
}

test "@bit_cast of packed struct containing pointer" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest; // TODO

    const S = struct {
        const A = packed struct {
            ptr: *const u32,
        };

        const B = packed struct {
            ptr: *const i32,
        };

        fn do_the_test() !void {
            const x: u32 = 123;
            var a: A = undefined;
            a = .{ .ptr = &x };
            const b: B = @bit_cast(a);
            try expect(b.ptr.* == 123);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}

test "@bit_cast of extern struct containing pointer" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest; // TODO

    const S = struct {
        const A = extern struct {
            ptr: *const u32,
        };

        const B = extern struct {
            ptr: *const i32,
        };

        fn do_the_test() !void {
            const x: u32 = 123;
            var a: A = undefined;
            a = .{ .ptr = &x };
            const b: B = @bit_cast(a);
            try expect(b.ptr.* == 123);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}
