const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;

const supports_128_bit_atomics = switch (builtin.cpu.arch) {
    // TODO: Ideally this could be sync'd with the logic in Sema.
    .aarch64, .aarch64_be, .aarch64_32 => true,
    .x86_64 => std.Target.x86.feature_set_has(builtin.cpu.features, .cx16),
    else => false,
};

test "cmpxchg" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_cmpxchg();
    try comptime test_cmpxchg();
}

fn test_cmpxchg() !void {
    var x: i32 = 1234;
    if (@cmpxchg_weak(i32, &x, 99, 5678, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == 1234);
    } else {
        @panic("cmpxchg should have failed");
    }

    while (@cmpxchg_weak(i32, &x, 1234, 5678, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == 1234);
    }
    try expect(x == 5678);

    try expect(@cmpxchg_strong(i32, &x, 5678, 42, .seq_cst, .seq_cst) == null);
    try expect(x == 42);
}

test "fence" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var x: i32 = 1234;
    @fence(.seq_cst);
    x = 5678;
}

test "atomicrmw and atomicload" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var data: u8 = 200;
    try test_atomic_rmw(&data);
    try expect(data == 42);
    try test_atomic_load(&data);
}

fn test_atomic_rmw(ptr: *u8) !void {
    const prev_value = @atomicRmw(u8, ptr, .Xchg, 42, .seq_cst);
    try expect(prev_value == 200);
    comptime {
        var x: i32 = 1234;
        const y: i32 = 12345;
        try expect(@atomicLoad(i32, &x, .seq_cst) == 1234);
        try expect(@atomicLoad(i32, &y, .seq_cst) == 12345);
    }
}

fn test_atomic_load(ptr: *u8) !void {
    const x = @atomicLoad(u8, ptr, .seq_cst);
    try expect(x == 42);
}

test "cmpxchg with ptr" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var data1: i32 = 1234;
    var data2: i32 = 5678;
    var data3: i32 = 9101;
    var x: *i32 = &data1;
    if (@cmpxchg_weak(*i32, &x, &data2, &data3, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == &data1);
    } else {
        @panic("cmpxchg should have failed");
    }

    while (@cmpxchg_weak(*i32, &x, &data1, &data3, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == &data1);
    }
    try expect(x == &data3);

    try expect(@cmpxchg_strong(*i32, &x, &data3, &data2, .seq_cst, .seq_cst) == null);
    try expect(x == &data2);
}

test "cmpxchg with ignored result" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var x: i32 = 1234;

    _ = @cmpxchg_strong(i32, &x, 1234, 5678, .monotonic, .monotonic);

    try expect(5678 == x);
}

test "128-bit cmpxchg" {
    if (!supports_128_bit_atomics) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO

    try test_u128_cmpxchg();
    try comptime test_u128_cmpxchg();
}

fn test_u128_cmpxchg() !void {
    var x: u128 align(16) = 1234;
    if (@cmpxchg_weak(u128, &x, 99, 5678, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == 1234);
    } else {
        @panic("cmpxchg should have failed");
    }

    while (@cmpxchg_weak(u128, &x, 1234, 5678, .seq_cst, .seq_cst)) |x1| {
        try expect(x1 == 1234);
    }
    try expect(x == 5678);

    try expect(@cmpxchg_strong(u128, &x, 5678, 42, .seq_cst, .seq_cst) == null);
    try expect(x == 42);
}

var a_global_variable = @as(u32, 1234);

test "cmpxchg on a global variable" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .aarch64) {
        // https://github.com/ziglang/zig/issues/10627
        return error.SkipZigTest;
    }

    _ = @cmpxchg_weak(u32, &a_global_variable, 1234, 42, .acquire, .monotonic);
    try expect(a_global_variable == 42);
}

test "atomic load and rmw with enum" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Value = enum(u8) { a, b, c };
    var x = Value.a;

    try expect(@atomicLoad(Value, &x, .seq_cst) != .b);

    _ = @atomicRmw(Value, &x, .Xchg, .c, .seq_cst);
    try expect(@atomicLoad(Value, &x, .seq_cst) == .c);
    try expect(@atomicLoad(Value, &x, .seq_cst) != .a);
    try expect(@atomicLoad(Value, &x, .seq_cst) != .b);
}

test "atomic store" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var x: u32 = 0;
    @atomicStore(u32, &x, 1, .seq_cst);
    try expect(@atomicLoad(u32, &x, .seq_cst) == 1);
    @atomicStore(u32, &x, 12345678, .seq_cst);
    try expect(@atomicLoad(u32, &x, .seq_cst) == 12345678);
}

test "atomic store comptime" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try comptime test_atomic_store();
    try test_atomic_store();
}

fn test_atomic_store() !void {
    var x: u32 = 0;
    @atomicStore(u32, &x, 1, .seq_cst);
    try expect(@atomicLoad(u32, &x, .seq_cst) == 1);
    @atomicStore(u32, &x, 12345678, .seq_cst);
    try expect(@atomicLoad(u32, &x, .seq_cst) == 12345678);
}

test "atomicrmw with floats" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .aarch64) {
        // https://github.com/ziglang/zig/issues/10627
        return error.SkipZigTest;
    }
    try test_atomic_rmw_float();
    try comptime test_atomic_rmw_float();
}

fn test_atomic_rmw_float() !void {
    var x: f32 = 0;
    try expect(x == 0);
    _ = @atomicRmw(f32, &x, .Xchg, 1, .seq_cst);
    try expect(x == 1);
    _ = @atomicRmw(f32, &x, .Add, 5, .seq_cst);
    try expect(x == 6);
    _ = @atomicRmw(f32, &x, .Sub, 2, .seq_cst);
    try expect(x == 4);
    _ = @atomicRmw(f32, &x, .Max, 13, .seq_cst);
    try expect(x == 13);
    _ = @atomicRmw(f32, &x, .Min, 42, .seq_cst);
    try expect(x == 13);
}

test "atomicrmw with ints" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_llvm and builtin.cpu.arch.is_mips()) {
        // https://github.com/ziglang/zig/issues/16846
        return error.SkipZigTest;
    }

    try test_atomic_rmw_ints();
    try comptime test_atomic_rmw_ints();
}

fn test_atomic_rmw_ints() !void {
    // TODO: Use the max atomic bit size for the target, maybe builtin?
    try test_atomic_rmw_int(.unsigned, 8);

    if (builtin.cpu.arch == .x86_64) {
        try test_atomic_rmw_int(.unsigned, 16);
        try test_atomic_rmw_int(.unsigned, 32);
        try test_atomic_rmw_int(.unsigned, 64);
    }
}

fn test_atomic_rmw_int(comptime signedness: std.builtin.Signedness, comptime N: usize) !void {
    const int = std.meta.Int(signedness, N);

    var x: int = 1;
    var res = @atomicRmw(int, &x, .Xchg, 3, .seq_cst);
    try expect(x == 3 and res == 1);

    res = @atomicRmw(int, &x, .Add, 3, .seq_cst);
    var y: int = 3;
    try expect(res == y);
    y = y + 3;
    try expect(x == y);

    res = @atomicRmw(int, &x, .Sub, 1, .seq_cst);
    try expect(res == y);
    y = y - 1;
    try expect(x == y);

    res = @atomicRmw(int, &x, .And, 4, .seq_cst);
    try expect(res == y);
    y = y & 4;
    try expect(x == y);

    res = @atomicRmw(int, &x, .Nand, 4, .seq_cst);
    try expect(res == y);
    y = ~(y & 4);
    try expect(x == y);

    res = @atomicRmw(int, &x, .Or, 6, .seq_cst);
    try expect(res == y);
    y = y | 6;
    try expect(x == y);

    res = @atomicRmw(int, &x, .Xor, 2, .seq_cst);
    try expect(res == y);
    y = y ^ 2;
    try expect(x == y);

    res = @atomicRmw(int, &x, .Max, 1, .seq_cst);
    try expect(res == y);
    y = @max(y, 1);
    try expect(x == y);

    res = @atomicRmw(int, &x, .Min, 1, .seq_cst);
    try expect(res == y);
    y = @min(y, 1);
    try expect(x == y);
}

test "atomicrmw with 128-bit ints" {
    if (!supports_128_bit_atomics) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO

    // TODO "ld.lld: undefined symbol: __sync_lock_test_and_set_16" on -mcpu x86_64
    if (builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm) return error.SkipZigTest;

    try test_atomic_rmw_int128(.signed);
    try test_atomic_rmw_int128(.unsigned);
    try comptime test_atomic_rmw_int128(.signed);
    try comptime test_atomic_rmw_int128(.unsigned);
}

fn test_atomic_rmw_int128(comptime signedness: std.builtin.Signedness) !void {
    const uint = std.meta.Int(.unsigned, 128);
    const int = std.meta.Int(signedness, 128);

    const initial: int = @as(int, @bit_cast(@as(uint, 0xaaaaaaaa_bbbbbbbb_cccccccc_dddddddd)));
    const replacement: int = 0x00000000_00000005_00000000_00000003;

    var x: int align(16) = initial;
    var res = @atomicRmw(int, &x, .Xchg, replacement, .seq_cst);
    try expect(x == replacement and res == initial);

    var operator: int = 0x00000001_00000000_20000000_00000000;
    res = @atomicRmw(int, &x, .Add, operator, .seq_cst);
    var y: int = replacement;
    try expect(res == y);
    y = y + operator;
    try expect(x == y);

    operator = 0x00000000_10000000_00000000_20000000;
    res = @atomicRmw(int, &x, .Sub, operator, .seq_cst);
    try expect(res == y);
    y = y - operator;
    try expect(x == y);

    operator = 0x12345678_87654321_12345678_87654321;
    res = @atomicRmw(int, &x, .And, operator, .seq_cst);
    try expect(res == y);
    y = y & operator;
    try expect(x == y);

    operator = 0x00000000_10000000_00000000_20000000;
    res = @atomicRmw(int, &x, .Nand, operator, .seq_cst);
    try expect(res == y);
    y = ~(y & operator);
    try expect(x == y);

    operator = 0x12340000_56780000_67890000_98760000;
    res = @atomicRmw(int, &x, .Or, operator, .seq_cst);
    try expect(res == y);
    y = y | operator;
    try expect(x == y);

    operator = 0x0a0b0c0d_0e0f0102_03040506_0708090a;
    res = @atomicRmw(int, &x, .Xor, operator, .seq_cst);
    try expect(res == y);
    y = y ^ operator;
    try expect(x == y);

    operator = 0x00000000_10000000_00000000_20000000;
    res = @atomicRmw(int, &x, .Max, operator, .seq_cst);
    try expect(res == y);
    y = @max(y, operator);
    try expect(x == y);

    res = @atomicRmw(int, &x, .Min, operator, .seq_cst);
    try expect(res == y);
    y = @min(y, operator);
    try expect(x == y);
}

test "atomics with different types" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_atomics_with_type(bool, true, false);

    try test_atomics_with_type(u1, 0, 1);
    try test_atomics_with_type(i4, 0, 1);
    try test_atomics_with_type(u5, 0, 1);
    try test_atomics_with_type(i15, 0, 1);
    try test_atomics_with_type(u24, 0, 1);

    try test_atomics_with_type(u0, 0, 0);
    try test_atomics_with_type(i0, 0, 0);
}

fn test_atomics_with_type(comptime T: type, a: T, b: T) !void {
    var x: T = b;
    @atomicStore(T, &x, a, .seq_cst);
    try expect(x == a);
    try expect(@atomicLoad(T, &x, .seq_cst) == a);
    try expect(@atomicRmw(T, &x, .Xchg, b, .seq_cst) == a);
    try expect(@cmpxchg_strong(T, &x, b, a, .seq_cst, .seq_cst) == null);
    if (@size_of(T) != 0)
        try expect(@cmpxchg_strong(T, &x, b, a, .seq_cst, .seq_cst).? == a);
}

test "return @atomicStore, using it as a void value" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const A = struct {
            value: usize,

            pub fn store(self: *A, value: usize) void {
                return @atomicStore(usize, &self.value, value, .unordered);
            }

            pub fn store2(self: *A, value: usize) void {
                return switch (value) {
                    else => @atomicStore(usize, &self.value, value, .unordered),
                };
            }
        };

        fn do_the_test() !void {
            var x: A = .{ .value = 5 };
            x.store(10);
            try expect(x.value == 10);
            x.store(100);
            try expect(x.value == 100);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}
