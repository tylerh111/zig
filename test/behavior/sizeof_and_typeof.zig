const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

test "@sizeof and @TypeOf" {
    const y: @TypeOf(x) = 120;
    try expect(@sizeof(@TypeOf(y)) == 2);
}
const x: u16 = 13;
const z: @TypeOf(x) = 19;

test "@sizeof on compile-time types" {
    try expect(@sizeof(comptime_int) == 0);
    try expect(@sizeof(comptime_float) == 0);
    try expect(@sizeof(@TypeOf(.hi)) == 0);
    try expect(@sizeof(@TypeOf(type)) == 0);
}

test "@TypeOf() with multiple arguments" {
    {
        var var_1: u32 = undefined;
        var var_2: u8 = undefined;
        var var_3: u64 = undefined;
        _ = .{ &var_1, &var_2, &var_3 };
        comptime assert(@TypeOf(var_1, var_2, var_3) == u64);
    }
    {
        var var_1: f16 = undefined;
        var var_2: f32 = undefined;
        var var_3: f64 = undefined;
        _ = .{ &var_1, &var_2, &var_3 };
        comptime assert(@TypeOf(var_1, var_2, var_3) == f64);
    }
    {
        var var_1: u16 = undefined;
        _ = &var_1;
        comptime assert(@TypeOf(var_1, 0xffff) == u16);
    }
    {
        var var_1: f32 = undefined;
        _ = &var_1;
        comptime assert(@TypeOf(var_1, 3.1415) == f32);
    }
}

fn fn1(alpha: bool) void {
    const n: usize = 7;
    _ = if (alpha) n else @sizeof(usize);
}

test "lazy @sizeof result is checked for definedness" {
    _ = &fn1;
}

const A = struct {
    a: u8,
    b: u32,
    c: u8,
    d: u3,
    e: u5,
    f: u16,
    g: u16,
    h: u9,
    i: u7,
};

const P = packed struct {
    a: u8,
    b: u32,
    c: u8,
    d: u3,
    e: u5,
    f: u16,
    g: u16,
    h: u9,
    i: u7,
};

test "@offsetof" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Packed structs have fixed memory layout
    try expect(@offsetof(P, "a") == 0);
    try expect(@offsetof(P, "b") == 1);
    try expect(@offsetof(P, "c") == 5);
    try expect(@offsetof(P, "d") == 6);
    try expect(@offsetof(P, "e") == 6);
    try expect(@offsetof(P, "f") == 7);
    try expect(@offsetof(P, "g") == 9);
    try expect(@offsetof(P, "h") == 11);
    try expect(@offsetof(P, "i") == 12);

    // // Normal struct fields can be moved/padded
    var a: A = undefined;
    try expect(@intfromptr(&a.a) - @intfromptr(&a) == @offsetof(A, "a"));
    try expect(@intfromptr(&a.b) - @intfromptr(&a) == @offsetof(A, "b"));
    try expect(@intfromptr(&a.c) - @intfromptr(&a) == @offsetof(A, "c"));
    try expect(@intfromptr(&a.d) - @intfromptr(&a) == @offsetof(A, "d"));
    try expect(@intfromptr(&a.e) - @intfromptr(&a) == @offsetof(A, "e"));
    try expect(@intfromptr(&a.f) - @intfromptr(&a) == @offsetof(A, "f"));
    try expect(@intfromptr(&a.g) - @intfromptr(&a) == @offsetof(A, "g"));
    try expect(@intfromptr(&a.h) - @intfromptr(&a) == @offsetof(A, "h"));
    try expect(@intfromptr(&a.i) - @intfromptr(&a) == @offsetof(A, "i"));
}

test "@bitoffsetof" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    // Packed structs have fixed memory layout
    try expect(@bitoffsetof(P, "a") == 0);
    try expect(@bitoffsetof(P, "b") == 8);
    try expect(@bitoffsetof(P, "c") == 40);
    try expect(@bitoffsetof(P, "d") == 48);
    try expect(@bitoffsetof(P, "e") == 51);
    try expect(@bitoffsetof(P, "f") == 56);
    try expect(@bitoffsetof(P, "g") == 72);

    try expect(@offsetof(A, "a") * 8 == @bitoffsetof(A, "a"));
    try expect(@offsetof(A, "b") * 8 == @bitoffsetof(A, "b"));
    try expect(@offsetof(A, "c") * 8 == @bitoffsetof(A, "c"));
    try expect(@offsetof(A, "d") * 8 == @bitoffsetof(A, "d"));
    try expect(@offsetof(A, "e") * 8 == @bitoffsetof(A, "e"));
    try expect(@offsetof(A, "f") * 8 == @bitoffsetof(A, "f"));
    try expect(@offsetof(A, "g") * 8 == @bitoffsetof(A, "g"));
}

test "@sizeof(T) == 0 doesn't force resolving struct size" {
    const S = struct {
        const Foo = struct {
            y: if (@sizeof(Foo) == 0) u64 else u32,
        };
        const Bar = struct {
            x: i32,
            y: if (0 == @sizeof(Bar)) u64 else u32,
        };
    };

    try expect(@sizeof(S.Foo) == 4);
    try expect(@sizeof(S.Bar) == 8);
}

test "@TypeOf() has no runtime side effects" {
    const S = struct {
        fn foo(comptime T: type, ptr: *T) T {
            ptr.* += 1;
            return ptr.*;
        }
    };
    var data: i32 = 0;
    const T = @TypeOf(S.foo(i32, &data));
    comptime assert(T == i32);
    try expect(data == 0);
}

test "branching logic inside @TypeOf" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        var data: i32 = 0;
        fn foo() anyerror!i32 {
            data += 1;
            return undefined;
        }
    };
    const T = @TypeOf(S.foo() catch undefined);
    comptime assert(T == i32);
    try expect(S.data == 0);
}

test "@bitsizeof" {
    try expect(@bitsizeof(u2) == 2);
    try expect(@bitsizeof(u8) == @sizeof(u8) * 8);
    try expect(@bitsizeof(struct {
        a: u2,
    }) == 8);
    try expect(@bitsizeof(packed struct {
        a: u2,
    }) == 2);
}

test "@sizeof comparison against zero" {
    const S0 = struct {
        f: *@This(),
    };
    const U0 = union {
        f: *@This(),
    };
    const S1 = struct {
        fn H(comptime T: type) type {
            return struct {
                x: T,
            };
        }
        f0: H(*@This()),
        f1: H(**@This()),
        f2: H(***@This()),
    };
    const U1 = union {
        fn H(comptime T: type) type {
            return struct {
                x: T,
            };
        }
        f0: H(*@This()),
        f1: H(**@This()),
        f2: H(***@This()),
    };
    const S = struct {
        fn doTheTest(comptime T: type, comptime result: bool) !void {
            try expect(result == (@sizeof(T) > 0));
        }
    };
    // Zero-sized type
    try S.doTheTest(u0, false);
    // Pointers to zero sized types still have addresses.
    try S.doTheTest(*u0, true);
    // Non byte-sized type
    try S.doTheTest(u1, true);
    try S.doTheTest(*u1, true);
    // Regular type
    try S.doTheTest(u8, true);
    try S.doTheTest(*u8, true);
    try S.doTheTest(f32, true);
    try S.doTheTest(*f32, true);
    // Container with ptr pointing to themselves
    try S.doTheTest(S0, true);
    try S.doTheTest(U0, true);
    try S.doTheTest(S1, true);
    try S.doTheTest(U1, true);
}

test "hardcoded address in typeof expression" {
    const S = struct {
        fn func() @TypeOf(@as(*[]u8, @ptrfromint(0x10)).*[0]) {
            return 0;
        }
    };
    try expect(S.func() == 0);
    comptime assert(S.func() == 0);
}

test "array access of generic param in typeof expression" {
    const S = struct {
        fn first(comptime items: anytype) @TypeOf(items[0]) {
            return items[0];
        }
    };
    try expect(S.first("a") == 'a');
    comptime assert(S.first("a") == 'a');
}

test "lazy size cast to float" {
    {
        const S = struct { a: u8 };
        try expect(@as(f32, @floatfromint(@sizeof(S))) == 1.0);
    }
    {
        const S = struct { a: u8 };
        try expect(@as(f32, @sizeof(S)) == 1.0);
    }
}

test "bitsizeof comptime_int" {
    try expect(@bitsizeof(comptime_int) == 0);
}

test "runtime instructions inside typeof in comptime only scope" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    {
        var y: i8 = 2;
        _ = &y;
        const i: [2]i8 = [_]i8{ 1, y };
        const T = struct {
            a: @TypeOf(i) = undefined, // causes crash
            b: @TypeOf(i[0]) = undefined, // causes crash
        };
        try expect(@TypeOf((T{}).a) == [2]i8);
        try expect(@TypeOf((T{}).b) == i8);
    }
    {
        var y: i8 = 2;
        _ = &y;
        const i = .{ 1, y };
        const T = struct {
            b: @TypeOf(i[1]) = undefined,
        };
        try expect(@TypeOf((T{}).b) == i8);
    }
}

test "@sizeof optional of previously unresolved union" {
    const Node = union { a: usize };
    try expect(@sizeof(?Node) == @sizeof(Node) + @alignof(Node));
}

test "@offsetof zero-bit field" {
    const S = packed struct {
        a: u32,
        b: u0,
        c: u32,
    };
    try expect(@offsetof(S, "b") == @offsetof(S, "c"));
}

test "@bitsizeof on array of structs" {
    const S = struct {
        foo: u64,
    };

    try expectEqual(128, @bitsizeof([2]S));
}

test "lazy abi size used in comparison" {
    const S = struct { a: usize };
    var rhs: i32 = 100;
    _ = &rhs;
    try expect(@sizeof(S) < rhs);
}

test "peer type resolution with @TypeOf doesn't trigger dependency loop check" {
    if (builtin.zig_backend == .stage2_x86) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const T = struct {
        next: @TypeOf(null, @as(*const @This(), undefined)),
    };
    var t: T = .{ .next = null };
    _ = &t;
    try std.testing.expect(t.next == null);
}

test "@sizeof reified union zero-size payload fields" {
    comptime {
        try std.testing.expect(0 == @sizeof(@Type(@typeinfo(union {}))));
        try std.testing.expect(0 == @sizeof(@Type(@typeinfo(union { a: void }))));
        if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
            try std.testing.expect(1 == @sizeof(@Type(@typeinfo(union { a: void, b: void }))));
            try std.testing.expect(1 == @sizeof(@Type(@typeinfo(union { a: void, b: void, c: void }))));
        } else {
            try std.testing.expect(0 == @sizeof(@Type(@typeinfo(union { a: void, b: void }))));
            try std.testing.expect(0 == @sizeof(@Type(@typeinfo(union { a: void, b: void, c: void }))));
        }
    }
}

const FILE = extern struct {
    dummy_field: u8,
};

extern fn c_printf([*c]const u8, ...) c_int;
extern fn c_fputs([*c]const u8, noalias [*c]FILE) c_int;
extern fn c_ftell([*c]FILE) c_long;
extern fn c_fopen([*c]const u8, [*c]const u8) [*c]FILE;

test "Extern function calls in @TypeOf" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = extern struct {
        state: c_short,

        extern fn s_do_thing([*c]const @This(), b: c_int) c_short;
    };

    const Test = struct {
        fn test_fn_1(a: anytype, b: anytype) @TypeOf(c_printf("%d %s\n", a, b)) {
            return 0;
        }

        fn test_fn_2(s: anytype, a: anytype) @TypeOf(s.s_do_thing(a)) {
            return 1;
        }

        fn doTheTest() !void {
            try expect(@TypeOf(test_fn_1(0, 42)) == c_int);
            try expect(@TypeOf(test_fn_2(&S{ .state = 1 }, 0)) == c_short);
        }
    };

    try Test.doTheTest();
    try comptime Test.doTheTest();
}

test "Peer resolution of extern function calls in @TypeOf" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const Test = struct {
        fn test_fn() @TypeOf(c_ftell(null), c_fputs(null, null)) {
            return 0;
        }

        fn doTheTest() !void {
            try expect(@TypeOf(test_fn()) == c_long);
        }
    };

    try Test.doTheTest();
    try comptime Test.doTheTest();
}

test "Extern function calls, dereferences and field access in @TypeOf" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Test = struct {
        fn test_fn_1(a: c_long) @TypeOf(c_fopen("test", "r").*) {
            _ = a;
            return .{ .dummy_field = 0 };
        }

        fn test_fn_2(a: anytype) @TypeOf(c_fopen("test", "r").*.dummy_field) {
            _ = a;
            return 255;
        }

        fn doTheTest() !void {
            try expect(@TypeOf(test_fn_1(0)) == FILE);
            try expect(@TypeOf(test_fn_2(0)) == u8);
        }
    };

    try Test.doTheTest();
    try comptime Test.doTheTest();
}

test "@sizeof struct is resolved when used as operand of slicing" {
    const dummy = struct {};
    const S = struct {
        var buf: [1]u8 = undefined;
    };
    S.buf[@sizeof(dummy)..][0] = 0;
    try expect(S.buf[0] == 0);
}
