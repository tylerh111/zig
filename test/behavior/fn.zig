const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;
const expect = testing.expect;
const expect_equal = testing.expect_equal;

test "params" {
    try expect(test_params_add(22, 11) == 33);
}
fn test_params_add(a: i32, b: i32) i32 {
    return a + b;
}

test "local variables" {
    test_loc_vars(2);
}
fn test_loc_vars(b: i32) void {
    const a: i32 = 1;
    if (a + b != 3) unreachable;
}

test "mutable local variables" {
    var zero: i32 = 0;
    _ = &zero;
    try expect(zero == 0);

    var i = @as(i32, 0);
    while (i != 3) {
        i += 1;
    }
    try expect(i == 3);
}

test "separate block scopes" {
    {
        const no_conflict: i32 = 5;
        try expect(no_conflict == 5);
    }

    const c = x: {
        const no_conflict = @as(i32, 10);
        break :x no_conflict;
    };
    try expect(c == 10);
}

fn @"weird function name"() i32 {
    return 1234;
}
test "weird function name" {
    try expect(@"weird function name"() == 1234);
}

test "assign inline fn to const variable" {
    const a = inline_fn;
    a();
}

inline fn inline_fn() void {}

fn outer(y: u32) *const fn (u32) u32 {
    const Y = @TypeOf(y);
    const st = struct {
        fn get(z: u32) u32 {
            return z + @size_of(Y);
        }
    };
    return st.get;
}

test "return inner function which references comptime variable of outer function" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const func = outer(10);
    try expect(func(3) == 7);
}

test "discard the result of a function that returns a struct" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn entry() void {
            _ = func();
        }

        fn func() Foo {
            return undefined;
        }

        const Foo = struct {
            a: u64,
            b: u64,
        };
    };
    S.entry();
    comptime S.entry();
}

test "inline function call that calls optional function pointer, return pointer at callsite interacts correctly with callsite return type" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        field: u32,

        fn do_the_test() !void {
            bar2 = actual_fn;
            const result = try foo();
            try expect(result.field == 1234);
        }

        const Foo = struct { field: u32 };

        fn foo() !Foo {
            var res: Foo = undefined;
            res.field = bar();
            return res;
        }

        inline fn bar() u32 {
            return bar2.?();
        }

        var bar2: ?*const fn () u32 = null;

        fn actual_fn() u32 {
            return 1234;
        }
    };
    try S.do_the_test();
}

test "implicit cast function unreachable return" {
    wants_fn_with_void(fn_with_unreachable);
}

fn wants_fn_with_void(comptime f: fn () void) void {
    _ = f;
}

fn fn_with_unreachable() noreturn {
    unreachable;
}

test "extern struct with stdcallcc fn pointer" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c and builtin.cpu.arch == .x86) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = extern struct {
        ptr: *const fn () callconv(if (builtin.target.cpu.arch == .x86) .Stdcall else .C) i32,

        fn foo() callconv(if (builtin.target.cpu.arch == .x86) .Stdcall else .C) i32 {
            return 1234;
        }
    };

    var s: S = undefined;
    s.ptr = S.foo;
    try expect(s.ptr() == 1234);
}

const nComplexCallconv = 100;
fn f_complex_callconv_ret(x: u32) callconv(blk: {
    const s: struct { n: u32 } = .{ .n = nComplexCallconv };
    break :blk switch (s.n) {
        0 => .C,
        1 => .Inline,
        else => .Unspecified,
    };
}) struct { x: u32 } {
    return .{ .x = x * x };
}

test "function with complex callconv and return type expressions" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(f_complex_callconv_ret(3).x == 9);
}

test "pass by non-copying value" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(add_point_coords(Point{ .x = 1, .y = 2 }) == 3);
}

const Point = struct {
    x: i32,
    y: i32,
};

fn add_point_coords(pt: Point) i32 {
    return pt.x + pt.y;
}

test "pass by non-copying value through var arg" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect((try add_point_coords_var(Point{ .x = 1, .y = 2 })) == 3);
}

fn add_point_coords_var(pt: anytype) !i32 {
    comptime assert(@TypeOf(pt) == Point);
    return pt.x + pt.y;
}

test "pass by non-copying value as method" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var pt = Point2{ .x = 1, .y = 2 };
    try expect(pt.add_point_coords() == 3);
}

const Point2 = struct {
    x: i32,
    y: i32,

    fn add_point_coords(self: Point2) i32 {
        return self.x + self.y;
    }
};

test "pass by non-copying value as method, which is generic" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var pt = Point3{ .x = 1, .y = 2 };
    try expect(pt.add_point_coords(i32) == 3);
}

const Point3 = struct {
    x: i32,
    y: i32,

    fn add_point_coords(self: Point3, comptime T: type) i32 {
        _ = T;
        return self.x + self.y;
    }
};

test "pass by non-copying value as method, at comptime" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    comptime {
        var pt = Point2{ .x = 1, .y = 2 };
        try expect(pt.add_point_coords() == 3);
    }
}

test "implicit cast fn call result to optional in field result" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn entry() !void {
            const x = Foo{
                .field = optional_ptr(),
            };
            try expect(x.field.?.* == 999);
        }

        const glob: i32 = 999;

        fn optional_ptr() *const i32 {
            return &glob;
        }

        const Foo = struct {
            field: ?*const i32,
        };
    };
    try S.entry();
    try comptime S.entry();
}

test "void parameters" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try void_fun(1, void{}, 2, {});
}
fn void_fun(a: i32, b: void, c: i32, d: void) !void {
    _ = d;
    const v = b;
    const vv: void = if (a == 1) v else {};
    try expect(a + c == 3);
    return vv;
}

test "call function with empty string" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    accepts_string("");
}

fn accepts_string(foo: []u8) void {
    _ = foo;
}

test "function pointers" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const fns = [_]*const @TypeOf(fn1){
        &fn1,
        &fn2,
        &fn3,
        &fn4,
    };
    for (fns, 0..) |f, i| {
        try expect(f() == @as(u32, @int_cast(i)) + 5);
    }
}
fn fn1() u32 {
    return 5;
}
fn fn2() u32 {
    return 6;
}
fn fn3() u32 {
    return 7;
}
fn fn4() u32 {
    return 8;
}

test "number literal as an argument" {
    try number_literal_arg(3);
    try comptime number_literal_arg(3);
}

fn number_literal_arg(a: anytype) !void {
    try expect(a == 3);
}

test "function call with anon list literal" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try consume_vec(.{ 9, 8, 7 });
        }

        fn consume_vec(vec: [3]f32) !void {
            try expect(vec[0] == 9);
            try expect(vec[1] == 8);
            try expect(vec[2] == 7);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "function call with anon list literal - 2D" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn do_the_test() !void {
            try consume_vec(.{ .{ 9, 8 }, .{ 7, 6 } });
        }

        fn consume_vec(vec: [2][2]f32) !void {
            try expect(vec[0][0] == 9);
            try expect(vec[0][1] == 8);
            try expect(vec[1][0] == 7);
            try expect(vec[1][1] == 6);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "ability to give comptime types and non comptime types to same parameter" {
    const S = struct {
        fn do_the_test() !void {
            var x: i32 = 1;
            _ = &x;
            try expect(foo(x) == 10);
            try expect(foo(i32) == 20);
        }

        fn foo(arg: anytype) i32 {
            if (@typeInfo(@TypeOf(arg)) == .Type and arg == i32) return 20;
            return 9 + arg;
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "function with inferred error set but returning no error" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn foo() !void {}
    };

    const return_ty = @typeInfo(@TypeOf(S.foo)).Fn.return_type.?;
    try expect_equal(0, @typeInfo(@typeInfo(return_ty).ErrorUnion.error_set).ErrorSet.?.len);
}

test "import passed byref to function in return type" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn get() @import("std").ArrayListUnmanaged(i32) {
            const x: @import("std").ArrayListUnmanaged(i32) = .{};
            return x;
        }
    };
    const list = S.get();
    try expect(list.items.len == 0);
}

test "implicit cast function to function ptr" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S1 = struct {
        export fn some_function_that_returns_avalue() c_int {
            return 123;
        }
    };
    var fnPtr1: *const fn () callconv(.C) c_int = S1.some_function_that_returns_avalue;
    _ = &fnPtr1;
    try expect(fnPtr1() == 123);
    const S2 = struct {
        extern fn some_function_that_returns_avalue() c_int;
    };
    var fnPtr2: *const fn () callconv(.C) c_int = S2.some_function_that_returns_avalue;
    _ = &fnPtr2;
    try expect(fnPtr2() == 123);
}

test "method call with optional and error union first param" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        x: i32 = 1234,

        fn opt(s: ?@This()) !void {
            try expect(s.?.x == 1234);
        }
        fn err_union(s: anyerror!@This()) !void {
            try expect((try s).x == 1234);
        }
    };
    var s: S = .{};
    try s.opt();
    try s.err_union();
}

test "method call with optional pointer first param" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        x: i32 = 1234,

        fn method(s: ?*@This()) !void {
            try expect(s.?.x == 1234);
        }
    };
    var s: S = .{};
    try s.method();
    const s_ptr = &s;
    try s_ptr.method();
}

test "using @ptr_cast on function pointers" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const A = struct { data: [4]u8 };

        fn at(arr: *const A, index: usize) *const u8 {
            return &arr.data[index];
        }

        fn run() !void {
            const a = A{ .data = "abcd".* };
            const casted_fn = @as(*const fn (*const anyopaque, usize) *const u8, @ptr_cast(&at));
            const casted_impl = @as(*const anyopaque, @ptr_cast(&a));
            const ptr = casted_fn(casted_impl, 2);
            try expect(ptr.* == 'c');
        }
    };

    try S.run();
    // https://github.com/ziglang/zig/issues/2626
    // try comptime S.run();
}

test "function returns function returning type" {
    const S = struct {
        fn a() fn () type {
            return (struct {
                fn b() type {
                    return u32;
                }
            }).b;
        }
    };
    try expect(S.a()() == u32);
}

test "peer type resolution of inferred error set with non-void payload" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn open_data_file(mode: enum { read, write }) !u32 {
            return switch (mode) {
                .read => foo(),
                .write => bar(),
            };
        }
        fn foo() error{ a, b }!u32 {
            return 1;
        }
        fn bar() error{ c, d }!u32 {
            return 2;
        }
    };
    try expect(try S.open_data_file(.read) == 1);
}

test "lazy values passed to anytype parameter" {
    const A = struct {
        a: u32,
        fn foo(comptime a: anytype) !void {
            try expect(a[0][0] == @size_of(@This()));
        }
    };
    try A.foo(.{[_]usize{@size_of(A)}});

    const B = struct {
        fn foo(comptime a: anytype) !void {
            try expect(a.x == 0);
        }
    };
    try B.foo(.{ .x = @size_of(B) });

    const C = struct {};
    try expect(@as(u32, @truncate(@size_of(C))) == 0);

    const D = struct {};
    try expect(@size_of(D) << 1 == 0);
}

test "pass and return comptime-only types" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn return_null(comptime x: @Type(.Null)) @Type(.Null) {
            return x;
        }
        fn return_undefined(comptime x: @Type(.Undefined)) @Type(.Undefined) {
            return x;
        }
    };

    try expect_equal(null, S.return_null(null));
    try expect_equal(@as(u0, 0), S.return_undefined(undefined));
}

test "pointer to alias behaves same as pointer to function" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = struct {
        fn foo() u32 {
            return 11227;
        }
        const bar = foo;
    };
    var a = &S.bar;
    _ = &a;
    try std.testing.expect(S.foo() == a());
}

test "comptime parameters don't have to be marked comptime if only called at comptime" {
    const S = struct {
        fn foo(x: comptime_int, y: comptime_int) u32 {
            return x + y;
        }
    };
    comptime std.debug.assert(S.foo(5, 6) == 11);
}

test "inline function with comptime-known comptime-only return type called at runtime" {
    const S = struct {
        inline fn foo(x: *i32, y: *const i32) type {
            x.* = y.*;
            return f32;
        }
    };
    var a: i32 = 0;
    const b: i32 = 111;
    const T = S.foo(&a, &b);
    try expect_equal(111, a);
    try expect_equal(f32, T);
}
