const builtin = @import("builtin");
const std = @import("std");
const expect = std.testing.expect;
const expect_equal_strings = std.testing.expect_equal_strings;
const expect_string_starts_with = std.testing.expect_string_starts_with;

// Most tests here can be comptime but use runtime so that a stacktrace
// can show failure location.
//
// Note certain results of `@type_name()` expect `behavior.zig` to be the
// root file. Running a test against this file as root will result in
// failures.

test "anon fn param" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/9339
    try expect_equal_strings_ignore_digits(
        "behavior.typename.TypeFromFn(behavior.typename.test.anon fn param__struct_0)",
        @type_name(TypeFromFn(struct {})),
    );
    try expect_equal_strings_ignore_digits(
        "behavior.typename.TypeFromFn(behavior.typename.test.anon fn param__union_0)",
        @type_name(TypeFromFn(union { unused: u8 })),
    );
    try expect_equal_strings_ignore_digits(
        "behavior.typename.TypeFromFn(behavior.typename.test.anon fn param__enum_0)",
        @type_name(TypeFromFn(enum { unused })),
    );

    try expect_equal_strings_ignore_digits(
        "behavior.typename.TypeFromFnB(behavior.typename.test.anon fn param__struct_0,behavior.typename.test.anon fn param__union_0,behavior.typename.test.anon fn param__enum_0)",
        @type_name(TypeFromFnB(struct {}, union { unused: u8 }, enum { unused })),
    );
}

test "anon field init" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Foo = .{
        .T1 = struct {},
        .T2 = union { unused: u8 },
        .T3 = enum { unused },
    };

    try expect_equal_strings_ignore_digits(
        "behavior.typename.test.anon field init__struct_0",
        @type_name(Foo.T1),
    );
    try expect_equal_strings_ignore_digits(
        "behavior.typename.test.anon field init__union_0",
        @type_name(Foo.T2),
    );
    try expect_equal_strings_ignore_digits(
        "behavior.typename.test.anon field init__enum_0",
        @type_name(Foo.T3),
    );
}

test "basic" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect_equal_strings("i64", @type_name(i64));
    try expect_equal_strings("*usize", @type_name(*usize));
    try expect_equal_strings("[]u8", @type_name([]u8));

    try expect_equal_strings("fn () void", @type_name(fn () void));
    try expect_equal_strings("fn (u32) void", @type_name(fn (u32) void));
    try expect_equal_strings("fn (u32) void", @type_name(fn (a: u32) void));

    try expect_equal_strings("fn (comptime u32) void", @type_name(fn (comptime u32) void));
    try expect_equal_strings("fn (noalias []u8) void", @type_name(fn (noalias []u8) void));

    try expect_equal_strings("fn () callconv(.C) void", @type_name(fn () callconv(.C) void));
    try expect_equal_strings("fn (...) callconv(.C) void", @type_name(fn (...) callconv(.C) void));
    try expect_equal_strings("fn (u32, ...) callconv(.C) void", @type_name(fn (u32, ...) callconv(.C) void));
}

test "top level decl" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect_equal_strings(
        "behavior.typename.A_Struct",
        @type_name(A_Struct),
    );
    try expect_equal_strings(
        "behavior.typename.A_Union",
        @type_name(A_Union),
    );
    try expect_equal_strings(
        "behavior.typename.A_Enum",
        @type_name(A_Enum),
    );

    // regular fn, without error
    try expect_equal_strings(
        "fn () void",
        @type_name(@TypeOf(regular)),
    );
    // regular fn inside struct, with error
    try expect_equal_strings(
        "fn () @typeInfo(@typeInfo(@TypeOf(behavior.typename.B.do_test)).Fn.return_type.?).ErrorUnion.error_set!void",
        @type_name(@TypeOf(B.do_test)),
    );
    // generic fn
    try expect_equal_strings(
        "fn (comptime type) type",
        @type_name(@TypeOf(TypeFromFn)),
    );
}

const A_Struct = struct {};
const A_Union = union {
    unused: u8,
};
const A_Enum = enum {
    unused,
};

fn regular() void {}

const B = struct {
    fn do_test() !void {}
};

test "fn param" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // https://github.com/ziglang/zig/issues/675
    try expect_equal_strings(
        "behavior.typename.TypeFromFn(u8)",
        @type_name(TypeFromFn(u8)),
    );
    try expect_equal_strings(
        "behavior.typename.TypeFromFn(behavior.typename.A_Struct)",
        @type_name(TypeFromFn(A_Struct)),
    );
    try expect_equal_strings(
        "behavior.typename.TypeFromFn(behavior.typename.A_Union)",
        @type_name(TypeFromFn(A_Union)),
    );
    try expect_equal_strings(
        "behavior.typename.TypeFromFn(behavior.typename.A_Enum)",
        @type_name(TypeFromFn(A_Enum)),
    );

    try expect_equal_strings(
        "behavior.typename.TypeFromFn2(u8,bool)",
        @type_name(TypeFromFn2(u8, bool)),
    );
}

fn TypeFromFn(comptime T: type) type {
    return struct {
        comptime {
            _ = T;
        }
    };
}

fn TypeFromFn2(comptime T1: type, comptime T2: type) type {
    return struct {
        comptime {
            _ = T1;
            _ = T2;
        }
    };
}

fn TypeFromFnB(comptime T1: type, comptime T2: type, comptime T3: type) type {
    return struct {
        comptime {
            _ = T1;
            _ = T2;
            _ = T3;
        }
    };
}

/// Replaces integers in `actual` with '0' before doing the test.
pub fn expect_equal_strings_ignore_digits(expected: []const u8, actual: []const u8) !void {
    var actual_buf: [1024]u8 = undefined;
    var actual_i: usize = 0;
    var last_digit = false;
    for (actual) |byte| {
        switch (byte) {
            '0'...'9' => {
                if (last_digit) continue;
                last_digit = true;
                actual_buf[actual_i] = '0';
                actual_i += 1;
            },
            else => {
                last_digit = false;
                actual_buf[actual_i] = byte;
                actual_i += 1;
            },
        }
    }
    return expect_equal_strings(expected, actual_buf[0..actual_i]);
}

test "local variable" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Foo = struct { a: u32 };
    const Bar = union { a: u32 };
    const Baz = enum { a, b };
    const Qux = enum { a, b };
    const Quux = enum { a, b };

    try expect_equal_strings("behavior.typename.test.local variable.Foo", @type_name(Foo));
    try expect_equal_strings("behavior.typename.test.local variable.Bar", @type_name(Bar));
    try expect_equal_strings("behavior.typename.test.local variable.Baz", @type_name(Baz));
    try expect_equal_strings("behavior.typename.test.local variable.Qux", @type_name(Qux));
    try expect_equal_strings("behavior.typename.test.local variable.Quux", @type_name(Quux));
}

test "comptime parameters not converted to anytype in function type" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const T = fn (fn (type) void, void) void;
    try expect_equal_strings("fn (comptime fn (comptime type) void, void) void", @type_name(T));
}

test "anon name strategy used in sub expression" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn get_the_name() []const u8 {
            return struct {
                const name = @type_name(@This());
            }.name;
        }
    };
    try expect_equal_strings_ignore_digits(
        "behavior.typename.test.anon name strategy used in sub expression.S.getTheName__struct_0",
        S.get_the_name(),
    );
}
