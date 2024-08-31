const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;

test "bool literals" {
    try expect(true);
    try expect(!false);
}

test "cast bool to int" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const t = true;
    const f = false;
    try expect_equal(@as(u32, 1), @int_from_bool(t));
    try expect_equal(@as(u32, 0), @int_from_bool(f));
    try expect_equal(-1, @as(i1, @bit_cast(@int_from_bool(t))));
    try expect_equal(0, @as(i1, @bit_cast(@int_from_bool(f))));
    try expect_equal(u1, @TypeOf(@int_from_bool(t)));
    try expect_equal(u1, @TypeOf(@int_from_bool(f)));
    try non_const_cast_int_from_bool(t, f);
}

fn non_const_cast_int_from_bool(t: bool, f: bool) !void {
    try expect_equal(@as(u32, 1), @int_from_bool(t));
    try expect_equal(@as(u32, 0), @int_from_bool(f));
    try expect_equal(@as(i1, -1), @as(i1, @bit_cast(@int_from_bool(t))));
    try expect_equal(@as(i1, 0), @as(i1, @bit_cast(@int_from_bool(f))));
    try expect_equal(u1, @TypeOf(@int_from_bool(t)));
    try expect_equal(u1, @TypeOf(@int_from_bool(f)));
}

test "bool cmp" {
    try expect(test_bool_cmp(true, false) == false);
}
fn test_bool_cmp(a: bool, b: bool) bool {
    return a == b;
}

const global_f = false;
const global_t = true;
const not_global_f = !global_f;
const not_global_t = !global_t;
test "compile time bool not" {
    try expect(not_global_f);
    try expect(!not_global_t);
}

test "short circuit" {
    try test_short_circuit(false, true);
    try comptime test_short_circuit(false, true);
}

fn test_short_circuit(f: bool, t: bool) !void {
    var hit_1 = f;
    var hit_2 = f;
    var hit_3 = f;
    var hit_4 = f;

    if (t or x: {
        try expect(f);
        break :x f;
    }) {
        hit_1 = t;
    }
    if (f or x: {
        hit_2 = t;
        break :x f;
    }) {
        try expect(f);
    }

    if (t and x: {
        hit_3 = t;
        break :x f;
    }) {
        try expect(f);
    }
    if (f and x: {
        try expect(f);
        break :x f;
    }) {
        try expect(f);
    } else {
        hit_4 = t;
    }
    try expect(hit_1);
    try expect(hit_2);
    try expect(hit_3);
    try expect(hit_4);
}

test "or with noreturn operand" {
    const S = struct {
        fn foo(a: u32, b: u32) bool {
            return a == 5 or b == 2 or @panic("oh no");
        }
    };
    _ = S.foo(2, 2);
}
