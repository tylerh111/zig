const std = @import("std");
const min_int = std.math.min_int;
const max_int = std.math.max_int;
const builtin = @import("builtin");

test "int comparison elision" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    test_int_edges(u0);
    test_int_edges(i0);
    test_int_edges(u1);
    test_int_edges(i1);
    test_int_edges(u4);
    test_int_edges(i4);

    // TODO: support int types > 128 bits wide in other backends
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    // TODO: panic: integer overflow with int types > 65528 bits wide
    // TODO: LLVM generates too many parameters for wasmtime when splitting up int > 64000 bits wide
    test_int_edges(u64000);
    test_int_edges(i64000);
}

// All comparisons in this test have a guaranteed result,
// so one branch of each 'if' should never be analyzed.
fn test_int_edges(comptime T: type) void {
    const min = min_int(T);
    const max = max_int(T);

    var runtime_val: T = undefined;
    _ = &runtime_val;

    if (min > runtime_val) @compile_error("analyzed impossible branch");
    if (min <= runtime_val) {} else @compile_error("analyzed impossible branch");
    if (runtime_val < min) @compile_error("analyzed impossible branch");
    if (runtime_val >= min) {} else @compile_error("analyzed impossible branch");

    if (min - 1 > runtime_val) @compile_error("analyzed impossible branch");
    if (min - 1 >= runtime_val) @compile_error("analyzed impossible branch");
    if (min - 1 < runtime_val) {} else @compile_error("analyzed impossible branch");
    if (min - 1 <= runtime_val) {} else @compile_error("analyzed impossible branch");
    if (min - 1 == runtime_val) @compile_error("analyzed impossible branch");
    if (min - 1 != runtime_val) {} else @compile_error("analyzed impossible branch");
    if (runtime_val < min - 1) @compile_error("analyzed impossible branch");
    if (runtime_val <= min - 1) @compile_error("analyzed impossible branch");
    if (runtime_val > min - 1) {} else @compile_error("analyzed impossible branch");
    if (runtime_val >= min - 1) {} else @compile_error("analyzed impossible branch");
    if (runtime_val == min - 1) @compile_error("analyzed impossible branch");
    if (runtime_val != min - 1) {} else @compile_error("analyzed impossible branch");

    if (max >= runtime_val) {} else @compile_error("analyzed impossible branch");
    if (max < runtime_val) @compile_error("analyzed impossible branch");
    if (runtime_val <= max) {} else @compile_error("analyzed impossible branch");
    if (runtime_val > max) @compile_error("analyzed impossible branch");

    if (max + 1 > runtime_val) {} else @compile_error("analyzed impossible branch");
    if (max + 1 >= runtime_val) {} else @compile_error("analyzed impossible branch");
    if (max + 1 < runtime_val) @compile_error("analyzed impossible branch");
    if (max + 1 <= runtime_val) @compile_error("analyzed impossible branch");
    if (max + 1 == runtime_val) @compile_error("analyzed impossible branch");
    if (max + 1 != runtime_val) {} else @compile_error("analyzed impossible branch");
    if (runtime_val < max + 1) {} else @compile_error("analyzed impossible branch");
    if (runtime_val <= max + 1) {} else @compile_error("analyzed impossible branch");
    if (runtime_val > max + 1) @compile_error("analyzed impossible branch");
    if (runtime_val >= max + 1) @compile_error("analyzed impossible branch");
    if (runtime_val == max + 1) @compile_error("analyzed impossible branch");
    if (runtime_val != max + 1) {} else @compile_error("analyzed impossible branch");

    const undef_const: T = undefined;

    if (min > undef_const) @compile_error("analyzed impossible branch");
    if (min <= undef_const) {} else @compile_error("analyzed impossible branch");
    if (undef_const < min) @compile_error("analyzed impossible branch");
    if (undef_const >= min) {} else @compile_error("analyzed impossible branch");

    if (min - 1 > undef_const) @compile_error("analyzed impossible branch");
    if (min - 1 >= undef_const) @compile_error("analyzed impossible branch");
    if (min - 1 < undef_const) {} else @compile_error("analyzed impossible branch");
    if (min - 1 <= undef_const) {} else @compile_error("analyzed impossible branch");
    if (min - 1 == undef_const) @compile_error("analyzed impossible branch");
    if (min - 1 != undef_const) {} else @compile_error("analyzed impossible branch");
    if (undef_const < min - 1) @compile_error("analyzed impossible branch");
    if (undef_const <= min - 1) @compile_error("analyzed impossible branch");
    if (undef_const > min - 1) {} else @compile_error("analyzed impossible branch");
    if (undef_const >= min - 1) {} else @compile_error("analyzed impossible branch");
    if (undef_const == min - 1) @compile_error("analyzed impossible branch");
    if (undef_const != min - 1) {} else @compile_error("analyzed impossible branch");

    if (max >= undef_const) {} else @compile_error("analyzed impossible branch");
    if (max < undef_const) @compile_error("analyzed impossible branch");
    if (undef_const <= max) {} else @compile_error("analyzed impossible branch");
    if (undef_const > max) @compile_error("analyzed impossible branch");

    if (max + 1 > undef_const) {} else @compile_error("analyzed impossible branch");
    if (max + 1 >= undef_const) {} else @compile_error("analyzed impossible branch");
    if (max + 1 < undef_const) @compile_error("analyzed impossible branch");
    if (max + 1 <= undef_const) @compile_error("analyzed impossible branch");
    if (max + 1 == undef_const) @compile_error("analyzed impossible branch");
    if (max + 1 != undef_const) {} else @compile_error("analyzed impossible branch");
    if (undef_const < max + 1) {} else @compile_error("analyzed impossible branch");
    if (undef_const <= max + 1) {} else @compile_error("analyzed impossible branch");
    if (undef_const > max + 1) @compile_error("analyzed impossible branch");
    if (undef_const >= max + 1) @compile_error("analyzed impossible branch");
    if (undef_const == max + 1) @compile_error("analyzed impossible branch");
    if (undef_const != max + 1) {} else @compile_error("analyzed impossible branch");
}

test "comparison elided on large integer value" {
    try std.testing.expect(-1 == @as(i8, -3) >> 2);
    try std.testing.expect(-1 == -3 >> 2000);
}
