const std = @import("std");
const builtin = @import("builtin");
const expect_equal = std.testing.expect_equal;

test "casting integer address to function pointer" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    address_to_function();
    comptime address_to_function();
}

fn address_to_function() void {
    var addr: usize = 0xdeadbee0;
    _ = &addr;
    _ = @as(*const fn () void, @ptrFromInt(addr));
}

test "mutate through ptr initialized with constant ptrFromInt value" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    force_compiler_analyze_branch_hard_coded_ptr_dereference(false);
}

fn force_compiler_analyze_branch_hard_coded_ptr_dereference(x: bool) void {
    const hardCodedP = @as(*volatile u8, @ptrFromInt(0xdeadbeef));
    if (x) {
        hardCodedP.* = hardCodedP.* | 10;
    } else {
        return;
    }
}

test "@ptrFromInt creates null pointer" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const ptr = @as(?*u32, @ptrFromInt(0));
    try expect_equal(@as(?*u32, null), ptr);
}

test "@ptrFromInt creates allowzero zero pointer" {
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const ptr = @as(*allowzero u32, @ptrFromInt(0));
    try expect_equal(@as(usize, 0), @int_from_ptr(ptr));
}
