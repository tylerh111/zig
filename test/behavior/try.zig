const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;

test "try on error union" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try try_on_error_union_impl();
    try comptime try_on_error_union_impl();
}

fn try_on_error_union_impl() !void {
    const x = if (returns_ten()) |val| val + 1 else |err| switch (err) {
        error.ItBroke, error.NoMem => 1,
        error.CrappedOut => @as(i32, 2),
        else => unreachable,
    };
    try expect(x == 11);
}

fn returns_ten() anyerror!i32 {
    return 10;
}

test "try without vars" {
    const result1 = if (fail_if_true(true)) 1 else |_| @as(i32, 2);
    try expect(result1 == 2);

    const result2 = if (fail_if_true(false)) 1 else |_| @as(i32, 2);
    try expect(result2 == 1);
}

fn fail_if_true(ok: bool) anyerror!void {
    if (ok) {
        return error.ItBroke;
    } else {
        return;
    }
}

test "try then not executed with assignment" {
    if (fail_if_true(true)) {
        unreachable;
    } else |err| {
        try expect(err == error.ItBroke);
    }
}

test "`try`ing an if/else expression" {
    if (builtin.zig_backend == .stage2_x86) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        fn get_error() !void {
            return error.Test;
        }

        fn get_error2() !void {
            var a: u8 = 'c';
            _ = &a;
            try if (a == 'a') get_error() else if (a == 'b') get_error() else get_error();
        }
    };

    try std.testing.expect_error(error.Test, S.get_error2());
}
