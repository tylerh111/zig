const builtin = @import("builtin");
const expect = @import("std").testing.expect;

fn foo(id: u64) !i32 {
    return switch (id) {
        1 => get_err_int(),
        2 => {
            const size = try get_err_int();
            _ = size;
            return try get_err_int();
        },
        else => error.ItBroke,
    };
}

fn get_err_int() anyerror!i32 {
    return 0;
}

test "ir block deps" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect((foo(1) catch unreachable) == 0);
    try expect((foo(2) catch unreachable) == 0);
}
