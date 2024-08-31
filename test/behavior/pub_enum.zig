const builtin = @import("builtin");
const other = @import("pub_enum/other.zig");
const expect = @import("std").testing.expect;

test "pub enum" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try pub_enum_test(other.APubEnum.Two);
}
fn pub_enum_test(foo: other.APubEnum) !void {
    try expect(foo == other.APubEnum.Two);
}

test "cast with imported symbol" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try expect(@as(other.size_t, 42) == 42);
}
