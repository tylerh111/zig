const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

var x: u8 = 1;

// This excludes builtin functions that return void or noreturn that cannot be tested.
test {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var val: u8 = undefined;
    try testing.expect_equal({}, @atomicStore(u8, &val, 0, .unordered));
    try testing.expect_equal(void, @TypeOf(@breakpoint()));
    try testing.expect_equal({}, @export(x, .{ .name = "x" }));
    try testing.expect_equal({}, @fence(.acquire));
    try testing.expect_equal({}, @memcpy(@as([*]u8, @ptrFromInt(1))[0..0], @as([*]u8, @ptrFromInt(1))[0..0]));
    try testing.expect_equal({}, @memset(@as([*]u8, @ptrFromInt(1))[0..0], undefined));
    try testing.expect_equal(noreturn, @TypeOf(if (true) @panic("") else {}));
    try testing.expect_equal({}, @prefetch(&val, .{}));
    try testing.expect_equal({}, @setAlignStack(16));
    try testing.expect_equal({}, @setCold(true));
    try testing.expect_equal({}, @setEvalBranchQuota(0));
    try testing.expect_equal({}, @setFloatMode(.optimized));
    try testing.expect_equal({}, @setRuntimeSafety(true));
}
