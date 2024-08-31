const std = @import("std");
const builtin = @import("builtin");
const expect = std.testing.expect;

test "memcpy and memset intrinsics" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_memcpy_memset();
    try comptime test_memcpy_memset();
}

fn test_memcpy_memset() !void {
    var foo: [20]u8 = undefined;
    var bar: [20]u8 = undefined;

    @memset(&foo, 'A');
    @memcpy(&bar, &foo);

    try expect(bar[0] == 'A');
    try expect(bar[11] == 'A');
    try expect(bar[19] == 'A');
}

test "@memcpy with both operands single-ptr-to-array, one is null-terminated" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_memcpy_both_single_ptr_array_one_is_null_terminated();
    try comptime test_memcpy_both_single_ptr_array_one_is_null_terminated();
}

fn test_memcpy_both_single_ptr_array_one_is_null_terminated() !void {
    var buf: [100]u8 = undefined;
    const suffix = "hello";
    @memcpy(buf[buf.len - suffix.len ..], suffix);
    try expect(buf[95] == 'h');
    try expect(buf[96] == 'e');
    try expect(buf[97] == 'l');
    try expect(buf[98] == 'l');
    try expect(buf[99] == 'o');
}

test "@memcpy dest many pointer" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_memcpy_dest_many_ptr();
    try comptime test_memcpy_dest_many_ptr();
}

fn test_memcpy_dest_many_ptr() !void {
    var str = "hello".*;
    var buf: [5]u8 = undefined;
    var len: usize = 5;
    _ = &len;
    @memcpy(@as([*]u8, @ptr_cast(&buf)), @as([*]const u8, @ptr_cast(&str))[0..len]);
    try expect(buf[0] == 'h');
    try expect(buf[1] == 'e');
    try expect(buf[2] == 'l');
    try expect(buf[3] == 'l');
    try expect(buf[4] == 'o');
}

test "@memcpy slice" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_memcpy_slice();
    try comptime test_memcpy_slice();
}

fn test_memcpy_slice() !void {
    var buf: [5]u8 = undefined;
    const dst: []u8 = &buf;
    const src: []const u8 = "hello";
    @memcpy(dst, src);
    try expect(buf[0] == 'h');
    try expect(buf[1] == 'e');
    try expect(buf[2] == 'l');
    try expect(buf[3] == 'l');
    try expect(buf[4] == 'o');
}

comptime {
    const S = struct {
        buffer: [8]u8 = undefined,
        fn set(self: *@This(), items: []const u8) void {
            @memcpy(self.buffer[0..items.len], items);
        }
    };

    var s = S{};
    s.set("hello");
    if (!std.mem.eql(u8, s.buffer[0..5], "hello")) @compile_error("bad");
}
