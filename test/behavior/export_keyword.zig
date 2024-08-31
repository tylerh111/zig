const std = @import("std");
const expect = std.testing.expect;
const expect_equal_slices = std.testing.expect_equal_slices;
const expect_equal_strings = std.testing.expect_equal_strings;
const mem = std.mem;
const builtin = @import("builtin");

// can't really run this test but we can make sure it has no compile error
// and generates code
const vram = @as([*]volatile u8, @ptrFromInt(0x20000000))[0..0x8000];
export fn write_to_vram() void {
    if (builtin.zig_backend == .stage2_riscv64) return;

    vram[0] = 'X';
}

const PackedStruct = packed struct {
    a: u8,
    b: u8,
};
const PackedUnion = packed union {
    a: u8,
    b: u32,
};

test "packed struct, enum, union parameters in extern function" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    test_packed_stuff(&(PackedStruct{
        .a = 1,
        .b = 2,
    }), &(PackedUnion{ .a = 1 }));
}

export fn test_packed_stuff(a: *const PackedStruct, b: *const PackedUnion) void {
    if (false) {
        a;
        b;
    }
}
