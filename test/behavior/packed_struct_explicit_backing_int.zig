const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect_equal = std.testing.expect_equal;
const native_endian = builtin.cpu.arch.endian();

test "packed struct explicit backing integer" {
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S1 = packed struct { a: u8, b: u8, c: u8 };

    const S2 = packed struct(i24) { d: u8, e: u8, f: u8 };

    const S3 = packed struct { x: S1, y: S2 };
    const S3Padded = packed struct(u64) { s3: S3, pad: u16 };

    try expect_equal(48, @bitSizeOf(S3));
    try expect_equal(@size_of(u48), @size_of(S3));

    try expect_equal(3, @offset_of(S3, "y"));
    try expect_equal(24, @bit_offset_of(S3, "y"));

    if (native_endian == .little) {
        const s3 = @as(S3Padded, @bit_cast(@as(u64, 0xe952d5c71ff4))).s3;
        try expect_equal(@as(u8, 0xf4), s3.x.a);
        try expect_equal(@as(u8, 0x1f), s3.x.b);
        try expect_equal(@as(u8, 0xc7), s3.x.c);
        try expect_equal(@as(u8, 0xd5), s3.y.d);
        try expect_equal(@as(u8, 0x52), s3.y.e);
        try expect_equal(@as(u8, 0xe9), s3.y.f);
    }

    const S4 = packed struct { a: i32, b: i8 };
    const S5 = packed struct(u80) { a: i32, b: i8, c: S4 };
    const S6 = packed struct(i80) { a: i32, b: S4, c: i8 };

    const expectedBitSize = 80;
    const expectedByteSize = @size_of(u80);
    try expect_equal(expectedBitSize, @bitSizeOf(S5));
    try expect_equal(expectedByteSize, @size_of(S5));
    try expect_equal(expectedBitSize, @bitSizeOf(S6));
    try expect_equal(expectedByteSize, @size_of(S6));

    try expect_equal(5, @offset_of(S5, "c"));
    try expect_equal(40, @bit_offset_of(S5, "c"));
    try expect_equal(9, @offset_of(S6, "c"));
    try expect_equal(72, @bit_offset_of(S6, "c"));
}
