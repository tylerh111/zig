const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const native_endian = builtin.cpu.arch.endian();

test "flags in packed structs" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    const Flags1 = packed struct {
        // first 8 bits
        b0_0: u1,
        b0_1: u1,
        b0_2: u1,
        b0_3: u1,
        b0_4: u1,
        b0_5: u1,
        b0_6: u1,
        b0_7: u1,

        // 7 more bits
        b1_0: u1,
        b1_1: u1,
        b1_2: u1,
        b1_3: u1,
        b1_4: u1,
        b1_5: u1,
        b1_6: u1,

        // some padding to fill to 24 bits
        _: u9,
    };

    try expect_equal(@size_of(u24), @size_of(Flags1));
    try expect_equal(24, @bitSizeOf(Flags1));

    const Flags2 = packed struct {
        // byte 0
        b0_0: u1,
        b0_1: u1,
        b0_2: u1,
        b0_3: u1,
        b0_4: u1,
        b0_5: u1,
        b0_6: u1,
        b0_7: u1,

        // partial byte 1 (but not 8 bits)
        b1_0: u1,
        b1_1: u1,
        b1_2: u1,
        b1_3: u1,
        b1_4: u1,
        b1_5: u1,
        b1_6: u1,

        // some padding that should yield @size_of(Flags2) == 4
        _: u10,
    };

    try expect_equal(@size_of(u25), @size_of(Flags2));
    try expect_equal(25, @bitSizeOf(Flags2));

    const Flags3 = packed struct {
        // byte 0
        b0_0: u1,
        b0_1: u1,
        b0_2: u1,
        b0_3: u1,
        b0_4: u1,
        b0_5: u1,
        b0_6: u1,
        b0_7: u1,

        // byte 1
        b1_0: u1,
        b1_1: u1,
        b1_2: u1,
        b1_3: u1,
        b1_4: u1,
        b1_5: u1,
        b1_6: u1,
        b1_7: u1,

        // some padding that should yield @size_of(Flags2) == 4
        _: u16, // it works, if the padding is 8-based
    };

    try expect_equal(@size_of(u32), @size_of(Flags3));
    try expect_equal(32, @bitSizeOf(Flags3));
}

test "consistent size of packed structs" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    const TxData1 = packed struct { data: u8, _23: u23, full: bool = false };
    const TxData2 = packed struct { data: u9, _22: u22, full: bool = false };

    const register_size_bits = 32;
    const register_size_bytes = @size_of(u32);

    try expect_equal(register_size_bits, @bitSizeOf(TxData1));
    try expect_equal(register_size_bytes, @size_of(TxData1));

    try expect_equal(register_size_bits, @bitSizeOf(TxData2));
    try expect_equal(register_size_bytes, @size_of(TxData2));

    const TxData4 = packed struct { a: u32, b: u24 };
    const TxData6 = packed struct { a: u24, b: u32 };

    const expectedBitSize = 56;
    const expectedByteSize = @size_of(u56);

    try expect_equal(expectedBitSize, @bitSizeOf(TxData4));
    try expect_equal(expectedByteSize, @size_of(TxData4));

    try expect_equal(expectedBitSize, @bitSizeOf(TxData6));
    try expect_equal(expectedByteSize, @size_of(TxData6));
}

test "correct size_of and offsets in packed structs" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const PStruct = packed struct {
        bool_a: bool,
        bool_b: bool,
        bool_c: bool,
        bool_d: bool,
        bool_e: bool,
        bool_f: bool,
        u1_a: u1,
        bool_g: bool,
        u1_b: u1,
        u3_a: u3,
        u10_a: u10,
        u10_b: u10,
    };
    try expect_equal(0, @offset_of(PStruct, "bool_a"));
    try expect_equal(0, @bit_offset_of(PStruct, "bool_a"));
    try expect_equal(0, @offset_of(PStruct, "bool_b"));
    try expect_equal(1, @bit_offset_of(PStruct, "bool_b"));
    try expect_equal(0, @offset_of(PStruct, "bool_c"));
    try expect_equal(2, @bit_offset_of(PStruct, "bool_c"));
    try expect_equal(0, @offset_of(PStruct, "bool_d"));
    try expect_equal(3, @bit_offset_of(PStruct, "bool_d"));
    try expect_equal(0, @offset_of(PStruct, "bool_e"));
    try expect_equal(4, @bit_offset_of(PStruct, "bool_e"));
    try expect_equal(0, @offset_of(PStruct, "bool_f"));
    try expect_equal(5, @bit_offset_of(PStruct, "bool_f"));
    try expect_equal(0, @offset_of(PStruct, "u1_a"));
    try expect_equal(6, @bit_offset_of(PStruct, "u1_a"));
    try expect_equal(0, @offset_of(PStruct, "bool_g"));
    try expect_equal(7, @bit_offset_of(PStruct, "bool_g"));
    try expect_equal(1, @offset_of(PStruct, "u1_b"));
    try expect_equal(8, @bit_offset_of(PStruct, "u1_b"));
    try expect_equal(1, @offset_of(PStruct, "u3_a"));
    try expect_equal(9, @bit_offset_of(PStruct, "u3_a"));
    try expect_equal(1, @offset_of(PStruct, "u10_a"));
    try expect_equal(12, @bit_offset_of(PStruct, "u10_a"));
    try expect_equal(2, @offset_of(PStruct, "u10_b"));
    try expect_equal(22, @bit_offset_of(PStruct, "u10_b"));
    try expect_equal(4, @size_of(PStruct));

    if (native_endian == .little) {
        const s1 = @as(PStruct, @bit_cast(@as(u32, 0x12345678)));
        try expect_equal(false, s1.bool_a);
        try expect_equal(false, s1.bool_b);
        try expect_equal(false, s1.bool_c);
        try expect_equal(true, s1.bool_d);
        try expect_equal(true, s1.bool_e);
        try expect_equal(true, s1.bool_f);
        try expect_equal(1, s1.u1_a);
        try expect_equal(false, s1.bool_g);
        try expect_equal(0, s1.u1_b);
        try expect_equal(3, s1.u3_a);
        try expect_equal(0b1101000101, s1.u10_a);
        try expect_equal(0b0001001000, s1.u10_b);

        const s2 = @as(packed struct { x: u1, y: u7, z: u24 }, @bit_cast(@as(u32, 0xd5c71ff4)));
        try expect_equal(0, s2.x);
        try expect_equal(0b1111010, s2.y);
        try expect_equal(0xd5c71f, s2.z);
    }
}

test "nested packed structs" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S1 = packed struct { a: u8, b: u8, c: u8 };

    const S2 = packed struct { d: u8, e: u8, f: u8 };

    const S3 = packed struct { x: S1, y: S2 };
    const S3Padded = packed struct { s3: S3, pad: u16 };

    try expect_equal(48, @bitSizeOf(S3));
    try expect_equal(@size_of(u48), @size_of(S3));

    try expect_equal(3, @offset_of(S3, "y"));
    try expect_equal(24, @bit_offset_of(S3, "y"));

    if (native_endian == .little) {
        const s3 = @as(S3Padded, @bit_cast(@as(u64, 0xe952d5c71ff4))).s3;
        try expect_equal(0xf4, s3.x.a);
        try expect_equal(0x1f, s3.x.b);
        try expect_equal(0xc7, s3.x.c);
        try expect_equal(0xd5, s3.y.d);
        try expect_equal(0x52, s3.y.e);
        try expect_equal(0xe9, s3.y.f);
    }

    const S4 = packed struct { a: i32, b: i8 };
    const S5 = packed struct { a: i32, b: i8, c: S4 };
    const S6 = packed struct { a: i32, b: S4, c: i8 };

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

test "regular in irregular packed struct" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Irregular = packed struct {
        bar: Regular = Regular{},
        _: u24 = 0,
        pub const Regular = packed struct { a: u16 = 0, b: u8 = 0 };
    };

    var foo = Irregular{};
    foo.bar.a = 235;
    foo.bar.b = 42;

    try expect_equal(235, foo.bar.a);
    try expect_equal(42, foo.bar.b);
}

test "nested packed struct unaligned" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (native_endian != .little) return error.SkipZigTest; // Byte aligned packed struct field pointers have not been implemented yet

    const S1 = packed struct {
        a: u4,
        b: u4,
        c: u8,
    };
    const S2 = packed struct {
        base: u8,
        p0: S1,
        bit0: u1,
        p1: packed struct {
            a: u8,
        },
        p2: packed struct {
            a: u7,
            b: u8,
        },
        p3: S1,

        var s: @This() = .{
            .base = 1,
            .p0 = .{ .a = 2, .b = 3, .c = 4 },
            .bit0 = 0,
            .p1 = .{ .a = 5 },
            .p2 = .{ .a = 6, .b = 7 },
            .p3 = .{ .a = 8, .b = 9, .c = 10 },
        };
    };

    try expect(S2.s.base == 1);
    try expect(S2.s.p0.a == 2);
    try expect(S2.s.p0.b == 3);
    try expect(S2.s.p0.c == 4);
    try expect(S2.s.bit0 == 0);
    try expect(S2.s.p1.a == 5);
    try expect(S2.s.p2.a == 6);
    try expect(S2.s.p2.b == 7);
    try expect(S2.s.p3.a == 8);
    try expect(S2.s.p3.b == 9);
    try expect(S2.s.p3.c == 10);

    const S3 = packed struct {
        pad: u8,
        v: u2,
        s: packed struct {
            v: u3,
            s: packed struct {
                v: u2,
                s: packed struct {
                    bit0: u1,
                    byte: u8,
                    bit1: u1,
                },
            },
        },
        var v0: @This() = .{ .pad = 0, .v = 1, .s = .{ .v = 2, .s = .{ .v = 3, .s = .{ .bit0 = 0, .byte = 4, .bit1 = 1 } } } };
    };

    try expect(S3.v0.v == 1);
    try expect(S3.v0.s.v == 2);
    try expect(S3.v0.s.s.v == 3);
    try expect(S3.v0.s.s.s.bit0 == 0);
    try expect(S3.v0.s.s.s.byte == 4);
    try expect(S3.v0.s.s.s.bit1 == 1);
}

test "byte-aligned field pointer offsets" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const A = packed struct {
            a: u8,
            b: u8,
            c: u8,
            d: u8,
        };

        const B = packed struct {
            a: u16,
            b: u16,
        };

        fn do_the_test() !void {
            var a: A = .{
                .a = 1,
                .b = 2,
                .c = 3,
                .d = 4,
            };
            switch (comptime builtin.cpu.arch.endian()) {
                .little => {
                    comptime assert(@TypeOf(&a.a) == *align(4) u8);
                    comptime assert(@TypeOf(&a.b) == *u8);
                    comptime assert(@TypeOf(&a.c) == *align(2) u8);
                    comptime assert(@TypeOf(&a.d) == *u8);
                },
                .big => {
                    // TODO re-evaluate packed struct endianness
                    comptime assert(@TypeOf(&a.a) == *align(4:0:4) u8);
                    comptime assert(@TypeOf(&a.b) == *align(4:8:4) u8);
                    comptime assert(@TypeOf(&a.c) == *align(4:16:4) u8);
                    comptime assert(@TypeOf(&a.d) == *align(4:24:4) u8);
                },
            }
            try expect(a.a == 1);
            try expect(a.b == 2);
            try expect(a.c == 3);
            try expect(a.d == 4);

            a.a += 1;
            try expect(a.a == 2);
            try expect(a.b == 2);
            try expect(a.c == 3);
            try expect(a.d == 4);

            a.b += 1;
            try expect(a.a == 2);
            try expect(a.b == 3);
            try expect(a.c == 3);
            try expect(a.d == 4);

            a.c += 1;
            try expect(a.a == 2);
            try expect(a.b == 3);
            try expect(a.c == 4);
            try expect(a.d == 4);

            a.d += 1;
            try expect(a.a == 2);
            try expect(a.b == 3);
            try expect(a.c == 4);
            try expect(a.d == 5);

            var b: B = .{
                .a = 1,
                .b = 2,
            };
            switch (comptime builtin.cpu.arch.endian()) {
                .little => {
                    comptime assert(@TypeOf(&b.a) == *align(4) u16);
                    comptime assert(@TypeOf(&b.b) == *u16);
                },
                .big => {
                    comptime assert(@TypeOf(&b.a) == *align(4:0:4) u16);
                    comptime assert(@TypeOf(&b.b) == *align(4:16:4) u16);
                },
            }
            try expect(b.a == 1);
            try expect(b.b == 2);

            b.a += 1;
            try expect(b.a == 2);
            try expect(b.b == 2);

            b.b += 1;
            try expect(b.a == 2);
            try expect(b.b == 3);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}

test "nested packed struct field pointers" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // ubsan unaligned pointer access
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (native_endian != .little) return error.SkipZigTest; // Byte aligned packed struct field pointers have not been implemented yet

    const S2 = packed struct {
        base: u8,
        p0: packed struct {
            a: u4,
            b: u4,
            c: u8,
        },
        bit: u1,
        p1: packed struct {
            a: u7,
            b: u8,
        },

        var s: @This() = .{ .base = 1, .p0 = .{ .a = 2, .b = 3, .c = 4 }, .bit = 0, .p1 = .{ .a = 5, .b = 6 } };
    };

    const ptr_base = &S2.s.base;
    const ptr_p0_a = &S2.s.p0.a;
    const ptr_p0_b = &S2.s.p0.b;
    const ptr_p0_c = &S2.s.p0.c;
    const ptr_p1_a = &S2.s.p1.a;
    const ptr_p1_b = &S2.s.p1.b;
    try expect_equal(1, ptr_base.*);
    try expect_equal(2, ptr_p0_a.*);
    try expect_equal(3, ptr_p0_b.*);
    try expect_equal(4, ptr_p0_c.*);
    try expect_equal(5, ptr_p1_a.*);
    try expect_equal(6, ptr_p1_b.*);
}

test "load pointer from packed struct" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const A = struct {
        index: u16,
    };
    const B = packed struct {
        x: *A,
        y: u32,
    };
    var a: A = .{ .index = 123 };
    const b_list: []const B = &.{.{ .x = &a, .y = 99 }};
    for (b_list) |b| {
        try expect(b.x.index == 123);
    }
}

test "@int_from_ptr on a packed struct field" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (native_endian != .little) return error.SkipZigTest;

    const S = struct {
        const P = packed struct {
            x: u8,
            y: u8,
            z: u32,
        };

        var p0: P = P{
            .x = 1,
            .y = 2,
            .z = 0,
        };
    };
    try expect(@int_from_ptr(&S.p0.z) - @int_from_ptr(&S.p0.x) == 2);
}

test "@int_from_ptr on a packed struct field unaligned and nested" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;
    if (native_endian != .little) return error.SkipZigTest; // Byte aligned packed struct field pointers have not been implemented yet

    const S1 = packed struct {
        a: u4,
        b: u4,
        c: u8,
    };
    const S2 = packed struct {
        base: u8,
        p0: S1,
        bit0: u1,
        p1: packed struct {
            a: u8,
        },
        p2: packed struct {
            a: u7,
            b: u8,
        },
        p3: S1,

        var s: @This() = .{
            .base = 1,
            .p0 = .{ .a = 2, .b = 3, .c = 4 },
            .bit0 = 0,
            .p1 = .{ .a = 5 },
            .p2 = .{ .a = 6, .b = 7 },
            .p3 = .{ .a = 8, .b = 9, .c = 10 },
        };
    };

    switch (comptime @alignOf(S2)) {
        4 => {
            comptime assert(@TypeOf(&S2.s.base) == *align(4) u8);
            comptime assert(@TypeOf(&S2.s.p0.a) == *align(1:0:2) u4);
            comptime assert(@TypeOf(&S2.s.p0.b) == *align(1:4:2) u4);
            comptime assert(@TypeOf(&S2.s.p0.c) == *u8);
            comptime assert(@TypeOf(&S2.s.bit0) == *align(4:24:8) u1);
            comptime assert(@TypeOf(&S2.s.p1.a) == *align(4:25:8) u8);
            comptime assert(@TypeOf(&S2.s.p2.a) == *align(4:33:8) u7);
            comptime assert(@TypeOf(&S2.s.p2.b) == *u8);
            comptime assert(@TypeOf(&S2.s.p3.a) == *align(2:0:2) u4);
            comptime assert(@TypeOf(&S2.s.p3.b) == *align(2:4:2) u4);
            comptime assert(@TypeOf(&S2.s.p3.c) == *u8);
        },
        8 => {
            comptime assert(@TypeOf(&S2.s.base) == *align(8) u8);
            comptime assert(@TypeOf(&S2.s.p0.a) == *align(1:0:2) u4);
            comptime assert(@TypeOf(&S2.s.p0.b) == *align(1:4:2) u4);
            comptime assert(@TypeOf(&S2.s.p0.c) == *u8);
            comptime assert(@TypeOf(&S2.s.bit0) == *align(8:24:8) u1);
            comptime assert(@TypeOf(&S2.s.p1.a) == *align(8:25:8) u8);
            comptime assert(@TypeOf(&S2.s.p2.a) == *align(8:33:8) u7);
            comptime assert(@TypeOf(&S2.s.p2.b) == *u8);
            comptime assert(@TypeOf(&S2.s.p3.a) == *align(2:0:2) u4);
            comptime assert(@TypeOf(&S2.s.p3.b) == *align(2:4:2) u4);
            comptime assert(@TypeOf(&S2.s.p3.c) == *u8);
        },
        else => {},
    }
    try expect(@int_from_ptr(&S2.s.base) - @int_from_ptr(&S2.s) == 0);
    try expect(@int_from_ptr(&S2.s.p0.a) - @int_from_ptr(&S2.s) == 1);
    try expect(@int_from_ptr(&S2.s.p0.b) - @int_from_ptr(&S2.s) == 1);
    try expect(@int_from_ptr(&S2.s.p0.c) - @int_from_ptr(&S2.s) == 2);
    try expect(@int_from_ptr(&S2.s.bit0) - @int_from_ptr(&S2.s) == 0);
    try expect(@int_from_ptr(&S2.s.p1.a) - @int_from_ptr(&S2.s) == 0);
    try expect(@int_from_ptr(&S2.s.p2.a) - @int_from_ptr(&S2.s) == 0);
    try expect(@int_from_ptr(&S2.s.p2.b) - @int_from_ptr(&S2.s) == 5);
    try expect(@int_from_ptr(&S2.s.p3.a) - @int_from_ptr(&S2.s) == 6);
    try expect(@int_from_ptr(&S2.s.p3.b) - @int_from_ptr(&S2.s) == 6);
    try expect(@int_from_ptr(&S2.s.p3.c) - @int_from_ptr(&S2.s) == 7);

    const S3 = packed struct {
        pad: u8,
        v: u2,
        s: packed struct {
            v: u3,
            s: packed struct {
                v: u2,
                s: packed struct {
                    bit0: u1,
                    byte: u8,
                    bit1: u1,
                },
            },
        },
        var v0: @This() = .{ .pad = 0, .v = 1, .s = .{ .v = 2, .s = .{ .v = 3, .s = .{ .bit0 = 0, .byte = 4, .bit1 = 1 } } } };
    };

    comptime assert(@TypeOf(&S3.v0.v) == *align(4:8:4) u2);
    comptime assert(@TypeOf(&S3.v0.s.v) == *align(4:10:4) u3);
    comptime assert(@TypeOf(&S3.v0.s.s.v) == *align(4:13:4) u2);
    comptime assert(@TypeOf(&S3.v0.s.s.s.bit0) == *align(4:15:4) u1);
    comptime assert(@TypeOf(&S3.v0.s.s.s.byte) == *align(2) u8);
    comptime assert(@TypeOf(&S3.v0.s.s.s.bit1) == *align(4:24:4) u1);
    try expect(@int_from_ptr(&S3.v0.v) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.v) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.s) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.s.v) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.s.s) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.s.s.bit0) - @int_from_ptr(&S3.v0) == 0);
    try expect(@int_from_ptr(&S3.v0.s.s.s.byte) - @int_from_ptr(&S3.v0) == 2);
    try expect(@int_from_ptr(&S3.v0.s.s.s.bit1) - @int_from_ptr(&S3.v0) == 0);
}

test "packed struct fields modification" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/16615
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const Small = packed struct {
        val: u8 = 0,
        lo: u4 = 0,
        hi: u4 = 0,

        var p: @This() = undefined;
    };
    Small.p = .{
        .val = 0x12,
        .lo = 3,
        .hi = 4,
    };
    try expect(@as(u16, @bit_cast(Small.p)) == 0x4312);

    Small.p.val -= Small.p.lo;
    Small.p.val += Small.p.hi;
    Small.p.hi -= Small.p.lo;
    try expect(@as(u16, @bit_cast(Small.p)) == 0x1313);
}

test "optional pointer in packed struct" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const T = packed struct { ptr: ?*const u8 };
    var n: u8 = 0;
    const x = T{ .ptr = &n };
    try expect(x.ptr.? == &n);
}

test "nested packed struct field access test" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO packed structs larger than 64 bits
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64 and builtin.target.ofmt != .elf and builtin.target.ofmt != .macho) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Vec2 = packed struct {
        x: f32,
        y: f32,
    };

    const Vec3 = packed struct {
        x: f32,
        y: f32,
        z: f32,
    };

    const NestedVec2 = packed struct {
        nested: Vec2,
    };

    const NestedVec3 = packed struct {
        nested: Vec3,
    };

    const vec2 = Vec2{
        .x = 1.0,
        .y = 2.0,
    };

    try std.testing.expect_equal(vec2.x, 1.0);
    try std.testing.expect_equal(vec2.y, 2.0);

    var vec2_o: Vec2 = undefined;
    const vec2_o_ptr: *Vec2 = &vec2_o;
    vec2_o_ptr.* = vec2;

    try std.testing.expect_equal(vec2_o.x, 1.0);
    try std.testing.expect_equal(vec2_o.y, 2.0);

    const nested_vec2 = NestedVec2{
        .nested = Vec2{
            .x = 1.0,
            .y = 2.0,
        },
    };

    try std.testing.expect_equal(nested_vec2.nested.x, 1.0);
    try std.testing.expect_equal(nested_vec2.nested.y, 2.0);

    var nested_o: NestedVec2 = undefined;
    const nested_o_ptr: *NestedVec2 = &nested_o;
    nested_o_ptr.* = nested_vec2;

    try std.testing.expect_equal(nested_o.nested.x, 1.0);
    try std.testing.expect_equal(nested_o.nested.y, 2.0);

    const vec3 = Vec3{
        .x = 1.0,
        .y = 2.0,
        .z = 3.0,
    };

    try std.testing.expect_equal(vec3.x, 1.0);
    try std.testing.expect_equal(vec3.y, 2.0);
    try std.testing.expect_equal(vec3.z, 3.0);

    var vec3_o: Vec3 = undefined;
    const vec3_o_ptr: *Vec3 = &vec3_o;
    vec3_o_ptr.* = vec3;

    try std.testing.expect_equal(vec3_o.x, 1.0);
    try std.testing.expect_equal(vec3_o.y, 2.0);
    try std.testing.expect_equal(vec3_o.z, 3.0);

    const nested_vec3 = NestedVec3{
        .nested = Vec3{
            .x = 1.0,
            .y = 2.0,
            .z = 3.0,
        },
    };

    try std.testing.expect_equal(nested_vec3.nested.x, 1.0);
    try std.testing.expect_equal(nested_vec3.nested.y, 2.0);
    try std.testing.expect_equal(nested_vec3.nested.z, 3.0);

    var nested_vec3_o: NestedVec3 = undefined;
    const nested_vec3_o_ptr: *NestedVec3 = &nested_vec3_o;
    nested_vec3_o_ptr.* = nested_vec3;

    try std.testing.expect_equal(nested_vec3_o.nested.x, 1.0);
    try std.testing.expect_equal(nested_vec3_o.nested.y, 2.0);
    try std.testing.expect_equal(nested_vec3_o.nested.z, 3.0);

    const hld = packed struct {
        c: u64,
        d: u32,
    };

    const mld = packed struct {
        h: u64,
        i: u64,
    };

    const a = packed struct {
        b: hld,
        g: mld,
    };

    var arg = a{ .b = hld{ .c = 1, .d = 2 }, .g = mld{ .h = 6, .i = 8 } };
    _ = &arg;
    try std.testing.expect(arg.b.c == 1);
    try std.testing.expect(arg.b.d == 2);
    try std.testing.expect(arg.g.h == 6);
    try std.testing.expect(arg.g.i == 8);
}

test "nested packed struct at non-zero offset" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Pair = packed struct(u24) {
        a: u16 = 0,
        b: u8 = 0,
    };
    const A = packed struct {
        p1: Pair,
        p2: Pair,
    };

    var k: u8 = 123;
    _ = &k;
    var v: A = .{
        .p1 = .{ .a = k + 1, .b = k },
        .p2 = .{ .a = k + 1, .b = k },
    };

    try expect(v.p1.a == k + 1 and v.p1.b == k);
    try expect(v.p2.a == k + 1 and v.p2.b == k);

    v.p2.a -= v.p1.a;
    v.p2.b -= v.p1.b;
    try expect(v.p2.a == 0 and v.p2.b == 0);
    try expect(v.p1.a == k + 1 and v.p1.b == k);
}

test "nested packed struct at non-zero offset 2" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO packed structs larger than 64 bits
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const Pair = packed struct(u40) {
            a: u32 = 0,
            b: u8 = 0,
        };
        const A = packed struct {
            p1: Pair,
            p2: Pair,
            c: C,
        };
        const C = packed struct {
            p1: Pair,
            pad1: u5,
            p2: Pair,
            pad2: u3,
            last: i16,
        };

        fn do_the_test() !void {
            var k: u8 = 123;
            _ = &k;
            var v: A = .{
                .p1 = .{ .a = k + 1, .b = k },
                .p2 = .{ .a = k + 1, .b = k },
                .c = .{
                    .pad1 = 11,
                    .pad2 = 2,
                    .p1 = .{ .a = k + 1, .b = k },
                    .p2 = .{ .a = k + 1, .b = k },
                    .last = -12345,
                },
            };

            try expect(v.p1.a == k + 1 and v.p1.b == k);
            try expect(v.p2.a == k + 1 and v.p2.b == k);
            try expect(v.c.p2.a == k + 1 and v.c.p2.b == k);
            try expect(v.c.p2.a == k + 1 and v.c.p2.b == k);
            try expect(v.c.last == -12345);
            try expect(v.c.pad1 == 11 and v.c.pad2 == 2);

            v.p2.a -= v.p1.a;
            v.p2.b -= v.p1.b;
            v.c.p2.a -= v.c.p1.a;
            v.c.p2.b -= v.c.p1.b;
            v.c.last -|= 32000;
            try expect(v.p2.a == 0 and v.p2.b == 0);
            try expect(v.p1.a == k + 1 and v.p1.b == k);
            try expect(v.c.p2.a == 0 and v.c.p2.b == 0);
            try expect(v.c.p1.a == k + 1 and v.c.p1.b == k);
            try expect(v.c.last == -32768);
            try expect(v.c.pad1 == 11 and v.c.pad2 == 2);
        }
    };

    try S.do_the_test();
    try comptime S.do_the_test();
}

test "runtime init of unnamed packed struct type" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    var z: u8 = 123;
    _ = &z;
    try (packed struct {
        x: u8,
        pub fn m(s: @This()) !void {
            try expect(s.x == 123);
        }
    }{ .x = z }).m();
}

test "packed struct passed to callconv(.C) function" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = struct {
        const Packed = packed struct {
            a: u16,
            b: bool = true,
            c: bool = true,
            d: u46 = 0,
        };

        fn foo(p: Packed, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.C) bool {
            return p.a == 12345 and p.b == true and p.c == true and p.d == 0 and a1 == 5 and a2 == 4 and a3 == 3 and a4 == 2 and a5 == 1;
        }
    };
    const result = S.foo(S.Packed{
        .a = 12345,
        .b = true,
        .c = true,
    }, 5, 4, 3, 2, 1);
    try expect(result);
}

test "overaligned pointer to packed struct" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = packed struct { a: u32, b: u32 };
    var foo: S align(4) = .{ .a = 123, .b = 456 };
    const ptr: *align(4) S = &foo;
    switch (comptime builtin.cpu.arch.endian()) {
        .little => {
            const ptr_to_b: *u32 = &ptr.b;
            try expect(ptr_to_b.* == 456);
        },
        .big => {
            // Byte aligned packed struct field pointers have not been implemented yet.
            const ptr_to_a: *align(4:0:8) u32 = &ptr.a;
            try expect(ptr_to_a.* == 123);
        },
    }
}

test "packed struct initialized in bitcast" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const T = packed struct { val: u8 };
    var val: u8 = 123;
    _ = &val;
    const t = @as(u8, @bit_cast(T{ .val = val }));
    try expect(t == val);
}

test "pointer to container level packed struct field" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = packed struct(u32) {
        test_bit: bool,
        someother_data: u12,
        other_test_bit: bool,
        someother_more_different_data: u12,
        other_bits: packed struct(u6) {
            enable_1: bool,
            enable_2: bool,
            enable_3: bool,
            enable_4: bool,
            enable_5: bool,
            enable_6: bool,
        },
        var arr = [_]u32{0} ** 2;
    };
    @as(*S, @ptr_cast(&S.arr[0])).other_bits.enable_3 = true;
    try expect(S.arr[0] == 0x10000000);
}

test "store undefined to packed result location" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var x: u4 = 0;
    _ = &x;
    const s = packed struct { x: u4, y: u4 }{ .x = x, .y = if (x > 0) x else undefined };
    try expect_equal(x, s.x);
}

test "bitcast back and forth" {
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/9914
    const S = packed struct { one: u6, two: u1 };
    const s = S{ .one = 0b110101, .two = 0b1 };
    const u: u7 = @bit_cast(s);
    const s2: S = @bit_cast(u);
    try expect(s.one == s2.one);
    try expect(s.two == s2.two);
}

test "field access of packed struct smaller than its abi size inside struct initialized with rls" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/14200
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = struct {
        ps: packed struct { x: i2, y: i2 },

        fn init(cond: bool) @This() {
            return .{ .ps = .{ .x = 0, .y = if (cond) 1 else 0 } };
        }
    };

    const s = S.init(true);
    // note: this bug is triggered by the == operator, expect_equal will hide it
    try expect(@as(i2, 0) == s.ps.x);
    try expect(@as(i2, 1) == s.ps.y);
}

test "modify nested packed struct aligned field" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/14632
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const Options = packed struct {
        foo: bool = false,
        bar: bool = false,
        pretty_print: packed struct {
            enabled: bool = false,
            num_spaces: u4 = 4,
            space_char: enum(u1) { space, tab } = .space,
            indent: u8 = 0,
        } = .{},
        baz: bool = false,
    };

    var opts = Options{};
    opts.pretty_print.indent += 1;
    try std.testing.expect_equal(0b00000000100100000, @as(u17, @bit_cast(opts)));
    try std.testing.expect(!opts.foo);
    try std.testing.expect(!opts.bar);
    try std.testing.expect(!opts.pretty_print.enabled);
    try std.testing.expect_equal(4, opts.pretty_print.num_spaces);
    try std.testing.expect_equal(1, opts.pretty_print.indent);
    try std.testing.expect(!opts.baz);
}

test "assigning packed struct inside another packed struct" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/9674
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    const S = struct {
        const Inner = packed struct {
            bits: u3,
            more_bits: u6,
        };

        const Outer = packed struct {
            padding: u5,
            inner: Inner,
        };
        fn t(inner: Inner) void {
            r.inner = inner;
        }

        var mem: Outer = undefined;
        var r: *volatile Outer = &mem;
    };

    const val = S.Inner{ .bits = 1, .more_bits = 11 };
    S.mem.padding = 0;
    S.t(val);

    try expect_equal(val, S.mem.inner);
    try expect(S.mem.padding == 0);
}

test "packed struct used as part of anon decl name" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = packed struct { a: u0 = 0 };
    var a: u8 = 0;
    _ = &a;
    try std.io.null_writer.print("\n{} {}\n", .{ a, S{} });
}

test "packed struct acts as a namespace" {
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    const Bar = packed struct {
        const Baz = enum {
            fizz,
            buzz,
        };
    };
    var foo = Bar.Baz.fizz;
    _ = &foo;
    try expect(foo == .fizz);
}

test "pointer loaded correctly from packed struct" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const RAM = struct {
        data: [0xFFFF + 1]u8,
        fn new() !@This() {
            return .{ .data = [_]u8{0} ** 0x10000 };
        }
        fn get(self: *@This(), addr: u16) u8 {
            return self.data[addr];
        }
    };

    const CPU = packed struct {
        interrupts: bool,
        ram: *RAM,
        fn new(ram: *RAM) !@This() {
            return .{
                .ram = ram,
                .interrupts = false,
            };
        }
        fn tick(self: *@This()) !void {
            const queued_interrupts = self.ram.get(0xFFFF) & self.ram.get(0xFF0F);
            if (self.interrupts and queued_interrupts != 0) {
                self.interrupts = false;
            }
        }
    };
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    if (builtin.zig_backend == .stage2_c and builtin.os.tag == .windows) return error.SkipZigTest; // crashes MSVC

    var ram = try RAM.new();
    var cpu = try CPU.new(&ram);
    try cpu.tick();
    try std.testing.expect(cpu.interrupts == false);
}

test "assignment to non-byte-aligned field in packed struct" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Frame = packed struct {
        num: u20,
    };

    const Entry = packed struct {
        other: u12,
        frame: Frame,
    };

    const frame = Frame{ .num = 0x7FDE };
    var entry = Entry{ .other = 0, .frame = .{ .num = 0xFFFFF } };
    entry.frame = frame;
    try expect(entry.frame.num == 0x7FDE);
}

test "packed struct field pointer aligned properly" {
    if (builtin.zig_backend == .stage2_x86) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Foo = packed struct {
        a: i32,
        b: u8,

        var buffer: [256]u8 = undefined;
    };

    var f1: *align(16) Foo = @align_cast(@as(*align(1) Foo, @ptr_cast(&Foo.buffer[0])));
    try expect(@typeInfo(@TypeOf(f1)).Pointer.alignment == 16);
    try expect(@int_from_ptr(f1) == @int_from_ptr(&f1.a));
    try expect(@typeInfo(@TypeOf(&f1.a)).Pointer.alignment == 16);
}

test "load flag from packed struct in union" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const A = packed struct {
        a: bool,
        b: bool,
        c: bool,
        d: bool,

        e: bool,
        f: bool,
        g: bool,
        h: bool,
    };

    const X = union {
        x: A,
        y: u64,

        pub fn a(_: i32, _: i32, _: i32, _: i32, _: i32, _: bool, flag_b: bool) !void {
            const flag_b_byte: u8 = @int_from_bool(flag_b);
            try std.testing.expect(flag_b_byte == 1);
        }
        pub fn b(x: *@This()) !void {
            try a(0, 1, 2, 3, 4, x.x.a, x.x.b);
        }
    };
    var flags = A{
        .a = false,
        .b = true,
        .c = false,
        .d = false,

        .e = false,
        .f = true,
        .g = false,
        .h = false,
    };
    _ = &flags;
    var x = X{
        .x = flags,
    };
    try X.b(&x);
    comptime if (@size_of(A) != 1) unreachable;
}

test "bitcasting a packed struct at comptime and using the result" {
    comptime {
        const Struct = packed struct {
            x: packed union { a: u63, b: i32 },
            y: u1,

            pub fn bitcast(fd: u64) @This() {
                return @bit_cast(fd);
            }

            pub fn cannot_reach(_: @This()) i32 {
                return 0;
            }
        };

        _ = Struct.bitcast(@as(u64, 0)).cannot_reach();
    }
}

test "2-byte packed struct argument in C calling convention" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const S = packed struct(u16) {
        x: u15 = 0,
        y: u1 = 0,

        fn foo(s: @This()) callconv(.C) i32 {
            return s.x;
        }
        fn bar(s: @This()) !void {
            try expect(foo(s) == 1);
        }
    };
    {
        var s: S = .{};
        s.x += 1;
        try S.bar(s);
    }
    comptime {
        var s: S = .{};
        s.x += 1;
        try S.bar(s);
    }
}

test "packed struct contains optional pointer" {
    const foo: packed struct {
        a: ?*@This() = null,
    } = .{};
    try expect(foo.a == null);
}
