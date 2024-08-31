const builtin = @import("builtin");
const std = @import("std");
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const max_int = std.math.max_int;

test "@int_cast i32 to u7" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    var x: u128 = max_int(u128);
    var y: i32 = 120;
    _ = .{ &x, &y };
    const z = x >> @as(u7, @int_cast(y));
    try expect(z == 0xff);
}

test "coerce i8 to i32 and @int_cast back" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO

    var x: i8 = -5;
    var y: i32 = -5;
    _ = .{ &x, &y };
    try expect(y == x);

    var x2: i32 = -5;
    var y2: i8 = -5;
    _ = .{ &x2, &y2 };
    try expect(y2 == @as(i8, @int_cast(x2)));
}

test "coerce non byte-sized integers accross 32bits boundary" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    {
        var v: u21 = 6417;
        _ = &v;
        const a: u32 = v;
        const b: u64 = v;
        const c: u64 = a;
        var w: u64 = 0x1234567812345678;
        _ = &w;
        const d: u21 = @truncate(w);
        const e: u60 = d;
        try expect_equal(@as(u32, 6417), a);
        try expect_equal(@as(u64, 6417), b);
        try expect_equal(@as(u64, 6417), c);
        try expect_equal(@as(u21, 0x145678), d);
        try expect_equal(@as(u60, 0x145678), e);
    }

    {
        var v: u10 = 234;
        _ = &v;
        const a: u32 = v;
        const b: u64 = v;
        const c: u64 = a;
        var w: u64 = 0x1234567812345678;
        _ = &w;
        const d: u10 = @truncate(w);
        const e: u60 = d;
        try expect_equal(@as(u32, 234), a);
        try expect_equal(@as(u64, 234), b);
        try expect_equal(@as(u64, 234), c);
        try expect_equal(@as(u21, 0x278), d);
        try expect_equal(@as(u60, 0x278), e);
    }
    {
        var v: u7 = 11;
        _ = &v;
        const a: u32 = v;
        const b: u64 = v;
        const c: u64 = a;
        var w: u64 = 0x1234567812345678;
        _ = &w;
        const d: u7 = @truncate(w);
        const e: u60 = d;
        try expect_equal(@as(u32, 11), a);
        try expect_equal(@as(u64, 11), b);
        try expect_equal(@as(u64, 11), c);
        try expect_equal(@as(u21, 0x78), d);
        try expect_equal(@as(u60, 0x78), e);
    }

    {
        var v: i21 = -6417;
        _ = &v;
        const a: i32 = v;
        const b: i64 = v;
        const c: i64 = a;
        var w: i64 = -12345;
        _ = &w;
        const d: i21 = @int_cast(w);
        const e: i60 = d;
        try expect_equal(@as(i32, -6417), a);
        try expect_equal(@as(i64, -6417), b);
        try expect_equal(@as(i64, -6417), c);
        try expect_equal(@as(i21, -12345), d);
        try expect_equal(@as(i60, -12345), e);
    }

    {
        var v: i10 = -234;
        _ = &v;
        const a: i32 = v;
        const b: i64 = v;
        const c: i64 = a;
        var w: i64 = -456;
        _ = &w;
        const d: i10 = @int_cast(w);
        const e: i60 = d;
        try expect_equal(@as(i32, -234), a);
        try expect_equal(@as(i64, -234), b);
        try expect_equal(@as(i64, -234), c);
        try expect_equal(@as(i10, -456), d);
        try expect_equal(@as(i60, -456), e);
    }
    {
        var v: i7 = -11;
        _ = &v;
        const a: i32 = v;
        const b: i64 = v;
        const c: i64 = a;
        var w: i64 = -42;
        _ = &w;
        const d: i7 = @int_cast(w);
        const e: i60 = d;
        try expect_equal(@as(i32, -11), a);
        try expect_equal(@as(i64, -11), b);
        try expect_equal(@as(i64, -11), c);
        try expect_equal(@as(i7, -42), d);
        try expect_equal(@as(i60, -42), e);
    }
}

const Piece = packed struct {
    color: Color,
    type: Type,

    const Type = enum(u3) { KING, QUEEN, BISHOP, KNIGHT, ROOK, PAWN };
    const Color = enum(u1) { WHITE, BLACK };

    fn char_to_piece(c: u8) !@This() {
        return .{
            .type = try char_to_piece_type(c),
            .color = if (std.ascii.is_upper(c)) Color.WHITE else Color.BLACK,
        };
    }

    fn char_to_piece_type(c: u8) !Type {
        return switch (std.ascii.to_lower(c)) {
            'p' => .PAWN,
            'k' => .KING,
            'q' => .QUEEN,
            'b' => .BISHOP,
            'n' => .KNIGHT,
            'r' => .ROOK,
            else => error.UnexpectedCharError,
        };
    }
};

test "load non byte-sized optional value" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/14200
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    // note: this bug is triggered by the == operator, expect_equal will hide it
    const opt: ?Piece = try Piece.char_to_piece('p');
    try expect(opt.?.type == .PAWN);
    try expect(opt.?.color == .BLACK);

    var p: Piece = undefined;
    @as(*u8, @ptr_cast(&p)).* = 0b11111011;
    try expect(p.type == .PAWN);
    try expect(p.color == .BLACK);
}

test "load non byte-sized value in struct" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    if (builtin.cpu.arch.endian() != .little) return error.SkipZigTest; // packed struct TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    // note: this bug is triggered by the == operator, expect_equal will hide it
    // using ptr_cast not to depend on unitialised memory state

    var struct0: struct {
        p: Piece,
        int: u8,
    } = undefined;
    @as(*u8, @ptr_cast(&struct0.p)).* = 0b11111011;
    try expect(struct0.p.type == .PAWN);
    try expect(struct0.p.color == .BLACK);

    var struct1: packed struct {
        p0: Piece,
        p1: Piece,
        pad: u1,
        p2: Piece,
    } = undefined;
    @as(*u8, @ptr_cast(&struct1.p0)).* = 0b11111011;
    struct1.p1 = try Piece.char_to_piece('p');
    struct1.p2 = try Piece.char_to_piece('p');
    try expect(struct1.p0.type == .PAWN);
    try expect(struct1.p0.color == .BLACK);
    try expect(struct1.p1.type == .PAWN);
    try expect(struct1.p1.color == .BLACK);
    try expect(struct1.p2.type == .PAWN);
    try expect(struct1.p2.color == .BLACK);
}

test "load non byte-sized value in union" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // note: this bug is triggered by the == operator, expect_equal will hide it
    // using ptr_cast not to depend on unitialised memory state

    var union0: packed union {
        p: Piece,
        int: u8,
    } = .{ .int = 0 };
    union0.int = 0b11111011;
    try expect(union0.p.type == .PAWN);
    try expect(union0.p.color == .BLACK);

    var union1: union {
        p: Piece,
        int: u8,
    } = .{ .p = .{ .color = .WHITE, .type = .KING } };
    @as(*u8, @ptr_cast(&union1.p)).* = 0b11111011;
    try expect(union1.p.type == .PAWN);
    try expect(union1.p.color == .BLACK);

    var pieces: [3]Piece = undefined;
    @as(*u8, @ptr_cast(&pieces[1])).* = 0b11111011;
    try expect(pieces[1].type == .PAWN);
    try expect(pieces[1].color == .BLACK);
}
