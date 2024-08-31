const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const expect_equal = std.testing.expect_equal;

test "flags in packed union" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_flags_in_packed_union();
    try comptime test_flags_in_packed_union();
}

fn test_flags_in_packed_union() !void {
    const FlagBits = packed struct(u8) {
        enable_1: bool = false,
        enable_2: bool = false,
        enable_3: bool = false,
        enable_4: bool = false,
        other_flags: packed union {
            flags: packed struct(u4) {
                enable_1: bool = true,
                enable_2: bool = false,
                enable_3: bool = false,
                enable_4: bool = false,
            },
            bits: u4,
        } = .{ .flags = .{} },
    };
    var test_bits: FlagBits = .{};

    try expect_equal(false, test_bits.enable_1);
    try expect_equal(true, test_bits.other_flags.flags.enable_1);

    test_bits.enable_1 = true;

    try expect_equal(true, test_bits.enable_1);
    try expect_equal(true, test_bits.other_flags.flags.enable_1);

    test_bits.other_flags.flags.enable_1 = false;

    try expect_equal(true, test_bits.enable_1);
    try expect_equal(false, test_bits.other_flags.flags.enable_1);
}

test "flags in packed union at offset" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    try test_flags_in_packed_union_at_offset();
    try comptime test_flags_in_packed_union_at_offset();
}

fn test_flags_in_packed_union_at_offset() !void {
    const FlagBits = packed union {
        base_flags: packed union {
            flags: packed struct(u4) {
                enable_1: bool = true,
                enable_2: bool = false,
                enable_3: bool = false,
                enable_4: bool = false,
            },
            bits: u4,
        },
        adv_flags: packed struct(u12) {
            pad: u8 = 0,
            adv: packed union {
                flags: packed struct(u4) {
                    enable_1: bool = true,
                    enable_2: bool = false,
                    enable_3: bool = false,
                    enable_4: bool = false,
                },
                bits: u4,
            },
        },
    };
    var test_bits: FlagBits = .{ .adv_flags = .{ .adv = .{ .flags = .{} } } };

    try expect_equal(@as(u8, 0), test_bits.adv_flags.pad);
    try expect_equal(true, test_bits.adv_flags.adv.flags.enable_1);
    try expect_equal(false, test_bits.adv_flags.adv.flags.enable_2);

    test_bits.adv_flags.adv.flags.enable_1 = false;
    test_bits.adv_flags.adv.flags.enable_2 = true;
    try expect_equal(@as(u8, 0), test_bits.adv_flags.pad);
    try expect_equal(false, test_bits.adv_flags.adv.flags.enable_1);
    try expect_equal(true, test_bits.adv_flags.adv.flags.enable_2);

    test_bits.adv_flags.adv.bits = 12;
    try expect_equal(@as(u8, 0), test_bits.adv_flags.pad);
    try expect_equal(false, test_bits.adv_flags.adv.flags.enable_1);
    try expect_equal(false, test_bits.adv_flags.adv.flags.enable_2);
}

test "packed union in packed struct" {
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    // Originally reported at https://github.com/ziglang/zig/issues/16581
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;

    try test_packed_union_in_packed_struct();
    try comptime test_packed_union_in_packed_struct();
}

fn test_packed_union_in_packed_struct() !void {
    const ReadRequest = packed struct { key: i32 };
    const RequestType = enum(u1) {
        read,
        insert,
    };
    const RequestUnion = packed union {
        read: ReadRequest,
    };

    const Request = packed struct {
        active_type: RequestType,
        request: RequestUnion,
        const Self = @This();

        fn init(read: ReadRequest) Self {
            return .{
                .active_type = .read,
                .request = RequestUnion{ .read = read },
            };
        }
    };

    try std.testing.expect_equal(RequestType.read, Request.init(.{ .key = 3 }).active_type);
}

test "packed union initialized with a runtime value" {
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_sparc64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_spirv64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_riscv64) return error.SkipZigTest;

    const Fields = packed struct {
        timestamp: u50,
        random_bits: u13,
    };
    const ID = packed union {
        value: u63,
        fields: Fields,

        fn value() i64 {
            return 1341;
        }
    };

    const timestamp: i64 = ID.value();
    const id = ID{ .fields = Fields{
        .timestamp = @as(u50, @int_cast(timestamp)),
        .random_bits = 420,
    } };
    try std.testing.expect((ID{ .value = id.value }).fields.timestamp == timestamp);
}

test "assigning to non-active field at comptime" {
    comptime {
        const FlagBits = packed union {
            flags: packed struct {},
            bits: packed struct {},
        };

        var test_bits: FlagBits = .{ .flags = .{} };
        test_bits.bits = .{};
    }
}

test "comptime packed union of pointers" {
    const U = packed union {
        a: *const u32,
        b: *const [1]u32,
    };

    const x: u32 = 123;
    const u: U = .{ .a = &x };

    comptime assert(u.b[0] == 123);
}
