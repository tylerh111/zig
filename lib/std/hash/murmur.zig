const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const native_endian = builtin.target.cpu.arch.endian();

const default_seed: u32 = 0xc70f6907;

pub const Murmur2_32 = struct {
    const Self = @This();

    pub fn hash(str: []const u8) u32 {
        return @call(.always_inline, Self.hash_with_seed, .{ str, default_seed });
    }

    pub fn hash_with_seed(str: []const u8, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = @truncate(str.len);
        var h1: u32 = seed ^ len;
        for (@as([*]align(1) const u32, @ptr_cast(str.ptr))[0..(len >> 2)]) |v| {
            var k1: u32 = v;
            if (native_endian == .big)
                k1 = @byte_swap(k1);
            k1 *%= m;
            k1 ^= k1 >> 24;
            k1 *%= m;
            h1 *%= m;
            h1 ^= k1;
        }
        const offset = len & 0xfffffffc;
        const rest = len & 3;
        if (rest >= 3) {
            h1 ^= @as(u32, @int_cast(str[offset + 2])) << 16;
        }
        if (rest >= 2) {
            h1 ^= @as(u32, @int_cast(str[offset + 1])) << 8;
        }
        if (rest >= 1) {
            h1 ^= @as(u32, @int_cast(str[offset + 0]));
            h1 *%= m;
        }
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }

    pub fn hash_uint32(v: u32) u32 {
        return @call(.always_inline, Self.hash_uint32_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint32_with_seed(v: u32, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = 4;
        var h1: u32 = seed ^ len;
        var k1: u32 = undefined;
        k1 = v *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }

    pub fn hash_uint64(v: u64) u32 {
        return @call(.always_inline, Self.hash_uint64_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint64_with_seed(v: u64, seed: u32) u32 {
        const m: u32 = 0x5bd1e995;
        const len: u32 = 8;
        var h1: u32 = seed ^ len;
        var k1: u32 = undefined;
        k1 = @as(u32, @truncate(v)) *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        k1 = @as(u32, @truncate(v >> 32)) *% m;
        k1 ^= k1 >> 24;
        k1 *%= m;
        h1 *%= m;
        h1 ^= k1;
        h1 ^= h1 >> 13;
        h1 *%= m;
        h1 ^= h1 >> 15;
        return h1;
    }
};

pub const Murmur2_64 = struct {
    const Self = @This();

    pub fn hash(str: []const u8) u64 {
        return @call(.always_inline, Self.hash_with_seed, .{ str, default_seed });
    }

    pub fn hash_with_seed(str: []const u8, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        var h1: u64 = seed ^ (@as(u64, str.len) *% m);
        for (@as([*]align(1) const u64, @ptr_cast(str.ptr))[0 .. str.len / 8]) |v| {
            var k1: u64 = v;
            if (native_endian == .big)
                k1 = @byte_swap(k1);
            k1 *%= m;
            k1 ^= k1 >> 47;
            k1 *%= m;
            h1 ^= k1;
            h1 *%= m;
        }
        const rest = str.len & 7;
        const offset = str.len - rest;
        if (rest > 0) {
            var k1: u64 = 0;
            @memcpy(@as([*]u8, @ptr_cast(&k1))[0..rest], str[offset..]);
            if (native_endian == .big)
                k1 = @byte_swap(k1);
            h1 ^= k1;
            h1 *%= m;
        }
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }

    pub fn hash_uint32(v: u32) u64 {
        return @call(.always_inline, Self.hash_uint32_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint32_with_seed(v: u32, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        const len: u64 = 4;
        var h1: u64 = seed ^ (len *% m);
        const k1: u64 = v;
        h1 ^= k1;
        h1 *%= m;
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }

    pub fn hash_uint64(v: u64) u64 {
        return @call(.always_inline, Self.hash_uint64_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint64_with_seed(v: u64, seed: u64) u64 {
        const m: u64 = 0xc6a4a7935bd1e995;
        const len: u64 = 8;
        var h1: u64 = seed ^ (len *% m);
        var k1: u64 = undefined;
        k1 = v *% m;
        k1 ^= k1 >> 47;
        k1 *%= m;
        h1 ^= k1;
        h1 *%= m;
        h1 ^= h1 >> 47;
        h1 *%= m;
        h1 ^= h1 >> 47;
        return h1;
    }
};

pub const Murmur3_32 = struct {
    const Self = @This();

    fn rotl32(x: u32, comptime r: u32) u32 {
        return (x << r) | (x >> (32 - r));
    }

    pub fn hash(str: []const u8) u32 {
        return @call(.always_inline, Self.hash_with_seed, .{ str, default_seed });
    }

    pub fn hash_with_seed(str: []const u8, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = @truncate(str.len);
        var h1: u32 = seed;
        for (@as([*]align(1) const u32, @ptr_cast(str.ptr))[0..(len >> 2)]) |v| {
            var k1: u32 = v;
            if (native_endian == .big)
                k1 = @byte_swap(k1);
            k1 *%= c1;
            k1 = rotl32(k1, 15);
            k1 *%= c2;
            h1 ^= k1;
            h1 = rotl32(h1, 13);
            h1 *%= 5;
            h1 +%= 0xe6546b64;
        }
        {
            var k1: u32 = 0;
            const offset = len & 0xfffffffc;
            const rest = len & 3;
            if (rest == 3) {
                k1 ^= @as(u32, @int_cast(str[offset + 2])) << 16;
            }
            if (rest >= 2) {
                k1 ^= @as(u32, @int_cast(str[offset + 1])) << 8;
            }
            if (rest >= 1) {
                k1 ^= @as(u32, @int_cast(str[offset + 0]));
                k1 *%= c1;
                k1 = rotl32(k1, 15);
                k1 *%= c2;
                h1 ^= k1;
            }
        }
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }

    pub fn hash_uint32(v: u32) u32 {
        return @call(.always_inline, Self.hash_uint32_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint32_with_seed(v: u32, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = 4;
        var h1: u32 = seed;
        var k1: u32 = undefined;
        k1 = v *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }

    pub fn hash_uint64(v: u64) u32 {
        return @call(.always_inline, Self.hash_uint64_with_seed, .{ v, default_seed });
    }

    pub fn hash_uint64_with_seed(v: u64, seed: u32) u32 {
        const c1: u32 = 0xcc9e2d51;
        const c2: u32 = 0x1b873593;
        const len: u32 = 8;
        var h1: u32 = seed;
        var k1: u32 = undefined;
        k1 = @as(u32, @truncate(v)) *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        k1 = @as(u32, @truncate(v >> 32)) *% c1;
        k1 = rotl32(k1, 15);
        k1 *%= c2;
        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 *%= 5;
        h1 +%= 0xe6546b64;
        h1 ^= len;
        h1 ^= h1 >> 16;
        h1 *%= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *%= 0xc2b2ae35;
        h1 ^= h1 >> 16;
        return h1;
    }
};

const verify = @import("verify.zig");

test "murmur2_32" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byte_swap(v0), @byte_swap(v1) },
    };
    try testing.expect_equal(Murmur2_32.hash(@as([*]const u8, @ptr_cast(&v0le))[0..4]), Murmur2_32.hash_uint32(v0));
    try testing.expect_equal(Murmur2_32.hash(@as([*]const u8, @ptr_cast(&v1le))[0..8]), Murmur2_32.hash_uint64(v1));
}

test "murmur2_32 smhasher" {
    const Test = struct {
        fn do() !void {
            try testing.expect_equal(verify.smhasher(Murmur2_32.hash_with_seed), 0x27864C1E);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}

test "murmur2_64" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byte_swap(v0), @byte_swap(v1) },
    };
    try testing.expect_equal(Murmur2_64.hash(@as([*]const u8, @ptr_cast(&v0le))[0..4]), Murmur2_64.hash_uint32(v0));
    try testing.expect_equal(Murmur2_64.hash(@as([*]const u8, @ptr_cast(&v1le))[0..8]), Murmur2_64.hash_uint64(v1));
}

test "mumur2_64 smhasher" {
    const Test = struct {
        fn do() !void {
            try std.testing.expect_equal(verify.smhasher(Murmur2_64.hash_with_seed), 0x1F0D3804);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}

test "murmur3_32" {
    const v0: u32 = 0x12345678;
    const v1: u64 = 0x1234567812345678;
    const v0le: u32, const v1le: u64 = switch (native_endian) {
        .little => .{ v0, v1 },
        .big => .{ @byte_swap(v0), @byte_swap(v1) },
    };
    try testing.expect_equal(Murmur3_32.hash(@as([*]const u8, @ptr_cast(&v0le))[0..4]), Murmur3_32.hash_uint32(v0));
    try testing.expect_equal(Murmur3_32.hash(@as([*]const u8, @ptr_cast(&v1le))[0..8]), Murmur3_32.hash_uint64(v1));
}

test "mumur3_32 smhasher" {
    const Test = struct {
        fn do() !void {
            try std.testing.expect_equal(verify.smhasher(Murmur3_32.hash_with_seed), 0xB0F57EE3);
        }
    };
    try Test.do();
    @setEvalBranchQuota(30000);
    try comptime Test.do();
}
