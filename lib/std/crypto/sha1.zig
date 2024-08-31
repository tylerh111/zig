const std = @import("../std.zig");
const mem = std.mem;
const math = std.math;

const RoundParam = struct {
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    i: u32,
};

fn round_param(a: usize, b: usize, c: usize, d: usize, e: usize, i: u32) RoundParam {
    return RoundParam{
        .a = a,
        .b = b,
        .c = c,
        .d = d,
        .e = e,
        .i = i,
    };
}

/// The SHA-1 function is now considered cryptographically broken.
/// Namely, it is feasible to find multiple inputs producing the same hash.
/// For a fast-performing, cryptographically secure hash function, see SHA512/256, BLAKE2 or BLAKE3.
pub const Sha1 = struct {
    const Self = @This();
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    s: [5]u32,
    // Streaming Cache
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{
            .s = [_]u32{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
        };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Sha1.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.round(d.buf[0..]);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.round(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        @memcpy(d.buf[d.buf_len..][0 .. b.len - off], b[off..]);
        d.buf_len += @as(u8, @int_cast(b[off..].len));

        d.total_len += b.len;
    }

    pub fn peek(d: Self) [digest_length]u8 {
        var copy = d;
        return copy.final_result();
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (64 - d.buf_len < 8) {
            d.round(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[63] = @as(u8, @int_cast(d.total_len & 0x1f)) << 3;
        while (i < 8) : (i += 1) {
            d.buf[63 - i] = @as(u8, @int_cast(len & 0xff));
            len >>= 8;
        }

        d.round(d.buf[0..]);

        for (d.s, 0..) |s, j| {
            mem.write_int(u32, out[4 * j ..][0..4], s, .big);
        }
    }

    pub fn final_result(d: *Self) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    fn round(d: *Self, b: *const [64]u8) void {
        var s: [16]u32 = undefined;

        var v: [5]u32 = [_]u32{
            d.s[0],
            d.s[1],
            d.s[2],
            d.s[3],
            d.s[4],
        };

        const round0a = comptime [_]RoundParam{
            round_param(0, 1, 2, 3, 4, 0),
            round_param(4, 0, 1, 2, 3, 1),
            round_param(3, 4, 0, 1, 2, 2),
            round_param(2, 3, 4, 0, 1, 3),
            round_param(1, 2, 3, 4, 0, 4),
            round_param(0, 1, 2, 3, 4, 5),
            round_param(4, 0, 1, 2, 3, 6),
            round_param(3, 4, 0, 1, 2, 7),
            round_param(2, 3, 4, 0, 1, 8),
            round_param(1, 2, 3, 4, 0, 9),
            round_param(0, 1, 2, 3, 4, 10),
            round_param(4, 0, 1, 2, 3, 11),
            round_param(3, 4, 0, 1, 2, 12),
            round_param(2, 3, 4, 0, 1, 13),
            round_param(1, 2, 3, 4, 0, 14),
            round_param(0, 1, 2, 3, 4, 15),
        };
        inline for (round0a) |r| {
            s[r.i] = mem.read_int(u32, b[r.i * 4 ..][0..4], .big);

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x5A827999 +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) | (~v[r.b] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round0b = comptime [_]RoundParam{
            round_param(4, 0, 1, 2, 3, 16),
            round_param(3, 4, 0, 1, 2, 17),
            round_param(2, 3, 4, 0, 1, 18),
            round_param(1, 2, 3, 4, 0, 19),
        };
        inline for (round0b) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x5A827999 +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) | (~v[r.b] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round1 = comptime [_]RoundParam{
            round_param(0, 1, 2, 3, 4, 20),
            round_param(4, 0, 1, 2, 3, 21),
            round_param(3, 4, 0, 1, 2, 22),
            round_param(2, 3, 4, 0, 1, 23),
            round_param(1, 2, 3, 4, 0, 24),
            round_param(0, 1, 2, 3, 4, 25),
            round_param(4, 0, 1, 2, 3, 26),
            round_param(3, 4, 0, 1, 2, 27),
            round_param(2, 3, 4, 0, 1, 28),
            round_param(1, 2, 3, 4, 0, 29),
            round_param(0, 1, 2, 3, 4, 30),
            round_param(4, 0, 1, 2, 3, 31),
            round_param(3, 4, 0, 1, 2, 32),
            round_param(2, 3, 4, 0, 1, 33),
            round_param(1, 2, 3, 4, 0, 34),
            round_param(0, 1, 2, 3, 4, 35),
            round_param(4, 0, 1, 2, 3, 36),
            round_param(3, 4, 0, 1, 2, 37),
            round_param(2, 3, 4, 0, 1, 38),
            round_param(1, 2, 3, 4, 0, 39),
        };
        inline for (round1) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x6ED9EBA1 +% s[r.i & 0xf] +% (v[r.b] ^ v[r.c] ^ v[r.d]);
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round2 = comptime [_]RoundParam{
            round_param(0, 1, 2, 3, 4, 40),
            round_param(4, 0, 1, 2, 3, 41),
            round_param(3, 4, 0, 1, 2, 42),
            round_param(2, 3, 4, 0, 1, 43),
            round_param(1, 2, 3, 4, 0, 44),
            round_param(0, 1, 2, 3, 4, 45),
            round_param(4, 0, 1, 2, 3, 46),
            round_param(3, 4, 0, 1, 2, 47),
            round_param(2, 3, 4, 0, 1, 48),
            round_param(1, 2, 3, 4, 0, 49),
            round_param(0, 1, 2, 3, 4, 50),
            round_param(4, 0, 1, 2, 3, 51),
            round_param(3, 4, 0, 1, 2, 52),
            round_param(2, 3, 4, 0, 1, 53),
            round_param(1, 2, 3, 4, 0, 54),
            round_param(0, 1, 2, 3, 4, 55),
            round_param(4, 0, 1, 2, 3, 56),
            round_param(3, 4, 0, 1, 2, 57),
            round_param(2, 3, 4, 0, 1, 58),
            round_param(1, 2, 3, 4, 0, 59),
        };
        inline for (round2) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0x8F1BBCDC +% s[r.i & 0xf] +% ((v[r.b] & v[r.c]) ^ (v[r.b] & v[r.d]) ^ (v[r.c] & v[r.d]));
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        const round3 = comptime [_]RoundParam{
            round_param(0, 1, 2, 3, 4, 60),
            round_param(4, 0, 1, 2, 3, 61),
            round_param(3, 4, 0, 1, 2, 62),
            round_param(2, 3, 4, 0, 1, 63),
            round_param(1, 2, 3, 4, 0, 64),
            round_param(0, 1, 2, 3, 4, 65),
            round_param(4, 0, 1, 2, 3, 66),
            round_param(3, 4, 0, 1, 2, 67),
            round_param(2, 3, 4, 0, 1, 68),
            round_param(1, 2, 3, 4, 0, 69),
            round_param(0, 1, 2, 3, 4, 70),
            round_param(4, 0, 1, 2, 3, 71),
            round_param(3, 4, 0, 1, 2, 72),
            round_param(2, 3, 4, 0, 1, 73),
            round_param(1, 2, 3, 4, 0, 74),
            round_param(0, 1, 2, 3, 4, 75),
            round_param(4, 0, 1, 2, 3, 76),
            round_param(3, 4, 0, 1, 2, 77),
            round_param(2, 3, 4, 0, 1, 78),
            round_param(1, 2, 3, 4, 0, 79),
        };
        inline for (round3) |r| {
            const t = s[(r.i - 3) & 0xf] ^ s[(r.i - 8) & 0xf] ^ s[(r.i - 14) & 0xf] ^ s[(r.i - 16) & 0xf];
            s[r.i & 0xf] = math.rotl(u32, t, @as(u32, 1));

            v[r.e] = v[r.e] +% math.rotl(u32, v[r.a], @as(u32, 5)) +% 0xCA62C1D6 +% s[r.i & 0xf] +% (v[r.b] ^ v[r.c] ^ v[r.d]);
            v[r.b] = math.rotl(u32, v[r.b], @as(u32, 30));
        }

        d.s[0] +%= v[0];
        d.s[1] +%= v[1];
        d.s[2] +%= v[2];
        d.s[3] +%= v[3];
        d.s[4] +%= v[4];
    }

    pub const Error = error{};
    pub const Writer = std.io.Writer(*Self, Error, write);

    fn write(self: *Self, bytes: []const u8) Error!usize {
        self.update(bytes);
        return bytes.len;
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }
};

const htest = @import("test.zig");

test "sha1 single" {
    try htest.assert_equal_hash(Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
    try htest.assert_equal_hash(Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d", "abc");
    try htest.assert_equal_hash(Sha1, "a49b2446a02c645bf419f995b67091253a04a259", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}

test "sha1 streaming" {
    var h = Sha1.init(.{});
    var out: [20]u8 = undefined;

    h.final(&out);
    try htest.assert_equal("da39a3ee5e6b4b0d3255bfef95601890afd80709", out[0..]);

    h = Sha1.init(.{});
    h.update("abc");
    h.final(&out);
    try htest.assert_equal("a9993e364706816aba3e25717850c26c9cd0d89d", out[0..]);

    h = Sha1.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(&out);
    try htest.assert_equal("a9993e364706816aba3e25717850c26c9cd0d89d", out[0..]);
}

test "sha1 aligned final" {
    var block = [_]u8{0} ** Sha1.block_length;
    var out: [Sha1.digest_length]u8 = undefined;

    var h = Sha1.init(.{});
    h.update(&block);
    h.final(out[0..]);
}
