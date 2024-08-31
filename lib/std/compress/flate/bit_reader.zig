const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub fn bit_reader(comptime T: type, reader: anytype) BitReader(T, @TypeOf(reader)) {
    return BitReader(T, @TypeOf(reader)).init(reader);
}

pub fn BitReader64(comptime ReaderType: type) type {
    return BitReader(u64, ReaderType);
}

pub fn BitReader32(comptime ReaderType: type) type {
    return BitReader(u32, ReaderType);
}

/// Bit reader used during inflate (decompression). Has internal buffer of 64
/// bits which shifts right after bits are consumed. Uses forward_reader to fill
/// that internal buffer when needed.
///
/// read_f is the core function. Supports few different ways of getting bits
/// controlled by flags. In hot path we try to avoid checking whether we need to
/// fill buffer from forward_reader by calling fill in advance and read_f with
/// buffered flag set.
///
pub fn BitReader(comptime T: type, comptime ReaderType: type) type {
    assert(T == u32 or T == u64);
    const t_bytes: usize = @size_of(T);
    const Tshift = if (T == u64) u6 else u5;

    return struct {
        // Underlying reader used for filling internal bits buffer
        forward_reader: ReaderType = undefined,
        // Internal buffer of 64 bits
        bits: T = 0,
        // Number of bits in the buffer
        nbits: u32 = 0,

        const Self = @This();

        pub const Error = ReaderType.Error || error{EndOfStream};

        pub fn init(rdr: ReaderType) Self {
            var self = Self{ .forward_reader = rdr };
            self.fill(1) catch {};
            return self;
        }

        /// Try to have `nice` bits are available in buffer. Reads from
        /// forward reader if there is no `nice` bits in buffer. Returns error
        /// if end of forward stream is reached and internal buffer is empty.
        /// It will not error if less than `nice` bits are in buffer, only when
        /// all bits are exhausted. During inflate we usually know what is the
        /// maximum bits for the next step but usually that step will need less
        /// bits to decode. So `nice` is not hard limit, it will just try to have
        /// that number of bits available. If end of forward stream is reached
        /// it may be some extra zero bits in buffer.
        pub inline fn fill(self: *Self, nice: u6) !void {
            if (self.nbits >= nice and nice != 0) {
                return; // We have enought bits
            }
            // Read more bits from forward reader

            // Number of empty bytes in bits, round nbits to whole bytes.
            const empty_bytes =
                @as(u8, if (self.nbits & 0x7 == 0) t_bytes else t_bytes - 1) - // 8 for 8, 16, 24..., 7 otherwise
                (self.nbits >> 3); // 0 for 0-7, 1 for 8-16, ... same as / 8

            var buf: [t_bytes]u8 = [_]u8{0} ** t_bytes;
            const bytes_read = self.forward_reader.read_all(buf[0..empty_bytes]) catch 0;
            if (bytes_read > 0) {
                const u: T = std.mem.read_int(T, buf[0..t_bytes], .little);
                self.bits |= u << @as(Tshift, @int_cast(self.nbits));
                self.nbits += 8 * @as(u8, @int_cast(bytes_read));
                return;
            }

            if (self.nbits == 0)
                return error.EndOfStream;
        }

        /// Read exactly buf.len bytes into buf.
        pub fn read_all(self: *Self, buf: []u8) !void {
            assert(self.align_bits() == 0); // internal bits must be at byte boundary

            // First read from internal bits buffer.
            var n: usize = 0;
            while (self.nbits > 0 and n < buf.len) {
                buf[n] = try self.read_f(u8, flag.buffered);
                n += 1;
            }
            // Then use forward reader for all other bytes.
            try self.forward_reader.read_no_eof(buf[n..]);
        }

        pub const flag = struct {
            pub const peek: u3 = 0b001; // dont advance internal buffer, just get bits, leave them in buffer
            pub const buffered: u3 = 0b010; // assume that there is no need to fill, fill should be called before
            pub const reverse: u3 = 0b100; // bit reverse readed bits
        };

        /// Alias for read_f(U, 0).
        pub fn read(self: *Self, comptime U: type) !U {
            return self.read_f(U, 0);
        }

        /// Alias for read_f with flag.peak set.
        pub inline fn peek_f(self: *Self, comptime U: type, comptime how: u3) !U {
            return self.read_f(U, how | flag.peek);
        }

        /// Read with flags provided.
        pub fn read_f(self: *Self, comptime U: type, comptime how: u3) !U {
            if (U == T) {
                assert(how == 0);
                assert(self.align_bits() == 0);
                try self.fill(@bitSizeOf(T));
                if (self.nbits != @bitSizeOf(T)) return error.EndOfStream;
                const v = self.bits;
                self.nbits = 0;
                self.bits = 0;
                return v;
            }
            const n: Tshift = @bitSizeOf(U);
            switch (how) {
                0 => { // `normal` read
                    try self.fill(n); // ensure that there are n bits in the buffer
                    const u: U = @truncate(self.bits); // get n bits
                    try self.shift(n); // advance buffer for n
                    return u;
                },
                (flag.peek) => { // no shift, leave bits in the buffer
                    try self.fill(n);
                    return @truncate(self.bits);
                },
                flag.buffered => { // no fill, assume that buffer has enought bits
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return u;
                },
                (flag.reverse) => { // same as 0 with bit reverse
                    try self.fill(n);
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bit_reverse(u);
                },
                (flag.peek | flag.reverse) => {
                    try self.fill(n);
                    return @bit_reverse(@as(U, @truncate(self.bits)));
                },
                (flag.buffered | flag.reverse) => {
                    const u: U = @truncate(self.bits);
                    try self.shift(n);
                    return @bit_reverse(u);
                },
                (flag.peek | flag.buffered) => {
                    return @truncate(self.bits);
                },
                (flag.peek | flag.buffered | flag.reverse) => {
                    return @bit_reverse(@as(U, @truncate(self.bits)));
                },
            }
        }

        /// Read n number of bits.
        /// Only buffered flag can be used in how.
        pub fn read_n(self: *Self, n: u4, comptime how: u3) !u16 {
            switch (how) {
                0 => {
                    try self.fill(n);
                },
                flag.buffered => {},
                else => unreachable,
            }
            const mask: u16 = (@as(u16, 1) << n) - 1;
            const u: u16 = @as(u16, @truncate(self.bits)) & mask;
            try self.shift(n);
            return u;
        }

        /// Advance buffer for n bits.
        pub fn shift(self: *Self, n: Tshift) !void {
            if (n > self.nbits) return error.EndOfStream;
            self.bits >>= n;
            self.nbits -= n;
        }

        /// Skip n bytes.
        pub fn skip_bytes(self: *Self, n: u16) !void {
            for (0..n) |_| {
                try self.fill(8);
                try self.shift(8);
            }
        }

        // Number of bits to align stream to the byte boundary.
        fn align_bits(self: *Self) u3 {
            return @int_cast(self.nbits & 0x7);
        }

        /// Align stream to the byte boundary.
        pub fn align_to_byte(self: *Self) void {
            const ab = self.align_bits();
            if (ab > 0) self.shift(ab) catch unreachable;
        }

        /// Skip zero terminated string.
        pub fn skip_string_z(self: *Self) !void {
            while (true) {
                if (try self.read_f(u8, 0) == 0) break;
            }
        }

        /// Read deflate fixed fixed code.
        /// Reads first 7 bits, and then mybe 1 or 2 more to get full 7,8 or 9 bit code.
        /// ref: https://datatracker.ietf.org/doc/html/rfc1951#page-12
        ///         Lit Value    Bits        Codes
        ///          ---------    ----        -----
        ///            0 - 143     8          00110000 through
        ///                                   10111111
        ///          144 - 255     9          110010000 through
        ///                                   111111111
        ///          256 - 279     7          0000000 through
        ///                                   0010111
        ///          280 - 287     8          11000000 through
        ///                                   11000111
        pub fn read_fixed_code(self: *Self) !u16 {
            try self.fill(7 + 2);
            const code7 = try self.read_f(u7, flag.buffered | flag.reverse);
            if (code7 <= 0b0010_111) { // 7 bits, 256-279, codes 0000_000 - 0010_111
                return @as(u16, code7) + 256;
            } else if (code7 <= 0b1011_111) { // 8 bits, 0-143, codes 0011_0000 through 1011_1111
                return (@as(u16, code7) << 1) + @as(u16, try self.read_f(u1, flag.buffered)) - 0b0011_0000;
            } else if (code7 <= 0b1100_011) { // 8 bit, 280-287, codes 1100_0000 - 1100_0111
                return (@as(u16, code7 - 0b1100000) << 1) + try self.read_f(u1, flag.buffered) + 280;
            } else { // 9 bit, 144-255, codes 1_1001_0000 - 1_1111_1111
                return (@as(u16, code7 - 0b1100_100) << 2) + @as(u16, try self.read_f(u2, flag.buffered | flag.reverse)) + 144;
            }
        }
    };
}

test "read_f" {
    var fbs = std.io.fixed_buffer_stream(&[_]u8{ 0xf3, 0x48, 0xcd, 0xc9, 0x00, 0x00 });
    var br = bit_reader(u64, fbs.reader());
    const F = BitReader64(@TypeOf(fbs.reader())).flag;

    try testing.expect_equal(@as(u8, 48), br.nbits);
    try testing.expect_equal(@as(u64, 0xc9cd48f3), br.bits);

    try testing.expect(try br.read_f(u1, 0) == 0b0000_0001);
    try testing.expect(try br.read_f(u2, 0) == 0b0000_0001);
    try testing.expect_equal(@as(u8, 48 - 3), br.nbits);
    try testing.expect_equal(@as(u3, 5), br.align_bits());

    try testing.expect(try br.read_f(u8, F.peek) == 0b0001_1110);
    try testing.expect(try br.read_f(u9, F.peek) == 0b1_0001_1110);
    try br.shift(9);
    try testing.expect_equal(@as(u8, 36), br.nbits);
    try testing.expect_equal(@as(u3, 4), br.align_bits());

    try testing.expect(try br.read_f(u4, 0) == 0b0100);
    try testing.expect_equal(@as(u8, 32), br.nbits);
    try testing.expect_equal(@as(u3, 0), br.align_bits());

    try br.shift(1);
    try testing.expect_equal(@as(u3, 7), br.align_bits());
    try br.shift(1);
    try testing.expect_equal(@as(u3, 6), br.align_bits());
    br.align_to_byte();
    try testing.expect_equal(@as(u3, 0), br.align_bits());

    try testing.expect_equal(@as(u64, 0xc9), br.bits);
    try testing.expect_equal(@as(u16, 0x9), try br.read_n(4, 0));
    try testing.expect_equal(@as(u16, 0xc), try br.read_n(4, 0));
}

test "read block type 1 data" {
    inline for ([_]type{ u64, u32 }) |T| {
        const data = [_]u8{
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, // deflate data block type 1
            0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
            0x0c, 0x01, 0x02, 0x03, //
            0xaa, 0xbb, 0xcc, 0xdd,
        };
        var fbs = std.io.fixed_buffer_stream(&data);
        var br = bit_reader(T, fbs.reader());
        const F = BitReader(T, @TypeOf(fbs.reader())).flag;

        try testing.expect_equal(@as(u1, 1), try br.read_f(u1, 0)); // bfinal
        try testing.expect_equal(@as(u2, 1), try br.read_f(u2, 0)); // block_type

        for ("Hello world\n") |c| {
            try testing.expect_equal(@as(u8, c), try br.read_f(u8, F.reverse) - 0x30);
        }
        try testing.expect_equal(@as(u7, 0), try br.read_f(u7, 0)); // end of block
        br.align_to_byte();
        try testing.expect_equal(@as(u32, 0x0302010c), try br.read_f(u32, 0));
        try testing.expect_equal(@as(u16, 0xbbaa), try br.read_f(u16, 0));
        try testing.expect_equal(@as(u16, 0xddcc), try br.read_f(u16, 0));
    }
}

test "shift/fill" {
    const data = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    var fbs = std.io.fixed_buffer_stream(&data);
    var br = bit_reader(u64, fbs.reader());

    try testing.expect_equal(@as(u64, 0x08_07_06_05_04_03_02_01), br.bits);
    try br.shift(8);
    try testing.expect_equal(@as(u64, 0x00_08_07_06_05_04_03_02), br.bits);
    try br.fill(60); // fill with 1 byte
    try testing.expect_equal(@as(u64, 0x01_08_07_06_05_04_03_02), br.bits);
    try br.shift(8 * 4 + 4);
    try testing.expect_equal(@as(u64, 0x00_00_00_00_00_10_80_70), br.bits);

    try br.fill(60); // fill with 4 bytes (shift by 4)
    try testing.expect_equal(@as(u64, 0x00_50_40_30_20_10_80_70), br.bits);
    try testing.expect_equal(@as(u8, 8 * 7 + 4), br.nbits);

    try br.shift(@int_cast(br.nbits)); // clear buffer
    try br.fill(8); // refill with the rest of the bytes
    try testing.expect_equal(@as(u64, 0x00_00_00_00_00_08_07_06), br.bits);
}

test "read_all" {
    inline for ([_]type{ u64, u32 }) |T| {
        const data = [_]u8{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        };
        var fbs = std.io.fixed_buffer_stream(&data);
        var br = bit_reader(T, fbs.reader());

        switch (T) {
            u64 => try testing.expect_equal(@as(u64, 0x08_07_06_05_04_03_02_01), br.bits),
            u32 => try testing.expect_equal(@as(u32, 0x04_03_02_01), br.bits),
            else => unreachable,
        }

        var out: [16]u8 = undefined;
        try br.read_all(out[0..]);
        try testing.expect(br.nbits == 0);
        try testing.expect(br.bits == 0);

        try testing.expect_equal_slices(u8, data[0..16], &out);
    }
}

test "read_fixed_code" {
    inline for ([_]type{ u64, u32 }) |T| {
        const fixed_codes = @import("huffman_encoder.zig").fixed_codes;

        var fbs = std.io.fixed_buffer_stream(&fixed_codes);
        var rdr = bit_reader(T, fbs.reader());

        for (0..286) |c| {
            try testing.expect_equal(c, try rdr.read_fixed_code());
        }
        try testing.expect(rdr.nbits == 0);
    }
}

test "u32 leaves no bits on u32 reads" {
    const data = [_]u8{
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    var fbs = std.io.fixed_buffer_stream(&data);
    var br = bit_reader(u32, fbs.reader());

    _ = try br.read(u3);
    try testing.expect_equal(29, br.nbits);
    br.align_to_byte();
    try testing.expect_equal(24, br.nbits);
    try testing.expect_equal(0x04_03_02_01, try br.read(u32));
    try testing.expect_equal(0, br.nbits);
    try testing.expect_equal(0x08_07_06_05, try br.read(u32));
    try testing.expect_equal(0, br.nbits);

    _ = try br.read(u9);
    try testing.expect_equal(23, br.nbits);
    br.align_to_byte();
    try testing.expect_equal(16, br.nbits);
    try testing.expect_equal(0x0e_0d_0c_0b, try br.read(u32));
    try testing.expect_equal(0, br.nbits);
}

test "u64 need fill after align_to_byte" {
    const data = [_]u8{
        0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    // without fill
    var fbs = std.io.fixed_buffer_stream(&data);
    var br = bit_reader(u64, fbs.reader());
    _ = try br.read(u23);
    try testing.expect_equal(41, br.nbits);
    br.align_to_byte();
    try testing.expect_equal(40, br.nbits);
    try testing.expect_equal(0x06_05_04_03, try br.read(u32));
    try testing.expect_equal(8, br.nbits);
    try testing.expect_equal(0x0a_09_08_07, try br.read(u32));
    try testing.expect_equal(32, br.nbits);

    // fill after align ensures all bits filled
    fbs.reset();
    br = bit_reader(u64, fbs.reader());
    _ = try br.read(u23);
    try testing.expect_equal(41, br.nbits);
    br.align_to_byte();
    try br.fill(0);
    try testing.expect_equal(64, br.nbits);
    try testing.expect_equal(0x06_05_04_03, try br.read(u32));
    try testing.expect_equal(32, br.nbits);
    try testing.expect_equal(0x0a_09_08_07, try br.read(u32));
    try testing.expect_equal(0, br.nbits);
}
