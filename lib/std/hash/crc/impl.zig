// There is a generic CRC implementation "Crc()" which can be paramterized via
// the Algorithm struct for a plethora of uses.
//
// The primary interface for all of the standard CRC algorithms is the
// generated file "crc.zig", which uses the implementation code here to define
// many standard CRCs.

const std = @import("std");

pub fn Algorithm(comptime W: type) type {
    return struct {
        polynomial: W,
        initial: W,
        reflect_input: bool,
        reflect_output: bool,
        xor_output: W,
    };
}

pub fn Crc(comptime W: type, comptime algorithm: Algorithm(W)) type {
    return struct {
        const Self = @This();
        const I = if (@bitSizeOf(W) < 8) u8 else W;
        const lookup_table = blk: {
            @setEvalBranchQuota(2500);

            const poly = if (algorithm.reflect_input)
                @bit_reverse(@as(I, algorithm.polynomial)) >> (@bitSizeOf(I) - @bitSizeOf(W))
            else
                @as(I, algorithm.polynomial) << (@bitSizeOf(I) - @bitSizeOf(W));

            var table: [256]I = undefined;
            for (&table, 0..) |*e, i| {
                var crc: I = i;
                if (algorithm.reflect_input) {
                    var j: usize = 0;
                    while (j < 8) : (j += 1) {
                        crc = (crc >> 1) ^ ((crc & 1) * poly);
                    }
                } else {
                    crc <<= @bitSizeOf(I) - 8;
                    var j: usize = 0;
                    while (j < 8) : (j += 1) {
                        crc = (crc << 1) ^ (((crc >> (@bitSizeOf(I) - 1)) & 1) * poly);
                    }
                }
                e.* = crc;
            }
            break :blk table;
        };

        crc: I,

        pub fn init() Self {
            const initial = if (algorithm.reflect_input)
                @bit_reverse(@as(I, algorithm.initial)) >> (@bitSizeOf(I) - @bitSizeOf(W))
            else
                @as(I, algorithm.initial) << (@bitSizeOf(I) - @bitSizeOf(W));
            return Self{ .crc = initial };
        }

        inline fn table_entry(index: I) I {
            return lookup_table[@as(u8, @int_cast(index & 0xFF))];
        }

        pub fn update(self: *Self, bytes: []const u8) void {
            var i: usize = 0;
            if (@bitSizeOf(I) <= 8) {
                while (i < bytes.len) : (i += 1) {
                    self.crc = table_entry(self.crc ^ bytes[i]);
                }
            } else if (algorithm.reflect_input) {
                while (i < bytes.len) : (i += 1) {
                    const table_index = self.crc ^ bytes[i];
                    self.crc = table_entry(table_index) ^ (self.crc >> 8);
                }
            } else {
                while (i < bytes.len) : (i += 1) {
                    const table_index = (self.crc >> (@bitSizeOf(I) - 8)) ^ bytes[i];
                    self.crc = table_entry(table_index) ^ (self.crc << 8);
                }
            }
        }

        pub fn final(self: Self) W {
            var c = self.crc;
            if (algorithm.reflect_input != algorithm.reflect_output) {
                c = @bit_reverse(c);
            }
            if (!algorithm.reflect_output) {
                c >>= @bitSizeOf(I) - @bitSizeOf(W);
            }
            return @as(W, @int_cast(c ^ algorithm.xor_output));
        }

        pub fn hash(bytes: []const u8) W {
            var c = Self.init();
            c.update(bytes);
            return c.final();
        }
    };
}

pub const Polynomial = enum(u32) {
    IEEE = @compile_error("use Crc with algorithm .Crc32IsoHdlc"),
    Castagnoli = @compile_error("use Crc with algorithm .Crc32Iscsi"),
    Koopman = @compile_error("use Crc with algorithm .Crc32Koopman"),
    _,
};

pub const Crc32WithPoly = @compile_error("use Crc instead");
pub const Crc32SmallWithPoly = @compile_error("use Crc instead");
