//! 64K buffer of uncompressed data created in inflate (decompression). Has enough
//! history to support writing match<length, distance>; copying length of bytes
//! from the position distance backward from current.
//!
//! Reads can return less than available bytes if they are spread across
//! different circles. So reads should repeat until get required number of bytes
//! or until returned slice is zero length.
//!
//! Note on deflate limits:
//!  * non-compressible block is limited to 65,535 bytes.
//!  * backward pointer is limited in distance to 32K bytes and in length to 258 bytes.
//!
//! Whole non-compressed block can be written without overlap. We always have
//! history of up to 64K, more then 32K needed.
//!
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const consts = @import("consts.zig").match;

const mask = 0xffff; // 64K - 1
const buffer_len = mask + 1; // 64K buffer

const Self = @This();

buffer: [buffer_len]u8 = undefined,
wp: usize = 0, // write position
rp: usize = 0, // read position

fn write_all(self: *Self, buf: []const u8) void {
    for (buf) |c| self.write(c);
}

/// Write literal.
pub fn write(self: *Self, b: u8) void {
    assert(self.wp - self.rp < mask);
    self.buffer[self.wp & mask] = b;
    self.wp += 1;
}

/// Write match (back-reference to the same data slice) starting at `distance`
/// back from current write position, and `length` of bytes.
pub fn write_match(self: *Self, length: u16, distance: u16) !void {
    if (self.wp < distance or
        length < consts.base_length or length > consts.max_length or
        distance < consts.min_distance or distance > consts.max_distance)
    {
        return error.InvalidMatch;
    }
    assert(self.wp - self.rp < mask);

    var from: usize = self.wp - distance & mask;
    const from_end: usize = from + length;
    var to: usize = self.wp & mask;
    const to_end: usize = to + length;

    self.wp += length;

    // Fast path using memcpy
    if (from_end < buffer_len and to_end < buffer_len) // start and end at the same circle
    {
        var cur_len = distance;
        var remaining_len = length;
        while (cur_len < remaining_len) {
            @memcpy(self.buffer[to..][0..cur_len], self.buffer[from..][0..cur_len]);
            to += cur_len;
            remaining_len -= cur_len;
            cur_len = cur_len * 2;
        }
        @memcpy(self.buffer[to..][0..remaining_len], self.buffer[from..][0..remaining_len]);
        return;
    }

    // Slow byte by byte
    while (to < to_end) {
        self.buffer[to & mask] = self.buffer[from & mask];
        to += 1;
        from += 1;
    }
}

/// Returns writable part of the internal buffer of size `n` at most. Advances
/// write pointer, assumes that returned buffer will be filled with data.
pub fn get_writable(self: *Self, n: usize) []u8 {
    const wp = self.wp & mask;
    const len = @min(n, buffer_len - wp);
    self.wp += len;
    return self.buffer[wp .. wp + len];
}

/// Read available data. Can return part of the available data if it is
/// spread across two circles. So read until this returns zero length.
pub fn read(self: *Self) []const u8 {
    return self.read_at_most(buffer_len);
}

/// Read part of available data. Can return less than max even if there are
/// more than max decoded data.
pub fn read_at_most(self: *Self, limit: usize) []const u8 {
    const rb = self.read_block(if (limit == 0) buffer_len else limit);
    defer self.rp += rb.len;
    return self.buffer[rb.head..rb.tail];
}

const ReadBlock = struct {
    head: usize,
    tail: usize,
    len: usize,
};

/// Returns position of continous read block data.
fn read_block(self: *Self, max: usize) ReadBlock {
    const r = self.rp & mask;
    const w = self.wp & mask;
    const n = @min(
        max,
        if (w >= r) w - r else buffer_len - r,
    );
    return .{
        .head = r,
        .tail = r + n,
        .len = n,
    };
}

/// Number of free bytes for write.
pub fn free(self: *Self) usize {
    return buffer_len - (self.wp - self.rp);
}

/// Full if largest match can't fit. 258 is largest match length. That much
/// bytes can be produced in single decode step.
pub fn full(self: *Self) bool {
    return self.free() < 258 + 1;
}

// example from: https://youtu.be/SJPvNi4HrWQ?t=3558
test write_match {
    var cb: Self = .{};

    cb.write_all("a salad; ");
    try cb.write_match(5, 9);
    try cb.write_match(3, 3);

    try testing.expect_equal_strings("a salad; a salsal", cb.read());
}

test "write_match overlap" {
    var cb: Self = .{};

    cb.write_all("a b c ");
    try cb.write_match(8, 4);
    cb.write('d');

    try testing.expect_equal_strings("a b c b c b c d", cb.read());
}

test read_at_most {
    var cb: Self = .{};

    cb.write_all("0123456789");
    try cb.write_match(50, 10);

    try testing.expect_equal_strings("0123456789" ** 6, cb.buffer[cb.rp..cb.wp]);
    for (0..6) |i| {
        try testing.expect_equal(i * 10, cb.rp);
        try testing.expect_equal_strings("0123456789", cb.read_at_most(10));
    }
    try testing.expect_equal_strings("", cb.read_at_most(10));
    try testing.expect_equal_strings("", cb.read());
}

test Self {
    var cb: Self = .{};

    const data = "0123456789abcdef" ** (1024 / 16);
    cb.write_all(data);
    try testing.expect_equal(@as(usize, 0), cb.rp);
    try testing.expect_equal(@as(usize, 1024), cb.wp);
    try testing.expect_equal(@as(usize, 1024 * 63), cb.free());

    for (0..62 * 4) |_|
        try cb.write_match(256, 1024); // write 62K

    try testing.expect_equal(@as(usize, 0), cb.rp);
    try testing.expect_equal(@as(usize, 63 * 1024), cb.wp);
    try testing.expect_equal(@as(usize, 1024), cb.free());

    cb.write_all(data[0..200]);
    _ = cb.read_at_most(1024); // make some space
    cb.write_all(data); // overflows write position
    try testing.expect_equal(@as(usize, 200 + 65536), cb.wp);
    try testing.expect_equal(@as(usize, 1024), cb.rp);
    try testing.expect_equal(@as(usize, 1024 - 200), cb.free());

    const rb = cb.read_block(Self.buffer_len);
    try testing.expect_equal(@as(usize, 65536 - 1024), rb.len);
    try testing.expect_equal(@as(usize, 1024), rb.head);
    try testing.expect_equal(@as(usize, 65536), rb.tail);

    try testing.expect_equal(@as(usize, 65536 - 1024), cb.read().len); // read to the end of the buffer
    try testing.expect_equal(@as(usize, 200 + 65536), cb.wp);
    try testing.expect_equal(@as(usize, 65536), cb.rp);
    try testing.expect_equal(@as(usize, 65536 - 200), cb.free());

    try testing.expect_equal(@as(usize, 200), cb.read().len); // read the rest
}

test "write overlap" {
    var cb: Self = .{};
    cb.wp = cb.buffer.len - 15;
    cb.rp = cb.wp;

    cb.write_all("0123456789");
    cb.write_all("abcdefghij");

    try testing.expect_equal(cb.buffer.len + 5, cb.wp);
    try testing.expect_equal(cb.buffer.len - 15, cb.rp);

    try testing.expect_equal_strings("0123456789abcde", cb.read());
    try testing.expect_equal_strings("fghij", cb.read());

    try testing.expect(cb.wp == cb.rp);
}

test "write_match/read overlap" {
    var cb: Self = .{};
    cb.wp = cb.buffer.len - 15;
    cb.rp = cb.wp;

    cb.write_all("0123456789");
    try cb.write_match(15, 5);

    try testing.expect_equal_strings("012345678956789", cb.read());
    try testing.expect_equal_strings("5678956789", cb.read());

    try cb.write_match(20, 25);
    try testing.expect_equal_strings("01234567895678956789", cb.read());
}
