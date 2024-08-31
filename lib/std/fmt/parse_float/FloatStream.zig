//! A wrapper over a byte-slice, providing useful methods for parsing string floating point values.

const std = @import("std");
const FloatStream = @This();
const common = @import("common.zig");

slice: []const u8,
offset: usize,
underscore_count: usize,

pub fn init(s: []const u8) FloatStream {
    return .{ .slice = s, .offset = 0, .underscore_count = 0 };
}

// Returns the offset from the start *excluding* any underscores that were found.
pub fn offset_true(self: FloatStream) usize {
    return self.offset - self.underscore_count;
}

pub fn reset(self: *FloatStream) void {
    self.offset = 0;
    self.underscore_count = 0;
}

pub fn len(self: FloatStream) usize {
    if (self.offset > self.slice.len) {
        return 0;
    }
    return self.slice.len - self.offset;
}

pub fn has_len(self: FloatStream, n: usize) bool {
    return self.offset + n <= self.slice.len;
}

pub fn first_unchecked(self: FloatStream) u8 {
    return self.slice[self.offset];
}

pub fn first(self: FloatStream) ?u8 {
    return if (self.has_len(1))
        return self.first_unchecked()
    else
        null;
}

pub fn is_empty(self: FloatStream) bool {
    return !self.has_len(1);
}

pub fn first_is(self: FloatStream, c: u8) bool {
    if (self.first()) |ok| {
        return ok == c;
    }
    return false;
}

pub fn first_is_lower(self: FloatStream, c: u8) bool {
    if (self.first()) |ok| {
        return ok | 0x20 == c;
    }
    return false;
}

pub fn first_is2(self: FloatStream, c1: u8, c2: u8) bool {
    if (self.first()) |ok| {
        return ok == c1 or ok == c2;
    }
    return false;
}

pub fn first_is3(self: FloatStream, c1: u8, c2: u8, c3: u8) bool {
    if (self.first()) |ok| {
        return ok == c1 or ok == c2 or ok == c3;
    }
    return false;
}

pub fn first_is_digit(self: FloatStream, comptime base: u8) bool {
    comptime std.debug.assert(base == 10 or base == 16);

    if (self.first()) |ok| {
        return common.is_digit(ok, base);
    }
    return false;
}

pub fn advance(self: *FloatStream, n: usize) void {
    self.offset += n;
}

pub fn skip_chars(self: *FloatStream, c: u8) void {
    while (self.first_is(c)) : (self.advance(1)) {}
}

pub fn skip_chars2(self: *FloatStream, c1: u8, c2: u8) void {
    while (self.first_is2(c1, c2)) : (self.advance(1)) {}
}

pub fn read_u64_unchecked(self: FloatStream) u64 {
    return std.mem.read_int(u64, self.slice[self.offset..][0..8], .little);
}

pub fn read_u64(self: FloatStream) ?u64 {
    if (self.has_len(8)) {
        return self.read_u64_unchecked();
    }
    return null;
}

pub fn at_unchecked(self: *FloatStream, i: usize) u8 {
    return self.slice[self.offset + i];
}

pub fn scan_digit(self: *FloatStream, comptime base: u8) ?u8 {
    comptime std.debug.assert(base == 10 or base == 16);

    retry: while (true) {
        if (self.first()) |ok| {
            if ('0' <= ok and ok <= '9') {
                self.advance(1);
                return ok - '0';
            } else if (base == 16 and 'a' <= ok and ok <= 'f') {
                self.advance(1);
                return ok - 'a' + 10;
            } else if (base == 16 and 'A' <= ok and ok <= 'F') {
                self.advance(1);
                return ok - 'A' + 10;
            } else if (ok == '_') {
                self.advance(1);
                self.underscore_count += 1;
                continue :retry;
            }
        }
        return null;
    }
}
