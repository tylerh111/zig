//! Effectively a stack of u1 values implemented using ArrayList(u8).

const BitStack = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

bytes: std.ArrayList(u8),
bit_len: usize = 0,

pub fn init(allocator: Allocator) @This() {
    return .{
        .bytes = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(self: *@This()) void {
    self.bytes.deinit();
    self.* = undefined;
}

pub fn ensure_total_capacity(self: *@This(), bit_capcity: usize) Allocator.Error!void {
    const byte_capacity = (bit_capcity + 7) >> 3;
    try self.bytes.ensure_total_capacity(byte_capacity);
}

pub fn push(self: *@This(), b: u1) Allocator.Error!void {
    const byte_index = self.bit_len >> 3;
    if (self.bytes.items.len <= byte_index) {
        try self.bytes.append(0);
    }

    push_with_state_assume_capacity(self.bytes.items, &self.bit_len, b);
}

pub fn peek(self: *const @This()) u1 {
    return peek_with_state(self.bytes.items, self.bit_len);
}

pub fn pop(self: *@This()) u1 {
    return pop_with_state(self.bytes.items, &self.bit_len);
}

/// Standalone function for working with a fixed-size buffer.
pub fn push_with_state_assume_capacity(buf: []u8, bit_len: *usize, b: u1) void {
    const byte_index = bit_len.* >> 3;
    const bit_index = @as(u3, @int_cast(bit_len.* & 7));

    buf[byte_index] &= ~(@as(u8, 1) << bit_index);
    buf[byte_index] |= @as(u8, b) << bit_index;

    bit_len.* += 1;
}

/// Standalone function for working with a fixed-size buffer.
pub fn peek_with_state(buf: []const u8, bit_len: usize) u1 {
    const byte_index = (bit_len - 1) >> 3;
    const bit_index = @as(u3, @int_cast((bit_len - 1) & 7));
    return @as(u1, @int_cast((buf[byte_index] >> bit_index) & 1));
}

/// Standalone function for working with a fixed-size buffer.
pub fn pop_with_state(buf: []const u8, bit_len: *usize) u1 {
    const b = peek_with_state(buf, bit_len.*);
    bit_len.* -= 1;
    return b;
}

const testing = std.testing;
test BitStack {
    var stack = BitStack.init(testing.allocator);
    defer stack.deinit();

    try stack.push(1);
    try stack.push(0);
    try stack.push(0);
    try stack.push(1);

    try testing.expect_equal(@as(u1, 1), stack.peek());
    try testing.expect_equal(@as(u1, 1), stack.pop());
    try testing.expect_equal(@as(u1, 0), stack.peek());
    try testing.expect_equal(@as(u1, 0), stack.pop());
    try testing.expect_equal(@as(u1, 0), stack.pop());
    try testing.expect_equal(@as(u1, 1), stack.pop());
}
