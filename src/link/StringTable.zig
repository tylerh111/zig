buffer: std.ArrayListUnmanaged(u8) = .{},
table: std.HashMapUnmanaged(u32, void, StringIndexContext, std.hash_map.default_max_load_percentage) = .{},

pub fn deinit(self: *Self, gpa: Allocator) void {
    self.buffer.deinit(gpa);
    self.table.deinit(gpa);
}

pub fn insert(self: *Self, gpa: Allocator, string: []const u8) !u32 {
    const gop = try self.table.get_or_put_context_adapted(gpa, @as([]const u8, string), StringIndexAdapter{
        .bytes = &self.buffer,
    }, StringIndexContext{
        .bytes = &self.buffer,
    });
    if (gop.found_existing) return gop.key_ptr.*;

    try self.buffer.ensure_unused_capacity(gpa, string.len + 1);
    const new_off = @as(u32, @int_cast(self.buffer.items.len));

    self.buffer.append_slice_assume_capacity(string);
    self.buffer.append_assume_capacity(0);

    gop.key_ptr.* = new_off;

    return new_off;
}

pub fn get_offset(self: *Self, string: []const u8) ?u32 {
    return self.table.get_key_adapted(string, StringIndexAdapter{
        .bytes = &self.buffer,
    });
}

pub fn get(self: Self, off: u32) ?[:0]const u8 {
    if (off >= self.buffer.items.len) return null;
    return mem.slice_to(@as([*:0]const u8, @ptr_cast(self.buffer.items.ptr + off)), 0);
}

pub fn get_assume_exists(self: Self, off: u32) [:0]const u8 {
    return self.get(off) orelse unreachable;
}

const std = @import("std");
const mem = std.mem;

const Allocator = mem.Allocator;
const Self = @This();
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;
