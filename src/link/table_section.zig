pub fn TableSection(comptime Entry: type) type {
    return struct {
        entries: std.ArrayListUnmanaged(Entry) = .{},
        free_list: std.ArrayListUnmanaged(Index) = .{},
        lookup: std.AutoHashMapUnmanaged(Entry, Index) = .{},

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.entries.deinit(allocator);
            self.free_list.deinit(allocator);
            self.lookup.deinit(allocator);
        }

        pub fn allocate_entry(self: *Self, allocator: Allocator, entry: Entry) Allocator.Error!Index {
            try self.entries.ensure_unused_capacity(allocator, 1);
            const index = blk: {
                if (self.free_list.pop_or_null()) |index| {
                    log.debug("  (reusing entry index {d})", .{index});
                    break :blk index;
                } else {
                    log.debug("  (allocating entry at index {d})", .{self.entries.items.len});
                    const index = @as(u32, @int_cast(self.entries.items.len));
                    _ = self.entries.add_one_assume_capacity();
                    break :blk index;
                }
            };
            self.entries.items[index] = entry;
            try self.lookup.put_no_clobber(allocator, entry, index);
            return index;
        }

        pub fn free_entry(self: *Self, allocator: Allocator, entry: Entry) void {
            const index = self.lookup.get(entry) orelse return;
            self.free_list.append(allocator, index) catch {};
            self.entries.items[index] = undefined;
            _ = self.lookup.remove(entry);
        }

        pub fn count(self: Self) usize {
            return self.entries.items.len;
        }

        pub fn format(
            self: Self,
            comptime unused_format_string: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = options;
            comptime assert(unused_format_string.len == 0);
            try writer.write_all("TableSection:\n");
            for (self.entries.items, 0..) |entry, i| {
                try writer.print("  {d} => {}\n", .{ i, entry });
            }
        }

        const Self = @This();
        pub const Index = u32;
    };
}

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.link);

const Allocator = std.mem.Allocator;
