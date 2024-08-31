const std = @import("std");
const Allocator = std.mem.Allocator;

const ParseOptions = @import("static.zig").ParseOptions;
const inner_parse = @import("static.zig").inner_parse;
const inner_parse_from_value = @import("static.zig").inner_parse_from_value;
const Value = @import("dynamic.zig").Value;

/// A thin wrapper around `std.StringArrayHashMapUnmanaged` that implements
/// `json_parse`, `json_parse_from_value`, and `json_stringify`.
/// This is useful when your JSON schema has an object with arbitrary data keys
/// instead of comptime-known struct field names.
pub fn ArrayHashMap(comptime T: type) type {
    return struct {
        map: std.StringArrayHashMapUnmanaged(T) = .{},

        pub fn deinit(self: *@This(), allocator: Allocator) void {
            self.map.deinit(allocator);
        }

        pub fn json_parse(allocator: Allocator, source: anytype, options: ParseOptions) !@This() {
            var map = std.StringArrayHashMapUnmanaged(T){};
            errdefer map.deinit(allocator);

            if (.object_begin != try source.next()) return error.UnexpectedToken;
            while (true) {
                const token = try source.next_alloc(allocator, options.allocate.?);
                switch (token) {
                    inline .string, .allocated_string => |k| {
                        const gop = try map.get_or_put(allocator, k);
                        if (gop.found_existing) {
                            switch (options.duplicate_field_behavior) {
                                .use_first => {
                                    // Parse and ignore the redundant value.
                                    // We don't want to skip the value, because we want type checking.
                                    _ = try inner_parse(T, allocator, source, options);
                                    continue;
                                },
                                .@"error" => return error.DuplicateField,
                                .use_last => {},
                            }
                        }
                        gop.value_ptr.* = try inner_parse(T, allocator, source, options);
                    },
                    .object_end => break,
                    else => unreachable,
                }
            }
            return .{ .map = map };
        }

        pub fn json_parse_from_value(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            if (source != .object) return error.UnexpectedToken;

            var map = std.StringArrayHashMapUnmanaged(T){};
            errdefer map.deinit(allocator);

            var it = source.object.iterator();
            while (it.next()) |kv| {
                try map.put(allocator, kv.key_ptr.*, try inner_parse_from_value(T, allocator, kv.value_ptr.*, options));
            }
            return .{ .map = map };
        }

        pub fn json_stringify(self: @This(), jws: anytype) !void {
            try jws.begin_object();
            var it = self.map.iterator();
            while (it.next()) |kv| {
                try jws.object_field(kv.key_ptr.*);
                try jws.write(kv.value_ptr.*);
            }
            try jws.end_object();
        }
    };
}

test {
    _ = @import("hashmap_test.zig");
}
