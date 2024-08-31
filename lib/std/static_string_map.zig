const std = @import("std.zig");
const mem = std.mem;

/// Static string map optimized for small sets of disparate string keys.
/// Works by separating the keys by length at initialization and only checking
/// strings of equal length at runtime.
pub fn StaticStringMap(comptime V: type) type {
    return StaticStringMapWithEql(V, default_eql);
}

/// Like `std.mem.eql`, but takes advantage of the fact that the lengths
/// of `a` and `b` are known to be equal.
pub fn default_eql(a: []const u8, b: []const u8) bool {
    if (a.ptr == b.ptr) return true;
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

/// Like `std.ascii.eql_ignore_case` but takes advantage of the fact that
/// the lengths of `a` and `b` are known to be equal.
pub fn eql_ascii_ignore_case(a: []const u8, b: []const u8) bool {
    if (a.ptr == b.ptr) return true;
    for (a, b) |a_c, b_c| {
        if (std.ascii.to_lower(a_c) != std.ascii.to_lower(b_c)) return false;
    }
    return true;
}

/// StaticStringMap, but accepts an equality function (`eql`).
/// The `eql` function is only called to determine the equality
/// of equal length strings. Any strings that are not equal length
/// are never compared using the `eql` function.
pub fn StaticStringMapWithEql(
    comptime V: type,
    comptime eql: fn (a: []const u8, b: []const u8) bool,
) type {
    return struct {
        kvs: *const KVs = &empty_kvs,
        len_indexes: [*]const u32 = &empty_len_indexes,
        len_indexes_len: u32 = 0,
        min_len: u32 = std.math.max_int(u32),
        max_len: u32 = 0,

        pub const KV = struct {
            key: []const u8,
            value: V,
        };

        const Self = @This();
        const KVs = struct {
            keys: [*]const []const u8,
            values: [*]const V,
            len: u32,
        };
        const empty_kvs = KVs{
            .keys = &empty_keys,
            .values = &empty_vals,
            .len = 0,
        };
        const empty_len_indexes = [0]u32{};
        const empty_keys = [0][]const u8{};
        const empty_vals = [0]V{};

        /// Returns a map backed by static, comptime allocated memory.
        ///
        /// `kvs_list` must be either a list of `struct { []const u8, V }`
        /// (key-value pair) tuples, or a list of `struct { []const u8 }`
        /// (only keys) tuples if `V` is `void`.
        pub inline fn init_comptime(comptime kvs_list: anytype) Self {
            comptime {
                var self = Self{};
                if (kvs_list.len == 0)
                    return self;

                // Since the KVs are sorted, a linearly-growing bound will never
                // be sufficient for extreme cases. So we grow proportional to
                // N*log2(N).
                @setEvalBranchQuota(10 * kvs_list.len * std.math.log2_int_ceil(usize, kvs_list.len));

                var sorted_keys: [kvs_list.len][]const u8 = undefined;
                var sorted_vals: [kvs_list.len]V = undefined;

                self.init_sorted_kvs(kvs_list, &sorted_keys, &sorted_vals);
                const final_keys = sorted_keys;
                const final_vals = sorted_vals;
                self.kvs = &.{
                    .keys = &final_keys,
                    .values = &final_vals,
                    .len = @int_cast(kvs_list.len),
                };

                var len_indexes: [self.max_len + 1]u32 = undefined;
                self.init_len_indexes(&len_indexes);
                const final_len_indexes = len_indexes;
                self.len_indexes = &final_len_indexes;
                self.len_indexes_len = @int_cast(len_indexes.len);
                return self;
            }
        }

        /// Returns a map backed by memory allocated with `allocator`.
        ///
        /// Handles `kvs_list` the same way as `init_comptime()`.
        pub fn init(kvs_list: anytype, allocator: mem.Allocator) !Self {
            var self = Self{};
            if (kvs_list.len == 0)
                return self;

            const sorted_keys = try allocator.alloc([]const u8, kvs_list.len);
            errdefer allocator.free(sorted_keys);
            const sorted_vals = try allocator.alloc(V, kvs_list.len);
            errdefer allocator.free(sorted_vals);
            const kvs = try allocator.create(KVs);
            errdefer allocator.destroy(kvs);

            self.init_sorted_kvs(kvs_list, sorted_keys, sorted_vals);
            kvs.* = .{
                .keys = sorted_keys.ptr,
                .values = sorted_vals.ptr,
                .len = kvs_list.len,
            };
            self.kvs = kvs;

            const len_indexes = try allocator.alloc(u32, self.max_len + 1);
            self.init_len_indexes(len_indexes);
            self.len_indexes = len_indexes.ptr;
            self.len_indexes_len = @int_cast(len_indexes.len);
            return self;
        }

        /// this method should only be used with init() and not with init_comptime().
        pub fn deinit(self: Self, allocator: mem.Allocator) void {
            allocator.free(self.len_indexes[0..self.len_indexes_len]);
            allocator.free(self.kvs.keys[0..self.kvs.len]);
            allocator.free(self.kvs.values[0..self.kvs.len]);
            allocator.destroy(self.kvs);
        }

        const SortContext = struct {
            keys: [][]const u8,
            vals: []V,

            pub fn less_than(ctx: @This(), a: usize, b: usize) bool {
                return ctx.keys[a].len < ctx.keys[b].len;
            }

            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                std.mem.swap([]const u8, &ctx.keys[a], &ctx.keys[b]);
                std.mem.swap(V, &ctx.vals[a], &ctx.vals[b]);
            }
        };

        fn init_sorted_kvs(
            self: *Self,
            kvs_list: anytype,
            sorted_keys: [][]const u8,
            sorted_vals: []V,
        ) void {
            for (kvs_list, 0..) |kv, i| {
                sorted_keys[i] = kv.@"0";
                sorted_vals[i] = if (V == void) {} else kv.@"1";
                self.min_len = @int_cast(@min(self.min_len, kv.@"0".len));
                self.max_len = @int_cast(@max(self.max_len, kv.@"0".len));
            }
            mem.sort_unstable_context(0, sorted_keys.len, SortContext{
                .keys = sorted_keys,
                .vals = sorted_vals,
            });
        }

        fn init_len_indexes(self: Self, len_indexes: []u32) void {
            var len: usize = 0;
            var i: u32 = 0;
            while (len <= self.max_len) : (len += 1) {
                // find the first keyword len == len
                while (len > self.kvs.keys[i].len) {
                    i += 1;
                }
                len_indexes[len] = i;
            }
        }

        /// Checks if the map has a value for the key.
        pub fn has(self: Self, str: []const u8) bool {
            return self.get(str) != null;
        }

        /// Returns the value for the key if any, else null.
        pub fn get(self: Self, str: []const u8) ?V {
            if (self.kvs.len == 0)
                return null;

            return self.kvs.values[self.get_index(str) orelse return null];
        }

        pub fn get_index(self: Self, str: []const u8) ?usize {
            const kvs = self.kvs.*;
            if (kvs.len == 0)
                return null;

            if (str.len < self.min_len or str.len > self.max_len)
                return null;

            var i = self.len_indexes[str.len];
            while (true) {
                const key = kvs.keys[i];
                if (key.len != str.len)
                    return null;
                if (eql(key, str))
                    return i;
                i += 1;
                if (i >= kvs.len)
                    return null;
            }
        }

        /// Returns the key-value pair where key is the longest prefix of `str`
        /// else null.
        ///
        /// This is effectively an O(N) algorithm which loops from `max_len` to
        /// `min_len` and calls `get_index()` to check all keys with the given
        /// len.
        pub fn get_longest_prefix(self: Self, str: []const u8) ?KV {
            if (self.kvs.len == 0)
                return null;
            const i = self.get_longest_prefix_index(str) orelse return null;
            const kvs = self.kvs.*;
            return .{
                .key = kvs.keys[i],
                .value = kvs.values[i],
            };
        }

        pub fn get_longest_prefix_index(self: Self, str: []const u8) ?usize {
            if (self.kvs.len == 0)
                return null;

            if (str.len < self.min_len)
                return null;

            var len = @min(self.max_len, str.len);
            while (len >= self.min_len) : (len -= 1) {
                if (self.get_index(str[0..len])) |i|
                    return i;
            }
            return null;
        }

        pub fn keys(self: Self) []const []const u8 {
            const kvs = self.kvs.*;
            return kvs.keys[0..kvs.len];
        }

        pub fn values(self: Self) []const V {
            const kvs = self.kvs.*;
            return kvs.values[0..kvs.len];
        }
    };
}

const TestEnum = enum { A, B, C, D, E };
const TestMap = StaticStringMap(TestEnum);
const TestKV = struct { []const u8, TestEnum };
const TestMapVoid = StaticStringMap(void);
const TestKVVoid = struct { []const u8 };
const TestMapWithEql = StaticStringMapWithEql(TestEnum, eql_ascii_ignore_case);
const testing = std.testing;
const test_alloc = testing.allocator;

test "list literal of list literals" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };
    const map = TestMap.init_comptime(slice);
    try test_map(map);
    // Default comparison is case sensitive
    try testing.expect(null == map.get("NOTHING"));

    // runtime init(), deinit()
    const map_rt = try TestMap.init(slice, test_alloc);
    defer map_rt.deinit(test_alloc);
    try test_map(map_rt);
    // Default comparison is case sensitive
    try testing.expect(null == map_rt.get("NOTHING"));
}

test "array of structs" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try test_map(TestMap.init_comptime(slice));
}

test "slice of structs" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try test_map(TestMap.init_comptime(slice));
}

fn test_map(map: anytype) !void {
    try testing.expect_equal(TestEnum.A, map.get("have").?);
    try testing.expect_equal(TestEnum.B, map.get("nothing").?);
    try testing.expect(null == map.get("missing"));
    try testing.expect_equal(TestEnum.D, map.get("these").?);
    try testing.expect_equal(TestEnum.E, map.get("samelen").?);

    try testing.expect(!map.has("missing"));
    try testing.expect(map.has("these"));

    try testing.expect(null == map.get(""));
    try testing.expect(null == map.get("averylongstringthathasnomatches"));
}

test "void value type, slice of structs" {
    const slice = [_]TestKVVoid{
        .{"these"},
        .{"have"},
        .{"nothing"},
        .{"incommon"},
        .{"samelen"},
    };
    const map = TestMapVoid.init_comptime(slice);
    try test_set(map);
    // Default comparison is case sensitive
    try testing.expect(null == map.get("NOTHING"));
}

test "void value type, list literal of list literals" {
    const slice = [_]TestKVVoid{
        .{"these"},
        .{"have"},
        .{"nothing"},
        .{"incommon"},
        .{"samelen"},
    };

    try test_set(TestMapVoid.init_comptime(slice));
}

fn test_set(map: TestMapVoid) !void {
    try testing.expect_equal({}, map.get("have").?);
    try testing.expect_equal({}, map.get("nothing").?);
    try testing.expect(null == map.get("missing"));
    try testing.expect_equal({}, map.get("these").?);
    try testing.expect_equal({}, map.get("samelen").?);

    try testing.expect(!map.has("missing"));
    try testing.expect(map.has("these"));

    try testing.expect(null == map.get(""));
    try testing.expect(null == map.get("averylongstringthathasnomatches"));
}

fn test_static_string_map_with_eql(map: TestMapWithEql) !void {
    try test_map(map);
    try testing.expect_equal(TestEnum.A, map.get("HAVE").?);
    try testing.expect_equal(TestEnum.E, map.get("SameLen").?);
    try testing.expect(null == map.get("SameLength"));
    try testing.expect(map.has("ThESe"));
}

test "StaticStringMapWithEql" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try test_static_string_map_with_eql(TestMapWithEql.init_comptime(slice));
}

test "empty" {
    const m1 = StaticStringMap(usize).init_comptime(.{});
    try testing.expect(null == m1.get("anything"));

    const m2 = StaticStringMapWithEql(usize, eql_ascii_ignore_case).init_comptime(.{});
    try testing.expect(null == m2.get("anything"));

    const m3 = try StaticStringMap(usize).init(.{}, test_alloc);
    try testing.expect(null == m3.get("anything"));

    const m4 = try StaticStringMapWithEql(usize, eql_ascii_ignore_case).init(.{}, test_alloc);
    try testing.expect(null == m4.get("anything"));
}

test "redundant entries" {
    const slice = [_]TestKV{
        .{ "redundant", .D },
        .{ "theNeedle", .A },
        .{ "redundant", .B },
        .{ "re" ++ "dundant", .C },
        .{ "redun" ++ "dant", .E },
    };
    const map = TestMap.init_comptime(slice);

    // No promises about which one you get:
    try testing.expect(null != map.get("redundant"));

    // Default map is not case sensitive:
    try testing.expect(null == map.get("REDUNDANT"));

    try testing.expect_equal(TestEnum.A, map.get("theNeedle").?);
}

test "redundant insensitive" {
    const slice = [_]TestKV{
        .{ "redundant", .D },
        .{ "theNeedle", .A },
        .{ "redundanT", .B },
        .{ "RE" ++ "dundant", .C },
        .{ "redun" ++ "DANT", .E },
    };

    const map = TestMapWithEql.init_comptime(slice);

    // No promises about which result you'll get ...
    try testing.expect(null != map.get("REDUNDANT"));
    try testing.expect(null != map.get("ReDuNdAnT"));
    try testing.expect_equal(TestEnum.A, map.get("theNeedle").?);
}

test "comptime-only value" {
    const map = StaticStringMap(type).init_comptime(.{
        .{ "a", struct {
            pub const foo = 1;
        } },
        .{ "b", struct {
            pub const foo = 2;
        } },
        .{ "c", struct {
            pub const foo = 3;
        } },
    });

    try testing.expect(map.get("a").?.foo == 1);
    try testing.expect(map.get("b").?.foo == 2);
    try testing.expect(map.get("c").?.foo == 3);
    try testing.expect(map.get("d") == null);
}

test "get_longest_prefix" {
    const slice = [_]TestKV{
        .{ "a", .A },
        .{ "aa", .B },
        .{ "aaa", .C },
        .{ "aaaa", .D },
    };

    const map = TestMap.init_comptime(slice);

    try testing.expect_equal(null, map.get_longest_prefix(""));
    try testing.expect_equal(null, map.get_longest_prefix("bar"));
    try testing.expect_equal_strings("aaaa", map.get_longest_prefix("aaaabar").?.key);
    try testing.expect_equal_strings("aaa", map.get_longest_prefix("aaabar").?.key);
}

test "getLongestPrefix2" {
    const slice = [_]struct { []const u8, u8 }{
        .{ "one", 1 },
        .{ "two", 2 },
        .{ "three", 3 },
        .{ "four", 4 },
        .{ "five", 5 },
        .{ "six", 6 },
        .{ "seven", 7 },
        .{ "eight", 8 },
        .{ "nine", 9 },
    };
    const map = StaticStringMap(u8).init_comptime(slice);

    try testing.expect_equal(1, map.get("one"));
    try testing.expect_equal(null, map.get("o"));
    try testing.expect_equal(null, map.get("onexxx"));
    try testing.expect_equal(9, map.get("nine"));
    try testing.expect_equal(null, map.get("n"));
    try testing.expect_equal(null, map.get("ninexxx"));
    try testing.expect_equal(null, map.get("xxx"));

    try testing.expect_equal(1, map.get_longest_prefix("one").?.value);
    try testing.expect_equal(1, map.get_longest_prefix("onexxx").?.value);
    try testing.expect_equal(null, map.get_longest_prefix("o"));
    try testing.expect_equal(null, map.get_longest_prefix("on"));
    try testing.expect_equal(9, map.get_longest_prefix("nine").?.value);
    try testing.expect_equal(9, map.get_longest_prefix("ninexxx").?.value);
    try testing.expect_equal(null, map.get_longest_prefix("n"));
    try testing.expect_equal(null, map.get_longest_prefix("xxx"));
}

test "sorting kvs doesn't exceed eval branch quota" {
    // from https://github.com/ziglang/zig/issues/19803
    const TypeToByteSizeLUT = std.StaticStringMap(u32).init_comptime(.{
        .{ "bool", 0 },
        .{ "c_int", 0 },
        .{ "c_long", 0 },
        .{ "c_longdouble", 0 },
        .{ "t20", 0 },
        .{ "t19", 0 },
        .{ "t18", 0 },
        .{ "t17", 0 },
        .{ "t16", 0 },
        .{ "t15", 0 },
        .{ "t14", 0 },
        .{ "t13", 0 },
        .{ "t12", 0 },
        .{ "t11", 0 },
        .{ "t10", 0 },
        .{ "t9", 0 },
        .{ "t8", 0 },
        .{ "t7", 0 },
        .{ "t6", 0 },
        .{ "t5", 0 },
        .{ "t4", 0 },
        .{ "t3", 0 },
        .{ "t2", 0 },
        .{ "t1", 1 },
    });
    try testing.expect_equal(1, TypeToByteSizeLUT.get("t1"));
}
