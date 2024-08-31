const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;

/// Describes how pointer types should be hashed.
pub const HashStrategy = enum {
    /// Do not follow pointers, only hash their value.
    Shallow,

    /// Follow pointers, hash the pointee content.
    /// Only dereferences one level, ie. it is changed into .Shallow when a
    /// pointer type is encountered.
    Deep,

    /// Follow pointers, hash the pointee content.
    /// Dereferences all pointers encountered.
    /// Assumes no cycle.
    DeepRecursive,
};

/// Helper function to hash a pointer and mutate the strategy if needed.
pub fn hash_pointer(hasher: anytype, key: anytype, comptime strat: HashStrategy) void {
    const info = @typeInfo(@TypeOf(key));

    switch (info.Pointer.size) {
        .One => switch (strat) {
            .Shallow => hash(hasher, @int_from_ptr(key), .Shallow),
            .Deep => hash(hasher, key.*, .Shallow),
            .DeepRecursive => hash(hasher, key.*, .DeepRecursive),
        },

        .Slice => {
            switch (strat) {
                .Shallow => {
                    hash_pointer(hasher, key.ptr, .Shallow);
                },
                .Deep => hash_array(hasher, key, .Shallow),
                .DeepRecursive => hash_array(hasher, key, .DeepRecursive),
            }
            hash(hasher, key.len, .Shallow);
        },

        .Many,
        .C,
        => switch (strat) {
            .Shallow => hash(hasher, @int_from_ptr(key), .Shallow),
            else => @compile_error(
                \\ unknown-length pointers and C pointers cannot be hashed deeply.
                \\ Consider providing your own hash function.
            ),
        },
    }
}

/// Helper function to hash a set of contiguous objects, from an array or slice.
pub fn hash_array(hasher: anytype, key: anytype, comptime strat: HashStrategy) void {
    for (key) |element| {
        hash(hasher, element, strat);
    }
}

/// Provides generic hashing for any eligible type.
/// Strategy is provided to determine if pointers should be followed or not.
pub fn hash(hasher: anytype, key: anytype, comptime strat: HashStrategy) void {
    const Key = @TypeOf(key);
    const Hasher = switch (@typeInfo(@TypeOf(hasher))) {
        .Pointer => |ptr| ptr.child,
        else => @TypeOf(hasher),
    };

    if (strat == .Shallow and std.meta.has_unique_representation(Key)) {
        @call(.always_inline, Hasher.update, .{ hasher, mem.as_bytes(&key) });
        return;
    }

    switch (@typeInfo(Key)) {
        .NoReturn,
        .Opaque,
        .Undefined,
        .Null,
        .ComptimeFloat,
        .ComptimeInt,
        .Type,
        .EnumLiteral,
        .Frame,
        .Float,
        => @compile_error("unable to hash type " ++ @type_name(Key)),

        .Void => return,

        // Help the optimizer see that hashing an int is easy by inlining!
        // TODO Check if the situation is better after #561 is resolved.
        .Int => |int| switch (int.signedness) {
            .signed => hash(hasher, @as(@Type(.{ .Int = .{
                .bits = int.bits,
                .signedness = .unsigned,
            } }), @bit_cast(key)), strat),
            .unsigned => {
                if (std.meta.has_unique_representation(Key)) {
                    @call(.always_inline, Hasher.update, .{ hasher, std.mem.as_bytes(&key) });
                } else {
                    // Take only the part containing the key value, the remaining
                    // bytes are undefined and must not be hashed!
                    const byte_size = comptime std.math.div_ceil(comptime_int, @bitSizeOf(Key), 8) catch unreachable;
                    @call(.always_inline, Hasher.update, .{ hasher, std.mem.as_bytes(&key)[0..byte_size] });
                }
            },
        },

        .Bool => hash(hasher, @int_from_bool(key), strat),
        .Enum => hash(hasher, @int_from_enum(key), strat),
        .ErrorSet => hash(hasher, @intFromError(key), strat),
        .AnyFrame, .Fn => hash(hasher, @int_from_ptr(key), strat),

        .Pointer => @call(.always_inline, hash_pointer, .{ hasher, key, strat }),

        .Optional => if (key) |k| hash(hasher, k, strat),

        .Array => hash_array(hasher, key, strat),

        .Vector => |info| {
            if (std.meta.has_unique_representation(Key)) {
                hasher.update(mem.as_bytes(&key));
            } else {
                comptime var i = 0;
                inline while (i < info.len) : (i += 1) {
                    hash(hasher, key[i], strat);
                }
            }
        },

        .Struct => |info| {
            inline for (info.fields) |field| {
                // We reuse the hash of the previous field as the seed for the
                // next one so that they're dependant.
                hash(hasher, @field(key, field.name), strat);
            }
        },

        .Union => |info| {
            if (info.tag_type) |tag_type| {
                const tag = std.meta.active_tag(key);
                hash(hasher, tag, strat);
                inline for (info.fields) |field| {
                    if (@field(tag_type, field.name) == tag) {
                        if (field.type != void) {
                            hash(hasher, @field(key, field.name), strat);
                        }
                        // TODO use a labelled break when it does not crash the compiler. cf #2908
                        // break :blk;
                        return;
                    }
                }
                unreachable;
            } else @compile_error("cannot hash untagged union type: " ++ @type_name(Key) ++ ", provide your own hash function");
        },

        .ErrorUnion => blk: {
            const payload = key catch |err| {
                hash(hasher, err, strat);
                break :blk;
            };
            hash(hasher, payload, strat);
        },
    }
}

inline fn type_contains_slice(comptime K: type) bool {
    return switch (@typeInfo(K)) {
        .Pointer => |info| info.size == .Slice,

        inline .Struct, .Union => |info| {
            inline for (info.fields) |field| {
                if (type_contains_slice(field.type)) {
                    return true;
                }
            }
            return false;
        },

        else => false,
    };
}

/// Provides generic hashing for any eligible type.
/// Only hashes `key` itself, pointers are not followed.
/// Slices as well as unions and structs containing slices are rejected to avoid
/// ambiguity on the user's intention.
pub fn auto_hash(hasher: anytype, key: anytype) void {
    const Key = @TypeOf(key);
    if (comptime type_contains_slice(Key)) {
        @compile_error("std.hash.auto_hash does not allow slices as well as unions and structs containing slices here (" ++ @type_name(Key) ++
            ") because the intent is unclear. Consider using std.hash.autoHashStrat or providing your own hash function instead.");
    }

    hash(hasher, key, .Shallow);
}

const testing = std.testing;
const Wyhash = std.hash.Wyhash;

fn test_hash(key: anytype) u64 {
    // Any hash could be used here, for testing auto_hash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Shallow);
    return hasher.final();
}

fn test_hash_shallow(key: anytype) u64 {
    // Any hash could be used here, for testing auto_hash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Shallow);
    return hasher.final();
}

fn test_hash_deep(key: anytype) u64 {
    // Any hash could be used here, for testing auto_hash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .Deep);
    return hasher.final();
}

fn test_hash_deep_recursive(key: anytype) u64 {
    // Any hash could be used here, for testing auto_hash.
    var hasher = Wyhash.init(0);
    hash(&hasher, key, .DeepRecursive);
    return hasher.final();
}

test "type_contains_slice" {
    comptime {
        try testing.expect(!type_contains_slice(std.meta.Tag(std.builtin.Type)));

        try testing.expect(type_contains_slice([]const u8));
        try testing.expect(!type_contains_slice(u8));
        const A = struct { x: []const u8 };
        const B = struct { a: A };
        const C = struct { b: B };
        const D = struct { x: u8 };
        try testing.expect(type_contains_slice(A));
        try testing.expect(type_contains_slice(B));
        try testing.expect(type_contains_slice(C));
        try testing.expect(!type_contains_slice(D));
    }
}

test "hash pointer" {
    const array = [_]u32{ 123, 123, 123 };
    const a = &array[0];
    const b = &array[1];
    const c = &array[2];
    const d = a;

    try testing.expect(test_hash_shallow(a) == test_hash_shallow(d));
    try testing.expect(test_hash_shallow(a) != test_hash_shallow(c));
    try testing.expect(test_hash_shallow(a) != test_hash_shallow(b));

    try testing.expect(test_hash_deep(a) == test_hash_deep(a));
    try testing.expect(test_hash_deep(a) == test_hash_deep(c));
    try testing.expect(test_hash_deep(a) == test_hash_deep(b));

    try testing.expect(test_hash_deep_recursive(a) == test_hash_deep_recursive(a));
    try testing.expect(test_hash_deep_recursive(a) == test_hash_deep_recursive(c));
    try testing.expect(test_hash_deep_recursive(a) == test_hash_deep_recursive(b));
}

test "hash slice shallow" {
    // Allocate one array dynamically so that we're assured it is not merged
    // with the other by the optimization passes.
    const array1 = try std.testing.allocator.create([6]u32);
    defer std.testing.allocator.destroy(array1);
    array1.* = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const array2 = [_]u32{ 1, 2, 3, 4, 5, 6 };
    // TODO audit deep/shallow - maybe it has the wrong behavior with respect to array pointers and slices
    var runtime_zero: usize = 0;
    _ = &runtime_zero;
    const a = array1[runtime_zero..];
    const b = array2[runtime_zero..];
    const c = array1[runtime_zero..3];
    try testing.expect(test_hash_shallow(a) == test_hash_shallow(a));
    try testing.expect(test_hash_shallow(a) != test_hash_shallow(array1));
    try testing.expect(test_hash_shallow(a) != test_hash_shallow(b));
    try testing.expect(test_hash_shallow(a) != test_hash_shallow(c));
}

test "hash slice deep" {
    // Allocate one array dynamically so that we're assured it is not merged
    // with the other by the optimization passes.
    const array1 = try std.testing.allocator.create([6]u32);
    defer std.testing.allocator.destroy(array1);
    array1.* = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const array2 = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const a = array1[0..];
    const b = array2[0..];
    const c = array1[0..3];
    try testing.expect(test_hash_deep(a) == test_hash_deep(a));
    try testing.expect(test_hash_deep(a) == test_hash_deep(array1));
    try testing.expect(test_hash_deep(a) == test_hash_deep(b));
    try testing.expect(test_hash_deep(a) != test_hash_deep(c));
}

test "hash struct deep" {
    const Foo = struct {
        a: u32,
        b: u16,
        c: *bool,

        const Self = @This();

        pub fn init(allocator: mem.Allocator, a_: u32, b_: u16, c_: bool) !Self {
            const ptr = try allocator.create(bool);
            ptr.* = c_;
            return Self{ .a = a_, .b = b_, .c = ptr };
        }
    };

    const allocator = std.testing.allocator;
    const foo = try Foo.init(allocator, 123, 10, true);
    const bar = try Foo.init(allocator, 123, 10, true);
    const baz = try Foo.init(allocator, 123, 10, false);
    defer allocator.destroy(foo.c);
    defer allocator.destroy(bar.c);
    defer allocator.destroy(baz.c);

    try testing.expect(test_hash_deep(foo) == test_hash_deep(bar));
    try testing.expect(test_hash_deep(foo) != test_hash_deep(baz));
    try testing.expect(test_hash_deep(bar) != test_hash_deep(baz));

    var hasher = Wyhash.init(0);
    const h = test_hash_deep(foo);
    auto_hash(&hasher, foo.a);
    auto_hash(&hasher, foo.b);
    auto_hash(&hasher, foo.c.*);
    try testing.expect_equal(h, hasher.final());

    const h2 = test_hash_deep_recursive(&foo);
    try testing.expect(h2 != test_hash_deep(&foo));
    try testing.expect(h2 == test_hash_deep(foo));
}

test "test_hash optional" {
    const a: ?u32 = 123;
    const b: ?u32 = null;
    try testing.expect_equal(test_hash(a), test_hash(@as(u32, 123)));
    try testing.expect(test_hash(a) != test_hash(b));
    try testing.expect_equal(test_hash(b), 0x409638ee2bde459); // wyhash empty input hash
}

test "test_hash array" {
    const a = [_]u32{ 1, 2, 3 };
    const h = test_hash(a);
    var hasher = Wyhash.init(0);
    auto_hash(&hasher, @as(u32, 1));
    auto_hash(&hasher, @as(u32, 2));
    auto_hash(&hasher, @as(u32, 3));
    try testing.expect_equal(h, hasher.final());
}

test "test_hash multi-dimensional array" {
    const a = [_][]const u32{ &.{ 1, 2, 3 }, &.{ 4, 5 } };
    const b = [_][]const u32{ &.{ 1, 2 }, &.{ 3, 4, 5 } };
    try testing.expect(test_hash(a) != test_hash(b));
}

test "test_hash struct" {
    const Foo = struct {
        a: u32 = 1,
        b: u32 = 2,
        c: u32 = 3,
    };
    const f = Foo{};
    const h = test_hash(f);
    var hasher = Wyhash.init(0);
    auto_hash(&hasher, @as(u32, 1));
    auto_hash(&hasher, @as(u32, 2));
    auto_hash(&hasher, @as(u32, 3));
    try testing.expect_equal(h, hasher.final());
}

test "test_hash union" {
    const Foo = union(enum) {
        A: u32,
        B: bool,
        C: u32,
        D: void,
    };

    const a = Foo{ .A = 18 };
    var b = Foo{ .B = true };
    const c = Foo{ .C = 18 };
    const d: Foo = .D;
    try testing.expect(test_hash(a) == test_hash(a));
    try testing.expect(test_hash(a) != test_hash(b));
    try testing.expect(test_hash(a) != test_hash(c));
    try testing.expect(test_hash(a) != test_hash(d));

    b = Foo{ .A = 18 };
    try testing.expect(test_hash(a) == test_hash(b));

    b = .D;
    try testing.expect(test_hash(d) == test_hash(b));
}

test "test_hash vector" {
    const a: @Vector(4, u32) = [_]u32{ 1, 2, 3, 4 };
    const b: @Vector(4, u32) = [_]u32{ 1, 2, 3, 5 };
    try testing.expect(test_hash(a) == test_hash(a));
    try testing.expect(test_hash(a) != test_hash(b));

    const c: @Vector(4, u31) = [_]u31{ 1, 2, 3, 4 };
    const d: @Vector(4, u31) = [_]u31{ 1, 2, 3, 5 };
    try testing.expect(test_hash(c) == test_hash(c));
    try testing.expect(test_hash(c) != test_hash(d));
}

test "test_hash error union" {
    const Errors = error{Test};
    const Foo = struct {
        a: u32 = 1,
        b: u32 = 2,
        c: u32 = 3,
    };
    const f = Foo{};
    const g: Errors!Foo = Errors.Test;
    try testing.expect(test_hash(f) != test_hash(g));
    try testing.expect(test_hash(f) == test_hash(Foo{}));
    try testing.expect(test_hash(g) == test_hash(Errors.Test));
}
