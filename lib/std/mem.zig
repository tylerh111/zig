const std = @import("std.zig");
const builtin = @import("builtin");
const debug = std.debug;
const assert = debug.assert;
const math = std.math;
const mem = @This();
const testing = std.testing;
const Endian = std.builtin.Endian;
const native_endian = builtin.cpu.arch.endian();

/// Compile time known minimum page size.
/// https://github.com/ziglang/zig/issues/4082
pub const page_size = switch (builtin.cpu.arch) {
    .wasm32, .wasm64 => 64 * 1024,
    .aarch64 => switch (builtin.os.tag) {
        .macos, .ios, .watchos, .tvos, .visionos => 16 * 1024,
        else => 4 * 1024,
    },
    .sparc64 => 8 * 1024,
    else => 4 * 1024,
};

/// The standard library currently thoroughly depends on byte size
/// being 8 bits.  (see the use of u8 throughout allocation code as
/// the "byte" type.)  Code which depends on this can reference this
/// declaration.  If we ever try to port the standard library to a
/// non-8-bit-byte platform, this will allow us to search for things
/// which need to be updated.
pub const byte_size_in_bits = 8;

pub const Allocator = @import("mem/Allocator.zig");

/// Detects and asserts if the std.mem.Allocator interface is violated by the caller
/// or the allocator.
pub fn ValidationAllocator(comptime T: type) type {
    return struct {
        const Self = @This();

        underlying_allocator: T,

        pub fn init(underlying_allocator: T) @This() {
            return .{
                .underlying_allocator = underlying_allocator,
            };
        }

        pub fn allocator(self: *Self) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .free = free,
                },
            };
        }

        fn get_underlying_allocator_ptr(self: *Self) Allocator {
            if (T == Allocator) return self.underlying_allocator;
            return self.underlying_allocator.allocator();
        }

        pub fn alloc(
            ctx: *anyopaque,
            n: usize,
            log2_ptr_align: u8,
            ret_addr: usize,
        ) ?[*]u8 {
            assert(n > 0);
            const self: *Self = @ptr_cast(@align_cast(ctx));
            const underlying = self.get_underlying_allocator_ptr();
            const result = underlying.raw_alloc(n, log2_ptr_align, ret_addr) orelse
                return null;
            assert(mem.is_aligned_log2(@int_from_ptr(result), log2_ptr_align));
            return result;
        }

        pub fn resize(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            new_len: usize,
            ret_addr: usize,
        ) bool {
            const self: *Self = @ptr_cast(@align_cast(ctx));
            assert(buf.len > 0);
            const underlying = self.get_underlying_allocator_ptr();
            return underlying.raw_resize(buf, log2_buf_align, new_len, ret_addr);
        }

        pub fn free(
            ctx: *anyopaque,
            buf: []u8,
            log2_buf_align: u8,
            ret_addr: usize,
        ) void {
            const self: *Self = @ptr_cast(@align_cast(ctx));
            assert(buf.len > 0);
            const underlying = self.get_underlying_allocator_ptr();
            underlying.raw_free(buf, log2_buf_align, ret_addr);
        }

        pub fn reset(self: *Self) void {
            self.underlying_allocator.reset();
        }
    };
}

pub fn validation_wrap(allocator: anytype) ValidationAllocator(@TypeOf(allocator)) {
    return ValidationAllocator(@TypeOf(allocator)).init(allocator);
}

/// An allocator helper function.  Adjusts an allocation length satisfy `len_align`.
/// `full_len` should be the full capacity of the allocation which may be greater
/// than the `len` that was requested.  This function should only be used by allocators
/// that are unaffected by `len_align`.
pub fn align_alloc_len(full_len: usize, alloc_len: usize, len_align: u29) usize {
    assert(alloc_len > 0);
    assert(alloc_len >= len_align);
    assert(full_len >= alloc_len);
    if (len_align == 0)
        return alloc_len;
    const adjusted = align_backward_any_align(full_len, len_align);
    assert(adjusted >= alloc_len);
    return adjusted;
}

const fail_allocator = Allocator{
    .ptr = undefined,
    .vtable = &failAllocator_vtable,
};

const failAllocator_vtable = Allocator.VTable{
    .alloc = fail_allocator_alloc,
    .resize = Allocator.no_resize,
    .free = Allocator.no_free,
};

fn fail_allocator_alloc(_: *anyopaque, n: usize, log2_alignment: u8, ra: usize) ?[*]u8 {
    _ = n;
    _ = log2_alignment;
    _ = ra;
    return null;
}

test "Allocator basics" {
    try testing.expect_error(error.OutOfMemory, fail_allocator.alloc(u8, 1));
    try testing.expect_error(error.OutOfMemory, fail_allocator.alloc_sentinel(u8, 1, 0));
}

test "Allocator.resize" {
    const primitiveIntTypes = .{
        i8,
        u8,
        i16,
        u16,
        i32,
        u32,
        i64,
        u64,
        i128,
        u128,
        isize,
        usize,
    };
    inline for (primitiveIntTypes) |T| {
        var values = try testing.allocator.alloc(T, 100);
        defer testing.allocator.free(values);

        for (values, 0..) |*v, i| v.* = @as(T, @int_cast(i));
        if (!testing.allocator.resize(values, values.len + 10)) return error.OutOfMemory;
        values = values.ptr[0 .. values.len + 10];
        try testing.expect(values.len == 110);
    }

    const primitiveFloatTypes = .{
        f16,
        f32,
        f64,
        f128,
    };
    inline for (primitiveFloatTypes) |T| {
        var values = try testing.allocator.alloc(T, 100);
        defer testing.allocator.free(values);

        for (values, 0..) |*v, i| v.* = @as(T, @float_from_int(i));
        if (!testing.allocator.resize(values, values.len + 10)) return error.OutOfMemory;
        values = values.ptr[0 .. values.len + 10];
        try testing.expect(values.len == 110);
    }
}

/// Copy all of source into dest at position 0.
/// dest.len must be >= source.len.
/// If the slices overlap, dest.ptr must be <= src.ptr.
pub fn copy_forwards(comptime T: type, dest: []T, source: []const T) void {
    for (dest[0..source.len], source) |*d, s| d.* = s;
}

/// Copy all of source into dest at position 0.
/// dest.len must be >= source.len.
/// If the slices overlap, dest.ptr must be >= src.ptr.
pub fn copy_backwards(comptime T: type, dest: []T, source: []const T) void {
    // TODO instead of manually doing this check for the whole array
    // and turning off runtime safety, the compiler should detect loops like
    // this and automatically omit safety checks for loops
    @setRuntimeSafety(false);
    assert(dest.len >= source.len);
    var i = source.len;
    while (i > 0) {
        i -= 1;
        dest[i] = source[i];
    }
}

/// Generally, Zig users are encouraged to explicitly initialize all fields of a struct explicitly rather than using this function.
/// However, it is recognized that there are sometimes use cases for initializing all fields to a "zero" value. For example, when
/// interfacing with a C API where this practice is more common and relied upon. If you are performing code review and see this
/// function used, examine closely - it may be a code smell.
/// Zero initializes the type.
/// This can be used to zero-initialize any type for which it makes sense. Structs will be initialized recursively.
pub fn zeroes(comptime T: type) T {
    switch (@typeInfo(T)) {
        .ComptimeInt, .Int, .ComptimeFloat, .Float => {
            return @as(T, 0);
        },
        .Enum, .EnumLiteral => {
            return @as(T, @enumFromInt(0));
        },
        .Void => {
            return {};
        },
        .Bool => {
            return false;
        },
        .Optional, .Null => {
            return null;
        },
        .Struct => |struct_info| {
            if (@size_of(T) == 0) return undefined;
            if (struct_info.layout == .@"extern") {
                var item: T = undefined;
                @memset(as_bytes(&item), 0);
                return item;
            } else {
                var structure: T = undefined;
                inline for (struct_info.fields) |field| {
                    if (!field.is_comptime) {
                        @field(structure, field.name) = zeroes(field.type);
                    }
                }
                return structure;
            }
        },
        .Pointer => |ptr_info| {
            switch (ptr_info.size) {
                .Slice => {
                    if (ptr_info.sentinel) |sentinel| {
                        if (ptr_info.child == u8 and @as(*const u8, @ptr_cast(sentinel)).* == 0) {
                            return ""; // A special case for the most common use-case: null-terminated strings.
                        }
                        @compile_error("Can't set a sentinel slice to zero. This would require allocating memory.");
                    } else {
                        return &[_]ptr_info.child{};
                    }
                },
                .C => {
                    return null;
                },
                .One, .Many => {
                    if (ptr_info.is_allowzero) return @ptrFromInt(0);
                    @compile_error("Only nullable and allowzero pointers can be set to zero.");
                },
            }
        },
        .Array => |info| {
            if (info.sentinel) |sentinel_ptr| {
                const sentinel = @as(*align(1) const info.child, @ptr_cast(sentinel_ptr)).*;
                return [_:sentinel]info.child{zeroes(info.child)} ** info.len;
            }
            return [_]info.child{zeroes(info.child)} ** info.len;
        },
        .Vector => |info| {
            return @splat(zeroes(info.child));
        },
        .Union => |info| {
            if (info.layout == .@"extern") {
                var item: T = undefined;
                @memset(as_bytes(&item), 0);
                return item;
            }
            @compile_error("Can't set a " ++ @type_name(T) ++ " to zero.");
        },
        .ErrorUnion,
        .ErrorSet,
        .Fn,
        .Type,
        .NoReturn,
        .Undefined,
        .Opaque,
        .Frame,
        .AnyFrame,
        => {
            @compile_error("Can't set a " ++ @type_name(T) ++ " to zero.");
        },
    }
}

test zeroes {
    const C_struct = extern struct {
        x: u32,
        y: u32 align(128),
    };

    var a = zeroes(C_struct);

    // Extern structs should have padding zeroed out.
    try testing.expect_equal_slices(u8, &[_]u8{0} ** @size_of(@TypeOf(a)), as_bytes(&a));

    a.y += 10;

    try testing.expect(a.x == 0);
    try testing.expect(a.y == 10);

    const ZigStruct = struct {
        comptime comptime_field: u8 = 5,

        integral_types: struct {
            integer_0: i0,
            integer_8: i8,
            integer_16: i16,
            integer_32: i32,
            integer_64: i64,
            integer_128: i128,
            unsigned_0: u0,
            unsigned_8: u8,
            unsigned_16: u16,
            unsigned_32: u32,
            unsigned_64: u64,
            unsigned_128: u128,

            float_32: f32,
            float_64: f64,
        },

        pointers: struct {
            optional: ?*u8,
            c_pointer: [*c]u8,
            slice: []u8,
            null_terminated_string: [:0]const u8,
        },

        array: [2]u32,
        vector_u32: @Vector(2, u32),
        vector_f32: @Vector(2, f32),
        vector_bool: @Vector(2, bool),
        optional_int: ?u8,
        empty: void,
        sentinel: [3:0]u8,
    };

    const b = zeroes(ZigStruct);
    try testing.expect_equal(@as(u8, 5), b.comptime_field);
    try testing.expect_equal(@as(i8, 0), b.integral_types.integer_0);
    try testing.expect_equal(@as(i8, 0), b.integral_types.integer_8);
    try testing.expect_equal(@as(i16, 0), b.integral_types.integer_16);
    try testing.expect_equal(@as(i32, 0), b.integral_types.integer_32);
    try testing.expect_equal(@as(i64, 0), b.integral_types.integer_64);
    try testing.expect_equal(@as(i128, 0), b.integral_types.integer_128);
    try testing.expect_equal(@as(u8, 0), b.integral_types.unsigned_0);
    try testing.expect_equal(@as(u8, 0), b.integral_types.unsigned_8);
    try testing.expect_equal(@as(u16, 0), b.integral_types.unsigned_16);
    try testing.expect_equal(@as(u32, 0), b.integral_types.unsigned_32);
    try testing.expect_equal(@as(u64, 0), b.integral_types.unsigned_64);
    try testing.expect_equal(@as(u128, 0), b.integral_types.unsigned_128);
    try testing.expect_equal(@as(f32, 0), b.integral_types.float_32);
    try testing.expect_equal(@as(f64, 0), b.integral_types.float_64);
    try testing.expect_equal(@as(?*u8, null), b.pointers.optional);
    try testing.expect_equal(@as([*c]u8, null), b.pointers.c_pointer);
    try testing.expect_equal(@as([]u8, &[_]u8{}), b.pointers.slice);
    try testing.expect_equal(@as([:0]const u8, ""), b.pointers.null_terminated_string);
    for (b.array) |e| {
        try testing.expect_equal(@as(u32, 0), e);
    }
    try testing.expect_equal(@as(@TypeOf(b.vector_u32), @splat(0)), b.vector_u32);
    try testing.expect_equal(@as(@TypeOf(b.vector_f32), @splat(0.0)), b.vector_f32);
    try testing.expect_equal(@as(@TypeOf(b.vector_bool), @splat(false)), b.vector_bool);
    try testing.expect_equal(@as(?u8, null), b.optional_int);
    for (b.sentinel) |e| {
        try testing.expect_equal(@as(u8, 0), e);
    }

    const C_union = extern union {
        a: u8,
        b: u32,
    };

    const c = zeroes(C_union);
    try testing.expect_equal(@as(u8, 0), c.a);
    try testing.expect_equal(@as(u32, 0), c.b);

    const comptime_union = comptime zeroes(C_union);
    try testing.expect_equal(@as(u8, 0), comptime_union.a);
    try testing.expect_equal(@as(u32, 0), comptime_union.b);

    // Ensure zero sized struct with fields is initialized correctly.
    _ = zeroes(struct { handle: void });
}

/// Initializes all fields of the struct with their default value, or zero values if no default value is present.
/// If the field is present in the provided initial values, it will have that value instead.
/// Structs are initialized recursively.
pub fn zero_init(comptime T: type, init: anytype) T {
    const Init = @TypeOf(init);

    switch (@typeInfo(T)) {
        .Struct => |struct_info| {
            switch (@typeInfo(Init)) {
                .Struct => |init_info| {
                    if (init_info.is_tuple) {
                        if (init_info.fields.len > struct_info.fields.len) {
                            @compile_error("Tuple initializer has more elements than there are fields in `" ++ @type_name(T) ++ "`");
                        }
                    } else {
                        inline for (init_info.fields) |field| {
                            if (!@has_field(T, field.name)) {
                                @compile_error("Encountered an initializer for `" ++ field.name ++ "`, but it is not a field of " ++ @type_name(T));
                            }
                        }
                    }

                    var value: T = if (struct_info.layout == .@"extern") zeroes(T) else undefined;

                    inline for (struct_info.fields, 0..) |field, i| {
                        if (field.is_comptime) {
                            continue;
                        }

                        if (init_info.is_tuple and init_info.fields.len > i) {
                            @field(value, field.name) = @field(init, init_info.fields[i].name);
                        } else if (@has_field(@TypeOf(init), field.name)) {
                            switch (@typeInfo(field.type)) {
                                .Struct => {
                                    @field(value, field.name) = zero_init(field.type, @field(init, field.name));
                                },
                                else => {
                                    @field(value, field.name) = @field(init, field.name);
                                },
                            }
                        } else if (field.default_value) |default_value_ptr| {
                            const default_value = @as(*align(1) const field.type, @ptr_cast(default_value_ptr)).*;
                            @field(value, field.name) = default_value;
                        } else {
                            switch (@typeInfo(field.type)) {
                                .Struct => {
                                    @field(value, field.name) = std.mem.zero_init(field.type, .{});
                                },
                                else => {
                                    @field(value, field.name) = std.mem.zeroes(@TypeOf(@field(value, field.name)));
                                },
                            }
                        }
                    }

                    return value;
                },
                else => {
                    @compile_error("The initializer must be a struct");
                },
            }
        },
        else => {
            @compile_error("Can't default init a " ++ @type_name(T));
        },
    }
}

test zero_init {
    const I = struct {
        d: f64,
    };

    const S = struct {
        a: u32,
        b: ?bool,
        c: I,
        e: [3]u8,
        f: i64 = -1,
    };

    const s = zero_init(S, .{
        .a = 42,
    });

    try testing.expect_equal(S{
        .a = 42,
        .b = null,
        .c = .{
            .d = 0,
        },
        .e = [3]u8{ 0, 0, 0 },
        .f = -1,
    }, s);

    const Color = struct {
        r: u8,
        g: u8,
        b: u8,
        a: u8,
    };

    const c = zero_init(Color, .{ 255, 255 });
    try testing.expect_equal(Color{
        .r = 255,
        .g = 255,
        .b = 0,
        .a = 0,
    }, c);

    const Foo = struct {
        foo: u8 = 69,
        bar: u8,
    };

    const f = zero_init(Foo, .{});
    try testing.expect_equal(Foo{
        .foo = 69,
        .bar = 0,
    }, f);

    const Bar = struct {
        foo: u32 = 666,
        bar: u32 = 420,
    };

    const b = zero_init(Bar, .{69});
    try testing.expect_equal(Bar{
        .foo = 69,
        .bar = 420,
    }, b);

    const Baz = struct {
        foo: [:0]const u8 = "bar",
    };

    const baz1 = zero_init(Baz, .{});
    try testing.expect_equal(Baz{}, baz1);

    const baz2 = zero_init(Baz, .{ .foo = "zab" });
    try testing.expect_equal_slices(u8, "zab", baz2.foo);

    const NestedBaz = struct {
        bbb: Baz,
    };
    const nested_baz = zero_init(NestedBaz, .{});
    try testing.expect_equal(NestedBaz{
        .bbb = Baz{},
    }, nested_baz);
}

pub fn sort(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    std.sort.block(T, items, context, lessThanFn);
}

pub fn sort_unstable(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    std.sort.pdq(T, items, context, lessThanFn);
}

/// TODO: currently this just calls `insertionSortContext`. The block sort implementation
/// in this file needs to be adapted to use the sort context.
pub fn sort_context(a: usize, b: usize, context: anytype) void {
    std.sort.insertion_context(a, b, context);
}

pub fn sort_unstable_context(a: usize, b: usize, context: anytype) void {
    std.sort.pdq_context(a, b, context);
}

/// Compares two slices of numbers lexicographically. O(n).
pub fn order(comptime T: type, lhs: []const T, rhs: []const T) math.Order {
    const n = @min(lhs.len, rhs.len);
    for (lhs[0..n], rhs[0..n]) |lhs_elem, rhs_elem| {
        switch (math.order(lhs_elem, rhs_elem)) {
            .eq => continue,
            .lt => return .lt,
            .gt => return .gt,
        }
    }
    return math.order(lhs.len, rhs.len);
}

/// Compares two many-item pointers with NUL-termination lexicographically.
pub fn order_z(comptime T: type, lhs: [*:0]const T, rhs: [*:0]const T) math.Order {
    var i: usize = 0;
    while (lhs[i] == rhs[i] and lhs[i] != 0) : (i += 1) {}
    return math.order(lhs[i], rhs[i]);
}

test order {
    try testing.expect(order(u8, "abcd", "bee") == .lt);
    try testing.expect(order(u8, "abc", "abc") == .eq);
    try testing.expect(order(u8, "abc", "abc0") == .lt);
    try testing.expect(order(u8, "", "") == .eq);
    try testing.expect(order(u8, "", "a") == .lt);
}

test order_z {
    try testing.expect(order_z(u8, "abcd", "bee") == .lt);
    try testing.expect(order_z(u8, "abc", "abc") == .eq);
    try testing.expect(order_z(u8, "abc", "abc0") == .lt);
    try testing.expect(order_z(u8, "", "") == .eq);
    try testing.expect(order_z(u8, "", "a") == .lt);
}

/// Returns true if lhs < rhs, false otherwise
pub fn less_than(comptime T: type, lhs: []const T, rhs: []const T) bool {
    return order(T, lhs, rhs) == .lt;
}

test less_than {
    try testing.expect(less_than(u8, "abcd", "bee"));
    try testing.expect(!less_than(u8, "abc", "abc"));
    try testing.expect(less_than(u8, "abc", "abc0"));
    try testing.expect(!less_than(u8, "", ""));
    try testing.expect(less_than(u8, "", "a"));
}

const backend_can_use_eql_bytes = switch (builtin.zig_backend) {
    // The SPIR-V backend does not support the optimized path yet.
    .stage2_spirv64 => false,
    // The RISC-V does not support vectors.
    .stage2_riscv64 => false,
    else => true,
};

/// Compares two slices and returns whether they are equal.
pub fn eql(comptime T: type, a: []const T, b: []const T) bool {
    if (@size_of(T) == 0) return true;
    if (!@in_comptime() and std.meta.has_unique_representation(T) and backend_can_use_eql_bytes) return eql_bytes(slice_as_bytes(a), slice_as_bytes(b));

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

/// std.mem.eql heavily optimized for slices of bytes.
fn eql_bytes(a: []const u8, b: []const u8) bool {
    if (!backend_can_use_eql_bytes) {
        return eql(u8, a, b);
    }

    if (a.len != b.len) return false;
    if (a.len == 0 or a.ptr == b.ptr) return true;

    if (a.len <= 16) {
        if (a.len < 4) {
            const x = (a[0] ^ b[0]) | (a[a.len - 1] ^ b[a.len - 1]) | (a[a.len / 2] ^ b[a.len / 2]);
            return x == 0;
        }
        var x: u32 = 0;
        for ([_]usize{ 0, a.len - 4, (a.len / 8) * 4, a.len - 4 - ((a.len / 8) * 4) }) |n| {
            x |= @as(u32, @bit_cast(a[n..][0..4].*)) ^ @as(u32, @bit_cast(b[n..][0..4].*));
        }
        return x == 0;
    }

    // Figure out the fastest way to scan through the input in chunks.
    // Uses vectors when supported and falls back to usize/words when not.
    const Scan = if (std.simd.suggest_vector_length(u8)) |vec_size|
        struct {
            pub const size = vec_size;
            pub const Chunk = @Vector(size, u8);
            pub inline fn is_not_equal(chunk_a: Chunk, chunk_b: Chunk) bool {
                return @reduce(.Or, chunk_a != chunk_b);
            }
        }
    else
        struct {
            pub const size = @size_of(usize);
            pub const Chunk = usize;
            pub inline fn is_not_equal(chunk_a: Chunk, chunk_b: Chunk) bool {
                return chunk_a != chunk_b;
            }
        };

    inline for (1..6) |s| {
        const n = 16 << s;
        if (n <= Scan.size and a.len <= n) {
            const V = @Vector(n / 2, u8);
            var x = @as(V, a[0 .. n / 2].*) ^ @as(V, b[0 .. n / 2].*);
            x |= @as(V, a[a.len - n / 2 ..][0 .. n / 2].*) ^ @as(V, b[a.len - n / 2 ..][0 .. n / 2].*);
            const zero: V = @splat(0);
            return !@reduce(.Or, x != zero);
        }
    }
    // Compare inputs in chunks at a time (excluding the last chunk).
    for (0..(a.len - 1) / Scan.size) |i| {
        const a_chunk: Scan.Chunk = @bit_cast(a[i * Scan.size ..][0..Scan.size].*);
        const b_chunk: Scan.Chunk = @bit_cast(b[i * Scan.size ..][0..Scan.size].*);
        if (Scan.is_not_equal(a_chunk, b_chunk)) return false;
    }

    // Compare the last chunk using an overlapping read (similar to the previous size strategies).
    const last_a_chunk: Scan.Chunk = @bit_cast(a[a.len - Scan.size ..][0..Scan.size].*);
    const last_b_chunk: Scan.Chunk = @bit_cast(b[a.len - Scan.size ..][0..Scan.size].*);
    return !Scan.is_not_equal(last_a_chunk, last_b_chunk);
}

/// Compares two slices and returns the index of the first inequality.
/// Returns null if the slices are equal.
pub fn index_of_diff(comptime T: type, a: []const T, b: []const T) ?usize {
    const shortest = @min(a.len, b.len);
    if (a.ptr == b.ptr)
        return if (a.len == b.len) null else shortest;
    var index: usize = 0;
    while (index < shortest) : (index += 1) if (a[index] != b[index]) return index;
    return if (a.len == b.len) null else shortest;
}

test index_of_diff {
    try testing.expect_equal(index_of_diff(u8, "one", "one"), null);
    try testing.expect_equal(index_of_diff(u8, "one two", "one"), 3);
    try testing.expect_equal(index_of_diff(u8, "one", "one two"), 3);
    try testing.expect_equal(index_of_diff(u8, "one twx", "one two"), 6);
    try testing.expect_equal(index_of_diff(u8, "xne", "one"), 0);
}

/// Takes a sentinel-terminated pointer and returns a slice preserving pointer attributes.
/// `[*c]` pointers are assumed to be 0-terminated and assumed to not be allowzero.
fn Span(comptime T: type) type {
    switch (@typeInfo(T)) {
        .Optional => |optional_info| {
            return ?Span(optional_info.child);
        },
        .Pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            switch (ptr_info.size) {
                .C => {
                    new_ptr_info.sentinel = &@as(ptr_info.child, 0);
                    new_ptr_info.is_allowzero = false;
                },
                .Many => if (ptr_info.sentinel == null) @compile_error("invalid type given to std.mem.span: " ++ @type_name(T)),
                .One, .Slice => @compile_error("invalid type given to std.mem.span: " ++ @type_name(T)),
            }
            new_ptr_info.size = .Slice;
            return @Type(.{ .Pointer = new_ptr_info });
        },
        else => {},
    }
    @compile_error("invalid type given to std.mem.span: " ++ @type_name(T));
}

test Span {
    try testing.expect(Span([*:1]u16) == [:1]u16);
    try testing.expect(Span(?[*:1]u16) == ?[:1]u16);
    try testing.expect(Span([*:1]const u8) == [:1]const u8);
    try testing.expect(Span(?[*:1]const u8) == ?[:1]const u8);
    try testing.expect(Span([*c]u16) == [:0]u16);
    try testing.expect(Span(?[*c]u16) == ?[:0]u16);
    try testing.expect(Span([*c]const u8) == [:0]const u8);
    try testing.expect(Span(?[*c]const u8) == ?[:0]const u8);
}

/// Takes a sentinel-terminated pointer and returns a slice, iterating over the
/// memory to find the sentinel and determine the length.
/// Pointer attributes such as const are preserved.
/// `[*c]` pointers are assumed to be non-null and 0-terminated.
pub fn span(ptr: anytype) Span(@TypeOf(ptr)) {
    if (@typeInfo(@TypeOf(ptr)) == .Optional) {
        if (ptr) |non_null| {
            return span(non_null);
        } else {
            return null;
        }
    }
    const Result = Span(@TypeOf(ptr));
    const l = len(ptr);
    const ptr_info = @typeInfo(Result).Pointer;
    if (ptr_info.sentinel) |s_ptr| {
        const s = @as(*align(1) const ptr_info.child, @ptr_cast(s_ptr)).*;
        return ptr[0..l :s];
    } else {
        return ptr[0..l];
    }
}

test span {
    var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
    const ptr = @as([*:3]u16, array[0..2 :3]);
    try testing.expect(eql(u16, span(ptr), &[_]u16{ 1, 2 }));
    try testing.expect_equal(@as(?[:0]u16, null), span(@as(?[*:0]u16, null)));
}

/// Helper for the return type of slice_to()
fn SliceTo(comptime T: type, comptime end: std.meta.Elem(T)) type {
    switch (@typeInfo(T)) {
        .Optional => |optional_info| {
            return ?SliceTo(optional_info.child, end);
        },
        .Pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            new_ptr_info.size = .Slice;
            switch (ptr_info.size) {
                .One => switch (@typeInfo(ptr_info.child)) {
                    .Array => |array_info| {
                        new_ptr_info.child = array_info.child;
                        // The return type must only be sentinel terminated if we are guaranteed
                        // to find the value searched for, which is only the case if it matches
                        // the sentinel of the type passed.
                        if (array_info.sentinel) |sentinel_ptr| {
                            const sentinel = @as(*align(1) const array_info.child, @ptr_cast(sentinel_ptr)).*;
                            if (end == sentinel) {
                                new_ptr_info.sentinel = &end;
                            } else {
                                new_ptr_info.sentinel = null;
                            }
                        }
                    },
                    else => {},
                },
                .Many, .Slice => {
                    // The return type must only be sentinel terminated if we are guaranteed
                    // to find the value searched for, which is only the case if it matches
                    // the sentinel of the type passed.
                    if (ptr_info.sentinel) |sentinel_ptr| {
                        const sentinel = @as(*align(1) const ptr_info.child, @ptr_cast(sentinel_ptr)).*;
                        if (end == sentinel) {
                            new_ptr_info.sentinel = &end;
                        } else {
                            new_ptr_info.sentinel = null;
                        }
                    }
                },
                .C => {
                    new_ptr_info.sentinel = &end;
                    // C pointers are always allowzero, but we don't want the return type to be.
                    assert(new_ptr_info.is_allowzero);
                    new_ptr_info.is_allowzero = false;
                },
            }
            return @Type(.{ .Pointer = new_ptr_info });
        },
        else => {},
    }
    @compile_error("invalid type given to std.mem.slice_to: " ++ @type_name(T));
}

/// Takes an array, a pointer to an array, a sentinel-terminated pointer, or a slice and
/// iterates searching for the first occurrence of `end`, returning the scanned slice.
/// If `end` is not found, the full length of the array/slice/sentinel terminated pointer is returned.
/// If the pointer type is sentinel terminated and `end` matches that terminator, the
/// resulting slice is also sentinel terminated.
/// Pointer properties such as mutability and alignment are preserved.
/// C pointers are assumed to be non-null.
pub fn slice_to(ptr: anytype, comptime end: std.meta.Elem(@TypeOf(ptr))) SliceTo(@TypeOf(ptr), end) {
    if (@typeInfo(@TypeOf(ptr)) == .Optional) {
        const non_null = ptr orelse return null;
        return slice_to(non_null, end);
    }
    const Result = SliceTo(@TypeOf(ptr), end);
    const length = len_slice_to(ptr, end);
    const ptr_info = @typeInfo(Result).Pointer;
    if (ptr_info.sentinel) |s_ptr| {
        const s = @as(*align(1) const ptr_info.child, @ptr_cast(s_ptr)).*;
        return ptr[0..length :s];
    } else {
        return ptr[0..length];
    }
}

test slice_to {
    try testing.expect_equal_slices(u8, "aoeu", slice_to("aoeu", 0));

    {
        var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
        try testing.expect_equal_slices(u16, &array, slice_to(&array, 0));
        try testing.expect_equal_slices(u16, array[0..3], slice_to(array[0..3], 0));
        try testing.expect_equal_slices(u16, array[0..2], slice_to(&array, 3));
        try testing.expect_equal_slices(u16, array[0..2], slice_to(array[0..3], 3));

        const sentinel_ptr = @as([*:5]u16, @ptr_cast(&array));
        try testing.expect_equal_slices(u16, array[0..2], slice_to(sentinel_ptr, 3));
        try testing.expect_equal_slices(u16, array[0..4], slice_to(sentinel_ptr, 99));

        const optional_sentinel_ptr = @as(?[*:5]u16, @ptr_cast(&array));
        try testing.expect_equal_slices(u16, array[0..2], slice_to(optional_sentinel_ptr, 3).?);
        try testing.expect_equal_slices(u16, array[0..4], slice_to(optional_sentinel_ptr, 99).?);

        const c_ptr = @as([*c]u16, &array);
        try testing.expect_equal_slices(u16, array[0..2], slice_to(c_ptr, 3));

        const slice: []u16 = &array;
        try testing.expect_equal_slices(u16, array[0..2], slice_to(slice, 3));
        try testing.expect_equal_slices(u16, &array, slice_to(slice, 99));

        const sentinel_slice: [:5]u16 = array[0..4 :5];
        try testing.expect_equal_slices(u16, array[0..2], slice_to(sentinel_slice, 3));
        try testing.expect_equal_slices(u16, array[0..4], slice_to(sentinel_slice, 99));
    }
    {
        var sentinel_array: [5:0]u16 = [_:0]u16{ 1, 2, 3, 4, 5 };
        try testing.expect_equal_slices(u16, sentinel_array[0..2], slice_to(&sentinel_array, 3));
        try testing.expect_equal_slices(u16, &sentinel_array, slice_to(&sentinel_array, 0));
        try testing.expect_equal_slices(u16, &sentinel_array, slice_to(&sentinel_array, 99));
    }

    try testing.expect_equal(@as(?[]u8, null), slice_to(@as(?[]u8, null), 0));
}

/// Private helper for slice_to(). If you want the length, use slice_to(foo, x).len
fn len_slice_to(ptr: anytype, comptime end: std.meta.Elem(@TypeOf(ptr))) usize {
    switch (@typeInfo(@TypeOf(ptr))) {
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .One => switch (@typeInfo(ptr_info.child)) {
                .Array => |array_info| {
                    if (array_info.sentinel) |sentinel_ptr| {
                        const sentinel = @as(*align(1) const array_info.child, @ptr_cast(sentinel_ptr)).*;
                        if (sentinel == end) {
                            return index_of_sentinel(array_info.child, end, ptr);
                        }
                    }
                    return index_of_scalar(array_info.child, ptr, end) orelse array_info.len;
                },
                else => {},
            },
            .Many => if (ptr_info.sentinel) |sentinel_ptr| {
                const sentinel = @as(*align(1) const ptr_info.child, @ptr_cast(sentinel_ptr)).*;
                if (sentinel == end) {
                    return index_of_sentinel(ptr_info.child, end, ptr);
                }
                // We're looking for something other than the sentinel,
                // but iterating past the sentinel would be a bug so we need
                // to check for both.
                var i: usize = 0;
                while (ptr[i] != end and ptr[i] != sentinel) i += 1;
                return i;
            },
            .C => {
                assert(ptr != null);
                return index_of_sentinel(ptr_info.child, end, ptr);
            },
            .Slice => {
                if (ptr_info.sentinel) |sentinel_ptr| {
                    const sentinel = @as(*align(1) const ptr_info.child, @ptr_cast(sentinel_ptr)).*;
                    if (sentinel == end) {
                        return index_of_sentinel(ptr_info.child, sentinel, ptr);
                    }
                }
                return index_of_scalar(ptr_info.child, ptr, end) orelse ptr.len;
            },
        },
        else => {},
    }
    @compile_error("invalid type given to std.mem.slice_to: " ++ @type_name(@TypeOf(ptr)));
}

test len_slice_to {
    try testing.expect(len_slice_to("aoeu", 0) == 4);

    {
        var array: [5]u16 = [_]u16{ 1, 2, 3, 4, 5 };
        try testing.expect_equal(@as(usize, 5), len_slice_to(&array, 0));
        try testing.expect_equal(@as(usize, 3), len_slice_to(array[0..3], 0));
        try testing.expect_equal(@as(usize, 2), len_slice_to(&array, 3));
        try testing.expect_equal(@as(usize, 2), len_slice_to(array[0..3], 3));

        const sentinel_ptr = @as([*:5]u16, @ptr_cast(&array));
        try testing.expect_equal(@as(usize, 2), len_slice_to(sentinel_ptr, 3));
        try testing.expect_equal(@as(usize, 4), len_slice_to(sentinel_ptr, 99));

        const c_ptr = @as([*c]u16, &array);
        try testing.expect_equal(@as(usize, 2), len_slice_to(c_ptr, 3));

        const slice: []u16 = &array;
        try testing.expect_equal(@as(usize, 2), len_slice_to(slice, 3));
        try testing.expect_equal(@as(usize, 5), len_slice_to(slice, 99));

        const sentinel_slice: [:5]u16 = array[0..4 :5];
        try testing.expect_equal(@as(usize, 2), len_slice_to(sentinel_slice, 3));
        try testing.expect_equal(@as(usize, 4), len_slice_to(sentinel_slice, 99));
    }
    {
        var sentinel_array: [5:0]u16 = [_:0]u16{ 1, 2, 3, 4, 5 };
        try testing.expect_equal(@as(usize, 2), len_slice_to(&sentinel_array, 3));
        try testing.expect_equal(@as(usize, 5), len_slice_to(&sentinel_array, 0));
        try testing.expect_equal(@as(usize, 5), len_slice_to(&sentinel_array, 99));
    }
}

/// Takes a sentinel-terminated pointer and iterates over the memory to find the
/// sentinel and determine the length.
/// `[*c]` pointers are assumed to be non-null and 0-terminated.
pub fn len(value: anytype) usize {
    switch (@typeInfo(@TypeOf(value))) {
        .Pointer => |info| switch (info.size) {
            .Many => {
                const sentinel_ptr = info.sentinel orelse
                    @compile_error("invalid type given to std.mem.len: " ++ @type_name(@TypeOf(value)));
                const sentinel = @as(*align(1) const info.child, @ptr_cast(sentinel_ptr)).*;
                return index_of_sentinel(info.child, sentinel, value);
            },
            .C => {
                assert(value != null);
                return index_of_sentinel(info.child, 0, value);
            },
            else => @compile_error("invalid type given to std.mem.len: " ++ @type_name(@TypeOf(value))),
        },
        else => @compile_error("invalid type given to std.mem.len: " ++ @type_name(@TypeOf(value))),
    }
}

test len {
    var array: [5]u16 = [_]u16{ 1, 2, 0, 4, 5 };
    const ptr = @as([*:4]u16, array[0..3 :4]);
    try testing.expect(len(ptr) == 3);
    const c_ptr = @as([*c]u16, ptr);
    try testing.expect(len(c_ptr) == 2);
}

const backend_supports_vectors = switch (builtin.zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

pub fn index_of_sentinel(comptime T: type, comptime sentinel: T, p: [*:sentinel]const T) usize {
    var i: usize = 0;

    if (backend_supports_vectors and
        !std.debug.in_valgrind() and // https://github.com/ziglang/zig/issues/17717
        !@in_comptime() and
        (@typeInfo(T) == .Int or @typeInfo(T) == .Float) and std.math.is_power_of_two(@bitSizeOf(T)))
    {
        switch (@import("builtin").cpu.arch) {
            // The below branch assumes that reading past the end of the buffer is valid, as long
            // as we don't read into a new page. This should be the case for most architectures
            // which use paged memory, however should be confirmed before adding a new arch below.
            .aarch64, .x86, .x86_64 => if (std.simd.suggest_vector_length(T)) |block_len| {
                const Block = @Vector(block_len, T);
                const mask: Block = @splat(sentinel);

                comptime std.debug.assert(std.mem.page_size % @size_of(Block) == 0);

                // First block may be unaligned
                const start_addr = @int_from_ptr(&p[i]);
                const offset_in_page = start_addr & (std.mem.page_size - 1);
                if (offset_in_page <= std.mem.page_size - @size_of(Block)) {
                    // Will not read past the end of a page, full block.
                    const block: Block = p[i..][0..block_len].*;
                    const matches = block == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.first_true(matches).?;
                    }

                    i += (std.mem.align_forward(usize, start_addr, @alignOf(Block)) - start_addr) / @size_of(T);
                } else {
                    // Would read over a page boundary. Per-byte at a time until aligned or found.
                    // 0.39% chance this branch is taken for 4K pages at 16b block length.
                    //
                    // An alternate strategy is to do read a full block (the last in the page) and
                    // mask the entries before the pointer.
                    while ((@int_from_ptr(&p[i]) & (@alignOf(Block) - 1)) != 0) : (i += 1) {
                        if (p[i] == sentinel) return i;
                    }
                }

                std.debug.assert(std.mem.is_aligned(@int_from_ptr(&p[i]), @alignOf(Block)));
                while (true) {
                    const block: *const Block = @ptr_cast(@align_cast(p[i..][0..block_len]));
                    const matches = block.* == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.first_true(matches).?;
                    }
                    i += block_len;
                }
            },
            else => {},
        }
    }

    while (p[i] != sentinel) {
        i += 1;
    }
    return i;
}

test "index_of_sentinel vector paths" {
    const Types = [_]type{ u8, u16, u32, u64 };
    const allocator = std.testing.allocator;

    inline for (Types) |T| {
        const block_len = std.simd.suggest_vector_length(T) orelse continue;

        // Allocate three pages so we guarantee a page-crossing address with a full page after
        const memory = try allocator.alloc(T, 3 * std.mem.page_size / @size_of(T));
        defer allocator.free(memory);
        @memset(memory, 0xaa);

        // Find starting page-alignment = 0
        var start: usize = 0;
        const start_addr = @int_from_ptr(&memory);
        start += (std.mem.align_forward(usize, start_addr, std.mem.page_size) - start_addr) / @size_of(T);
        try testing.expect(start < std.mem.page_size / @size_of(T));

        // Validate all sub-block alignments
        const search_len = std.mem.page_size / @size_of(T);
        memory[start + search_len] = 0;
        for (0..block_len) |offset| {
            try testing.expect_equal(search_len - offset, index_of_sentinel(T, 0, @ptr_cast(&memory[start + offset])));
        }
        memory[start + search_len] = 0xaa;

        // Validate page boundary crossing
        const start_page_boundary = start + (std.mem.page_size / @size_of(T));
        memory[start_page_boundary + block_len] = 0;
        for (0..block_len) |offset| {
            try testing.expect_equal(2 * block_len - offset, index_of_sentinel(T, 0, @ptr_cast(&memory[start_page_boundary - block_len + offset])));
        }
    }
}

/// Returns true if all elements in a slice are equal to the scalar value provided
pub fn all_equal(comptime T: type, slice: []const T, scalar: T) bool {
    for (slice) |item| {
        if (item != scalar) return false;
    }
    return true;
}

/// Remove a set of values from the beginning of a slice.
pub fn trim_left(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var begin: usize = 0;
    while (begin < slice.len and index_of_scalar(T, values_to_strip, slice[begin]) != null) : (begin += 1) {}
    return slice[begin..];
}

/// Remove a set of values from the end of a slice.
pub fn trim_right(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var end: usize = slice.len;
    while (end > 0 and index_of_scalar(T, values_to_strip, slice[end - 1]) != null) : (end -= 1) {}
    return slice[0..end];
}

/// Remove a set of values from the beginning and end of a slice.
pub fn trim(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    var begin: usize = 0;
    var end: usize = slice.len;
    while (begin < end and index_of_scalar(T, values_to_strip, slice[begin]) != null) : (begin += 1) {}
    while (end > begin and index_of_scalar(T, values_to_strip, slice[end - 1]) != null) : (end -= 1) {}
    return slice[begin..end];
}

test trim {
    try testing.expect_equal_slices(u8, "foo\n ", trim_left(u8, " foo\n ", " \n"));
    try testing.expect_equal_slices(u8, " foo", trim_right(u8, " foo\n ", " \n"));
    try testing.expect_equal_slices(u8, "foo", trim(u8, " foo\n ", " \n"));
    try testing.expect_equal_slices(u8, "foo", trim(u8, "foo", " \n"));
}

/// Linear search for the index of a scalar value inside a slice.
pub fn index_of_scalar(comptime T: type, slice: []const T, value: T) ?usize {
    return index_of_scalar_pos(T, slice, 0, value);
}

/// Linear search for the last index of a scalar value inside a slice.
pub fn last_index_of_scalar(comptime T: type, slice: []const T, value: T) ?usize {
    var i: usize = slice.len;
    while (i != 0) {
        i -= 1;
        if (slice[i] == value) return i;
    }
    return null;
}

pub fn index_of_scalar_pos(comptime T: type, slice: []const T, start_index: usize, value: T) ?usize {
    if (start_index >= slice.len) return null;

    var i: usize = start_index;
    if (backend_supports_vectors and
        !std.debug.in_valgrind() and // https://github.com/ziglang/zig/issues/17717
        !@in_comptime() and
        (@typeInfo(T) == .Int or @typeInfo(T) == .Float) and std.math.is_power_of_two(@bitSizeOf(T)))
    {
        if (std.simd.suggest_vector_length(T)) |block_len| {
            // For Intel Nehalem (2009) and AMD Bulldozer (2012) or later, unaligned loads on aligned data result
            // in the same execution as aligned loads. We ignore older arch's here and don't bother pre-aligning.
            //
            // Use `std.simd.suggest_vector_length(T)` to get the same alignment as used in this function
            // however this usually isn't necessary unless your arch has a performance penalty due to this.
            //
            // This may differ for other arch's. Arm for example costs a cycle when loading across a cache
            // line so explicit alignment prologues may be worth exploration.

            // Unrolling here is ~10% improvement. We can then do one bounds check every 2 blocks
            // instead of one which adds up.
            const Block = @Vector(block_len, T);
            if (i + 2 * block_len < slice.len) {
                const mask: Block = @splat(value);
                while (true) {
                    inline for (0..2) |_| {
                        const block: Block = slice[i..][0..block_len].*;
                        const matches = block == mask;
                        if (@reduce(.Or, matches)) {
                            return i + std.simd.first_true(matches).?;
                        }
                        i += block_len;
                    }
                    if (i + 2 * block_len >= slice.len) break;
                }
            }

            // {block_len, block_len / 2} check
            inline for (0..2) |j| {
                const block_x_len = block_len / (1 << j);
                comptime if (block_x_len < 4) break;

                const BlockX = @Vector(block_x_len, T);
                if (i + block_x_len < slice.len) {
                    const mask: BlockX = @splat(value);
                    const block: BlockX = slice[i..][0..block_x_len].*;
                    const matches = block == mask;
                    if (@reduce(.Or, matches)) {
                        return i + std.simd.first_true(matches).?;
                    }
                    i += block_x_len;
                }
            }
        }
    }

    for (slice[i..], i..) |c, j| {
        if (c == value) return j;
    }
    return null;
}

test index_of_scalar_pos {
    const Types = [_]type{ u8, u16, u32, u64 };

    inline for (Types) |T| {
        var memory: [64 / @size_of(T)]T = undefined;
        @memset(&memory, 0xaa);
        memory[memory.len - 1] = 0;

        for (0..memory.len) |i| {
            try testing.expect_equal(memory.len - i - 1, index_of_scalar_pos(T, memory[i..], 0, 0).?);
        }
    }
}

pub fn index_of_any(comptime T: type, slice: []const T, values: []const T) ?usize {
    return index_of_any_pos(T, slice, 0, values);
}

pub fn last_index_of_any(comptime T: type, slice: []const T, values: []const T) ?usize {
    var i: usize = slice.len;
    while (i != 0) {
        i -= 1;
        for (values) |value| {
            if (slice[i] == value) return i;
        }
    }
    return null;
}

pub fn index_of_any_pos(comptime T: type, slice: []const T, start_index: usize, values: []const T) ?usize {
    if (start_index >= slice.len) return null;
    for (slice[start_index..], start_index..) |c, i| {
        for (values) |value| {
            if (c == value) return i;
        }
    }
    return null;
}

/// Find the first item in `slice` which is not contained in `values`.
///
/// Comparable to `strspn` in the C standard library.
pub fn index_of_none(comptime T: type, slice: []const T, values: []const T) ?usize {
    return index_of_none_pos(T, slice, 0, values);
}

/// Find the last item in `slice` which is not contained in `values`.
///
/// Like `strspn` in the C standard library, but searches from the end.
pub fn last_index_of_none(comptime T: type, slice: []const T, values: []const T) ?usize {
    var i: usize = slice.len;
    outer: while (i != 0) {
        i -= 1;
        for (values) |value| {
            if (slice[i] == value) continue :outer;
        }
        return i;
    }
    return null;
}

/// Find the first item in `slice[start_index..]` which is not contained in `values`.
/// The returned index will be relative to the start of `slice`, and never less than `start_index`.
///
/// Comparable to `strspn` in the C standard library.
pub fn index_of_none_pos(comptime T: type, slice: []const T, start_index: usize, values: []const T) ?usize {
    if (start_index >= slice.len) return null;
    outer: for (slice[start_index..], start_index..) |c, i| {
        for (values) |value| {
            if (c == value) continue :outer;
        }
        return i;
    }
    return null;
}

test index_of_none {
    try testing.expect(index_of_none(u8, "abc123", "123").? == 0);
    try testing.expect(last_index_of_none(u8, "abc123", "123").? == 2);
    try testing.expect(index_of_none(u8, "123abc", "123").? == 3);
    try testing.expect(last_index_of_none(u8, "123abc", "123").? == 5);
    try testing.expect(index_of_none(u8, "123123", "123") == null);
    try testing.expect(index_of_none(u8, "333333", "123") == null);

    try testing.expect(index_of_none_pos(u8, "abc123", 3, "321") == null);
}

pub fn index_of(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    return index_of_pos(T, haystack, 0, needle);
}

/// Find the index in a slice of a sub-slice, searching from the end backwards.
/// To start looking at a different index, slice the haystack first.
/// Consider using `last_index_of` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn last_index_of_linear(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    var i: usize = haystack.len - needle.len;
    while (true) : (i -= 1) {
        if (mem.eql(T, haystack[i..][0..needle.len], needle)) return i;
        if (i == 0) return null;
    }
}

/// Consider using `index_of_pos` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn index_of_pos_linear(comptime T: type, haystack: []const T, start_index: usize, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    var i: usize = start_index;
    const end = haystack.len - needle.len;
    while (i <= end) : (i += 1) {
        if (eql(T, haystack[i..][0..needle.len], needle)) return i;
    }
    return null;
}

test index_of_pos_linear {
    try testing.expect_equal(0, index_of_pos_linear(u8, "", 0, ""));
    try testing.expect_equal(0, index_of_pos_linear(u8, "123", 0, ""));

    try testing.expect_equal(null, index_of_pos_linear(u8, "", 0, "1"));
    try testing.expect_equal(0, index_of_pos_linear(u8, "1", 0, "1"));
    try testing.expect_equal(null, index_of_pos_linear(u8, "2", 0, "1"));
    try testing.expect_equal(1, index_of_pos_linear(u8, "21", 0, "1"));
    try testing.expect_equal(null, index_of_pos_linear(u8, "222", 0, "1"));

    try testing.expect_equal(null, index_of_pos_linear(u8, "", 0, "12"));
    try testing.expect_equal(null, index_of_pos_linear(u8, "1", 0, "12"));
    try testing.expect_equal(null, index_of_pos_linear(u8, "2", 0, "12"));
    try testing.expect_equal(0, index_of_pos_linear(u8, "12", 0, "12"));
    try testing.expect_equal(null, index_of_pos_linear(u8, "21", 0, "12"));
    try testing.expect_equal(1, index_of_pos_linear(u8, "212", 0, "12"));
    try testing.expect_equal(0, index_of_pos_linear(u8, "122", 0, "12"));
    try testing.expect_equal(1, index_of_pos_linear(u8, "212112", 0, "12"));
}

fn boyer_moore_horspool_preprocess_reverse(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = pattern.len - 1;
    // The first item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i > 0) : (i -= 1) {
        table[pattern[i]] = i;
    }
}

fn boyer_moore_horspool_preprocess(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = 0;
    // The last item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i < pattern.len - 1) : (i += 1) {
        table[pattern[i]] = pattern.len - 1 - i;
    }
}

/// Find the index in a slice of a sub-slice, searching from the end backwards.
/// To start looking at a different index, slice the haystack first.
/// Uses the Reverse Boyer-Moore-Horspool algorithm on large inputs;
/// `last_index_of_linear` on small inputs.
pub fn last_index_of(comptime T: type, haystack: []const T, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len == 0) return haystack.len;

    if (!std.meta.has_unique_representation(T) or haystack.len < 52 or needle.len <= 4)
        return last_index_of_linear(T, haystack, needle);

    const haystack_bytes = slice_as_bytes(haystack);
    const needle_bytes = slice_as_bytes(needle);

    var skip_table: [256]usize = undefined;
    boyer_moore_horspool_preprocess_reverse(needle_bytes, skip_table[0..]);

    var i: usize = haystack_bytes.len - needle_bytes.len;
    while (true) {
        if (i % @size_of(T) == 0 and mem.eql(u8, haystack_bytes[i .. i + needle_bytes.len], needle_bytes)) {
            return @div_exact(i, @size_of(T));
        }
        const skip = skip_table[haystack_bytes[i]];
        if (skip > i) break;
        i -= skip;
    }

    return null;
}

/// Uses Boyer-Moore-Horspool algorithm on large inputs; `index_of_pos_linear` on small inputs.
pub fn index_of_pos(comptime T: type, haystack: []const T, start_index: usize, needle: []const T) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len < 2) {
        if (needle.len == 0) return start_index;
        // index_of_scalar_pos is significantly faster than index_of_pos_linear
        return index_of_scalar_pos(T, haystack, start_index, needle[0]);
    }

    if (!std.meta.has_unique_representation(T) or haystack.len < 52 or needle.len <= 4)
        return index_of_pos_linear(T, haystack, start_index, needle);

    const haystack_bytes = slice_as_bytes(haystack);
    const needle_bytes = slice_as_bytes(needle);

    var skip_table: [256]usize = undefined;
    boyer_moore_horspool_preprocess(needle_bytes, skip_table[0..]);

    var i: usize = start_index * @size_of(T);
    while (i <= haystack_bytes.len - needle_bytes.len) {
        if (i % @size_of(T) == 0 and mem.eql(u8, haystack_bytes[i .. i + needle_bytes.len], needle_bytes)) {
            return @div_exact(i, @size_of(T));
        }
        i += skip_table[haystack_bytes[i + needle_bytes.len - 1]];
    }

    return null;
}

test index_of {
    try testing.expect(index_of(u8, "one two three four five six seven eight nine ten eleven", "three four").? == 8);
    try testing.expect(last_index_of(u8, "one two three four five six seven eight nine ten eleven", "three four").? == 8);
    try testing.expect(index_of(u8, "one two three four five six seven eight nine ten eleven", "two two") == null);
    try testing.expect(last_index_of(u8, "one two three four five six seven eight nine ten eleven", "two two") == null);

    try testing.expect(index_of(u8, "one two three four five six seven eight nine ten", "").? == 0);
    try testing.expect(last_index_of(u8, "one two three four five six seven eight nine ten", "").? == 48);

    try testing.expect(index_of(u8, "one two three four", "four").? == 14);
    try testing.expect(last_index_of(u8, "one two three two four", "two").? == 14);
    try testing.expect(index_of(u8, "one two three four", "gour") == null);
    try testing.expect(last_index_of(u8, "one two three four", "gour") == null);
    try testing.expect(index_of(u8, "foo", "foo").? == 0);
    try testing.expect(last_index_of(u8, "foo", "foo").? == 0);
    try testing.expect(index_of(u8, "foo", "fool") == null);
    try testing.expect(last_index_of(u8, "foo", "lfoo") == null);
    try testing.expect(last_index_of(u8, "foo", "fool") == null);

    try testing.expect(index_of(u8, "foo foo", "foo").? == 0);
    try testing.expect(last_index_of(u8, "foo foo", "foo").? == 4);
    try testing.expect(last_index_of_any(u8, "boo, cat", "abo").? == 6);
    try testing.expect(last_index_of_scalar(u8, "boo", 'o').? == 2);
}

test "index_of multibyte" {
    {
        // make haystack and needle long enough to trigger Boyer-Moore-Horspool algorithm
        const haystack = [1]u16{0} ** 100 ++ [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee, 0x00ff };
        const needle = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee };
        try testing.expect_equal(index_of_pos(u16, &haystack, 0, &needle), 100);

        // check for misaligned false positives (little and big endian)
        const needleLE = [_]u16{ 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff };
        try testing.expect_equal(index_of_pos(u16, &haystack, 0, &needleLE), null);
        const needleBE = [_]u16{ 0xaacc, 0xbbdd, 0xccee, 0xddff, 0xee00 };
        try testing.expect_equal(index_of_pos(u16, &haystack, 0, &needleBE), null);
    }

    {
        // make haystack and needle long enough to trigger Boyer-Moore-Horspool algorithm
        const haystack = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee, 0x00ff } ++ [1]u16{0} ** 100;
        const needle = [_]u16{ 0xbbaa, 0xccbb, 0xddcc, 0xeedd, 0xffee };
        try testing.expect_equal(last_index_of(u16, &haystack, &needle), 0);

        // check for misaligned false positives (little and big endian)
        const needleLE = [_]u16{ 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff };
        try testing.expect_equal(last_index_of(u16, &haystack, &needleLE), null);
        const needleBE = [_]u16{ 0xaacc, 0xbbdd, 0xccee, 0xddff, 0xee00 };
        try testing.expect_equal(last_index_of(u16, &haystack, &needleBE), null);
    }
}

test "index_of_pos empty needle" {
    try testing.expect_equal(index_of_pos(u8, "abracadabra", 5, ""), 5);
}

/// Returns the number of needles inside the haystack
/// needle.len must be > 0
/// does not count overlapping needles
pub fn count(comptime T: type, haystack: []const T, needle: []const T) usize {
    assert(needle.len > 0);
    var i: usize = 0;
    var found: usize = 0;

    while (index_of_pos(T, haystack, i, needle)) |idx| {
        i = idx + needle.len;
        found += 1;
    }

    return found;
}

test count {
    try testing.expect(count(u8, "", "h") == 0);
    try testing.expect(count(u8, "h", "h") == 1);
    try testing.expect(count(u8, "hh", "h") == 2);
    try testing.expect(count(u8, "world!", "hello") == 0);
    try testing.expect(count(u8, "hello world!", "hello") == 1);
    try testing.expect(count(u8, "   abcabc   abc", "abc") == 3);
    try testing.expect(count(u8, "udexdcbvbruhasdrw", "bruh") == 1);
    try testing.expect(count(u8, "foo bar", "o bar") == 1);
    try testing.expect(count(u8, "foofoofoo", "foo") == 3);
    try testing.expect(count(u8, "fffffff", "ff") == 3);
    try testing.expect(count(u8, "owowowu", "owowu") == 1);
}

/// Returns true if the haystack contains expected_count or more needles
/// needle.len must be > 0
/// does not count overlapping needles
pub fn contains_at_least(comptime T: type, haystack: []const T, expected_count: usize, needle: []const T) bool {
    assert(needle.len > 0);
    if (expected_count == 0) return true;

    var i: usize = 0;
    var found: usize = 0;

    while (index_of_pos(T, haystack, i, needle)) |idx| {
        i = idx + needle.len;
        found += 1;
        if (found == expected_count) return true;
    }
    return false;
}

test contains_at_least {
    try testing.expect(contains_at_least(u8, "aa", 0, "a"));
    try testing.expect(contains_at_least(u8, "aa", 1, "a"));
    try testing.expect(contains_at_least(u8, "aa", 2, "a"));
    try testing.expect(!contains_at_least(u8, "aa", 3, "a"));

    try testing.expect(contains_at_least(u8, "radaradar", 1, "radar"));
    try testing.expect(!contains_at_least(u8, "radaradar", 2, "radar"));

    try testing.expect(contains_at_least(u8, "radarradaradarradar", 3, "radar"));
    try testing.expect(!contains_at_least(u8, "radarradaradarradar", 4, "radar"));

    try testing.expect(contains_at_least(u8, "   radar      radar   ", 2, "radar"));
    try testing.expect(!contains_at_least(u8, "   radar      radar   ", 3, "radar"));
}

/// Reads an integer from memory with size equal to bytes.len.
/// T specifies the return type, which must be large enough to store
/// the result.
pub fn read_var_int(comptime ReturnType: type, bytes: []const u8, endian: Endian) ReturnType {
    var result: ReturnType = 0;
    switch (endian) {
        .big => {
            for (bytes) |b| {
                result = (result << 8) | b;
            }
        },
        .little => {
            const ShiftType = math.Log2Int(ReturnType);
            for (bytes, 0..) |b, index| {
                result = result | (@as(ReturnType, b) << @as(ShiftType, @int_cast(index * 8)));
            }
        },
    }
    return result;
}

/// Loads an integer from packed memory with provided bit_count, bit_offset, and signedness.
/// Asserts that T is large enough to store the read value.
///
/// Example:
///     const T = packed struct(u16){ a: u3, b: u7, c: u6 };
///     var st = T{ .a = 1, .b = 2, .c = 4 };
///     const b_field = read_var_packed_int(u64, std.mem.as_bytes(&st), @bit_offset_of(T, "b"), 7, builtin.cpu.arch.endian(), .unsigned);
///
pub fn read_var_packed_int(
    comptime T: type,
    bytes: []const u8,
    bit_offset: usize,
    bit_count: usize,
    endian: std.builtin.Endian,
    signedness: std.builtin.Signedness,
) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const iN = std.meta.Int(.signed, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const read_size = (bit_count + (bit_offset % 8) + 7) / 8;
    const bit_shift = @as(u3, @int_cast(bit_offset % 8));
    const pad = @as(Log2N, @int_cast(@bitSizeOf(T) - bit_count));

    const lowest_byte = switch (endian) {
        .big => bytes.len - (bit_offset / 8) - read_size,
        .little => bit_offset / 8,
    };
    const read_bytes = bytes[lowest_byte..][0..read_size];

    if (@bitSizeOf(T) <= 8) {
        // These are the same shifts/masks we perform below, but adds `@truncate`/`@int_cast`
        // where needed since int is smaller than a byte.
        const value = if (read_size == 1) b: {
            break :b @as(uN, @truncate(read_bytes[0] >> bit_shift));
        } else b: {
            const i: u1 = @int_from_bool(endian == .big);
            const head = @as(uN, @truncate(read_bytes[i] >> bit_shift));
            const tail_shift = @as(Log2N, @int_cast(@as(u4, 8) - bit_shift));
            const tail = @as(uN, @truncate(read_bytes[1 - i]));
            break :b (tail << tail_shift) | head;
        };
        switch (signedness) {
            .signed => return @as(T, @int_cast((@as(iN, @bit_cast(value)) << pad) >> pad)),
            .unsigned => return @as(T, @int_cast((@as(uN, @bit_cast(value)) << pad) >> pad)),
        }
    }

    // Copy the value out (respecting endianness), accounting for bit_shift
    var int: uN = 0;
    switch (endian) {
        .big => {
            for (read_bytes[0 .. read_size - 1]) |elem| {
                int = elem | (int << 8);
            }
            int = (read_bytes[read_size - 1] >> bit_shift) | (int << (@as(u4, 8) - bit_shift));
        },
        .little => {
            int = read_bytes[0] >> bit_shift;
            for (read_bytes[1..], 0..) |elem, i| {
                int |= (@as(uN, elem) << @as(Log2N, @int_cast((8 * (i + 1) - bit_shift))));
            }
        },
    }
    switch (signedness) {
        .signed => return @as(T, @int_cast((@as(iN, @bit_cast(int)) << pad) >> pad)),
        .unsigned => return @as(T, @int_cast((@as(uN, @bit_cast(int)) << pad) >> pad)),
    }
}

/// Reads an integer from memory with bit count specified by T.
/// The bit count of T must be evenly divisible by 8.
/// This function cannot fail and cannot cause undefined behavior.
pub inline fn read_int(comptime T: type, buffer: *const [@div_exact(@typeInfo(T).Int.bits, 8)]u8, endian: Endian) T {
    const value: T = @bit_cast(buffer.*);
    return if (endian == native_endian) value else @byte_swap(value);
}

test read_int {
    try testing.expect(read_int(u0, &[_]u8{}, .big) == 0x0);
    try testing.expect(read_int(u0, &[_]u8{}, .little) == 0x0);

    try testing.expect(read_int(u8, &[_]u8{0x32}, .big) == 0x32);
    try testing.expect(read_int(u8, &[_]u8{0x12}, .little) == 0x12);

    try testing.expect(read_int(u16, &[_]u8{ 0x12, 0x34 }, .big) == 0x1234);
    try testing.expect(read_int(u16, &[_]u8{ 0x12, 0x34 }, .little) == 0x3412);

    try testing.expect(read_int(u72, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24 }, .big) == 0x123456789abcdef024);
    try testing.expect(read_int(u72, &[_]u8{ 0xec, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }, .little) == 0xfedcba9876543210ec);

    try testing.expect(read_int(i8, &[_]u8{0xff}, .big) == -1);
    try testing.expect(read_int(i8, &[_]u8{0xfe}, .little) == -2);

    try testing.expect(read_int(i16, &[_]u8{ 0xff, 0xfd }, .big) == -3);
    try testing.expect(read_int(i16, &[_]u8{ 0xfc, 0xff }, .little) == -4);

    try more_read_int_tests();
    try comptime more_read_int_tests();
}

fn read_packed_int_little(comptime T: type, bytes: []const u8, bit_offset: usize) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @int_cast(bit_offset % 8));

    const load_size = (bit_count + 7) / 8;
    const load_tail_bits = @as(u3, @int_cast((load_size * 8) - bit_count));
    const LoadInt = std.meta.Int(.unsigned, load_size * 8);

    if (bit_count == 0)
        return 0;

    // Read by loading a LoadInt, and then follow it up with a 1-byte read
    // of the tail if bit_offset pushed us over a byte boundary.
    const read_bytes = bytes[bit_offset / 8 ..];
    const val = @as(uN, @truncate(read_int(LoadInt, read_bytes[0..load_size], .little) >> bit_shift));
    if (bit_shift > load_tail_bits) {
        const tail_bits = @as(Log2N, @int_cast(bit_shift - load_tail_bits));
        const tail_byte = read_bytes[load_size];
        const tail_truncated = if (bit_count < 8) @as(uN, @truncate(tail_byte)) else @as(uN, tail_byte);
        return @as(T, @bit_cast(val | (tail_truncated << (@as(Log2N, @truncate(bit_count)) -% tail_bits))));
    } else return @as(T, @bit_cast(val));
}

fn read_packed_int_big(comptime T: type, bytes: []const u8, bit_offset: usize) T {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @int_cast(bit_offset % 8));
    const byte_count = (@as(usize, bit_shift) + bit_count + 7) / 8;

    const load_size = (bit_count + 7) / 8;
    const load_tail_bits = @as(u3, @int_cast((load_size * 8) - bit_count));
    const LoadInt = std.meta.Int(.unsigned, load_size * 8);

    if (bit_count == 0)
        return 0;

    // Read by loading a LoadInt, and then follow it up with a 1-byte read
    // of the tail if bit_offset pushed us over a byte boundary.
    const end = bytes.len - (bit_offset / 8);
    const read_bytes = bytes[(end - byte_count)..end];
    const val = @as(uN, @truncate(read_int(LoadInt, bytes[(end - load_size)..end][0..load_size], .big) >> bit_shift));
    if (bit_shift > load_tail_bits) {
        const tail_bits = @as(Log2N, @int_cast(bit_shift - load_tail_bits));
        const tail_byte = if (bit_count < 8) @as(uN, @truncate(read_bytes[0])) else @as(uN, read_bytes[0]);
        return @as(T, @bit_cast(val | (tail_byte << (@as(Log2N, @truncate(bit_count)) -% tail_bits))));
    } else return @as(T, @bit_cast(val));
}

pub const readPackedIntNative = switch (native_endian) {
    .little => read_packed_int_little,
    .big => read_packed_int_big,
};

pub const readPackedIntForeign = switch (native_endian) {
    .little => read_packed_int_big,
    .big => read_packed_int_little,
};

/// Loads an integer from packed memory.
/// Asserts that buffer contains at least bit_offset + @bitSizeOf(T) bits.
///
/// Example:
///     const T = packed struct(u16){ a: u3, b: u7, c: u6 };
///     var st = T{ .a = 1, .b = 2, .c = 4 };
///     const b_field = read_packed_int(u7, std.mem.as_bytes(&st), @bit_offset_of(T, "b"), builtin.cpu.arch.endian());
///
pub fn read_packed_int(comptime T: type, bytes: []const u8, bit_offset: usize, endian: Endian) T {
    switch (endian) {
        .little => return read_packed_int_little(T, bytes, bit_offset),
        .big => return read_packed_int_big(T, bytes, bit_offset),
    }
}

test "comptime read/write int" {
    comptime {
        var bytes: [2]u8 = undefined;
        write_int(u16, &bytes, 0x1234, .little);
        const result = read_int(u16, &bytes, .big);
        try testing.expect(result == 0x3412);
    }
    comptime {
        var bytes: [2]u8 = undefined;
        write_int(u16, &bytes, 0x1234, .big);
        const result = read_int(u16, &bytes, .little);
        try testing.expect(result == 0x3412);
    }
}

/// Writes an integer to memory, storing it in twos-complement.
/// This function always succeeds, has defined behavior for all inputs, but
/// the integer bit width must be divisible by 8.
pub inline fn write_int(comptime T: type, buffer: *[@div_exact(@typeInfo(T).Int.bits, 8)]u8, value: T, endian: Endian) void {
    buffer.* = @bit_cast(if (endian == native_endian) value else @byte_swap(value));
}

test write_int {
    var buf0: [0]u8 = undefined;
    var buf1: [1]u8 = undefined;
    var buf2: [2]u8 = undefined;
    var buf9: [9]u8 = undefined;

    write_int(u0, &buf0, 0x0, .big);
    try testing.expect(eql(u8, buf0[0..], &[_]u8{}));
    write_int(u0, &buf0, 0x0, .little);
    try testing.expect(eql(u8, buf0[0..], &[_]u8{}));

    write_int(u8, &buf1, 0x12, .big);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0x12}));
    write_int(u8, &buf1, 0x34, .little);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0x34}));

    write_int(u16, &buf2, 0x1234, .big);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0x12, 0x34 }));
    write_int(u16, &buf2, 0x5678, .little);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0x78, 0x56 }));

    write_int(u72, &buf9, 0x123456789abcdef024, .big);
    try testing.expect(eql(u8, buf9[0..], &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x24 }));
    write_int(u72, &buf9, 0xfedcba9876543210ec, .little);
    try testing.expect(eql(u8, buf9[0..], &[_]u8{ 0xec, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe }));

    write_int(i8, &buf1, -1, .big);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0xff}));
    write_int(i8, &buf1, -2, .little);
    try testing.expect(eql(u8, buf1[0..], &[_]u8{0xfe}));

    write_int(i16, &buf2, -3, .big);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0xff, 0xfd }));
    write_int(i16, &buf2, -4, .little);
    try testing.expect(eql(u8, buf2[0..], &[_]u8{ 0xfc, 0xff }));
}

fn write_packed_int_little(comptime T: type, bytes: []u8, bit_offset: usize, value: T) void {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @int_cast(bit_offset % 8));

    const store_size = (@bitSizeOf(T) + 7) / 8;
    const store_tail_bits = @as(u3, @int_cast((store_size * 8) - bit_count));
    const StoreInt = std.meta.Int(.unsigned, store_size * 8);

    if (bit_count == 0)
        return;

    // Write by storing a StoreInt, and then follow it up with a 1-byte tail
    // if bit_offset pushed us over a byte boundary.
    const write_bytes = bytes[bit_offset / 8 ..];
    const head = write_bytes[0] & ((@as(u8, 1) << bit_shift) - 1);

    var write_value = (@as(StoreInt, @as(uN, @bit_cast(value))) << bit_shift) | @as(StoreInt, @int_cast(head));
    if (bit_shift > store_tail_bits) {
        const tail_len = @as(Log2N, @int_cast(bit_shift - store_tail_bits));
        write_bytes[store_size] &= ~((@as(u8, 1) << @as(u3, @int_cast(tail_len))) - 1);
        write_bytes[store_size] |= @as(u8, @int_cast((@as(uN, @bit_cast(value)) >> (@as(Log2N, @truncate(bit_count)) -% tail_len))));
    } else if (bit_shift < store_tail_bits) {
        const tail_len = store_tail_bits - bit_shift;
        const tail = write_bytes[store_size - 1] & (@as(u8, 0xfe) << (7 - tail_len));
        write_value |= @as(StoreInt, tail) << (8 * (store_size - 1));
    }

    write_int(StoreInt, write_bytes[0..store_size], write_value, .little);
}

fn write_packed_int_big(comptime T: type, bytes: []u8, bit_offset: usize, value: T) void {
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));
    const Log2N = std.math.Log2Int(T);

    const bit_count = @as(usize, @bitSizeOf(T));
    const bit_shift = @as(u3, @int_cast(bit_offset % 8));
    const byte_count = (bit_shift + bit_count + 7) / 8;

    const store_size = (@bitSizeOf(T) + 7) / 8;
    const store_tail_bits = @as(u3, @int_cast((store_size * 8) - bit_count));
    const StoreInt = std.meta.Int(.unsigned, store_size * 8);

    if (bit_count == 0)
        return;

    // Write by storing a StoreInt, and then follow it up with a 1-byte tail
    // if bit_offset pushed us over a byte boundary.
    const end = bytes.len - (bit_offset / 8);
    const write_bytes = bytes[(end - byte_count)..end];
    const head = write_bytes[byte_count - 1] & ((@as(u8, 1) << bit_shift) - 1);

    var write_value = (@as(StoreInt, @as(uN, @bit_cast(value))) << bit_shift) | @as(StoreInt, @int_cast(head));
    if (bit_shift > store_tail_bits) {
        const tail_len = @as(Log2N, @int_cast(bit_shift - store_tail_bits));
        write_bytes[0] &= ~((@as(u8, 1) << @as(u3, @int_cast(tail_len))) - 1);
        write_bytes[0] |= @as(u8, @int_cast((@as(uN, @bit_cast(value)) >> (@as(Log2N, @truncate(bit_count)) -% tail_len))));
    } else if (bit_shift < store_tail_bits) {
        const tail_len = store_tail_bits - bit_shift;
        const tail = write_bytes[0] & (@as(u8, 0xfe) << (7 - tail_len));
        write_value |= @as(StoreInt, tail) << (8 * (store_size - 1));
    }

    write_int(StoreInt, write_bytes[(byte_count - store_size)..][0..store_size], write_value, .big);
}

pub const writePackedIntNative = switch (native_endian) {
    .little => write_packed_int_little,
    .big => write_packed_int_big,
};

pub const writePackedIntForeign = switch (native_endian) {
    .little => write_packed_int_big,
    .big => write_packed_int_little,
};

/// Stores an integer to packed memory.
/// Asserts that buffer contains at least bit_offset + @bitSizeOf(T) bits.
///
/// Example:
///     const T = packed struct(u16){ a: u3, b: u7, c: u6 };
///     var st = T{ .a = 1, .b = 2, .c = 4 };
///     // st.b = 0x7f;
///     write_packed_int(u7, std.mem.as_bytes(&st), @bit_offset_of(T, "b"), 0x7f, builtin.cpu.arch.endian());
///
pub fn write_packed_int(comptime T: type, bytes: []u8, bit_offset: usize, value: T, endian: Endian) void {
    switch (endian) {
        .little => write_packed_int_little(T, bytes, bit_offset, value),
        .big => write_packed_int_big(T, bytes, bit_offset, value),
    }
}

/// Stores an integer to packed memory with provided bit_count, bit_offset, and signedness.
/// If negative, the written value is sign-extended.
///
/// Example:
///     const T = packed struct(u16){ a: u3, b: u7, c: u6 };
///     var st = T{ .a = 1, .b = 2, .c = 4 };
///     // st.b = 0x7f;
///     var value: u64 = 0x7f;
///     write_var_packed_int(std.mem.as_bytes(&st), @bit_offset_of(T, "b"), 7, value, builtin.cpu.arch.endian());
///
pub fn write_var_packed_int(bytes: []u8, bit_offset: usize, bit_count: usize, value: anytype, endian: std.builtin.Endian) void {
    const T = @TypeOf(value);
    const uN = std.meta.Int(.unsigned, @bitSizeOf(T));

    const bit_shift = @as(u3, @int_cast(bit_offset % 8));
    const write_size = (bit_count + bit_shift + 7) / 8;
    const lowest_byte = switch (endian) {
        .big => bytes.len - (bit_offset / 8) - write_size,
        .little => bit_offset / 8,
    };
    const write_bytes = bytes[lowest_byte..][0..write_size];

    if (write_size == 1) {
        // Single byte writes are handled specially, since we need to mask bits
        // on both ends of the byte.
        const mask = (@as(u8, 0xff) >> @as(u3, @int_cast(8 - bit_count)));
        const new_bits = @as(u8, @int_cast(@as(uN, @bit_cast(value)) & mask)) << bit_shift;
        write_bytes[0] = (write_bytes[0] & ~(mask << bit_shift)) | new_bits;
        return;
    }

    var remaining: T = value;

    // Iterate bytes forward for Little-endian, backward for Big-endian
    const delta: i2 = if (endian == .big) -1 else 1;
    const start = if (endian == .big) @as(isize, @int_cast(write_bytes.len - 1)) else 0;

    var i: isize = start; // isize for signed index arithmetic

    // Write first byte, using a mask to protects bits preceding bit_offset
    const head_mask = @as(u8, 0xff) >> bit_shift;
    write_bytes[@int_cast(i)] &= ~(head_mask << bit_shift);
    write_bytes[@int_cast(i)] |= @as(u8, @int_cast(@as(uN, @bit_cast(remaining)) & head_mask)) << bit_shift;
    remaining = math.shr(T, remaining, @as(u4, 8) - bit_shift);
    i += delta;

    // Write bytes[1..bytes.len - 1]
    if (@bitSizeOf(T) > 8) {
        const loop_end = start + delta * (@as(isize, @int_cast(write_size)) - 1);
        while (i != loop_end) : (i += delta) {
            write_bytes[@as(usize, @int_cast(i))] = @as(u8, @truncate(@as(uN, @bit_cast(remaining))));
            remaining >>= 8;
        }
    }

    // Write last byte, using a mask to protect bits following bit_offset + bit_count
    const following_bits = -%@as(u3, @truncate(bit_shift + bit_count));
    const tail_mask = (@as(u8, 0xff) << following_bits) >> following_bits;
    write_bytes[@as(usize, @int_cast(i))] &= ~tail_mask;
    write_bytes[@as(usize, @int_cast(i))] |= @as(u8, @int_cast(@as(uN, @bit_cast(remaining)) & tail_mask));
}

/// Swap the byte order of all the members of the fields of a struct
/// (Changing their endianness)
pub fn byte_swap_all_fields(comptime S: type, ptr: *S) void {
    switch (@typeInfo(S)) {
        .Struct => {
            inline for (std.meta.fields(S)) |f| {
                switch (@typeInfo(f.type)) {
                    .Struct => |struct_info| if (struct_info.backing_integer) |Int| {
                        @field(ptr, f.name) = @bit_cast(@byte_swap(@as(Int, @bit_cast(@field(ptr, f.name)))));
                    } else {
                        byte_swap_all_fields(f.type, &@field(ptr, f.name));
                    },
                    .Array => byte_swap_all_fields(f.type, &@field(ptr, f.name)),
                    .Enum => {
                        @field(ptr, f.name) = @enumFromInt(@byte_swap(@int_from_enum(@field(ptr, f.name))));
                    },
                    else => {
                        @field(ptr, f.name) = @byte_swap(@field(ptr, f.name));
                    },
                }
            }
        },
        .Array => {
            for (ptr) |*item| {
                switch (@typeInfo(@TypeOf(item.*))) {
                    .Struct, .Array => byte_swap_all_fields(@TypeOf(item.*), item),
                    .Enum => {
                        item.* = @enumFromInt(@byte_swap(@int_from_enum(item.*)));
                    },
                    else => {
                        item.* = @byte_swap(item.*);
                    },
                }
            }
        },
        else => @compile_error("byte_swap_all_fields expects a struct or array as the first argument"),
    }
}

test byte_swap_all_fields {
    const T = extern struct {
        f0: u8,
        f1: u16,
        f2: u32,
        f3: [1]u8,
    };
    const K = extern struct {
        f0: u8,
        f1: T,
        f2: u16,
        f3: [1]u8,
    };
    var s = T{
        .f0 = 0x12,
        .f1 = 0x1234,
        .f2 = 0x12345678,
        .f3 = .{0x12},
    };
    var k = K{
        .f0 = 0x12,
        .f1 = s,
        .f2 = 0x1234,
        .f3 = .{0x12},
    };
    byte_swap_all_fields(T, &s);
    byte_swap_all_fields(K, &k);
    try std.testing.expect_equal(T{
        .f0 = 0x12,
        .f1 = 0x3412,
        .f2 = 0x78563412,
        .f3 = .{0x12},
    }, s);
    try std.testing.expect_equal(K{
        .f0 = 0x12,
        .f1 = s,
        .f2 = 0x3412,
        .f3 = .{0x12},
    }, k);
}

/// Deprecated: use `tokenize_any`, `tokenize_sequence`, or `tokenize_scalar`
pub const tokenize = tokenize_any;

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// any of the items in `delimiters`.
///
/// `tokenize_any(u8, "   abc|def ||  ghi  ", " |")` will return slices
/// for "abc", "def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `tokenize_sequence`, `tokenize_scalar`,
///           `split_sequence`,`split_any`, `split_scalar`,
///           `split_backwards_sequence`, `split_backwards_any`, and `split_backwards_scalar`
pub fn tokenize_any(comptime T: type, buffer: []const T, delimiters: []const T) TokenIterator(T, .any) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// the sequence in `delimiter`.
///
/// `tokenize_sequence(u8, "<>abc><def<><>ghi", "<>")` will return slices
/// for "abc><def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `tokenize_any`, `tokenize_scalar`,
///           `split_sequence`,`split_any`, and `split_scalar`
///           `split_backwards_sequence`, `split_backwards_any`, and `split_backwards_scalar`
pub fn tokenize_sequence(comptime T: type, buffer: []const T, delimiter: []const T) TokenIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that are not
/// `delimiter`.
///
/// `tokenize_scalar(u8, "   abc def     ghi  ", ' ')` will return slices
/// for "abc", "def", "ghi", null, in that order.
///
/// If `buffer` is empty, the iterator will return null.
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `tokenize_any`, `tokenize_sequence`,
///           `split_sequence`,`split_any`, and `split_scalar`
///           `split_backwards_sequence`, `split_backwards_any`, and `split_backwards_scalar`
pub fn tokenize_scalar(comptime T: type, buffer: []const T, delimiter: T) TokenIterator(T, .scalar) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test tokenize_scalar {
    var it = tokenize_scalar(u8, "   abc def   ghi  ", ' ');
    try testing.expect(eql(u8, it.next().?, "abc"));
    try testing.expect(eql(u8, it.peek().?, "def"));
    try testing.expect(eql(u8, it.next().?, "def"));
    try testing.expect(eql(u8, it.next().?, "ghi"));
    try testing.expect(it.next() == null);

    it = tokenize_scalar(u8, "..\\bob", '\\');
    try testing.expect(eql(u8, it.next().?, ".."));
    try testing.expect(eql(u8, "..", "..\\bob"[0..it.index]));
    try testing.expect(eql(u8, it.next().?, "bob"));
    try testing.expect(it.next() == null);

    it = tokenize_scalar(u8, "//a/b", '/');
    try testing.expect(eql(u8, it.next().?, "a"));
    try testing.expect(eql(u8, it.next().?, "b"));
    try testing.expect(eql(u8, "//a/b", "//a/b"[0..it.index]));
    try testing.expect(it.next() == null);

    it = tokenize_scalar(u8, "|", '|');
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenize_scalar(u8, "", '|');
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenize_scalar(u8, "hello", ' ');
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = tokenize_scalar(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("hello"),
        ' ',
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("hello")));
    try testing.expect(it16.next() == null);
}

test tokenize_any {
    var it = tokenize_any(u8, "a|b,c/d e", " /,|");
    try testing.expect(eql(u8, it.next().?, "a"));
    try testing.expect(eql(u8, it.peek().?, "b"));
    try testing.expect(eql(u8, it.next().?, "b"));
    try testing.expect(eql(u8, it.next().?, "c"));
    try testing.expect(eql(u8, it.next().?, "d"));
    try testing.expect(eql(u8, it.next().?, "e"));
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    it = tokenize_any(u8, "hello", "");
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = tokenize_any(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a|b,c/d e"),
        std.unicode.utf8_to_utf16_le_string_literal(" /,|"),
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("a")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("e")));
    try testing.expect(it16.next() == null);
}

test tokenize_sequence {
    var it = tokenize_sequence(u8, "a<>b<><>c><>d><", "<>");
    try testing.expect_equal_strings("a", it.next().?);
    try testing.expect_equal_strings("b", it.peek().?);
    try testing.expect_equal_strings("b", it.next().?);
    try testing.expect_equal_strings("c>", it.next().?);
    try testing.expect_equal_strings("d><", it.next().?);
    try testing.expect(it.next() == null);
    try testing.expect(it.peek() == null);

    var it16 = tokenize_sequence(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a<>b<><>c><>d><"),
        std.unicode.utf8_to_utf16_le_string_literal("<>"),
    );
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("a")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c>")));
    try testing.expect(eql(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d><")));
    try testing.expect(it16.next() == null);
}

test "tokenize (reset)" {
    {
        var it = tokenize_any(u8, "   abc def   ghi  ", " ");
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = tokenize_sequence(u8, "<><>abc<>def<><>ghi<>", "<>");
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = tokenize_scalar(u8, "   abc def   ghi  ", ' ');
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
}

/// Deprecated: use `split_sequence`, `split_any`, or `split_scalar`
pub const split = split_sequence;

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by the byte sequence in `delimiter`.
///
/// `split_sequence(u8, "abc||def||||ghi", "||")` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `split_any`, `split_scalar`, `split_backwards_sequence`,
///           `split_backwards_any`,`split_backwards_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_sequence(comptime T: type, buffer: []const T, delimiter: []const T) SplitIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by any item in `delimiters`.
///
/// `split_any(u8, "abc,def||ghi", "|,")` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `split_sequence`, `split_scalar`, `split_backwards_sequence`,
///           `split_backwards_any`,`split_backwards_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_any(comptime T: type, buffer: []const T, delimiters: []const T) SplitIterator(T, .any) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates over the slices of `buffer` that
/// are separated by `delimiter`.
///
/// `split_scalar(u8, "abc|def||ghi", '|')` will return slices
/// for "abc", "def", "", "ghi", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `split_sequence`, `split_any`, `split_backwards_sequence`,
///           `split_backwards_any`,`split_backwards_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_scalar(comptime T: type, buffer: []const T, delimiter: T) SplitIterator(T, .scalar) {
    return .{
        .index = 0,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test split_scalar {
    var it = split_scalar(u8, "abc|def||ghi", '|');
    try testing.expect_equal_slices(u8, it.rest(), "abc|def||ghi");
    try testing.expect_equal_slices(u8, it.first(), "abc");

    try testing.expect_equal_slices(u8, it.rest(), "def||ghi");
    try testing.expect_equal_slices(u8, it.peek().?, "def");
    try testing.expect_equal_slices(u8, it.next().?, "def");

    try testing.expect_equal_slices(u8, it.rest(), "|ghi");
    try testing.expect_equal_slices(u8, it.next().?, "");

    try testing.expect_equal_slices(u8, it.rest(), "ghi");
    try testing.expect_equal_slices(u8, it.peek().?, "ghi");
    try testing.expect_equal_slices(u8, it.next().?, "ghi");

    try testing.expect_equal_slices(u8, it.rest(), "");
    try testing.expect(it.peek() == null);
    try testing.expect(it.next() == null);

    it = split_scalar(u8, "", '|');
    try testing.expect_equal_slices(u8, it.first(), "");
    try testing.expect(it.next() == null);

    it = split_scalar(u8, "|", '|');
    try testing.expect_equal_slices(u8, it.first(), "");
    try testing.expect_equal_slices(u8, it.next().?, "");
    try testing.expect(it.peek() == null);
    try testing.expect(it.next() == null);

    it = split_scalar(u8, "hello", ' ');
    try testing.expect_equal_slices(u8, it.first(), "hello");
    try testing.expect(it.next() == null);

    var it16 = split_scalar(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("hello"),
        ' ',
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("hello"));
    try testing.expect(it16.next() == null);
}

test split_sequence {
    var it = split_sequence(u8, "a, b ,, c, d, e", ", ");
    try testing.expect_equal_slices(u8, it.first(), "a");
    try testing.expect_equal_slices(u8, it.rest(), "b ,, c, d, e");
    try testing.expect_equal_slices(u8, it.next().?, "b ,");
    try testing.expect_equal_slices(u8, it.next().?, "c");
    try testing.expect_equal_slices(u8, it.next().?, "d");
    try testing.expect_equal_slices(u8, it.next().?, "e");
    try testing.expect(it.next() == null);

    var it16 = split_sequence(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a, b ,, c, d, e"),
        std.unicode.utf8_to_utf16_le_string_literal(", "),
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("a"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b ,"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("e"));
    try testing.expect(it16.next() == null);
}

test split_any {
    var it = split_any(u8, "a,b, c d e", ", ");
    try testing.expect_equal_slices(u8, it.first(), "a");
    try testing.expect_equal_slices(u8, it.rest(), "b, c d e");
    try testing.expect_equal_slices(u8, it.next().?, "b");
    try testing.expect_equal_slices(u8, it.next().?, "");
    try testing.expect_equal_slices(u8, it.next().?, "c");
    try testing.expect_equal_slices(u8, it.next().?, "d");
    try testing.expect_equal_slices(u8, it.next().?, "e");
    try testing.expect(it.next() == null);

    it = split_any(u8, "hello", "");
    try testing.expect(eql(u8, it.next().?, "hello"));
    try testing.expect(it.next() == null);

    var it16 = split_any(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a,b, c d e"),
        std.unicode.utf8_to_utf16_le_string_literal(", "),
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("a"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal(""));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("e"));
    try testing.expect(it16.next() == null);
}

test "split (reset)" {
    {
        var it = split_sequence(u8, "abc def ghi", " ");
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = split_any(u8, "abc def,ghi", " ,");
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
    {
        var it = split_scalar(u8, "abc def ghi", ' ');
        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "abc"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "ghi"));
        try testing.expect(it.next() == null);
    }
}

/// Deprecated: use `split_backwards_sequence`, `split_backwards_any`, or `split_backwards_scalar`
pub const splitBackwards = split_backwards_sequence;

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by the sequence in `delimiter`.
///
/// `split_backwards_sequence(u8, "abc||def||||ghi", "||")` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
/// The delimiter length must not be zero.
///
/// See also: `split_backwards_any`, `split_backwards_scalar`,
///           `split_sequence`, `split_any`,`split_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_backwards_sequence(comptime T: type, buffer: []const T, delimiter: []const T) SplitBackwardsIterator(T, .sequence) {
    assert(delimiter.len != 0);
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by any item in `delimiters`.
///
/// `split_backwards_any(u8, "abc,def||ghi", "|,")` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If none of `delimiters` exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `split_backwards_sequence`, `split_backwards_scalar`,
///           `split_sequence`, `split_any`,`split_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_backwards_any(comptime T: type, buffer: []const T, delimiters: []const T) SplitBackwardsIterator(T, .any) {
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiters,
    };
}

/// Returns an iterator that iterates backwards over the slices of `buffer` that
/// are separated by `delimiter`.
///
/// `split_backwards_scalar(u8, "abc|def||ghi", '|')` will return slices
/// for "ghi", "", "def", "abc", null, in that order.
///
/// If `delimiter` does not exist in buffer,
/// the iterator will return `buffer`, null, in that order.
///
/// See also: `split_backwards_sequence`, `split_backwards_any`,
///           `split_sequence`, `split_any`,`split_scalar`,
///           `tokenize_any`, `tokenize_sequence`, and `tokenize_scalar`.
pub fn split_backwards_scalar(comptime T: type, buffer: []const T, delimiter: T) SplitBackwardsIterator(T, .scalar) {
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

test split_backwards_scalar {
    var it = split_backwards_scalar(u8, "abc|def||ghi", '|');
    try testing.expect_equal_slices(u8, it.rest(), "abc|def||ghi");
    try testing.expect_equal_slices(u8, it.first(), "ghi");

    try testing.expect_equal_slices(u8, it.rest(), "abc|def|");
    try testing.expect_equal_slices(u8, it.next().?, "");

    try testing.expect_equal_slices(u8, it.rest(), "abc|def");
    try testing.expect_equal_slices(u8, it.next().?, "def");

    try testing.expect_equal_slices(u8, it.rest(), "abc");
    try testing.expect_equal_slices(u8, it.next().?, "abc");

    try testing.expect_equal_slices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    it = split_backwards_scalar(u8, "", '|');
    try testing.expect_equal_slices(u8, it.first(), "");
    try testing.expect(it.next() == null);

    it = split_backwards_scalar(u8, "|", '|');
    try testing.expect_equal_slices(u8, it.first(), "");
    try testing.expect_equal_slices(u8, it.next().?, "");
    try testing.expect(it.next() == null);

    it = split_backwards_scalar(u8, "hello", ' ');
    try testing.expect_equal_slices(u8, it.first(), "hello");
    try testing.expect(it.next() == null);

    var it16 = split_backwards_scalar(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("hello"),
        ' ',
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("hello"));
    try testing.expect(it16.next() == null);
}

test split_backwards_sequence {
    var it = split_backwards_sequence(u8, "a, b ,, c, d, e", ", ");
    try testing.expect_equal_slices(u8, it.rest(), "a, b ,, c, d, e");
    try testing.expect_equal_slices(u8, it.first(), "e");

    try testing.expect_equal_slices(u8, it.rest(), "a, b ,, c, d");
    try testing.expect_equal_slices(u8, it.next().?, "d");

    try testing.expect_equal_slices(u8, it.rest(), "a, b ,, c");
    try testing.expect_equal_slices(u8, it.next().?, "c");

    try testing.expect_equal_slices(u8, it.rest(), "a, b ,");
    try testing.expect_equal_slices(u8, it.next().?, "b ,");

    try testing.expect_equal_slices(u8, it.rest(), "a");
    try testing.expect_equal_slices(u8, it.next().?, "a");

    try testing.expect_equal_slices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    var it16 = split_backwards_sequence(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a, b ,, c, d, e"),
        std.unicode.utf8_to_utf16_le_string_literal(", "),
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("e"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b ,"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("a"));
    try testing.expect(it16.next() == null);
}

test split_backwards_any {
    var it = split_backwards_any(u8, "a,b, c d e", ", ");
    try testing.expect_equal_slices(u8, it.rest(), "a,b, c d e");
    try testing.expect_equal_slices(u8, it.first(), "e");

    try testing.expect_equal_slices(u8, it.rest(), "a,b, c d");
    try testing.expect_equal_slices(u8, it.next().?, "d");

    try testing.expect_equal_slices(u8, it.rest(), "a,b, c");
    try testing.expect_equal_slices(u8, it.next().?, "c");

    try testing.expect_equal_slices(u8, it.rest(), "a,b,");
    try testing.expect_equal_slices(u8, it.next().?, "");

    try testing.expect_equal_slices(u8, it.rest(), "a,b");
    try testing.expect_equal_slices(u8, it.next().?, "b");

    try testing.expect_equal_slices(u8, it.rest(), "a");
    try testing.expect_equal_slices(u8, it.next().?, "a");

    try testing.expect_equal_slices(u8, it.rest(), "");
    try testing.expect(it.next() == null);

    var it16 = split_backwards_any(
        u16,
        std.unicode.utf8_to_utf16_le_string_literal("a,b, c d e"),
        std.unicode.utf8_to_utf16_le_string_literal(", "),
    );
    try testing.expect_equal_slices(u16, it16.first(), std.unicode.utf8_to_utf16_le_string_literal("e"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("d"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("c"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal(""));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("b"));
    try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("a"));
    try testing.expect(it16.next() == null);
}

test "splitBackwards (reset)" {
    {
        var it = split_backwards_sequence(u8, "abc def ghi", " ");
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
    {
        var it = split_backwards_any(u8, "abc def,ghi", " ,");
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
    {
        var it = split_backwards_scalar(u8, "abc def ghi", ' ');
        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));

        it.reset();

        try testing.expect(eql(u8, it.first(), "ghi"));
        try testing.expect(eql(u8, it.next().?, "def"));
        try testing.expect(eql(u8, it.next().?, "abc"));
        try testing.expect(it.next() == null);
    }
}

/// Returns an iterator with a sliding window of slices for `buffer`.
/// The sliding window has length `size` and on every iteration moves
/// forward by `advance`.
///
/// Extract data for moving average with:
/// `window(u8, "abcdefg", 3, 1)` will return slices
/// "abc", "bcd", "cde", "def", "efg", null, in that order.
///
/// Chunk or split every N items with:
/// `window(u8, "abcdefg", 3, 3)` will return slices
/// "abc", "def", "g", null, in that order.
///
/// Pick every even index with:
/// `window(u8, "abcdefg", 1, 2)` will return slices
/// "a", "c", "e", "g" null, in that order.
///
/// The `size` and `advance` must be not be zero.
pub fn window(comptime T: type, buffer: []const T, size: usize, advance: usize) WindowIterator(T) {
    assert(size != 0);
    assert(advance != 0);
    return .{
        .index = 0,
        .buffer = buffer,
        .size = size,
        .advance = advance,
    };
}

test window {
    {
        // moving average size 3
        var it = window(u8, "abcdefg", 3, 1);
        try testing.expect_equal_slices(u8, it.next().?, "abc");
        try testing.expect_equal_slices(u8, it.next().?, "bcd");
        try testing.expect_equal_slices(u8, it.next().?, "cde");
        try testing.expect_equal_slices(u8, it.next().?, "def");
        try testing.expect_equal_slices(u8, it.next().?, "efg");
        try testing.expect_equal(it.next(), null);

        // multibyte
        var it16 = window(u16, std.unicode.utf8_to_utf16_le_string_literal("abcdefg"), 3, 1);
        try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("abc"));
        try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("bcd"));
        try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("cde"));
        try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("def"));
        try testing.expect_equal_slices(u16, it16.next().?, std.unicode.utf8_to_utf16_le_string_literal("efg"));
        try testing.expect_equal(it16.next(), null);
    }

    {
        // chunk/split every 3
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expect_equal_slices(u8, it.next().?, "abc");
        try testing.expect_equal_slices(u8, it.next().?, "def");
        try testing.expect_equal_slices(u8, it.next().?, "g");
        try testing.expect_equal(it.next(), null);
    }

    {
        // pick even
        var it = window(u8, "abcdefg", 1, 2);
        try testing.expect_equal_slices(u8, it.next().?, "a");
        try testing.expect_equal_slices(u8, it.next().?, "c");
        try testing.expect_equal_slices(u8, it.next().?, "e");
        try testing.expect_equal_slices(u8, it.next().?, "g");
        try testing.expect_equal(it.next(), null);
    }

    {
        // empty
        var it = window(u8, "", 1, 1);
        try testing.expect_equal_slices(u8, it.next().?, "");
        try testing.expect_equal(it.next(), null);

        it = window(u8, "", 10, 1);
        try testing.expect_equal_slices(u8, it.next().?, "");
        try testing.expect_equal(it.next(), null);

        it = window(u8, "", 1, 10);
        try testing.expect_equal_slices(u8, it.next().?, "");
        try testing.expect_equal(it.next(), null);

        it = window(u8, "", 10, 10);
        try testing.expect_equal_slices(u8, it.next().?, "");
        try testing.expect_equal(it.next(), null);
    }

    {
        // first
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expect_equal_slices(u8, it.first(), "abc");
        it.reset();
        try testing.expect_equal_slices(u8, it.next().?, "abc");
    }

    {
        // reset
        var it = window(u8, "abcdefg", 3, 3);
        try testing.expect_equal_slices(u8, it.next().?, "abc");
        try testing.expect_equal_slices(u8, it.next().?, "def");
        try testing.expect_equal_slices(u8, it.next().?, "g");
        try testing.expect_equal(it.next(), null);

        it.reset();
        try testing.expect_equal_slices(u8, it.next().?, "abc");
        try testing.expect_equal_slices(u8, it.next().?, "def");
        try testing.expect_equal_slices(u8, it.next().?, "g");
        try testing.expect_equal(it.next(), null);
    }
}

pub fn WindowIterator(comptime T: type) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        size: usize,
        advance: usize,

        const Self = @This();

        /// Returns a slice of the first window. This never fails.
        /// Call this only to get the first window and then use `next` to get
        /// all subsequent windows.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == 0);
            return self.next().?;
        }

        /// Returns a slice of the next window, or null if window is at end.
        pub fn next(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const next_index = start + self.advance;
            const end = if (start + self.size < self.buffer.len and next_index < self.buffer.len) blk: {
                self.index = next_index;
                break :blk start + self.size;
            } else blk: {
                self.index = null;
                break :blk self.buffer.len;
            };

            return self.buffer[start..end];
        }

        /// Resets the iterator to the initial window.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }
    };
}

pub fn starts_with(comptime T: type, haystack: []const T, needle: []const T) bool {
    return if (needle.len > haystack.len) false else eql(T, haystack[0..needle.len], needle);
}

test starts_with {
    try testing.expect(starts_with(u8, "Bob", "Bo"));
    try testing.expect(!starts_with(u8, "Needle in haystack", "haystack"));
}

pub fn ends_with(comptime T: type, haystack: []const T, needle: []const T) bool {
    return if (needle.len > haystack.len) false else eql(T, haystack[haystack.len - needle.len ..], needle);
}

test ends_with {
    try testing.expect(ends_with(u8, "Needle in haystack", "haystack"));
    try testing.expect(!ends_with(u8, "Bob", "Bo"));
}

pub const DelimiterType = enum { sequence, any, scalar };

pub fn TokenIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },
        index: usize,

        const Self = @This();

        /// Returns a slice of the current token, or null if tokenization is
        /// complete, and advances to the next token.
        pub fn next(self: *Self) ?[]const T {
            const result = self.peek() orelse return null;
            self.index += result.len;
            return result;
        }

        /// Returns a slice of the current token, or null if tokenization is
        /// complete. Does not advance to the next token.
        pub fn peek(self: *Self) ?[]const T {
            // move to beginning of token
            while (self.index < self.buffer.len and self.is_delimiter(self.index)) : (self.index += switch (delimiter_type) {
                .sequence => self.delimiter.len,
                .any, .scalar => 1,
            }) {}
            const start = self.index;
            if (start == self.buffer.len) {
                return null;
            }

            // move to end of token
            var end = start;
            while (end < self.buffer.len and !self.is_delimiter(end)) : (end += 1) {}

            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            // move to beginning of token
            var index: usize = self.index;
            while (index < self.buffer.len and self.is_delimiter(index)) : (index += switch (delimiter_type) {
                .sequence => self.delimiter.len,
                .any, .scalar => 1,
            }) {}
            return self.buffer[index..];
        }

        /// Resets the iterator to the initial token.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }

        fn is_delimiter(self: Self, index: usize) bool {
            switch (delimiter_type) {
                .sequence => return starts_with(T, self.buffer[index..], self.delimiter),
                .any => {
                    const item = self.buffer[index];
                    for (self.delimiter) |delimiter_item| {
                        if (item == delimiter_item) {
                            return true;
                        }
                    }
                    return false;
                },
                .scalar => return self.buffer[index] == self.delimiter,
            }
        }
    };
}

pub fn SplitIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },

        const Self = @This();

        /// Returns a slice of the first field. This never fails.
        /// Call this only to get the first field and then use `next` to get all subsequent fields.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == 0);
            return self.next().?;
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        pub fn next(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const end = if (switch (delimiter_type) {
                .sequence => index_of_pos(T, self.buffer, start, self.delimiter),
                .any => index_of_any_pos(T, self.buffer, start, self.delimiter),
                .scalar => index_of_scalar_pos(T, self.buffer, start, self.delimiter),
            }) |delim_start| blk: {
                self.index = delim_start + switch (delimiter_type) {
                    .sequence => self.delimiter.len,
                    .any, .scalar => 1,
                };
                break :blk delim_start;
            } else blk: {
                self.index = null;
                break :blk self.buffer.len;
            };
            return self.buffer[start..end];
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        /// This method does not alter self.index.
        pub fn peek(self: *Self) ?[]const T {
            const start = self.index orelse return null;
            const end = if (switch (delimiter_type) {
                .sequence => index_of_pos(T, self.buffer, start, self.delimiter),
                .any => index_of_any_pos(T, self.buffer, start, self.delimiter),
                .scalar => index_of_scalar_pos(T, self.buffer, start, self.delimiter),
            }) |delim_start| delim_start else self.buffer.len;
            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            const end = self.buffer.len;
            const start = self.index orelse end;
            return self.buffer[start..end];
        }

        /// Resets the iterator to the initial slice.
        pub fn reset(self: *Self) void {
            self.index = 0;
        }
    };
}

pub fn SplitBackwardsIterator(comptime T: type, comptime delimiter_type: DelimiterType) type {
    return struct {
        buffer: []const T,
        index: ?usize,
        delimiter: switch (delimiter_type) {
            .sequence, .any => []const T,
            .scalar => T,
        },

        const Self = @This();

        /// Returns a slice of the first field. This never fails.
        /// Call this only to get the first field and then use `next` to get all subsequent fields.
        pub fn first(self: *Self) []const T {
            assert(self.index.? == self.buffer.len);
            return self.next().?;
        }

        /// Returns a slice of the next field, or null if splitting is complete.
        pub fn next(self: *Self) ?[]const T {
            const end = self.index orelse return null;
            const start = if (switch (delimiter_type) {
                .sequence => last_index_of(T, self.buffer[0..end], self.delimiter),
                .any => last_index_of_any(T, self.buffer[0..end], self.delimiter),
                .scalar => last_index_of_scalar(T, self.buffer[0..end], self.delimiter),
            }) |delim_start| blk: {
                self.index = delim_start;
                break :blk delim_start + switch (delimiter_type) {
                    .sequence => self.delimiter.len,
                    .any, .scalar => 1,
                };
            } else blk: {
                self.index = null;
                break :blk 0;
            };
            return self.buffer[start..end];
        }

        /// Returns a slice of the remaining bytes. Does not affect iterator state.
        pub fn rest(self: Self) []const T {
            const end = self.index orelse 0;
            return self.buffer[0..end];
        }

        /// Resets the iterator to the initial slice.
        pub fn reset(self: *Self) void {
            self.index = self.buffer.len;
        }
    };
}

/// Naively combines a series of slices with a separator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join(allocator: Allocator, separator: []const u8, slices: []const []const u8) Allocator.Error![]u8 {
    return join_maybe_z(allocator, separator, slices, false);
}

/// Naively combines a series of slices with a separator and null terminator.
/// Allocates memory for the result, which must be freed by the caller.
pub fn join_z(allocator: Allocator, separator: []const u8, slices: []const []const u8) Allocator.Error![:0]u8 {
    const out = try join_maybe_z(allocator, separator, slices, true);
    return out[0 .. out.len - 1 :0];
}

fn join_maybe_z(allocator: Allocator, separator: []const u8, slices: []const []const u8, zero: bool) Allocator.Error![]u8 {
    if (slices.len == 0) return if (zero) try allocator.dupe(u8, &[1]u8{0}) else &[0]u8{};

    const total_len = blk: {
        var sum: usize = separator.len * (slices.len - 1);
        for (slices) |slice| sum += slice.len;
        if (zero) sum += 1;
        break :blk sum;
    };

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    @memcpy(buf[0..slices[0].len], slices[0]);
    var buf_index: usize = slices[0].len;
    for (slices[1..]) |slice| {
        @memcpy(buf[buf_index .. buf_index + separator.len], separator);
        buf_index += separator.len;
        @memcpy(buf[buf_index .. buf_index + slice.len], slice);
        buf_index += slice.len;
    }

    if (zero) buf[buf.len - 1] = 0;

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

test join {
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, ""));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{ "a", "b", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,b,c"));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{"a"});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a"));
    }
    {
        const str = try join(testing.allocator, ",", &[_][]const u8{ "a", "", "b", "", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,,b,,c"));
    }
}

test join_z {
    {
        const str = try join_z(testing.allocator, ",", &[_][]const u8{});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, ""));
        try testing.expect_equal(str[str.len], 0);
    }
    {
        const str = try join_z(testing.allocator, ",", &[_][]const u8{ "a", "b", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,b,c"));
        try testing.expect_equal(str[str.len], 0);
    }
    {
        const str = try join_z(testing.allocator, ",", &[_][]const u8{"a"});
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a"));
        try testing.expect_equal(str[str.len], 0);
    }
    {
        const str = try join_z(testing.allocator, ",", &[_][]const u8{ "a", "", "b", "", "c" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "a,,b,,c"));
        try testing.expect_equal(str[str.len], 0);
    }
}

/// Copies each T from slices into a new slice that exactly holds all the elements.
pub fn concat(allocator: Allocator, comptime T: type, slices: []const []const T) Allocator.Error![]T {
    return concat_maybe_sentinel(allocator, T, slices, null);
}

/// Copies each T from slices into a new slice that exactly holds all the elements.
pub fn concat_with_sentinel(allocator: Allocator, comptime T: type, slices: []const []const T, comptime s: T) Allocator.Error![:s]T {
    const ret = try concat_maybe_sentinel(allocator, T, slices, s);
    return ret[0 .. ret.len - 1 :s];
}

/// Copies each T from slices into a new slice that exactly holds all the elements as well as the sentinel.
pub fn concat_maybe_sentinel(allocator: Allocator, comptime T: type, slices: []const []const T, comptime s: ?T) Allocator.Error![]T {
    if (slices.len == 0) return if (s) |sentinel| try allocator.dupe(T, &[1]T{sentinel}) else &[0]T{};

    const total_len = blk: {
        var sum: usize = 0;
        for (slices) |slice| {
            sum += slice.len;
        }

        if (s) |_| {
            sum += 1;
        }

        break :blk sum;
    };

    const buf = try allocator.alloc(T, total_len);
    errdefer allocator.free(buf);

    var buf_index: usize = 0;
    for (slices) |slice| {
        @memcpy(buf[buf_index .. buf_index + slice.len], slice);
        buf_index += slice.len;
    }

    if (s) |sentinel| {
        buf[buf.len - 1] = sentinel;
    }

    // No need for shrink since buf is exactly the correct size.
    return buf;
}

test concat {
    {
        const str = try concat(testing.allocator, u8, &[_][]const u8{ "abc", "def", "ghi" });
        defer testing.allocator.free(str);
        try testing.expect(eql(u8, str, "abcdefghi"));
    }
    {
        const str = try concat(testing.allocator, u32, &[_][]const u32{
            &[_]u32{ 0, 1 },
            &[_]u32{ 2, 3, 4 },
            &[_]u32{},
            &[_]u32{5},
        });
        defer testing.allocator.free(str);
        try testing.expect(eql(u32, str, &[_]u32{ 0, 1, 2, 3, 4, 5 }));
    }
    {
        const str = try concat_with_sentinel(testing.allocator, u8, &[_][]const u8{ "abc", "def", "ghi" }, 0);
        defer testing.allocator.free(str);
        try testing.expect_equal_sentinel(u8, 0, str, "abcdefghi");
    }
    {
        const slice = try concat_with_sentinel(testing.allocator, u8, &[_][]const u8{}, 0);
        defer testing.allocator.free(slice);
        try testing.expect_equal_sentinel(u8, 0, slice, &[_:0]u8{});
    }
    {
        const slice = try concat_with_sentinel(testing.allocator, u32, &[_][]const u32{
            &[_]u32{ 0, 1 },
            &[_]u32{ 2, 3, 4 },
            &[_]u32{},
            &[_]u32{5},
        }, 2);
        defer testing.allocator.free(slice);
        try testing.expect_equal_sentinel(u32, 2, slice, &[_:2]u32{ 0, 1, 2, 3, 4, 5 });
    }
}

test eql {
    try testing.expect(eql(u8, "abcd", "abcd"));
    try testing.expect(!eql(u8, "abcdef", "abZdef"));
    try testing.expect(!eql(u8, "abcdefg", "abcdef"));
}

fn more_read_int_tests() !void {
    {
        const bytes = [_]u8{
            0x12,
            0x34,
            0x56,
            0x78,
        };
        try testing.expect(read_int(u32, &bytes, .big) == 0x12345678);
        try testing.expect(read_int(u32, &bytes, .big) == 0x12345678);
        try testing.expect(read_int(i32, &bytes, .big) == 0x12345678);
        try testing.expect(read_int(u32, &bytes, .little) == 0x78563412);
        try testing.expect(read_int(u32, &bytes, .little) == 0x78563412);
        try testing.expect(read_int(i32, &bytes, .little) == 0x78563412);
    }
    {
        const buf = [_]u8{
            0x00,
            0x00,
            0x12,
            0x34,
        };
        const answer = read_int(u32, &buf, .big);
        try testing.expect(answer == 0x00001234);
    }
    {
        const buf = [_]u8{
            0x12,
            0x34,
            0x00,
            0x00,
        };
        const answer = read_int(u32, &buf, .little);
        try testing.expect(answer == 0x00003412);
    }
    {
        const bytes = [_]u8{
            0xff,
            0xfe,
        };
        try testing.expect(read_int(u16, &bytes, .big) == 0xfffe);
        try testing.expect(read_int(i16, &bytes, .big) == -0x0002);
        try testing.expect(read_int(u16, &bytes, .little) == 0xfeff);
        try testing.expect(read_int(i16, &bytes, .little) == -0x0101);
    }
}

/// Returns the smallest number in a slice. O(n).
/// `slice` must not be empty.
pub fn min(comptime T: type, slice: []const T) T {
    assert(slice.len > 0);
    var best = slice[0];
    for (slice[1..]) |item| {
        best = @min(best, item);
    }
    return best;
}

test min {
    try testing.expect_equal(min(u8, "abcdefg"), 'a');
    try testing.expect_equal(min(u8, "bcdefga"), 'a');
    try testing.expect_equal(min(u8, "a"), 'a');
}

/// Returns the largest number in a slice. O(n).
/// `slice` must not be empty.
pub fn max(comptime T: type, slice: []const T) T {
    assert(slice.len > 0);
    var best = slice[0];
    for (slice[1..]) |item| {
        best = @max(best, item);
    }
    return best;
}

test max {
    try testing.expect_equal(max(u8, "abcdefg"), 'g');
    try testing.expect_equal(max(u8, "gabcdef"), 'g');
    try testing.expect_equal(max(u8, "g"), 'g');
}

/// Finds the smallest and largest number in a slice. O(n).
/// Returns an anonymous struct with the fields `min` and `max`.
/// `slice` must not be empty.
pub fn min_max(comptime T: type, slice: []const T) struct { T, T } {
    assert(slice.len > 0);
    var running_minimum = slice[0];
    var running_maximum = slice[0];
    for (slice[1..]) |item| {
        running_minimum = @min(running_minimum, item);
        running_maximum = @max(running_maximum, item);
    }
    return .{ running_minimum, running_maximum };
}

test min_max {
    {
        const actual_min, const actual_max = min_max(u8, "abcdefg");
        try testing.expect_equal(@as(u8, 'a'), actual_min);
        try testing.expect_equal(@as(u8, 'g'), actual_max);
    }
    {
        const actual_min, const actual_max = min_max(u8, "bcdefga");
        try testing.expect_equal(@as(u8, 'a'), actual_min);
        try testing.expect_equal(@as(u8, 'g'), actual_max);
    }
    {
        const actual_min, const actual_max = min_max(u8, "a");
        try testing.expect_equal(@as(u8, 'a'), actual_min);
        try testing.expect_equal(@as(u8, 'a'), actual_max);
    }
}

/// Returns the index of the smallest number in a slice. O(n).
/// `slice` must not be empty.
pub fn index_of_min(comptime T: type, slice: []const T) usize {
    assert(slice.len > 0);
    var best = slice[0];
    var index: usize = 0;
    for (slice[1..], 0..) |item, i| {
        if (item < best) {
            best = item;
            index = i + 1;
        }
    }
    return index;
}

test index_of_min {
    try testing.expect_equal(index_of_min(u8, "abcdefg"), 0);
    try testing.expect_equal(index_of_min(u8, "bcdefga"), 6);
    try testing.expect_equal(index_of_min(u8, "a"), 0);
}

/// Returns the index of the largest number in a slice. O(n).
/// `slice` must not be empty.
pub fn index_of_max(comptime T: type, slice: []const T) usize {
    assert(slice.len > 0);
    var best = slice[0];
    var index: usize = 0;
    for (slice[1..], 0..) |item, i| {
        if (item > best) {
            best = item;
            index = i + 1;
        }
    }
    return index;
}

test index_of_max {
    try testing.expect_equal(index_of_max(u8, "abcdefg"), 6);
    try testing.expect_equal(index_of_max(u8, "gabcdef"), 0);
    try testing.expect_equal(index_of_max(u8, "a"), 0);
}

/// Finds the indices of the smallest and largest number in a slice. O(n).
/// Returns the indices of the smallest and largest numbers in that order.
/// `slice` must not be empty.
pub fn index_of_min_max(comptime T: type, slice: []const T) struct { usize, usize } {
    assert(slice.len > 0);
    var minVal = slice[0];
    var maxVal = slice[0];
    var minIdx: usize = 0;
    var maxIdx: usize = 0;
    for (slice[1..], 0..) |item, i| {
        if (item < minVal) {
            minVal = item;
            minIdx = i + 1;
        }
        if (item > maxVal) {
            maxVal = item;
            maxIdx = i + 1;
        }
    }
    return .{ minIdx, maxIdx };
}

test index_of_min_max {
    try testing.expect_equal(.{ 0, 6 }, index_of_min_max(u8, "abcdefg"));
    try testing.expect_equal(.{ 1, 0 }, index_of_min_max(u8, "gabcdef"));
    try testing.expect_equal(.{ 0, 0 }, index_of_min_max(u8, "a"));
}

pub fn swap(comptime T: type, a: *T, b: *T) void {
    const tmp = a.*;
    a.* = b.*;
    b.* = tmp;
}

/// In-place order reversal of a slice
pub fn reverse(comptime T: type, items: []T) void {
    var i: usize = 0;
    const end = items.len / 2;
    while (i < end) : (i += 1) {
        swap(T, &items[i], &items[items.len - i - 1]);
    }
}

test reverse {
    var arr = [_]i32{ 5, 3, 1, 2, 4 };
    reverse(i32, arr[0..]);

    try testing.expect(eql(i32, &arr, &[_]i32{ 4, 2, 1, 3, 5 }));
}

fn ReverseIterator(comptime T: type) type {
    const Pointer = blk: {
        switch (@typeInfo(T)) {
            .Pointer => |ptr_info| switch (ptr_info.size) {
                .One => switch (@typeInfo(ptr_info.child)) {
                    .Array => |array_info| {
                        var new_ptr_info = ptr_info;
                        new_ptr_info.size = .Many;
                        new_ptr_info.child = array_info.child;
                        new_ptr_info.sentinel = array_info.sentinel;
                        break :blk @Type(.{ .Pointer = new_ptr_info });
                    },
                    else => {},
                },
                .Slice => {
                    var new_ptr_info = ptr_info;
                    new_ptr_info.size = .Many;
                    break :blk @Type(.{ .Pointer = new_ptr_info });
                },
                else => {},
            },
            else => {},
        }
        @compile_error("expected slice or pointer to array, found '" ++ @type_name(T) ++ "'");
    };
    const Element = std.meta.Elem(Pointer);
    const ElementPointer = @Type(.{ .Pointer = ptr: {
        var ptr = @typeInfo(Pointer).Pointer;
        ptr.size = .One;
        ptr.child = Element;
        ptr.sentinel = null;
        break :ptr ptr;
    } });
    return struct {
        ptr: Pointer,
        index: usize,
        pub fn next(self: *@This()) ?Element {
            if (self.index == 0) return null;
            self.index -= 1;
            return self.ptr[self.index];
        }
        pub fn next_ptr(self: *@This()) ?ElementPointer {
            if (self.index == 0) return null;
            self.index -= 1;
            return &self.ptr[self.index];
        }
    };
}

/// Iterates over a slice in reverse.
pub fn reverse_iterator(slice: anytype) ReverseIterator(@TypeOf(slice)) {
    return .{ .ptr = slice.ptr, .index = slice.len };
}

test reverse_iterator {
    {
        var it = reverse_iterator("abc");
        try testing.expect_equal(@as(?u8, 'c'), it.next());
        try testing.expect_equal(@as(?u8, 'b'), it.next());
        try testing.expect_equal(@as(?u8, 'a'), it.next());
        try testing.expect_equal(@as(?u8, null), it.next());
    }
    {
        var array = [2]i32{ 3, 7 };
        const slice: []const i32 = &array;
        var it = reverse_iterator(slice);
        try testing.expect_equal(@as(?i32, 7), it.next());
        try testing.expect_equal(@as(?i32, 3), it.next());
        try testing.expect_equal(@as(?i32, null), it.next());

        it = reverse_iterator(slice);
        try testing.expect(*const i32 == @TypeOf(it.next_ptr().?));
        try testing.expect_equal(@as(?i32, 7), it.next_ptr().?.*);
        try testing.expect_equal(@as(?i32, 3), it.next_ptr().?.*);
        try testing.expect_equal(@as(?*const i32, null), it.next_ptr());

        const mut_slice: []i32 = &array;
        var mut_it = reverse_iterator(mut_slice);
        mut_it.next_ptr().?.* += 1;
        mut_it.next_ptr().?.* += 2;
        try testing.expect_equal([2]i32{ 5, 8 }, array);
    }
    {
        var array = [2]i32{ 3, 7 };
        const ptr_to_array: *const [2]i32 = &array;
        var it = reverse_iterator(ptr_to_array);
        try testing.expect_equal(@as(?i32, 7), it.next());
        try testing.expect_equal(@as(?i32, 3), it.next());
        try testing.expect_equal(@as(?i32, null), it.next());

        it = reverse_iterator(ptr_to_array);
        try testing.expect(*const i32 == @TypeOf(it.next_ptr().?));
        try testing.expect_equal(@as(?i32, 7), it.next_ptr().?.*);
        try testing.expect_equal(@as(?i32, 3), it.next_ptr().?.*);
        try testing.expect_equal(@as(?*const i32, null), it.next_ptr());

        const mut_ptr_to_array: *[2]i32 = &array;
        var mut_it = reverse_iterator(mut_ptr_to_array);
        mut_it.next_ptr().?.* += 1;
        mut_it.next_ptr().?.* += 2;
        try testing.expect_equal([2]i32{ 5, 8 }, array);
    }
}

/// In-place rotation of the values in an array ([0 1 2 3] becomes [1 2 3 0] if we rotate by 1)
/// Assumes 0 <= amount <= items.len
pub fn rotate(comptime T: type, items: []T, amount: usize) void {
    reverse(T, items[0..amount]);
    reverse(T, items[amount..]);
    reverse(T, items);
}

test rotate {
    var arr = [_]i32{ 5, 3, 1, 2, 4 };
    rotate(i32, arr[0..], 2);

    try testing.expect(eql(i32, &arr, &[_]i32{ 1, 2, 4, 5, 3 }));
}

/// Replace needle with replacement as many times as possible, writing to an output buffer which is assumed to be of
/// appropriate size. Use replacement_size to calculate an appropriate buffer size.
/// The needle must not be empty.
/// Returns the number of replacements made.
pub fn replace(comptime T: type, input: []const T, needle: []const T, replacement: []const T, output: []T) usize {
    // Empty needle will loop until output buffer overflows.
    assert(needle.len > 0);

    var i: usize = 0;
    var slide: usize = 0;
    var replacements: usize = 0;
    while (slide < input.len) {
        if (mem.starts_with(T, input[slide..], needle)) {
            @memcpy(output[i..][0..replacement.len], replacement);
            i += replacement.len;
            slide += needle.len;
            replacements += 1;
        } else {
            output[i] = input[slide];
            i += 1;
            slide += 1;
        }
    }

    return replacements;
}

test replace {
    var output: [29]u8 = undefined;
    var replacements = replace(u8, "All your base are belong to us", "base", "Zig", output[0..]);
    var expected: []const u8 = "All your Zig are belong to us";
    try testing.expect(replacements == 1);
    try testing.expect_equal_strings(expected, output[0..expected.len]);

    replacements = replace(u8, "Favor reading code over writing code.", "code", "", output[0..]);
    expected = "Favor reading  over writing .";
    try testing.expect(replacements == 2);
    try testing.expect_equal_strings(expected, output[0..expected.len]);

    // Empty needle is not allowed but input may be empty.
    replacements = replace(u8, "", "x", "y", output[0..0]);
    expected = "";
    try testing.expect(replacements == 0);
    try testing.expect_equal_strings(expected, output[0..expected.len]);

    // Adjacent replacements.

    replacements = replace(u8, "\\n\\n", "\\n", "\n", output[0..]);
    expected = "\n\n";
    try testing.expect(replacements == 2);
    try testing.expect_equal_strings(expected, output[0..expected.len]);

    replacements = replace(u8, "abbba", "b", "cd", output[0..]);
    expected = "acdcdcda";
    try testing.expect(replacements == 3);
    try testing.expect_equal_strings(expected, output[0..expected.len]);
}

/// Replace all occurrences of `match` with `replacement`.
pub fn replace_scalar(comptime T: type, slice: []T, match: T, replacement: T) void {
    for (slice) |*e| {
        if (e.* == match)
            e.* = replacement;
    }
}

/// Collapse consecutive duplicate elements into one entry.
pub fn collapse_repeats_len(comptime T: type, slice: []T, elem: T) usize {
    if (slice.len == 0) return 0;
    var write_idx: usize = 1;
    var read_idx: usize = 1;
    while (read_idx < slice.len) : (read_idx += 1) {
        if (slice[read_idx - 1] != elem or slice[read_idx] != elem) {
            slice[write_idx] = slice[read_idx];
            write_idx += 1;
        }
    }
    return write_idx;
}

/// Collapse consecutive duplicate elements into one entry.
pub fn collapse_repeats(comptime T: type, slice: []T, elem: T) []T {
    return slice[0..collapse_repeats_len(T, slice, elem)];
}

fn test_collapse_repeats(str: []const u8, elem: u8, expected: []const u8) !void {
    const mutable = try std.testing.allocator.dupe(u8, str);
    defer std.testing.allocator.free(mutable);
    try testing.expect(std.mem.eql(u8, collapse_repeats(u8, mutable, elem), expected));
}
test collapse_repeats {
    try test_collapse_repeats("", '/', "");
    try test_collapse_repeats("a", '/', "a");
    try test_collapse_repeats("/", '/', "/");
    try test_collapse_repeats("//", '/', "/");
    try test_collapse_repeats("/a", '/', "/a");
    try test_collapse_repeats("//a", '/', "/a");
    try test_collapse_repeats("a/", '/', "a/");
    try test_collapse_repeats("a//", '/', "a/");
    try test_collapse_repeats("a/a", '/', "a/a");
    try test_collapse_repeats("a//a", '/', "a/a");
    try test_collapse_repeats("//a///a////", '/', "/a/a/");
}

/// Calculate the size needed in an output buffer to perform a replacement.
/// The needle must not be empty.
pub fn replacement_size(comptime T: type, input: []const T, needle: []const T, replacement: []const T) usize {
    // Empty needle will loop forever.
    assert(needle.len > 0);

    var i: usize = 0;
    var size: usize = input.len;
    while (i < input.len) {
        if (mem.starts_with(T, input[i..], needle)) {
            size = size - needle.len + replacement.len;
            i += needle.len;
        } else {
            i += 1;
        }
    }

    return size;
}

test replacement_size {
    try testing.expect(replacement_size(u8, "All your base are belong to us", "base", "Zig") == 29);
    try testing.expect(replacement_size(u8, "Favor reading code over writing code.", "code", "") == 29);
    try testing.expect(replacement_size(u8, "Only one obvious way to do things.", "things.", "things in Zig.") == 41);

    // Empty needle is not allowed but input may be empty.
    try testing.expect(replacement_size(u8, "", "x", "y") == 0);

    // Adjacent replacements.
    try testing.expect(replacement_size(u8, "\\n\\n", "\\n", "\n") == 2);
    try testing.expect(replacement_size(u8, "abbba", "b", "cd") == 8);
}

/// Perform a replacement on an allocated buffer of pre-determined size. Caller must free returned memory.
pub fn replace_owned(comptime T: type, allocator: Allocator, input: []const T, needle: []const T, replacement: []const T) Allocator.Error![]T {
    const output = try allocator.alloc(T, replacement_size(T, input, needle, replacement));
    _ = replace(T, input, needle, replacement, output);
    return output;
}

test replace_owned {
    const gpa = std.testing.allocator;

    const base_replace = replace_owned(u8, gpa, "All your base are belong to us", "base", "Zig") catch @panic("out of memory");
    defer gpa.free(base_replace);
    try testing.expect(eql(u8, base_replace, "All your Zig are belong to us"));

    const zen_replace = replace_owned(u8, gpa, "Favor reading code over writing code.", " code", "") catch @panic("out of memory");
    defer gpa.free(zen_replace);
    try testing.expect(eql(u8, zen_replace, "Favor reading over writing."));
}

/// Converts a little-endian integer to host endianness.
pub fn little_to_native(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => x,
        .big => @byte_swap(x),
    };
}

/// Converts a big-endian integer to host endianness.
pub fn big_to_native(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => @byte_swap(x),
        .big => x,
    };
}

/// Converts an integer from specified endianness to host endianness.
pub fn to_native(comptime T: type, x: T, endianness_of_x: Endian) T {
    return switch (endianness_of_x) {
        .little => little_to_native(T, x),
        .big => big_to_native(T, x),
    };
}

/// Converts an integer which has host endianness to the desired endianness.
pub fn native_to(comptime T: type, x: T, desired_endianness: Endian) T {
    return switch (desired_endianness) {
        .little => native_to_little(T, x),
        .big => native_to_big(T, x),
    };
}

/// Converts an integer which has host endianness to little endian.
pub fn native_to_little(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => x,
        .big => @byte_swap(x),
    };
}

/// Converts an integer which has host endianness to big endian.
pub fn native_to_big(comptime T: type, x: T) T {
    return switch (native_endian) {
        .little => @byte_swap(x),
        .big => x,
    };
}

/// Returns the number of elements that, if added to the given pointer, align it
/// to a multiple of the given quantity, or `null` if one of the following
/// conditions is met:
/// - The aligned pointer would not fit the address space,
/// - The delta required to align the pointer is not a multiple of the pointee's
///   type.
pub fn align_pointer_offset(ptr: anytype, align_to: usize) ?usize {
    assert(is_valid_align(align_to));

    const T = @TypeOf(ptr);
    const info = @typeInfo(T);
    if (info != .Pointer or info.Pointer.size != .Many)
        @compile_error("expected many item pointer, got " ++ @type_name(T));

    // Do nothing if the pointer is already well-aligned.
    if (align_to <= info.Pointer.alignment)
        return 0;

    // Calculate the aligned base address with an eye out for overflow.
    const addr = @int_from_ptr(ptr);
    var ov = @add_with_overflow(addr, align_to - 1);
    if (ov[1] != 0) return null;
    ov[0] &= ~@as(usize, align_to - 1);

    // The delta is expressed in terms of bytes, turn it into a number of child
    // type elements.
    const delta = ov[0] - addr;
    const pointee_size = @size_of(info.Pointer.child);
    if (delta % pointee_size != 0) return null;
    return delta / pointee_size;
}

/// Aligns a given pointer value to a specified alignment factor.
/// Returns an aligned pointer or null if one of the following conditions is
/// met:
/// - The aligned pointer would not fit the address space,
/// - The delta required to align the pointer is not a multiple of the pointee's
///   type.
pub fn align_pointer(ptr: anytype, align_to: usize) ?@TypeOf(ptr) {
    const adjust_off = align_pointer_offset(ptr, align_to) orelse return null;
    // Avoid the use of ptrFromInt to avoid losing the pointer provenance info.
    return @align_cast(ptr + adjust_off);
}

test align_pointer {
    const S = struct {
        fn check_align(comptime T: type, base: usize, align_to: usize, expected: usize) !void {
            const ptr: T = @ptrFromInt(base);
            const aligned = align_pointer(ptr, align_to);
            try testing.expect_equal(expected, @int_from_ptr(aligned));
        }
    };

    try S.check_align([*]u8, 0x123, 0x200, 0x200);
    try S.check_align([*]align(4) u8, 0x10, 2, 0x10);
    try S.check_align([*]u32, 0x10, 2, 0x10);
    try S.check_align([*]u32, 0x4, 16, 0x10);
    // Misaligned.
    try S.check_align([*]align(1) u32, 0x3, 2, 0);
    // Overflow.
    try S.check_align([*]u32, math.max_int(usize) - 3, 8, 0);
}

fn CopyPtrAttrs(
    comptime source: type,
    comptime size: std.builtin.Type.Pointer.Size,
    comptime child: type,
) type {
    const info = @typeInfo(source).Pointer;
    return @Type(.{
        .Pointer = .{
            .size = size,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = info.alignment,
            .address_space = info.address_space,
            .child = child,
            .sentinel = null,
        },
    });
}

fn AsBytesReturnType(comptime P: type) type {
    const size = @size_of(std.meta.Child(P));
    return CopyPtrAttrs(P, .One, [size]u8);
}

/// Given a pointer to a single item, returns a slice of the underlying bytes, preserving pointer attributes.
pub fn as_bytes(ptr: anytype) AsBytesReturnType(@TypeOf(ptr)) {
    return @ptr_cast(@align_cast(ptr));
}

test as_bytes {
    const deadbeef = @as(u32, 0xDEADBEEF);
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    try testing.expect(eql(u8, as_bytes(&deadbeef), deadbeef_bytes));

    var codeface = @as(u32, 0xC0DEFACE);
    for (as_bytes(&codeface)) |*b|
        b.* = 0;
    try testing.expect(codeface == 0);

    const S = packed struct {
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    };

    const inst = S{
        .a = 0xBE,
        .b = 0xEF,
        .c = 0xDE,
        .d = 0xA1,
    };
    switch (native_endian) {
        .little => {
            try testing.expect(eql(u8, as_bytes(&inst), "\xBE\xEF\xDE\xA1"));
        },
        .big => {
            try testing.expect(eql(u8, as_bytes(&inst), "\xA1\xDE\xEF\xBE"));
        },
    }

    const ZST = struct {};
    const zero = ZST{};
    try testing.expect(eql(u8, as_bytes(&zero), ""));
}

test "as_bytes preserves pointer attributes" {
    const inArr: u32 align(16) = 0xDEADBEEF;
    const inPtr = @as(*align(16) const volatile u32, @ptr_cast(&inArr));
    const outSlice = as_bytes(inPtr);

    const in = @typeInfo(@TypeOf(inPtr)).Pointer;
    const out = @typeInfo(@TypeOf(outSlice)).Pointer;

    try testing.expect_equal(in.is_const, out.is_const);
    try testing.expect_equal(in.is_volatile, out.is_volatile);
    try testing.expect_equal(in.is_allowzero, out.is_allowzero);
    try testing.expect_equal(in.alignment, out.alignment);
}

/// Given any value, returns a copy of its bytes in an array.
pub fn to_bytes(value: anytype) [@size_of(@TypeOf(value))]u8 {
    return as_bytes(&value).*;
}

test to_bytes {
    var my_bytes = to_bytes(@as(u32, 0x12345678));
    switch (native_endian) {
        .big => try testing.expect(eql(u8, &my_bytes, "\x12\x34\x56\x78")),
        .little => try testing.expect(eql(u8, &my_bytes, "\x78\x56\x34\x12")),
    }

    my_bytes[0] = '\x99';
    switch (native_endian) {
        .big => try testing.expect(eql(u8, &my_bytes, "\x99\x34\x56\x78")),
        .little => try testing.expect(eql(u8, &my_bytes, "\x99\x56\x34\x12")),
    }
}

fn BytesAsValueReturnType(comptime T: type, comptime B: type) type {
    return CopyPtrAttrs(B, .One, T);
}

/// Given a pointer to an array of bytes, returns a pointer to a value of the specified type
/// backed by those bytes, preserving pointer attributes.
pub fn bytes_as_value(comptime T: type, bytes: anytype) BytesAsValueReturnType(T, @TypeOf(bytes)) {
    return @ptr_cast(bytes);
}

test bytes_as_value {
    const deadbeef = @as(u32, 0xDEADBEEF);
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    try testing.expect(deadbeef == bytes_as_value(u32, deadbeef_bytes).*);

    var codeface_bytes: [4]u8 = switch (native_endian) {
        .big => "\xC0\xDE\xFA\xCE",
        .little => "\xCE\xFA\xDE\xC0",
    }.*;
    const codeface = bytes_as_value(u32, &codeface_bytes);
    try testing.expect(codeface.* == 0xC0DEFACE);
    codeface.* = 0;
    for (codeface_bytes) |b|
        try testing.expect(b == 0);

    const S = packed struct {
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    };

    const inst = S{
        .a = 0xBE,
        .b = 0xEF,
        .c = 0xDE,
        .d = 0xA1,
    };
    const inst_bytes = switch (native_endian) {
        .little => "\xBE\xEF\xDE\xA1",
        .big => "\xA1\xDE\xEF\xBE",
    };
    const inst2 = bytes_as_value(S, inst_bytes);
    try testing.expect(std.meta.eql(inst, inst2.*));
}

test "bytes_as_value preserves pointer attributes" {
    const inArr align(16) = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const inSlice = @as(*align(16) const volatile [4]u8, @ptr_cast(&inArr))[0..];
    const outPtr = bytes_as_value(u32, inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).Pointer;
    const out = @typeInfo(@TypeOf(outPtr)).Pointer;

    try testing.expect_equal(in.is_const, out.is_const);
    try testing.expect_equal(in.is_volatile, out.is_volatile);
    try testing.expect_equal(in.is_allowzero, out.is_allowzero);
    try testing.expect_equal(in.alignment, out.alignment);
}

/// Given a pointer to an array of bytes, returns a value of the specified type backed by a
/// copy of those bytes.
pub fn bytes_to_value(comptime T: type, bytes: anytype) T {
    return bytes_as_value(T, bytes).*;
}
test bytes_to_value {
    const deadbeef_bytes = switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xEF\xBE\xAD\xDE",
    };

    const deadbeef = bytes_to_value(u32, deadbeef_bytes);
    try testing.expect(deadbeef == @as(u32, 0xDEADBEEF));
}

fn BytesAsSliceReturnType(comptime T: type, comptime bytesType: type) type {
    return CopyPtrAttrs(bytesType, .Slice, T);
}

/// Given a slice of bytes, returns a slice of the specified type
/// backed by those bytes, preserving pointer attributes.
pub fn bytes_as_slice(comptime T: type, bytes: anytype) BytesAsSliceReturnType(T, @TypeOf(bytes)) {
    // let's not give an undefined pointer to @ptr_cast
    // it may be equal to zero and fail a null check
    if (bytes.len == 0) {
        return &[0]T{};
    }

    const cast_target = CopyPtrAttrs(@TypeOf(bytes), .Many, T);

    return @as(cast_target, @ptr_cast(bytes))[0..@div_exact(bytes.len, @size_of(T))];
}

test bytes_as_slice {
    {
        const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        const slice = bytes_as_slice(u16, bytes[0..]);
        try testing.expect(slice.len == 2);
        try testing.expect(big_to_native(u16, slice[0]) == 0xDEAD);
        try testing.expect(big_to_native(u16, slice[1]) == 0xBEEF);
    }
    {
        const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        const slice = bytes_as_slice(u16, bytes[runtime_zero..]);
        try testing.expect(slice.len == 2);
        try testing.expect(big_to_native(u16, slice[0]) == 0xDEAD);
        try testing.expect(big_to_native(u16, slice[1]) == 0xBEEF);
    }
}

test "bytes_as_slice keeps pointer alignment" {
    {
        var bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
        const numbers = bytes_as_slice(u32, bytes[0..]);
        try comptime testing.expect(@TypeOf(numbers) == []align(@alignOf(@TypeOf(bytes))) u32);
    }
    {
        var bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
        var runtime_zero: usize = 0;
        _ = &runtime_zero;
        const numbers = bytes_as_slice(u32, bytes[runtime_zero..]);
        try comptime testing.expect(@TypeOf(numbers) == []align(@alignOf(@TypeOf(bytes))) u32);
    }
}

test "bytes_as_slice on a packed struct" {
    const F = packed struct {
        a: u8,
    };

    const b: [1]u8 = .{9};
    const f = bytes_as_slice(F, &b);
    try testing.expect(f[0].a == 9);
}

test "bytes_as_slice with specified alignment" {
    var bytes align(4) = [_]u8{
        0x33,
        0x33,
        0x33,
        0x33,
    };
    const slice: []u32 = std.mem.bytes_as_slice(u32, bytes[0..]);
    try testing.expect(slice[0] == 0x33333333);
}

test "bytes_as_slice preserves pointer attributes" {
    const inArr align(16) = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const inSlice = @as(*align(16) const volatile [4]u8, @ptr_cast(&inArr))[0..];
    const outSlice = bytes_as_slice(u16, inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).Pointer;
    const out = @typeInfo(@TypeOf(outSlice)).Pointer;

    try testing.expect_equal(in.is_const, out.is_const);
    try testing.expect_equal(in.is_volatile, out.is_volatile);
    try testing.expect_equal(in.is_allowzero, out.is_allowzero);
    try testing.expect_equal(in.alignment, out.alignment);
}

fn SliceAsBytesReturnType(comptime Slice: type) type {
    return CopyPtrAttrs(Slice, .Slice, u8);
}

/// Given a slice, returns a slice of the underlying bytes, preserving pointer attributes.
pub fn slice_as_bytes(slice: anytype) SliceAsBytesReturnType(@TypeOf(slice)) {
    const Slice = @TypeOf(slice);

    // a slice of zero-bit values always occupies zero bytes
    if (@size_of(std.meta.Elem(Slice)) == 0) return &[0]u8{};

    // let's not give an undefined pointer to @ptr_cast
    // it may be equal to zero and fail a null check
    if (slice.len == 0 and std.meta.sentinel(Slice) == null) return &[0]u8{};

    const cast_target = CopyPtrAttrs(Slice, .Many, u8);

    return @as(cast_target, @ptr_cast(slice))[0 .. slice.len * @size_of(std.meta.Elem(Slice))];
}

test slice_as_bytes {
    const bytes = [_]u16{ 0xDEAD, 0xBEEF };
    const slice = slice_as_bytes(bytes[0..]);
    try testing.expect(slice.len == 4);
    try testing.expect(eql(u8, slice, switch (native_endian) {
        .big => "\xDE\xAD\xBE\xEF",
        .little => "\xAD\xDE\xEF\xBE",
    }));
}

test "slice_as_bytes with sentinel slice" {
    const empty_string: [:0]const u8 = "";
    const bytes = slice_as_bytes(empty_string);
    try testing.expect(bytes.len == 0);
}

test "slice_as_bytes with zero-bit element type" {
    const lots_of_nothing = [1]void{{}} ** 10_000;
    const bytes = slice_as_bytes(&lots_of_nothing);
    try testing.expect(bytes.len == 0);
}

test "slice_as_bytes packed struct at runtime and comptime" {
    const Foo = packed struct {
        a: u4,
        b: u4,
    };
    const S = struct {
        fn do_the_test() !void {
            var foo: Foo = undefined;
            var slice = slice_as_bytes(@as(*[1]Foo, &foo)[0..1]);
            slice[0] = 0x13;
            try testing.expect(foo.a == 0x3);
            try testing.expect(foo.b == 0x1);
        }
    };
    try S.do_the_test();
    try comptime S.do_the_test();
}

test "slice_as_bytes and bytes_as_slice back" {
    try testing.expect(@size_of(i32) == 4);

    var big_thing_array = [_]i32{ 1, 2, 3, 4 };
    const big_thing_slice: []i32 = big_thing_array[0..];

    const bytes = slice_as_bytes(big_thing_slice);
    try testing.expect(bytes.len == 4 * 4);

    bytes[4] = 0;
    bytes[5] = 0;
    bytes[6] = 0;
    bytes[7] = 0;
    try testing.expect(big_thing_slice[1] == 0);

    const big_thing_again = bytes_as_slice(i32, bytes);
    try testing.expect(big_thing_again[2] == 3);

    big_thing_again[2] = -1;
    try testing.expect(bytes[8] == math.max_int(u8));
    try testing.expect(bytes[9] == math.max_int(u8));
    try testing.expect(bytes[10] == math.max_int(u8));
    try testing.expect(bytes[11] == math.max_int(u8));
}

test "slice_as_bytes preserves pointer attributes" {
    const inArr align(16) = [2]u16{ 0xDEAD, 0xBEEF };
    const inSlice = @as(*align(16) const volatile [2]u16, @ptr_cast(&inArr))[0..];
    const outSlice = slice_as_bytes(inSlice);

    const in = @typeInfo(@TypeOf(inSlice)).Pointer;
    const out = @typeInfo(@TypeOf(outSlice)).Pointer;

    try testing.expect_equal(in.is_const, out.is_const);
    try testing.expect_equal(in.is_volatile, out.is_volatile);
    try testing.expect_equal(in.is_allowzero, out.is_allowzero);
    try testing.expect_equal(in.alignment, out.alignment);
}

/// Round an address up to the next (or current) aligned address.
/// The alignment must be a power of 2 and greater than 0.
/// Asserts that rounding up the address does not cause integer overflow.
pub fn align_forward(comptime T: type, addr: T, alignment: T) T {
    assert(is_valid_align_generic(T, alignment));
    return align_backward(T, addr + (alignment - 1), alignment);
}

pub fn align_forward_log2(addr: usize, log2_alignment: u8) usize {
    const alignment = @as(usize, 1) << @as(math.Log2Int(usize), @int_cast(log2_alignment));
    return align_forward(usize, addr, alignment);
}

pub const alignForwardGeneric = @compile_error("renamed to align_forward");

/// Force an evaluation of the expression; this tries to prevent
/// the compiler from optimizing the computation away even if the
/// result eventually gets discarded.
// TODO: use @declareSideEffect() when it is available - https://github.com/ziglang/zig/issues/6168
pub fn do_not_optimize_away(val: anytype) void {
    if (@in_comptime()) return;

    const max_gp_register_bits = @bitSizeOf(c_long);
    const t = @typeInfo(@TypeOf(val));
    switch (t) {
        .Void, .Null, .ComptimeInt, .ComptimeFloat => return,
        .Enum => do_not_optimize_away(@int_from_enum(val)),
        .Bool => do_not_optimize_away(@int_from_bool(val)),
        .Int => {
            const bits = t.Int.bits;
            if (bits <= max_gp_register_bits and builtin.zig_backend != .stage2_c) {
                const val2 = @as(
                    std.meta.Int(t.Int.signedness, @max(8, std.math.ceil_power_of_two_assert(u16, bits))),
                    val,
                );
                asm volatile (""
                    :
                    : [val2] "r" (val2),
                );
            } else do_not_optimize_away(&val);
        },
        .Float => {
            if ((t.Float.bits == 32 or t.Float.bits == 64) and builtin.zig_backend != .stage2_c) {
                asm volatile (""
                    :
                    : [val] "rm" (val),
                );
            } else do_not_optimize_away(&val);
        },
        .Pointer => {
            if (builtin.zig_backend == .stage2_c) {
                do_not_optimize_away_c(val);
            } else {
                asm volatile (""
                    :
                    : [val] "m" (val),
                    : "memory"
                );
            }
        },
        .Array => {
            if (t.Array.len * @size_of(t.Array.child) <= 64) {
                for (val) |v| do_not_optimize_away(v);
            } else do_not_optimize_away(&val);
        },
        else => do_not_optimize_away(&val),
    }
}

/// .stage2_c doesn't support asm blocks yet, so use volatile stores instead
var deopt_target: if (builtin.zig_backend == .stage2_c) u8 else void = undefined;
fn do_not_optimize_away_c(ptr: anytype) void {
    const dest = @as(*volatile u8, @ptr_cast(&deopt_target));
    for (as_bytes(ptr)) |b| {
        dest.* = b;
    }
    dest.* = 0;
}

test do_not_optimize_away {
    comptime do_not_optimize_away("test");

    do_not_optimize_away(null);
    do_not_optimize_away(true);
    do_not_optimize_away(0);
    do_not_optimize_away(0.0);
    do_not_optimize_away(@as(u1, 0));
    do_not_optimize_away(@as(u3, 0));
    do_not_optimize_away(@as(u8, 0));
    do_not_optimize_away(@as(u16, 0));
    do_not_optimize_away(@as(u32, 0));
    do_not_optimize_away(@as(u64, 0));
    do_not_optimize_away(@as(u128, 0));
    do_not_optimize_away(@as(u13, 0));
    do_not_optimize_away(@as(u37, 0));
    do_not_optimize_away(@as(u96, 0));
    do_not_optimize_away(@as(u200, 0));
    do_not_optimize_away(@as(f32, 0.0));
    do_not_optimize_away(@as(f64, 0.0));
    do_not_optimize_away([_]u8{0} ** 4);
    do_not_optimize_away([_]u8{0} ** 100);
    do_not_optimize_away(@as(std.builtin.Endian, .little));
}

test align_forward {
    try testing.expect(align_forward(usize, 1, 1) == 1);
    try testing.expect(align_forward(usize, 2, 1) == 2);
    try testing.expect(align_forward(usize, 1, 2) == 2);
    try testing.expect(align_forward(usize, 2, 2) == 2);
    try testing.expect(align_forward(usize, 3, 2) == 4);
    try testing.expect(align_forward(usize, 4, 2) == 4);
    try testing.expect(align_forward(usize, 7, 8) == 8);
    try testing.expect(align_forward(usize, 8, 8) == 8);
    try testing.expect(align_forward(usize, 9, 8) == 16);
    try testing.expect(align_forward(usize, 15, 8) == 16);
    try testing.expect(align_forward(usize, 16, 8) == 16);
    try testing.expect(align_forward(usize, 17, 8) == 24);
}

/// Round an address down to the previous (or current) aligned address.
/// Unlike `align_backward`, `alignment` can be any positive number, not just a power of 2.
pub fn align_backward_any_align(i: usize, alignment: usize) usize {
    if (is_valid_align(alignment))
        return align_backward(usize, i, alignment);
    assert(alignment != 0);
    return i - @mod(i, alignment);
}

/// Round an address down to the previous (or current) aligned address.
/// The alignment must be a power of 2 and greater than 0.
pub fn align_backward(comptime T: type, addr: T, alignment: T) T {
    assert(is_valid_align_generic(T, alignment));
    // 000010000 // example alignment
    // 000001111 // subtract 1
    // 111110000 // binary not
    return addr & ~(alignment - 1);
}

pub const alignBackwardGeneric = @compile_error("renamed to align_backward");

/// Returns whether `alignment` is a valid alignment, meaning it is
/// a positive power of 2.
pub fn is_valid_align(alignment: usize) bool {
    return is_valid_align_generic(usize, alignment);
}

/// Returns whether `alignment` is a valid alignment, meaning it is
/// a positive power of 2.
pub fn is_valid_align_generic(comptime T: type, alignment: T) bool {
    return alignment > 0 and std.math.is_power_of_two(alignment);
}

pub fn is_aligned_any_align(i: usize, alignment: usize) bool {
    if (is_valid_align(alignment))
        return is_aligned(i, alignment);
    assert(alignment != 0);
    return 0 == @mod(i, alignment);
}

pub fn is_aligned_log2(addr: usize, log2_alignment: u8) bool {
    return @ctz(addr) >= log2_alignment;
}

/// Given an address and an alignment, return true if the address is a multiple of the alignment
/// The alignment must be a power of 2 and greater than 0.
pub fn is_aligned(addr: usize, alignment: usize) bool {
    return is_aligned_generic(u64, addr, alignment);
}

pub fn is_aligned_generic(comptime T: type, addr: T, alignment: T) bool {
    return align_backward(T, addr, alignment) == addr;
}

test is_aligned {
    try testing.expect(is_aligned(0, 4));
    try testing.expect(is_aligned(1, 1));
    try testing.expect(is_aligned(2, 1));
    try testing.expect(is_aligned(2, 2));
    try testing.expect(!is_aligned(2, 4));
    try testing.expect(is_aligned(3, 1));
    try testing.expect(!is_aligned(3, 2));
    try testing.expect(!is_aligned(3, 4));
    try testing.expect(is_aligned(4, 4));
    try testing.expect(is_aligned(4, 2));
    try testing.expect(is_aligned(4, 1));
    try testing.expect(!is_aligned(4, 8));
    try testing.expect(!is_aligned(4, 16));
}

test "freeing empty string with null-terminated sentinel" {
    const empty_string = try testing.allocator.dupe_z(u8, "");
    testing.allocator.free(empty_string);
}

/// Returns a slice with the given new alignment,
/// all other pointer attributes copied from `AttributeSource`.
fn AlignedSlice(comptime AttributeSource: type, comptime new_alignment: usize) type {
    const info = @typeInfo(AttributeSource).Pointer;
    return @Type(.{
        .Pointer = .{
            .size = .Slice,
            .is_const = info.is_const,
            .is_volatile = info.is_volatile,
            .is_allowzero = info.is_allowzero,
            .alignment = new_alignment,
            .address_space = info.address_space,
            .child = info.child,
            .sentinel = null,
        },
    });
}

/// Returns the largest slice in the given bytes that conforms to the new alignment,
/// or `null` if the given bytes contain no conforming address.
pub fn align_in_bytes(bytes: []u8, comptime new_alignment: usize) ?[]align(new_alignment) u8 {
    const begin_address = @int_from_ptr(bytes.ptr);
    const end_address = begin_address + bytes.len;

    const begin_address_aligned = mem.align_forward(usize, begin_address, new_alignment);
    const new_length = std.math.sub(usize, end_address, begin_address_aligned) catch |e| switch (e) {
        error.Overflow => return null,
    };
    const alignment_offset = begin_address_aligned - begin_address;
    return @align_cast(bytes[alignment_offset .. alignment_offset + new_length]);
}

/// Returns the largest sub-slice within the given slice that conforms to the new alignment,
/// or `null` if the given slice contains no conforming address.
pub fn align_in_slice(slice: anytype, comptime new_alignment: usize) ?AlignedSlice(@TypeOf(slice), new_alignment) {
    const bytes = slice_as_bytes(slice);
    const aligned_bytes = align_in_bytes(bytes, new_alignment) orelse return null;

    const Element = @TypeOf(slice[0]);
    const slice_length_bytes = aligned_bytes.len - (aligned_bytes.len % @size_of(Element));
    const aligned_slice = bytes_as_slice(Element, aligned_bytes[0..slice_length_bytes]);
    return @align_cast(aligned_slice);
}

test "read/write(Var)PackedInt" {
    switch (builtin.cpu.arch) {
        // This test generates too much code to execute on WASI.
        // LLVM backend fails with "too many locals: locals exceed maximum"
        .wasm32, .wasm64 => return error.SkipZigTest,
        else => {},
    }

    if (builtin.cpu.arch == .powerpc) {
        // https://github.com/ziglang/zig/issues/16951
        return error.SkipZigTest;
    }

    const foreign_endian: Endian = if (native_endian == .big) .little else .big;
    const expect = std.testing.expect;
    var prng = std.Random.DefaultPrng.init(1234);
    const random = prng.random();

    @setEvalBranchQuota(10_000);
    inline for ([_]type{ u8, u16, u32, u128 }) |BackingType| {
        for ([_]BackingType{
            @as(BackingType, 0), // all zeros
            -%@as(BackingType, 1), // all ones
            random.int(BackingType), // random
            random.int(BackingType), // random
            random.int(BackingType), // random
        }) |init_value| {
            const uTs = [_]type{ u1, u3, u7, u8, u9, u10, u15, u16, u86 };
            const iTs = [_]type{ i1, i3, i7, i8, i9, i10, i15, i16, i86 };
            inline for (uTs ++ iTs) |PackedType| {
                if (@bitSizeOf(PackedType) > @bitSizeOf(BackingType))
                    continue;

                const iPackedType = std.meta.Int(.signed, @bitSizeOf(PackedType));
                const uPackedType = std.meta.Int(.unsigned, @bitSizeOf(PackedType));
                const Log2T = std.math.Log2Int(BackingType);

                const offset_at_end = @bitSizeOf(BackingType) - @bitSizeOf(PackedType);
                for ([_]usize{ 0, 1, 7, 8, 9, 10, 15, 16, 86, offset_at_end }) |offset| {
                    if (offset > offset_at_end or offset == @bitSizeOf(BackingType))
                        continue;

                    for ([_]PackedType{
                        ~@as(PackedType, 0), // all ones: -1 iN / max_int uN
                        @as(PackedType, 0), // all zeros: 0 iN / 0 uN
                        @as(PackedType, @bit_cast(@as(iPackedType, math.max_int(iPackedType)))), // max_int iN
                        @as(PackedType, @bit_cast(@as(iPackedType, math.min_int(iPackedType)))), // max_int iN
                        random.int(PackedType), // random
                        random.int(PackedType), // random
                    }) |write_value| {
                        { // Fixed-size Read/Write (Native-endian)

                            // Initialize Value
                            var value: BackingType = init_value;

                            // Read
                            const read_value1 = read_packed_int(PackedType, as_bytes(&value), offset, native_endian);
                            try expect(read_value1 == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(value >> @as(Log2T, @int_cast(offset)))))));

                            // Write
                            write_packed_int(PackedType, as_bytes(&value), offset, write_value, native_endian);
                            try expect(write_value == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(value >> @as(Log2T, @int_cast(offset)))))));

                            // Read again
                            const read_value2 = read_packed_int(PackedType, as_bytes(&value), offset, native_endian);
                            try expect(read_value2 == write_value);

                            // Verify bits outside of the target integer are unmodified
                            const diff_bits = init_value ^ value;
                            if (offset != offset_at_end)
                                try expect(diff_bits >> @as(Log2T, @int_cast(offset + @bitSizeOf(PackedType))) == 0);
                            if (offset != 0)
                                try expect(diff_bits << @as(Log2T, @int_cast(@bitSizeOf(BackingType) - offset)) == 0);
                        }

                        { // Fixed-size Read/Write (Foreign-endian)

                            // Initialize Value
                            var value: BackingType = @byte_swap(init_value);

                            // Read
                            const read_value1 = read_packed_int(PackedType, as_bytes(&value), offset, foreign_endian);
                            try expect(read_value1 == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(@byte_swap(value) >> @as(Log2T, @int_cast(offset)))))));

                            // Write
                            write_packed_int(PackedType, as_bytes(&value), offset, write_value, foreign_endian);
                            try expect(write_value == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(@byte_swap(value) >> @as(Log2T, @int_cast(offset)))))));

                            // Read again
                            const read_value2 = read_packed_int(PackedType, as_bytes(&value), offset, foreign_endian);
                            try expect(read_value2 == write_value);

                            // Verify bits outside of the target integer are unmodified
                            const diff_bits = init_value ^ @byte_swap(value);
                            if (offset != offset_at_end)
                                try expect(diff_bits >> @as(Log2T, @int_cast(offset + @bitSizeOf(PackedType))) == 0);
                            if (offset != 0)
                                try expect(diff_bits << @as(Log2T, @int_cast(@bitSizeOf(BackingType) - offset)) == 0);
                        }

                        const signedness = @typeInfo(PackedType).Int.signedness;
                        const NextPowerOfTwoInt = std.meta.Int(signedness, try comptime std.math.ceil_power_of_two(u16, @bitSizeOf(PackedType)));
                        const ui64 = std.meta.Int(signedness, 64);
                        inline for ([_]type{ PackedType, NextPowerOfTwoInt, ui64 }) |U| {
                            { // Variable-size Read/Write (Native-endian)

                                if (@bitSizeOf(U) < @bitSizeOf(PackedType))
                                    continue;

                                // Initialize Value
                                var value: BackingType = init_value;

                                // Read
                                const read_value1 = read_var_packed_int(U, as_bytes(&value), offset, @bitSizeOf(PackedType), native_endian, signedness);
                                try expect(read_value1 == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(value >> @as(Log2T, @int_cast(offset)))))));

                                // Write
                                write_var_packed_int(as_bytes(&value), offset, @bitSizeOf(PackedType), @as(U, write_value), native_endian);
                                try expect(write_value == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(value >> @as(Log2T, @int_cast(offset)))))));

                                // Read again
                                const read_value2 = read_var_packed_int(U, as_bytes(&value), offset, @bitSizeOf(PackedType), native_endian, signedness);
                                try expect(read_value2 == write_value);

                                // Verify bits outside of the target integer are unmodified
                                const diff_bits = init_value ^ value;
                                if (offset != offset_at_end)
                                    try expect(diff_bits >> @as(Log2T, @int_cast(offset + @bitSizeOf(PackedType))) == 0);
                                if (offset != 0)
                                    try expect(diff_bits << @as(Log2T, @int_cast(@bitSizeOf(BackingType) - offset)) == 0);
                            }

                            { // Variable-size Read/Write (Foreign-endian)

                                if (@bitSizeOf(U) < @bitSizeOf(PackedType))
                                    continue;

                                // Initialize Value
                                var value: BackingType = @byte_swap(init_value);

                                // Read
                                const read_value1 = read_var_packed_int(U, as_bytes(&value), offset, @bitSizeOf(PackedType), foreign_endian, signedness);
                                try expect(read_value1 == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(@byte_swap(value) >> @as(Log2T, @int_cast(offset)))))));

                                // Write
                                write_var_packed_int(as_bytes(&value), offset, @bitSizeOf(PackedType), @as(U, write_value), foreign_endian);
                                try expect(write_value == @as(PackedType, @bit_cast(@as(uPackedType, @truncate(@byte_swap(value) >> @as(Log2T, @int_cast(offset)))))));

                                // Read again
                                const read_value2 = read_var_packed_int(U, as_bytes(&value), offset, @bitSizeOf(PackedType), foreign_endian, signedness);
                                try expect(read_value2 == write_value);

                                // Verify bits outside of the target integer are unmodified
                                const diff_bits = init_value ^ @byte_swap(value);
                                if (offset != offset_at_end)
                                    try expect(diff_bits >> @as(Log2T, @int_cast(offset + @bitSizeOf(PackedType))) == 0);
                                if (offset != 0)
                                    try expect(diff_bits << @as(Log2T, @int_cast(@bitSizeOf(BackingType) - offset)) == 0);
                            }
                        }
                    }
                }
            }
        }
    }
}
