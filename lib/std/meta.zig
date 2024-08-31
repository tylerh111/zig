const std = @import("std.zig");
const debug = std.debug;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const root = @import("root");

pub const TrailerFlags = @import("meta/trailer_flags.zig").TrailerFlags;

const Type = std.builtin.Type;

test {
    _ = TrailerFlags;
}

/// Returns the variant of an enum type, `T`, which is named `str`, or `null` if no such variant exists.
pub fn string_to_enum(comptime T: type, str: []const u8) ?T {
    // Using StaticStringMap here is more performant, but it will start to take too
    // long to compile if the enum is large enough, due to the current limits of comptime
    // performance when doing things like constructing lookup maps at comptime.
    // TODO The '100' here is arbitrary and should be increased when possible:
    // - https://github.com/ziglang/zig/issues/4055
    // - https://github.com/ziglang/zig/issues/3863
    if (@typeInfo(T).Enum.fields.len <= 100) {
        const kvs = comptime build_kvs: {
            const EnumKV = struct { []const u8, T };
            var kvs_array: [@typeInfo(T).Enum.fields.len]EnumKV = undefined;
            for (@typeInfo(T).Enum.fields, 0..) |enumField, i| {
                kvs_array[i] = .{ enumField.name, @field(T, enumField.name) };
            }
            break :build_kvs kvs_array[0..];
        };
        const map = std.StaticStringMap(T).init_comptime(kvs);
        return map.get(str);
    } else {
        inline for (@typeInfo(T).Enum.fields) |enumField| {
            if (mem.eql(u8, str, enumField.name)) {
                return @field(T, enumField.name);
            }
        }
        return null;
    }
}

test string_to_enum {
    const E1 = enum {
        A,
        B,
    };
    try testing.expect(E1.A == string_to_enum(E1, "A").?);
    try testing.expect(E1.B == string_to_enum(E1, "B").?);
    try testing.expect(null == string_to_enum(E1, "C"));
}

/// Returns the alignment of type T.
/// Note that if T is a pointer type the result is different than the one
/// returned by @alignOf(T).
/// If T is a pointer type the alignment of the type it points to is returned.
pub fn alignment(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .Optional => |info| switch (@typeInfo(info.child)) {
            .Pointer, .Fn => alignment(info.child),
            else => @alignOf(T),
        },
        .Pointer => |info| info.alignment,
        else => @alignOf(T),
    };
}

test alignment {
    try testing.expect(alignment(u8) == 1);
    try testing.expect(alignment(*align(1) u8) == 1);
    try testing.expect(alignment(*align(2) u8) == 2);
    try testing.expect(alignment([]align(1) u8) == 1);
    try testing.expect(alignment([]align(2) u8) == 2);
    try testing.expect(alignment(fn () void) > 0);
    try testing.expect(alignment(*const fn () void) > 0);
    try testing.expect(alignment(*align(128) const fn () void) == 128);
}

/// Given a parameterized type (array, vector, pointer, optional), returns the "child type".
pub fn Child(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .Array => |info| info.child,
        .Vector => |info| info.child,
        .Pointer => |info| info.child,
        .Optional => |info| info.child,
        else => @compile_error("Expected pointer, optional, array or vector type, found '" ++ @type_name(T) ++ "'"),
    };
}

test Child {
    try testing.expect(Child([1]u8) == u8);
    try testing.expect(Child(*u8) == u8);
    try testing.expect(Child([]u8) == u8);
    try testing.expect(Child(?u8) == u8);
    try testing.expect(Child(@Vector(2, u8)) == u8);
}

/// Given a "memory span" type (array, slice, vector, or pointer to such), returns the "element type".
pub fn Elem(comptime T: type) type {
    switch (@typeInfo(T)) {
        .Array => |info| return info.child,
        .Vector => |info| return info.child,
        .Pointer => |info| switch (info.size) {
            .One => switch (@typeInfo(info.child)) {
                .Array => |array_info| return array_info.child,
                .Vector => |vector_info| return vector_info.child,
                else => {},
            },
            .Many, .C, .Slice => return info.child,
        },
        .Optional => |info| return Elem(info.child),
        else => {},
    }
    @compile_error("Expected pointer, slice, array or vector type, found '" ++ @type_name(T) ++ "'");
}

test Elem {
    try testing.expect(Elem([1]u8) == u8);
    try testing.expect(Elem([*]u8) == u8);
    try testing.expect(Elem([]u8) == u8);
    try testing.expect(Elem(*[10]u8) == u8);
    try testing.expect(Elem(@Vector(2, u8)) == u8);
    try testing.expect(Elem(*@Vector(2, u8)) == u8);
    try testing.expect(Elem(?[*]u8) == u8);
}

/// Given a type which can have a sentinel e.g. `[:0]u8`, returns the sentinel value,
/// or `null` if there is not one.
/// Types which cannot possibly have a sentinel will be a compile error.
/// Result is always comptime-known.
pub inline fn sentinel(comptime T: type) ?Elem(T) {
    switch (@typeInfo(T)) {
        .Array => |info| {
            const sentinel_ptr = info.sentinel orelse return null;
            return @as(*const info.child, @ptr_cast(sentinel_ptr)).*;
        },
        .Pointer => |info| {
            switch (info.size) {
                .Many, .Slice => {
                    const sentinel_ptr = info.sentinel orelse return null;
                    return @as(*align(1) const info.child, @ptr_cast(sentinel_ptr)).*;
                },
                .One => switch (@typeInfo(info.child)) {
                    .Array => |array_info| {
                        const sentinel_ptr = array_info.sentinel orelse return null;
                        return @as(*align(1) const array_info.child, @ptr_cast(sentinel_ptr)).*;
                    },
                    else => {},
                },
                else => {},
            }
        },
        else => {},
    }
    @compile_error("type '" ++ @type_name(T) ++ "' cannot possibly have a sentinel");
}

test sentinel {
    try test_sentinel();
    try comptime test_sentinel();
}

fn test_sentinel() !void {
    try testing.expect_equal(@as(u8, 0), sentinel([:0]u8).?);
    try testing.expect_equal(@as(u8, 0), sentinel([*:0]u8).?);
    try testing.expect_equal(@as(u8, 0), sentinel([5:0]u8).?);
    try testing.expect_equal(@as(u8, 0), sentinel(*const [5:0]u8).?);

    try testing.expect(sentinel([]u8) == null);
    try testing.expect(sentinel([*]u8) == null);
    try testing.expect(sentinel([5]u8) == null);
    try testing.expect(sentinel(*const [5]u8) == null);
}

/// Given a "memory span" type, returns the same type except with the given sentinel value.
pub fn Sentinel(comptime T: type, comptime sentinel_val: Elem(T)) type {
    switch (@typeInfo(T)) {
        .Pointer => |info| switch (info.size) {
            .One => switch (@typeInfo(info.child)) {
                .Array => |array_info| return @Type(.{
                    .Pointer = .{
                        .size = info.size,
                        .is_const = info.is_const,
                        .is_volatile = info.is_volatile,
                        .alignment = info.alignment,
                        .address_space = info.address_space,
                        .child = @Type(.{
                            .Array = .{
                                .len = array_info.len,
                                .child = array_info.child,
                                .sentinel = @as(?*const anyopaque, @ptr_cast(&sentinel_val)),
                            },
                        }),
                        .is_allowzero = info.is_allowzero,
                        .sentinel = info.sentinel,
                    },
                }),
                else => {},
            },
            .Many, .Slice => return @Type(.{
                .Pointer = .{
                    .size = info.size,
                    .is_const = info.is_const,
                    .is_volatile = info.is_volatile,
                    .alignment = info.alignment,
                    .address_space = info.address_space,
                    .child = info.child,
                    .is_allowzero = info.is_allowzero,
                    .sentinel = @as(?*const anyopaque, @ptr_cast(&sentinel_val)),
                },
            }),
            else => {},
        },
        .Optional => |info| switch (@typeInfo(info.child)) {
            .Pointer => |ptr_info| switch (ptr_info.size) {
                .Many => return @Type(.{
                    .Optional = .{
                        .child = @Type(.{
                            .Pointer = .{
                                .size = ptr_info.size,
                                .is_const = ptr_info.is_const,
                                .is_volatile = ptr_info.is_volatile,
                                .alignment = ptr_info.alignment,
                                .address_space = ptr_info.address_space,
                                .child = ptr_info.child,
                                .is_allowzero = ptr_info.is_allowzero,
                                .sentinel = @as(?*const anyopaque, @ptr_cast(&sentinel_val)),
                            },
                        }),
                    },
                }),
                else => {},
            },
            else => {},
        },
        else => {},
    }
    @compile_error("Unable to derive a sentinel pointer type from " ++ @type_name(T));
}

pub const assumeSentinel = @compile_error("This function has been removed, consider using std.mem.slice_to() or if needed a @ptr_cast()");

pub fn container_layout(comptime T: type) Type.ContainerLayout {
    return switch (@typeInfo(T)) {
        .Struct => |info| info.layout,
        .Union => |info| info.layout,
        else => @compile_error("expected struct or union type, found '" ++ @type_name(T) ++ "'"),
    };
}

test container_layout {
    const S1 = struct {};
    const S2 = packed struct {};
    const S3 = extern struct {};
    const U1 = union {
        a: u8,
    };
    const U2 = packed union {
        a: u8,
    };
    const U3 = extern union {
        a: u8,
    };

    try testing.expect(container_layout(S1) == .auto);
    try testing.expect(container_layout(S2) == .@"packed");
    try testing.expect(container_layout(S3) == .@"extern");
    try testing.expect(container_layout(U1) == .auto);
    try testing.expect(container_layout(U2) == .@"packed");
    try testing.expect(container_layout(U3) == .@"extern");
}

/// Instead of this function, prefer to use e.g. `@typeInfo(foo).Struct.decls`
/// directly when you know what kind of type it is.
pub fn declarations(comptime T: type) []const Type.Declaration {
    return switch (@typeInfo(T)) {
        .Struct => |info| info.decls,
        .Enum => |info| info.decls,
        .Union => |info| info.decls,
        .Opaque => |info| info.decls,
        else => @compile_error("Expected struct, enum, union, or opaque type, found '" ++ @type_name(T) ++ "'"),
    };
}

test declarations {
    const E1 = enum {
        A,

        pub fn a() void {}
    };
    const S1 = struct {
        pub fn a() void {}
    };
    const U1 = union {
        a: u8,

        pub fn a() void {}
    };
    const O1 = opaque {
        pub fn a() void {}
    };

    const decls = comptime [_][]const Type.Declaration{
        declarations(E1),
        declarations(S1),
        declarations(U1),
        declarations(O1),
    };

    inline for (decls) |decl| {
        try testing.expect(decl.len == 1);
        try testing.expect(comptime mem.eql(u8, decl[0].name, "a"));
    }
}

pub fn declaration_info(comptime T: type, comptime decl_name: []const u8) Type.Declaration {
    inline for (comptime declarations(T)) |decl| {
        if (comptime mem.eql(u8, decl.name, decl_name))
            return decl;
    }

    @compile_error("'" ++ @type_name(T) ++ "' has no declaration '" ++ decl_name ++ "'");
}

test declaration_info {
    const E1 = enum {
        A,

        pub fn a() void {}
    };
    const S1 = struct {
        pub fn a() void {}
    };
    const U1 = union {
        a: u8,

        pub fn a() void {}
    };

    const infos = comptime [_]Type.Declaration{
        declaration_info(E1, "a"),
        declaration_info(S1, "a"),
        declaration_info(U1, "a"),
    };

    inline for (infos) |info| {
        try testing.expect(comptime mem.eql(u8, info.name, "a"));
    }
}
pub fn fields(comptime T: type) switch (@typeInfo(T)) {
    .Struct => []const Type.StructField,
    .Union => []const Type.UnionField,
    .ErrorSet => []const Type.Error,
    .Enum => []const Type.EnumField,
    else => @compile_error("Expected struct, union, error set or enum type, found '" ++ @type_name(T) ++ "'"),
} {
    return switch (@typeInfo(T)) {
        .Struct => |info| info.fields,
        .Union => |info| info.fields,
        .Enum => |info| info.fields,
        .ErrorSet => |errors| errors.?, // must be non global error set
        else => @compile_error("Expected struct, union, error set or enum type, found '" ++ @type_name(T) ++ "'"),
    };
}

test fields {
    const E1 = enum {
        A,
    };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
    };

    const e1f = comptime fields(E1);
    const e2f = comptime fields(E2);
    const sf = comptime fields(S1);
    const uf = comptime fields(U1);

    try testing.expect(e1f.len == 1);
    try testing.expect(e2f.len == 1);
    try testing.expect(sf.len == 1);
    try testing.expect(uf.len == 1);
    try testing.expect(mem.eql(u8, e1f[0].name, "A"));
    try testing.expect(mem.eql(u8, e2f[0].name, "A"));
    try testing.expect(mem.eql(u8, sf[0].name, "a"));
    try testing.expect(mem.eql(u8, uf[0].name, "a"));
    try testing.expect(comptime sf[0].type == u8);
    try testing.expect(comptime uf[0].type == u8);
}

pub fn field_info(comptime T: type, comptime field: FieldEnum(T)) switch (@typeInfo(T)) {
    .Struct => Type.StructField,
    .Union => Type.UnionField,
    .ErrorSet => Type.Error,
    .Enum => Type.EnumField,
    else => @compile_error("Expected struct, union, error set or enum type, found '" ++ @type_name(T) ++ "'"),
} {
    return fields(T)[@int_from_enum(field)];
}

test field_info {
    const E1 = enum {
        A,
    };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
    };

    const e1f = field_info(E1, .A);
    const e2f = field_info(E2, .A);
    const sf = field_info(S1, .a);
    const uf = field_info(U1, .a);

    try testing.expect(mem.eql(u8, e1f.name, "A"));
    try testing.expect(mem.eql(u8, e2f.name, "A"));
    try testing.expect(mem.eql(u8, sf.name, "a"));
    try testing.expect(mem.eql(u8, uf.name, "a"));
    try testing.expect(comptime sf.type == u8);
    try testing.expect(comptime uf.type == u8);
}

pub fn FieldType(comptime T: type, comptime field: FieldEnum(T)) type {
    if (@typeInfo(T) != .Struct and @typeInfo(T) != .Union) {
        @compile_error("Expected struct or union, found '" ++ @type_name(T) ++ "'");
    }

    return field_info(T, field).type;
}

test FieldType {
    const S = struct {
        a: u8,
        b: u16,
    };

    const U = union {
        c: u32,
        d: *const u8,
    };

    try testing.expect(FieldType(S, .a) == u8);
    try testing.expect(FieldType(S, .b) == u16);

    try testing.expect(FieldType(U, .c) == u32);
    try testing.expect(FieldType(U, .d) == *const u8);
}

pub fn field_names(comptime T: type) *const [fields(T).len][:0]const u8 {
    return comptime blk: {
        const fieldInfos = fields(T);
        var names: [fieldInfos.len][:0]const u8 = undefined;
        // This concat can be removed with the next zig1 update.
        for (&names, fieldInfos) |*name, field| name.* = field.name ++ "";
        const final = names;
        break :blk &final;
    };
}

test field_names {
    const E1 = enum { A, B };
    const E2 = error{A};
    const S1 = struct {
        a: u8,
    };
    const U1 = union {
        a: u8,
        b: void,
    };

    const e1names = field_names(E1);
    const e2names = field_names(E2);
    const s1names = field_names(S1);
    const u1names = field_names(U1);

    try testing.expect(e1names.len == 2);
    try testing.expect_equal_slices(u8, e1names[0], "A");
    try testing.expect_equal_slices(u8, e1names[1], "B");
    try testing.expect(e2names.len == 1);
    try testing.expect_equal_slices(u8, e2names[0], "A");
    try testing.expect(s1names.len == 1);
    try testing.expect_equal_slices(u8, s1names[0], "a");
    try testing.expect(u1names.len == 2);
    try testing.expect_equal_slices(u8, u1names[0], "a");
    try testing.expect_equal_slices(u8, u1names[1], "b");
}

/// Given an enum or error set type, returns a pointer to an array containing all tags for that
/// enum or error set.
pub fn tags(comptime T: type) *const [fields(T).len]T {
    return comptime blk: {
        const fieldInfos = fields(T);
        var res: [fieldInfos.len]T = undefined;
        for (fieldInfos, 0..) |field, i| {
            res[i] = @field(T, field.name);
        }
        const final = res;
        break :blk &final;
    };
}

test tags {
    const E1 = enum { A, B };
    const E2 = error{A};

    const e1_tags = tags(E1);
    const e2_tags = tags(E2);

    try testing.expect(e1_tags.len == 2);
    try testing.expect_equal(E1.A, e1_tags[0]);
    try testing.expect_equal(E1.B, e1_tags[1]);
    try testing.expect(e2_tags.len == 1);
    try testing.expect_equal(E2.A, e2_tags[0]);
}

/// Returns an enum with a variant named after each field of `T`.
pub fn FieldEnum(comptime T: type) type {
    const field_infos = fields(T);

    if (field_infos.len == 0) {
        return @Type(.{
            .Enum = .{
                .tag_type = u0,
                .fields = &.{},
                .decls = &.{},
                .is_exhaustive = true,
            },
        });
    }

    if (@typeInfo(T) == .Union) {
        if (@typeInfo(T).Union.tag_type) |tag_type| {
            for (std.enums.values(tag_type), 0..) |v, i| {
                if (@int_from_enum(v) != i) break; // enum values not consecutive
                if (!std.mem.eql(u8, @tag_name(v), field_infos[i].name)) break; // fields out of order
            } else {
                return tag_type;
            }
        }
    }

    var enum_fields: [field_infos.len]std.builtin.Type.EnumField = undefined;
    var decls = [_]std.builtin.Type.Declaration{};
    inline for (field_infos, 0..) |field, i| {
        enum_fields[i] = .{
            .name = field.name ++ "",
            .value = i,
        };
    }
    return @Type(.{
        .Enum = .{
            .tag_type = std.math.IntFittingRange(0, field_infos.len - 1),
            .fields = &enum_fields,
            .decls = &decls,
            .is_exhaustive = true,
        },
    });
}

fn expect_equal_enum(expected: anytype, actual: @TypeOf(expected)) !void {
    // TODO: https://github.com/ziglang/zig/issues/7419
    // testing.expect_equal(@typeInfo(expected).Enum, @typeInfo(actual).Enum);
    try testing.expect_equal(
        @typeInfo(expected).Enum.tag_type,
        @typeInfo(actual).Enum.tag_type,
    );
    // For comparing decls and fields, we cannot use the meta eql function here
    // because the language does not guarantee that the slice pointers for field names
    // and decl names will be the same.
    comptime {
        const expected_fields = @typeInfo(expected).Enum.fields;
        const actual_fields = @typeInfo(actual).Enum.fields;
        if (expected_fields.len != actual_fields.len) return error.FailedTest;
        for (expected_fields, 0..) |expected_field, i| {
            const actual_field = actual_fields[i];
            try testing.expect_equal(expected_field.value, actual_field.value);
            try testing.expect_equal_strings(expected_field.name, actual_field.name);
        }
    }
    comptime {
        const expected_decls = @typeInfo(expected).Enum.decls;
        const actual_decls = @typeInfo(actual).Enum.decls;
        if (expected_decls.len != actual_decls.len) return error.FailedTest;
        for (expected_decls, 0..) |expected_decl, i| {
            const actual_decl = actual_decls[i];
            try testing.expect_equal_strings(expected_decl.name, actual_decl.name);
        }
    }
    try testing.expect_equal(
        @typeInfo(expected).Enum.is_exhaustive,
        @typeInfo(actual).Enum.is_exhaustive,
    );
}

test FieldEnum {
    try expect_equal_enum(enum {}, FieldEnum(struct {}));
    try expect_equal_enum(enum { a }, FieldEnum(struct { a: u8 }));
    try expect_equal_enum(enum { a, b, c }, FieldEnum(struct { a: u8, b: void, c: f32 }));
    try expect_equal_enum(enum { a, b, c }, FieldEnum(union { a: u8, b: void, c: f32 }));

    const Tagged = union(enum) { a: u8, b: void, c: f32 };
    try testing.expect_equal(Tag(Tagged), FieldEnum(Tagged));

    const Tag2 = enum { a, b, c };
    const Tagged2 = union(Tag2) { a: u8, b: void, c: f32 };
    try testing.expect(Tag(Tagged2) == FieldEnum(Tagged2));

    const Tag3 = enum(u8) { a, b, c = 7 };
    const Tagged3 = union(Tag3) { a: u8, b: void, c: f32 };
    try testing.expect(Tag(Tagged3) != FieldEnum(Tagged3));
}

pub fn DeclEnum(comptime T: type) type {
    const fieldInfos = std.meta.declarations(T);
    var enumDecls: [fieldInfos.len]std.builtin.Type.EnumField = undefined;
    var decls = [_]std.builtin.Type.Declaration{};
    inline for (fieldInfos, 0..) |field, i| {
        enumDecls[i] = .{ .name = field.name ++ "", .value = i };
    }
    return @Type(.{
        .Enum = .{
            .tag_type = std.math.IntFittingRange(0, fieldInfos.len - 1),
            .fields = &enumDecls,
            .decls = &decls,
            .is_exhaustive = true,
        },
    });
}

test DeclEnum {
    const A = struct {
        pub const a: u8 = 0;
    };
    const B = union {
        foo: void,

        pub const a: u8 = 0;
        pub const b: void = {};
        pub const c: f32 = 0;
    };
    const C = enum {
        bar,

        pub const a: u8 = 0;
        pub const b: void = {};
        pub const c: f32 = 0;
    };
    try expect_equal_enum(enum { a }, DeclEnum(A));
    try expect_equal_enum(enum { a, b, c }, DeclEnum(B));
    try expect_equal_enum(enum { a, b, c }, DeclEnum(C));
}

pub fn Tag(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .Enum => |info| info.tag_type,
        .Union => |info| info.tag_type orelse @compile_error(@type_name(T) ++ " has no tag type"),
        else => @compile_error("expected enum or union type, found '" ++ @type_name(T) ++ "'"),
    };
}

test Tag {
    const E = enum(u8) {
        C = 33,
        D,
    };
    const U = union(E) {
        C: u8,
        D: u16,
    };

    try testing.expect(Tag(E) == u8);
    try testing.expect(Tag(U) == E);
}

///Returns the active tag of a tagged union
pub fn active_tag(u: anytype) Tag(@TypeOf(u)) {
    const T = @TypeOf(u);
    return @as(Tag(T), u);
}

test active_tag {
    const UE = enum {
        Int,
        Float,
    };

    const U = union(UE) {
        Int: u32,
        Float: f32,
    };

    var u = U{ .Int = 32 };
    try testing.expect(active_tag(u) == UE.Int);

    u = U{ .Float = 112.9876 };
    try testing.expect(active_tag(u) == UE.Float);
}

const TagPayloadType = TagPayload;

pub fn TagPayloadByName(comptime U: type, comptime tag_name: []const u8) type {
    const info = @typeInfo(U).Union;

    inline for (info.fields) |field_info| {
        if (comptime mem.eql(u8, field_info.name, tag_name))
            return field_info.type;
    }

    @compile_error("no field '" ++ tag_name ++ "' in union '" ++ @type_name(U) ++ "'");
}

/// Given a tagged union type, and an enum, return the type of the union field
/// corresponding to the enum tag.
pub fn TagPayload(comptime U: type, comptime tag: Tag(U)) type {
    return TagPayloadByName(U, @tag_name(tag));
}

test TagPayload {
    const Event = union(enum) {
        Moved: struct {
            from: i32,
            to: i32,
        },
    };
    const MovedEvent = TagPayload(Event, Event.Moved);
    const e: Event = .{ .Moved = undefined };
    try testing.expect(MovedEvent == @TypeOf(e.Moved));
}

/// Compares two of any type for equality. Containers are compared on a field-by-field basis,
/// where possible. Pointers are not followed.
pub fn eql(a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);

    switch (@typeInfo(T)) {
        .Struct => |info| {
            inline for (info.fields) |field_info| {
                if (!eql(@field(a, field_info.name), @field(b, field_info.name))) return false;
            }
            return true;
        },
        .ErrorUnion => {
            if (a) |a_p| {
                if (b) |b_p| return eql(a_p, b_p) else |_| return false;
            } else |a_e| {
                if (b) |_| return false else |b_e| return a_e == b_e;
            }
        },
        .Union => |info| {
            if (info.tag_type) |UnionTag| {
                const tag_a = active_tag(a);
                const tag_b = active_tag(b);
                if (tag_a != tag_b) return false;

                inline for (info.fields) |field_info| {
                    if (@field(UnionTag, field_info.name) == tag_a) {
                        return eql(@field(a, field_info.name), @field(b, field_info.name));
                    }
                }
                return false;
            }

            @compile_error("cannot compare untagged union type " ++ @type_name(T));
        },
        .Array => {
            if (a.len != b.len) return false;
            for (a, 0..) |e, i|
                if (!eql(e, b[i])) return false;
            return true;
        },
        .Vector => |info| {
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                if (!eql(a[i], b[i])) return false;
            }
            return true;
        },
        .Pointer => |info| {
            return switch (info.size) {
                .One, .Many, .C => a == b,
                .Slice => a.ptr == b.ptr and a.len == b.len,
            };
        },
        .Optional => {
            if (a == null and b == null) return true;
            if (a == null or b == null) return false;
            return eql(a.?, b.?);
        },
        else => return a == b,
    }
}

test eql {
    const S = struct {
        a: u32,
        b: f64,
        c: [5]u8,
    };

    const U = union(enum) {
        s: S,
        f: ?f32,
    };

    const s_1 = S{
        .a = 134,
        .b = 123.3,
        .c = "12345".*,
    };

    var s_3 = S{
        .a = 134,
        .b = 123.3,
        .c = "12345".*,
    };

    const u_1 = U{ .f = 24 };
    const u_2 = U{ .s = s_1 };
    const u_3 = U{ .f = 24 };

    try testing.expect(eql(s_1, s_3));
    try testing.expect(eql(&s_1, &s_1));
    try testing.expect(!eql(&s_1, &s_3));
    try testing.expect(eql(u_1, u_3));
    try testing.expect(!eql(u_1, u_2));

    const a1 = "abcdef".*;
    const a2 = "abcdef".*;
    const a3 = "ghijkl".*;

    try testing.expect(eql(a1, a2));
    try testing.expect(!eql(a1, a3));

    const EU = struct {
        fn tst(err: bool) !u8 {
            if (err) return error.Error;
            return @as(u8, 5);
        }
    };

    try testing.expect(eql(EU.tst(true), EU.tst(true)));
    try testing.expect(eql(EU.tst(false), EU.tst(false)));
    try testing.expect(!eql(EU.tst(false), EU.tst(true)));

    const V = @Vector(4, u32);
    const v1: V = @splat(1);
    const v2: V = @splat(1);
    const v3: V = @splat(2);

    try testing.expect(eql(v1, v2));
    try testing.expect(!eql(v1, v3));
}

test int_to_enum {
    const E1 = enum {
        A,
    };
    const E2 = enum {
        A,
        B,
    };
    const E3 = enum(i8) { A, _ };

    var zero: u8 = 0;
    var one: u16 = 1;
    _ = &zero;
    _ = &one;
    try testing.expect(int_to_enum(E1, zero) catch unreachable == E1.A);
    try testing.expect(int_to_enum(E2, one) catch unreachable == E2.B);
    try testing.expect(int_to_enum(E3, zero) catch unreachable == E3.A);
    try testing.expect(int_to_enum(E3, 127) catch unreachable == @as(E3, @enumFromInt(127)));
    try testing.expect(int_to_enum(E3, -128) catch unreachable == @as(E3, @enumFromInt(-128)));
    try testing.expect_error(error.InvalidEnumTag, int_to_enum(E1, one));
    try testing.expect_error(error.InvalidEnumTag, int_to_enum(E3, 128));
    try testing.expect_error(error.InvalidEnumTag, int_to_enum(E3, -129));
}

pub const IntToEnumError = error{InvalidEnumTag};

pub fn int_to_enum(comptime EnumTag: type, tag_int: anytype) IntToEnumError!EnumTag {
    const enum_info = @typeInfo(EnumTag).Enum;

    if (!enum_info.is_exhaustive) {
        if (std.math.cast(enum_info.tag_type, tag_int)) |tag| {
            return @as(EnumTag, @enumFromInt(tag));
        }
        return error.InvalidEnumTag;
    }

    // We don't direcly iterate over the fields of EnumTag, as that
    // would require an inline loop. Instead, we create an array of
    // values that is comptime-know, but can be iterated at runtime
    // without requiring an inline loop. This generates better
    // machine code.
    const values = comptime blk: {
        var result: [enum_info.fields.len]enum_info.tag_type = undefined;
        for (&result, enum_info.fields) |*dst, src| {
            dst.* = src.value;
        }
        break :blk result;
    };
    for (values) |v| {
        if (v == tag_int) return @enumFromInt(tag_int);
    }
    return error.InvalidEnumTag;
}

/// Given a type and a name, return the field index according to source order.
/// Returns `null` if the field is not found.
pub fn field_index(comptime T: type, comptime name: []const u8) ?comptime_int {
    inline for (fields(T), 0..) |field, i| {
        if (mem.eql(u8, field.name, name))
            return i;
    }
    return null;
}

pub const ref_all_decls = @compile_error("ref_all_decls has been moved from std.meta to std.testing");

/// Returns a slice of pointers to public declarations of a namespace.
pub fn decl_list(comptime Namespace: type, comptime Decl: type) []const *const Decl {
    const S = struct {
        fn decl_name_less_than(context: void, lhs: *const Decl, rhs: *const Decl) bool {
            _ = context;
            return mem.less_than(u8, lhs.name, rhs.name);
        }
    };
    comptime {
        const decls = declarations(Namespace);
        var array: [decls.len]*const Decl = undefined;
        for (decls, 0..) |decl, i| {
            array[i] = &@field(Namespace, decl.name);
        }
        mem.sort(*const Decl, &array, {}, S.decl_name_less_than);
        return &array;
    }
}

pub const IntType = @compile_error("replaced by std.meta.Int");

pub fn Int(comptime signedness: std.builtin.Signedness, comptime bit_count: u16) type {
    return @Type(.{
        .Int = .{
            .signedness = signedness,
            .bits = bit_count,
        },
    });
}

pub fn Float(comptime bit_count: u8) type {
    return @Type(.{
        .Float = .{ .bits = bit_count },
    });
}

test Float {
    try testing.expect_equal(f16, Float(16));
    try testing.expect_equal(f32, Float(32));
    try testing.expect_equal(f64, Float(64));
    try testing.expect_equal(f128, Float(128));
}

/// For a given function type, returns a tuple type which fields will
/// correspond to the argument types.
///
/// Examples:
/// - `ArgsTuple(fn () void)` ⇒ `tuple { }`
/// - `ArgsTuple(fn (a: u32) u32)` ⇒ `tuple { u32 }`
/// - `ArgsTuple(fn (a: u32, b: f16) noreturn)` ⇒ `tuple { u32, f16 }`
pub fn ArgsTuple(comptime Function: type) type {
    const info = @typeInfo(Function);
    if (info != .Fn)
        @compile_error("ArgsTuple expects a function type");

    const function_info = info.Fn;
    if (function_info.is_var_args)
        @compile_error("Cannot create ArgsTuple for variadic function");

    var argument_field_list: [function_info.params.len]type = undefined;
    inline for (function_info.params, 0..) |arg, i| {
        const T = arg.type orelse @compile_error("cannot create ArgsTuple for function with an 'anytype' parameter");
        argument_field_list[i] = T;
    }

    return CreateUniqueTuple(argument_field_list.len, argument_field_list);
}

/// For a given anonymous list of types, returns a new tuple type
/// with those types as fields.
///
/// Examples:
/// - `Tuple(&[_]type {})` ⇒ `tuple { }`
/// - `Tuple(&[_]type {f32})` ⇒ `tuple { f32 }`
/// - `Tuple(&[_]type {f32,u32})` ⇒ `tuple { f32, u32 }`
pub fn Tuple(comptime types: []const type) type {
    return CreateUniqueTuple(types.len, types[0..types.len].*);
}

fn CreateUniqueTuple(comptime N: comptime_int, comptime types: [N]type) type {
    var tuple_fields: [types.len]std.builtin.Type.StructField = undefined;
    inline for (types, 0..) |T, i| {
        @setEvalBranchQuota(10_000);
        var num_buf: [128]u8 = undefined;
        tuple_fields[i] = .{
            .name = std.fmt.buf_print_z(&num_buf, "{d}", .{i}) catch unreachable,
            .type = T,
            .default_value = null,
            .is_comptime = false,
            .alignment = if (@size_of(T) > 0) @alignOf(T) else 0,
        };
    }

    return @Type(.{
        .Struct = .{
            .is_tuple = true,
            .layout = .auto,
            .decls = &.{},
            .fields = &tuple_fields,
        },
    });
}

const TupleTester = struct {
    fn assert_type_equal(comptime Expected: type, comptime Actual: type) void {
        if (Expected != Actual)
            @compile_error("Expected type " ++ @type_name(Expected) ++ ", but got type " ++ @type_name(Actual));
    }

    fn assert_tuple(comptime expected: anytype, comptime Actual: type) void {
        const info = @typeInfo(Actual);
        if (info != .Struct)
            @compile_error("Expected struct type");
        if (!info.Struct.is_tuple)
            @compile_error("Struct type must be a tuple type");

        const fields_list = std.meta.fields(Actual);
        if (expected.len != fields_list.len)
            @compile_error("Argument count mismatch");

        inline for (fields_list, 0..) |fld, i| {
            if (expected[i] != fld.type) {
                @compile_error("Field " ++ fld.name ++ " expected to be type " ++ @type_name(expected[i]) ++ ", but was type " ++ @type_name(fld.type));
            }
        }
    }
};

test ArgsTuple {
    TupleTester.assert_tuple(.{}, ArgsTuple(fn () void));
    TupleTester.assert_tuple(.{u32}, ArgsTuple(fn (a: u32) []const u8));
    TupleTester.assert_tuple(.{ u32, f16 }, ArgsTuple(fn (a: u32, b: f16) noreturn));
    TupleTester.assert_tuple(.{ u32, f16, []const u8, void }, ArgsTuple(fn (a: u32, b: f16, c: []const u8, void) noreturn));
    TupleTester.assert_tuple(.{u32}, ArgsTuple(fn (comptime a: u32) []const u8));
}

test Tuple {
    TupleTester.assert_tuple(.{}, Tuple(&[_]type{}));
    TupleTester.assert_tuple(.{u32}, Tuple(&[_]type{u32}));
    TupleTester.assert_tuple(.{ u32, f16 }, Tuple(&[_]type{ u32, f16 }));
    TupleTester.assert_tuple(.{ u32, f16, []const u8, void }, Tuple(&[_]type{ u32, f16, []const u8, void }));
}

test "Tuple deduplication" {
    const T1 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T2 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T3 = std.meta.Tuple(&.{ u32, f32, i7 });

    if (T1 != T2) {
        @compile_error("std.meta.Tuple doesn't deduplicate tuple types.");
    }
    if (T1 == T3) {
        @compile_error("std.meta.Tuple fails to generate different types.");
    }
}

test "ArgsTuple forwarding" {
    const T1 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T2 = std.meta.ArgsTuple(fn (u32, f32, i8) void);
    const T3 = std.meta.ArgsTuple(fn (u32, f32, i8) callconv(.C) noreturn);

    if (T1 != T2) {
        @compile_error("std.meta.ArgsTuple produces different types than std.meta.Tuple");
    }
    if (T1 != T3) {
        @compile_error("std.meta.ArgsTuple produces different types for the same argument lists.");
    }
}

/// Returns whether `error_union` contains an error.
pub fn is_error(error_union: anytype) bool {
    return if (error_union) |_| false else |_| true;
}

test is_error {
    try std.testing.expect(is_error(math.div_trunc(u8, 5, 0)));
    try std.testing.expect(!is_error(math.div_trunc(u8, 5, 5)));
}

/// Returns true if a type has a namespace and the namespace contains `name`;
/// `false` otherwise. Result is always comptime-known.
pub inline fn has_fn(comptime T: type, comptime name: []const u8) bool {
    switch (@typeInfo(T)) {
        .Struct, .Union, .Enum, .Opaque => {},
        else => return false,
    }
    if (!@hasDecl(T, name))
        return false;

    return @typeInfo(@TypeOf(@field(T, name))) == .Fn;
}

test has_fn {
    const S1 = struct {
        pub fn foo() void {}
    };

    try std.testing.expect(has_fn(S1, "foo"));
    try std.testing.expect(!has_fn(S1, "bar"));
    try std.testing.expect(!has_fn(*S1, "foo"));

    const S2 = struct {
        foo: fn () void,
    };

    try std.testing.expect(!has_fn(S2, "foo"));
}

/// Returns true if a type has a `name` method; `false` otherwise.
/// Result is always comptime-known.
pub inline fn has_method(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .Pointer => |P| switch (P.size) {
            .One => has_fn(P.child, name),
            .Many, .Slice, .C => false,
        },
        else => has_fn(T, name),
    };
}

test has_method {
    try std.testing.expect(!has_method(u32, "foo"));
    try std.testing.expect(!has_method([]u32, "len"));
    try std.testing.expect(!has_method(struct { u32, u64 }, "len"));

    const S1 = struct {
        pub fn foo() void {}
    };

    try std.testing.expect(has_method(S1, "foo"));
    try std.testing.expect(has_method(*S1, "foo"));

    try std.testing.expect(!has_method(S1, "bar"));
    try std.testing.expect(!has_method(*[1]S1, "foo"));
    try std.testing.expect(!has_method(*[10]S1, "foo"));
    try std.testing.expect(!has_method([]S1, "foo"));

    const S2 = struct {
        foo: fn () void,
    };

    try std.testing.expect(!has_method(S2, "foo"));

    const U = union {
        pub fn foo() void {}
    };

    try std.testing.expect(has_method(U, "foo"));
    try std.testing.expect(has_method(*U, "foo"));
    try std.testing.expect(!has_method(U, "bar"));
}

/// True if every value of the type `T` has a unique bit pattern representing it.
/// In other words, `T` has no unused bits and no padding.
/// Result is always comptime-known.
pub inline fn has_unique_representation(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        else => false, // TODO can we know if it's true for some of these types ?

        .AnyFrame,
        .Enum,
        .ErrorSet,
        .Fn,
        => true,

        .Bool => false,

        .Int => |info| @size_of(T) * 8 == info.bits,

        .Pointer => |info| info.size != .Slice,

        .Array => |info| has_unique_representation(info.child),

        .Struct => |info| {
            if (info.layout == .@"packed") return @size_of(T) * 8 == @bitSizeOf(T);

            var sum_size = @as(usize, 0);

            inline for (info.fields) |field| {
                if (!has_unique_representation(field.type)) return false;
                sum_size += @size_of(field.type);
            }

            return @size_of(T) == sum_size;
        },

        .Vector => |info| has_unique_representation(info.child) and
            @size_of(T) == @size_of(info.child) * info.len,
    };
}

test has_unique_representation {
    const TestStruct1 = struct {
        a: u32,
        b: u32,
    };

    try testing.expect(has_unique_representation(TestStruct1));

    const TestStruct2 = struct {
        a: u32,
        b: u16,
    };

    try testing.expect(!has_unique_representation(TestStruct2));

    const TestStruct3 = struct {
        a: u32,
        b: u32,
    };

    try testing.expect(has_unique_representation(TestStruct3));

    const TestStruct4 = struct { a: []const u8 };

    try testing.expect(!has_unique_representation(TestStruct4));

    const TestStruct5 = struct { a: TestStruct4 };

    try testing.expect(!has_unique_representation(TestStruct5));

    const TestStruct6 = packed struct(u8) {
        @"0": bool,
        @"1": bool,
        @"2": bool,
        @"3": bool,
        @"4": bool,
        @"5": bool,
        @"6": bool,
        @"7": bool,
    };

    try testing.expect(has_unique_representation(TestStruct6));

    const TestUnion1 = packed union {
        a: u32,
        b: u16,
    };

    try testing.expect(!has_unique_representation(TestUnion1));

    const TestUnion2 = extern union {
        a: u32,
        b: u16,
    };

    try testing.expect(!has_unique_representation(TestUnion2));

    const TestUnion3 = union {
        a: u32,
        b: u16,
    };

    try testing.expect(!has_unique_representation(TestUnion3));

    const TestUnion4 = union(enum) {
        a: u32,
        b: u16,
    };

    try testing.expect(!has_unique_representation(TestUnion4));

    inline for ([_]type{ i0, u8, i16, u32, i64 }) |T| {
        try testing.expect(has_unique_representation(T));
    }
    inline for ([_]type{ i1, u9, i17, u33, i24 }) |T| {
        try testing.expect(!has_unique_representation(T));
    }

    try testing.expect(!has_unique_representation([]u8));
    try testing.expect(!has_unique_representation([]const u8));

    try testing.expect(has_unique_representation(@Vector(std.simd.suggest_vector_length(u8) orelse 1, u8)));
    try testing.expect(@size_of(@Vector(3, u8)) == 3 or !has_unique_representation(@Vector(3, u8)));
}
