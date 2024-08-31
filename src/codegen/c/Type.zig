index: CType.Index,

pub const @"void": CType = .{ .index = .void };
pub const @"bool": CType = .{ .index = .bool };
pub const @"i8": CType = .{ .index = .int8_t };
pub const @"u8": CType = .{ .index = .uint8_t };
pub const @"i16": CType = .{ .index = .int16_t };
pub const @"u16": CType = .{ .index = .uint16_t };
pub const @"i32": CType = .{ .index = .int32_t };
pub const @"u32": CType = .{ .index = .uint32_t };
pub const @"i64": CType = .{ .index = .int64_t };
pub const @"u64": CType = .{ .index = .uint64_t };
pub const @"i128": CType = .{ .index = .zig_i128 };
pub const @"u128": CType = .{ .index = .zig_u128 };
pub const @"isize": CType = .{ .index = .intptr_t };
pub const @"usize": CType = .{ .index = .uintptr_t };
pub const @"f16": CType = .{ .index = .zig_f16 };
pub const @"f32": CType = .{ .index = .zig_f32 };
pub const @"f64": CType = .{ .index = .zig_f64 };
pub const @"f80": CType = .{ .index = .zig_f80 };
pub const @"f128": CType = .{ .index = .zig_f128 };

pub fn from_pool_index(pool_index: usize) CType {
    return .{ .index = @enumFromInt(CType.Index.first_pool_index + pool_index) };
}

pub fn to_pool_index(ctype: CType) ?u32 {
    const pool_index, const is_null =
        @sub_with_overflow(@int_from_enum(ctype.index), CType.Index.first_pool_index);
    return switch (is_null) {
        0 => pool_index,
        1 => null,
    };
}

pub fn eql(lhs: CType, rhs: CType) bool {
    return lhs.index == rhs.index;
}

pub fn is_bool(ctype: CType) bool {
    return switch (ctype.index) {
        ._Bool, .bool => true,
        else => false,
    };
}

pub fn is_integer(ctype: CType) bool {
    return switch (ctype.index) {
        .char,
        .@"signed char",
        .short,
        .int,
        .long,
        .@"long long",
        .@"unsigned char",
        .@"unsigned short",
        .@"unsigned int",
        .@"unsigned long",
        .@"unsigned long long",
        .size_t,
        .ptrdiff_t,
        .uint8_t,
        .int8_t,
        .uint16_t,
        .int16_t,
        .uint32_t,
        .int32_t,
        .uint64_t,
        .int64_t,
        .uintptr_t,
        .intptr_t,
        .zig_u128,
        .zig_i128,
        => true,
        else => false,
    };
}

pub fn signedness(ctype: CType, mod: *Module) std.builtin.Signedness {
    return switch (ctype.index) {
        .char => mod.resolved_target.result.char_signedness(),
        .@"signed char",
        .short,
        .int,
        .long,
        .@"long long",
        .ptrdiff_t,
        .int8_t,
        .int16_t,
        .int32_t,
        .int64_t,
        .intptr_t,
        .zig_i128,
        => .signed,
        .@"unsigned char",
        .@"unsigned short",
        .@"unsigned int",
        .@"unsigned long",
        .@"unsigned long long",
        .size_t,
        .uint8_t,
        .uint16_t,
        .uint32_t,
        .uint64_t,
        .uintptr_t,
        .zig_u128,
        => .unsigned,
        else => unreachable,
    };
}

pub fn is_float(ctype: CType) bool {
    return switch (ctype.index) {
        .float,
        .double,
        .@"long double",
        .zig_f16,
        .zig_f32,
        .zig_f64,
        .zig_f80,
        .zig_f128,
        .zig_c_longdouble,
        => true,
        else => false,
    };
}

pub fn to_signed(ctype: CType) CType {
    return switch (ctype.index) {
        .char, .@"signed char", .@"unsigned char" => .{ .index = .@"signed char" },
        .short, .@"unsigned short" => .{ .index = .short },
        .int, .@"unsigned int" => .{ .index = .int },
        .long, .@"unsigned long" => .{ .index = .long },
        .@"long long", .@"unsigned long long" => .{ .index = .@"long long" },
        .size_t, .ptrdiff_t => .{ .index = .ptrdiff_t },
        .uint8_t, .int8_t => .{ .index = .int8_t },
        .uint16_t, .int16_t => .{ .index = .int16_t },
        .uint32_t, .int32_t => .{ .index = .int32_t },
        .uint64_t, .int64_t => .{ .index = .int64_t },
        .uintptr_t, .intptr_t => .{ .index = .intptr_t },
        .zig_u128, .zig_i128 => .{ .index = .zig_i128 },
        .float,
        .double,
        .@"long double",
        .zig_f16,
        .zig_f32,
        .zig_f80,
        .zig_f128,
        .zig_c_longdouble,
        => ctype,
        else => unreachable,
    };
}

pub fn to_unsigned(ctype: CType) CType {
    return switch (ctype.index) {
        .char, .@"signed char", .@"unsigned char" => .{ .index = .@"unsigned char" },
        .short, .@"unsigned short" => .{ .index = .@"unsigned short" },
        .int, .@"unsigned int" => .{ .index = .@"unsigned int" },
        .long, .@"unsigned long" => .{ .index = .@"unsigned long" },
        .@"long long", .@"unsigned long long" => .{ .index = .@"unsigned long long" },
        .size_t, .ptrdiff_t => .{ .index = .size_t },
        .uint8_t, .int8_t => .{ .index = .uint8_t },
        .uint16_t, .int16_t => .{ .index = .uint16_t },
        .uint32_t, .int32_t => .{ .index = .uint32_t },
        .uint64_t, .int64_t => .{ .index = .uint64_t },
        .uintptr_t, .intptr_t => .{ .index = .uintptr_t },
        .zig_u128, .zig_i128 => .{ .index = .zig_u128 },
        else => unreachable,
    };
}

pub fn to_signedness(ctype: CType, s: std.builtin.Signedness) CType {
    return switch (s) {
        .unsigned => ctype.to_unsigned(),
        .signed => ctype.to_signed(),
    };
}

pub fn get_standard_define_abbrev(ctype: CType) ?[]const u8 {
    return switch (ctype.index) {
        .char => "CHAR",
        .@"signed char" => "SCHAR",
        .short => "SHRT",
        .int => "INT",
        .long => "LONG",
        .@"long long" => "LLONG",
        .@"unsigned char" => "UCHAR",
        .@"unsigned short" => "USHRT",
        .@"unsigned int" => "UINT",
        .@"unsigned long" => "ULONG",
        .@"unsigned long long" => "ULLONG",
        .float => "FLT",
        .double => "DBL",
        .@"long double" => "LDBL",
        .size_t => "SIZE",
        .ptrdiff_t => "PTRDIFF",
        .uint8_t => "UINT8",
        .int8_t => "INT8",
        .uint16_t => "UINT16",
        .int16_t => "INT16",
        .uint32_t => "UINT32",
        .int32_t => "INT32",
        .uint64_t => "UINT64",
        .int64_t => "INT64",
        .uintptr_t => "UINTPTR",
        .intptr_t => "INTPTR",
        else => null,
    };
}

pub fn render_literal_prefix(ctype: CType, writer: anytype, kind: Kind, pool: *const Pool) @TypeOf(writer).Error!void {
    switch (ctype.info(pool)) {
        .basic => |basic_info| switch (basic_info) {
            .void => unreachable,
            ._Bool,
            .char,
            .@"signed char",
            .short,
            .@"unsigned short",
            .bool,
            .size_t,
            .ptrdiff_t,
            .uintptr_t,
            .intptr_t,
            => switch (kind) {
                else => try writer.print("({s})", .{@tag_name(basic_info)}),
                .global => {},
            },
            .int,
            .long,
            .@"long long",
            .@"unsigned char",
            .@"unsigned int",
            .@"unsigned long",
            .@"unsigned long long",
            .float,
            .double,
            .@"long double",
            => {},
            .uint8_t,
            .int8_t,
            .uint16_t,
            .int16_t,
            .uint32_t,
            .int32_t,
            .uint64_t,
            .int64_t,
            => try writer.print("{s}_C(", .{ctype.get_standard_define_abbrev().?}),
            .zig_u128,
            .zig_i128,
            .zig_f16,
            .zig_f32,
            .zig_f64,
            .zig_f80,
            .zig_f128,
            .zig_c_longdouble,
            => try writer.print("zig_{s}_{s}(", .{
                switch (kind) {
                    else => "make",
                    .global => "init",
                },
                @tag_name(basic_info)["zig_".len..],
            }),
            .va_list => unreachable,
            _ => unreachable,
        },
        .array, .vector => try writer.write_byte('{'),
        else => unreachable,
    }
}

pub fn render_literal_suffix(ctype: CType, writer: anytype, pool: *const Pool) @TypeOf(writer).Error!void {
    switch (ctype.info(pool)) {
        .basic => |basic_info| switch (basic_info) {
            .void => unreachable,
            ._Bool => {},
            .char,
            .@"signed char",
            .short,
            .int,
            => {},
            .long => try writer.write_byte('l'),
            .@"long long" => try writer.write_all("ll"),
            .@"unsigned char",
            .@"unsigned short",
            .@"unsigned int",
            => try writer.write_byte('u'),
            .@"unsigned long",
            .size_t,
            .uintptr_t,
            => try writer.write_all("ul"),
            .@"unsigned long long" => try writer.write_all("ull"),
            .float => try writer.write_byte('f'),
            .double => {},
            .@"long double" => try writer.write_byte('l'),
            .bool,
            .ptrdiff_t,
            .intptr_t,
            => {},
            .uint8_t,
            .int8_t,
            .uint16_t,
            .int16_t,
            .uint32_t,
            .int32_t,
            .uint64_t,
            .int64_t,
            .zig_u128,
            .zig_i128,
            .zig_f16,
            .zig_f32,
            .zig_f64,
            .zig_f80,
            .zig_f128,
            .zig_c_longdouble,
            => try writer.write_byte(')'),
            .va_list => unreachable,
            _ => unreachable,
        },
        .array, .vector => try writer.write_byte('}'),
        else => unreachable,
    }
}

pub fn float_active_bits(ctype: CType, mod: *Module) u16 {
    const target = &mod.resolved_target.result;
    return switch (ctype.index) {
        .float => target.c_type_bit_size(.float),
        .double => target.c_type_bit_size(.double),
        .@"long double", .zig_c_longdouble => target.c_type_bit_size(.longdouble),
        .zig_f16 => 16,
        .zig_f32 => 32,
        .zig_f64 => 64,
        .zig_f80 => 80,
        .zig_f128 => 128,
        else => unreachable,
    };
}

pub fn byte_size(ctype: CType, pool: *const Pool, mod: *Module) u64 {
    const target = &mod.resolved_target.result;
    return switch (ctype.info(pool)) {
        .basic => |basic_info| switch (basic_info) {
            .void => 0,
            .char, .@"signed char", ._Bool, .@"unsigned char", .bool, .uint8_t, .int8_t => 1,
            .short => target.c_type_byte_size(.short),
            .int => target.c_type_byte_size(.int),
            .long => target.c_type_byte_size(.long),
            .@"long long" => target.c_type_byte_size(.longlong),
            .@"unsigned short" => target.c_type_byte_size(.ushort),
            .@"unsigned int" => target.c_type_byte_size(.uint),
            .@"unsigned long" => target.c_type_byte_size(.ulong),
            .@"unsigned long long" => target.c_type_byte_size(.ulonglong),
            .float => target.c_type_byte_size(.float),
            .double => target.c_type_byte_size(.double),
            .@"long double" => target.c_type_byte_size(.longdouble),
            .size_t,
            .ptrdiff_t,
            .uintptr_t,
            .intptr_t,
            => @div_exact(target.ptr_bit_width(), 8),
            .uint16_t, .int16_t, .zig_f16 => 2,
            .uint32_t, .int32_t, .zig_f32 => 4,
            .uint64_t, .int64_t, .zig_f64 => 8,
            .zig_u128, .zig_i128, .zig_f128 => 16,
            .zig_f80 => if (target.c_type_bit_size(.longdouble) == 80)
                target.c_type_byte_size(.longdouble)
            else
                16,
            .zig_c_longdouble => target.c_type_byte_size(.longdouble),
            .va_list => unreachable,
            _ => unreachable,
        },
        .pointer => @div_exact(target.ptr_bit_width(), 8),
        .array, .vector => |sequence_info| sequence_info.elem_ctype.byte_size(pool, mod) * sequence_info.len,
        else => unreachable,
    };
}

pub fn info(ctype: CType, pool: *const Pool) Info {
    const pool_index = ctype.to_pool_index() orelse return .{ .basic = ctype.index };
    const item = pool.items.get(pool_index);
    switch (item.tag) {
        .basic => unreachable,
        .pointer => return .{ .pointer = .{
            .elem_ctype = .{ .index = @enumFromInt(item.data) },
        } },
        .pointer_const => return .{ .pointer = .{
            .elem_ctype = .{ .index = @enumFromInt(item.data) },
            .@"const" = true,
        } },
        .pointer_volatile => return .{ .pointer = .{
            .elem_ctype = .{ .index = @enumFromInt(item.data) },
            .@"volatile" = true,
        } },
        .pointer_const_volatile => return .{ .pointer = .{
            .elem_ctype = .{ .index = @enumFromInt(item.data) },
            .@"const" = true,
            .@"volatile" = true,
        } },
        .aligned => {
            const extra = pool.get_extra(Pool.Aligned, item.data);
            return .{ .aligned = .{
                .ctype = .{ .index = extra.ctype },
                .alignas = extra.flags.alignas,
            } };
        },
        .array_small => {
            const extra = pool.get_extra(Pool.SequenceSmall, item.data);
            return .{ .array = .{
                .elem_ctype = .{ .index = extra.elem_ctype },
                .len = extra.len,
            } };
        },
        .array_large => {
            const extra = pool.get_extra(Pool.SequenceLarge, item.data);
            return .{ .array = .{
                .elem_ctype = .{ .index = extra.elem_ctype },
                .len = extra.len(),
            } };
        },
        .vector => {
            const extra = pool.get_extra(Pool.SequenceSmall, item.data);
            return .{ .vector = .{
                .elem_ctype = .{ .index = extra.elem_ctype },
                .len = extra.len,
            } };
        },
        .fwd_decl_struct_anon => {
            const extra_trail = pool.get_extra_trail(Pool.FwdDeclAnon, item.data);
            return .{ .fwd_decl = .{
                .tag = .@"struct",
                .name = .{ .anon = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                } },
            } };
        },
        .fwd_decl_union_anon => {
            const extra_trail = pool.get_extra_trail(Pool.FwdDeclAnon, item.data);
            return .{ .fwd_decl = .{
                .tag = .@"union",
                .name = .{ .anon = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                } },
            } };
        },
        .fwd_decl_struct => return .{ .fwd_decl = .{
            .tag = .@"struct",
            .name = .{ .owner_decl = @enumFromInt(item.data) },
        } },
        .fwd_decl_union => return .{ .fwd_decl = .{
            .tag = .@"union",
            .name = .{ .owner_decl = @enumFromInt(item.data) },
        } },
        .aggregate_struct_anon => {
            const extra_trail = pool.get_extra_trail(Pool.AggregateAnon, item.data);
            return .{ .aggregate = .{
                .tag = .@"struct",
                .name = .{ .anon = .{
                    .owner_decl = extra_trail.extra.owner_decl,
                    .id = extra_trail.extra.id,
                } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_union_anon => {
            const extra_trail = pool.get_extra_trail(Pool.AggregateAnon, item.data);
            return .{ .aggregate = .{
                .tag = .@"union",
                .name = .{ .anon = .{
                    .owner_decl = extra_trail.extra.owner_decl,
                    .id = extra_trail.extra.id,
                } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_struct_packed_anon => {
            const extra_trail = pool.get_extra_trail(Pool.AggregateAnon, item.data);
            return .{ .aggregate = .{
                .tag = .@"struct",
                .@"packed" = true,
                .name = .{ .anon = .{
                    .owner_decl = extra_trail.extra.owner_decl,
                    .id = extra_trail.extra.id,
                } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_union_packed_anon => {
            const extra_trail = pool.get_extra_trail(Pool.AggregateAnon, item.data);
            return .{ .aggregate = .{
                .tag = .@"union",
                .@"packed" = true,
                .name = .{ .anon = .{
                    .owner_decl = extra_trail.extra.owner_decl,
                    .id = extra_trail.extra.id,
                } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_struct => {
            const extra_trail = pool.get_extra_trail(Pool.Aggregate, item.data);
            return .{ .aggregate = .{
                .tag = .@"struct",
                .name = .{ .fwd_decl = .{ .index = extra_trail.extra.fwd_decl } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_union => {
            const extra_trail = pool.get_extra_trail(Pool.Aggregate, item.data);
            return .{ .aggregate = .{
                .tag = .@"union",
                .name = .{ .fwd_decl = .{ .index = extra_trail.extra.fwd_decl } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_struct_packed => {
            const extra_trail = pool.get_extra_trail(Pool.Aggregate, item.data);
            return .{ .aggregate = .{
                .tag = .@"struct",
                .@"packed" = true,
                .name = .{ .fwd_decl = .{ .index = extra_trail.extra.fwd_decl } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .aggregate_union_packed => {
            const extra_trail = pool.get_extra_trail(Pool.Aggregate, item.data);
            return .{ .aggregate = .{
                .tag = .@"union",
                .@"packed" = true,
                .name = .{ .fwd_decl = .{ .index = extra_trail.extra.fwd_decl } },
                .fields = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.fields_len,
                },
            } };
        },
        .function => {
            const extra_trail = pool.get_extra_trail(Pool.Function, item.data);
            return .{ .function = .{
                .return_ctype = .{ .index = extra_trail.extra.return_ctype },
                .param_ctypes = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.param_ctypes_len,
                },
                .varargs = false,
            } };
        },
        .function_varargs => {
            const extra_trail = pool.get_extra_trail(Pool.Function, item.data);
            return .{ .function = .{
                .return_ctype = .{ .index = extra_trail.extra.return_ctype },
                .param_ctypes = .{
                    .extra_index = extra_trail.trail.extra_index,
                    .len = extra_trail.extra.param_ctypes_len,
                },
                .varargs = true,
            } };
        },
    }
}

pub fn hash(ctype: CType, pool: *const Pool) Pool.Map.Hash {
    return if (ctype.to_pool_index()) |pool_index|
        pool.map.entries.items(.hash)[pool_index]
    else
        CType.Index.basic_hashes[@int_from_enum(ctype.index)];
}

fn to_forward(ctype: CType, pool: *Pool, allocator: std.mem.Allocator) !CType {
    return switch (ctype.info(pool)) {
        .basic, .pointer, .fwd_decl => ctype,
        .aligned => |aligned_info| pool.get_aligned(allocator, .{
            .ctype = try aligned_info.ctype.to_forward(pool, allocator),
            .alignas = aligned_info.alignas,
        }),
        .array => |array_info| pool.get_array(allocator, .{
            .elem_ctype = try array_info.elem_ctype.to_forward(pool, allocator),
            .len = array_info.len,
        }),
        .vector => |vector_info| pool.get_vector(allocator, .{
            .elem_ctype = try vector_info.elem_ctype.to_forward(pool, allocator),
            .len = vector_info.len,
        }),
        .aggregate => |aggregate_info| switch (aggregate_info.name) {
            .anon => ctype,
            .fwd_decl => |fwd_decl| fwd_decl,
        },
        .function => unreachable,
    };
}

const Index = enum(u32) {
    void,

    // C basic types
    char,

    @"signed char",
    short,
    int,
    long,
    @"long long",

    _Bool,
    @"unsigned char",
    @"unsigned short",
    @"unsigned int",
    @"unsigned long",
    @"unsigned long long",

    float,
    double,
    @"long double",

    // C header types
    //  - stdbool.h
    bool,
    //  - stddef.h
    size_t,
    ptrdiff_t,
    //  - stdint.h
    uint8_t,
    int8_t,
    uint16_t,
    int16_t,
    uint32_t,
    int32_t,
    uint64_t,
    int64_t,
    uintptr_t,
    intptr_t,
    //  - stdarg.h
    va_list,

    // zig.h types
    zig_u128,
    zig_i128,
    zig_f16,
    zig_f32,
    zig_f64,
    zig_f80,
    zig_f128,
    zig_c_longdouble,

    _,

    const first_pool_index: u32 = @typeInfo(CType.Index).Enum.fields.len;
    const basic_hashes = init: {
        @setEvalBranchQuota(1_600);
        var basic_hashes_init: [first_pool_index]Pool.Map.Hash = undefined;
        for (&basic_hashes_init, 0..) |*basic_hash, index| {
            const ctype_index: CType.Index = @enumFromInt(index);
            var hasher = Pool.Hasher.init;
            hasher.update(@int_from_enum(ctype_index));
            basic_hash.* = hasher.final(.basic);
        }
        break :init basic_hashes_init;
    };
};

const Slice = struct {
    extra_index: Pool.ExtraIndex,
    len: u32,

    pub fn at(slice: CType.Slice, index: usize, pool: *const Pool) CType {
        var extra: Pool.ExtraTrail = .{ .extra_index = slice.extra_index };
        return .{ .index = extra.next(slice.len, CType.Index, pool)[index] };
    }
};

pub const Kind = enum {
    forward,
    forward_parameter,
    complete,
    global,
    parameter,

    pub fn is_forward(kind: Kind) bool {
        return switch (kind) {
            .forward, .forward_parameter => true,
            .complete, .global, .parameter => false,
        };
    }

    pub fn is_parameter(kind: Kind) bool {
        return switch (kind) {
            .forward_parameter, .parameter => true,
            .forward, .complete, .global => false,
        };
    }

    pub fn as_parameter(kind: Kind) Kind {
        return switch (kind) {
            .forward, .forward_parameter => .forward_parameter,
            .complete, .parameter, .global => .parameter,
        };
    }

    pub fn no_parameter(kind: Kind) Kind {
        return switch (kind) {
            .forward, .forward_parameter => .forward,
            .complete, .parameter => .complete,
            .global => .global,
        };
    }
};

pub const Info = union(enum) {
    basic: CType.Index,
    pointer: Pointer,
    aligned: Aligned,
    array: Sequence,
    vector: Sequence,
    fwd_decl: FwdDecl,
    aggregate: Aggregate,
    function: Function,

    const Tag = @typeInfo(Info).Union.tag_type.?;

    pub const Pointer = struct {
        elem_ctype: CType,
        @"const": bool = false,
        @"volatile": bool = false,

        fn tag(pointer_info: Pointer) Pool.Tag {
            return @enumFromInt(@int_from_enum(Pool.Tag.pointer) +
                @as(u2, @bit_cast(packed struct(u2) {
                @"const": bool,
                @"volatile": bool,
            }{
                .@"const" = pointer_info.@"const",
                .@"volatile" = pointer_info.@"volatile",
            })));
        }
    };

    pub const Aligned = struct {
        ctype: CType,
        alignas: AlignAs,
    };

    pub const Sequence = struct {
        elem_ctype: CType,
        len: u64,
    };

    pub const AggregateTag = enum { @"enum", @"struct", @"union" };

    pub const Field = struct {
        name: Pool.String,
        ctype: CType,
        alignas: AlignAs,

        pub const Slice = struct {
            extra_index: Pool.ExtraIndex,
            len: u32,

            pub fn at(slice: Field.Slice, index: usize, pool: *const Pool) Field {
                assert(index < slice.len);
                const extra = pool.get_extra(Pool.Field, @int_cast(slice.extra_index +
                    index * @typeInfo(Pool.Field).Struct.fields.len));
                return .{
                    .name = .{ .index = extra.name },
                    .ctype = .{ .index = extra.ctype },
                    .alignas = extra.flags.alignas,
                };
            }

            fn eql_adapted(
                lhs_slice: Field.Slice,
                lhs_pool: *const Pool,
                rhs_slice: Field.Slice,
                rhs_pool: *const Pool,
                pool_adapter: anytype,
            ) bool {
                if (lhs_slice.len != rhs_slice.len) return false;
                for (0..lhs_slice.len) |index| {
                    if (!lhs_slice.at(index, lhs_pool).eql_adapted(
                        lhs_pool,
                        rhs_slice.at(index, rhs_pool),
                        rhs_pool,
                        pool_adapter,
                    )) return false;
                }
                return true;
            }
        };

        fn eql_adapted(
            lhs_field: Field,
            lhs_pool: *const Pool,
            rhs_field: Field,
            rhs_pool: *const Pool,
            pool_adapter: anytype,
        ) bool {
            if (!std.meta.eql(lhs_field.alignas, rhs_field.alignas)) return false;
            if (!pool_adapter.eql(lhs_field.ctype, rhs_field.ctype)) return false;
            return if (lhs_field.name.to_pool_slice(lhs_pool)) |lhs_name|
                if (rhs_field.name.to_pool_slice(rhs_pool)) |rhs_name|
                    std.mem.eql(u8, lhs_name, rhs_name)
                else
                    false
            else
                lhs_field.name.index == rhs_field.name.index;
        }
    };

    pub const FwdDecl = struct {
        tag: AggregateTag,
        name: union(enum) {
            anon: Field.Slice,
            owner_decl: DeclIndex,
        },
    };

    pub const Aggregate = struct {
        tag: AggregateTag,
        @"packed": bool = false,
        name: union(enum) {
            anon: struct {
                owner_decl: DeclIndex,
                id: u32,
            },
            fwd_decl: CType,
        },
        fields: Field.Slice,
    };

    pub const Function = struct {
        return_ctype: CType,
        param_ctypes: CType.Slice,
        varargs: bool = false,
    };

    pub fn eql_adapted(
        lhs_info: Info,
        lhs_pool: *const Pool,
        rhs_ctype: CType,
        rhs_pool: *const Pool,
        pool_adapter: anytype,
    ) bool {
        const rhs_info = rhs_ctype.info(rhs_pool);
        if (@as(Info.Tag, lhs_info) != @as(Info.Tag, rhs_info)) return false;
        return switch (lhs_info) {
            .basic => |lhs_basic_info| lhs_basic_info == rhs_info.basic,
            .pointer => |lhs_pointer_info| lhs_pointer_info.@"const" == rhs_info.pointer.@"const" and
                lhs_pointer_info.@"volatile" == rhs_info.pointer.@"volatile" and
                pool_adapter.eql(lhs_pointer_info.elem_ctype, rhs_info.pointer.elem_ctype),
            .aligned => |lhs_aligned_info| std.meta.eql(lhs_aligned_info.alignas, rhs_info.aligned.alignas) and
                pool_adapter.eql(lhs_aligned_info.ctype, rhs_info.aligned.ctype),
            .array => |lhs_array_info| lhs_array_info.len == rhs_info.array.len and
                pool_adapter.eql(lhs_array_info.elem_ctype, rhs_info.array.elem_ctype),
            .vector => |lhs_vector_info| lhs_vector_info.len == rhs_info.vector.len and
                pool_adapter.eql(lhs_vector_info.elem_ctype, rhs_info.vector.elem_ctype),
            .fwd_decl => |lhs_fwd_decl_info| lhs_fwd_decl_info.tag == rhs_info.fwd_decl.tag and
                switch (lhs_fwd_decl_info.name) {
                .anon => |lhs_anon| rhs_info.fwd_decl.name == .anon and lhs_anon.eql_adapted(
                    lhs_pool,
                    rhs_info.fwd_decl.name.anon,
                    rhs_pool,
                    pool_adapter,
                ),
                .owner_decl => |lhs_owner_decl| rhs_info.fwd_decl.name == .owner_decl and
                    lhs_owner_decl == rhs_info.fwd_decl.name.owner_decl,
            },
            .aggregate => |lhs_aggregate_info| lhs_aggregate_info.tag == rhs_info.aggregate.tag and
                lhs_aggregate_info.@"packed" == rhs_info.aggregate.@"packed" and
                switch (lhs_aggregate_info.name) {
                .anon => |lhs_anon| rhs_info.aggregate.name == .anon and
                    lhs_anon.owner_decl == rhs_info.aggregate.name.anon.owner_decl and
                    lhs_anon.id == rhs_info.aggregate.name.anon.id,
                .fwd_decl => |lhs_fwd_decl| rhs_info.aggregate.name == .fwd_decl and
                    pool_adapter.eql(lhs_fwd_decl, rhs_info.aggregate.name.fwd_decl),
            } and lhs_aggregate_info.fields.eql_adapted(
                lhs_pool,
                rhs_info.aggregate.fields,
                rhs_pool,
                pool_adapter,
            ),
            .function => |lhs_function_info| lhs_function_info.param_ctypes.len ==
                rhs_info.function.param_ctypes.len and
                pool_adapter.eql(lhs_function_info.return_ctype, rhs_info.function.return_ctype) and
                for (0..lhs_function_info.param_ctypes.len) |param_index|
            {
                if (!pool_adapter.eql(
                    lhs_function_info.param_ctypes.at(param_index, lhs_pool),
                    rhs_info.function.param_ctypes.at(param_index, rhs_pool),
                )) break false;
            } else true,
        };
    }
};

pub const Pool = struct {
    map: Map,
    items: std.MultiArrayList(Item),
    extra: std.ArrayListUnmanaged(u32),

    string_map: Map,
    string_indices: std.ArrayListUnmanaged(u32),
    string_bytes: std.ArrayListUnmanaged(u8),

    const Map = std.AutoArrayHashMapUnmanaged(void, void);

    pub const String = struct {
        index: String.Index,

        const FormatData = struct { string: String, pool: *const Pool };
        fn format(
            data: FormatData,
            comptime fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (fmt_str.len > 0) @compile_error("invalid format string '" ++ fmt_str ++ "'");
            if (data.string.to_slice(data.pool)) |slice|
                try writer.write_all(slice)
            else
                try writer.print("f{d}", .{@int_from_enum(data.string.index)});
        }
        pub fn fmt(str: String, pool: *const Pool) std.fmt.Formatter(format) {
            return .{ .data = .{ .string = str, .pool = pool } };
        }

        fn from_unnamed(index: u31) String {
            return .{ .index = @enumFromInt(index) };
        }

        fn is_named(str: String) bool {
            return @int_from_enum(str.index) >= String.Index.first_named_index;
        }

        pub fn to_slice(str: String, pool: *const Pool) ?[]const u8 {
            return str.to_pool_slice(pool) orelse if (str.is_named()) @tag_name(str.index) else null;
        }

        fn to_pool_slice(str: String, pool: *const Pool) ?[]const u8 {
            if (str.to_pool_index()) |pool_index| {
                const start = pool.string_indices.items[pool_index + 0];
                const end = pool.string_indices.items[pool_index + 1];
                return pool.string_bytes.items[start..end];
            } else return null;
        }

        fn from_pool_index(pool_index: usize) String {
            return .{ .index = @enumFromInt(String.Index.first_pool_index + pool_index) };
        }

        fn to_pool_index(str: String) ?u32 {
            const pool_index, const is_null =
                @sub_with_overflow(@int_from_enum(str.index), String.Index.first_pool_index);
            return switch (is_null) {
                0 => pool_index,
                1 => null,
            };
        }

        const Index = enum(u32) {
            array = first_named_index,
            @"error",
            is_null,
            len,
            payload,
            ptr,
            tag,
            _,

            const first_named_index: u32 = 1 << 31;
            const first_pool_index: u32 = first_named_index + @typeInfo(String.Index).Enum.fields.len;
        };

        const Adapter = struct {
            pool: *const Pool,
            pub fn hash(_: @This(), slice: []const u8) Map.Hash {
                return @truncate(Hasher.Impl.hash(1, slice));
            }
            pub fn eql(string_adapter: @This(), lhs_slice: []const u8, _: void, rhs_index: usize) bool {
                const rhs_string = String.from_pool_index(rhs_index);
                const rhs_slice = rhs_string.to_pool_slice(string_adapter.pool).?;
                return std.mem.eql(u8, lhs_slice, rhs_slice);
            }
        };
    };

    pub const empty: Pool = .{
        .map = .{},
        .items = .{},
        .extra = .{},

        .string_map = .{},
        .string_indices = .{},
        .string_bytes = .{},
    };

    pub fn init(pool: *Pool, allocator: std.mem.Allocator) !void {
        if (pool.string_indices.items.len == 0)
            try pool.string_indices.append(allocator, 0);
    }

    pub fn deinit(pool: *Pool, allocator: std.mem.Allocator) void {
        pool.map.deinit(allocator);
        pool.items.deinit(allocator);
        pool.extra.deinit(allocator);

        pool.string_map.deinit(allocator);
        pool.string_indices.deinit(allocator);
        pool.string_bytes.deinit(allocator);

        pool.* = undefined;
    }

    pub fn move(pool: *Pool) Pool {
        defer pool.* = empty;
        return pool.*;
    }

    pub fn clear_retaining_capacity(pool: *Pool) void {
        pool.map.clear_retaining_capacity();
        pool.items.shrink_retaining_capacity(0);
        pool.extra.clear_retaining_capacity();

        pool.string_map.clear_retaining_capacity();
        pool.string_indices.shrink_retaining_capacity(1);
        pool.string_bytes.clear_retaining_capacity();
    }

    pub fn free_unused_capacity(pool: *Pool, allocator: std.mem.Allocator) void {
        pool.map.shrink_and_free(allocator, pool.map.count());
        pool.items.shrink_and_free(allocator, pool.items.len);
        pool.extra.shrink_and_free(allocator, pool.extra.items.len);

        pool.string_map.shrink_and_free(allocator, pool.string_map.count());
        pool.string_indices.shrink_and_free(allocator, pool.string_indices.items.len);
        pool.string_bytes.shrink_and_free(allocator, pool.string_bytes.items.len);
    }

    pub fn get_pointer(pool: *Pool, allocator: std.mem.Allocator, pointer_info: Info.Pointer) !CType {
        var hasher = Hasher.init;
        hasher.update(pointer_info.elem_ctype.hash(pool));
        return pool.tag_data(
            allocator,
            hasher,
            pointer_info.tag(),
            @int_from_enum(pointer_info.elem_ctype.index),
        );
    }

    pub fn get_aligned(pool: *Pool, allocator: std.mem.Allocator, aligned_info: Info.Aligned) !CType {
        return pool.tag_extra(allocator, .aligned, Aligned, .{
            .ctype = aligned_info.ctype.index,
            .flags = .{ .alignas = aligned_info.alignas },
        });
    }

    pub fn get_array(pool: *Pool, allocator: std.mem.Allocator, array_info: Info.Sequence) !CType {
        return if (std.math.cast(u32, array_info.len)) |small_len|
            pool.tag_extra(allocator, .array_small, SequenceSmall, .{
                .elem_ctype = array_info.elem_ctype.index,
                .len = small_len,
            })
        else
            pool.tag_extra(allocator, .array_large, SequenceLarge, .{
                .elem_ctype = array_info.elem_ctype.index,
                .len_lo = @truncate(array_info.len >> 0),
                .len_hi = @truncate(array_info.len >> 32),
            });
    }

    pub fn get_vector(pool: *Pool, allocator: std.mem.Allocator, vector_info: Info.Sequence) !CType {
        return pool.tag_extra(allocator, .vector, SequenceSmall, .{
            .elem_ctype = vector_info.elem_ctype.index,
            .len = @int_cast(vector_info.len),
        });
    }

    pub fn get_fwd_decl(
        pool: *Pool,
        allocator: std.mem.Allocator,
        fwd_decl_info: struct {
            tag: Info.AggregateTag,
            name: union(enum) {
                anon: []const Info.Field,
                owner_decl: DeclIndex,
            },
        },
    ) !CType {
        var hasher = Hasher.init;
        switch (fwd_decl_info.name) {
            .anon => |fields| {
                const ExpectedContents = [32]CType;
                var stack align(@max(
                    @alignOf(std.heap.StackFallbackAllocator(0)),
                    @alignOf(ExpectedContents),
                )) = std.heap.stack_fallback(@size_of(ExpectedContents), allocator);
                const stack_allocator = stack.get();
                const field_ctypes = try stack_allocator.alloc(CType, fields.len);
                defer stack_allocator.free(field_ctypes);
                for (field_ctypes, fields) |*field_ctype, field|
                    field_ctype.* = try field.ctype.to_forward(pool, allocator);
                const extra: FwdDeclAnon = .{ .fields_len = @int_cast(fields.len) };
                const extra_index = try pool.add_extra(
                    allocator,
                    FwdDeclAnon,
                    extra,
                    fields.len * @typeInfo(Field).Struct.fields.len,
                );
                for (fields, field_ctypes) |field, field_ctype| pool.add_hashed_extra_assume_capacity(
                    &hasher,
                    Field,
                    .{
                        .name = field.name.index,
                        .ctype = field_ctype.index,
                        .flags = .{ .alignas = field.alignas },
                    },
                );
                hasher.update_extra(FwdDeclAnon, extra, pool);
                return pool.tag_trailing_extra(allocator, hasher, switch (fwd_decl_info.tag) {
                    .@"struct" => .fwd_decl_struct_anon,
                    .@"union" => .fwd_decl_union_anon,
                    .@"enum" => unreachable,
                }, extra_index);
            },
            .owner_decl => |owner_decl| {
                hasher.update(owner_decl);
                return pool.tag_data(allocator, hasher, switch (fwd_decl_info.tag) {
                    .@"struct" => .fwd_decl_struct,
                    .@"union" => .fwd_decl_union,
                    .@"enum" => unreachable,
                }, @int_from_enum(owner_decl));
            },
        }
    }

    pub fn get_aggregate(
        pool: *Pool,
        allocator: std.mem.Allocator,
        aggregate_info: struct {
            tag: Info.AggregateTag,
            @"packed": bool = false,
            name: union(enum) {
                anon: struct {
                    owner_decl: DeclIndex,
                    id: u32,
                },
                fwd_decl: CType,
            },
            fields: []const Info.Field,
        },
    ) !CType {
        var hasher = Hasher.init;
        switch (aggregate_info.name) {
            .anon => |anon| {
                const extra: AggregateAnon = .{
                    .owner_decl = anon.owner_decl,
                    .id = anon.id,
                    .fields_len = @int_cast(aggregate_info.fields.len),
                };
                const extra_index = try pool.add_extra(
                    allocator,
                    AggregateAnon,
                    extra,
                    aggregate_info.fields.len * @typeInfo(Field).Struct.fields.len,
                );
                for (aggregate_info.fields) |field| pool.add_hashed_extra_assume_capacity(&hasher, Field, .{
                    .name = field.name.index,
                    .ctype = field.ctype.index,
                    .flags = .{ .alignas = field.alignas },
                });
                hasher.update_extra(AggregateAnon, extra, pool);
                return pool.tag_trailing_extra(allocator, hasher, switch (aggregate_info.tag) {
                    .@"struct" => switch (aggregate_info.@"packed") {
                        false => .aggregate_struct_anon,
                        true => .aggregate_struct_packed_anon,
                    },
                    .@"union" => switch (aggregate_info.@"packed") {
                        false => .aggregate_union_anon,
                        true => .aggregate_union_packed_anon,
                    },
                    .@"enum" => unreachable,
                }, extra_index);
            },
            .fwd_decl => |fwd_decl| {
                const extra: Aggregate = .{
                    .fwd_decl = fwd_decl.index,
                    .fields_len = @int_cast(aggregate_info.fields.len),
                };
                const extra_index = try pool.add_extra(
                    allocator,
                    Aggregate,
                    extra,
                    aggregate_info.fields.len * @typeInfo(Field).Struct.fields.len,
                );
                for (aggregate_info.fields) |field| pool.add_hashed_extra_assume_capacity(&hasher, Field, .{
                    .name = field.name.index,
                    .ctype = field.ctype.index,
                    .flags = .{ .alignas = field.alignas },
                });
                hasher.update_extra(Aggregate, extra, pool);
                return pool.tag_trailing_extra(allocator, hasher, switch (aggregate_info.tag) {
                    .@"struct" => switch (aggregate_info.@"packed") {
                        false => .aggregate_struct,
                        true => .aggregate_struct_packed,
                    },
                    .@"union" => switch (aggregate_info.@"packed") {
                        false => .aggregate_union,
                        true => .aggregate_union_packed,
                    },
                    .@"enum" => unreachable,
                }, extra_index);
            },
        }
    }

    pub fn get_function(
        pool: *Pool,
        allocator: std.mem.Allocator,
        function_info: struct {
            return_ctype: CType,
            param_ctypes: []const CType,
            varargs: bool = false,
        },
    ) !CType {
        var hasher = Hasher.init;
        const extra: Function = .{
            .return_ctype = function_info.return_ctype.index,
            .param_ctypes_len = @int_cast(function_info.param_ctypes.len),
        };
        const extra_index = try pool.add_extra(allocator, Function, extra, function_info.param_ctypes.len);
        for (function_info.param_ctypes) |param_ctype| {
            hasher.update(param_ctype.hash(pool));
            pool.extra.append_assume_capacity(@int_from_enum(param_ctype.index));
        }
        hasher.update_extra(Function, extra, pool);
        return pool.tag_trailing_extra(allocator, hasher, switch (function_info.varargs) {
            false => .function,
            true => .function_varargs,
        }, extra_index);
    }

    pub fn from_fields(
        pool: *Pool,
        allocator: std.mem.Allocator,
        tag: Info.AggregateTag,
        fields: []Info.Field,
        kind: Kind,
    ) !CType {
        sort_fields(fields);
        const fwd_decl = try pool.get_fwd_decl(allocator, .{
            .tag = tag,
            .name = .{ .anon = fields },
        });
        return if (kind.is_forward()) fwd_decl else pool.get_aggregate(allocator, .{
            .tag = tag,
            .name = .{ .fwd_decl = fwd_decl },
            .fields = fields,
        });
    }

    pub fn from_int_info(
        pool: *Pool,
        allocator: std.mem.Allocator,
        int_info: std.builtin.Type.Int,
        mod: *Module,
        kind: Kind,
    ) !CType {
        switch (int_info.bits) {
            0 => return CType.void,
            1...8 => switch (int_info.signedness) {
                .signed => return CType.i8,
                .unsigned => return CType.u8,
            },
            9...16 => switch (int_info.signedness) {
                .signed => return CType.i16,
                .unsigned => return CType.u16,
            },
            17...32 => switch (int_info.signedness) {
                .signed => return CType.i32,
                .unsigned => return CType.u32,
            },
            33...64 => switch (int_info.signedness) {
                .signed => return CType.i64,
                .unsigned => return CType.u64,
            },
            65...128 => switch (int_info.signedness) {
                .signed => return CType.i128,
                .unsigned => return CType.u128,
            },
            else => {
                const target = &mod.resolved_target.result;
                const abi_align = Type.int_abi_alignment(int_info.bits, target.*, false);
                const abi_align_bytes = abi_align.to_byte_units().?;
                const array_ctype = try pool.get_array(allocator, .{
                    .len = @div_exact(Type.int_abi_size(int_info.bits, target.*, false), abi_align_bytes),
                    .elem_ctype = try pool.from_int_info(allocator, .{
                        .signedness = .unsigned,
                        .bits = @int_cast(abi_align_bytes * 8),
                    }, mod, kind.no_parameter()),
                });
                if (!kind.is_parameter()) return array_ctype;
                var fields = [_]Info.Field{
                    .{
                        .name = .{ .index = .array },
                        .ctype = array_ctype,
                        .alignas = AlignAs.from_abi_alignment(abi_align),
                    },
                };
                return pool.from_fields(allocator, .@"struct", &fields, kind);
            },
        }
    }

    pub fn from_type(
        pool: *Pool,
        allocator: std.mem.Allocator,
        scratch: *std.ArrayListUnmanaged(u32),
        ty: Type,
        zcu: *Zcu,
        mod: *Module,
        kind: Kind,
    ) !CType {
        const ip = &zcu.intern_pool;
        switch (ty.to_intern()) {
            .u0_type,
            .i0_type,
            .anyopaque_type,
            .void_type,
            .empty_struct_type,
            .type_type,
            .comptime_int_type,
            .comptime_float_type,
            .null_type,
            .undefined_type,
            .enum_literal_type,
            => return CType.void,
            .u1_type, .u8_type => return CType.u8,
            .i8_type => return CType.i8,
            .u16_type => return CType.u16,
            .i16_type => return CType.i16,
            .u29_type, .u32_type => return CType.u32,
            .i32_type => return CType.i32,
            .u64_type => return CType.u64,
            .i64_type => return CType.i64,
            .u80_type, .u128_type => return CType.u128,
            .i128_type => return CType.i128,
            .usize_type => return CType.usize,
            .isize_type => return CType.isize,
            .c_char_type => return .{ .index = .char },
            .c_short_type => return .{ .index = .short },
            .c_ushort_type => return .{ .index = .@"unsigned short" },
            .c_int_type => return .{ .index = .int },
            .c_uint_type => return .{ .index = .@"unsigned int" },
            .c_long_type => return .{ .index = .long },
            .c_ulong_type => return .{ .index = .@"unsigned long" },
            .c_longlong_type => return .{ .index = .@"long long" },
            .c_ulonglong_type => return .{ .index = .@"unsigned long long" },
            .c_longdouble_type => return .{ .index = .@"long double" },
            .f16_type => return CType.f16,
            .f32_type => return CType.f32,
            .f64_type => return CType.f64,
            .f80_type => return CType.f80,
            .f128_type => return CType.f128,
            .bool_type, .optional_noreturn_type => return CType.bool,
            .noreturn_type,
            .anyframe_type,
            .generic_poison_type,
            => unreachable,
            .atomic_order_type,
            .atomic_rmw_op_type,
            .calling_convention_type,
            .address_space_type,
            .float_mode_type,
            .reduce_op_type,
            .call_modifier_type,
            => |ip_index| return pool.from_type(
                allocator,
                scratch,
                Type.from_interned(ip.load_enum_type(ip_index).tag_ty),
                zcu,
                mod,
                kind,
            ),
            .anyerror_type,
            .anyerror_void_error_union_type,
            .adhoc_inferred_error_set_type,
            => return pool.from_int_info(allocator, .{
                .signedness = .unsigned,
                .bits = zcu.error_set_bits(),
            }, mod, kind),
            .manyptr_u8_type,
            => return pool.get_pointer(allocator, .{
                .elem_ctype = CType.u8,
            }),
            .manyptr_const_u8_type,
            .manyptr_const_u8_sentinel_0_type,
            => return pool.get_pointer(allocator, .{
                .elem_ctype = CType.u8,
                .@"const" = true,
            }),
            .single_const_pointer_to_comptime_int_type,
            => return pool.get_pointer(allocator, .{
                .elem_ctype = CType.void,
                .@"const" = true,
            }),
            .slice_const_u8_type,
            .slice_const_u8_sentinel_0_type,
            => {
                const target = &mod.resolved_target.result;
                var fields = [_]Info.Field{
                    .{
                        .name = .{ .index = .ptr },
                        .ctype = try pool.get_pointer(allocator, .{
                            .elem_ctype = CType.u8,
                            .@"const" = true,
                        }),
                        .alignas = AlignAs.from_abi_alignment(Type.ptr_abi_alignment(target.*)),
                    },
                    .{
                        .name = .{ .index = .len },
                        .ctype = CType.usize,
                        .alignas = AlignAs.from_abi_alignment(
                            Type.int_abi_alignment(target.ptr_bit_width(), target.*, false),
                        ),
                    },
                };
                return pool.from_fields(allocator, .@"struct", &fields, kind);
            },

            .undef,
            .zero,
            .zero_usize,
            .zero_u8,
            .one,
            .one_usize,
            .one_u8,
            .four_u8,
            .negative_one,
            .calling_convention_c,
            .calling_convention_inline,
            .void_value,
            .unreachable_value,
            .null_value,
            .bool_true,
            .bool_false,
            .empty_struct,
            .generic_poison,
            .none,
            => unreachable,

            //.prefetch_options_type,
            //.export_options_type,
            //.extern_options_type,
            //.type_info_type,
            //_,
            else => |ip_index| switch (ip.index_to_key(ip_index)) {
                .int_type => |int_info| return pool.from_int_info(allocator, int_info, mod, kind),
                .ptr_type => |ptr_info| switch (ptr_info.flags.size) {
                    .One, .Many, .C => {
                        const elem_ctype = elem_ctype: {
                            if (ptr_info.packed_offset.host_size > 0 and
                                ptr_info.flags.vector_index == .none)
                                break :elem_ctype try pool.from_int_info(allocator, .{
                                    .signedness = .unsigned,
                                    .bits = ptr_info.packed_offset.host_size * 8,
                                }, mod, .forward);
                            const elem: Info.Aligned = .{
                                .ctype = try pool.from_type(
                                    allocator,
                                    scratch,
                                    Type.from_interned(ptr_info.child),
                                    zcu,
                                    mod,
                                    .forward,
                                ),
                                .alignas = AlignAs.from_alignment(.{
                                    .@"align" = ptr_info.flags.alignment,
                                    .abi = Type.from_interned(ptr_info.child).abi_alignment(zcu),
                                }),
                            };
                            break :elem_ctype if (elem.alignas.abi_order().compare(.gte))
                                elem.ctype
                            else
                                try pool.get_aligned(allocator, elem);
                        };
                        const elem_tag: Info.Tag = switch (elem_ctype.info(pool)) {
                            .aligned => |aligned_info| aligned_info.ctype.info(pool),
                            else => |elem_tag| elem_tag,
                        };
                        return pool.get_pointer(allocator, .{
                            .elem_ctype = elem_ctype,
                            .@"const" = switch (elem_tag) {
                                .basic,
                                .pointer,
                                .aligned,
                                .array,
                                .vector,
                                .fwd_decl,
                                .aggregate,
                                => ptr_info.flags.is_const,
                                .function => false,
                            },
                            .@"volatile" = ptr_info.flags.is_volatile,
                        });
                    },
                    .Slice => {
                        const target = &mod.resolved_target.result;
                        var fields = [_]Info.Field{
                            .{
                                .name = .{ .index = .ptr },
                                .ctype = try pool.from_type(
                                    allocator,
                                    scratch,
                                    Type.from_interned(ip.slice_ptr_type(ip_index)),
                                    zcu,
                                    mod,
                                    kind,
                                ),
                                .alignas = AlignAs.from_abi_alignment(Type.ptr_abi_alignment(target.*)),
                            },
                            .{
                                .name = .{ .index = .len },
                                .ctype = CType.usize,
                                .alignas = AlignAs.from_abi_alignment(
                                    Type.int_abi_alignment(target.ptr_bit_width(), target.*, false),
                                ),
                            },
                        };
                        return pool.from_fields(allocator, .@"struct", &fields, kind);
                    },
                },
                .array_type => |array_info| {
                    const len = array_info.len_including_sentinel();
                    if (len == 0) return CType.void;
                    const elem_type = Type.from_interned(array_info.child);
                    const elem_ctype = try pool.from_type(
                        allocator,
                        scratch,
                        elem_type,
                        zcu,
                        mod,
                        kind.no_parameter(),
                    );
                    if (elem_ctype.index == .void) return CType.void;
                    const array_ctype = try pool.get_array(allocator, .{
                        .elem_ctype = elem_ctype,
                        .len = len,
                    });
                    if (!kind.is_parameter()) return array_ctype;
                    var fields = [_]Info.Field{
                        .{
                            .name = .{ .index = .array },
                            .ctype = array_ctype,
                            .alignas = AlignAs.from_abi_alignment(elem_type.abi_alignment(zcu)),
                        },
                    };
                    return pool.from_fields(allocator, .@"struct", &fields, kind);
                },
                .vector_type => |vector_info| {
                    if (vector_info.len == 0) return CType.void;
                    const elem_type = Type.from_interned(vector_info.child);
                    const elem_ctype = try pool.from_type(
                        allocator,
                        scratch,
                        elem_type,
                        zcu,
                        mod,
                        kind.no_parameter(),
                    );
                    if (elem_ctype.index == .void) return CType.void;
                    const vector_ctype = try pool.get_vector(allocator, .{
                        .elem_ctype = elem_ctype,
                        .len = vector_info.len,
                    });
                    if (!kind.is_parameter()) return vector_ctype;
                    var fields = [_]Info.Field{
                        .{
                            .name = .{ .index = .array },
                            .ctype = vector_ctype,
                            .alignas = AlignAs.from_abi_alignment(elem_type.abi_alignment(zcu)),
                        },
                    };
                    return pool.from_fields(allocator, .@"struct", &fields, kind);
                },
                .opt_type => |payload_type| {
                    if (ip.is_no_return(payload_type)) return CType.void;
                    const payload_ctype = try pool.from_type(
                        allocator,
                        scratch,
                        Type.from_interned(payload_type),
                        zcu,
                        mod,
                        kind.no_parameter(),
                    );
                    if (payload_ctype.index == .void) return CType.bool;
                    switch (payload_type) {
                        .anyerror_type => return payload_ctype,
                        else => switch (ip.index_to_key(payload_type)) {
                            .ptr_type => |payload_ptr_info| if (payload_ptr_info.flags.size != .C and
                                !payload_ptr_info.flags.is_allowzero) return payload_ctype,
                            .error_set_type, .inferred_error_set_type => return payload_ctype,
                            else => {},
                        },
                    }
                    var fields = [_]Info.Field{
                        .{
                            .name = .{ .index = .is_null },
                            .ctype = CType.bool,
                            .alignas = AlignAs.from_abi_alignment(.@"1"),
                        },
                        .{
                            .name = .{ .index = .payload },
                            .ctype = payload_ctype,
                            .alignas = AlignAs.from_abi_alignment(
                                Type.from_interned(payload_type).abi_alignment(zcu),
                            ),
                        },
                    };
                    return pool.from_fields(allocator, .@"struct", &fields, kind);
                },
                .anyframe_type => unreachable,
                .error_union_type => |error_union_info| {
                    const error_set_bits = zcu.error_set_bits();
                    const error_set_ctype = try pool.from_int_info(allocator, .{
                        .signedness = .unsigned,
                        .bits = error_set_bits,
                    }, mod, kind);
                    if (ip.is_no_return(error_union_info.payload_type)) return error_set_ctype;
                    const payload_type = Type.from_interned(error_union_info.payload_type);
                    const payload_ctype = try pool.from_type(
                        allocator,
                        scratch,
                        payload_type,
                        zcu,
                        mod,
                        kind.no_parameter(),
                    );
                    if (payload_ctype.index == .void) return error_set_ctype;
                    const target = &mod.resolved_target.result;
                    var fields = [_]Info.Field{
                        .{
                            .name = .{ .index = .@"error" },
                            .ctype = error_set_ctype,
                            .alignas = AlignAs.from_abi_alignment(
                                Type.int_abi_alignment(error_set_bits, target.*, false),
                            ),
                        },
                        .{
                            .name = .{ .index = .payload },
                            .ctype = payload_ctype,
                            .alignas = AlignAs.from_abi_alignment(payload_type.abi_alignment(zcu)),
                        },
                    };
                    return pool.from_fields(allocator, .@"struct", &fields, kind);
                },
                .simple_type => unreachable,
                .struct_type => {
                    const loaded_struct = ip.load_struct_type(ip_index);
                    switch (loaded_struct.layout) {
                        .auto, .@"extern" => {
                            const fwd_decl = try pool.get_fwd_decl(allocator, .{
                                .tag = .@"struct",
                                .name = .{ .owner_decl = loaded_struct.decl.unwrap().? },
                            });
                            if (kind.is_forward()) return if (ty.has_runtime_bits_ignore_comptime(zcu))
                                fwd_decl
                            else
                                CType.void;
                            const scratch_top = scratch.items.len;
                            defer scratch.shrink_retaining_capacity(scratch_top);
                            try scratch.ensure_unused_capacity(
                                allocator,
                                loaded_struct.field_types.len * @typeInfo(Field).Struct.fields.len,
                            );
                            var hasher = Hasher.init;
                            var tag: Pool.Tag = .aggregate_struct;
                            var field_it = loaded_struct.iterate_runtime_order(ip);
                            while (field_it.next()) |field_index| {
                                const field_type = Type.from_interned(
                                    loaded_struct.field_types.get(ip)[field_index],
                                );
                                const field_ctype = try pool.from_type(
                                    allocator,
                                    scratch,
                                    field_type,
                                    zcu,
                                    mod,
                                    kind.no_parameter(),
                                );
                                if (field_ctype.index == .void) continue;
                                const field_name = if (loaded_struct.field_name(ip, field_index)
                                    .unwrap()) |field_name|
                                    try pool.string(allocator, field_name.to_slice(ip))
                                else
                                    String.from_unnamed(@int_cast(field_index));
                                const field_alignas = AlignAs.from_alignment(.{
                                    .@"align" = loaded_struct.field_align(ip, field_index),
                                    .abi = field_type.abi_alignment(zcu),
                                });
                                pool.add_hashed_extra_assume_capacity_to(scratch, &hasher, Field, .{
                                    .name = field_name.index,
                                    .ctype = field_ctype.index,
                                    .flags = .{ .alignas = field_alignas },
                                });
                                if (field_alignas.abi_order().compare(.lt))
                                    tag = .aggregate_struct_packed;
                            }
                            const fields_len: u32 = @int_cast(@div_exact(
                                scratch.items.len - scratch_top,
                                @typeInfo(Field).Struct.fields.len,
                            ));
                            if (fields_len == 0) return CType.void;
                            try pool.ensure_unused_capacity(allocator, 1);
                            const extra_index = try pool.add_hashed_extra(allocator, &hasher, Aggregate, .{
                                .fwd_decl = fwd_decl.index,
                                .fields_len = fields_len,
                            }, fields_len * @typeInfo(Field).Struct.fields.len);
                            pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                            return pool.tag_trailing_extra_assume_capacity(hasher, tag, extra_index);
                        },
                        .@"packed" => return pool.from_type(
                            allocator,
                            scratch,
                            Type.from_interned(loaded_struct.backing_int_type(ip).*),
                            zcu,
                            mod,
                            kind,
                        ),
                    }
                },
                .anon_struct_type => |anon_struct_info| {
                    const scratch_top = scratch.items.len;
                    defer scratch.shrink_retaining_capacity(scratch_top);
                    try scratch.ensure_unused_capacity(allocator, anon_struct_info.types.len *
                        @typeInfo(Field).Struct.fields.len);
                    var hasher = Hasher.init;
                    for (0..anon_struct_info.types.len) |field_index| {
                        if (anon_struct_info.values.get(ip)[field_index] != .none) continue;
                        const field_type = Type.from_interned(
                            anon_struct_info.types.get(ip)[field_index],
                        );
                        const field_ctype = try pool.from_type(
                            allocator,
                            scratch,
                            field_type,
                            zcu,
                            mod,
                            kind.no_parameter(),
                        );
                        if (field_ctype.index == .void) continue;
                        const field_name = if (anon_struct_info.field_name(ip, @int_cast(field_index))
                            .unwrap()) |field_name|
                            try pool.string(allocator, field_name.to_slice(ip))
                        else
                            try pool.fmt(allocator, "f{d}", .{field_index});
                        pool.add_hashed_extra_assume_capacity_to(scratch, &hasher, Field, .{
                            .name = field_name.index,
                            .ctype = field_ctype.index,
                            .flags = .{ .alignas = AlignAs.from_abi_alignment(
                                field_type.abi_alignment(zcu),
                            ) },
                        });
                    }
                    const fields_len: u32 = @int_cast(@div_exact(
                        scratch.items.len - scratch_top,
                        @typeInfo(Field).Struct.fields.len,
                    ));
                    if (fields_len == 0) return CType.void;
                    if (kind.is_forward()) {
                        try pool.ensure_unused_capacity(allocator, 1);
                        const extra_index = try pool.add_hashed_extra(
                            allocator,
                            &hasher,
                            FwdDeclAnon,
                            .{ .fields_len = fields_len },
                            fields_len * @typeInfo(Field).Struct.fields.len,
                        );
                        pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                        return pool.tag_trailing_extra(
                            allocator,
                            hasher,
                            .fwd_decl_struct_anon,
                            extra_index,
                        );
                    }
                    const fwd_decl = try pool.from_type(allocator, scratch, ty, zcu, mod, .forward);
                    try pool.ensure_unused_capacity(allocator, 1);
                    const extra_index = try pool.add_hashed_extra(allocator, &hasher, Aggregate, .{
                        .fwd_decl = fwd_decl.index,
                        .fields_len = fields_len,
                    }, fields_len * @typeInfo(Field).Struct.fields.len);
                    pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                    return pool.tag_trailing_extra_assume_capacity(hasher, .aggregate_struct, extra_index);
                },
                .union_type => {
                    const loaded_union = ip.load_union_type(ip_index);
                    switch (loaded_union.get_layout(ip)) {
                        .auto, .@"extern" => {
                            const has_tag = loaded_union.has_tag(ip);
                            const fwd_decl = try pool.get_fwd_decl(allocator, .{
                                .tag = if (has_tag) .@"struct" else .@"union",
                                .name = .{ .owner_decl = loaded_union.decl },
                            });
                            if (kind.is_forward()) return if (ty.has_runtime_bits_ignore_comptime(zcu))
                                fwd_decl
                            else
                                CType.void;
                            const loaded_tag = loaded_union.load_tag_type(ip);
                            const scratch_top = scratch.items.len;
                            defer scratch.shrink_retaining_capacity(scratch_top);
                            try scratch.ensure_unused_capacity(
                                allocator,
                                loaded_union.field_types.len * @typeInfo(Field).Struct.fields.len,
                            );
                            var hasher = Hasher.init;
                            var tag: Pool.Tag = .aggregate_union;
                            var payload_align: Alignment = .@"1";
                            for (0..loaded_union.field_types.len) |field_index| {
                                const field_type = Type.from_interned(
                                    loaded_union.field_types.get(ip)[field_index],
                                );
                                if (ip.is_no_return(field_type.to_intern())) continue;
                                const field_ctype = try pool.from_type(
                                    allocator,
                                    scratch,
                                    field_type,
                                    zcu,
                                    mod,
                                    kind.no_parameter(),
                                );
                                if (field_ctype.index == .void) continue;
                                const field_name = try pool.string(
                                    allocator,
                                    loaded_tag.names.get(ip)[field_index].to_slice(ip),
                                );
                                const field_alignas = AlignAs.from_alignment(.{
                                    .@"align" = loaded_union.field_align(ip, field_index),
                                    .abi = field_type.abi_alignment(zcu),
                                });
                                pool.add_hashed_extra_assume_capacity_to(scratch, &hasher, Field, .{
                                    .name = field_name.index,
                                    .ctype = field_ctype.index,
                                    .flags = .{ .alignas = field_alignas },
                                });
                                if (field_alignas.abi_order().compare(.lt))
                                    tag = .aggregate_union_packed;
                                payload_align = payload_align.max_strict(field_alignas.@"align");
                            }
                            const fields_len: u32 = @int_cast(@div_exact(
                                scratch.items.len - scratch_top,
                                @typeInfo(Field).Struct.fields.len,
                            ));
                            if (!has_tag) {
                                if (fields_len == 0) return CType.void;
                                try pool.ensure_unused_capacity(allocator, 1);
                                const extra_index = try pool.add_hashed_extra(
                                    allocator,
                                    &hasher,
                                    Aggregate,
                                    .{ .fwd_decl = fwd_decl.index, .fields_len = fields_len },
                                    fields_len * @typeInfo(Field).Struct.fields.len,
                                );
                                pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                                return pool.tag_trailing_extra_assume_capacity(hasher, tag, extra_index);
                            }
                            try pool.ensure_unused_capacity(allocator, 2);
                            var struct_fields: [2]Info.Field = undefined;
                            var struct_fields_len: usize = 0;
                            if (loaded_tag.tag_ty != .comptime_int_type) {
                                const tag_type = Type.from_interned(loaded_tag.tag_ty);
                                const tag_ctype: CType = try pool.from_type(
                                    allocator,
                                    scratch,
                                    tag_type,
                                    zcu,
                                    mod,
                                    kind.no_parameter(),
                                );
                                if (tag_ctype.index != .void) {
                                    struct_fields[struct_fields_len] = .{
                                        .name = .{ .index = .tag },
                                        .ctype = tag_ctype,
                                        .alignas = AlignAs.from_abi_alignment(tag_type.abi_alignment(zcu)),
                                    };
                                    struct_fields_len += 1;
                                }
                            }
                            if (fields_len > 0) {
                                const payload_ctype = payload_ctype: {
                                    const extra_index = try pool.add_hashed_extra(
                                        allocator,
                                        &hasher,
                                        AggregateAnon,
                                        .{
                                            .owner_decl = loaded_union.decl,
                                            .id = 0,
                                            .fields_len = fields_len,
                                        },
                                        fields_len * @typeInfo(Field).Struct.fields.len,
                                    );
                                    pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                                    break :payload_ctype pool.tag_trailing_extra_assume_capacity(
                                        hasher,
                                        switch (tag) {
                                            .aggregate_union => .aggregate_union_anon,
                                            .aggregate_union_packed => .aggregate_union_packed_anon,
                                            else => unreachable,
                                        },
                                        extra_index,
                                    );
                                };
                                if (payload_ctype.index != .void) {
                                    struct_fields[struct_fields_len] = .{
                                        .name = .{ .index = .payload },
                                        .ctype = payload_ctype,
                                        .alignas = AlignAs.from_abi_alignment(payload_align),
                                    };
                                    struct_fields_len += 1;
                                }
                            }
                            if (struct_fields_len == 0) return CType.void;
                            sort_fields(struct_fields[0..struct_fields_len]);
                            return pool.get_aggregate(allocator, .{
                                .tag = .@"struct",
                                .name = .{ .fwd_decl = fwd_decl },
                                .fields = struct_fields[0..struct_fields_len],
                            });
                        },
                        .@"packed" => return pool.from_int_info(allocator, .{
                            .signedness = .unsigned,
                            .bits = @int_cast(ty.bit_size(zcu)),
                        }, mod, kind),
                    }
                },
                .opaque_type => return CType.void,
                .enum_type => return pool.from_type(
                    allocator,
                    scratch,
                    Type.from_interned(ip.load_enum_type(ip_index).tag_ty),
                    zcu,
                    mod,
                    kind,
                ),
                .func_type => |func_info| if (func_info.is_generic) return CType.void else {
                    const scratch_top = scratch.items.len;
                    defer scratch.shrink_retaining_capacity(scratch_top);
                    try scratch.ensure_unused_capacity(allocator, func_info.param_types.len);
                    var hasher = Hasher.init;
                    const return_type = Type.from_interned(func_info.return_type);
                    const return_ctype: CType =
                        if (!ip.is_no_return(func_info.return_type)) try pool.from_type(
                        allocator,
                        scratch,
                        return_type,
                        zcu,
                        mod,
                        kind.as_parameter(),
                    ) else CType.void;
                    for (0..func_info.param_types.len) |param_index| {
                        const param_type = Type.from_interned(
                            func_info.param_types.get(ip)[param_index],
                        );
                        const param_ctype = try pool.from_type(
                            allocator,
                            scratch,
                            param_type,
                            zcu,
                            mod,
                            kind.as_parameter(),
                        );
                        if (param_ctype.index == .void) continue;
                        hasher.update(param_ctype.hash(pool));
                        scratch.append_assume_capacity(@int_from_enum(param_ctype.index));
                    }
                    const param_ctypes_len: u32 = @int_cast(scratch.items.len - scratch_top);
                    try pool.ensure_unused_capacity(allocator, 1);
                    const extra_index = try pool.add_hashed_extra(allocator, &hasher, Function, .{
                        .return_ctype = return_ctype.index,
                        .param_ctypes_len = param_ctypes_len,
                    }, param_ctypes_len);
                    pool.extra.append_slice_assume_capacity(scratch.items[scratch_top..]);
                    return pool.tag_trailing_extra_assume_capacity(hasher, switch (func_info.is_var_args) {
                        false => .function,
                        true => .function_varargs,
                    }, extra_index);
                },
                .error_set_type,
                .inferred_error_set_type,
                => return pool.from_int_info(allocator, .{
                    .signedness = .unsigned,
                    .bits = zcu.error_set_bits(),
                }, mod, kind),

                .undef,
                .simple_value,
                .variable,
                .extern_func,
                .func,
                .int,
                .err,
                .error_union,
                .enum_literal,
                .enum_tag,
                .empty_enum_value,
                .float,
                .ptr,
                .slice,
                .opt,
                .aggregate,
                .un,
                .memoized_call,
                => unreachable,
            },
        }
    }

    pub fn get_or_put_adapted(
        pool: *Pool,
        allocator: std.mem.Allocator,
        source_pool: *const Pool,
        source_ctype: CType,
        pool_adapter: anytype,
    ) !struct { CType, bool } {
        const tag = source_pool.items.items(.tag)[
            source_ctype.to_pool_index() orelse return .{ source_ctype, true }
        ];
        try pool.ensure_unused_capacity(allocator, 1);
        const CTypeAdapter = struct {
            pool: *const Pool,
            source_pool: *const Pool,
            source_info: Info,
            pool_adapter: @TypeOf(pool_adapter),
            pub fn hash(map_adapter: @This(), key_ctype: CType) Map.Hash {
                return key_ctype.hash(map_adapter.source_pool);
            }
            pub fn eql(map_adapter: @This(), _: CType, _: void, pool_index: usize) bool {
                return map_adapter.source_info.eql_adapted(
                    map_adapter.source_pool,
                    CType.from_pool_index(pool_index),
                    map_adapter.pool,
                    map_adapter.pool_adapter,
                );
            }
        };
        const source_info = source_ctype.info(source_pool);
        const gop = pool.map.get_or_put_assume_capacity_adapted(source_ctype, CTypeAdapter{
            .pool = pool,
            .source_pool = source_pool,
            .source_info = source_info,
            .pool_adapter = pool_adapter,
        });
        errdefer _ = pool.map.pop();
        const ctype = CType.from_pool_index(gop.index);
        if (!gop.found_existing) switch (source_info) {
            .basic => unreachable,
            .pointer => |pointer_info| pool.items.append_assume_capacity(.{
                .tag = tag,
                .data = @int_from_enum(pool_adapter.copy(pointer_info.elem_ctype).index),
            }),
            .aligned => |aligned_info| pool.items.append_assume_capacity(.{
                .tag = tag,
                .data = try pool.add_extra(allocator, Aligned, .{
                    .ctype = pool_adapter.copy(aligned_info.ctype).index,
                    .flags = .{ .alignas = aligned_info.alignas },
                }, 0),
            }),
            .array, .vector => |sequence_info| pool.items.append_assume_capacity(.{
                .tag = tag,
                .data = switch (tag) {
                    .array_small, .vector => try pool.add_extra(allocator, SequenceSmall, .{
                        .elem_ctype = pool_adapter.copy(sequence_info.elem_ctype).index,
                        .len = @int_cast(sequence_info.len),
                    }, 0),
                    .array_large => try pool.add_extra(allocator, SequenceLarge, .{
                        .elem_ctype = pool_adapter.copy(sequence_info.elem_ctype).index,
                        .len_lo = @truncate(sequence_info.len >> 0),
                        .len_hi = @truncate(sequence_info.len >> 32),
                    }, 0),
                    else => unreachable,
                },
            }),
            .fwd_decl => |fwd_decl_info| switch (fwd_decl_info.name) {
                .anon => |fields| {
                    pool.items.append_assume_capacity(.{
                        .tag = tag,
                        .data = try pool.add_extra(allocator, FwdDeclAnon, .{
                            .fields_len = fields.len,
                        }, fields.len * @typeInfo(Field).Struct.fields.len),
                    });
                    for (0..fields.len) |field_index| {
                        const field = fields.at(field_index, source_pool);
                        const field_name = if (field.name.to_pool_slice(source_pool)) |slice|
                            try pool.string(allocator, slice)
                        else
                            field.name;
                        pool.add_extra_assume_capacity(Field, .{
                            .name = field_name.index,
                            .ctype = pool_adapter.copy(field.ctype).index,
                            .flags = .{ .alignas = field.alignas },
                        });
                    }
                },
                .owner_decl => |owner_decl| pool.items.append_assume_capacity(.{
                    .tag = tag,
                    .data = @int_from_enum(owner_decl),
                }),
            },
            .aggregate => |aggregate_info| {
                pool.items.append_assume_capacity(.{
                    .tag = tag,
                    .data = switch (aggregate_info.name) {
                        .anon => |anon| try pool.add_extra(allocator, AggregateAnon, .{
                            .owner_decl = anon.owner_decl,
                            .id = anon.id,
                            .fields_len = aggregate_info.fields.len,
                        }, aggregate_info.fields.len * @typeInfo(Field).Struct.fields.len),
                        .fwd_decl => |fwd_decl| try pool.add_extra(allocator, Aggregate, .{
                            .fwd_decl = pool_adapter.copy(fwd_decl).index,
                            .fields_len = aggregate_info.fields.len,
                        }, aggregate_info.fields.len * @typeInfo(Field).Struct.fields.len),
                    },
                });
                for (0..aggregate_info.fields.len) |field_index| {
                    const field = aggregate_info.fields.at(field_index, source_pool);
                    const field_name = if (field.name.to_pool_slice(source_pool)) |slice|
                        try pool.string(allocator, slice)
                    else
                        field.name;
                    pool.add_extra_assume_capacity(Field, .{
                        .name = field_name.index,
                        .ctype = pool_adapter.copy(field.ctype).index,
                        .flags = .{ .alignas = field.alignas },
                    });
                }
            },
            .function => |function_info| {
                pool.items.append_assume_capacity(.{
                    .tag = tag,
                    .data = try pool.add_extra(allocator, Function, .{
                        .return_ctype = pool_adapter.copy(function_info.return_ctype).index,
                        .param_ctypes_len = function_info.param_ctypes.len,
                    }, function_info.param_ctypes.len),
                });
                for (0..function_info.param_ctypes.len) |param_index| pool.extra.append_assume_capacity(
                    @int_from_enum(pool_adapter.copy(
                        function_info.param_ctypes.at(param_index, source_pool),
                    ).index),
                );
            },
        };
        assert(source_info.eql_adapted(source_pool, ctype, pool, pool_adapter));
        assert(source_ctype.hash(source_pool) == ctype.hash(pool));
        return .{ ctype, gop.found_existing };
    }

    pub fn string(pool: *Pool, allocator: std.mem.Allocator, slice: []const u8) !String {
        try pool.string_bytes.append_slice(allocator, slice);
        return pool.trailing_string(allocator);
    }

    pub fn fmt(
        pool: *Pool,
        allocator: std.mem.Allocator,
        comptime fmt_str: []const u8,
        fmt_args: anytype,
    ) !String {
        try pool.string_bytes.writer(allocator).print(fmt_str, fmt_args);
        return pool.trailing_string(allocator);
    }

    fn ensure_unused_capacity(pool: *Pool, allocator: std.mem.Allocator, len: u32) !void {
        try pool.map.ensure_unused_capacity(allocator, len);
        try pool.items.ensure_unused_capacity(allocator, len);
    }

    const Hasher = struct {
        const Impl = std.hash.Wyhash;
        impl: Impl,

        const init: Hasher = .{ .impl = Impl.init(0) };

        fn update_extra(hasher: *Hasher, comptime Extra: type, extra: Extra, pool: *const Pool) void {
            inline for (@typeInfo(Extra).Struct.fields) |field| {
                const value = @field(extra, field.name);
                switch (field.type) {
                    Pool.Tag, String, CType => unreachable,
                    CType.Index => hasher.update((CType{ .index = value }).hash(pool)),
                    String.Index => if ((String{ .index = value }).to_pool_slice(pool)) |slice|
                        hasher.update(slice)
                    else
                        hasher.update(@int_from_enum(value)),
                    else => hasher.update(value),
                }
            }
        }
        fn update(hasher: *Hasher, data: anytype) void {
            switch (@TypeOf(data)) {
                Pool.Tag => @compile_error("pass tag to final"),
                CType, CType.Index => @compile_error("hash ctype.hash(pool) instead"),
                String, String.Index => @compile_error("hash string.slice(pool) instead"),
                u32, DeclIndex, Aligned.Flags => hasher.impl.update(std.mem.as_bytes(&data)),
                []const u8 => hasher.impl.update(data),
                else => @compile_error("unhandled type: " ++ @type_name(@TypeOf(data))),
            }
        }

        fn final(hasher: Hasher, tag: Pool.Tag) Map.Hash {
            var impl = hasher.impl;
            impl.update(std.mem.as_bytes(&tag));
            return @truncate(impl.final());
        }
    };

    fn tag_data(
        pool: *Pool,
        allocator: std.mem.Allocator,
        hasher: Hasher,
        tag: Pool.Tag,
        data: u32,
    ) !CType {
        try pool.ensure_unused_capacity(allocator, 1);
        const Key = struct { hash: Map.Hash, tag: Pool.Tag, data: u32 };
        const CTypeAdapter = struct {
            pool: *const Pool,
            pub fn hash(_: @This(), key: Key) Map.Hash {
                return key.hash;
            }
            pub fn eql(ctype_adapter: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
                const rhs_item = ctype_adapter.pool.items.get(rhs_index);
                return lhs_key.tag == rhs_item.tag and lhs_key.data == rhs_item.data;
            }
        };
        const gop = pool.map.get_or_put_assume_capacity_adapted(
            Key{ .hash = hasher.final(tag), .tag = tag, .data = data },
            CTypeAdapter{ .pool = pool },
        );
        if (!gop.found_existing) pool.items.append_assume_capacity(.{ .tag = tag, .data = data });
        return CType.from_pool_index(gop.index);
    }

    fn tag_extra(
        pool: *Pool,
        allocator: std.mem.Allocator,
        tag: Pool.Tag,
        comptime Extra: type,
        extra: Extra,
    ) !CType {
        var hasher = Hasher.init;
        hasher.update_extra(Extra, extra, pool);
        return pool.tag_trailing_extra(
            allocator,
            hasher,
            tag,
            try pool.add_extra(allocator, Extra, extra, 0),
        );
    }

    fn tag_trailing_extra(
        pool: *Pool,
        allocator: std.mem.Allocator,
        hasher: Hasher,
        tag: Pool.Tag,
        extra_index: ExtraIndex,
    ) !CType {
        try pool.ensure_unused_capacity(allocator, 1);
        return pool.tag_trailing_extra_assume_capacity(hasher, tag, extra_index);
    }

    fn tag_trailing_extra_assume_capacity(
        pool: *Pool,
        hasher: Hasher,
        tag: Pool.Tag,
        extra_index: ExtraIndex,
    ) CType {
        const Key = struct { hash: Map.Hash, tag: Pool.Tag, extra: []const u32 };
        const CTypeAdapter = struct {
            pool: *const Pool,
            pub fn hash(_: @This(), key: Key) Map.Hash {
                return key.hash;
            }
            pub fn eql(ctype_adapter: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
                const rhs_item = ctype_adapter.pool.items.get(rhs_index);
                if (lhs_key.tag != rhs_item.tag) return false;
                const rhs_extra = ctype_adapter.pool.extra.items[rhs_item.data..];
                return std.mem.starts_with(u32, rhs_extra, lhs_key.extra);
            }
        };
        const gop = pool.map.get_or_put_assume_capacity_adapted(
            Key{ .hash = hasher.final(tag), .tag = tag, .extra = pool.extra.items[extra_index..] },
            CTypeAdapter{ .pool = pool },
        );
        if (gop.found_existing)
            pool.extra.shrink_retaining_capacity(extra_index)
        else
            pool.items.append_assume_capacity(.{ .tag = tag, .data = extra_index });
        return CType.from_pool_index(gop.index);
    }

    fn sort_fields(fields: []Info.Field) void {
        std.mem.sort(Info.Field, fields, {}, struct {
            fn before(_: void, lhs_field: Info.Field, rhs_field: Info.Field) bool {
                return lhs_field.alignas.order(rhs_field.alignas).compare(.gt);
            }
        }.before);
    }

    fn trailing_string(pool: *Pool, allocator: std.mem.Allocator) !String {
        const start = pool.string_indices.get_last();
        const slice: []const u8 = pool.string_bytes.items[start..];
        if (slice.len >= 2 and slice[0] == 'f' and switch (slice[1]) {
            '0' => slice.len == 2,
            '1'...'9' => true,
            else => false,
        }) if (std.fmt.parse_int(u31, slice[1..], 10)) |unnamed| {
            pool.string_bytes.shrink_retaining_capacity(start);
            return String.from_unnamed(unnamed);
        } else |_| {};
        if (std.meta.string_to_enum(String.Index, slice)) |index| {
            pool.string_bytes.shrink_retaining_capacity(start);
            return .{ .index = index };
        }

        try pool.string_map.ensure_unused_capacity(allocator, 1);
        try pool.string_indices.ensure_unused_capacity(allocator, 1);

        const gop = pool.string_map.get_or_put_assume_capacity_adapted(slice, String.Adapter{ .pool = pool });
        if (gop.found_existing)
            pool.string_bytes.shrink_retaining_capacity(start)
        else
            pool.string_indices.append_assume_capacity(@int_cast(pool.string_bytes.items.len));
        return String.from_pool_index(gop.index);
    }

    const Item = struct {
        tag: Pool.Tag,
        data: u32,
    };

    const ExtraIndex = u32;

    const Tag = enum(u8) {
        basic,
        pointer,
        pointer_const,
        pointer_volatile,
        pointer_const_volatile,
        aligned,
        array_small,
        array_large,
        vector,
        fwd_decl_struct_anon,
        fwd_decl_union_anon,
        fwd_decl_struct,
        fwd_decl_union,
        aggregate_struct_anon,
        aggregate_struct_packed_anon,
        aggregate_union_anon,
        aggregate_union_packed_anon,
        aggregate_struct,
        aggregate_struct_packed,
        aggregate_union,
        aggregate_union_packed,
        function,
        function_varargs,
    };

    const Aligned = struct {
        ctype: CType.Index,
        flags: Flags,

        const Flags = packed struct(u32) {
            alignas: AlignAs,
            _: u20 = 0,
        };
    };

    const SequenceSmall = struct {
        elem_ctype: CType.Index,
        len: u32,
    };

    const SequenceLarge = struct {
        elem_ctype: CType.Index,
        len_lo: u32,
        len_hi: u32,

        fn len(extra: SequenceLarge) u64 {
            return @as(u64, extra.len_lo) << 0 |
                @as(u64, extra.len_hi) << 32;
        }
    };

    const Field = struct {
        name: String.Index,
        ctype: CType.Index,
        flags: Flags,

        const Flags = Aligned.Flags;
    };

    const FwdDeclAnon = struct {
        fields_len: u32,
    };

    const AggregateAnon = struct {
        owner_decl: DeclIndex,
        id: u32,
        fields_len: u32,
    };

    const Aggregate = struct {
        fwd_decl: CType.Index,
        fields_len: u32,
    };

    const Function = struct {
        return_ctype: CType.Index,
        param_ctypes_len: u32,
    };

    fn add_extra(
        pool: *Pool,
        allocator: std.mem.Allocator,
        comptime Extra: type,
        extra: Extra,
        trailing_len: usize,
    ) !ExtraIndex {
        try pool.extra.ensure_unused_capacity(
            allocator,
            @typeInfo(Extra).Struct.fields.len + trailing_len,
        );
        defer pool.add_extra_assume_capacity(Extra, extra);
        return @int_cast(pool.extra.items.len);
    }
    fn add_extra_assume_capacity(pool: *Pool, comptime Extra: type, extra: Extra) void {
        add_extra_assume_capacity_to(&pool.extra, Extra, extra);
    }
    fn add_extra_assume_capacity_to(
        array: *std.ArrayListUnmanaged(u32),
        comptime Extra: type,
        extra: Extra,
    ) void {
        inline for (@typeInfo(Extra).Struct.fields) |field| {
            const value = @field(extra, field.name);
            array.append_assume_capacity(switch (field.type) {
                u32 => value,
                CType.Index, String.Index, DeclIndex => @int_from_enum(value),
                Aligned.Flags => @bit_cast(value),
                else => @compile_error("bad field type: " ++ field.name ++ ": " ++
                    @type_name(field.type)),
            });
        }
    }

    fn add_hashed_extra(
        pool: *Pool,
        allocator: std.mem.Allocator,
        hasher: *Hasher,
        comptime Extra: type,
        extra: Extra,
        trailing_len: usize,
    ) !ExtraIndex {
        hasher.update_extra(Extra, extra, pool);
        return pool.add_extra(allocator, Extra, extra, trailing_len);
    }
    fn add_hashed_extra_assume_capacity(
        pool: *Pool,
        hasher: *Hasher,
        comptime Extra: type,
        extra: Extra,
    ) void {
        hasher.update_extra(Extra, extra, pool);
        pool.add_extra_assume_capacity(Extra, extra);
    }
    fn add_hashed_extra_assume_capacity_to(
        pool: *Pool,
        array: *std.ArrayListUnmanaged(u32),
        hasher: *Hasher,
        comptime Extra: type,
        extra: Extra,
    ) void {
        hasher.update_extra(Extra, extra, pool);
        add_extra_assume_capacity_to(array, Extra, extra);
    }

    const ExtraTrail = struct {
        extra_index: ExtraIndex,

        fn next(
            extra_trail: *ExtraTrail,
            len: u32,
            comptime Extra: type,
            pool: *const Pool,
        ) []const Extra {
            defer extra_trail.extra_index += @int_cast(len);
            return @ptr_cast(pool.extra.items[extra_trail.extra_index..][0..len]);
        }
    };

    fn get_extra_trail(
        pool: *const Pool,
        comptime Extra: type,
        extra_index: ExtraIndex,
    ) struct { extra: Extra, trail: ExtraTrail } {
        var extra: Extra = undefined;
        const fields = @typeInfo(Extra).Struct.fields;
        inline for (fields, pool.extra.items[extra_index..][0..fields.len]) |field, value|
            @field(extra, field.name) = switch (field.type) {
                u32 => value,
                CType.Index, String.Index, DeclIndex => @enumFromInt(value),
                Aligned.Flags => @bit_cast(value),
                else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
            };
        return .{
            .extra = extra,
            .trail = .{ .extra_index = extra_index + @as(ExtraIndex, @int_cast(fields.len)) },
        };
    }

    fn get_extra(pool: *const Pool, comptime Extra: type, extra_index: ExtraIndex) Extra {
        return pool.get_extra_trail(Extra, extra_index).extra;
    }
};

pub const AlignAs = packed struct {
    @"align": Alignment,
    abi: Alignment,

    pub fn from_alignment(alignas: AlignAs) AlignAs {
        assert(alignas.abi != .none);
        return .{
            .@"align" = if (alignas.@"align" != .none) alignas.@"align" else alignas.abi,
            .abi = alignas.abi,
        };
    }
    pub fn from_abi_alignment(abi: Alignment) AlignAs {
        assert(abi != .none);
        return .{ .@"align" = abi, .abi = abi };
    }
    pub fn from_byte_units(@"align": u64, abi: u64) AlignAs {
        return from_alignment(.{
            .@"align" = Alignment.from_byte_units(@"align"),
            .abi = Alignment.from_nonzero_byte_units(abi),
        });
    }

    pub fn order(lhs: AlignAs, rhs: AlignAs) std.math.Order {
        return lhs.@"align".order(rhs.@"align");
    }
    pub fn abi_order(alignas: AlignAs) std.math.Order {
        return alignas.@"align".order(alignas.abi);
    }
    pub fn to_byte_units(alignas: AlignAs) u64 {
        return alignas.@"align".to_byte_units().?;
    }
};

const Alignment = @import("../../InternPool.zig").Alignment;
const assert = std.debug.assert;
const CType = @This();
const DeclIndex = std.zig.DeclIndex;
const Module = @import("../../Package/Module.zig");
const std = @import("std");
const Type = @import("../../type.zig").Type;
const Zcu = @import("../../Module.zig");
