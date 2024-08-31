const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const BigIntConst = std.math.big.int.Const;
const BigIntMutable = std.math.big.int.Mutable;
const Hash = std.hash.Wyhash;
const Limb = std.math.big.Limb;

const Interner = @This();

map: std.AutoArrayHashMapUnmanaged(void, void) = .{},
items: std.MultiArrayList(struct {
    tag: Tag,
    data: u32,
}) = .{},
extra: std.ArrayListUnmanaged(u32) = .{},
limbs: std.ArrayListUnmanaged(Limb) = .{},
strings: std.ArrayListUnmanaged(u8) = .{},

const KeyAdapter = struct {
    interner: *const Interner,

    pub fn eql(adapter: KeyAdapter, a: Key, b_void: void, b_map_index: usize) bool {
        _ = b_void;
        return adapter.interner.get(@as(Ref, @enumFromInt(b_map_index))).eql(a);
    }

    pub fn hash(adapter: KeyAdapter, a: Key) u32 {
        _ = adapter;
        return a.hash();
    }
};

pub const Key = union(enum) {
    int_ty: u16,
    float_ty: u16,
    ptr_ty,
    noreturn_ty,
    void_ty,
    func_ty,
    array_ty: struct {
        len: u64,
        child: Ref,
    },
    vector_ty: struct {
        len: u32,
        child: Ref,
    },
    record_ty: []const Ref,
    /// May not be zero
    null,
    int: union(enum) {
        u64: u64,
        i64: i64,
        big_int: BigIntConst,

        pub fn to_big_int(repr: @This(), space: *Tag.Int.BigIntSpace) BigIntConst {
            return switch (repr) {
                .big_int => |x| x,
                inline .u64, .i64 => |x| BigIntMutable.init(&space.limbs, x).to_const(),
            };
        }
    },
    float: Float,
    bytes: []const u8,

    pub const Float = union(enum) {
        f16: f16,
        f32: f32,
        f64: f64,
        f80: f80,
        f128: f128,
    };

    pub fn hash(key: Key) u32 {
        var hasher = Hash.init(0);
        const tag = std.meta.active_tag(key);
        std.hash.auto_hash(&hasher, tag);
        switch (key) {
            .bytes => |bytes| {
                hasher.update(bytes);
            },
            .record_ty => |elems| for (elems) |elem| {
                std.hash.auto_hash(&hasher, elem);
            },
            .float => |repr| switch (repr) {
                inline else => |data| std.hash.auto_hash(
                    &hasher,
                    @as(std.meta.Int(.unsigned, @bitSizeOf(@TypeOf(data))), @bit_cast(data)),
                ),
            },
            .int => |repr| {
                var space: Tag.Int.BigIntSpace = undefined;
                const big = repr.to_big_int(&space);
                std.hash.auto_hash(&hasher, big.positive);
                for (big.limbs) |limb| std.hash.auto_hash(&hasher, limb);
            },
            inline else => |info| {
                std.hash.auto_hash(&hasher, info);
            },
        }
        return @truncate(hasher.final());
    }

    pub fn eql(a: Key, b: Key) bool {
        const KeyTag = std.meta.Tag(Key);
        const a_tag: KeyTag = a;
        const b_tag: KeyTag = b;
        if (a_tag != b_tag) return false;
        switch (a) {
            .record_ty => |a_elems| {
                const b_elems = b.record_ty;
                if (a_elems.len != b_elems.len) return false;
                for (a_elems, b_elems) |a_elem, b_elem| {
                    if (a_elem != b_elem) return false;
                }
                return true;
            },
            .bytes => |a_bytes| {
                const b_bytes = b.bytes;
                return std.mem.eql(u8, a_bytes, b_bytes);
            },
            .int => |a_repr| {
                var a_space: Tag.Int.BigIntSpace = undefined;
                const a_big = a_repr.to_big_int(&a_space);
                var b_space: Tag.Int.BigIntSpace = undefined;
                const b_big = b.int.to_big_int(&b_space);

                return a_big.eql(b_big);
            },
            inline else => |a_info, tag| {
                const b_info = @field(b, @tag_name(tag));
                return std.meta.eql(a_info, b_info);
            },
        }
    }

    fn to_ref(key: Key) ?Ref {
        switch (key) {
            .int_ty => |bits| switch (bits) {
                1 => return .i1,
                8 => return .i8,
                16 => return .i16,
                32 => return .i32,
                64 => return .i64,
                128 => return .i128,
                else => {},
            },
            .float_ty => |bits| switch (bits) {
                16 => return .f16,
                32 => return .f32,
                64 => return .f64,
                80 => return .f80,
                128 => return .f128,
                else => unreachable,
            },
            .ptr_ty => return .ptr,
            .func_ty => return .func,
            .noreturn_ty => return .noreturn,
            .void_ty => return .void,
            .int => |repr| {
                var space: Tag.Int.BigIntSpace = undefined;
                const big = repr.to_big_int(&space);
                if (big.eql_zero()) return .zero;
                const big_one = BigIntConst{ .limbs = &.{1}, .positive = true };
                if (big.eql(big_one)) return .one;
            },
            .float => |repr| switch (repr) {
                inline else => |data| {
                    if (std.math.is_positive_zero(data)) return .zero;
                    if (data == 1) return .one;
                },
            },
            .null => return .null,
            else => {},
        }
        return null;
    }
};

pub const Ref = enum(u32) {
    const max = std.math.max_int(u32);

    ptr = max - 1,
    noreturn = max - 2,
    void = max - 3,
    i1 = max - 4,
    i8 = max - 5,
    i16 = max - 6,
    i32 = max - 7,
    i64 = max - 8,
    i128 = max - 9,
    f16 = max - 10,
    f32 = max - 11,
    f64 = max - 12,
    f80 = max - 13,
    f128 = max - 14,
    func = max - 15,
    zero = max - 16,
    one = max - 17,
    null = max - 18,
    _,
};

pub const OptRef = enum(u32) {
    const max = std.math.max_int(u32);

    none = max - 0,
    ptr = max - 1,
    noreturn = max - 2,
    void = max - 3,
    i1 = max - 4,
    i8 = max - 5,
    i16 = max - 6,
    i32 = max - 7,
    i64 = max - 8,
    i128 = max - 9,
    f16 = max - 10,
    f32 = max - 11,
    f64 = max - 12,
    f80 = max - 13,
    f128 = max - 14,
    func = max - 15,
    zero = max - 16,
    one = max - 17,
    null = max - 18,
    _,
};

pub const Tag = enum(u8) {
    /// `data` is `u16`
    int_ty,
    /// `data` is `u16`
    float_ty,
    /// `data` is index to `Array`
    array_ty,
    /// `data` is index to `Vector`
    vector_ty,
    /// `data` is `u32`
    u32,
    /// `data` is `i32`
    i32,
    /// `data` is `Int`
    int_positive,
    /// `data` is `Int`
    int_negative,
    /// `data` is `f16`
    f16,
    /// `data` is `f32`
    f32,
    /// `data` is `F64`
    f64,
    /// `data` is `F80`
    f80,
    /// `data` is `F128`
    f128,
    /// `data` is `Bytes`
    bytes,
    /// `data` is `Record`
    record_ty,

    pub const Array = struct {
        len0: u32,
        len1: u32,
        child: Ref,

        pub fn get_len(a: Array) u64 {
            return (PackedU64{
                .a = a.len0,
                .b = a.len1,
            }).get();
        }
    };

    pub const Vector = struct {
        len: u32,
        child: Ref,
    };

    pub const Int = struct {
        limbs_index: u32,
        limbs_len: u32,

        /// Big enough to fit any non-BigInt value
        pub const BigIntSpace = struct {
            /// The +1 is headroom so that operations such as incrementing once
            /// or decrementing once are possible without using an allocator.
            limbs: [(@size_of(u64) / @size_of(std.math.big.Limb)) + 1]std.math.big.Limb,
        };
    };

    pub const F64 = struct {
        piece0: u32,
        piece1: u32,

        pub fn get(self: F64) f64 {
            const int_bits = @as(u64, self.piece0) | (@as(u64, self.piece1) << 32);
            return @bit_cast(int_bits);
        }

        fn pack(val: f64) F64 {
            const bits = @as(u64, @bit_cast(val));
            return .{
                .piece0 = @as(u32, @truncate(bits)),
                .piece1 = @as(u32, @truncate(bits >> 32)),
            };
        }
    };

    pub const F80 = struct {
        piece0: u32,
        piece1: u32,
        piece2: u32, // u16 part, top bits

        pub fn get(self: F80) f80 {
            const int_bits = @as(u80, self.piece0) |
                (@as(u80, self.piece1) << 32) |
                (@as(u80, self.piece2) << 64);
            return @bit_cast(int_bits);
        }

        fn pack(val: f80) F80 {
            const bits = @as(u80, @bit_cast(val));
            return .{
                .piece0 = @as(u32, @truncate(bits)),
                .piece1 = @as(u32, @truncate(bits >> 32)),
                .piece2 = @as(u16, @truncate(bits >> 64)),
            };
        }
    };

    pub const F128 = struct {
        piece0: u32,
        piece1: u32,
        piece2: u32,
        piece3: u32,

        pub fn get(self: F128) f128 {
            const int_bits = @as(u128, self.piece0) |
                (@as(u128, self.piece1) << 32) |
                (@as(u128, self.piece2) << 64) |
                (@as(u128, self.piece3) << 96);
            return @bit_cast(int_bits);
        }

        fn pack(val: f128) F128 {
            const bits = @as(u128, @bit_cast(val));
            return .{
                .piece0 = @as(u32, @truncate(bits)),
                .piece1 = @as(u32, @truncate(bits >> 32)),
                .piece2 = @as(u32, @truncate(bits >> 64)),
                .piece3 = @as(u32, @truncate(bits >> 96)),
            };
        }
    };

    pub const Bytes = struct {
        strings_index: u32,
        len: u32,
    };

    pub const Record = struct {
        elements_len: u32,
        // trailing
        // [elements_len]Ref
    };
};

pub const PackedU64 = packed struct(u64) {
    a: u32,
    b: u32,

    pub fn get(x: PackedU64) u64 {
        return @bit_cast(x);
    }

    pub fn init(x: u64) PackedU64 {
        return @bit_cast(x);
    }
};

pub fn deinit(i: *Interner, gpa: Allocator) void {
    i.map.deinit(gpa);
    i.items.deinit(gpa);
    i.extra.deinit(gpa);
    i.limbs.deinit(gpa);
    i.strings.deinit(gpa);
}

pub fn put(i: *Interner, gpa: Allocator, key: Key) !Ref {
    if (key.to_ref()) |some| return some;
    const adapter: KeyAdapter = .{ .interner = i };
    const gop = try i.map.get_or_put_adapted(gpa, key, adapter);
    if (gop.found_existing) return @enumFromInt(gop.index);
    try i.items.ensure_unused_capacity(gpa, 1);

    switch (key) {
        .int_ty => |bits| {
            i.items.append_assume_capacity(.{
                .tag = .int_ty,
                .data = bits,
            });
        },
        .float_ty => |bits| {
            i.items.append_assume_capacity(.{
                .tag = .float_ty,
                .data = bits,
            });
        },
        .array_ty => |info| {
            const split_len = PackedU64.init(info.len);
            i.items.append_assume_capacity(.{
                .tag = .array_ty,
                .data = try i.add_extra(gpa, Tag.Array{
                    .len0 = split_len.a,
                    .len1 = split_len.b,
                    .child = info.child,
                }),
            });
        },
        .vector_ty => |info| {
            i.items.append_assume_capacity(.{
                .tag = .vector_ty,
                .data = try i.add_extra(gpa, Tag.Vector{
                    .len = info.len,
                    .child = info.child,
                }),
            });
        },
        .int => |repr| int: {
            var space: Tag.Int.BigIntSpace = undefined;
            const big = repr.to_big_int(&space);
            switch (repr) {
                .u64 => |data| if (std.math.cast(u32, data)) |small| {
                    i.items.append_assume_capacity(.{
                        .tag = .u32,
                        .data = small,
                    });
                    break :int;
                },
                .i64 => |data| if (std.math.cast(i32, data)) |small| {
                    i.items.append_assume_capacity(.{
                        .tag = .i32,
                        .data = @bit_cast(small),
                    });
                    break :int;
                },
                .big_int => |data| {
                    if (data.fits_in_twos_comp(.unsigned, 32)) {
                        i.items.append_assume_capacity(.{
                            .tag = .u32,
                            .data = data.to(u32) catch unreachable,
                        });
                        break :int;
                    } else if (data.fits_in_twos_comp(.signed, 32)) {
                        i.items.append_assume_capacity(.{
                            .tag = .i32,
                            .data = @bit_cast(data.to(i32) catch unreachable),
                        });
                        break :int;
                    }
                },
            }
            const limbs_index: u32 = @int_cast(i.limbs.items.len);
            try i.limbs.append_slice(gpa, big.limbs);
            i.items.append_assume_capacity(.{
                .tag = if (big.positive) .int_positive else .int_negative,
                .data = try i.add_extra(gpa, Tag.Int{
                    .limbs_index = limbs_index,
                    .limbs_len = @int_cast(big.limbs.len),
                }),
            });
        },
        .float => |repr| switch (repr) {
            .f16 => |data| i.items.append_assume_capacity(.{
                .tag = .f16,
                .data = @as(u16, @bit_cast(data)),
            }),
            .f32 => |data| i.items.append_assume_capacity(.{
                .tag = .f32,
                .data = @as(u32, @bit_cast(data)),
            }),
            .f64 => |data| i.items.append_assume_capacity(.{
                .tag = .f64,
                .data = try i.add_extra(gpa, Tag.F64.pack(data)),
            }),
            .f80 => |data| i.items.append_assume_capacity(.{
                .tag = .f80,
                .data = try i.add_extra(gpa, Tag.F80.pack(data)),
            }),
            .f128 => |data| i.items.append_assume_capacity(.{
                .tag = .f128,
                .data = try i.add_extra(gpa, Tag.F128.pack(data)),
            }),
        },
        .bytes => |bytes| {
            const strings_index: u32 = @int_cast(i.strings.items.len);
            try i.strings.append_slice(gpa, bytes);
            i.items.append_assume_capacity(.{
                .tag = .bytes,
                .data = try i.add_extra(gpa, Tag.Bytes{
                    .strings_index = strings_index,
                    .len = @int_cast(bytes.len),
                }),
            });
        },
        .record_ty => |elems| {
            try i.extra.ensure_unused_capacity(gpa, @typeInfo(Tag.Record).Struct.fields.len +
                elems.len);
            i.items.append_assume_capacity(.{
                .tag = .record_ty,
                .data = i.add_extra_assume_capacity(Tag.Record{
                    .elements_len = @int_cast(elems.len),
                }),
            });
            i.extra.append_slice_assume_capacity(@ptr_cast(elems));
        },
        .ptr_ty,
        .noreturn_ty,
        .void_ty,
        .func_ty,
        .null,
        => unreachable,
    }

    return @enumFromInt(gop.index);
}

fn add_extra(i: *Interner, gpa: Allocator, extra: anytype) Allocator.Error!u32 {
    const fields = @typeInfo(@TypeOf(extra)).Struct.fields;
    try i.extra.ensure_unused_capacity(gpa, fields.len);
    return i.add_extra_assume_capacity(extra);
}

fn add_extra_assume_capacity(i: *Interner, extra: anytype) u32 {
    const result = @as(u32, @int_cast(i.extra.items.len));
    inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
        i.extra.append_assume_capacity(switch (field.type) {
            Ref => @int_from_enum(@field(extra, field.name)),
            u32 => @field(extra, field.name),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        });
    }
    return result;
}

pub fn get(i: *const Interner, ref: Ref) Key {
    switch (ref) {
        .ptr => return .ptr_ty,
        .func => return .func_ty,
        .noreturn => return .noreturn_ty,
        .void => return .void_ty,
        .i1 => return .{ .int_ty = 1 },
        .i8 => return .{ .int_ty = 8 },
        .i16 => return .{ .int_ty = 16 },
        .i32 => return .{ .int_ty = 32 },
        .i64 => return .{ .int_ty = 64 },
        .i128 => return .{ .int_ty = 128 },
        .f16 => return .{ .float_ty = 16 },
        .f32 => return .{ .float_ty = 32 },
        .f64 => return .{ .float_ty = 64 },
        .f80 => return .{ .float_ty = 80 },
        .f128 => return .{ .float_ty = 128 },
        .zero => return .{ .int = .{ .u64 = 0 } },
        .one => return .{ .int = .{ .u64 = 1 } },
        .null => return .null,
        else => {},
    }

    const item = i.items.get(@int_from_enum(ref));
    const data = item.data;
    return switch (item.tag) {
        .int_ty => .{ .int_ty = @int_cast(data) },
        .float_ty => .{ .float_ty = @int_cast(data) },
        .array_ty => {
            const array_ty = i.extra_data(Tag.Array, data);
            return .{ .array_ty = .{
                .len = array_ty.get_len(),
                .child = array_ty.child,
            } };
        },
        .vector_ty => {
            const vector_ty = i.extra_data(Tag.Vector, data);
            return .{ .vector_ty = .{
                .len = vector_ty.len,
                .child = vector_ty.child,
            } };
        },
        .u32 => .{ .int = .{ .u64 = data } },
        .i32 => .{ .int = .{ .i64 = @as(i32, @bit_cast(data)) } },
        .int_positive, .int_negative => {
            const int_info = i.extra_data(Tag.Int, data);
            const limbs = i.limbs.items[int_info.limbs_index..][0..int_info.limbs_len];
            return .{ .int = .{
                .big_int = .{
                    .positive = item.tag == .int_positive,
                    .limbs = limbs,
                },
            } };
        },
        .f16 => .{ .float = .{ .f16 = @bit_cast(@as(u16, @int_cast(data))) } },
        .f32 => .{ .float = .{ .f32 = @bit_cast(data) } },
        .f64 => {
            const float = i.extra_data(Tag.F64, data);
            return .{ .float = .{ .f64 = float.get() } };
        },
        .f80 => {
            const float = i.extra_data(Tag.F80, data);
            return .{ .float = .{ .f80 = float.get() } };
        },
        .f128 => {
            const float = i.extra_data(Tag.F128, data);
            return .{ .float = .{ .f128 = float.get() } };
        },
        .bytes => {
            const bytes = i.extra_data(Tag.Bytes, data);
            return .{ .bytes = i.strings.items[bytes.strings_index..][0..bytes.len] };
        },
        .record_ty => {
            const extra = i.extra_data_trail(Tag.Record, data);
            return .{
                .record_ty = @ptr_cast(i.extra.items[extra.end..][0..extra.data.elements_len]),
            };
        },
    };
}

fn extra_data(i: *const Interner, comptime T: type, index: usize) T {
    return i.extra_data_trail(T, index).data;
}

fn extra_data_trail(i: *const Interner, comptime T: type, index: usize) struct { data: T, end: u32 } {
    var result: T = undefined;
    const fields = @typeInfo(T).Struct.fields;
    inline for (fields, 0..) |field, field_i| {
        const int32 = i.extra.items[field_i + index];
        @field(result, field.name) = switch (field.type) {
            Ref => @enumFromInt(int32),
            u32 => int32,
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        };
    }
    return .{
        .data = result,
        .end = @int_cast(index + fields.len),
    };
}
