gpa: Allocator,
strip: bool,

source_filename: String,
data_layout: String,
target_triple: String,
module_asm: std.ArrayListUnmanaged(u8),

string_map: std.AutoArrayHashMapUnmanaged(void, void),
string_indices: std.ArrayListUnmanaged(u32),
string_bytes: std.ArrayListUnmanaged(u8),

types: std.AutoArrayHashMapUnmanaged(String, Type),
next_unnamed_type: String,
next_unique_type_id: std.AutoHashMapUnmanaged(String, u32),
type_map: std.AutoArrayHashMapUnmanaged(void, void),
type_items: std.ArrayListUnmanaged(Type.Item),
type_extra: std.ArrayListUnmanaged(u32),

attributes: std.AutoArrayHashMapUnmanaged(Attribute.Storage, void),
attributes_map: std.AutoArrayHashMapUnmanaged(void, void),
attributes_indices: std.ArrayListUnmanaged(u32),
attributes_extra: std.ArrayListUnmanaged(u32),

function_attributes_set: std.AutoArrayHashMapUnmanaged(FunctionAttributes, void),

globals: std.AutoArrayHashMapUnmanaged(StrtabString, Global),
next_unnamed_global: StrtabString,
next_replaced_global: StrtabString,
next_unique_global_id: std.AutoHashMapUnmanaged(StrtabString, u32),
aliases: std.ArrayListUnmanaged(Alias),
variables: std.ArrayListUnmanaged(Variable),
functions: std.ArrayListUnmanaged(Function),

strtab_string_map: std.AutoArrayHashMapUnmanaged(void, void),
strtab_string_indices: std.ArrayListUnmanaged(u32),
strtab_string_bytes: std.ArrayListUnmanaged(u8),

constant_map: std.AutoArrayHashMapUnmanaged(void, void),
constant_items: std.MultiArrayList(Constant.Item),
constant_extra: std.ArrayListUnmanaged(u32),
constant_limbs: std.ArrayListUnmanaged(std.math.big.Limb),

metadata_map: std.AutoArrayHashMapUnmanaged(void, void),
metadata_items: std.MultiArrayList(Metadata.Item),
metadata_extra: std.ArrayListUnmanaged(u32),
metadata_limbs: std.ArrayListUnmanaged(std.math.big.Limb),
metadata_forward_references: std.ArrayListUnmanaged(Metadata),
metadata_named: std.AutoArrayHashMapUnmanaged(MetadataString, struct {
    len: u32,
    index: Metadata.Item.ExtraIndex,
}),

metadata_string_map: std.AutoArrayHashMapUnmanaged(void, void),
metadata_string_indices: std.ArrayListUnmanaged(u32),
metadata_string_bytes: std.ArrayListUnmanaged(u8),

pub const expected_args_len = 16;
pub const expected_attrs_len = 16;
pub const expected_fields_len = 32;
pub const expected_gep_indices_len = 8;
pub const expected_cases_len = 8;
pub const expected_incoming_len = 8;

pub const Options = struct {
    allocator: Allocator,
    strip: bool = true,
    name: []const u8 = &.{},
    target: std.Target = builtin.target,
    triple: []const u8 = &.{},
};

pub const String = enum(u32) {
    none = std.math.max_int(u31),
    empty,
    _,

    pub fn is_anon(self: String) bool {
        assert(self != .none);
        return self.to_index() == null;
    }

    pub fn slice(self: String, builder: *const Builder) ?[]const u8 {
        const index = self.to_index() orelse return null;
        const start = builder.string_indices.items[index];
        const end = builder.string_indices.items[index + 1];
        return builder.string_bytes.items[start..end];
    }

    const FormatData = struct {
        string: String,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.index_of_none(u8, fmt_str, "\"r")) |_|
            @compile_error("invalid format string: '" ++ fmt_str ++ "'");
        assert(data.string != .none);
        const string_slice = data.string.slice(data.builder) orelse
            return writer.print("{d}", .{@int_from_enum(data.string)});
        if (comptime std.mem.index_of_scalar(u8, fmt_str, 'r')) |_|
            return writer.write_all(string_slice);
        try print_escaped_string(
            string_slice,
            if (comptime std.mem.index_of_scalar(u8, fmt_str, '"')) |_|
                .always_quote
            else
                .quote_unless_valid_identifier,
            writer,
        );
    }
    pub fn fmt(self: String, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .string = self, .builder = builder } };
    }

    fn from_index(index: ?usize) String {
        return @enumFromInt(@as(u32, @int_cast((index orelse return .none) +
            @int_from_enum(String.empty))));
    }

    fn to_index(self: String) ?usize {
        return std.math.sub(u32, @int_from_enum(self), @int_from_enum(String.empty)) catch null;
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            return std.mem.eql(u8, lhs_key, String.from_index(rhs_index).slice(ctx.builder).?);
        }
    };
};

pub const BinaryOpcode = enum(u4) {
    add = 0,
    sub = 1,
    mul = 2,
    udiv = 3,
    sdiv = 4,
    urem = 5,
    srem = 6,
    shl = 7,
    lshr = 8,
    ashr = 9,
    @"and" = 10,
    @"or" = 11,
    xor = 12,
};

pub const CastOpcode = enum(u4) {
    trunc = 0,
    zext = 1,
    sext = 2,
    fptoui = 3,
    fptosi = 4,
    uitofp = 5,
    sitofp = 6,
    fptrunc = 7,
    fpext = 8,
    ptrtoint = 9,
    inttoptr = 10,
    bitcast = 11,
    addrspacecast = 12,
};

pub const CmpPredicate = enum(u6) {
    fcmp_false = 0,
    fcmp_oeq = 1,
    fcmp_ogt = 2,
    fcmp_oge = 3,
    fcmp_olt = 4,
    fcmp_ole = 5,
    fcmp_one = 6,
    fcmp_ord = 7,
    fcmp_uno = 8,
    fcmp_ueq = 9,
    fcmp_ugt = 10,
    fcmp_uge = 11,
    fcmp_ult = 12,
    fcmp_ule = 13,
    fcmp_une = 14,
    fcmp_true = 15,
    icmp_eq = 32,
    icmp_ne = 33,
    icmp_ugt = 34,
    icmp_uge = 35,
    icmp_ult = 36,
    icmp_ule = 37,
    icmp_sgt = 38,
    icmp_sge = 39,
    icmp_slt = 40,
    icmp_sle = 41,
};

pub const Type = enum(u32) {
    void,
    half,
    bfloat,
    float,
    double,
    fp128,
    x86_fp80,
    ppc_fp128,
    x86_amx,
    x86_mmx,
    label,
    token,
    metadata,

    i1,
    i8,
    i16,
    i29,
    i32,
    i64,
    i80,
    i128,
    ptr,
    @"ptr addrspace(4)",

    none = std.math.max_int(u32),
    _,

    pub const ptr_amdgpu_constant =
        @field(Type, std.fmt.comptime_print("ptr{ }", .{AddrSpace.amdgpu.constant}));

    pub const Tag = enum(u4) {
        simple,
        function,
        vararg_function,
        integer,
        pointer,
        target,
        vector,
        scalable_vector,
        small_array,
        array,
        structure,
        packed_structure,
        named_structure,
    };

    pub const Simple = enum(u5) {
        void = 2,
        half = 10,
        bfloat = 23,
        float = 3,
        double = 4,
        fp128 = 14,
        x86_fp80 = 13,
        ppc_fp128 = 15,
        x86_amx = 24,
        x86_mmx = 17,
        label = 5,
        token = 22,
        metadata = 16,
    };

    pub const Function = struct {
        ret: Type,
        params_len: u32,
        //params: [params_len]Value,

        pub const Kind = enum { normal, vararg };
    };

    pub const Target = extern struct {
        name: String,
        types_len: u32,
        ints_len: u32,
        //types: [types_len]Type,
        //ints: [ints_len]u32,
    };

    pub const Vector = extern struct {
        len: u32,
        child: Type,

        fn length(self: Vector) u32 {
            return self.len;
        }

        pub const Kind = enum { normal, scalable };
    };

    pub const Array = extern struct {
        len_lo: u32,
        len_hi: u32,
        child: Type,

        fn length(self: Array) u64 {
            return @as(u64, self.len_hi) << 32 | self.len_lo;
        }
    };

    pub const Structure = struct {
        fields_len: u32,
        //fields: [fields_len]Type,

        pub const Kind = enum { normal, @"packed" };
    };

    pub const NamedStructure = struct {
        id: String,
        body: Type,
    };

    pub const Item = packed struct(u32) {
        tag: Tag,
        data: ExtraIndex,

        pub const ExtraIndex = u28;
    };

    pub fn tag(self: Type, builder: *const Builder) Tag {
        return builder.type_items.items[@int_from_enum(self)].tag;
    }

    pub fn unnamed_tag(self: Type, builder: *const Builder) Tag {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .named_structure => builder.type_extra_data(Type.NamedStructure, item.data).body
                .unnamed_tag(builder),
            else => item.tag,
        };
    }

    pub fn scalar_tag(self: Type, builder: *const Builder) Tag {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .vector, .scalable_vector => builder.type_extra_data(Type.Vector, item.data)
                .child.tag(builder),
            else => item.tag,
        };
    }

    pub fn is_floating_point(self: Type) bool {
        return switch (self) {
            .half, .bfloat, .float, .double, .fp128, .x86_fp80, .ppc_fp128 => true,
            else => false,
        };
    }

    pub fn is_integer(self: Type, builder: *const Builder) bool {
        return switch (self) {
            .i1, .i8, .i16, .i29, .i32, .i64, .i80, .i128 => true,
            else => switch (self.tag(builder)) {
                .integer => true,
                else => false,
            },
        };
    }

    pub fn is_pointer(self: Type, builder: *const Builder) bool {
        return switch (self) {
            .ptr => true,
            else => switch (self.tag(builder)) {
                .pointer => true,
                else => false,
            },
        };
    }

    pub fn pointer_addr_space(self: Type, builder: *const Builder) AddrSpace {
        switch (self) {
            .ptr => return .default,
            else => {
                const item = builder.type_items.items[@int_from_enum(self)];
                assert(item.tag == .pointer);
                return @enumFromInt(item.data);
            },
        }
    }

    pub fn is_function(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .function, .vararg_function => true,
            else => false,
        };
    }

    pub fn function_kind(self: Type, builder: *const Builder) Type.Function.Kind {
        return switch (self.tag(builder)) {
            .function => .normal,
            .vararg_function => .vararg,
            else => unreachable,
        };
    }

    pub fn function_parameters(self: Type, builder: *const Builder) []const Type {
        const item = builder.type_items.items[@int_from_enum(self)];
        switch (item.tag) {
            .function,
            .vararg_function,
            => {
                var extra = builder.type_extra_data_trail(Type.Function, item.data);
                return extra.trail.next(extra.data.params_len, Type, builder);
            },
            else => unreachable,
        }
    }

    pub fn function_return(self: Type, builder: *const Builder) Type {
        const item = builder.type_items.items[@int_from_enum(self)];
        switch (item.tag) {
            .function,
            .vararg_function,
            => return builder.type_extra_data(Type.Function, item.data).ret,
            else => unreachable,
        }
    }

    pub fn is_vector(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .vector, .scalable_vector => true,
            else => false,
        };
    }

    pub fn vector_kind(self: Type, builder: *const Builder) Type.Vector.Kind {
        return switch (self.tag(builder)) {
            .vector => .normal,
            .scalable_vector => .scalable,
            else => unreachable,
        };
    }

    pub fn is_struct(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .structure, .packed_structure, .named_structure => true,
            else => false,
        };
    }

    pub fn struct_kind(self: Type, builder: *const Builder) Type.Structure.Kind {
        return switch (self.unnamed_tag(builder)) {
            .structure => .normal,
            .packed_structure => .@"packed",
            else => unreachable,
        };
    }

    pub fn is_aggregate(self: Type, builder: *const Builder) bool {
        return switch (self.tag(builder)) {
            .small_array, .array, .structure, .packed_structure, .named_structure => true,
            else => false,
        };
    }

    pub fn scalar_bits(self: Type, builder: *const Builder) u24 {
        return switch (self) {
            .void, .label, .token, .metadata, .none, .x86_amx => unreachable,
            .i1 => 1,
            .i8 => 8,
            .half, .bfloat, .i16 => 16,
            .i29 => 29,
            .float, .i32 => 32,
            .double, .i64, .x86_mmx => 64,
            .x86_fp80, .i80 => 80,
            .fp128, .ppc_fp128, .i128 => 128,
            .ptr, .@"ptr addrspace(4)" => @panic("TODO: query data layout"),
            _ => {
                const item = builder.type_items.items[@int_from_enum(self)];
                return switch (item.tag) {
                    .simple,
                    .function,
                    .vararg_function,
                    => unreachable,
                    .integer => @int_cast(item.data),
                    .pointer => @panic("TODO: query data layout"),
                    .target => unreachable,
                    .vector,
                    .scalable_vector,
                    => builder.type_extra_data(Type.Vector, item.data).child.scalar_bits(builder),
                    .small_array,
                    .array,
                    .structure,
                    .packed_structure,
                    .named_structure,
                    => unreachable,
                };
            },
        };
    }

    pub fn child_type(self: Type, builder: *const Builder) Type {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            .small_array,
            => builder.type_extra_data(Type.Vector, item.data).child,
            .array => builder.type_extra_data(Type.Array, item.data).child,
            .named_structure => builder.type_extra_data(Type.NamedStructure, item.data).body,
            else => unreachable,
        };
    }

    pub fn scalar_type(self: Type, builder: *const Builder) Type {
        if (self.is_floating_point()) return self;
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .integer,
            .pointer,
            => self,
            .vector,
            .scalable_vector,
            => builder.type_extra_data(Type.Vector, item.data).child,
            else => unreachable,
        };
    }

    pub fn change_scalar(self: Type, scalar: Type, builder: *Builder) Allocator.Error!Type {
        try builder.ensure_unused_type_capacity(1, Type.Vector, 0);
        return self.change_scalar_assume_capacity(scalar, builder);
    }

    pub fn change_scalar_assume_capacity(self: Type, scalar: Type, builder: *Builder) Type {
        if (self.is_floating_point()) return scalar;
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .integer,
            .pointer,
            => scalar,
            inline .vector,
            .scalable_vector,
            => |kind| builder.vector_type_assume_capacity(
                switch (kind) {
                    .vector => .normal,
                    .scalable_vector => .scalable,
                    else => unreachable,
                },
                builder.type_extra_data(Type.Vector, item.data).len,
                scalar,
            ),
            else => unreachable,
        };
    }

    pub fn vector_len(self: Type, builder: *const Builder) u32 {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            => builder.type_extra_data(Type.Vector, item.data).len,
            else => unreachable,
        };
    }

    pub fn change_length(self: Type, len: u32, builder: *Builder) Allocator.Error!Type {
        try builder.ensure_unused_type_capacity(1, Type.Array, 0);
        return self.change_length_assume_capacity(len, builder);
    }

    pub fn change_length_assume_capacity(self: Type, len: u32, builder: *Builder) Type {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            inline .vector,
            .scalable_vector,
            => |kind| builder.vector_type_assume_capacity(
                switch (kind) {
                    .vector => .normal,
                    .scalable_vector => .scalable,
                    else => unreachable,
                },
                len,
                builder.type_extra_data(Type.Vector, item.data).child,
            ),
            .small_array => builder.array_type_assume_capacity(
                len,
                builder.type_extra_data(Type.Vector, item.data).child,
            ),
            .array => builder.array_type_assume_capacity(
                len,
                builder.type_extra_data(Type.Array, item.data).child,
            ),
            else => unreachable,
        };
    }

    pub fn aggregate_len(self: Type, builder: *const Builder) usize {
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .vector,
            .scalable_vector,
            .small_array,
            => builder.type_extra_data(Type.Vector, item.data).len,
            .array => @int_cast(builder.type_extra_data(Type.Array, item.data).length()),
            .structure,
            .packed_structure,
            => builder.type_extra_data(Type.Structure, item.data).fields_len,
            .named_structure => builder.type_extra_data(Type.NamedStructure, item.data).body
                .aggregate_len(builder),
            else => unreachable,
        };
    }

    pub fn struct_fields(self: Type, builder: *const Builder) []const Type {
        const item = builder.type_items.items[@int_from_enum(self)];
        switch (item.tag) {
            .structure,
            .packed_structure,
            => {
                var extra = builder.type_extra_data_trail(Type.Structure, item.data);
                return extra.trail.next(extra.data.fields_len, Type, builder);
            },
            .named_structure => return builder.type_extra_data(Type.NamedStructure, item.data).body
                .struct_fields(builder),
            else => unreachable,
        }
    }

    pub fn child_type_at(self: Type, indices: []const u32, builder: *const Builder) Type {
        if (indices.len == 0) return self;
        const item = builder.type_items.items[@int_from_enum(self)];
        return switch (item.tag) {
            .small_array => builder.type_extra_data(Type.Vector, item.data).child
                .child_type_at(indices[1..], builder),
            .array => builder.type_extra_data(Type.Array, item.data).child
                .child_type_at(indices[1..], builder),
            .structure,
            .packed_structure,
            => {
                var extra = builder.type_extra_data_trail(Type.Structure, item.data);
                const fields = extra.trail.next(extra.data.fields_len, Type, builder);
                return fields[indices[0]].child_type_at(indices[1..], builder);
            },
            .named_structure => builder.type_extra_data(Type.NamedStructure, item.data).body
                .child_type_at(indices, builder),
            else => unreachable,
        };
    }

    pub fn target_layout_type(self: Type, builder: *const Builder) Type {
        _ = self;
        _ = builder;
        @panic("TODO: implement target_layout_type");
    }

    pub fn is_sized(self: Type, builder: *const Builder) Allocator.Error!bool {
        var visited: IsSizedVisited = .{};
        defer visited.deinit(builder.gpa);
        const result = try self.is_sized_visited(&visited, builder);
        return result;
    }

    const FormatData = struct {
        type: Type,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        assert(data.type != .none);
        if (comptime std.mem.eql(u8, fmt_str, "m")) {
            const item = data.builder.type_items.items[@int_from_enum(data.type)];
            switch (item.tag) {
                .simple => try writer.write_all(switch (@as(Simple, @enumFromInt(item.data))) {
                    .void => "isVoid",
                    .half => "f16",
                    .bfloat => "bf16",
                    .float => "f32",
                    .double => "f64",
                    .fp128 => "f128",
                    .x86_fp80 => "f80",
                    .ppc_fp128 => "ppcf128",
                    .x86_amx => "x86amx",
                    .x86_mmx => "x86mmx",
                    .label, .token => unreachable,
                    .metadata => "Metadata",
                }),
                .function, .vararg_function => |kind| {
                    var extra = data.builder.type_extra_data_trail(Type.Function, item.data);
                    const params = extra.trail.next(extra.data.params_len, Type, data.builder);
                    try writer.print("f_{m}", .{extra.data.ret.fmt(data.builder)});
                    for (params) |param| try writer.print("{m}", .{param.fmt(data.builder)});
                    switch (kind) {
                        .function => {},
                        .vararg_function => try writer.write_all("vararg"),
                        else => unreachable,
                    }
                    try writer.write_byte('f');
                },
                .integer => try writer.print("i{d}", .{item.data}),
                .pointer => try writer.print("p{d}", .{item.data}),
                .target => {
                    var extra = data.builder.type_extra_data_trail(Type.Target, item.data);
                    const types = extra.trail.next(extra.data.types_len, Type, data.builder);
                    const ints = extra.trail.next(extra.data.ints_len, u32, data.builder);
                    try writer.print("t{s}", .{extra.data.name.slice(data.builder).?});
                    for (types) |ty| try writer.print("_{m}", .{ty.fmt(data.builder)});
                    for (ints) |int| try writer.print("_{d}", .{int});
                    try writer.write_byte('t');
                },
                .vector, .scalable_vector => |kind| {
                    const extra = data.builder.type_extra_data(Type.Vector, item.data);
                    try writer.print("{s}v{d}{m}", .{
                        switch (kind) {
                            .vector => "",
                            .scalable_vector => "nx",
                            else => unreachable,
                        },
                        extra.len,
                        extra.child.fmt(data.builder),
                    });
                },
                inline .small_array, .array => |kind| {
                    const extra = data.builder.type_extra_data(switch (kind) {
                        .small_array => Type.Vector,
                        .array => Type.Array,
                        else => unreachable,
                    }, item.data);
                    try writer.print("a{d}{m}", .{ extra.length(), extra.child.fmt(data.builder) });
                },
                .structure, .packed_structure => {
                    var extra = data.builder.type_extra_data_trail(Type.Structure, item.data);
                    const fields = extra.trail.next(extra.data.fields_len, Type, data.builder);
                    try writer.write_all("sl_");
                    for (fields) |field| try writer.print("{m}", .{field.fmt(data.builder)});
                    try writer.write_byte('s');
                },
                .named_structure => {
                    const extra = data.builder.type_extra_data(Type.NamedStructure, item.data);
                    try writer.write_all("s_");
                    if (extra.id.slice(data.builder)) |id| try writer.write_all(id);
                },
            }
            return;
        }
        if (std.enums.tag_name(Type, data.type)) |name| return writer.write_all(name);
        const item = data.builder.type_items.items[@int_from_enum(data.type)];
        switch (item.tag) {
            .simple => unreachable,
            .function, .vararg_function => |kind| {
                var extra = data.builder.type_extra_data_trail(Type.Function, item.data);
                const params = extra.trail.next(extra.data.params_len, Type, data.builder);
                if (!comptime std.mem.eql(u8, fmt_str, ">"))
                    try writer.print("{%} ", .{extra.data.ret.fmt(data.builder)});
                if (!comptime std.mem.eql(u8, fmt_str, "<")) {
                    try writer.write_byte('(');
                    for (params, 0..) |param, index| {
                        if (index > 0) try writer.write_all(", ");
                        try writer.print("{%}", .{param.fmt(data.builder)});
                    }
                    switch (kind) {
                        .function => {},
                        .vararg_function => {
                            if (params.len > 0) try writer.write_all(", ");
                            try writer.write_all("...");
                        },
                        else => unreachable,
                    }
                    try writer.write_byte(')');
                }
            },
            .integer => try writer.print("i{d}", .{item.data}),
            .pointer => try writer.print("ptr{ }", .{@as(AddrSpace, @enumFromInt(item.data))}),
            .target => {
                var extra = data.builder.type_extra_data_trail(Type.Target, item.data);
                const types = extra.trail.next(extra.data.types_len, Type, data.builder);
                const ints = extra.trail.next(extra.data.ints_len, u32, data.builder);
                try writer.print(
                    \\target({"}
                , .{extra.data.name.fmt(data.builder)});
                for (types) |ty| try writer.print(", {%}", .{ty.fmt(data.builder)});
                for (ints) |int| try writer.print(", {d}", .{int});
                try writer.write_byte(')');
            },
            .vector, .scalable_vector => |kind| {
                const extra = data.builder.type_extra_data(Type.Vector, item.data);
                try writer.print("<{s}{d} x {%}>", .{
                    switch (kind) {
                        .vector => "",
                        .scalable_vector => "vscale x ",
                        else => unreachable,
                    },
                    extra.len,
                    extra.child.fmt(data.builder),
                });
            },
            inline .small_array, .array => |kind| {
                const extra = data.builder.type_extra_data(switch (kind) {
                    .small_array => Type.Vector,
                    .array => Type.Array,
                    else => unreachable,
                }, item.data);
                try writer.print("[{d} x {%}]", .{ extra.length(), extra.child.fmt(data.builder) });
            },
            .structure, .packed_structure => |kind| {
                var extra = data.builder.type_extra_data_trail(Type.Structure, item.data);
                const fields = extra.trail.next(extra.data.fields_len, Type, data.builder);
                switch (kind) {
                    .structure => {},
                    .packed_structure => try writer.write_byte('<'),
                    else => unreachable,
                }
                try writer.write_all("{ ");
                for (fields, 0..) |field, index| {
                    if (index > 0) try writer.write_all(", ");
                    try writer.print("{%}", .{field.fmt(data.builder)});
                }
                try writer.write_all(" }");
                switch (kind) {
                    .structure => {},
                    .packed_structure => try writer.write_byte('>'),
                    else => unreachable,
                }
            },
            .named_structure => {
                const extra = data.builder.type_extra_data(Type.NamedStructure, item.data);
                if (comptime std.mem.eql(u8, fmt_str, "%")) try writer.print("%{}", .{
                    extra.id.fmt(data.builder),
                }) else switch (extra.body) {
                    .none => try writer.write_all("opaque"),
                    else => try format(.{
                        .type = extra.body,
                        .builder = data.builder,
                    }, fmt_str, fmt_opts, writer),
                }
            },
        }
    }
    pub fn fmt(self: Type, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .type = self, .builder = builder } };
    }

    const IsSizedVisited = std.AutoHashMapUnmanaged(Type, void);
    fn is_sized_visited(
        self: Type,
        visited: *IsSizedVisited,
        builder: *const Builder,
    ) Allocator.Error!bool {
        return switch (self) {
            .void,
            .label,
            .token,
            .metadata,
            => false,
            .half,
            .bfloat,
            .float,
            .double,
            .fp128,
            .x86_fp80,
            .ppc_fp128,
            .x86_amx,
            .x86_mmx,
            .i1,
            .i8,
            .i16,
            .i29,
            .i32,
            .i64,
            .i80,
            .i128,
            .ptr,
            .@"ptr addrspace(4)",
            => true,
            .none => unreachable,
            _ => {
                const item = builder.type_items.items[@int_from_enum(self)];
                return switch (item.tag) {
                    .simple => unreachable,
                    .function,
                    .vararg_function,
                    => false,
                    .integer,
                    .pointer,
                    => true,
                    .target => self.target_layout_type(builder).is_sized_visited(visited, builder),
                    .vector,
                    .scalable_vector,
                    .small_array,
                    => builder.type_extra_data(Type.Vector, item.data)
                        .child.is_sized_visited(visited, builder),
                    .array => builder.type_extra_data(Type.Array, item.data)
                        .child.is_sized_visited(visited, builder),
                    .structure,
                    .packed_structure,
                    => {
                        if (try visited.fetch_put(builder.gpa, self, {})) |_| return false;

                        var extra = builder.type_extra_data_trail(Type.Structure, item.data);
                        const fields = extra.trail.next(extra.data.fields_len, Type, builder);
                        for (fields) |field| {
                            if (field.is_vector(builder) and field.vector_kind(builder) == .scalable)
                                return false;
                            if (!try field.is_sized_visited(visited, builder))
                                return false;
                        }
                        return true;
                    },
                    .named_structure => {
                        const body = builder.type_extra_data(Type.NamedStructure, item.data).body;
                        return body != .none and try body.is_sized_visited(visited, builder);
                    },
                };
            },
        };
    }
};

pub const Attribute = union(Kind) {
    // Parameter Attributes
    zeroext,
    signext,
    inreg,
    byval: Type,
    byref: Type,
    preallocated: Type,
    inalloca: Type,
    sret: Type,
    elementtype: Type,
    @"align": Alignment,
    @"noalias",
    nocapture,
    nofree,
    nest,
    returned,
    nonnull,
    dereferenceable: u32,
    dereferenceable_or_null: u32,
    swiftself,
    swiftasync,
    swifterror,
    immarg,
    noundef,
    nofpclass: FpClass,
    alignstack: Alignment,
    allocalign,
    allocptr,
    readnone,
    readonly,
    writeonly,

    // Function Attributes
    //alignstack: Alignment,
    allockind: AllocKind,
    allocsize: AllocSize,
    alwaysinline,
    builtin,
    cold,
    convergent,
    disable_sanitizer_information,
    fn_ret_thunk_extern,
    hot,
    inlinehint,
    jumptable,
    memory: Memory,
    minsize,
    naked,
    nobuiltin,
    nocallback,
    noduplicate,
    //nofree,
    noimplicitfloat,
    @"noinline",
    nomerge,
    nonlazybind,
    noprofile,
    skipprofile,
    noredzone,
    noreturn,
    norecurse,
    willreturn,
    nosync,
    nounwind,
    nosanitize_bounds,
    nosanitize_coverage,
    null_pointer_is_valid,
    optforfuzzing,
    optnone,
    optsize,
    //preallocated: Type,
    returns_twice,
    safestack,
    sanitize_address,
    sanitize_memory,
    sanitize_thread,
    sanitize_hwaddress,
    sanitize_memtag,
    speculative_load_hardening,
    speculatable,
    ssp,
    sspstrong,
    sspreq,
    strictfp,
    uwtable: UwTable,
    nocf_check,
    shadowcallstack,
    mustprogress,
    vscale_range: VScaleRange,

    // Global Attributes
    no_sanitize_address,
    no_sanitize_hwaddress,
    //sanitize_memtag,
    sanitize_address_dyninit,

    string: struct { kind: String, value: String },
    none: noreturn,

    pub const Index = enum(u32) {
        _,

        pub fn get_kind(self: Index, builder: *const Builder) Kind {
            return self.to_storage(builder).kind;
        }

        pub fn to_attribute(self: Index, builder: *const Builder) Attribute {
            @setEvalBranchQuota(2_000);
            const storage = self.to_storage(builder);
            if (storage.kind.to_string()) |kind| return .{ .string = .{
                .kind = kind,
                .value = @enumFromInt(storage.value),
            } } else return switch (storage.kind) {
                inline .zeroext,
                .signext,
                .inreg,
                .byval,
                .byref,
                .preallocated,
                .inalloca,
                .sret,
                .elementtype,
                .@"align",
                .@"noalias",
                .nocapture,
                .nofree,
                .nest,
                .returned,
                .nonnull,
                .dereferenceable,
                .dereferenceable_or_null,
                .swiftself,
                .swiftasync,
                .swifterror,
                .immarg,
                .noundef,
                .nofpclass,
                .alignstack,
                .allocalign,
                .allocptr,
                .readnone,
                .readonly,
                .writeonly,
                //.alignstack,
                .allockind,
                .allocsize,
                .alwaysinline,
                .builtin,
                .cold,
                .convergent,
                .disable_sanitizer_information,
                .fn_ret_thunk_extern,
                .hot,
                .inlinehint,
                .jumptable,
                .memory,
                .minsize,
                .naked,
                .nobuiltin,
                .nocallback,
                .noduplicate,
                //.nofree,
                .noimplicitfloat,
                .@"noinline",
                .nomerge,
                .nonlazybind,
                .noprofile,
                .skipprofile,
                .noredzone,
                .noreturn,
                .norecurse,
                .willreturn,
                .nosync,
                .nounwind,
                .nosanitize_bounds,
                .nosanitize_coverage,
                .null_pointer_is_valid,
                .optforfuzzing,
                .optnone,
                .optsize,
                //.preallocated,
                .returns_twice,
                .safestack,
                .sanitize_address,
                .sanitize_memory,
                .sanitize_thread,
                .sanitize_hwaddress,
                .sanitize_memtag,
                .speculative_load_hardening,
                .speculatable,
                .ssp,
                .sspstrong,
                .sspreq,
                .strictfp,
                .uwtable,
                .nocf_check,
                .shadowcallstack,
                .mustprogress,
                .vscale_range,
                .no_sanitize_address,
                .no_sanitize_hwaddress,
                .sanitize_address_dyninit,
                => |kind| {
                    const field = comptime blk: {
                        @setEvalBranchQuota(10_000);
                        for (@typeInfo(Attribute).Union.fields) |field| {
                            if (std.mem.eql(u8, field.name, @tag_name(kind))) break :blk field;
                        }
                        unreachable;
                    };
                    comptime assert(std.mem.eql(u8, @tag_name(kind), field.name));
                    return @union_init(Attribute, field.name, switch (field.type) {
                        void => {},
                        u32 => storage.value,
                        Alignment, String, Type, UwTable => @enumFromInt(storage.value),
                        AllocKind, AllocSize, FpClass, Memory, VScaleRange => @bit_cast(storage.value),
                        else => @compile_error("bad payload type: " ++ field.name ++ ": " ++
                            @type_name(field.type)),
                    });
                },
                .string, .none => unreachable,
                _ => unreachable,
            };
        }

        const FormatData = struct {
            attribute_index: Index,
            builder: *const Builder,
        };
        fn format(
            data: FormatData,
            comptime fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (comptime std.mem.index_of_none(u8, fmt_str, "\"#")) |_|
                @compile_error("invalid format string: '" ++ fmt_str ++ "'");
            const attribute = data.attribute_index.to_attribute(data.builder);
            switch (attribute) {
                .zeroext,
                .signext,
                .inreg,
                .@"noalias",
                .nocapture,
                .nofree,
                .nest,
                .returned,
                .nonnull,
                .swiftself,
                .swiftasync,
                .swifterror,
                .immarg,
                .noundef,
                .allocalign,
                .allocptr,
                .readnone,
                .readonly,
                .writeonly,
                .alwaysinline,
                .builtin,
                .cold,
                .convergent,
                .disable_sanitizer_information,
                .fn_ret_thunk_extern,
                .hot,
                .inlinehint,
                .jumptable,
                .minsize,
                .naked,
                .nobuiltin,
                .nocallback,
                .noduplicate,
                .noimplicitfloat,
                .@"noinline",
                .nomerge,
                .nonlazybind,
                .noprofile,
                .skipprofile,
                .noredzone,
                .noreturn,
                .norecurse,
                .willreturn,
                .nosync,
                .nounwind,
                .nosanitize_bounds,
                .nosanitize_coverage,
                .null_pointer_is_valid,
                .optforfuzzing,
                .optnone,
                .optsize,
                .returns_twice,
                .safestack,
                .sanitize_address,
                .sanitize_memory,
                .sanitize_thread,
                .sanitize_hwaddress,
                .sanitize_memtag,
                .speculative_load_hardening,
                .speculatable,
                .ssp,
                .sspstrong,
                .sspreq,
                .strictfp,
                .nocf_check,
                .shadowcallstack,
                .mustprogress,
                .no_sanitize_address,
                .no_sanitize_hwaddress,
                .sanitize_address_dyninit,
                => try writer.print(" {s}", .{@tag_name(attribute)}),
                .byval,
                .byref,
                .preallocated,
                .inalloca,
                .sret,
                .elementtype,
                => |ty| try writer.print(" {s}({%})", .{ @tag_name(attribute), ty.fmt(data.builder) }),
                .@"align" => |alignment| try writer.print("{ }", .{alignment}),
                .dereferenceable,
                .dereferenceable_or_null,
                => |size| try writer.print(" {s}({d})", .{ @tag_name(attribute), size }),
                .nofpclass => |fpclass| {
                    const Int = @typeInfo(FpClass).Struct.backing_integer.?;
                    try writer.print(" {s}(", .{@tag_name(attribute)});
                    var any = false;
                    var remaining: Int = @bit_cast(fpclass);
                    inline for (@typeInfo(FpClass).Struct.decls) |decl| {
                        const pattern: Int = @bit_cast(@field(FpClass, decl.name));
                        if (remaining & pattern == pattern) {
                            if (!any) {
                                try writer.write_byte(' ');
                                any = true;
                            }
                            try writer.write_all(decl.name);
                            remaining &= ~pattern;
                        }
                    }
                    try writer.write_byte(')');
                },
                .alignstack => |alignment| try writer.print(
                    if (comptime std.mem.index_of_scalar(u8, fmt_str, '#') != null)
                        " {s}={d}"
                    else
                        " {s}({d})",
                    .{ @tag_name(attribute), alignment.to_byte_units() orelse return },
                ),
                .allockind => |allockind| {
                    try writer.print(" {s}(\"", .{@tag_name(attribute)});
                    var any = false;
                    inline for (@typeInfo(AllocKind).Struct.fields) |field| {
                        if (comptime std.mem.eql(u8, field.name, "_")) continue;
                        if (@field(allockind, field.name)) {
                            if (!any) {
                                try writer.write_byte(',');
                                any = true;
                            }
                            try writer.write_all(field.name);
                        }
                    }
                    try writer.write_all("\")");
                },
                .allocsize => |allocsize| {
                    try writer.print(" {s}({d}", .{ @tag_name(attribute), allocsize.elem_size });
                    if (allocsize.num_elems != AllocSize.none)
                        try writer.print(",{d}", .{allocsize.num_elems});
                    try writer.write_byte(')');
                },
                .memory => |memory| {
                    try writer.print(" {s}(", .{@tag_name(attribute)});
                    var any = memory.other != .none or
                        (memory.argmem == .none and memory.inaccessiblemem == .none);
                    if (any) try writer.write_all(@tag_name(memory.other));
                    inline for (.{ "argmem", "inaccessiblemem" }) |kind| {
                        if (@field(memory, kind) != memory.other) {
                            if (any) try writer.write_all(", ");
                            try writer.print("{s}: {s}", .{ kind, @tag_name(@field(memory, kind)) });
                            any = true;
                        }
                    }
                    try writer.write_byte(')');
                },
                .uwtable => |uwtable| if (uwtable != .none) {
                    try writer.print(" {s}", .{@tag_name(attribute)});
                    if (uwtable != UwTable.default) try writer.print("({s})", .{@tag_name(uwtable)});
                },
                .vscale_range => |vscale_range| try writer.print(" {s}({d},{d})", .{
                    @tag_name(attribute),
                    vscale_range.min.to_byte_units().?,
                    vscale_range.max.to_byte_units() orelse 0,
                }),
                .string => |string_attr| if (comptime std.mem.index_of_scalar(u8, fmt_str, '"') != null) {
                    try writer.print(" {\"}", .{string_attr.kind.fmt(data.builder)});
                    if (string_attr.value != .empty)
                        try writer.print("={\"}", .{string_attr.value.fmt(data.builder)});
                },
                .none => unreachable,
            }
        }
        pub fn fmt(self: Index, builder: *const Builder) std.fmt.Formatter(format) {
            return .{ .data = .{ .attribute_index = self, .builder = builder } };
        }

        fn to_storage(self: Index, builder: *const Builder) Storage {
            return builder.attributes.keys()[@int_from_enum(self)];
        }
    };

    pub const Kind = enum(u32) {
        // Parameter Attributes
        zeroext = 34,
        signext = 24,
        inreg = 5,
        byval = 3,
        byref = 69,
        preallocated = 65,
        inalloca = 38,
        sret = 29, // TODO: ?
        elementtype = 77,
        @"align" = 1,
        @"noalias" = 9,
        nocapture = 11,
        nofree = 62,
        nest = 8,
        returned = 22,
        nonnull = 39,
        dereferenceable = 41,
        dereferenceable_or_null = 42,
        swiftself = 46,
        swiftasync = 75,
        swifterror = 47,
        immarg = 60,
        noundef = 68,
        nofpclass = 87,
        alignstack = 25,
        allocalign = 80,
        allocptr = 81,
        readnone = 20,
        readonly = 21,
        writeonly = 52,

        // Function Attributes
        //alignstack,
        allockind = 82,
        allocsize = 51,
        alwaysinline = 2,
        builtin = 35,
        cold = 36,
        convergent = 43,
        disable_sanitizer_information = 78,
        fn_ret_thunk_extern = 84,
        hot = 72,
        inlinehint = 4,
        jumptable = 40,
        memory = 86,
        minsize = 6,
        naked = 7,
        nobuiltin = 10,
        nocallback = 71,
        noduplicate = 12,
        //nofree,
        noimplicitfloat = 13,
        @"noinline" = 14,
        nomerge = 66,
        nonlazybind = 15,
        noprofile = 73,
        skipprofile = 85,
        noredzone = 16,
        noreturn = 17,
        norecurse = 48,
        willreturn = 61,
        nosync = 63,
        nounwind = 18,
        nosanitize_bounds = 79,
        nosanitize_coverage = 76,
        null_pointer_is_valid = 67,
        optforfuzzing = 57,
        optnone = 37,
        optsize = 19,
        //preallocated,
        returns_twice = 23,
        safestack = 44,
        sanitize_address = 30,
        sanitize_memory = 32,
        sanitize_thread = 31,
        sanitize_hwaddress = 55,
        sanitize_memtag = 64,
        speculative_load_hardening = 59,
        speculatable = 53,
        ssp = 26,
        sspstrong = 28,
        sspreq = 27,
        strictfp = 54,
        uwtable = 33,
        nocf_check = 56,
        shadowcallstack = 58,
        mustprogress = 70,
        vscale_range = 74,

        // Global Attributes
        no_sanitize_address = 100,
        no_sanitize_hwaddress = 101,
        //sanitize_memtag,
        sanitize_address_dyninit = 102,

        string = std.math.max_int(u31),
        none = std.math.max_int(u32),
        _,

        pub const len = @typeInfo(Kind).Enum.fields.len - 2;

        pub fn from_string(str: String) Kind {
            assert(!str.is_anon());
            const kind: Kind = @enumFromInt(@int_from_enum(str));
            assert(kind != .none);
            return kind;
        }

        fn to_string(self: Kind) ?String {
            assert(self != .none);
            const str: String = @enumFromInt(@int_from_enum(self));
            return if (str.is_anon()) null else str;
        }
    };

    pub const FpClass = packed struct(u32) {
        signaling_nan: bool = false,
        quiet_nan: bool = false,
        negative_infinity: bool = false,
        negative_normal: bool = false,
        negative_subnormal: bool = false,
        negative_zero: bool = false,
        positive_zero: bool = false,
        positive_subnormal: bool = false,
        positive_normal: bool = false,
        positive_infinity: bool = false,
        _: u22 = 0,

        pub const all = FpClass{
            .signaling_nan = true,
            .quiet_nan = true,
            .negative_infinity = true,
            .negative_normal = true,
            .negative_subnormal = true,
            .negative_zero = true,
            .positive_zero = true,
            .positive_subnormal = true,
            .positive_normal = true,
            .positive_infinity = true,
        };

        pub const nan = FpClass{ .signaling_nan = true, .quiet_nan = true };
        pub const snan = FpClass{ .signaling_nan = true };
        pub const qnan = FpClass{ .quiet_nan = true };

        pub const inf = FpClass{ .negative_infinity = true, .positive_infinity = true };
        pub const ninf = FpClass{ .negative_infinity = true };
        pub const pinf = FpClass{ .positive_infinity = true };

        pub const zero = FpClass{ .positive_zero = true, .negative_zero = true };
        pub const nzero = FpClass{ .negative_zero = true };
        pub const pzero = FpClass{ .positive_zero = true };

        pub const sub = FpClass{ .positive_subnormal = true, .negative_subnormal = true };
        pub const nsub = FpClass{ .negative_subnormal = true };
        pub const psub = FpClass{ .positive_subnormal = true };

        pub const norm = FpClass{ .positive_normal = true, .negative_normal = true };
        pub const nnorm = FpClass{ .negative_normal = true };
        pub const pnorm = FpClass{ .positive_normal = true };
    };

    pub const AllocKind = packed struct(u32) {
        alloc: bool,
        realloc: bool,
        free: bool,
        uninitialized: bool,
        zeroed: bool,
        aligned: bool,
        _: u26 = 0,
    };

    pub const AllocSize = packed struct(u32) {
        elem_size: u16,
        num_elems: u16,

        pub const none = std.math.max_int(u16);

        fn to_llvm(self: AllocSize) packed struct(u64) { num_elems: u32, elem_size: u32 } {
            return .{ .num_elems = switch (self.num_elems) {
                else => self.num_elems,
                none => std.math.max_int(u32),
            }, .elem_size = self.elem_size };
        }
    };

    pub const Memory = packed struct(u32) {
        argmem: Effect = .none,
        inaccessiblemem: Effect = .none,
        other: Effect = .none,
        _: u26 = 0,

        pub const Effect = enum(u2) { none, read, write, readwrite };

        fn all(effect: Effect) Memory {
            return .{ .argmem = effect, .inaccessiblemem = effect, .other = effect };
        }
    };

    pub const UwTable = enum(u32) {
        none,
        sync,
        @"async",

        pub const default = UwTable.@"async";
    };

    pub const VScaleRange = packed struct(u32) {
        min: Alignment,
        max: Alignment,
        _: u20 = 0,

        fn to_llvm(self: VScaleRange) packed struct(u64) { max: u32, min: u32 } {
            return .{
                .max = @int_cast(self.max.to_byte_units() orelse 0),
                .min = @int_cast(self.min.to_byte_units().?),
            };
        }
    };

    pub fn get_kind(self: Attribute) Kind {
        return switch (self) {
            else => self,
            .string => |string_attr| Kind.from_string(string_attr.kind),
        };
    }

    const Storage = extern struct {
        kind: Kind,
        value: u32,
    };

    fn to_storage(self: Attribute) Storage {
        return switch (self) {
            inline else => |value, tag| .{ .kind = @as(Kind, self), .value = switch (@TypeOf(value)) {
                void => 0,
                u32 => value,
                Alignment, String, Type, UwTable => @int_from_enum(value),
                AllocKind, AllocSize, FpClass, Memory, VScaleRange => @bit_cast(value),
                else => @compile_error("bad payload type: " ++ @tag_name(tag) ++ @type_name(@TypeOf(value))),
            } },
            .string => |string_attr| .{
                .kind = Kind.from_string(string_attr.kind),
                .value = @int_from_enum(string_attr.value),
            },
            .none => unreachable,
        };
    }
};

pub const Attributes = enum(u32) {
    none,
    _,

    pub fn slice(self: Attributes, builder: *const Builder) []const Attribute.Index {
        const start = builder.attributes_indices.items[@int_from_enum(self)];
        const end = builder.attributes_indices.items[@int_from_enum(self) + 1];
        return @ptr_cast(builder.attributes_extra.items[start..end]);
    }

    const FormatData = struct {
        attributes: Attributes,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        for (data.attributes.slice(data.builder)) |attribute_index| try Attribute.Index.format(.{
            .attribute_index = attribute_index,
            .builder = data.builder,
        }, fmt_str, fmt_opts, writer);
    }
    pub fn fmt(self: Attributes, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .attributes = self, .builder = builder } };
    }
};

pub const FunctionAttributes = enum(u32) {
    none,
    _,

    const function_index = 0;
    const return_index = 1;
    const params_index = 2;

    pub const Wip = struct {
        maps: Maps = .{},

        const Map = std.AutoArrayHashMapUnmanaged(Attribute.Kind, Attribute.Index);
        const Maps = std.ArrayListUnmanaged(Map);

        pub fn deinit(self: *Wip, builder: *const Builder) void {
            for (self.maps.items) |*map| map.deinit(builder.gpa);
            self.maps.deinit(builder.gpa);
            self.* = undefined;
        }

        pub fn add_fn_attr(self: *Wip, attribute: Attribute, builder: *Builder) Allocator.Error!void {
            try self.add_attr(function_index, attribute, builder);
        }

        pub fn add_fn_attr_index(
            self: *Wip,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.add_attr_index(function_index, attribute_index, builder);
        }

        pub fn remove_fn_attr(self: *Wip, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            return self.remove_attr(function_index, attribute_kind);
        }

        pub fn add_ret_attr(self: *Wip, attribute: Attribute, builder: *Builder) Allocator.Error!void {
            try self.add_attr(return_index, attribute, builder);
        }

        pub fn add_ret_attr_index(
            self: *Wip,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.add_attr_index(return_index, attribute_index, builder);
        }

        pub fn remove_ret_attr(self: *Wip, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            return self.remove_attr(return_index, attribute_kind);
        }

        pub fn add_param_attr(
            self: *Wip,
            param_index: usize,
            attribute: Attribute,
            builder: *Builder,
        ) Allocator.Error!void {
            try self.add_attr(params_index + param_index, attribute, builder);
        }

        pub fn add_param_attr_index(
            self: *Wip,
            param_index: usize,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.add_attr_index(params_index + param_index, attribute_index, builder);
        }

        pub fn remove_param_attr(
            self: *Wip,
            param_index: usize,
            attribute_kind: Attribute.Kind,
        ) Allocator.Error!bool {
            return self.remove_attr(params_index + param_index, attribute_kind);
        }

        pub fn finish(self: *const Wip, builder: *Builder) Allocator.Error!FunctionAttributes {
            const attributes = try builder.gpa.alloc(Attributes, self.maps.items.len);
            defer builder.gpa.free(attributes);
            for (attributes, self.maps.items) |*attribute, map|
                attribute.* = try builder.attrs(map.values());
            return builder.fn_attrs(attributes);
        }

        fn add_attr(
            self: *Wip,
            index: usize,
            attribute: Attribute,
            builder: *Builder,
        ) Allocator.Error!void {
            const map = try self.get_or_put_map(builder.gpa, index);
            try map.put(builder.gpa, attribute.get_kind(), try builder.attr(attribute));
        }

        fn add_attr_index(
            self: *Wip,
            index: usize,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            const map = try self.get_or_put_map(builder.gpa, index);
            try map.put(builder.gpa, attribute_index.get_kind(builder), attribute_index);
        }

        fn remove_attr(self: *Wip, index: usize, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            const map = self.get_map(index) orelse return false;
            return map.swap_remove(attribute_kind);
        }

        fn get_or_put_map(self: *Wip, allocator: Allocator, index: usize) Allocator.Error!*Map {
            if (index >= self.maps.items.len)
                try self.maps.append_ntimes(allocator, .{}, index + 1 - self.maps.items.len);
            return &self.maps.items[index];
        }

        fn get_map(self: *Wip, index: usize) ?*Map {
            return if (index >= self.maps.items.len) null else &self.maps.items[index];
        }

        fn ensure_total_length(self: *Wip, new_len: usize) Allocator.Error!void {
            try self.maps.append_ntimes(
                .{},
                std.math.sub(usize, new_len, self.maps.items.len) catch return,
            );
        }
    };

    pub fn func(self: FunctionAttributes, builder: *const Builder) Attributes {
        return self.get(function_index, builder);
    }

    pub fn ret(self: FunctionAttributes, builder: *const Builder) Attributes {
        return self.get(return_index, builder);
    }

    pub fn param(self: FunctionAttributes, param_index: usize, builder: *const Builder) Attributes {
        return self.get(params_index + param_index, builder);
    }

    pub fn to_wip(self: FunctionAttributes, builder: *const Builder) Allocator.Error!Wip {
        var wip: Wip = .{};
        errdefer wip.deinit(builder);
        const attributes_slice = self.slice(builder);
        try wip.maps.ensure_total_capacity_precise(builder.gpa, attributes_slice.len);
        for (attributes_slice) |attributes| {
            const map = wip.maps.add_one_assume_capacity();
            map.* = .{};
            const attribute_slice = attributes.slice(builder);
            try map.ensure_total_capacity(builder.gpa, attribute_slice.len);
            for (attributes.slice(builder)) |attribute|
                map.put_assume_capacity_no_clobber(attribute.get_kind(builder), attribute);
        }
        return wip;
    }

    fn get(self: FunctionAttributes, index: usize, builder: *const Builder) Attributes {
        const attribute_slice = self.slice(builder);
        return if (index < attribute_slice.len) attribute_slice[index] else .none;
    }

    fn slice(self: FunctionAttributes, builder: *const Builder) []const Attributes {
        const start = builder.attributes_indices.items[@int_from_enum(self)];
        const end = builder.attributes_indices.items[@int_from_enum(self) + 1];
        return @ptr_cast(builder.attributes_extra.items[start..end]);
    }
};

pub const Linkage = enum(u4) {
    private = 9,
    internal = 3,
    weak = 1,
    weak_odr = 10,
    linkonce = 4,
    linkonce_odr = 11,
    available_externally = 12,
    appending = 2,
    common = 8,
    extern_weak = 7,
    external = 0,

    pub fn format(
        self: Linkage,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .external) try writer.print(" {s}", .{@tag_name(self)});
    }

    fn format_optional(
        data: ?Linkage,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (data) |linkage| try writer.print(" {s}", .{@tag_name(linkage)});
    }
    pub fn fmt_optional(self: ?Linkage) std.fmt.Formatter(format_optional) {
        return .{ .data = self };
    }
};

pub const Preemption = enum {
    dso_preemptable,
    dso_local,
    implicit_dso_local,

    pub fn format(
        self: Preemption,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .dso_local) try writer.print(" {s}", .{@tag_name(self)});
    }
};

pub const Visibility = enum(u2) {
    default = 0,
    hidden = 1,
    protected = 2,

    pub fn format(
        self: Visibility,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tag_name(self)});
    }
};

pub const DllStorageClass = enum(u2) {
    default = 0,
    dllimport = 1,
    dllexport = 2,

    pub fn format(
        self: DllStorageClass,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tag_name(self)});
    }
};

pub const ThreadLocal = enum(u3) {
    default = 0,
    generaldynamic = 1,
    localdynamic = 2,
    initialexec = 3,
    localexec = 4,

    pub fn format(
        self: ThreadLocal,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .default) return;
        try writer.print("{s}thread_local", .{prefix});
        if (self != .generaldynamic) try writer.print("({s})", .{@tag_name(self)});
    }
};

pub const Mutability = enum { global, constant };

pub const UnnamedAddr = enum(u2) {
    default = 0,
    unnamed_addr = 1,
    local_unnamed_addr = 2,

    pub fn format(
        self: UnnamedAddr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tag_name(self)});
    }
};

pub const AddrSpace = enum(u24) {
    default,
    _,

    // See llvm/lib/Target/X86/X86.h
    pub const x86 = struct {
        pub const gs: AddrSpace = @enumFromInt(256);
        pub const fs: AddrSpace = @enumFromInt(257);
        pub const ss: AddrSpace = @enumFromInt(258);

        pub const ptr32_sptr: AddrSpace = @enumFromInt(270);
        pub const ptr32_uptr: AddrSpace = @enumFromInt(271);
        pub const ptr64: AddrSpace = @enumFromInt(272);
    };
    pub const x86_64 = x86;

    // See llvm/lib/Target/AVR/AVR.h
    pub const avr = struct {
        pub const data: AddrSpace = @enumFromInt(0);
        pub const program: AddrSpace = @enumFromInt(1);
        pub const program1: AddrSpace = @enumFromInt(2);
        pub const program2: AddrSpace = @enumFromInt(3);
        pub const program3: AddrSpace = @enumFromInt(4);
        pub const program4: AddrSpace = @enumFromInt(5);
        pub const program5: AddrSpace = @enumFromInt(6);
    };

    // See llvm/lib/Target/NVPTX/NVPTX.h
    pub const nvptx = struct {
        pub const generic: AddrSpace = @enumFromInt(0);
        pub const global: AddrSpace = @enumFromInt(1);
        pub const constant: AddrSpace = @enumFromInt(2);
        pub const shared: AddrSpace = @enumFromInt(3);
        pub const param: AddrSpace = @enumFromInt(4);
        pub const local: AddrSpace = @enumFromInt(5);
    };

    // See llvm/lib/Target/AMDGPU/AMDGPU.h
    pub const amdgpu = struct {
        pub const flat: AddrSpace = @enumFromInt(0);
        pub const global: AddrSpace = @enumFromInt(1);
        pub const region: AddrSpace = @enumFromInt(2);
        pub const local: AddrSpace = @enumFromInt(3);
        pub const constant: AddrSpace = @enumFromInt(4);
        pub const private: AddrSpace = @enumFromInt(5);
        pub const constant_32bit: AddrSpace = @enumFromInt(6);
        pub const buffer_fat_pointer: AddrSpace = @enumFromInt(7);
        pub const buffer_resource: AddrSpace = @enumFromInt(8);
        pub const param_d: AddrSpace = @enumFromInt(6);
        pub const param_i: AddrSpace = @enumFromInt(7);
        pub const constant_buffer_0: AddrSpace = @enumFromInt(8);
        pub const constant_buffer_1: AddrSpace = @enumFromInt(9);
        pub const constant_buffer_2: AddrSpace = @enumFromInt(10);
        pub const constant_buffer_3: AddrSpace = @enumFromInt(11);
        pub const constant_buffer_4: AddrSpace = @enumFromInt(12);
        pub const constant_buffer_5: AddrSpace = @enumFromInt(13);
        pub const constant_buffer_6: AddrSpace = @enumFromInt(14);
        pub const constant_buffer_7: AddrSpace = @enumFromInt(15);
        pub const constant_buffer_8: AddrSpace = @enumFromInt(16);
        pub const constant_buffer_9: AddrSpace = @enumFromInt(17);
        pub const constant_buffer_10: AddrSpace = @enumFromInt(18);
        pub const constant_buffer_11: AddrSpace = @enumFromInt(19);
        pub const constant_buffer_12: AddrSpace = @enumFromInt(20);
        pub const constant_buffer_13: AddrSpace = @enumFromInt(21);
        pub const constant_buffer_14: AddrSpace = @enumFromInt(22);
        pub const constant_buffer_15: AddrSpace = @enumFromInt(23);
    };

    // See llvm/include/llvm/CodeGen/WasmAddressSpaces.h
    pub const wasm = struct {
        pub const variable: AddrSpace = @enumFromInt(1);
        pub const externref: AddrSpace = @enumFromInt(10);
        pub const funcref: AddrSpace = @enumFromInt(20);
    };

    pub fn format(
        self: AddrSpace,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print("{s}addrspace({d})", .{ prefix, @int_from_enum(self) });
    }
};

pub const ExternallyInitialized = enum {
    default,
    externally_initialized,

    pub fn format(
        self: ExternallyInitialized,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .default) return;
        try writer.write_byte(' ');
        try writer.write_all(@tag_name(self));
    }
};

pub const Alignment = enum(u6) {
    default = std.math.max_int(u6),
    _,

    pub fn from_byte_units(bytes: u64) Alignment {
        if (bytes == 0) return .default;
        assert(std.math.is_power_of_two(bytes));
        assert(bytes <= 1 << 32);
        return @enumFromInt(@ctz(bytes));
    }

    pub fn to_byte_units(self: Alignment) ?u64 {
        return if (self == .default) null else @as(u64, 1) << @int_from_enum(self);
    }

    pub fn to_llvm(self: Alignment) u6 {
        return if (self == .default) 0 else (@int_from_enum(self) + 1);
    }

    pub fn format(
        self: Alignment,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.print("{s}align {d}", .{ prefix, self.to_byte_units() orelse return });
    }
};

pub const CallConv = enum(u10) {
    ccc,

    fastcc = 8,
    coldcc,
    ghccc,

    webkit_jscc = 12,
    anyregcc,
    preserve_mostcc,
    preserve_allcc,
    swiftcc,
    cxx_fast_tlscc,
    tailcc,
    cfguard_checkcc,
    swifttailcc,

    x86_stdcallcc = 64,
    x86_fastcallcc,
    arm_apcscc,
    arm_aapcscc,
    arm_aapcs_vfpcc,
    msp430_intrcc,
    x86_thiscallcc,
    ptx_kernel,
    ptx_device,

    spir_func = 75,
    spir_kernel,
    intel_ocl_bicc,
    x86_64_sysvcc,
    win64cc,
    x86_vectorcallcc,
    hhvmcc,
    hhvm_ccc,
    x86_intrcc,
    avr_intrcc,
    avr_signalcc,

    amdgpu_vs = 87,
    amdgpu_gs,
    amdgpu_ps,
    amdgpu_cs,
    amdgpu_kernel,
    x86_regcallcc,
    amdgpu_hs,

    amdgpu_ls = 95,
    amdgpu_es,
    aarch64_vector_pcs,
    aarch64_sve_vector_pcs,

    amdgpu_gfx = 100,

    aarch64_sme_preservemost_from_x0 = 102,
    aarch64_sme_preservemost_from_x2,

    _,

    pub const default = CallConv.ccc;

    pub fn format(
        self: CallConv,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (self) {
            default => {},
            .fastcc,
            .coldcc,
            .ghccc,
            .webkit_jscc,
            .anyregcc,
            .preserve_mostcc,
            .preserve_allcc,
            .swiftcc,
            .cxx_fast_tlscc,
            .tailcc,
            .cfguard_checkcc,
            .swifttailcc,
            .x86_stdcallcc,
            .x86_fastcallcc,
            .arm_apcscc,
            .arm_aapcscc,
            .arm_aapcs_vfpcc,
            .msp430_intrcc,
            .x86_thiscallcc,
            .ptx_kernel,
            .ptx_device,
            .spir_func,
            .spir_kernel,
            .intel_ocl_bicc,
            .x86_64_sysvcc,
            .win64cc,
            .x86_vectorcallcc,
            .hhvmcc,
            .hhvm_ccc,
            .x86_intrcc,
            .avr_intrcc,
            .avr_signalcc,
            .amdgpu_vs,
            .amdgpu_gs,
            .amdgpu_ps,
            .amdgpu_cs,
            .amdgpu_kernel,
            .x86_regcallcc,
            .amdgpu_hs,
            .amdgpu_ls,
            .amdgpu_es,
            .aarch64_vector_pcs,
            .aarch64_sve_vector_pcs,
            .amdgpu_gfx,
            .aarch64_sme_preservemost_from_x0,
            .aarch64_sme_preservemost_from_x2,
            => try writer.print(" {s}", .{@tag_name(self)}),
            _ => try writer.print(" cc{d}", .{@int_from_enum(self)}),
        }
    }
};

pub const StrtabString = enum(u32) {
    none = std.math.max_int(u31),
    empty,
    _,

    pub fn is_anon(self: StrtabString) bool {
        assert(self != .none);
        return self.to_index() == null;
    }

    pub fn slice(self: StrtabString, builder: *const Builder) ?[]const u8 {
        const index = self.to_index() orelse return null;
        const start = builder.strtab_string_indices.items[index];
        const end = builder.strtab_string_indices.items[index + 1];
        return builder.strtab_string_bytes.items[start..end];
    }

    const FormatData = struct {
        string: StrtabString,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.index_of_none(u8, fmt_str, "\"r")) |_|
            @compile_error("invalid format string: '" ++ fmt_str ++ "'");
        assert(data.string != .none);
        const string_slice = data.string.slice(data.builder) orelse
            return writer.print("{d}", .{@int_from_enum(data.string)});
        if (comptime std.mem.index_of_scalar(u8, fmt_str, 'r')) |_|
            return writer.write_all(string_slice);
        try print_escaped_string(
            string_slice,
            if (comptime std.mem.index_of_scalar(u8, fmt_str, '"')) |_|
                .always_quote
            else
                .quote_unless_valid_identifier,
            writer,
        );
    }
    pub fn fmt(self: StrtabString, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .string = self, .builder = builder } };
    }

    fn from_index(index: ?usize) StrtabString {
        return @enumFromInt(@as(u32, @int_cast((index orelse return .none) +
            @int_from_enum(StrtabString.empty))));
    }

    fn to_index(self: StrtabString) ?usize {
        return std.math.sub(u32, @int_from_enum(self), @int_from_enum(StrtabString.empty)) catch null;
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            return std.mem.eql(u8, lhs_key, StrtabString.from_index(rhs_index).slice(ctx.builder).?);
        }
    };
};

pub fn strtab_string(self: *Builder, bytes: []const u8) Allocator.Error!StrtabString {
    try self.strtab_string_bytes.ensure_unused_capacity(self.gpa, bytes.len);
    try self.strtab_string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.strtab_string_map.ensure_unused_capacity(self.gpa, 1);

    const gop = self.strtab_string_map.get_or_put_assume_capacity_adapted(bytes, StrtabString.Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.strtab_string_bytes.append_slice_assume_capacity(bytes);
        self.strtab_string_indices.append_assume_capacity(@int_cast(self.strtab_string_bytes.items.len));
    }
    return StrtabString.from_index(gop.index);
}

pub fn strtab_string_if_exists(self: *const Builder, bytes: []const u8) ?StrtabString {
    return StrtabString.from_index(
        self.strtab_string_map.get_index_adapted(bytes, StrtabString.Adapter{ .builder = self }) orelse return null,
    );
}

pub fn strtab_string_fmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!StrtabString {
    try self.strtab_string_map.ensure_unused_capacity(self.gpa, 1);
    try self.strtab_string_bytes.ensure_unused_capacity(self.gpa, @int_cast(std.fmt.count(fmt_str, fmt_args)));
    try self.strtab_string_indices.ensure_unused_capacity(self.gpa, 1);
    return self.strtab_string_fmt_assume_capacity(fmt_str, fmt_args);
}

pub fn strtab_string_fmt_assume_capacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) StrtabString {
    self.strtab_string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailing_strtab_string_assume_capacity();
}

pub fn trailing_strtab_string(self: *Builder) Allocator.Error!StrtabString {
    try self.strtab_string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.strtab_string_map.ensure_unused_capacity(self.gpa, 1);
    return self.trailing_strtab_string_assume_capacity();
}

pub fn trailing_strtab_string_assume_capacity(self: *Builder) StrtabString {
    const start = self.strtab_string_indices.get_last();
    const bytes: []const u8 = self.strtab_string_bytes.items[start..];
    const gop = self.strtab_string_map.get_or_put_assume_capacity_adapted(bytes, StrtabString.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.strtab_string_bytes.shrink_retaining_capacity(start);
    } else {
        self.strtab_string_indices.append_assume_capacity(@int_cast(self.strtab_string_bytes.items.len));
    }
    return StrtabString.from_index(gop.index);
}

pub const Global = struct {
    linkage: Linkage = .external,
    preemption: Preemption = .dso_preemptable,
    visibility: Visibility = .default,
    dll_storage_class: DllStorageClass = .default,
    unnamed_addr: UnnamedAddr = .default,
    addr_space: AddrSpace = .default,
    externally_initialized: ExternallyInitialized = .default,
    type: Type,
    partition: String = .none,
    dbg: Metadata = .none,
    kind: union(enum) {
        alias: Alias.Index,
        variable: Variable.Index,
        function: Function.Index,
        replaced: Global.Index,
    },

    pub const Index = enum(u32) {
        none = std.math.max_int(u32),
        _,

        pub fn unwrap(self: Index, builder: *const Builder) Index {
            var cur = self;
            while (true) {
                const replacement = cur.get_replacement(builder);
                if (replacement == .none) return cur;
                cur = replacement;
            }
        }

        pub fn eql(self: Index, other: Index, builder: *const Builder) bool {
            return self.unwrap(builder) == other.unwrap(builder);
        }

        pub fn ptr(self: Index, builder: *Builder) *Global {
            return &builder.globals.values()[@int_from_enum(self.unwrap(builder))];
        }

        pub fn ptr_const(self: Index, builder: *const Builder) *const Global {
            return &builder.globals.values()[@int_from_enum(self.unwrap(builder))];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return builder.globals.keys()[@int_from_enum(self.unwrap(builder))];
        }

        pub fn strtab(self: Index, builder: *const Builder) struct {
            offset: u32,
            size: u32,
        } {
            const name_index = self.name(builder).to_index() orelse return .{
                .offset = 0,
                .size = 0,
            };

            return .{
                .offset = builder.strtab_string_indices.items[name_index],
                .size = builder.strtab_string_indices.items[name_index + 1] -
                    builder.strtab_string_indices.items[name_index],
            };
        }

        pub fn type_of(self: Index, builder: *const Builder) Type {
            return self.ptr_const(builder).type;
        }

        pub fn to_const(self: Index) Constant {
            return @enumFromInt(@int_from_enum(Constant.first_global) + @int_from_enum(self));
        }

        pub fn set_linkage(self: Index, linkage: Linkage, builder: *Builder) void {
            self.ptr(builder).linkage = linkage;
            self.update_dso_local(builder);
        }

        pub fn set_visibility(self: Index, visibility: Visibility, builder: *Builder) void {
            self.ptr(builder).visibility = visibility;
            self.update_dso_local(builder);
        }

        pub fn set_dll_storage_class(self: Index, class: DllStorageClass, builder: *Builder) void {
            self.ptr(builder).dll_storage_class = class;
        }

        pub fn set_unnamed_addr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            self.ptr(builder).unnamed_addr = unnamed_addr;
        }

        pub fn set_debug_metadata(self: Index, dbg: Metadata, builder: *Builder) void {
            self.ptr(builder).dbg = dbg;
        }

        const FormatData = struct {
            global: Index,
            builder: *const Builder,
        };
        fn format(
            data: FormatData,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            try writer.print("@{}", .{
                data.global.unwrap(data.builder).name(data.builder).fmt(data.builder),
            });
        }
        pub fn fmt(self: Index, builder: *const Builder) std.fmt.Formatter(format) {
            return .{ .data = .{ .global = self, .builder = builder } };
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            try builder.ensure_unused_global_capacity(new_name);
            self.rename_assume_capacity(new_name, builder);
        }

        pub fn take_name(self: Index, other: Index, builder: *Builder) Allocator.Error!void {
            try builder.ensure_unused_global_capacity(.empty);
            self.take_name_assume_capacity(other, builder);
        }

        pub fn replace(self: Index, other: Index, builder: *Builder) Allocator.Error!void {
            try builder.ensure_unused_global_capacity(.empty);
            self.replace_assume_capacity(other, builder);
        }

        pub fn delete(self: Index, builder: *Builder) void {
            self.ptr(builder).kind = .{ .replaced = .none };
        }

        fn update_dso_local(self: Index, builder: *Builder) void {
            const self_ptr = self.ptr(builder);
            switch (self_ptr.linkage) {
                .private, .internal => {
                    self_ptr.visibility = .default;
                    self_ptr.dll_storage_class = .default;
                    self_ptr.preemption = .implicit_dso_local;
                },
                .extern_weak => if (self_ptr.preemption == .implicit_dso_local) {
                    self_ptr.preemption = .dso_local;
                },
                else => switch (self_ptr.visibility) {
                    .default => if (self_ptr.preemption == .implicit_dso_local) {
                        self_ptr.preemption = .dso_local;
                    },
                    else => self_ptr.preemption = .implicit_dso_local,
                },
            }
        }

        fn rename_assume_capacity(self: Index, new_name: StrtabString, builder: *Builder) void {
            const old_name = self.name(builder);
            if (new_name == old_name) return;
            const index = @int_from_enum(self.unwrap(builder));
            _ = builder.add_global_assume_capacity(new_name, builder.globals.values()[index]);
            builder.globals.swap_remove_at(index);
            if (!old_name.is_anon()) return;
            builder.next_unnamed_global = @enumFromInt(@int_from_enum(builder.next_unnamed_global) - 1);
            if (builder.next_unnamed_global == old_name) return;
            builder.get_global(builder.next_unnamed_global).?.rename_assume_capacity(old_name, builder);
        }

        fn take_name_assume_capacity(self: Index, other: Index, builder: *Builder) void {
            const other_name = other.name(builder);
            other.rename_assume_capacity(.empty, builder);
            self.rename_assume_capacity(other_name, builder);
        }

        fn replace_assume_capacity(self: Index, other: Index, builder: *Builder) void {
            if (self.eql(other, builder)) return;
            builder.next_replaced_global = @enumFromInt(@int_from_enum(builder.next_replaced_global) - 1);
            self.rename_assume_capacity(builder.next_replaced_global, builder);
            self.ptr(builder).kind = .{ .replaced = other.unwrap(builder) };
        }

        fn get_replacement(self: Index, builder: *const Builder) Index {
            return switch (builder.globals.values()[@int_from_enum(self)].kind) {
                .replaced => |replacement| replacement,
                else => .none,
            };
        }
    };
};

pub const Alias = struct {
    global: Global.Index,
    thread_local: ThreadLocal = .default,
    aliasee: Constant = .no_init,

    pub const Index = enum(u32) {
        none = std.math.max_int(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Alias {
            return &builder.aliases.items[@int_from_enum(self)];
        }

        pub fn ptr_const(self: Index, builder: *const Builder) *const Alias {
            return &builder.aliases.items[@int_from_enum(self)];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return self.ptr_const(builder).global.name(builder);
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            return self.ptr_const(builder).global.rename(new_name, builder);
        }

        pub fn type_of(self: Index, builder: *const Builder) Type {
            return self.ptr_const(builder).global.type_of(builder);
        }

        pub fn to_const(self: Index, builder: *const Builder) Constant {
            return self.ptr_const(builder).global.to_const();
        }

        pub fn to_value(self: Index, builder: *const Builder) Value {
            return self.to_const(builder).to_value();
        }

        pub fn get_aliasee(self: Index, builder: *const Builder) Global.Index {
            const aliasee = self.ptr_const(builder).aliasee.get_base(builder);
            assert(aliasee != .none);
            return aliasee;
        }

        pub fn set_aliasee(self: Index, aliasee: Constant, builder: *Builder) void {
            self.ptr(builder).aliasee = aliasee;
        }
    };
};

pub const Variable = struct {
    global: Global.Index,
    thread_local: ThreadLocal = .default,
    mutability: Mutability = .global,
    init: Constant = .no_init,
    section: String = .none,
    alignment: Alignment = .default,

    pub const Index = enum(u32) {
        none = std.math.max_int(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Variable {
            return &builder.variables.items[@int_from_enum(self)];
        }

        pub fn ptr_const(self: Index, builder: *const Builder) *const Variable {
            return &builder.variables.items[@int_from_enum(self)];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return self.ptr_const(builder).global.name(builder);
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            return self.ptr_const(builder).global.rename(new_name, builder);
        }

        pub fn type_of(self: Index, builder: *const Builder) Type {
            return self.ptr_const(builder).global.type_of(builder);
        }

        pub fn to_const(self: Index, builder: *const Builder) Constant {
            return self.ptr_const(builder).global.to_const();
        }

        pub fn to_value(self: Index, builder: *const Builder) Value {
            return self.to_const(builder).to_value();
        }

        pub fn set_linkage(self: Index, linkage: Linkage, builder: *Builder) void {
            return self.ptr_const(builder).global.set_linkage(linkage, builder);
        }

        pub fn set_unnamed_addr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            return self.ptr_const(builder).global.set_unnamed_addr(unnamed_addr, builder);
        }

        pub fn set_thread_local(self: Index, thread_local: ThreadLocal, builder: *Builder) void {
            self.ptr(builder).thread_local = thread_local;
        }

        pub fn set_mutability(self: Index, mutability: Mutability, builder: *Builder) void {
            self.ptr(builder).mutability = mutability;
        }

        pub fn set_initializer(
            self: Index,
            initializer: Constant,
            builder: *Builder,
        ) Allocator.Error!void {
            if (initializer != .no_init) {
                const variable = self.ptr_const(builder);
                const global = variable.global.ptr(builder);
                const initializer_type = initializer.type_of(builder);
                global.type = initializer_type;
            }
            self.ptr(builder).init = initializer;
        }

        pub fn set_section(self: Index, section: String, builder: *Builder) void {
            self.ptr(builder).section = section;
        }

        pub fn set_alignment(self: Index, alignment: Alignment, builder: *Builder) void {
            self.ptr(builder).alignment = alignment;
        }

        pub fn get_alignment(self: Index, builder: *Builder) Alignment {
            return self.ptr(builder).alignment;
        }

        pub fn set_global_variable_expression(self: Index, expression: Metadata, builder: *Builder) void {
            self.ptr_const(builder).global.set_debug_metadata(expression, builder);
        }
    };
};

pub const Intrinsic = enum {
    // Variable Argument Handling
    va_start,
    va_end,
    va_copy,

    // Code Generator
    returnaddress,
    addressofreturnaddress,
    sponentry,
    frameaddress,
    prefetch,
    @"thread.pointer",

    // Standard C/C++ Library
    abs,
    smax,
    smin,
    umax,
    umin,
    memcpy,
    @"memcpy.inline",
    memmove,
    memset,
    @"memset.inline",
    sqrt,
    powi,
    sin,
    cos,
    pow,
    exp,
    exp2,
    ldexp,
    frexp,
    log,
    log10,
    log2,
    fma,
    fabs,
    minnum,
    maxnum,
    minimum,
    maximum,
    copysign,
    floor,
    ceil,
    trunc,
    rint,
    nearbyint,
    round,
    roundeven,
    lround,
    llround,
    lrint,
    llrint,

    // Bit Manipulation
    bitreverse,
    bswap,
    ctpop,
    ctlz,
    cttz,
    fshl,
    fshr,

    // Arithmetic with Overflow
    @"sadd.with.overflow",
    @"uadd.with.overflow",
    @"ssub.with.overflow",
    @"usub.with.overflow",
    @"smul.with.overflow",
    @"umul.with.overflow",

    // Saturation Arithmetic
    @"sadd.sat",
    @"uadd.sat",
    @"ssub.sat",
    @"usub.sat",
    @"sshl.sat",
    @"ushl.sat",

    // Fixed Point Arithmetic
    @"smul.fix",
    @"umul.fix",
    @"smul.fix.sat",
    @"umul.fix.sat",
    @"sdiv.fix",
    @"udiv.fix",
    @"sdiv.fix.sat",
    @"udiv.fix.sat",

    // Specialised Arithmetic
    canonicalize,
    fmuladd,

    // Vector Reduction
    @"vector.reduce.add",
    @"vector.reduce.fadd",
    @"vector.reduce.mul",
    @"vector.reduce.fmul",
    @"vector.reduce.and",
    @"vector.reduce.or",
    @"vector.reduce.xor",
    @"vector.reduce.smax",
    @"vector.reduce.smin",
    @"vector.reduce.umax",
    @"vector.reduce.umin",
    @"vector.reduce.fmax",
    @"vector.reduce.fmin",
    @"vector.reduce.fmaximum",
    @"vector.reduce.fminimum",
    @"vector.insert",
    @"vector.extract",

    // Floating-Point Test
    @"is.fpclass",

    // General
    @"var.annotation",
    @"ptr.annotation",
    annotation,
    @"codeview.annotation",
    trap,
    debugtrap,
    ubsantrap,
    stackprotector,
    stackguard,
    objectsize,
    expect,
    @"expect.with.probability",
    assume,
    @"ssa.copy",
    @"type.test",
    @"type.checked.load",
    @"type.checked.load.relative",
    @"arithmetic.fence",
    donothing,
    @"load.relative",
    sideeffect,
    @"is.constant",
    ptrmask,
    @"threadlocal.address",
    vscale,

    // Debug
    @"dbg.declare",
    @"dbg.value",

    // AMDGPU
    @"amdgcn.workitem.id.x",
    @"amdgcn.workitem.id.y",
    @"amdgcn.workitem.id.z",
    @"amdgcn.workgroup.id.x",
    @"amdgcn.workgroup.id.y",
    @"amdgcn.workgroup.id.z",
    @"amdgcn.dispatch.ptr",

    // WebAssembly
    @"wasm.memory.size",
    @"wasm.memory.grow",

    const Signature = struct {
        ret_len: u8,
        params: []const Parameter,
        attrs: []const Attribute = &.{},

        const Parameter = struct {
            kind: Kind,
            attrs: []const Attribute = &.{},

            const Kind = union(enum) {
                type: Type,
                overloaded,
                matches: u8,
                matches_scalar: u8,
                matches_changed_scalar: struct {
                    index: u8,
                    scalar: Type,
                },
            };
        };
    };

    const signatures = std.enums.EnumArray(Intrinsic, Signature).init(.{
        .va_start = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .va_end = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .va_copy = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },

        .returnaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .addressofreturnaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .sponentry = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .frameaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .prefetch = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .readonly } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.readwrite) } },
        },
        .@"thread.pointer" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .abs = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .smax = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .smin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .umax = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .umin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .memcpy = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .readonly } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .@"memcpy.inline" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .readonly } },
                .{ .kind = .overloaded, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .memmove = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .readonly } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .memset = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .{ .type = .i8 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .write } } },
        },
        .@"memset.inline" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .{ .type = .i8 } },
                .{ .kind = .overloaded, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .write } } },
        },
        .sqrt = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .powi = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .sin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .cos = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .pow = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .exp = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .exp2 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ldexp = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .frexp = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log10 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log2 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fma = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fabs = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .minnum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .maxnum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .minimum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .maximum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .copysign = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .floor = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ceil = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .trunc = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .rint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .nearbyint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .round = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .roundeven = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .lround = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .llround = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .lrint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .llrint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .bitreverse = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .bswap = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ctpop = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ctlz = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .cttz = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fshl = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fshr = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"sadd.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"uadd.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ssub.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"usub.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"smul.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"sadd.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"uadd.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ssub.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"usub.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sshl.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ushl.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"smul.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"smul.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sdiv.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"udiv.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sdiv.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"udiv.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .canonicalize = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fmuladd = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"vector.reduce.add" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fadd" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.mul" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmul" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.and" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.or" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.xor" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.smax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.smin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.umax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.umin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmaximum" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fminimum" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.insert" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i64 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.extract" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i64 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"is.fpclass" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 1, .scalar = .i1 } } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"var.annotation" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 1 } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 1 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"ptr.annotation" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 2 } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 2 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .annotation = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 2 } },
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"codeview.annotation" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .noduplicate, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .trap = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .cold, .noreturn, .nounwind, .{ .memory = .{ .inaccessiblemem = .write } } },
        },
        .debugtrap = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{.nounwind},
        },
        .ubsantrap = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .i8 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .cold, .noreturn, .nounwind },
        },
        .stackprotector = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .stackguard = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .objectsize = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .expect = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"expect.with.probability" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .double }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .assume = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.noundef} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .write } } },
        },
        .@"ssa.copy" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 }, .attrs = &.{.returned} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.test" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.checked.load" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"type.checked.load.relative" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"arithmetic.fence" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .donothing = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"load.relative" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .argmem = .read } } },
        },
        .sideeffect = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"is.constant" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .convergent, .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ptrmask = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"threadlocal.address" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{.nonnull} },
                .{ .kind = .{ .matches = 0 }, .attrs = &.{.nonnull} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .vscale = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"dbg.declare" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"dbg.value" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"amdgcn.workitem.id.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workitem.id.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workitem.id.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.x" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.y" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.workgroup.id.z" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"amdgcn.dispatch.ptr" = .{
            .ret_len = 1,
            .params = &.{
                .{
                    .kind = .{ .type = Type.ptr_amdgpu_constant },
                    .attrs = &.{.{ .@"align" = Builder.Alignment.from_byte_units(4) }},
                },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"wasm.memory.size" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"wasm.memory.grow" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
    });
};

pub const Function = struct {
    global: Global.Index,
    call_conv: CallConv = CallConv.default,
    attributes: FunctionAttributes = .none,
    section: String = .none,
    alignment: Alignment = .default,
    blocks: []const Block = &.{},
    instructions: std.MultiArrayList(Instruction) = .{},
    names: [*]const String = &[0]String{},
    value_indices: [*]const u32 = &[0]u32{},
    strip: bool,
    debug_locations: std.AutoHashMapUnmanaged(Instruction.Index, DebugLocation) = .{},
    debug_values: []const Instruction.Index = &.{},
    extra: []const u32 = &.{},

    pub const Index = enum(u32) {
        none = std.math.max_int(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Function {
            return &builder.functions.items[@int_from_enum(self)];
        }

        pub fn ptr_const(self: Index, builder: *const Builder) *const Function {
            return &builder.functions.items[@int_from_enum(self)];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return self.ptr_const(builder).global.name(builder);
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            return self.ptr_const(builder).global.rename(new_name, builder);
        }

        pub fn type_of(self: Index, builder: *const Builder) Type {
            return self.ptr_const(builder).global.type_of(builder);
        }

        pub fn to_const(self: Index, builder: *const Builder) Constant {
            return self.ptr_const(builder).global.to_const();
        }

        pub fn to_value(self: Index, builder: *const Builder) Value {
            return self.to_const(builder).to_value();
        }

        pub fn set_linkage(self: Index, linkage: Linkage, builder: *Builder) void {
            return self.ptr_const(builder).global.set_linkage(linkage, builder);
        }

        pub fn set_unnamed_addr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            return self.ptr_const(builder).global.set_unnamed_addr(unnamed_addr, builder);
        }

        pub fn set_call_conv(self: Index, call_conv: CallConv, builder: *Builder) void {
            self.ptr(builder).call_conv = call_conv;
        }

        pub fn set_attributes(
            self: Index,
            new_function_attributes: FunctionAttributes,
            builder: *Builder,
        ) void {
            self.ptr(builder).attributes = new_function_attributes;
        }

        pub fn set_section(self: Index, section: String, builder: *Builder) void {
            self.ptr(builder).section = section;
        }

        pub fn set_alignment(self: Index, alignment: Alignment, builder: *Builder) void {
            self.ptr(builder).alignment = alignment;
        }

        pub fn set_subprogram(self: Index, subprogram: Metadata, builder: *Builder) void {
            self.ptr_const(builder).global.set_debug_metadata(subprogram, builder);
        }
    };

    pub const Block = struct {
        instruction: Instruction.Index,

        pub const Index = WipFunction.Block.Index;
    };

    pub const Instruction = struct {
        tag: Tag,
        data: u32,

        pub const Tag = enum(u8) {
            add,
            @"add nsw",
            @"add nuw",
            @"add nuw nsw",
            addrspacecast,
            alloca,
            @"alloca inalloca",
            @"and",
            arg,
            ashr,
            @"ashr exact",
            atomicrmw,
            bitcast,
            block,
            br,
            br_cond,
            call,
            @"call fast",
            cmpxchg,
            @"cmpxchg weak",
            extractelement,
            extractvalue,
            fadd,
            @"fadd fast",
            @"fcmp false",
            @"fcmp fast false",
            @"fcmp fast oeq",
            @"fcmp fast oge",
            @"fcmp fast ogt",
            @"fcmp fast ole",
            @"fcmp fast olt",
            @"fcmp fast one",
            @"fcmp fast ord",
            @"fcmp fast true",
            @"fcmp fast ueq",
            @"fcmp fast uge",
            @"fcmp fast ugt",
            @"fcmp fast ule",
            @"fcmp fast ult",
            @"fcmp fast une",
            @"fcmp fast uno",
            @"fcmp oeq",
            @"fcmp oge",
            @"fcmp ogt",
            @"fcmp ole",
            @"fcmp olt",
            @"fcmp one",
            @"fcmp ord",
            @"fcmp true",
            @"fcmp ueq",
            @"fcmp uge",
            @"fcmp ugt",
            @"fcmp ule",
            @"fcmp ult",
            @"fcmp une",
            @"fcmp uno",
            fdiv,
            @"fdiv fast",
            fence,
            fmul,
            @"fmul fast",
            fneg,
            @"fneg fast",
            fpext,
            fptosi,
            fptoui,
            fptrunc,
            frem,
            @"frem fast",
            fsub,
            @"fsub fast",
            getelementptr,
            @"getelementptr inbounds",
            @"icmp eq",
            @"icmp ne",
            @"icmp sge",
            @"icmp sgt",
            @"icmp sle",
            @"icmp slt",
            @"icmp uge",
            @"icmp ugt",
            @"icmp ule",
            @"icmp ult",
            insertelement,
            insertvalue,
            inttoptr,
            load,
            @"load atomic",
            lshr,
            @"lshr exact",
            mul,
            @"mul nsw",
            @"mul nuw",
            @"mul nuw nsw",
            @"musttail call",
            @"musttail call fast",
            @"notail call",
            @"notail call fast",
            @"or",
            phi,
            @"phi fast",
            ptrtoint,
            ret,
            @"ret void",
            sdiv,
            @"sdiv exact",
            select,
            @"select fast",
            sext,
            shl,
            @"shl nsw",
            @"shl nuw",
            @"shl nuw nsw",
            shufflevector,
            sitofp,
            srem,
            store,
            @"store atomic",
            sub,
            @"sub nsw",
            @"sub nuw",
            @"sub nuw nsw",
            @"switch",
            @"tail call",
            @"tail call fast",
            trunc,
            udiv,
            @"udiv exact",
            urem,
            uitofp,
            @"unreachable",
            va_arg,
            xor,
            zext,

            pub fn to_binary_opcode(self: Tag) BinaryOpcode {
                return switch (self) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .fadd,
                    .@"fadd fast",
                    => .add,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .fsub,
                    .@"fsub fast",
                    => .sub,
                    .sdiv,
                    .@"sdiv exact",
                    .fdiv,
                    .@"fdiv fast",
                    => .sdiv,
                    .fmul,
                    .@"fmul fast",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    => .mul,
                    .srem,
                    .frem,
                    .@"frem fast",
                    => .srem,
                    .udiv,
                    .@"udiv exact",
                    => .udiv,
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    => .shl,
                    .lshr,
                    .@"lshr exact",
                    => .lshr,
                    .ashr,
                    .@"ashr exact",
                    => .ashr,
                    .@"and" => .@"and",
                    .@"or" => .@"or",
                    .xor => .xor,
                    .urem => .urem,
                    else => unreachable,
                };
            }

            pub fn to_cast_opcode(self: Tag) CastOpcode {
                return switch (self) {
                    .trunc => .trunc,
                    .zext => .zext,
                    .sext => .sext,
                    .fptoui => .fptoui,
                    .fptosi => .fptosi,
                    .uitofp => .uitofp,
                    .sitofp => .sitofp,
                    .fptrunc => .fptrunc,
                    .fpext => .fpext,
                    .ptrtoint => .ptrtoint,
                    .inttoptr => .inttoptr,
                    .bitcast => .bitcast,
                    .addrspacecast => .addrspacecast,
                    else => unreachable,
                };
            }

            pub fn to_cmp_predicate(self: Tag) CmpPredicate {
                return switch (self) {
                    .@"fcmp false",
                    .@"fcmp fast false",
                    => .fcmp_false,
                    .@"fcmp oeq",
                    .@"fcmp fast oeq",
                    => .fcmp_oeq,
                    .@"fcmp oge",
                    .@"fcmp fast oge",
                    => .fcmp_oge,
                    .@"fcmp ogt",
                    .@"fcmp fast ogt",
                    => .fcmp_ogt,
                    .@"fcmp ole",
                    .@"fcmp fast ole",
                    => .fcmp_ole,
                    .@"fcmp olt",
                    .@"fcmp fast olt",
                    => .fcmp_olt,
                    .@"fcmp one",
                    .@"fcmp fast one",
                    => .fcmp_one,
                    .@"fcmp ord",
                    .@"fcmp fast ord",
                    => .fcmp_ord,
                    .@"fcmp true",
                    .@"fcmp fast true",
                    => .fcmp_true,
                    .@"fcmp ueq",
                    .@"fcmp fast ueq",
                    => .fcmp_ueq,
                    .@"fcmp uge",
                    .@"fcmp fast uge",
                    => .fcmp_uge,
                    .@"fcmp ugt",
                    .@"fcmp fast ugt",
                    => .fcmp_ugt,
                    .@"fcmp ule",
                    .@"fcmp fast ule",
                    => .fcmp_ule,
                    .@"fcmp ult",
                    .@"fcmp fast ult",
                    => .fcmp_ult,
                    .@"fcmp une",
                    .@"fcmp fast une",
                    => .fcmp_une,
                    .@"fcmp uno",
                    .@"fcmp fast uno",
                    => .fcmp_uno,
                    .@"icmp eq" => .icmp_eq,
                    .@"icmp ne" => .icmp_ne,
                    .@"icmp sge" => .icmp_sge,
                    .@"icmp sgt" => .icmp_sgt,
                    .@"icmp sle" => .icmp_sle,
                    .@"icmp slt" => .icmp_slt,
                    .@"icmp uge" => .icmp_uge,
                    .@"icmp ugt" => .icmp_ugt,
                    .@"icmp ule" => .icmp_ule,
                    .@"icmp ult" => .icmp_ult,
                    else => unreachable,
                };
            }
        };

        pub const Index = enum(u32) {
            none = std.math.max_int(u31),
            _,

            pub fn name(self: Instruction.Index, function: *const Function) String {
                return function.names[@int_from_enum(self)];
            }

            pub fn value_index(self: Instruction.Index, function: *const Function) u32 {
                return function.value_indices[@int_from_enum(self)];
            }

            pub fn to_value(self: Instruction.Index) Value {
                return @enumFromInt(@int_from_enum(self));
            }

            pub fn is_terminator_wip(self: Instruction.Index, wip: *const WipFunction) bool {
                return switch (wip.instructions.items(.tag)[@int_from_enum(self)]) {
                    .br,
                    .br_cond,
                    .ret,
                    .@"ret void",
                    .@"switch",
                    .@"unreachable",
                    => true,
                    else => false,
                };
            }

            pub fn has_result_wip(self: Instruction.Index, wip: *const WipFunction) bool {
                return switch (wip.instructions.items(.tag)[@int_from_enum(self)]) {
                    .br,
                    .br_cond,
                    .fence,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    .block,
                    => false,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => self.type_of_wip(wip) != .void,
                    else => true,
                };
            }

            pub fn type_of_wip(self: Instruction.Index, wip: *const WipFunction) Type {
                const instruction = wip.instructions.get(@int_from_enum(self));
                return switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => wip.extra_data(Binary, instruction.data).lhs.type_of_wip(wip),
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => wip.extra_data(Cast, instruction.data).type,
                    .alloca,
                    .@"alloca inalloca",
                    => wip.builder.ptr_type_assume_capacity(
                        wip.extra_data(Alloca, instruction.data).info.addr_space,
                    ),
                    .arg => wip.function.type_of(wip.builder)
                        .function_parameters(wip.builder)[instruction.data],
                    .atomicrmw => wip.extra_data(AtomicRmw, instruction.data).val.type_of_wip(wip),
                    .block => .label,
                    .br,
                    .br_cond,
                    .fence,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    => .none,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => wip.extra_data(Call, instruction.data).ty.function_return(wip.builder),
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => wip.builder.struct_type_assume_capacity(.normal, &.{
                        wip.extra_data(CmpXchg, instruction.data).cmp.type_of_wip(wip),
                        .i1,
                    }),
                    .extractelement => wip.extra_data(ExtractElement, instruction.data)
                        .val.type_of_wip(wip).child_type(wip.builder),
                    .extractvalue => {
                        var extra = wip.extra_data_trail(ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, wip);
                        return extra.data.val.type_of_wip(wip).child_type_at(indices, wip.builder);
                    },
                    .@"fcmp false",
                    .@"fcmp fast false",
                    .@"fcmp fast oeq",
                    .@"fcmp fast oge",
                    .@"fcmp fast ogt",
                    .@"fcmp fast ole",
                    .@"fcmp fast olt",
                    .@"fcmp fast one",
                    .@"fcmp fast ord",
                    .@"fcmp fast true",
                    .@"fcmp fast ueq",
                    .@"fcmp fast uge",
                    .@"fcmp fast ugt",
                    .@"fcmp fast ule",
                    .@"fcmp fast ult",
                    .@"fcmp fast une",
                    .@"fcmp fast uno",
                    .@"fcmp oeq",
                    .@"fcmp oge",
                    .@"fcmp ogt",
                    .@"fcmp ole",
                    .@"fcmp olt",
                    .@"fcmp one",
                    .@"fcmp ord",
                    .@"fcmp true",
                    .@"fcmp ueq",
                    .@"fcmp uge",
                    .@"fcmp ugt",
                    .@"fcmp ule",
                    .@"fcmp ult",
                    .@"fcmp une",
                    .@"fcmp uno",
                    .@"icmp eq",
                    .@"icmp ne",
                    .@"icmp sge",
                    .@"icmp sgt",
                    .@"icmp sle",
                    .@"icmp slt",
                    .@"icmp uge",
                    .@"icmp ugt",
                    .@"icmp ule",
                    .@"icmp ult",
                    => wip.extra_data(Binary, instruction.data).lhs.type_of_wip(wip)
                        .change_scalar_assume_capacity(.i1, wip.builder),
                    .fneg,
                    .@"fneg fast",
                    => @as(Value, @enumFromInt(instruction.data)).type_of_wip(wip),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = wip.extra_data_trail(GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, wip);
                        const base_ty = extra.data.base.type_of_wip(wip);
                        if (!base_ty.is_vector(wip.builder)) for (indices) |index| {
                            const index_ty = index.type_of_wip(wip);
                            if (!index_ty.is_vector(wip.builder)) continue;
                            return index_ty.change_scalar_assume_capacity(base_ty, wip.builder);
                        };
                        return base_ty;
                    },
                    .insertelement => wip.extra_data(InsertElement, instruction.data).val.type_of_wip(wip),
                    .insertvalue => wip.extra_data(InsertValue, instruction.data).val.type_of_wip(wip),
                    .load,
                    .@"load atomic",
                    => wip.extra_data(Load, instruction.data).type,
                    .phi,
                    .@"phi fast",
                    => wip.extra_data(Phi, instruction.data).type,
                    .select,
                    .@"select fast",
                    => wip.extra_data(Select, instruction.data).lhs.type_of_wip(wip),
                    .shufflevector => {
                        const extra = wip.extra_data(ShuffleVector, instruction.data);
                        return extra.lhs.type_of_wip(wip).change_length_assume_capacity(
                            extra.mask.type_of_wip(wip).vector_len(wip.builder),
                            wip.builder,
                        );
                    },
                    .va_arg => wip.extra_data(VaArg, instruction.data).type,
                };
            }

            pub fn type_of(
                self: Instruction.Index,
                function_index: Function.Index,
                builder: *Builder,
            ) Type {
                const function = function_index.ptr_const(builder);
                const instruction = function.instructions.get(@int_from_enum(self));
                return switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => function.extra_data(Binary, instruction.data).lhs.type_of(function_index, builder),
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => function.extra_data(Cast, instruction.data).type,
                    .alloca,
                    .@"alloca inalloca",
                    => builder.ptr_type_assume_capacity(
                        function.extra_data(Alloca, instruction.data).info.addr_space,
                    ),
                    .arg => function.global.type_of(builder)
                        .function_parameters(builder)[instruction.data],
                    .atomicrmw => function.extra_data(AtomicRmw, instruction.data)
                        .val.type_of(function_index, builder),
                    .block => .label,
                    .br,
                    .br_cond,
                    .fence,
                    .ret,
                    .@"ret void",
                    .store,
                    .@"store atomic",
                    .@"switch",
                    .@"unreachable",
                    => .none,
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => function.extra_data(Call, instruction.data).ty.function_return(builder),
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => builder.struct_type_assume_capacity(.normal, &.{
                        function.extra_data(CmpXchg, instruction.data)
                            .cmp.type_of(function_index, builder),
                        .i1,
                    }),
                    .extractelement => function.extra_data(ExtractElement, instruction.data)
                        .val.type_of(function_index, builder).child_type(builder),
                    .extractvalue => {
                        var extra = function.extra_data_trail(ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, function);
                        return extra.data.val.type_of(function_index, builder)
                            .child_type_at(indices, builder);
                    },
                    .@"fcmp false",
                    .@"fcmp fast false",
                    .@"fcmp fast oeq",
                    .@"fcmp fast oge",
                    .@"fcmp fast ogt",
                    .@"fcmp fast ole",
                    .@"fcmp fast olt",
                    .@"fcmp fast one",
                    .@"fcmp fast ord",
                    .@"fcmp fast true",
                    .@"fcmp fast ueq",
                    .@"fcmp fast uge",
                    .@"fcmp fast ugt",
                    .@"fcmp fast ule",
                    .@"fcmp fast ult",
                    .@"fcmp fast une",
                    .@"fcmp fast uno",
                    .@"fcmp oeq",
                    .@"fcmp oge",
                    .@"fcmp ogt",
                    .@"fcmp ole",
                    .@"fcmp olt",
                    .@"fcmp one",
                    .@"fcmp ord",
                    .@"fcmp true",
                    .@"fcmp ueq",
                    .@"fcmp uge",
                    .@"fcmp ugt",
                    .@"fcmp ule",
                    .@"fcmp ult",
                    .@"fcmp une",
                    .@"fcmp uno",
                    .@"icmp eq",
                    .@"icmp ne",
                    .@"icmp sge",
                    .@"icmp sgt",
                    .@"icmp sle",
                    .@"icmp slt",
                    .@"icmp uge",
                    .@"icmp ugt",
                    .@"icmp ule",
                    .@"icmp ult",
                    => function.extra_data(Binary, instruction.data).lhs.type_of(function_index, builder)
                        .change_scalar_assume_capacity(.i1, builder),
                    .fneg,
                    .@"fneg fast",
                    => @as(Value, @enumFromInt(instruction.data)).type_of(function_index, builder),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = function.extra_data_trail(GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, function);
                        const base_ty = extra.data.base.type_of(function_index, builder);
                        if (!base_ty.is_vector(builder)) for (indices) |index| {
                            const index_ty = index.type_of(function_index, builder);
                            if (!index_ty.is_vector(builder)) continue;
                            return index_ty.change_scalar_assume_capacity(base_ty, builder);
                        };
                        return base_ty;
                    },
                    .insertelement => function.extra_data(InsertElement, instruction.data)
                        .val.type_of(function_index, builder),
                    .insertvalue => function.extra_data(InsertValue, instruction.data)
                        .val.type_of(function_index, builder),
                    .load,
                    .@"load atomic",
                    => function.extra_data(Load, instruction.data).type,
                    .phi,
                    .@"phi fast",
                    => function.extra_data(Phi, instruction.data).type,
                    .select,
                    .@"select fast",
                    => function.extra_data(Select, instruction.data).lhs.type_of(function_index, builder),
                    .shufflevector => {
                        const extra = function.extra_data(ShuffleVector, instruction.data);
                        return extra.lhs.type_of(function_index, builder).change_length_assume_capacity(
                            extra.mask.type_of(function_index, builder).vector_len(builder),
                            builder,
                        );
                    },
                    .va_arg => function.extra_data(VaArg, instruction.data).type,
                };
            }

            const FormatData = struct {
                instruction: Instruction.Index,
                function: Function.Index,
                builder: *Builder,
            };
            fn format(
                data: FormatData,
                comptime fmt_str: []const u8,
                _: std.fmt.FormatOptions,
                writer: anytype,
            ) @TypeOf(writer).Error!void {
                if (comptime std.mem.index_of_none(u8, fmt_str, ", %")) |_|
                    @compile_error("invalid format string: '" ++ fmt_str ++ "'");
                if (comptime std.mem.index_of_scalar(u8, fmt_str, ',') != null) {
                    if (data.instruction == .none) return;
                    try writer.write_byte(',');
                }
                if (comptime std.mem.index_of_scalar(u8, fmt_str, ' ') != null) {
                    if (data.instruction == .none) return;
                    try writer.write_byte(' ');
                }
                if (comptime std.mem.index_of_scalar(u8, fmt_str, '%') != null) try writer.print(
                    "{%} ",
                    .{data.instruction.type_of(data.function, data.builder).fmt(data.builder)},
                );
                assert(data.instruction != .none);
                try writer.print("%{}", .{
                    data.instruction.name(data.function.ptr_const(data.builder)).fmt(data.builder),
                });
            }
            pub fn fmt(
                self: Instruction.Index,
                function: Function.Index,
                builder: *Builder,
            ) std.fmt.Formatter(format) {
                return .{ .data = .{ .instruction = self, .function = function, .builder = builder } };
            }
        };

        pub const ExtraIndex = u32;

        pub const BrCond = struct {
            cond: Value,
            then: Block.Index,
            @"else": Block.Index,
        };

        pub const Switch = struct {
            val: Value,
            default: Block.Index,
            cases_len: u32,
            //case_vals: [cases_len]Constant,
            //case_blocks: [cases_len]Block.Index,
        };

        pub const Binary = struct {
            lhs: Value,
            rhs: Value,
        };

        pub const ExtractElement = struct {
            val: Value,
            index: Value,
        };

        pub const InsertElement = struct {
            val: Value,
            elem: Value,
            index: Value,
        };

        pub const ShuffleVector = struct {
            lhs: Value,
            rhs: Value,
            mask: Value,
        };

        pub const ExtractValue = struct {
            val: Value,
            indices_len: u32,
            //indices: [indices_len]u32,
        };

        pub const InsertValue = struct {
            val: Value,
            elem: Value,
            indices_len: u32,
            //indices: [indices_len]u32,
        };

        pub const Alloca = struct {
            type: Type,
            len: Value,
            info: Info,

            pub const Kind = enum { normal, inalloca };
            pub const Info = packed struct(u32) {
                alignment: Alignment,
                addr_space: AddrSpace,
                _: u2 = undefined,
            };
        };

        pub const Load = struct {
            info: MemoryAccessInfo,
            type: Type,
            ptr: Value,
        };

        pub const Store = struct {
            info: MemoryAccessInfo,
            val: Value,
            ptr: Value,
        };

        pub const CmpXchg = struct {
            info: MemoryAccessInfo,
            ptr: Value,
            cmp: Value,
            new: Value,

            pub const Kind = enum { strong, weak };
        };

        pub const AtomicRmw = struct {
            info: MemoryAccessInfo,
            ptr: Value,
            val: Value,

            pub const Operation = enum(u5) {
                xchg = 0,
                add = 1,
                sub = 2,
                @"and" = 3,
                nand = 4,
                @"or" = 5,
                xor = 6,
                max = 7,
                min = 8,
                umax = 9,
                umin = 10,
                fadd = 11,
                fsub = 12,
                fmax = 13,
                fmin = 14,
                none = std.math.max_int(u5),
            };
        };

        pub const GetElementPtr = struct {
            type: Type,
            base: Value,
            indices_len: u32,
            //indices: [indices_len]Value,

            pub const Kind = Constant.GetElementPtr.Kind;
        };

        pub const Cast = struct {
            val: Value,
            type: Type,

            pub const Signedness = Constant.Cast.Signedness;
        };

        pub const Phi = struct {
            type: Type,
            //incoming_vals: [block.incoming]Value,
            //incoming_blocks: [block.incoming]Block.Index,
        };

        pub const Select = struct {
            cond: Value,
            lhs: Value,
            rhs: Value,
        };

        pub const Call = struct {
            info: Info,
            attributes: FunctionAttributes,
            ty: Type,
            callee: Value,
            args_len: u32,
            //args: [args_len]Value,

            pub const Kind = enum {
                normal,
                fast,
                musttail,
                musttail_fast,
                notail,
                notail_fast,
                tail,
                tail_fast,
            };
            pub const Info = packed struct(u32) {
                call_conv: CallConv,
                _: u22 = undefined,
            };
        };

        pub const VaArg = struct {
            list: Value,
            type: Type,
        };
    };

    pub fn deinit(self: *Function, gpa: Allocator) void {
        gpa.free(self.extra);
        gpa.free(self.debug_values);
        self.debug_locations.deinit(gpa);
        gpa.free(self.value_indices[0..self.instructions.len]);
        gpa.free(self.names[0..self.instructions.len]);
        self.instructions.deinit(gpa);
        gpa.free(self.blocks);
        self.* = undefined;
    }

    pub fn arg(self: *const Function, index: u32) Value {
        const argument = self.instructions.get(index);
        assert(argument.tag == .arg);
        assert(argument.data == index);

        const argument_index: Instruction.Index = @enumFromInt(index);
        return argument_index.to_value();
    }

    const ExtraDataTrail = struct {
        index: Instruction.ExtraIndex,

        fn next_mut(self: *ExtraDataTrail, len: u32, comptime Item: type, function: *Function) []Item {
            const items: []Item = @ptr_cast(function.extra[self.index..][0..len]);
            self.index += @int_cast(len);
            return items;
        }

        fn next(
            self: *ExtraDataTrail,
            len: u32,
            comptime Item: type,
            function: *const Function,
        ) []const Item {
            const items: []const Item = @ptr_cast(function.extra[self.index..][0..len]);
            self.index += @int_cast(len);
            return items;
        }
    };

    fn extra_data_trail(
        self: *const Function,
        comptime T: type,
        index: Instruction.ExtraIndex,
    ) struct { data: T, trail: ExtraDataTrail } {
        var result: T = undefined;
        const fields = @typeInfo(T).Struct.fields;
        inline for (fields, self.extra[index..][0..fields.len]) |field, value|
            @field(result, field.name) = switch (field.type) {
                u32 => value,
                Alignment,
                AtomicOrdering,
                Block.Index,
                FunctionAttributes,
                Type,
                Value,
                => @enumFromInt(value),
                MemoryAccessInfo,
                Instruction.Alloca.Info,
                Instruction.Call.Info,
                => @bit_cast(value),
                else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
            };
        return .{
            .data = result,
            .trail = .{ .index = index + @as(Type.Item.ExtraIndex, @int_cast(fields.len)) },
        };
    }

    fn extra_data(self: *const Function, comptime T: type, index: Instruction.ExtraIndex) T {
        return self.extra_data_trail(T, index).data;
    }
};

pub const DebugLocation = union(enum) {
    no_location: void,
    location: Location,

    pub const Location = struct {
        line: u32,
        column: u32,
        scope: Builder.Metadata,
        inlined_at: Builder.Metadata,
    };

    pub fn to_metadata(self: DebugLocation, builder: *Builder) Allocator.Error!Metadata {
        return switch (self) {
            .no_location => .none,
            .location => |location| try builder.debug_location(
                location.line,
                location.column,
                location.scope,
                location.inlined_at,
            ),
        };
    }
};

pub const WipFunction = struct {
    builder: *Builder,
    function: Function.Index,
    prev_debug_location: DebugLocation,
    debug_location: DebugLocation,
    cursor: Cursor,
    blocks: std.ArrayListUnmanaged(Block),
    instructions: std.MultiArrayList(Instruction),
    names: std.ArrayListUnmanaged(String),
    strip: bool,
    debug_locations: std.AutoArrayHashMapUnmanaged(Instruction.Index, DebugLocation),
    debug_values: std.AutoArrayHashMapUnmanaged(Instruction.Index, void),
    extra: std.ArrayListUnmanaged(u32),

    pub const Cursor = struct { block: Block.Index, instruction: u32 = 0 };

    pub const Block = struct {
        name: String,
        incoming: u32,
        branches: u32 = 0,
        instructions: std.ArrayListUnmanaged(Instruction.Index),

        const Index = enum(u32) {
            entry,
            _,

            pub fn ptr(self: Index, wip: *WipFunction) *Block {
                return &wip.blocks.items[@int_from_enum(self)];
            }

            pub fn ptr_const(self: Index, wip: *const WipFunction) *const Block {
                return &wip.blocks.items[@int_from_enum(self)];
            }

            pub fn to_inst(self: Index, function: *const Function) Instruction.Index {
                return function.blocks[@int_from_enum(self)].instruction;
            }
        };
    };

    pub const Instruction = Function.Instruction;

    pub fn init(builder: *Builder, options: struct {
        function: Function.Index,
        strip: bool,
    }) Allocator.Error!WipFunction {
        var self: WipFunction = .{
            .builder = builder,
            .function = options.function,
            .prev_debug_location = .no_location,
            .debug_location = .no_location,
            .cursor = undefined,
            .blocks = .{},
            .instructions = .{},
            .names = .{},
            .strip = options.strip,
            .debug_locations = .{},
            .debug_values = .{},
            .extra = .{},
        };
        errdefer self.deinit();

        const params_len = options.function.type_of(self.builder).function_parameters(self.builder).len;
        try self.ensure_unused_extra_capacity(params_len, NoExtra, 0);
        try self.instructions.ensure_unused_capacity(self.builder.gpa, params_len);
        if (!self.strip) {
            try self.names.ensure_unused_capacity(self.builder.gpa, params_len);
        }
        for (0..params_len) |param_index| {
            self.instructions.append_assume_capacity(.{ .tag = .arg, .data = @int_cast(param_index) });
            if (!self.strip) {
                self.names.append_assume_capacity(.empty); // TODO: param names
            }
        }

        return self;
    }

    pub fn arg(self: *const WipFunction, index: u32) Value {
        const argument = self.instructions.get(index);
        assert(argument.tag == .arg);
        assert(argument.data == index);

        const argument_index: Instruction.Index = @enumFromInt(index);
        return argument_index.to_value();
    }

    pub fn block(self: *WipFunction, incoming: u32, name: []const u8) Allocator.Error!Block.Index {
        try self.blocks.ensure_unused_capacity(self.builder.gpa, 1);

        const index: Block.Index = @enumFromInt(self.blocks.items.len);
        const final_name = if (self.strip) .empty else try self.builder.string(name);
        self.blocks.append_assume_capacity(.{
            .name = final_name,
            .incoming = incoming,
            .instructions = .{},
        });
        return index;
    }

    pub fn ret(self: *WipFunction, val: Value) Allocator.Error!Instruction.Index {
        assert(val.type_of_wip(self) == self.function.type_of(self.builder).function_return(self.builder));
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        return try self.add_inst(null, .{ .tag = .ret, .data = @int_from_enum(val) });
    }

    pub fn ret_void(self: *WipFunction) Allocator.Error!Instruction.Index {
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        return try self.add_inst(null, .{ .tag = .@"ret void", .data = undefined });
    }

    pub fn br(self: *WipFunction, dest: Block.Index) Allocator.Error!Instruction.Index {
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        const instruction = try self.add_inst(null, .{ .tag = .br, .data = @int_from_enum(dest) });
        dest.ptr(self).branches += 1;
        return instruction;
    }

    pub fn br_cond(
        self: *WipFunction,
        cond: Value,
        then: Block.Index,
        @"else": Block.Index,
    ) Allocator.Error!Instruction.Index {
        assert(cond.type_of_wip(self) == .i1);
        try self.ensure_unused_extra_capacity(1, Instruction.BrCond, 0);
        const instruction = try self.add_inst(null, .{
            .tag = .br_cond,
            .data = self.add_extra_assume_capacity(Instruction.BrCond{
                .cond = cond,
                .then = then,
                .@"else" = @"else",
            }),
        });
        then.ptr(self).branches += 1;
        @"else".ptr(self).branches += 1;
        return instruction;
    }

    pub const WipSwitch = struct {
        index: u32,
        instruction: Instruction.Index,

        pub fn add_case(
            self: *WipSwitch,
            val: Constant,
            dest: Block.Index,
            wip: *WipFunction,
        ) Allocator.Error!void {
            const instruction = wip.instructions.get(@int_from_enum(self.instruction));
            var extra = wip.extra_data_trail(Instruction.Switch, instruction.data);
            assert(val.type_of(wip.builder) == extra.data.val.type_of_wip(wip));
            extra.trail.next_mut(extra.data.cases_len, Constant, wip)[self.index] = val;
            extra.trail.next_mut(extra.data.cases_len, Block.Index, wip)[self.index] = dest;
            self.index += 1;
            dest.ptr(wip).branches += 1;
        }

        pub fn finish(self: WipSwitch, wip: *WipFunction) void {
            const instruction = wip.instructions.get(@int_from_enum(self.instruction));
            const extra = wip.extra_data(Instruction.Switch, instruction.data);
            assert(self.index == extra.cases_len);
        }
    };

    pub fn @"switch"(
        self: *WipFunction,
        val: Value,
        default: Block.Index,
        cases_len: u32,
    ) Allocator.Error!WipSwitch {
        try self.ensure_unused_extra_capacity(1, Instruction.Switch, cases_len * 2);
        const instruction = try self.add_inst(null, .{
            .tag = .@"switch",
            .data = self.add_extra_assume_capacity(Instruction.Switch{
                .val = val,
                .default = default,
                .cases_len = cases_len,
            }),
        });
        _ = self.extra.add_many_as_slice_assume_capacity(cases_len * 2);
        default.ptr(self).branches += 1;
        return .{ .index = 0, .instruction = instruction };
    }

    pub fn @"unreachable"(self: *WipFunction) Allocator.Error!Instruction.Index {
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        const instruction = try self.add_inst(null, .{ .tag = .@"unreachable", .data = undefined });
        return instruction;
    }

    pub fn un(
        self: *WipFunction,
        tag: Instruction.Tag,
        val: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .fneg,
            .@"fneg fast",
            => assert(val.type_of_wip(self).scalar_type(self.builder).is_floating_point()),
            else => unreachable,
        }
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        const instruction = try self.add_inst(name, .{ .tag = tag, .data = @int_from_enum(val) });
        return instruction.to_value();
    }

    pub fn not(self: *WipFunction, val: Value, name: []const u8) Allocator.Error!Value {
        const ty = val.type_of_wip(self);
        const all_ones = try self.builder.splat_value(
            ty,
            try self.builder.int_const(ty.scalar_type(self.builder), -1),
        );
        return self.bin(.xor, val, all_ones, name);
    }

    pub fn neg(self: *WipFunction, val: Value, name: []const u8) Allocator.Error!Value {
        return self.bin(.sub, try self.builder.zero_init_value(val.type_of_wip(self)), val, name);
    }

    pub fn bin(
        self: *WipFunction,
        tag: Instruction.Tag,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .add,
            .@"add nsw",
            .@"add nuw",
            .@"and",
            .ashr,
            .@"ashr exact",
            .fadd,
            .@"fadd fast",
            .fdiv,
            .@"fdiv fast",
            .fmul,
            .@"fmul fast",
            .frem,
            .@"frem fast",
            .fsub,
            .@"fsub fast",
            .lshr,
            .@"lshr exact",
            .mul,
            .@"mul nsw",
            .@"mul nuw",
            .@"or",
            .sdiv,
            .@"sdiv exact",
            .shl,
            .@"shl nsw",
            .@"shl nuw",
            .srem,
            .sub,
            .@"sub nsw",
            .@"sub nuw",
            .udiv,
            .@"udiv exact",
            .urem,
            .xor,
            => assert(lhs.type_of_wip(self) == rhs.type_of_wip(self)),
            else => unreachable,
        }
        try self.ensure_unused_extra_capacity(1, Instruction.Binary, 0);
        const instruction = try self.add_inst(name, .{
            .tag = tag,
            .data = self.add_extra_assume_capacity(Instruction.Binary{ .lhs = lhs, .rhs = rhs }),
        });
        return instruction.to_value();
    }

    pub fn extract_element(
        self: *WipFunction,
        val: Value,
        index: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(val.type_of_wip(self).is_vector(self.builder));
        assert(index.type_of_wip(self).is_integer(self.builder));
        try self.ensure_unused_extra_capacity(1, Instruction.ExtractElement, 0);
        const instruction = try self.add_inst(name, .{
            .tag = .extractelement,
            .data = self.add_extra_assume_capacity(Instruction.ExtractElement{
                .val = val,
                .index = index,
            }),
        });
        return instruction.to_value();
    }

    pub fn insert_element(
        self: *WipFunction,
        val: Value,
        elem: Value,
        index: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(val.type_of_wip(self).scalar_type(self.builder) == elem.type_of_wip(self));
        assert(index.type_of_wip(self).is_integer(self.builder));
        try self.ensure_unused_extra_capacity(1, Instruction.InsertElement, 0);
        const instruction = try self.add_inst(name, .{
            .tag = .insertelement,
            .data = self.add_extra_assume_capacity(Instruction.InsertElement{
                .val = val,
                .elem = elem,
                .index = index,
            }),
        });
        return instruction.to_value();
    }

    pub fn shuffle_vector(
        self: *WipFunction,
        lhs: Value,
        rhs: Value,
        mask: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(lhs.type_of_wip(self).is_vector(self.builder));
        assert(lhs.type_of_wip(self) == rhs.type_of_wip(self));
        assert(mask.type_of_wip(self).scalar_type(self.builder).is_integer(self.builder));
        _ = try self.ensure_unused_extra_capacity(1, Instruction.ShuffleVector, 0);
        const instruction = try self.add_inst(name, .{
            .tag = .shufflevector,
            .data = self.add_extra_assume_capacity(Instruction.ShuffleVector{
                .lhs = lhs,
                .rhs = rhs,
                .mask = mask,
            }),
        });
        return instruction.to_value();
    }

    pub fn splat_vector(
        self: *WipFunction,
        ty: Type,
        elem: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const scalar_ty = try ty.change_length(1, self.builder);
        const mask_ty = try ty.change_scalar(.i32, self.builder);
        const poison = try self.builder.poison_value(scalar_ty);
        const mask = try self.builder.splat_value(mask_ty, .@"0");
        const scalar = try self.insert_element(poison, elem, .@"0", name);
        return self.shuffle_vector(scalar, poison, mask, name);
    }

    pub fn extract_value(
        self: *WipFunction,
        val: Value,
        indices: []const u32,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(indices.len > 0);
        _ = val.type_of_wip(self).child_type_at(indices, self.builder);
        try self.ensure_unused_extra_capacity(1, Instruction.ExtractValue, indices.len);
        const instruction = try self.add_inst(name, .{
            .tag = .extractvalue,
            .data = self.add_extra_assume_capacity(Instruction.ExtractValue{
                .val = val,
                .indices_len = @int_cast(indices.len),
            }),
        });
        self.extra.append_slice_assume_capacity(indices);
        return instruction.to_value();
    }

    pub fn insert_value(
        self: *WipFunction,
        val: Value,
        elem: Value,
        indices: []const u32,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(indices.len > 0);
        assert(val.type_of_wip(self).child_type_at(indices, self.builder) == elem.type_of_wip(self));
        try self.ensure_unused_extra_capacity(1, Instruction.InsertValue, indices.len);
        const instruction = try self.add_inst(name, .{
            .tag = .insertvalue,
            .data = self.add_extra_assume_capacity(Instruction.InsertValue{
                .val = val,
                .elem = elem,
                .indices_len = @int_cast(indices.len),
            }),
        });
        self.extra.append_slice_assume_capacity(indices);
        return instruction.to_value();
    }

    pub fn build_aggregate(
        self: *WipFunction,
        ty: Type,
        elems: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ty.aggregate_len(self.builder) == elems.len);
        var cur = try self.builder.poison_value(ty);
        for (elems, 0..) |elem, index|
            cur = try self.insert_value(cur, elem, &[_]u32{@int_cast(index)}, name);
        return cur;
    }

    pub fn alloca(
        self: *WipFunction,
        kind: Instruction.Alloca.Kind,
        ty: Type,
        len: Value,
        alignment: Alignment,
        addr_space: AddrSpace,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(len == .none or len.type_of_wip(self).is_integer(self.builder));
        _ = try self.builder.ptr_type(addr_space);
        try self.ensure_unused_extra_capacity(1, Instruction.Alloca, 0);
        const instruction = try self.add_inst(name, .{
            .tag = switch (kind) {
                .normal => .alloca,
                .inalloca => .@"alloca inalloca",
            },
            .data = self.add_extra_assume_capacity(Instruction.Alloca{
                .type = ty,
                .len = switch (len) {
                    .none => .@"1",
                    else => len,
                },
                .info = .{ .alignment = alignment, .addr_space = addr_space },
            }),
        });
        return instruction.to_value();
    }

    pub fn load(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        ty: Type,
        ptr: Value,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.load_atomic(access_kind, ty, ptr, .system, .none, alignment, name);
    }

    pub fn load_atomic(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        ty: Type,
        ptr: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.type_of_wip(self).is_pointer(self.builder));
        try self.ensure_unused_extra_capacity(1, Instruction.Load, 0);
        const instruction = try self.add_inst(name, .{
            .tag = switch (ordering) {
                .none => .load,
                else => .@"load atomic",
            },
            .data = self.add_extra_assume_capacity(Instruction.Load{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = switch (ordering) {
                        .none => .system,
                        else => sync_scope,
                    },
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .type = ty,
                .ptr = ptr,
            }),
        });
        return instruction.to_value();
    }

    pub fn store(
        self: *WipFunction,
        kind: MemoryAccessKind,
        val: Value,
        ptr: Value,
        alignment: Alignment,
    ) Allocator.Error!Instruction.Index {
        return self.store_atomic(kind, val, ptr, .system, .none, alignment);
    }

    pub fn store_atomic(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        val: Value,
        ptr: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
    ) Allocator.Error!Instruction.Index {
        assert(ptr.type_of_wip(self).is_pointer(self.builder));
        try self.ensure_unused_extra_capacity(1, Instruction.Store, 0);
        const instruction = try self.add_inst(null, .{
            .tag = switch (ordering) {
                .none => .store,
                else => .@"store atomic",
            },
            .data = self.add_extra_assume_capacity(Instruction.Store{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = switch (ordering) {
                        .none => .system,
                        else => sync_scope,
                    },
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .val = val,
                .ptr = ptr,
            }),
        });
        return instruction;
    }

    pub fn fence(
        self: *WipFunction,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
    ) Allocator.Error!Instruction.Index {
        assert(ordering != .none);
        try self.ensure_unused_extra_capacity(1, NoExtra, 0);
        const instruction = try self.add_inst(null, .{
            .tag = .fence,
            .data = @bit_cast(MemoryAccessInfo{
                .sync_scope = sync_scope,
                .success_ordering = ordering,
            }),
        });
        return instruction;
    }

    pub fn cmpxchg(
        self: *WipFunction,
        kind: Instruction.CmpXchg.Kind,
        access_kind: MemoryAccessKind,
        ptr: Value,
        cmp: Value,
        new: Value,
        sync_scope: SyncScope,
        success_ordering: AtomicOrdering,
        failure_ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.type_of_wip(self).is_pointer(self.builder));
        const ty = cmp.type_of_wip(self);
        assert(ty == new.type_of_wip(self));
        assert(success_ordering != .none);
        assert(failure_ordering != .none);

        _ = try self.builder.struct_type(.normal, &.{ ty, .i1 });
        try self.ensure_unused_extra_capacity(1, Instruction.CmpXchg, 0);
        const instruction = try self.add_inst(name, .{
            .tag = switch (kind) {
                .strong => .cmpxchg,
                .weak => .@"cmpxchg weak",
            },
            .data = self.add_extra_assume_capacity(Instruction.CmpXchg{
                .info = .{
                    .access_kind = access_kind,
                    .sync_scope = sync_scope,
                    .success_ordering = success_ordering,
                    .failure_ordering = failure_ordering,
                    .alignment = alignment,
                },
                .ptr = ptr,
                .cmp = cmp,
                .new = new,
            }),
        });
        return instruction.to_value();
    }

    pub fn atomicrmw(
        self: *WipFunction,
        access_kind: MemoryAccessKind,
        operation: Instruction.AtomicRmw.Operation,
        ptr: Value,
        val: Value,
        sync_scope: SyncScope,
        ordering: AtomicOrdering,
        alignment: Alignment,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ptr.type_of_wip(self).is_pointer(self.builder));
        assert(ordering != .none);

        try self.ensure_unused_extra_capacity(1, Instruction.AtomicRmw, 0);
        const instruction = try self.add_inst(name, .{
            .tag = .atomicrmw,
            .data = self.add_extra_assume_capacity(Instruction.AtomicRmw{
                .info = .{
                    .access_kind = access_kind,
                    .atomic_rmw_operation = operation,
                    .sync_scope = sync_scope,
                    .success_ordering = ordering,
                    .alignment = alignment,
                },
                .ptr = ptr,
                .val = val,
            }),
        });
        return instruction.to_value();
    }

    pub fn gep(
        self: *WipFunction,
        kind: Instruction.GetElementPtr.Kind,
        ty: Type,
        base: Value,
        indices: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const base_ty = base.type_of_wip(self);
        const base_is_vector = base_ty.is_vector(self.builder);

        const VectorInfo = struct {
            kind: Type.Vector.Kind,
            len: u32,

            fn init(vector_ty: Type, builder: *const Builder) @This() {
                return .{ .kind = vector_ty.vector_kind(builder), .len = vector_ty.vector_len(builder) };
            }
        };
        var vector_info: ?VectorInfo =
            if (base_is_vector) VectorInfo.init(base_ty, self.builder) else null;
        for (indices) |index| {
            const index_ty = index.type_of_wip(self);
            switch (index_ty.tag(self.builder)) {
                .integer => {},
                .vector, .scalable_vector => {
                    const index_info = VectorInfo.init(index_ty, self.builder);
                    if (vector_info) |info|
                        assert(std.meta.eql(info, index_info))
                    else
                        vector_info = index_info;
                },
                else => unreachable,
            }
        }
        if (!base_is_vector) if (vector_info) |info| switch (info.kind) {
            inline else => |vector_kind| _ = try self.builder.vector_type(
                vector_kind,
                info.len,
                base_ty,
            ),
        };

        try self.ensure_unused_extra_capacity(1, Instruction.GetElementPtr, indices.len);
        const instruction = try self.add_inst(name, .{
            .tag = switch (kind) {
                .normal => .getelementptr,
                .inbounds => .@"getelementptr inbounds",
            },
            .data = self.add_extra_assume_capacity(Instruction.GetElementPtr{
                .type = ty,
                .base = base,
                .indices_len = @int_cast(indices.len),
            }),
        });
        self.extra.append_slice_assume_capacity(@ptr_cast(indices));
        return instruction.to_value();
    }

    pub fn gep_struct(
        self: *WipFunction,
        ty: Type,
        base: Value,
        index: usize,
        name: []const u8,
    ) Allocator.Error!Value {
        assert(ty.is_struct(self.builder));
        return self.gep(.inbounds, ty, base, &.{ .@"0", try self.builder.int_value(.i32, index) }, name);
    }

    pub fn conv(
        self: *WipFunction,
        signedness: Instruction.Cast.Signedness,
        val: Value,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!Value {
        const val_ty = val.type_of_wip(self);
        if (val_ty == ty) return val;
        return self.cast(self.builder.conv_tag(signedness, val_ty, ty), val, ty, name);
    }

    pub fn cast(
        self: *WipFunction,
        tag: Instruction.Tag,
        val: Value,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .addrspacecast,
            .bitcast,
            .fpext,
            .fptosi,
            .fptoui,
            .fptrunc,
            .inttoptr,
            .ptrtoint,
            .sext,
            .sitofp,
            .trunc,
            .uitofp,
            .zext,
            => {},
            else => unreachable,
        }
        if (val.type_of_wip(self) == ty) return val;
        try self.ensure_unused_extra_capacity(1, Instruction.Cast, 0);
        const instruction = try self.add_inst(name, .{
            .tag = tag,
            .data = self.add_extra_assume_capacity(Instruction.Cast{
                .val = val,
                .type = ty,
            }),
        });
        return instruction.to_value();
    }

    pub fn icmp(
        self: *WipFunction,
        cond: IntegerCondition,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.cmp_tag(switch (cond) {
            inline else => |tag| @field(Instruction.Tag, "icmp " ++ @tag_name(tag)),
        }, lhs, rhs, name);
    }

    pub fn fcmp(
        self: *WipFunction,
        fast: FastMathKind,
        cond: FloatCondition,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.cmp_tag(switch (fast) {
            inline else => |fast_tag| switch (cond) {
                inline else => |cond_tag| @field(Instruction.Tag, "fcmp " ++ switch (fast_tag) {
                    .normal => "",
                    .fast => "fast ",
                } ++ @tag_name(cond_tag)),
            },
        }, lhs, rhs, name);
    }

    pub const WipPhi = struct {
        block: Block.Index,
        instruction: Instruction.Index,

        pub fn to_value(self: WipPhi) Value {
            return self.instruction.to_value();
        }

        pub fn finish(
            self: WipPhi,
            vals: []const Value,
            blocks: []const Block.Index,
            wip: *WipFunction,
        ) void {
            const incoming_len = self.block.ptr_const(wip).incoming;
            assert(vals.len == incoming_len and blocks.len == incoming_len);
            const instruction = wip.instructions.get(@int_from_enum(self.instruction));
            var extra = wip.extra_data_trail(Instruction.Phi, instruction.data);
            for (vals) |val| assert(val.type_of_wip(wip) == extra.data.type);
            @memcpy(extra.trail.next_mut(incoming_len, Value, wip), vals);
            @memcpy(extra.trail.next_mut(incoming_len, Block.Index, wip), blocks);
        }
    };

    pub fn phi(self: *WipFunction, ty: Type, name: []const u8) Allocator.Error!WipPhi {
        return self.phi_tag(.phi, ty, name);
    }

    pub fn phi_fast(self: *WipFunction, ty: Type, name: []const u8) Allocator.Error!WipPhi {
        return self.phi_tag(.@"phi fast", ty, name);
    }

    pub fn select(
        self: *WipFunction,
        fast: FastMathKind,
        cond: Value,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        return self.select_tag(switch (fast) {
            .normal => .select,
            .fast => .@"select fast",
        }, cond, lhs, rhs, name);
    }

    pub fn call(
        self: *WipFunction,
        kind: Instruction.Call.Kind,
        call_conv: CallConv,
        function_attributes: FunctionAttributes,
        ty: Type,
        callee: Value,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const ret_ty = ty.function_return(self.builder);
        assert(ty.is_function(self.builder));
        assert(callee.type_of_wip(self).is_pointer(self.builder));
        const params = ty.function_parameters(self.builder);
        for (params, args[0..params.len]) |param, arg_val| assert(param == arg_val.type_of_wip(self));

        try self.ensure_unused_extra_capacity(1, Instruction.Call, args.len);
        const instruction = try self.add_inst(switch (ret_ty) {
            .void => null,
            else => name,
        }, .{
            .tag = switch (kind) {
                .normal => .call,
                .fast => .@"call fast",
                .musttail => .@"musttail call",
                .musttail_fast => .@"musttail call fast",
                .notail => .@"notail call",
                .notail_fast => .@"notail call fast",
                .tail => .@"tail call",
                .tail_fast => .@"tail call fast",
            },
            .data = self.add_extra_assume_capacity(Instruction.Call{
                .info = .{ .call_conv = call_conv },
                .attributes = function_attributes,
                .ty = ty,
                .callee = callee,
                .args_len = @int_cast(args.len),
            }),
        });
        self.extra.append_slice_assume_capacity(@ptr_cast(args));
        return instruction.to_value();
    }

    pub fn call_asm(
        self: *WipFunction,
        function_attributes: FunctionAttributes,
        ty: Type,
        kind: Constant.Assembly.Info,
        assembly: String,
        constraints: String,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const callee = try self.builder.asm_value(ty, kind, assembly, constraints);
        return self.call(.normal, CallConv.default, function_attributes, ty, callee, args, name);
    }

    pub fn call_intrinsic(
        self: *WipFunction,
        fast: FastMathKind,
        function_attributes: FunctionAttributes,
        id: Intrinsic,
        overload: []const Type,
        args: []const Value,
        name: []const u8,
    ) Allocator.Error!Value {
        const intrinsic = try self.builder.get_intrinsic(id, overload);
        return self.call(
            fast.to_call_kind(),
            CallConv.default,
            function_attributes,
            intrinsic.type_of(self.builder),
            intrinsic.to_value(self.builder),
            args,
            name,
        );
    }

    pub fn call_mem_cpy(
        self: *WipFunction,
        dst: Value,
        dst_align: Alignment,
        src: Value,
        src_align: Alignment,
        len: Value,
        kind: MemoryAccessKind,
    ) Allocator.Error!Instruction.Index {
        var dst_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = dst_align })};
        var src_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = src_align })};
        const value = try self.call_intrinsic(
            .normal,
            try self.builder.fn_attrs(&.{
                .none,
                .none,
                try self.builder.attrs(&dst_attrs),
                try self.builder.attrs(&src_attrs),
            }),
            .memcpy,
            &.{ dst.type_of_wip(self), src.type_of_wip(self), len.type_of_wip(self) },
            &.{ dst, src, len, switch (kind) {
                .normal => Value.false,
                .@"volatile" => Value.true,
            } },
            undefined,
        );
        return value.unwrap().instruction;
    }

    pub fn call_mem_set(
        self: *WipFunction,
        dst: Value,
        dst_align: Alignment,
        val: Value,
        len: Value,
        kind: MemoryAccessKind,
    ) Allocator.Error!Instruction.Index {
        var dst_attrs = [_]Attribute.Index{try self.builder.attr(.{ .@"align" = dst_align })};
        const value = try self.call_intrinsic(
            .normal,
            try self.builder.fn_attrs(&.{ .none, .none, try self.builder.attrs(&dst_attrs) }),
            .memset,
            &.{ dst.type_of_wip(self), len.type_of_wip(self) },
            &.{ dst, val, len, switch (kind) {
                .normal => Value.false,
                .@"volatile" => Value.true,
            } },
            undefined,
        );
        return value.unwrap().instruction;
    }

    pub fn va_arg(self: *WipFunction, list: Value, ty: Type, name: []const u8) Allocator.Error!Value {
        try self.ensure_unused_extra_capacity(1, Instruction.VaArg, 0);
        const instruction = try self.add_inst(name, .{
            .tag = .va_arg,
            .data = self.add_extra_assume_capacity(Instruction.VaArg{
                .list = list,
                .type = ty,
            }),
        });
        return instruction.to_value();
    }

    pub fn debug_value(self: *WipFunction, value: Value) Allocator.Error!Metadata {
        if (self.strip) return .none;
        return switch (value.unwrap()) {
            .instruction => |instr_index| blk: {
                const gop = try self.debug_values.get_or_put(self.builder.gpa, instr_index);

                const metadata: Metadata = @enumFromInt(Metadata.first_local_metadata + gop.index);
                if (!gop.found_existing) gop.key_ptr.* = instr_index;

                break :blk metadata;
            },
            .constant => |constant| try self.builder.debug_constant(constant),
            .metadata => |metadata| metadata,
        };
    }

    pub fn finish(self: *WipFunction) Allocator.Error!void {
        const gpa = self.builder.gpa;
        const function = self.function.ptr(self.builder);
        const params_len = self.function.type_of(self.builder).function_parameters(self.builder).len;
        const final_instructions_len = self.blocks.items.len + self.instructions.len;

        const blocks = try gpa.alloc(Function.Block, self.blocks.items.len);
        errdefer gpa.free(blocks);

        const instructions: struct {
            items: []Instruction.Index,

            fn map(instructions: @This(), val: Value) Value {
                if (val == .none) return .none;
                return switch (val.unwrap()) {
                    .instruction => |instruction| instructions.items[
                        @int_from_enum(instruction)
                    ].to_value(),
                    .constant => |constant| constant.to_value(),
                    .metadata => |metadata| metadata.to_value(),
                };
            }
        } = .{ .items = try gpa.alloc(Instruction.Index, self.instructions.len) };
        defer gpa.free(instructions.items);

        const names = try gpa.alloc(String, final_instructions_len);
        errdefer gpa.free(names);

        const value_indices = try gpa.alloc(u32, final_instructions_len);
        errdefer gpa.free(value_indices);

        var debug_locations: std.AutoHashMapUnmanaged(Instruction.Index, DebugLocation) = .{};
        errdefer debug_locations.deinit(gpa);
        try debug_locations.ensure_unused_capacity(gpa, @int_cast(self.debug_locations.count()));

        const debug_values = try gpa.alloc(Instruction.Index, self.debug_values.count());
        errdefer gpa.free(debug_values);

        var wip_extra: struct {
            index: Instruction.ExtraIndex = 0,
            items: []u32,

            fn add_extra(wip_extra: *@This(), extra: anytype) Instruction.ExtraIndex {
                const result = wip_extra.index;
                inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
                    const value = @field(extra, field.name);
                    wip_extra.items[wip_extra.index] = switch (field.type) {
                        u32 => value,
                        Alignment,
                        AtomicOrdering,
                        Block.Index,
                        FunctionAttributes,
                        Type,
                        Value,
                        => @int_from_enum(value),
                        MemoryAccessInfo,
                        Instruction.Alloca.Info,
                        Instruction.Call.Info,
                        => @bit_cast(value),
                        else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
                    };
                    wip_extra.index += 1;
                }
                return result;
            }

            fn append_slice(wip_extra: *@This(), slice: anytype) void {
                if (@typeInfo(@TypeOf(slice)).Pointer.child == Value)
                    @compile_error("use append_mapped_values");
                const data: []const u32 = @ptr_cast(slice);
                @memcpy(wip_extra.items[wip_extra.index..][0..data.len], data);
                wip_extra.index += @int_cast(data.len);
            }

            fn append_mapped_values(wip_extra: *@This(), vals: []const Value, ctx: anytype) void {
                for (wip_extra.items[wip_extra.index..][0..vals.len], vals) |*extra, val|
                    extra.* = @int_from_enum(ctx.map(val));
                wip_extra.index += @int_cast(vals.len);
            }

            fn finish(wip_extra: *const @This()) []const u32 {
                assert(wip_extra.index == wip_extra.items.len);
                return wip_extra.items;
            }
        } = .{ .items = try gpa.alloc(u32, self.extra.items.len) };
        errdefer gpa.free(wip_extra.items);

        gpa.free(function.blocks);
        function.blocks = &.{};
        gpa.free(function.names[0..function.instructions.len]);
        function.debug_locations.deinit(gpa);
        function.debug_locations = .{};
        gpa.free(function.debug_values);
        function.debug_values = &.{};
        gpa.free(function.extra);
        function.extra = &.{};

        function.instructions.shrink_retaining_capacity(0);
        try function.instructions.set_capacity(gpa, final_instructions_len);
        errdefer function.instructions.shrink_retaining_capacity(0);

        {
            var final_instruction_index: Instruction.Index = @enumFromInt(0);
            for (0..params_len) |param_index| {
                instructions.items[param_index] = final_instruction_index;
                final_instruction_index = @enumFromInt(@int_from_enum(final_instruction_index) + 1);
            }
            for (blocks, self.blocks.items) |*final_block, current_block| {
                assert(current_block.incoming == current_block.branches);
                final_block.instruction = final_instruction_index;
                final_instruction_index = @enumFromInt(@int_from_enum(final_instruction_index) + 1);
                for (current_block.instructions.items) |instruction| {
                    instructions.items[@int_from_enum(instruction)] = final_instruction_index;
                    final_instruction_index = @enumFromInt(@int_from_enum(final_instruction_index) + 1);
                }
            }
        }

        var wip_name: struct {
            next_name: String = @enumFromInt(0),
            next_unique_name: std.AutoHashMap(String, String),
            builder: *Builder,

            fn map(wip_name: *@This(), name: String, sep: []const u8) Allocator.Error!String {
                switch (name) {
                    .none => return .none,
                    .empty => {
                        assert(wip_name.next_name != .none);
                        defer wip_name.next_name = @enumFromInt(@int_from_enum(wip_name.next_name) + 1);
                        return wip_name.next_name;
                    },
                    _ => {
                        assert(!name.is_anon());
                        const gop = try wip_name.next_unique_name.get_or_put(name);
                        if (!gop.found_existing) {
                            gop.value_ptr.* = @enumFromInt(0);
                            return name;
                        }

                        while (true) {
                            gop.value_ptr.* = @enumFromInt(@int_from_enum(gop.value_ptr.*) + 1);
                            const unique_name = try wip_name.builder.fmt("{r}{s}{r}", .{
                                name.fmt(wip_name.builder),
                                sep,
                                gop.value_ptr.fmt(wip_name.builder),
                            });
                            const unique_gop = try wip_name.next_unique_name.get_or_put(unique_name);
                            if (!unique_gop.found_existing) {
                                unique_gop.value_ptr.* = @enumFromInt(0);
                                return unique_name;
                            }
                        }
                    },
                }
            }
        } = .{
            .next_unique_name = std.AutoHashMap(String, String).init(gpa),
            .builder = self.builder,
        };
        defer wip_name.next_unique_name.deinit();

        var value_index: u32 = 0;
        for (0..params_len) |param_index| {
            const old_argument_index: Instruction.Index = @enumFromInt(param_index);
            const new_argument_index: Instruction.Index = @enumFromInt(function.instructions.len);
            const argument = self.instructions.get(@int_from_enum(old_argument_index));
            assert(argument.tag == .arg);
            assert(argument.data == param_index);
            value_indices[function.instructions.len] = value_index;
            value_index += 1;
            function.instructions.append_assume_capacity(argument);
            names[@int_from_enum(new_argument_index)] = try wip_name.map(
                if (self.strip) .empty else self.names.items[@int_from_enum(old_argument_index)],
                ".",
            );
            if (self.debug_locations.get(old_argument_index)) |location| {
                debug_locations.put_assume_capacity(new_argument_index, location);
            }
            if (self.debug_values.get_index(old_argument_index)) |index| {
                debug_values[index] = new_argument_index;
            }
        }
        for (self.blocks.items) |current_block| {
            const new_block_index: Instruction.Index = @enumFromInt(function.instructions.len);
            value_indices[function.instructions.len] = value_index;
            function.instructions.append_assume_capacity(.{
                .tag = .block,
                .data = current_block.incoming,
            });
            names[@int_from_enum(new_block_index)] = try wip_name.map(current_block.name, "");
            for (current_block.instructions.items) |old_instruction_index| {
                const new_instruction_index: Instruction.Index =
                    @enumFromInt(function.instructions.len);
                var instruction = self.instructions.get(@int_from_enum(old_instruction_index));
                switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .@"fcmp false",
                    .@"fcmp fast false",
                    .@"fcmp fast oeq",
                    .@"fcmp fast oge",
                    .@"fcmp fast ogt",
                    .@"fcmp fast ole",
                    .@"fcmp fast olt",
                    .@"fcmp fast one",
                    .@"fcmp fast ord",
                    .@"fcmp fast true",
                    .@"fcmp fast ueq",
                    .@"fcmp fast uge",
                    .@"fcmp fast ugt",
                    .@"fcmp fast ule",
                    .@"fcmp fast ult",
                    .@"fcmp fast une",
                    .@"fcmp fast uno",
                    .@"fcmp oeq",
                    .@"fcmp oge",
                    .@"fcmp ogt",
                    .@"fcmp ole",
                    .@"fcmp olt",
                    .@"fcmp one",
                    .@"fcmp ord",
                    .@"fcmp true",
                    .@"fcmp ueq",
                    .@"fcmp uge",
                    .@"fcmp ugt",
                    .@"fcmp ule",
                    .@"fcmp ult",
                    .@"fcmp une",
                    .@"fcmp uno",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .@"icmp eq",
                    .@"icmp ne",
                    .@"icmp sge",
                    .@"icmp sgt",
                    .@"icmp sle",
                    .@"icmp slt",
                    .@"icmp uge",
                    .@"icmp ugt",
                    .@"icmp ule",
                    .@"icmp ult",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .srem,
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => {
                        const extra = self.extra_data(Instruction.Binary, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Binary{
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                        });
                    },
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => {
                        const extra = self.extra_data(Instruction.Cast, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Cast{
                            .val = instructions.map(extra.val),
                            .type = extra.type,
                        });
                    },
                    .alloca,
                    .@"alloca inalloca",
                    => {
                        const extra = self.extra_data(Instruction.Alloca, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Alloca{
                            .type = extra.type,
                            .len = instructions.map(extra.len),
                            .info = extra.info,
                        });
                    },
                    .arg,
                    .block,
                    => unreachable,
                    .atomicrmw => {
                        const extra = self.extra_data(Instruction.AtomicRmw, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.AtomicRmw{
                            .info = extra.info,
                            .ptr = instructions.map(extra.ptr),
                            .val = instructions.map(extra.val),
                        });
                    },
                    .br,
                    .fence,
                    .@"ret void",
                    .@"unreachable",
                    => {},
                    .br_cond => {
                        const extra = self.extra_data(Instruction.BrCond, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.BrCond{
                            .cond = instructions.map(extra.cond),
                            .then = extra.then,
                            .@"else" = extra.@"else",
                        });
                    },
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => {
                        var extra = self.extra_data_trail(Instruction.Call, instruction.data);
                        const args = extra.trail.next(extra.data.args_len, Value, self);
                        instruction.data = wip_extra.add_extra(Instruction.Call{
                            .info = extra.data.info,
                            .attributes = extra.data.attributes,
                            .ty = extra.data.ty,
                            .callee = instructions.map(extra.data.callee),
                            .args_len = extra.data.args_len,
                        });
                        wip_extra.append_mapped_values(args, instructions);
                    },
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => {
                        const extra = self.extra_data(Instruction.CmpXchg, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.CmpXchg{
                            .info = extra.info,
                            .ptr = instructions.map(extra.ptr),
                            .cmp = instructions.map(extra.cmp),
                            .new = instructions.map(extra.new),
                        });
                    },
                    .extractelement => {
                        const extra = self.extra_data(Instruction.ExtractElement, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.ExtractElement{
                            .val = instructions.map(extra.val),
                            .index = instructions.map(extra.index),
                        });
                    },
                    .extractvalue => {
                        var extra = self.extra_data_trail(Instruction.ExtractValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, self);
                        instruction.data = wip_extra.add_extra(Instruction.ExtractValue{
                            .val = instructions.map(extra.data.val),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.append_slice(indices);
                    },
                    .fneg,
                    .@"fneg fast",
                    .ret,
                    => instruction.data = @int_from_enum(instructions.map(@enumFromInt(instruction.data))),
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = self.extra_data_trail(Instruction.GetElementPtr, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, Value, self);
                        instruction.data = wip_extra.add_extra(Instruction.GetElementPtr{
                            .type = extra.data.type,
                            .base = instructions.map(extra.data.base),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.append_mapped_values(indices, instructions);
                    },
                    .insertelement => {
                        const extra = self.extra_data(Instruction.InsertElement, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.InsertElement{
                            .val = instructions.map(extra.val),
                            .elem = instructions.map(extra.elem),
                            .index = instructions.map(extra.index),
                        });
                    },
                    .insertvalue => {
                        var extra = self.extra_data_trail(Instruction.InsertValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, self);
                        instruction.data = wip_extra.add_extra(Instruction.InsertValue{
                            .val = instructions.map(extra.data.val),
                            .elem = instructions.map(extra.data.elem),
                            .indices_len = extra.data.indices_len,
                        });
                        wip_extra.append_slice(indices);
                    },
                    .load,
                    .@"load atomic",
                    => {
                        const extra = self.extra_data(Instruction.Load, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Load{
                            .type = extra.type,
                            .ptr = instructions.map(extra.ptr),
                            .info = extra.info,
                        });
                    },
                    .phi,
                    .@"phi fast",
                    => {
                        const incoming_len = current_block.incoming;
                        var extra = self.extra_data_trail(Instruction.Phi, instruction.data);
                        const incoming_vals = extra.trail.next(incoming_len, Value, self);
                        const incoming_blocks = extra.trail.next(incoming_len, Block.Index, self);
                        instruction.data = wip_extra.add_extra(Instruction.Phi{
                            .type = extra.data.type,
                        });
                        wip_extra.append_mapped_values(incoming_vals, instructions);
                        wip_extra.append_slice(incoming_blocks);
                    },
                    .select,
                    .@"select fast",
                    => {
                        const extra = self.extra_data(Instruction.Select, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Select{
                            .cond = instructions.map(extra.cond),
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                        });
                    },
                    .shufflevector => {
                        const extra = self.extra_data(Instruction.ShuffleVector, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.ShuffleVector{
                            .lhs = instructions.map(extra.lhs),
                            .rhs = instructions.map(extra.rhs),
                            .mask = instructions.map(extra.mask),
                        });
                    },
                    .store,
                    .@"store atomic",
                    => {
                        const extra = self.extra_data(Instruction.Store, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.Store{
                            .val = instructions.map(extra.val),
                            .ptr = instructions.map(extra.ptr),
                            .info = extra.info,
                        });
                    },
                    .@"switch" => {
                        var extra = self.extra_data_trail(Instruction.Switch, instruction.data);
                        const case_vals = extra.trail.next(extra.data.cases_len, Constant, self);
                        const case_blocks = extra.trail.next(extra.data.cases_len, Block.Index, self);
                        instruction.data = wip_extra.add_extra(Instruction.Switch{
                            .val = instructions.map(extra.data.val),
                            .default = extra.data.default,
                            .cases_len = extra.data.cases_len,
                        });
                        wip_extra.append_slice(case_vals);
                        wip_extra.append_slice(case_blocks);
                    },
                    .va_arg => {
                        const extra = self.extra_data(Instruction.VaArg, instruction.data);
                        instruction.data = wip_extra.add_extra(Instruction.VaArg{
                            .list = instructions.map(extra.list),
                            .type = extra.type,
                        });
                    },
                }
                function.instructions.append_assume_capacity(instruction);
                names[@int_from_enum(new_instruction_index)] = try wip_name.map(if (self.strip)
                    if (old_instruction_index.has_result_wip(self)) .empty else .none
                else
                    self.names.items[@int_from_enum(old_instruction_index)], ".");

                if (self.debug_locations.get(old_instruction_index)) |location| {
                    debug_locations.put_assume_capacity(new_instruction_index, location);
                }

                if (self.debug_values.get_index(old_instruction_index)) |index| {
                    debug_values[index] = new_instruction_index;
                }

                value_indices[@int_from_enum(new_instruction_index)] = value_index;
                if (old_instruction_index.has_result_wip(self)) value_index += 1;
            }
        }

        assert(function.instructions.len == final_instructions_len);
        function.extra = wip_extra.finish();
        function.blocks = blocks;
        function.names = names.ptr;
        function.value_indices = value_indices.ptr;
        function.strip = self.strip;
        function.debug_locations = debug_locations;
        function.debug_values = debug_values;
    }

    pub fn deinit(self: *WipFunction) void {
        self.extra.deinit(self.builder.gpa);
        self.debug_values.deinit(self.builder.gpa);
        self.debug_locations.deinit(self.builder.gpa);
        self.names.deinit(self.builder.gpa);
        self.instructions.deinit(self.builder.gpa);
        for (self.blocks.items) |*b| b.instructions.deinit(self.builder.gpa);
        self.blocks.deinit(self.builder.gpa);
        self.* = undefined;
    }

    fn cmp_tag(
        self: *WipFunction,
        tag: Instruction.Tag,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .@"fcmp false",
            .@"fcmp fast false",
            .@"fcmp fast oeq",
            .@"fcmp fast oge",
            .@"fcmp fast ogt",
            .@"fcmp fast ole",
            .@"fcmp fast olt",
            .@"fcmp fast one",
            .@"fcmp fast ord",
            .@"fcmp fast true",
            .@"fcmp fast ueq",
            .@"fcmp fast uge",
            .@"fcmp fast ugt",
            .@"fcmp fast ule",
            .@"fcmp fast ult",
            .@"fcmp fast une",
            .@"fcmp fast uno",
            .@"fcmp oeq",
            .@"fcmp oge",
            .@"fcmp ogt",
            .@"fcmp ole",
            .@"fcmp olt",
            .@"fcmp one",
            .@"fcmp ord",
            .@"fcmp true",
            .@"fcmp ueq",
            .@"fcmp uge",
            .@"fcmp ugt",
            .@"fcmp ule",
            .@"fcmp ult",
            .@"fcmp une",
            .@"fcmp uno",
            .@"icmp eq",
            .@"icmp ne",
            .@"icmp sge",
            .@"icmp sgt",
            .@"icmp sle",
            .@"icmp slt",
            .@"icmp uge",
            .@"icmp ugt",
            .@"icmp ule",
            .@"icmp ult",
            => assert(lhs.type_of_wip(self) == rhs.type_of_wip(self)),
            else => unreachable,
        }
        _ = try lhs.type_of_wip(self).change_scalar(.i1, self.builder);
        try self.ensure_unused_extra_capacity(1, Instruction.Binary, 0);
        const instruction = try self.add_inst(name, .{
            .tag = tag,
            .data = self.add_extra_assume_capacity(Instruction.Binary{
                .lhs = lhs,
                .rhs = rhs,
            }),
        });
        return instruction.to_value();
    }

    fn phi_tag(
        self: *WipFunction,
        tag: Instruction.Tag,
        ty: Type,
        name: []const u8,
    ) Allocator.Error!WipPhi {
        switch (tag) {
            .phi, .@"phi fast" => assert(try ty.is_sized(self.builder)),
            else => unreachable,
        }
        const incoming = self.cursor.block.ptr_const(self).incoming;
        assert(incoming > 0);
        try self.ensure_unused_extra_capacity(1, Instruction.Phi, incoming * 2);
        const instruction = try self.add_inst(name, .{
            .tag = tag,
            .data = self.add_extra_assume_capacity(Instruction.Phi{ .type = ty }),
        });
        _ = self.extra.add_many_as_slice_assume_capacity(incoming * 2);
        return .{ .block = self.cursor.block, .instruction = instruction };
    }

    fn select_tag(
        self: *WipFunction,
        tag: Instruction.Tag,
        cond: Value,
        lhs: Value,
        rhs: Value,
        name: []const u8,
    ) Allocator.Error!Value {
        switch (tag) {
            .select, .@"select fast" => {
                assert(cond.type_of_wip(self).scalar_type(self.builder) == .i1);
                assert(lhs.type_of_wip(self) == rhs.type_of_wip(self));
            },
            else => unreachable,
        }
        try self.ensure_unused_extra_capacity(1, Instruction.Select, 0);
        const instruction = try self.add_inst(name, .{
            .tag = tag,
            .data = self.add_extra_assume_capacity(Instruction.Select{
                .cond = cond,
                .lhs = lhs,
                .rhs = rhs,
            }),
        });
        return instruction.to_value();
    }

    fn ensure_unused_extra_capacity(
        self: *WipFunction,
        count: usize,
        comptime Extra: type,
        trail_len: usize,
    ) Allocator.Error!void {
        try self.extra.ensure_unused_capacity(
            self.builder.gpa,
            count * (@typeInfo(Extra).Struct.fields.len + trail_len),
        );
    }

    fn add_inst(
        self: *WipFunction,
        name: ?[]const u8,
        instruction: Instruction,
    ) Allocator.Error!Instruction.Index {
        const block_instructions = &self.cursor.block.ptr(self).instructions;
        try self.instructions.ensure_unused_capacity(self.builder.gpa, 1);
        if (!self.strip) {
            try self.names.ensure_unused_capacity(self.builder.gpa, 1);
            try self.debug_locations.ensure_unused_capacity(self.builder.gpa, 1);
        }
        try block_instructions.ensure_unused_capacity(self.builder.gpa, 1);
        const final_name = if (name) |n|
            if (self.strip) .empty else try self.builder.string(n)
        else
            .none;

        const index: Instruction.Index = @enumFromInt(self.instructions.len);
        self.instructions.append_assume_capacity(instruction);
        if (!self.strip) {
            self.names.append_assume_capacity(final_name);
            if (block_instructions.items.len == 0 or
                !std.meta.eql(self.debug_location, self.prev_debug_location))
            {
                self.debug_locations.put_assume_capacity(index, self.debug_location);
                self.prev_debug_location = self.debug_location;
            }
        }
        block_instructions.insert_assume_capacity(self.cursor.instruction, index);
        self.cursor.instruction += 1;
        return index;
    }

    fn add_extra_assume_capacity(self: *WipFunction, extra: anytype) Instruction.ExtraIndex {
        const result: Instruction.ExtraIndex = @int_cast(self.extra.items.len);
        inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
            const value = @field(extra, field.name);
            self.extra.append_assume_capacity(switch (field.type) {
                u32 => value,
                Alignment,
                AtomicOrdering,
                Block.Index,
                FunctionAttributes,
                Type,
                Value,
                => @int_from_enum(value),
                MemoryAccessInfo,
                Instruction.Alloca.Info,
                Instruction.Call.Info,
                => @bit_cast(value),
                else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
            });
        }
        return result;
    }

    const ExtraDataTrail = struct {
        index: Instruction.ExtraIndex,

        fn next_mut(self: *ExtraDataTrail, len: u32, comptime Item: type, wip: *WipFunction) []Item {
            const items: []Item = @ptr_cast(wip.extra.items[self.index..][0..len]);
            self.index += @int_cast(len);
            return items;
        }

        fn next(
            self: *ExtraDataTrail,
            len: u32,
            comptime Item: type,
            wip: *const WipFunction,
        ) []const Item {
            const items: []const Item = @ptr_cast(wip.extra.items[self.index..][0..len]);
            self.index += @int_cast(len);
            return items;
        }
    };

    fn extra_data_trail(
        self: *const WipFunction,
        comptime T: type,
        index: Instruction.ExtraIndex,
    ) struct { data: T, trail: ExtraDataTrail } {
        var result: T = undefined;
        const fields = @typeInfo(T).Struct.fields;
        inline for (fields, self.extra.items[index..][0..fields.len]) |field, value|
            @field(result, field.name) = switch (field.type) {
                u32 => value,
                Alignment,
                AtomicOrdering,
                Block.Index,
                FunctionAttributes,
                Type,
                Value,
                => @enumFromInt(value),
                MemoryAccessInfo,
                Instruction.Alloca.Info,
                Instruction.Call.Info,
                => @bit_cast(value),
                else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
            };
        return .{
            .data = result,
            .trail = .{ .index = index + @as(Type.Item.ExtraIndex, @int_cast(fields.len)) },
        };
    }

    fn extra_data(self: *const WipFunction, comptime T: type, index: Instruction.ExtraIndex) T {
        return self.extra_data_trail(T, index).data;
    }
};

pub const FloatCondition = enum(u4) {
    oeq = 1,
    ogt = 2,
    oge = 3,
    olt = 4,
    ole = 5,
    one = 6,
    ord = 7,
    uno = 8,
    ueq = 9,
    ugt = 10,
    uge = 11,
    ult = 12,
    ule = 13,
    une = 14,
};

pub const IntegerCondition = enum(u6) {
    eq = 32,
    ne = 33,
    ugt = 34,
    uge = 35,
    ult = 36,
    ule = 37,
    sgt = 38,
    sge = 39,
    slt = 40,
    sle = 41,
};

pub const MemoryAccessKind = enum(u1) {
    normal,
    @"volatile",

    pub fn format(
        self: MemoryAccessKind,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .normal) try writer.print("{s}{s}", .{ prefix, @tag_name(self) });
    }
};

pub const SyncScope = enum(u1) {
    singlethread,
    system,

    pub fn format(
        self: SyncScope,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .system) try writer.print(
            \\{s}syncscope("{s}")
        , .{ prefix, @tag_name(self) });
    }
};

pub const AtomicOrdering = enum(u3) {
    none = 0,
    unordered = 1,
    monotonic = 2,
    acquire = 3,
    release = 4,
    acq_rel = 5,
    seq_cst = 6,

    pub fn format(
        self: AtomicOrdering,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .none) try writer.print("{s}{s}", .{ prefix, @tag_name(self) });
    }
};

const MemoryAccessInfo = packed struct(u32) {
    access_kind: MemoryAccessKind = .normal,
    atomic_rmw_operation: Function.Instruction.AtomicRmw.Operation = .none,
    sync_scope: SyncScope,
    success_ordering: AtomicOrdering,
    failure_ordering: AtomicOrdering = .none,
    alignment: Alignment = .default,
    _: u13 = undefined,
};

pub const FastMath = packed struct(u8) {
    unsafe_algebra: bool = false, // Legacy
    nnan: bool = false,
    ninf: bool = false,
    nsz: bool = false,
    arcp: bool = false,
    contract: bool = false,
    afn: bool = false,
    reassoc: bool = false,

    pub const fast = FastMath{
        .nnan = true,
        .ninf = true,
        .nsz = true,
        .arcp = true,
        .contract = true,
        .afn = true,
        .reassoc = true,
    };
};

pub const FastMathKind = enum {
    normal,
    fast,

    pub fn to_call_kind(self: FastMathKind) Function.Instruction.Call.Kind {
        return switch (self) {
            .normal => .normal,
            .fast => .fast,
        };
    }
};

pub const Constant = enum(u32) {
    false,
    true,
    @"0",
    @"1",
    none,
    no_init = (1 << 30) - 1,
    _,

    const first_global: Constant = @enumFromInt(1 << 29);

    pub const Tag = enum(u7) {
        positive_integer,
        negative_integer,
        half,
        bfloat,
        float,
        double,
        fp128,
        x86_fp80,
        ppc_fp128,
        null,
        none,
        structure,
        packed_structure,
        array,
        string,
        vector,
        splat,
        zeroinitializer,
        undef,
        poison,
        blockaddress,
        dso_local_equivalent,
        no_cfi,
        trunc,
        ptrtoint,
        inttoptr,
        bitcast,
        addrspacecast,
        getelementptr,
        @"getelementptr inbounds",
        add,
        @"add nsw",
        @"add nuw",
        sub,
        @"sub nsw",
        @"sub nuw",
        shl,
        xor,
        @"asm",
        @"asm sideeffect",
        @"asm alignstack",
        @"asm sideeffect alignstack",
        @"asm inteldialect",
        @"asm sideeffect inteldialect",
        @"asm alignstack inteldialect",
        @"asm sideeffect alignstack inteldialect",
        @"asm unwind",
        @"asm sideeffect unwind",
        @"asm alignstack unwind",
        @"asm sideeffect alignstack unwind",
        @"asm inteldialect unwind",
        @"asm sideeffect inteldialect unwind",
        @"asm alignstack inteldialect unwind",
        @"asm sideeffect alignstack inteldialect unwind",

        pub fn to_binary_opcode(self: Tag) BinaryOpcode {
            return switch (self) {
                .add,
                .@"add nsw",
                .@"add nuw",
                => .add,
                .sub,
                .@"sub nsw",
                .@"sub nuw",
                => .sub,
                .shl => .shl,
                .xor => .xor,
                else => unreachable,
            };
        }

        pub fn to_cast_opcode(self: Tag) CastOpcode {
            return switch (self) {
                .trunc => .trunc,
                .ptrtoint => .ptrtoint,
                .inttoptr => .inttoptr,
                .bitcast => .bitcast,
                .addrspacecast => .addrspacecast,
                else => unreachable,
            };
        }
    };

    pub const Item = struct {
        tag: Tag,
        data: ExtraIndex,

        const ExtraIndex = u32;
    };

    pub const Integer = packed struct(u64) {
        type: Type,
        limbs_len: u32,

        pub const limbs = @div_exact(@bitSizeOf(Integer), @bitSizeOf(std.math.big.Limb));
    };

    pub const Double = struct {
        lo: u32,
        hi: u32,
    };

    pub const Fp80 = struct {
        lo_lo: u32,
        lo_hi: u32,
        hi: u32,
    };

    pub const Fp128 = struct {
        lo_lo: u32,
        lo_hi: u32,
        hi_lo: u32,
        hi_hi: u32,
    };

    pub const Aggregate = struct {
        type: Type,
        //fields: [type.aggregate_len(builder)]Constant,
    };

    pub const Splat = extern struct {
        type: Type,
        value: Constant,
    };

    pub const BlockAddress = extern struct {
        function: Function.Index,
        block: Function.Block.Index,
    };

    pub const Cast = extern struct {
        val: Constant,
        type: Type,

        pub const Signedness = enum { unsigned, signed, unneeded };
    };

    pub const GetElementPtr = struct {
        type: Type,
        base: Constant,
        info: Info,
        //indices: [info.indices_len]Constant,

        pub const Kind = enum { normal, inbounds };
        pub const InRangeIndex = enum(u16) { none = std.math.max_int(u16), _ };
        pub const Info = packed struct(u32) { indices_len: u16, inrange: InRangeIndex };
    };

    pub const Binary = extern struct {
        lhs: Constant,
        rhs: Constant,
    };

    pub const Assembly = extern struct {
        type: Type,
        assembly: String,
        constraints: String,

        pub const Info = packed struct {
            sideeffect: bool = false,
            alignstack: bool = false,
            inteldialect: bool = false,
            unwind: bool = false,
        };
    };

    pub fn unwrap(self: Constant) union(enum) {
        constant: u30,
        global: Global.Index,
    } {
        return if (@int_from_enum(self) < @int_from_enum(first_global))
            .{ .constant = @int_cast(@int_from_enum(self)) }
        else
            .{ .global = @enumFromInt(@int_from_enum(self) - @int_from_enum(first_global)) };
    }

    pub fn to_value(self: Constant) Value {
        return @enumFromInt(Value.first_constant + @int_from_enum(self));
    }

    pub fn type_of(self: Constant, builder: *Builder) Type {
        switch (self.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                return switch (item.tag) {
                    .positive_integer,
                    .negative_integer,
                    => @as(
                        *align(@alignOf(std.math.big.Limb)) Integer,
                        @ptr_cast(builder.constant_limbs.items[item.data..][0..Integer.limbs]),
                    ).type,
                    .half => .half,
                    .bfloat => .bfloat,
                    .float => .float,
                    .double => .double,
                    .fp128 => .fp128,
                    .x86_fp80 => .x86_fp80,
                    .ppc_fp128 => .ppc_fp128,
                    .null,
                    .none,
                    .zeroinitializer,
                    .undef,
                    .poison,
                    => @enumFromInt(item.data),
                    .structure,
                    .packed_structure,
                    .array,
                    .vector,
                    => builder.constant_extra_data(Aggregate, item.data).type,
                    .splat => builder.constant_extra_data(Splat, item.data).type,
                    .string => builder.array_type_assume_capacity(
                        @as(String, @enumFromInt(item.data)).slice(builder).?.len,
                        .i8,
                    ),
                    .blockaddress => builder.ptr_type_assume_capacity(
                        builder.constant_extra_data(BlockAddress, item.data)
                            .function.ptr_const(builder).global.ptr_const(builder).addr_space,
                    ),
                    .dso_local_equivalent,
                    .no_cfi,
                    => builder.ptr_type_assume_capacity(@as(Function.Index, @enumFromInt(item.data))
                        .ptr_const(builder).global.ptr_const(builder).addr_space),
                    .trunc,
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    .addrspacecast,
                    => builder.constant_extra_data(Cast, item.data).type,
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => {
                        var extra = builder.constant_extra_data_trail(GetElementPtr, item.data);
                        const indices =
                            extra.trail.next(extra.data.info.indices_len, Constant, builder);
                        const base_ty = extra.data.base.type_of(builder);
                        if (!base_ty.is_vector(builder)) for (indices) |index| {
                            const index_ty = index.type_of(builder);
                            if (!index_ty.is_vector(builder)) continue;
                            return index_ty.change_scalar_assume_capacity(base_ty, builder);
                        };
                        return base_ty;
                    },
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .shl,
                    .xor,
                    => builder.constant_extra_data(Binary, item.data).lhs.type_of(builder),
                    .@"asm",
                    .@"asm sideeffect",
                    .@"asm alignstack",
                    .@"asm sideeffect alignstack",
                    .@"asm inteldialect",
                    .@"asm sideeffect inteldialect",
                    .@"asm alignstack inteldialect",
                    .@"asm sideeffect alignstack inteldialect",
                    .@"asm unwind",
                    .@"asm sideeffect unwind",
                    .@"asm alignstack unwind",
                    .@"asm sideeffect alignstack unwind",
                    .@"asm inteldialect unwind",
                    .@"asm sideeffect inteldialect unwind",
                    .@"asm alignstack inteldialect unwind",
                    .@"asm sideeffect alignstack inteldialect unwind",
                    => .ptr,
                };
            },
            .global => |global| return builder.ptr_type_assume_capacity(
                global.ptr_const(builder).addr_space,
            ),
        }
    }

    pub fn is_zero_init(self: Constant, builder: *const Builder) bool {
        switch (self.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                return switch (item.tag) {
                    .positive_integer => {
                        const extra: *align(@alignOf(std.math.big.Limb)) Integer =
                            @ptr_cast(builder.constant_limbs.items[item.data..][0..Integer.limbs]);
                        const limbs = builder.constant_limbs
                            .items[item.data + Integer.limbs ..][0..extra.limbs_len];
                        return std.mem.eql(std.math.big.Limb, limbs, &.{0});
                    },
                    .half, .bfloat, .float => item.data == 0,
                    .double => {
                        const extra = builder.constant_extra_data(Constant.Double, item.data);
                        return extra.lo == 0 and extra.hi == 0;
                    },
                    .fp128, .ppc_fp128 => {
                        const extra = builder.constant_extra_data(Constant.Fp128, item.data);
                        return extra.lo_lo == 0 and extra.lo_hi == 0 and
                            extra.hi_lo == 0 and extra.hi_hi == 0;
                    },
                    .x86_fp80 => {
                        const extra = builder.constant_extra_data(Constant.Fp80, item.data);
                        return extra.lo_lo == 0 and extra.lo_hi == 0 and extra.hi == 0;
                    },
                    .vector => {
                        var extra = builder.constant_extra_data_trail(Aggregate, item.data);
                        const len: u32 = @int_cast(extra.data.type.aggregate_len(builder));
                        const vals = extra.trail.next(len, Constant, builder);
                        for (vals) |val| if (!val.is_zero_init(builder)) return false;
                        return true;
                    },
                    .null, .zeroinitializer => true,
                    else => false,
                };
            },
            .global => return false,
        }
    }

    pub fn get_base(self: Constant, builder: *const Builder) Global.Index {
        var cur = self;
        while (true) switch (cur.unwrap()) {
            .constant => |constant| {
                const item = builder.constant_items.get(constant);
                switch (item.tag) {
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    => cur = builder.constant_extra_data(Cast, item.data).val,
                    .getelementptr => cur = builder.constant_extra_data(GetElementPtr, item.data).base,
                    .add => {
                        const extra = builder.constant_extra_data(Binary, item.data);
                        const lhs_base = extra.lhs.get_base(builder);
                        const rhs_base = extra.rhs.get_base(builder);
                        return if (lhs_base != .none and rhs_base != .none)
                            .none
                        else if (lhs_base != .none) lhs_base else rhs_base;
                    },
                    .sub => {
                        const extra = builder.constant_extra_data(Binary, item.data);
                        if (extra.rhs.get_base(builder) != .none) return .none;
                        cur = extra.lhs;
                    },
                    else => return .none,
                }
            },
            .global => |global| switch (global.ptr_const(builder).kind) {
                .alias => |alias| cur = alias.ptr_const(builder).aliasee,
                .variable, .function => return global,
                .replaced => unreachable,
            },
        };
    }

    const FormatData = struct {
        constant: Constant,
        builder: *Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.index_of_none(u8, fmt_str, ", %")) |_|
            @compile_error("invalid format string: '" ++ fmt_str ++ "'");
        if (comptime std.mem.index_of_scalar(u8, fmt_str, ',') != null) {
            if (data.constant == .no_init) return;
            try writer.write_byte(',');
        }
        if (comptime std.mem.index_of_scalar(u8, fmt_str, ' ') != null) {
            if (data.constant == .no_init) return;
            try writer.write_byte(' ');
        }
        if (comptime std.mem.index_of_scalar(u8, fmt_str, '%') != null)
            try writer.print("{%} ", .{data.constant.type_of(data.builder).fmt(data.builder)});
        assert(data.constant != .no_init);
        if (std.enums.tag_name(Constant, data.constant)) |name| return writer.write_all(name);
        switch (data.constant.unwrap()) {
            .constant => |constant| {
                const item = data.builder.constant_items.get(constant);
                switch (item.tag) {
                    .positive_integer,
                    .negative_integer,
                    => |tag| {
                        const extra: *align(@alignOf(std.math.big.Limb)) const Integer =
                            @ptr_cast(data.builder.constant_limbs.items[item.data..][0..Integer.limbs]);
                        const limbs = data.builder.constant_limbs
                            .items[item.data + Integer.limbs ..][0..extra.limbs_len];
                        const bigint: std.math.big.int.Const = .{
                            .limbs = limbs,
                            .positive = switch (tag) {
                                .positive_integer => true,
                                .negative_integer => false,
                                else => unreachable,
                            },
                        };
                        const ExpectedContents = extern struct {
                            const expected_limbs = @div_exact(512, @bitSizeOf(std.math.big.Limb));
                            string: [
                                (std.math.big.int.Const{
                                    .limbs = &([1]std.math.big.Limb{
                                        std.math.max_int(std.math.big.Limb),
                                    } ** expected_limbs),
                                    .positive = false,
                                }).size_in_base_upper_bound(10)
                            ]u8,
                            limbs: [
                                std.math.big.int.calc_to_string_limbs_buffer_len(expected_limbs, 10)
                            ]std.math.big.Limb,
                        };
                        var stack align(@alignOf(ExpectedContents)) =
                            std.heap.stack_fallback(@size_of(ExpectedContents), data.builder.gpa);
                        const allocator = stack.get();
                        const str = try bigint.to_string_alloc(allocator, 10, undefined);
                        defer allocator.free(str);
                        try writer.write_all(str);
                    },
                    .half,
                    .bfloat,
                    => |tag| try writer.print("0x{c}{X:0>4}", .{ @as(u8, switch (tag) {
                        .half => 'H',
                        .bfloat => 'R',
                        else => unreachable,
                    }), item.data >> switch (tag) {
                        .half => 0,
                        .bfloat => 16,
                        else => unreachable,
                    } }),
                    .float => {
                        const Float = struct {
                            fn Repr(comptime T: type) type {
                                return packed struct(std.meta.Int(.unsigned, @bitSizeOf(T))) {
                                    mantissa: std.meta.Int(.unsigned, std.math.float_mantissa_bits(T)),
                                    exponent: std.meta.Int(.unsigned, std.math.float_exponent_bits(T)),
                                    sign: u1,
                                };
                            }
                        };
                        const Mantissa64 = std.meta.FieldType(Float.Repr(f64), .mantissa);
                        const Exponent32 = std.meta.FieldType(Float.Repr(f32), .exponent);
                        const Exponent64 = std.meta.FieldType(Float.Repr(f64), .exponent);

                        const repr: Float.Repr(f32) = @bit_cast(item.data);
                        const denormal_shift = switch (repr.exponent) {
                            std.math.min_int(Exponent32) => @as(
                                std.math.Log2Int(Mantissa64),
                                @clz(repr.mantissa),
                            ) + 1,
                            else => 0,
                        };
                        try writer.print("0x{X:0>16}", .{@as(u64, @bit_cast(Float.Repr(f64){
                            .mantissa = std.math.shl(
                                Mantissa64,
                                repr.mantissa,
                                std.math.float_mantissa_bits(f64) - std.math.float_mantissa_bits(f32) +
                                    denormal_shift,
                            ),
                            .exponent = switch (repr.exponent) {
                                std.math.min_int(Exponent32) => if (repr.mantissa > 0)
                                    @as(Exponent64, std.math.float_exponent_min(f32) +
                                        std.math.float_exponent_max(f64)) - denormal_shift
                                else
                                    std.math.min_int(Exponent64),
                                else => @as(Exponent64, repr.exponent) +
                                    (std.math.float_exponent_max(f64) - std.math.float_exponent_max(f32)),
                                std.math.max_int(Exponent32) => std.math.max_int(Exponent64),
                            },
                            .sign = repr.sign,
                        }))});
                    },
                    .double => {
                        const extra = data.builder.constant_extra_data(Double, item.data);
                        try writer.print("0x{X:0>8}{X:0>8}", .{ extra.hi, extra.lo });
                    },
                    .fp128,
                    .ppc_fp128,
                    => |tag| {
                        const extra = data.builder.constant_extra_data(Fp128, item.data);
                        try writer.print("0x{c}{X:0>8}{X:0>8}{X:0>8}{X:0>8}", .{
                            @as(u8, switch (tag) {
                                .fp128 => 'L',
                                .ppc_fp128 => 'M',
                                else => unreachable,
                            }),
                            extra.lo_hi,
                            extra.lo_lo,
                            extra.hi_hi,
                            extra.hi_lo,
                        });
                    },
                    .x86_fp80 => {
                        const extra = data.builder.constant_extra_data(Fp80, item.data);
                        try writer.print("0xK{X:0>4}{X:0>8}{X:0>8}", .{
                            extra.hi, extra.lo_hi, extra.lo_lo,
                        });
                    },
                    .null,
                    .none,
                    .zeroinitializer,
                    .undef,
                    .poison,
                    => |tag| try writer.write_all(@tag_name(tag)),
                    .structure,
                    .packed_structure,
                    .array,
                    .vector,
                    => |tag| {
                        var extra = data.builder.constant_extra_data_trail(Aggregate, item.data);
                        const len: u32 = @int_cast(extra.data.type.aggregate_len(data.builder));
                        const vals = extra.trail.next(len, Constant, data.builder);
                        try writer.write_all(switch (tag) {
                            .structure => "{ ",
                            .packed_structure => "<{ ",
                            .array => "[",
                            .vector => "<",
                            else => unreachable,
                        });
                        for (vals, 0..) |val, index| {
                            if (index > 0) try writer.write_all(", ");
                            try writer.print("{%}", .{val.fmt(data.builder)});
                        }
                        try writer.write_all(switch (tag) {
                            .structure => " }",
                            .packed_structure => " }>",
                            .array => "]",
                            .vector => ">",
                            else => unreachable,
                        });
                    },
                    .splat => {
                        const extra = data.builder.constant_extra_data(Splat, item.data);
                        const len = extra.type.vector_len(data.builder);
                        try writer.write_byte('<');
                        for (0..len) |index| {
                            if (index > 0) try writer.write_all(", ");
                            try writer.print("{%}", .{extra.value.fmt(data.builder)});
                        }
                        try writer.write_byte('>');
                    },
                    .string => try writer.print("c{\"}", .{
                        @as(String, @enumFromInt(item.data)).fmt(data.builder),
                    }),
                    .blockaddress => |tag| {
                        const extra = data.builder.constant_extra_data(BlockAddress, item.data);
                        const function = extra.function.ptr_const(data.builder);
                        try writer.print("{s}({}, %{d})", .{
                            @tag_name(tag),
                            function.global.fmt(data.builder),
                            @int_from_enum(extra.block), // TODO
                        });
                    },
                    .dso_local_equivalent,
                    .no_cfi,
                    => |tag| {
                        const function: Function.Index = @enumFromInt(item.data);
                        try writer.print("{s} {}", .{
                            @tag_name(tag),
                            function.ptr_const(data.builder).global.fmt(data.builder),
                        });
                    },
                    .trunc,
                    .ptrtoint,
                    .inttoptr,
                    .bitcast,
                    .addrspacecast,
                    => |tag| {
                        const extra = data.builder.constant_extra_data(Cast, item.data);
                        try writer.print("{s} ({%} to {%})", .{
                            @tag_name(tag),
                            extra.val.fmt(data.builder),
                            extra.type.fmt(data.builder),
                        });
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = data.builder.constant_extra_data_trail(GetElementPtr, item.data);
                        const indices =
                            extra.trail.next(extra.data.info.indices_len, Constant, data.builder);
                        try writer.print("{s} ({%}, {%}", .{
                            @tag_name(tag),
                            extra.data.type.fmt(data.builder),
                            extra.data.base.fmt(data.builder),
                        });
                        for (indices) |index| try writer.print(", {%}", .{index.fmt(data.builder)});
                        try writer.write_byte(')');
                    },
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .shl,
                    .xor,
                    => |tag| {
                        const extra = data.builder.constant_extra_data(Binary, item.data);
                        try writer.print("{s} ({%}, {%})", .{
                            @tag_name(tag),
                            extra.lhs.fmt(data.builder),
                            extra.rhs.fmt(data.builder),
                        });
                    },
                    .@"asm",
                    .@"asm sideeffect",
                    .@"asm alignstack",
                    .@"asm sideeffect alignstack",
                    .@"asm inteldialect",
                    .@"asm sideeffect inteldialect",
                    .@"asm alignstack inteldialect",
                    .@"asm sideeffect alignstack inteldialect",
                    .@"asm unwind",
                    .@"asm sideeffect unwind",
                    .@"asm alignstack unwind",
                    .@"asm sideeffect alignstack unwind",
                    .@"asm inteldialect unwind",
                    .@"asm sideeffect inteldialect unwind",
                    .@"asm alignstack inteldialect unwind",
                    .@"asm sideeffect alignstack inteldialect unwind",
                    => |tag| {
                        const extra = data.builder.constant_extra_data(Assembly, item.data);
                        try writer.print("{s} {\"}, {\"}", .{
                            @tag_name(tag),
                            extra.assembly.fmt(data.builder),
                            extra.constraints.fmt(data.builder),
                        });
                    },
                }
            },
            .global => |global| try writer.print("{}", .{global.fmt(data.builder)}),
        }
    }
    pub fn fmt(self: Constant, builder: *Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .constant = self, .builder = builder } };
    }
};

pub const Value = enum(u32) {
    none = std.math.max_int(u31),
    false = first_constant + @int_from_enum(Constant.false),
    true = first_constant + @int_from_enum(Constant.true),
    @"0" = first_constant + @int_from_enum(Constant.@"0"),
    @"1" = first_constant + @int_from_enum(Constant.@"1"),
    _,

    const first_constant = 1 << 30;
    const first_metadata = 1 << 31;

    pub fn unwrap(self: Value) union(enum) {
        instruction: Function.Instruction.Index,
        constant: Constant,
        metadata: Metadata,
    } {
        return if (@int_from_enum(self) < first_constant)
            .{ .instruction = @enumFromInt(@int_from_enum(self)) }
        else if (@int_from_enum(self) < first_metadata)
            .{ .constant = @enumFromInt(@int_from_enum(self) - first_constant) }
        else
            .{ .metadata = @enumFromInt(@int_from_enum(self) - first_metadata) };
    }

    pub fn type_of_wip(self: Value, wip: *const WipFunction) Type {
        return switch (self.unwrap()) {
            .instruction => |instruction| instruction.type_of_wip(wip),
            .constant => |constant| constant.type_of(wip.builder),
            .metadata => .metadata,
        };
    }

    pub fn type_of(self: Value, function: Function.Index, builder: *Builder) Type {
        return switch (self.unwrap()) {
            .instruction => |instruction| instruction.type_of(function, builder),
            .constant => |constant| constant.type_of(builder),
            .metadata => .metadata,
        };
    }

    pub fn to_const(self: Value) ?Constant {
        return switch (self.unwrap()) {
            .instruction, .metadata => null,
            .constant => |constant| constant,
        };
    }

    const FormatData = struct {
        value: Value,
        function: Function.Index,
        builder: *Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (data.value.unwrap()) {
            .instruction => |instruction| try Function.Instruction.Index.format(.{
                .instruction = instruction,
                .function = data.function,
                .builder = data.builder,
            }, fmt_str, fmt_opts, writer),
            .constant => |constant| try Constant.format(.{
                .constant = constant,
                .builder = data.builder,
            }, fmt_str, fmt_opts, writer),
            .metadata => unreachable,
        }
    }
    pub fn fmt(self: Value, function: Function.Index, builder: *Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .value = self, .function = function, .builder = builder } };
    }
};

pub const MetadataString = enum(u32) {
    none = 0,
    _,

    pub fn slice(self: MetadataString, builder: *const Builder) []const u8 {
        const index = @int_from_enum(self);
        const start = builder.metadata_string_indices.items[index];
        const end = builder.metadata_string_indices.items[index + 1];
        return builder.metadata_string_bytes.items[start..end];
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            const rhs_metadata_string: MetadataString = @enumFromInt(rhs_index);
            return std.mem.eql(u8, lhs_key, rhs_metadata_string.slice(ctx.builder));
        }
    };

    const FormatData = struct {
        metadata_string: MetadataString,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try print_escaped_string(data.metadata_string.slice(data.builder), .always_quote, writer);
    }
    fn fmt(self: MetadataString, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .metadata_string = self, .builder = builder } };
    }
};

pub const Metadata = enum(u32) {
    none = 0,
    _,

    const first_forward_reference = 1 << 29;
    const first_local_metadata = 1 << 30;

    pub const Tag = enum(u6) {
        none,
        file,
        compile_unit,
        @"compile_unit optimized",
        subprogram,
        @"subprogram local",
        @"subprogram definition",
        @"subprogram local definition",
        @"subprogram optimized",
        @"subprogram optimized local",
        @"subprogram optimized definition",
        @"subprogram optimized local definition",
        lexical_block,
        location,
        basic_bool_type,
        basic_unsigned_type,
        basic_signed_type,
        basic_float_type,
        composite_struct_type,
        composite_union_type,
        composite_enumeration_type,
        composite_array_type,
        composite_vector_type,
        derived_pointer_type,
        derived_member_type,
        subroutine_type,
        enumerator_unsigned,
        enumerator_signed_positive,
        enumerator_signed_negative,
        subrange,
        tuple,
        module_flag,
        expression,
        local_var,
        parameter,
        global_var,
        @"global_var local",
        global_var_expression,
        constant,

        pub fn is_inline(tag: Tag) bool {
            return switch (tag) {
                .none,
                .expression,
                .constant,
                => true,
                .file,
                .compile_unit,
                .@"compile_unit optimized",
                .subprogram,
                .@"subprogram local",
                .@"subprogram definition",
                .@"subprogram local definition",
                .@"subprogram optimized",
                .@"subprogram optimized local",
                .@"subprogram optimized definition",
                .@"subprogram optimized local definition",
                .lexical_block,
                .location,
                .basic_bool_type,
                .basic_unsigned_type,
                .basic_signed_type,
                .basic_float_type,
                .composite_struct_type,
                .composite_union_type,
                .composite_enumeration_type,
                .composite_array_type,
                .composite_vector_type,
                .derived_pointer_type,
                .derived_member_type,
                .subroutine_type,
                .enumerator_unsigned,
                .enumerator_signed_positive,
                .enumerator_signed_negative,
                .subrange,
                .tuple,
                .module_flag,
                .local_var,
                .parameter,
                .global_var,
                .@"global_var local",
                .global_var_expression,
                => false,
            };
        }
    };

    pub fn is_inline(self: Metadata, builder: *const Builder) bool {
        return builder.metadata_items.items(.tag)[@int_from_enum(self)].is_inline();
    }

    pub fn unwrap(self: Metadata, builder: *const Builder) Metadata {
        var metadata = self;
        while (@int_from_enum(metadata) >= Metadata.first_forward_reference and
            @int_from_enum(metadata) < Metadata.first_local_metadata)
        {
            const index = @int_from_enum(metadata) - Metadata.first_forward_reference;
            metadata = builder.metadata_forward_references.items[index];
            assert(metadata != .none);
        }
        return metadata;
    }

    pub const Item = struct {
        tag: Tag,
        data: ExtraIndex,

        const ExtraIndex = u32;
    };

    pub const DIFlags = packed struct(u32) {
        Visibility: enum(u2) { Zero, Private, Protected, Public } = .Zero,
        FwdDecl: bool = false,
        AppleBlock: bool = false,
        ReservedBit4: u1 = 0,
        Virtual: bool = false,
        Artificial: bool = false,
        Explicit: bool = false,
        Prototyped: bool = false,
        ObjcClassComplete: bool = false,
        ObjectPointer: bool = false,
        Vector: bool = false,
        StaticMember: bool = false,
        LValueReference: bool = false,
        RValueReference: bool = false,
        ExportSymbols: bool = false,
        Inheritance: enum(u2) {
            Zero,
            SingleInheritance,
            MultipleInheritance,
            VirtualInheritance,
        } = .Zero,
        IntroducedVirtual: bool = false,
        BitField: bool = false,
        NoReturn: bool = false,
        ReservedBit21: u1 = 0,
        TypePassbyValue: bool = false,
        TypePassbyReference: bool = false,
        EnumClass: bool = false,
        Thunk: bool = false,
        NonTrivial: bool = false,
        BigEndian: bool = false,
        LittleEndian: bool = false,
        AllCallsDescribed: bool = false,
        Unused: u2 = 0,

        pub fn format(
            self: DIFlags,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            var need_pipe = false;
            inline for (@typeInfo(DIFlags).Struct.fields) |field| {
                switch (@typeInfo(field.type)) {
                    .Bool => if (@field(self, field.name)) {
                        if (need_pipe) try writer.write_all(" | ") else need_pipe = true;
                        try writer.print("DIFlag{s}", .{field.name});
                    },
                    .Enum => if (@field(self, field.name) != .Zero) {
                        if (need_pipe) try writer.write_all(" | ") else need_pipe = true;
                        try writer.print("DIFlag{s}", .{@tag_name(@field(self, field.name))});
                    },
                    .Int => assert(@field(self, field.name) == 0),
                    else => @compile_error("bad field type: " ++ field.name ++ ": " ++
                        @type_name(field.type)),
                }
            }
            if (!need_pipe) try writer.write_byte('0');
        }
    };

    pub const File = struct {
        filename: MetadataString,
        directory: MetadataString,
    };

    pub const CompileUnit = struct {
        pub const Options = struct {
            optimized: bool,
        };

        file: Metadata,
        producer: MetadataString,
        enums: Metadata,
        globals: Metadata,
    };

    pub const Subprogram = struct {
        pub const Options = struct {
            di_flags: DIFlags,
            sp_flags: DISPFlags,
        };

        pub const DISPFlags = packed struct(u32) {
            Virtuality: enum(u2) { Zero, Virtual, PureVirtual } = .Zero,
            LocalToUnit: bool = false,
            Definition: bool = false,
            Optimized: bool = false,
            Pure: bool = false,
            Elemental: bool = false,
            Recursive: bool = false,
            MainSubprogram: bool = false,
            Deleted: bool = false,
            ReservedBit10: u1 = 0,
            ObjCDirect: bool = false,
            Unused: u20 = 0,

            pub fn format(
                self: DISPFlags,
                comptime _: []const u8,
                _: std.fmt.FormatOptions,
                writer: anytype,
            ) @TypeOf(writer).Error!void {
                var need_pipe = false;
                inline for (@typeInfo(DISPFlags).Struct.fields) |field| {
                    switch (@typeInfo(field.type)) {
                        .Bool => if (@field(self, field.name)) {
                            if (need_pipe) try writer.write_all(" | ") else need_pipe = true;
                            try writer.print("DISPFlag{s}", .{field.name});
                        },
                        .Enum => if (@field(self, field.name) != .Zero) {
                            if (need_pipe) try writer.write_all(" | ") else need_pipe = true;
                            try writer.print("DISPFlag{s}", .{@tag_name(@field(self, field.name))});
                        },
                        .Int => assert(@field(self, field.name) == 0),
                        else => @compile_error("bad field type: " ++ field.name ++ ": " ++
                            @type_name(field.type)),
                    }
                }
                if (!need_pipe) try writer.write_byte('0');
            }
        };

        file: Metadata,
        name: MetadataString,
        linkage_name: MetadataString,
        line: u32,
        scope_line: u32,
        ty: Metadata,
        di_flags: DIFlags,
        compile_unit: Metadata,
    };

    pub const LexicalBlock = struct {
        scope: Metadata,
        file: Metadata,
        line: u32,
        column: u32,
    };

    pub const Location = struct {
        line: u32,
        column: u32,
        scope: Metadata,
        inlined_at: Metadata,
    };

    pub const BasicType = struct {
        name: MetadataString,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,

        pub fn bit_size(self: BasicType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
    };

    pub const CompositeType = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        underlying_type: Metadata,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,
        align_in_bits_lo: u32,
        align_in_bits_hi: u32,
        fields_tuple: Metadata,

        pub fn bit_size(self: CompositeType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
        pub fn bit_align(self: CompositeType) u64 {
            return @as(u64, self.align_in_bits_hi) << 32 | self.align_in_bits_lo;
        }
    };

    pub const DerivedType = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        underlying_type: Metadata,
        size_in_bits_lo: u32,
        size_in_bits_hi: u32,
        align_in_bits_lo: u32,
        align_in_bits_hi: u32,
        offset_in_bits_lo: u32,
        offset_in_bits_hi: u32,

        pub fn bit_size(self: DerivedType) u64 {
            return @as(u64, self.size_in_bits_hi) << 32 | self.size_in_bits_lo;
        }
        pub fn bit_align(self: DerivedType) u64 {
            return @as(u64, self.align_in_bits_hi) << 32 | self.align_in_bits_lo;
        }
        pub fn bit_offset(self: DerivedType) u64 {
            return @as(u64, self.offset_in_bits_hi) << 32 | self.offset_in_bits_lo;
        }
    };

    pub const SubroutineType = struct {
        types_tuple: Metadata,
    };

    pub const Enumerator = struct {
        name: MetadataString,
        bit_width: u32,
        limbs_index: u32,
        limbs_len: u32,
    };

    pub const Subrange = struct {
        lower_bound: Metadata,
        count: Metadata,
    };

    pub const Expression = struct {
        elements_len: u32,

        // elements: [elements_len]u32
    };

    pub const Tuple = struct {
        elements_len: u32,

        // elements: [elements_len]Metadata
    };

    pub const ModuleFlag = struct {
        behavior: Metadata,
        name: MetadataString,
        constant: Metadata,
    };

    pub const LocalVar = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
    };

    pub const Parameter = struct {
        name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
        arg_no: u32,
    };

    pub const GlobalVar = struct {
        pub const Options = struct {
            local: bool,
        };

        name: MetadataString,
        linkage_name: MetadataString,
        file: Metadata,
        scope: Metadata,
        line: u32,
        ty: Metadata,
        variable: Variable.Index,
    };

    pub const GlobalVarExpression = struct {
        variable: Metadata,
        expression: Metadata,
    };

    pub fn to_value(self: Metadata) Value {
        return @enumFromInt(Value.first_metadata + @int_from_enum(self));
    }

    const Formatter = struct {
        builder: *Builder,
        need_comma: bool,
        map: std.AutoArrayHashMapUnmanaged(union(enum) {
            metadata: Metadata,
            debug_location: DebugLocation.Location,
        }, void) = .{},

        const FormatData = struct {
            formatter: *Formatter,
            prefix: []const u8 = "",
            node: Node,

            const Node = union(enum) {
                none,
                @"inline": Metadata,
                index: u32,

                local_value: ValueData,
                local_metadata: ValueData,
                local_inline: Metadata,
                local_index: u32,

                string: MetadataString,
                bool: bool,
                u32: u32,
                u64: u64,
                di_flags: DIFlags,
                sp_flags: Subprogram.DISPFlags,
                raw: []const u8,

                const ValueData = struct {
                    value: Value,
                    function: Function.Index,
                };
            };
        };
        fn format(
            data: FormatData,
            comptime fmt_str: []const u8,
            fmt_opts: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (data.node == .none) return;

            const is_specialized = fmt_str.len > 0 and fmt_str[0] == 'S';
            const recurse_fmt_str = if (is_specialized) fmt_str[1..] else fmt_str;

            if (data.formatter.need_comma) try writer.write_all(", ");
            defer data.formatter.need_comma = true;
            try writer.write_all(data.prefix);

            const builder = data.formatter.builder;
            switch (data.node) {
                .none => unreachable,
                .@"inline" => |node| {
                    const needed_comma = data.formatter.need_comma;
                    defer data.formatter.need_comma = needed_comma;
                    data.formatter.need_comma = false;

                    const item = builder.metadata_items.get(@int_from_enum(node));
                    switch (item.tag) {
                        .expression => {
                            var extra = builder.metadata_extra_data_trail(Expression, item.data);
                            const elements = extra.trail.next(extra.data.elements_len, u32, builder);
                            try writer.write_all("!DIExpression(");
                            for (elements) |element| try format(.{
                                .formatter = data.formatter,
                                .node = .{ .u64 = element },
                            }, "%", fmt_opts, writer);
                            try writer.write_byte(')');
                        },
                        .constant => try Constant.format(.{
                            .constant = @enumFromInt(item.data),
                            .builder = builder,
                        }, recurse_fmt_str, fmt_opts, writer),
                        else => unreachable,
                    }
                },
                .index => |node| try writer.print("!{d}", .{node}),
                inline .local_value, .local_metadata => |node, tag| try Value.format(.{
                    .value = node.value,
                    .function = node.function,
                    .builder = builder,
                }, switch (tag) {
                    .local_value => recurse_fmt_str,
                    .local_metadata => "%",
                    else => unreachable,
                }, fmt_opts, writer),
                inline .local_inline, .local_index => |node, tag| {
                    if (comptime std.mem.eql(u8, recurse_fmt_str, "%"))
                        try writer.print("{%} ", .{Type.metadata.fmt(builder)});
                    try format(.{
                        .formatter = data.formatter,
                        .node = @union_init(FormatData.Node, @tag_name(tag)["local_".len..], node),
                    }, "%", fmt_opts, writer);
                },
                .string => |node| try writer.print((if (is_specialized) "" else "!") ++ "{}", .{
                    node.fmt(builder),
                }),
                inline .bool,
                .u32,
                .u64,
                .di_flags,
                .sp_flags,
                => |node| try writer.print("{}", .{node}),
                .raw => |node| try writer.write_all(node),
            }
        }
        inline fn fmt(formatter: *Formatter, prefix: []const u8, node: anytype) switch (@TypeOf(node)) {
            Metadata => Allocator.Error,
            else => error{},
        }!std.fmt.Formatter(format) {
            const Node = @TypeOf(node);
            const MaybeNode = switch (@typeInfo(Node)) {
                .Optional => Node,
                .Null => ?noreturn,
                else => ?Node,
            };
            const Some = @typeInfo(MaybeNode).Optional.child;
            return .{ .data = .{
                .formatter = formatter,
                .prefix = prefix,
                .node = if (@as(MaybeNode, node)) |some| switch (@typeInfo(Some)) {
                    .Enum => |enum_info| switch (Some) {
                        Metadata => switch (some) {
                            .none => .none,
                            else => try formatter.ref_unwrapped(some.unwrap(formatter.builder)),
                        },
                        MetadataString => .{ .string = some },
                        else => if (enum_info.is_exhaustive)
                            .{ .raw = @tag_name(some) }
                        else
                            @compile_error("unknown type to format: " ++ @type_name(Node)),
                    },
                    .EnumLiteral => .{ .raw = @tag_name(some) },
                    .Bool => .{ .bool = some },
                    .Struct => switch (Some) {
                        DIFlags => .{ .di_flags = some },
                        Subprogram.DISPFlags => .{ .sp_flags = some },
                        else => @compile_error("unknown type to format: " ++ @type_name(Node)),
                    },
                    .Int, .ComptimeInt => .{ .u64 = some },
                    .Pointer => .{ .raw = some },
                    else => @compile_error("unknown type to format: " ++ @type_name(Node)),
                } else switch (@typeInfo(Node)) {
                    .Optional, .Null => .none,
                    else => unreachable,
                },
            } };
        }
        inline fn fmt_local(
            formatter: *Formatter,
            prefix: []const u8,
            value: Value,
            function: Function.Index,
        ) Allocator.Error!std.fmt.Formatter(format) {
            return .{ .data = .{
                .formatter = formatter,
                .prefix = prefix,
                .node = switch (value.unwrap()) {
                    .instruction, .constant => .{ .local_value = .{
                        .value = value,
                        .function = function,
                    } },
                    .metadata => |metadata| if (value == .none) .none else node: {
                        const unwrapped = metadata.unwrap(formatter.builder);
                        break :node if (@int_from_enum(unwrapped) >= first_local_metadata)
                            .{ .local_metadata = .{
                                .value = function.ptr_const(formatter.builder).debug_values[
                                    @int_from_enum(unwrapped) - first_local_metadata
                                ].to_value(),
                                .function = function,
                            } }
                        else switch (try formatter.ref_unwrapped(unwrapped)) {
                            .@"inline" => |node| .{ .local_inline = node },
                            .index => |node| .{ .local_index = node },
                            else => unreachable,
                        };
                    },
                },
            } };
        }
        fn ref_unwrapped(formatter: *Formatter, node: Metadata) Allocator.Error!FormatData.Node {
            assert(node != .none);
            assert(@int_from_enum(node) < first_forward_reference);
            const builder = formatter.builder;
            const unwrapped_metadata = node.unwrap(builder);
            const tag = formatter.builder.metadata_items.items(.tag)[@int_from_enum(unwrapped_metadata)];
            switch (tag) {
                .none => unreachable,
                .expression, .constant => return .{ .@"inline" = unwrapped_metadata },
                else => {
                    assert(!tag.is_inline());
                    const gop = try formatter.map.get_or_put(builder.gpa, .{ .metadata = unwrapped_metadata });
                    return .{ .index = @int_cast(gop.index) };
                },
            }
        }

        inline fn specialized(
            formatter: *Formatter,
            distinct: enum { @"!", @"distinct !" },
            node: enum {
                DIFile,
                DICompileUnit,
                DISubprogram,
                DILexicalBlock,
                DILocation,
                DIBasicType,
                DICompositeType,
                DIDerivedType,
                DISubroutineType,
                DIEnumerator,
                DISubrange,
                DILocalVariable,
                DIGlobalVariable,
                DIGlobalVariableExpression,
            },
            nodes: anytype,
            writer: anytype,
        ) !void {
            comptime var fmt_str: []const u8 = "";
            const names = comptime std.meta.field_names(@TypeOf(nodes));
            comptime var fields: [2 + names.len]std.builtin.Type.StructField = undefined;
            inline for (fields[0..2], .{ "distinct", "node" }) |*field, name| {
                fmt_str = fmt_str ++ "{[" ++ name ++ "]s}";
                field.* = .{
                    .name = name,
                    .type = []const u8,
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                };
            }
            fmt_str = fmt_str ++ "(";
            inline for (fields[2..], names) |*field, name| {
                fmt_str = fmt_str ++ "{[" ++ name ++ "]S}";
                field.* = .{
                    .name = name,
                    .type = std.fmt.Formatter(format),
                    .default_value = null,
                    .is_comptime = false,
                    .alignment = 0,
                };
            }
            fmt_str = fmt_str ++ ")\n";

            var fmt_args: @Type(.{ .Struct = .{
                .layout = .auto,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            } }) = undefined;
            fmt_args.distinct = @tag_name(distinct);
            fmt_args.node = @tag_name(node);
            inline for (names) |name| @field(fmt_args, name) = try formatter.fmt(
                name ++ ": ",
                @field(nodes, name),
            );
            try writer.print(fmt_str, fmt_args);
        }
    };
};

pub fn init(options: Options) Allocator.Error!Builder {
    var self = Builder{
        .gpa = options.allocator,
        .strip = options.strip,

        .source_filename = .none,
        .data_layout = .none,
        .target_triple = .none,
        .module_asm = .{},

        .string_map = .{},
        .string_indices = .{},
        .string_bytes = .{},

        .types = .{},
        .next_unnamed_type = @enumFromInt(0),
        .next_unique_type_id = .{},
        .type_map = .{},
        .type_items = .{},
        .type_extra = .{},

        .attributes = .{},
        .attributes_map = .{},
        .attributes_indices = .{},
        .attributes_extra = .{},

        .function_attributes_set = .{},

        .globals = .{},
        .next_unnamed_global = @enumFromInt(0),
        .next_replaced_global = .none,
        .next_unique_global_id = .{},
        .aliases = .{},
        .variables = .{},
        .functions = .{},

        .strtab_string_map = .{},
        .strtab_string_indices = .{},
        .strtab_string_bytes = .{},

        .constant_map = .{},
        .constant_items = .{},
        .constant_extra = .{},
        .constant_limbs = .{},

        .metadata_map = .{},
        .metadata_items = .{},
        .metadata_extra = .{},
        .metadata_limbs = .{},
        .metadata_forward_references = .{},
        .metadata_named = .{},
        .metadata_string_map = .{},
        .metadata_string_indices = .{},
        .metadata_string_bytes = .{},
    };
    errdefer self.deinit();

    try self.string_indices.append(self.gpa, 0);
    assert(try self.string("") == .empty);

    try self.strtab_string_indices.append(self.gpa, 0);
    assert(try self.strtab_string("") == .empty);

    if (options.name.len > 0) self.source_filename = try self.string(options.name);

    if (options.triple.len > 0) {
        self.target_triple = try self.string(options.triple);
    }

    {
        const static_len = @typeInfo(Type).Enum.fields.len - 1;
        try self.type_map.ensure_total_capacity(self.gpa, static_len);
        try self.type_items.ensure_total_capacity(self.gpa, static_len);
        inline for (@typeInfo(Type.Simple).Enum.fields) |simple_field| {
            const result = self.get_or_put_type_no_extra_assume_capacity(
                .{ .tag = .simple, .data = simple_field.value },
            );
            assert(result.new and result.type == @field(Type, simple_field.name));
        }
        inline for (.{ 1, 8, 16, 29, 32, 64, 80, 128 }) |bits|
            assert(self.int_type_assume_capacity(bits) ==
                @field(Type, std.fmt.comptime_print("i{d}", .{bits})));
        inline for (.{ 0, 4 }) |addr_space_index| {
            const addr_space: AddrSpace = @enumFromInt(addr_space_index);
            assert(self.ptr_type_assume_capacity(addr_space) ==
                @field(Type, std.fmt.comptime_print("ptr{ }", .{addr_space})));
        }
    }

    {
        try self.attributes_indices.append(self.gpa, 0);
        assert(try self.attrs(&.{}) == .none);
        assert(try self.fn_attrs(&.{}) == .none);
    }

    assert(try self.int_const(.i1, 0) == .false);
    assert(try self.int_const(.i1, 1) == .true);
    assert(try self.int_const(.i32, 0) == .@"0");
    assert(try self.int_const(.i32, 1) == .@"1");
    assert(try self.none_const(.token) == .none);
    if (!self.strip) assert(try self.debug_none() == .none);

    try self.metadata_string_indices.append(self.gpa, 0);
    assert(try self.metadata_string("") == .none);

    return self;
}

pub fn clear_and_free(self: *Builder) void {
    self.module_asm.clear_and_free(self.gpa);

    self.string_map.clear_and_free(self.gpa);
    self.string_indices.clear_and_free(self.gpa);
    self.string_bytes.clear_and_free(self.gpa);

    self.types.clear_and_free(self.gpa);
    self.next_unique_type_id.clear_and_free(self.gpa);
    self.type_map.clear_and_free(self.gpa);
    self.type_items.clear_and_free(self.gpa);
    self.type_extra.clear_and_free(self.gpa);

    self.attributes.clear_and_free(self.gpa);
    self.attributes_map.clear_and_free(self.gpa);
    self.attributes_indices.clear_and_free(self.gpa);
    self.attributes_extra.clear_and_free(self.gpa);

    self.function_attributes_set.clear_and_free(self.gpa);

    self.globals.clear_and_free(self.gpa);
    self.next_unique_global_id.clear_and_free(self.gpa);
    self.aliases.clear_and_free(self.gpa);
    self.variables.clear_and_free(self.gpa);
    for (self.functions.items) |*function| function.deinit(self.gpa);
    self.functions.clear_and_free(self.gpa);

    self.strtab_string_map.clear_and_free(self.gpa);
    self.strtab_string_indices.clear_and_free(self.gpa);
    self.strtab_string_bytes.clear_and_free(self.gpa);

    self.constant_map.clear_and_free(self.gpa);
    self.constant_items.shrink_and_free(self.gpa, 0);
    self.constant_extra.clear_and_free(self.gpa);
    self.constant_limbs.clear_and_free(self.gpa);

    self.metadata_map.clear_and_free(self.gpa);
    self.metadata_items.shrink_and_free(self.gpa, 0);
    self.metadata_extra.clear_and_free(self.gpa);
    self.metadata_limbs.clear_and_free(self.gpa);
    self.metadata_forward_references.clear_and_free(self.gpa);
    self.metadata_named.clear_and_free(self.gpa);

    self.metadata_string_map.clear_and_free(self.gpa);
    self.metadata_string_indices.clear_and_free(self.gpa);
    self.metadata_string_bytes.clear_and_free(self.gpa);
}

pub fn deinit(self: *Builder) void {
    self.module_asm.deinit(self.gpa);

    self.string_map.deinit(self.gpa);
    self.string_indices.deinit(self.gpa);
    self.string_bytes.deinit(self.gpa);

    self.types.deinit(self.gpa);
    self.next_unique_type_id.deinit(self.gpa);
    self.type_map.deinit(self.gpa);
    self.type_items.deinit(self.gpa);
    self.type_extra.deinit(self.gpa);

    self.attributes.deinit(self.gpa);
    self.attributes_map.deinit(self.gpa);
    self.attributes_indices.deinit(self.gpa);
    self.attributes_extra.deinit(self.gpa);

    self.function_attributes_set.deinit(self.gpa);

    self.globals.deinit(self.gpa);
    self.next_unique_global_id.deinit(self.gpa);
    self.aliases.deinit(self.gpa);
    self.variables.deinit(self.gpa);
    for (self.functions.items) |*function| function.deinit(self.gpa);
    self.functions.deinit(self.gpa);

    self.strtab_string_map.deinit(self.gpa);
    self.strtab_string_indices.deinit(self.gpa);
    self.strtab_string_bytes.deinit(self.gpa);

    self.constant_map.deinit(self.gpa);
    self.constant_items.deinit(self.gpa);
    self.constant_extra.deinit(self.gpa);
    self.constant_limbs.deinit(self.gpa);

    self.metadata_map.deinit(self.gpa);
    self.metadata_items.deinit(self.gpa);
    self.metadata_extra.deinit(self.gpa);
    self.metadata_limbs.deinit(self.gpa);
    self.metadata_forward_references.deinit(self.gpa);
    self.metadata_named.deinit(self.gpa);

    self.metadata_string_map.deinit(self.gpa);
    self.metadata_string_indices.deinit(self.gpa);
    self.metadata_string_bytes.deinit(self.gpa);

    self.* = undefined;
}

pub fn set_module_asm(self: *Builder) std.ArrayListUnmanaged(u8).Writer {
    self.module_asm.clear_retaining_capacity();
    return self.append_module_asm();
}

pub fn append_module_asm(self: *Builder) std.ArrayListUnmanaged(u8).Writer {
    return self.module_asm.writer(self.gpa);
}

pub fn finish_module_asm(self: *Builder) Allocator.Error!void {
    if (self.module_asm.get_last_or_null()) |last| if (last != '\n')
        try self.module_asm.append(self.gpa, '\n');
}

pub fn string(self: *Builder, bytes: []const u8) Allocator.Error!String {
    try self.string_bytes.ensure_unused_capacity(self.gpa, bytes.len);
    try self.string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.string_map.ensure_unused_capacity(self.gpa, 1);

    const gop = self.string_map.get_or_put_assume_capacity_adapted(bytes, String.Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.string_bytes.append_slice_assume_capacity(bytes);
        self.string_indices.append_assume_capacity(@int_cast(self.string_bytes.items.len));
    }
    return String.from_index(gop.index);
}

pub fn string_null(self: *Builder, bytes: [:0]const u8) Allocator.Error!String {
    return self.string(bytes[0 .. bytes.len + 1]);
}

pub fn string_if_exists(self: *const Builder, bytes: []const u8) ?String {
    return String.from_index(
        self.string_map.get_index_adapted(bytes, String.Adapter{ .builder = self }) orelse return null,
    );
}

pub fn fmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!String {
    try self.string_map.ensure_unused_capacity(self.gpa, 1);
    try self.string_bytes.ensure_unused_capacity(self.gpa, @int_cast(std.fmt.count(fmt_str, fmt_args)));
    try self.string_indices.ensure_unused_capacity(self.gpa, 1);
    return self.fmt_assume_capacity(fmt_str, fmt_args);
}

pub fn fmt_assume_capacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) String {
    self.string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailing_string_assume_capacity();
}

pub fn trailing_string(self: *Builder) Allocator.Error!String {
    try self.string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.string_map.ensure_unused_capacity(self.gpa, 1);
    return self.trailing_string_assume_capacity();
}

pub fn trailing_string_assume_capacity(self: *Builder) String {
    const start = self.string_indices.get_last();
    const bytes: []const u8 = self.string_bytes.items[start..];
    const gop = self.string_map.get_or_put_assume_capacity_adapted(bytes, String.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.string_bytes.shrink_retaining_capacity(start);
    } else {
        self.string_indices.append_assume_capacity(@int_cast(self.string_bytes.items.len));
    }
    return String.from_index(gop.index);
}

pub fn fn_type(
    self: *Builder,
    ret: Type,
    params: []const Type,
    kind: Type.Function.Kind,
) Allocator.Error!Type {
    try self.ensure_unused_type_capacity(1, Type.Function, params.len);
    switch (kind) {
        inline else => |comptime_kind| return self.fn_type_assume_capacity(ret, params, comptime_kind),
    }
}

pub fn int_type(self: *Builder, bits: u24) Allocator.Error!Type {
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    return self.int_type_assume_capacity(bits);
}

pub fn ptr_type(self: *Builder, addr_space: AddrSpace) Allocator.Error!Type {
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    return self.ptr_type_assume_capacity(addr_space);
}

pub fn vector_type(
    self: *Builder,
    kind: Type.Vector.Kind,
    len: u32,
    child: Type,
) Allocator.Error!Type {
    try self.ensure_unused_type_capacity(1, Type.Vector, 0);
    switch (kind) {
        inline else => |comptime_kind| return self.vector_type_assume_capacity(comptime_kind, len, child),
    }
}

pub fn array_type(self: *Builder, len: u64, child: Type) Allocator.Error!Type {
    comptime assert(@size_of(Type.Array) >= @size_of(Type.Vector));
    try self.ensure_unused_type_capacity(1, Type.Array, 0);
    return self.array_type_assume_capacity(len, child);
}

pub fn struct_type(
    self: *Builder,
    kind: Type.Structure.Kind,
    fields: []const Type,
) Allocator.Error!Type {
    try self.ensure_unused_type_capacity(1, Type.Structure, fields.len);
    switch (kind) {
        inline else => |comptime_kind| return self.struct_type_assume_capacity(comptime_kind, fields),
    }
}

pub fn opaque_type(self: *Builder, name: String) Allocator.Error!Type {
    try self.string_map.ensure_unused_capacity(self.gpa, 1);
    if (name.slice(self)) |id| {
        const count: usize = comptime std.fmt.count("{d}", .{std.math.max_int(u32)});
        try self.string_bytes.ensure_unused_capacity(self.gpa, id.len + count);
    }
    try self.string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.types.ensure_unused_capacity(self.gpa, 1);
    try self.next_unique_type_id.ensure_unused_capacity(self.gpa, 1);
    try self.ensure_unused_type_capacity(1, Type.NamedStructure, 0);
    return self.opaque_type_assume_capacity(name);
}

pub fn named_type_set_body(
    self: *Builder,
    named_type: Type,
    body_type: Type,
) void {
    const named_item = self.type_items.items[@int_from_enum(named_type)];
    self.type_extra.items[named_item.data + std.meta.field_index(Type.NamedStructure, "body").?] =
        @int_from_enum(body_type);
}

pub fn attr(self: *Builder, attribute: Attribute) Allocator.Error!Attribute.Index {
    try self.attributes.ensure_unused_capacity(self.gpa, 1);

    const gop = self.attributes.get_or_put_assume_capacity(attribute.to_storage());
    if (!gop.found_existing) gop.value_ptr.* = {};
    return @enumFromInt(gop.index);
}

pub fn attrs(self: *Builder, attributes: []Attribute.Index) Allocator.Error!Attributes {
    std.sort.heap(Attribute.Index, attributes, self, struct {
        pub fn less_than(builder: *const Builder, lhs: Attribute.Index, rhs: Attribute.Index) bool {
            const lhs_kind = lhs.get_kind(builder);
            const rhs_kind = rhs.get_kind(builder);
            assert(lhs_kind != rhs_kind);
            return @int_from_enum(lhs_kind) < @int_from_enum(rhs_kind);
        }
    }.less_than);
    return @enumFromInt(try self.attr_generic(@ptr_cast(attributes)));
}

pub fn fn_attrs(self: *Builder, fn_attributes: []const Attributes) Allocator.Error!FunctionAttributes {
    try self.function_attributes_set.ensure_unused_capacity(self.gpa, 1);
    const function_attributes: FunctionAttributes = @enumFromInt(try self.attr_generic(@ptr_cast(
        fn_attributes[0..if (std.mem.last_index_of_none(Attributes, fn_attributes, &.{.none})) |last|
            last + 1
        else
            0],
    )));

    _ = self.function_attributes_set.get_or_put_assume_capacity(function_attributes);
    return function_attributes;
}

pub fn add_global(self: *Builder, name: StrtabString, global: Global) Allocator.Error!Global.Index {
    assert(!name.is_anon());
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    try self.ensure_unused_global_capacity(name);
    return self.add_global_assume_capacity(name, global);
}

pub fn add_global_assume_capacity(self: *Builder, name: StrtabString, global: Global) Global.Index {
    _ = self.ptr_type_assume_capacity(global.addr_space);
    var id = name;
    if (name == .empty) {
        id = self.next_unnamed_global;
        assert(id != self.next_replaced_global);
        self.next_unnamed_global = @enumFromInt(@int_from_enum(id) + 1);
    }
    while (true) {
        const global_gop = self.globals.get_or_put_assume_capacity(id);
        if (!global_gop.found_existing) {
            global_gop.value_ptr.* = global;
            const global_index: Global.Index = @enumFromInt(global_gop.index);
            global_index.update_dso_local(self);
            return global_index;
        }

        const unique_gop = self.next_unique_global_id.get_or_put_assume_capacity(name);
        if (!unique_gop.found_existing) unique_gop.value_ptr.* = 2;
        id = self.strtab_string_fmt_assume_capacity("{s}.{d}", .{ name.slice(self).?, unique_gop.value_ptr.* });
        unique_gop.value_ptr.* += 1;
    }
}

pub fn get_global(self: *const Builder, name: StrtabString) ?Global.Index {
    return @enumFromInt(self.globals.get_index(name) orelse return null);
}

pub fn add_alias(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
    aliasee: Constant,
) Allocator.Error!Alias.Index {
    assert(!name.is_anon());
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    try self.ensure_unused_global_capacity(name);
    try self.aliases.ensure_unused_capacity(self.gpa, 1);
    return self.add_alias_assume_capacity(name, ty, addr_space, aliasee);
}

pub fn add_alias_assume_capacity(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
    aliasee: Constant,
) Alias.Index {
    const alias_index: Alias.Index = @enumFromInt(self.aliases.items.len);
    self.aliases.append_assume_capacity(.{ .global = self.add_global_assume_capacity(name, .{
        .addr_space = addr_space,
        .type = ty,
        .kind = .{ .alias = alias_index },
    }), .aliasee = aliasee });
    return alias_index;
}

pub fn add_variable(
    self: *Builder,
    name: StrtabString,
    ty: Type,
    addr_space: AddrSpace,
) Allocator.Error!Variable.Index {
    assert(!name.is_anon());
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    try self.ensure_unused_global_capacity(name);
    try self.variables.ensure_unused_capacity(self.gpa, 1);
    return self.add_variable_assume_capacity(ty, name, addr_space);
}

pub fn add_variable_assume_capacity(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Variable.Index {
    const variable_index: Variable.Index = @enumFromInt(self.variables.items.len);
    self.variables.append_assume_capacity(.{ .global = self.add_global_assume_capacity(name, .{
        .addr_space = addr_space,
        .type = ty,
        .kind = .{ .variable = variable_index },
    }) });
    return variable_index;
}

pub fn add_function(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Allocator.Error!Function.Index {
    assert(!name.is_anon());
    try self.ensure_unused_type_capacity(1, NoExtra, 0);
    try self.ensure_unused_global_capacity(name);
    try self.functions.ensure_unused_capacity(self.gpa, 1);
    return self.add_function_assume_capacity(ty, name, addr_space);
}

pub fn add_function_assume_capacity(
    self: *Builder,
    ty: Type,
    name: StrtabString,
    addr_space: AddrSpace,
) Function.Index {
    assert(ty.is_function(self));
    const function_index: Function.Index = @enumFromInt(self.functions.items.len);
    self.functions.append_assume_capacity(.{
        .global = self.add_global_assume_capacity(name, .{
            .addr_space = addr_space,
            .type = ty,
            .kind = .{ .function = function_index },
        }),
        .strip = undefined,
    });
    return function_index;
}

pub fn get_intrinsic(
    self: *Builder,
    id: Intrinsic,
    overload: []const Type,
) Allocator.Error!Function.Index {
    const ExpectedContents = extern union {
        attrs: extern struct {
            params: [expected_args_len]Type,
            fn_attrs: [FunctionAttributes.params_index + expected_args_len]Attributes,
            attrs: [expected_attrs_len]Attribute.Index,
            fields: [expected_fields_len]Type,
        },
    };
    var stack align(@max(@alignOf(std.heap.StackFallbackAllocator(0)), @alignOf(ExpectedContents))) =
        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
    const allocator = stack.get();

    const name = name: {
        const writer = self.strtab_string_bytes.writer(self.gpa);
        try writer.print("llvm.{s}", .{@tag_name(id)});
        for (overload) |ty| try writer.print(".{m}", .{ty.fmt(self)});
        break :name try self.trailing_strtab_string();
    };
    if (self.get_global(name)) |global| return global.ptr_const(self).kind.function;

    const signature = Intrinsic.signatures.get(id);
    const param_types = try allocator.alloc(Type, signature.params.len);
    defer allocator.free(param_types);
    const function_attributes = try allocator.alloc(
        Attributes,
        FunctionAttributes.params_index + (signature.params.len - signature.ret_len),
    );
    defer allocator.free(function_attributes);

    var attributes: struct {
        builder: *Builder,
        list: std.ArrayList(Attribute.Index),

        fn deinit(state: *@This()) void {
            state.list.deinit();
            state.* = undefined;
        }

        fn get(state: *@This(), attributes: []const Attribute) Allocator.Error!Attributes {
            try state.list.resize(attributes.len);
            for (state.list.items, attributes) |*item, attribute|
                item.* = try state.builder.attr(attribute);
            return state.builder.attrs(state.list.items);
        }
    } = .{ .builder = self, .list = std.ArrayList(Attribute.Index).init(allocator) };
    defer attributes.deinit();

    var overload_index: usize = 0;
    function_attributes[FunctionAttributes.function_index] = try attributes.get(signature.attrs);
    function_attributes[FunctionAttributes.return_index] = .none; // needed for void return
    for (0.., param_types, signature.params) |param_index, *param_type, signature_param| {
        switch (signature_param.kind) {
            .type => |ty| param_type.* = ty,
            .overloaded => {
                param_type.* = overload[overload_index];
                overload_index += 1;
            },
            .matches, .matches_scalar, .matches_changed_scalar => {},
        }
        function_attributes[
            if (param_index < signature.ret_len)
                FunctionAttributes.return_index
            else
                FunctionAttributes.params_index + (param_index - signature.ret_len)
        ] = try attributes.get(signature_param.attrs);
    }
    assert(overload_index == overload.len);
    for (param_types, signature.params) |*param_type, signature_param| {
        param_type.* = switch (signature_param.kind) {
            .type, .overloaded => continue,
            .matches => |param_index| param_types[param_index],
            .matches_scalar => |param_index| param_types[param_index].scalar_type(self),
            .matches_changed_scalar => |info| try param_types[info.index]
                .change_scalar(info.scalar, self),
        };
    }

    const function_index = try self.add_function(try self.fn_type(switch (signature.ret_len) {
        0 => .void,
        1 => param_types[0],
        else => try self.struct_type(.normal, param_types[0..signature.ret_len]),
    }, param_types[signature.ret_len..], .normal), name, .default);
    function_index.ptr(self).attributes = try self.fn_attrs(function_attributes);
    return function_index;
}

pub fn int_const(self: *Builder, ty: Type, value: anytype) Allocator.Error!Constant {
    const int_value = switch (@typeInfo(@TypeOf(value))) {
        .Int, .ComptimeInt => value,
        .Enum => @int_from_enum(value),
        else => @compile_error("int_const expected an integral value, got " ++ @type_name(@TypeOf(value))),
    };
    var limbs: [
        switch (@typeInfo(@TypeOf(int_value))) {
            .Int => |info| std.math.big.int.calc_twos_comp_limb_count(info.bits),
            .ComptimeInt => std.math.big.int.calc_limb_len(int_value),
            else => unreachable,
        }
    ]std.math.big.Limb = undefined;
    return self.big_int_const(ty, std.math.big.int.Mutable.init(&limbs, int_value).to_const());
}

pub fn int_value(self: *Builder, ty: Type, value: anytype) Allocator.Error!Value {
    return (try self.int_const(ty, value)).to_value();
}

pub fn big_int_const(self: *Builder, ty: Type, value: std.math.big.int.Const) Allocator.Error!Constant {
    try self.constant_map.ensure_unused_capacity(self.gpa, 1);
    try self.constant_items.ensure_unused_capacity(self.gpa, 1);
    try self.constant_limbs.ensure_unused_capacity(self.gpa, Constant.Integer.limbs + value.limbs.len);
    return self.big_int_const_assume_capacity(ty, value);
}

pub fn big_int_value(self: *Builder, ty: Type, value: std.math.big.int.Const) Allocator.Error!Value {
    return (try self.big_int_const(ty, value)).to_value();
}

pub fn fp_const(self: *Builder, ty: Type, comptime val: comptime_float) Allocator.Error!Constant {
    return switch (ty) {
        .half => try self.half_const(val),
        .bfloat => try self.bfloat_const(val),
        .float => try self.float_const(val),
        .double => try self.double_const(val),
        .fp128 => try self.fp128_const(val),
        .x86_fp80 => try self.x86_fp80_const(val),
        .ppc_fp128 => try self.ppc_fp128_const(.{ val, -0.0 }),
        else => unreachable,
    };
}

pub fn fp_value(self: *Builder, ty: Type, comptime value: comptime_float) Allocator.Error!Value {
    return (try self.fp_const(ty, value)).to_value();
}

pub fn nan_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    return switch (ty) {
        .half => try self.half_const(std.math.nan(f16)),
        .bfloat => try self.bfloat_const(std.math.nan(f32)),
        .float => try self.float_const(std.math.nan(f32)),
        .double => try self.double_const(std.math.nan(f64)),
        .fp128 => try self.fp128_const(std.math.nan(f128)),
        .x86_fp80 => try self.x86_fp80_const(std.math.nan(f80)),
        .ppc_fp128 => try self.ppc_fp128_const(.{std.math.nan(f64)} ** 2),
        else => unreachable,
    };
}

pub fn nan_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.nan_const(ty)).to_value();
}

pub fn half_const(self: *Builder, val: f16) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.half_const_assume_capacity(val);
}

pub fn half_value(self: *Builder, ty: Type, value: f16) Allocator.Error!Value {
    return (try self.half_const(ty, value)).to_value();
}

pub fn bfloat_const(self: *Builder, val: f32) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.bfloat_const_assume_capacity(val);
}

pub fn bfloat_value(self: *Builder, ty: Type, value: f32) Allocator.Error!Value {
    return (try self.bfloat_const(ty, value)).to_value();
}

pub fn float_const(self: *Builder, val: f32) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.float_const_assume_capacity(val);
}

pub fn float_value(self: *Builder, ty: Type, value: f32) Allocator.Error!Value {
    return (try self.float_const(ty, value)).to_value();
}

pub fn double_const(self: *Builder, val: f64) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Double, 0);
    return self.double_const_assume_capacity(val);
}

pub fn double_value(self: *Builder, ty: Type, value: f64) Allocator.Error!Value {
    return (try self.double_const(ty, value)).to_value();
}

pub fn fp128_const(self: *Builder, val: f128) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Fp128, 0);
    return self.fp128_const_assume_capacity(val);
}

pub fn fp128_value(self: *Builder, ty: Type, value: f128) Allocator.Error!Value {
    return (try self.fp128_const(ty, value)).to_value();
}

pub fn x86_fp80_const(self: *Builder, val: f80) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Fp80, 0);
    return self.x86_fp80_const_assume_capacity(val);
}

pub fn x86_fp80_value(self: *Builder, ty: Type, value: f80) Allocator.Error!Value {
    return (try self.x86_fp80_const(ty, value)).to_value();
}

pub fn ppc_fp128_const(self: *Builder, val: [2]f64) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Fp128, 0);
    return self.ppc_fp128_const_assume_capacity(val);
}

pub fn ppc_fp128_value(self: *Builder, ty: Type, value: [2]f64) Allocator.Error!Value {
    return (try self.ppc_fp128_const(ty, value)).to_value();
}

pub fn null_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.null_const_assume_capacity(ty);
}

pub fn null_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.null_const(ty)).to_value();
}

pub fn none_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.none_const_assume_capacity(ty);
}

pub fn none_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.none_const(ty)).to_value();
}

pub fn struct_const(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Aggregate, vals.len);
    return self.struct_const_assume_capacity(ty, vals);
}

pub fn struct_value(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.struct_const(ty, vals)).to_value();
}

pub fn array_const(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Aggregate, vals.len);
    return self.array_const_assume_capacity(ty, vals);
}

pub fn array_value(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.array_const(ty, vals)).to_value();
}

pub fn string_const(self: *Builder, val: String) Allocator.Error!Constant {
    try self.ensure_unused_type_capacity(1, Type.Array, 0);
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.string_const_assume_capacity(val);
}

pub fn string_value(self: *Builder, val: String) Allocator.Error!Value {
    return (try self.string_const(val)).to_value();
}

pub fn vector_const(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Aggregate, vals.len);
    return self.vector_const_assume_capacity(ty, vals);
}

pub fn vector_value(self: *Builder, ty: Type, vals: []const Constant) Allocator.Error!Value {
    return (try self.vector_const(ty, vals)).to_value();
}

pub fn splat_const(self: *Builder, ty: Type, val: Constant) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Splat, 0);
    return self.splat_const_assume_capacity(ty, val);
}

pub fn splat_value(self: *Builder, ty: Type, val: Constant) Allocator.Error!Value {
    return (try self.splat_const(ty, val)).to_value();
}

pub fn zero_init_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Fp128, 0);
    try self.constant_limbs.ensure_unused_capacity(
        self.gpa,
        Constant.Integer.limbs + comptime std.math.big.int.calc_limb_len(0),
    );
    return self.zero_init_const_assume_capacity(ty);
}

pub fn zero_init_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.zero_init_const(ty)).to_value();
}

pub fn undef_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.undef_const_assume_capacity(ty);
}

pub fn undef_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.undef_const(ty)).to_value();
}

pub fn poison_const(self: *Builder, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.poison_const_assume_capacity(ty);
}

pub fn poison_value(self: *Builder, ty: Type) Allocator.Error!Value {
    return (try self.poison_const(ty)).to_value();
}

pub fn block_addr_const(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.BlockAddress, 0);
    return self.block_addr_const_assume_capacity(function, block);
}

pub fn block_addr_value(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Allocator.Error!Value {
    return (try self.block_addr_const(function, block)).to_value();
}

pub fn dso_local_equivalent_const(self: *Builder, function: Function.Index) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.dso_local_equivalent_const_assume_capacity(function);
}

pub fn dso_local_equivalent_value(self: *Builder, function: Function.Index) Allocator.Error!Value {
    return (try self.dso_local_equivalent_const(function)).to_value();
}

pub fn no_cfi_const(self: *Builder, function: Function.Index) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, NoExtra, 0);
    return self.no_cfi_const_assume_capacity(function);
}

pub fn no_cfi_value(self: *Builder, function: Function.Index) Allocator.Error!Value {
    return (try self.no_cfi_const(function)).to_value();
}

pub fn conv_const(
    self: *Builder,
    val: Constant,
    ty: Type,
) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Cast, 0);
    return self.conv_const_assume_capacity(val, ty);
}

pub fn conv_value(
    self: *Builder,
    val: Constant,
    ty: Type,
) Allocator.Error!Value {
    return (try self.conv_const(val, ty)).to_value();
}

pub fn cast_const(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Cast, 0);
    return self.cast_const_assume_capacity(tag, val, ty);
}

pub fn cast_value(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Allocator.Error!Value {
    return (try self.cast_const(tag, val, ty)).to_value();
}

pub fn gep_const(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Allocator.Error!Constant {
    try self.ensure_unused_type_capacity(1, Type.Vector, 0);
    try self.ensure_unused_constant_capacity(1, Constant.GetElementPtr, indices.len);
    return self.gep_const_assume_capacity(kind, ty, base, inrange, indices);
}

pub fn gep_value(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Allocator.Error!Value {
    return (try self.gep_const(kind, ty, base, inrange, indices)).to_value();
}

pub fn bin_const(
    self: *Builder,
    tag: Constant.Tag,
    lhs: Constant,
    rhs: Constant,
) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Binary, 0);
    return self.bin_const_assume_capacity(tag, lhs, rhs);
}

pub fn bin_value(self: *Builder, tag: Constant.Tag, lhs: Constant, rhs: Constant) Allocator.Error!Value {
    return (try self.bin_const(tag, lhs, rhs)).to_value();
}

pub fn asm_const(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Allocator.Error!Constant {
    try self.ensure_unused_constant_capacity(1, Constant.Assembly, 0);
    return self.asm_const_assume_capacity(ty, info, assembly, constraints);
}

pub fn asm_value(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Allocator.Error!Value {
    return (try self.asm_const(ty, info, assembly, constraints)).to_value();
}

pub fn dump(self: *Builder) void {
    self.print(std.io.get_std_err().writer()) catch {};
}

pub fn print_to_file(self: *Builder, path: []const u8) Allocator.Error!bool {
    var file = std.fs.cwd().create_file(path, .{}) catch |err| {
        log.err("failed printing LLVM module to \"{s}\": {s}", .{ path, @errorName(err) });
        return false;
    };
    defer file.close();
    self.print(file.writer()) catch |err| {
        log.err("failed printing LLVM module to \"{s}\": {s}", .{ path, @errorName(err) });
        return false;
    };
    return true;
}

pub fn print(self: *Builder, writer: anytype) (@TypeOf(writer).Error || Allocator.Error)!void {
    var bw = std.io.buffered_writer(writer);
    try self.print_unbuffered(bw.writer());
    try bw.flush();
}

fn WriterWithErrors(comptime BackingWriter: type, comptime ExtraErrors: type) type {
    return struct {
        backing_writer: BackingWriter,

        pub const Error = BackingWriter.Error || ExtraErrors;
        pub const Writer = std.io.Writer(*const Self, Error, write);

        const Self = @This();

        pub fn writer(self: *const Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *const Self, bytes: []const u8) Error!usize {
            return self.backing_writer.write(bytes);
        }
    };
}
fn writer_with_errors(
    backing_writer: anytype,
    comptime ExtraErrors: type,
) WriterWithErrors(@TypeOf(backing_writer), ExtraErrors) {
    return .{ .backing_writer = backing_writer };
}

pub fn print_unbuffered(
    self: *Builder,
    backing_writer: anytype,
) (@TypeOf(backing_writer).Error || Allocator.Error)!void {
    const writer_with_errors = writer_with_errors(backing_writer, Allocator.Error);
    const writer = writer_with_errors.writer();

    var need_newline = false;
    var metadata_formatter: Metadata.Formatter = .{ .builder = self, .need_comma = undefined };
    defer metadata_formatter.map.deinit(self.gpa);

    if (self.source_filename != .none or self.data_layout != .none or self.target_triple != .none) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        if (self.source_filename != .none) try writer.print(
            \\; ModuleID = '{s}'
            \\source_filename = {"}
            \\
        , .{ self.source_filename.slice(self).?, self.source_filename.fmt(self) });
        if (self.data_layout != .none) try writer.print(
            \\target datalayout = {"}
            \\
        , .{self.data_layout.fmt(self)});
        if (self.target_triple != .none) try writer.print(
            \\target triple = {"}
            \\
        , .{self.target_triple.fmt(self)});
    }

    if (self.module_asm.items.len > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        var line_it = std.mem.tokenize_scalar(u8, self.module_asm.items, '\n');
        while (line_it.next()) |line| {
            try writer.write_all("module asm ");
            try print_escaped_string(line, .always_quote, writer);
            try writer.write_byte('\n');
        }
    }

    if (self.types.count() > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        for (self.types.keys(), self.types.values()) |id, ty| try writer.print(
            \\%{} = type {}
            \\
        , .{ id.fmt(self), ty.fmt(self) });
    }

    if (self.variables.items.len > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        for (self.variables.items) |variable| {
            if (variable.global.get_replacement(self) != .none) continue;
            const global = variable.global.ptr_const(self);
            metadata_formatter.need_comma = true;
            defer metadata_formatter.need_comma = undefined;
            try writer.print(
                \\{} ={}{}{}{}{ }{}{ }{} {s} {%}{ }{, }{}
                \\
            , .{
                variable.global.fmt(self),
                Linkage.fmt_optional(if (global.linkage == .external and
                    variable.init != .no_init) null else global.linkage),
                global.preemption,
                global.visibility,
                global.dll_storage_class,
                variable.thread_local,
                global.unnamed_addr,
                global.addr_space,
                global.externally_initialized,
                @tag_name(variable.mutability),
                global.type.fmt(self),
                variable.init.fmt(self),
                variable.alignment,
                try metadata_formatter.fmt("!dbg ", global.dbg),
            });
        }
    }

    if (self.aliases.items.len > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        for (self.aliases.items) |alias| {
            if (alias.global.get_replacement(self) != .none) continue;
            const global = alias.global.ptr_const(self);
            metadata_formatter.need_comma = true;
            defer metadata_formatter.need_comma = undefined;
            try writer.print(
                \\{} ={}{}{}{}{ }{} alias {%}, {%}{}
                \\
            , .{
                alias.global.fmt(self),
                global.linkage,
                global.preemption,
                global.visibility,
                global.dll_storage_class,
                alias.thread_local,
                global.unnamed_addr,
                global.type.fmt(self),
                alias.aliasee.fmt(self),
                try metadata_formatter.fmt("!dbg ", global.dbg),
            });
        }
    }

    var attribute_groups: std.AutoArrayHashMapUnmanaged(Attributes, void) = .{};
    defer attribute_groups.deinit(self.gpa);

    for (0.., self.functions.items) |function_i, function| {
        if (function.global.get_replacement(self) != .none) continue;
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        const function_index: Function.Index = @enumFromInt(function_i);
        const global = function.global.ptr_const(self);
        const params_len = global.type.function_parameters(self).len;
        const function_attributes = function.attributes.func(self);
        if (function_attributes != .none) try writer.print(
            \\; Function Attrs:{}
            \\
        , .{function_attributes.fmt(self)});
        try writer.print(
            \\{s}{}{}{}{}{}{"} {} {}(
        , .{
            if (function.instructions.len > 0) "define" else "declare",
            global.linkage,
            global.preemption,
            global.visibility,
            global.dll_storage_class,
            function.call_conv,
            function.attributes.ret(self).fmt(self),
            global.type.function_return(self).fmt(self),
            function.global.fmt(self),
        });
        for (0..params_len) |arg| {
            if (arg > 0) try writer.write_all(", ");
            try writer.print(
                \\{%}{"}
            , .{
                global.type.function_parameters(self)[arg].fmt(self),
                function.attributes.param(arg, self).fmt(self),
            });
            if (function.instructions.len > 0)
                try writer.print(" {}", .{function.arg(@int_cast(arg)).fmt(function_index, self)})
            else
                try writer.print(" %{d}", .{arg});
        }
        switch (global.type.function_kind(self)) {
            .normal => {},
            .vararg => {
                if (params_len > 0) try writer.write_all(", ");
                try writer.write_all("...");
            },
        }
        try writer.print("){}{ }", .{ global.unnamed_addr, global.addr_space });
        if (function_attributes != .none) try writer.print(" #{d}", .{
            (try attribute_groups.get_or_put_value(self.gpa, function_attributes, {})).index,
        });
        {
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;
            try writer.print("{ }{}", .{
                function.alignment,
                try metadata_formatter.fmt(" !dbg ", global.dbg),
            });
        }
        if (function.instructions.len > 0) {
            var block_incoming_len: u32 = undefined;
            try writer.write_all(" {\n");
            var maybe_dbg_index: ?u32 = null;
            for (params_len..function.instructions.len) |instruction_i| {
                const instruction_index: Function.Instruction.Index = @enumFromInt(instruction_i);
                const instruction = function.instructions.get(@int_from_enum(instruction_index));
                if (function.debug_locations.get(instruction_index)) |debug_location| switch (debug_location) {
                    .no_location => maybe_dbg_index = null,
                    .location => |location| {
                        const gop = try metadata_formatter.map.get_or_put(self.gpa, .{
                            .debug_location = location,
                        });
                        maybe_dbg_index = @int_cast(gop.index);
                    },
                };
                switch (instruction.tag) {
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .@"add nuw nsw",
                    .@"and",
                    .ashr,
                    .@"ashr exact",
                    .fadd,
                    .@"fadd fast",
                    .@"fcmp false",
                    .@"fcmp fast false",
                    .@"fcmp fast oeq",
                    .@"fcmp fast oge",
                    .@"fcmp fast ogt",
                    .@"fcmp fast ole",
                    .@"fcmp fast olt",
                    .@"fcmp fast one",
                    .@"fcmp fast ord",
                    .@"fcmp fast true",
                    .@"fcmp fast ueq",
                    .@"fcmp fast uge",
                    .@"fcmp fast ugt",
                    .@"fcmp fast ule",
                    .@"fcmp fast ult",
                    .@"fcmp fast une",
                    .@"fcmp fast uno",
                    .@"fcmp oeq",
                    .@"fcmp oge",
                    .@"fcmp ogt",
                    .@"fcmp ole",
                    .@"fcmp olt",
                    .@"fcmp one",
                    .@"fcmp ord",
                    .@"fcmp true",
                    .@"fcmp ueq",
                    .@"fcmp uge",
                    .@"fcmp ugt",
                    .@"fcmp ule",
                    .@"fcmp ult",
                    .@"fcmp une",
                    .@"fcmp uno",
                    .fdiv,
                    .@"fdiv fast",
                    .fmul,
                    .@"fmul fast",
                    .frem,
                    .@"frem fast",
                    .fsub,
                    .@"fsub fast",
                    .@"icmp eq",
                    .@"icmp ne",
                    .@"icmp sge",
                    .@"icmp sgt",
                    .@"icmp sle",
                    .@"icmp slt",
                    .@"icmp uge",
                    .@"icmp ugt",
                    .@"icmp ule",
                    .@"icmp ult",
                    .lshr,
                    .@"lshr exact",
                    .mul,
                    .@"mul nsw",
                    .@"mul nuw",
                    .@"mul nuw nsw",
                    .@"or",
                    .sdiv,
                    .@"sdiv exact",
                    .srem,
                    .shl,
                    .@"shl nsw",
                    .@"shl nuw",
                    .@"shl nuw nsw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .@"sub nuw nsw",
                    .udiv,
                    .@"udiv exact",
                    .urem,
                    .xor,
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Binary, instruction.data);
                        try writer.print("  %{} = {s} {%}, {}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
                        });
                    },
                    .addrspacecast,
                    .bitcast,
                    .fpext,
                    .fptosi,
                    .fptoui,
                    .fptrunc,
                    .inttoptr,
                    .ptrtoint,
                    .sext,
                    .sitofp,
                    .trunc,
                    .uitofp,
                    .zext,
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Cast, instruction.data);
                        try writer.print("  %{} = {s} {%} to {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.val.fmt(function_index, self),
                            extra.type.fmt(self),
                        });
                    },
                    .alloca,
                    .@"alloca inalloca",
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Alloca, instruction.data);
                        try writer.print("  %{} = {s} {%}{,%}{, }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.type.fmt(self),
                            Value.fmt(switch (extra.len) {
                                .@"1" => .none,
                                else => extra.len,
                            }, function_index, self),
                            extra.info.alignment,
                            extra.info.addr_space,
                        });
                    },
                    .arg => unreachable,
                    .atomicrmw => |tag| {
                        const extra =
                            function.extra_data(Function.Instruction.AtomicRmw, instruction.data);
                        try writer.print("  %{} = {s}{ } {s} {%}, {%}{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.info.access_kind,
                            @tag_name(extra.info.atomic_rmw_operation),
                            extra.ptr.fmt(function_index, self),
                            extra.val.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .block => {
                        block_incoming_len = instruction.data;
                        const name = instruction_index.name(&function);
                        if (@int_from_enum(instruction_index) > params_len)
                            try writer.write_byte('\n');
                        try writer.print("{}:\n", .{name.fmt(self)});
                        continue;
                    },
                    .br => |tag| {
                        const target: Function.Block.Index = @enumFromInt(instruction.data);
                        try writer.print("  {s} {%}", .{
                            @tag_name(tag), target.to_inst(&function).fmt(function_index, self),
                        });
                    },
                    .br_cond => {
                        const extra = function.extra_data(Function.Instruction.BrCond, instruction.data);
                        try writer.print("  br {%}, {%}, {%}", .{
                            extra.cond.fmt(function_index, self),
                            extra.then.to_inst(&function).fmt(function_index, self),
                            extra.@"else".to_inst(&function).fmt(function_index, self),
                        });
                    },
                    .call,
                    .@"call fast",
                    .@"musttail call",
                    .@"musttail call fast",
                    .@"notail call",
                    .@"notail call fast",
                    .@"tail call",
                    .@"tail call fast",
                    => |tag| {
                        var extra =
                            function.extra_data_trail(Function.Instruction.Call, instruction.data);
                        const args = extra.trail.next(extra.data.args_len, Value, &function);
                        try writer.write_all("  ");
                        const ret_ty = extra.data.ty.function_return(self);
                        switch (ret_ty) {
                            .void => {},
                            else => try writer.print("%{} = ", .{
                                instruction_index.name(&function).fmt(self),
                            }),
                            .none => unreachable,
                        }
                        try writer.print("{s}{}{}{} {%} {}(", .{
                            @tag_name(tag),
                            extra.data.info.call_conv,
                            extra.data.attributes.ret(self).fmt(self),
                            extra.data.callee.type_of(function_index, self).pointer_addr_space(self),
                            switch (extra.data.ty.function_kind(self)) {
                                .normal => ret_ty,
                                .vararg => extra.data.ty,
                            }.fmt(self),
                            extra.data.callee.fmt(function_index, self),
                        });
                        for (0.., args) |arg_index, arg| {
                            if (arg_index > 0) try writer.write_all(", ");
                            metadata_formatter.need_comma = false;
                            defer metadata_formatter.need_comma = undefined;
                            try writer.print("{%}{}{}", .{
                                arg.type_of(function_index, self).fmt(self),
                                extra.data.attributes.param(arg_index, self).fmt(self),
                                try metadata_formatter.fmt_local(" ", arg, function_index),
                            });
                        }
                        try writer.write_byte(')');
                        const call_function_attributes = extra.data.attributes.func(self);
                        if (call_function_attributes != .none) try writer.print(" #{d}", .{
                            (try attribute_groups.get_or_put_value(
                                self.gpa,
                                call_function_attributes,
                                {},
                            )).index,
                        });
                    },
                    .cmpxchg,
                    .@"cmpxchg weak",
                    => |tag| {
                        const extra =
                            function.extra_data(Function.Instruction.CmpXchg, instruction.data);
                        try writer.print("  %{} = {s}{ } {%}, {%}, {%}{ }{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.info.access_kind,
                            extra.ptr.fmt(function_index, self),
                            extra.cmp.fmt(function_index, self),
                            extra.new.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.failure_ordering,
                            extra.info.alignment,
                        });
                    },
                    .extractelement => |tag| {
                        const extra =
                            function.extra_data(Function.Instruction.ExtractElement, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.val.fmt(function_index, self),
                            extra.index.fmt(function_index, self),
                        });
                    },
                    .extractvalue => |tag| {
                        var extra = function.extra_data_trail(
                            Function.Instruction.ExtractValue,
                            instruction.data,
                        );
                        const indices = extra.trail.next(extra.data.indices_len, u32, &function);
                        try writer.print("  %{} = {s} {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.data.val.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {d}", .{index});
                    },
                    .fence => |tag| {
                        const info: MemoryAccessInfo = @bit_cast(instruction.data);
                        try writer.print("  {s}{ }{ }", .{
                            @tag_name(tag),
                            info.sync_scope,
                            info.success_ordering,
                        });
                    },
                    .fneg,
                    .@"fneg fast",
                    => |tag| {
                        const val: Value = @enumFromInt(instruction.data);
                        try writer.print("  %{} = {s} {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            val.fmt(function_index, self),
                        });
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = function.extra_data_trail(
                            Function.Instruction.GetElementPtr,
                            instruction.data,
                        );
                        const indices = extra.trail.next(extra.data.indices_len, Value, &function);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.data.type.fmt(self),
                            extra.data.base.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {%}", .{
                            index.fmt(function_index, self),
                        });
                    },
                    .insertelement => |tag| {
                        const extra =
                            function.extra_data(Function.Instruction.InsertElement, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.val.fmt(function_index, self),
                            extra.elem.fmt(function_index, self),
                            extra.index.fmt(function_index, self),
                        });
                    },
                    .insertvalue => |tag| {
                        var extra =
                            function.extra_data_trail(Function.Instruction.InsertValue, instruction.data);
                        const indices = extra.trail.next(extra.data.indices_len, u32, &function);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.data.val.fmt(function_index, self),
                            extra.data.elem.fmt(function_index, self),
                        });
                        for (indices) |index| try writer.print(", {d}", .{index});
                    },
                    .load,
                    .@"load atomic",
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Load, instruction.data);
                        try writer.print("  %{} = {s}{ } {%}, {%}{ }{ }{, }", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.info.access_kind,
                            extra.type.fmt(self),
                            extra.ptr.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .phi,
                    .@"phi fast",
                    => |tag| {
                        var extra = function.extra_data_trail(Function.Instruction.Phi, instruction.data);
                        const vals = extra.trail.next(block_incoming_len, Value, &function);
                        const blocks =
                            extra.trail.next(block_incoming_len, Function.Block.Index, &function);
                        try writer.print("  %{} = {s} {%} ", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            vals[0].type_of(function_index, self).fmt(self),
                        });
                        for (0.., vals, blocks) |incoming_index, incoming_val, incoming_block| {
                            if (incoming_index > 0) try writer.write_all(", ");
                            try writer.print("[ {}, {} ]", .{
                                incoming_val.fmt(function_index, self),
                                incoming_block.to_inst(&function).fmt(function_index, self),
                            });
                        }
                    },
                    .ret => |tag| {
                        const val: Value = @enumFromInt(instruction.data);
                        try writer.print("  {s} {%}", .{
                            @tag_name(tag),
                            val.fmt(function_index, self),
                        });
                    },
                    .@"ret void",
                    .@"unreachable",
                    => |tag| try writer.print("  {s}", .{@tag_name(tag)}),
                    .select,
                    .@"select fast",
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Select, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.cond.fmt(function_index, self),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
                        });
                    },
                    .shufflevector => |tag| {
                        const extra =
                            function.extra_data(Function.Instruction.ShuffleVector, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.lhs.fmt(function_index, self),
                            extra.rhs.fmt(function_index, self),
                            extra.mask.fmt(function_index, self),
                        });
                    },
                    .store,
                    .@"store atomic",
                    => |tag| {
                        const extra = function.extra_data(Function.Instruction.Store, instruction.data);
                        try writer.print("  {s}{ } {%}, {%}{ }{ }{, }", .{
                            @tag_name(tag),
                            extra.info.access_kind,
                            extra.val.fmt(function_index, self),
                            extra.ptr.fmt(function_index, self),
                            extra.info.sync_scope,
                            extra.info.success_ordering,
                            extra.info.alignment,
                        });
                    },
                    .@"switch" => |tag| {
                        var extra =
                            function.extra_data_trail(Function.Instruction.Switch, instruction.data);
                        const vals = extra.trail.next(extra.data.cases_len, Constant, &function);
                        const blocks =
                            extra.trail.next(extra.data.cases_len, Function.Block.Index, &function);
                        try writer.print("  {s} {%}, {%} [\n", .{
                            @tag_name(tag),
                            extra.data.val.fmt(function_index, self),
                            extra.data.default.to_inst(&function).fmt(function_index, self),
                        });
                        for (vals, blocks) |case_val, case_block| try writer.print(
                            "    {%}, {%}\n",
                            .{
                                case_val.fmt(self),
                                case_block.to_inst(&function).fmt(function_index, self),
                            },
                        );
                        try writer.write_all("  ]");
                    },
                    .va_arg => |tag| {
                        const extra = function.extra_data(Function.Instruction.VaArg, instruction.data);
                        try writer.print("  %{} = {s} {%}, {%}", .{
                            instruction_index.name(&function).fmt(self),
                            @tag_name(tag),
                            extra.list.fmt(function_index, self),
                            extra.type.fmt(self),
                        });
                    },
                }

                if (maybe_dbg_index) |dbg_index| {
                    try writer.print(", !dbg !{}\n", .{dbg_index});
                } else try writer.write_byte('\n');
            }
            try writer.write_byte('}');
        }
        try writer.write_byte('\n');
    }

    if (attribute_groups.count() > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        for (0.., attribute_groups.keys()) |attribute_group_index, attribute_group|
            try writer.print(
                \\attributes #{d} = {{{#"} }}
                \\
            , .{ attribute_group_index, attribute_group.fmt(self) });
    }

    if (self.metadata_named.count() > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        for (self.metadata_named.keys(), self.metadata_named.values()) |name, data| {
            const elements: []const Metadata =
                @ptr_cast(self.metadata_extra.items[data.index..][0..data.len]);
            try writer.write_byte('!');
            try print_escaped_string(name.slice(self), .quote_unless_valid_identifier, writer);
            try writer.write_all(" = !{");
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;
            for (elements) |element| try writer.print("{}", .{try metadata_formatter.fmt("", element)});
            try writer.write_all("}\n");
        }
    }

    if (metadata_formatter.map.count() > 0) {
        if (need_newline) try writer.write_byte('\n') else need_newline = true;
        var metadata_index: usize = 0;
        while (metadata_index < metadata_formatter.map.count()) : (metadata_index += 1) {
            @setEvalBranchQuota(10_000);
            try writer.print("!{} = ", .{metadata_index});
            metadata_formatter.need_comma = false;
            defer metadata_formatter.need_comma = undefined;

            const key = metadata_formatter.map.keys()[metadata_index];
            const metadata_item = switch (key) {
                .debug_location => |location| {
                    try metadata_formatter.specialized(.@"!", .DILocation, .{
                        .line = location.line,
                        .column = location.column,
                        .scope = location.scope,
                        .inlinedAt = location.inlined_at,
                        .isImplicitCode = false,
                    }, writer);
                    continue;
                },
                .metadata => |metadata| self.metadata_items.get(@int_from_enum(metadata)),
            };

            switch (metadata_item.tag) {
                .none, .expression, .constant => unreachable,
                .file => {
                    const extra = self.metadata_extra_data(Metadata.File, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIFile, .{
                        .filename = extra.filename,
                        .directory = extra.directory,
                        .checksumkind = null,
                        .checksum = null,
                        .source = null,
                    }, writer);
                },
                .compile_unit,
                .@"compile_unit optimized",
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.CompileUnit, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DICompileUnit, .{
                        .language = .DW_LANG_C99,
                        .file = extra.file,
                        .producer = extra.producer,
                        .isOptimized = switch (kind) {
                            .compile_unit => false,
                            .@"compile_unit optimized" => true,
                            else => unreachable,
                        },
                        .flags = null,
                        .runtimeVersion = 0,
                        .splitDebugFilename = null,
                        .emissionKind = .FullDebug,
                        .enums = extra.enums,
                        .retainedTypes = null,
                        .globals = extra.globals,
                        .imports = null,
                        .macros = null,
                        .dwoId = null,
                        .splitDebugInlining = false,
                        .debugInfoForProfiling = null,
                        .nameTableKind = null,
                        .rangesBaseAddress = null,
                        .sysroot = null,
                        .sdk = null,
                    }, writer);
                },
                .subprogram,
                .@"subprogram local",
                .@"subprogram definition",
                .@"subprogram local definition",
                .@"subprogram optimized",
                .@"subprogram optimized local",
                .@"subprogram optimized definition",
                .@"subprogram optimized local definition",
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.Subprogram, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DISubprogram, .{
                        .name = extra.name,
                        .linkageName = extra.linkage_name,
                        .scope = extra.file,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .scopeLine = extra.scope_line,
                        .containingType = null,
                        .virtualIndex = null,
                        .thisAdjustment = null,
                        .flags = extra.di_flags,
                        .spFlags = @as(Metadata.Subprogram.DISPFlags, @bit_cast(@as(u32, @as(u3, @int_cast(
                            @int_from_enum(kind) - @int_from_enum(Metadata.Tag.subprogram),
                        ))) << 2)),
                        .unit = extra.compile_unit,
                        .templateParams = null,
                        .declaration = null,
                        .retainedNodes = null,
                        .thrownTypes = null,
                        .annotations = null,
                        .targetFuncName = null,
                    }, writer);
                },
                .lexical_block => {
                    const extra = self.metadata_extra_data(Metadata.LexicalBlock, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DILexicalBlock, .{
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .column = extra.column,
                    }, writer);
                },
                .location => {
                    const extra = self.metadata_extra_data(Metadata.Location, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocation, .{
                        .line = extra.line,
                        .column = extra.column,
                        .scope = extra.scope,
                        .inlinedAt = extra.inlined_at,
                        .isImplicitCode = false,
                    }, writer);
                },
                .basic_bool_type,
                .basic_unsigned_type,
                .basic_signed_type,
                .basic_float_type,
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.BasicType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIBasicType, .{
                        .tag = null,
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .size = extra.bit_size(),
                        .@"align" = null,
                        .encoding = @as(enum {
                            DW_ATE_boolean,
                            DW_ATE_unsigned,
                            DW_ATE_signed,
                            DW_ATE_float,
                        }, switch (kind) {
                            .basic_bool_type => .DW_ATE_boolean,
                            .basic_unsigned_type => .DW_ATE_unsigned,
                            .basic_signed_type => .DW_ATE_signed,
                            .basic_float_type => .DW_ATE_float,
                            else => unreachable,
                        }),
                        .flags = null,
                    }, writer);
                },
                .composite_struct_type,
                .composite_union_type,
                .composite_enumeration_type,
                .composite_array_type,
                .composite_vector_type,
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.CompositeType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DICompositeType, .{
                        .tag = @as(enum {
                            DW_TAG_structure_type,
                            DW_TAG_union_type,
                            DW_TAG_enumeration_type,
                            DW_TAG_array_type,
                        }, switch (kind) {
                            .composite_struct_type => .DW_TAG_structure_type,
                            .composite_union_type => .DW_TAG_union_type,
                            .composite_enumeration_type => .DW_TAG_enumeration_type,
                            .composite_array_type, .composite_vector_type => .DW_TAG_array_type,
                            else => unreachable,
                        }),
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .scope = extra.scope,
                        .file = null,
                        .line = null,
                        .baseType = extra.underlying_type,
                        .size = extra.bit_size(),
                        .@"align" = extra.bit_align(),
                        .offset = null,
                        .flags = null,
                        .elements = extra.fields_tuple,
                        .runtimeLang = null,
                        .vtableHolder = null,
                        .templateParams = null,
                        .identifier = null,
                        .discriminator = null,
                        .dataLocation = null,
                        .associated = null,
                        .allocated = null,
                        .rank = null,
                        .annotations = null,
                    }, writer);
                },
                .derived_pointer_type,
                .derived_member_type,
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.DerivedType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIDerivedType, .{
                        .tag = @as(enum {
                            DW_TAG_pointer_type,
                            DW_TAG_member,
                        }, switch (kind) {
                            .derived_pointer_type => .DW_TAG_pointer_type,
                            .derived_member_type => .DW_TAG_member,
                            else => unreachable,
                        }),
                        .name = switch (extra.name) {
                            .none => null,
                            else => extra.name,
                        },
                        .scope = extra.scope,
                        .file = null,
                        .line = null,
                        .baseType = extra.underlying_type,
                        .size = extra.bit_size(),
                        .@"align" = extra.bit_align(),
                        .offset = switch (extra.bit_offset()) {
                            0 => null,
                            else => |bit_offset| bit_offset,
                        },
                        .flags = null,
                        .extra_data = null,
                        .dwarfAddressSpace = null,
                        .annotations = null,
                    }, writer);
                },
                .subroutine_type => {
                    const extra = self.metadata_extra_data(Metadata.SubroutineType, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DISubroutineType, .{
                        .flags = null,
                        .cc = null,
                        .types = extra.types_tuple,
                    }, writer);
                },
                .enumerator_unsigned,
                .enumerator_signed_positive,
                .enumerator_signed_negative,
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.Enumerator, metadata_item.data);

                    const ExpectedContents = extern struct {
                        const expected_limbs = @div_exact(512, @bitSizeOf(std.math.big.Limb));
                        string: [
                            (std.math.big.int.Const{
                                .limbs = &([1]std.math.big.Limb{
                                    std.math.max_int(std.math.big.Limb),
                                } ** expected_limbs),
                                .positive = false,
                            }).size_in_base_upper_bound(10)
                        ]u8,
                        limbs: [
                            std.math.big.int.calc_to_string_limbs_buffer_len(expected_limbs, 10)
                        ]std.math.big.Limb,
                    };
                    var stack align(@alignOf(ExpectedContents)) =
                        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
                    const allocator = stack.get();

                    const limbs = self.metadata_limbs.items[extra.limbs_index..][0..extra.limbs_len];
                    const bigint: std.math.big.int.Const = .{
                        .limbs = limbs,
                        .positive = switch (kind) {
                            .enumerator_unsigned,
                            .enumerator_signed_positive,
                            => true,
                            .enumerator_signed_negative => false,
                            else => unreachable,
                        },
                    };
                    const str = try bigint.to_string_alloc(allocator, 10, undefined);
                    defer allocator.free(str);

                    try metadata_formatter.specialized(.@"!", .DIEnumerator, .{
                        .name = extra.name,
                        .value = str,
                        .is_unsigned = switch (kind) {
                            .enumerator_unsigned => true,
                            .enumerator_signed_positive,
                            .enumerator_signed_negative,
                            => false,
                            else => unreachable,
                        },
                    }, writer);
                },
                .subrange => {
                    const extra = self.metadata_extra_data(Metadata.Subrange, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DISubrange, .{
                        .count = extra.count,
                        .lower_bound = extra.lower_bound,
                        .upper_bound = null,
                        .stride = null,
                    }, writer);
                },
                .tuple => {
                    var extra = self.metadata_extra_data_trail(Metadata.Tuple, metadata_item.data);
                    const elements = extra.trail.next(extra.data.elements_len, Metadata, self);
                    try writer.write_all("!{");
                    for (elements) |element| try writer.print("{[element]%}", .{
                        .element = try metadata_formatter.fmt("", element),
                    });
                    try writer.write_all("}\n");
                },
                .module_flag => {
                    const extra = self.metadata_extra_data(Metadata.ModuleFlag, metadata_item.data);
                    try writer.print("!{{{[behavior]%}{[name]%}{[constant]%}}}\n", .{
                        .behavior = try metadata_formatter.fmt("", extra.behavior),
                        .name = try metadata_formatter.fmt("", extra.name),
                        .constant = try metadata_formatter.fmt("", extra.constant),
                    });
                },
                .local_var => {
                    const extra = self.metadata_extra_data(Metadata.LocalVar, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocalVariable, .{
                        .name = extra.name,
                        .arg = null,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .flags = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .parameter => {
                    const extra = self.metadata_extra_data(Metadata.Parameter, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DILocalVariable, .{
                        .name = extra.name,
                        .arg = extra.arg_no,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .flags = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .global_var,
                .@"global_var local",
                => |kind| {
                    const extra = self.metadata_extra_data(Metadata.GlobalVar, metadata_item.data);
                    try metadata_formatter.specialized(.@"distinct !", .DIGlobalVariable, .{
                        .name = extra.name,
                        .linkageName = extra.linkage_name,
                        .scope = extra.scope,
                        .file = extra.file,
                        .line = extra.line,
                        .type = extra.ty,
                        .is_local = switch (kind) {
                            .global_var => false,
                            .@"global_var local" => true,
                            else => unreachable,
                        },
                        .isDefinition = true,
                        .declaration = null,
                        .templateParams = null,
                        .@"align" = null,
                        .annotations = null,
                    }, writer);
                },
                .global_var_expression => {
                    const extra =
                        self.metadata_extra_data(Metadata.GlobalVarExpression, metadata_item.data);
                    try metadata_formatter.specialized(.@"!", .DIGlobalVariableExpression, .{
                        .@"var" = extra.variable,
                        .expr = extra.expression,
                    }, writer);
                },
            }
        }
    }
}

const NoExtra = struct {};

fn is_valid_identifier(id: []const u8) bool {
    for (id, 0..) |byte, index| switch (byte) {
        '$', '-', '.', 'A'...'Z', '_', 'a'...'z' => {},
        '0'...'9' => if (index == 0) return false,
        else => return false,
    };
    return true;
}

const QuoteBehavior = enum { always_quote, quote_unless_valid_identifier };
fn print_escaped_string(
    slice: []const u8,
    quotes: QuoteBehavior,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const need_quotes = switch (quotes) {
        .always_quote => true,
        .quote_unless_valid_identifier => !is_valid_identifier(slice),
    };
    if (need_quotes) try writer.write_byte('"');
    for (slice) |byte| switch (byte) {
        '\\' => try writer.write_all("\\\\"),
        ' '...'"' - 1, '"' + 1...'\\' - 1, '\\' + 1...'~' => try writer.write_byte(byte),
        else => try writer.print("\\{X:0>2}", .{byte}),
    };
    if (need_quotes) try writer.write_byte('"');
}

fn ensure_unused_global_capacity(self: *Builder, name: StrtabString) Allocator.Error!void {
    try self.strtab_string_map.ensure_unused_capacity(self.gpa, 1);
    if (name.slice(self)) |id| {
        const count: usize = comptime std.fmt.count("{d}", .{std.math.max_int(u32)});
        try self.strtab_string_bytes.ensure_unused_capacity(self.gpa, id.len + count);
    }
    try self.strtab_string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.globals.ensure_unused_capacity(self.gpa, 1);
    try self.next_unique_global_id.ensure_unused_capacity(self.gpa, 1);
}

fn fn_type_assume_capacity(
    self: *Builder,
    ret: Type,
    params: []const Type,
    comptime kind: Type.Function.Kind,
) Type {
    const tag: Type.Tag = switch (kind) {
        .normal => .function,
        .vararg => .vararg_function,
    };
    const Key = struct { ret: Type, params: []const Type };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(comptime std.hash.uint32(@int_from_enum(tag)));
            hasher.update(std.mem.as_bytes(&key.ret));
            hasher.update(std.mem.slice_as_bytes(key.params));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            if (rhs_data.tag != tag) return false;
            var rhs_extra = ctx.builder.type_extra_data_trail(Type.Function, rhs_data.data);
            const rhs_params = rhs_extra.trail.next(rhs_extra.data.params_len, Type, ctx.builder);
            return lhs_key.ret == rhs_extra.data.ret and std.mem.eql(Type, lhs_key.params, rhs_params);
        }
    };
    const gop = self.type_map.get_or_put_assume_capacity_adapted(
        Key{ .ret = ret, .params = params },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_type_extra_assume_capacity(Type.Function{
                .ret = ret,
                .params_len = @int_cast(params.len),
            }),
        });
        self.type_extra.append_slice_assume_capacity(@ptr_cast(params));
    }
    return @enumFromInt(gop.index);
}

fn int_type_assume_capacity(self: *Builder, bits: u24) Type {
    assert(bits > 0);
    const result = self.get_or_put_type_no_extra_assume_capacity(.{ .tag = .integer, .data = bits });
    return result.type;
}

fn ptr_type_assume_capacity(self: *Builder, addr_space: AddrSpace) Type {
    const result = self.get_or_put_type_no_extra_assume_capacity(
        .{ .tag = .pointer, .data = @int_from_enum(addr_space) },
    );
    return result.type;
}

fn vector_type_assume_capacity(
    self: *Builder,
    comptime kind: Type.Vector.Kind,
    len: u32,
    child: Type,
) Type {
    assert(child.is_floating_point() or child.is_integer(self) or child.is_pointer(self));
    const tag: Type.Tag = switch (kind) {
        .normal => .vector,
        .scalable => .scalable_vector,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Type.Vector) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(tag)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Type.Vector, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            return rhs_data.tag == tag and
                std.meta.eql(lhs_key, ctx.builder.type_extra_data(Type.Vector, rhs_data.data));
        }
    };
    const data = Type.Vector{ .len = len, .child = child };
    const gop = self.type_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_type_extra_assume_capacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn array_type_assume_capacity(self: *Builder, len: u64, child: Type) Type {
    if (std.math.cast(u32, len)) |small_len| {
        const Adapter = struct {
            builder: *const Builder,
            pub fn hash(_: @This(), key: Type.Vector) u32 {
                return @truncate(std.hash.Wyhash.hash(
                    comptime std.hash.uint32(@int_from_enum(Type.Tag.small_array)),
                    std.mem.as_bytes(&key),
                ));
            }
            pub fn eql(ctx: @This(), lhs_key: Type.Vector, _: void, rhs_index: usize) bool {
                const rhs_data = ctx.builder.type_items.items[rhs_index];
                return rhs_data.tag == .small_array and
                    std.meta.eql(lhs_key, ctx.builder.type_extra_data(Type.Vector, rhs_data.data));
            }
        };
        const data = Type.Vector{ .len = small_len, .child = child };
        const gop = self.type_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
        if (!gop.found_existing) {
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.append_assume_capacity(.{
                .tag = .small_array,
                .data = self.add_type_extra_assume_capacity(data),
            });
        }
        return @enumFromInt(gop.index);
    } else {
        const Adapter = struct {
            builder: *const Builder,
            pub fn hash(_: @This(), key: Type.Array) u32 {
                return @truncate(std.hash.Wyhash.hash(
                    comptime std.hash.uint32(@int_from_enum(Type.Tag.array)),
                    std.mem.as_bytes(&key),
                ));
            }
            pub fn eql(ctx: @This(), lhs_key: Type.Array, _: void, rhs_index: usize) bool {
                const rhs_data = ctx.builder.type_items.items[rhs_index];
                return rhs_data.tag == .array and
                    std.meta.eql(lhs_key, ctx.builder.type_extra_data(Type.Array, rhs_data.data));
            }
        };
        const data = Type.Array{
            .len_lo = @truncate(len),
            .len_hi = @int_cast(len >> 32),
            .child = child,
        };
        const gop = self.type_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
        if (!gop.found_existing) {
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.append_assume_capacity(.{
                .tag = .array,
                .data = self.add_type_extra_assume_capacity(data),
            });
        }
        return @enumFromInt(gop.index);
    }
}

fn struct_type_assume_capacity(
    self: *Builder,
    comptime kind: Type.Structure.Kind,
    fields: []const Type,
) Type {
    const tag: Type.Tag = switch (kind) {
        .normal => .structure,
        .@"packed" => .packed_structure,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: []const Type) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(tag)),
                std.mem.slice_as_bytes(key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: []const Type, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            if (rhs_data.tag != tag) return false;
            var rhs_extra = ctx.builder.type_extra_data_trail(Type.Structure, rhs_data.data);
            const rhs_fields = rhs_extra.trail.next(rhs_extra.data.fields_len, Type, ctx.builder);
            return std.mem.eql(Type, lhs_key, rhs_fields);
        }
    };
    const gop = self.type_map.get_or_put_assume_capacity_adapted(fields, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_type_extra_assume_capacity(Type.Structure{
                .fields_len = @int_cast(fields.len),
            }),
        });
        self.type_extra.append_slice_assume_capacity(@ptr_cast(fields));
    }
    return @enumFromInt(gop.index);
}

fn opaque_type_assume_capacity(self: *Builder, name: String) Type {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: String) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Type.Tag.named_structure)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: String, _: void, rhs_index: usize) bool {
            const rhs_data = ctx.builder.type_items.items[rhs_index];
            return rhs_data.tag == .named_structure and
                lhs_key == ctx.builder.type_extra_data(Type.NamedStructure, rhs_data.data).id;
        }
    };
    var id = name;
    if (name == .empty) {
        id = self.next_unnamed_type;
        assert(id != .none);
        self.next_unnamed_type = @enumFromInt(@int_from_enum(id) + 1);
    } else assert(!name.is_anon());
    while (true) {
        const type_gop = self.types.get_or_put_assume_capacity(id);
        if (!type_gop.found_existing) {
            const gop = self.type_map.get_or_put_assume_capacity_adapted(id, Adapter{ .builder = self });
            assert(!gop.found_existing);
            gop.key_ptr.* = {};
            gop.value_ptr.* = {};
            self.type_items.append_assume_capacity(.{
                .tag = .named_structure,
                .data = self.add_type_extra_assume_capacity(Type.NamedStructure{
                    .id = id,
                    .body = .none,
                }),
            });
            const result: Type = @enumFromInt(gop.index);
            type_gop.value_ptr.* = result;
            return result;
        }

        const unique_gop = self.next_unique_type_id.get_or_put_assume_capacity(name);
        if (!unique_gop.found_existing) unique_gop.value_ptr.* = 2;
        id = self.fmt_assume_capacity("{s}.{d}", .{ name.slice(self).?, unique_gop.value_ptr.* });
        unique_gop.value_ptr.* += 1;
    }
}

fn ensure_unused_type_capacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.type_map.ensure_unused_capacity(self.gpa, count);
    try self.type_items.ensure_unused_capacity(self.gpa, count);
    try self.type_extra.ensure_unused_capacity(
        self.gpa,
        count * (@typeInfo(Extra).Struct.fields.len + trail_len),
    );
}

fn get_or_put_type_no_extra_assume_capacity(self: *Builder, item: Type.Item) struct { new: bool, type: Type } {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Type.Item) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Type.Tag.simple)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Type.Item, _: void, rhs_index: usize) bool {
            const lhs_bits: u32 = @bit_cast(lhs_key);
            const rhs_bits: u32 = @bit_cast(ctx.builder.type_items.items[rhs_index]);
            return lhs_bits == rhs_bits;
        }
    };
    const gop = self.type_map.get_or_put_assume_capacity_adapted(item, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.type_items.append_assume_capacity(item);
    }
    return .{ .new = !gop.found_existing, .type = @enumFromInt(gop.index) };
}

fn add_type_extra_assume_capacity(self: *Builder, extra: anytype) Type.Item.ExtraIndex {
    const result: Type.Item.ExtraIndex = @int_cast(self.type_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
        const value = @field(extra, field.name);
        self.type_extra.append_assume_capacity(switch (field.type) {
            u32 => value,
            String, Type => @int_from_enum(value),
            else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
        });
    }
    return result;
}

const TypeExtraDataTrail = struct {
    index: Type.Item.ExtraIndex,

    fn next_mut(self: *TypeExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptr_cast(builder.type_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }

    fn next(
        self: *TypeExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptr_cast(builder.type_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }
};

fn type_extra_data_trail(
    self: *const Builder,
    comptime T: type,
    index: Type.Item.ExtraIndex,
) struct { data: T, trail: TypeExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).Struct.fields;
    inline for (fields, self.type_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            String, Type => @enumFromInt(value),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Type.Item.ExtraIndex, @int_cast(fields.len)) },
    };
}

fn type_extra_data(self: *const Builder, comptime T: type, index: Type.Item.ExtraIndex) T {
    return self.type_extra_data_trail(T, index).data;
}

fn attr_generic(self: *Builder, data: []const u32) Allocator.Error!u32 {
    try self.attributes_map.ensure_unused_capacity(self.gpa, 1);
    try self.attributes_indices.ensure_unused_capacity(self.gpa, 1);
    try self.attributes_extra.ensure_unused_capacity(self.gpa, data.len);

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: []const u32) u32 {
            return @truncate(std.hash.Wyhash.hash(1, std.mem.slice_as_bytes(key)));
        }
        pub fn eql(ctx: @This(), lhs_key: []const u32, _: void, rhs_index: usize) bool {
            const start = ctx.builder.attributes_indices.items[rhs_index];
            const end = ctx.builder.attributes_indices.items[rhs_index + 1];
            return std.mem.eql(u32, lhs_key, ctx.builder.attributes_extra.items[start..end]);
        }
    };
    const gop = self.attributes_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.attributes_extra.append_slice_assume_capacity(data);
        self.attributes_indices.append_assume_capacity(@int_cast(self.attributes_extra.items.len));
    }
    return @int_cast(gop.index);
}

fn big_int_const_assume_capacity(
    self: *Builder,
    ty: Type,
    value: std.math.big.int.Const,
) Allocator.Error!Constant {
    const type_item = self.type_items.items[@int_from_enum(ty)];
    assert(type_item.tag == .integer);
    const bits = type_item.data;

    const ExpectedContents = [64 / @size_of(std.math.big.Limb)]std.math.big.Limb;
    var stack align(@alignOf(ExpectedContents)) =
        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
    const allocator = stack.get();

    var limbs: []std.math.big.Limb = &.{};
    defer allocator.free(limbs);
    const canonical_value = if (value.fits_in_twos_comp(.signed, bits)) value else canon: {
        assert(value.fits_in_twos_comp(.unsigned, bits));
        limbs = try allocator.alloc(std.math.big.Limb, std.math.big.int.calc_twos_comp_limb_count(bits));
        var temp_value = std.math.big.int.Mutable.init(limbs, 0);
        temp_value.truncate(value, .signed, bits);
        break :canon temp_value.to_const();
    };
    assert(canonical_value.fits_in_twos_comp(.signed, bits));

    const ExtraPtr = *align(@alignOf(std.math.big.Limb)) Constant.Integer;
    const Key = struct { tag: Constant.Tag, type: Type, limbs: []const std.math.big.Limb };
    const tag: Constant.Tag = switch (canonical_value.positive) {
        true => .positive_integer,
        false => .negative_integer,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(key.tag)));
            hasher.update(std.mem.as_bytes(&key.type));
            hasher.update(std.mem.slice_as_bytes(key.limbs));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra: ExtraPtr =
                @ptr_cast(ctx.builder.constant_limbs.items[rhs_data..][0..Constant.Integer.limbs]);
            const rhs_limbs = ctx.builder.constant_limbs
                .items[rhs_data + Constant.Integer.limbs ..][0..rhs_extra.limbs_len];
            return lhs_key.type == rhs_extra.type and
                std.mem.eql(std.math.big.Limb, lhs_key.limbs, rhs_limbs);
        }
    };

    const gop = self.constant_map.get_or_put_assume_capacity_adapted(
        Key{ .tag = tag, .type = ty, .limbs = canonical_value.limbs },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = tag,
            .data = @int_cast(self.constant_limbs.items.len),
        });
        const extra: ExtraPtr =
            @ptr_cast(self.constant_limbs.add_many_as_array_assume_capacity(Constant.Integer.limbs));
        extra.* = .{ .type = ty, .limbs_len = @int_cast(canonical_value.limbs.len) };
        self.constant_limbs.append_slice_assume_capacity(canonical_value.limbs);
    }
    return @enumFromInt(gop.index);
}

fn half_const_assume_capacity(self: *Builder, val: f16) Constant {
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .half, .data = @as(u16, @bit_cast(val)) },
    );
    return result.constant;
}

fn bfloat_const_assume_capacity(self: *Builder, val: f32) Constant {
    assert(@as(u16, @truncate(@as(u32, @bit_cast(val)))) == 0);
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .bfloat, .data = @bit_cast(val) },
    );
    return result.constant;
}

fn float_const_assume_capacity(self: *Builder, val: f32) Constant {
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .float, .data = @bit_cast(val) },
    );
    return result.constant;
}

fn double_const_assume_capacity(self: *Builder, val: f64) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f64) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.double)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f64, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .double) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Double, rhs_data);
            return @as(u64, @bit_cast(lhs_key)) == @as(u64, rhs_extra.hi) << 32 | rhs_extra.lo;
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .double,
            .data = self.add_constant_extra_assume_capacity(Constant.Double{
                .lo = @truncate(@as(u64, @bit_cast(val))),
                .hi = @int_cast(@as(u64, @bit_cast(val)) >> 32),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn fp128_const_assume_capacity(self: *Builder, val: f128) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f128) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.fp128)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f128, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .fp128) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Fp128, rhs_data);
            return @as(u128, @bit_cast(lhs_key)) == @as(u128, rhs_extra.hi_hi) << 96 |
                @as(u128, rhs_extra.hi_lo) << 64 | @as(u128, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo;
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .fp128,
            .data = self.add_constant_extra_assume_capacity(Constant.Fp128{
                .lo_lo = @truncate(@as(u128, @bit_cast(val))),
                .lo_hi = @truncate(@as(u128, @bit_cast(val)) >> 32),
                .hi_lo = @truncate(@as(u128, @bit_cast(val)) >> 64),
                .hi_hi = @int_cast(@as(u128, @bit_cast(val)) >> 96),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn x86_fp80_const_assume_capacity(self: *Builder, val: f80) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: f80) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.x86_fp80)),
                std.mem.as_bytes(&key)[0..10],
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: f80, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .x86_fp80) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Fp80, rhs_data);
            return @as(u80, @bit_cast(lhs_key)) == @as(u80, rhs_extra.hi) << 64 |
                @as(u80, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo;
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .x86_fp80,
            .data = self.add_constant_extra_assume_capacity(Constant.Fp80{
                .lo_lo = @truncate(@as(u80, @bit_cast(val))),
                .lo_hi = @truncate(@as(u80, @bit_cast(val)) >> 32),
                .hi = @int_cast(@as(u80, @bit_cast(val)) >> 64),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn ppc_fp128_const_assume_capacity(self: *Builder, val: [2]f64) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: [2]f64) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.ppc_fp128)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: [2]f64, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .ppc_fp128) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Fp128, rhs_data);
            return @as(u64, @bit_cast(lhs_key[0])) == @as(u64, rhs_extra.lo_hi) << 32 | rhs_extra.lo_lo and
                @as(u64, @bit_cast(lhs_key[1])) == @as(u64, rhs_extra.hi_hi) << 32 | rhs_extra.hi_lo;
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(val, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .ppc_fp128,
            .data = self.add_constant_extra_assume_capacity(Constant.Fp128{
                .lo_lo = @truncate(@as(u64, @bit_cast(val[0]))),
                .lo_hi = @int_cast(@as(u64, @bit_cast(val[0])) >> 32),
                .hi_lo = @truncate(@as(u64, @bit_cast(val[1]))),
                .hi_hi = @int_cast(@as(u64, @bit_cast(val[1])) >> 32),
            }),
        });
    }
    return @enumFromInt(gop.index);
}

fn null_const_assume_capacity(self: *Builder, ty: Type) Constant {
    assert(self.type_items.items[@int_from_enum(ty)].tag == .pointer);
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .null, .data = @int_from_enum(ty) },
    );
    return result.constant;
}

fn none_const_assume_capacity(self: *Builder, ty: Type) Constant {
    assert(ty == .token);
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .none, .data = @int_from_enum(ty) },
    );
    return result.constant;
}

fn struct_const_assume_capacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    const type_item = self.type_items.items[@int_from_enum(ty)];
    var extra = self.type_extra_data_trail(Type.Structure, switch (type_item.tag) {
        .structure, .packed_structure => type_item.data,
        .named_structure => data: {
            const body_ty = self.type_extra_data(Type.NamedStructure, type_item.data).body;
            const body_item = self.type_items.items[@int_from_enum(body_ty)];
            switch (body_item.tag) {
                .structure, .packed_structure => break :data body_item.data,
                else => unreachable,
            }
        },
        else => unreachable,
    });
    const fields = extra.trail.next(extra.data.fields_len, Type, self);
    for (fields, vals) |field, val| assert(field == val.type_of(self));

    for (vals) |val| {
        if (!val.is_zero_init(self)) break;
    } else return self.zero_init_const_assume_capacity(ty);

    const tag: Constant.Tag = switch (ty.unnamed_tag(self)) {
        .structure => .structure,
        .packed_structure => .packed_structure,
        else => unreachable,
    };
    const result = self.get_or_put_constant_aggregate_assume_capacity(tag, ty, vals);
    return result.constant;
}

fn array_const_assume_capacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    const type_item = self.type_items.items[@int_from_enum(ty)];
    const type_extra: struct { len: u64, child: Type } = switch (type_item.tag) {
        inline .small_array, .array => |kind| extra: {
            const extra = self.type_extra_data(switch (kind) {
                .small_array => Type.Vector,
                .array => Type.Array,
                else => unreachable,
            }, type_item.data);
            break :extra .{ .len = extra.length(), .child = extra.child };
        },
        else => unreachable,
    };
    assert(type_extra.len == vals.len);
    for (vals) |val| assert(type_extra.child == val.type_of(self));

    for (vals) |val| {
        if (!val.is_zero_init(self)) break;
    } else return self.zero_init_const_assume_capacity(ty);

    const result = self.get_or_put_constant_aggregate_assume_capacity(.array, ty, vals);
    return result.constant;
}

fn string_const_assume_capacity(self: *Builder, val: String) Constant {
    const slice = val.slice(self).?;
    const ty = self.array_type_assume_capacity(slice.len, .i8);
    if (std.mem.all_equal(u8, slice, 0)) return self.zero_init_const_assume_capacity(ty);
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .string, .data = @int_from_enum(val) },
    );
    return result.constant;
}

fn vector_const_assume_capacity(self: *Builder, ty: Type, vals: []const Constant) Constant {
    assert(ty.is_vector(self));
    assert(ty.vector_len(self) == vals.len);
    for (vals) |val| assert(ty.child_type(self) == val.type_of(self));

    for (vals[1..]) |val| {
        if (vals[0] != val) break;
    } else return self.splat_const_assume_capacity(ty, vals[0]);
    for (vals) |val| {
        if (!val.is_zero_init(self)) break;
    } else return self.zero_init_const_assume_capacity(ty);

    const result = self.get_or_put_constant_aggregate_assume_capacity(.vector, ty, vals);
    return result.constant;
}

fn splat_const_assume_capacity(self: *Builder, ty: Type, val: Constant) Constant {
    assert(ty.scalar_type(self) == val.type_of(self));

    if (!ty.is_vector(self)) return val;
    if (val.is_zero_init(self)) return self.zero_init_const_assume_capacity(ty);

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.Splat) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.splat)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.Splat, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .splat) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Splat, rhs_data);
            return std.meta.eql(lhs_key, rhs_extra);
        }
    };
    const data = Constant.Splat{ .type = ty, .value = val };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .splat,
            .data = self.add_constant_extra_assume_capacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn zero_init_const_assume_capacity(self: *Builder, ty: Type) Constant {
    switch (ty) {
        inline .half,
        .bfloat,
        .float,
        .double,
        .fp128,
        .x86_fp80,
        => |tag| return @field(Builder, @tag_name(tag) ++ "ConstAssumeCapacity")(self, 0.0),
        .ppc_fp128 => return self.ppc_fp128_const_assume_capacity(.{ 0.0, 0.0 }),
        .token => return .none,
        .i1 => return .false,
        else => switch (self.type_items.items[@int_from_enum(ty)].tag) {
            .simple,
            .function,
            .vararg_function,
            => unreachable,
            .integer => {
                var limbs: [std.math.big.int.calc_limb_len(0)]std.math.big.Limb = undefined;
                const bigint = std.math.big.int.Mutable.init(&limbs, 0);
                return self.big_int_const_assume_capacity(ty, bigint.to_const()) catch unreachable;
            },
            .pointer => return self.null_const_assume_capacity(ty),
            .target,
            .vector,
            .scalable_vector,
            .small_array,
            .array,
            .structure,
            .packed_structure,
            .named_structure,
            => {},
        },
    }
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .zeroinitializer, .data = @int_from_enum(ty) },
    );
    return result.constant;
}

fn undef_const_assume_capacity(self: *Builder, ty: Type) Constant {
    switch (self.type_items.items[@int_from_enum(ty)].tag) {
        .simple => switch (ty) {
            .void, .label => unreachable,
            else => {},
        },
        .function, .vararg_function => unreachable,
        else => {},
    }
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .undef, .data = @int_from_enum(ty) },
    );
    return result.constant;
}

fn poison_const_assume_capacity(self: *Builder, ty: Type) Constant {
    switch (self.type_items.items[@int_from_enum(ty)].tag) {
        .simple => switch (ty) {
            .void, .label => unreachable,
            else => {},
        },
        .function, .vararg_function => unreachable,
        else => {},
    }
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .poison, .data = @int_from_enum(ty) },
    );
    return result.constant;
}

fn block_addr_const_assume_capacity(
    self: *Builder,
    function: Function.Index,
    block: Function.Block.Index,
) Constant {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.BlockAddress) u32 {
            return @truncate(std.hash.Wyhash.hash(
                comptime std.hash.uint32(@int_from_enum(Constant.Tag.blockaddress)),
                std.mem.as_bytes(&key),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.BlockAddress, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != .blockaddress) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.BlockAddress, rhs_data);
            return std.meta.eql(lhs_key, rhs_extra);
        }
    };
    const data = Constant.BlockAddress{ .function = function, .block = block };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = .blockaddress,
            .data = self.add_constant_extra_assume_capacity(data),
        });
    }
    return @enumFromInt(gop.index);
}

fn dso_local_equivalent_const_assume_capacity(self: *Builder, function: Function.Index) Constant {
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .dso_local_equivalent, .data = @int_from_enum(function) },
    );
    return result.constant;
}

fn no_cfi_const_assume_capacity(self: *Builder, function: Function.Index) Constant {
    const result = self.get_or_put_constant_no_extra_assume_capacity(
        .{ .tag = .no_cfi, .data = @int_from_enum(function) },
    );
    return result.constant;
}

fn conv_tag(
    self: *Builder,
    signedness: Constant.Cast.Signedness,
    val_ty: Type,
    ty: Type,
) Function.Instruction.Tag {
    assert(val_ty != ty);
    return switch (val_ty.scalar_tag(self)) {
        .simple => switch (ty.scalar_tag(self)) {
            .simple => switch (std.math.order(val_ty.scalar_bits(self), ty.scalar_bits(self))) {
                .lt => .fpext,
                .eq => unreachable,
                .gt => .fptrunc,
            },
            .integer => switch (signedness) {
                .unsigned => .fptoui,
                .signed => .fptosi,
                .unneeded => unreachable,
            },
            else => unreachable,
        },
        .integer => switch (ty.scalar_tag(self)) {
            .simple => switch (signedness) {
                .unsigned => .uitofp,
                .signed => .sitofp,
                .unneeded => unreachable,
            },
            .integer => switch (std.math.order(val_ty.scalar_bits(self), ty.scalar_bits(self))) {
                .lt => switch (signedness) {
                    .unsigned => .zext,
                    .signed => .sext,
                    .unneeded => unreachable,
                },
                .eq => unreachable,
                .gt => .trunc,
            },
            .pointer => .inttoptr,
            else => unreachable,
        },
        .pointer => switch (ty.scalar_tag(self)) {
            .integer => .ptrtoint,
            .pointer => .addrspacecast,
            else => unreachable,
        },
        else => unreachable,
    };
}

fn conv_const_tag(
    self: *Builder,
    val_ty: Type,
    ty: Type,
) Constant.Tag {
    assert(val_ty != ty);
    return switch (val_ty.scalar_tag(self)) {
        .integer => switch (ty.scalar_tag(self)) {
            .integer => switch (std.math.order(val_ty.scalar_bits(self), ty.scalar_bits(self))) {
                .gt => .trunc,
                else => unreachable,
            },
            .pointer => .inttoptr,
            else => unreachable,
        },
        .pointer => switch (ty.scalar_tag(self)) {
            .integer => .ptrtoint,
            .pointer => .addrspacecast,
            else => unreachable,
        },
        else => unreachable,
    };
}

fn conv_const_assume_capacity(
    self: *Builder,
    val: Constant,
    ty: Type,
) Constant {
    const val_ty = val.type_of(self);
    if (val_ty == ty) return val;
    return self.cast_const_assume_capacity(self.conv_const_tag(val_ty, ty), val, ty);
}

fn cast_const_assume_capacity(self: *Builder, tag: Constant.Tag, val: Constant, ty: Type) Constant {
    const Key = struct { tag: Constant.Tag, cast: Constant.Cast };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@int_from_enum(key.tag)),
                std.mem.as_bytes(&key.cast),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Cast, rhs_data);
            return std.meta.eql(lhs_key.cast, rhs_extra);
        }
    };
    const data = Key{ .tag = tag, .cast = .{ .val = val, .type = ty } };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_constant_extra_assume_capacity(data.cast),
        });
    }
    return @enumFromInt(gop.index);
}

fn gep_const_assume_capacity(
    self: *Builder,
    comptime kind: Constant.GetElementPtr.Kind,
    ty: Type,
    base: Constant,
    inrange: ?u16,
    indices: []const Constant,
) Constant {
    const tag: Constant.Tag = switch (kind) {
        .normal => .getelementptr,
        .inbounds => .@"getelementptr inbounds",
    };
    const base_ty = base.type_of(self);
    const base_is_vector = base_ty.is_vector(self);

    const VectorInfo = struct {
        kind: Type.Vector.Kind,
        len: u32,

        fn init(vector_ty: Type, builder: *const Builder) @This() {
            return .{ .kind = vector_ty.vector_kind(builder), .len = vector_ty.vector_len(builder) };
        }
    };
    var vector_info: ?VectorInfo = if (base_is_vector) VectorInfo.init(base_ty, self) else null;
    for (indices) |index| {
        const index_ty = index.type_of(self);
        switch (index_ty.tag(self)) {
            .integer => {},
            .vector, .scalable_vector => {
                const index_info = VectorInfo.init(index_ty, self);
                if (vector_info) |info|
                    assert(std.meta.eql(info, index_info))
                else
                    vector_info = index_info;
            },
            else => unreachable,
        }
    }
    if (!base_is_vector) if (vector_info) |info| switch (info.kind) {
        inline else => |vector_kind| _ = self.vector_type_assume_capacity(vector_kind, info.len, base_ty),
    };

    const Key = struct {
        type: Type,
        base: Constant,
        inrange: Constant.GetElementPtr.InRangeIndex,
        indices: []const Constant,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(comptime std.hash.uint32(@int_from_enum(tag)));
            hasher.update(std.mem.as_bytes(&key.type));
            hasher.update(std.mem.as_bytes(&key.base));
            hasher.update(std.mem.as_bytes(&key.inrange));
            hasher.update(std.mem.slice_as_bytes(key.indices));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (ctx.builder.constant_items.items(.tag)[rhs_index] != tag) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.constant_extra_data_trail(Constant.GetElementPtr, rhs_data);
            const rhs_indices =
                rhs_extra.trail.next(rhs_extra.data.info.indices_len, Constant, ctx.builder);
            return lhs_key.type == rhs_extra.data.type and lhs_key.base == rhs_extra.data.base and
                lhs_key.inrange == rhs_extra.data.info.inrange and
                std.mem.eql(Constant, lhs_key.indices, rhs_indices);
        }
    };
    const data = Key{
        .type = ty,
        .base = base,
        .inrange = if (inrange) |index| @enumFromInt(index) else .none,
        .indices = indices,
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_constant_extra_assume_capacity(Constant.GetElementPtr{
                .type = ty,
                .base = base,
                .info = .{ .indices_len = @int_cast(indices.len), .inrange = data.inrange },
            }),
        });
        self.constant_extra.append_slice_assume_capacity(@ptr_cast(indices));
    }
    return @enumFromInt(gop.index);
}

fn bin_const_assume_capacity(
    self: *Builder,
    tag: Constant.Tag,
    lhs: Constant,
    rhs: Constant,
) Constant {
    switch (tag) {
        .add,
        .@"add nsw",
        .@"add nuw",
        .sub,
        .@"sub nsw",
        .@"sub nuw",
        .shl,
        .xor,
        => {},
        else => unreachable,
    }
    const Key = struct { tag: Constant.Tag, extra: Constant.Binary };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@int_from_enum(key.tag)),
                std.mem.as_bytes(&key.extra),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Binary, rhs_data);
            return std.meta.eql(lhs_key.extra, rhs_extra);
        }
    };
    const data = Key{ .tag = tag, .extra = .{ .lhs = lhs, .rhs = rhs } };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_constant_extra_assume_capacity(data.extra),
        });
    }
    return @enumFromInt(gop.index);
}

fn asm_const_assume_capacity(
    self: *Builder,
    ty: Type,
    info: Constant.Assembly.Info,
    assembly: String,
    constraints: String,
) Constant {
    assert(ty.function_kind(self) == .normal);

    const Key = struct { tag: Constant.Tag, extra: Constant.Assembly };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@int_from_enum(key.tag)),
                std.mem.as_bytes(&key.extra),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.constant_extra_data(Constant.Assembly, rhs_data);
            return std.meta.eql(lhs_key.extra, rhs_extra);
        }
    };

    const data = Key{
        .tag = @enumFromInt(@int_from_enum(Constant.Tag.@"asm") + @as(u4, @bit_cast(info))),
        .extra = .{ .type = ty, .assembly = assembly, .constraints = constraints },
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(data, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = data.tag,
            .data = self.add_constant_extra_assume_capacity(data.extra),
        });
    }
    return @enumFromInt(gop.index);
}

fn ensure_unused_constant_capacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.constant_map.ensure_unused_capacity(self.gpa, count);
    try self.constant_items.ensure_unused_capacity(self.gpa, count);
    try self.constant_extra.ensure_unused_capacity(
        self.gpa,
        count * (@typeInfo(Extra).Struct.fields.len + trail_len),
    );
}

fn get_or_put_constant_no_extra_assume_capacity(
    self: *Builder,
    item: Constant.Item,
) struct { new: bool, constant: Constant } {
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant.Item) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@int_from_enum(key.tag)),
                std.mem.as_bytes(&key.data),
            ));
        }
        pub fn eql(ctx: @This(), lhs_key: Constant.Item, _: void, rhs_index: usize) bool {
            return std.meta.eql(lhs_key, ctx.builder.constant_items.get(rhs_index));
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(item, Adapter{ .builder = self });
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(item);
    }
    return .{ .new = !gop.found_existing, .constant = @enumFromInt(gop.index) };
}

fn get_or_put_constant_aggregate_assume_capacity(
    self: *Builder,
    tag: Constant.Tag,
    ty: Type,
    vals: []const Constant,
) struct { new: bool, constant: Constant } {
    switch (tag) {
        .structure, .packed_structure, .array, .vector => {},
        else => unreachable,
    }
    const Key = struct { tag: Constant.Tag, type: Type, vals: []const Constant };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(key.tag)));
            hasher.update(std.mem.as_bytes(&key.type));
            hasher.update(std.mem.slice_as_bytes(key.vals));
            return @truncate(hasher.final());
        }
        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.constant_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.constant_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.constant_extra_data_trail(Constant.Aggregate, rhs_data);
            if (lhs_key.type != rhs_extra.data.type) return false;
            const rhs_vals = rhs_extra.trail.next(@int_cast(lhs_key.vals.len), Constant, ctx.builder);
            return std.mem.eql(Constant, lhs_key.vals, rhs_vals);
        }
    };
    const gop = self.constant_map.get_or_put_assume_capacity_adapted(
        Key{ .tag = tag, .type = ty, .vals = vals },
        Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.constant_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_constant_extra_assume_capacity(Constant.Aggregate{ .type = ty }),
        });
        self.constant_extra.append_slice_assume_capacity(@ptr_cast(vals));
    }
    return .{ .new = !gop.found_existing, .constant = @enumFromInt(gop.index) };
}

fn add_constant_extra_assume_capacity(self: *Builder, extra: anytype) Constant.Item.ExtraIndex {
    const result: Constant.Item.ExtraIndex = @int_cast(self.constant_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
        const value = @field(extra, field.name);
        self.constant_extra.append_assume_capacity(switch (field.type) {
            u32 => value,
            String, Type, Constant, Function.Index, Function.Block.Index => @int_from_enum(value),
            Constant.GetElementPtr.Info => @bit_cast(value),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        });
    }
    return result;
}

const ConstantExtraDataTrail = struct {
    index: Constant.Item.ExtraIndex,

    fn next_mut(self: *ConstantExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptr_cast(builder.constant_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }

    fn next(
        self: *ConstantExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptr_cast(builder.constant_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }
};

fn constant_extra_data_trail(
    self: *const Builder,
    comptime T: type,
    index: Constant.Item.ExtraIndex,
) struct { data: T, trail: ConstantExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).Struct.fields;
    inline for (fields, self.constant_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            String, Type, Constant, Function.Index, Function.Block.Index => @enumFromInt(value),
            Constant.GetElementPtr.Info => @bit_cast(value),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Constant.Item.ExtraIndex, @int_cast(fields.len)) },
    };
}

fn constant_extra_data(self: *const Builder, comptime T: type, index: Constant.Item.ExtraIndex) T {
    return self.constant_extra_data_trail(T, index).data;
}

fn ensure_unused_metadata_capacity(
    self: *Builder,
    count: usize,
    comptime Extra: type,
    trail_len: usize,
) Allocator.Error!void {
    try self.metadata_map.ensure_unused_capacity(self.gpa, count);
    try self.metadata_items.ensure_unused_capacity(self.gpa, count);
    try self.metadata_extra.ensure_unused_capacity(
        self.gpa,
        count * (@typeInfo(Extra).Struct.fields.len + trail_len),
    );
}

fn add_metadata_extra_assume_capacity(self: *Builder, extra: anytype) Metadata.Item.ExtraIndex {
    const result: Metadata.Item.ExtraIndex = @int_cast(self.metadata_extra.items.len);
    inline for (@typeInfo(@TypeOf(extra)).Struct.fields) |field| {
        const value = @field(extra, field.name);
        self.metadata_extra.append_assume_capacity(switch (field.type) {
            u32 => value,
            MetadataString, Metadata, Variable.Index, Value => @int_from_enum(value),
            Metadata.DIFlags => @bit_cast(value),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        });
    }
    return result;
}

const MetadataExtraDataTrail = struct {
    index: Metadata.Item.ExtraIndex,

    fn next_mut(self: *MetadataExtraDataTrail, len: u32, comptime Item: type, builder: *Builder) []Item {
        const items: []Item = @ptr_cast(builder.metadata_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }

    fn next(
        self: *MetadataExtraDataTrail,
        len: u32,
        comptime Item: type,
        builder: *const Builder,
    ) []const Item {
        const items: []const Item = @ptr_cast(builder.metadata_extra.items[self.index..][0..len]);
        self.index += @int_cast(len);
        return items;
    }
};

fn metadata_extra_data_trail(
    self: *const Builder,
    comptime T: type,
    index: Metadata.Item.ExtraIndex,
) struct { data: T, trail: MetadataExtraDataTrail } {
    var result: T = undefined;
    const fields = @typeInfo(T).Struct.fields;
    inline for (fields, self.metadata_extra.items[index..][0..fields.len]) |field, value|
        @field(result, field.name) = switch (field.type) {
            u32 => value,
            MetadataString, Metadata, Variable.Index, Value => @enumFromInt(value),
            Metadata.DIFlags => @bit_cast(value),
            else => @compile_error("bad field type: " ++ @type_name(field.type)),
        };
    return .{
        .data = result,
        .trail = .{ .index = index + @as(Metadata.Item.ExtraIndex, @int_cast(fields.len)) },
    };
}

fn metadata_extra_data(self: *const Builder, comptime T: type, index: Metadata.Item.ExtraIndex) T {
    return self.metadata_extra_data_trail(T, index).data;
}

pub fn metadata_string(self: *Builder, bytes: []const u8) Allocator.Error!MetadataString {
    try self.metadata_string_bytes.ensure_unused_capacity(self.gpa, bytes.len);
    try self.metadata_string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.metadata_string_map.ensure_unused_capacity(self.gpa, 1);

    const gop = self.metadata_string_map.get_or_put_assume_capacity_adapted(
        bytes,
        MetadataString.Adapter{ .builder = self },
    );
    if (!gop.found_existing) {
        self.metadata_string_bytes.append_slice_assume_capacity(bytes);
        self.metadata_string_indices.append_assume_capacity(@int_cast(self.metadata_string_bytes.items.len));
    }
    return @enumFromInt(gop.index);
}

pub fn metadata_string_from_strtab_string(self: *Builder, str: StrtabString) Allocator.Error!MetadataString {
    if (str == .none or str == .empty) return MetadataString.none;
    return try self.metadata_string(str.slice(self).?);
}

pub fn metadata_string_fmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!MetadataString {
    try self.metadata_string_map.ensure_unused_capacity(self.gpa, 1);
    try self.metadata_string_bytes.ensure_unused_capacity(self.gpa, @int_cast(std.fmt.count(fmt_str, fmt_args)));
    try self.metadata_string_indices.ensure_unused_capacity(self.gpa, 1);
    return self.metadata_string_fmt_assume_capacity(fmt_str, fmt_args);
}

pub fn metadata_string_fmt_assume_capacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) MetadataString {
    self.metadata_string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailing_metadata_string_assume_capacity();
}

pub fn trailing_metadata_string(self: *Builder) Allocator.Error!MetadataString {
    try self.metadata_string_indices.ensure_unused_capacity(self.gpa, 1);
    try self.metadata_string_map.ensure_unused_capacity(self.gpa, 1);
    return self.trailing_metadata_string_assume_capacity();
}

pub fn trailing_metadata_string_assume_capacity(self: *Builder) MetadataString {
    const start = self.metadata_string_indices.get_last();
    const bytes: []const u8 = self.metadata_string_bytes.items[start..];
    const gop = self.metadata_string_map.get_or_put_assume_capacity_adapted(bytes, String.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.metadata_string_bytes.shrink_retaining_capacity(start);
    } else {
        self.metadata_string_indices.append_assume_capacity(@int_cast(self.metadata_string_bytes.items.len));
    }
    return @enumFromInt(gop.index);
}

pub fn debug_named(self: *Builder, name: MetadataString, operands: []const Metadata) Allocator.Error!void {
    try self.metadata_extra.ensure_unused_capacity(self.gpa, operands.len);
    try self.metadata_named.ensure_unused_capacity(self.gpa, 1);
    self.debug_named_assume_capacity(name, operands);
}

fn debug_none(self: *Builder) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, NoExtra, 0);
    return self.debug_none_assume_capacity();
}

pub fn debug_file(
    self: *Builder,
    filename: MetadataString,
    directory: MetadataString,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.File, 0);
    return self.debug_file_assume_capacity(filename, directory);
}

pub fn debug_compile_unit(
    self: *Builder,
    file: Metadata,
    producer: MetadataString,
    enums: Metadata,
    globals: Metadata,
    options: Metadata.CompileUnit.Options,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompileUnit, 0);
    return self.debug_compile_unit_assume_capacity(file, producer, enums, globals, options);
}

pub fn debug_subprogram(
    self: *Builder,
    file: Metadata,
    name: MetadataString,
    linkage_name: MetadataString,
    line: u32,
    scope_line: u32,
    ty: Metadata,
    options: Metadata.Subprogram.Options,
    compile_unit: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Subprogram, 0);
    return self.debug_subprogram_assume_capacity(
        file,
        name,
        linkage_name,
        line,
        scope_line,
        ty,
        options,
        compile_unit,
    );
}

pub fn debug_lexical_block(self: *Builder, scope: Metadata, file: Metadata, line: u32, column: u32) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.LexicalBlock, 0);
    return self.debug_lexical_block_assume_capacity(scope, file, line, column);
}

pub fn debug_location(self: *Builder, line: u32, column: u32, scope: Metadata, inlined_at: Metadata) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Location, 0);
    return self.debug_location_assume_capacity(line, column, scope, inlined_at);
}

pub fn debug_bool_type(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.BasicType, 0);
    return self.debug_bool_type_assume_capacity(name, size_in_bits);
}

pub fn debug_unsigned_type(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.BasicType, 0);
    return self.debug_unsigned_type_assume_capacity(name, size_in_bits);
}

pub fn debug_signed_type(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.BasicType, 0);
    return self.debug_signed_type_assume_capacity(name, size_in_bits);
}

pub fn debug_float_type(self: *Builder, name: MetadataString, size_in_bits: u64) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.BasicType, 0);
    return self.debug_float_type_assume_capacity(name, size_in_bits);
}

pub fn debug_forward_reference(self: *Builder) Allocator.Error!Metadata {
    try self.metadata_forward_references.ensure_unused_capacity(self.gpa, 1);
    return self.debug_forward_reference_assume_capacity();
}

pub fn debug_struct_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompositeType, 0);
    return self.debug_struct_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debug_union_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompositeType, 0);
    return self.debug_union_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debug_enumeration_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompositeType, 0);
    return self.debug_enumeration_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debug_array_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompositeType, 0);
    return self.debug_array_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debug_vector_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.CompositeType, 0);
    return self.debug_vector_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

pub fn debug_pointer_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.DerivedType, 0);
    return self.debug_pointer_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        offset_in_bits,
    );
}

pub fn debug_member_type(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.DerivedType, 0);
    return self.debug_member_type_assume_capacity(
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        offset_in_bits,
    );
}

pub fn debug_subroutine_type(
    self: *Builder,
    types_tuple: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.SubroutineType, 0);
    return self.debug_subroutine_type_assume_capacity(types_tuple);
}

pub fn debug_enumerator(
    self: *Builder,
    name: MetadataString,
    unsigned: bool,
    bit_width: u32,
    value: std.math.big.int.Const,
) Allocator.Error!Metadata {
    assert(!(unsigned and !value.positive));
    try self.ensure_unused_metadata_capacity(1, Metadata.Enumerator, 0);
    try self.metadata_limbs.ensure_unused_capacity(self.gpa, value.limbs.len);
    return self.debug_enumerator_assume_capacity(name, unsigned, bit_width, value);
}

pub fn debug_subrange(
    self: *Builder,
    lower_bound: Metadata,
    count: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Subrange, 0);
    return self.debug_subrange_assume_capacity(lower_bound, count);
}

pub fn debug_expression(
    self: *Builder,
    elements: []const u32,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Expression, elements.len * @size_of(u32));
    return self.debug_expression_assume_capacity(elements);
}

pub fn debug_tuple(
    self: *Builder,
    elements: []const Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Tuple, elements.len * @size_of(Metadata));
    return self.debug_tuple_assume_capacity(elements);
}

pub fn debug_module_flag(
    self: *Builder,
    behavior: Metadata,
    name: MetadataString,
    constant: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.ModuleFlag, 0);
    return self.debug_module_flag_assume_capacity(behavior, name, constant);
}

pub fn debug_local_var(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.LocalVar, 0);
    return self.debug_local_var_assume_capacity(name, file, scope, line, ty);
}

pub fn debug_parameter(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    arg_no: u32,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.Parameter, 0);
    return self.debug_parameter_assume_capacity(name, file, scope, line, ty, arg_no);
}

pub fn debug_global_var(
    self: *Builder,
    name: MetadataString,
    linkage_name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    variable: Variable.Index,
    options: Metadata.GlobalVar.Options,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.GlobalVar, 0);
    return self.debug_global_var_assume_capacity(
        name,
        linkage_name,
        file,
        scope,
        line,
        ty,
        variable,
        options,
    );
}

pub fn debug_global_var_expression(
    self: *Builder,
    variable: Metadata,
    expression: Metadata,
) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, Metadata.GlobalVarExpression, 0);
    return self.debug_global_var_expression_assume_capacity(variable, expression);
}

pub fn debug_constant(self: *Builder, value: Constant) Allocator.Error!Metadata {
    try self.ensure_unused_metadata_capacity(1, NoExtra, 0);
    return self.debug_constant_assume_capacity(value);
}

pub fn debug_forward_reference_set_type(self: *Builder, fwd_ref: Metadata, ty: Metadata) void {
    assert(
        @int_from_enum(fwd_ref) >= Metadata.first_forward_reference and
            @int_from_enum(fwd_ref) <= Metadata.first_local_metadata,
    );
    const index = @int_from_enum(fwd_ref) - Metadata.first_forward_reference;
    self.metadata_forward_references.items[index] = ty;
}

fn metadata_simple_assume_capacity(self: *Builder, tag: Metadata.Tag, value: anytype) Metadata {
    const Key = struct {
        tag: Metadata.Tag,
        value: @TypeOf(value),
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(key.tag)));
            inline for (std.meta.fields(@TypeOf(value))) |field| {
                hasher.update(std.mem.as_bytes(&@field(key.value, field.name)));
            }
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.metadata_extra_data(@TypeOf(value), rhs_data);
            return std.meta.eql(lhs_key.value, rhs_extra);
        }
    };

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        Key{ .tag = tag, .value = value },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_metadata_extra_assume_capacity(value),
        });
    }
    return @enumFromInt(gop.index);
}

fn metadata_distinct_assume_capacity(self: *Builder, tag: Metadata.Tag, value: anytype) Metadata {
    const Key = struct { tag: Metadata.Tag, index: Metadata };
    const Adapter = struct {
        pub fn hash(_: @This(), key: Key) u32 {
            return @truncate(std.hash.Wyhash.hash(
                std.hash.uint32(@int_from_enum(key.tag)),
                std.mem.as_bytes(&key.index),
            ));
        }

        pub fn eql(_: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            return @int_from_enum(lhs_key.index) == rhs_index;
        }
    };

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        Key{ .tag = tag, .index = @enumFromInt(self.metadata_map.count()) },
        Adapter{},
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_metadata_extra_assume_capacity(value),
        });
    }
    return @enumFromInt(gop.index);
}

fn debug_named_assume_capacity(self: *Builder, name: MetadataString, operands: []const Metadata) void {
    assert(!self.strip);
    assert(name != .none);
    const extra_index: u32 = @int_cast(self.metadata_extra.items.len);
    self.metadata_extra.append_slice_assume_capacity(@ptr_cast(operands));

    const gop = self.metadata_named.get_or_put_assume_capacity(name);
    gop.value_ptr.* = .{
        .index = extra_index,
        .len = @int_cast(operands.len),
    };
}

pub fn debug_none_assume_capacity(self: *Builder) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.none, .{});
}

fn debug_file_assume_capacity(
    self: *Builder,
    filename: MetadataString,
    directory: MetadataString,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.file, Metadata.File{
        .filename = filename,
        .directory = directory,
    });
}

pub fn debug_compile_unit_assume_capacity(
    self: *Builder,
    file: Metadata,
    producer: MetadataString,
    enums: Metadata,
    globals: Metadata,
    options: Metadata.CompileUnit.Options,
) Metadata {
    assert(!self.strip);
    return self.metadata_distinct_assume_capacity(
        if (options.optimized) .@"compile_unit optimized" else .compile_unit,
        Metadata.CompileUnit{
            .file = file,
            .producer = producer,
            .enums = enums,
            .globals = globals,
        },
    );
}

fn debug_subprogram_assume_capacity(
    self: *Builder,
    file: Metadata,
    name: MetadataString,
    linkage_name: MetadataString,
    line: u32,
    scope_line: u32,
    ty: Metadata,
    options: Metadata.Subprogram.Options,
    compile_unit: Metadata,
) Metadata {
    assert(!self.strip);
    const tag: Metadata.Tag = @enumFromInt(@int_from_enum(Metadata.Tag.subprogram) +
        @as(u3, @truncate(@as(u32, @bit_cast(options.sp_flags)) >> 2)));
    return self.metadata_distinct_assume_capacity(tag, Metadata.Subprogram{
        .file = file,
        .name = name,
        .linkage_name = linkage_name,
        .line = line,
        .scope_line = scope_line,
        .ty = ty,
        .di_flags = options.di_flags,
        .compile_unit = compile_unit,
    });
}

fn debug_lexical_block_assume_capacity(self: *Builder, scope: Metadata, file: Metadata, line: u32, column: u32) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.lexical_block, Metadata.LexicalBlock{
        .scope = scope,
        .file = file,
        .line = line,
        .column = column,
    });
}

fn debug_location_assume_capacity(self: *Builder, line: u32, column: u32, scope: Metadata, inlined_at: Metadata) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.location, Metadata.Location{
        .line = line,
        .column = column,
        .scope = scope,
        .inlined_at = inlined_at,
    });
}

fn debug_bool_type_assume_capacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.basic_bool_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debug_unsigned_type_assume_capacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.basic_unsigned_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debug_signed_type_assume_capacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.basic_signed_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debug_float_type_assume_capacity(self: *Builder, name: MetadataString, size_in_bits: u64) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.basic_float_type, Metadata.BasicType{
        .name = name,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
    });
}

fn debug_forward_reference_assume_capacity(self: *Builder) Metadata {
    assert(!self.strip);
    const index = Metadata.first_forward_reference + self.metadata_forward_references.items.len;
    self.metadata_forward_references.append_assume_capacity(.none);
    return @enumFromInt(index);
}

fn debug_struct_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debug_composite_type_assume_capacity(
        .composite_struct_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debug_union_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debug_composite_type_assume_capacity(
        .composite_union_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debug_enumeration_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debug_composite_type_assume_capacity(
        .composite_enumeration_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debug_array_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debug_composite_type_assume_capacity(
        .composite_array_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debug_vector_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.debug_composite_type_assume_capacity(
        .composite_vector_type,
        name,
        file,
        scope,
        line,
        underlying_type,
        size_in_bits,
        align_in_bits,
        fields_tuple,
    );
}

fn debug_composite_type_assume_capacity(
    self: *Builder,
    tag: Metadata.Tag,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    fields_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(tag, Metadata.CompositeType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .fields_tuple = fields_tuple,
    });
}

fn debug_pointer_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.derived_pointer_type, Metadata.DerivedType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .offset_in_bits_lo = @truncate(offset_in_bits),
        .offset_in_bits_hi = @truncate(offset_in_bits >> 32),
    });
}

fn debug_member_type_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    underlying_type: Metadata,
    size_in_bits: u64,
    align_in_bits: u64,
    offset_in_bits: u64,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.derived_member_type, Metadata.DerivedType{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .underlying_type = underlying_type,
        .size_in_bits_lo = @truncate(size_in_bits),
        .size_in_bits_hi = @truncate(size_in_bits >> 32),
        .align_in_bits_lo = @truncate(align_in_bits),
        .align_in_bits_hi = @truncate(align_in_bits >> 32),
        .offset_in_bits_lo = @truncate(offset_in_bits),
        .offset_in_bits_hi = @truncate(offset_in_bits >> 32),
    });
}

fn debug_subroutine_type_assume_capacity(
    self: *Builder,
    types_tuple: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.subroutine_type, Metadata.SubroutineType{
        .types_tuple = types_tuple,
    });
}

fn debug_enumerator_assume_capacity(
    self: *Builder,
    name: MetadataString,
    unsigned: bool,
    bit_width: u32,
    value: std.math.big.int.Const,
) Metadata {
    assert(!self.strip);
    const Key = struct {
        tag: Metadata.Tag,
        name: MetadataString,
        bit_width: u32,
        value: std.math.big.int.Const,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(key.tag)));
            hasher.update(std.mem.as_bytes(&key.name));
            hasher.update(std.mem.as_bytes(&key.bit_width));
            hasher.update(std.mem.slice_as_bytes(key.value.limbs));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (lhs_key.tag != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            const rhs_extra = ctx.builder.metadata_extra_data(Metadata.Enumerator, rhs_data);
            const limbs = ctx.builder.metadata_limbs
                .items[rhs_extra.limbs_index..][0..rhs_extra.limbs_len];
            const rhs_value = std.math.big.int.Const{
                .limbs = limbs,
                .positive = lhs_key.value.positive,
            };
            return lhs_key.name == rhs_extra.name and
                lhs_key.bit_width == rhs_extra.bit_width and
                lhs_key.value.eql(rhs_value);
        }
    };

    const tag: Metadata.Tag = if (unsigned)
        .enumerator_unsigned
    else if (value.positive)
        .enumerator_signed_positive
    else
        .enumerator_signed_negative;

    assert(!(tag == .enumerator_unsigned and !value.positive));

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        Key{
            .tag = tag,
            .name = name,
            .bit_width = bit_width,
            .value = value,
        },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = tag,
            .data = self.add_metadata_extra_assume_capacity(Metadata.Enumerator{
                .name = name,
                .bit_width = bit_width,
                .limbs_index = @int_cast(self.metadata_limbs.items.len),
                .limbs_len = @int_cast(value.limbs.len),
            }),
        });
        self.metadata_limbs.append_slice_assume_capacity(value.limbs);
    }
    return @enumFromInt(gop.index);
}

fn debug_subrange_assume_capacity(
    self: *Builder,
    lower_bound: Metadata,
    count: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.subrange, Metadata.Subrange{
        .lower_bound = lower_bound,
        .count = count,
    });
}

fn debug_expression_assume_capacity(
    self: *Builder,
    elements: []const u32,
) Metadata {
    assert(!self.strip);
    const Key = struct {
        elements: []const u32,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(Metadata.Tag.expression)));
            hasher.update(std.mem.slice_as_bytes(key.elements));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.expression != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.metadata_extra_data_trail(Metadata.Expression, rhs_data);
            return std.mem.eql(
                u32,
                lhs_key.elements,
                rhs_extra.trail.next(rhs_extra.data.elements_len, u32, ctx.builder),
            );
        }
    };

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        Key{ .elements = elements },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = .expression,
            .data = self.add_metadata_extra_assume_capacity(Metadata.Expression{
                .elements_len = @int_cast(elements.len),
            }),
        });
        self.metadata_extra.append_slice_assume_capacity(@ptr_cast(elements));
    }
    return @enumFromInt(gop.index);
}

fn debug_tuple_assume_capacity(
    self: *Builder,
    elements: []const Metadata,
) Metadata {
    assert(!self.strip);
    const Key = struct {
        elements: []const Metadata,
    };
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Key) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(Metadata.Tag.tuple)));
            hasher.update(std.mem.slice_as_bytes(key.elements));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Key, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.tuple != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data = ctx.builder.metadata_items.items(.data)[rhs_index];
            var rhs_extra = ctx.builder.metadata_extra_data_trail(Metadata.Tuple, rhs_data);
            return std.mem.eql(
                Metadata,
                lhs_key.elements,
                rhs_extra.trail.next(rhs_extra.data.elements_len, Metadata, ctx.builder),
            );
        }
    };

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        Key{ .elements = elements },
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = .tuple,
            .data = self.add_metadata_extra_assume_capacity(Metadata.Tuple{
                .elements_len = @int_cast(elements.len),
            }),
        });
        self.metadata_extra.append_slice_assume_capacity(@ptr_cast(elements));
    }
    return @enumFromInt(gop.index);
}

fn debug_module_flag_assume_capacity(
    self: *Builder,
    behavior: Metadata,
    name: MetadataString,
    constant: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.module_flag, Metadata.ModuleFlag{
        .behavior = behavior,
        .name = name,
        .constant = constant,
    });
}

fn debug_local_var_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.local_var, Metadata.LocalVar{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .ty = ty,
    });
}

fn debug_parameter_assume_capacity(
    self: *Builder,
    name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    arg_no: u32,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.parameter, Metadata.Parameter{
        .name = name,
        .file = file,
        .scope = scope,
        .line = line,
        .ty = ty,
        .arg_no = arg_no,
    });
}

fn debug_global_var_assume_capacity(
    self: *Builder,
    name: MetadataString,
    linkage_name: MetadataString,
    file: Metadata,
    scope: Metadata,
    line: u32,
    ty: Metadata,
    variable: Variable.Index,
    options: Metadata.GlobalVar.Options,
) Metadata {
    assert(!self.strip);
    return self.metadata_distinct_assume_capacity(
        if (options.local) .@"global_var local" else .global_var,
        Metadata.GlobalVar{
            .name = name,
            .linkage_name = linkage_name,
            .file = file,
            .scope = scope,
            .line = line,
            .ty = ty,
            .variable = variable,
        },
    );
}

fn debug_global_var_expression_assume_capacity(
    self: *Builder,
    variable: Metadata,
    expression: Metadata,
) Metadata {
    assert(!self.strip);
    return self.metadata_simple_assume_capacity(.global_var_expression, Metadata.GlobalVarExpression{
        .variable = variable,
        .expression = expression,
    });
}

fn debug_constant_assume_capacity(self: *Builder, constant: Constant) Metadata {
    assert(!self.strip);
    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: @This(), key: Constant) u32 {
            var hasher = comptime std.hash.Wyhash.init(std.hash.uint32(@int_from_enum(Metadata.Tag.constant)));
            hasher.update(std.mem.as_bytes(&key));
            return @truncate(hasher.final());
        }

        pub fn eql(ctx: @This(), lhs_key: Constant, _: void, rhs_index: usize) bool {
            if (Metadata.Tag.constant != ctx.builder.metadata_items.items(.tag)[rhs_index]) return false;
            const rhs_data: Constant = @enumFromInt(ctx.builder.metadata_items.items(.data)[rhs_index]);
            return rhs_data == lhs_key;
        }
    };

    const gop = self.metadata_map.get_or_put_assume_capacity_adapted(
        constant,
        Adapter{ .builder = self },
    );

    if (!gop.found_existing) {
        gop.key_ptr.* = {};
        gop.value_ptr.* = {};
        self.metadata_items.append_assume_capacity(.{
            .tag = .constant,
            .data = @int_from_enum(constant),
        });
    }
    return @enumFromInt(gop.index);
}

pub fn to_bitcode(self: *Builder, allocator: Allocator) bitcode_writer.Error![]const u32 {
    const BitcodeWriter = bitcode_writer.BitcodeWriter(&.{ Type, FunctionAttributes });
    var bitcode = BitcodeWriter.init(allocator, .{
        std.math.log2_int_ceil(usize, self.type_items.items.len),
        std.math.log2_int_ceil(usize, 1 + self.function_attributes_set.count()),
    });
    errdefer bitcode.deinit();

    // Write LLVM IR magic
    try bitcode.write_bits(ir.MAGIC, 32);

    var record: std.ArrayListUnmanaged(u64) = .{};
    defer record.deinit(self.gpa);

    // IDENTIFICATION_BLOCK
    {
        const Identification = ir.Identification;
        var identification_block = try bitcode.enter_top_block(Identification);

        const producer = try std.fmt.alloc_print(self.gpa, "zig {d}.{d}.{d}", .{
            build_options.semver.major,
            build_options.semver.minor,
            build_options.semver.patch,
        });
        defer self.gpa.free(producer);

        try identification_block.write_abbrev(Identification.Version{ .string = producer });
        try identification_block.write_abbrev(Identification.Epoch{ .epoch = 0 });

        try identification_block.end();
    }

    // MODULE_BLOCK
    {
        const Module = ir.Module;
        var module_block = try bitcode.enter_top_block(Module);

        try module_block.write_abbrev(Module.Version{});

        if (self.target_triple.slice(self)) |triple| {
            try module_block.write_abbrev(Module.String{
                .code = 2,
                .string = triple,
            });
        }

        if (self.data_layout.slice(self)) |data_layout| {
            try module_block.write_abbrev(Module.String{
                .code = 3,
                .string = data_layout,
            });
        }

        if (self.source_filename.slice(self)) |source_filename| {
            try module_block.write_abbrev(Module.String{
                .code = 16,
                .string = source_filename,
            });
        }

        if (self.module_asm.items.len != 0) {
            try module_block.write_abbrev(Module.String{
                .code = 4,
                .string = self.module_asm.items,
            });
        }

        // TYPE_BLOCK
        {
            var type_block = try module_block.enter_sub_block(ir.Type, true);

            try type_block.write_abbrev(ir.Type.NumEntry{ .num = @int_cast(self.type_items.items.len) });

            for (self.type_items.items, 0..) |item, i| {
                const ty: Type = @enumFromInt(i);

                switch (item.tag) {
                    .simple => try type_block.write_abbrev(ir.Type.Simple{ .code = @truncate(item.data) }),
                    .integer => try type_block.write_abbrev(ir.Type.Integer{ .width = item.data }),
                    .structure,
                    .packed_structure,
                    => |kind| {
                        const is_packed = switch (kind) {
                            .structure => false,
                            .packed_structure => true,
                            else => unreachable,
                        };
                        var extra = self.type_extra_data_trail(Type.Structure, item.data);
                        try type_block.write_abbrev(ir.Type.StructAnon{
                            .is_packed = is_packed,
                            .types = extra.trail.next(extra.data.fields_len, Type, self),
                        });
                    },
                    .named_structure => {
                        const extra = self.type_extra_data(Type.NamedStructure, item.data);
                        try type_block.write_abbrev(ir.Type.StructName{
                            .string = extra.id.slice(self).?,
                        });

                        switch (extra.body) {
                            .none => try type_block.write_abbrev(ir.Type.Opaque{}),
                            else => {
                                const real_struct = self.type_items.items[@int_from_enum(extra.body)];
                                const is_packed: bool = switch (real_struct.tag) {
                                    .structure => false,
                                    .packed_structure => true,
                                    else => unreachable,
                                };

                                var real_extra = self.type_extra_data_trail(Type.Structure, real_struct.data);
                                try type_block.write_abbrev(ir.Type.StructNamed{
                                    .is_packed = is_packed,
                                    .types = real_extra.trail.next(real_extra.data.fields_len, Type, self),
                                });
                            },
                        }
                    },
                    .array,
                    .small_array,
                    => try type_block.write_abbrev(ir.Type.Array{
                        .len = ty.aggregate_len(self),
                        .child = ty.child_type(self),
                    }),
                    .vector,
                    .scalable_vector,
                    => try type_block.write_abbrev(ir.Type.Vector{
                        .len = ty.aggregate_len(self),
                        .child = ty.child_type(self),
                    }),
                    .pointer => try type_block.write_abbrev(ir.Type.Pointer{
                        .addr_space = ty.pointer_addr_space(self),
                    }),
                    .target => {
                        var extra = self.type_extra_data_trail(Type.Target, item.data);
                        try type_block.write_abbrev(ir.Type.StructName{
                            .string = extra.data.name.slice(self).?,
                        });

                        const types = extra.trail.next(extra.data.types_len, Type, self);
                        const ints = extra.trail.next(extra.data.ints_len, u32, self);

                        try type_block.write_abbrev(ir.Type.Target{
                            .num_types = extra.data.types_len,
                            .types = types,
                            .ints = ints,
                        });
                    },
                    .function, .vararg_function => |kind| {
                        const is_vararg = switch (kind) {
                            .function => false,
                            .vararg_function => true,
                            else => unreachable,
                        };
                        var extra = self.type_extra_data_trail(Type.Function, item.data);
                        try type_block.write_abbrev(ir.Type.Function{
                            .is_vararg = is_vararg,
                            .return_type = extra.data.ret,
                            .param_types = extra.trail.next(extra.data.params_len, Type, self),
                        });
                    },
                }
            }

            try type_block.end();
        }

        var attributes_set: std.AutoArrayHashMapUnmanaged(struct {
            attributes: Attributes,
            index: u32,
        }, void) = .{};
        defer attributes_set.deinit(self.gpa);

        // PARAMATTR_GROUP_BLOCK
        {
            const ParamattrGroup = ir.ParamattrGroup;

            var paramattr_group_block = try module_block.enter_sub_block(ParamattrGroup, true);

            for (self.function_attributes_set.keys()) |func_attributes| {
                for (func_attributes.slice(self), 0..) |attributes, i| {
                    const attributes_slice = attributes.slice(self);
                    if (attributes_slice.len == 0) continue;

                    const attr_gop = try attributes_set.get_or_put(self.gpa, .{
                        .attributes = attributes,
                        .index = @int_cast(i),
                    });

                    if (attr_gop.found_existing) continue;

                    record.clear_retaining_capacity();
                    try record.ensure_unused_capacity(self.gpa, 2);

                    record.append_assume_capacity(attr_gop.index);
                    record.append_assume_capacity(switch (i) {
                        0 => 0xffffffff,
                        else => i - 1,
                    });

                    for (attributes_slice) |attr_index| {
                        const kind = attr_index.get_kind(self);
                        switch (attr_index.to_attribute(self)) {
                            .zeroext,
                            .signext,
                            .inreg,
                            .@"noalias",
                            .nocapture,
                            .nofree,
                            .nest,
                            .returned,
                            .nonnull,
                            .swiftself,
                            .swiftasync,
                            .swifterror,
                            .immarg,
                            .noundef,
                            .allocalign,
                            .allocptr,
                            .readnone,
                            .readonly,
                            .writeonly,
                            .alwaysinline,
                            .builtin,
                            .cold,
                            .convergent,
                            .disable_sanitizer_information,
                            .fn_ret_thunk_extern,
                            .hot,
                            .inlinehint,
                            .jumptable,
                            .minsize,
                            .naked,
                            .nobuiltin,
                            .nocallback,
                            .noduplicate,
                            .noimplicitfloat,
                            .@"noinline",
                            .nomerge,
                            .nonlazybind,
                            .noprofile,
                            .skipprofile,
                            .noredzone,
                            .noreturn,
                            .norecurse,
                            .willreturn,
                            .nosync,
                            .nounwind,
                            .nosanitize_bounds,
                            .nosanitize_coverage,
                            .null_pointer_is_valid,
                            .optforfuzzing,
                            .optnone,
                            .optsize,
                            .returns_twice,
                            .safestack,
                            .sanitize_address,
                            .sanitize_memory,
                            .sanitize_thread,
                            .sanitize_hwaddress,
                            .sanitize_memtag,
                            .speculative_load_hardening,
                            .speculatable,
                            .ssp,
                            .sspstrong,
                            .sspreq,
                            .strictfp,
                            .nocf_check,
                            .shadowcallstack,
                            .mustprogress,
                            .no_sanitize_address,
                            .no_sanitize_hwaddress,
                            .sanitize_address_dyninit,
                            => {
                                try record.ensure_unused_capacity(self.gpa, 2);
                                record.append_assume_capacity(0);
                                record.append_assume_capacity(@int_from_enum(kind));
                            },
                            .byval,
                            .byref,
                            .preallocated,
                            .inalloca,
                            .sret,
                            .elementtype,
                            => |ty| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(6);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@int_from_enum(ty));
                            },
                            .@"align",
                            .alignstack,
                            => |alignment| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(alignment.to_byte_units() orelse 0);
                            },
                            .dereferenceable,
                            .dereferenceable_or_null,
                            => |size| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(size);
                            },
                            .nofpclass => |fpclass| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@as(u32, @bit_cast(fpclass)));
                            },
                            .allockind => |allockind| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@as(u32, @bit_cast(allockind)));
                            },

                            .allocsize => |allocsize| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@bit_cast(allocsize.to_llvm()));
                            },
                            .memory => |memory| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@as(u32, @bit_cast(memory)));
                            },
                            .uwtable => |uwtable| if (uwtable != .none) {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@int_from_enum(uwtable));
                            },
                            .vscale_range => |vscale_range| {
                                try record.ensure_unused_capacity(self.gpa, 3);
                                record.append_assume_capacity(1);
                                record.append_assume_capacity(@int_from_enum(kind));
                                record.append_assume_capacity(@bit_cast(vscale_range.to_llvm()));
                            },
                            .string => |string_attr| {
                                const string_attr_kind_slice = string_attr.kind.slice(self).?;
                                const string_attr_value_slice = if (string_attr.value != .none)
                                    string_attr.value.slice(self).?
                                else
                                    null;

                                try record.ensure_unused_capacity(
                                    self.gpa,
                                    2 + string_attr_kind_slice.len + if (string_attr_value_slice) |slice| slice.len + 1 else 0,
                                );
                                record.append_assume_capacity(if (string_attr.value == .none) 3 else 4);
                                for (string_attr.kind.slice(self).?) |c| {
                                    record.append_assume_capacity(c);
                                }
                                record.append_assume_capacity(0);
                                if (string_attr_value_slice) |slice| {
                                    for (slice) |c| {
                                        record.append_assume_capacity(c);
                                    }
                                    record.append_assume_capacity(0);
                                }
                            },
                            .none => unreachable,
                        }
                    }

                    try paramattr_group_block.write_unabbrev(3, record.items);
                }
            }

            try paramattr_group_block.end();
        }

        // PARAMATTR_BLOCK
        {
            const Paramattr = ir.Paramattr;
            var paramattr_block = try module_block.enter_sub_block(Paramattr, true);

            for (self.function_attributes_set.keys()) |func_attributes| {
                const func_attributes_slice = func_attributes.slice(self);
                record.clear_retaining_capacity();
                try record.ensure_unused_capacity(self.gpa, func_attributes_slice.len);
                for (func_attributes_slice, 0..) |attributes, i| {
                    const attributes_slice = attributes.slice(self);
                    if (attributes_slice.len == 0) continue;

                    const group_index = attributes_set.get_index(.{
                        .attributes = attributes,
                        .index = @int_cast(i),
                    }).?;
                    record.append_assume_capacity(@int_cast(group_index));
                }

                try paramattr_block.write_abbrev(Paramattr.Entry{ .group_indices = record.items });
            }

            try paramattr_block.end();
        }

        var globals: std.AutoArrayHashMapUnmanaged(Global.Index, void) = .{};
        defer globals.deinit(self.gpa);
        try globals.ensure_unused_capacity(
            self.gpa,
            self.variables.items.len +
                self.functions.items.len +
                self.aliases.items.len,
        );

        for (self.variables.items) |variable| {
            if (variable.global.get_replacement(self) != .none) continue;

            globals.put_assume_capacity(variable.global, {});
        }

        for (self.functions.items) |function| {
            if (function.global.get_replacement(self) != .none) continue;

            globals.put_assume_capacity(function.global, {});
        }

        for (self.aliases.items) |alias| {
            if (alias.global.get_replacement(self) != .none) continue;

            globals.put_assume_capacity(alias.global, {});
        }

        const ConstantAdapter = struct {
            const ConstantAdapter = @This();
            builder: *const Builder,
            globals: *const std.AutoArrayHashMapUnmanaged(Global.Index, void),

            pub fn get(adapter: @This(), param: anytype, comptime field_name: []const u8) @TypeOf(param) {
                _ = field_name;
                return switch (@TypeOf(param)) {
                    Constant => @enumFromInt(adapter.get_constant_index(param)),
                    else => param,
                };
            }

            pub fn get_constant_index(adapter: ConstantAdapter, constant: Constant) u32 {
                return switch (constant.unwrap()) {
                    .constant => |c| c + adapter.num_globals(),
                    .global => |global| @int_cast(adapter.globals.get_index(global.unwrap(adapter.builder)).?),
                };
            }

            pub fn num_constants(adapter: ConstantAdapter) u32 {
                return @int_cast(adapter.globals.count() + adapter.builder.constant_items.len);
            }

            pub fn num_globals(adapter: ConstantAdapter) u32 {
                return @int_cast(adapter.globals.count());
            }
        };

        const constant_adapter = ConstantAdapter{
            .builder = self,
            .globals = &globals,
        };

        // Globals
        {
            var section_map: std.AutoArrayHashMapUnmanaged(String, void) = .{};
            defer section_map.deinit(self.gpa);
            try section_map.ensure_unused_capacity(self.gpa, globals.count());

            for (self.variables.items) |variable| {
                if (variable.global.get_replacement(self) != .none) continue;

                const section = blk: {
                    if (variable.section == .none) break :blk 0;
                    const gop = section_map.get_or_put_assume_capacity(variable.section);
                    if (!gop.found_existing) {
                        try module_block.write_abbrev(Module.String{
                            .code = 5,
                            .string = variable.section.slice(self).?,
                        });
                    }
                    break :blk gop.index + 1;
                };

                const initid = if (variable.init == .no_init)
                    0
                else
                    (constant_adapter.get_constant_index(variable.init) + 1);

                const strtab = variable.global.strtab(self);

                const global = variable.global.ptr_const(self);
                try module_block.write_abbrev(Module.Variable{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .is_const = .{
                        .is_const = switch (variable.mutability) {
                            .global => false,
                            .constant => true,
                        },
                        .addr_space = global.addr_space,
                    },
                    .initid = initid,
                    .linkage = global.linkage,
                    .alignment = variable.alignment.to_llvm(),
                    .section = section,
                    .visibility = global.visibility,
                    .thread_local = variable.thread_local,
                    .unnamed_addr = global.unnamed_addr,
                    .externally_initialized = global.externally_initialized,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                });
            }

            for (self.functions.items) |func| {
                if (func.global.get_replacement(self) != .none) continue;

                const section = blk: {
                    if (func.section == .none) break :blk 0;
                    const gop = section_map.get_or_put_assume_capacity(func.section);
                    if (!gop.found_existing) {
                        try module_block.write_abbrev(Module.String{
                            .code = 5,
                            .string = func.section.slice(self).?,
                        });
                    }
                    break :blk gop.index + 1;
                };

                const paramattr_index = if (self.function_attributes_set.get_index(func.attributes)) |index|
                    index + 1
                else
                    0;

                const strtab = func.global.strtab(self);

                const global = func.global.ptr_const(self);
                try module_block.write_abbrev(Module.Function{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .call_conv = func.call_conv,
                    .is_proto = func.instructions.len == 0,
                    .linkage = global.linkage,
                    .paramattr = paramattr_index,
                    .alignment = func.alignment.to_llvm(),
                    .section = section,
                    .visibility = global.visibility,
                    .unnamed_addr = global.unnamed_addr,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                    .addr_space = global.addr_space,
                });
            }

            for (self.aliases.items) |alias| {
                if (alias.global.get_replacement(self) != .none) continue;

                const strtab = alias.global.strtab(self);

                const global = alias.global.ptr_const(self);
                try module_block.write_abbrev(Module.Alias{
                    .strtab_offset = strtab.offset,
                    .strtab_size = strtab.size,
                    .type_index = global.type,
                    .addr_space = global.addr_space,
                    .aliasee = constant_adapter.get_constant_index(alias.aliasee),
                    .linkage = global.linkage,
                    .visibility = global.visibility,
                    .thread_local = alias.thread_local,
                    .unnamed_addr = global.unnamed_addr,
                    .dllstorageclass = global.dll_storage_class,
                    .preemption = global.preemption,
                });
            }
        }

        // CONSTANTS_BLOCK
        {
            const Constants = ir.Constants;
            var constants_block = try module_block.enter_sub_block(Constants, true);

            var current_type: Type = .none;
            const tags = self.constant_items.items(.tag);
            const datas = self.constant_items.items(.data);
            for (0..self.constant_items.len) |index| {
                record.clear_retaining_capacity();
                const constant: Constant = @enumFromInt(index);
                const constant_type = constant.type_of(self);
                if (constant_type != current_type) {
                    try constants_block.write_abbrev(Constants.SetType{ .type_id = constant_type });
                    current_type = constant_type;
                }
                const data = datas[index];
                switch (tags[index]) {
                    .null,
                    .zeroinitializer,
                    .none,
                    => try constants_block.write_abbrev(Constants.Null{}),
                    .undef => try constants_block.write_abbrev(Constants.Undef{}),
                    .poison => try constants_block.write_abbrev(Constants.Poison{}),
                    .positive_integer,
                    .negative_integer,
                    => |tag| {
                        const extra: *align(@alignOf(std.math.big.Limb)) Constant.Integer =
                            @ptr_cast(self.constant_limbs.items[data..][0..Constant.Integer.limbs]);
                        const bigint: std.math.big.int.Const = .{
                            .limbs = self.constant_limbs
                                .items[data + Constant.Integer.limbs ..][0..extra.limbs_len],
                            .positive = switch (tag) {
                                .positive_integer => true,
                                .negative_integer => false,
                                else => unreachable,
                            },
                        };
                        const bit_count = extra.type.scalar_bits(self);
                        const val: i64 = if (bit_count <= 64)
                            bigint.to(i64) catch unreachable
                        else if (bigint.to(u64)) |val|
                            @bit_cast(val)
                        else |_| {
                            const limbs = try record.add_many_as_slice(
                                self.gpa,
                                std.math.div_ceil(u24, bit_count, 64) catch unreachable,
                            );
                            bigint.write_twos_complement(std.mem.slice_as_bytes(limbs), .little);
                            for (limbs) |*limb| {
                                const val = std.mem.little_to_native(i64, @bit_cast(limb.*));
                                limb.* = @bit_cast(if (val >= 0)
                                    val << 1 | 0
                                else
                                    -%val << 1 | 1);
                            }
                            try constants_block.write_unabbrev(5, record.items);
                            continue;
                        };
                        try constants_block.write_abbrev(Constants.Integer{
                            .value = @bit_cast(if (val >= 0)
                                val << 1 | 0
                            else
                                -%val << 1 | 1),
                        });
                    },
                    .half,
                    .bfloat,
                    => try constants_block.write_abbrev(Constants.Half{ .value = @truncate(data) }),
                    .float => try constants_block.write_abbrev(Constants.Float{ .value = data }),
                    .double => {
                        const extra = self.constant_extra_data(Constant.Double, data);
                        try constants_block.write_abbrev(Constants.Double{
                            .value = (@as(u64, extra.hi) << 32) | extra.lo,
                        });
                    },
                    .x86_fp80 => {
                        const extra = self.constant_extra_data(Constant.Fp80, data);
                        try constants_block.write_abbrev(Constants.Fp80{
                            .hi = @as(u64, extra.hi) << 48 | @as(u64, extra.lo_hi) << 16 |
                                extra.lo_lo >> 16,
                            .lo = @truncate(extra.lo_lo),
                        });
                    },
                    .fp128,
                    .ppc_fp128,
                    => {
                        const extra = self.constant_extra_data(Constant.Fp128, data);
                        try constants_block.write_abbrev(Constants.Fp128{
                            .lo = @as(u64, extra.lo_hi) << 32 | @as(u64, extra.lo_lo),
                            .hi = @as(u64, extra.hi_hi) << 32 | @as(u64, extra.hi_lo),
                        });
                    },
                    .array,
                    .vector,
                    .structure,
                    .packed_structure,
                    => {
                        var extra = self.constant_extra_data_trail(Constant.Aggregate, data);
                        const len: u32 = @int_cast(extra.data.type.aggregate_len(self));
                        const values = extra.trail.next(len, Constant, self);

                        try constants_block.write_abbrev_adapted(
                            Constants.Aggregate{ .values = values },
                            constant_adapter,
                        );
                    },
                    .splat => {
                        const ConstantsWriter = @TypeOf(constants_block);
                        const extra = self.constant_extra_data(Constant.Splat, data);
                        const vector_len = extra.type.vector_len(self);
                        const c = constant_adapter.get_constant_index(extra.value);

                        try bitcode.write_bits(
                            ConstantsWriter.abbrev_id(Constants.Aggregate),
                            ConstantsWriter.abbrev_len,
                        );
                        try bitcode.write_vbr(vector_len, 6);
                        for (0..vector_len) |_| {
                            try bitcode.write_bits(c, Constants.Aggregate.ops[1].array_fixed);
                        }
                    },
                    .string => {
                        const str: String = @enumFromInt(data);
                        if (str == .none) {
                            try constants_block.write_abbrev(Constants.Null{});
                        } else {
                            const slice = str.slice(self).?;
                            if (slice.len > 0 and slice[slice.len - 1] == 0)
                                try constants_block.write_abbrev(Constants.CString{ .string = slice[0 .. slice.len - 1] })
                            else
                                try constants_block.write_abbrev(Constants.String{ .string = slice });
                        }
                    },
                    .bitcast,
                    .inttoptr,
                    .ptrtoint,
                    .addrspacecast,
                    .trunc,
                    => |tag| {
                        const extra = self.constant_extra_data(Constant.Cast, data);
                        try constants_block.write_abbrev_adapted(Constants.Cast{
                            .type_index = extra.type,
                            .val = extra.val,
                            .opcode = tag.to_cast_opcode(),
                        }, constant_adapter);
                    },
                    .add,
                    .@"add nsw",
                    .@"add nuw",
                    .sub,
                    .@"sub nsw",
                    .@"sub nuw",
                    .shl,
                    .xor,
                    => |tag| {
                        const extra = self.constant_extra_data(Constant.Binary, data);
                        try constants_block.write_abbrev_adapted(Constants.Binary{
                            .opcode = tag.to_binary_opcode(),
                            .lhs = extra.lhs,
                            .rhs = extra.rhs,
                        }, constant_adapter);
                    },
                    .getelementptr,
                    .@"getelementptr inbounds",
                    => |tag| {
                        var extra = self.constant_extra_data_trail(Constant.GetElementPtr, data);
                        const indices = extra.trail.next(extra.data.info.indices_len, Constant, self);
                        try record.ensure_unused_capacity(self.gpa, 1 + 2 + 2 * indices.len);

                        record.append_assume_capacity(@int_from_enum(extra.data.type));

                        record.append_assume_capacity(@int_from_enum(extra.data.base.type_of(self)));
                        record.append_assume_capacity(constant_adapter.get_constant_index(extra.data.base));

                        for (indices) |i| {
                            record.append_assume_capacity(@int_from_enum(i.type_of(self)));
                            record.append_assume_capacity(constant_adapter.get_constant_index(i));
                        }

                        try constants_block.write_unabbrev(switch (tag) {
                            .getelementptr => 12,
                            .@"getelementptr inbounds" => 20,
                            else => unreachable,
                        }, record.items);
                    },
                    .@"asm",
                    .@"asm sideeffect",
                    .@"asm alignstack",
                    .@"asm sideeffect alignstack",
                    .@"asm inteldialect",
                    .@"asm sideeffect inteldialect",
                    .@"asm alignstack inteldialect",
                    .@"asm sideeffect alignstack inteldialect",
                    .@"asm unwind",
                    .@"asm sideeffect unwind",
                    .@"asm alignstack unwind",
                    .@"asm sideeffect alignstack unwind",
                    .@"asm inteldialect unwind",
                    .@"asm sideeffect inteldialect unwind",
                    .@"asm alignstack inteldialect unwind",
                    .@"asm sideeffect alignstack inteldialect unwind",
                    => |tag| {
                        const extra = self.constant_extra_data(Constant.Assembly, data);

                        const assembly_slice = extra.assembly.slice(self).?;
                        const constraints_slice = extra.constraints.slice(self).?;

                        try record.ensure_unused_capacity(self.gpa, 4 + assembly_slice.len + constraints_slice.len);

                        record.append_assume_capacity(@int_from_enum(extra.type));
                        record.append_assume_capacity(switch (tag) {
                            .@"asm" => 0,
                            .@"asm sideeffect" => 0b0001,
                            .@"asm sideeffect alignstack" => 0b0011,
                            .@"asm sideeffect inteldialect" => 0b0101,
                            .@"asm sideeffect alignstack inteldialect" => 0b0111,
                            .@"asm sideeffect unwind" => 0b1001,
                            .@"asm sideeffect alignstack unwind" => 0b1011,
                            .@"asm sideeffect inteldialect unwind" => 0b1101,
                            .@"asm sideeffect alignstack inteldialect unwind" => 0b1111,
                            .@"asm alignstack" => 0b0010,
                            .@"asm inteldialect" => 0b0100,
                            .@"asm alignstack inteldialect" => 0b0110,
                            .@"asm unwind" => 0b1000,
                            .@"asm alignstack unwind" => 0b1010,
                            .@"asm inteldialect unwind" => 0b1100,
                            .@"asm alignstack inteldialect unwind" => 0b1110,
                            else => unreachable,
                        });

                        record.append_assume_capacity(assembly_slice.len);
                        for (assembly_slice) |c| record.append_assume_capacity(c);

                        record.append_assume_capacity(constraints_slice.len);
                        for (constraints_slice) |c| record.append_assume_capacity(c);

                        try constants_block.write_unabbrev(30, record.items);
                    },
                    .blockaddress => {
                        const extra = self.constant_extra_data(Constant.BlockAddress, data);
                        try constants_block.write_abbrev(Constants.BlockAddress{
                            .type_id = extra.function.type_of(self),
                            .function = constant_adapter.get_constant_index(extra.function.to_const(self)),
                            .block = @int_from_enum(extra.block),
                        });
                    },
                    .dso_local_equivalent,
                    .no_cfi,
                    => |tag| {
                        const function: Function.Index = @enumFromInt(data);
                        try constants_block.write_abbrev(Constants.DsoLocalEquivalentOrNoCfi{
                            .code = switch (tag) {
                                .dso_local_equivalent => 27,
                                .no_cfi => 29,
                                else => unreachable,
                            },
                            .type_id = function.type_of(self),
                            .function = constant_adapter.get_constant_index(function.to_const(self)),
                        });
                    },
                }
            }

            try constants_block.end();
        }

        // METADATA_KIND_BLOCK
        if (!self.strip) {
            const MetadataKindBlock = ir.MetadataKindBlock;
            var metadata_kind_block = try module_block.enter_sub_block(MetadataKindBlock, true);

            inline for (@typeInfo(ir.MetadataKind).Enum.fields) |field| {
                try metadata_kind_block.write_abbrev(MetadataKindBlock.Kind{
                    .id = field.value,
                    .name = field.name,
                });
            }

            try metadata_kind_block.end();
        }

        const MetadataAdapter = struct {
            builder: *const Builder,
            constant_adapter: ConstantAdapter,

            pub fn init(
                builder: *const Builder,
                const_adapter: ConstantAdapter,
            ) @This() {
                return .{
                    .builder = builder,
                    .constant_adapter = const_adapter,
                };
            }

            pub fn get(adapter: @This(), value: anytype, comptime field_name: []const u8) @TypeOf(value) {
                _ = field_name;
                const Ty = @TypeOf(value);
                return switch (Ty) {
                    Metadata => @enumFromInt(adapter.get_metadata_index(value)),
                    MetadataString => @enumFromInt(adapter.get_metadata_string_index(value)),
                    Constant => @enumFromInt(adapter.constant_adapter.get_constant_index(value)),
                    else => value,
                };
            }

            pub fn get_metadata_index(adapter: @This(), metadata: Metadata) u32 {
                if (metadata == .none) return 0;
                return @int_cast(adapter.builder.metadata_string_map.count() +
                    @int_from_enum(metadata.unwrap(adapter.builder)) - 1);
            }

            pub fn get_metadata_string_index(_: @This(), metadata_string: MetadataString) u32 {
                return @int_from_enum(metadata_string);
            }
        };

        const metadata_adapter = MetadataAdapter.init(self, constant_adapter);

        // METADATA_BLOCK
        if (!self.strip) {
            const MetadataBlock = ir.MetadataBlock;
            var metadata_block = try module_block.enter_sub_block(MetadataBlock, true);

            const MetadataBlockWriter = @TypeOf(metadata_block);

            // Emit all MetadataStrings
            {
                const strings_offset, const strings_size = blk: {
                    var strings_offset: u32 = 0;
                    var strings_size: u32 = 0;
                    for (1..self.metadata_string_map.count()) |metadata_string_index| {
                        const metadata_string: MetadataString = @enumFromInt(metadata_string_index);
                        const slice = metadata_string.slice(self);
                        strings_offset += bitcode.bits_vbr(@as(u32, @int_cast(slice.len)), 6);
                        strings_size += @int_cast(slice.len * 8);
                    }
                    break :blk .{
                        std.mem.align_forward(u32, strings_offset, 32) / 8,
                        std.mem.align_forward(u32, strings_size, 32) / 8,
                    };
                };

                try bitcode.write_bits(
                    comptime MetadataBlockWriter.abbrev_id(MetadataBlock.Strings),
                    MetadataBlockWriter.abbrev_len,
                );

                try bitcode.write_vbr(@as(u32, @int_cast(self.metadata_string_map.count() - 1)), 6);
                try bitcode.write_vbr(strings_offset, 6);

                try bitcode.write_vbr(strings_size + strings_offset, 6);

                try bitcode.align_to32();

                for (1..self.metadata_string_map.count()) |metadata_string_index| {
                    const metadata_string: MetadataString = @enumFromInt(metadata_string_index);
                    const slice = metadata_string.slice(self);
                    try bitcode.write_vbr(@as(u32, @int_cast(slice.len)), 6);
                }

                try bitcode.write_blob(self.metadata_string_bytes.items);
            }

            for (
                self.metadata_items.items(.tag)[1..],
                self.metadata_items.items(.data)[1..],
            ) |tag, data| {
                record.clear_retaining_capacity();
                switch (tag) {
                    .none => unreachable,
                    .file => {
                        const extra = self.metadata_extra_data(Metadata.File, data);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.File{
                            .filename = extra.filename,
                            .directory = extra.directory,
                        }, metadata_adapter);
                    },
                    .compile_unit,
                    .@"compile_unit optimized",
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.CompileUnit, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.CompileUnit{
                            .file = extra.file,
                            .producer = extra.producer,
                            .is_optimized = switch (kind) {
                                .compile_unit => false,
                                .@"compile_unit optimized" => true,
                                else => unreachable,
                            },
                            .enums = extra.enums,
                            .globals = extra.globals,
                        }, metadata_adapter);
                    },
                    .subprogram,
                    .@"subprogram local",
                    .@"subprogram definition",
                    .@"subprogram local definition",
                    .@"subprogram optimized",
                    .@"subprogram optimized local",
                    .@"subprogram optimized definition",
                    .@"subprogram optimized local definition",
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.Subprogram, data);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.Subprogram{
                            .scope = extra.file,
                            .name = extra.name,
                            .linkage_name = extra.linkage_name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .scope_line = extra.scope_line,
                            .sp_flags = @bit_cast(@as(u32, @as(u3, @int_cast(
                                @int_from_enum(kind) - @int_from_enum(Metadata.Tag.subprogram),
                            ))) << 2),
                            .flags = extra.di_flags,
                            .compile_unit = extra.compile_unit,
                        }, metadata_adapter);
                    },
                    .lexical_block => {
                        const extra = self.metadata_extra_data(Metadata.LexicalBlock, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.LexicalBlock{
                            .scope = extra.scope,
                            .file = extra.file,
                            .line = extra.line,
                            .column = extra.column,
                        }, metadata_adapter);
                    },
                    .location => {
                        const extra = self.metadata_extra_data(Metadata.Location, data);
                        assert(extra.scope != .none);
                        try metadata_block.write_abbrev(MetadataBlock.Location{
                            .line = extra.line,
                            .column = extra.column,
                            .scope = metadata_adapter.get_metadata_index(extra.scope) - 1,
                            .inlined_at = @enumFromInt(metadata_adapter.get_metadata_index(extra.inlined_at)),
                        });
                    },
                    .basic_bool_type,
                    .basic_unsigned_type,
                    .basic_signed_type,
                    .basic_float_type,
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.BasicType, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.BasicType{
                            .name = extra.name,
                            .size_in_bits = extra.bit_size(),
                            .encoding = switch (kind) {
                                .basic_bool_type => DW.ATE.boolean,
                                .basic_unsigned_type => DW.ATE.unsigned,
                                .basic_signed_type => DW.ATE.signed,
                                .basic_float_type => DW.ATE.float,
                                else => unreachable,
                            },
                        }, metadata_adapter);
                    },
                    .composite_struct_type,
                    .composite_union_type,
                    .composite_enumeration_type,
                    .composite_array_type,
                    .composite_vector_type,
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.CompositeType, data);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.CompositeType{
                            .tag = switch (kind) {
                                .composite_struct_type => DW.TAG.structure_type,
                                .composite_union_type => DW.TAG.union_type,
                                .composite_enumeration_type => DW.TAG.enumeration_type,
                                .composite_array_type, .composite_vector_type => DW.TAG.array_type,
                                else => unreachable,
                            },
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .scope = extra.scope,
                            .underlying_type = extra.underlying_type,
                            .size_in_bits = extra.bit_size(),
                            .align_in_bits = extra.bit_align(),
                            .flags = if (kind == .composite_vector_type) .{ .Vector = true } else .{},
                            .elements = extra.fields_tuple,
                        }, metadata_adapter);
                    },
                    .derived_pointer_type,
                    .derived_member_type,
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.DerivedType, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.DerivedType{
                            .tag = switch (kind) {
                                .derived_pointer_type => DW.TAG.pointer_type,
                                .derived_member_type => DW.TAG.member,
                                else => unreachable,
                            },
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .scope = extra.scope,
                            .underlying_type = extra.underlying_type,
                            .size_in_bits = extra.bit_size(),
                            .align_in_bits = extra.bit_align(),
                            .offset_in_bits = extra.bit_offset(),
                        }, metadata_adapter);
                    },
                    .subroutine_type => {
                        const extra = self.metadata_extra_data(Metadata.SubroutineType, data);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.SubroutineType{
                            .types = extra.types_tuple,
                        }, metadata_adapter);
                    },
                    .enumerator_unsigned,
                    .enumerator_signed_positive,
                    .enumerator_signed_negative,
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.Enumerator, data);
                        const bigint: std.math.big.int.Const = .{
                            .limbs = self.metadata_limbs.items[extra.limbs_index..][0..extra.limbs_len],
                            .positive = switch (kind) {
                                .enumerator_unsigned,
                                .enumerator_signed_positive,
                                => true,
                                .enumerator_signed_negative => false,
                                else => unreachable,
                            },
                        };
                        const flags: MetadataBlock.Enumerator.Flags = .{
                            .unsigned = switch (kind) {
                                .enumerator_unsigned => true,
                                .enumerator_signed_positive,
                                .enumerator_signed_negative,
                                => false,
                                else => unreachable,
                            },
                        };
                        const val: i64 = if (bigint.to(i64)) |val|
                            val
                        else |_| if (bigint.to(u64)) |val|
                            @bit_cast(val)
                        else |_| {
                            const limbs_len = std.math.div_ceil(u32, extra.bit_width, 64) catch unreachable;
                            try record.ensure_total_capacity(self.gpa, 3 + limbs_len);
                            record.append_assume_capacity(@as(
                                @typeInfo(MetadataBlock.Enumerator.Flags).Struct.backing_integer.?,
                                @bit_cast(flags),
                            ));
                            record.append_assume_capacity(extra.bit_width);
                            record.append_assume_capacity(metadata_adapter.get_metadata_string_index(extra.name));
                            const limbs = record.add_many_as_slice_assume_capacity(limbs_len);
                            bigint.write_twos_complement(std.mem.slice_as_bytes(limbs), .little);
                            for (limbs) |*limb| {
                                const val = std.mem.little_to_native(i64, @bit_cast(limb.*));
                                limb.* = @bit_cast(if (val >= 0)
                                    val << 1 | 0
                                else
                                    -%val << 1 | 1);
                            }
                            try metadata_block.write_unabbrev(MetadataBlock.Enumerator.id, record.items);
                            continue;
                        };
                        try metadata_block.write_abbrev_adapted(MetadataBlock.Enumerator{
                            .flags = flags,
                            .bit_width = extra.bit_width,
                            .name = extra.name,
                            .value = @bit_cast(if (val >= 0)
                                val << 1 | 0
                            else
                                -%val << 1 | 1),
                        }, metadata_adapter);
                    },
                    .subrange => {
                        const extra = self.metadata_extra_data(Metadata.Subrange, data);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.Subrange{
                            .count = extra.count,
                            .lower_bound = extra.lower_bound,
                        }, metadata_adapter);
                    },
                    .expression => {
                        var extra = self.metadata_extra_data_trail(Metadata.Expression, data);

                        const elements = extra.trail.next(extra.data.elements_len, u32, self);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.Expression{
                            .elements = elements,
                        }, metadata_adapter);
                    },
                    .tuple => {
                        var extra = self.metadata_extra_data_trail(Metadata.Tuple, data);

                        const elements = extra.trail.next(extra.data.elements_len, Metadata, self);

                        try metadata_block.write_abbrev_adapted(MetadataBlock.Node{
                            .elements = elements,
                        }, metadata_adapter);
                    },
                    .module_flag => {
                        const extra = self.metadata_extra_data(Metadata.ModuleFlag, data);
                        try metadata_block.write_abbrev(MetadataBlock.Node{
                            .elements = &.{
                                @enumFromInt(metadata_adapter.get_metadata_index(extra.behavior)),
                                @enumFromInt(metadata_adapter.get_metadata_string_index(extra.name)),
                                @enumFromInt(metadata_adapter.get_metadata_index(extra.constant)),
                            },
                        });
                    },
                    .local_var => {
                        const extra = self.metadata_extra_data(Metadata.LocalVar, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.LocalVar{
                            .scope = extra.scope,
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                        }, metadata_adapter);
                    },
                    .parameter => {
                        const extra = self.metadata_extra_data(Metadata.Parameter, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.Parameter{
                            .scope = extra.scope,
                            .name = extra.name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .arg = extra.arg_no,
                        }, metadata_adapter);
                    },
                    .global_var,
                    .@"global_var local",
                    => |kind| {
                        const extra = self.metadata_extra_data(Metadata.GlobalVar, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.GlobalVar{
                            .scope = extra.scope,
                            .name = extra.name,
                            .linkage_name = extra.linkage_name,
                            .file = extra.file,
                            .line = extra.line,
                            .ty = extra.ty,
                            .local = kind == .@"global_var local",
                        }, metadata_adapter);
                    },
                    .global_var_expression => {
                        const extra = self.metadata_extra_data(Metadata.GlobalVarExpression, data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.GlobalVarExpression{
                            .variable = extra.variable,
                            .expression = extra.expression,
                        }, metadata_adapter);
                    },
                    .constant => {
                        const constant: Constant = @enumFromInt(data);
                        try metadata_block.write_abbrev_adapted(MetadataBlock.Constant{
                            .ty = constant.type_of(self),
                            .constant = constant,
                        }, metadata_adapter);
                    },
                }
            }

            // Write named metadata
            for (self.metadata_named.keys(), self.metadata_named.values()) |name, operands| {
                const slice = name.slice(self);
                try metadata_block.write_abbrev(MetadataBlock.Name{
                    .name = slice,
                });

                const elements = self.metadata_extra.items[operands.index..][0..operands.len];
                for (elements) |*e| {
                    e.* = metadata_adapter.get_metadata_index(@enumFromInt(e.*)) - 1;
                }

                try metadata_block.write_abbrev(MetadataBlock.NamedNode{
                    .elements = @ptr_cast(elements),
                });
            }

            // Write global attached metadata
            {
                for (globals.keys()) |global| {
                    const global_ptr = global.ptr_const(self);
                    if (global_ptr.dbg == .none) continue;

                    switch (global_ptr.kind) {
                        .function => |f| if (f.ptr_const(self).instructions.len != 0) continue,
                        else => {},
                    }

                    try metadata_block.write_abbrev(MetadataBlock.GlobalDeclAttachment{
                        .value = @enumFromInt(constant_adapter.get_constant_index(global.to_const())),
                        .kind = ir.MetadataKind.dbg,
                        .metadata = @enumFromInt(metadata_adapter.get_metadata_index(global_ptr.dbg) - 1),
                    });
                }
            }

            try metadata_block.end();
        }

        // Block info
        {
            const BlockInfo = ir.BlockInfo;
            var block_info_block = try module_block.enter_sub_block(BlockInfo, true);

            try block_info_block.write_unabbrev(BlockInfo.set_block_id, &.{ir.FunctionBlock.id});
            inline for (ir.FunctionBlock.abbrevs) |abbrev| {
                try block_info_block.define_abbrev(&abbrev.ops);
            }

            try block_info_block.write_unabbrev(BlockInfo.set_block_id, &.{ir.FunctionValueSymbolTable.id});
            inline for (ir.FunctionValueSymbolTable.abbrevs) |abbrev| {
                try block_info_block.define_abbrev(&abbrev.ops);
            }

            try block_info_block.write_unabbrev(BlockInfo.set_block_id, &.{ir.FunctionMetadataBlock.id});
            inline for (ir.FunctionMetadataBlock.abbrevs) |abbrev| {
                try block_info_block.define_abbrev(&abbrev.ops);
            }

            try block_info_block.write_unabbrev(BlockInfo.set_block_id, &.{ir.MetadataAttachmentBlock.id});
            inline for (ir.MetadataAttachmentBlock.abbrevs) |abbrev| {
                try block_info_block.define_abbrev(&abbrev.ops);
            }

            try block_info_block.end();
        }

        // FUNCTION_BLOCKS
        {
            const FunctionAdapter = struct {
                constant_adapter: ConstantAdapter,
                metadata_adapter: MetadataAdapter,
                func: *const Function,
                instruction_index: u32 = 0,

                pub fn init(
                    const_adapter: ConstantAdapter,
                    meta_adapter: MetadataAdapter,
                    func: *const Function,
                ) @This() {
                    return .{
                        .constant_adapter = const_adapter,
                        .metadata_adapter = meta_adapter,
                        .func = func,
                        .instruction_index = 0,
                    };
                }

                pub fn get(adapter: @This(), value: anytype, comptime field_name: []const u8) @TypeOf(value) {
                    _ = field_name;
                    const Ty = @TypeOf(value);
                    return switch (Ty) {
                        Value => @enumFromInt(adapter.get_offset_value_index(value)),
                        Constant => @enumFromInt(adapter.get_offset_constant_index(value)),
                        FunctionAttributes => @enumFromInt(switch (value) {
                            .none => 0,
                            else => 1 + adapter.constant_adapter.builder.function_attributes_set.get_index(value).?,
                        }),
                        else => value,
                    };
                }

                pub fn get_value_index(adapter: @This(), value: Value) u32 {
                    return @int_cast(switch (value.unwrap()) {
                        .instruction => |instruction| instruction.value_index(adapter.func) + adapter.first_instr(),
                        .constant => |constant| adapter.constant_adapter.get_constant_index(constant),
                        .metadata => |metadata| {
                            assert(!adapter.func.strip);
                            const real_metadata = metadata.unwrap(adapter.metadata_adapter.builder);
                            if (@int_from_enum(real_metadata) < Metadata.first_local_metadata)
                                return adapter.metadata_adapter.get_metadata_index(real_metadata) - 1;

                            return @int_cast(@int_from_enum(metadata) -
                                Metadata.first_local_metadata +
                                adapter.metadata_adapter.builder.metadata_string_map.count() - 1 +
                                adapter.metadata_adapter.builder.metadata_map.count() - 1);
                        },
                    });
                }

                pub fn get_offset_value_index(adapter: @This(), value: Value) u32 {
                    return adapter.offset() -% adapter.get_value_index(value);
                }

                pub fn get_offset_value_signed_index(adapter: @This(), value: Value) i32 {
                    const signed_offset: i32 = @int_cast(adapter.offset());
                    const signed_value: i32 = @int_cast(adapter.get_value_index(value));
                    return signed_offset - signed_value;
                }

                pub fn get_offset_constant_index(adapter: @This(), constant: Constant) u32 {
                    return adapter.offset() - adapter.constant_adapter.get_constant_index(constant);
                }

                pub fn offset(adapter: @This()) u32 {
                    return @as(
                        Function.Instruction.Index,
                        @enumFromInt(adapter.instruction_index),
                    ).value_index(adapter.func) + adapter.first_instr();
                }

                fn first_instr(adapter: @This()) u32 {
                    return adapter.constant_adapter.num_constants();
                }

                pub fn next(adapter: *@This()) void {
                    adapter.instruction_index += 1;
                }
            };

            for (self.functions.items, 0..) |func, func_index| {
                const FunctionBlock = ir.FunctionBlock;
                if (func.global.get_replacement(self) != .none) continue;

                if (func.instructions.len == 0) continue;

                var function_block = try module_block.enter_sub_block(FunctionBlock, false);

                try function_block.write_abbrev(FunctionBlock.DeclareBlocks{ .num_blocks = func.blocks.len });

                var adapter = FunctionAdapter.init(constant_adapter, metadata_adapter, &func);

                // Emit function level metadata block
                if (!func.strip and func.debug_values.len > 0) {
                    const MetadataBlock = ir.FunctionMetadataBlock;
                    var metadata_block = try function_block.enter_sub_block(MetadataBlock, false);

                    for (func.debug_values) |value| {
                        try metadata_block.write_abbrev(MetadataBlock.Value{
                            .ty = value.type_of(@enumFromInt(func_index), self),
                            .value = @enumFromInt(adapter.get_value_index(value.to_value())),
                        });
                    }

                    try metadata_block.end();
                }

                const tags = func.instructions.items(.tag);
                const datas = func.instructions.items(.data);

                var has_location = false;

                var block_incoming_len: u32 = undefined;
                for (0..func.instructions.len) |instr_index| {
                    const tag = tags[instr_index];

                    record.clear_retaining_capacity();

                    switch (tag) {
                        .block => block_incoming_len = datas[instr_index],
                        .arg => {},
                        .@"unreachable" => try function_block.write_abbrev(FunctionBlock.Unreachable{}),
                        .call,
                        .@"musttail call",
                        .@"notail call",
                        .@"tail call",
                        => |kind| {
                            var extra = func.extra_data_trail(Function.Instruction.Call, datas[instr_index]);

                            const call_conv = extra.data.info.call_conv;
                            const args = extra.trail.next(extra.data.args_len, Value, &func);
                            try function_block.write_abbrev_adapted(FunctionBlock.Call{
                                .attributes = extra.data.attributes,
                                .call_type = switch (kind) {
                                    .call => .{ .call_conv = call_conv },
                                    .@"tail call" => .{ .tail = true, .call_conv = call_conv },
                                    .@"musttail call" => .{ .must_tail = true, .call_conv = call_conv },
                                    .@"notail call" => .{ .no_tail = true, .call_conv = call_conv },
                                    else => unreachable,
                                },
                                .type_id = extra.data.ty,
                                .callee = extra.data.callee,
                                .args = args,
                            }, adapter);
                        },
                        .@"call fast",
                        .@"musttail call fast",
                        .@"notail call fast",
                        .@"tail call fast",
                        => |kind| {
                            var extra = func.extra_data_trail(Function.Instruction.Call, datas[instr_index]);

                            const call_conv = extra.data.info.call_conv;
                            const args = extra.trail.next(extra.data.args_len, Value, &func);
                            try function_block.write_abbrev_adapted(FunctionBlock.CallFast{
                                .attributes = extra.data.attributes,
                                .call_type = switch (kind) {
                                    .@"call fast" => .{ .call_conv = call_conv },
                                    .@"tail call fast" => .{ .tail = true, .call_conv = call_conv },
                                    .@"musttail call fast" => .{ .must_tail = true, .call_conv = call_conv },
                                    .@"notail call fast" => .{ .no_tail = true, .call_conv = call_conv },
                                    else => unreachable,
                                },
                                .fast_math = FastMath.fast,
                                .type_id = extra.data.ty,
                                .callee = extra.data.callee,
                                .args = args,
                            }, adapter);
                        },
                        .add,
                        .@"and",
                        .fadd,
                        .fdiv,
                        .fmul,
                        .mul,
                        .frem,
                        .fsub,
                        .sdiv,
                        .sub,
                        .udiv,
                        .xor,
                        .shl,
                        .lshr,
                        .@"or",
                        .urem,
                        .srem,
                        .ashr,
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Binary{
                                .opcode = kind.to_binary_opcode(),
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                            });
                        },
                        .@"sdiv exact",
                        .@"udiv exact",
                        .@"lshr exact",
                        .@"ashr exact",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.BinaryExact{
                                .opcode = kind.to_binary_opcode(),
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                            });
                        },
                        .@"add nsw",
                        .@"add nuw",
                        .@"add nuw nsw",
                        .@"mul nsw",
                        .@"mul nuw",
                        .@"mul nuw nsw",
                        .@"sub nsw",
                        .@"sub nuw",
                        .@"sub nuw nsw",
                        .@"shl nsw",
                        .@"shl nuw",
                        .@"shl nuw nsw",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.BinaryNoWrap{
                                .opcode = kind.to_binary_opcode(),
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .flags = switch (kind) {
                                    .@"add nsw",
                                    .@"mul nsw",
                                    .@"sub nsw",
                                    .@"shl nsw",
                                    => .{ .no_unsigned_wrap = false, .no_signed_wrap = true },
                                    .@"add nuw",
                                    .@"mul nuw",
                                    .@"sub nuw",
                                    .@"shl nuw",
                                    => .{ .no_unsigned_wrap = true, .no_signed_wrap = false },
                                    .@"add nuw nsw",
                                    .@"mul nuw nsw",
                                    .@"sub nuw nsw",
                                    .@"shl nuw nsw",
                                    => .{ .no_unsigned_wrap = true, .no_signed_wrap = true },
                                    else => unreachable,
                                },
                            });
                        },
                        .@"fadd fast",
                        .@"fdiv fast",
                        .@"fmul fast",
                        .@"frem fast",
                        .@"fsub fast",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.BinaryFast{
                                .opcode = kind.to_binary_opcode(),
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .alloca,
                        .@"alloca inalloca",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Alloca, datas[instr_index]);
                            const alignment = extra.info.alignment.to_llvm();
                            try function_block.write_abbrev(FunctionBlock.Alloca{
                                .inst_type = extra.type,
                                .len_type = extra.len.type_of(@enumFromInt(func_index), self),
                                .len_value = adapter.get_value_index(extra.len),
                                .flags = .{
                                    .align_lower = @truncate(alignment),
                                    .inalloca = kind == .@"alloca inalloca",
                                    .explicit_type = true,
                                    .swift_error = false,
                                    .align_upper = @truncate(alignment << 5),
                                },
                            });
                        },
                        .bitcast,
                        .inttoptr,
                        .ptrtoint,
                        .fptosi,
                        .fptoui,
                        .sitofp,
                        .uitofp,
                        .addrspacecast,
                        .fptrunc,
                        .trunc,
                        .fpext,
                        .sext,
                        .zext,
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Cast, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Cast{
                                .val = adapter.get_offset_value_index(extra.val),
                                .type_index = extra.type,
                                .opcode = kind.to_cast_opcode(),
                            });
                        },
                        .@"fcmp false",
                        .@"fcmp oeq",
                        .@"fcmp oge",
                        .@"fcmp ogt",
                        .@"fcmp ole",
                        .@"fcmp olt",
                        .@"fcmp one",
                        .@"fcmp ord",
                        .@"fcmp true",
                        .@"fcmp ueq",
                        .@"fcmp uge",
                        .@"fcmp ugt",
                        .@"fcmp ule",
                        .@"fcmp ult",
                        .@"fcmp une",
                        .@"fcmp uno",
                        .@"icmp eq",
                        .@"icmp ne",
                        .@"icmp sge",
                        .@"icmp sgt",
                        .@"icmp sle",
                        .@"icmp slt",
                        .@"icmp uge",
                        .@"icmp ugt",
                        .@"icmp ule",
                        .@"icmp ult",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Cmp{
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .pred = kind.to_cmp_predicate(),
                            });
                        },
                        .@"fcmp fast false",
                        .@"fcmp fast oeq",
                        .@"fcmp fast oge",
                        .@"fcmp fast ogt",
                        .@"fcmp fast ole",
                        .@"fcmp fast olt",
                        .@"fcmp fast one",
                        .@"fcmp fast ord",
                        .@"fcmp fast true",
                        .@"fcmp fast ueq",
                        .@"fcmp fast uge",
                        .@"fcmp fast ugt",
                        .@"fcmp fast ule",
                        .@"fcmp fast ult",
                        .@"fcmp fast une",
                        .@"fcmp fast uno",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.Binary, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.CmpFast{
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .pred = kind.to_cmp_predicate(),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .fneg => try function_block.write_abbrev(FunctionBlock.FNeg{
                            .val = adapter.get_offset_value_index(@enumFromInt(datas[instr_index])),
                        }),
                        .@"fneg fast" => try function_block.write_abbrev(FunctionBlock.FNegFast{
                            .val = adapter.get_offset_value_index(@enumFromInt(datas[instr_index])),
                            .fast_math = FastMath.fast,
                        }),
                        .extractvalue => {
                            var extra = func.extra_data_trail(Function.Instruction.ExtractValue, datas[instr_index]);
                            const indices = extra.trail.next(extra.data.indices_len, u32, &func);
                            try function_block.write_abbrev(FunctionBlock.ExtractValue{
                                .val = adapter.get_offset_value_index(extra.data.val),
                                .indices = indices,
                            });
                        },
                        .insertvalue => {
                            var extra = func.extra_data_trail(Function.Instruction.InsertValue, datas[instr_index]);
                            const indices = extra.trail.next(extra.data.indices_len, u32, &func);
                            try function_block.write_abbrev(FunctionBlock.InsertValue{
                                .val = adapter.get_offset_value_index(extra.data.val),
                                .elem = adapter.get_offset_value_index(extra.data.elem),
                                .indices = indices,
                            });
                        },
                        .extractelement => {
                            const extra = func.extra_data(Function.Instruction.ExtractElement, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.ExtractElement{
                                .val = adapter.get_offset_value_index(extra.val),
                                .index = adapter.get_offset_value_index(extra.index),
                            });
                        },
                        .insertelement => {
                            const extra = func.extra_data(Function.Instruction.InsertElement, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.InsertElement{
                                .val = adapter.get_offset_value_index(extra.val),
                                .elem = adapter.get_offset_value_index(extra.elem),
                                .index = adapter.get_offset_value_index(extra.index),
                            });
                        },
                        .select => {
                            const extra = func.extra_data(Function.Instruction.Select, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Select{
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .cond = adapter.get_offset_value_index(extra.cond),
                            });
                        },
                        .@"select fast" => {
                            const extra = func.extra_data(Function.Instruction.Select, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.SelectFast{
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .cond = adapter.get_offset_value_index(extra.cond),
                                .fast_math = FastMath.fast,
                            });
                        },
                        .shufflevector => {
                            const extra = func.extra_data(Function.Instruction.ShuffleVector, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.ShuffleVector{
                                .lhs = adapter.get_offset_value_index(extra.lhs),
                                .rhs = adapter.get_offset_value_index(extra.rhs),
                                .mask = adapter.get_offset_value_index(extra.mask),
                            });
                        },
                        .getelementptr,
                        .@"getelementptr inbounds",
                        => |kind| {
                            var extra = func.extra_data_trail(Function.Instruction.GetElementPtr, datas[instr_index]);
                            const indices = extra.trail.next(extra.data.indices_len, Value, &func);
                            try function_block.write_abbrev_adapted(
                                FunctionBlock.GetElementPtr{
                                    .is_inbounds = kind == .@"getelementptr inbounds",
                                    .type_index = extra.data.type,
                                    .base = extra.data.base,
                                    .indices = indices,
                                },
                                adapter,
                            );
                        },
                        .load => {
                            const extra = func.extra_data(Function.Instruction.Load, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Load{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .ty = extra.type,
                                .alignment = extra.info.alignment.to_llvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                            });
                        },
                        .@"load atomic" => {
                            const extra = func.extra_data(Function.Instruction.Load, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.LoadAtomic{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .ty = extra.type,
                                .alignment = extra.info.alignment.to_llvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                            });
                        },
                        .store => {
                            const extra = func.extra_data(Function.Instruction.Store, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Store{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .val = adapter.get_offset_value_index(extra.val),
                                .alignment = extra.info.alignment.to_llvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                            });
                        },
                        .@"store atomic" => {
                            const extra = func.extra_data(Function.Instruction.Store, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.StoreAtomic{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .val = adapter.get_offset_value_index(extra.val),
                                .alignment = extra.info.alignment.to_llvm(),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                            });
                        },
                        .br => {
                            try function_block.write_abbrev(FunctionBlock.BrUnconditional{
                                .block = datas[instr_index],
                            });
                        },
                        .br_cond => {
                            const extra = func.extra_data(Function.Instruction.BrCond, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.BrConditional{
                                .then_block = @int_from_enum(extra.then),
                                .else_block = @int_from_enum(extra.@"else"),
                                .condition = adapter.get_offset_value_index(extra.cond),
                            });
                        },
                        .@"switch" => {
                            var extra = func.extra_data_trail(Function.Instruction.Switch, datas[instr_index]);

                            try record.ensure_unused_capacity(self.gpa, 3 + extra.data.cases_len * 2);

                            // Conditional type
                            record.append_assume_capacity(@int_from_enum(extra.data.val.type_of(@enumFromInt(func_index), self)));

                            // Conditional
                            record.append_assume_capacity(adapter.get_offset_value_index(extra.data.val));

                            // Default block
                            record.append_assume_capacity(@int_from_enum(extra.data.default));

                            const vals = extra.trail.next(extra.data.cases_len, Constant, &func);
                            const blocks = extra.trail.next(extra.data.cases_len, Function.Block.Index, &func);
                            for (vals, blocks) |val, block| {
                                record.append_assume_capacity(adapter.constant_adapter.get_constant_index(val));
                                record.append_assume_capacity(@int_from_enum(block));
                            }

                            try function_block.write_unabbrev(12, record.items);
                        },
                        .va_arg => {
                            const extra = func.extra_data(Function.Instruction.VaArg, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.VaArg{
                                .list_type = extra.list.type_of(@enumFromInt(func_index), self),
                                .list = adapter.get_offset_value_index(extra.list),
                                .type = extra.type,
                            });
                        },
                        .phi,
                        .@"phi fast",
                        => |kind| {
                            var extra = func.extra_data_trail(Function.Instruction.Phi, datas[instr_index]);
                            const vals = extra.trail.next(block_incoming_len, Value, &func);
                            const blocks = extra.trail.next(block_incoming_len, Function.Block.Index, &func);

                            try record.ensure_unused_capacity(
                                self.gpa,
                                1 + block_incoming_len * 2 + @int_from_bool(kind == .@"phi fast"),
                            );

                            record.append_assume_capacity(@int_from_enum(extra.data.type));

                            for (vals, blocks) |val, block| {
                                const offset_value = adapter.get_offset_value_signed_index(val);
                                const abs_value: u32 = @int_cast(@abs(offset_value));
                                const signed_vbr = if (offset_value > 0) abs_value << 1 else ((abs_value << 1) | 1);
                                record.append_assume_capacity(signed_vbr);
                                record.append_assume_capacity(@int_from_enum(block));
                            }

                            if (kind == .@"phi fast") record.append_assume_capacity(@as(u8, @bit_cast(FastMath{})));

                            try function_block.write_unabbrev(16, record.items);
                        },
                        .ret => try function_block.write_abbrev(FunctionBlock.Ret{
                            .val = adapter.get_offset_value_index(@enumFromInt(datas[instr_index])),
                        }),
                        .@"ret void" => try function_block.write_abbrev(FunctionBlock.RetVoid{}),
                        .atomicrmw => {
                            const extra = func.extra_data(Function.Instruction.AtomicRmw, datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.AtomicRmw{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .val = adapter.get_offset_value_index(extra.val),
                                .operation = extra.info.atomic_rmw_operation,
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                                .alignment = extra.info.alignment.to_llvm(),
                            });
                        },
                        .cmpxchg,
                        .@"cmpxchg weak",
                        => |kind| {
                            const extra = func.extra_data(Function.Instruction.CmpXchg, datas[instr_index]);

                            try function_block.write_abbrev(FunctionBlock.CmpXchg{
                                .ptr = adapter.get_offset_value_index(extra.ptr),
                                .cmp = adapter.get_offset_value_index(extra.cmp),
                                .new = adapter.get_offset_value_index(extra.new),
                                .is_volatile = extra.info.access_kind == .@"volatile",
                                .success_ordering = extra.info.success_ordering,
                                .sync_scope = extra.info.sync_scope,
                                .failure_ordering = extra.info.failure_ordering,
                                .is_weak = kind == .@"cmpxchg weak",
                                .alignment = extra.info.alignment.to_llvm(),
                            });
                        },
                        .fence => {
                            const info: MemoryAccessInfo = @bit_cast(datas[instr_index]);
                            try function_block.write_abbrev(FunctionBlock.Fence{
                                .ordering = info.success_ordering,
                                .sync_scope = info.sync_scope,
                            });
                        },
                    }

                    if (!func.strip) {
                        if (func.debug_locations.get(@enumFromInt(instr_index))) |debug_location| {
                            switch (debug_location) {
                                .no_location => has_location = false,
                                .location => |location| {
                                    try function_block.write_abbrev(FunctionBlock.DebugLoc{
                                        .line = location.line,
                                        .column = location.column,
                                        .scope = @enumFromInt(metadata_adapter.get_metadata_index(location.scope)),
                                        .inlined_at = @enumFromInt(metadata_adapter.get_metadata_index(location.inlined_at)),
                                    });
                                    has_location = true;
                                },
                            }
                        } else if (has_location) {
                            try function_block.write_abbrev(FunctionBlock.DebugLocAgain{});
                        }
                    }

                    adapter.next();
                }

                // VALUE_SYMTAB
                if (!func.strip) {
                    const ValueSymbolTable = ir.FunctionValueSymbolTable;

                    var value_symtab_block = try function_block.enter_sub_block(ValueSymbolTable, false);

                    for (func.blocks, 0..) |block, block_index| {
                        const name = block.instruction.name(&func);

                        if (name == .none or name == .empty) continue;

                        try value_symtab_block.write_abbrev(ValueSymbolTable.BlockEntry{
                            .value_id = @int_cast(block_index),
                            .string = name.slice(self).?,
                        });
                    }

                    // TODO: Emit non block entries if the builder ever starts assigning names to non blocks

                    try value_symtab_block.end();
                }

                // METADATA_ATTACHMENT_BLOCK
                if (!func.strip) blk: {
                    const dbg = func.global.ptr_const(self).dbg;

                    if (dbg == .none) break :blk;

                    const MetadataAttachmentBlock = ir.MetadataAttachmentBlock;
                    var metadata_attach_block = try function_block.enter_sub_block(MetadataAttachmentBlock, false);

                    try metadata_attach_block.write_abbrev(MetadataAttachmentBlock.AttachmentSingle{
                        .kind = ir.MetadataKind.dbg,
                        .metadata = @enumFromInt(metadata_adapter.get_metadata_index(dbg) - 1),
                    });

                    try metadata_attach_block.end();
                }

                try function_block.end();
            }
        }

        try module_block.end();
    }

    // STRTAB_BLOCK
    {
        const Strtab = ir.Strtab;
        var strtab_block = try bitcode.enter_top_block(Strtab);

        try strtab_block.write_abbrev(Strtab.Blob{ .blob = self.strtab_string_bytes.items });

        try strtab_block.end();
    }

    return bitcode.to_owned_slice();
}

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const bitcode_writer = @import("bitcode_writer.zig");
const build_options = @import("build_options");
const Builder = @This();
const builtin = @import("builtin");
const DW = std.dwarf;
const ir = @import("ir.zig");
const log = std.log.scoped(.llvm);
const std = @import("std");
