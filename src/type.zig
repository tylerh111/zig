const std = @import("std");
const builtin = @import("builtin");
const Value = @import("Value.zig");
const assert = std.debug.assert;
const Target = std.Target;
const Module = @import("Module.zig");
const Zcu = Module;
const log = std.log.scoped(.Type);
const target_util = @import("target.zig");
const Sema = @import("Sema.zig");
const InternPool = @import("InternPool.zig");
const Alignment = InternPool.Alignment;

/// Both types and values are canonically represented by a single 32-bit integer
/// which is an index into an `InternPool` data structure.
/// This struct abstracts around this storage by providing methods only
/// applicable to types rather than values in general.
pub const Type = struct {
    ip_index: InternPool.Index,

    pub fn zig_type_tag(ty: Type, mod: *const Module) std.builtin.TypeId {
        return ty.zig_type_tag_or_poison(mod) catch unreachable;
    }

    pub fn zig_type_tag_or_poison(ty: Type, mod: *const Module) error{GenericPoison}!std.builtin.TypeId {
        return mod.intern_pool.zig_type_tag_or_poison(ty.to_intern());
    }

    pub fn base_zig_type_tag(self: Type, mod: *Module) std.builtin.TypeId {
        return switch (self.zig_type_tag(mod)) {
            .ErrorUnion => self.error_union_payload(mod).base_zig_type_tag(mod),
            .Optional => {
                return self.optional_child(mod).base_zig_type_tag(mod);
            },
            else => |t| t,
        };
    }

    pub fn is_self_comparable(ty: Type, mod: *const Module, is_equality_cmp: bool) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Int,
            .Float,
            .ComptimeFloat,
            .ComptimeInt,
            => true,

            .Vector => ty.elem_type2(mod).is_self_comparable(mod, is_equality_cmp),

            .Bool,
            .Type,
            .Void,
            .ErrorSet,
            .Fn,
            .Opaque,
            .AnyFrame,
            .Enum,
            .EnumLiteral,
            => is_equality_cmp,

            .NoReturn,
            .Array,
            .Struct,
            .Undefined,
            .Null,
            .ErrorUnion,
            .Union,
            .Frame,
            => false,

            .Pointer => !ty.is_slice(mod) and (is_equality_cmp or ty.is_cptr(mod)),
            .Optional => {
                if (!is_equality_cmp) return false;
                return ty.optional_child(mod).is_self_comparable(mod, is_equality_cmp);
            },
        };
    }

    /// If it is a function pointer, returns the function type. Otherwise returns null.
    pub fn cast_ptr_to_fn(ty: Type, mod: *const Module) ?Type {
        if (ty.zig_type_tag(mod) != .Pointer) return null;
        const elem_ty = ty.child_type(mod);
        if (elem_ty.zig_type_tag(mod) != .Fn) return null;
        return elem_ty;
    }

    /// Asserts the type is a pointer.
    pub fn ptr_is_mutable(ty: Type, mod: *const Module) bool {
        return !mod.intern_pool.index_to_key(ty.to_intern()).ptr_type.flags.is_const;
    }

    pub const ArrayInfo = struct {
        elem_type: Type,
        sentinel: ?Value = null,
        len: u64,
    };

    pub fn array_info(self: Type, mod: *const Module) ArrayInfo {
        return .{
            .len = self.array_len(mod),
            .sentinel = self.sentinel(mod),
            .elem_type = self.child_type(mod),
        };
    }

    pub fn ptr_info(ty: Type, mod: *const Module) InternPool.Key.PtrType {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |p| p,
            .opt_type => |child| switch (mod.intern_pool.index_to_key(child)) {
                .ptr_type => |p| p,
                else => unreachable,
            },
            else => unreachable,
        };
    }

    pub fn eql(a: Type, b: Type, mod: *const Module) bool {
        _ = mod; // TODO: remove this parameter
        // The InternPool data structure hashes based on Key to make interned objects
        // unique. An Index can be treated simply as u32 value for the
        // purpose of Type/Value hashing and equality.
        return a.to_intern() == b.to_intern();
    }

    pub fn format(ty: Type, comptime unused_fmt_string: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = ty;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compile_error("do not format types directly; use either ty.fmt_debug() or ty.fmt()");
    }

    pub const Formatter = std.fmt.Formatter(format2);

    pub fn fmt(ty: Type, module: *Module) Formatter {
        return .{ .data = .{
            .ty = ty,
            .module = module,
        } };
    }

    const FormatContext = struct {
        ty: Type,
        module: *Module,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        comptime assert(unused_format_string.len == 0);
        _ = options;
        return print(ctx.ty, writer, ctx.module);
    }

    pub fn fmt_debug(ty: Type) std.fmt.Formatter(dump) {
        return .{ .data = ty };
    }

    /// This is a debug function. In order to print types in a meaningful way
    /// we also need access to the module.
    pub fn dump(
        start_type: Type,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        comptime assert(unused_format_string.len == 0);
        return writer.print("{any}", .{start_type.ip_index});
    }

    /// Prints a name suitable for `@type_name`.
    /// TODO: take an `opt_sema` to pass to `fmt_value` when printing sentinels.
    pub fn print(ty: Type, writer: anytype, mod: *Module) @TypeOf(writer).Error!void {
        const ip = &mod.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .int_type => |int_type| {
                const sign_char: u8 = switch (int_type.signedness) {
                    .signed => 'i',
                    .unsigned => 'u',
                };
                return writer.print("{c}{d}", .{ sign_char, int_type.bits });
            },
            .ptr_type => {
                const info = ty.ptr_info(mod);

                if (info.sentinel != .none) switch (info.flags.size) {
                    .One, .C => unreachable,
                    .Many => try writer.print("[*:{}]", .{Value.from_interned(info.sentinel).fmt_value(mod, null)}),
                    .Slice => try writer.print("[:{}]", .{Value.from_interned(info.sentinel).fmt_value(mod, null)}),
                } else switch (info.flags.size) {
                    .One => try writer.write_all("*"),
                    .Many => try writer.write_all("[*]"),
                    .C => try writer.write_all("[*c]"),
                    .Slice => try writer.write_all("[]"),
                }
                if (info.flags.alignment != .none or
                    info.packed_offset.host_size != 0 or
                    info.flags.vector_index != .none)
                {
                    const alignment = if (info.flags.alignment != .none)
                        info.flags.alignment
                    else
                        Type.from_interned(info.child).abi_alignment(mod);
                    try writer.print("align({d}", .{alignment.to_byte_units() orelse 0});

                    if (info.packed_offset.bit_offset != 0 or info.packed_offset.host_size != 0) {
                        try writer.print(":{d}:{d}", .{
                            info.packed_offset.bit_offset, info.packed_offset.host_size,
                        });
                    }
                    if (info.flags.vector_index == .runtime) {
                        try writer.write_all(":?");
                    } else if (info.flags.vector_index != .none) {
                        try writer.print(":{d}", .{@int_from_enum(info.flags.vector_index)});
                    }
                    try writer.write_all(") ");
                }
                if (info.flags.address_space != .generic) {
                    try writer.print("addrspace(.{s}) ", .{@tag_name(info.flags.address_space)});
                }
                if (info.flags.is_const) try writer.write_all("const ");
                if (info.flags.is_volatile) try writer.write_all("volatile ");
                if (info.flags.is_allowzero and info.flags.size != .C) try writer.write_all("allowzero ");

                try print(Type.from_interned(info.child), writer, mod);
                return;
            },
            .array_type => |array_type| {
                if (array_type.sentinel == .none) {
                    try writer.print("[{d}]", .{array_type.len});
                    try print(Type.from_interned(array_type.child), writer, mod);
                } else {
                    try writer.print("[{d}:{}]", .{
                        array_type.len,
                        Value.from_interned(array_type.sentinel).fmt_value(mod, null),
                    });
                    try print(Type.from_interned(array_type.child), writer, mod);
                }
                return;
            },
            .vector_type => |vector_type| {
                try writer.print("@Vector({d}, ", .{vector_type.len});
                try print(Type.from_interned(vector_type.child), writer, mod);
                try writer.write_all(")");
                return;
            },
            .opt_type => |child| {
                try writer.write_byte('?');
                return print(Type.from_interned(child), writer, mod);
            },
            .error_union_type => |error_union_type| {
                try print(Type.from_interned(error_union_type.error_set_type), writer, mod);
                try writer.write_byte('!');
                if (error_union_type.payload_type == .generic_poison_type) {
                    try writer.write_all("anytype");
                } else {
                    try print(Type.from_interned(error_union_type.payload_type), writer, mod);
                }
                return;
            },
            .inferred_error_set_type => |func_index| {
                try writer.write_all("@typeInfo(@typeInfo(@TypeOf(");
                const owner_decl = mod.func_owner_decl_ptr(func_index);
                try owner_decl.render_fully_qualified_name(mod, writer);
                try writer.write_all(")).Fn.return_type.?).ErrorUnion.error_set");
            },
            .error_set_type => |error_set_type| {
                const names = error_set_type.names;
                try writer.write_all("error{");
                for (names.get(ip), 0..) |name, i| {
                    if (i != 0) try writer.write_byte(',');
                    try writer.print("{}", .{name.fmt(ip)});
                }
                try writer.write_all("}");
            },
            .simple_type => |s| switch (s) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_char,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                .anyopaque,
                .bool,
                .void,
                .type,
                .anyerror,
                .comptime_int,
                .comptime_float,
                .noreturn,
                .adhoc_inferred_error_set,
                => return writer.write_all(@tag_name(s)),

                .null,
                .undefined,
                => try writer.print("@TypeOf({s})", .{@tag_name(s)}),

                .enum_literal => try writer.print("@TypeOf(.{s})", .{@tag_name(s)}),
                .atomic_order => try writer.write_all("std.builtin.AtomicOrder"),
                .atomic_rmw_op => try writer.write_all("std.builtin.AtomicRmwOp"),
                .calling_convention => try writer.write_all("std.builtin.CallingConvention"),
                .address_space => try writer.write_all("std.builtin.AddressSpace"),
                .float_mode => try writer.write_all("std.builtin.FloatMode"),
                .reduce_op => try writer.write_all("std.builtin.ReduceOp"),
                .call_modifier => try writer.write_all("std.builtin.CallModifier"),
                .prefetch_options => try writer.write_all("std.builtin.PrefetchOptions"),
                .export_options => try writer.write_all("std.builtin.ExportOptions"),
                .extern_options => try writer.write_all("std.builtin.ExternOptions"),
                .type_info => try writer.write_all("std.builtin.Type"),

                .generic_poison => unreachable,
            },
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                if (struct_type.decl.unwrap()) |decl_index| {
                    const decl = mod.decl_ptr(decl_index);
                    try decl.render_fully_qualified_name(mod, writer);
                } else if (ip.load_struct_type(ty.to_intern()).namespace.unwrap()) |namespace_index| {
                    const namespace = mod.namespace_ptr(namespace_index);
                    try namespace.render_fully_qualified_name(mod, .empty, writer);
                } else {
                    try writer.write_all("@TypeOf(.{})");
                }
            },
            .anon_struct_type => |anon_struct| {
                if (anon_struct.types.len == 0) {
                    return writer.write_all("@TypeOf(.{})");
                }
                try writer.write_all("struct{");
                for (anon_struct.types.get(ip), anon_struct.values.get(ip), 0..) |field_ty, val, i| {
                    if (i != 0) try writer.write_all(", ");
                    if (val != .none) {
                        try writer.write_all("comptime ");
                    }
                    if (anon_struct.names.len != 0) {
                        try writer.print("{}: ", .{anon_struct.names.get(ip)[i].fmt(&mod.intern_pool)});
                    }

                    try print(Type.from_interned(field_ty), writer, mod);

                    if (val != .none) {
                        try writer.print(" = {}", .{Value.from_interned(val).fmt_value(mod, null)});
                    }
                }
                try writer.write_all("}");
            },

            .union_type => {
                const decl = mod.decl_ptr(ip.load_union_type(ty.to_intern()).decl);
                try decl.render_fully_qualified_name(mod, writer);
            },
            .opaque_type => {
                const decl = mod.decl_ptr(ip.load_opaque_type(ty.to_intern()).decl);
                try decl.render_fully_qualified_name(mod, writer);
            },
            .enum_type => {
                const decl = mod.decl_ptr(ip.load_enum_type(ty.to_intern()).decl);
                try decl.render_fully_qualified_name(mod, writer);
            },
            .func_type => |fn_info| {
                if (fn_info.is_noinline) {
                    try writer.write_all("noinline ");
                }
                try writer.write_all("fn (");
                const param_types = fn_info.param_types.get(&mod.intern_pool);
                for (param_types, 0..) |param_ty, i| {
                    if (i != 0) try writer.write_all(", ");
                    if (std.math.cast(u5, i)) |index| {
                        if (fn_info.param_is_comptime(index)) {
                            try writer.write_all("comptime ");
                        }
                        if (fn_info.param_is_noalias(index)) {
                            try writer.write_all("noalias ");
                        }
                    }
                    if (param_ty == .generic_poison_type) {
                        try writer.write_all("anytype");
                    } else {
                        try print(Type.from_interned(param_ty), writer, mod);
                    }
                }
                if (fn_info.is_var_args) {
                    if (param_types.len != 0) {
                        try writer.write_all(", ");
                    }
                    try writer.write_all("...");
                }
                try writer.write_all(") ");
                if (fn_info.cc != .Unspecified) {
                    try writer.write_all("callconv(.");
                    try writer.write_all(@tag_name(fn_info.cc));
                    try writer.write_all(") ");
                }
                if (fn_info.return_type == .generic_poison_type) {
                    try writer.write_all("anytype");
                } else {
                    try print(Type.from_interned(fn_info.return_type), writer, mod);
                }
            },
            .anyframe_type => |child| {
                if (child == .none) return writer.write_all("anyframe");
                try writer.write_all("anyframe->");
                return print(Type.from_interned(child), writer, mod);
            },

            // values, not types
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
            // memoization, not types
            .memoized_call,
            => unreachable,
        }
    }

    pub fn from_interned(i: InternPool.Index) Type {
        assert(i != .none);
        return .{ .ip_index = i };
    }

    pub fn to_intern(ty: Type) InternPool.Index {
        assert(ty.ip_index != .none);
        return ty.ip_index;
    }

    pub fn to_value(self: Type) Value {
        return Value.from_interned(self.to_intern());
    }

    const RuntimeBitsError = Module.CompileError || error{NeedLazy};

    /// true if and only if the type takes up space in memory at runtime.
    /// There are two reasons a type will return false:
    /// * the type is a comptime-only type. For example, the type `type` itself.
    ///   - note, however, that a struct can have mixed fields and only the non-comptime-only
    ///     fields will count towards the ABI size. For example, `struct {T: type, x: i32}`
    ///     has_runtime_bits()=true and abi_size()=4
    /// * the type has only one possible value, making its ABI size 0.
    ///   - an enum with an explicit tag type has the ABI size of the integer tag type,
    ///     making it one-possible-value only if the integer tag type has 0 bits.
    /// When `ignore_comptime_only` is true, then types that are comptime-only
    /// may return false positives.
    pub fn has_runtime_bits_advanced(
        ty: Type,
        mod: *Module,
        ignore_comptime_only: bool,
        strat: AbiAlignmentAdvancedStrat,
    ) RuntimeBitsError!bool {
        const ip = &mod.intern_pool;
        return switch (ty.to_intern()) {
            // False because it is a comptime-only type.
            .empty_struct_type => false,
            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => |int_type| int_type.bits != 0,
                .ptr_type => {
                    // Pointers to zero-bit types still have a runtime address; however, pointers
                    // to comptime-only types do not, with the exception of function pointers.
                    if (ignore_comptime_only) return true;
                    return switch (strat) {
                        .sema => |sema| !(try sema.type_requires_comptime(ty)),
                        .eager => !comptime_only(ty, mod),
                        .lazy => error.NeedLazy,
                    };
                },
                .anyframe_type => true,
                .array_type => |array_type| return array_type.len_including_sentinel() > 0 and
                    try Type.from_interned(array_type.child).has_runtime_bits_advanced(mod, ignore_comptime_only, strat),
                .vector_type => |vector_type| return vector_type.len > 0 and
                    try Type.from_interned(vector_type.child).has_runtime_bits_advanced(mod, ignore_comptime_only, strat),
                .opt_type => |child| {
                    const child_ty = Type.from_interned(child);
                    if (child_ty.is_no_return(mod)) {
                        // Then the optional is comptime-known to be null.
                        return false;
                    }
                    if (ignore_comptime_only) return true;
                    return switch (strat) {
                        .sema => |sema| !(try sema.type_requires_comptime(child_ty)),
                        .eager => !comptime_only(child_ty, mod),
                        .lazy => error.NeedLazy,
                    };
                },
                .error_union_type,
                .error_set_type,
                .inferred_error_set_type,
                => true,

                // These are function *bodies*, not pointers.
                // They return false here because they are comptime-only types.
                // Special exceptions have to be made when emitting functions due to
                // this returning false.
                .func_type => false,

                .simple_type => |t| switch (t) {
                    .f16,
                    .f32,
                    .f64,
                    .f80,
                    .f128,
                    .usize,
                    .isize,
                    .c_char,
                    .c_short,
                    .c_ushort,
                    .c_int,
                    .c_uint,
                    .c_long,
                    .c_ulong,
                    .c_longlong,
                    .c_ulonglong,
                    .c_longdouble,
                    .bool,
                    .anyerror,
                    .adhoc_inferred_error_set,
                    .anyopaque,
                    .atomic_order,
                    .atomic_rmw_op,
                    .calling_convention,
                    .address_space,
                    .float_mode,
                    .reduce_op,
                    .call_modifier,
                    .prefetch_options,
                    .export_options,
                    .extern_options,
                    => true,

                    // These are false because they are comptime-only types.
                    .void,
                    .type,
                    .comptime_int,
                    .comptime_float,
                    .noreturn,
                    .null,
                    .undefined,
                    .enum_literal,
                    .type_info,
                    => false,

                    .generic_poison => unreachable,
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    if (struct_type.assume_runtime_bits_if_field_types_wip(ip)) {
                        // In this case, we guess that has_runtime_bits() for this type is true,
                        // and then later if our guess was incorrect, we emit a compile error.
                        return true;
                    }
                    switch (strat) {
                        .sema => |sema| _ = try sema.resolve_type_fields(ty),
                        .eager => assert(struct_type.have_field_types(ip)),
                        .lazy => if (!struct_type.have_field_types(ip)) return error.NeedLazy,
                    }
                    for (0..struct_type.field_types.len) |i| {
                        if (struct_type.comptime_bits.get_bit(ip, i)) continue;
                        const field_ty = Type.from_interned(struct_type.field_types.get(ip)[i]);
                        if (try field_ty.has_runtime_bits_advanced(mod, ignore_comptime_only, strat))
                            return true;
                    } else {
                        return false;
                    }
                },
                .anon_struct_type => |tuple| {
                    for (tuple.types.get(ip), tuple.values.get(ip)) |field_ty, val| {
                        if (val != .none) continue; // comptime field
                        if (try Type.from_interned(field_ty).has_runtime_bits_advanced(mod, ignore_comptime_only, strat)) return true;
                    }
                    return false;
                },

                .union_type => {
                    const union_type = ip.load_union_type(ty.to_intern());
                    switch (union_type.flags_ptr(ip).runtime_tag) {
                        .none => {
                            if (union_type.flags_ptr(ip).status == .field_types_wip) {
                                // In this case, we guess that has_runtime_bits() for this type is true,
                                // and then later if our guess was incorrect, we emit a compile error.
                                union_type.flags_ptr(ip).assumed_runtime_bits = true;
                                return true;
                            }
                        },
                        .safety, .tagged => {
                            const tag_ty = union_type.tag_type_ptr(ip).*;
                            // tag_ty will be `none` if this union's tag type is not resolved yet,
                            // in which case we want control flow to continue down below.
                            if (tag_ty != .none and
                                try Type.from_interned(tag_ty).has_runtime_bits_advanced(mod, ignore_comptime_only, strat))
                            {
                                return true;
                            }
                        },
                    }
                    switch (strat) {
                        .sema => |sema| _ = try sema.resolve_type_fields(ty),
                        .eager => assert(union_type.flags_ptr(ip).status.have_field_types()),
                        .lazy => if (!union_type.flags_ptr(ip).status.have_field_types())
                            return error.NeedLazy,
                    }
                    for (0..union_type.field_types.len) |field_index| {
                        const field_ty = Type.from_interned(union_type.field_types.get(ip)[field_index]);
                        if (try field_ty.has_runtime_bits_advanced(mod, ignore_comptime_only, strat))
                            return true;
                    } else {
                        return false;
                    }
                },

                .opaque_type => true,
                .enum_type => Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty).has_runtime_bits_advanced(mod, ignore_comptime_only, strat),

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        };
    }

    /// true if and only if the type has a well-defined memory layout
    /// readFrom/write_to_memory are supported only for types with a well-
    /// defined memory layout
    pub fn has_well_defined_layout(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .int_type,
            .vector_type,
            => true,

            .error_union_type,
            .error_set_type,
            .inferred_error_set_type,
            .anon_struct_type,
            .opaque_type,
            .anyframe_type,
            // These are function bodies, not function pointers.
            .func_type,
            => false,

            .array_type => |array_type| Type.from_interned(array_type.child).has_well_defined_layout(mod),
            .opt_type => ty.is_ptr_like_optional(mod),
            .ptr_type => |ptr_type| ptr_type.flags.size != .Slice,

            .simple_type => |t| switch (t) {
                .f16,
                .f32,
                .f64,
                .f80,
                .f128,
                .usize,
                .isize,
                .c_char,
                .c_short,
                .c_ushort,
                .c_int,
                .c_uint,
                .c_long,
                .c_ulong,
                .c_longlong,
                .c_ulonglong,
                .c_longdouble,
                .bool,
                .void,
                => true,

                .anyerror,
                .adhoc_inferred_error_set,
                .anyopaque,
                .atomic_order,
                .atomic_rmw_op,
                .calling_convention,
                .address_space,
                .float_mode,
                .reduce_op,
                .call_modifier,
                .prefetch_options,
                .export_options,
                .extern_options,
                .type,
                .comptime_int,
                .comptime_float,
                .noreturn,
                .null,
                .undefined,
                .enum_literal,
                .type_info,
                .generic_poison,
                => false,
            },
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                // Struct with no fields have a well-defined layout of no bits.
                return struct_type.layout != .auto or struct_type.field_types.len == 0;
            },
            .union_type => {
                const union_type = ip.load_union_type(ty.to_intern());
                return switch (union_type.flags_ptr(ip).runtime_tag) {
                    .none, .safety => union_type.flags_ptr(ip).layout != .auto,
                    .tagged => false,
                };
            },
            .enum_type => switch (ip.load_enum_type(ty.to_intern()).tag_mode) {
                .auto => false,
                .explicit, .nonexhaustive => true,
            },

            // values, not types
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
            // memoization, not types
            .memoized_call,
            => unreachable,
        };
    }

    pub fn has_runtime_bits(ty: Type, mod: *Module) bool {
        return has_runtime_bits_advanced(ty, mod, false, .eager) catch unreachable;
    }

    pub fn has_runtime_bits_ignore_comptime(ty: Type, mod: *Module) bool {
        return has_runtime_bits_advanced(ty, mod, true, .eager) catch unreachable;
    }

    pub fn fn_has_runtime_bits(ty: Type, mod: *Module) bool {
        return ty.fn_has_runtime_bits_advanced(mod, null) catch unreachable;
    }

    /// Determines whether a function type has runtime bits, i.e. whether a
    /// function with this type can exist at runtime.
    /// Asserts that `ty` is a function type.
    /// If `opt_sema` is not provided, asserts that the return type is sufficiently resolved.
    pub fn fn_has_runtime_bits_advanced(ty: Type, mod: *Module, opt_sema: ?*Sema) Module.CompileError!bool {
        const fn_info = mod.type_to_func(ty).?;
        if (fn_info.is_generic) return false;
        if (fn_info.is_var_args) return true;
        if (fn_info.cc == .Inline) return false;
        return !try Type.from_interned(fn_info.return_type).comptime_only_advanced(mod, opt_sema);
    }

    pub fn is_fn_or_has_runtime_bits(ty: Type, mod: *Module) bool {
        switch (ty.zig_type_tag(mod)) {
            .Fn => return ty.fn_has_runtime_bits(mod),
            else => return ty.has_runtime_bits(mod),
        }
    }

    /// Same as `is_fn_or_has_runtime_bits` but comptime-only types may return a false positive.
    pub fn is_fn_or_has_runtime_bits_ignore_comptime(ty: Type, mod: *Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Fn => true,
            else => return ty.has_runtime_bits_ignore_comptime(mod),
        };
    }

    pub fn is_no_return(ty: Type, mod: *Module) bool {
        return mod.intern_pool.is_no_return(ty.to_intern());
    }

    /// Returns `none` if the pointer is naturally aligned and the element type is 0-bit.
    pub fn ptr_alignment(ty: Type, mod: *Module) Alignment {
        return ptr_alignment_advanced(ty, mod, null) catch unreachable;
    }

    pub fn ptr_alignment_advanced(ty: Type, mod: *Module, opt_sema: ?*Sema) !Alignment {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| {
                if (ptr_type.flags.alignment != .none)
                    return ptr_type.flags.alignment;

                if (opt_sema) |sema| {
                    const res = try Type.from_interned(ptr_type.child).abi_alignment_advanced(mod, .{ .sema = sema });
                    return res.scalar;
                }

                return (Type.from_interned(ptr_type.child).abi_alignment_advanced(mod, .eager) catch unreachable).scalar;
            },
            .opt_type => |child| Type.from_interned(child).ptr_alignment_advanced(mod, opt_sema),
            else => unreachable,
        };
    }

    pub fn ptr_address_space(ty: Type, mod: *const Module) std.builtin.AddressSpace {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.address_space,
            .opt_type => |child| mod.intern_pool.index_to_key(child).ptr_type.flags.address_space,
            else => unreachable,
        };
    }

    /// Never returns `none`. Asserts that all necessary type resolution is already done.
    pub fn abi_alignment(ty: Type, mod: *Module) Alignment {
        return (ty.abi_alignment_advanced(mod, .eager) catch unreachable).scalar;
    }

    /// May capture a reference to `ty`.
    /// Returned value has type `comptime_int`.
    pub fn lazy_abi_alignment(ty: Type, mod: *Module) !Value {
        switch (try ty.abi_alignment_advanced(mod, .lazy)) {
            .val => |val| return val,
            .scalar => |x| return mod.int_value(Type.comptime_int, x.to_byte_units() orelse 0),
        }
    }

    pub const AbiAlignmentAdvanced = union(enum) {
        scalar: Alignment,
        val: Value,
    };

    pub const AbiAlignmentAdvancedStrat = union(enum) {
        eager,
        lazy,
        sema: *Sema,
    };

    /// If you pass `eager` you will get back `scalar` and assert the type is resolved.
    /// In this case there will be no error, guaranteed.
    /// If you pass `lazy` you may get back `scalar` or `val`.
    /// If `val` is returned, a reference to `ty` has been captured.
    /// If you pass `sema` you will get back `scalar` and resolve the type if
    /// necessary, possibly returning a CompileError.
    pub fn abi_alignment_advanced(
        ty: Type,
        mod: *Module,
        strat: AbiAlignmentAdvancedStrat,
    ) Module.CompileError!AbiAlignmentAdvanced {
        const target = mod.get_target();
        const use_llvm = mod.comp.config.use_llvm;
        const ip = &mod.intern_pool;

        const opt_sema = switch (strat) {
            .sema => |sema| sema,
            else => null,
        };

        switch (ty.to_intern()) {
            .empty_struct_type => return AbiAlignmentAdvanced{ .scalar = .@"1" },
            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => |int_type| {
                    if (int_type.bits == 0) return AbiAlignmentAdvanced{ .scalar = .@"1" };
                    return .{ .scalar = int_abi_alignment(int_type.bits, target, use_llvm) };
                },
                .ptr_type, .anyframe_type => {
                    return .{ .scalar = ptr_abi_alignment(target) };
                },
                .array_type => |array_type| {
                    return Type.from_interned(array_type.child).abi_alignment_advanced(mod, strat);
                },
                .vector_type => |vector_type| {
                    if (vector_type.len == 0) return .{ .scalar = .@"1" };
                    switch (mod.comp.get_zig_backend()) {
                        else => {
                            const elem_bits: u32 = @int_cast(try Type.from_interned(vector_type.child).bit_size_advanced(mod, opt_sema));
                            if (elem_bits == 0) return .{ .scalar = .@"1" };
                            const bytes = ((elem_bits * vector_type.len) + 7) / 8;
                            const alignment = std.math.ceil_power_of_two_assert(u32, bytes);
                            return .{ .scalar = Alignment.from_byte_units(alignment) };
                        },
                        .stage2_c => {
                            return Type.from_interned(vector_type.child).abi_alignment_advanced(mod, strat);
                        },
                        .stage2_x86_64 => {
                            if (vector_type.child == .bool_type) {
                                if (vector_type.len > 256 and std.Target.x86.feature_set_has(target.cpu.features, .avx512f)) return .{ .scalar = .@"64" };
                                if (vector_type.len > 128 and std.Target.x86.feature_set_has(target.cpu.features, .avx2)) return .{ .scalar = .@"32" };
                                if (vector_type.len > 64) return .{ .scalar = .@"16" };
                                const bytes = std.math.div_ceil(u32, vector_type.len, 8) catch unreachable;
                                const alignment = std.math.ceil_power_of_two_assert(u32, bytes);
                                return .{ .scalar = Alignment.from_byte_units(alignment) };
                            }
                            const elem_bytes: u32 = @int_cast((try Type.from_interned(vector_type.child).abi_size_advanced(mod, strat)).scalar);
                            if (elem_bytes == 0) return .{ .scalar = .@"1" };
                            const bytes = elem_bytes * vector_type.len;
                            if (bytes > 32 and std.Target.x86.feature_set_has(target.cpu.features, .avx512f)) return .{ .scalar = .@"64" };
                            if (bytes > 16 and std.Target.x86.feature_set_has(target.cpu.features, .avx)) return .{ .scalar = .@"32" };
                            return .{ .scalar = .@"16" };
                        },
                    }
                },

                .opt_type => return abi_alignment_advanced_optional(ty, mod, strat),
                .error_union_type => |info| return abi_alignment_advanced_error_union(ty, mod, strat, Type.from_interned(info.payload_type)),

                .error_set_type, .inferred_error_set_type => {
                    const bits = mod.error_set_bits();
                    if (bits == 0) return AbiAlignmentAdvanced{ .scalar = .@"1" };
                    return .{ .scalar = int_abi_alignment(bits, target, use_llvm) };
                },

                // represents machine code; not a pointer
                .func_type => return .{ .scalar = target_util.default_function_alignment(target) },

                .simple_type => |t| switch (t) {
                    .bool,
                    .atomic_order,
                    .atomic_rmw_op,
                    .calling_convention,
                    .address_space,
                    .float_mode,
                    .reduce_op,
                    .call_modifier,
                    .prefetch_options,
                    .anyopaque,
                    => return .{ .scalar = .@"1" },

                    .usize,
                    .isize,
                    => return .{ .scalar = int_abi_alignment(target.ptr_bit_width(), target, use_llvm) },

                    .export_options,
                    .extern_options,
                    .type_info,
                    => return .{ .scalar = ptr_abi_alignment(target) },

                    .c_char => return .{ .scalar = c_type_align(target, .char) },
                    .c_short => return .{ .scalar = c_type_align(target, .short) },
                    .c_ushort => return .{ .scalar = c_type_align(target, .ushort) },
                    .c_int => return .{ .scalar = c_type_align(target, .int) },
                    .c_uint => return .{ .scalar = c_type_align(target, .uint) },
                    .c_long => return .{ .scalar = c_type_align(target, .long) },
                    .c_ulong => return .{ .scalar = c_type_align(target, .ulong) },
                    .c_longlong => return .{ .scalar = c_type_align(target, .longlong) },
                    .c_ulonglong => return .{ .scalar = c_type_align(target, .ulonglong) },
                    .c_longdouble => return .{ .scalar = c_type_align(target, .longdouble) },

                    .f16 => return .{ .scalar = .@"2" },
                    .f32 => return .{ .scalar = c_type_align(target, .float) },
                    .f64 => switch (target.c_type_bit_size(.double)) {
                        64 => return .{ .scalar = c_type_align(target, .double) },
                        else => return .{ .scalar = .@"8" },
                    },
                    .f80 => switch (target.c_type_bit_size(.longdouble)) {
                        80 => return .{ .scalar = c_type_align(target, .longdouble) },
                        else => {
                            const u80_ty: Type = .{ .ip_index = .u80_type };
                            return .{ .scalar = abi_alignment(u80_ty, mod) };
                        },
                    },
                    .f128 => switch (target.c_type_bit_size(.longdouble)) {
                        128 => return .{ .scalar = c_type_align(target, .longdouble) },
                        else => return .{ .scalar = .@"16" },
                    },

                    .anyerror, .adhoc_inferred_error_set => {
                        const bits = mod.error_set_bits();
                        if (bits == 0) return AbiAlignmentAdvanced{ .scalar = .@"1" };
                        return .{ .scalar = int_abi_alignment(bits, target, use_llvm) };
                    },

                    .void,
                    .type,
                    .comptime_int,
                    .comptime_float,
                    .null,
                    .undefined,
                    .enum_literal,
                    => return .{ .scalar = .@"1" },

                    .noreturn => unreachable,
                    .generic_poison => unreachable,
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    if (struct_type.layout == .@"packed") {
                        switch (strat) {
                            .sema => |sema| try sema.resolve_type_layout(ty),
                            .lazy => if (struct_type.backing_int_type(ip).* == .none) return .{
                                .val = Value.from_interned((try mod.intern(.{ .int = .{
                                    .ty = .comptime_int_type,
                                    .storage = .{ .lazy_align = ty.to_intern() },
                                } }))),
                            },
                            .eager => {},
                        }
                        return .{ .scalar = Type.from_interned(struct_type.backing_int_type(ip).*).abi_alignment(mod) };
                    }

                    const flags = struct_type.flags_ptr(ip).*;
                    if (flags.alignment != .none) return .{ .scalar = flags.alignment };

                    return switch (strat) {
                        .eager => unreachable, // struct alignment not resolved
                        .sema => |sema| .{
                            .scalar = try sema.resolve_struct_alignment(ty.to_intern(), struct_type),
                        },
                        .lazy => .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                            .ty = .comptime_int_type,
                            .storage = .{ .lazy_align = ty.to_intern() },
                        } }))) },
                    };
                },
                .anon_struct_type => |tuple| {
                    var big_align: Alignment = .@"1";
                    for (tuple.types.get(ip), tuple.values.get(ip)) |field_ty, val| {
                        if (val != .none) continue; // comptime field
                        switch (try Type.from_interned(field_ty).abi_alignment_advanced(mod, strat)) {
                            .scalar => |field_align| big_align = big_align.max(field_align),
                            .val => switch (strat) {
                                .eager => unreachable, // field type alignment not resolved
                                .sema => unreachable, // passed to abi_alignment_advanced above
                                .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                                    .ty = .comptime_int_type,
                                    .storage = .{ .lazy_align = ty.to_intern() },
                                } }))) },
                            },
                        }
                    }
                    return .{ .scalar = big_align };
                },
                .union_type => {
                    const union_type = ip.load_union_type(ty.to_intern());
                    const flags = union_type.flags_ptr(ip).*;
                    if (flags.alignment != .none) return .{ .scalar = flags.alignment };

                    if (!union_type.have_layout(ip)) switch (strat) {
                        .eager => unreachable, // union layout not resolved
                        .sema => |sema| return .{ .scalar = try sema.resolve_union_alignment(ty, union_type) },
                        .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                            .ty = .comptime_int_type,
                            .storage = .{ .lazy_align = ty.to_intern() },
                        } }))) },
                    };

                    return .{ .scalar = union_type.flags_ptr(ip).alignment };
                },
                .opaque_type => return .{ .scalar = .@"1" },
                .enum_type => return .{
                    .scalar = Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty).abi_alignment(mod),
                },

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        }
    }

    fn abi_alignment_advanced_error_union(
        ty: Type,
        mod: *Module,
        strat: AbiAlignmentAdvancedStrat,
        payload_ty: Type,
    ) Module.CompileError!AbiAlignmentAdvanced {
        // This code needs to be kept in sync with the equivalent switch prong
        // in abi_size_advanced.
        const code_align = abi_alignment(Type.anyerror, mod);
        switch (strat) {
            .eager, .sema => {
                if (!(payload_ty.has_runtime_bits_advanced(mod, false, strat) catch |err| switch (err) {
                    error.NeedLazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                        .ty = .comptime_int_type,
                        .storage = .{ .lazy_align = ty.to_intern() },
                    } }))) },
                    else => |e| return e,
                })) {
                    return .{ .scalar = code_align };
                }
                return .{ .scalar = code_align.max(
                    (try payload_ty.abi_alignment_advanced(mod, strat)).scalar,
                ) };
            },
            .lazy => {
                switch (try payload_ty.abi_alignment_advanced(mod, strat)) {
                    .scalar => |payload_align| return .{ .scalar = code_align.max(payload_align) },
                    .val => {},
                }
                return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                    .ty = .comptime_int_type,
                    .storage = .{ .lazy_align = ty.to_intern() },
                } }))) };
            },
        }
    }

    fn abi_alignment_advanced_optional(
        ty: Type,
        mod: *Module,
        strat: AbiAlignmentAdvancedStrat,
    ) Module.CompileError!AbiAlignmentAdvanced {
        const target = mod.get_target();
        const child_type = ty.optional_child(mod);

        switch (child_type.zig_type_tag(mod)) {
            .Pointer => return .{ .scalar = ptr_abi_alignment(target) },
            .ErrorSet => return abi_alignment_advanced(Type.anyerror, mod, strat),
            .NoReturn => return .{ .scalar = .@"1" },
            else => {},
        }

        switch (strat) {
            .eager, .sema => {
                if (!(child_type.has_runtime_bits_advanced(mod, false, strat) catch |err| switch (err) {
                    error.NeedLazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                        .ty = .comptime_int_type,
                        .storage = .{ .lazy_align = ty.to_intern() },
                    } }))) },
                    else => |e| return e,
                })) {
                    return .{ .scalar = .@"1" };
                }
                return child_type.abi_alignment_advanced(mod, strat);
            },
            .lazy => switch (try child_type.abi_alignment_advanced(mod, strat)) {
                .scalar => |x| return .{ .scalar = x.max(.@"1") },
                .val => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                    .ty = .comptime_int_type,
                    .storage = .{ .lazy_align = ty.to_intern() },
                } }))) },
            },
        }
    }

    /// May capture a reference to `ty`.
    pub fn lazy_abi_size(ty: Type, mod: *Module) !Value {
        switch (try ty.abi_size_advanced(mod, .lazy)) {
            .val => |val| return val,
            .scalar => |x| return mod.int_value(Type.comptime_int, x),
        }
    }

    /// Asserts the type has the ABI size already resolved.
    /// Types that return false for has_runtime_bits() return 0.
    pub fn abi_size(ty: Type, mod: *Module) u64 {
        return (abi_size_advanced(ty, mod, .eager) catch unreachable).scalar;
    }

    const AbiSizeAdvanced = union(enum) {
        scalar: u64,
        val: Value,
    };

    /// If you pass `eager` you will get back `scalar` and assert the type is resolved.
    /// In this case there will be no error, guaranteed.
    /// If you pass `lazy` you may get back `scalar` or `val`.
    /// If `val` is returned, a reference to `ty` has been captured.
    /// If you pass `sema` you will get back `scalar` and resolve the type if
    /// necessary, possibly returning a CompileError.
    pub fn abi_size_advanced(
        ty: Type,
        mod: *Module,
        strat: AbiAlignmentAdvancedStrat,
    ) Module.CompileError!AbiSizeAdvanced {
        const target = mod.get_target();
        const use_llvm = mod.comp.config.use_llvm;
        const ip = &mod.intern_pool;

        switch (ty.to_intern()) {
            .empty_struct_type => return AbiSizeAdvanced{ .scalar = 0 },

            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => |int_type| {
                    if (int_type.bits == 0) return AbiSizeAdvanced{ .scalar = 0 };
                    return AbiSizeAdvanced{ .scalar = int_abi_size(int_type.bits, target, use_llvm) };
                },
                .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                    .Slice => return .{ .scalar = @div_exact(target.ptr_bit_width(), 8) * 2 },
                    else => return .{ .scalar = @div_exact(target.ptr_bit_width(), 8) },
                },
                .anyframe_type => return AbiSizeAdvanced{ .scalar = @div_exact(target.ptr_bit_width(), 8) },

                .array_type => |array_type| {
                    const len = array_type.len_including_sentinel();
                    if (len == 0) return .{ .scalar = 0 };
                    switch (try Type.from_interned(array_type.child).abi_size_advanced(mod, strat)) {
                        .scalar => |elem_size| return .{ .scalar = len * elem_size },
                        .val => switch (strat) {
                            .sema, .eager => unreachable,
                            .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                                .ty = .comptime_int_type,
                                .storage = .{ .lazy_size = ty.to_intern() },
                            } }))) },
                        },
                    }
                },
                .vector_type => |vector_type| {
                    const opt_sema = switch (strat) {
                        .sema => |sema| sema,
                        .eager => null,
                        .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                            .ty = .comptime_int_type,
                            .storage = .{ .lazy_size = ty.to_intern() },
                        } }))) },
                    };
                    const alignment = switch (try ty.abi_alignment_advanced(mod, strat)) {
                        .scalar => |x| x,
                        .val => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                            .ty = .comptime_int_type,
                            .storage = .{ .lazy_size = ty.to_intern() },
                        } }))) },
                    };
                    const total_bytes = switch (mod.comp.get_zig_backend()) {
                        else => total_bytes: {
                            const elem_bits = try Type.from_interned(vector_type.child).bit_size_advanced(mod, opt_sema);
                            const total_bits = elem_bits * vector_type.len;
                            break :total_bytes (total_bits + 7) / 8;
                        },
                        .stage2_c => total_bytes: {
                            const elem_bytes: u32 = @int_cast((try Type.from_interned(vector_type.child).abi_size_advanced(mod, strat)).scalar);
                            break :total_bytes elem_bytes * vector_type.len;
                        },
                        .stage2_x86_64 => total_bytes: {
                            if (vector_type.child == .bool_type) break :total_bytes std.math.div_ceil(u32, vector_type.len, 8) catch unreachable;
                            const elem_bytes: u32 = @int_cast((try Type.from_interned(vector_type.child).abi_size_advanced(mod, strat)).scalar);
                            break :total_bytes elem_bytes * vector_type.len;
                        },
                    };
                    return AbiSizeAdvanced{ .scalar = alignment.forward(total_bytes) };
                },

                .opt_type => return ty.abi_size_advanced_optional(mod, strat),

                .error_set_type, .inferred_error_set_type => {
                    const bits = mod.error_set_bits();
                    if (bits == 0) return AbiSizeAdvanced{ .scalar = 0 };
                    return AbiSizeAdvanced{ .scalar = int_abi_size(bits, target, use_llvm) };
                },

                .error_union_type => |error_union_type| {
                    const payload_ty = Type.from_interned(error_union_type.payload_type);
                    // This code needs to be kept in sync with the equivalent switch prong
                    // in abi_alignment_advanced.
                    const code_size = abi_size(Type.anyerror, mod);
                    if (!(payload_ty.has_runtime_bits_advanced(mod, false, strat) catch |err| switch (err) {
                        error.NeedLazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                            .ty = .comptime_int_type,
                            .storage = .{ .lazy_size = ty.to_intern() },
                        } }))) },
                        else => |e| return e,
                    })) {
                        // Same as anyerror.
                        return AbiSizeAdvanced{ .scalar = code_size };
                    }
                    const code_align = abi_alignment(Type.anyerror, mod);
                    const payload_align = abi_alignment(payload_ty, mod);
                    const payload_size = switch (try payload_ty.abi_size_advanced(mod, strat)) {
                        .scalar => |elem_size| elem_size,
                        .val => switch (strat) {
                            .sema => unreachable,
                            .eager => unreachable,
                            .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                                .ty = .comptime_int_type,
                                .storage = .{ .lazy_size = ty.to_intern() },
                            } }))) },
                        },
                    };

                    var size: u64 = 0;
                    if (code_align.compare(.gt, payload_align)) {
                        size += code_size;
                        size = payload_align.forward(size);
                        size += payload_size;
                        size = code_align.forward(size);
                    } else {
                        size += payload_size;
                        size = code_align.forward(size);
                        size += code_size;
                        size = payload_align.forward(size);
                    }
                    return AbiSizeAdvanced{ .scalar = size };
                },
                .func_type => unreachable, // represents machine code; not a pointer
                .simple_type => |t| switch (t) {
                    .bool,
                    .atomic_order,
                    .atomic_rmw_op,
                    .calling_convention,
                    .address_space,
                    .float_mode,
                    .reduce_op,
                    .call_modifier,
                    => return AbiSizeAdvanced{ .scalar = 1 },

                    .f16 => return AbiSizeAdvanced{ .scalar = 2 },
                    .f32 => return AbiSizeAdvanced{ .scalar = 4 },
                    .f64 => return AbiSizeAdvanced{ .scalar = 8 },
                    .f128 => return AbiSizeAdvanced{ .scalar = 16 },
                    .f80 => switch (target.c_type_bit_size(.longdouble)) {
                        80 => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.longdouble) },
                        else => {
                            const u80_ty: Type = .{ .ip_index = .u80_type };
                            return AbiSizeAdvanced{ .scalar = abi_size(u80_ty, mod) };
                        },
                    },

                    .usize,
                    .isize,
                    => return AbiSizeAdvanced{ .scalar = @div_exact(target.ptr_bit_width(), 8) },

                    .c_char => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.char) },
                    .c_short => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.short) },
                    .c_ushort => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.ushort) },
                    .c_int => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.int) },
                    .c_uint => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.uint) },
                    .c_long => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.long) },
                    .c_ulong => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.ulong) },
                    .c_longlong => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.longlong) },
                    .c_ulonglong => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.ulonglong) },
                    .c_longdouble => return AbiSizeAdvanced{ .scalar = target.c_type_byte_size(.longdouble) },

                    .anyopaque,
                    .void,
                    .type,
                    .comptime_int,
                    .comptime_float,
                    .null,
                    .undefined,
                    .enum_literal,
                    => return AbiSizeAdvanced{ .scalar = 0 },

                    .anyerror, .adhoc_inferred_error_set => {
                        const bits = mod.error_set_bits();
                        if (bits == 0) return AbiSizeAdvanced{ .scalar = 0 };
                        return AbiSizeAdvanced{ .scalar = int_abi_size(bits, target, use_llvm) };
                    },

                    .prefetch_options => unreachable, // missing call to resolve_type_fields
                    .export_options => unreachable, // missing call to resolve_type_fields
                    .extern_options => unreachable, // missing call to resolve_type_fields

                    .type_info => unreachable,
                    .noreturn => unreachable,
                    .generic_poison => unreachable,
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    switch (strat) {
                        .sema => |sema| try sema.resolve_type_layout(ty),
                        .lazy => switch (struct_type.layout) {
                            .@"packed" => {
                                if (struct_type.backing_int_type(ip).* == .none) return .{
                                    .val = Value.from_interned((try mod.intern(.{ .int = .{
                                        .ty = .comptime_int_type,
                                        .storage = .{ .lazy_size = ty.to_intern() },
                                    } }))),
                                };
                            },
                            .auto, .@"extern" => {
                                if (!struct_type.have_layout(ip)) return .{
                                    .val = Value.from_interned((try mod.intern(.{ .int = .{
                                        .ty = .comptime_int_type,
                                        .storage = .{ .lazy_size = ty.to_intern() },
                                    } }))),
                                };
                            },
                        },
                        .eager => {},
                    }
                    switch (struct_type.layout) {
                        .@"packed" => return .{
                            .scalar = Type.from_interned(struct_type.backing_int_type(ip).*).abi_size(mod),
                        },
                        .auto, .@"extern" => {
                            assert(struct_type.have_layout(ip));
                            return .{ .scalar = struct_type.size(ip).* };
                        },
                    }
                },
                .anon_struct_type => |tuple| {
                    switch (strat) {
                        .sema => |sema| try sema.resolve_type_layout(ty),
                        .lazy, .eager => {},
                    }
                    const field_count = tuple.types.len;
                    if (field_count == 0) {
                        return AbiSizeAdvanced{ .scalar = 0 };
                    }
                    return AbiSizeAdvanced{ .scalar = ty.struct_field_offset(field_count, mod) };
                },

                .union_type => {
                    const union_type = ip.load_union_type(ty.to_intern());
                    switch (strat) {
                        .sema => |sema| try sema.resolve_type_layout(ty),
                        .lazy => if (!union_type.flags_ptr(ip).status.have_layout()) return .{
                            .val = Value.from_interned((try mod.intern(.{ .int = .{
                                .ty = .comptime_int_type,
                                .storage = .{ .lazy_size = ty.to_intern() },
                            } }))),
                        },
                        .eager => {},
                    }

                    assert(union_type.have_layout(ip));
                    return .{ .scalar = union_type.size(ip).* };
                },
                .opaque_type => unreachable, // no size available
                .enum_type => return .{ .scalar = Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty).abi_size(mod) },

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        }
    }

    fn abi_size_advanced_optional(
        ty: Type,
        mod: *Module,
        strat: AbiAlignmentAdvancedStrat,
    ) Module.CompileError!AbiSizeAdvanced {
        const child_ty = ty.optional_child(mod);

        if (child_ty.is_no_return(mod)) {
            return AbiSizeAdvanced{ .scalar = 0 };
        }

        if (!(child_ty.has_runtime_bits_advanced(mod, false, strat) catch |err| switch (err) {
            error.NeedLazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                .ty = .comptime_int_type,
                .storage = .{ .lazy_size = ty.to_intern() },
            } }))) },
            else => |e| return e,
        })) return AbiSizeAdvanced{ .scalar = 1 };

        if (ty.optional_repr_is_payload(mod)) {
            return abi_size_advanced(child_ty, mod, strat);
        }

        const payload_size = switch (try child_ty.abi_size_advanced(mod, strat)) {
            .scalar => |elem_size| elem_size,
            .val => switch (strat) {
                .sema => unreachable,
                .eager => unreachable,
                .lazy => return .{ .val = Value.from_interned((try mod.intern(.{ .int = .{
                    .ty = .comptime_int_type,
                    .storage = .{ .lazy_size = ty.to_intern() },
                } }))) },
            },
        };

        // Optional types are represented as a struct with the child type as the first
        // field and a boolean as the second. Since the child type's abi alignment is
        // guaranteed to be >= that of bool's (1 byte) the added size is exactly equal
        // to the child type's ABI alignment.
        return AbiSizeAdvanced{
            .scalar = (child_ty.abi_alignment(mod).to_byte_units() orelse 0) + payload_size,
        };
    }

    pub fn ptr_abi_alignment(target: Target) Alignment {
        return Alignment.from_nonzero_byte_units(@div_exact(target.ptr_bit_width(), 8));
    }

    pub fn int_abi_size(bits: u16, target: Target, use_llvm: bool) u64 {
        return int_abi_alignment(bits, target, use_llvm).forward(@as(u16, @int_cast((@as(u17, bits) + 7) / 8)));
    }

    pub fn int_abi_alignment(bits: u16, target: Target, use_llvm: bool) Alignment {
        return switch (target.cpu.arch) {
            .x86 => switch (bits) {
                0 => .none,
                1...8 => .@"1",
                9...16 => .@"2",
                17...64 => .@"4",
                else => .@"16",
            },
            .x86_64 => switch (bits) {
                0 => .none,
                1...8 => .@"1",
                9...16 => .@"2",
                17...32 => .@"4",
                33...64 => .@"8",
                else => switch (target_util.zig_backend(target, use_llvm)) {
                    .stage2_x86_64 => .@"8",
                    else => .@"16",
                },
            },
            else => return Alignment.from_byte_units(@min(
                std.math.ceil_power_of_two_promote(u16, @as(u16, @int_cast((@as(u17, bits) + 7) / 8))),
                max_int_alignment(target, use_llvm),
            )),
        };
    }

    pub fn max_int_alignment(target: std.Target, use_llvm: bool) u16 {
        return switch (target.cpu.arch) {
            .avr => 1,
            .msp430 => 2,
            .xcore => 4,

            .arm,
            .armeb,
            .thumb,
            .thumbeb,
            .hexagon,
            .mips,
            .mipsel,
            .powerpc,
            .powerpcle,
            .r600,
            .amdgcn,
            .riscv32,
            .sparc,
            .sparcel,
            .s390x,
            .lanai,
            .wasm32,
            .wasm64,
            => 8,

            // For these, LLVMABIAlignmentOfType(i128) reports 8. Note that 16
            // is a relevant number in three cases:
            // 1. Different machine code instruction when loading into SIMD register.
            // 2. The C ABI wants 16 for extern structs.
            // 3. 16-byte cmpxchg needs 16-byte alignment.
            // Same logic for powerpc64, mips64, sparc64.
            .powerpc64,
            .powerpc64le,
            .mips64,
            .mips64el,
            .sparc64,
            => switch (target.ofmt) {
                .c => 16,
                else => 8,
            },

            .x86_64 => switch (target_util.zig_backend(target, use_llvm)) {
                .stage2_x86_64 => 8,
                else => 16,
            },

            // Even LLVMABIAlignmentOfType(i128) agrees on these targets.
            .x86,
            .aarch64,
            .aarch64_be,
            .aarch64_32,
            .riscv64,
            .bpfel,
            .bpfeb,
            .nvptx,
            .nvptx64,
            => 16,

            // Below this comment are unverified but based on the fact that C requires
            // int128_t to be 16 bytes aligned, it's a safe default.
            .spu_2,
            .csky,
            .arc,
            .m68k,
            .tce,
            .tcele,
            .le32,
            .amdil,
            .hsail,
            .spir,
            .kalimba,
            .renderscript32,
            .spirv,
            .spirv32,
            .shave,
            .le64,
            .amdil64,
            .hsail64,
            .spir64,
            .renderscript64,
            .ve,
            .spirv64,
            .dxil,
            .loongarch32,
            .loongarch64,
            .xtensa,
            => 16,
        };
    }

    pub fn bit_size(ty: Type, mod: *Module) u64 {
        return bit_size_advanced(ty, mod, null) catch unreachable;
    }

    /// If you pass `opt_sema`, any recursive type resolutions will happen if
    /// necessary, possibly returning a CompileError. Passing `null` instead asserts
    /// the type is fully resolved, and there will be no error, guaranteed.
    pub fn bit_size_advanced(
        ty: Type,
        mod: *Module,
        opt_sema: ?*Sema,
    ) Module.CompileError!u64 {
        const target = mod.get_target();
        const ip = &mod.intern_pool;

        const strat: AbiAlignmentAdvancedStrat = if (opt_sema) |sema| .{ .sema = sema } else .eager;

        switch (ip.index_to_key(ty.to_intern())) {
            .int_type => |int_type| return int_type.bits,
            .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                .Slice => return target.ptr_bit_width() * 2,
                else => return target.ptr_bit_width(),
            },
            .anyframe_type => return target.ptr_bit_width(),

            .array_type => |array_type| {
                const len = array_type.len_including_sentinel();
                if (len == 0) return 0;
                const elem_ty = Type.from_interned(array_type.child);
                const elem_size = @max(
                    (try elem_ty.abi_alignment_advanced(mod, strat)).scalar.to_byte_units() orelse 0,
                    (try elem_ty.abi_size_advanced(mod, strat)).scalar,
                );
                if (elem_size == 0) return 0;
                const elem_bit_size = try bit_size_advanced(elem_ty, mod, opt_sema);
                return (len - 1) * 8 * elem_size + elem_bit_size;
            },
            .vector_type => |vector_type| {
                const child_ty = Type.from_interned(vector_type.child);
                const elem_bit_size = try bit_size_advanced(child_ty, mod, opt_sema);
                return elem_bit_size * vector_type.len;
            },
            .opt_type => {
                // Optionals and error unions are not packed so their bitsize
                // includes padding bits.
                return (try abi_size_advanced(ty, mod, strat)).scalar * 8;
            },

            .error_set_type, .inferred_error_set_type => return mod.error_set_bits(),

            .error_union_type => {
                // Optionals and error unions are not packed so their bitsize
                // includes padding bits.
                return (try abi_size_advanced(ty, mod, strat)).scalar * 8;
            },
            .func_type => unreachable, // represents machine code; not a pointer
            .simple_type => |t| switch (t) {
                .f16 => return 16,
                .f32 => return 32,
                .f64 => return 64,
                .f80 => return 80,
                .f128 => return 128,

                .usize,
                .isize,
                => return target.ptr_bit_width(),

                .c_char => return target.c_type_bit_size(.char),
                .c_short => return target.c_type_bit_size(.short),
                .c_ushort => return target.c_type_bit_size(.ushort),
                .c_int => return target.c_type_bit_size(.int),
                .c_uint => return target.c_type_bit_size(.uint),
                .c_long => return target.c_type_bit_size(.long),
                .c_ulong => return target.c_type_bit_size(.ulong),
                .c_longlong => return target.c_type_bit_size(.longlong),
                .c_ulonglong => return target.c_type_bit_size(.ulonglong),
                .c_longdouble => return target.c_type_bit_size(.longdouble),

                .bool => return 1,
                .void => return 0,

                .anyerror,
                .adhoc_inferred_error_set,
                => return mod.error_set_bits(),

                .anyopaque => unreachable,
                .type => unreachable,
                .comptime_int => unreachable,
                .comptime_float => unreachable,
                .noreturn => unreachable,
                .null => unreachable,
                .undefined => unreachable,
                .enum_literal => unreachable,
                .generic_poison => unreachable,

                .atomic_order => unreachable,
                .atomic_rmw_op => unreachable,
                .calling_convention => unreachable,
                .address_space => unreachable,
                .float_mode => unreachable,
                .reduce_op => unreachable,
                .call_modifier => unreachable,
                .prefetch_options => unreachable,
                .export_options => unreachable,
                .extern_options => unreachable,
                .type_info => unreachable,
            },
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                const is_packed = struct_type.layout == .@"packed";
                if (opt_sema) |sema| {
                    try sema.resolve_type_fields(ty);
                    if (is_packed) try sema.resolve_type_layout(ty);
                }
                if (is_packed) {
                    return try Type.from_interned(struct_type.backing_int_type(ip).*).bit_size_advanced(mod, opt_sema);
                }
                return (try ty.abi_size_advanced(mod, strat)).scalar * 8;
            },

            .anon_struct_type => {
                if (opt_sema) |sema| try sema.resolve_type_fields(ty);
                return (try ty.abi_size_advanced(mod, strat)).scalar * 8;
            },

            .union_type => {
                const union_type = ip.load_union_type(ty.to_intern());
                const is_packed = ty.container_layout(mod) == .@"packed";
                if (opt_sema) |sema| {
                    try sema.resolve_type_fields(ty);
                    if (is_packed) try sema.resolve_type_layout(ty);
                }
                if (!is_packed) {
                    return (try ty.abi_size_advanced(mod, strat)).scalar * 8;
                }
                assert(union_type.flags_ptr(ip).status.have_field_types());

                var size: u64 = 0;
                for (0..union_type.field_types.len) |field_index| {
                    const field_ty = union_type.field_types.get(ip)[field_index];
                    size = @max(size, try bit_size_advanced(Type.from_interned(field_ty), mod, opt_sema));
                }

                return size;
            },
            .opaque_type => unreachable,
            .enum_type => return bit_size_advanced(Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty), mod, opt_sema),

            // values, not types
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
            // memoization, not types
            .memoized_call,
            => unreachable,
        }
    }

    /// Returns true if the type's layout is already resolved and it is safe
    /// to use `abi_size`, `abi_alignment` and `bit_size` on it.
    pub fn layout_is_resolved(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).have_layout(ip),
            .union_type => ip.load_union_type(ty.to_intern()).have_layout(ip),
            .array_type => |array_type| {
                if (array_type.len_including_sentinel() == 0) return true;
                return Type.from_interned(array_type.child).layout_is_resolved(mod);
            },
            .opt_type => |child| Type.from_interned(child).layout_is_resolved(mod),
            .error_union_type => |k| Type.from_interned(k.payload_type).layout_is_resolved(mod),
            else => true,
        };
    }

    pub fn is_single_pointer(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_info| ptr_info.flags.size == .One,
            else => false,
        };
    }

    /// Asserts `ty` is a pointer.
    pub fn ptr_size(ty: Type, mod: *const Module) std.builtin.Type.Pointer.Size {
        return ptr_size_or_null(ty, mod).?;
    }

    /// Returns `null` if `ty` is not a pointer.
    pub fn ptr_size_or_null(ty: Type, mod: *const Module) ?std.builtin.Type.Pointer.Size {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_info| ptr_info.flags.size,
            else => null,
        };
    }

    pub fn is_slice(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.size == .Slice,
            else => false,
        };
    }

    pub fn slice_ptr_field_type(ty: Type, mod: *const Module) Type {
        return Type.from_interned(mod.intern_pool.slice_ptr_type(ty.to_intern()));
    }

    pub fn is_const_ptr(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.is_const,
            else => false,
        };
    }

    pub fn is_volatile_ptr(ty: Type, mod: *const Module) bool {
        return is_volatile_ptr_ip(ty, &mod.intern_pool);
    }

    pub fn is_volatile_ptr_ip(ty: Type, ip: *const InternPool) bool {
        return switch (ip.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.is_volatile,
            else => false,
        };
    }

    pub fn is_allowzero_ptr(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.is_allowzero,
            .opt_type => true,
            else => false,
        };
    }

    pub fn is_cptr(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.size == .C,
            else => false,
        };
    }

    pub fn is_ptr_at_runtime(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                .Slice => false,
                .One, .Many, .C => true,
            },
            .opt_type => |child| switch (mod.intern_pool.index_to_key(child)) {
                .ptr_type => |p| switch (p.flags.size) {
                    .Slice, .C => false,
                    .Many, .One => !p.flags.is_allowzero,
                },
                else => false,
            },
            else => false,
        };
    }

    /// For pointer-like optionals, returns true, otherwise returns the allowzero property
    /// of pointers.
    pub fn ptr_allows_zero(ty: Type, mod: *const Module) bool {
        if (ty.is_ptr_like_optional(mod)) {
            return true;
        }
        return ty.ptr_info(mod).flags.is_allowzero;
    }

    /// See also `is_ptr_like_optional`.
    pub fn optional_repr_is_payload(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .opt_type => |child_type| child_type == .anyerror_type or switch (mod.intern_pool.index_to_key(child_type)) {
                .ptr_type => |ptr_type| ptr_type.flags.size != .C and !ptr_type.flags.is_allowzero,
                .error_set_type, .inferred_error_set_type => true,
                else => false,
            },
            .ptr_type => |ptr_type| ptr_type.flags.size == .C,
            else => false,
        };
    }

    /// Returns true if the type is optional and would be lowered to a single pointer
    /// address value, using 0 for null. Note that this returns true for C pointers.
    /// This function must be kept in sync with `Sema.type_ptr_or_optional_ptr_ty`.
    pub fn is_ptr_like_optional(ty: Type, mod: *const Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| ptr_type.flags.size == .C,
            .opt_type => |child| switch (mod.intern_pool.index_to_key(child)) {
                .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                    .Slice, .C => false,
                    .Many, .One => !ptr_type.flags.is_allowzero,
                },
                else => false,
            },
            else => false,
        };
    }

    /// For *[N]T,  returns [N]T.
    /// For *T,     returns T.
    /// For [*]T,   returns T.
    pub fn child_type(ty: Type, mod: *const Module) Type {
        return child_type_ip(ty, &mod.intern_pool);
    }

    pub fn child_type_ip(ty: Type, ip: *const InternPool) Type {
        return Type.from_interned(ip.child_type(ty.to_intern()));
    }

    /// For *[N]T,       returns T.
    /// For ?*T,         returns T.
    /// For ?*[N]T,      returns T.
    /// For ?[*]T,       returns T.
    /// For *T,          returns T.
    /// For [*]T,        returns T.
    /// For [N]T,        returns T.
    /// For []T,         returns T.
    /// For anyframe->T, returns T.
    pub fn elem_type2(ty: Type, mod: *const Module) Type {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .ptr_type => |ptr_type| switch (ptr_type.flags.size) {
                .One => Type.from_interned(ptr_type.child).shallow_elem_type(mod),
                .Many, .C, .Slice => Type.from_interned(ptr_type.child),
            },
            .anyframe_type => |child| {
                assert(child != .none);
                return Type.from_interned(child);
            },
            .vector_type => |vector_type| Type.from_interned(vector_type.child),
            .array_type => |array_type| Type.from_interned(array_type.child),
            .opt_type => |child| Type.from_interned(mod.intern_pool.child_type(child)),
            else => unreachable,
        };
    }

    fn shallow_elem_type(child_ty: Type, mod: *const Module) Type {
        return switch (child_ty.zig_type_tag(mod)) {
            .Array, .Vector => child_ty.child_type(mod),
            else => child_ty,
        };
    }

    /// For vectors, returns the element type. Otherwise returns self.
    pub fn scalar_type(ty: Type, mod: *Module) Type {
        return switch (ty.zig_type_tag(mod)) {
            .Vector => ty.child_type(mod),
            else => ty,
        };
    }

    /// Asserts that the type is an optional.
    /// Note that for C pointers this returns the type unmodified.
    pub fn optional_child(ty: Type, mod: *const Module) Type {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .opt_type => |child| Type.from_interned(child),
            .ptr_type => |ptr_type| b: {
                assert(ptr_type.flags.size == .C);
                break :b ty;
            },
            else => unreachable,
        };
    }

    /// Returns the tag type of a union, if the type is a union and it has a tag type.
    /// Otherwise, returns `null`.
    pub fn union_tag_type(ty: Type, mod: *Module) ?Type {
        const ip = &mod.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .union_type => {},
            else => return null,
        }
        const union_type = ip.load_union_type(ty.to_intern());
        switch (union_type.flags_ptr(ip).runtime_tag) {
            .tagged => {
                assert(union_type.flags_ptr(ip).status.have_field_types());
                return Type.from_interned(union_type.enum_tag_ty);
            },
            else => return null,
        }
    }

    /// Same as `union_tag_type` but includes safety tag.
    /// Codegen should use this version.
    pub fn union_tag_type_safety(ty: Type, mod: *Module) ?Type {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .union_type => {
                const union_type = ip.load_union_type(ty.to_intern());
                if (!union_type.has_tag(ip)) return null;
                assert(union_type.have_field_types(ip));
                return Type.from_interned(union_type.enum_tag_ty);
            },
            else => null,
        };
    }

    /// Asserts the type is a union; returns the tag type, even if the tag will
    /// not be stored at runtime.
    pub fn union_tag_type_hypothetical(ty: Type, mod: *Module) Type {
        const union_obj = mod.type_to_union(ty).?;
        return Type.from_interned(union_obj.enum_tag_ty);
    }

    pub fn union_field_type(ty: Type, enum_tag: Value, mod: *Module) ?Type {
        const ip = &mod.intern_pool;
        const union_obj = mod.type_to_union(ty).?;
        const union_fields = union_obj.field_types.get(ip);
        const index = mod.union_tag_field_index(union_obj, enum_tag) orelse return null;
        return Type.from_interned(union_fields[index]);
    }

    pub fn union_field_type_by_index(ty: Type, index: usize, mod: *Module) Type {
        const ip = &mod.intern_pool;
        const union_obj = mod.type_to_union(ty).?;
        return Type.from_interned(union_obj.field_types.get(ip)[index]);
    }

    pub fn union_tag_field_index(ty: Type, enum_tag: Value, mod: *Module) ?u32 {
        const union_obj = mod.type_to_union(ty).?;
        return mod.union_tag_field_index(union_obj, enum_tag);
    }

    pub fn union_has_all_zero_bit_field_types(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        const union_obj = mod.type_to_union(ty).?;
        for (union_obj.field_types.get(ip)) |field_ty| {
            if (Type.from_interned(field_ty).has_runtime_bits(mod)) return false;
        }
        return true;
    }

    /// Returns the type used for backing storage of this union during comptime operations.
    /// Asserts the type is either an extern or packed union.
    pub fn union_backing_type(ty: Type, mod: *Module) !Type {
        return switch (ty.container_layout(mod)) {
            .@"extern" => try mod.array_type(.{ .len = ty.abi_size(mod), .child = .u8_type }),
            .@"packed" => try mod.int_type(.unsigned, @int_cast(ty.bit_size(mod))),
            .auto => unreachable,
        };
    }

    pub fn union_get_layout(ty: Type, mod: *Module) Module.UnionLayout {
        const ip = &mod.intern_pool;
        const union_obj = ip.load_union_type(ty.to_intern());
        return mod.get_union_layout(union_obj);
    }

    pub fn container_layout(ty: Type, mod: *Module) std.builtin.Type.ContainerLayout {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).layout,
            .anon_struct_type => .auto,
            .union_type => ip.load_union_type(ty.to_intern()).flags_ptr(ip).layout,
            else => unreachable,
        };
    }

    /// Asserts that the type is an error union.
    pub fn error_union_payload(ty: Type, mod: *Module) Type {
        return Type.from_interned(mod.intern_pool.index_to_key(ty.to_intern()).error_union_type.payload_type);
    }

    /// Asserts that the type is an error union.
    pub fn error_union_set(ty: Type, mod: *Module) Type {
        return Type.from_interned(mod.intern_pool.error_union_set(ty.to_intern()));
    }

    /// Returns false for unresolved inferred error sets.
    pub fn error_set_is_empty(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ty.to_intern()) {
            .anyerror_type, .adhoc_inferred_error_set_type => false,
            else => switch (ip.index_to_key(ty.to_intern())) {
                .error_set_type => |error_set_type| error_set_type.names.len == 0,
                .inferred_error_set_type => |i| switch (ip.func_ies_resolved(i).*) {
                    .none, .anyerror_type => false,
                    else => |t| ip.index_to_key(t).error_set_type.names.len == 0,
                },
                else => unreachable,
            },
        };
    }

    /// Returns true if it is an error set that includes anyerror, false otherwise.
    /// Note that the result may be a false negative if the type did not get error set
    /// resolution prior to this call.
    pub fn is_any_error(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ty.to_intern()) {
            .anyerror_type => true,
            .adhoc_inferred_error_set_type => false,
            else => switch (mod.intern_pool.index_to_key(ty.to_intern())) {
                .inferred_error_set_type => |i| ip.func_ies_resolved(i).* == .anyerror_type,
                else => false,
            },
        };
    }

    pub fn is_error(ty: Type, mod: *const Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .ErrorUnion, .ErrorSet => true,
            else => false,
        };
    }

    /// Returns whether ty, which must be an error set, includes an error `name`.
    /// Might return a false negative if `ty` is an inferred error set and not fully
    /// resolved yet.
    pub fn error_set_has_field_ip(
        ip: *const InternPool,
        ty: InternPool.Index,
        name: InternPool.NullTerminatedString,
    ) bool {
        return switch (ty) {
            .anyerror_type => true,
            else => switch (ip.index_to_key(ty)) {
                .error_set_type => |error_set_type| error_set_type.name_index(ip, name) != null,
                .inferred_error_set_type => |i| switch (ip.func_ies_resolved(i).*) {
                    .anyerror_type => true,
                    .none => false,
                    else => |t| ip.index_to_key(t).error_set_type.name_index(ip, name) != null,
                },
                else => unreachable,
            },
        };
    }

    /// Returns whether ty, which must be an error set, includes an error `name`.
    /// Might return a false negative if `ty` is an inferred error set and not fully
    /// resolved yet.
    pub fn error_set_has_field(ty: Type, name: []const u8, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ty.to_intern()) {
            .anyerror_type => true,
            else => switch (ip.index_to_key(ty.to_intern())) {
                .error_set_type => |error_set_type| {
                    // If the string is not interned, then the field certainly is not present.
                    const field_name_interned = ip.get_string(name).unwrap() orelse return false;
                    return error_set_type.name_index(ip, field_name_interned) != null;
                },
                .inferred_error_set_type => |i| switch (ip.func_ies_resolved(i).*) {
                    .anyerror_type => true,
                    .none => false,
                    else => |t| {
                        // If the string is not interned, then the field certainly is not present.
                        const field_name_interned = ip.get_string(name).unwrap() orelse return false;
                        return ip.index_to_key(t).error_set_type.name_index(ip, field_name_interned) != null;
                    },
                },
                else => unreachable,
            },
        };
    }

    /// Asserts the type is an array or vector or struct.
    pub fn array_len(ty: Type, mod: *const Module) u64 {
        return ty.array_len_ip(&mod.intern_pool);
    }

    pub fn array_len_ip(ty: Type, ip: *const InternPool) u64 {
        return ip.aggregate_type_len(ty.to_intern());
    }

    pub fn array_len_including_sentinel(ty: Type, mod: *const Module) u64 {
        return mod.intern_pool.aggregate_type_len_including_sentinel(ty.to_intern());
    }

    pub fn vector_len(ty: Type, mod: *const Module) u32 {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .vector_type => |vector_type| vector_type.len,
            .anon_struct_type => |tuple| @int_cast(tuple.types.len),
            else => unreachable,
        };
    }

    /// Asserts the type is an array, pointer or vector.
    pub fn sentinel(ty: Type, mod: *const Module) ?Value {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .vector_type,
            .struct_type,
            .anon_struct_type,
            => null,

            .array_type => |t| if (t.sentinel != .none) Value.from_interned(t.sentinel) else null,
            .ptr_type => |t| if (t.sentinel != .none) Value.from_interned(t.sentinel) else null,

            else => unreachable,
        };
    }

    /// Returns true if and only if the type is a fixed-width integer.
    pub fn is_int(self: Type, mod: *const Module) bool {
        return self.to_intern() != .comptime_int_type and
            mod.intern_pool.is_integer_type(self.to_intern());
    }

    /// Returns true if and only if the type is a fixed-width, signed integer.
    pub fn is_signed_int(ty: Type, mod: *const Module) bool {
        return switch (ty.to_intern()) {
            .c_char_type => mod.get_target().char_signedness() == .signed,
            .isize_type, .c_short_type, .c_int_type, .c_long_type, .c_longlong_type => true,
            else => switch (mod.intern_pool.index_to_key(ty.to_intern())) {
                .int_type => |int_type| int_type.signedness == .signed,
                else => false,
            },
        };
    }

    /// Returns true if and only if the type is a fixed-width, unsigned integer.
    pub fn is_unsigned_int(ty: Type, mod: *const Module) bool {
        return switch (ty.to_intern()) {
            .c_char_type => mod.get_target().char_signedness() == .unsigned,
            .usize_type, .c_ushort_type, .c_uint_type, .c_ulong_type, .c_ulonglong_type => true,
            else => switch (mod.intern_pool.index_to_key(ty.to_intern())) {
                .int_type => |int_type| int_type.signedness == .unsigned,
                else => false,
            },
        };
    }

    /// Returns true for integers, enums, error sets, and packed structs.
    /// If this function returns true, then int_info() can be called on the type.
    pub fn is_abi_int(ty: Type, mod: *Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Int, .Enum, .ErrorSet => true,
            .Struct => ty.container_layout(mod) == .@"packed",
            else => false,
        };
    }

    /// Asserts the type is an integer, enum, error set, or vector of one of them.
    pub fn int_info(starting_ty: Type, mod: *Module) InternPool.Key.IntType {
        const ip = &mod.intern_pool;
        const target = mod.get_target();
        var ty = starting_ty;

        while (true) switch (ty.to_intern()) {
            .anyerror_type, .adhoc_inferred_error_set_type => {
                return .{ .signedness = .unsigned, .bits = mod.error_set_bits() };
            },
            .usize_type => return .{ .signedness = .unsigned, .bits = target.ptr_bit_width() },
            .isize_type => return .{ .signedness = .signed, .bits = target.ptr_bit_width() },
            .c_char_type => return .{ .signedness = mod.get_target().char_signedness(), .bits = target.c_type_bit_size(.char) },
            .c_short_type => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.short) },
            .c_ushort_type => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ushort) },
            .c_int_type => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.int) },
            .c_uint_type => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.uint) },
            .c_long_type => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.long) },
            .c_ulong_type => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ulong) },
            .c_longlong_type => return .{ .signedness = .signed, .bits = target.c_type_bit_size(.longlong) },
            .c_ulonglong_type => return .{ .signedness = .unsigned, .bits = target.c_type_bit_size(.ulonglong) },
            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => |int_type| return int_type,
                .struct_type => ty = Type.from_interned(ip.load_struct_type(ty.to_intern()).backing_int_type(ip).*),
                .enum_type => ty = Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty),
                .vector_type => |vector_type| ty = Type.from_interned(vector_type.child),

                .error_set_type, .inferred_error_set_type => {
                    return .{ .signedness = .unsigned, .bits = mod.error_set_bits() };
                },

                .anon_struct_type => unreachable,

                .ptr_type => unreachable,
                .anyframe_type => unreachable,
                .array_type => unreachable,

                .opt_type => unreachable,
                .error_union_type => unreachable,
                .func_type => unreachable,
                .simple_type => unreachable, // handled via Index enum tag above

                .union_type => unreachable,
                .opaque_type => unreachable,

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        };
    }

    pub fn is_named_int(ty: Type) bool {
        return switch (ty.to_intern()) {
            .usize_type,
            .isize_type,
            .c_char_type,
            .c_short_type,
            .c_ushort_type,
            .c_int_type,
            .c_uint_type,
            .c_long_type,
            .c_ulong_type,
            .c_longlong_type,
            .c_ulonglong_type,
            => true,

            else => false,
        };
    }

    /// Returns `false` for `comptime_float`.
    pub fn is_runtime_float(ty: Type) bool {
        return switch (ty.to_intern()) {
            .f16_type,
            .f32_type,
            .f64_type,
            .f80_type,
            .f128_type,
            .c_longdouble_type,
            => true,

            else => false,
        };
    }

    /// Returns `true` for `comptime_float`.
    pub fn is_any_float(ty: Type) bool {
        return switch (ty.to_intern()) {
            .f16_type,
            .f32_type,
            .f64_type,
            .f80_type,
            .f128_type,
            .c_longdouble_type,
            .comptime_float_type,
            => true,

            else => false,
        };
    }

    /// Asserts the type is a fixed-size float or comptime_float.
    /// Returns 128 for comptime_float types.
    pub fn float_bits(ty: Type, target: Target) u16 {
        return switch (ty.to_intern()) {
            .f16_type => 16,
            .f32_type => 32,
            .f64_type => 64,
            .f80_type => 80,
            .f128_type, .comptime_float_type => 128,
            .c_longdouble_type => target.c_type_bit_size(.longdouble),

            else => unreachable,
        };
    }

    /// Asserts the type is a function or a function pointer.
    pub fn fn_return_type(ty: Type, mod: *Module) Type {
        return Type.from_interned(mod.intern_pool.func_type_return_type(ty.to_intern()));
    }

    /// Asserts the type is a function.
    pub fn fn_calling_convention(ty: Type, mod: *Module) std.builtin.CallingConvention {
        return mod.intern_pool.index_to_key(ty.to_intern()).func_type.cc;
    }

    pub fn is_valid_param_type(self: Type, mod: *const Module) bool {
        return switch (self.zig_type_tag_or_poison(mod) catch return true) {
            .Opaque, .NoReturn => false,
            else => true,
        };
    }

    pub fn is_valid_return_type(self: Type, mod: *const Module) bool {
        return switch (self.zig_type_tag_or_poison(mod) catch return true) {
            .Opaque => false,
            else => true,
        };
    }

    /// Asserts the type is a function.
    pub fn fn_is_var_args(ty: Type, mod: *Module) bool {
        return mod.intern_pool.index_to_key(ty.to_intern()).func_type.is_var_args;
    }

    pub fn is_numeric(ty: Type, mod: *const Module) bool {
        return switch (ty.to_intern()) {
            .f16_type,
            .f32_type,
            .f64_type,
            .f80_type,
            .f128_type,
            .c_longdouble_type,
            .comptime_int_type,
            .comptime_float_type,
            .usize_type,
            .isize_type,
            .c_char_type,
            .c_short_type,
            .c_ushort_type,
            .c_int_type,
            .c_uint_type,
            .c_long_type,
            .c_ulong_type,
            .c_longlong_type,
            .c_ulonglong_type,
            => true,

            else => switch (mod.intern_pool.index_to_key(ty.to_intern())) {
                .int_type => true,
                else => false,
            },
        };
    }

    /// During semantic analysis, instead call `Sema.type_has_one_possible_value` which
    /// resolves field types rather than asserting they are already resolved.
    pub fn one_possible_value(starting_type: Type, mod: *Module) !?Value {
        var ty = starting_type;
        const ip = &mod.intern_pool;
        while (true) switch (ty.to_intern()) {
            .empty_struct_type => return Value.empty_struct,

            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => |int_type| {
                    if (int_type.bits == 0) {
                        return try mod.int_value(ty, 0);
                    } else {
                        return null;
                    }
                },

                .ptr_type,
                .error_union_type,
                .func_type,
                .anyframe_type,
                .error_set_type,
                .inferred_error_set_type,
                => return null,

                inline .array_type, .vector_type => |seq_type, seq_tag| {
                    const has_sentinel = seq_tag == .array_type and seq_type.sentinel != .none;
                    if (seq_type.len + @int_from_bool(has_sentinel) == 0) return Value.from_interned((try mod.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = &.{} },
                    } })));
                    if (try Type.from_interned(seq_type.child).one_possible_value(mod)) |opv| {
                        return Value.from_interned((try mod.intern(.{ .aggregate = .{
                            .ty = ty.to_intern(),
                            .storage = .{ .repeated_elem = opv.to_intern() },
                        } })));
                    }
                    return null;
                },
                .opt_type => |child| {
                    if (child == .noreturn_type) {
                        return try mod.null_value(ty);
                    } else {
                        return null;
                    }
                },

                .simple_type => |t| switch (t) {
                    .f16,
                    .f32,
                    .f64,
                    .f80,
                    .f128,
                    .usize,
                    .isize,
                    .c_char,
                    .c_short,
                    .c_ushort,
                    .c_int,
                    .c_uint,
                    .c_long,
                    .c_ulong,
                    .c_longlong,
                    .c_ulonglong,
                    .c_longdouble,
                    .anyopaque,
                    .bool,
                    .type,
                    .anyerror,
                    .comptime_int,
                    .comptime_float,
                    .enum_literal,
                    .atomic_order,
                    .atomic_rmw_op,
                    .calling_convention,
                    .address_space,
                    .float_mode,
                    .reduce_op,
                    .call_modifier,
                    .prefetch_options,
                    .export_options,
                    .extern_options,
                    .type_info,
                    .adhoc_inferred_error_set,
                    => return null,

                    .void => return Value.void,
                    .noreturn => return Value.@"unreachable",
                    .null => return Value.null,
                    .undefined => return Value.undef,

                    .generic_poison => unreachable,
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    assert(struct_type.have_field_types(ip));
                    if (struct_type.known_non_opv(ip))
                        return null;
                    const field_vals = try mod.gpa.alloc(InternPool.Index, struct_type.field_types.len);
                    defer mod.gpa.free(field_vals);
                    for (field_vals, 0..) |*field_val, i_usize| {
                        const i: u32 = @int_cast(i_usize);
                        if (struct_type.field_is_comptime(ip, i)) {
                            assert(struct_type.have_field_inits(ip));
                            field_val.* = struct_type.field_inits.get(ip)[i];
                            continue;
                        }
                        const field_ty = Type.from_interned(struct_type.field_types.get(ip)[i]);
                        if (try field_ty.one_possible_value(mod)) |field_opv| {
                            field_val.* = field_opv.to_intern();
                        } else return null;
                    }

                    // In this case the struct has no runtime-known fields and
                    // therefore has one possible value.
                    return Value.from_interned((try mod.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = field_vals },
                    } })));
                },

                .anon_struct_type => |tuple| {
                    for (tuple.values.get(ip)) |val| {
                        if (val == .none) return null;
                    }
                    // In this case the struct has all comptime-known fields and
                    // therefore has one possible value.
                    // TODO: write something like get_coerced_ints to avoid needing to dupe
                    const duped_values = try mod.gpa.dupe(InternPool.Index, tuple.values.get(ip));
                    defer mod.gpa.free(duped_values);
                    return Value.from_interned((try mod.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = duped_values },
                    } })));
                },

                .union_type => {
                    const union_obj = ip.load_union_type(ty.to_intern());
                    const tag_val = (try Type.from_interned(union_obj.enum_tag_ty).one_possible_value(mod)) orelse
                        return null;
                    if (union_obj.field_types.len == 0) {
                        const only = try mod.intern(.{ .empty_enum_value = ty.to_intern() });
                        return Value.from_interned(only);
                    }
                    const only_field_ty = union_obj.field_types.get(ip)[0];
                    const val_val = (try Type.from_interned(only_field_ty).one_possible_value(mod)) orelse
                        return null;
                    const only = try mod.intern(.{ .un = .{
                        .ty = ty.to_intern(),
                        .tag = tag_val.to_intern(),
                        .val = val_val.to_intern(),
                    } });
                    return Value.from_interned(only);
                },
                .opaque_type => return null,
                .enum_type => {
                    const enum_type = ip.load_enum_type(ty.to_intern());
                    switch (enum_type.tag_mode) {
                        .nonexhaustive => {
                            if (enum_type.tag_ty == .comptime_int_type) return null;

                            if (try Type.from_interned(enum_type.tag_ty).one_possible_value(mod)) |int_opv| {
                                const only = try mod.intern(.{ .enum_tag = .{
                                    .ty = ty.to_intern(),
                                    .int = int_opv.to_intern(),
                                } });
                                return Value.from_interned(only);
                            }

                            return null;
                        },
                        .auto, .explicit => {
                            if (Type.from_interned(enum_type.tag_ty).has_runtime_bits(mod)) return null;

                            switch (enum_type.names.len) {
                                0 => {
                                    const only = try mod.intern(.{ .empty_enum_value = ty.to_intern() });
                                    return Value.from_interned(only);
                                },
                                1 => {
                                    if (enum_type.values.len == 0) {
                                        const only = try mod.intern(.{ .enum_tag = .{
                                            .ty = ty.to_intern(),
                                            .int = try mod.intern(.{ .int = .{
                                                .ty = enum_type.tag_ty,
                                                .storage = .{ .u64 = 0 },
                                            } }),
                                        } });
                                        return Value.from_interned(only);
                                    } else {
                                        return Value.from_interned(enum_type.values.get(ip)[0]);
                                    }
                                },
                                else => return null,
                            }
                        },
                    }
                },

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        };
    }

    /// During semantic analysis, instead call `Sema.type_requires_comptime` which
    /// resolves field types rather than asserting they are already resolved.
    pub fn comptime_only(ty: Type, mod: *Module) bool {
        return ty.comptime_only_advanced(mod, null) catch unreachable;
    }

    /// `generic_poison` will return false.
    /// May return false negatives when structs and unions are having their field types resolved.
    /// If `opt_sema` is not provided, asserts that the type is sufficiently resolved.
    pub fn comptime_only_advanced(ty: Type, mod: *Module, opt_sema: ?*Sema) Module.CompileError!bool {
        const ip = &mod.intern_pool;
        return switch (ty.to_intern()) {
            .empty_struct_type => false,

            else => switch (ip.index_to_key(ty.to_intern())) {
                .int_type => false,
                .ptr_type => |ptr_type| {
                    const child_ty = Type.from_interned(ptr_type.child);
                    switch (child_ty.zig_type_tag(mod)) {
                        .Fn => return !try child_ty.fn_has_runtime_bits_advanced(mod, opt_sema),
                        .Opaque => return false,
                        else => return child_ty.comptime_only_advanced(mod, opt_sema),
                    }
                },
                .anyframe_type => |child| {
                    if (child == .none) return false;
                    return Type.from_interned(child).comptime_only_advanced(mod, opt_sema);
                },
                .array_type => |array_type| return Type.from_interned(array_type.child).comptime_only_advanced(mod, opt_sema),
                .vector_type => |vector_type| return Type.from_interned(vector_type.child).comptime_only_advanced(mod, opt_sema),
                .opt_type => |child| return Type.from_interned(child).comptime_only_advanced(mod, opt_sema),
                .error_union_type => |error_union_type| return Type.from_interned(error_union_type.payload_type).comptime_only_advanced(mod, opt_sema),

                .error_set_type,
                .inferred_error_set_type,
                => false,

                // These are function bodies, not function pointers.
                .func_type => true,

                .simple_type => |t| switch (t) {
                    .f16,
                    .f32,
                    .f64,
                    .f80,
                    .f128,
                    .usize,
                    .isize,
                    .c_char,
                    .c_short,
                    .c_ushort,
                    .c_int,
                    .c_uint,
                    .c_long,
                    .c_ulong,
                    .c_longlong,
                    .c_ulonglong,
                    .c_longdouble,
                    .anyopaque,
                    .bool,
                    .void,
                    .anyerror,
                    .adhoc_inferred_error_set,
                    .noreturn,
                    .generic_poison,
                    .atomic_order,
                    .atomic_rmw_op,
                    .calling_convention,
                    .address_space,
                    .float_mode,
                    .reduce_op,
                    .call_modifier,
                    .prefetch_options,
                    .export_options,
                    .extern_options,
                    => false,

                    .type,
                    .comptime_int,
                    .comptime_float,
                    .null,
                    .undefined,
                    .enum_literal,
                    .type_info,
                    => true,
                },
                .struct_type => {
                    const struct_type = ip.load_struct_type(ty.to_intern());
                    // packed structs cannot be comptime-only because they have a well-defined
                    // memory layout and every field has a well-defined bit pattern.
                    if (struct_type.layout == .@"packed")
                        return false;

                    // A struct with no fields is not comptime-only.
                    return switch (struct_type.flags_ptr(ip).requires_comptime) {
                        .no, .wip => false,
                        .yes => true,
                        .unknown => {
                            // The type is not resolved; assert that we have a Sema.
                            const sema = opt_sema.?;

                            if (struct_type.flags_ptr(ip).field_types_wip)
                                return false;

                            struct_type.flags_ptr(ip).requires_comptime = .wip;
                            errdefer struct_type.flags_ptr(ip).requires_comptime = .unknown;

                            try sema.resolve_type_fields_struct(ty.to_intern(), struct_type);

                            for (0..struct_type.field_types.len) |i_usize| {
                                const i: u32 = @int_cast(i_usize);
                                if (struct_type.field_is_comptime(ip, i)) continue;
                                const field_ty = struct_type.field_types.get(ip)[i];
                                if (try Type.from_interned(field_ty).comptime_only_advanced(mod, opt_sema)) {
                                    // Note that this does not cause the layout to
                                    // be considered resolved. Comptime-only types
                                    // still maintain a layout of their
                                    // runtime-known fields.
                                    struct_type.flags_ptr(ip).requires_comptime = .yes;
                                    return true;
                                }
                            }

                            struct_type.flags_ptr(ip).requires_comptime = .no;
                            return false;
                        },
                    };
                },

                .anon_struct_type => |tuple| {
                    for (tuple.types.get(ip), tuple.values.get(ip)) |field_ty, val| {
                        const have_comptime_val = val != .none;
                        if (!have_comptime_val and try Type.from_interned(field_ty).comptime_only_advanced(mod, opt_sema)) return true;
                    }
                    return false;
                },

                .union_type => {
                    const union_type = ip.load_union_type(ty.to_intern());
                    switch (union_type.flags_ptr(ip).requires_comptime) {
                        .no, .wip => return false,
                        .yes => return true,
                        .unknown => {
                            // The type is not resolved; assert that we have a Sema.
                            const sema = opt_sema.?;

                            if (union_type.flags_ptr(ip).status == .field_types_wip)
                                return false;

                            union_type.flags_ptr(ip).requires_comptime = .wip;
                            errdefer union_type.flags_ptr(ip).requires_comptime = .unknown;

                            try sema.resolve_type_fields_union(ty, union_type);

                            for (0..union_type.field_types.len) |field_idx| {
                                const field_ty = union_type.field_types.get(ip)[field_idx];
                                if (try Type.from_interned(field_ty).comptime_only_advanced(mod, opt_sema)) {
                                    union_type.flags_ptr(ip).requires_comptime = .yes;
                                    return true;
                                }
                            }

                            union_type.flags_ptr(ip).requires_comptime = .no;
                            return false;
                        },
                    }
                },

                .opaque_type => false,

                .enum_type => return Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty).comptime_only_advanced(mod, opt_sema),

                // values, not types
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
                // memoization, not types
                .memoized_call,
                => unreachable,
            },
        };
    }

    pub fn is_vector(ty: Type, mod: *const Module) bool {
        return ty.zig_type_tag(mod) == .Vector;
    }

    /// Returns 0 if not a vector, otherwise returns @bitSizeOf(Element) * vector_len.
    pub fn total_vector_bits(ty: Type, zcu: *Zcu) u64 {
        if (!ty.is_vector(zcu)) return 0;
        const v = zcu.intern_pool.index_to_key(ty.to_intern()).vector_type;
        return v.len * Type.from_interned(v.child).bit_size(zcu);
    }

    pub fn is_array_or_vector(ty: Type, mod: *const Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Array, .Vector => true,
            else => false,
        };
    }

    pub fn is_indexable(ty: Type, mod: *Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Array, .Vector => true,
            .Pointer => switch (ty.ptr_size(mod)) {
                .Slice, .Many, .C => true,
                .One => switch (ty.child_type(mod).zig_type_tag(mod)) {
                    .Array, .Vector => true,
                    .Struct => ty.child_type(mod).is_tuple(mod),
                    else => false,
                },
            },
            .Struct => ty.is_tuple(mod),
            else => false,
        };
    }

    pub fn indexable_has_len(ty: Type, mod: *Module) bool {
        return switch (ty.zig_type_tag(mod)) {
            .Array, .Vector => true,
            .Pointer => switch (ty.ptr_size(mod)) {
                .Many, .C => false,
                .Slice => true,
                .One => switch (ty.child_type(mod).zig_type_tag(mod)) {
                    .Array, .Vector => true,
                    .Struct => ty.child_type(mod).is_tuple(mod),
                    else => false,
                },
            },
            .Struct => ty.is_tuple(mod),
            else => false,
        };
    }

    /// Asserts that the type can have a namespace.
    pub fn get_namespace_index(ty: Type, zcu: *Zcu) InternPool.OptionalNamespaceIndex {
        return ty.get_namespace(zcu).?;
    }

    /// Returns null if the type has no namespace.
    pub fn get_namespace(ty: Type, zcu: *Zcu) ?InternPool.OptionalNamespaceIndex {
        const ip = &zcu.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .opaque_type => ip.load_opaque_type(ty.to_intern()).namespace,
            .struct_type => ip.load_struct_type(ty.to_intern()).namespace,
            .union_type => ip.load_union_type(ty.to_intern()).namespace,
            .enum_type => ip.load_enum_type(ty.to_intern()).namespace,

            .anon_struct_type => .none,
            .simple_type => |s| switch (s) {
                .anyopaque,
                .atomic_order,
                .atomic_rmw_op,
                .calling_convention,
                .address_space,
                .float_mode,
                .reduce_op,
                .call_modifier,
                .prefetch_options,
                .export_options,
                .extern_options,
                .type_info,
                => .none,
                else => null,
            },

            else => null,
        };
    }

    // Works for vectors and vectors of integers.
    pub fn min_int(ty: Type, mod: *Module, dest_ty: Type) !Value {
        const scalar = try min_int_scalar(ty.scalar_type(mod), mod, dest_ty.scalar_type(mod));
        return if (ty.zig_type_tag(mod) == .Vector) Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = dest_ty.to_intern(),
            .storage = .{ .repeated_elem = scalar.to_intern() },
        } }))) else scalar;
    }

    /// Asserts that the type is an integer.
    pub fn min_int_scalar(ty: Type, mod: *Module, dest_ty: Type) !Value {
        const info = ty.int_info(mod);
        if (info.signedness == .unsigned) return mod.int_value(dest_ty, 0);
        if (info.bits == 0) return mod.int_value(dest_ty, -1);

        if (std.math.cast(u6, info.bits - 1)) |shift| {
            const n = @as(i64, std.math.min_int(i64)) >> (63 - shift);
            return mod.int_value(dest_ty, n);
        }

        var res = try std.math.big.int.Managed.init(mod.gpa);
        defer res.deinit();

        try res.set_twos_comp_int_limit(.min, info.signedness, info.bits);

        return mod.int_value_big(dest_ty, res.to_const());
    }

    // Works for vectors and vectors of integers.
    /// The returned Value will have type dest_ty.
    pub fn max_int(ty: Type, mod: *Module, dest_ty: Type) !Value {
        const scalar = try max_int_scalar(ty.scalar_type(mod), mod, dest_ty.scalar_type(mod));
        return if (ty.zig_type_tag(mod) == .Vector) Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = dest_ty.to_intern(),
            .storage = .{ .repeated_elem = scalar.to_intern() },
        } }))) else scalar;
    }

    /// The returned Value will have type dest_ty.
    pub fn max_int_scalar(ty: Type, mod: *Module, dest_ty: Type) !Value {
        const info = ty.int_info(mod);

        switch (info.bits) {
            0 => return switch (info.signedness) {
                .signed => try mod.int_value(dest_ty, -1),
                .unsigned => try mod.int_value(dest_ty, 0),
            },
            1 => return switch (info.signedness) {
                .signed => try mod.int_value(dest_ty, 0),
                .unsigned => try mod.int_value(dest_ty, 1),
            },
            else => {},
        }

        if (std.math.cast(u6, info.bits - 1)) |shift| switch (info.signedness) {
            .signed => {
                const n = @as(i64, std.math.max_int(i64)) >> (63 - shift);
                return mod.int_value(dest_ty, n);
            },
            .unsigned => {
                const n = @as(u64, std.math.max_int(u64)) >> (63 - shift);
                return mod.int_value(dest_ty, n);
            },
        };

        var res = try std.math.big.int.Managed.init(mod.gpa);
        defer res.deinit();

        try res.set_twos_comp_int_limit(.max, info.signedness, info.bits);

        return mod.int_value_big(dest_ty, res.to_const());
    }

    /// Asserts the type is an enum or a union.
    pub fn int_tag_type(ty: Type, mod: *Module) Type {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .union_type => Type.from_interned(ip.load_union_type(ty.to_intern()).enum_tag_ty).int_tag_type(mod),
            .enum_type => Type.from_interned(ip.load_enum_type(ty.to_intern()).tag_ty),
            else => unreachable,
        };
    }

    pub fn is_nonexhaustive_enum(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .enum_type => switch (ip.load_enum_type(ty.to_intern()).tag_mode) {
                .nonexhaustive => true,
                .auto, .explicit => false,
            },
            else => false,
        };
    }

    // Asserts that `ty` is an error set and not `anyerror`.
    // Asserts that `ty` is resolved if it is an inferred error set.
    pub fn error_set_names(ty: Type, mod: *Module) InternPool.NullTerminatedString.Slice {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .error_set_type => |x| x.names,
            .inferred_error_set_type => |i| switch (ip.func_ies_resolved(i).*) {
                .none => unreachable, // unresolved inferred error set
                .anyerror_type => unreachable,
                else => |t| ip.index_to_key(t).error_set_type.names,
            },
            else => unreachable,
        };
    }

    pub fn enum_fields(ty: Type, mod: *Module) InternPool.NullTerminatedString.Slice {
        return mod.intern_pool.load_enum_type(ty.to_intern()).names;
    }

    pub fn enum_field_count(ty: Type, mod: *Module) usize {
        return mod.intern_pool.load_enum_type(ty.to_intern()).names.len;
    }

    pub fn enum_field_name(ty: Type, field_index: usize, mod: *Module) InternPool.NullTerminatedString {
        const ip = &mod.intern_pool;
        return ip.load_enum_type(ty.to_intern()).names.get(ip)[field_index];
    }

    pub fn enum_field_index(ty: Type, field_name: InternPool.NullTerminatedString, mod: *Module) ?u32 {
        const ip = &mod.intern_pool;
        const enum_type = ip.load_enum_type(ty.to_intern());
        return enum_type.name_index(ip, field_name);
    }

    /// Asserts `ty` is an enum. `enum_tag` can either be `enum_field_index` or
    /// an integer which represents the enum value. Returns the field index in
    /// declaration order, or `null` if `enum_tag` does not match any field.
    pub fn enum_tag_field_index(ty: Type, enum_tag: Value, mod: *Module) ?u32 {
        const ip = &mod.intern_pool;
        const enum_type = ip.load_enum_type(ty.to_intern());
        const int_tag = switch (ip.index_to_key(enum_tag.to_intern())) {
            .int => enum_tag.to_intern(),
            .enum_tag => |info| info.int,
            else => unreachable,
        };
        assert(ip.type_of(int_tag) == enum_type.tag_ty);
        return enum_type.tag_value_index(ip, int_tag);
    }

    /// Returns none in the case of a tuple which uses the integer index as the field name.
    pub fn struct_field_name(ty: Type, index: usize, mod: *Module) InternPool.OptionalNullTerminatedString {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).field_name(ip, index),
            .anon_struct_type => |anon_struct| anon_struct.field_name(ip, index),
            else => unreachable,
        };
    }

    pub fn struct_field_count(ty: Type, mod: *Module) u32 {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).field_types.len,
            .anon_struct_type => |anon_struct| anon_struct.types.len,
            else => unreachable,
        };
    }

    /// Supports structs and unions.
    pub fn struct_field_type(ty: Type, index: usize, mod: *Module) Type {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => Type.from_interned(ip.load_struct_type(ty.to_intern()).field_types.get(ip)[index]),
            .union_type => {
                const union_obj = ip.load_union_type(ty.to_intern());
                return Type.from_interned(union_obj.field_types.get(ip)[index]);
            },
            .anon_struct_type => |anon_struct| Type.from_interned(anon_struct.types.get(ip)[index]),
            else => unreachable,
        };
    }

    pub fn struct_field_align(ty: Type, index: usize, zcu: *Zcu) Alignment {
        return ty.struct_field_align_advanced(index, zcu, null) catch unreachable;
    }

    pub fn struct_field_align_advanced(ty: Type, index: usize, zcu: *Zcu, opt_sema: ?*Sema) !Alignment {
        const ip = &zcu.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                assert(struct_type.layout != .@"packed");
                const explicit_align = struct_type.field_align(ip, index);
                const field_ty = Type.from_interned(struct_type.field_types.get(ip)[index]);
                if (opt_sema) |sema| {
                    return sema.struct_field_alignment(explicit_align, field_ty, struct_type.layout);
                } else {
                    return zcu.struct_field_alignment(explicit_align, field_ty, struct_type.layout);
                }
            },
            .anon_struct_type => |anon_struct| {
                return (try Type.from_interned(anon_struct.types.get(ip)[index]).abi_alignment_advanced(zcu, if (opt_sema) |sema| .{ .sema = sema } else .eager)).scalar;
            },
            .union_type => {
                const union_obj = ip.load_union_type(ty.to_intern());
                if (opt_sema) |sema| {
                    return sema.union_field_alignment(union_obj, @int_cast(index));
                } else {
                    return zcu.union_field_normal_alignment(union_obj, @int_cast(index));
                }
            },
            else => unreachable,
        }
    }

    pub fn struct_field_default_value(ty: Type, index: usize, mod: *Module) Value {
        const ip = &mod.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                const val = struct_type.field_init(ip, index);
                // TODO: avoid using `unreachable` to indicate this.
                if (val == .none) return Value.@"unreachable";
                return Value.from_interned(val);
            },
            .anon_struct_type => |anon_struct| {
                const val = anon_struct.values.get(ip)[index];
                // TODO: avoid using `unreachable` to indicate this.
                if (val == .none) return Value.@"unreachable";
                return Value.from_interned(val);
            },
            else => unreachable,
        }
    }

    pub fn struct_field_value_comptime(ty: Type, mod: *Module, index: usize) !?Value {
        const ip = &mod.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                if (struct_type.field_is_comptime(ip, index)) {
                    assert(struct_type.have_field_inits(ip));
                    return Value.from_interned(struct_type.field_inits.get(ip)[index]);
                } else {
                    return Type.from_interned(struct_type.field_types.get(ip)[index]).one_possible_value(mod);
                }
            },
            .anon_struct_type => |tuple| {
                const val = tuple.values.get(ip)[index];
                if (val == .none) {
                    return Type.from_interned(tuple.types.get(ip)[index]).one_possible_value(mod);
                } else {
                    return Value.from_interned(val);
                }
            },
            else => unreachable,
        }
    }

    pub fn struct_field_is_comptime(ty: Type, index: usize, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).field_is_comptime(ip, index),
            .anon_struct_type => |anon_struct| anon_struct.values.get(ip)[index] != .none,
            else => unreachable,
        };
    }

    pub const FieldOffset = struct {
        field: usize,
        offset: u64,
    };

    /// Supports structs and unions.
    pub fn struct_field_offset(ty: Type, index: usize, mod: *Module) u64 {
        const ip = &mod.intern_pool;
        switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                assert(struct_type.have_layout(ip));
                assert(struct_type.layout != .@"packed");
                return struct_type.offsets.get(ip)[index];
            },

            .anon_struct_type => |tuple| {
                var offset: u64 = 0;
                var big_align: Alignment = .none;

                for (tuple.types.get(ip), tuple.values.get(ip), 0..) |field_ty, field_val, i| {
                    if (field_val != .none or !Type.from_interned(field_ty).has_runtime_bits(mod)) {
                        // comptime field
                        if (i == index) return offset;
                        continue;
                    }

                    const field_align = Type.from_interned(field_ty).abi_alignment(mod);
                    big_align = big_align.max(field_align);
                    offset = field_align.forward(offset);
                    if (i == index) return offset;
                    offset += Type.from_interned(field_ty).abi_size(mod);
                }
                offset = big_align.max(.@"1").forward(offset);
                return offset;
            },

            .union_type => {
                const union_type = ip.load_union_type(ty.to_intern());
                if (!union_type.has_tag(ip))
                    return 0;
                const layout = mod.get_union_layout(union_type);
                if (layout.tag_align.compare(.gte, layout.payload_align)) {
                    // {Tag, Payload}
                    return layout.payload_align.forward(layout.tag_size);
                } else {
                    // {Payload, Tag}
                    return 0;
                }
            },

            else => unreachable,
        }
    }

    pub fn decl_src_loc(ty: Type, mod: *Module) Module.SrcLoc {
        return decl_src_loc_or_null(ty, mod).?;
    }

    pub fn decl_src_loc_or_null(ty: Type, mod: *Module) ?Module.SrcLoc {
        const decl = ty.get_owner_decl_or_null(mod) orelse return null;
        return mod.decl_ptr(decl).src_loc(mod);
    }

    pub fn get_owner_decl(ty: Type, mod: *Module) InternPool.DeclIndex {
        return ty.get_owner_decl_or_null(mod) orelse unreachable;
    }

    pub fn get_owner_decl_or_null(ty: Type, mod: *Module) ?InternPool.DeclIndex {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).decl.unwrap(),
            .union_type => ip.load_union_type(ty.to_intern()).decl,
            .opaque_type => ip.load_opaque_type(ty.to_intern()).decl,
            .enum_type => ip.load_enum_type(ty.to_intern()).decl,
            else => null,
        };
    }

    pub fn is_generic_poison(ty: Type) bool {
        return ty.to_intern() == .generic_poison_type;
    }

    pub fn is_tuple(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                if (struct_type.layout == .@"packed") return false;
                if (struct_type.decl == .none) return false;
                return struct_type.flags_ptr(ip).is_tuple;
            },
            .anon_struct_type => |anon_struct| anon_struct.names.len == 0,
            else => false,
        };
    }

    pub fn is_anon_struct(ty: Type, mod: *Module) bool {
        if (ty.to_intern() == .empty_struct_type) return true;
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .anon_struct_type => |anon_struct_type| anon_struct_type.names.len > 0,
            else => false,
        };
    }

    pub fn is_tuple_or_anon_struct(ty: Type, mod: *Module) bool {
        const ip = &mod.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                if (struct_type.layout == .@"packed") return false;
                if (struct_type.decl == .none) return false;
                return struct_type.flags_ptr(ip).is_tuple;
            },
            .anon_struct_type => true,
            else => false,
        };
    }

    pub fn is_simple_tuple(ty: Type, mod: *Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .anon_struct_type => |anon_struct_type| anon_struct_type.names.len == 0,
            else => false,
        };
    }

    pub fn is_simple_tuple_or_anon_struct(ty: Type, mod: *Module) bool {
        return switch (mod.intern_pool.index_to_key(ty.to_intern())) {
            .anon_struct_type => true,
            else => false,
        };
    }

    /// Traverses optional child types and error union payloads until the type
    /// is not a pointer. For `E!?u32`, returns `u32`; for `*u8`, returns `*u8`.
    pub fn opt_eu_base_type(ty: Type, mod: *Module) Type {
        var cur = ty;
        while (true) switch (cur.zig_type_tag(mod)) {
            .Optional => cur = cur.optional_child(mod),
            .ErrorUnion => cur = cur.error_union_payload(mod),
            else => return cur,
        };
    }

    pub fn to_unsigned(ty: Type, mod: *Module) !Type {
        return switch (ty.zig_type_tag(mod)) {
            .Int => mod.int_type(.unsigned, ty.int_info(mod).bits),
            .Vector => try mod.vector_type(.{
                .len = ty.vector_len(mod),
                .child = (try ty.child_type(mod).to_unsigned(mod)).to_intern(),
            }),
            else => unreachable,
        };
    }

    pub fn type_decl_inst(ty: Type, zcu: *const Zcu) ?InternPool.TrackedInst.Index {
        const ip = &zcu.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).zir_index.unwrap(),
            .union_type => ip.load_union_type(ty.to_intern()).zir_index,
            .enum_type => ip.load_enum_type(ty.to_intern()).zir_index.unwrap(),
            .opaque_type => ip.load_opaque_type(ty.to_intern()).zir_index,
            else => null,
        };
    }

    /// Given a namespace type, returns its list of caotured values.
    pub fn get_captures(ty: Type, zcu: *const Zcu) InternPool.CaptureValue.Slice {
        const ip = &zcu.intern_pool;
        return switch (ip.index_to_key(ty.to_intern())) {
            .struct_type => ip.load_struct_type(ty.to_intern()).captures,
            .union_type => ip.load_union_type(ty.to_intern()).captures,
            .enum_type => ip.load_enum_type(ty.to_intern()).captures,
            .opaque_type => ip.load_opaque_type(ty.to_intern()).captures,
            else => unreachable,
        };
    }

    pub fn array_base(ty: Type, zcu: *const Zcu) struct { Type, u64 } {
        var cur_ty: Type = ty;
        var cur_len: u64 = 1;
        while (cur_ty.zig_type_tag(zcu) == .Array) {
            cur_len *= cur_ty.array_len_including_sentinel(zcu);
            cur_ty = cur_ty.child_type(zcu);
        }
        return .{ cur_ty, cur_len };
    }

    pub fn packed_struct_field_ptr_info(struct_ty: Type, parent_ptr_ty: Type, field_idx: u32, zcu: *Zcu) union(enum) {
        /// The result is a bit-pointer with the same value and a new packed offset.
        bit_ptr: InternPool.Key.PtrType.PackedOffset,
        /// The result is a standard pointer.
        byte_ptr: struct {
            /// The byte offset of the field pointer from the parent pointer value.
            offset: u64,
            /// The alignment of the field pointer type.
            alignment: InternPool.Alignment,
        },
    } {
        comptime assert(Type.packed_struct_layout_version == 2);

        const parent_ptr_info = parent_ptr_ty.ptr_info(zcu);
        const field_ty = struct_ty.struct_field_type(field_idx, zcu);

        var bit_offset: u16 = 0;
        var running_bits: u16 = 0;
        for (0..struct_ty.struct_field_count(zcu)) |i| {
            const f_ty = struct_ty.struct_field_type(i, zcu);
            if (i == field_idx) {
                bit_offset = running_bits;
            }
            running_bits += @int_cast(f_ty.bit_size(zcu));
        }

        const res_host_size: u16, const res_bit_offset: u16 = if (parent_ptr_info.packed_offset.host_size != 0)
            .{ parent_ptr_info.packed_offset.host_size, parent_ptr_info.packed_offset.bit_offset + bit_offset }
        else
            .{ (running_bits + 7) / 8, bit_offset };

        // If the field happens to be byte-aligned, simplify the pointer type.
        // We can only do this if the pointee's bit size matches its ABI byte size,
        // so that loads and stores do not interfere with surrounding packed bits.
        //
        // TODO: we do not attempt this with big-endian targets yet because of nested
        // structs and floats. I need to double-check the desired behavior for big endian
        // targets before adding the necessary complications to this code. This will not
        // cause miscompilations; it only means the field pointer uses bit masking when it
        // might not be strictly necessary.
        if (res_bit_offset % 8 == 0 and field_ty.bit_size(zcu) == field_ty.abi_size(zcu) * 8 and zcu.get_target().cpu.arch.endian() == .little) {
            const byte_offset = res_bit_offset / 8;
            const new_align = Alignment.from_log2_units(@ctz(byte_offset | parent_ptr_ty.ptr_alignment(zcu).to_byte_units().?));
            return .{ .byte_ptr = .{
                .offset = byte_offset,
                .alignment = new_align,
            } };
        }

        return .{ .bit_ptr = .{
            .host_size = res_host_size,
            .bit_offset = res_bit_offset,
        } };
    }

    pub const @"u1": Type = .{ .ip_index = .u1_type };
    pub const @"u8": Type = .{ .ip_index = .u8_type };
    pub const @"u16": Type = .{ .ip_index = .u16_type };
    pub const @"u29": Type = .{ .ip_index = .u29_type };
    pub const @"u32": Type = .{ .ip_index = .u32_type };
    pub const @"u64": Type = .{ .ip_index = .u64_type };
    pub const @"u128": Type = .{ .ip_index = .u128_type };

    pub const @"i8": Type = .{ .ip_index = .i8_type };
    pub const @"i16": Type = .{ .ip_index = .i16_type };
    pub const @"i32": Type = .{ .ip_index = .i32_type };
    pub const @"i64": Type = .{ .ip_index = .i64_type };
    pub const @"i128": Type = .{ .ip_index = .i128_type };

    pub const @"f16": Type = .{ .ip_index = .f16_type };
    pub const @"f32": Type = .{ .ip_index = .f32_type };
    pub const @"f64": Type = .{ .ip_index = .f64_type };
    pub const @"f80": Type = .{ .ip_index = .f80_type };
    pub const @"f128": Type = .{ .ip_index = .f128_type };

    pub const @"bool": Type = .{ .ip_index = .bool_type };
    pub const @"usize": Type = .{ .ip_index = .usize_type };
    pub const @"isize": Type = .{ .ip_index = .isize_type };
    pub const @"comptime_int": Type = .{ .ip_index = .comptime_int_type };
    pub const @"comptime_float": Type = .{ .ip_index = .comptime_float_type };
    pub const @"void": Type = .{ .ip_index = .void_type };
    pub const @"type": Type = .{ .ip_index = .type_type };
    pub const @"anyerror": Type = .{ .ip_index = .anyerror_type };
    pub const @"anyopaque": Type = .{ .ip_index = .anyopaque_type };
    pub const @"anyframe": Type = .{ .ip_index = .anyframe_type };
    pub const @"null": Type = .{ .ip_index = .null_type };
    pub const @"undefined": Type = .{ .ip_index = .undefined_type };
    pub const @"noreturn": Type = .{ .ip_index = .noreturn_type };

    pub const @"c_char": Type = .{ .ip_index = .c_char_type };
    pub const @"c_short": Type = .{ .ip_index = .c_short_type };
    pub const @"c_ushort": Type = .{ .ip_index = .c_ushort_type };
    pub const @"c_int": Type = .{ .ip_index = .c_int_type };
    pub const @"c_uint": Type = .{ .ip_index = .c_uint_type };
    pub const @"c_long": Type = .{ .ip_index = .c_long_type };
    pub const @"c_ulong": Type = .{ .ip_index = .c_ulong_type };
    pub const @"c_longlong": Type = .{ .ip_index = .c_longlong_type };
    pub const @"c_ulonglong": Type = .{ .ip_index = .c_ulonglong_type };
    pub const @"c_longdouble": Type = .{ .ip_index = .c_longdouble_type };

    pub const slice_const_u8: Type = .{ .ip_index = .slice_const_u8_type };
    pub const manyptr_u8: Type = .{ .ip_index = .manyptr_u8_type };
    pub const single_const_pointer_to_comptime_int: Type = .{
        .ip_index = .single_const_pointer_to_comptime_int_type,
    };
    pub const slice_const_u8_sentinel_0: Type = .{ .ip_index = .slice_const_u8_sentinel_0_type };
    pub const empty_struct_literal: Type = .{ .ip_index = .empty_struct_type };

    pub const generic_poison: Type = .{ .ip_index = .generic_poison_type };

    pub fn smallest_unsigned_bits(max: u64) u16 {
        if (max == 0) return 0;
        const base = std.math.log2(max);
        const upper = (@as(u64, 1) << @as(u6, @int_cast(base))) - 1;
        return @as(u16, @int_cast(base + @int_from_bool(upper < max)));
    }

    /// This is only used for comptime asserts. Bump this number when you make a change
    /// to packed struct layout to find out all the places in the codebase you need to edit!
    pub const packed_struct_layout_version = 2;
};

fn c_type_align(target: Target, c_type: Target.CType) Alignment {
    return Alignment.from_byte_units(target.c_type_alignment(c_type));
}
