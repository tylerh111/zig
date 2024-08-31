const std = @import("std");
const builtin = @import("builtin");
const Type = @import("type.zig").Type;
const assert = std.debug.assert;
const BigIntConst = std.math.big.int.Const;
const BigIntMutable = std.math.big.int.Mutable;
const Target = std.Target;
const Allocator = std.mem.Allocator;
const Zcu = @import("Module.zig");
const Module = Zcu;
const Sema = @import("Sema.zig");
const InternPool = @import("InternPool.zig");
const print_value = @import("print_value.zig");
const Value = @This();

ip_index: InternPool.Index,

pub fn format(val: Value, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
    _ = val;
    _ = fmt;
    _ = options;
    _ = writer;
    @compile_error("do not use format values directly; use either fmt_debug or fmt_value");
}

/// This is a debug function. In order to print values in a meaningful way
/// we also need access to the type.
pub fn dump(
    start_val: Value,
    comptime fmt: []const u8,
    _: std.fmt.FormatOptions,
    out_stream: anytype,
) !void {
    comptime assert(fmt.len == 0);
    try out_stream.print("(interned: {})", .{start_val.to_intern()});
}

pub fn fmt_debug(val: Value) std.fmt.Formatter(dump) {
    return .{ .data = val };
}

pub fn fmt_value(val: Value, mod: *Module, opt_sema: ?*Sema) std.fmt.Formatter(print_value.format) {
    return .{ .data = .{
        .val = val,
        .mod = mod,
        .opt_sema = opt_sema,
        .depth = 3,
    } };
}

pub fn fmt_value_full(ctx: print_value.FormatContext) std.fmt.Formatter(print_value.format) {
    return .{ .data = ctx };
}

/// Converts `val` to a null-terminated string stored in the InternPool.
/// Asserts `val` is an array of `u8`
pub fn to_ip_string(val: Value, ty: Type, mod: *Module) !InternPool.NullTerminatedString {
    assert(ty.zig_type_tag(mod) == .Array);
    assert(ty.child_type(mod).to_intern() == .u8_type);
    const ip = &mod.intern_pool;
    switch (mod.intern_pool.index_to_key(val.to_intern()).aggregate.storage) {
        .bytes => |bytes| return bytes.to_null_terminated_string(ty.array_len(mod), ip),
        .elems => return array_to_ip_string(val, ty.array_len(mod), mod),
        .repeated_elem => |elem| {
            const byte: u8 = @int_cast(Value.from_interned(elem).to_unsigned_int(mod));
            const len: usize = @int_cast(ty.array_len(mod));
            try ip.string_bytes.append_ntimes(mod.gpa, byte, len);
            return ip.get_or_put_trailing_string(mod.gpa, len, .no_embedded_nulls);
        },
    }
}

/// Asserts that the value is representable as an array of bytes.
/// Copies the value into a freshly allocated slice of memory, which is owned by the caller.
pub fn to_allocated_bytes(val: Value, ty: Type, allocator: Allocator, mod: *Module) ![]u8 {
    const ip = &mod.intern_pool;
    return switch (ip.index_to_key(val.to_intern())) {
        .enum_literal => |enum_literal| allocator.dupe(u8, enum_literal.to_slice(ip)),
        .slice => |slice| try array_to_allocated_bytes(val, Value.from_interned(slice.len).to_unsigned_int(mod), allocator, mod),
        .aggregate => |aggregate| switch (aggregate.storage) {
            .bytes => |bytes| try allocator.dupe(u8, bytes.to_slice(ty.array_len_including_sentinel(mod), ip)),
            .elems => try array_to_allocated_bytes(val, ty.array_len(mod), allocator, mod),
            .repeated_elem => |elem| {
                const byte: u8 = @int_cast(Value.from_interned(elem).to_unsigned_int(mod));
                const result = try allocator.alloc(u8, @int_cast(ty.array_len(mod)));
                @memset(result, byte);
                return result;
            },
        },
        else => unreachable,
    };
}

fn array_to_allocated_bytes(val: Value, len: u64, allocator: Allocator, mod: *Module) ![]u8 {
    const result = try allocator.alloc(u8, @int_cast(len));
    for (result, 0..) |*elem, i| {
        const elem_val = try val.elem_value(mod, i);
        elem.* = @int_cast(elem_val.to_unsigned_int(mod));
    }
    return result;
}

fn array_to_ip_string(val: Value, len_u64: u64, mod: *Module) !InternPool.NullTerminatedString {
    const gpa = mod.gpa;
    const ip = &mod.intern_pool;
    const len: usize = @int_cast(len_u64);
    try ip.string_bytes.ensure_unused_capacity(gpa, len);
    for (0..len) |i| {
        // I don't think elem_value has the possibility to affect ip.string_bytes. Let's
        // assert just to be sure.
        const prev = ip.string_bytes.items.len;
        const elem_val = try val.elem_value(mod, i);
        assert(ip.string_bytes.items.len == prev);
        const byte: u8 = @int_cast(elem_val.to_unsigned_int(mod));
        ip.string_bytes.append_assume_capacity(byte);
    }
    return ip.get_or_put_trailing_string(gpa, len, .no_embedded_nulls);
}

pub fn from_interned(i: InternPool.Index) Value {
    assert(i != .none);
    return .{ .ip_index = i };
}

pub fn to_intern(val: Value) InternPool.Index {
    assert(val.ip_index != .none);
    return val.ip_index;
}

/// Asserts that the value is representable as a type.
pub fn to_type(self: Value) Type {
    return Type.from_interned(self.to_intern());
}

pub fn int_from_enum(val: Value, ty: Type, mod: *Module) Allocator.Error!Value {
    const ip = &mod.intern_pool;
    const enum_ty = ip.type_of(val.to_intern());
    return switch (ip.index_to_key(enum_ty)) {
        // Assume it is already an integer and return it directly.
        .simple_type, .int_type => val,
        .enum_literal => |enum_literal| {
            const field_index = ty.enum_field_index(enum_literal, mod).?;
            switch (ip.index_to_key(ty.to_intern())) {
                // Assume it is already an integer and return it directly.
                .simple_type, .int_type => return val,
                .enum_type => {
                    const enum_type = ip.load_enum_type(ty.to_intern());
                    if (enum_type.values.len != 0) {
                        return Value.from_interned(enum_type.values.get(ip)[field_index]);
                    } else {
                        // Field index and integer values are the same.
                        return mod.int_value(Type.from_interned(enum_type.tag_ty), field_index);
                    }
                },
                else => unreachable,
            }
        },
        .enum_type => try mod.get_coerced(val, Type.from_interned(ip.load_enum_type(enum_ty).tag_ty)),
        else => unreachable,
    };
}

/// Asserts the value is an integer.
pub fn to_big_int(val: Value, space: *BigIntSpace, mod: *Module) BigIntConst {
    return val.to_big_int_advanced(space, mod, null) catch unreachable;
}

/// Asserts the value is an integer.
pub fn to_big_int_advanced(
    val: Value,
    space: *BigIntSpace,
    mod: *Module,
    opt_sema: ?*Sema,
) Module.CompileError!BigIntConst {
    return switch (val.to_intern()) {
        .bool_false => BigIntMutable.init(&space.limbs, 0).to_const(),
        .bool_true => BigIntMutable.init(&space.limbs, 1).to_const(),
        .null_value => BigIntMutable.init(&space.limbs, 0).to_const(),
        else => switch (mod.intern_pool.index_to_key(val.to_intern())) {
            .int => |int| switch (int.storage) {
                .u64, .i64, .big_int => int.storage.to_big_int(space),
                .lazy_align, .lazy_size => |ty| {
                    if (opt_sema) |sema| try sema.resolve_type_layout(Type.from_interned(ty));
                    const x = switch (int.storage) {
                        else => unreachable,
                        .lazy_align => Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0,
                        .lazy_size => Type.from_interned(ty).abi_size(mod),
                    };
                    return BigIntMutable.init(&space.limbs, x).to_const();
                },
            },
            .enum_tag => |enum_tag| Value.from_interned(enum_tag.int).to_big_int_advanced(space, mod, opt_sema),
            .opt, .ptr => BigIntMutable.init(
                &space.limbs,
                (try val.get_unsigned_int_advanced(mod, opt_sema)).?,
            ).to_const(),
            else => unreachable,
        },
    };
}

pub fn is_func_body(val: Value, mod: *Module) bool {
    return mod.intern_pool.is_func_body(val.to_intern());
}

pub fn get_function(val: Value, mod: *Module) ?InternPool.Key.Func {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .func => |x| x,
        else => null,
    };
}

pub fn get_extern_func(val: Value, mod: *Module) ?InternPool.Key.ExternFunc {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .extern_func => |extern_func| extern_func,
        else => null,
    };
}

pub fn get_variable(val: Value, mod: *Module) ?InternPool.Key.Variable {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .variable => |variable| variable,
        else => null,
    };
}

/// If the value fits in a u64, return it, otherwise null.
/// Asserts not undefined.
pub fn get_unsigned_int(val: Value, mod: *Module) ?u64 {
    return get_unsigned_int_advanced(val, mod, null) catch unreachable;
}

/// If the value fits in a u64, return it, otherwise null.
/// Asserts not undefined.
pub fn get_unsigned_int_advanced(val: Value, mod: *Module, opt_sema: ?*Sema) !?u64 {
    return switch (val.to_intern()) {
        .undef => unreachable,
        .bool_false => 0,
        .bool_true => 1,
        else => switch (mod.intern_pool.index_to_key(val.to_intern())) {
            .undef => unreachable,
            .int => |int| switch (int.storage) {
                .big_int => |big_int| big_int.to(u64) catch null,
                .u64 => |x| x,
                .i64 => |x| std.math.cast(u64, x),
                .lazy_align => |ty| if (opt_sema) |sema|
                    (try Type.from_interned(ty).abi_alignment_advanced(mod, .{ .sema = sema })).scalar.to_byte_units() orelse 0
                else
                    Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0,
                .lazy_size => |ty| if (opt_sema) |sema|
                    (try Type.from_interned(ty).abi_size_advanced(mod, .{ .sema = sema })).scalar
                else
                    Type.from_interned(ty).abi_size(mod),
            },
            .ptr => |ptr| switch (ptr.base_addr) {
                .int => ptr.byte_offset,
                .field => |field| {
                    const base_addr = (try Value.from_interned(field.base).get_unsigned_int_advanced(mod, opt_sema)) orelse return null;
                    const struct_ty = Value.from_interned(field.base).type_of(mod).child_type(mod);
                    if (opt_sema) |sema| try sema.resolve_type_layout(struct_ty);
                    return base_addr + struct_ty.struct_field_offset(@int_cast(field.index), mod) + ptr.byte_offset;
                },
                else => null,
            },
            .opt => |opt| switch (opt.val) {
                .none => 0,
                else => |payload| Value.from_interned(payload).get_unsigned_int_advanced(mod, opt_sema),
            },
            else => null,
        },
    };
}

/// Asserts the value is an integer and it fits in a u64
pub fn to_unsigned_int(val: Value, mod: *Module) u64 {
    return get_unsigned_int(val, mod).?;
}

/// Asserts the value is an integer and it fits in a u64
pub fn to_unsigned_int_advanced(val: Value, sema: *Sema) !u64 {
    return (try get_unsigned_int_advanced(val, sema.mod, sema)).?;
}

/// Asserts the value is an integer and it fits in a i64
pub fn to_signed_int(val: Value, mod: *Module) i64 {
    return switch (val.to_intern()) {
        .bool_false => 0,
        .bool_true => 1,
        else => switch (mod.intern_pool.index_to_key(val.to_intern())) {
            .int => |int| switch (int.storage) {
                .big_int => |big_int| big_int.to(i64) catch unreachable,
                .i64 => |x| x,
                .u64 => |x| @int_cast(x),
                .lazy_align => |ty| @int_cast(Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0),
                .lazy_size => |ty| @int_cast(Type.from_interned(ty).abi_size(mod)),
            },
            else => unreachable,
        },
    };
}

pub fn to_bool(val: Value) bool {
    return switch (val.to_intern()) {
        .bool_true => true,
        .bool_false => false,
        else => unreachable,
    };
}

fn ptr_has_int_addr(val: Value, mod: *Module) bool {
    var check = val;
    while (true) switch (mod.intern_pool.index_to_key(check.to_intern())) {
        .ptr => |ptr| switch (ptr.base_addr) {
            .decl, .comptime_alloc, .comptime_field, .anon_decl => return false,
            .int => return true,
            .eu_payload, .opt_payload => |base| check = Value.from_interned(base),
            .arr_elem, .field => |base_index| check = Value.from_interned(base_index.base),
        },
        else => unreachable,
    };
}

/// Write a Value's contents to `buffer`.
///
/// Asserts that buffer.len >= ty.abi_size(). The buffer is allowed to extend past
/// the end of the value in memory.
pub fn write_to_memory(val: Value, ty: Type, mod: *Module, buffer: []u8) error{
    ReinterpretDeclRef,
    IllDefinedMemoryLayout,
    Unimplemented,
    OutOfMemory,
}!void {
    const target = mod.get_target();
    const endian = target.cpu.arch.endian();
    if (val.is_undef(mod)) {
        const size: usize = @int_cast(ty.abi_size(mod));
        @memset(buffer[0..size], 0xaa);
        return;
    }
    const ip = &mod.intern_pool;
    switch (ty.zig_type_tag(mod)) {
        .Void => {},
        .Bool => {
            buffer[0] = @int_from_bool(val.to_bool());
        },
        .Int, .Enum => {
            const int_info = ty.int_info(mod);
            const bits = int_info.bits;
            const byte_count: u16 = @int_cast((@as(u17, bits) + 7) / 8);

            var bigint_buffer: BigIntSpace = undefined;
            const bigint = val.to_big_int(&bigint_buffer, mod);
            bigint.write_twos_complement(buffer[0..byte_count], endian);
        },
        .Float => switch (ty.float_bits(target)) {
            16 => std.mem.write_int(u16, buffer[0..2], @bit_cast(val.to_float(f16, mod)), endian),
            32 => std.mem.write_int(u32, buffer[0..4], @bit_cast(val.to_float(f32, mod)), endian),
            64 => std.mem.write_int(u64, buffer[0..8], @bit_cast(val.to_float(f64, mod)), endian),
            80 => std.mem.write_int(u80, buffer[0..10], @bit_cast(val.to_float(f80, mod)), endian),
            128 => std.mem.write_int(u128, buffer[0..16], @bit_cast(val.to_float(f128, mod)), endian),
            else => unreachable,
        },
        .Array => {
            const len = ty.array_len(mod);
            const elem_ty = ty.child_type(mod);
            const elem_size: usize = @int_cast(elem_ty.abi_size(mod));
            var elem_i: usize = 0;
            var buf_off: usize = 0;
            while (elem_i < len) : (elem_i += 1) {
                const elem_val = try val.elem_value(mod, elem_i);
                try elem_val.write_to_memory(elem_ty, mod, buffer[buf_off..]);
                buf_off += elem_size;
            }
        },
        .Vector => {
            // We use byte_count instead of abi_size here, so that any padding bytes
            // follow the data bytes, on both big- and little-endian systems.
            const byte_count = (@as(usize, @int_cast(ty.bit_size(mod))) + 7) / 8;
            return write_to_packed_memory(val, ty, mod, buffer[0..byte_count], 0);
        },
        .Struct => {
            const struct_type = mod.type_to_struct(ty) orelse return error.IllDefinedMemoryLayout;
            switch (struct_type.layout) {
                .auto => return error.IllDefinedMemoryLayout,
                .@"extern" => for (0..struct_type.field_types.len) |field_index| {
                    const off: usize = @int_cast(ty.struct_field_offset(field_index, mod));
                    const field_val = Value.from_interned(switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                        .bytes => |bytes| {
                            buffer[off] = bytes.at(field_index, ip);
                            continue;
                        },
                        .elems => |elems| elems[field_index],
                        .repeated_elem => |elem| elem,
                    });
                    const field_ty = Type.from_interned(struct_type.field_types.get(ip)[field_index]);
                    try write_to_memory(field_val, field_ty, mod, buffer[off..]);
                },
                .@"packed" => {
                    const byte_count = (@as(usize, @int_cast(ty.bit_size(mod))) + 7) / 8;
                    return write_to_packed_memory(val, ty, mod, buffer[0..byte_count], 0);
                },
            }
        },
        .ErrorSet => {
            const bits = mod.error_set_bits();
            const byte_count: u16 = @int_cast((@as(u17, bits) + 7) / 8);

            const name = switch (ip.index_to_key(val.to_intern())) {
                .err => |err| err.name,
                .error_union => |error_union| error_union.val.err_name,
                else => unreachable,
            };
            var bigint_buffer: BigIntSpace = undefined;
            const bigint = BigIntMutable.init(
                &bigint_buffer.limbs,
                mod.global_error_set.get_index(name).?,
            ).to_const();
            bigint.write_twos_complement(buffer[0..byte_count], endian);
        },
        .Union => switch (ty.container_layout(mod)) {
            .auto => return error.IllDefinedMemoryLayout, // Sema is supposed to have emitted a compile error already
            .@"extern" => {
                if (val.union_tag(mod)) |union_tag| {
                    const union_obj = mod.type_to_union(ty).?;
                    const field_index = mod.union_tag_field_index(union_obj, union_tag).?;
                    const field_type = Type.from_interned(union_obj.field_types.get(&mod.intern_pool)[field_index]);
                    const field_val = try val.field_value(mod, field_index);
                    const byte_count: usize = @int_cast(field_type.abi_size(mod));
                    return write_to_memory(field_val, field_type, mod, buffer[0..byte_count]);
                } else {
                    const backing_ty = try ty.union_backing_type(mod);
                    const byte_count: usize = @int_cast(backing_ty.abi_size(mod));
                    return write_to_memory(val.union_value(mod), backing_ty, mod, buffer[0..byte_count]);
                }
            },
            .@"packed" => {
                const backing_ty = try ty.union_backing_type(mod);
                const byte_count: usize = @int_cast(backing_ty.abi_size(mod));
                return write_to_packed_memory(val, ty, mod, buffer[0..byte_count], 0);
            },
        },
        .Pointer => {
            if (ty.is_slice(mod)) return error.IllDefinedMemoryLayout;
            if (!val.ptr_has_int_addr(mod)) return error.ReinterpretDeclRef;
            return val.write_to_memory(Type.usize, mod, buffer);
        },
        .Optional => {
            if (!ty.is_ptr_like_optional(mod)) return error.IllDefinedMemoryLayout;
            const child = ty.optional_child(mod);
            const opt_val = val.optional_value(mod);
            if (opt_val) |some| {
                return some.write_to_memory(child, mod, buffer);
            } else {
                return write_to_memory(try mod.int_value(Type.usize, 0), Type.usize, mod, buffer);
            }
        },
        else => return error.Unimplemented,
    }
}

/// Write a Value's contents to `buffer`.
///
/// Both the start and the end of the provided buffer must be tight, since
/// big-endian packed memory layouts start at the end of the buffer.
pub fn write_to_packed_memory(
    val: Value,
    ty: Type,
    mod: *Module,
    buffer: []u8,
    bit_offset: usize,
) error{ ReinterpretDeclRef, OutOfMemory }!void {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    const endian = target.cpu.arch.endian();
    if (val.is_undef(mod)) {
        const bit_size: usize = @int_cast(ty.bit_size(mod));
        if (bit_size != 0) {
            std.mem.write_var_packed_int(buffer, bit_offset, bit_size, @as(u1, 0), endian);
        }
        return;
    }
    switch (ty.zig_type_tag(mod)) {
        .Void => {},
        .Bool => {
            const byte_index = switch (endian) {
                .little => bit_offset / 8,
                .big => buffer.len - bit_offset / 8 - 1,
            };
            if (val.to_bool()) {
                buffer[byte_index] |= (@as(u8, 1) << @as(u3, @int_cast(bit_offset % 8)));
            } else {
                buffer[byte_index] &= ~(@as(u8, 1) << @as(u3, @int_cast(bit_offset % 8)));
            }
        },
        .Int, .Enum => {
            if (buffer.len == 0) return;
            const bits = ty.int_info(mod).bits;
            if (bits == 0) return;

            switch (ip.index_to_key((try val.int_from_enum(ty, mod)).to_intern()).int.storage) {
                inline .u64, .i64 => |int| std.mem.write_var_packed_int(buffer, bit_offset, bits, int, endian),
                .big_int => |bigint| bigint.write_packed_twos_complement(buffer, bit_offset, bits, endian),
                .lazy_align => |lazy_align| {
                    const num = Type.from_interned(lazy_align).abi_alignment(mod).to_byte_units() orelse 0;
                    std.mem.write_var_packed_int(buffer, bit_offset, bits, num, endian);
                },
                .lazy_size => |lazy_size| {
                    const num = Type.from_interned(lazy_size).abi_size(mod);
                    std.mem.write_var_packed_int(buffer, bit_offset, bits, num, endian);
                },
            }
        },
        .Float => switch (ty.float_bits(target)) {
            16 => std.mem.write_packed_int(u16, buffer, bit_offset, @bit_cast(val.to_float(f16, mod)), endian),
            32 => std.mem.write_packed_int(u32, buffer, bit_offset, @bit_cast(val.to_float(f32, mod)), endian),
            64 => std.mem.write_packed_int(u64, buffer, bit_offset, @bit_cast(val.to_float(f64, mod)), endian),
            80 => std.mem.write_packed_int(u80, buffer, bit_offset, @bit_cast(val.to_float(f80, mod)), endian),
            128 => std.mem.write_packed_int(u128, buffer, bit_offset, @bit_cast(val.to_float(f128, mod)), endian),
            else => unreachable,
        },
        .Vector => {
            const elem_ty = ty.child_type(mod);
            const elem_bit_size: u16 = @int_cast(elem_ty.bit_size(mod));
            const len: usize = @int_cast(ty.array_len(mod));

            var bits: u16 = 0;
            var elem_i: usize = 0;
            while (elem_i < len) : (elem_i += 1) {
                // On big-endian systems, LLVM reverses the element order of vectors by default
                const tgt_elem_i = if (endian == .big) len - elem_i - 1 else elem_i;
                const elem_val = try val.elem_value(mod, tgt_elem_i);
                try elem_val.write_to_packed_memory(elem_ty, mod, buffer, bit_offset + bits);
                bits += elem_bit_size;
            }
        },
        .Struct => {
            const struct_type = ip.load_struct_type(ty.to_intern());
            // Sema is supposed to have emitted a compile error already in the case of Auto,
            // and Extern is handled in non-packed write_to_memory.
            assert(struct_type.layout == .@"packed");
            var bits: u16 = 0;
            for (0..struct_type.field_types.len) |i| {
                const field_val = Value.from_interned(switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                    .bytes => unreachable,
                    .elems => |elems| elems[i],
                    .repeated_elem => |elem| elem,
                });
                const field_ty = Type.from_interned(struct_type.field_types.get(ip)[i]);
                const field_bits: u16 = @int_cast(field_ty.bit_size(mod));
                try field_val.write_to_packed_memory(field_ty, mod, buffer, bit_offset + bits);
                bits += field_bits;
            }
        },
        .Union => {
            const union_obj = mod.type_to_union(ty).?;
            switch (union_obj.get_layout(ip)) {
                .auto, .@"extern" => unreachable, // Handled in non-packed write_to_memory
                .@"packed" => {
                    if (val.union_tag(mod)) |union_tag| {
                        const field_index = mod.union_tag_field_index(union_obj, union_tag).?;
                        const field_type = Type.from_interned(union_obj.field_types.get(ip)[field_index]);
                        const field_val = try val.field_value(mod, field_index);
                        return field_val.write_to_packed_memory(field_type, mod, buffer, bit_offset);
                    } else {
                        const backing_ty = try ty.union_backing_type(mod);
                        return val.union_value(mod).write_to_packed_memory(backing_ty, mod, buffer, bit_offset);
                    }
                },
            }
        },
        .Pointer => {
            assert(!ty.is_slice(mod)); // No well defined layout.
            if (!val.ptr_has_int_addr(mod)) return error.ReinterpretDeclRef;
            return val.write_to_packed_memory(Type.usize, mod, buffer, bit_offset);
        },
        .Optional => {
            assert(ty.is_ptr_like_optional(mod));
            const child = ty.optional_child(mod);
            const opt_val = val.optional_value(mod);
            if (opt_val) |some| {
                return some.write_to_packed_memory(child, mod, buffer, bit_offset);
            } else {
                return write_to_packed_memory(try mod.int_value(Type.usize, 0), Type.usize, mod, buffer, bit_offset);
            }
        },
        else => @panic("TODO implement write_to_packed_memory for more types"),
    }
}

/// Load a Value from the contents of `buffer`.
///
/// Asserts that buffer.len >= ty.abi_size(). The buffer is allowed to extend past
/// the end of the value in memory.
pub fn read_from_memory(
    ty: Type,
    mod: *Module,
    buffer: []const u8,
    arena: Allocator,
) error{
    IllDefinedMemoryLayout,
    Unimplemented,
    OutOfMemory,
}!Value {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    const endian = target.cpu.arch.endian();
    switch (ty.zig_type_tag(mod)) {
        .Void => return Value.void,
        .Bool => {
            if (buffer[0] == 0) {
                return Value.false;
            } else {
                return Value.true;
            }
        },
        .Int, .Enum => |ty_tag| {
            const int_ty = switch (ty_tag) {
                .Int => ty,
                .Enum => ty.int_tag_type(mod),
                else => unreachable,
            };
            const int_info = int_ty.int_info(mod);
            const bits = int_info.bits;
            const byte_count: u16 = @int_cast((@as(u17, bits) + 7) / 8);
            if (bits == 0 or buffer.len == 0) return mod.get_coerced(try mod.int_value(int_ty, 0), ty);

            if (bits <= 64) switch (int_info.signedness) { // Fast path for integers <= u64
                .signed => {
                    const val = std.mem.read_var_int(i64, buffer[0..byte_count], endian);
                    const result = (val << @as(u6, @int_cast(64 - bits))) >> @as(u6, @int_cast(64 - bits));
                    return mod.get_coerced(try mod.int_value(int_ty, result), ty);
                },
                .unsigned => {
                    const val = std.mem.read_var_int(u64, buffer[0..byte_count], endian);
                    const result = (val << @as(u6, @int_cast(64 - bits))) >> @as(u6, @int_cast(64 - bits));
                    return mod.get_coerced(try mod.int_value(int_ty, result), ty);
                },
            } else { // Slow path, we have to construct a big-int
                const Limb = std.math.big.Limb;
                const limb_count = (byte_count + @size_of(Limb) - 1) / @size_of(Limb);
                const limbs_buffer = try arena.alloc(Limb, limb_count);

                var bigint = BigIntMutable.init(limbs_buffer, 0);
                bigint.read_twos_complement(buffer[0..byte_count], bits, endian, int_info.signedness);
                return mod.get_coerced(try mod.int_value_big(int_ty, bigint.to_const()), ty);
            }
        },
        .Float => return Value.from_interned((try mod.intern(.{ .float = .{
            .ty = ty.to_intern(),
            .storage = switch (ty.float_bits(target)) {
                16 => .{ .f16 = @bit_cast(std.mem.read_int(u16, buffer[0..2], endian)) },
                32 => .{ .f32 = @bit_cast(std.mem.read_int(u32, buffer[0..4], endian)) },
                64 => .{ .f64 = @bit_cast(std.mem.read_int(u64, buffer[0..8], endian)) },
                80 => .{ .f80 = @bit_cast(std.mem.read_int(u80, buffer[0..10], endian)) },
                128 => .{ .f128 = @bit_cast(std.mem.read_int(u128, buffer[0..16], endian)) },
                else => unreachable,
            },
        } }))),
        .Array => {
            const elem_ty = ty.child_type(mod);
            const elem_size = elem_ty.abi_size(mod);
            const elems = try arena.alloc(InternPool.Index, @int_cast(ty.array_len(mod)));
            var offset: usize = 0;
            for (elems) |*elem| {
                elem.* = (try read_from_memory(elem_ty, mod, buffer[offset..], arena)).to_intern();
                offset += @int_cast(elem_size);
            }
            return Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = ty.to_intern(),
                .storage = .{ .elems = elems },
            } })));
        },
        .Vector => {
            // We use byte_count instead of abi_size here, so that any padding bytes
            // follow the data bytes, on both big- and little-endian systems.
            const byte_count = (@as(usize, @int_cast(ty.bit_size(mod))) + 7) / 8;
            return read_from_packed_memory(ty, mod, buffer[0..byte_count], 0, arena);
        },
        .Struct => {
            const struct_type = mod.type_to_struct(ty).?;
            switch (struct_type.layout) {
                .auto => unreachable, // Sema is supposed to have emitted a compile error already
                .@"extern" => {
                    const field_types = struct_type.field_types;
                    const field_vals = try arena.alloc(InternPool.Index, field_types.len);
                    for (field_vals, 0..) |*field_val, i| {
                        const field_ty = Type.from_interned(field_types.get(ip)[i]);
                        const off: usize = @int_cast(ty.struct_field_offset(i, mod));
                        const sz: usize = @int_cast(field_ty.abi_size(mod));
                        field_val.* = (try read_from_memory(field_ty, mod, buffer[off..(off + sz)], arena)).to_intern();
                    }
                    return Value.from_interned((try mod.intern(.{ .aggregate = .{
                        .ty = ty.to_intern(),
                        .storage = .{ .elems = field_vals },
                    } })));
                },
                .@"packed" => {
                    const byte_count = (@as(usize, @int_cast(ty.bit_size(mod))) + 7) / 8;
                    return read_from_packed_memory(ty, mod, buffer[0..byte_count], 0, arena);
                },
            }
        },
        .ErrorSet => {
            const bits = mod.error_set_bits();
            const byte_count: u16 = @int_cast((@as(u17, bits) + 7) / 8);
            const int = std.mem.read_var_int(u64, buffer[0..byte_count], endian);
            const index = (int << @as(u6, @int_cast(64 - bits))) >> @as(u6, @int_cast(64 - bits));
            const name = mod.global_error_set.keys()[@int_cast(index)];

            return Value.from_interned((try mod.intern(.{ .err = .{
                .ty = ty.to_intern(),
                .name = name,
            } })));
        },
        .Union => switch (ty.container_layout(mod)) {
            .auto => return error.IllDefinedMemoryLayout,
            .@"extern" => {
                const union_size = ty.abi_size(mod);
                const array_ty = try mod.array_type(.{ .len = union_size, .child = .u8_type });
                const val = (try read_from_memory(array_ty, mod, buffer, arena)).to_intern();
                return Value.from_interned((try mod.intern(.{ .un = .{
                    .ty = ty.to_intern(),
                    .tag = .none,
                    .val = val,
                } })));
            },
            .@"packed" => {
                const byte_count = (@as(usize, @int_cast(ty.bit_size(mod))) + 7) / 8;
                return read_from_packed_memory(ty, mod, buffer[0..byte_count], 0, arena);
            },
        },
        .Pointer => {
            assert(!ty.is_slice(mod)); // No well defined layout.
            const int_val = try read_from_memory(Type.usize, mod, buffer, arena);
            return Value.from_interned((try mod.intern(.{ .ptr = .{
                .ty = ty.to_intern(),
                .base_addr = .int,
                .byte_offset = int_val.to_unsigned_int(mod),
            } })));
        },
        .Optional => {
            assert(ty.is_ptr_like_optional(mod));
            const child_ty = ty.optional_child(mod);
            const child_val = try read_from_memory(child_ty, mod, buffer, arena);
            return Value.from_interned((try mod.intern(.{ .opt = .{
                .ty = ty.to_intern(),
                .val = switch (child_val.order_against_zero(mod)) {
                    .lt => unreachable,
                    .eq => .none,
                    .gt => child_val.to_intern(),
                },
            } })));
        },
        else => return error.Unimplemented,
    }
}

/// Load a Value from the contents of `buffer`.
///
/// Both the start and the end of the provided buffer must be tight, since
/// big-endian packed memory layouts start at the end of the buffer.
pub fn read_from_packed_memory(
    ty: Type,
    mod: *Module,
    buffer: []const u8,
    bit_offset: usize,
    arena: Allocator,
) error{
    IllDefinedMemoryLayout,
    OutOfMemory,
}!Value {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    const endian = target.cpu.arch.endian();
    switch (ty.zig_type_tag(mod)) {
        .Void => return Value.void,
        .Bool => {
            const byte = switch (endian) {
                .big => buffer[buffer.len - bit_offset / 8 - 1],
                .little => buffer[bit_offset / 8],
            };
            if (((byte >> @as(u3, @int_cast(bit_offset % 8))) & 1) == 0) {
                return Value.false;
            } else {
                return Value.true;
            }
        },
        .Int => {
            if (buffer.len == 0) return mod.int_value(ty, 0);
            const int_info = ty.int_info(mod);
            const bits = int_info.bits;
            if (bits == 0) return mod.int_value(ty, 0);

            // Fast path for integers <= u64
            if (bits <= 64) switch (int_info.signedness) {
                // Use different backing types for unsigned vs signed to avoid the need to go via
                // a larger type like `i128`.
                .unsigned => return mod.int_value(ty, std.mem.read_var_packed_int(u64, buffer, bit_offset, bits, endian, .unsigned)),
                .signed => return mod.int_value(ty, std.mem.read_var_packed_int(i64, buffer, bit_offset, bits, endian, .signed)),
            };

            // Slow path, we have to construct a big-int
            const abi_size: usize = @int_cast(ty.abi_size(mod));
            const Limb = std.math.big.Limb;
            const limb_count = (abi_size + @size_of(Limb) - 1) / @size_of(Limb);
            const limbs_buffer = try arena.alloc(Limb, limb_count);

            var bigint = BigIntMutable.init(limbs_buffer, 0);
            bigint.read_packed_twos_complement(buffer, bit_offset, bits, endian, int_info.signedness);
            return mod.int_value_big(ty, bigint.to_const());
        },
        .Enum => {
            const int_ty = ty.int_tag_type(mod);
            const int_val = try Value.read_from_packed_memory(int_ty, mod, buffer, bit_offset, arena);
            return mod.get_coerced(int_val, ty);
        },
        .Float => return Value.from_interned((try mod.intern(.{ .float = .{
            .ty = ty.to_intern(),
            .storage = switch (ty.float_bits(target)) {
                16 => .{ .f16 = @bit_cast(std.mem.read_packed_int(u16, buffer, bit_offset, endian)) },
                32 => .{ .f32 = @bit_cast(std.mem.read_packed_int(u32, buffer, bit_offset, endian)) },
                64 => .{ .f64 = @bit_cast(std.mem.read_packed_int(u64, buffer, bit_offset, endian)) },
                80 => .{ .f80 = @bit_cast(std.mem.read_packed_int(u80, buffer, bit_offset, endian)) },
                128 => .{ .f128 = @bit_cast(std.mem.read_packed_int(u128, buffer, bit_offset, endian)) },
                else => unreachable,
            },
        } }))),
        .Vector => {
            const elem_ty = ty.child_type(mod);
            const elems = try arena.alloc(InternPool.Index, @int_cast(ty.array_len(mod)));

            var bits: u16 = 0;
            const elem_bit_size: u16 = @int_cast(elem_ty.bit_size(mod));
            for (elems, 0..) |_, i| {
                // On big-endian systems, LLVM reverses the element order of vectors by default
                const tgt_elem_i = if (endian == .big) elems.len - i - 1 else i;
                elems[tgt_elem_i] = (try read_from_packed_memory(elem_ty, mod, buffer, bit_offset + bits, arena)).to_intern();
                bits += elem_bit_size;
            }
            return Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = ty.to_intern(),
                .storage = .{ .elems = elems },
            } })));
        },
        .Struct => {
            // Sema is supposed to have emitted a compile error already for Auto layout structs,
            // and Extern is handled by non-packed read_from_memory.
            const struct_type = mod.type_to_packed_struct(ty).?;
            var bits: u16 = 0;
            const field_vals = try arena.alloc(InternPool.Index, struct_type.field_types.len);
            for (field_vals, 0..) |*field_val, i| {
                const field_ty = Type.from_interned(struct_type.field_types.get(ip)[i]);
                const field_bits: u16 = @int_cast(field_ty.bit_size(mod));
                field_val.* = (try read_from_packed_memory(field_ty, mod, buffer, bit_offset + bits, arena)).to_intern();
                bits += field_bits;
            }
            return Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = ty.to_intern(),
                .storage = .{ .elems = field_vals },
            } })));
        },
        .Union => switch (ty.container_layout(mod)) {
            .auto, .@"extern" => unreachable, // Handled by non-packed read_from_memory
            .@"packed" => {
                const backing_ty = try ty.union_backing_type(mod);
                const val = (try read_from_packed_memory(backing_ty, mod, buffer, bit_offset, arena)).to_intern();
                return Value.from_interned((try mod.intern(.{ .un = .{
                    .ty = ty.to_intern(),
                    .tag = .none,
                    .val = val,
                } })));
            },
        },
        .Pointer => {
            assert(!ty.is_slice(mod)); // No well defined layout.
            const int_val = try read_from_packed_memory(Type.usize, mod, buffer, bit_offset, arena);
            return Value.from_interned(try mod.intern(.{ .ptr = .{
                .ty = ty.to_intern(),
                .base_addr = .int,
                .byte_offset = int_val.to_unsigned_int(mod),
            } }));
        },
        .Optional => {
            assert(ty.is_ptr_like_optional(mod));
            const child_ty = ty.optional_child(mod);
            const child_val = try read_from_packed_memory(child_ty, mod, buffer, bit_offset, arena);
            return Value.from_interned(try mod.intern(.{ .opt = .{
                .ty = ty.to_intern(),
                .val = switch (child_val.order_against_zero(mod)) {
                    .lt => unreachable,
                    .eq => .none,
                    .gt => child_val.to_intern(),
                },
            } }));
        },
        else => @panic("TODO implement read_from_packed_memory for more types"),
    }
}

/// Asserts that the value is a float or an integer.
pub fn to_float(val: Value, comptime T: type, mod: *Module) T {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .int => |int| switch (int.storage) {
            .big_int => |big_int| @float_cast(big_int_to_float(big_int.limbs, big_int.positive)),
            inline .u64, .i64 => |x| {
                if (T == f80) {
                    @panic("TODO we can't lower this properly on non-x86 llvm backend yet");
                }
                return @float_from_int(x);
            },
            .lazy_align => |ty| @float_from_int(Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0),
            .lazy_size => |ty| @float_from_int(Type.from_interned(ty).abi_size(mod)),
        },
        .float => |float| switch (float.storage) {
            inline else => |x| @float_cast(x),
        },
        else => unreachable,
    };
}

/// TODO move this to std lib big int code
fn big_int_to_float(limbs: []const std.math.big.Limb, positive: bool) f128 {
    if (limbs.len == 0) return 0;

    const base = std.math.max_int(std.math.big.Limb) + 1;
    var result: f128 = 0;
    var i: usize = limbs.len;
    while (i != 0) {
        i -= 1;
        const limb: f128 = @float_from_int(limbs[i]);
        result = @mul_add(f128, base, result, limb);
    }
    if (positive) {
        return result;
    } else {
        return -result;
    }
}

pub fn clz(val: Value, ty: Type, mod: *Module) u64 {
    var bigint_buf: BigIntSpace = undefined;
    const bigint = val.to_big_int(&bigint_buf, mod);
    return bigint.clz(ty.int_info(mod).bits);
}

pub fn ctz(val: Value, ty: Type, mod: *Module) u64 {
    var bigint_buf: BigIntSpace = undefined;
    const bigint = val.to_big_int(&bigint_buf, mod);
    return bigint.ctz(ty.int_info(mod).bits);
}

pub fn pop_count(val: Value, ty: Type, mod: *Module) u64 {
    var bigint_buf: BigIntSpace = undefined;
    const bigint = val.to_big_int(&bigint_buf, mod);
    return @int_cast(bigint.pop_count(ty.int_info(mod).bits));
}

pub fn bit_reverse(val: Value, ty: Type, mod: *Module, arena: Allocator) !Value {
    const info = ty.int_info(mod);

    var buffer: Value.BigIntSpace = undefined;
    const operand_bigint = val.to_big_int(&buffer, mod);

    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.bit_reverse(operand_bigint, info.signedness, info.bits);

    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn byte_swap(val: Value, ty: Type, mod: *Module, arena: Allocator) !Value {
    const info = ty.int_info(mod);

    // Bit count must be evenly divisible by 8
    assert(info.bits % 8 == 0);

    var buffer: Value.BigIntSpace = undefined;
    const operand_bigint = val.to_big_int(&buffer, mod);

    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.byte_swap(operand_bigint, info.signedness, info.bits / 8);

    return mod.int_value_big(ty, result_bigint.to_const());
}

/// Asserts the value is an integer and not undefined.
/// Returns the number of bits the value requires to represent stored in twos complement form.
pub fn int_bit_count_twos_comp(self: Value, mod: *Module) usize {
    var buffer: BigIntSpace = undefined;
    const big_int = self.to_big_int(&buffer, mod);
    return big_int.bit_count_twos_comp();
}

/// Converts an integer or a float to a float. May result in a loss of information.
/// Caller can find out by equality checking the result against the operand.
pub fn float_cast(val: Value, dest_ty: Type, zcu: *Zcu) !Value {
    const target = zcu.get_target();
    if (val.is_undef(zcu)) return zcu.undef_value(dest_ty);
    return Value.from_interned((try zcu.intern(.{ .float = .{
        .ty = dest_ty.to_intern(),
        .storage = switch (dest_ty.float_bits(target)) {
            16 => .{ .f16 = val.to_float(f16, zcu) },
            32 => .{ .f32 = val.to_float(f32, zcu) },
            64 => .{ .f64 = val.to_float(f64, zcu) },
            80 => .{ .f80 = val.to_float(f80, zcu) },
            128 => .{ .f128 = val.to_float(f128, zcu) },
            else => unreachable,
        },
    } })));
}

/// Asserts the value is a float
pub fn float_has_fraction(self: Value, mod: *const Module) bool {
    return switch (mod.intern_pool.index_to_key(self.to_intern())) {
        .float => |float| switch (float.storage) {
            inline else => |x| @rem(x, 1) != 0,
        },
        else => unreachable,
    };
}

pub fn order_against_zero(lhs: Value, mod: *Module) std.math.Order {
    return order_against_zero_advanced(lhs, mod, null) catch unreachable;
}

pub fn order_against_zero_advanced(
    lhs: Value,
    mod: *Module,
    opt_sema: ?*Sema,
) Module.CompileError!std.math.Order {
    return switch (lhs.to_intern()) {
        .bool_false => .eq,
        .bool_true => .gt,
        else => switch (mod.intern_pool.index_to_key(lhs.to_intern())) {
            .ptr => |ptr| if (ptr.byte_offset > 0) .gt else switch (ptr.base_addr) {
                .decl, .comptime_alloc, .comptime_field => .gt,
                .int => .eq,
                else => unreachable,
            },
            .int => |int| switch (int.storage) {
                .big_int => |big_int| big_int.order_against_scalar(0),
                inline .u64, .i64 => |x| std.math.order(x, 0),
                .lazy_align => .gt, // alignment is never 0
                .lazy_size => |ty| return if (Type.from_interned(ty).has_runtime_bits_advanced(
                    mod,
                    false,
                    if (opt_sema) |sema| .{ .sema = sema } else .eager,
                ) catch |err| switch (err) {
                    error.NeedLazy => unreachable,
                    else => |e| return e,
                }) .gt else .eq,
            },
            .enum_tag => |enum_tag| Value.from_interned(enum_tag.int).order_against_zero_advanced(mod, opt_sema),
            .float => |float| switch (float.storage) {
                inline else => |x| std.math.order(x, 0),
            },
            else => unreachable,
        },
    };
}

/// Asserts the value is comparable.
pub fn order(lhs: Value, rhs: Value, mod: *Module) std.math.Order {
    return order_advanced(lhs, rhs, mod, null) catch unreachable;
}

/// Asserts the value is comparable.
/// If opt_sema is null then this function asserts things are resolved and cannot fail.
pub fn order_advanced(lhs: Value, rhs: Value, mod: *Module, opt_sema: ?*Sema) !std.math.Order {
    const lhs_against_zero = try lhs.order_against_zero_advanced(mod, opt_sema);
    const rhs_against_zero = try rhs.order_against_zero_advanced(mod, opt_sema);
    switch (lhs_against_zero) {
        .lt => if (rhs_against_zero != .lt) return .lt,
        .eq => return rhs_against_zero.invert(),
        .gt => {},
    }
    switch (rhs_against_zero) {
        .lt => if (lhs_against_zero != .lt) return .gt,
        .eq => return lhs_against_zero,
        .gt => {},
    }

    if (lhs.is_float(mod) or rhs.is_float(mod)) {
        const lhs_f128 = lhs.to_float(f128, mod);
        const rhs_f128 = rhs.to_float(f128, mod);
        return std.math.order(lhs_f128, rhs_f128);
    }

    var lhs_bigint_space: BigIntSpace = undefined;
    var rhs_bigint_space: BigIntSpace = undefined;
    const lhs_bigint = try lhs.to_big_int_advanced(&lhs_bigint_space, mod, opt_sema);
    const rhs_bigint = try rhs.to_big_int_advanced(&rhs_bigint_space, mod, opt_sema);
    return lhs_bigint.order(rhs_bigint);
}

/// Asserts the value is comparable. Does not take a type parameter because it supports
/// comparisons between heterogeneous types.
pub fn compare_hetero(lhs: Value, op: std.math.CompareOperator, rhs: Value, mod: *Module) bool {
    return compare_hetero_advanced(lhs, op, rhs, mod, null) catch unreachable;
}

pub fn compare_hetero_advanced(
    lhs: Value,
    op: std.math.CompareOperator,
    rhs: Value,
    mod: *Module,
    opt_sema: ?*Sema,
) !bool {
    if (lhs.pointer_decl(mod)) |lhs_decl| {
        if (rhs.pointer_decl(mod)) |rhs_decl| {
            switch (op) {
                .eq => return lhs_decl == rhs_decl,
                .neq => return lhs_decl != rhs_decl,
                else => {},
            }
        } else {
            switch (op) {
                .eq => return false,
                .neq => return true,
                else => {},
            }
        }
    } else if (rhs.pointer_decl(mod)) |_| {
        switch (op) {
            .eq => return false,
            .neq => return true,
            else => {},
        }
    }
    return (try order_advanced(lhs, rhs, mod, opt_sema)).compare(op);
}

/// Asserts the values are comparable. Both operands have type `ty`.
/// For vectors, returns true if comparison is true for ALL elements.
pub fn compare_all(lhs: Value, op: std.math.CompareOperator, rhs: Value, ty: Type, mod: *Module) !bool {
    if (ty.zig_type_tag(mod) == .Vector) {
        const scalar_ty = ty.scalar_type(mod);
        for (0..ty.vector_len(mod)) |i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            if (!compare_scalar(lhs_elem, op, rhs_elem, scalar_ty, mod)) {
                return false;
            }
        }
        return true;
    }
    return compare_scalar(lhs, op, rhs, ty, mod);
}

/// Asserts the values are comparable. Both operands have type `ty`.
pub fn compare_scalar(
    lhs: Value,
    op: std.math.CompareOperator,
    rhs: Value,
    ty: Type,
    mod: *Module,
) bool {
    return switch (op) {
        .eq => lhs.eql(rhs, ty, mod),
        .neq => !lhs.eql(rhs, ty, mod),
        else => compare_hetero(lhs, op, rhs, mod),
    };
}

/// Asserts the value is comparable.
/// For vectors, returns true if comparison is true for ALL elements.
/// Returns `false` if the value or any vector element is undefined.
///
/// Note that `!compare_all_with_zero(.eq, ...) != compare_all_with_zero(.neq, ...)`
pub fn compare_all_with_zero(lhs: Value, op: std.math.CompareOperator, mod: *Module) bool {
    return compare_all_with_zero_advanced_extra(lhs, op, mod, null) catch unreachable;
}

pub fn compare_all_with_zero_advanced(
    lhs: Value,
    op: std.math.CompareOperator,
    sema: *Sema,
) Module.CompileError!bool {
    return compare_all_with_zero_advanced_extra(lhs, op, sema.mod, sema);
}

pub fn compare_all_with_zero_advanced_extra(
    lhs: Value,
    op: std.math.CompareOperator,
    mod: *Module,
    opt_sema: ?*Sema,
) Module.CompileError!bool {
    if (lhs.is_inf(mod)) {
        switch (op) {
            .neq => return true,
            .eq => return false,
            .gt, .gte => return !lhs.is_negative_inf(mod),
            .lt, .lte => return lhs.is_negative_inf(mod),
        }
    }

    switch (mod.intern_pool.index_to_key(lhs.to_intern())) {
        .float => |float| switch (float.storage) {
            inline else => |x| if (std.math.is_nan(x)) return op == .neq,
        },
        .aggregate => |aggregate| return switch (aggregate.storage) {
            .bytes => |bytes| for (bytes.to_slice(lhs.type_of(mod).array_len_including_sentinel(mod), &mod.intern_pool)) |byte| {
                if (!std.math.order(byte, 0).compare(op)) break false;
            } else true,
            .elems => |elems| for (elems) |elem| {
                if (!try Value.from_interned(elem).compare_all_with_zero_advanced_extra(op, mod, opt_sema)) break false;
            } else true,
            .repeated_elem => |elem| Value.from_interned(elem).compare_all_with_zero_advanced_extra(op, mod, opt_sema),
        },
        .undef => return false,
        else => {},
    }
    return (try order_against_zero_advanced(lhs, mod, opt_sema)).compare(op);
}

pub fn eql(a: Value, b: Value, ty: Type, mod: *Module) bool {
    assert(mod.intern_pool.type_of(a.to_intern()) == ty.to_intern());
    assert(mod.intern_pool.type_of(b.to_intern()) == ty.to_intern());
    return a.to_intern() == b.to_intern();
}

pub fn can_mutate_comptime_var_state(val: Value, zcu: *Zcu) bool {
    return switch (zcu.intern_pool.index_to_key(val.to_intern())) {
        .error_union => |error_union| switch (error_union.val) {
            .err_name => false,
            .payload => |payload| Value.from_interned(payload).can_mutate_comptime_var_state(zcu),
        },
        .ptr => |ptr| switch (ptr.base_addr) {
            .decl => false, // The value of a Decl can never reference a comptime alloc.
            .int => false,
            .comptime_alloc => true, // A comptime alloc is either mutable or references comptime-mutable memory.
            .comptime_field => true, // Comptime field pointers are comptime-mutable, albeit only to the "correct" value.
            .eu_payload, .opt_payload => |base| Value.from_interned(base).can_mutate_comptime_var_state(zcu),
            .anon_decl => |anon_decl| Value.from_interned(anon_decl.val).can_mutate_comptime_var_state(zcu),
            .arr_elem, .field => |base_index| Value.from_interned(base_index.base).can_mutate_comptime_var_state(zcu),
        },
        .slice => |slice| return Value.from_interned(slice.ptr).can_mutate_comptime_var_state(zcu),
        .opt => |opt| switch (opt.val) {
            .none => false,
            else => |payload| Value.from_interned(payload).can_mutate_comptime_var_state(zcu),
        },
        .aggregate => |aggregate| for (aggregate.storage.values()) |elem| {
            if (Value.from_interned(elem).can_mutate_comptime_var_state(zcu)) break true;
        } else false,
        .un => |un| Value.from_interned(un.val).can_mutate_comptime_var_state(zcu),
        else => false,
    };
}

/// Gets the decl referenced by this pointer.  If the pointer does not point
/// to a decl, or if it points to some part of a decl (like field_ptr or element_ptr),
/// this function returns null.
pub fn pointer_decl(val: Value, mod: *Module) ?InternPool.DeclIndex {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .variable => |variable| variable.decl,
        .extern_func => |extern_func| extern_func.decl,
        .func => |func| func.owner_decl,
        .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
            .decl => |decl| decl,
            else => null,
        } else null,
        else => null,
    };
}

pub const slice_ptr_index = 0;
pub const slice_len_index = 1;

pub fn slice_ptr(val: Value, mod: *Module) Value {
    return Value.from_interned(mod.intern_pool.slice_ptr(val.to_intern()));
}

/// Gets the `len` field of a slice value as a `u64`.
/// Resolves the length using the provided `Sema` if necessary.
pub fn slice_len(val: Value, sema: *Sema) !u64 {
    return Value.from_interned(sema.mod.intern_pool.slice_len(val.to_intern())).to_unsigned_int_advanced(sema);
}

/// Asserts the value is an aggregate, and returns the element value at the given index.
pub fn elem_value(val: Value, zcu: *Zcu, index: usize) Allocator.Error!Value {
    const ip = &zcu.intern_pool;
    switch (zcu.intern_pool.index_to_key(val.to_intern())) {
        .undef => |ty| {
            return Value.from_interned(try zcu.intern(.{ .undef = Type.from_interned(ty).child_type(zcu).to_intern() }));
        },
        .aggregate => |aggregate| {
            const len = ip.aggregate_type_len(aggregate.ty);
            if (index < len) return Value.from_interned(switch (aggregate.storage) {
                .bytes => |bytes| try zcu.intern(.{ .int = .{
                    .ty = .u8_type,
                    .storage = .{ .u64 = bytes.at(index, ip) },
                } }),
                .elems => |elems| elems[index],
                .repeated_elem => |elem| elem,
            });
            assert(index == len);
            return Type.from_interned(aggregate.ty).sentinel(zcu).?;
        },
        else => unreachable,
    }
}

pub fn is_lazy_align(val: Value, mod: *Module) bool {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .int => |int| int.storage == .lazy_align,
        else => false,
    };
}

pub fn is_lazy_size(val: Value, mod: *Module) bool {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .int => |int| int.storage == .lazy_size,
        else => false,
    };
}

pub fn is_ptr_to_thread_local(val: Value, mod: *Module) bool {
    const backing_decl = mod.intern_pool.get_backing_decl(val.to_intern()).unwrap() orelse return false;
    const variable = mod.decl_ptr(backing_decl).get_owned_variable(mod) orelse return false;
    return variable.is_threadlocal;
}

// Asserts that the provided start/end are in-bounds.
pub fn slice_array(
    val: Value,
    sema: *Sema,
    start: usize,
    end: usize,
) error{OutOfMemory}!Value {
    const mod = sema.mod;
    const ip = &mod.intern_pool;
    return Value.from_interned(try mod.intern(.{
        .aggregate = .{
            .ty = switch (mod.intern_pool.index_to_key(mod.intern_pool.type_of(val.to_intern()))) {
                .array_type => |array_type| try mod.array_type(.{
                    .len = @int_cast(end - start),
                    .child = array_type.child,
                    .sentinel = if (end == array_type.len) array_type.sentinel else .none,
                }),
                .vector_type => |vector_type| try mod.vector_type(.{
                    .len = @int_cast(end - start),
                    .child = vector_type.child,
                }),
                else => unreachable,
            }.to_intern(),
            .storage = switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                .bytes => |bytes| storage: {
                    try ip.string_bytes.ensure_unused_capacity(sema.gpa, end - start + 1);
                    break :storage .{ .bytes = try ip.get_or_put_string(
                        sema.gpa,
                        bytes.to_slice(end, ip)[start..],
                        .maybe_embedded_nulls,
                    ) };
                },
                // TODO: write something like get_coerced_ints to avoid needing to dupe
                .elems => |elems| .{ .elems = try sema.arena.dupe(InternPool.Index, elems[start..end]) },
                .repeated_elem => |elem| .{ .repeated_elem = elem },
            },
        },
    }));
}

pub fn field_value(val: Value, mod: *Module, index: usize) !Value {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .undef => |ty| Value.from_interned((try mod.intern(.{
            .undef = Type.from_interned(ty).struct_field_type(index, mod).to_intern(),
        }))),
        .aggregate => |aggregate| Value.from_interned(switch (aggregate.storage) {
            .bytes => |bytes| try mod.intern(.{ .int = .{
                .ty = .u8_type,
                .storage = .{ .u64 = bytes.at(index, &mod.intern_pool) },
            } }),
            .elems => |elems| elems[index],
            .repeated_elem => |elem| elem,
        }),
        // TODO assert the tag is correct
        .un => |un| Value.from_interned(un.val),
        else => unreachable,
    };
}

pub fn union_tag(val: Value, mod: *Module) ?Value {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .undef, .enum_tag => val,
        .un => |un| if (un.tag != .none) Value.from_interned(un.tag) else return null,
        else => unreachable,
    };
}

pub fn union_value(val: Value, mod: *Module) Value {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .un => |un| Value.from_interned(un.val),
        else => unreachable,
    };
}

pub fn is_undef(val: Value, mod: *Module) bool {
    return mod.intern_pool.is_undef(val.to_intern());
}

/// TODO: check for cases such as array that is not marked undef but all the element
/// values are marked undef, or struct that is not marked undef but all fields are marked
/// undef, etc.
pub fn is_undef_deep(val: Value, mod: *Module) bool {
    return val.is_undef(mod);
}

/// Asserts the value is not undefined and not unreachable.
/// C pointers with an integer value of 0 are also considered null.
pub fn is_null(val: Value, mod: *Module) bool {
    return switch (val.to_intern()) {
        .undef => unreachable,
        .unreachable_value => unreachable,
        .null_value => true,
        else => return switch (mod.intern_pool.index_to_key(val.to_intern())) {
            .undef => unreachable,
            .ptr => |ptr| switch (ptr.base_addr) {
                .int => ptr.byte_offset == 0,
                else => false,
            },
            .opt => |opt| opt.val == .none,
            else => false,
        },
    };
}

/// Valid only for error (union) types. Asserts the value is not undefined and not unreachable.
pub fn get_error_name(val: Value, mod: *const Module) InternPool.OptionalNullTerminatedString {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .err => |err| err.name.to_optional(),
        .error_union => |error_union| switch (error_union.val) {
            .err_name => |err_name| err_name.to_optional(),
            .payload => .none,
        },
        else => unreachable,
    };
}

pub fn get_error_int(val: Value, mod: *const Module) Module.ErrorInt {
    return if (get_error_name(val, mod).unwrap()) |err_name|
        @int_cast(mod.global_error_set.get_index(err_name).?)
    else
        0;
}

/// Assumes the type is an error union. Returns true if and only if the value is
/// the error union payload, not an error.
pub fn error_union_is_payload(val: Value, mod: *const Module) bool {
    return mod.intern_pool.index_to_key(val.to_intern()).error_union.val == .payload;
}

/// Value of the optional, null if optional has no payload.
pub fn optional_value(val: Value, mod: *const Module) ?Value {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .opt => |opt| switch (opt.val) {
            .none => null,
            else => |payload| Value.from_interned(payload),
        },
        .ptr => val,
        else => unreachable,
    };
}

/// Valid for all types. Asserts the value is not undefined.
pub fn is_float(self: Value, mod: *const Module) bool {
    return switch (self.to_intern()) {
        .undef => unreachable,
        else => switch (mod.intern_pool.index_to_key(self.to_intern())) {
            .undef => unreachable,
            .float => true,
            else => false,
        },
    };
}

pub fn float_from_int(val: Value, arena: Allocator, int_ty: Type, float_ty: Type, mod: *Module) !Value {
    return float_from_int_advanced(val, arena, int_ty, float_ty, mod, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => unreachable,
    };
}

pub fn float_from_int_advanced(val: Value, arena: Allocator, int_ty: Type, float_ty: Type, mod: *Module, opt_sema: ?*Sema) !Value {
    if (int_ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, int_ty.vector_len(mod));
        const scalar_ty = float_ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try float_from_int_scalar(elem_val, scalar_ty, mod, opt_sema)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_from_int_scalar(val, float_ty, mod, opt_sema);
}

pub fn float_from_int_scalar(val: Value, float_ty: Type, mod: *Module, opt_sema: ?*Sema) !Value {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .undef => try mod.undef_value(float_ty),
        .int => |int| switch (int.storage) {
            .big_int => |big_int| {
                const float = big_int_to_float(big_int.limbs, big_int.positive);
                return mod.float_value(float_ty, float);
            },
            inline .u64, .i64 => |x| float_from_int_inner(x, float_ty, mod),
            .lazy_align => |ty| if (opt_sema) |sema| {
                return float_from_int_inner((try Type.from_interned(ty).abi_alignment_advanced(mod, .{ .sema = sema })).scalar.to_byte_units() orelse 0, float_ty, mod);
            } else {
                return float_from_int_inner(Type.from_interned(ty).abi_alignment(mod).to_byte_units() orelse 0, float_ty, mod);
            },
            .lazy_size => |ty| if (opt_sema) |sema| {
                return float_from_int_inner((try Type.from_interned(ty).abi_size_advanced(mod, .{ .sema = sema })).scalar, float_ty, mod);
            } else {
                return float_from_int_inner(Type.from_interned(ty).abi_size(mod), float_ty, mod);
            },
        },
        else => unreachable,
    };
}

fn float_from_int_inner(x: anytype, dest_ty: Type, mod: *Module) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (dest_ty.float_bits(target)) {
        16 => .{ .f16 = @float_from_int(x) },
        32 => .{ .f32 = @float_from_int(x) },
        64 => .{ .f64 = @float_from_int(x) },
        80 => .{ .f80 = @float_from_int(x) },
        128 => .{ .f128 = @float_from_int(x) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = dest_ty.to_intern(),
        .storage = storage,
    } })));
}

fn calc_limb_len_float(scalar: anytype) usize {
    if (scalar == 0) {
        return 1;
    }

    const w_value = @abs(scalar);
    return @div_floor(@as(std.math.big.Limb, @int_from_float(std.math.log2(w_value))), @typeInfo(std.math.big.Limb).Int.bits) + 1;
}

pub const OverflowArithmeticResult = struct {
    overflow_bit: Value,
    wrapped_result: Value,
};

/// Supports (vectors of) integers only; asserts neither operand is undefined.
pub fn int_add_sat(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try int_add_sat_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_add_sat_scalar(lhs, rhs, ty, arena, mod);
}

/// Supports integers only; asserts neither operand is undefined.
pub fn int_add_sat_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    assert(!lhs.is_undef(mod));
    assert(!rhs.is_undef(mod));

    const info = ty.int_info(mod);

    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.add_sat(lhs_bigint, rhs_bigint, info.signedness, info.bits);
    return mod.int_value_big(ty, result_bigint.to_const());
}

/// Supports (vectors of) integers only; asserts neither operand is undefined.
pub fn int_sub_sat(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try int_sub_sat_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_sub_sat_scalar(lhs, rhs, ty, arena, mod);
}

/// Supports integers only; asserts neither operand is undefined.
pub fn int_sub_sat_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    assert(!lhs.is_undef(mod));
    assert(!rhs.is_undef(mod));

    const info = ty.int_info(mod);

    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.sub_sat(lhs_bigint, rhs_bigint, info.signedness, info.bits);
    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn int_mul_with_overflow(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !OverflowArithmeticResult {
    if (ty.zig_type_tag(mod) == .Vector) {
        const vec_len = ty.vector_len(mod);
        const overflowed_data = try arena.alloc(InternPool.Index, vec_len);
        const result_data = try arena.alloc(InternPool.Index, vec_len);
        const scalar_ty = ty.scalar_type(mod);
        for (overflowed_data, result_data, 0..) |*of, *scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            const of_math_result = try int_mul_with_overflow_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod);
            of.* = of_math_result.overflow_bit.to_intern();
            scalar.* = of_math_result.wrapped_result.to_intern();
        }
        return OverflowArithmeticResult{
            .overflow_bit = Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = (try mod.vector_type(.{ .len = vec_len, .child = .u1_type })).to_intern(),
                .storage = .{ .elems = overflowed_data },
            } }))),
            .wrapped_result = Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = ty.to_intern(),
                .storage = .{ .elems = result_data },
            } }))),
        };
    }
    return int_mul_with_overflow_scalar(lhs, rhs, ty, arena, mod);
}

pub fn int_mul_with_overflow_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !OverflowArithmeticResult {
    const info = ty.int_info(mod);

    if (lhs.is_undef(mod) or rhs.is_undef(mod)) {
        return .{
            .overflow_bit = try mod.undef_value(Type.u1),
            .wrapped_result = try mod.undef_value(ty),
        };
    }

    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len + rhs_bigint.limbs.len,
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    const limbs_buffer = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_mul_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len, 1),
    );
    result_bigint.mul(lhs_bigint, rhs_bigint, limbs_buffer, arena);

    const overflowed = !result_bigint.to_const().fits_in_twos_comp(info.signedness, info.bits);
    if (overflowed) {
        result_bigint.truncate(result_bigint.to_const(), info.signedness, info.bits);
    }

    return OverflowArithmeticResult{
        .overflow_bit = try mod.int_value(Type.u1, @int_from_bool(overflowed)),
        .wrapped_result = try mod.int_value_big(ty, result_bigint.to_const()),
    };
}

/// Supports both (vectors of) floats and ints; handles undefined scalars.
pub fn number_mul_wrap(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try number_mul_wrap_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return number_mul_wrap_scalar(lhs, rhs, ty, arena, mod);
}

/// Supports both floats and ints; handles undefined.
pub fn number_mul_wrap_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (lhs.is_undef(mod) or rhs.is_undef(mod)) return Value.undef;

    if (ty.zig_type_tag(mod) == .ComptimeInt) {
        return int_mul(lhs, rhs, ty, undefined, arena, mod);
    }

    if (ty.is_any_float()) {
        return float_mul(lhs, rhs, ty, arena, mod);
    }

    const overflow_result = try int_mul_with_overflow(lhs, rhs, ty, arena, mod);
    return overflow_result.wrapped_result;
}

/// Supports (vectors of) integers only; asserts neither operand is undefined.
pub fn int_mul_sat(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try int_mul_sat_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_mul_sat_scalar(lhs, rhs, ty, arena, mod);
}

/// Supports (vectors of) integers only; asserts neither operand is undefined.
pub fn int_mul_sat_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    assert(!lhs.is_undef(mod));
    assert(!rhs.is_undef(mod));

    const info = ty.int_info(mod);

    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        @max(
            // For the saturate
            std.math.big.int.calc_twos_comp_limb_count(info.bits),
            lhs_bigint.limbs.len + rhs_bigint.limbs.len,
        ),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    const limbs_buffer = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_mul_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len, 1),
    );
    result_bigint.mul(lhs_bigint, rhs_bigint, limbs_buffer, arena);
    result_bigint.saturate(result_bigint.to_const(), info.signedness, info.bits);
    return mod.int_value_big(ty, result_bigint.to_const());
}

/// Supports both floats and ints; handles undefined.
pub fn number_max(lhs: Value, rhs: Value, mod: *Module) Value {
    if (lhs.is_undef(mod) or rhs.is_undef(mod)) return undef;
    if (lhs.is_nan(mod)) return rhs;
    if (rhs.is_nan(mod)) return lhs;

    return switch (order(lhs, rhs, mod)) {
        .lt => rhs,
        .gt, .eq => lhs,
    };
}

/// Supports both floats and ints; handles undefined.
pub fn number_min(lhs: Value, rhs: Value, mod: *Module) Value {
    if (lhs.is_undef(mod) or rhs.is_undef(mod)) return undef;
    if (lhs.is_nan(mod)) return rhs;
    if (rhs.is_nan(mod)) return lhs;

    return switch (order(lhs, rhs, mod)) {
        .lt => lhs,
        .gt, .eq => rhs,
    };
}

/// operands must be (vectors of) integers; handles undefined scalars.
pub fn bitwise_not(val: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try bitwise_not_scalar(elem_val, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return bitwise_not_scalar(val, ty, arena, mod);
}

/// operands must be integers; handles undefined.
pub fn bitwise_not_scalar(val: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (val.is_undef(mod)) return Value.from_interned((try mod.intern(.{ .undef = ty.to_intern() })));
    if (ty.to_intern() == .bool_type) return make_bool(!val.to_bool());

    const info = ty.int_info(mod);

    if (info.bits == 0) {
        return val;
    }

    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var val_space: Value.BigIntSpace = undefined;
    const val_bigint = val.to_big_int(&val_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );

    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.bit_not_wrap(val_bigint, info.signedness, info.bits);
    return mod.int_value_big(ty, result_bigint.to_const());
}

/// operands must be (vectors of) integers; handles undefined scalars.
pub fn bitwise_and(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try bitwise_and_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return bitwise_and_scalar(lhs, rhs, ty, allocator, mod);
}

/// operands must be integers; handles undefined.
pub fn bitwise_and_scalar(orig_lhs: Value, orig_rhs: Value, ty: Type, arena: Allocator, zcu: *Zcu) !Value {
    // If one operand is defined, we turn the other into `0xAA` so the bitwise AND can
    // still zero out some bits.
    // TODO: ideally we'd still like tracking for the undef bits. Related: #19634.
    const lhs: Value, const rhs: Value = make_defined: {
        const lhs_undef = orig_lhs.is_undef(zcu);
        const rhs_undef = orig_rhs.is_undef(zcu);
        break :make_defined switch ((@as(u2, @int_from_bool(lhs_undef)) << 1) | @int_from_bool(rhs_undef)) {
            0b00 => .{ orig_lhs, orig_rhs },
            0b01 => .{ orig_lhs, try int_value_aa(ty, arena, zcu) },
            0b10 => .{ try int_value_aa(ty, arena, zcu), orig_rhs },
            0b11 => return zcu.undef_value(ty),
        };
    };

    if (ty.to_intern() == .bool_type) return make_bool(lhs.to_bool() and rhs.to_bool());

    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, zcu);
    const rhs_bigint = rhs.to_big_int(&rhs_space, zcu);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        // + 1 for negatives
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len) + 1,
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.bit_and(lhs_bigint, rhs_bigint);
    return zcu.int_value_big(ty, result_bigint.to_const());
}

/// Given an integer or boolean type, creates an value of that with the bit pattern 0xAA.
/// This is used to convert undef values into 0xAA when performing e.g. bitwise operations.
fn int_value_aa(ty: Type, arena: Allocator, zcu: *Zcu) !Value {
    if (ty.to_intern() == .bool_type) return Value.true;
    const info = ty.int_info(zcu);

    const buf = try arena.alloc(u8, (info.bits + 7) / 8);
    @memset(buf, 0xAA);

    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.read_twos_complement(buf, info.bits, zcu.get_target().cpu.arch.endian(), info.signedness);
    return zcu.int_value_big(ty, result_bigint.to_const());
}

/// operands must be (vectors of) integers; handles undefined scalars.
pub fn bitwise_nand(lhs: Value, rhs: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try bitwise_nand_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return bitwise_nand_scalar(lhs, rhs, ty, arena, mod);
}

/// operands must be integers; handles undefined.
pub fn bitwise_nand_scalar(lhs: Value, rhs: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (lhs.is_undef(mod) or rhs.is_undef(mod)) return Value.from_interned((try mod.intern(.{ .undef = ty.to_intern() })));
    if (ty.to_intern() == .bool_type) return make_bool(!(lhs.to_bool() and rhs.to_bool()));

    const anded = try bitwise_and(lhs, rhs, ty, arena, mod);
    const all_ones = if (ty.is_signed_int(mod)) try mod.int_value(ty, -1) else try ty.max_int_scalar(mod, ty);
    return bitwise_xor(anded, all_ones, ty, arena, mod);
}

/// operands must be (vectors of) integers; handles undefined scalars.
pub fn bitwise_or(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try bitwise_or_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return bitwise_or_scalar(lhs, rhs, ty, allocator, mod);
}

/// operands must be integers; handles undefined.
pub fn bitwise_or_scalar(orig_lhs: Value, orig_rhs: Value, ty: Type, arena: Allocator, zcu: *Zcu) !Value {
    // If one operand is defined, we turn the other into `0xAA` so the bitwise AND can
    // still zero out some bits.
    // TODO: ideally we'd still like tracking for the undef bits. Related: #19634.
    const lhs: Value, const rhs: Value = make_defined: {
        const lhs_undef = orig_lhs.is_undef(zcu);
        const rhs_undef = orig_rhs.is_undef(zcu);
        break :make_defined switch ((@as(u2, @int_from_bool(lhs_undef)) << 1) | @int_from_bool(rhs_undef)) {
            0b00 => .{ orig_lhs, orig_rhs },
            0b01 => .{ orig_lhs, try int_value_aa(ty, arena, zcu) },
            0b10 => .{ try int_value_aa(ty, arena, zcu), orig_rhs },
            0b11 => return zcu.undef_value(ty),
        };
    };

    if (ty.to_intern() == .bool_type) return make_bool(lhs.to_bool() or rhs.to_bool());

    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, zcu);
    const rhs_bigint = rhs.to_big_int(&rhs_space, zcu);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.bit_or(lhs_bigint, rhs_bigint);
    return zcu.int_value_big(ty, result_bigint.to_const());
}

/// operands must be (vectors of) integers; handles undefined scalars.
pub fn bitwise_xor(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try bitwise_xor_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return bitwise_xor_scalar(lhs, rhs, ty, allocator, mod);
}

/// operands must be integers; handles undefined.
pub fn bitwise_xor_scalar(lhs: Value, rhs: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (lhs.is_undef(mod) or rhs.is_undef(mod)) return Value.from_interned((try mod.intern(.{ .undef = ty.to_intern() })));
    if (ty.to_intern() == .bool_type) return make_bool(lhs.to_bool() != rhs.to_bool());

    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try arena.alloc(
        std.math.big.Limb,
        // + 1 for negatives
        @max(lhs_bigint.limbs.len, rhs_bigint.limbs.len) + 1,
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    result_bigint.bit_xor(lhs_bigint, rhs_bigint);
    return mod.int_value_big(ty, result_bigint.to_const());
}

/// If the value overflowed the type, returns a comptime_int (or vector thereof) instead, setting
/// overflow_idx to the vector index the overflow was at (or 0 for a scalar).
pub fn int_div(lhs: Value, rhs: Value, ty: Type, overflow_idx: *?usize, allocator: Allocator, mod: *Module) !Value {
    var overflow: usize = undefined;
    return int_div_inner(lhs, rhs, ty, &overflow, allocator, mod) catch |err| switch (err) {
        error.Overflow => {
            const is_vec = ty.is_vector(mod);
            overflow_idx.* = if (is_vec) overflow else 0;
            const safe_ty = if (is_vec) try mod.vector_type(.{
                .len = ty.vector_len(mod),
                .child = .comptime_int_type,
            }) else Type.comptime_int;
            return int_div_inner(lhs, rhs, safe_ty, undefined, allocator, mod) catch |err1| switch (err1) {
                error.Overflow => unreachable,
                else => |e| return e,
            };
        },
        else => |e| return e,
    };
}

fn int_div_inner(lhs: Value, rhs: Value, ty: Type, overflow_idx: *usize, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            const val = int_div_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod) catch |err| switch (err) {
                error.Overflow => {
                    overflow_idx.* = i;
                    return error.Overflow;
                },
                else => |e| return e,
            };
            scalar.* = val.to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_div_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn int_div_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs_q = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len,
    );
    const limbs_r = try allocator.alloc(
        std.math.big.Limb,
        rhs_bigint.limbs.len,
    );
    const limbs_buffer = try allocator.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_div_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    var result_q = BigIntMutable{ .limbs = limbs_q, .positive = undefined, .len = undefined };
    var result_r = BigIntMutable{ .limbs = limbs_r, .positive = undefined, .len = undefined };
    result_q.div_trunc(&result_r, lhs_bigint, rhs_bigint, limbs_buffer);
    if (ty.to_intern() != .comptime_int_type) {
        const info = ty.int_info(mod);
        if (!result_q.to_const().fits_in_twos_comp(info.signedness, info.bits)) {
            return error.Overflow;
        }
    }
    return mod.int_value_big(ty, result_q.to_const());
}

pub fn int_div_floor(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try int_div_floor_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_div_floor_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn int_div_floor_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs_q = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len,
    );
    const limbs_r = try allocator.alloc(
        std.math.big.Limb,
        rhs_bigint.limbs.len,
    );
    const limbs_buffer = try allocator.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_div_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    var result_q = BigIntMutable{ .limbs = limbs_q, .positive = undefined, .len = undefined };
    var result_r = BigIntMutable{ .limbs = limbs_r, .positive = undefined, .len = undefined };
    result_q.div_floor(&result_r, lhs_bigint, rhs_bigint, limbs_buffer);
    return mod.int_value_big(ty, result_q.to_const());
}

pub fn int_mod(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try int_mod_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_mod_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn int_mod_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs_q = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len,
    );
    const limbs_r = try allocator.alloc(
        std.math.big.Limb,
        rhs_bigint.limbs.len,
    );
    const limbs_buffer = try allocator.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_div_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len),
    );
    var result_q = BigIntMutable{ .limbs = limbs_q, .positive = undefined, .len = undefined };
    var result_r = BigIntMutable{ .limbs = limbs_r, .positive = undefined, .len = undefined };
    result_q.div_floor(&result_r, lhs_bigint, rhs_bigint, limbs_buffer);
    return mod.int_value_big(ty, result_r.to_const());
}

/// Returns true if the value is a floating point type and is NaN. Returns false otherwise.
pub fn is_nan(val: Value, mod: *const Module) bool {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .float => |float| switch (float.storage) {
            inline else => |x| std.math.is_nan(x),
        },
        else => false,
    };
}

/// Returns true if the value is a floating point type and is infinite. Returns false otherwise.
pub fn is_inf(val: Value, mod: *const Module) bool {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .float => |float| switch (float.storage) {
            inline else => |x| std.math.is_inf(x),
        },
        else => false,
    };
}

pub fn is_negative_inf(val: Value, mod: *const Module) bool {
    return switch (mod.intern_pool.index_to_key(val.to_intern())) {
        .float => |float| switch (float.storage) {
            inline else => |x| std.math.is_negative_inf(x),
        },
        else => false,
    };
}

pub fn float_rem(lhs: Value, rhs: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_rem_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_rem_scalar(lhs, rhs, float_type, mod);
}

pub fn float_rem_scalar(lhs: Value, rhs: Value, float_type: Type, mod: *Module) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @rem(lhs.to_float(f16, mod), rhs.to_float(f16, mod)) },
        32 => .{ .f32 = @rem(lhs.to_float(f32, mod), rhs.to_float(f32, mod)) },
        64 => .{ .f64 = @rem(lhs.to_float(f64, mod), rhs.to_float(f64, mod)) },
        80 => .{ .f80 = @rem(lhs.to_float(f80, mod), rhs.to_float(f80, mod)) },
        128 => .{ .f128 = @rem(lhs.to_float(f128, mod), rhs.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_mod(lhs: Value, rhs: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_mod_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_mod_scalar(lhs, rhs, float_type, mod);
}

pub fn float_mod_scalar(lhs: Value, rhs: Value, float_type: Type, mod: *Module) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @mod(lhs.to_float(f16, mod), rhs.to_float(f16, mod)) },
        32 => .{ .f32 = @mod(lhs.to_float(f32, mod), rhs.to_float(f32, mod)) },
        64 => .{ .f64 = @mod(lhs.to_float(f64, mod), rhs.to_float(f64, mod)) },
        80 => .{ .f80 = @mod(lhs.to_float(f80, mod), rhs.to_float(f80, mod)) },
        128 => .{ .f128 = @mod(lhs.to_float(f128, mod), rhs.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

/// If the value overflowed the type, returns a comptime_int (or vector thereof) instead, setting
/// overflow_idx to the vector index the overflow was at (or 0 for a scalar).
pub fn int_mul(lhs: Value, rhs: Value, ty: Type, overflow_idx: *?usize, allocator: Allocator, mod: *Module) !Value {
    var overflow: usize = undefined;
    return int_mul_inner(lhs, rhs, ty, &overflow, allocator, mod) catch |err| switch (err) {
        error.Overflow => {
            const is_vec = ty.is_vector(mod);
            overflow_idx.* = if (is_vec) overflow else 0;
            const safe_ty = if (is_vec) try mod.vector_type(.{
                .len = ty.vector_len(mod),
                .child = .comptime_int_type,
            }) else Type.comptime_int;
            return int_mul_inner(lhs, rhs, safe_ty, undefined, allocator, mod) catch |err1| switch (err1) {
                error.Overflow => unreachable,
                else => |e| return e,
            };
        },
        else => |e| return e,
    };
}

fn int_mul_inner(lhs: Value, rhs: Value, ty: Type, overflow_idx: *usize, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            const val = int_mul_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod) catch |err| switch (err) {
                error.Overflow => {
                    overflow_idx.* = i;
                    return error.Overflow;
                },
                else => |e| return e,
            };
            scalar.* = val.to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_mul_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn int_mul_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.to_intern() != .comptime_int_type) {
        const res = try int_mul_with_overflow_scalar(lhs, rhs, ty, allocator, mod);
        if (res.overflow_bit.compare_all_with_zero(.neq, mod)) return error.Overflow;
        return res.wrapped_result;
    }
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    var rhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const rhs_bigint = rhs.to_big_int(&rhs_space, mod);
    const limbs = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len + rhs_bigint.limbs.len,
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };
    const limbs_buffer = try allocator.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_mul_limbs_buffer_len(lhs_bigint.limbs.len, rhs_bigint.limbs.len, 1),
    );
    defer allocator.free(limbs_buffer);
    result_bigint.mul(lhs_bigint, rhs_bigint, limbs_buffer, allocator);
    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn int_trunc(val: Value, ty: Type, allocator: Allocator, signedness: std.builtin.Signedness, bits: u16, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try int_trunc_scalar(elem_val, scalar_ty, allocator, signedness, bits, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_trunc_scalar(val, ty, allocator, signedness, bits, mod);
}

/// This variant may vectorize on `bits`. Asserts that `bits` is a (vector of) `u16`.
pub fn int_trunc_bits_as_value(
    val: Value,
    ty: Type,
    allocator: Allocator,
    signedness: std.builtin.Signedness,
    bits: Value,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            const bits_elem = try bits.elem_value(mod, i);
            scalar.* = (try int_trunc_scalar(elem_val, scalar_ty, allocator, signedness, @int_cast(bits_elem.to_unsigned_int(mod)), mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return int_trunc_scalar(val, ty, allocator, signedness, @int_cast(bits.to_unsigned_int(mod)), mod);
}

pub fn int_trunc_scalar(
    val: Value,
    ty: Type,
    allocator: Allocator,
    signedness: std.builtin.Signedness,
    bits: u16,
    zcu: *Zcu,
) !Value {
    if (bits == 0) return zcu.int_value(ty, 0);

    if (val.is_undef(zcu)) return zcu.undef_value(ty);

    var val_space: Value.BigIntSpace = undefined;
    const val_bigint = val.to_big_int(&val_space, zcu);

    const limbs = try allocator.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(bits),
    );
    var result_bigint = BigIntMutable{ .limbs = limbs, .positive = undefined, .len = undefined };

    result_bigint.truncate(val_bigint, signedness, bits);
    return zcu.int_value_big(ty, result_bigint.to_const());
}

pub fn shl(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try shl_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return shl_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn shl_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const shift: usize = @int_cast(rhs.to_unsigned_int(mod));
    const limbs = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len + (shift / (@size_of(std.math.big.Limb) * 8)) + 1,
    );
    var result_bigint = BigIntMutable{
        .limbs = limbs,
        .positive = undefined,
        .len = undefined,
    };
    result_bigint.shift_left(lhs_bigint, shift);
    if (ty.to_intern() != .comptime_int_type) {
        const int_info = ty.int_info(mod);
        result_bigint.truncate(result_bigint.to_const(), int_info.signedness, int_info.bits);
    }

    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn shl_with_overflow(
    lhs: Value,
    rhs: Value,
    ty: Type,
    allocator: Allocator,
    mod: *Module,
) !OverflowArithmeticResult {
    if (ty.zig_type_tag(mod) == .Vector) {
        const vec_len = ty.vector_len(mod);
        const overflowed_data = try allocator.alloc(InternPool.Index, vec_len);
        const result_data = try allocator.alloc(InternPool.Index, vec_len);
        const scalar_ty = ty.scalar_type(mod);
        for (overflowed_data, result_data, 0..) |*of, *scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            const of_math_result = try shl_with_overflow_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod);
            of.* = of_math_result.overflow_bit.to_intern();
            scalar.* = of_math_result.wrapped_result.to_intern();
        }
        return OverflowArithmeticResult{
            .overflow_bit = Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = (try mod.vector_type(.{ .len = vec_len, .child = .u1_type })).to_intern(),
                .storage = .{ .elems = overflowed_data },
            } }))),
            .wrapped_result = Value.from_interned((try mod.intern(.{ .aggregate = .{
                .ty = ty.to_intern(),
                .storage = .{ .elems = result_data },
            } }))),
        };
    }
    return shl_with_overflow_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn shl_with_overflow_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    allocator: Allocator,
    mod: *Module,
) !OverflowArithmeticResult {
    const info = ty.int_info(mod);
    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const shift: usize = @int_cast(rhs.to_unsigned_int(mod));
    const limbs = try allocator.alloc(
        std.math.big.Limb,
        lhs_bigint.limbs.len + (shift / (@size_of(std.math.big.Limb) * 8)) + 1,
    );
    var result_bigint = BigIntMutable{
        .limbs = limbs,
        .positive = undefined,
        .len = undefined,
    };
    result_bigint.shift_left(lhs_bigint, shift);
    const overflowed = !result_bigint.to_const().fits_in_twos_comp(info.signedness, info.bits);
    if (overflowed) {
        result_bigint.truncate(result_bigint.to_const(), info.signedness, info.bits);
    }
    return OverflowArithmeticResult{
        .overflow_bit = try mod.int_value(Type.u1, @int_from_bool(overflowed)),
        .wrapped_result = try mod.int_value_big(ty, result_bigint.to_const()),
    };
}

pub fn shl_sat(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try shl_sat_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return shl_sat_scalar(lhs, rhs, ty, arena, mod);
}

pub fn shl_sat_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    const info = ty.int_info(mod);

    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const shift: usize = @int_cast(rhs.to_unsigned_int(mod));
    const limbs = try arena.alloc(
        std.math.big.Limb,
        std.math.big.int.calc_twos_comp_limb_count(info.bits) + 1,
    );
    var result_bigint = BigIntMutable{
        .limbs = limbs,
        .positive = undefined,
        .len = undefined,
    };
    result_bigint.shift_left_sat(lhs_bigint, shift, info.signedness, info.bits);
    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn shl_trunc(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try shl_trunc_scalar(lhs_elem, rhs_elem, scalar_ty, arena, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return shl_trunc_scalar(lhs, rhs, ty, arena, mod);
}

pub fn shl_trunc_scalar(
    lhs: Value,
    rhs: Value,
    ty: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    const shifted = try lhs.shl(rhs, ty, arena, mod);
    const int_info = ty.int_info(mod);
    const truncated = try shifted.int_trunc(ty, arena, int_info.signedness, int_info.bits, mod);
    return truncated;
}

pub fn shr(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try allocator.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try shr_scalar(lhs_elem, rhs_elem, scalar_ty, allocator, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return shr_scalar(lhs, rhs, ty, allocator, mod);
}

pub fn shr_scalar(lhs: Value, rhs: Value, ty: Type, allocator: Allocator, mod: *Module) !Value {
    // TODO is this a performance issue? maybe we should try the operation without
    // resorting to BigInt first.
    var lhs_space: Value.BigIntSpace = undefined;
    const lhs_bigint = lhs.to_big_int(&lhs_space, mod);
    const shift: usize = @int_cast(rhs.to_unsigned_int(mod));

    const result_limbs = lhs_bigint.limbs.len -| (shift / (@size_of(std.math.big.Limb) * 8));
    if (result_limbs == 0) {
        // The shift is enough to remove all the bits from the number, which means the
        // result is 0 or -1 depending on the sign.
        if (lhs_bigint.positive) {
            return mod.int_value(ty, 0);
        } else {
            return mod.int_value(ty, -1);
        }
    }

    const limbs = try allocator.alloc(
        std.math.big.Limb,
        result_limbs,
    );
    var result_bigint = BigIntMutable{
        .limbs = limbs,
        .positive = undefined,
        .len = undefined,
    };
    result_bigint.shift_right(lhs_bigint, shift);
    return mod.int_value_big(ty, result_bigint.to_const());
}

pub fn float_neg(
    val: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try float_neg_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_neg_scalar(val, float_type, mod);
}

pub fn float_neg_scalar(
    val: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = -val.to_float(f16, mod) },
        32 => .{ .f32 = -val.to_float(f32, mod) },
        64 => .{ .f64 = -val.to_float(f64, mod) },
        80 => .{ .f80 = -val.to_float(f80, mod) },
        128 => .{ .f128 = -val.to_float(f128, mod) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_add(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_add_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_add_scalar(lhs, rhs, float_type, mod);
}

pub fn float_add_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = lhs.to_float(f16, mod) + rhs.to_float(f16, mod) },
        32 => .{ .f32 = lhs.to_float(f32, mod) + rhs.to_float(f32, mod) },
        64 => .{ .f64 = lhs.to_float(f64, mod) + rhs.to_float(f64, mod) },
        80 => .{ .f80 = lhs.to_float(f80, mod) + rhs.to_float(f80, mod) },
        128 => .{ .f128 = lhs.to_float(f128, mod) + rhs.to_float(f128, mod) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_sub(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_sub_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_sub_scalar(lhs, rhs, float_type, mod);
}

pub fn float_sub_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = lhs.to_float(f16, mod) - rhs.to_float(f16, mod) },
        32 => .{ .f32 = lhs.to_float(f32, mod) - rhs.to_float(f32, mod) },
        64 => .{ .f64 = lhs.to_float(f64, mod) - rhs.to_float(f64, mod) },
        80 => .{ .f80 = lhs.to_float(f80, mod) - rhs.to_float(f80, mod) },
        128 => .{ .f128 = lhs.to_float(f128, mod) - rhs.to_float(f128, mod) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_div(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_div_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_div_scalar(lhs, rhs, float_type, mod);
}

pub fn float_div_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = lhs.to_float(f16, mod) / rhs.to_float(f16, mod) },
        32 => .{ .f32 = lhs.to_float(f32, mod) / rhs.to_float(f32, mod) },
        64 => .{ .f64 = lhs.to_float(f64, mod) / rhs.to_float(f64, mod) },
        80 => .{ .f80 = lhs.to_float(f80, mod) / rhs.to_float(f80, mod) },
        128 => .{ .f128 = lhs.to_float(f128, mod) / rhs.to_float(f128, mod) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_div_floor(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_div_floor_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_div_floor_scalar(lhs, rhs, float_type, mod);
}

pub fn float_div_floor_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @div_floor(lhs.to_float(f16, mod), rhs.to_float(f16, mod)) },
        32 => .{ .f32 = @div_floor(lhs.to_float(f32, mod), rhs.to_float(f32, mod)) },
        64 => .{ .f64 = @div_floor(lhs.to_float(f64, mod), rhs.to_float(f64, mod)) },
        80 => .{ .f80 = @div_floor(lhs.to_float(f80, mod), rhs.to_float(f80, mod)) },
        128 => .{ .f128 = @div_floor(lhs.to_float(f128, mod), rhs.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_div_trunc(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_div_trunc_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_div_trunc_scalar(lhs, rhs, float_type, mod);
}

pub fn float_div_trunc_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @div_trunc(lhs.to_float(f16, mod), rhs.to_float(f16, mod)) },
        32 => .{ .f32 = @div_trunc(lhs.to_float(f32, mod), rhs.to_float(f32, mod)) },
        64 => .{ .f64 = @div_trunc(lhs.to_float(f64, mod), rhs.to_float(f64, mod)) },
        80 => .{ .f80 = @div_trunc(lhs.to_float(f80, mod), rhs.to_float(f80, mod)) },
        128 => .{ .f128 = @div_trunc(lhs.to_float(f128, mod), rhs.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn float_mul(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const lhs_elem = try lhs.elem_value(mod, i);
            const rhs_elem = try rhs.elem_value(mod, i);
            scalar.* = (try float_mul_scalar(lhs_elem, rhs_elem, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return float_mul_scalar(lhs, rhs, float_type, mod);
}

pub fn float_mul_scalar(
    lhs: Value,
    rhs: Value,
    float_type: Type,
    mod: *Module,
) !Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = lhs.to_float(f16, mod) * rhs.to_float(f16, mod) },
        32 => .{ .f32 = lhs.to_float(f32, mod) * rhs.to_float(f32, mod) },
        64 => .{ .f64 = lhs.to_float(f64, mod) * rhs.to_float(f64, mod) },
        80 => .{ .f80 = lhs.to_float(f80, mod) * rhs.to_float(f80, mod) },
        128 => .{ .f128 = lhs.to_float(f128, mod) * rhs.to_float(f128, mod) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn sqrt(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try sqrt_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return sqrt_scalar(val, float_type, mod);
}

pub fn sqrt_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @sqrt(val.to_float(f16, mod)) },
        32 => .{ .f32 = @sqrt(val.to_float(f32, mod)) },
        64 => .{ .f64 = @sqrt(val.to_float(f64, mod)) },
        80 => .{ .f80 = @sqrt(val.to_float(f80, mod)) },
        128 => .{ .f128 = @sqrt(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn sin(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try sin_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return sin_scalar(val, float_type, mod);
}

pub fn sin_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @sin(val.to_float(f16, mod)) },
        32 => .{ .f32 = @sin(val.to_float(f32, mod)) },
        64 => .{ .f64 = @sin(val.to_float(f64, mod)) },
        80 => .{ .f80 = @sin(val.to_float(f80, mod)) },
        128 => .{ .f128 = @sin(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn cos(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try cos_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return cos_scalar(val, float_type, mod);
}

pub fn cos_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @cos(val.to_float(f16, mod)) },
        32 => .{ .f32 = @cos(val.to_float(f32, mod)) },
        64 => .{ .f64 = @cos(val.to_float(f64, mod)) },
        80 => .{ .f80 = @cos(val.to_float(f80, mod)) },
        128 => .{ .f128 = @cos(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn tan(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try tan_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return tan_scalar(val, float_type, mod);
}

pub fn tan_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @tan(val.to_float(f16, mod)) },
        32 => .{ .f32 = @tan(val.to_float(f32, mod)) },
        64 => .{ .f64 = @tan(val.to_float(f64, mod)) },
        80 => .{ .f80 = @tan(val.to_float(f80, mod)) },
        128 => .{ .f128 = @tan(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn exp(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try exp_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return exp_scalar(val, float_type, mod);
}

pub fn exp_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @exp(val.to_float(f16, mod)) },
        32 => .{ .f32 = @exp(val.to_float(f32, mod)) },
        64 => .{ .f64 = @exp(val.to_float(f64, mod)) },
        80 => .{ .f80 = @exp(val.to_float(f80, mod)) },
        128 => .{ .f128 = @exp(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn exp2(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try exp2_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return exp2_scalar(val, float_type, mod);
}

pub fn exp2_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @exp2(val.to_float(f16, mod)) },
        32 => .{ .f32 = @exp2(val.to_float(f32, mod)) },
        64 => .{ .f64 = @exp2(val.to_float(f64, mod)) },
        80 => .{ .f80 = @exp2(val.to_float(f80, mod)) },
        128 => .{ .f128 = @exp2(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn log(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try log_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return log_scalar(val, float_type, mod);
}

pub fn log_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @log(val.to_float(f16, mod)) },
        32 => .{ .f32 = @log(val.to_float(f32, mod)) },
        64 => .{ .f64 = @log(val.to_float(f64, mod)) },
        80 => .{ .f80 = @log(val.to_float(f80, mod)) },
        128 => .{ .f128 = @log(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn log2(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try log2_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return log2_scalar(val, float_type, mod);
}

pub fn log2_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @log2(val.to_float(f16, mod)) },
        32 => .{ .f32 = @log2(val.to_float(f32, mod)) },
        64 => .{ .f64 = @log2(val.to_float(f64, mod)) },
        80 => .{ .f80 = @log2(val.to_float(f80, mod)) },
        128 => .{ .f128 = @log2(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn log10(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try log10_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return log10_scalar(val, float_type, mod);
}

pub fn log10_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @log10(val.to_float(f16, mod)) },
        32 => .{ .f32 = @log10(val.to_float(f32, mod)) },
        64 => .{ .f64 = @log10(val.to_float(f64, mod)) },
        80 => .{ .f80 = @log10(val.to_float(f80, mod)) },
        128 => .{ .f128 = @log10(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn abs(val: Value, ty: Type, arena: Allocator, mod: *Module) !Value {
    if (ty.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, ty.vector_len(mod));
        const scalar_ty = ty.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try abs_scalar(elem_val, scalar_ty, mod, arena)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = ty.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return abs_scalar(val, ty, mod, arena);
}

pub fn abs_scalar(val: Value, ty: Type, mod: *Module, arena: Allocator) Allocator.Error!Value {
    switch (ty.zig_type_tag(mod)) {
        .Int => {
            var buffer: Value.BigIntSpace = undefined;
            var operand_bigint = try val.to_big_int(&buffer, mod).to_managed(arena);
            operand_bigint.abs();

            return mod.int_value_big(try ty.to_unsigned(mod), operand_bigint.to_const());
        },
        .ComptimeInt => {
            var buffer: Value.BigIntSpace = undefined;
            var operand_bigint = try val.to_big_int(&buffer, mod).to_managed(arena);
            operand_bigint.abs();

            return mod.int_value_big(ty, operand_bigint.to_const());
        },
        .ComptimeFloat, .Float => {
            const target = mod.get_target();
            const storage: InternPool.Key.Float.Storage = switch (ty.float_bits(target)) {
                16 => .{ .f16 = @abs(val.to_float(f16, mod)) },
                32 => .{ .f32 = @abs(val.to_float(f32, mod)) },
                64 => .{ .f64 = @abs(val.to_float(f64, mod)) },
                80 => .{ .f80 = @abs(val.to_float(f80, mod)) },
                128 => .{ .f128 = @abs(val.to_float(f128, mod)) },
                else => unreachable,
            };
            return Value.from_interned((try mod.intern(.{ .float = .{
                .ty = ty.to_intern(),
                .storage = storage,
            } })));
        },
        else => unreachable,
    }
}

pub fn floor(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try floor_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return floor_scalar(val, float_type, mod);
}

pub fn floor_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @floor(val.to_float(f16, mod)) },
        32 => .{ .f32 = @floor(val.to_float(f32, mod)) },
        64 => .{ .f64 = @floor(val.to_float(f64, mod)) },
        80 => .{ .f80 = @floor(val.to_float(f80, mod)) },
        128 => .{ .f128 = @floor(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn ceil(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try ceil_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return ceil_scalar(val, float_type, mod);
}

pub fn ceil_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @ceil(val.to_float(f16, mod)) },
        32 => .{ .f32 = @ceil(val.to_float(f32, mod)) },
        64 => .{ .f64 = @ceil(val.to_float(f64, mod)) },
        80 => .{ .f80 = @ceil(val.to_float(f80, mod)) },
        128 => .{ .f128 = @ceil(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn round(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try round_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return round_scalar(val, float_type, mod);
}

pub fn round_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @round(val.to_float(f16, mod)) },
        32 => .{ .f32 = @round(val.to_float(f32, mod)) },
        64 => .{ .f64 = @round(val.to_float(f64, mod)) },
        80 => .{ .f80 = @round(val.to_float(f80, mod)) },
        128 => .{ .f128 = @round(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn trunc(val: Value, float_type: Type, arena: Allocator, mod: *Module) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const elem_val = try val.elem_value(mod, i);
            scalar.* = (try trunc_scalar(elem_val, scalar_ty, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return trunc_scalar(val, float_type, mod);
}

pub fn trunc_scalar(val: Value, float_type: Type, mod: *Module) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @trunc(val.to_float(f16, mod)) },
        32 => .{ .f32 = @trunc(val.to_float(f32, mod)) },
        64 => .{ .f64 = @trunc(val.to_float(f64, mod)) },
        80 => .{ .f80 = @trunc(val.to_float(f80, mod)) },
        128 => .{ .f128 = @trunc(val.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

pub fn mul_add(
    float_type: Type,
    mulend1: Value,
    mulend2: Value,
    addend: Value,
    arena: Allocator,
    mod: *Module,
) !Value {
    if (float_type.zig_type_tag(mod) == .Vector) {
        const result_data = try arena.alloc(InternPool.Index, float_type.vector_len(mod));
        const scalar_ty = float_type.scalar_type(mod);
        for (result_data, 0..) |*scalar, i| {
            const mulend1_elem = try mulend1.elem_value(mod, i);
            const mulend2_elem = try mulend2.elem_value(mod, i);
            const addend_elem = try addend.elem_value(mod, i);
            scalar.* = (try mul_add_scalar(scalar_ty, mulend1_elem, mulend2_elem, addend_elem, mod)).to_intern();
        }
        return Value.from_interned((try mod.intern(.{ .aggregate = .{
            .ty = float_type.to_intern(),
            .storage = .{ .elems = result_data },
        } })));
    }
    return mul_add_scalar(float_type, mulend1, mulend2, addend, mod);
}

pub fn mul_add_scalar(
    float_type: Type,
    mulend1: Value,
    mulend2: Value,
    addend: Value,
    mod: *Module,
) Allocator.Error!Value {
    const target = mod.get_target();
    const storage: InternPool.Key.Float.Storage = switch (float_type.float_bits(target)) {
        16 => .{ .f16 = @mul_add(f16, mulend1.to_float(f16, mod), mulend2.to_float(f16, mod), addend.to_float(f16, mod)) },
        32 => .{ .f32 = @mul_add(f32, mulend1.to_float(f32, mod), mulend2.to_float(f32, mod), addend.to_float(f32, mod)) },
        64 => .{ .f64 = @mul_add(f64, mulend1.to_float(f64, mod), mulend2.to_float(f64, mod), addend.to_float(f64, mod)) },
        80 => .{ .f80 = @mul_add(f80, mulend1.to_float(f80, mod), mulend2.to_float(f80, mod), addend.to_float(f80, mod)) },
        128 => .{ .f128 = @mul_add(f128, mulend1.to_float(f128, mod), mulend2.to_float(f128, mod), addend.to_float(f128, mod)) },
        else => unreachable,
    };
    return Value.from_interned((try mod.intern(.{ .float = .{
        .ty = float_type.to_intern(),
        .storage = storage,
    } })));
}

/// If the value is represented in-memory as a series of bytes that all
/// have the same value, return that byte value, otherwise null.
pub fn has_repeated_byte_repr(val: Value, ty: Type, mod: *Module) !?u8 {
    const abi_size = std.math.cast(usize, ty.abi_size(mod)) orelse return null;
    assert(abi_size >= 1);
    const byte_buffer = try mod.gpa.alloc(u8, abi_size);
    defer mod.gpa.free(byte_buffer);

    write_to_memory(val, ty, mod, byte_buffer) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ReinterpretDeclRef => return null,
        // TODO: The write_to_memory function was originally created for the purpose
        // of comptime pointer casting. However, it is now additionally being used
        // for checking the actual memory layout that will be generated by machine
        // code late in compilation. So, this error handling is too aggressive and
        // causes some false negatives, causing less-than-ideal code generation.
        error.IllDefinedMemoryLayout => return null,
        error.Unimplemented => return null,
    };
    const first_byte = byte_buffer[0];
    for (byte_buffer[1..]) |byte| {
        if (byte != first_byte) return null;
    }
    return first_byte;
}

pub fn is_generic_poison(val: Value) bool {
    return val.to_intern() == .generic_poison;
}

pub fn type_of(val: Value, zcu: *const Zcu) Type {
    return Type.from_interned(zcu.intern_pool.type_of(val.to_intern()));
}

/// For an integer (comptime or fixed-width) `val`, returns the comptime-known bounds of the value.
/// If `val` is not undef, the bounds are both `val`.
/// If `val` is undef and has a fixed-width type, the bounds are the bounds of the type.
/// If `val` is undef and is a `comptime_int`, returns null.
pub fn int_value_bounds(val: Value, mod: *Module) !?[2]Value {
    if (!val.is_undef(mod)) return .{ val, val };
    const ty = mod.intern_pool.type_of(val.to_intern());
    if (ty == .comptime_int_type) return null;
    return .{
        try Type.from_interned(ty).min_int(mod, Type.from_interned(ty)),
        try Type.from_interned(ty).max_int(mod, Type.from_interned(ty)),
    };
}

pub const BigIntSpace = InternPool.Key.Int.Storage.BigIntSpace;

pub const zero_usize: Value = .{ .ip_index = .zero_usize };
pub const zero_u8: Value = .{ .ip_index = .zero_u8 };
pub const zero_comptime_int: Value = .{ .ip_index = .zero };
pub const one_comptime_int: Value = .{ .ip_index = .one };
pub const negative_one_comptime_int: Value = .{ .ip_index = .negative_one };
pub const undef: Value = .{ .ip_index = .undef };
pub const @"void": Value = .{ .ip_index = .void_value };
pub const @"null": Value = .{ .ip_index = .null_value };
pub const @"false": Value = .{ .ip_index = .bool_false };
pub const @"true": Value = .{ .ip_index = .bool_true };
pub const @"unreachable": Value = .{ .ip_index = .unreachable_value };

pub const generic_poison: Value = .{ .ip_index = .generic_poison };
pub const generic_poison_type: Value = .{ .ip_index = .generic_poison_type };
pub const empty_struct: Value = .{ .ip_index = .empty_struct };

pub fn make_bool(x: bool) Value {
    return if (x) Value.true else Value.false;
}

pub const RuntimeIndex = InternPool.RuntimeIndex;

/// `parent_ptr` must be a single-pointer to some optional.
/// Returns a pointer to the payload of the optional.
/// This takes a `Sema` because it may need to perform type resolution.
pub fn ptr_opt_payload(parent_ptr: Value, sema: *Sema) !Value {
    const zcu = sema.mod;

    const parent_ptr_ty = parent_ptr.type_of(zcu);
    const opt_ty = parent_ptr_ty.child_type(zcu);

    assert(parent_ptr_ty.ptr_size(zcu) == .One);
    assert(opt_ty.zig_type_tag(zcu) == .Optional);

    const result_ty = try sema.ptr_type(info: {
        var new = parent_ptr_ty.ptr_info(zcu);
        // We can correctly preserve alignment `.none`, since an optional has the same
        // natural alignment as its child type.
        new.child = opt_ty.child_type(zcu).to_intern();
        break :info new;
    });

    if (parent_ptr.is_undef(zcu)) return zcu.undef_value(result_ty);

    if (opt_ty.is_ptr_like_optional(zcu)) {
        // Just reinterpret the pointer, since the layout is well-defined
        return zcu.get_coerced(parent_ptr, result_ty);
    }

    const base_ptr = try parent_ptr.canonicalize_base_ptr(.One, opt_ty, zcu);
    return Value.from_interned(try zcu.intern(.{ .ptr = .{
        .ty = result_ty.to_intern(),
        .base_addr = .{ .opt_payload = base_ptr.to_intern() },
        .byte_offset = 0,
    } }));
}

/// `parent_ptr` must be a single-pointer to some error union.
/// Returns a pointer to the payload of the error union.
/// This takes a `Sema` because it may need to perform type resolution.
pub fn ptr_eu_payload(parent_ptr: Value, sema: *Sema) !Value {
    const zcu = sema.mod;

    const parent_ptr_ty = parent_ptr.type_of(zcu);
    const eu_ty = parent_ptr_ty.child_type(zcu);

    assert(parent_ptr_ty.ptr_size(zcu) == .One);
    assert(eu_ty.zig_type_tag(zcu) == .ErrorUnion);

    const result_ty = try sema.ptr_type(info: {
        var new = parent_ptr_ty.ptr_info(zcu);
        // We can correctly preserve alignment `.none`, since an error union has a
        // natural alignment greater than or equal to that of its payload type.
        new.child = eu_ty.error_union_payload(zcu).to_intern();
        break :info new;
    });

    if (parent_ptr.is_undef(zcu)) return zcu.undef_value(result_ty);

    const base_ptr = try parent_ptr.canonicalize_base_ptr(.One, eu_ty, zcu);
    return Value.from_interned(try zcu.intern(.{ .ptr = .{
        .ty = result_ty.to_intern(),
        .base_addr = .{ .eu_payload = base_ptr.to_intern() },
        .byte_offset = 0,
    } }));
}

/// `parent_ptr` must be a single-pointer to a struct, union, or slice.
/// Returns a pointer to the aggregate field at the specified index.
/// For slices, uses `slice_ptr_index` and `slice_len_index`.
/// This takes a `Sema` because it may need to perform type resolution.
pub fn ptr_field(parent_ptr: Value, field_idx: u32, sema: *Sema) !Value {
    const zcu = sema.mod;

    const parent_ptr_ty = parent_ptr.type_of(zcu);
    const aggregate_ty = parent_ptr_ty.child_type(zcu);

    const parent_ptr_info = parent_ptr_ty.ptr_info(zcu);
    assert(parent_ptr_info.flags.size == .One);

    // Exiting this `switch` indicates that the `field` pointer repsentation should be used.
    // `field_align` may be `.none` to represent the natural alignment of `field_ty`, but is not necessarily.
    const field_ty: Type, const field_align: InternPool.Alignment = switch (aggregate_ty.zig_type_tag(zcu)) {
        .Struct => field: {
            const field_ty = aggregate_ty.struct_field_type(field_idx, zcu);
            switch (aggregate_ty.container_layout(zcu)) {
                .auto => break :field .{ field_ty, try aggregate_ty.struct_field_align_advanced(@int_cast(field_idx), zcu, sema) },
                .@"extern" => {
                    // Well-defined layout, so just offset the pointer appropriately.
                    const byte_off = aggregate_ty.struct_field_offset(field_idx, zcu);
                    const field_align = a: {
                        const parent_align = if (parent_ptr_info.flags.alignment == .none) pa: {
                            break :pa try sema.type_abi_alignment(aggregate_ty);
                        } else parent_ptr_info.flags.alignment;
                        break :a InternPool.Alignment.from_log2_units(@min(parent_align.to_log2_units(), @ctz(byte_off)));
                    };
                    const result_ty = try sema.ptr_type(info: {
                        var new = parent_ptr_info;
                        new.child = field_ty.to_intern();
                        new.flags.alignment = field_align;
                        break :info new;
                    });
                    return parent_ptr.get_offset_ptr(byte_off, result_ty, zcu);
                },
                .@"packed" => switch (aggregate_ty.packed_struct_field_ptr_info(parent_ptr_ty, field_idx, zcu)) {
                    .bit_ptr => |packed_offset| {
                        const result_ty = try zcu.ptr_type(info: {
                            var new = parent_ptr_info;
                            new.packed_offset = packed_offset;
                            new.child = field_ty.to_intern();
                            if (new.flags.alignment == .none) {
                                new.flags.alignment = try sema.type_abi_alignment(aggregate_ty);
                            }
                            break :info new;
                        });
                        return zcu.get_coerced(parent_ptr, result_ty);
                    },
                    .byte_ptr => |ptr_info| {
                        const result_ty = try sema.ptr_type(info: {
                            var new = parent_ptr_info;
                            new.child = field_ty.to_intern();
                            new.packed_offset = .{
                                .host_size = 0,
                                .bit_offset = 0,
                            };
                            new.flags.alignment = ptr_info.alignment;
                            break :info new;
                        });
                        return parent_ptr.get_offset_ptr(ptr_info.offset, result_ty, zcu);
                    },
                },
            }
        },
        .Union => field: {
            const union_obj = zcu.type_to_union(aggregate_ty).?;
            const field_ty = Type.from_interned(union_obj.field_types.get(&zcu.intern_pool)[field_idx]);
            switch (aggregate_ty.container_layout(zcu)) {
                .auto => break :field .{ field_ty, try aggregate_ty.struct_field_align_advanced(@int_cast(field_idx), zcu, sema) },
                .@"extern" => {
                    // Point to the same address.
                    const result_ty = try sema.ptr_type(info: {
                        var new = parent_ptr_info;
                        new.child = field_ty.to_intern();
                        break :info new;
                    });
                    return zcu.get_coerced(parent_ptr, result_ty);
                },
                .@"packed" => {
                    // If the field has an ABI size matching its bit size, then we can continue to use a
                    // non-bit pointer if the parent pointer is also a non-bit pointer.
                    if (parent_ptr_info.packed_offset.host_size == 0 and try sema.type_abi_size(field_ty) * 8 == try field_ty.bit_size_advanced(zcu, sema)) {
                        // We must offset the pointer on big-endian targets, since the bits of packed memory don't align nicely.
                        const byte_offset = switch (zcu.get_target().cpu.arch.endian()) {
                            .little => 0,
                            .big => try sema.type_abi_size(aggregate_ty) - try sema.type_abi_size(field_ty),
                        };
                        const result_ty = try sema.ptr_type(info: {
                            var new = parent_ptr_info;
                            new.child = field_ty.to_intern();
                            new.flags.alignment = InternPool.Alignment.from_log2_units(
                                @ctz(byte_offset | (try parent_ptr_ty.ptr_alignment_advanced(zcu, sema)).to_byte_units().?),
                            );
                            break :info new;
                        });
                        return parent_ptr.get_offset_ptr(byte_offset, result_ty, zcu);
                    } else {
                        // The result must be a bit-pointer if it is not already.
                        const result_ty = try sema.ptr_type(info: {
                            var new = parent_ptr_info;
                            new.child = field_ty.to_intern();
                            if (new.packed_offset.host_size == 0) {
                                new.packed_offset.host_size = @int_cast(((try aggregate_ty.bit_size_advanced(zcu, sema)) + 7) / 8);
                                assert(new.packed_offset.bit_offset == 0);
                            }
                            break :info new;
                        });
                        return zcu.get_coerced(parent_ptr, result_ty);
                    }
                },
            }
        },
        .Pointer => field_ty: {
            assert(aggregate_ty.is_slice(zcu));
            break :field_ty switch (field_idx) {
                Value.slice_ptr_index => .{ aggregate_ty.slice_ptr_field_type(zcu), Type.usize.abi_alignment(zcu) },
                Value.slice_len_index => .{ Type.usize, Type.usize.abi_alignment(zcu) },
                else => unreachable,
            };
        },
        else => unreachable,
    };

    const new_align: InternPool.Alignment = if (parent_ptr_info.flags.alignment != .none) a: {
        const ty_align = try sema.type_abi_alignment(field_ty);
        const true_field_align = if (field_align == .none) ty_align else field_align;
        const new_align = true_field_align.min(parent_ptr_info.flags.alignment);
        if (new_align == ty_align) break :a .none;
        break :a new_align;
    } else field_align;

    const result_ty = try sema.ptr_type(info: {
        var new = parent_ptr_info;
        new.child = field_ty.to_intern();
        new.flags.alignment = new_align;
        break :info new;
    });

    if (parent_ptr.is_undef(zcu)) return zcu.undef_value(result_ty);

    const base_ptr = try parent_ptr.canonicalize_base_ptr(.One, aggregate_ty, zcu);
    return Value.from_interned(try zcu.intern(.{ .ptr = .{
        .ty = result_ty.to_intern(),
        .base_addr = .{ .field = .{
            .base = base_ptr.to_intern(),
            .index = field_idx,
        } },
        .byte_offset = 0,
    } }));
}

/// `orig_parent_ptr` must be either a single-pointer to an array or vector, or a many-pointer or C-pointer or slice.
/// Returns a pointer to the element at the specified index.
/// This takes a `Sema` because it may need to perform type resolution.
pub fn ptr_elem(orig_parent_ptr: Value, field_idx: u64, sema: *Sema) !Value {
    const zcu = sema.mod;

    const parent_ptr = switch (orig_parent_ptr.type_of(zcu).ptr_size(zcu)) {
        .One, .Many, .C => orig_parent_ptr,
        .Slice => orig_parent_ptr.slice_ptr(zcu),
    };

    const parent_ptr_ty = parent_ptr.type_of(zcu);
    const elem_ty = parent_ptr_ty.child_type(zcu);
    const result_ty = try sema.elem_ptr_type(parent_ptr_ty, @int_cast(field_idx));

    if (parent_ptr.is_undef(zcu)) return zcu.undef_value(result_ty);

    if (result_ty.ptr_info(zcu).packed_offset.host_size != 0) {
        // Since we have a bit-pointer, the pointer address should be unchanged.
        assert(elem_ty.zig_type_tag(zcu) == .Vector);
        return zcu.get_coerced(parent_ptr, result_ty);
    }

    const PtrStrat = union(enum) {
        offset: u64,
        elem_ptr: Type, // many-ptr elem ty
    };

    const strat: PtrStrat = switch (parent_ptr_ty.ptr_size(zcu)) {
        .One => switch (elem_ty.zig_type_tag(zcu)) {
            .Vector => .{ .offset = field_idx * @div_exact(try elem_ty.child_type(zcu).bit_size_advanced(zcu, sema), 8) },
            .Array => strat: {
                const arr_elem_ty = elem_ty.child_type(zcu);
                if (try sema.type_requires_comptime(arr_elem_ty)) {
                    break :strat .{ .elem_ptr = arr_elem_ty };
                }
                break :strat .{ .offset = field_idx * try sema.type_abi_size(arr_elem_ty) };
            },
            else => unreachable,
        },

        .Many, .C => if (try sema.type_requires_comptime(elem_ty))
            .{ .elem_ptr = elem_ty }
        else
            .{ .offset = field_idx * try sema.type_abi_size(elem_ty) },

        .Slice => unreachable,
    };

    switch (strat) {
        .offset => |byte_offset| {
            return parent_ptr.get_offset_ptr(byte_offset, result_ty, zcu);
        },
        .elem_ptr => |manyptr_elem_ty| if (field_idx == 0) {
            return zcu.get_coerced(parent_ptr, result_ty);
        } else {
            const arr_base_ty, const arr_base_len = manyptr_elem_ty.array_base(zcu);
            const base_idx = arr_base_len * field_idx;
            const parent_info = zcu.intern_pool.index_to_key(parent_ptr.to_intern()).ptr;
            switch (parent_info.base_addr) {
                .arr_elem => |arr_elem| {
                    if (Value.from_interned(arr_elem.base).type_of(zcu).child_type(zcu).to_intern() == arr_base_ty.to_intern()) {
                        // We already have a pointer to an element of an array of this type.
                        // Just modify the index.
                        return Value.from_interned(try zcu.intern(.{ .ptr = ptr: {
                            var new = parent_info;
                            new.base_addr.arr_elem.index += base_idx;
                            new.ty = result_ty.to_intern();
                            break :ptr new;
                        } }));
                    }
                },
                else => {},
            }
            const base_ptr = try parent_ptr.canonicalize_base_ptr(.Many, arr_base_ty, zcu);
            return Value.from_interned(try zcu.intern(.{ .ptr = .{
                .ty = result_ty.to_intern(),
                .base_addr = .{ .arr_elem = .{
                    .base = base_ptr.to_intern(),
                    .index = base_idx,
                } },
                .byte_offset = 0,
            } }));
        },
    }
}

fn canonicalize_base_ptr(base_ptr: Value, want_size: std.builtin.Type.Pointer.Size, want_child: Type, zcu: *Zcu) !Value {
    const ptr_ty = base_ptr.type_of(zcu);
    const ptr_info = ptr_ty.ptr_info(zcu);

    if (ptr_info.flags.size == want_size and
        ptr_info.child == want_child.to_intern() and
        !ptr_info.flags.is_const and
        !ptr_info.flags.is_volatile and
        !ptr_info.flags.is_allowzero and
        ptr_info.sentinel == .none and
        ptr_info.flags.alignment == .none)
    {
        // Already canonical!
        return base_ptr;
    }

    const new_ty = try zcu.ptr_type(.{
        .child = want_child.to_intern(),
        .sentinel = .none,
        .flags = .{
            .size = want_size,
            .alignment = .none,
            .is_const = false,
            .is_volatile = false,
            .is_allowzero = false,
            .address_space = ptr_info.flags.address_space,
        },
    });
    return zcu.get_coerced(base_ptr, new_ty);
}

pub fn get_offset_ptr(ptr_val: Value, byte_off: u64, new_ty: Type, zcu: *Zcu) !Value {
    if (ptr_val.is_undef(zcu)) return ptr_val;
    var ptr = zcu.intern_pool.index_to_key(ptr_val.to_intern()).ptr;
    ptr.ty = new_ty.to_intern();
    ptr.byte_offset += byte_off;
    return Value.from_interned(try zcu.intern(.{ .ptr = ptr }));
}

pub const PointerDeriveStep = union(enum) {
    int: struct {
        addr: u64,
        ptr_ty: Type,
    },
    decl_ptr: InternPool.DeclIndex,
    anon_decl_ptr: InternPool.Key.Ptr.BaseAddr.AnonDecl,
    comptime_alloc_ptr: struct {
        val: Value,
        ptr_ty: Type,
    },
    comptime_field_ptr: Value,
    eu_payload_ptr: struct {
        parent: *PointerDeriveStep,
        /// This type will never be cast: it is provided for convenience.
        result_ptr_ty: Type,
    },
    opt_payload_ptr: struct {
        parent: *PointerDeriveStep,
        /// This type will never be cast: it is provided for convenience.
        result_ptr_ty: Type,
    },
    field_ptr: struct {
        parent: *PointerDeriveStep,
        field_idx: u32,
        /// This type will never be cast: it is provided for convenience.
        result_ptr_ty: Type,
    },
    elem_ptr: struct {
        parent: *PointerDeriveStep,
        elem_idx: u64,
        /// This type will never be cast: it is provided for convenience.
        result_ptr_ty: Type,
    },
    offset_and_cast: struct {
        parent: *PointerDeriveStep,
        byte_offset: u64,
        new_ptr_ty: Type,
    },

    pub fn ptr_type(step: PointerDeriveStep, zcu: *Zcu) !Type {
        return switch (step) {
            .int => |int| int.ptr_ty,
            .decl_ptr => |decl| try zcu.decl_ptr(decl).decl_ptr_type(zcu),
            .anon_decl_ptr => |ad| Type.from_interned(ad.orig_ty),
            .comptime_alloc_ptr => |info| info.ptr_ty,
            .comptime_field_ptr => |val| try zcu.single_const_ptr_type(val.type_of(zcu)),
            .offset_and_cast => |oac| oac.new_ptr_ty,
            inline .eu_payload_ptr, .opt_payload_ptr, .field_ptr, .elem_ptr => |x| x.result_ptr_ty,
        };
    }
};

pub fn pointer_derivation(ptr_val: Value, arena: Allocator, zcu: *Zcu) Allocator.Error!PointerDeriveStep {
    return ptr_val.pointer_derivation_advanced(arena, zcu, null) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.AnalysisFail,
        error.NeededSourceLocation,
        error.GenericPoison,
        error.ComptimeReturn,
        error.ComptimeBreak,
        => unreachable,
    };
}

/// Given a pointer value, get the sequence of steps to derive it, ideally by taking
/// only field and element pointers with no casts. This can be used by codegen backends
/// which prefer field/elem accesses when lowering constant pointer values.
/// It is also used by the Value printing logic for pointers.
pub fn pointer_derivation_advanced(ptr_val: Value, arena: Allocator, zcu: *Zcu, opt_sema: ?*Sema) !PointerDeriveStep {
    const ptr = zcu.intern_pool.index_to_key(ptr_val.to_intern()).ptr;
    const base_derive: PointerDeriveStep = switch (ptr.base_addr) {
        .int => return .{ .int = .{
            .addr = ptr.byte_offset,
            .ptr_ty = Type.from_interned(ptr.ty),
        } },
        .decl => |decl| .{ .decl_ptr = decl },
        .anon_decl => |ad| base: {
            // A slight tweak: `orig_ty` here is sometimes not `const`, but it ought to be.
            // TODO: fix this in the sites interning anon decls!
            const const_ty = try zcu.ptr_type(info: {
                var info = Type.from_interned(ad.orig_ty).ptr_info(zcu);
                info.flags.is_const = true;
                break :info info;
            });
            break :base .{ .anon_decl_ptr = .{
                .val = ad.val,
                .orig_ty = const_ty.to_intern(),
            } };
        },
        .comptime_alloc => |idx| base: {
            const alloc = opt_sema.?.get_comptime_alloc(idx);
            const val = try alloc.val.intern(zcu, opt_sema.?.arena);
            const ty = val.type_of(zcu);
            break :base .{ .comptime_alloc_ptr = .{
                .val = val,
                .ptr_ty = try zcu.ptr_type(.{
                    .child = ty.to_intern(),
                    .flags = .{
                        .alignment = alloc.alignment,
                    },
                }),
            } };
        },
        .comptime_field => |val| .{ .comptime_field_ptr = Value.from_interned(val) },
        .eu_payload => |eu_ptr| base: {
            const base_ptr = Value.from_interned(eu_ptr);
            const base_ptr_ty = base_ptr.type_of(zcu);
            const parent_step = try arena.create(PointerDeriveStep);
            parent_step.* = try pointer_derivation_advanced(Value.from_interned(eu_ptr), arena, zcu, opt_sema);
            break :base .{ .eu_payload_ptr = .{
                .parent = parent_step,
                .result_ptr_ty = try zcu.adjust_ptr_type_child(base_ptr_ty, base_ptr_ty.child_type(zcu).error_union_payload(zcu)),
            } };
        },
        .opt_payload => |opt_ptr| base: {
            const base_ptr = Value.from_interned(opt_ptr);
            const base_ptr_ty = base_ptr.type_of(zcu);
            const parent_step = try arena.create(PointerDeriveStep);
            parent_step.* = try pointer_derivation_advanced(Value.from_interned(opt_ptr), arena, zcu, opt_sema);
            break :base .{ .opt_payload_ptr = .{
                .parent = parent_step,
                .result_ptr_ty = try zcu.adjust_ptr_type_child(base_ptr_ty, base_ptr_ty.child_type(zcu).optional_child(zcu)),
            } };
        },
        .field => |field| base: {
            const base_ptr = Value.from_interned(field.base);
            const base_ptr_ty = base_ptr.type_of(zcu);
            const agg_ty = base_ptr_ty.child_type(zcu);
            const field_ty, const field_align = switch (agg_ty.zig_type_tag(zcu)) {
                .Struct => .{ agg_ty.struct_field_type(@int_cast(field.index), zcu), try agg_ty.struct_field_align_advanced(@int_cast(field.index), zcu, opt_sema) },
                .Union => .{ agg_ty.union_field_type_by_index(@int_cast(field.index), zcu), try agg_ty.struct_field_align_advanced(@int_cast(field.index), zcu, opt_sema) },
                .Pointer => .{ switch (field.index) {
                    Value.slice_ptr_index => agg_ty.slice_ptr_field_type(zcu),
                    Value.slice_len_index => Type.usize,
                    else => unreachable,
                }, Type.usize.abi_alignment(zcu) },
                else => unreachable,
            };
            const base_align = base_ptr_ty.ptr_alignment(zcu);
            const result_align = field_align.min_strict(base_align);
            const result_ty = try zcu.ptr_type(.{
                .child = field_ty.to_intern(),
                .flags = flags: {
                    var flags = base_ptr_ty.ptr_info(zcu).flags;
                    if (result_align == field_ty.abi_alignment(zcu)) {
                        flags.alignment = .none;
                    } else {
                        flags.alignment = result_align;
                    }
                    break :flags flags;
                },
            });
            const parent_step = try arena.create(PointerDeriveStep);
            parent_step.* = try pointer_derivation_advanced(base_ptr, arena, zcu, opt_sema);
            break :base .{ .field_ptr = .{
                .parent = parent_step,
                .field_idx = @int_cast(field.index),
                .result_ptr_ty = result_ty,
            } };
        },
        .arr_elem => |arr_elem| base: {
            const parent_step = try arena.create(PointerDeriveStep);
            parent_step.* = try pointer_derivation_advanced(Value.from_interned(arr_elem.base), arena, zcu, opt_sema);
            const parent_ptr_info = (try parent_step.ptr_type(zcu)).ptr_info(zcu);
            const result_ptr_ty = try zcu.ptr_type(.{
                .child = parent_ptr_info.child,
                .flags = flags: {
                    var flags = parent_ptr_info.flags;
                    flags.size = .One;
                    break :flags flags;
                },
            });
            break :base .{ .elem_ptr = .{
                .parent = parent_step,
                .elem_idx = arr_elem.index,
                .result_ptr_ty = result_ptr_ty,
            } };
        },
    };

    if (ptr.byte_offset == 0 and ptr.ty == (try base_derive.ptr_type(zcu)).to_intern()) {
        return base_derive;
    }

    const need_child = Type.from_interned(ptr.ty).child_type(zcu);
    if (need_child.comptime_only(zcu)) {
        // No refinement can happen - this pointer is presumably invalid.
        // Just offset it.
        const parent = try arena.create(PointerDeriveStep);
        parent.* = base_derive;
        return .{ .offset_and_cast = .{
            .parent = parent,
            .byte_offset = ptr.byte_offset,
            .new_ptr_ty = Type.from_interned(ptr.ty),
        } };
    }
    const need_bytes = need_child.abi_size(zcu);

    var cur_derive = base_derive;
    var cur_offset = ptr.byte_offset;

    // Refine through fields and array elements as much as possible.

    if (need_bytes > 0) while (true) {
        const cur_ty = (try cur_derive.ptr_type(zcu)).child_type(zcu);
        if (cur_ty.to_intern() == need_child.to_intern() and cur_offset == 0) {
            break;
        }
        switch (cur_ty.zig_type_tag(zcu)) {
            .NoReturn,
            .Type,
            .ComptimeInt,
            .ComptimeFloat,
            .Null,
            .Undefined,
            .EnumLiteral,
            .Opaque,
            .Fn,
            .ErrorUnion,
            .Int,
            .Float,
            .Bool,
            .Void,
            .Pointer,
            .ErrorSet,
            .AnyFrame,
            .Frame,
            .Enum,
            .Vector,
            .Optional,
            .Union,
            => break,

            .Array => {
                const elem_ty = cur_ty.child_type(zcu);
                const elem_size = elem_ty.abi_size(zcu);
                const start_idx = cur_offset / elem_size;
                const end_idx = (cur_offset + need_bytes + elem_size - 1) / elem_size;
                if (end_idx == start_idx + 1) {
                    const parent = try arena.create(PointerDeriveStep);
                    parent.* = cur_derive;
                    cur_derive = .{ .elem_ptr = .{
                        .parent = parent,
                        .elem_idx = start_idx,
                        .result_ptr_ty = try zcu.adjust_ptr_type_child(try parent.ptr_type(zcu), elem_ty),
                    } };
                    cur_offset -= start_idx * elem_size;
                } else {
                    // Go into the first element if needed, but don't go any deeper.
                    if (start_idx > 0) {
                        const parent = try arena.create(PointerDeriveStep);
                        parent.* = cur_derive;
                        cur_derive = .{ .elem_ptr = .{
                            .parent = parent,
                            .elem_idx = start_idx,
                            .result_ptr_ty = try zcu.adjust_ptr_type_child(try parent.ptr_type(zcu), elem_ty),
                        } };
                        cur_offset -= start_idx * elem_size;
                    }
                    break;
                }
            },
            .Struct => switch (cur_ty.container_layout(zcu)) {
                .auto, .@"packed" => break,
                .@"extern" => for (0..cur_ty.struct_field_count(zcu)) |field_idx| {
                    const field_ty = cur_ty.struct_field_type(field_idx, zcu);
                    const start_off = cur_ty.struct_field_offset(field_idx, zcu);
                    const end_off = start_off + field_ty.abi_size(zcu);
                    if (cur_offset >= start_off and cur_offset + need_bytes <= end_off) {
                        const old_ptr_ty = try cur_derive.ptr_type(zcu);
                        const parent_align = old_ptr_ty.ptr_alignment(zcu);
                        const field_align = InternPool.Alignment.from_log2_units(@min(parent_align.to_log2_units(), @ctz(start_off)));
                        const parent = try arena.create(PointerDeriveStep);
                        parent.* = cur_derive;
                        const new_ptr_ty = try zcu.ptr_type(.{
                            .child = field_ty.to_intern(),
                            .flags = flags: {
                                var flags = old_ptr_ty.ptr_info(zcu).flags;
                                if (field_align == field_ty.abi_alignment(zcu)) {
                                    flags.alignment = .none;
                                } else {
                                    flags.alignment = field_align;
                                }
                                break :flags flags;
                            },
                        });
                        cur_derive = .{ .field_ptr = .{
                            .parent = parent,
                            .field_idx = @int_cast(field_idx),
                            .result_ptr_ty = new_ptr_ty,
                        } };
                        cur_offset -= start_off;
                        break;
                    }
                } else break, // pointer spans multiple fields
            },
        }
    };

    if (cur_offset == 0 and (try cur_derive.ptr_type(zcu)).to_intern() == ptr.ty) {
        return cur_derive;
    }

    const parent = try arena.create(PointerDeriveStep);
    parent.* = cur_derive;
    return .{ .offset_and_cast = .{
        .parent = parent,
        .byte_offset = cur_offset,
        .new_ptr_ty = Type.from_interned(ptr.ty),
    } };
}
