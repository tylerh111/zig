//! Classifies Zig types to follow the C-ABI for Wasm.
//! The convention for Wasm's C-ABI can be found at the tool-conventions repo:
//! https://github.com/WebAssembly/tool-conventions/blob/main/BasicCABI.md
//! When not targeting the C-ABI, Zig is allowed to do derail from this convention.
//! Note: Above mentioned document is not an official specification, therefore called a convention.

const std = @import("std");
const Target = std.Target;
const assert = std.debug.assert;

const Type = @import("../../type.zig").Type;
const Module = @import("../../Module.zig");

/// Defines how to pass a type as part of a function signature,
/// both for parameters as well as return values.
pub const Class = enum { direct, indirect, none };

const none: [2]Class = .{ .none, .none };
const memory: [2]Class = .{ .indirect, .none };
const direct: [2]Class = .{ .direct, .none };

/// Classifies a given Zig type to determine how they must be passed
/// or returned as value within a wasm function.
/// When all elements result in `.none`, no value must be passed in or returned.
pub fn classify_type(ty: Type, mod: *Module) [2]Class {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    if (!ty.has_runtime_bits_ignore_comptime(mod)) return none;
    switch (ty.zig_type_tag(mod)) {
        .Struct => {
            const struct_type = mod.type_to_struct(ty).?;
            if (struct_type.layout == .@"packed") {
                if (ty.bit_size(mod) <= 64) return direct;
                return .{ .direct, .direct };
            }
            if (struct_type.field_types.len > 1) {
                // The struct type is non-scalar.
                return memory;
            }
            const field_ty = Type.from_interned(struct_type.field_types.get(ip)[0]);
            const explicit_align = struct_type.field_align(ip, 0);
            if (explicit_align != .none) {
                if (explicit_align.compare_strict(.gt, field_ty.abi_alignment(mod)))
                    return memory;
            }
            return classify_type(field_ty, mod);
        },
        .Int, .Enum, .ErrorSet => {
            const int_bits = ty.int_info(mod).bits;
            if (int_bits <= 64) return direct;
            if (int_bits <= 128) return .{ .direct, .direct };
            return memory;
        },
        .Float => {
            const float_bits = ty.float_bits(target);
            if (float_bits <= 64) return direct;
            if (float_bits <= 128) return .{ .direct, .direct };
            return memory;
        },
        .Bool => return direct,
        .Vector => return direct,
        .Array => return memory,
        .Optional => {
            assert(ty.is_ptr_like_optional(mod));
            return direct;
        },
        .Pointer => {
            assert(!ty.is_slice(mod));
            return direct;
        },
        .Union => {
            const union_obj = mod.type_to_union(ty).?;
            if (union_obj.get_layout(ip) == .@"packed") {
                if (ty.bit_size(mod) <= 64) return direct;
                return .{ .direct, .direct };
            }
            const layout = ty.union_get_layout(mod);
            assert(layout.tag_size == 0);
            if (union_obj.field_types.len > 1) return memory;
            const first_field_ty = Type.from_interned(union_obj.field_types.get(ip)[0]);
            return classify_type(first_field_ty, mod);
        },
        .ErrorUnion,
        .Frame,
        .AnyFrame,
        .NoReturn,
        .Void,
        .Type,
        .ComptimeFloat,
        .ComptimeInt,
        .Undefined,
        .Null,
        .Fn,
        .Opaque,
        .EnumLiteral,
        => unreachable,
    }
}

/// Returns the scalar type a given type can represent.
/// Asserts given type can be represented as scalar, such as
/// a struct with a single scalar field.
pub fn scalar_type(ty: Type, mod: *Module) Type {
    const ip = &mod.intern_pool;
    switch (ty.zig_type_tag(mod)) {
        .Struct => {
            if (mod.type_to_packed_struct(ty)) |packed_struct| {
                return scalar_type(Type.from_interned(packed_struct.backing_int_type(ip).*), mod);
            } else {
                assert(ty.struct_field_count(mod) == 1);
                return scalar_type(ty.struct_field_type(0, mod), mod);
            }
        },
        .Union => {
            const union_obj = mod.type_to_union(ty).?;
            if (union_obj.get_layout(ip) != .@"packed") {
                const layout = mod.get_union_layout(union_obj);
                if (layout.payload_size == 0 and layout.tag_size != 0) {
                    return scalar_type(ty.union_tag_type_safety(mod).?, mod);
                }
                assert(union_obj.field_types.len == 1);
            }
            const first_field_ty = Type.from_interned(union_obj.field_types.get(ip)[0]);
            return scalar_type(first_field_ty, mod);
        },
        else => return ty,
    }
}
