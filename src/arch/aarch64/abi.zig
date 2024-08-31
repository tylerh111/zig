const std = @import("std");
const builtin = @import("builtin");
const bits = @import("bits.zig");
const Register = bits.Register;
const RegisterManagerFn = @import("../../register_manager.zig").RegisterManager;
const Type = @import("../../type.zig").Type;
const Module = @import("../../Module.zig");

pub const Class = union(enum) {
    memory,
    byval,
    integer,
    double_integer,
    float_array: u8,
};

/// For `float_array` the second element will be the amount of floats.
pub fn classify_type(ty: Type, mod: *Module) Class {
    std.debug.assert(ty.has_runtime_bits_ignore_comptime(mod));

    var maybe_float_bits: ?u16 = null;
    switch (ty.zig_type_tag(mod)) {
        .Struct => {
            if (ty.container_layout(mod) == .@"packed") return .byval;
            const float_count = count_floats(ty, mod, &maybe_float_bits);
            if (float_count <= sret_float_count) return .{ .float_array = float_count };

            const bit_size = ty.bit_size(mod);
            if (bit_size > 128) return .memory;
            if (bit_size > 64) return .double_integer;
            return .integer;
        },
        .Union => {
            if (ty.container_layout(mod) == .@"packed") return .byval;
            const float_count = count_floats(ty, mod, &maybe_float_bits);
            if (float_count <= sret_float_count) return .{ .float_array = float_count };

            const bit_size = ty.bit_size(mod);
            if (bit_size > 128) return .memory;
            if (bit_size > 64) return .double_integer;
            return .integer;
        },
        .Int, .Enum, .ErrorSet, .Float, .Bool => return .byval,
        .Vector => {
            const bit_size = ty.bit_size(mod);
            // TODO is this controlled by a cpu feature?
            if (bit_size > 128) return .memory;
            return .byval;
        },
        .Optional => {
            std.debug.assert(ty.is_ptr_like_optional(mod));
            return .byval;
        },
        .Pointer => {
            std.debug.assert(!ty.is_slice(mod));
            return .byval;
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
        .Array,
        => unreachable,
    }
}

const sret_float_count = 4;
fn count_floats(ty: Type, mod: *Module, maybe_float_bits: *?u16) u8 {
    const ip = &mod.intern_pool;
    const target = mod.get_target();
    const invalid = std.math.max_int(u8);
    switch (ty.zig_type_tag(mod)) {
        .Union => {
            const union_obj = mod.type_to_union(ty).?;
            var max_count: u8 = 0;
            for (union_obj.field_types.get(ip)) |field_ty| {
                const field_count = count_floats(Type.from_interned(field_ty), mod, maybe_float_bits);
                if (field_count == invalid) return invalid;
                if (field_count > max_count) max_count = field_count;
                if (max_count > sret_float_count) return invalid;
            }
            return max_count;
        },
        .Struct => {
            const fields_len = ty.struct_field_count(mod);
            var count: u8 = 0;
            var i: u32 = 0;
            while (i < fields_len) : (i += 1) {
                const field_ty = ty.struct_field_type(i, mod);
                const field_count = count_floats(field_ty, mod, maybe_float_bits);
                if (field_count == invalid) return invalid;
                count += field_count;
                if (count > sret_float_count) return invalid;
            }
            return count;
        },
        .Float => {
            const float_bits = maybe_float_bits.* orelse {
                maybe_float_bits.* = ty.float_bits(target);
                return 1;
            };
            if (ty.float_bits(target) == float_bits) return 1;
            return invalid;
        },
        .Void => return 0,
        else => return invalid,
    }
}

pub fn get_float_array_type(ty: Type, mod: *Module) ?Type {
    const ip = &mod.intern_pool;
    switch (ty.zig_type_tag(mod)) {
        .Union => {
            const union_obj = mod.type_to_union(ty).?;
            for (union_obj.field_types.get(ip)) |field_ty| {
                if (get_float_array_type(Type.from_interned(field_ty), mod)) |some| return some;
            }
            return null;
        },
        .Struct => {
            const fields_len = ty.struct_field_count(mod);
            var i: u32 = 0;
            while (i < fields_len) : (i += 1) {
                const field_ty = ty.struct_field_type(i, mod);
                if (get_float_array_type(field_ty, mod)) |some| return some;
            }
            return null;
        },
        .Float => return ty,
        else => return null,
    }
}

pub const callee_preserved_regs = [_]Register{
    .x19, .x20, .x21, .x22, .x23,
    .x24, .x25, .x26, .x27, .x28,
};

pub const c_abi_int_param_regs = [_]Register{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };
pub const c_abi_int_return_regs = [_]Register{ .x0, .x1, .x2, .x3, .x4, .x5, .x6, .x7 };

const allocatable_registers = callee_preserved_regs;
pub const RegisterManager = RegisterManagerFn(@import("CodeGen.zig"), Register, &allocatable_registers);

// Register classes
const RegisterBitSet = RegisterManager.RegisterBitSet;
pub const RegisterClass = struct {
    pub const gp: RegisterBitSet = blk: {
        var set = RegisterBitSet.init_empty();
        for (callee_preserved_regs) |reg| {
            const index = RegisterManager.index_of_reg_into_tracked(reg).?;
            set.set(index);
        }
        break :blk set;
    };
};
