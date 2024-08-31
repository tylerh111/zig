const std = @import("std");
const bits = @import("bits.zig");
const Register = bits.Register;
const RegisterManagerFn = @import("../../register_manager.zig").RegisterManager;
const Type = @import("../../type.zig").Type;
const InternPool = @import("../../InternPool.zig");
const Module = @import("../../Module.zig");
const assert = std.debug.assert;

pub const Class = enum { memory, byval, integer, double_integer, fields, none };

pub fn classify_type(ty: Type, mod: *Module) Class {
    const target = mod.get_target();
    std.debug.assert(ty.has_runtime_bits_ignore_comptime(mod));

    const max_byval_size = target.ptr_bit_width() * 2;
    switch (ty.zig_type_tag(mod)) {
        .Struct => {
            const bit_size = ty.bit_size(mod);
            if (ty.container_layout(mod) == .@"packed") {
                if (bit_size > max_byval_size) return .memory;
                return .byval;
            }

            if (std.Target.riscv.feature_set_has(target.cpu.features, .d)) fields: {
                var any_fp = false;
                var field_count: usize = 0;
                for (0..ty.struct_field_count(mod)) |field_index| {
                    const field_ty = ty.struct_field_type(field_index, mod);
                    if (!field_ty.has_runtime_bits_ignore_comptime(mod)) continue;
                    if (field_ty.is_runtime_float())
                        any_fp = true
                    else if (!field_ty.is_abi_int(mod))
                        break :fields;
                    field_count += 1;
                    if (field_count > 2) break :fields;
                }
                std.debug.assert(field_count > 0 and field_count <= 2);
                if (any_fp) return .fields;
            }

            // TODO this doesn't exactly match what clang produces but its better than nothing
            if (bit_size > max_byval_size) return .memory;
            if (bit_size > max_byval_size / 2) return .double_integer;
            return .integer;
        },
        .Union => {
            const bit_size = ty.bit_size(mod);
            if (ty.container_layout(mod) == .@"packed") {
                if (bit_size > max_byval_size) return .memory;
                return .byval;
            }
            // TODO this doesn't exactly match what clang produces but its better than nothing
            if (bit_size > max_byval_size) return .memory;
            if (bit_size > max_byval_size / 2) return .double_integer;
            return .integer;
        },
        .Bool => return .integer,
        .Float => return .byval,
        .Int, .Enum, .ErrorSet => {
            const bit_size = ty.bit_size(mod);
            if (bit_size > max_byval_size) return .memory;
            return .byval;
        },
        .Vector => {
            const bit_size = ty.bit_size(mod);
            if (bit_size > max_byval_size) return .memory;
            return .integer;
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

/// There are a maximum of 8 possible return slots. Returned values are in
/// the beginning of the array; unused slots are filled with .none.
pub fn classify_system(ty: Type, zcu: *Module) [8]Class {
    var result = [1]Class{.none} ** 8;
    const memory_class = [_]Class{
        .memory, .none, .none, .none,
        .none,   .none, .none, .none,
    };
    switch (ty.zig_type_tag(zcu)) {
        .Bool, .Void, .NoReturn => {
            result[0] = .integer;
            return result;
        },
        .Pointer => switch (ty.ptr_size(zcu)) {
            .Slice => {
                result[0] = .integer;
                result[1] = .integer;
                return result;
            },
            else => {
                result[0] = .integer;
                return result;
            },
        },
        .Optional => {
            if (ty.is_ptr_like_optional(zcu)) {
                result[0] = .integer;
                return result;
            }
            result[0] = .integer;
            result[1] = .integer;
            return result;
        },
        .Int, .Enum, .ErrorSet => {
            const int_bits = ty.int_info(zcu).bits;
            if (int_bits <= 64) {
                result[0] = .integer;
                return result;
            }
            if (int_bits <= 128) {
                result[0] = .integer;
                result[1] = .integer;
                return result;
            }
            unreachable; // support > 128 bit int arguments
        },
        .ErrorUnion => {
            const payload_ty = ty.error_union_payload(zcu);
            const payload_bits = payload_ty.bit_size(zcu);

            // the error union itself
            result[0] = .integer;

            // anyerror!void can fit into one register
            if (payload_bits == 0) return result;

            if (payload_bits <= 64) {
                result[1] = .integer;
                return result;
            }

            std.debug.panic("TODO: classify_system ErrorUnion > 64 bit payload", .{});
        },
        .Struct => {
            const layout = ty.container_layout(zcu);
            const ty_size = ty.abi_size(zcu);

            if (layout == .@"packed") {
                assert(ty_size <= 16);
                result[0] = .integer;
                if (ty_size > 8) result[1] = .integer;
                return result;
            }

            return memory_class;
        },
        else => |bad_ty| std.debug.panic("classify_system {s}", .{@tag_name(bad_ty)}),
    }
}

fn classify_struct(
    result: *[8]Class,
    byte_offset: *u64,
    loaded_struct: InternPool.LoadedStructType,
    zcu: *Module,
) void {
    const ip = &zcu.intern_pool;
    var field_it = loaded_struct.iterate_runtime_order(ip);

    while (field_it.next()) |field_index| {
        const field_ty = Type.from_interned(loaded_struct.field_types.get(ip)[field_index]);
        const field_align = loaded_struct.field_align(ip, field_index);
        byte_offset.* = std.mem.align_forward(
            u64,
            byte_offset.*,
            field_align.to_byte_units() orelse field_ty.abi_alignment(zcu).to_byte_units().?,
        );
        if (zcu.type_to_struct(field_ty)) |field_loaded_struct| {
            if (field_loaded_struct.layout != .@"packed") {
                classify_struct(result, byte_offset, field_loaded_struct, zcu);
                continue;
            }
        }
        const field_class = std.mem.slice_to(&classify_system(field_ty, zcu), .none);
        const field_size = field_ty.abi_size(zcu);

        combine: {
            const result_class = &result[@int_cast(byte_offset.* / 8)];
            if (result_class.* == field_class[0]) {
                break :combine;
            }

            if (result_class.* == .none) {
                result_class.* = field_class[0];
                break :combine;
            }
            assert(field_class[0] != .none);

            // "If one of the classes is MEMORY, the result is the MEMORY class."
            if (result_class.* == .memory or field_class[0] == .memory) {
                result_class.* = .memory;
                break :combine;
            }

            // "If one of the classes is INTEGER, the result is the INTEGER."
            if (result_class.* == .integer or field_class[0] == .integer) {
                result_class.* = .integer;
                break :combine;
            }

            result_class.* = .integer;
        }
        @memcpy(result[@int_cast(byte_offset.* / 8 + 1)..][0 .. field_class.len - 1], field_class[1..]);
        byte_offset.* += field_size;
    }
}

pub const callee_preserved_regs = [_]Register{
    // .s0 is ommited to be used as a frame pointer
    .s1, .s2, .s3, .s4, .s5, .s6, .s7, .s8, .s9, .s10, .s11,
};

pub const function_arg_regs = [_]Register{
    .a0, .a1, .a2, .a3, .a4, .a5, .a6, .a7,
};

pub const function_ret_regs = [_]Register{
    .a0, .a1,
};

pub const temporary_regs = [_]Register{
    .t0, .t1, .t2, .t3, .t4, .t5, .t6,
};

const allocatable_registers = callee_preserved_regs ++ function_arg_regs ++ temporary_regs;
pub const RegisterManager = RegisterManagerFn(@import("CodeGen.zig"), Register, &allocatable_registers);

// Register classes
const RegisterBitSet = RegisterManager.RegisterBitSet;
pub const RegisterClass = struct {
    pub const gp: RegisterBitSet = blk: {
        var set = RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = 0,
            .end = callee_preserved_regs.len,
        }, true);
        break :blk set;
    };

    pub const fa: RegisterBitSet = blk: {
        var set = RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = callee_preserved_regs.len,
            .end = callee_preserved_regs.len + function_arg_regs.len,
        }, true);
        break :blk set;
    };

    pub const fr: RegisterBitSet = blk: {
        var set = RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = callee_preserved_regs.len,
            .end = callee_preserved_regs.len + function_ret_regs.len,
        }, true);
        break :blk set;
    };

    pub const tp: RegisterBitSet = blk: {
        var set = RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = callee_preserved_regs.len + function_arg_regs.len,
            .end = callee_preserved_regs.len + function_arg_regs.len + temporary_regs.len,
        }, true);
        break :blk set;
    };
};
