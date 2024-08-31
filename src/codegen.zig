const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const leb128 = std.leb;
const link = @import("link.zig");
const log = std.log.scoped(.codegen);
const mem = std.mem;
const math = std.math;
const target_util = @import("target.zig");
const trace = @import("tracy.zig").trace;

const Air = @import("Air.zig");
const Allocator = mem.Allocator;
const Compilation = @import("Compilation.zig");
const ErrorMsg = Module.ErrorMsg;
const InternPool = @import("InternPool.zig");
const Liveness = @import("Liveness.zig");
const Zcu = @import("Module.zig");
const Module = Zcu;
const Target = std.Target;
const Type = @import("type.zig").Type;
const Value = @import("Value.zig");
const Zir = std.zig.Zir;
const Alignment = InternPool.Alignment;

pub const Result = union(enum) {
    /// The `code` parameter passed to `generate_symbol` has the value ok.
    ok: void,

    /// There was a codegen error.
    fail: *ErrorMsg,
};

pub const CodeGenError = error{
    OutOfMemory,
    Overflow,
    CodegenFail,
};

pub const DebugInfoOutput = union(enum) {
    dwarf: *link.File.Dwarf.DeclState,
    plan9: *link.File.Plan9.DebugInfoOutput,
    none,
};

pub fn generate_function(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    func_index: InternPool.Index,
    air: Air,
    liveness: Liveness,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
) CodeGenError!Result {
    const zcu = lf.comp.module.?;
    const func = zcu.func_info(func_index);
    const decl = zcu.decl_ptr(func.owner_decl);
    const namespace = zcu.namespace_ptr(decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;
    switch (target.cpu.arch) {
        .arm,
        .armeb,
        => return @import("arch/arm/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        .aarch64,
        .aarch64_be,
        .aarch64_32,
        => return @import("arch/aarch64/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        .riscv64 => return @import("arch/riscv64/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        .sparc64 => return @import("arch/sparc64/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        .x86_64 => return @import("arch/x86_64/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        .wasm32,
        .wasm64,
        => return @import("arch/wasm/CodeGen.zig").generate(lf, src_loc, func_index, air, liveness, code, debug_output),
        else => unreachable,
    }
}

pub fn generate_lazy_function(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    lazy_sym: link.File.LazySymbol,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
) CodeGenError!Result {
    const zcu = lf.comp.module.?;
    const decl_index = lazy_sym.ty.get_owner_decl(zcu);
    const decl = zcu.decl_ptr(decl_index);
    const namespace = zcu.namespace_ptr(decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;
    switch (target.cpu.arch) {
        .x86_64 => return @import("arch/x86_64/CodeGen.zig").generate_lazy(lf, src_loc, lazy_sym, code, debug_output),
        else => unreachable,
    }
}

fn write_float(comptime F: type, f: F, target: Target, endian: std.builtin.Endian, code: []u8) void {
    _ = target;
    const bits = @typeInfo(F).Float.bits;
    const Int = @Type(.{ .Int = .{ .signedness = .unsigned, .bits = bits } });
    const int: Int = @bit_cast(f);
    mem.write_int(Int, code[0..@div_exact(bits, 8)], int, endian);
}

pub fn generate_lazy_symbol(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    lazy_sym: link.File.LazySymbol,
    // TODO don't use an "out" parameter like this; put it in the result instead
    alignment: *Alignment,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
    reloc_info: RelocInfo,
) CodeGenError!Result {
    _ = reloc_info;

    const tracy = trace(@src());
    defer tracy.end();

    const comp = bin_file.comp;
    const zcu = comp.module.?;
    const ip = &zcu.intern_pool;
    const target = comp.root_mod.resolved_target.result;
    const endian = target.cpu.arch.endian();
    const gpa = comp.gpa;

    log.debug("generate_lazy_symbol: kind = {s}, ty = {}", .{
        @tag_name(lazy_sym.kind),
        lazy_sym.ty.fmt(zcu),
    });

    if (lazy_sym.kind == .code) {
        alignment.* = target_util.default_function_alignment(target);
        return generate_lazy_function(bin_file, src_loc, lazy_sym, code, debug_output);
    }

    if (lazy_sym.ty.is_any_error(zcu)) {
        alignment.* = .@"4";
        const err_names = zcu.global_error_set.keys();
        mem.write_int(u32, try code.add_many_as_array(4), @int_cast(err_names.len), endian);
        var offset = code.items.len;
        try code.resize((1 + err_names.len + 1) * 4);
        for (err_names) |err_name_nts| {
            const err_name = err_name_nts.to_slice(ip);
            mem.write_int(u32, code.items[offset..][0..4], @int_cast(code.items.len), endian);
            offset += 4;
            try code.ensure_unused_capacity(err_name.len + 1);
            code.append_slice_assume_capacity(err_name);
            code.append_assume_capacity(0);
        }
        mem.write_int(u32, code.items[offset..][0..4], @int_cast(code.items.len), endian);
        return Result.ok;
    } else if (lazy_sym.ty.zig_type_tag(zcu) == .Enum) {
        alignment.* = .@"1";
        const tag_names = lazy_sym.ty.enum_fields(zcu);
        for (0..tag_names.len) |tag_index| {
            const tag_name = tag_names.get(ip)[tag_index].to_slice(ip);
            try code.ensure_unused_capacity(tag_name.len + 1);
            code.append_slice_assume_capacity(tag_name);
            code.append_assume_capacity(0);
        }
        return Result.ok;
    } else return .{ .fail = try ErrorMsg.create(
        gpa,
        src_loc,
        "TODO implement generate_lazy_symbol for {s} {}",
        .{ @tag_name(lazy_sym.kind), lazy_sym.ty.fmt(zcu) },
    ) };
}

pub fn generate_symbol(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    val: Value,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
    reloc_info: RelocInfo,
) CodeGenError!Result {
    const tracy = trace(@src());
    defer tracy.end();

    const mod = bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    const ty = val.type_of(mod);

    const target = mod.get_target();
    const endian = target.cpu.arch.endian();

    log.debug("generate_symbol: val = {}", .{val.fmt_value(mod, null)});

    if (val.is_undef_deep(mod)) {
        const abi_size = math.cast(usize, ty.abi_size(mod)) orelse return error.Overflow;
        try code.append_ntimes(0xaa, abi_size);
        return .ok;
    }

    switch (ip.index_to_key(val.to_intern())) {
        .int_type,
        .ptr_type,
        .array_type,
        .vector_type,
        .opt_type,
        .anyframe_type,
        .error_union_type,
        .simple_type,
        .struct_type,
        .anon_struct_type,
        .union_type,
        .opaque_type,
        .enum_type,
        .func_type,
        .error_set_type,
        .inferred_error_set_type,
        => unreachable, // types, not values

        .undef => unreachable, // handled above
        .simple_value => |simple_value| switch (simple_value) {
            .undefined,
            .void,
            .null,
            .empty_struct,
            .@"unreachable",
            .generic_poison,
            => unreachable, // non-runtime values
            .false, .true => try code.append(switch (simple_value) {
                .false => 0,
                .true => 1,
                else => unreachable,
            }),
        },
        .variable,
        .extern_func,
        .func,
        .enum_literal,
        .empty_enum_value,
        => unreachable, // non-runtime values
        .int => {
            const abi_size = math.cast(usize, ty.abi_size(mod)) orelse return error.Overflow;
            var space: Value.BigIntSpace = undefined;
            const int_val = val.to_big_int(&space, mod);
            int_val.write_twos_complement(try code.add_many_as_slice(abi_size), endian);
        },
        .err => |err| {
            const int = try mod.get_error_value(err.name);
            try code.writer().write_int(u16, @int_cast(int), endian);
        },
        .error_union => |error_union| {
            const payload_ty = ty.error_union_payload(mod);
            const err_val: u16 = switch (error_union.val) {
                .err_name => |err_name| @int_cast(try mod.get_error_value(err_name)),
                .payload => 0,
            };

            if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                try code.writer().write_int(u16, err_val, endian);
                return .ok;
            }

            const payload_align = payload_ty.abi_alignment(mod);
            const error_align = Type.anyerror.abi_alignment(mod);
            const abi_align = ty.abi_alignment(mod);

            // error value first when its type is larger than the error union's payload
            if (error_align.order(payload_align) == .gt) {
                try code.writer().write_int(u16, err_val, endian);
            }

            // emit payload part of the error union
            {
                const begin = code.items.len;
                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(switch (error_union.val) {
                    .err_name => try mod.intern(.{ .undef = payload_ty.to_intern() }),
                    .payload => |payload| payload,
                }), code, debug_output, reloc_info)) {
                    .ok => {},
                    .fail => |em| return .{ .fail = em },
                }
                const unpadded_end = code.items.len - begin;
                const padded_end = abi_align.forward(unpadded_end);
                const padding = math.cast(usize, padded_end - unpadded_end) orelse return error.Overflow;

                if (padding > 0) {
                    try code.append_ntimes(0, padding);
                }
            }

            // Payload size is larger than error set, so emit our error set last
            if (error_align.compare(.lte, payload_align)) {
                const begin = code.items.len;
                try code.writer().write_int(u16, err_val, endian);
                const unpadded_end = code.items.len - begin;
                const padded_end = abi_align.forward(unpadded_end);
                const padding = math.cast(usize, padded_end - unpadded_end) orelse return error.Overflow;

                if (padding > 0) {
                    try code.append_ntimes(0, padding);
                }
            }
        },
        .enum_tag => |enum_tag| {
            const int_tag_ty = ty.int_tag_type(mod);
            switch (try generate_symbol(bin_file, src_loc, try mod.get_coerced(Value.from_interned(enum_tag.int), int_tag_ty), code, debug_output, reloc_info)) {
                .ok => {},
                .fail => |em| return .{ .fail = em },
            }
        },
        .float => |float| switch (float.storage) {
            .f16 => |f16_val| write_float(f16, f16_val, target, endian, try code.add_many_as_array(2)),
            .f32 => |f32_val| write_float(f32, f32_val, target, endian, try code.add_many_as_array(4)),
            .f64 => |f64_val| write_float(f64, f64_val, target, endian, try code.add_many_as_array(8)),
            .f80 => |f80_val| {
                write_float(f80, f80_val, target, endian, try code.add_many_as_array(10));
                const abi_size = math.cast(usize, ty.abi_size(mod)) orelse return error.Overflow;
                try code.append_ntimes(0, abi_size - 10);
            },
            .f128 => |f128_val| write_float(f128, f128_val, target, endian, try code.add_many_as_array(16)),
        },
        .ptr => switch (try lower_ptr(bin_file, src_loc, val.to_intern(), code, debug_output, reloc_info, 0)) {
            .ok => {},
            .fail => |em| return .{ .fail = em },
        },
        .slice => |slice| {
            switch (try generate_symbol(bin_file, src_loc, Value.from_interned(slice.ptr), code, debug_output, reloc_info)) {
                .ok => {},
                .fail => |em| return .{ .fail = em },
            }
            switch (try generate_symbol(bin_file, src_loc, Value.from_interned(slice.len), code, debug_output, reloc_info)) {
                .ok => {},
                .fail => |em| return .{ .fail = em },
            }
        },
        .opt => {
            const payload_type = ty.optional_child(mod);
            const payload_val = val.optional_value(mod);
            const abi_size = math.cast(usize, ty.abi_size(mod)) orelse return error.Overflow;

            if (ty.optional_repr_is_payload(mod)) {
                if (payload_val) |value| {
                    switch (try generate_symbol(bin_file, src_loc, value, code, debug_output, reloc_info)) {
                        .ok => {},
                        .fail => |em| return Result{ .fail = em },
                    }
                } else {
                    try code.append_ntimes(0, abi_size);
                }
            } else {
                const padding = abi_size - (math.cast(usize, payload_type.abi_size(mod)) orelse return error.Overflow) - 1;
                if (payload_type.has_runtime_bits(mod)) {
                    const value = payload_val orelse Value.from_interned((try mod.intern(.{ .undef = payload_type.to_intern() })));
                    switch (try generate_symbol(bin_file, src_loc, value, code, debug_output, reloc_info)) {
                        .ok => {},
                        .fail => |em| return Result{ .fail = em },
                    }
                }
                try code.writer().write_byte(@int_from_bool(payload_val != null));
                try code.append_ntimes(0, padding);
            }
        },
        .aggregate => |aggregate| switch (ip.index_to_key(ty.to_intern())) {
            .array_type => |array_type| switch (aggregate.storage) {
                .bytes => |bytes| try code.append_slice(bytes.to_slice(array_type.len_including_sentinel(), ip)),
                .elems, .repeated_elem => {
                    var index: u64 = 0;
                    while (index < array_type.len_including_sentinel()) : (index += 1) {
                        switch (try generate_symbol(bin_file, src_loc, Value.from_interned(switch (aggregate.storage) {
                            .bytes => unreachable,
                            .elems => |elems| elems[@int_cast(index)],
                            .repeated_elem => |elem| if (index < array_type.len)
                                elem
                            else
                                array_type.sentinel,
                        }), code, debug_output, reloc_info)) {
                            .ok => {},
                            .fail => |em| return .{ .fail = em },
                        }
                    }
                },
            },
            .vector_type => |vector_type| {
                const abi_size = math.cast(usize, ty.abi_size(mod)) orelse
                    return error.Overflow;
                if (vector_type.child == .bool_type) {
                    const bytes = try code.add_many_as_slice(abi_size);
                    @memset(bytes, 0xaa);
                    var index: usize = 0;
                    const len = math.cast(usize, vector_type.len) orelse return error.Overflow;
                    while (index < len) : (index += 1) {
                        const bit_index = switch (endian) {
                            .big => len - 1 - index,
                            .little => index,
                        };
                        const byte = &bytes[bit_index / 8];
                        const mask = @as(u8, 1) << @truncate(bit_index);
                        if (switch (switch (aggregate.storage) {
                            .bytes => unreachable,
                            .elems => |elems| elems[index],
                            .repeated_elem => |elem| elem,
                        }) {
                            .bool_true => true,
                            .bool_false => false,
                            else => |elem| switch (ip.index_to_key(elem)) {
                                .undef => continue,
                                .int => |int| switch (int.storage) {
                                    .u64 => |x| switch (x) {
                                        0 => false,
                                        1 => true,
                                        else => unreachable,
                                    },
                                    .i64 => |x| switch (x) {
                                        -1 => true,
                                        0 => false,
                                        else => unreachable,
                                    },
                                    else => unreachable,
                                },
                                else => unreachable,
                            },
                        }) byte.* |= mask else byte.* &= ~mask;
                    }
                } else {
                    switch (aggregate.storage) {
                        .bytes => |bytes| try code.append_slice(bytes.to_slice(vector_type.len, ip)),
                        .elems, .repeated_elem => {
                            var index: u64 = 0;
                            while (index < vector_type.len) : (index += 1) {
                                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(switch (aggregate.storage) {
                                    .bytes => unreachable,
                                    .elems => |elems| elems[
                                        math.cast(usize, index) orelse return error.Overflow
                                    ],
                                    .repeated_elem => |elem| elem,
                                }), code, debug_output, reloc_info)) {
                                    .ok => {},
                                    .fail => |em| return .{ .fail = em },
                                }
                            }
                        },
                    }

                    const padding = abi_size -
                        (math.cast(usize, Type.from_interned(vector_type.child).abi_size(mod) * vector_type.len) orelse
                        return error.Overflow);
                    if (padding > 0) try code.append_ntimes(0, padding);
                }
            },
            .anon_struct_type => |tuple| {
                const struct_begin = code.items.len;
                for (
                    tuple.types.get(ip),
                    tuple.values.get(ip),
                    0..,
                ) |field_ty, comptime_val, index| {
                    if (comptime_val != .none) continue;
                    if (!Type.from_interned(field_ty).has_runtime_bits(mod)) continue;

                    const field_val = switch (aggregate.storage) {
                        .bytes => |bytes| try ip.get(mod.gpa, .{ .int = .{
                            .ty = field_ty,
                            .storage = .{ .u64 = bytes.at(index, ip) },
                        } }),
                        .elems => |elems| elems[index],
                        .repeated_elem => |elem| elem,
                    };

                    switch (try generate_symbol(bin_file, src_loc, Value.from_interned(field_val), code, debug_output, reloc_info)) {
                        .ok => {},
                        .fail => |em| return Result{ .fail = em },
                    }
                    const unpadded_field_end = code.items.len - struct_begin;

                    // Pad struct members if required
                    const padded_field_end = ty.struct_field_offset(index + 1, mod);
                    const padding = math.cast(usize, padded_field_end - unpadded_field_end) orelse
                        return error.Overflow;

                    if (padding > 0) {
                        try code.append_ntimes(0, padding);
                    }
                }
            },
            .struct_type => {
                const struct_type = ip.load_struct_type(ty.to_intern());
                switch (struct_type.layout) {
                    .@"packed" => {
                        const abi_size = math.cast(usize, ty.abi_size(mod)) orelse
                            return error.Overflow;
                        const current_pos = code.items.len;
                        try code.append_ntimes(0, abi_size);
                        var bits: u16 = 0;

                        for (struct_type.field_types.get(ip), 0..) |field_ty, index| {
                            const field_val = switch (aggregate.storage) {
                                .bytes => |bytes| try ip.get(mod.gpa, .{ .int = .{
                                    .ty = field_ty,
                                    .storage = .{ .u64 = bytes.at(index, ip) },
                                } }),
                                .elems => |elems| elems[index],
                                .repeated_elem => |elem| elem,
                            };

                            // pointer may point to a decl which must be marked used
                            // but can also result in a relocation. Therefore we handle those separately.
                            if (Type.from_interned(field_ty).zig_type_tag(mod) == .Pointer) {
                                const field_size = math.cast(usize, Type.from_interned(field_ty).abi_size(mod)) orelse
                                    return error.Overflow;
                                var tmp_list = try std.ArrayList(u8).init_capacity(code.allocator, field_size);
                                defer tmp_list.deinit();
                                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(field_val), &tmp_list, debug_output, reloc_info)) {
                                    .ok => @memcpy(code.items[current_pos..][0..tmp_list.items.len], tmp_list.items),
                                    .fail => |em| return Result{ .fail = em },
                                }
                            } else {
                                Value.from_interned(field_val).write_to_packed_memory(Type.from_interned(field_ty), mod, code.items[current_pos..], bits) catch unreachable;
                            }
                            bits += @int_cast(Type.from_interned(field_ty).bit_size(mod));
                        }
                    },
                    .auto, .@"extern" => {
                        const struct_begin = code.items.len;
                        const field_types = struct_type.field_types.get(ip);
                        const offsets = struct_type.offsets.get(ip);

                        var it = struct_type.iterate_runtime_order(ip);
                        while (it.next()) |field_index| {
                            const field_ty = field_types[field_index];
                            if (!Type.from_interned(field_ty).has_runtime_bits(mod)) continue;

                            const field_val = switch (ip.index_to_key(val.to_intern()).aggregate.storage) {
                                .bytes => |bytes| try ip.get(mod.gpa, .{ .int = .{
                                    .ty = field_ty,
                                    .storage = .{ .u64 = bytes.at(field_index, ip) },
                                } }),
                                .elems => |elems| elems[field_index],
                                .repeated_elem => |elem| elem,
                            };

                            const padding = math.cast(
                                usize,
                                offsets[field_index] - (code.items.len - struct_begin),
                            ) orelse return error.Overflow;
                            if (padding > 0) try code.append_ntimes(0, padding);

                            switch (try generate_symbol(bin_file, src_loc, Value.from_interned(field_val), code, debug_output, reloc_info)) {
                                .ok => {},
                                .fail => |em| return Result{ .fail = em },
                            }
                        }

                        const size = struct_type.size(ip).*;
                        const alignment = struct_type.flags_ptr(ip).alignment.to_byte_units().?;

                        const padding = math.cast(
                            usize,
                            std.mem.align_forward(u64, size, @max(alignment, 1)) -
                                (code.items.len - struct_begin),
                        ) orelse return error.Overflow;
                        if (padding > 0) try code.append_ntimes(0, padding);
                    },
                }
            },
            else => unreachable,
        },
        .un => |un| {
            const layout = ty.union_get_layout(mod);

            if (layout.payload_size == 0) {
                return generate_symbol(bin_file, src_loc, Value.from_interned(un.tag), code, debug_output, reloc_info);
            }

            // Check if we should store the tag first.
            if (layout.tag_size > 0 and layout.tag_align.compare(.gte, layout.payload_align)) {
                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(un.tag), code, debug_output, reloc_info)) {
                    .ok => {},
                    .fail => |em| return Result{ .fail = em },
                }
            }

            const union_obj = mod.type_to_union(ty).?;
            if (un.tag != .none) {
                const field_index = ty.union_tag_field_index(Value.from_interned(un.tag), mod).?;
                const field_ty = Type.from_interned(union_obj.field_types.get(ip)[field_index]);
                if (!field_ty.has_runtime_bits(mod)) {
                    try code.append_ntimes(0xaa, math.cast(usize, layout.payload_size) orelse return error.Overflow);
                } else {
                    switch (try generate_symbol(bin_file, src_loc, Value.from_interned(un.val), code, debug_output, reloc_info)) {
                        .ok => {},
                        .fail => |em| return Result{ .fail = em },
                    }

                    const padding = math.cast(usize, layout.payload_size - field_ty.abi_size(mod)) orelse return error.Overflow;
                    if (padding > 0) {
                        try code.append_ntimes(0, padding);
                    }
                }
            } else {
                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(un.val), code, debug_output, reloc_info)) {
                    .ok => {},
                    .fail => |em| return Result{ .fail = em },
                }
            }

            if (layout.tag_size > 0 and layout.tag_align.compare(.lt, layout.payload_align)) {
                switch (try generate_symbol(bin_file, src_loc, Value.from_interned(un.tag), code, debug_output, reloc_info)) {
                    .ok => {},
                    .fail => |em| return Result{ .fail = em },
                }

                if (layout.padding > 0) {
                    try code.append_ntimes(0, layout.padding);
                }
            }
        },
        .memoized_call => unreachable,
    }
    return .ok;
}

fn lower_ptr(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    ptr_val: InternPool.Index,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
    reloc_info: RelocInfo,
    prev_offset: u64,
) CodeGenError!Result {
    const zcu = bin_file.comp.module.?;
    const ptr = zcu.intern_pool.index_to_key(ptr_val).ptr;
    const offset: u64 = prev_offset + ptr.byte_offset;
    return switch (ptr.base_addr) {
        .decl => |decl| try lower_decl_ref(bin_file, src_loc, decl, code, debug_output, reloc_info, offset),
        .anon_decl => |ad| try lower_anon_decl_ref(bin_file, src_loc, ad, code, debug_output, reloc_info, offset),
        .int => try generate_symbol(bin_file, src_loc, try zcu.int_value(Type.usize, offset), code, debug_output, reloc_info),
        .eu_payload => |eu_ptr| try lower_ptr(
            bin_file,
            src_loc,
            eu_ptr,
            code,
            debug_output,
            reloc_info,
            offset + err_union_payload_offset(
                Value.from_interned(eu_ptr).type_of(zcu).child_type(zcu).error_union_payload(zcu),
                zcu,
            ),
        ),
        .opt_payload => |opt_ptr| try lower_ptr(
            bin_file,
            src_loc,
            opt_ptr,
            code,
            debug_output,
            reloc_info,
            offset,
        ),
        .field => |field| {
            const base_ptr = Value.from_interned(field.base);
            const base_ty = base_ptr.type_of(zcu).child_type(zcu);
            const field_off: u64 = switch (base_ty.zig_type_tag(zcu)) {
                .Pointer => off: {
                    assert(base_ty.is_slice(zcu));
                    break :off switch (field.index) {
                        Value.slice_ptr_index => 0,
                        Value.slice_len_index => @div_exact(zcu.get_target().ptr_bit_width(), 8),
                        else => unreachable,
                    };
                },
                .Struct, .Union => switch (base_ty.container_layout(zcu)) {
                    .auto => base_ty.struct_field_offset(@int_cast(field.index), zcu),
                    .@"extern", .@"packed" => unreachable,
                },
                else => unreachable,
            };
            return lower_ptr(bin_file, src_loc, field.base, code, debug_output, reloc_info, offset + field_off);
        },
        .arr_elem, .comptime_field, .comptime_alloc => unreachable,
    };
}

const RelocInfo = struct {
    parent_atom_index: u32,
};

fn lower_anon_decl_ref(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    anon_decl: InternPool.Key.Ptr.BaseAddr.AnonDecl,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
    reloc_info: RelocInfo,
    offset: u64,
) CodeGenError!Result {
    _ = debug_output;
    const zcu = lf.comp.module.?;
    const ip = &zcu.intern_pool;
    const target = lf.comp.root_mod.resolved_target.result;

    const ptr_width_bytes = @div_exact(target.ptr_bit_width(), 8);
    const decl_val = anon_decl.val;
    const decl_ty = Type.from_interned(ip.type_of(decl_val));
    log.debug("lower_anon_decl: ty = {}", .{decl_ty.fmt(zcu)});
    const is_fn_body = decl_ty.zig_type_tag(zcu) == .Fn;
    if (!is_fn_body and !decl_ty.has_runtime_bits(zcu)) {
        try code.append_ntimes(0xaa, ptr_width_bytes);
        return Result.ok;
    }

    const decl_align = ip.index_to_key(anon_decl.orig_ty).ptr_type.flags.alignment;
    const res = try lf.lower_anon_decl(decl_val, decl_align, src_loc);
    switch (res) {
        .ok => {},
        .fail => |em| return .{ .fail = em },
    }

    const vaddr = try lf.get_anon_decl_vaddr(decl_val, .{
        .parent_atom_index = reloc_info.parent_atom_index,
        .offset = code.items.len,
        .addend = @int_cast(offset),
    });
    const endian = target.cpu.arch.endian();
    switch (ptr_width_bytes) {
        2 => mem.write_int(u16, try code.add_many_as_array(2), @int_cast(vaddr), endian),
        4 => mem.write_int(u32, try code.add_many_as_array(4), @int_cast(vaddr), endian),
        8 => mem.write_int(u64, try code.add_many_as_array(8), vaddr, endian),
        else => unreachable,
    }

    return Result.ok;
}

fn lower_decl_ref(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    decl_index: InternPool.DeclIndex,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
    reloc_info: RelocInfo,
    offset: u64,
) CodeGenError!Result {
    _ = src_loc;
    _ = debug_output;
    const zcu = lf.comp.module.?;
    const decl = zcu.decl_ptr(decl_index);
    const namespace = zcu.namespace_ptr(decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;

    const ptr_width = target.ptr_bit_width();
    const is_fn_body = decl.type_of(zcu).zig_type_tag(zcu) == .Fn;
    if (!is_fn_body and !decl.type_of(zcu).has_runtime_bits(zcu)) {
        try code.append_ntimes(0xaa, @div_exact(ptr_width, 8));
        return Result.ok;
    }

    const vaddr = try lf.get_decl_vaddr(decl_index, .{
        .parent_atom_index = reloc_info.parent_atom_index,
        .offset = code.items.len,
        .addend = @int_cast(offset),
    });
    const endian = target.cpu.arch.endian();
    switch (ptr_width) {
        16 => mem.write_int(u16, try code.add_many_as_array(2), @int_cast(vaddr), endian),
        32 => mem.write_int(u32, try code.add_many_as_array(4), @int_cast(vaddr), endian),
        64 => mem.write_int(u64, try code.add_many_as_array(8), vaddr, endian),
        else => unreachable,
    }

    return Result.ok;
}

/// Helper struct to denote that the value is in memory but requires a linker relocation fixup:
/// * got - the value is referenced indirectly via GOT entry index (the linker emits a got-type reloc)
/// * direct - the value is referenced directly via symbol index index (the linker emits a displacement reloc)
/// * import - the value is referenced indirectly via import entry index (the linker emits an import-type reloc)
pub const LinkerLoad = struct {
    type: enum {
        got,
        direct,
        import,
    },
    sym_index: u32,
};

pub const GenResult = union(enum) {
    mcv: MCValue,
    fail: *ErrorMsg,

    const MCValue = union(enum) {
        none,
        undef,
        /// The bit-width of the immediate may be smaller than `u64`. For example, on 32-bit targets
        /// such as ARM, the immediate will never exceed 32-bits.
        immediate: u64,
        /// Threadlocal variable with address deferred until the linker allocates
        /// everything in virtual memory.
        /// Payload is a symbol index.
        load_tlv: u32,
        /// Decl with address deferred until the linker allocates everything in virtual memory.
        /// Payload is a symbol index.
        load_direct: u32,
        /// Decl referenced via GOT with address deferred until the linker allocates
        /// everything in virtual memory.
        /// Payload is a symbol index.
        load_got: u32,
        /// Direct by-address reference to memory location.
        memory: u64,
        /// Reference to memory location but deferred until linker allocated the Decl in memory.
        /// Traditionally, this corresponds to emitting a relocation in a relocatable object file.
        load_symbol: u32,
    };

    fn mcv(val: MCValue) GenResult {
        return .{ .mcv = val };
    }

    fn fail(
        gpa: Allocator,
        src_loc: Module.SrcLoc,
        comptime format: []const u8,
        args: anytype,
    ) Allocator.Error!GenResult {
        const msg = try ErrorMsg.create(gpa, src_loc, format, args);
        return .{ .fail = msg };
    }
};

fn gen_decl_ref(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    val: Value,
    ptr_decl_index: InternPool.DeclIndex,
) CodeGenError!GenResult {
    const zcu = lf.comp.module.?;
    const ip = &zcu.intern_pool;
    const ty = val.type_of(zcu);
    log.debug("gen_decl_ref: val = {}", .{val.fmt_value(zcu, null)});

    const ptr_decl = zcu.decl_ptr(ptr_decl_index);
    const namespace = zcu.namespace_ptr(ptr_decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;

    const ptr_bits = target.ptr_bit_width();
    const ptr_bytes: u64 = @div_exact(ptr_bits, 8);

    const decl_index = switch (ip.index_to_key(ptr_decl.val.to_intern())) {
        .func => |func| func.owner_decl,
        .extern_func => |extern_func| extern_func.decl,
        else => ptr_decl_index,
    };
    const decl = zcu.decl_ptr(decl_index);

    if (!decl.type_of(zcu).is_fn_or_has_runtime_bits_ignore_comptime(zcu)) {
        const imm: u64 = switch (ptr_bytes) {
            1 => 0xaa,
            2 => 0xaaaa,
            4 => 0xaaaaaaaa,
            8 => 0xaaaaaaaaaaaaaaaa,
            else => unreachable,
        };
        return GenResult.mcv(.{ .immediate = imm });
    }

    const comp = lf.comp;
    const gpa = comp.gpa;

    // TODO this feels clunky. Perhaps we should check for it in `gen_typed_value`?
    if (ty.cast_ptr_to_fn(zcu)) |fn_ty| {
        if (zcu.type_to_func(fn_ty).?.is_generic) {
            return GenResult.mcv(.{ .immediate = fn_ty.abi_alignment(zcu).to_byte_units().? });
        }
    } else if (ty.zig_type_tag(zcu) == .Pointer) {
        const elem_ty = ty.elem_type2(zcu);
        if (!elem_ty.has_runtime_bits(zcu)) {
            return GenResult.mcv(.{ .immediate = elem_ty.abi_alignment(zcu).to_byte_units().? });
        }
    }

    const decl_namespace = zcu.namespace_ptr(decl.src_namespace);
    const single_threaded = decl_namespace.file_scope.mod.single_threaded;
    const is_threadlocal = val.is_ptr_to_thread_local(zcu) and !single_threaded;
    const is_extern = decl.is_extern(zcu);

    if (lf.cast(link.File.Elf)) |elf_file| {
        if (is_extern) {
            const name = decl.name.to_slice(ip);
            // TODO audit this
            const lib_name = if (decl.get_owned_variable(zcu)) |ov| ov.lib_name.to_slice(ip) else null;
            const sym_index = try elf_file.get_global_symbol(name, lib_name);
            elf_file.symbol(elf_file.zig_object_ptr().?.symbol(sym_index)).flags.needs_got = true;
            return GenResult.mcv(.{ .load_symbol = sym_index });
        }
        const sym_index = try elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, decl_index);
        const sym = elf_file.symbol(sym_index);
        if (is_threadlocal) {
            return GenResult.mcv(.{ .load_tlv = sym.esym_index });
        }
        return GenResult.mcv(.{ .load_symbol = sym.esym_index });
    } else if (lf.cast(link.File.MachO)) |macho_file| {
        if (is_extern) {
            const name = decl.name.to_slice(ip);
            const lib_name = if (decl.get_owned_variable(zcu)) |ov| ov.lib_name.to_slice(ip) else null;
            const sym_index = try macho_file.get_global_symbol(name, lib_name);
            macho_file.get_symbol(macho_file.get_zig_object().?.symbols.items[sym_index]).flags.needs_got = true;
            return GenResult.mcv(.{ .load_symbol = sym_index });
        }
        const sym_index = try macho_file.get_zig_object().?.get_or_create_metadata_for_decl(macho_file, decl_index);
        const sym = macho_file.get_symbol(sym_index);
        if (is_threadlocal) {
            return GenResult.mcv(.{ .load_tlv = sym.nlist_idx });
        }
        return GenResult.mcv(.{ .load_symbol = sym.nlist_idx });
    } else if (lf.cast(link.File.Coff)) |coff_file| {
        if (is_extern) {
            const name = decl.name.to_slice(ip);
            // TODO audit this
            const lib_name = if (decl.get_owned_variable(zcu)) |ov| ov.lib_name.to_slice(ip) else null;
            const global_index = try coff_file.get_global_symbol(name, lib_name);
            try coff_file.need_got_table.put(gpa, global_index, {}); // needs GOT
            return GenResult.mcv(.{ .load_got = link.File.Coff.global_symbol_bit | global_index });
        }
        const atom_index = try coff_file.get_or_create_atom_for_decl(decl_index);
        const sym_index = coff_file.get_atom(atom_index).get_symbol_index().?;
        return GenResult.mcv(.{ .load_got = sym_index });
    } else if (lf.cast(link.File.Plan9)) |p9| {
        const atom_index = try p9.see_decl(decl_index);
        const atom = p9.get_atom(atom_index);
        return GenResult.mcv(.{ .memory = atom.get_offset_table_address(p9) });
    } else {
        return GenResult.fail(gpa, src_loc, "TODO gen_decl_ref for target {}", .{target});
    }
}

fn gen_unnamed_const(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    val: Value,
    owner_decl_index: InternPool.DeclIndex,
) CodeGenError!GenResult {
    const zcu = lf.comp.module.?;
    const gpa = lf.comp.gpa;
    log.debug("gen_unnamed_const: val = {}", .{val.fmt_value(zcu, null)});

    const local_sym_index = lf.lower_unnamed_const(val, owner_decl_index) catch |err| {
        return GenResult.fail(gpa, src_loc, "lowering unnamed constant failed: {s}", .{@errorName(err)});
    };
    switch (lf.tag) {
        .elf => {
            const elf_file = lf.cast(link.File.Elf).?;
            const local = elf_file.symbol(local_sym_index);
            return GenResult.mcv(.{ .load_symbol = local.esym_index });
        },
        .macho => {
            const macho_file = lf.cast(link.File.MachO).?;
            const local = macho_file.get_symbol(local_sym_index);
            return GenResult.mcv(.{ .load_symbol = local.nlist_idx });
        },
        .coff => {
            return GenResult.mcv(.{ .load_direct = local_sym_index });
        },
        .plan9 => {
            const atom_index = local_sym_index; // plan9 returns the atom_index
            return GenResult.mcv(.{ .load_direct = atom_index });
        },

        .c => return GenResult.fail(gpa, src_loc, "TODO gen_unnamed_const for -ofmt=c", .{}),
        .wasm => return GenResult.fail(gpa, src_loc, "TODO gen_unnamed_const for wasm", .{}),
        .spirv => return GenResult.fail(gpa, src_loc, "TODO gen_unnamed_const for spirv", .{}),
        .nvptx => return GenResult.fail(gpa, src_loc, "TODO gen_unnamed_const for nvptx", .{}),
    }
}

pub fn gen_typed_value(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    val: Value,
    owner_decl_index: InternPool.DeclIndex,
) CodeGenError!GenResult {
    const zcu = lf.comp.module.?;
    const ip = &zcu.intern_pool;
    const ty = val.type_of(zcu);

    log.debug("gen_typed_value: val = {}", .{val.fmt_value(zcu, null)});

    if (val.is_undef(zcu))
        return GenResult.mcv(.undef);

    const owner_decl = zcu.decl_ptr(owner_decl_index);
    const namespace = zcu.namespace_ptr(owner_decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;
    const ptr_bits = target.ptr_bit_width();

    if (!ty.is_slice(zcu)) switch (ip.index_to_key(val.to_intern())) {
        .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
            .decl => |decl| return gen_decl_ref(lf, src_loc, val, decl),
            else => {},
        },
        else => {},
    };

    switch (ty.zig_type_tag(zcu)) {
        .Void => return GenResult.mcv(.none),
        .Pointer => switch (ty.ptr_size(zcu)) {
            .Slice => {},
            else => switch (val.to_intern()) {
                .null_value => {
                    return GenResult.mcv(.{ .immediate = 0 });
                },
                .none => {},
                else => switch (ip.index_to_key(val.to_intern())) {
                    .int => {
                        return GenResult.mcv(.{ .immediate = val.to_unsigned_int(zcu) });
                    },
                    else => {},
                },
            },
        },
        .Int => {
            const info = ty.int_info(zcu);
            if (info.bits <= ptr_bits) {
                const unsigned: u64 = switch (info.signedness) {
                    .signed => @bit_cast(val.to_signed_int(zcu)),
                    .unsigned => val.to_unsigned_int(zcu),
                };
                return GenResult.mcv(.{ .immediate = unsigned });
            }
        },
        .Bool => {
            return GenResult.mcv(.{ .immediate = @int_from_bool(val.to_bool()) });
        },
        .Optional => {
            if (ty.is_ptr_like_optional(zcu)) {
                return gen_typed_value(
                    lf,
                    src_loc,
                    val.optional_value(zcu) orelse return GenResult.mcv(.{ .immediate = 0 }),
                    owner_decl_index,
                );
            } else if (ty.abi_size(zcu) == 1) {
                return GenResult.mcv(.{ .immediate = @int_from_bool(!val.is_null(zcu)) });
            }
        },
        .Enum => {
            const enum_tag = ip.index_to_key(val.to_intern()).enum_tag;
            return gen_typed_value(
                lf,
                src_loc,
                Value.from_interned(enum_tag.int),
                owner_decl_index,
            );
        },
        .ErrorSet => {
            const err_name = ip.index_to_key(val.to_intern()).err.name;
            const error_index = zcu.global_error_set.get_index(err_name).?;
            return GenResult.mcv(.{ .immediate = error_index });
        },
        .ErrorUnion => {
            const err_type = ty.error_union_set(zcu);
            const payload_type = ty.error_union_payload(zcu);
            if (!payload_type.has_runtime_bits_ignore_comptime(zcu)) {
                // We use the error type directly as the type.
                const err_int_ty = try zcu.error_int_type();
                switch (ip.index_to_key(val.to_intern()).error_union.val) {
                    .err_name => |err_name| return gen_typed_value(
                        lf,
                        src_loc,
                        Value.from_interned(try zcu.intern(.{ .err = .{
                            .ty = err_type.to_intern(),
                            .name = err_name,
                        } })),
                        owner_decl_index,
                    ),
                    .payload => return gen_typed_value(
                        lf,
                        src_loc,
                        try zcu.int_value(err_int_ty, 0),
                        owner_decl_index,
                    ),
                }
            }
        },

        .ComptimeInt => unreachable,
        .ComptimeFloat => unreachable,
        .Type => unreachable,
        .EnumLiteral => unreachable,
        .NoReturn => unreachable,
        .Undefined => unreachable,
        .Null => unreachable,
        .Opaque => unreachable,

        else => {},
    }

    return gen_unnamed_const(lf, src_loc, val, owner_decl_index);
}

pub fn err_union_payload_offset(payload_ty: Type, mod: *Module) u64 {
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) return 0;
    const payload_align = payload_ty.abi_alignment(mod);
    const error_align = Type.anyerror.abi_alignment(mod);
    if (payload_align.compare(.gte, error_align) or !payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return 0;
    } else {
        return payload_align.forward(Type.anyerror.abi_size(mod));
    }
}

pub fn err_union_error_offset(payload_ty: Type, mod: *Module) u64 {
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) return 0;
    const payload_align = payload_ty.abi_alignment(mod);
    const error_align = Type.anyerror.abi_alignment(mod);
    if (payload_align.compare(.gte, error_align) and payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return error_align.forward(payload_ty.abi_size(mod));
    } else {
        return 0;
    }
}
