//! Contains all logic to lower wasm MIR into its binary
//! or textual representation.

const Emit = @This();
const std = @import("std");
const Mir = @import("Mir.zig");
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const InternPool = @import("../../InternPool.zig");
const codegen = @import("../../codegen.zig");
const leb128 = std.leb;

/// Contains our list of instructions
mir: Mir,
/// Reference to the Wasm module linker
bin_file: *link.File.Wasm,
/// Possible error message. When set, the value is allocated and
/// must be freed manually.
error_msg: ?*Module.ErrorMsg = null,
/// The binary representation that will be emit by this module.
code: *std.ArrayList(u8),
/// List of allocated locals.
locals: []const u8,
/// The declaration that code is being generated for.
decl_index: InternPool.DeclIndex,

// Debug information
/// Holds the debug information for this emission
dbg_output: codegen.DebugInfoOutput,
/// Previous debug info line
prev_di_line: u32,
/// Previous debug info column
prev_di_column: u32,
/// Previous offset relative to code section
prev_di_offset: u32,

const InnerError = error{
    OutOfMemory,
    EmitFail,
};

pub fn emit_mir(emit: *Emit) InnerError!void {
    const mir_tags = emit.mir.instructions.items(.tag);
    // write the locals in the prologue of the function body
    // before we emit the function body when lowering MIR
    try emit.emit_locals();

    for (mir_tags, 0..) |tag, index| {
        const inst = @as(u32, @int_cast(index));
        switch (tag) {
            // block instructions
            .block => try emit.emit_block(tag, inst),
            .loop => try emit.emit_block(tag, inst),

            .dbg_line => try emit.emit_dbg_line(inst),
            .dbg_epilogue_begin => try emit.emit_dbg_epilogue_begin(),
            .dbg_prologue_end => try emit.emit_dbg_prologue_end(),

            // branch instructions
            .br_if => try emit.emit_label(tag, inst),
            .br_table => try emit.emit_br_table(inst),
            .br => try emit.emit_label(tag, inst),

            // relocatables
            .call => try emit.emit_call(inst),
            .call_indirect => try emit.emit_call_indirect(inst),
            .global_get => try emit.emit_global(tag, inst),
            .global_set => try emit.emit_global(tag, inst),
            .function_index => try emit.emit_function_index(inst),
            .memory_address => try emit.emit_mem_address(inst),

            // immediates
            .f32_const => try emit.emit_float32(inst),
            .f64_const => try emit.emit_float64(inst),
            .i32_const => try emit.emit_imm32(inst),
            .i64_const => try emit.emit_imm64(inst),

            // memory instructions
            .i32_load => try emit.emit_mem_arg(tag, inst),
            .i64_load => try emit.emit_mem_arg(tag, inst),
            .f32_load => try emit.emit_mem_arg(tag, inst),
            .f64_load => try emit.emit_mem_arg(tag, inst),
            .i32_load8_s => try emit.emit_mem_arg(tag, inst),
            .i32_load8_u => try emit.emit_mem_arg(tag, inst),
            .i32_load16_s => try emit.emit_mem_arg(tag, inst),
            .i32_load16_u => try emit.emit_mem_arg(tag, inst),
            .i64_load8_s => try emit.emit_mem_arg(tag, inst),
            .i64_load8_u => try emit.emit_mem_arg(tag, inst),
            .i64_load16_s => try emit.emit_mem_arg(tag, inst),
            .i64_load16_u => try emit.emit_mem_arg(tag, inst),
            .i64_load32_s => try emit.emit_mem_arg(tag, inst),
            .i64_load32_u => try emit.emit_mem_arg(tag, inst),
            .i32_store => try emit.emit_mem_arg(tag, inst),
            .i64_store => try emit.emit_mem_arg(tag, inst),
            .f32_store => try emit.emit_mem_arg(tag, inst),
            .f64_store => try emit.emit_mem_arg(tag, inst),
            .i32_store8 => try emit.emit_mem_arg(tag, inst),
            .i32_store16 => try emit.emit_mem_arg(tag, inst),
            .i64_store8 => try emit.emit_mem_arg(tag, inst),
            .i64_store16 => try emit.emit_mem_arg(tag, inst),
            .i64_store32 => try emit.emit_mem_arg(tag, inst),

            // Instructions with an index that do not require relocations
            .local_get => try emit.emit_label(tag, inst),
            .local_set => try emit.emit_label(tag, inst),
            .local_tee => try emit.emit_label(tag, inst),
            .memory_grow => try emit.emit_label(tag, inst),
            .memory_size => try emit.emit_label(tag, inst),

            // no-ops
            .end => try emit.emit_tag(tag),
            .@"return" => try emit.emit_tag(tag),
            .@"unreachable" => try emit.emit_tag(tag),

            .select => try emit.emit_tag(tag),

            // arithmetic
            .i32_eqz => try emit.emit_tag(tag),
            .i32_eq => try emit.emit_tag(tag),
            .i32_ne => try emit.emit_tag(tag),
            .i32_lt_s => try emit.emit_tag(tag),
            .i32_lt_u => try emit.emit_tag(tag),
            .i32_gt_s => try emit.emit_tag(tag),
            .i32_gt_u => try emit.emit_tag(tag),
            .i32_le_s => try emit.emit_tag(tag),
            .i32_le_u => try emit.emit_tag(tag),
            .i32_ge_s => try emit.emit_tag(tag),
            .i32_ge_u => try emit.emit_tag(tag),
            .i64_eqz => try emit.emit_tag(tag),
            .i64_eq => try emit.emit_tag(tag),
            .i64_ne => try emit.emit_tag(tag),
            .i64_lt_s => try emit.emit_tag(tag),
            .i64_lt_u => try emit.emit_tag(tag),
            .i64_gt_s => try emit.emit_tag(tag),
            .i64_gt_u => try emit.emit_tag(tag),
            .i64_le_s => try emit.emit_tag(tag),
            .i64_le_u => try emit.emit_tag(tag),
            .i64_ge_s => try emit.emit_tag(tag),
            .i64_ge_u => try emit.emit_tag(tag),
            .f32_eq => try emit.emit_tag(tag),
            .f32_ne => try emit.emit_tag(tag),
            .f32_lt => try emit.emit_tag(tag),
            .f32_gt => try emit.emit_tag(tag),
            .f32_le => try emit.emit_tag(tag),
            .f32_ge => try emit.emit_tag(tag),
            .f64_eq => try emit.emit_tag(tag),
            .f64_ne => try emit.emit_tag(tag),
            .f64_lt => try emit.emit_tag(tag),
            .f64_gt => try emit.emit_tag(tag),
            .f64_le => try emit.emit_tag(tag),
            .f64_ge => try emit.emit_tag(tag),
            .i32_add => try emit.emit_tag(tag),
            .i32_sub => try emit.emit_tag(tag),
            .i32_mul => try emit.emit_tag(tag),
            .i32_div_s => try emit.emit_tag(tag),
            .i32_div_u => try emit.emit_tag(tag),
            .i32_and => try emit.emit_tag(tag),
            .i32_or => try emit.emit_tag(tag),
            .i32_xor => try emit.emit_tag(tag),
            .i32_shl => try emit.emit_tag(tag),
            .i32_shr_s => try emit.emit_tag(tag),
            .i32_shr_u => try emit.emit_tag(tag),
            .i64_add => try emit.emit_tag(tag),
            .i64_sub => try emit.emit_tag(tag),
            .i64_mul => try emit.emit_tag(tag),
            .i64_div_s => try emit.emit_tag(tag),
            .i64_div_u => try emit.emit_tag(tag),
            .i64_and => try emit.emit_tag(tag),
            .i64_or => try emit.emit_tag(tag),
            .i64_xor => try emit.emit_tag(tag),
            .i64_shl => try emit.emit_tag(tag),
            .i64_shr_s => try emit.emit_tag(tag),
            .i64_shr_u => try emit.emit_tag(tag),
            .f32_abs => try emit.emit_tag(tag),
            .f32_neg => try emit.emit_tag(tag),
            .f32_ceil => try emit.emit_tag(tag),
            .f32_floor => try emit.emit_tag(tag),
            .f32_trunc => try emit.emit_tag(tag),
            .f32_nearest => try emit.emit_tag(tag),
            .f32_sqrt => try emit.emit_tag(tag),
            .f32_add => try emit.emit_tag(tag),
            .f32_sub => try emit.emit_tag(tag),
            .f32_mul => try emit.emit_tag(tag),
            .f32_div => try emit.emit_tag(tag),
            .f32_min => try emit.emit_tag(tag),
            .f32_max => try emit.emit_tag(tag),
            .f32_copysign => try emit.emit_tag(tag),
            .f64_abs => try emit.emit_tag(tag),
            .f64_neg => try emit.emit_tag(tag),
            .f64_ceil => try emit.emit_tag(tag),
            .f64_floor => try emit.emit_tag(tag),
            .f64_trunc => try emit.emit_tag(tag),
            .f64_nearest => try emit.emit_tag(tag),
            .f64_sqrt => try emit.emit_tag(tag),
            .f64_add => try emit.emit_tag(tag),
            .f64_sub => try emit.emit_tag(tag),
            .f64_mul => try emit.emit_tag(tag),
            .f64_div => try emit.emit_tag(tag),
            .f64_min => try emit.emit_tag(tag),
            .f64_max => try emit.emit_tag(tag),
            .f64_copysign => try emit.emit_tag(tag),
            .i32_wrap_i64 => try emit.emit_tag(tag),
            .i64_extend_i32_s => try emit.emit_tag(tag),
            .i64_extend_i32_u => try emit.emit_tag(tag),
            .i32_extend8_s => try emit.emit_tag(tag),
            .i32_extend16_s => try emit.emit_tag(tag),
            .i64_extend8_s => try emit.emit_tag(tag),
            .i64_extend16_s => try emit.emit_tag(tag),
            .i64_extend32_s => try emit.emit_tag(tag),
            .f32_demote_f64 => try emit.emit_tag(tag),
            .f64_promote_f32 => try emit.emit_tag(tag),
            .i32_reinterpret_f32 => try emit.emit_tag(tag),
            .i64_reinterpret_f64 => try emit.emit_tag(tag),
            .f32_reinterpret_i32 => try emit.emit_tag(tag),
            .f64_reinterpret_i64 => try emit.emit_tag(tag),
            .i32_trunc_f32_s => try emit.emit_tag(tag),
            .i32_trunc_f32_u => try emit.emit_tag(tag),
            .i32_trunc_f64_s => try emit.emit_tag(tag),
            .i32_trunc_f64_u => try emit.emit_tag(tag),
            .i64_trunc_f32_s => try emit.emit_tag(tag),
            .i64_trunc_f32_u => try emit.emit_tag(tag),
            .i64_trunc_f64_s => try emit.emit_tag(tag),
            .i64_trunc_f64_u => try emit.emit_tag(tag),
            .f32_convert_i32_s => try emit.emit_tag(tag),
            .f32_convert_i32_u => try emit.emit_tag(tag),
            .f32_convert_i64_s => try emit.emit_tag(tag),
            .f32_convert_i64_u => try emit.emit_tag(tag),
            .f64_convert_i32_s => try emit.emit_tag(tag),
            .f64_convert_i32_u => try emit.emit_tag(tag),
            .f64_convert_i64_s => try emit.emit_tag(tag),
            .f64_convert_i64_u => try emit.emit_tag(tag),
            .i32_rem_s => try emit.emit_tag(tag),
            .i32_rem_u => try emit.emit_tag(tag),
            .i64_rem_s => try emit.emit_tag(tag),
            .i64_rem_u => try emit.emit_tag(tag),
            .i32_popcnt => try emit.emit_tag(tag),
            .i64_popcnt => try emit.emit_tag(tag),
            .i32_clz => try emit.emit_tag(tag),
            .i32_ctz => try emit.emit_tag(tag),
            .i64_clz => try emit.emit_tag(tag),
            .i64_ctz => try emit.emit_tag(tag),

            .misc_prefix => try emit.emit_extended(inst),
            .simd_prefix => try emit.emit_simd(inst),
            .atomics_prefix => try emit.emit_atomic(inst),
        }
    }
}

fn offset(self: Emit) u32 {
    return @as(u32, @int_cast(self.code.items.len));
}

fn fail(emit: *Emit, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    std.debug.assert(emit.error_msg == null);
    const comp = emit.bin_file.base.comp;
    const zcu = comp.module.?;
    const gpa = comp.gpa;
    emit.error_msg = try Module.ErrorMsg.create(gpa, zcu.decl_ptr(emit.decl_index).src_loc(zcu), format, args);
    return error.EmitFail;
}

fn emit_locals(emit: *Emit) !void {
    const writer = emit.code.writer();
    try leb128.write_uleb128(writer, @as(u32, @int_cast(emit.locals.len)));
    // emit the actual locals amount
    for (emit.locals) |local| {
        try leb128.write_uleb128(writer, @as(u32, 1));
        try writer.write_byte(local);
    }
}

fn emit_tag(emit: *Emit, tag: Mir.Inst.Tag) !void {
    try emit.code.append(@int_from_enum(tag));
}

fn emit_block(emit: *Emit, tag: Mir.Inst.Tag, inst: Mir.Inst.Index) !void {
    const block_type = emit.mir.instructions.items(.data)[inst].block_type;
    try emit.code.append(@int_from_enum(tag));
    try emit.code.append(block_type);
}

fn emit_br_table(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const extra = emit.mir.extra_data(Mir.JumpTable, extra_index);
    const labels = emit.mir.extra[extra.end..][0..extra.data.length];
    const writer = emit.code.writer();

    try emit.code.append(std.wasm.opcode(.br_table));
    try leb128.write_uleb128(writer, extra.data.length - 1); // Default label is not part of length/depth
    for (labels) |label| {
        try leb128.write_uleb128(writer, label);
    }
}

fn emit_label(emit: *Emit, tag: Mir.Inst.Tag, inst: Mir.Inst.Index) !void {
    const label = emit.mir.instructions.items(.data)[inst].label;
    try emit.code.append(@int_from_enum(tag));
    try leb128.write_uleb128(emit.code.writer(), label);
}

fn emit_global(emit: *Emit, tag: Mir.Inst.Tag, inst: Mir.Inst.Index) !void {
    const comp = emit.bin_file.base.comp;
    const gpa = comp.gpa;
    const label = emit.mir.instructions.items(.data)[inst].label;
    try emit.code.append(@int_from_enum(tag));
    var buf: [5]u8 = undefined;
    leb128.write_unsigned_fixed(5, &buf, label);
    const global_offset = emit.offset();
    try emit.code.append_slice(&buf);

    const atom_index = emit.bin_file.zig_object_ptr().?.decls_map.get(emit.decl_index).?.atom;
    const atom = emit.bin_file.get_atom_ptr(atom_index);
    try atom.relocs.append(gpa, .{
        .index = label,
        .offset = global_offset,
        .relocation_type = .R_WASM_GLOBAL_INDEX_LEB,
    });
}

fn emit_imm32(emit: *Emit, inst: Mir.Inst.Index) !void {
    const value: i32 = emit.mir.instructions.items(.data)[inst].imm32;
    try emit.code.append(std.wasm.opcode(.i32_const));
    try leb128.write_ileb128(emit.code.writer(), value);
}

fn emit_imm64(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const value = emit.mir.extra_data(Mir.Imm64, extra_index);
    try emit.code.append(std.wasm.opcode(.i64_const));
    try leb128.write_ileb128(emit.code.writer(), @as(i64, @bit_cast(value.data.to_u64())));
}

fn emit_float32(emit: *Emit, inst: Mir.Inst.Index) !void {
    const value: f32 = emit.mir.instructions.items(.data)[inst].float32;
    try emit.code.append(std.wasm.opcode(.f32_const));
    try emit.code.writer().write_int(u32, @bit_cast(value), .little);
}

fn emit_float64(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const value = emit.mir.extra_data(Mir.Float64, extra_index);
    try emit.code.append(std.wasm.opcode(.f64_const));
    try emit.code.writer().write_int(u64, value.data.to_u64(), .little);
}

fn emit_mem_arg(emit: *Emit, tag: Mir.Inst.Tag, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const mem_arg = emit.mir.extra_data(Mir.MemArg, extra_index).data;
    try emit.code.append(@int_from_enum(tag));
    try encode_mem_arg(mem_arg, emit.code.writer());
}

fn encode_mem_arg(mem_arg: Mir.MemArg, writer: anytype) !void {
    // wasm encodes alignment as power of 2, rather than natural alignment
    const encoded_alignment = @ctz(mem_arg.alignment);
    try leb128.write_uleb128(writer, encoded_alignment);
    try leb128.write_uleb128(writer, mem_arg.offset);
}

fn emit_call(emit: *Emit, inst: Mir.Inst.Index) !void {
    const comp = emit.bin_file.base.comp;
    const gpa = comp.gpa;
    const label = emit.mir.instructions.items(.data)[inst].label;
    try emit.code.append(std.wasm.opcode(.call));
    const call_offset = emit.offset();
    var buf: [5]u8 = undefined;
    leb128.write_unsigned_fixed(5, &buf, label);
    try emit.code.append_slice(&buf);

    if (label != 0) {
        const atom_index = emit.bin_file.zig_object_ptr().?.decls_map.get(emit.decl_index).?.atom;
        const atom = emit.bin_file.get_atom_ptr(atom_index);
        try atom.relocs.append(gpa, .{
            .offset = call_offset,
            .index = label,
            .relocation_type = .R_WASM_FUNCTION_INDEX_LEB,
        });
    }
}

fn emit_call_indirect(emit: *Emit, inst: Mir.Inst.Index) !void {
    const type_index = emit.mir.instructions.items(.data)[inst].label;
    try emit.code.append(std.wasm.opcode(.call_indirect));
    // NOTE: If we remove unused function types in the future for incremental
    // linking, we must also emit a relocation for this `type_index`
    const call_offset = emit.offset();
    var buf: [5]u8 = undefined;
    leb128.write_unsigned_fixed(5, &buf, type_index);
    try emit.code.append_slice(&buf);
    if (type_index != 0) {
        const atom_index = emit.bin_file.zig_object_ptr().?.decls_map.get(emit.decl_index).?.atom;
        const atom = emit.bin_file.get_atom_ptr(atom_index);
        try atom.relocs.append(emit.bin_file.base.comp.gpa, .{
            .offset = call_offset,
            .index = type_index,
            .relocation_type = .R_WASM_TYPE_INDEX_LEB,
        });
    }
    try leb128.write_uleb128(emit.code.writer(), @as(u32, 0)); // TODO: Emit relocation for table index
}

fn emit_function_index(emit: *Emit, inst: Mir.Inst.Index) !void {
    const comp = emit.bin_file.base.comp;
    const gpa = comp.gpa;
    const symbol_index = emit.mir.instructions.items(.data)[inst].label;
    try emit.code.append(std.wasm.opcode(.i32_const));
    const index_offset = emit.offset();
    var buf: [5]u8 = undefined;
    leb128.write_unsigned_fixed(5, &buf, symbol_index);
    try emit.code.append_slice(&buf);

    if (symbol_index != 0) {
        const atom_index = emit.bin_file.zig_object_ptr().?.decls_map.get(emit.decl_index).?.atom;
        const atom = emit.bin_file.get_atom_ptr(atom_index);
        try atom.relocs.append(gpa, .{
            .offset = index_offset,
            .index = symbol_index,
            .relocation_type = .R_WASM_TABLE_INDEX_SLEB,
        });
    }
}

fn emit_mem_address(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const mem = emit.mir.extra_data(Mir.Memory, extra_index).data;
    const mem_offset = emit.offset() + 1;
    const comp = emit.bin_file.base.comp;
    const gpa = comp.gpa;
    const target = comp.root_mod.resolved_target.result;
    const is_wasm32 = target.cpu.arch == .wasm32;
    if (is_wasm32) {
        try emit.code.append(std.wasm.opcode(.i32_const));
        var buf: [5]u8 = undefined;
        leb128.write_unsigned_fixed(5, &buf, mem.pointer);
        try emit.code.append_slice(&buf);
    } else {
        try emit.code.append(std.wasm.opcode(.i64_const));
        var buf: [10]u8 = undefined;
        leb128.write_unsigned_fixed(10, &buf, mem.pointer);
        try emit.code.append_slice(&buf);
    }

    if (mem.pointer != 0) {
        const atom_index = emit.bin_file.zig_object_ptr().?.decls_map.get(emit.decl_index).?.atom;
        const atom = emit.bin_file.get_atom_ptr(atom_index);
        try atom.relocs.append(gpa, .{
            .offset = mem_offset,
            .index = mem.pointer,
            .relocation_type = if (is_wasm32) .R_WASM_MEMORY_ADDR_LEB else .R_WASM_MEMORY_ADDR_LEB64,
            .addend = @as(i32, @int_cast(mem.offset)),
        });
    }
}

fn emit_extended(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const opcode = emit.mir.extra[extra_index];
    const writer = emit.code.writer();
    try emit.code.append(std.wasm.opcode(.misc_prefix));
    try leb128.write_uleb128(writer, opcode);
    switch (@as(std.wasm.MiscOpcode, @enumFromInt(opcode))) {
        // bulk-memory opcodes
        .data_drop => {
            const segment = emit.mir.extra[extra_index + 1];
            try leb128.write_uleb128(writer, segment);
        },
        .memory_init => {
            const segment = emit.mir.extra[extra_index + 1];
            try leb128.write_uleb128(writer, segment);
            try leb128.write_uleb128(writer, @as(u32, 0)); // memory index
        },
        .memory_fill => {
            try leb128.write_uleb128(writer, @as(u32, 0)); // memory index
        },
        .memory_copy => {
            try leb128.write_uleb128(writer, @as(u32, 0)); // dst memory index
            try leb128.write_uleb128(writer, @as(u32, 0)); // src memory index
        },

        // nontrapping-float-to-int-conversion opcodes
        .i32_trunc_sat_f32_s,
        .i32_trunc_sat_f32_u,
        .i32_trunc_sat_f64_s,
        .i32_trunc_sat_f64_u,
        .i64_trunc_sat_f32_s,
        .i64_trunc_sat_f32_u,
        .i64_trunc_sat_f64_s,
        .i64_trunc_sat_f64_u,
        => {}, // opcode already written
        else => |tag| return emit.fail("TODO: Implement extension instruction: {s}\n", .{@tag_name(tag)}),
    }
}

fn emit_simd(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const opcode = emit.mir.extra[extra_index];
    const writer = emit.code.writer();
    try emit.code.append(std.wasm.opcode(.simd_prefix));
    try leb128.write_uleb128(writer, opcode);
    switch (@as(std.wasm.SimdOpcode, @enumFromInt(opcode))) {
        .v128_store,
        .v128_load,
        .v128_load8_splat,
        .v128_load16_splat,
        .v128_load32_splat,
        .v128_load64_splat,
        => {
            const mem_arg = emit.mir.extra_data(Mir.MemArg, extra_index + 1).data;
            try encode_mem_arg(mem_arg, writer);
        },
        .v128_const,
        .i8x16_shuffle,
        => {
            const simd_value = emit.mir.extra[extra_index + 1 ..][0..4];
            try writer.write_all(std.mem.as_bytes(simd_value));
        },
        .i8x16_extract_lane_s,
        .i8x16_extract_lane_u,
        .i8x16_replace_lane,
        .i16x8_extract_lane_s,
        .i16x8_extract_lane_u,
        .i16x8_replace_lane,
        .i32x4_extract_lane,
        .i32x4_replace_lane,
        .i64x2_extract_lane,
        .i64x2_replace_lane,
        .f32x4_extract_lane,
        .f32x4_replace_lane,
        .f64x2_extract_lane,
        .f64x2_replace_lane,
        => {
            try writer.write_byte(@as(u8, @int_cast(emit.mir.extra[extra_index + 1])));
        },
        .i8x16_splat,
        .i16x8_splat,
        .i32x4_splat,
        .i64x2_splat,
        .f32x4_splat,
        .f64x2_splat,
        => {}, // opcode already written
        else => |tag| return emit.fail("TODO: Implement simd instruction: {s}", .{@tag_name(tag)}),
    }
}

fn emit_atomic(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const opcode = emit.mir.extra[extra_index];
    const writer = emit.code.writer();
    try emit.code.append(std.wasm.opcode(.atomics_prefix));
    try leb128.write_uleb128(writer, opcode);
    switch (@as(std.wasm.AtomicsOpcode, @enumFromInt(opcode))) {
        .i32_atomic_load,
        .i64_atomic_load,
        .i32_atomic_load8_u,
        .i32_atomic_load16_u,
        .i64_atomic_load8_u,
        .i64_atomic_load16_u,
        .i64_atomic_load32_u,
        .i32_atomic_store,
        .i64_atomic_store,
        .i32_atomic_store8,
        .i32_atomic_store16,
        .i64_atomic_store8,
        .i64_atomic_store16,
        .i64_atomic_store32,
        .i32_atomic_rmw_add,
        .i64_atomic_rmw_add,
        .i32_atomic_rmw8_add_u,
        .i32_atomic_rmw16_add_u,
        .i64_atomic_rmw8_add_u,
        .i64_atomic_rmw16_add_u,
        .i64_atomic_rmw32_add_u,
        .i32_atomic_rmw_sub,
        .i64_atomic_rmw_sub,
        .i32_atomic_rmw8_sub_u,
        .i32_atomic_rmw16_sub_u,
        .i64_atomic_rmw8_sub_u,
        .i64_atomic_rmw16_sub_u,
        .i64_atomic_rmw32_sub_u,
        .i32_atomic_rmw_and,
        .i64_atomic_rmw_and,
        .i32_atomic_rmw8_and_u,
        .i32_atomic_rmw16_and_u,
        .i64_atomic_rmw8_and_u,
        .i64_atomic_rmw16_and_u,
        .i64_atomic_rmw32_and_u,
        .i32_atomic_rmw_or,
        .i64_atomic_rmw_or,
        .i32_atomic_rmw8_or_u,
        .i32_atomic_rmw16_or_u,
        .i64_atomic_rmw8_or_u,
        .i64_atomic_rmw16_or_u,
        .i64_atomic_rmw32_or_u,
        .i32_atomic_rmw_xor,
        .i64_atomic_rmw_xor,
        .i32_atomic_rmw8_xor_u,
        .i32_atomic_rmw16_xor_u,
        .i64_atomic_rmw8_xor_u,
        .i64_atomic_rmw16_xor_u,
        .i64_atomic_rmw32_xor_u,
        .i32_atomic_rmw_xchg,
        .i64_atomic_rmw_xchg,
        .i32_atomic_rmw8_xchg_u,
        .i32_atomic_rmw16_xchg_u,
        .i64_atomic_rmw8_xchg_u,
        .i64_atomic_rmw16_xchg_u,
        .i64_atomic_rmw32_xchg_u,

        .i32_atomic_rmw_cmpxchg,
        .i64_atomic_rmw_cmpxchg,
        .i32_atomic_rmw8_cmpxchg_u,
        .i32_atomic_rmw16_cmpxchg_u,
        .i64_atomic_rmw8_cmpxchg_u,
        .i64_atomic_rmw16_cmpxchg_u,
        .i64_atomic_rmw32_cmpxchg_u,
        => {
            const mem_arg = emit.mir.extra_data(Mir.MemArg, extra_index + 1).data;
            try encode_mem_arg(mem_arg, writer);
        },
        .atomic_fence => {
            // TODO: When multi-memory proposal is accepted and implemented in the compiler,
            // change this to (user-)specified index, rather than hardcode it to memory index 0.
            const memory_index: u32 = 0;
            try leb128.write_uleb128(writer, memory_index);
        },
        else => |tag| return emit.fail("TODO: Implement atomic instruction: {s}", .{@tag_name(tag)}),
    }
}

fn emit_mem_fill(emit: *Emit) !void {
    try emit.code.append(0xFC);
    try emit.code.append(0x0B);
    // When multi-memory proposal reaches phase 4, we
    // can emit a different memory index here.
    // For now we will always emit index 0.
    try leb128.write_uleb128(emit.code.writer(), @as(u32, 0));
}

fn emit_dbg_line(emit: *Emit, inst: Mir.Inst.Index) !void {
    const extra_index = emit.mir.instructions.items(.data)[inst].payload;
    const dbg_line = emit.mir.extra_data(Mir.DbgLineColumn, extra_index).data;
    try emit.dbg_advance_pcand_line(dbg_line.line, dbg_line.column);
}

fn dbg_advance_pcand_line(emit: *Emit, line: u32, column: u32) !void {
    if (emit.dbg_output != .dwarf) return;

    const delta_line = @as(i32, @int_cast(line)) - @as(i32, @int_cast(emit.prev_di_line));
    const delta_pc = emit.offset() - emit.prev_di_offset;
    // TODO: This must emit a relocation to calculate the offset relative
    // to the code section start.
    try emit.dbg_output.dwarf.advance_pcand_line(delta_line, delta_pc);

    emit.prev_di_line = line;
    emit.prev_di_column = column;
    emit.prev_di_offset = emit.offset();
}

fn emit_dbg_prologue_end(emit: *Emit) !void {
    if (emit.dbg_output != .dwarf) return;

    try emit.dbg_output.dwarf.set_prologue_end();
    try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
}

fn emit_dbg_epilogue_begin(emit: *Emit) !void {
    if (emit.dbg_output != .dwarf) return;

    try emit.dbg_output.dwarf.set_epilogue_begin();
    try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
}
