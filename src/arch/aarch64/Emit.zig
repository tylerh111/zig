//! This file contains the functionality for lowering AArch64 MIR into
//! machine code

const Emit = @This();
const std = @import("std");
const math = std.math;
const Mir = @import("Mir.zig");
const bits = @import("bits.zig");
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const ErrorMsg = Module.ErrorMsg;
const assert = std.debug.assert;
const Instruction = bits.Instruction;
const Register = bits.Register;
const log = std.log.scoped(.aarch64_emit);
const DebugInfoOutput = @import("../../codegen.zig").DebugInfoOutput;

mir: Mir,
bin_file: *link.File,
debug_output: DebugInfoOutput,
target: *const std.Target,
err_msg: ?*ErrorMsg = null,
src_loc: Module.SrcLoc,
code: *std.ArrayList(u8),

prev_di_line: u32,
prev_di_column: u32,

/// Relative to the beginning of `code`.
prev_di_pc: usize,

/// The amount of stack space consumed by the saved callee-saved
/// registers in bytes
saved_regs_stack_space: u32,

/// The branch type of every branch
branch_types: std.AutoHashMapUnmanaged(Mir.Inst.Index, BranchType) = .{},

/// For every forward branch, maps the target instruction to a list of
/// branches which branch to this target instruction
branch_forward_origins: std.AutoHashMapUnmanaged(Mir.Inst.Index, std.ArrayListUnmanaged(Mir.Inst.Index)) = .{},

/// For backward branches: stores the code offset of the target
/// instruction
///
/// For forward branches: stores the code offset of the branch
/// instruction
code_offset_mapping: std.AutoHashMapUnmanaged(Mir.Inst.Index, usize) = .{},

/// The final stack frame size of the function (already aligned to the
/// respective stack alignment). Does not include prologue stack space.
stack_size: u32,

const InnerError = error{
    OutOfMemory,
    EmitFail,
};

const BranchType = enum {
    cbz,
    b_cond,
    unconditional_branch_immediate,

    fn default(tag: Mir.Inst.Tag) BranchType {
        return switch (tag) {
            .cbz => .cbz,
            .b, .bl => .unconditional_branch_immediate,
            .b_cond => .b_cond,
            else => unreachable,
        };
    }
};

pub fn emit_mir(
    emit: *Emit,
) !void {
    const mir_tags = emit.mir.instructions.items(.tag);

    // Find smallest lowerings for branch instructions
    try emit.lower_branches();

    // Emit machine code
    for (mir_tags, 0..) |tag, index| {
        const inst = @as(u32, @int_cast(index));
        switch (tag) {
            .add_immediate => try emit.mir_add_subtract_immediate(inst),
            .adds_immediate => try emit.mir_add_subtract_immediate(inst),
            .cmp_immediate => try emit.mir_add_subtract_immediate(inst),
            .sub_immediate => try emit.mir_add_subtract_immediate(inst),
            .subs_immediate => try emit.mir_add_subtract_immediate(inst),

            .asr_register => try emit.mir_data_processing2_source(inst),
            .lsl_register => try emit.mir_data_processing2_source(inst),
            .lsr_register => try emit.mir_data_processing2_source(inst),
            .sdiv => try emit.mir_data_processing2_source(inst),
            .udiv => try emit.mir_data_processing2_source(inst),

            .asr_immediate => try emit.mir_shift_immediate(inst),
            .lsl_immediate => try emit.mir_shift_immediate(inst),
            .lsr_immediate => try emit.mir_shift_immediate(inst),

            .b_cond => try emit.mir_conditional_branch_immediate(inst),

            .b => try emit.mir_branch(inst),
            .bl => try emit.mir_branch(inst),

            .cbz => try emit.mir_compare_and_branch(inst),

            .blr => try emit.mir_unconditional_branch_register(inst),
            .ret => try emit.mir_unconditional_branch_register(inst),

            .brk => try emit.mir_exception_generation(inst),
            .svc => try emit.mir_exception_generation(inst),

            .call_extern => try emit.mir_call_extern(inst),

            .eor_immediate => try emit.mir_logical_immediate(inst),
            .tst_immediate => try emit.mir_logical_immediate(inst),

            .add_shifted_register => try emit.mir_add_subtract_shifted_register(inst),
            .adds_shifted_register => try emit.mir_add_subtract_shifted_register(inst),
            .cmp_shifted_register => try emit.mir_add_subtract_shifted_register(inst),
            .sub_shifted_register => try emit.mir_add_subtract_shifted_register(inst),
            .subs_shifted_register => try emit.mir_add_subtract_shifted_register(inst),

            .add_extended_register => try emit.mir_add_subtract_extended_register(inst),
            .adds_extended_register => try emit.mir_add_subtract_extended_register(inst),
            .sub_extended_register => try emit.mir_add_subtract_extended_register(inst),
            .subs_extended_register => try emit.mir_add_subtract_extended_register(inst),
            .cmp_extended_register => try emit.mir_add_subtract_extended_register(inst),

            .csel => try emit.mir_conditional_select(inst),
            .cset => try emit.mir_conditional_select(inst),

            .dbg_line => try emit.mir_dbg_line(inst),

            .dbg_prologue_end => try emit.mir_debug_prologue_end(),
            .dbg_epilogue_begin => try emit.mir_debug_epilogue_begin(),

            .and_shifted_register => try emit.mir_logical_shifted_register(inst),
            .eor_shifted_register => try emit.mir_logical_shifted_register(inst),
            .orr_shifted_register => try emit.mir_logical_shifted_register(inst),

            .load_memory_got => try emit.mir_load_memory_pie(inst),
            .load_memory_direct => try emit.mir_load_memory_pie(inst),
            .load_memory_import => try emit.mir_load_memory_pie(inst),
            .load_memory_ptr_got => try emit.mir_load_memory_pie(inst),
            .load_memory_ptr_direct => try emit.mir_load_memory_pie(inst),

            .ldp => try emit.mir_load_store_register_pair(inst),
            .stp => try emit.mir_load_store_register_pair(inst),

            .ldr_ptr_stack => try emit.mir_load_store_stack(inst),
            .ldr_stack => try emit.mir_load_store_stack(inst),
            .ldrb_stack => try emit.mir_load_store_stack(inst),
            .ldrh_stack => try emit.mir_load_store_stack(inst),
            .ldrsb_stack => try emit.mir_load_store_stack(inst),
            .ldrsh_stack => try emit.mir_load_store_stack(inst),
            .str_stack => try emit.mir_load_store_stack(inst),
            .strb_stack => try emit.mir_load_store_stack(inst),
            .strh_stack => try emit.mir_load_store_stack(inst),

            .ldr_ptr_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldr_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrb_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrh_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrsb_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrsh_stack_argument => try emit.mir_load_stack_argument(inst),

            .ldr_register => try emit.mir_load_store_register_register(inst),
            .ldrb_register => try emit.mir_load_store_register_register(inst),
            .ldrh_register => try emit.mir_load_store_register_register(inst),
            .str_register => try emit.mir_load_store_register_register(inst),
            .strb_register => try emit.mir_load_store_register_register(inst),
            .strh_register => try emit.mir_load_store_register_register(inst),

            .ldr_immediate => try emit.mir_load_store_register_immediate(inst),
            .ldrb_immediate => try emit.mir_load_store_register_immediate(inst),
            .ldrh_immediate => try emit.mir_load_store_register_immediate(inst),
            .ldrsb_immediate => try emit.mir_load_store_register_immediate(inst),
            .ldrsh_immediate => try emit.mir_load_store_register_immediate(inst),
            .ldrsw_immediate => try emit.mir_load_store_register_immediate(inst),
            .str_immediate => try emit.mir_load_store_register_immediate(inst),
            .strb_immediate => try emit.mir_load_store_register_immediate(inst),
            .strh_immediate => try emit.mir_load_store_register_immediate(inst),

            .mov_register => try emit.mir_move_register(inst),
            .mov_to_from_sp => try emit.mir_move_register(inst),
            .mvn => try emit.mir_move_register(inst),

            .movk => try emit.mir_move_wide_immediate(inst),
            .movz => try emit.mir_move_wide_immediate(inst),

            .msub => try emit.mir_data_processing3_source(inst),
            .mul => try emit.mir_data_processing3_source(inst),
            .smulh => try emit.mir_data_processing3_source(inst),
            .smull => try emit.mir_data_processing3_source(inst),
            .umulh => try emit.mir_data_processing3_source(inst),
            .umull => try emit.mir_data_processing3_source(inst),

            .nop => try emit.mir_nop(),

            .push_regs => try emit.mir_push_pop_regs(inst),
            .pop_regs => try emit.mir_push_pop_regs(inst),

            .sbfx,
            .ubfx,
            => try emit.mir_bitfield_extract(inst),

            .sxtb,
            .sxth,
            .sxtw,
            .uxtb,
            .uxth,
            => try emit.mir_extend(inst),
        }
    }
}

pub fn deinit(emit: *Emit) void {
    const comp = emit.bin_file.comp;
    const gpa = comp.gpa;
    var iter = emit.branch_forward_origins.value_iterator();
    while (iter.next()) |origin_list| {
        origin_list.deinit(gpa);
    }

    emit.branch_types.deinit(gpa);
    emit.branch_forward_origins.deinit(gpa);
    emit.code_offset_mapping.deinit(gpa);
    emit.* = undefined;
}

fn optimal_branch_type(emit: *Emit, tag: Mir.Inst.Tag, offset: i64) !BranchType {
    assert(offset & 0b11 == 0);

    switch (tag) {
        .cbz => {
            if (std.math.cast(i19, @shrExact(offset, 2))) |_| {
                return BranchType.cbz;
            } else {
                return emit.fail("TODO support cbz branches larger than +-1 MiB", .{});
            }
        },
        .b, .bl => {
            if (std.math.cast(i26, @shrExact(offset, 2))) |_| {
                return BranchType.unconditional_branch_immediate;
            } else {
                return emit.fail("TODO support unconditional branches larger than +-128 MiB", .{});
            }
        },
        .b_cond => {
            if (std.math.cast(i19, @shrExact(offset, 2))) |_| {
                return BranchType.b_cond;
            } else {
                return emit.fail("TODO support conditional branches larger than +-1 MiB", .{});
            }
        },
        else => unreachable,
    }
}

fn instruction_size(emit: *Emit, inst: Mir.Inst.Index) usize {
    const tag = emit.mir.instructions.items(.tag)[inst];

    if (is_branch(tag)) {
        switch (emit.branch_types.get(inst).?) {
            .cbz,
            .unconditional_branch_immediate,
            .b_cond,
            => return 4,
        }
    }

    switch (tag) {
        .load_memory_direct => return 3 * 4,
        .load_memory_got,
        .load_memory_ptr_got,
        .load_memory_ptr_direct,
        => return 2 * 4,
        .pop_regs, .push_regs => {
            const reg_list = emit.mir.instructions.items(.data)[inst].reg_list;
            const number_of_regs = @pop_count(reg_list);
            const number_of_insts = std.math.div_ceil(u6, number_of_regs, 2) catch unreachable;
            return number_of_insts * 4;
        },
        .call_extern => return 4,
        .dbg_line,
        .dbg_epilogue_begin,
        .dbg_prologue_end,
        => return 0,
        else => return 4,
    }
}

fn is_branch(tag: Mir.Inst.Tag) bool {
    return switch (tag) {
        .cbz,
        .b,
        .bl,
        .b_cond,
        => true,
        else => false,
    };
}

fn branch_target(emit: *Emit, inst: Mir.Inst.Index) Mir.Inst.Index {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .cbz => return emit.mir.instructions.items(.data)[inst].r_inst.inst,
        .b, .bl => return emit.mir.instructions.items(.data)[inst].inst,
        .b_cond => return emit.mir.instructions.items(.data)[inst].inst_cond.inst,
        else => unreachable,
    }
}

fn lower_branches(emit: *Emit) !void {
    const comp = emit.bin_file.comp;
    const gpa = comp.gpa;
    const mir_tags = emit.mir.instructions.items(.tag);

    // First pass: Note down all branches and their target
    // instructions, i.e. populate branch_types,
    // branch_forward_origins, and code_offset_mapping
    //
    // TODO optimization opportunity: do this in codegen while
    // generating MIR
    for (mir_tags, 0..) |tag, index| {
        const inst = @as(u32, @int_cast(index));
        if (is_branch(tag)) {
            const target_inst = emit.branch_target(inst);

            // Remember this branch instruction
            try emit.branch_types.put(gpa, inst, BranchType.default(tag));

            // Forward branches require some extra stuff: We only
            // know their offset once we arrive at the target
            // instruction. Therefore, we need to be able to
            // access the branch instruction when we visit the
            // target instruction in order to manipulate its type
            // etc.
            if (target_inst > inst) {
                // Remember the branch instruction index
                try emit.code_offset_mapping.put(gpa, inst, 0);

                if (emit.branch_forward_origins.get_ptr(target_inst)) |origin_list| {
                    try origin_list.append(gpa, inst);
                } else {
                    var origin_list: std.ArrayListUnmanaged(Mir.Inst.Index) = .{};
                    try origin_list.append(gpa, inst);
                    try emit.branch_forward_origins.put(gpa, target_inst, origin_list);
                }
            }

            // Remember the target instruction index so that we
            // update the real code offset in all future passes
            //
            // put_no_clobber may not be used as the put operation
            // may clobber the entry when multiple branches branch
            // to the same target instruction
            try emit.code_offset_mapping.put(gpa, target_inst, 0);
        }
    }

    // Further passes: Until all branches are lowered, interate
    // through all instructions and calculate new offsets and
    // potentially new branch types
    var all_branches_lowered = false;
    while (!all_branches_lowered) {
        all_branches_lowered = true;
        var current_code_offset: usize = 0;

        for (mir_tags, 0..) |tag, index| {
            const inst = @as(u32, @int_cast(index));

            // If this instruction contained in the code offset
            // mapping (when it is a target of a branch or if it is a
            // forward branch), update the code offset
            if (emit.code_offset_mapping.get_ptr(inst)) |offset| {
                offset.* = current_code_offset;
            }

            // If this instruction is a backward branch, calculate the
            // offset, which may potentially update the branch type
            if (is_branch(tag)) {
                const target_inst = emit.branch_target(inst);
                if (target_inst < inst) {
                    const target_offset = emit.code_offset_mapping.get(target_inst).?;
                    const offset = @as(i64, @int_cast(target_offset)) - @as(i64, @int_cast(current_code_offset));
                    const branch_type = emit.branch_types.get_ptr(inst).?;
                    const optimal_branch_type = try emit.optimal_branch_type(tag, offset);
                    if (branch_type.* != optimal_branch_type) {
                        branch_type.* = optimal_branch_type;
                        all_branches_lowered = false;
                    }

                    log.debug("lower_branches: branch {} has offset {}", .{ inst, offset });
                }
            }

            // If this instruction is the target of one or more
            // forward branches, calculate the offset, which may
            // potentially update the branch type
            if (emit.branch_forward_origins.get(inst)) |origin_list| {
                for (origin_list.items) |forward_branch_inst| {
                    const branch_tag = emit.mir.instructions.items(.tag)[forward_branch_inst];
                    const forward_branch_inst_offset = emit.code_offset_mapping.get(forward_branch_inst).?;
                    const offset = @as(i64, @int_cast(current_code_offset)) - @as(i64, @int_cast(forward_branch_inst_offset));
                    const branch_type = emit.branch_types.get_ptr(forward_branch_inst).?;
                    const optimal_branch_type = try emit.optimal_branch_type(branch_tag, offset);
                    if (branch_type.* != optimal_branch_type) {
                        branch_type.* = optimal_branch_type;
                        all_branches_lowered = false;
                    }

                    log.debug("lower_branches: branch {} has offset {}", .{ forward_branch_inst, offset });
                }
            }

            // Increment code offset
            current_code_offset += emit.instruction_size(inst);
        }
    }
}

fn write_instruction(emit: *Emit, instruction: Instruction) !void {
    const endian = emit.target.cpu.arch.endian();
    std.mem.write_int(u32, try emit.code.add_many_as_array(4), instruction.to_u32(), endian);
}

fn fail(emit: *Emit, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(emit.err_msg == null);
    const comp = emit.bin_file.comp;
    const gpa = comp.gpa;
    emit.err_msg = try ErrorMsg.create(gpa, emit.src_loc, format, args);
    return error.EmitFail;
}

fn dbg_advance_pcand_line(emit: *Emit, line: u32, column: u32) InnerError!void {
    const delta_line = @as(i33, line) - @as(i33, emit.prev_di_line);
    const delta_pc: usize = emit.code.items.len - emit.prev_di_pc;
    log.debug("  (advance pc={d} and line={d})", .{ delta_pc, delta_line });
    switch (emit.debug_output) {
        .dwarf => |dw| {
            if (column != emit.prev_di_column) try dw.set_column(column);
            try dw.advance_pcand_line(delta_line, delta_pc);
            emit.prev_di_line = line;
            emit.prev_di_column = column;
            emit.prev_di_pc = emit.code.items.len;
        },
        .plan9 => |dbg_out| {
            if (delta_pc <= 0) return; // only do this when the pc changes

            // increasing the line number
            try link.File.Plan9.change_line(&dbg_out.dbg_line, @int_cast(delta_line));
            // increasing the pc
            const d_pc_p9 = @as(i64, @int_cast(delta_pc)) - dbg_out.pc_quanta;
            if (d_pc_p9 > 0) {
                // minus one because if its the last one, we want to leave space to change the line which is one pc quanta
                var diff = @div_exact(d_pc_p9, dbg_out.pc_quanta) - dbg_out.pc_quanta;
                while (diff > 0) {
                    if (diff < 64) {
                        try dbg_out.dbg_line.append(@int_cast(diff + 128));
                        diff = 0;
                    } else {
                        try dbg_out.dbg_line.append(@int_cast(64 + 128));
                        diff -= 64;
                    }
                }
                if (dbg_out.pcop_change_index) |pci|
                    dbg_out.dbg_line.items[pci] += 1;
                dbg_out.pcop_change_index = @int_cast(dbg_out.dbg_line.items.len - 1);
            } else if (d_pc_p9 == 0) {
                // we don't need to do anything, because adding the pc quanta does it for us
            } else unreachable;
            if (dbg_out.start_line == null)
                dbg_out.start_line = emit.prev_di_line;
            dbg_out.end_line = line;
            // only do this if the pc changed
            emit.prev_di_line = line;
            emit.prev_di_column = column;
            emit.prev_di_pc = emit.code.items.len;
        },
        .none => {},
    }
}

fn mir_add_subtract_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    switch (tag) {
        .add_immediate,
        .adds_immediate,
        .sub_immediate,
        .subs_immediate,
        => {
            const rr_imm12_sh = emit.mir.instructions.items(.data)[inst].rr_imm12_sh;
            const rd = rr_imm12_sh.rd;
            const rn = rr_imm12_sh.rn;
            const imm12 = rr_imm12_sh.imm12;
            const sh = rr_imm12_sh.sh == 1;

            switch (tag) {
                .add_immediate => try emit.write_instruction(Instruction.add(rd, rn, imm12, sh)),
                .adds_immediate => try emit.write_instruction(Instruction.adds(rd, rn, imm12, sh)),
                .sub_immediate => try emit.write_instruction(Instruction.sub(rd, rn, imm12, sh)),
                .subs_immediate => try emit.write_instruction(Instruction.subs(rd, rn, imm12, sh)),
                else => unreachable,
            }
        },
        .cmp_immediate => {
            const r_imm12_sh = emit.mir.instructions.items(.data)[inst].r_imm12_sh;
            const rn = r_imm12_sh.rn;
            const imm12 = r_imm12_sh.imm12;
            const sh = r_imm12_sh.sh == 1;
            const zr: Register = switch (rn.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };

            try emit.write_instruction(Instruction.subs(zr, rn, imm12, sh));
        },
        else => unreachable,
    }
}

fn mir_data_processing2_source(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rrr = emit.mir.instructions.items(.data)[inst].rrr;
    const rd = rrr.rd;
    const rn = rrr.rn;
    const rm = rrr.rm;

    switch (tag) {
        .asr_register => try emit.write_instruction(Instruction.asrRegister(rd, rn, rm)),
        .lsl_register => try emit.write_instruction(Instruction.lslRegister(rd, rn, rm)),
        .lsr_register => try emit.write_instruction(Instruction.lsrRegister(rd, rn, rm)),
        .sdiv => try emit.write_instruction(Instruction.sdiv(rd, rn, rm)),
        .udiv => try emit.write_instruction(Instruction.udiv(rd, rn, rm)),
        else => unreachable,
    }
}

fn mir_shift_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rr_shift = emit.mir.instructions.items(.data)[inst].rr_shift;
    const rd = rr_shift.rd;
    const rn = rr_shift.rn;
    const shift = rr_shift.shift;

    switch (tag) {
        .asr_immediate => try emit.write_instruction(Instruction.asr_immediate(rd, rn, shift)),
        .lsl_immediate => try emit.write_instruction(Instruction.lsl_immediate(rd, rn, shift)),
        .lsr_immediate => try emit.write_instruction(Instruction.lsr_immediate(rd, rn, shift)),
        else => unreachable,
    }
}

fn mir_conditional_branch_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const inst_cond = emit.mir.instructions.items(.data)[inst].inst_cond;

    const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(inst_cond.inst).?)) - @as(i64, @int_cast(emit.code.items.len));
    const branch_type = emit.branch_types.get(inst).?;
    log.debug("mir_conditional_branch_immediate: {} offset={}", .{ inst, offset });

    switch (branch_type) {
        .b_cond => switch (tag) {
            .b_cond => try emit.write_instruction(Instruction.b_cond(inst_cond.cond, @as(i21, @int_cast(offset)))),
            else => unreachable,
        },
        else => unreachable,
    }
}

fn mir_branch(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const target_inst = emit.mir.instructions.items(.data)[inst].inst;

    log.debug("branch {}(tag: {}) -> {}(tag: {})", .{
        inst,
        tag,
        target_inst,
        emit.mir.instructions.items(.tag)[target_inst],
    });

    const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(target_inst).?)) - @as(i64, @int_cast(emit.code.items.len));
    const branch_type = emit.branch_types.get(inst).?;
    log.debug("mir_branch: {} offset={}", .{ inst, offset });

    switch (branch_type) {
        .unconditional_branch_immediate => switch (tag) {
            .b => try emit.write_instruction(Instruction.b(@as(i28, @int_cast(offset)))),
            .bl => try emit.write_instruction(Instruction.bl(@as(i28, @int_cast(offset)))),
            else => unreachable,
        },
        else => unreachable,
    }
}

fn mir_compare_and_branch(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const r_inst = emit.mir.instructions.items(.data)[inst].r_inst;

    const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(r_inst.inst).?)) - @as(i64, @int_cast(emit.code.items.len));
    const branch_type = emit.branch_types.get(inst).?;
    log.debug("mir_compare_and_branch: {} offset={}", .{ inst, offset });

    switch (branch_type) {
        .cbz => switch (tag) {
            .cbz => try emit.write_instruction(Instruction.cbz(r_inst.rt, @as(i21, @int_cast(offset)))),
            else => unreachable,
        },
        else => unreachable,
    }
}

fn mir_unconditional_branch_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const reg = emit.mir.instructions.items(.data)[inst].reg;

    switch (tag) {
        .blr => try emit.write_instruction(Instruction.blr(reg)),
        .ret => try emit.write_instruction(Instruction.ret(reg)),
        else => unreachable,
    }
}

fn mir_exception_generation(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const imm16 = emit.mir.instructions.items(.data)[inst].imm16;

    switch (tag) {
        .brk => try emit.write_instruction(Instruction.brk(imm16)),
        .svc => try emit.write_instruction(Instruction.svc(imm16)),
        else => unreachable,
    }
}

fn mir_dbg_line(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const dbg_line_column = emit.mir.instructions.items(.data)[inst].dbg_line_column;

    switch (tag) {
        .dbg_line => try emit.dbg_advance_pcand_line(dbg_line_column.line, dbg_line_column.column),
        else => unreachable,
    }
}

fn mir_debug_prologue_end(emit: *Emit) !void {
    switch (emit.debug_output) {
        .dwarf => |dw| {
            try dw.set_prologue_end();
            log.debug("mirDbgPrologueEnd (line={d}, col={d})", .{
                emit.prev_di_line, emit.prev_di_column,
            });
            try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
        },
        .plan9 => {},
        .none => {},
    }
}

fn mir_debug_epilogue_begin(emit: *Emit) !void {
    switch (emit.debug_output) {
        .dwarf => |dw| {
            try dw.set_epilogue_begin();
            try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
        },
        .plan9 => {},
        .none => {},
    }
}

fn mir_call_extern(emit: *Emit, inst: Mir.Inst.Index) !void {
    assert(emit.mir.instructions.items(.tag)[inst] == .call_extern);
    const relocation = emit.mir.instructions.items(.data)[inst].relocation;
    _ = relocation;

    const offset = blk: {
        const offset = @as(u32, @int_cast(emit.code.items.len));
        // bl
        try emit.write_instruction(Instruction.bl(0));
        break :blk offset;
    };
    _ = offset;

    if (emit.bin_file.cast(link.File.MachO)) |macho_file| {
        _ = macho_file;
        @panic("TODO mir_call_extern");
        // // Add relocation to the decl.
        // const atom_index = macho_file.get_atom_index_for_symbol(.{ .sym_index = relocation.atom_index }).?;
        // const target = macho_file.get_global_by_index(relocation.sym_index);
        // try link.File.MachO.Atom.add_relocation(macho_file, atom_index, .{
        //     .type = .branch,
        //     .target = target,
        //     .offset = offset,
        //     .addend = 0,
        //     .pcrel = true,
        //     .length = 2,
        // });
    } else if (emit.bin_file.cast(link.File.Coff)) |_| {
        unreachable; // Calling imports is handled via `.load_memory_import`
    } else {
        return emit.fail("Implement call_extern for linking backends != {{ COFF, MachO }}", .{});
    }
}

fn mir_logical_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rr_bitmask = emit.mir.instructions.items(.data)[inst].rr_bitmask;
    const rd = rr_bitmask.rd;
    const rn = rr_bitmask.rn;
    const imms = rr_bitmask.imms;
    const immr = rr_bitmask.immr;
    const n = rr_bitmask.n;

    switch (tag) {
        .eor_immediate => try emit.write_instruction(Instruction.eor_immediate(rd, rn, imms, immr, n)),
        .tst_immediate => {
            const zr: Register = switch (rd.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };
            try emit.write_instruction(Instruction.ands_immediate(zr, rn, imms, immr, n));
        },
        else => unreachable,
    }
}

fn mir_add_subtract_shifted_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    switch (tag) {
        .add_shifted_register,
        .adds_shifted_register,
        .sub_shifted_register,
        .subs_shifted_register,
        => {
            const rrr_imm6_shift = emit.mir.instructions.items(.data)[inst].rrr_imm6_shift;
            const rd = rrr_imm6_shift.rd;
            const rn = rrr_imm6_shift.rn;
            const rm = rrr_imm6_shift.rm;
            const shift = rrr_imm6_shift.shift;
            const imm6 = rrr_imm6_shift.imm6;

            switch (tag) {
                .add_shifted_register => try emit.write_instruction(Instruction.add_shifted_register(rd, rn, rm, shift, imm6)),
                .adds_shifted_register => try emit.write_instruction(Instruction.adds_shifted_register(rd, rn, rm, shift, imm6)),
                .sub_shifted_register => try emit.write_instruction(Instruction.sub_shifted_register(rd, rn, rm, shift, imm6)),
                .subs_shifted_register => try emit.write_instruction(Instruction.subs_shifted_register(rd, rn, rm, shift, imm6)),
                else => unreachable,
            }
        },
        .cmp_shifted_register => {
            const rr_imm6_shift = emit.mir.instructions.items(.data)[inst].rr_imm6_shift;
            const rn = rr_imm6_shift.rn;
            const rm = rr_imm6_shift.rm;
            const shift = rr_imm6_shift.shift;
            const imm6 = rr_imm6_shift.imm6;
            const zr: Register = switch (rn.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };

            try emit.write_instruction(Instruction.subs_shifted_register(zr, rn, rm, shift, imm6));
        },
        else => unreachable,
    }
}

fn mir_add_subtract_extended_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    switch (tag) {
        .add_extended_register,
        .adds_extended_register,
        .sub_extended_register,
        .subs_extended_register,
        => {
            const rrr_extend_shift = emit.mir.instructions.items(.data)[inst].rrr_extend_shift;
            const rd = rrr_extend_shift.rd;
            const rn = rrr_extend_shift.rn;
            const rm = rrr_extend_shift.rm;
            const ext_type = rrr_extend_shift.ext_type;
            const imm3 = rrr_extend_shift.imm3;

            switch (tag) {
                .add_extended_register => try emit.write_instruction(Instruction.add_extended_register(rd, rn, rm, ext_type, imm3)),
                .adds_extended_register => try emit.write_instruction(Instruction.adds_extended_register(rd, rn, rm, ext_type, imm3)),
                .sub_extended_register => try emit.write_instruction(Instruction.sub_extended_register(rd, rn, rm, ext_type, imm3)),
                .subs_extended_register => try emit.write_instruction(Instruction.subs_extended_register(rd, rn, rm, ext_type, imm3)),
                else => unreachable,
            }
        },
        .cmp_extended_register => {
            const rr_extend_shift = emit.mir.instructions.items(.data)[inst].rr_extend_shift;
            const rn = rr_extend_shift.rn;
            const rm = rr_extend_shift.rm;
            const ext_type = rr_extend_shift.ext_type;
            const imm3 = rr_extend_shift.imm3;
            const zr: Register = switch (rn.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };

            try emit.write_instruction(Instruction.subs_extended_register(zr, rn, rm, ext_type, imm3));
        },
        else => unreachable,
    }
}

fn mir_conditional_select(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    switch (tag) {
        .csel => {
            const rrr_cond = emit.mir.instructions.items(.data)[inst].rrr_cond;
            const rd = rrr_cond.rd;
            const rn = rrr_cond.rn;
            const rm = rrr_cond.rm;
            const cond = rrr_cond.cond;
            try emit.write_instruction(Instruction.csel(rd, rn, rm, cond));
        },
        .cset => {
            const r_cond = emit.mir.instructions.items(.data)[inst].r_cond;
            const zr: Register = switch (r_cond.rd.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };
            try emit.write_instruction(Instruction.csinc(r_cond.rd, zr, zr, r_cond.cond.negate()));
        },
        else => unreachable,
    }
}

fn mir_logical_shifted_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rrr_imm6_logical_shift = emit.mir.instructions.items(.data)[inst].rrr_imm6_logical_shift;
    const rd = rrr_imm6_logical_shift.rd;
    const rn = rrr_imm6_logical_shift.rn;
    const rm = rrr_imm6_logical_shift.rm;
    const shift = rrr_imm6_logical_shift.shift;
    const imm6 = rrr_imm6_logical_shift.imm6;

    switch (tag) {
        .and_shifted_register => try emit.write_instruction(Instruction.and_shifted_register(rd, rn, rm, shift, imm6)),
        .eor_shifted_register => try emit.write_instruction(Instruction.eor_shifted_register(rd, rn, rm, shift, imm6)),
        .orr_shifted_register => try emit.write_instruction(Instruction.orr_shifted_register(rd, rn, rm, shift, imm6)),
        else => unreachable,
    }
}

fn mir_load_memory_pie(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const payload = emit.mir.instructions.items(.data)[inst].payload;
    const data = emit.mir.extra_data(Mir.LoadMemoryPie, payload).data;
    const reg = @as(Register, @enumFromInt(data.register));

    // PC-relative displacement to the entry in memory.
    // adrp
    const offset = @as(u32, @int_cast(emit.code.items.len));
    try emit.write_instruction(Instruction.adrp(reg.to_x(), 0));

    switch (tag) {
        .load_memory_got,
        .load_memory_import,
        => {
            // ldr reg, reg, offset
            try emit.write_instruction(Instruction.ldr(
                reg,
                reg.to_x(),
                Instruction.LoadStoreOffset.imm(0),
            ));
        },
        .load_memory_direct => {
            // We cannot load the offset directly as it may not be aligned properly.
            // For example, load for 64bit register will require the target address offset
            // to be 8-byte aligned, while the value might have non-8-byte natural alignment,
            // meaning the linker might have put it at a non-8-byte aligned address. To circumvent
            // this, we use `adrp, add` to form the address value which we then dereference with
            // `ldr`.
            // Note that this can potentially be optimised out by the codegen/linker if the
            // target address is appropriately aligned.
            // add reg, reg, offset
            try emit.write_instruction(Instruction.add(reg.to_x(), reg.to_x(), 0, false));
            // ldr reg, reg, offset
            try emit.write_instruction(Instruction.ldr(
                reg,
                reg.to_x(),
                Instruction.LoadStoreOffset.imm(0),
            ));
        },
        .load_memory_ptr_direct,
        .load_memory_ptr_got,
        => {
            // add reg, reg, offset
            try emit.write_instruction(Instruction.add(reg, reg, 0, false));
        },
        else => unreachable,
    }

    if (emit.bin_file.cast(link.File.MachO)) |macho_file| {
        _ = macho_file;
        @panic("TODO mir_load_memory_pie");
        // const Atom = link.File.MachO.Atom;
        // const Relocation = Atom.Relocation;
        // const atom_index = macho_file.get_atom_index_for_symbol(.{ .sym_index = data.atom_index }).?;
        // try Atom.addRelocations(macho_file, atom_index, &[_]Relocation{ .{
        //     .target = .{ .sym_index = data.sym_index },
        //     .offset = offset,
        //     .addend = 0,
        //     .pcrel = true,
        //     .length = 2,
        //     .type = switch (tag) {
        //         .load_memory_got, .load_memory_ptr_got => Relocation.Type.got_page,
        //         .load_memory_direct, .load_memory_ptr_direct => Relocation.Type.page,
        //         else => unreachable,
        //     },
        // }, .{
        //     .target = .{ .sym_index = data.sym_index },
        //     .offset = offset + 4,
        //     .addend = 0,
        //     .pcrel = false,
        //     .length = 2,
        //     .type = switch (tag) {
        //         .load_memory_got, .load_memory_ptr_got => Relocation.Type.got_pageoff,
        //         .load_memory_direct, .load_memory_ptr_direct => Relocation.Type.pageoff,
        //         else => unreachable,
        //     },
        // } });
    } else if (emit.bin_file.cast(link.File.Coff)) |coff_file| {
        const atom_index = coff_file.get_atom_index_for_symbol(.{ .sym_index = data.atom_index, .file = null }).?;
        const target = switch (tag) {
            .load_memory_got,
            .load_memory_ptr_got,
            .load_memory_direct,
            .load_memory_ptr_direct,
            => link.File.Coff.SymbolWithLoc{ .sym_index = data.sym_index, .file = null },
            .load_memory_import => coff_file.get_global_by_index(data.sym_index),
            else => unreachable,
        };
        try link.File.Coff.Atom.add_relocation(coff_file, atom_index, .{
            .target = target,
            .offset = offset,
            .addend = 0,
            .pcrel = true,
            .length = 2,
            .type = switch (tag) {
                .load_memory_got,
                .load_memory_ptr_got,
                => .got_page,
                .load_memory_direct,
                .load_memory_ptr_direct,
                => .page,
                .load_memory_import => .import_page,
                else => unreachable,
            },
        });
        try link.File.Coff.Atom.add_relocation(coff_file, atom_index, .{
            .target = target,
            .offset = offset + 4,
            .addend = 0,
            .pcrel = false,
            .length = 2,
            .type = switch (tag) {
                .load_memory_got,
                .load_memory_ptr_got,
                => .got_pageoff,
                .load_memory_direct,
                .load_memory_ptr_direct,
                => .pageoff,
                .load_memory_import => .import_pageoff,
                else => unreachable,
            },
        });
    } else {
        return emit.fail("TODO implement load_memory for PIE GOT indirection on this platform", .{});
    }
}

fn mir_load_store_register_pair(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const load_store_register_pair = emit.mir.instructions.items(.data)[inst].load_store_register_pair;
    const rt = load_store_register_pair.rt;
    const rt2 = load_store_register_pair.rt2;
    const rn = load_store_register_pair.rn;
    const offset = load_store_register_pair.offset;

    switch (tag) {
        .stp => try emit.write_instruction(Instruction.stp(rt, rt2, rn, offset)),
        .ldp => try emit.write_instruction(Instruction.ldp(rt, rt2, rn, offset)),
        else => unreachable,
    }
}

fn mir_load_stack_argument(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const load_store_stack = emit.mir.instructions.items(.data)[inst].load_store_stack;
    const rt = load_store_stack.rt;

    const raw_offset = emit.stack_size + emit.saved_regs_stack_space + load_store_stack.offset;
    switch (tag) {
        .ldr_ptr_stack_argument => {
            const offset = if (math.cast(u12, raw_offset)) |imm| imm else {
                return emit.fail("TODO load stack argument ptr with larger offset", .{});
            };

            switch (tag) {
                .ldr_ptr_stack_argument => try emit.write_instruction(Instruction.add(rt, .sp, offset, false)),
                else => unreachable,
            }
        },
        .ldrb_stack_argument, .ldrsb_stack_argument => {
            const offset = if (math.cast(u12, raw_offset)) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load stack argument byte with larger offset", .{});
            };

            switch (tag) {
                .ldrb_stack_argument => try emit.write_instruction(Instruction.ldrb(rt, .sp, offset)),
                .ldrsb_stack_argument => try emit.write_instruction(Instruction.ldrsb(rt, .sp, offset)),
                else => unreachable,
            }
        },
        .ldrh_stack_argument, .ldrsh_stack_argument => {
            assert(std.mem.is_aligned_generic(u32, raw_offset, 2)); // misaligned stack entry
            const offset = if (math.cast(u12, @div_exact(raw_offset, 2))) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load stack argument halfword with larger offset", .{});
            };

            switch (tag) {
                .ldrh_stack_argument => try emit.write_instruction(Instruction.ldrh(rt, .sp, offset)),
                .ldrsh_stack_argument => try emit.write_instruction(Instruction.ldrsh(rt, .sp, offset)),
                else => unreachable,
            }
        },
        .ldr_stack_argument => {
            const alignment: u32 = switch (rt.size()) {
                32 => 4,
                64 => 8,
                else => unreachable,
            };

            assert(std.mem.is_aligned_generic(u32, raw_offset, alignment)); // misaligned stack entry
            const offset = if (math.cast(u12, @div_exact(raw_offset, alignment))) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load stack argument with larger offset", .{});
            };

            switch (tag) {
                .ldr_stack_argument => try emit.write_instruction(Instruction.ldr(rt, .sp, offset)),
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn mir_load_store_stack(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const load_store_stack = emit.mir.instructions.items(.data)[inst].load_store_stack;
    const rt = load_store_stack.rt;

    const raw_offset = emit.stack_size - load_store_stack.offset;
    switch (tag) {
        .ldr_ptr_stack => {
            const offset = if (math.cast(u12, raw_offset)) |imm| imm else {
                return emit.fail("TODO load stack argument ptr with larger offset", .{});
            };

            switch (tag) {
                .ldr_ptr_stack => try emit.write_instruction(Instruction.add(rt, .sp, offset, false)),
                else => unreachable,
            }
        },
        .ldrb_stack, .ldrsb_stack, .strb_stack => {
            const offset = if (math.cast(u12, raw_offset)) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load/store stack byte with larger offset", .{});
            };

            switch (tag) {
                .ldrb_stack => try emit.write_instruction(Instruction.ldrb(rt, .sp, offset)),
                .ldrsb_stack => try emit.write_instruction(Instruction.ldrsb(rt, .sp, offset)),
                .strb_stack => try emit.write_instruction(Instruction.strb(rt, .sp, offset)),
                else => unreachable,
            }
        },
        .ldrh_stack, .ldrsh_stack, .strh_stack => {
            assert(std.mem.is_aligned_generic(u32, raw_offset, 2)); // misaligned stack entry
            const offset = if (math.cast(u12, @div_exact(raw_offset, 2))) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load/store stack halfword with larger offset", .{});
            };

            switch (tag) {
                .ldrh_stack => try emit.write_instruction(Instruction.ldrh(rt, .sp, offset)),
                .ldrsh_stack => try emit.write_instruction(Instruction.ldrsh(rt, .sp, offset)),
                .strh_stack => try emit.write_instruction(Instruction.strh(rt, .sp, offset)),
                else => unreachable,
            }
        },
        .ldr_stack, .str_stack => {
            const alignment: u32 = switch (rt.size()) {
                32 => 4,
                64 => 8,
                else => unreachable,
            };

            assert(std.mem.is_aligned_generic(u32, raw_offset, alignment)); // misaligned stack entry
            const offset = if (math.cast(u12, @div_exact(raw_offset, alignment))) |imm| Instruction.LoadStoreOffset.imm(imm) else {
                return emit.fail("TODO load/store stack with larger offset", .{});
            };

            switch (tag) {
                .ldr_stack => try emit.write_instruction(Instruction.ldr(rt, .sp, offset)),
                .str_stack => try emit.write_instruction(Instruction.str(rt, .sp, offset)),
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn mir_load_store_register_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const load_store_register_immediate = emit.mir.instructions.items(.data)[inst].load_store_register_immediate;
    const rt = load_store_register_immediate.rt;
    const rn = load_store_register_immediate.rn;
    const offset = Instruction.LoadStoreOffset{ .immediate = load_store_register_immediate.offset };

    switch (tag) {
        .ldr_immediate => try emit.write_instruction(Instruction.ldr(rt, rn, offset)),
        .ldrb_immediate => try emit.write_instruction(Instruction.ldrb(rt, rn, offset)),
        .ldrh_immediate => try emit.write_instruction(Instruction.ldrh(rt, rn, offset)),
        .ldrsb_immediate => try emit.write_instruction(Instruction.ldrsb(rt, rn, offset)),
        .ldrsh_immediate => try emit.write_instruction(Instruction.ldrsh(rt, rn, offset)),
        .ldrsw_immediate => try emit.write_instruction(Instruction.ldrsw(rt, rn, offset)),
        .str_immediate => try emit.write_instruction(Instruction.str(rt, rn, offset)),
        .strb_immediate => try emit.write_instruction(Instruction.strb(rt, rn, offset)),
        .strh_immediate => try emit.write_instruction(Instruction.strh(rt, rn, offset)),
        else => unreachable,
    }
}

fn mir_load_store_register_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const load_store_register_register = emit.mir.instructions.items(.data)[inst].load_store_register_register;
    const rt = load_store_register_register.rt;
    const rn = load_store_register_register.rn;
    const offset = Instruction.LoadStoreOffset{ .register = load_store_register_register.offset };

    switch (tag) {
        .ldr_register => try emit.write_instruction(Instruction.ldr(rt, rn, offset)),
        .ldrb_register => try emit.write_instruction(Instruction.ldrb(rt, rn, offset)),
        .ldrh_register => try emit.write_instruction(Instruction.ldrh(rt, rn, offset)),
        .str_register => try emit.write_instruction(Instruction.str(rt, rn, offset)),
        .strb_register => try emit.write_instruction(Instruction.strb(rt, rn, offset)),
        .strh_register => try emit.write_instruction(Instruction.strh(rt, rn, offset)),
        else => unreachable,
    }
}

fn mir_move_register(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    switch (tag) {
        .mov_register => {
            const rr = emit.mir.instructions.items(.data)[inst].rr;
            const zr: Register = switch (rr.rd.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };

            try emit.write_instruction(Instruction.orr_shifted_register(rr.rd, zr, rr.rn, .lsl, 0));
        },
        .mov_to_from_sp => {
            const rr = emit.mir.instructions.items(.data)[inst].rr;
            try emit.write_instruction(Instruction.add(rr.rd, rr.rn, 0, false));
        },
        .mvn => {
            const rr_imm6_logical_shift = emit.mir.instructions.items(.data)[inst].rr_imm6_logical_shift;
            const rd = rr_imm6_logical_shift.rd;
            const rm = rr_imm6_logical_shift.rm;
            const shift = rr_imm6_logical_shift.shift;
            const imm6 = rr_imm6_logical_shift.imm6;
            const zr: Register = switch (rd.size()) {
                32 => .wzr,
                64 => .xzr,
                else => unreachable,
            };

            try emit.write_instruction(Instruction.orn_shifted_register(rd, zr, rm, shift, imm6));
        },
        else => unreachable,
    }
}

fn mir_move_wide_immediate(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const r_imm16_sh = emit.mir.instructions.items(.data)[inst].r_imm16_sh;

    switch (tag) {
        .movz => try emit.write_instruction(Instruction.movz(r_imm16_sh.rd, r_imm16_sh.imm16, @as(u6, r_imm16_sh.hw) << 4)),
        .movk => try emit.write_instruction(Instruction.movk(r_imm16_sh.rd, r_imm16_sh.imm16, @as(u6, r_imm16_sh.hw) << 4)),
        else => unreachable,
    }
}

fn mir_data_processing3_source(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .mul,
        .smulh,
        .smull,
        .umulh,
        .umull,
        => {
            const rrr = emit.mir.instructions.items(.data)[inst].rrr;
            switch (tag) {
                .mul => try emit.write_instruction(Instruction.mul(rrr.rd, rrr.rn, rrr.rm)),
                .smulh => try emit.write_instruction(Instruction.smulh(rrr.rd, rrr.rn, rrr.rm)),
                .smull => try emit.write_instruction(Instruction.smull(rrr.rd, rrr.rn, rrr.rm)),
                .umulh => try emit.write_instruction(Instruction.umulh(rrr.rd, rrr.rn, rrr.rm)),
                .umull => try emit.write_instruction(Instruction.umull(rrr.rd, rrr.rn, rrr.rm)),
                else => unreachable,
            }
        },
        .msub => {
            const rrrr = emit.mir.instructions.items(.data)[inst].rrrr;
            switch (tag) {
                .msub => try emit.write_instruction(Instruction.msub(rrrr.rd, rrrr.rn, rrrr.rm, rrrr.ra)),
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn mir_nop(emit: *Emit) !void {
    try emit.write_instruction(Instruction.nop());
}

fn reg_list_is_set(reg_list: u32, reg: Register) bool {
    return reg_list & @as(u32, 1) << @as(u5, @int_cast(reg.id())) != 0;
}

fn mir_push_pop_regs(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const reg_list = emit.mir.instructions.items(.data)[inst].reg_list;

    if (reg_list_is_set(reg_list, .xzr)) return emit.fail("xzr is not a valid register for {}", .{tag});

    // sp must be aligned at all times, so we only use stp and ldp
    // instructions for minimal instruction count.
    //
    // However, if we have an odd number of registers, for pop_regs we
    // use one ldr instruction followed by zero or more ldp
    // instructions; for push_regs we use zero or more stp
    // instructions followed by one str instruction.
    const number_of_regs = @pop_count(reg_list);
    const odd_number_of_regs = number_of_regs % 2 != 0;

    switch (tag) {
        .pop_regs => {
            var i: u6 = 32;
            var count: u6 = 0;
            var other_reg: ?Register = null;
            while (i > 0) : (i -= 1) {
                const reg = @as(Register, @enumFromInt(i - 1));
                if (reg_list_is_set(reg_list, reg)) {
                    if (count == 0 and odd_number_of_regs) {
                        try emit.write_instruction(Instruction.ldr(
                            reg,
                            .sp,
                            Instruction.LoadStoreOffset.imm_post_index(16),
                        ));
                    } else if (other_reg) |r| {
                        try emit.write_instruction(Instruction.ldp(
                            reg,
                            r,
                            .sp,
                            Instruction.LoadStorePairOffset.post_index(16),
                        ));
                        other_reg = null;
                    } else {
                        other_reg = reg;
                    }
                    count += 1;
                }
            }
            assert(count == number_of_regs);
        },
        .push_regs => {
            var i: u6 = 0;
            var count: u6 = 0;
            var other_reg: ?Register = null;
            while (i < 32) : (i += 1) {
                const reg = @as(Register, @enumFromInt(i));
                if (reg_list_is_set(reg_list, reg)) {
                    if (count == number_of_regs - 1 and odd_number_of_regs) {
                        try emit.write_instruction(Instruction.str(
                            reg,
                            .sp,
                            Instruction.LoadStoreOffset.imm_pre_index(-16),
                        ));
                    } else if (other_reg) |r| {
                        try emit.write_instruction(Instruction.stp(
                            r,
                            reg,
                            .sp,
                            Instruction.LoadStorePairOffset.pre_index(-16),
                        ));
                        other_reg = null;
                    } else {
                        other_reg = reg;
                    }
                    count += 1;
                }
            }
            assert(count == number_of_regs);
        },
        else => unreachable,
    }
}

fn mir_bitfield_extract(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rr_lsb_width = emit.mir.instructions.items(.data)[inst].rr_lsb_width;
    const rd = rr_lsb_width.rd;
    const rn = rr_lsb_width.rn;
    const lsb = rr_lsb_width.lsb;
    const width = rr_lsb_width.width;

    switch (tag) {
        .sbfx => try emit.write_instruction(Instruction.sbfx(rd, rn, lsb, width)),
        .ubfx => try emit.write_instruction(Instruction.ubfx(rd, rn, lsb, width)),
        else => unreachable,
    }
}

fn mir_extend(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const rr = emit.mir.instructions.items(.data)[inst].rr;

    switch (tag) {
        .sxtb => try emit.write_instruction(Instruction.sxtb(rr.rd, rr.rn)),
        .sxth => try emit.write_instruction(Instruction.sxth(rr.rd, rr.rn)),
        .sxtw => try emit.write_instruction(Instruction.sxtw(rr.rd, rr.rn)),
        .uxtb => try emit.write_instruction(Instruction.uxtb(rr.rd, rr.rn)),
        .uxth => try emit.write_instruction(Instruction.uxth(rr.rd, rr.rn)),
        else => unreachable,
    }
}
