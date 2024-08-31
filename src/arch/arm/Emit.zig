//! This file contains the functionality for lowering AArch32 MIR into
//! machine code

const Emit = @This();
const builtin = @import("builtin");
const std = @import("std");
const math = std.math;
const Mir = @import("Mir.zig");
const bits = @import("bits.zig");
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const Type = @import("../../type.zig").Type;
const ErrorMsg = Module.ErrorMsg;
const Target = std.Target;
const assert = std.debug.assert;
const Instruction = bits.Instruction;
const Register = bits.Register;
const log = std.log.scoped(.aarch32_emit);
const DebugInfoOutput = @import("../../codegen.zig").DebugInfoOutput;
const CodeGen = @import("CodeGen.zig");

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

/// The final stack frame size of the function (already aligned to the
/// respective stack alignment). Does not include prologue stack space.
stack_size: u32,

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

const InnerError = error{
    OutOfMemory,
    EmitFail,
};

const BranchType = enum {
    b,

    fn default(tag: Mir.Inst.Tag) BranchType {
        return switch (tag) {
            .b => .b,
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
            .add => try emit.mir_data_processing(inst),
            .adds => try emit.mir_data_processing(inst),
            .@"and" => try emit.mir_data_processing(inst),
            .cmp => try emit.mir_data_processing(inst),
            .eor => try emit.mir_data_processing(inst),
            .mov => try emit.mir_data_processing(inst),
            .mvn => try emit.mir_data_processing(inst),
            .orr => try emit.mir_data_processing(inst),
            .rsb => try emit.mir_data_processing(inst),
            .sub => try emit.mir_data_processing(inst),
            .subs => try emit.mir_data_processing(inst),

            .sub_sp_scratch_r4 => try emit.mir_sub_stack_pointer(inst),

            .asr => try emit.mir_shift(inst),
            .lsl => try emit.mir_shift(inst),
            .lsr => try emit.mir_shift(inst),

            .b => try emit.mir_branch(inst),

            .undefined_instruction => try emit.mir_undefined_instruction(),
            .bkpt => try emit.mir_exception_generation(inst),

            .blx => try emit.mir_branch_exchange(inst),
            .bx => try emit.mir_branch_exchange(inst),

            .dbg_line => try emit.mir_dbg_line(inst),

            .dbg_prologue_end => try emit.mir_debug_prologue_end(),

            .dbg_epilogue_begin => try emit.mir_debug_epilogue_begin(),

            .ldr => try emit.mir_load_store(inst),
            .ldrb => try emit.mir_load_store(inst),
            .str => try emit.mir_load_store(inst),
            .strb => try emit.mir_load_store(inst),

            .ldr_ptr_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldr_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrb_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrh_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrsb_stack_argument => try emit.mir_load_stack_argument(inst),
            .ldrsh_stack_argument => try emit.mir_load_stack_argument(inst),

            .ldrh => try emit.mir_load_store_extra(inst),
            .ldrsb => try emit.mir_load_store_extra(inst),
            .ldrsh => try emit.mir_load_store_extra(inst),
            .strh => try emit.mir_load_store_extra(inst),

            .movw => try emit.mir_special_move(inst),
            .movt => try emit.mir_special_move(inst),

            .mul => try emit.mir_multiply(inst),
            .smulbb => try emit.mir_multiply(inst),

            .smull => try emit.mir_multiply_long(inst),
            .umull => try emit.mir_multiply_long(inst),

            .nop => try emit.mir_nop(),

            .pop => try emit.mir_block_data_transfer(inst),
            .push => try emit.mir_block_data_transfer(inst),

            .svc => try emit.mir_supervisor_call(inst),

            .sbfx => try emit.mir_bit_field_extract(inst),
            .ubfx => try emit.mir_bit_field_extract(inst),
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
    assert(std.mem.is_aligned_generic(i64, offset, 4)); // misaligned offset

    switch (tag) {
        .b => {
            if (std.math.cast(i24, @div_exact(offset, 4))) |_| {
                return BranchType.b;
            } else {
                return emit.fail("TODO support larger branches", .{});
            }
        },
        else => unreachable,
    }
}

fn instruction_size(emit: *Emit, inst: Mir.Inst.Index) usize {
    const tag = emit.mir.instructions.items(.tag)[inst];

    if (is_branch(tag)) {
        switch (emit.branch_types.get(inst).?) {
            .b => return 4,
        }
    }

    switch (tag) {
        .dbg_line,
        .dbg_epilogue_begin,
        .dbg_prologue_end,
        => return 0,

        .sub_sp_scratch_r4 => {
            const imm32 = emit.mir.instructions.items(.data)[inst].imm32;

            if (imm32 == 0) {
                return 0 * 4;
            } else if (Instruction.Operand.from_u32(imm32) != null) {
                // sub
                return 1 * 4;
            } else if (Target.arm.feature_set_has(emit.target.cpu.features, .has_v7)) {
                // movw; movt; sub
                return 3 * 4;
            } else {
                // mov; orr; orr; orr; sub
                return 5 * 4;
            }
        },

        else => return 4,
    }
}

fn is_branch(tag: Mir.Inst.Tag) bool {
    return switch (tag) {
        .b => true,
        else => false,
    };
}

fn branch_target(emit: *Emit, inst: Mir.Inst.Index) Mir.Inst.Index {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .b => return emit.mir.instructions.items(.data)[inst].inst,
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
                    const offset = @as(i64, @int_cast(target_offset)) - @as(i64, @int_cast(current_code_offset + 8));
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
                    const offset = @as(i64, @int_cast(current_code_offset)) - @as(i64, @int_cast(forward_branch_inst_offset + 8));
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

fn dbg_advance_pcand_line(self: *Emit, line: u32, column: u32) !void {
    const delta_line = @as(i32, @int_cast(line)) - @as(i32, @int_cast(self.prev_di_line));
    const delta_pc: usize = self.code.items.len - self.prev_di_pc;
    switch (self.debug_output) {
        .dwarf => |dw| {
            try dw.advance_pcand_line(delta_line, delta_pc);
            self.prev_di_line = line;
            self.prev_di_column = column;
            self.prev_di_pc = self.code.items.len;
        },
        .plan9 => |dbg_out| {
            if (delta_pc <= 0) return; // only do this when the pc changes

            // increasing the line number
            try link.File.Plan9.change_line(&dbg_out.dbg_line, delta_line);
            // increasing the pc
            const d_pc_p9 = @as(i64, @int_cast(delta_pc)) - dbg_out.pc_quanta;
            if (d_pc_p9 > 0) {
                // minus one because if its the last one, we want to leave space to change the line which is one pc quanta
                try dbg_out.dbg_line.append(@as(u8, @int_cast(@div_exact(d_pc_p9, dbg_out.pc_quanta) + 128)) - dbg_out.pc_quanta);
                if (dbg_out.pcop_change_index) |pci|
                    dbg_out.dbg_line.items[pci] += 1;
                dbg_out.pcop_change_index = @as(u32, @int_cast(dbg_out.dbg_line.items.len - 1));
            } else if (d_pc_p9 == 0) {
                // we don't need to do anything, because adding the pc quanta does it for us
            } else unreachable;
            if (dbg_out.start_line == null)
                dbg_out.start_line = self.prev_di_line;
            dbg_out.end_line = line;
            // only do this if the pc changed
            self.prev_di_line = line;
            self.prev_di_column = column;
            self.prev_di_pc = self.code.items.len;
        },
        .none => {},
    }
}

fn mir_data_processing(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];

    switch (tag) {
        .add,
        .adds,
        .@"and",
        .eor,
        .orr,
        .rsb,
        .sub,
        .subs,
        => {
            const rr_op = emit.mir.instructions.items(.data)[inst].rr_op;
            switch (tag) {
                .add => try emit.write_instruction(Instruction.add(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .adds => try emit.write_instruction(Instruction.adds(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .@"and" => try emit.write_instruction(Instruction.@"and"(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .eor => try emit.write_instruction(Instruction.eor(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .orr => try emit.write_instruction(Instruction.orr(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .rsb => try emit.write_instruction(Instruction.rsb(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .sub => try emit.write_instruction(Instruction.sub(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                .subs => try emit.write_instruction(Instruction.subs(cond, rr_op.rd, rr_op.rn, rr_op.op)),
                else => unreachable,
            }
        },
        .cmp => {
            const r_op_cmp = emit.mir.instructions.items(.data)[inst].r_op_cmp;
            try emit.write_instruction(Instruction.cmp(cond, r_op_cmp.rn, r_op_cmp.op));
        },
        .mov,
        .mvn,
        => {
            const r_op_mov = emit.mir.instructions.items(.data)[inst].r_op_mov;
            switch (tag) {
                .mov => try emit.write_instruction(Instruction.mov(cond, r_op_mov.rd, r_op_mov.op)),
                .mvn => try emit.write_instruction(Instruction.mvn(cond, r_op_mov.rd, r_op_mov.op)),
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn mir_sub_stack_pointer(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const imm32 = emit.mir.instructions.items(.data)[inst].imm32;

    switch (tag) {
        .sub_sp_scratch_r4 => {
            if (imm32 == 0) return;

            const operand = Instruction.Operand.from_u32(imm32) orelse blk: {
                const scratch: Register = .r4;

                if (Target.arm.feature_set_has(emit.target.cpu.features, .has_v7)) {
                    try emit.write_instruction(Instruction.movw(cond, scratch, @as(u16, @truncate(imm32))));
                    try emit.write_instruction(Instruction.movt(cond, scratch, @as(u16, @truncate(imm32 >> 16))));
                } else {
                    try emit.write_instruction(Instruction.mov(cond, scratch, Instruction.Operand.imm(@as(u8, @truncate(imm32)), 0)));
                    try emit.write_instruction(Instruction.orr(cond, scratch, scratch, Instruction.Operand.imm(@as(u8, @truncate(imm32 >> 8)), 12)));
                    try emit.write_instruction(Instruction.orr(cond, scratch, scratch, Instruction.Operand.imm(@as(u8, @truncate(imm32 >> 16)), 8)));
                    try emit.write_instruction(Instruction.orr(cond, scratch, scratch, Instruction.Operand.imm(@as(u8, @truncate(imm32 >> 24)), 4)));
                }

                break :blk Instruction.Operand.reg(scratch, Instruction.Operand.Shift.none);
            };

            try emit.write_instruction(Instruction.sub(cond, .sp, .sp, operand));
        },
        else => unreachable,
    }
}

fn mir_shift(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rr_shift = emit.mir.instructions.items(.data)[inst].rr_shift;

    switch (tag) {
        .asr => try emit.write_instruction(Instruction.asr(cond, rr_shift.rd, rr_shift.rm, rr_shift.shift_amount)),
        .lsl => try emit.write_instruction(Instruction.lsl(cond, rr_shift.rd, rr_shift.rm, rr_shift.shift_amount)),
        .lsr => try emit.write_instruction(Instruction.lsr(cond, rr_shift.rd, rr_shift.rm, rr_shift.shift_amount)),
        else => unreachable,
    }
}

fn mir_branch(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const target_inst = emit.mir.instructions.items(.data)[inst].inst;

    const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(target_inst).?)) - @as(i64, @int_cast(emit.code.items.len + 8));
    const branch_type = emit.branch_types.get(inst).?;

    switch (branch_type) {
        .b => switch (tag) {
            .b => try emit.write_instruction(Instruction.b(cond, @as(i26, @int_cast(offset)))),
            else => unreachable,
        },
    }
}

fn mir_undefined_instruction(emit: *Emit) !void {
    try emit.write_instruction(Instruction.undefined_instruction());
}

fn mir_exception_generation(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const imm16 = emit.mir.instructions.items(.data)[inst].imm16;

    switch (tag) {
        .bkpt => try emit.write_instruction(Instruction.bkpt(imm16)),
        else => unreachable,
    }
}

fn mir_branch_exchange(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const reg = emit.mir.instructions.items(.data)[inst].reg;

    switch (tag) {
        .blx => try emit.write_instruction(Instruction.blx(cond, reg)),
        .bx => try emit.write_instruction(Instruction.bx(cond, reg)),
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

fn mir_load_store(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rr_offset = emit.mir.instructions.items(.data)[inst].rr_offset;

    switch (tag) {
        .ldr => try emit.write_instruction(Instruction.ldr(cond, rr_offset.rt, rr_offset.rn, rr_offset.offset)),
        .ldrb => try emit.write_instruction(Instruction.ldrb(cond, rr_offset.rt, rr_offset.rn, rr_offset.offset)),
        .str => try emit.write_instruction(Instruction.str(cond, rr_offset.rt, rr_offset.rn, rr_offset.offset)),
        .strb => try emit.write_instruction(Instruction.strb(cond, rr_offset.rt, rr_offset.rn, rr_offset.offset)),
        else => unreachable,
    }
}

fn mir_load_stack_argument(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const r_stack_offset = emit.mir.instructions.items(.data)[inst].r_stack_offset;
    const rt = r_stack_offset.rt;

    const raw_offset = emit.stack_size + emit.saved_regs_stack_space + r_stack_offset.stack_offset;
    switch (tag) {
        .ldr_ptr_stack_argument => {
            const operand = Instruction.Operand.from_u32(raw_offset) orelse
                return emit.fail("TODO mirLoadStack larger offsets", .{});

            try emit.write_instruction(Instruction.add(cond, rt, .sp, operand));
        },
        .ldr_stack_argument,
        .ldrb_stack_argument,
        => {
            const offset = if (raw_offset <= math.max_int(u12)) blk: {
                break :blk Instruction.Offset.imm(@as(u12, @int_cast(raw_offset)));
            } else return emit.fail("TODO mirLoadStack larger offsets", .{});

            switch (tag) {
                .ldr_stack_argument => try emit.write_instruction(Instruction.ldr(cond, rt, .sp, .{ .offset = offset })),
                .ldrb_stack_argument => try emit.write_instruction(Instruction.ldrb(cond, rt, .sp, .{ .offset = offset })),
                else => unreachable,
            }
        },
        .ldrh_stack_argument,
        .ldrsb_stack_argument,
        .ldrsh_stack_argument,
        => {
            const offset = if (raw_offset <= math.max_int(u8)) blk: {
                break :blk Instruction.ExtraLoadStoreOffset.imm(@as(u8, @int_cast(raw_offset)));
            } else return emit.fail("TODO mirLoadStack larger offsets", .{});

            switch (tag) {
                .ldrh_stack_argument => try emit.write_instruction(Instruction.ldrh(cond, rt, .sp, .{ .offset = offset })),
                .ldrsb_stack_argument => try emit.write_instruction(Instruction.ldrsb(cond, rt, .sp, .{ .offset = offset })),
                .ldrsh_stack_argument => try emit.write_instruction(Instruction.ldrsh(cond, rt, .sp, .{ .offset = offset })),
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn mir_load_store_extra(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rr_extra_offset = emit.mir.instructions.items(.data)[inst].rr_extra_offset;

    switch (tag) {
        .ldrh => try emit.write_instruction(Instruction.ldrh(cond, rr_extra_offset.rt, rr_extra_offset.rn, rr_extra_offset.offset)),
        .ldrsb => try emit.write_instruction(Instruction.ldrsb(cond, rr_extra_offset.rt, rr_extra_offset.rn, rr_extra_offset.offset)),
        .ldrsh => try emit.write_instruction(Instruction.ldrsh(cond, rr_extra_offset.rt, rr_extra_offset.rn, rr_extra_offset.offset)),
        .strh => try emit.write_instruction(Instruction.strh(cond, rr_extra_offset.rt, rr_extra_offset.rn, rr_extra_offset.offset)),
        else => unreachable,
    }
}

fn mir_special_move(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const r_imm16 = emit.mir.instructions.items(.data)[inst].r_imm16;

    switch (tag) {
        .movw => try emit.write_instruction(Instruction.movw(cond, r_imm16.rd, r_imm16.imm16)),
        .movt => try emit.write_instruction(Instruction.movt(cond, r_imm16.rd, r_imm16.imm16)),
        else => unreachable,
    }
}

fn mir_multiply(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rrr = emit.mir.instructions.items(.data)[inst].rrr;

    switch (tag) {
        .mul => try emit.write_instruction(Instruction.mul(cond, rrr.rd, rrr.rn, rrr.rm)),
        .smulbb => try emit.write_instruction(Instruction.smulbb(cond, rrr.rd, rrr.rn, rrr.rm)),
        else => unreachable,
    }
}

fn mir_multiply_long(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rrrr = emit.mir.instructions.items(.data)[inst].rrrr;

    switch (tag) {
        .smull => try emit.write_instruction(Instruction.smull(cond, rrrr.rdlo, rrrr.rdhi, rrrr.rn, rrrr.rm)),
        .umull => try emit.write_instruction(Instruction.umull(cond, rrrr.rdlo, rrrr.rdhi, rrrr.rn, rrrr.rm)),
        else => unreachable,
    }
}

fn mir_nop(emit: *Emit) !void {
    try emit.write_instruction(Instruction.nop());
}

fn mir_block_data_transfer(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const register_list = emit.mir.instructions.items(.data)[inst].register_list;

    switch (tag) {
        .pop => try emit.write_instruction(Instruction.ldm(cond, .sp, true, register_list)),
        .push => try emit.write_instruction(Instruction.stmdb(cond, .sp, true, register_list)),
        else => unreachable,
    }
}

fn mir_supervisor_call(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const imm24 = emit.mir.instructions.items(.data)[inst].imm24;

    switch (tag) {
        .svc => try emit.write_instruction(Instruction.svc(cond, imm24)),
        else => unreachable,
    }
}

fn mir_bit_field_extract(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const cond = emit.mir.instructions.items(.cond)[inst];
    const rr_lsb_width = emit.mir.instructions.items(.data)[inst].rr_lsb_width;
    const rd = rr_lsb_width.rd;
    const rn = rr_lsb_width.rn;
    const lsb = rr_lsb_width.lsb;
    const width = rr_lsb_width.width;

    switch (tag) {
        .sbfx => try emit.write_instruction(Instruction.sbfx(cond, rd, rn, lsb, width)),
        .ubfx => try emit.write_instruction(Instruction.ubfx(cond, rd, rn, lsb, width)),
        else => unreachable,
    }
}
