//! This file contains the functionality for lowering SPARCv9 MIR into
//! machine code

const std = @import("std");
const Endian = std.builtin.Endian;
const assert = std.debug.assert;
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const ErrorMsg = Module.ErrorMsg;
const Liveness = @import("../../Liveness.zig");
const log = std.log.scoped(.sparcv9_emit);
const DebugInfoOutput = @import("../../codegen.zig").DebugInfoOutput;

const Emit = @This();
const Mir = @import("Mir.zig");
const bits = @import("bits.zig");
const Instruction = bits.Instruction;
const Register = bits.Register;

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
    bpcc,
    bpr,
    fn default(tag: Mir.Inst.Tag) BranchType {
        return switch (tag) {
            .bpcc => .bpcc,
            .bpr => .bpr,
            else => unreachable,
        };
    }
};

pub fn emit_mir(
    emit: *Emit,
) InnerError!void {
    const mir_tags = emit.mir.instructions.items(.tag);

    // Convert absolute addresses into offsets and
    // find smallest lowerings for branch instructions
    try emit.lower_branches();

    // Emit machine code
    for (mir_tags, 0..) |tag, index| {
        const inst = @as(u32, @int_cast(index));
        switch (tag) {
            .dbg_line => try emit.mir_dbg_line(inst),
            .dbg_prologue_end => try emit.mir_debug_prologue_end(),
            .dbg_epilogue_begin => try emit.mir_debug_epilogue_begin(),

            .add => try emit.mir_arithmetic3_op(inst),
            .addcc => try emit.mir_arithmetic3_op(inst),

            .bpr => try emit.mir_conditional_branch(inst),
            .bpcc => try emit.mir_conditional_branch(inst),

            .call => @panic("TODO implement sparc64 call"),

            .jmpl => try emit.mir_arithmetic3_op(inst),

            .ldub => try emit.mir_arithmetic3_op(inst),
            .lduh => try emit.mir_arithmetic3_op(inst),
            .lduw => try emit.mir_arithmetic3_op(inst),
            .ldx => try emit.mir_arithmetic3_op(inst),

            .lduba => try emit.mir_mem_asi(inst),
            .lduha => try emit.mir_mem_asi(inst),
            .lduwa => try emit.mir_mem_asi(inst),
            .ldxa => try emit.mir_mem_asi(inst),

            .@"and" => try emit.mir_arithmetic3_op(inst),
            .@"or" => try emit.mir_arithmetic3_op(inst),
            .xor => try emit.mir_arithmetic3_op(inst),
            .xnor => try emit.mir_arithmetic3_op(inst),

            .membar => try emit.mir_membar(inst),

            .movcc => try emit.mir_conditional_move(inst),

            .movr => try emit.mir_conditional_move(inst),

            .mulx => try emit.mir_arithmetic3_op(inst),
            .sdivx => try emit.mir_arithmetic3_op(inst),
            .udivx => try emit.mir_arithmetic3_op(inst),

            .nop => try emit.mir_nop(),

            .@"return" => try emit.mir_arithmetic2_op(inst),

            .save => try emit.mir_arithmetic3_op(inst),
            .restore => try emit.mir_arithmetic3_op(inst),

            .sethi => try emit.mir_sethi(inst),

            .sll => try emit.mir_shift(inst),
            .srl => try emit.mir_shift(inst),
            .sra => try emit.mir_shift(inst),
            .sllx => try emit.mir_shift(inst),
            .srlx => try emit.mir_shift(inst),
            .srax => try emit.mir_shift(inst),

            .stb => try emit.mir_arithmetic3_op(inst),
            .sth => try emit.mir_arithmetic3_op(inst),
            .stw => try emit.mir_arithmetic3_op(inst),
            .stx => try emit.mir_arithmetic3_op(inst),

            .stba => try emit.mir_mem_asi(inst),
            .stha => try emit.mir_mem_asi(inst),
            .stwa => try emit.mir_mem_asi(inst),
            .stxa => try emit.mir_mem_asi(inst),

            .sub => try emit.mir_arithmetic3_op(inst),
            .subcc => try emit.mir_arithmetic3_op(inst),

            .tcc => try emit.mir_trap(inst),

            .cmp => try emit.mir_arithmetic2_op(inst),

            .mov => try emit.mir_arithmetic2_op(inst),

            .not => try emit.mir_arithmetic2_op(inst),
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
        .dwarf => |dbg_out| {
            try dbg_out.set_prologue_end();
            try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
        },
        .plan9 => {},
        .none => {},
    }
}

fn mir_debug_epilogue_begin(emit: *Emit) !void {
    switch (emit.debug_output) {
        .dwarf => |dbg_out| {
            try dbg_out.set_epilogue_begin();
            try emit.dbg_advance_pcand_line(emit.prev_di_line, emit.prev_di_column);
        },
        .plan9 => {},
        .none => {},
    }
}

fn mir_arithmetic2_op(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].arithmetic_2op;

    const rs1 = data.rs1;

    if (data.is_imm) {
        const imm = data.rs2_or_imm.imm;
        switch (tag) {
            .@"return" => try emit.write_instruction(Instruction.@"return"(i13, rs1, imm)),
            .cmp => try emit.write_instruction(Instruction.subcc(i13, rs1, imm, .g0)),
            .mov => try emit.write_instruction(Instruction.@"or"(i13, .g0, imm, rs1)),
            .not => try emit.write_instruction(Instruction.xnor(i13, .g0, imm, rs1)),
            else => unreachable,
        }
    } else {
        const rs2 = data.rs2_or_imm.rs2;
        switch (tag) {
            .@"return" => try emit.write_instruction(Instruction.@"return"(Register, rs1, rs2)),
            .cmp => try emit.write_instruction(Instruction.subcc(Register, rs1, rs2, .g0)),
            .mov => try emit.write_instruction(Instruction.@"or"(Register, .g0, rs2, rs1)),
            .not => try emit.write_instruction(Instruction.xnor(Register, rs2, .g0, rs1)),
            else => unreachable,
        }
    }
}

fn mir_arithmetic3_op(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].arithmetic_3op;

    const rd = data.rd;
    const rs1 = data.rs1;

    if (data.is_imm) {
        const imm = data.rs2_or_imm.imm;
        switch (tag) {
            .add => try emit.write_instruction(Instruction.add(i13, rs1, imm, rd)),
            .addcc => try emit.write_instruction(Instruction.addcc(i13, rs1, imm, rd)),
            .jmpl => try emit.write_instruction(Instruction.jmpl(i13, rs1, imm, rd)),
            .ldub => try emit.write_instruction(Instruction.ldub(i13, rs1, imm, rd)),
            .lduh => try emit.write_instruction(Instruction.lduh(i13, rs1, imm, rd)),
            .lduw => try emit.write_instruction(Instruction.lduw(i13, rs1, imm, rd)),
            .ldx => try emit.write_instruction(Instruction.ldx(i13, rs1, imm, rd)),
            .@"and" => try emit.write_instruction(Instruction.@"and"(i13, rs1, imm, rd)),
            .@"or" => try emit.write_instruction(Instruction.@"or"(i13, rs1, imm, rd)),
            .xor => try emit.write_instruction(Instruction.xor(i13, rs1, imm, rd)),
            .xnor => try emit.write_instruction(Instruction.xnor(i13, rs1, imm, rd)),
            .mulx => try emit.write_instruction(Instruction.mulx(i13, rs1, imm, rd)),
            .sdivx => try emit.write_instruction(Instruction.sdivx(i13, rs1, imm, rd)),
            .udivx => try emit.write_instruction(Instruction.udivx(i13, rs1, imm, rd)),
            .save => try emit.write_instruction(Instruction.save(i13, rs1, imm, rd)),
            .restore => try emit.write_instruction(Instruction.restore(i13, rs1, imm, rd)),
            .stb => try emit.write_instruction(Instruction.stb(i13, rs1, imm, rd)),
            .sth => try emit.write_instruction(Instruction.sth(i13, rs1, imm, rd)),
            .stw => try emit.write_instruction(Instruction.stw(i13, rs1, imm, rd)),
            .stx => try emit.write_instruction(Instruction.stx(i13, rs1, imm, rd)),
            .sub => try emit.write_instruction(Instruction.sub(i13, rs1, imm, rd)),
            .subcc => try emit.write_instruction(Instruction.subcc(i13, rs1, imm, rd)),
            else => unreachable,
        }
    } else {
        const rs2 = data.rs2_or_imm.rs2;
        switch (tag) {
            .add => try emit.write_instruction(Instruction.add(Register, rs1, rs2, rd)),
            .addcc => try emit.write_instruction(Instruction.addcc(Register, rs1, rs2, rd)),
            .jmpl => try emit.write_instruction(Instruction.jmpl(Register, rs1, rs2, rd)),
            .ldub => try emit.write_instruction(Instruction.ldub(Register, rs1, rs2, rd)),
            .lduh => try emit.write_instruction(Instruction.lduh(Register, rs1, rs2, rd)),
            .lduw => try emit.write_instruction(Instruction.lduw(Register, rs1, rs2, rd)),
            .ldx => try emit.write_instruction(Instruction.ldx(Register, rs1, rs2, rd)),
            .@"and" => try emit.write_instruction(Instruction.@"and"(Register, rs1, rs2, rd)),
            .@"or" => try emit.write_instruction(Instruction.@"or"(Register, rs1, rs2, rd)),
            .xor => try emit.write_instruction(Instruction.xor(Register, rs1, rs2, rd)),
            .xnor => try emit.write_instruction(Instruction.xnor(Register, rs1, rs2, rd)),
            .mulx => try emit.write_instruction(Instruction.mulx(Register, rs1, rs2, rd)),
            .sdivx => try emit.write_instruction(Instruction.sdivx(Register, rs1, rs2, rd)),
            .udivx => try emit.write_instruction(Instruction.udivx(Register, rs1, rs2, rd)),
            .save => try emit.write_instruction(Instruction.save(Register, rs1, rs2, rd)),
            .restore => try emit.write_instruction(Instruction.restore(Register, rs1, rs2, rd)),
            .stb => try emit.write_instruction(Instruction.stb(Register, rs1, rs2, rd)),
            .sth => try emit.write_instruction(Instruction.sth(Register, rs1, rs2, rd)),
            .stw => try emit.write_instruction(Instruction.stw(Register, rs1, rs2, rd)),
            .stx => try emit.write_instruction(Instruction.stx(Register, rs1, rs2, rd)),
            .sub => try emit.write_instruction(Instruction.sub(Register, rs1, rs2, rd)),
            .subcc => try emit.write_instruction(Instruction.subcc(Register, rs1, rs2, rd)),
            else => unreachable,
        }
    }
}

fn mir_conditional_branch(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const branch_type = emit.branch_types.get(inst).?;

    switch (branch_type) {
        .bpcc => switch (tag) {
            .bpcc => {
                const branch_predict_int = emit.mir.instructions.items(.data)[inst].branch_predict_int;
                const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(branch_predict_int.inst).?)) - @as(i64, @int_cast(emit.code.items.len));
                log.debug("mir_conditional_branch: {} offset={}", .{ inst, offset });

                try emit.write_instruction(
                    Instruction.bpcc(
                        branch_predict_int.cond,
                        branch_predict_int.annul,
                        branch_predict_int.pt,
                        branch_predict_int.ccr,
                        @as(i21, @int_cast(offset)),
                    ),
                );
            },
            else => unreachable,
        },
        .bpr => switch (tag) {
            .bpr => {
                const branch_predict_reg = emit.mir.instructions.items(.data)[inst].branch_predict_reg;
                const offset = @as(i64, @int_cast(emit.code_offset_mapping.get(branch_predict_reg.inst).?)) - @as(i64, @int_cast(emit.code.items.len));
                log.debug("mir_conditional_branch: {} offset={}", .{ inst, offset });

                try emit.write_instruction(
                    Instruction.bpr(
                        branch_predict_reg.cond,
                        branch_predict_reg.annul,
                        branch_predict_reg.pt,
                        branch_predict_reg.rs1,
                        @as(i18, @int_cast(offset)),
                    ),
                );
            },
            else => unreachable,
        },
    }
}

fn mir_conditional_move(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .movcc => {
            const data = emit.mir.instructions.items(.data)[inst].conditional_move_int;
            if (data.is_imm) {
                try emit.write_instruction(Instruction.movcc(
                    i11,
                    data.cond,
                    data.ccr,
                    data.rs2_or_imm.imm,
                    data.rd,
                ));
            } else {
                try emit.write_instruction(Instruction.movcc(
                    Register,
                    data.cond,
                    data.ccr,
                    data.rs2_or_imm.rs2,
                    data.rd,
                ));
            }
        },
        .movr => {
            const data = emit.mir.instructions.items(.data)[inst].conditional_move_reg;
            if (data.is_imm) {
                try emit.write_instruction(Instruction.movr(
                    i10,
                    data.cond,
                    data.rs1,
                    data.rs2_or_imm.imm,
                    data.rd,
                ));
            } else {
                try emit.write_instruction(Instruction.movr(
                    Register,
                    data.cond,
                    data.rs1,
                    data.rs2_or_imm.rs2,
                    data.rd,
                ));
            }
        },
        else => unreachable,
    }
}

fn mir_mem_asi(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].mem_asi;

    const rd = data.rd;
    const rs1 = data.rs1;
    const rs2 = data.rs2;
    const asi = data.asi;

    switch (tag) {
        .lduba => try emit.write_instruction(Instruction.lduba(rs1, rs2, asi, rd)),
        .lduha => try emit.write_instruction(Instruction.lduha(rs1, rs2, asi, rd)),
        .lduwa => try emit.write_instruction(Instruction.lduwa(rs1, rs2, asi, rd)),
        .ldxa => try emit.write_instruction(Instruction.ldxa(rs1, rs2, asi, rd)),

        .stba => try emit.write_instruction(Instruction.stba(rs1, rs2, asi, rd)),
        .stha => try emit.write_instruction(Instruction.stha(rs1, rs2, asi, rd)),
        .stwa => try emit.write_instruction(Instruction.stwa(rs1, rs2, asi, rd)),
        .stxa => try emit.write_instruction(Instruction.stxa(rs1, rs2, asi, rd)),
        else => unreachable,
    }
}

fn mir_membar(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const mask = emit.mir.instructions.items(.data)[inst].membar_mask;
    assert(tag == .membar);

    try emit.write_instruction(Instruction.membar(
        mask.cmask,
        mask.mmask,
    ));
}

fn mir_nop(emit: *Emit) !void {
    try emit.write_instruction(Instruction.nop());
}

fn mir_sethi(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].sethi;

    const imm = data.imm;
    const rd = data.rd;

    assert(tag == .sethi);
    try emit.write_instruction(Instruction.sethi(imm, rd));
}

fn mir_shift(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].shift;

    const rd = data.rd;
    const rs1 = data.rs1;

    if (data.is_imm) {
        const imm = data.rs2_or_imm.imm;
        switch (tag) {
            .sll => try emit.write_instruction(Instruction.sll(u5, rs1, @as(u5, @truncate(imm)), rd)),
            .srl => try emit.write_instruction(Instruction.srl(u5, rs1, @as(u5, @truncate(imm)), rd)),
            .sra => try emit.write_instruction(Instruction.sra(u5, rs1, @as(u5, @truncate(imm)), rd)),
            .sllx => try emit.write_instruction(Instruction.sllx(u6, rs1, imm, rd)),
            .srlx => try emit.write_instruction(Instruction.srlx(u6, rs1, imm, rd)),
            .srax => try emit.write_instruction(Instruction.srax(u6, rs1, imm, rd)),
            else => unreachable,
        }
    } else {
        const rs2 = data.rs2_or_imm.rs2;
        switch (tag) {
            .sll => try emit.write_instruction(Instruction.sll(Register, rs1, rs2, rd)),
            .srl => try emit.write_instruction(Instruction.srl(Register, rs1, rs2, rd)),
            .sra => try emit.write_instruction(Instruction.sra(Register, rs1, rs2, rd)),
            .sllx => try emit.write_instruction(Instruction.sllx(Register, rs1, rs2, rd)),
            .srlx => try emit.write_instruction(Instruction.srlx(Register, rs1, rs2, rd)),
            .srax => try emit.write_instruction(Instruction.srax(Register, rs1, rs2, rd)),
            else => unreachable,
        }
    }
}

fn mir_trap(emit: *Emit, inst: Mir.Inst.Index) !void {
    const tag = emit.mir.instructions.items(.tag)[inst];
    const data = emit.mir.instructions.items(.data)[inst].trap;

    const cond = data.cond;
    const ccr = data.ccr;
    const rs1 = data.rs1;

    if (data.is_imm) {
        const imm = data.rs2_or_imm.imm;
        switch (tag) {
            .tcc => try emit.write_instruction(Instruction.trap(u7, cond, ccr, rs1, imm)),
            else => unreachable,
        }
    } else {
        const rs2 = data.rs2_or_imm.rs2;
        switch (tag) {
            .tcc => try emit.write_instruction(Instruction.trap(Register, cond, ccr, rs1, rs2)),
            else => unreachable,
        }
    }
}

// Common helper functions

fn branch_target(emit: *Emit, inst: Mir.Inst.Index) Mir.Inst.Index {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .bpcc => return emit.mir.instructions.items(.data)[inst].branch_predict_int.inst,
        .bpr => return emit.mir.instructions.items(.data)[inst].branch_predict_reg.inst,
        else => unreachable,
    }
}

fn dbg_advance_pcand_line(emit: *Emit, line: u32, column: u32) !void {
    const delta_line = @as(i32, @int_cast(line)) - @as(i32, @int_cast(emit.prev_di_line));
    const delta_pc: usize = emit.code.items.len - emit.prev_di_pc;
    switch (emit.debug_output) {
        .dwarf => |dbg_out| {
            try dbg_out.advance_pcand_line(delta_line, delta_pc);
            emit.prev_di_line = line;
            emit.prev_di_column = column;
            emit.prev_di_pc = emit.code.items.len;
        },
        else => {},
    }
}

fn fail(emit: *Emit, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(emit.err_msg == null);
    const comp = emit.bin_file.comp;
    const gpa = comp.gpa;
    emit.err_msg = try ErrorMsg.create(gpa, emit.src_loc, format, args);
    return error.EmitFail;
}

fn instruction_size(emit: *Emit, inst: Mir.Inst.Index) usize {
    const tag = emit.mir.instructions.items(.tag)[inst];

    switch (tag) {
        .dbg_line,
        .dbg_epilogue_begin,
        .dbg_prologue_end,
        => return 0,
        // Currently Mir instructions always map to single machine instruction.
        else => return 4,
    }
}

fn is_branch(tag: Mir.Inst.Tag) bool {
    return switch (tag) {
        .bpcc => true,
        .bpr => true,
        else => false,
    };
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

fn optimal_branch_type(emit: *Emit, tag: Mir.Inst.Tag, offset: i64) !BranchType {
    assert(offset & 0b11 == 0);

    switch (tag) {
        // TODO use the following strategy to implement long branches:
        // - Negate the conditional and target of the original instruction;
        // - In the space immediately after the branch, load
        //   the address of the original target, preferrably in
        //   a PC-relative way, into %o7; and
        // - jmpl %o7 + %g0, %g0

        .bpcc => {
            if (std.math.cast(i21, offset)) |_| {
                return BranchType.bpcc;
            } else {
                return emit.fail("TODO support BPcc branches larger than +-1 MiB", .{});
            }
        },
        .bpr => {
            if (std.math.cast(i18, offset)) |_| {
                return BranchType.bpr;
            } else {
                return emit.fail("TODO support BPr branches larger than +-128 KiB", .{});
            }
        },
        else => unreachable,
    }
}

fn write_instruction(emit: *Emit, instruction: Instruction) !void {
    // SPARCv9 instructions are always arranged in BE regardless of the
    // endianness mode the CPU is running in (Section 3.1 of the ISA specification).
    // This is to ease porting in case someone wants to do a LE SPARCv9 backend.
    const endian = Endian.big;

    std.mem.write_int(u32, try emit.code.add_many_as_array(4), instruction.to_u32(), endian);
}
