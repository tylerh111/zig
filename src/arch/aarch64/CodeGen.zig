const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const math = std.math;
const assert = std.debug.assert;
const codegen = @import("../../codegen.zig");
const Air = @import("../../Air.zig");
const Mir = @import("Mir.zig");
const Emit = @import("Emit.zig");
const Liveness = @import("../../Liveness.zig");
const Type = @import("../../type.zig").Type;
const Value = @import("../../Value.zig");
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const InternPool = @import("../../InternPool.zig");
const Compilation = @import("../../Compilation.zig");
const ErrorMsg = Module.ErrorMsg;
const Target = std.Target;
const Allocator = mem.Allocator;
const trace = @import("../../tracy.zig").trace;
const DW = std.dwarf;
const leb128 = std.leb;
const log = std.log.scoped(.codegen);
const build_options = @import("build_options");
const Alignment = InternPool.Alignment;

const CodeGenError = codegen.CodeGenError;
const Result = codegen.Result;
const DebugInfoOutput = codegen.DebugInfoOutput;

const bits = @import("bits.zig");
const abi = @import("abi.zig");
const err_union_payload_offset = codegen.err_union_payload_offset;
const err_union_error_offset = codegen.err_union_error_offset;
const RegisterManager = abi.RegisterManager;
const RegisterLock = RegisterManager.RegisterLock;
const Register = bits.Register;
const Instruction = bits.Instruction;
const Condition = bits.Instruction.Condition;
const callee_preserved_regs = abi.callee_preserved_regs;
const c_abi_int_param_regs = abi.c_abi_int_param_regs;
const c_abi_int_return_regs = abi.c_abi_int_return_regs;
const gp = abi.RegisterClass.gp;

const InnerError = CodeGenError || error{OutOfRegisters};

gpa: Allocator,
air: Air,
liveness: Liveness,
bin_file: *link.File,
debug_output: DebugInfoOutput,
target: *const std.Target,
func_index: InternPool.Index,
owner_decl: InternPool.DeclIndex,
err_msg: ?*ErrorMsg,
args: []MCValue,
ret_mcv: MCValue,
fn_type: Type,
arg_index: u32,
src_loc: Module.SrcLoc,
stack_align: u32,

/// MIR Instructions
mir_instructions: std.MultiArrayList(Mir.Inst) = .{},
/// MIR extra data
mir_extra: std.ArrayListUnmanaged(u32) = .{},

/// Byte offset within the source file of the ending curly.
end_di_line: u32,
end_di_column: u32,

/// The value is an offset into the `Function` `code` from the beginning.
/// To perform the reloc, write 32-bit signed little-endian integer
/// which is a relative jump, based on the address following the reloc.
exitlude_jump_relocs: std.ArrayListUnmanaged(usize) = .{},

/// We postpone the creation of debug info for function args and locals
/// until after all Mir instructions have been generated. Only then we
/// will know saved_regs_stack_space which is necessary in order to
/// calculate the right stack offsest with respect to the `.fp` register.
dbg_info_relocs: std.ArrayListUnmanaged(DbgInfoReloc) = .{},

/// Whenever there is a runtime branch, we push a Branch onto this stack,
/// and pop it off when the runtime branch joins. This provides an "overlay"
/// of the table of mappings from instructions to `MCValue` from within the branch.
/// This way we can modify the `MCValue` for an instruction in different ways
/// within different branches. Special consideration is needed when a branch
/// joins with its parent, to make sure all instructions have the same MCValue
/// across each runtime branch upon joining.
branch_stack: *std.ArrayList(Branch),

// Key is the block instruction
blocks: std.AutoHashMapUnmanaged(Air.Inst.Index, BlockData) = .{},

register_manager: RegisterManager = .{},
/// Maps offset to what is stored there.
stack: std.AutoHashMapUnmanaged(u32, StackAllocation) = .{},
/// Tracks the current instruction allocated to the compare flags
compare_flags_inst: ?Air.Inst.Index = null,

/// Offset from the stack base, representing the end of the stack frame.
max_end_stack: u32 = 0,
/// Represents the current end stack offset. If there is no existing slot
/// to place a new stack allocation, it goes here, and then bumps `max_end_stack`.
next_stack_offset: u32 = 0,

saved_regs_stack_space: u32 = 0,

/// Debug field, used to find bugs in the compiler.
air_bookkeeping: @TypeOf(air_bookkeeping_init) = air_bookkeeping_init,

const air_bookkeeping_init = if (std.debug.runtime_safety) @as(usize, 0) else {};

const MCValue = union(enum) {
    /// No runtime bits. `void` types, empty structs, u0, enums with 1
    /// tag, etc.
    ///
    /// TODO Look into deleting this tag and using `dead` instead,
    /// since every use of MCValue.none should be instead looking at
    /// the type and noticing it is 0 bits.
    none,
    /// Control flow will not allow this value to be observed.
    unreach,
    /// No more references to this value remain.
    dead,
    /// The value is undefined.
    undef,
    /// A pointer-sized integer that fits in a register.
    ///
    /// If the type is a pointer, this is the pointer address in
    /// virtual address space.
    immediate: u64,
    /// The value is in a target-specific register.
    register: Register,
    /// The value is a tuple { wrapped: u32, overflow: u1 } where
    /// wrapped is stored in the register and the overflow bit is
    /// stored in the C (signed) or V (unsigned) flag of the CPSR.
    ///
    /// This MCValue is only generated by a add_with_overflow or
    /// sub_with_overflow instruction operating on 32- or 64-bit values.
    register_with_overflow: struct { reg: Register, flag: bits.Instruction.Condition },
    /// The value is in memory at a hard-coded address.
    ///
    /// If the type is a pointer, it means the pointer address is at
    /// this memory location.
    memory: u64,
    /// The value is in memory but requires a linker relocation fixup.
    linker_load: codegen.LinkerLoad,
    /// The value is one of the stack variables.
    ///
    /// If the type is a pointer, it means the pointer address is in
    /// the stack at this offset.
    stack_offset: u32,
    /// The value is a pointer to one of the stack variables (payload
    /// is stack offset).
    ptr_stack_offset: u32,
    /// The value resides in the N, Z, C, V flags. The value is 1 (if
    /// the type is u1) or true (if the type in bool) iff the
    /// specified condition is true.
    compare_flags: Condition,
    /// The value is a function argument passed via the stack.
    stack_argument_offset: u32,
};

const DbgInfoReloc = struct {
    tag: Air.Inst.Tag,
    ty: Type,
    name: [:0]const u8,
    mcv: MCValue,

    fn gen_dbg_info(reloc: DbgInfoReloc, function: Self) !void {
        switch (reloc.tag) {
            .arg => try reloc.gen_arg_dbg_info(function),

            .dbg_var_ptr,
            .dbg_var_val,
            => try reloc.gen_var_dbg_info(function),

            else => unreachable,
        }
    }

    fn gen_arg_dbg_info(reloc: DbgInfoReloc, function: Self) error{OutOfMemory}!void {
        switch (function.debug_output) {
            .dwarf => |dw| {
                const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (reloc.mcv) {
                    .register => |reg| .{ .register = reg.dwarf_loc_op() },
                    .stack_offset,
                    .stack_argument_offset,
                    => |offset| blk: {
                        const adjusted_offset = switch (reloc.mcv) {
                            .stack_offset => -@as(i32, @int_cast(offset)),
                            .stack_argument_offset => @as(i32, @int_cast(function.saved_regs_stack_space + offset)),
                            else => unreachable,
                        };
                        break :blk .{ .stack = .{
                            .fp_register = Register.x29.dwarf_loc_op_deref(),
                            .offset = adjusted_offset,
                        } };
                    },
                    else => unreachable, // not a possible argument

                };
                try dw.gen_arg_dbg_info(reloc.name, reloc.ty, function.owner_decl, loc);
            },
            .plan9 => {},
            .none => {},
        }
    }

    fn gen_var_dbg_info(reloc: DbgInfoReloc, function: Self) !void {
        const is_ptr = switch (reloc.tag) {
            .dbg_var_ptr => true,
            .dbg_var_val => false,
            else => unreachable,
        };

        switch (function.debug_output) {
            .dwarf => |dw| {
                const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (reloc.mcv) {
                    .register => |reg| .{ .register = reg.dwarf_loc_op() },
                    .ptr_stack_offset,
                    .stack_offset,
                    .stack_argument_offset,
                    => |offset| blk: {
                        const adjusted_offset = switch (reloc.mcv) {
                            .ptr_stack_offset,
                            .stack_offset,
                            => -@as(i32, @int_cast(offset)),
                            .stack_argument_offset => @as(i32, @int_cast(function.saved_regs_stack_space + offset)),
                            else => unreachable,
                        };
                        break :blk .{
                            .stack = .{
                                .fp_register = Register.x29.dwarf_loc_op_deref(),
                                .offset = adjusted_offset,
                            },
                        };
                    },
                    .memory => |address| .{ .memory = address },
                    .linker_load => |linker_load| .{ .linker_load = linker_load },
                    .immediate => |x| .{ .immediate = x },
                    .undef => .undef,
                    .none => .none,
                    else => blk: {
                        log.debug("TODO generate debug info for {}", .{reloc.mcv});
                        break :blk .nop;
                    },
                };
                try dw.gen_var_dbg_info(reloc.name, reloc.ty, function.owner_decl, is_ptr, loc);
            },
            .plan9 => {},
            .none => {},
        }
    }
};

const Branch = struct {
    inst_table: std.AutoArrayHashMapUnmanaged(Air.Inst.Index, MCValue) = .{},

    fn deinit(self: *Branch, gpa: Allocator) void {
        self.inst_table.deinit(gpa);
        self.* = undefined;
    }
};

const StackAllocation = struct {
    inst: Air.Inst.Index,
    /// TODO do we need size? should be determined by inst.ty.abi_size()
    size: u32,
};

const BlockData = struct {
    relocs: std.ArrayListUnmanaged(Mir.Inst.Index),
    /// The first break instruction encounters `null` here and chooses a
    /// machine code value for the block result, populating this field.
    /// Following break instructions encounter that value and use it for
    /// the location to store their block results.
    mcv: MCValue,
};

const BigTomb = struct {
    function: *Self,
    inst: Air.Inst.Index,
    lbt: Liveness.BigTomb,

    fn feed(bt: *BigTomb, op_ref: Air.Inst.Ref) void {
        const dies = bt.lbt.feed();
        const op_index = op_ref.to_index() orelse return;
        if (!dies) return;
        bt.function.process_death(op_index);
    }

    fn finish_air(bt: *BigTomb, result: MCValue) void {
        const is_used = !bt.function.liveness.is_unused(bt.inst);
        if (is_used) {
            log.debug("%{d} => {}", .{ bt.inst, result });
            const branch = &bt.function.branch_stack.items[bt.function.branch_stack.items.len - 1];
            branch.inst_table.put_assume_capacity_no_clobber(bt.inst, result);

            switch (result) {
                .register => |reg| {
                    // In some cases (such as bitcast), an operand
                    // may be the same MCValue as the result. If
                    // that operand died and was a register, it
                    // was freed by process_death. We have to
                    // "re-allocate" the register.
                    if (bt.function.register_manager.is_reg_free(reg)) {
                        bt.function.register_manager.get_reg_assume_free(reg, bt.inst);
                    }
                },
                .register_with_overflow => |rwo| {
                    if (bt.function.register_manager.is_reg_free(rwo.reg)) {
                        bt.function.register_manager.get_reg_assume_free(rwo.reg, bt.inst);
                    }
                    bt.function.compare_flags_inst = bt.inst;
                },
                .compare_flags => |_| {
                    bt.function.compare_flags_inst = bt.inst;
                },
                else => {},
            }
        }
        bt.function.finish_air_bookkeeping();
    }
};

const Self = @This();

pub fn generate(
    lf: *link.File,
    src_loc: Module.SrcLoc,
    func_index: InternPool.Index,
    air: Air,
    liveness: Liveness,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
) CodeGenError!Result {
    const gpa = lf.comp.gpa;
    const zcu = lf.comp.module.?;
    const func = zcu.func_info(func_index);
    const fn_owner_decl = zcu.decl_ptr(func.owner_decl);
    assert(fn_owner_decl.has_tv);
    const fn_type = fn_owner_decl.type_of(zcu);
    const namespace = zcu.namespace_ptr(fn_owner_decl.src_namespace);
    const target = &namespace.file_scope.mod.resolved_target.result;

    var branch_stack = std.ArrayList(Branch).init(gpa);
    defer {
        assert(branch_stack.items.len == 1);
        branch_stack.items[0].deinit(gpa);
        branch_stack.deinit();
    }
    try branch_stack.append(.{});

    var function = Self{
        .gpa = gpa,
        .air = air,
        .liveness = liveness,
        .debug_output = debug_output,
        .target = target,
        .bin_file = lf,
        .func_index = func_index,
        .owner_decl = func.owner_decl,
        .err_msg = null,
        .args = undefined, // populated after `resolve_calling_convention_values`
        .ret_mcv = undefined, // populated after `resolve_calling_convention_values`
        .fn_type = fn_type,
        .arg_index = 0,
        .branch_stack = &branch_stack,
        .src_loc = src_loc,
        .stack_align = undefined,
        .end_di_line = func.rbrace_line,
        .end_di_column = func.rbrace_column,
    };
    defer function.stack.deinit(gpa);
    defer function.blocks.deinit(gpa);
    defer function.exitlude_jump_relocs.deinit(gpa);
    defer function.dbg_info_relocs.deinit(gpa);

    var call_info = function.resolve_calling_convention_values(fn_type) catch |err| switch (err) {
        error.CodegenFail => return Result{ .fail = function.err_msg.? },
        error.OutOfRegisters => return Result{
            .fail = try ErrorMsg.create(gpa, src_loc, "CodeGen ran out of registers. This is a bug in the Zig compiler.", .{}),
        },
        else => |e| return e,
    };
    defer call_info.deinit(&function);

    function.args = call_info.args;
    function.ret_mcv = call_info.return_value;
    function.stack_align = call_info.stack_align;
    function.max_end_stack = call_info.stack_byte_count;

    function.gen() catch |err| switch (err) {
        error.CodegenFail => return Result{ .fail = function.err_msg.? },
        error.OutOfRegisters => return Result{
            .fail = try ErrorMsg.create(gpa, src_loc, "CodeGen ran out of registers. This is a bug in the Zig compiler.", .{}),
        },
        else => |e| return e,
    };

    for (function.dbg_info_relocs.items) |reloc| {
        try reloc.gen_dbg_info(function);
    }

    var mir = Mir{
        .instructions = function.mir_instructions.to_owned_slice(),
        .extra = try function.mir_extra.to_owned_slice(gpa),
    };
    defer mir.deinit(gpa);

    var emit = Emit{
        .mir = mir,
        .bin_file = lf,
        .debug_output = debug_output,
        .target = target,
        .src_loc = src_loc,
        .code = code,
        .prev_di_pc = 0,
        .prev_di_line = func.lbrace_line,
        .prev_di_column = func.lbrace_column,
        .stack_size = function.max_end_stack,
        .saved_regs_stack_space = function.saved_regs_stack_space,
    };
    defer emit.deinit();

    emit.emit_mir() catch |err| switch (err) {
        error.EmitFail => return Result{ .fail = emit.err_msg.? },
        else => |e| return e,
    };

    if (function.err_msg) |em| {
        return Result{ .fail = em };
    } else {
        return Result.ok;
    }
}

fn add_inst(self: *Self, inst: Mir.Inst) error{OutOfMemory}!Mir.Inst.Index {
    const gpa = self.gpa;

    try self.mir_instructions.ensure_unused_capacity(gpa, 1);

    const result_index: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
    self.mir_instructions.append_assume_capacity(inst);
    return result_index;
}

fn add_nop(self: *Self) error{OutOfMemory}!Mir.Inst.Index {
    return try self.add_inst(.{
        .tag = .nop,
        .data = .{ .nop = {} },
    });
}

pub fn add_extra(self: *Self, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try self.mir_extra.ensure_unused_capacity(self.gpa, fields.len);
    return self.add_extra_assume_capacity(extra);
}

pub fn add_extra_assume_capacity(self: *Self, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const result = @as(u32, @int_cast(self.mir_extra.items.len));
    inline for (fields) |field| {
        self.mir_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            i32 => @as(u32, @bit_cast(@field(extra, field.name))),
            else => @compile_error("bad field type"),
        });
    }
    return result;
}

fn gen(self: *Self) !void {
    const mod = self.bin_file.comp.module.?;
    const cc = self.fn_type.fn_calling_convention(mod);
    if (cc != .Naked) {
        // stp fp, lr, [sp, #-16]!
        _ = try self.add_inst(.{
            .tag = .stp,
            .data = .{ .load_store_register_pair = .{
                .rt = .x29,
                .rt2 = .x30,
                .rn = .sp,
                .offset = Instruction.LoadStorePairOffset.pre_index(-16),
            } },
        });

        // <store other registers>
        const backpatch_save_registers = try self.add_nop();

        // mov fp, sp
        _ = try self.add_inst(.{
            .tag = .mov_to_from_sp,
            .data = .{ .rr = .{ .rd = .x29, .rn = .sp } },
        });

        // sub sp, sp, #reloc
        const backpatch_reloc = try self.add_nop();

        if (self.ret_mcv == .stack_offset) {
            // The address of where to store the return value is in x0
            // (or w0 when pointer size is 32 bits). As this register
            // might get overwritten along the way, save the address
            // to the stack.
            const ret_ptr_reg = self.register_alias(.x0, Type.usize);

            const stack_offset = try self.alloc_mem(8, .@"8", null);

            try self.gen_set_stack(Type.usize, stack_offset, MCValue{ .register = ret_ptr_reg });
            self.ret_mcv = MCValue{ .stack_offset = stack_offset };
        }

        for (self.args, 0..) |*arg, arg_index| {
            // Copy register arguments to the stack
            switch (arg.*) {
                .register => |reg| {
                    // The first AIR instructions of the main body are guaranteed
                    // to be the functions arguments
                    const inst = self.air.get_main_body()[arg_index];
                    assert(self.air.instructions.items(.tag)[@int_from_enum(inst)] == .arg);

                    const ty = self.type_of_index(inst);

                    const abi_size = @as(u32, @int_cast(ty.abi_size(mod)));
                    const abi_align = ty.abi_alignment(mod);
                    const stack_offset = try self.alloc_mem(abi_size, abi_align, inst);
                    try self.gen_set_stack(ty, stack_offset, MCValue{ .register = reg });

                    arg.* = MCValue{ .stack_offset = stack_offset };
                },
                else => {},
            }
        }

        _ = try self.add_inst(.{
            .tag = .dbg_prologue_end,
            .data = .{ .nop = {} },
        });

        try self.gen_body(self.air.get_main_body());

        // Backpatch push callee saved regs
        var saved_regs: u32 = 0;
        self.saved_regs_stack_space = 16;
        inline for (callee_preserved_regs) |reg| {
            if (self.register_manager.is_reg_allocated(reg)) {
                saved_regs |= @as(u32, 1) << @as(u5, @int_cast(reg.id()));
                self.saved_regs_stack_space += 8;
            }
        }

        // Emit.mirPopPushRegs automatically adds extra empty space so
        // that sp is always aligned to 16
        if (!std.mem.is_aligned_generic(u32, self.saved_regs_stack_space, 16)) {
            self.saved_regs_stack_space += 8;
        }
        assert(std.mem.is_aligned_generic(u32, self.saved_regs_stack_space, 16));

        self.mir_instructions.set(backpatch_save_registers, .{
            .tag = .push_regs,
            .data = .{ .reg_list = saved_regs },
        });

        // Backpatch stack offset
        const total_stack_size = self.max_end_stack + self.saved_regs_stack_space;
        const aligned_total_stack_end = mem.align_forward(u32, total_stack_size, self.stack_align);
        const stack_size = aligned_total_stack_end - self.saved_regs_stack_space;
        self.max_end_stack = stack_size;
        if (math.cast(u12, stack_size)) |size| {
            self.mir_instructions.set(backpatch_reloc, .{
                .tag = .sub_immediate,
                .data = .{ .rr_imm12_sh = .{ .rd = .sp, .rn = .sp, .imm12 = size } },
            });
        } else {
            return self.fail_symbol("TODO AArch64: allow larger stacks", .{});
        }

        _ = try self.add_inst(.{
            .tag = .dbg_epilogue_begin,
            .data = .{ .nop = {} },
        });

        // exitlude jumps
        if (self.exitlude_jump_relocs.items.len > 0 and
            self.exitlude_jump_relocs.items[self.exitlude_jump_relocs.items.len - 1] == self.mir_instructions.len - 2)
        {
            // If the last Mir instruction (apart from the
            // dbg_epilogue_begin) is the last exitlude jump
            // relocation (which would just jump one instruction
            // further), it can be safely removed
            self.mir_instructions.ordered_remove(self.exitlude_jump_relocs.pop());
        }

        for (self.exitlude_jump_relocs.items) |jmp_reloc| {
            self.mir_instructions.set(jmp_reloc, .{
                .tag = .b,
                .data = .{ .inst = @as(u32, @int_cast(self.mir_instructions.len)) },
            });
        }

        // add sp, sp, #stack_size
        _ = try self.add_inst(.{
            .tag = .add_immediate,
            .data = .{ .rr_imm12_sh = .{ .rd = .sp, .rn = .sp, .imm12 = @as(u12, @int_cast(stack_size)) } },
        });

        // <load other registers>
        _ = try self.add_inst(.{
            .tag = .pop_regs,
            .data = .{ .reg_list = saved_regs },
        });

        // ldp fp, lr, [sp], #16
        _ = try self.add_inst(.{
            .tag = .ldp,
            .data = .{ .load_store_register_pair = .{
                .rt = .x29,
                .rt2 = .x30,
                .rn = .sp,
                .offset = Instruction.LoadStorePairOffset.post_index(16),
            } },
        });

        // ret lr
        _ = try self.add_inst(.{
            .tag = .ret,
            .data = .{ .reg = .x30 },
        });
    } else {
        _ = try self.add_inst(.{
            .tag = .dbg_prologue_end,
            .data = .{ .nop = {} },
        });

        try self.gen_body(self.air.get_main_body());

        _ = try self.add_inst(.{
            .tag = .dbg_epilogue_begin,
            .data = .{ .nop = {} },
        });
    }

    // Drop them off at the rbrace.
    _ = try self.add_inst(.{
        .tag = .dbg_line,
        .data = .{ .dbg_line_column = .{
            .line = self.end_di_line,
            .column = self.end_di_column,
        } },
    });
}

fn gen_body(self: *Self, body: []const Air.Inst.Index) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    const air_tags = self.air.instructions.items(.tag);

    for (body) |inst| {
        // TODO: remove now-redundant is_unused calls from AIR handler functions
        if (self.liveness.is_unused(inst) and !self.air.must_lower(inst, ip))
            continue;

        const old_air_bookkeeping = self.air_bookkeeping;
        try self.ensure_process_death_capacity(Liveness.bpi);

        switch (air_tags[@int_from_enum(inst)]) {
            // zig fmt: off
            .add             => try self.air_bin_op(inst, .add),
            .add_wrap        => try self.air_bin_op(inst, .add_wrap),
            .sub             => try self.air_bin_op(inst, .sub),
            .sub_wrap        => try self.air_bin_op(inst, .sub_wrap),
            .mul             => try self.air_bin_op(inst, .mul),
            .mul_wrap        => try self.air_bin_op(inst, .mul_wrap),
            .shl             => try self.air_bin_op(inst, .shl),
            .shl_exact       => try self.air_bin_op(inst, .shl_exact),
            .bool_and        => try self.air_bin_op(inst, .bool_and),
            .bool_or         => try self.air_bin_op(inst, .bool_or),
            .bit_and         => try self.air_bin_op(inst, .bit_and),
            .bit_or          => try self.air_bin_op(inst, .bit_or),
            .xor             => try self.air_bin_op(inst, .xor),
            .shr             => try self.air_bin_op(inst, .shr),
            .shr_exact       => try self.air_bin_op(inst, .shr_exact),
            .div_float       => try self.air_bin_op(inst, .div_float),
            .div_trunc       => try self.air_bin_op(inst, .div_trunc),
            .div_floor       => try self.air_bin_op(inst, .div_floor),
            .div_exact       => try self.air_bin_op(inst, .div_exact),
            .rem             => try self.air_bin_op(inst, .rem),
            .mod             => try self.air_bin_op(inst, .mod),

            .ptr_add         => try self.air_ptr_arithmetic(inst, .ptr_add),
            .ptr_sub         => try self.air_ptr_arithmetic(inst, .ptr_sub),

            .min             => try self.air_min_max(inst),
            .max             => try self.air_min_max(inst),

            .add_sat         => try self.air_add_sat(inst),
            .sub_sat         => try self.air_sub_sat(inst),
            .mul_sat         => try self.air_mul_sat(inst),
            .shl_sat         => try self.air_shl_sat(inst),
            .slice           => try self.air_slice(inst),

            .sqrt,
            .sin,
            .cos,
            .tan,
            .exp,
            .exp2,
            .log,
            .log2,
            .log10,
            .floor,
            .ceil,
            .round,
            .trunc_float,
            .neg,
            => try self.air_unary_math(inst),

            .add_with_overflow => try self.air_overflow(inst),
            .sub_with_overflow => try self.air_overflow(inst),
            .mul_with_overflow => try self.air_mul_with_overflow(inst),
            .shl_with_overflow => try self.air_shl_with_overflow(inst),

            .cmp_lt  => try self.air_cmp(inst, .lt),
            .cmp_lte => try self.air_cmp(inst, .lte),
            .cmp_eq  => try self.air_cmp(inst, .eq),
            .cmp_gte => try self.air_cmp(inst, .gte),
            .cmp_gt  => try self.air_cmp(inst, .gt),
            .cmp_neq => try self.air_cmp(inst, .neq),

            .cmp_vector => try self.air_cmp_vector(inst),
            .cmp_lt_errors_len => try self.air_cmp_lt_errors_len(inst),

            .alloc           => try self.air_alloc(inst),
            .ret_ptr         => try self.air_ret_ptr(inst),
            .arg             => try self.air_arg(inst),
            .assembly        => try self.air_asm(inst),
            .bitcast         => try self.air_bit_cast(inst),
            .block           => try self.air_block(inst),
            .br              => try self.air_br(inst),
            .trap            => try self.air_trap(),
            .breakpoint      => try self.air_breakpoint(),
            .ret_addr        => try self.air_ret_addr(inst),
            .frame_addr      => try self.air_frame_address(inst),
            .fence           => try self.air_fence(),
            .cond_br         => try self.air_cond_br(inst),
            .fptrunc         => try self.air_fptrunc(inst),
            .fpext           => try self.air_fpext(inst),
            .intcast         => try self.air_int_cast(inst),
            .trunc           => try self.air_trunc(inst),
            .int_from_bool     => try self.air_int_from_bool(inst),
            .is_non_null     => try self.air_is_non_null(inst),
            .is_non_null_ptr => try self.air_is_non_null_ptr(inst),
            .is_null         => try self.air_is_null(inst),
            .is_null_ptr     => try self.air_is_null_ptr(inst),
            .is_non_err      => try self.air_is_non_err(inst),
            .is_non_err_ptr  => try self.air_is_non_err_ptr(inst),
            .is_err          => try self.air_is_err(inst),
            .is_err_ptr      => try self.air_is_err_ptr(inst),
            .load            => try self.air_load(inst),
            .loop            => try self.air_loop(inst),
            .not             => try self.air_not(inst),
            .int_from_ptr        => try self.air_int_from_ptr(inst),
            .ret             => try self.air_ret(inst),
            .ret_safe        => try self.air_ret(inst), // TODO
            .ret_load        => try self.air_ret_load(inst),
            .store           => try self.air_store(inst, false),
            .store_safe      => try self.air_store(inst, true),
            .struct_field_ptr=> try self.air_struct_field_ptr(inst),
            .struct_field_val=> try self.air_struct_field_val(inst),
            .array_to_slice  => try self.air_array_to_slice(inst),
            .float_from_int    => try self.air_float_from_int(inst),
            .int_from_float    => try self.air_int_from_float(inst),
            .cmpxchg_strong  => try self.air_cmpxchg(inst),
            .cmpxchg_weak    => try self.air_cmpxchg(inst),
            .atomic_rmw      => try self.air_atomic_rmw(inst),
            .atomic_load     => try self.air_atomic_load(inst),
            .memcpy          => try self.air_memcpy(inst),
            .memset          => try self.air_memset(inst, false),
            .memset_safe     => try self.air_memset(inst, true),
            .set_union_tag   => try self.air_set_union_tag(inst),
            .get_union_tag   => try self.air_get_union_tag(inst),
            .clz             => try self.air_clz(inst),
            .ctz             => try self.air_ctz(inst),
            .popcount        => try self.air_popcount(inst),
            .abs             => try self.air_abs(inst),
            .byte_swap       => try self.air_byte_swap(inst),
            .bit_reverse     => try self.air_bit_reverse(inst),
            .tag_name        => try self.air_tag_name(inst),
            .error_name      => try self.air_error_name(inst),
            .splat           => try self.air_splat(inst),
            .select          => try self.air_select(inst),
            .shuffle         => try self.air_shuffle(inst),
            .reduce          => try self.air_reduce(inst),
            .aggregate_init  => try self.air_aggregate_init(inst),
            .union_init      => try self.air_union_init(inst),
            .prefetch        => try self.air_prefetch(inst),
            .mul_add         => try self.air_mul_add(inst),
            .addrspace_cast  => return self.fail("TODO implement addrspace_cast", .{}),

            .@"try"          => try self.air_try(inst),
            .try_ptr         => try self.air_try_ptr(inst),

            .dbg_stmt         => try self.air_dbg_stmt(inst),
            .dbg_inline_block => try self.air_dbg_inline_block(inst),
            .dbg_var_ptr,
            .dbg_var_val,
            => try self.air_dbg_var(inst),

            .call              => try self.air_call(inst, .auto),
            .call_always_tail  => try self.air_call(inst, .always_tail),
            .call_never_tail   => try self.air_call(inst, .never_tail),
            .call_never_inline => try self.air_call(inst, .never_inline),

            .atomic_store_unordered => try self.air_atomic_store(inst, .unordered),
            .atomic_store_monotonic => try self.air_atomic_store(inst, .monotonic),
            .atomic_store_release   => try self.air_atomic_store(inst, .release),
            .atomic_store_seq_cst   => try self.air_atomic_store(inst, .seq_cst),

            .struct_field_ptr_index_0 => try self.air_struct_field_ptr_index(inst, 0),
            .struct_field_ptr_index_1 => try self.air_struct_field_ptr_index(inst, 1),
            .struct_field_ptr_index_2 => try self.air_struct_field_ptr_index(inst, 2),
            .struct_field_ptr_index_3 => try self.air_struct_field_ptr_index(inst, 3),

            .field_parent_ptr => try self.air_field_parent_ptr(inst),

            .switch_br       => try self.air_switch(inst),
            .slice_ptr       => try self.air_slice_ptr(inst),
            .slice_len       => try self.air_slice_len(inst),

            .ptr_slice_len_ptr => try self.air_ptr_slice_len_ptr(inst),
            .ptr_slice_ptr_ptr => try self.air_ptr_slice_ptr_ptr(inst),

            .array_elem_val      => try self.air_array_elem_val(inst),
            .slice_elem_val      => try self.air_slice_elem_val(inst),
            .slice_elem_ptr      => try self.air_slice_elem_ptr(inst),
            .ptr_elem_val        => try self.air_ptr_elem_val(inst),
            .ptr_elem_ptr        => try self.air_ptr_elem_ptr(inst),

            .inferred_alloc, .inferred_alloc_comptime => unreachable,
            .unreach  => self.finish_air_bookkeeping(),

            .optional_payload           => try self.air_optional_payload(inst),
            .optional_payload_ptr       => try self.air_optional_payload_ptr(inst),
            .optional_payload_ptr_set   => try self.air_optional_payload_ptr_set(inst),
            .unwrap_errunion_err        => try self.air_unwrap_err_err(inst),
            .unwrap_errunion_payload    => try self.air_unwrap_err_payload(inst),
            .unwrap_errunion_err_ptr    => try self.air_unwrap_err_err_ptr(inst),
            .unwrap_errunion_payload_ptr=> try self.air_unwrap_err_payload_ptr(inst),
            .errunion_payload_ptr_set   => try self.air_err_union_payload_ptr_set(inst),
            .err_return_trace           => try self.air_err_return_trace(inst),
            .set_err_return_trace       => try self.air_set_err_return_trace(inst),
            .save_err_return_trace_index=> try self.air_save_err_return_trace_index(inst),

            .wrap_optional         => try self.air_wrap_optional(inst),
            .wrap_errunion_payload => try self.air_wrap_err_union_payload(inst),
            .wrap_errunion_err     => try self.air_wrap_err_union_err(inst),

            .add_optimized,
            .sub_optimized,
            .mul_optimized,
            .div_float_optimized,
            .div_trunc_optimized,
            .div_floor_optimized,
            .div_exact_optimized,
            .rem_optimized,
            .mod_optimized,
            .neg_optimized,
            .cmp_lt_optimized,
            .cmp_lte_optimized,
            .cmp_eq_optimized,
            .cmp_gte_optimized,
            .cmp_gt_optimized,
            .cmp_neq_optimized,
            .cmp_vector_optimized,
            .reduce_optimized,
            .int_from_float_optimized,
            => return self.fail("TODO implement optimized float mode", .{}),

            .add_safe,
            .sub_safe,
            .mul_safe,
            => return self.fail("TODO implement safety_checked_instructions", .{}),

            .is_named_enum_value => return self.fail("TODO implement is_named_enum_value", .{}),
            .error_set_has_value => return self.fail("TODO implement error_set_has_value", .{}),
            .vector_store_elem => return self.fail("TODO implement vector_store_elem", .{}),

            .c_va_arg => return self.fail("TODO implement c_va_arg", .{}),
            .c_va_copy => return self.fail("TODO implement c_va_copy", .{}),
            .c_va_end => return self.fail("TODO implement c_va_end", .{}),
            .c_va_start => return self.fail("TODO implement c_va_start", .{}),

            .wasm_memory_size => unreachable,
            .wasm_memory_grow => unreachable,

            .work_item_id => unreachable,
            .work_group_size => unreachable,
            .work_group_id => unreachable,
            // zig fmt: on
        }

        assert(!self.register_manager.locked_regs_exist());

        if (std.debug.runtime_safety) {
            if (self.air_bookkeeping < old_air_bookkeeping + 1) {
                std.debug.panic("in codegen.zig, handling of AIR instruction %{d} ('{}') did not do proper bookkeeping. Look for a missing call to finish_air.", .{ inst, air_tags[@int_from_enum(inst)] });
            }
        }
    }
}

/// Asserts there is already capacity to insert into top branch inst_table.
fn process_death(self: *Self, inst: Air.Inst.Index) void {
    // When editing this function, note that the logic must synchronize with `reuse_operand`.
    const prev_value = self.get_resolved_inst_value(inst);
    const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
    branch.inst_table.put_assume_capacity(inst, .dead);
    switch (prev_value) {
        .register => |reg| {
            self.register_manager.free_reg(reg);
        },
        .register_with_overflow => |rwo| {
            self.register_manager.free_reg(rwo.reg);
            self.compare_flags_inst = null;
        },
        .compare_flags => {
            self.compare_flags_inst = null;
        },
        else => {}, // TODO process stack allocation death
    }
}

/// Called when there are no operands, and the instruction is always unreferenced.
fn finish_air_bookkeeping(self: *Self) void {
    if (std.debug.runtime_safety) {
        self.air_bookkeeping += 1;
    }
}

fn finish_air(self: *Self, inst: Air.Inst.Index, result: MCValue, operands: [Liveness.bpi - 1]Air.Inst.Ref) void {
    var tomb_bits = self.liveness.get_tomb_bits(inst);
    for (operands) |op| {
        const dies = @as(u1, @truncate(tomb_bits)) != 0;
        tomb_bits >>= 1;
        if (!dies) continue;
        const op_index = op.to_index() orelse continue;
        self.process_death(op_index);
    }
    const is_used = @as(u1, @truncate(tomb_bits)) == 0;
    if (is_used) {
        log.debug("%{d} => {}", .{ inst, result });
        const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
        branch.inst_table.put_assume_capacity_no_clobber(inst, result);

        switch (result) {
            .register => |reg| {
                // In some cases (such as bitcast), an operand
                // may be the same MCValue as the result. If
                // that operand died and was a register, it
                // was freed by process_death. We have to
                // "re-allocate" the register.
                if (self.register_manager.is_reg_free(reg)) {
                    self.register_manager.get_reg_assume_free(reg, inst);
                }
            },
            .register_with_overflow => |rwo| {
                if (self.register_manager.is_reg_free(rwo.reg)) {
                    self.register_manager.get_reg_assume_free(rwo.reg, inst);
                }
                self.compare_flags_inst = inst;
            },
            .compare_flags => |_| {
                self.compare_flags_inst = inst;
            },
            else => {},
        }
    }
    self.finish_air_bookkeeping();
}

fn ensure_process_death_capacity(self: *Self, additional_count: usize) !void {
    const table = &self.branch_stack.items[self.branch_stack.items.len - 1].inst_table;
    try table.ensure_unused_capacity(self.gpa, additional_count);
}

fn alloc_mem(
    self: *Self,
    abi_size: u32,
    abi_align: Alignment,
    maybe_inst: ?Air.Inst.Index,
) !u32 {
    assert(abi_size > 0);
    assert(abi_align != .none);

    // In order to efficiently load and store stack items that fit
    // into registers, we bump up the alignment to the next power of
    // two.
    const adjusted_align = if (abi_size > 8)
        abi_align
    else
        Alignment.from_nonzero_byte_units(std.math.ceil_power_of_two_assert(u64, abi_size));

    // TODO find a free slot instead of always appending
    const offset: u32 = @int_cast(adjusted_align.forward(self.next_stack_offset) + abi_size);
    self.next_stack_offset = offset;
    self.max_end_stack = @max(self.max_end_stack, self.next_stack_offset);

    if (maybe_inst) |inst| {
        try self.stack.put_no_clobber(self.gpa, offset, .{
            .inst = inst,
            .size = abi_size,
        });
    }

    return offset;
}

/// Use a pointer instruction as the basis for allocating stack memory.
fn alloc_mem_ptr(self: *Self, inst: Air.Inst.Index) !u32 {
    const mod = self.bin_file.comp.module.?;
    const elem_ty = self.type_of_index(inst).child_type(mod);

    if (!elem_ty.has_runtime_bits(mod)) {
        // return the stack offset 0. Stack offset 0 will be where all
        // zero-sized stack allocations live as non-zero-sized
        // allocations will always have an offset > 0.
        return @as(u32, 0);
    }

    const abi_size = math.cast(u32, elem_ty.abi_size(mod)) orelse {
        return self.fail("type '{}' too big to fit into stack frame", .{elem_ty.fmt(mod)});
    };
    // TODO swap this for inst.ty.ptrAlign
    const abi_align = elem_ty.abi_alignment(mod);

    return self.alloc_mem(abi_size, abi_align, inst);
}

fn alloc_reg_or_mem(self: *Self, elem_ty: Type, reg_ok: bool, maybe_inst: ?Air.Inst.Index) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const abi_size = math.cast(u32, elem_ty.abi_size(mod)) orelse {
        return self.fail("type '{}' too big to fit into stack frame", .{elem_ty.fmt(mod)});
    };
    const abi_align = elem_ty.abi_alignment(mod);

    if (reg_ok) {
        // Make sure the type can fit in a register before we try to allocate one.
        if (abi_size <= 8) {
            if (self.register_manager.try_alloc_reg(maybe_inst, gp)) |reg| {
                return MCValue{ .register = self.register_alias(reg, elem_ty) };
            }
        }
    }

    const stack_offset = try self.alloc_mem(abi_size, abi_align, maybe_inst);
    return MCValue{ .stack_offset = stack_offset };
}

pub fn spill_instruction(self: *Self, reg: Register, inst: Air.Inst.Index) !void {
    const stack_mcv = try self.alloc_reg_or_mem(self.type_of_index(inst), false, inst);
    log.debug("spilling {d} to stack mcv {any}", .{ inst, stack_mcv });

    const reg_mcv = self.get_resolved_inst_value(inst);
    switch (reg_mcv) {
        .register => |r| assert(reg.id() == r.id()),
        .register_with_overflow => |rwo| assert(rwo.reg.id() == reg.id()),
        else => unreachable, // not a register
    }

    const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
    try branch.inst_table.put(self.gpa, inst, stack_mcv);
    try self.gen_set_stack(self.type_of_index(inst), stack_mcv.stack_offset, reg_mcv);
}

/// Save the current instruction stored in the compare flags if
/// occupied
fn spill_compare_flags_if_occupied(self: *Self) !void {
    if (self.compare_flags_inst) |inst_to_save| {
        const ty = self.type_of_index(inst_to_save);
        const mcv = self.get_resolved_inst_value(inst_to_save);
        const new_mcv = switch (mcv) {
            .compare_flags => try self.alloc_reg_or_mem(ty, true, inst_to_save),
            .register_with_overflow => try self.alloc_reg_or_mem(ty, false, inst_to_save),
            else => unreachable, // mcv doesn't occupy the compare flags
        };

        try self.set_reg_or_mem(self.type_of_index(inst_to_save), new_mcv, mcv);
        log.debug("spilling {d} to mcv {any}", .{ inst_to_save, new_mcv });

        const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
        try branch.inst_table.put(self.gpa, inst_to_save, new_mcv);

        self.compare_flags_inst = null;

        // TODO consolidate with register manager and spill_instruction
        // this call should really belong in the register manager!
        switch (mcv) {
            .register_with_overflow => |rwo| self.register_manager.free_reg(rwo.reg),
            else => {},
        }
    }
}

/// Copies a value to a register without tracking the register. The register is not considered
/// allocated. A second call to `copy_to_tmp_register` may return the same register.
/// This can have a side effect of spilling instructions to the stack to free up a register.
fn copy_to_tmp_register(self: *Self, ty: Type, mcv: MCValue) !Register {
    const raw_reg = try self.register_manager.alloc_reg(null, gp);
    const reg = self.register_alias(raw_reg, ty);
    try self.gen_set_reg(ty, reg, mcv);
    return reg;
}

/// Allocates a new register and copies `mcv` into it.
/// `reg_owner` is the instruction that gets associated with the register in the register table.
/// This can have a side effect of spilling instructions to the stack to free up a register.
fn copy_to_new_register(self: *Self, reg_owner: Air.Inst.Index, mcv: MCValue) !MCValue {
    const raw_reg = try self.register_manager.alloc_reg(reg_owner, gp);
    const ty = self.type_of_index(reg_owner);
    const reg = self.register_alias(raw_reg, ty);
    try self.gen_set_reg(self.type_of_index(reg_owner), reg, mcv);
    return MCValue{ .register = reg };
}

fn air_alloc(self: *Self, inst: Air.Inst.Index) !void {
    const stack_offset = try self.alloc_mem_ptr(inst);
    return self.finish_air(inst, .{ .ptr_stack_offset = stack_offset }, .{ .none, .none, .none });
}

fn air_ret_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const result: MCValue = switch (self.ret_mcv) {
        .none, .register => .{ .ptr_stack_offset = try self.alloc_mem_ptr(inst) },
        .stack_offset => blk: {
            // self.ret_mcv is an address to where this function
            // should store its result into
            const ret_ty = self.fn_type.fn_return_type(mod);
            const ptr_ty = try mod.single_mut_ptr_type(ret_ty);

            // addr_reg will contain the address of where to store the
            // result into
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, self.ret_mcv);
            break :blk .{ .register = addr_reg };
        },
        else => unreachable, // invalid return result
    };

    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_fptrunc(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_fptrunc for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_fpext(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_fpext for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_cast(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    if (self.liveness.is_unused(inst))
        return self.finish_air(inst, .dead, .{ ty_op.operand, .none, .none });

    const mod = self.bin_file.comp.module.?;
    const operand = ty_op.operand;
    const operand_mcv = try self.resolve_inst(operand);
    const operand_ty = self.type_of(operand);
    const operand_info = operand_ty.int_info(mod);

    const dest_ty = self.type_of_index(inst);
    const dest_info = dest_ty.int_info(mod);

    const result: MCValue = result: {
        const operand_lock: ?RegisterLock = switch (operand_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (operand_lock) |lock| self.register_manager.unlock_reg(lock);

        const truncated: MCValue = switch (operand_mcv) {
            .register => |r| MCValue{ .register = self.register_alias(r, dest_ty) },
            else => operand_mcv,
        };

        if (dest_info.bits > operand_info.bits) {
            const dest_mcv = try self.alloc_reg_or_mem(dest_ty, true, inst);
            try self.set_reg_or_mem(self.type_of_index(inst), dest_mcv, truncated);
            break :result dest_mcv;
        } else {
            if (self.reuse_operand(inst, operand, 0, truncated)) {
                break :result truncated;
            } else {
                const dest_mcv = try self.alloc_reg_or_mem(dest_ty, true, inst);
                try self.set_reg_or_mem(self.type_of_index(inst), dest_mcv, truncated);
                break :result dest_mcv;
            }
        }
    };

    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn trunc_register(
    self: *Self,
    operand_reg: Register,
    dest_reg: Register,
    int_signedness: std.builtin.Signedness,
    int_bits: u16,
) !void {
    switch (int_bits) {
        1...31, 33...63 => {
            _ = try self.add_inst(.{
                .tag = switch (int_signedness) {
                    .signed => .sbfx,
                    .unsigned => .ubfx,
                },
                .data = .{ .rr_lsb_width = .{
                    .rd = dest_reg,
                    .rn = operand_reg,
                    .lsb = 0,
                    .width = @as(u6, @int_cast(int_bits)),
                } },
            });
        },
        32, 64 => {
            _ = try self.add_inst(.{
                .tag = .mov_register,
                .data = .{ .rr = .{
                    .rd = if (int_bits == 32) dest_reg.to_w() else dest_reg.to_x(),
                    .rn = if (int_bits == 32) operand_reg.to_w() else operand_reg.to_x(),
                } },
            });
        },
        else => unreachable,
    }
}

fn trunc(
    self: *Self,
    maybe_inst: ?Air.Inst.Index,
    operand: MCValue,
    operand_ty: Type,
    dest_ty: Type,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const info_a = operand_ty.int_info(mod);
    const info_b = dest_ty.int_info(mod);

    if (info_b.bits <= 64) {
        const operand_reg = switch (operand) {
            .register => |r| r,
            else => operand_reg: {
                if (info_a.bits <= 64) {
                    const raw_reg = try self.copy_to_tmp_register(operand_ty, operand);
                    break :operand_reg self.register_alias(raw_reg, operand_ty);
                } else {
                    return self.fail("TODO load least significant word into register", .{});
                }
            },
        };
        const lock = self.register_manager.lock_reg(operand_reg);
        defer if (lock) |reg| self.register_manager.unlock_reg(reg);

        const dest_reg = if (maybe_inst) |inst| blk: {
            const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

            if (operand == .register and self.reuse_operand(inst, ty_op.operand, 0, operand)) {
                break :blk self.register_alias(operand_reg, dest_ty);
            } else {
                const raw_reg = try self.register_manager.alloc_reg(inst, gp);
                break :blk self.register_alias(raw_reg, dest_ty);
            }
        } else blk: {
            const raw_reg = try self.register_manager.alloc_reg(null, gp);
            break :blk self.register_alias(raw_reg, dest_ty);
        };

        try self.trunc_register(operand_reg, dest_reg, info_b.signedness, info_b.bits);

        return MCValue{ .register = dest_reg };
    } else {
        return self.fail("TODO: truncate to ints > 64 bits", .{});
    }
}

fn air_trunc(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand = try self.resolve_inst(ty_op.operand);
    const operand_ty = self.type_of(ty_op.operand);
    const dest_ty = self.type_of_index(inst);

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else blk: {
        break :blk try self.trunc(inst, operand, operand_ty, dest_ty);
    };

    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_bool(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else operand;
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_not(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const mod = self.bin_file.comp.module.?;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);
        switch (operand) {
            .dead => unreachable,
            .unreach => unreachable,
            .compare_flags => |cond| break :result MCValue{ .compare_flags = cond.negate() },
            else => {
                switch (operand_ty.zig_type_tag(mod)) {
                    .Bool => {
                        // TODO convert this to mvn + and
                        const op_reg = switch (operand) {
                            .register => |r| r,
                            else => try self.copy_to_tmp_register(operand_ty, operand),
                        };
                        const reg_lock = self.register_manager.lock_reg_assume_unused(op_reg);
                        defer self.register_manager.unlock_reg(reg_lock);

                        const dest_reg = blk: {
                            if (operand == .register and self.reuse_operand(inst, ty_op.operand, 0, operand)) {
                                break :blk op_reg;
                            }

                            const raw_reg = try self.register_manager.alloc_reg(null, gp);
                            break :blk self.register_alias(raw_reg, operand_ty);
                        };

                        _ = try self.add_inst(.{
                            .tag = .eor_immediate,
                            .data = .{ .rr_bitmask = .{
                                .rd = dest_reg,
                                .rn = op_reg,
                                .imms = 0b000000,
                                .immr = 0b000000,
                                .n = 0b0,
                            } },
                        });

                        break :result MCValue{ .register = dest_reg };
                    },
                    .Vector => return self.fail("TODO bitwise not for vectors", .{}),
                    .Int => {
                        const int_info = operand_ty.int_info(mod);
                        if (int_info.bits <= 64) {
                            const op_reg = switch (operand) {
                                .register => |r| r,
                                else => try self.copy_to_tmp_register(operand_ty, operand),
                            };
                            const reg_lock = self.register_manager.lock_reg_assume_unused(op_reg);
                            defer self.register_manager.unlock_reg(reg_lock);

                            const dest_reg = blk: {
                                if (operand == .register and self.reuse_operand(inst, ty_op.operand, 0, operand)) {
                                    break :blk op_reg;
                                }

                                const raw_reg = try self.register_manager.alloc_reg(null, gp);
                                break :blk self.register_alias(raw_reg, operand_ty);
                            };

                            _ = try self.add_inst(.{
                                .tag = .mvn,
                                .data = .{ .rr_imm6_logical_shift = .{
                                    .rd = dest_reg,
                                    .rm = op_reg,
                                    .imm6 = 0,
                                    .shift = .lsl,
                                } },
                            });

                            try self.trunc_register(dest_reg, dest_reg, int_info.signedness, int_info.bits);

                            break :result MCValue{ .register = dest_reg };
                        } else {
                            return self.fail("TODO AArch64 not on integers > u64/i64", .{});
                        }
                    },
                    else => unreachable,
                }
            },
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn min_max(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO ARM min/max on floats", .{}),
        .Vector => return self.fail("TODO ARM min/max on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                var lhs_reg: Register = undefined;
                var rhs_reg: Register = undefined;
                var dest_reg: Register = undefined;

                const read_args = [_]ReadArg{
                    .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
                    .{ .ty = rhs_ty, .bind = rhs_bind, .class = gp, .reg = &rhs_reg },
                };
                const write_args = [_]WriteArg{
                    .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
                };
                try self.alloc_regs(
                    &read_args,
                    &write_args,
                    if (maybe_inst) |inst| .{
                        .corresponding_inst = inst,
                        .operand_mapping = &.{ 0, 1 },
                    } else null,
                );

                // lhs == reg should have been checked by air_min_max
                assert(lhs_reg != rhs_reg); // see note above

                _ = try self.add_inst(.{
                    .tag = .cmp_shifted_register,
                    .data = .{ .rr_imm6_shift = .{
                        .rn = lhs_reg,
                        .rm = rhs_reg,
                        .imm6 = 0,
                        .shift = .lsl,
                    } },
                });

                const cond_choose_lhs: Condition = switch (tag) {
                    .max => switch (int_info.signedness) {
                        .signed => Condition.gt,
                        .unsigned => Condition.hi,
                    },
                    .min => switch (int_info.signedness) {
                        .signed => Condition.lt,
                        .unsigned => Condition.cc,
                    },
                    else => unreachable,
                };

                _ = try self.add_inst(.{
                    .tag = .csel,
                    .data = .{ .rrr_cond = .{
                        .rd = dest_reg,
                        .rn = lhs_reg,
                        .rm = rhs_reg,
                        .cond = cond_choose_lhs,
                    } },
                });

                return MCValue{ .register = dest_reg };
            } else {
                return self.fail("TODO ARM min/max on integers > u32/i32", .{});
            }
        },
        else => unreachable,
    }
}

fn air_min_max(self: *Self, inst: Air.Inst.Index) !void {
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = bin_op.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = bin_op.rhs };

        const lhs = try self.resolve_inst(bin_op.lhs);
        if (bin_op.lhs == bin_op.rhs) break :result lhs;

        break :result try self.min_max(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_slice(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const ptr = try self.resolve_inst(bin_op.lhs);
        const ptr_ty = self.type_of(bin_op.lhs);
        const len = try self.resolve_inst(bin_op.rhs);
        const len_ty = self.type_of(bin_op.rhs);

        const stack_offset = try self.alloc_mem(16, .@"8", inst);
        try self.gen_set_stack(ptr_ty, stack_offset, ptr);
        try self.gen_set_stack(len_ty, stack_offset - 8, len);
        break :result MCValue{ .stack_offset = stack_offset };
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

/// An argument to a Mir instruction which is read (and possibly also
/// written to) by the respective instruction
const ReadArg = struct {
    ty: Type,
    bind: Bind,
    class: RegisterManager.RegisterBitSet,
    reg: *Register,

    const Bind = union(enum) {
        inst: Air.Inst.Ref,
        mcv: MCValue,

        fn resolve_to_mcv(bind: Bind, function: *Self) InnerError!MCValue {
            return switch (bind) {
                .inst => |inst| try function.resolve_inst(inst),
                .mcv => |mcv| mcv,
            };
        }

        fn resolve_to_immediate(bind: Bind, function: *Self) InnerError!?u64 {
            switch (bind) {
                .inst => |inst| {
                    // TODO resolve independently of inst_table
                    const mcv = try function.resolve_inst(inst);
                    switch (mcv) {
                        .immediate => |imm| return imm,
                        else => return null,
                    }
                },
                .mcv => |mcv| {
                    switch (mcv) {
                        .immediate => |imm| return imm,
                        else => return null,
                    }
                },
            }
        }
    };
};

/// An argument to a Mir instruction which is written to (but not read
/// from) by the respective instruction
const WriteArg = struct {
    ty: Type,
    bind: Bind,
    class: RegisterManager.RegisterBitSet,
    reg: *Register,

    const Bind = union(enum) {
        reg: Register,
        none: void,
    };
};

/// Holds all data necessary for enabling the potential reuse of
/// operand registers as destinations
const ReuseMetadata = struct {
    corresponding_inst: Air.Inst.Index,

    /// Maps every element index of read_args to the corresponding
    /// index in the Air instruction
    ///
    /// When the order of read_args corresponds exactly to the order
    /// of the inputs of the Air instruction, this would be e.g.
    /// &.{ 0, 1 }. However, when the order is not the same or some
    /// inputs to the Air instruction are omitted (e.g. when they can
    /// be represented as immediates to the Mir instruction),
    /// operand_mapping should reflect that fact.
    operand_mapping: []const Liveness.OperandInt,
};

/// Allocate a set of registers for use as arguments for a Mir
/// instruction
///
/// If the Mir instruction these registers are allocated for
/// corresponds exactly to a single Air instruction, populate
/// reuse_metadata in order to enable potential reuse of an operand as
/// the destination (provided that that operand dies in this
/// instruction).
///
/// Reusing an operand register as destination is the only time two
/// arguments may share the same register. In all other cases,
/// alloc_regs guarantees that a register will never be allocated to
/// more than one argument.
///
/// Furthermore, alloc_reg guarantees that all arguments which are
/// already bound to registers before calling alloc_regs will not
/// change their register binding. This is done by locking these
/// registers.
fn alloc_regs(
    self: *Self,
    read_args: []const ReadArg,
    write_args: []const WriteArg,
    reuse_metadata: ?ReuseMetadata,
) InnerError!void {
    // Air instructions have exactly one output
    assert(!(reuse_metadata != null and write_args.len != 1)); // see note above

    // The operand mapping is a 1:1 mapping of read args to their
    // corresponding operand index in the Air instruction
    assert(!(reuse_metadata != null and reuse_metadata.?.operand_mapping.len != read_args.len)); // see note above

    const locks = try self.gpa.alloc(?RegisterLock, read_args.len + write_args.len);
    defer self.gpa.free(locks);
    const read_locks = locks[0..read_args.len];
    const write_locks = locks[read_args.len..];

    @memset(locks, null);
    defer for (locks) |lock| {
        if (lock) |locked_reg| self.register_manager.unlock_reg(locked_reg);
    };

    // When we reuse a read_arg as a destination, the corresponding
    // MCValue of the read_arg will be set to .dead. In that case, we
    // skip allocating this read_arg.
    var reused_read_arg: ?usize = null;

    // Lock all args which are already allocated to registers
    for (read_args, 0..) |arg, i| {
        const mcv = try arg.bind.resolve_to_mcv(self);
        if (mcv == .register) {
            read_locks[i] = self.register_manager.lock_reg(mcv.register);
        }
    }

    for (write_args, 0..) |arg, i| {
        if (arg.bind == .reg) {
            write_locks[i] = self.register_manager.lock_reg(arg.bind.reg);
        }
    }

    // Allocate registers for all args which aren't allocated to
    // registers yet
    for (read_args, 0..) |arg, i| {
        const mcv = try arg.bind.resolve_to_mcv(self);
        if (mcv == .register) {
            const raw_reg = mcv.register;
            arg.reg.* = self.register_alias(raw_reg, arg.ty);
        } else {
            const track_inst: ?Air.Inst.Index = switch (arg.bind) {
                .inst => |inst| inst.to_index().?,
                else => null,
            };
            const raw_reg = try self.register_manager.alloc_reg(track_inst, gp);
            arg.reg.* = self.register_alias(raw_reg, arg.ty);
            read_locks[i] = self.register_manager.lock_reg_assume_unused(arg.reg.*);
        }
    }

    if (reuse_metadata != null) {
        const inst = reuse_metadata.?.corresponding_inst;
        const operand_mapping = reuse_metadata.?.operand_mapping;
        const arg = write_args[0];
        if (arg.bind == .reg) {
            const raw_reg = arg.bind.reg;
            arg.reg.* = self.register_alias(raw_reg, arg.ty);
        } else {
            reuse_operand: for (read_args, 0..) |read_arg, i| {
                if (read_arg.bind == .inst) {
                    const operand = read_arg.bind.inst;
                    const mcv = try self.resolve_inst(operand);
                    if (mcv == .register and
                        std.meta.eql(arg.class, read_arg.class) and
                        self.reuse_operand(inst, operand, operand_mapping[i], mcv))
                    {
                        const raw_reg = mcv.register;
                        arg.reg.* = self.register_alias(raw_reg, arg.ty);
                        write_locks[0] = null;
                        reused_read_arg = i;
                        break :reuse_operand;
                    }
                }
            } else {
                const raw_reg = try self.register_manager.alloc_reg(inst, arg.class);
                arg.reg.* = self.register_alias(raw_reg, arg.ty);
                write_locks[0] = self.register_manager.lock_reg(arg.reg.*);
            }
        }
    } else {
        for (write_args, 0..) |arg, i| {
            if (arg.bind == .reg) {
                const raw_reg = arg.bind.reg;
                arg.reg.* = self.register_alias(raw_reg, arg.ty);
            } else {
                const raw_reg = try self.register_manager.alloc_reg(null, arg.class);
                arg.reg.* = self.register_alias(raw_reg, arg.ty);
                write_locks[i] = self.register_manager.lock_reg(arg.reg.*);
            }
        }
    }

    // For all read_args which need to be moved from non-register to
    // register, perform the move
    for (read_args, 0..) |arg, i| {
        if (reused_read_arg) |j| {
            // Check whether this read_arg was reused
            if (i == j) continue;
        }

        const mcv = try arg.bind.resolve_to_mcv(self);
        if (mcv != .register) {
            if (arg.bind == .inst) {
                const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
                const inst = arg.bind.inst.to_index().?;

                // Overwrite the MCValue associated with this inst
                branch.inst_table.put_assume_capacity(inst, .{ .register = arg.reg.* });

                // If the previous MCValue occupied some space we track, we
                // need to make sure it is marked as free now.
                switch (mcv) {
                    .compare_flags => {
                        assert(self.compare_flags_inst.? == inst);
                        self.compare_flags_inst = null;
                    },
                    .register => |prev_reg| {
                        assert(!self.register_manager.is_reg_free(prev_reg));
                        self.register_manager.free_reg(prev_reg);
                    },
                    else => {},
                }
            }

            try self.gen_set_reg(arg.ty, arg.reg.*, mcv);
        }
    }
}

/// Wrapper around alloc_regs and add_inst tailored for specific Mir
/// instructions which are binary operations acting on two registers
///
/// Returns the destination register
fn bin_op_register(
    self: *Self,
    mir_tag: Mir.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    var lhs_reg: Register = undefined;
    var rhs_reg: Register = undefined;
    var dest_reg: Register = undefined;

    const read_args = [_]ReadArg{
        .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
        .{ .ty = rhs_ty, .bind = rhs_bind, .class = gp, .reg = &rhs_reg },
    };
    const write_args = [_]WriteArg{
        .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
    };
    try self.alloc_regs(
        &read_args,
        &write_args,
        if (maybe_inst) |inst| .{
            .corresponding_inst = inst,
            .operand_mapping = &.{ 0, 1 },
        } else null,
    );

    const mir_data: Mir.Inst.Data = switch (mir_tag) {
        .add_shifted_register,
        .adds_shifted_register,
        .sub_shifted_register,
        .subs_shifted_register,
        => .{ .rrr_imm6_shift = .{
            .rd = dest_reg,
            .rn = lhs_reg,
            .rm = rhs_reg,
            .imm6 = 0,
            .shift = .lsl,
        } },
        .mul,
        .lsl_register,
        .asr_register,
        .lsr_register,
        .sdiv,
        .udiv,
        => .{ .rrr = .{
            .rd = dest_reg,
            .rn = lhs_reg,
            .rm = rhs_reg,
        } },
        .smull,
        .umull,
        => .{ .rrr = .{
            .rd = dest_reg.to_x(),
            .rn = lhs_reg,
            .rm = rhs_reg,
        } },
        .and_shifted_register,
        .orr_shifted_register,
        .eor_shifted_register,
        => .{ .rrr_imm6_logical_shift = .{
            .rd = dest_reg,
            .rn = lhs_reg,
            .rm = rhs_reg,
            .imm6 = 0,
            .shift = .lsl,
        } },
        else => unreachable,
    };

    _ = try self.add_inst(.{
        .tag = mir_tag,
        .data = mir_data,
    });

    return MCValue{ .register = dest_reg };
}

/// Wrapper around alloc_regs and add_inst tailored for specific Mir
/// instructions which are binary operations acting on a register and
/// an immediate
///
/// Returns the destination register
fn bin_op_immediate(
    self: *Self,
    mir_tag: Mir.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_immediate: u64,
    lhs_ty: Type,
    lhs_and_rhs_swapped: bool,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    var lhs_reg: Register = undefined;
    var dest_reg: Register = undefined;

    const read_args = [_]ReadArg{
        .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
    };
    const write_args = [_]WriteArg{
        .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
    };
    const operand_mapping: []const Liveness.OperandInt = if (lhs_and_rhs_swapped) &.{1} else &.{0};
    try self.alloc_regs(
        &read_args,
        &write_args,
        if (maybe_inst) |inst| .{
            .corresponding_inst = inst,
            .operand_mapping = operand_mapping,
        } else null,
    );

    const mir_data: Mir.Inst.Data = switch (mir_tag) {
        .add_immediate,
        .adds_immediate,
        .sub_immediate,
        .subs_immediate,
        => .{ .rr_imm12_sh = .{
            .rd = dest_reg,
            .rn = lhs_reg,
            .imm12 = @as(u12, @int_cast(rhs_immediate)),
        } },
        .lsl_immediate,
        .asr_immediate,
        .lsr_immediate,
        => .{ .rr_shift = .{
            .rd = dest_reg,
            .rn = lhs_reg,
            .shift = @as(u6, @int_cast(rhs_immediate)),
        } },
        else => unreachable,
    };

    _ = try self.add_inst(.{
        .tag = mir_tag,
        .data = mir_data,
    });

    return MCValue{ .register = dest_reg };
}

fn add_sub(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO binary operations on floats", .{}),
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                const lhs_immediate = try lhs_bind.resolve_to_immediate(self);
                const rhs_immediate = try rhs_bind.resolve_to_immediate(self);

                // Only say yes if the operation is
                // commutative, i.e. we can swap both of the
                // operands
                const lhs_immediate_ok = switch (tag) {
                    .add => if (lhs_immediate) |imm| imm <= std.math.max_int(u12) else false,
                    .sub => false,
                    else => unreachable,
                };
                const rhs_immediate_ok = switch (tag) {
                    .add,
                    .sub,
                    => if (rhs_immediate) |imm| imm <= std.math.max_int(u12) else false,
                    else => unreachable,
                };

                const mir_tag_register: Mir.Inst.Tag = switch (tag) {
                    .add => .add_shifted_register,
                    .sub => .sub_shifted_register,
                    else => unreachable,
                };
                const mir_tag_immediate: Mir.Inst.Tag = switch (tag) {
                    .add => .add_immediate,
                    .sub => .sub_immediate,
                    else => unreachable,
                };

                if (rhs_immediate_ok) {
                    return try self.bin_op_immediate(mir_tag_immediate, lhs_bind, rhs_immediate.?, lhs_ty, false, maybe_inst);
                } else if (lhs_immediate_ok) {
                    // swap lhs and rhs
                    return try self.bin_op_immediate(mir_tag_immediate, rhs_bind, lhs_immediate.?, rhs_ty, true, maybe_inst);
                } else {
                    return try self.bin_op_register(mir_tag_register, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                }
            } else {
                return self.fail("TODO binary operations on int with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn mul(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                // TODO add optimisations for multiplication
                // with immediates, for example a * 2 can be
                // lowered to a << 1
                return try self.bin_op_register(.mul, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
            } else {
                return self.fail("TODO binary operations on int with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn div_float(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    _ = lhs_bind;
    _ = rhs_bind;
    _ = rhs_ty;
    _ = maybe_inst;

    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO div_float", .{}),
        .Vector => return self.fail("TODO div_float on vectors", .{}),
        else => unreachable,
    }
}

fn div_trunc(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO div on floats", .{}),
        .Vector => return self.fail("TODO div on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                switch (int_info.signedness) {
                    .signed => {
                        // TODO optimize integer division by constants
                        return try self.bin_op_register(.sdiv, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                    },
                    .unsigned => {
                        // TODO optimize integer division by constants
                        return try self.bin_op_register(.udiv, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                    },
                }
            } else {
                return self.fail("TODO integer division for ints with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn div_floor(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO div on floats", .{}),
        .Vector => return self.fail("TODO div on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                switch (int_info.signedness) {
                    .signed => {
                        return self.fail("TODO div_floor on signed integers", .{});
                    },
                    .unsigned => {
                        // TODO optimize integer division by constants
                        return try self.bin_op_register(.udiv, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                    },
                }
            } else {
                return self.fail("TODO integer division for ints with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn div_exact(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO div on floats", .{}),
        .Vector => return self.fail("TODO div on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                switch (int_info.signedness) {
                    .signed => {
                        // TODO optimize integer division by constants
                        return try self.bin_op_register(.sdiv, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                    },
                    .unsigned => {
                        // TODO optimize integer division by constants
                        return try self.bin_op_register(.udiv, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
                    },
                }
            } else {
                return self.fail("TODO integer division for ints with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn rem(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    _ = maybe_inst;

    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO rem/mod on floats", .{}),
        .Vector => return self.fail("TODO rem/mod on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                var lhs_reg: Register = undefined;
                var rhs_reg: Register = undefined;
                var quotient_reg: Register = undefined;
                var remainder_reg: Register = undefined;

                const read_args = [_]ReadArg{
                    .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
                    .{ .ty = rhs_ty, .bind = rhs_bind, .class = gp, .reg = &rhs_reg },
                };
                const write_args = [_]WriteArg{
                    .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &quotient_reg },
                    .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &remainder_reg },
                };
                try self.alloc_regs(
                    &read_args,
                    &write_args,
                    null,
                );

                _ = try self.add_inst(.{
                    .tag = switch (int_info.signedness) {
                        .signed => .sdiv,
                        .unsigned => .udiv,
                    },
                    .data = .{ .rrr = .{
                        .rd = quotient_reg,
                        .rn = lhs_reg,
                        .rm = rhs_reg,
                    } },
                });

                _ = try self.add_inst(.{
                    .tag = .msub,
                    .data = .{ .rrrr = .{
                        .rd = remainder_reg,
                        .rn = quotient_reg,
                        .rm = rhs_reg,
                        .ra = lhs_reg,
                    } },
                });

                return MCValue{ .register = remainder_reg };
            } else {
                return self.fail("TODO rem/mod for integers with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn modulo(
    self: *Self,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    _ = lhs_bind;
    _ = rhs_bind;
    _ = rhs_ty;
    _ = maybe_inst;

    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Float => return self.fail("TODO mod on floats", .{}),
        .Vector => return self.fail("TODO mod on vectors", .{}),
        .Int => return self.fail("TODO mod on ints", .{}),
        else => unreachable,
    }
}

fn wrapping_arithmetic(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                // Generate an add/sub/mul
                const result: MCValue = switch (tag) {
                    .add_wrap => try self.add_sub(.add, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst),
                    .sub_wrap => try self.add_sub(.sub, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst),
                    .mul_wrap => try self.mul(lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst),
                    else => unreachable,
                };

                // Truncate if necessary
                const result_reg = result.register;
                try self.trunc_register(result_reg, result_reg, int_info.signedness, int_info.bits);
                return result;
            } else {
                return self.fail("TODO binary operations on integers > u64/i64", .{});
            }
        },
        else => unreachable,
    }
}

fn bitwise(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            assert(lhs_ty.eql(rhs_ty, mod));
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                // TODO implement bitwise operations with immediates
                const mir_tag: Mir.Inst.Tag = switch (tag) {
                    .bit_and => .and_shifted_register,
                    .bit_or => .orr_shifted_register,
                    .xor => .eor_shifted_register,
                    else => unreachable,
                };

                return try self.bin_op_register(mir_tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
            } else {
                return self.fail("TODO binary operations on int with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn shift_exact(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    _ = rhs_ty;

    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                const rhs_immediate = try rhs_bind.resolve_to_immediate(self);

                const mir_tag_register: Mir.Inst.Tag = switch (tag) {
                    .shl_exact => .lsl_register,
                    .shr_exact => switch (int_info.signedness) {
                        .signed => Mir.Inst.Tag.asr_register,
                        .unsigned => Mir.Inst.Tag.lsr_register,
                    },
                    else => unreachable,
                };
                const mir_tag_immediate: Mir.Inst.Tag = switch (tag) {
                    .shl_exact => .lsl_immediate,
                    .shr_exact => switch (int_info.signedness) {
                        .signed => Mir.Inst.Tag.asr_immediate,
                        .unsigned => Mir.Inst.Tag.lsr_immediate,
                    },
                    else => unreachable,
                };

                if (rhs_immediate) |imm| {
                    return try self.bin_op_immediate(mir_tag_immediate, lhs_bind, imm, lhs_ty, false, maybe_inst);
                } else {
                    // We intentionally pass lhs_ty here in order to
                    // prevent using the 32-bit register alias when
                    // lhs_ty is > 32 bits.
                    return try self.bin_op_register(mir_tag_register, lhs_bind, rhs_bind, lhs_ty, lhs_ty, maybe_inst);
                }
            } else {
                return self.fail("TODO binary operations on int with bits > 64", .{});
            }
        },
        else => unreachable,
    }
}

fn shift_normal(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO binary operations on vectors", .{}),
        .Int => {
            const int_info = lhs_ty.int_info(mod);
            if (int_info.bits <= 64) {
                // Generate a shl_exact/shr_exact
                const result: MCValue = switch (tag) {
                    .shl => try self.shift_exact(.shl_exact, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst),
                    .shr => try self.shift_exact(.shr_exact, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst),
                    else => unreachable,
                };

                // Truncate if necessary
                switch (tag) {
                    .shr => return result,
                    .shl => {
                        const result_reg = result.register;
                        try self.trunc_register(result_reg, result_reg, int_info.signedness, int_info.bits);
                        return result;
                    },
                    else => unreachable,
                }
            } else {
                return self.fail("TODO binary operations on integers > u64/i64", .{});
            }
        },
        else => unreachable,
    }
}

fn boolean_op(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Bool => {
            assert((try lhs_bind.resolve_to_immediate(self)) == null); // should have been handled by Sema
            assert((try rhs_bind.resolve_to_immediate(self)) == null); // should have been handled by Sema

            const mir_tag_register: Mir.Inst.Tag = switch (tag) {
                .bool_and => .and_shifted_register,
                .bool_or => .orr_shifted_register,
                else => unreachable,
            };

            return try self.bin_op_register(mir_tag_register, lhs_bind, rhs_bind, lhs_ty, rhs_ty, maybe_inst);
        },
        else => unreachable,
    }
}

fn ptr_arithmetic(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs_bind: ReadArg.Bind,
    rhs_bind: ReadArg.Bind,
    lhs_ty: Type,
    rhs_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (lhs_ty.zig_type_tag(mod)) {
        .Pointer => {
            assert(rhs_ty.eql(Type.usize, mod));

            const ptr_ty = lhs_ty;
            const elem_ty = switch (ptr_ty.ptr_size(mod)) {
                .One => ptr_ty.child_type(mod).child_type(mod), // ptr to array, so get array element type
                else => ptr_ty.child_type(mod),
            };
            const elem_size = elem_ty.abi_size(mod);

            const base_tag: Air.Inst.Tag = switch (tag) {
                .ptr_add => .add,
                .ptr_sub => .sub,
                else => unreachable,
            };

            if (elem_size == 1) {
                return try self.add_sub(base_tag, lhs_bind, rhs_bind, Type.usize, Type.usize, maybe_inst);
            } else {
                // convert the offset into a byte offset by
                // multiplying it with elem_size
                const imm_bind = ReadArg.Bind{ .mcv = .{ .immediate = elem_size } };

                const offset = try self.mul(rhs_bind, imm_bind, Type.usize, Type.usize, null);
                const offset_bind = ReadArg.Bind{ .mcv = offset };

                const addr = try self.add_sub(base_tag, lhs_bind, offset_bind, Type.usize, Type.usize, null);
                return addr;
            }
        },
        else => unreachable,
    }
}

fn air_bin_op(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = bin_op.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = bin_op.rhs };

        break :result switch (tag) {
            .add => try self.add_sub(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .sub => try self.add_sub(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .mul => try self.mul(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .div_float => try self.div_float(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .div_trunc => try self.div_trunc(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .div_floor => try self.div_floor(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .div_exact => try self.div_exact(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .rem => try self.rem(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .mod => try self.modulo(lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .add_wrap => try self.wrapping_arithmetic(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .sub_wrap => try self.wrapping_arithmetic(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .mul_wrap => try self.wrapping_arithmetic(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .bit_and => try self.bitwise(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .bit_or => try self.bitwise(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .xor => try self.bitwise(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .shl_exact => try self.shift_exact(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .shr_exact => try self.shift_exact(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .shl => try self.shift_normal(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .shr => try self.shift_normal(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            .bool_and => try self.boolean_op(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),
            .bool_or => try self.boolean_op(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst),

            else => unreachable,
        };
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_arithmetic(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = bin_op.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = bin_op.rhs };

        break :result try self.ptr_arithmetic(tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, inst);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement add_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_sub_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement sub_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mul_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement mul_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const mod = self.bin_file.comp.module.?;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = extra.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = extra.rhs };
        const lhs_ty = self.type_of(extra.lhs);
        const rhs_ty = self.type_of(extra.rhs);

        const tuple_ty = self.type_of_index(inst);
        const tuple_size = @as(u32, @int_cast(tuple_ty.abi_size(mod)));
        const tuple_align = tuple_ty.abi_alignment(mod);
        const overflow_bit_offset = @as(u32, @int_cast(tuple_ty.struct_field_offset(1, mod)));

        switch (lhs_ty.zig_type_tag(mod)) {
            .Vector => return self.fail("TODO implement add_with_overflow/sub_with_overflow for vectors", .{}),
            .Int => {
                assert(lhs_ty.eql(rhs_ty, mod));
                const int_info = lhs_ty.int_info(mod);
                switch (int_info.bits) {
                    1...31, 33...63 => {
                        const stack_offset = try self.alloc_mem(tuple_size, tuple_align, inst);

                        try self.spill_compare_flags_if_occupied();
                        self.compare_flags_inst = null;

                        const base_tag: Air.Inst.Tag = switch (tag) {
                            .add_with_overflow => .add,
                            .sub_with_overflow => .sub,
                            else => unreachable,
                        };
                        const dest = try self.add_sub(base_tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, null);
                        const dest_reg = dest.register;
                        const dest_reg_lock = self.register_manager.lock_reg_assume_unused(dest_reg);
                        defer self.register_manager.unlock_reg(dest_reg_lock);

                        const raw_truncated_reg = try self.register_manager.alloc_reg(null, gp);
                        const truncated_reg = self.register_alias(raw_truncated_reg, lhs_ty);
                        const truncated_reg_lock = self.register_manager.lock_reg_assume_unused(truncated_reg);
                        defer self.register_manager.unlock_reg(truncated_reg_lock);

                        // sbfx/ubfx truncated, dest, #0, #bits
                        try self.trunc_register(dest_reg, truncated_reg, int_info.signedness, int_info.bits);

                        // cmp dest, truncated
                        _ = try self.add_inst(.{
                            .tag = .cmp_shifted_register,
                            .data = .{ .rr_imm6_shift = .{
                                .rn = dest_reg,
                                .rm = truncated_reg,
                                .imm6 = 0,
                                .shift = .lsl,
                            } },
                        });

                        try self.gen_set_stack(lhs_ty, stack_offset, .{ .register = truncated_reg });
                        try self.gen_set_stack(Type.u1, stack_offset - overflow_bit_offset, .{ .compare_flags = .ne });

                        break :result MCValue{ .stack_offset = stack_offset };
                    },
                    32, 64 => {
                        const lhs_immediate = try lhs_bind.resolve_to_immediate(self);
                        const rhs_immediate = try rhs_bind.resolve_to_immediate(self);

                        // Only say yes if the operation is
                        // commutative, i.e. we can swap both of the
                        // operands
                        const lhs_immediate_ok = switch (tag) {
                            .add_with_overflow => if (lhs_immediate) |imm| imm <= std.math.max_int(u12) else false,
                            .sub_with_overflow => false,
                            else => unreachable,
                        };
                        const rhs_immediate_ok = switch (tag) {
                            .add_with_overflow,
                            .sub_with_overflow,
                            => if (rhs_immediate) |imm| imm <= std.math.max_int(u12) else false,
                            else => unreachable,
                        };

                        const mir_tag_register: Mir.Inst.Tag = switch (tag) {
                            .add_with_overflow => .adds_shifted_register,
                            .sub_with_overflow => .subs_shifted_register,
                            else => unreachable,
                        };
                        const mir_tag_immediate: Mir.Inst.Tag = switch (tag) {
                            .add_with_overflow => .adds_immediate,
                            .sub_with_overflow => .subs_immediate,
                            else => unreachable,
                        };

                        try self.spill_compare_flags_if_occupied();
                        self.compare_flags_inst = inst;

                        const dest = blk: {
                            if (rhs_immediate_ok) {
                                break :blk try self.bin_op_immediate(mir_tag_immediate, lhs_bind, rhs_immediate.?, lhs_ty, false, null);
                            } else if (lhs_immediate_ok) {
                                // swap lhs and rhs
                                break :blk try self.bin_op_immediate(mir_tag_immediate, rhs_bind, lhs_immediate.?, rhs_ty, true, null);
                            } else {
                                break :blk try self.bin_op_register(mir_tag_register, lhs_bind, rhs_bind, lhs_ty, rhs_ty, null);
                            }
                        };

                        const flag: bits.Instruction.Condition = switch (int_info.signedness) {
                            .unsigned => switch (tag) {
                                .add_with_overflow => bits.Instruction.Condition.cs,
                                .sub_with_overflow => bits.Instruction.Condition.cc,
                                else => unreachable,
                            },
                            .signed => .vs,
                        };
                        break :result MCValue{ .register_with_overflow = .{
                            .reg = dest.register,
                            .flag = flag,
                        } };
                    },
                    else => return self.fail("TODO overflow operations on integers > u32/i32", .{}),
                }
            },
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_mul_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    if (self.liveness.is_unused(inst)) return self.finish_air(inst, .dead, .{ extra.lhs, extra.rhs, .none });
    const mod = self.bin_file.comp.module.?;
    const result: MCValue = result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = extra.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = extra.rhs };
        const lhs_ty = self.type_of(extra.lhs);
        const rhs_ty = self.type_of(extra.rhs);

        const tuple_ty = self.type_of_index(inst);
        const tuple_size = @as(u32, @int_cast(tuple_ty.abi_size(mod)));
        const tuple_align = tuple_ty.abi_alignment(mod);
        const overflow_bit_offset = @as(u32, @int_cast(tuple_ty.struct_field_offset(1, mod)));

        switch (lhs_ty.zig_type_tag(mod)) {
            .Vector => return self.fail("TODO implement mul_with_overflow for vectors", .{}),
            .Int => {
                assert(lhs_ty.eql(rhs_ty, mod));
                const int_info = lhs_ty.int_info(mod);
                if (int_info.bits <= 32) {
                    const stack_offset = try self.alloc_mem(tuple_size, tuple_align, inst);

                    try self.spill_compare_flags_if_occupied();

                    const base_tag: Mir.Inst.Tag = switch (int_info.signedness) {
                        .signed => .smull,
                        .unsigned => .umull,
                    };

                    const dest = try self.bin_op_register(base_tag, lhs_bind, rhs_bind, lhs_ty, rhs_ty, null);
                    const dest_reg = dest.register;
                    const dest_reg_lock = self.register_manager.lock_reg_assume_unused(dest_reg);
                    defer self.register_manager.unlock_reg(dest_reg_lock);

                    const truncated_reg = try self.register_manager.alloc_reg(null, gp);
                    const truncated_reg_lock = self.register_manager.lock_reg_assume_unused(truncated_reg);
                    defer self.register_manager.unlock_reg(truncated_reg_lock);

                    try self.trunc_register(
                        dest_reg.to_w(),
                        truncated_reg.to_w(),
                        int_info.signedness,
                        int_info.bits,
                    );

                    switch (int_info.signedness) {
                        .signed => {
                            _ = try self.add_inst(.{
                                .tag = .cmp_extended_register,
                                .data = .{ .rr_extend_shift = .{
                                    .rn = dest_reg.to_x(),
                                    .rm = truncated_reg.to_w(),
                                    .ext_type = .sxtw,
                                    .imm3 = 0,
                                } },
                            });
                        },
                        .unsigned => {
                            _ = try self.add_inst(.{
                                .tag = .cmp_extended_register,
                                .data = .{ .rr_extend_shift = .{
                                    .rn = dest_reg.to_x(),
                                    .rm = truncated_reg.to_w(),
                                    .ext_type = .uxtw,
                                    .imm3 = 0,
                                } },
                            });
                        },
                    }

                    try self.gen_set_stack(lhs_ty, stack_offset, .{ .register = truncated_reg });
                    try self.gen_set_stack(Type.u1, stack_offset - overflow_bit_offset, .{ .compare_flags = .ne });

                    break :result MCValue{ .stack_offset = stack_offset };
                } else if (int_info.bits <= 64) {
                    const stack_offset = try self.alloc_mem(tuple_size, tuple_align, inst);

                    try self.spill_compare_flags_if_occupied();

                    var lhs_reg: Register = undefined;
                    var rhs_reg: Register = undefined;
                    var dest_reg: Register = undefined;
                    var dest_high_reg: Register = undefined;
                    var truncated_reg: Register = undefined;

                    const read_args = [_]ReadArg{
                        .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
                        .{ .ty = rhs_ty, .bind = rhs_bind, .class = gp, .reg = &rhs_reg },
                    };
                    const write_args = [_]WriteArg{
                        .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
                        .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_high_reg },
                        .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &truncated_reg },
                    };
                    try self.alloc_regs(
                        &read_args,
                        &write_args,
                        null,
                    );

                    switch (int_info.signedness) {
                        .signed => {
                            // mul dest, lhs, rhs
                            _ = try self.add_inst(.{
                                .tag = .mul,
                                .data = .{ .rrr = .{
                                    .rd = dest_reg,
                                    .rn = lhs_reg,
                                    .rm = rhs_reg,
                                } },
                            });

                            // smulh dest_high, lhs, rhs
                            _ = try self.add_inst(.{
                                .tag = .smulh,
                                .data = .{ .rrr = .{
                                    .rd = dest_high_reg,
                                    .rn = lhs_reg,
                                    .rm = rhs_reg,
                                } },
                            });

                            // cmp dest_high, dest, asr #63
                            _ = try self.add_inst(.{
                                .tag = .cmp_shifted_register,
                                .data = .{ .rr_imm6_shift = .{
                                    .rn = dest_high_reg,
                                    .rm = dest_reg,
                                    .imm6 = 63,
                                    .shift = .asr,
                                } },
                            });

                            const shift: u6 = @as(u6, @int_cast(@as(u7, 64) - @as(u7, @int_cast(int_info.bits))));
                            if (shift > 0) {
                                // lsl dest_high, dest, #shift
                                _ = try self.add_inst(.{
                                    .tag = .lsl_immediate,
                                    .data = .{ .rr_shift = .{
                                        .rd = dest_high_reg,
                                        .rn = dest_reg,
                                        .shift = shift,
                                    } },
                                });

                                // cmp dest, dest_high, #shift
                                _ = try self.add_inst(.{
                                    .tag = .cmp_shifted_register,
                                    .data = .{ .rr_imm6_shift = .{
                                        .rn = dest_reg,
                                        .rm = dest_high_reg,
                                        .imm6 = shift,
                                        .shift = .asr,
                                    } },
                                });
                            }
                        },
                        .unsigned => {
                            // umulh dest_high, lhs, rhs
                            _ = try self.add_inst(.{
                                .tag = .umulh,
                                .data = .{ .rrr = .{
                                    .rd = dest_high_reg,
                                    .rn = lhs_reg,
                                    .rm = rhs_reg,
                                } },
                            });

                            // mul dest, lhs, rhs
                            _ = try self.add_inst(.{
                                .tag = .mul,
                                .data = .{ .rrr = .{
                                    .rd = dest_reg,
                                    .rn = lhs_reg,
                                    .rm = rhs_reg,
                                } },
                            });

                            _ = try self.add_inst(.{
                                .tag = .cmp_immediate,
                                .data = .{ .r_imm12_sh = .{
                                    .rn = dest_high_reg,
                                    .imm12 = 0,
                                } },
                            });

                            if (int_info.bits < 64) {
                                // lsr dest_high, dest, #shift
                                _ = try self.add_inst(.{
                                    .tag = .lsr_immediate,
                                    .data = .{ .rr_shift = .{
                                        .rd = dest_high_reg,
                                        .rn = dest_reg,
                                        .shift = @as(u6, @int_cast(int_info.bits)),
                                    } },
                                });

                                _ = try self.add_inst(.{
                                    .tag = .cmp_immediate,
                                    .data = .{ .r_imm12_sh = .{
                                        .rn = dest_high_reg,
                                        .imm12 = 0,
                                    } },
                                });
                            }
                        },
                    }

                    try self.trunc_register(dest_reg, truncated_reg, int_info.signedness, int_info.bits);

                    try self.gen_set_stack(lhs_ty, stack_offset, .{ .register = truncated_reg });
                    try self.gen_set_stack(Type.u1, stack_offset - overflow_bit_offset, .{ .compare_flags = .ne });

                    break :result MCValue{ .stack_offset = stack_offset };
                } else return self.fail("TODO implement mul_with_overflow for integers > u64/i64", .{});
            },
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_shl_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    if (self.liveness.is_unused(inst)) return self.finish_air(inst, .dead, .{ extra.lhs, extra.rhs, .none });
    const mod = self.bin_file.comp.module.?;
    const result: MCValue = result: {
        const lhs_bind: ReadArg.Bind = .{ .inst = extra.lhs };
        const rhs_bind: ReadArg.Bind = .{ .inst = extra.rhs };
        const lhs_ty = self.type_of(extra.lhs);
        const rhs_ty = self.type_of(extra.rhs);

        const tuple_ty = self.type_of_index(inst);
        const tuple_size = @as(u32, @int_cast(tuple_ty.abi_size(mod)));
        const tuple_align = tuple_ty.abi_alignment(mod);
        const overflow_bit_offset = @as(u32, @int_cast(tuple_ty.struct_field_offset(1, mod)));

        switch (lhs_ty.zig_type_tag(mod)) {
            .Vector => return self.fail("TODO implement shl_with_overflow for vectors", .{}),
            .Int => {
                const int_info = lhs_ty.int_info(mod);
                if (int_info.bits <= 64) {
                    const stack_offset = try self.alloc_mem(tuple_size, tuple_align, inst);

                    try self.spill_compare_flags_if_occupied();

                    var lhs_reg: Register = undefined;
                    var rhs_reg: Register = undefined;
                    var dest_reg: Register = undefined;
                    var reconstructed_reg: Register = undefined;

                    const rhs_immediate = try rhs_bind.resolve_to_immediate(self);
                    if (rhs_immediate) |imm| {
                        const read_args = [_]ReadArg{
                            .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
                        };
                        const write_args = [_]WriteArg{
                            .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
                            .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &reconstructed_reg },
                        };
                        try self.alloc_regs(
                            &read_args,
                            &write_args,
                            null,
                        );

                        // lsl dest, lhs, rhs
                        _ = try self.add_inst(.{
                            .tag = .lsl_immediate,
                            .data = .{ .rr_shift = .{
                                .rd = dest_reg,
                                .rn = lhs_reg,
                                .shift = @as(u6, @int_cast(imm)),
                            } },
                        });

                        try self.trunc_register(dest_reg, dest_reg, int_info.signedness, int_info.bits);

                        // asr/lsr reconstructed, dest, rhs
                        _ = try self.add_inst(.{
                            .tag = switch (int_info.signedness) {
                                .signed => Mir.Inst.Tag.asr_immediate,
                                .unsigned => Mir.Inst.Tag.lsr_immediate,
                            },
                            .data = .{ .rr_shift = .{
                                .rd = reconstructed_reg,
                                .rn = dest_reg,
                                .shift = @as(u6, @int_cast(imm)),
                            } },
                        });
                    } else {
                        const read_args = [_]ReadArg{
                            .{ .ty = lhs_ty, .bind = lhs_bind, .class = gp, .reg = &lhs_reg },
                            .{ .ty = rhs_ty, .bind = rhs_bind, .class = gp, .reg = &rhs_reg },
                        };
                        const write_args = [_]WriteArg{
                            .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &dest_reg },
                            .{ .ty = lhs_ty, .bind = .none, .class = gp, .reg = &reconstructed_reg },
                        };
                        try self.alloc_regs(
                            &read_args,
                            &write_args,
                            null,
                        );

                        // lsl dest, lhs, rhs
                        _ = try self.add_inst(.{
                            .tag = .lsl_register,
                            .data = .{ .rrr = .{
                                .rd = dest_reg,
                                .rn = lhs_reg,
                                .rm = rhs_reg,
                            } },
                        });

                        try self.trunc_register(dest_reg, dest_reg, int_info.signedness, int_info.bits);

                        // asr/lsr reconstructed, dest, rhs
                        _ = try self.add_inst(.{
                            .tag = switch (int_info.signedness) {
                                .signed => Mir.Inst.Tag.asr_register,
                                .unsigned => Mir.Inst.Tag.lsr_register,
                            },
                            .data = .{ .rrr = .{
                                .rd = reconstructed_reg,
                                .rn = dest_reg,
                                .rm = rhs_reg,
                            } },
                        });
                    }

                    // cmp lhs, reconstructed
                    _ = try self.add_inst(.{
                        .tag = .cmp_shifted_register,
                        .data = .{ .rr_imm6_shift = .{
                            .rn = lhs_reg,
                            .rm = reconstructed_reg,
                            .imm6 = 0,
                            .shift = .lsl,
                        } },
                    });

                    try self.gen_set_stack(lhs_ty, stack_offset, .{ .register = dest_reg });
                    try self.gen_set_stack(Type.u1, stack_offset - overflow_bit_offset, .{ .compare_flags = .ne });

                    break :result MCValue{ .stack_offset = stack_offset };
                } else {
                    return self.fail("TODO ARM overflow operations on integers > u32/i32", .{});
                }
            },
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_shl_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement shl_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_optional_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const optional_ty = self.type_of(ty_op.operand);
        const mcv = try self.resolve_inst(ty_op.operand);
        break :result try self.optional_payload(inst, mcv, optional_ty);
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn optional_payload(self: *Self, inst: Air.Inst.Index, mcv: MCValue, optional_ty: Type) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const payload_ty = optional_ty.optional_child(mod);
    if (!payload_ty.has_runtime_bits(mod)) return MCValue.none;
    if (optional_ty.is_ptr_like_optional(mod)) {
        // TODO should we reuse the operand here?
        const raw_reg = try self.register_manager.alloc_reg(inst, gp);
        const reg = self.register_alias(raw_reg, payload_ty);
        try self.gen_set_reg(payload_ty, reg, mcv);
        return MCValue{ .register = reg };
    }

    switch (mcv) {
        .register => {
            // TODO should we reuse the operand here?
            const raw_reg = try self.register_manager.alloc_reg(inst, gp);
            const dest_reg = raw_reg.to_x();

            try self.gen_set_reg(payload_ty, dest_reg, mcv);
            return MCValue{ .register = self.register_alias(dest_reg, payload_ty) };
        },
        .stack_argument_offset, .stack_offset, .memory => return mcv,
        else => unreachable, // invalid MCValue for an error union
    }
}

fn air_optional_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement .optional_payload_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_optional_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement .optional_payload_ptr_set for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// Given an error union, returns the error
fn err_union_err(
    self: *Self,
    error_union_bind: ReadArg.Bind,
    error_union_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const err_ty = error_union_ty.error_union_set(mod);
    const payload_ty = error_union_ty.error_union_payload(mod);
    if (err_ty.error_set_is_empty(mod)) {
        return MCValue{ .immediate = 0 };
    }
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return try error_union_bind.resolve_to_mcv(self);
    }

    const err_offset = @as(u32, @int_cast(err_union_error_offset(payload_ty, mod)));
    switch (try error_union_bind.resolve_to_mcv(self)) {
        .register => {
            var operand_reg: Register = undefined;
            var dest_reg: Register = undefined;

            const read_args = [_]ReadArg{
                .{ .ty = error_union_ty, .bind = error_union_bind, .class = gp, .reg = &operand_reg },
            };
            const write_args = [_]WriteArg{
                .{ .ty = err_ty, .bind = .none, .class = gp, .reg = &dest_reg },
            };
            try self.alloc_regs(
                &read_args,
                &write_args,
                if (maybe_inst) |inst| .{
                    .corresponding_inst = inst,
                    .operand_mapping = &.{0},
                } else null,
            );

            const err_bit_offset = err_offset * 8;
            const err_bit_size = @as(u32, @int_cast(err_ty.abi_size(mod))) * 8;

            _ = try self.add_inst(.{
                .tag = .ubfx, // errors are unsigned integers
                .data = .{
                    .rr_lsb_width = .{
                        // Set both registers to the X variant to get the full width
                        .rd = dest_reg.to_x(),
                        .rn = operand_reg.to_x(),
                        .lsb = @as(u6, @int_cast(err_bit_offset)),
                        .width = @as(u7, @int_cast(err_bit_size)),
                    },
                },
            });

            return MCValue{ .register = dest_reg };
        },
        .stack_argument_offset => |off| {
            return MCValue{ .stack_argument_offset = off + err_offset };
        },
        .stack_offset => |off| {
            return MCValue{ .stack_offset = off - err_offset };
        },
        .memory => |addr| {
            return MCValue{ .memory = addr + err_offset };
        },
        else => unreachable, // invalid MCValue for an error union
    }
}

fn air_unwrap_err_err(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const error_union_bind: ReadArg.Bind = .{ .inst = ty_op.operand };
        const error_union_ty = self.type_of(ty_op.operand);

        break :result try self.err_union_err(error_union_bind, error_union_ty, inst);
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// Given an error union, returns the payload
fn err_union_payload(
    self: *Self,
    error_union_bind: ReadArg.Bind,
    error_union_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const err_ty = error_union_ty.error_union_set(mod);
    const payload_ty = error_union_ty.error_union_payload(mod);
    if (err_ty.error_set_is_empty(mod)) {
        return try error_union_bind.resolve_to_mcv(self);
    }
    if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
        return MCValue.none;
    }

    const payload_offset = @as(u32, @int_cast(err_union_payload_offset(payload_ty, mod)));
    switch (try error_union_bind.resolve_to_mcv(self)) {
        .register => {
            var operand_reg: Register = undefined;
            var dest_reg: Register = undefined;

            const read_args = [_]ReadArg{
                .{ .ty = error_union_ty, .bind = error_union_bind, .class = gp, .reg = &operand_reg },
            };
            const write_args = [_]WriteArg{
                .{ .ty = err_ty, .bind = .none, .class = gp, .reg = &dest_reg },
            };
            try self.alloc_regs(
                &read_args,
                &write_args,
                if (maybe_inst) |inst| .{
                    .corresponding_inst = inst,
                    .operand_mapping = &.{0},
                } else null,
            );

            const payload_bit_offset = payload_offset * 8;
            const payload_bit_size = @as(u32, @int_cast(payload_ty.abi_size(mod))) * 8;

            _ = try self.add_inst(.{
                .tag = if (payload_ty.is_signed_int(mod)) Mir.Inst.Tag.sbfx else .ubfx,
                .data = .{
                    .rr_lsb_width = .{
                        // Set both registers to the X variant to get the full width
                        .rd = dest_reg.to_x(),
                        .rn = operand_reg.to_x(),
                        .lsb = @as(u5, @int_cast(payload_bit_offset)),
                        .width = @as(u6, @int_cast(payload_bit_size)),
                    },
                },
            });

            return MCValue{ .register = dest_reg };
        },
        .stack_argument_offset => |off| {
            return MCValue{ .stack_argument_offset = off + payload_offset };
        },
        .stack_offset => |off| {
            return MCValue{ .stack_offset = off - payload_offset };
        },
        .memory => |addr| {
            return MCValue{ .memory = addr + payload_offset };
        },
        else => unreachable, // invalid MCValue for an error union
    }
}

fn air_unwrap_err_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const error_union_bind: ReadArg.Bind = .{ .inst = ty_op.operand };
        const error_union_ty = self.type_of(ty_op.operand);

        break :result try self.err_union_payload(error_union_bind, error_union_ty, inst);
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

// *(E!T) -> E
fn air_unwrap_err_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement unwrap error union error ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

// *(E!T) -> *T
fn air_unwrap_err_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement unwrap error union payload ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_err_union_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement .errunion_payload_ptr_set for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_err_return_trace(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = if (self.liveness.is_unused(inst))
        .dead
    else
        return self.fail("TODO implement air_err_return_trace for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_set_err_return_trace(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_set_err_return_trace for {}", .{self.target.cpu.arch});
}

fn air_save_err_return_trace_index(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_save_err_return_trace_index for {}", .{self.target.cpu.arch});
}

fn air_wrap_optional(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    if (self.liveness.is_unused(inst)) {
        return self.finish_air(inst, .dead, .{ ty_op.operand, .none, .none });
    }

    const result: MCValue = result: {
        const payload_ty = self.type_of(ty_op.operand);
        if (!payload_ty.has_runtime_bits(mod)) {
            break :result MCValue{ .immediate = 1 };
        }

        const optional_ty = self.type_of_index(inst);
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_lock: ?RegisterLock = switch (operand) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (operand_lock) |lock| self.register_manager.unlock_reg(lock);

        if (optional_ty.is_ptr_like_optional(mod)) {
            // TODO should we check if we can reuse the operand?
            const raw_reg = try self.register_manager.alloc_reg(inst, gp);
            const reg = self.register_alias(raw_reg, payload_ty);
            try self.gen_set_reg(payload_ty, raw_reg, operand);
            break :result MCValue{ .register = reg };
        }

        const optional_abi_size: u32 = @int_cast(optional_ty.abi_size(mod));
        const optional_abi_align = optional_ty.abi_alignment(mod);
        const offset: u32 = @int_cast(payload_ty.abi_size(mod));

        const stack_offset = try self.alloc_mem(optional_abi_size, optional_abi_align, inst);
        try self.gen_set_stack(payload_ty, stack_offset, operand);
        try self.gen_set_stack(Type.bool, stack_offset - offset, .{ .immediate = 1 });

        break :result MCValue{ .stack_offset = stack_offset };
    };

    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// T to E!T
fn air_wrap_err_union_payload(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const error_union_ty = ty_op.ty.to_type();
        const error_ty = error_union_ty.error_union_set(mod);
        const payload_ty = error_union_ty.error_union_payload(mod);
        const operand = try self.resolve_inst(ty_op.operand);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) break :result operand;

        const abi_size = @as(u32, @int_cast(error_union_ty.abi_size(mod)));
        const abi_align = error_union_ty.abi_alignment(mod);
        const stack_offset = try self.alloc_mem(abi_size, abi_align, inst);
        const payload_off = err_union_payload_offset(payload_ty, mod);
        const err_off = err_union_error_offset(payload_ty, mod);
        try self.gen_set_stack(payload_ty, stack_offset - @as(u32, @int_cast(payload_off)), operand);
        try self.gen_set_stack(error_ty, stack_offset - @as(u32, @int_cast(err_off)), .{ .immediate = 0 });

        break :result MCValue{ .stack_offset = stack_offset };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// E to E!T
fn air_wrap_err_union_err(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const mod = self.bin_file.comp.module.?;
        const error_union_ty = ty_op.ty.to_type();
        const error_ty = error_union_ty.error_union_set(mod);
        const payload_ty = error_union_ty.error_union_payload(mod);
        const operand = try self.resolve_inst(ty_op.operand);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) break :result operand;

        const abi_size = @as(u32, @int_cast(error_union_ty.abi_size(mod)));
        const abi_align = error_union_ty.abi_alignment(mod);
        const stack_offset = try self.alloc_mem(abi_size, abi_align, inst);
        const payload_off = err_union_payload_offset(payload_ty, mod);
        const err_off = err_union_error_offset(payload_ty, mod);
        try self.gen_set_stack(error_ty, stack_offset - @as(u32, @int_cast(err_off)), operand);
        try self.gen_set_stack(payload_ty, stack_offset - @as(u32, @int_cast(payload_off)), .undef);

        break :result MCValue{ .stack_offset = stack_offset };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn slice_ptr(mcv: MCValue) MCValue {
    switch (mcv) {
        .dead, .unreach, .none => unreachable,
        .register => unreachable, // a slice doesn't fit in one register
        .stack_argument_offset => |off| {
            return MCValue{ .stack_argument_offset = off };
        },
        .stack_offset => |off| {
            return MCValue{ .stack_offset = off };
        },
        .memory => |addr| {
            return MCValue{ .memory = addr };
        },
        else => unreachable, // invalid MCValue for a slice
    }
}

fn air_slice_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const mcv = try self.resolve_inst(ty_op.operand);
        break :result slice_ptr(mcv);
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_len(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const ptr_bits = 64;
        const ptr_bytes = @div_exact(ptr_bits, 8);
        const mcv = try self.resolve_inst(ty_op.operand);
        switch (mcv) {
            .dead, .unreach, .none => unreachable,
            .register => unreachable, // a slice doesn't fit in one register
            .stack_argument_offset => |off| {
                break :result MCValue{ .stack_argument_offset = off + ptr_bytes };
            },
            .stack_offset => |off| {
                break :result MCValue{ .stack_offset = off - ptr_bytes };
            },
            .memory => |addr| {
                break :result MCValue{ .memory = addr + ptr_bytes };
            },
            else => return self.fail("TODO implement slice_len for {}", .{mcv}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_len_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const ptr_bits = 64;
        const ptr_bytes = @div_exact(ptr_bits, 8);
        const mcv = try self.resolve_inst(ty_op.operand);
        switch (mcv) {
            .dead, .unreach, .none => unreachable,
            .ptr_stack_offset => |off| {
                break :result MCValue{ .ptr_stack_offset = off - ptr_bytes };
            },
            else => return self.fail("TODO implement ptr_slice_len_ptr for {}", .{mcv}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_ptr_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const mcv = try self.resolve_inst(ty_op.operand);
        switch (mcv) {
            .dead, .unreach, .none => unreachable,
            .ptr_stack_offset => |off| {
                break :result MCValue{ .ptr_stack_offset = off };
            },
            else => return self.fail("TODO implement ptr_slice_len_ptr for {}", .{mcv}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const slice_ty = self.type_of(bin_op.lhs);
    const result: MCValue = if (!slice_ty.is_volatile_ptr(mod) and self.liveness.is_unused(inst)) .dead else result: {
        const ptr_ty = slice_ty.slice_ptr_field_type(mod);

        const slice_mcv = try self.resolve_inst(bin_op.lhs);
        const base_mcv = slice_ptr(slice_mcv);

        const base_bind: ReadArg.Bind = .{ .mcv = base_mcv };
        const index_bind: ReadArg.Bind = .{ .inst = bin_op.rhs };

        break :result try self.ptr_elem_val(base_bind, index_bind, ptr_ty, inst);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn ptr_elem_val(
    self: *Self,
    ptr_bind: ReadArg.Bind,
    index_bind: ReadArg.Bind,
    ptr_ty: Type,
    maybe_inst: ?Air.Inst.Index,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const elem_ty = ptr_ty.child_type(mod);
    const elem_size = @as(u32, @int_cast(elem_ty.abi_size(mod)));

    // TODO optimize for elem_sizes of 1, 2, 4, 8
    switch (elem_size) {
        else => {
            const addr = try self.ptr_arithmetic(.ptr_add, ptr_bind, index_bind, ptr_ty, Type.usize, null);

            const dest = try self.alloc_reg_or_mem(elem_ty, true, maybe_inst);
            try self.load(dest, addr, ptr_ty);
            return dest;
        },
    }
}

fn air_slice_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const slice_mcv = try self.resolve_inst(extra.lhs);
        const base_mcv = slice_ptr(slice_mcv);

        const base_bind: ReadArg.Bind = .{ .mcv = base_mcv };
        const index_bind: ReadArg.Bind = .{ .inst = extra.rhs };

        const slice_ty = self.type_of(extra.lhs);
        const index_ty = self.type_of(extra.rhs);

        const addr = try self.ptr_arithmetic(.ptr_add, base_bind, index_bind, slice_ty, index_ty, null);
        break :result addr;
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_array_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement array_elem_val for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ptr_ty = self.type_of(bin_op.lhs);
    const result: MCValue = if (!ptr_ty.is_volatile_ptr(mod) and self.liveness.is_unused(inst)) .dead else result: {
        const base_bind: ReadArg.Bind = .{ .inst = bin_op.lhs };
        const index_bind: ReadArg.Bind = .{ .inst = bin_op.rhs };

        break :result try self.ptr_elem_val(base_bind, index_bind, ptr_ty, inst);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const ptr_bind: ReadArg.Bind = .{ .inst = extra.lhs };
        const index_bind: ReadArg.Bind = .{ .inst = extra.rhs };

        const ptr_ty = self.type_of(extra.lhs);
        const index_ty = self.type_of(extra.rhs);

        const addr = try self.ptr_arithmetic(.ptr_add, ptr_bind, index_bind, ptr_ty, index_ty, null);
        break :result addr;
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_set_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    _ = bin_op;
    return self.fail("TODO implement air_set_union_tag for {}", .{self.target.cpu.arch});
}

fn air_get_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_get_union_tag for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_clz(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_clz for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ctz(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_ctz for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_popcount(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_popcount for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_abs(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_abs for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_byte_swap(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_byte_swap for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_bit_reverse(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_bit_reverse for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unary_math(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst))
        .dead
    else
        return self.fail("TODO implement air_unary_math for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn reuse_operand(
    self: *Self,
    inst: Air.Inst.Index,
    operand: Air.Inst.Ref,
    op_index: Liveness.OperandInt,
    mcv: MCValue,
) bool {
    if (!self.liveness.operand_dies(inst, op_index))
        return false;

    switch (mcv) {
        .register => |reg| {
            // If it's in the registers table, need to associate the register with the
            // new instruction.
            if (RegisterManager.index_of_reg_into_tracked(reg)) |index| {
                if (!self.register_manager.is_reg_free(reg)) {
                    self.register_manager.registers[index] = inst;
                }
            }
            log.debug("%{d} => {} (reused)", .{ inst, reg });
        },
        .stack_offset => |off| {
            log.debug("%{d} => stack offset {d} (reused)", .{ inst, off });
        },
        else => return false,
    }

    // Prevent the operand deaths processing code from deallocating it.
    self.liveness.clear_operand_death(inst, op_index);

    // That makes us responsible for doing the rest of the stuff that process_death would have done.
    const branch = &self.branch_stack.items[self.branch_stack.items.len - 1];
    branch.inst_table.put_assume_capacity(operand.to_index().?, .dead);

    return true;
}

fn load(self: *Self, dst_mcv: MCValue, ptr: MCValue, ptr_ty: Type) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const elem_ty = ptr_ty.child_type(mod);
    const elem_size = elem_ty.abi_size(mod);

    switch (ptr) {
        .none => unreachable,
        .undef => unreachable,
        .unreach => unreachable,
        .dead => unreachable,
        .compare_flags,
        .register_with_overflow,
        => unreachable, // cannot hold an address
        .immediate => |imm| try self.set_reg_or_mem(elem_ty, dst_mcv, .{ .memory = imm }),
        .ptr_stack_offset => |off| try self.set_reg_or_mem(elem_ty, dst_mcv, .{ .stack_offset = off }),
        .register => |addr_reg| {
            const addr_reg_lock = self.register_manager.lock_reg(addr_reg);
            defer if (addr_reg_lock) |reg| self.register_manager.unlock_reg(reg);

            switch (dst_mcv) {
                .dead => unreachable,
                .undef => unreachable,
                .compare_flags => unreachable,
                .register => |dst_reg| {
                    try self.gen_ldr_register(dst_reg, addr_reg, elem_ty);
                },
                .stack_offset => |off| {
                    if (elem_size <= 8) {
                        const raw_tmp_reg = try self.register_manager.alloc_reg(null, gp);
                        const tmp_reg = self.register_alias(raw_tmp_reg, elem_ty);
                        const tmp_reg_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                        defer self.register_manager.unlock_reg(tmp_reg_lock);

                        try self.load(.{ .register = tmp_reg }, ptr, ptr_ty);
                        try self.gen_set_stack(elem_ty, off, MCValue{ .register = tmp_reg });
                    } else {
                        // TODO optimize the register allocation
                        const regs = try self.register_manager.alloc_regs(4, .{ null, null, null, null }, gp);
                        const regs_locks = self.register_manager.lock_regs_assume_unused(4, regs);
                        defer for (regs_locks) |reg| {
                            self.register_manager.unlock_reg(reg);
                        };

                        const src_reg = addr_reg;
                        const dst_reg = regs[0];
                        const len_reg = regs[1];
                        const count_reg = regs[2];
                        const tmp_reg = regs[3];

                        // sub dst_reg, fp, #off
                        try self.gen_set_reg(ptr_ty, dst_reg, .{ .ptr_stack_offset = off });

                        // mov len, #elem_size
                        try self.gen_set_reg(Type.usize, len_reg, .{ .immediate = elem_size });

                        // memcpy(src, dst, len)
                        try self.gen_inline_memcpy(src_reg, dst_reg, len_reg, count_reg, tmp_reg);
                    }
                },
                else => return self.fail("TODO load from register into {}", .{dst_mcv}),
            }
        },
        .memory,
        .stack_offset,
        .stack_argument_offset,
        .linker_load,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr);
            try self.load(dst_mcv, .{ .register = addr_reg }, ptr_ty);
        },
    }
}

fn gen_inline_memcpy(
    self: *Self,
    src: Register,
    dst: Register,
    len: Register,
    count: Register,
    tmp: Register,
) !void {
    // movz count, #0
    _ = try self.add_inst(.{
        .tag = .movz,
        .data = .{ .r_imm16_sh = .{
            .rd = count,
            .imm16 = 0,
        } },
    });

    // loop:
    // cmp count, len
    _ = try self.add_inst(.{
        .tag = .cmp_shifted_register,
        .data = .{ .rr_imm6_shift = .{
            .rn = count,
            .rm = len,
            .imm6 = 0,
            .shift = .lsl,
        } },
    });

    // bge end
    _ = try self.add_inst(.{
        .tag = .b_cond,
        .data = .{ .inst_cond = .{
            .inst = @as(u32, @int_cast(self.mir_instructions.len + 5)),
            .cond = .ge,
        } },
    });

    // ldrb tmp, [src, count]
    _ = try self.add_inst(.{
        .tag = .ldrb_register,
        .data = .{ .load_store_register_register = .{
            .rt = tmp,
            .rn = src,
            .offset = Instruction.LoadStoreOffset.reg(count).register,
        } },
    });

    // strb tmp, [dest, count]
    _ = try self.add_inst(.{
        .tag = .strb_register,
        .data = .{ .load_store_register_register = .{
            .rt = tmp,
            .rn = dst,
            .offset = Instruction.LoadStoreOffset.reg(count).register,
        } },
    });

    // add count, count, #1
    _ = try self.add_inst(.{
        .tag = .add_immediate,
        .data = .{ .rr_imm12_sh = .{
            .rd = count,
            .rn = count,
            .imm12 = 1,
        } },
    });

    // b loop
    _ = try self.add_inst(.{
        .tag = .b,
        .data = .{ .inst = @as(u32, @int_cast(self.mir_instructions.len - 5)) },
    });

    // end:
}

fn gen_inline_memset(
    self: *Self,
    dst: MCValue,
    val: MCValue,
    len: MCValue,
) !void {
    const dst_reg = switch (dst) {
        .register => |r| r,
        else => try self.copy_to_tmp_register(Type.manyptr_u8, dst),
    };
    const dst_reg_lock = self.register_manager.lock_reg(dst_reg);
    defer if (dst_reg_lock) |lock| self.register_manager.unlock_reg(lock);

    const val_reg = switch (val) {
        .register => |r| r,
        else => try self.copy_to_tmp_register(Type.u8, val),
    };
    const val_reg_lock = self.register_manager.lock_reg(val_reg);
    defer if (val_reg_lock) |lock| self.register_manager.unlock_reg(lock);

    const len_reg = switch (len) {
        .register => |r| r,
        else => try self.copy_to_tmp_register(Type.usize, len),
    };
    const len_reg_lock = self.register_manager.lock_reg(len_reg);
    defer if (len_reg_lock) |lock| self.register_manager.unlock_reg(lock);

    const count_reg = try self.register_manager.alloc_reg(null, gp);

    try self.gen_inline_memset_code(dst_reg, val_reg, len_reg, count_reg);
}

fn gen_inline_memset_code(
    self: *Self,
    dst: Register,
    val: Register,
    len: Register,
    count: Register,
) !void {
    // mov count, #0
    _ = try self.add_inst(.{
        .tag = .movz,
        .data = .{ .r_imm16_sh = .{
            .rd = count,
            .imm16 = 0,
        } },
    });

    // loop:
    // cmp count, len
    _ = try self.add_inst(.{
        .tag = .cmp_shifted_register,
        .data = .{ .rr_imm6_shift = .{
            .rn = count,
            .rm = len,
            .imm6 = 0,
            .shift = .lsl,
        } },
    });

    // bge end
    _ = try self.add_inst(.{
        .tag = .b_cond,
        .data = .{ .inst_cond = .{
            .inst = @as(u32, @int_cast(self.mir_instructions.len + 4)),
            .cond = .ge,
        } },
    });

    // strb val, [src, count]
    _ = try self.add_inst(.{
        .tag = .strb_register,
        .data = .{ .load_store_register_register = .{
            .rt = val,
            .rn = dst,
            .offset = Instruction.LoadStoreOffset.reg(count).register,
        } },
    });

    // add count, count, #1
    _ = try self.add_inst(.{
        .tag = .add_immediate,
        .data = .{ .rr_imm12_sh = .{
            .rd = count,
            .rn = count,
            .imm12 = 1,
        } },
    });

    // b loop
    _ = try self.add_inst(.{
        .tag = .b,
        .data = .{ .inst = @as(u32, @int_cast(self.mir_instructions.len - 4)) },
    });

    // end:
}

fn air_load(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const elem_ty = self.type_of_index(inst);
    const elem_size = elem_ty.abi_size(mod);
    const result: MCValue = result: {
        if (!elem_ty.has_runtime_bits(mod))
            break :result MCValue.none;

        const ptr = try self.resolve_inst(ty_op.operand);
        const is_volatile = self.type_of(ty_op.operand).is_volatile_ptr(mod);
        if (self.liveness.is_unused(inst) and !is_volatile)
            break :result MCValue.dead;

        const dst_mcv: MCValue = blk: {
            if (elem_size <= 8 and self.reuse_operand(inst, ty_op.operand, 0, ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk switch (ptr) {
                    .register => |reg| MCValue{ .register = self.register_alias(reg, elem_ty) },
                    else => ptr,
                };
            } else {
                break :blk try self.alloc_reg_or_mem(elem_ty, true, inst);
            }
        };
        try self.load(dst_mcv, ptr, self.type_of(ty_op.operand));
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn gen_ldr_register(self: *Self, value_reg: Register, addr_reg: Register, ty: Type) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size = ty.abi_size(mod);

    const tag: Mir.Inst.Tag = switch (abi_size) {
        1 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsb_immediate else .ldrb_immediate,
        2 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsh_immediate else .ldrh_immediate,
        4 => .ldr_immediate,
        8 => .ldr_immediate,
        3, 5, 6, 7 => return self.fail("TODO: gen_ldr_register for more abi_sizes", .{}),
        else => unreachable,
    };

    _ = try self.add_inst(.{
        .tag = tag,
        .data = .{ .load_store_register_immediate = .{
            .rt = value_reg,
            .rn = addr_reg,
            .offset = Instruction.LoadStoreOffset.none.immediate,
        } },
    });
}

fn gen_str_register(self: *Self, value_reg: Register, addr_reg: Register, ty: Type) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size = ty.abi_size(mod);

    const tag: Mir.Inst.Tag = switch (abi_size) {
        1 => .strb_immediate,
        2 => .strh_immediate,
        4, 8 => .str_immediate,
        3, 5, 6, 7 => return self.fail("TODO: gen_str_register for more abi_sizes", .{}),
        else => unreachable,
    };

    _ = try self.add_inst(.{
        .tag = tag,
        .data = .{ .load_store_register_immediate = .{
            .rt = value_reg,
            .rn = addr_reg,
            .offset = Instruction.LoadStoreOffset.none.immediate,
        } },
    });
}

fn store(self: *Self, ptr: MCValue, value: MCValue, ptr_ty: Type, value_ty: Type) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    log.debug("store: storing {} to {}", .{ value, ptr });
    const abi_size = value_ty.abi_size(mod);

    switch (ptr) {
        .none => unreachable,
        .undef => unreachable,
        .unreach => unreachable,
        .dead => unreachable,
        .compare_flags,
        .register_with_overflow,
        => unreachable, // cannot hold an address
        .immediate => |imm| {
            try self.set_reg_or_mem(value_ty, .{ .memory = imm }, value);
        },
        .ptr_stack_offset => |off| {
            try self.gen_set_stack(value_ty, off, value);
        },
        .register => |addr_reg| {
            const addr_reg_lock = self.register_manager.lock_reg(addr_reg);
            defer if (addr_reg_lock) |reg| self.register_manager.unlock_reg(reg);

            switch (value) {
                .dead => unreachable,
                .undef => {
                    try self.gen_set_reg(value_ty, addr_reg, value);
                },
                .register => |value_reg| {
                    log.debug("store: register {} to {}", .{ value_reg, addr_reg });
                    try self.gen_str_register(value_reg, addr_reg, value_ty);
                },
                else => {
                    if (abi_size <= 8) {
                        const raw_tmp_reg = try self.register_manager.alloc_reg(null, gp);
                        const tmp_reg = self.register_alias(raw_tmp_reg, value_ty);
                        const tmp_reg_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                        defer self.register_manager.unlock_reg(tmp_reg_lock);

                        try self.gen_set_reg(value_ty, tmp_reg, value);
                        try self.store(ptr, .{ .register = tmp_reg }, ptr_ty, value_ty);
                    } else {
                        const regs = try self.register_manager.alloc_regs(4, .{ null, null, null, null }, gp);
                        const regs_locks = self.register_manager.lock_regs_assume_unused(4, regs);
                        defer for (regs_locks) |reg| {
                            self.register_manager.unlock_reg(reg);
                        };

                        const src_reg = regs[0];
                        const dst_reg = addr_reg;
                        const len_reg = regs[1];
                        const count_reg = regs[2];
                        const tmp_reg = regs[3];

                        switch (value) {
                            .stack_offset => |off| {
                                // sub src_reg, fp, #off
                                try self.gen_set_reg(ptr_ty, src_reg, .{ .ptr_stack_offset = off });
                            },
                            .stack_argument_offset => |off| {
                                _ = try self.add_inst(.{
                                    .tag = .ldr_ptr_stack_argument,
                                    .data = .{ .load_store_stack = .{
                                        .rt = src_reg,
                                        .offset = off,
                                    } },
                                });
                            },
                            .memory => |addr| try self.gen_set_reg(Type.usize, src_reg, .{ .immediate = @as(u32, @int_cast(addr)) }),
                            .linker_load => |load_struct| {
                                const tag: Mir.Inst.Tag = switch (load_struct.type) {
                                    .got => .load_memory_ptr_got,
                                    .direct => .load_memory_ptr_direct,
                                    .import => unreachable,
                                };
                                const atom_index = switch (self.bin_file.tag) {
                                    .macho => {
                                        // const macho_file = self.bin_file.cast(link.File.MachO).?;
                                        // const atom = try macho_file.get_or_create_atom_for_decl(self.owner_decl);
                                        // break :blk macho_file.get_atom(atom).get_symbol_index().?;
                                        @panic("TODO store");
                                    },
                                    .coff => blk: {
                                        const coff_file = self.bin_file.cast(link.File.Coff).?;
                                        const atom = try coff_file.get_or_create_atom_for_decl(self.owner_decl);
                                        break :blk coff_file.get_atom(atom).get_symbol_index().?;
                                    },
                                    else => unreachable, // unsupported target format
                                };
                                _ = try self.add_inst(.{
                                    .tag = tag,
                                    .data = .{
                                        .payload = try self.add_extra(Mir.LoadMemoryPie{
                                            .register = @int_from_enum(src_reg),
                                            .atom_index = atom_index,
                                            .sym_index = load_struct.sym_index,
                                        }),
                                    },
                                });
                            },
                            else => return self.fail("TODO store {} to register", .{value}),
                        }

                        // mov len, #abi_size
                        try self.gen_set_reg(Type.usize, len_reg, .{ .immediate = abi_size });

                        // memcpy(src, dst, len)
                        try self.gen_inline_memcpy(src_reg, dst_reg, len_reg, count_reg, tmp_reg);
                    }
                },
            }
        },
        .memory,
        .stack_offset,
        .stack_argument_offset,
        .linker_load,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr);
            try self.store(.{ .register = addr_reg }, value, ptr_ty, value_ty);
        },
    }
}

fn air_store(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    if (safety) {
        // TODO if the value is undef, write 0xaa bytes to dest
    } else {
        // TODO if the value is undef, don't lower this instruction
    }
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ptr = try self.resolve_inst(bin_op.lhs);
    const value = try self.resolve_inst(bin_op.rhs);
    const ptr_ty = self.type_of(bin_op.lhs);
    const value_ty = self.type_of(bin_op.rhs);

    try self.store(ptr, value, ptr_ty, value_ty);

    return self.finish_air(inst, .dead, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_struct_field_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
    const result = try self.struct_field_ptr(inst, extra.struct_operand, extra.field_index);
    return self.finish_air(inst, result, .{ extra.struct_operand, .none, .none });
}

fn air_struct_field_ptr_index(self: *Self, inst: Air.Inst.Index, index: u8) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = try self.struct_field_ptr(inst, ty_op.operand, index);
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn struct_field_ptr(self: *Self, inst: Air.Inst.Index, operand: Air.Inst.Ref, index: u32) !MCValue {
    return if (self.liveness.is_unused(inst)) .dead else result: {
        const mod = self.bin_file.comp.module.?;
        const mcv = try self.resolve_inst(operand);
        const ptr_ty = self.type_of(operand);
        const struct_ty = ptr_ty.child_type(mod);
        const struct_field_offset = @as(u32, @int_cast(struct_ty.struct_field_offset(index, mod)));
        switch (mcv) {
            .ptr_stack_offset => |off| {
                break :result MCValue{ .ptr_stack_offset = off - struct_field_offset };
            },
            else => {
                const lhs_bind: ReadArg.Bind = .{ .mcv = mcv };
                const rhs_bind: ReadArg.Bind = .{ .mcv = .{ .immediate = struct_field_offset } };

                break :result try self.add_sub(.add, lhs_bind, rhs_bind, Type.usize, Type.usize, null);
            },
        }
    };
}

fn air_struct_field_val(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
    const operand = extra.struct_operand;
    const index = extra.field_index;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const mod = self.bin_file.comp.module.?;
        const mcv = try self.resolve_inst(operand);
        const struct_ty = self.type_of(operand);
        const struct_field_ty = struct_ty.struct_field_type(index, mod);
        const struct_field_offset = @as(u32, @int_cast(struct_ty.struct_field_offset(index, mod)));

        switch (mcv) {
            .dead, .unreach => unreachable,
            .stack_argument_offset => |off| {
                break :result MCValue{ .stack_argument_offset = off + struct_field_offset };
            },
            .stack_offset => |off| {
                break :result MCValue{ .stack_offset = off - struct_field_offset };
            },
            .memory => |addr| {
                break :result MCValue{ .memory = addr + struct_field_offset };
            },
            .register_with_overflow => |rwo| {
                const reg_lock = self.register_manager.lock_reg_assume_unused(rwo.reg);
                defer self.register_manager.unlock_reg(reg_lock);

                const field: MCValue = switch (index) {
                    // get wrapped value: return register
                    0 => MCValue{ .register = rwo.reg },

                    // get overflow bit: return C or V flag
                    1 => MCValue{ .compare_flags = rwo.flag },

                    else => unreachable,
                };

                if (self.reuse_operand(inst, operand, 0, field)) {
                    break :result field;
                } else {
                    // Copy to new register
                    const raw_dest_reg = try self.register_manager.alloc_reg(null, gp);
                    const dest_reg = self.register_alias(raw_dest_reg, struct_field_ty);
                    try self.gen_set_reg(struct_field_ty, dest_reg, field);

                    break :result MCValue{ .register = dest_reg };
                }
            },
            else => return self.fail("TODO implement codegen struct_field_val for {}", .{mcv}),
        }
    };

    return self.finish_air(inst, result, .{ extra.struct_operand, .none, .none });
}

fn air_field_parent_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const field_ptr = try self.resolve_inst(extra.field_ptr);
        const struct_ty = ty_pl.ty.to_type().child_type(mod);
        const struct_field_offset = @as(u32, @int_cast(struct_ty.struct_field_offset(extra.field_index, mod)));
        switch (field_ptr) {
            .ptr_stack_offset => |off| {
                break :result MCValue{ .ptr_stack_offset = off + struct_field_offset };
            },
            else => {
                const lhs_bind: ReadArg.Bind = .{ .mcv = field_ptr };
                const rhs_bind: ReadArg.Bind = .{ .mcv = .{ .immediate = struct_field_offset } };

                break :result try self.add_sub(.sub, lhs_bind, rhs_bind, Type.usize, Type.usize, null);
            },
        }
    };
    return self.finish_air(inst, result, .{ extra.field_ptr, .none, .none });
}

fn air_arg(self: *Self, inst: Air.Inst.Index) !void {
    // skip zero-bit arguments as they don't have a corresponding arg instruction
    var arg_index = self.arg_index;
    while (self.args[arg_index] == .none) arg_index += 1;
    self.arg_index = arg_index + 1;

    const mod = self.bin_file.comp.module.?;
    const ty = self.type_of_index(inst);
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const src_index = self.air.instructions.items(.data)[@int_from_enum(inst)].arg.src_index;
    const name = mod.get_param_name(self.func_index, src_index);

    try self.dbg_info_relocs.append(self.gpa, .{
        .tag = tag,
        .ty = ty,
        .name = name,
        .mcv = self.args[arg_index],
    });

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else self.args[arg_index];
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_trap(self: *Self) !void {
    _ = try self.add_inst(.{
        .tag = .brk,
        .data = .{ .imm16 = 0x0001 },
    });
    return self.finish_air_bookkeeping();
}

fn air_breakpoint(self: *Self) !void {
    _ = try self.add_inst(.{
        .tag = .brk,
        .data = .{ .imm16 = 0xf000 },
    });
    return self.finish_air_bookkeeping();
}

fn air_ret_addr(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_ret_addr for aarch64", .{});
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_frame_address(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_frame_address for aarch64", .{});
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_fence(self: *Self) !void {
    return self.fail("TODO implement fence() for {}", .{self.target.cpu.arch});
    //return self.finish_air_bookkeeping();
}

fn air_call(self: *Self, inst: Air.Inst.Index, modifier: std.builtin.CallModifier) !void {
    if (modifier == .always_tail) return self.fail("TODO implement tail calls for aarch64", .{});
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const callee = pl_op.operand;
    const extra = self.air.extra_data(Air.Call, pl_op.payload);
    const args = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[extra.end..][0..extra.data.args_len]));
    const ty = self.type_of(callee);
    const mod = self.bin_file.comp.module.?;

    const fn_ty = switch (ty.zig_type_tag(mod)) {
        .Fn => ty,
        .Pointer => ty.child_type(mod),
        else => unreachable,
    };

    var info = try self.resolve_calling_convention_values(fn_ty);
    defer info.deinit(self);

    // According to the Procedure Call Standard for the ARM
    // Architecture, compare flags are not preserved across
    // calls. Therefore, if some value is currently stored there, we
    // need to save it.
    //
    // TODO once caller-saved registers are implemented, save them
    // here too, but crucially *after* we save the compare flags as
    // saving compare flags may require a new caller-saved register
    try self.spill_compare_flags_if_occupied();

    if (info.return_value == .stack_offset) {
        log.debug("air_call: return by reference", .{});
        const ret_ty = fn_ty.fn_return_type(mod);
        const ret_abi_size: u32 = @int_cast(ret_ty.abi_size(mod));
        const ret_abi_align = ret_ty.abi_alignment(mod);
        const stack_offset = try self.alloc_mem(ret_abi_size, ret_abi_align, inst);

        const ret_ptr_reg = self.register_alias(.x0, Type.usize);

        const ptr_ty = try mod.single_mut_ptr_type(ret_ty);
        try self.register_manager.get_reg(ret_ptr_reg, null);
        try self.gen_set_reg(ptr_ty, ret_ptr_reg, .{ .ptr_stack_offset = stack_offset });

        info.return_value = .{ .stack_offset = stack_offset };
    }

    // Make space for the arguments passed via the stack
    self.max_end_stack += info.stack_byte_count;

    for (info.args, 0..) |mc_arg, arg_i| {
        const arg = args[arg_i];
        const arg_ty = self.type_of(arg);
        const arg_mcv = try self.resolve_inst(args[arg_i]);

        switch (mc_arg) {
            .none => continue,
            .register => |reg| {
                try self.register_manager.get_reg(reg, null);
                try self.gen_set_reg(arg_ty, reg, arg_mcv);
            },
            .stack_offset => unreachable,
            .stack_argument_offset => |offset| try self.gen_set_stack_argument(
                arg_ty,
                offset,
                arg_mcv,
            ),
            else => unreachable,
        }
    }

    // Due to incremental compilation, how function calls are generated depends
    // on linking.
    if (try self.air.value(callee, mod)) |func_value| {
        if (func_value.get_function(mod)) |func| {
            if (self.bin_file.cast(link.File.Elf)) |elf_file| {
                const sym_index = try elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, func.owner_decl);
                const sym = elf_file.symbol(sym_index);
                _ = try sym.get_or_create_zig_got_entry(sym_index, elf_file);
                const got_addr = @as(u32, @int_cast(sym.zig_got_address(elf_file)));
                try self.gen_set_reg(Type.usize, .x30, .{ .memory = got_addr });
            } else if (self.bin_file.cast(link.File.MachO)) |macho_file| {
                _ = macho_file;
                @panic("TODO air_call");
                // const atom = try macho_file.get_or_create_atom_for_decl(func.owner_decl);
                // const sym_index = macho_file.get_atom(atom).get_symbol_index().?;
                // try self.gen_set_reg(Type.u64, .x30, .{
                //     .linker_load = .{
                //         .type = .got,
                //         .sym_index = sym_index,
                //     },
                // });
            } else if (self.bin_file.cast(link.File.Coff)) |coff_file| {
                const atom = try coff_file.get_or_create_atom_for_decl(func.owner_decl);
                const sym_index = coff_file.get_atom(atom).get_symbol_index().?;
                try self.gen_set_reg(Type.u64, .x30, .{
                    .linker_load = .{
                        .type = .got,
                        .sym_index = sym_index,
                    },
                });
            } else if (self.bin_file.cast(link.File.Plan9)) |p9| {
                const atom_index = try p9.see_decl(func.owner_decl);
                const atom = p9.get_atom(atom_index);
                try self.gen_set_reg(Type.usize, .x30, .{ .memory = atom.get_offset_table_address(p9) });
            } else unreachable;

            _ = try self.add_inst(.{
                .tag = .blr,
                .data = .{ .reg = .x30 },
            });
        } else if (func_value.get_extern_func(mod)) |extern_func| {
            const decl_name = mod.decl_ptr(extern_func.decl).name.to_slice(&mod.intern_pool);
            const lib_name = extern_func.lib_name.to_slice(&mod.intern_pool);
            if (self.bin_file.cast(link.File.MachO)) |macho_file| {
                _ = macho_file;
                @panic("TODO air_call");
                // const sym_index = try macho_file.get_global_symbol(decl_name, lib_name);
                // const atom = try macho_file.get_or_create_atom_for_decl(self.owner_decl);
                // const atom_index = macho_file.get_atom(atom).get_symbol_index().?;
                // _ = try self.add_inst(.{
                //     .tag = .call_extern,
                //     .data = .{
                //         .relocation = .{
                //             .atom_index = atom_index,
                //             .sym_index = sym_index,
                //         },
                //     },
                // });
            } else if (self.bin_file.cast(link.File.Coff)) |coff_file| {
                const sym_index = try coff_file.get_global_symbol(decl_name, lib_name);
                try self.gen_set_reg(Type.u64, .x30, .{
                    .linker_load = .{
                        .type = .import,
                        .sym_index = sym_index,
                    },
                });
                _ = try self.add_inst(.{
                    .tag = .blr,
                    .data = .{ .reg = .x30 },
                });
            } else {
                return self.fail("TODO implement calling extern functions", .{});
            }
        } else {
            return self.fail("TODO implement calling bitcasted functions", .{});
        }
    } else {
        assert(ty.zig_type_tag(mod) == .Pointer);
        const mcv = try self.resolve_inst(callee);
        try self.gen_set_reg(ty, .x30, mcv);

        _ = try self.add_inst(.{
            .tag = .blr,
            .data = .{ .reg = .x30 },
        });
    }

    const result: MCValue = result: {
        switch (info.return_value) {
            .register => |reg| {
                if (RegisterManager.index_of_reg(&callee_preserved_regs, reg) == null) {
                    // Save function return value in a callee saved register
                    break :result try self.copy_to_new_register(inst, info.return_value);
                }
            },
            else => {},
        }
        break :result info.return_value;
    };

    if (args.len + 1 <= Liveness.bpi - 1) {
        var buf = [1]Air.Inst.Ref{.none} ** (Liveness.bpi - 1);
        buf[0] = callee;
        @memcpy(buf[1..][0..args.len], args);
        return self.finish_air(inst, result, buf);
    }
    var bt = try self.iterate_big_tomb(inst, 1 + args.len);
    bt.feed(callee);
    for (args) |arg| {
        bt.feed(arg);
    }
    return bt.finish_air(result);
}

fn air_ret(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ret_ty = self.fn_type.fn_return_type(mod);

    switch (self.ret_mcv) {
        .none => {},
        .immediate => {
            assert(ret_ty.is_error(mod));
        },
        .register => |reg| {
            // Return result by value
            try self.gen_set_reg(ret_ty, reg, operand);
        },
        .stack_offset => {
            // Return result by reference
            //
            // self.ret_mcv is an address to where this function
            // should store its result into
            const ptr_ty = try mod.single_mut_ptr_type(ret_ty);
            try self.store(self.ret_mcv, operand, ptr_ty, ret_ty);
        },
        else => unreachable,
    }

    // Just add space for an instruction, patch this later
    try self.exitlude_jump_relocs.append(self.gpa, try self.add_nop());

    return self.finish_air(inst, .dead, .{ un_op, .none, .none });
}

fn air_ret_load(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ptr = try self.resolve_inst(un_op);
    const ptr_ty = self.type_of(un_op);
    const ret_ty = self.fn_type.fn_return_type(mod);

    switch (self.ret_mcv) {
        .none => {},
        .register => {
            // Return result by value
            try self.load(self.ret_mcv, ptr, ptr_ty);
        },
        .stack_offset => {
            // Return result by reference
            //
            // self.ret_mcv is an address to where this function
            // should store its result into
            //
            // If the operand is a ret_ptr instruction, we are done
            // here. Else we need to load the result from the location
            // pointed to by the operand and store it to the result
            // location.
            const op_inst = un_op.to_index().?;
            if (self.air.instructions.items(.tag)[@int_from_enum(op_inst)] != .ret_ptr) {
                const abi_size = @as(u32, @int_cast(ret_ty.abi_size(mod)));
                const abi_align = ret_ty.abi_alignment(mod);

                const offset = try self.alloc_mem(abi_size, abi_align, null);

                const tmp_mcv = MCValue{ .stack_offset = offset };
                try self.load(tmp_mcv, ptr, ptr_ty);
                try self.store(self.ret_mcv, tmp_mcv, ptr_ty, ret_ty);
            }
        },
        else => unreachable, // invalid return result
    }

    try self.exitlude_jump_relocs.append(self.gpa, try self.add_nop());

    return self.finish_air(inst, .dead, .{ un_op, .none, .none });
}

fn air_cmp(self: *Self, inst: Air.Inst.Index, op: math.CompareOperator) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const lhs_ty = self.type_of(bin_op.lhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else blk: {
        break :blk try self.cmp(.{ .inst = bin_op.lhs }, .{ .inst = bin_op.rhs }, lhs_ty, op);
    };

    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn cmp(
    self: *Self,
    lhs: ReadArg.Bind,
    rhs: ReadArg.Bind,
    lhs_ty: Type,
    op: math.CompareOperator,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const int_ty = switch (lhs_ty.zig_type_tag(mod)) {
        .Optional => blk: {
            const payload_ty = lhs_ty.optional_child(mod);
            if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
                break :blk Type.u1;
            } else if (lhs_ty.is_ptr_like_optional(mod)) {
                break :blk Type.usize;
            } else {
                return self.fail("TODO ARM cmp non-pointer optionals", .{});
            }
        },
        .Float => return self.fail("TODO ARM cmp floats", .{}),
        .Enum => lhs_ty.int_tag_type(mod),
        .Int => lhs_ty,
        .Bool => Type.u1,
        .Pointer => Type.usize,
        .ErrorSet => Type.u16,
        else => unreachable,
    };

    const int_info = int_ty.int_info(mod);
    if (int_info.bits <= 64) {
        try self.spill_compare_flags_if_occupied();

        var lhs_reg: Register = undefined;
        var rhs_reg: Register = undefined;

        const rhs_immediate = try rhs.resolve_to_immediate(self);
        const rhs_immediate_ok = if (rhs_immediate) |imm| imm <= std.math.max_int(u12) else false;

        if (rhs_immediate_ok) {
            const read_args = [_]ReadArg{
                .{ .ty = int_ty, .bind = lhs, .class = gp, .reg = &lhs_reg },
            };
            try self.alloc_regs(
                &read_args,
                &.{},
                null, // we won't be able to reuse a register as there are no write_regs
            );

            _ = try self.add_inst(.{
                .tag = .cmp_immediate,
                .data = .{ .r_imm12_sh = .{
                    .rn = lhs_reg,
                    .imm12 = @as(u12, @int_cast(rhs_immediate.?)),
                } },
            });
        } else {
            const read_args = [_]ReadArg{
                .{ .ty = int_ty, .bind = lhs, .class = gp, .reg = &lhs_reg },
                .{ .ty = int_ty, .bind = rhs, .class = gp, .reg = &rhs_reg },
            };
            try self.alloc_regs(
                &read_args,
                &.{},
                null, // we won't be able to reuse a register as there are no write_regs
            );

            _ = try self.add_inst(.{
                .tag = .cmp_shifted_register,
                .data = .{ .rr_imm6_shift = .{
                    .rn = lhs_reg,
                    .rm = rhs_reg,
                    .imm6 = 0,
                    .shift = .lsl,
                } },
            });
        }

        return switch (int_info.signedness) {
            .signed => MCValue{ .compare_flags = Condition.from_compare_operator_signed(op) },
            .unsigned => MCValue{ .compare_flags = Condition.from_compare_operator_unsigned(op) },
        };
    } else {
        return self.fail("TODO AArch64 cmp for ints > 64 bits", .{});
    }
}

fn air_cmp_vector(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_cmp_vector for {}", .{self.target.cpu.arch});
}

fn air_cmp_lt_errors_len(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    _ = operand;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_cmp_lt_errors_len for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_dbg_stmt(self: *Self, inst: Air.Inst.Index) !void {
    const dbg_stmt = self.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;

    _ = try self.add_inst(.{
        .tag = .dbg_line,
        .data = .{ .dbg_line_column = .{
            .line = dbg_stmt.line,
            .column = dbg_stmt.column,
        } },
    });

    return self.finish_air_bookkeeping();
}

fn air_dbg_inline_block(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
    const func = mod.func_info(extra.data.func);
    // TODO emit debug info for function change
    _ = func;
    try self.lower_block(inst, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
}

fn air_dbg_var(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const operand = pl_op.operand;
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const ty = self.type_of(operand);
    const mcv = try self.resolve_inst(operand);
    const name = self.air.null_terminated_string(pl_op.payload);

    log.debug("air_dbg_var: %{d}: {}, {}", .{ inst, ty.fmt_debug(), mcv });

    try self.dbg_info_relocs.append(self.gpa, .{
        .tag = tag,
        .ty = ty,
        .name = name,
        .mcv = mcv,
    });

    return self.finish_air(inst, .dead, .{ operand, .none, .none });
}

fn cond_br(self: *Self, condition: MCValue) !Mir.Inst.Index {
    switch (condition) {
        .compare_flags => |cond| return try self.add_inst(.{
            .tag = .b_cond,
            .data = .{
                .inst_cond = .{
                    .inst = undefined, // populated later through perform_reloc
                    // Here we map to the opposite condition because the jump is to the false branch.
                    .cond = cond.negate(),
                },
            },
        }),
        else => {
            const reg = switch (condition) {
                .register => |r| r,
                else => try self.copy_to_tmp_register(Type.bool, condition),
            };

            return try self.add_inst(.{
                .tag = .cbz,
                .data = .{
                    .r_inst = .{
                        .rt = reg,
                        .inst = undefined, // populated later through perform_reloc
                    },
                },
            });
        },
    }
}

fn air_cond_br(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const cond = try self.resolve_inst(pl_op.operand);
    const extra = self.air.extra_data(Air.CondBr, pl_op.payload);
    const then_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
    const liveness_condbr = self.liveness.get_cond_br(inst);

    const reloc = try self.cond_br(cond);

    // If the condition dies here in this condbr instruction, process
    // that death now instead of later as this has an effect on
    // whether it needs to be spilled in the branches
    if (self.liveness.operand_dies(inst, 0)) {
        if (pl_op.operand.to_index()) |op_index| {
            self.process_death(op_index);
        }
    }

    // Capture the state of register and stack allocation state so that we can revert to it.
    const parent_next_stack_offset = self.next_stack_offset;
    const parent_free_registers = self.register_manager.free_registers;
    var parent_stack = try self.stack.clone(self.gpa);
    defer parent_stack.deinit(self.gpa);
    const parent_registers = self.register_manager.registers;
    const parent_compare_flags_inst = self.compare_flags_inst;

    try self.branch_stack.append(.{});
    errdefer {
        _ = self.branch_stack.pop();
    }

    try self.ensure_process_death_capacity(liveness_condbr.then_deaths.len);
    for (liveness_condbr.then_deaths) |operand| {
        self.process_death(operand);
    }
    try self.gen_body(then_body);

    // Revert to the previous register and stack allocation state.

    var saved_then_branch = self.branch_stack.pop();
    defer saved_then_branch.deinit(self.gpa);

    self.register_manager.registers = parent_registers;
    self.compare_flags_inst = parent_compare_flags_inst;

    self.stack.deinit(self.gpa);
    self.stack = parent_stack;
    parent_stack = .{};

    self.next_stack_offset = parent_next_stack_offset;
    self.register_manager.free_registers = parent_free_registers;

    try self.perform_reloc(reloc);
    const else_branch = self.branch_stack.add_one_assume_capacity();
    else_branch.* = .{};

    try self.ensure_process_death_capacity(liveness_condbr.else_deaths.len);
    for (liveness_condbr.else_deaths) |operand| {
        self.process_death(operand);
    }
    try self.gen_body(else_body);

    // At this point, each branch will possibly have conflicting values for where
    // each instruction is stored. They agree, however, on which instructions are alive/dead.
    // We use the first ("then") branch as canonical, and here emit
    // instructions into the second ("else") branch to make it conform.
    // We continue respect the data structure semantic guarantees of the else_branch so
    // that we can use all the code emitting abstractions. This is why at the bottom we
    // assert that parent_branch.free_registers equals the saved_then_branch.free_registers
    // rather than assigning it.
    const parent_branch = &self.branch_stack.items[self.branch_stack.items.len - 2];
    try parent_branch.inst_table.ensure_unused_capacity(self.gpa, else_branch.inst_table.count());

    const else_slice = else_branch.inst_table.entries.slice();
    const else_keys = else_slice.items(.key);
    const else_values = else_slice.items(.value);
    for (else_keys, 0..) |else_key, else_idx| {
        const else_value = else_values[else_idx];
        const canon_mcv = if (saved_then_branch.inst_table.fetch_swap_remove(else_key)) |then_entry| blk: {
            // The instruction's MCValue is overridden in both branches.
            parent_branch.inst_table.put_assume_capacity(else_key, then_entry.value);
            if (else_value == .dead) {
                assert(then_entry.value == .dead);
                continue;
            }
            break :blk then_entry.value;
        } else blk: {
            if (else_value == .dead)
                continue;
            // The instruction is only overridden in the else branch.
            var i: usize = self.branch_stack.items.len - 1;
            while (true) {
                i -= 1; // If this overflows, the question is: why wasn't the instruction marked dead?
                if (self.branch_stack.items[i].inst_table.get(else_key)) |mcv| {
                    assert(mcv != .dead);
                    break :blk mcv;
                }
            }
        };
        log.debug("consolidating else_entry {d} {}=>{}", .{ else_key, else_value, canon_mcv });
        // TODO make sure the destination stack offset / register does not already have something
        // going on there.
        try self.set_reg_or_mem(self.type_of_index(else_key), canon_mcv, else_value);
        // TODO track the new register / stack allocation
    }
    try parent_branch.inst_table.ensure_unused_capacity(self.gpa, saved_then_branch.inst_table.count());
    const then_slice = saved_then_branch.inst_table.entries.slice();
    const then_keys = then_slice.items(.key);
    const then_values = then_slice.items(.value);
    for (then_keys, 0..) |then_key, then_idx| {
        const then_value = then_values[then_idx];
        // We already deleted the items from this table that matched the else_branch.
        // So these are all instructions that are only overridden in the then branch.
        parent_branch.inst_table.put_assume_capacity(then_key, then_value);
        if (then_value == .dead)
            continue;
        const parent_mcv = blk: {
            var i: usize = self.branch_stack.items.len - 1;
            while (true) {
                i -= 1;
                if (self.branch_stack.items[i].inst_table.get(then_key)) |mcv| {
                    assert(mcv != .dead);
                    break :blk mcv;
                }
            }
        };
        log.debug("consolidating then_entry {d} {}=>{}", .{ then_key, parent_mcv, then_value });
        // TODO make sure the destination stack offset / register does not already have something
        // going on there.
        try self.set_reg_or_mem(self.type_of_index(then_key), parent_mcv, then_value);
        // TODO track the new register / stack allocation
    }

    {
        var item = self.branch_stack.pop();
        item.deinit(self.gpa);
    }

    // We already took care of pl_op.operand earlier, so we're going
    // to pass .none here
    return self.finish_air(inst, .unreach, .{ .none, .none, .none });
}

fn is_null(self: *Self, operand_bind: ReadArg.Bind, operand_ty: Type) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const sentinel: struct { ty: Type, bind: ReadArg.Bind } = if (!operand_ty.is_ptr_like_optional(mod)) blk: {
        const payload_ty = operand_ty.optional_child(mod);
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod))
            break :blk .{ .ty = operand_ty, .bind = operand_bind };

        const offset = @as(u32, @int_cast(payload_ty.abi_size(mod)));
        const operand_mcv = try operand_bind.resolve_to_mcv(self);
        const new_mcv: MCValue = switch (operand_mcv) {
            .register => |source_reg| new: {
                // TODO should we reuse the operand here?
                const raw_reg = try self.register_manager.alloc_reg(null, gp);
                const dest_reg = raw_reg.to_x();

                const shift = @as(u6, @int_cast(offset * 8));
                if (shift == 0) {
                    try self.gen_set_reg(payload_ty, dest_reg, operand_mcv);
                } else {
                    _ = try self.add_inst(.{
                        .tag = if (payload_ty.is_signed_int(mod))
                            Mir.Inst.Tag.asr_immediate
                        else
                            Mir.Inst.Tag.lsr_immediate,
                        .data = .{ .rr_shift = .{
                            .rd = dest_reg,
                            .rn = source_reg.to_x(),
                            .shift = shift,
                        } },
                    });
                }

                break :new .{ .register = self.register_alias(dest_reg, payload_ty) };
            },
            .stack_argument_offset => |off| .{ .stack_argument_offset = off + offset },
            .stack_offset => |off| .{ .stack_offset = off - offset },
            .memory => |addr| .{ .memory = addr + offset },
            else => unreachable, // invalid MCValue for an optional
        };

        break :blk .{ .ty = Type.bool, .bind = .{ .mcv = new_mcv } };
    } else .{ .ty = operand_ty, .bind = operand_bind };
    const imm_bind: ReadArg.Bind = .{ .mcv = .{ .immediate = 0 } };
    return self.cmp(sentinel.bind, imm_bind, sentinel.ty, .eq);
}

fn is_non_null(self: *Self, operand_bind: ReadArg.Bind, operand_ty: Type) !MCValue {
    const is_null_res = try self.is_null(operand_bind, operand_ty);
    assert(is_null_res.compare_flags == .eq);
    return MCValue{ .compare_flags = is_null_res.compare_flags.negate() };
}

fn is_err(
    self: *Self,
    error_union_bind: ReadArg.Bind,
    error_union_ty: Type,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const error_type = error_union_ty.error_union_set(mod);

    if (error_type.error_set_is_empty(mod)) {
        return MCValue{ .immediate = 0 }; // always false
    }

    const error_mcv = try self.err_union_err(error_union_bind, error_union_ty, null);
    return try self.cmp(.{ .mcv = error_mcv }, .{ .mcv = .{ .immediate = 0 } }, error_type, .gt);
}

fn is_non_err(
    self: *Self,
    error_union_bind: ReadArg.Bind,
    error_union_ty: Type,
) !MCValue {
    const is_err_result = try self.is_err(error_union_bind, error_union_ty);
    switch (is_err_result) {
        .compare_flags => |cond| {
            assert(cond == .hi);
            return MCValue{ .compare_flags = cond.negate() };
        },
        .immediate => |imm| {
            assert(imm == 0);
            return MCValue{ .immediate = 1 };
        },
        else => unreachable,
    }
}

fn air_is_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);

        break :result try self.is_null(.{ .mcv = operand }, operand_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const ptr_ty = self.type_of(un_op);
        const elem_ty = ptr_ty.child_type(mod);

        const operand = try self.alloc_reg_or_mem(elem_ty, true, null);
        try self.load(operand, operand_ptr, ptr_ty);

        break :result try self.is_null(.{ .mcv = operand }, elem_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);

        break :result try self.is_non_null(.{ .mcv = operand }, operand_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const ptr_ty = self.type_of(un_op);
        const elem_ty = ptr_ty.child_type(mod);

        const operand = try self.alloc_reg_or_mem(elem_ty, true, null);
        try self.load(operand, operand_ptr, ptr_ty);

        break :result try self.is_non_null(.{ .mcv = operand }, elem_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const error_union_bind: ReadArg.Bind = .{ .inst = un_op };
        const error_union_ty = self.type_of(un_op);

        break :result try self.is_err(error_union_bind, error_union_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const ptr_ty = self.type_of(un_op);
        const elem_ty = ptr_ty.child_type(mod);

        const operand = try self.alloc_reg_or_mem(elem_ty, true, null);
        try self.load(operand, operand_ptr, ptr_ty);

        break :result try self.is_err(.{ .mcv = operand }, elem_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const error_union_bind: ReadArg.Bind = .{ .inst = un_op };
        const error_union_ty = self.type_of(un_op);

        break :result try self.is_non_err(error_union_bind, error_union_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const ptr_ty = self.type_of(un_op);
        const elem_ty = ptr_ty.child_type(mod);

        const operand = try self.alloc_reg_or_mem(elem_ty, true, null);
        try self.load(operand, operand_ptr, ptr_ty);

        break :result try self.is_non_err(.{ .mcv = operand }, elem_ty);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_loop(self: *Self, inst: Air.Inst.Index) !void {
    // A loop is a setup to be able to jump back to the beginning.
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const loop = self.air.extra_data(Air.Block, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[loop.end..][0..loop.data.body_len]);
    const start_index = @as(u32, @int_cast(self.mir_instructions.len));

    try self.gen_body(body);
    try self.jump(start_index);

    return self.finish_air_bookkeeping();
}

/// Send control flow to `inst`.
fn jump(self: *Self, inst: Mir.Inst.Index) !void {
    _ = try self.add_inst(.{
        .tag = .b,
        .data = .{ .inst = inst },
    });
}

fn air_block(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Block, ty_pl.payload);
    try self.lower_block(inst, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
}

fn lower_block(self: *Self, inst: Air.Inst.Index, body: []const Air.Inst.Index) !void {
    try self.blocks.put_no_clobber(self.gpa, inst, .{
        // A block is a setup to be able to jump to the end.
        .relocs = .{},
        // It also acts as a receptacle for break operands.
        // Here we use `MCValue.none` to represent a null value so that the first
        // break instruction will choose a MCValue for the block result and overwrite
        // this field. Following break instructions will use that MCValue to put their
        // block results.
        .mcv = MCValue{ .none = {} },
    });
    defer self.blocks.get_ptr(inst).?.relocs.deinit(self.gpa);

    // TODO emit debug info lexical block
    try self.gen_body(body);

    // relocations for `br` instructions
    const relocs = &self.blocks.get_ptr(inst).?.relocs;
    if (relocs.items.len > 0 and relocs.items[relocs.items.len - 1] == self.mir_instructions.len - 1) {
        // If the last Mir instruction is the last relocation (which
        // would just jump one instruction further), it can be safely
        // removed
        self.mir_instructions.ordered_remove(relocs.pop());
    }
    for (relocs.items) |reloc| {
        try self.perform_reloc(reloc);
    }

    const result = self.blocks.get_ptr(inst).?.mcv;
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_switch(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const condition_ty = self.type_of(pl_op.operand);
    const switch_br = self.air.extra_data(Air.SwitchBr, pl_op.payload);
    const liveness = try self.liveness.get_switch_br(
        self.gpa,
        inst,
        switch_br.data.cases_len + 1,
    );
    defer self.gpa.free(liveness.deaths);

    var extra_index: usize = switch_br.end;
    var case_i: u32 = 0;
    while (case_i < switch_br.data.cases_len) : (case_i += 1) {
        const case = self.air.extra_data(Air.SwitchBr.Case, extra_index);
        const items = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[case.end..][0..case.data.items_len]));
        assert(items.len > 0);
        const case_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[case.end + items.len ..][0..case.data.body_len]);
        extra_index = case.end + items.len + case_body.len;

        // For every item, we compare it to condition and branch into
        // the prong if they are equal. After we compared to all
        // items, we branch into the next prong (or if no other prongs
        // exist out of the switch statement).
        //
        //             cmp condition, item1
        //             beq prong
        //             cmp condition, item2
        //             beq prong
        //             cmp condition, item3
        //             beq prong
        //             b out
        // prong:      ...
        //             ...
        // out:        ...
        const branch_into_prong_relocs = try self.gpa.alloc(u32, items.len);
        defer self.gpa.free(branch_into_prong_relocs);

        for (items, 0..) |item, idx| {
            const cmp_result = try self.cmp(.{ .inst = pl_op.operand }, .{ .inst = item }, condition_ty, .neq);
            branch_into_prong_relocs[idx] = try self.cond_br(cmp_result);
        }

        const branch_away_from_prong_reloc = try self.add_inst(.{
            .tag = .b,
            .data = .{ .inst = undefined }, // populated later through perform_reloc
        });

        for (branch_into_prong_relocs) |reloc| {
            try self.perform_reloc(reloc);
        }

        // Capture the state of register and stack allocation state so that we can revert to it.
        const parent_next_stack_offset = self.next_stack_offset;
        const parent_free_registers = self.register_manager.free_registers;
        const parent_compare_flags_inst = self.compare_flags_inst;
        var parent_stack = try self.stack.clone(self.gpa);
        defer parent_stack.deinit(self.gpa);
        const parent_registers = self.register_manager.registers;

        try self.branch_stack.append(.{});
        errdefer {
            _ = self.branch_stack.pop();
        }

        try self.ensure_process_death_capacity(liveness.deaths[case_i].len);
        for (liveness.deaths[case_i]) |operand| {
            self.process_death(operand);
        }
        try self.gen_body(case_body);

        // Revert to the previous register and stack allocation state.
        var saved_case_branch = self.branch_stack.pop();
        defer saved_case_branch.deinit(self.gpa);

        self.register_manager.registers = parent_registers;
        self.compare_flags_inst = parent_compare_flags_inst;
        self.stack.deinit(self.gpa);
        self.stack = parent_stack;
        parent_stack = .{};

        self.next_stack_offset = parent_next_stack_offset;
        self.register_manager.free_registers = parent_free_registers;

        try self.perform_reloc(branch_away_from_prong_reloc);
    }

    if (switch_br.data.else_body_len > 0) {
        const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra_index..][0..switch_br.data.else_body_len]);

        // Capture the state of register and stack allocation state so that we can revert to it.
        const parent_next_stack_offset = self.next_stack_offset;
        const parent_free_registers = self.register_manager.free_registers;
        const parent_compare_flags_inst = self.compare_flags_inst;
        var parent_stack = try self.stack.clone(self.gpa);
        defer parent_stack.deinit(self.gpa);
        const parent_registers = self.register_manager.registers;

        try self.branch_stack.append(.{});
        errdefer {
            _ = self.branch_stack.pop();
        }

        const else_deaths = liveness.deaths.len - 1;
        try self.ensure_process_death_capacity(liveness.deaths[else_deaths].len);
        for (liveness.deaths[else_deaths]) |operand| {
            self.process_death(operand);
        }
        try self.gen_body(else_body);

        // Revert to the previous register and stack allocation state.
        var saved_case_branch = self.branch_stack.pop();
        defer saved_case_branch.deinit(self.gpa);

        self.register_manager.registers = parent_registers;
        self.compare_flags_inst = parent_compare_flags_inst;
        self.stack.deinit(self.gpa);
        self.stack = parent_stack;
        parent_stack = .{};

        self.next_stack_offset = parent_next_stack_offset;
        self.register_manager.free_registers = parent_free_registers;

        // TODO consolidate returned MCValues between prongs and else branch like we do
        // in air_cond_br.
    }

    return self.finish_air(inst, .unreach, .{ pl_op.operand, .none, .none });
}

fn perform_reloc(self: *Self, inst: Mir.Inst.Index) !void {
    const tag = self.mir_instructions.items(.tag)[inst];
    switch (tag) {
        .cbz => self.mir_instructions.items(.data)[inst].r_inst.inst = @int_cast(self.mir_instructions.len),
        .b_cond => self.mir_instructions.items(.data)[inst].inst_cond.inst = @int_cast(self.mir_instructions.len),
        .b => self.mir_instructions.items(.data)[inst].inst = @int_cast(self.mir_instructions.len),
        else => unreachable,
    }
}

fn air_br(self: *Self, inst: Air.Inst.Index) !void {
    const branch = self.air.instructions.items(.data)[@int_from_enum(inst)].br;
    try self.br(branch.block_inst, branch.operand);
    return self.finish_air(inst, .dead, .{ branch.operand, .none, .none });
}

fn br(self: *Self, block: Air.Inst.Index, operand: Air.Inst.Ref) !void {
    const mod = self.bin_file.comp.module.?;
    const block_data = self.blocks.get_ptr(block).?;

    if (self.type_of(operand).has_runtime_bits(mod)) {
        const operand_mcv = try self.resolve_inst(operand);
        const block_mcv = block_data.mcv;
        if (block_mcv == .none) {
            block_data.mcv = switch (operand_mcv) {
                .none, .dead, .unreach => unreachable,
                .register, .stack_offset, .memory => operand_mcv,
                .immediate, .stack_argument_offset, .compare_flags => blk: {
                    const new_mcv = try self.alloc_reg_or_mem(self.type_of_index(block), true, block);
                    try self.set_reg_or_mem(self.type_of_index(block), new_mcv, operand_mcv);
                    break :blk new_mcv;
                },
                else => return self.fail("TODO implement block_data.mcv = operand_mcv for {}", .{operand_mcv}),
            };
        } else {
            try self.set_reg_or_mem(self.type_of_index(block), block_mcv, operand_mcv);
        }
    }
    return self.br_void(block);
}

fn br_void(self: *Self, block: Air.Inst.Index) !void {
    const block_data = self.blocks.get_ptr(block).?;

    // Emit a jump with a relocation. It will be patched up after the block ends.
    try block_data.relocs.ensure_unused_capacity(self.gpa, 1);

    block_data.relocs.append_assume_capacity(try self.add_inst(.{
        .tag = .b,
        .data = .{ .inst = undefined }, // populated later through perform_reloc
    }));
}

fn air_asm(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Asm, ty_pl.payload);
    const is_volatile = @as(u1, @truncate(extra.data.flags >> 31)) != 0;
    const clobbers_len = @as(u31, @truncate(extra.data.flags));
    var extra_i: usize = extra.end;
    const outputs = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[extra_i..][0..extra.data.outputs_len]));
    extra_i += outputs.len;
    const inputs = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[extra_i..][0..extra.data.inputs_len]));
    extra_i += inputs.len;

    const dead = !is_volatile and self.liveness.is_unused(inst);
    const result: MCValue = if (dead) .dead else result: {
        if (outputs.len > 1) {
            return self.fail("TODO implement codegen for asm with more than 1 output", .{});
        }

        const output_constraint: ?[]const u8 = for (outputs) |output| {
            if (output != .none) {
                return self.fail("TODO implement codegen for non-expr asm", .{});
            }
            const extra_bytes = std.mem.slice_as_bytes(self.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(std.mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            break constraint;
        } else null;

        for (inputs) |input| {
            const input_bytes = std.mem.slice_as_bytes(self.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(input_bytes, 0);
            const name = std.mem.slice_to(input_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (constraint.len < 3 or constraint[0] != '{' or constraint[constraint.len - 1] != '}') {
                return self.fail("unrecognized asm input constraint: '{s}'", .{constraint});
            }
            const reg_name = constraint[1 .. constraint.len - 1];
            const reg = parse_reg_name(reg_name) orelse
                return self.fail("unrecognized register: '{s}'", .{reg_name});

            const arg_mcv = try self.resolve_inst(input);
            try self.register_manager.get_reg(reg, null);
            try self.gen_set_reg(self.type_of(input), reg, arg_mcv);
        }

        {
            var clobber_i: u32 = 0;
            while (clobber_i < clobbers_len) : (clobber_i += 1) {
                const clobber = std.mem.slice_to(std.mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
                // This equation accounts for the fact that even if we have exactly 4 bytes
                // for the string, we still use the next u32 for the null terminator.
                extra_i += clobber.len / 4 + 1;

                // TODO honor these
            }
        }

        const asm_source = std.mem.slice_as_bytes(self.air.extra[extra_i..])[0..extra.data.source_len];

        if (mem.eql(u8, asm_source, "svc #0")) {
            _ = try self.add_inst(.{
                .tag = .svc,
                .data = .{ .imm16 = 0x0 },
            });
        } else if (mem.eql(u8, asm_source, "svc #0x80")) {
            _ = try self.add_inst(.{
                .tag = .svc,
                .data = .{ .imm16 = 0x80 },
            });
        } else {
            return self.fail("TODO implement support for more aarch64 assembly instructions", .{});
        }

        if (output_constraint) |output| {
            if (output.len < 4 or output[0] != '=' or output[1] != '{' or output[output.len - 1] != '}') {
                return self.fail("unrecognized asm output constraint: '{s}'", .{output});
            }
            const reg_name = output[2 .. output.len - 1];
            const reg = parse_reg_name(reg_name) orelse
                return self.fail("unrecognized register: '{s}'", .{reg_name});
            break :result MCValue{ .register = reg };
        } else {
            break :result MCValue{ .none = {} };
        }
    };

    simple: {
        var buf = [1]Air.Inst.Ref{.none} ** (Liveness.bpi - 1);
        var buf_index: usize = 0;
        for (outputs) |output| {
            if (output == .none) continue;

            if (buf_index >= buf.len) break :simple;
            buf[buf_index] = output;
            buf_index += 1;
        }
        if (buf_index + inputs.len > buf.len) break :simple;
        @memcpy(buf[buf_index..][0..inputs.len], inputs);
        return self.finish_air(inst, result, buf);
    }
    var bt = try self.iterate_big_tomb(inst, outputs.len + inputs.len);
    for (outputs) |output| {
        if (output == .none) continue;

        bt.feed(output);
    }
    for (inputs) |input| {
        bt.feed(input);
    }
    return bt.finish_air(result);
}

fn iterate_big_tomb(self: *Self, inst: Air.Inst.Index, operand_count: usize) !BigTomb {
    try self.ensure_process_death_capacity(operand_count + 1);
    return BigTomb{
        .function = self,
        .inst = inst,
        .lbt = self.liveness.iterate_big_tomb(inst),
    };
}

/// Sets the value without any modifications to register allocation metadata or stack allocation metadata.
fn set_reg_or_mem(self: *Self, ty: Type, loc: MCValue, val: MCValue) !void {
    switch (loc) {
        .none => return,
        .register => |reg| return self.gen_set_reg(ty, reg, val),
        .stack_offset => |off| return self.gen_set_stack(ty, off, val),
        .memory => {
            return self.fail("TODO implement set_reg_or_mem for memory", .{});
        },
        else => unreachable,
    }
}

fn gen_set_stack(self: *Self, ty: Type, stack_offset: u32, mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const abi_size = @as(u32, @int_cast(ty.abi_size(mod)));
    switch (mcv) {
        .dead => unreachable,
        .unreach, .none => return, // Nothing to do.
        .undef => {
            if (!self.want_safety())
                return; // The already existing value will do just fine.
            // TODO Upgrade this to a memset call when we have that available.
            switch (abi_size) {
                1 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaa }),
                2 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaa }),
                4 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaaaaaa }),
                8 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaaaaaaaaaaaaaa }),
                else => try self.gen_inline_memset(
                    .{ .ptr_stack_offset = stack_offset },
                    .{ .immediate = 0xaa },
                    .{ .immediate = abi_size },
                ),
            }
        },
        .compare_flags,
        .immediate,
        .ptr_stack_offset,
        => {
            const reg = try self.copy_to_tmp_register(ty, mcv);
            return self.gen_set_stack(ty, stack_offset, MCValue{ .register = reg });
        },
        .register => |reg| {
            switch (abi_size) {
                1, 2, 4, 8 => {
                    assert(std.mem.is_aligned_generic(u32, stack_offset, abi_size));

                    const tag: Mir.Inst.Tag = switch (abi_size) {
                        1 => .strb_stack,
                        2 => .strh_stack,
                        4, 8 => .str_stack,
                        else => unreachable, // unexpected abi size
                    };
                    const rt = self.register_alias(reg, ty);

                    _ = try self.add_inst(.{
                        .tag = tag,
                        .data = .{ .load_store_stack = .{
                            .rt = rt,
                            .offset = stack_offset,
                        } },
                    });
                },
                else => return self.fail("TODO implement storing other types abi_size={}", .{abi_size}),
            }
        },
        .register_with_overflow => |rwo| {
            const reg_lock = self.register_manager.lock_reg(rwo.reg);
            defer if (reg_lock) |locked_reg| self.register_manager.unlock_reg(locked_reg);

            const wrapped_ty = ty.struct_field_type(0, mod);
            try self.gen_set_stack(wrapped_ty, stack_offset, .{ .register = rwo.reg });

            const overflow_bit_ty = ty.struct_field_type(1, mod);
            const overflow_bit_offset = @as(u32, @int_cast(ty.struct_field_offset(1, mod)));
            const raw_cond_reg = try self.register_manager.alloc_reg(null, gp);
            const cond_reg = self.register_alias(raw_cond_reg, overflow_bit_ty);

            _ = try self.add_inst(.{
                .tag = .cset,
                .data = .{ .r_cond = .{
                    .rd = cond_reg,
                    .cond = rwo.flag,
                } },
            });

            try self.gen_set_stack(overflow_bit_ty, stack_offset - overflow_bit_offset, .{
                .register = cond_reg,
            });
        },
        .linker_load,
        .memory,
        .stack_argument_offset,
        .stack_offset,
        => {
            switch (mcv) {
                .stack_offset => |off| {
                    if (stack_offset == off)
                        return; // Copy stack variable to itself; nothing to do.
                },
                else => {},
            }

            if (abi_size <= 8) {
                const reg = try self.copy_to_tmp_register(ty, mcv);
                return self.gen_set_stack(ty, stack_offset, MCValue{ .register = reg });
            } else {
                const ptr_ty = try mod.single_mut_ptr_type(ty);

                // TODO call extern memcpy
                const regs = try self.register_manager.alloc_regs(5, .{ null, null, null, null, null }, gp);
                const regs_locks = self.register_manager.lock_regs_assume_unused(5, regs);
                defer for (regs_locks) |reg| {
                    self.register_manager.unlock_reg(reg);
                };

                const src_reg = regs[0];
                const dst_reg = regs[1];
                const len_reg = regs[2];
                const count_reg = regs[3];
                const tmp_reg = regs[4];

                switch (mcv) {
                    .stack_offset => |off| {
                        // sub src_reg, fp, #off
                        try self.gen_set_reg(ptr_ty, src_reg, .{ .ptr_stack_offset = off });
                    },
                    .stack_argument_offset => |off| {
                        _ = try self.add_inst(.{
                            .tag = .ldr_ptr_stack_argument,
                            .data = .{ .load_store_stack = .{
                                .rt = src_reg,
                                .offset = off,
                            } },
                        });
                    },
                    .memory => |addr| try self.gen_set_reg(Type.usize, src_reg, .{ .immediate = addr }),
                    .linker_load => |load_struct| {
                        const tag: Mir.Inst.Tag = switch (load_struct.type) {
                            .got => .load_memory_ptr_got,
                            .direct => .load_memory_ptr_direct,
                            .import => unreachable,
                        };
                        const atom_index = switch (self.bin_file.tag) {
                            .macho => {
                                // const macho_file = self.bin_file.cast(link.File.MachO).?;
                                // const atom = try macho_file.get_or_create_atom_for_decl(self.owner_decl);
                                // break :blk macho_file.get_atom(atom).get_symbol_index().?;
                                @panic("TODO gen_set_stack");
                            },
                            .coff => blk: {
                                const coff_file = self.bin_file.cast(link.File.Coff).?;
                                const atom = try coff_file.get_or_create_atom_for_decl(self.owner_decl);
                                break :blk coff_file.get_atom(atom).get_symbol_index().?;
                            },
                            else => unreachable, // unsupported target format
                        };
                        _ = try self.add_inst(.{
                            .tag = tag,
                            .data = .{
                                .payload = try self.add_extra(Mir.LoadMemoryPie{
                                    .register = @int_from_enum(src_reg),
                                    .atom_index = atom_index,
                                    .sym_index = load_struct.sym_index,
                                }),
                            },
                        });
                    },
                    else => unreachable,
                }

                // sub dst_reg, fp, #stack_offset
                try self.gen_set_reg(ptr_ty, dst_reg, .{ .ptr_stack_offset = stack_offset });

                // mov len, #abi_size
                try self.gen_set_reg(Type.usize, len_reg, .{ .immediate = abi_size });

                // memcpy(src, dst, len)
                try self.gen_inline_memcpy(src_reg, dst_reg, len_reg, count_reg, tmp_reg);
            }
        },
    }
}

fn gen_set_reg(self: *Self, ty: Type, reg: Register, mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    switch (mcv) {
        .dead => unreachable,
        .unreach, .none => return, // Nothing to do.
        .undef => {
            if (!self.want_safety())
                return; // The already existing value will do just fine.
            // Write the debug undefined value.
            switch (reg.size()) {
                32 => return self.gen_set_reg(ty, reg, .{ .immediate = 0xaaaaaaaa }),
                64 => return self.gen_set_reg(ty, reg, .{ .immediate = 0xaaaaaaaaaaaaaaaa }),
                else => unreachable, // unexpected register size
            }
        },
        .ptr_stack_offset => |off| {
            _ = try self.add_inst(.{
                .tag = .ldr_ptr_stack,
                .data = .{ .load_store_stack = .{
                    .rt = reg,
                    .offset = @as(u32, @int_cast(off)),
                } },
            });
        },
        .compare_flags => |condition| {
            _ = try self.add_inst(.{
                .tag = .cset,
                .data = .{ .r_cond = .{
                    .rd = reg,
                    .cond = condition,
                } },
            });
        },
        .immediate => |x| {
            _ = try self.add_inst(.{
                .tag = .movz,
                .data = .{ .r_imm16_sh = .{ .rd = reg, .imm16 = @as(u16, @truncate(x)) } },
            });

            if (x & 0x0000_0000_ffff_0000 != 0) {
                _ = try self.add_inst(.{
                    .tag = .movk,
                    .data = .{ .r_imm16_sh = .{ .rd = reg, .imm16 = @as(u16, @truncate(x >> 16)), .hw = 1 } },
                });
            }

            if (reg.size() == 64) {
                if (x & 0x0000_ffff_0000_0000 != 0) {
                    _ = try self.add_inst(.{
                        .tag = .movk,
                        .data = .{ .r_imm16_sh = .{ .rd = reg, .imm16 = @as(u16, @truncate(x >> 32)), .hw = 2 } },
                    });
                }
                if (x & 0xffff_0000_0000_0000 != 0) {
                    _ = try self.add_inst(.{
                        .tag = .movk,
                        .data = .{ .r_imm16_sh = .{ .rd = reg, .imm16 = @as(u16, @truncate(x >> 48)), .hw = 3 } },
                    });
                }
            }
        },
        .register => |src_reg| {
            assert(src_reg.size() == reg.size());

            // If the registers are the same, nothing to do.
            if (src_reg.id() == reg.id())
                return;

            // mov reg, src_reg
            _ = try self.add_inst(.{
                .tag = .mov_register,
                .data = .{ .rr = .{ .rd = reg, .rn = src_reg } },
            });
        },
        .register_with_overflow => unreachable, // doesn't fit into a register
        .linker_load => |load_struct| {
            const tag: Mir.Inst.Tag = switch (load_struct.type) {
                .got => .load_memory_got,
                .direct => .load_memory_direct,
                .import => .load_memory_import,
            };
            const atom_index = switch (self.bin_file.tag) {
                .macho => {
                    @panic("TODO gen_set_reg");
                    // const macho_file = self.bin_file.cast(link.File.MachO).?;
                    // const atom = try macho_file.get_or_create_atom_for_decl(self.owner_decl);
                    // break :blk macho_file.get_atom(atom).get_symbol_index().?;
                },
                .coff => blk: {
                    const coff_file = self.bin_file.cast(link.File.Coff).?;
                    const atom = try coff_file.get_or_create_atom_for_decl(self.owner_decl);
                    break :blk coff_file.get_atom(atom).get_symbol_index().?;
                },
                else => unreachable, // unsupported target format
            };
            _ = try self.add_inst(.{
                .tag = tag,
                .data = .{
                    .payload = try self.add_extra(Mir.LoadMemoryPie{
                        .register = @int_from_enum(reg),
                        .atom_index = atom_index,
                        .sym_index = load_struct.sym_index,
                    }),
                },
            });
        },
        .memory => |addr| {
            // The value is in memory at a hard-coded address.
            // If the type is a pointer, it means the pointer address is at this memory location.
            try self.gen_set_reg(ty, reg.to_x(), .{ .immediate = addr });
            try self.gen_ldr_register(reg, reg.to_x(), ty);
        },
        .stack_offset => |off| {
            const abi_size = ty.abi_size(mod);

            switch (abi_size) {
                1, 2, 4, 8 => {
                    const tag: Mir.Inst.Tag = switch (abi_size) {
                        1 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsb_stack else .ldrb_stack,
                        2 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsh_stack else .ldrh_stack,
                        4, 8 => .ldr_stack,
                        else => unreachable, // unexpected abi size
                    };

                    _ = try self.add_inst(.{
                        .tag = tag,
                        .data = .{ .load_store_stack = .{
                            .rt = reg,
                            .offset = @as(u32, @int_cast(off)),
                        } },
                    });
                },
                3, 5, 6, 7 => return self.fail("TODO implement gen_set_reg types size {}", .{abi_size}),
                else => unreachable,
            }
        },
        .stack_argument_offset => |off| {
            const abi_size = ty.abi_size(mod);

            switch (abi_size) {
                1, 2, 4, 8 => {
                    const tag: Mir.Inst.Tag = switch (abi_size) {
                        1 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsb_stack_argument else .ldrb_stack_argument,
                        2 => if (ty.is_signed_int(mod)) Mir.Inst.Tag.ldrsh_stack_argument else .ldrh_stack_argument,
                        4, 8 => .ldr_stack_argument,
                        else => unreachable, // unexpected abi size
                    };

                    _ = try self.add_inst(.{
                        .tag = tag,
                        .data = .{ .load_store_stack = .{
                            .rt = reg,
                            .offset = @as(u32, @int_cast(off)),
                        } },
                    });
                },
                3, 5, 6, 7 => return self.fail("TODO implement gen_set_reg types size {}", .{abi_size}),
                else => unreachable,
            }
        },
    }
}

fn gen_set_stack_argument(self: *Self, ty: Type, stack_offset: u32, mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const abi_size = @as(u32, @int_cast(ty.abi_size(mod)));
    switch (mcv) {
        .dead => unreachable,
        .none, .unreach => return,
        .undef => {
            if (!self.want_safety())
                return; // The already existing value will do just fine.
            // TODO Upgrade this to a memset call when we have that available.
            switch (ty.abi_size(mod)) {
                1 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaa }),
                2 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaa }),
                4 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaaaaaa }),
                8 => return self.gen_set_stack(ty, stack_offset, .{ .immediate = 0xaaaaaaaaaaaaaaaa }),
                else => return self.fail("TODO implement memset", .{}),
            }
        },
        .register => |reg| {
            switch (abi_size) {
                1, 2, 4, 8 => {
                    const tag: Mir.Inst.Tag = switch (abi_size) {
                        1 => .strb_immediate,
                        2 => .strh_immediate,
                        4, 8 => .str_immediate,
                        else => unreachable, // unexpected abi size
                    };
                    const rt = self.register_alias(reg, ty);
                    const offset = switch (abi_size) {
                        1 => blk: {
                            if (math.cast(u12, stack_offset)) |imm| {
                                break :blk Instruction.LoadStoreOffset.imm(imm);
                            } else {
                                return self.fail("TODO gen_set_stack_argument byte with larger offset", .{});
                            }
                        },
                        2 => blk: {
                            assert(std.mem.is_aligned_generic(u32, stack_offset, 2)); // misaligned stack entry
                            if (math.cast(u12, @div_exact(stack_offset, 2))) |imm| {
                                break :blk Instruction.LoadStoreOffset.imm(imm);
                            } else {
                                return self.fail("TODO getSetStackArgument halfword with larger offset", .{});
                            }
                        },
                        4, 8 => blk: {
                            const alignment = abi_size;
                            assert(std.mem.is_aligned_generic(u32, stack_offset, alignment)); // misaligned stack entry
                            if (math.cast(u12, @div_exact(stack_offset, alignment))) |imm| {
                                break :blk Instruction.LoadStoreOffset.imm(imm);
                            } else {
                                return self.fail("TODO gen_set_stack_argument with larger offset", .{});
                            }
                        },
                        else => unreachable,
                    };

                    _ = try self.add_inst(.{
                        .tag = tag,
                        .data = .{ .load_store_register_immediate = .{
                            .rt = rt,
                            .rn = .sp,
                            .offset = offset.immediate,
                        } },
                    });
                },
                else => return self.fail("TODO gen_set_stack_argument other types abi_size={}", .{abi_size}),
            }
        },
        .register_with_overflow => {
            return self.fail("TODO implement gen_set_stack_argument {}", .{mcv});
        },
        .linker_load,
        .memory,
        .stack_argument_offset,
        .stack_offset,
        => {
            if (abi_size <= 4) {
                const reg = try self.copy_to_tmp_register(ty, mcv);
                return self.gen_set_stack_argument(ty, stack_offset, MCValue{ .register = reg });
            } else {
                const ptr_ty = try mod.single_mut_ptr_type(ty);

                // TODO call extern memcpy
                const regs = try self.register_manager.alloc_regs(5, .{ null, null, null, null, null }, gp);
                const regs_locks = self.register_manager.lock_regs_assume_unused(5, regs);
                defer for (regs_locks) |reg| {
                    self.register_manager.unlock_reg(reg);
                };

                const src_reg = regs[0];
                const dst_reg = regs[1];
                const len_reg = regs[2];
                const count_reg = regs[3];
                const tmp_reg = regs[4];

                switch (mcv) {
                    .stack_offset => |off| {
                        // sub src_reg, fp, #off
                        try self.gen_set_reg(ptr_ty, src_reg, .{ .ptr_stack_offset = off });
                    },
                    .stack_argument_offset => |off| {
                        _ = try self.add_inst(.{
                            .tag = .ldr_ptr_stack_argument,
                            .data = .{ .load_store_stack = .{
                                .rt = src_reg,
                                .offset = off,
                            } },
                        });
                    },
                    .memory => |addr| try self.gen_set_reg(ptr_ty, src_reg, .{ .immediate = @as(u32, @int_cast(addr)) }),
                    .linker_load => |load_struct| {
                        const tag: Mir.Inst.Tag = switch (load_struct.type) {
                            .got => .load_memory_ptr_got,
                            .direct => .load_memory_ptr_direct,
                            .import => unreachable,
                        };
                        const atom_index = switch (self.bin_file.tag) {
                            .macho => {
                                @panic("TODO gen_set_stack_argument");
                                // const macho_file = self.bin_file.cast(link.File.MachO).?;
                                // const atom = try macho_file.get_or_create_atom_for_decl(self.owner_decl);
                                // break :blk macho_file.get_atom(atom).get_symbol_index().?;
                            },
                            .coff => blk: {
                                const coff_file = self.bin_file.cast(link.File.Coff).?;
                                const atom = try coff_file.get_or_create_atom_for_decl(self.owner_decl);
                                break :blk coff_file.get_atom(atom).get_symbol_index().?;
                            },
                            else => unreachable, // unsupported target format
                        };
                        _ = try self.add_inst(.{
                            .tag = tag,
                            .data = .{
                                .payload = try self.add_extra(Mir.LoadMemoryPie{
                                    .register = @int_from_enum(src_reg),
                                    .atom_index = atom_index,
                                    .sym_index = load_struct.sym_index,
                                }),
                            },
                        });
                    },
                    else => unreachable,
                }

                // add dst_reg, sp, #stack_offset
                _ = try self.add_inst(.{
                    .tag = .add_immediate,
                    .data = .{ .rr_imm12_sh = .{
                        .rd = dst_reg,
                        .rn = .sp,
                        .imm12 = math.cast(u12, stack_offset) orelse {
                            return self.fail("TODO load: set reg to stack offset with all possible offsets", .{});
                        },
                    } },
                });

                // mov len, #abi_size
                try self.gen_set_reg(Type.usize, len_reg, .{ .immediate = abi_size });

                // memcpy(src, dst, len)
                try self.gen_inline_memcpy(src_reg, dst_reg, len_reg, count_reg, tmp_reg);
            }
        },
        .compare_flags,
        .immediate,
        .ptr_stack_offset,
        => {
            const reg = try self.copy_to_tmp_register(ty, mcv);
            return self.gen_set_stack_argument(ty, stack_offset, MCValue{ .register = reg });
        },
    }
}

fn air_int_from_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result = try self.resolve_inst(un_op);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_bit_cast(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = if (self.liveness.is_unused(inst)) .dead else result: {
        const operand = try self.resolve_inst(ty_op.operand);
        if (self.reuse_operand(inst, ty_op.operand, 0, operand)) break :result operand;

        const operand_lock = switch (operand) {
            .register => |reg| self.register_manager.lock_reg(reg),
            .register_with_overflow => |rwo| self.register_manager.lock_reg(rwo.reg),
            else => null,
        };
        defer if (operand_lock) |lock| self.register_manager.unlock_reg(lock);

        const dest_ty = self.type_of_index(inst);
        const dest = try self.alloc_reg_or_mem(dest_ty, true, inst);
        try self.set_reg_or_mem(dest_ty, dest, operand);
        break :result dest;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_array_to_slice(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else result: {
        const ptr_ty = self.type_of(ty_op.operand);
        const ptr = try self.resolve_inst(ty_op.operand);
        const array_ty = ptr_ty.child_type(mod);
        const array_len = @as(u32, @int_cast(array_ty.array_len(mod)));
        const ptr_bytes = 8;
        const stack_offset = try self.alloc_mem(ptr_bytes * 2, .@"8", inst);
        try self.gen_set_stack(ptr_ty, stack_offset, ptr);
        try self.gen_set_stack(Type.usize, stack_offset - ptr_bytes, .{ .immediate = array_len });
        break :result MCValue{ .stack_offset = stack_offset };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_float_from_int(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_float_from_int for {}", .{
        self.target.cpu.arch,
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_float(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_int_from_float for {}", .{
        self.target.cpu.arch,
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_cmpxchg(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Block, ty_pl.payload);
    _ = extra;

    return self.fail("TODO implement air_cmpxchg for {}", .{
        self.target.cpu.arch,
    });
}

fn air_atomic_rmw(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_cmpxchg for {}", .{self.target.cpu.arch});
}

fn air_atomic_load(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_atomic_load for {}", .{self.target.cpu.arch});
}

fn air_atomic_store(self: *Self, inst: Air.Inst.Index, order: std.builtin.AtomicOrder) !void {
    _ = inst;
    _ = order;
    return self.fail("TODO implement air_atomic_store for {}", .{self.target.cpu.arch});
}

fn air_memset(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    _ = inst;
    if (safety) {
        // TODO if the value is undef, write 0xaa bytes to dest
    } else {
        // TODO if the value is undef, don't lower this instruction
    }
    return self.fail("TODO implement air_memset for {}", .{self.target.cpu.arch});
}

fn air_memcpy(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_memcpy for {}", .{self.target.cpu.arch});
}

fn air_tag_name(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else {
        _ = operand;
        return self.fail("TODO implement air_tag_name for aarch64", .{});
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_error_name(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else {
        _ = operand;
        return self.fail("TODO implement air_error_name for aarch64", .{});
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_splat(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_splat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_select(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_select for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ pl_op.operand, extra.lhs, extra.rhs });
}

fn air_shuffle(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Shuffle, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_shuffle for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ extra.a, extra.b, .none });
}

fn air_reduce(self: *Self, inst: Air.Inst.Index) !void {
    const reduce = self.air.instructions.items(.data)[@int_from_enum(inst)].reduce;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else return self.fail("TODO implement air_reduce for aarch64", .{});
    return self.finish_air(inst, result, .{ reduce.operand, .none, .none });
}

fn air_aggregate_init(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const vector_ty = self.type_of_index(inst);
    const len = vector_ty.vector_len(mod);
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const elements = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[ty_pl.payload..][0..len]));
    const result: MCValue = res: {
        if (self.liveness.is_unused(inst)) break :res MCValue.dead;
        return self.fail("TODO implement air_aggregate_init for {}", .{self.target.cpu.arch});
    };

    if (elements.len <= Liveness.bpi - 1) {
        var buf = [1]Air.Inst.Ref{.none} ** (Liveness.bpi - 1);
        @memcpy(buf[0..elements.len], elements);
        return self.finish_air(inst, result, buf);
    }
    var bt = try self.iterate_big_tomb(inst, elements.len);
    for (elements) |elem| {
        bt.feed(elem);
    }
    return bt.finish_air(result);
}

fn air_union_init(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.UnionInit, ty_pl.payload).data;
    _ = extra;
    return self.fail("TODO implement air_union_init for aarch64", .{});
}

fn air_prefetch(self: *Self, inst: Air.Inst.Index) !void {
    const prefetch = self.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;
    return self.finish_air(inst, MCValue.dead, .{ prefetch.ptr, .none, .none });
}

fn air_mul_add(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .dead else {
        return self.fail("TODO implement air_mul_add for aarch64", .{});
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, pl_op.operand });
}

fn air_try(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Try, pl_op.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
    const result: MCValue = result: {
        const error_union_bind: ReadArg.Bind = .{ .inst = pl_op.operand };
        const error_union_ty = self.type_of(pl_op.operand);
        const error_union_size = @as(u32, @int_cast(error_union_ty.abi_size(mod)));
        const error_union_align = error_union_ty.abi_alignment(mod);

        // The error union will die in the body. However, we need the
        // error union after the body in order to extract the payload
        // of the error union, so we create a copy of it
        const error_union_copy = try self.alloc_mem(error_union_size, error_union_align, null);
        try self.gen_set_stack(error_union_ty, error_union_copy, try error_union_bind.resolve_to_mcv(self));

        const is_err_result = try self.is_err(error_union_bind, error_union_ty);
        const reloc = try self.cond_br(is_err_result);

        try self.gen_body(body);
        try self.perform_reloc(reloc);

        break :result try self.err_union_payload(.{ .mcv = .{ .stack_offset = error_union_copy } }, error_union_ty, null);
    };
    return self.finish_air(inst, result, .{ pl_op.operand, .none, .none });
}

fn air_try_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.TryPtr, ty_pl.payload);
    const body = self.air.extra[extra.end..][0..extra.data.body_len];
    _ = body;
    return self.fail("TODO implement air_try_ptr for arm", .{});
    // return self.finish_air(inst, result, .{ extra.data.ptr, .none, .none });
}

fn resolve_inst(self: *Self, inst: Air.Inst.Ref) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;

    // If the type has no codegen bits, no need to store it.
    const inst_ty = self.type_of(inst);
    if (!inst_ty.has_runtime_bits_ignore_comptime(mod) and !inst_ty.is_error(mod))
        return MCValue{ .none = {} };

    const inst_index = inst.to_index() orelse return self.gen_typed_value((try self.air.value(inst, mod)).?);

    return self.get_resolved_inst_value(inst_index);
}

fn get_resolved_inst_value(self: *Self, inst: Air.Inst.Index) MCValue {
    // Treat each stack item as a "layer" on top of the previous one.
    var i: usize = self.branch_stack.items.len;
    while (true) {
        i -= 1;
        if (self.branch_stack.items[i].inst_table.get(inst)) |mcv| {
            assert(mcv != .dead);
            return mcv;
        }
    }
}

fn gen_typed_value(self: *Self, val: Value) InnerError!MCValue {
    const mcv: MCValue = switch (try codegen.gen_typed_value(
        self.bin_file,
        self.src_loc,
        val,
        self.owner_decl,
    )) {
        .mcv => |mcv| switch (mcv) {
            .none => .none,
            .undef => .undef,
            .immediate => |imm| .{ .immediate = imm },
            .memory => |addr| .{ .memory = addr },
            .load_got => |sym_index| .{ .linker_load = .{ .type = .got, .sym_index = sym_index } },
            .load_direct => |sym_index| .{ .linker_load = .{ .type = .direct, .sym_index = sym_index } },
            .load_symbol, .load_tlv => unreachable, // TODO
        },
        .fail => |msg| {
            self.err_msg = msg;
            return error.CodegenFail;
        },
    };
    return mcv;
}

const CallMCValues = struct {
    args: []MCValue,
    return_value: MCValue,
    stack_byte_count: u32,
    stack_align: u32,

    fn deinit(self: *CallMCValues, func: *Self) void {
        func.gpa.free(self.args);
        self.* = undefined;
    }
};

/// Caller must call `CallMCValues.deinit`.
fn resolve_calling_convention_values(self: *Self, fn_ty: Type) !CallMCValues {
    const mod = self.bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    const fn_info = mod.type_to_func(fn_ty).?;
    const cc = fn_info.cc;
    var result: CallMCValues = .{
        .args = try self.gpa.alloc(MCValue, fn_info.param_types.len),
        // These undefined values must be populated before returning from this function.
        .return_value = undefined,
        .stack_byte_count = undefined,
        .stack_align = undefined,
    };
    errdefer self.gpa.free(result.args);

    const ret_ty = fn_ty.fn_return_type(mod);

    switch (cc) {
        .Naked => {
            assert(result.args.len == 0);
            result.return_value = .{ .unreach = {} };
            result.stack_byte_count = 0;
            result.stack_align = 1;
            return result;
        },
        .C => {
            // ARM64 Procedure Call Standard
            var ncrn: usize = 0; // Next Core Register Number
            var nsaa: u32 = 0; // Next stacked argument address

            if (ret_ty.zig_type_tag(mod) == .NoReturn) {
                result.return_value = .{ .unreach = {} };
            } else if (!ret_ty.has_runtime_bits_ignore_comptime(mod) and !ret_ty.is_error(mod)) {
                result.return_value = .{ .none = {} };
            } else {
                const ret_ty_size = @as(u32, @int_cast(ret_ty.abi_size(mod)));
                if (ret_ty_size == 0) {
                    assert(ret_ty.is_error(mod));
                    result.return_value = .{ .immediate = 0 };
                } else if (ret_ty_size <= 8) {
                    result.return_value = .{ .register = self.register_alias(c_abi_int_return_regs[0], ret_ty) };
                } else {
                    return self.fail("TODO support more return types for ARM backend", .{});
                }
            }

            for (fn_info.param_types.get(ip), result.args) |ty, *result_arg| {
                const param_size = @as(u32, @int_cast(Type.from_interned(ty).abi_size(mod)));
                if (param_size == 0) {
                    result_arg.* = .{ .none = {} };
                    continue;
                }

                // We round up NCRN only for non-Apple platforms which allow the 16-byte aligned
                // values to spread across odd-numbered registers.
                if (Type.from_interned(ty).abi_alignment(mod) == .@"16" and !self.target.is_darwin()) {
                    // Round up NCRN to the next even number
                    ncrn += ncrn % 2;
                }

                if (std.math.div_ceil(u32, param_size, 8) catch unreachable <= 8 - ncrn) {
                    if (param_size <= 8) {
                        result_arg.* = .{ .register = self.register_alias(c_abi_int_param_regs[ncrn], Type.from_interned(ty)) };
                        ncrn += 1;
                    } else {
                        return self.fail("TODO MCValues with multiple registers", .{});
                    }
                } else if (ncrn < 8 and nsaa == 0) {
                    return self.fail("TODO MCValues split between registers and stack", .{});
                } else {
                    ncrn = 8;
                    // TODO Apple allows the arguments on the stack to be non-8-byte aligned provided
                    // that the entire stack space consumed by the arguments is 8-byte aligned.
                    if (Type.from_interned(ty).abi_alignment(mod) == .@"8") {
                        if (nsaa % 8 != 0) {
                            nsaa += 8 - (nsaa % 8);
                        }
                    }

                    result_arg.* = .{ .stack_argument_offset = nsaa };
                    nsaa += param_size;
                }
            }

            result.stack_byte_count = nsaa;
            result.stack_align = 16;
        },
        .Unspecified => {
            if (ret_ty.zig_type_tag(mod) == .NoReturn) {
                result.return_value = .{ .unreach = {} };
            } else if (!ret_ty.has_runtime_bits_ignore_comptime(mod) and !ret_ty.is_error(mod)) {
                result.return_value = .{ .none = {} };
            } else {
                const ret_ty_size = @as(u32, @int_cast(ret_ty.abi_size(mod)));
                if (ret_ty_size == 0) {
                    assert(ret_ty.is_error(mod));
                    result.return_value = .{ .immediate = 0 };
                } else if (ret_ty_size <= 8) {
                    result.return_value = .{ .register = self.register_alias(.x0, ret_ty) };
                } else {
                    // The result is returned by reference, not by
                    // value. This means that x0 (or w0 when pointer
                    // size is 32 bits) will contain the address of
                    // where this function should write the result
                    // into.
                    result.return_value = .{ .stack_offset = 0 };
                }
            }

            var stack_offset: u32 = 0;

            for (fn_info.param_types.get(ip), result.args) |ty, *result_arg| {
                if (Type.from_interned(ty).abi_size(mod) > 0) {
                    const param_size: u32 = @int_cast(Type.from_interned(ty).abi_size(mod));
                    const param_alignment = Type.from_interned(ty).abi_alignment(mod);

                    stack_offset = @int_cast(param_alignment.forward(stack_offset));
                    result_arg.* = .{ .stack_argument_offset = stack_offset };
                    stack_offset += param_size;
                } else {
                    result_arg.* = .{ .none = {} };
                }
            }

            result.stack_byte_count = stack_offset;
            result.stack_align = 16;
        },
        else => return self.fail("TODO implement function parameters for {} on aarch64", .{cc}),
    }

    return result;
}

/// TODO support scope overrides. Also note this logic is duplicated with `Module.want_safety`.
fn want_safety(self: *Self) bool {
    return switch (self.bin_file.comp.root_mod.optimize_mode) {
        .Debug => true,
        .ReleaseSafe => true,
        .ReleaseFast => false,
        .ReleaseSmall => false,
    };
}

fn fail(self: *Self, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(self.err_msg == null);
    self.err_msg = try ErrorMsg.create(self.gpa, self.src_loc, format, args);
    return error.CodegenFail;
}

fn fail_symbol(self: *Self, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(self.err_msg == null);
    self.err_msg = try ErrorMsg.create(self.gpa, self.src_loc, format, args);
    return error.CodegenFail;
}

fn parse_reg_name(name: []const u8) ?Register {
    if (@hasDecl(Register, "parse_reg_name")) {
        return Register.parse_reg_name(name);
    }
    return std.meta.string_to_enum(Register, name);
}

fn register_alias(self: *Self, reg: Register, ty: Type) Register {
    const mod = self.bin_file.comp.module.?;
    const abi_size = ty.abi_size(mod);

    switch (reg.class()) {
        .general_purpose => {
            if (abi_size == 0) {
                unreachable; // should be comptime-known
            } else if (abi_size <= 4) {
                return reg.to_w();
            } else if (abi_size <= 8) {
                return reg.to_x();
            } else unreachable;
        },
        .stack_pointer => unreachable, // we can't store/load the sp
        .floating_point => {
            return switch (ty.float_bits(self.target.*)) {
                16 => reg.to_h(),
                32 => reg.to_s(),
                64 => reg.to_d(),
                128 => reg.to_q(),

                80 => unreachable, // f80 registers don't exist
                else => unreachable,
            };
        },
    }
}

fn type_of(self: *Self, inst: Air.Inst.Ref) Type {
    const mod = self.bin_file.comp.module.?;
    return self.air.type_of(inst, &mod.intern_pool);
}

fn type_of_index(self: *Self, inst: Air.Inst.Index) Type {
    const mod = self.bin_file.comp.module.?;
    return self.air.type_of_index(inst, &mod.intern_pool);
}
