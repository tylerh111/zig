const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const math = std.math;
const assert = std.debug.assert;
const Air = @import("../../Air.zig");
const Mir = @import("Mir.zig");
const Emit = @import("Emit.zig");
const Liveness = @import("../../Liveness.zig");
const Type = @import("../../type.zig").Type;
const Value = @import("../../Value.zig");
const link = @import("../../link.zig");
const Module = @import("../../Module.zig");
const Package = @import("../../Package.zig");
const InternPool = @import("../../InternPool.zig");
const Compilation = @import("../../Compilation.zig");
const ErrorMsg = Module.ErrorMsg;
const Target = std.Target;
const Allocator = mem.Allocator;
const trace = @import("../../tracy.zig").trace;
const DW = std.dwarf;
const leb128 = std.leb;
const log = std.log.scoped(.riscv_codegen);
const tracking_log = std.log.scoped(.tracking);
const build_options = @import("build_options");
const codegen = @import("../../codegen.zig");
const Alignment = InternPool.Alignment;

const CodeGenError = codegen.CodeGenError;
const Result = codegen.Result;
const DebugInfoOutput = codegen.DebugInfoOutput;

const bits = @import("bits.zig");
const abi = @import("abi.zig");
const Register = bits.Register;
const Immediate = bits.Immediate;
const Memory = bits.Memory;
const FrameIndex = bits.FrameIndex;
const RegisterManager = abi.RegisterManager;
const RegisterLock = RegisterManager.RegisterLock;
const callee_preserved_regs = abi.callee_preserved_regs;
/// General Purpose
const gp = abi.RegisterClass.gp;
/// Function Args
const fa = abi.RegisterClass.fa;
/// Function Returns
const fr = abi.RegisterClass.fr;
/// Temporary Use
const tp = abi.RegisterClass.tp;

const InnerError = CodeGenError || error{OutOfRegisters};

const RegisterView = enum(u1) {
    caller,
    callee,
};

gpa: Allocator,
air: Air,
mod: *Package.Module,
liveness: Liveness,
bin_file: *link.File,
target: *const std.Target,
func_index: InternPool.Index,
code: *std.ArrayList(u8),
debug_output: DebugInfoOutput,
err_msg: ?*ErrorMsg,
args: []MCValue,
ret_mcv: InstTracking,
fn_type: Type,
arg_index: usize,
src_loc: Module.SrcLoc,

/// MIR Instructions
mir_instructions: std.MultiArrayList(Mir.Inst) = .{},
/// MIR extra data
mir_extra: std.ArrayListUnmanaged(u32) = .{},

/// Byte offset within the source file of the ending curly.
end_di_line: u32,
end_di_column: u32,

scope_generation: u32,

/// The value is an offset into the `Function` `code` from the beginning.
/// To perform the reloc, write 32-bit signed little-endian integer
/// which is a relative jump, based on the address following the reloc.
exitlude_jump_relocs: std.ArrayListUnmanaged(usize) = .{},

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

const_tracking: ConstTrackingMap = .{},
inst_tracking: InstTrackingMap = .{},

frame_allocs: std.MultiArrayList(FrameAlloc) = .{},
free_frame_indices: std.AutoArrayHashMapUnmanaged(FrameIndex, void) = .{},
frame_locs: std.MultiArrayList(Mir.FrameLoc) = .{},

/// Debug field, used to find bugs in the compiler.
air_bookkeeping: @TypeOf(air_bookkeeping_init) = air_bookkeeping_init,

const air_bookkeeping_init = if (std.debug.runtime_safety) @as(usize, 0) else {};

const SymbolOffset = struct { sym: u32, off: i32 = 0 };
const RegisterOffset = struct { reg: Register, off: i32 = 0 };
pub const FrameAddr = struct { index: FrameIndex, off: i32 = 0 };

const MCValue = union(enum) {
    /// No runtime bits. `void` types, empty structs, u0, enums with 1 tag, etc.
    /// TODO Look into deleting this tag and using `dead` instead, since every use
    /// of MCValue.none should be instead looking at the type and noticing it is 0 bits.
    none,
    /// Control flow will not allow this value to be observed.
    unreach,
    /// No more references to this value remain.
    /// The payload is the value of scope_generation at the point where the death occurred
    dead: u32,
    /// The value is undefined.
    undef,
    /// A pointer-sized integer that fits in a register.
    /// If the type is a pointer, this is the pointer address in virtual address space.
    immediate: u64,
    /// The value doesn't exist in memory yet.
    load_symbol: SymbolOffset,
    /// The address of the memory location not-yet-allocated by the linker.
    lea_symbol: SymbolOffset,
    /// The value is in a target-specific register.
    register: Register,
    /// The value is split across two registers
    register_pair: [2]Register,
    /// The value is in memory at a hard-coded address.
    /// If the type is a pointer, it means the pointer address is at this memory location.
    memory: u64,
    /// The value stored at an offset from a frame index
    /// Payload is a frame address.
    load_frame: FrameAddr,
    /// The address of an offset from a frame index
    /// Payload is a frame address.
    lea_frame: FrameAddr,
    air_ref: Air.Inst.Ref,
    /// The value is in memory at a constant offset from the address in a register.
    indirect: RegisterOffset,
    /// The value is a constant offset from the value in a register.
    register_offset: RegisterOffset,
    /// This indicates that we have already allocated a frame index for this instruction,
    /// but it has not been spilled there yet in the current control flow.
    /// Payload is a frame index.
    reserved_frame: FrameIndex,

    fn is_memory(mcv: MCValue) bool {
        return switch (mcv) {
            .memory, .indirect, .load_frame => true,
            else => false,
        };
    }

    fn is_immediate(mcv: MCValue) bool {
        return switch (mcv) {
            .immediate => true,
            else => false,
        };
    }

    fn is_mutable(mcv: MCValue) bool {
        return switch (mcv) {
            .none => unreachable,
            .unreach => unreachable,
            .dead => unreachable,

            .immediate,
            .memory,
            .lea_frame,
            .undef,
            .lea_symbol,
            .air_ref,
            .reserved_frame,
            => false,

            .register,
            .register_pair,
            .register_offset,
            .load_frame,
            .load_symbol,
            .indirect,
            => true,
        };
    }

    fn address(mcv: MCValue) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .immediate,
            .lea_frame,
            .register_offset,
            .register_pair,
            .register,
            .undef,
            .air_ref,
            .lea_symbol,
            .reserved_frame,
            => unreachable, // not in memory

            .load_symbol => |sym_off| .{ .lea_symbol = sym_off },
            .memory => |addr| .{ .immediate = addr },
            .load_frame => |off| .{ .lea_frame = off },
            .indirect => |reg_off| switch (reg_off.off) {
                0 => .{ .register = reg_off.reg },
                else => .{ .register_offset = reg_off },
            },
        };
    }

    fn deref(mcv: MCValue) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .memory,
            .indirect,
            .undef,
            .air_ref,
            .load_frame,
            .register_pair,
            .load_symbol,
            .reserved_frame,
            => unreachable, // not a pointer

            .immediate => |addr| .{ .memory = addr },
            .lea_frame => |off| .{ .load_frame = off },
            .register => |reg| .{ .indirect = .{ .reg = reg } },
            .register_offset => |reg_off| .{ .indirect = reg_off },
            .lea_symbol => |sym_off| .{ .load_symbol = sym_off },
        };
    }

    fn offset(mcv: MCValue, off: i32) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .air_ref,
            .reserved_frame,
            => unreachable, // not valid
            .register_pair,
            .memory,
            .indirect,
            .load_frame,
            .load_symbol,
            .lea_symbol,
            => switch (off) {
                0 => mcv,
                else => unreachable, // not offsettable
            },
            .immediate => |imm| .{ .immediate = @bit_cast(@as(i64, @bit_cast(imm)) +% off) },
            .register => |reg| .{ .register_offset = .{ .reg = reg, .off = off } },
            .register_offset => |reg_off| .{ .register_offset = .{ .reg = reg_off.reg, .off = reg_off.off + off } },
            .lea_frame => |frame_addr| .{
                .lea_frame = .{ .index = frame_addr.index, .off = frame_addr.off + off },
            },
        };
    }

    fn get_reg(mcv: MCValue) ?Register {
        return switch (mcv) {
            .register => |reg| reg,
            .register_offset, .indirect => |ro| ro.reg,
            else => null,
        };
    }

    fn get_regs(mcv: *const MCValue) []const Register {
        return switch (mcv.*) {
            .register => |*reg| @as(*const [1]Register, reg),
            .register_pair => |*regs| regs,
            .register_offset, .indirect => |*ro| @as(*const [1]Register, &ro.reg),
            else => &.{},
        };
    }
};

const Branch = struct {
    inst_table: std.AutoArrayHashMapUnmanaged(Air.Inst.Index, MCValue) = .{},

    fn deinit(self: *Branch, gpa: Allocator) void {
        self.inst_table.deinit(gpa);
        self.* = undefined;
    }
};

const InstTrackingMap = std.AutoArrayHashMapUnmanaged(Air.Inst.Index, InstTracking);
const ConstTrackingMap = std.AutoArrayHashMapUnmanaged(InternPool.Index, InstTracking);
const InstTracking = struct {
    long: MCValue,
    short: MCValue,

    fn init(result: MCValue) InstTracking {
        return .{ .long = switch (result) {
            .none,
            .unreach,
            .undef,
            .immediate,
            .memory,
            .load_frame,
            .lea_frame,
            .load_symbol,
            .lea_symbol,
            => result,
            .dead,
            .reserved_frame,
            .air_ref,
            => unreachable,
            .register,
            .register_pair,
            .register_offset,
            .indirect,
            => .none,
        }, .short = result };
    }

    fn get_reg(self: InstTracking) ?Register {
        return self.short.get_reg();
    }

    fn get_regs(self: *const InstTracking) []const Register {
        return self.short.get_regs();
    }

    fn spill(self: *InstTracking, function: *Self, inst: Air.Inst.Index) !void {
        if (std.meta.eql(self.long, self.short)) return; // Already spilled
        // Allocate or reuse frame index
        switch (self.long) {
            .none => self.long = try function.alloc_reg_or_mem(inst, false),
            .load_frame => {},
            .reserved_frame => |index| self.long = .{ .load_frame = .{ .index = index } },
            else => unreachable,
        }
        tracking_log.debug("spill %{d} from {} to {}", .{ inst, self.short, self.long });
        try function.gen_copy(function.type_of_index(inst), self.long, self.short);
    }

    fn reuse_frame(self: *InstTracking) void {
        switch (self.long) {
            .reserved_frame => |index| self.long = .{ .load_frame = .{ .index = index } },
            else => {},
        }
        self.short = switch (self.long) {
            .none,
            .unreach,
            .undef,
            .immediate,
            .memory,
            .load_frame,
            .lea_frame,
            .load_symbol,
            .lea_symbol,
            => self.long,
            .dead,
            .register,
            .register_pair,
            .register_offset,
            .indirect,
            .reserved_frame,
            .air_ref,
            => unreachable,
        };
    }

    fn track_spill(self: *InstTracking, function: *Self, inst: Air.Inst.Index) !void {
        try function.free_value(self.short);
        self.reuse_frame();
        tracking_log.debug("%{d} => {} (spilled)", .{ inst, self.* });
    }

    fn verify_materialize(self: InstTracking, target: InstTracking) void {
        switch (self.long) {
            .none,
            .unreach,
            .undef,
            .immediate,
            .memory,
            .lea_frame,
            .load_symbol,
            .lea_symbol,
            => assert(std.meta.eql(self.long, target.long)),
            .load_frame,
            .reserved_frame,
            => switch (target.long) {
                .none,
                .load_frame,
                .reserved_frame,
                => {},
                else => unreachable,
            },
            .dead,
            .register,
            .register_pair,
            .register_offset,
            .indirect,
            .air_ref,
            => unreachable,
        }
    }

    fn materialize(
        self: *InstTracking,
        function: *Self,
        inst: Air.Inst.Index,
        target: InstTracking,
    ) !void {
        self.verify_materialize(target);
        try self.materialize_unsafe(function, inst, target);
    }

    fn materialize_unsafe(
        self: InstTracking,
        function: *Self,
        inst: Air.Inst.Index,
        target: InstTracking,
    ) !void {
        const ty = function.type_of_index(inst);
        if ((self.long == .none or self.long == .reserved_frame) and target.long == .load_frame)
            try function.gen_copy(ty, target.long, self.short);
        try function.gen_copy(ty, target.short, self.short);
    }

    fn track_materialize(self: *InstTracking, inst: Air.Inst.Index, target: InstTracking) void {
        self.verify_materialize(target);
        // Don't clobber reserved frame indices
        self.long = if (target.long == .none) switch (self.long) {
            .load_frame => |addr| .{ .reserved_frame = addr.index },
            .reserved_frame => self.long,
            else => target.long,
        } else target.long;
        self.short = target.short;
        tracking_log.debug("%{d} => {} (materialize)", .{ inst, self.* });
    }

    fn resurrect(self: *InstTracking, inst: Air.Inst.Index, scope_generation: u32) void {
        switch (self.short) {
            .dead => |die_generation| if (die_generation >= scope_generation) {
                self.reuse_frame();
                tracking_log.debug("%{d} => {} (resurrect)", .{ inst, self.* });
            },
            else => {},
        }
    }

    fn die(self: *InstTracking, function: *Self, inst: Air.Inst.Index) !void {
        if (self.short == .dead) return;
        try function.free_value(self.short);
        self.short = .{ .dead = function.scope_generation };
        tracking_log.debug("%{d} => {} (death)", .{ inst, self.* });
    }

    fn reuse(
        self: *InstTracking,
        function: *Self,
        new_inst: ?Air.Inst.Index,
        old_inst: Air.Inst.Index,
    ) void {
        self.short = .{ .dead = function.scope_generation };
        if (new_inst) |inst|
            tracking_log.debug("%{d} => {} (reuse %{d})", .{ inst, self.*, old_inst })
        else
            tracking_log.debug("tmp => {} (reuse %{d})", .{ self.*, old_inst });
    }

    fn live_out(self: *InstTracking, function: *Self, inst: Air.Inst.Index) void {
        for (self.get_regs()) |reg| {
            if (function.register_manager.is_reg_free(reg)) {
                tracking_log.debug("%{d} => {} (live-out)", .{ inst, self.* });
                continue;
            }

            const index = RegisterManager.index_of_reg_into_tracked(reg).?;
            const tracked_inst = function.register_manager.registers[index];
            const tracking = function.get_resolved_inst_value(tracked_inst);

            // Disable death.
            var found_reg = false;
            var remaining_reg: Register = .zero;
            for (tracking.get_regs()) |tracked_reg| if (tracked_reg.id() == reg.id()) {
                assert(!found_reg);
                found_reg = true;
            } else {
                assert(remaining_reg == .zero);
                remaining_reg = tracked_reg;
            };
            assert(found_reg);
            tracking.short = switch (remaining_reg) {
                .zero => .{ .dead = function.scope_generation },
                else => .{ .register = remaining_reg },
            };

            // Perform side-effects of free_value manually.
            function.register_manager.free_reg(reg);

            tracking_log.debug("%{d} => {} (live-out %{d})", .{ inst, self.*, tracked_inst });
        }
    }

    pub fn format(
        self: InstTracking,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (!std.meta.eql(self.long, self.short)) try writer.print("|{}| ", .{self.long});
        try writer.print("{}", .{self.short});
    }
};

const FrameAlloc = struct {
    abi_size: u31,
    spill_pad: u3,
    abi_align: Alignment,
    ref_count: u16,

    fn init(alloc_abi: struct { size: u64, pad: u3 = 0, alignment: Alignment }) FrameAlloc {
        return .{
            .abi_size = @int_cast(alloc_abi.size),
            .spill_pad = alloc_abi.pad,
            .abi_align = alloc_abi.alignment,
            .ref_count = 0,
        };
    }
    fn init_type(ty: Type, zcu: *Module) FrameAlloc {
        return init(.{
            .size = ty.abi_size(zcu),
            .alignment = ty.abi_alignment(zcu),
        });
    }
    fn init_spill(ty: Type, zcu: *Module) FrameAlloc {
        const abi_size = ty.abi_size(zcu);
        const spill_size = if (abi_size < 8)
            math.ceil_power_of_two_assert(u64, abi_size)
        else
            std.mem.align_forward(u64, abi_size, 8);
        return init(.{
            .size = spill_size,
            .pad = @int_cast(spill_size - abi_size),
            .alignment = ty.abi_alignment(zcu).max_strict(
                Alignment.from_nonzero_byte_units(@min(spill_size, 8)),
            ),
        });
    }
};

const StackAllocation = struct {
    inst: ?Air.Inst.Index,
    /// TODO: make the size inferred from the bits of the inst
    size: u32,
};

const BlockData = struct {
    relocs: std.ArrayListUnmanaged(Mir.Inst.Index) = .{},
    state: State,

    fn deinit(self: *BlockData, gpa: Allocator) void {
        self.relocs.deinit(gpa);
        self.* = undefined;
    }
};

const State = struct {
    registers: RegisterManager.TrackedRegisters,
    reg_tracking: [RegisterManager.RegisterBitSet.bit_length]InstTracking,
    free_registers: RegisterManager.RegisterBitSet,
    inst_tracking_len: u32,
    scope_generation: u32,
};

fn init_retroactive_state(self: *Self) State {
    var state: State = undefined;
    state.inst_tracking_len = @int_cast(self.inst_tracking.count());
    state.scope_generation = self.scope_generation;
    return state;
}

fn save_retroactive_state(self: *Self, state: *State) !void {
    const free_registers = self.register_manager.free_registers;
    var it = free_registers.iterator(.{ .kind = .unset });
    while (it.next()) |index| {
        const tracked_inst = self.register_manager.registers[index];
        state.registers[index] = tracked_inst;
        state.reg_tracking[index] = self.inst_tracking.get(tracked_inst).?;
    }
    state.free_registers = free_registers;
}

fn save_state(self: *Self) !State {
    var state = self.init_retroactive_state();
    try self.save_retroactive_state(&state);
    return state;
}

fn restore_state(self: *Self, state: State, deaths: []const Air.Inst.Index, comptime opts: struct {
    emit_instructions: bool,
    update_tracking: bool,
    resurrect: bool,
    close_scope: bool,
}) !void {
    if (opts.close_scope) {
        for (
            self.inst_tracking.keys()[state.inst_tracking_len..],
            self.inst_tracking.values()[state.inst_tracking_len..],
        ) |inst, *tracking| try tracking.die(self, inst);
        self.inst_tracking.shrink_retaining_capacity(state.inst_tracking_len);
    }

    if (opts.resurrect) for (
        self.inst_tracking.keys()[0..state.inst_tracking_len],
        self.inst_tracking.values()[0..state.inst_tracking_len],
    ) |inst, *tracking| tracking.resurrect(inst, state.scope_generation);
    for (deaths) |death| try self.process_death(death);

    const ExpectedContents = [@typeInfo(RegisterManager.TrackedRegisters).Array.len]RegisterLock;
    var stack align(@max(@alignOf(ExpectedContents), @alignOf(std.heap.StackFallbackAllocator(0)))) =
        if (opts.update_tracking)
    {} else std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);

    var reg_locks = if (opts.update_tracking) {} else try std.ArrayList(RegisterLock).init_capacity(
        stack.get(),
        @typeInfo(ExpectedContents).Array.len,
    );
    defer if (!opts.update_tracking) {
        for (reg_locks.items) |lock| self.register_manager.unlock_reg(lock);
        reg_locks.deinit();
    };

    for (0..state.registers.len) |index| {
        const current_maybe_inst = if (self.register_manager.free_registers.is_set(index))
            null
        else
            self.register_manager.registers[index];
        const target_maybe_inst = if (state.free_registers.is_set(index))
            null
        else
            state.registers[index];
        if (std.debug.runtime_safety) if (target_maybe_inst) |target_inst|
            assert(self.inst_tracking.get_index(target_inst).? < state.inst_tracking_len);
        if (opts.emit_instructions) {
            if (current_maybe_inst) |current_inst| {
                try self.inst_tracking.get_ptr(current_inst).?.spill(self, current_inst);
            }
            if (target_maybe_inst) |target_inst| {
                const target_tracking = self.inst_tracking.get_ptr(target_inst).?;
                try target_tracking.materialize(self, target_inst, state.reg_tracking[index]);
            }
        }
        if (opts.update_tracking) {
            if (current_maybe_inst) |current_inst| {
                try self.inst_tracking.get_ptr(current_inst).?.track_spill(self, current_inst);
            }
            {
                const reg = RegisterManager.reg_at_tracked_index(@int_cast(index));
                self.register_manager.free_reg(reg);
                self.register_manager.get_reg_assume_free(reg, target_maybe_inst);
            }
            if (target_maybe_inst) |target_inst| {
                self.inst_tracking.get_ptr(target_inst).?.track_materialize(
                    target_inst,
                    state.reg_tracking[index],
                );
            }
        } else if (target_maybe_inst) |_|
            try reg_locks.append(self.register_manager.lock_reg_index_assume_unused(@int_cast(index)));
    }

    if (opts.update_tracking and std.debug.runtime_safety) {
        assert(self.register_manager.free_registers.eql(state.free_registers));
        var used_reg_it = state.free_registers.iterator(.{ .kind = .unset });
        while (used_reg_it.next()) |index|
            assert(self.register_manager.registers[index] == state.registers[index]);
    }
}

const Self = @This();

const CallView = enum(u1) {
    callee,
    caller,
};

pub fn generate(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    func_index: InternPool.Index,
    air: Air,
    liveness: Liveness,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
) CodeGenError!Result {
    const comp = bin_file.comp;
    const gpa = comp.gpa;
    const zcu = comp.module.?;
    const ip = &zcu.intern_pool;
    const func = zcu.func_info(func_index);
    const fn_owner_decl = zcu.decl_ptr(func.owner_decl);
    assert(fn_owner_decl.has_tv);
    const fn_type = fn_owner_decl.type_of(zcu);
    const namespace = zcu.namespace_ptr(fn_owner_decl.src_namespace);
    const target = &namespace.file_scope.mod.resolved_target.result;
    const mod = namespace.file_scope.mod;

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
        .mod = mod,
        .liveness = liveness,
        .target = target,
        .bin_file = bin_file,
        .func_index = func_index,
        .code = code,
        .debug_output = debug_output,
        .err_msg = null,
        .args = undefined, // populated after `resolve_calling_convention_values`
        .ret_mcv = undefined, // populated after `resolve_calling_convention_values`
        .fn_type = fn_type,
        .arg_index = 0,
        .branch_stack = &branch_stack,
        .src_loc = src_loc,
        .end_di_line = func.rbrace_line,
        .end_di_column = func.rbrace_column,
        .scope_generation = 0,
    };
    defer {
        function.frame_allocs.deinit(gpa);
        function.free_frame_indices.deinit(gpa);
        function.frame_locs.deinit(gpa);
        var block_it = function.blocks.value_iterator();
        while (block_it.next()) |block| block.deinit(gpa);
        function.blocks.deinit(gpa);
        function.inst_tracking.deinit(gpa);
        function.const_tracking.deinit(gpa);
        function.exitlude_jump_relocs.deinit(gpa);
        function.mir_instructions.deinit(gpa);
        function.mir_extra.deinit(gpa);
    }

    try function.frame_allocs.resize(gpa, FrameIndex.named_count);
    function.frame_allocs.set(
        @int_from_enum(FrameIndex.stack_frame),
        FrameAlloc.init(.{
            .size = 0,
            .alignment = func.analysis(ip).stack_alignment.max(.@"1"),
        }),
    );
    function.frame_allocs.set(
        @int_from_enum(FrameIndex.call_frame),
        FrameAlloc.init(.{ .size = 0, .alignment = .@"1" }),
    );

    const fn_info = zcu.type_to_func(fn_type).?;
    var call_info = function.resolve_calling_convention_values(fn_info) catch |err| switch (err) {
        error.CodegenFail => return Result{ .fail = function.err_msg.? },
        error.OutOfRegisters => return Result{
            .fail = try ErrorMsg.create(gpa, src_loc, "CodeGen ran out of registers. This is a bug in the Zig compiler.", .{}),
        },
        else => |e| return e,
    };

    defer call_info.deinit(&function);

    function.args = call_info.args;
    function.ret_mcv = call_info.return_value;
    function.frame_allocs.set(@int_from_enum(FrameIndex.ret_addr), FrameAlloc.init(.{
        .size = Type.usize.abi_size(zcu),
        .alignment = Type.usize.abi_alignment(zcu).min(call_info.stack_align),
    }));
    function.frame_allocs.set(@int_from_enum(FrameIndex.base_ptr), FrameAlloc.init(.{
        .size = Type.usize.abi_size(zcu),
        .alignment = Alignment.min(
            call_info.stack_align,
            Alignment.from_nonzero_byte_units(function.target.stack_alignment()),
        ),
    }));
    function.frame_allocs.set(@int_from_enum(FrameIndex.args_frame), FrameAlloc.init(.{
        .size = call_info.stack_byte_count,
        .alignment = call_info.stack_align,
    }));
    function.frame_allocs.set(@int_from_enum(FrameIndex.spill_frame), FrameAlloc.init(.{
        .size = 0,
        .alignment = Type.usize.abi_alignment(zcu),
    }));

    function.gen() catch |err| switch (err) {
        error.CodegenFail => return Result{ .fail = function.err_msg.? },
        error.OutOfRegisters => return Result{
            .fail = try ErrorMsg.create(gpa, src_loc, "CodeGen ran out of registers. This is a bug in the Zig compiler.", .{}),
        },
        else => |e| return e,
    };

    var mir = Mir{
        .instructions = function.mir_instructions.to_owned_slice(),
        .extra = try function.mir_extra.to_owned_slice(gpa),
        .frame_locs = function.frame_locs.to_owned_slice(),
    };
    defer mir.deinit(gpa);

    var emit = Emit{
        .lower = .{
            .bin_file = bin_file,
            .allocator = gpa,
            .mir = mir,
            .cc = fn_info.cc,
            .src_loc = src_loc,
            .output_mode = comp.config.output_mode,
            .link_mode = comp.config.link_mode,
            .pic = mod.pic,
        },
        .debug_output = debug_output,
        .code = code,
        .prev_di_pc = 0,
        .prev_di_line = func.lbrace_line,
        .prev_di_column = func.lbrace_column,
    };
    defer emit.deinit();

    emit.emit_mir() catch |err| switch (err) {
        error.LowerFail, error.EmitFail => return Result{ .fail = emit.lower.err_msg.? },
        error.InvalidInstruction => |e| {
            const msg = switch (e) {
                error.InvalidInstruction => "CodeGen failed to find a viable instruction.",
            };
            return Result{
                .fail = try ErrorMsg.create(
                    gpa,
                    src_loc,
                    "{s} This is a bug in the Zig compiler.",
                    .{msg},
                ),
            };
        },
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
    return self.add_inst(.{
        .tag = .nop,
        .ops = .none,
        .data = undefined,
    });
}

fn add_pseudo_none(self: *Self, ops: Mir.Inst.Ops) !void {
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = ops,
        .data = undefined,
    });
}

fn add_pseudo(self: *Self, ops: Mir.Inst.Ops) !Mir.Inst.Index {
    return self.add_inst(.{
        .tag = .pseudo,
        .ops = ops,
        .data = undefined,
    });
}

pub fn add_extra(self: *Self, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try self.mir_extra.ensure_unused_capacity(self.gpa, fields.len);
    return self.add_extra_assume_capacity(extra);
}

pub fn add_extra_assume_capacity(self: *Self, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const result: u32 = @int_cast(self.mir_extra.items.len);
    inline for (fields) |field| {
        self.mir_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            i32 => @bit_cast(@field(extra, field.name)),
            else => @compile_error("bad field type"),
        });
    }
    return result;
}

fn gen(self: *Self) !void {
    const mod = self.bin_file.comp.module.?;
    const fn_info = mod.type_to_func(self.fn_type).?;

    if (fn_info.cc != .Naked) {
        try self.add_pseudo_none(.pseudo_dbg_prologue_end);

        const backpatch_stack_alloc = try self.add_pseudo(.pseudo_dead);
        const backpatch_ra_spill = try self.add_pseudo(.pseudo_dead);
        const backpatch_fp_spill = try self.add_pseudo(.pseudo_dead);
        const backpatch_fp_add = try self.add_pseudo(.pseudo_dead);
        const backpatch_spill_callee_preserved_regs = try self.add_pseudo(.pseudo_dead);

        try self.gen_body(self.air.get_main_body());

        for (self.exitlude_jump_relocs.items) |jmp_reloc| {
            self.mir_instructions.items(.data)[jmp_reloc].inst =
                @int_cast(self.mir_instructions.len);
        }

        try self.add_pseudo_none(.pseudo_dbg_epilogue_begin);

        const backpatch_restore_callee_preserved_regs = try self.add_pseudo(.pseudo_dead);
        const backpatch_ra_restore = try self.add_pseudo(.pseudo_dead);
        const backpatch_fp_restore = try self.add_pseudo(.pseudo_dead);
        const backpatch_stack_alloc_restore = try self.add_pseudo(.pseudo_dead);
        try self.add_pseudo_none(.pseudo_ret);

        const frame_layout = try self.compute_frame_layout();
        const need_save_reg = frame_layout.save_reg_list.count() > 0;

        self.mir_instructions.set(backpatch_stack_alloc, .{
            .tag = .addi,
            .ops = .rri,
            .data = .{ .i_type = .{
                .rd = .sp,
                .rs1 = .sp,
                .imm12 = Immediate.s(-@as(i32, @int_cast(frame_layout.stack_adjust))),
            } },
        });
        self.mir_instructions.set(backpatch_ra_spill, .{
            .tag = .pseudo,
            .ops = .pseudo_store_rm,
            .data = .{ .rm = .{
                .r = .ra,
                .m = .{
                    .base = .{ .frame = .ret_addr },
                    .mod = .{ .rm = .{ .size = .dword } },
                },
            } },
        });
        self.mir_instructions.set(backpatch_ra_restore, .{
            .tag = .pseudo,
            .ops = .pseudo_load_rm,
            .data = .{ .rm = .{
                .r = .ra,
                .m = .{
                    .base = .{ .frame = .ret_addr },
                    .mod = .{ .rm = .{ .size = .dword } },
                },
            } },
        });
        self.mir_instructions.set(backpatch_fp_spill, .{
            .tag = .pseudo,
            .ops = .pseudo_store_rm,
            .data = .{ .rm = .{
                .r = .s0,
                .m = .{
                    .base = .{ .frame = .base_ptr },
                    .mod = .{ .rm = .{ .size = .dword } },
                },
            } },
        });
        self.mir_instructions.set(backpatch_fp_restore, .{
            .tag = .pseudo,
            .ops = .pseudo_load_rm,
            .data = .{ .rm = .{
                .r = .s0,
                .m = .{
                    .base = .{ .frame = .base_ptr },
                    .mod = .{ .rm = .{ .size = .dword } },
                },
            } },
        });
        self.mir_instructions.set(backpatch_fp_add, .{
            .tag = .addi,
            .ops = .rri,
            .data = .{ .i_type = .{
                .rd = .s0,
                .rs1 = .sp,
                .imm12 = Immediate.s(@int_cast(frame_layout.stack_adjust)),
            } },
        });
        self.mir_instructions.set(backpatch_stack_alloc_restore, .{
            .tag = .addi,
            .ops = .rri,
            .data = .{ .i_type = .{
                .rd = .sp,
                .rs1 = .sp,
                .imm12 = Immediate.s(@int_cast(frame_layout.stack_adjust)),
            } },
        });

        if (need_save_reg) {
            self.mir_instructions.set(backpatch_spill_callee_preserved_regs, .{
                .tag = .pseudo,
                .ops = .pseudo_spill_regs,
                .data = .{ .reg_list = frame_layout.save_reg_list },
            });

            self.mir_instructions.set(backpatch_restore_callee_preserved_regs, .{
                .tag = .pseudo,
                .ops = .pseudo_restore_regs,
                .data = .{ .reg_list = frame_layout.save_reg_list },
            });
        }
    } else {
        try self.add_pseudo_none(.pseudo_dbg_prologue_end);
        try self.gen_body(self.air.get_main_body());
        try self.add_pseudo_none(.pseudo_dbg_epilogue_begin);
    }

    // Drop them off at the rbrace.
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_line_column,
        .data = .{ .pseudo_dbg_line_column = .{
            .line = self.end_di_line,
            .column = self.end_di_column,
        } },
    });
}

fn gen_body(self: *Self, body: []const Air.Inst.Index) InnerError!void {
    const zcu = self.bin_file.comp.module.?;
    const ip = &zcu.intern_pool;
    const air_tags = self.air.instructions.items(.tag);

    for (body) |inst| {
        if (self.liveness.is_unused(inst) and !self.air.must_lower(inst, ip)) continue;

        const old_air_bookkeeping = self.air_bookkeeping;
        try self.inst_tracking.ensure_unused_capacity(self.gpa, 1);
        switch (air_tags[@int_from_enum(inst)]) {
            // zig fmt: off
            .ptr_add => try self.air_ptr_arithmetic(inst, .ptr_add),
            .ptr_sub => try self.air_ptr_arithmetic(inst, .ptr_sub),

            .add => try self.air_bin_op(inst, .add),
            .sub => try self.air_bin_op(inst, .sub),

            .add_safe,
            .sub_safe,
            .mul_safe,
            => return self.fail("TODO implement safety_checked_instructions", .{}),

            .add_wrap        => try self.air_add_wrap(inst),
            .add_sat         => try self.air_add_sat(inst),
            .sub_wrap        => try self.air_sub_wrap(inst),
            .sub_sat         => try self.air_sub_sat(inst),
            .mul             => try self.air_mul(inst),
            .mul_wrap        => try self.air_mul_wrap(inst),
            .mul_sat         => try self.air_mul_sat(inst),
            .rem             => try self.air_rem(inst),
            .mod             => try self.air_mod(inst),
            .shl, .shl_exact => try self.air_shl(inst),
            .shl_sat         => try self.air_shl_sat(inst),
            .min             => try self.air_min_max(inst, .min),
            .max             => try self.air_min_max(inst, .max),
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

            .add_with_overflow => try self.air_add_with_overflow(inst),
            .sub_with_overflow => try self.air_sub_with_overflow(inst),
            .mul_with_overflow => try self.air_mul_with_overflow(inst),
            .shl_with_overflow => try self.air_shl_with_overflow(inst),

            .div_float, .div_trunc, .div_floor, .div_exact => try self.air_div(inst),

            .cmp_lt  => try self.air_cmp(inst),
            .cmp_lte => try self.air_cmp(inst),
            .cmp_eq  => try self.air_cmp(inst),
            .cmp_gte => try self.air_cmp(inst),
            .cmp_gt  => try self.air_cmp(inst),
            .cmp_neq => try self.air_cmp(inst),

            .cmp_vector => try self.air_cmp_vector(inst),
            .cmp_lt_errors_len => try self.air_cmp_lt_errors_len(inst),

            .bool_and        => try self.air_bool_op(inst),
            .bool_or         => try self.air_bool_op(inst),
            .bit_and         => try self.air_bit_and(inst),
            .bit_or          => try self.air_bit_or(inst),
            .xor             => try self.air_xor(inst),
            .shr, .shr_exact => try self.air_shr(inst),

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
            .dbg_stmt        => try self.air_dbg_stmt(inst),
            .fptrunc         => try self.air_fptrunc(inst),
            .fpext           => try self.air_fpext(inst),
            .intcast         => try self.air_int_cast(inst),
            .trunc           => try self.air_trunc(inst),
            .int_from_bool   => try self.air_int_from_bool(inst),
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
            .int_from_ptr    => try self.air_int_from_ptr(inst),
            .ret             => try self.air_ret(inst, false),
            .ret_safe        => try self.air_ret(inst, true),
            .ret_load        => try self.air_ret_load(inst),
            .store           => try self.air_store(inst, false),
            .store_safe      => try self.air_store(inst, true),
            .struct_field_ptr=> try self.air_struct_field_ptr(inst),
            .struct_field_val=> try self.air_struct_field_val(inst),
            .array_to_slice  => try self.air_array_to_slice(inst),
            .float_from_int  => try self.air_float_from_int(inst),
            .int_from_float  => try self.air_int_from_float(inst),
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
            .addrspace_cast  => return self.fail("TODO: addrspace_cast", .{}),

            .@"try"          =>  try self.air_try(inst),
            .try_ptr         =>  return self.fail("TODO: try_ptr", .{}),

            .dbg_var_ptr,
            .dbg_var_val,
            => try self.air_dbg_var(inst),

            .dbg_inline_block => try self.air_dbg_inline_block(inst),

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

            { // check consistency of tracked registers
                var it = self.register_manager.free_registers.iterator(.{ .kind = .unset });
                while (it.next()) |index| {
                    const tracked_inst = self.register_manager.registers[index];
                    const tracking = self.get_resolved_inst_value(tracked_inst);
                    for (tracking.get_regs()) |reg| {
                        if (RegisterManager.index_of_reg_into_tracked(reg).? == index) break;
                    } else return self.fail(
                        \\%{} takes up these regs: {any}, however those regs don't use it
                    , .{ index, tracking.get_regs() });
                }
            }
        }
    }
}

fn get_value(self: *Self, value: MCValue, inst: ?Air.Inst.Index) !void {
    for (value.get_regs()) |reg| try self.register_manager.get_reg(reg, inst);
}

fn get_value_if_free(self: *Self, value: MCValue, inst: ?Air.Inst.Index) void {
    for (value.get_regs()) |reg| if (self.register_manager.is_reg_free(reg))
        self.register_manager.get_reg_assume_free(reg, inst);
}

fn free_value(self: *Self, value: MCValue) !void {
    switch (value) {
        .register => |reg| self.register_manager.free_reg(reg),
        .register_pair => |regs| for (regs) |reg| self.register_manager.free_reg(reg),
        .register_offset => |reg_off| self.register_manager.free_reg(reg_off.reg),
        else => {}, // TODO process stack allocation death
    }
}

fn feed(self: *Self, bt: *Liveness.BigTomb, operand: Air.Inst.Ref) !void {
    if (bt.feed()) if (operand.to_index()) |inst| {
        log.debug("feed inst: %{}", .{inst});
        try self.process_death(inst);
    };
}

/// Asserts there is already capacity to insert into top branch inst_table.
fn process_death(self: *Self, inst: Air.Inst.Index) !void {
    try self.inst_tracking.get_ptr(inst).?.die(self, inst);
}

/// Called when there are no operands, and the instruction is always unreferenced.
fn finish_air_bookkeeping(self: *Self) void {
    if (std.debug.runtime_safety) {
        self.air_bookkeeping += 1;
    }
}

fn finish_air_result(self: *Self, inst: Air.Inst.Index, result: MCValue) void {
    if (self.liveness.is_unused(inst)) switch (result) {
        .none, .dead, .unreach => {},
        else => unreachable, // Why didn't the result die?
    } else {
        tracking_log.debug("%{d} => {} (birth)", .{ inst, result });
        self.inst_tracking.put_assume_capacity_no_clobber(inst, InstTracking.init(result));
        // In some cases, an operand may be reused as the result.
        // If that operand died and was a register, it was freed by
        // process_death, so we have to "re-allocate" the register.
        self.get_value_if_free(result, inst);
    }
    self.finish_air_bookkeeping();
}

fn finish_air(
    self: *Self,
    inst: Air.Inst.Index,
    result: MCValue,
    operands: [Liveness.bpi - 1]Air.Inst.Ref,
) !void {
    var tomb_bits = self.liveness.get_tomb_bits(inst);
    for (operands) |op| {
        const dies = @as(u1, @truncate(tomb_bits)) != 0;
        tomb_bits >>= 1;
        if (!dies) continue;
        try self.process_death(op.to_index_allow_none() orelse continue);
    }
    self.finish_air_result(inst, result);
}

const FrameLayout = struct {
    stack_adjust: u32,
    save_reg_list: Mir.RegisterList,
};

fn set_frame_loc(
    self: *Self,
    frame_index: FrameIndex,
    base: Register,
    offset: *i32,
    comptime aligned: bool,
) void {
    const frame_i = @int_from_enum(frame_index);
    if (aligned) {
        const alignment: InternPool.Alignment = self.frame_allocs.items(.abi_align)[frame_i];
        offset.* = if (math.sign(offset.*) < 0)
            -1 * @as(i32, @int_cast(alignment.backward(@int_cast(@abs(offset.*)))))
        else
            @int_cast(alignment.forward(@int_cast(@abs(offset.*))));
    }
    self.frame_locs.set(frame_i, .{ .base = base, .disp = offset.* });
    offset.* += self.frame_allocs.items(.abi_size)[frame_i];
}

fn compute_frame_layout(self: *Self) !FrameLayout {
    const frame_allocs_len = self.frame_allocs.len;
    try self.frame_locs.resize(self.gpa, frame_allocs_len);
    const stack_frame_order = try self.gpa.alloc(FrameIndex, frame_allocs_len - FrameIndex.named_count);
    defer self.gpa.free(stack_frame_order);

    const frame_size = self.frame_allocs.items(.abi_size);
    const frame_align = self.frame_allocs.items(.abi_align);

    for (stack_frame_order, FrameIndex.named_count..) |*frame_order, frame_index|
        frame_order.* = @enumFromInt(frame_index);

    {
        const SortContext = struct {
            frame_align: @TypeOf(frame_align),
            pub fn less_than(context: @This(), lhs: FrameIndex, rhs: FrameIndex) bool {
                return context.frame_align[@int_from_enum(lhs)].compare(.gt, context.frame_align[@int_from_enum(rhs)]);
            }
        };
        const sort_context = SortContext{ .frame_align = frame_align };
        mem.sort(FrameIndex, stack_frame_order, sort_context, SortContext.less_than);
    }

    var save_reg_list = Mir.RegisterList{};
    for (callee_preserved_regs) |reg| {
        if (self.register_manager.is_reg_allocated(reg)) {
            save_reg_list.push(&callee_preserved_regs, reg);
        }
    }

    const total_alloc_size: i32 = blk: {
        var i: i32 = 0;
        for (stack_frame_order) |frame_index| {
            i += frame_size[@int_from_enum(frame_index)];
        }
        break :blk i;
    };
    const saved_reg_size = save_reg_list.size();

    frame_size[@int_from_enum(FrameIndex.spill_frame)] = @int_cast(saved_reg_size);

    // The total frame size is calculated by the amount of s registers you need to save * 8, as each
    // register is 8 bytes, the total allocation sizes, and 16 more register for the spilled ra and s0
    // register. Finally we align the frame size to the align of the base pointer.
    const args_frame_size = frame_size[@int_from_enum(FrameIndex.args_frame)];
    const spill_frame_size = frame_size[@int_from_enum(FrameIndex.spill_frame)];
    const call_frame_size = frame_size[@int_from_enum(FrameIndex.call_frame)];

    // TODO: this 64 should be a 16, but we were clobbering the top and bottom of the frame.
    // maybe everything can go from the bottom?
    const acc_frame_size: i32 = std.mem.align_forward(
        i32,
        total_alloc_size + 64 + args_frame_size + spill_frame_size + call_frame_size,
        @int_cast(frame_align[@int_from_enum(FrameIndex.base_ptr)].to_byte_units().?),
    );
    log.debug("frame size: {}", .{acc_frame_size});

    // store the ra at total_size - 8, so it's the very first thing in the stack
    // relative to the fp
    self.frame_locs.set(
        @int_from_enum(FrameIndex.ret_addr),
        .{ .base = .sp, .disp = acc_frame_size - 8 },
    );
    self.frame_locs.set(
        @int_from_enum(FrameIndex.base_ptr),
        .{ .base = .sp, .disp = acc_frame_size - 16 },
    );

    // now we grow the stack frame from the bottom of total frame in order to
    // not need to know the size of the first allocation. Stack offsets point at the "bottom"
    // of variables.
    var s0_offset: i32 = -acc_frame_size;
    self.set_frame_loc(.stack_frame, .s0, &s0_offset, true);
    for (stack_frame_order) |frame_index| self.set_frame_loc(frame_index, .s0, &s0_offset, true);
    self.set_frame_loc(.args_frame, .s0, &s0_offset, true);
    self.set_frame_loc(.call_frame, .s0, &s0_offset, true);
    self.set_frame_loc(.spill_frame, .s0, &s0_offset, true);

    return .{
        .stack_adjust = @int_cast(acc_frame_size),
        .save_reg_list = save_reg_list,
    };
}

fn ensure_process_death_capacity(self: *Self, additional_count: usize) !void {
    const table = &self.branch_stack.items[self.branch_stack.items.len - 1].inst_table;
    try table.ensure_unused_capacity(self.gpa, additional_count);
}

fn mem_size(self: *Self, ty: Type) Memory.Size {
    const mod = self.bin_file.comp.module.?;
    return switch (ty.zig_type_tag(mod)) {
        .Float => Memory.Size.from_bit_size(ty.float_bits(self.target.*)),
        else => Memory.Size.from_byte_size(ty.abi_size(mod)),
    };
}

fn split_type(self: *Self, ty: Type) ![2]Type {
    const zcu = self.bin_file.comp.module.?;
    const classes = mem.slice_to(&abi.classify_system(ty, zcu), .none);
    var parts: [2]Type = undefined;
    if (classes.len == 2) for (&parts, classes, 0..) |*part, class, part_i| {
        part.* = switch (class) {
            .integer => switch (part_i) {
                0 => Type.u64,
                1 => part: {
                    const elem_size = ty.abi_alignment(zcu).min_strict(.@"8").to_byte_units().?;
                    const elem_ty = try zcu.int_type(.unsigned, @int_cast(elem_size * 8));
                    break :part switch (@div_exact(ty.abi_size(zcu) - 8, elem_size)) {
                        1 => elem_ty,
                        else => |len| try zcu.array_type(.{ .len = len, .child = elem_ty.to_intern() }),
                    };
                },
                else => unreachable,
            },
            else => return self.fail("TODO: split_type class {}", .{class}),
        };
    } else if (parts[0].abi_size(zcu) + parts[1].abi_size(zcu) == ty.abi_size(zcu)) return parts;
    return self.fail("TODO implement split_type for {}", .{ty.fmt(zcu)});
}

fn symbol_index(self: *Self) !u32 {
    const zcu = self.bin_file.comp.module.?;
    const decl_index = zcu.func_owner_decl_index(self.func_index);
    return switch (self.bin_file.tag) {
        .elf => blk: {
            const elf_file = self.bin_file.cast(link.File.Elf).?;
            const atom_index = try elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, decl_index);
            break :blk atom_index;
        },
        else => return self.fail("TODO gen_set_reg load_symbol for {s}", .{@tag_name(self.bin_file.tag)}),
    };
}

fn alloc_frame_index(self: *Self, alloc: FrameAlloc) !FrameIndex {
    const frame_allocs_slice = self.frame_allocs.slice();
    const frame_size = frame_allocs_slice.items(.abi_size);
    const frame_align = frame_allocs_slice.items(.abi_align);

    const stack_frame_align = &frame_align[@int_from_enum(FrameIndex.stack_frame)];
    stack_frame_align.* = stack_frame_align.max(alloc.abi_align);

    for (self.free_frame_indices.keys(), 0..) |frame_index, free_i| {
        const abi_size = frame_size[@int_from_enum(frame_index)];
        if (abi_size != alloc.abi_size) continue;
        const abi_align = &frame_align[@int_from_enum(frame_index)];
        abi_align.* = abi_align.max(alloc.abi_align);

        _ = self.free_frame_indices.swap_remove_at(free_i);
        return frame_index;
    }
    const frame_index: FrameIndex = @enumFromInt(self.frame_allocs.len);
    try self.frame_allocs.append(self.gpa, alloc);
    log.debug("allocated frame {}", .{frame_index});
    return frame_index;
}

/// Use a pointer instruction as the basis for allocating stack memory.
fn alloc_mem_ptr(self: *Self, inst: Air.Inst.Index) !FrameIndex {
    const zcu = self.bin_file.comp.module.?;
    const ptr_ty = self.type_of_index(inst);
    const val_ty = ptr_ty.child_type(zcu);
    return self.alloc_frame_index(FrameAlloc.init(.{
        .size = math.cast(u32, val_ty.abi_size(zcu)) orelse {
            return self.fail("type '{}' too big to fit into stack frame", .{val_ty.fmt(zcu)});
        },
        .alignment = ptr_ty.ptr_alignment(zcu).max(.@"1"),
    }));
}

fn alloc_reg_or_mem(self: *Self, inst: Air.Inst.Index, reg_ok: bool) !MCValue {
    const zcu = self.bin_file.comp.module.?;
    const elem_ty = self.type_of_index(inst);

    const abi_size = math.cast(u32, elem_ty.abi_size(zcu)) orelse {
        return self.fail("type '{}' too big to fit into stack frame", .{elem_ty.fmt(zcu)});
    };

    if (reg_ok) {
        // Make sure the type can fit in a register before we try to allocate one.
        const ptr_bits = self.target.ptr_bit_width();
        const ptr_bytes: u64 = @div_exact(ptr_bits, 8);
        if (abi_size <= ptr_bytes) {
            if (self.register_manager.try_alloc_reg(inst, gp)) |reg| {
                return .{ .register = reg };
            }
        }
    }

    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(elem_ty, zcu));
    return .{ .load_frame = .{ .index = frame_index } };
}

/// Allocates a register from the general purpose set and returns the Register and the Lock.
///
/// Up to the user to unlock the register later.
fn alloc_reg(self: *Self) !struct { Register, RegisterLock } {
    const reg = try self.register_manager.alloc_reg(null, gp);
    const lock = self.register_manager.lock_reg_assume_unused(reg);
    return .{ reg, lock };
}

fn elem_offset(self: *Self, index_ty: Type, index: MCValue, elem_size: u64) !Register {
    const reg: Register = blk: {
        switch (index) {
            .immediate => |imm| {
                // Optimisation: if index MCValue is an immediate, we can multiply in `comptime`
                // and set the register directly to the scaled offset as an immediate.
                const reg = try self.register_manager.alloc_reg(null, gp);
                try self.gen_set_reg(index_ty, reg, .{ .immediate = imm * elem_size });
                break :blk reg;
            },
            else => {
                const reg = try self.copy_to_tmp_register(index_ty, index);
                const lock = self.register_manager.lock_reg_assume_unused(reg);
                defer self.register_manager.unlock_reg(lock);

                const result = try self.bin_op(
                    .mul,
                    .{ .register = reg },
                    index_ty,
                    .{ .immediate = elem_size },
                    index_ty,
                );
                break :blk result.register;
            },
        }
    };
    return reg;
}

pub fn spill_instruction(self: *Self, reg: Register, inst: Air.Inst.Index) !void {
    const tracking = self.inst_tracking.get_ptr(inst) orelse return;
    for (tracking.get_regs()) |tracked_reg| {
        if (tracked_reg.id() == reg.id()) break;
    } else unreachable; // spilled reg not tracked with spilled instruciton
    try tracking.spill(self, inst);
    try tracking.track_spill(self, inst);
}

/// Copies a value to a register without tracking the register. The register is not considered
/// allocated. A second call to `copy_to_tmp_register` may return the same register.
/// This can have a side effect of spilling instructions to the stack to free up a register.
fn copy_to_tmp_register(self: *Self, ty: Type, mcv: MCValue) !Register {
    const reg = try self.register_manager.alloc_reg(null, tp);
    try self.gen_set_reg(ty, reg, mcv);
    return reg;
}

/// Allocates a new register and copies `mcv` into it.
/// `reg_owner` is the instruction that gets associated with the register in the register table.
/// This can have a side effect of spilling instructions to the stack to free up a register.
fn copy_to_new_register(self: *Self, reg_owner: Air.Inst.Index, mcv: MCValue) !MCValue {
    const reg = try self.register_manager.alloc_reg(reg_owner, gp);
    try self.gen_set_reg(self.type_of_index(reg_owner), reg, mcv);
    return MCValue{ .register = reg };
}

fn air_alloc(self: *Self, inst: Air.Inst.Index) !void {
    const result = MCValue{ .lea_frame = .{ .index = try self.alloc_mem_ptr(inst) } };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_ret_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = switch (self.ret_mcv.long) {
        .none => .{ .lea_frame = .{ .index = try self.alloc_mem_ptr(inst) } },
        .load_frame => .{ .register_offset = .{
            .reg = (try self.copy_to_new_register(
                inst,
                self.ret_mcv.long,
            )).register,
            .off = self.ret_mcv.short.indirect.off,
        } },
        else => |t| return self.fail("TODO: air_ret_ptr {s}", .{@tag_name(t)}),
    };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_fptrunc(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_fptrunc for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_fpext(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_fpext for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_cast(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const src_ty = self.type_of(ty_op.operand);
    const dst_ty = self.type_of_index(inst);

    const result: MCValue = result: {
        const src_int_info = src_ty.int_info(zcu);
        const dst_int_info = dst_ty.int_info(zcu);

        const min_ty = if (dst_int_info.bits < src_int_info.bits) dst_ty else src_ty;

        const src_mcv = try self.resolve_inst(ty_op.operand);

        const src_storage_bits: u16 = switch (src_mcv) {
            .register => 64,
            .load_frame => src_int_info.bits,
            else => return self.fail("air_int_cast from {s}", .{@tag_name(src_mcv)}),
        };

        const dst_mcv = if (dst_int_info.bits <= src_storage_bits and
            math.div_ceil(u16, dst_int_info.bits, 64) catch unreachable ==
            math.div_ceil(u32, src_storage_bits, 64) catch unreachable and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) src_mcv else dst: {
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(min_ty, dst_mcv, src_mcv);
            break :dst dst_mcv;
        };

        if (dst_int_info.bits <= src_int_info.bits)
            break :result dst_mcv;

        if (dst_int_info.bits > 64 or src_int_info.bits > 64)
            break :result null; // TODO

        break :result dst_mcv;
    } orelse return self.fail("TODO implement air_int_cast from {} to {}", .{
        src_ty.fmt(zcu), dst_ty.fmt(zcu),
    });

    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_trunc(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    if (self.liveness.is_unused(inst))
        return self.finish_air(inst, .unreach, .{ ty_op.operand, .none, .none });

    const operand = try self.resolve_inst(ty_op.operand);
    _ = operand;
    return self.fail("TODO implement trunc for {}", .{self.target.cpu.arch});
    // return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_bool(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else operand;
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_not(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const zcu = self.bin_file.comp.module.?;

        const operand = try self.resolve_inst(ty_op.operand);
        const ty = self.type_of(ty_op.operand);

        switch (ty.zig_type_tag(zcu)) {
            .Bool => {
                const operand_reg = blk: {
                    if (operand == .register) break :blk operand.register;
                    break :blk try self.copy_to_tmp_register(ty, operand);
                };

                const dst_reg: Register =
                    if (self.reuse_operand(inst, ty_op.operand, 0, operand) and operand == .register)
                    operand.register
                else
                    try self.register_manager.alloc_reg(inst, gp);

                _ = try self.add_inst(.{
                    .tag = .pseudo,
                    .ops = .pseudo_not,
                    .data = .{
                        .rr = .{
                            .rs = operand_reg,
                            .rd = dst_reg,
                        },
                    },
                });

                break :result .{ .register = dst_reg };
            },
            .Int => return self.fail("TODO: air_not ints", .{}),
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_min_max(
    self: *Self,
    inst: Air.Inst.Index,
    comptime tag: enum {
        max,
        min,
    },
) !void {
    const zcu = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const lhs_ty = self.type_of(bin_op.lhs);
        const rhs_ty = self.type_of(bin_op.rhs);

        const int_info = lhs_ty.int_info(zcu);

        if (int_info.bits > 64) return self.fail("TODO: > 64 bit @min", .{});

        const lhs_reg, const lhs_lock = blk: {
            if (lhs == .register) break :blk .{ lhs.register, null };

            const lhs_reg, const lhs_lock = try self.alloc_reg();
            try self.gen_set_reg(lhs_ty, lhs_reg, lhs);
            break :blk .{ lhs_reg, lhs_lock };
        };
        defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const rhs_reg, const rhs_lock = blk: {
            if (rhs == .register) break :blk .{ rhs.register, null };

            const rhs_reg, const rhs_lock = try self.alloc_reg();
            try self.gen_set_reg(rhs_ty, rhs_reg, rhs);
            break :blk .{ rhs_reg, rhs_lock };
        };
        defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const mask_reg, const mask_lock = try self.alloc_reg();
        defer self.register_manager.unlock_reg(mask_lock);

        const result_reg, const result_lock = try self.alloc_reg();
        defer self.register_manager.unlock_reg(result_lock);

        _ = try self.add_inst(.{
            .tag = if (int_info.signedness == .unsigned) .sltu else .slt,
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = mask_reg,
                .rs1 = lhs_reg,
                .rs2 = rhs_reg,
            } },
        });

        _ = try self.add_inst(.{
            .tag = .sub,
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = mask_reg,
                .rs1 = .zero,
                .rs2 = mask_reg,
            } },
        });

        _ = try self.add_inst(.{
            .tag = .xor,
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = result_reg,
                .rs1 = lhs_reg,
                .rs2 = rhs_reg,
            } },
        });

        _ = try self.add_inst(.{
            .tag = .@"and",
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = mask_reg,
                .rs1 = result_reg,
                .rs2 = mask_reg,
            } },
        });

        _ = try self.add_inst(.{
            .tag = .xor,
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = result_reg,
                .rs1 = if (tag == .min) rhs_reg else lhs_reg,
                .rs2 = mask_reg,
            } },
        });

        break :result .{ .register = result_reg };
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_slice(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement slice for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_bin_op(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const lhs = try self.resolve_inst(bin_op.lhs);
    const rhs = try self.resolve_inst(bin_op.rhs);
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        break :result try self.bin_op(tag, lhs, lhs_ty, rhs, rhs_ty);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

/// For all your binary operation needs, this function will generate
/// the corresponding Mir instruction(s). Returns the location of the
/// result.
///
/// If the binary operation itself happens to be an Air instruction,
/// pass the corresponding index in the inst parameter. That helps
/// this function do stuff like reusing operands.
///
/// This function does not do any lowering to Mir itself, but instead
/// looks at the lhs and rhs and determines which kind of lowering
/// would be best suitable and then delegates the lowering to other
/// functions.
///
/// `maybe_inst` **needs** to be a bin_op, make sure of that.
fn bin_op(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs: MCValue,
    lhs_ty: Type,
    rhs: MCValue,
    rhs_ty: Type,
) InnerError!MCValue {
    const zcu = self.bin_file.comp.module.?;

    switch (tag) {
        // Arithmetic operations on integers and floats
        .add,
        .sub,
        .mul,
        .cmp_eq,
        .cmp_neq,
        .cmp_gt,
        .cmp_gte,
        .cmp_lt,
        .cmp_lte,
        => {
            switch (lhs_ty.zig_type_tag(zcu)) {
                .Float => return self.fail("TODO binary operations on floats", .{}),
                .Vector => return self.fail("TODO binary operations on vectors", .{}),
                .Int => {
                    assert(lhs_ty.eql(rhs_ty, zcu));
                    const int_info = lhs_ty.int_info(zcu);
                    if (int_info.bits <= 64) {
                        return self.bin_op_register(tag, lhs, lhs_ty, rhs, rhs_ty);
                    } else {
                        return self.fail("TODO binary operations on int with bits > 64", .{});
                    }
                },
                else => |x| return self.fail("TOOD: bin_op {s}", .{@tag_name(x)}),
            }
        },

        .ptr_add,
        .ptr_sub,
        => {
            switch (lhs_ty.zig_type_tag(zcu)) {
                .Pointer => {
                    const ptr_ty = lhs_ty;
                    const elem_ty = switch (ptr_ty.ptr_size(zcu)) {
                        .One => ptr_ty.child_type(zcu).child_type(zcu), // ptr to array, so get array element type
                        else => ptr_ty.child_type(zcu),
                    };
                    const elem_size = elem_ty.abi_size(zcu);

                    if (elem_size == 1) {
                        const base_tag: Air.Inst.Tag = switch (tag) {
                            .ptr_add => .add,
                            .ptr_sub => .sub,
                            else => unreachable,
                        };

                        return try self.bin_op_register(base_tag, lhs, lhs_ty, rhs, rhs_ty);
                    } else {
                        const offset = try self.bin_op(
                            .mul,
                            rhs,
                            Type.usize,
                            .{ .immediate = elem_size },
                            Type.usize,
                        );

                        const addr = try self.bin_op(
                            tag,
                            lhs,
                            Type.manyptr_u8,
                            offset,
                            Type.usize,
                        );
                        return addr;
                    }
                },
                else => unreachable,
            }
        },

        // These instructions have unsymteric bit sizes on RHS and LHS.
        .shr,
        .shl,
        => {
            switch (lhs_ty.zig_type_tag(zcu)) {
                .Float => return self.fail("TODO binary operations on floats", .{}),
                .Vector => return self.fail("TODO binary operations on vectors", .{}),
                .Int => {
                    const int_info = lhs_ty.int_info(zcu);
                    if (int_info.bits <= 64) {
                        return self.bin_op_register(tag, lhs, lhs_ty, rhs, rhs_ty);
                    } else {
                        return self.fail("TODO binary operations on int with bits > 64", .{});
                    }
                },
                else => unreachable,
            }
        },
        else => return self.fail("TODO bin_op {}", .{tag}),
    }
}
/// Don't call this function directly. Use bin_op instead.
///
/// Calling this function signals an intention to generate a Mir
/// instruction of the form
///
///     op dest, lhs, rhs
///
/// Asserts that generating an instruction of that form is possible.
fn bin_op_register(
    self: *Self,
    tag: Air.Inst.Tag,
    lhs: MCValue,
    lhs_ty: Type,
    rhs: MCValue,
    rhs_ty: Type,
) !MCValue {
    const lhs_reg, const lhs_lock = blk: {
        if (lhs == .register) break :blk .{ lhs.register, null };

        const lhs_reg, const lhs_lock = try self.alloc_reg();
        try self.gen_set_reg(lhs_ty, lhs_reg, lhs);
        break :blk .{ lhs_reg, lhs_lock };
    };
    defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const rhs_reg, const rhs_lock = blk: {
        if (rhs == .register) break :blk .{ rhs.register, null };

        const rhs_reg, const rhs_lock = try self.alloc_reg();
        try self.gen_set_reg(rhs_ty, rhs_reg, rhs);
        break :blk .{ rhs_reg, rhs_lock };
    };
    defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const dest_reg, const dest_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(dest_lock);

    const mir_tag: Mir.Inst.Tag = switch (tag) {
        .add => .add,
        .sub => .sub,
        .mul => .mul,

        .shl => .sllw,
        .shr => .srlw,

        .cmp_eq,
        .cmp_neq,
        .cmp_gt,
        .cmp_gte,
        .cmp_lt,
        .cmp_lte,
        => .pseudo,

        else => return self.fail("TODO: bin_op_register {s}", .{@tag_name(tag)}),
    };

    switch (mir_tag) {
        .add,
        .sub,
        .mul,
        .sllw,
        .srlw,
        => {
            _ = try self.add_inst(.{
                .tag = mir_tag,
                .ops = .rrr,
                .data = .{
                    .r_type = .{
                        .rd = dest_reg,
                        .rs1 = lhs_reg,
                        .rs2 = rhs_reg,
                    },
                },
            });
        },

        .pseudo => {
            const pseudo_op = switch (tag) {
                .cmp_eq,
                .cmp_neq,
                .cmp_gt,
                .cmp_gte,
                .cmp_lt,
                .cmp_lte,
                => .pseudo_compare,
                else => unreachable,
            };

            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = pseudo_op,
                .data = .{
                    .compare = .{
                        .rd = dest_reg,
                        .rs1 = lhs_reg,
                        .rs2 = rhs_reg,
                        .op = switch (tag) {
                            .cmp_eq => .eq,
                            .cmp_neq => .neq,
                            .cmp_gt => .gt,
                            .cmp_gte => .gte,
                            .cmp_lt => .lt,
                            .cmp_lte => .lte,
                            else => unreachable,
                        },
                    },
                },
            });
        },

        else => unreachable,
    }

    // generate the struct for OF checks

    return MCValue{ .register = dest_reg };
}

fn air_ptr_arithmetic(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const lhs = try self.resolve_inst(bin_op.lhs);
    const rhs = try self.resolve_inst(bin_op.rhs);
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        break :result try self.bin_op(tag, lhs, lhs_ty, rhs, rhs_ty);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_wrap(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement addwrap for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement add_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_sub_wrap(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        // RISCV arthemtic instructions already wrap, so this is simply a sub bin_op with
        // no overflow checks.
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const lhs_ty = self.type_of(bin_op.lhs);
        const rhs_ty = self.type_of(bin_op.rhs);

        break :result try self.bin_op(.sub, lhs, lhs_ty, rhs, rhs_ty);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_sub_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement sub_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mul(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement mul for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mul_wrap(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement mulwrap for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mul_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement mul_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const lhs = try self.resolve_inst(extra.lhs);
        const rhs = try self.resolve_inst(extra.rhs);
        const lhs_ty = self.type_of(extra.lhs);
        const rhs_ty = self.type_of(extra.rhs);

        const int_info = lhs_ty.int_info(zcu);

        const tuple_ty = self.type_of_index(inst);
        const result_mcv = try self.alloc_reg_or_mem(inst, false);
        const offset = result_mcv.load_frame;

        if (int_info.bits >= 8 and math.is_power_of_two(int_info.bits)) {
            const add_result = try self.bin_op(.add, lhs, lhs_ty, rhs, rhs_ty);
            const add_result_reg = try self.copy_to_tmp_register(lhs_ty, add_result);
            const add_result_reg_lock = self.register_manager.lock_reg_assume_unused(add_result_reg);
            defer self.register_manager.unlock_reg(add_result_reg_lock);

            const shift_amount: u6 = @int_cast(Type.usize.bit_size(zcu) - int_info.bits);

            const shift_reg, const shift_lock = try self.alloc_reg();
            defer self.register_manager.unlock_reg(shift_lock);

            _ = try self.add_inst(.{
                .tag = .slli,
                .ops = .rri,
                .data = .{
                    .i_type = .{
                        .rd = shift_reg,
                        .rs1 = add_result_reg,
                        .imm12 = Immediate.s(shift_amount),
                    },
                },
            });

            _ = try self.add_inst(.{
                .tag = if (int_info.signedness == .unsigned) .srli else .srai,
                .ops = .rri,
                .data = .{
                    .i_type = .{
                        .rd = shift_reg,
                        .rs1 = shift_reg,
                        .imm12 = Immediate.s(shift_amount),
                    },
                },
            });

            const add_result_frame: FrameAddr = .{
                .index = offset.index,
                .off = offset.off + @as(i32, @int_cast(tuple_ty.struct_field_offset(0, zcu))),
            };
            try self.gen_set_stack(
                lhs_ty,
                add_result_frame,
                add_result,
            );

            const overflow_mcv = try self.bin_op(
                .cmp_neq,
                .{ .register = shift_reg },
                lhs_ty,
                .{ .register = add_result_reg },
                lhs_ty,
            );

            const overflow_frame: FrameAddr = .{
                .index = offset.index,
                .off = offset.off + @as(i32, @int_cast(tuple_ty.struct_field_offset(1, zcu))),
            };
            try self.gen_set_stack(
                Type.u1,
                overflow_frame,
                overflow_mcv,
            );

            break :result result_mcv;
        } else {
            return self.fail("TODO: less than 8 bit or non-pow 2 addition", .{});
        }
    };

    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_sub_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_sub_with_overflow for {}", .{self.target.cpu.arch});
}

fn air_mul_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    //const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const zcu = self.bin_file.comp.module.?;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const lhs = try self.resolve_inst(extra.lhs);
        const rhs = try self.resolve_inst(extra.rhs);
        const lhs_ty = self.type_of(extra.lhs);
        const rhs_ty = self.type_of(extra.rhs);

        switch (lhs_ty.zig_type_tag(zcu)) {
            else => |x| return self.fail("TODO: air_mul_with_overflow {s}", .{@tag_name(x)}),
            .Int => {
                assert(lhs_ty.eql(rhs_ty, zcu));
                const int_info = lhs_ty.int_info(zcu);
                switch (int_info.bits) {
                    1...32 => {
                        if (self.has_feature(.m)) {
                            const dest = try self.bin_op(.mul, lhs, lhs_ty, rhs, rhs_ty);

                            const add_result_lock = self.register_manager.lock_reg_assume_unused(dest.register);
                            defer self.register_manager.unlock_reg(add_result_lock);

                            const tuple_ty = self.type_of_index(inst);

                            // TODO: optimization, set this to true. needs the other struct access stuff to support
                            // accessing registers.
                            const result_mcv = try self.alloc_reg_or_mem(inst, false);

                            const result_off: i32 = @int_cast(tuple_ty.struct_field_offset(0, zcu));
                            const overflow_off: i32 = @int_cast(tuple_ty.struct_field_offset(1, zcu));

                            try self.gen_set_stack(lhs_ty, result_mcv.offset(result_off).load_frame, dest);

                            if (int_info.bits >= 8 and math.is_power_of_two(int_info.bits)) {
                                if (int_info.signedness == .unsigned) {
                                    switch (int_info.bits) {
                                        1...8 => {
                                            const max_val = std.math.pow(u16, 2, int_info.bits) - 1;

                                            const overflow_reg, const overflow_lock = try self.alloc_reg();
                                            defer self.register_manager.unlock_reg(overflow_lock);

                                            const add_reg, const add_lock = blk: {
                                                if (dest == .register) break :blk .{ dest.register, null };

                                                const add_reg, const add_lock = try self.alloc_reg();
                                                try self.gen_set_reg(lhs_ty, add_reg, dest);
                                                break :blk .{ add_reg, add_lock };
                                            };
                                            defer if (add_lock) |lock| self.register_manager.unlock_reg(lock);

                                            _ = try self.add_inst(.{
                                                .tag = .andi,
                                                .ops = .rri,
                                                .data = .{ .i_type = .{
                                                    .rd = overflow_reg,
                                                    .rs1 = add_reg,
                                                    .imm12 = Immediate.s(max_val),
                                                } },
                                            });

                                            const overflow_mcv = try self.bin_op(
                                                .cmp_neq,
                                                .{ .register = overflow_reg },
                                                lhs_ty,
                                                .{ .register = add_reg },
                                                lhs_ty,
                                            );

                                            try self.gen_set_stack(
                                                lhs_ty,
                                                result_mcv.offset(overflow_off).load_frame,
                                                overflow_mcv,
                                            );

                                            break :result result_mcv;
                                        },

                                        else => return self.fail("TODO: air_mul_with_overflow check for size {d}", .{int_info.bits}),
                                    }
                                } else {
                                    return self.fail("TODO: air_mul_with_overflow calculate carry for signed addition", .{});
                                }
                            } else {
                                return self.fail("TODO: air_mul_with_overflow with < 8 bits or non-pow of 2", .{});
                            }
                        } else {
                            return self.fail("TODO: emulate mul for targets without M feature", .{});
                        }
                    },
                    else => return self.fail("TODO: air_mul_with_overflow larger than 32-bit mul", .{}),
                }
            },
        }
    };

    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_shl_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_shl_with_overflow for {}", .{self.target.cpu.arch});
}

fn air_div(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement div for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_rem(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement rem for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mod(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement zcu for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_bit_and(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement bitwise and for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_bit_or(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement bitwise or for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_xor(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement xor for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_shl(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const lhs_ty = self.type_of(bin_op.lhs);
        const rhs_ty = self.type_of(bin_op.rhs);

        break :result try self.bin_op(.shl, lhs, lhs_ty, rhs, rhs_ty);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_shl_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement shl_sat for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_shr(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement shr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_optional_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement .optional_payload for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_optional_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement .optional_payload_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_optional_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement .optional_payload_ptr_set for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unwrap_err_err(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const zcu = self.bin_file.comp.module.?;
    const err_union_ty = self.type_of(ty_op.operand);
    const err_ty = err_union_ty.error_union_set(zcu);
    const payload_ty = err_union_ty.error_union_payload(zcu);
    const operand = try self.resolve_inst(ty_op.operand);

    const result: MCValue = result: {
        if (err_ty.error_set_is_empty(zcu)) {
            break :result .{ .immediate = 0 };
        }

        if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) {
            break :result operand;
        }

        const err_off: u32 = @int_cast(err_union_error_offset(payload_ty, zcu));

        switch (operand) {
            .register => |reg| {
                const eu_lock = self.register_manager.lock_reg(reg);
                defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

                var result = try self.copy_to_new_register(inst, operand);

                if (err_off > 0) {
                    result = try self.bin_op(
                        .shr,
                        result,
                        err_union_ty,
                        .{ .immediate = @as(u6, @int_cast(err_off * 8)) },
                        Type.u8,
                    );
                }
                break :result result;
            },
            else => return self.fail("TODO implement unwrap_err_err for {}", .{operand}),
        }
    };

    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unwrap_err_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand_ty = self.type_of(ty_op.operand);
    const operand = try self.resolve_inst(ty_op.operand);
    const result = try self.gen_unwrap_err_union_payload_mir(operand_ty, operand);
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn gen_unwrap_err_union_payload_mir(
    self: *Self,
    err_union_ty: Type,
    err_union: MCValue,
) !MCValue {
    const zcu = self.bin_file.comp.module.?;
    const payload_ty = err_union_ty.error_union_payload(zcu);

    const result: MCValue = result: {
        if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) break :result .none;

        const payload_off: u31 = @int_cast(err_union_payload_offset(payload_ty, zcu));
        switch (err_union) {
            .load_frame => |frame_addr| break :result .{ .load_frame = .{
                .index = frame_addr.index,
                .off = frame_addr.off + payload_off,
            } },
            .register => |reg| {
                const eu_lock = self.register_manager.lock_reg(reg);
                defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

                var result: MCValue = .{ .register = try self.copy_to_tmp_register(err_union_ty, err_union) };

                if (payload_off > 0) {
                    result = try self.bin_op(
                        .shr,
                        result,
                        err_union_ty,
                        .{ .immediate = @as(u6, @int_cast(payload_off * 8)) },
                        Type.u8,
                    );
                }

                break :result result;
            },
            else => return self.fail("TODO implement gen_unwrap_err_union_payload_mir for {}", .{err_union}),
        }
    };

    return result;
}

// *(E!T) -> E
fn air_unwrap_err_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement unwrap error union error ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

// *(E!T) -> *T
fn air_unwrap_err_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement unwrap error union payload ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_err_union_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement .errunion_payload_ptr_set for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_err_return_trace(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = if (self.liveness.is_unused(inst))
        .unreach
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
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const zcu = self.bin_file.comp.module.?;
        const optional_ty = self.type_of_index(inst);

        // Optional with a zero-bit payload type is just a boolean true
        if (optional_ty.abi_size(zcu) == 1)
            break :result MCValue{ .immediate = 1 };

        return self.fail("TODO implement wrap optional for {}", .{self.target.cpu.arch});
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// T to E!T
fn air_wrap_err_union_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement wrap errunion payload for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// E to E!T
fn air_wrap_err_union_err(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const eu_ty = ty_op.ty.to_type();
    const pl_ty = eu_ty.error_union_payload(zcu);
    const err_ty = eu_ty.error_union_set(zcu);

    const result: MCValue = result: {
        if (!pl_ty.has_runtime_bits_ignore_comptime(zcu)) break :result try self.resolve_inst(ty_op.operand);

        const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(eu_ty, zcu));
        const pl_off: i32 = @int_cast(err_union_payload_offset(pl_ty, zcu));
        const err_off: i32 = @int_cast(err_union_error_offset(pl_ty, zcu));
        try self.gen_set_stack(pl_ty, .{ .index = frame_index, .off = pl_off }, .undef);
        const operand = try self.resolve_inst(ty_op.operand);
        try self.gen_set_stack(err_ty, .{ .index = frame_index, .off = err_off }, operand);
        break :result .{ .load_frame = .{ .index = frame_index } };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_try(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Try, pl_op.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
    const operand_ty = self.type_of(pl_op.operand);
    const result = try self.gen_try(inst, pl_op.operand, body, operand_ty, false);
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn gen_try(
    self: *Self,
    inst: Air.Inst.Index,
    operand: Air.Inst.Ref,
    body: []const Air.Inst.Index,
    operand_ty: Type,
    operand_is_ptr: bool,
) !MCValue {
    _ = operand_is_ptr;

    const liveness_cond_br = self.liveness.get_cond_br(inst);

    const operand_mcv = try self.resolve_inst(operand);
    const is_err_mcv = try self.is_err(null, operand_ty, operand_mcv);

    // A branch to the false section. Uses beq. 1 is the default "true" state.
    const reloc = try self.cond_br(Type.anyerror, is_err_mcv);

    if (self.liveness.operand_dies(inst, 0)) {
        if (operand.to_index()) |operand_inst| try self.process_death(operand_inst);
    }

    self.scope_generation += 1;
    const state = try self.save_state();

    for (liveness_cond_br.else_deaths) |death| try self.process_death(death);
    try self.gen_body(body);
    try self.restore_state(state, &.{}, .{
        .emit_instructions = false,
        .update_tracking = true,
        .resurrect = true,
        .close_scope = true,
    });

    self.perform_reloc(reloc);

    for (liveness_cond_br.then_deaths) |death| try self.process_death(death);

    const result = if (self.liveness.is_unused(inst))
        .unreach
    else
        try self.gen_unwrap_err_union_payload_mir(operand_ty, operand_mcv);

    return result;
}

fn air_slice_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);
        if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result src_mcv;

        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
        const dst_ty = self.type_of_index(inst);
        try self.gen_copy(dst_ty, dst_mcv, src_mcv);
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_len(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);
        switch (src_mcv) {
            .load_frame => |frame_addr| {
                const len_mcv: MCValue = .{ .load_frame = .{
                    .index = frame_addr.index,
                    .off = frame_addr.off + 8,
                } };
                if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result len_mcv;

                const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                try self.gen_copy(Type.usize, dst_mcv, len_mcv);
                break :result dst_mcv;
            },
            .register_pair => |pair| {
                const len_mcv: MCValue = .{ .register = pair[1] };

                if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result len_mcv;

                const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                try self.gen_copy(Type.usize, dst_mcv, len_mcv);
                break :result dst_mcv;
            },
            else => return self.fail("TODO air_slice_len for {}", .{src_mcv}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_len_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement ptr_slice_len_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_ptr_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement ptr_slice_ptr_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const is_volatile = false; // TODO
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    if (!is_volatile and self.liveness.is_unused(inst)) return self.finish_air(
        inst,
        .unreach,
        .{ bin_op.lhs, bin_op.rhs, .none },
    );
    const result: MCValue = result: {
        const slice_mcv = try self.resolve_inst(bin_op.lhs);
        const index_mcv = try self.resolve_inst(bin_op.rhs);

        const slice_ty = self.type_of(bin_op.lhs);

        const slice_ptr_field_type = slice_ty.slice_ptr_field_type(zcu);

        const index_lock: ?RegisterLock = if (index_mcv == .register)
            self.register_manager.lock_reg_assume_unused(index_mcv.register)
        else
            null;
        defer if (index_lock) |reg| self.register_manager.unlock_reg(reg);

        const base_mcv: MCValue = switch (slice_mcv) {
            .load_frame,
            .load_symbol,
            => .{ .register = try self.copy_to_tmp_register(slice_ptr_field_type, slice_mcv) },
            else => return self.fail("TODO slice_elem_val when slice is {}", .{slice_mcv}),
        };

        const dest = try self.alloc_reg_or_mem(inst, true);
        const addr = try self.bin_op(.ptr_add, base_mcv, slice_ptr_field_type, index_mcv, Type.usize);
        try self.load(dest, addr, slice_ptr_field_type);

        break :result dest;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_slice_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement slice_elem_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_array_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const array_ty = self.type_of(bin_op.lhs);
        const array_mcv = try self.resolve_inst(bin_op.lhs);

        const index_mcv = try self.resolve_inst(bin_op.rhs);
        const index_ty = self.type_of(bin_op.rhs);

        const elem_ty = array_ty.child_type(zcu);
        const elem_abi_size = elem_ty.abi_size(zcu);

        const addr_reg, const addr_reg_lock = try self.alloc_reg();
        defer self.register_manager.unlock_reg(addr_reg_lock);

        switch (array_mcv) {
            .register => {
                const frame_index = try self.alloc_frame_index(FrameAlloc.init_type(array_ty, zcu));
                try self.gen_set_stack(array_ty, .{ .index = frame_index }, array_mcv);
                try self.gen_set_reg(Type.usize, addr_reg, .{ .lea_frame = .{ .index = frame_index } });
            },
            .load_frame => |frame_addr| {
                try self.gen_set_reg(Type.usize, addr_reg, .{ .lea_frame = frame_addr });
            },
            else => try self.gen_set_reg(Type.usize, addr_reg, array_mcv.address()),
        }

        const offset_reg = try self.elem_offset(index_ty, index_mcv, elem_abi_size);
        const offset_lock = self.register_manager.lock_reg_assume_unused(offset_reg);
        defer self.register_manager.unlock_reg(offset_lock);

        const dst_mcv = try self.alloc_reg_or_mem(inst, false);
        _ = try self.add_inst(.{
            .tag = .add,
            .ops = .rrr,
            .data = .{ .r_type = .{
                .rd = addr_reg,
                .rs1 = offset_reg,
                .rs2 = addr_reg,
            } },
        });
        try self.gen_copy(elem_ty, dst_mcv, .{ .indirect = .{ .reg = addr_reg } });
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const is_volatile = false; // TODO
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result: MCValue = if (!is_volatile and self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement ptr_elem_val for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement ptr_elem_ptr for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_set_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    _ = bin_op;
    return self.fail("TODO implement air_set_union_tag for {}", .{self.target.cpu.arch});
    // return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_get_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_get_union_tag for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_clz(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_clz for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ctz(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand = try self.resolve_inst(ty_op.operand);
        const operand_ty = self.type_of(ty_op.operand);

        const dest_reg = try self.register_manager.alloc_reg(inst, gp);

        const source_reg, const source_lock = blk: {
            if (operand == .register) break :blk .{ operand.register, null };

            const source_reg, const source_lock = try self.alloc_reg();
            try self.gen_set_reg(operand_ty, source_reg, operand);
            break :blk .{ source_reg, source_lock };
        };
        defer if (source_lock) |lock| self.register_manager.unlock_reg(lock);

        // TODO: the B extension for RISCV should have the ctz instruction, and we should use it.

        try self.ctz(source_reg, dest_reg, operand_ty);

        break :result .{ .register = dest_reg };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn ctz(self: *Self, src: Register, dst: Register, ty: Type) !void {
    const zcu = self.bin_file.comp.module.?;
    const length = (ty.abi_size(zcu) * 8) - 1;

    const count_reg, const count_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(count_lock);

    const len_reg, const len_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(len_lock);

    try self.gen_set_reg(Type.usize, count_reg, .{ .immediate = 0 });
    try self.gen_set_reg(Type.usize, len_reg, .{ .immediate = length });

    _ = src;
    _ = dst;

    return self.fail("TODO: finish ctz", .{});
}

fn air_popcount(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_popcount for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_abs(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const ty = self.type_of(ty_op.operand);
        const scalar_ty = ty.scalar_type(zcu);
        const operand = try self.resolve_inst(ty_op.operand);

        switch (scalar_ty.zig_type_tag(zcu)) {
            .Int => if (ty.zig_type_tag(zcu) == .Vector) {
                return self.fail("TODO implement air_abs for {}", .{ty.fmt(zcu)});
            } else {
                const int_bits = ty.int_info(zcu).bits;

                if (int_bits > 32) {
                    return self.fail("TODO: air_abs for larger than 32 bits", .{});
                }

                // promote the src into a register
                const src_mcv = try self.copy_to_new_register(inst, operand);
                // temp register for shift
                const temp_reg = try self.register_manager.alloc_reg(inst, gp);

                _ = try self.add_inst(.{
                    .tag = .abs,
                    .ops = .rri,
                    .data = .{
                        .i_type = .{
                            .rs1 = src_mcv.register,
                            .rd = temp_reg,
                            .imm12 = Immediate.s(int_bits - 1),
                        },
                    },
                });

                break :result src_mcv;
            },
            else => return self.fail("TODO: implement air_abs {}", .{scalar_ty.fmt(zcu)}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_byte_swap(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const zcu = self.bin_file.comp.module.?;
        const ty = self.type_of(ty_op.operand);
        const operand = try self.resolve_inst(ty_op.operand);

        const int_bits = ty.int_info(zcu).bits;

        // bytes are no-op
        if (int_bits == 8 and self.reuse_operand(inst, ty_op.operand, 0, operand)) {
            return self.finish_air(inst, operand, .{ ty_op.operand, .none, .none });
        }

        const dest_reg = try self.register_manager.alloc_reg(null, gp);
        try self.gen_set_reg(ty, dest_reg, operand);

        const dest_mcv: MCValue = .{ .register = dest_reg };

        switch (int_bits) {
            16 => {
                const temp = try self.bin_op(.shr, dest_mcv, ty, .{ .immediate = 8 }, Type.u8);
                assert(temp == .register);
                _ = try self.add_inst(.{
                    .tag = .slli,
                    .ops = .rri,
                    .data = .{ .i_type = .{
                        .imm12 = Immediate.s(8),
                        .rd = dest_reg,
                        .rs1 = dest_reg,
                    } },
                });
                _ = try self.add_inst(.{
                    .tag = .@"or",
                    .ops = .rri,
                    .data = .{ .r_type = .{
                        .rd = dest_reg,
                        .rs1 = dest_reg,
                        .rs2 = temp.register,
                    } },
                });
            },
            else => return self.fail("TODO: {d} bits for air_byte_swap", .{int_bits}),
        }

        break :result dest_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_bit_reverse(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_bit_reverse for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unary_math(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst))
        .unreach
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
    return self.reuse_operand_advanced(inst, operand, op_index, mcv, inst);
}

fn reuse_operand_advanced(
    self: *Self,
    inst: Air.Inst.Index,
    operand: Air.Inst.Ref,
    op_index: Liveness.OperandInt,
    mcv: MCValue,
    maybe_tracked_inst: ?Air.Inst.Index,
) bool {
    if (!self.liveness.operand_dies(inst, op_index))
        return false;

    switch (mcv) {
        .register,
        .register_pair,
        => for (mcv.get_regs()) |reg| {
            // If it's in the registers table, need to associate the register(s) with the
            // new instruction.
            if (maybe_tracked_inst) |tracked_inst| {
                if (!self.register_manager.is_reg_free(reg)) {
                    if (RegisterManager.index_of_reg_into_tracked(reg)) |index| {
                        self.register_manager.registers[index] = tracked_inst;
                    }
                }
            } else self.register_manager.free_reg(reg);
        },
        .load_frame => |frame_addr| if (frame_addr.index.is_named()) return false,
        else => return false,
    }

    // Prevent the operand deaths processing code from deallocating it.
    self.liveness.clear_operand_death(inst, op_index);
    const op_inst = operand.to_index().?;
    self.get_resolved_inst_value(op_inst).reuse(self, maybe_tracked_inst, op_inst);

    return true;
}

fn air_load(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const elem_ty = self.type_of_index(inst);
    const result: MCValue = result: {
        if (!elem_ty.has_runtime_bits(zcu))
            break :result .none;

        const ptr = try self.resolve_inst(ty_op.operand);
        const is_volatile = self.type_of(ty_op.operand).is_volatile_ptr(zcu);
        if (self.liveness.is_unused(inst) and !is_volatile)
            break :result .unreach;

        const dst_mcv: MCValue = blk: {
            if (self.reuse_operand(inst, ty_op.operand, 0, ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk ptr;
            } else {
                break :blk try self.alloc_reg_or_mem(inst, true);
            }
        };

        try self.load(dst_mcv, ptr, self.type_of(ty_op.operand));
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn load(self: *Self, dst_mcv: MCValue, ptr_mcv: MCValue, ptr_ty: Type) InnerError!void {
    const zcu = self.bin_file.comp.module.?;
    const dst_ty = ptr_ty.child_type(zcu);

    log.debug("loading {}:{} into {}", .{ ptr_mcv, ptr_ty.fmt(zcu), dst_mcv });

    switch (ptr_mcv) {
        .none,
        .undef,
        .unreach,
        .dead,
        .register_pair,
        .reserved_frame,
        => unreachable, // not a valid pointer

        .immediate,
        .register,
        .register_offset,
        .lea_frame,
        .lea_symbol,
        => try self.gen_copy(dst_ty, dst_mcv, ptr_mcv.deref()),

        .memory,
        .indirect,
        .load_symbol,
        .load_frame,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try self.gen_copy(dst_ty, dst_mcv, .{ .indirect = .{ .reg = addr_reg } });
        },
        .air_ref => |ptr_ref| try self.load(dst_mcv, try self.resolve_inst(ptr_ref), ptr_ty),
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

    return self.finish_air(inst, .none, .{ bin_op.lhs, bin_op.rhs, .none });
}

/// Loads `value` into the "payload" of `pointer`.
fn store(self: *Self, ptr_mcv: MCValue, src_mcv: MCValue, ptr_ty: Type, src_ty: Type) !void {
    const zcu = self.bin_file.comp.module.?;

    log.debug("storing {}:{} in {}:{}", .{ src_mcv, src_ty.fmt(zcu), ptr_mcv, ptr_ty.fmt(zcu) });

    switch (ptr_mcv) {
        .none => unreachable,
        .undef => unreachable,
        .unreach => unreachable,
        .dead => unreachable,
        .register_pair => unreachable,
        .reserved_frame => unreachable,

        .immediate,
        .register,
        .register_offset,
        .lea_symbol,
        .lea_frame,
        => try self.gen_copy(src_ty, ptr_mcv.deref(), src_mcv),

        .memory,
        .indirect,
        .load_symbol,
        .load_frame,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try self.gen_copy(src_ty, .{ .indirect = .{ .reg = addr_reg } }, src_mcv);
        },
        .air_ref => |ptr_ref| try self.store(try self.resolve_inst(ptr_ref), src_mcv, ptr_ty, src_ty),
    }
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
    const zcu = self.bin_file.comp.module.?;
    const ptr_field_ty = self.type_of_index(inst);
    const ptr_container_ty = self.type_of(operand);
    const ptr_container_ty_info = ptr_container_ty.ptr_info(zcu);
    const container_ty = ptr_container_ty.child_type(zcu);

    const field_offset: i32 = if (zcu.type_to_packed_struct(container_ty)) |struct_obj|
        if (ptr_field_ty.ptr_info(zcu).packed_offset.host_size == 0)
            @div_exact(zcu.struct_packed_field_bit_offset(struct_obj, index) +
                ptr_container_ty_info.packed_offset.bit_offset, 8)
        else
            0
    else
        @int_cast(container_ty.struct_field_offset(index, zcu));

    const src_mcv = try self.resolve_inst(operand);
    const dst_mcv = if (switch (src_mcv) {
        .immediate, .lea_frame => true,
        .register, .register_offset => self.reuse_operand(inst, operand, 0, src_mcv),
        else => false,
    }) src_mcv else try self.copy_to_new_register(inst, src_mcv);
    return dst_mcv.offset(field_offset);
}

fn air_struct_field_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;

    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
    const operand = extra.struct_operand;
    const index = extra.field_index;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const zcu = self.bin_file.comp.module.?;
        const src_mcv = try self.resolve_inst(operand);
        const struct_ty = self.type_of(operand);
        const field_ty = struct_ty.struct_field_type(index, zcu);
        if (!field_ty.has_runtime_bits_ignore_comptime(zcu)) break :result .none;

        const field_off: u32 = switch (struct_ty.container_layout(zcu)) {
            .auto, .@"extern" => @int_cast(struct_ty.struct_field_offset(index, zcu) * 8),
            .@"packed" => if (zcu.type_to_struct(struct_ty)) |struct_type|
                zcu.struct_packed_field_bit_offset(struct_type, index)
            else
                0,
        };

        switch (src_mcv) {
            .dead, .unreach => unreachable,
            .register => |src_reg| {
                const src_reg_lock = self.register_manager.lock_reg_assume_unused(src_reg);
                defer self.register_manager.unlock_reg(src_reg_lock);

                const dst_reg = if (field_off == 0)
                    (try self.copy_to_new_register(inst, src_mcv)).register
                else
                    try self.copy_to_tmp_register(Type.usize, .{ .register = src_reg });

                const dst_mcv: MCValue = .{ .register = dst_reg };
                const dst_lock = self.register_manager.lock_reg(dst_reg);
                defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

                if (field_off > 0) {
                    _ = try self.add_inst(.{
                        .tag = .srli,
                        .ops = .rri,
                        .data = .{ .i_type = .{
                            .imm12 = Immediate.s(@int_cast(field_off)),
                            .rd = dst_reg,
                            .rs1 = dst_reg,
                        } },
                    });

                    return self.fail("TODO: air_struct_field_val register with field_off > 0", .{});
                }

                break :result if (field_off == 0) dst_mcv else try self.copy_to_new_register(inst, dst_mcv);
            },
            .load_frame => {
                const field_abi_size: u32 = @int_cast(field_ty.abi_size(mod));
                if (field_off % 8 == 0) {
                    const field_byte_off = @div_exact(field_off, 8);
                    const off_mcv = src_mcv.address().offset(@int_cast(field_byte_off)).deref();
                    const field_bit_size = field_ty.bit_size(mod);

                    if (field_abi_size <= 8) {
                        const int_ty = try mod.int_type(
                            if (field_ty.is_abi_int(mod)) field_ty.int_info(mod).signedness else .unsigned,
                            @int_cast(field_bit_size),
                        );

                        const dst_reg, const dst_lock = try self.alloc_reg();
                        const dst_mcv = MCValue{ .register = dst_reg };
                        defer self.register_manager.unlock_reg(dst_lock);

                        try self.gen_copy(int_ty, dst_mcv, off_mcv);
                        break :result try self.copy_to_new_register(inst, dst_mcv);
                    }

                    const container_abi_size: u32 = @int_cast(struct_ty.abi_size(mod));
                    const dst_mcv = if (field_byte_off + field_abi_size <= container_abi_size and
                        self.reuse_operand(inst, operand, 0, src_mcv))
                        off_mcv
                    else dst: {
                        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                        try self.gen_copy(field_ty, dst_mcv, off_mcv);
                        break :dst dst_mcv;
                    };
                    if (field_abi_size * 8 > field_bit_size and dst_mcv.is_memory()) {
                        const tmp_reg, const tmp_lock = try self.alloc_reg();
                        defer self.register_manager.unlock_reg(tmp_lock);

                        const hi_mcv =
                            dst_mcv.address().offset(@int_cast(field_bit_size / 64 * 8)).deref();
                        try self.gen_set_reg(Type.usize, tmp_reg, hi_mcv);
                        try self.gen_copy(Type.usize, hi_mcv, .{ .register = tmp_reg });
                    }
                    break :result dst_mcv;
                }

                return self.fail("TODO: air_struct_field_val load_frame field_off non multiple of 8", .{});
            },
            else => return self.fail("TODO: airStructField {s}", .{@tag_name(src_mcv)}),
        }
    };

    return self.finish_air(inst, result, .{ extra.struct_operand, .none, .none });
}

fn air_field_parent_ptr(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement codegen air_field_parent_ptr", .{});
}

fn gen_arg_dbg_info(self: Self, inst: Air.Inst.Index, mcv: MCValue) !void {
    const zcu = self.bin_file.comp.module.?;
    const arg = self.air.instructions.items(.data)[@int_from_enum(inst)].arg;
    const ty = arg.ty.to_type();
    const owner_decl = zcu.func_owner_decl_index(self.func_index);
    const name = zcu.get_param_name(self.func_index, arg.src_index);

    switch (self.debug_output) {
        .dwarf => |dw| switch (mcv) {
            .register => |reg| try dw.gen_arg_dbg_info(name, ty, owner_decl, .{
                .register = reg.dwarf_loc_op(),
            }),
            .load_frame => {},
            else => {},
        },
        .plan9 => {},
        .none => {},
    }
}

fn air_arg(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    var arg_index = self.arg_index;

    // we skip over args that have no bits
    while (self.args[arg_index] == .none) arg_index += 1;
    self.arg_index = arg_index + 1;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const src_mcv = self.args[arg_index];

        const arg_ty = self.type_of_index(inst);

        const dst_mcv = switch (src_mcv) {
            .register => dst: {
                const frame = try self.alloc_frame_index(FrameAlloc.init(.{
                    .size = Type.usize.abi_size(zcu),
                    .alignment = Type.usize.abi_alignment(zcu),
                }));
                const dst_mcv: MCValue = .{ .load_frame = .{ .index = frame } };
                try self.gen_copy(Type.usize, dst_mcv, src_mcv);
                break :dst dst_mcv;
            },
            .register_pair => dst: {
                const frame = try self.alloc_frame_index(FrameAlloc.init(.{
                    .size = Type.usize.abi_size(zcu) * 2,
                    .alignment = Type.usize.abi_alignment(zcu),
                }));
                const dst_mcv: MCValue = .{ .load_frame = .{ .index = frame } };
                try self.gen_copy(arg_ty, dst_mcv, src_mcv);
                break :dst dst_mcv;
            },
            .load_frame => src_mcv,
            else => return self.fail("TODO: air_arg {s}", .{@tag_name(src_mcv)}),
        };

        try self.gen_arg_dbg_info(inst, src_mcv);
        break :result dst_mcv;
    };

    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_trap(self: *Self) !void {
    _ = try self.add_inst(.{
        .tag = .unimp,
        .ops = .none,
        .data = undefined,
    });
    return self.finish_air_bookkeeping();
}

fn air_breakpoint(self: *Self) !void {
    _ = try self.add_inst(.{
        .tag = .ebreak,
        .ops = .none,
        .data = undefined,
    });
    return self.finish_air_bookkeeping();
}

fn air_ret_addr(self: *Self, inst: Air.Inst.Index) !void {
    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
    try self.gen_copy(Type.usize, dst_mcv, .{ .load_frame = .{ .index = .ret_addr } });
    return self.finish_air(inst, dst_mcv, .{ .none, .none, .none });
}

fn air_frame_address(self: *Self, inst: Air.Inst.Index) !void {
    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
    try self.gen_copy(Type.usize, dst_mcv, .{ .lea_frame = .{ .index = .base_ptr } });
    return self.finish_air(inst, dst_mcv, .{ .none, .none, .none });
}

fn air_fence(self: *Self) !void {
    return self.fail("TODO implement fence() for {}", .{self.target.cpu.arch});
    //return self.finish_air_bookkeeping();
}

fn air_call(self: *Self, inst: Air.Inst.Index, modifier: std.builtin.CallModifier) !void {
    if (modifier == .always_tail) return self.fail("TODO implement tail calls for riscv64", .{});
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const callee = pl_op.operand;
    const extra = self.air.extra_data(Air.Call, pl_op.payload);
    const arg_refs: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra.end..][0..extra.data.args_len]);

    const expected_num_args = 8;
    const ExpectedContents = extern struct {
        vals: [expected_num_args][@size_of(MCValue)]u8 align(@alignOf(MCValue)),
    };
    var stack align(@max(@alignOf(ExpectedContents), @alignOf(std.heap.StackFallbackAllocator(0)))) =
        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
    const allocator = stack.get();

    const arg_tys = try allocator.alloc(Type, arg_refs.len);
    defer allocator.free(arg_tys);
    for (arg_tys, arg_refs) |*arg_ty, arg_ref| arg_ty.* = self.type_of(arg_ref);

    const arg_vals = try allocator.alloc(MCValue, arg_refs.len);
    defer allocator.free(arg_vals);
    for (arg_vals, arg_refs) |*arg_val, arg_ref| arg_val.* = .{ .air_ref = arg_ref };

    const call_ret = try self.gen_call(.{ .air = callee }, arg_tys, arg_vals);

    var bt = self.liveness.iterate_big_tomb(inst);
    try self.feed(&bt, pl_op.operand);
    for (arg_refs) |arg_ref| try self.feed(&bt, arg_ref);

    const result = if (self.liveness.is_unused(inst)) .unreach else call_ret;
    return self.finish_air_result(inst, result);
}

fn gen_call(
    self: *Self,
    info: union(enum) {
        air: Air.Inst.Ref,
        lib: struct {
            return_type: InternPool.Index,
            param_types: []const InternPool.Index,
            lib: ?[]const u8 = null,
            callee: []const u8,
        },
    },
    arg_tys: []const Type,
    args: []const MCValue,
) !MCValue {
    const zcu = self.bin_file.comp.module.?;

    const fn_ty = switch (info) {
        .air => |callee| fn_info: {
            const callee_ty = self.type_of(callee);
            break :fn_info switch (callee_ty.zig_type_tag(zcu)) {
                .Fn => callee_ty,
                .Pointer => callee_ty.child_type(zcu),
                else => unreachable,
            };
        },
        .lib => |lib| try zcu.func_type(.{
            .param_types = lib.param_types,
            .return_type = lib.return_type,
            .cc = .C,
        }),
    };

    const fn_info = zcu.type_to_func(fn_ty).?;
    var call_info = try self.resolve_calling_convention_values(fn_info);
    defer call_info.deinit(self);

    // We need a properly aligned and sized call frame to be able to call this function.
    {
        const needed_call_frame = FrameAlloc.init(.{
            .size = call_info.stack_byte_count,
            .alignment = call_info.stack_align,
        });
        const frame_allocs_slice = self.frame_allocs.slice();
        const stack_frame_size =
            &frame_allocs_slice.items(.abi_size)[@int_from_enum(FrameIndex.call_frame)];
        stack_frame_size.* = @max(stack_frame_size.*, needed_call_frame.abi_size);
        const stack_frame_align =
            &frame_allocs_slice.items(.abi_align)[@int_from_enum(FrameIndex.call_frame)];
        stack_frame_align.* = stack_frame_align.max(needed_call_frame.abi_align);
    }

    for (call_info.args, 0..) |mc_arg, arg_i| try self.gen_copy(arg_tys[arg_i], mc_arg, args[arg_i]);

    // Due to incremental compilation, how function calls are generated depends
    // on linking.
    switch (info) {
        .air => |callee| {
            if (try self.air.value(callee, zcu)) |func_value| {
                const func_key = zcu.intern_pool.index_to_key(func_value.ip_index);
                switch (switch (func_key) {
                    else => func_key,
                    .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
                        .decl => |decl| zcu.intern_pool.index_to_key(zcu.decl_ptr(decl).val.to_intern()),
                        else => func_key,
                    } else func_key,
                }) {
                    .func => |func| {
                        if (self.bin_file.cast(link.File.Elf)) |elf_file| {
                            const sym_index = try elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, func.owner_decl);
                            const sym = elf_file.symbol(sym_index);

                            _ = try sym.get_or_create_zig_got_entry(sym_index, elf_file);
                            const got_addr = sym.zig_got_address(elf_file);
                            try self.gen_set_reg(Type.usize, .ra, .{ .memory = @int_cast(got_addr) });

                            _ = try self.add_inst(.{
                                .tag = .jalr,
                                .ops = .rri,
                                .data = .{ .i_type = .{
                                    .rd = .ra,
                                    .rs1 = .ra,
                                    .imm12 = Immediate.s(0),
                                } },
                            });
                        } else unreachable;
                    },
                    .extern_func => return self.fail("TODO: extern func calls", .{}),
                    else => return self.fail("TODO implement calling bitcasted functions", .{}),
                }
            } else {
                assert(self.type_of(callee).zig_type_tag(zcu) == .Pointer);
                const addr_reg, const addr_lock = try self.alloc_reg();
                defer self.register_manager.unlock_reg(addr_lock);
                try self.gen_set_reg(Type.usize, addr_reg, .{ .air_ref = callee });
                _ = try self.add_inst(.{
                    .tag = .jalr,
                    .ops = .rri,
                    .data = .{ .i_type = .{
                        .rd = .ra,
                        .rs1 = addr_reg,
                        .imm12 = Immediate.s(0),
                    } },
                });
            }
        },
        .lib => return self.fail("TODO: lib func calls", .{}),
    }

    return call_info.return_value.short;
}

fn air_ret(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    const zcu = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    if (safety) {
        // safe
    } else {
        // not safe
    }

    const ret_ty = self.fn_type.fn_return_type(zcu);
    switch (self.ret_mcv.short) {
        .none => {},
        .register,
        .register_pair,
        => try self.gen_copy(ret_ty, self.ret_mcv.short, .{ .air_ref = un_op }),
        .indirect => |reg_off| {
            try self.register_manager.get_reg(reg_off.reg, null);
            const lock = self.register_manager.lock_reg_assume_unused(reg_off.reg);
            defer self.register_manager.unlock_reg(lock);

            try self.gen_set_reg(Type.usize, reg_off.reg, self.ret_mcv.long);
            try self.gen_copy(
                ret_ty,
                .{ .register_offset = reg_off },
                .{ .air_ref = un_op },
            );
        },
        else => unreachable,
    }

    self.ret_mcv.live_out(self, inst);
    try self.finish_air(inst, .unreach, .{ un_op, .none, .none });

    // Just add space for an instruction, reloced this later
    const index = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_j,
        .data = .{ .inst = undefined },
    });

    try self.exitlude_jump_relocs.append(self.gpa, index);
}

fn air_ret_load(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ptr = try self.resolve_inst(un_op);

    const ptr_ty = self.type_of(un_op);
    switch (self.ret_mcv.short) {
        .none => {},
        .register, .register_pair => try self.load(self.ret_mcv.short, ptr, ptr_ty),
        .indirect => |reg_off| try self.gen_set_reg(ptr_ty, reg_off.reg, ptr),
        else => unreachable,
    }
    self.ret_mcv.live_out(self, inst);
    try self.finish_air(inst, .unreach, .{ un_op, .none, .none });

    // Just add space for an instruction, reloced this later
    const index = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_j,
        .data = .{ .inst = undefined },
    });

    try self.exitlude_jump_relocs.append(self.gpa, index);
}

fn air_cmp(self: *Self, inst: Air.Inst.Index) !void {
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const zcu = self.bin_file.comp.module.?;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const lhs = try self.resolve_inst(bin_op.lhs);
        const rhs = try self.resolve_inst(bin_op.rhs);
        const lhs_ty = self.type_of(bin_op.lhs);

        const int_ty = switch (lhs_ty.zig_type_tag(zcu)) {
            .Vector => unreachable, // Handled by cmp_vector.
            .Enum => lhs_ty.int_tag_type(zcu),
            .Int => lhs_ty,
            .Bool => Type.u1,
            .Pointer => Type.usize,
            .ErrorSet => Type.u16,
            .Optional => blk: {
                const payload_ty = lhs_ty.optional_child(zcu);
                if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) {
                    break :blk Type.u1;
                } else if (lhs_ty.is_ptr_like_optional(zcu)) {
                    break :blk Type.usize;
                } else {
                    return self.fail("TODO riscv cmp non-pointer optionals", .{});
                }
            },
            .Float => return self.fail("TODO riscv cmp floats", .{}),
            else => unreachable,
        };

        const int_info = int_ty.int_info(zcu);
        if (int_info.bits <= 64) {
            break :result try self.bin_op(tag, lhs, int_ty, rhs, int_ty);
        } else {
            return self.fail("TODO riscv cmp for ints > 64 bits", .{});
        }
    };

    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_cmp_vector(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_cmp_vector for {}", .{self.target.cpu.arch});
}

fn air_cmp_lt_errors_len(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    _ = operand;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_cmp_lt_errors_len for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_dbg_stmt(self: *Self, inst: Air.Inst.Index) !void {
    const dbg_stmt = self.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;

    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_line_column,
        .data = .{ .pseudo_dbg_line_column = .{
            .line = dbg_stmt.line,
            .column = dbg_stmt.column,
        } },
    });

    return self.finish_air_bookkeeping();
}

fn air_dbg_inline_block(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
    try self.lower_block(inst, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
}

fn air_dbg_var(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const operand = pl_op.operand;
    const ty = self.type_of(operand);
    const mcv = try self.resolve_inst(operand);

    const name = self.air.null_terminated_string(pl_op.payload);

    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
    try self.gen_var_dbg_info(tag, ty, mcv, name);

    return self.finish_air(inst, .unreach, .{ operand, .none, .none });
}

fn gen_var_dbg_info(
    self: Self,
    tag: Air.Inst.Tag,
    ty: Type,
    mcv: MCValue,
    name: [:0]const u8,
) !void {
    const zcu = self.bin_file.comp.module.?;
    const is_ptr = switch (tag) {
        .dbg_var_ptr => true,
        .dbg_var_val => false,
        else => unreachable,
    };

    switch (self.debug_output) {
        .dwarf => |dw| {
            const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (mcv) {
                .register => |reg| .{ .register = reg.dwarf_loc_op() },
                .memory => |address| .{ .memory = address },
                .load_symbol => |sym_off| loc: {
                    assert(sym_off.off == 0);
                    break :loc .{ .linker_load = .{ .type = .direct, .sym_index = sym_off.sym } };
                },
                .immediate => |x| .{ .immediate = x },
                .undef => .undef,
                .none => .none,
                else => blk: {
                    // log.warn("TODO generate debug info for {}", .{mcv});
                    break :blk .nop;
                },
            };
            try dw.gen_var_dbg_info(name, ty, zcu.func_owner_decl_index(self.func_index), is_ptr, loc);
        },
        .plan9 => {},
        .none => {},
    }
}

fn air_cond_br(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const cond = try self.resolve_inst(pl_op.operand);
    const cond_ty = self.type_of(pl_op.operand);
    const extra = self.air.extra_data(Air.CondBr, pl_op.payload);
    const then_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
    const liveness_cond_br = self.liveness.get_cond_br(inst);

    // If the condition dies here in this condbr instruction, process
    // that death now instead of later as this has an effect on
    // whether it needs to be spilled in the branches
    if (self.liveness.operand_dies(inst, 0)) {
        if (pl_op.operand.to_index()) |op_inst| try self.process_death(op_inst);
    }

    self.scope_generation += 1;
    const state = try self.save_state();
    const reloc = try self.cond_br(cond_ty, cond);

    for (liveness_cond_br.then_deaths) |death| try self.process_death(death);
    try self.gen_body(then_body);
    try self.restore_state(state, &.{}, .{
        .emit_instructions = false,
        .update_tracking = true,
        .resurrect = true,
        .close_scope = true,
    });

    self.perform_reloc(reloc);

    for (liveness_cond_br.else_deaths) |death| try self.process_death(death);
    try self.gen_body(else_body);
    try self.restore_state(state, &.{}, .{
        .emit_instructions = false,
        .update_tracking = true,
        .resurrect = true,
        .close_scope = true,
    });

    // We already took care of pl_op.operand earlier, so there's nothing left to do.
    self.finish_air_bookkeeping();
}

fn cond_br(self: *Self, cond_ty: Type, condition: MCValue) !Mir.Inst.Index {
    const cond_reg = try self.copy_to_tmp_register(cond_ty, condition);

    return try self.add_inst(.{
        .tag = .beq,
        .ops = .rr_inst,
        .data = .{
            .b_type = .{
                .rs1 = cond_reg,
                .rs2 = .zero,
                .inst = undefined,
            },
        },
    });
}

fn air_is_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand = try self.resolve_inst(un_op);
        break :result try self.is_null(operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const operand: MCValue = blk: {
            if (self.reuse_operand(inst, un_op, 0, operand_ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk operand_ptr;
            } else {
                break :blk try self.alloc_reg_or_mem(inst, true);
            }
        };
        try self.load(operand, operand_ptr, self.type_of(un_op));
        break :result try self.is_null(operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn is_null(self: *Self, operand: MCValue) !MCValue {
    _ = operand;
    // Here you can specialize this instruction if it makes sense to, otherwise the default
    // will call is_non_null and invert the result.
    return self.fail("TODO call is_non_null and invert the result", .{});
}

fn air_is_non_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand = try self.resolve_inst(un_op);
        break :result try self.is_non_null(operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn is_non_null(self: *Self, operand: MCValue) !MCValue {
    _ = operand;
    // Here you can specialize this instruction if it makes sense to, otherwise the default
    // will call is_null and invert the result.
    return self.fail("TODO call is_null and invert the result", .{});
}

fn air_is_non_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const operand: MCValue = blk: {
            if (self.reuse_operand(inst, un_op, 0, operand_ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk operand_ptr;
            } else {
                break :blk try self.alloc_reg_or_mem(inst, true);
            }
        };
        try self.load(operand, operand_ptr, self.type_of(un_op));
        break :result try self.is_non_null(operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand = try self.resolve_inst(un_op);
        const operand_ty = self.type_of(un_op);
        break :result try self.is_err(inst, operand_ty, operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const operand: MCValue = blk: {
            if (self.reuse_operand(inst, un_op, 0, operand_ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk operand_ptr;
            } else {
                break :blk try self.alloc_reg_or_mem(inst, true);
            }
        };
        try self.load(operand, operand_ptr, self.type_of(un_op));
        const operand_ptr_ty = self.type_of(un_op);
        const operand_ty = operand_ptr_ty.child_type(zcu);

        break :result try self.is_err(inst, operand_ty, operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

/// Generates a compare instruction which will indicate if `eu_mcv` is an error.
///
/// Result is in the return register.
fn is_err(self: *Self, maybe_inst: ?Air.Inst.Index, eu_ty: Type, eu_mcv: MCValue) !MCValue {
    const zcu = self.bin_file.comp.module.?;
    const err_ty = eu_ty.error_union_set(zcu);
    if (err_ty.error_set_is_empty(zcu)) return MCValue{ .immediate = 0 }; // always false

    _ = maybe_inst;

    const err_off = err_union_error_offset(eu_ty.error_union_payload(zcu), zcu);

    switch (eu_mcv) {
        .register => |reg| {
            const eu_lock = self.register_manager.lock_reg(reg);
            defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

            const return_reg = try self.copy_to_tmp_register(eu_ty, eu_mcv);
            const return_lock = self.register_manager.lock_reg_assume_unused(return_reg);
            defer self.register_manager.unlock_reg(return_lock);

            var return_mcv: MCValue = .{ .register = return_reg };

            if (err_off > 0) {
                return_mcv = try self.bin_op(
                    .shr,
                    return_mcv,
                    eu_ty,
                    .{ .immediate = @as(u6, @int_cast(err_off * 8)) },
                    Type.u8,
                );
            }

            return_mcv = try self.bin_op(
                .cmp_neq,
                return_mcv,
                Type.u16,
                .{ .immediate = 0 },
                Type.u16,
            );

            return return_mcv;
        },
        else => return self.fail("TODO implement is_err for {}", .{eu_mcv}),
    }
}

fn air_is_non_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand = try self.resolve_inst(un_op);
        const ty = self.type_of(un_op);
        break :result try self.is_non_err(inst, ty, operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn is_non_err(self: *Self, inst: Air.Inst.Index, eu_ty: Type, eu_mcv: MCValue) !MCValue {
    const is_err_res = try self.is_err(inst, eu_ty, eu_mcv);
    switch (is_err_res) {
        .register => |reg| {
            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_not,
                .data = .{
                    .rr = .{
                        .rd = reg,
                        .rs = reg,
                    },
                },
            });
            return is_err_res;
        },
        // always false case
        .immediate => |imm| {
            assert(imm == 0);
            return MCValue{ .immediate = @int_from_bool(imm == 0) };
        },
        else => unreachable,
    }
}

fn air_is_non_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const operand_ptr = try self.resolve_inst(un_op);
        const operand: MCValue = blk: {
            if (self.reuse_operand(inst, un_op, 0, operand_ptr)) {
                // The MCValue that holds the pointer can be re-used as the value.
                break :blk operand_ptr;
            } else {
                break :blk try self.alloc_reg_or_mem(inst, true);
            }
        };
        const operand_ptr_ty = self.type_of(un_op);
        const operand_ty = operand_ptr_ty.child_type(zcu);

        try self.load(operand, operand_ptr, self.type_of(un_op));
        break :result try self.is_non_err(inst, operand_ty, operand);
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_loop(self: *Self, inst: Air.Inst.Index) !void {
    // A loop is a setup to be able to jump back to the beginning.
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const loop = self.air.extra_data(Air.Block, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[loop.end..][0..loop.data.body_len]);

    self.scope_generation += 1;
    const state = try self.save_state();

    const jmp_target: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
    try self.gen_body(body);
    try self.restore_state(state, &.{}, .{
        .emit_instructions = true,
        .update_tracking = false,
        .resurrect = false,
        .close_scope = true,
    });
    _ = try self.jump(jmp_target);

    self.finish_air_bookkeeping();
}

/// Send control flow to the `index` of `self.code`.
fn jump(self: *Self, index: Mir.Inst.Index) !Mir.Inst.Index {
    return self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_j,
        .data = .{
            .inst = index,
        },
    });
}

fn air_block(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Block, ty_pl.payload);
    try self.lower_block(inst, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
}

fn lower_block(self: *Self, inst: Air.Inst.Index, body: []const Air.Inst.Index) !void {
    // A block is a setup to be able to jump to the end.
    const inst_tracking_i = self.inst_tracking.count();
    self.inst_tracking.put_assume_capacity_no_clobber(inst, InstTracking.init(.unreach));

    self.scope_generation += 1;
    try self.blocks.put_no_clobber(self.gpa, inst, .{ .state = self.init_retroactive_state() });
    const liveness = self.liveness.get_block(inst);

    // TODO emit debug info lexical block
    try self.gen_body(body);

    var block_data = self.blocks.fetch_remove(inst).?;
    defer block_data.value.deinit(self.gpa);
    if (block_data.value.relocs.items.len > 0) {
        try self.restore_state(block_data.value.state, liveness.deaths, .{
            .emit_instructions = false,
            .update_tracking = true,
            .resurrect = true,
            .close_scope = true,
        });
        for (block_data.value.relocs.items) |reloc| self.perform_reloc(reloc);
    }

    if (std.debug.runtime_safety) assert(self.inst_tracking.get_index(inst).? == inst_tracking_i);
    const tracking = &self.inst_tracking.values()[inst_tracking_i];
    if (self.liveness.is_unused(inst)) try tracking.die(self, inst);
    self.get_value_if_free(tracking.short, inst);
    self.finish_air_bookkeeping();
}

fn air_switch(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const condition = pl_op.operand;
    _ = condition;
    return self.fail("TODO air_switch for {}", .{self.target.cpu.arch});
    // return self.finish_air(inst, .dead, .{ condition, .none, .none });
}

fn perform_reloc(self: *Self, inst: Mir.Inst.Index) void {
    const tag = self.mir_instructions.items(.tag)[inst];
    const ops = self.mir_instructions.items(.ops)[inst];
    const target: Mir.Inst.Index = @int_cast(self.mir_instructions.len);

    switch (tag) {
        .bne,
        .beq,
        => self.mir_instructions.items(.data)[inst].b_type.inst = target,
        .jal => self.mir_instructions.items(.data)[inst].j_type.inst = target,
        .pseudo => switch (ops) {
            .pseudo_j => self.mir_instructions.items(.data)[inst].inst = target,
            else => std.debug.panic("TODO: perform_reloc {s}", .{@tag_name(ops)}),
        },
        else => std.debug.panic("TODO: perform_reloc {s}", .{@tag_name(tag)}),
    }
}

fn air_br(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const br = self.air.instructions.items(.data)[@int_from_enum(inst)].br;

    const block_ty = self.type_of_index(br.block_inst);
    const block_unused =
        !block_ty.has_runtime_bits_ignore_comptime(mod) or self.liveness.is_unused(br.block_inst);
    const block_tracking = self.inst_tracking.get_ptr(br.block_inst).?;
    const block_data = self.blocks.get_ptr(br.block_inst).?;
    const first_br = block_data.relocs.items.len == 0;
    const block_result = result: {
        if (block_unused) break :result .none;

        if (!first_br) try self.get_value(block_tracking.short, null);
        const src_mcv = try self.resolve_inst(br.operand);

        if (self.reuse_operand_advanced(inst, br.operand, 0, src_mcv, br.block_inst)) {
            if (first_br) break :result src_mcv;

            try self.get_value(block_tracking.short, br.block_inst);
            // .long = .none to avoid merging operand and block result stack frames.
            const current_tracking: InstTracking = .{ .long = .none, .short = src_mcv };
            try current_tracking.materialize_unsafe(self, br.block_inst, block_tracking.*);
            for (current_tracking.get_regs()) |src_reg| self.register_manager.free_reg(src_reg);
            break :result block_tracking.short;
        }

        const dst_mcv = if (first_br) try self.alloc_reg_or_mem(br.block_inst, true) else dst: {
            try self.get_value(block_tracking.short, br.block_inst);
            break :dst block_tracking.short;
        };
        try self.gen_copy(block_ty, dst_mcv, try self.resolve_inst(br.operand));
        break :result dst_mcv;
    };

    // Process operand death so that it is properly accounted for in the State below.
    if (self.liveness.operand_dies(inst, 0)) {
        if (br.operand.to_index()) |op_inst| try self.process_death(op_inst);
    }

    if (first_br) {
        block_tracking.* = InstTracking.init(block_result);
        try self.save_retroactive_state(&block_data.state);
    } else try self.restore_state(block_data.state, &.{}, .{
        .emit_instructions = true,
        .update_tracking = false,
        .resurrect = false,
        .close_scope = false,
    });

    // Emit a jump with a relocation. It will be patched up after the block ends.
    // Leave the jump offset undefined
    const jmp_reloc = try self.jump(undefined);
    try block_data.relocs.append(self.gpa, jmp_reloc);

    // Stop tracking block result without forgetting tracking info
    try self.free_value(block_tracking.short);

    self.finish_air_bookkeeping();
}

fn air_bool_op(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const air_tags = self.air.instructions.items(.tag);
    _ = air_tags;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement boolean operations for {}", .{self.target.cpu.arch});
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_asm(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Asm, ty_pl.payload);
    const is_volatile = @as(u1, @truncate(extra.data.flags >> 31)) != 0;
    const clobbers_len: u31 = @truncate(extra.data.flags);
    var extra_i: usize = extra.end;
    const outputs: []const Air.Inst.Ref =
        @ptr_cast(self.air.extra[extra_i..][0..extra.data.outputs_len]);
    extra_i += outputs.len;
    const inputs: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra_i..][0..extra.data.inputs_len]);
    extra_i += inputs.len;

    log.debug("air_asm input: {any}", .{inputs});

    const dead = !is_volatile and self.liveness.is_unused(inst);
    const result: MCValue = if (dead) .unreach else result: {
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

                if (std.mem.eql(u8, clobber, "") or std.mem.eql(u8, clobber, "memory")) {
                    // nothing really to do
                } else {
                    try self.register_manager.get_reg(parse_reg_name(clobber) orelse
                        return self.fail("invalid clobber: '{s}'", .{clobber}), null);
                }
            }
        }

        const asm_source = std.mem.slice_as_bytes(self.air.extra[extra_i..])[0..extra.data.source_len];

        if (std.meta.string_to_enum(Mir.Inst.Tag, asm_source)) |tag| {
            _ = try self.add_inst(.{
                .tag = tag,
                .ops = .none,
                .data = undefined,
            });
        } else {
            return self.fail("TODO: asm_source {s}", .{asm_source});
        }

        if (output_constraint) |output| {
            if (output.len < 4 or output[0] != '=' or output[1] != '{' or output[output.len - 1] != '}') {
                return self.fail("unrecognized asm output constraint: '{s}'", .{output});
            }
            const reg_name = output[2 .. output.len - 1];
            const reg = parse_reg_name(reg_name) orelse
                return self.fail("unrecognized register: '{s}'", .{reg_name});
            break :result .{ .register = reg };
        } else {
            break :result .{ .none = {} };
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
    var bt = self.liveness.iterate_big_tomb(inst);
    for (outputs) |output| if (output != .none) try self.feed(&bt, output);
    for (inputs) |input| try self.feed(&bt, input);
    return self.finish_air_result(inst, result);
}

/// Sets the value without any modifications to register allocation metadata or stack allocation metadata.
fn gen_copy(self: *Self, ty: Type, dst_mcv: MCValue, src_mcv: MCValue) !void {
    const zcu = self.bin_file.comp.module.?;

    // There isn't anything to store
    if (dst_mcv == .none) return;

    if (!dst_mcv.is_mutable()) {
        // panic so we can see the trace
        return self.fail("tried to gen_copy immutable: {s}", .{@tag_name(dst_mcv)});
    }

    switch (dst_mcv) {
        .register => |reg| return self.gen_set_reg(ty, reg, src_mcv),
        .register_offset => |dst_reg_off| try self.gen_set_reg(ty, dst_reg_off.reg, switch (src_mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            => unreachable,
            .immediate,
            .register,
            .register_offset,
            => src_mcv.offset(-dst_reg_off.off),
            else => .{ .register_offset = .{
                .reg = try self.copy_to_tmp_register(ty, src_mcv),
                .off = -dst_reg_off.off,
            } },
        }),
        .indirect => |ro| {
            const src_reg = try self.copy_to_tmp_register(ty, src_mcv);

            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_store_rm,
                .data = .{ .rm = .{
                    .r = src_reg,
                    .m = .{
                        .base = .{ .reg = ro.reg },
                        .mod = .{ .rm = .{ .disp = ro.off, .size = self.mem_size(ty) } },
                    },
                } },
            });
        },
        .load_frame => |frame| return self.gen_set_stack(ty, frame, src_mcv),
        .memory => return self.fail("TODO: gen_copy memory", .{}),
        .register_pair => |dst_regs| {
            const src_info: ?struct { addr_reg: Register, addr_lock: RegisterLock } = switch (src_mcv) {
                .register_pair, .memory, .indirect, .load_frame => null,
                .load_symbol => src: {
                    const src_addr_reg, const src_addr_lock = try self.alloc_reg();
                    errdefer self.register_manager.unlock_reg(src_addr_lock);

                    try self.gen_set_reg(Type.usize, src_addr_reg, src_mcv.address());
                    break :src .{ .addr_reg = src_addr_reg, .addr_lock = src_addr_lock };
                },
                .air_ref => |src_ref| return self.gen_copy(
                    ty,
                    dst_mcv,
                    try self.resolve_inst(src_ref),
                ),
                else => unreachable,
            };
            defer if (src_info) |info| self.register_manager.unlock_reg(info.addr_lock);

            var part_disp: i32 = 0;
            for (dst_regs, try self.split_type(ty), 0..) |dst_reg, dst_ty, part_i| {
                try self.gen_set_reg(dst_ty, dst_reg, switch (src_mcv) {
                    .register_pair => |src_regs| .{ .register = src_regs[part_i] },
                    .memory, .indirect, .load_frame => src_mcv.address().offset(part_disp).deref(),
                    .load_symbol => .{ .indirect = .{
                        .reg = src_info.?.addr_reg,
                        .off = part_disp,
                    } },
                    else => unreachable,
                });
                part_disp += @int_cast(dst_ty.abi_size(zcu));
            }
        },
        else => return self.fail("TODO: gen_copy to {s} from {s}", .{ @tag_name(dst_mcv), @tag_name(src_mcv) }),
    }
}

fn gen_set_stack(
    self: *Self,
    ty: Type,
    frame: FrameAddr,
    src_mcv: MCValue,
) InnerError!void {
    const zcu = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(zcu));

    switch (src_mcv) {
        .none => return,
        .dead => unreachable,
        .undef => {
            if (!self.want_safety()) return;
            try self.gen_set_stack(ty, frame, .{ .immediate = 0xaaaaaaaaaaaaaaaa });
        },
        .immediate,
        .lea_frame,
        => {
            // TODO: remove this lock in favor of a copy_to_tmp_register when we load 64 bit immediates with
            // a register allocation.
            const reg, const reg_lock = try self.alloc_reg();
            defer self.register_manager.unlock_reg(reg_lock);

            try self.gen_set_reg(ty, reg, src_mcv);

            return self.gen_set_stack(ty, frame, .{ .register = reg });
        },
        .register => |reg| {
            switch (abi_size) {
                1, 2, 4, 8 => {
                    _ = try self.add_inst(.{
                        .tag = .pseudo,
                        .ops = .pseudo_store_rm,
                        .data = .{ .rm = .{
                            .r = reg,
                            .m = .{
                                .base = .{ .frame = frame.index },
                                .mod = .{
                                    .rm = .{
                                        .size = self.mem_size(ty),
                                        .disp = frame.off,
                                    },
                                },
                            },
                        } },
                    });
                },
                else => unreachable, // register can hold a max of 8 bytes
            }
        },
        .register_pair => |pair| {
            var part_disp: i32 = frame.off;
            for (try self.split_type(ty), pair) |src_ty, src_reg| {
                try self.gen_set_stack(
                    src_ty,
                    .{ .index = frame.index, .off = part_disp },
                    .{ .register = src_reg },
                );
                part_disp += @int_cast(src_ty.abi_size(zcu));
            }
        },
        .load_frame,
        .indirect,
        .load_symbol,
        => {
            if (abi_size <= 8) {
                const reg = try self.copy_to_tmp_register(ty, src_mcv);
                return self.gen_set_stack(ty, frame, .{ .register = reg });
            }

            try self.gen_inline_memcpy(
                .{ .lea_frame = frame },
                src_mcv.address(),
                .{ .immediate = abi_size },
            );
        },
        .air_ref => |ref| try self.gen_set_stack(ty, frame, try self.resolve_inst(ref)),
        else => return self.fail("TODO: gen_set_stack {s}", .{@tag_name(src_mcv)}),
    }
}

fn gen_inline_memcpy(
    self: *Self,
    dst_ptr: MCValue,
    src_ptr: MCValue,
    len: MCValue,
) !void {
    const regs = try self.register_manager.alloc_regs(4, .{null} ** 4, tp);
    const locks = self.register_manager.lock_regs_assume_unused(4, regs);
    defer for (locks) |lock| self.register_manager.unlock_reg(lock);

    const count = regs[0];
    const tmp = regs[1];
    const src = regs[2];
    const dst = regs[3];

    try self.gen_set_reg(Type.usize, count, len);
    try self.gen_set_reg(Type.usize, src, src_ptr);
    try self.gen_set_reg(Type.usize, dst, dst_ptr);

    // lb tmp, 0(src)
    const first_inst = try self.add_inst(.{
        .tag = .lb,
        .ops = .rri,
        .data = .{
            .i_type = .{
                .rd = tmp,
                .rs1 = src,
                .imm12 = Immediate.s(0),
            },
        },
    });

    // sb tmp, 0(dst)
    _ = try self.add_inst(.{
        .tag = .sb,
        .ops = .rri,
        .data = .{
            .i_type = .{
                .rd = dst,
                .rs1 = tmp,
                .imm12 = Immediate.s(0),
            },
        },
    });

    // dec count by 1
    _ = try self.add_inst(.{
        .tag = .addi,
        .ops = .rri,
        .data = .{
            .i_type = .{
                .rd = count,
                .rs1 = count,
                .imm12 = Immediate.s(-1),
            },
        },
    });

    // branch if count is 0
    _ = try self.add_inst(.{
        .tag = .beq,
        .ops = .rr_inst,
        .data = .{
            .b_type = .{
                .inst = @int_cast(self.mir_instructions.len + 4), // points after the last inst
                .rs1 = count,
                .rs2 = .zero,
            },
        },
    });

    // increment the pointers
    _ = try self.add_inst(.{
        .tag = .addi,
        .ops = .rri,
        .data = .{
            .i_type = .{
                .rd = src,
                .rs1 = src,
                .imm12 = Immediate.s(1),
            },
        },
    });

    _ = try self.add_inst(.{
        .tag = .addi,
        .ops = .rri,
        .data = .{
            .i_type = .{
                .rd = dst,
                .rs1 = dst,
                .imm12 = Immediate.s(1),
            },
        },
    });

    // jump back to start of loop
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_j,
        .data = .{
            .inst = first_inst,
        },
    });
}

/// Sets the value of `src_mcv` into `reg`. Assumes you have a lock on it.
fn gen_set_reg(self: *Self, ty: Type, reg: Register, src_mcv: MCValue) InnerError!void {
    const zcu = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(zcu));

    if (abi_size > 8) return self.fail("tried to set reg with size {}", .{abi_size});

    switch (src_mcv) {
        .dead => unreachable,
        .unreach, .none => return, // Nothing to do.
        .undef => {
            if (!self.want_safety())
                return; // The already existing value will do just fine.
            // Write the debug undefined value.
            return self.gen_set_reg(ty, reg, .{ .immediate = 0xaaaaaaaaaaaaaaaa });
        },
        .immediate => |unsigned_x| {
            const x: i64 = @bit_cast(unsigned_x);
            if (math.min_int(i12) <= x and x <= math.max_int(i12)) {
                _ = try self.add_inst(.{
                    .tag = .addi,
                    .ops = .rri,
                    .data = .{ .i_type = .{
                        .rd = reg,
                        .rs1 = .zero,
                        .imm12 = Immediate.s(@int_cast(x)),
                    } },
                });
            } else if (math.min_int(i32) <= x and x <= math.max_int(i32)) {
                const lo12: i12 = @truncate(x);
                const carry: i32 = if (lo12 < 0) 1 else 0;
                const hi20: i20 = @truncate((x >> 12) +% carry);

                _ = try self.add_inst(.{
                    .tag = .lui,
                    .ops = .ri,
                    .data = .{ .u_type = .{
                        .rd = reg,
                        .imm20 = Immediate.s(hi20),
                    } },
                });
                _ = try self.add_inst(.{
                    .tag = .addi,
                    .ops = .rri,
                    .data = .{ .i_type = .{
                        .rd = reg,
                        .rs1 = reg,
                        .imm12 = Immediate.s(lo12),
                    } },
                });
            } else {
                // TODO: use a more advanced myriad seq to do this without a reg.
                // see: https://github.com/llvm/llvm-project/blob/081a66ffacfe85a37ff775addafcf3371e967328/llvm/lib/Target/RISCV/MCTargetDesc/RISCVMatInt.cpp#L224

                const temp, const temp_lock = try self.alloc_reg();
                defer self.register_manager.unlock_reg(temp_lock);

                const lo32: i32 = @truncate(x);
                const carry: i32 = if (lo32 < 0) 1 else 0;
                const hi32: i32 = @truncate((x >> 32) +% carry);

                try self.gen_set_reg(Type.i32, temp, .{ .immediate = @bit_cast(@as(i64, lo32)) });
                try self.gen_set_reg(Type.i32, reg, .{ .immediate = @bit_cast(@as(i64, hi32)) });

                _ = try self.add_inst(.{
                    .tag = .slli,
                    .ops = .rri,
                    .data = .{ .i_type = .{
                        .rd = reg,
                        .rs1 = reg,
                        .imm12 = Immediate.s(32),
                    } },
                });

                _ = try self.add_inst(.{
                    .tag = .add,
                    .ops = .rrr,
                    .data = .{ .r_type = .{
                        .rd = reg,
                        .rs1 = reg,
                        .rs2 = temp,
                    } },
                });
            }
        },
        .register => |src_reg| {
            // If the registers are the same, nothing to do.
            if (src_reg.id() == reg.id())
                return;

            // mov reg, src_reg
            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_mv,
                .data = .{ .rr = .{
                    .rd = reg,
                    .rs = src_reg,
                } },
            });
        },
        .register_pair => |pair| try self.gen_set_reg(ty, reg, .{ .register = pair[0] }),
        .memory => |addr| {
            try self.gen_set_reg(ty, reg, .{ .immediate = addr });

            _ = try self.add_inst(.{
                .tag = .ld,
                .ops = .rri,
                .data = .{ .i_type = .{
                    .rd = reg,
                    .rs1 = reg,
                    .imm12 = Immediate.s(0),
                } },
            });
        },
        .load_frame => |frame| {
            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_load_rm,
                .data = .{ .rm = .{
                    .r = reg,
                    .m = .{
                        .base = .{ .frame = frame.index },
                        .mod = .{
                            .rm = .{
                                .size = self.mem_size(ty),
                                .disp = frame.off,
                            },
                        },
                    },
                } },
            });
        },
        .lea_frame => |frame| {
            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_lea_rm,
                .data = .{ .rm = .{
                    .r = reg,
                    .m = .{
                        .base = .{ .frame = frame.index },
                        .mod = .{
                            .rm = .{
                                .size = self.mem_size(ty),
                                .disp = frame.off,
                            },
                        },
                    },
                } },
            });
        },
        .load_symbol => {
            try self.gen_set_reg(ty, reg, src_mcv.address());
            try self.gen_set_reg(ty, reg, .{ .indirect = .{ .reg = reg } });
        },
        .indirect => |reg_off| {
            const load_tag: Mir.Inst.Tag = switch (abi_size) {
                1 => .lb,
                2 => .lh,
                4 => .lw,
                8 => .ld,
                else => return self.fail("TODO: gen_set_reg for size {d}", .{abi_size}),
            };

            _ = try self.add_inst(.{
                .tag = load_tag,
                .ops = .rri,
                .data = .{ .i_type = .{
                    .rd = reg,
                    .rs1 = reg_off.reg,
                    .imm12 = Immediate.s(reg_off.off),
                } },
            });
        },
        .lea_symbol => |sym_off| {
            assert(sym_off.off == 0);

            const atom_index = try self.symbol_index();

            _ = try self.add_inst(.{
                .tag = .pseudo,
                .ops = .pseudo_load_symbol,
                .data = .{ .payload = try self.add_extra(Mir.LoadSymbolPayload{
                    .register = reg.id(),
                    .atom_index = atom_index,
                    .sym_index = sym_off.sym,
                }) },
            });
        },
        .air_ref => |ref| try self.gen_set_reg(ty, reg, try self.resolve_inst(ref)),
        else => return self.fail("TODO: gen_set_reg {s}", .{@tag_name(src_mcv)}),
    }
}

fn air_int_from_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result = result: {
        const src_mcv = try self.resolve_inst(un_op);
        if (self.reuse_operand(inst, un_op, 0, src_mcv)) break :result src_mcv;

        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
        const dst_ty = self.type_of_index(inst);
        try self.gen_copy(dst_ty, dst_mcv, src_mcv);
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_bit_cast(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;

    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = if (self.liveness.is_unused(inst)) .unreach else result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);

        const dst_ty = self.type_of_index(inst);
        const src_ty = self.type_of(ty_op.operand);

        const src_lock = if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
        defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_mcv = if (dst_ty.abi_size(zcu) <= src_ty.abi_size(zcu) and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) src_mcv else dst: {
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(switch (math.order(dst_ty.abi_size(zcu), src_ty.abi_size(zcu))) {
                .lt => dst_ty,
                .eq => if (!dst_mcv.is_memory() or src_mcv.is_memory()) dst_ty else src_ty,
                .gt => src_ty,
            }, dst_mcv, src_mcv);
            break :dst dst_mcv;
        };

        if (dst_ty.is_abi_int(zcu) and src_ty.is_abi_int(zcu) and
            dst_ty.int_info(zcu).signedness == src_ty.int_info(zcu).signedness) break :result dst_mcv;

        const abi_size = dst_ty.abi_size(zcu);
        const bit_size = dst_ty.bit_size(zcu);
        if (abi_size * 8 <= bit_size) break :result dst_mcv;

        return self.fail("TODO: air_bit_cast {} to {}", .{ src_ty.fmt(zcu), dst_ty.fmt(zcu) });
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_array_to_slice(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_array_to_slice for {}", .{
        self.target.cpu.arch,
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_float_from_int(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_float_from_int for {}", .{
        self.target.cpu.arch,
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_float(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_int_from_float for {}", .{
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
    // return self.finish_air(inst, result, .{ extra.ptr, extra.expected_value, extra.new_value });
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
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else {
        _ = operand;
        return self.fail("TODO implement air_tag_name for riscv64", .{});
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_error_name(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const err_ty = self.type_of(un_op);
    const err_mcv = try self.resolve_inst(un_op);

    const err_reg = try self.copy_to_tmp_register(err_ty, err_mcv);
    const err_lock = self.register_manager.lock_reg_assume_unused(err_reg);
    defer self.register_manager.unlock_reg(err_lock);

    const addr_reg, const addr_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(addr_lock);

    const lazy_sym = link.File.LazySymbol.init_decl(.const_data, null, zcu);
    if (self.bin_file.cast(link.File.Elf)) |elf_file| {
        const sym_index = elf_file.zig_object_ptr().?.get_or_create_metadata_for_lazy_symbol(elf_file, lazy_sym) catch |err|
            return self.fail("{s} creating lazy symbol", .{@errorName(err)});
        const sym = elf_file.symbol(sym_index);
        try self.gen_set_reg(Type.usize, addr_reg, .{ .load_symbol = .{ .sym = sym.esym_index } });
    } else {
        return self.fail("TODO: riscv non-elf", .{});
    }

    const start_reg, const start_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(start_lock);

    const end_reg, const end_lock = try self.alloc_reg();
    defer self.register_manager.unlock_reg(end_lock);

    _ = start_reg;
    _ = end_reg;

    return self.fail("TODO: air_error_name", .{});
}

fn air_splat(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_splat for riscv64", .{});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_select(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_select for riscv64", .{});
    return self.finish_air(inst, result, .{ pl_op.operand, extra.lhs, extra.rhs });
}

fn air_shuffle(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_shuffle for riscv64", .{});
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_reduce(self: *Self, inst: Air.Inst.Index) !void {
    const reduce = self.air.instructions.items(.data)[@int_from_enum(inst)].reduce;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else return self.fail("TODO implement air_reduce for riscv64", .{});
    return self.finish_air(inst, result, .{ reduce.operand, .none, .none });
}

fn air_aggregate_init(self: *Self, inst: Air.Inst.Index) !void {
    const zcu = self.bin_file.comp.module.?;
    const result_ty = self.type_of_index(inst);
    const len: usize = @int_cast(result_ty.array_len(zcu));
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const elements: []const Air.Inst.Ref = @ptr_cast(self.air.extra[ty_pl.payload..][0..len]);
    const result: MCValue = result: {
        switch (result_ty.zig_type_tag(zcu)) {
            .Struct => {
                const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(result_ty, zcu));

                if (result_ty.container_layout(zcu) == .@"packed") {} else for (elements, 0..) |elem, elem_i| {
                    if ((try result_ty.struct_field_value_comptime(zcu, elem_i)) != null) continue;

                    const elem_ty = result_ty.struct_field_type(elem_i, zcu);
                    const elem_off: i32 = @int_cast(result_ty.struct_field_offset(elem_i, zcu));
                    const elem_mcv = try self.resolve_inst(elem);

                    const elem_frame: FrameAddr = .{
                        .index = frame_index,
                        .off = elem_off,
                    };
                    try self.gen_set_stack(
                        elem_ty,
                        elem_frame,
                        elem_mcv,
                    );
                }
            },
            else => return self.fail("TODO: air_aggregate_init {}", .{result_ty.fmt(zcu)}),
        }
        break :result .{ .register = .zero };
    };

    if (elements.len <= Liveness.bpi - 1) {
        var buf = [1]Air.Inst.Ref{.none} ** (Liveness.bpi - 1);
        @memcpy(buf[0..elements.len], elements);
        return self.finish_air(inst, result, buf);
    }
    var bt = self.liveness.iterate_big_tomb(inst);
    for (elements) |elem| try self.feed(&bt, elem);
    return self.finish_air_result(inst, result);
}

fn air_union_init(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.UnionInit, ty_pl.payload).data;
    _ = extra;
    return self.fail("TODO implement air_union_init for riscv64", .{});
    // return self.finish_air(inst, result, .{ extra.ptr, extra.expected_value, extra.new_value });
}

fn air_prefetch(self: *Self, inst: Air.Inst.Index) !void {
    const prefetch = self.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;
    // TODO: RISC-V does have prefetch instruction variants.
    // see here: https://raw.githubusercontent.com/riscv/riscv-CMOs/master/specifications/cmobase-v1.0.1.pdf
    return self.finish_air(inst, .unreach, .{ prefetch.ptr, .none, .none });
}

fn air_mul_add(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else {
        return self.fail("TODO implement air_mul_add for riscv64", .{});
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, pl_op.operand });
}

fn resolve_inst(self: *Self, ref: Air.Inst.Ref) InnerError!MCValue {
    const zcu = self.bin_file.comp.module.?;

    // If the type has no codegen bits, no need to store it.
    const inst_ty = self.type_of(ref);
    if (!inst_ty.has_runtime_bits(zcu))
        return .none;

    const mcv = if (ref.to_index()) |inst| mcv: {
        break :mcv self.inst_tracking.get_ptr(inst).?.short;
    } else mcv: {
        const ip_index = ref.to_interned().?;
        const gop = try self.const_tracking.get_or_put(self.gpa, ip_index);
        if (!gop.found_existing) gop.value_ptr.* = InstTracking.init(
            try self.gen_typed_value(Value.from_interned(ip_index)),
        );
        break :mcv gop.value_ptr.short;
    };

    return mcv;
}

fn get_resolved_inst_value(self: *Self, inst: Air.Inst.Index) *InstTracking {
    const tracking = self.inst_tracking.get_ptr(inst).?;
    return switch (tracking.short) {
        .none, .unreach, .dead => unreachable,
        else => tracking,
    };
}

fn gen_typed_value(self: *Self, val: Value) InnerError!MCValue {
    const zcu = self.bin_file.comp.module.?;
    const result = try codegen.gen_typed_value(
        self.bin_file,
        self.src_loc,
        val,
        zcu.func_owner_decl_index(self.func_index),
    );
    const mcv: MCValue = switch (result) {
        .mcv => |mcv| switch (mcv) {
            .none => .none,
            .undef => .undef,
            .load_symbol => |sym_index| .{ .load_symbol = .{ .sym = sym_index } },
            .immediate => |imm| .{ .immediate = imm },
            .memory => |addr| .{ .memory = addr },
            .load_got, .load_direct, .load_tlv => {
                return self.fail("TODO: gen_typed_value {s}", .{@tag_name(mcv)});
            },
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
    return_value: InstTracking,
    stack_byte_count: u31,
    stack_align: Alignment,

    fn deinit(self: *CallMCValues, func: *Self) void {
        func.gpa.free(self.args);
        self.* = undefined;
    }
};

/// Caller must call `CallMCValues.deinit`.
fn resolve_calling_convention_values(
    self: *Self,
    fn_info: InternPool.Key.FuncType,
) !CallMCValues {
    const zcu = self.bin_file.comp.module.?;
    const ip = &zcu.intern_pool;

    const param_types = try self.gpa.alloc(Type, fn_info.param_types.len);
    defer self.gpa.free(param_types);

    for (param_types[0..fn_info.param_types.len], fn_info.param_types.get(ip)) |*dest, src| {
        dest.* = Type.from_interned(src);
    }

    const cc = fn_info.cc;
    var result: CallMCValues = .{
        .args = try self.gpa.alloc(MCValue, param_types.len),
        // These undefined values must be populated before returning from this function.
        .return_value = undefined,
        .stack_byte_count = 0,
        .stack_align = undefined,
    };
    errdefer self.gpa.free(result.args);

    const ret_ty = Type.from_interned(fn_info.return_type);

    switch (cc) {
        .Naked => {
            assert(result.args.len == 0);
            result.return_value = InstTracking.init(.unreach);
            result.stack_align = .@"8";
        },
        .C, .Unspecified => {
            if (result.args.len > 8) {
                return self.fail("RISC-V calling convention does not support more than 8 arguments", .{});
            }

            var ret_int_reg_i: u32 = 0;
            var param_int_reg_i: u32 = 0;

            result.stack_align = .@"16";

            // Return values
            if (ret_ty.zig_type_tag(zcu) == .NoReturn) {
                result.return_value = InstTracking.init(.unreach);
            } else if (!ret_ty.has_runtime_bits_ignore_comptime(zcu)) {
                result.return_value = InstTracking.init(.none);
            } else {
                var ret_tracking: [2]InstTracking = undefined;
                var ret_tracking_i: usize = 0;

                const classes = mem.slice_to(&abi.classify_system(ret_ty, zcu), .none);

                for (classes) |class| switch (class) {
                    .integer => {
                        const ret_int_reg = abi.function_ret_regs[ret_int_reg_i];
                        ret_int_reg_i += 1;

                        ret_tracking[ret_tracking_i] = InstTracking.init(.{ .register = ret_int_reg });
                        ret_tracking_i += 1;
                    },
                    .memory => {
                        const ret_int_reg = abi.function_ret_regs[ret_int_reg_i];
                        ret_int_reg_i += 1;
                        const ret_indirect_reg = abi.function_arg_regs[param_int_reg_i];
                        param_int_reg_i += 1;

                        ret_tracking[ret_tracking_i] = .{
                            .short = .{ .indirect = .{ .reg = ret_int_reg } },
                            .long = .{ .indirect = .{ .reg = ret_indirect_reg } },
                        };
                        ret_tracking_i += 1;
                    },
                    else => return self.fail("TODO: C calling convention return class {}", .{class}),
                };

                result.return_value = switch (ret_tracking_i) {
                    else => return self.fail("ty {} took {} tracking return indices", .{ ret_ty.fmt(zcu), ret_tracking_i }),
                    1 => ret_tracking[0],
                    2 => InstTracking.init(.{ .register_pair = .{
                        ret_tracking[0].short.register, ret_tracking[1].short.register,
                    } }),
                };
            }

            for (param_types, result.args) |ty, *arg| {
                assert(ty.has_runtime_bits_ignore_comptime(zcu));

                var arg_mcv: [2]MCValue = undefined;
                var arg_mcv_i: usize = 0;

                const classes = mem.slice_to(&abi.classify_system(ty, zcu), .none);

                for (classes) |class| switch (class) {
                    .integer => {
                        const param_int_regs = abi.function_arg_regs;
                        if (param_int_reg_i >= param_int_regs.len) break;

                        const param_int_reg = param_int_regs[param_int_reg_i];
                        param_int_reg_i += 1;

                        arg_mcv[arg_mcv_i] = .{ .register = param_int_reg };
                        arg_mcv_i += 1;
                    },
                    .memory => {
                        const param_int_regs = abi.function_arg_regs;
                        const param_int_reg = param_int_regs[param_int_reg_i];

                        arg_mcv[arg_mcv_i] = .{ .indirect = .{ .reg = param_int_reg } };
                        arg_mcv_i += 1;
                    },
                    else => return self.fail("TODO: C calling convention arg class {}", .{class}),
                } else {
                    arg.* = switch (arg_mcv_i) {
                        else => return self.fail("ty {} took {} tracking arg indices", .{ ty.fmt(zcu), arg_mcv_i }),
                        1 => arg_mcv[0],
                        2 => .{ .register_pair = .{ arg_mcv[0].register, arg_mcv[1].register } },
                    };
                    continue;
                }

                return self.fail("TODO: pass args by stack", .{});
            }
        },
        else => return self.fail("TODO implement function parameters for {} on riscv64", .{cc}),
    }

    result.stack_byte_count = @int_cast(result.stack_align.forward(result.stack_byte_count));
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

fn type_of(self: *Self, inst: Air.Inst.Ref) Type {
    const zcu = self.bin_file.comp.module.?;
    return self.air.type_of(inst, &zcu.intern_pool);
}

fn type_of_index(self: *Self, inst: Air.Inst.Index) Type {
    const zcu = self.bin_file.comp.module.?;
    return self.air.type_of_index(inst, &zcu.intern_pool);
}

fn has_feature(self: *Self, feature: Target.riscv.Feature) bool {
    return Target.riscv.feature_set_has(self.target.cpu.features, feature);
}

pub fn err_union_payload_offset(payload_ty: Type, zcu: *Module) u64 {
    if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) return 0;
    const payload_align = payload_ty.abi_alignment(zcu);
    const error_align = Type.anyerror.abi_alignment(zcu);
    if (payload_align.compare(.gte, error_align) or !payload_ty.has_runtime_bits_ignore_comptime(zcu)) {
        return 0;
    } else {
        return payload_align.forward(Type.anyerror.abi_size(zcu));
    }
}

pub fn err_union_error_offset(payload_ty: Type, zcu: *Module) u64 {
    if (!payload_ty.has_runtime_bits_ignore_comptime(zcu)) return 0;
    const payload_align = payload_ty.abi_alignment(zcu);
    const error_align = Type.anyerror.abi_alignment(zcu);
    if (payload_align.compare(.gte, error_align) and payload_ty.has_runtime_bits_ignore_comptime(zcu)) {
        return error_align.forward(payload_ty.abi_size(zcu));
    } else {
        return 0;
    }
}
