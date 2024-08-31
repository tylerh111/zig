const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const codegen = @import("../../codegen.zig");
const leb128 = std.leb;
const link = @import("../../link.zig");
const log = std.log.scoped(.codegen);
const tracking_log = std.log.scoped(.tracking);
const verbose_tracking_log = std.log.scoped(.verbose_tracking);
const wip_mir_log = std.log.scoped(.wip_mir);
const math = std.math;
const mem = std.mem;
const trace = @import("../../tracy.zig").trace;

const Air = @import("../../Air.zig");
const Allocator = mem.Allocator;
const CodeGenError = codegen.CodeGenError;
const Compilation = @import("../../Compilation.zig");
const DebugInfoOutput = codegen.DebugInfoOutput;
const DW = std.dwarf;
const ErrorMsg = Module.ErrorMsg;
const Result = codegen.Result;
const Emit = @import("Emit.zig");
const Liveness = @import("../../Liveness.zig");
const Lower = @import("Lower.zig");
const Mir = @import("Mir.zig");
const Package = @import("../../Package.zig");
const Module = @import("../../Module.zig");
const Zcu = Module;
const InternPool = @import("../../InternPool.zig");
const Alignment = InternPool.Alignment;
const Target = std.Target;
const Type = @import("../../type.zig").Type;
const Value = @import("../../Value.zig");
const Instruction = @import("encoder.zig").Instruction;

const abi = @import("abi.zig");
const bits = @import("bits.zig");
const err_union_error_offset = codegen.err_union_error_offset;
const err_union_payload_offset = codegen.err_union_payload_offset;

const Condition = bits.Condition;
const Immediate = bits.Immediate;
const Memory = bits.Memory;
const Register = bits.Register;
const RegisterManager = abi.RegisterManager;
const RegisterLock = RegisterManager.RegisterLock;
const FrameIndex = bits.FrameIndex;

const InnerError = CodeGenError || error{OutOfRegisters};

gpa: Allocator,
air: Air,
liveness: Liveness,
bin_file: *link.File,
debug_output: DebugInfoOutput,
target: *const std.Target,
owner: Owner,
inline_func: InternPool.Index,
mod: *Package.Module,
err_msg: ?*ErrorMsg,
args: []MCValue,
va_info: union {
    sysv: struct {
        gp_count: u32,
        fp_count: u32,
        overflow_arg_area: FrameAddr,
        reg_save_area: FrameAddr,
    },
    win64: struct {},
},
ret_mcv: InstTracking,
fn_type: Type,
arg_index: u32,
src_loc: Module.SrcLoc,

eflags_inst: ?Air.Inst.Index = null,

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
exitlude_jump_relocs: std.ArrayListUnmanaged(Mir.Inst.Index) = .{},

const_tracking: ConstTrackingMap = .{},
inst_tracking: InstTrackingMap = .{},

// Key is the block instruction
blocks: std.AutoHashMapUnmanaged(Air.Inst.Index, BlockData) = .{},

register_manager: RegisterManager = .{},

/// Generation of the current scope, increments by 1 for every entered scope.
scope_generation: u32 = 0,

frame_allocs: std.MultiArrayList(FrameAlloc) = .{},
free_frame_indices: std.AutoArrayHashMapUnmanaged(FrameIndex, void) = .{},
frame_locs: std.MultiArrayList(Mir.FrameLoc) = .{},

/// Debug field, used to find bugs in the compiler.
air_bookkeeping: @TypeOf(air_bookkeeping_init) = air_bookkeeping_init,

const air_bookkeeping_init = if (std.debug.runtime_safety) @as(usize, 0) else {};

const FrameAddr = struct { index: FrameIndex, off: i32 = 0 };
const RegisterOffset = struct { reg: Register, off: i32 = 0 };
const SymbolOffset = struct { sym: u32, off: i32 = 0 };

const Owner = union(enum) {
    func_index: InternPool.Index,
    lazy_sym: link.File.LazySymbol,

    fn get_decl(owner: Owner, mod: *Module) InternPool.DeclIndex {
        return switch (owner) {
            .func_index => |func_index| mod.func_owner_decl_index(func_index),
            .lazy_sym => |lazy_sym| lazy_sym.ty.get_owner_decl(mod),
        };
    }

    fn get_symbol_index(owner: Owner, ctx: *Self) !u32 {
        switch (owner) {
            .func_index => |func_index| {
                const mod = ctx.bin_file.comp.module.?;
                const decl_index = mod.func_owner_decl_index(func_index);
                if (ctx.bin_file.cast(link.File.Elf)) |elf_file| {
                    return elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, decl_index);
                } else if (ctx.bin_file.cast(link.File.MachO)) |macho_file| {
                    return macho_file.get_zig_object().?.get_or_create_metadata_for_decl(macho_file, decl_index);
                } else if (ctx.bin_file.cast(link.File.Coff)) |coff_file| {
                    const atom = try coff_file.get_or_create_atom_for_decl(decl_index);
                    return coff_file.get_atom(atom).get_symbol_index().?;
                } else if (ctx.bin_file.cast(link.File.Plan9)) |p9_file| {
                    return p9_file.see_decl(decl_index);
                } else unreachable;
            },
            .lazy_sym => |lazy_sym| {
                if (ctx.bin_file.cast(link.File.Elf)) |elf_file| {
                    return elf_file.zig_object_ptr().?.get_or_create_metadata_for_lazy_symbol(elf_file, lazy_sym) catch |err|
                        ctx.fail("{s} creating lazy symbol", .{@errorName(err)});
                } else if (ctx.bin_file.cast(link.File.MachO)) |macho_file| {
                    return macho_file.get_zig_object().?.get_or_create_metadata_for_lazy_symbol(macho_file, lazy_sym) catch |err|
                        ctx.fail("{s} creating lazy symbol", .{@errorName(err)});
                } else if (ctx.bin_file.cast(link.File.Coff)) |coff_file| {
                    const atom = coff_file.get_or_create_atom_for_lazy_symbol(lazy_sym) catch |err|
                        return ctx.fail("{s} creating lazy symbol", .{@errorName(err)});
                    return coff_file.get_atom(atom).get_symbol_index().?;
                } else if (ctx.bin_file.cast(link.File.Plan9)) |p9_file| {
                    return p9_file.get_or_create_atom_for_lazy_symbol(lazy_sym) catch |err|
                        return ctx.fail("{s} creating lazy symbol", .{@errorName(err)});
                } else unreachable;
            },
        }
    }
};

pub const MCValue = union(enum) {
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
    /// The value resides in the EFLAGS register.
    eflags: Condition,
    /// The value is in a register.
    register: Register,
    /// The value is split across two registers.
    register_pair: [2]Register,
    /// The value is a constant offset from the value in a register.
    register_offset: RegisterOffset,
    /// The value is a tuple { wrapped, overflow } where wrapped value is stored in the GP register.
    register_overflow: struct { reg: Register, eflags: Condition },
    /// The value is in memory at a hard-coded address.
    /// If the type is a pointer, it means the pointer address is stored at this memory location.
    memory: u64,
    /// The value is in memory at an address not-yet-allocated by the linker.
    /// This traditionally corresponds to a relocation emitted in a relocatable object file.
    load_symbol: SymbolOffset,
    /// The address of the memory location not-yet-allocated by the linker.
    lea_symbol: SymbolOffset,
    /// The value is in memory at a constant offset from the address in a register.
    indirect: RegisterOffset,
    /// The value is in memory.
    /// Payload is a symbol index.
    load_direct: u32,
    /// The value is a pointer to a value in memory.
    /// Payload is a symbol index.
    lea_direct: u32,
    /// The value is in memory referenced indirectly via GOT.
    /// Payload is a symbol index.
    load_got: u32,
    /// The value is a pointer to a value referenced indirectly via GOT.
    /// Payload is a symbol index.
    lea_got: u32,
    /// The value is a threadlocal variable.
    /// Payload is a symbol index.
    load_tlv: u32,
    /// The value is a pointer to a threadlocal variable.
    /// Payload is a symbol index.
    lea_tlv: u32,
    /// The value stored at an offset from a frame index
    /// Payload is a frame address.
    load_frame: FrameAddr,
    /// The address of an offset from a frame index
    /// Payload is a frame address.
    lea_frame: FrameAddr,
    /// Supports integer_per_element abi
    elementwise_regs_then_frame: packed struct { regs: u3 = 0, frame_off: i29 = 0, frame_index: FrameIndex },
    /// This indicates that we have already allocated a frame index for this instruction,
    /// but it has not been spilled there yet in the current control flow.
    /// Payload is a frame index.
    reserved_frame: FrameIndex,
    air_ref: Air.Inst.Ref,

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

    fn is_register(mcv: MCValue) bool {
        return switch (mcv) {
            .register => true,
            .register_offset => |reg_off| return reg_off.off == 0,
            else => false,
        };
    }

    fn is_register_offset(mcv: MCValue) bool {
        return switch (mcv) {
            .register, .register_offset => true,
            else => false,
        };
    }

    fn get_reg(mcv: MCValue) ?Register {
        return switch (mcv) {
            .register => |reg| reg,
            .register_offset, .indirect => |ro| ro.reg,
            .register_overflow => |ro| ro.reg,
            else => null,
        };
    }

    fn get_regs(mcv: *const MCValue) []const Register {
        return switch (mcv.*) {
            .register => |*reg| @as(*const [1]Register, reg),
            .register_pair => |*regs| regs,
            .register_offset, .indirect => |*ro| @as(*const [1]Register, &ro.reg),
            .register_overflow => |*ro| @as(*const [1]Register, &ro.reg),
            else => &.{},
        };
    }

    fn get_condition(mcv: MCValue) ?Condition {
        return switch (mcv) {
            .eflags => |cc| cc,
            .register_overflow => |reg_ov| reg_ov.eflags,
            else => null,
        };
    }

    fn address(mcv: MCValue) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .immediate,
            .eflags,
            .register,
            .register_pair,
            .register_offset,
            .register_overflow,
            .lea_symbol,
            .lea_direct,
            .lea_got,
            .lea_tlv,
            .lea_frame,
            .elementwise_regs_then_frame,
            .reserved_frame,
            .air_ref,
            => unreachable, // not in memory
            .memory => |addr| .{ .immediate = addr },
            .indirect => |reg_off| switch (reg_off.off) {
                0 => .{ .register = reg_off.reg },
                else => .{ .register_offset = reg_off },
            },
            .load_direct => |sym_index| .{ .lea_direct = sym_index },
            .load_got => |sym_index| .{ .lea_got = sym_index },
            .load_tlv => |sym_index| .{ .lea_tlv = sym_index },
            .load_frame => |frame_addr| .{ .lea_frame = frame_addr },
            .load_symbol => |sym_off| .{ .lea_symbol = sym_off },
        };
    }

    fn deref(mcv: MCValue) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .eflags,
            .register_pair,
            .register_overflow,
            .memory,
            .indirect,
            .load_direct,
            .load_got,
            .load_tlv,
            .load_frame,
            .load_symbol,
            .elementwise_regs_then_frame,
            .reserved_frame,
            .air_ref,
            => unreachable, // not dereferenceable
            .immediate => |addr| .{ .memory = addr },
            .register => |reg| .{ .indirect = .{ .reg = reg } },
            .register_offset => |reg_off| .{ .indirect = reg_off },
            .lea_direct => |sym_index| .{ .load_direct = sym_index },
            .lea_got => |sym_index| .{ .load_got = sym_index },
            .lea_tlv => |sym_index| .{ .load_tlv = sym_index },
            .lea_frame => |frame_addr| .{ .load_frame = frame_addr },
            .lea_symbol => |sym_index| .{ .load_symbol = sym_index },
        };
    }

    fn offset(mcv: MCValue, off: i32) MCValue {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .elementwise_regs_then_frame,
            .reserved_frame,
            .air_ref,
            => unreachable, // not valid
            .eflags,
            .register_pair,
            .register_overflow,
            .memory,
            .indirect,
            .load_direct,
            .lea_direct,
            .load_got,
            .lea_got,
            .load_tlv,
            .lea_tlv,
            .load_frame,
            .load_symbol,
            .lea_symbol,
            => switch (off) {
                0 => mcv,
                else => unreachable, // not offsettable
            },
            .immediate => |imm| .{ .immediate = @bit_cast(@as(i64, @bit_cast(imm)) +% off) },
            .register => |reg| .{ .register_offset = .{ .reg = reg, .off = off } },
            .register_offset => |reg_off| .{
                .register_offset = .{ .reg = reg_off.reg, .off = reg_off.off + off },
            },
            .lea_frame => |frame_addr| .{
                .lea_frame = .{ .index = frame_addr.index, .off = frame_addr.off + off },
            },
        };
    }

    fn mem(mcv: MCValue, function: *Self, size: Memory.Size) !Memory {
        return switch (mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .immediate,
            .eflags,
            .register,
            .register_pair,
            .register_offset,
            .register_overflow,
            .load_direct,
            .lea_direct,
            .load_got,
            .lea_got,
            .load_tlv,
            .lea_tlv,
            .lea_frame,
            .elementwise_regs_then_frame,
            .reserved_frame,
            .lea_symbol,
            => unreachable,
            .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |small_addr| .{
                .base = .{ .reg = .ds },
                .mod = .{ .rm = .{
                    .size = size,
                    .disp = small_addr,
                } },
            } else .{ .base = .{ .reg = .ds }, .mod = .{ .off = addr } },
            .indirect => |reg_off| .{
                .base = .{ .reg = reg_off.reg },
                .mod = .{ .rm = .{
                    .size = size,
                    .disp = reg_off.off,
                } },
            },
            .load_frame => |frame_addr| .{
                .base = .{ .frame = frame_addr.index },
                .mod = .{ .rm = .{
                    .size = size,
                    .disp = frame_addr.off,
                } },
            },
            .load_symbol => |sym_off| {
                assert(sym_off.off == 0);
                return .{
                    .base = .{ .reloc = .{
                        .atom_index = try function.owner.get_symbol_index(function),
                        .sym_index = sym_off.sym,
                    } },
                    .mod = .{ .rm = .{
                        .size = size,
                        .disp = sym_off.off,
                    } },
                };
            },
            .air_ref => |ref| (try function.resolve_inst(ref)).mem(function, size),
        };
    }

    pub fn format(
        mcv: MCValue,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (mcv) {
            .none, .unreach, .dead, .undef => try writer.print("({s})", .{@tag_name(mcv)}),
            .immediate => |pl| try writer.print("0x{x}", .{pl}),
            .memory => |pl| try writer.print("[ds:0x{x}]", .{pl}),
            inline .eflags, .register => |pl| try writer.print("{s}", .{@tag_name(pl)}),
            .register_pair => |pl| try writer.print("{s}:{s}", .{ @tag_name(pl[1]), @tag_name(pl[0]) }),
            .register_offset => |pl| try writer.print("{s} + 0x{x}", .{ @tag_name(pl.reg), pl.off }),
            .register_overflow => |pl| try writer.print("{s}:{s}", .{
                @tag_name(pl.eflags), @tag_name(pl.reg),
            }),
            .load_symbol => |pl| try writer.print("[{} + 0x{x}]", .{ pl.sym, pl.off }),
            .lea_symbol => |pl| try writer.print("{} + 0x{x}", .{ pl.sym, pl.off }),
            .indirect => |pl| try writer.print("[{s} + 0x{x}]", .{ @tag_name(pl.reg), pl.off }),
            .load_direct => |pl| try writer.print("[direct:{d}]", .{pl}),
            .lea_direct => |pl| try writer.print("direct:{d}", .{pl}),
            .load_got => |pl| try writer.print("[got:{d}]", .{pl}),
            .lea_got => |pl| try writer.print("got:{d}", .{pl}),
            .load_tlv => |pl| try writer.print("[tlv:{d}]", .{pl}),
            .lea_tlv => |pl| try writer.print("tlv:{d}", .{pl}),
            .load_frame => |pl| try writer.print("[{} + 0x{x}]", .{ pl.index, pl.off }),
            .elementwise_regs_then_frame => |pl| try writer.print("elementwise:{d}:[{} + 0x{x}]", .{ pl.regs, pl.frame_index, pl.frame_off }),
            .lea_frame => |pl| try writer.print("{} + 0x{x}", .{ pl.index, pl.off }),
            .reserved_frame => |pl| try writer.print("(dead:{})", .{pl}),
            .air_ref => |pl| try writer.print("(air:0x{x})", .{@int_from_enum(pl)}),
        }
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
            .load_direct,
            .lea_direct,
            .load_got,
            .lea_got,
            .load_tlv,
            .lea_tlv,
            .load_frame,
            .lea_frame,
            .load_symbol,
            .lea_symbol,
            => result,
            .dead,
            .elementwise_regs_then_frame,
            .reserved_frame,
            .air_ref,
            => unreachable,
            .eflags,
            .register,
            .register_pair,
            .register_offset,
            .register_overflow,
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

    fn get_condition(self: InstTracking) ?Condition {
        return self.short.get_condition();
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
        try function.gen_copy(function.type_of_index(inst), self.long, self.short, .{});
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
            .load_direct,
            .lea_direct,
            .load_got,
            .lea_got,
            .load_tlv,
            .lea_tlv,
            .load_frame,
            .lea_frame,
            .load_symbol,
            .lea_symbol,
            => self.long,
            .dead,
            .eflags,
            .register,
            .register_pair,
            .register_offset,
            .register_overflow,
            .indirect,
            .elementwise_regs_then_frame,
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
            .load_direct,
            .lea_direct,
            .load_got,
            .lea_got,
            .load_tlv,
            .lea_tlv,
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
            .eflags,
            .register,
            .register_pair,
            .register_offset,
            .register_overflow,
            .indirect,
            .elementwise_regs_then_frame,
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
            try function.gen_copy(ty, target.long, self.short, .{});
        try function.gen_copy(ty, target.short, self.short, .{});
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
            var remaining_reg: Register = .none;
            for (tracking.get_regs()) |tracked_reg| if (tracked_reg.id() == reg.id()) {
                assert(!found_reg);
                found_reg = true;
            } else {
                assert(remaining_reg == .none);
                remaining_reg = tracked_reg;
            };
            assert(found_reg);
            tracking.short = switch (remaining_reg) {
                .none => .{ .dead = function.scope_generation },
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
    fn init_type(ty: Type, mod: *Module) FrameAlloc {
        return init(.{
            .size = ty.abi_size(mod),
            .alignment = ty.abi_alignment(mod),
        });
    }
    fn init_spill(ty: Type, mod: *Module) FrameAlloc {
        const abi_size = ty.abi_size(mod);
        const spill_size = if (abi_size < 8)
            math.ceil_power_of_two_assert(u64, abi_size)
        else
            std.mem.align_forward(u64, abi_size, 8);
        return init(.{
            .size = spill_size,
            .pad = @int_cast(spill_size - abi_size),
            .alignment = ty.abi_alignment(mod).max_strict(
                Alignment.from_nonzero_byte_units(@min(spill_size, 8)),
            ),
        });
    }
};

const StackAllocation = struct {
    inst: ?Air.Inst.Index,
    /// TODO do we need size? should be determined by inst.ty.abi_size(mod)
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

const Self = @This();

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
    const func = zcu.func_info(func_index);
    const fn_owner_decl = zcu.decl_ptr(func.owner_decl);
    assert(fn_owner_decl.has_tv);
    const fn_type = fn_owner_decl.type_of(zcu);
    const namespace = zcu.namespace_ptr(fn_owner_decl.src_namespace);
    const mod = namespace.file_scope.mod;

    var function = Self{
        .gpa = gpa,
        .air = air,
        .liveness = liveness,
        .target = &mod.resolved_target.result,
        .mod = mod,
        .bin_file = bin_file,
        .debug_output = debug_output,
        .owner = .{ .func_index = func_index },
        .inline_func = func_index,
        .err_msg = null,
        .args = undefined, // populated after `resolve_calling_convention_values`
        .va_info = undefined, // populated after `resolve_calling_convention_values`
        .ret_mcv = undefined, // populated after `resolve_calling_convention_values`
        .fn_type = fn_type,
        .arg_index = 0,
        .src_loc = src_loc,
        .end_di_line = func.rbrace_line,
        .end_di_column = func.rbrace_column,
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

    wip_mir_log.debug("{}:", .{function.fmt_decl(func.owner_decl)});

    const ip = &zcu.intern_pool;

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
    const cc = abi.resolve_calling_convention(fn_info.cc, function.target.*);
    var call_info = function.resolve_calling_convention_values(fn_info, &.{}, .args_frame) catch |err| switch (err) {
        error.CodegenFail => return Result{ .fail = function.err_msg.? },
        error.OutOfRegisters => return Result{
            .fail = try ErrorMsg.create(
                gpa,
                src_loc,
                "CodeGen ran out of registers. This is a bug in the Zig compiler.",
                .{},
            ),
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
    function.frame_allocs.set(
        @int_from_enum(FrameIndex.args_frame),
        FrameAlloc.init(.{
            .size = call_info.stack_byte_count,
            .alignment = call_info.stack_align,
        }),
    );
    function.va_info = switch (cc) {
        .SysV => .{ .sysv = .{
            .gp_count = call_info.gp_count,
            .fp_count = call_info.fp_count,
            .overflow_arg_area = .{ .index = .args_frame, .off = call_info.stack_byte_count },
            .reg_save_area = undefined,
        } },
        .Win64 => .{ .win64 = .{} },
        else => undefined,
    };

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
            .cc = cc,
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
        error.InvalidInstruction, error.CannotEncode => |e| {
            const msg = switch (e) {
                error.InvalidInstruction => "CodeGen failed to find a viable instruction.",
                error.CannotEncode => "CodeGen failed to encode the instruction.",
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

pub fn generate_lazy(
    bin_file: *link.File,
    src_loc: Module.SrcLoc,
    lazy_sym: link.File.LazySymbol,
    code: *std.ArrayList(u8),
    debug_output: DebugInfoOutput,
) CodeGenError!Result {
    const comp = bin_file.comp;
    const gpa = comp.gpa;
    // This function is for generating global code, so we use the root module.
    const mod = comp.root_mod;
    var function = Self{
        .gpa = gpa,
        .air = undefined,
        .liveness = undefined,
        .target = &mod.resolved_target.result,
        .mod = mod,
        .bin_file = bin_file,
        .debug_output = debug_output,
        .owner = .{ .lazy_sym = lazy_sym },
        .inline_func = undefined,
        .err_msg = null,
        .args = undefined,
        .va_info = undefined,
        .ret_mcv = undefined,
        .fn_type = undefined,
        .arg_index = undefined,
        .src_loc = src_loc,
        .end_di_line = undefined, // no debug info yet
        .end_di_column = undefined, // no debug info yet
    };
    defer {
        function.mir_instructions.deinit(gpa);
        function.mir_extra.deinit(gpa);
    }

    function.gen_lazy(lazy_sym) catch |err| switch (err) {
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
            .cc = abi.resolve_calling_convention(.Unspecified, function.target.*),
            .src_loc = src_loc,
            .output_mode = comp.config.output_mode,
            .link_mode = comp.config.link_mode,
            .pic = mod.pic,
        },
        .debug_output = debug_output,
        .code = code,
        .prev_di_pc = undefined, // no debug info yet
        .prev_di_line = undefined, // no debug info yet
        .prev_di_column = undefined, // no debug info yet
    };
    defer emit.deinit();
    emit.emit_mir() catch |err| switch (err) {
        error.LowerFail, error.EmitFail => return Result{ .fail = emit.lower.err_msg.? },
        error.InvalidInstruction, error.CannotEncode => |e| {
            const msg = switch (e) {
                error.InvalidInstruction => "CodeGen failed to find a viable instruction.",
                error.CannotEncode => "CodeGen failed to encode the instruction.",
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

const FormatDeclData = struct {
    mod: *Module,
    decl_index: InternPool.DeclIndex,
};
fn format_decl(
    data: FormatDeclData,
    comptime _: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    try data.mod.decl_ptr(data.decl_index).render_fully_qualified_name(data.mod, writer);
}
fn fmt_decl(self: *Self, decl_index: InternPool.DeclIndex) std.fmt.Formatter(format_decl) {
    return .{ .data = .{
        .mod = self.bin_file.comp.module.?,
        .decl_index = decl_index,
    } };
}

const FormatAirData = struct {
    self: *Self,
    inst: Air.Inst.Index,
};
fn format_air(
    data: FormatAirData,
    comptime _: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    @import("../../print_air.zig").dump_inst(
        data.inst,
        data.self.bin_file.comp.module.?,
        data.self.air,
        data.self.liveness,
    );
}
fn fmt_air(self: *Self, inst: Air.Inst.Index) std.fmt.Formatter(format_air) {
    return .{ .data = .{ .self = self, .inst = inst } };
}

const FormatWipMirData = struct {
    self: *Self,
    inst: Mir.Inst.Index,
};
fn format_wip_mir(
    data: FormatWipMirData,
    comptime _: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    const comp = data.self.bin_file.comp;
    const mod = comp.root_mod;
    var lower = Lower{
        .bin_file = data.self.bin_file,
        .allocator = data.self.gpa,
        .mir = .{
            .instructions = data.self.mir_instructions.slice(),
            .extra = data.self.mir_extra.items,
            .frame_locs = (std.MultiArrayList(Mir.FrameLoc){}).slice(),
        },
        .cc = .Unspecified,
        .src_loc = data.self.src_loc,
        .output_mode = comp.config.output_mode,
        .link_mode = comp.config.link_mode,
        .pic = mod.pic,
    };
    var first = true;
    for ((lower.lower_mir(data.inst) catch |err| switch (err) {
        error.LowerFail => {
            defer {
                lower.err_msg.?.deinit(data.self.gpa);
                lower.err_msg = null;
            }
            try writer.write_all(lower.err_msg.?.msg);
            return;
        },
        error.OutOfMemory, error.InvalidInstruction, error.CannotEncode => |e| {
            try writer.write_all(switch (e) {
                error.OutOfMemory => "Out of memory",
                error.InvalidInstruction => "CodeGen failed to find a viable instruction.",
                error.CannotEncode => "CodeGen failed to encode the instruction.",
            });
            return;
        },
        else => |e| return e,
    }).insts) |lowered_inst| {
        if (!first) try writer.write_all("\ndebug(wip_mir): ");
        try writer.print("  | {}", .{lowered_inst});
        first = false;
    }
}
fn fmt_wip_mir(self: *Self, inst: Mir.Inst.Index) std.fmt.Formatter(format_wip_mir) {
    return .{ .data = .{ .self = self, .inst = inst } };
}

const FormatTrackingData = struct {
    self: *Self,
};
fn format_tracking(
    data: FormatTrackingData,
    comptime _: []const u8,
    _: std.fmt.FormatOptions,
    writer: anytype,
) @TypeOf(writer).Error!void {
    var it = data.self.inst_tracking.iterator();
    while (it.next()) |entry| try writer.print("\n%{d} = {}", .{ entry.key_ptr.*, entry.value_ptr.* });
}
fn fmt_tracking(self: *Self) std.fmt.Formatter(format_tracking) {
    return .{ .data = .{ .self = self } };
}

fn add_inst(self: *Self, inst: Mir.Inst) error{OutOfMemory}!Mir.Inst.Index {
    const gpa = self.gpa;
    try self.mir_instructions.ensure_unused_capacity(gpa, 1);
    const result_index: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
    self.mir_instructions.append_assume_capacity(inst);
    if (inst.tag != .pseudo or switch (inst.ops) {
        else => true,
        .pseudo_dbg_prologue_end_none,
        .pseudo_dbg_line_line_column,
        .pseudo_dbg_epilogue_begin_none,
        .pseudo_dead_none,
        => false,
    }) wip_mir_log.debug("{}", .{self.fmt_wip_mir(result_index)});
    return result_index;
}

fn add_extra(self: *Self, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try self.mir_extra.ensure_unused_capacity(self.gpa, fields.len);
    return self.add_extra_assume_capacity(extra);
}

fn add_extra_assume_capacity(self: *Self, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const result: u32 = @int_cast(self.mir_extra.items.len);
    inline for (fields) |field| {
        self.mir_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            i32, Mir.Memory.Info => @bit_cast(@field(extra, field.name)),
            else => @compile_error("bad field type: " ++ field.name ++ ": " ++ @type_name(field.type)),
        });
    }
    return result;
}

/// A `cc` of `.z_and_np` clobbers `reg2`!
fn asm_cmovcc_register_register(self: *Self, cc: Condition, reg1: Register, reg2: Register) !void {
    _ = try self.add_inst(.{
        .tag = switch (cc) {
            else => .cmov,
            .z_and_np, .nz_or_p => .pseudo,
        },
        .ops = switch (cc) {
            else => .rr,
            .z_and_np => .pseudo_cmov_z_and_np_rr,
            .nz_or_p => .pseudo_cmov_nz_or_p_rr,
        },
        .data = .{ .rr = .{
            .fixes = switch (cc) {
                else => Mir.Inst.Fixes.from_condition(cc),
                .z_and_np, .nz_or_p => ._,
            },
            .r1 = reg1,
            .r2 = reg2,
        } },
    });
}

/// A `cc` of `.z_and_np` is not supported by this encoding!
fn asm_cmovcc_register_memory(self: *Self, cc: Condition, reg: Register, m: Memory) !void {
    _ = try self.add_inst(.{
        .tag = switch (cc) {
            else => .cmov,
            .z_and_np => unreachable,
            .nz_or_p => .pseudo,
        },
        .ops = switch (cc) {
            else => .rm,
            .z_and_np => unreachable,
            .nz_or_p => .pseudo_cmov_nz_or_p_rm,
        },
        .data = .{ .rx = .{
            .fixes = switch (cc) {
                else => Mir.Inst.Fixes.from_condition(cc),
                .z_and_np => unreachable,
                .nz_or_p => ._,
            },
            .r1 = reg,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_setcc_register(self: *Self, cc: Condition, reg: Register) !void {
    _ = try self.add_inst(.{
        .tag = switch (cc) {
            else => .set,
            .z_and_np, .nz_or_p => .pseudo,
        },
        .ops = switch (cc) {
            else => .r,
            .z_and_np => .pseudo_set_z_and_np_r,
            .nz_or_p => .pseudo_set_nz_or_p_r,
        },
        .data = switch (cc) {
            else => .{ .r = .{
                .fixes = Mir.Inst.Fixes.from_condition(cc),
                .r1 = reg,
            } },
            .z_and_np, .nz_or_p => .{ .rr = .{
                .r1 = reg,
                .r2 = (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to8(),
            } },
        },
    });
}

fn asm_setcc_memory(self: *Self, cc: Condition, m: Memory) !void {
    const payload = try self.add_extra(Mir.Memory.encode(m));
    _ = try self.add_inst(.{
        .tag = switch (cc) {
            else => .set,
            .z_and_np, .nz_or_p => .pseudo,
        },
        .ops = switch (cc) {
            else => .m,
            .z_and_np => .pseudo_set_z_and_np_m,
            .nz_or_p => .pseudo_set_nz_or_p_m,
        },
        .data = switch (cc) {
            else => .{ .x = .{
                .fixes = Mir.Inst.Fixes.from_condition(cc),
                .payload = payload,
            } },
            .z_and_np, .nz_or_p => .{ .rx = .{
                .r1 = (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to8(),
                .payload = payload,
            } },
        },
    });
}

fn asm_jmp_reloc(self: *Self, target: Mir.Inst.Index) !Mir.Inst.Index {
    return self.add_inst(.{
        .tag = .jmp,
        .ops = .inst,
        .data = .{ .inst = .{
            .inst = target,
        } },
    });
}

fn asm_jcc_reloc(self: *Self, cc: Condition, target: Mir.Inst.Index) !Mir.Inst.Index {
    return self.add_inst(.{
        .tag = switch (cc) {
            else => .j,
            .z_and_np, .nz_or_p => .pseudo,
        },
        .ops = switch (cc) {
            else => .inst,
            .z_and_np => .pseudo_j_z_and_np_inst,
            .nz_or_p => .pseudo_j_nz_or_p_inst,
        },
        .data = .{ .inst = .{
            .fixes = switch (cc) {
                else => Mir.Inst.Fixes.from_condition(cc),
                .z_and_np, .nz_or_p => ._,
            },
            .inst = target,
        } },
    });
}

fn asm_reloc(self: *Self, tag: Mir.Inst.FixedTag, target: Mir.Inst.Index) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .inst,
        .data = .{ .inst = .{
            .fixes = tag[0],
            .inst = target,
        } },
    });
}

fn asm_placeholder(self: *Self) !Mir.Inst.Index {
    return self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dead_none,
        .data = undefined,
    });
}

fn asm_op_only(self: *Self, tag: Mir.Inst.FixedTag) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .none,
        .data = .{ .none = .{
            .fixes = tag[0],
        } },
    });
}

fn asm_pseudo(self: *Self, ops: Mir.Inst.Ops) !void {
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = ops,
        .data = undefined,
    });
}

fn asm_register(self: *Self, tag: Mir.Inst.FixedTag, reg: Register) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .r,
        .data = .{ .r = .{
            .fixes = tag[0],
            .r1 = reg,
        } },
    });
}

fn asm_immediate(self: *Self, tag: Mir.Inst.FixedTag, imm: Immediate) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = switch (imm) {
            .signed => .i_s,
            .unsigned => .i_u,
        },
        .data = .{ .i = .{
            .fixes = tag[0],
            .i = switch (imm) {
                .signed => |s| @bit_cast(s),
                .unsigned => |u| @int_cast(u),
            },
        } },
    });
}

fn asm_register_register(self: *Self, tag: Mir.Inst.FixedTag, reg1: Register, reg2: Register) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rr,
        .data = .{ .rr = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
        } },
    });
}

fn asm_register_immediate(self: *Self, tag: Mir.Inst.FixedTag, reg: Register, imm: Immediate) !void {
    const ops: Mir.Inst.Ops = switch (imm) {
        .signed => .ri_s,
        .unsigned => |u| if (math.cast(u32, u)) |_| .ri_u else .ri64,
    };
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = ops,
        .data = switch (ops) {
            .ri_s, .ri_u => .{ .ri = .{
                .fixes = tag[0],
                .r1 = reg,
                .i = switch (imm) {
                    .signed => |s| @bit_cast(s),
                    .unsigned => |u| @int_cast(u),
                },
            } },
            .ri64 => .{ .rx = .{
                .fixes = tag[0],
                .r1 = reg,
                .payload = try self.add_extra(Mir.Imm64.encode(imm.unsigned)),
            } },
            else => unreachable,
        },
    });
}

fn asm_register_register_register(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    reg3: Register,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrr,
        .data = .{ .rrr = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .r3 = reg3,
        } },
    });
}

fn asm_register_register_register_register(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    reg3: Register,
    reg4: Register,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrrr,
        .data = .{ .rrrr = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .r3 = reg3,
            .r4 = reg4,
        } },
    });
}

fn asm_register_register_register_immediate(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    reg3: Register,
    imm: Immediate,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrri,
        .data = .{ .rrri = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .r3 = reg3,
            .i = switch (imm) {
                .signed => |s| @bit_cast(@as(i8, @int_cast(s))),
                .unsigned => |u| @int_cast(u),
            },
        } },
    });
}

fn asm_register_register_immediate(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    imm: Immediate,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = switch (imm) {
            .signed => .rri_s,
            .unsigned => .rri_u,
        },
        .data = .{ .rri = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .i = switch (imm) {
                .signed => |s| @bit_cast(s),
                .unsigned => |u| @int_cast(u),
            },
        } },
    });
}

fn asm_register_register_memory(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    m: Memory,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrm,
        .data = .{ .rrx = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_register_register_memory_register(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    m: Memory,
    reg3: Register,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrmr,
        .data = .{ .rrrx = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .r3 = reg3,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_memory(self: *Self, tag: Mir.Inst.FixedTag, m: Memory) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .m,
        .data = .{ .x = .{
            .fixes = tag[0],
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_register_memory(self: *Self, tag: Mir.Inst.FixedTag, reg: Register, m: Memory) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rm,
        .data = .{ .rx = .{
            .fixes = tag[0],
            .r1 = reg,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_register_memory_register(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    m: Memory,
    reg2: Register,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rmr,
        .data = .{ .rrx = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_register_memory_immediate(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg: Register,
    m: Memory,
    imm: Immediate,
) !void {
    if (switch (imm) {
        .signed => |s| if (math.cast(i16, s)) |x| @as(u16, @bit_cast(x)) else null,
        .unsigned => |u| math.cast(u16, u),
    }) |small_imm| {
        _ = try self.add_inst(.{
            .tag = tag[1],
            .ops = .rmi,
            .data = .{ .rix = .{
                .fixes = tag[0],
                .r1 = reg,
                .i = small_imm,
                .payload = try self.add_extra(Mir.Memory.encode(m)),
            } },
        });
    } else {
        const payload = try self.add_extra(Mir.Imm32{ .imm = switch (imm) {
            .signed => |s| @bit_cast(s),
            .unsigned => unreachable,
        } });
        assert(payload + 1 == try self.add_extra(Mir.Memory.encode(m)));
        _ = try self.add_inst(.{
            .tag = tag[1],
            .ops = switch (imm) {
                .signed => .rmi_s,
                .unsigned => .rmi_u,
            },
            .data = .{ .rx = .{
                .fixes = tag[0],
                .r1 = reg,
                .payload = payload,
            } },
        });
    }
}

fn asm_register_register_memory_immediate(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    reg1: Register,
    reg2: Register,
    m: Memory,
    imm: Immediate,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .rrmi,
        .data = .{ .rrix = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .i = @int_cast(imm.unsigned),
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_memory_register(self: *Self, tag: Mir.Inst.FixedTag, m: Memory, reg: Register) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .mr,
        .data = .{ .rx = .{
            .fixes = tag[0],
            .r1 = reg,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_memory_immediate(self: *Self, tag: Mir.Inst.FixedTag, m: Memory, imm: Immediate) !void {
    const payload = try self.add_extra(Mir.Imm32{ .imm = switch (imm) {
        .signed => |s| @bit_cast(s),
        .unsigned => |u| @int_cast(u),
    } });
    assert(payload + 1 == try self.add_extra(Mir.Memory.encode(m)));
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = switch (imm) {
            .signed => .mi_s,
            .unsigned => .mi_u,
        },
        .data = .{ .x = .{
            .fixes = tag[0],
            .payload = payload,
        } },
    });
}

fn asm_memory_register_register(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    m: Memory,
    reg1: Register,
    reg2: Register,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .mrr,
        .data = .{ .rrx = .{
            .fixes = tag[0],
            .r1 = reg1,
            .r2 = reg2,
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn asm_memory_register_immediate(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    m: Memory,
    reg: Register,
    imm: Immediate,
) !void {
    _ = try self.add_inst(.{
        .tag = tag[1],
        .ops = .mri,
        .data = .{ .rix = .{
            .fixes = tag[0],
            .r1 = reg,
            .i = @int_cast(imm.unsigned),
            .payload = try self.add_extra(Mir.Memory.encode(m)),
        } },
    });
}

fn gen(self: *Self) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const fn_info = mod.type_to_func(self.fn_type).?;
    const cc = abi.resolve_calling_convention(fn_info.cc, self.target.*);
    if (cc != .Naked) {
        try self.asm_register(.{ ._, .push }, .rbp);
        try self.asm_register_register(.{ ._, .mov }, .rbp, .rsp);
        const backpatch_push_callee_preserved_regs = try self.asm_placeholder();
        const backpatch_frame_align = try self.asm_placeholder();
        const backpatch_frame_align_extra = try self.asm_placeholder();
        const backpatch_stack_alloc = try self.asm_placeholder();
        const backpatch_stack_alloc_extra = try self.asm_placeholder();

        switch (self.ret_mcv.long) {
            .none, .unreach => {},
            .indirect => {
                // The address where to store the return value for the caller is in a
                // register which the callee is free to clobber. Therefore, we purposely
                // spill it to stack immediately.
                const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(Type.usize, mod));
                try self.gen_set_mem(
                    .{ .frame = frame_index },
                    0,
                    Type.usize,
                    self.ret_mcv.long.address().offset(-self.ret_mcv.short.indirect.off),
                    .{},
                );
                self.ret_mcv.long = .{ .load_frame = .{ .index = frame_index } };
                tracking_log.debug("spill {} to {}", .{ self.ret_mcv.long, frame_index });
            },
            else => unreachable,
        }

        if (fn_info.is_var_args) switch (cc) {
            .SysV => {
                const info = &self.va_info.sysv;
                const reg_save_area_fi = try self.alloc_frame_index(FrameAlloc.init(.{
                    .size = abi.SysV.c_abi_int_param_regs.len * 8 +
                        abi.SysV.c_abi_sse_param_regs.len * 16,
                    .alignment = .@"16",
                }));
                info.reg_save_area = .{ .index = reg_save_area_fi };

                for (abi.SysV.c_abi_int_param_regs[info.gp_count..], info.gp_count..) |reg, reg_i|
                    try self.gen_set_mem(
                        .{ .frame = reg_save_area_fi },
                        @int_cast(reg_i * 8),
                        Type.usize,
                        .{ .register = reg },
                        .{},
                    );

                try self.asm_register_immediate(.{ ._, .cmp }, .al, Immediate.u(info.fp_count));
                const skip_sse_reloc = try self.asm_jcc_reloc(.na, undefined);

                const vec_2_f64 = try mod.vector_type(.{ .len = 2, .child = .f64_type });
                for (abi.SysV.c_abi_sse_param_regs[info.fp_count..], info.fp_count..) |reg, reg_i|
                    try self.gen_set_mem(
                        .{ .frame = reg_save_area_fi },
                        @int_cast(abi.SysV.c_abi_int_param_regs.len * 8 + reg_i * 16),
                        vec_2_f64,
                        .{ .register = reg },
                        .{},
                    );

                self.perform_reloc(skip_sse_reloc);
            },
            .Win64 => return self.fail("TODO implement gen var arg function for Win64", .{}),
            else => unreachable,
        };

        try self.asm_pseudo(.pseudo_dbg_prologue_end_none);

        try self.gen_body(self.air.get_main_body());

        // TODO can single exitlude jump reloc be elided? What if it is not at the end of the code?
        // Example:
        // pub fn main() void {
        //     maybeErr() catch return;
        //     unreachable;
        // }
        // Eliding the reloc will cause a miscompilation in this case.
        for (self.exitlude_jump_relocs.items) |jmp_reloc| {
            self.mir_instructions.items(.data)[jmp_reloc].inst.inst =
                @int_cast(self.mir_instructions.len);
        }

        try self.asm_pseudo(.pseudo_dbg_epilogue_begin_none);
        const backpatch_stack_dealloc = try self.asm_placeholder();
        const backpatch_pop_callee_preserved_regs = try self.asm_placeholder();
        try self.asm_register(.{ ._, .pop }, .rbp);
        try self.asm_op_only(.{ ._, .ret });

        const frame_layout = try self.compute_frame_layout(cc);
        const need_frame_align = frame_layout.stack_mask != math.max_int(u32);
        const need_stack_adjust = frame_layout.stack_adjust > 0;
        const need_save_reg = frame_layout.save_reg_list.count() > 0;
        if (need_frame_align) {
            const page_align = @as(u32, math.max_int(u32)) << 12;
            self.mir_instructions.set(backpatch_frame_align, .{
                .tag = .@"and",
                .ops = .ri_s,
                .data = .{ .ri = .{
                    .r1 = .rsp,
                    .i = @max(frame_layout.stack_mask, page_align),
                } },
            });
            if (frame_layout.stack_mask < page_align) {
                self.mir_instructions.set(backpatch_frame_align_extra, .{
                    .tag = .pseudo,
                    .ops = .pseudo_probe_align_ri_s,
                    .data = .{ .ri = .{
                        .r1 = .rsp,
                        .i = ~frame_layout.stack_mask & page_align,
                    } },
                });
            }
        }
        if (need_stack_adjust) {
            const page_size: u32 = 1 << 12;
            if (frame_layout.stack_adjust <= page_size) {
                self.mir_instructions.set(backpatch_stack_alloc, .{
                    .tag = .sub,
                    .ops = .ri_s,
                    .data = .{ .ri = .{
                        .r1 = .rsp,
                        .i = frame_layout.stack_adjust,
                    } },
                });
            } else if (frame_layout.stack_adjust <
                page_size * Lower.pseudo_probe_adjust_unrolled_max_insts)
            {
                self.mir_instructions.set(backpatch_stack_alloc, .{
                    .tag = .pseudo,
                    .ops = .pseudo_probe_adjust_unrolled_ri_s,
                    .data = .{ .ri = .{
                        .r1 = .rsp,
                        .i = frame_layout.stack_adjust,
                    } },
                });
            } else {
                self.mir_instructions.set(backpatch_stack_alloc, .{
                    .tag = .pseudo,
                    .ops = .pseudo_probe_adjust_setup_rri_s,
                    .data = .{ .rri = .{
                        .r1 = .rsp,
                        .r2 = .rax,
                        .i = frame_layout.stack_adjust,
                    } },
                });
                self.mir_instructions.set(backpatch_stack_alloc_extra, .{
                    .tag = .pseudo,
                    .ops = .pseudo_probe_adjust_loop_rr,
                    .data = .{ .rr = .{
                        .r1 = .rsp,
                        .r2 = .rax,
                    } },
                });
            }
        }
        if (need_frame_align or need_stack_adjust) {
            self.mir_instructions.set(backpatch_stack_dealloc, .{
                .tag = .lea,
                .ops = .rm,
                .data = .{ .rx = .{
                    .r1 = .rsp,
                    .payload = try self.add_extra(Mir.Memory.encode(.{
                        .base = .{ .reg = .rbp },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .disp = -frame_layout.save_reg_list.size(),
                        } },
                    })),
                } },
            });
        }
        if (need_save_reg) {
            self.mir_instructions.set(backpatch_push_callee_preserved_regs, .{
                .tag = .pseudo,
                .ops = .pseudo_push_reg_list,
                .data = .{ .reg_list = frame_layout.save_reg_list },
            });
            self.mir_instructions.set(backpatch_pop_callee_preserved_regs, .{
                .tag = .pseudo,
                .ops = .pseudo_pop_reg_list,
                .data = .{ .reg_list = frame_layout.save_reg_list },
            });
        }
    } else {
        try self.asm_pseudo(.pseudo_dbg_prologue_end_none);
        try self.gen_body(self.air.get_main_body());
        try self.asm_pseudo(.pseudo_dbg_epilogue_begin_none);
    }

    // Drop them off at the rbrace.
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_line_line_column,
        .data = .{ .line_column = .{
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
        if (self.liveness.is_unused(inst) and !self.air.must_lower(inst, ip)) continue;
        wip_mir_log.debug("{}", .{self.fmt_air(inst)});
        verbose_tracking_log.debug("{}", .{self.fmt_tracking()});

        const old_air_bookkeeping = self.air_bookkeeping;
        try self.inst_tracking.ensure_unused_capacity(self.gpa, 1);
        switch (air_tags[@int_from_enum(inst)]) {
            // zig fmt: off
            .not,
            => |tag| try self.air_un_op(inst, tag),

            .add,
            .add_wrap,
            .sub,
            .sub_wrap,
            .bool_and,
            .bool_or,
            .bit_and,
            .bit_or,
            .xor,
            .min,
            .max,
            => |tag| try self.air_bin_op(inst, tag),

            .ptr_add, .ptr_sub => |tag| try self.air_ptr_arithmetic(inst, tag),

            .shr, .shr_exact => try self.air_shl_shr_bin_op(inst),
            .shl, .shl_exact => try self.air_shl_shr_bin_op(inst),

            .mul             => try self.air_mul_div_bin_op(inst),
            .mul_wrap        => try self.air_mul_div_bin_op(inst),
            .rem             => try self.air_mul_div_bin_op(inst),
            .mod             => try self.air_mul_div_bin_op(inst),

            .add_sat         => try self.air_add_sat(inst),
            .sub_sat         => try self.air_sub_sat(inst),
            .mul_sat         => try self.air_mul_sat(inst),
            .shl_sat         => try self.air_shl_sat(inst),
            .slice           => try self.air_slice(inst),

            .sin,
            .cos,
            .tan,
            .exp,
            .exp2,
            .log,
            .log2,
            .log10,
            .round,
            => |tag| try self.air_unary_math(inst, tag),

            .floor       => try self.air_round(inst, .{ .mode = .down, .precision = .inexact }),
            .ceil        => try self.air_round(inst, .{ .mode = .up, .precision = .inexact }),
            .trunc_float => try self.air_round(inst, .{ .mode = .zero, .precision = .inexact }),
            .sqrt        => try self.air_sqrt(inst),
            .neg         => try self.air_float_sign(inst),

            .abs => try self.air_abs(inst),

            .add_with_overflow => try self.air_add_sub_with_overflow(inst),
            .sub_with_overflow => try self.air_add_sub_with_overflow(inst),
            .mul_with_overflow => try self.air_mul_with_overflow(inst),
            .shl_with_overflow => try self.air_shl_with_overflow(inst),

            .div_float, .div_trunc, .div_floor, .div_exact => try self.air_mul_div_bin_op(inst),

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
            .fence           => try self.air_fence(inst),
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
            .int_from_ptr        => try self.air_int_from_ptr(inst),
            .ret             => try self.air_ret(inst, false),
            .ret_safe        => try self.air_ret(inst, true),
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
            .popcount        => try self.air_pop_count(inst),
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

            .switch_br       => try self.air_switch_br(inst),
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
            .unwrap_errunion_err        => try self.air_unwrap_err_union_err(inst),
            .unwrap_errunion_payload    => try self.air_unwrap_err_union_payload(inst),
            .unwrap_errunion_err_ptr    => try self.air_unwrap_err_union_err_ptr(inst),
            .unwrap_errunion_payload_ptr=> try self.air_unwrap_err_union_payload_ptr(inst),
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

            .c_va_arg => try self.air_va_arg(inst),
            .c_va_copy => try self.air_va_copy(inst),
            .c_va_end => try self.air_va_end(inst),
            .c_va_start => try self.air_va_start(inst),

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
                    } else unreachable; // tracked register not in use
                }
            }
        }
    }
    verbose_tracking_log.debug("{}", .{self.fmt_tracking()});
}

fn gen_lazy(self: *Self, lazy_sym: link.File.LazySymbol) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    switch (lazy_sym.ty.zig_type_tag(mod)) {
        .Enum => {
            const enum_ty = lazy_sym.ty;
            wip_mir_log.debug("{}.@tag_name:", .{enum_ty.fmt(mod)});

            const resolved_cc = abi.resolve_calling_convention(.Unspecified, self.target.*);
            const param_regs = abi.get_cabi_int_param_regs(resolved_cc);
            const param_locks = self.register_manager.lock_regs_assume_unused(2, param_regs[0..2].*);
            defer for (param_locks) |lock| self.register_manager.unlock_reg(lock);

            const ret_reg = param_regs[0];
            const enum_mcv = MCValue{ .register = param_regs[1] };

            const exitlude_jump_relocs = try self.gpa.alloc(Mir.Inst.Index, enum_ty.enum_field_count(mod));
            defer self.gpa.free(exitlude_jump_relocs);

            const data_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const data_lock = self.register_manager.lock_reg_assume_unused(data_reg);
            defer self.register_manager.unlock_reg(data_lock);
            try self.gen_lazy_symbol_ref(.lea, data_reg, .{ .kind = .const_data, .ty = enum_ty });

            var data_off: i32 = 0;
            const tag_names = enum_ty.enum_fields(mod);
            for (exitlude_jump_relocs, 0..) |*exitlude_jump_reloc, tag_index| {
                const tag_name_len = tag_names.get(ip)[tag_index].length(ip);
                const tag_val = try mod.enum_value_field_index(enum_ty, @int_cast(tag_index));
                const tag_mcv = try self.gen_typed_value(tag_val);
                try self.gen_bin_op_mir(.{ ._, .cmp }, enum_ty, enum_mcv, tag_mcv);
                const skip_reloc = try self.asm_jcc_reloc(.ne, undefined);

                try self.gen_set_mem(
                    .{ .reg = ret_reg },
                    0,
                    Type.usize,
                    .{ .register_offset = .{ .reg = data_reg, .off = data_off } },
                    .{},
                );
                try self.gen_set_mem(
                    .{ .reg = ret_reg },
                    8,
                    Type.usize,
                    .{ .immediate = tag_name_len },
                    .{},
                );

                exitlude_jump_reloc.* = try self.asm_jmp_reloc(undefined);
                self.perform_reloc(skip_reloc);

                data_off += @int_cast(tag_name_len + 1);
            }

            try self.air_trap();

            for (exitlude_jump_relocs) |reloc| self.perform_reloc(reloc);
            try self.asm_op_only(.{ ._, .ret });
        },
        else => return self.fail(
            "TODO implement {s} for {}",
            .{ @tag_name(lazy_sym.kind), lazy_sym.ty.fmt(mod) },
        ),
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
        .register => |reg| {
            self.register_manager.free_reg(reg);
            if (reg.class() == .x87) try self.asm_register(.{ .f_, .free }, reg);
        },
        .register_pair => |regs| for (regs) |reg| self.register_manager.free_reg(reg),
        .register_offset => |reg_off| self.register_manager.free_reg(reg_off.reg),
        .register_overflow => |reg_ov| {
            self.register_manager.free_reg(reg_ov.reg);
            self.eflags_inst = null;
        },
        .eflags => self.eflags_inst = null,
        else => {}, // TODO process stack allocation death
    }
}

fn feed(self: *Self, bt: *Liveness.BigTomb, operand: Air.Inst.Ref) !void {
    if (bt.feed()) if (operand.to_index()) |inst| try self.process_death(inst);
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
    stack_mask: u32,
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
        const alignment = self.frame_allocs.items(.abi_align)[frame_i];
        offset.* = @int_cast(alignment.forward(@int_cast(offset.*)));
    }
    self.frame_locs.set(frame_i, .{ .base = base, .disp = offset.* });
    offset.* += self.frame_allocs.items(.abi_size)[frame_i];
}

fn compute_frame_layout(self: *Self, cc: std.builtin.CallingConvention) !FrameLayout {
    const frame_allocs_len = self.frame_allocs.len;
    try self.frame_locs.resize(self.gpa, frame_allocs_len);
    const stack_frame_order = try self.gpa.alloc(FrameIndex, frame_allocs_len - FrameIndex.named_count);
    defer self.gpa.free(stack_frame_order);

    const frame_size = self.frame_allocs.items(.abi_size);
    const frame_align = self.frame_allocs.items(.abi_align);
    const frame_offset = self.frame_locs.items(.disp);

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

    const call_frame_align = frame_align[@int_from_enum(FrameIndex.call_frame)];
    const stack_frame_align = frame_align[@int_from_enum(FrameIndex.stack_frame)];
    const args_frame_align = frame_align[@int_from_enum(FrameIndex.args_frame)];
    const needed_align = call_frame_align.max(stack_frame_align);
    const need_align_stack = needed_align.compare(.gt, args_frame_align);

    // Create list of registers to save in the prologue.
    // TODO handle register classes
    var save_reg_list = Mir.RegisterList{};
    const callee_preserved_regs =
        abi.get_callee_preserved_regs(abi.resolve_calling_convention(cc, self.target.*));
    for (callee_preserved_regs) |reg| {
        if (self.register_manager.is_reg_allocated(reg) or true) {
            save_reg_list.push(callee_preserved_regs, reg);
        }
    }

    var rbp_offset: i32 = 0;
    self.set_frame_loc(.base_ptr, .rbp, &rbp_offset, false);
    self.set_frame_loc(.ret_addr, .rbp, &rbp_offset, false);
    self.set_frame_loc(.args_frame, .rbp, &rbp_offset, false);
    const stack_frame_align_offset = if (need_align_stack)
        0
    else
        save_reg_list.size() + frame_offset[@int_from_enum(FrameIndex.args_frame)];

    var rsp_offset: i32 = 0;
    self.set_frame_loc(.call_frame, .rsp, &rsp_offset, true);
    self.set_frame_loc(.stack_frame, .rsp, &rsp_offset, true);
    for (stack_frame_order) |frame_index| self.set_frame_loc(frame_index, .rsp, &rsp_offset, true);
    rsp_offset += stack_frame_align_offset;
    rsp_offset = @int_cast(needed_align.forward(@int_cast(rsp_offset)));
    rsp_offset -= stack_frame_align_offset;
    frame_size[@int_from_enum(FrameIndex.call_frame)] =
        @int_cast(rsp_offset - frame_offset[@int_from_enum(FrameIndex.stack_frame)]);

    return .{
        .stack_mask = @as(u32, math.max_int(u32)) << @int_cast(if (need_align_stack) @int_from_enum(needed_align) else 0),
        .stack_adjust = @int_cast(rsp_offset - frame_offset[@int_from_enum(FrameIndex.call_frame)]),
        .save_reg_list = save_reg_list,
    };
}

fn get_frame_addr_alignment(self: *Self, frame_addr: FrameAddr) Alignment {
    const alloc_align = self.frame_allocs.get(@int_from_enum(frame_addr.index)).abi_align;
    return @enumFromInt(@min(@int_from_enum(alloc_align), @ctz(frame_addr.off)));
}

fn get_frame_addr_size(self: *Self, frame_addr: FrameAddr) u32 {
    return self.frame_allocs.get(@int_from_enum(frame_addr.index)).abi_size - @as(u31, @int_cast(frame_addr.off));
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
    return frame_index;
}

/// Use a pointer instruction as the basis for allocating stack memory.
fn alloc_mem_ptr(self: *Self, inst: Air.Inst.Index) !FrameIndex {
    const mod = self.bin_file.comp.module.?;
    const ptr_ty = self.type_of_index(inst);
    const val_ty = ptr_ty.child_type(mod);
    return self.alloc_frame_index(FrameAlloc.init(.{
        .size = math.cast(u32, val_ty.abi_size(mod)) orelse {
            return self.fail("type '{}' too big to fit into stack frame", .{val_ty.fmt(mod)});
        },
        .alignment = ptr_ty.ptr_alignment(mod).max(.@"1"),
    }));
}

fn alloc_reg_or_mem(self: *Self, inst: Air.Inst.Index, reg_ok: bool) !MCValue {
    return self.alloc_reg_or_mem_advanced(self.type_of_index(inst), inst, reg_ok);
}

fn alloc_temp_reg_or_mem(self: *Self, elem_ty: Type, reg_ok: bool) !MCValue {
    return self.alloc_reg_or_mem_advanced(elem_ty, null, reg_ok);
}

fn alloc_reg_or_mem_advanced(self: *Self, ty: Type, inst: ?Air.Inst.Index, reg_ok: bool) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const abi_size = math.cast(u32, ty.abi_size(mod)) orelse {
        return self.fail("type '{}' too big to fit into stack frame", .{ty.fmt(mod)});
    };

    if (reg_ok) need_mem: {
        if (abi_size <= @as(u32, switch (ty.zig_type_tag(mod)) {
            .Float => switch (ty.float_bits(self.target.*)) {
                16, 32, 64, 128 => 16,
                80 => break :need_mem,
                else => unreachable,
            },
            .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                    16, 32, 64, 128 => if (self.has_feature(.avx)) 32 else 16,
                    80 => break :need_mem,
                    else => unreachable,
                },
                else => if (self.has_feature(.avx)) 32 else 16,
            },
            else => 8,
        })) {
            if (self.register_manager.try_alloc_reg(inst, self.reg_class_for_type(ty))) |reg| {
                return MCValue{ .register = register_alias(reg, abi_size) };
            }
        }
    }

    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(ty, mod));
    return .{ .load_frame = .{ .index = frame_index } };
}

fn reg_class_for_type(self: *Self, ty: Type) RegisterManager.RegisterBitSet {
    const mod = self.bin_file.comp.module.?;
    return switch (ty.zig_type_tag(mod)) {
        .Float => switch (ty.float_bits(self.target.*)) {
            80 => abi.RegisterClass.x87,
            else => abi.RegisterClass.sse,
        },
        .Vector => switch (ty.child_type(mod).to_intern()) {
            .bool_type, .u1_type => abi.RegisterClass.gp,
            else => if (ty.is_abi_int(mod) and ty.int_info(mod).bits == 1)
                abi.RegisterClass.gp
            else
                abi.RegisterClass.sse,
        },
        else => abi.RegisterClass.gp,
    };
}

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
    try self.spill_eflags_if_occupied();
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
    if (opts.emit_instructions) if (self.eflags_inst) |inst|
        try self.inst_tracking.get_ptr(inst).?.spill(self, inst);
    if (opts.update_tracking) if (self.eflags_inst) |inst| {
        self.eflags_inst = null;
        try self.inst_tracking.get_ptr(inst).?.track_spill(self, inst);
    };

    if (opts.update_tracking and std.debug.runtime_safety) {
        assert(self.eflags_inst == null);
        assert(self.register_manager.free_registers.eql(state.free_registers));
        var used_reg_it = state.free_registers.iterator(.{ .kind = .unset });
        while (used_reg_it.next()) |index|
            assert(self.register_manager.registers[index] == state.registers[index]);
    }
}

pub fn spill_instruction(self: *Self, reg: Register, inst: Air.Inst.Index) !void {
    const tracking = self.inst_tracking.get_ptr(inst) orelse return;
    for (tracking.get_regs()) |tracked_reg| {
        if (tracked_reg.id() == reg.id()) break;
    } else unreachable; // spilled reg not tracked with spilled instruciton
    try tracking.spill(self, inst);
    try tracking.track_spill(self, inst);
}

pub fn spill_eflags_if_occupied(self: *Self) !void {
    if (self.eflags_inst) |inst| {
        self.eflags_inst = null;
        const tracking = self.inst_tracking.get_ptr(inst).?;
        assert(tracking.get_condition() != null);
        try tracking.spill(self, inst);
        try tracking.track_spill(self, inst);
    }
}

pub fn spill_caller_preserved_regs(self: *Self, cc: std.builtin.CallingConvention) !void {
    switch (cc) {
        inline .SysV, .Win64 => |known_cc| try self.spill_registers(
            comptime abi.get_caller_preserved_regs(known_cc),
        ),
        else => unreachable,
    }
}

pub fn spill_registers(self: *Self, comptime registers: []const Register) !void {
    inline for (registers) |reg| try self.register_manager.get_known_reg(reg, null);
}

/// Copies a value to a register without tracking the register. The register is not considered
/// allocated. A second call to `copy_to_tmp_register` may return the same register.
/// This can have a side effect of spilling instructions to the stack to free up a register.
fn copy_to_tmp_register(self: *Self, ty: Type, mcv: MCValue) !Register {
    const reg = try self.register_manager.alloc_reg(null, self.reg_class_for_type(ty));
    try self.gen_set_reg(reg, ty, mcv, .{});
    return reg;
}

/// Allocates a new register and copies `mcv` into it.
/// `reg_owner` is the instruction that gets associated with the register in the register table.
/// This can have a side effect of spilling instructions to the stack to free up a register.
/// WARNING make sure that the allocated register matches the returned MCValue from an instruction!
fn copy_to_register_with_inst_tracking(
    self: *Self,
    reg_owner: Air.Inst.Index,
    ty: Type,
    mcv: MCValue,
) !MCValue {
    const reg: Register = try self.register_manager.alloc_reg(reg_owner, self.reg_class_for_type(ty));
    try self.gen_set_reg(reg, ty, mcv, .{});
    return MCValue{ .register = reg };
}

fn air_alloc(self: *Self, inst: Air.Inst.Index) !void {
    const result = MCValue{ .lea_frame = .{ .index = try self.alloc_mem_ptr(inst) } };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_ret_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const result: MCValue = switch (self.ret_mcv.long) {
        else => unreachable,
        .none => .{ .lea_frame = .{ .index = try self.alloc_mem_ptr(inst) } },
        .load_frame => .{ .register_offset = .{
            .reg = (try self.copy_to_register_with_inst_tracking(
                inst,
                self.type_of_index(inst),
                self.ret_mcv.long,
            )).register,
            .off = self.ret_mcv.short.indirect.off,
        } },
    };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_fptrunc(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const dst_ty = self.type_of_index(inst);
    const dst_bits = dst_ty.float_bits(self.target.*);
    const src_ty = self.type_of(ty_op.operand);
    const src_bits = src_ty.float_bits(self.target.*);

    const result = result: {
        if (switch (dst_bits) {
            16 => switch (src_bits) {
                32 => !self.has_feature(.f16c),
                64, 80, 128 => true,
                else => unreachable,
            },
            32 => switch (src_bits) {
                64 => false,
                80, 128 => true,
                else => unreachable,
            },
            64 => switch (src_bits) {
                80, 128 => true,
                else => unreachable,
            },
            80 => switch (src_bits) {
                128 => true,
                else => unreachable,
            },
            else => unreachable,
        }) {
            var callee_buf: ["__trunc?f?f2".len]u8 = undefined;
            break :result try self.gen_call(.{ .lib = .{
                .return_type = self.float_compiler_rt_abi_type(dst_ty, src_ty).to_intern(),
                .param_types = &.{self.float_compiler_rt_abi_type(src_ty, dst_ty).to_intern()},
                .callee = std.fmt.buf_print(&callee_buf, "__trunc{c}f{c}f2", .{
                    float_compiler_rt_abi_name(src_bits),
                    float_compiler_rt_abi_name(dst_bits),
                }) catch unreachable,
            } }, &.{src_ty}, &.{.{ .air_ref = ty_op.operand }});
        }

        const src_mcv = try self.resolve_inst(ty_op.operand);
        const dst_mcv = if (src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv
        else
            try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv);
        const dst_reg = dst_mcv.get_reg().?.to128();
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        if (dst_bits == 16) {
            assert(self.has_feature(.f16c));
            switch (src_bits) {
                32 => {
                    const mat_src_reg = if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(src_ty, src_mcv);
                    try self.asm_register_register_immediate(
                        .{ .v_, .cvtps2ph },
                        dst_reg,
                        mat_src_reg.to128(),
                        Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                    );
                },
                else => unreachable,
            }
        } else {
            assert(src_bits == 64 and dst_bits == 32);
            if (self.has_feature(.avx)) if (src_mcv.is_memory()) try self.asm_register_register_memory(
                .{ .v_ss, .cvtsd2 },
                dst_reg,
                dst_reg,
                try src_mcv.mem(self, .qword),
            ) else try self.asm_register_register_register(
                .{ .v_ss, .cvtsd2 },
                dst_reg,
                dst_reg,
                (if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(src_ty, src_mcv)).to128(),
            ) else if (src_mcv.is_memory()) try self.asm_register_memory(
                .{ ._ss, .cvtsd2 },
                dst_reg,
                try src_mcv.mem(self, .qword),
            ) else try self.asm_register_register(
                .{ ._ss, .cvtsd2 },
                dst_reg,
                (if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(src_ty, src_mcv)).to128(),
            );
        }
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_fpext(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const dst_ty = self.type_of_index(inst);
    const dst_scalar_ty = dst_ty.scalar_type(mod);
    const dst_bits = dst_scalar_ty.float_bits(self.target.*);
    const src_ty = self.type_of(ty_op.operand);
    const src_scalar_ty = src_ty.scalar_type(mod);
    const src_bits = src_scalar_ty.float_bits(self.target.*);

    const result = result: {
        if (switch (src_bits) {
            16 => switch (dst_bits) {
                32, 64 => !self.has_feature(.f16c),
                80, 128 => true,
                else => unreachable,
            },
            32 => switch (dst_bits) {
                64 => false,
                80, 128 => true,
                else => unreachable,
            },
            64 => switch (dst_bits) {
                80, 128 => true,
                else => unreachable,
            },
            80 => switch (dst_bits) {
                128 => true,
                else => unreachable,
            },
            else => unreachable,
        }) {
            if (dst_ty.is_vector(mod)) break :result null;
            var callee_buf: ["__extend?f?f2".len]u8 = undefined;
            break :result try self.gen_call(.{ .lib = .{
                .return_type = self.float_compiler_rt_abi_type(dst_scalar_ty, src_scalar_ty).to_intern(),
                .param_types = &.{self.float_compiler_rt_abi_type(src_scalar_ty, dst_scalar_ty).to_intern()},
                .callee = std.fmt.buf_print(&callee_buf, "__extend{c}f{c}f2", .{
                    float_compiler_rt_abi_name(src_bits),
                    float_compiler_rt_abi_name(dst_bits),
                }) catch unreachable,
            } }, &.{src_scalar_ty}, &.{.{ .air_ref = ty_op.operand }});
        }

        const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));
        const src_mcv = try self.resolve_inst(ty_op.operand);
        const dst_mcv = if (src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv
        else
            try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv);
        const dst_reg = dst_mcv.get_reg().?;
        const dst_alias = register_alias(dst_reg, @int_cast(@max(dst_ty.abi_size(mod), 16)));
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const vec_len = if (dst_ty.is_vector(mod)) dst_ty.vector_len(mod) else 1;
        if (src_bits == 16) {
            assert(self.has_feature(.f16c));
            const mat_src_reg = if (src_mcv.is_register())
                src_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(src_ty, src_mcv);
            try self.asm_register_register(
                .{ .v_ps, .cvtph2 },
                dst_alias,
                register_alias(mat_src_reg, src_abi_size),
            );
            switch (dst_bits) {
                32 => {},
                64 => try self.asm_register_register_register(
                    .{ .v_sd, .cvtss2 },
                    dst_alias,
                    dst_alias,
                    dst_alias,
                ),
                else => unreachable,
            }
        } else {
            assert(src_bits == 32 and dst_bits == 64);
            if (self.has_feature(.avx)) switch (vec_len) {
                1 => if (src_mcv.is_memory()) try self.asm_register_register_memory(
                    .{ .v_sd, .cvtss2 },
                    dst_alias,
                    dst_alias,
                    try src_mcv.mem(self, self.mem_size(src_ty)),
                ) else try self.asm_register_register_register(
                    .{ .v_sd, .cvtss2 },
                    dst_alias,
                    dst_alias,
                    register_alias(if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(src_ty, src_mcv), src_abi_size),
                ),
                2...4 => if (src_mcv.is_memory()) try self.asm_register_memory(
                    .{ .v_pd, .cvtps2 },
                    dst_alias,
                    try src_mcv.mem(self, self.mem_size(src_ty)),
                ) else try self.asm_register_register(
                    .{ .v_pd, .cvtps2 },
                    dst_alias,
                    register_alias(if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(src_ty, src_mcv), src_abi_size),
                ),
                else => break :result null,
            } else if (src_mcv.is_memory()) try self.asm_register_memory(
                switch (vec_len) {
                    1 => .{ ._sd, .cvtss2 },
                    2 => .{ ._pd, .cvtps2 },
                    else => break :result null,
                },
                dst_alias,
                try src_mcv.mem(self, self.mem_size(src_ty)),
            ) else try self.asm_register_register(
                switch (vec_len) {
                    1 => .{ ._sd, .cvtss2 },
                    2 => .{ ._pd, .cvtps2 },
                    else => break :result null,
                },
                dst_alias,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(src_ty, src_mcv), src_abi_size),
            );
        }
        break :result dst_mcv;
    } orelse return self.fail("TODO implement air_fpext from {} to {}", .{
        src_ty.fmt(mod), dst_ty.fmt(mod),
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_cast(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const src_ty = self.type_of(ty_op.operand);
    const dst_ty = self.type_of_index(inst);

    const result = @as(?MCValue, result: {
        const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));

        const src_int_info = src_ty.int_info(mod);
        const dst_int_info = dst_ty.int_info(mod);
        const extend = switch (src_int_info.signedness) {
            .signed => dst_int_info,
            .unsigned => src_int_info,
        }.signedness;

        const src_mcv = try self.resolve_inst(ty_op.operand);
        if (dst_ty.is_vector(mod)) {
            const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));
            const max_abi_size = @max(dst_abi_size, src_abi_size);
            if (max_abi_size > @as(u32, if (self.has_feature(.avx2)) 32 else 16)) break :result null;
            const has_avx = self.has_feature(.avx);

            const dst_elem_abi_size = dst_ty.child_type(mod).abi_size(mod);
            const src_elem_abi_size = src_ty.child_type(mod).abi_size(mod);
            switch (math.order(dst_elem_abi_size, src_elem_abi_size)) {
                .lt => {
                    const mir_tag: Mir.Inst.FixedTag = switch (dst_elem_abi_size) {
                        else => break :result null,
                        1 => switch (src_elem_abi_size) {
                            else => break :result null,
                            2 => switch (dst_int_info.signedness) {
                                .signed => if (has_avx) .{ .vp_b, .ackssw } else .{ .p_b, .ackssw },
                                .unsigned => if (has_avx) .{ .vp_b, .ackusw } else .{ .p_b, .ackusw },
                            },
                        },
                        2 => switch (src_elem_abi_size) {
                            else => break :result null,
                            4 => switch (dst_int_info.signedness) {
                                .signed => if (has_avx) .{ .vp_w, .ackssd } else .{ .p_w, .ackssd },
                                .unsigned => if (has_avx)
                                    .{ .vp_w, .ackusd }
                                else if (self.has_feature(.sse4_1))
                                    .{ .p_w, .ackusd }
                                else
                                    break :result null,
                            },
                        },
                    };

                    const dst_mcv: MCValue = if (src_mcv.is_register() and
                        self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                        src_mcv
                    else if (has_avx and src_mcv.is_register())
                        .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
                    else
                        try self.copy_to_register_with_inst_tracking(inst, src_ty, src_mcv);
                    const dst_reg = dst_mcv.get_reg().?;
                    const dst_alias = register_alias(dst_reg, dst_abi_size);

                    if (has_avx) try self.asm_register_register_register(
                        mir_tag,
                        dst_alias,
                        register_alias(if (src_mcv.is_register())
                            src_mcv.get_reg().?
                        else
                            dst_reg, src_abi_size),
                        dst_alias,
                    ) else try self.asm_register_register(
                        mir_tag,
                        dst_alias,
                        dst_alias,
                    );
                    break :result dst_mcv;
                },
                .eq => if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                    break :result src_mcv
                else {
                    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                    try self.gen_copy(dst_ty, dst_mcv, src_mcv, .{});
                    break :result dst_mcv;
                },
                .gt => if (self.has_feature(.sse4_1)) {
                    const mir_tag: Mir.Inst.FixedTag = .{ switch (dst_elem_abi_size) {
                        else => break :result null,
                        2 => if (has_avx) .vp_w else .p_w,
                        4 => if (has_avx) .vp_d else .p_d,
                        8 => if (has_avx) .vp_q else .p_q,
                    }, switch (src_elem_abi_size) {
                        else => break :result null,
                        1 => switch (extend) {
                            .signed => .movsxb,
                            .unsigned => .movzxb,
                        },
                        2 => switch (extend) {
                            .signed => .movsxw,
                            .unsigned => .movzxw,
                        },
                        4 => switch (extend) {
                            .signed => .movsxd,
                            .unsigned => .movzxd,
                        },
                    } };

                    const dst_mcv: MCValue = if (src_mcv.is_register() and
                        self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                        src_mcv
                    else
                        .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) };
                    const dst_reg = dst_mcv.get_reg().?;
                    const dst_alias = register_alias(dst_reg, dst_abi_size);

                    if (src_mcv.is_memory()) try self.asm_register_memory(
                        mir_tag,
                        dst_alias,
                        try src_mcv.mem(self, self.mem_size(src_ty)),
                    ) else try self.asm_register_register(
                        mir_tag,
                        dst_alias,
                        register_alias(if (src_mcv.is_register())
                            src_mcv.get_reg().?
                        else
                            try self.copy_to_tmp_register(src_ty, src_mcv), src_abi_size),
                    );
                    break :result dst_mcv;
                } else {
                    const mir_tag: Mir.Inst.FixedTag = switch (dst_elem_abi_size) {
                        else => break :result null,
                        2 => switch (src_elem_abi_size) {
                            else => break :result null,
                            1 => .{ .p_, .unpcklbw },
                        },
                        4 => switch (src_elem_abi_size) {
                            else => break :result null,
                            2 => .{ .p_, .unpcklwd },
                        },
                        8 => switch (src_elem_abi_size) {
                            else => break :result null,
                            2 => .{ .p_, .unpckldq },
                        },
                    };

                    const dst_mcv: MCValue = if (src_mcv.is_register() and
                        self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                        src_mcv
                    else
                        try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv);
                    const dst_reg = dst_mcv.get_reg().?;

                    const ext_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.sse);
                    const ext_alias = register_alias(ext_reg, src_abi_size);
                    const ext_lock = self.register_manager.lock_reg_assume_unused(ext_reg);
                    defer self.register_manager.unlock_reg(ext_lock);

                    try self.asm_register_register(.{ .p_, .xor }, ext_alias, ext_alias);
                    switch (extend) {
                        .signed => try self.asm_register_register(
                            .{ switch (src_elem_abi_size) {
                                else => unreachable,
                                1 => .p_b,
                                2 => .p_w,
                                4 => .p_d,
                            }, .cmpgt },
                            ext_alias,
                            register_alias(dst_reg, src_abi_size),
                        ),
                        .unsigned => {},
                    }
                    try self.asm_register_register(
                        mir_tag,
                        register_alias(dst_reg, dst_abi_size),
                        register_alias(ext_reg, dst_abi_size),
                    );
                    break :result dst_mcv;
                },
            }
            @compile_error("unreachable");
        }

        const min_ty = if (dst_int_info.bits < src_int_info.bits) dst_ty else src_ty;

        const src_storage_bits: u16 = switch (src_mcv) {
            .register, .register_offset => 64,
            .register_pair => 128,
            .load_frame => |frame_addr| @int_cast(self.get_frame_addr_size(frame_addr) * 8),
            else => src_int_info.bits,
        };

        const dst_mcv = if (dst_int_info.bits <= src_storage_bits and
            math.div_ceil(u16, dst_int_info.bits, 64) catch unreachable ==
            math.div_ceil(u32, src_storage_bits, 64) catch unreachable and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) src_mcv else dst: {
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(min_ty, dst_mcv, src_mcv, .{});
            break :dst dst_mcv;
        };

        if (dst_int_info.bits <= src_int_info.bits) break :result if (dst_mcv.is_register())
            .{ .register = register_alias(dst_mcv.get_reg().?, dst_abi_size) }
        else
            dst_mcv;

        if (dst_mcv.is_register()) {
            try self.truncate_register(src_ty, dst_mcv.get_reg().?);
            break :result .{ .register = register_alias(dst_mcv.get_reg().?, dst_abi_size) };
        }

        const src_limbs_len = math.div_ceil(u16, src_int_info.bits, 64) catch unreachable;
        const dst_limbs_len = math.div_ceil(u16, dst_int_info.bits, 64) catch unreachable;

        const high_mcv: MCValue = if (dst_mcv.is_memory())
            dst_mcv.address().offset((src_limbs_len - 1) * 8).deref()
        else
            .{ .register = dst_mcv.register_pair[1] };
        const high_reg = if (high_mcv.is_register())
            high_mcv.get_reg().?
        else
            try self.copy_to_tmp_register(switch (src_int_info.signedness) {
                .signed => Type.isize,
                .unsigned => Type.usize,
            }, high_mcv);
        const high_lock = self.register_manager.lock_reg_assume_unused(high_reg);
        defer self.register_manager.unlock_reg(high_lock);

        const high_bits = src_int_info.bits % 64;
        if (high_bits > 0) {
            try self.truncate_register(src_ty, high_reg);
            const high_ty = if (dst_int_info.bits >= 64) Type.usize else dst_ty;
            try self.gen_copy(high_ty, high_mcv, .{ .register = high_reg }, .{});
        }

        if (dst_limbs_len > src_limbs_len) try self.gen_inline_memset(
            dst_mcv.address().offset(src_limbs_len * 8),
            switch (extend) {
                .signed => extend: {
                    const extend_mcv = MCValue{ .register = high_reg };
                    try self.gen_shift_bin_op_mir(
                        .{ ._r, .sa },
                        Type.isize,
                        extend_mcv,
                        Type.u8,
                        .{ .immediate = 63 },
                    );
                    break :extend extend_mcv;
                },
                .unsigned => .{ .immediate = 0 },
            },
            .{ .immediate = (dst_limbs_len - src_limbs_len) * 8 },
            .{},
        );

        break :result dst_mcv;
    }) orelse return self.fail("TODO implement air_int_cast from {} to {}", .{
        src_ty.fmt(mod), dst_ty.fmt(mod),
    });
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_trunc(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dst_ty = self.type_of_index(inst);
    const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    const src_ty = self.type_of(ty_op.operand);
    const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));

    const result = result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);
        const src_lock =
            if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg_assume_unused(reg) else null;
        defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_mcv = if (src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv
        else if (dst_abi_size <= 8)
            try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv)
        else if (dst_abi_size <= 16 and !dst_ty.is_vector(mod)) dst: {
            const dst_regs =
                try self.register_manager.alloc_regs(2, .{ inst, inst }, abi.RegisterClass.gp);
            const dst_mcv: MCValue = .{ .register_pair = dst_regs };
            const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
            defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

            try self.gen_copy(dst_ty, dst_mcv, src_mcv, .{});
            break :dst dst_mcv;
        } else dst: {
            const dst_mcv = try self.alloc_reg_or_mem_advanced(src_ty, inst, true);
            try self.gen_copy(src_ty, dst_mcv, src_mcv, .{});
            break :dst dst_mcv;
        };

        if (dst_ty.zig_type_tag(mod) == .Vector) {
            assert(src_ty.zig_type_tag(mod) == .Vector and dst_ty.vector_len(mod) == src_ty.vector_len(mod));
            const dst_elem_ty = dst_ty.child_type(mod);
            const dst_elem_abi_size: u32 = @int_cast(dst_elem_ty.abi_size(mod));
            const src_elem_ty = src_ty.child_type(mod);
            const src_elem_abi_size: u32 = @int_cast(src_elem_ty.abi_size(mod));

            const mir_tag = @as(?Mir.Inst.FixedTag, switch (dst_elem_abi_size) {
                1 => switch (src_elem_abi_size) {
                    2 => switch (dst_ty.vector_len(mod)) {
                        1...8 => if (self.has_feature(.avx)) .{ .vp_b, .ackusw } else .{ .p_b, .ackusw },
                        9...16 => if (self.has_feature(.avx2)) .{ .vp_b, .ackusw } else null,
                        else => null,
                    },
                    else => null,
                },
                2 => switch (src_elem_abi_size) {
                    4 => switch (dst_ty.vector_len(mod)) {
                        1...4 => if (self.has_feature(.avx))
                            .{ .vp_w, .ackusd }
                        else if (self.has_feature(.sse4_1))
                            .{ .p_w, .ackusd }
                        else
                            null,
                        5...8 => if (self.has_feature(.avx2)) .{ .vp_w, .ackusd } else null,
                        else => null,
                    },
                    else => null,
                },
                else => null,
            }) orelse return self.fail("TODO implement air_trunc for {}", .{dst_ty.fmt(mod)});

            const dst_info = dst_elem_ty.int_info(mod);
            const src_info = src_elem_ty.int_info(mod);

            const mask_val = try mod.int_value(src_elem_ty, @as(u64, math.max_int(u64)) >> @int_cast(64 - dst_info.bits));

            const splat_ty = try mod.vector_type(.{
                .len = @int_cast(@div_exact(@as(u64, if (src_abi_size > 16) 256 else 128), src_info.bits)),
                .child = src_elem_ty.ip_index,
            });
            const splat_abi_size: u32 = @int_cast(splat_ty.abi_size(mod));

            const splat_val = try mod.intern(.{ .aggregate = .{
                .ty = splat_ty.ip_index,
                .storage = .{ .repeated_elem = mask_val.ip_index },
            } });

            const splat_mcv = try self.gen_typed_value(Value.from_interned(splat_val));
            const splat_addr_mcv: MCValue = switch (splat_mcv) {
                .memory, .indirect, .load_frame => splat_mcv.address(),
                else => .{ .register = try self.copy_to_tmp_register(Type.usize, splat_mcv.address()) },
            };

            const dst_reg = dst_mcv.get_reg().?;
            const dst_alias = register_alias(dst_reg, src_abi_size);
            if (self.has_feature(.avx)) {
                try self.asm_register_register_memory(
                    .{ .vp_, .@"and" },
                    dst_alias,
                    dst_alias,
                    try splat_addr_mcv.deref().mem(self, Memory.Size.from_size(splat_abi_size)),
                );
                if (src_abi_size > 16) {
                    const temp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.sse);
                    const temp_lock = self.register_manager.lock_reg_assume_unused(temp_reg);
                    defer self.register_manager.unlock_reg(temp_lock);

                    try self.asm_register_register_immediate(
                        .{ if (self.has_feature(.avx2)) .v_i128 else .v_f128, .extract },
                        register_alias(temp_reg, dst_abi_size),
                        dst_alias,
                        Immediate.u(1),
                    );
                    try self.asm_register_register_register(
                        mir_tag,
                        register_alias(dst_reg, dst_abi_size),
                        register_alias(dst_reg, dst_abi_size),
                        register_alias(temp_reg, dst_abi_size),
                    );
                } else try self.asm_register_register_register(mir_tag, dst_alias, dst_alias, dst_alias);
            } else {
                try self.asm_register_memory(
                    .{ .p_, .@"and" },
                    dst_alias,
                    try splat_addr_mcv.deref().mem(self, Memory.Size.from_size(splat_abi_size)),
                );
                try self.asm_register_register(mir_tag, dst_alias, dst_alias);
            }
            break :result dst_mcv;
        }

        // when truncating a `u16` to `u5`, for example, those top 3 bits in the result
        // have to be removed. this only happens if the dst if not a power-of-two size.
        if (dst_abi_size <= 8) {
            if (self.reg_extra_bits(dst_ty) > 0) {
                try self.truncate_register(dst_ty, dst_mcv.register.to64());
            }
        } else if (dst_abi_size <= 16) {
            const dst_info = dst_ty.int_info(mod);
            const high_ty = try mod.int_type(dst_info.signedness, dst_info.bits - 64);
            if (self.reg_extra_bits(high_ty) > 0) {
                try self.truncate_register(high_ty, dst_mcv.register_pair[1].to64());
            }
        }

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_bool(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ty = self.type_of_index(inst);

    const operand = try self.resolve_inst(un_op);
    const dst_mcv = if (self.reuse_operand(inst, un_op, 0, operand))
        operand
    else
        try self.copy_to_register_with_inst_tracking(inst, ty, operand);

    return self.finish_air(inst, dst_mcv, .{ un_op, .none, .none });
}

fn air_slice(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;

    const slice_ty = self.type_of_index(inst);
    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(slice_ty, mod));

    const ptr_ty = self.type_of(bin_op.lhs);
    try self.gen_set_mem(.{ .frame = frame_index }, 0, ptr_ty, .{ .air_ref = bin_op.lhs }, .{});

    const len_ty = self.type_of(bin_op.rhs);
    try self.gen_set_mem(
        .{ .frame = frame_index },
        @int_cast(ptr_ty.abi_size(mod)),
        len_ty,
        .{ .air_ref = bin_op.rhs },
        .{},
    );

    const result = MCValue{ .load_frame = .{ .index = frame_index } };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_un_op(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const dst_mcv = try self.gen_un_op(inst, tag, ty_op.operand);
    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_bin_op(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const dst_mcv = try self.gen_bin_op(inst, tag, bin_op.lhs, bin_op.rhs);

    const dst_ty = self.type_of_index(inst);
    if (dst_ty.is_abi_int(mod)) {
        const abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
        const bit_size: u32 = @int_cast(dst_ty.bit_size(mod));
        if (abi_size * 8 > bit_size) {
            const dst_lock = switch (dst_mcv) {
                .register => |dst_reg| self.register_manager.lock_reg_assume_unused(dst_reg),
                else => null,
            };
            defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

            if (dst_mcv.is_register()) {
                try self.truncate_register(dst_ty, dst_mcv.get_reg().?);
            } else {
                const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                const hi_ty = try mod.int_type(.unsigned, @int_cast((dst_ty.bit_size(mod) - 1) % 64 + 1));
                const hi_mcv = dst_mcv.address().offset(@int_cast(bit_size / 64 * 8)).deref();
                try self.gen_set_reg(tmp_reg, hi_ty, hi_mcv, .{});
                try self.truncate_register(dst_ty, tmp_reg);
                try self.gen_copy(hi_ty, hi_mcv, .{ .register = tmp_reg }, .{});
            }
        }
    }
    return self.finish_air(inst, dst_mcv, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_arithmetic(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const dst_mcv = try self.gen_bin_op(inst, tag, bin_op.lhs, bin_op.rhs);
    return self.finish_air(inst, dst_mcv, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn active_int_bits(self: *Self, dst_air: Air.Inst.Ref) u16 {
    const mod = self.bin_file.comp.module.?;
    const air_tag = self.air.instructions.items(.tag);
    const air_data = self.air.instructions.items(.data);

    const dst_ty = self.type_of(dst_air);
    const dst_info = dst_ty.int_info(mod);
    if (dst_air.to_index()) |inst| {
        switch (air_tag[@int_from_enum(inst)]) {
            .intcast => {
                const src_ty = self.type_of(air_data[@int_from_enum(inst)].ty_op.operand);
                const src_info = src_ty.int_info(mod);
                return @min(switch (src_info.signedness) {
                    .signed => switch (dst_info.signedness) {
                        .signed => src_info.bits,
                        .unsigned => src_info.bits - 1,
                    },
                    .unsigned => switch (dst_info.signedness) {
                        .signed => src_info.bits + 1,
                        .unsigned => src_info.bits,
                    },
                }, dst_info.bits);
            },
            else => {},
        }
    } else if (dst_air.to_interned()) |ip_index| {
        var space: Value.BigIntSpace = undefined;
        const src_int = Value.from_interned(ip_index).to_big_int(&space, mod);
        return @as(u16, @int_cast(src_int.bit_count_twos_comp())) +
            @int_from_bool(src_int.positive and dst_info.signedness == .signed);
    }
    return dst_info.bits;
}

fn air_mul_div_bin_op(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const result = result: {
        const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
        const dst_ty = self.type_of_index(inst);
        switch (dst_ty.zig_type_tag(mod)) {
            .Float, .Vector => break :result try self.gen_bin_op(inst, tag, bin_op.lhs, bin_op.rhs),
            else => {},
        }
        const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));

        const dst_info = dst_ty.int_info(mod);
        const src_ty = try mod.int_type(dst_info.signedness, switch (tag) {
            else => unreachable,
            .mul, .mul_wrap => @max(
                self.active_int_bits(bin_op.lhs),
                self.active_int_bits(bin_op.rhs),
                dst_info.bits / 2,
            ),
            .div_trunc, .div_floor, .div_exact, .rem, .mod => dst_info.bits,
        });
        const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));

        if (dst_abi_size == 16 and src_abi_size == 16) switch (tag) {
            else => unreachable,
            .mul, .mul_wrap => {},
            .div_trunc, .div_floor, .div_exact, .rem, .mod => {
                const signed = dst_ty.is_signed_int(mod);
                var callee_buf: ["__udiv?i3".len]u8 = undefined;
                const signed_div_floor_state: struct {
                    frame_index: FrameIndex,
                    state: State,
                    reloc: Mir.Inst.Index,
                } = if (signed and tag == .div_floor) state: {
                    const frame_index = try self.alloc_frame_index(FrameAlloc.init_type(Type.usize, mod));
                    try self.asm_memory_immediate(
                        .{ ._, .mov },
                        .{ .base = .{ .frame = frame_index }, .mod = .{ .rm = .{ .size = .qword } } },
                        Immediate.u(0),
                    );

                    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                    const mat_lhs_mcv = switch (lhs_mcv) {
                        .load_symbol => mat_lhs_mcv: {
                            // TODO clean this up!
                            const addr_reg = try self.copy_to_tmp_register(Type.usize, lhs_mcv.address());
                            break :mat_lhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                        },
                        else => lhs_mcv,
                    };
                    const mat_lhs_lock = switch (mat_lhs_mcv) {
                        .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                        else => null,
                    };
                    defer if (mat_lhs_lock) |lock| self.register_manager.unlock_reg(lock);
                    if (mat_lhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ ._, .mov },
                        tmp_reg,
                        try mat_lhs_mcv.address().offset(8).deref().mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ ._, .mov },
                        tmp_reg,
                        mat_lhs_mcv.register_pair[1],
                    );

                    const rhs_mcv = try self.resolve_inst(bin_op.rhs);
                    const mat_rhs_mcv = switch (rhs_mcv) {
                        .load_symbol => mat_rhs_mcv: {
                            // TODO clean this up!
                            const addr_reg = try self.copy_to_tmp_register(Type.usize, rhs_mcv.address());
                            break :mat_rhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                        },
                        else => rhs_mcv,
                    };
                    const mat_rhs_lock = switch (mat_rhs_mcv) {
                        .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                        else => null,
                    };
                    defer if (mat_rhs_lock) |lock| self.register_manager.unlock_reg(lock);
                    if (mat_rhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ ._, .xor },
                        tmp_reg,
                        try mat_rhs_mcv.address().offset(8).deref().mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ ._, .xor },
                        tmp_reg,
                        mat_rhs_mcv.register_pair[1],
                    );
                    const state = try self.save_state();
                    const reloc = try self.asm_jcc_reloc(.ns, undefined);

                    break :state .{ .frame_index = frame_index, .state = state, .reloc = reloc };
                } else undefined;
                const call_mcv = try self.gen_call(
                    .{ .lib = .{
                        .return_type = dst_ty.to_intern(),
                        .param_types = &.{ src_ty.to_intern(), src_ty.to_intern() },
                        .callee = std.fmt.buf_print(&callee_buf, "__{s}{s}{c}i3", .{
                            if (signed) "" else "u",
                            switch (tag) {
                                .div_trunc, .div_exact => "div",
                                .div_floor => if (signed) "mod" else "div",
                                .rem, .mod => "mod",
                                else => unreachable,
                            },
                            int_compiler_rt_abi_name(@int_cast(dst_ty.bit_size(mod))),
                        }) catch unreachable,
                    } },
                    &.{ src_ty, src_ty },
                    &.{ .{ .air_ref = bin_op.lhs }, .{ .air_ref = bin_op.rhs } },
                );
                break :result if (signed) switch (tag) {
                    .div_floor => {
                        try self.asm_register_register(
                            .{ ._, .@"or" },
                            call_mcv.register_pair[0],
                            call_mcv.register_pair[1],
                        );
                        try self.asm_setcc_memory(.nz, .{
                            .base = .{ .frame = signed_div_floor_state.frame_index },
                            .mod = .{ .rm = .{ .size = .byte } },
                        });
                        try self.restore_state(signed_div_floor_state.state, &.{}, .{
                            .emit_instructions = true,
                            .update_tracking = true,
                            .resurrect = true,
                            .close_scope = true,
                        });
                        self.perform_reloc(signed_div_floor_state.reloc);
                        const dst_mcv = try self.gen_call(
                            .{ .lib = .{
                                .return_type = dst_ty.to_intern(),
                                .param_types = &.{ src_ty.to_intern(), src_ty.to_intern() },
                                .callee = std.fmt.buf_print(&callee_buf, "__div{c}i3", .{
                                    int_compiler_rt_abi_name(@int_cast(dst_ty.bit_size(mod))),
                                }) catch unreachable,
                            } },
                            &.{ src_ty, src_ty },
                            &.{ .{ .air_ref = bin_op.lhs }, .{ .air_ref = bin_op.rhs } },
                        );
                        try self.asm_register_memory(
                            .{ ._, .sub },
                            dst_mcv.register_pair[0],
                            .{
                                .base = .{ .frame = signed_div_floor_state.frame_index },
                                .mod = .{ .rm = .{ .size = .qword } },
                            },
                        );
                        try self.asm_register_immediate(
                            .{ ._, .sbb },
                            dst_mcv.register_pair[1],
                            Immediate.u(0),
                        );
                        try self.free_value(
                            .{ .load_frame = .{ .index = signed_div_floor_state.frame_index } },
                        );
                        break :result dst_mcv;
                    },
                    .mod => {
                        const dst_regs = call_mcv.register_pair;
                        const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
                        defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

                        const tmp_regs =
                            try self.register_manager.alloc_regs(2, .{null} ** 2, abi.RegisterClass.gp);
                        const tmp_locks = self.register_manager.lock_regs_assume_unused(2, tmp_regs);
                        defer for (tmp_locks) |lock| self.register_manager.unlock_reg(lock);

                        const rhs_mcv = try self.resolve_inst(bin_op.rhs);
                        const mat_rhs_mcv = switch (rhs_mcv) {
                            .load_symbol => mat_rhs_mcv: {
                                // TODO clean this up!
                                const addr_reg = try self.copy_to_tmp_register(Type.usize, rhs_mcv.address());
                                break :mat_rhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                            },
                            else => rhs_mcv,
                        };
                        const mat_rhs_lock = switch (mat_rhs_mcv) {
                            .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                            else => null,
                        };
                        defer if (mat_rhs_lock) |lock| self.register_manager.unlock_reg(lock);

                        for (tmp_regs, dst_regs) |tmp_reg, dst_reg|
                            try self.asm_register_register(.{ ._, .mov }, tmp_reg, dst_reg);
                        if (mat_rhs_mcv.is_memory()) {
                            try self.asm_register_memory(
                                .{ ._, .add },
                                tmp_regs[0],
                                try mat_rhs_mcv.mem(self, .qword),
                            );
                            try self.asm_register_memory(
                                .{ ._, .adc },
                                tmp_regs[1],
                                try mat_rhs_mcv.address().offset(8).deref().mem(self, .qword),
                            );
                        } else for (
                            [_]Mir.Inst.Tag{ .add, .adc },
                            tmp_regs,
                            mat_rhs_mcv.register_pair,
                        ) |op, tmp_reg, rhs_reg|
                            try self.asm_register_register(.{ ._, op }, tmp_reg, rhs_reg);
                        try self.asm_register_register(.{ ._, .@"test" }, dst_regs[1], dst_regs[1]);
                        for (dst_regs, tmp_regs) |dst_reg, tmp_reg|
                            try self.asm_cmovcc_register_register(.s, dst_reg, tmp_reg);
                        break :result call_mcv;
                    },
                    else => call_mcv,
                } else call_mcv;
            },
        };

        try self.spill_eflags_if_occupied();
        try self.spill_registers(&.{ .rax, .rcx, .rdx });
        const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rax, .rcx, .rdx });
        defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

        const lhs_mcv = try self.resolve_inst(bin_op.lhs);
        const rhs_mcv = try self.resolve_inst(bin_op.rhs);
        break :result try self.gen_mul_div_bin_op(tag, inst, dst_ty, src_ty, lhs_mcv, rhs_mcv);
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_sat(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ty = self.type_of(bin_op.lhs);
    if (ty.zig_type_tag(mod) == .Vector or ty.abi_size(mod) > 8) return self.fail(
        "TODO implement air_add_sat for {}",
        .{ty.fmt(mod)},
    );

    const lhs_mcv = try self.resolve_inst(bin_op.lhs);
    const dst_mcv = if (lhs_mcv.is_register() and self.reuse_operand(inst, bin_op.lhs, 0, lhs_mcv))
        lhs_mcv
    else
        try self.copy_to_register_with_inst_tracking(inst, ty, lhs_mcv);
    const dst_reg = dst_mcv.register;
    const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
    defer self.register_manager.unlock_reg(dst_lock);

    const rhs_mcv = try self.resolve_inst(bin_op.rhs);
    const rhs_lock = switch (rhs_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const limit_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const limit_mcv = MCValue{ .register = limit_reg };
    const limit_lock = self.register_manager.lock_reg_assume_unused(limit_reg);
    defer self.register_manager.unlock_reg(limit_lock);

    const reg_bits = self.reg_bit_size(ty);
    const reg_extra_bits = self.reg_extra_bits(ty);
    const cc: Condition = if (ty.is_signed_int(mod)) cc: {
        if (reg_extra_bits > 0) {
            try self.gen_shift_bin_op_mir(
                .{ ._l, .sa },
                ty,
                dst_mcv,
                Type.u8,
                .{ .immediate = reg_extra_bits },
            );
        }
        try self.gen_set_reg(limit_reg, ty, dst_mcv, .{});
        try self.gen_shift_bin_op_mir(
            .{ ._r, .sa },
            ty,
            limit_mcv,
            Type.u8,
            .{ .immediate = reg_bits - 1 },
        );
        try self.gen_bin_op_mir(.{ ._, .xor }, ty, limit_mcv, .{
            .immediate = (@as(u64, 1) << @int_cast(reg_bits - 1)) - 1,
        });
        if (reg_extra_bits > 0) {
            const shifted_rhs_reg = try self.copy_to_tmp_register(ty, rhs_mcv);
            const shifted_rhs_mcv = MCValue{ .register = shifted_rhs_reg };
            const shifted_rhs_lock = self.register_manager.lock_reg_assume_unused(shifted_rhs_reg);
            defer self.register_manager.unlock_reg(shifted_rhs_lock);

            try self.gen_shift_bin_op_mir(
                .{ ._l, .sa },
                ty,
                shifted_rhs_mcv,
                Type.u8,
                .{ .immediate = reg_extra_bits },
            );
            try self.gen_bin_op_mir(.{ ._, .add }, ty, dst_mcv, shifted_rhs_mcv);
        } else try self.gen_bin_op_mir(.{ ._, .add }, ty, dst_mcv, rhs_mcv);
        break :cc .o;
    } else cc: {
        try self.gen_set_reg(limit_reg, ty, .{
            .immediate = @as(u64, math.max_int(u64)) >> @int_cast(64 - ty.bit_size(mod)),
        }, .{});

        try self.gen_bin_op_mir(.{ ._, .add }, ty, dst_mcv, rhs_mcv);
        if (reg_extra_bits > 0) {
            try self.gen_bin_op_mir(.{ ._, .cmp }, ty, dst_mcv, limit_mcv);
            break :cc .a;
        }
        break :cc .c;
    };

    const cmov_abi_size = @max(@as(u32, @int_cast(ty.abi_size(mod))), 2);
    try self.asm_cmovcc_register_register(
        cc,
        register_alias(dst_reg, cmov_abi_size),
        register_alias(limit_reg, cmov_abi_size),
    );

    if (reg_extra_bits > 0 and ty.is_signed_int(mod)) try self.gen_shift_bin_op_mir(
        .{ ._r, .sa },
        ty,
        dst_mcv,
        Type.u8,
        .{ .immediate = reg_extra_bits },
    );

    return self.finish_air(inst, dst_mcv, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_sub_sat(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ty = self.type_of(bin_op.lhs);
    if (ty.zig_type_tag(mod) == .Vector or ty.abi_size(mod) > 8) return self.fail(
        "TODO implement air_sub_sat for {}",
        .{ty.fmt(mod)},
    );

    const lhs_mcv = try self.resolve_inst(bin_op.lhs);
    const dst_mcv = if (lhs_mcv.is_register() and self.reuse_operand(inst, bin_op.lhs, 0, lhs_mcv))
        lhs_mcv
    else
        try self.copy_to_register_with_inst_tracking(inst, ty, lhs_mcv);
    const dst_reg = dst_mcv.register;
    const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
    defer self.register_manager.unlock_reg(dst_lock);

    const rhs_mcv = try self.resolve_inst(bin_op.rhs);
    const rhs_lock = switch (rhs_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const limit_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const limit_mcv = MCValue{ .register = limit_reg };
    const limit_lock = self.register_manager.lock_reg_assume_unused(limit_reg);
    defer self.register_manager.unlock_reg(limit_lock);

    const reg_bits = self.reg_bit_size(ty);
    const reg_extra_bits = self.reg_extra_bits(ty);
    const cc: Condition = if (ty.is_signed_int(mod)) cc: {
        if (reg_extra_bits > 0) {
            try self.gen_shift_bin_op_mir(
                .{ ._l, .sa },
                ty,
                dst_mcv,
                Type.u8,
                .{ .immediate = reg_extra_bits },
            );
        }
        try self.gen_set_reg(limit_reg, ty, dst_mcv, .{});
        try self.gen_shift_bin_op_mir(
            .{ ._r, .sa },
            ty,
            limit_mcv,
            Type.u8,
            .{ .immediate = reg_bits - 1 },
        );
        try self.gen_bin_op_mir(.{ ._, .xor }, ty, limit_mcv, .{
            .immediate = (@as(u64, 1) << @int_cast(reg_bits - 1)) - 1,
        });
        if (reg_extra_bits > 0) {
            const shifted_rhs_reg = try self.copy_to_tmp_register(ty, rhs_mcv);
            const shifted_rhs_mcv = MCValue{ .register = shifted_rhs_reg };
            const shifted_rhs_lock = self.register_manager.lock_reg_assume_unused(shifted_rhs_reg);
            defer self.register_manager.unlock_reg(shifted_rhs_lock);

            try self.gen_shift_bin_op_mir(
                .{ ._l, .sa },
                ty,
                shifted_rhs_mcv,
                Type.u8,
                .{ .immediate = reg_extra_bits },
            );
            try self.gen_bin_op_mir(.{ ._, .sub }, ty, dst_mcv, shifted_rhs_mcv);
        } else try self.gen_bin_op_mir(.{ ._, .sub }, ty, dst_mcv, rhs_mcv);
        break :cc .o;
    } else cc: {
        try self.gen_set_reg(limit_reg, ty, .{ .immediate = 0 }, .{});
        try self.gen_bin_op_mir(.{ ._, .sub }, ty, dst_mcv, rhs_mcv);
        break :cc .c;
    };

    const cmov_abi_size = @max(@as(u32, @int_cast(ty.abi_size(mod))), 2);
    try self.asm_cmovcc_register_register(
        cc,
        register_alias(dst_reg, cmov_abi_size),
        register_alias(limit_reg, cmov_abi_size),
    );

    if (reg_extra_bits > 0 and ty.is_signed_int(mod)) try self.gen_shift_bin_op_mir(
        .{ ._r, .sa },
        ty,
        dst_mcv,
        Type.u8,
        .{ .immediate = reg_extra_bits },
    );

    return self.finish_air(inst, dst_mcv, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_mul_sat(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ty = self.type_of(bin_op.lhs);

    const result = result: {
        if (ty.to_intern() == .i128_type) {
            const ptr_c_int = try mod.single_mut_ptr_type(Type.c_int);
            const overflow = try self.alloc_temp_reg_or_mem(Type.c_int, false);

            const dst_mcv = try self.gen_call(.{ .lib = .{
                .return_type = .i128_type,
                .param_types = &.{ .i128_type, .i128_type, ptr_c_int.to_intern() },
                .callee = "__muloti4",
            } }, &.{ Type.i128, Type.i128, ptr_c_int }, &.{
                .{ .air_ref = bin_op.lhs },
                .{ .air_ref = bin_op.rhs },
                overflow.address(),
            });
            const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_mcv.register_pair);
            defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

            const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
            defer self.register_manager.unlock_reg(tmp_lock);

            const lhs_mcv = try self.resolve_inst(bin_op.lhs);
            const mat_lhs_mcv = switch (lhs_mcv) {
                .load_symbol => mat_lhs_mcv: {
                    // TODO clean this up!
                    const addr_reg = try self.copy_to_tmp_register(Type.usize, lhs_mcv.address());
                    break :mat_lhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                },
                else => lhs_mcv,
            };
            const mat_lhs_lock = switch (mat_lhs_mcv) {
                .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                else => null,
            };
            defer if (mat_lhs_lock) |lock| self.register_manager.unlock_reg(lock);
            if (mat_lhs_mcv.is_memory()) try self.asm_register_memory(
                .{ ._, .mov },
                tmp_reg,
                try mat_lhs_mcv.address().offset(8).deref().mem(self, .qword),
            ) else try self.asm_register_register(
                .{ ._, .mov },
                tmp_reg,
                mat_lhs_mcv.register_pair[1],
            );

            const rhs_mcv = try self.resolve_inst(bin_op.rhs);
            const mat_rhs_mcv = switch (rhs_mcv) {
                .load_symbol => mat_rhs_mcv: {
                    // TODO clean this up!
                    const addr_reg = try self.copy_to_tmp_register(Type.usize, rhs_mcv.address());
                    break :mat_rhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                },
                else => rhs_mcv,
            };
            const mat_rhs_lock = switch (mat_rhs_mcv) {
                .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                else => null,
            };
            defer if (mat_rhs_lock) |lock| self.register_manager.unlock_reg(lock);
            if (mat_rhs_mcv.is_memory()) try self.asm_register_memory(
                .{ ._, .xor },
                tmp_reg,
                try mat_rhs_mcv.address().offset(8).deref().mem(self, .qword),
            ) else try self.asm_register_register(
                .{ ._, .xor },
                tmp_reg,
                mat_rhs_mcv.register_pair[1],
            );

            try self.asm_register_immediate(.{ ._r, .sa }, tmp_reg, Immediate.u(63));
            try self.asm_register(.{ ._, .not }, tmp_reg);
            try self.asm_memory_immediate(.{ ._, .cmp }, try overflow.mem(self, .dword), Immediate.s(0));
            try self.free_value(overflow);
            try self.asm_cmovcc_register_register(.ne, dst_mcv.register_pair[0], tmp_reg);
            try self.asm_register_immediate(.{ ._c, .bt }, tmp_reg, Immediate.u(63));
            try self.asm_cmovcc_register_register(.ne, dst_mcv.register_pair[1], tmp_reg);
            break :result dst_mcv;
        }

        if (ty.zig_type_tag(mod) == .Vector or ty.abi_size(mod) > 8) return self.fail(
            "TODO implement air_mul_sat for {}",
            .{ty.fmt(mod)},
        );

        try self.spill_registers(&.{ .rax, .rcx, .rdx });
        const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rax, .rcx, .rdx });
        defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

        const lhs_mcv = try self.resolve_inst(bin_op.lhs);
        const lhs_lock = switch (lhs_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const rhs_mcv = try self.resolve_inst(bin_op.rhs);
        const rhs_lock = switch (rhs_mcv) {
            .register => |reg| self.register_manager.lock_reg(reg),
            else => null,
        };
        defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const limit_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
        const limit_mcv = MCValue{ .register = limit_reg };
        const limit_lock = self.register_manager.lock_reg_assume_unused(limit_reg);
        defer self.register_manager.unlock_reg(limit_lock);

        const reg_bits = self.reg_bit_size(ty);
        const cc: Condition = if (ty.is_signed_int(mod)) cc: {
            try self.gen_set_reg(limit_reg, ty, lhs_mcv, .{});
            try self.gen_bin_op_mir(.{ ._, .xor }, ty, limit_mcv, rhs_mcv);
            try self.gen_shift_bin_op_mir(
                .{ ._r, .sa },
                ty,
                limit_mcv,
                Type.u8,
                .{ .immediate = reg_bits - 1 },
            );
            try self.gen_bin_op_mir(.{ ._, .xor }, ty, limit_mcv, .{
                .immediate = (@as(u64, 1) << @int_cast(reg_bits - 1)) - 1,
            });
            break :cc .o;
        } else cc: {
            try self.gen_set_reg(limit_reg, ty, .{
                .immediate = @as(u64, math.max_int(u64)) >> @int_cast(64 - reg_bits),
            }, .{});
            break :cc .c;
        };

        const dst_mcv = try self.gen_mul_div_bin_op(.mul, inst, ty, ty, lhs_mcv, rhs_mcv);
        const cmov_abi_size = @max(@as(u32, @int_cast(ty.abi_size(mod))), 2);
        try self.asm_cmovcc_register_register(
            cc,
            register_alias(dst_mcv.register, cmov_abi_size),
            register_alias(limit_reg, cmov_abi_size),
        );
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_add_sub_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = result: {
        const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];
        const ty = self.type_of(bin_op.lhs);
        switch (ty.zig_type_tag(mod)) {
            .Vector => return self.fail("TODO implement add/sub with overflow for Vector type", .{}),
            .Int => {
                try self.spill_eflags_if_occupied();
                try self.spill_registers(&.{ .rcx, .rdi, .rsi });
                const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rcx, .rdi, .rsi });
                defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

                const partial_mcv = try self.gen_bin_op(null, switch (tag) {
                    .add_with_overflow => .add,
                    .sub_with_overflow => .sub,
                    else => unreachable,
                }, bin_op.lhs, bin_op.rhs);
                const int_info = ty.int_info(mod);
                const cc: Condition = switch (int_info.signedness) {
                    .unsigned => .c,
                    .signed => .o,
                };

                const tuple_ty = self.type_of_index(inst);
                if (int_info.bits >= 8 and math.is_power_of_two(int_info.bits)) {
                    switch (partial_mcv) {
                        .register => |reg| {
                            self.eflags_inst = inst;
                            break :result .{ .register_overflow = .{ .reg = reg, .eflags = cc } };
                        },
                        else => {},
                    }

                    const frame_index =
                        try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                    try self.gen_set_mem(
                        .{ .frame = frame_index },
                        @int_cast(tuple_ty.struct_field_offset(1, mod)),
                        Type.u1,
                        .{ .eflags = cc },
                        .{},
                    );
                    try self.gen_set_mem(
                        .{ .frame = frame_index },
                        @int_cast(tuple_ty.struct_field_offset(0, mod)),
                        ty,
                        partial_mcv,
                        .{},
                    );
                    break :result .{ .load_frame = .{ .index = frame_index } };
                }

                const frame_index =
                    try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                try self.gen_set_frame_truncated_overflow_compare(tuple_ty, frame_index, partial_mcv, cc);
                break :result .{ .load_frame = .{ .index = frame_index } };
            },
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_shl_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const result: MCValue = result: {
        const lhs_ty = self.type_of(bin_op.lhs);
        const rhs_ty = self.type_of(bin_op.rhs);
        switch (lhs_ty.zig_type_tag(mod)) {
            .Vector => return self.fail("TODO implement shl with overflow for Vector type", .{}),
            .Int => {
                try self.spill_eflags_if_occupied();
                try self.spill_registers(&.{ .rcx, .rdi, .rsi });
                const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rcx, .rdi, .rsi });
                defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

                const lhs = try self.resolve_inst(bin_op.lhs);
                const rhs = try self.resolve_inst(bin_op.rhs);

                const int_info = lhs_ty.int_info(mod);

                const partial_mcv = try self.gen_shift_bin_op(.shl, null, lhs, rhs, lhs_ty, rhs_ty);
                const partial_lock = switch (partial_mcv) {
                    .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                    else => null,
                };
                defer if (partial_lock) |lock| self.register_manager.unlock_reg(lock);

                const tmp_mcv = try self.gen_shift_bin_op(.shr, null, partial_mcv, rhs, lhs_ty, rhs_ty);
                const tmp_lock = switch (tmp_mcv) {
                    .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                    else => null,
                };
                defer if (tmp_lock) |lock| self.register_manager.unlock_reg(lock);

                try self.gen_bin_op_mir(.{ ._, .cmp }, lhs_ty, tmp_mcv, lhs);
                const cc = Condition.ne;

                const tuple_ty = self.type_of_index(inst);
                if (int_info.bits >= 8 and math.is_power_of_two(int_info.bits)) {
                    switch (partial_mcv) {
                        .register => |reg| {
                            self.eflags_inst = inst;
                            break :result .{ .register_overflow = .{ .reg = reg, .eflags = cc } };
                        },
                        else => {},
                    }

                    const frame_index =
                        try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                    try self.gen_set_mem(
                        .{ .frame = frame_index },
                        @int_cast(tuple_ty.struct_field_offset(1, mod)),
                        tuple_ty.struct_field_type(1, mod),
                        .{ .eflags = cc },
                        .{},
                    );
                    try self.gen_set_mem(
                        .{ .frame = frame_index },
                        @int_cast(tuple_ty.struct_field_offset(0, mod)),
                        tuple_ty.struct_field_type(0, mod),
                        partial_mcv,
                        .{},
                    );
                    break :result .{ .load_frame = .{ .index = frame_index } };
                }

                const frame_index =
                    try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                try self.gen_set_frame_truncated_overflow_compare(tuple_ty, frame_index, partial_mcv, cc);
                break :result .{ .load_frame = .{ .index = frame_index } };
            },
            else => unreachable,
        }
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn gen_set_frame_truncated_overflow_compare(
    self: *Self,
    tuple_ty: Type,
    frame_index: FrameIndex,
    src_mcv: MCValue,
    overflow_cc: ?Condition,
) !void {
    const mod = self.bin_file.comp.module.?;
    const src_lock = switch (src_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

    const ty = tuple_ty.struct_field_type(0, mod);
    const int_info = ty.int_info(mod);

    const hi_bits = (int_info.bits - 1) % 64 + 1;
    const hi_ty = try mod.int_type(int_info.signedness, hi_bits);

    const limb_bits: u16 = @int_cast(if (int_info.bits <= 64) self.reg_bit_size(ty) else 64);
    const limb_ty = try mod.int_type(int_info.signedness, limb_bits);

    const rest_ty = try mod.int_type(.unsigned, int_info.bits - hi_bits);

    const temp_regs =
        try self.register_manager.alloc_regs(3, .{null} ** 3, abi.RegisterClass.gp);
    const temp_locks = self.register_manager.lock_regs_assume_unused(3, temp_regs);
    defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

    const overflow_reg = temp_regs[0];
    if (overflow_cc) |cc| try self.asm_setcc_register(cc, overflow_reg.to8());

    const scratch_reg = temp_regs[1];
    const hi_limb_off = if (int_info.bits <= 64) 0 else (int_info.bits - 1) / 64 * 8;
    const hi_limb_mcv = if (hi_limb_off > 0)
        src_mcv.address().offset(int_info.bits / 64 * 8).deref()
    else
        src_mcv;
    try self.gen_set_reg(scratch_reg, limb_ty, hi_limb_mcv, .{});
    try self.truncate_register(hi_ty, scratch_reg);
    try self.gen_bin_op_mir(.{ ._, .cmp }, limb_ty, .{ .register = scratch_reg }, hi_limb_mcv);

    const eq_reg = temp_regs[2];
    if (overflow_cc) |_| {
        try self.asm_setcc_register(.ne, eq_reg.to8());
        try self.gen_bin_op_mir(
            .{ ._, .@"or" },
            Type.u8,
            .{ .register = overflow_reg },
            .{ .register = eq_reg },
        );
    }

    const payload_off: i32 = @int_cast(tuple_ty.struct_field_offset(0, mod));
    if (hi_limb_off > 0) try self.gen_set_mem(
        .{ .frame = frame_index },
        payload_off,
        rest_ty,
        src_mcv,
        .{},
    );
    try self.gen_set_mem(
        .{ .frame = frame_index },
        payload_off + hi_limb_off,
        limb_ty,
        .{ .register = scratch_reg },
        .{},
    );
    try self.gen_set_mem(
        .{ .frame = frame_index },
        @int_cast(tuple_ty.struct_field_offset(1, mod)),
        tuple_ty.struct_field_type(1, mod),
        if (overflow_cc) |_| .{ .register = overflow_reg.to8() } else .{ .eflags = .ne },
        .{},
    );
}

fn air_mul_with_overflow(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const bin_op = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const tuple_ty = self.type_of_index(inst);
    const dst_ty = self.type_of(bin_op.lhs);
    const result: MCValue = switch (dst_ty.zig_type_tag(mod)) {
        .Vector => return self.fail("TODO implement air_mul_with_overflow for {}", .{dst_ty.fmt(mod)}),
        .Int => result: {
            const dst_info = dst_ty.int_info(mod);
            if (dst_info.bits > 128 and dst_info.signedness == .unsigned) {
                const slow_inc = self.has_feature(.slow_incdec);
                const abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
                const limb_len = math.div_ceil(u32, abi_size, 8) catch unreachable;

                try self.spill_registers(&.{ .rax, .rcx, .rdx });
                const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rax, .rcx, .rdx });
                defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

                const dst_mcv = try self.alloc_reg_or_mem(inst, false);
                try self.gen_inline_memset(
                    dst_mcv.address(),
                    .{ .immediate = 0 },
                    .{ .immediate = tuple_ty.abi_size(mod) },
                    .{},
                );
                const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                const rhs_mcv = try self.resolve_inst(bin_op.rhs);

                const temp_regs =
                    try self.register_manager.alloc_regs(4, .{null} ** 4, abi.RegisterClass.gp);
                const temp_locks = self.register_manager.lock_regs_assume_unused(4, temp_regs);
                defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

                try self.asm_register_register(.{ ._, .xor }, temp_regs[0].to32(), temp_regs[0].to32());

                const outer_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_register_memory(.{ ._, .mov }, temp_regs[1].to64(), .{
                    .base = .{ .frame = rhs_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[0].to64(),
                        .scale = .@"8",
                        .disp = rhs_mcv.load_frame.off,
                    } },
                });
                try self.asm_register_register(.{ ._, .@"test" }, temp_regs[1].to64(), temp_regs[1].to64());
                const skip_inner = try self.asm_jcc_reloc(.z, undefined);

                try self.asm_register_register(.{ ._, .xor }, temp_regs[2].to32(), temp_regs[2].to32());
                try self.asm_register_register(.{ ._, .mov }, temp_regs[3].to32(), temp_regs[0].to32());
                try self.asm_register_register(.{ ._, .xor }, .ecx, .ecx);
                try self.asm_register_register(.{ ._, .xor }, .edx, .edx);

                const inner_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_register_immediate(.{ ._r, .sh }, .cl, Immediate.u(1));
                try self.asm_memory_register(.{ ._, .adc }, .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[3].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off +
                            @as(i32, @int_cast(tuple_ty.struct_field_offset(0, mod))),
                    } },
                }, .rdx);
                try self.asm_setcc_register(.c, .cl);

                try self.asm_register_memory(.{ ._, .mov }, .rax, .{
                    .base = .{ .frame = lhs_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[2].to64(),
                        .scale = .@"8",
                        .disp = lhs_mcv.load_frame.off,
                    } },
                });
                try self.asm_register(.{ ._, .mul }, temp_regs[1].to64());

                try self.asm_register_immediate(.{ ._r, .sh }, .ch, Immediate.u(1));
                try self.asm_memory_register(.{ ._, .adc }, .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[3].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off +
                            @as(i32, @int_cast(tuple_ty.struct_field_offset(0, mod))),
                    } },
                }, .rax);
                try self.asm_setcc_register(.c, .ch);

                if (slow_inc) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[2].to32(), Immediate.u(1));
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[3].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[2].to32());
                    try self.asm_register(.{ ._, .inc }, temp_regs[3].to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    temp_regs[3].to32(),
                    Immediate.u(limb_len),
                );
                _ = try self.asm_jcc_reloc(.b, inner_loop);

                try self.asm_register_register(.{ ._, .@"or" }, .rdx, .rcx);
                const overflow = try self.asm_jcc_reloc(.nz, undefined);
                const overflow_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    temp_regs[2].to32(),
                    Immediate.u(limb_len),
                );
                const no_overflow = try self.asm_jcc_reloc(.nb, undefined);
                if (slow_inc) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[2].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[2].to32());
                }
                try self.asm_memory_immediate(.{ ._, .cmp }, .{
                    .base = .{ .frame = lhs_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[2].to64(),
                        .scale = .@"8",
                        .disp = lhs_mcv.load_frame.off - 8,
                    } },
                }, Immediate.u(0));
                _ = try self.asm_jcc_reloc(.z, overflow_loop);
                self.perform_reloc(overflow);
                try self.asm_memory_immediate(.{ ._, .mov }, .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .byte,
                        .disp = dst_mcv.load_frame.off +
                            @as(i32, @int_cast(tuple_ty.struct_field_offset(1, mod))),
                    } },
                }, Immediate.u(1));
                self.perform_reloc(no_overflow);

                self.perform_reloc(skip_inner);
                if (slow_inc) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[0].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[0].to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    temp_regs[0].to32(),
                    Immediate.u(limb_len),
                );
                _ = try self.asm_jcc_reloc(.b, outer_loop);

                break :result dst_mcv;
            }

            const lhs_active_bits = self.active_int_bits(bin_op.lhs);
            const rhs_active_bits = self.active_int_bits(bin_op.rhs);
            const src_bits = @max(lhs_active_bits, rhs_active_bits, dst_info.bits / 2);
            const src_ty = try mod.int_type(dst_info.signedness, src_bits);
            if (src_bits > 64 and src_bits <= 128 and
                dst_info.bits > 64 and dst_info.bits <= 128) switch (dst_info.signedness) {
                .signed => {
                    const ptr_c_int = try mod.single_mut_ptr_type(Type.c_int);
                    const overflow = try self.alloc_temp_reg_or_mem(Type.c_int, false);
                    const result = try self.gen_call(.{ .lib = .{
                        .return_type = .i128_type,
                        .param_types = &.{ .i128_type, .i128_type, ptr_c_int.to_intern() },
                        .callee = "__muloti4",
                    } }, &.{ Type.i128, Type.i128, ptr_c_int }, &.{
                        .{ .air_ref = bin_op.lhs },
                        .{ .air_ref = bin_op.rhs },
                        overflow.address(),
                    });

                    const dst_mcv = try self.alloc_reg_or_mem(inst, false);
                    try self.gen_set_mem(
                        .{ .frame = dst_mcv.load_frame.index },
                        @int_cast(tuple_ty.struct_field_offset(0, mod)),
                        tuple_ty.struct_field_type(0, mod),
                        result,
                        .{},
                    );
                    try self.asm_memory_immediate(
                        .{ ._, .cmp },
                        try overflow.mem(self, self.mem_size(Type.c_int)),
                        Immediate.s(0),
                    );
                    try self.gen_set_mem(
                        .{ .frame = dst_mcv.load_frame.index },
                        @int_cast(tuple_ty.struct_field_offset(1, mod)),
                        tuple_ty.struct_field_type(1, mod),
                        .{ .eflags = .ne },
                        .{},
                    );
                    try self.free_value(overflow);
                    break :result dst_mcv;
                },
                .unsigned => {
                    try self.spill_eflags_if_occupied();
                    try self.spill_registers(&.{ .rax, .rdx });
                    const reg_locks = self.register_manager.lock_regs_assume_unused(2, .{ .rax, .rdx });
                    defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

                    const tmp_regs =
                        try self.register_manager.alloc_regs(4, .{null} ** 4, abi.RegisterClass.gp);
                    const tmp_locks = self.register_manager.lock_regs_assume_unused(4, tmp_regs);
                    defer for (tmp_locks) |lock| self.register_manager.unlock_reg(lock);

                    const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                    const rhs_mcv = try self.resolve_inst(bin_op.rhs);
                    const mat_lhs_mcv = switch (lhs_mcv) {
                        .load_symbol => mat_lhs_mcv: {
                            // TODO clean this up!
                            const addr_reg = try self.copy_to_tmp_register(Type.usize, lhs_mcv.address());
                            break :mat_lhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                        },
                        else => lhs_mcv,
                    };
                    const mat_lhs_lock = switch (mat_lhs_mcv) {
                        .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                        else => null,
                    };
                    defer if (mat_lhs_lock) |lock| self.register_manager.unlock_reg(lock);
                    const mat_rhs_mcv = switch (rhs_mcv) {
                        .load_symbol => mat_rhs_mcv: {
                            // TODO clean this up!
                            const addr_reg = try self.copy_to_tmp_register(Type.usize, rhs_mcv.address());
                            break :mat_rhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
                        },
                        else => rhs_mcv,
                    };
                    const mat_rhs_lock = switch (mat_rhs_mcv) {
                        .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
                        else => null,
                    };
                    defer if (mat_rhs_lock) |lock| self.register_manager.unlock_reg(lock);

                    if (mat_lhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ ._, .mov },
                        .rax,
                        try mat_lhs_mcv.mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ ._, .mov },
                        .rax,
                        mat_lhs_mcv.register_pair[0],
                    );
                    if (mat_rhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ ._, .mov },
                        tmp_regs[0],
                        try mat_rhs_mcv.address().offset(8).deref().mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ ._, .mov },
                        tmp_regs[0],
                        mat_rhs_mcv.register_pair[1],
                    );
                    try self.asm_register_register(.{ ._, .@"test" }, tmp_regs[0], tmp_regs[0]);
                    try self.asm_setcc_register(.nz, tmp_regs[1].to8());
                    try self.asm_register_register(.{ .i_, .mul }, tmp_regs[0], .rax);
                    try self.asm_setcc_register(.o, tmp_regs[2].to8());
                    if (mat_rhs_mcv.is_memory())
                        try self.asm_memory(.{ ._, .mul }, try mat_rhs_mcv.mem(self, .qword))
                    else
                        try self.asm_register(.{ ._, .mul }, mat_rhs_mcv.register_pair[0]);
                    try self.asm_register_register(.{ ._, .add }, .rdx, tmp_regs[0]);
                    try self.asm_setcc_register(.c, tmp_regs[3].to8());
                    try self.asm_register_register(.{ ._, .@"or" }, tmp_regs[2].to8(), tmp_regs[3].to8());
                    if (mat_lhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ ._, .mov },
                        tmp_regs[0],
                        try mat_lhs_mcv.address().offset(8).deref().mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ ._, .mov },
                        tmp_regs[0],
                        mat_lhs_mcv.register_pair[1],
                    );
                    try self.asm_register_register(.{ ._, .@"test" }, tmp_regs[0], tmp_regs[0]);
                    try self.asm_setcc_register(.nz, tmp_regs[3].to8());
                    try self.asm_register_register(
                        .{ ._, .@"and" },
                        tmp_regs[1].to8(),
                        tmp_regs[3].to8(),
                    );
                    try self.asm_register_register(.{ ._, .@"or" }, tmp_regs[1].to8(), tmp_regs[2].to8());
                    if (mat_rhs_mcv.is_memory()) try self.asm_register_memory(
                        .{ .i_, .mul },
                        tmp_regs[0],
                        try mat_rhs_mcv.mem(self, .qword),
                    ) else try self.asm_register_register(
                        .{ .i_, .mul },
                        tmp_regs[0],
                        mat_rhs_mcv.register_pair[0],
                    );
                    try self.asm_setcc_register(.o, tmp_regs[2].to8());
                    try self.asm_register_register(.{ ._, .@"or" }, tmp_regs[1].to8(), tmp_regs[2].to8());
                    try self.asm_register_register(.{ ._, .add }, .rdx, tmp_regs[0]);
                    try self.asm_setcc_register(.c, tmp_regs[2].to8());
                    try self.asm_register_register(.{ ._, .@"or" }, tmp_regs[1].to8(), tmp_regs[2].to8());

                    const dst_mcv = try self.alloc_reg_or_mem(inst, false);
                    try self.gen_set_mem(
                        .{ .frame = dst_mcv.load_frame.index },
                        @int_cast(tuple_ty.struct_field_offset(0, mod)),
                        tuple_ty.struct_field_type(0, mod),
                        .{ .register_pair = .{ .rax, .rdx } },
                        .{},
                    );
                    try self.gen_set_mem(
                        .{ .frame = dst_mcv.load_frame.index },
                        @int_cast(tuple_ty.struct_field_offset(1, mod)),
                        tuple_ty.struct_field_type(1, mod),
                        .{ .register = tmp_regs[1] },
                        .{},
                    );
                    break :result dst_mcv;
                },
            };

            try self.spill_eflags_if_occupied();
            try self.spill_registers(&.{ .rax, .rcx, .rdx, .rdi, .rsi });
            const reg_locks = self.register_manager.lock_regs_assume_unused(5, .{ .rax, .rcx, .rdx, .rdi, .rsi });
            defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

            const cc: Condition = switch (dst_info.signedness) {
                .unsigned => .c,
                .signed => .o,
            };

            const lhs = try self.resolve_inst(bin_op.lhs);
            const rhs = try self.resolve_inst(bin_op.rhs);

            const extra_bits = if (dst_info.bits <= 64)
                self.reg_extra_bits(dst_ty)
            else
                dst_info.bits % 64;
            const partial_mcv = try self.gen_mul_div_bin_op(.mul, null, dst_ty, src_ty, lhs, rhs);

            switch (partial_mcv) {
                .register => |reg| if (extra_bits == 0) {
                    self.eflags_inst = inst;
                    break :result .{ .register_overflow = .{ .reg = reg, .eflags = cc } };
                } else {
                    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                    try self.gen_set_frame_truncated_overflow_compare(tuple_ty, frame_index, partial_mcv, cc);
                    break :result .{ .load_frame = .{ .index = frame_index } };
                },
                else => {
                    // For now, this is the only supported multiply that doesn't fit in a register.
                    if (dst_info.bits > 128 or src_bits != 64)
                        return self.fail("TODO implement airWithOverflow from {} to {}", .{
                            src_ty.fmt(mod), dst_ty.fmt(mod),
                        });

                    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(tuple_ty, mod));
                    if (dst_info.bits >= lhs_active_bits + rhs_active_bits) {
                        try self.gen_set_mem(
                            .{ .frame = frame_index },
                            @int_cast(tuple_ty.struct_field_offset(0, mod)),
                            tuple_ty.struct_field_type(0, mod),
                            partial_mcv,
                            .{},
                        );
                        try self.gen_set_mem(
                            .{ .frame = frame_index },
                            @int_cast(tuple_ty.struct_field_offset(1, mod)),
                            tuple_ty.struct_field_type(1, mod),
                            .{ .immediate = 0 }, // cc being set is impossible
                            .{},
                        );
                    } else try self.gen_set_frame_truncated_overflow_compare(
                        tuple_ty,
                        frame_index,
                        partial_mcv,
                        null,
                    );
                    break :result .{ .load_frame = .{ .index = frame_index } };
                },
            }
        },
        else => unreachable,
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

/// Generates signed or unsigned integer multiplication/division.
/// Clobbers .rax and .rdx registers.
/// Quotient is saved in .rax and remainder in .rdx.
fn gen_int_mul_div_op_mir(self: *Self, tag: Mir.Inst.FixedTag, ty: Type, lhs: MCValue, rhs: MCValue) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    const bit_size: u32 = @int_cast(self.reg_bit_size(ty));
    if (abi_size > 8) {
        return self.fail("TODO implement gen_int_mul_div_op_mir for ABI size larger than 8", .{});
    }

    try self.gen_set_reg(.rax, ty, lhs, .{});
    switch (tag[1]) {
        else => unreachable,
        .mul => {},
        .div => switch (tag[0]) {
            ._ => {
                const hi_reg: Register =
                    switch (bit_size) {
                    8 => .ah,
                    16, 32, 64 => .edx,
                    else => unreachable,
                };
                try self.asm_register_register(.{ ._, .xor }, hi_reg, hi_reg);
            },
            .i_ => try self.asm_op_only(.{ ._, switch (bit_size) {
                8 => .cbw,
                16 => .cwd,
                32 => .cdq,
                64 => .cqo,
                else => unreachable,
            } }),
            else => unreachable,
        },
    }

    const mat_rhs: MCValue = switch (rhs) {
        .register, .indirect, .load_frame => rhs,
        else => .{ .register = try self.copy_to_tmp_register(ty, rhs) },
    };
    switch (mat_rhs) {
        .register => |reg| try self.asm_register(tag, register_alias(reg, abi_size)),
        .memory, .indirect, .load_frame => try self.asm_memory(
            tag,
            try mat_rhs.mem(self, Memory.Size.from_size(abi_size)),
        ),
        else => unreachable,
    }
    if (tag[1] == .div and bit_size == 8) try self.asm_register_register(.{ ._, .mov }, .dl, .ah);
}

/// Always returns a register.
/// Clobbers .rax and .rdx registers.
fn gen_inline_int_div_floor(self: *Self, ty: Type, lhs: MCValue, rhs: MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    const int_info = ty.int_info(mod);
    const dividend = switch (lhs) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(ty, lhs),
    };
    const dividend_lock = self.register_manager.lock_reg(dividend);
    defer if (dividend_lock) |lock| self.register_manager.unlock_reg(lock);

    const divisor = switch (rhs) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(ty, rhs),
    };
    const divisor_lock = self.register_manager.lock_reg(divisor);
    defer if (divisor_lock) |lock| self.register_manager.unlock_reg(lock);

    try self.gen_int_mul_div_op_mir(
        switch (int_info.signedness) {
            .signed => .{ .i_, .div },
            .unsigned => .{ ._, .div },
        },
        ty,
        .{ .register = dividend },
        .{ .register = divisor },
    );

    try self.asm_register_register(
        .{ ._, .xor },
        register_alias(divisor, abi_size),
        register_alias(dividend, abi_size),
    );
    try self.asm_register_immediate(
        .{ ._r, .sa },
        register_alias(divisor, abi_size),
        Immediate.u(int_info.bits - 1),
    );
    try self.asm_register_register(
        .{ ._, .@"test" },
        register_alias(.rdx, abi_size),
        register_alias(.rdx, abi_size),
    );
    try self.asm_cmovcc_register_register(
        .z,
        register_alias(divisor, @max(abi_size, 2)),
        register_alias(.rdx, @max(abi_size, 2)),
    );
    try self.gen_bin_op_mir(.{ ._, .add }, ty, .{ .register = divisor }, .{ .register = .rax });
    return MCValue{ .register = divisor };
}

fn air_shl_shr_bin_op(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const air_tags = self.air.instructions.items(.tag);
    const tag = air_tags[@int_from_enum(inst)];
    const lhs_ty = self.type_of(bin_op.lhs);
    const rhs_ty = self.type_of(bin_op.rhs);
    const result: MCValue = result: {
        switch (lhs_ty.zig_type_tag(mod)) {
            .Int => {
                try self.spill_registers(&.{.rcx});
                try self.register_manager.get_known_reg(.rcx, null);
                const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                const rhs_mcv = try self.resolve_inst(bin_op.rhs);

                const dst_mcv = try self.gen_shift_bin_op(tag, inst, lhs_mcv, rhs_mcv, lhs_ty, rhs_ty);
                switch (tag) {
                    .shr, .shr_exact, .shl_exact => {},
                    .shl => switch (dst_mcv) {
                        .register => |dst_reg| try self.truncate_register(lhs_ty, dst_reg),
                        .register_pair => |dst_regs| try self.truncate_register(lhs_ty, dst_regs[1]),
                        .load_frame => |frame_addr| {
                            const tmp_reg =
                                try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            const lhs_bits: u31 = @int_cast(lhs_ty.bit_size(mod));
                            const tmp_ty = if (lhs_bits > 64) Type.usize else lhs_ty;
                            const off = frame_addr.off + (lhs_bits - 1) / 64 * 8;
                            try self.gen_set_reg(
                                tmp_reg,
                                tmp_ty,
                                .{ .load_frame = .{ .index = frame_addr.index, .off = off } },
                                .{},
                            );
                            try self.truncate_register(lhs_ty, tmp_reg);
                            try self.gen_set_mem(
                                .{ .frame = frame_addr.index },
                                off,
                                tmp_ty,
                                .{ .register = tmp_reg },
                                .{},
                            );
                        },
                        else => {},
                    },
                    else => unreachable,
                }
                break :result dst_mcv;
            },
            .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                .Int => if (@as(?Mir.Inst.FixedTag, switch (lhs_ty.child_type(mod).int_info(mod).bits) {
                    else => null,
                    16 => switch (lhs_ty.vector_len(mod)) {
                        else => null,
                        1...8 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx))
                                    .{ .vp_w, .sra }
                                else
                                    .{ .p_w, .sra },
                                .unsigned => if (self.has_feature(.avx))
                                    .{ .vp_w, .srl }
                                else
                                    .{ .p_w, .srl },
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx))
                                .{ .vp_w, .sll }
                            else
                                .{ .p_w, .sll },
                        },
                        9...16 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx2)) .{ .vp_w, .sra } else null,
                                .unsigned => if (self.has_feature(.avx2)) .{ .vp_w, .srl } else null,
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx2)) .{ .vp_w, .sll } else null,
                        },
                    },
                    32 => switch (lhs_ty.vector_len(mod)) {
                        else => null,
                        1...4 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx))
                                    .{ .vp_d, .sra }
                                else
                                    .{ .p_d, .sra },
                                .unsigned => if (self.has_feature(.avx))
                                    .{ .vp_d, .srl }
                                else
                                    .{ .p_d, .srl },
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx))
                                .{ .vp_d, .sll }
                            else
                                .{ .p_d, .sll },
                        },
                        5...8 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx2)) .{ .vp_d, .sra } else null,
                                .unsigned => if (self.has_feature(.avx2)) .{ .vp_d, .srl } else null,
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx2)) .{ .vp_d, .sll } else null,
                        },
                    },
                    64 => switch (lhs_ty.vector_len(mod)) {
                        else => null,
                        1...2 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx))
                                    .{ .vp_q, .sra }
                                else
                                    .{ .p_q, .sra },
                                .unsigned => if (self.has_feature(.avx))
                                    .{ .vp_q, .srl }
                                else
                                    .{ .p_q, .srl },
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx))
                                .{ .vp_q, .sll }
                            else
                                .{ .p_q, .sll },
                        },
                        3...4 => switch (tag) {
                            else => unreachable,
                            .shr, .shr_exact => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                                .signed => if (self.has_feature(.avx2)) .{ .vp_q, .sra } else null,
                                .unsigned => if (self.has_feature(.avx2)) .{ .vp_q, .srl } else null,
                            },
                            .shl, .shl_exact => if (self.has_feature(.avx2)) .{ .vp_q, .sll } else null,
                        },
                    },
                })) |mir_tag| if (try self.air.value(bin_op.rhs, mod)) |rhs_val| {
                    switch (mod.intern_pool.index_to_key(rhs_val.to_intern())) {
                        .aggregate => |rhs_aggregate| switch (rhs_aggregate.storage) {
                            .repeated_elem => |rhs_elem| {
                                const abi_size: u32 = @int_cast(lhs_ty.abi_size(mod));

                                const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                                const dst_reg, const lhs_reg = if (lhs_mcv.is_register() and
                                    self.reuse_operand(inst, bin_op.lhs, 0, lhs_mcv))
                                    .{lhs_mcv.get_reg().?} ** 2
                                else if (lhs_mcv.is_register() and self.has_feature(.avx)) .{
                                    try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse),
                                    lhs_mcv.get_reg().?,
                                } else .{(try self.copy_to_register_with_inst_tracking(
                                    inst,
                                    lhs_ty,
                                    lhs_mcv,
                                )).register} ** 2;
                                const reg_locks =
                                    self.register_manager.lock_regs(2, .{ dst_reg, lhs_reg });
                                defer for (reg_locks) |reg_lock| if (reg_lock) |lock|
                                    self.register_manager.unlock_reg(lock);

                                const shift_imm =
                                    Immediate.u(@int_cast(Value.from_interned(rhs_elem).to_unsigned_int(mod)));
                                if (self.has_feature(.avx)) try self.asm_register_register_immediate(
                                    mir_tag,
                                    register_alias(dst_reg, abi_size),
                                    register_alias(lhs_reg, abi_size),
                                    shift_imm,
                                ) else {
                                    assert(dst_reg.id() == lhs_reg.id());
                                    try self.asm_register_immediate(
                                        mir_tag,
                                        register_alias(dst_reg, abi_size),
                                        shift_imm,
                                    );
                                }
                                break :result .{ .register = dst_reg };
                            },
                            else => {},
                        },
                        else => {},
                    }
                } else if (bin_op.rhs.to_index()) |rhs_inst| switch (air_tags[@int_from_enum(rhs_inst)]) {
                    .splat => {
                        const abi_size: u32 = @int_cast(lhs_ty.abi_size(mod));

                        const lhs_mcv = try self.resolve_inst(bin_op.lhs);
                        const dst_reg, const lhs_reg = if (lhs_mcv.is_register() and
                            self.reuse_operand(inst, bin_op.lhs, 0, lhs_mcv))
                            .{lhs_mcv.get_reg().?} ** 2
                        else if (lhs_mcv.is_register() and self.has_feature(.avx)) .{
                            try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse),
                            lhs_mcv.get_reg().?,
                        } else .{(try self.copy_to_register_with_inst_tracking(
                            inst,
                            lhs_ty,
                            lhs_mcv,
                        )).register} ** 2;
                        const reg_locks = self.register_manager.lock_regs(2, .{ dst_reg, lhs_reg });
                        defer for (reg_locks) |reg_lock| if (reg_lock) |lock|
                            self.register_manager.unlock_reg(lock);

                        const shift_reg =
                            try self.copy_to_tmp_register(rhs_ty, .{ .air_ref = bin_op.rhs });
                        const shift_lock = self.register_manager.lock_reg_assume_unused(shift_reg);
                        defer self.register_manager.unlock_reg(shift_lock);

                        const mask_ty = try mod.vector_type(.{ .len = 16, .child = .u8_type });
                        const mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                            .ty = mask_ty.to_intern(),
                            .storage = .{ .elems = &([1]InternPool.Index{
                                (try rhs_ty.child_type(mod).max_int_scalar(mod, Type.u8)).to_intern(),
                            } ++ [1]InternPool.Index{
                                (try mod.int_value(Type.u8, 0)).to_intern(),
                            } ** 15) },
                        } })));
                        const mask_addr_reg =
                            try self.copy_to_tmp_register(Type.usize, mask_mcv.address());
                        const mask_addr_lock = self.register_manager.lock_reg_assume_unused(mask_addr_reg);
                        defer self.register_manager.unlock_reg(mask_addr_lock);

                        if (self.has_feature(.avx)) {
                            try self.asm_register_register_memory(
                                .{ .vp_, .@"and" },
                                shift_reg.to128(),
                                shift_reg.to128(),
                                .{
                                    .base = .{ .reg = mask_addr_reg },
                                    .mod = .{ .rm = .{ .size = .xword } },
                                },
                            );
                            try self.asm_register_register_register(
                                mir_tag,
                                register_alias(dst_reg, abi_size),
                                register_alias(lhs_reg, abi_size),
                                shift_reg.to128(),
                            );
                        } else {
                            try self.asm_register_memory(
                                .{ .p_, .@"and" },
                                shift_reg.to128(),
                                .{
                                    .base = .{ .reg = mask_addr_reg },
                                    .mod = .{ .rm = .{ .size = .xword } },
                                },
                            );
                            assert(dst_reg.id() == lhs_reg.id());
                            try self.asm_register_register(
                                mir_tag,
                                register_alias(dst_reg, abi_size),
                                shift_reg.to128(),
                            );
                        }
                        break :result .{ .register = dst_reg };
                    },
                    else => {},
                },
                else => {},
            },
            else => {},
        }
        return self.fail("TODO implement air_shl_shr_bin_op for {}", .{lhs_ty.fmt(mod)});
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_shl_sat(self: *Self, inst: Air.Inst.Index) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    _ = bin_op;
    return self.fail("TODO implement shl_sat for {}", .{self.target.cpu.arch});
    //return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_optional_payload(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = result: {
        const pl_ty = self.type_of_index(inst);
        if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;

        const opt_mcv = try self.resolve_inst(ty_op.operand);
        if (self.reuse_operand(inst, ty_op.operand, 0, opt_mcv)) {
            const pl_mcv: MCValue = switch (opt_mcv) {
                .register_overflow => |ro| pl: {
                    self.eflags_inst = null; // actually stop tracking the overflow part
                    break :pl .{ .register = ro.reg };
                },
                else => opt_mcv,
            };
            switch (pl_mcv) {
                .register => |pl_reg| try self.truncate_register(pl_ty, pl_reg),
                else => {},
            }
            break :result pl_mcv;
        }

        const pl_mcv = try self.alloc_reg_or_mem(inst, true);
        try self.gen_copy(pl_ty, pl_mcv, switch (opt_mcv) {
            else => opt_mcv,
            .register_overflow => |ro| .{ .register = ro.reg },
        }, .{});
        break :result pl_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_optional_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dst_ty = self.type_of_index(inst);
    const opt_mcv = try self.resolve_inst(ty_op.operand);

    const dst_mcv = if (self.reuse_operand(inst, ty_op.operand, 0, opt_mcv))
        opt_mcv
    else
        try self.copy_to_register_with_inst_tracking(inst, dst_ty, opt_mcv);
    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_optional_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        const dst_ty = self.type_of_index(inst);
        const src_ty = self.type_of(ty_op.operand);
        const opt_ty = src_ty.child_type(mod);
        const src_mcv = try self.resolve_inst(ty_op.operand);

        if (opt_ty.optional_repr_is_payload(mod)) {
            break :result if (self.liveness.is_unused(inst))
                .unreach
            else if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                src_mcv
            else
                try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv);
        }

        const dst_mcv: MCValue = if (src_mcv.is_register() and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv
        else if (self.liveness.is_unused(inst))
            .{ .register = try self.copy_to_tmp_register(dst_ty, src_mcv) }
        else
            try self.copy_to_register_with_inst_tracking(inst, dst_ty, src_mcv);

        const pl_ty = dst_ty.child_type(mod);
        const pl_abi_size: i32 = @int_cast(pl_ty.abi_size(mod));
        try self.gen_set_mem(
            .{ .reg = dst_mcv.get_reg().? },
            pl_abi_size,
            Type.bool,
            .{ .immediate = 1 },
            .{},
        );
        break :result if (self.liveness.is_unused(inst)) .unreach else dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unwrap_err_union_err(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const err_union_ty = self.type_of(ty_op.operand);
    const err_ty = err_union_ty.error_union_set(mod);
    const payload_ty = err_union_ty.error_union_payload(mod);
    const operand = try self.resolve_inst(ty_op.operand);

    const result: MCValue = result: {
        if (err_ty.error_set_is_empty(mod)) {
            break :result MCValue{ .immediate = 0 };
        }

        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) {
            break :result operand;
        }

        const err_off = err_union_error_offset(payload_ty, mod);
        switch (operand) {
            .register => |reg| {
                // TODO reuse operand
                const eu_lock = self.register_manager.lock_reg(reg);
                defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

                const result = try self.copy_to_register_with_inst_tracking(inst, err_union_ty, operand);
                if (err_off > 0) try self.gen_shift_bin_op_mir(
                    .{ ._r, .sh },
                    err_union_ty,
                    result,
                    Type.u8,
                    .{ .immediate = @as(u6, @int_cast(err_off * 8)) },
                ) else try self.truncate_register(Type.anyerror, result.register);
                break :result result;
            },
            .load_frame => |frame_addr| break :result .{ .load_frame = .{
                .index = frame_addr.index,
                .off = frame_addr.off + @as(i32, @int_cast(err_off)),
            } },
            else => return self.fail("TODO implement unwrap_err_err for {}", .{operand}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_unwrap_err_union_payload(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand_ty = self.type_of(ty_op.operand);
    const operand = try self.resolve_inst(ty_op.operand);
    const result = try self.gen_unwrap_err_union_payload_mir(inst, operand_ty, operand);
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

// *(E!T) -> E
fn air_unwrap_err_union_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const src_ty = self.type_of(ty_op.operand);
    const src_mcv = try self.resolve_inst(ty_op.operand);
    const src_reg = switch (src_mcv) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(src_ty, src_mcv),
    };
    const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
    defer self.register_manager.unlock_reg(src_lock);

    const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
    const dst_mcv = MCValue{ .register = dst_reg };
    const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
    defer self.register_manager.unlock_reg(dst_lock);

    const eu_ty = src_ty.child_type(mod);
    const pl_ty = eu_ty.error_union_payload(mod);
    const err_ty = eu_ty.error_union_set(mod);
    const err_off: i32 = @int_cast(err_union_error_offset(pl_ty, mod));
    const err_abi_size: u32 = @int_cast(err_ty.abi_size(mod));
    try self.asm_register_memory(
        .{ ._, .mov },
        register_alias(dst_reg, err_abi_size),
        .{
            .base = .{ .reg = src_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(err_abi_size),
                .disp = err_off,
            } },
        },
    );

    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

// *(E!T) -> *T
fn air_unwrap_err_union_payload_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const operand_ty = self.type_of(ty_op.operand);
    const operand = try self.resolve_inst(ty_op.operand);
    const result = try self.gen_unwrap_err_union_payload_ptr_mir(inst, operand_ty, operand);
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_err_union_payload_ptr_set(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = result: {
        const src_ty = self.type_of(ty_op.operand);
        const src_mcv = try self.resolve_inst(ty_op.operand);
        const src_reg = switch (src_mcv) {
            .register => |reg| reg,
            else => try self.copy_to_tmp_register(src_ty, src_mcv),
        };
        const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
        defer self.register_manager.unlock_reg(src_lock);

        const eu_ty = src_ty.child_type(mod);
        const pl_ty = eu_ty.error_union_payload(mod);
        const err_ty = eu_ty.error_union_set(mod);
        const err_off: i32 = @int_cast(err_union_error_offset(pl_ty, mod));
        const err_abi_size: u32 = @int_cast(err_ty.abi_size(mod));
        try self.asm_memory_immediate(
            .{ ._, .mov },
            .{
                .base = .{ .reg = src_reg },
                .mod = .{ .rm = .{
                    .size = Memory.Size.from_size(err_abi_size),
                    .disp = err_off,
                } },
            },
            Immediate.u(0),
        );

        if (self.liveness.is_unused(inst)) break :result .unreach;

        const dst_ty = self.type_of_index(inst);
        const dst_reg = if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_reg
        else
            try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const pl_off: i32 = @int_cast(err_union_payload_offset(pl_ty, mod));
        const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
        try self.asm_register_memory(
            .{ ._, .lea },
            register_alias(dst_reg, dst_abi_size),
            .{
                .base = .{ .reg = src_reg },
                .mod = .{ .rm = .{ .size = .qword, .disp = pl_off } },
            },
        );
        break :result .{ .register = dst_reg };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn gen_unwrap_err_union_payload_mir(
    self: *Self,
    maybe_inst: ?Air.Inst.Index,
    err_union_ty: Type,
    err_union: MCValue,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const payload_ty = err_union_ty.error_union_payload(mod);

    const result: MCValue = result: {
        if (!payload_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;

        const payload_off: u31 = @int_cast(err_union_payload_offset(payload_ty, mod));
        switch (err_union) {
            .load_frame => |frame_addr| break :result .{ .load_frame = .{
                .index = frame_addr.index,
                .off = frame_addr.off + payload_off,
            } },
            .register => |reg| {
                // TODO reuse operand
                const eu_lock = self.register_manager.lock_reg(reg);
                defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

                const payload_in_gp = self.reg_class_for_type(payload_ty).superset_of(abi.RegisterClass.gp);
                const result_mcv: MCValue = if (payload_in_gp and maybe_inst != null)
                    try self.copy_to_register_with_inst_tracking(maybe_inst.?, err_union_ty, err_union)
                else
                    .{ .register = try self.copy_to_tmp_register(err_union_ty, err_union) };
                if (payload_off > 0) try self.gen_shift_bin_op_mir(
                    .{ ._r, .sh },
                    err_union_ty,
                    result_mcv,
                    Type.u8,
                    .{ .immediate = @as(u6, @int_cast(payload_off * 8)) },
                ) else try self.truncate_register(payload_ty, result_mcv.register);
                break :result if (payload_in_gp)
                    result_mcv
                else if (maybe_inst) |inst|
                    try self.copy_to_register_with_inst_tracking(inst, payload_ty, result_mcv)
                else
                    .{ .register = try self.copy_to_tmp_register(payload_ty, result_mcv) };
            },
            else => return self.fail("TODO implement gen_unwrap_err_union_payload_mir for {}", .{err_union}),
        }
    };

    return result;
}

fn gen_unwrap_err_union_payload_ptr_mir(
    self: *Self,
    maybe_inst: ?Air.Inst.Index,
    ptr_ty: Type,
    ptr_mcv: MCValue,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const err_union_ty = ptr_ty.child_type(mod);
    const payload_ty = err_union_ty.error_union_payload(mod);

    const result: MCValue = result: {
        const payload_off = err_union_payload_offset(payload_ty, mod);
        const result_mcv: MCValue = if (maybe_inst) |inst|
            try self.copy_to_register_with_inst_tracking(inst, ptr_ty, ptr_mcv)
        else
            .{ .register = try self.copy_to_tmp_register(ptr_ty, ptr_mcv) };
        try self.gen_bin_op_mir(.{ ._, .add }, ptr_ty, result_mcv, .{ .immediate = payload_off });
        break :result result_mcv;
    };

    return result;
}

fn air_err_return_trace(self: *Self, inst: Air.Inst.Index) !void {
    _ = inst;
    return self.fail("TODO implement air_err_return_trace for {}", .{self.target.cpu.arch});
    //return self.finish_air(inst, result, .{ .none, .none, .none });
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
    const result: MCValue = result: {
        const pl_ty = self.type_of(ty_op.operand);
        if (!pl_ty.has_runtime_bits(mod)) break :result .{ .immediate = 1 };

        const opt_ty = self.type_of_index(inst);
        const pl_mcv = try self.resolve_inst(ty_op.operand);
        const same_repr = opt_ty.optional_repr_is_payload(mod);
        if (same_repr and self.reuse_operand(inst, ty_op.operand, 0, pl_mcv)) break :result pl_mcv;

        const pl_lock: ?RegisterLock = switch (pl_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (pl_lock) |lock| self.register_manager.unlock_reg(lock);

        const opt_mcv = try self.alloc_reg_or_mem(inst, true);
        try self.gen_copy(pl_ty, opt_mcv, pl_mcv, .{});

        if (!same_repr) {
            const pl_abi_size: i32 = @int_cast(pl_ty.abi_size(mod));
            switch (opt_mcv) {
                else => unreachable,

                .register => |opt_reg| {
                    try self.truncate_register(pl_ty, opt_reg);
                    try self.asm_register_immediate(
                        .{ ._s, .bt },
                        opt_reg,
                        Immediate.u(@as(u6, @int_cast(pl_abi_size * 8))),
                    );
                },

                .load_frame => |frame_addr| try self.asm_memory_immediate(
                    .{ ._, .mov },
                    .{
                        .base = .{ .frame = frame_addr.index },
                        .mod = .{ .rm = .{
                            .size = .byte,
                            .disp = frame_addr.off + pl_abi_size,
                        } },
                    },
                    Immediate.u(1),
                ),
            }
        }
        break :result opt_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// T to E!T
fn air_wrap_err_union_payload(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const eu_ty = ty_op.ty.to_type();
    const pl_ty = eu_ty.error_union_payload(mod);
    const err_ty = eu_ty.error_union_set(mod);
    const operand = try self.resolve_inst(ty_op.operand);

    const result: MCValue = result: {
        if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) break :result .{ .immediate = 0 };

        const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(eu_ty, mod));
        const pl_off: i32 = @int_cast(err_union_payload_offset(pl_ty, mod));
        const err_off: i32 = @int_cast(err_union_error_offset(pl_ty, mod));
        try self.gen_set_mem(.{ .frame = frame_index }, pl_off, pl_ty, operand, .{});
        try self.gen_set_mem(.{ .frame = frame_index }, err_off, err_ty, .{ .immediate = 0 }, .{});
        break :result .{ .load_frame = .{ .index = frame_index } };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

/// E to E!T
fn air_wrap_err_union_err(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const eu_ty = ty_op.ty.to_type();
    const pl_ty = eu_ty.error_union_payload(mod);
    const err_ty = eu_ty.error_union_set(mod);

    const result: MCValue = result: {
        if (!pl_ty.has_runtime_bits_ignore_comptime(mod)) break :result try self.resolve_inst(ty_op.operand);

        const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(eu_ty, mod));
        const pl_off: i32 = @int_cast(err_union_payload_offset(pl_ty, mod));
        const err_off: i32 = @int_cast(err_union_error_offset(pl_ty, mod));
        try self.gen_set_mem(.{ .frame = frame_index }, pl_off, pl_ty, .undef, .{});
        const operand = try self.resolve_inst(ty_op.operand);
        try self.gen_set_mem(.{ .frame = frame_index }, err_off, err_ty, operand, .{});
        break :result .{ .load_frame = .{ .index = frame_index } };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);
        if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result src_mcv;

        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
        const dst_ty = self.type_of_index(inst);
        try self.gen_copy(dst_ty, dst_mcv, src_mcv, .{});
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_slice_len(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const result: MCValue = result: {
        const src_mcv = try self.resolve_inst(ty_op.operand);
        switch (src_mcv) {
            .load_frame => |frame_addr| {
                const len_mcv: MCValue = .{ .load_frame = .{
                    .index = frame_addr.index,
                    .off = frame_addr.off + 8,
                } };
                if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result len_mcv;

                const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                try self.gen_copy(Type.usize, dst_mcv, len_mcv, .{});
                break :result dst_mcv;
            },
            else => return self.fail("TODO implement slice_len for {}", .{src_mcv}),
        }
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_len_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const src_ty = self.type_of(ty_op.operand);
    const src_mcv = try self.resolve_inst(ty_op.operand);
    const src_reg = switch (src_mcv) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(src_ty, src_mcv),
    };
    const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
    defer self.register_manager.unlock_reg(src_lock);

    const dst_ty = self.type_of_index(inst);
    const dst_reg = if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
        src_reg
    else
        try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
    const dst_mcv = MCValue{ .register = dst_reg };
    const dst_lock = self.register_manager.lock_reg(dst_reg);
    defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

    const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    try self.asm_register_memory(
        .{ ._, .lea },
        register_alias(dst_reg, dst_abi_size),
        .{
            .base = .{ .reg = src_reg },
            .mod = .{ .rm = .{ .size = .qword, .disp = 8 } },
        },
    );

    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_ptr_slice_ptr_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dst_ty = self.type_of_index(inst);
    const opt_mcv = try self.resolve_inst(ty_op.operand);

    const dst_mcv = if (self.reuse_operand(inst, ty_op.operand, 0, opt_mcv))
        opt_mcv
    else
        try self.copy_to_register_with_inst_tracking(inst, dst_ty, opt_mcv);
    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn elem_offset(self: *Self, index_ty: Type, index: MCValue, elem_size: u64) !Register {
    const reg: Register = blk: {
        switch (index) {
            .immediate => |imm| {
                // Optimisation: if index MCValue is an immediate, we can multiply in `comptime`
                // and set the register directly to the scaled offset as an immediate.
                const reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                try self.gen_set_reg(reg, index_ty, .{ .immediate = imm * elem_size }, .{});
                break :blk reg;
            },
            else => {
                const reg = try self.copy_to_tmp_register(index_ty, index);
                try self.gen_int_mul_complex_op_mir(index_ty, .{ .register = reg }, .{ .immediate = elem_size });
                break :blk reg;
            },
        }
    };
    return reg;
}

fn gen_slice_elem_ptr(self: *Self, lhs: Air.Inst.Ref, rhs: Air.Inst.Ref) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const slice_ty = self.type_of(lhs);
    const slice_mcv = try self.resolve_inst(lhs);
    const slice_mcv_lock: ?RegisterLock = switch (slice_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (slice_mcv_lock) |lock| self.register_manager.unlock_reg(lock);

    const elem_ty = slice_ty.child_type(mod);
    const elem_size = elem_ty.abi_size(mod);
    const slice_ptr_field_type = slice_ty.slice_ptr_field_type(mod);

    const index_ty = self.type_of(rhs);
    const index_mcv = try self.resolve_inst(rhs);
    const index_mcv_lock: ?RegisterLock = switch (index_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (index_mcv_lock) |lock| self.register_manager.unlock_reg(lock);

    const offset_reg = try self.elem_offset(index_ty, index_mcv, elem_size);
    const offset_reg_lock = self.register_manager.lock_reg_assume_unused(offset_reg);
    defer self.register_manager.unlock_reg(offset_reg_lock);

    const addr_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    try self.gen_set_reg(addr_reg, Type.usize, slice_mcv, .{});
    // TODO we could allocate register here, but need to expect addr register and potentially
    // offset register.
    try self.gen_bin_op_mir(.{ ._, .add }, slice_ptr_field_type, .{ .register = addr_reg }, .{
        .register = offset_reg,
    });
    return MCValue{ .register = addr_reg.to64() };
}

fn air_slice_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const result: MCValue = result: {
        const elem_ty = self.type_of_index(inst);
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;

        const slice_ty = self.type_of(bin_op.lhs);
        const slice_ptr_field_type = slice_ty.slice_ptr_field_type(mod);
        const elem_ptr = try self.gen_slice_elem_ptr(bin_op.lhs, bin_op.rhs);
        const dst_mcv = try self.alloc_reg_or_mem(inst, false);
        try self.load(dst_mcv, slice_ptr_field_type, elem_ptr);
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_slice_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
    const dst_mcv = try self.gen_slice_elem_ptr(extra.lhs, extra.rhs);
    return self.finish_air(inst, dst_mcv, .{ extra.lhs, extra.rhs, .none });
}

fn air_array_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const result: MCValue = result: {
        const array_ty = self.type_of(bin_op.lhs);
        const elem_ty = array_ty.child_type(mod);

        const array_mcv = try self.resolve_inst(bin_op.lhs);
        const array_lock: ?RegisterLock = switch (array_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (array_lock) |lock| self.register_manager.unlock_reg(lock);

        const index_ty = self.type_of(bin_op.rhs);
        const index_mcv = try self.resolve_inst(bin_op.rhs);
        const index_lock: ?RegisterLock = switch (index_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (index_lock) |lock| self.register_manager.unlock_reg(lock);

        try self.spill_eflags_if_occupied();
        if (array_ty.is_vector(mod) and elem_ty.bit_size(mod) == 1) {
            const index_reg = switch (index_mcv) {
                .register => |reg| reg,
                else => try self.copy_to_tmp_register(index_ty, index_mcv),
            };
            switch (array_mcv) {
                .register => |array_reg| switch (array_reg.class()) {
                    .general_purpose => try self.asm_register_register(
                        .{ ._, .bt },
                        array_reg.to64(),
                        index_reg.to64(),
                    ),
                    .sse => {
                        const frame_index = try self.alloc_frame_index(FrameAlloc.init_type(array_ty, mod));
                        try self.gen_set_mem(.{ .frame = frame_index }, 0, array_ty, array_mcv, .{});
                        try self.asm_memory_register(
                            .{ ._, .bt },
                            .{
                                .base = .{ .frame = frame_index },
                                .mod = .{ .rm = .{ .size = .qword } },
                            },
                            index_reg.to64(),
                        );
                    },
                    else => unreachable,
                },
                .load_frame => try self.asm_memory_register(
                    .{ ._, .bt },
                    try array_mcv.mem(self, .qword),
                    index_reg.to64(),
                ),
                .memory, .load_symbol, .load_direct, .load_got, .load_tlv => try self.asm_memory_register(
                    .{ ._, .bt },
                    .{
                        .base = .{
                            .reg = try self.copy_to_tmp_register(Type.usize, array_mcv.address()),
                        },
                        .mod = .{ .rm = .{ .size = .qword } },
                    },
                    index_reg.to64(),
                ),
                else => return self.fail("TODO air_array_elem_val for {s} of {}", .{
                    @tag_name(array_mcv), array_ty.fmt(mod),
                }),
            }

            const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
            try self.asm_setcc_register(.c, dst_reg.to8());
            break :result .{ .register = dst_reg };
        }

        const elem_abi_size = elem_ty.abi_size(mod);
        const addr_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
        const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
        defer self.register_manager.unlock_reg(addr_lock);

        switch (array_mcv) {
            .register => {
                const frame_index = try self.alloc_frame_index(FrameAlloc.init_type(array_ty, mod));
                try self.gen_set_mem(.{ .frame = frame_index }, 0, array_ty, array_mcv, .{});
                try self.asm_register_memory(
                    .{ ._, .lea },
                    addr_reg,
                    .{ .base = .{ .frame = frame_index }, .mod = .{ .rm = .{ .size = .qword } } },
                );
            },
            .load_frame => |frame_addr| try self.asm_register_memory(
                .{ ._, .lea },
                addr_reg,
                .{
                    .base = .{ .frame = frame_addr.index },
                    .mod = .{ .rm = .{ .size = .qword, .disp = frame_addr.off } },
                },
            ),
            .memory,
            .load_symbol,
            .load_direct,
            .load_got,
            .load_tlv,
            => try self.gen_set_reg(addr_reg, Type.usize, array_mcv.address(), .{}),
            .lea_symbol, .lea_direct, .lea_tlv => unreachable,
            else => return self.fail("TODO airArrayElemVal_val for {s} of {}", .{
                @tag_name(array_mcv), array_ty.fmt(mod),
            }),
        }

        const offset_reg = try self.elem_offset(index_ty, index_mcv, elem_abi_size);
        const offset_lock = self.register_manager.lock_reg_assume_unused(offset_reg);
        defer self.register_manager.unlock_reg(offset_lock);

        // TODO we could allocate register here, but need to expect addr register and potentially
        // offset register.
        const dst_mcv = try self.alloc_reg_or_mem(inst, false);
        try self.gen_bin_op_mir(
            .{ ._, .add },
            Type.usize,
            .{ .register = addr_reg },
            .{ .register = offset_reg },
        );
        try self.gen_copy(elem_ty, dst_mcv, .{ .indirect = .{ .reg = addr_reg } }, .{});
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ptr_ty = self.type_of(bin_op.lhs);

    // this is identical to the `air_ptr_elem_ptr` codegen expect here an
    // additional `mov` is needed at the end to get the actual value

    const result = result: {
        const elem_ty = ptr_ty.elem_type2(mod);
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;

        const elem_abi_size: u32 = @int_cast(elem_ty.abi_size(mod));
        const index_ty = self.type_of(bin_op.rhs);
        const index_mcv = try self.resolve_inst(bin_op.rhs);
        const index_lock = switch (index_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (index_lock) |lock| self.register_manager.unlock_reg(lock);

        const offset_reg = try self.elem_offset(index_ty, index_mcv, elem_abi_size);
        const offset_lock = self.register_manager.lock_reg_assume_unused(offset_reg);
        defer self.register_manager.unlock_reg(offset_lock);

        const ptr_mcv = try self.resolve_inst(bin_op.lhs);
        const elem_ptr_reg = if (ptr_mcv.is_register() and self.liveness.operand_dies(inst, 0))
            ptr_mcv.register
        else
            try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
        const elem_ptr_lock = self.register_manager.lock_reg_assume_unused(elem_ptr_reg);
        defer self.register_manager.unlock_reg(elem_ptr_lock);
        try self.asm_register_register(
            .{ ._, .add },
            elem_ptr_reg,
            offset_reg,
        );

        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
        const dst_lock = switch (dst_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);
        try self.load(dst_mcv, ptr_ty, .{ .register = elem_ptr_reg });
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_ptr_elem_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;

    const result = result: {
        const elem_ptr_ty = self.type_of_index(inst);
        const base_ptr_ty = self.type_of(extra.lhs);

        const base_ptr_mcv = try self.resolve_inst(extra.lhs);
        const base_ptr_lock: ?RegisterLock = switch (base_ptr_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (base_ptr_lock) |lock| self.register_manager.unlock_reg(lock);

        if (elem_ptr_ty.ptr_info(mod).flags.vector_index != .none) {
            break :result if (self.reuse_operand(inst, extra.lhs, 0, base_ptr_mcv))
                base_ptr_mcv
            else
                try self.copy_to_register_with_inst_tracking(inst, elem_ptr_ty, base_ptr_mcv);
        }

        const elem_ty = base_ptr_ty.elem_type2(mod);
        const elem_abi_size = elem_ty.abi_size(mod);
        const index_ty = self.type_of(extra.rhs);
        const index_mcv = try self.resolve_inst(extra.rhs);
        const index_lock: ?RegisterLock = switch (index_mcv) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (index_lock) |lock| self.register_manager.unlock_reg(lock);

        const offset_reg = try self.elem_offset(index_ty, index_mcv, elem_abi_size);
        const offset_reg_lock = self.register_manager.lock_reg_assume_unused(offset_reg);
        defer self.register_manager.unlock_reg(offset_reg_lock);

        const dst_mcv = try self.copy_to_register_with_inst_tracking(inst, elem_ptr_ty, base_ptr_mcv);
        try self.gen_bin_op_mir(.{ ._, .add }, elem_ptr_ty, dst_mcv, .{ .register = offset_reg });

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ extra.lhs, extra.rhs, .none });
}

fn air_set_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    const ptr_union_ty = self.type_of(bin_op.lhs);
    const union_ty = ptr_union_ty.child_type(mod);
    const tag_ty = self.type_of(bin_op.rhs);
    const layout = union_ty.union_get_layout(mod);

    if (layout.tag_size == 0) {
        return self.finish_air(inst, .none, .{ bin_op.lhs, bin_op.rhs, .none });
    }

    const ptr = try self.resolve_inst(bin_op.lhs);
    const ptr_lock: ?RegisterLock = switch (ptr) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const tag = try self.resolve_inst(bin_op.rhs);
    const tag_lock: ?RegisterLock = switch (tag) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (tag_lock) |lock| self.register_manager.unlock_reg(lock);

    const adjusted_ptr: MCValue = if (layout.payload_size > 0 and layout.tag_align.compare(.lt, layout.payload_align)) blk: {
        // TODO reusing the operand
        const reg = try self.copy_to_tmp_register(ptr_union_ty, ptr);
        try self.gen_bin_op_mir(
            .{ ._, .add },
            ptr_union_ty,
            .{ .register = reg },
            .{ .immediate = layout.payload_size },
        );
        break :blk MCValue{ .register = reg };
    } else ptr;

    const ptr_tag_ty = try mod.adjust_ptr_type_child(ptr_union_ty, tag_ty);
    try self.store(ptr_tag_ty, adjusted_ptr, tag, .{});

    return self.finish_air(inst, .none, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_get_union_tag(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const tag_ty = self.type_of_index(inst);
    const union_ty = self.type_of(ty_op.operand);
    const layout = union_ty.union_get_layout(mod);

    if (layout.tag_size == 0) {
        return self.finish_air(inst, .none, .{ ty_op.operand, .none, .none });
    }

    // TODO reusing the operand
    const operand = try self.resolve_inst(ty_op.operand);
    const operand_lock: ?RegisterLock = switch (operand) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (operand_lock) |lock| self.register_manager.unlock_reg(lock);

    const tag_abi_size = tag_ty.abi_size(mod);
    const dst_mcv: MCValue = blk: {
        switch (operand) {
            .load_frame => |frame_addr| {
                if (tag_abi_size <= 8) {
                    const off: i32 = if (layout.tag_align.compare(.lt, layout.payload_align))
                        @int_cast(layout.payload_size)
                    else
                        0;
                    break :blk try self.copy_to_register_with_inst_tracking(inst, tag_ty, .{
                        .load_frame = .{ .index = frame_addr.index, .off = frame_addr.off + off },
                    });
                }

                return self.fail(
                    "TODO implement get_union_tag for ABI larger than 8 bytes and operand {}",
                    .{operand},
                );
            },
            .register => {
                const shift: u6 = if (layout.tag_align.compare(.lt, layout.payload_align))
                    @int_cast(layout.payload_size * 8)
                else
                    0;
                const result = try self.copy_to_register_with_inst_tracking(inst, union_ty, operand);
                try self.gen_shift_bin_op_mir(
                    .{ ._r, .sh },
                    Type.usize,
                    result,
                    Type.u8,
                    .{ .immediate = shift },
                );
                break :blk MCValue{
                    .register = register_alias(result.register, @int_cast(layout.tag_size)),
                };
            },
            else => return self.fail("TODO implement get_union_tag for {}", .{operand}),
        }
    };

    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_clz(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        try self.spill_eflags_if_occupied();

        const dst_ty = self.type_of_index(inst);
        const src_ty = self.type_of(ty_op.operand);
        if (src_ty.zig_type_tag(mod) == .Vector) return self.fail("TODO implement air_clz for {}", .{
            src_ty.fmt(mod),
        });

        const src_mcv = try self.resolve_inst(ty_op.operand);
        const mat_src_mcv = switch (src_mcv) {
            .immediate => MCValue{ .register = try self.copy_to_tmp_register(src_ty, src_mcv) },
            else => src_mcv,
        };
        const mat_src_lock = switch (mat_src_mcv) {
            .register => |reg| self.register_manager.lock_reg(reg),
            else => null,
        };
        defer if (mat_src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
        const dst_mcv = MCValue{ .register = dst_reg };
        const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
        defer self.register_manager.unlock_reg(dst_lock);

        const abi_size: u31 = @int_cast(src_ty.abi_size(mod));
        const src_bits: u31 = @int_cast(src_ty.bit_size(mod));
        const has_lzcnt = self.has_feature(.lzcnt);
        if (src_bits > @as(u32, if (has_lzcnt) 128 else 64)) {
            const limbs_len = math.div_ceil(u32, abi_size, 8) catch unreachable;
            const extra_bits = abi_size * 8 - src_bits;

            const index_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const index_lock = self.register_manager.lock_reg_assume_unused(index_reg);
            defer self.register_manager.unlock_reg(index_lock);

            try self.asm_register_immediate(.{ ._, .mov }, index_reg.to32(), Immediate.u(limbs_len));
            switch (extra_bits) {
                1 => try self.asm_register_register(.{ ._, .xor }, dst_reg.to32(), dst_reg.to32()),
                else => try self.asm_register_immediate(
                    .{ ._, .mov },
                    dst_reg.to32(),
                    Immediate.s(@as(i32, extra_bits) - 1),
                ),
            }
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            try self.asm_register_register(.{ ._, .@"test" }, index_reg.to32(), index_reg.to32());
            const zero = try self.asm_jcc_reloc(.z, undefined);
            if (self.has_feature(.slow_incdec)) {
                try self.asm_register_immediate(.{ ._, .sub }, index_reg.to32(), Immediate.u(1));
            } else {
                try self.asm_register(.{ ._, .dec }, index_reg.to32());
            }
            try self.asm_memory_immediate(.{ ._, .cmp }, .{
                .base = .{ .frame = src_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = index_reg.to64(),
                    .scale = .@"8",
                    .disp = src_mcv.load_frame.off,
                } },
            }, Immediate.u(0));
            _ = try self.asm_jcc_reloc(.e, loop);
            try self.asm_register_memory(.{ ._, .bsr }, dst_reg.to64(), .{
                .base = .{ .frame = src_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = index_reg.to64(),
                    .scale = .@"8",
                    .disp = src_mcv.load_frame.off,
                } },
            });
            self.perform_reloc(zero);
            try self.asm_register_immediate(.{ ._l, .sh }, index_reg.to32(), Immediate.u(6));
            try self.asm_register_register(.{ ._, .add }, index_reg.to32(), dst_reg.to32());
            try self.asm_register_immediate(.{ ._, .mov }, dst_reg.to32(), Immediate.u(src_bits - 1));
            try self.asm_register_register(.{ ._, .sub }, dst_reg.to32(), index_reg.to32());
            break :result dst_mcv;
        }

        if (has_lzcnt) {
            if (src_bits <= 8) {
                const wide_reg = try self.copy_to_tmp_register(src_ty, mat_src_mcv);
                try self.truncate_register(src_ty, wide_reg);
                try self.gen_bin_op_mir(.{ ._, .lzcnt }, Type.u32, dst_mcv, .{ .register = wide_reg });
                try self.gen_bin_op_mir(
                    .{ ._, .sub },
                    dst_ty,
                    dst_mcv,
                    .{ .immediate = 32 - src_bits },
                );
            } else if (src_bits <= 64) {
                try self.gen_bin_op_mir(.{ ._, .lzcnt }, src_ty, dst_mcv, mat_src_mcv);
                const extra_bits = self.reg_extra_bits(src_ty);
                if (extra_bits > 0) {
                    try self.gen_bin_op_mir(.{ ._, .sub }, dst_ty, dst_mcv, .{ .immediate = extra_bits });
                }
            } else {
                assert(src_bits <= 128);
                const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const tmp_mcv = MCValue{ .register = tmp_reg };
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                try self.gen_bin_op_mir(
                    .{ ._, .lzcnt },
                    Type.u64,
                    dst_mcv,
                    if (mat_src_mcv.is_memory())
                        mat_src_mcv
                    else
                        .{ .register = mat_src_mcv.register_pair[0] },
                );
                try self.gen_bin_op_mir(.{ ._, .add }, dst_ty, dst_mcv, .{ .immediate = 64 });
                try self.gen_bin_op_mir(
                    .{ ._, .lzcnt },
                    Type.u64,
                    tmp_mcv,
                    if (mat_src_mcv.is_memory())
                        mat_src_mcv.address().offset(8).deref()
                    else
                        .{ .register = mat_src_mcv.register_pair[1] },
                );
                try self.asm_cmovcc_register_register(.nc, dst_reg.to32(), tmp_reg.to32());

                if (src_bits < 128) try self.gen_bin_op_mir(
                    .{ ._, .sub },
                    dst_ty,
                    dst_mcv,
                    .{ .immediate = 128 - src_bits },
                );
            }
            break :result dst_mcv;
        }

        assert(src_bits <= 64);
        const cmov_abi_size = @max(@as(u32, @int_cast(dst_ty.abi_size(mod))), 2);
        if (math.is_power_of_two(src_bits)) {
            const imm_reg = try self.copy_to_tmp_register(dst_ty, .{
                .immediate = src_bits ^ (src_bits - 1),
            });
            const imm_lock = self.register_manager.lock_reg_assume_unused(imm_reg);
            defer self.register_manager.unlock_reg(imm_lock);

            if (src_bits <= 8) {
                const wide_reg = try self.copy_to_tmp_register(src_ty, mat_src_mcv);
                const wide_lock = self.register_manager.lock_reg_assume_unused(wide_reg);
                defer self.register_manager.unlock_reg(wide_lock);

                try self.truncate_register(src_ty, wide_reg);
                try self.gen_bin_op_mir(.{ ._, .bsr }, Type.u16, dst_mcv, .{ .register = wide_reg });
            } else try self.gen_bin_op_mir(.{ ._, .bsr }, src_ty, dst_mcv, mat_src_mcv);

            try self.asm_cmovcc_register_register(
                .z,
                register_alias(dst_reg, cmov_abi_size),
                register_alias(imm_reg, cmov_abi_size),
            );

            try self.gen_bin_op_mir(.{ ._, .xor }, dst_ty, dst_mcv, .{ .immediate = src_bits - 1 });
        } else {
            const imm_reg = try self.copy_to_tmp_register(dst_ty, .{
                .immediate = @as(u64, math.max_int(u64)) >> @int_cast(64 - self.reg_bit_size(dst_ty)),
            });
            const imm_lock = self.register_manager.lock_reg_assume_unused(imm_reg);
            defer self.register_manager.unlock_reg(imm_lock);

            const wide_reg = try self.copy_to_tmp_register(src_ty, mat_src_mcv);
            const wide_lock = self.register_manager.lock_reg_assume_unused(wide_reg);
            defer self.register_manager.unlock_reg(wide_lock);

            try self.truncate_register(src_ty, wide_reg);
            try self.gen_bin_op_mir(
                .{ ._, .bsr },
                if (src_bits <= 8) Type.u16 else src_ty,
                dst_mcv,
                .{ .register = wide_reg },
            );

            try self.asm_cmovcc_register_register(
                .nz,
                register_alias(imm_reg, cmov_abi_size),
                register_alias(dst_reg, cmov_abi_size),
            );

            try self.gen_set_reg(dst_reg, dst_ty, .{ .immediate = src_bits - 1 }, .{});
            try self.gen_bin_op_mir(.{ ._, .sub }, dst_ty, dst_mcv, .{ .register = imm_reg });
        }
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_ctz(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = result: {
        try self.spill_eflags_if_occupied();

        const dst_ty = self.type_of_index(inst);
        const src_ty = self.type_of(ty_op.operand);
        if (src_ty.zig_type_tag(mod) == .Vector) return self.fail("TODO implement air_ctz for {}", .{
            src_ty.fmt(mod),
        });

        const src_mcv = try self.resolve_inst(ty_op.operand);
        const mat_src_mcv = switch (src_mcv) {
            .immediate => MCValue{ .register = try self.copy_to_tmp_register(src_ty, src_mcv) },
            else => src_mcv,
        };
        const mat_src_lock = switch (mat_src_mcv) {
            .register => |reg| self.register_manager.lock_reg(reg),
            else => null,
        };
        defer if (mat_src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
        const dst_mcv = MCValue{ .register = dst_reg };
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const abi_size: u31 = @int_cast(src_ty.abi_size(mod));
        const src_bits: u31 = @int_cast(src_ty.bit_size(mod));
        const has_bmi = self.has_feature(.bmi);
        if (src_bits > @as(u32, if (has_bmi) 128 else 64)) {
            const limbs_len = math.div_ceil(u32, abi_size, 8) catch unreachable;
            const extra_bits = abi_size * 8 - src_bits;

            const index_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const index_lock = self.register_manager.lock_reg_assume_unused(index_reg);
            defer self.register_manager.unlock_reg(index_lock);

            try self.asm_register_immediate(.{ ._, .mov }, index_reg.to32(), Immediate.s(-1));
            switch (extra_bits) {
                0 => try self.asm_register_register(.{ ._, .xor }, dst_reg.to32(), dst_reg.to32()),
                1 => try self.asm_register_register(.{ ._, .mov }, dst_reg.to32(), dst_reg.to32()),
                else => try self.asm_register_immediate(
                    .{ ._, .mov },
                    dst_reg.to32(),
                    Immediate.s(-@as(i32, extra_bits)),
                ),
            }
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            if (self.has_feature(.slow_incdec)) {
                try self.asm_register_immediate(.{ ._, .add }, index_reg.to32(), Immediate.u(1));
            } else {
                try self.asm_register(.{ ._, .inc }, index_reg.to32());
            }
            try self.asm_register_immediate(.{ ._, .cmp }, index_reg.to32(), Immediate.u(limbs_len));
            const zero = try self.asm_jcc_reloc(.nb, undefined);
            try self.asm_memory_immediate(.{ ._, .cmp }, .{
                .base = .{ .frame = src_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = index_reg.to64(),
                    .scale = .@"8",
                    .disp = src_mcv.load_frame.off,
                } },
            }, Immediate.u(0));
            _ = try self.asm_jcc_reloc(.e, loop);
            try self.asm_register_memory(.{ ._, .bsf }, dst_reg.to64(), .{
                .base = .{ .frame = src_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = index_reg.to64(),
                    .scale = .@"8",
                    .disp = src_mcv.load_frame.off,
                } },
            });
            self.perform_reloc(zero);
            try self.asm_register_immediate(.{ ._l, .sh }, index_reg.to32(), Immediate.u(6));
            try self.asm_register_register(.{ ._, .add }, dst_reg.to32(), index_reg.to32());
            break :result dst_mcv;
        }

        const wide_ty = if (src_bits <= 8) Type.u16 else src_ty;
        if (has_bmi) {
            if (src_bits <= 64) {
                const extra_bits = self.reg_extra_bits(src_ty) + @as(u64, if (src_bits <= 8) 8 else 0);
                const masked_mcv = if (extra_bits > 0) masked: {
                    const tmp_mcv = tmp: {
                        if (src_mcv.is_immediate() or self.liveness.operand_dies(inst, 0))
                            break :tmp src_mcv;
                        try self.gen_set_reg(dst_reg, wide_ty, src_mcv, .{});
                        break :tmp dst_mcv;
                    };
                    try self.gen_bin_op_mir(
                        .{ ._, .@"or" },
                        wide_ty,
                        tmp_mcv,
                        .{ .immediate = (@as(u64, math.max_int(u64)) >> @int_cast(64 - extra_bits)) <<
                            @int_cast(src_bits) },
                    );
                    break :masked tmp_mcv;
                } else mat_src_mcv;
                try self.gen_bin_op_mir(.{ ._, .tzcnt }, wide_ty, dst_mcv, masked_mcv);
            } else {
                assert(src_bits <= 128);
                const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const tmp_mcv = MCValue{ .register = tmp_reg };
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                const lo_mat_src_mcv: MCValue = if (mat_src_mcv.is_memory())
                    mat_src_mcv
                else
                    .{ .register = mat_src_mcv.register_pair[0] };
                const hi_mat_src_mcv: MCValue = if (mat_src_mcv.is_memory())
                    mat_src_mcv.address().offset(8).deref()
                else
                    .{ .register = mat_src_mcv.register_pair[1] };
                const masked_mcv = if (src_bits < 128) masked: {
                    try self.gen_copy(Type.u64, dst_mcv, hi_mat_src_mcv, .{});
                    try self.gen_bin_op_mir(
                        .{ ._, .@"or" },
                        Type.u64,
                        dst_mcv,
                        .{ .immediate = @as(u64, math.max_int(u64)) << @int_cast(src_bits - 64) },
                    );
                    break :masked dst_mcv;
                } else hi_mat_src_mcv;
                try self.gen_bin_op_mir(.{ ._, .tzcnt }, Type.u64, dst_mcv, masked_mcv);
                try self.gen_bin_op_mir(.{ ._, .add }, dst_ty, dst_mcv, .{ .immediate = 64 });
                try self.gen_bin_op_mir(.{ ._, .tzcnt }, Type.u64, tmp_mcv, lo_mat_src_mcv);
                try self.asm_cmovcc_register_register(.nc, dst_reg.to32(), tmp_reg.to32());
            }
            break :result dst_mcv;
        }

        assert(src_bits <= 64);
        const width_reg = try self.copy_to_tmp_register(dst_ty, .{ .immediate = src_bits });
        const width_lock = self.register_manager.lock_reg_assume_unused(width_reg);
        defer self.register_manager.unlock_reg(width_lock);

        if (src_bits <= 8 or !math.is_power_of_two(src_bits)) {
            const wide_reg = try self.copy_to_tmp_register(src_ty, mat_src_mcv);
            const wide_lock = self.register_manager.lock_reg_assume_unused(wide_reg);
            defer self.register_manager.unlock_reg(wide_lock);

            try self.truncate_register(src_ty, wide_reg);
            try self.gen_bin_op_mir(.{ ._, .bsf }, wide_ty, dst_mcv, .{ .register = wide_reg });
        } else try self.gen_bin_op_mir(.{ ._, .bsf }, src_ty, dst_mcv, mat_src_mcv);

        const cmov_abi_size = @max(@as(u32, @int_cast(dst_ty.abi_size(mod))), 2);
        try self.asm_cmovcc_register_register(
            .z,
            register_alias(dst_reg, cmov_abi_size),
            register_alias(width_reg, cmov_abi_size),
        );
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_pop_count(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result: MCValue = result: {
        try self.spill_eflags_if_occupied();

        const src_ty = self.type_of(ty_op.operand);
        const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));
        if (src_ty.zig_type_tag(mod) == .Vector or src_abi_size > 16)
            return self.fail("TODO implement air_pop_count for {}", .{src_ty.fmt(mod)});
        const src_mcv = try self.resolve_inst(ty_op.operand);

        const mat_src_mcv = switch (src_mcv) {
            .immediate => MCValue{ .register = try self.copy_to_tmp_register(src_ty, src_mcv) },
            else => src_mcv,
        };
        const mat_src_lock = switch (mat_src_mcv) {
            .register => |reg| self.register_manager.lock_reg(reg),
            else => null,
        };
        defer if (mat_src_lock) |lock| self.register_manager.unlock_reg(lock);

        if (src_abi_size <= 8) {
            const dst_contains_src =
                src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv);
            const dst_reg = if (dst_contains_src)
                src_mcv.get_reg().?
            else
                try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
            const dst_lock = self.register_manager.lock_reg(dst_reg);
            defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

            try self.gen_pop_count(dst_reg, src_ty, mat_src_mcv, dst_contains_src);
            break :result .{ .register = dst_reg };
        }

        assert(src_abi_size > 8 and src_abi_size <= 16);
        const tmp_regs = try self.register_manager.alloc_regs(2, .{ inst, null }, abi.RegisterClass.gp);
        const tmp_locks = self.register_manager.lock_regs_assume_unused(2, tmp_regs);
        defer for (tmp_locks) |lock| self.register_manager.unlock_reg(lock);

        try self.gen_pop_count(tmp_regs[0], Type.usize, if (mat_src_mcv.is_memory())
            mat_src_mcv
        else
            .{ .register = mat_src_mcv.register_pair[0] }, false);
        const src_info = src_ty.int_info(mod);
        const hi_ty = try mod.int_type(src_info.signedness, (src_info.bits - 1) % 64 + 1);
        try self.gen_pop_count(tmp_regs[1], hi_ty, if (mat_src_mcv.is_memory())
            mat_src_mcv.address().offset(8).deref()
        else
            .{ .register = mat_src_mcv.register_pair[1] }, false);
        try self.asm_register_register(.{ ._, .add }, tmp_regs[0].to8(), tmp_regs[1].to8());
        break :result .{ .register = tmp_regs[0] };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn gen_pop_count(
    self: *Self,
    dst_reg: Register,
    src_ty: Type,
    src_mcv: MCValue,
    dst_contains_src: bool,
) !void {
    const mod = self.bin_file.comp.module.?;

    const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));
    if (self.has_feature(.popcnt)) return self.gen_bin_op_mir(
        .{ ._, .popcnt },
        if (src_abi_size > 1) src_ty else Type.u32,
        .{ .register = dst_reg },
        if (src_abi_size > 1) src_mcv else src: {
            if (!dst_contains_src) try self.gen_set_reg(dst_reg, src_ty, src_mcv, .{});
            try self.truncate_register(try src_ty.to_unsigned(mod), dst_reg);
            break :src .{ .register = dst_reg };
        },
    );

    const mask = @as(u64, math.max_int(u64)) >> @int_cast(64 - src_abi_size * 8);
    const imm_0_1 = Immediate.u(mask / 0b1_1);
    const imm_00_11 = Immediate.u(mask / 0b01_01);
    const imm_0000_1111 = Immediate.u(mask / 0b0001_0001);
    const imm_0000_0001 = Immediate.u(mask / 0b1111_1111);

    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
    defer self.register_manager.unlock_reg(tmp_lock);

    const dst = register_alias(dst_reg, src_abi_size);
    const tmp = register_alias(tmp_reg, src_abi_size);
    const imm = if (src_abi_size > 4)
        try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)
    else
        undefined;

    if (!dst_contains_src) try self.gen_set_reg(dst, src_ty, src_mcv, .{});
    // dst = operand
    try self.asm_register_register(.{ ._, .mov }, tmp, dst);
    // tmp = operand
    try self.asm_register_immediate(.{ ._r, .sh }, tmp, Immediate.u(1));
    // tmp = operand >> 1
    if (src_abi_size > 4) {
        try self.asm_register_immediate(.{ ._, .mov }, imm, imm_0_1);
        try self.asm_register_register(.{ ._, .@"and" }, tmp, imm);
    } else try self.asm_register_immediate(.{ ._, .@"and" }, tmp, imm_0_1);
    // tmp = (operand >> 1) & 0x55...55
    try self.asm_register_register(.{ ._, .sub }, dst, tmp);
    // dst = temp1 = operand - ((operand >> 1) & 0x55...55)
    try self.asm_register_register(.{ ._, .mov }, tmp, dst);
    // tmp = temp1
    try self.asm_register_immediate(.{ ._r, .sh }, dst, Immediate.u(2));
    // dst = temp1 >> 2
    if (src_abi_size > 4) {
        try self.asm_register_immediate(.{ ._, .mov }, imm, imm_00_11);
        try self.asm_register_register(.{ ._, .@"and" }, tmp, imm);
        try self.asm_register_register(.{ ._, .@"and" }, dst, imm);
    } else {
        try self.asm_register_immediate(.{ ._, .@"and" }, tmp, imm_00_11);
        try self.asm_register_immediate(.{ ._, .@"and" }, dst, imm_00_11);
    }
    // tmp = temp1 & 0x33...33
    // dst = (temp1 >> 2) & 0x33...33
    try self.asm_register_register(.{ ._, .add }, tmp, dst);
    // tmp = temp2 = (temp1 & 0x33...33) + ((temp1 >> 2) & 0x33...33)
    try self.asm_register_register(.{ ._, .mov }, dst, tmp);
    // dst = temp2
    try self.asm_register_immediate(.{ ._r, .sh }, tmp, Immediate.u(4));
    // tmp = temp2 >> 4
    try self.asm_register_register(.{ ._, .add }, dst, tmp);
    // dst = temp2 + (temp2 >> 4)
    if (src_abi_size > 4) {
        try self.asm_register_immediate(.{ ._, .mov }, imm, imm_0000_1111);
        try self.asm_register_immediate(.{ ._, .mov }, tmp, imm_0000_0001);
        try self.asm_register_register(.{ ._, .@"and" }, dst, imm);
        try self.asm_register_register(.{ .i_, .mul }, dst, tmp);
    } else {
        try self.asm_register_immediate(.{ ._, .@"and" }, dst, imm_0000_1111);
        if (src_abi_size > 1) {
            try self.asm_register_register_immediate(.{ .i_, .mul }, dst, dst, imm_0000_0001);
        }
    }
    // dst = temp3 = (temp2 + (temp2 >> 4)) & 0x0f...0f
    // dst = temp3 * 0x01...01
    if (src_abi_size > 1) {
        try self.asm_register_immediate(.{ ._r, .sh }, dst, Immediate.u((src_abi_size - 1) * 8));
    }
    // dst = (temp3 * 0x01...01) >> (bits - 8)
}

fn gen_byte_swap(
    self: *Self,
    inst: Air.Inst.Index,
    src_ty: Type,
    src_mcv: MCValue,
    mem_ok: bool,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const has_movbe = self.has_feature(.movbe);

    if (src_ty.zig_type_tag(mod) == .Vector) return self.fail(
        "TODO implement gen_byte_swap for {}",
        .{src_ty.fmt(mod)},
    );

    const src_lock = switch (src_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

    const abi_size: u32 = @int_cast(src_ty.abi_size(mod));
    switch (abi_size) {
        0 => unreachable,
        1 => return if ((mem_ok or src_mcv.is_register()) and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv
        else
            try self.copy_to_register_with_inst_tracking(inst, src_ty, src_mcv),
        2 => if ((mem_ok or src_mcv.is_register()) and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
        {
            try self.gen_bin_op_mir(.{ ._l, .ro }, src_ty, src_mcv, .{ .immediate = 8 });
            return src_mcv;
        },
        3...8 => if (src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) {
            try self.gen_un_op_mir(.{ ._, .bswap }, src_ty, src_mcv);
            return src_mcv;
        },
        9...16 => {
            switch (src_mcv) {
                .register_pair => |src_regs| if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) {
                    for (src_regs) |src_reg| try self.asm_register(.{ ._, .bswap }, src_reg.to64());
                    return .{ .register_pair = .{ src_regs[1], src_regs[0] } };
                },
                else => {},
            }

            const dst_regs =
                try self.register_manager.alloc_regs(2, .{ inst, inst }, abi.RegisterClass.gp);
            const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
            defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

            for (dst_regs, 0..) |dst_reg, limb_index| {
                if (src_mcv.is_memory()) {
                    try self.asm_register_memory(
                        .{ ._, if (has_movbe) .movbe else .mov },
                        dst_reg.to64(),
                        try src_mcv.address().offset(@int_cast(limb_index * 8)).deref().mem(self, .qword),
                    );
                    if (!has_movbe) try self.asm_register(.{ ._, .bswap }, dst_reg.to64());
                } else {
                    try self.asm_register_register(
                        .{ ._, .mov },
                        dst_reg.to64(),
                        src_mcv.register_pair[limb_index].to64(),
                    );
                    try self.asm_register(.{ ._, .bswap }, dst_reg.to64());
                }
            }
            return .{ .register_pair = .{ dst_regs[1], dst_regs[0] } };
        },
        else => {
            const limbs_len = math.div_ceil(u32, abi_size, 8) catch unreachable;

            const temp_regs =
                try self.register_manager.alloc_regs(4, .{null} ** 4, abi.RegisterClass.gp);
            const temp_locks = self.register_manager.lock_regs_assume_unused(4, temp_regs);
            defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

            const dst_mcv = try self.alloc_reg_or_mem(inst, false);
            try self.asm_register_register(.{ ._, .xor }, temp_regs[0].to32(), temp_regs[0].to32());
            try self.asm_register_immediate(
                .{ ._, .mov },
                temp_regs[1].to32(),
                Immediate.u(limbs_len - 1),
            );

            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            try self.asm_register_memory(
                .{ ._, if (has_movbe) .movbe else .mov },
                temp_regs[2].to64(),
                .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[0].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off,
                    } },
                },
            );
            try self.asm_register_memory(
                .{ ._, if (has_movbe) .movbe else .mov },
                temp_regs[3].to64(),
                .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[1].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off,
                    } },
                },
            );
            if (!has_movbe) {
                try self.asm_register(.{ ._, .bswap }, temp_regs[2].to64());
                try self.asm_register(.{ ._, .bswap }, temp_regs[3].to64());
            }
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[0].to64(),
                    .scale = .@"8",
                    .disp = dst_mcv.load_frame.off,
                } },
            }, temp_regs[3].to64());
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[1].to64(),
                    .scale = .@"8",
                    .disp = dst_mcv.load_frame.off,
                } },
            }, temp_regs[2].to64());
            if (self.has_feature(.slow_incdec)) {
                try self.asm_register_immediate(.{ ._, .add }, temp_regs[0].to32(), Immediate.u(1));
                try self.asm_register_immediate(.{ ._, .sub }, temp_regs[1].to32(), Immediate.u(1));
            } else {
                try self.asm_register(.{ ._, .inc }, temp_regs[0].to32());
                try self.asm_register(.{ ._, .dec }, temp_regs[1].to32());
            }
            try self.asm_register_register(.{ ._, .cmp }, temp_regs[0].to32(), temp_regs[1].to32());
            _ = try self.asm_jcc_reloc(.be, loop);
            return dst_mcv;
        },
    }

    const dst_mcv: MCValue = if (mem_ok and has_movbe and src_mcv.is_register())
        try self.alloc_reg_or_mem(inst, true)
    else
        .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp) };
    if (dst_mcv.get_reg()) |dst_reg| {
        const dst_lock = self.register_manager.lock_reg_assume_unused(dst_mcv.register);
        defer self.register_manager.unlock_reg(dst_lock);

        try self.gen_set_reg(dst_reg, src_ty, src_mcv, .{});
        switch (abi_size) {
            else => unreachable,
            2 => try self.gen_bin_op_mir(.{ ._l, .ro }, src_ty, dst_mcv, .{ .immediate = 8 }),
            3...8 => try self.gen_un_op_mir(.{ ._, .bswap }, src_ty, dst_mcv),
        }
    } else try self.gen_bin_op_mir(.{ ._, .movbe }, src_ty, dst_mcv, src_mcv);
    return dst_mcv;
}

fn air_byte_swap(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const src_ty = self.type_of(ty_op.operand);
    const src_bits: u32 = @int_cast(src_ty.bit_size(mod));
    const src_mcv = try self.resolve_inst(ty_op.operand);

    const dst_mcv = try self.gen_byte_swap(inst, src_ty, src_mcv, true);
    try self.gen_shift_bin_op_mir(
        .{ ._r, switch (if (src_ty.is_abi_int(mod)) src_ty.int_info(mod).signedness else .unsigned) {
            .signed => .sa,
            .unsigned => .sh,
        } },
        src_ty,
        dst_mcv,
        if (src_bits > 256) Type.u16 else Type.u8,
        .{ .immediate = src_ty.abi_size(mod) * 8 - src_bits },
    );
    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_bit_reverse(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const src_ty = self.type_of(ty_op.operand);
    const abi_size: u32 = @int_cast(src_ty.abi_size(mod));
    const bit_size: u32 = @int_cast(src_ty.bit_size(mod));
    const src_mcv = try self.resolve_inst(ty_op.operand);

    const dst_mcv = try self.gen_byte_swap(inst, src_ty, src_mcv, false);
    const dst_locks: [2]?RegisterLock = switch (dst_mcv) {
        .register => |dst_reg| .{ self.register_manager.lock_reg(dst_reg), null },
        .register_pair => |dst_regs| self.register_manager.lock_regs(2, dst_regs),
        else => unreachable,
    };
    defer for (dst_locks) |dst_lock| if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
    defer self.register_manager.unlock_reg(tmp_lock);

    const limb_abi_size: u32 = @min(abi_size, 8);
    const tmp = register_alias(tmp_reg, limb_abi_size);
    const imm = if (limb_abi_size > 4)
        try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)
    else
        undefined;

    const mask = @as(u64, math.max_int(u64)) >> @int_cast(64 - limb_abi_size * 8);
    const imm_0000_1111 = Immediate.u(mask / 0b0001_0001);
    const imm_00_11 = Immediate.u(mask / 0b01_01);
    const imm_0_1 = Immediate.u(mask / 0b1_1);

    for (dst_mcv.get_regs()) |dst_reg| {
        const dst = register_alias(dst_reg, limb_abi_size);

        // dst = temp1 = bswap(operand)
        try self.asm_register_register(.{ ._, .mov }, tmp, dst);
        // tmp = temp1
        try self.asm_register_immediate(.{ ._r, .sh }, dst, Immediate.u(4));
        // dst = temp1 >> 4
        if (limb_abi_size > 4) {
            try self.asm_register_immediate(.{ ._, .mov }, imm, imm_0000_1111);
            try self.asm_register_register(.{ ._, .@"and" }, tmp, imm);
            try self.asm_register_register(.{ ._, .@"and" }, dst, imm);
        } else {
            try self.asm_register_immediate(.{ ._, .@"and" }, tmp, imm_0000_1111);
            try self.asm_register_immediate(.{ ._, .@"and" }, dst, imm_0000_1111);
        }
        // tmp = temp1 & 0x0F...0F
        // dst = (temp1 >> 4) & 0x0F...0F
        try self.asm_register_immediate(.{ ._l, .sh }, tmp, Immediate.u(4));
        // tmp = (temp1 & 0x0F...0F) << 4
        try self.asm_register_register(.{ ._, .@"or" }, dst, tmp);
        // dst = temp2 = ((temp1 >> 4) & 0x0F...0F) | ((temp1 & 0x0F...0F) << 4)
        try self.asm_register_register(.{ ._, .mov }, tmp, dst);
        // tmp = temp2
        try self.asm_register_immediate(.{ ._r, .sh }, dst, Immediate.u(2));
        // dst = temp2 >> 2
        if (limb_abi_size > 4) {
            try self.asm_register_immediate(.{ ._, .mov }, imm, imm_00_11);
            try self.asm_register_register(.{ ._, .@"and" }, tmp, imm);
            try self.asm_register_register(.{ ._, .@"and" }, dst, imm);
        } else {
            try self.asm_register_immediate(.{ ._, .@"and" }, tmp, imm_00_11);
            try self.asm_register_immediate(.{ ._, .@"and" }, dst, imm_00_11);
        }
        // tmp = temp2 & 0x33...33
        // dst = (temp2 >> 2) & 0x33...33
        try self.asm_register_memory(
            .{ ._, .lea },
            if (limb_abi_size > 4) tmp.to64() else tmp.to32(),
            .{
                .base = .{ .reg = dst.to64() },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = tmp.to64(),
                    .scale = .@"4",
                } },
            },
        );
        // tmp = temp3 = ((temp2 >> 2) & 0x33...33) + ((temp2 & 0x33...33) << 2)
        try self.asm_register_register(.{ ._, .mov }, dst, tmp);
        // dst = temp3
        try self.asm_register_immediate(.{ ._r, .sh }, tmp, Immediate.u(1));
        // tmp = temp3 >> 1
        if (limb_abi_size > 4) {
            try self.asm_register_immediate(.{ ._, .mov }, imm, imm_0_1);
            try self.asm_register_register(.{ ._, .@"and" }, dst, imm);
            try self.asm_register_register(.{ ._, .@"and" }, tmp, imm);
        } else {
            try self.asm_register_immediate(.{ ._, .@"and" }, dst, imm_0_1);
            try self.asm_register_immediate(.{ ._, .@"and" }, tmp, imm_0_1);
        }
        // dst = temp3 & 0x55...55
        // tmp = (temp3 >> 1) & 0x55...55
        try self.asm_register_memory(
            .{ ._, .lea },
            if (limb_abi_size > 4) dst.to64() else dst.to32(),
            .{
                .base = .{ .reg = tmp.to64() },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = dst.to64(),
                    .scale = .@"2",
                } },
            },
        );
        // dst = ((temp3 >> 1) & 0x55...55) + ((temp3 & 0x55...55) << 1)
    }

    const extra_bits = abi_size * 8 - bit_size;
    const signedness: std.builtin.Signedness =
        if (src_ty.is_abi_int(mod)) src_ty.int_info(mod).signedness else .unsigned;
    if (extra_bits > 0) try self.gen_shift_bin_op_mir(switch (signedness) {
        .signed => .{ ._r, .sa },
        .unsigned => .{ ._r, .sh },
    }, src_ty, dst_mcv, Type.u8, .{ .immediate = extra_bits });

    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn float_sign(self: *Self, inst: Air.Inst.Index, operand: Air.Inst.Ref, ty: Type) !void {
    const mod = self.bin_file.comp.module.?;
    const tag = self.air.instructions.items(.tag)[@int_from_enum(inst)];

    const result = result: {
        const scalar_bits = ty.scalar_type(mod).float_bits(self.target.*);
        if (scalar_bits == 80) {
            if (ty.zig_type_tag(mod) != .Float) return self.fail("TODO implement float_sign for {}", .{
                ty.fmt(mod),
            });

            const src_mcv = try self.resolve_inst(operand);
            const src_lock = if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
            defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

            const dst_mcv: MCValue = .{ .register = .st0 };
            if (!std.meta.eql(src_mcv, dst_mcv) or !self.reuse_operand(inst, operand, 0, src_mcv))
                try self.register_manager.get_known_reg(.st0, inst);

            try self.gen_copy(ty, dst_mcv, src_mcv, .{});
            switch (tag) {
                .neg => try self.asm_op_only(.{ .f_, .chs }),
                .abs => try self.asm_op_only(.{ .f_, .abs }),
                else => unreachable,
            }
            break :result dst_mcv;
        }

        const abi_size: u32 = switch (ty.abi_size(mod)) {
            1...16 => 16,
            17...32 => 32,
            else => return self.fail("TODO implement float_sign for {}", .{
                ty.fmt(mod),
            }),
        };

        const src_mcv = try self.resolve_inst(operand);
        const src_lock = if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
        defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_mcv: MCValue = if (src_mcv.is_register() and
            self.reuse_operand(inst, operand, 0, src_mcv))
            src_mcv
        else if (self.has_feature(.avx))
            .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
        else
            try self.copy_to_register_with_inst_tracking(inst, ty, src_mcv);
        const dst_reg = dst_mcv.get_reg().?;
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const vec_ty = try mod.vector_type(.{
            .len = @div_exact(abi_size * 8, scalar_bits),
            .child = (try mod.int_type(.signed, scalar_bits)).ip_index,
        });

        const sign_mcv = try self.gen_typed_value(switch (tag) {
            .neg => try vec_ty.min_int(mod, vec_ty),
            .abs => try vec_ty.max_int(mod, vec_ty),
            else => unreachable,
        });
        const sign_mem: Memory = if (sign_mcv.is_memory())
            try sign_mcv.mem(self, Memory.Size.from_size(abi_size))
        else
            .{
                .base = .{ .reg = try self.copy_to_tmp_register(Type.usize, sign_mcv.address()) },
                .mod = .{ .rm = .{ .size = Memory.Size.from_size(abi_size) } },
            };

        if (self.has_feature(.avx)) try self.asm_register_register_memory(
            switch (scalar_bits) {
                16, 128 => if (abi_size <= 16 or self.has_feature(.avx2)) switch (tag) {
                    .neg => .{ .vp_, .xor },
                    .abs => .{ .vp_, .@"and" },
                    else => unreachable,
                } else switch (tag) {
                    .neg => .{ .v_ps, .xor },
                    .abs => .{ .v_ps, .@"and" },
                    else => unreachable,
                },
                32 => switch (tag) {
                    .neg => .{ .v_ps, .xor },
                    .abs => .{ .v_ps, .@"and" },
                    else => unreachable,
                },
                64 => switch (tag) {
                    .neg => .{ .v_pd, .xor },
                    .abs => .{ .v_pd, .@"and" },
                    else => unreachable,
                },
                80 => return self.fail("TODO implement float_sign for {}", .{ty.fmt(mod)}),
                else => unreachable,
            },
            register_alias(dst_reg, abi_size),
            register_alias(if (src_mcv.is_register())
                src_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(ty, src_mcv), abi_size),
            sign_mem,
        ) else try self.asm_register_memory(
            switch (scalar_bits) {
                16, 128 => switch (tag) {
                    .neg => .{ .p_, .xor },
                    .abs => .{ .p_, .@"and" },
                    else => unreachable,
                },
                32 => switch (tag) {
                    .neg => .{ ._ps, .xor },
                    .abs => .{ ._ps, .@"and" },
                    else => unreachable,
                },
                64 => switch (tag) {
                    .neg => .{ ._pd, .xor },
                    .abs => .{ ._pd, .@"and" },
                    else => unreachable,
                },
                80 => return self.fail("TODO implement float_sign for {}", .{ty.fmt(mod)}),
                else => unreachable,
            },
            register_alias(dst_reg, abi_size),
            sign_mem,
        );
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ operand, .none, .none });
}

fn air_float_sign(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ty = self.type_of(un_op);
    return self.float_sign(inst, un_op, ty);
}

const RoundMode = packed struct(u5) {
    mode: enum(u4) {
        /// Round to nearest (even)
        nearest = 0b0_00,
        /// Round down (toward -∞)
        down = 0b0_01,
        /// Round up (toward +∞)
        up = 0b0_10,
        /// Round toward zero (truncate)
        zero = 0b0_11,
        /// Use current rounding mode of MXCSR.RC
        mxcsr = 0b1_00,
    },
    precision: enum(u1) {
        normal = 0b0,
        inexact = 0b1,
    } = .normal,
};

fn air_round(self: *Self, inst: Air.Inst.Index, mode: RoundMode) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ty = self.type_of(un_op);

    const result = result: {
        switch (try self.gen_round_libcall(ty, .{ .air_ref = un_op }, mode)) {
            .none => {},
            else => |dst_mcv| break :result dst_mcv,
        }

        const src_mcv = try self.resolve_inst(un_op);
        const dst_mcv = if (src_mcv.is_register() and self.reuse_operand(inst, un_op, 0, src_mcv))
            src_mcv
        else
            try self.copy_to_register_with_inst_tracking(inst, ty, src_mcv);
        const dst_reg = dst_mcv.get_reg().?;
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);
        try self.gen_round(ty, dst_reg, src_mcv, mode);
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn get_round_tag(self: *Self, ty: Type) ?Mir.Inst.FixedTag {
    const mod = self.bin_file.comp.module.?;
    return if (self.has_feature(.sse4_1)) switch (ty.zig_type_tag(mod)) {
        .Float => switch (ty.float_bits(self.target.*)) {
            32 => if (self.has_feature(.avx)) .{ .v_ss, .round } else .{ ._ss, .round },
            64 => if (self.has_feature(.avx)) .{ .v_sd, .round } else .{ ._sd, .round },
            16, 80, 128 => null,
            else => unreachable,
        },
        .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
            .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                32 => switch (ty.vector_len(mod)) {
                    1 => if (self.has_feature(.avx)) .{ .v_ss, .round } else .{ ._ss, .round },
                    2...4 => if (self.has_feature(.avx)) .{ .v_ps, .round } else .{ ._ps, .round },
                    5...8 => if (self.has_feature(.avx)) .{ .v_ps, .round } else null,
                    else => null,
                },
                64 => switch (ty.vector_len(mod)) {
                    1 => if (self.has_feature(.avx)) .{ .v_sd, .round } else .{ ._sd, .round },
                    2 => if (self.has_feature(.avx)) .{ .v_pd, .round } else .{ ._pd, .round },
                    3...4 => if (self.has_feature(.avx)) .{ .v_pd, .round } else null,
                    else => null,
                },
                16, 80, 128 => null,
                else => unreachable,
            },
            else => null,
        },
        else => unreachable,
    } else null;
}

fn gen_round_libcall(self: *Self, ty: Type, src_mcv: MCValue, mode: RoundMode) !MCValue {
    const mod = self.bin_file.comp.module.?;
    if (self.get_round_tag(ty)) |_| return .none;

    if (ty.zig_type_tag(mod) != .Float)
        return self.fail("TODO implement gen_round for {}", .{ty.fmt(mod)});

    var callee_buf: ["__trunc?".len]u8 = undefined;
    return try self.gen_call(.{ .lib = .{
        .return_type = ty.to_intern(),
        .param_types = &.{ty.to_intern()},
        .callee = std.fmt.buf_print(&callee_buf, "{s}{s}{s}", .{
            float_libc_abi_prefix(ty),
            switch (mode.mode) {
                .down => "floor",
                .up => "ceil",
                .zero => "trunc",
                else => unreachable,
            },
            float_libc_abi_suffix(ty),
        }) catch unreachable,
    } }, &.{ty}, &.{src_mcv});
}

fn gen_round(self: *Self, ty: Type, dst_reg: Register, src_mcv: MCValue, mode: RoundMode) !void {
    const mod = self.bin_file.comp.module.?;
    const mir_tag = self.get_round_tag(ty) orelse {
        const result = try self.gen_round_libcall(ty, src_mcv, mode);
        return self.gen_set_reg(dst_reg, ty, result, .{});
    };
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    const dst_alias = register_alias(dst_reg, abi_size);
    switch (mir_tag[0]) {
        .v_ss, .v_sd => if (src_mcv.is_memory()) try self.asm_register_register_memory_immediate(
            mir_tag,
            dst_alias,
            dst_alias,
            try src_mcv.mem(self, Memory.Size.from_size(abi_size)),
            Immediate.u(@as(u5, @bit_cast(mode))),
        ) else try self.asm_register_register_register_immediate(
            mir_tag,
            dst_alias,
            dst_alias,
            register_alias(if (src_mcv.is_register())
                src_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(ty, src_mcv), abi_size),
            Immediate.u(@as(u5, @bit_cast(mode))),
        ),
        else => if (src_mcv.is_memory()) try self.asm_register_memory_immediate(
            mir_tag,
            dst_alias,
            try src_mcv.mem(self, Memory.Size.from_size(abi_size)),
            Immediate.u(@as(u5, @bit_cast(mode))),
        ) else try self.asm_register_register_immediate(
            mir_tag,
            dst_alias,
            register_alias(if (src_mcv.is_register())
                src_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(ty, src_mcv), abi_size),
            Immediate.u(@as(u5, @bit_cast(mode))),
        ),
    }
}

fn air_abs(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const ty = self.type_of(ty_op.operand);

    const result: MCValue = result: {
        const mir_tag = @as(?Mir.Inst.FixedTag, switch (ty.zig_type_tag(mod)) {
            else => null,
            .Int => switch (ty.abi_size(mod)) {
                0 => unreachable,
                1...8 => {
                    try self.spill_eflags_if_occupied();
                    const src_mcv = try self.resolve_inst(ty_op.operand);
                    const dst_mcv = try self.copy_to_register_with_inst_tracking(inst, ty, src_mcv);

                    try self.gen_un_op_mir(.{ ._, .neg }, ty, dst_mcv);

                    const cmov_abi_size = @max(@as(u32, @int_cast(ty.abi_size(mod))), 2);
                    switch (src_mcv) {
                        .register => |val_reg| try self.asm_cmovcc_register_register(
                            .l,
                            register_alias(dst_mcv.register, cmov_abi_size),
                            register_alias(val_reg, cmov_abi_size),
                        ),
                        .memory, .indirect, .load_frame => try self.asm_cmovcc_register_memory(
                            .l,
                            register_alias(dst_mcv.register, cmov_abi_size),
                            try src_mcv.mem(self, Memory.Size.from_size(cmov_abi_size)),
                        ),
                        else => {
                            const val_reg = try self.copy_to_tmp_register(ty, src_mcv);
                            try self.asm_cmovcc_register_register(
                                .l,
                                register_alias(dst_mcv.register, cmov_abi_size),
                                register_alias(val_reg, cmov_abi_size),
                            );
                        },
                    }
                    break :result dst_mcv;
                },
                9...16 => {
                    try self.spill_eflags_if_occupied();
                    const src_mcv = try self.resolve_inst(ty_op.operand);
                    const dst_mcv = if (src_mcv == .register_pair and
                        self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) src_mcv else dst: {
                        const dst_regs = try self.register_manager.alloc_regs(
                            2,
                            .{ inst, inst },
                            abi.RegisterClass.gp,
                        );
                        const dst_mcv: MCValue = .{ .register_pair = dst_regs };
                        const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
                        defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

                        try self.gen_copy(ty, dst_mcv, src_mcv, .{});
                        break :dst dst_mcv;
                    };
                    const dst_regs = dst_mcv.register_pair;
                    const dst_locks = self.register_manager.lock_regs(2, dst_regs);
                    defer for (dst_locks) |dst_lock| if (dst_lock) |lock|
                        self.register_manager.unlock_reg(lock);

                    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    try self.asm_register_register(.{ ._, .mov }, tmp_reg, dst_regs[1]);
                    try self.asm_register_immediate(.{ ._r, .sa }, tmp_reg, Immediate.u(63));
                    try self.asm_register_register(.{ ._, .xor }, dst_regs[0], tmp_reg);
                    try self.asm_register_register(.{ ._, .xor }, dst_regs[1], tmp_reg);
                    try self.asm_register_register(.{ ._, .sub }, dst_regs[0], tmp_reg);
                    try self.asm_register_register(.{ ._, .sbb }, dst_regs[1], tmp_reg);

                    break :result dst_mcv;
                },
                else => {
                    const abi_size: u31 = @int_cast(ty.abi_size(mod));
                    const limb_len = math.div_ceil(u31, abi_size, 8) catch unreachable;

                    const tmp_regs =
                        try self.register_manager.alloc_regs(3, .{null} ** 3, abi.RegisterClass.gp);
                    const tmp_locks = self.register_manager.lock_regs_assume_unused(3, tmp_regs);
                    defer for (tmp_locks) |lock| self.register_manager.unlock_reg(lock);

                    try self.spill_eflags_if_occupied();
                    const src_mcv = try self.resolve_inst(ty_op.operand);
                    const dst_mcv = if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                        src_mcv
                    else
                        try self.alloc_reg_or_mem(inst, false);

                    try self.asm_memory_immediate(
                        .{ ._, .cmp },
                        try dst_mcv.address().offset((limb_len - 1) * 8).deref().mem(self, .qword),
                        Immediate.u(0),
                    );
                    const positive = try self.asm_jcc_reloc(.ns, undefined);

                    try self.asm_register_register(.{ ._, .xor }, tmp_regs[0].to32(), tmp_regs[0].to32());
                    try self.asm_register_register(.{ ._, .xor }, tmp_regs[1].to8(), tmp_regs[1].to8());

                    const neg_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                    try self.asm_register_register(.{ ._, .xor }, tmp_regs[2].to32(), tmp_regs[2].to32());
                    try self.asm_register_immediate(.{ ._r, .sh }, tmp_regs[1].to8(), Immediate.u(1));
                    try self.asm_register_memory(.{ ._, .sbb }, tmp_regs[2].to64(), .{
                        .base = .{ .frame = dst_mcv.load_frame.index },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .index = tmp_regs[0].to64(),
                            .scale = .@"8",
                            .disp = dst_mcv.load_frame.off,
                        } },
                    });
                    try self.asm_setcc_register(.c, tmp_regs[1].to8());
                    try self.asm_memory_register(.{ ._, .mov }, .{
                        .base = .{ .frame = dst_mcv.load_frame.index },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .index = tmp_regs[0].to64(),
                            .scale = .@"8",
                            .disp = dst_mcv.load_frame.off,
                        } },
                    }, tmp_regs[2].to64());

                    if (self.has_feature(.slow_incdec)) {
                        try self.asm_register_immediate(.{ ._, .add }, tmp_regs[0].to32(), Immediate.u(1));
                    } else {
                        try self.asm_register(.{ ._, .inc }, tmp_regs[0].to32());
                    }
                    try self.asm_register_immediate(.{ ._, .cmp }, tmp_regs[0].to32(), Immediate.u(limb_len));
                    _ = try self.asm_jcc_reloc(.b, neg_loop);

                    self.perform_reloc(positive);
                    break :result dst_mcv;
                },
            },
            .Float => return self.float_sign(inst, ty_op.operand, ty),
            .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                else => null,
                .Int => switch (ty.child_type(mod).int_info(mod).bits) {
                    else => null,
                    8 => switch (ty.vector_len(mod)) {
                        else => null,
                        1...16 => if (self.has_feature(.avx))
                            .{ .vp_b, .abs }
                        else if (self.has_feature(.ssse3))
                            .{ .p_b, .abs }
                        else
                            null,
                        17...32 => if (self.has_feature(.avx2)) .{ .vp_b, .abs } else null,
                    },
                    16 => switch (ty.vector_len(mod)) {
                        else => null,
                        1...8 => if (self.has_feature(.avx))
                            .{ .vp_w, .abs }
                        else if (self.has_feature(.ssse3))
                            .{ .p_w, .abs }
                        else
                            null,
                        9...16 => if (self.has_feature(.avx2)) .{ .vp_w, .abs } else null,
                    },
                    32 => switch (ty.vector_len(mod)) {
                        else => null,
                        1...4 => if (self.has_feature(.avx))
                            .{ .vp_d, .abs }
                        else if (self.has_feature(.ssse3))
                            .{ .p_d, .abs }
                        else
                            null,
                        5...8 => if (self.has_feature(.avx2)) .{ .vp_d, .abs } else null,
                    },
                },
                .Float => return self.float_sign(inst, ty_op.operand, ty),
            },
        }) orelse return self.fail("TODO implement air_abs for {}", .{ty.fmt(mod)});

        const abi_size: u32 = @int_cast(ty.abi_size(mod));
        const src_mcv = try self.resolve_inst(ty_op.operand);
        const dst_reg = if (src_mcv.is_register() and self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
            src_mcv.get_reg().?
        else
            try self.register_manager.alloc_reg(inst, self.reg_class_for_type(ty));
        const dst_alias = register_alias(dst_reg, abi_size);
        if (src_mcv.is_memory()) try self.asm_register_memory(
            mir_tag,
            dst_alias,
            try src_mcv.mem(self, self.mem_size(ty)),
        ) else try self.asm_register_register(
            mir_tag,
            dst_alias,
            register_alias(if (src_mcv.is_register())
                src_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(ty, src_mcv), abi_size),
        );
        break :result .{ .register = dst_reg };
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_sqrt(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ty = self.type_of(un_op);
    const abi_size: u32 = @int_cast(ty.abi_size(mod));

    const result: MCValue = result: {
        switch (ty.zig_type_tag(mod)) {
            .Float => {
                const float_bits = ty.float_bits(self.target.*);
                if (switch (float_bits) {
                    16 => !self.has_feature(.f16c),
                    32, 64 => false,
                    80, 128 => true,
                    else => unreachable,
                }) {
                    var callee_buf: ["__sqrt?".len]u8 = undefined;
                    break :result try self.gen_call(.{ .lib = .{
                        .return_type = ty.to_intern(),
                        .param_types = &.{ty.to_intern()},
                        .callee = std.fmt.buf_print(&callee_buf, "{s}sqrt{s}", .{
                            float_libc_abi_prefix(ty),
                            float_libc_abi_suffix(ty),
                        }) catch unreachable,
                    } }, &.{ty}, &.{.{ .air_ref = un_op }});
                }
            },
            else => {},
        }

        const src_mcv = try self.resolve_inst(un_op);
        const dst_mcv = if (src_mcv.is_register() and self.reuse_operand(inst, un_op, 0, src_mcv))
            src_mcv
        else
            try self.copy_to_register_with_inst_tracking(inst, ty, src_mcv);
        const dst_reg = register_alias(dst_mcv.get_reg().?, abi_size);
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const mir_tag = @as(?Mir.Inst.FixedTag, switch (ty.zig_type_tag(mod)) {
            .Float => switch (ty.float_bits(self.target.*)) {
                16 => {
                    assert(self.has_feature(.f16c));
                    const mat_src_reg = if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(ty, src_mcv);
                    try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, mat_src_reg.to128());
                    try self.asm_register_register_register(.{ .v_ss, .sqrt }, dst_reg, dst_reg, dst_reg);
                    try self.asm_register_register_immediate(
                        .{ .v_, .cvtps2ph },
                        dst_reg,
                        dst_reg,
                        Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                    );
                    break :result dst_mcv;
                },
                32 => if (self.has_feature(.avx)) .{ .v_ss, .sqrt } else .{ ._ss, .sqrt },
                64 => if (self.has_feature(.avx)) .{ .v_sd, .sqrt } else .{ ._sd, .sqrt },
                else => unreachable,
            },
            .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                    16 => if (self.has_feature(.f16c)) switch (ty.vector_len(mod)) {
                        1 => {
                            try self.asm_register_register(
                                .{ .v_ps, .cvtph2 },
                                dst_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register_register(
                                .{ .v_ss, .sqrt },
                                dst_reg,
                                dst_reg,
                                dst_reg,
                            );
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                dst_reg,
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            break :result dst_mcv;
                        },
                        2...8 => {
                            const wide_reg = register_alias(dst_reg, abi_size * 2);
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                .{ .v_ps, .cvtph2 },
                                wide_reg,
                                try src_mcv.mem(self, Memory.Size.from_size(
                                    @int_cast(@div_exact(wide_reg.bit_size(), 16)),
                                )),
                            ) else try self.asm_register_register(
                                .{ .v_ps, .cvtph2 },
                                wide_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register(.{ .v_ps, .sqrt }, wide_reg, wide_reg);
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                wide_reg,
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            break :result dst_mcv;
                        },
                        else => null,
                    } else null,
                    32 => switch (ty.vector_len(mod)) {
                        1 => if (self.has_feature(.avx)) .{ .v_ss, .sqrt } else .{ ._ss, .sqrt },
                        2...4 => if (self.has_feature(.avx)) .{ .v_ps, .sqrt } else .{ ._ps, .sqrt },
                        5...8 => if (self.has_feature(.avx)) .{ .v_ps, .sqrt } else null,
                        else => null,
                    },
                    64 => switch (ty.vector_len(mod)) {
                        1 => if (self.has_feature(.avx)) .{ .v_sd, .sqrt } else .{ ._sd, .sqrt },
                        2 => if (self.has_feature(.avx)) .{ .v_pd, .sqrt } else .{ ._pd, .sqrt },
                        3...4 => if (self.has_feature(.avx)) .{ .v_pd, .sqrt } else null,
                        else => null,
                    },
                    80, 128 => null,
                    else => unreachable,
                },
                else => unreachable,
            },
            else => unreachable,
        }) orelse return self.fail("TODO implement air_sqrt for {}", .{
            ty.fmt(mod),
        });
        switch (mir_tag[0]) {
            .v_ss, .v_sd => if (src_mcv.is_memory()) try self.asm_register_register_memory(
                mir_tag,
                dst_reg,
                dst_reg,
                try src_mcv.mem(self, Memory.Size.from_size(abi_size)),
            ) else try self.asm_register_register_register(
                mir_tag,
                dst_reg,
                dst_reg,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(ty, src_mcv), abi_size),
            ),
            else => if (src_mcv.is_memory()) try self.asm_register_memory(
                mir_tag,
                dst_reg,
                try src_mcv.mem(self, Memory.Size.from_size(abi_size)),
            ) else try self.asm_register_register(
                mir_tag,
                dst_reg,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(ty, src_mcv), abi_size),
            ),
        }
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_unary_math(self: *Self, inst: Air.Inst.Index, tag: Air.Inst.Tag) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ty = self.type_of(un_op);
    var callee_buf: ["__round?".len]u8 = undefined;
    const result = try self.gen_call(.{ .lib = .{
        .return_type = ty.to_intern(),
        .param_types = &.{ty.to_intern()},
        .callee = std.fmt.buf_print(&callee_buf, "{s}{s}{s}", .{
            float_libc_abi_prefix(ty),
            switch (tag) {
                .sin,
                .cos,
                .tan,
                .exp,
                .exp2,
                .log,
                .log2,
                .log10,
                .round,
                => @tag_name(tag),
                else => unreachable,
            },
            float_libc_abi_suffix(ty),
        }) catch unreachable,
    } }, &.{ty}, &.{.{ .air_ref = un_op }});
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
        .register, .register_pair, .register_overflow => for (mcv.get_regs()) |reg| {
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
    switch (mcv) {
        .eflags, .register_overflow => self.eflags_inst = maybe_tracked_inst,
        else => {},
    }

    // Prevent the operand deaths processing code from deallocating it.
    self.liveness.clear_operand_death(inst, op_index);
    const op_inst = operand.to_index().?;
    self.get_resolved_inst_value(op_inst).reuse(self, maybe_tracked_inst, op_inst);

    return true;
}

fn packed_load(self: *Self, dst_mcv: MCValue, ptr_ty: Type, ptr_mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;

    const ptr_info = ptr_ty.ptr_info(mod);
    const val_ty = Type.from_interned(ptr_info.child);
    if (!val_ty.has_runtime_bits_ignore_comptime(mod)) return;
    const val_abi_size: u32 = @int_cast(val_ty.abi_size(mod));

    const val_bit_size: u32 = @int_cast(val_ty.bit_size(mod));
    const ptr_bit_off = ptr_info.packed_offset.bit_offset + switch (ptr_info.flags.vector_index) {
        .none => 0,
        .runtime => unreachable,
        else => |vector_index| @int_from_enum(vector_index) * val_bit_size,
    };
    if (ptr_bit_off % 8 == 0) {
        {
            const mat_ptr_mcv: MCValue = switch (ptr_mcv) {
                .immediate, .register, .register_offset, .lea_frame => ptr_mcv,
                else => .{ .register = try self.copy_to_tmp_register(ptr_ty, ptr_mcv) },
            };
            const mat_ptr_lock = switch (mat_ptr_mcv) {
                .register => |mat_ptr_reg| self.register_manager.lock_reg(mat_ptr_reg),
                else => null,
            };
            defer if (mat_ptr_lock) |lock| self.register_manager.unlock_reg(lock);

            try self.load(dst_mcv, ptr_ty, mat_ptr_mcv.offset(@int_cast(@div_exact(ptr_bit_off, 8))));
        }

        if (val_abi_size * 8 > val_bit_size) {
            if (dst_mcv.is_register()) {
                try self.truncate_register(val_ty, dst_mcv.get_reg().?);
            } else {
                const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                const hi_mcv = dst_mcv.address().offset(@int_cast(val_bit_size / 64 * 8)).deref();
                try self.gen_set_reg(tmp_reg, Type.usize, hi_mcv, .{});
                try self.truncate_register(val_ty, tmp_reg);
                try self.gen_copy(Type.usize, hi_mcv, .{ .register = tmp_reg }, .{});
            }
        }
        return;
    }

    if (val_abi_size > 8) return self.fail("TODO implement packed load of {}", .{val_ty.fmt(mod)});

    const limb_abi_size: u31 = @min(val_abi_size, 8);
    const limb_abi_bits = limb_abi_size * 8;
    const val_byte_off: i32 = @int_cast(ptr_bit_off / limb_abi_bits * limb_abi_size);
    const val_bit_off = ptr_bit_off % limb_abi_bits;
    const val_extra_bits = self.reg_extra_bits(val_ty);

    const ptr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
    const ptr_lock = self.register_manager.lock_reg_assume_unused(ptr_reg);
    defer self.register_manager.unlock_reg(ptr_lock);

    const dst_reg = switch (dst_mcv) {
        .register => |reg| reg,
        else => try self.register_manager.alloc_reg(null, abi.RegisterClass.gp),
    };
    const dst_lock = self.register_manager.lock_reg(dst_reg);
    defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

    const load_abi_size =
        if (val_bit_off < val_extra_bits) val_abi_size else val_abi_size * 2;
    if (load_abi_size <= 8) {
        const load_reg = register_alias(dst_reg, load_abi_size);
        try self.asm_register_memory(.{ ._, .mov }, load_reg, .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(load_abi_size),
                .disp = val_byte_off,
            } },
        });
        try self.spill_eflags_if_occupied();
        try self.asm_register_immediate(.{ ._r, .sh }, load_reg, Immediate.u(val_bit_off));
    } else {
        const tmp_reg =
            register_alias(try self.register_manager.alloc_reg(null, abi.RegisterClass.gp), val_abi_size);
        const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
        defer self.register_manager.unlock_reg(tmp_lock);

        const dst_alias = register_alias(dst_reg, val_abi_size);
        try self.asm_register_memory(.{ ._, .mov }, dst_alias, .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(val_abi_size),
                .disp = val_byte_off,
            } },
        });
        try self.asm_register_memory(.{ ._, .mov }, tmp_reg, .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(val_abi_size),
                .disp = val_byte_off + limb_abi_size,
            } },
        });
        try self.spill_eflags_if_occupied();
        try self.asm_register_register_immediate(
            .{ ._rd, .sh },
            dst_alias,
            tmp_reg,
            Immediate.u(val_bit_off),
        );
    }

    if (val_extra_bits > 0) try self.truncate_register(val_ty, dst_reg);
    try self.gen_copy(val_ty, dst_mcv, .{ .register = dst_reg }, .{});
}

fn load(self: *Self, dst_mcv: MCValue, ptr_ty: Type, ptr_mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const dst_ty = ptr_ty.child_type(mod);
    if (!dst_ty.has_runtime_bits_ignore_comptime(mod)) return;
    switch (ptr_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .eflags,
        .register_pair,
        .register_overflow,
        .elementwise_regs_then_frame,
        .reserved_frame,
        => unreachable, // not a valid pointer
        .immediate,
        .register,
        .register_offset,
        .lea_symbol,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        => try self.gen_copy(dst_ty, dst_mcv, ptr_mcv.deref(), .{}),
        .memory,
        .indirect,
        .load_symbol,
        .load_direct,
        .load_got,
        .load_tlv,
        .load_frame,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try self.gen_copy(dst_ty, dst_mcv, .{ .indirect = .{ .reg = addr_reg } }, .{});
        },
        .air_ref => |ptr_ref| try self.load(dst_mcv, ptr_ty, try self.resolve_inst(ptr_ref)),
    }
}

fn air_load(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const elem_ty = self.type_of_index(inst);
    const result: MCValue = result: {
        if (!elem_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;

        try self.spill_registers(&.{ .rdi, .rsi, .rcx });
        const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rdi, .rsi, .rcx });
        defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

        const ptr_ty = self.type_of(ty_op.operand);
        const elem_size = elem_ty.abi_size(mod);

        const elem_rc = self.reg_class_for_type(elem_ty);
        const ptr_rc = self.reg_class_for_type(ptr_ty);

        const ptr_mcv = try self.resolve_inst(ty_op.operand);
        const dst_mcv = if (elem_size <= 8 and elem_rc.superset_of(ptr_rc) and
            self.reuse_operand(inst, ty_op.operand, 0, ptr_mcv))
            // The MCValue that holds the pointer can be re-used as the value.
            ptr_mcv
        else
            try self.alloc_reg_or_mem(inst, true);

        const ptr_info = ptr_ty.ptr_info(mod);
        if (ptr_info.flags.vector_index != .none or ptr_info.packed_offset.host_size > 0) {
            try self.packed_load(dst_mcv, ptr_ty, ptr_mcv);
        } else {
            try self.load(dst_mcv, ptr_ty, ptr_mcv);
        }

        if (elem_ty.is_abi_int(mod) and elem_size * 8 > elem_ty.bit_size(mod)) {
            const high_mcv: MCValue = switch (dst_mcv) {
                .register => |dst_reg| .{ .register = dst_reg },
                .register_pair => |dst_regs| .{ .register = dst_regs[1] },
                else => dst_mcv.address().offset(@int_cast((elem_size - 1) / 8 * 8)).deref(),
            };
            const high_reg = if (high_mcv.is_register())
                high_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(Type.usize, high_mcv);
            const high_lock = self.register_manager.lock_reg(high_reg);
            defer if (high_lock) |lock| self.register_manager.unlock_reg(lock);

            try self.truncate_register(elem_ty, high_reg);
            if (!high_mcv.is_register()) try self.gen_copy(
                if (elem_size <= 8) elem_ty else Type.usize,
                high_mcv,
                .{ .register = high_reg },
                .{},
            );
        }
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn packed_store(self: *Self, ptr_ty: Type, ptr_mcv: MCValue, src_mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const ptr_info = ptr_ty.ptr_info(mod);
    const src_ty = Type.from_interned(ptr_info.child);
    if (!src_ty.has_runtime_bits_ignore_comptime(mod)) return;

    const limb_abi_size: u16 = @min(ptr_info.packed_offset.host_size, 8);
    const limb_abi_bits = limb_abi_size * 8;
    const limb_ty = try mod.int_type(.unsigned, limb_abi_bits);

    const src_bit_size = src_ty.bit_size(mod);
    const ptr_bit_off = ptr_info.packed_offset.bit_offset + switch (ptr_info.flags.vector_index) {
        .none => 0,
        .runtime => unreachable,
        else => |vector_index| @int_from_enum(vector_index) * src_bit_size,
    };
    const src_byte_off: i32 = @int_cast(ptr_bit_off / limb_abi_bits * limb_abi_size);
    const src_bit_off = ptr_bit_off % limb_abi_bits;

    const ptr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
    const ptr_lock = self.register_manager.lock_reg_assume_unused(ptr_reg);
    defer self.register_manager.unlock_reg(ptr_lock);

    var limb_i: u16 = 0;
    while (limb_i * limb_abi_bits < src_bit_off + src_bit_size) : (limb_i += 1) {
        const part_bit_off = if (limb_i == 0) src_bit_off else 0;
        const part_bit_size =
            @min(src_bit_off + src_bit_size - limb_i * limb_abi_bits, limb_abi_bits) - part_bit_off;
        const limb_mem: Memory = .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(limb_abi_size),
                .disp = src_byte_off + limb_i * limb_abi_size,
            } },
        };

        const part_mask = (@as(u64, math.max_int(u64)) >> @int_cast(64 - part_bit_size)) <<
            @int_cast(part_bit_off);
        const part_mask_not = part_mask ^ (@as(u64, math.max_int(u64)) >> @int_cast(64 - limb_abi_bits));
        if (limb_abi_size <= 4) {
            try self.asm_memory_immediate(.{ ._, .@"and" }, limb_mem, Immediate.u(part_mask_not));
        } else if (math.cast(i32, @as(i64, @bit_cast(part_mask_not)))) |small| {
            try self.asm_memory_immediate(.{ ._, .@"and" }, limb_mem, Immediate.s(small));
        } else {
            const part_mask_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            try self.asm_register_immediate(.{ ._, .mov }, part_mask_reg, Immediate.u(part_mask_not));
            try self.asm_memory_register(.{ ._, .@"and" }, limb_mem, part_mask_reg);
        }

        if (src_bit_size <= 64) {
            const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const tmp_mcv = MCValue{ .register = tmp_reg };
            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
            defer self.register_manager.unlock_reg(tmp_lock);

            try self.gen_set_reg(tmp_reg, limb_ty, src_mcv, .{});
            switch (limb_i) {
                0 => try self.gen_shift_bin_op_mir(
                    .{ ._l, .sh },
                    limb_ty,
                    tmp_mcv,
                    Type.u8,
                    .{ .immediate = src_bit_off },
                ),
                1 => try self.gen_shift_bin_op_mir(
                    .{ ._r, .sh },
                    limb_ty,
                    tmp_mcv,
                    Type.u8,
                    .{ .immediate = limb_abi_bits - src_bit_off },
                ),
                else => unreachable,
            }
            try self.gen_bin_op_mir(.{ ._, .@"and" }, limb_ty, tmp_mcv, .{ .immediate = part_mask });
            try self.asm_memory_register(
                .{ ._, .@"or" },
                limb_mem,
                register_alias(tmp_reg, limb_abi_size),
            );
        } else if (src_bit_size <= 128 and src_bit_off == 0) {
            const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const tmp_mcv = MCValue{ .register = tmp_reg };
            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
            defer self.register_manager.unlock_reg(tmp_lock);

            try self.gen_set_reg(tmp_reg, limb_ty, switch (limb_i) {
                0 => src_mcv,
                else => src_mcv.address().offset(limb_i * limb_abi_size).deref(),
            }, .{});
            try self.gen_bin_op_mir(.{ ._, .@"and" }, limb_ty, tmp_mcv, .{ .immediate = part_mask });
            try self.asm_memory_register(
                .{ ._, .@"or" },
                limb_mem,
                register_alias(tmp_reg, limb_abi_size),
            );
        } else return self.fail("TODO: implement packed store of {}", .{src_ty.fmt(mod)});
    }
}

fn store(
    self: *Self,
    ptr_ty: Type,
    ptr_mcv: MCValue,
    src_mcv: MCValue,
    opts: CopyOptions,
) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const src_ty = ptr_ty.child_type(mod);
    if (!src_ty.has_runtime_bits_ignore_comptime(mod)) return;
    switch (ptr_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .eflags,
        .register_pair,
        .register_overflow,
        .elementwise_regs_then_frame,
        .reserved_frame,
        => unreachable, // not a valid pointer
        .immediate,
        .register,
        .register_offset,
        .lea_symbol,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        => try self.gen_copy(src_ty, ptr_mcv.deref(), src_mcv, opts),
        .memory,
        .indirect,
        .load_symbol,
        .load_direct,
        .load_got,
        .load_tlv,
        .load_frame,
        => {
            const addr_reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv);
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try self.gen_copy(src_ty, .{ .indirect = .{ .reg = addr_reg } }, src_mcv, opts);
        },
        .air_ref => |ptr_ref| try self.store(ptr_ty, try self.resolve_inst(ptr_ref), src_mcv, opts),
    }
}

fn air_store(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    result: {
        if (!safety and (try self.resolve_inst(bin_op.rhs)) == .undef) break :result;

        try self.spill_registers(&.{ .rdi, .rsi, .rcx });
        const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rdi, .rsi, .rcx });
        defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

        const src_mcv = try self.resolve_inst(bin_op.rhs);
        const ptr_mcv = try self.resolve_inst(bin_op.lhs);
        const ptr_ty = self.type_of(bin_op.lhs);

        const ptr_info = ptr_ty.ptr_info(mod);
        if (ptr_info.flags.vector_index != .none or ptr_info.packed_offset.host_size > 0) {
            try self.packed_store(ptr_ty, ptr_mcv, src_mcv);
        } else {
            try self.store(ptr_ty, ptr_mcv, src_mcv, .{ .safety = safety });
        }
    }
    return self.finish_air(inst, .none, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_struct_field_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
    const result = try self.field_ptr(inst, extra.struct_operand, extra.field_index);
    return self.finish_air(inst, result, .{ extra.struct_operand, .none, .none });
}

fn air_struct_field_ptr_index(self: *Self, inst: Air.Inst.Index, index: u8) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const result = try self.field_ptr(inst, ty_op.operand, index);
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn field_ptr(self: *Self, inst: Air.Inst.Index, operand: Air.Inst.Ref, index: u32) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const ptr_field_ty = self.type_of_index(inst);
    const ptr_container_ty = self.type_of(operand);
    const container_ty = ptr_container_ty.child_type(mod);

    const field_off: i32 = switch (container_ty.container_layout(mod)) {
        .auto, .@"extern" => @int_cast(container_ty.struct_field_offset(index, mod)),
        .@"packed" => @div_exact(@as(i32, ptr_container_ty.ptr_info(mod).packed_offset.bit_offset) +
            (if (mod.type_to_struct(container_ty)) |struct_obj| mod.struct_packed_field_bit_offset(struct_obj, index) else 0) -
            ptr_field_ty.ptr_info(mod).packed_offset.bit_offset, 8),
    };

    const src_mcv = try self.resolve_inst(operand);
    const dst_mcv = if (switch (src_mcv) {
        .immediate, .lea_frame => true,
        .register, .register_offset => self.reuse_operand(inst, operand, 0, src_mcv),
        else => false,
    }) src_mcv else try self.copy_to_register_with_inst_tracking(inst, ptr_field_ty, src_mcv);
    return dst_mcv.offset(field_off);
}

fn air_struct_field_val(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
    const result: MCValue = result: {
        const operand = extra.struct_operand;
        const index = extra.field_index;

        const container_ty = self.type_of(operand);
        const container_rc = self.reg_class_for_type(container_ty);
        const field_ty = container_ty.struct_field_type(index, mod);
        if (!field_ty.has_runtime_bits_ignore_comptime(mod)) break :result .none;
        const field_rc = self.reg_class_for_type(field_ty);
        const field_is_gp = field_rc.superset_of(abi.RegisterClass.gp);

        const src_mcv = try self.resolve_inst(operand);
        const field_off: u32 = switch (container_ty.container_layout(mod)) {
            .auto, .@"extern" => @int_cast(container_ty.struct_field_offset(extra.field_index, mod) * 8),
            .@"packed" => if (mod.type_to_struct(container_ty)) |struct_obj| mod.struct_packed_field_bit_offset(struct_obj, extra.field_index) else 0,
        };

        switch (src_mcv) {
            .register => |src_reg| {
                const src_reg_lock = self.register_manager.lock_reg_assume_unused(src_reg);
                defer self.register_manager.unlock_reg(src_reg_lock);

                const src_in_field_rc =
                    field_rc.is_set(RegisterManager.index_of_reg_into_tracked(src_reg).?);
                const dst_reg = if (src_in_field_rc and self.reuse_operand(inst, operand, 0, src_mcv))
                    src_reg
                else if (field_off == 0)
                    (try self.copy_to_register_with_inst_tracking(inst, field_ty, src_mcv)).register
                else
                    try self.copy_to_tmp_register(Type.usize, .{ .register = src_reg });
                const dst_mcv: MCValue = .{ .register = dst_reg };
                const dst_lock = self.register_manager.lock_reg(dst_reg);
                defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

                if (field_off > 0) {
                    try self.spill_eflags_if_occupied();
                    try self.gen_shift_bin_op_mir(
                        .{ ._r, .sh },
                        Type.usize,
                        dst_mcv,
                        Type.u8,
                        .{ .immediate = field_off },
                    );
                }
                if (abi.RegisterClass.gp.is_set(RegisterManager.index_of_reg_into_tracked(dst_reg).?) and
                    container_ty.abi_size(mod) * 8 > field_ty.bit_size(mod))
                    try self.truncate_register(field_ty, dst_reg);

                break :result if (field_off == 0 or field_rc.superset_of(abi.RegisterClass.gp))
                    dst_mcv
                else
                    try self.copy_to_register_with_inst_tracking(inst, field_ty, dst_mcv);
            },
            .register_pair => |src_regs| {
                const src_regs_lock = self.register_manager.lock_regs_assume_unused(2, src_regs);
                defer for (src_regs_lock) |lock| self.register_manager.unlock_reg(lock);

                const field_bit_size: u32 = @int_cast(field_ty.bit_size(mod));
                const src_reg = if (field_off + field_bit_size <= 64)
                    src_regs[0]
                else if (field_off >= 64)
                    src_regs[1]
                else {
                    const dst_regs: [2]Register = if (field_rc.superset_of(container_rc) and
                        self.reuse_operand(inst, operand, 0, src_mcv)) src_regs else dst: {
                        const dst_regs =
                            try self.register_manager.alloc_regs(2, .{null} ** 2, field_rc);
                        const dst_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
                        defer for (dst_locks) |lock| self.register_manager.unlock_reg(lock);

                        try self.gen_copy(container_ty, .{ .register_pair = dst_regs }, src_mcv, .{});
                        break :dst dst_regs;
                    };
                    const dst_mcv = MCValue{ .register_pair = dst_regs };
                    const dst_locks = self.register_manager.lock_regs(2, dst_regs);
                    defer for (dst_locks) |dst_lock| if (dst_lock) |lock|
                        self.register_manager.unlock_reg(lock);

                    if (field_off > 0) {
                        try self.spill_eflags_if_occupied();
                        try self.gen_shift_bin_op_mir(
                            .{ ._r, .sh },
                            Type.u128,
                            dst_mcv,
                            Type.u8,
                            .{ .immediate = field_off },
                        );
                    }

                    if (field_bit_size <= 64) {
                        if (self.reg_extra_bits(field_ty) > 0)
                            try self.truncate_register(field_ty, dst_regs[0]);
                        break :result if (field_rc.superset_of(abi.RegisterClass.gp))
                            .{ .register = dst_regs[0] }
                        else
                            try self.copy_to_register_with_inst_tracking(inst, field_ty, .{
                                .register = dst_regs[0],
                            });
                    }

                    if (field_bit_size < 128) try self.truncate_register(
                        try mod.int_type(.unsigned, @int_cast(field_bit_size - 64)),
                        dst_regs[1],
                    );
                    break :result if (field_rc.superset_of(abi.RegisterClass.gp))
                        dst_mcv
                    else
                        try self.copy_to_register_with_inst_tracking(inst, field_ty, dst_mcv);
                };

                const dst_reg = try self.copy_to_tmp_register(Type.usize, .{ .register = src_reg });
                const dst_mcv = MCValue{ .register = dst_reg };
                const dst_lock = self.register_manager.lock_reg(dst_reg);
                defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

                if (field_off % 64 > 0) {
                    try self.spill_eflags_if_occupied();
                    try self.gen_shift_bin_op_mir(
                        .{ ._r, .sh },
                        Type.usize,
                        dst_mcv,
                        Type.u8,
                        .{ .immediate = field_off % 64 },
                    );
                }
                if (self.reg_extra_bits(field_ty) > 0) try self.truncate_register(field_ty, dst_reg);

                break :result if (field_rc.superset_of(abi.RegisterClass.gp))
                    dst_mcv
                else
                    try self.copy_to_register_with_inst_tracking(inst, field_ty, dst_mcv);
            },
            .register_overflow => |ro| {
                switch (index) {
                    // Get wrapped value for overflow operation.
                    0 => if (self.reuse_operand(inst, extra.struct_operand, 0, src_mcv)) {
                        self.eflags_inst = null; // actually stop tracking the overflow part
                        break :result .{ .register = ro.reg };
                    } else break :result try self.copy_to_register_with_inst_tracking(
                        inst,
                        Type.usize,
                        .{ .register = ro.reg },
                    ),
                    // Get overflow bit.
                    1 => if (self.reuse_operand_advanced(inst, extra.struct_operand, 0, src_mcv, null)) {
                        self.eflags_inst = inst; // actually keep tracking the overflow part
                        break :result .{ .eflags = ro.eflags };
                    } else {
                        const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
                        try self.asm_setcc_register(ro.eflags, dst_reg.to8());
                        break :result .{ .register = dst_reg.to8() };
                    },
                    else => unreachable,
                }
            },
            .load_frame => |frame_addr| {
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

                        const dst_reg = try self.register_manager.alloc_reg(
                            if (field_is_gp) inst else null,
                            abi.RegisterClass.gp,
                        );
                        const dst_mcv = MCValue{ .register = dst_reg };
                        const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
                        defer self.register_manager.unlock_reg(dst_lock);

                        try self.gen_copy(int_ty, dst_mcv, off_mcv, .{});
                        if (self.reg_extra_bits(field_ty) > 0) try self.truncate_register(int_ty, dst_reg);
                        break :result if (field_is_gp)
                            dst_mcv
                        else
                            try self.copy_to_register_with_inst_tracking(inst, field_ty, dst_mcv);
                    }

                    const container_abi_size: u32 = @int_cast(container_ty.abi_size(mod));
                    const dst_mcv = if (field_byte_off + field_abi_size <= container_abi_size and
                        self.reuse_operand(inst, operand, 0, src_mcv))
                        off_mcv
                    else dst: {
                        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                        try self.gen_copy(field_ty, dst_mcv, off_mcv, .{});
                        break :dst dst_mcv;
                    };
                    if (field_abi_size * 8 > field_bit_size and dst_mcv.is_memory()) {
                        const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                        const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                        defer self.register_manager.unlock_reg(tmp_lock);

                        const hi_mcv =
                            dst_mcv.address().offset(@int_cast(field_bit_size / 64 * 8)).deref();
                        try self.gen_set_reg(tmp_reg, Type.usize, hi_mcv, .{});
                        try self.truncate_register(field_ty, tmp_reg);
                        try self.gen_copy(Type.usize, hi_mcv, .{ .register = tmp_reg }, .{});
                    }
                    break :result dst_mcv;
                }

                const limb_abi_size: u31 = @min(field_abi_size, 8);
                const limb_abi_bits = limb_abi_size * 8;
                const field_byte_off: i32 = @int_cast(field_off / limb_abi_bits * limb_abi_size);
                const field_bit_off = field_off % limb_abi_bits;

                if (field_abi_size > 8) {
                    return self.fail("TODO implement struct_field_val with large packed field", .{});
                }

                const dst_reg = try self.register_manager.alloc_reg(
                    if (field_is_gp) inst else null,
                    abi.RegisterClass.gp,
                );
                const field_extra_bits = self.reg_extra_bits(field_ty);
                const load_abi_size =
                    if (field_bit_off < field_extra_bits) field_abi_size else field_abi_size * 2;
                if (load_abi_size <= 8) {
                    const load_reg = register_alias(dst_reg, load_abi_size);
                    try self.asm_register_memory(.{ ._, .mov }, load_reg, .{
                        .base = .{ .frame = frame_addr.index },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(load_abi_size),
                            .disp = frame_addr.off + field_byte_off,
                        } },
                    });
                    try self.spill_eflags_if_occupied();
                    try self.asm_register_immediate(.{ ._r, .sh }, load_reg, Immediate.u(field_bit_off));
                } else {
                    const tmp_reg = register_alias(
                        try self.register_manager.alloc_reg(null, abi.RegisterClass.gp),
                        field_abi_size,
                    );
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    const dst_alias = register_alias(dst_reg, field_abi_size);
                    try self.asm_register_memory(
                        .{ ._, .mov },
                        dst_alias,
                        .{
                            .base = .{ .frame = frame_addr.index },
                            .mod = .{ .rm = .{
                                .size = Memory.Size.from_size(field_abi_size),
                                .disp = frame_addr.off + field_byte_off,
                            } },
                        },
                    );
                    try self.asm_register_memory(.{ ._, .mov }, tmp_reg, .{
                        .base = .{ .frame = frame_addr.index },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(field_abi_size),
                            .disp = frame_addr.off + field_byte_off + limb_abi_size,
                        } },
                    });
                    try self.spill_eflags_if_occupied();
                    try self.asm_register_register_immediate(
                        .{ ._rd, .sh },
                        dst_alias,
                        tmp_reg,
                        Immediate.u(field_bit_off),
                    );
                }

                if (field_extra_bits > 0) try self.truncate_register(field_ty, dst_reg);

                const dst_mcv = MCValue{ .register = dst_reg };
                break :result if (field_is_gp)
                    dst_mcv
                else
                    try self.copy_to_register_with_inst_tracking(inst, field_ty, dst_mcv);
            },
            else => return self.fail("TODO implement air_struct_field_val for {}", .{src_mcv}),
        }
    };
    return self.finish_air(inst, result, .{ extra.struct_operand, .none, .none });
}

fn air_field_parent_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;

    const inst_ty = self.type_of_index(inst);
    const parent_ty = inst_ty.child_type(mod);
    const field_off: i32 = switch (parent_ty.container_layout(mod)) {
        .auto, .@"extern" => @int_cast(parent_ty.struct_field_offset(extra.field_index, mod)),
        .@"packed" => @div_exact(@as(i32, inst_ty.ptr_info(mod).packed_offset.bit_offset) +
            (if (mod.type_to_struct(parent_ty)) |struct_obj| mod.struct_packed_field_bit_offset(struct_obj, extra.field_index) else 0) -
            self.type_of(extra.field_ptr).ptr_info(mod).packed_offset.bit_offset, 8),
    };

    const src_mcv = try self.resolve_inst(extra.field_ptr);
    const dst_mcv = if (src_mcv.is_register_offset() and
        self.reuse_operand(inst, extra.field_ptr, 0, src_mcv))
        src_mcv
    else
        try self.copy_to_register_with_inst_tracking(inst, inst_ty, src_mcv);
    const result = dst_mcv.offset(-field_off);
    return self.finish_air(inst, result, .{ extra.field_ptr, .none, .none });
}

fn gen_un_op(self: *Self, maybe_inst: ?Air.Inst.Index, tag: Air.Inst.Tag, src_air: Air.Inst.Ref) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const src_ty = self.type_of(src_air);
    if (src_ty.zig_type_tag(mod) == .Vector)
        return self.fail("TODO implement gen_un_op for {}", .{src_ty.fmt(mod)});

    var src_mcv = try self.resolve_inst(src_air);
    switch (src_mcv) {
        .eflags => |cc| switch (tag) {
            .not => {
                if (maybe_inst) |inst| if (self.reuse_operand(inst, src_air, 0, src_mcv))
                    return .{ .eflags = cc.negate() };
                try self.spill_eflags_if_occupied();
                src_mcv = try self.resolve_inst(src_air);
            },
            else => {},
        },
        else => {},
    }

    const src_lock = switch (src_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

    const dst_mcv: MCValue = dst: {
        if (maybe_inst) |inst| if (self.reuse_operand(inst, src_air, 0, src_mcv)) break :dst src_mcv;

        const dst_mcv = try self.alloc_reg_or_mem_advanced(src_ty, maybe_inst, true);
        try self.gen_copy(src_ty, dst_mcv, src_mcv, .{});
        break :dst dst_mcv;
    };
    const dst_lock = switch (dst_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

    const abi_size: u16 = @int_cast(src_ty.abi_size(mod));
    switch (tag) {
        .not => {
            const limb_abi_size: u16 = @min(abi_size, 8);
            const int_info = if (src_ty.ip_index == .bool_type)
                std.builtin.Type.Int{ .signedness = .unsigned, .bits = 1 }
            else
                src_ty.int_info(mod);
            var byte_off: i32 = 0;
            while (byte_off * 8 < int_info.bits) : (byte_off += limb_abi_size) {
                const limb_bits: u16 = @int_cast(@min(switch (int_info.signedness) {
                    .signed => abi_size * 8,
                    .unsigned => int_info.bits,
                } - byte_off * 8, limb_abi_size * 8));
                const limb_ty = try mod.int_type(int_info.signedness, limb_bits);
                const limb_mcv = switch (byte_off) {
                    0 => dst_mcv,
                    else => dst_mcv.address().offset(byte_off).deref(),
                };

                if (int_info.signedness == .unsigned and self.reg_extra_bits(limb_ty) > 0) {
                    const mask = @as(u64, math.max_int(u64)) >> @int_cast(64 - limb_bits);
                    try self.gen_bin_op_mir(.{ ._, .xor }, limb_ty, limb_mcv, .{ .immediate = mask });
                } else try self.gen_un_op_mir(.{ ._, .not }, limb_ty, limb_mcv);
            }
        },
        .neg => {
            try self.gen_un_op_mir(.{ ._, .neg }, src_ty, dst_mcv);
            const bit_size = src_ty.int_info(mod).bits;
            if (abi_size * 8 > bit_size) {
                if (dst_mcv.is_register()) {
                    try self.truncate_register(src_ty, dst_mcv.get_reg().?);
                } else {
                    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    const hi_mcv = dst_mcv.address().offset(@int_cast(bit_size / 64 * 8)).deref();
                    try self.gen_set_reg(tmp_reg, Type.usize, hi_mcv, .{});
                    try self.truncate_register(src_ty, tmp_reg);
                    try self.gen_copy(Type.usize, hi_mcv, .{ .register = tmp_reg }, .{});
                }
            }
        },
        else => unreachable,
    }
    return dst_mcv;
}

fn gen_un_op_mir(self: *Self, mir_tag: Mir.Inst.FixedTag, dst_ty: Type, dst_mcv: MCValue) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    if (abi_size > 8) return self.fail("TODO implement {} for {}", .{ mir_tag, dst_ty.fmt(mod) });
    switch (dst_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .immediate,
        .register_offset,
        .eflags,
        .register_overflow,
        .lea_symbol,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        .elementwise_regs_then_frame,
        .reserved_frame,
        .air_ref,
        => unreachable, // unmodifiable destination
        .register => |dst_reg| try self.asm_register(mir_tag, register_alias(dst_reg, abi_size)),
        .register_pair => unreachable, // unimplemented
        .memory, .load_symbol, .load_got, .load_direct, .load_tlv => {
            const addr_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const addr_reg_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_reg_lock);

            try self.gen_set_reg(addr_reg, Type.usize, dst_mcv.address(), .{});
            try self.asm_memory(mir_tag, .{ .base = .{ .reg = addr_reg }, .mod = .{ .rm = .{
                .size = Memory.Size.from_size(abi_size),
            } } });
        },
        .indirect, .load_frame => try self.asm_memory(
            mir_tag,
            try dst_mcv.mem(self, Memory.Size.from_size(abi_size)),
        ),
    }
}

/// Clobbers .rcx for non-immediate shift value.
fn gen_shift_bin_op_mir(
    self: *Self,
    tag: Mir.Inst.FixedTag,
    lhs_ty: Type,
    lhs_mcv: MCValue,
    rhs_ty: Type,
    rhs_mcv: MCValue,
) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(lhs_ty.abi_size(mod));
    const shift_abi_size: u32 = @int_cast(rhs_ty.abi_size(mod));
    try self.spill_eflags_if_occupied();

    if (abi_size > 16) {
        const limbs_len = math.div_ceil(u32, abi_size, 8) catch unreachable;
        assert(shift_abi_size >= 1 and shift_abi_size <= 2);

        const rcx_lock: ?RegisterLock = switch (rhs_mcv) {
            .immediate => |shift_imm| switch (shift_imm) {
                0 => return,
                else => null,
            },
            else => lock: {
                if (switch (rhs_mcv) {
                    .register => |rhs_reg| rhs_reg.id() != Register.rcx.id(),
                    else => true,
                }) {
                    self.register_manager.get_reg_assume_free(.rcx, null);
                    try self.gen_set_reg(.rcx, rhs_ty, rhs_mcv, .{});
                }
                break :lock self.register_manager.lock_reg(.rcx);
            },
        };
        defer if (rcx_lock) |lock| self.register_manager.unlock_reg(lock);

        const temp_regs = try self.register_manager.alloc_regs(4, .{null} ** 4, abi.RegisterClass.gp);
        const temp_locks = self.register_manager.lock_regs_assume_unused(4, temp_regs);
        defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

        switch (tag[0]) {
            ._l => {
                try self.asm_register_immediate(.{ ._, .mov }, temp_regs[1].to32(), Immediate.u(limbs_len - 1));
                switch (rhs_mcv) {
                    .immediate => |shift_imm| try self.asm_register_immediate(
                        .{ ._, .mov },
                        temp_regs[0].to32(),
                        Immediate.u(limbs_len - (shift_imm >> 6) - 1),
                    ),
                    else => {
                        try self.asm_register_register(
                            .{ ._, .movzx },
                            temp_regs[2].to32(),
                            register_alias(.rcx, shift_abi_size),
                        );
                        try self.asm_register_immediate(
                            .{ ._, .@"and" },
                            .cl,
                            Immediate.u(math.max_int(u6)),
                        );
                        try self.asm_register_immediate(
                            .{ ._r, .sh },
                            temp_regs[2].to32(),
                            Immediate.u(6),
                        );
                        try self.asm_register_register(
                            .{ ._, .mov },
                            temp_regs[0].to32(),
                            temp_regs[1].to32(),
                        );
                        try self.asm_register_register(
                            .{ ._, .sub },
                            temp_regs[0].to32(),
                            temp_regs[2].to32(),
                        );
                    },
                }
            },
            ._r => {
                try self.asm_register_register(.{ ._, .xor }, temp_regs[1].to32(), temp_regs[1].to32());
                switch (rhs_mcv) {
                    .immediate => |shift_imm| try self.asm_register_immediate(
                        .{ ._, .mov },
                        temp_regs[0].to32(),
                        Immediate.u(shift_imm >> 6),
                    ),
                    else => {
                        try self.asm_register_register(
                            .{ ._, .movzx },
                            temp_regs[0].to32(),
                            register_alias(.rcx, shift_abi_size),
                        );
                        try self.asm_register_immediate(
                            .{ ._, .@"and" },
                            .cl,
                            Immediate.u(math.max_int(u6)),
                        );
                        try self.asm_register_immediate(
                            .{ ._r, .sh },
                            temp_regs[0].to32(),
                            Immediate.u(6),
                        );
                    },
                }
            },
            else => unreachable,
        }

        const slow_inc_dec = self.has_feature(.slow_incdec);
        if (switch (rhs_mcv) {
            .immediate => |shift_imm| shift_imm >> 6 < limbs_len - 1,
            else => true,
        }) {
            try self.asm_register_memory(.{ ._, .mov }, temp_regs[2].to64(), .{
                .base = .{ .frame = lhs_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[0].to64(),
                    .scale = .@"8",
                    .disp = lhs_mcv.load_frame.off,
                } },
            });
            const skip = switch (rhs_mcv) {
                .immediate => undefined,
                else => switch (tag[0]) {
                    ._l => try self.asm_jcc_reloc(.z, undefined),
                    ._r => skip: {
                        try self.asm_register_immediate(
                            .{ ._, .cmp },
                            temp_regs[0].to32(),
                            Immediate.u(limbs_len - 1),
                        );
                        break :skip try self.asm_jcc_reloc(.nb, undefined);
                    },
                    else => unreachable,
                },
            };
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            try self.asm_register_memory(.{ ._, .mov }, temp_regs[3].to64(), .{
                .base = .{ .frame = lhs_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[0].to64(),
                    .scale = .@"8",
                    .disp = switch (tag[0]) {
                        ._l => lhs_mcv.load_frame.off - 8,
                        ._r => lhs_mcv.load_frame.off + 8,
                        else => unreachable,
                    },
                } },
            });
            switch (rhs_mcv) {
                .immediate => |shift_imm| try self.asm_register_register_immediate(
                    .{ switch (tag[0]) {
                        ._l => ._ld,
                        ._r => ._rd,
                        else => unreachable,
                    }, .sh },
                    temp_regs[2].to64(),
                    temp_regs[3].to64(),
                    Immediate.u(shift_imm & math.max_int(u6)),
                ),
                else => try self.asm_register_register_register(.{ switch (tag[0]) {
                    ._l => ._ld,
                    ._r => ._rd,
                    else => unreachable,
                }, .sh }, temp_regs[2].to64(), temp_regs[3].to64(), .cl),
            }
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = lhs_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[1].to64(),
                    .scale = .@"8",
                    .disp = lhs_mcv.load_frame.off,
                } },
            }, temp_regs[2].to64());
            try self.asm_register_register(.{ ._, .mov }, temp_regs[2].to64(), temp_regs[3].to64());
            switch (tag[0]) {
                ._l => {
                    if (slow_inc_dec) {
                        try self.asm_register_immediate(.{ ._, .sub }, temp_regs[1].to32(), Immediate.u(1));
                        try self.asm_register_immediate(.{ ._, .sub }, temp_regs[0].to32(), Immediate.u(1));
                    } else {
                        try self.asm_register(.{ ._, .dec }, temp_regs[1].to32());
                        try self.asm_register(.{ ._, .dec }, temp_regs[0].to32());
                    }
                    _ = try self.asm_jcc_reloc(.nz, loop);
                },
                ._r => {
                    if (slow_inc_dec) {
                        try self.asm_register_immediate(.{ ._, .add }, temp_regs[1].to32(), Immediate.u(1));
                        try self.asm_register_immediate(.{ ._, .add }, temp_regs[0].to32(), Immediate.u(1));
                    } else {
                        try self.asm_register(.{ ._, .inc }, temp_regs[1].to32());
                        try self.asm_register(.{ ._, .inc }, temp_regs[0].to32());
                    }
                    try self.asm_register_immediate(
                        .{ ._, .cmp },
                        temp_regs[0].to32(),
                        Immediate.u(limbs_len - 1),
                    );
                    _ = try self.asm_jcc_reloc(.b, loop);
                },
                else => unreachable,
            }
            switch (rhs_mcv) {
                .immediate => {},
                else => self.perform_reloc(skip),
            }
        }
        switch (rhs_mcv) {
            .immediate => |shift_imm| try self.asm_register_immediate(
                tag,
                temp_regs[2].to64(),
                Immediate.u(shift_imm & math.max_int(u6)),
            ),
            else => try self.asm_register_register(tag, temp_regs[2].to64(), .cl),
        }
        try self.asm_memory_register(.{ ._, .mov }, .{
            .base = .{ .frame = lhs_mcv.load_frame.index },
            .mod = .{ .rm = .{
                .size = .qword,
                .index = temp_regs[1].to64(),
                .scale = .@"8",
                .disp = lhs_mcv.load_frame.off,
            } },
        }, temp_regs[2].to64());
        if (tag[0] == ._r and tag[1] == .sa) try self.asm_register_immediate(
            tag,
            temp_regs[2].to64(),
            Immediate.u(63),
        );
        if (switch (rhs_mcv) {
            .immediate => |shift_imm| shift_imm >> 6 > 0,
            else => true,
        }) {
            const skip = switch (rhs_mcv) {
                .immediate => undefined,
                else => switch (tag[0]) {
                    ._l => skip: {
                        try self.asm_register_register(
                            .{ ._, .@"test" },
                            temp_regs[1].to32(),
                            temp_regs[1].to32(),
                        );
                        break :skip try self.asm_jcc_reloc(.z, undefined);
                    },
                    ._r => skip: {
                        try self.asm_register_immediate(
                            .{ ._, .cmp },
                            temp_regs[1].to32(),
                            Immediate.u(limbs_len - 1),
                        );
                        break :skip try self.asm_jcc_reloc(.nb, undefined);
                    },
                    else => unreachable,
                },
            };
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            switch (tag[0]) {
                ._l => if (slow_inc_dec) {
                    try self.asm_register_immediate(.{ ._, .sub }, temp_regs[1].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .dec }, temp_regs[1].to32());
                },
                ._r => if (slow_inc_dec) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[1].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[1].to32());
                },
                else => unreachable,
            }
            if (tag[0] == ._r and tag[1] == .sa) try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = lhs_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[1].to64(),
                    .scale = .@"8",
                    .disp = lhs_mcv.load_frame.off,
                } },
            }, temp_regs[2].to64()) else try self.asm_memory_immediate(.{ ._, .mov }, .{
                .base = .{ .frame = lhs_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = temp_regs[1].to64(),
                    .scale = .@"8",
                    .disp = lhs_mcv.load_frame.off,
                } },
            }, Immediate.u(0));
            switch (tag[0]) {
                ._l => _ = try self.asm_jcc_reloc(.nz, loop),
                ._r => {
                    try self.asm_register_immediate(
                        .{ ._, .cmp },
                        temp_regs[1].to32(),
                        Immediate.u(limbs_len - 1),
                    );
                    _ = try self.asm_jcc_reloc(.b, loop);
                },
                else => unreachable,
            }
            switch (rhs_mcv) {
                .immediate => {},
                else => self.perform_reloc(skip),
            }
        }
        return;
    }

    assert(shift_abi_size == 1);
    const shift_mcv: MCValue = shift: {
        switch (rhs_mcv) {
            .immediate => |shift_imm| switch (shift_imm) {
                0 => return,
                else => break :shift rhs_mcv,
            },
            .register => |rhs_reg| if (rhs_reg.id() == Register.rcx.id())
                break :shift rhs_mcv,
            else => {},
        }
        self.register_manager.get_reg_assume_free(.rcx, null);
        try self.gen_set_reg(.cl, rhs_ty, rhs_mcv, .{});
        break :shift .{ .register = .rcx };
    };
    if (abi_size > 8) {
        const info: struct { indices: [2]u31, double_tag: Mir.Inst.FixedTag } = switch (tag[0]) {
            ._l => .{ .indices = .{ 0, 1 }, .double_tag = .{ ._ld, .sh } },
            ._r => .{ .indices = .{ 1, 0 }, .double_tag = .{ ._rd, .sh } },
            else => unreachable,
        };
        switch (lhs_mcv) {
            .register_pair => |lhs_regs| switch (shift_mcv) {
                .immediate => |shift_imm| if (shift_imm > 0 and shift_imm < 64) {
                    try self.asm_register_register_immediate(
                        info.double_tag,
                        lhs_regs[info.indices[1]],
                        lhs_regs[info.indices[0]],
                        Immediate.u(shift_imm),
                    );
                    try self.asm_register_immediate(
                        tag,
                        lhs_regs[info.indices[0]],
                        Immediate.u(shift_imm),
                    );
                    return;
                } else {
                    assert(shift_imm < 128);
                    try self.asm_register_register(
                        .{ ._, .mov },
                        lhs_regs[info.indices[1]],
                        lhs_regs[info.indices[0]],
                    );
                    if (tag[0] == ._r and tag[1] == .sa) try self.asm_register_immediate(
                        tag,
                        lhs_regs[info.indices[0]],
                        Immediate.u(63),
                    ) else try self.asm_register_register(
                        .{ ._, .xor },
                        lhs_regs[info.indices[0]],
                        lhs_regs[info.indices[0]],
                    );
                    if (shift_imm > 64) try self.asm_register_immediate(
                        tag,
                        lhs_regs[info.indices[1]],
                        Immediate.u(shift_imm - 64),
                    );
                    return;
                },
                .register => |shift_reg| {
                    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    if (tag[0] == ._r and tag[1] == .sa) {
                        try self.asm_register_register(.{ ._, .mov }, tmp_reg, lhs_regs[info.indices[0]]);
                        try self.asm_register_immediate(tag, tmp_reg, Immediate.u(63));
                    } else try self.asm_register_register(
                        .{ ._, .xor },
                        tmp_reg.to32(),
                        tmp_reg.to32(),
                    );
                    try self.asm_register_register_register(
                        info.double_tag,
                        lhs_regs[info.indices[1]],
                        lhs_regs[info.indices[0]],
                        register_alias(shift_reg, 1),
                    );
                    try self.asm_register_register(
                        tag,
                        lhs_regs[info.indices[0]],
                        register_alias(shift_reg, 1),
                    );
                    try self.asm_register_immediate(
                        .{ ._, .cmp },
                        register_alias(shift_reg, 1),
                        Immediate.u(64),
                    );
                    try self.asm_cmovcc_register_register(
                        .ae,
                        lhs_regs[info.indices[1]],
                        lhs_regs[info.indices[0]],
                    );
                    try self.asm_cmovcc_register_register(.ae, lhs_regs[info.indices[0]], tmp_reg);
                    return;
                },
                else => {},
            },
            .load_frame => |dst_frame_addr| {
                const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                switch (shift_mcv) {
                    .immediate => |shift_imm| if (shift_imm > 0 and shift_imm < 64) {
                        try self.asm_register_memory(
                            .{ ._, .mov },
                            tmp_reg,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                        );
                        try self.asm_memory_register_immediate(
                            info.double_tag,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[1] * 8,
                                } },
                            },
                            tmp_reg,
                            Immediate.u(shift_imm),
                        );
                        try self.asm_memory_immediate(
                            tag,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                            Immediate.u(shift_imm),
                        );
                        return;
                    } else {
                        assert(shift_imm < 128);
                        try self.asm_register_memory(
                            .{ ._, .mov },
                            tmp_reg,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                        );
                        if (shift_imm > 64) try self.asm_register_immediate(
                            tag,
                            tmp_reg,
                            Immediate.u(shift_imm - 64),
                        );
                        try self.asm_memory_register(
                            .{ ._, .mov },
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[1] * 8,
                                } },
                            },
                            tmp_reg,
                        );
                        if (tag[0] == ._r and tag[1] == .sa) try self.asm_memory_immediate(
                            tag,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                            Immediate.u(63),
                        ) else {
                            try self.asm_register_register(.{ ._, .xor }, tmp_reg.to32(), tmp_reg.to32());
                            try self.asm_memory_register(
                                .{ ._, .mov },
                                .{
                                    .base = .{ .frame = dst_frame_addr.index },
                                    .mod = .{ .rm = .{
                                        .size = .qword,
                                        .disp = dst_frame_addr.off + info.indices[0] * 8,
                                    } },
                                },
                                tmp_reg,
                            );
                        }
                        return;
                    },
                    .register => |shift_reg| {
                        const first_reg =
                            try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                        const first_lock = self.register_manager.lock_reg_assume_unused(first_reg);
                        defer self.register_manager.unlock_reg(first_lock);

                        const second_reg =
                            try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                        const second_lock = self.register_manager.lock_reg_assume_unused(second_reg);
                        defer self.register_manager.unlock_reg(second_lock);

                        try self.asm_register_memory(
                            .{ ._, .mov },
                            first_reg,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                        );
                        try self.asm_register_memory(
                            .{ ._, .mov },
                            second_reg,
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[1] * 8,
                                } },
                            },
                        );
                        if (tag[0] == ._r and tag[1] == .sa) {
                            try self.asm_register_register(.{ ._, .mov }, tmp_reg, first_reg);
                            try self.asm_register_immediate(tag, tmp_reg, Immediate.u(63));
                        } else try self.asm_register_register(
                            .{ ._, .xor },
                            tmp_reg.to32(),
                            tmp_reg.to32(),
                        );
                        try self.asm_register_register_register(
                            info.double_tag,
                            second_reg,
                            first_reg,
                            register_alias(shift_reg, 1),
                        );
                        try self.asm_register_register(tag, first_reg, register_alias(shift_reg, 1));
                        try self.asm_register_immediate(
                            .{ ._, .cmp },
                            register_alias(shift_reg, 1),
                            Immediate.u(64),
                        );
                        try self.asm_cmovcc_register_register(.ae, second_reg, first_reg);
                        try self.asm_cmovcc_register_register(.ae, first_reg, tmp_reg);
                        try self.asm_memory_register(
                            .{ ._, .mov },
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[1] * 8,
                                } },
                            },
                            second_reg,
                        );
                        try self.asm_memory_register(
                            .{ ._, .mov },
                            .{
                                .base = .{ .frame = dst_frame_addr.index },
                                .mod = .{ .rm = .{
                                    .size = .qword,
                                    .disp = dst_frame_addr.off + info.indices[0] * 8,
                                } },
                            },
                            first_reg,
                        );
                        return;
                    },
                    else => {},
                }
            },
            else => {},
        }
    } else switch (lhs_mcv) {
        .register => |lhs_reg| switch (shift_mcv) {
            .immediate => |shift_imm| return self.asm_register_immediate(
                tag,
                register_alias(lhs_reg, abi_size),
                Immediate.u(shift_imm),
            ),
            .register => |shift_reg| return self.asm_register_register(
                tag,
                register_alias(lhs_reg, abi_size),
                register_alias(shift_reg, 1),
            ),
            else => {},
        },
        .memory, .indirect, .load_frame => {
            const lhs_mem: Memory = switch (lhs_mcv) {
                .memory => |addr| .{
                    .base = .{ .reg = .ds },
                    .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(abi_size),
                        .disp = math.cast(i32, @as(i64, @bit_cast(addr))) orelse
                            return self.fail("TODO gen_shift_bin_op_mir between {s} and {s}", .{
                            @tag_name(lhs_mcv),
                            @tag_name(shift_mcv),
                        }),
                    } },
                },
                .indirect => |reg_off| .{
                    .base = .{ .reg = reg_off.reg },
                    .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(abi_size),
                        .disp = reg_off.off,
                    } },
                },
                .load_frame => |frame_addr| .{
                    .base = .{ .frame = frame_addr.index },
                    .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(abi_size),
                        .disp = frame_addr.off,
                    } },
                },
                else => unreachable,
            };
            switch (shift_mcv) {
                .immediate => |shift_imm| return self.asm_memory_immediate(
                    tag,
                    lhs_mem,
                    Immediate.u(shift_imm),
                ),
                .register => |shift_reg| return self.asm_memory_register(
                    tag,
                    lhs_mem,
                    register_alias(shift_reg, 1),
                ),
                else => {},
            }
        },
        else => {},
    }
    return self.fail("TODO gen_shift_bin_op_mir between {s} and {s}", .{
        @tag_name(lhs_mcv),
        @tag_name(shift_mcv),
    });
}

/// Result is always a register.
/// Clobbers .rcx for non-immediate rhs, therefore care is needed to spill .rcx upfront.
/// Asserts .rcx is free.
fn gen_shift_bin_op(
    self: *Self,
    air_tag: Air.Inst.Tag,
    maybe_inst: ?Air.Inst.Index,
    lhs_mcv: MCValue,
    rhs_mcv: MCValue,
    lhs_ty: Type,
    rhs_ty: Type,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    if (lhs_ty.zig_type_tag(mod) == .Vector) return self.fail("TODO implement gen_shift_bin_op for {}", .{
        lhs_ty.fmt(mod),
    });

    try self.register_manager.get_known_reg(.rcx, null);
    const rcx_lock = self.register_manager.lock_reg(.rcx);
    defer if (rcx_lock) |lock| self.register_manager.unlock_reg(lock);

    const lhs_lock = switch (lhs_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const rhs_lock = switch (rhs_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const dst_mcv: MCValue = dst: {
        if (maybe_inst) |inst| {
            const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
            if (self.reuse_operand(inst, bin_op.lhs, 0, lhs_mcv)) break :dst lhs_mcv;
        }
        const dst_mcv = try self.alloc_reg_or_mem_advanced(lhs_ty, maybe_inst, true);
        try self.gen_copy(lhs_ty, dst_mcv, lhs_mcv, .{});
        break :dst dst_mcv;
    };

    const signedness = lhs_ty.int_info(mod).signedness;
    try self.gen_shift_bin_op_mir(switch (air_tag) {
        .shl, .shl_exact => switch (signedness) {
            .signed => .{ ._l, .sa },
            .unsigned => .{ ._l, .sh },
        },
        .shr, .shr_exact => switch (signedness) {
            .signed => .{ ._r, .sa },
            .unsigned => .{ ._r, .sh },
        },
        else => unreachable,
    }, lhs_ty, dst_mcv, rhs_ty, rhs_mcv);
    return dst_mcv;
}

/// Result is always a register.
/// Clobbers .rax and .rdx therefore care is needed to spill .rax and .rdx upfront.
/// Asserts .rax and .rdx are free.
fn gen_mul_div_bin_op(
    self: *Self,
    tag: Air.Inst.Tag,
    maybe_inst: ?Air.Inst.Index,
    dst_ty: Type,
    src_ty: Type,
    lhs_mcv: MCValue,
    rhs_mcv: MCValue,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    if (dst_ty.zig_type_tag(mod) == .Vector or dst_ty.zig_type_tag(mod) == .Float) return self.fail(
        "TODO implement gen_mul_div_bin_op for {s} from {} to {}",
        .{ @tag_name(tag), src_ty.fmt(mod), dst_ty.fmt(mod) },
    );
    const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    const src_abi_size: u32 = @int_cast(src_ty.abi_size(mod));

    assert(self.register_manager.is_reg_free(.rax));
    assert(self.register_manager.is_reg_free(.rcx));
    assert(self.register_manager.is_reg_free(.rdx));
    assert(self.eflags_inst == null);

    if (dst_abi_size == 16 and src_abi_size == 16) {
        assert(tag == .mul or tag == .mul_wrap);
        const reg_locks = self.register_manager.lock_regs(2, .{ .rax, .rdx });
        defer for (reg_locks) |reg_lock| if (reg_lock) |lock| self.register_manager.unlock_reg(lock);

        const mat_lhs_mcv = switch (lhs_mcv) {
            .load_symbol => mat_lhs_mcv: {
                // TODO clean this up!
                const addr_reg = try self.copy_to_tmp_register(Type.usize, lhs_mcv.address());
                break :mat_lhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
            },
            else => lhs_mcv,
        };
        const mat_lhs_lock = switch (mat_lhs_mcv) {
            .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
            else => null,
        };
        defer if (mat_lhs_lock) |lock| self.register_manager.unlock_reg(lock);
        const mat_rhs_mcv = switch (rhs_mcv) {
            .load_symbol => mat_rhs_mcv: {
                // TODO clean this up!
                const addr_reg = try self.copy_to_tmp_register(Type.usize, rhs_mcv.address());
                break :mat_rhs_mcv MCValue{ .indirect = .{ .reg = addr_reg } };
            },
            else => rhs_mcv,
        };
        const mat_rhs_lock = switch (mat_rhs_mcv) {
            .indirect => |reg_off| self.register_manager.lock_reg(reg_off.reg),
            else => null,
        };
        defer if (mat_rhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
        const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
        defer self.register_manager.unlock_reg(tmp_lock);

        if (mat_lhs_mcv.is_memory())
            try self.asm_register_memory(.{ ._, .mov }, .rax, try mat_lhs_mcv.mem(self, .qword))
        else
            try self.asm_register_register(.{ ._, .mov }, .rax, mat_lhs_mcv.register_pair[0]);
        if (mat_rhs_mcv.is_memory()) try self.asm_register_memory(
            .{ ._, .mov },
            tmp_reg,
            try mat_rhs_mcv.address().offset(8).deref().mem(self, .qword),
        ) else try self.asm_register_register(.{ ._, .mov }, tmp_reg, mat_rhs_mcv.register_pair[1]);
        try self.asm_register_register(.{ .i_, .mul }, tmp_reg, .rax);
        if (mat_rhs_mcv.is_memory())
            try self.asm_memory(.{ ._, .mul }, try mat_rhs_mcv.mem(self, .qword))
        else
            try self.asm_register(.{ ._, .mul }, mat_rhs_mcv.register_pair[0]);
        try self.asm_register_register(.{ ._, .add }, .rdx, tmp_reg);
        if (mat_lhs_mcv.is_memory()) try self.asm_register_memory(
            .{ ._, .mov },
            tmp_reg,
            try mat_lhs_mcv.address().offset(8).deref().mem(self, .qword),
        ) else try self.asm_register_register(.{ ._, .mov }, tmp_reg, mat_lhs_mcv.register_pair[1]);
        if (mat_rhs_mcv.is_memory())
            try self.asm_register_memory(.{ .i_, .mul }, tmp_reg, try mat_rhs_mcv.mem(self, .qword))
        else
            try self.asm_register_register(.{ .i_, .mul }, tmp_reg, mat_rhs_mcv.register_pair[0]);
        try self.asm_register_register(.{ ._, .add }, .rdx, tmp_reg);
        return .{ .register_pair = .{ .rax, .rdx } };
    }

    if (switch (tag) {
        else => unreachable,
        .mul, .mul_wrap => dst_abi_size != src_abi_size and dst_abi_size != src_abi_size * 2,
        .div_trunc, .div_floor, .div_exact, .rem, .mod => dst_abi_size != src_abi_size,
    } or src_abi_size > 8) {
        const src_info = src_ty.int_info(mod);
        switch (tag) {
            .mul, .mul_wrap => {
                const slow_inc = self.has_feature(.slow_incdec);
                const limb_len = math.div_ceil(u32, src_abi_size, 8) catch unreachable;

                try self.spill_registers(&.{ .rax, .rcx, .rdx });
                const reg_locks = self.register_manager.lock_regs(3, .{ .rax, .rcx, .rdx });
                defer for (reg_locks) |reg_lock| if (reg_lock) |lock|
                    self.register_manager.unlock_reg(lock);

                const dst_mcv = try self.alloc_reg_or_mem_advanced(dst_ty, maybe_inst, false);
                try self.gen_inline_memset(
                    dst_mcv.address(),
                    .{ .immediate = 0 },
                    .{ .immediate = src_abi_size },
                    .{},
                );

                const temp_regs =
                    try self.register_manager.alloc_regs(4, .{null} ** 4, abi.RegisterClass.gp);
                const temp_locks = self.register_manager.lock_regs_assume_unused(4, temp_regs);
                defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

                try self.asm_register_register(.{ ._, .xor }, temp_regs[0].to32(), temp_regs[0].to32());

                const outer_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_register_memory(.{ ._, .mov }, temp_regs[1].to64(), .{
                    .base = .{ .frame = rhs_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[0].to64(),
                        .scale = .@"8",
                        .disp = rhs_mcv.load_frame.off,
                    } },
                });
                try self.asm_register_register(.{ ._, .@"test" }, temp_regs[1].to64(), temp_regs[1].to64());
                const skip_inner = try self.asm_jcc_reloc(.z, undefined);

                try self.asm_register_register(.{ ._, .xor }, temp_regs[2].to32(), temp_regs[2].to32());
                try self.asm_register_register(.{ ._, .mov }, temp_regs[3].to32(), temp_regs[0].to32());
                try self.asm_register_register(.{ ._, .xor }, .ecx, .ecx);
                try self.asm_register_register(.{ ._, .xor }, .edx, .edx);

                const inner_loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_register_immediate(.{ ._r, .sh }, .cl, Immediate.u(1));
                try self.asm_memory_register(.{ ._, .adc }, .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[3].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off,
                    } },
                }, .rdx);
                try self.asm_setcc_register(.c, .cl);

                try self.asm_register_memory(.{ ._, .mov }, .rax, .{
                    .base = .{ .frame = lhs_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[2].to64(),
                        .scale = .@"8",
                        .disp = lhs_mcv.load_frame.off,
                    } },
                });
                try self.asm_register(.{ ._, .mul }, temp_regs[1].to64());

                try self.asm_register_immediate(.{ ._r, .sh }, .ch, Immediate.u(1));
                try self.asm_memory_register(.{ ._, .adc }, .{
                    .base = .{ .frame = dst_mcv.load_frame.index },
                    .mod = .{ .rm = .{
                        .size = .qword,
                        .index = temp_regs[3].to64(),
                        .scale = .@"8",
                        .disp = dst_mcv.load_frame.off,
                    } },
                }, .rax);
                try self.asm_setcc_register(.c, .ch);

                if (slow_inc) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[2].to32(), Immediate.u(1));
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[3].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[2].to32());
                    try self.asm_register(.{ ._, .inc }, temp_regs[3].to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    temp_regs[3].to32(),
                    Immediate.u(limb_len),
                );
                _ = try self.asm_jcc_reloc(.b, inner_loop);

                self.perform_reloc(skip_inner);
                if (slow_inc) {
                    try self.asm_register_immediate(.{ ._, .add }, temp_regs[0].to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, temp_regs[0].to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    temp_regs[0].to32(),
                    Immediate.u(limb_len),
                );
                _ = try self.asm_jcc_reloc(.b, outer_loop);

                return dst_mcv;
            },
            .div_trunc, .div_floor, .div_exact, .rem, .mod => switch (src_info.signedness) {
                .signed => {},
                .unsigned => {
                    const dst_mcv = try self.alloc_reg_or_mem_advanced(dst_ty, maybe_inst, false);
                    const manyptr_u32_ty = try mod.ptr_type(.{
                        .child = .u32_type,
                        .flags = .{
                            .size = .Many,
                        },
                    });
                    const manyptr_const_u32_ty = try mod.ptr_type(.{
                        .child = .u32_type,
                        .flags = .{
                            .size = .Many,
                            .is_const = true,
                        },
                    });
                    _ = try self.gen_call(.{ .lib = .{
                        .return_type = .void_type,
                        .param_types = &.{
                            manyptr_u32_ty.to_intern(),
                            manyptr_const_u32_ty.to_intern(),
                            manyptr_const_u32_ty.to_intern(),
                            .usize_type,
                        },
                        .callee = switch (tag) {
                            .div_trunc,
                            .div_floor,
                            .div_exact,
                            => "__udivei4",
                            .rem,
                            .mod,
                            => "__umodei4",
                            else => unreachable,
                        },
                    } }, &.{
                        manyptr_u32_ty,
                        manyptr_const_u32_ty,
                        manyptr_const_u32_ty,
                        Type.usize,
                    }, &.{
                        dst_mcv.address(),
                        lhs_mcv.address(),
                        rhs_mcv.address(),
                        .{ .immediate = src_info.bits },
                    });
                    return dst_mcv;
                },
            },
            else => {},
        }
        return self.fail(
            "TODO implement gen_mul_div_bin_op for {s} from {} to {}",
            .{ @tag_name(tag), src_ty.fmt(mod), dst_ty.fmt(mod) },
        );
    }
    const ty = if (dst_abi_size <= 8) dst_ty else src_ty;
    const abi_size = if (dst_abi_size <= 8) dst_abi_size else src_abi_size;

    const reg_locks = self.register_manager.lock_regs(2, .{ .rax, .rdx });
    defer for (reg_locks) |reg_lock| if (reg_lock) |lock| self.register_manager.unlock_reg(lock);

    const signedness = ty.int_info(mod).signedness;
    switch (tag) {
        .mul,
        .mul_wrap,
        .rem,
        .div_trunc,
        .div_exact,
        => {
            const track_inst_rax = switch (tag) {
                .mul, .mul_wrap => if (dst_abi_size <= 8) maybe_inst else null,
                .div_exact, .div_trunc => maybe_inst,
                else => null,
            };
            const track_inst_rdx = switch (tag) {
                .rem => maybe_inst,
                else => null,
            };
            try self.register_manager.get_known_reg(.rax, track_inst_rax);
            try self.register_manager.get_known_reg(.rdx, track_inst_rdx);

            try self.gen_int_mul_div_op_mir(switch (signedness) {
                .signed => switch (tag) {
                    .mul, .mul_wrap => .{ .i_, .mul },
                    .div_trunc, .div_exact, .rem => .{ .i_, .div },
                    else => unreachable,
                },
                .unsigned => switch (tag) {
                    .mul, .mul_wrap => .{ ._, .mul },
                    .div_trunc, .div_exact, .rem => .{ ._, .div },
                    else => unreachable,
                },
            }, ty, lhs_mcv, rhs_mcv);

            if (dst_abi_size <= 8) return .{ .register = register_alias(switch (tag) {
                .mul, .mul_wrap, .div_trunc, .div_exact => .rax,
                .rem => .rdx,
                else => unreachable,
            }, dst_abi_size) };

            const dst_mcv = try self.alloc_reg_or_mem_advanced(dst_ty, maybe_inst, false);
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .disp = dst_mcv.load_frame.off,
                } },
            }, .rax);
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .disp = dst_mcv.load_frame.off + 8,
                } },
            }, .rdx);
            return dst_mcv;
        },

        .mod => {
            try self.register_manager.get_known_reg(.rax, null);
            try self.register_manager.get_known_reg(
                .rdx,
                if (signedness == .unsigned) maybe_inst else null,
            );

            switch (signedness) {
                .signed => {
                    const lhs_lock = switch (lhs_mcv) {
                        .register => |reg| self.register_manager.lock_reg(reg),
                        else => null,
                    };
                    defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);
                    const rhs_lock = switch (rhs_mcv) {
                        .register => |reg| self.register_manager.lock_reg(reg),
                        else => null,
                    };
                    defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

                    // hack around hazard between rhs and div_floor by copying rhs to another register
                    const rhs_copy = try self.copy_to_tmp_register(ty, rhs_mcv);
                    const rhs_copy_lock = self.register_manager.lock_reg_assume_unused(rhs_copy);
                    defer self.register_manager.unlock_reg(rhs_copy_lock);

                    const div_floor = try self.gen_inline_int_div_floor(ty, lhs_mcv, rhs_mcv);
                    try self.gen_int_mul_complex_op_mir(ty, div_floor, .{ .register = rhs_copy });
                    const div_floor_lock = self.register_manager.lock_reg(div_floor.register);
                    defer if (div_floor_lock) |lock| self.register_manager.unlock_reg(lock);

                    const result: MCValue = if (maybe_inst) |inst|
                        try self.copy_to_register_with_inst_tracking(inst, ty, lhs_mcv)
                    else
                        .{ .register = try self.copy_to_tmp_register(ty, lhs_mcv) };
                    try self.gen_bin_op_mir(.{ ._, .sub }, ty, result, div_floor);

                    return result;
                },
                .unsigned => {
                    try self.gen_int_mul_div_op_mir(.{ ._, .div }, ty, lhs_mcv, rhs_mcv);
                    return .{ .register = register_alias(.rdx, abi_size) };
                },
            }
        },

        .div_floor => {
            try self.register_manager.get_known_reg(
                .rax,
                if (signedness == .unsigned) maybe_inst else null,
            );
            try self.register_manager.get_known_reg(.rdx, null);

            const lhs_lock: ?RegisterLock = switch (lhs_mcv) {
                .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                else => null,
            };
            defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

            const actual_rhs_mcv: MCValue = blk: {
                switch (signedness) {
                    .signed => {
                        const rhs_lock: ?RegisterLock = switch (rhs_mcv) {
                            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                            else => null,
                        };
                        defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

                        if (maybe_inst) |inst| {
                            break :blk try self.copy_to_register_with_inst_tracking(inst, ty, rhs_mcv);
                        }
                        break :blk MCValue{ .register = try self.copy_to_tmp_register(ty, rhs_mcv) };
                    },
                    .unsigned => break :blk rhs_mcv,
                }
            };
            const rhs_lock: ?RegisterLock = switch (actual_rhs_mcv) {
                .register => |reg| self.register_manager.lock_reg(reg),
                else => null,
            };
            defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

            switch (signedness) {
                .signed => return try self.gen_inline_int_div_floor(ty, lhs_mcv, actual_rhs_mcv),
                .unsigned => {
                    try self.gen_int_mul_div_op_mir(.{ ._, .div }, ty, lhs_mcv, actual_rhs_mcv);
                    return .{ .register = register_alias(.rax, abi_size) };
                },
            }
        },

        else => unreachable,
    }
}

fn gen_bin_op(
    self: *Self,
    maybe_inst: ?Air.Inst.Index,
    air_tag: Air.Inst.Tag,
    lhs_air: Air.Inst.Ref,
    rhs_air: Air.Inst.Ref,
) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const lhs_ty = self.type_of(lhs_air);
    const rhs_ty = self.type_of(rhs_air);
    const abi_size: u32 = @int_cast(lhs_ty.abi_size(mod));

    if (lhs_ty.is_runtime_float()) libcall: {
        const float_bits = lhs_ty.float_bits(self.target.*);
        const type_needs_libcall = switch (float_bits) {
            16 => !self.has_feature(.f16c),
            32, 64 => false,
            80, 128 => true,
            else => unreachable,
        };
        switch (air_tag) {
            .rem, .mod => {},
            else => if (!type_needs_libcall) break :libcall,
        }
        var callee_buf: ["__mod?f3".len]u8 = undefined;
        const callee = switch (air_tag) {
            .add,
            .sub,
            .mul,
            .div_float,
            .div_trunc,
            .div_floor,
            .div_exact,
            => std.fmt.buf_print(&callee_buf, "__{s}{c}f3", .{
                @tag_name(air_tag)[0..3],
                float_compiler_rt_abi_name(float_bits),
            }),
            .rem, .mod, .min, .max => std.fmt.buf_print(&callee_buf, "{s}f{s}{s}", .{
                float_libc_abi_prefix(lhs_ty),
                switch (air_tag) {
                    .rem, .mod => "mod",
                    .min => "min",
                    .max => "max",
                    else => unreachable,
                },
                float_libc_abi_suffix(lhs_ty),
            }),
            else => return self.fail("TODO implement gen_bin_op for {s} {}", .{
                @tag_name(air_tag), lhs_ty.fmt(mod),
            }),
        } catch unreachable;
        const result = try self.gen_call(.{ .lib = .{
            .return_type = lhs_ty.to_intern(),
            .param_types = &.{ lhs_ty.to_intern(), rhs_ty.to_intern() },
            .callee = callee,
        } }, &.{ lhs_ty, rhs_ty }, &.{ .{ .air_ref = lhs_air }, .{ .air_ref = rhs_air } });
        return switch (air_tag) {
            .mod => result: {
                const adjusted: MCValue = if (type_needs_libcall) adjusted: {
                    var add_callee_buf: ["__add?f3".len]u8 = undefined;
                    break :adjusted try self.gen_call(.{ .lib = .{
                        .return_type = lhs_ty.to_intern(),
                        .param_types = &.{
                            lhs_ty.to_intern(),
                            rhs_ty.to_intern(),
                        },
                        .callee = std.fmt.buf_print(&add_callee_buf, "__add{c}f3", .{
                            float_compiler_rt_abi_name(float_bits),
                        }) catch unreachable,
                    } }, &.{ lhs_ty, rhs_ty }, &.{ result, .{ .air_ref = rhs_air } });
                } else switch (float_bits) {
                    16, 32, 64 => adjusted: {
                        const dst_reg = switch (result) {
                            .register => |reg| reg,
                            else => if (maybe_inst) |inst|
                                (try self.copy_to_register_with_inst_tracking(inst, lhs_ty, result)).register
                            else
                                try self.copy_to_tmp_register(lhs_ty, result),
                        };
                        const dst_lock = self.register_manager.lock_reg(dst_reg);
                        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

                        const rhs_mcv = try self.resolve_inst(rhs_air);
                        const src_mcv: MCValue = if (float_bits == 16) src: {
                            assert(self.has_feature(.f16c));
                            const tmp_reg = (try self.register_manager.alloc_reg(
                                null,
                                abi.RegisterClass.sse,
                            )).to128();
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                                .{ .vp_w, .insr },
                                dst_reg,
                                dst_reg,
                                try rhs_mcv.mem(self, .word),
                                Immediate.u(1),
                            ) else try self.asm_register_register_register(
                                .{ .vp_, .unpcklwd },
                                dst_reg,
                                dst_reg,
                                (if (rhs_mcv.is_register())
                                    rhs_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, rhs_mcv)).to128(),
                            );
                            try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, dst_reg);
                            break :src .{ .register = tmp_reg };
                        } else rhs_mcv;

                        if (self.has_feature(.avx)) {
                            const mir_tag: Mir.Inst.FixedTag = switch (float_bits) {
                                16, 32 => .{ .v_ss, .add },
                                64 => .{ .v_sd, .add },
                                else => unreachable,
                            };
                            if (src_mcv.is_memory()) try self.asm_register_register_memory(
                                mir_tag,
                                dst_reg,
                                dst_reg,
                                try src_mcv.mem(self, Memory.Size.from_bit_size(float_bits)),
                            ) else try self.asm_register_register_register(
                                mir_tag,
                                dst_reg,
                                dst_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                        } else {
                            const mir_tag: Mir.Inst.FixedTag = switch (float_bits) {
                                32 => .{ ._ss, .add },
                                64 => .{ ._sd, .add },
                                else => unreachable,
                            };
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                mir_tag,
                                dst_reg,
                                try src_mcv.mem(self, Memory.Size.from_bit_size(float_bits)),
                            ) else try self.asm_register_register(
                                mir_tag,
                                dst_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                        }

                        if (float_bits == 16) try self.asm_register_register_immediate(
                            .{ .v_, .cvtps2ph },
                            dst_reg,
                            dst_reg,
                            Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                        );
                        break :adjusted .{ .register = dst_reg };
                    },
                    80, 128 => return self.fail("TODO implement gen_bin_op for {s} of {}", .{
                        @tag_name(air_tag), lhs_ty.fmt(mod),
                    }),
                    else => unreachable,
                };
                break :result try self.gen_call(.{ .lib = .{
                    .return_type = lhs_ty.to_intern(),
                    .param_types = &.{ lhs_ty.to_intern(), rhs_ty.to_intern() },
                    .callee = callee,
                } }, &.{ lhs_ty, rhs_ty }, &.{ adjusted, .{ .air_ref = rhs_air } });
            },
            .div_trunc, .div_floor => try self.gen_round_libcall(lhs_ty, result, .{
                .mode = switch (air_tag) {
                    .div_trunc => .zero,
                    .div_floor => .down,
                    else => unreachable,
                },
                .precision = .inexact,
            }),
            else => result,
        };
    }

    const sse_op = switch (lhs_ty.zig_type_tag(mod)) {
        else => false,
        .Float => true,
        .Vector => switch (lhs_ty.child_type(mod).to_intern()) {
            .bool_type, .u1_type => false,
            else => true,
        },
    };
    if (sse_op and ((lhs_ty.scalar_type(mod).is_runtime_float() and
        lhs_ty.scalar_type(mod).float_bits(self.target.*) == 80) or
        lhs_ty.abi_size(mod) > @as(u6, if (self.has_feature(.avx)) 32 else 16)))
        return self.fail("TODO implement gen_bin_op for {s} {}", .{ @tag_name(air_tag), lhs_ty.fmt(mod) });

    const maybe_mask_reg = switch (air_tag) {
        else => null,
        .rem, .mod => unreachable,
        .max, .min => if (lhs_ty.scalar_type(mod).is_runtime_float()) register_alias(
            if (!self.has_feature(.avx) and self.has_feature(.sse4_1)) mask: {
                try self.register_manager.get_known_reg(.xmm0, null);
                break :mask .xmm0;
            } else try self.register_manager.alloc_reg(null, abi.RegisterClass.sse),
            abi_size,
        ) else null,
    };
    const mask_lock =
        if (maybe_mask_reg) |mask_reg| self.register_manager.lock_reg_assume_unused(mask_reg) else null;
    defer if (mask_lock) |lock| self.register_manager.unlock_reg(lock);

    const ordered_air: [2]Air.Inst.Ref = if (lhs_ty.is_vector(mod) and
        switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
        .Bool => false,
        .Int => switch (air_tag) {
            .cmp_lt, .cmp_gte => true,
            else => false,
        },
        .Float => switch (air_tag) {
            .cmp_gte, .cmp_gt => true,
            else => false,
        },
        else => unreachable,
    }) .{ rhs_air, lhs_air } else .{ lhs_air, rhs_air };

    if (lhs_ty.is_abi_int(mod)) for (ordered_air) |op_air| {
        switch (try self.resolve_inst(op_air)) {
            .register => |op_reg| switch (op_reg.class()) {
                .sse => try self.register_manager.get_reg(op_reg, null),
                else => {},
            },
            else => {},
        }
    };

    const lhs_mcv = try self.resolve_inst(ordered_air[0]);
    var rhs_mcv = try self.resolve_inst(ordered_air[1]);
    switch (lhs_mcv) {
        .immediate => |imm| switch (imm) {
            0 => switch (air_tag) {
                .sub, .sub_wrap => return self.gen_un_op(maybe_inst, .neg, ordered_air[1]),
                else => {},
            },
            else => {},
        },
        else => {},
    }

    const is_commutative = switch (air_tag) {
        .add,
        .add_wrap,
        .mul,
        .bool_or,
        .bit_or,
        .bool_and,
        .bit_and,
        .xor,
        .min,
        .max,
        .cmp_eq,
        .cmp_neq,
        => true,

        else => false,
    };

    const lhs_locks: [2]?RegisterLock = switch (lhs_mcv) {
        .register => |lhs_reg| .{ self.register_manager.lock_reg_assume_unused(lhs_reg), null },
        .register_pair => |lhs_regs| locks: {
            const locks = self.register_manager.lock_regs_assume_unused(2, lhs_regs);
            break :locks .{ locks[0], locks[1] };
        },
        else => .{null} ** 2,
    };
    defer for (lhs_locks) |lhs_lock| if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

    const rhs_locks: [2]?RegisterLock = switch (rhs_mcv) {
        .register => |rhs_reg| .{ self.register_manager.lock_reg(rhs_reg), null },
        .register_pair => |rhs_regs| self.register_manager.lock_regs(2, rhs_regs),
        else => .{null} ** 2,
    };
    defer for (rhs_locks) |rhs_lock| if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

    var flipped = false;
    var copied_to_dst = true;
    const dst_mcv: MCValue = dst: {
        const tracked_inst = switch (air_tag) {
            else => maybe_inst,
            .cmp_lt, .cmp_lte, .cmp_eq, .cmp_gte, .cmp_gt, .cmp_neq => null,
        };
        if (maybe_inst) |inst| {
            if ((!sse_op or lhs_mcv.is_register()) and
                self.reuse_operand_advanced(inst, ordered_air[0], 0, lhs_mcv, tracked_inst))
                break :dst lhs_mcv;
            if (is_commutative and (!sse_op or rhs_mcv.is_register()) and
                self.reuse_operand_advanced(inst, ordered_air[1], 1, rhs_mcv, tracked_inst))
            {
                flipped = true;
                break :dst rhs_mcv;
            }
        }
        const dst_mcv = try self.alloc_reg_or_mem_advanced(lhs_ty, tracked_inst, true);
        if (sse_op and lhs_mcv.is_register() and self.has_feature(.avx))
            copied_to_dst = false
        else
            try self.gen_copy(lhs_ty, dst_mcv, lhs_mcv, .{});
        rhs_mcv = try self.resolve_inst(ordered_air[1]);
        break :dst dst_mcv;
    };
    const dst_locks: [2]?RegisterLock = switch (dst_mcv) {
        .register => |dst_reg| .{ self.register_manager.lock_reg(dst_reg), null },
        .register_pair => |dst_regs| self.register_manager.lock_regs(2, dst_regs),
        else => .{null} ** 2,
    };
    defer for (dst_locks) |dst_lock| if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

    const unmat_src_mcv = if (flipped) lhs_mcv else rhs_mcv;
    const src_mcv: MCValue = if (maybe_mask_reg) |mask_reg|
        if (self.has_feature(.avx) and unmat_src_mcv.is_register() and maybe_inst != null and
            self.liveness.operand_dies(maybe_inst.?, if (flipped) 0 else 1)) unmat_src_mcv else src: {
            try self.gen_set_reg(mask_reg, rhs_ty, unmat_src_mcv, .{});
            break :src .{ .register = mask_reg };
        }
    else
        unmat_src_mcv;
    const src_locks: [2]?RegisterLock = switch (src_mcv) {
        .register => |src_reg| .{ self.register_manager.lock_reg(src_reg), null },
        .register_pair => |src_regs| self.register_manager.lock_regs(2, src_regs),
        else => .{null} ** 2,
    };
    defer for (src_locks) |src_lock| if (src_lock) |lock| self.register_manager.unlock_reg(lock);

    if (!sse_op) {
        switch (air_tag) {
            .add,
            .add_wrap,
            => try self.gen_bin_op_mir(.{ ._, .add }, lhs_ty, dst_mcv, src_mcv),

            .sub,
            .sub_wrap,
            => try self.gen_bin_op_mir(.{ ._, .sub }, lhs_ty, dst_mcv, src_mcv),

            .ptr_add,
            .ptr_sub,
            => {
                const tmp_reg = try self.copy_to_tmp_register(rhs_ty, src_mcv);
                const tmp_mcv = MCValue{ .register = tmp_reg };
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                const elem_size = lhs_ty.elem_type2(mod).abi_size(mod);
                try self.gen_int_mul_complex_op_mir(rhs_ty, tmp_mcv, .{ .immediate = elem_size });
                try self.gen_bin_op_mir(
                    switch (air_tag) {
                        .ptr_add => .{ ._, .add },
                        .ptr_sub => .{ ._, .sub },
                        else => unreachable,
                    },
                    lhs_ty,
                    dst_mcv,
                    tmp_mcv,
                );
            },

            .bool_or,
            .bit_or,
            => try self.gen_bin_op_mir(.{ ._, .@"or" }, lhs_ty, dst_mcv, src_mcv),

            .bool_and,
            .bit_and,
            => try self.gen_bin_op_mir(.{ ._, .@"and" }, lhs_ty, dst_mcv, src_mcv),

            .xor => try self.gen_bin_op_mir(.{ ._, .xor }, lhs_ty, dst_mcv, src_mcv),

            .min,
            .max,
            => {
                const resolved_src_mcv = switch (src_mcv) {
                    else => src_mcv,
                    .air_ref => |src_ref| try self.resolve_inst(src_ref),
                };

                if (abi_size > 8) {
                    const dst_regs = switch (dst_mcv) {
                        .register_pair => |dst_regs| dst_regs,
                        else => dst: {
                            const dst_regs = try self.register_manager.alloc_regs(
                                2,
                                .{null} ** 2,
                                abi.RegisterClass.gp,
                            );
                            const dst_regs_locks = self.register_manager.lock_regs_assume_unused(2, dst_regs);
                            defer for (dst_regs_locks) |lock| self.register_manager.unlock_reg(lock);

                            try self.gen_copy(lhs_ty, .{ .register_pair = dst_regs }, dst_mcv, .{});
                            break :dst dst_regs;
                        },
                    };
                    const dst_regs_locks = self.register_manager.lock_regs(2, dst_regs);
                    defer for (dst_regs_locks) |dst_lock| if (dst_lock) |lock|
                        self.register_manager.unlock_reg(lock);

                    const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    const signed = lhs_ty.is_signed_int(mod);
                    const cc: Condition = switch (air_tag) {
                        .min => if (signed) .nl else .nb,
                        .max => if (signed) .nge else .nae,
                        else => unreachable,
                    };

                    try self.asm_register_register(.{ ._, .mov }, tmp_reg, dst_regs[1]);
                    if (src_mcv.is_memory()) {
                        try self.asm_register_memory(
                            .{ ._, .cmp },
                            dst_regs[0],
                            try src_mcv.mem(self, .qword),
                        );
                        try self.asm_register_memory(
                            .{ ._, .sbb },
                            tmp_reg,
                            try src_mcv.address().offset(8).deref().mem(self, .qword),
                        );
                        try self.asm_cmovcc_register_memory(
                            cc,
                            dst_regs[0],
                            try src_mcv.mem(self, .qword),
                        );
                        try self.asm_cmovcc_register_memory(
                            cc,
                            dst_regs[1],
                            try src_mcv.address().offset(8).deref().mem(self, .qword),
                        );
                    } else {
                        try self.asm_register_register(
                            .{ ._, .cmp },
                            dst_regs[0],
                            src_mcv.register_pair[0],
                        );
                        try self.asm_register_register(
                            .{ ._, .sbb },
                            tmp_reg,
                            src_mcv.register_pair[1],
                        );
                        try self.asm_cmovcc_register_register(cc, dst_regs[0], src_mcv.register_pair[0]);
                        try self.asm_cmovcc_register_register(cc, dst_regs[1], src_mcv.register_pair[1]);
                    }
                    try self.gen_copy(lhs_ty, dst_mcv, .{ .register_pair = dst_regs }, .{});
                } else {
                    const mat_src_mcv: MCValue = if (switch (resolved_src_mcv) {
                        .immediate,
                        .eflags,
                        .register_offset,
                        .load_symbol,
                        .lea_symbol,
                        .load_direct,
                        .lea_direct,
                        .load_got,
                        .lea_got,
                        .load_tlv,
                        .lea_tlv,
                        .lea_frame,
                        => true,
                        .memory => |addr| math.cast(i32, @as(i64, @bit_cast(addr))) == null,
                        else => false,
                        .register_pair,
                        .register_overflow,
                        => unreachable,
                    })
                        .{ .register = try self.copy_to_tmp_register(rhs_ty, resolved_src_mcv) }
                    else
                        resolved_src_mcv;
                    const mat_mcv_lock = switch (mat_src_mcv) {
                        .register => |reg| self.register_manager.lock_reg(reg),
                        else => null,
                    };
                    defer if (mat_mcv_lock) |lock| self.register_manager.unlock_reg(lock);

                    try self.gen_bin_op_mir(.{ ._, .cmp }, lhs_ty, dst_mcv, mat_src_mcv);

                    const int_info = lhs_ty.int_info(mod);
                    const cc: Condition = switch (int_info.signedness) {
                        .unsigned => switch (air_tag) {
                            .min => .a,
                            .max => .b,
                            else => unreachable,
                        },
                        .signed => switch (air_tag) {
                            .min => .g,
                            .max => .l,
                            else => unreachable,
                        },
                    };

                    const cmov_abi_size = @max(@as(u32, @int_cast(lhs_ty.abi_size(mod))), 2);
                    const tmp_reg = switch (dst_mcv) {
                        .register => |reg| reg,
                        else => try self.copy_to_tmp_register(lhs_ty, dst_mcv),
                    };
                    const tmp_lock = self.register_manager.lock_reg(tmp_reg);
                    defer if (tmp_lock) |lock| self.register_manager.unlock_reg(lock);
                    switch (mat_src_mcv) {
                        .none,
                        .unreach,
                        .dead,
                        .undef,
                        .immediate,
                        .eflags,
                        .register_pair,
                        .register_offset,
                        .register_overflow,
                        .load_symbol,
                        .lea_symbol,
                        .load_direct,
                        .lea_direct,
                        .load_got,
                        .lea_got,
                        .load_tlv,
                        .lea_tlv,
                        .lea_frame,
                        .elementwise_regs_then_frame,
                        .reserved_frame,
                        .air_ref,
                        => unreachable,
                        .register => |src_reg| try self.asm_cmovcc_register_register(
                            cc,
                            register_alias(tmp_reg, cmov_abi_size),
                            register_alias(src_reg, cmov_abi_size),
                        ),
                        .memory, .indirect, .load_frame => try self.asm_cmovcc_register_memory(
                            cc,
                            register_alias(tmp_reg, cmov_abi_size),
                            switch (mat_src_mcv) {
                                .memory => |addr| .{
                                    .base = .{ .reg = .ds },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(cmov_abi_size),
                                        .disp = @int_cast(@as(i64, @bit_cast(addr))),
                                    } },
                                },
                                .indirect => |reg_off| .{
                                    .base = .{ .reg = reg_off.reg },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(cmov_abi_size),
                                        .disp = reg_off.off,
                                    } },
                                },
                                .load_frame => |frame_addr| .{
                                    .base = .{ .frame = frame_addr.index },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(cmov_abi_size),
                                        .disp = frame_addr.off,
                                    } },
                                },
                                else => unreachable,
                            },
                        ),
                    }
                    try self.gen_copy(lhs_ty, dst_mcv, .{ .register = tmp_reg }, .{});
                }
            },

            .cmp_eq, .cmp_neq => {
                assert(lhs_ty.is_vector(mod) and lhs_ty.child_type(mod).to_intern() == .bool_type);
                try self.gen_bin_op_mir(.{ ._, .xor }, lhs_ty, dst_mcv, src_mcv);
                switch (air_tag) {
                    .cmp_eq => try self.gen_un_op_mir(.{ ._, .not }, lhs_ty, dst_mcv),
                    .cmp_neq => {},
                    else => unreachable,
                }
            },

            else => return self.fail("TODO implement gen_bin_op for {s} {}", .{
                @tag_name(air_tag), lhs_ty.fmt(mod),
            }),
        }
        return dst_mcv;
    }

    const dst_reg = register_alias(dst_mcv.get_reg().?, abi_size);
    const mir_tag = @as(?Mir.Inst.FixedTag, switch (lhs_ty.zig_type_tag(mod)) {
        else => unreachable,
        .Float => switch (lhs_ty.float_bits(self.target.*)) {
            16 => {
                assert(self.has_feature(.f16c));
                const tmp_reg =
                    (try self.register_manager.alloc_reg(null, abi.RegisterClass.sse)).to128();
                const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                defer self.register_manager.unlock_reg(tmp_lock);

                if (src_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                    .{ .vp_w, .insr },
                    dst_reg,
                    dst_reg,
                    try src_mcv.mem(self, .word),
                    Immediate.u(1),
                ) else try self.asm_register_register_register(
                    .{ .vp_, .unpcklwd },
                    dst_reg,
                    dst_reg,
                    (if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                );
                try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, dst_reg);
                try self.asm_register_register(.{ .v_, .movshdup }, tmp_reg, dst_reg);
                try self.asm_register_register_register(
                    switch (air_tag) {
                        .add => .{ .v_ss, .add },
                        .sub => .{ .v_ss, .sub },
                        .mul => .{ .v_ss, .mul },
                        .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ss, .div },
                        .max => .{ .v_ss, .max },
                        .min => .{ .v_ss, .max },
                        else => unreachable,
                    },
                    dst_reg,
                    dst_reg,
                    tmp_reg,
                );
                switch (air_tag) {
                    .div_trunc, .div_floor => try self.asm_register_register_register_immediate(
                        .{ .v_ss, .round },
                        dst_reg,
                        dst_reg,
                        dst_reg,
                        Immediate.u(@as(u5, @bit_cast(RoundMode{
                            .mode = switch (air_tag) {
                                .div_trunc => .zero,
                                .div_floor => .down,
                                else => unreachable,
                            },
                            .precision = .inexact,
                        }))),
                    ),
                    else => {},
                }
                try self.asm_register_register_immediate(
                    .{ .v_, .cvtps2ph },
                    dst_reg,
                    dst_reg,
                    Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                );
                return dst_mcv;
            },
            32 => switch (air_tag) {
                .add => if (self.has_feature(.avx)) .{ .v_ss, .add } else .{ ._ss, .add },
                .sub => if (self.has_feature(.avx)) .{ .v_ss, .sub } else .{ ._ss, .sub },
                .mul => if (self.has_feature(.avx)) .{ .v_ss, .mul } else .{ ._ss, .mul },
                .div_float,
                .div_trunc,
                .div_floor,
                .div_exact,
                => if (self.has_feature(.avx)) .{ .v_ss, .div } else .{ ._ss, .div },
                .max => if (self.has_feature(.avx)) .{ .v_ss, .max } else .{ ._ss, .max },
                .min => if (self.has_feature(.avx)) .{ .v_ss, .min } else .{ ._ss, .min },
                else => unreachable,
            },
            64 => switch (air_tag) {
                .add => if (self.has_feature(.avx)) .{ .v_sd, .add } else .{ ._sd, .add },
                .sub => if (self.has_feature(.avx)) .{ .v_sd, .sub } else .{ ._sd, .sub },
                .mul => if (self.has_feature(.avx)) .{ .v_sd, .mul } else .{ ._sd, .mul },
                .div_float,
                .div_trunc,
                .div_floor,
                .div_exact,
                => if (self.has_feature(.avx)) .{ .v_sd, .div } else .{ ._sd, .div },
                .max => if (self.has_feature(.avx)) .{ .v_sd, .max } else .{ ._sd, .max },
                .min => if (self.has_feature(.avx)) .{ .v_sd, .min } else .{ ._sd, .min },
                else => unreachable,
            },
            80, 128 => null,
            else => unreachable,
        },
        .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
            else => null,
            .Int => switch (lhs_ty.child_type(mod).int_info(mod).bits) {
                8 => switch (lhs_ty.vector_len(mod)) {
                    1...16 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_b, .add } else .{ .p_b, .add },
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_b, .sub } else .{ .p_b, .sub },
                        .bit_and => if (self.has_feature(.avx))
                            .{ .vp_, .@"and" }
                        else
                            .{ .p_, .@"and" },
                        .bit_or => if (self.has_feature(.avx)) .{ .vp_, .@"or" } else .{ .p_, .@"or" },
                        .xor => if (self.has_feature(.avx)) .{ .vp_, .xor } else .{ .p_, .xor },
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_b, .mins }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_b, .mins }
                            else
                                null,
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_b, .minu }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_b, .minu }
                            else
                                null,
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_b, .maxs }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_b, .maxs }
                            else
                                null,
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_b, .maxu }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_b, .maxu }
                            else
                                null,
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_b, .cmpgt }
                            else
                                .{ .p_b, .cmpgt },
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_b, .cmpeq } else .{ .p_b, .cmpeq },
                        else => null,
                    },
                    17...32 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_b, .add } else null,
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_b, .sub } else null,
                        .bit_and => if (self.has_feature(.avx2)) .{ .vp_, .@"and" } else null,
                        .bit_or => if (self.has_feature(.avx2)) .{ .vp_, .@"or" } else null,
                        .xor => if (self.has_feature(.avx2)) .{ .vp_, .xor } else null,
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_b, .mins } else null,
                            .unsigned => if (self.has_feature(.avx)) .{ .vp_b, .minu } else null,
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_b, .maxs } else null,
                            .unsigned => if (self.has_feature(.avx2)) .{ .vp_b, .maxu } else null,
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx)) .{ .vp_b, .cmpgt } else null,
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_b, .cmpeq } else null,
                        else => null,
                    },
                    else => null,
                },
                16 => switch (lhs_ty.vector_len(mod)) {
                    1...8 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_w, .add } else .{ .p_w, .add },
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_w, .sub } else .{ .p_w, .sub },
                        .mul,
                        .mul_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_w, .mull } else .{ .p_d, .mull },
                        .bit_and => if (self.has_feature(.avx))
                            .{ .vp_, .@"and" }
                        else
                            .{ .p_, .@"and" },
                        .bit_or => if (self.has_feature(.avx)) .{ .vp_, .@"or" } else .{ .p_, .@"or" },
                        .xor => if (self.has_feature(.avx)) .{ .vp_, .xor } else .{ .p_, .xor },
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_w, .mins }
                            else
                                .{ .p_w, .mins },
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_w, .minu }
                            else
                                .{ .p_w, .minu },
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_w, .maxs }
                            else
                                .{ .p_w, .maxs },
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_w, .maxu }
                            else
                                .{ .p_w, .maxu },
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_w, .cmpgt }
                            else
                                .{ .p_w, .cmpgt },
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_w, .cmpeq } else .{ .p_w, .cmpeq },
                        else => null,
                    },
                    9...16 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_w, .add } else null,
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_w, .sub } else null,
                        .mul,
                        .mul_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_w, .mull } else null,
                        .bit_and => if (self.has_feature(.avx2)) .{ .vp_, .@"and" } else null,
                        .bit_or => if (self.has_feature(.avx2)) .{ .vp_, .@"or" } else null,
                        .xor => if (self.has_feature(.avx2)) .{ .vp_, .xor } else null,
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_w, .mins } else null,
                            .unsigned => if (self.has_feature(.avx)) .{ .vp_w, .minu } else null,
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_w, .maxs } else null,
                            .unsigned => if (self.has_feature(.avx2)) .{ .vp_w, .maxu } else null,
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx)) .{ .vp_w, .cmpgt } else null,
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_w, .cmpeq } else null,
                        else => null,
                    },
                    else => null,
                },
                32 => switch (lhs_ty.vector_len(mod)) {
                    1...4 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_d, .add } else .{ .p_d, .add },
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_d, .sub } else .{ .p_d, .sub },
                        .mul,
                        .mul_wrap,
                        => if (self.has_feature(.avx))
                            .{ .vp_d, .mull }
                        else if (self.has_feature(.sse4_1))
                            .{ .p_d, .mull }
                        else
                            null,
                        .bit_and => if (self.has_feature(.avx))
                            .{ .vp_, .@"and" }
                        else
                            .{ .p_, .@"and" },
                        .bit_or => if (self.has_feature(.avx)) .{ .vp_, .@"or" } else .{ .p_, .@"or" },
                        .xor => if (self.has_feature(.avx)) .{ .vp_, .xor } else .{ .p_, .xor },
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_d, .mins }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_d, .mins }
                            else
                                null,
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_d, .minu }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_d, .minu }
                            else
                                null,
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_d, .maxs }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_d, .maxs }
                            else
                                null,
                            .unsigned => if (self.has_feature(.avx))
                                .{ .vp_d, .maxu }
                            else if (self.has_feature(.sse4_1))
                                .{ .p_d, .maxu }
                            else
                                null,
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_d, .cmpgt }
                            else
                                .{ .p_d, .cmpgt },
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_d, .cmpeq } else .{ .p_d, .cmpeq },
                        else => null,
                    },
                    5...8 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_d, .add } else null,
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_d, .sub } else null,
                        .mul,
                        .mul_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_d, .mull } else null,
                        .bit_and => if (self.has_feature(.avx2)) .{ .vp_, .@"and" } else null,
                        .bit_or => if (self.has_feature(.avx2)) .{ .vp_, .@"or" } else null,
                        .xor => if (self.has_feature(.avx2)) .{ .vp_, .xor } else null,
                        .min => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_d, .mins } else null,
                            .unsigned => if (self.has_feature(.avx)) .{ .vp_d, .minu } else null,
                        },
                        .max => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx2)) .{ .vp_d, .maxs } else null,
                            .unsigned => if (self.has_feature(.avx2)) .{ .vp_d, .maxu } else null,
                        },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx)) .{ .vp_d, .cmpgt } else null,
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_d, .cmpeq } else null,
                        else => null,
                    },
                    else => null,
                },
                64 => switch (lhs_ty.vector_len(mod)) {
                    1...2 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_q, .add } else .{ .p_q, .add },
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx)) .{ .vp_q, .sub } else .{ .p_q, .sub },
                        .bit_and => if (self.has_feature(.avx))
                            .{ .vp_, .@"and" }
                        else
                            .{ .p_, .@"and" },
                        .bit_or => if (self.has_feature(.avx)) .{ .vp_, .@"or" } else .{ .p_, .@"or" },
                        .xor => if (self.has_feature(.avx)) .{ .vp_, .xor } else .{ .p_, .xor },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gte,
                        .cmp_gt,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx))
                                .{ .vp_q, .cmpgt }
                            else if (self.has_feature(.sse4_2))
                                .{ .p_q, .cmpgt }
                            else
                                null,
                            .unsigned => null,
                        },
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx))
                            .{ .vp_q, .cmpeq }
                        else if (self.has_feature(.sse4_1))
                            .{ .p_q, .cmpeq }
                        else
                            null,
                        else => null,
                    },
                    3...4 => switch (air_tag) {
                        .add,
                        .add_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_q, .add } else null,
                        .sub,
                        .sub_wrap,
                        => if (self.has_feature(.avx2)) .{ .vp_q, .sub } else null,
                        .bit_and => if (self.has_feature(.avx2)) .{ .vp_, .@"and" } else null,
                        .bit_or => if (self.has_feature(.avx2)) .{ .vp_, .@"or" } else null,
                        .xor => if (self.has_feature(.avx2)) .{ .vp_, .xor } else null,
                        .cmp_eq,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .vp_d, .cmpeq } else null,
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_gt,
                        .cmp_gte,
                        => switch (lhs_ty.child_type(mod).int_info(mod).signedness) {
                            .signed => if (self.has_feature(.avx)) .{ .vp_d, .cmpgt } else null,
                            .unsigned => null,
                        },
                        else => null,
                    },
                    else => null,
                },
                else => null,
            },
            .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                16 => tag: {
                    assert(self.has_feature(.f16c));
                    switch (lhs_ty.vector_len(mod)) {
                        1 => {
                            const tmp_reg = (try self.register_manager.alloc_reg(
                                null,
                                abi.RegisterClass.sse,
                            )).to128();
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            if (src_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                                .{ .vp_w, .insr },
                                dst_reg,
                                dst_reg,
                                try src_mcv.mem(self, .word),
                                Immediate.u(1),
                            ) else try self.asm_register_register_register(
                                .{ .vp_, .unpcklwd },
                                dst_reg,
                                dst_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, dst_reg);
                            try self.asm_register_register(.{ .v_, .movshdup }, tmp_reg, dst_reg);
                            try self.asm_register_register_register(
                                switch (air_tag) {
                                    .add => .{ .v_ss, .add },
                                    .sub => .{ .v_ss, .sub },
                                    .mul => .{ .v_ss, .mul },
                                    .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ss, .div },
                                    .max => .{ .v_ss, .max },
                                    .min => .{ .v_ss, .max },
                                    else => unreachable,
                                },
                                dst_reg,
                                dst_reg,
                                tmp_reg,
                            );
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                dst_reg,
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            return dst_mcv;
                        },
                        2 => {
                            const tmp_reg = (try self.register_manager.alloc_reg(
                                null,
                                abi.RegisterClass.sse,
                            )).to128();
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            if (src_mcv.is_memory()) try self.asm_register_memory_immediate(
                                .{ .vp_d, .insr },
                                dst_reg,
                                try src_mcv.mem(self, .dword),
                                Immediate.u(1),
                            ) else try self.asm_register_register_register(
                                .{ .v_ps, .unpckl },
                                dst_reg,
                                dst_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, dst_reg);
                            try self.asm_register_register_register(
                                .{ .v_ps, .movhl },
                                tmp_reg,
                                dst_reg,
                                dst_reg,
                            );
                            try self.asm_register_register_register(
                                switch (air_tag) {
                                    .add => .{ .v_ps, .add },
                                    .sub => .{ .v_ps, .sub },
                                    .mul => .{ .v_ps, .mul },
                                    .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ps, .div },
                                    .max => .{ .v_ps, .max },
                                    .min => .{ .v_ps, .max },
                                    else => unreachable,
                                },
                                dst_reg,
                                dst_reg,
                                tmp_reg,
                            );
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                dst_reg,
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            return dst_mcv;
                        },
                        3...4 => {
                            const tmp_reg = (try self.register_manager.alloc_reg(
                                null,
                                abi.RegisterClass.sse,
                            )).to128();
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg, dst_reg);
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                .{ .v_ps, .cvtph2 },
                                tmp_reg,
                                try src_mcv.mem(self, .qword),
                            ) else try self.asm_register_register(
                                .{ .v_ps, .cvtph2 },
                                tmp_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register_register(
                                switch (air_tag) {
                                    .add => .{ .v_ps, .add },
                                    .sub => .{ .v_ps, .sub },
                                    .mul => .{ .v_ps, .mul },
                                    .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ps, .div },
                                    .max => .{ .v_ps, .max },
                                    .min => .{ .v_ps, .max },
                                    else => unreachable,
                                },
                                dst_reg,
                                dst_reg,
                                tmp_reg,
                            );
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                dst_reg,
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            return dst_mcv;
                        },
                        5...8 => {
                            const tmp_reg = (try self.register_manager.alloc_reg(
                                null,
                                abi.RegisterClass.sse,
                            )).to256();
                            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                            defer self.register_manager.unlock_reg(tmp_lock);

                            try self.asm_register_register(.{ .v_ps, .cvtph2 }, dst_reg.to256(), dst_reg);
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                .{ .v_ps, .cvtph2 },
                                tmp_reg,
                                try src_mcv.mem(self, .xword),
                            ) else try self.asm_register_register(
                                .{ .v_ps, .cvtph2 },
                                tmp_reg,
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(rhs_ty, src_mcv)).to128(),
                            );
                            try self.asm_register_register_register(
                                switch (air_tag) {
                                    .add => .{ .v_ps, .add },
                                    .sub => .{ .v_ps, .sub },
                                    .mul => .{ .v_ps, .mul },
                                    .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ps, .div },
                                    .max => .{ .v_ps, .max },
                                    .min => .{ .v_ps, .max },
                                    else => unreachable,
                                },
                                dst_reg.to256(),
                                dst_reg.to256(),
                                tmp_reg,
                            );
                            try self.asm_register_register_immediate(
                                .{ .v_, .cvtps2ph },
                                dst_reg,
                                dst_reg.to256(),
                                Immediate.u(@as(u5, @bit_cast(RoundMode{ .mode = .mxcsr }))),
                            );
                            return dst_mcv;
                        },
                        else => break :tag null,
                    }
                },
                32 => switch (lhs_ty.vector_len(mod)) {
                    1 => switch (air_tag) {
                        .add => if (self.has_feature(.avx)) .{ .v_ss, .add } else .{ ._ss, .add },
                        .sub => if (self.has_feature(.avx)) .{ .v_ss, .sub } else .{ ._ss, .sub },
                        .mul => if (self.has_feature(.avx)) .{ .v_ss, .mul } else .{ ._ss, .mul },
                        .div_float,
                        .div_trunc,
                        .div_floor,
                        .div_exact,
                        => if (self.has_feature(.avx)) .{ .v_ss, .div } else .{ ._ss, .div },
                        .max => if (self.has_feature(.avx)) .{ .v_ss, .max } else .{ ._ss, .max },
                        .min => if (self.has_feature(.avx)) .{ .v_ss, .min } else .{ ._ss, .min },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_eq,
                        .cmp_gte,
                        .cmp_gt,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .v_ss, .cmp } else .{ ._ss, .cmp },
                        else => unreachable,
                    },
                    2...4 => switch (air_tag) {
                        .add => if (self.has_feature(.avx)) .{ .v_ps, .add } else .{ ._ps, .add },
                        .sub => if (self.has_feature(.avx)) .{ .v_ps, .sub } else .{ ._ps, .sub },
                        .mul => if (self.has_feature(.avx)) .{ .v_ps, .mul } else .{ ._ps, .mul },
                        .div_float,
                        .div_trunc,
                        .div_floor,
                        .div_exact,
                        => if (self.has_feature(.avx)) .{ .v_ps, .div } else .{ ._ps, .div },
                        .max => if (self.has_feature(.avx)) .{ .v_ps, .max } else .{ ._ps, .max },
                        .min => if (self.has_feature(.avx)) .{ .v_ps, .min } else .{ ._ps, .min },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_eq,
                        .cmp_gte,
                        .cmp_gt,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .v_ps, .cmp } else .{ ._ps, .cmp },
                        else => unreachable,
                    },
                    5...8 => if (self.has_feature(.avx)) switch (air_tag) {
                        .add => .{ .v_ps, .add },
                        .sub => .{ .v_ps, .sub },
                        .mul => .{ .v_ps, .mul },
                        .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_ps, .div },
                        .max => .{ .v_ps, .max },
                        .min => .{ .v_ps, .min },
                        .cmp_lt, .cmp_lte, .cmp_eq, .cmp_gte, .cmp_gt, .cmp_neq => .{ .v_ps, .cmp },
                        else => unreachable,
                    } else null,
                    else => null,
                },
                64 => switch (lhs_ty.vector_len(mod)) {
                    1 => switch (air_tag) {
                        .add => if (self.has_feature(.avx)) .{ .v_sd, .add } else .{ ._sd, .add },
                        .sub => if (self.has_feature(.avx)) .{ .v_sd, .sub } else .{ ._sd, .sub },
                        .mul => if (self.has_feature(.avx)) .{ .v_sd, .mul } else .{ ._sd, .mul },
                        .div_float,
                        .div_trunc,
                        .div_floor,
                        .div_exact,
                        => if (self.has_feature(.avx)) .{ .v_sd, .div } else .{ ._sd, .div },
                        .max => if (self.has_feature(.avx)) .{ .v_sd, .max } else .{ ._sd, .max },
                        .min => if (self.has_feature(.avx)) .{ .v_sd, .min } else .{ ._sd, .min },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_eq,
                        .cmp_gte,
                        .cmp_gt,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .v_sd, .cmp } else .{ ._sd, .cmp },
                        else => unreachable,
                    },
                    2 => switch (air_tag) {
                        .add => if (self.has_feature(.avx)) .{ .v_pd, .add } else .{ ._pd, .add },
                        .sub => if (self.has_feature(.avx)) .{ .v_pd, .sub } else .{ ._pd, .sub },
                        .mul => if (self.has_feature(.avx)) .{ .v_pd, .mul } else .{ ._pd, .mul },
                        .div_float,
                        .div_trunc,
                        .div_floor,
                        .div_exact,
                        => if (self.has_feature(.avx)) .{ .v_pd, .div } else .{ ._pd, .div },
                        .max => if (self.has_feature(.avx)) .{ .v_pd, .max } else .{ ._pd, .max },
                        .min => if (self.has_feature(.avx)) .{ .v_pd, .min } else .{ ._pd, .min },
                        .cmp_lt,
                        .cmp_lte,
                        .cmp_eq,
                        .cmp_gte,
                        .cmp_gt,
                        .cmp_neq,
                        => if (self.has_feature(.avx)) .{ .v_pd, .cmp } else .{ ._pd, .cmp },
                        else => unreachable,
                    },
                    3...4 => if (self.has_feature(.avx)) switch (air_tag) {
                        .add => .{ .v_pd, .add },
                        .sub => .{ .v_pd, .sub },
                        .mul => .{ .v_pd, .mul },
                        .div_float, .div_trunc, .div_floor, .div_exact => .{ .v_pd, .div },
                        .max => .{ .v_pd, .max },
                        .cmp_lt, .cmp_lte, .cmp_eq, .cmp_gte, .cmp_gt, .cmp_neq => .{ .v_pd, .cmp },
                        .min => .{ .v_pd, .min },
                        else => unreachable,
                    } else null,
                    else => null,
                },
                80, 128 => null,
                else => unreachable,
            },
        },
    }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
        @tag_name(air_tag), lhs_ty.fmt(mod),
    });

    const lhs_copy_reg = if (maybe_mask_reg) |_| register_alias(
        if (copied_to_dst) try self.copy_to_tmp_register(lhs_ty, dst_mcv) else lhs_mcv.get_reg().?,
        abi_size,
    ) else null;
    const lhs_copy_lock = if (lhs_copy_reg) |reg| self.register_manager.lock_reg(reg) else null;
    defer if (lhs_copy_lock) |lock| self.register_manager.unlock_reg(lock);

    switch (mir_tag[1]) {
        else => if (self.has_feature(.avx)) {
            const lhs_reg =
                if (copied_to_dst) dst_reg else register_alias(lhs_mcv.get_reg().?, abi_size);
            if (src_mcv.is_memory()) try self.asm_register_register_memory(
                mir_tag,
                dst_reg,
                lhs_reg,
                try src_mcv.mem(self, switch (lhs_ty.zig_type_tag(mod)) {
                    else => Memory.Size.from_size(abi_size),
                    .Vector => Memory.Size.from_bit_size(dst_reg.bit_size()),
                }),
            ) else try self.asm_register_register_register(
                mir_tag,
                dst_reg,
                lhs_reg,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(rhs_ty, src_mcv), abi_size),
            );
        } else {
            assert(copied_to_dst);
            if (src_mcv.is_memory()) try self.asm_register_memory(
                mir_tag,
                dst_reg,
                try src_mcv.mem(self, switch (lhs_ty.zig_type_tag(mod)) {
                    else => Memory.Size.from_size(abi_size),
                    .Vector => Memory.Size.from_bit_size(dst_reg.bit_size()),
                }),
            ) else try self.asm_register_register(
                mir_tag,
                dst_reg,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(rhs_ty, src_mcv), abi_size),
            );
        },
        .cmp => {
            const imm = Immediate.u(switch (air_tag) {
                .cmp_eq => 0,
                .cmp_lt, .cmp_gt => 1,
                .cmp_lte, .cmp_gte => 2,
                .cmp_neq => 4,
                else => unreachable,
            });
            if (self.has_feature(.avx)) {
                const lhs_reg =
                    if (copied_to_dst) dst_reg else register_alias(lhs_mcv.get_reg().?, abi_size);
                if (src_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                    mir_tag,
                    dst_reg,
                    lhs_reg,
                    try src_mcv.mem(self, switch (lhs_ty.zig_type_tag(mod)) {
                        else => Memory.Size.from_size(abi_size),
                        .Vector => Memory.Size.from_bit_size(dst_reg.bit_size()),
                    }),
                    imm,
                ) else try self.asm_register_register_register_immediate(
                    mir_tag,
                    dst_reg,
                    lhs_reg,
                    register_alias(if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(rhs_ty, src_mcv), abi_size),
                    imm,
                );
            } else {
                assert(copied_to_dst);
                if (src_mcv.is_memory()) try self.asm_register_memory_immediate(
                    mir_tag,
                    dst_reg,
                    try src_mcv.mem(self, switch (lhs_ty.zig_type_tag(mod)) {
                        else => Memory.Size.from_size(abi_size),
                        .Vector => Memory.Size.from_bit_size(dst_reg.bit_size()),
                    }),
                    imm,
                ) else try self.asm_register_register_immediate(
                    mir_tag,
                    dst_reg,
                    register_alias(if (src_mcv.is_register())
                        src_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(rhs_ty, src_mcv), abi_size),
                    imm,
                );
            }
        },
    }

    switch (air_tag) {
        .add, .add_wrap, .sub, .sub_wrap, .mul, .mul_wrap, .div_float, .div_exact => {},
        .div_trunc, .div_floor => try self.gen_round(lhs_ty, dst_reg, .{ .register = dst_reg }, .{
            .mode = switch (air_tag) {
                .div_trunc => .zero,
                .div_floor => .down,
                else => unreachable,
            },
            .precision = .inexact,
        }),
        .bit_and, .bit_or, .xor => {},
        .max, .min => if (maybe_mask_reg) |mask_reg| if (self.has_feature(.avx)) {
            const rhs_copy_reg = register_alias(src_mcv.get_reg().?, abi_size);

            try self.asm_register_register_register_immediate(
                @as(?Mir.Inst.FixedTag, switch (lhs_ty.zig_type_tag(mod)) {
                    .Float => switch (lhs_ty.float_bits(self.target.*)) {
                        32 => .{ .v_ss, .cmp },
                        64 => .{ .v_sd, .cmp },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                        .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                            32 => switch (lhs_ty.vector_len(mod)) {
                                1 => .{ .v_ss, .cmp },
                                2...8 => .{ .v_ps, .cmp },
                                else => null,
                            },
                            64 => switch (lhs_ty.vector_len(mod)) {
                                1 => .{ .v_sd, .cmp },
                                2...4 => .{ .v_pd, .cmp },
                                else => null,
                            },
                            16, 80, 128 => null,
                            else => unreachable,
                        },
                        else => unreachable,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
                    @tag_name(air_tag), lhs_ty.fmt(mod),
                }),
                mask_reg,
                rhs_copy_reg,
                rhs_copy_reg,
                Immediate.u(3), // unord
            );
            try self.asm_register_register_register_register(
                @as(?Mir.Inst.FixedTag, switch (lhs_ty.zig_type_tag(mod)) {
                    .Float => switch (lhs_ty.float_bits(self.target.*)) {
                        32 => .{ .v_ps, .blendv },
                        64 => .{ .v_pd, .blendv },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                        .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                            32 => switch (lhs_ty.vector_len(mod)) {
                                1...8 => .{ .v_ps, .blendv },
                                else => null,
                            },
                            64 => switch (lhs_ty.vector_len(mod)) {
                                1...4 => .{ .v_pd, .blendv },
                                else => null,
                            },
                            16, 80, 128 => null,
                            else => unreachable,
                        },
                        else => unreachable,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
                    @tag_name(air_tag), lhs_ty.fmt(mod),
                }),
                dst_reg,
                dst_reg,
                lhs_copy_reg.?,
                mask_reg,
            );
        } else {
            const has_blend = self.has_feature(.sse4_1);
            try self.asm_register_register_immediate(
                @as(?Mir.Inst.FixedTag, switch (lhs_ty.zig_type_tag(mod)) {
                    .Float => switch (lhs_ty.float_bits(self.target.*)) {
                        32 => .{ ._ss, .cmp },
                        64 => .{ ._sd, .cmp },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                        .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                            32 => switch (lhs_ty.vector_len(mod)) {
                                1 => .{ ._ss, .cmp },
                                2...4 => .{ ._ps, .cmp },
                                else => null,
                            },
                            64 => switch (lhs_ty.vector_len(mod)) {
                                1 => .{ ._sd, .cmp },
                                2 => .{ ._pd, .cmp },
                                else => null,
                            },
                            16, 80, 128 => null,
                            else => unreachable,
                        },
                        else => unreachable,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
                    @tag_name(air_tag), lhs_ty.fmt(mod),
                }),
                mask_reg,
                mask_reg,
                Immediate.u(if (has_blend) 3 else 7), // unord, ord
            );
            if (has_blend) try self.asm_register_register_register(
                @as(?Mir.Inst.FixedTag, switch (lhs_ty.zig_type_tag(mod)) {
                    .Float => switch (lhs_ty.float_bits(self.target.*)) {
                        32 => .{ ._ps, .blendv },
                        64 => .{ ._pd, .blendv },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                        .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                            32 => switch (lhs_ty.vector_len(mod)) {
                                1...4 => .{ ._ps, .blendv },
                                else => null,
                            },
                            64 => switch (lhs_ty.vector_len(mod)) {
                                1...2 => .{ ._pd, .blendv },
                                else => null,
                            },
                            16, 80, 128 => null,
                            else => unreachable,
                        },
                        else => unreachable,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
                    @tag_name(air_tag), lhs_ty.fmt(mod),
                }),
                dst_reg,
                lhs_copy_reg.?,
                mask_reg,
            ) else {
                const mir_fixes = @as(?Mir.Inst.Fixes, switch (lhs_ty.zig_type_tag(mod)) {
                    .Float => switch (lhs_ty.float_bits(self.target.*)) {
                        32 => ._ps,
                        64 => ._pd,
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    .Vector => switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                        .Float => switch (lhs_ty.child_type(mod).float_bits(self.target.*)) {
                            32 => switch (lhs_ty.vector_len(mod)) {
                                1...4 => ._ps,
                                else => null,
                            },
                            64 => switch (lhs_ty.vector_len(mod)) {
                                1...2 => ._pd,
                                else => null,
                            },
                            16, 80, 128 => null,
                            else => unreachable,
                        },
                        else => unreachable,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement gen_bin_op for {s} {}", .{
                    @tag_name(air_tag), lhs_ty.fmt(mod),
                });
                try self.asm_register_register(.{ mir_fixes, .@"and" }, dst_reg, mask_reg);
                try self.asm_register_register(.{ mir_fixes, .andn }, mask_reg, lhs_copy_reg.?);
                try self.asm_register_register(.{ mir_fixes, .@"or" }, dst_reg, mask_reg);
            }
        },
        .cmp_lt, .cmp_lte, .cmp_eq, .cmp_gte, .cmp_gt, .cmp_neq => {
            switch (lhs_ty.child_type(mod).zig_type_tag(mod)) {
                .Int => switch (air_tag) {
                    .cmp_lt,
                    .cmp_eq,
                    .cmp_gt,
                    => {},
                    .cmp_lte,
                    .cmp_gte,
                    .cmp_neq,
                    => {
                        const unsigned_ty = try lhs_ty.to_unsigned(mod);
                        const not_mcv = try self.gen_typed_value(try unsigned_ty.max_int(mod, unsigned_ty));
                        const not_mem: Memory = if (not_mcv.is_memory())
                            try not_mcv.mem(self, Memory.Size.from_size(abi_size))
                        else
                            .{ .base = .{
                                .reg = try self.copy_to_tmp_register(Type.usize, not_mcv.address()),
                            }, .mod = .{ .rm = .{ .size = Memory.Size.from_size(abi_size) } } };
                        switch (mir_tag[0]) {
                            .vp_b, .vp_d, .vp_q, .vp_w => try self.asm_register_register_memory(
                                .{ .vp_, .xor },
                                dst_reg,
                                dst_reg,
                                not_mem,
                            ),
                            .p_b, .p_d, .p_q, .p_w => try self.asm_register_memory(
                                .{ .p_, .xor },
                                dst_reg,
                                not_mem,
                            ),
                            else => unreachable,
                        }
                    },
                    else => unreachable,
                },
                .Float => {},
                else => unreachable,
            }

            const gp_reg = try self.register_manager.alloc_reg(maybe_inst, abi.RegisterClass.gp);
            const gp_lock = self.register_manager.lock_reg_assume_unused(gp_reg);
            defer self.register_manager.unlock_reg(gp_lock);

            try self.asm_register_register(switch (mir_tag[0]) {
                ._pd, ._sd, .p_q => .{ ._pd, .movmsk },
                ._ps, ._ss, .p_d => .{ ._ps, .movmsk },
                .p_b => .{ .p_b, .movmsk },
                .p_w => movmsk: {
                    try self.asm_register_register(.{ .p_b, .ackssw }, dst_reg, dst_reg);
                    break :movmsk .{ .p_b, .movmsk };
                },
                .v_pd, .v_sd, .vp_q => .{ .v_pd, .movmsk },
                .v_ps, .v_ss, .vp_d => .{ .v_ps, .movmsk },
                .vp_b => .{ .vp_b, .movmsk },
                .vp_w => movmsk: {
                    try self.asm_register_register_register(
                        .{ .vp_b, .ackssw },
                        dst_reg,
                        dst_reg,
                        dst_reg,
                    );
                    break :movmsk .{ .vp_b, .movmsk };
                },
                else => unreachable,
            }, gp_reg.to32(), dst_reg);
            return .{ .register = gp_reg };
        },
        else => unreachable,
    }

    return dst_mcv;
}

fn gen_bin_op_mir(
    self: *Self,
    mir_tag: Mir.Inst.FixedTag,
    ty: Type,
    dst_mcv: MCValue,
    src_mcv: MCValue,
) !void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    try self.spill_eflags_if_occupied();
    switch (dst_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .immediate,
        .eflags,
        .register_overflow,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        .lea_symbol,
        .elementwise_regs_then_frame,
        .reserved_frame,
        .air_ref,
        => unreachable, // unmodifiable destination
        .register, .register_pair, .register_offset => {
            switch (dst_mcv) {
                .register, .register_pair => {},
                .register_offset => |ro| assert(ro.off == 0),
                else => unreachable,
            }
            for (dst_mcv.get_regs(), 0..) |dst_reg, dst_reg_i| {
                const dst_reg_lock = self.register_manager.lock_reg(dst_reg);
                defer if (dst_reg_lock) |lock| self.register_manager.unlock_reg(lock);

                const mir_limb_tag: Mir.Inst.FixedTag = switch (dst_reg_i) {
                    0 => mir_tag,
                    1 => switch (mir_tag[1]) {
                        .add => .{ ._, .adc },
                        .sub, .cmp => .{ ._, .sbb },
                        .@"or", .@"and", .xor => mir_tag,
                        else => return self.fail("TODO gen_bin_op_mir implement large ABI for {s}", .{
                            @tag_name(mir_tag[1]),
                        }),
                    },
                    else => unreachable,
                };
                const off: u4 = @int_cast(dst_reg_i * 8);
                const limb_abi_size = @min(abi_size - off, 8);
                const dst_alias = register_alias(dst_reg, limb_abi_size);
                switch (src_mcv) {
                    .none,
                    .unreach,
                    .dead,
                    .undef,
                    .register_overflow,
                    .elementwise_regs_then_frame,
                    .reserved_frame,
                    => unreachable,
                    .register, .register_pair => try self.asm_register_register(
                        mir_limb_tag,
                        dst_alias,
                        register_alias(src_mcv.get_regs()[dst_reg_i], limb_abi_size),
                    ),
                    .immediate => |imm| {
                        assert(off == 0);
                        switch (self.reg_bit_size(ty)) {
                            8 => try self.asm_register_immediate(
                                mir_limb_tag,
                                dst_alias,
                                if (math.cast(i8, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u8, @int_cast(imm))),
                            ),
                            16 => try self.asm_register_immediate(
                                mir_limb_tag,
                                dst_alias,
                                if (math.cast(i16, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u16, @int_cast(imm))),
                            ),
                            32 => try self.asm_register_immediate(
                                mir_limb_tag,
                                dst_alias,
                                if (math.cast(i32, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u32, @int_cast(imm))),
                            ),
                            64 => if (math.cast(i32, @as(i64, @bit_cast(imm)))) |small|
                                try self.asm_register_immediate(mir_limb_tag, dst_alias, Immediate.s(small))
                            else
                                try self.asm_register_register(mir_limb_tag, dst_alias, register_alias(
                                    try self.copy_to_tmp_register(ty, src_mcv),
                                    limb_abi_size,
                                )),
                            else => unreachable,
                        }
                    },
                    .eflags,
                    .register_offset,
                    .memory,
                    .indirect,
                    .load_symbol,
                    .lea_symbol,
                    .load_direct,
                    .lea_direct,
                    .load_got,
                    .lea_got,
                    .load_tlv,
                    .lea_tlv,
                    .load_frame,
                    .lea_frame,
                    => {
                        direct: {
                            try self.asm_register_memory(mir_limb_tag, dst_alias, switch (src_mcv) {
                                .memory => |addr| .{
                                    .base = .{ .reg = .ds },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(limb_abi_size),
                                        .disp = math.cast(i32, addr + off) orelse break :direct,
                                    } },
                                },
                                .indirect => |reg_off| .{
                                    .base = .{ .reg = reg_off.reg },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(limb_abi_size),
                                        .disp = reg_off.off + off,
                                    } },
                                },
                                .load_frame => |frame_addr| .{
                                    .base = .{ .frame = frame_addr.index },
                                    .mod = .{ .rm = .{
                                        .size = Memory.Size.from_size(limb_abi_size),
                                        .disp = frame_addr.off + off,
                                    } },
                                },
                                else => break :direct,
                            });
                            continue;
                        }

                        switch (src_mcv) {
                            .eflags,
                            .register_offset,
                            .lea_symbol,
                            .lea_direct,
                            .lea_got,
                            .lea_tlv,
                            .lea_frame,
                            => {
                                assert(off == 0);
                                const reg = try self.copy_to_tmp_register(ty, src_mcv);
                                return self.gen_bin_op_mir(
                                    mir_limb_tag,
                                    ty,
                                    dst_mcv,
                                    .{ .register = reg },
                                );
                            },
                            .memory,
                            .load_symbol,
                            .load_direct,
                            .load_got,
                            .load_tlv,
                            => {
                                const ptr_ty = try mod.single_const_ptr_type(ty);
                                const addr_reg = try self.copy_to_tmp_register(ptr_ty, src_mcv.address());
                                return self.gen_bin_op_mir(mir_limb_tag, ty, dst_mcv, .{
                                    .indirect = .{ .reg = addr_reg, .off = off },
                                });
                            },
                            else => unreachable,
                        }
                    },
                    .air_ref => |src_ref| return self.gen_bin_op_mir(
                        mir_tag,
                        ty,
                        dst_mcv,
                        try self.resolve_inst(src_ref),
                    ),
                }
            }
        },
        .memory, .indirect, .load_symbol, .load_got, .load_direct, .load_tlv, .load_frame => {
            const OpInfo = ?struct { addr_reg: Register, addr_lock: RegisterLock };
            const limb_abi_size: u32 = @min(abi_size, 8);

            const dst_info: OpInfo = switch (dst_mcv) {
                else => unreachable,
                .memory, .load_symbol, .load_got, .load_direct, .load_tlv => dst: {
                    const dst_addr_reg =
                        (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to64();
                    const dst_addr_lock = self.register_manager.lock_reg_assume_unused(dst_addr_reg);
                    errdefer self.register_manager.unlock_reg(dst_addr_lock);

                    try self.gen_set_reg(dst_addr_reg, Type.usize, dst_mcv.address(), .{});
                    break :dst .{ .addr_reg = dst_addr_reg, .addr_lock = dst_addr_lock };
                },
                .load_frame => null,
            };
            defer if (dst_info) |info| self.register_manager.unlock_reg(info.addr_lock);

            const resolved_src_mcv = switch (src_mcv) {
                else => src_mcv,
                .air_ref => |src_ref| try self.resolve_inst(src_ref),
            };
            const src_info: OpInfo = switch (resolved_src_mcv) {
                .none,
                .unreach,
                .dead,
                .undef,
                .register_overflow,
                .elementwise_regs_then_frame,
                .reserved_frame,
                .air_ref,
                => unreachable,
                .immediate,
                .eflags,
                .register,
                .register_pair,
                .register_offset,
                .indirect,
                .lea_direct,
                .lea_got,
                .lea_tlv,
                .load_frame,
                .lea_frame,
                .lea_symbol,
                => null,
                .memory, .load_symbol, .load_got, .load_direct, .load_tlv => src: {
                    switch (resolved_src_mcv) {
                        .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr))) != null and
                            math.cast(i32, @as(i64, @bit_cast(addr)) + abi_size - limb_abi_size) != null)
                            break :src null,
                        .load_symbol, .load_got, .load_direct, .load_tlv => {},
                        else => unreachable,
                    }

                    const src_addr_reg =
                        (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to64();
                    const src_addr_lock = self.register_manager.lock_reg_assume_unused(src_addr_reg);
                    errdefer self.register_manager.unlock_reg(src_addr_lock);

                    try self.gen_set_reg(src_addr_reg, Type.usize, resolved_src_mcv.address(), .{});
                    break :src .{ .addr_reg = src_addr_reg, .addr_lock = src_addr_lock };
                },
            };
            defer if (src_info) |info| self.register_manager.unlock_reg(info.addr_lock);

            const ty_signedness =
                if (ty.is_abi_int(mod)) ty.int_info(mod).signedness else .unsigned;
            const limb_ty = if (abi_size <= 8) ty else switch (ty_signedness) {
                .signed => Type.usize,
                .unsigned => Type.isize,
            };
            var limb_i: usize = 0;
            var off: i32 = 0;
            while (off < abi_size) : ({
                limb_i += 1;
                off += 8;
            }) {
                const mir_limb_tag: Mir.Inst.FixedTag = switch (limb_i) {
                    0 => mir_tag,
                    else => switch (mir_tag[1]) {
                        .add => .{ ._, .adc },
                        .sub, .cmp => .{ ._, .sbb },
                        .@"or", .@"and", .xor => mir_tag,
                        else => return self.fail("TODO gen_bin_op_mir implement large ABI for {s}", .{
                            @tag_name(mir_tag[1]),
                        }),
                    },
                };
                const dst_limb_mem: Memory = switch (dst_mcv) {
                    .memory,
                    .load_symbol,
                    .load_got,
                    .load_direct,
                    .load_tlv,
                    => .{
                        .base = .{ .reg = dst_info.?.addr_reg },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(limb_abi_size),
                            .disp = off,
                        } },
                    },
                    .indirect => |reg_off| .{
                        .base = .{ .reg = reg_off.reg },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(limb_abi_size),
                            .disp = reg_off.off + off,
                        } },
                    },
                    .load_frame => |frame_addr| .{
                        .base = .{ .frame = frame_addr.index },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(limb_abi_size),
                            .disp = frame_addr.off + off,
                        } },
                    },
                    else => unreachable,
                };
                switch (resolved_src_mcv) {
                    .none,
                    .unreach,
                    .dead,
                    .undef,
                    .register_overflow,
                    .elementwise_regs_then_frame,
                    .reserved_frame,
                    .air_ref,
                    => unreachable,
                    .immediate => |src_imm| {
                        const imm: u64 = switch (limb_i) {
                            0 => src_imm,
                            else => switch (ty_signedness) {
                                .signed => @bit_cast(@as(i64, @bit_cast(src_imm)) >> 63),
                                .unsigned => 0,
                            },
                        };
                        switch (self.reg_bit_size(limb_ty)) {
                            8 => try self.asm_memory_immediate(
                                mir_limb_tag,
                                dst_limb_mem,
                                if (math.cast(i8, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u8, @int_cast(imm))),
                            ),
                            16 => try self.asm_memory_immediate(
                                mir_limb_tag,
                                dst_limb_mem,
                                if (math.cast(i16, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u16, @int_cast(imm))),
                            ),
                            32 => try self.asm_memory_immediate(
                                mir_limb_tag,
                                dst_limb_mem,
                                if (math.cast(i32, @as(i64, @bit_cast(imm)))) |small|
                                    Immediate.s(small)
                                else
                                    Immediate.u(@as(u32, @int_cast(imm))),
                            ),
                            64 => if (math.cast(i32, @as(i64, @bit_cast(imm)))) |small|
                                try self.asm_memory_immediate(
                                    mir_limb_tag,
                                    dst_limb_mem,
                                    Immediate.s(small),
                                )
                            else
                                try self.asm_memory_register(
                                    mir_limb_tag,
                                    dst_limb_mem,
                                    register_alias(
                                        try self.copy_to_tmp_register(limb_ty, .{ .immediate = imm }),
                                        limb_abi_size,
                                    ),
                                ),
                            else => unreachable,
                        }
                    },
                    .register,
                    .register_pair,
                    .register_offset,
                    .eflags,
                    .memory,
                    .indirect,
                    .load_symbol,
                    .lea_symbol,
                    .load_direct,
                    .lea_direct,
                    .load_got,
                    .lea_got,
                    .load_tlv,
                    .lea_tlv,
                    .load_frame,
                    .lea_frame,
                    => {
                        const src_limb_mcv: MCValue = if (src_info) |info| .{
                            .indirect = .{ .reg = info.addr_reg, .off = off },
                        } else switch (resolved_src_mcv) {
                            .register, .register_pair => .{
                                .register = resolved_src_mcv.get_regs()[limb_i],
                            },
                            .eflags,
                            .register_offset,
                            .lea_symbol,
                            .lea_direct,
                            .lea_got,
                            .lea_tlv,
                            .lea_frame,
                            => switch (limb_i) {
                                0 => resolved_src_mcv,
                                else => .{ .immediate = 0 },
                            },
                            .memory => |addr| .{ .memory = @bit_cast(@as(i64, @bit_cast(addr)) + off) },
                            .indirect => |reg_off| .{ .indirect = .{
                                .reg = reg_off.reg,
                                .off = reg_off.off + off,
                            } },
                            .load_frame => |frame_addr| .{ .load_frame = .{
                                .index = frame_addr.index,
                                .off = frame_addr.off + off,
                            } },
                            else => unreachable,
                        };
                        const src_limb_reg = if (src_limb_mcv.is_register())
                            src_limb_mcv.get_reg().?
                        else
                            try self.copy_to_tmp_register(limb_ty, src_limb_mcv);
                        try self.asm_memory_register(
                            mir_limb_tag,
                            dst_limb_mem,
                            register_alias(src_limb_reg, limb_abi_size),
                        );
                    },
                }
            }
        },
    }
}

/// Performs multi-operand integer multiplication between dst_mcv and src_mcv, storing the result in dst_mcv.
/// Does not support byte-size operands.
fn gen_int_mul_complex_op_mir(self: *Self, dst_ty: Type, dst_mcv: MCValue, src_mcv: MCValue) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    try self.spill_eflags_if_occupied();
    switch (dst_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .immediate,
        .eflags,
        .register_offset,
        .register_overflow,
        .lea_symbol,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        .elementwise_regs_then_frame,
        .reserved_frame,
        .air_ref,
        => unreachable, // unmodifiable destination
        .register => |dst_reg| {
            const dst_alias = register_alias(dst_reg, abi_size);
            const dst_lock = self.register_manager.lock_reg(dst_reg);
            defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

            const resolved_src_mcv = switch (src_mcv) {
                else => src_mcv,
                .air_ref => |src_ref| try self.resolve_inst(src_ref),
            };
            switch (resolved_src_mcv) {
                .none,
                .unreach,
                .dead,
                .undef,
                .register_pair,
                .register_overflow,
                .elementwise_regs_then_frame,
                .reserved_frame,
                .air_ref,
                => unreachable,
                .register => |src_reg| try self.asm_register_register(
                    .{ .i_, .mul },
                    dst_alias,
                    register_alias(src_reg, abi_size),
                ),
                .immediate => |imm| {
                    if (math.cast(i32, imm)) |small| {
                        try self.asm_register_register_immediate(
                            .{ .i_, .mul },
                            dst_alias,
                            dst_alias,
                            Immediate.s(small),
                        );
                    } else {
                        const src_reg = try self.copy_to_tmp_register(dst_ty, resolved_src_mcv);
                        return self.gen_int_mul_complex_op_mir(dst_ty, dst_mcv, MCValue{ .register = src_reg });
                    }
                },
                .register_offset,
                .eflags,
                .load_symbol,
                .lea_symbol,
                .load_direct,
                .lea_direct,
                .load_got,
                .lea_got,
                .load_tlv,
                .lea_tlv,
                .lea_frame,
                => try self.asm_register_register(
                    .{ .i_, .mul },
                    dst_alias,
                    register_alias(try self.copy_to_tmp_register(dst_ty, resolved_src_mcv), abi_size),
                ),
                .memory, .indirect, .load_frame => try self.asm_register_memory(
                    .{ .i_, .mul },
                    dst_alias,
                    switch (resolved_src_mcv) {
                        .memory => |addr| .{
                            .base = .{ .reg = .ds },
                            .mod = .{ .rm = .{
                                .size = Memory.Size.from_size(abi_size),
                                .disp = math.cast(i32, @as(i64, @bit_cast(addr))) orelse
                                    return self.asm_register_register(
                                    .{ .i_, .mul },
                                    dst_alias,
                                    register_alias(
                                        try self.copy_to_tmp_register(dst_ty, resolved_src_mcv),
                                        abi_size,
                                    ),
                                ),
                            } },
                        },
                        .indirect => |reg_off| .{
                            .base = .{ .reg = reg_off.reg },
                            .mod = .{ .rm = .{
                                .size = Memory.Size.from_size(abi_size),
                                .disp = reg_off.off,
                            } },
                        },
                        .load_frame => |frame_addr| .{
                            .base = .{ .frame = frame_addr.index },
                            .mod = .{ .rm = .{
                                .size = Memory.Size.from_size(abi_size),
                                .disp = frame_addr.off,
                            } },
                        },
                        else => unreachable,
                    },
                ),
            }
        },
        .register_pair => unreachable, // unimplemented
        .memory, .indirect, .load_symbol, .load_direct, .load_got, .load_tlv, .load_frame => {
            const tmp_reg = try self.copy_to_tmp_register(dst_ty, dst_mcv);
            const tmp_mcv = MCValue{ .register = tmp_reg };
            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
            defer self.register_manager.unlock_reg(tmp_lock);

            try self.gen_int_mul_complex_op_mir(dst_ty, tmp_mcv, src_mcv);
            try self.gen_copy(dst_ty, dst_mcv, tmp_mcv, .{});
        },
    }
}

fn air_arg(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    // skip zero-bit arguments as they don't have a corresponding arg instruction
    var arg_index = self.arg_index;
    while (self.args[arg_index] == .none) arg_index += 1;
    self.arg_index = arg_index + 1;

    const result: MCValue = if (self.liveness.is_unused(inst)) .unreach else result: {
        const arg_ty = self.type_of_index(inst);
        const src_mcv = self.args[arg_index];
        const dst_mcv = switch (src_mcv) {
            .register, .register_pair, .load_frame => dst: {
                for (src_mcv.get_regs()) |reg| self.register_manager.get_reg_assume_free(reg, inst);
                break :dst src_mcv;
            },
            .indirect => |reg_off| dst: {
                self.register_manager.get_reg_assume_free(reg_off.reg, inst);
                const dst_mcv = try self.alloc_reg_or_mem(inst, false);
                try self.gen_copy(arg_ty, dst_mcv, src_mcv, .{});
                break :dst dst_mcv;
            },
            .elementwise_regs_then_frame => |regs_frame_addr| dst: {
                try self.spill_eflags_if_occupied();

                const fn_info = mod.type_to_func(self.fn_type).?;
                const cc = abi.resolve_calling_convention(fn_info.cc, self.target.*);
                const param_int_regs = abi.get_cabi_int_param_regs(cc);
                var prev_reg: Register = undefined;
                for (
                    param_int_regs[param_int_regs.len - regs_frame_addr.regs ..],
                    0..,
                ) |dst_reg, elem_index| {
                    assert(self.register_manager.is_reg_free(dst_reg));
                    if (elem_index > 0) {
                        try self.asm_register_immediate(
                            .{ ._l, .sh },
                            dst_reg.to8(),
                            Immediate.u(elem_index),
                        );
                        try self.asm_register_register(
                            .{ ._, .@"or" },
                            dst_reg.to8(),
                            prev_reg.to8(),
                        );
                    }
                    prev_reg = dst_reg;
                }

                const prev_lock = if (regs_frame_addr.regs > 0)
                    self.register_manager.lock_reg_assume_unused(prev_reg)
                else
                    null;
                defer if (prev_lock) |lock| self.register_manager.unlock_reg(lock);

                const dst_mcv = try self.alloc_reg_or_mem(inst, false);
                if (regs_frame_addr.regs > 0) try self.asm_memory_register(
                    .{ ._, .mov },
                    try dst_mcv.mem(self, .byte),
                    prev_reg.to8(),
                );
                try self.gen_inline_memset(
                    dst_mcv.address().offset(@int_from_bool(regs_frame_addr.regs > 0)),
                    .{ .immediate = 0 },
                    .{ .immediate = arg_ty.abi_size(mod) - @int_from_bool(regs_frame_addr.regs > 0) },
                    .{},
                );

                const index_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const index_lock = self.register_manager.lock_reg_assume_unused(index_reg);
                defer self.register_manager.unlock_reg(index_lock);

                try self.asm_register_immediate(
                    .{ ._, .mov },
                    index_reg.to32(),
                    Immediate.u(regs_frame_addr.regs),
                );
                const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_memory_immediate(.{ ._, .cmp }, .{
                    .base = .{ .frame = regs_frame_addr.frame_index },
                    .mod = .{ .rm = .{
                        .size = .byte,
                        .index = index_reg.to64(),
                        .scale = .@"8",
                        .disp = regs_frame_addr.frame_off - @as(u6, regs_frame_addr.regs) * 8,
                    } },
                }, Immediate.u(0));
                const unset = try self.asm_jcc_reloc(.e, undefined);
                try self.asm_memory_register(
                    .{ ._s, .bt },
                    try dst_mcv.mem(self, .dword),
                    index_reg.to32(),
                );
                self.perform_reloc(unset);
                if (self.has_feature(.slow_incdec)) {
                    try self.asm_register_immediate(.{ ._, .add }, index_reg.to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, index_reg.to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    index_reg.to32(),
                    Immediate.u(arg_ty.vector_len(mod)),
                );
                _ = try self.asm_jcc_reloc(.b, loop);

                break :dst dst_mcv;
            },
            else => return self.fail("TODO implement arg for {}", .{src_mcv}),
        };

        const src_index = self.air.instructions.items(.data)[@int_from_enum(inst)].arg.src_index;
        const name = mod.get_param_name(self.owner.func_index, src_index);
        try self.gen_arg_dbg_info(arg_ty, name, src_mcv);

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn gen_arg_dbg_info(self: Self, ty: Type, name: [:0]const u8, mcv: MCValue) !void {
    const mod = self.bin_file.comp.module.?;
    switch (self.debug_output) {
        .dwarf => |dw| {
            const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (mcv) {
                .register => |reg| .{ .register = reg.dwarf_num() },
                .register_pair => |regs| .{ .register_pair = .{
                    regs[0].dwarf_num(), regs[1].dwarf_num(),
                } },
                // TODO use a frame index
                .load_frame, .elementwise_regs_then_frame => return,
                //.stack_offset => |off| .{
                //    .stack = .{
                //        // TODO handle -fomit-frame-pointer
                //        .fp_register = Register.rbp.dwarf_num(),
                //        .offset = -off,
                //    },
                //},
                else => unreachable, // not a valid function parameter
            };
            // TODO: this might need adjusting like the linkers do.
            // Instead of flattening the owner and passing Decl.Index here we may
            // want to special case LazySymbol in DWARF linker too.
            try dw.gen_arg_dbg_info(name, ty, self.owner.get_decl(mod), loc);
        },
        .plan9 => {},
        .none => {},
    }
}

fn gen_var_dbg_info(
    self: Self,
    tag: Air.Inst.Tag,
    ty: Type,
    mcv: MCValue,
    name: [:0]const u8,
) !void {
    const mod = self.bin_file.comp.module.?;
    const is_ptr = switch (tag) {
        .dbg_var_ptr => true,
        .dbg_var_val => false,
        else => unreachable,
    };

    switch (self.debug_output) {
        .dwarf => |dw| {
            const loc: link.File.Dwarf.DeclState.DbgInfoLoc = switch (mcv) {
                .register => |reg| .{ .register = reg.dwarf_num() },
                // TODO use a frame index
                .load_frame, .lea_frame => return,
                //=> |off| .{ .stack = .{
                //    .fp_register = Register.rbp.dwarf_num(),
                //    .offset = -off,
                //} },
                .memory => |address| .{ .memory = address },
                .load_symbol => |sym_off| loc: {
                    assert(sym_off.off == 0);
                    break :loc .{ .linker_load = .{ .type = .direct, .sym_index = sym_off.sym } };
                }, // TODO
                .load_got => |sym_index| .{ .linker_load = .{ .type = .got, .sym_index = sym_index } },
                .load_direct => |sym_index| .{
                    .linker_load = .{ .type = .direct, .sym_index = sym_index },
                },
                .immediate => |x| .{ .immediate = x },
                .undef => .undef,
                .none => .none,
                else => blk: {
                    log.debug("TODO generate debug info for {}", .{mcv});
                    break :blk .nop;
                },
            };
            // TODO: this might need adjusting like the linkers do.
            // Instead of flattening the owner and passing Decl.Index here we may
            // want to special case LazySymbol in DWARF linker too.
            try dw.gen_var_dbg_info(name, ty, self.owner.get_decl(mod), is_ptr, loc);
        },
        .plan9 => {},
        .none => {},
    }
}

fn air_trap(self: *Self) !void {
    try self.asm_op_only(.{ ._, .ud2 });
    self.finish_air_bookkeeping();
}

fn air_breakpoint(self: *Self) !void {
    try self.asm_op_only(.{ ._, .int3 });
    self.finish_air_bookkeeping();
}

fn air_ret_addr(self: *Self, inst: Air.Inst.Index) !void {
    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
    try self.gen_copy(Type.usize, dst_mcv, .{ .load_frame = .{ .index = .ret_addr } }, .{});
    return self.finish_air(inst, dst_mcv, .{ .none, .none, .none });
}

fn air_frame_address(self: *Self, inst: Air.Inst.Index) !void {
    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
    try self.gen_copy(Type.usize, dst_mcv, .{ .lea_frame = .{ .index = .base_ptr } }, .{});
    return self.finish_air(inst, dst_mcv, .{ .none, .none, .none });
}

fn air_fence(self: *Self, inst: Air.Inst.Index) !void {
    const order = self.air.instructions.items(.data)[@int_from_enum(inst)].fence;
    switch (order) {
        .unordered, .monotonic => unreachable,
        .acquire, .release, .acq_rel => {},
        .seq_cst => try self.asm_op_only(.{ ._, .mfence }),
    }
    self.finish_air_bookkeeping();
}

fn air_call(self: *Self, inst: Air.Inst.Index, modifier: std.builtin.CallModifier) !void {
    if (modifier == .always_tail) return self.fail("TODO implement tail calls for x86_64", .{});

    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Call, pl_op.payload);
    const arg_refs: []const Air.Inst.Ref =
        @ptr_cast(self.air.extra[extra.end..][0..extra.data.args_len]);

    const ExpectedContents = extern struct {
        tys: [16][@size_of(Type)]u8 align(@alignOf(Type)),
        vals: [16][@size_of(MCValue)]u8 align(@alignOf(MCValue)),
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

    const ret = try self.gen_call(.{ .air = pl_op.operand }, arg_tys, arg_vals);

    var bt = self.liveness.iterate_big_tomb(inst);
    try self.feed(&bt, pl_op.operand);
    for (arg_refs) |arg_ref| try self.feed(&bt, arg_ref);

    const result = if (self.liveness.is_unused(inst)) .unreach else ret;
    return self.finish_air_result(inst, result);
}

fn gen_call(self: *Self, info: union(enum) {
    air: Air.Inst.Ref,
    lib: struct {
        return_type: InternPool.Index,
        param_types: []const InternPool.Index,
        lib: ?[]const u8 = null,
        callee: []const u8,
    },
}, arg_types: []const Type, args: []const MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;

    const fn_ty = switch (info) {
        .air => |callee| fn_info: {
            const callee_ty = self.type_of(callee);
            break :fn_info switch (callee_ty.zig_type_tag(mod)) {
                .Fn => callee_ty,
                .Pointer => callee_ty.child_type(mod),
                else => unreachable,
            };
        },
        .lib => |lib| try mod.func_type(.{
            .param_types = lib.param_types,
            .return_type = lib.return_type,
            .cc = .C,
        }),
    };
    const fn_info = mod.type_to_func(fn_ty).?;
    const resolved_cc = abi.resolve_calling_convention(fn_info.cc, self.target.*);

    const ExpectedContents = extern struct {
        var_args: [16][@size_of(Type)]u8 align(@alignOf(Type)),
        frame_indices: [16]FrameIndex,
        reg_locks: [16][@size_of(?RegisterLock)]u8 align(@alignOf(?RegisterLock)),
    };
    var stack align(@max(@alignOf(ExpectedContents), @alignOf(std.heap.StackFallbackAllocator(0)))) =
        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
    const allocator = stack.get();

    const var_args = try allocator.alloc(Type, args.len - fn_info.param_types.len);
    defer allocator.free(var_args);
    for (var_args, arg_types[fn_info.param_types.len..]) |*var_arg, arg_ty| var_arg.* = arg_ty;

    const frame_indices = try allocator.alloc(FrameIndex, args.len);
    defer allocator.free(frame_indices);

    var reg_locks = std.ArrayList(?RegisterLock).init(allocator);
    defer reg_locks.deinit();
    try reg_locks.ensure_total_capacity(16);
    defer for (reg_locks.items) |reg_lock| if (reg_lock) |lock| self.register_manager.unlock_reg(lock);

    var call_info = try self.resolve_calling_convention_values(fn_info, var_args, .call_frame);
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

    try self.spill_eflags_if_occupied();
    try self.spill_caller_preserved_regs(resolved_cc);

    // set stack arguments first because this can clobber registers
    // also clobber spill arguments as we go
    switch (call_info.return_value.long) {
        .none, .unreach => {},
        .indirect => |reg_off| try self.register_manager.get_reg(reg_off.reg, null),
        else => unreachable,
    }
    for (call_info.args, arg_types, args, frame_indices) |dst_arg, arg_ty, src_arg, *frame_index|
        switch (dst_arg) {
            .none => {},
            .register => |reg| {
                try self.register_manager.get_reg(reg, null);
                try reg_locks.append(self.register_manager.lock_reg(reg));
            },
            .register_pair => |regs| {
                for (regs) |reg| try self.register_manager.get_reg(reg, null);
                try reg_locks.append_slice(&self.register_manager.lock_regs(2, regs));
            },
            .indirect => |reg_off| {
                frame_index.* = try self.alloc_frame_index(FrameAlloc.init_type(arg_ty, mod));
                try self.gen_set_mem(.{ .frame = frame_index.* }, 0, arg_ty, src_arg, .{});
                try self.register_manager.get_reg(reg_off.reg, null);
                try reg_locks.append(self.register_manager.lock_reg(reg_off.reg));
            },
            .load_frame => {
                try self.gen_copy(arg_ty, dst_arg, src_arg, .{});
                try self.free_value(src_arg);
            },
            .elementwise_regs_then_frame => |regs_frame_addr| {
                const index_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const index_lock = self.register_manager.lock_reg_assume_unused(index_reg);
                defer self.register_manager.unlock_reg(index_lock);

                const src_mem: Memory = if (src_arg.is_memory()) try src_arg.mem(self, .dword) else .{
                    .base = .{ .reg = try self.copy_to_tmp_register(
                        Type.usize,
                        switch (src_arg) {
                            else => src_arg,
                            .air_ref => |src_ref| try self.resolve_inst(src_ref),
                        }.address(),
                    ) },
                    .mod = .{ .rm = .{ .size = .dword } },
                };
                const src_lock = switch (src_mem.base) {
                    .reg => |src_reg| self.register_manager.lock_reg(src_reg),
                    else => null,
                };
                defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

                try self.asm_register_immediate(
                    .{ ._, .mov },
                    index_reg.to32(),
                    Immediate.u(regs_frame_addr.regs),
                );
                const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
                try self.asm_memory_register(.{ ._, .bt }, src_mem, index_reg.to32());
                try self.asm_setcc_memory(.c, .{
                    .base = .{ .frame = regs_frame_addr.frame_index },
                    .mod = .{ .rm = .{
                        .size = .byte,
                        .index = index_reg.to64(),
                        .scale = .@"8",
                        .disp = regs_frame_addr.frame_off - @as(u6, regs_frame_addr.regs) * 8,
                    } },
                });
                if (self.has_feature(.slow_incdec)) {
                    try self.asm_register_immediate(.{ ._, .add }, index_reg.to32(), Immediate.u(1));
                } else {
                    try self.asm_register(.{ ._, .inc }, index_reg.to32());
                }
                try self.asm_register_immediate(
                    .{ ._, .cmp },
                    index_reg.to32(),
                    Immediate.u(arg_ty.vector_len(mod)),
                );
                _ = try self.asm_jcc_reloc(.b, loop);

                const param_int_regs = abi.get_cabi_int_param_regs(resolved_cc);
                for (param_int_regs[param_int_regs.len - regs_frame_addr.regs ..]) |dst_reg| {
                    try self.register_manager.get_reg(dst_reg, null);
                    try reg_locks.append(self.register_manager.lock_reg(dst_reg));
                }
            },
            else => unreachable,
        };

    // now we are free to set register arguments
    switch (call_info.return_value.long) {
        .none, .unreach => {},
        .indirect => |reg_off| {
            const ret_ty = Type.from_interned(fn_info.return_type);
            const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(ret_ty, mod));
            try self.gen_set_reg(reg_off.reg, Type.usize, .{
                .lea_frame = .{ .index = frame_index, .off = -reg_off.off },
            }, .{});
            call_info.return_value.short = .{ .load_frame = .{ .index = frame_index } };
            try reg_locks.append(self.register_manager.lock_reg(reg_off.reg));
        },
        else => unreachable,
    }

    for (call_info.args, arg_types, args, frame_indices) |dst_arg, arg_ty, src_arg, frame_index|
        switch (dst_arg) {
            .none, .load_frame => {},
            .register => |dst_reg| switch (fn_info.cc) {
                else => try self.gen_set_reg(
                    register_alias(dst_reg, @int_cast(arg_ty.abi_size(mod))),
                    arg_ty,
                    src_arg,
                    .{},
                ),
                .C, .SysV, .Win64 => {
                    const promoted_ty = self.promote_int(arg_ty);
                    const promoted_abi_size: u32 = @int_cast(promoted_ty.abi_size(mod));
                    const dst_alias = register_alias(dst_reg, promoted_abi_size);
                    try self.gen_set_reg(dst_alias, promoted_ty, src_arg, .{});
                    if (promoted_ty.to_intern() != arg_ty.to_intern())
                        try self.truncate_register(arg_ty, dst_alias);
                },
            },
            .register_pair => try self.gen_copy(arg_ty, dst_arg, src_arg, .{}),
            .indirect => |reg_off| try self.gen_set_reg(reg_off.reg, Type.usize, .{
                .lea_frame = .{ .index = frame_index, .off = -reg_off.off },
            }, .{}),
            .elementwise_regs_then_frame => |regs_frame_addr| {
                const src_mem: Memory = if (src_arg.is_memory()) try src_arg.mem(self, .dword) else .{
                    .base = .{ .reg = try self.copy_to_tmp_register(
                        Type.usize,
                        switch (src_arg) {
                            else => src_arg,
                            .air_ref => |src_ref| try self.resolve_inst(src_ref),
                        }.address(),
                    ) },
                    .mod = .{ .rm = .{ .size = .dword } },
                };
                const src_lock = switch (src_mem.base) {
                    .reg => |src_reg| self.register_manager.lock_reg(src_reg),
                    else => null,
                };
                defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

                const param_int_regs = abi.get_cabi_int_param_regs(resolved_cc);
                for (
                    param_int_regs[param_int_regs.len - regs_frame_addr.regs ..],
                    0..,
                ) |dst_reg, elem_index| {
                    try self.asm_register_register(.{ ._, .xor }, dst_reg.to32(), dst_reg.to32());
                    try self.asm_memory_immediate(
                        .{ ._, .bt },
                        src_mem,
                        Immediate.u(elem_index),
                    );
                    try self.asm_setcc_register(.c, dst_reg.to8());
                }
            },
            else => unreachable,
        };

    if (fn_info.is_var_args)
        try self.asm_register_immediate(.{ ._, .mov }, .al, Immediate.u(call_info.fp_count));

    // Due to incremental compilation, how function calls are generated depends
    // on linking.
    switch (info) {
        .air => |callee| if (try self.air.value(callee, mod)) |func_value| {
            const func_key = mod.intern_pool.index_to_key(func_value.ip_index);
            switch (switch (func_key) {
                else => func_key,
                .ptr => |ptr| if (ptr.byte_offset == 0) switch (ptr.base_addr) {
                    .decl => |decl| mod.intern_pool.index_to_key(mod.decl_ptr(decl).val.to_intern()),
                    else => func_key,
                } else func_key,
            }) {
                .func => |func| {
                    if (self.bin_file.cast(link.File.Elf)) |elf_file| {
                        const sym_index = try elf_file.zig_object_ptr().?.get_or_create_metadata_for_decl(elf_file, func.owner_decl);
                        const sym = elf_file.symbol(sym_index);
                        if (self.mod.pic) {
                            const callee_reg: Register = switch (resolved_cc) {
                                .SysV => callee: {
                                    if (!fn_info.is_var_args) break :callee .rax;
                                    const param_regs = abi.get_cabi_int_param_regs(resolved_cc);
                                    break :callee if (call_info.gp_count < param_regs.len)
                                        param_regs[call_info.gp_count]
                                    else
                                        .r10;
                                },
                                .Win64 => .rax,
                                else => unreachable,
                            };
                            try self.gen_set_reg(
                                callee_reg,
                                Type.usize,
                                .{ .load_symbol = .{ .sym = sym.esym_index } },
                                .{},
                            );
                            try self.asm_register(.{ ._, .call }, callee_reg);
                        } else try self.asm_memory(.{ ._, .call }, .{
                            .base = .{ .reloc = .{
                                .atom_index = try self.owner.get_symbol_index(self),
                                .sym_index = sym.esym_index,
                            } },
                            .mod = .{ .rm = .{ .size = .qword } },
                        });
                    } else if (self.bin_file.cast(link.File.Coff)) |coff_file| {
                        const atom = try coff_file.get_or_create_atom_for_decl(func.owner_decl);
                        const sym_index = coff_file.get_atom(atom).get_symbol_index().?;
                        try self.gen_set_reg(.rax, Type.usize, .{ .lea_got = sym_index }, .{});
                        try self.asm_register(.{ ._, .call }, .rax);
                    } else if (self.bin_file.cast(link.File.MachO)) |macho_file| {
                        const sym_index = try macho_file.get_zig_object().?.get_or_create_metadata_for_decl(macho_file, func.owner_decl);
                        const sym = macho_file.get_symbol(sym_index);
                        try self.gen_set_reg(
                            .rax,
                            Type.usize,
                            .{ .load_symbol = .{ .sym = sym.nlist_idx } },
                            .{},
                        );
                        try self.asm_register(.{ ._, .call }, .rax);
                    } else if (self.bin_file.cast(link.File.Plan9)) |p9| {
                        const atom_index = try p9.see_decl(func.owner_decl);
                        const atom = p9.get_atom(atom_index);
                        try self.asm_memory(.{ ._, .call }, .{
                            .base = .{ .reg = .ds },
                            .mod = .{ .rm = .{
                                .size = .qword,
                                .disp = @int_cast(atom.get_offset_table_address(p9)),
                            } },
                        });
                    } else unreachable;
                },
                .extern_func => |extern_func| {
                    const owner_decl = mod.decl_ptr(extern_func.decl);
                    const lib_name = extern_func.lib_name.to_slice(&mod.intern_pool);
                    const decl_name = owner_decl.name.to_slice(&mod.intern_pool);
                    try self.gen_extern_symbol_ref(.call, lib_name, decl_name);
                },
                else => return self.fail("TODO implement calling bitcasted functions", .{}),
            }
        } else {
            assert(self.type_of(callee).zig_type_tag(mod) == .Pointer);
            try self.gen_set_reg(.rax, Type.usize, .{ .air_ref = callee }, .{});
            try self.asm_register(.{ ._, .call }, .rax);
        },
        .lib => |lib| try self.gen_extern_symbol_ref(.call, lib.lib, lib.callee),
    }
    return call_info.return_value.short;
}

fn air_ret(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const ret_ty = self.fn_type.fn_return_type(mod);
    switch (self.ret_mcv.short) {
        .none => {},
        .register,
        .register_pair,
        => try self.gen_copy(ret_ty, self.ret_mcv.short, .{ .air_ref = un_op }, .{ .safety = safety }),
        .indirect => |reg_off| {
            try self.register_manager.get_reg(reg_off.reg, null);
            const lock = self.register_manager.lock_reg_assume_unused(reg_off.reg);
            defer self.register_manager.unlock_reg(lock);

            try self.gen_set_reg(reg_off.reg, Type.usize, self.ret_mcv.long, .{});
            try self.gen_set_mem(
                .{ .reg = reg_off.reg },
                reg_off.off,
                ret_ty,
                .{ .air_ref = un_op },
                .{ .safety = safety },
            );
        },
        else => unreachable,
    }
    self.ret_mcv.live_out(self, inst);
    try self.finish_air(inst, .unreach, .{ un_op, .none, .none });

    // TODO optimization opportunity: figure out when we can emit this as a 2 byte instruction
    // which is available if the jump is 127 bytes or less forward.
    const jmp_reloc = try self.asm_jmp_reloc(undefined);
    try self.exitlude_jump_relocs.append(self.gpa, jmp_reloc);
}

fn air_ret_load(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const ptr = try self.resolve_inst(un_op);

    const ptr_ty = self.type_of(un_op);
    switch (self.ret_mcv.short) {
        .none => {},
        .register, .register_pair => try self.load(self.ret_mcv.short, ptr_ty, ptr),
        .indirect => |reg_off| try self.gen_set_reg(reg_off.reg, ptr_ty, ptr, .{}),
        else => unreachable,
    }
    self.ret_mcv.live_out(self, inst);
    try self.finish_air(inst, .unreach, .{ un_op, .none, .none });

    // TODO optimization opportunity: figure out when we can emit this as a 2 byte instruction
    // which is available if the jump is 127 bytes or less forward.
    const jmp_reloc = try self.asm_jmp_reloc(undefined);
    try self.exitlude_jump_relocs.append(self.gpa, jmp_reloc);
}

fn air_cmp(self: *Self, inst: Air.Inst.Index, op: math.CompareOperator) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
    var ty = self.type_of(bin_op.lhs);
    var null_compare: ?Mir.Inst.Index = null;

    const result: Condition = result: {
        try self.spill_eflags_if_occupied();

        const lhs_mcv = try self.resolve_inst(bin_op.lhs);
        const lhs_locks: [2]?RegisterLock = switch (lhs_mcv) {
            .register => |lhs_reg| .{ self.register_manager.lock_reg_assume_unused(lhs_reg), null },
            .register_pair => |lhs_regs| locks: {
                const locks = self.register_manager.lock_regs_assume_unused(2, lhs_regs);
                break :locks .{ locks[0], locks[1] };
            },
            .register_offset => |lhs_ro| .{
                self.register_manager.lock_reg_assume_unused(lhs_ro.reg),
                null,
            },
            else => .{null} ** 2,
        };
        defer for (lhs_locks) |lhs_lock| if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const rhs_mcv = try self.resolve_inst(bin_op.rhs);
        const rhs_locks: [2]?RegisterLock = switch (rhs_mcv) {
            .register => |rhs_reg| .{ self.register_manager.lock_reg(rhs_reg), null },
            .register_pair => |rhs_regs| self.register_manager.lock_regs(2, rhs_regs),
            .register_offset => |rhs_ro| .{ self.register_manager.lock_reg(rhs_ro.reg), null },
            else => .{null} ** 2,
        };
        defer for (rhs_locks) |rhs_lock| if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

        switch (ty.zig_type_tag(mod)) {
            .Float => {
                const float_bits = ty.float_bits(self.target.*);
                if (switch (float_bits) {
                    16 => !self.has_feature(.f16c),
                    32, 64 => false,
                    80, 128 => true,
                    else => unreachable,
                }) {
                    var callee_buf: ["__???f2".len]u8 = undefined;
                    const ret = try self.gen_call(.{ .lib = .{
                        .return_type = .i32_type,
                        .param_types = &.{ ty.to_intern(), ty.to_intern() },
                        .callee = std.fmt.buf_print(&callee_buf, "__{s}{c}f2", .{
                            switch (op) {
                                .eq => "eq",
                                .neq => "ne",
                                .lt => "lt",
                                .lte => "le",
                                .gt => "gt",
                                .gte => "ge",
                            },
                            float_compiler_rt_abi_name(float_bits),
                        }) catch unreachable,
                    } }, &.{ ty, ty }, &.{ .{ .air_ref = bin_op.lhs }, .{ .air_ref = bin_op.rhs } });
                    try self.gen_bin_op_mir(.{ ._, .@"test" }, Type.i32, ret, ret);
                    break :result switch (op) {
                        .eq => .e,
                        .neq => .ne,
                        .lt => .l,
                        .lte => .le,
                        .gt => .g,
                        .gte => .ge,
                    };
                }
            },
            .Optional => if (!ty.optional_repr_is_payload(mod)) {
                const opt_ty = ty;
                const opt_abi_size: u31 = @int_cast(opt_ty.abi_size(mod));
                ty = opt_ty.optional_child(mod);
                const payload_abi_size: u31 = @int_cast(ty.abi_size(mod));

                const temp_lhs_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const temp_lhs_lock = self.register_manager.lock_reg_assume_unused(temp_lhs_reg);
                defer self.register_manager.unlock_reg(temp_lhs_lock);

                if (lhs_mcv.is_memory()) try self.asm_register_memory(
                    .{ ._, .mov },
                    temp_lhs_reg.to8(),
                    try lhs_mcv.address().offset(payload_abi_size).deref().mem(self, .byte),
                ) else {
                    try self.gen_set_reg(temp_lhs_reg, opt_ty, lhs_mcv, .{});
                    try self.asm_register_immediate(
                        .{ ._r, .sh },
                        register_alias(temp_lhs_reg, opt_abi_size),
                        Immediate.u(payload_abi_size * 8),
                    );
                }

                const payload_compare = payload_compare: {
                    if (rhs_mcv.is_memory()) {
                        const rhs_mem =
                            try rhs_mcv.address().offset(payload_abi_size).deref().mem(self, .byte);
                        try self.asm_memory_register(.{ ._, .@"test" }, rhs_mem, temp_lhs_reg.to8());
                        const payload_compare = try self.asm_jcc_reloc(.nz, undefined);
                        try self.asm_register_memory(.{ ._, .cmp }, temp_lhs_reg.to8(), rhs_mem);
                        break :payload_compare payload_compare;
                    }

                    const temp_rhs_reg = try self.copy_to_tmp_register(opt_ty, rhs_mcv);
                    const temp_rhs_lock = self.register_manager.lock_reg_assume_unused(temp_rhs_reg);
                    defer self.register_manager.unlock_reg(temp_rhs_lock);

                    try self.asm_register_immediate(
                        .{ ._r, .sh },
                        register_alias(temp_rhs_reg, opt_abi_size),
                        Immediate.u(payload_abi_size * 8),
                    );
                    try self.asm_register_register(
                        .{ ._, .@"test" },
                        temp_lhs_reg.to8(),
                        temp_rhs_reg.to8(),
                    );
                    const payload_compare = try self.asm_jcc_reloc(.nz, undefined);
                    try self.asm_register_register(
                        .{ ._, .cmp },
                        temp_lhs_reg.to8(),
                        temp_rhs_reg.to8(),
                    );
                    break :payload_compare payload_compare;
                };
                null_compare = try self.asm_jmp_reloc(undefined);
                self.perform_reloc(payload_compare);
            },
            else => {},
        }

        switch (ty.zig_type_tag(mod)) {
            else => {
                const abi_size: u16 = @int_cast(ty.abi_size(mod));
                const may_flip: enum {
                    may_flip,
                    must_flip,
                    must_not_flip,
                } = if (abi_size > 8) switch (op) {
                    .lt, .gte => .must_not_flip,
                    .lte, .gt => .must_flip,
                    .eq, .neq => .may_flip,
                } else .may_flip;

                const flipped = switch (may_flip) {
                    .may_flip => !lhs_mcv.is_register() and !lhs_mcv.is_memory(),
                    .must_flip => true,
                    .must_not_flip => false,
                };
                const unmat_dst_mcv = if (flipped) rhs_mcv else lhs_mcv;
                const dst_mcv = if (unmat_dst_mcv.is_register() or
                    (abi_size <= 8 and unmat_dst_mcv.is_memory())) unmat_dst_mcv else dst: {
                    const dst_mcv = try self.alloc_temp_reg_or_mem(ty, true);
                    try self.gen_copy(ty, dst_mcv, unmat_dst_mcv, .{});
                    break :dst dst_mcv;
                };
                const dst_lock =
                    if (dst_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
                defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

                const src_mcv = try self.resolve_inst(if (flipped) bin_op.lhs else bin_op.rhs);
                const src_lock =
                    if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
                defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

                break :result Condition.from_compare_operator(
                    if (ty.is_abi_int(mod)) ty.int_info(mod).signedness else .unsigned,
                    result_op: {
                        const flipped_op = if (flipped) op.reverse() else op;
                        if (abi_size > 8) switch (flipped_op) {
                            .lt, .gte => {},
                            .lte, .gt => unreachable,
                            .eq, .neq => {
                                const OpInfo = ?struct { addr_reg: Register, addr_lock: RegisterLock };

                                const resolved_dst_mcv = switch (dst_mcv) {
                                    else => dst_mcv,
                                    .air_ref => |dst_ref| try self.resolve_inst(dst_ref),
                                };
                                const dst_info: OpInfo = switch (resolved_dst_mcv) {
                                    .none,
                                    .unreach,
                                    .dead,
                                    .undef,
                                    .immediate,
                                    .eflags,
                                    .register,
                                    .register_offset,
                                    .register_overflow,
                                    .indirect,
                                    .lea_direct,
                                    .lea_got,
                                    .lea_tlv,
                                    .lea_frame,
                                    .lea_symbol,
                                    .elementwise_regs_then_frame,
                                    .reserved_frame,
                                    .air_ref,
                                    => unreachable,
                                    .register_pair, .load_frame => null,
                                    .memory, .load_symbol, .load_got, .load_direct, .load_tlv => dst: {
                                        switch (resolved_dst_mcv) {
                                            .memory => |addr| if (math.cast(
                                                i32,
                                                @as(i64, @bit_cast(addr)),
                                            ) != null and math.cast(
                                                i32,
                                                @as(i64, @bit_cast(addr)) + abi_size - 8,
                                            ) != null) break :dst null,
                                            .load_symbol, .load_got, .load_direct, .load_tlv => {},
                                            else => unreachable,
                                        }

                                        const dst_addr_reg = (try self.register_manager.alloc_reg(
                                            null,
                                            abi.RegisterClass.gp,
                                        )).to64();
                                        const dst_addr_lock =
                                            self.register_manager.lock_reg_assume_unused(dst_addr_reg);
                                        errdefer self.register_manager.unlock_reg(dst_addr_lock);

                                        try self.gen_set_reg(
                                            dst_addr_reg,
                                            Type.usize,
                                            resolved_dst_mcv.address(),
                                            .{},
                                        );
                                        break :dst .{
                                            .addr_reg = dst_addr_reg,
                                            .addr_lock = dst_addr_lock,
                                        };
                                    },
                                };
                                defer if (dst_info) |info|
                                    self.register_manager.unlock_reg(info.addr_lock);

                                const resolved_src_mcv = switch (src_mcv) {
                                    else => src_mcv,
                                    .air_ref => |src_ref| try self.resolve_inst(src_ref),
                                };
                                const src_info: OpInfo = switch (resolved_src_mcv) {
                                    .none,
                                    .unreach,
                                    .dead,
                                    .undef,
                                    .immediate,
                                    .eflags,
                                    .register,
                                    .register_offset,
                                    .register_overflow,
                                    .indirect,
                                    .lea_symbol,
                                    .lea_direct,
                                    .lea_got,
                                    .lea_tlv,
                                    .lea_frame,
                                    .elementwise_regs_then_frame,
                                    .reserved_frame,
                                    .air_ref,
                                    => unreachable,
                                    .register_pair, .load_frame => null,
                                    .memory, .load_symbol, .load_got, .load_direct, .load_tlv => src: {
                                        switch (resolved_src_mcv) {
                                            .memory => |addr| if (math.cast(
                                                i32,
                                                @as(i64, @bit_cast(addr)),
                                            ) != null and math.cast(
                                                i32,
                                                @as(i64, @bit_cast(addr)) + abi_size - 8,
                                            ) != null) break :src null,
                                            .load_symbol, .load_got, .load_direct, .load_tlv => {},
                                            else => unreachable,
                                        }

                                        const src_addr_reg = (try self.register_manager.alloc_reg(
                                            null,
                                            abi.RegisterClass.gp,
                                        )).to64();
                                        const src_addr_lock =
                                            self.register_manager.lock_reg_assume_unused(src_addr_reg);
                                        errdefer self.register_manager.unlock_reg(src_addr_lock);

                                        try self.gen_set_reg(
                                            src_addr_reg,
                                            Type.usize,
                                            resolved_src_mcv.address(),
                                            .{},
                                        );
                                        break :src .{
                                            .addr_reg = src_addr_reg,
                                            .addr_lock = src_addr_lock,
                                        };
                                    },
                                };
                                defer if (src_info) |info|
                                    self.register_manager.unlock_reg(info.addr_lock);

                                const regs = try self.register_manager.alloc_regs(
                                    2,
                                    .{null} ** 2,
                                    abi.RegisterClass.gp,
                                );
                                const acc_reg = regs[0].to64();
                                const locks = self.register_manager.lock_regs_assume_unused(2, regs);
                                defer for (locks) |lock| self.register_manager.unlock_reg(lock);

                                const limbs_len = math.div_ceil(u16, abi_size, 8) catch unreachable;
                                var limb_i: u16 = 0;
                                while (limb_i < limbs_len) : (limb_i += 1) {
                                    const off = limb_i * 8;
                                    const tmp_reg = regs[@min(limb_i, 1)].to64();

                                    try self.gen_set_reg(tmp_reg, Type.usize, if (dst_info) |info| .{
                                        .indirect = .{ .reg = info.addr_reg, .off = off },
                                    } else switch (resolved_dst_mcv) {
                                        .register_pair => |dst_regs| .{ .register = dst_regs[limb_i] },
                                        .memory => |dst_addr| .{
                                            .memory = @bit_cast(@as(i64, @bit_cast(dst_addr)) + off),
                                        },
                                        .indirect => |reg_off| .{ .indirect = .{
                                            .reg = reg_off.reg,
                                            .off = reg_off.off + off,
                                        } },
                                        .load_frame => |frame_addr| .{ .load_frame = .{
                                            .index = frame_addr.index,
                                            .off = frame_addr.off + off,
                                        } },
                                        else => unreachable,
                                    }, .{});

                                    try self.gen_bin_op_mir(
                                        .{ ._, .xor },
                                        Type.usize,
                                        .{ .register = tmp_reg },
                                        if (src_info) |info| .{
                                            .indirect = .{ .reg = info.addr_reg, .off = off },
                                        } else switch (resolved_src_mcv) {
                                            .register_pair => |src_regs| .{
                                                .register = src_regs[limb_i],
                                            },
                                            .memory => |src_addr| .{
                                                .memory = @bit_cast(@as(i64, @bit_cast(src_addr)) + off),
                                            },
                                            .indirect => |reg_off| .{ .indirect = .{
                                                .reg = reg_off.reg,
                                                .off = reg_off.off + off,
                                            } },
                                            .load_frame => |frame_addr| .{ .load_frame = .{
                                                .index = frame_addr.index,
                                                .off = frame_addr.off + off,
                                            } },
                                            else => unreachable,
                                        },
                                    );

                                    if (limb_i > 0)
                                        try self.asm_register_register(.{ ._, .@"or" }, acc_reg, tmp_reg);
                                }
                                assert(limbs_len >= 2); // use flags from or
                                break :result_op flipped_op;
                            },
                        };
                        try self.gen_bin_op_mir(.{ ._, .cmp }, ty, dst_mcv, src_mcv);
                        break :result_op flipped_op;
                    },
                );
            },
            .Float => {
                const flipped = switch (op) {
                    .lt, .lte => true,
                    .eq, .gte, .gt, .neq => false,
                };

                const dst_mcv = if (flipped) rhs_mcv else lhs_mcv;
                const dst_reg = if (dst_mcv.is_register())
                    dst_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(ty, dst_mcv);
                const dst_lock = self.register_manager.lock_reg(dst_reg);
                defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);
                const src_mcv = if (flipped) lhs_mcv else rhs_mcv;

                switch (ty.float_bits(self.target.*)) {
                    16 => {
                        assert(self.has_feature(.f16c));
                        const tmp1_reg =
                            (try self.register_manager.alloc_reg(null, abi.RegisterClass.sse)).to128();
                        const tmp1_mcv = MCValue{ .register = tmp1_reg };
                        const tmp1_lock = self.register_manager.lock_reg_assume_unused(tmp1_reg);
                        defer self.register_manager.unlock_reg(tmp1_lock);

                        const tmp2_reg =
                            (try self.register_manager.alloc_reg(null, abi.RegisterClass.sse)).to128();
                        const tmp2_mcv = MCValue{ .register = tmp2_reg };
                        const tmp2_lock = self.register_manager.lock_reg_assume_unused(tmp2_reg);
                        defer self.register_manager.unlock_reg(tmp2_lock);

                        if (src_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                            .{ .vp_w, .insr },
                            tmp1_reg,
                            dst_reg.to128(),
                            try src_mcv.mem(self, .word),
                            Immediate.u(1),
                        ) else try self.asm_register_register_register(
                            .{ .vp_, .unpcklwd },
                            tmp1_reg,
                            dst_reg.to128(),
                            (if (src_mcv.is_register())
                                src_mcv.get_reg().?
                            else
                                try self.copy_to_tmp_register(ty, src_mcv)).to128(),
                        );
                        try self.asm_register_register(.{ .v_ps, .cvtph2 }, tmp1_reg, tmp1_reg);
                        try self.asm_register_register(.{ .v_, .movshdup }, tmp2_reg, tmp1_reg);
                        try self.gen_bin_op_mir(.{ ._ss, .ucomi }, ty, tmp1_mcv, tmp2_mcv);
                    },
                    32 => try self.gen_bin_op_mir(
                        .{ ._ss, .ucomi },
                        ty,
                        .{ .register = dst_reg },
                        src_mcv,
                    ),
                    64 => try self.gen_bin_op_mir(
                        .{ ._sd, .ucomi },
                        ty,
                        .{ .register = dst_reg },
                        src_mcv,
                    ),
                    else => unreachable,
                }

                break :result switch (if (flipped) op.reverse() else op) {
                    .lt, .lte => unreachable, // required to have been canonicalized to gt(e)
                    .gt => .a,
                    .gte => .ae,
                    .eq => .z_and_np,
                    .neq => .nz_or_p,
                };
            },
        }
    };

    if (null_compare) |reloc| self.perform_reloc(reloc);
    self.eflags_inst = inst;
    return self.finish_air(inst, .{ .eflags = result }, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_cmp_vector(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.VectorCmp, ty_pl.payload).data;
    const dst_mcv = try self.gen_bin_op(
        inst,
        Air.Inst.Tag.from_cmp_op(extra.compare_operator(), false),
        extra.lhs,
        extra.rhs,
    );
    return self.finish_air(inst, dst_mcv, .{ extra.lhs, extra.rhs, .none });
}

fn air_cmp_lt_errors_len(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const addr_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
    defer self.register_manager.unlock_reg(addr_lock);
    try self.gen_lazy_symbol_ref(.lea, addr_reg, link.File.LazySymbol.init_decl(.const_data, null, mod));

    try self.spill_eflags_if_occupied();

    const op_ty = self.type_of(un_op);
    const op_abi_size: u32 = @int_cast(op_ty.abi_size(mod));
    const op_mcv = try self.resolve_inst(un_op);
    const dst_reg = switch (op_mcv) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(op_ty, op_mcv),
    };
    try self.asm_register_memory(
        .{ ._, .cmp },
        register_alias(dst_reg, op_abi_size),
        .{
            .base = .{ .reg = addr_reg },
            .mod = .{ .rm = .{ .size = Memory.Size.from_size(op_abi_size) } },
        },
    );

    self.eflags_inst = inst;
    return self.finish_air(inst, .{ .eflags = .b }, .{ un_op, .none, .none });
}

fn air_try(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Try, pl_op.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
    const operand_ty = self.type_of(pl_op.operand);
    const result = try self.gen_try(inst, pl_op.operand, body, operand_ty, false);
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_try_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.TryPtr, ty_pl.payload);
    const body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);
    const operand_ty = self.type_of(extra.data.ptr);
    const result = try self.gen_try(inst, extra.data.ptr, body, operand_ty, true);
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
    const liveness_cond_br = self.liveness.get_cond_br(inst);

    const operand_mcv = try self.resolve_inst(operand);
    const is_err_mcv = if (operand_is_ptr)
        try self.is_err_ptr(null, operand_ty, operand_mcv)
    else
        try self.is_err(null, operand_ty, operand_mcv);

    const reloc = try self.gen_cond_br_mir(Type.anyerror, is_err_mcv);

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
    else if (operand_is_ptr)
        try self.gen_unwrap_err_union_payload_ptr_mir(inst, operand_ty, operand_mcv)
    else
        try self.gen_unwrap_err_union_payload_mir(inst, operand_ty, operand_mcv);
    return result;
}

fn air_dbg_stmt(self: *Self, inst: Air.Inst.Index) !void {
    const dbg_stmt = self.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_line_line_column,
        .data = .{ .line_column = .{
            .line = dbg_stmt.line,
            .column = dbg_stmt.column,
        } },
    });
    self.finish_air_bookkeeping();
}

fn air_dbg_inline_block(self: *Self, inst: Air.Inst.Index) !void {
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.DbgInlineBlock, ty_pl.payload);
    const old_inline_func = self.inline_func;
    defer self.inline_func = old_inline_func;
    self.inline_func = extra.data.func;
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_inline_func,
        .data = .{ .func = extra.data.func },
    });
    try self.lower_block(inst, @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]));
    _ = try self.add_inst(.{
        .tag = .pseudo,
        .ops = .pseudo_dbg_inline_func,
        .data = .{ .func = old_inline_func },
    });
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

fn gen_cond_br_mir(self: *Self, ty: Type, mcv: MCValue) !Mir.Inst.Index {
    const mod = self.bin_file.comp.module.?;
    const abi_size = ty.abi_size(mod);
    switch (mcv) {
        .eflags => |cc| {
            // Here we map the opposites since the jump is to the false branch.
            return self.asm_jcc_reloc(cc.negate(), undefined);
        },
        .register => |reg| {
            try self.spill_eflags_if_occupied();
            try self.asm_register_immediate(.{ ._, .@"test" }, reg.to8(), Immediate.u(1));
            return self.asm_jcc_reloc(.z, undefined);
        },
        .immediate,
        .load_frame,
        => {
            try self.spill_eflags_if_occupied();
            if (abi_size <= 8) {
                const reg = try self.copy_to_tmp_register(ty, mcv);
                return self.gen_cond_br_mir(ty, .{ .register = reg });
            }
            return self.fail("TODO implement condbr when condition is {} with abi larger than 8 bytes", .{mcv});
        },
        else => return self.fail("TODO implement condbr when condition is {s}", .{@tag_name(mcv)}),
    }
}

fn air_cond_br(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const cond = try self.resolve_inst(pl_op.operand);
    const cond_ty = self.type_of(pl_op.operand);
    const extra = self.air.extra_data(Air.CondBr, pl_op.payload);
    const then_body: []const Air.Inst.Index =
        @ptr_cast(self.air.extra[extra.end..][0..extra.data.then_body_len]);
    const else_body: []const Air.Inst.Index =
        @ptr_cast(self.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
    const liveness_cond_br = self.liveness.get_cond_br(inst);

    // If the condition dies here in this condbr instruction, process
    // that death now instead of later as this has an effect on
    // whether it needs to be spilled in the branches
    if (self.liveness.operand_dies(inst, 0)) {
        if (pl_op.operand.to_index()) |op_inst| try self.process_death(op_inst);
    }

    self.scope_generation += 1;
    const state = try self.save_state();
    const reloc = try self.gen_cond_br_mir(cond_ty, cond);

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

fn is_null(self: *Self, inst: Air.Inst.Index, opt_ty: Type, opt_mcv: MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;
    switch (opt_mcv) {
        .register_overflow => |ro| return .{ .eflags = ro.eflags.negate() },
        else => {},
    }

    try self.spill_eflags_if_occupied();

    const pl_ty = opt_ty.optional_child(mod);

    const some_info: struct { off: i32, ty: Type } = if (opt_ty.optional_repr_is_payload(mod))
        .{ .off = 0, .ty = if (pl_ty.is_slice(mod)) pl_ty.slice_ptr_field_type(mod) else pl_ty }
    else
        .{ .off = @int_cast(pl_ty.abi_size(mod)), .ty = Type.bool };

    self.eflags_inst = inst;
    switch (opt_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .immediate,
        .eflags,
        .register_pair,
        .register_offset,
        .register_overflow,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        .lea_symbol,
        .elementwise_regs_then_frame,
        .reserved_frame,
        .air_ref,
        => unreachable,

        .register => |opt_reg| {
            if (some_info.off == 0) {
                const some_abi_size: u32 = @int_cast(some_info.ty.abi_size(mod));
                const alias_reg = register_alias(opt_reg, some_abi_size);
                assert(some_abi_size * 8 == alias_reg.bit_size());
                try self.asm_register_register(.{ ._, .@"test" }, alias_reg, alias_reg);
                return .{ .eflags = .z };
            }
            assert(some_info.ty.ip_index == .bool_type);
            const opt_abi_size: u32 = @int_cast(opt_ty.abi_size(mod));
            try self.asm_register_immediate(
                .{ ._, .bt },
                register_alias(opt_reg, opt_abi_size),
                Immediate.u(@as(u6, @int_cast(some_info.off * 8))),
            );
            return .{ .eflags = .nc };
        },

        .memory,
        .load_symbol,
        .load_got,
        .load_direct,
        .load_tlv,
        => {
            const addr_reg = (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to64();
            const addr_reg_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_reg_lock);

            try self.gen_set_reg(addr_reg, Type.usize, opt_mcv.address(), .{});
            const some_abi_size: u32 = @int_cast(some_info.ty.abi_size(mod));
            try self.asm_memory_immediate(
                .{ ._, .cmp },
                .{
                    .base = .{ .reg = addr_reg },
                    .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(some_abi_size),
                        .disp = some_info.off,
                    } },
                },
                Immediate.u(0),
            );
            return .{ .eflags = .e };
        },

        .indirect, .load_frame => {
            const some_abi_size: u32 = @int_cast(some_info.ty.abi_size(mod));
            try self.asm_memory_immediate(
                .{ ._, .cmp },
                switch (opt_mcv) {
                    .indirect => |reg_off| .{
                        .base = .{ .reg = reg_off.reg },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(some_abi_size),
                            .disp = reg_off.off + some_info.off,
                        } },
                    },
                    .load_frame => |frame_addr| .{
                        .base = .{ .frame = frame_addr.index },
                        .mod = .{ .rm = .{
                            .size = Memory.Size.from_size(some_abi_size),
                            .disp = frame_addr.off + some_info.off,
                        } },
                    },
                    else => unreachable,
                },
                Immediate.u(0),
            );
            return .{ .eflags = .e };
        },
    }
}

fn is_null_ptr(self: *Self, inst: Air.Inst.Index, ptr_ty: Type, ptr_mcv: MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const opt_ty = ptr_ty.child_type(mod);
    const pl_ty = opt_ty.optional_child(mod);

    try self.spill_eflags_if_occupied();

    const some_info: struct { off: i32, ty: Type } = if (opt_ty.optional_repr_is_payload(mod))
        .{ .off = 0, .ty = if (pl_ty.is_slice(mod)) pl_ty.slice_ptr_field_type(mod) else pl_ty }
    else
        .{ .off = @int_cast(pl_ty.abi_size(mod)), .ty = Type.bool };

    const ptr_reg = switch (ptr_mcv) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(ptr_ty, ptr_mcv),
    };
    const ptr_lock = self.register_manager.lock_reg(ptr_reg);
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const some_abi_size: u32 = @int_cast(some_info.ty.abi_size(mod));
    try self.asm_memory_immediate(
        .{ ._, .cmp },
        .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = Memory.Size.from_size(some_abi_size),
                .disp = some_info.off,
            } },
        },
        Immediate.u(0),
    );

    self.eflags_inst = inst;
    return .{ .eflags = .e };
}

fn is_err(self: *Self, maybe_inst: ?Air.Inst.Index, eu_ty: Type, eu_mcv: MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const err_ty = eu_ty.error_union_set(mod);
    if (err_ty.error_set_is_empty(mod)) return MCValue{ .immediate = 0 }; // always false

    try self.spill_eflags_if_occupied();

    const err_off: u31 = @int_cast(err_union_error_offset(eu_ty.error_union_payload(mod), mod));
    switch (eu_mcv) {
        .register => |reg| {
            const eu_lock = self.register_manager.lock_reg(reg);
            defer if (eu_lock) |lock| self.register_manager.unlock_reg(lock);

            const tmp_reg = try self.copy_to_tmp_register(eu_ty, eu_mcv);
            if (err_off > 0) {
                try self.gen_shift_bin_op_mir(
                    .{ ._r, .sh },
                    eu_ty,
                    .{ .register = tmp_reg },
                    Type.u8,
                    .{ .immediate = @as(u6, @int_cast(err_off * 8)) },
                );
            } else {
                try self.truncate_register(Type.anyerror, tmp_reg);
            }
            try self.gen_bin_op_mir(
                .{ ._, .cmp },
                Type.anyerror,
                .{ .register = tmp_reg },
                .{ .immediate = 0 },
            );
        },
        .load_frame => |frame_addr| try self.gen_bin_op_mir(
            .{ ._, .cmp },
            Type.anyerror,
            .{ .load_frame = .{
                .index = frame_addr.index,
                .off = frame_addr.off + err_off,
            } },
            .{ .immediate = 0 },
        ),
        else => return self.fail("TODO implement is_err for {}", .{eu_mcv}),
    }

    if (maybe_inst) |inst| self.eflags_inst = inst;
    return MCValue{ .eflags = .a };
}

fn is_err_ptr(self: *Self, maybe_inst: ?Air.Inst.Index, ptr_ty: Type, ptr_mcv: MCValue) !MCValue {
    const mod = self.bin_file.comp.module.?;
    const eu_ty = ptr_ty.child_type(mod);
    const err_ty = eu_ty.error_union_set(mod);
    if (err_ty.error_set_is_empty(mod)) return MCValue{ .immediate = 0 }; // always false

    try self.spill_eflags_if_occupied();

    const ptr_reg = switch (ptr_mcv) {
        .register => |reg| reg,
        else => try self.copy_to_tmp_register(ptr_ty, ptr_mcv),
    };
    const ptr_lock = self.register_manager.lock_reg(ptr_reg);
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const err_off: u31 = @int_cast(err_union_error_offset(eu_ty.error_union_payload(mod), mod));
    try self.asm_memory_immediate(
        .{ ._, .cmp },
        .{
            .base = .{ .reg = ptr_reg },
            .mod = .{ .rm = .{
                .size = self.mem_size(Type.anyerror),
                .disp = err_off,
            } },
        },
        Immediate.u(0),
    );

    if (maybe_inst) |inst| self.eflags_inst = inst;
    return MCValue{ .eflags = .a };
}

fn is_non_err(self: *Self, inst: Air.Inst.Index, eu_ty: Type, eu_mcv: MCValue) !MCValue {
    const is_err_res = try self.is_err(inst, eu_ty, eu_mcv);
    switch (is_err_res) {
        .eflags => |cc| {
            assert(cc == .a);
            return MCValue{ .eflags = cc.negate() };
        },
        .immediate => |imm| {
            assert(imm == 0);
            return MCValue{ .immediate = @int_from_bool(imm == 0) };
        },
        else => unreachable,
    }
}

fn is_non_err_ptr(self: *Self, inst: Air.Inst.Index, ptr_ty: Type, ptr_mcv: MCValue) !MCValue {
    const is_err_res = try self.is_err_ptr(inst, ptr_ty, ptr_mcv);
    switch (is_err_res) {
        .eflags => |cc| {
            assert(cc == .a);
            return MCValue{ .eflags = cc.negate() };
        },
        .immediate => |imm| {
            assert(imm == 0);
            return MCValue{ .immediate = @int_from_bool(imm == 0) };
        },
        else => unreachable,
    }
}

fn air_is_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_null(inst, ty, operand);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_null_ptr(inst, ty, operand);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_null(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = switch (try self.is_null(inst, ty, operand)) {
        .eflags => |cc| .{ .eflags = cc.negate() },
        else => unreachable,
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_null_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = switch (try self.is_null_ptr(inst, ty, operand)) {
        .eflags => |cc| .{ .eflags = cc.negate() },
        else => unreachable,
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_err(inst, ty, operand);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_err_ptr(inst, ty, operand);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_err(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_non_err(inst, ty, operand);
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_is_non_err_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const operand = try self.resolve_inst(un_op);
    const ty = self.type_of(un_op);
    const result = try self.is_non_err_ptr(inst, ty, operand);
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
    _ = try self.asm_jmp_reloc(jmp_target);

    self.finish_air_bookkeeping();
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

fn air_switch_br(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const condition = try self.resolve_inst(pl_op.operand);
    const condition_ty = self.type_of(pl_op.operand);
    const switch_br = self.air.extra_data(Air.SwitchBr, pl_op.payload);
    var extra_index: usize = switch_br.end;
    var case_i: u32 = 0;
    const liveness = try self.liveness.get_switch_br(self.gpa, inst, switch_br.data.cases_len + 1);
    defer self.gpa.free(liveness.deaths);

    // If the condition dies here in this switch instruction, process
    // that death now instead of later as this has an effect on
    // whether it needs to be spilled in the branches
    if (self.liveness.operand_dies(inst, 0)) {
        if (pl_op.operand.to_index()) |op_inst| try self.process_death(op_inst);
    }

    self.scope_generation += 1;
    const state = try self.save_state();

    while (case_i < switch_br.data.cases_len) : (case_i += 1) {
        const case = self.air.extra_data(Air.SwitchBr.Case, extra_index);
        const items: []const Air.Inst.Ref =
            @ptr_cast(self.air.extra[case.end..][0..case.data.items_len]);
        const case_body: []const Air.Inst.Index =
            @ptr_cast(self.air.extra[case.end + items.len ..][0..case.data.body_len]);
        extra_index = case.end + items.len + case_body.len;

        var relocs = try self.gpa.alloc(Mir.Inst.Index, items.len);
        defer self.gpa.free(relocs);

        try self.spill_eflags_if_occupied();
        for (items, relocs, 0..) |item, *reloc, i| {
            const item_mcv = try self.resolve_inst(item);
            const cc: Condition = switch (condition) {
                .eflags => |cc| switch (item_mcv.immediate) {
                    0 => cc.negate(),
                    1 => cc,
                    else => unreachable,
                },
                else => cc: {
                    try self.gen_bin_op_mir(.{ ._, .cmp }, condition_ty, condition, item_mcv);
                    break :cc .e;
                },
            };
            reloc.* = try self.asm_jcc_reloc(if (i < relocs.len - 1) cc else cc.negate(), undefined);
        }

        for (liveness.deaths[case_i]) |operand| try self.process_death(operand);

        for (relocs[0 .. relocs.len - 1]) |reloc| self.perform_reloc(reloc);
        try self.gen_body(case_body);
        try self.restore_state(state, &.{}, .{
            .emit_instructions = false,
            .update_tracking = true,
            .resurrect = true,
            .close_scope = true,
        });

        self.perform_reloc(relocs[relocs.len - 1]);
    }

    if (switch_br.data.else_body_len > 0) {
        const else_body: []const Air.Inst.Index =
            @ptr_cast(self.air.extra[extra_index..][0..switch_br.data.else_body_len]);

        const else_deaths = liveness.deaths.len - 1;
        for (liveness.deaths[else_deaths]) |operand| try self.process_death(operand);

        try self.gen_body(else_body);
        try self.restore_state(state, &.{}, .{
            .emit_instructions = false,
            .update_tracking = true,
            .resurrect = true,
            .close_scope = true,
        });
    }

    // We already took care of pl_op.operand earlier, so there's nothing left to do
    self.finish_air_bookkeeping();
}

fn perform_reloc(self: *Self, reloc: Mir.Inst.Index) void {
    const next_inst: u32 = @int_cast(self.mir_instructions.len);
    switch (self.mir_instructions.items(.tag)[reloc]) {
        .j, .jmp => {},
        .pseudo => switch (self.mir_instructions.items(.ops)[reloc]) {
            .pseudo_j_z_and_np_inst, .pseudo_j_nz_or_p_inst => {},
            else => unreachable,
        },
        else => unreachable,
    }
    self.mir_instructions.items(.data)[reloc].inst.inst = next_inst;
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
        try self.gen_copy(block_ty, dst_mcv, try self.resolve_inst(br.operand), .{});
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
    const jmp_reloc = try self.asm_jmp_reloc(undefined);
    try block_data.relocs.append(self.gpa, jmp_reloc);

    // Stop tracking block result without forgetting tracking info
    try self.free_value(block_tracking.short);

    self.finish_air_bookkeeping();
}

fn air_asm(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Asm, ty_pl.payload);
    const clobbers_len: u31 = @truncate(extra.data.flags);
    var extra_i: usize = extra.end;
    const outputs: []const Air.Inst.Ref =
        @ptr_cast(self.air.extra[extra_i..][0..extra.data.outputs_len]);
    extra_i += outputs.len;
    const inputs: []const Air.Inst.Ref = @ptr_cast(self.air.extra[extra_i..][0..extra.data.inputs_len]);
    extra_i += inputs.len;

    var result: MCValue = .none;
    var args = std.ArrayList(MCValue).init(self.gpa);
    try args.ensure_total_capacity(outputs.len + inputs.len);
    defer {
        for (args.items) |arg| if (arg.get_reg()) |reg| self.register_manager.unlock_reg(.{
            .tracked_index = RegisterManager.index_of_reg_into_tracked(reg) orelse continue,
        });
        args.deinit();
    }
    var arg_map = std.StringHashMap(u8).init(self.gpa);
    try arg_map.ensure_total_capacity(@int_cast(outputs.len + inputs.len));
    defer arg_map.deinit();

    var outputs_extra_i = extra_i;
    for (outputs) |output| {
        const extra_bytes = mem.slice_as_bytes(self.air.extra[extra_i..]);
        const constraint = mem.slice_to(mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
        const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
        // This equation accounts for the fact that even if we have exactly 4 bytes
        // for the string, we still use the next u32 for the null terminator.
        extra_i += (constraint.len + name.len + (2 + 3)) / 4;

        const maybe_inst = switch (output) {
            .none => inst,
            else => null,
        };
        const ty = switch (output) {
            .none => self.type_of_index(inst),
            else => self.type_of(output).child_type(mod),
        };
        const is_read = switch (constraint[0]) {
            '=' => false,
            '+' => read: {
                if (output == .none) return self.fail(
                    "read-write constraint unsupported for asm result: '{s}'",
                    .{constraint},
                );
                break :read true;
            },
            else => return self.fail("invalid constraint: '{s}'", .{constraint}),
        };
        const is_early_clobber = constraint[1] == '&';
        const rest = constraint[@as(usize, 1) + @int_from_bool(is_early_clobber) ..];
        const arg_mcv: MCValue = arg_mcv: {
            const arg_maybe_reg: ?Register = if (mem.eql(u8, rest, "r") or
                mem.eql(u8, rest, "f") or mem.eql(u8, rest, "x"))
                register_alias(
                    self.register_manager.try_alloc_reg(maybe_inst, switch (rest[0]) {
                        'r' => abi.RegisterClass.gp,
                        'f' => abi.RegisterClass.x87,
                        'x' => abi.RegisterClass.sse,
                        else => unreachable,
                    }) orelse return self.fail("ran out of registers lowering inline asm", .{}),
                    @int_cast(ty.abi_size(mod)),
                )
            else if (mem.eql(u8, rest, "m"))
                if (output != .none) null else return self.fail(
                    "memory constraint unsupported for asm result: '{s}'",
                    .{constraint},
                )
            else if (mem.eql(u8, rest, "g") or
                mem.eql(u8, rest, "rm") or mem.eql(u8, rest, "mr") or
                mem.eql(u8, rest, "r,m") or mem.eql(u8, rest, "m,r"))
                self.register_manager.try_alloc_reg(maybe_inst, abi.RegisterClass.gp) orelse
                    if (output != .none)
                    null
                else
                    return self.fail("ran out of registers lowering inline asm", .{})
            else if (mem.starts_with(u8, rest, "{") and mem.ends_with(u8, rest, "}"))
                parse_reg_name(rest["{".len .. rest.len - "}".len]) orelse
                    return self.fail("invalid register constraint: '{s}'", .{constraint})
            else if (rest.len == 1 and std.ascii.is_digit(rest[0])) {
                const index = std.fmt.char_to_digit(rest[0], 10) catch unreachable;
                if (index >= args.items.len) return self.fail("constraint out of bounds: '{s}'", .{
                    constraint,
                });
                break :arg_mcv args.items[index];
            } else return self.fail("invalid constraint: '{s}'", .{constraint});
            break :arg_mcv if (arg_maybe_reg) |reg| .{ .register = reg } else arg: {
                const ptr_mcv = try self.resolve_inst(output);
                switch (ptr_mcv) {
                    .immediate => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |_|
                        break :arg ptr_mcv.deref(),
                    .register, .register_offset, .lea_frame => break :arg ptr_mcv.deref(),
                    else => {},
                }
                break :arg .{ .indirect = .{ .reg = try self.copy_to_tmp_register(Type.usize, ptr_mcv) } };
            };
        };
        if (arg_mcv.get_reg()) |reg| if (RegisterManager.index_of_reg_into_tracked(reg)) |_| {
            _ = self.register_manager.lock_reg(reg);
        };
        if (!mem.eql(u8, name, "_"))
            arg_map.put_assume_capacity_no_clobber(name, @int_cast(args.items.len));
        args.append_assume_capacity(arg_mcv);
        if (output == .none) result = arg_mcv;
        if (is_read) try self.load(arg_mcv, self.type_of(output), .{ .air_ref = output });
    }

    for (inputs) |input| {
        const input_bytes = mem.slice_as_bytes(self.air.extra[extra_i..]);
        const constraint = mem.slice_to(input_bytes, 0);
        const name = mem.slice_to(input_bytes[constraint.len + 1 ..], 0);
        // This equation accounts for the fact that even if we have exactly 4 bytes
        // for the string, we still use the next u32 for the null terminator.
        extra_i += (constraint.len + name.len + (2 + 3)) / 4;

        const ty = self.type_of(input);
        const input_mcv = try self.resolve_inst(input);
        const arg_mcv: MCValue = if (mem.eql(u8, constraint, "r") or
            mem.eql(u8, constraint, "f") or mem.eql(u8, constraint, "x"))
        arg: {
            const rc = switch (constraint[0]) {
                'r' => abi.RegisterClass.gp,
                'f' => abi.RegisterClass.x87,
                'x' => abi.RegisterClass.sse,
                else => unreachable,
            };
            if (input_mcv.is_register() and
                rc.is_set(RegisterManager.index_of_reg_into_tracked(input_mcv.get_reg().?).?))
                break :arg input_mcv;
            const reg = try self.register_manager.alloc_reg(null, rc);
            try self.gen_set_reg(reg, ty, input_mcv, .{});
            break :arg .{ .register = register_alias(reg, @int_cast(ty.abi_size(mod))) };
        } else if (mem.eql(u8, constraint, "i") or mem.eql(u8, constraint, "n"))
            switch (input_mcv) {
                .immediate => |imm| .{ .immediate = imm },
                else => return self.fail("immediate operand requires comptime value: '{s}'", .{
                    constraint,
                }),
            }
        else if (mem.eql(u8, constraint, "m")) arg: {
            switch (input_mcv) {
                .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |_|
                    break :arg input_mcv,
                .indirect, .load_frame => break :arg input_mcv,
                .load_symbol, .load_direct, .load_got, .load_tlv => {},
                else => {
                    const temp_mcv = try self.alloc_temp_reg_or_mem(ty, false);
                    try self.gen_copy(ty, temp_mcv, input_mcv, .{});
                    break :arg temp_mcv;
                },
            }
            const addr_reg = self.register_manager.try_alloc_reg(null, abi.RegisterClass.gp) orelse {
                const temp_mcv = try self.alloc_temp_reg_or_mem(ty, false);
                try self.gen_copy(ty, temp_mcv, input_mcv, .{});
                break :arg temp_mcv;
            };
            try self.gen_set_reg(addr_reg, Type.usize, input_mcv.address(), .{});
            break :arg .{ .indirect = .{ .reg = addr_reg } };
        } else if (mem.eql(u8, constraint, "g") or
            mem.eql(u8, constraint, "rm") or mem.eql(u8, constraint, "mr") or
            mem.eql(u8, constraint, "r,m") or mem.eql(u8, constraint, "m,r"))
        arg: {
            switch (input_mcv) {
                .register, .indirect, .load_frame => break :arg input_mcv,
                .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |_|
                    break :arg input_mcv,
                else => {},
            }
            const temp_mcv = try self.alloc_temp_reg_or_mem(ty, true);
            try self.gen_copy(ty, temp_mcv, input_mcv, .{});
            break :arg temp_mcv;
        } else if (mem.eql(u8, constraint, "X"))
            input_mcv
        else if (mem.starts_with(u8, constraint, "{") and mem.ends_with(u8, constraint, "}")) arg: {
            const reg = parse_reg_name(constraint["{".len .. constraint.len - "}".len]) orelse
                return self.fail("invalid register constraint: '{s}'", .{constraint});
            try self.register_manager.get_reg(reg, null);
            try self.gen_set_reg(reg, ty, input_mcv, .{});
            break :arg .{ .register = reg };
        } else if (constraint.len == 1 and std.ascii.is_digit(constraint[0])) arg: {
            const index = std.fmt.char_to_digit(constraint[0], 10) catch unreachable;
            if (index >= args.items.len) return self.fail("constraint out of bounds: '{s}'", .{constraint});
            try self.gen_copy(ty, args.items[index], input_mcv, .{});
            break :arg args.items[index];
        } else return self.fail("invalid constraint: '{s}'", .{constraint});
        if (arg_mcv.get_reg()) |reg| if (RegisterManager.index_of_reg_into_tracked(reg)) |_| {
            _ = self.register_manager.lock_reg(reg);
        };
        if (!mem.eql(u8, name, "_"))
            arg_map.put_assume_capacity_no_clobber(name, @int_cast(args.items.len));
        args.append_assume_capacity(arg_mcv);
    }

    {
        var clobber_i: u32 = 0;
        while (clobber_i < clobbers_len) : (clobber_i += 1) {
            const clobber = mem.slice_to(mem.slice_as_bytes(self.air.extra[extra_i..]), 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the string, we still use the next u32 for the null terminator.
            extra_i += clobber.len / 4 + 1;

            if (std.mem.eql(u8, clobber, "") or std.mem.eql(u8, clobber, "memory")) {
                // ok, sure
            } else if (std.mem.eql(u8, clobber, "cc") or
                std.mem.eql(u8, clobber, "flags") or
                std.mem.eql(u8, clobber, "eflags") or
                std.mem.eql(u8, clobber, "rflags"))
            {
                try self.spill_eflags_if_occupied();
            } else {
                try self.register_manager.get_reg(parse_reg_name(clobber) orelse
                    return self.fail("invalid clobber: '{s}'", .{clobber}), null);
            }
        }
    }

    const Label = struct {
        target: Mir.Inst.Index = undefined,
        pending_relocs: std.ArrayListUnmanaged(Mir.Inst.Index) = .{},

        const Kind = enum { definition, reference };

        fn is_valid(kind: Kind, name: []const u8) bool {
            for (name, 0..) |c, i| switch (c) {
                else => return false,
                '$' => if (i == 0) return false,
                '.' => {},
                '0'...'9' => if (i == 0) switch (kind) {
                    .definition => if (name.len != 1) return false,
                    .reference => {
                        if (name.len != 2) return false;
                        switch (name[1]) {
                            else => return false,
                            'B', 'F', 'b', 'f' => {},
                        }
                    },
                },
                '@', 'A'...'Z', '_', 'a'...'z' => {},
            };
            return name.len > 0;
        }
    };
    var labels: std.StringHashMapUnmanaged(Label) = .{};
    defer {
        var label_it = labels.value_iterator();
        while (label_it.next()) |label| label.pending_relocs.deinit(self.gpa);
        labels.deinit(self.gpa);
    }

    const asm_source = mem.slice_as_bytes(self.air.extra[extra_i..])[0..extra.data.source_len];
    var line_it = mem.tokenize_any(u8, asm_source, "\n\r;");
    next_line: while (line_it.next()) |line| {
        var mnem_it = mem.tokenize_any(u8, line, " \t");
        var prefix: Instruction.Prefix = .none;
        const mnem_str = while (mnem_it.next()) |mnem_str| {
            if (mem.starts_with(u8, mnem_str, "#")) continue :next_line;
            if (mem.starts_with(u8, mnem_str, "//")) continue :next_line;
            if (std.meta.string_to_enum(Instruction.Prefix, mnem_str)) |pre| {
                if (prefix != .none) return self.fail("extra prefix: '{s}'", .{mnem_str});
                prefix = pre;
                continue;
            }
            if (!mem.ends_with(u8, mnem_str, ":")) break mnem_str;
            const label_name = mnem_str[0 .. mnem_str.len - ":".len];
            if (!Label.is_valid(.definition, label_name))
                return self.fail("invalid label: '{s}'", .{label_name});
            const label_gop = try labels.get_or_put(self.gpa, label_name);
            if (!label_gop.found_existing) label_gop.value_ptr.* = .{} else {
                const anon = std.ascii.is_digit(label_name[0]);
                if (!anon and label_gop.value_ptr.pending_relocs.items.len == 0)
                    return self.fail("redefined label: '{s}'", .{label_name});
                for (label_gop.value_ptr.pending_relocs.items) |pending_reloc|
                    self.perform_reloc(pending_reloc);
                if (anon)
                    label_gop.value_ptr.pending_relocs.clear_retaining_capacity()
                else
                    label_gop.value_ptr.pending_relocs.clear_and_free(self.gpa);
            }
            label_gop.value_ptr.target = @int_cast(self.mir_instructions.len);
        } else continue;

        var mnem_size: ?Memory.Size = if (mem.ends_with(u8, mnem_str, "b"))
            .byte
        else if (mem.ends_with(u8, mnem_str, "w"))
            .word
        else if (mem.ends_with(u8, mnem_str, "l"))
            .dword
        else if (mem.ends_with(u8, mnem_str, "q") and
            (std.mem.index_of_scalar(u8, "vp", mnem_str[0]) == null or !mem.ends_with(u8, mnem_str, "dq")))
            .qword
        else if (mem.ends_with(u8, mnem_str, "t"))
            .tbyte
        else
            null;
        const mnem_tag = while (true) break std.meta.string_to_enum(
            Instruction.Mnemonic,
            mnem_str[0 .. mnem_str.len - @int_from_bool(mnem_size != null)],
        ) orelse if (mnem_size) |_| {
            mnem_size = null;
            continue;
        } else return self.fail("invalid mnemonic: '{s}'", .{mnem_str});
        if (@as(?Memory.Size, switch (mnem_tag) {
            .clflush => .byte,
            .fldenv, .fnstenv, .fstenv => .none,
            .ldmxcsr, .stmxcsr, .vldmxcsr, .vstmxcsr => .dword,
            else => null,
        })) |fixed_mnem_size| {
            if (mnem_size) |size| if (size != fixed_mnem_size)
                return self.fail("invalid size: '{s}'", .{mnem_str});
            mnem_size = fixed_mnem_size;
        }
        const mnem_name = @tag_name(mnem_tag);
        const mnem_fixed_tag: Mir.Inst.FixedTag = for (std.enums.values(Mir.Inst.Fixes)) |fixes| {
            const fixes_name = @tag_name(fixes);
            const space_i = mem.index_of_scalar(u8, fixes_name, ' ');
            const fixes_prefix = if (space_i) |i|
                std.meta.string_to_enum(Instruction.Prefix, fixes_name[0..i]).?
            else
                .none;
            if (fixes_prefix != prefix) continue;
            const pattern = fixes_name[if (space_i) |i| i + " ".len else 0..];
            const wildcard_i = mem.index_of_scalar(u8, pattern, '_').?;
            const mnem_prefix = pattern[0..wildcard_i];
            const mnem_suffix = pattern[wildcard_i + "_".len ..];
            if (!mem.starts_with(u8, mnem_name, mnem_prefix)) continue;
            if (!mem.ends_with(u8, mnem_name, mnem_suffix)) continue;
            break .{ fixes, std.meta.string_to_enum(
                Mir.Inst.Tag,
                mnem_name[mnem_prefix.len .. mnem_name.len - mnem_suffix.len],
            ) orelse continue };
        } else {
            assert(prefix != .none); // no combination of fixes produced a known mnemonic
            return self.fail("invalid prefix for mnemonic: '{s} {s}'", .{
                @tag_name(prefix), mnem_str,
            });
        };

        const Operand = union(enum) {
            none,
            reg: Register,
            mem: Memory,
            imm: Immediate,
            inst: Mir.Inst.Index,
        };
        var ops: [4]Operand = .{.none} ** 4;

        var last_op = false;
        var op_it = mem.split_scalar(u8, mnem_it.rest(), ',');
        next_op: for (&ops) |*op| {
            const op_str = while (!last_op) {
                const full_str = op_it.next() orelse break :next_op;
                const code_str = if (mem.index_of_scalar(u8, full_str, '#') orelse
                    mem.index_of(u8, full_str, "//")) |comment|
                code: {
                    last_op = true;
                    break :code full_str[0..comment];
                } else full_str;
                const trim_str = mem.trim(u8, code_str, " \t*");
                if (trim_str.len > 0) break trim_str;
            } else break;
            if (mem.starts_with(u8, op_str, "%%")) {
                const colon = mem.index_of_scalar_pos(u8, op_str, "%%".len + 2, ':');
                const reg = parse_reg_name(op_str["%%".len .. colon orelse op_str.len]) orelse
                    return self.fail("invalid register: '{s}'", .{op_str});
                if (colon) |colon_pos| {
                    const disp = std.fmt.parse_int(i32, op_str[colon_pos + ":".len ..], 0) catch
                        return self.fail("invalid displacement: '{s}'", .{op_str});
                    op.* = .{ .mem = .{
                        .base = .{ .reg = reg },
                        .mod = .{ .rm = .{
                            .size = mnem_size orelse return self.fail("unknown size: '{s}'", .{op_str}),
                            .disp = disp,
                        } },
                    } };
                } else {
                    if (mnem_size) |size| if (reg.bit_size() != size.bit_size())
                        return self.fail("invalid register size: '{s}'", .{op_str});
                    op.* = .{ .reg = reg };
                }
            } else if (mem.starts_with(u8, op_str, "%[") and mem.ends_with(u8, op_str, "]")) {
                const colon = mem.index_of_scalar_pos(u8, op_str, "%[".len, ':');
                const modifier = if (colon) |colon_pos|
                    op_str[colon_pos + ":".len .. op_str.len - "]".len]
                else
                    "";
                op.* = switch (args.items[
                    arg_map.get(op_str["%[".len .. colon orelse op_str.len - "]".len]) orelse
                        return self.fail("no matching constraint: '{s}'", .{op_str})
                ]) {
                    .immediate => |imm| if (mem.eql(u8, modifier, "") or mem.eql(u8, modifier, "c"))
                        .{ .imm = Immediate.u(imm) }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .register => |reg| if (mem.eql(u8, modifier, ""))
                        .{ .reg = reg }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .memory => |addr| if (mem.eql(u8, modifier, "") or mem.eql(u8, modifier, "P"))
                        .{ .mem = .{
                            .base = .{ .reg = .ds },
                            .mod = .{ .rm = .{
                                .size = mnem_size orelse
                                    return self.fail("unknown size: '{s}'", .{op_str}),
                                .disp = @int_cast(@as(i64, @bit_cast(addr))),
                            } },
                        } }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .indirect => |reg_off| if (mem.eql(u8, modifier, ""))
                        .{ .mem = .{
                            .base = .{ .reg = reg_off.reg },
                            .mod = .{ .rm = .{
                                .size = mnem_size orelse
                                    return self.fail("unknown size: '{s}'", .{op_str}),
                                .disp = reg_off.off,
                            } },
                        } }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .load_frame => |frame_addr| if (mem.eql(u8, modifier, ""))
                        .{ .mem = .{
                            .base = .{ .frame = frame_addr.index },
                            .mod = .{ .rm = .{
                                .size = mnem_size orelse
                                    return self.fail("unknown size: '{s}'", .{op_str}),
                                .disp = frame_addr.off,
                            } },
                        } }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .lea_got => |sym_index| if (mem.eql(u8, modifier, "P"))
                        .{ .reg = try self.copy_to_tmp_register(Type.usize, .{ .lea_got = sym_index }) }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    .load_symbol => |sym_off| if (mem.eql(u8, modifier, "P"))
                        .{ .reg = try self.copy_to_tmp_register(Type.usize, .{ .load_symbol = sym_off }) }
                    else
                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                    else => return self.fail("invalid constraint: '{s}'", .{op_str}),
                };
            } else if (mem.starts_with(u8, op_str, "$")) {
                if (std.fmt.parse_int(i32, op_str["$".len..], 0)) |s| {
                    if (mnem_size) |size| {
                        const max = @as(u64, math.max_int(u64)) >> @int_cast(64 - (size.bit_size() - 1));
                        if ((if (s < 0) ~s else s) > max)
                            return self.fail("invalid immediate size: '{s}'", .{op_str});
                    }
                    op.* = .{ .imm = Immediate.s(s) };
                } else |_| if (std.fmt.parse_int(u64, op_str["$".len..], 0)) |u| {
                    if (mnem_size) |size| {
                        const max = @as(u64, math.max_int(u64)) >> @int_cast(64 - size.bit_size());
                        if (u > max)
                            return self.fail("invalid immediate size: '{s}'", .{op_str});
                    }
                    op.* = .{ .imm = Immediate.u(u) };
                } else |_| return self.fail("invalid immediate: '{s}'", .{op_str});
            } else if (mem.ends_with(u8, op_str, ")")) {
                const open = mem.index_of_scalar(u8, op_str, '(') orelse
                    return self.fail("invalid operand: '{s}'", .{op_str});
                var sib_it = mem.split_scalar(u8, op_str[open + "(".len .. op_str.len - ")".len], ',');
                const base_str = sib_it.next() orelse
                    return self.fail("invalid memory operand: '{s}'", .{op_str});
                if (base_str.len > 0 and !mem.starts_with(u8, base_str, "%%"))
                    return self.fail("invalid memory operand: '{s}'", .{op_str});
                const index_str = sib_it.next() orelse "";
                if (index_str.len > 0 and !mem.starts_with(u8, base_str, "%%"))
                    return self.fail("invalid memory operand: '{s}'", .{op_str});
                const scale_str = sib_it.next() orelse "";
                if (index_str.len == 0 and scale_str.len > 0)
                    return self.fail("invalid memory operand: '{s}'", .{op_str});
                const scale: Memory.Scale = if (scale_str.len > 0)
                    switch (std.fmt.parse_int(u4, scale_str, 10) catch
                        return self.fail("invalid scale: '{s}'", .{op_str})) {
                        1 => .@"1",
                        2 => .@"2",
                        4 => .@"4",
                        8 => .@"8",
                        else => return self.fail("invalid scale: '{s}'", .{op_str}),
                    }
                else
                    .@"1";
                if (sib_it.next()) |_| return self.fail("invalid memory operand: '{s}'", .{op_str});
                op.* = .{
                    .mem = .{
                        .base = if (base_str.len > 0)
                            .{ .reg = parse_reg_name(base_str["%%".len..]) orelse
                                return self.fail("invalid base register: '{s}'", .{base_str}) }
                        else
                            .none,
                        .mod = .{ .rm = .{
                            .size = mnem_size orelse return self.fail("unknown size: '{s}'", .{op_str}),
                            .index = if (index_str.len > 0)
                                parse_reg_name(index_str["%%".len..]) orelse
                                    return self.fail("invalid index register: '{s}'", .{op_str})
                            else
                                .none,
                            .scale = scale,
                            .disp = if (mem.starts_with(u8, op_str[0..open], "%[") and
                                mem.ends_with(u8, op_str[0..open], "]"))
                            disp: {
                                const colon = mem.index_of_scalar_pos(u8, op_str[0..open], "%[".len, ':');
                                const modifier = if (colon) |colon_pos|
                                    op_str[colon_pos + ":".len .. open - "]".len]
                                else
                                    "";
                                break :disp switch (args.items[
                                    arg_map.get(op_str["%[".len .. colon orelse open - "]".len]) orelse
                                        return self.fail("no matching constraint: '{s}'", .{op_str})
                                ]) {
                                    .immediate => |imm| if (mem.eql(u8, modifier, "") or
                                        mem.eql(u8, modifier, "c"))
                                        math.cast(i32, @as(i64, @bit_cast(imm))) orelse
                                            return self.fail("invalid displacement: '{s}'", .{op_str})
                                    else
                                        return self.fail("invalid modifier: '{s}'", .{modifier}),
                                    else => return self.fail("invalid constraint: '{s}'", .{op_str}),
                                };
                            } else if (open > 0)
                                std.fmt.parse_int(i32, op_str[0..open], 0) catch
                                    return self.fail("invalid displacement: '{s}'", .{op_str})
                            else
                                0,
                        } },
                    },
                };
            } else if (Label.is_valid(.reference, op_str)) {
                const anon = std.ascii.is_digit(op_str[0]);
                const label_gop = try labels.get_or_put(self.gpa, op_str[0..if (anon) 1 else op_str.len]);
                if (!label_gop.found_existing) label_gop.value_ptr.* = .{};
                if (anon and (op_str[1] == 'b' or op_str[1] == 'B') and !label_gop.found_existing)
                    return self.fail("undefined label: '{s}'", .{op_str});
                const pending_relocs = &label_gop.value_ptr.pending_relocs;
                if (if (anon)
                    op_str[1] == 'f' or op_str[1] == 'F'
                else
                    !label_gop.found_existing or pending_relocs.items.len > 0)
                    try pending_relocs.append(self.gpa, @int_cast(self.mir_instructions.len));
                op.* = .{ .inst = label_gop.value_ptr.target };
            } else return self.fail("invalid operand: '{s}'", .{op_str});
        } else if (op_it.next()) |op_str| return self.fail("extra operand: '{s}'", .{op_str});

        (switch (ops[0]) {
            .none => self.asm_op_only(mnem_fixed_tag),
            .reg => |reg0| switch (ops[1]) {
                .none => self.asm_register(mnem_fixed_tag, reg0),
                .reg => |reg1| switch (ops[2]) {
                    .none => self.asm_register_register(mnem_fixed_tag, reg1, reg0),
                    .reg => |reg2| switch (ops[3]) {
                        .none => self.asm_register_register_register(mnem_fixed_tag, reg2, reg1, reg0),
                        else => error.InvalidInstruction,
                    },
                    .mem => |mem2| switch (ops[3]) {
                        .none => self.asm_memory_register_register(mnem_fixed_tag, mem2, reg1, reg0),
                        else => error.InvalidInstruction,
                    },
                    else => error.InvalidInstruction,
                },
                .mem => |mem1| switch (ops[2]) {
                    .none => self.asm_memory_register(mnem_fixed_tag, mem1, reg0),
                    else => error.InvalidInstruction,
                },
                else => error.InvalidInstruction,
            },
            .mem => |mem0| switch (ops[1]) {
                .none => self.asm_memory(mnem_fixed_tag, mem0),
                .reg => |reg1| switch (ops[2]) {
                    .none => self.asm_register_memory(mnem_fixed_tag, reg1, mem0),
                    else => error.InvalidInstruction,
                },
                else => error.InvalidInstruction,
            },
            .imm => |imm0| switch (ops[1]) {
                .none => self.asm_immediate(mnem_fixed_tag, imm0),
                .reg => |reg1| switch (ops[2]) {
                    .none => self.asm_register_immediate(mnem_fixed_tag, reg1, imm0),
                    .reg => |reg2| switch (ops[3]) {
                        .none => self.asm_register_register_immediate(mnem_fixed_tag, reg2, reg1, imm0),
                        .reg => |reg3| self.asm_register_register_register_immediate(
                            mnem_fixed_tag,
                            reg3,
                            reg2,
                            reg1,
                            imm0,
                        ),
                        else => error.InvalidInstruction,
                    },
                    .mem => |mem2| switch (ops[3]) {
                        .none => self.asm_memory_register_immediate(mnem_fixed_tag, mem2, reg1, imm0),
                        else => error.InvalidInstruction,
                    },
                    else => error.InvalidInstruction,
                },
                .mem => |mem1| switch (ops[2]) {
                    .none => self.asm_memory_immediate(mnem_fixed_tag, mem1, imm0),
                    else => error.InvalidInstruction,
                },
                else => error.InvalidInstruction,
            },
            .inst => |inst0| switch (ops[1]) {
                .none => self.asm_reloc(mnem_fixed_tag, inst0),
                else => error.InvalidInstruction,
            },
        }) catch |err| switch (err) {
            error.InvalidInstruction => return self.fail(
                "invalid instruction: '{s} {s} {s} {s} {s}'",
                .{
                    mnem_str,
                    @tag_name(ops[0]),
                    @tag_name(ops[1]),
                    @tag_name(ops[2]),
                    @tag_name(ops[3]),
                },
            ),
            else => |e| return e,
        };
    }

    var label_it = labels.iterator();
    while (label_it.next()) |label| if (label.value_ptr.pending_relocs.items.len > 0)
        return self.fail("undefined label: '{s}'", .{label.key_ptr.*});

    for (outputs, args.items[0..outputs.len]) |output, arg_mcv| {
        const extra_bytes = mem.slice_as_bytes(self.air.extra[outputs_extra_i..]);
        const constraint =
            mem.slice_to(mem.slice_as_bytes(self.air.extra[outputs_extra_i..]), 0);
        const name = mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
        // This equation accounts for the fact that even if we have exactly 4 bytes
        // for the string, we still use the next u32 for the null terminator.
        outputs_extra_i += (constraint.len + name.len + (2 + 3)) / 4;

        if (output == .none) continue;
        if (arg_mcv != .register) continue;
        if (constraint.len == 2 and std.ascii.is_digit(constraint[1])) continue;
        try self.store(self.type_of(output), .{ .air_ref = output }, arg_mcv, .{});
    }

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

const MoveStrategy = union(enum) {
    move: Mir.Inst.FixedTag,
    x87_load_store,
    insert_extract: InsertExtract,
    vex_insert_extract: InsertExtract,

    const InsertExtract = struct {
        insert: Mir.Inst.FixedTag,
        extract: Mir.Inst.FixedTag,
    };

    pub fn read(strat: MoveStrategy, self: *Self, dst_reg: Register, src_mem: Memory) !void {
        switch (strat) {
            .move => |tag| try self.asm_register_memory(tag, dst_reg, src_mem),
            .x87_load_store => {
                try self.asm_memory(.{ .f_, .ld }, src_mem);
                assert(dst_reg != .st7);
                try self.asm_register(.{ .f_p, .st }, @enumFromInt(@int_from_enum(dst_reg) + 1));
            },
            .insert_extract => |ie| try self.asm_register_memory_immediate(
                ie.insert,
                dst_reg,
                src_mem,
                Immediate.u(0),
            ),
            .vex_insert_extract => |ie| try self.asm_register_register_memory_immediate(
                ie.insert,
                dst_reg,
                dst_reg,
                src_mem,
                Immediate.u(0),
            ),
        }
    }
    pub fn write(strat: MoveStrategy, self: *Self, dst_mem: Memory, src_reg: Register) !void {
        switch (strat) {
            .move => |tag| try self.asm_memory_register(tag, dst_mem, src_reg),
            .x87_load_store => {
                try self.asm_register(.{ .f_, .ld }, src_reg);
                try self.asm_memory(.{ .f_p, .st }, dst_mem);
            },
            .insert_extract, .vex_insert_extract => |ie| try self.asm_memory_register_immediate(
                ie.extract,
                dst_mem,
                src_reg,
                Immediate.u(0),
            ),
        }
    }
};
fn move_strategy(self: *Self, ty: Type, class: Register.Class, aligned: bool) !MoveStrategy {
    const mod = self.bin_file.comp.module.?;
    switch (class) {
        .general_purpose, .segment => return .{ .move = .{ ._, .mov } },
        .x87 => return .x87_load_store,
        .mmx => {},
        .sse => switch (ty.zig_type_tag(mod)) {
            else => {
                const classes = mem.slice_to(&abi.classify_system_v(ty, mod, self.target.*, .other), .none);
                assert(std.mem.index_of_none(abi.Class, classes, &.{
                    .integer, .sse, .sseup, .memory, .float, .float_combine,
                }) == null);
                const abi_size = ty.abi_size(mod);
                if (abi_size < 4 or
                    std.mem.index_of_scalar(abi.Class, classes, .integer) != null) switch (abi_size) {
                    1 => if (self.has_feature(.avx)) return .{ .vex_insert_extract = .{
                        .insert = .{ .vp_b, .insr },
                        .extract = .{ .vp_b, .extr },
                    } } else if (self.has_feature(.sse4_2)) return .{ .insert_extract = .{
                        .insert = .{ .p_b, .insr },
                        .extract = .{ .p_b, .extr },
                    } },
                    2 => return if (self.has_feature(.avx)) .{ .vex_insert_extract = .{
                        .insert = .{ .vp_w, .insr },
                        .extract = .{ .vp_w, .extr },
                    } } else .{ .insert_extract = .{
                        .insert = .{ .p_w, .insr },
                        .extract = .{ .p_w, .extr },
                    } },
                    3...4 => return .{ .move = if (self.has_feature(.avx))
                        .{ .v_d, .mov }
                    else
                        .{ ._d, .mov } },
                    5...8 => return .{ .move = if (self.has_feature(.avx))
                        .{ .v_q, .mov }
                    else
                        .{ ._q, .mov } },
                    9...16 => return .{ .move = if (self.has_feature(.avx))
                        if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                    else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                    17...32 => if (self.has_feature(.avx))
                        return .{ .move = if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu } },
                    else => {},
                } else switch (abi_size) {
                    4 => return .{ .move = if (self.has_feature(.avx))
                        .{ .v_ss, .mov }
                    else
                        .{ ._ss, .mov } },
                    5...8 => return .{ .move = if (self.has_feature(.avx))
                        .{ .v_sd, .mov }
                    else
                        .{ ._sd, .mov } },
                    9...16 => return .{ .move = if (self.has_feature(.avx))
                        if (aligned) .{ .v_pd, .mova } else .{ .v_pd, .movu }
                    else if (aligned) .{ ._pd, .mova } else .{ ._pd, .movu } },
                    17...32 => if (self.has_feature(.avx)) return .{ .move = if (aligned)
                        .{ .v_pd, .mova }
                    else
                        .{ .v_pd, .movu } },
                    else => {},
                }
            },
            .Float => switch (ty.float_bits(self.target.*)) {
                16 => return if (self.has_feature(.avx)) .{ .vex_insert_extract = .{
                    .insert = .{ .vp_w, .insr },
                    .extract = .{ .vp_w, .extr },
                } } else .{ .insert_extract = .{
                    .insert = .{ .p_w, .insr },
                    .extract = .{ .p_w, .extr },
                } },
                32 => return .{ .move = if (self.has_feature(.avx))
                    .{ .v_ss, .mov }
                else
                    .{ ._ss, .mov } },
                64 => return .{ .move = if (self.has_feature(.avx))
                    .{ .v_sd, .mov }
                else
                    .{ ._sd, .mov } },
                128 => return .{ .move = if (self.has_feature(.avx))
                    if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                else => {},
            },
            .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                .Bool => switch (ty.vector_len(mod)) {
                    33...64 => return .{ .move = if (self.has_feature(.avx))
                        .{ .v_q, .mov }
                    else
                        .{ ._q, .mov } },
                    else => {},
                },
                .Int => switch (ty.child_type(mod).int_info(mod).bits) {
                    1...8 => switch (ty.vector_len(mod)) {
                        1...16 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        17...32 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    9...16 => switch (ty.vector_len(mod)) {
                        1...8 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        9...16 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    17...32 => switch (ty.vector_len(mod)) {
                        1...4 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        5...8 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    33...64 => switch (ty.vector_len(mod)) {
                        1...2 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        3...4 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    65...128 => switch (ty.vector_len(mod)) {
                        1 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        2 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    129...256 => switch (ty.vector_len(mod)) {
                        1 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    else => {},
                },
                .Pointer, .Optional => if (ty.child_type(mod).is_ptr_at_runtime(mod))
                    switch (ty.vector_len(mod)) {
                        1...2 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        3...4 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    }
                else
                    unreachable,
                .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                    16 => switch (ty.vector_len(mod)) {
                        1...8 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        9...16 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    32 => switch (ty.vector_len(mod)) {
                        1...4 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_ps, .mova } else .{ .v_ps, .movu }
                        else if (aligned) .{ ._ps, .mova } else .{ ._ps, .movu } },
                        5...8 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_ps, .mova }
                            else
                                .{ .v_ps, .movu } },
                        else => {},
                    },
                    64 => switch (ty.vector_len(mod)) {
                        1...2 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_pd, .mova } else .{ .v_pd, .movu }
                        else if (aligned) .{ ._pd, .mova } else .{ ._pd, .movu } },
                        3...4 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_pd, .mova }
                            else
                                .{ .v_pd, .movu } },
                        else => {},
                    },
                    128 => switch (ty.vector_len(mod)) {
                        1 => return .{ .move = if (self.has_feature(.avx))
                            if (aligned) .{ .v_, .movdqa } else .{ .v_, .movdqu }
                        else if (aligned) .{ ._, .movdqa } else .{ ._, .movdqu } },
                        2 => if (self.has_feature(.avx))
                            return .{ .move = if (aligned)
                                .{ .v_, .movdqa }
                            else
                                .{ .v_, .movdqu } },
                        else => {},
                    },
                    else => {},
                },
                else => {},
            },
        },
    }
    return self.fail("TODO move_strategy for {}", .{ty.fmt(mod)});
}

const CopyOptions = struct {
    safety: bool = false,
};

fn gen_copy(self: *Self, ty: Type, dst_mcv: MCValue, src_mcv: MCValue, opts: CopyOptions) InnerError!void {
    const mod = self.bin_file.comp.module.?;

    const src_lock = if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
    defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

    switch (dst_mcv) {
        .none,
        .unreach,
        .dead,
        .undef,
        .immediate,
        .eflags,
        .register_overflow,
        .lea_direct,
        .lea_got,
        .lea_tlv,
        .lea_frame,
        .lea_symbol,
        .elementwise_regs_then_frame,
        .reserved_frame,
        .air_ref,
        => unreachable, // unmodifiable destination
        .register => |reg| try self.gen_set_reg(reg, ty, src_mcv, opts),
        .register_offset => |dst_reg_off| try self.gen_set_reg(dst_reg_off.reg, ty, switch (src_mcv) {
            .none,
            .unreach,
            .dead,
            .undef,
            .register_overflow,
            .elementwise_regs_then_frame,
            .reserved_frame,
            => unreachable,
            .immediate,
            .register,
            .register_offset,
            .lea_frame,
            => src_mcv.offset(-dst_reg_off.off),
            else => .{ .register_offset = .{
                .reg = try self.copy_to_tmp_register(ty, src_mcv),
                .off = -dst_reg_off.off,
            } },
        }, opts),
        .register_pair => |dst_regs| {
            const src_info: ?struct { addr_reg: Register, addr_lock: RegisterLock } = switch (src_mcv) {
                .register_pair, .memory, .indirect, .load_frame => null,
                .load_symbol, .load_direct, .load_got, .load_tlv => src: {
                    const src_addr_reg =
                        (try self.register_manager.alloc_reg(null, abi.RegisterClass.gp)).to64();
                    const src_addr_lock = self.register_manager.lock_reg_assume_unused(src_addr_reg);
                    errdefer self.register_manager.unlock_reg(src_addr_lock);

                    try self.gen_set_reg(src_addr_reg, Type.usize, src_mcv.address(), opts);
                    break :src .{ .addr_reg = src_addr_reg, .addr_lock = src_addr_lock };
                },
                .air_ref => |src_ref| return self.gen_copy(
                    ty,
                    dst_mcv,
                    try self.resolve_inst(src_ref),
                    opts,
                ),
                else => return self.fail("TODO implement gen_copy for {s} of {}", .{
                    @tag_name(src_mcv), ty.fmt(mod),
                }),
            };
            defer if (src_info) |info| self.register_manager.unlock_reg(info.addr_lock);

            var part_disp: i32 = 0;
            for (dst_regs, try self.split_type(ty), 0..) |dst_reg, dst_ty, part_i| {
                try self.gen_set_reg(dst_reg, dst_ty, switch (src_mcv) {
                    .register_pair => |src_regs| .{ .register = src_regs[part_i] },
                    .memory, .indirect, .load_frame => src_mcv.address().offset(part_disp).deref(),
                    .load_symbol, .load_direct, .load_got, .load_tlv => .{ .indirect = .{
                        .reg = src_info.?.addr_reg,
                        .off = part_disp,
                    } },
                    else => unreachable,
                }, opts);
                part_disp += @int_cast(dst_ty.abi_size(mod));
            }
        },
        .indirect => |reg_off| try self.gen_set_mem(
            .{ .reg = reg_off.reg },
            reg_off.off,
            ty,
            src_mcv,
            opts,
        ),
        .memory, .load_symbol, .load_direct, .load_got, .load_tlv => {
            switch (dst_mcv) {
                .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |small_addr|
                    return self.gen_set_mem(.{ .reg = .ds }, small_addr, ty, src_mcv, opts),
                .load_symbol, .load_direct, .load_got, .load_tlv => {},
                else => unreachable,
            }

            const addr_reg = try self.copy_to_tmp_register(Type.usize, dst_mcv.address());
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try self.gen_set_mem(.{ .reg = addr_reg }, 0, ty, src_mcv, opts);
        },
        .load_frame => |frame_addr| try self.gen_set_mem(
            .{ .frame = frame_addr.index },
            frame_addr.off,
            ty,
            src_mcv,
            opts,
        ),
    }
}

fn gen_set_reg(
    self: *Self,
    dst_reg: Register,
    ty: Type,
    src_mcv: MCValue,
    opts: CopyOptions,
) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    if (ty.bit_size(mod) > dst_reg.bit_size())
        return self.fail("gen_set_reg called with a value larger than dst_reg", .{});
    switch (src_mcv) {
        .none,
        .unreach,
        .dead,
        .register_overflow,
        .elementwise_regs_then_frame,
        .reserved_frame,
        => unreachable,
        .undef => if (opts.safety) switch (dst_reg.class()) {
            .general_purpose => switch (abi_size) {
                1 => try self.asm_register_immediate(.{ ._, .mov }, dst_reg.to8(), Immediate.u(0xAA)),
                2 => try self.asm_register_immediate(.{ ._, .mov }, dst_reg.to16(), Immediate.u(0xAAAA)),
                3...4 => try self.asm_register_immediate(
                    .{ ._, .mov },
                    dst_reg.to32(),
                    Immediate.s(@as(i32, @bit_cast(@as(u32, 0xAAAAAAAA)))),
                ),
                5...8 => try self.asm_register_immediate(
                    .{ ._, .mov },
                    dst_reg.to64(),
                    Immediate.u(0xAAAAAAAAAAAAAAAA),
                ),
                else => unreachable,
            },
            .segment, .x87, .mmx, .sse => try self.gen_set_reg(dst_reg, ty, try self.gen_typed_value(try mod.undef_value(ty)), opts),
        },
        .eflags => |cc| try self.asm_setcc_register(cc, dst_reg.to8()),
        .immediate => |imm| {
            if (imm == 0) {
                // 32-bit moves zero-extend to 64-bit, so xoring the 32-bit
                // register is the fastest way to zero a register.
                try self.spill_eflags_if_occupied();
                try self.asm_register_register(.{ ._, .xor }, dst_reg.to32(), dst_reg.to32());
            } else if (abi_size > 4 and math.cast(u32, imm) != null) {
                // 32-bit moves zero-extend to 64-bit.
                try self.asm_register_immediate(.{ ._, .mov }, dst_reg.to32(), Immediate.u(imm));
            } else if (abi_size <= 4 and @as(i64, @bit_cast(imm)) < 0) {
                try self.asm_register_immediate(
                    .{ ._, .mov },
                    register_alias(dst_reg, abi_size),
                    Immediate.s(@int_cast(@as(i64, @bit_cast(imm)))),
                );
            } else {
                try self.asm_register_immediate(
                    .{ ._, .mov },
                    register_alias(dst_reg, abi_size),
                    Immediate.u(imm),
                );
            }
        },
        .register => |src_reg| if (dst_reg.id() != src_reg.id()) switch (dst_reg.class()) {
            .general_purpose => switch (src_reg.class()) {
                .general_purpose => try self.asm_register_register(
                    .{ ._, .mov },
                    register_alias(dst_reg, abi_size),
                    register_alias(src_reg, abi_size),
                ),
                .segment => try self.asm_register_register(
                    .{ ._, .mov },
                    register_alias(dst_reg, abi_size),
                    src_reg,
                ),
                .x87, .mmx => unreachable,
                .sse => try self.asm_register_register(
                    switch (abi_size) {
                        1...4 => if (self.has_feature(.avx)) .{ .v_d, .mov } else .{ ._d, .mov },
                        5...8 => if (self.has_feature(.avx)) .{ .v_q, .mov } else .{ ._q, .mov },
                        else => unreachable,
                    },
                    register_alias(dst_reg, @max(abi_size, 4)),
                    src_reg.to128(),
                ),
            },
            .segment => try self.asm_register_register(
                .{ ._, .mov },
                dst_reg,
                switch (src_reg.class()) {
                    .general_purpose, .segment => register_alias(src_reg, abi_size),
                    .x87, .mmx => unreachable,
                    .sse => try self.copy_to_tmp_register(ty, src_mcv),
                },
            ),
            .x87 => switch (src_reg.class()) {
                .general_purpose, .segment => unreachable,
                .x87 => switch (src_reg) {
                    .st0 => try self.asm_register(.{ .f_, .st }, dst_reg),
                    .st1, .st2, .st3, .st4, .st5, .st6 => {
                        try self.asm_register(.{ .f_, .ld }, src_reg);
                        assert(dst_reg != .st7);
                        try self.asm_register(.{ .f_p, .st }, @enumFromInt(@int_from_enum(dst_reg) + 1));
                    },
                    else => unreachable,
                },
                .mmx, .sse => unreachable,
            },
            .mmx => unreachable,
            .sse => switch (src_reg.class()) {
                .general_purpose => try self.asm_register_register(
                    switch (abi_size) {
                        1...4 => if (self.has_feature(.avx)) .{ .v_d, .mov } else .{ ._d, .mov },
                        5...8 => if (self.has_feature(.avx)) .{ .v_q, .mov } else .{ ._q, .mov },
                        else => unreachable,
                    },
                    dst_reg.to128(),
                    register_alias(src_reg, @max(abi_size, 4)),
                ),
                .segment => try self.gen_set_reg(
                    dst_reg,
                    ty,
                    .{ .register = try self.copy_to_tmp_register(ty, src_mcv) },
                    opts,
                ),
                .x87, .mmx => unreachable,
                .sse => try self.asm_register_register(
                    @as(?Mir.Inst.FixedTag, switch (ty.scalar_type(mod).zig_type_tag(mod)) {
                        else => switch (abi_size) {
                            1...16 => if (self.has_feature(.avx)) .{ .v_, .movdqa } else .{ ._, .movdqa },
                            17...32 => if (self.has_feature(.avx)) .{ .v_, .movdqa } else null,
                            else => null,
                        },
                        .Float => switch (ty.scalar_type(mod).float_bits(self.target.*)) {
                            16, 128 => switch (abi_size) {
                                2...16 => if (self.has_feature(.avx))
                                    .{ .v_, .movdqa }
                                else
                                    .{ ._, .movdqa },
                                17...32 => if (self.has_feature(.avx)) .{ .v_, .movdqa } else null,
                                else => null,
                            },
                            32 => if (self.has_feature(.avx)) .{ .v_ps, .mova } else .{ ._ps, .mova },
                            64 => if (self.has_feature(.avx)) .{ .v_pd, .mova } else .{ ._pd, .mova },
                            80 => null,
                            else => unreachable,
                        },
                    }) orelse return self.fail("TODO implement gen_set_reg for {}", .{ty.fmt(mod)}),
                    register_alias(dst_reg, abi_size),
                    register_alias(src_reg, abi_size),
                ),
            },
        },
        .register_pair => |src_regs| try self.gen_set_reg(dst_reg, ty, .{ .register = src_regs[0] }, opts),
        .register_offset,
        .indirect,
        .load_frame,
        .lea_frame,
        => try @as(MoveStrategy, switch (src_mcv) {
            .register_offset => |reg_off| switch (reg_off.off) {
                0 => return self.gen_set_reg(dst_reg, ty, .{ .register = reg_off.reg }, opts),
                else => .{ .move = .{ ._, .lea } },
            },
            .indirect => try self.move_strategy(ty, dst_reg.class(), false),
            .load_frame => |frame_addr| try self.move_strategy(
                ty,
                dst_reg.class(),
                self.get_frame_addr_alignment(frame_addr).compare(.gte, Alignment.from_log2_units(
                    math.log2_int_ceil(u10, @div_exact(dst_reg.bit_size(), 8)),
                )),
            ),
            .lea_frame => .{ .move = .{ ._, .lea } },
            else => unreachable,
        }).read(self, register_alias(dst_reg, abi_size), switch (src_mcv) {
            .register_offset, .indirect => |reg_off| .{
                .base = .{ .reg = reg_off.reg },
                .mod = .{ .rm = .{
                    .size = self.mem_size(ty),
                    .disp = reg_off.off,
                } },
            },
            .load_frame, .lea_frame => |frame_addr| .{
                .base = .{ .frame = frame_addr.index },
                .mod = .{ .rm = .{
                    .size = self.mem_size(ty),
                    .disp = frame_addr.off,
                } },
            },
            else => unreachable,
        }),
        .memory, .load_symbol, .load_direct, .load_got, .load_tlv => {
            switch (src_mcv) {
                .memory => |addr| if (math.cast(i32, @as(i64, @bit_cast(addr)))) |small_addr|
                    return (try self.move_strategy(
                        ty,
                        dst_reg.class(),
                        ty.abi_alignment(mod).check(@as(u32, @bit_cast(small_addr))),
                    )).read(self, register_alias(dst_reg, abi_size), .{
                        .base = .{ .reg = .ds },
                        .mod = .{ .rm = .{
                            .size = self.mem_size(ty),
                            .disp = small_addr,
                        } },
                    }),
                .load_symbol => |sym_off| switch (dst_reg.class()) {
                    .general_purpose => {
                        assert(sym_off.off == 0);
                        try self.asm_register_memory(.{ ._, .mov }, register_alias(dst_reg, abi_size), .{
                            .base = .{ .reloc = .{
                                .atom_index = try self.owner.get_symbol_index(self),
                                .sym_index = sym_off.sym,
                            } },
                            .mod = .{ .rm = .{
                                .size = self.mem_size(ty),
                                .disp = sym_off.off,
                            } },
                        });
                        return;
                    },
                    .segment, .mmx => unreachable,
                    .x87, .sse => {},
                },
                .load_direct => |sym_index| switch (dst_reg.class()) {
                    .general_purpose => {
                        _ = try self.add_inst(.{
                            .tag = .mov,
                            .ops = .direct_reloc,
                            .data = .{ .rx = .{
                                .r1 = register_alias(dst_reg, abi_size),
                                .payload = try self.add_extra(bits.Symbol{
                                    .atom_index = try self.owner.get_symbol_index(self),
                                    .sym_index = sym_index,
                                }),
                            } },
                        });
                        return;
                    },
                    .segment, .mmx => unreachable,
                    .x87, .sse => {},
                },
                .load_got, .load_tlv => {},
                else => unreachable,
            }

            const addr_reg = try self.copy_to_tmp_register(Type.usize, src_mcv.address());
            const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
            defer self.register_manager.unlock_reg(addr_lock);

            try (try self.move_strategy(ty, dst_reg.class(), false)).read(
                self,
                register_alias(dst_reg, abi_size),
                .{
                    .base = .{ .reg = addr_reg },
                    .mod = .{ .rm = .{ .size = self.mem_size(ty) } },
                },
            );
        },
        .lea_symbol => |sym_index| {
            const atom_index = try self.owner.get_symbol_index(self);
            switch (self.bin_file.tag) {
                .elf, .macho => {
                    try self.asm_register_memory(
                        .{ ._, .lea },
                        dst_reg.to64(),
                        .{
                            .base = .{ .reloc = .{
                                .atom_index = atom_index,
                                .sym_index = sym_index.sym,
                            } },
                            .mod = .{ .rm = .{
                                .size = .qword,
                                .disp = sym_index.off,
                            } },
                        },
                    );
                },
                else => return self.fail("TODO emit symbol sequence on {s}", .{
                    @tag_name(self.bin_file.tag),
                }),
            }
        },
        .lea_direct, .lea_got => |sym_index| {
            const atom_index = try self.owner.get_symbol_index(self);
            _ = try self.add_inst(.{
                .tag = switch (src_mcv) {
                    .lea_direct => .lea,
                    .lea_got => .mov,
                    else => unreachable,
                },
                .ops = switch (src_mcv) {
                    .lea_direct => .direct_reloc,
                    .lea_got => .got_reloc,
                    else => unreachable,
                },
                .data = .{ .rx = .{
                    .r1 = dst_reg.to64(),
                    .payload = try self.add_extra(bits.Symbol{
                        .atom_index = atom_index,
                        .sym_index = sym_index,
                    }),
                } },
            });
        },
        .lea_tlv => unreachable, // TODO: remove this
        .air_ref => |src_ref| try self.gen_set_reg(dst_reg, ty, try self.resolve_inst(src_ref), opts),
    }
}

fn gen_set_mem(
    self: *Self,
    base: Memory.Base,
    disp: i32,
    ty: Type,
    src_mcv: MCValue,
    opts: CopyOptions,
) InnerError!void {
    const mod = self.bin_file.comp.module.?;
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    const dst_ptr_mcv: MCValue = switch (base) {
        .none => .{ .immediate = @bit_cast(@as(i64, disp)) },
        .reg => |base_reg| .{ .register_offset = .{ .reg = base_reg, .off = disp } },
        .frame => |base_frame_index| .{ .lea_frame = .{ .index = base_frame_index, .off = disp } },
        .reloc => |base_symbol| .{ .lea_symbol = .{ .sym = base_symbol.sym_index, .off = disp } },
    };
    switch (src_mcv) {
        .none,
        .unreach,
        .dead,
        .elementwise_regs_then_frame,
        .reserved_frame,
        => unreachable,
        .undef => if (opts.safety) try self.gen_inline_memset(
            dst_ptr_mcv,
            src_mcv,
            .{ .immediate = abi_size },
            opts,
        ),
        .immediate => |imm| switch (abi_size) {
            1, 2, 4 => {
                const immediate = switch (if (ty.is_abi_int(mod))
                    ty.int_info(mod).signedness
                else
                    .unsigned) {
                    .signed => Immediate.s(@truncate(@as(i64, @bit_cast(imm)))),
                    .unsigned => Immediate.u(@as(u32, @int_cast(imm))),
                };
                try self.asm_memory_immediate(
                    .{ ._, .mov },
                    .{ .base = base, .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(abi_size),
                        .disp = disp,
                    } } },
                    immediate,
                );
            },
            3, 5...7 => unreachable,
            else => if (math.cast(i32, @as(i64, @bit_cast(imm)))) |small| {
                try self.asm_memory_immediate(
                    .{ ._, .mov },
                    .{ .base = base, .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(abi_size),
                        .disp = disp,
                    } } },
                    Immediate.s(small),
                );
            } else {
                var offset: i32 = 0;
                while (offset < abi_size) : (offset += 4) try self.asm_memory_immediate(
                    .{ ._, .mov },
                    .{ .base = base, .mod = .{ .rm = .{
                        .size = .dword,
                        .disp = disp + offset,
                    } } },
                    if (ty.is_signed_int(mod)) Immediate.s(
                        @truncate(@as(i64, @bit_cast(imm)) >> (math.cast(u6, offset * 8) orelse 63)),
                    ) else Immediate.u(
                        @as(u32, @truncate(if (math.cast(u6, offset * 8)) |shift| imm >> shift else 0)),
                    ),
                );
            },
        },
        .eflags => |cc| try self.asm_setcc_memory(cc, .{ .base = base, .mod = .{
            .rm = .{ .size = .byte, .disp = disp },
        } }),
        .register => |src_reg| {
            const mem_size = switch (base) {
                .frame => |base_fi| mem_size: {
                    assert(disp >= 0);
                    const frame_abi_size = self.frame_allocs.items(.abi_size)[@int_from_enum(base_fi)];
                    const frame_spill_pad = self.frame_allocs.items(.spill_pad)[@int_from_enum(base_fi)];
                    assert(frame_abi_size - frame_spill_pad - disp >= abi_size);
                    break :mem_size if (frame_abi_size - frame_spill_pad - disp == abi_size)
                        frame_abi_size
                    else
                        abi_size;
                },
                else => abi_size,
            };
            const src_alias = register_alias(src_reg, abi_size);
            const src_size: u32 = @int_cast(switch (src_alias.class()) {
                .general_purpose, .segment, .x87 => @div_exact(src_alias.bit_size(), 8),
                .mmx, .sse => abi_size,
            });
            const src_align = Alignment.from_nonzero_byte_units(math.ceil_power_of_two_assert(u32, src_size));
            if (src_size > mem_size) {
                const frame_index = try self.alloc_frame_index(FrameAlloc.init(.{
                    .size = src_size,
                    .alignment = src_align,
                }));
                const frame_mcv: MCValue = .{ .load_frame = .{ .index = frame_index } };
                try (try self.move_strategy(ty, src_alias.class(), true)).write(
                    self,
                    .{ .base = .{ .frame = frame_index }, .mod = .{ .rm = .{
                        .size = Memory.Size.from_size(src_size),
                    } } },
                    src_alias,
                );
                try self.gen_set_mem(base, disp, ty, frame_mcv, opts);
                try self.free_value(frame_mcv);
            } else try (try self.move_strategy(ty, src_alias.class(), switch (base) {
                .none => src_align.check(@as(u32, @bit_cast(disp))),
                .reg => |reg| switch (reg) {
                    .es, .cs, .ss, .ds => src_align.check(@as(u32, @bit_cast(disp))),
                    else => false,
                },
                .frame => |frame_index| self.get_frame_addr_alignment(.{
                    .index = frame_index,
                    .off = disp,
                }).compare(.gte, src_align),
                .reloc => false,
            })).write(
                self,
                .{ .base = base, .mod = .{ .rm = .{
                    .size = self.mem_size(ty),
                    .disp = disp,
                } } },
                src_alias,
            );
        },
        .register_pair => |src_regs| {
            var part_disp: i32 = disp;
            for (try self.split_type(ty), src_regs) |src_ty, src_reg| {
                try self.gen_set_mem(base, part_disp, src_ty, .{ .register = src_reg }, opts);
                part_disp += @int_cast(src_ty.abi_size(mod));
            }
        },
        .register_overflow => |ro| switch (ty.zig_type_tag(mod)) {
            .Struct => {
                try self.gen_set_mem(
                    base,
                    disp + @as(i32, @int_cast(ty.struct_field_offset(0, mod))),
                    ty.struct_field_type(0, mod),
                    .{ .register = ro.reg },
                    opts,
                );
                try self.gen_set_mem(
                    base,
                    disp + @as(i32, @int_cast(ty.struct_field_offset(1, mod))),
                    ty.struct_field_type(1, mod),
                    .{ .eflags = ro.eflags },
                    opts,
                );
            },
            .Optional => {
                assert(!ty.optional_repr_is_payload(mod));
                const child_ty = ty.optional_child(mod);
                try self.gen_set_mem(base, disp, child_ty, .{ .register = ro.reg }, opts);
                try self.gen_set_mem(
                    base,
                    disp + @as(i32, @int_cast(child_ty.abi_size(mod))),
                    Type.bool,
                    .{ .eflags = ro.eflags },
                    opts,
                );
            },
            else => return self.fail("TODO implement gen_set_mem for {s} of {}", .{
                @tag_name(src_mcv), ty.fmt(mod),
            }),
        },
        .register_offset,
        .memory,
        .indirect,
        .load_direct,
        .lea_direct,
        .load_got,
        .lea_got,
        .load_tlv,
        .lea_tlv,
        .load_frame,
        .lea_frame,
        .load_symbol,
        .lea_symbol,
        => switch (abi_size) {
            0 => {},
            1, 2, 4, 8 => {
                const src_reg = try self.copy_to_tmp_register(ty, src_mcv);
                const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
                defer self.register_manager.unlock_reg(src_lock);

                try self.gen_set_mem(base, disp, ty, .{ .register = src_reg }, opts);
            },
            else => try self.gen_inline_memcpy(
                dst_ptr_mcv,
                src_mcv.address(),
                .{ .immediate = abi_size },
            ),
        },
        .air_ref => |src_ref| try self.gen_set_mem(base, disp, ty, try self.resolve_inst(src_ref), opts),
    }
}

fn gen_inline_memcpy(self: *Self, dst_ptr: MCValue, src_ptr: MCValue, len: MCValue) InnerError!void {
    try self.spill_registers(&.{ .rsi, .rdi, .rcx });
    try self.gen_set_reg(.rsi, Type.usize, src_ptr, .{});
    try self.gen_set_reg(.rdi, Type.usize, dst_ptr, .{});
    try self.gen_set_reg(.rcx, Type.usize, len, .{});
    try self.asm_op_only(.{ .@"rep _sb", .mov });
}

fn gen_inline_memset(
    self: *Self,
    dst_ptr: MCValue,
    value: MCValue,
    len: MCValue,
    opts: CopyOptions,
) InnerError!void {
    try self.spill_registers(&.{ .rdi, .al, .rcx });
    try self.gen_set_reg(.rdi, Type.usize, dst_ptr, .{});
    try self.gen_set_reg(.al, Type.u8, value, opts);
    try self.gen_set_reg(.rcx, Type.usize, len, .{});
    try self.asm_op_only(.{ .@"rep _sb", .sto });
}

fn gen_extern_symbol_ref(
    self: *Self,
    comptime tag: Mir.Inst.Tag,
    lib: ?[]const u8,
    callee: []const u8,
) InnerError!void {
    const atom_index = try self.owner.get_symbol_index(self);
    if (self.bin_file.cast(link.File.Elf)) |elf_file| {
        _ = try self.add_inst(.{
            .tag = tag,
            .ops = .extern_fn_reloc,
            .data = .{ .reloc = .{
                .atom_index = atom_index,
                .sym_index = try elf_file.get_global_symbol(callee, lib),
            } },
        });
    } else if (self.bin_file.cast(link.File.Coff)) |coff_file| {
        const global_index = try coff_file.get_global_symbol(callee, lib);
        _ = try self.add_inst(.{
            .tag = .mov,
            .ops = .import_reloc,
            .data = .{ .rx = .{
                .r1 = .rax,
                .payload = try self.add_extra(bits.Symbol{
                    .atom_index = atom_index,
                    .sym_index = link.File.Coff.global_symbol_bit | global_index,
                }),
            } },
        });
        switch (tag) {
            .mov => {},
            .call => try self.asm_register(.{ ._, .call }, .rax),
            else => unreachable,
        }
    } else if (self.bin_file.cast(link.File.MachO)) |macho_file| {
        _ = try self.add_inst(.{
            .tag = .call,
            .ops = .extern_fn_reloc,
            .data = .{ .reloc = .{
                .atom_index = atom_index,
                .sym_index = try macho_file.get_global_symbol(callee, lib),
            } },
        });
    } else return self.fail("TODO implement calling extern functions", .{});
}

fn gen_lazy_symbol_ref(
    self: *Self,
    comptime tag: Mir.Inst.Tag,
    reg: Register,
    lazy_sym: link.File.LazySymbol,
) InnerError!void {
    if (self.bin_file.cast(link.File.Elf)) |elf_file| {
        const sym_index = elf_file.zig_object_ptr().?.get_or_create_metadata_for_lazy_symbol(elf_file, lazy_sym) catch |err|
            return self.fail("{s} creating lazy symbol", .{@errorName(err)});
        const sym = elf_file.symbol(sym_index);
        if (self.mod.pic) {
            switch (tag) {
                .lea, .call => try self.gen_set_reg(reg, Type.usize, .{
                    .load_symbol = .{ .sym = sym.esym_index },
                }, .{}),
                .mov => try self.gen_set_reg(reg, Type.usize, .{
                    .load_symbol = .{ .sym = sym.esym_index },
                }, .{}),
                else => unreachable,
            }
            switch (tag) {
                .lea, .mov => {},
                .call => try self.asm_register(.{ ._, .call }, reg),
                else => unreachable,
            }
        } else {
            const reloc = bits.Symbol{
                .atom_index = try self.owner.get_symbol_index(self),
                .sym_index = sym.esym_index,
            };
            switch (tag) {
                .lea, .mov => try self.asm_register_memory(.{ ._, .mov }, reg.to64(), .{
                    .base = .{ .reloc = reloc },
                    .mod = .{ .rm = .{ .size = .qword } },
                }),
                .call => try self.asm_memory(.{ ._, .call }, .{
                    .base = .{ .reloc = reloc },
                    .mod = .{ .rm = .{ .size = .qword } },
                }),
                else => unreachable,
            }
        }
    } else if (self.bin_file.cast(link.File.Plan9)) |p9_file| {
        const atom_index = p9_file.get_or_create_atom_for_lazy_symbol(lazy_sym) catch |err|
            return self.fail("{s} creating lazy symbol", .{@errorName(err)});
        var atom = p9_file.get_atom(atom_index);
        _ = atom.get_or_create_offset_table_entry(p9_file);
        const got_addr = atom.get_offset_table_address(p9_file);
        const got_mem: Memory = .{
            .base = .{ .reg = .ds },
            .mod = .{ .rm = .{
                .size = .qword,
                .disp = @int_cast(got_addr),
            } },
        };
        switch (tag) {
            .lea, .mov => try self.asm_register_memory(.{ ._, .mov }, reg.to64(), got_mem),
            .call => try self.asm_memory(.{ ._, .call }, got_mem),
            else => unreachable,
        }
        switch (tag) {
            .lea, .call => {},
            .mov => try self.asm_register_memory(
                .{ ._, tag },
                reg.to64(),
                Memory.sib(.qword, .{ .base = .{ .reg = reg.to64() } }),
            ),
            else => unreachable,
        }
    } else if (self.bin_file.cast(link.File.Coff)) |coff_file| {
        const atom_index = coff_file.get_or_create_atom_for_lazy_symbol(lazy_sym) catch |err|
            return self.fail("{s} creating lazy symbol", .{@errorName(err)});
        const sym_index = coff_file.get_atom(atom_index).get_symbol_index().?;
        switch (tag) {
            .lea, .call => try self.gen_set_reg(reg, Type.usize, .{ .lea_got = sym_index }, .{}),
            .mov => try self.gen_set_reg(reg, Type.usize, .{ .load_got = sym_index }, .{}),
            else => unreachable,
        }
        switch (tag) {
            .lea, .mov => {},
            .call => try self.asm_register(.{ ._, .call }, reg),
            else => unreachable,
        }
    } else if (self.bin_file.cast(link.File.MachO)) |macho_file| {
        const sym_index = macho_file.get_zig_object().?.get_or_create_metadata_for_lazy_symbol(macho_file, lazy_sym) catch |err|
            return self.fail("{s} creating lazy symbol", .{@errorName(err)});
        const sym = macho_file.get_symbol(sym_index);
        switch (tag) {
            .lea, .call => try self.gen_set_reg(
                reg,
                Type.usize,
                .{ .load_symbol = .{ .sym = sym.nlist_idx } },
                .{},
            ),
            .mov => try self.gen_set_reg(reg, Type.usize, .{ .load_symbol = .{ .sym = sym.nlist_idx } }, .{}),
            else => unreachable,
        }
        switch (tag) {
            .lea, .mov => {},
            .call => try self.asm_register(.{ ._, .call }, reg),
            else => unreachable,
        }
    } else {
        return self.fail("TODO implement genLazySymbol for x86_64 {s}", .{@tag_name(self.bin_file.tag)});
    }
}

fn air_int_from_ptr(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const result = result: {
        // TODO: handle case where the operand is a slice not a raw pointer
        const src_mcv = try self.resolve_inst(un_op);
        if (self.reuse_operand(inst, un_op, 0, src_mcv)) break :result src_mcv;

        const dst_mcv = try self.alloc_reg_or_mem(inst, true);
        const dst_ty = self.type_of_index(inst);
        try self.gen_copy(dst_ty, dst_mcv, src_mcv, .{});
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ un_op, .none, .none });
}

fn air_bit_cast(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const dst_ty = self.type_of_index(inst);
    const src_ty = self.type_of(ty_op.operand);

    const result = result: {
        const dst_rc = self.reg_class_for_type(dst_ty);
        const src_rc = self.reg_class_for_type(src_ty);
        const src_mcv = try self.resolve_inst(ty_op.operand);

        const src_lock = if (src_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
        defer if (src_lock) |lock| self.register_manager.unlock_reg(lock);

        const dst_mcv = if (dst_rc.superset_of(src_rc) and dst_ty.abi_size(mod) <= src_ty.abi_size(mod) and
            self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) src_mcv else dst: {
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(switch (math.order(dst_ty.abi_size(mod), src_ty.abi_size(mod))) {
                .lt => dst_ty,
                .eq => if (!dst_mcv.is_memory() or src_mcv.is_memory()) dst_ty else src_ty,
                .gt => src_ty,
            }, dst_mcv, src_mcv, .{});
            break :dst dst_mcv;
        };

        if (dst_ty.is_runtime_float()) break :result dst_mcv;

        if (dst_ty.is_abi_int(mod) and src_ty.is_abi_int(mod) and
            dst_ty.int_info(mod).signedness == src_ty.int_info(mod).signedness) break :result dst_mcv;

        const abi_size = dst_ty.abi_size(mod);
        const bit_size = dst_ty.bit_size(mod);
        if (abi_size * 8 <= bit_size or dst_ty.is_vector(mod)) break :result dst_mcv;

        const dst_limbs_len = math.div_ceil(i32, @int_cast(bit_size), 64) catch unreachable;
        const high_mcv: MCValue = switch (dst_mcv) {
            .register => |dst_reg| .{ .register = dst_reg },
            .register_pair => |dst_regs| .{ .register = dst_regs[1] },
            else => dst_mcv.address().offset((dst_limbs_len - 1) * 8).deref(),
        };
        const high_reg = if (high_mcv.is_register())
            high_mcv.get_reg().?
        else
            try self.copy_to_tmp_register(Type.usize, high_mcv);
        const high_lock = self.register_manager.lock_reg(high_reg);
        defer if (high_lock) |lock| self.register_manager.unlock_reg(lock);

        try self.truncate_register(dst_ty, high_reg);
        if (!high_mcv.is_register()) try self.gen_copy(
            if (abi_size <= 8) dst_ty else Type.usize,
            high_mcv,
            .{ .register = high_reg },
            .{},
        );
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_array_to_slice(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const slice_ty = self.type_of_index(inst);
    const ptr_ty = self.type_of(ty_op.operand);
    const ptr = try self.resolve_inst(ty_op.operand);
    const array_ty = ptr_ty.child_type(mod);
    const array_len = array_ty.array_len(mod);

    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(slice_ty, mod));
    try self.gen_set_mem(.{ .frame = frame_index }, 0, ptr_ty, ptr, .{});
    try self.gen_set_mem(
        .{ .frame = frame_index },
        @int_cast(ptr_ty.abi_size(mod)),
        Type.usize,
        .{ .immediate = array_len },
        .{},
    );

    const result = MCValue{ .load_frame = .{ .index = frame_index } };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_float_from_int(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dst_ty = self.type_of_index(inst);
    const dst_bits = dst_ty.float_bits(self.target.*);

    const src_ty = self.type_of(ty_op.operand);
    const src_bits: u32 = @int_cast(src_ty.bit_size(mod));
    const src_signedness =
        if (src_ty.is_abi_int(mod)) src_ty.int_info(mod).signedness else .unsigned;
    const src_size = math.div_ceil(u32, @max(switch (src_signedness) {
        .signed => src_bits,
        .unsigned => src_bits + 1,
    }, 32), 8) catch unreachable;

    const result = result: {
        if (switch (dst_bits) {
            16, 80, 128 => true,
            32, 64 => src_size > 8,
            else => unreachable,
        }) {
            if (src_bits > 128) return self.fail("TODO implement air_float_from_int from {} to {}", .{
                src_ty.fmt(mod), dst_ty.fmt(mod),
            });

            var callee_buf: ["__floatun?i?f".len]u8 = undefined;
            break :result try self.gen_call(.{ .lib = .{
                .return_type = dst_ty.to_intern(),
                .param_types = &.{src_ty.to_intern()},
                .callee = std.fmt.buf_print(&callee_buf, "__float{s}{c}i{c}f", .{
                    switch (src_signedness) {
                        .signed => "",
                        .unsigned => "un",
                    },
                    int_compiler_rt_abi_name(src_bits),
                    float_compiler_rt_abi_name(dst_bits),
                }) catch unreachable,
            } }, &.{src_ty}, &.{.{ .air_ref = ty_op.operand }});
        }

        const src_mcv = try self.resolve_inst(ty_op.operand);
        const src_reg = if (src_mcv.is_register())
            src_mcv.get_reg().?
        else
            try self.copy_to_tmp_register(src_ty, src_mcv);
        const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
        defer self.register_manager.unlock_reg(src_lock);

        if (src_bits < src_size * 8) try self.truncate_register(src_ty, src_reg);

        const dst_reg = try self.register_manager.alloc_reg(inst, self.reg_class_for_type(dst_ty));
        const dst_mcv = MCValue{ .register = dst_reg };
        const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
        defer self.register_manager.unlock_reg(dst_lock);

        const mir_tag = @as(?Mir.Inst.FixedTag, switch (dst_ty.zig_type_tag(mod)) {
            .Float => switch (dst_ty.float_bits(self.target.*)) {
                32 => if (self.has_feature(.avx)) .{ .v_ss, .cvtsi2 } else .{ ._ss, .cvtsi2 },
                64 => if (self.has_feature(.avx)) .{ .v_sd, .cvtsi2 } else .{ ._sd, .cvtsi2 },
                16, 80, 128 => null,
                else => unreachable,
            },
            else => null,
        }) orelse return self.fail("TODO implement air_float_from_int from {} to {}", .{
            src_ty.fmt(mod), dst_ty.fmt(mod),
        });
        const dst_alias = dst_reg.to128();
        const src_alias = register_alias(src_reg, src_size);
        switch (mir_tag[0]) {
            .v_ss, .v_sd => try self.asm_register_register_register(mir_tag, dst_alias, dst_alias, src_alias),
            else => try self.asm_register_register(mir_tag, dst_alias, src_alias),
        }

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_int_from_float(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;

    const dst_ty = self.type_of_index(inst);
    const dst_bits: u32 = @int_cast(dst_ty.bit_size(mod));
    const dst_signedness =
        if (dst_ty.is_abi_int(mod)) dst_ty.int_info(mod).signedness else .unsigned;
    const dst_size = math.div_ceil(u32, @max(switch (dst_signedness) {
        .signed => dst_bits,
        .unsigned => dst_bits + 1,
    }, 32), 8) catch unreachable;

    const src_ty = self.type_of(ty_op.operand);
    const src_bits = src_ty.float_bits(self.target.*);

    const result = result: {
        if (switch (src_bits) {
            16, 80, 128 => true,
            32, 64 => dst_size > 8,
            else => unreachable,
        }) {
            if (dst_bits > 128) return self.fail("TODO implement air_int_from_float from {} to {}", .{
                src_ty.fmt(mod), dst_ty.fmt(mod),
            });

            var callee_buf: ["__fixuns?f?i".len]u8 = undefined;
            break :result try self.gen_call(.{ .lib = .{
                .return_type = dst_ty.to_intern(),
                .param_types = &.{src_ty.to_intern()},
                .callee = std.fmt.buf_print(&callee_buf, "__fix{s}{c}f{c}i", .{
                    switch (dst_signedness) {
                        .signed => "",
                        .unsigned => "uns",
                    },
                    float_compiler_rt_abi_name(src_bits),
                    int_compiler_rt_abi_name(dst_bits),
                }) catch unreachable,
            } }, &.{src_ty}, &.{.{ .air_ref = ty_op.operand }});
        }

        const src_mcv = try self.resolve_inst(ty_op.operand);
        const src_reg = if (src_mcv.is_register())
            src_mcv.get_reg().?
        else
            try self.copy_to_tmp_register(src_ty, src_mcv);
        const src_lock = self.register_manager.lock_reg_assume_unused(src_reg);
        defer self.register_manager.unlock_reg(src_lock);

        const dst_reg = try self.register_manager.alloc_reg(inst, self.reg_class_for_type(dst_ty));
        const dst_mcv = MCValue{ .register = dst_reg };
        const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
        defer self.register_manager.unlock_reg(dst_lock);

        try self.asm_register_register(
            switch (src_bits) {
                32 => if (self.has_feature(.avx)) .{ .v_, .cvttss2si } else .{ ._, .cvttss2si },
                64 => if (self.has_feature(.avx)) .{ .v_, .cvttsd2si } else .{ ._, .cvttsd2si },
                else => unreachable,
            },
            register_alias(dst_reg, dst_size),
            src_reg.to128(),
        );

        if (dst_bits < dst_size * 8) try self.truncate_register(dst_ty, dst_reg);

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_cmpxchg(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;

    const ptr_ty = self.type_of(extra.ptr);
    const val_ty = self.type_of(extra.expected_value);
    const val_abi_size: u32 = @int_cast(val_ty.abi_size(mod));

    try self.spill_registers(&.{ .rax, .rdx, .rbx, .rcx });
    const regs_lock = self.register_manager.lock_regs_assume_unused(4, .{ .rax, .rdx, .rbx, .rcx });
    defer for (regs_lock) |lock| self.register_manager.unlock_reg(lock);

    const exp_mcv = try self.resolve_inst(extra.expected_value);
    if (val_abi_size > 8) {
        const exp_addr_mcv: MCValue = switch (exp_mcv) {
            .memory, .indirect, .load_frame => exp_mcv.address(),
            else => .{ .register = try self.copy_to_tmp_register(Type.usize, exp_mcv.address()) },
        };
        const exp_addr_lock =
            if (exp_addr_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
        defer if (exp_addr_lock) |lock| self.register_manager.unlock_reg(lock);

        try self.gen_set_reg(.rax, Type.usize, exp_addr_mcv.deref(), .{});
        try self.gen_set_reg(.rdx, Type.usize, exp_addr_mcv.offset(8).deref(), .{});
    } else try self.gen_set_reg(.rax, val_ty, exp_mcv, .{});

    const new_mcv = try self.resolve_inst(extra.new_value);
    const new_reg = if (val_abi_size > 8) new: {
        const new_addr_mcv: MCValue = switch (new_mcv) {
            .memory, .indirect, .load_frame => new_mcv.address(),
            else => .{ .register = try self.copy_to_tmp_register(Type.usize, new_mcv.address()) },
        };
        const new_addr_lock =
            if (new_addr_mcv.get_reg()) |reg| self.register_manager.lock_reg(reg) else null;
        defer if (new_addr_lock) |lock| self.register_manager.unlock_reg(lock);

        try self.gen_set_reg(.rbx, Type.usize, new_addr_mcv.deref(), .{});
        try self.gen_set_reg(.rcx, Type.usize, new_addr_mcv.offset(8).deref(), .{});
        break :new null;
    } else try self.copy_to_tmp_register(val_ty, new_mcv);
    const new_lock = if (new_reg) |reg| self.register_manager.lock_reg_assume_unused(reg) else null;
    defer if (new_lock) |lock| self.register_manager.unlock_reg(lock);

    const ptr_mcv = try self.resolve_inst(extra.ptr);
    const mem_size = Memory.Size.from_size(val_abi_size);
    const ptr_mem: Memory = switch (ptr_mcv) {
        .immediate, .register, .register_offset, .lea_frame => try ptr_mcv.deref().mem(self, mem_size),
        else => .{
            .base = .{ .reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv) },
            .mod = .{ .rm = .{ .size = mem_size } },
        },
    };
    switch (ptr_mem.mod) {
        .rm => {},
        .off => return self.fail("TODO air_cmpxchg with {s}", .{@tag_name(ptr_mcv)}),
    }
    const ptr_lock = switch (ptr_mem.base) {
        .none, .frame, .reloc => null,
        .reg => |reg| self.register_manager.lock_reg(reg),
    };
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    try self.spill_eflags_if_occupied();
    if (val_abi_size <= 8) try self.asm_memory_register(
        .{ .@"lock _", .cmpxchg },
        ptr_mem,
        register_alias(new_reg.?, val_abi_size),
    ) else try self.asm_memory(.{ .@"lock _16b", .cmpxchg }, ptr_mem);

    const result: MCValue = result: {
        if (self.liveness.is_unused(inst)) break :result .unreach;

        if (val_abi_size <= 8) {
            self.eflags_inst = inst;
            break :result .{ .register_overflow = .{ .reg = .rax, .eflags = .ne } };
        }

        const dst_mcv = try self.alloc_reg_or_mem(inst, false);
        try self.gen_copy(Type.usize, dst_mcv, .{ .register = .rax }, .{});
        try self.gen_copy(Type.usize, dst_mcv.address().offset(8).deref(), .{ .register = .rdx }, .{});
        try self.gen_copy(Type.bool, dst_mcv.address().offset(16).deref(), .{ .eflags = .ne }, .{});
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ extra.ptr, extra.expected_value, extra.new_value });
}

fn atomic_op(
    self: *Self,
    ptr_mcv: MCValue,
    val_mcv: MCValue,
    ptr_ty: Type,
    val_ty: Type,
    unused: bool,
    rmw_op: ?std.builtin.AtomicRmwOp,
    order: std.builtin.AtomicOrder,
) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    const ptr_lock = switch (ptr_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const val_lock = switch (val_mcv) {
        .register => |reg| self.register_manager.lock_reg(reg),
        else => null,
    };
    defer if (val_lock) |lock| self.register_manager.unlock_reg(lock);

    const val_abi_size: u32 = @int_cast(val_ty.abi_size(mod));
    const mem_size = Memory.Size.from_size(val_abi_size);
    const ptr_mem: Memory = switch (ptr_mcv) {
        .immediate, .register, .register_offset, .lea_frame => try ptr_mcv.deref().mem(self, mem_size),
        else => .{
            .base = .{ .reg = try self.copy_to_tmp_register(ptr_ty, ptr_mcv) },
            .mod = .{ .rm = .{ .size = mem_size } },
        },
    };
    switch (ptr_mem.mod) {
        .rm => {},
        .off => return self.fail("TODO air_cmpxchg with {s}", .{@tag_name(ptr_mcv)}),
    }
    const mem_lock = switch (ptr_mem.base) {
        .none, .frame, .reloc => null,
        .reg => |reg| self.register_manager.lock_reg(reg),
    };
    defer if (mem_lock) |lock| self.register_manager.unlock_reg(lock);

    const use_sse = rmw_op orelse .Xchg != .Xchg and val_ty.is_runtime_float();
    const strat: enum { lock, loop, libcall } = if (use_sse) .loop else switch (rmw_op orelse .Xchg) {
        .Xchg,
        .Add,
        .Sub,
        => if (val_abi_size <= 8) .lock else if (val_abi_size <= 16) .loop else .libcall,
        .And,
        .Or,
        .Xor,
        => if (val_abi_size <= 8 and unused) .lock else if (val_abi_size <= 16) .loop else .libcall,
        .Nand,
        .Max,
        .Min,
        => if (val_abi_size <= 16) .loop else .libcall,
    };
    switch (strat) {
        .lock => {
            const tag: Mir.Inst.Tag = if (rmw_op) |op| switch (op) {
                .Xchg => if (unused) .mov else .xchg,
                .Add => if (unused) .add else .xadd,
                .Sub => if (unused) .sub else .xadd,
                .And => .@"and",
                .Or => .@"or",
                .Xor => .xor,
                else => unreachable,
            } else switch (order) {
                .unordered, .monotonic, .release, .acq_rel => .mov,
                .acquire => unreachable,
                .seq_cst => .xchg,
            };

            const dst_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const dst_mcv = MCValue{ .register = dst_reg };
            const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
            defer self.register_manager.unlock_reg(dst_lock);

            try self.gen_set_reg(dst_reg, val_ty, val_mcv, .{});
            if (rmw_op == std.builtin.AtomicRmwOp.Sub and tag == .xadd) {
                try self.gen_un_op_mir(.{ ._, .neg }, val_ty, dst_mcv);
            }
            try self.asm_memory_register(
                switch (tag) {
                    .mov, .xchg => .{ ._, tag },
                    .xadd, .add, .sub, .@"and", .@"or", .xor => .{ .@"lock _", tag },
                    else => unreachable,
                },
                ptr_mem,
                register_alias(dst_reg, val_abi_size),
            );

            return if (unused) .unreach else dst_mcv;
        },
        .loop => _ = if (val_abi_size <= 8) {
            const sse_reg: Register = if (use_sse)
                try self.register_manager.alloc_reg(null, abi.RegisterClass.sse)
            else
                undefined;
            const sse_lock =
                if (use_sse) self.register_manager.lock_reg_assume_unused(sse_reg) else undefined;
            defer if (use_sse) self.register_manager.unlock_reg(sse_lock);

            const tmp_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const tmp_mcv = MCValue{ .register = tmp_reg };
            const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
            defer self.register_manager.unlock_reg(tmp_lock);

            try self.asm_register_memory(.{ ._, .mov }, register_alias(.rax, val_abi_size), ptr_mem);
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            if (!use_sse and rmw_op orelse .Xchg != .Xchg) {
                try self.gen_set_reg(tmp_reg, val_ty, .{ .register = .rax }, .{});
            }
            if (rmw_op) |op| if (use_sse) {
                const mir_tag = @as(?Mir.Inst.FixedTag, switch (op) {
                    .Add => switch (val_ty.float_bits(self.target.*)) {
                        32 => if (self.has_feature(.avx)) .{ .v_ss, .add } else .{ ._ss, .add },
                        64 => if (self.has_feature(.avx)) .{ .v_sd, .add } else .{ ._sd, .add },
                        else => null,
                    },
                    .Sub => switch (val_ty.float_bits(self.target.*)) {
                        32 => if (self.has_feature(.avx)) .{ .v_ss, .sub } else .{ ._ss, .sub },
                        64 => if (self.has_feature(.avx)) .{ .v_sd, .sub } else .{ ._sd, .sub },
                        else => null,
                    },
                    .Min => switch (val_ty.float_bits(self.target.*)) {
                        32 => if (self.has_feature(.avx)) .{ .v_ss, .min } else .{ ._ss, .min },
                        64 => if (self.has_feature(.avx)) .{ .v_sd, .min } else .{ ._sd, .min },
                        else => null,
                    },
                    .Max => switch (val_ty.float_bits(self.target.*)) {
                        32 => if (self.has_feature(.avx)) .{ .v_ss, .max } else .{ ._ss, .max },
                        64 => if (self.has_feature(.avx)) .{ .v_sd, .max } else .{ ._sd, .max },
                        else => null,
                    },
                    else => unreachable,
                }) orelse return self.fail("TODO implement atomic_op of {s} for {}", .{
                    @tag_name(op), val_ty.fmt(mod),
                });
                try self.gen_set_reg(sse_reg, val_ty, .{ .register = .rax }, .{});
                switch (mir_tag[0]) {
                    .v_ss, .v_sd => if (val_mcv.is_memory()) try self.asm_register_register_memory(
                        mir_tag,
                        sse_reg.to128(),
                        sse_reg.to128(),
                        try val_mcv.mem(self, self.mem_size(val_ty)),
                    ) else try self.asm_register_register_register(
                        mir_tag,
                        sse_reg.to128(),
                        sse_reg.to128(),
                        (if (val_mcv.is_register())
                            val_mcv.get_reg().?
                        else
                            try self.copy_to_tmp_register(val_ty, val_mcv)).to128(),
                    ),
                    ._ss, ._sd => if (val_mcv.is_memory()) try self.asm_register_memory(
                        mir_tag,
                        sse_reg.to128(),
                        try val_mcv.mem(self, self.mem_size(val_ty)),
                    ) else try self.asm_register_register(
                        mir_tag,
                        sse_reg.to128(),
                        (if (val_mcv.is_register())
                            val_mcv.get_reg().?
                        else
                            try self.copy_to_tmp_register(val_ty, val_mcv)).to128(),
                    ),
                    else => unreachable,
                }
                try self.gen_set_reg(tmp_reg, val_ty, .{ .register = sse_reg }, .{});
            } else switch (op) {
                .Xchg => try self.gen_set_reg(tmp_reg, val_ty, val_mcv, .{}),
                .Add => try self.gen_bin_op_mir(.{ ._, .add }, val_ty, tmp_mcv, val_mcv),
                .Sub => try self.gen_bin_op_mir(.{ ._, .sub }, val_ty, tmp_mcv, val_mcv),
                .And => try self.gen_bin_op_mir(.{ ._, .@"and" }, val_ty, tmp_mcv, val_mcv),
                .Nand => {
                    try self.gen_bin_op_mir(.{ ._, .@"and" }, val_ty, tmp_mcv, val_mcv);
                    try self.gen_un_op_mir(.{ ._, .not }, val_ty, tmp_mcv);
                },
                .Or => try self.gen_bin_op_mir(.{ ._, .@"or" }, val_ty, tmp_mcv, val_mcv),
                .Xor => try self.gen_bin_op_mir(.{ ._, .xor }, val_ty, tmp_mcv, val_mcv),
                .Min, .Max => {
                    const cc: Condition = switch (if (val_ty.is_abi_int(mod))
                        val_ty.int_info(mod).signedness
                    else
                        .unsigned) {
                        .unsigned => switch (op) {
                            .Min => .a,
                            .Max => .b,
                            else => unreachable,
                        },
                        .signed => switch (op) {
                            .Min => .g,
                            .Max => .l,
                            else => unreachable,
                        },
                    };

                    const cmov_abi_size = @max(val_abi_size, 2);
                    switch (val_mcv) {
                        .register => |val_reg| {
                            try self.gen_bin_op_mir(.{ ._, .cmp }, val_ty, tmp_mcv, val_mcv);
                            try self.asm_cmovcc_register_register(
                                cc,
                                register_alias(tmp_reg, cmov_abi_size),
                                register_alias(val_reg, cmov_abi_size),
                            );
                        },
                        .memory, .indirect, .load_frame => {
                            try self.gen_bin_op_mir(.{ ._, .cmp }, val_ty, tmp_mcv, val_mcv);
                            try self.asm_cmovcc_register_memory(
                                cc,
                                register_alias(tmp_reg, cmov_abi_size),
                                try val_mcv.mem(self, Memory.Size.from_size(cmov_abi_size)),
                            );
                        },
                        else => {
                            const mat_reg = try self.copy_to_tmp_register(val_ty, val_mcv);
                            const mat_lock = self.register_manager.lock_reg_assume_unused(mat_reg);
                            defer self.register_manager.unlock_reg(mat_lock);

                            try self.gen_bin_op_mir(
                                .{ ._, .cmp },
                                val_ty,
                                tmp_mcv,
                                .{ .register = mat_reg },
                            );
                            try self.asm_cmovcc_register_register(
                                cc,
                                register_alias(tmp_reg, cmov_abi_size),
                                register_alias(mat_reg, cmov_abi_size),
                            );
                        },
                    }
                },
            };
            try self.asm_memory_register(
                .{ .@"lock _", .cmpxchg },
                ptr_mem,
                register_alias(tmp_reg, val_abi_size),
            );
            _ = try self.asm_jcc_reloc(.ne, loop);
            return if (unused) .unreach else .{ .register = .rax };
        } else {
            try self.asm_register_memory(.{ ._, .mov }, .rax, .{
                .base = ptr_mem.base,
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = ptr_mem.mod.rm.index,
                    .scale = ptr_mem.mod.rm.scale,
                    .disp = ptr_mem.mod.rm.disp + 0,
                } },
            });
            try self.asm_register_memory(.{ ._, .mov }, .rdx, .{
                .base = ptr_mem.base,
                .mod = .{ .rm = .{
                    .size = .qword,
                    .index = ptr_mem.mod.rm.index,
                    .scale = ptr_mem.mod.rm.scale,
                    .disp = ptr_mem.mod.rm.disp + 8,
                } },
            });
            const loop: Mir.Inst.Index = @int_cast(self.mir_instructions.len);
            const val_mem_mcv: MCValue = switch (val_mcv) {
                .memory, .indirect, .load_frame => val_mcv,
                else => .{ .indirect = .{
                    .reg = try self.copy_to_tmp_register(Type.usize, val_mcv.address()),
                } },
            };
            const val_lo_mem = try val_mem_mcv.mem(self, .qword);
            const val_hi_mem = try val_mem_mcv.address().offset(8).deref().mem(self, .qword);
            if (rmw_op != std.builtin.AtomicRmwOp.Xchg) {
                try self.asm_register_register(.{ ._, .mov }, .rbx, .rax);
                try self.asm_register_register(.{ ._, .mov }, .rcx, .rdx);
            }
            if (rmw_op) |op| switch (op) {
                .Xchg => {
                    try self.asm_register_memory(.{ ._, .mov }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .mov }, .rcx, val_hi_mem);
                },
                .Add => {
                    try self.asm_register_memory(.{ ._, .add }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .adc }, .rcx, val_hi_mem);
                },
                .Sub => {
                    try self.asm_register_memory(.{ ._, .sub }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .sbb }, .rcx, val_hi_mem);
                },
                .And => {
                    try self.asm_register_memory(.{ ._, .@"and" }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .@"and" }, .rcx, val_hi_mem);
                },
                .Nand => {
                    try self.asm_register_memory(.{ ._, .@"and" }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .@"and" }, .rcx, val_hi_mem);
                    try self.asm_register(.{ ._, .not }, .rbx);
                    try self.asm_register(.{ ._, .not }, .rcx);
                },
                .Or => {
                    try self.asm_register_memory(.{ ._, .@"or" }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .@"or" }, .rcx, val_hi_mem);
                },
                .Xor => {
                    try self.asm_register_memory(.{ ._, .xor }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .xor }, .rcx, val_hi_mem);
                },
                .Min, .Max => {
                    const cc: Condition = switch (if (val_ty.is_abi_int(mod))
                        val_ty.int_info(mod).signedness
                    else
                        .unsigned) {
                        .unsigned => switch (op) {
                            .Min => .a,
                            .Max => .b,
                            else => unreachable,
                        },
                        .signed => switch (op) {
                            .Min => .g,
                            .Max => .l,
                            else => unreachable,
                        },
                    };

                    const tmp_reg = try self.copy_to_tmp_register(Type.usize, .{ .register = .rcx });
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    try self.asm_register_memory(.{ ._, .cmp }, .rbx, val_lo_mem);
                    try self.asm_register_memory(.{ ._, .sbb }, tmp_reg, val_hi_mem);
                    try self.asm_cmovcc_register_memory(cc, .rbx, val_lo_mem);
                    try self.asm_cmovcc_register_memory(cc, .rcx, val_hi_mem);
                },
            };
            try self.asm_memory(.{ .@"lock _16b", .cmpxchg }, ptr_mem);
            _ = try self.asm_jcc_reloc(.ne, loop);

            if (unused) return .unreach;
            const dst_mcv = try self.alloc_temp_reg_or_mem(val_ty, false);
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .disp = dst_mcv.load_frame.off + 0,
                } },
            }, .rax);
            try self.asm_memory_register(.{ ._, .mov }, .{
                .base = .{ .frame = dst_mcv.load_frame.index },
                .mod = .{ .rm = .{
                    .size = .qword,
                    .disp = dst_mcv.load_frame.off + 8,
                } },
            }, .rdx);
            return dst_mcv;
        },
        .libcall => return self.fail("TODO implement x86 atomic libcall", .{}),
    }
}

fn air_atomic_rmw(self: *Self, inst: Air.Inst.Index) !void {
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.AtomicRmw, pl_op.payload).data;

    try self.spill_registers(&.{ .rax, .rdx, .rbx, .rcx });
    const regs_lock = self.register_manager.lock_regs_assume_unused(4, .{ .rax, .rdx, .rbx, .rcx });
    defer for (regs_lock) |lock| self.register_manager.unlock_reg(lock);

    const unused = self.liveness.is_unused(inst);

    const ptr_ty = self.type_of(pl_op.operand);
    const ptr_mcv = try self.resolve_inst(pl_op.operand);

    const val_ty = self.type_of(extra.operand);
    const val_mcv = try self.resolve_inst(extra.operand);

    const result =
        try self.atomic_op(ptr_mcv, val_mcv, ptr_ty, val_ty, unused, extra.op(), extra.ordering());
    return self.finish_air(inst, result, .{ pl_op.operand, extra.operand, .none });
}

fn air_atomic_load(self: *Self, inst: Air.Inst.Index) !void {
    const atomic_load = self.air.instructions.items(.data)[@int_from_enum(inst)].atomic_load;

    const ptr_ty = self.type_of(atomic_load.ptr);
    const ptr_mcv = try self.resolve_inst(atomic_load.ptr);
    const ptr_lock = switch (ptr_mcv) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const dst_mcv =
        if (self.reuse_operand(inst, atomic_load.ptr, 0, ptr_mcv))
        ptr_mcv
    else
        try self.alloc_reg_or_mem(inst, true);

    try self.load(dst_mcv, ptr_ty, ptr_mcv);
    return self.finish_air(inst, dst_mcv, .{ atomic_load.ptr, .none, .none });
}

fn air_atomic_store(self: *Self, inst: Air.Inst.Index, order: std.builtin.AtomicOrder) !void {
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    const ptr_ty = self.type_of(bin_op.lhs);
    const ptr_mcv = try self.resolve_inst(bin_op.lhs);

    const val_ty = self.type_of(bin_op.rhs);
    const val_mcv = try self.resolve_inst(bin_op.rhs);

    const result = try self.atomic_op(ptr_mcv, val_mcv, ptr_ty, val_ty, true, null, order);
    return self.finish_air(inst, result, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_memset(self: *Self, inst: Air.Inst.Index, safety: bool) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    result: {
        if (!safety and (try self.resolve_inst(bin_op.rhs)) == .undef) break :result;

        try self.spill_registers(&.{ .rax, .rdi, .rsi, .rcx });
        const reg_locks = self.register_manager.lock_regs_assume_unused(4, .{ .rax, .rdi, .rsi, .rcx });
        defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

        const dst_ptr = try self.resolve_inst(bin_op.lhs);
        const dst_ptr_ty = self.type_of(bin_op.lhs);
        const dst_ptr_lock: ?RegisterLock = switch (dst_ptr) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (dst_ptr_lock) |lock| self.register_manager.unlock_reg(lock);

        const src_val = try self.resolve_inst(bin_op.rhs);
        const elem_ty = self.type_of(bin_op.rhs);
        const src_val_lock: ?RegisterLock = switch (src_val) {
            .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
            else => null,
        };
        defer if (src_val_lock) |lock| self.register_manager.unlock_reg(lock);

        const elem_abi_size: u31 = @int_cast(elem_ty.abi_size(mod));

        if (elem_abi_size == 1) {
            const ptr: MCValue = switch (dst_ptr_ty.ptr_size(mod)) {
                // TODO: this only handles slices stored in the stack
                .Slice => dst_ptr,
                .One => dst_ptr,
                .C, .Many => unreachable,
            };
            const len: MCValue = switch (dst_ptr_ty.ptr_size(mod)) {
                // TODO: this only handles slices stored in the stack
                .Slice => dst_ptr.address().offset(8).deref(),
                .One => .{ .immediate = dst_ptr_ty.child_type(mod).array_len(mod) },
                .C, .Many => unreachable,
            };
            const len_lock: ?RegisterLock = switch (len) {
                .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                else => null,
            };
            defer if (len_lock) |lock| self.register_manager.unlock_reg(lock);

            try self.gen_inline_memset(ptr, src_val, len, .{ .safety = safety });
            break :result;
        }

        // Store the first element, and then rely on memcpy copying forwards.
        // Length zero requires a runtime check - so we handle arrays specially
        // here to elide it.
        switch (dst_ptr_ty.ptr_size(mod)) {
            .Slice => {
                const slice_ptr_ty = dst_ptr_ty.slice_ptr_field_type(mod);

                // TODO: this only handles slices stored in the stack
                const ptr = dst_ptr;
                const len = dst_ptr.address().offset(8).deref();

                // Used to store the number of elements for comparison.
                // After comparison, updated to store number of bytes needed to copy.
                const len_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const len_mcv: MCValue = .{ .register = len_reg };
                const len_lock = self.register_manager.lock_reg_assume_unused(len_reg);
                defer self.register_manager.unlock_reg(len_lock);

                try self.gen_set_reg(len_reg, Type.usize, len, .{});
                try self.asm_register_register(.{ ._, .@"test" }, len_reg, len_reg);

                const skip_reloc = try self.asm_jcc_reloc(.z, undefined);
                try self.store(slice_ptr_ty, ptr, src_val, .{ .safety = safety });

                const second_elem_ptr_reg =
                    try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const second_elem_ptr_mcv: MCValue = .{ .register = second_elem_ptr_reg };
                const second_elem_ptr_lock =
                    self.register_manager.lock_reg_assume_unused(second_elem_ptr_reg);
                defer self.register_manager.unlock_reg(second_elem_ptr_lock);

                try self.gen_set_reg(second_elem_ptr_reg, Type.usize, .{ .register_offset = .{
                    .reg = try self.copy_to_tmp_register(Type.usize, ptr),
                    .off = elem_abi_size,
                } }, .{});

                try self.gen_bin_op_mir(.{ ._, .sub }, Type.usize, len_mcv, .{ .immediate = 1 });
                try self.asm_register_register_immediate(
                    .{ .i_, .mul },
                    len_reg,
                    len_reg,
                    Immediate.s(elem_abi_size),
                );
                try self.gen_inline_memcpy(second_elem_ptr_mcv, ptr, len_mcv);

                self.perform_reloc(skip_reloc);
            },
            .One => {
                const elem_ptr_ty = try mod.single_mut_ptr_type(elem_ty);

                const len = dst_ptr_ty.child_type(mod).array_len(mod);

                assert(len != 0); // prevented by Sema
                try self.store(elem_ptr_ty, dst_ptr, src_val, .{ .safety = safety });

                const second_elem_ptr_reg =
                    try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
                const second_elem_ptr_mcv: MCValue = .{ .register = second_elem_ptr_reg };
                const second_elem_ptr_lock =
                    self.register_manager.lock_reg_assume_unused(second_elem_ptr_reg);
                defer self.register_manager.unlock_reg(second_elem_ptr_lock);

                try self.gen_set_reg(second_elem_ptr_reg, Type.usize, .{ .register_offset = .{
                    .reg = try self.copy_to_tmp_register(Type.usize, dst_ptr),
                    .off = elem_abi_size,
                } }, .{});

                const bytes_to_copy: MCValue = .{ .immediate = elem_abi_size * (len - 1) };
                try self.gen_inline_memcpy(second_elem_ptr_mcv, dst_ptr, bytes_to_copy);
            },
            .C, .Many => unreachable,
        }
    }
    return self.finish_air(inst, .unreach, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_memcpy(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const bin_op = self.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;

    try self.spill_registers(&.{ .rdi, .rsi, .rcx });
    const reg_locks = self.register_manager.lock_regs_assume_unused(3, .{ .rdi, .rsi, .rcx });
    defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

    const dst_ptr = try self.resolve_inst(bin_op.lhs);
    const dst_ptr_ty = self.type_of(bin_op.lhs);
    const dst_ptr_lock: ?RegisterLock = switch (dst_ptr) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (dst_ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const src_ptr = try self.resolve_inst(bin_op.rhs);
    const src_ptr_lock: ?RegisterLock = switch (src_ptr) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (src_ptr_lock) |lock| self.register_manager.unlock_reg(lock);

    const len: MCValue = switch (dst_ptr_ty.ptr_size(mod)) {
        .Slice => len: {
            const len_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
            const len_lock = self.register_manager.lock_reg_assume_unused(len_reg);
            defer self.register_manager.unlock_reg(len_lock);

            try self.asm_register_memory_immediate(
                .{ .i_, .mul },
                len_reg,
                try dst_ptr.address().offset(8).deref().mem(self, .qword),
                Immediate.s(@int_cast(dst_ptr_ty.child_type(mod).abi_size(mod))),
            );
            break :len .{ .register = len_reg };
        },
        .One => len: {
            const array_ty = dst_ptr_ty.child_type(mod);
            break :len .{ .immediate = array_ty.array_len(mod) * array_ty.child_type(mod).abi_size(mod) };
        },
        .C, .Many => unreachable,
    };
    const len_lock: ?RegisterLock = switch (len) {
        .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
        else => null,
    };
    defer if (len_lock) |lock| self.register_manager.unlock_reg(lock);

    // TODO: dst_ptr and src_ptr could be slices rather than raw pointers
    try self.gen_inline_memcpy(dst_ptr, src_ptr, len);

    return self.finish_air(inst, .unreach, .{ bin_op.lhs, bin_op.rhs, .none });
}

fn air_tag_name(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    const inst_ty = self.type_of_index(inst);
    const enum_ty = self.type_of(un_op);
    const resolved_cc = abi.resolve_calling_convention(.Unspecified, self.target.*);

    // We need a properly aligned and sized call frame to be able to call this function.
    {
        const needed_call_frame = FrameAlloc.init(.{
            .size = inst_ty.abi_size(mod),
            .alignment = inst_ty.abi_alignment(mod),
        });
        const frame_allocs_slice = self.frame_allocs.slice();
        const stack_frame_size =
            &frame_allocs_slice.items(.abi_size)[@int_from_enum(FrameIndex.call_frame)];
        stack_frame_size.* = @max(stack_frame_size.*, needed_call_frame.abi_size);
        const stack_frame_align =
            &frame_allocs_slice.items(.abi_align)[@int_from_enum(FrameIndex.call_frame)];
        stack_frame_align.* = stack_frame_align.max(needed_call_frame.abi_align);
    }

    try self.spill_eflags_if_occupied();
    try self.spill_caller_preserved_regs(resolved_cc);

    const param_regs = abi.get_cabi_int_param_regs(resolved_cc);

    const dst_mcv = try self.alloc_reg_or_mem(inst, false);
    try self.gen_set_reg(param_regs[0], Type.usize, dst_mcv.address(), .{});

    const operand = try self.resolve_inst(un_op);
    try self.gen_set_reg(param_regs[1], enum_ty, operand, .{});

    try self.gen_lazy_symbol_ref(
        .call,
        .rax,
        link.File.LazySymbol.init_decl(.code, enum_ty.get_owner_decl(mod), mod),
    );

    return self.finish_air(inst, dst_mcv, .{ un_op, .none, .none });
}

fn air_error_name(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;

    const err_ty = self.type_of(un_op);
    const err_mcv = try self.resolve_inst(un_op);
    const err_reg = try self.copy_to_tmp_register(err_ty, err_mcv);
    const err_lock = self.register_manager.lock_reg_assume_unused(err_reg);
    defer self.register_manager.unlock_reg(err_lock);

    const addr_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const addr_lock = self.register_manager.lock_reg_assume_unused(addr_reg);
    defer self.register_manager.unlock_reg(addr_lock);
    try self.gen_lazy_symbol_ref(.lea, addr_reg, link.File.LazySymbol.init_decl(.const_data, null, mod));

    const start_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const start_lock = self.register_manager.lock_reg_assume_unused(start_reg);
    defer self.register_manager.unlock_reg(start_lock);

    const end_reg = try self.register_manager.alloc_reg(null, abi.RegisterClass.gp);
    const end_lock = self.register_manager.lock_reg_assume_unused(end_reg);
    defer self.register_manager.unlock_reg(end_lock);

    try self.truncate_register(err_ty, err_reg.to32());

    try self.asm_register_memory(
        .{ ._, .mov },
        start_reg.to32(),
        .{
            .base = .{ .reg = addr_reg.to64() },
            .mod = .{ .rm = .{
                .size = .dword,
                .index = err_reg.to64(),
                .scale = .@"4",
                .disp = 4,
            } },
        },
    );
    try self.asm_register_memory(
        .{ ._, .mov },
        end_reg.to32(),
        .{
            .base = .{ .reg = addr_reg.to64() },
            .mod = .{ .rm = .{
                .size = .dword,
                .index = err_reg.to64(),
                .scale = .@"4",
                .disp = 8,
            } },
        },
    );
    try self.asm_register_register(.{ ._, .sub }, end_reg.to32(), start_reg.to32());
    try self.asm_register_memory(
        .{ ._, .lea },
        start_reg.to64(),
        .{
            .base = .{ .reg = addr_reg.to64() },
            .mod = .{ .rm = .{
                .size = .dword,
                .index = start_reg.to64(),
            } },
        },
    );
    try self.asm_register_memory(
        .{ ._, .lea },
        end_reg.to32(),
        .{
            .base = .{ .reg = end_reg.to64() },
            .mod = .{ .rm = .{
                .size = .byte,
                .disp = -1,
            } },
        },
    );

    const dst_mcv = try self.alloc_reg_or_mem(inst, false);
    try self.asm_memory_register(
        .{ ._, .mov },
        .{
            .base = .{ .frame = dst_mcv.load_frame.index },
            .mod = .{ .rm = .{
                .size = .qword,
                .disp = dst_mcv.load_frame.off,
            } },
        },
        start_reg.to64(),
    );
    try self.asm_memory_register(
        .{ ._, .mov },
        .{
            .base = .{ .frame = dst_mcv.load_frame.index },
            .mod = .{ .rm = .{
                .size = .qword,
                .disp = dst_mcv.load_frame.off + 8,
            } },
        },
        end_reg.to64(),
    );

    return self.finish_air(inst, dst_mcv, .{ un_op, .none, .none });
}

fn air_splat(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const vector_ty = self.type_of_index(inst);
    const vector_len = vector_ty.vector_len(mod);
    const dst_rc = self.reg_class_for_type(vector_ty);
    const scalar_ty = self.type_of(ty_op.operand);

    const result: MCValue = result: {
        switch (scalar_ty.zig_type_tag(mod)) {
            else => {},
            .Bool => {
                const regs =
                    try self.register_manager.alloc_regs(2, .{ inst, null }, abi.RegisterClass.gp);
                const reg_locks = self.register_manager.lock_regs_assume_unused(2, regs);
                defer for (reg_locks) |lock| self.register_manager.unlock_reg(lock);

                try self.gen_set_reg(regs[1], vector_ty, .{ .immediate = 0 }, .{});
                try self.gen_set_reg(
                    regs[1],
                    vector_ty,
                    .{ .immediate = @as(u64, math.max_int(u64)) >> @int_cast(64 - vector_len) },
                    .{},
                );
                const src_mcv = try self.resolve_inst(ty_op.operand);
                const abi_size = @max(math.div_ceil(u32, vector_len, 8) catch unreachable, 4);
                try self.asm_cmovcc_register_register(
                    switch (src_mcv) {
                        .eflags => |cc| cc,
                        .register => |src_reg| cc: {
                            try self.asm_register_immediate(
                                .{ ._, .@"test" },
                                src_reg.to8(),
                                Immediate.u(1),
                            );
                            break :cc .nz;
                        },
                        else => cc: {
                            try self.asm_memory_immediate(
                                .{ ._, .@"test" },
                                try src_mcv.mem(self, .byte),
                                Immediate.u(1),
                            );
                            break :cc .nz;
                        },
                    },
                    register_alias(regs[0], abi_size),
                    register_alias(regs[1], abi_size),
                );
                break :result .{ .register = regs[0] };
            },
            .Int => if (self.has_feature(.avx2)) avx2: {
                const mir_tag = @as(?Mir.Inst.FixedTag, switch (scalar_ty.int_info(mod).bits) {
                    else => null,
                    1...8 => switch (vector_len) {
                        else => null,
                        1...32 => .{ .vp_b, .broadcast },
                    },
                    9...16 => switch (vector_len) {
                        else => null,
                        1...16 => .{ .vp_w, .broadcast },
                    },
                    17...32 => switch (vector_len) {
                        else => null,
                        1...8 => .{ .vp_d, .broadcast },
                    },
                    33...64 => switch (vector_len) {
                        else => null,
                        1...4 => .{ .vp_q, .broadcast },
                    },
                    65...128 => switch (vector_len) {
                        else => null,
                        1...2 => .{ .v_i128, .broadcast },
                    },
                }) orelse break :avx2;

                const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse);
                const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
                defer self.register_manager.unlock_reg(dst_lock);

                const src_mcv = try self.resolve_inst(ty_op.operand);
                if (src_mcv.is_memory()) try self.asm_register_memory(
                    mir_tag,
                    register_alias(dst_reg, @int_cast(vector_ty.abi_size(mod))),
                    try src_mcv.mem(self, self.mem_size(scalar_ty)),
                ) else {
                    if (mir_tag[0] == .v_i128) break :avx2;
                    try self.gen_set_reg(dst_reg, scalar_ty, src_mcv, .{});
                    try self.asm_register_register(
                        mir_tag,
                        register_alias(dst_reg, @int_cast(vector_ty.abi_size(mod))),
                        register_alias(dst_reg, @int_cast(scalar_ty.abi_size(mod))),
                    );
                }
                break :result .{ .register = dst_reg };
            } else {
                const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse);
                const dst_lock = self.register_manager.lock_reg_assume_unused(dst_reg);
                defer self.register_manager.unlock_reg(dst_lock);

                try self.gen_set_reg(dst_reg, scalar_ty, .{ .air_ref = ty_op.operand }, .{});
                if (vector_len == 1) break :result .{ .register = dst_reg };

                const dst_alias = register_alias(dst_reg, @int_cast(vector_ty.abi_size(mod)));
                const scalar_bits = scalar_ty.int_info(mod).bits;
                if (switch (scalar_bits) {
                    1...8 => true,
                    9...128 => false,
                    else => unreachable,
                }) if (self.has_feature(.avx)) try self.asm_register_register_register(
                    .{ .vp_, .unpcklbw },
                    dst_alias,
                    dst_alias,
                    dst_alias,
                ) else try self.asm_register_register(
                    .{ .p_, .unpcklbw },
                    dst_alias,
                    dst_alias,
                );
                if (switch (scalar_bits) {
                    1...8 => vector_len > 2,
                    9...16 => true,
                    17...128 => false,
                    else => unreachable,
                }) try self.asm_register_register_immediate(
                    .{ if (self.has_feature(.avx)) .vp_w else .p_w, .shufl },
                    dst_alias,
                    dst_alias,
                    Immediate.u(0b00_00_00_00),
                );
                if (switch (scalar_bits) {
                    1...8 => vector_len > 4,
                    9...16 => vector_len > 2,
                    17...64 => true,
                    65...128 => false,
                    else => unreachable,
                }) try self.asm_register_register_immediate(
                    .{ if (self.has_feature(.avx)) .vp_d else .p_d, .shuf },
                    dst_alias,
                    dst_alias,
                    Immediate.u(if (scalar_bits <= 64) 0b00_00_00_00 else 0b01_00_01_00),
                );
                break :result .{ .register = dst_reg };
            },
            .Float => switch (scalar_ty.float_bits(self.target.*)) {
                32 => switch (vector_len) {
                    1 => {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result src_mcv;
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        try self.gen_set_reg(dst_reg, scalar_ty, src_mcv, .{});
                        break :result .{ .register = dst_reg };
                    },
                    2...4 => {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        if (self.has_feature(.avx)) {
                            const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                .{ .v_ss, .broadcast },
                                dst_reg.to128(),
                                try src_mcv.mem(self, .dword),
                            ) else {
                                const src_reg = if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(scalar_ty, src_mcv);
                                try self.asm_register_register_register_immediate(
                                    .{ .v_ps, .shuf },
                                    dst_reg.to128(),
                                    src_reg.to128(),
                                    src_reg.to128(),
                                    Immediate.u(0),
                                );
                            }
                            break :result .{ .register = dst_reg };
                        } else {
                            const dst_mcv = if (src_mcv.is_register() and
                                self.reuse_operand(inst, ty_op.operand, 0, src_mcv))
                                src_mcv
                            else
                                try self.copy_to_register_with_inst_tracking(inst, scalar_ty, src_mcv);
                            const dst_reg = dst_mcv.get_reg().?;
                            try self.asm_register_register_immediate(
                                .{ ._ps, .shuf },
                                dst_reg.to128(),
                                dst_reg.to128(),
                                Immediate.u(0),
                            );
                            break :result dst_mcv;
                        }
                    },
                    5...8 => if (self.has_feature(.avx)) {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        if (src_mcv.is_memory()) try self.asm_register_memory(
                            .{ .v_ss, .broadcast },
                            dst_reg.to256(),
                            try src_mcv.mem(self, .dword),
                        ) else {
                            const src_reg = if (src_mcv.is_register())
                                src_mcv.get_reg().?
                            else
                                try self.copy_to_tmp_register(scalar_ty, src_mcv);
                            if (self.has_feature(.avx2)) try self.asm_register_register(
                                .{ .v_ss, .broadcast },
                                dst_reg.to256(),
                                src_reg.to128(),
                            ) else {
                                try self.asm_register_register_register_immediate(
                                    .{ .v_ps, .shuf },
                                    dst_reg.to128(),
                                    src_reg.to128(),
                                    src_reg.to128(),
                                    Immediate.u(0),
                                );
                                try self.asm_register_register_register_immediate(
                                    .{ .v_f128, .insert },
                                    dst_reg.to256(),
                                    dst_reg.to256(),
                                    dst_reg.to128(),
                                    Immediate.u(1),
                                );
                            }
                        }
                        break :result .{ .register = dst_reg };
                    },
                    else => {},
                },
                64 => switch (vector_len) {
                    1 => {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result src_mcv;
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        try self.gen_set_reg(dst_reg, scalar_ty, src_mcv, .{});
                        break :result .{ .register = dst_reg };
                    },
                    2 => {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        if (self.has_feature(.sse3)) {
                            if (src_mcv.is_memory()) try self.asm_register_memory(
                                if (self.has_feature(.avx)) .{ .v_, .movddup } else .{ ._, .movddup },
                                dst_reg.to128(),
                                try src_mcv.mem(self, .qword),
                            ) else try self.asm_register_register(
                                if (self.has_feature(.avx)) .{ .v_, .movddup } else .{ ._, .movddup },
                                dst_reg.to128(),
                                (if (src_mcv.is_register())
                                    src_mcv.get_reg().?
                                else
                                    try self.copy_to_tmp_register(scalar_ty, src_mcv)).to128(),
                            );
                            break :result .{ .register = dst_reg };
                        } else try self.asm_register_register(
                            .{ ._ps, .movlh },
                            dst_reg.to128(),
                            (if (src_mcv.is_register())
                                src_mcv.get_reg().?
                            else
                                try self.copy_to_tmp_register(scalar_ty, src_mcv)).to128(),
                        );
                    },
                    3...4 => if (self.has_feature(.avx)) {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        if (src_mcv.is_memory()) try self.asm_register_memory(
                            .{ .v_sd, .broadcast },
                            dst_reg.to256(),
                            try src_mcv.mem(self, .qword),
                        ) else {
                            const src_reg = if (src_mcv.is_register())
                                src_mcv.get_reg().?
                            else
                                try self.copy_to_tmp_register(scalar_ty, src_mcv);
                            if (self.has_feature(.avx2)) try self.asm_register_register(
                                .{ .v_sd, .broadcast },
                                dst_reg.to256(),
                                src_reg.to128(),
                            ) else {
                                try self.asm_register_register(
                                    .{ .v_, .movddup },
                                    dst_reg.to128(),
                                    src_reg.to128(),
                                );
                                try self.asm_register_register_register_immediate(
                                    .{ .v_f128, .insert },
                                    dst_reg.to256(),
                                    dst_reg.to256(),
                                    dst_reg.to128(),
                                    Immediate.u(1),
                                );
                            }
                        }
                        break :result .{ .register = dst_reg };
                    },
                    else => {},
                },
                128 => switch (vector_len) {
                    1 => {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        if (self.reuse_operand(inst, ty_op.operand, 0, src_mcv)) break :result src_mcv;
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        try self.gen_set_reg(dst_reg, scalar_ty, src_mcv, .{});
                        break :result .{ .register = dst_reg };
                    },
                    2 => if (self.has_feature(.avx)) {
                        const src_mcv = try self.resolve_inst(ty_op.operand);
                        const dst_reg = try self.register_manager.alloc_reg(inst, dst_rc);
                        if (src_mcv.is_memory()) try self.asm_register_memory(
                            .{ .v_f128, .broadcast },
                            dst_reg.to256(),
                            try src_mcv.mem(self, .xword),
                        ) else {
                            const src_reg = if (src_mcv.is_register())
                                src_mcv.get_reg().?
                            else
                                try self.copy_to_tmp_register(scalar_ty, src_mcv);
                            try self.asm_register_register_register_immediate(
                                .{ .v_f128, .insert },
                                dst_reg.to256(),
                                src_reg.to256(),
                                src_reg.to128(),
                                Immediate.u(1),
                            );
                        }
                        break :result .{ .register = dst_reg };
                    },
                    else => {},
                },
                16, 80 => {},
                else => unreachable,
            },
        }
        return self.fail("TODO implement air_splat for {}", .{vector_ty.fmt(mod)});
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_select(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const ty = self.type_of_index(inst);
    const vec_len = ty.vector_len(mod);
    const elem_ty = ty.child_type(mod);
    const elem_abi_size: u32 = @int_cast(elem_ty.abi_size(mod));
    const abi_size: u32 = @int_cast(ty.abi_size(mod));
    const pred_ty = self.type_of(pl_op.operand);

    const result = result: {
        const has_blend = self.has_feature(.sse4_1);
        const has_avx = self.has_feature(.avx);
        const need_xmm0 = has_blend and !has_avx;
        const pred_mcv = try self.resolve_inst(pl_op.operand);
        const mask_reg = mask: {
            switch (pred_mcv) {
                .register => |pred_reg| switch (pred_reg.class()) {
                    .general_purpose => {},
                    .sse => if (need_xmm0 and pred_reg.id() != comptime Register.xmm0.id()) {
                        try self.register_manager.get_known_reg(.xmm0, null);
                        try self.gen_set_reg(.xmm0, pred_ty, pred_mcv, .{});
                        break :mask .xmm0;
                    } else break :mask if (has_blend)
                        pred_reg
                    else
                        try self.copy_to_tmp_register(pred_ty, pred_mcv),
                    else => unreachable,
                },
                else => {},
            }
            const mask_reg: Register = if (need_xmm0) mask_reg: {
                try self.register_manager.get_known_reg(.xmm0, null);
                break :mask_reg .xmm0;
            } else try self.register_manager.alloc_reg(null, abi.RegisterClass.sse);
            const mask_alias = register_alias(mask_reg, abi_size);
            const mask_lock = self.register_manager.lock_reg_assume_unused(mask_reg);
            defer self.register_manager.unlock_reg(mask_lock);

            const pred_fits_in_elem = vec_len <= elem_abi_size;
            if (self.has_feature(.avx2) and abi_size <= 32) {
                if (pred_mcv.is_register()) broadcast: {
                    try self.asm_register_register(
                        .{ .v_d, .mov },
                        mask_reg.to128(),
                        pred_mcv.get_reg().?.to32(),
                    );
                    if (pred_fits_in_elem and vec_len > 1) try self.asm_register_register(
                        .{ switch (elem_abi_size) {
                            1 => .vp_b,
                            2 => .vp_w,
                            3...4 => .vp_d,
                            5...8 => .vp_q,
                            9...16 => {
                                try self.asm_register_register_register_immediate(
                                    .{ .v_f128, .insert },
                                    mask_alias,
                                    mask_alias,
                                    mask_reg.to128(),
                                    Immediate.u(1),
                                );
                                break :broadcast;
                            },
                            17...32 => break :broadcast,
                            else => unreachable,
                        }, .broadcast },
                        mask_alias,
                        mask_reg.to128(),
                    );
                } else try self.asm_register_memory(
                    .{ switch (vec_len) {
                        1...8 => .vp_b,
                        9...16 => .vp_w,
                        17...32 => .vp_d,
                        else => unreachable,
                    }, .broadcast },
                    mask_alias,
                    if (pred_mcv.is_memory()) try pred_mcv.mem(self, .byte) else .{
                        .base = .{ .reg = (try self.copy_to_tmp_register(
                            Type.usize,
                            pred_mcv.address(),
                        )).to64() },
                        .mod = .{ .rm = .{ .size = .byte } },
                    },
                );
            } else if (abi_size <= 16) broadcast: {
                try self.asm_register_register(
                    .{ if (has_avx) .v_d else ._d, .mov },
                    mask_alias,
                    (if (pred_mcv.is_register())
                        pred_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(pred_ty, pred_mcv.address())).to32(),
                );
                if (!pred_fits_in_elem or vec_len == 1) break :broadcast;
                if (elem_abi_size <= 1) {
                    if (has_avx) try self.asm_register_register_register(
                        .{ .vp_, .unpcklbw },
                        mask_alias,
                        mask_alias,
                        mask_alias,
                    ) else try self.asm_register_register(
                        .{ .p_, .unpcklbw },
                        mask_alias,
                        mask_alias,
                    );
                    if (abi_size <= 2) break :broadcast;
                }
                if (elem_abi_size <= 2) {
                    try self.asm_register_register_immediate(
                        .{ if (has_avx) .vp_w else .p_w, .shufl },
                        mask_alias,
                        mask_alias,
                        Immediate.u(0b00_00_00_00),
                    );
                    if (abi_size <= 8) break :broadcast;
                }
                try self.asm_register_register_immediate(
                    .{ if (has_avx) .vp_d else .p_d, .shuf },
                    mask_alias,
                    mask_alias,
                    Immediate.u(switch (elem_abi_size) {
                        1...2, 5...8 => 0b01_00_01_00,
                        3...4 => 0b00_00_00_00,
                        else => unreachable,
                    }),
                );
            } else return self.fail("TODO implement air_select for {}", .{ty.fmt(mod)});
            const elem_bits: u16 = @int_cast(elem_abi_size * 8);
            const mask_elem_ty = try mod.int_type(.unsigned, elem_bits);
            const mask_ty = try mod.vector_type(.{ .len = vec_len, .child = mask_elem_ty.to_intern() });
            if (!pred_fits_in_elem) if (self.has_feature(.ssse3)) {
                var mask_elems: [32]InternPool.Index = undefined;
                for (mask_elems[0..vec_len], 0..) |*elem, bit| elem.* = try mod.intern(.{ .int = .{
                    .ty = mask_elem_ty.to_intern(),
                    .storage = .{ .u64 = bit / elem_bits },
                } });
                const mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                    .ty = mask_ty.to_intern(),
                    .storage = .{ .elems = mask_elems[0..vec_len] },
                } })));
                const mask_mem: Memory = .{
                    .base = .{ .reg = try self.copy_to_tmp_register(Type.usize, mask_mcv.address()) },
                    .mod = .{ .rm = .{ .size = self.mem_size(ty) } },
                };
                if (has_avx) try self.asm_register_register_memory(
                    .{ .vp_b, .shuf },
                    mask_alias,
                    mask_alias,
                    mask_mem,
                ) else try self.asm_register_memory(
                    .{ .p_b, .shuf },
                    mask_alias,
                    mask_mem,
                );
            } else return self.fail("TODO implement air_select for {}", .{ty.fmt(mod)});
            {
                var mask_elems: [32]InternPool.Index = undefined;
                for (mask_elems[0..vec_len], 0..) |*elem, bit| elem.* = try mod.intern(.{ .int = .{
                    .ty = mask_elem_ty.to_intern(),
                    .storage = .{ .u64 = @as(u32, 1) << @int_cast(bit & (elem_bits - 1)) },
                } });
                const mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                    .ty = mask_ty.to_intern(),
                    .storage = .{ .elems = mask_elems[0..vec_len] },
                } })));
                const mask_mem: Memory = .{
                    .base = .{ .reg = try self.copy_to_tmp_register(Type.usize, mask_mcv.address()) },
                    .mod = .{ .rm = .{ .size = self.mem_size(ty) } },
                };
                if (has_avx) {
                    try self.asm_register_register_memory(
                        .{ .vp_, .@"and" },
                        mask_alias,
                        mask_alias,
                        mask_mem,
                    );
                    try self.asm_register_register_memory(
                        .{ .vp_d, .cmpeq },
                        mask_alias,
                        mask_alias,
                        mask_mem,
                    );
                } else {
                    try self.asm_register_memory(
                        .{ .p_, .@"and" },
                        mask_alias,
                        mask_mem,
                    );
                    try self.asm_register_memory(
                        .{ .p_d, .cmpeq },
                        mask_alias,
                        mask_mem,
                    );
                }
            }
            break :mask mask_reg;
        };
        const mask_alias = register_alias(mask_reg, abi_size);
        const mask_lock = self.register_manager.lock_reg_assume_unused(mask_reg);
        defer self.register_manager.unlock_reg(mask_lock);

        const lhs_mcv = try self.resolve_inst(extra.lhs);
        const lhs_lock = switch (lhs_mcv) {
            .register => |lhs_reg| self.register_manager.lock_reg_assume_unused(lhs_reg),
            else => null,
        };
        defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const rhs_mcv = try self.resolve_inst(extra.rhs);
        const rhs_lock = switch (rhs_mcv) {
            .register => |rhs_reg| self.register_manager.lock_reg(rhs_reg),
            else => null,
        };
        defer if (rhs_lock) |lock| self.register_manager.unlock_reg(lock);

        const reuse_mcv = if (has_blend) rhs_mcv else lhs_mcv;
        const dst_mcv: MCValue = if (reuse_mcv.is_register() and self.reuse_operand(
            inst,
            if (has_blend) extra.rhs else extra.lhs,
            @int_from_bool(has_blend),
            reuse_mcv,
        )) reuse_mcv else if (has_avx)
            .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
        else
            try self.copy_to_register_with_inst_tracking(inst, ty, reuse_mcv);
        const dst_reg = dst_mcv.get_reg().?;
        const dst_alias = register_alias(dst_reg, abi_size);
        const dst_lock = self.register_manager.lock_reg(dst_reg);
        defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

        const mir_tag = @as(?Mir.Inst.FixedTag, switch (ty.child_type(mod).zig_type_tag(mod)) {
            else => null,
            .Int => switch (abi_size) {
                0 => unreachable,
                1...16 => if (has_avx)
                    .{ .vp_b, .blendv }
                else if (has_blend)
                    .{ .p_b, .blendv }
                else
                    .{ .p_, undefined },
                17...32 => if (self.has_feature(.avx2))
                    .{ .vp_b, .blendv }
                else
                    null,
                else => null,
            },
            .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                else => unreachable,
                16, 80, 128 => null,
                32 => switch (vec_len) {
                    0 => unreachable,
                    1...4 => if (has_avx) .{ .v_ps, .blendv } else .{ ._ps, .blendv },
                    5...8 => if (has_avx) .{ .v_ps, .blendv } else null,
                    else => null,
                },
                64 => switch (vec_len) {
                    0 => unreachable,
                    1...2 => if (has_avx) .{ .v_pd, .blendv } else .{ ._pd, .blendv },
                    3...4 => if (has_avx) .{ .v_pd, .blendv } else null,
                    else => null,
                },
            },
        }) orelse return self.fail("TODO implement air_select for {}", .{ty.fmt(mod)});
        if (has_avx) {
            const rhs_alias = if (rhs_mcv.is_register())
                register_alias(rhs_mcv.get_reg().?, abi_size)
            else rhs: {
                try self.gen_set_reg(dst_reg, ty, rhs_mcv, .{});
                break :rhs dst_alias;
            };
            if (lhs_mcv.is_memory()) try self.asm_register_register_memory_register(
                mir_tag,
                dst_alias,
                rhs_alias,
                try lhs_mcv.mem(self, self.mem_size(ty)),
                mask_alias,
            ) else try self.asm_register_register_register_register(
                mir_tag,
                dst_alias,
                rhs_alias,
                register_alias(if (lhs_mcv.is_register())
                    lhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(ty, lhs_mcv), abi_size),
                mask_alias,
            );
        } else if (has_blend) if (lhs_mcv.is_memory()) try self.asm_register_memory_register(
            mir_tag,
            dst_alias,
            try lhs_mcv.mem(self, self.mem_size(ty)),
            mask_alias,
        ) else try self.asm_register_register_register(
            mir_tag,
            dst_alias,
            register_alias(if (lhs_mcv.is_register())
                lhs_mcv.get_reg().?
            else
                try self.copy_to_tmp_register(ty, lhs_mcv), abi_size),
            mask_alias,
        ) else {
            const mir_fixes = @as(?Mir.Inst.Fixes, switch (elem_ty.zig_type_tag(mod)) {
                else => null,
                .Int => .p_,
                .Float => switch (elem_ty.float_bits(self.target.*)) {
                    32 => ._ps,
                    64 => ._pd,
                    16, 80, 128 => null,
                    else => unreachable,
                },
            }) orelse return self.fail("TODO implement air_select for {}", .{ty.fmt(mod)});
            try self.asm_register_register(.{ mir_fixes, .@"and" }, dst_alias, mask_alias);
            if (rhs_mcv.is_memory()) try self.asm_register_memory(
                .{ mir_fixes, .andn },
                mask_alias,
                try rhs_mcv.mem(self, Memory.Size.from_size(abi_size)),
            ) else try self.asm_register_register(
                .{ mir_fixes, .andn },
                mask_alias,
                if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(ty, rhs_mcv),
            );
            try self.asm_register_register(.{ mir_fixes, .@"or" }, dst_alias, mask_alias);
        }
        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ pl_op.operand, extra.lhs, extra.rhs });
}

fn air_shuffle(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.Shuffle, ty_pl.payload).data;

    const dst_ty = self.type_of_index(inst);
    const elem_ty = dst_ty.child_type(mod);
    const elem_abi_size: u16 = @int_cast(elem_ty.abi_size(mod));
    const dst_abi_size: u32 = @int_cast(dst_ty.abi_size(mod));
    const lhs_ty = self.type_of(extra.a);
    const lhs_abi_size: u32 = @int_cast(lhs_ty.abi_size(mod));
    const rhs_ty = self.type_of(extra.b);
    const rhs_abi_size: u32 = @int_cast(rhs_ty.abi_size(mod));
    const max_abi_size = @max(dst_abi_size, lhs_abi_size, rhs_abi_size);

    const ExpectedContents = [32]?i32;
    var stack align(@max(@alignOf(ExpectedContents), @alignOf(std.heap.StackFallbackAllocator(0)))) =
        std.heap.stack_fallback(@size_of(ExpectedContents), self.gpa);
    const allocator = stack.get();

    const mask_elems = try allocator.alloc(?i32, extra.mask_len);
    defer allocator.free(mask_elems);
    for (mask_elems, 0..) |*mask_elem, elem_index| {
        const mask_elem_val =
            Value.from_interned(extra.mask).elem_value(mod, elem_index) catch unreachable;
        mask_elem.* = if (mask_elem_val.is_undef(mod))
            null
        else
            @int_cast(mask_elem_val.to_signed_int(mod));
    }

    const has_avx = self.has_feature(.avx);
    const result = @as(?MCValue, result: {
        for (mask_elems) |mask_elem| {
            if (mask_elem) |_| break;
        } else break :result try self.alloc_reg_or_mem(inst, true);

        for (mask_elems, 0..) |mask_elem, elem_index| {
            if (mask_elem orelse continue != elem_index) break;
        } else {
            const lhs_mcv = try self.resolve_inst(extra.a);
            if (self.reuse_operand(inst, extra.a, 0, lhs_mcv)) break :result lhs_mcv;
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(dst_ty, dst_mcv, lhs_mcv, .{});
            break :result dst_mcv;
        }

        for (mask_elems, 0..) |mask_elem, elem_index| {
            if (~(mask_elem orelse continue) != elem_index) break;
        } else {
            const rhs_mcv = try self.resolve_inst(extra.b);
            if (self.reuse_operand(inst, extra.b, 1, rhs_mcv)) break :result rhs_mcv;
            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(dst_ty, dst_mcv, rhs_mcv, .{});
            break :result dst_mcv;
        }

        for ([_]Mir.Inst.Tag{ .unpckl, .unpckh }) |variant| unpck: {
            if (elem_abi_size > 8) break :unpck;
            if (dst_abi_size > @as(u32, if (if (elem_abi_size >= 4)
                has_avx
            else
                self.has_feature(.avx2)) 32 else 16)) break :unpck;

            var sources = [1]?u1{null} ** 2;
            for (mask_elems, 0..) |maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index =
                    math.cast(u5, if (mask_elem < 0) ~mask_elem else mask_elem) orelse break :unpck;
                const elem_byte = (elem_index >> 1) * elem_abi_size;
                if (mask_elem_index * elem_abi_size != (elem_byte & 0b0111) | @as(u4, switch (variant) {
                    .unpckl => 0b0000,
                    .unpckh => 0b1000,
                    else => unreachable,
                }) | (elem_byte << 1 & 0b10000)) break :unpck;

                const source = @int_from_bool(mask_elem < 0);
                if (sources[elem_index & 0b00001]) |prev_source| {
                    if (source != prev_source) break :unpck;
                } else sources[elem_index & 0b00001] = source;
            }
            if (sources[0] orelse break :unpck == sources[1] orelse break :unpck) break :unpck;

            const operands = [2]Air.Inst.Ref{ extra.a, extra.b };
            const operand_tys = [2]Type{ lhs_ty, rhs_ty };
            const lhs_mcv = try self.resolve_inst(operands[sources[0].?]);
            const rhs_mcv = try self.resolve_inst(operands[sources[1].?]);

            const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                self.reuse_operand(inst, operands[sources[0].?], sources[0].?, lhs_mcv))
                lhs_mcv
            else if (has_avx and lhs_mcv.is_register())
                .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
            else
                try self.copy_to_register_with_inst_tracking(inst, operand_tys[sources[0].?], lhs_mcv);
            const dst_reg = dst_mcv.get_reg().?;
            const dst_alias = register_alias(dst_reg, max_abi_size);

            const mir_tag: Mir.Inst.FixedTag = if ((elem_abi_size >= 4 and elem_ty.is_runtime_float()) or
                (dst_abi_size > 16 and !self.has_feature(.avx2))) .{ switch (elem_abi_size) {
                4 => if (has_avx) .v_ps else ._ps,
                8 => if (has_avx) .v_pd else ._pd,
                else => unreachable,
            }, variant } else .{ if (has_avx) .vp_ else .p_, switch (variant) {
                .unpckl => switch (elem_abi_size) {
                    1 => .unpcklbw,
                    2 => .unpcklwd,
                    4 => .unpckldq,
                    8 => .unpcklqdq,
                    else => unreachable,
                },
                .unpckh => switch (elem_abi_size) {
                    1 => .unpckhbw,
                    2 => .unpckhwd,
                    4 => .unpckhdq,
                    8 => .unpckhqdq,
                    else => unreachable,
                },
                else => unreachable,
            } };
            if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory(
                mir_tag,
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
            ) else try self.asm_register_register_register(
                mir_tag,
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
            ) else if (rhs_mcv.is_memory()) try self.asm_register_memory(
                mir_tag,
                dst_alias,
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
            ) else try self.asm_register_register(
                mir_tag,
                dst_alias,
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
            );
            break :result dst_mcv;
        }

        pshufd: {
            if (elem_abi_size != 4) break :pshufd;
            if (max_abi_size > @as(u32, if (has_avx) 32 else 16)) break :pshufd;

            var control: u8 = 0b00_00_00_00;
            var sources = [1]?u1{null} ** 1;
            for (mask_elems, 0..) |maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index: u3 = @int_cast(if (mask_elem < 0) ~mask_elem else mask_elem);
                if (mask_elem_index & 0b100 != elem_index & 0b100) break :pshufd;

                const source = @int_from_bool(mask_elem < 0);
                if (sources[0]) |prev_source| {
                    if (source != prev_source) break :pshufd;
                } else sources[(elem_index & 0b010) >> 1] = source;

                const select_bit: u3 = @int_cast((elem_index & 0b011) << 1);
                const select = @as(u8, @int_cast(mask_elem_index & 0b011)) << select_bit;
                if (elem_index & 0b100 == 0)
                    control |= select
                else if (control & @as(u8, 0b11) << select_bit != select) break :pshufd;
            }

            const operands = [2]Air.Inst.Ref{ extra.a, extra.b };
            const operand_tys = [2]Type{ lhs_ty, rhs_ty };
            const src_mcv = try self.resolve_inst(operands[sources[0] orelse break :pshufd]);

            const dst_reg = if (src_mcv.is_register() and
                self.reuse_operand(inst, operands[sources[0].?], sources[0].?, src_mcv))
                src_mcv.get_reg().?
            else
                try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse);
            const dst_alias = register_alias(dst_reg, max_abi_size);

            if (src_mcv.is_memory()) try self.asm_register_memory_immediate(
                .{ if (has_avx) .vp_d else .p_d, .shuf },
                dst_alias,
                try src_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
                Immediate.u(control),
            ) else try self.asm_register_register_immediate(
                .{ if (has_avx) .vp_d else .p_d, .shuf },
                dst_alias,
                register_alias(if (src_mcv.is_register())
                    src_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[0].?], src_mcv), max_abi_size),
                Immediate.u(control),
            );
            break :result .{ .register = dst_reg };
        }

        shufps: {
            if (elem_abi_size != 4) break :shufps;
            if (max_abi_size > @as(u32, if (has_avx) 32 else 16)) break :shufps;

            var control: u8 = 0b00_00_00_00;
            var sources = [1]?u1{null} ** 2;
            for (mask_elems, 0..) |maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index: u3 = @int_cast(if (mask_elem < 0) ~mask_elem else mask_elem);
                if (mask_elem_index & 0b100 != elem_index & 0b100) break :shufps;

                const source = @int_from_bool(mask_elem < 0);
                if (sources[(elem_index & 0b010) >> 1]) |prev_source| {
                    if (source != prev_source) break :shufps;
                } else sources[(elem_index & 0b010) >> 1] = source;

                const select_bit: u3 = @int_cast((elem_index & 0b011) << 1);
                const select = @as(u8, @int_cast(mask_elem_index & 0b011)) << select_bit;
                if (elem_index & 0b100 == 0)
                    control |= select
                else if (control & @as(u8, 0b11) << select_bit != select) break :shufps;
            }
            if (sources[0] orelse break :shufps == sources[1] orelse break :shufps) break :shufps;

            const operands = [2]Air.Inst.Ref{ extra.a, extra.b };
            const operand_tys = [2]Type{ lhs_ty, rhs_ty };
            const lhs_mcv = try self.resolve_inst(operands[sources[0].?]);
            const rhs_mcv = try self.resolve_inst(operands[sources[1].?]);

            const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                self.reuse_operand(inst, operands[sources[0].?], sources[0].?, lhs_mcv))
                lhs_mcv
            else if (has_avx and lhs_mcv.is_register())
                .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
            else
                try self.copy_to_register_with_inst_tracking(inst, operand_tys[sources[0].?], lhs_mcv);
            const dst_reg = dst_mcv.get_reg().?;
            const dst_alias = register_alias(dst_reg, max_abi_size);

            if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                .{ .v_ps, .shuf },
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
                Immediate.u(control),
            ) else try self.asm_register_register_register_immediate(
                .{ .v_ps, .shuf },
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
                Immediate.u(control),
            ) else if (rhs_mcv.is_memory()) try self.asm_register_memory_immediate(
                .{ ._ps, .shuf },
                dst_alias,
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
                Immediate.u(control),
            ) else try self.asm_register_register_immediate(
                .{ ._ps, .shuf },
                dst_alias,
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
                Immediate.u(control),
            );
            break :result dst_mcv;
        }

        shufpd: {
            if (elem_abi_size != 8) break :shufpd;
            if (max_abi_size > @as(u32, if (has_avx) 32 else 16)) break :shufpd;

            var control: u4 = 0b0_0_0_0;
            var sources = [1]?u1{null} ** 2;
            for (mask_elems, 0..) |maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index: u2 = @int_cast(if (mask_elem < 0) ~mask_elem else mask_elem);
                if (mask_elem_index & 0b10 != elem_index & 0b10) break :shufpd;

                const source = @int_from_bool(mask_elem < 0);
                if (sources[elem_index & 0b01]) |prev_source| {
                    if (source != prev_source) break :shufpd;
                } else sources[elem_index & 0b01] = source;

                control |= @as(u4, @int_cast(mask_elem_index & 0b01)) << @int_cast(elem_index);
            }
            if (sources[0] orelse break :shufpd == sources[1] orelse break :shufpd) break :shufpd;

            const operands: [2]Air.Inst.Ref = .{ extra.a, extra.b };
            const operand_tys: [2]Type = .{ lhs_ty, rhs_ty };
            const lhs_mcv = try self.resolve_inst(operands[sources[0].?]);
            const rhs_mcv = try self.resolve_inst(operands[sources[1].?]);

            const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                self.reuse_operand(inst, operands[sources[0].?], sources[0].?, lhs_mcv))
                lhs_mcv
            else if (has_avx and lhs_mcv.is_register())
                .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
            else
                try self.copy_to_register_with_inst_tracking(inst, operand_tys[sources[0].?], lhs_mcv);
            const dst_reg = dst_mcv.get_reg().?;
            const dst_alias = register_alias(dst_reg, max_abi_size);

            if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                .{ .v_pd, .shuf },
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
                Immediate.u(control),
            ) else try self.asm_register_register_register_immediate(
                .{ .v_pd, .shuf },
                dst_alias,
                register_alias(lhs_mcv.get_reg() orelse dst_reg, max_abi_size),
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
                Immediate.u(control),
            ) else if (rhs_mcv.is_memory()) try self.asm_register_memory_immediate(
                .{ ._pd, .shuf },
                dst_alias,
                try rhs_mcv.mem(self, Memory.Size.from_size(max_abi_size)),
                Immediate.u(control),
            ) else try self.asm_register_register_immediate(
                .{ ._pd, .shuf },
                dst_alias,
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(operand_tys[sources[1].?], rhs_mcv), max_abi_size),
                Immediate.u(control),
            );
            break :result dst_mcv;
        }

        blend: {
            if (elem_abi_size < 2) break :blend;
            if (dst_abi_size > @as(u32, if (has_avx) 32 else 16)) break :blend;
            if (!self.has_feature(.sse4_1)) break :blend;

            var control: u8 = 0b0_0_0_0_0_0_0_0;
            for (mask_elems, 0..) |maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index =
                    math.cast(u4, if (mask_elem < 0) ~mask_elem else mask_elem) orelse break :blend;
                if (mask_elem_index != elem_index) break :blend;

                const select = @as(u8, @int_from_bool(mask_elem < 0)) << @truncate(elem_index);
                if (elem_index & 0b1000 == 0)
                    control |= select
                else if (control & @as(u8, 0b1) << @truncate(elem_index) != select) break :blend;
            }

            if (!elem_ty.is_runtime_float() and self.has_feature(.avx2)) vpblendd: {
                const expanded_control = switch (elem_abi_size) {
                    4 => control,
                    8 => @as(u8, if (control & 0b0001 != 0) 0b00_00_00_11 else 0b00_00_00_00) |
                        @as(u8, if (control & 0b0010 != 0) 0b00_00_11_00 else 0b00_00_00_00) |
                        @as(u8, if (control & 0b0100 != 0) 0b00_11_00_00 else 0b00_00_00_00) |
                        @as(u8, if (control & 0b1000 != 0) 0b11_00_00_00 else 0b00_00_00_00),
                    else => break :vpblendd,
                };

                const lhs_mcv = try self.resolve_inst(extra.a);
                const lhs_reg = if (lhs_mcv.is_register())
                    lhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(dst_ty, lhs_mcv);
                const lhs_lock = self.register_manager.lock_reg(lhs_reg);
                defer if (lhs_lock) |lock| self.register_manager.unlock_reg(lock);

                const rhs_mcv = try self.resolve_inst(extra.b);
                const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse);
                if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                    .{ .vp_d, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    register_alias(lhs_reg, dst_abi_size),
                    try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                    Immediate.u(expanded_control),
                ) else try self.asm_register_register_register_immediate(
                    .{ .vp_d, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    register_alias(lhs_reg, dst_abi_size),
                    register_alias(if (rhs_mcv.is_register())
                        rhs_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                    Immediate.u(expanded_control),
                );
                break :result .{ .register = dst_reg };
            }

            if (!elem_ty.is_runtime_float() or elem_abi_size == 2) pblendw: {
                const expanded_control = switch (elem_abi_size) {
                    2 => control,
                    4 => if (dst_abi_size <= 16 or
                        @as(u4, @int_cast(control >> 4)) == @as(u4, @truncate(control >> 0)))
                        @as(u8, if (control & 0b0001 != 0) 0b00_00_00_11 else 0b00_00_00_00) |
                            @as(u8, if (control & 0b0010 != 0) 0b00_00_11_00 else 0b00_00_00_00) |
                            @as(u8, if (control & 0b0100 != 0) 0b00_11_00_00 else 0b00_00_00_00) |
                            @as(u8, if (control & 0b1000 != 0) 0b11_00_00_00 else 0b00_00_00_00)
                    else
                        break :pblendw,
                    8 => if (dst_abi_size <= 16 or
                        @as(u2, @int_cast(control >> 2)) == @as(u2, @truncate(control >> 0)))
                        @as(u8, if (control & 0b01 != 0) 0b0000_1111 else 0b0000_0000) |
                            @as(u8, if (control & 0b10 != 0) 0b1111_0000 else 0b0000_0000)
                    else
                        break :pblendw,
                    16 => break :pblendw,
                    else => unreachable,
                };

                const lhs_mcv = try self.resolve_inst(extra.a);
                const rhs_mcv = try self.resolve_inst(extra.b);

                const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                    self.reuse_operand(inst, extra.a, 0, lhs_mcv))
                    lhs_mcv
                else if (has_avx and lhs_mcv.is_register())
                    .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
                else
                    try self.copy_to_register_with_inst_tracking(inst, dst_ty, lhs_mcv);
                const dst_reg = dst_mcv.get_reg().?;

                if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                    .{ .vp_w, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    register_alias(if (lhs_mcv.is_register())
                        lhs_mcv.get_reg().?
                    else
                        dst_reg, dst_abi_size),
                    try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                    Immediate.u(expanded_control),
                ) else try self.asm_register_register_register_immediate(
                    .{ .vp_w, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    register_alias(if (lhs_mcv.is_register())
                        lhs_mcv.get_reg().?
                    else
                        dst_reg, dst_abi_size),
                    register_alias(if (rhs_mcv.is_register())
                        rhs_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                    Immediate.u(expanded_control),
                ) else if (rhs_mcv.is_memory()) try self.asm_register_memory_immediate(
                    .{ .p_w, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                    Immediate.u(expanded_control),
                ) else try self.asm_register_register_immediate(
                    .{ .p_w, .blend },
                    register_alias(dst_reg, dst_abi_size),
                    register_alias(if (rhs_mcv.is_register())
                        rhs_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                    Immediate.u(expanded_control),
                );
                break :result .{ .register = dst_reg };
            }

            const expanded_control = switch (elem_abi_size) {
                4, 8 => control,
                16 => @as(u4, if (control & 0b01 != 0) 0b00_11 else 0b00_00) |
                    @as(u4, if (control & 0b10 != 0) 0b11_00 else 0b00_00),
                else => unreachable,
            };

            const lhs_mcv = try self.resolve_inst(extra.a);
            const rhs_mcv = try self.resolve_inst(extra.b);

            const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                self.reuse_operand(inst, extra.a, 0, lhs_mcv))
                lhs_mcv
            else if (has_avx and lhs_mcv.is_register())
                .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
            else
                try self.copy_to_register_with_inst_tracking(inst, dst_ty, lhs_mcv);
            const dst_reg = dst_mcv.get_reg().?;

            if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory_immediate(
                switch (elem_abi_size) {
                    4 => .{ .v_ps, .blend },
                    8, 16 => .{ .v_pd, .blend },
                    else => unreachable,
                },
                register_alias(dst_reg, dst_abi_size),
                register_alias(if (lhs_mcv.is_register())
                    lhs_mcv.get_reg().?
                else
                    dst_reg, dst_abi_size),
                try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                Immediate.u(expanded_control),
            ) else try self.asm_register_register_register_immediate(
                switch (elem_abi_size) {
                    4 => .{ .v_ps, .blend },
                    8, 16 => .{ .v_pd, .blend },
                    else => unreachable,
                },
                register_alias(dst_reg, dst_abi_size),
                register_alias(if (lhs_mcv.is_register())
                    lhs_mcv.get_reg().?
                else
                    dst_reg, dst_abi_size),
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                Immediate.u(expanded_control),
            ) else if (rhs_mcv.is_memory()) try self.asm_register_memory_immediate(
                switch (elem_abi_size) {
                    4 => .{ ._ps, .blend },
                    8, 16 => .{ ._pd, .blend },
                    else => unreachable,
                },
                register_alias(dst_reg, dst_abi_size),
                try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                Immediate.u(expanded_control),
            ) else try self.asm_register_register_immediate(
                switch (elem_abi_size) {
                    4 => .{ ._ps, .blend },
                    8, 16 => .{ ._pd, .blend },
                    else => unreachable,
                },
                register_alias(dst_reg, dst_abi_size),
                register_alias(if (rhs_mcv.is_register())
                    rhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                Immediate.u(expanded_control),
            );
            break :result .{ .register = dst_reg };
        }

        blendv: {
            if (dst_abi_size > @as(u32, if (if (elem_abi_size >= 4)
                has_avx
            else
                self.has_feature(.avx2)) 32 else 16)) break :blendv;

            const select_mask_elem_ty = try mod.int_type(.unsigned, elem_abi_size * 8);
            const select_mask_ty = try mod.vector_type(.{
                .len = @int_cast(mask_elems.len),
                .child = select_mask_elem_ty.to_intern(),
            });
            var select_mask_elems: [32]InternPool.Index = undefined;
            for (
                select_mask_elems[0..mask_elems.len],
                mask_elems,
                0..,
            ) |*select_mask_elem, maybe_mask_elem, elem_index| {
                const mask_elem = maybe_mask_elem orelse continue;
                const mask_elem_index =
                    math.cast(u5, if (mask_elem < 0) ~mask_elem else mask_elem) orelse break :blendv;
                if (mask_elem_index != elem_index) break :blendv;

                select_mask_elem.* = (if (mask_elem < 0)
                    try select_mask_elem_ty.max_int_scalar(mod, select_mask_elem_ty)
                else
                    try select_mask_elem_ty.min_int_scalar(mod, select_mask_elem_ty)).to_intern();
            }
            const select_mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                .ty = select_mask_ty.to_intern(),
                .storage = .{ .elems = select_mask_elems[0..mask_elems.len] },
            } })));

            if (self.has_feature(.sse4_1)) {
                const mir_tag: Mir.Inst.FixedTag = .{
                    if ((elem_abi_size >= 4 and elem_ty.is_runtime_float()) or
                        (dst_abi_size > 16 and !self.has_feature(.avx2))) switch (elem_abi_size) {
                        4 => if (has_avx) .v_ps else ._ps,
                        8 => if (has_avx) .v_pd else ._pd,
                        else => unreachable,
                    } else if (has_avx) .vp_b else .p_b,
                    .blendv,
                };

                const select_mask_reg = if (!has_avx) reg: {
                    try self.register_manager.get_known_reg(.xmm0, null);
                    try self.gen_set_reg(.xmm0, select_mask_elem_ty, select_mask_mcv, .{});
                    break :reg .xmm0;
                } else try self.copy_to_tmp_register(select_mask_ty, select_mask_mcv);
                const select_mask_alias = register_alias(select_mask_reg, dst_abi_size);
                const select_mask_lock = self.register_manager.lock_reg_assume_unused(select_mask_reg);
                defer self.register_manager.unlock_reg(select_mask_lock);

                const lhs_mcv = try self.resolve_inst(extra.a);
                const rhs_mcv = try self.resolve_inst(extra.b);

                const dst_mcv: MCValue = if (lhs_mcv.is_register() and
                    self.reuse_operand(inst, extra.a, 0, lhs_mcv))
                    lhs_mcv
                else if (has_avx and lhs_mcv.is_register())
                    .{ .register = try self.register_manager.alloc_reg(inst, abi.RegisterClass.sse) }
                else
                    try self.copy_to_register_with_inst_tracking(inst, dst_ty, lhs_mcv);
                const dst_reg = dst_mcv.get_reg().?;
                const dst_alias = register_alias(dst_reg, dst_abi_size);

                if (has_avx) if (rhs_mcv.is_memory()) try self.asm_register_register_memory_register(
                    mir_tag,
                    dst_alias,
                    if (lhs_mcv.is_register())
                        register_alias(lhs_mcv.get_reg().?, dst_abi_size)
                    else
                        dst_alias,
                    try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                    select_mask_alias,
                ) else try self.asm_register_register_register_register(
                    mir_tag,
                    dst_alias,
                    if (lhs_mcv.is_register())
                        register_alias(lhs_mcv.get_reg().?, dst_abi_size)
                    else
                        dst_alias,
                    register_alias(if (rhs_mcv.is_register())
                        rhs_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                    select_mask_alias,
                ) else if (rhs_mcv.is_memory()) try self.asm_register_memory_register(
                    mir_tag,
                    dst_alias,
                    try rhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
                    select_mask_alias,
                ) else try self.asm_register_register_register(
                    mir_tag,
                    dst_alias,
                    register_alias(if (rhs_mcv.is_register())
                        rhs_mcv.get_reg().?
                    else
                        try self.copy_to_tmp_register(dst_ty, rhs_mcv), dst_abi_size),
                    select_mask_alias,
                );
                break :result dst_mcv;
            }

            const lhs_mcv = try self.resolve_inst(extra.a);
            const rhs_mcv = try self.resolve_inst(extra.b);

            const dst_mcv: MCValue = if (rhs_mcv.is_register() and
                self.reuse_operand(inst, extra.b, 1, rhs_mcv))
                rhs_mcv
            else
                try self.copy_to_register_with_inst_tracking(inst, dst_ty, rhs_mcv);
            const dst_reg = dst_mcv.get_reg().?;
            const dst_alias = register_alias(dst_reg, dst_abi_size);

            const mask_reg = try self.copy_to_tmp_register(select_mask_ty, select_mask_mcv);
            const mask_alias = register_alias(mask_reg, dst_abi_size);
            const mask_lock = self.register_manager.lock_reg_assume_unused(mask_reg);
            defer self.register_manager.unlock_reg(mask_lock);

            const mir_fixes: Mir.Inst.Fixes = if (elem_ty.is_runtime_float())
                switch (elem_ty.float_bits(self.target.*)) {
                    16, 80, 128 => .p_,
                    32 => ._ps,
                    64 => ._pd,
                    else => unreachable,
                }
            else
                .p_;
            try self.asm_register_register(.{ mir_fixes, .@"and" }, dst_alias, mask_alias);
            if (lhs_mcv.is_memory()) try self.asm_register_memory(
                .{ mir_fixes, .andn },
                mask_alias,
                try lhs_mcv.mem(self, Memory.Size.from_size(dst_abi_size)),
            ) else try self.asm_register_register(
                .{ mir_fixes, .andn },
                mask_alias,
                if (lhs_mcv.is_register())
                    lhs_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(dst_ty, lhs_mcv),
            );
            try self.asm_register_register(.{ mir_fixes, .@"or" }, dst_alias, mask_alias);
            break :result dst_mcv;
        }

        pshufb: {
            if (max_abi_size > 16) break :pshufb;
            if (!self.has_feature(.ssse3)) break :pshufb;

            const temp_regs =
                try self.register_manager.alloc_regs(2, .{ inst, null }, abi.RegisterClass.sse);
            const temp_locks = self.register_manager.lock_regs_assume_unused(2, temp_regs);
            defer for (temp_locks) |lock| self.register_manager.unlock_reg(lock);

            const lhs_temp_alias = register_alias(temp_regs[0], max_abi_size);
            try self.gen_set_reg(temp_regs[0], lhs_ty, .{ .air_ref = extra.a }, .{});

            const rhs_temp_alias = register_alias(temp_regs[1], max_abi_size);
            try self.gen_set_reg(temp_regs[1], rhs_ty, .{ .air_ref = extra.b }, .{});

            var lhs_mask_elems: [16]InternPool.Index = undefined;
            for (lhs_mask_elems[0..max_abi_size], 0..) |*lhs_mask_elem, byte_index| {
                const elem_index = byte_index / elem_abi_size;
                lhs_mask_elem.* = try mod.intern(.{ .int = .{
                    .ty = .u8_type,
                    .storage = .{ .u64 = if (elem_index >= mask_elems.len) 0b1_00_00000 else elem: {
                        const mask_elem = mask_elems[elem_index] orelse break :elem 0b1_00_00000;
                        if (mask_elem < 0) break :elem 0b1_00_00000;
                        const mask_elem_index: u31 = @int_cast(mask_elem);
                        const byte_off: u32 = @int_cast(byte_index % elem_abi_size);
                        break :elem @int_cast(mask_elem_index * elem_abi_size + byte_off);
                    } },
                } });
            }
            const lhs_mask_ty = try mod.vector_type(.{ .len = max_abi_size, .child = .u8_type });
            const lhs_mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                .ty = lhs_mask_ty.to_intern(),
                .storage = .{ .elems = lhs_mask_elems[0..max_abi_size] },
            } })));
            const lhs_mask_mem: Memory = .{
                .base = .{ .reg = try self.copy_to_tmp_register(Type.usize, lhs_mask_mcv.address()) },
                .mod = .{ .rm = .{ .size = Memory.Size.from_size(@max(max_abi_size, 16)) } },
            };
            if (has_avx) try self.asm_register_register_memory(
                .{ .vp_b, .shuf },
                lhs_temp_alias,
                lhs_temp_alias,
                lhs_mask_mem,
            ) else try self.asm_register_memory(
                .{ .p_b, .shuf },
                lhs_temp_alias,
                lhs_mask_mem,
            );

            var rhs_mask_elems: [16]InternPool.Index = undefined;
            for (rhs_mask_elems[0..max_abi_size], 0..) |*rhs_mask_elem, byte_index| {
                const elem_index = byte_index / elem_abi_size;
                rhs_mask_elem.* = try mod.intern(.{ .int = .{
                    .ty = .u8_type,
                    .storage = .{ .u64 = if (elem_index >= mask_elems.len) 0b1_00_00000 else elem: {
                        const mask_elem = mask_elems[elem_index] orelse break :elem 0b1_00_00000;
                        if (mask_elem >= 0) break :elem 0b1_00_00000;
                        const mask_elem_index: u31 = @int_cast(~mask_elem);
                        const byte_off: u32 = @int_cast(byte_index % elem_abi_size);
                        break :elem @int_cast(mask_elem_index * elem_abi_size + byte_off);
                    } },
                } });
            }
            const rhs_mask_ty = try mod.vector_type(.{ .len = max_abi_size, .child = .u8_type });
            const rhs_mask_mcv = try self.gen_typed_value(Value.from_interned(try mod.intern(.{ .aggregate = .{
                .ty = rhs_mask_ty.to_intern(),
                .storage = .{ .elems = rhs_mask_elems[0..max_abi_size] },
            } })));
            const rhs_mask_mem: Memory = .{
                .base = .{ .reg = try self.copy_to_tmp_register(Type.usize, rhs_mask_mcv.address()) },
                .mod = .{ .rm = .{ .size = Memory.Size.from_size(@max(max_abi_size, 16)) } },
            };
            if (has_avx) try self.asm_register_register_memory(
                .{ .vp_b, .shuf },
                rhs_temp_alias,
                rhs_temp_alias,
                rhs_mask_mem,
            ) else try self.asm_register_memory(
                .{ .p_b, .shuf },
                rhs_temp_alias,
                rhs_mask_mem,
            );

            if (has_avx) try self.asm_register_register_register(
                .{ switch (elem_ty.zig_type_tag(mod)) {
                    else => break :result null,
                    .Int => .vp_,
                    .Float => switch (elem_ty.float_bits(self.target.*)) {
                        32 => .v_ps,
                        64 => .v_pd,
                        16, 80, 128 => break :result null,
                        else => unreachable,
                    },
                }, .@"or" },
                lhs_temp_alias,
                lhs_temp_alias,
                rhs_temp_alias,
            ) else try self.asm_register_register(
                .{ switch (elem_ty.zig_type_tag(mod)) {
                    else => break :result null,
                    .Int => .p_,
                    .Float => switch (elem_ty.float_bits(self.target.*)) {
                        32 => ._ps,
                        64 => ._pd,
                        16, 80, 128 => break :result null,
                        else => unreachable,
                    },
                }, .@"or" },
                lhs_temp_alias,
                rhs_temp_alias,
            );
            break :result .{ .register = temp_regs[0] };
        }

        break :result null;
    }) orelse return self.fail("TODO implement air_shuffle from {} and {} to {} with {}", .{
        lhs_ty.fmt(mod),                                    rhs_ty.fmt(mod), dst_ty.fmt(mod),
        Value.from_interned(extra.mask).fmt_value(mod, null),
    });
    return self.finish_air(inst, result, .{ extra.a, extra.b, .none });
}

fn air_reduce(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const reduce = self.air.instructions.items(.data)[@int_from_enum(inst)].reduce;

    const result: MCValue = result: {
        const operand_ty = self.type_of(reduce.operand);
        if (operand_ty.is_vector(mod) and operand_ty.child_type(mod).to_intern() == .bool_type) {
            try self.spill_eflags_if_occupied();

            const operand_mcv = try self.resolve_inst(reduce.operand);
            const mask_len = (math.cast(u6, operand_ty.vector_len(mod)) orelse
                return self.fail("TODO implement air_reduce for {}", .{operand_ty.fmt(mod)}));
            const mask = (@as(u64, 1) << mask_len) - 1;
            const abi_size: u32 = @int_cast(operand_ty.abi_size(mod));
            switch (reduce.operation) {
                .Or => {
                    if (operand_mcv.is_memory()) try self.asm_memory_immediate(
                        .{ ._, .@"test" },
                        try operand_mcv.mem(self, Memory.Size.from_size(abi_size)),
                        Immediate.u(mask),
                    ) else {
                        const operand_reg = register_alias(if (operand_mcv.is_register())
                            operand_mcv.get_reg().?
                        else
                            try self.copy_to_tmp_register(operand_ty, operand_mcv), abi_size);
                        if (mask_len < abi_size * 8) try self.asm_register_immediate(
                            .{ ._, .@"test" },
                            operand_reg,
                            Immediate.u(mask),
                        ) else try self.asm_register_register(
                            .{ ._, .@"test" },
                            operand_reg,
                            operand_reg,
                        );
                    }
                    break :result .{ .eflags = .nz };
                },
                .And => {
                    const tmp_reg = try self.copy_to_tmp_register(operand_ty, operand_mcv);
                    const tmp_lock = self.register_manager.lock_reg_assume_unused(tmp_reg);
                    defer self.register_manager.unlock_reg(tmp_lock);

                    try self.asm_register(.{ ._, .not }, tmp_reg);
                    if (mask_len < abi_size * 8)
                        try self.asm_register_immediate(.{ ._, .@"test" }, tmp_reg, Immediate.u(mask))
                    else
                        try self.asm_register_register(.{ ._, .@"test" }, tmp_reg, tmp_reg);
                    break :result .{ .eflags = .z };
                },
                else => return self.fail("TODO implement air_reduce for {}", .{operand_ty.fmt(mod)}),
            }
        }
        return self.fail("TODO implement air_reduce for {}", .{operand_ty.fmt(mod)});
    };
    return self.finish_air(inst, result, .{ reduce.operand, .none, .none });
}

fn air_aggregate_init(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const result_ty = self.type_of_index(inst);
    const len: usize = @int_cast(result_ty.array_len(mod));
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const elements: []const Air.Inst.Ref = @ptr_cast(self.air.extra[ty_pl.payload..][0..len]);
    const result: MCValue = result: {
        switch (result_ty.zig_type_tag(mod)) {
            .Struct => {
                const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(result_ty, mod));
                if (result_ty.container_layout(mod) == .@"packed") {
                    const struct_obj = mod.type_to_struct(result_ty).?;
                    try self.gen_inline_memset(
                        .{ .lea_frame = .{ .index = frame_index } },
                        .{ .immediate = 0 },
                        .{ .immediate = result_ty.abi_size(mod) },
                        .{},
                    );
                    for (elements, 0..) |elem, elem_i_usize| {
                        const elem_i: u32 = @int_cast(elem_i_usize);
                        if ((try result_ty.struct_field_value_comptime(mod, elem_i)) != null) continue;

                        const elem_ty = result_ty.struct_field_type(elem_i, mod);
                        const elem_bit_size: u32 = @int_cast(elem_ty.bit_size(mod));
                        if (elem_bit_size > 64) {
                            return self.fail(
                                "TODO air_aggregate_init implement packed structs with large fields",
                                .{},
                            );
                        }
                        const elem_abi_size: u32 = @int_cast(elem_ty.abi_size(mod));
                        const elem_abi_bits = elem_abi_size * 8;
                        const elem_off = mod.struct_packed_field_bit_offset(struct_obj, elem_i);
                        const elem_byte_off: i32 = @int_cast(elem_off / elem_abi_bits * elem_abi_size);
                        const elem_bit_off = elem_off % elem_abi_bits;
                        const elem_mcv = try self.resolve_inst(elem);
                        const mat_elem_mcv = switch (elem_mcv) {
                            .load_tlv => |sym_index| MCValue{ .lea_tlv = sym_index },
                            else => elem_mcv,
                        };
                        const elem_lock = switch (mat_elem_mcv) {
                            .register => |reg| self.register_manager.lock_reg(reg),
                            .immediate => |imm| lock: {
                                if (imm == 0) continue;
                                break :lock null;
                            },
                            else => null,
                        };
                        defer if (elem_lock) |lock| self.register_manager.unlock_reg(lock);

                        const elem_extra_bits = self.reg_extra_bits(elem_ty);
                        {
                            const temp_reg = try self.copy_to_tmp_register(elem_ty, mat_elem_mcv);
                            const temp_alias = register_alias(temp_reg, elem_abi_size);
                            const temp_lock = self.register_manager.lock_reg_assume_unused(temp_reg);
                            defer self.register_manager.unlock_reg(temp_lock);

                            if (elem_bit_off < elem_extra_bits) {
                                try self.truncate_register(elem_ty, temp_alias);
                            }
                            if (elem_bit_off > 0) try self.gen_shift_bin_op_mir(
                                .{ ._l, .sh },
                                elem_ty,
                                .{ .register = temp_alias },
                                Type.u8,
                                .{ .immediate = elem_bit_off },
                            );
                            try self.gen_bin_op_mir(
                                .{ ._, .@"or" },
                                elem_ty,
                                .{ .load_frame = .{ .index = frame_index, .off = elem_byte_off } },
                                .{ .register = temp_alias },
                            );
                        }
                        if (elem_bit_off > elem_extra_bits) {
                            const temp_reg = try self.copy_to_tmp_register(elem_ty, mat_elem_mcv);
                            const temp_alias = register_alias(temp_reg, elem_abi_size);
                            const temp_lock = self.register_manager.lock_reg_assume_unused(temp_reg);
                            defer self.register_manager.unlock_reg(temp_lock);

                            if (elem_extra_bits > 0) {
                                try self.truncate_register(elem_ty, temp_alias);
                            }
                            try self.gen_shift_bin_op_mir(
                                .{ ._r, .sh },
                                elem_ty,
                                .{ .register = temp_reg },
                                Type.u8,
                                .{ .immediate = elem_abi_bits - elem_bit_off },
                            );
                            try self.gen_bin_op_mir(
                                .{ ._, .@"or" },
                                elem_ty,
                                .{ .load_frame = .{
                                    .index = frame_index,
                                    .off = elem_byte_off + @as(i32, @int_cast(elem_abi_size)),
                                } },
                                .{ .register = temp_alias },
                            );
                        }
                    }
                } else for (elements, 0..) |elem, elem_i| {
                    if ((try result_ty.struct_field_value_comptime(mod, elem_i)) != null) continue;

                    const elem_ty = result_ty.struct_field_type(elem_i, mod);
                    const elem_off: i32 = @int_cast(result_ty.struct_field_offset(elem_i, mod));
                    const elem_mcv = try self.resolve_inst(elem);
                    const mat_elem_mcv = switch (elem_mcv) {
                        .load_tlv => |sym_index| MCValue{ .lea_tlv = sym_index },
                        else => elem_mcv,
                    };
                    try self.gen_set_mem(.{ .frame = frame_index }, elem_off, elem_ty, mat_elem_mcv, .{});
                }
                break :result .{ .load_frame = .{ .index = frame_index } };
            },
            .Array, .Vector => {
                const elem_ty = result_ty.child_type(mod);
                if (result_ty.is_vector(mod) and elem_ty.to_intern() == .bool_type) {
                    const result_size: u32 = @int_cast(result_ty.abi_size(mod));
                    const dst_reg = try self.register_manager.alloc_reg(inst, abi.RegisterClass.gp);
                    try self.asm_register_register(
                        .{ ._, .xor },
                        register_alias(dst_reg, @min(result_size, 4)),
                        register_alias(dst_reg, @min(result_size, 4)),
                    );

                    for (elements, 0..) |elem, elem_i| {
                        const elem_reg = try self.copy_to_tmp_register(elem_ty, .{ .air_ref = elem });
                        const elem_lock = self.register_manager.lock_reg_assume_unused(elem_reg);
                        defer self.register_manager.unlock_reg(elem_lock);

                        try self.asm_register_immediate(
                            .{ ._, .@"and" },
                            register_alias(elem_reg, @min(result_size, 4)),
                            Immediate.u(1),
                        );
                        if (elem_i > 0) try self.asm_register_immediate(
                            .{ ._l, .sh },
                            register_alias(elem_reg, result_size),
                            Immediate.u(@int_cast(elem_i)),
                        );
                        try self.asm_register_register(
                            .{ ._, .@"or" },
                            register_alias(dst_reg, result_size),
                            register_alias(elem_reg, result_size),
                        );
                    }
                    break :result .{ .register = dst_reg };
                } else {
                    const frame_index = try self.alloc_frame_index(FrameAlloc.init_spill(result_ty, mod));
                    const elem_size: u32 = @int_cast(elem_ty.abi_size(mod));

                    for (elements, 0..) |elem, elem_i| {
                        const elem_mcv = try self.resolve_inst(elem);
                        const mat_elem_mcv = switch (elem_mcv) {
                            .load_tlv => |sym_index| MCValue{ .lea_tlv = sym_index },
                            else => elem_mcv,
                        };
                        const elem_off: i32 = @int_cast(elem_size * elem_i);
                        try self.gen_set_mem(
                            .{ .frame = frame_index },
                            elem_off,
                            elem_ty,
                            mat_elem_mcv,
                            .{},
                        );
                    }
                    if (result_ty.sentinel(mod)) |sentinel| try self.gen_set_mem(
                        .{ .frame = frame_index },
                        @int_cast(elem_size * elements.len),
                        elem_ty,
                        try self.gen_typed_value(sentinel),
                        .{},
                    );
                    break :result .{ .load_frame = .{ .index = frame_index } };
                }
            },
            else => unreachable,
        }
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
    const mod = self.bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    const ty_pl = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
    const extra = self.air.extra_data(Air.UnionInit, ty_pl.payload).data;
    const result: MCValue = result: {
        const union_ty = self.type_of_index(inst);
        const layout = union_ty.union_get_layout(mod);

        const src_ty = self.type_of(extra.init);
        const src_mcv = try self.resolve_inst(extra.init);
        if (layout.tag_size == 0) {
            if (layout.abi_size <= src_ty.abi_size(mod) and
                self.reuse_operand(inst, extra.init, 0, src_mcv)) break :result src_mcv;

            const dst_mcv = try self.alloc_reg_or_mem(inst, true);
            try self.gen_copy(src_ty, dst_mcv, src_mcv, .{});
            break :result dst_mcv;
        }

        const dst_mcv = try self.alloc_reg_or_mem(inst, false);

        const union_obj = mod.type_to_union(union_ty).?;
        const field_name = union_obj.load_tag_type(ip).names.get(ip)[extra.field_index];
        const tag_ty = Type.from_interned(union_obj.enum_tag_ty);
        const field_index = tag_ty.enum_field_index(field_name, mod).?;
        const tag_val = try mod.enum_value_field_index(tag_ty, field_index);
        const tag_int_val = try tag_val.int_from_enum(tag_ty, mod);
        const tag_int = tag_int_val.to_unsigned_int(mod);
        const tag_off: i32 = if (layout.tag_align.compare(.lt, layout.payload_align))
            @int_cast(layout.payload_size)
        else
            0;
        try self.gen_copy(
            tag_ty,
            dst_mcv.address().offset(tag_off).deref(),
            .{ .immediate = tag_int },
            .{},
        );

        const pl_off: i32 = if (layout.tag_align.compare(.lt, layout.payload_align))
            0
        else
            @int_cast(layout.tag_size);
        try self.gen_copy(src_ty, dst_mcv.address().offset(pl_off).deref(), src_mcv, .{});

        break :result dst_mcv;
    };
    return self.finish_air(inst, result, .{ extra.init, .none, .none });
}

fn air_prefetch(self: *Self, inst: Air.Inst.Index) !void {
    const prefetch = self.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;
    return self.finish_air(inst, .unreach, .{ prefetch.ptr, .none, .none });
}

fn air_mul_add(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const pl_op = self.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
    const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
    const ty = self.type_of_index(inst);

    const ops = [3]Air.Inst.Ref{ extra.lhs, extra.rhs, pl_op.operand };
    const result = result: {
        if (switch (ty.scalar_type(mod).float_bits(self.target.*)) {
            16, 80, 128 => true,
            32, 64 => !self.has_feature(.fma),
            else => unreachable,
        }) {
            if (ty.zig_type_tag(mod) != .Float) return self.fail("TODO implement air_mul_add for {}", .{
                ty.fmt(mod),
            });

            var callee_buf: ["__fma?".len]u8 = undefined;
            break :result try self.gen_call(.{ .lib = .{
                .return_type = ty.to_intern(),
                .param_types = &.{ ty.to_intern(), ty.to_intern(), ty.to_intern() },
                .callee = std.fmt.buf_print(&callee_buf, "{s}fma{s}", .{
                    float_libc_abi_prefix(ty),
                    float_libc_abi_suffix(ty),
                }) catch unreachable,
            } }, &.{ ty, ty, ty }, &.{
                .{ .air_ref = extra.lhs }, .{ .air_ref = extra.rhs }, .{ .air_ref = pl_op.operand },
            });
        }

        var mcvs: [3]MCValue = undefined;
        var locks = [1]?RegisterManager.RegisterLock{null} ** 3;
        defer for (locks) |reg_lock| if (reg_lock) |lock| self.register_manager.unlock_reg(lock);
        var order = [1]u2{0} ** 3;
        var unused = std.StaticBitSet(3).init_full();
        for (ops, &mcvs, &locks, 0..) |op, *mcv, *lock, op_i| {
            const op_index: u2 = @int_cast(op_i);
            mcv.* = try self.resolve_inst(op);
            if (unused.is_set(0) and mcv.is_register() and self.reuse_operand(inst, op, op_index, mcv.*)) {
                order[op_index] = 1;
                unused.unset(0);
            } else if (unused.is_set(2) and mcv.is_memory()) {
                order[op_index] = 3;
                unused.unset(2);
            }
            switch (mcv.*) {
                .register => |reg| lock.* = self.register_manager.lock_reg(reg),
                else => {},
            }
        }
        for (&order, &mcvs, &locks) |*mop_index, *mcv, *lock| {
            if (mop_index.* != 0) continue;
            mop_index.* = 1 + @as(u2, @int_cast(unused.toggle_first_set().?));
            if (mop_index.* > 1 and mcv.is_register()) continue;
            const reg = try self.copy_to_tmp_register(ty, mcv.*);
            mcv.* = .{ .register = reg };
            if (lock.*) |old_lock| self.register_manager.unlock_reg(old_lock);
            lock.* = self.register_manager.lock_reg_assume_unused(reg);
        }

        const mir_tag = @as(?Mir.Inst.FixedTag, if (mem.eql(u2, &order, &.{ 1, 3, 2 }) or
            mem.eql(u2, &order, &.{ 3, 1, 2 }))
            switch (ty.zig_type_tag(mod)) {
                .Float => switch (ty.float_bits(self.target.*)) {
                    32 => .{ .v_ss, .fmadd132 },
                    64 => .{ .v_sd, .fmadd132 },
                    16, 80, 128 => null,
                    else => unreachable,
                },
                .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                    .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                        32 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_ss, .fmadd132 },
                            2...8 => .{ .v_ps, .fmadd132 },
                            else => null,
                        },
                        64 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_sd, .fmadd132 },
                            2...4 => .{ .v_pd, .fmadd132 },
                            else => null,
                        },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    else => unreachable,
                },
                else => unreachable,
            }
        else if (mem.eql(u2, &order, &.{ 2, 1, 3 }) or mem.eql(u2, &order, &.{ 1, 2, 3 }))
            switch (ty.zig_type_tag(mod)) {
                .Float => switch (ty.float_bits(self.target.*)) {
                    32 => .{ .v_ss, .fmadd213 },
                    64 => .{ .v_sd, .fmadd213 },
                    16, 80, 128 => null,
                    else => unreachable,
                },
                .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                    .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                        32 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_ss, .fmadd213 },
                            2...8 => .{ .v_ps, .fmadd213 },
                            else => null,
                        },
                        64 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_sd, .fmadd213 },
                            2...4 => .{ .v_pd, .fmadd213 },
                            else => null,
                        },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    else => unreachable,
                },
                else => unreachable,
            }
        else if (mem.eql(u2, &order, &.{ 2, 3, 1 }) or mem.eql(u2, &order, &.{ 3, 2, 1 }))
            switch (ty.zig_type_tag(mod)) {
                .Float => switch (ty.float_bits(self.target.*)) {
                    32 => .{ .v_ss, .fmadd231 },
                    64 => .{ .v_sd, .fmadd231 },
                    16, 80, 128 => null,
                    else => unreachable,
                },
                .Vector => switch (ty.child_type(mod).zig_type_tag(mod)) {
                    .Float => switch (ty.child_type(mod).float_bits(self.target.*)) {
                        32 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_ss, .fmadd231 },
                            2...8 => .{ .v_ps, .fmadd231 },
                            else => null,
                        },
                        64 => switch (ty.vector_len(mod)) {
                            1 => .{ .v_sd, .fmadd231 },
                            2...4 => .{ .v_pd, .fmadd231 },
                            else => null,
                        },
                        16, 80, 128 => null,
                        else => unreachable,
                    },
                    else => unreachable,
                },
                else => unreachable,
            }
        else
            unreachable) orelse return self.fail("TODO implement air_mul_add for {}", .{ty.fmt(mod)});

        var mops: [3]MCValue = undefined;
        for (order, mcvs) |mop_index, mcv| mops[mop_index - 1] = mcv;

        const abi_size: u32 = @int_cast(ty.abi_size(mod));
        const mop1_reg = register_alias(mops[0].get_reg().?, abi_size);
        const mop2_reg = register_alias(mops[1].get_reg().?, abi_size);
        if (mops[2].is_register()) try self.asm_register_register_register(
            mir_tag,
            mop1_reg,
            mop2_reg,
            register_alias(mops[2].get_reg().?, abi_size),
        ) else try self.asm_register_register_memory(
            mir_tag,
            mop1_reg,
            mop2_reg,
            try mops[2].mem(self, Memory.Size.from_size(abi_size)),
        );
        break :result mops[0];
    };
    return self.finish_air(inst, result, ops);
}

fn air_va_start(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const va_list_ty = self.air.instructions.items(.data)[@int_from_enum(inst)].ty;
    const ptr_anyopaque_ty = try mod.single_mut_ptr_type(Type.anyopaque);

    const result: MCValue = switch (abi.resolve_calling_convention(
        self.fn_type.fn_calling_convention(mod),
        self.target.*,
    )) {
        .SysV => result: {
            const info = self.va_info.sysv;
            const dst_fi = try self.alloc_frame_index(FrameAlloc.init_spill(va_list_ty, mod));
            var field_off: u31 = 0;
            // gp_offset: c_uint,
            try self.gen_set_mem(
                .{ .frame = dst_fi },
                field_off,
                Type.c_uint,
                .{ .immediate = info.gp_count * 8 },
                .{},
            );
            field_off += @int_cast(Type.c_uint.abi_size(mod));
            // fp_offset: c_uint,
            try self.gen_set_mem(
                .{ .frame = dst_fi },
                field_off,
                Type.c_uint,
                .{ .immediate = abi.SysV.c_abi_int_param_regs.len * 8 + info.fp_count * 16 },
                .{},
            );
            field_off += @int_cast(Type.c_uint.abi_size(mod));
            // overflow_arg_area: *anyopaque,
            try self.gen_set_mem(
                .{ .frame = dst_fi },
                field_off,
                ptr_anyopaque_ty,
                .{ .lea_frame = info.overflow_arg_area },
                .{},
            );
            field_off += @int_cast(ptr_anyopaque_ty.abi_size(mod));
            // reg_save_area: *anyopaque,
            try self.gen_set_mem(
                .{ .frame = dst_fi },
                field_off,
                ptr_anyopaque_ty,
                .{ .lea_frame = info.reg_save_area },
                .{},
            );
            field_off += @int_cast(ptr_anyopaque_ty.abi_size(mod));
            break :result .{ .load_frame = .{ .index = dst_fi } };
        },
        .Win64 => return self.fail("TODO implement c_va_start for Win64", .{}),
        else => unreachable,
    };
    return self.finish_air(inst, result, .{ .none, .none, .none });
}

fn air_va_arg(self: *Self, inst: Air.Inst.Index) !void {
    const mod = self.bin_file.comp.module.?;
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const ty = self.type_of_index(inst);
    const promote_ty = self.promote_var_arg(ty);
    const ptr_anyopaque_ty = try mod.single_mut_ptr_type(Type.anyopaque);
    const unused = self.liveness.is_unused(inst);

    const result: MCValue = switch (abi.resolve_calling_convention(
        self.fn_type.fn_calling_convention(mod),
        self.target.*,
    )) {
        .SysV => result: {
            try self.spill_eflags_if_occupied();

            const tmp_regs =
                try self.register_manager.alloc_regs(2, .{null} ** 2, abi.RegisterClass.gp);
            const offset_reg = tmp_regs[0].to32();
            const addr_reg = tmp_regs[1].to64();
            const tmp_locks = self.register_manager.lock_regs_assume_unused(2, tmp_regs);
            defer for (tmp_locks) |lock| self.register_manager.unlock_reg(lock);

            const promote_mcv = try self.alloc_temp_reg_or_mem(promote_ty, true);
            const promote_lock = switch (promote_mcv) {
                .register => |reg| self.register_manager.lock_reg_assume_unused(reg),
                else => null,
            };
            defer if (promote_lock) |lock| self.register_manager.unlock_reg(lock);

            const ptr_arg_list_reg =
                try self.copy_to_tmp_register(self.type_of(ty_op.operand), .{ .air_ref = ty_op.operand });
            const ptr_arg_list_lock = self.register_manager.lock_reg_assume_unused(ptr_arg_list_reg);
            defer self.register_manager.unlock_reg(ptr_arg_list_lock);

            const gp_offset: MCValue = .{ .indirect = .{ .reg = ptr_arg_list_reg, .off = 0 } };
            const fp_offset: MCValue = .{ .indirect = .{ .reg = ptr_arg_list_reg, .off = 4 } };
            const overflow_arg_area: MCValue = .{ .indirect = .{ .reg = ptr_arg_list_reg, .off = 8 } };
            const reg_save_area: MCValue = .{ .indirect = .{ .reg = ptr_arg_list_reg, .off = 16 } };

            const classes = mem.slice_to(&abi.classify_system_v(promote_ty, mod, self.target.*, .arg), .none);
            switch (classes[0]) {
                .integer => {
                    assert(classes.len == 1);

                    try self.gen_set_reg(offset_reg, Type.c_uint, gp_offset, .{});
                    try self.asm_register_immediate(.{ ._, .cmp }, offset_reg, Immediate.u(
                        abi.SysV.c_abi_int_param_regs.len * 8,
                    ));
                    const mem_reloc = try self.asm_jcc_reloc(.ae, undefined);

                    try self.gen_set_reg(addr_reg, ptr_anyopaque_ty, reg_save_area, .{});
                    if (!unused) try self.asm_register_memory(.{ ._, .lea }, addr_reg, .{
                        .base = .{ .reg = addr_reg },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .index = offset_reg.to64(),
                        } },
                    });
                    try self.asm_register_memory(.{ ._, .lea }, offset_reg, .{
                        .base = .{ .reg = offset_reg.to64() },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .disp = 8,
                        } },
                    });
                    try self.gen_copy(Type.c_uint, gp_offset, .{ .register = offset_reg }, .{});
                    const done_reloc = try self.asm_jmp_reloc(undefined);

                    self.perform_reloc(mem_reloc);
                    try self.gen_set_reg(addr_reg, ptr_anyopaque_ty, overflow_arg_area, .{});
                    try self.asm_register_memory(.{ ._, .lea }, offset_reg.to64(), .{
                        .base = .{ .reg = addr_reg },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .disp = @int_cast(@max(promote_ty.abi_size(mod), 8)),
                        } },
                    });
                    try self.gen_copy(
                        ptr_anyopaque_ty,
                        overflow_arg_area,
                        .{ .register = offset_reg.to64() },
                        .{},
                    );

                    self.perform_reloc(done_reloc);
                    if (!unused) try self.gen_copy(promote_ty, promote_mcv, .{
                        .indirect = .{ .reg = addr_reg },
                    }, .{});
                },
                .sse => {
                    assert(classes.len == 1);

                    try self.gen_set_reg(offset_reg, Type.c_uint, fp_offset, .{});
                    try self.asm_register_immediate(.{ ._, .cmp }, offset_reg, Immediate.u(
                        abi.SysV.c_abi_int_param_regs.len * 8 + abi.SysV.c_abi_sse_param_regs.len * 16,
                    ));
                    const mem_reloc = try self.asm_jcc_reloc(.ae, undefined);

                    try self.gen_set_reg(addr_reg, ptr_anyopaque_ty, reg_save_area, .{});
                    if (!unused) try self.asm_register_memory(.{ ._, .lea }, addr_reg, .{
                        .base = .{ .reg = addr_reg },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .index = offset_reg.to64(),
                        } },
                    });
                    try self.asm_register_memory(.{ ._, .lea }, offset_reg, .{
                        .base = .{ .reg = offset_reg.to64() },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .disp = 16,
                        } },
                    });
                    try self.gen_copy(Type.c_uint, fp_offset, .{ .register = offset_reg }, .{});
                    const done_reloc = try self.asm_jmp_reloc(undefined);

                    self.perform_reloc(mem_reloc);
                    try self.gen_set_reg(addr_reg, ptr_anyopaque_ty, overflow_arg_area, .{});
                    try self.asm_register_memory(.{ ._, .lea }, offset_reg.to64(), .{
                        .base = .{ .reg = addr_reg },
                        .mod = .{ .rm = .{
                            .size = .qword,
                            .disp = @int_cast(@max(promote_ty.abi_size(mod), 8)),
                        } },
                    });
                    try self.gen_copy(
                        ptr_anyopaque_ty,
                        overflow_arg_area,
                        .{ .register = offset_reg.to64() },
                        .{},
                    );

                    self.perform_reloc(done_reloc);
                    if (!unused) try self.gen_copy(promote_ty, promote_mcv, .{
                        .indirect = .{ .reg = addr_reg },
                    }, .{});
                },
                .memory => {
                    assert(classes.len == 1);
                    unreachable;
                },
                else => return self.fail("TODO implement c_va_arg for {} on SysV", .{
                    promote_ty.fmt(mod),
                }),
            }

            if (unused) break :result .unreach;
            if (ty.to_intern() == promote_ty.to_intern()) break :result promote_mcv;

            if (!promote_ty.is_runtime_float()) {
                const dst_mcv = try self.alloc_reg_or_mem(inst, true);
                try self.gen_copy(ty, dst_mcv, promote_mcv, .{});
                break :result dst_mcv;
            }

            assert(ty.to_intern() == .f32_type and promote_ty.to_intern() == .f64_type);
            const dst_mcv = if (promote_mcv.is_register())
                promote_mcv
            else
                try self.copy_to_register_with_inst_tracking(inst, ty, promote_mcv);
            const dst_reg = dst_mcv.get_reg().?.to128();
            const dst_lock = self.register_manager.lock_reg(dst_reg);
            defer if (dst_lock) |lock| self.register_manager.unlock_reg(lock);

            if (self.has_feature(.avx)) if (promote_mcv.is_memory()) try self.asm_register_register_memory(
                .{ .v_ss, .cvtsd2 },
                dst_reg,
                dst_reg,
                try promote_mcv.mem(self, .qword),
            ) else try self.asm_register_register_register(
                .{ .v_ss, .cvtsd2 },
                dst_reg,
                dst_reg,
                (if (promote_mcv.is_register())
                    promote_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(promote_ty, promote_mcv)).to128(),
            ) else if (promote_mcv.is_memory()) try self.asm_register_memory(
                .{ ._ss, .cvtsd2 },
                dst_reg,
                try promote_mcv.mem(self, .qword),
            ) else try self.asm_register_register(
                .{ ._ss, .cvtsd2 },
                dst_reg,
                (if (promote_mcv.is_register())
                    promote_mcv.get_reg().?
                else
                    try self.copy_to_tmp_register(promote_ty, promote_mcv)).to128(),
            );
            break :result promote_mcv;
        },
        .Win64 => return self.fail("TODO implement c_va_arg for Win64", .{}),
        else => unreachable,
    };
    return self.finish_air(inst, result, .{ ty_op.operand, .none, .none });
}

fn air_va_copy(self: *Self, inst: Air.Inst.Index) !void {
    const ty_op = self.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
    const ptr_va_list_ty = self.type_of(ty_op.operand);

    const dst_mcv = try self.alloc_reg_or_mem(inst, true);
    try self.load(dst_mcv, ptr_va_list_ty, .{ .air_ref = ty_op.operand });
    return self.finish_air(inst, dst_mcv, .{ ty_op.operand, .none, .none });
}

fn air_va_end(self: *Self, inst: Air.Inst.Index) !void {
    const un_op = self.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
    return self.finish_air(inst, .unreach, .{ un_op, .none, .none });
}

fn resolve_inst(self: *Self, ref: Air.Inst.Ref) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    const ty = self.type_of(ref);

    // If the type has no codegen bits, no need to store it.
    if (!ty.has_runtime_bits_ignore_comptime(mod)) return .none;

    const mcv = if (ref.to_index()) |inst| mcv: {
        break :mcv self.inst_tracking.get_ptr(inst).?.short;
    } else mcv: {
        const ip_index = ref.to_interned().?;
        const gop = try self.const_tracking.get_or_put(self.gpa, ip_index);
        if (!gop.found_existing) gop.value_ptr.* = InstTracking.init(init: {
            const const_mcv = try self.gen_typed_value(Value.from_interned(ip_index));
            switch (const_mcv) {
                .lea_tlv => |tlv_sym| switch (self.bin_file.tag) {
                    .elf, .macho => {
                        if (self.mod.pic) {
                            try self.spill_registers(&.{ .rdi, .rax });
                        } else {
                            try self.spill_registers(&.{.rax});
                        }
                        const frame_index = try self.alloc_frame_index(FrameAlloc.init(.{
                            .size = 8,
                            .alignment = .@"8",
                        }));
                        try self.gen_set_mem(
                            .{ .frame = frame_index },
                            0,
                            Type.usize,
                            .{ .lea_symbol = .{ .sym = tlv_sym } },
                            .{},
                        );
                        break :init .{ .load_frame = .{ .index = frame_index } };
                    },
                    else => break :init const_mcv,
                },
                else => break :init const_mcv,
            }
        });
        break :mcv gop.value_ptr.short;
    };

    switch (mcv) {
        .none, .unreach, .dead => unreachable,
        else => return mcv,
    }
}

fn get_resolved_inst_value(self: *Self, inst: Air.Inst.Index) *InstTracking {
    const tracking = self.inst_tracking.get_ptr(inst).?;
    return switch (tracking.short) {
        .none, .unreach, .dead => unreachable,
        else => tracking,
    };
}

/// If the MCValue is an immediate, and it does not fit within this type,
/// we put it in a register.
/// A potential opportunity for future optimization here would be keeping track
/// of the fact that the instruction is available both as an immediate
/// and as a register.
fn limit_immediate_type(self: *Self, operand: Air.Inst.Ref, comptime T: type) !MCValue {
    const mcv = try self.resolve_inst(operand);
    const ti = @typeInfo(T).Int;
    switch (mcv) {
        .immediate => |imm| {
            // This immediate is unsigned.
            const U = std.meta.Int(.unsigned, ti.bits - @int_from_bool(ti.signedness == .signed));
            if (imm >= math.max_int(U)) {
                return MCValue{ .register = try self.copy_to_tmp_register(Type.usize, mcv) };
            }
        },
        else => {},
    }
    return mcv;
}

fn gen_typed_value(self: *Self, val: Value) InnerError!MCValue {
    const mod = self.bin_file.comp.module.?;
    return switch (try codegen.gen_typed_value(self.bin_file, self.src_loc, val, self.owner.get_decl(mod))) {
        .mcv => |mcv| switch (mcv) {
            .none => .none,
            .undef => .undef,
            .immediate => |imm| .{ .immediate = imm },
            .memory => |addr| .{ .memory = addr },
            .load_symbol => |sym_index| .{ .load_symbol = .{ .sym = sym_index } },
            .load_direct => |sym_index| .{ .load_direct = sym_index },
            .load_got => |sym_index| .{ .lea_got = sym_index },
            .load_tlv => |sym_index| .{ .lea_tlv = sym_index },
        },
        .fail => |msg| {
            self.err_msg = msg;
            return error.CodegenFail;
        },
    };
}

const CallMCValues = struct {
    args: []MCValue,
    return_value: InstTracking,
    stack_byte_count: u31,
    stack_align: Alignment,
    gp_count: u32,
    fp_count: u32,

    fn deinit(self: *CallMCValues, func: *Self) void {
        func.gpa.free(self.args);
        self.* = undefined;
    }
};

/// Caller must call `CallMCValues.deinit`.
fn resolve_calling_convention_values(
    self: *Self,
    fn_info: InternPool.Key.FuncType,
    var_args: []const Type,
    stack_frame_base: FrameIndex,
) !CallMCValues {
    const mod = self.bin_file.comp.module.?;
    const ip = &mod.intern_pool;
    const cc = fn_info.cc;
    const param_types = try self.gpa.alloc(Type, fn_info.param_types.len + var_args.len);
    defer self.gpa.free(param_types);

    for (param_types[0..fn_info.param_types.len], fn_info.param_types.get(ip)) |*dest, src| {
        dest.* = Type.from_interned(src);
    }
    for (param_types[fn_info.param_types.len..], var_args) |*param_ty, arg_ty|
        param_ty.* = self.promote_var_arg(arg_ty);

    var result: CallMCValues = .{
        .args = try self.gpa.alloc(MCValue, param_types.len),
        // These undefined values must be populated before returning from this function.
        .return_value = undefined,
        .stack_byte_count = 0,
        .stack_align = undefined,
        .gp_count = 0,
        .fp_count = 0,
    };
    errdefer self.gpa.free(result.args);

    const ret_ty = Type.from_interned(fn_info.return_type);

    const resolved_cc = abi.resolve_calling_convention(cc, self.target.*);
    switch (cc) {
        .Naked => {
            assert(result.args.len == 0);
            result.return_value = InstTracking.init(.unreach);
            result.stack_align = .@"8";
        },
        .C, .SysV, .Win64 => {
            var ret_int_reg_i: u32 = 0;
            var ret_sse_reg_i: u32 = 0;
            var param_int_reg_i: u32 = 0;
            var param_sse_reg_i: u32 = 0;
            result.stack_align = .@"16";

            switch (resolved_cc) {
                .SysV => {},
                .Win64 => {
                    // Align the stack to 16bytes before allocating shadow stack space (if any).
                    result.stack_byte_count += @int_cast(4 * Type.usize.abi_size(mod));
                },
                else => unreachable,
            }

            // Return values
            if (ret_ty.zig_type_tag(mod) == .NoReturn) {
                result.return_value = InstTracking.init(.unreach);
            } else if (!ret_ty.has_runtime_bits_ignore_comptime(mod)) {
                // TODO: is this even possible for C calling convention?
                result.return_value = InstTracking.init(.none);
            } else {
                var ret_tracking: [2]InstTracking = undefined;
                var ret_tracking_i: usize = 0;

                const classes = switch (resolved_cc) {
                    .SysV => mem.slice_to(&abi.classify_system_v(ret_ty, mod, self.target.*, .ret), .none),
                    .Win64 => &.{abi.classify_windows(ret_ty, mod)},
                    else => unreachable,
                };
                for (classes) |class| switch (class) {
                    .integer => {
                        const ret_int_reg = register_alias(
                            abi.get_cabi_int_return_regs(resolved_cc)[ret_int_reg_i],
                            @int_cast(@min(ret_ty.abi_size(mod), 8)),
                        );
                        ret_int_reg_i += 1;

                        ret_tracking[ret_tracking_i] = InstTracking.init(.{ .register = ret_int_reg });
                        ret_tracking_i += 1;
                    },
                    .sse, .float, .float_combine, .win_i128 => {
                        const ret_sse_reg = register_alias(
                            abi.get_cabi_sse_return_regs(resolved_cc)[ret_sse_reg_i],
                            @int_cast(ret_ty.abi_size(mod)),
                        );
                        ret_sse_reg_i += 1;

                        ret_tracking[ret_tracking_i] = InstTracking.init(.{ .register = ret_sse_reg });
                        ret_tracking_i += 1;
                    },
                    .sseup => assert(ret_tracking[ret_tracking_i - 1].short.register.class() == .sse),
                    .x87 => {
                        ret_tracking[ret_tracking_i] = InstTracking.init(.{ .register = .st0 });
                        ret_tracking_i += 1;
                    },
                    .x87up => assert(ret_tracking[ret_tracking_i - 1].short.register.class() == .x87),
                    .complex_x87 => {
                        ret_tracking[ret_tracking_i] =
                            InstTracking.init(.{ .register_pair = .{ .st0, .st1 } });
                        ret_tracking_i += 1;
                    },
                    .memory => {
                        const ret_int_reg = abi.get_cabi_int_return_regs(resolved_cc)[ret_int_reg_i].to64();
                        ret_int_reg_i += 1;
                        const ret_indirect_reg = abi.get_cabi_int_param_regs(resolved_cc)[param_int_reg_i];
                        param_int_reg_i += 1;

                        ret_tracking[ret_tracking_i] = .{
                            .short = .{ .indirect = .{ .reg = ret_int_reg } },
                            .long = .{ .indirect = .{ .reg = ret_indirect_reg } },
                        };
                        ret_tracking_i += 1;
                    },
                    .none, .integer_per_element => unreachable,
                };
                result.return_value = switch (ret_tracking_i) {
                    else => unreachable,
                    1 => ret_tracking[0],
                    2 => InstTracking.init(.{ .register_pair = .{
                        ret_tracking[0].short.register, ret_tracking[1].short.register,
                    } }),
                };
            }

            // Input params
            for (param_types, result.args) |ty, *arg| {
                assert(ty.has_runtime_bits_ignore_comptime(mod));
                switch (resolved_cc) {
                    .SysV => {},
                    .Win64 => {
                        param_int_reg_i = @max(param_int_reg_i, param_sse_reg_i);
                        param_sse_reg_i = param_int_reg_i;
                    },
                    else => unreachable,
                }

                var arg_mcv: [2]MCValue = undefined;
                var arg_mcv_i: usize = 0;

                const classes = switch (resolved_cc) {
                    .SysV => mem.slice_to(&abi.classify_system_v(ty, mod, self.target.*, .arg), .none),
                    .Win64 => &.{abi.classify_windows(ty, mod)},
                    else => unreachable,
                };
                for (classes) |class| switch (class) {
                    .integer => {
                        const param_int_regs = abi.get_cabi_int_param_regs(resolved_cc);
                        if (param_int_reg_i >= param_int_regs.len) break;

                        const param_int_reg = register_alias(
                            abi.get_cabi_int_param_regs(resolved_cc)[param_int_reg_i],
                            @int_cast(@min(ty.abi_size(mod), 8)),
                        );
                        param_int_reg_i += 1;

                        arg_mcv[arg_mcv_i] = .{ .register = param_int_reg };
                        arg_mcv_i += 1;
                    },
                    .sse, .float, .float_combine => {
                        const param_sse_regs = abi.get_cabi_sse_param_regs(resolved_cc);
                        if (param_sse_reg_i >= param_sse_regs.len) break;

                        const param_sse_reg = register_alias(
                            abi.get_cabi_sse_param_regs(resolved_cc)[param_sse_reg_i],
                            @int_cast(ty.abi_size(mod)),
                        );
                        param_sse_reg_i += 1;

                        arg_mcv[arg_mcv_i] = .{ .register = param_sse_reg };
                        arg_mcv_i += 1;
                    },
                    .sseup => assert(arg_mcv[arg_mcv_i - 1].register.class() == .sse),
                    .x87, .x87up, .complex_x87, .memory, .win_i128 => switch (resolved_cc) {
                        .SysV => switch (class) {
                            .x87, .x87up, .complex_x87, .memory => break,
                            else => unreachable,
                        },
                        .Win64 => if (ty.abi_size(mod) > 8) {
                            const param_int_reg =
                                abi.get_cabi_int_param_regs(resolved_cc)[param_int_reg_i].to64();
                            param_int_reg_i += 1;

                            arg_mcv[arg_mcv_i] = .{ .indirect = .{ .reg = param_int_reg } };
                            arg_mcv_i += 1;
                        } else break,
                        else => unreachable,
                    },
                    .none => unreachable,
                    .integer_per_element => {
                        const param_int_regs_len: u32 =
                            @int_cast(abi.get_cabi_int_param_regs(resolved_cc).len);
                        const remaining_param_int_regs: u3 =
                            @int_cast(param_int_regs_len - param_int_reg_i);
                        param_int_reg_i = param_int_regs_len;

                        const frame_elem_align = 8;
                        const frame_elems_len = ty.vector_len(mod) - remaining_param_int_regs;
                        const frame_elem_size = mem.align_forward(
                            u64,
                            ty.child_type(mod).abi_size(mod),
                            frame_elem_align,
                        );
                        const frame_size: u31 = @int_cast(frame_elems_len * frame_elem_size);

                        result.stack_byte_count =
                            mem.align_forward(u31, result.stack_byte_count, frame_elem_align);
                        arg_mcv[arg_mcv_i] = .{ .elementwise_regs_then_frame = .{
                            .regs = remaining_param_int_regs,
                            .frame_off = @int_cast(result.stack_byte_count),
                            .frame_index = stack_frame_base,
                        } };
                        arg_mcv_i += 1;
                        result.stack_byte_count += frame_size;
                    },
                } else {
                    arg.* = switch (arg_mcv_i) {
                        else => unreachable,
                        1 => arg_mcv[0],
                        2 => .{ .register_pair = .{ arg_mcv[0].register, arg_mcv[1].register } },
                    };
                    continue;
                }

                const param_size: u31 = @int_cast(ty.abi_size(mod));
                const param_align: u31 =
                    @int_cast(@max(ty.abi_alignment(mod).to_byte_units().?, 8));
                result.stack_byte_count =
                    mem.align_forward(u31, result.stack_byte_count, param_align);
                arg.* = .{ .load_frame = .{
                    .index = stack_frame_base,
                    .off = result.stack_byte_count,
                } };
                result.stack_byte_count += param_size;
            }
            assert(param_int_reg_i <= 6);
            result.gp_count = param_int_reg_i;
            assert(param_sse_reg_i <= 16);
            result.fp_count = param_sse_reg_i;
        },
        .Unspecified => {
            result.stack_align = .@"16";

            // Return values
            if (ret_ty.zig_type_tag(mod) == .NoReturn) {
                result.return_value = InstTracking.init(.unreach);
            } else if (!ret_ty.has_runtime_bits_ignore_comptime(mod)) {
                result.return_value = InstTracking.init(.none);
            } else {
                const ret_reg = abi.get_cabi_int_return_regs(resolved_cc)[0];
                const ret_ty_size: u31 = @int_cast(ret_ty.abi_size(mod));
                if (ret_ty_size <= 8 and !ret_ty.is_runtime_float()) {
                    const aliased_reg = register_alias(ret_reg, ret_ty_size);
                    result.return_value = .{ .short = .{ .register = aliased_reg }, .long = .none };
                } else {
                    const ret_indirect_reg = abi.get_cabi_int_param_regs(resolved_cc)[0];
                    result.return_value = .{
                        .short = .{ .indirect = .{ .reg = ret_reg } },
                        .long = .{ .indirect = .{ .reg = ret_indirect_reg } },
                    };
                }
            }

            // Input params
            for (param_types, result.args) |ty, *arg| {
                if (!ty.has_runtime_bits_ignore_comptime(mod)) {
                    arg.* = .none;
                    continue;
                }
                const param_size: u31 = @int_cast(ty.abi_size(mod));
                const param_align: u31 = @int_cast(ty.abi_alignment(mod).to_byte_units().?);
                result.stack_byte_count =
                    mem.align_forward(u31, result.stack_byte_count, param_align);
                arg.* = .{ .load_frame = .{
                    .index = stack_frame_base,
                    .off = result.stack_byte_count,
                } };
                result.stack_byte_count += param_size;
            }
        },
        else => return self.fail("TODO implement function parameters and return values for {} on x86_64", .{cc}),
    }

    result.stack_byte_count = @int_cast(result.stack_align.forward(result.stack_byte_count));
    return result;
}

fn fail(self: *Self, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(self.err_msg == null);
    const gpa = self.gpa;
    self.err_msg = try ErrorMsg.create(gpa, self.src_loc, format, args);
    return error.CodegenFail;
}

fn fail_symbol(self: *Self, comptime format: []const u8, args: anytype) InnerError {
    @setCold(true);
    assert(self.err_msg == null);
    const gpa = self.gpa;
    self.err_msg = try ErrorMsg.create(gpa, self.src_loc, format, args);
    return error.CodegenFail;
}

fn parse_reg_name(name: []const u8) ?Register {
    if (@hasDecl(Register, "parse_reg_name")) {
        return Register.parse_reg_name(name);
    }
    return std.meta.string_to_enum(Register, name);
}

/// Returns register wide enough to hold at least `size_bytes`.
fn register_alias(reg: Register, size_bytes: u32) Register {
    return switch (reg.class()) {
        .general_purpose => if (size_bytes == 0)
            unreachable // should be comptime-known
        else if (size_bytes <= 1)
            reg.to8()
        else if (size_bytes <= 2)
            reg.to16()
        else if (size_bytes <= 4)
            reg.to32()
        else if (size_bytes <= 8)
            reg.to64()
        else
            unreachable,
        .segment => if (size_bytes <= 2)
            reg
        else
            unreachable,
        .x87 => if (size_bytes == 16)
            reg
        else
            unreachable,
        .mmx => if (size_bytes <= 8)
            reg
        else
            unreachable,
        .sse => if (size_bytes <= 16)
            reg.to128()
        else if (size_bytes <= 32)
            reg.to256()
        else
            unreachable,
    };
}

fn mem_size(self: *Self, ty: Type) Memory.Size {
    const mod = self.bin_file.comp.module.?;
    return switch (ty.zig_type_tag(mod)) {
        .Float => Memory.Size.from_bit_size(ty.float_bits(self.target.*)),
        else => Memory.Size.from_size(@int_cast(ty.abi_size(mod))),
    };
}

fn split_type(self: *Self, ty: Type) ![2]Type {
    const mod = self.bin_file.comp.module.?;
    const classes = mem.slice_to(&abi.classify_system_v(ty, mod, self.target.*, .other), .none);
    var parts: [2]Type = undefined;
    if (classes.len == 2) for (&parts, classes, 0..) |*part, class, part_i| {
        part.* = switch (class) {
            .integer => switch (part_i) {
                0 => Type.u64,
                1 => part: {
                    const elem_size = ty.abi_alignment(mod).min_strict(.@"8").to_byte_units().?;
                    const elem_ty = try mod.int_type(.unsigned, @int_cast(elem_size * 8));
                    break :part switch (@div_exact(ty.abi_size(mod) - 8, elem_size)) {
                        1 => elem_ty,
                        else => |len| try mod.array_type(.{ .len = len, .child = elem_ty.to_intern() }),
                    };
                },
                else => unreachable,
            },
            .float => Type.f32,
            .float_combine => try mod.array_type(.{ .len = 2, .child = .f32_type }),
            .sse => Type.f64,
            else => break,
        };
    } else if (parts[0].abi_size(mod) + parts[1].abi_size(mod) == ty.abi_size(mod)) return parts;
    return self.fail("TODO implement split_type for {}", .{ty.fmt(mod)});
}

/// Truncates the value in the register in place.
/// Clobbers any remaining bits.
fn truncate_register(self: *Self, ty: Type, reg: Register) !void {
    const mod = self.bin_file.comp.module.?;
    const int_info = if (ty.is_abi_int(mod)) ty.int_info(mod) else std.builtin.Type.Int{
        .signedness = .unsigned,
        .bits = @int_cast(ty.bit_size(mod)),
    };
    const shift = math.cast(u6, 64 - int_info.bits % 64) orelse return;
    try self.spill_eflags_if_occupied();
    switch (int_info.signedness) {
        .signed => {
            try self.gen_shift_bin_op_mir(
                .{ ._l, .sa },
                Type.isize,
                .{ .register = reg },
                Type.u8,
                .{ .immediate = shift },
            );
            try self.gen_shift_bin_op_mir(
                .{ ._r, .sa },
                Type.isize,
                .{ .register = reg },
                Type.u8,
                .{ .immediate = shift },
            );
        },
        .unsigned => {
            const mask = ~@as(u64, 0) >> shift;
            if (int_info.bits <= 32) {
                try self.gen_bin_op_mir(
                    .{ ._, .@"and" },
                    Type.u32,
                    .{ .register = reg },
                    .{ .immediate = mask },
                );
            } else {
                const tmp_reg = try self.copy_to_tmp_register(Type.usize, .{ .immediate = mask });
                try self.gen_bin_op_mir(
                    .{ ._, .@"and" },
                    Type.usize,
                    .{ .register = reg },
                    .{ .register = tmp_reg },
                );
            }
        },
    }
}

fn reg_bit_size(self: *Self, ty: Type) u64 {
    const mod = self.bin_file.comp.module.?;
    const abi_size = ty.abi_size(mod);
    return switch (ty.zig_type_tag(mod)) {
        else => switch (abi_size) {
            1 => 8,
            2 => 16,
            3...4 => 32,
            5...8 => 64,
            else => unreachable,
        },
        .Float => switch (abi_size) {
            1...16 => 128,
            17...32 => 256,
            else => unreachable,
        },
    };
}

fn reg_extra_bits(self: *Self, ty: Type) u64 {
    const mod = self.bin_file.comp.module.?;
    return self.reg_bit_size(ty) - ty.bit_size(mod);
}

fn has_feature(self: *Self, feature: Target.x86.Feature) bool {
    return Target.x86.feature_set_has(self.target.cpu.features, feature);
}
fn has_any_features(self: *Self, features: anytype) bool {
    return Target.x86.feature_set_has_any(self.target.cpu.features, features);
}
fn has_all_features(self: *Self, features: anytype) bool {
    return Target.x86.feature_set_has_all(self.target.cpu.features, features);
}

fn type_of(self: *Self, inst: Air.Inst.Ref) Type {
    const mod = self.bin_file.comp.module.?;
    return self.air.type_of(inst, &mod.intern_pool);
}

fn type_of_index(self: *Self, inst: Air.Inst.Index) Type {
    const mod = self.bin_file.comp.module.?;
    return self.air.type_of_index(inst, &mod.intern_pool);
}

fn int_compiler_rt_abi_name(int_bits: u32) u8 {
    return switch (int_bits) {
        1...32 => 's',
        33...64 => 'd',
        65...128 => 't',
        else => unreachable,
    };
}

fn float_compiler_rt_abi_name(float_bits: u32) u8 {
    return switch (float_bits) {
        16 => 'h',
        32 => 's',
        64 => 'd',
        80 => 'x',
        128 => 't',
        else => unreachable,
    };
}

fn float_compiler_rt_abi_type(self: *Self, ty: Type, other_ty: Type) Type {
    if (ty.to_intern() == .f16_type and
        (other_ty.to_intern() == .f32_type or other_ty.to_intern() == .f64_type) and
        self.target.is_darwin()) return Type.u16;
    return ty;
}

fn float_libc_abi_prefix(ty: Type) []const u8 {
    return switch (ty.to_intern()) {
        .f16_type, .f80_type => "__",
        .f32_type, .f64_type, .f128_type, .c_longdouble_type => "",
        else => unreachable,
    };
}

fn float_libc_abi_suffix(ty: Type) []const u8 {
    return switch (ty.to_intern()) {
        .f16_type => "h",
        .f32_type => "f",
        .f64_type => "",
        .f80_type => "x",
        .f128_type => "q",
        .c_longdouble_type => "l",
        else => unreachable,
    };
}

fn promote_int(self: *Self, ty: Type) Type {
    const mod = self.bin_file.comp.module.?;
    const int_info: InternPool.Key.IntType = switch (ty.to_intern()) {
        .bool_type => .{ .signedness = .unsigned, .bits = 1 },
        else => if (ty.is_abi_int(mod)) ty.int_info(mod) else return ty,
    };
    for ([_]Type{
        Type.c_int,      Type.c_uint,
        Type.c_long,     Type.c_ulong,
        Type.c_longlong, Type.c_ulonglong,
    }) |promote_ty| {
        const promote_info = promote_ty.int_info(mod);
        if (int_info.signedness == .signed and promote_info.signedness == .unsigned) continue;
        if (int_info.bits + @int_from_bool(int_info.signedness == .unsigned and
            promote_info.signedness == .signed) <= promote_info.bits) return promote_ty;
    }
    return ty;
}

fn promote_var_arg(self: *Self, ty: Type) Type {
    if (!ty.is_runtime_float()) return self.promote_int(ty);
    switch (ty.float_bits(self.target.*)) {
        32, 64 => return Type.f64,
        else => |float_bits| {
            assert(float_bits == self.target.c_type_bit_size(.longdouble));
            return Type.c_longdouble;
        },
    }
}
