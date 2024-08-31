const std = @import("std");
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Air = @import("Air.zig");
const StaticBitSet = std.bit_set.StaticBitSet;
const Type = @import("type.zig").Type;
const Module = @import("Module.zig");
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;
const expect_equal_slices = std.testing.expect_equal_slices;

const log = std.log.scoped(.register_manager);

pub const AllocateRegistersError = error{
    /// No registers are available anymore
    OutOfRegisters,
    /// Can happen when spilling an instruction in codegen runs out of
    /// memory, so we propagate that error
    OutOfMemory,
    /// Can happen when spilling an instruction in codegen triggers integer
    /// overflow, so we propagate that error
    Overflow,
    /// Can happen when spilling an instruction triggers a codegen
    /// error, so we propagate that error
    CodegenFail,
};

pub fn RegisterManager(
    comptime Function: type,
    comptime Register: type,
    comptime tracked_registers: []const Register,
) type {
    // architectures which do not have a concept of registers should
    // refrain from using RegisterManager
    assert(tracked_registers.len > 0); // see note above

    return struct {
        /// Tracks the AIR instruction allocated to every register. If
        /// no instruction is allocated to a register (i.e. the
        /// register is free), the value in that slot is undefined.
        ///
        /// The key must be canonical register.
        registers: TrackedRegisters = undefined,
        /// Tracks which registers are free (in which case the
        /// corresponding bit is set to 1)
        free_registers: RegisterBitSet = RegisterBitSet.init_full(),
        /// Tracks all registers allocated in the course of this
        /// function
        allocated_registers: RegisterBitSet = RegisterBitSet.init_empty(),
        /// Tracks registers which are locked from being allocated
        locked_registers: RegisterBitSet = RegisterBitSet.init_empty(),

        const Self = @This();

        pub const TrackedRegisters = [tracked_registers.len]Air.Inst.Index;
        pub const TrackedIndex = std.math.IntFittingRange(0, tracked_registers.len - 1);
        pub const RegisterBitSet = StaticBitSet(tracked_registers.len);

        fn get_function(self: *Self) *Function {
            return @align_cast(@fieldParentPtr("register_manager", self));
        }

        fn exclude_register(reg: Register, register_class: RegisterBitSet) bool {
            const index = index_of_reg_into_tracked(reg) orelse return true;
            return !register_class.is_set(index);
        }

        fn mark_reg_index_allocated(self: *Self, tracked_index: TrackedIndex) void {
            self.allocated_registers.set(tracked_index);
        }
        fn mark_reg_allocated(self: *Self, reg: Register) void {
            self.mark_reg_index_allocated(index_of_reg_into_tracked(reg) orelse return);
        }

        fn mark_reg_index_used(self: *Self, tracked_index: TrackedIndex) void {
            self.free_registers.unset(tracked_index);
        }
        fn mark_reg_used(self: *Self, reg: Register) void {
            self.mark_reg_index_used(index_of_reg_into_tracked(reg) orelse return);
        }

        fn mark_reg_index_free(self: *Self, tracked_index: TrackedIndex) void {
            self.free_registers.set(tracked_index);
        }
        fn mark_reg_free(self: *Self, reg: Register) void {
            self.mark_reg_index_free(index_of_reg_into_tracked(reg) orelse return);
        }

        pub fn index_of_reg(
            comptime set: []const Register,
            reg: Register,
        ) ?std.math.IntFittingRange(0, set.len - 1) {
            const Id = @TypeOf(reg.id());
            comptime var min_id: Id = std.math.max_int(Id);
            comptime var max_id: Id = std.math.min_int(Id);
            inline for (set) |elem| {
                const elem_id = comptime elem.id();
                min_id = @min(elem_id, min_id);
                max_id = @max(elem_id, max_id);
            }

            const OptionalIndex = std.math.IntFittingRange(0, set.len);
            comptime var map = [1]OptionalIndex{set.len} ** (max_id - min_id + 1);
            inline for (set, 0..) |elem, elem_index| map[comptime elem.id() - min_id] = elem_index;

            const id_index = reg.id() -% min_id;
            if (id_index >= map.len) return null;
            const set_index = map[id_index];
            return if (set_index < set.len) @int_cast(set_index) else null;
        }

        pub fn index_of_reg_into_tracked(reg: Register) ?TrackedIndex {
            return index_of_reg(tracked_registers, reg);
        }

        pub fn reg_at_tracked_index(tracked_index: TrackedIndex) Register {
            return tracked_registers[tracked_index];
        }

        /// Returns true when this register is not tracked
        pub fn is_reg_index_free(self: Self, tracked_index: TrackedIndex) bool {
            return self.free_registers.is_set(tracked_index);
        }
        pub fn is_reg_free(self: Self, reg: Register) bool {
            return self.is_reg_index_free(index_of_reg_into_tracked(reg) orelse return true);
        }

        /// Returns whether this register was allocated in the course
        /// of this function.
        ///
        /// Returns false when this register is not tracked
        pub fn is_reg_allocated(self: Self, reg: Register) bool {
            const index = index_of_reg_into_tracked(reg) orelse return false;
            return self.allocated_registers.is_set(index);
        }

        /// Returns whether this register is locked
        ///
        /// Returns false when this register is not tracked
        fn is_reg_index_locked(self: Self, tracked_index: TrackedIndex) bool {
            return self.locked_registers.is_set(tracked_index);
        }
        pub fn is_reg_locked(self: Self, reg: Register) bool {
            return self.is_reg_index_locked(index_of_reg_into_tracked(reg) orelse return false);
        }

        pub const RegisterLock = struct { tracked_index: TrackedIndex };

        /// Prevents the register from being allocated until they are
        /// unlocked again.
        /// Returns `RegisterLock` if the register was not already
        /// locked, or `null` otherwise.
        /// Only the owner of the `RegisterLock` can unlock the
        /// register later.
        pub fn lock_reg_index(self: *Self, tracked_index: TrackedIndex) ?RegisterLock {
            log.debug("locking {}", .{reg_at_tracked_index(tracked_index)});
            if (self.is_reg_index_locked(tracked_index)) {
                log.debug("  register already locked", .{});
                return null;
            }
            self.locked_registers.set(tracked_index);
            return RegisterLock{ .tracked_index = tracked_index };
        }
        pub fn lock_reg(self: *Self, reg: Register) ?RegisterLock {
            return self.lock_reg_index(index_of_reg_into_tracked(reg) orelse return null);
        }

        /// Like `lock_reg` but asserts the register was unused always
        /// returning a valid lock.
        pub fn lock_reg_index_assume_unused(self: *Self, tracked_index: TrackedIndex) RegisterLock {
            log.debug("locking asserting free {}", .{reg_at_tracked_index(tracked_index)});
            assert(!self.is_reg_index_locked(tracked_index));
            self.locked_registers.set(tracked_index);
            return RegisterLock{ .tracked_index = tracked_index };
        }
        pub fn lock_reg_assume_unused(self: *Self, reg: Register) RegisterLock {
            return self.lock_reg_index_assume_unused(index_of_reg_into_tracked(reg) orelse unreachable);
        }

        /// Like `lock_reg` but locks multiple registers.
        pub fn lock_regs(
            self: *Self,
            comptime count: comptime_int,
            regs: [count]Register,
        ) [count]?RegisterLock {
            var results: [count]?RegisterLock = undefined;
            for (&results, regs) |*result, reg| result.* = self.lock_reg(reg);
            return results;
        }

        /// Like `lock_reg_assume_unused` but locks multiple registers.
        pub fn lock_regs_assume_unused(
            self: *Self,
            comptime count: comptime_int,
            regs: [count]Register,
        ) [count]RegisterLock {
            var results: [count]RegisterLock = undefined;
            for (&results, regs) |*result, reg| result.* = self.lock_reg_assume_unused(reg);
            return results;
        }

        /// Unlocks the register allowing its re-allocation and re-use.
        /// Requires `RegisterLock` to unlock a register.
        /// Call `lock_reg` to obtain the lock first.
        pub fn unlock_reg(self: *Self, lock: RegisterLock) void {
            log.debug("unlocking {}", .{reg_at_tracked_index(lock.tracked_index)});
            self.locked_registers.unset(lock.tracked_index);
        }

        /// Returns true when at least one register is locked
        pub fn locked_regs_exist(self: Self) bool {
            return self.locked_registers.count() > 0;
        }

        /// Allocates a specified number of registers, optionally
        /// tracking them. Returns `null` if not enough registers are
        /// free.
        pub fn try_alloc_regs(
            self: *Self,
            comptime count: comptime_int,
            insts: [count]?Air.Inst.Index,
            register_class: RegisterBitSet,
        ) ?[count]Register {
            comptime assert(count > 0 and count <= tracked_registers.len);

            var free_and_not_locked_registers = self.free_registers;
            free_and_not_locked_registers.set_intersection(register_class);

            var unlocked_registers = self.locked_registers;
            unlocked_registers.toggle_all();

            free_and_not_locked_registers.set_intersection(unlocked_registers);

            if (free_and_not_locked_registers.count() < count) return null;

            var regs: [count]Register = undefined;
            var i: usize = 0;
            for (tracked_registers) |reg| {
                if (i >= count) break;
                if (exclude_register(reg, register_class)) continue;
                if (self.is_reg_locked(reg)) continue;
                if (!self.is_reg_free(reg)) continue;

                regs[i] = reg;
                i += 1;
            }
            assert(i == count);

            for (regs, insts) |reg, inst| {
                log.debug("try_alloc_reg {} for inst {?}", .{ reg, inst });
                self.mark_reg_allocated(reg);

                if (inst) |tracked_inst| {
                    // Track the register
                    const index = index_of_reg_into_tracked(reg).?; // index_of_reg() on a callee-preserved reg should never return null
                    self.registers[index] = tracked_inst;
                    self.mark_reg_used(reg);
                }
            }

            return regs;
        }

        /// Allocates a register and optionally tracks it with a
        /// corresponding instruction. Returns `null` if all registers
        /// are allocated.
        pub fn try_alloc_reg(self: *Self, inst: ?Air.Inst.Index, register_class: RegisterBitSet) ?Register {
            return if (try_alloc_regs(self, 1, .{inst}, register_class)) |regs| regs[0] else null;
        }

        /// Allocates a specified number of registers, optionally
        /// tracking them. Asserts that count is not
        /// larger than the total number of registers available.
        pub fn alloc_regs(
            self: *Self,
            comptime count: comptime_int,
            insts: [count]?Air.Inst.Index,
            register_class: RegisterBitSet,
        ) AllocateRegistersError![count]Register {
            comptime assert(count > 0 and count <= tracked_registers.len);

            var locked_registers = self.locked_registers;
            locked_registers.set_intersection(register_class);

            if (count > register_class.count() - locked_registers.count()) return error.OutOfRegisters;

            const result = self.try_alloc_regs(count, insts, register_class) orelse blk: {
                // We'll take over the first count registers. Spill
                // the instructions that were previously there to a
                // stack allocations.
                var regs: [count]Register = undefined;
                var i: usize = 0;
                for (tracked_registers) |reg| {
                    if (i >= count) break;
                    if (exclude_register(reg, register_class)) break;
                    if (self.is_reg_locked(reg)) continue;

                    log.debug("alloc_reg {} for inst {?}", .{ reg, insts[i] });
                    regs[i] = reg;
                    self.mark_reg_allocated(reg);
                    const index = index_of_reg_into_tracked(reg).?; // index_of_reg() on a callee-preserved reg should never return null
                    if (insts[i]) |inst| {
                        // Track the register
                        if (self.is_reg_free(reg)) {
                            self.mark_reg_used(reg);
                        } else {
                            const spilled_inst = self.registers[index];
                            try self.get_function().spill_instruction(reg, spilled_inst);
                        }
                        self.registers[index] = inst;
                    } else {
                        // Don't track the register
                        if (!self.is_reg_free(reg)) {
                            const spilled_inst = self.registers[index];
                            try self.get_function().spill_instruction(reg, spilled_inst);
                            self.free_reg(reg);
                        }
                    }

                    i += 1;
                }

                break :blk regs;
            };

            log.debug("allocated registers {any} for insts {any}", .{ result, insts });
            return result;
        }

        /// Allocates a register and optionally tracks it with a
        /// corresponding instruction.
        pub fn alloc_reg(
            self: *Self,
            inst: ?Air.Inst.Index,
            register_class: RegisterBitSet,
        ) AllocateRegistersError!Register {
            return (try self.alloc_regs(1, .{inst}, register_class))[0];
        }

        /// Spills the register if it is currently allocated. If a
        /// corresponding instruction is passed, will also track this
        /// register.
        fn get_reg_index(
            self: *Self,
            tracked_index: TrackedIndex,
            inst: ?Air.Inst.Index,
        ) AllocateRegistersError!void {
            log.debug("get_reg {} for inst {?}", .{ reg_at_tracked_index(tracked_index), inst });
            if (!self.is_reg_index_free(tracked_index)) {
                self.mark_reg_index_allocated(tracked_index);

                // Move the instruction that was previously there to a
                // stack allocation.
                const spilled_inst = self.registers[tracked_index];
                if (inst) |tracked_inst| self.registers[tracked_index] = tracked_inst;
                try self.get_function().spill_instruction(reg_at_tracked_index(tracked_index), spilled_inst);
                if (inst == null) self.free_reg_index(tracked_index);
            } else self.get_reg_index_assume_free(tracked_index, inst);
        }
        pub fn get_reg(self: *Self, reg: Register, inst: ?Air.Inst.Index) AllocateRegistersError!void {
            log.debug("getting reg: {}", .{reg});
            return self.get_reg_index(index_of_reg_into_tracked(reg) orelse return, inst);
        }
        pub fn get_known_reg(
            self: *Self,
            comptime reg: Register,
            inst: ?Air.Inst.Index,
        ) AllocateRegistersError!void {
            return self.get_reg_index((comptime index_of_reg_into_tracked(reg)) orelse return, inst);
        }

        /// Allocates the specified register with the specified
        /// instruction. Asserts that the register is free and no
        /// spilling is necessary.
        fn get_reg_index_assume_free(
            self: *Self,
            tracked_index: TrackedIndex,
            inst: ?Air.Inst.Index,
        ) void {
            log.debug("get_reg_assume_free {} for inst {?}", .{ reg_at_tracked_index(tracked_index), inst });
            self.mark_reg_index_allocated(tracked_index);

            assert(self.is_reg_index_free(tracked_index));
            if (inst) |tracked_inst| {
                self.registers[tracked_index] = tracked_inst;
                self.mark_reg_index_used(tracked_index);
            }
        }
        pub fn get_reg_assume_free(self: *Self, reg: Register, inst: ?Air.Inst.Index) void {
            self.get_reg_index_assume_free(index_of_reg_into_tracked(reg) orelse return, inst);
        }

        /// Marks the specified register as free
        fn free_reg_index(self: *Self, tracked_index: TrackedIndex) void {
            log.debug("freeing register {}", .{reg_at_tracked_index(tracked_index)});
            self.registers[tracked_index] = undefined;
            self.mark_reg_index_free(tracked_index);
        }
        pub fn free_reg(self: *Self, reg: Register) void {
            self.free_reg_index(index_of_reg_into_tracked(reg) orelse return);
        }
    };
}

const MockRegister1 = enum(u2) {
    r0,
    r1,
    r2,
    r3,

    pub fn id(reg: MockRegister1) u2 {
        return @int_from_enum(reg);
    }

    const allocatable_registers = [_]MockRegister1{ .r2, .r3 };

    const RM = RegisterManager(
        MockFunction1,
        MockRegister1,
        &MockRegister1.allocatable_registers,
    );

    const gp: RM.RegisterBitSet = blk: {
        var set = RM.RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = 0,
            .end = allocatable_registers.len,
        }, true);
        break :blk set;
    };
};

const MockRegister2 = enum(u2) {
    r0,
    r1,
    r2,
    r3,

    pub fn id(reg: MockRegister2) u2 {
        return @int_from_enum(reg);
    }

    const allocatable_registers = [_]MockRegister2{ .r0, .r1, .r2, .r3 };

    const RM = RegisterManager(
        MockFunction2,
        MockRegister2,
        &MockRegister2.allocatable_registers,
    );

    const gp: RM.RegisterBitSet = blk: {
        var set = RM.RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = 0,
            .end = allocatable_registers.len,
        }, true);
        break :blk set;
    };
};

const MockRegister3 = enum(u3) {
    r0,
    r1,
    r2,
    r3,
    x0,
    x1,
    x2,
    x3,

    pub fn id(reg: MockRegister3) u3 {
        return switch (@int_from_enum(reg)) {
            0...3 => @as(u3, @as(u2, @truncate(@int_from_enum(reg)))),
            4...7 => @int_from_enum(reg),
        };
    }

    pub fn enc(reg: MockRegister3) u2 {
        return @as(u2, @truncate(@int_from_enum(reg)));
    }

    const gp_regs = [_]MockRegister3{ .r0, .r1, .r2, .r3 };
    const ext_regs = [_]MockRegister3{ .x0, .x1, .x2, .x3 };
    const allocatable_registers = gp_regs ++ ext_regs;

    const RM = RegisterManager(
        MockFunction3,
        MockRegister3,
        &MockRegister3.allocatable_registers,
    );

    const gp: RM.RegisterBitSet = blk: {
        var set = RM.RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = 0,
            .end = gp_regs.len,
        }, true);
        break :blk set;
    };
    const ext: RM.RegisterBitSet = blk: {
        var set = RM.RegisterBitSet.init_empty();
        set.set_range_value(.{
            .start = gp_regs.len,
            .end = allocatable_registers.len,
        }, true);
        break :blk set;
    };
};

fn MockFunction(comptime Register: type) type {
    return struct {
        allocator: Allocator,
        register_manager: Register.RM = .{},
        spilled: std.ArrayListUnmanaged(Register) = .{},

        const Self = @This();

        pub fn deinit(self: *Self) void {
            self.spilled.deinit(self.allocator);
        }

        pub fn spill_instruction(self: *Self, reg: Register, inst: Air.Inst.Index) !void {
            _ = inst;
            try self.spilled.append(self.allocator, reg);
        }

        pub fn gen_add(self: *Self, res: Register, lhs: Register, rhs: Register) !void {
            _ = self;
            _ = res;
            _ = lhs;
            _ = rhs;
        }
    };
}

const MockFunction1 = MockFunction(MockRegister1);
const MockFunction2 = MockFunction(MockRegister2);
const MockFunction3 = MockFunction(MockRegister3);

test "default state" {
    const allocator = std.testing.allocator;

    var function = MockFunction1{
        .allocator = allocator,
    };
    defer function.deinit();

    try expect(!function.register_manager.is_reg_allocated(.r2));
    try expect(!function.register_manager.is_reg_allocated(.r3));
    try expect(function.register_manager.is_reg_free(.r2));
    try expect(function.register_manager.is_reg_free(.r3));
}

test "try_alloc_reg: no spilling" {
    const allocator = std.testing.allocator;

    var function = MockFunction1{
        .allocator = allocator,
    };
    defer function.deinit();

    const mock_instruction: Air.Inst.Index = 1;
    const gp = MockRegister1.gp;

    try expect_equal(@as(?MockRegister1, .r2), function.register_manager.try_alloc_reg(mock_instruction, gp));
    try expect_equal(@as(?MockRegister1, .r3), function.register_manager.try_alloc_reg(mock_instruction, gp));
    try expect_equal(@as(?MockRegister1, null), function.register_manager.try_alloc_reg(mock_instruction, gp));

    try expect(function.register_manager.is_reg_allocated(.r2));
    try expect(function.register_manager.is_reg_allocated(.r3));
    try expect(!function.register_manager.is_reg_free(.r2));
    try expect(!function.register_manager.is_reg_free(.r3));

    function.register_manager.free_reg(.r2);
    function.register_manager.free_reg(.r3);

    try expect(function.register_manager.is_reg_allocated(.r2));
    try expect(function.register_manager.is_reg_allocated(.r3));
    try expect(function.register_manager.is_reg_free(.r2));
    try expect(function.register_manager.is_reg_free(.r3));
}

test "alloc_reg: spilling" {
    const allocator = std.testing.allocator;

    var function = MockFunction1{
        .allocator = allocator,
    };
    defer function.deinit();

    const mock_instruction: Air.Inst.Index = 1;
    const gp = MockRegister1.gp;

    try expect_equal(@as(?MockRegister1, .r2), try function.register_manager.alloc_reg(mock_instruction, gp));
    try expect_equal(@as(?MockRegister1, .r3), try function.register_manager.alloc_reg(mock_instruction, gp));

    // Spill a register
    try expect_equal(@as(?MockRegister1, .r2), try function.register_manager.alloc_reg(mock_instruction, gp));
    try expect_equal_slices(MockRegister1, &[_]MockRegister1{.r2}, function.spilled.items);

    // No spilling necessary
    function.register_manager.free_reg(.r3);
    try expect_equal(@as(?MockRegister1, .r3), try function.register_manager.alloc_reg(mock_instruction, gp));
    try expect_equal_slices(MockRegister1, &[_]MockRegister1{.r2}, function.spilled.items);

    // Locked registers
    function.register_manager.free_reg(.r3);
    {
        const lock = function.register_manager.lock_reg(.r2);
        defer if (lock) |reg| function.register_manager.unlock_reg(reg);

        try expect_equal(@as(?MockRegister1, .r3), try function.register_manager.alloc_reg(mock_instruction, gp));
    }
    try expect(!function.register_manager.locked_regs_exist());
}

test "try_alloc_regs" {
    const allocator = std.testing.allocator;

    var function = MockFunction2{
        .allocator = allocator,
    };
    defer function.deinit();

    const gp = MockRegister2.gp;

    try expect_equal([_]MockRegister2{ .r0, .r1, .r2 }, function.register_manager.try_alloc_regs(3, .{
        null,
        null,
        null,
    }, gp).?);

    try expect(function.register_manager.is_reg_allocated(.r0));
    try expect(function.register_manager.is_reg_allocated(.r1));
    try expect(function.register_manager.is_reg_allocated(.r2));
    try expect(!function.register_manager.is_reg_allocated(.r3));

    // Locked registers
    function.register_manager.free_reg(.r0);
    function.register_manager.free_reg(.r2);
    function.register_manager.free_reg(.r3);
    {
        const lock = function.register_manager.lock_reg(.r1);
        defer if (lock) |reg| function.register_manager.unlock_reg(reg);

        try expect_equal([_]MockRegister2{ .r0, .r2, .r3 }, function.register_manager.try_alloc_regs(3, .{
            null,
            null,
            null,
        }, gp).?);
    }
    try expect(!function.register_manager.locked_regs_exist());

    try expect(function.register_manager.is_reg_allocated(.r0));
    try expect(function.register_manager.is_reg_allocated(.r1));
    try expect(function.register_manager.is_reg_allocated(.r2));
    try expect(function.register_manager.is_reg_allocated(.r3));
}

test "alloc_regs: normal usage" {
    // TODO: convert this into a decltest once that is supported

    const allocator = std.testing.allocator;

    var function = MockFunction2{
        .allocator = allocator,
    };
    defer function.deinit();

    const gp = MockRegister2.gp;

    {
        const result_reg: MockRegister2 = .r1;

        // The result register is known and fixed at this point, we
        // don't want to accidentally allocate lhs or rhs to the
        // result register, this is why we lock it.
        //
        // Using defer unlock right after lock is a good idea in
        // most cases as you probably are using the locked registers
        // in the remainder of this scope and don't need to use it
        // after the end of this scope. However, in some situations,
        // it may make sense to manually unlock registers before the
        // end of the scope when you are certain that they don't
        // contain any valuable data anymore and can be reused. For an
        // example of that, see `selectively reducing register
        // pressure`.
        const lock = function.register_manager.lock_reg(result_reg);
        defer if (lock) |reg| function.register_manager.unlock_reg(reg);

        const regs = try function.register_manager.alloc_regs(2, .{ null, null }, gp);
        try function.gen_add(result_reg, regs[0], regs[1]);
    }
}

test "alloc_regs: selectively reducing register pressure" {
    // TODO: convert this into a decltest once that is supported

    const allocator = std.testing.allocator;

    var function = MockFunction2{
        .allocator = allocator,
    };
    defer function.deinit();

    const gp = MockRegister2.gp;

    {
        const result_reg: MockRegister2 = .r1;

        const lock = function.register_manager.lock_reg(result_reg);

        // Here, we don't defer unlock because we manually unlock
        // after gen_add
        const regs = try function.register_manager.alloc_regs(2, .{ null, null }, gp);

        try function.gen_add(result_reg, regs[0], regs[1]);
        function.register_manager.unlock_reg(lock.?);

        const extra_summand_reg = try function.register_manager.alloc_reg(null, gp);
        try function.gen_add(result_reg, result_reg, extra_summand_reg);
    }
}

test "get_reg" {
    const allocator = std.testing.allocator;

    var function = MockFunction1{
        .allocator = allocator,
    };
    defer function.deinit();

    const mock_instruction: Air.Inst.Index = 1;

    try function.register_manager.get_reg(.r3, mock_instruction);

    try expect(!function.register_manager.is_reg_allocated(.r2));
    try expect(function.register_manager.is_reg_allocated(.r3));
    try expect(function.register_manager.is_reg_free(.r2));
    try expect(!function.register_manager.is_reg_free(.r3));

    // Spill r3
    try function.register_manager.get_reg(.r3, mock_instruction);

    try expect(!function.register_manager.is_reg_allocated(.r2));
    try expect(function.register_manager.is_reg_allocated(.r3));
    try expect(function.register_manager.is_reg_free(.r2));
    try expect(!function.register_manager.is_reg_free(.r3));
    try expect_equal_slices(MockRegister1, &[_]MockRegister1{.r3}, function.spilled.items);
}

test "alloc_reg with multiple, non-overlapping register classes" {
    const allocator = std.testing.allocator;

    var function = MockFunction3{
        .allocator = allocator,
    };
    defer function.deinit();

    const gp = MockRegister3.gp;
    const ext = MockRegister3.ext;

    const gp_reg = try function.register_manager.alloc_reg(null, gp);

    try expect(function.register_manager.is_reg_allocated(.r0));
    try expect(!function.register_manager.is_reg_allocated(.x0));

    const ext_reg = try function.register_manager.alloc_reg(null, ext);

    try expect(function.register_manager.is_reg_allocated(.r0));
    try expect(!function.register_manager.is_reg_allocated(.r1));
    try expect(function.register_manager.is_reg_allocated(.x0));
    try expect(!function.register_manager.is_reg_allocated(.x1));
    try expect(gp_reg.enc() == ext_reg.enc());

    const ext_lock = function.register_manager.lock_reg_assume_unused(ext_reg);
    defer function.register_manager.unlock_reg(ext_lock);

    const ext_reg2 = try function.register_manager.alloc_reg(null, ext);

    try expect(function.register_manager.is_reg_allocated(.r0));
    try expect(function.register_manager.is_reg_allocated(.x0));
    try expect(!function.register_manager.is_reg_allocated(.r1));
    try expect(function.register_manager.is_reg_allocated(.x1));
    try expect(ext_reg2.enc() == MockRegister3.r1.enc());
}
