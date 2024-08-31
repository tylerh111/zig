//! Verifies that liveness information is valid.

gpa: std.mem.Allocator,
air: Air,
liveness: Liveness,
live: LiveMap = .{},
blocks: std.AutoHashMapUnmanaged(Air.Inst.Index, LiveMap) = .{},
intern_pool: *const InternPool,

pub const Error = error{ LivenessInvalid, OutOfMemory };

pub fn deinit(self: *Verify) void {
    self.live.deinit(self.gpa);
    var block_it = self.blocks.value_iterator();
    while (block_it.next()) |block| block.deinit(self.gpa);
    self.blocks.deinit(self.gpa);
    self.* = undefined;
}

pub fn verify(self: *Verify) Error!void {
    self.live.clear_retaining_capacity();
    self.blocks.clear_retaining_capacity();
    try self.verify_body(self.air.get_main_body());
    // We don't care about `self.live` now, because the loop body was noreturn - everything being dead was checked on `ret` etc
    assert(self.blocks.count() == 0);
}

const LiveMap = std.AutoHashMapUnmanaged(Air.Inst.Index, void);

fn verify_body(self: *Verify, body: []const Air.Inst.Index) Error!void {
    const ip = self.intern_pool;
    const tags = self.air.instructions.items(.tag);
    const data = self.air.instructions.items(.data);
    for (body) |inst| {
        if (self.liveness.is_unused(inst) and !self.air.must_lower(inst, ip)) {
            // This instruction will not be lowered and should be ignored.
            continue;
        }

        switch (tags[@int_from_enum(inst)]) {
            // no operands
            .arg,
            .alloc,
            .inferred_alloc,
            .inferred_alloc_comptime,
            .ret_ptr,
            .breakpoint,
            .dbg_stmt,
            .fence,
            .ret_addr,
            .frame_addr,
            .wasm_memory_size,
            .err_return_trace,
            .save_err_return_trace_index,
            .c_va_start,
            .work_item_id,
            .work_group_size,
            .work_group_id,
            => try self.verify_inst_operands(inst, .{ .none, .none, .none }),

            .trap, .unreach => {
                try self.verify_inst_operands(inst, .{ .none, .none, .none });
                // This instruction terminates the function, so everything should be dead
                if (self.live.count() > 0) return invalid("%{}: instructions still alive", .{inst});
            },

            // unary
            .not,
            .bitcast,
            .load,
            .fpext,
            .fptrunc,
            .intcast,
            .trunc,
            .optional_payload,
            .optional_payload_ptr,
            .optional_payload_ptr_set,
            .errunion_payload_ptr_set,
            .wrap_optional,
            .unwrap_errunion_payload,
            .unwrap_errunion_err,
            .unwrap_errunion_payload_ptr,
            .unwrap_errunion_err_ptr,
            .wrap_errunion_payload,
            .wrap_errunion_err,
            .slice_ptr,
            .slice_len,
            .ptr_slice_len_ptr,
            .ptr_slice_ptr_ptr,
            .struct_field_ptr_index_0,
            .struct_field_ptr_index_1,
            .struct_field_ptr_index_2,
            .struct_field_ptr_index_3,
            .array_to_slice,
            .int_from_float,
            .int_from_float_optimized,
            .float_from_int,
            .get_union_tag,
            .clz,
            .ctz,
            .popcount,
            .byte_swap,
            .bit_reverse,
            .splat,
            .error_set_has_value,
            .addrspace_cast,
            .c_va_arg,
            .c_va_copy,
            .abs,
            => {
                const ty_op = data[@int_from_enum(inst)].ty_op;
                try self.verify_inst_operands(inst, .{ ty_op.operand, .none, .none });
            },
            .is_null,
            .is_non_null,
            .is_null_ptr,
            .is_non_null_ptr,
            .is_err,
            .is_non_err,
            .is_err_ptr,
            .is_non_err_ptr,
            .int_from_ptr,
            .int_from_bool,
            .is_named_enum_value,
            .tag_name,
            .error_name,
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
            .neg_optimized,
            .cmp_lt_errors_len,
            .set_err_return_trace,
            .c_va_end,
            => {
                const un_op = data[@int_from_enum(inst)].un_op;
                try self.verify_inst_operands(inst, .{ un_op, .none, .none });
            },
            .ret,
            .ret_safe,
            .ret_load,
            => {
                const un_op = data[@int_from_enum(inst)].un_op;
                try self.verify_inst_operands(inst, .{ un_op, .none, .none });
                // This instruction terminates the function, so everything should be dead
                if (self.live.count() > 0) return invalid("%{}: instructions still alive", .{inst});
            },
            .dbg_var_ptr,
            .dbg_var_val,
            .wasm_memory_grow,
            => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                try self.verify_inst_operands(inst, .{ pl_op.operand, .none, .none });
            },
            .prefetch => {
                const prefetch = data[@int_from_enum(inst)].prefetch;
                try self.verify_inst_operands(inst, .{ prefetch.ptr, .none, .none });
            },
            .reduce,
            .reduce_optimized,
            => {
                const reduce = data[@int_from_enum(inst)].reduce;
                try self.verify_inst_operands(inst, .{ reduce.operand, .none, .none });
            },
            .union_init => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.UnionInit, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.init, .none, .none });
            },
            .struct_field_ptr, .struct_field_val => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.StructField, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.struct_operand, .none, .none });
            },
            .field_parent_ptr => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.field_ptr, .none, .none });
            },
            .atomic_load => {
                const atomic_load = data[@int_from_enum(inst)].atomic_load;
                try self.verify_inst_operands(inst, .{ atomic_load.ptr, .none, .none });
            },

            // binary
            .add,
            .add_safe,
            .add_optimized,
            .add_wrap,
            .add_sat,
            .sub,
            .sub_safe,
            .sub_optimized,
            .sub_wrap,
            .sub_sat,
            .mul,
            .mul_safe,
            .mul_optimized,
            .mul_wrap,
            .mul_sat,
            .div_float,
            .div_float_optimized,
            .div_trunc,
            .div_trunc_optimized,
            .div_floor,
            .div_floor_optimized,
            .div_exact,
            .div_exact_optimized,
            .rem,
            .rem_optimized,
            .mod,
            .mod_optimized,
            .bit_and,
            .bit_or,
            .xor,
            .cmp_lt,
            .cmp_lt_optimized,
            .cmp_lte,
            .cmp_lte_optimized,
            .cmp_eq,
            .cmp_eq_optimized,
            .cmp_gte,
            .cmp_gte_optimized,
            .cmp_gt,
            .cmp_gt_optimized,
            .cmp_neq,
            .cmp_neq_optimized,
            .bool_and,
            .bool_or,
            .store,
            .store_safe,
            .array_elem_val,
            .slice_elem_val,
            .ptr_elem_val,
            .shl,
            .shl_exact,
            .shl_sat,
            .shr,
            .shr_exact,
            .atomic_store_unordered,
            .atomic_store_monotonic,
            .atomic_store_release,
            .atomic_store_seq_cst,
            .set_union_tag,
            .min,
            .max,
            .memset,
            .memset_safe,
            .memcpy,
            => {
                const bin_op = data[@int_from_enum(inst)].bin_op;
                try self.verify_inst_operands(inst, .{ bin_op.lhs, bin_op.rhs, .none });
            },
            .add_with_overflow,
            .sub_with_overflow,
            .mul_with_overflow,
            .shl_with_overflow,
            .ptr_add,
            .ptr_sub,
            .ptr_elem_ptr,
            .slice_elem_ptr,
            .slice,
            => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.Bin, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.lhs, extra.rhs, .none });
            },
            .shuffle => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.Shuffle, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.a, extra.b, .none });
            },
            .cmp_vector,
            .cmp_vector_optimized,
            => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.VectorCmp, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.lhs, extra.rhs, .none });
            },
            .atomic_rmw => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.AtomicRmw, pl_op.payload).data;
                try self.verify_inst_operands(inst, .{ pl_op.operand, extra.operand, .none });
            },

            // ternary
            .select => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
                try self.verify_inst_operands(inst, .{ pl_op.operand, extra.lhs, extra.rhs });
            },
            .mul_add => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.Bin, pl_op.payload).data;
                try self.verify_inst_operands(inst, .{ extra.lhs, extra.rhs, pl_op.operand });
            },
            .vector_store_elem => {
                const vector_store_elem = data[@int_from_enum(inst)].vector_store_elem;
                const extra = self.air.extra_data(Air.Bin, vector_store_elem.payload).data;
                try self.verify_inst_operands(inst, .{ vector_store_elem.vector_ptr, extra.lhs, extra.rhs });
            },
            .cmpxchg_strong,
            .cmpxchg_weak,
            => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;
                try self.verify_inst_operands(inst, .{ extra.ptr, extra.expected_value, extra.new_value });
            },

            // big tombs
            .aggregate_init => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const aggregate_ty = ty_pl.ty.to_type();
                const len = @as(usize, @int_cast(aggregate_ty.array_len_ip(ip)));
                const elements = @as([]const Air.Inst.Ref, @ptr_cast(self.air.extra[ty_pl.payload..][0..len]));

                var bt = self.liveness.iterate_big_tomb(inst);
                for (elements) |element| {
                    try self.verify_operand(inst, element, bt.feed());
                }
                try self.verify_inst(inst);
            },
            .call, .call_always_tail, .call_never_tail, .call_never_inline => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.Call, pl_op.payload);
                const args = @as(
                    []const Air.Inst.Ref,
                    @ptr_cast(self.air.extra[extra.end..][0..extra.data.args_len]),
                );

                var bt = self.liveness.iterate_big_tomb(inst);
                try self.verify_operand(inst, pl_op.operand, bt.feed());
                for (args) |arg| {
                    try self.verify_operand(inst, arg, bt.feed());
                }
                try self.verify_inst(inst);
            },
            .assembly => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.Asm, ty_pl.payload);
                var extra_i = extra.end;
                const outputs = @as(
                    []const Air.Inst.Ref,
                    @ptr_cast(self.air.extra[extra_i..][0..extra.data.outputs_len]),
                );
                extra_i += outputs.len;
                const inputs = @as(
                    []const Air.Inst.Ref,
                    @ptr_cast(self.air.extra[extra_i..][0..extra.data.inputs_len]),
                );
                extra_i += inputs.len;

                var bt = self.liveness.iterate_big_tomb(inst);
                for (outputs) |output| {
                    if (output != .none) {
                        try self.verify_operand(inst, output, bt.feed());
                    }
                }
                for (inputs) |input| {
                    try self.verify_operand(inst, input, bt.feed());
                }
                try self.verify_inst(inst);
            },

            // control flow
            .@"try" => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.Try, pl_op.payload);
                const try_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);

                const cond_br_liveness = self.liveness.get_cond_br(inst);

                try self.verify_operand(inst, pl_op.operand, self.liveness.operand_dies(inst, 0));

                var live = try self.live.clone(self.gpa);
                defer live.deinit(self.gpa);

                for (cond_br_liveness.else_deaths) |death| try self.verify_death(inst, death);
                try self.verify_body(try_body);

                self.live.deinit(self.gpa);
                self.live = live.move();

                for (cond_br_liveness.then_deaths) |death| try self.verify_death(inst, death);

                try self.verify_inst(inst);
            },
            .try_ptr => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.TryPtr, ty_pl.payload);
                const try_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);

                const cond_br_liveness = self.liveness.get_cond_br(inst);

                try self.verify_operand(inst, extra.data.ptr, self.liveness.operand_dies(inst, 0));

                var live = try self.live.clone(self.gpa);
                defer live.deinit(self.gpa);

                for (cond_br_liveness.else_deaths) |death| try self.verify_death(inst, death);
                try self.verify_body(try_body);

                self.live.deinit(self.gpa);
                self.live = live.move();

                for (cond_br_liveness.then_deaths) |death| try self.verify_death(inst, death);

                try self.verify_inst(inst);
            },
            .br => {
                const br = data[@int_from_enum(inst)].br;
                const gop = try self.blocks.get_or_put(self.gpa, br.block_inst);

                try self.verify_operand(inst, br.operand, self.liveness.operand_dies(inst, 0));
                if (gop.found_existing) {
                    try self.verify_matching_liveness(br.block_inst, gop.value_ptr.*);
                } else {
                    gop.value_ptr.* = try self.live.clone(self.gpa);
                }
                try self.verify_inst(inst);
            },
            .block, .dbg_inline_block => |tag| {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const block_ty = ty_pl.ty.to_type();
                const block_body: []const Air.Inst.Index = @ptr_cast(switch (tag) {
                    inline .block, .dbg_inline_block => |comptime_tag| body: {
                        const extra = self.air.extra_data(switch (comptime_tag) {
                            .block => Air.Block,
                            .dbg_inline_block => Air.DbgInlineBlock,
                            else => unreachable,
                        }, ty_pl.payload);
                        break :body self.air.extra[extra.end..][0..extra.data.body_len];
                    },
                    else => unreachable,
                });
                const block_liveness = self.liveness.get_block(inst);

                var orig_live = try self.live.clone(self.gpa);
                defer orig_live.deinit(self.gpa);

                assert(!self.blocks.contains(inst));
                try self.verify_body(block_body);

                // Liveness data after the block body is garbage, but we want to
                // restore it to verify deaths
                self.live.deinit(self.gpa);
                self.live = orig_live.move();

                for (block_liveness.deaths) |death| try self.verify_death(inst, death);

                if (ip.is_no_return(block_ty.to_intern())) {
                    assert(!self.blocks.contains(inst));
                } else {
                    var live = self.blocks.fetch_remove(inst).?.value;
                    defer live.deinit(self.gpa);

                    try self.verify_matching_liveness(inst, live);
                }

                try self.verify_inst_operands(inst, .{ .none, .none, .none });
            },
            .loop => {
                const ty_pl = data[@int_from_enum(inst)].ty_pl;
                const extra = self.air.extra_data(Air.Block, ty_pl.payload);
                const loop_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.body_len]);

                var live = try self.live.clone(self.gpa);
                defer live.deinit(self.gpa);

                try self.verify_body(loop_body);

                // The same stuff should be alive after the loop as before it
                try self.verify_matching_liveness(inst, live);

                try self.verify_inst_operands(inst, .{ .none, .none, .none });
            },
            .cond_br => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const extra = self.air.extra_data(Air.CondBr, pl_op.payload);
                const then_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end..][0..extra.data.then_body_len]);
                const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
                const cond_br_liveness = self.liveness.get_cond_br(inst);

                try self.verify_operand(inst, pl_op.operand, self.liveness.operand_dies(inst, 0));

                var live = try self.live.clone(self.gpa);
                defer live.deinit(self.gpa);

                for (cond_br_liveness.then_deaths) |death| try self.verify_death(inst, death);
                try self.verify_body(then_body);

                self.live.deinit(self.gpa);
                self.live = live.move();

                for (cond_br_liveness.else_deaths) |death| try self.verify_death(inst, death);
                try self.verify_body(else_body);

                try self.verify_inst(inst);
            },
            .switch_br => {
                const pl_op = data[@int_from_enum(inst)].pl_op;
                const switch_br = self.air.extra_data(Air.SwitchBr, pl_op.payload);
                var extra_index = switch_br.end;
                var case_i: u32 = 0;
                const switch_br_liveness = try self.liveness.get_switch_br(
                    self.gpa,
                    inst,
                    switch_br.data.cases_len + 1,
                );
                defer self.gpa.free(switch_br_liveness.deaths);

                try self.verify_operand(inst, pl_op.operand, self.liveness.operand_dies(inst, 0));

                var live = self.live.move();
                defer live.deinit(self.gpa);

                while (case_i < switch_br.data.cases_len) : (case_i += 1) {
                    const case = self.air.extra_data(Air.SwitchBr.Case, extra_index);
                    const items = @as(
                        []const Air.Inst.Ref,
                        @ptr_cast(self.air.extra[case.end..][0..case.data.items_len]),
                    );
                    const case_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[case.end + items.len ..][0..case.data.body_len]);
                    extra_index = case.end + items.len + case_body.len;

                    self.live.deinit(self.gpa);
                    self.live = try live.clone(self.gpa);

                    for (switch_br_liveness.deaths[case_i]) |death| try self.verify_death(inst, death);
                    try self.verify_body(case_body);
                }

                const else_body: []const Air.Inst.Index = @ptr_cast(self.air.extra[extra_index..][0..switch_br.data.else_body_len]);
                if (else_body.len > 0) {
                    self.live.deinit(self.gpa);
                    self.live = try live.clone(self.gpa);

                    for (switch_br_liveness.deaths[case_i]) |death| try self.verify_death(inst, death);
                    try self.verify_body(else_body);
                }

                try self.verify_inst(inst);
            },
        }
    }
}

fn verify_death(self: *Verify, inst: Air.Inst.Index, operand: Air.Inst.Index) Error!void {
    try self.verify_operand(inst, operand.to_ref(), true);
}

fn verify_operand(self: *Verify, inst: Air.Inst.Index, op_ref: Air.Inst.Ref, dies: bool) Error!void {
    const operand = op_ref.to_index_allow_none() orelse {
        assert(!dies);
        return;
    };
    if (dies) {
        if (!self.live.remove(operand)) return invalid("%{}: dead operand %{} reused and killed again", .{ inst, operand });
    } else {
        if (!self.live.contains(operand)) return invalid("%{}: dead operand %{} reused", .{ inst, operand });
    }
}

fn verify_inst_operands(
    self: *Verify,
    inst: Air.Inst.Index,
    operands: [Liveness.bpi - 1]Air.Inst.Ref,
) Error!void {
    for (operands, 0..) |operand, operand_index| {
        const dies = self.liveness.operand_dies(inst, @as(Liveness.OperandInt, @int_cast(operand_index)));
        try self.verify_operand(inst, operand, dies);
    }
    try self.verify_inst(inst);
}

fn verify_inst(self: *Verify, inst: Air.Inst.Index) Error!void {
    if (self.liveness.is_unused(inst)) {
        assert(!self.live.contains(inst));
    } else {
        try self.live.put_no_clobber(self.gpa, inst, {});
    }
}

fn verify_matching_liveness(self: *Verify, block: Air.Inst.Index, live: LiveMap) Error!void {
    if (self.live.count() != live.count()) return invalid("%{}: different deaths across branches", .{block});
    var live_it = self.live.key_iterator();
    while (live_it.next()) |live_inst| if (!live.contains(live_inst.*)) return invalid("%{}: different deaths across branches", .{block});
}

fn invalid(comptime fmt: []const u8, args: anytype) error{LivenessInvalid} {
    log.err(fmt, args);
    return error.LivenessInvalid;
}

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.liveness_verify);

const Air = @import("../Air.zig");
const Liveness = @import("../Liveness.zig");
const InternPool = @import("../InternPool.zig");
const Verify = @This();
