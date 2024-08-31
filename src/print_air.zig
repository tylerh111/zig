const std = @import("std");
const Allocator = std.mem.Allocator;
const fmt_int_size_bin = std.fmt.fmt_int_size_bin;

const Module = @import("Module.zig");
const Value = @import("Value.zig");
const Type = @import("type.zig").Type;
const Air = @import("Air.zig");
const Liveness = @import("Liveness.zig");
const InternPool = @import("InternPool.zig");

pub fn write(stream: anytype, module: *Module, air: Air, liveness: ?Liveness) void {
    const instruction_bytes = air.instructions.len *
        // Here we don't use @size_of(Air.Inst.Data) because it would include
        // the debug safety tag but we want to measure release size.
        (@size_of(Air.Inst.Tag) + 8);
    const extra_bytes = air.extra.len * @size_of(u32);
    const tomb_bytes = if (liveness) |l| l.tomb_bits.len * @size_of(usize) else 0;
    const liveness_extra_bytes = if (liveness) |l| l.extra.len * @size_of(u32) else 0;
    const liveness_special_bytes = if (liveness) |l| l.special.count() * 8 else 0;
    const total_bytes = @size_of(Air) + instruction_bytes + extra_bytes +
        @size_of(Liveness) + liveness_extra_bytes +
        liveness_special_bytes + tomb_bytes;

    // zig fmt: off
    stream.print(
        \\# Total AIR+Liveness bytes: {}
        \\# AIR Instructions:         {d} ({})
        \\# AIR Extra Data:           {d} ({})
        \\# Liveness tomb_bits:       {}
        \\# Liveness Extra Data:      {d} ({})
        \\# Liveness special table:   {d} ({})
        \\
    , .{
        fmt_int_size_bin(total_bytes),
        air.instructions.len, fmt_int_size_bin(instruction_bytes),
        air.extra.len, fmt_int_size_bin(extra_bytes),
        fmt_int_size_bin(tomb_bytes),
        if (liveness) |l| l.extra.len else 0, fmt_int_size_bin(liveness_extra_bytes),
        if (liveness) |l| l.special.count() else 0, fmt_int_size_bin(liveness_special_bytes),
    }) catch return;
    // zig fmt: on

    var writer: Writer = .{
        .module = module,
        .gpa = module.gpa,
        .air = air,
        .liveness = liveness,
        .indent = 2,
        .skip_body = false,
    };
    writer.write_body(stream, air.get_main_body()) catch return;
}

pub fn write_inst(
    stream: anytype,
    inst: Air.Inst.Index,
    module: *Module,
    air: Air,
    liveness: ?Liveness,
) void {
    var writer: Writer = .{
        .module = module,
        .gpa = module.gpa,
        .air = air,
        .liveness = liveness,
        .indent = 2,
        .skip_body = true,
    };
    writer.write_inst(stream, inst) catch return;
}

pub fn dump(module: *Module, air: Air, liveness: ?Liveness) void {
    write(std.io.get_std_err().writer(), module, air, liveness);
}

pub fn dump_inst(inst: Air.Inst.Index, module: *Module, air: Air, liveness: ?Liveness) void {
    write_inst(std.io.get_std_err().writer(), inst, module, air, liveness);
}

const Writer = struct {
    module: *Module,
    gpa: Allocator,
    air: Air,
    liveness: ?Liveness,
    indent: usize,
    skip_body: bool,

    fn write_body(w: *Writer, s: anytype, body: []const Air.Inst.Index) @TypeOf(s).Error!void {
        for (body) |inst| {
            try w.write_inst(s, inst);
            try s.write_byte('\n');
        }
    }

    fn write_inst(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const tag = w.air.instructions.items(.tag)[@int_from_enum(inst)];
        try s.write_byte_ntimes(' ', w.indent);
        try s.print("%{d}{c}= {s}(", .{
            @int_from_enum(inst),
            @as(u8, if (if (w.liveness) |liveness| liveness.is_unused(inst) else false) '!' else ' '),
            @tag_name(tag),
        });
        switch (tag) {
            .add,
            .add_optimized,
            .add_safe,
            .add_wrap,
            .add_sat,
            .sub,
            .sub_optimized,
            .sub_safe,
            .sub_wrap,
            .sub_sat,
            .mul,
            .mul_optimized,
            .mul_safe,
            .mul_wrap,
            .mul_sat,
            .div_float,
            .div_trunc,
            .div_floor,
            .div_exact,
            .rem,
            .mod,
            .bit_and,
            .bit_or,
            .xor,
            .cmp_lt,
            .cmp_lte,
            .cmp_eq,
            .cmp_gte,
            .cmp_gt,
            .cmp_neq,
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
            .set_union_tag,
            .min,
            .max,
            .div_float_optimized,
            .div_trunc_optimized,
            .div_floor_optimized,
            .div_exact_optimized,
            .rem_optimized,
            .mod_optimized,
            .cmp_lt_optimized,
            .cmp_lte_optimized,
            .cmp_eq_optimized,
            .cmp_gte_optimized,
            .cmp_gt_optimized,
            .cmp_neq_optimized,
            .memcpy,
            .memset,
            .memset_safe,
            => try w.write_bin_op(s, inst),

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
            .ret,
            .ret_safe,
            .ret_load,
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
            => try w.write_un_op(s, inst),

            .trap,
            .breakpoint,
            .unreach,
            .ret_addr,
            .frame_addr,
            .save_err_return_trace_index,
            => try w.write_no_op(s, inst),

            .alloc,
            .ret_ptr,
            .err_return_trace,
            .c_va_start,
            => try w.write_ty(s, inst),

            .arg => try w.write_arg(s, inst),

            .not,
            .bitcast,
            .load,
            .fptrunc,
            .fpext,
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
            .float_from_int,
            .splat,
            .int_from_float,
            .int_from_float_optimized,
            .get_union_tag,
            .clz,
            .ctz,
            .popcount,
            .byte_swap,
            .bit_reverse,
            .abs,
            .error_set_has_value,
            .addrspace_cast,
            .c_va_arg,
            .c_va_copy,
            => try w.write_ty_op(s, inst),

            .block, .dbg_inline_block => try w.write_block(s, tag, inst),

            .loop => try w.write_loop(s, inst),

            .slice,
            .slice_elem_ptr,
            .ptr_elem_ptr,
            .ptr_add,
            .ptr_sub,
            .add_with_overflow,
            .sub_with_overflow,
            .mul_with_overflow,
            .shl_with_overflow,
            => try w.write_ty_pl_bin(s, inst),

            .call,
            .call_always_tail,
            .call_never_tail,
            .call_never_inline,
            => try w.write_call(s, inst),

            .dbg_var_ptr,
            .dbg_var_val,
            => try w.write_dbg_var(s, inst),

            .struct_field_ptr => try w.write_struct_field(s, inst),
            .struct_field_val => try w.write_struct_field(s, inst),
            .inferred_alloc => @panic("TODO"),
            .inferred_alloc_comptime => @panic("TODO"),
            .assembly => try w.write_assembly(s, inst),
            .dbg_stmt => try w.write_dbg_stmt(s, inst),

            .aggregate_init => try w.write_aggregate_init(s, inst),
            .union_init => try w.write_union_init(s, inst),
            .br => try w.write_br(s, inst),
            .cond_br => try w.write_cond_br(s, inst),
            .@"try" => try w.write_try(s, inst),
            .try_ptr => try w.write_try_ptr(s, inst),
            .switch_br => try w.write_switch_br(s, inst),
            .cmpxchg_weak, .cmpxchg_strong => try w.write_cmpxchg(s, inst),
            .fence => try w.write_fence(s, inst),
            .atomic_load => try w.write_atomic_load(s, inst),
            .prefetch => try w.write_prefetch(s, inst),
            .atomic_store_unordered => try w.write_atomic_store(s, inst, .unordered),
            .atomic_store_monotonic => try w.write_atomic_store(s, inst, .monotonic),
            .atomic_store_release => try w.write_atomic_store(s, inst, .release),
            .atomic_store_seq_cst => try w.write_atomic_store(s, inst, .seq_cst),
            .atomic_rmw => try w.write_atomic_rmw(s, inst),
            .field_parent_ptr => try w.write_field_parent_ptr(s, inst),
            .wasm_memory_size => try w.write_wasm_memory_size(s, inst),
            .wasm_memory_grow => try w.write_wasm_memory_grow(s, inst),
            .mul_add => try w.write_mul_add(s, inst),
            .select => try w.write_select(s, inst),
            .shuffle => try w.write_shuffle(s, inst),
            .reduce, .reduce_optimized => try w.write_reduce(s, inst),
            .cmp_vector, .cmp_vector_optimized => try w.write_cmp_vector(s, inst),
            .vector_store_elem => try w.write_vector_store_elem(s, inst),

            .work_item_id,
            .work_group_size,
            .work_group_id,
            => try w.write_work_dimension(s, inst),
        }
        try s.write_byte(')');
    }

    fn write_bin_op(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const bin_op = w.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        try w.write_operand(s, inst, 0, bin_op.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, bin_op.rhs);
    }

    fn write_un_op(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const un_op = w.air.instructions.items(.data)[@int_from_enum(inst)].un_op;
        try w.write_operand(s, inst, 0, un_op);
    }

    fn write_no_op(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        _ = w;
        _ = inst;
        // no-op, no argument to write
    }

    fn write_type(w: *Writer, s: anytype, ty: Type) !void {
        return ty.print(s, w.module);
    }

    fn write_ty(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty = w.air.instructions.items(.data)[@int_from_enum(inst)].ty;
        try w.write_type(s, ty);
    }

    fn write_arg(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const arg = w.air.instructions.items(.data)[@int_from_enum(inst)].arg;
        try w.write_type(s, arg.ty.to_type());
        try s.print(", {d}", .{arg.src_index});
    }

    fn write_ty_op(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_op = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_op;
        try w.write_type(s, ty_op.ty.to_type());
        try s.write_all(", ");
        try w.write_operand(s, inst, 0, ty_op.operand);
    }

    fn write_block(w: *Writer, s: anytype, tag: Air.Inst.Tag, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        try w.write_type(s, ty_pl.ty.to_type());
        const body: []const Air.Inst.Index = @ptr_cast(switch (tag) {
            inline .block, .dbg_inline_block => |comptime_tag| body: {
                const extra = w.air.extra_data(switch (comptime_tag) {
                    .block => Air.Block,
                    .dbg_inline_block => Air.DbgInlineBlock,
                    else => unreachable,
                }, ty_pl.payload);
                switch (comptime_tag) {
                    .block => {},
                    .dbg_inline_block => {
                        try s.write_all(", ");
                        try w.write_inst_ref(s, Air.interned_to_ref(extra.data.func), false);
                    },
                    else => unreachable,
                }
                break :body w.air.extra[extra.end..][0..extra.data.body_len];
            },
            else => unreachable,
        });
        if (w.skip_body) return s.write_all(", ...");
        const liveness_block = if (w.liveness) |liveness|
            liveness.get_block(inst)
        else
            Liveness.BlockSlices{ .deaths = &.{} };

        try s.write_all(", {\n");
        const old_indent = w.indent;
        w.indent += 2;
        try w.write_body(s, body);
        w.indent = old_indent;
        try s.write_byte_ntimes(' ', w.indent);
        try s.write_all("}");

        for (liveness_block.deaths) |operand| {
            try s.print(" %{d}!", .{@int_from_enum(operand)});
        }
    }

    fn write_loop(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.Block, ty_pl.payload);
        const body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra.end..][0..extra.data.body_len]);

        try w.write_type(s, ty_pl.ty.to_type());
        if (w.skip_body) return s.write_all(", ...");
        try s.write_all(", {\n");
        const old_indent = w.indent;
        w.indent += 2;
        try w.write_body(s, body);
        w.indent = old_indent;
        try s.write_byte_ntimes(' ', w.indent);
        try s.write_all("}");
    }

    fn write_aggregate_init(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const mod = w.module;
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const vector_ty = ty_pl.ty.to_type();
        const len = @as(usize, @int_cast(vector_ty.array_len(mod)));
        const elements = @as([]const Air.Inst.Ref, @ptr_cast(w.air.extra[ty_pl.payload..][0..len]));

        try w.write_type(s, vector_ty);
        try s.write_all(", [");
        for (elements, 0..) |elem, i| {
            if (i != 0) try s.write_all(", ");
            try w.write_operand(s, inst, i, elem);
        }
        try s.write_all("]");
    }

    fn write_union_init(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.UnionInit, ty_pl.payload).data;

        try s.print("{d}, ", .{extra.field_index});
        try w.write_operand(s, inst, 0, extra.init);
    }

    fn write_struct_field(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.StructField, ty_pl.payload).data;

        try w.write_operand(s, inst, 0, extra.struct_operand);
        try s.print(", {d}", .{extra.field_index});
    }

    fn write_ty_pl_bin(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const data = w.air.instructions.items(.data);
        const ty_pl = data[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.Bin, ty_pl.payload).data;

        const inst_ty = data[@int_from_enum(inst)].ty_pl.ty.to_type();
        try w.write_type(s, inst_ty);
        try s.write_all(", ");
        try w.write_operand(s, inst, 0, extra.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.rhs);
    }

    fn write_cmpxchg(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.Cmpxchg, ty_pl.payload).data;

        try w.write_operand(s, inst, 0, extra.ptr);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.expected_value);
        try s.write_all(", ");
        try w.write_operand(s, inst, 2, extra.new_value);
        try s.print(", {s}, {s}", .{
            @tag_name(extra.success_order()), @tag_name(extra.failure_order()),
        });
    }

    fn write_mul_add(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.Bin, pl_op.payload).data;

        try w.write_operand(s, inst, 0, extra.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.rhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 2, pl_op.operand);
    }

    fn write_shuffle(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.Shuffle, ty_pl.payload).data;

        try w.write_operand(s, inst, 0, extra.a);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.b);
        try s.print(", mask {d}, len {d}", .{ extra.mask, extra.mask_len });
    }

    fn write_select(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const mod = w.module;
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.Bin, pl_op.payload).data;

        const elem_ty = w.type_of_index(inst).child_type(mod);
        try w.write_type(s, elem_ty);
        try s.write_all(", ");
        try w.write_operand(s, inst, 0, pl_op.operand);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 2, extra.rhs);
    }

    fn write_reduce(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const reduce = w.air.instructions.items(.data)[@int_from_enum(inst)].reduce;

        try w.write_operand(s, inst, 0, reduce.operand);
        try s.print(", {s}", .{@tag_name(reduce.operation)});
    }

    fn write_cmp_vector(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.VectorCmp, ty_pl.payload).data;

        try s.print("{s}, ", .{@tag_name(extra.compare_operator())});
        try w.write_operand(s, inst, 0, extra.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.rhs);
    }

    fn write_vector_store_elem(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const data = w.air.instructions.items(.data)[@int_from_enum(inst)].vector_store_elem;
        const extra = w.air.extra_data(Air.VectorCmp, data.payload).data;

        try w.write_operand(s, inst, 0, data.vector_ptr);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 2, extra.rhs);
    }

    fn write_fence(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const atomic_order = w.air.instructions.items(.data)[@int_from_enum(inst)].fence;

        try s.print("{s}", .{@tag_name(atomic_order)});
    }

    fn write_atomic_load(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const atomic_load = w.air.instructions.items(.data)[@int_from_enum(inst)].atomic_load;

        try w.write_operand(s, inst, 0, atomic_load.ptr);
        try s.print(", {s}", .{@tag_name(atomic_load.order)});
    }

    fn write_prefetch(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const prefetch = w.air.instructions.items(.data)[@int_from_enum(inst)].prefetch;

        try w.write_operand(s, inst, 0, prefetch.ptr);
        try s.print(", {s}, {d}, {s}", .{
            @tag_name(prefetch.rw), prefetch.locality, @tag_name(prefetch.cache),
        });
    }

    fn write_atomic_store(
        w: *Writer,
        s: anytype,
        inst: Air.Inst.Index,
        order: std.builtin.AtomicOrder,
    ) @TypeOf(s).Error!void {
        const bin_op = w.air.instructions.items(.data)[@int_from_enum(inst)].bin_op;
        try w.write_operand(s, inst, 0, bin_op.lhs);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, bin_op.rhs);
        try s.print(", {s}", .{@tag_name(order)});
    }

    fn write_atomic_rmw(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.AtomicRmw, pl_op.payload).data;

        try w.write_operand(s, inst, 0, pl_op.operand);
        try s.write_all(", ");
        try w.write_operand(s, inst, 1, extra.operand);
        try s.print(", {s}, {s}", .{ @tag_name(extra.op()), @tag_name(extra.ordering()) });
    }

    fn write_field_parent_ptr(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.FieldParentPtr, ty_pl.payload).data;

        try w.write_operand(s, inst, 0, extra.field_ptr);
        try s.print(", {d}", .{extra.field_index});
    }

    fn write_assembly(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.Asm, ty_pl.payload);
        const is_volatile = @as(u1, @truncate(extra.data.flags >> 31)) != 0;
        const clobbers_len = @as(u31, @truncate(extra.data.flags));
        var extra_i: usize = extra.end;
        var op_index: usize = 0;

        const ret_ty = w.type_of_index(inst);
        try w.write_type(s, ret_ty);

        if (is_volatile) {
            try s.write_all(", volatile");
        }

        const outputs = @as([]const Air.Inst.Ref, @ptr_cast(w.air.extra[extra_i..][0..extra.data.outputs_len]));
        extra_i += outputs.len;
        const inputs = @as([]const Air.Inst.Ref, @ptr_cast(w.air.extra[extra_i..][0..extra.data.inputs_len]));
        extra_i += inputs.len;

        for (outputs) |output| {
            const extra_bytes = std.mem.slice_as_bytes(w.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(extra_bytes, 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);

            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the strings and their null terminators, we still use the next u32
            // for the null terminator.
            extra_i += (constraint.len + name.len + (2 + 3)) / 4;

            if (output == .none) {
                try s.print(", [{s}] -> {s}", .{ name, constraint });
            } else {
                try s.print(", [{s}] out {s} = (", .{ name, constraint });
                try w.write_operand(s, inst, op_index, output);
                op_index += 1;
                try s.write_byte(')');
            }
        }

        for (inputs) |input| {
            const extra_bytes = std.mem.slice_as_bytes(w.air.extra[extra_i..]);
            const constraint = std.mem.slice_to(extra_bytes, 0);
            const name = std.mem.slice_to(extra_bytes[constraint.len + 1 ..], 0);
            // This equation accounts for the fact that even if we have exactly 4 bytes
            // for the strings and their null terminators, we still use the next u32
            // for the null terminator.
            extra_i += (constraint.len + name.len + 1) / 4 + 1;

            try s.print(", [{s}] in {s} = (", .{ name, constraint });
            try w.write_operand(s, inst, op_index, input);
            op_index += 1;
            try s.write_byte(')');
        }

        {
            var clobber_i: u32 = 0;
            while (clobber_i < clobbers_len) : (clobber_i += 1) {
                const extra_bytes = std.mem.slice_as_bytes(w.air.extra[extra_i..]);
                const clobber = std.mem.slice_to(extra_bytes, 0);
                // This equation accounts for the fact that even if we have exactly 4 bytes
                // for the string, we still use the next u32 for the null terminator.
                extra_i += clobber.len / 4 + 1;

                try s.write_all(", ~{");
                try s.write_all(clobber);
                try s.write_all("}");
            }
        }
        const asm_source = std.mem.slice_as_bytes(w.air.extra[extra_i..])[0..extra.data.source_len];
        try s.print(", \"{s}\"", .{asm_source});
    }

    fn write_dbg_stmt(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const dbg_stmt = w.air.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
        try s.print("{d}:{d}", .{ dbg_stmt.line + 1, dbg_stmt.column + 1 });
    }

    fn write_dbg_var(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        try w.write_operand(s, inst, 0, pl_op.operand);
        const name = w.air.null_terminated_string(pl_op.payload);
        try s.print(", \"{}\"", .{std.zig.fmt_escapes(name)});
    }

    fn write_call(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.Call, pl_op.payload);
        const args = @as([]const Air.Inst.Ref, @ptr_cast(w.air.extra[extra.end..][0..extra.data.args_len]));
        try w.write_operand(s, inst, 0, pl_op.operand);
        try s.write_all(", [");
        for (args, 0..) |arg, i| {
            if (i != 0) try s.write_all(", ");
            try w.write_operand(s, inst, 1 + i, arg);
        }
        try s.write_all("]");
    }

    fn write_br(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const br = w.air.instructions.items(.data)[@int_from_enum(inst)].br;
        try w.write_inst_index(s, br.block_inst, false);
        try s.write_all(", ");
        try w.write_operand(s, inst, 0, br.operand);
    }

    fn write_try(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.Try, pl_op.payload);
        const body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra.end..][0..extra.data.body_len]);
        const liveness_condbr = if (w.liveness) |liveness|
            liveness.get_cond_br(inst)
        else
            Liveness.CondBrSlices{ .then_deaths = &.{}, .else_deaths = &.{} };

        try w.write_operand(s, inst, 0, pl_op.operand);
        if (w.skip_body) return s.write_all(", ...");
        try s.write_all(", {\n");
        const old_indent = w.indent;
        w.indent += 2;

        if (liveness_condbr.else_deaths.len != 0) {
            try s.write_byte_ntimes(' ', w.indent);
            for (liveness_condbr.else_deaths, 0..) |operand, i| {
                if (i != 0) try s.write_all(" ");
                try s.print("%{d}!", .{@int_from_enum(operand)});
            }
            try s.write_all("\n");
        }
        try w.write_body(s, body);

        w.indent = old_indent;
        try s.write_byte_ntimes(' ', w.indent);
        try s.write_all("}");

        for (liveness_condbr.then_deaths) |operand| {
            try s.print(" %{d}!", .{@int_from_enum(operand)});
        }
    }

    fn write_try_ptr(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const ty_pl = w.air.instructions.items(.data)[@int_from_enum(inst)].ty_pl;
        const extra = w.air.extra_data(Air.TryPtr, ty_pl.payload);
        const body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra.end..][0..extra.data.body_len]);
        const liveness_condbr = if (w.liveness) |liveness|
            liveness.get_cond_br(inst)
        else
            Liveness.CondBrSlices{ .then_deaths = &.{}, .else_deaths = &.{} };

        try w.write_operand(s, inst, 0, extra.data.ptr);

        try s.write_all(", ");
        try w.write_type(s, ty_pl.ty.to_type());
        if (w.skip_body) return s.write_all(", ...");
        try s.write_all(", {\n");
        const old_indent = w.indent;
        w.indent += 2;

        if (liveness_condbr.else_deaths.len != 0) {
            try s.write_byte_ntimes(' ', w.indent);
            for (liveness_condbr.else_deaths, 0..) |operand, i| {
                if (i != 0) try s.write_all(" ");
                try s.print("%{d}!", .{@int_from_enum(operand)});
            }
            try s.write_all("\n");
        }
        try w.write_body(s, body);

        w.indent = old_indent;
        try s.write_byte_ntimes(' ', w.indent);
        try s.write_all("}");

        for (liveness_condbr.then_deaths) |operand| {
            try s.print(" %{d}!", .{@int_from_enum(operand)});
        }
    }

    fn write_cond_br(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const extra = w.air.extra_data(Air.CondBr, pl_op.payload);
        const then_body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra.end..][0..extra.data.then_body_len]);
        const else_body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra.end + then_body.len ..][0..extra.data.else_body_len]);
        const liveness_condbr = if (w.liveness) |liveness|
            liveness.get_cond_br(inst)
        else
            Liveness.CondBrSlices{ .then_deaths = &.{}, .else_deaths = &.{} };

        try w.write_operand(s, inst, 0, pl_op.operand);
        if (w.skip_body) return s.write_all(", ...");
        try s.write_all(", {\n");
        const old_indent = w.indent;
        w.indent += 2;

        if (liveness_condbr.then_deaths.len != 0) {
            try s.write_byte_ntimes(' ', w.indent);
            for (liveness_condbr.then_deaths, 0..) |operand, i| {
                if (i != 0) try s.write_all(" ");
                try s.print("%{d}!", .{@int_from_enum(operand)});
            }
            try s.write_all("\n");
        }

        try w.write_body(s, then_body);
        try s.write_byte_ntimes(' ', old_indent);
        try s.write_all("}, {\n");

        if (liveness_condbr.else_deaths.len != 0) {
            try s.write_byte_ntimes(' ', w.indent);
            for (liveness_condbr.else_deaths, 0..) |operand, i| {
                if (i != 0) try s.write_all(" ");
                try s.print("%{d}!", .{@int_from_enum(operand)});
            }
            try s.write_all("\n");
        }

        try w.write_body(s, else_body);
        w.indent = old_indent;

        try s.write_byte_ntimes(' ', old_indent);
        try s.write_all("}");
    }

    fn write_switch_br(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        const switch_br = w.air.extra_data(Air.SwitchBr, pl_op.payload);
        const liveness = if (w.liveness) |liveness|
            liveness.get_switch_br(w.gpa, inst, switch_br.data.cases_len + 1) catch
                @panic("out of memory")
        else blk: {
            const slice = w.gpa.alloc([]const Air.Inst.Index, switch_br.data.cases_len + 1) catch
                @panic("out of memory");
            @memset(slice, &.{});
            break :blk Liveness.SwitchBrTable{ .deaths = slice };
        };
        defer w.gpa.free(liveness.deaths);
        var extra_index: usize = switch_br.end;
        var case_i: u32 = 0;

        try w.write_operand(s, inst, 0, pl_op.operand);
        if (w.skip_body) return s.write_all(", ...");
        const old_indent = w.indent;
        w.indent += 2;

        while (case_i < switch_br.data.cases_len) : (case_i += 1) {
            const case = w.air.extra_data(Air.SwitchBr.Case, extra_index);
            const items = @as([]const Air.Inst.Ref, @ptr_cast(w.air.extra[case.end..][0..case.data.items_len]));
            const case_body: []const Air.Inst.Index = @ptr_cast(w.air.extra[case.end + items.len ..][0..case.data.body_len]);
            extra_index = case.end + case.data.items_len + case_body.len;

            try s.write_all(", [");
            for (items, 0..) |item, item_i| {
                if (item_i != 0) try s.write_all(", ");
                try w.write_inst_ref(s, item, false);
            }
            try s.write_all("] => {\n");
            w.indent += 2;

            const deaths = liveness.deaths[case_i];
            if (deaths.len != 0) {
                try s.write_byte_ntimes(' ', w.indent);
                for (deaths, 0..) |operand, i| {
                    if (i != 0) try s.write_all(" ");
                    try s.print("%{d}!", .{@int_from_enum(operand)});
                }
                try s.write_all("\n");
            }

            try w.write_body(s, case_body);
            w.indent -= 2;
            try s.write_byte_ntimes(' ', w.indent);
            try s.write_all("}");
        }

        const else_body: []const Air.Inst.Index = @ptr_cast(w.air.extra[extra_index..][0..switch_br.data.else_body_len]);
        if (else_body.len != 0) {
            try s.write_all(", else => {\n");
            w.indent += 2;

            const deaths = liveness.deaths[liveness.deaths.len - 1];
            if (deaths.len != 0) {
                try s.write_byte_ntimes(' ', w.indent);
                for (deaths, 0..) |operand, i| {
                    if (i != 0) try s.write_all(" ");
                    try s.print("%{d}!", .{@int_from_enum(operand)});
                }
                try s.write_all("\n");
            }

            try w.write_body(s, else_body);
            w.indent -= 2;
            try s.write_byte_ntimes(' ', w.indent);
            try s.write_all("}");
        }

        try s.write_all("\n");
        try s.write_byte_ntimes(' ', old_indent);
    }

    fn write_wasm_memory_size(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        try s.print("{d}", .{pl_op.payload});
    }

    fn write_wasm_memory_grow(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        try s.print("{d}, ", .{pl_op.payload});
        try w.write_operand(s, inst, 0, pl_op.operand);
    }

    fn write_work_dimension(w: *Writer, s: anytype, inst: Air.Inst.Index) @TypeOf(s).Error!void {
        const pl_op = w.air.instructions.items(.data)[@int_from_enum(inst)].pl_op;
        try s.print("{d}", .{pl_op.payload});
    }

    fn write_operand(
        w: *Writer,
        s: anytype,
        inst: Air.Inst.Index,
        op_index: usize,
        operand: Air.Inst.Ref,
    ) @TypeOf(s).Error!void {
        const small_tomb_bits = Liveness.bpi - 1;
        const dies = if (w.liveness) |liveness| blk: {
            if (op_index < small_tomb_bits)
                break :blk liveness.operand_dies(inst, @as(Liveness.OperandInt, @int_cast(op_index)));
            var extra_index = liveness.special.get(inst).?;
            var tomb_op_index: usize = small_tomb_bits;
            while (true) {
                const bits = liveness.extra[extra_index];
                if (op_index < tomb_op_index + 31) {
                    break :blk @as(u1, @truncate(bits >> @as(u5, @int_cast(op_index - tomb_op_index)))) != 0;
                }
                if ((bits >> 31) != 0) break :blk false;
                extra_index += 1;
                tomb_op_index += 31;
            }
        } else false;
        return w.write_inst_ref(s, operand, dies);
    }

    fn write_inst_ref(
        w: *Writer,
        s: anytype,
        operand: Air.Inst.Ref,
        dies: bool,
    ) @TypeOf(s).Error!void {
        if (@int_from_enum(operand) < InternPool.static_len) {
            return s.print("@{}", .{operand});
        } else if (operand.to_interned()) |ip_index| {
            const mod = w.module;
            const ty = Type.from_interned(mod.intern_pool.index_to_key(ip_index).type_of());
            try s.print("<{}, {}>", .{
                ty.fmt(mod),
                Value.from_interned(ip_index).fmt_value(mod, null),
            });
        } else {
            return w.write_inst_index(s, operand.to_index().?, dies);
        }
    }

    fn write_inst_index(
        w: *Writer,
        s: anytype,
        inst: Air.Inst.Index,
        dies: bool,
    ) @TypeOf(s).Error!void {
        _ = w;
        try s.print("%{d}", .{@int_from_enum(inst)});
        if (dies) try s.write_byte('!');
    }

    fn type_of_index(w: *Writer, inst: Air.Inst.Index) Type {
        const mod = w.module;
        return w.air.type_of_index(inst, &mod.intern_pool);
    }
};
