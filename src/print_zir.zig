const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const InternPool = @import("InternPool.zig");

const Zir = std.zig.Zir;
const Module = @import("Module.zig");
const LazySrcLoc = std.zig.LazySrcLoc;

/// Write human-readable, debug formatted ZIR code to a file.
pub fn render_as_text_to_file(
    gpa: Allocator,
    scope_file: *Module.File,
    fs_file: std.fs.File,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var writer: Writer = .{
        .gpa = gpa,
        .arena = arena.allocator(),
        .file = scope_file,
        .code = scope_file.zir,
        .indent = 0,
        .parent_decl_node = 0,
        .recurse_decls = true,
        .recurse_blocks = true,
    };

    var raw_stream = std.io.buffered_writer(fs_file.writer());
    const stream = raw_stream.writer();

    const main_struct_inst: Zir.Inst.Index = .main_struct_inst;
    try stream.print("%{d} ", .{@int_from_enum(main_struct_inst)});
    try writer.write_inst_to_stream(stream, main_struct_inst);
    try stream.write_all("\n");
    const imports_index = scope_file.zir.extra[@int_from_enum(Zir.ExtraIndex.imports)];
    if (imports_index != 0) {
        try stream.write_all("Imports:\n");

        const extra = scope_file.zir.extra_data(Zir.Inst.Imports, imports_index);
        var extra_index = extra.end;

        for (0..extra.data.imports_len) |_| {
            const item = scope_file.zir.extra_data(Zir.Inst.Imports.Item, extra_index);
            extra_index = item.end;

            const src: LazySrcLoc = .{ .token_abs = item.data.token };
            const import_path = scope_file.zir.null_terminated_string(item.data.name);
            try stream.print("  @import(\"{}\") ", .{
                std.zig.fmt_escapes(import_path),
            });
            try writer.write_src(stream, src);
            try stream.write_all("\n");
        }
    }

    try raw_stream.flush();
}

pub fn render_instruction_context(
    gpa: Allocator,
    block: []const Zir.Inst.Index,
    block_index: usize,
    scope_file: *Module.File,
    parent_decl_node: Ast.Node.Index,
    indent: u32,
    stream: anytype,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var writer: Writer = .{
        .gpa = gpa,
        .arena = arena.allocator(),
        .file = scope_file,
        .code = scope_file.zir,
        .indent = if (indent < 2) 2 else indent,
        .parent_decl_node = parent_decl_node,
        .recurse_decls = false,
        .recurse_blocks = true,
    };

    try writer.write_body(stream, block[0..block_index]);
    try stream.write_byte_ntimes(' ', writer.indent - 2);
    try stream.print("> %{d} ", .{@int_from_enum(block[block_index])});
    try writer.write_inst_to_stream(stream, block[block_index]);
    try stream.write_byte('\n');
    if (block_index + 1 < block.len) {
        try writer.write_body(stream, block[block_index + 1 ..]);
    }
}

pub fn render_single_instruction(
    gpa: Allocator,
    inst: Zir.Inst.Index,
    scope_file: *Module.File,
    parent_decl_node: Ast.Node.Index,
    indent: u32,
    stream: anytype,
) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var writer: Writer = .{
        .gpa = gpa,
        .arena = arena.allocator(),
        .file = scope_file,
        .code = scope_file.zir,
        .indent = indent,
        .parent_decl_node = parent_decl_node,
        .recurse_decls = false,
        .recurse_blocks = false,
    };

    try stream.print("%{d} ", .{@int_from_enum(inst)});
    try writer.write_inst_to_stream(stream, inst);
}

const Writer = struct {
    gpa: Allocator,
    arena: Allocator,
    file: *Module.File,
    code: Zir,
    indent: u32,
    parent_decl_node: Ast.Node.Index,
    recurse_decls: bool,
    recurse_blocks: bool,

    /// Using `std.zig.find_line_column` whenever we need to resolve a source location makes ZIR
    /// printing O(N^2), which can have drastic effects - taking a ZIR dump from a few seconds to
    /// many minutes. Since we're usually resolving source locations close to one another,
    /// preserving state across source location resolutions speeds things up a lot.
    line_col_cursor: struct {
        line: usize = 0,
        column: usize = 0,
        line_start: usize = 0,
        off: usize = 0,

        fn find(cur: *@This(), source: []const u8, want_offset: usize) std.zig.Loc {
            if (want_offset < cur.off) {
                // Go back to the start of this line
                cur.off = cur.line_start;
                cur.column = 0;

                while (want_offset < cur.off) {
                    // Go back to the newline
                    cur.off -= 1;

                    // Seek to the start of the previous line
                    while (cur.off > 0 and source[cur.off - 1] != '\n') {
                        cur.off -= 1;
                    }
                    cur.line_start = cur.off;
                    cur.line -= 1;
                }
            }

            // The cursor is now positioned before `want_offset`.
            // Seek forward as in `std.zig.find_line_column`.

            while (cur.off < want_offset) : (cur.off += 1) {
                switch (source[cur.off]) {
                    '\n' => {
                        cur.line += 1;
                        cur.column = 0;
                        cur.line_start = cur.off + 1;
                    },
                    else => {
                        cur.column += 1;
                    },
                }
            }

            while (cur.off < source.len and source[cur.off] != '\n') {
                cur.off += 1;
            }

            return .{
                .line = cur.line,
                .column = cur.column,
                .source_line = source[cur.line_start..cur.off],
            };
        }
    } = .{},

    fn relative_to_node_index(self: *Writer, offset: i32) Ast.Node.Index {
        return @as(Ast.Node.Index, @bit_cast(offset + @as(i32, @bit_cast(self.parent_decl_node))));
    }

    fn write_inst_to_stream(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const tags = self.code.instructions.items(.tag);
        const tag = tags[@int_from_enum(inst)];
        try stream.print("= {s}(", .{@tag_name(tags[@int_from_enum(inst)])});
        switch (tag) {
            .alloc,
            .alloc_mut,
            .alloc_comptime_mut,
            .elem_type,
            .indexable_ptr_elem_type,
            .vector_elem_type,
            .indexable_ptr_len,
            .anyframe_type,
            .bit_not,
            .bool_not,
            .negate,
            .negate_wrap,
            .load,
            .ensure_result_used,
            .ensure_result_non_error,
            .ensure_err_union_payload_void,
            .ret_node,
            .ret_load,
            .resolve_inferred_alloc,
            .optional_type,
            .optional_payload_safe,
            .optional_payload_unsafe,
            .optional_payload_safe_ptr,
            .optional_payload_unsafe_ptr,
            .err_union_payload_unsafe,
            .err_union_payload_unsafe_ptr,
            .err_union_code,
            .err_union_code_ptr,
            .is_non_null,
            .is_non_null_ptr,
            .is_non_err,
            .is_non_err_ptr,
            .ret_is_non_err,
            .typeof,
            .type_info,
            .size_of,
            .bit_size_of,
            .typeof_log2_int_type,
            .int_from_ptr,
            .compile_error,
            .set_eval_branch_quota,
            .int_from_enum,
            .align_of,
            .int_from_bool,
            .embed_file,
            .error_name,
            .panic,
            .set_runtime_safety,
            .sqrt,
            .sin,
            .cos,
            .tan,
            .exp,
            .exp2,
            .log,
            .log2,
            .log10,
            .abs,
            .floor,
            .ceil,
            .trunc,
            .round,
            .tag_name,
            .type_name,
            .frame_type,
            .frame_size,
            .clz,
            .ctz,
            .pop_count,
            .byte_swap,
            .bit_reverse,
            .@"resume",
            .@"await",
            .make_ptr_const,
            .validate_deref,
            .check_comptime_control_flow,
            .opt_eu_base_ptr_init,
            .restore_err_ret_index_unconditional,
            .restore_err_ret_index_fn_entry,
            => try self.write_un_node(stream, inst),

            .ref,
            .ret_implicit,
            .validate_ref_ty,
            => try self.write_un_tok(stream, inst),

            .bool_br_and,
            .bool_br_or,
            => try self.write_bool_br(stream, inst),

            .validate_destructure => try self.write_validate_destructure(stream, inst),
            .array_type_sentinel => try self.write_array_type_sentinel(stream, inst),
            .ptr_type => try self.write_ptr_type(stream, inst),
            .int => try self.write_int(stream, inst),
            .int_big => try self.write_int_big(stream, inst),
            .float => try self.write_float(stream, inst),
            .float128 => try self.write_float128(stream, inst),
            .str => try self.write_str(stream, inst),
            .int_type => try self.write_int_type(stream, inst),

            .save_err_ret_index => try self.write_save_err_ret_index(stream, inst),

            .@"break",
            .break_inline,
            => try self.write_break(stream, inst),

            .slice_start => try self.write_slice_start(stream, inst),
            .slice_end => try self.write_slice_end(stream, inst),
            .slice_sentinel => try self.write_slice_sentinel(stream, inst),
            .slice_length => try self.write_slice_length(stream, inst),

            .union_init => try self.write_union_init(stream, inst),

            // Struct inits

            .struct_init_empty,
            .struct_init_empty_result,
            .struct_init_empty_ref_result,
            => try self.write_un_node(stream, inst),

            .struct_init_anon => try self.write_struct_init_anon(stream, inst),

            .struct_init,
            .struct_init_ref,
            => try self.write_struct_init(stream, inst),

            .validate_struct_init_ty,
            .validate_struct_init_result_ty,
            => try self.write_un_node(stream, inst),

            .validate_ptr_struct_init => try self.write_block(stream, inst),
            .struct_init_field_type => try self.write_struct_init_field_type(stream, inst),
            .struct_init_field_ptr => try self.write_pl_node_field(stream, inst),

            // Array inits

            .array_init_anon => try self.write_array_init_anon(stream, inst),

            .array_init,
            .array_init_ref,
            => try self.write_array_init(stream, inst),

            .validate_array_init_ty,
            .validate_array_init_result_ty,
            => try self.write_validate_array_init_ty(stream, inst),

            .validate_array_init_ref_ty => try self.write_validate_array_init_ref_ty(stream, inst),
            .validate_ptr_array_init => try self.write_block(stream, inst),
            .array_init_elem_type => try self.write_array_init_elem_type(stream, inst),
            .array_init_elem_ptr => try self.write_array_init_elem_ptr(stream, inst),

            .atomic_load => try self.write_atomic_load(stream, inst),
            .atomic_store => try self.write_atomic_store(stream, inst),
            .atomic_rmw => try self.write_atomic_rmw(stream, inst),
            .shuffle => try self.write_shuffle(stream, inst),
            .mul_add => try self.write_mul_add(stream, inst),
            .builtin_call => try self.write_builtin_call(stream, inst),

            .field_type_ref => try self.write_field_type_ref(stream, inst),

            .add,
            .addwrap,
            .add_sat,
            .add_unsafe,
            .array_cat,
            .mul,
            .mulwrap,
            .mul_sat,
            .sub,
            .subwrap,
            .sub_sat,
            .cmp_lt,
            .cmp_lte,
            .cmp_eq,
            .cmp_gte,
            .cmp_gt,
            .cmp_neq,
            .div,
            .has_decl,
            .has_field,
            .mod_rem,
            .shl,
            .shl_exact,
            .shl_sat,
            .shr,
            .shr_exact,
            .xor,
            .store_node,
            .store_to_inferred_ptr,
            .error_union_type,
            .merge_error_sets,
            .bit_and,
            .bit_or,
            .int_from_float,
            .float_from_int,
            .ptr_from_int,
            .enum_from_int,
            .float_cast,
            .int_cast,
            .ptr_cast,
            .truncate,
            .div_exact,
            .div_floor,
            .div_trunc,
            .mod,
            .rem,
            .bit_offset_of,
            .offset_of,
            .splat,
            .reduce,
            .bitcast,
            .vector_type,
            .max,
            .min,
            .memcpy,
            .memset,
            .elem_ptr_node,
            .elem_val_node,
            .elem_ptr,
            .elem_val,
            .array_type,
            .coerce_ptr_elem_ty,
            => try self.write_pl_node_bin(stream, inst),

            .for_len => try self.write_pl_node_multi_op(stream, inst),

            .array_mul => try self.write_array_mul(stream, inst),

            .elem_val_imm => try self.write_elem_val_imm(stream, inst),

            .@"export" => try self.write_pl_node_export(stream, inst),
            .export_value => try self.write_pl_node_export_value(stream, inst),

            .call => try self.write_call(stream, inst, .direct),
            .field_call => try self.write_call(stream, inst, .field),

            .block,
            .block_comptime,
            .block_inline,
            .suspend_block,
            .loop,
            .c_import,
            .typeof_builtin,
            => try self.write_block(stream, inst),

            .condbr,
            .condbr_inline,
            => try self.write_cond_br(stream, inst),

            .@"try",
            .try_ptr,
            => try self.write_try(stream, inst),

            .error_set_decl => try self.write_error_set_decl(stream, inst, .parent),
            .error_set_decl_anon => try self.write_error_set_decl(stream, inst, .anon),
            .error_set_decl_func => try self.write_error_set_decl(stream, inst, .func),

            .switch_block,
            .switch_block_ref,
            => try self.write_switch_block(stream, inst),

            .switch_block_err_union => try self.write_switch_block_err_union(stream, inst),

            .field_val,
            .field_ptr,
            => try self.write_pl_node_field(stream, inst),

            .field_ptr_named,
            .field_val_named,
            => try self.write_pl_node_field_named(stream, inst),

            .as_node, .as_shift_operand => try self.write_as(stream, inst),

            .repeat,
            .repeat_inline,
            .alloc_inferred,
            .alloc_inferred_mut,
            .alloc_inferred_comptime,
            .alloc_inferred_comptime_mut,
            .ret_ptr,
            .ret_type,
            .trap,
            => try self.write_node(stream, inst),

            .error_value,
            .enum_literal,
            .decl_ref,
            .decl_val,
            .import,
            .ret_err_value,
            .ret_err_value_code,
            .param_anytype,
            .param_anytype_comptime,
            => try self.write_str_tok(stream, inst),

            .dbg_var_ptr,
            .dbg_var_val,
            => try self.write_str_op(stream, inst),

            .param, .param_comptime => try self.write_param(stream, inst),

            .func => try self.write_func(stream, inst, false),
            .func_inferred => try self.write_func(stream, inst, true),
            .func_fancy => try self.write_func_fancy(stream, inst),

            .@"unreachable" => try self.write_unreachable(stream, inst),

            .dbg_stmt => try self.write_dbg_stmt(stream, inst),

            .@"defer" => try self.write_defer(stream, inst),
            .defer_err_code => try self.write_defer_err_code(stream, inst),

            .declaration => try self.write_declaration(stream, inst),

            .extended => try self.write_extended(stream, inst),
        }
    }

    fn write_extended(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const extended = self.code.instructions.items(.data)[@int_from_enum(inst)].extended;
        try stream.print("{s}(", .{@tag_name(extended.opcode)});
        switch (extended.opcode) {
            .this,
            .ret_addr,
            .error_return_trace,
            .frame,
            .frame_address,
            .breakpoint,
            .c_va_start,
            .in_comptime,
            .value_placeholder,
            => try self.write_ext_node(stream, extended),

            .builtin_src => {
                try stream.write_all("))");
                const inst_data = self.code.extra_data(Zir.Inst.LineColumn, extended.operand).data;
                try stream.print(":{d}:{d}", .{ inst_data.line + 1, inst_data.column + 1 });
            },

            .@"asm" => try self.write_asm(stream, extended, false),
            .asm_expr => try self.write_asm(stream, extended, true),
            .variable => try self.write_var_extended(stream, extended),
            .alloc => try self.write_alloc_extended(stream, extended),

            .compile_log => try self.write_node_multi_op(stream, extended),
            .typeof_peer => try self.write_typeof_peer(stream, extended),
            .min_multi => try self.write_node_multi_op(stream, extended),
            .max_multi => try self.write_node_multi_op(stream, extended),

            .select => try self.write_select(stream, extended),

            .add_with_overflow,
            .sub_with_overflow,
            .mul_with_overflow,
            .shl_with_overflow,
            => try self.write_overflow_arithmetic(stream, extended),

            .struct_decl => try self.write_struct_decl(stream, extended),
            .union_decl => try self.write_union_decl(stream, extended),
            .enum_decl => try self.write_enum_decl(stream, extended),
            .opaque_decl => try self.write_opaque_decl(stream, extended),

            .await_nosuspend,
            .c_undef,
            .c_include,
            .fence,
            .set_float_mode,
            .set_align_stack,
            .set_cold,
            .wasm_memory_size,
            .int_from_error,
            .error_from_int,
            .reify,
            .c_va_copy,
            .c_va_end,
            .work_item_id,
            .work_group_size,
            .work_group_id,
            => {
                const inst_data = self.code.extra_data(Zir.Inst.UnNode, extended.operand).data;
                const src = LazySrcLoc.nodeOffset(inst_data.node);
                try self.write_inst_ref(stream, inst_data.operand);
                try stream.write_all(")) ");
                try self.write_src(stream, src);
            },

            .builtin_extern,
            .c_define,
            .error_cast,
            .wasm_memory_grow,
            .prefetch,
            .c_va_arg,
            => {
                const inst_data = self.code.extra_data(Zir.Inst.BinNode, extended.operand).data;
                const src = LazySrcLoc.nodeOffset(inst_data.node);
                try self.write_inst_ref(stream, inst_data.lhs);
                try stream.write_all(", ");
                try self.write_inst_ref(stream, inst_data.rhs);
                try stream.write_all(")) ");
                try self.write_src(stream, src);
            },

            .builtin_async_call => try self.write_builtin_async_call(stream, extended),
            .cmpxchg => try self.write_cmpxchg(stream, extended),
            .ptr_cast_full => try self.write_ptr_cast_full(stream, extended),
            .ptr_cast_no_dest => try self.write_ptr_cast_no_dest(stream, extended),

            .restore_err_ret_index => try self.write_restore_err_ret_index(stream, extended),
            .closure_get => try self.write_closure_get(stream, extended),
            .field_parent_ptr => try self.write_field_parent_ptr(stream, extended),
        }
    }

    fn write_ext_node(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const src = LazySrcLoc.nodeOffset(@as(i32, @bit_cast(extended.operand)));
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_array_init_elem_type(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].bin;
        try self.write_inst_ref(stream, inst_data.lhs);
        try stream.print(", {d})", .{@int_from_enum(inst_data.rhs)});
    }

    fn write_un_node(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].un_node;
        try self.write_inst_ref(stream, inst_data.operand);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_un_tok(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].un_tok;
        try self.write_inst_ref(stream, inst_data.operand);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_validate_destructure(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ValidateDestructure, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.operand);
        try stream.print(", {d}) (destructure=", .{extra.expect_len});
        try self.write_src(stream, LazySrcLoc.nodeOffset(extra.destructure_node));
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_validate_array_init_ty(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ArrayInit, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.ty);
        try stream.print(", {d}) ", .{extra.init_count});
        try self.write_src(stream, inst_data.src());
    }

    fn write_array_type_sentinel(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ArrayTypeSentinel, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.len);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.sentinel);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.elem_type);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_ptr_type(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].ptr_type;
        const str_allowzero = if (inst_data.flags.is_allowzero) "allowzero, " else "";
        const str_const = if (!inst_data.flags.is_mutable) "const, " else "";
        const str_volatile = if (inst_data.flags.is_volatile) "volatile, " else "";
        const extra = self.code.extra_data(Zir.Inst.PtrType, inst_data.payload_index);
        try self.write_inst_ref(stream, extra.data.elem_type);
        try stream.print(", {s}{s}{s}{s}", .{
            str_allowzero,
            str_const,
            str_volatile,
            @tag_name(inst_data.size),
        });
        var extra_index = extra.end;
        if (inst_data.flags.has_sentinel) {
            try stream.write_all(", ");
            try self.write_inst_ref(stream, @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index])));
            extra_index += 1;
        }
        if (inst_data.flags.has_align) {
            try stream.write_all(", align(");
            try self.write_inst_ref(stream, @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index])));
            extra_index += 1;
            if (inst_data.flags.has_bit_range) {
                const bit_start = extra_index + @int_from_bool(inst_data.flags.has_addrspace);
                try stream.write_all(":");
                try self.write_inst_ref(stream, @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[bit_start])));
                try stream.write_all(":");
                try self.write_inst_ref(stream, @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[bit_start + 1])));
            }
            try stream.write_all(")");
        }
        if (inst_data.flags.has_addrspace) {
            try stream.write_all(", addrspace(");
            try self.write_inst_ref(stream, @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index])));
            try stream.write_all(")");
        }
        try stream.write_all(") ");
        try self.write_src(stream, LazySrcLoc.nodeOffset(extra.data.src_node));
    }

    fn write_int(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].int;
        try stream.print("{d})", .{inst_data});
    }

    fn write_int_big(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].str;
        const byte_count = inst_data.len * @size_of(std.math.big.Limb);
        const limb_bytes = self.code.null_terminated_string(inst_data.start)[0..byte_count];
        // limb_bytes is not aligned properly; we must allocate and copy the bytes
        // in order to accomplish this.
        const limbs = try self.gpa.alloc(std.math.big.Limb, inst_data.len);
        defer self.gpa.free(limbs);

        @memcpy(mem.slice_as_bytes(limbs), limb_bytes);
        const big_int: std.math.big.int.Const = .{
            .limbs = limbs,
            .positive = true,
        };
        const as_string = try big_int.to_string_alloc(self.gpa, 10, .lower);
        defer self.gpa.free(as_string);
        try stream.print("{s})", .{as_string});
    }

    fn write_float(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const number = self.code.instructions.items(.data)[@int_from_enum(inst)].float;
        try stream.print("{d})", .{number});
    }

    fn write_float128(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Float128, inst_data.payload_index).data;
        const src = inst_data.src();
        const number = extra.get();
        // TODO improve std.format to be able to print f128 values
        try stream.print("{d}) ", .{@as(f64, @float_cast(number))});
        try self.write_src(stream, src);
    }

    fn write_str(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].str;
        const str = inst_data.get(self.code);
        try stream.print("\"{}\")", .{std.zig.fmt_escapes(str)});
    }

    fn write_slice_start(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SliceStart, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.start);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_slice_end(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SliceEnd, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.start);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.end);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_slice_sentinel(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SliceSentinel, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.start);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.end);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.sentinel);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_slice_length(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SliceLength, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.start);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.len);
        if (extra.sentinel != .none) {
            try stream.write_all(", ");
            try self.write_inst_ref(stream, extra.sentinel);
        }
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_union_init(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.UnionInit, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.union_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.field_name);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.init);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_shuffle(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Shuffle, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.elem_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.a);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.b);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.mask);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_select(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.Select, extended.operand).data;
        try self.write_inst_ref(stream, extra.elem_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.pred);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.a);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.b);
        try stream.write_all(") ");
        try self.write_src(stream, LazySrcLoc.nodeOffset(extra.node));
    }

    fn write_mul_add(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.MulAdd, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.mulend1);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.mulend2);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.addend);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_builtin_call(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.BuiltinCall, inst_data.payload_index).data;

        try self.write_flag(stream, "nodiscard ", extra.flags.ensure_result_used);
        try self.write_flag(stream, "nosuspend ", extra.flags.is_nosuspend);

        try self.write_inst_ref(stream, extra.modifier);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.callee);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.args);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_field_parent_ptr(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.FieldParentPtr, extended.operand).data;
        const FlagsInt = @typeInfo(Zir.Inst.FullPtrCastFlags).Struct.backing_integer.?;
        const flags: Zir.Inst.FullPtrCastFlags = @bit_cast(@as(FlagsInt, @truncate(extended.small)));
        if (flags.align_cast) try stream.write_all("align_cast, ");
        if (flags.addrspace_cast) try stream.write_all("addrspace_cast, ");
        if (flags.const_cast) try stream.write_all("const_cast, ");
        if (flags.volatile_cast) try stream.write_all("volatile_cast, ");
        try self.write_inst_ref(stream, extra.parent_ptr_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.field_name);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.field_ptr);
        try stream.write_all(") ");
        try self.write_src(stream, extra.src());
    }

    fn write_builtin_async_call(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.AsyncCall, extended.operand).data;
        try self.write_inst_ref(stream, extra.frame_buffer);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.result_ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.fn_ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.args);
        try stream.write_all(") ");
        try self.write_src(stream, LazySrcLoc.nodeOffset(extra.node));
    }

    fn write_param(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_tok;
        const extra = self.code.extra_data(Zir.Inst.Param, inst_data.payload_index);
        const body = self.code.body_slice(extra.end, extra.data.body_len);
        try stream.print("\"{}\", ", .{
            std.zig.fmt_escapes(self.code.null_terminated_string(extra.data.name)),
        });

        if (extra.data.doc_comment != .empty) {
            try stream.write_all("\n");
            try self.write_doc_comment(stream, extra.data.doc_comment);
            try stream.write_byte_ntimes(' ', self.indent);
        }
        try self.write_braced_body(stream, body);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_bin(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Bin, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.rhs);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_multi_op(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.MultiOp, inst_data.payload_index);
        const args = self.code.ref_slice(extra.end, extra.data.operands_len);
        try stream.write_all("{");
        for (args, 0..) |arg, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, arg);
        }
        try stream.write_all("}) ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_array_mul(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ArrayMul, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.res_ty);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.rhs);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_elem_val_imm(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].elem_val_imm;
        try self.write_inst_ref(stream, inst_data.operand);
        try stream.print(", {d})", .{inst_data.idx});
    }

    fn write_array_init_elem_ptr(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ElemPtrImm, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.ptr);
        try stream.print(", {d}) ", .{extra.index});
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_export(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Export, inst_data.payload_index).data;
        const decl_name = self.code.null_terminated_string(extra.decl_name);

        try self.write_inst_ref(stream, extra.namespace);
        try stream.print(", {p}, ", .{std.zig.fmt_id(decl_name)});
        try self.write_inst_ref(stream, extra.options);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_export_value(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ExportValue, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.operand);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.options);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_validate_array_init_ref_ty(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ArrayInitRefTy, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.ptr_ty);
        try stream.write_all(", ");
        try stream.print(", {}) ", .{extra.elem_count});
        try self.write_src(stream, inst_data.src());
    }

    fn write_struct_init(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.StructInit, inst_data.payload_index);
        var field_i: u32 = 0;
        var extra_index = extra.end;

        while (field_i < extra.data.fields_len) : (field_i += 1) {
            const item = self.code.extra_data(Zir.Inst.StructInit.Item, extra_index);
            extra_index = item.end;

            if (field_i != 0) {
                try stream.write_all(", [");
            } else {
                try stream.write_all("[");
            }
            try self.write_inst_index(stream, item.data.field_type);
            try stream.write_all(", ");
            try self.write_inst_ref(stream, item.data.init);
            try stream.write_all("]");
        }
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_cmpxchg(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.Cmpxchg, extended.operand).data;
        const src = LazySrcLoc.nodeOffset(extra.node);

        try self.write_inst_ref(stream, extra.ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.expected_value);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.new_value);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.success_order);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.failure_order);
        try stream.write_all(") ");
        try self.write_src(stream, src);
    }

    fn write_ptr_cast_full(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const FlagsInt = @typeInfo(Zir.Inst.FullPtrCastFlags).Struct.backing_integer.?;
        const flags: Zir.Inst.FullPtrCastFlags = @bit_cast(@as(FlagsInt, @truncate(extended.small)));
        const extra = self.code.extra_data(Zir.Inst.BinNode, extended.operand).data;
        const src = LazySrcLoc.nodeOffset(extra.node);
        if (flags.ptr_cast) try stream.write_all("ptr_cast, ");
        if (flags.align_cast) try stream.write_all("align_cast, ");
        if (flags.addrspace_cast) try stream.write_all("addrspace_cast, ");
        if (flags.const_cast) try stream.write_all("const_cast, ");
        if (flags.volatile_cast) try stream.write_all("volatile_cast, ");
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.rhs);
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_ptr_cast_no_dest(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const FlagsInt = @typeInfo(Zir.Inst.FullPtrCastFlags).Struct.backing_integer.?;
        const flags: Zir.Inst.FullPtrCastFlags = @bit_cast(@as(FlagsInt, @truncate(extended.small)));
        const extra = self.code.extra_data(Zir.Inst.UnNode, extended.operand).data;
        const src = LazySrcLoc.nodeOffset(extra.node);
        if (flags.const_cast) try stream.write_all("const_cast, ");
        if (flags.volatile_cast) try stream.write_all("volatile_cast, ");
        try self.write_inst_ref(stream, extra.operand);
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_atomic_load(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.AtomicLoad, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.elem_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.ordering);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_atomic_store(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.AtomicStore, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.operand);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.ordering);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_atomic_rmw(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.AtomicRmw, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.ptr);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.operation);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.operand);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.ordering);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_struct_init_anon(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.StructInitAnon, inst_data.payload_index);
        var field_i: u32 = 0;
        var extra_index = extra.end;

        while (field_i < extra.data.fields_len) : (field_i += 1) {
            const item = self.code.extra_data(Zir.Inst.StructInitAnon.Item, extra_index);
            extra_index = item.end;

            const field_name = self.code.null_terminated_string(item.data.field_name);

            const prefix = if (field_i != 0) ", [" else "[";
            try stream.print("{s}{s}=", .{ prefix, field_name });
            try self.write_inst_ref(stream, item.data.init);
            try stream.write_all("]");
        }
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_struct_init_field_type(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.FieldType, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.container_type);
        const field_name = self.code.null_terminated_string(extra.name_start);
        try stream.print(", {s}) ", .{field_name});
        try self.write_src(stream, inst_data.src());
    }

    fn write_field_type_ref(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.FieldTypeRef, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.container_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.field_name);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_node_multi_op(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.NodeMultiOp, extended.operand);
        const src = LazySrcLoc.nodeOffset(extra.data.src_node);
        const operands = self.code.ref_slice(extra.end, extended.small);

        for (operands, 0..) |operand, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, operand);
        }
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_inst_node(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].inst_node;
        try self.write_inst_index(stream, inst_data.inst);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_asm(
        self: *Writer,
        stream: anytype,
        extended: Zir.Inst.Extended.InstData,
        tmpl_is_expr: bool,
    ) !void {
        const extra = self.code.extra_data(Zir.Inst.Asm, extended.operand);
        const src = LazySrcLoc.nodeOffset(extra.data.src_node);
        const outputs_len = @as(u5, @truncate(extended.small));
        const inputs_len = @as(u5, @truncate(extended.small >> 5));
        const clobbers_len = @as(u5, @truncate(extended.small >> 10));
        const is_volatile = @as(u1, @truncate(extended.small >> 15)) != 0;

        try self.write_flag(stream, "volatile, ", is_volatile);
        if (tmpl_is_expr) {
            try self.write_inst_ref(stream, @enumFromInt(@int_from_enum(extra.data.asm_source)));
            try stream.write_all(", ");
        } else {
            const asm_source = self.code.null_terminated_string(extra.data.asm_source);
            try stream.print("\"{}\", ", .{std.zig.fmt_escapes(asm_source)});
        }
        try stream.write_all(", ");

        var extra_i: usize = extra.end;
        var output_type_bits = extra.data.output_type_bits;
        {
            var i: usize = 0;
            while (i < outputs_len) : (i += 1) {
                const output = self.code.extra_data(Zir.Inst.Asm.Output, extra_i);
                extra_i = output.end;

                const is_type = @as(u1, @truncate(output_type_bits)) != 0;
                output_type_bits >>= 1;

                const name = self.code.null_terminated_string(output.data.name);
                const constraint = self.code.null_terminated_string(output.data.constraint);
                try stream.print("output({p}, \"{}\", ", .{
                    std.zig.fmt_id(name), std.zig.fmt_escapes(constraint),
                });
                try self.write_flag(stream, "->", is_type);
                try self.write_inst_ref(stream, output.data.operand);
                try stream.write_all(")");
                if (i + 1 < outputs_len) {
                    try stream.write_all("), ");
                }
            }
        }
        {
            var i: usize = 0;
            while (i < inputs_len) : (i += 1) {
                const input = self.code.extra_data(Zir.Inst.Asm.Input, extra_i);
                extra_i = input.end;

                const name = self.code.null_terminated_string(input.data.name);
                const constraint = self.code.null_terminated_string(input.data.constraint);
                try stream.print("input({p}, \"{}\", ", .{
                    std.zig.fmt_id(name), std.zig.fmt_escapes(constraint),
                });
                try self.write_inst_ref(stream, input.data.operand);
                try stream.write_all(")");
                if (i + 1 < inputs_len) {
                    try stream.write_all(", ");
                }
            }
        }
        {
            var i: usize = 0;
            while (i < clobbers_len) : (i += 1) {
                const str_index = self.code.extra[extra_i];
                extra_i += 1;
                const clobber = self.code.null_terminated_string(@enumFromInt(str_index));
                try stream.print("{p}", .{std.zig.fmt_id(clobber)});
                if (i + 1 < clobbers_len) {
                    try stream.write_all(", ");
                }
            }
        }
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_overflow_arithmetic(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.BinNode, extended.operand).data;
        const src = LazySrcLoc.nodeOffset(extra.node);

        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.rhs);
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_call(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
        comptime kind: enum { direct, field },
    ) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const ExtraType = switch (kind) {
            .direct => Zir.Inst.Call,
            .field => Zir.Inst.FieldCall,
        };
        const extra = self.code.extra_data(ExtraType, inst_data.payload_index);
        const args_len = extra.data.flags.args_len;
        const body = self.code.extra[extra.end..];

        if (extra.data.flags.ensure_result_used) {
            try stream.write_all("nodiscard ");
        }
        try stream.print(".{s}, ", .{@tag_name(@as(std.builtin.CallModifier, @enumFromInt(extra.data.flags.packed_modifier)))});
        switch (kind) {
            .direct => try self.write_inst_ref(stream, extra.data.callee),
            .field => {
                const field_name = self.code.null_terminated_string(extra.data.field_name_start);
                try self.write_inst_ref(stream, extra.data.obj_ptr);
                try stream.print(", \"{}\"", .{std.zig.fmt_escapes(field_name)});
            },
        }
        try stream.write_all(", [");

        self.indent += 2;
        if (args_len != 0) {
            try stream.write_all("\n");
        }
        var i: usize = 0;
        var arg_start: u32 = args_len;
        while (i < args_len) : (i += 1) {
            try stream.write_byte_ntimes(' ', self.indent);
            const arg_end = self.code.extra[extra.end + i];
            defer arg_start = arg_end;
            const arg_body = body[arg_start..arg_end];
            try self.write_braced_body(stream, @ptr_cast(arg_body));

            try stream.write_all(",\n");
        }
        self.indent -= 2;
        if (args_len != 0) {
            try stream.write_byte_ntimes(' ', self.indent);
        }

        try stream.write_all("]) ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_block(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        try self.write_pl_node_block_without_src(stream, inst);
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_block_without_src(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Block, inst_data.payload_index);
        const body = self.code.body_slice(extra.end, extra.data.body_len);
        try self.write_braced_body(stream, body);
        try stream.write_all(") ");
    }

    fn write_cond_br(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.CondBr, inst_data.payload_index);
        const then_body = self.code.body_slice(extra.end, extra.data.then_body_len);
        const else_body = self.code.body_slice(extra.end + then_body.len, extra.data.else_body_len);
        try self.write_inst_ref(stream, extra.data.condition);
        try stream.write_all(", ");
        try self.write_braced_body(stream, then_body);
        try stream.write_all(", ");
        try self.write_braced_body(stream, else_body);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_try(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Try, inst_data.payload_index);
        const body = self.code.body_slice(extra.end, extra.data.body_len);
        try self.write_inst_ref(stream, extra.data.operand);
        try stream.write_all(", ");
        try self.write_braced_body(stream, body);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_struct_decl(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const small = @as(Zir.Inst.StructDecl.Small, @bit_cast(extended.small));

        const extra = self.code.extra_data(Zir.Inst.StructDecl, extended.operand);
        const fields_hash: std.zig.SrcHash = @bit_cast([4]u32{
            extra.data.fields_hash_0,
            extra.data.fields_hash_1,
            extra.data.fields_hash_2,
            extra.data.fields_hash_3,
        });

        try stream.print("hash({}) ", .{std.fmt.fmt_slice_hex_lower(&fields_hash)});

        var extra_index: usize = extra.end;

        const captures_len = if (small.has_captures_len) blk: {
            const captures_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk captures_len;
        } else 0;

        const fields_len = if (small.has_fields_len) blk: {
            const fields_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk fields_len;
        } else 0;

        const decls_len = if (small.has_decls_len) blk: {
            const decls_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk decls_len;
        } else 0;

        try self.write_flag(stream, "known_non_opv, ", small.known_non_opv);
        try self.write_flag(stream, "known_comptime_only, ", small.known_comptime_only);
        try self.write_flag(stream, "tuple, ", small.is_tuple);

        try stream.print("{s}, ", .{@tag_name(small.name_strategy)});

        if (captures_len == 0) {
            try stream.write_all("{}, ");
        } else {
            try stream.write_all("{ ");
            try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;
            for (1..captures_len) |_| {
                try stream.write_all(", ");
                try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
            }
            try stream.write_all(" }, ");
        }

        if (small.has_backing_int) {
            const backing_int_body_len = self.code.extra[extra_index];
            extra_index += 1;
            try stream.write_all("packed(");
            if (backing_int_body_len == 0) {
                const backing_int_ref: Zir.Inst.Ref = @enumFromInt(self.code.extra[extra_index]);
                extra_index += 1;
                try self.write_inst_ref(stream, backing_int_ref);
            } else {
                const body = self.code.body_slice(extra_index, backing_int_body_len);
                extra_index += backing_int_body_len;
                self.indent += 2;
                try self.write_braced_decl(stream, body);
                self.indent -= 2;
            }
            try stream.write_all("), ");
        } else {
            try stream.print("{s}, ", .{@tag_name(small.layout)});
        }

        if (decls_len == 0) {
            try stream.write_all("{}, ");
        } else {
            const prev_parent_decl_node = self.parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
            defer self.parent_decl_node = prev_parent_decl_node;

            try stream.write_all("{\n");
            self.indent += 2;
            try self.write_body(stream, self.code.body_slice(extra_index, decls_len));
            self.indent -= 2;
            extra_index += decls_len;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("}, ");
        }

        if (fields_len == 0) {
            try stream.write_all("{}, {})");
        } else {
            const bits_per_field = 4;
            const fields_per_u32 = 32 / bits_per_field;
            const bit_bags_count = std.math.div_ceil(usize, fields_len, fields_per_u32) catch unreachable;
            const Field = struct {
                doc_comment_index: Zir.NullTerminatedString,
                type_len: u32 = 0,
                align_len: u32 = 0,
                init_len: u32 = 0,
                type: Zir.Inst.Ref = .none,
                name: Zir.NullTerminatedString,
                is_comptime: bool,
            };
            const fields = try self.arena.alloc(Field, fields_len);
            {
                var bit_bag_index: usize = extra_index;
                extra_index += bit_bags_count;
                var cur_bit_bag: u32 = undefined;
                var field_i: u32 = 0;
                while (field_i < fields_len) : (field_i += 1) {
                    if (field_i % fields_per_u32 == 0) {
                        cur_bit_bag = self.code.extra[bit_bag_index];
                        bit_bag_index += 1;
                    }
                    const has_align = @as(u1, @truncate(cur_bit_bag)) != 0;
                    cur_bit_bag >>= 1;
                    const has_default = @as(u1, @truncate(cur_bit_bag)) != 0;
                    cur_bit_bag >>= 1;
                    const is_comptime = @as(u1, @truncate(cur_bit_bag)) != 0;
                    cur_bit_bag >>= 1;
                    const has_type_body = @as(u1, @truncate(cur_bit_bag)) != 0;
                    cur_bit_bag >>= 1;

                    var field_name_index: Zir.NullTerminatedString = .empty;
                    if (!small.is_tuple) {
                        field_name_index = @enumFromInt(self.code.extra[extra_index]);
                        extra_index += 1;
                    }
                    const doc_comment_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
                    extra_index += 1;

                    fields[field_i] = .{
                        .doc_comment_index = doc_comment_index,
                        .is_comptime = is_comptime,
                        .name = field_name_index,
                    };

                    if (has_type_body) {
                        fields[field_i].type_len = self.code.extra[extra_index];
                    } else {
                        fields[field_i].type = @enumFromInt(self.code.extra[extra_index]);
                    }
                    extra_index += 1;

                    if (has_align) {
                        fields[field_i].align_len = self.code.extra[extra_index];
                        extra_index += 1;
                    }

                    if (has_default) {
                        fields[field_i].init_len = self.code.extra[extra_index];
                        extra_index += 1;
                    }
                }
            }

            const prev_parent_decl_node = self.parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
            try stream.write_all("{\n");
            self.indent += 2;

            for (fields, 0..) |field, i| {
                try self.write_doc_comment(stream, field.doc_comment_index);
                try stream.write_byte_ntimes(' ', self.indent);
                try self.write_flag(stream, "comptime ", field.is_comptime);
                if (field.name != .empty) {
                    const field_name = self.code.null_terminated_string(field.name);
                    try stream.print("{p}: ", .{std.zig.fmt_id(field_name)});
                } else {
                    try stream.print("@\"{d}\": ", .{i});
                }
                if (field.type != .none) {
                    try self.write_inst_ref(stream, field.type);
                }

                if (field.type_len > 0) {
                    const body = self.code.body_slice(extra_index, field.type_len);
                    extra_index += body.len;
                    self.indent += 2;
                    try self.write_braced_decl(stream, body);
                    self.indent -= 2;
                }

                if (field.align_len > 0) {
                    const body = self.code.body_slice(extra_index, field.align_len);
                    extra_index += body.len;
                    self.indent += 2;
                    try stream.write_all(" align(");
                    try self.write_braced_decl(stream, body);
                    try stream.write_all(")");
                    self.indent -= 2;
                }

                if (field.init_len > 0) {
                    const body = self.code.body_slice(extra_index, field.init_len);
                    extra_index += body.len;
                    self.indent += 2;
                    try stream.write_all(" = ");
                    try self.write_braced_decl(stream, body);
                    self.indent -= 2;
                }

                try stream.write_all(",\n");
            }

            self.parent_decl_node = prev_parent_decl_node;
            self.indent -= 2;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("})");
        }
        try self.write_src_node(stream, extra.data.src_node);
    }

    fn write_union_decl(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const small = @as(Zir.Inst.UnionDecl.Small, @bit_cast(extended.small));

        const extra = self.code.extra_data(Zir.Inst.UnionDecl, extended.operand);
        const fields_hash: std.zig.SrcHash = @bit_cast([4]u32{
            extra.data.fields_hash_0,
            extra.data.fields_hash_1,
            extra.data.fields_hash_2,
            extra.data.fields_hash_3,
        });

        try stream.print("hash({}) ", .{std.fmt.fmt_slice_hex_lower(&fields_hash)});

        var extra_index: usize = extra.end;

        const tag_type_ref = if (small.has_tag_type) blk: {
            const tag_type_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk tag_type_ref;
        } else .none;

        const captures_len = if (small.has_captures_len) blk: {
            const captures_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk captures_len;
        } else 0;

        const body_len = if (small.has_body_len) blk: {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk body_len;
        } else 0;

        const fields_len = if (small.has_fields_len) blk: {
            const fields_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk fields_len;
        } else 0;

        const decls_len = if (small.has_decls_len) blk: {
            const decls_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk decls_len;
        } else 0;

        try stream.print("{s}, {s}, ", .{
            @tag_name(small.name_strategy), @tag_name(small.layout),
        });
        try self.write_flag(stream, "autoenum, ", small.auto_enum_tag);

        if (captures_len == 0) {
            try stream.write_all("{}, ");
        } else {
            try stream.write_all("{ ");
            try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;
            for (1..captures_len) |_| {
                try stream.write_all(", ");
                try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
            }
            try stream.write_all(" }, ");
        }

        if (decls_len == 0) {
            try stream.write_all("{}");
        } else {
            const prev_parent_decl_node = self.parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
            defer self.parent_decl_node = prev_parent_decl_node;

            try stream.write_all("{\n");
            self.indent += 2;
            try self.write_body(stream, self.code.body_slice(extra_index, decls_len));
            self.indent -= 2;
            extra_index += decls_len;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("}");
        }

        if (tag_type_ref != .none) {
            try stream.write_all(", ");
            try self.write_inst_ref(stream, tag_type_ref);
        }

        if (fields_len == 0) {
            try stream.write_all("})");
            try self.write_src_node(stream, extra.data.src_node);
            return;
        }
        try stream.write_all(", ");

        const body = self.code.body_slice(extra_index, body_len);
        extra_index += body.len;

        const prev_parent_decl_node = self.parent_decl_node;
        self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
        try self.write_braced_decl(stream, body);
        try stream.write_all(", {\n");

        self.indent += 2;
        const bits_per_field = 4;
        const fields_per_u32 = 32 / bits_per_field;
        const bit_bags_count = std.math.div_ceil(usize, fields_len, fields_per_u32) catch unreachable;
        const body_end = extra_index;
        extra_index += bit_bags_count;
        var bit_bag_index: usize = body_end;
        var cur_bit_bag: u32 = undefined;
        var field_i: u32 = 0;
        while (field_i < fields_len) : (field_i += 1) {
            if (field_i % fields_per_u32 == 0) {
                cur_bit_bag = self.code.extra[bit_bag_index];
                bit_bag_index += 1;
            }
            const has_type = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const has_align = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const has_value = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;
            const unused = @as(u1, @truncate(cur_bit_bag)) != 0;
            cur_bit_bag >>= 1;

            _ = unused;

            const field_name_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
            const field_name = self.code.null_terminated_string(field_name_index);
            extra_index += 1;
            const doc_comment_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
            extra_index += 1;

            try self.write_doc_comment(stream, doc_comment_index);
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.print("{p}", .{std.zig.fmt_id(field_name)});

            if (has_type) {
                const field_type = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;

                try stream.write_all(": ");
                try self.write_inst_ref(stream, field_type);
            }
            if (has_align) {
                const align_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;

                try stream.write_all(" align(");
                try self.write_inst_ref(stream, align_ref);
                try stream.write_all(")");
            }
            if (has_value) {
                const default_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;

                try stream.write_all(" = ");
                try self.write_inst_ref(stream, default_ref);
            }
            try stream.write_all(",\n");
        }

        self.parent_decl_node = prev_parent_decl_node;
        self.indent -= 2;
        try stream.write_byte_ntimes(' ', self.indent);
        try stream.write_all("})");
        try self.write_src_node(stream, extra.data.src_node);
    }

    fn write_enum_decl(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const small = @as(Zir.Inst.EnumDecl.Small, @bit_cast(extended.small));

        const extra = self.code.extra_data(Zir.Inst.EnumDecl, extended.operand);
        const fields_hash: std.zig.SrcHash = @bit_cast([4]u32{
            extra.data.fields_hash_0,
            extra.data.fields_hash_1,
            extra.data.fields_hash_2,
            extra.data.fields_hash_3,
        });

        try stream.print("hash({}) ", .{std.fmt.fmt_slice_hex_lower(&fields_hash)});

        var extra_index: usize = extra.end;

        const tag_type_ref = if (small.has_tag_type) blk: {
            const tag_type_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk tag_type_ref;
        } else .none;

        const captures_len = if (small.has_captures_len) blk: {
            const captures_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk captures_len;
        } else 0;

        const body_len = if (small.has_body_len) blk: {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk body_len;
        } else 0;

        const fields_len = if (small.has_fields_len) blk: {
            const fields_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk fields_len;
        } else 0;

        const decls_len = if (small.has_decls_len) blk: {
            const decls_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk decls_len;
        } else 0;

        try stream.print("{s}, ", .{@tag_name(small.name_strategy)});
        try self.write_flag(stream, "nonexhaustive, ", small.nonexhaustive);

        if (captures_len == 0) {
            try stream.write_all("{}, ");
        } else {
            try stream.write_all("{ ");
            try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;
            for (1..captures_len) |_| {
                try stream.write_all(", ");
                try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
            }
            try stream.write_all(" }, ");
        }

        if (decls_len == 0) {
            try stream.write_all("{}, ");
        } else {
            const prev_parent_decl_node = self.parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
            defer self.parent_decl_node = prev_parent_decl_node;

            try stream.write_all("{\n");
            self.indent += 2;
            try self.write_body(stream, self.code.body_slice(extra_index, decls_len));
            self.indent -= 2;
            extra_index += decls_len;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("}, ");
        }

        if (tag_type_ref != .none) {
            try self.write_inst_ref(stream, tag_type_ref);
            try stream.write_all(", ");
        }

        const body = self.code.body_slice(extra_index, body_len);
        extra_index += body.len;

        const prev_parent_decl_node = self.parent_decl_node;
        self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
        try self.write_braced_decl(stream, body);
        if (fields_len == 0) {
            try stream.write_all(", {})");
            self.parent_decl_node = prev_parent_decl_node;
        } else {
            try stream.write_all(", {\n");

            self.indent += 2;
            const bit_bags_count = std.math.div_ceil(usize, fields_len, 32) catch unreachable;
            const body_end = extra_index;
            extra_index += bit_bags_count;
            var bit_bag_index: usize = body_end;
            var cur_bit_bag: u32 = undefined;
            var field_i: u32 = 0;
            while (field_i < fields_len) : (field_i += 1) {
                if (field_i % 32 == 0) {
                    cur_bit_bag = self.code.extra[bit_bag_index];
                    bit_bag_index += 1;
                }
                const has_tag_value = @as(u1, @truncate(cur_bit_bag)) != 0;
                cur_bit_bag >>= 1;

                const field_name = self.code.null_terminated_string(@enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;

                const doc_comment_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
                extra_index += 1;

                try self.write_doc_comment(stream, doc_comment_index);

                try stream.write_byte_ntimes(' ', self.indent);
                try stream.print("{p}", .{std.zig.fmt_id(field_name)});

                if (has_tag_value) {
                    const tag_value_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                    extra_index += 1;

                    try stream.write_all(" = ");
                    try self.write_inst_ref(stream, tag_value_ref);
                }
                try stream.write_all(",\n");
            }
            self.parent_decl_node = prev_parent_decl_node;
            self.indent -= 2;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("})");
        }
        try self.write_src_node(stream, extra.data.src_node);
    }

    fn write_opaque_decl(
        self: *Writer,
        stream: anytype,
        extended: Zir.Inst.Extended.InstData,
    ) !void {
        const small = @as(Zir.Inst.OpaqueDecl.Small, @bit_cast(extended.small));
        const extra = self.code.extra_data(Zir.Inst.OpaqueDecl, extended.operand);
        var extra_index: usize = extra.end;

        const captures_len = if (small.has_captures_len) blk: {
            const captures_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk captures_len;
        } else 0;

        const decls_len = if (small.has_decls_len) blk: {
            const decls_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk decls_len;
        } else 0;

        try stream.print("{s}, ", .{@tag_name(small.name_strategy)});

        if (captures_len == 0) {
            try stream.write_all("{}, ");
        } else {
            try stream.write_all("{ ");
            try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;
            for (1..captures_len) |_| {
                try stream.write_all(", ");
                try self.write_capture(stream, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
            }
            try stream.write_all(" }, ");
        }

        if (decls_len == 0) {
            try stream.write_all("{})");
        } else {
            const prev_parent_decl_node = self.parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(extra.data.src_node);
            defer self.parent_decl_node = prev_parent_decl_node;

            try stream.write_all("{\n");
            self.indent += 2;
            try self.write_body(stream, self.code.body_slice(extra_index, decls_len));
            self.indent -= 2;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("})");
        }
        try self.write_src_node(stream, extra.data.src_node);
    }

    fn write_error_set_decl(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
        name_strategy: Zir.Inst.NameStrategy,
    ) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.ErrorSetDecl, inst_data.payload_index);

        try stream.print("{s}, ", .{@tag_name(name_strategy)});

        try stream.write_all("{\n");
        self.indent += 2;

        var extra_index = @as(u32, @int_cast(extra.end));
        const extra_index_end = extra_index + (extra.data.fields_len * 2);
        while (extra_index < extra_index_end) : (extra_index += 2) {
            const name_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
            const name = self.code.null_terminated_string(name_index);
            const doc_comment_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index + 1]);
            try self.write_doc_comment(stream, doc_comment_index);
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.print("{p},\n", .{std.zig.fmt_id(name)});
        }

        self.indent -= 2;
        try stream.write_byte_ntimes(' ', self.indent);
        try stream.write_all("}) ");

        try self.write_src(stream, inst_data.src());
    }

    fn write_switch_block_err_union(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SwitchBlockErrUnion, inst_data.payload_index);

        var extra_index: usize = extra.end;

        const multi_cases_len = if (extra.data.bits.has_multi_cases) blk: {
            const multi_cases_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk multi_cases_len;
        } else 0;

        const err_capture_inst: Zir.Inst.Index = if (extra.data.bits.any_uses_err_capture) blk: {
            const tag_capture_inst = self.code.extra[extra_index];
            extra_index += 1;
            break :blk @enumFromInt(tag_capture_inst);
        } else undefined;

        try self.write_inst_ref(stream, extra.data.operand);

        if (extra.data.bits.any_uses_err_capture) {
            try stream.write_all(", err_capture=");
            try self.write_inst_index(stream, err_capture_inst);
        }

        self.indent += 2;

        {
            const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;

            assert(!info.is_inline);
            const body = self.code.body_slice(extra_index, info.body_len);
            extra_index += body.len;

            try stream.write_all(",\n");
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("non_err => ");
            try self.write_braced_body(stream, body);
        }

        if (extra.data.bits.has_else) {
            const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
            extra_index += 1;
            const capture_text = switch (info.capture) {
                .none => "",
                .by_val => "by_val ",
                .by_ref => "by_ref ",
            };
            const inline_text = if (info.is_inline) "inline " else "";
            const body = self.code.body_slice(extra_index, info.body_len);
            extra_index += body.len;

            try stream.write_all(",\n");
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.print("{s}{s}else => ", .{ capture_text, inline_text });
            try self.write_braced_body(stream, body);
        }

        {
            const scalar_cases_len = extra.data.bits.scalar_cases_len;
            var scalar_i: usize = 0;
            while (scalar_i < scalar_cases_len) : (scalar_i += 1) {
                const item_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;
                const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
                const body = self.code.body_slice(extra_index, info.body_len);
                extra_index += info.body_len;

                try stream.write_all(",\n");
                try stream.write_byte_ntimes(' ', self.indent);
                switch (info.capture) {
                    .none => {},
                    .by_val => try stream.write_all("by_val "),
                    .by_ref => try stream.write_all("by_ref "),
                }
                if (info.is_inline) try stream.write_all("inline ");
                try self.write_inst_ref(stream, item_ref);
                try stream.write_all(" => ");
                try self.write_braced_body(stream, body);
            }
        }
        {
            var multi_i: usize = 0;
            while (multi_i < multi_cases_len) : (multi_i += 1) {
                const items_len = self.code.extra[extra_index];
                extra_index += 1;
                const ranges_len = self.code.extra[extra_index];
                extra_index += 1;
                const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
                const items = self.code.ref_slice(extra_index, items_len);
                extra_index += items_len;

                try stream.write_all(",\n");
                try stream.write_byte_ntimes(' ', self.indent);
                switch (info.capture) {
                    .none => {},
                    .by_val => try stream.write_all("by_val "),
                    .by_ref => try stream.write_all("by_ref "),
                }
                if (info.is_inline) try stream.write_all("inline ");

                for (items, 0..) |item_ref, item_i| {
                    if (item_i != 0) try stream.write_all(", ");
                    try self.write_inst_ref(stream, item_ref);
                }

                var range_i: usize = 0;
                while (range_i < ranges_len) : (range_i += 1) {
                    const item_first = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                    extra_index += 1;
                    const item_last = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                    extra_index += 1;

                    if (range_i != 0 or items.len != 0) {
                        try stream.write_all(", ");
                    }
                    try self.write_inst_ref(stream, item_first);
                    try stream.write_all("...");
                    try self.write_inst_ref(stream, item_last);
                }

                const body = self.code.body_slice(extra_index, info.body_len);
                extra_index += info.body_len;
                try stream.write_all(" => ");
                try self.write_braced_body(stream, body);
            }
        }

        self.indent -= 2;

        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_switch_block(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.SwitchBlock, inst_data.payload_index);

        var extra_index: usize = extra.end;

        const multi_cases_len = if (extra.data.bits.has_multi_cases) blk: {
            const multi_cases_len = self.code.extra[extra_index];
            extra_index += 1;
            break :blk multi_cases_len;
        } else 0;

        const tag_capture_inst: Zir.Inst.Index = if (extra.data.bits.any_has_tag_capture) blk: {
            const tag_capture_inst = self.code.extra[extra_index];
            extra_index += 1;
            break :blk @enumFromInt(tag_capture_inst);
        } else undefined;

        try self.write_inst_ref(stream, extra.data.operand);

        if (extra.data.bits.any_has_tag_capture) {
            try stream.write_all(", tag_capture=");
            try self.write_inst_index(stream, tag_capture_inst);
        }

        self.indent += 2;

        else_prong: {
            const special_prong = extra.data.bits.special_prong();
            const prong_name = switch (special_prong) {
                .@"else" => "else",
                .under => "_",
                else => break :else_prong,
            };

            const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
            const capture_text = switch (info.capture) {
                .none => "",
                .by_val => "by_val ",
                .by_ref => "by_ref ",
            };
            const inline_text = if (info.is_inline) "inline " else "";
            extra_index += 1;
            const body = self.code.body_slice(extra_index, info.body_len);
            extra_index += body.len;

            try stream.write_all(",\n");
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.print("{s}{s}{s} => ", .{ capture_text, inline_text, prong_name });
            try self.write_braced_body(stream, body);
        }

        {
            const scalar_cases_len = extra.data.bits.scalar_cases_len;
            var scalar_i: usize = 0;
            while (scalar_i < scalar_cases_len) : (scalar_i += 1) {
                const item_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;
                const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
                const body = self.code.body_slice(extra_index, info.body_len);
                extra_index += info.body_len;

                try stream.write_all(",\n");
                try stream.write_byte_ntimes(' ', self.indent);
                switch (info.capture) {
                    .none => {},
                    .by_val => try stream.write_all("by_val "),
                    .by_ref => try stream.write_all("by_ref "),
                }
                if (info.is_inline) try stream.write_all("inline ");
                try self.write_inst_ref(stream, item_ref);
                try stream.write_all(" => ");
                try self.write_braced_body(stream, body);
            }
        }
        {
            var multi_i: usize = 0;
            while (multi_i < multi_cases_len) : (multi_i += 1) {
                const items_len = self.code.extra[extra_index];
                extra_index += 1;
                const ranges_len = self.code.extra[extra_index];
                extra_index += 1;
                const info = @as(Zir.Inst.SwitchBlock.ProngInfo, @bit_cast(self.code.extra[extra_index]));
                extra_index += 1;
                const items = self.code.ref_slice(extra_index, items_len);
                extra_index += items_len;

                try stream.write_all(",\n");
                try stream.write_byte_ntimes(' ', self.indent);
                switch (info.capture) {
                    .none => {},
                    .by_val => try stream.write_all("by_val "),
                    .by_ref => try stream.write_all("by_ref "),
                }
                if (info.is_inline) try stream.write_all("inline ");

                for (items, 0..) |item_ref, item_i| {
                    if (item_i != 0) try stream.write_all(", ");
                    try self.write_inst_ref(stream, item_ref);
                }

                var range_i: usize = 0;
                while (range_i < ranges_len) : (range_i += 1) {
                    const item_first = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                    extra_index += 1;
                    const item_last = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                    extra_index += 1;

                    if (range_i != 0 or items.len != 0) {
                        try stream.write_all(", ");
                    }
                    try self.write_inst_ref(stream, item_first);
                    try stream.write_all("...");
                    try self.write_inst_ref(stream, item_last);
                }

                const body = self.code.body_slice(extra_index, info.body_len);
                extra_index += info.body_len;
                try stream.write_all(" => ");
                try self.write_braced_body(stream, body);
            }
        }

        self.indent -= 2;

        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_field(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Field, inst_data.payload_index).data;
        const name = self.code.null_terminated_string(extra.field_name_start);
        try self.write_inst_ref(stream, extra.lhs);
        try stream.print(", \"{}\") ", .{std.zig.fmt_escapes(name)});
        try self.write_src(stream, inst_data.src());
    }

    fn write_pl_node_field_named(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.FieldNamed, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.lhs);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.field_name);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_as(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.As, inst_data.payload_index).data;
        try self.write_inst_ref(stream, extra.dest_type);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, extra.operand);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_node(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const src_node = self.code.instructions.items(.data)[@int_from_enum(inst)].node;
        const src = LazySrcLoc.nodeOffset(src_node);
        try stream.write_all(") ");
        try self.write_src(stream, src);
    }

    fn write_str_tok(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
    ) (@TypeOf(stream).Error || error{OutOfMemory})!void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].str_tok;
        const str = inst_data.get(self.code);
        try stream.print("\"{}\") ", .{std.zig.fmt_escapes(str)});
        try self.write_src(stream, inst_data.src());
    }

    fn write_str_op(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].str_op;
        const str = inst_data.get_str(self.code);
        try self.write_inst_ref(stream, inst_data.operand);
        try stream.print(", \"{}\")", .{std.zig.fmt_escapes(str)});
    }

    fn write_func(
        self: *Writer,
        stream: anytype,
        inst: Zir.Inst.Index,
        inferred_error_set: bool,
    ) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const src = inst_data.src();
        const extra = self.code.extra_data(Zir.Inst.Func, inst_data.payload_index);

        var extra_index = extra.end;
        var ret_ty_ref: Zir.Inst.Ref = .none;
        var ret_ty_body: []const Zir.Inst.Index = &.{};

        switch (extra.data.ret_body_len) {
            0 => {
                ret_ty_ref = .void_type;
            },
            1 => {
                ret_ty_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
                extra_index += 1;
            },
            else => {
                ret_ty_body = self.code.body_slice(extra_index, extra.data.ret_body_len);
                extra_index += ret_ty_body.len;
            },
        }

        const body = self.code.body_slice(extra_index, extra.data.body_len);
        extra_index += body.len;

        var src_locs: Zir.Inst.Func.SrcLocs = undefined;
        if (body.len != 0) {
            src_locs = self.code.extra_data(Zir.Inst.Func.SrcLocs, extra_index).data;
        }
        return self.write_func_common(
            stream,
            inferred_error_set,
            false,
            false,
            false,

            .none,
            &.{},
            .none,
            &.{},
            .none,
            &.{},
            .none,
            &.{},
            ret_ty_ref,
            ret_ty_body,

            body,
            src,
            src_locs,
            0,
        );
    }

    fn write_func_fancy(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.FuncFancy, inst_data.payload_index);
        const src = inst_data.src();

        var extra_index: usize = extra.end;
        var align_ref: Zir.Inst.Ref = .none;
        var align_body: []const Zir.Inst.Index = &.{};
        var addrspace_ref: Zir.Inst.Ref = .none;
        var addrspace_body: []const Zir.Inst.Index = &.{};
        var section_ref: Zir.Inst.Ref = .none;
        var section_body: []const Zir.Inst.Index = &.{};
        var cc_ref: Zir.Inst.Ref = .none;
        var cc_body: []const Zir.Inst.Index = &.{};
        var ret_ty_ref: Zir.Inst.Ref = .none;
        var ret_ty_body: []const Zir.Inst.Index = &.{};

        if (extra.data.bits.has_lib_name) {
            const lib_name = self.code.null_terminated_string(@enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            try stream.print("lib_name=\"{}\", ", .{std.zig.fmt_escapes(lib_name)});
        }
        try self.write_flag(stream, "test, ", extra.data.bits.is_test);

        if (extra.data.bits.has_align_body) {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            align_body = self.code.body_slice(extra_index, body_len);
            extra_index += align_body.len;
        } else if (extra.data.bits.has_align_ref) {
            align_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
        }
        if (extra.data.bits.has_addrspace_body) {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            addrspace_body = self.code.body_slice(extra_index, body_len);
            extra_index += addrspace_body.len;
        } else if (extra.data.bits.has_addrspace_ref) {
            addrspace_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
        }
        if (extra.data.bits.has_section_body) {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            section_body = self.code.body_slice(extra_index, body_len);
            extra_index += section_body.len;
        } else if (extra.data.bits.has_section_ref) {
            section_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
        }
        if (extra.data.bits.has_cc_body) {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            cc_body = self.code.body_slice(extra_index, body_len);
            extra_index += cc_body.len;
        } else if (extra.data.bits.has_cc_ref) {
            cc_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
        }
        if (extra.data.bits.has_ret_ty_body) {
            const body_len = self.code.extra[extra_index];
            extra_index += 1;
            ret_ty_body = self.code.body_slice(extra_index, body_len);
            extra_index += ret_ty_body.len;
        } else if (extra.data.bits.has_ret_ty_ref) {
            ret_ty_ref = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
        }

        const noalias_bits: u32 = if (extra.data.bits.has_any_noalias) blk: {
            const x = self.code.extra[extra_index];
            extra_index += 1;
            break :blk x;
        } else 0;

        const body = self.code.body_slice(extra_index, extra.data.body_len);
        extra_index += body.len;

        var src_locs: Zir.Inst.Func.SrcLocs = undefined;
        if (body.len != 0) {
            src_locs = self.code.extra_data(Zir.Inst.Func.SrcLocs, extra_index).data;
        }
        return self.write_func_common(
            stream,
            extra.data.bits.is_inferred_error,
            extra.data.bits.is_var_args,
            extra.data.bits.is_extern,
            extra.data.bits.is_noinline,
            align_ref,
            align_body,
            addrspace_ref,
            addrspace_body,
            section_ref,
            section_body,
            cc_ref,
            cc_body,
            ret_ty_ref,
            ret_ty_body,
            body,
            src,
            src_locs,
            noalias_bits,
        );
    }

    fn write_var_extended(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.ExtendedVar, extended.operand);
        const small = @as(Zir.Inst.ExtendedVar.Small, @bit_cast(extended.small));

        try self.write_inst_ref(stream, extra.data.var_type);

        var extra_index: usize = extra.end;
        if (small.has_lib_name) {
            const lib_name_index: Zir.NullTerminatedString = @enumFromInt(self.code.extra[extra_index]);
            const lib_name = self.code.null_terminated_string(lib_name_index);
            extra_index += 1;
            try stream.print(", lib_name=\"{}\"", .{std.zig.fmt_escapes(lib_name)});
        }
        const align_inst: Zir.Inst.Ref = if (!small.has_align) .none else blk: {
            const align_inst = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk align_inst;
        };
        const init_inst: Zir.Inst.Ref = if (!small.has_init) .none else blk: {
            const init_inst = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk init_inst;
        };
        try self.write_flag(stream, ", is_extern", small.is_extern);
        try self.write_flag(stream, ", is_threadlocal", small.is_threadlocal);
        try self.write_optional_inst_ref(stream, ", align=", align_inst);
        try self.write_optional_inst_ref(stream, ", init=", init_inst);
        try stream.write_all("))");
    }

    fn write_alloc_extended(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.AllocExtended, extended.operand);
        const small = @as(Zir.Inst.AllocExtended.Small, @bit_cast(extended.small));
        const src = LazySrcLoc.nodeOffset(extra.data.src_node);

        var extra_index: usize = extra.end;
        const type_inst: Zir.Inst.Ref = if (!small.has_type) .none else blk: {
            const type_inst = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk type_inst;
        };
        const align_inst: Zir.Inst.Ref = if (!small.has_align) .none else blk: {
            const align_inst = @as(Zir.Inst.Ref, @enumFromInt(self.code.extra[extra_index]));
            extra_index += 1;
            break :blk align_inst;
        };
        try self.write_flag(stream, ",is_const", small.is_const);
        try self.write_flag(stream, ",is_comptime", small.is_comptime);
        try self.write_optional_inst_ref(stream, ",ty=", type_inst);
        try self.write_optional_inst_ref(stream, ",align=", align_inst);
        try stream.write_all(")) ");
        try self.write_src(stream, src);
    }

    fn write_typeof_peer(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.TypeOfPeer, extended.operand);
        const body = self.code.body_slice(extra.data.body_index, extra.data.body_len);
        try self.write_braced_body(stream, body);
        try stream.write_all(",[");
        const args = self.code.ref_slice(extra.end, extended.small);
        for (args, 0..) |arg, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, arg);
        }
        try stream.write_all("])");
    }

    fn write_bool_br(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.BoolBr, inst_data.payload_index);
        const body = self.code.body_slice(extra.end, extra.data.body_len);
        try self.write_inst_ref(stream, extra.data.lhs);
        try stream.write_all(", ");
        try self.write_braced_body(stream, body);
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_int_type(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const int_type = self.code.instructions.items(.data)[@int_from_enum(inst)].int_type;
        const prefix: u8 = switch (int_type.signedness) {
            .signed => 'i',
            .unsigned => 'u',
        };
        try stream.print("{c}{d}) ", .{ prefix, int_type.bit_count });
        try self.write_src(stream, int_type.src());
    }

    fn write_save_err_ret_index(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].save_err_ret_index;

        try self.write_inst_ref(stream, inst_data.operand);

        try stream.write_all(")");
    }

    fn write_restore_err_ret_index(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const extra = self.code.extra_data(Zir.Inst.RestoreErrRetIndex, extended.operand).data;

        try self.write_inst_ref(stream, extra.block);
        try self.write_inst_ref(stream, extra.operand);

        try stream.write_all(") ");
        try self.write_src(stream, extra.src());
    }

    fn write_break(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].@"break";
        const extra = self.code.extra_data(Zir.Inst.Break, inst_data.payload_index).data;

        try self.write_inst_index(stream, extra.block_inst);
        try stream.write_all(", ");
        try self.write_inst_ref(stream, inst_data.operand);
        try stream.write_all(")");
    }

    fn write_array_init(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;

        const extra = self.code.extra_data(Zir.Inst.MultiOp, inst_data.payload_index);
        const args = self.code.ref_slice(extra.end, extra.data.operands_len);

        try self.write_inst_ref(stream, args[0]);
        try stream.write_all("{");
        for (args[1..], 0..) |arg, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, arg);
        }
        try stream.write_all("}) ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_array_init_anon(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;

        const extra = self.code.extra_data(Zir.Inst.MultiOp, inst_data.payload_index);
        const args = self.code.ref_slice(extra.end, extra.data.operands_len);

        try stream.write_all("{");
        for (args, 0..) |arg, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, arg);
        }
        try stream.write_all("}) ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_array_init_sent(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;

        const extra = self.code.extra_data(Zir.Inst.MultiOp, inst_data.payload_index);
        const args = self.code.ref_slice(extra.end, extra.data.operands_len);
        const sent = args[args.len - 1];
        const elems = args[0 .. args.len - 1];

        try self.write_inst_ref(stream, sent);
        try stream.write_all(", ");

        try stream.write_all(".{");
        for (elems, 0..) |elem, i| {
            if (i != 0) try stream.write_all(", ");
            try self.write_inst_ref(stream, elem);
        }
        try stream.write_all("}) ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_unreachable(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].@"unreachable";
        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_func_common(
        self: *Writer,
        stream: anytype,
        inferred_error_set: bool,
        var_args: bool,
        is_extern: bool,
        is_noinline: bool,
        align_ref: Zir.Inst.Ref,
        align_body: []const Zir.Inst.Index,
        addrspace_ref: Zir.Inst.Ref,
        addrspace_body: []const Zir.Inst.Index,
        section_ref: Zir.Inst.Ref,
        section_body: []const Zir.Inst.Index,
        cc_ref: Zir.Inst.Ref,
        cc_body: []const Zir.Inst.Index,
        ret_ty_ref: Zir.Inst.Ref,
        ret_ty_body: []const Zir.Inst.Index,
        body: []const Zir.Inst.Index,
        src: LazySrcLoc,
        src_locs: Zir.Inst.Func.SrcLocs,
        noalias_bits: u32,
    ) !void {
        try self.write_optional_inst_ref_or_body(stream, "align=", align_ref, align_body);
        try self.write_optional_inst_ref_or_body(stream, "addrspace=", addrspace_ref, addrspace_body);
        try self.write_optional_inst_ref_or_body(stream, "section=", section_ref, section_body);
        try self.write_optional_inst_ref_or_body(stream, "cc=", cc_ref, cc_body);
        try self.write_optional_inst_ref_or_body(stream, "ret_ty=", ret_ty_ref, ret_ty_body);
        try self.write_flag(stream, "vargs, ", var_args);
        try self.write_flag(stream, "extern, ", is_extern);
        try self.write_flag(stream, "inferror, ", inferred_error_set);
        try self.write_flag(stream, "noinline, ", is_noinline);

        if (noalias_bits != 0) {
            try stream.print("noalias=0b{b}, ", .{noalias_bits});
        }

        try stream.write_all("body=");
        try self.write_braced_body(stream, body);
        try stream.write_all(") ");
        if (body.len != 0) {
            try stream.print("(lbrace={d}:{d},rbrace={d}:{d}) ", .{
                src_locs.lbrace_line + 1, @as(u16, @truncate(src_locs.columns)) + 1,
                src_locs.rbrace_line + 1, @as(u16, @truncate(src_locs.columns >> 16)) + 1,
            });
        }
        try self.write_src(stream, src);
    }

    fn write_dbg_stmt(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].dbg_stmt;
        try stream.print("{d}, {d})", .{ inst_data.line + 1, inst_data.column + 1 });
    }

    fn write_defer(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].@"defer";
        const body = self.code.body_slice(inst_data.index, inst_data.len);
        try self.write_braced_body(stream, body);
        try stream.write_byte(')');
    }

    fn write_defer_err_code(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].defer_err_code;
        const extra = self.code.extra_data(Zir.Inst.DeferErrCode, inst_data.payload_index).data;

        try self.write_inst_ref(stream, extra.remapped_err_code.to_ref());
        try stream.write_all(" = ");
        try self.write_inst_ref(stream, inst_data.err_code);
        try stream.write_all(", ");
        const body = self.code.body_slice(extra.index, extra.len);
        try self.write_braced_body(stream, body);
        try stream.write_byte(')');
    }

    fn write_declaration(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        const inst_data = self.code.instructions.items(.data)[@int_from_enum(inst)].pl_node;
        const extra = self.code.extra_data(Zir.Inst.Declaration, inst_data.payload_index);
        const doc_comment: ?Zir.NullTerminatedString = if (extra.data.flags.has_doc_comment) dc: {
            break :dc @enumFromInt(self.code.extra[extra.end]);
        } else null;
        if (extra.data.flags.is_pub) try stream.write_all("pub ");
        if (extra.data.flags.is_export) try stream.write_all("export ");
        switch (extra.data.name) {
            .@"comptime" => try stream.write_all("comptime"),
            .@"usingnamespace" => try stream.write_all("usingnamespace"),
            .unnamed_test => try stream.write_all("test"),
            .decltest => try stream.print("decltest '{s}'", .{self.code.null_terminated_string(doc_comment.?)}),
            _ => {
                const name = extra.data.name.to_string(self.code).?;
                const prefix = if (extra.data.name.is_named_test(self.code)) "test " else "";
                try stream.print("{s}'{s}'", .{ prefix, self.code.null_terminated_string(name) });
            },
        }
        const src_hash_arr: [4]u32 = .{
            extra.data.src_hash_0,
            extra.data.src_hash_1,
            extra.data.src_hash_2,
            extra.data.src_hash_3,
        };
        const src_hash_bytes: [16]u8 = @bit_cast(src_hash_arr);
        try stream.print(" line(+{d}) hash({})", .{ extra.data.line_offset, std.fmt.fmt_slice_hex_lower(&src_hash_bytes) });

        {
            const prev_parent_decl_node = self.parent_decl_node;
            defer self.parent_decl_node = prev_parent_decl_node;
            self.parent_decl_node = self.relative_to_node_index(inst_data.src_node);

            const bodies = extra.data.get_bodies(@int_cast(extra.end), self.code);

            try stream.write_all(" value=");
            try self.write_braced_decl(stream, bodies.value_body);

            if (bodies.align_body) |b| {
                try stream.write_all(" align=");
                try self.write_braced_decl(stream, b);
            }

            if (bodies.linksection_body) |b| {
                try stream.write_all(" linksection=");
                try self.write_braced_decl(stream, b);
            }

            if (bodies.addrspace_body) |b| {
                try stream.write_all(" addrspace=");
                try self.write_braced_decl(stream, b);
            }
        }

        try stream.write_all(") ");
        try self.write_src(stream, inst_data.src());
    }

    fn write_closure_get(self: *Writer, stream: anytype, extended: Zir.Inst.Extended.InstData) !void {
        const src = LazySrcLoc.nodeOffset(@bit_cast(extended.operand));
        try stream.print("{d})) ", .{extended.small});
        try self.write_src(stream, src);
    }

    fn write_inst_ref(self: *Writer, stream: anytype, ref: Zir.Inst.Ref) !void {
        if (ref == .none) {
            return stream.write_all(".none");
        } else if (ref.to_index()) |i| {
            return self.write_inst_index(stream, i);
        } else {
            const val: InternPool.Index = @enumFromInt(@int_from_enum(ref));
            return stream.print("@{s}", .{@tag_name(val)});
        }
    }

    fn write_inst_index(self: *Writer, stream: anytype, inst: Zir.Inst.Index) !void {
        _ = self;
        return stream.print("%{d}", .{@int_from_enum(inst)});
    }

    fn write_capture(self: *Writer, stream: anytype, capture: Zir.Inst.Capture) !void {
        switch (capture.unwrap()) {
            .nested => |i| return stream.print("[{d}]", .{i}),
            .instruction => |inst| return self.write_inst_index(stream, inst),
            .instruction_load => |ptr_inst| {
                try stream.write_all("load ");
                try self.write_inst_index(stream, ptr_inst);
            },
            .decl_val => |str| try stream.print("decl_val \"{}\"", .{
                std.zig.fmt_escapes(self.code.null_terminated_string(str)),
            }),
            .decl_ref => |str| try stream.print("decl_ref \"{}\"", .{
                std.zig.fmt_escapes(self.code.null_terminated_string(str)),
            }),
        }
    }

    fn write_optional_inst_ref(
        self: *Writer,
        stream: anytype,
        prefix: []const u8,
        inst: Zir.Inst.Ref,
    ) !void {
        if (inst == .none) return;
        try stream.write_all(prefix);
        try self.write_inst_ref(stream, inst);
    }

    fn write_optional_inst_ref_or_body(
        self: *Writer,
        stream: anytype,
        prefix: []const u8,
        ref: Zir.Inst.Ref,
        body: []const Zir.Inst.Index,
    ) !void {
        if (body.len != 0) {
            try stream.write_all(prefix);
            try self.write_braced_body(stream, body);
            try stream.write_all(", ");
        } else if (ref != .none) {
            try stream.write_all(prefix);
            try self.write_inst_ref(stream, ref);
            try stream.write_all(", ");
        }
    }

    fn write_flag(
        self: *Writer,
        stream: anytype,
        name: []const u8,
        flag: bool,
    ) !void {
        _ = self;
        if (!flag) return;
        try stream.write_all(name);
    }

    fn write_src(self: *Writer, stream: anytype, src: LazySrcLoc) !void {
        if (self.file.tree_loaded) {
            const tree = self.file.tree;
            const src_loc: Module.SrcLoc = .{
                .file_scope = self.file,
                .parent_decl_node = self.parent_decl_node,
                .lazy = src,
            };
            const src_span = src_loc.span(self.gpa) catch unreachable;
            const start = self.line_col_cursor.find(tree.source, src_span.start);
            const end = self.line_col_cursor.find(tree.source, src_span.end);
            try stream.print("{s}:{d}:{d} to :{d}:{d}", .{
                @tag_name(src), start.line + 1, start.column + 1,
                end.line + 1,  end.column + 1,
            });
        }
    }

    fn write_src_node(self: *Writer, stream: anytype, src_node: ?i32) !void {
        const node_offset = src_node orelse return;
        const src = LazySrcLoc.nodeOffset(node_offset);
        try stream.write_all(" ");
        return self.write_src(stream, src);
    }

    fn write_braced_decl(self: *Writer, stream: anytype, body: []const Zir.Inst.Index) !void {
        try self.write_braced_body_conditional(stream, body, self.recurse_decls);
    }

    fn write_braced_body(self: *Writer, stream: anytype, body: []const Zir.Inst.Index) !void {
        try self.write_braced_body_conditional(stream, body, self.recurse_blocks);
    }

    fn write_braced_body_conditional(self: *Writer, stream: anytype, body: []const Zir.Inst.Index, enabled: bool) !void {
        if (body.len == 0) {
            try stream.write_all("{}");
        } else if (enabled) {
            try stream.write_all("{\n");
            self.indent += 2;
            try self.write_body(stream, body);
            self.indent -= 2;
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.write_all("}");
        } else if (body.len == 1) {
            try stream.write_byte('{');
            try self.write_inst_index(stream, body[0]);
            try stream.write_byte('}');
        } else if (body.len == 2) {
            try stream.write_byte('{');
            try self.write_inst_index(stream, body[0]);
            try stream.write_all(", ");
            try self.write_inst_index(stream, body[1]);
            try stream.write_byte('}');
        } else {
            try stream.write_byte('{');
            try self.write_inst_index(stream, body[0]);
            try stream.write_all("..");
            try self.write_inst_index(stream, body[body.len - 1]);
            try stream.write_byte('}');
        }
    }

    fn write_doc_comment(self: *Writer, stream: anytype, doc_comment_index: Zir.NullTerminatedString) !void {
        if (doc_comment_index != .empty) {
            const doc_comment = self.code.null_terminated_string(doc_comment_index);
            var it = std.mem.tokenize_scalar(u8, doc_comment, '\n');
            while (it.next()) |doc_line| {
                try stream.write_byte_ntimes(' ', self.indent);
                try stream.print("///{s}\n", .{doc_line});
            }
        }
    }

    fn write_body(self: *Writer, stream: anytype, body: []const Zir.Inst.Index) !void {
        for (body) |inst| {
            try stream.write_byte_ntimes(' ', self.indent);
            try stream.print("%{d} ", .{@int_from_enum(inst)});
            try self.write_inst_to_stream(stream, inst);
            try stream.write_byte('\n');
        }
    }
};
