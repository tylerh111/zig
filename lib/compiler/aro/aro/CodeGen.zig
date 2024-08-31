const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const backend = @import("../backend.zig");
const Interner = backend.Interner;
const Ir = backend.Ir;
const Builtins = @import("Builtins.zig");
const Builtin = Builtins.Builtin;
const Compilation = @import("Compilation.zig");
const Builder = Ir.Builder;
const StrInt = @import("StringInterner.zig");
const StringId = StrInt.StringId;
const Tree = @import("Tree.zig");
const NodeIndex = Tree.NodeIndex;
const Type = @import("Type.zig");
const Value = @import("Value.zig");

const WipSwitch = struct {
    cases: Cases = .{},
    default: ?Ir.Ref = null,
    size: u64,

    const Cases = std.MultiArrayList(struct {
        val: Interner.Ref,
        label: Ir.Ref,
    });
};

const Symbol = struct {
    name: StringId,
    val: Ir.Ref,
};

const Error = Compilation.Error;

const CodeGen = @This();

tree: Tree,
comp: *Compilation,
builder: Builder,
node_tag: []const Tree.Tag,
node_data: []const Tree.Node.Data,
node_ty: []const Type,
wip_switch: *WipSwitch = undefined,
symbols: std.ArrayListUnmanaged(Symbol) = .{},
ret_nodes: std.ArrayListUnmanaged(Ir.Inst.Phi.Input) = .{},
phi_nodes: std.ArrayListUnmanaged(Ir.Inst.Phi.Input) = .{},
record_elem_buf: std.ArrayListUnmanaged(Interner.Ref) = .{},
record_cache: std.AutoHashMapUnmanaged(*Type.Record, Interner.Ref) = .{},
cond_dummy_ty: ?Interner.Ref = null,
bool_invert: bool = false,
bool_end_label: Ir.Ref = .none,
cond_dummy_ref: Ir.Ref = undefined,
continue_label: Ir.Ref = undefined,
break_label: Ir.Ref = undefined,
return_label: Ir.Ref = undefined,

fn fail(c: *CodeGen, comptime fmt: []const u8, args: anytype) error{ FatalError, OutOfMemory } {
    try c.comp.diagnostics.list.append(c.comp.gpa, .{
        .tag = .cli_error,
        .kind = .@"fatal error",
        .extra = .{ .str = try std.fmt.alloc_print(c.comp.diagnostics.arena.allocator(), fmt, args) },
    });
    return error.FatalError;
}

pub fn gen_ir(tree: Tree) Compilation.Error!Ir {
    const gpa = tree.comp.gpa;
    var c = CodeGen{
        .builder = .{
            .gpa = tree.comp.gpa,
            .interner = &tree.comp.interner,
            .arena = std.heap.ArenaAllocator.init(gpa),
        },
        .tree = tree,
        .comp = tree.comp,
        .node_tag = tree.nodes.items(.tag),
        .node_data = tree.nodes.items(.data),
        .node_ty = tree.nodes.items(.ty),
    };
    defer c.symbols.deinit(gpa);
    defer c.ret_nodes.deinit(gpa);
    defer c.phi_nodes.deinit(gpa);
    defer c.record_elem_buf.deinit(gpa);
    defer c.record_cache.deinit(gpa);
    defer c.builder.deinit();

    const node_tags = tree.nodes.items(.tag);
    for (tree.root_decls) |decl| {
        c.builder.arena.deinit();
        c.builder.arena = std.heap.ArenaAllocator.init(gpa);

        switch (node_tags[@int_from_enum(decl)]) {
            .static_assert,
            .typedef,
            .struct_decl_two,
            .union_decl_two,
            .enum_decl_two,
            .struct_decl,
            .union_decl,
            .enum_decl,
            => {},

            .fn_proto,
            .static_fn_proto,
            .inline_fn_proto,
            .inline_static_fn_proto,
            .extern_var,
            .threadlocal_extern_var,
            => {},

            .fn_def,
            .static_fn_def,
            .inline_fn_def,
            .inline_static_fn_def,
            => c.gen_fn(decl) catch |err| switch (err) {
                error.FatalError => return error.FatalError,
                error.OutOfMemory => return error.OutOfMemory,
            },

            .@"var",
            .static_var,
            .threadlocal_var,
            .threadlocal_static_var,
            => c.gen_var(decl) catch |err| switch (err) {
                error.FatalError => return error.FatalError,
                error.OutOfMemory => return error.OutOfMemory,
            },
            else => unreachable,
        }
    }
    return c.builder.finish();
}

fn gen_type(c: *CodeGen, base_ty: Type) !Interner.Ref {
    var key: Interner.Key = undefined;
    const ty = base_ty.canonicalize(.standard);
    switch (ty.specifier) {
        .void => return .void,
        .bool => return .i1,
        .@"struct" => {
            if (c.record_cache.get(ty.data.record)) |some| return some;

            const elem_buf_top = c.record_elem_buf.items.len;
            defer c.record_elem_buf.items.len = elem_buf_top;

            for (ty.data.record.fields) |field| {
                if (!field.is_regular_field()) {
                    return c.fail("TODO lower struct bitfields", .{});
                }
                // TODO handle padding bits
                const field_ref = try c.gen_type(field.ty);
                try c.record_elem_buf.append(c.builder.gpa, field_ref);
            }

            return c.builder.interner.put(c.builder.gpa, .{
                .record_ty = c.record_elem_buf.items[elem_buf_top..],
            });
        },
        .@"union" => {
            return c.fail("TODO lower union types", .{});
        },
        else => {},
    }
    if (ty.is_ptr()) return .ptr;
    if (ty.is_func()) return .func;
    if (!ty.is_real()) return c.fail("TODO lower complex types", .{});
    if (ty.is_int()) {
        const bits = ty.bit_sizeof(c.comp).?;
        key = .{ .int_ty = @int_cast(bits) };
    } else if (ty.is_float()) {
        const bits = ty.bit_sizeof(c.comp).?;
        key = .{ .float_ty = @int_cast(bits) };
    } else if (ty.is_array()) {
        const elem = try c.gen_type(ty.elem_type());
        key = .{ .array_ty = .{ .child = elem, .len = ty.array_len().? } };
    } else if (ty.specifier == .vector) {
        const elem = try c.gen_type(ty.elem_type());
        key = .{ .vector_ty = .{ .child = elem, .len = @int_cast(ty.data.array.len) } };
    } else if (ty.is(.nullptr_t)) {
        return c.fail("TODO lower nullptr_t", .{});
    }
    return c.builder.interner.put(c.builder.gpa, key);
}

fn gen_fn(c: *CodeGen, decl: NodeIndex) Error!void {
    const name = c.tree.tok_slice(c.node_data[@int_from_enum(decl)].decl.name);
    const func_ty = c.node_ty[@int_from_enum(decl)].canonicalize(.standard);
    c.ret_nodes.items.len = 0;

    try c.builder.start_fn();

    for (func_ty.data.func.params) |param| {
        // TODO handle calling convention here
        const arg = try c.builder.add_arg(try c.gen_type(param.ty));

        const size: u32 = @int_cast(param.ty.sizeof(c.comp).?); // TODO add error in parser
        const @"align" = param.ty.alignof(c.comp);
        const alloc = try c.builder.add_alloc(size, @"align");
        try c.builder.add_store(alloc, arg);
        try c.symbols.append(c.comp.gpa, .{ .name = param.name, .val = alloc });
    }

    // Generate body
    c.return_label = try c.builder.make_label("return");
    try c.gen_stmt(c.node_data[@int_from_enum(decl)].decl.node);

    // Relocate returns
    if (c.ret_nodes.items.len == 0) {
        _ = try c.builder.add_inst(.ret, .{ .un = .none }, .noreturn);
    } else if (c.ret_nodes.items.len == 1) {
        c.builder.body.items.len -= 1;
        _ = try c.builder.add_inst(.ret, .{ .un = c.ret_nodes.items[0].value }, .noreturn);
    } else {
        try c.builder.start_block(c.return_label);
        const phi = try c.builder.add_phi(c.ret_nodes.items, try c.gen_type(func_ty.return_type()));
        _ = try c.builder.add_inst(.ret, .{ .un = phi }, .noreturn);
    }

    try c.builder.finish_fn(name);
}

fn add_un(c: *CodeGen, tag: Ir.Inst.Tag, operand: Ir.Ref, ty: Type) !Ir.Ref {
    return c.builder.add_inst(tag, .{ .un = operand }, try c.gen_type(ty));
}

fn add_bin(c: *CodeGen, tag: Ir.Inst.Tag, lhs: Ir.Ref, rhs: Ir.Ref, ty: Type) !Ir.Ref {
    return c.builder.add_inst(tag, .{ .bin = .{ .lhs = lhs, .rhs = rhs } }, try c.gen_type(ty));
}

fn add_branch(c: *CodeGen, cond: Ir.Ref, true_label: Ir.Ref, false_label: Ir.Ref) !void {
    if (true_label == c.bool_end_label) {
        if (false_label == c.bool_end_label) {
            try c.phi_nodes.append(c.comp.gpa, .{ .label = c.builder.current_label, .value = cond });
            return;
        }
        try c.add_bool_phi(!c.bool_invert);
    }
    if (false_label == c.bool_end_label) {
        try c.add_bool_phi(c.bool_invert);
    }
    return c.builder.add_branch(cond, true_label, false_label);
}

fn add_bool_phi(c: *CodeGen, value: bool) !void {
    const val = try c.builder.add_constant((try Value.int(@int_from_bool(value), c.comp)).ref(), .i1);
    try c.phi_nodes.append(c.comp.gpa, .{ .label = c.builder.current_label, .value = val });
}

fn gen_stmt(c: *CodeGen, node: NodeIndex) Error!void {
    _ = try c.gen_expr(node);
}

fn gen_expr(c: *CodeGen, node: NodeIndex) Error!Ir.Ref {
    std.debug.assert(node != .none);
    const ty = c.node_ty[@int_from_enum(node)];
    if (c.tree.value_map.get(node)) |val| {
        return c.builder.add_constant(val.ref(), try c.gen_type(ty));
    }
    const data = c.node_data[@int_from_enum(node)];
    switch (c.node_tag[@int_from_enum(node)]) {
        .enumeration_ref,
        .bool_literal,
        .int_literal,
        .char_literal,
        .float_literal,
        .imaginary_literal,
        .string_literal_expr,
        .alignof_expr,
        => unreachable, // These should have an entry in value_map.
        .fn_def,
        .static_fn_def,
        .inline_fn_def,
        .inline_static_fn_def,
        .invalid,
        .threadlocal_var,
        => unreachable,
        .static_assert,
        .fn_proto,
        .static_fn_proto,
        .inline_fn_proto,
        .inline_static_fn_proto,
        .extern_var,
        .threadlocal_extern_var,
        .typedef,
        .struct_decl_two,
        .union_decl_two,
        .enum_decl_two,
        .struct_decl,
        .union_decl,
        .enum_decl,
        .enum_field_decl,
        .record_field_decl,
        .indirect_record_field_decl,
        .struct_forward_decl,
        .union_forward_decl,
        .enum_forward_decl,
        .null_stmt,
        => {},
        .static_var,
        .implicit_static_var,
        .threadlocal_static_var,
        => try c.gen_var(node), // TODO
        .@"var" => {
            const size: u32 = @int_cast(ty.sizeof(c.comp).?); // TODO add error in parser
            const @"align" = ty.alignof(c.comp);
            const alloc = try c.builder.add_alloc(size, @"align");
            const name = try StrInt.intern(c.comp, c.tree.tok_slice(data.decl.name));
            try c.symbols.append(c.comp.gpa, .{ .name = name, .val = alloc });
            if (data.decl.node != .none) {
                try c.gen_initializer(alloc, ty, data.decl.node);
            }
        },
        .labeled_stmt => {
            const label = try c.builder.make_label("label");
            try c.builder.start_block(label);
            try c.gen_stmt(data.decl.node);
        },
        .compound_stmt_two => {
            const old_sym_len = c.symbols.items.len;
            c.symbols.items.len = old_sym_len;

            if (data.bin.lhs != .none) try c.gen_stmt(data.bin.lhs);
            if (data.bin.rhs != .none) try c.gen_stmt(data.bin.rhs);
        },
        .compound_stmt => {
            const old_sym_len = c.symbols.items.len;
            c.symbols.items.len = old_sym_len;

            for (c.tree.data[data.range.start..data.range.end]) |stmt| try c.gen_stmt(stmt);
        },
        .if_then_else_stmt => {
            const then_label = try c.builder.make_label("if.then");
            const else_label = try c.builder.make_label("if.else");
            const end_label = try c.builder.make_label("if.end");

            try c.gen_bool_expr(data.if3.cond, then_label, else_label);

            try c.builder.start_block(then_label);
            try c.gen_stmt(c.tree.data[data.if3.body]); // then
            try c.builder.add_jump(end_label);

            try c.builder.start_block(else_label);
            try c.gen_stmt(c.tree.data[data.if3.body + 1]); // else

            try c.builder.start_block(end_label);
        },
        .if_then_stmt => {
            const then_label = try c.builder.make_label("if.then");
            const end_label = try c.builder.make_label("if.end");

            try c.gen_bool_expr(data.bin.lhs, then_label, end_label);

            try c.builder.start_block(then_label);
            try c.gen_stmt(data.bin.rhs); // then
            try c.builder.start_block(end_label);
        },
        .switch_stmt => {
            var wip_switch = WipSwitch{
                .size = c.node_ty[@int_from_enum(data.bin.lhs)].sizeof(c.comp).?,
            };
            defer wip_switch.cases.deinit(c.builder.gpa);

            const old_wip_switch = c.wip_switch;
            defer c.wip_switch = old_wip_switch;
            c.wip_switch = &wip_switch;

            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;
            const end_ref = try c.builder.make_label("switch.end");
            c.break_label = end_ref;

            const cond = try c.gen_expr(data.bin.lhs);
            const switch_index = c.builder.instructions.len;
            _ = try c.builder.add_inst(.@"switch", undefined, .noreturn);

            try c.gen_stmt(data.bin.rhs); // body

            const default_ref = wip_switch.default orelse end_ref;
            try c.builder.start_block(end_ref);

            const a = c.builder.arena.allocator();
            const switch_data = try a.create(Ir.Inst.Switch);
            switch_data.* = .{
                .target = cond,
                .cases_len = @int_cast(wip_switch.cases.len),
                .case_vals = (try a.dupe(Interner.Ref, wip_switch.cases.items(.val))).ptr,
                .case_labels = (try a.dupe(Ir.Ref, wip_switch.cases.items(.label))).ptr,
                .default = default_ref,
            };
            c.builder.instructions.items(.data)[switch_index] = .{ .@"switch" = switch_data };
        },
        .case_stmt => {
            const val = c.tree.value_map.get(data.bin.lhs).?;
            const label = try c.builder.make_label("case");
            try c.builder.start_block(label);
            try c.wip_switch.cases.append(c.builder.gpa, .{
                .val = val.ref(),
                .label = label,
            });
            try c.gen_stmt(data.bin.rhs);
        },
        .default_stmt => {
            const default = try c.builder.make_label("default");
            try c.builder.start_block(default);
            c.wip_switch.default = default;
            try c.gen_stmt(data.un);
        },
        .while_stmt => {
            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;

            const old_continue_label = c.continue_label;
            defer c.continue_label = old_continue_label;

            const cond_label = try c.builder.make_label("while.cond");
            const then_label = try c.builder.make_label("while.then");
            const end_label = try c.builder.make_label("while.end");

            c.continue_label = cond_label;
            c.break_label = end_label;

            try c.builder.start_block(cond_label);
            try c.gen_bool_expr(data.bin.lhs, then_label, end_label);

            try c.builder.start_block(then_label);
            try c.gen_stmt(data.bin.rhs);
            try c.builder.add_jump(cond_label);
            try c.builder.start_block(end_label);
        },
        .do_while_stmt => {
            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;

            const old_continue_label = c.continue_label;
            defer c.continue_label = old_continue_label;

            const then_label = try c.builder.make_label("do.then");
            const cond_label = try c.builder.make_label("do.cond");
            const end_label = try c.builder.make_label("do.end");

            c.continue_label = cond_label;
            c.break_label = end_label;

            try c.builder.start_block(then_label);
            try c.gen_stmt(data.bin.rhs);

            try c.builder.start_block(cond_label);
            try c.gen_bool_expr(data.bin.lhs, then_label, end_label);

            try c.builder.start_block(end_label);
        },
        .for_decl_stmt => {
            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;

            const old_continue_label = c.continue_label;
            defer c.continue_label = old_continue_label;

            const for_decl = data.for_decl(&c.tree);
            for (for_decl.decls) |decl| try c.gen_stmt(decl);

            const then_label = try c.builder.make_label("for.then");
            var cond_label = then_label;
            const cont_label = try c.builder.make_label("for.cont");
            const end_label = try c.builder.make_label("for.end");

            c.continue_label = cont_label;
            c.break_label = end_label;

            if (for_decl.cond != .none) {
                cond_label = try c.builder.make_label("for.cond");
                try c.builder.start_block(cond_label);
                try c.gen_bool_expr(for_decl.cond, then_label, end_label);
            }
            try c.builder.start_block(then_label);
            try c.gen_stmt(for_decl.body);
            if (for_decl.incr != .none) {
                _ = try c.gen_expr(for_decl.incr);
            }
            try c.builder.add_jump(cond_label);
            try c.builder.start_block(end_label);
        },
        .forever_stmt => {
            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;

            const old_continue_label = c.continue_label;
            defer c.continue_label = old_continue_label;

            const then_label = try c.builder.make_label("for.then");
            const end_label = try c.builder.make_label("for.end");

            c.continue_label = then_label;
            c.break_label = end_label;

            try c.builder.start_block(then_label);
            try c.gen_stmt(data.un);
            try c.builder.start_block(end_label);
        },
        .for_stmt => {
            const old_break_label = c.break_label;
            defer c.break_label = old_break_label;

            const old_continue_label = c.continue_label;
            defer c.continue_label = old_continue_label;

            const for_stmt = data.for_stmt(&c.tree);
            if (for_stmt.init != .none) _ = try c.gen_expr(for_stmt.init);

            const then_label = try c.builder.make_label("for.then");
            var cond_label = then_label;
            const cont_label = try c.builder.make_label("for.cont");
            const end_label = try c.builder.make_label("for.end");

            c.continue_label = cont_label;
            c.break_label = end_label;

            if (for_stmt.cond != .none) {
                cond_label = try c.builder.make_label("for.cond");
                try c.builder.start_block(cond_label);
                try c.gen_bool_expr(for_stmt.cond, then_label, end_label);
            }
            try c.builder.start_block(then_label);
            try c.gen_stmt(for_stmt.body);
            if (for_stmt.incr != .none) {
                _ = try c.gen_expr(for_stmt.incr);
            }
            try c.builder.add_jump(cond_label);
            try c.builder.start_block(end_label);
        },
        .continue_stmt => try c.builder.add_jump(c.continue_label),
        .break_stmt => try c.builder.add_jump(c.break_label),
        .return_stmt => {
            if (data.un != .none) {
                const operand = try c.gen_expr(data.un);
                try c.ret_nodes.append(c.comp.gpa, .{ .value = operand, .label = c.builder.current_label });
            }
            try c.builder.add_jump(c.return_label);
        },
        .implicit_return => {
            if (data.return_zero) {
                const operand = try c.builder.add_constant(.zero, try c.gen_type(ty));
                try c.ret_nodes.append(c.comp.gpa, .{ .value = operand, .label = c.builder.current_label });
            }
            // No need to emit a jump since implicit_return is always the last instruction.
        },
        .case_range_stmt,
        .goto_stmt,
        .computed_goto_stmt,
        .nullptr_literal,
        => return c.fail("TODO CodeGen.gen_stmt {}\n", .{c.node_tag[@int_from_enum(node)]}),
        .comma_expr => {
            _ = try c.gen_expr(data.bin.lhs);
            return c.gen_expr(data.bin.rhs);
        },
        .assign_expr => {
            const rhs = try c.gen_expr(data.bin.rhs);
            const lhs = try c.gen_lval(data.bin.lhs);
            try c.builder.add_store(lhs, rhs);
            return rhs;
        },
        .mul_assign_expr => return c.gen_compound_assign(node, .mul),
        .div_assign_expr => return c.gen_compound_assign(node, .div),
        .mod_assign_expr => return c.gen_compound_assign(node, .mod),
        .add_assign_expr => return c.gen_compound_assign(node, .add),
        .sub_assign_expr => return c.gen_compound_assign(node, .sub),
        .shl_assign_expr => return c.gen_compound_assign(node, .bit_shl),
        .shr_assign_expr => return c.gen_compound_assign(node, .bit_shr),
        .bit_and_assign_expr => return c.gen_compound_assign(node, .bit_and),
        .bit_xor_assign_expr => return c.gen_compound_assign(node, .bit_xor),
        .bit_or_assign_expr => return c.gen_compound_assign(node, .bit_or),
        .bit_or_expr => return c.gen_bin_op(node, .bit_or),
        .bit_xor_expr => return c.gen_bin_op(node, .bit_xor),
        .bit_and_expr => return c.gen_bin_op(node, .bit_and),
        .equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_eq);
            return c.add_un(.zext, cmp, ty);
        },
        .not_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_ne);
            return c.add_un(.zext, cmp, ty);
        },
        .less_than_expr => {
            const cmp = try c.gen_comparison(node, .cmp_lt);
            return c.add_un(.zext, cmp, ty);
        },
        .less_than_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_lte);
            return c.add_un(.zext, cmp, ty);
        },
        .greater_than_expr => {
            const cmp = try c.gen_comparison(node, .cmp_gt);
            return c.add_un(.zext, cmp, ty);
        },
        .greater_than_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_gte);
            return c.add_un(.zext, cmp, ty);
        },
        .shl_expr => return c.gen_bin_op(node, .bit_shl),
        .shr_expr => return c.gen_bin_op(node, .bit_shr),
        .add_expr => {
            if (ty.is_ptr()) {
                const lhs_ty = c.node_ty[@int_from_enum(data.bin.lhs)];
                if (lhs_ty.is_ptr()) {
                    const ptr = try c.gen_expr(data.bin.lhs);
                    const offset = try c.gen_expr(data.bin.rhs);
                    const offset_ty = c.node_ty[@int_from_enum(data.bin.rhs)];
                    return c.gen_ptr_arithmetic(ptr, offset, offset_ty, ty);
                } else {
                    const offset = try c.gen_expr(data.bin.lhs);
                    const ptr = try c.gen_expr(data.bin.rhs);
                    const offset_ty = lhs_ty;
                    return c.gen_ptr_arithmetic(ptr, offset, offset_ty, ty);
                }
            }
            return c.gen_bin_op(node, .add);
        },
        .sub_expr => {
            if (ty.is_ptr()) {
                const ptr = try c.gen_expr(data.bin.lhs);
                const offset = try c.gen_expr(data.bin.rhs);
                const offset_ty = c.node_ty[@int_from_enum(data.bin.rhs)];
                return c.gen_ptr_arithmetic(ptr, offset, offset_ty, ty);
            }
            return c.gen_bin_op(node, .sub);
        },
        .mul_expr => return c.gen_bin_op(node, .mul),
        .div_expr => return c.gen_bin_op(node, .div),
        .mod_expr => return c.gen_bin_op(node, .mod),
        .addr_of_expr => return try c.gen_lval(data.un),
        .deref_expr => {
            const un_data = c.node_data[@int_from_enum(data.un)];
            if (c.node_tag[@int_from_enum(data.un)] == .implicit_cast and un_data.cast.kind == .function_to_pointer) {
                return c.gen_expr(data.un);
            }
            const operand = try c.gen_lval(data.un);
            return c.add_un(.load, operand, ty);
        },
        .plus_expr => return c.gen_expr(data.un),
        .negate_expr => {
            const zero = try c.builder.add_constant(.zero, try c.gen_type(ty));
            const operand = try c.gen_expr(data.un);
            return c.add_bin(.sub, zero, operand, ty);
        },
        .bit_not_expr => {
            const operand = try c.gen_expr(data.un);
            return c.add_un(.bit_not, operand, ty);
        },
        .bool_not_expr => {
            const zero = try c.builder.add_constant(.zero, try c.gen_type(ty));
            const operand = try c.gen_expr(data.un);
            return c.add_bin(.cmp_ne, zero, operand, ty);
        },
        .pre_inc_expr => {
            const operand = try c.gen_lval(data.un);
            const val = try c.add_un(.load, operand, ty);
            const one = try c.builder.add_constant(.one, try c.gen_type(ty));
            const plus_one = try c.add_bin(.add, val, one, ty);
            try c.builder.add_store(operand, plus_one);
            return plus_one;
        },
        .pre_dec_expr => {
            const operand = try c.gen_lval(data.un);
            const val = try c.add_un(.load, operand, ty);
            const one = try c.builder.add_constant(.one, try c.gen_type(ty));
            const plus_one = try c.add_bin(.sub, val, one, ty);
            try c.builder.add_store(operand, plus_one);
            return plus_one;
        },
        .post_inc_expr => {
            const operand = try c.gen_lval(data.un);
            const val = try c.add_un(.load, operand, ty);
            const one = try c.builder.add_constant(.one, try c.gen_type(ty));
            const plus_one = try c.add_bin(.add, val, one, ty);
            try c.builder.add_store(operand, plus_one);
            return val;
        },
        .post_dec_expr => {
            const operand = try c.gen_lval(data.un);
            const val = try c.add_un(.load, operand, ty);
            const one = try c.builder.add_constant(.one, try c.gen_type(ty));
            const plus_one = try c.add_bin(.sub, val, one, ty);
            try c.builder.add_store(operand, plus_one);
            return val;
        },
        .paren_expr => return c.gen_expr(data.un),
        .decl_ref_expr => unreachable, // Lval expression.
        .explicit_cast, .implicit_cast => switch (data.cast.kind) {
            .no_op => return c.gen_expr(data.cast.operand),
            .to_void => {
                _ = try c.gen_expr(data.cast.operand);
                return .none;
            },
            .lval_to_rval => {
                const operand = try c.gen_lval(data.cast.operand);
                return c.add_un(.load, operand, ty);
            },
            .function_to_pointer, .array_to_pointer => {
                return c.gen_lval(data.cast.operand);
            },
            .int_cast => {
                const operand = try c.gen_expr(data.cast.operand);
                const src_ty = c.node_ty[@int_from_enum(data.cast.operand)];
                const src_bits = src_ty.bit_sizeof(c.comp).?;
                const dest_bits = ty.bit_sizeof(c.comp).?;
                if (src_bits == dest_bits) {
                    return operand;
                } else if (src_bits < dest_bits) {
                    if (src_ty.is_unsigned_int(c.comp))
                        return c.add_un(.zext, operand, ty)
                    else
                        return c.add_un(.sext, operand, ty);
                } else {
                    return c.add_un(.trunc, operand, ty);
                }
            },
            .bool_to_int => {
                const operand = try c.gen_expr(data.cast.operand);
                return c.add_un(.zext, operand, ty);
            },
            .pointer_to_bool, .int_to_bool, .float_to_bool => {
                const lhs = try c.gen_expr(data.cast.operand);
                const rhs = try c.builder.add_constant(.zero, try c.gen_type(c.node_ty[@int_from_enum(node)]));
                return c.builder.add_inst(.cmp_ne, .{ .bin = .{ .lhs = lhs, .rhs = rhs } }, .i1);
            },
            .bitcast,
            .pointer_to_int,
            .bool_to_float,
            .bool_to_pointer,
            .int_to_float,
            .complex_int_to_complex_float,
            .int_to_pointer,
            .float_to_int,
            .complex_float_to_complex_int,
            .complex_int_cast,
            .complex_int_to_real,
            .real_to_complex_int,
            .float_cast,
            .complex_float_cast,
            .complex_float_to_real,
            .real_to_complex_float,
            .null_to_pointer,
            .union_cast,
            .vector_splat,
            => return c.fail("TODO CodeGen gen CastKind {}\n", .{data.cast.kind}),
        },
        .binary_cond_expr => {
            if (c.tree.value_map.get(data.if3.cond)) |cond| {
                if (cond.to_bool(c.comp)) {
                    c.cond_dummy_ref = try c.gen_expr(data.if3.cond);
                    return c.gen_expr(c.tree.data[data.if3.body]); // then
                } else {
                    return c.gen_expr(c.tree.data[data.if3.body + 1]); // else
                }
            }

            const then_label = try c.builder.make_label("ternary.then");
            const else_label = try c.builder.make_label("ternary.else");
            const end_label = try c.builder.make_label("ternary.end");
            const cond_ty = c.node_ty[@int_from_enum(data.if3.cond)];
            {
                const old_cond_dummy_ty = c.cond_dummy_ty;
                defer c.cond_dummy_ty = old_cond_dummy_ty;
                c.cond_dummy_ty = try c.gen_type(cond_ty);

                try c.gen_bool_expr(data.if3.cond, then_label, else_label);
            }

            try c.builder.start_block(then_label);
            if (c.builder.instructions.items(.ty)[@int_from_enum(c.cond_dummy_ref)] == .i1) {
                c.cond_dummy_ref = try c.add_un(.zext, c.cond_dummy_ref, cond_ty);
            }
            const then_val = try c.gen_expr(c.tree.data[data.if3.body]); // then
            try c.builder.add_jump(end_label);
            const then_exit = c.builder.current_label;

            try c.builder.start_block(else_label);
            const else_val = try c.gen_expr(c.tree.data[data.if3.body + 1]); // else
            const else_exit = c.builder.current_label;

            try c.builder.start_block(end_label);

            var phi_buf: [2]Ir.Inst.Phi.Input = .{
                .{ .value = then_val, .label = then_exit },
                .{ .value = else_val, .label = else_exit },
            };
            return c.builder.add_phi(&phi_buf, try c.gen_type(ty));
        },
        .cond_dummy_expr => return c.cond_dummy_ref,
        .cond_expr => {
            if (c.tree.value_map.get(data.if3.cond)) |cond| {
                if (cond.to_bool(c.comp)) {
                    return c.gen_expr(c.tree.data[data.if3.body]); // then
                } else {
                    return c.gen_expr(c.tree.data[data.if3.body + 1]); // else
                }
            }

            const then_label = try c.builder.make_label("ternary.then");
            const else_label = try c.builder.make_label("ternary.else");
            const end_label = try c.builder.make_label("ternary.end");

            try c.gen_bool_expr(data.if3.cond, then_label, else_label);

            try c.builder.start_block(then_label);
            const then_val = try c.gen_expr(c.tree.data[data.if3.body]); // then
            try c.builder.add_jump(end_label);
            const then_exit = c.builder.current_label;

            try c.builder.start_block(else_label);
            const else_val = try c.gen_expr(c.tree.data[data.if3.body + 1]); // else
            const else_exit = c.builder.current_label;

            try c.builder.start_block(end_label);

            var phi_buf: [2]Ir.Inst.Phi.Input = .{
                .{ .value = then_val, .label = then_exit },
                .{ .value = else_val, .label = else_exit },
            };
            return c.builder.add_phi(&phi_buf, try c.gen_type(ty));
        },
        .call_expr_one => if (data.bin.rhs == .none) {
            return c.gen_call(data.bin.lhs, &.{}, ty);
        } else {
            return c.gen_call(data.bin.lhs, &.{data.bin.rhs}, ty);
        },
        .call_expr => {
            return c.gen_call(c.tree.data[data.range.start], c.tree.data[data.range.start + 1 .. data.range.end], ty);
        },
        .bool_or_expr => {
            if (c.tree.value_map.get(data.bin.lhs)) |lhs| {
                if (!lhs.to_bool(c.comp)) {
                    return c.builder.add_constant(.one, try c.gen_type(ty));
                }
                return c.gen_expr(data.bin.rhs);
            }

            const false_label = try c.builder.make_label("bool_false");
            const exit_label = try c.builder.make_label("bool_exit");

            const old_bool_end_label = c.bool_end_label;
            defer c.bool_end_label = old_bool_end_label;
            c.bool_end_label = exit_label;

            const phi_nodes_top = c.phi_nodes.items.len;
            defer c.phi_nodes.items.len = phi_nodes_top;

            try c.gen_bool_expr(data.bin.lhs, exit_label, false_label);

            try c.builder.start_block(false_label);
            try c.gen_bool_expr(data.bin.rhs, exit_label, exit_label);

            try c.builder.start_block(exit_label);

            const phi = try c.builder.add_phi(c.phi_nodes.items[phi_nodes_top..], .i1);
            return c.add_un(.zext, phi, ty);
        },
        .bool_and_expr => {
            if (c.tree.value_map.get(data.bin.lhs)) |lhs| {
                if (!lhs.to_bool(c.comp)) {
                    return c.builder.add_constant(.zero, try c.gen_type(ty));
                }
                return c.gen_expr(data.bin.rhs);
            }

            const true_label = try c.builder.make_label("bool_true");
            const exit_label = try c.builder.make_label("bool_exit");

            const old_bool_end_label = c.bool_end_label;
            defer c.bool_end_label = old_bool_end_label;
            c.bool_end_label = exit_label;

            const phi_nodes_top = c.phi_nodes.items.len;
            defer c.phi_nodes.items.len = phi_nodes_top;

            try c.gen_bool_expr(data.bin.lhs, true_label, exit_label);

            try c.builder.start_block(true_label);
            try c.gen_bool_expr(data.bin.rhs, exit_label, exit_label);

            try c.builder.start_block(exit_label);

            const phi = try c.builder.add_phi(c.phi_nodes.items[phi_nodes_top..], .i1);
            return c.add_un(.zext, phi, ty);
        },
        .builtin_choose_expr => {
            const cond = c.tree.value_map.get(data.if3.cond).?;
            if (cond.to_bool(c.comp)) {
                return c.gen_expr(c.tree.data[data.if3.body]);
            } else {
                return c.gen_expr(c.tree.data[data.if3.body + 1]);
            }
        },
        .generic_expr_one => {
            const index = @int_from_enum(data.bin.rhs);
            switch (c.node_tag[index]) {
                .generic_association_expr, .generic_default_expr => {
                    return c.gen_expr(c.node_data[index].un);
                },
                else => unreachable,
            }
        },
        .generic_expr => {
            const index = @int_from_enum(c.tree.data[data.range.start + 1]);
            switch (c.node_tag[index]) {
                .generic_association_expr, .generic_default_expr => {
                    return c.gen_expr(c.node_data[index].un);
                },
                else => unreachable,
            }
        },
        .generic_association_expr, .generic_default_expr => unreachable,
        .stmt_expr => switch (c.node_tag[@int_from_enum(data.un)]) {
            .compound_stmt_two => {
                const old_sym_len = c.symbols.items.len;
                c.symbols.items.len = old_sym_len;

                const stmt_data = c.node_data[@int_from_enum(data.un)];
                if (stmt_data.bin.rhs == .none) return c.gen_expr(stmt_data.bin.lhs);
                try c.gen_stmt(stmt_data.bin.lhs);
                return c.gen_expr(stmt_data.bin.rhs);
            },
            .compound_stmt => {
                const old_sym_len = c.symbols.items.len;
                c.symbols.items.len = old_sym_len;

                const stmt_data = c.node_data[@int_from_enum(data.un)];
                for (c.tree.data[stmt_data.range.start .. stmt_data.range.end - 1]) |stmt| try c.gen_stmt(stmt);
                return c.gen_expr(c.tree.data[stmt_data.range.end]);
            },
            else => unreachable,
        },
        .builtin_call_expr_one => {
            const name = c.tree.tok_slice(data.decl.name);
            const builtin = c.comp.builtins.lookup(name).builtin;
            if (data.decl.node == .none) {
                return c.gen_builtin_call(builtin, &.{}, ty);
            } else {
                return c.gen_builtin_call(builtin, &.{data.decl.node}, ty);
            }
        },
        .builtin_call_expr => {
            const name_node_idx = c.tree.data[data.range.start];
            const name = c.tree.tok_slice(@int_from_enum(name_node_idx));
            const builtin = c.comp.builtins.lookup(name).builtin;
            return c.gen_builtin_call(builtin, c.tree.data[data.range.start + 1 .. data.range.end], ty);
        },
        .addr_of_label,
        .imag_expr,
        .real_expr,
        .sizeof_expr,
        .special_builtin_call_one,
        => return c.fail("TODO CodeGen.gen_expr {}\n", .{c.node_tag[@int_from_enum(node)]}),
        else => unreachable, // Not an expression.
    }
    return .none;
}

fn gen_lval(c: *CodeGen, node: NodeIndex) Error!Ir.Ref {
    std.debug.assert(node != .none);
    assert(c.tree.is_lval(node));
    const data = c.node_data[@int_from_enum(node)];
    switch (c.node_tag[@int_from_enum(node)]) {
        .string_literal_expr => {
            const val = c.tree.value_map.get(node).?;
            return c.builder.add_constant(val.ref(), .ptr);
        },
        .paren_expr => return c.gen_lval(data.un),
        .decl_ref_expr => {
            const slice = c.tree.tok_slice(data.decl_ref);
            const name = try StrInt.intern(c.comp, slice);
            var i = c.symbols.items.len;
            while (i > 0) {
                i -= 1;
                if (c.symbols.items[i].name == name) {
                    return c.symbols.items[i].val;
                }
            }

            const duped_name = try c.builder.arena.allocator().dupe_z(u8, slice);
            const ref: Ir.Ref = @enumFromInt(c.builder.instructions.len);
            try c.builder.instructions.append(c.builder.gpa, .{ .tag = .symbol, .data = .{ .label = duped_name }, .ty = .ptr });
            return ref;
        },
        .deref_expr => return c.gen_expr(data.un),
        .compound_literal_expr => {
            const ty = c.node_ty[@int_from_enum(node)];
            const size: u32 = @int_cast(ty.sizeof(c.comp).?); // TODO add error in parser
            const @"align" = ty.alignof(c.comp);
            const alloc = try c.builder.add_alloc(size, @"align");
            try c.gen_initializer(alloc, ty, data.un);
            return alloc;
        },
        .builtin_choose_expr => {
            const cond = c.tree.value_map.get(data.if3.cond).?;
            if (cond.to_bool(c.comp)) {
                return c.gen_lval(c.tree.data[data.if3.body]);
            } else {
                return c.gen_lval(c.tree.data[data.if3.body + 1]);
            }
        },
        .member_access_expr,
        .member_access_ptr_expr,
        .array_access_expr,
        .static_compound_literal_expr,
        .thread_local_compound_literal_expr,
        .static_thread_local_compound_literal_expr,
        => return c.fail("TODO CodeGen.gen_lval {}\n", .{c.node_tag[@int_from_enum(node)]}),
        else => unreachable, // Not an lval expression.
    }
}

fn gen_bool_expr(c: *CodeGen, base: NodeIndex, true_label: Ir.Ref, false_label: Ir.Ref) Error!void {
    var node = base;
    while (true) switch (c.node_tag[@int_from_enum(node)]) {
        .paren_expr => {
            node = c.node_data[@int_from_enum(node)].un;
        },
        else => break,
    };

    const data = c.node_data[@int_from_enum(node)];
    switch (c.node_tag[@int_from_enum(node)]) {
        .bool_or_expr => {
            if (c.tree.value_map.get(data.bin.lhs)) |lhs| {
                if (lhs.to_bool(c.comp)) {
                    if (true_label == c.bool_end_label) {
                        return c.add_bool_phi(!c.bool_invert);
                    }
                    return c.builder.add_jump(true_label);
                }
                return c.gen_bool_expr(data.bin.rhs, true_label, false_label);
            }

            const new_false_label = try c.builder.make_label("bool_false");
            try c.gen_bool_expr(data.bin.lhs, true_label, new_false_label);
            try c.builder.start_block(new_false_label);

            if (c.cond_dummy_ty) |ty| c.cond_dummy_ref = try c.builder.add_constant(.one, ty);
            return c.gen_bool_expr(data.bin.rhs, true_label, false_label);
        },
        .bool_and_expr => {
            if (c.tree.value_map.get(data.bin.lhs)) |lhs| {
                if (!lhs.to_bool(c.comp)) {
                    if (false_label == c.bool_end_label) {
                        return c.add_bool_phi(c.bool_invert);
                    }
                    return c.builder.add_jump(false_label);
                }
                return c.gen_bool_expr(data.bin.rhs, true_label, false_label);
            }

            const new_true_label = try c.builder.make_label("bool_true");
            try c.gen_bool_expr(data.bin.lhs, new_true_label, false_label);
            try c.builder.start_block(new_true_label);

            if (c.cond_dummy_ty) |ty| c.cond_dummy_ref = try c.builder.add_constant(.one, ty);
            return c.gen_bool_expr(data.bin.rhs, true_label, false_label);
        },
        .bool_not_expr => {
            c.bool_invert = !c.bool_invert;
            defer c.bool_invert = !c.bool_invert;

            if (c.cond_dummy_ty) |ty| c.cond_dummy_ref = try c.builder.add_constant(.zero, ty);
            return c.gen_bool_expr(data.un, false_label, true_label);
        },
        .equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_eq);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .not_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_ne);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .less_than_expr => {
            const cmp = try c.gen_comparison(node, .cmp_lt);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .less_than_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_lte);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .greater_than_expr => {
            const cmp = try c.gen_comparison(node, .cmp_gt);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .greater_than_equal_expr => {
            const cmp = try c.gen_comparison(node, .cmp_gte);
            if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
            return c.add_branch(cmp, true_label, false_label);
        },
        .explicit_cast, .implicit_cast => switch (data.cast.kind) {
            .bool_to_int => {
                const operand = try c.gen_expr(data.cast.operand);
                if (c.cond_dummy_ty != null) c.cond_dummy_ref = operand;
                return c.add_branch(operand, true_label, false_label);
            },
            else => {},
        },
        .binary_cond_expr => {
            if (c.tree.value_map.get(data.if3.cond)) |cond| {
                if (cond.to_bool(c.comp)) {
                    return c.gen_bool_expr(c.tree.data[data.if3.body], true_label, false_label); // then
                } else {
                    return c.gen_bool_expr(c.tree.data[data.if3.body + 1], true_label, false_label); // else
                }
            }

            const new_false_label = try c.builder.make_label("ternary.else");
            try c.gen_bool_expr(data.if3.cond, true_label, new_false_label);

            try c.builder.start_block(new_false_label);
            if (c.cond_dummy_ty) |ty| c.cond_dummy_ref = try c.builder.add_constant(.one, ty);
            return c.gen_bool_expr(c.tree.data[data.if3.body + 1], true_label, false_label); // else
        },
        .cond_expr => {
            if (c.tree.value_map.get(data.if3.cond)) |cond| {
                if (cond.to_bool(c.comp)) {
                    return c.gen_bool_expr(c.tree.data[data.if3.body], true_label, false_label); // then
                } else {
                    return c.gen_bool_expr(c.tree.data[data.if3.body + 1], true_label, false_label); // else
                }
            }

            const new_true_label = try c.builder.make_label("ternary.then");
            const new_false_label = try c.builder.make_label("ternary.else");
            try c.gen_bool_expr(data.if3.cond, new_true_label, new_false_label);

            try c.builder.start_block(new_true_label);
            try c.gen_bool_expr(c.tree.data[data.if3.body], true_label, false_label); // then
            try c.builder.start_block(new_false_label);
            if (c.cond_dummy_ty) |ty| c.cond_dummy_ref = try c.builder.add_constant(.one, ty);
            return c.gen_bool_expr(c.tree.data[data.if3.body + 1], true_label, false_label); // else
        },
        else => {},
    }

    if (c.tree.value_map.get(node)) |value| {
        if (value.to_bool(c.comp)) {
            if (true_label == c.bool_end_label) {
                return c.add_bool_phi(!c.bool_invert);
            }
            return c.builder.add_jump(true_label);
        } else {
            if (false_label == c.bool_end_label) {
                return c.add_bool_phi(c.bool_invert);
            }
            return c.builder.add_jump(false_label);
        }
    }

    // Assume int operand.
    const lhs = try c.gen_expr(node);
    const rhs = try c.builder.add_constant(.zero, try c.gen_type(c.node_ty[@int_from_enum(node)]));
    const cmp = try c.builder.add_inst(.cmp_ne, .{ .bin = .{ .lhs = lhs, .rhs = rhs } }, .i1);
    if (c.cond_dummy_ty != null) c.cond_dummy_ref = cmp;
    try c.add_branch(cmp, true_label, false_label);
}

fn gen_builtin_call(c: *CodeGen, builtin: Builtin, arg_nodes: []const NodeIndex, ty: Type) Error!Ir.Ref {
    _ = arg_nodes;
    _ = ty;
    return c.fail("TODO CodeGen.gen_builtin_call {s}\n", .{Builtin.name_from_tag(builtin.tag).span()});
}

fn gen_call(c: *CodeGen, fn_node: NodeIndex, arg_nodes: []const NodeIndex, ty: Type) Error!Ir.Ref {
    // Detect direct calls.
    const fn_ref = blk: {
        const data = c.node_data[@int_from_enum(fn_node)];
        if (c.node_tag[@int_from_enum(fn_node)] != .implicit_cast or data.cast.kind != .function_to_pointer) {
            break :blk try c.gen_expr(fn_node);
        }

        var cur = @int_from_enum(data.cast.operand);
        while (true) switch (c.node_tag[cur]) {
            .paren_expr, .addr_of_expr, .deref_expr => {
                cur = @int_from_enum(c.node_data[cur].un);
            },
            .implicit_cast => {
                const cast = c.node_data[cur].cast;
                if (cast.kind != .function_to_pointer) {
                    break :blk try c.gen_expr(fn_node);
                }
                cur = @int_from_enum(cast.operand);
            },
            .decl_ref_expr => {
                const slice = c.tree.tok_slice(c.node_data[cur].decl_ref);
                const name = try StrInt.intern(c.comp, slice);
                var i = c.symbols.items.len;
                while (i > 0) {
                    i -= 1;
                    if (c.symbols.items[i].name == name) {
                        break :blk try c.gen_expr(fn_node);
                    }
                }

                const duped_name = try c.builder.arena.allocator().dupe_z(u8, slice);
                const ref: Ir.Ref = @enumFromInt(c.builder.instructions.len);
                try c.builder.instructions.append(c.builder.gpa, .{ .tag = .symbol, .data = .{ .label = duped_name }, .ty = .ptr });
                break :blk ref;
            },
            else => break :blk try c.gen_expr(fn_node),
        };
    };

    const args = try c.builder.arena.allocator().alloc(Ir.Ref, arg_nodes.len);
    for (arg_nodes, args) |node, *arg| {
        // TODO handle calling convention here
        arg.* = try c.gen_expr(node);
    }
    // TODO handle variadic call
    const call = try c.builder.arena.allocator().create(Ir.Inst.Call);
    call.* = .{
        .func = fn_ref,
        .args_len = @int_cast(args.len),
        .args_ptr = args.ptr,
    };
    return c.builder.add_inst(.call, .{ .call = call }, try c.gen_type(ty));
}

fn gen_compound_assign(c: *CodeGen, node: NodeIndex, tag: Ir.Inst.Tag) Error!Ir.Ref {
    const bin = c.node_data[@int_from_enum(node)].bin;
    const ty = c.node_ty[@int_from_enum(node)];
    const rhs = try c.gen_expr(bin.rhs);
    const lhs = try c.gen_lval(bin.lhs);
    const res = try c.add_bin(tag, lhs, rhs, ty);
    try c.builder.add_store(lhs, res);
    return res;
}

fn gen_bin_op(c: *CodeGen, node: NodeIndex, tag: Ir.Inst.Tag) Error!Ir.Ref {
    const bin = c.node_data[@int_from_enum(node)].bin;
    const ty = c.node_ty[@int_from_enum(node)];
    const lhs = try c.gen_expr(bin.lhs);
    const rhs = try c.gen_expr(bin.rhs);
    return c.add_bin(tag, lhs, rhs, ty);
}

fn gen_comparison(c: *CodeGen, node: NodeIndex, tag: Ir.Inst.Tag) Error!Ir.Ref {
    const bin = c.node_data[@int_from_enum(node)].bin;
    const lhs = try c.gen_expr(bin.lhs);
    const rhs = try c.gen_expr(bin.rhs);

    return c.builder.add_inst(tag, .{ .bin = .{ .lhs = lhs, .rhs = rhs } }, .i1);
}

fn gen_ptr_arithmetic(c: *CodeGen, ptr: Ir.Ref, offset: Ir.Ref, offset_ty: Type, ty: Type) Error!Ir.Ref {
    // TODO consider adding a getelemptr instruction
    const size = ty.elem_type().sizeof(c.comp).?;
    if (size == 1) {
        return c.builder.add_inst(.add, .{ .bin = .{ .lhs = ptr, .rhs = offset } }, try c.gen_type(ty));
    }

    const size_inst = try c.builder.add_constant((try Value.int(size, c.comp)).ref(), try c.gen_type(offset_ty));
    const offset_inst = try c.add_bin(.mul, offset, size_inst, offset_ty);
    return c.add_bin(.add, ptr, offset_inst, offset_ty);
}

fn gen_initializer(c: *CodeGen, ptr: Ir.Ref, dest_ty: Type, initializer: NodeIndex) Error!void {
    std.debug.assert(initializer != .none);
    switch (c.node_tag[@int_from_enum(initializer)]) {
        .array_init_expr_two,
        .array_init_expr,
        .struct_init_expr_two,
        .struct_init_expr,
        .union_init_expr,
        .array_filler_expr,
        .default_init_expr,
        => return c.fail("TODO CodeGen.gen_initializer {}\n", .{c.node_tag[@int_from_enum(initializer)]}),
        .string_literal_expr => {
            const val = c.tree.value_map.get(initializer).?;
            const str_ptr = try c.builder.add_constant(val.ref(), .ptr);
            if (dest_ty.is_array()) {
                return c.fail("TODO memcpy\n", .{});
            } else {
                try c.builder.add_store(ptr, str_ptr);
            }
        },
        else => {
            const res = try c.gen_expr(initializer);
            try c.builder.add_store(ptr, res);
        },
    }
}

fn gen_var(c: *CodeGen, decl: NodeIndex) Error!void {
    _ = decl;
    return c.fail("TODO CodeGen.gen_var\n", .{});
}
