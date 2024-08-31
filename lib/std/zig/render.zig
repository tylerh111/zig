const std = @import("../std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const meta = std.meta;
const Ast = std.zig.Ast;
const Token = std.zig.Token;
const primitives = std.zig.primitives;

const indent_delta = 4;
const asm_indent_delta = 2;

pub const Error = Ast.RenderError;

const Ais = AutoIndentingStream(std.ArrayList(u8).Writer);

pub const Fixups = struct {
    /// The key is the mut token (`var`/`const`) of the variable declaration
    /// that should have a `_ = foo;` inserted afterwards.
    unused_var_decls: std.AutoHashMapUnmanaged(Ast.TokenIndex, void) = .{},
    /// The functions in this unordered set of AST fn decl nodes will render
    /// with a function body of `@trap()` instead, with all parameters
    /// discarded.
    gut_functions: std.AutoHashMapUnmanaged(Ast.Node.Index, void) = .{},
    /// These global declarations will be omitted.
    omit_nodes: std.AutoHashMapUnmanaged(Ast.Node.Index, void) = .{},
    /// These expressions will be replaced with the string value.
    replace_nodes_with_string: std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8) = .{},
    /// The string value will be inserted directly after the node.
    append_string_after_node: std.AutoHashMapUnmanaged(Ast.Node.Index, []const u8) = .{},
    /// These nodes will be replaced with a different node.
    replace_nodes_with_node: std.AutoHashMapUnmanaged(Ast.Node.Index, Ast.Node.Index) = .{},
    /// Change all identifier names matching the key to be value instead.
    rename_identifiers: std.StringArrayHashMapUnmanaged([]const u8) = .{},

    /// All `@import` builtin calls which refer to a file path will be prefixed
    /// with this path.
    rebase_imported_paths: ?[]const u8 = null,

    pub fn count(f: Fixups) usize {
        return f.unused_var_decls.count() +
            f.gut_functions.count() +
            f.omit_nodes.count() +
            f.replace_nodes_with_string.count() +
            f.append_string_after_node.count() +
            f.replace_nodes_with_node.count() +
            f.rename_identifiers.count() +
            @int_from_bool(f.rebase_imported_paths != null);
    }

    pub fn clear_retaining_capacity(f: *Fixups) void {
        f.unused_var_decls.clear_retaining_capacity();
        f.gut_functions.clear_retaining_capacity();
        f.omit_nodes.clear_retaining_capacity();
        f.replace_nodes_with_string.clear_retaining_capacity();
        f.append_string_after_node.clear_retaining_capacity();
        f.replace_nodes_with_node.clear_retaining_capacity();
        f.rename_identifiers.clear_retaining_capacity();

        f.rebase_imported_paths = null;
    }

    pub fn deinit(f: *Fixups, gpa: Allocator) void {
        f.unused_var_decls.deinit(gpa);
        f.gut_functions.deinit(gpa);
        f.omit_nodes.deinit(gpa);
        f.replace_nodes_with_string.deinit(gpa);
        f.append_string_after_node.deinit(gpa);
        f.replace_nodes_with_node.deinit(gpa);
        f.rename_identifiers.deinit(gpa);
        f.* = undefined;
    }
};

const Render = struct {
    gpa: Allocator,
    ais: *Ais,
    tree: Ast,
    fixups: Fixups,
};

pub fn render_tree(buffer: *std.ArrayList(u8), tree: Ast, fixups: Fixups) Error!void {
    assert(tree.errors.len == 0); // Cannot render an invalid tree.
    var auto_indenting_stream = Ais{
        .indent_delta = indent_delta,
        .underlying_writer = buffer.writer(),
    };
    var r: Render = .{
        .gpa = buffer.allocator,
        .ais = &auto_indenting_stream,
        .tree = tree,
        .fixups = fixups,
    };

    // Render all the line comments at the beginning of the file.
    const comment_end_loc = tree.tokens.items(.start)[0];
    _ = try render_comments(&r, 0, comment_end_loc);

    if (tree.tokens.items(.tag)[0] == .container_doc_comment) {
        try render_container_doc_comments(&r, 0);
    }

    if (tree.mode == .zon) {
        try render_expression(
            &r,
            tree.nodes.items(.data)[0].lhs,
            .newline,
        );
    } else {
        try render_members(&r, tree.root_decls());
    }

    if (auto_indenting_stream.disabled_offset) |disabled_offset| {
        try write_fixing_whitespace(auto_indenting_stream.underlying_writer, tree.source[disabled_offset..]);
    }
}

/// Render all members in the given slice, keeping empty lines where appropriate
fn render_members(r: *Render, members: []const Ast.Node.Index) Error!void {
    const tree = r.tree;
    if (members.len == 0) return;
    const container: Container = for (members) |member| {
        if (tree.full_container_field(member)) |field| if (!field.ast.tuple_like) break .other;
    } else .tuple;
    try render_member(r, container, members[0], .newline);
    for (members[1..]) |member| {
        try render_extra_newline(r, member);
        try render_member(r, container, member, .newline);
    }
}

const Container = enum {
    @"enum",
    tuple,
    other,
};

fn render_member(
    r: *Render,
    container: Container,
    decl: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);
    if (r.fixups.omit_nodes.contains(decl)) return;
    try render_doc_comments(r, tree.first_token(decl));
    switch (tree.nodes.items(.tag)[decl]) {
        .fn_decl => {
            // Some examples:
            // pub extern "foo" fn ...
            // export fn ...
            const fn_proto = datas[decl].lhs;
            const fn_token = main_tokens[fn_proto];
            // Go back to the first token we should render here.
            var i = fn_token;
            while (i > 0) {
                i -= 1;
                switch (token_tags[i]) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_pub,
                    .string_literal,
                    .keyword_inline,
                    .keyword_noinline,
                    => continue,

                    else => {
                        i += 1;
                        break;
                    },
                }
            }
            while (i < fn_token) : (i += 1) {
                try render_token(r, i, .space);
            }
            switch (tree.nodes.items(.tag)[fn_proto]) {
                .fn_proto_one, .fn_proto => {
                    const callconv_expr = if (tree.nodes.items(.tag)[fn_proto] == .fn_proto_one)
                        tree.extra_data(datas[fn_proto].lhs, Ast.Node.FnProtoOne).callconv_expr
                    else
                        tree.extra_data(datas[fn_proto].lhs, Ast.Node.FnProto).callconv_expr;
                    if (callconv_expr != 0 and tree.nodes.items(.tag)[callconv_expr] == .enum_literal) {
                        if (mem.eql(u8, "Inline", tree.token_slice(main_tokens[callconv_expr]))) {
                            try ais.writer().write_all("inline ");
                        }
                    }
                },
                .fn_proto_simple, .fn_proto_multi => {},
                else => unreachable,
            }
            assert(datas[decl].rhs != 0);
            try render_expression(r, fn_proto, .space);
            const body_node = datas[decl].rhs;
            if (r.fixups.gut_functions.contains(decl)) {
                ais.push_indent();
                const lbrace = tree.nodes.items(.main_token)[body_node];
                try render_token(r, lbrace, .newline);
                try discard_all_params(r, fn_proto);
                try ais.writer().write_all("@trap();");
                ais.pop_indent();
                try ais.insert_newline();
                try render_token(r, tree.last_token(body_node), space); // rbrace
            } else if (r.fixups.unused_var_decls.count() != 0) {
                ais.push_indent_next_line();
                const lbrace = tree.nodes.items(.main_token)[body_node];
                try render_token(r, lbrace, .newline);

                var fn_proto_buf: [1]Ast.Node.Index = undefined;
                const full_fn_proto = tree.full_fn_proto(&fn_proto_buf, fn_proto).?;
                var it = full_fn_proto.iterate(&tree);
                while (it.next()) |param| {
                    const name_ident = param.name_token.?;
                    assert(token_tags[name_ident] == .identifier);
                    if (r.fixups.unused_var_decls.contains(name_ident)) {
                        const w = ais.writer();
                        try w.write_all("_ = ");
                        try w.write_all(token_slice_for_render(r.tree, name_ident));
                        try w.write_all(";\n");
                    }
                }
                var statements_buf: [2]Ast.Node.Index = undefined;
                const statements = switch (node_tags[body_node]) {
                    .block_two,
                    .block_two_semicolon,
                    => b: {
                        statements_buf = .{ datas[body_node].lhs, datas[body_node].rhs };
                        if (datas[body_node].lhs == 0) {
                            break :b statements_buf[0..0];
                        } else if (datas[body_node].rhs == 0) {
                            break :b statements_buf[0..1];
                        } else {
                            break :b statements_buf[0..2];
                        }
                    },
                    .block,
                    .block_semicolon,
                    => tree.extra_data[datas[body_node].lhs..datas[body_node].rhs],

                    else => unreachable,
                };
                return finish_render_block(r, body_node, statements, space);
            } else {
                return render_expression(r, body_node, space);
            }
        },
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            // Extern function prototypes are parsed as these tags.
            // Go back to the first token we should render here.
            const fn_token = main_tokens[decl];
            var i = fn_token;
            while (i > 0) {
                i -= 1;
                switch (token_tags[i]) {
                    .keyword_extern,
                    .keyword_export,
                    .keyword_pub,
                    .string_literal,
                    .keyword_inline,
                    .keyword_noinline,
                    => continue,

                    else => {
                        i += 1;
                        break;
                    },
                }
            }
            while (i < fn_token) : (i += 1) {
                try render_token(r, i, .space);
            }
            try render_expression(r, decl, .none);
            return render_token(r, tree.last_token(decl) + 1, space); // semicolon
        },

        .@"usingnamespace" => {
            const main_token = main_tokens[decl];
            const expr = datas[decl].lhs;
            if (main_token > 0 and token_tags[main_token - 1] == .keyword_pub) {
                try render_token(r, main_token - 1, .space); // pub
            }
            try render_token(r, main_token, .space); // usingnamespace
            try render_expression(r, expr, .none);
            return render_token(r, tree.last_token(expr) + 1, space); // ;
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => return render_var_decl(r, tree.full_var_decl(decl).?, false, .semicolon),

        .test_decl => {
            const test_token = main_tokens[decl];
            try render_token(r, test_token, .space);
            const test_name_tag = token_tags[test_token + 1];
            switch (test_name_tag) {
                .string_literal => try render_token(r, test_token + 1, .space),
                .identifier => try render_identifier(r, test_token + 1, .space, .preserve_when_shadowing),
                else => {},
            }
            try render_expression(r, datas[decl].rhs, space);
        },

        .container_field_init,
        .container_field_align,
        .container_field,
        => return render_container_field(r, container, tree.full_container_field(decl).?, space),

        .@"comptime" => return render_expression(r, decl, space),

        .root => unreachable,
        else => unreachable,
    }
}

/// Render all expressions in the slice, keeping empty lines where appropriate
fn render_expressions(r: *Render, expressions: []const Ast.Node.Index, space: Space) Error!void {
    if (expressions.len == 0) return;
    try render_expression(r, expressions[0], space);
    for (expressions[1..]) |expression| {
        try render_extra_newline(r, expression);
        try render_expression(r, expression, space);
    }
}

fn render_expression(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    if (r.fixups.replace_nodes_with_string.get(node)) |replacement| {
        try ais.writer().write_all(replacement);
        try render_only_space(r, space);
        return;
    } else if (r.fixups.replace_nodes_with_node.get(node)) |replacement| {
        return render_expression(r, replacement, space);
    }
    switch (node_tags[node]) {
        .identifier => {
            const token_index = main_tokens[node];
            return render_identifier(r, token_index, space, .preserve_when_shadowing);
        },

        .number_literal,
        .char_literal,
        .unreachable_literal,
        .anyframe_literal,
        .string_literal,
        => return render_token(r, main_tokens[node], space),

        .multiline_string_literal => {
            var locked_indents = ais.lock_one_shot_indent();
            try ais.maybe_insert_newline();

            var i = datas[node].lhs;
            while (i <= datas[node].rhs) : (i += 1) try render_token(r, i, .newline);

            while (locked_indents > 0) : (locked_indents -= 1) ais.pop_indent();

            switch (space) {
                .none, .space, .newline, .skip => {},
                .semicolon => if (token_tags[i] == .semicolon) try render_token(r, i, .newline),
                .comma => if (token_tags[i] == .comma) try render_token(r, i, .newline),
                .comma_space => if (token_tags[i] == .comma) try render_token(r, i, .space),
            }
        },

        .error_value => {
            try render_token(r, main_tokens[node], .none);
            try render_token(r, main_tokens[node] + 1, .none);
            return render_identifier(r, main_tokens[node] + 2, space, .eagerly_unquote);
        },

        .block_two,
        .block_two_semicolon,
        => {
            const statements = [2]Ast.Node.Index{ datas[node].lhs, datas[node].rhs };
            if (datas[node].lhs == 0) {
                return render_block(r, node, statements[0..0], space);
            } else if (datas[node].rhs == 0) {
                return render_block(r, node, statements[0..1], space);
            } else {
                return render_block(r, node, statements[0..2], space);
            }
        },
        .block,
        .block_semicolon,
        => {
            const statements = tree.extra_data[datas[node].lhs..datas[node].rhs];
            return render_block(r, node, statements, space);
        },

        .@"errdefer" => {
            const defer_token = main_tokens[node];
            const payload_token = datas[node].lhs;
            const expr = datas[node].rhs;

            try render_token(r, defer_token, .space);
            if (payload_token != 0) {
                try render_token(r, payload_token - 1, .none); // |
                try render_identifier(r, payload_token, .none, .preserve_when_shadowing); // identifier
                try render_token(r, payload_token + 1, .space); // |
            }
            return render_expression(r, expr, space);
        },

        .@"defer" => {
            const defer_token = main_tokens[node];
            const expr = datas[node].rhs;
            try render_token(r, defer_token, .space);
            return render_expression(r, expr, space);
        },
        .@"comptime", .@"nosuspend" => {
            const comptime_token = main_tokens[node];
            const block = datas[node].lhs;
            try render_token(r, comptime_token, .space);
            return render_expression(r, block, space);
        },

        .@"suspend" => {
            const suspend_token = main_tokens[node];
            const body = datas[node].lhs;
            try render_token(r, suspend_token, .space);
            return render_expression(r, body, space);
        },

        .@"catch" => {
            const main_token = main_tokens[node];
            const fallback_first = tree.first_token(datas[node].rhs);

            const same_line = tree.tokens_on_same_line(main_token, fallback_first);
            const after_op_space = if (same_line) Space.space else Space.newline;

            try render_expression(r, datas[node].lhs, .space); // target

            if (token_tags[fallback_first - 1] == .pipe) {
                try render_token(r, main_token, .space); // catch keyword
                try render_token(r, main_token + 1, .none); // pipe
                try render_identifier(r, main_token + 2, .none, .preserve_when_shadowing); // payload identifier
                try render_token(r, main_token + 3, after_op_space); // pipe
            } else {
                assert(token_tags[fallback_first - 1] == .keyword_catch);
                try render_token(r, main_token, after_op_space); // catch keyword
            }

            ais.push_indent_one_shot();
            try render_expression(r, datas[node].rhs, space); // fallback
        },

        .field_access => {
            const main_token = main_tokens[node];
            const field_access = datas[node];

            try render_expression(r, field_access.lhs, .none);

            // Allow a line break between the lhs and the dot if the lhs and rhs
            // are on different lines.
            const lhs_last_token = tree.last_token(field_access.lhs);
            const same_line = tree.tokens_on_same_line(lhs_last_token, main_token + 1);
            if (!same_line) {
                if (!has_comment(tree, lhs_last_token, main_token)) try ais.insert_newline();
                ais.push_indent_one_shot();
            }

            try render_token(r, main_token, .none); // .

            // This check ensures that zag() is indented in the following example:
            // const x = foo
            //     .bar()
            //     . // comment
            //     zag();
            if (!same_line and has_comment(tree, main_token, main_token + 1)) {
                ais.push_indent_one_shot();
            }

            return render_identifier(r, field_access.rhs, space, .eagerly_unquote); // field
        },

        .error_union,
        .switch_range,
        => {
            const infix = datas[node];
            try render_expression(r, infix.lhs, .none);
            try render_token(r, main_tokens[node], .none);
            return render_expression(r, infix.rhs, space);
        },
        .for_range => {
            const infix = datas[node];
            try render_expression(r, infix.lhs, .none);
            if (infix.rhs != 0) {
                try render_token(r, main_tokens[node], .none);
                return render_expression(r, infix.rhs, space);
            } else {
                return render_token(r, main_tokens[node], space);
            }
        },

        .add,
        .add_wrap,
        .add_sat,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        .bang_equal,
        .bit_and,
        .bit_or,
        .shl,
        .shl_sat,
        .shr,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .mul_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .@"orelse",
        => {
            const infix = datas[node];
            try render_expression(r, infix.lhs, .space);
            const op_token = main_tokens[node];
            if (tree.tokens_on_same_line(op_token, op_token + 1)) {
                try render_token(r, op_token, .space);
            } else {
                ais.push_indent();
                try render_token(r, op_token, .newline);
                ais.pop_indent();
            }
            ais.push_indent_one_shot();
            return render_expression(r, infix.rhs, space);
        },

        .assign_destructure => {
            const full = tree.assign_destructure(node);
            if (full.comptime_token) |comptime_token| {
                try render_token(r, comptime_token, .space);
            }

            for (full.ast.variables, 0..) |variable_node, i| {
                const variable_space: Space = if (i == full.ast.variables.len - 1) .space else .comma_space;
                switch (node_tags[variable_node]) {
                    .global_var_decl,
                    .local_var_decl,
                    .simple_var_decl,
                    .aligned_var_decl,
                    => {
                        try render_var_decl(r, tree.full_var_decl(variable_node).?, true, variable_space);
                    },
                    else => try render_expression(r, variable_node, variable_space),
                }
            }
            if (tree.tokens_on_same_line(full.ast.equal_token, full.ast.equal_token + 1)) {
                try render_token(r, full.ast.equal_token, .space);
            } else {
                ais.push_indent();
                try render_token(r, full.ast.equal_token, .newline);
                ais.pop_indent();
            }
            ais.push_indent_one_shot();
            return render_expression(r, full.ast.value_expr, space);
        },

        .bit_not,
        .bool_not,
        .negation,
        .negation_wrap,
        .optional_type,
        .address_of,
        => {
            try render_token(r, main_tokens[node], .none);
            return render_expression(r, datas[node].lhs, space);
        },

        .@"try",
        .@"resume",
        .@"await",
        => {
            try render_token(r, main_tokens[node], .space);
            return render_expression(r, datas[node].lhs, space);
        },

        .array_type,
        .array_type_sentinel,
        => return render_array_type(r, tree.full_array_type(node).?, space),

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => return render_ptr_type(r, tree.full_ptr_type(node).?, space),

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var elements: [2]Ast.Node.Index = undefined;
            return render_array_init(r, tree.full_array_init(&elements, node).?, space);
        },

        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return render_struct_init(r, node, tree.full_struct_init(&buf, node).?, space);
        },

        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return render_call(r, tree.full_call(&buf, node).?, space);
        },

        .array_access => {
            const suffix = datas[node];
            const lbracket = tree.first_token(suffix.rhs) - 1;
            const rbracket = tree.last_token(suffix.rhs) + 1;
            const one_line = tree.tokens_on_same_line(lbracket, rbracket);
            const inner_space = if (one_line) Space.none else Space.newline;
            try render_expression(r, suffix.lhs, .none);
            ais.push_indent_next_line();
            try render_token(r, lbracket, inner_space); // [
            try render_expression(r, suffix.rhs, inner_space);
            ais.pop_indent();
            return render_token(r, rbracket, space); // ]
        },

        .slice_open, .slice, .slice_sentinel => return render_slice(r, node, tree.full_slice(node).?, space),

        .deref => {
            try render_expression(r, datas[node].lhs, .none);
            return render_token(r, main_tokens[node], space);
        },

        .unwrap_optional => {
            try render_expression(r, datas[node].lhs, .none);
            try render_token(r, main_tokens[node], .none);
            return render_token(r, datas[node].rhs, space);
        },

        .@"break" => {
            const main_token = main_tokens[node];
            const label_token = datas[node].lhs;
            const target = datas[node].rhs;
            if (label_token == 0 and target == 0) {
                try render_token(r, main_token, space); // break keyword
            } else if (label_token == 0 and target != 0) {
                try render_token(r, main_token, .space); // break keyword
                try render_expression(r, target, space);
            } else if (label_token != 0 and target == 0) {
                try render_token(r, main_token, .space); // break keyword
                try render_token(r, label_token - 1, .none); // colon
                try render_identifier(r, label_token, space, .eagerly_unquote); // identifier
            } else if (label_token != 0 and target != 0) {
                try render_token(r, main_token, .space); // break keyword
                try render_token(r, label_token - 1, .none); // colon
                try render_identifier(r, label_token, .space, .eagerly_unquote); // identifier
                try render_expression(r, target, space);
            }
        },

        .@"continue" => {
            const main_token = main_tokens[node];
            const label = datas[node].lhs;
            if (label != 0) {
                try render_token(r, main_token, .space); // continue
                try render_token(r, label - 1, .none); // :
                return render_identifier(r, label, space, .eagerly_unquote); // label
            } else {
                return render_token(r, main_token, space); // continue
            }
        },

        .@"return" => {
            if (datas[node].lhs != 0) {
                try render_token(r, main_tokens[node], .space);
                try render_expression(r, datas[node].lhs, space);
            } else {
                try render_token(r, main_tokens[node], space);
            }
        },

        .grouped_expression => {
            try render_token(r, main_tokens[node], .none); // lparen
            ais.push_indent_one_shot();
            try render_expression(r, datas[node].lhs, .none);
            return render_token(r, datas[node].rhs, space); // rparen
        },

        .container_decl,
        .container_decl_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return render_container_decl(r, node, tree.full_container_decl(&buf, node).?, space);
        },

        .error_set_decl => {
            const error_token = main_tokens[node];
            const lbrace = error_token + 1;
            const rbrace = datas[node].rhs;

            try render_token(r, error_token, .none);

            if (lbrace + 1 == rbrace) {
                // There is nothing between the braces so render condensed: `error{}`
                try render_token(r, lbrace, .none);
                return render_token(r, rbrace, space);
            } else if (lbrace + 2 == rbrace and token_tags[lbrace + 1] == .identifier) {
                // There is exactly one member and no trailing comma or
                // comments, so render without surrounding spaces: `error{Foo}`
                try render_token(r, lbrace, .none);
                try render_identifier(r, lbrace + 1, .none, .eagerly_unquote); // identifier
                return render_token(r, rbrace, space);
            } else if (token_tags[rbrace - 1] == .comma) {
                // There is a trailing comma so render each member on a new line.
                ais.push_indent_next_line();
                try render_token(r, lbrace, .newline);
                var i = lbrace + 1;
                while (i < rbrace) : (i += 1) {
                    if (i > lbrace + 1) try render_extra_newline_token(r, i);
                    switch (token_tags[i]) {
                        .doc_comment => try render_token(r, i, .newline),
                        .identifier => try render_identifier(r, i, .comma, .eagerly_unquote),
                        .comma => {},
                        else => unreachable,
                    }
                }
                ais.pop_indent();
                return render_token(r, rbrace, space);
            } else {
                // There is no trailing comma so render everything on one line.
                try render_token(r, lbrace, .space);
                var i = lbrace + 1;
                while (i < rbrace) : (i += 1) {
                    switch (token_tags[i]) {
                        .doc_comment => unreachable, // TODO
                        .identifier => try render_identifier(r, i, .comma_space, .eagerly_unquote),
                        .comma => {},
                        else => unreachable,
                    }
                }
                return render_token(r, rbrace, space);
            }
        },

        .builtin_call_two, .builtin_call_two_comma => {
            if (datas[node].lhs == 0) {
                return render_builtin_call(r, main_tokens[node], &.{}, space);
            } else if (datas[node].rhs == 0) {
                return render_builtin_call(r, main_tokens[node], &.{datas[node].lhs}, space);
            } else {
                return render_builtin_call(r, main_tokens[node], &.{ datas[node].lhs, datas[node].rhs }, space);
            }
        },
        .builtin_call, .builtin_call_comma => {
            const params = tree.extra_data[datas[node].lhs..datas[node].rhs];
            return render_builtin_call(r, main_tokens[node], params, space);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return render_fn_proto(r, tree.full_fn_proto(&buf, node).?, space);
        },

        .anyframe_type => {
            const main_token = main_tokens[node];
            if (datas[node].rhs != 0) {
                try render_token(r, main_token, .none); // anyframe
                try render_token(r, main_token + 1, .none); // ->
                return render_expression(r, datas[node].rhs, space);
            } else {
                return render_token(r, main_token, space); // anyframe
            }
        },

        .@"switch",
        .switch_comma,
        => {
            const switch_token = main_tokens[node];
            const condition = datas[node].lhs;
            const extra = tree.extra_data(datas[node].rhs, Ast.Node.SubRange);
            const cases = tree.extra_data[extra.start..extra.end];
            const rparen = tree.last_token(condition) + 1;

            try render_token(r, switch_token, .space); // switch keyword
            try render_token(r, switch_token + 1, .none); // lparen
            try render_expression(r, condition, .none); // condition expression
            try render_token(r, rparen, .space); // rparen

            ais.push_indent_next_line();
            if (cases.len == 0) {
                try render_token(r, rparen + 1, .none); // lbrace
            } else {
                try render_token(r, rparen + 1, .newline); // lbrace
                try render_expressions(r, cases, .comma);
            }
            ais.pop_indent();
            return render_token(r, tree.last_token(node), space); // rbrace
        },

        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => return render_switch_case(r, tree.full_switch_case(node).?, space),

        .while_simple,
        .while_cont,
        .@"while",
        => return render_while(r, tree.full_while(node).?, space),

        .for_simple,
        .@"for",
        => return render_for(r, tree.full_for(node).?, space),

        .if_simple,
        .@"if",
        => return render_if(r, tree.full_if(node).?, space),

        .asm_simple,
        .@"asm",
        => return render_asm(r, tree.full_asm(node).?, space),

        .enum_literal => {
            try render_token(r, main_tokens[node] - 1, .none); // .
            return render_identifier(r, main_tokens[node], space, .eagerly_unquote); // name
        },

        .fn_decl => unreachable,
        .container_field => unreachable,
        .container_field_init => unreachable,
        .container_field_align => unreachable,
        .root => unreachable,
        .global_var_decl => unreachable,
        .local_var_decl => unreachable,
        .simple_var_decl => unreachable,
        .aligned_var_decl => unreachable,
        .@"usingnamespace" => unreachable,
        .test_decl => unreachable,
        .asm_output => unreachable,
        .asm_input => unreachable,
    }
}

/// Same as `render_expression`, but afterwards looks for any
/// append_string_after_node fixups to apply
fn render_expression_fixup(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const ais = r.ais;
    try render_expression(r, node, space);
    if (r.fixups.append_string_after_node.get(node)) |bytes| {
        try ais.writer().write_all(bytes);
    }
}

fn render_array_type(
    r: *Render,
    array_type: Ast.full.ArrayType,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const rbracket = tree.first_token(array_type.ast.elem_type) - 1;
    const one_line = tree.tokens_on_same_line(array_type.ast.lbracket, rbracket);
    const inner_space = if (one_line) Space.none else Space.newline;
    ais.push_indent_next_line();
    try render_token(r, array_type.ast.lbracket, inner_space); // lbracket
    try render_expression(r, array_type.ast.elem_count, inner_space);
    if (array_type.ast.sentinel != 0) {
        try render_token(r, tree.first_token(array_type.ast.sentinel) - 1, inner_space); // colon
        try render_expression(r, array_type.ast.sentinel, inner_space);
    }
    ais.pop_indent();
    try render_token(r, rbracket, .none); // rbracket
    return render_expression(r, array_type.ast.elem_type, space);
}

fn render_ptr_type(r: *Render, ptr_type: Ast.full.PtrType, space: Space) Error!void {
    const tree = r.tree;
    switch (ptr_type.size) {
        .One => {
            // Since ** tokens exist and the same token is shared by two
            // nested pointer types, we check to see if we are the parent
            // in such a relationship. If so, skip rendering anything for
            // this pointer type and rely on the child to render our asterisk
            // as well when it renders the ** token.
            if (tree.tokens.items(.tag)[ptr_type.ast.main_token] == .asterisk_asterisk and
                ptr_type.ast.main_token == tree.nodes.items(.main_token)[ptr_type.ast.child_type])
            {
                return render_expression(r, ptr_type.ast.child_type, space);
            }
            try render_token(r, ptr_type.ast.main_token, .none); // asterisk
        },
        .Many => {
            if (ptr_type.ast.sentinel == 0) {
                try render_token(r, ptr_type.ast.main_token - 1, .none); // lbracket
                try render_token(r, ptr_type.ast.main_token, .none); // asterisk
                try render_token(r, ptr_type.ast.main_token + 1, .none); // rbracket
            } else {
                try render_token(r, ptr_type.ast.main_token - 1, .none); // lbracket
                try render_token(r, ptr_type.ast.main_token, .none); // asterisk
                try render_token(r, ptr_type.ast.main_token + 1, .none); // colon
                try render_expression(r, ptr_type.ast.sentinel, .none);
                try render_token(r, tree.last_token(ptr_type.ast.sentinel) + 1, .none); // rbracket
            }
        },
        .C => {
            try render_token(r, ptr_type.ast.main_token - 1, .none); // lbracket
            try render_token(r, ptr_type.ast.main_token, .none); // asterisk
            try render_token(r, ptr_type.ast.main_token + 1, .none); // c
            try render_token(r, ptr_type.ast.main_token + 2, .none); // rbracket
        },
        .Slice => {
            if (ptr_type.ast.sentinel == 0) {
                try render_token(r, ptr_type.ast.main_token, .none); // lbracket
                try render_token(r, ptr_type.ast.main_token + 1, .none); // rbracket
            } else {
                try render_token(r, ptr_type.ast.main_token, .none); // lbracket
                try render_token(r, ptr_type.ast.main_token + 1, .none); // colon
                try render_expression(r, ptr_type.ast.sentinel, .none);
                try render_token(r, tree.last_token(ptr_type.ast.sentinel) + 1, .none); // rbracket
            }
        },
    }

    if (ptr_type.allowzero_token) |allowzero_token| {
        try render_token(r, allowzero_token, .space);
    }

    if (ptr_type.ast.align_node != 0) {
        const align_first = tree.first_token(ptr_type.ast.align_node);
        try render_token(r, align_first - 2, .none); // align
        try render_token(r, align_first - 1, .none); // lparen
        try render_expression(r, ptr_type.ast.align_node, .none);
        if (ptr_type.ast.bit_range_start != 0) {
            assert(ptr_type.ast.bit_range_end != 0);
            try render_token(r, tree.first_token(ptr_type.ast.bit_range_start) - 1, .none); // colon
            try render_expression(r, ptr_type.ast.bit_range_start, .none);
            try render_token(r, tree.first_token(ptr_type.ast.bit_range_end) - 1, .none); // colon
            try render_expression(r, ptr_type.ast.bit_range_end, .none);
            try render_token(r, tree.last_token(ptr_type.ast.bit_range_end) + 1, .space); // rparen
        } else {
            try render_token(r, tree.last_token(ptr_type.ast.align_node) + 1, .space); // rparen
        }
    }

    if (ptr_type.ast.addrspace_node != 0) {
        const addrspace_first = tree.first_token(ptr_type.ast.addrspace_node);
        try render_token(r, addrspace_first - 2, .none); // addrspace
        try render_token(r, addrspace_first - 1, .none); // lparen
        try render_expression(r, ptr_type.ast.addrspace_node, .none);
        try render_token(r, tree.last_token(ptr_type.ast.addrspace_node) + 1, .space); // rparen
    }

    if (ptr_type.const_token) |const_token| {
        try render_token(r, const_token, .space);
    }

    if (ptr_type.volatile_token) |volatile_token| {
        try render_token(r, volatile_token, .space);
    }

    try render_expression(r, ptr_type.ast.child_type, space);
}

fn render_slice(
    r: *Render,
    slice_node: Ast.Node.Index,
    slice: Ast.full.Slice,
    space: Space,
) Error!void {
    const tree = r.tree;
    const node_tags = tree.nodes.items(.tag);
    const after_start_space_bool = node_causes_slice_op_space(node_tags[slice.ast.start]) or
        if (slice.ast.end != 0) node_causes_slice_op_space(node_tags[slice.ast.end]) else false;
    const after_start_space = if (after_start_space_bool) Space.space else Space.none;
    const after_dots_space = if (slice.ast.end != 0)
        after_start_space
    else if (slice.ast.sentinel != 0) Space.space else Space.none;

    try render_expression(r, slice.ast.sliced, .none);
    try render_token(r, slice.ast.lbracket, .none); // lbracket

    const start_last = tree.last_token(slice.ast.start);
    try render_expression(r, slice.ast.start, after_start_space);
    try render_token(r, start_last + 1, after_dots_space); // ellipsis2 ("..")

    if (slice.ast.end != 0) {
        const after_end_space = if (slice.ast.sentinel != 0) Space.space else Space.none;
        try render_expression(r, slice.ast.end, after_end_space);
    }

    if (slice.ast.sentinel != 0) {
        try render_token(r, tree.first_token(slice.ast.sentinel) - 1, .none); // colon
        try render_expression(r, slice.ast.sentinel, .none);
    }

    try render_token(r, tree.last_token(slice_node), space); // rbracket
}

fn render_asm_output(
    r: *Render,
    asm_output: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);
    assert(node_tags[asm_output] == .asm_output);
    const symbolic_name = main_tokens[asm_output];

    try render_token(r, symbolic_name - 1, .none); // lbracket
    try render_identifier(r, symbolic_name, .none, .eagerly_unquote); // ident
    try render_token(r, symbolic_name + 1, .space); // rbracket
    try render_token(r, symbolic_name + 2, .space); // "constraint"
    try render_token(r, symbolic_name + 3, .none); // lparen

    if (token_tags[symbolic_name + 4] == .arrow) {
        try render_token(r, symbolic_name + 4, .space); // ->
        try render_expression(r, datas[asm_output].lhs, Space.none);
        return render_token(r, datas[asm_output].rhs, space); // rparen
    } else {
        try render_identifier(r, symbolic_name + 4, .none, .eagerly_unquote); // ident
        return render_token(r, symbolic_name + 5, space); // rparen
    }
}

fn render_asm_input(
    r: *Render,
    asm_input: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const datas = tree.nodes.items(.data);
    assert(node_tags[asm_input] == .asm_input);
    const symbolic_name = main_tokens[asm_input];

    try render_token(r, symbolic_name - 1, .none); // lbracket
    try render_identifier(r, symbolic_name, .none, .eagerly_unquote); // ident
    try render_token(r, symbolic_name + 1, .space); // rbracket
    try render_token(r, symbolic_name + 2, .space); // "constraint"
    try render_token(r, symbolic_name + 3, .none); // lparen
    try render_expression(r, datas[asm_input].lhs, Space.none);
    return render_token(r, datas[asm_input].rhs, space); // rparen
}

fn render_var_decl(
    r: *Render,
    var_decl: Ast.full.VarDecl,
    /// Destructures intentionally ignore leading `comptime` tokens.
    ignore_comptime_token: bool,
    /// `comma_space` and `space` are used for destructure LHS decls.
    space: Space,
) Error!void {
    try render_var_decl_without_fixups(r, var_decl, ignore_comptime_token, space);
    if (r.fixups.unused_var_decls.contains(var_decl.ast.mut_token + 1)) {
        // Discard the variable like this: `_ = foo;`
        const w = r.ais.writer();
        try w.write_all("_ = ");
        try w.write_all(token_slice_for_render(r.tree, var_decl.ast.mut_token + 1));
        try w.write_all(";\n");
    }
}

fn render_var_decl_without_fixups(
    r: *Render,
    var_decl: Ast.full.VarDecl,
    /// Destructures intentionally ignore leading `comptime` tokens.
    ignore_comptime_token: bool,
    /// `comma_space` and `space` are used for destructure LHS decls.
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;

    if (var_decl.visib_token) |visib_token| {
        try render_token(r, visib_token, Space.space); // pub
    }

    if (var_decl.extern_export_token) |extern_export_token| {
        try render_token(r, extern_export_token, Space.space); // extern

        if (var_decl.lib_name) |lib_name| {
            try render_token(r, lib_name, Space.space); // "lib"
        }
    }

    if (var_decl.threadlocal_token) |thread_local_token| {
        try render_token(r, thread_local_token, Space.space); // threadlocal
    }

    if (!ignore_comptime_token) {
        if (var_decl.comptime_token) |comptime_token| {
            try render_token(r, comptime_token, Space.space); // comptime
        }
    }

    try render_token(r, var_decl.ast.mut_token, .space); // var

    if (var_decl.ast.type_node != 0 or var_decl.ast.align_node != 0 or
        var_decl.ast.addrspace_node != 0 or var_decl.ast.section_node != 0 or
        var_decl.ast.init_node != 0)
    {
        const name_space = if (var_decl.ast.type_node == 0 and
            (var_decl.ast.align_node != 0 or
            var_decl.ast.addrspace_node != 0 or
            var_decl.ast.section_node != 0 or
            var_decl.ast.init_node != 0))
            Space.space
        else
            Space.none;

        try render_identifier(r, var_decl.ast.mut_token + 1, name_space, .preserve_when_shadowing); // name
    } else {
        return render_identifier(r, var_decl.ast.mut_token + 1, space, .preserve_when_shadowing); // name
    }

    if (var_decl.ast.type_node != 0) {
        try render_token(r, var_decl.ast.mut_token + 2, Space.space); // :
        if (var_decl.ast.align_node != 0 or var_decl.ast.addrspace_node != 0 or
            var_decl.ast.section_node != 0 or var_decl.ast.init_node != 0)
        {
            try render_expression(r, var_decl.ast.type_node, .space);
        } else {
            return render_expression(r, var_decl.ast.type_node, space);
        }
    }

    if (var_decl.ast.align_node != 0) {
        const lparen = tree.first_token(var_decl.ast.align_node) - 1;
        const align_kw = lparen - 1;
        const rparen = tree.last_token(var_decl.ast.align_node) + 1;
        try render_token(r, align_kw, Space.none); // align
        try render_token(r, lparen, Space.none); // (
        try render_expression(r, var_decl.ast.align_node, Space.none);
        if (var_decl.ast.addrspace_node != 0 or var_decl.ast.section_node != 0 or
            var_decl.ast.init_node != 0)
        {
            try render_token(r, rparen, .space); // )
        } else {
            return render_token(r, rparen, space); // )
        }
    }

    if (var_decl.ast.addrspace_node != 0) {
        const lparen = tree.first_token(var_decl.ast.addrspace_node) - 1;
        const addrspace_kw = lparen - 1;
        const rparen = tree.last_token(var_decl.ast.addrspace_node) + 1;
        try render_token(r, addrspace_kw, Space.none); // addrspace
        try render_token(r, lparen, Space.none); // (
        try render_expression(r, var_decl.ast.addrspace_node, Space.none);
        if (var_decl.ast.section_node != 0 or var_decl.ast.init_node != 0) {
            try render_token(r, rparen, .space); // )
        } else {
            try render_token(r, rparen, .none); // )
            return render_token(r, rparen + 1, Space.newline); // ;
        }
    }

    if (var_decl.ast.section_node != 0) {
        const lparen = tree.first_token(var_decl.ast.section_node) - 1;
        const section_kw = lparen - 1;
        const rparen = tree.last_token(var_decl.ast.section_node) + 1;
        try render_token(r, section_kw, Space.none); // linksection
        try render_token(r, lparen, Space.none); // (
        try render_expression(r, var_decl.ast.section_node, Space.none);
        if (var_decl.ast.init_node != 0) {
            try render_token(r, rparen, .space); // )
        } else {
            return render_token(r, rparen, space); // )
        }
    }

    assert(var_decl.ast.init_node != 0);

    const eq_token = tree.first_token(var_decl.ast.init_node) - 1;
    const eq_space: Space = if (tree.tokens_on_same_line(eq_token, eq_token + 1)) .space else .newline;
    {
        ais.push_indent();
        try render_token(r, eq_token, eq_space); // =
        ais.pop_indent();
    }
    ais.push_indent_one_shot();
    return render_expression(r, var_decl.ast.init_node, space); // ;
}

fn render_if(r: *Render, if_node: Ast.full.If, space: Space) Error!void {
    return render_while(r, .{
        .ast = .{
            .while_token = if_node.ast.if_token,
            .cond_expr = if_node.ast.cond_expr,
            .cont_expr = 0,
            .then_expr = if_node.ast.then_expr,
            .else_expr = if_node.ast.else_expr,
        },
        .inline_token = null,
        .label_token = null,
        .payload_token = if_node.payload_token,
        .else_token = if_node.else_token,
        .error_token = if_node.error_token,
    }, space);
}

/// Note that this function is additionally used to render if expressions, with
/// respective values set to null.
fn render_while(r: *Render, while_node: Ast.full.While, space: Space) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);

    if (while_node.label_token) |label| {
        try render_identifier(r, label, .none, .eagerly_unquote); // label
        try render_token(r, label + 1, .space); // :
    }

    if (while_node.inline_token) |inline_token| {
        try render_token(r, inline_token, .space); // inline
    }

    try render_token(r, while_node.ast.while_token, .space); // if/for/while
    try render_token(r, while_node.ast.while_token + 1, .none); // lparen
    try render_expression(r, while_node.ast.cond_expr, .none); // condition

    var last_prefix_token = tree.last_token(while_node.ast.cond_expr) + 1; // rparen

    if (while_node.payload_token) |payload_token| {
        try render_token(r, last_prefix_token, .space);
        try render_token(r, payload_token - 1, .none); // |
        const ident = blk: {
            if (token_tags[payload_token] == .asterisk) {
                try render_token(r, payload_token, .none); // *
                break :blk payload_token + 1;
            } else {
                break :blk payload_token;
            }
        };
        try render_identifier(r, ident, .none, .preserve_when_shadowing); // identifier
        const pipe = blk: {
            if (token_tags[ident + 1] == .comma) {
                try render_token(r, ident + 1, .space); // ,
                try render_identifier(r, ident + 2, .none, .preserve_when_shadowing); // index
                break :blk ident + 3;
            } else {
                break :blk ident + 1;
            }
        };
        last_prefix_token = pipe;
    }

    if (while_node.ast.cont_expr != 0) {
        try render_token(r, last_prefix_token, .space);
        const lparen = tree.first_token(while_node.ast.cont_expr) - 1;
        try render_token(r, lparen - 1, .space); // :
        try render_token(r, lparen, .none); // lparen
        try render_expression(r, while_node.ast.cont_expr, .none);
        last_prefix_token = tree.last_token(while_node.ast.cont_expr) + 1; // rparen
    }

    try render_then_else(
        r,
        last_prefix_token,
        while_node.ast.then_expr,
        while_node.else_token,
        while_node.error_token,
        while_node.ast.else_expr,
        space,
    );
}

fn render_then_else(
    r: *Render,
    last_prefix_token: Ast.TokenIndex,
    then_expr: Ast.Node.Index,
    else_token: Ast.TokenIndex,
    maybe_error_token: ?Ast.TokenIndex,
    else_expr: Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const node_tags = tree.nodes.items(.tag);
    const then_expr_is_block = node_is_block(node_tags[then_expr]);
    const indent_then_expr = !then_expr_is_block and
        !tree.tokens_on_same_line(last_prefix_token, tree.first_token(then_expr));
    if (indent_then_expr or (then_expr_is_block and ais.is_line_over_indented())) {
        ais.push_indent_next_line();
        try render_token(r, last_prefix_token, .newline);
        ais.pop_indent();
    } else {
        try render_token(r, last_prefix_token, .space);
    }

    if (else_expr != 0) {
        if (indent_then_expr) {
            ais.push_indent();
            try render_expression(r, then_expr, .newline);
            ais.pop_indent();
        } else {
            try render_expression(r, then_expr, .space);
        }

        var last_else_token = else_token;

        if (maybe_error_token) |error_token| {
            try render_token(r, else_token, .space); // else
            try render_token(r, error_token - 1, .none); // |
            try render_identifier(r, error_token, .none, .preserve_when_shadowing); // identifier
            last_else_token = error_token + 1; // |
        }

        const indent_else_expr = indent_then_expr and
            !node_is_block(node_tags[else_expr]) and
            !node_is_if_for_while_switch(node_tags[else_expr]);
        if (indent_else_expr) {
            ais.push_indent_next_line();
            try render_token(r, last_else_token, .newline);
            ais.pop_indent();
            try render_expression_indented(r, else_expr, space);
        } else {
            try render_token(r, last_else_token, .space);
            try render_expression(r, else_expr, space);
        }
    } else {
        if (indent_then_expr) {
            try render_expression_indented(r, then_expr, space);
        } else {
            try render_expression(r, then_expr, space);
        }
    }
}

fn render_for(r: *Render, for_node: Ast.full.For, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);

    if (for_node.label_token) |label| {
        try render_identifier(r, label, .none, .eagerly_unquote); // label
        try render_token(r, label + 1, .space); // :
    }

    if (for_node.inline_token) |inline_token| {
        try render_token(r, inline_token, .space); // inline
    }

    try render_token(r, for_node.ast.for_token, .space); // if/for/while

    const lparen = for_node.ast.for_token + 1;
    try render_param_list(r, lparen, for_node.ast.inputs, .space);

    var cur = for_node.payload_token;
    const pipe = std.mem.index_of_scalar_pos(std.zig.Token.Tag, token_tags, cur, .pipe).?;
    if (token_tags[pipe - 1] == .comma) {
        ais.push_indent_next_line();
        try render_token(r, cur - 1, .newline); // |
        while (true) {
            if (token_tags[cur] == .asterisk) {
                try render_token(r, cur, .none); // *
                cur += 1;
            }
            try render_identifier(r, cur, .none, .preserve_when_shadowing); // identifier
            cur += 1;
            if (token_tags[cur] == .comma) {
                try render_token(r, cur, .newline); // ,
                cur += 1;
            }
            if (token_tags[cur] == .pipe) {
                break;
            }
        }
        ais.pop_indent();
    } else {
        try render_token(r, cur - 1, .none); // |
        while (true) {
            if (token_tags[cur] == .asterisk) {
                try render_token(r, cur, .none); // *
                cur += 1;
            }
            try render_identifier(r, cur, .none, .preserve_when_shadowing); // identifier
            cur += 1;
            if (token_tags[cur] == .comma) {
                try render_token(r, cur, .space); // ,
                cur += 1;
            }
            if (token_tags[cur] == .pipe) {
                break;
            }
        }
    }

    try render_then_else(
        r,
        cur,
        for_node.ast.then_expr,
        for_node.else_token,
        null,
        for_node.ast.else_expr,
        space,
    );
}

fn render_container_field(
    r: *Render,
    container: Container,
    field_param: Ast.full.ContainerField,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    var field = field_param;
    if (container != .tuple) field.convert_to_non_tuple_like(tree.nodes);
    const quote: QuoteBehavior = switch (container) {
        .@"enum" => .eagerly_unquote_except_underscore,
        .tuple, .other => .eagerly_unquote,
    };

    if (field.comptime_token) |t| {
        try render_token(r, t, .space); // comptime
    }
    if (field.ast.type_expr == 0 and field.ast.value_expr == 0) {
        if (field.ast.align_expr != 0) {
            try render_identifier(r, field.ast.main_token, .space, quote); // name
            const lparen_token = tree.first_token(field.ast.align_expr) - 1;
            const align_kw = lparen_token - 1;
            const rparen_token = tree.last_token(field.ast.align_expr) + 1;
            try render_token(r, align_kw, .none); // align
            try render_token(r, lparen_token, .none); // (
            try render_expression(r, field.ast.align_expr, .none); // alignment
            return render_token(r, rparen_token, .space); // )
        }
        return render_identifier_comma(r, field.ast.main_token, space, quote); // name
    }
    if (field.ast.type_expr != 0 and field.ast.value_expr == 0) {
        if (!field.ast.tuple_like) {
            try render_identifier(r, field.ast.main_token, .none, quote); // name
            try render_token(r, field.ast.main_token + 1, .space); // :
        }

        if (field.ast.align_expr != 0) {
            try render_expression(r, field.ast.type_expr, .space); // type
            const align_token = tree.first_token(field.ast.align_expr) - 2;
            try render_token(r, align_token, .none); // align
            try render_token(r, align_token + 1, .none); // (
            try render_expression(r, field.ast.align_expr, .none); // alignment
            const rparen = tree.last_token(field.ast.align_expr) + 1;
            return render_token_comma(r, rparen, space); // )
        } else {
            return render_expression_comma(r, field.ast.type_expr, space); // type
        }
    }
    if (field.ast.type_expr == 0 and field.ast.value_expr != 0) {
        try render_identifier(r, field.ast.main_token, .space, quote); // name
        if (field.ast.align_expr != 0) {
            const lparen_token = tree.first_token(field.ast.align_expr) - 1;
            const align_kw = lparen_token - 1;
            const rparen_token = tree.last_token(field.ast.align_expr) + 1;
            try render_token(r, align_kw, .none); // align
            try render_token(r, lparen_token, .none); // (
            try render_expression(r, field.ast.align_expr, .none); // alignment
            try render_token(r, rparen_token, .space); // )
        }
        try render_token(r, field.ast.main_token + 1, .space); // =
        return render_expression_comma(r, field.ast.value_expr, space); // value
    }
    if (!field.ast.tuple_like) {
        try render_identifier(r, field.ast.main_token, .none, quote); // name
        try render_token(r, field.ast.main_token + 1, .space); // :
    }
    try render_expression(r, field.ast.type_expr, .space); // type

    if (field.ast.align_expr != 0) {
        const lparen_token = tree.first_token(field.ast.align_expr) - 1;
        const align_kw = lparen_token - 1;
        const rparen_token = tree.last_token(field.ast.align_expr) + 1;
        try render_token(r, align_kw, .none); // align
        try render_token(r, lparen_token, .none); // (
        try render_expression(r, field.ast.align_expr, .none); // alignment
        try render_token(r, rparen_token, .space); // )
    }
    const eq_token = tree.first_token(field.ast.value_expr) - 1;
    const eq_space: Space = if (tree.tokens_on_same_line(eq_token, eq_token + 1)) .space else .newline;
    {
        ais.push_indent();
        try render_token(r, eq_token, eq_space); // =
        ais.pop_indent();
    }

    if (eq_space == .space)
        return render_expression_comma(r, field.ast.value_expr, space); // value

    const token_tags = tree.tokens.items(.tag);
    const maybe_comma = tree.last_token(field.ast.value_expr) + 1;

    if (token_tags[maybe_comma] == .comma) {
        ais.push_indent();
        try render_expression(r, field.ast.value_expr, .none); // value
        ais.pop_indent();
        try render_token(r, maybe_comma, .newline);
    } else {
        ais.push_indent();
        try render_expression(r, field.ast.value_expr, space); // value
        ais.pop_indent();
    }
}

fn render_builtin_call(
    r: *Render,
    builtin_token: Ast.TokenIndex,
    params: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    try render_token(r, builtin_token, .none); // @name

    if (params.len == 0) {
        try render_token(r, builtin_token + 1, .none); // (
        return render_token(r, builtin_token + 2, space); // )
    }

    if (r.fixups.rebase_imported_paths) |prefix| {
        const slice = tree.token_slice(builtin_token);
        if (mem.eql(u8, slice, "@import")) f: {
            const param = params[0];
            const str_lit_token = main_tokens[param];
            assert(token_tags[str_lit_token] == .string_literal);
            const token_bytes = tree.token_slice(str_lit_token);
            const imported_string = std.zig.string_literal.parse_alloc(r.gpa, token_bytes) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidLiteral => break :f,
            };
            defer r.gpa.free(imported_string);
            const new_string = try std.fs.path.resolve_posix(r.gpa, &.{ prefix, imported_string });
            defer r.gpa.free(new_string);

            try render_token(r, builtin_token + 1, .none); // (
            try ais.writer().print("\"{}\"", .{std.zig.fmt_escapes(new_string)});
            return render_token(r, str_lit_token + 1, space); // )
        }
    }

    const last_param = params[params.len - 1];
    const after_last_param_token = tree.last_token(last_param) + 1;

    if (token_tags[after_last_param_token] != .comma) {
        // Render all on one line, no trailing comma.
        try render_token(r, builtin_token + 1, .none); // (

        for (params, 0..) |param_node, i| {
            const first_param_token = tree.first_token(param_node);
            if (token_tags[first_param_token] == .multiline_string_literal_line or
                has_same_line_comment(tree, first_param_token - 1))
            {
                ais.push_indent_one_shot();
            }
            try render_expression(r, param_node, .none);

            if (i + 1 < params.len) {
                const comma_token = tree.last_token(param_node) + 1;
                try render_token(r, comma_token, .space); // ,
            }
        }
        return render_token(r, after_last_param_token, space); // )
    } else {
        // Render one param per line.
        ais.push_indent();
        try render_token(r, builtin_token + 1, Space.newline); // (

        for (params) |param_node| {
            try render_expression(r, param_node, .comma);
        }
        ais.pop_indent();

        return render_token(r, after_last_param_token + 1, space); // )
    }
}

fn render_fn_proto(r: *Render, fn_proto: Ast.full.FnProto, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    const token_starts = tree.tokens.items(.start);

    const after_fn_token = fn_proto.ast.fn_token + 1;
    const lparen = if (token_tags[after_fn_token] == .identifier) blk: {
        try render_token(r, fn_proto.ast.fn_token, .space); // fn
        try render_identifier(r, after_fn_token, .none, .preserve_when_shadowing); // name
        break :blk after_fn_token + 1;
    } else blk: {
        try render_token(r, fn_proto.ast.fn_token, .space); // fn
        break :blk fn_proto.ast.fn_token + 1;
    };
    assert(token_tags[lparen] == .l_paren);

    const maybe_bang = tree.first_token(fn_proto.ast.return_type) - 1;
    const rparen = blk: {
        // These may appear in any order, so we have to check the token_starts array
        // to find out which is first.
        var rparen = if (token_tags[maybe_bang] == .bang) maybe_bang - 1 else maybe_bang;
        var smallest_start = token_starts[maybe_bang];
        if (fn_proto.ast.align_expr != 0) {
            const tok = tree.first_token(fn_proto.ast.align_expr) - 3;
            const start = token_starts[tok];
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.addrspace_expr != 0) {
            const tok = tree.first_token(fn_proto.ast.addrspace_expr) - 3;
            const start = token_starts[tok];
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.section_expr != 0) {
            const tok = tree.first_token(fn_proto.ast.section_expr) - 3;
            const start = token_starts[tok];
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        if (fn_proto.ast.callconv_expr != 0) {
            const tok = tree.first_token(fn_proto.ast.callconv_expr) - 3;
            const start = token_starts[tok];
            if (start < smallest_start) {
                rparen = tok;
                smallest_start = start;
            }
        }
        break :blk rparen;
    };
    assert(token_tags[rparen] == .r_paren);

    // The params list is a sparse set that does *not* include anytype or ... parameters.

    const trailing_comma = token_tags[rparen - 1] == .comma;
    if (!trailing_comma and !has_comment(tree, lparen, rparen)) {
        // Render all on one line, no trailing comma.
        try render_token(r, lparen, .none); // (

        var param_i: usize = 0;
        var last_param_token = lparen;
        while (true) {
            last_param_token += 1;
            switch (token_tags[last_param_token]) {
                .doc_comment => {
                    try render_token(r, last_param_token, .newline);
                    continue;
                },
                .ellipsis3 => {
                    try render_token(r, last_param_token, .none); // ...
                    break;
                },
                .keyword_noalias, .keyword_comptime => {
                    try render_token(r, last_param_token, .space);
                    last_param_token += 1;
                },
                .identifier => {},
                .keyword_anytype => {
                    try render_token(r, last_param_token, .none); // anytype
                    continue;
                },
                .r_paren => break,
                .comma => {
                    try render_token(r, last_param_token, .space); // ,
                    continue;
                },
                else => {}, // Parameter type without a name.
            }
            if (token_tags[last_param_token] == .identifier and
                token_tags[last_param_token + 1] == .colon)
            {
                try render_identifier(r, last_param_token, .none, .preserve_when_shadowing); // name
                last_param_token += 1;
                try render_token(r, last_param_token, .space); // :
                last_param_token += 1;
            }
            if (token_tags[last_param_token] == .keyword_anytype) {
                try render_token(r, last_param_token, .none); // anytype
                continue;
            }
            const param = fn_proto.ast.params[param_i];
            param_i += 1;
            try render_expression(r, param, .none);
            last_param_token = tree.last_token(param);
        }
    } else {
        // One param per line.
        ais.push_indent();
        try render_token(r, lparen, .newline); // (

        var param_i: usize = 0;
        var last_param_token = lparen;
        while (true) {
            last_param_token += 1;
            switch (token_tags[last_param_token]) {
                .doc_comment => {
                    try render_token(r, last_param_token, .newline);
                    continue;
                },
                .ellipsis3 => {
                    try render_token(r, last_param_token, .comma); // ...
                    break;
                },
                .keyword_noalias, .keyword_comptime => {
                    try render_token(r, last_param_token, .space);
                    last_param_token += 1;
                },
                .identifier => {},
                .keyword_anytype => {
                    try render_token(r, last_param_token, .comma); // anytype
                    if (token_tags[last_param_token + 1] == .comma)
                        last_param_token += 1;
                    continue;
                },
                .r_paren => break,
                else => {}, // Parameter type without a name.
            }
            if (token_tags[last_param_token] == .identifier and
                token_tags[last_param_token + 1] == .colon)
            {
                try render_identifier(r, last_param_token, .none, .preserve_when_shadowing); // name
                last_param_token += 1;
                try render_token(r, last_param_token, .space); // :
                last_param_token += 1;
            }
            if (token_tags[last_param_token] == .keyword_anytype) {
                try render_token(r, last_param_token, .comma); // anytype
                if (token_tags[last_param_token + 1] == .comma)
                    last_param_token += 1;
                continue;
            }
            const param = fn_proto.ast.params[param_i];
            param_i += 1;
            try render_expression(r, param, .comma);
            last_param_token = tree.last_token(param);
            if (token_tags[last_param_token + 1] == .comma) last_param_token += 1;
        }
        ais.pop_indent();
    }

    try render_token(r, rparen, .space); // )

    if (fn_proto.ast.align_expr != 0) {
        const align_lparen = tree.first_token(fn_proto.ast.align_expr) - 1;
        const align_rparen = tree.last_token(fn_proto.ast.align_expr) + 1;

        try render_token(r, align_lparen - 1, .none); // align
        try render_token(r, align_lparen, .none); // (
        try render_expression(r, fn_proto.ast.align_expr, .none);
        try render_token(r, align_rparen, .space); // )
    }

    if (fn_proto.ast.addrspace_expr != 0) {
        const align_lparen = tree.first_token(fn_proto.ast.addrspace_expr) - 1;
        const align_rparen = tree.last_token(fn_proto.ast.addrspace_expr) + 1;

        try render_token(r, align_lparen - 1, .none); // addrspace
        try render_token(r, align_lparen, .none); // (
        try render_expression(r, fn_proto.ast.addrspace_expr, .none);
        try render_token(r, align_rparen, .space); // )
    }

    if (fn_proto.ast.section_expr != 0) {
        const section_lparen = tree.first_token(fn_proto.ast.section_expr) - 1;
        const section_rparen = tree.last_token(fn_proto.ast.section_expr) + 1;

        try render_token(r, section_lparen - 1, .none); // section
        try render_token(r, section_lparen, .none); // (
        try render_expression(r, fn_proto.ast.section_expr, .none);
        try render_token(r, section_rparen, .space); // )
    }

    const is_callconv_inline = mem.eql(u8, "Inline", tree.token_slice(tree.nodes.items(.main_token)[fn_proto.ast.callconv_expr]));
    const is_declaration = fn_proto.name_token != null;
    if (fn_proto.ast.callconv_expr != 0 and !(is_declaration and is_callconv_inline)) {
        const callconv_lparen = tree.first_token(fn_proto.ast.callconv_expr) - 1;
        const callconv_rparen = tree.last_token(fn_proto.ast.callconv_expr) + 1;

        try render_token(r, callconv_lparen - 1, .none); // callconv
        try render_token(r, callconv_lparen, .none); // (
        try render_expression(r, fn_proto.ast.callconv_expr, .none);
        try render_token(r, callconv_rparen, .space); // )
    }

    if (token_tags[maybe_bang] == .bang) {
        try render_token(r, maybe_bang, .none); // !
    }
    return render_expression(r, fn_proto.ast.return_type, space);
}

fn render_switch_case(
    r: *Render,
    switch_case: Ast.full.SwitchCase,
    space: Space,
) Error!void {
    const tree = r.tree;
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);
    const trailing_comma = token_tags[switch_case.ast.arrow_token - 1] == .comma;
    const has_comment_before_arrow = blk: {
        if (switch_case.ast.values.len == 0) break :blk false;
        break :blk has_comment(tree, tree.first_token(switch_case.ast.values[0]), switch_case.ast.arrow_token);
    };

    // render inline keyword
    if (switch_case.inline_token) |some| {
        try render_token(r, some, .space);
    }

    // Render everything before the arrow
    if (switch_case.ast.values.len == 0) {
        try render_token(r, switch_case.ast.arrow_token - 1, .space); // else keyword
    } else if (trailing_comma or has_comment_before_arrow) {
        // Render each value on a new line
        try render_expressions(r, switch_case.ast.values, .comma);
    } else {
        // Render on one line
        for (switch_case.ast.values) |value_expr| {
            try render_expression(r, value_expr, .comma_space);
        }
    }

    // Render the arrow and everything after it
    const pre_target_space = if (node_tags[switch_case.ast.target_expr] == .multiline_string_literal)
        // Newline gets inserted when rendering the target expr.
        Space.none
    else
        Space.space;
    const after_arrow_space: Space = if (switch_case.payload_token == null) pre_target_space else .space;
    try render_token(r, switch_case.ast.arrow_token, after_arrow_space); // =>

    if (switch_case.payload_token) |payload_token| {
        try render_token(r, payload_token - 1, .none); // pipe
        const ident = payload_token + @int_from_bool(token_tags[payload_token] == .asterisk);
        if (token_tags[payload_token] == .asterisk) {
            try render_token(r, payload_token, .none); // asterisk
        }
        try render_identifier(r, ident, .none, .preserve_when_shadowing); // identifier
        if (token_tags[ident + 1] == .comma) {
            try render_token(r, ident + 1, .space); // ,
            try render_identifier(r, ident + 2, .none, .preserve_when_shadowing); // identifier
            try render_token(r, ident + 3, pre_target_space); // pipe
        } else {
            try render_token(r, ident + 1, pre_target_space); // pipe
        }
    }

    try render_expression(r, switch_case.ast.target_expr, space);
}

fn render_block(
    r: *Render,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    const lbrace = tree.nodes.items(.main_token)[block_node];

    if (token_tags[lbrace - 1] == .colon and
        token_tags[lbrace - 2] == .identifier)
    {
        try render_identifier(r, lbrace - 2, .none, .eagerly_unquote); // identifier
        try render_token(r, lbrace - 1, .space); // :
    }
    ais.push_indent_next_line();
    if (statements.len == 0) {
        try render_token(r, lbrace, .none);
        ais.pop_indent();
        try render_token(r, tree.last_token(block_node), space); // rbrace
        return;
    }
    try render_token(r, lbrace, .newline);
    return finish_render_block(r, block_node, statements, space);
}

fn finish_render_block(
    r: *Render,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const node_tags = tree.nodes.items(.tag);
    const ais = r.ais;
    for (statements, 0..) |stmt, i| {
        if (i != 0) try render_extra_newline(r, stmt);
        if (r.fixups.omit_nodes.contains(stmt)) continue;
        switch (node_tags[stmt]) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => try render_var_decl(r, tree.full_var_decl(stmt).?, false, .semicolon),

            else => try render_expression(r, stmt, .semicolon),
        }
    }
    ais.pop_indent();

    try render_token(r, tree.last_token(block_node), space); // rbrace
}

fn render_struct_init(
    r: *Render,
    struct_node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    if (struct_init.ast.type_expr == 0) {
        try render_token(r, struct_init.ast.lbrace - 1, .none); // .
    } else {
        try render_expression(r, struct_init.ast.type_expr, .none); // T
    }
    if (struct_init.ast.fields.len == 0) {
        ais.push_indent_next_line();
        try render_token(r, struct_init.ast.lbrace, .none); // lbrace
        ais.pop_indent();
        return render_token(r, struct_init.ast.lbrace + 1, space); // rbrace
    }

    const rbrace = tree.last_token(struct_node);
    const trailing_comma = token_tags[rbrace - 1] == .comma;
    if (trailing_comma or has_comment(tree, struct_init.ast.lbrace, rbrace)) {
        // Render one field init per line.
        ais.push_indent_next_line();
        try render_token(r, struct_init.ast.lbrace, .newline);

        try render_token(r, struct_init.ast.lbrace + 1, .none); // .
        try render_identifier(r, struct_init.ast.lbrace + 2, .space, .eagerly_unquote); // name
        // Don't output a space after the = if expression is a multiline string,
        // since then it will start on the next line.
        const nodes = tree.nodes.items(.tag);
        const field_node = struct_init.ast.fields[0];
        const expr = nodes[field_node];
        var space_after_equal: Space = if (expr == .multiline_string_literal) .none else .space;
        try render_token(r, struct_init.ast.lbrace + 3, space_after_equal); // =
        try render_expression_fixup(r, field_node, .comma);

        for (struct_init.ast.fields[1..]) |field_init| {
            const init_token = tree.first_token(field_init);
            try render_extra_newline_token(r, init_token - 3);
            try render_token(r, init_token - 3, .none); // .
            try render_identifier(r, init_token - 2, .space, .eagerly_unquote); // name
            space_after_equal = if (nodes[field_init] == .multiline_string_literal) .none else .space;
            try render_token(r, init_token - 1, space_after_equal); // =
            try render_expression_fixup(r, field_init, .comma);
        }

        ais.pop_indent();
    } else {
        // Render all on one line, no trailing comma.
        try render_token(r, struct_init.ast.lbrace, .space);

        for (struct_init.ast.fields) |field_init| {
            const init_token = tree.first_token(field_init);
            try render_token(r, init_token - 3, .none); // .
            try render_identifier(r, init_token - 2, .space, .eagerly_unquote); // name
            try render_token(r, init_token - 1, .space); // =
            try render_expression_fixup(r, field_init, .comma_space);
        }
    }

    return render_token(r, rbrace, space);
}

fn render_array_init(
    r: *Render,
    array_init: Ast.full.ArrayInit,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const gpa = r.gpa;
    const token_tags = tree.tokens.items(.tag);

    if (array_init.ast.type_expr == 0) {
        try render_token(r, array_init.ast.lbrace - 1, .none); // .
    } else {
        try render_expression(r, array_init.ast.type_expr, .none); // T
    }

    if (array_init.ast.elements.len == 0) {
        ais.push_indent_next_line();
        try render_token(r, array_init.ast.lbrace, .none); // lbrace
        ais.pop_indent();
        return render_token(r, array_init.ast.lbrace + 1, space); // rbrace
    }

    const last_elem = array_init.ast.elements[array_init.ast.elements.len - 1];
    const last_elem_token = tree.last_token(last_elem);
    const trailing_comma = token_tags[last_elem_token + 1] == .comma;
    const rbrace = if (trailing_comma) last_elem_token + 2 else last_elem_token + 1;
    assert(token_tags[rbrace] == .r_brace);

    if (array_init.ast.elements.len == 1) {
        const only_elem = array_init.ast.elements[0];
        const first_token = tree.first_token(only_elem);
        if (token_tags[first_token] != .multiline_string_literal_line and
            !anything_between(tree, last_elem_token, rbrace))
        {
            try render_token(r, array_init.ast.lbrace, .none);
            try render_expression(r, only_elem, .none);
            return render_token(r, rbrace, space);
        }
    }

    const contains_comment = has_comment(tree, array_init.ast.lbrace, rbrace);
    const contains_multiline_string = has_multiline_string(tree, array_init.ast.lbrace, rbrace);

    if (!trailing_comma and !contains_comment and !contains_multiline_string) {
        // Render all on one line, no trailing comma.
        if (array_init.ast.elements.len == 1) {
            // If there is only one element, we don't use spaces
            try render_token(r, array_init.ast.lbrace, .none);
            try render_expression(r, array_init.ast.elements[0], .none);
        } else {
            try render_token(r, array_init.ast.lbrace, .space);
            for (array_init.ast.elements) |elem| {
                try render_expression(r, elem, .comma_space);
            }
        }
        return render_token(r, last_elem_token + 1, space); // rbrace
    }

    ais.push_indent_next_line();
    try render_token(r, array_init.ast.lbrace, .newline);

    var expr_index: usize = 0;
    while (true) {
        const row_size = row_size(tree, array_init.ast.elements[expr_index..], rbrace);
        const row_exprs = array_init.ast.elements[expr_index..];
        // A place to store the width of each expression and its column's maximum
        const widths = try gpa.alloc(usize, row_exprs.len + row_size);
        defer gpa.free(widths);
        @memset(widths, 0);

        const expr_newlines = try gpa.alloc(bool, row_exprs.len);
        defer gpa.free(expr_newlines);
        @memset(expr_newlines, false);

        const expr_widths = widths[0..row_exprs.len];
        const column_widths = widths[row_exprs.len..];

        // Find next row with trailing comment (if any) to end the current section.
        const section_end = sec_end: {
            var this_line_first_expr: usize = 0;
            var this_line_size = row_size(tree, row_exprs, rbrace);
            for (row_exprs, 0..) |expr, i| {
                // Ignore comment on first line of this section.
                if (i == 0) continue;
                const expr_last_token = tree.last_token(expr);
                if (tree.tokens_on_same_line(tree.first_token(row_exprs[0]), expr_last_token))
                    continue;
                // Track start of line containing comment.
                if (!tree.tokens_on_same_line(tree.first_token(row_exprs[this_line_first_expr]), expr_last_token)) {
                    this_line_first_expr = i;
                    this_line_size = row_size(tree, row_exprs[this_line_first_expr..], rbrace);
                }

                const maybe_comma = expr_last_token + 1;
                if (token_tags[maybe_comma] == .comma) {
                    if (has_same_line_comment(tree, maybe_comma))
                        break :sec_end i - this_line_size + 1;
                }
            }
            break :sec_end row_exprs.len;
        };
        expr_index += section_end;

        const section_exprs = row_exprs[0..section_end];

        var sub_expr_buffer = std.ArrayList(u8).init(gpa);
        defer sub_expr_buffer.deinit();

        const sub_expr_buffer_starts = try gpa.alloc(usize, section_exprs.len + 1);
        defer gpa.free(sub_expr_buffer_starts);

        var auto_indenting_stream = Ais{
            .indent_delta = indent_delta,
            .underlying_writer = sub_expr_buffer.writer(),
        };
        var sub_render: Render = .{
            .gpa = r.gpa,
            .ais = &auto_indenting_stream,
            .tree = r.tree,
            .fixups = r.fixups,
        };

        // Calculate size of columns in current section
        var column_counter: usize = 0;
        var single_line = true;
        var contains_newline = false;
        for (section_exprs, 0..) |expr, i| {
            const start = sub_expr_buffer.items.len;
            sub_expr_buffer_starts[i] = start;

            if (i + 1 < section_exprs.len) {
                try render_expression(&sub_render, expr, .none);
                const width = sub_expr_buffer.items.len - start;
                const this_contains_newline = mem.index_of_scalar(u8, sub_expr_buffer.items[start..], '\n') != null;
                contains_newline = contains_newline or this_contains_newline;
                expr_widths[i] = width;
                expr_newlines[i] = this_contains_newline;

                if (!this_contains_newline) {
                    const column = column_counter % row_size;
                    column_widths[column] = @max(column_widths[column], width);

                    const expr_last_token = tree.last_token(expr) + 1;
                    const next_expr = section_exprs[i + 1];
                    column_counter += 1;
                    if (!tree.tokens_on_same_line(expr_last_token, tree.first_token(next_expr))) single_line = false;
                } else {
                    single_line = false;
                    column_counter = 0;
                }
            } else {
                try render_expression(&sub_render, expr, .comma);
                const width = sub_expr_buffer.items.len - start - 2;
                const this_contains_newline = mem.index_of_scalar(u8, sub_expr_buffer.items[start .. sub_expr_buffer.items.len - 1], '\n') != null;
                contains_newline = contains_newline or this_contains_newline;
                expr_widths[i] = width;
                expr_newlines[i] = contains_newline;

                if (!contains_newline) {
                    const column = column_counter % row_size;
                    column_widths[column] = @max(column_widths[column], width);
                }
            }
        }
        sub_expr_buffer_starts[section_exprs.len] = sub_expr_buffer.items.len;

        // Render exprs in current section.
        column_counter = 0;
        for (section_exprs, 0..) |expr, i| {
            const start = sub_expr_buffer_starts[i];
            const end = sub_expr_buffer_starts[i + 1];
            const expr_text = sub_expr_buffer.items[start..end];
            if (!expr_newlines[i]) {
                try ais.writer().write_all(expr_text);
            } else {
                var by_line = std.mem.split_scalar(u8, expr_text, '\n');
                var last_line_was_empty = false;
                try ais.writer().write_all(by_line.first());
                while (by_line.next()) |line| {
                    if (std.mem.starts_with(u8, line, "//") and last_line_was_empty) {
                        try ais.insert_newline();
                    } else {
                        try ais.maybe_insert_newline();
                    }
                    last_line_was_empty = (line.len == 0);
                    try ais.writer().write_all(line);
                }
            }

            if (i + 1 < section_exprs.len) {
                const next_expr = section_exprs[i + 1];
                const comma = tree.last_token(expr) + 1;

                if (column_counter != row_size - 1) {
                    if (!expr_newlines[i] and !expr_newlines[i + 1]) {
                        // Neither the current or next expression is multiline
                        try render_token(r, comma, .space); // ,
                        assert(column_widths[column_counter % row_size] >= expr_widths[i]);
                        const padding = column_widths[column_counter % row_size] - expr_widths[i];
                        try ais.writer().write_byte_ntimes(' ', padding);

                        column_counter += 1;
                        continue;
                    }
                }

                if (single_line and row_size != 1) {
                    try render_token(r, comma, .space); // ,
                    continue;
                }

                column_counter = 0;
                try render_token(r, comma, .newline); // ,
                try render_extra_newline(r, next_expr);
            }
        }

        if (expr_index == array_init.ast.elements.len)
            break;
    }

    ais.pop_indent();
    return render_token(r, rbrace, space); // rbrace
}

fn render_container_decl(
    r: *Render,
    container_decl_node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);

    if (container_decl.layout_token) |layout_token| {
        try render_token(r, layout_token, .space);
    }

    const container: Container = switch (token_tags[container_decl.ast.main_token]) {
        .keyword_enum => .@"enum",
        .keyword_struct => for (container_decl.ast.members) |member| {
            if (tree.full_container_field(member)) |field| if (!field.ast.tuple_like) break .other;
        } else .tuple,
        else => .other,
    };

    var lbrace: Ast.TokenIndex = undefined;
    if (container_decl.ast.enum_token) |enum_token| {
        try render_token(r, container_decl.ast.main_token, .none); // union
        try render_token(r, enum_token - 1, .none); // lparen
        try render_token(r, enum_token, .none); // enum
        if (container_decl.ast.arg != 0) {
            try render_token(r, enum_token + 1, .none); // lparen
            try render_expression(r, container_decl.ast.arg, .none);
            const rparen = tree.last_token(container_decl.ast.arg) + 1;
            try render_token(r, rparen, .none); // rparen
            try render_token(r, rparen + 1, .space); // rparen
            lbrace = rparen + 2;
        } else {
            try render_token(r, enum_token + 1, .space); // rparen
            lbrace = enum_token + 2;
        }
    } else if (container_decl.ast.arg != 0) {
        try render_token(r, container_decl.ast.main_token, .none); // union
        try render_token(r, container_decl.ast.main_token + 1, .none); // lparen
        try render_expression(r, container_decl.ast.arg, .none);
        const rparen = tree.last_token(container_decl.ast.arg) + 1;
        try render_token(r, rparen, .space); // rparen
        lbrace = rparen + 1;
    } else {
        try render_token(r, container_decl.ast.main_token, .space); // union
        lbrace = container_decl.ast.main_token + 1;
    }

    const rbrace = tree.last_token(container_decl_node);
    if (container_decl.ast.members.len == 0) {
        ais.push_indent_next_line();
        if (token_tags[lbrace + 1] == .container_doc_comment) {
            try render_token(r, lbrace, .newline); // lbrace
            try render_container_doc_comments(r, lbrace + 1);
        } else {
            try render_token(r, lbrace, .none); // lbrace
        }
        ais.pop_indent();
        return render_token(r, rbrace, space); // rbrace
    }

    const src_has_trailing_comma = token_tags[rbrace - 1] == .comma;
    if (!src_has_trailing_comma) one_line: {
        // We print all the members in-line unless one of the following conditions are true:

        // 1. The container has comments or multiline strings.
        if (has_comment(tree, lbrace, rbrace) or has_multiline_string(tree, lbrace, rbrace)) {
            break :one_line;
        }

        // 2. The container has a container comment.
        if (token_tags[lbrace + 1] == .container_doc_comment) break :one_line;

        // 3. A member of the container has a doc comment.
        for (token_tags[lbrace + 1 .. rbrace - 1]) |tag| {
            if (tag == .doc_comment) break :one_line;
        }

        // 4. The container has non-field members.
        for (container_decl.ast.members) |member| {
            if (tree.full_container_field(member) == null) break :one_line;
        }

        // Print all the declarations on the same line.
        try render_token(r, lbrace, .space); // lbrace
        for (container_decl.ast.members) |member| {
            try render_member(r, container, member, .space);
        }
        return render_token(r, rbrace, space); // rbrace
    }

    // One member per line.
    ais.push_indent_next_line();
    try render_token(r, lbrace, .newline); // lbrace
    if (token_tags[lbrace + 1] == .container_doc_comment) {
        try render_container_doc_comments(r, lbrace + 1);
    }
    for (container_decl.ast.members, 0..) |member, i| {
        if (i != 0) try render_extra_newline(r, member);
        switch (tree.nodes.items(.tag)[member]) {
            // For container fields, ensure a trailing comma is added if necessary.
            .container_field_init,
            .container_field_align,
            .container_field,
            => try render_member(r, container, member, .comma),

            else => try render_member(r, container, member, .newline),
        }
    }
    ais.pop_indent();

    return render_token(r, rbrace, space); // rbrace
}

fn render_asm(
    r: *Render,
    asm_node: Ast.full.Asm,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);

    try render_token(r, asm_node.ast.asm_token, .space); // asm

    if (asm_node.volatile_token) |volatile_token| {
        try render_token(r, volatile_token, .space); // volatile
        try render_token(r, volatile_token + 1, .none); // lparen
    } else {
        try render_token(r, asm_node.ast.asm_token + 1, .none); // lparen
    }

    if (asm_node.ast.items.len == 0) {
        ais.push_indent();
        if (asm_node.first_clobber) |first_clobber| {
            // asm ("foo" ::: "a", "b")
            // asm ("foo" ::: "a", "b",)
            try render_expression(r, asm_node.ast.template, .space);
            // Render the three colons.
            try render_token(r, first_clobber - 3, .none);
            try render_token(r, first_clobber - 2, .none);
            try render_token(r, first_clobber - 1, .space);

            var tok_i = first_clobber;
            while (true) : (tok_i += 1) {
                try render_token(r, tok_i, .none);
                tok_i += 1;
                switch (token_tags[tok_i]) {
                    .r_paren => {
                        ais.pop_indent();
                        return render_token(r, tok_i, space);
                    },
                    .comma => {
                        if (token_tags[tok_i + 1] == .r_paren) {
                            ais.pop_indent();
                            return render_token(r, tok_i + 1, space);
                        } else {
                            try render_token(r, tok_i, .space);
                        }
                    },
                    else => unreachable,
                }
            }
        } else {
            // asm ("foo")
            try render_expression(r, asm_node.ast.template, .none);
            ais.pop_indent();
            return render_token(r, asm_node.ast.rparen, space); // rparen
        }
    }

    ais.push_indent();
    try render_expression(r, asm_node.ast.template, .newline);
    ais.set_indent_delta(asm_indent_delta);
    const colon1 = tree.last_token(asm_node.ast.template) + 1;

    const colon2 = if (asm_node.outputs.len == 0) colon2: {
        try render_token(r, colon1, .newline); // :
        break :colon2 colon1 + 1;
    } else colon2: {
        try render_token(r, colon1, .space); // :

        ais.push_indent();
        for (asm_node.outputs, 0..) |asm_output, i| {
            if (i + 1 < asm_node.outputs.len) {
                const next_asm_output = asm_node.outputs[i + 1];
                try render_asm_output(r, asm_output, .none);

                const comma = tree.first_token(next_asm_output) - 1;
                try render_token(r, comma, .newline); // ,
                try render_extra_newline_token(r, tree.first_token(next_asm_output));
            } else if (asm_node.inputs.len == 0 and asm_node.first_clobber == null) {
                try render_asm_output(r, asm_output, .comma);
                ais.pop_indent();
                ais.set_indent_delta(indent_delta);
                ais.pop_indent();
                return render_token(r, asm_node.ast.rparen, space); // rparen
            } else {
                try render_asm_output(r, asm_output, .comma);
                const comma_or_colon = tree.last_token(asm_output) + 1;
                ais.pop_indent();
                break :colon2 switch (token_tags[comma_or_colon]) {
                    .comma => comma_or_colon + 1,
                    else => comma_or_colon,
                };
            }
        } else unreachable;
    };

    const colon3 = if (asm_node.inputs.len == 0) colon3: {
        try render_token(r, colon2, .newline); // :
        break :colon3 colon2 + 1;
    } else colon3: {
        try render_token(r, colon2, .space); // :
        ais.push_indent();
        for (asm_node.inputs, 0..) |asm_input, i| {
            if (i + 1 < asm_node.inputs.len) {
                const next_asm_input = asm_node.inputs[i + 1];
                try render_asm_input(r, asm_input, .none);

                const first_token = tree.first_token(next_asm_input);
                try render_token(r, first_token - 1, .newline); // ,
                try render_extra_newline_token(r, first_token);
            } else if (asm_node.first_clobber == null) {
                try render_asm_input(r, asm_input, .comma);
                ais.pop_indent();
                ais.set_indent_delta(indent_delta);
                ais.pop_indent();
                return render_token(r, asm_node.ast.rparen, space); // rparen
            } else {
                try render_asm_input(r, asm_input, .comma);
                const comma_or_colon = tree.last_token(asm_input) + 1;
                ais.pop_indent();
                break :colon3 switch (token_tags[comma_or_colon]) {
                    .comma => comma_or_colon + 1,
                    else => comma_or_colon,
                };
            }
        }
        unreachable;
    };

    try render_token(r, colon3, .space); // :
    const first_clobber = asm_node.first_clobber.?;
    var tok_i = first_clobber;
    while (true) {
        switch (token_tags[tok_i + 1]) {
            .r_paren => {
                ais.set_indent_delta(indent_delta);
                ais.pop_indent();
                try render_token(r, tok_i, .newline);
                return render_token(r, tok_i + 1, space);
            },
            .comma => {
                switch (token_tags[tok_i + 2]) {
                    .r_paren => {
                        ais.set_indent_delta(indent_delta);
                        ais.pop_indent();
                        try render_token(r, tok_i, .newline);
                        return render_token(r, tok_i + 2, space);
                    },
                    else => {
                        try render_token(r, tok_i, .none);
                        try render_token(r, tok_i + 1, .space);
                        tok_i += 2;
                    },
                }
            },
            else => unreachable,
        }
    }
}

fn render_call(
    r: *Render,
    call: Ast.full.Call,
    space: Space,
) Error!void {
    if (call.async_token) |async_token| {
        try render_token(r, async_token, .space);
    }
    try render_expression(r, call.ast.fn_expr, .none);
    try render_param_list(r, call.ast.lparen, call.ast.params, space);
}

fn render_param_list(
    r: *Render,
    lparen: Ast.TokenIndex,
    params: []const Ast.Node.Index,
    space: Space,
) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);

    if (params.len == 0) {
        ais.push_indent_next_line();
        try render_token(r, lparen, .none);
        ais.pop_indent();
        return render_token(r, lparen + 1, space); // )
    }

    const last_param = params[params.len - 1];
    const after_last_param_tok = tree.last_token(last_param) + 1;
    if (token_tags[after_last_param_tok] == .comma) {
        ais.push_indent_next_line();
        try render_token(r, lparen, .newline); // (
        for (params, 0..) |param_node, i| {
            if (i + 1 < params.len) {
                try render_expression(r, param_node, .none);

                // Unindent the comma for multiline string literals.
                const is_multiline_string =
                    token_tags[tree.first_token(param_node)] == .multiline_string_literal_line;
                if (is_multiline_string) ais.pop_indent();

                const comma = tree.last_token(param_node) + 1;
                try render_token(r, comma, .newline); // ,

                if (is_multiline_string) ais.push_indent();

                try render_extra_newline(r, params[i + 1]);
            } else {
                try render_expression(r, param_node, .comma);
            }
        }
        ais.pop_indent();
        return render_token(r, after_last_param_tok + 1, space); // )
    }

    try render_token(r, lparen, .none); // (

    for (params, 0..) |param_node, i| {
        const first_param_token = tree.first_token(param_node);
        if (token_tags[first_param_token] == .multiline_string_literal_line or
            has_same_line_comment(tree, first_param_token - 1))
        {
            ais.push_indent_one_shot();
        }
        try render_expression(r, param_node, .none);

        if (i + 1 < params.len) {
            const comma = tree.last_token(param_node) + 1;
            const next_multiline_string =
                token_tags[tree.first_token(params[i + 1])] == .multiline_string_literal_line;
            const comma_space: Space = if (next_multiline_string) .none else .space;
            try render_token(r, comma, comma_space);
        }
    }

    return render_token(r, after_last_param_tok, space); // )
}

/// Renders the given expression indented, popping the indent before rendering
/// any following line comments
fn render_expression_indented(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);

    ais.push_indent();

    var last_token = tree.last_token(node);
    const punctuation = switch (space) {
        .none, .space, .newline, .skip => false,
        .comma => true,
        .comma_space => token_tags[last_token + 1] == .comma,
        .semicolon => token_tags[last_token + 1] == .semicolon,
    };

    try render_expression(r, node, if (punctuation) .none else .skip);

    switch (space) {
        .none, .space, .newline, .skip => {},
        .comma => {
            if (token_tags[last_token + 1] == .comma) {
                try render_token(r, last_token + 1, .skip);
                last_token += 1;
            } else {
                try ais.writer().write_byte(',');
            }
        },
        .comma_space => if (token_tags[last_token + 1] == .comma) {
            try render_token(r, last_token + 1, .skip);
            last_token += 1;
        },
        .semicolon => if (token_tags[last_token + 1] == .semicolon) {
            try render_token(r, last_token + 1, .skip);
            last_token += 1;
        },
    }

    ais.pop_indent();

    if (space == .skip) return;

    const comment_start = token_starts[last_token] + token_slice_for_render(tree, last_token).len;
    const comment = try render_comments(r, comment_start, token_starts[last_token + 1]);

    if (!comment) switch (space) {
        .none => {},
        .space,
        .comma_space,
        => try ais.writer().write_byte(' '),
        .newline,
        .comma,
        .semicolon,
        => try ais.insert_newline(),
        .skip => unreachable,
    };
}

/// Render an expression, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn render_expression_comma(r: *Render, node: Ast.Node.Index, space: Space) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    const maybe_comma = tree.last_token(node) + 1;
    if (token_tags[maybe_comma] == .comma and space != .comma) {
        try render_expression(r, node, .none);
        return render_token(r, maybe_comma, space);
    } else {
        return render_expression(r, node, space);
    }
}

/// Render a token, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn render_token_comma(r: *Render, token: Ast.TokenIndex, space: Space) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    const maybe_comma = token + 1;
    if (token_tags[maybe_comma] == .comma and space != .comma) {
        try render_token(r, token, .none);
        return render_token(r, maybe_comma, space);
    } else {
        return render_token(r, token, space);
    }
}

/// Render an identifier, and the comma that follows it, if it is present in the source.
/// If a comma is present, and `space` is `Space.comma`, render only a single comma.
fn render_identifier_comma(r: *Render, token: Ast.TokenIndex, space: Space, quote: QuoteBehavior) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    const maybe_comma = token + 1;
    if (token_tags[maybe_comma] == .comma and space != .comma) {
        try render_identifier(r, token, .none, quote);
        return render_token(r, maybe_comma, space);
    } else {
        return render_identifier(r, token, space, quote);
    }
}

const Space = enum {
    /// Output the token lexeme only.
    none,
    /// Output the token lexeme followed by a single space.
    space,
    /// Output the token lexeme followed by a newline.
    newline,
    /// If the next token is a comma, render it as well. If not, insert one.
    /// In either case, a newline will be inserted afterwards.
    comma,
    /// Additionally consume the next token if it is a comma.
    /// In either case, a space will be inserted afterwards.
    comma_space,
    /// Additionally consume the next token if it is a semicolon.
    /// In either case, a newline will be inserted afterwards.
    semicolon,
    /// Skip rendering whitespace and comments. If this is used, the caller
    /// *must* handle whitespace and comments manually.
    skip,
};

fn render_token(r: *Render, token_index: Ast.TokenIndex, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const lexeme = token_slice_for_render(tree, token_index);
    try ais.writer().write_all(lexeme);
    try render_space(r, token_index, lexeme.len, space);
}

fn render_space(r: *Render, token_index: Ast.TokenIndex, lexeme_len: usize, space: Space) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    const token_starts = tree.tokens.items(.start);

    const token_start = token_starts[token_index];

    if (space == .skip) return;

    if (space == .comma and token_tags[token_index + 1] != .comma) {
        try ais.writer().write_byte(',');
    }

    const comment = try render_comments(r, token_start + lexeme_len, token_starts[token_index + 1]);
    switch (space) {
        .none => {},
        .space => if (!comment) try ais.writer().write_byte(' '),
        .newline => if (!comment) try ais.insert_newline(),

        .comma => if (token_tags[token_index + 1] == .comma) {
            try render_token(r, token_index + 1, .newline);
        } else if (!comment) {
            try ais.insert_newline();
        },

        .comma_space => if (token_tags[token_index + 1] == .comma) {
            try render_token(r, token_index + 1, .space);
        } else if (!comment) {
            try ais.writer().write_byte(' ');
        },

        .semicolon => if (token_tags[token_index + 1] == .semicolon) {
            try render_token(r, token_index + 1, .newline);
        } else if (!comment) {
            try ais.insert_newline();
        },

        .skip => unreachable,
    }
}

fn render_only_space(r: *Render, space: Space) Error!void {
    const ais = r.ais;
    switch (space) {
        .none => {},
        .space => try ais.writer().write_byte(' '),
        .newline => try ais.insert_newline(),
        .comma => try ais.writer().write_all(",\n"),
        .comma_space => try ais.writer().write_all(", "),
        .semicolon => try ais.writer().write_all(";\n"),
        .skip => unreachable,
    }
}

const QuoteBehavior = enum {
    preserve_when_shadowing,
    eagerly_unquote,
    eagerly_unquote_except_underscore,
};

fn render_identifier(r: *Render, token_index: Ast.TokenIndex, space: Space, quote: QuoteBehavior) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    assert(token_tags[token_index] == .identifier);
    const lexeme = token_slice_for_render(tree, token_index);

    if (r.fixups.rename_identifiers.get(lexeme)) |mangled| {
        try r.ais.writer().write_all(mangled);
        try render_space(r, token_index, lexeme.len, space);
        return;
    }

    if (lexeme[0] != '@') {
        return render_token(r, token_index, space);
    }

    assert(lexeme.len >= 3);
    assert(lexeme[0] == '@');
    assert(lexeme[1] == '\"');
    assert(lexeme[lexeme.len - 1] == '\"');
    const contents = lexeme[2 .. lexeme.len - 1]; // inside the @"" quotation

    // Empty name can't be unquoted.
    if (contents.len == 0) {
        return render_quoted_identifier(r, token_index, space, false);
    }

    // Special case for _.
    if (std.zig.is_underscore(contents)) switch (quote) {
        .eagerly_unquote => return render_quoted_identifier(r, token_index, space, true),
        .eagerly_unquote_except_underscore,
        .preserve_when_shadowing,
        => return render_quoted_identifier(r, token_index, space, false),
    };

    // Scan the entire name for characters that would (after un-escaping) be illegal in a symbol,
    // i.e. contents don't match: [A-Za-z_][A-Za-z0-9_]*
    var contents_i: usize = 0;
    while (contents_i < contents.len) {
        switch (contents[contents_i]) {
            '0'...'9' => if (contents_i == 0) return render_quoted_identifier(r, token_index, space, false),
            'A'...'Z', 'a'...'z', '_' => {},
            '\\' => {
                var esc_offset = contents_i;
                const res = std.zig.string_literal.parse_escape_sequence(contents, &esc_offset);
                switch (res) {
                    .success => |char| switch (char) {
                        '0'...'9' => if (contents_i == 0) return render_quoted_identifier(r, token_index, space, false),
                        'A'...'Z', 'a'...'z', '_' => {},
                        else => return render_quoted_identifier(r, token_index, space, false),
                    },
                    .failure => return render_quoted_identifier(r, token_index, space, false),
                }
                contents_i += esc_offset;
                continue;
            },
            else => return render_quoted_identifier(r, token_index, space, false),
        }
        contents_i += 1;
    }

    // Read enough of the name (while un-escaping) to determine if it's a keyword or primitive.
    // If it's too long to fit in this buffer, we know it's neither and quoting is unnecessary.
    // If we read the whole thing, we have to do further checks.
    const longest_keyword_or_primitive_len = comptime blk: {
        var longest = 0;
        for (primitives.names.keys()) |key| {
            if (key.len > longest) longest = key.len;
        }
        for (std.zig.Token.keywords.keys()) |key| {
            if (key.len > longest) longest = key.len;
        }
        break :blk longest;
    };
    var buf: [longest_keyword_or_primitive_len]u8 = undefined;

    contents_i = 0;
    var buf_i: usize = 0;
    while (contents_i < contents.len and buf_i < longest_keyword_or_primitive_len) {
        if (contents[contents_i] == '\\') {
            const res = std.zig.string_literal.parse_escape_sequence(contents, &contents_i).success;
            buf[buf_i] = @as(u8, @int_cast(res));
            buf_i += 1;
        } else {
            buf[buf_i] = contents[contents_i];
            contents_i += 1;
            buf_i += 1;
        }
    }

    // We read the whole thing, so it could be a keyword or primitive.
    if (contents_i == contents.len) {
        if (!std.zig.is_valid_id(buf[0..buf_i])) {
            return render_quoted_identifier(r, token_index, space, false);
        }
        if (primitives.is_primitive(buf[0..buf_i])) switch (quote) {
            .eagerly_unquote,
            .eagerly_unquote_except_underscore,
            => return render_quoted_identifier(r, token_index, space, true),
            .preserve_when_shadowing => return render_quoted_identifier(r, token_index, space, false),
        };
    }

    try render_quoted_identifier(r, token_index, space, true);
}

// Renders a @"" quoted identifier, normalizing escapes.
// Unnecessary escapes are un-escaped, and \u escapes are normalized to \x when they fit.
// If unquote is true, the @"" is removed and the result is a bare symbol whose validity is asserted.
fn render_quoted_identifier(r: *Render, token_index: Ast.TokenIndex, space: Space, comptime unquote: bool) !void {
    const tree = r.tree;
    const ais = r.ais;
    const token_tags = tree.tokens.items(.tag);
    assert(token_tags[token_index] == .identifier);
    const lexeme = token_slice_for_render(tree, token_index);
    assert(lexeme.len >= 3 and lexeme[0] == '@');

    if (!unquote) try ais.writer().write_all("@\"");
    const contents = lexeme[2 .. lexeme.len - 1];
    try render_identifier_contents(ais.writer(), contents);
    if (!unquote) try ais.writer().write_byte('\"');

    try render_space(r, token_index, lexeme.len, space);
}

fn render_identifier_contents(writer: anytype, bytes: []const u8) !void {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const byte = bytes[pos];
        switch (byte) {
            '\\' => {
                const old_pos = pos;
                const res = std.zig.string_literal.parse_escape_sequence(bytes, &pos);
                const escape_sequence = bytes[old_pos..pos];
                switch (res) {
                    .success => |codepoint| {
                        if (codepoint <= 0x7f) {
                            const buf = [1]u8{@as(u8, @int_cast(codepoint))};
                            try std.fmt.format(writer, "{}", .{std.zig.fmt_escapes(&buf)});
                        } else {
                            try writer.write_all(escape_sequence);
                        }
                    },
                    .failure => {
                        try writer.write_all(escape_sequence);
                    },
                }
            },
            0x00...('\\' - 1), ('\\' + 1)...0x7f => {
                const buf = [1]u8{byte};
                try std.fmt.format(writer, "{}", .{std.zig.fmt_escapes(&buf)});
                pos += 1;
            },
            0x80...0xff => {
                try writer.write_byte(byte);
                pos += 1;
            },
        }
    }
}

/// Returns true if there exists a line comment between any of the tokens from
/// `start_token` to `end_token`. This is used to determine if e.g. a
/// fn_proto should be wrapped and have a trailing comma inserted even if
/// there is none in the source.
fn has_comment(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    const token_starts = tree.tokens.items(.start);

    var i = start_token;
    while (i < end_token) : (i += 1) {
        const start = token_starts[i] + tree.token_slice(i).len;
        const end = token_starts[i + 1];
        if (mem.index_of(u8, tree.source[start..end], "//") != null) return true;
    }

    return false;
}

/// Returns true if there exists a multiline string literal between the start
/// of token `start_token` and the start of token `end_token`.
fn has_multiline_string(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    const token_tags = tree.tokens.items(.tag);

    for (token_tags[start_token..end_token]) |tag| {
        switch (tag) {
            .multiline_string_literal_line => return true,
            else => continue,
        }
    }

    return false;
}

/// Assumes that start is the first byte past the previous token and
/// that end is the last byte before the next token.
fn render_comments(r: *Render, start: usize, end: usize) Error!bool {
    const tree = r.tree;
    const ais = r.ais;

    var index: usize = start;
    while (mem.index_of(u8, tree.source[index..end], "//")) |offset| {
        const comment_start = index + offset;

        // If there is no newline, the comment ends with EOF
        const newline_index = mem.index_of_scalar(u8, tree.source[comment_start..end], '\n');
        const newline = if (newline_index) |i| comment_start + i else null;

        const untrimmed_comment = tree.source[comment_start .. newline orelse tree.source.len];
        const trimmed_comment = mem.trim_right(u8, untrimmed_comment, &std.ascii.whitespace);

        // Don't leave any whitespace at the start of the file
        if (index != 0) {
            if (index == start and mem.contains_at_least(u8, tree.source[index..comment_start], 2, "\n")) {
                // Leave up to one empty line before the first comment
                try ais.insert_newline();
                try ais.insert_newline();
            } else if (mem.index_of_scalar(u8, tree.source[index..comment_start], '\n') != null) {
                // Respect the newline directly before the comment.
                // Note: This allows an empty line between comments
                try ais.insert_newline();
            } else if (index == start) {
                // Otherwise if the first comment is on the same line as
                // the token before it, prefix it with a single space.
                try ais.writer().write_byte(' ');
            }
        }

        index = 1 + (newline orelse end - 1);

        const comment_content = mem.trim_left(u8, trimmed_comment["//".len..], &std.ascii.whitespace);
        if (ais.disabled_offset != null and mem.eql(u8, comment_content, "zig fmt: on")) {
            // Write the source for which formatting was disabled directly
            // to the underlying writer, fixing up invalid whitespace.
            const disabled_source = tree.source[ais.disabled_offset.?..comment_start];
            try write_fixing_whitespace(ais.underlying_writer, disabled_source);
            // Write with the canonical single space.
            try ais.underlying_writer.write_all("// zig fmt: on\n");
            ais.disabled_offset = null;
        } else if (ais.disabled_offset == null and mem.eql(u8, comment_content, "zig fmt: off")) {
            // Write with the canonical single space.
            try ais.writer().write_all("// zig fmt: off\n");
            ais.disabled_offset = index;
        } else {
            // Write the comment minus trailing whitespace.
            try ais.writer().print("{s}\n", .{trimmed_comment});
        }
    }

    if (index != start and mem.contains_at_least(u8, tree.source[index - 1 .. end], 2, "\n")) {
        // Don't leave any whitespace at the end of the file
        if (end != tree.source.len) {
            try ais.insert_newline();
        }
    }

    return index != start;
}

fn render_extra_newline(r: *Render, node: Ast.Node.Index) Error!void {
    return render_extra_newline_token(r, r.tree.first_token(node));
}

/// Check if there is an empty line immediately before the given token. If so, render it.
fn render_extra_newline_token(r: *Render, token_index: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    const ais = r.ais;
    const token_starts = tree.tokens.items(.start);
    const token_start = token_starts[token_index];
    if (token_start == 0) return;
    const prev_token_end = if (token_index == 0)
        0
    else
        token_starts[token_index - 1] + token_slice_for_render(tree, token_index - 1).len;

    // If there is a immediately preceding comment or doc_comment,
    // skip it because required extra newline has already been rendered.
    if (mem.index_of(u8, tree.source[prev_token_end..token_start], "//") != null) return;
    if (token_index > 0 and tree.tokens.items(.tag)[token_index - 1] == .doc_comment) return;

    // Iterate backwards to the end of the previous token, stopping if a
    // non-whitespace character is encountered or two newlines have been found.
    var i = token_start - 1;
    var newlines: u2 = 0;
    while (std.ascii.is_whitespace(tree.source[i])) : (i -= 1) {
        if (tree.source[i] == '\n') newlines += 1;
        if (newlines == 2) return ais.insert_newline();
        if (i == prev_token_end) break;
    }
}

/// end_token is the token one past the last doc comment token. This function
/// searches backwards from there.
fn render_doc_comments(r: *Render, end_token: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    // Search backwards for the first doc comment.
    const token_tags = tree.tokens.items(.tag);
    if (end_token == 0) return;
    var tok = end_token - 1;
    while (token_tags[tok] == .doc_comment) {
        if (tok == 0) break;
        tok -= 1;
    } else {
        tok += 1;
    }
    const first_tok = tok;
    if (first_tok == end_token) return;

    if (first_tok != 0) {
        const prev_token_tag = token_tags[first_tok - 1];

        // Prevent accidental use of `render_doc_comments` for a function argument doc comment
        assert(prev_token_tag != .l_paren);

        if (prev_token_tag != .l_brace) {
            try render_extra_newline_token(r, first_tok);
        }
    }

    while (token_tags[tok] == .doc_comment) : (tok += 1) {
        try render_token(r, tok, .newline);
    }
}

/// start_token is first container doc comment token.
fn render_container_doc_comments(r: *Render, start_token: Ast.TokenIndex) Error!void {
    const tree = r.tree;
    const token_tags = tree.tokens.items(.tag);
    var tok = start_token;
    while (token_tags[tok] == .container_doc_comment) : (tok += 1) {
        try render_token(r, tok, .newline);
    }
    // Render extra newline if there is one between final container doc comment and
    // the next token. If the next token is a doc comment, that code path
    // will have its own logic to insert a newline.
    if (token_tags[tok] != .doc_comment) {
        try render_extra_newline_token(r, tok);
    }
}

fn discard_all_params(r: *Render, fn_proto_node: Ast.Node.Index) Error!void {
    const tree = &r.tree;
    const ais = r.ais;
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = tree.full_fn_proto(&buf, fn_proto_node).?;
    const token_tags = tree.tokens.items(.tag);
    var it = fn_proto.iterate(tree);
    while (it.next()) |param| {
        const name_ident = param.name_token.?;
        assert(token_tags[name_ident] == .identifier);
        const w = ais.writer();
        try w.write_all("_ = ");
        try w.write_all(token_slice_for_render(r.tree, name_ident));
        try w.write_all(";\n");
    }
}

fn token_slice_for_render(tree: Ast, token_index: Ast.TokenIndex) []const u8 {
    var ret = tree.token_slice(token_index);
    switch (tree.tokens.items(.tag)[token_index]) {
        .multiline_string_literal_line => {
            if (ret[ret.len - 1] == '\n') ret.len -= 1;
        },
        .container_doc_comment, .doc_comment => {
            ret = mem.trim_right(u8, ret, &std.ascii.whitespace);
        },
        else => {},
    }
    return ret;
}

fn has_same_line_comment(tree: Ast, token_index: Ast.TokenIndex) bool {
    const token_starts = tree.tokens.items(.start);
    const between_source = tree.source[token_starts[token_index]..token_starts[token_index + 1]];
    for (between_source) |byte| switch (byte) {
        '\n' => return false,
        '/' => return true,
        else => continue,
    };
    return false;
}

/// Returns `true` if and only if there are any tokens or line comments between
/// start_token and end_token.
fn anything_between(tree: Ast, start_token: Ast.TokenIndex, end_token: Ast.TokenIndex) bool {
    if (start_token + 1 != end_token) return true;
    const token_starts = tree.tokens.items(.start);
    const between_source = tree.source[token_starts[start_token]..token_starts[start_token + 1]];
    for (between_source) |byte| switch (byte) {
        '/' => return true,
        else => continue,
    };
    return false;
}

fn write_fixing_whitespace(writer: std.ArrayList(u8).Writer, slice: []const u8) Error!void {
    for (slice) |byte| switch (byte) {
        '\t' => try writer.write_all(" " ** 4),
        '\r' => {},
        else => try writer.write_byte(byte),
    };
}

fn node_is_block(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => true,
        else => false,
    };
}

fn node_is_if_for_while_switch(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"if",
        .if_simple,
        .@"for",
        .for_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .@"switch",
        .switch_comma,
        => true,
        else => false,
    };
}

fn node_causes_slice_op_space(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"catch",
        .add,
        .add_wrap,
        .array_cat,
        .array_mult,
        .assign,
        .assign_bit_and,
        .assign_bit_or,
        .assign_shl,
        .assign_shr,
        .assign_bit_xor,
        .assign_div,
        .assign_sub,
        .assign_sub_wrap,
        .assign_mod,
        .assign_add,
        .assign_add_wrap,
        .assign_mul,
        .assign_mul_wrap,
        .bang_equal,
        .bit_and,
        .bit_or,
        .shl,
        .shr,
        .bit_xor,
        .bool_and,
        .bool_or,
        .div,
        .equal_equal,
        .error_union,
        .greater_or_equal,
        .greater_than,
        .less_or_equal,
        .less_than,
        .merge_error_sets,
        .mod,
        .mul,
        .mul_wrap,
        .sub,
        .sub_wrap,
        .@"orelse",
        => true,

        else => false,
    };
}

// Returns the number of nodes in `exprs` that are on the same line as `rtoken`.
fn row_size(tree: Ast, exprs: []const Ast.Node.Index, rtoken: Ast.TokenIndex) usize {
    const token_tags = tree.tokens.items(.tag);

    const first_token = tree.first_token(exprs[0]);
    if (tree.tokens_on_same_line(first_token, rtoken)) {
        const maybe_comma = rtoken - 1;
        if (token_tags[maybe_comma] == .comma)
            return 1;
        return exprs.len; // no newlines
    }

    var count: usize = 1;
    for (exprs, 0..) |expr, i| {
        if (i + 1 < exprs.len) {
            const expr_last_token = tree.last_token(expr) + 1;
            if (!tree.tokens_on_same_line(expr_last_token, tree.first_token(exprs[i + 1]))) return count;
            count += 1;
        } else {
            return count;
        }
    }
    unreachable;
}

/// Automatically inserts indentation of written data by keeping
/// track of the current indentation level
fn AutoIndentingStream(comptime UnderlyingWriter: type) type {
    return struct {
        const Self = @This();
        pub const WriteError = UnderlyingWriter.Error;
        pub const Writer = std.io.Writer(*Self, WriteError, write);

        underlying_writer: UnderlyingWriter,

        /// Offset into the source at which formatting has been disabled with
        /// a `zig fmt: off` comment.
        ///
        /// If non-null, the AutoIndentingStream will not write any bytes
        /// to the underlying writer. It will however continue to track the
        /// indentation level.
        disabled_offset: ?usize = null,

        indent_count: usize = 0,
        indent_delta: usize,
        current_line_empty: bool = true,
        /// automatically popped when applied
        indent_one_shot_count: usize = 0,
        /// the most recently applied indent
        applied_indent: usize = 0,
        /// not used until the next line
        indent_next_line: usize = 0,

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0)
                return @as(usize, 0);

            try self.apply_indent();
            return self.write_no_indent(bytes);
        }

        // Change the indent delta without changing the final indentation level
        pub fn set_indent_delta(self: *Self, new_indent_delta: usize) void {
            if (self.indent_delta == new_indent_delta) {
                return;
            } else if (self.indent_delta > new_indent_delta) {
                assert(self.indent_delta % new_indent_delta == 0);
                self.indent_count = self.indent_count * (self.indent_delta / new_indent_delta);
            } else {
                // assert that the current indentation (in spaces) in a multiple of the new delta
                assert((self.indent_count * self.indent_delta) % new_indent_delta == 0);
                self.indent_count = self.indent_count / (new_indent_delta / self.indent_delta);
            }
            self.indent_delta = new_indent_delta;
        }

        fn write_no_indent(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0)
                return @as(usize, 0);

            if (self.disabled_offset == null) try self.underlying_writer.write_all(bytes);
            if (bytes[bytes.len - 1] == '\n')
                self.reset_line();
            return bytes.len;
        }

        pub fn insert_newline(self: *Self) WriteError!void {
            _ = try self.write_no_indent("\n");
        }

        fn reset_line(self: *Self) void {
            self.current_line_empty = true;
            self.indent_next_line = 0;
        }

        /// Insert a newline unless the current line is blank
        pub fn maybe_insert_newline(self: *Self) WriteError!void {
            if (!self.current_line_empty)
                try self.insert_newline();
        }

        /// Push default indentation
        /// Doesn't actually write any indentation.
        /// Just primes the stream to be able to write the correct indentation if it needs to.
        pub fn push_indent(self: *Self) void {
            self.indent_count += 1;
        }

        /// Push an indent that is automatically popped after being applied
        pub fn push_indent_one_shot(self: *Self) void {
            self.indent_one_shot_count += 1;
            self.push_indent();
        }

        /// Turns all one-shot indents into regular indents
        /// Returns number of indents that must now be manually popped
        pub fn lock_one_shot_indent(self: *Self) usize {
            const locked_count = self.indent_one_shot_count;
            self.indent_one_shot_count = 0;
            return locked_count;
        }

        /// Push an indent that should not take effect until the next line
        pub fn push_indent_next_line(self: *Self) void {
            self.indent_next_line += 1;
            self.push_indent();
        }

        pub fn pop_indent(self: *Self) void {
            assert(self.indent_count != 0);
            self.indent_count -= 1;

            if (self.indent_next_line > 0)
                self.indent_next_line -= 1;
        }

        /// Writes ' ' bytes if the current line is empty
        fn apply_indent(self: *Self) WriteError!void {
            const current_indent = self.current_indent();
            if (self.current_line_empty and current_indent > 0) {
                if (self.disabled_offset == null) {
                    try self.underlying_writer.write_byte_ntimes(' ', current_indent);
                }
                self.applied_indent = current_indent;
            }

            self.indent_count -= self.indent_one_shot_count;
            self.indent_one_shot_count = 0;
            self.current_line_empty = false;
        }

        /// Checks to see if the most recent indentation exceeds the currently pushed indents
        pub fn is_line_over_indented(self: *Self) bool {
            if (self.current_line_empty) return false;
            return self.applied_indent > self.current_indent();
        }

        fn current_indent(self: *Self) usize {
            var indent_current: usize = 0;
            if (self.indent_count > 0) {
                const indent_count = self.indent_count - self.indent_next_line;
                indent_current = indent_count * self.indent_delta;
            }
            return indent_current;
        }
    };
}
