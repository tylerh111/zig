//! Represents in-progress parsing, will be converted to an Ast after completion.

pub const Error = error{ParseError} || Allocator.Error;

gpa: Allocator,
source: []const u8,
token_tags: []const Token.Tag,
token_starts: []const Ast.ByteOffset,
tok_i: TokenIndex,
errors: std.ArrayListUnmanaged(AstError),
nodes: Ast.NodeList,
extra_data: std.ArrayListUnmanaged(Node.Index),
scratch: std.ArrayListUnmanaged(Node.Index),

const SmallSpan = union(enum) {
    zero_or_one: Node.Index,
    multi: Node.SubRange,
};

const Members = struct {
    len: usize,
    lhs: Node.Index,
    rhs: Node.Index,
    trailing: bool,

    fn to_span(self: Members, p: *Parse) !Node.SubRange {
        if (self.len <= 2) {
            const nodes = [2]Node.Index{ self.lhs, self.rhs };
            return p.list_to_span(nodes[0..self.len]);
        } else {
            return Node.SubRange{ .start = self.lhs, .end = self.rhs };
        }
    }
};

fn list_to_span(p: *Parse, list: []const Node.Index) !Node.SubRange {
    try p.extra_data.append_slice(p.gpa, list);
    return Node.SubRange{
        .start = @as(Node.Index, @int_cast(p.extra_data.items.len - list.len)),
        .end = @as(Node.Index, @int_cast(p.extra_data.items.len)),
    };
}

fn add_node(p: *Parse, elem: Ast.Node) Allocator.Error!Node.Index {
    const result = @as(Node.Index, @int_cast(p.nodes.len));
    try p.nodes.append(p.gpa, elem);
    return result;
}

fn set_node(p: *Parse, i: usize, elem: Ast.Node) Node.Index {
    p.nodes.set(i, elem);
    return @as(Node.Index, @int_cast(i));
}

fn reserve_node(p: *Parse, tag: Ast.Node.Tag) !usize {
    try p.nodes.resize(p.gpa, p.nodes.len + 1);
    p.nodes.items(.tag)[p.nodes.len - 1] = tag;
    return p.nodes.len - 1;
}

fn unreserve_node(p: *Parse, node_index: usize) void {
    if (p.nodes.len == node_index) {
        p.nodes.resize(p.gpa, p.nodes.len - 1) catch unreachable;
    } else {
        // There is zombie node left in the tree, let's make it as inoffensive as possible
        // (sadly there's no no-op node)
        p.nodes.items(.tag)[node_index] = .unreachable_literal;
        p.nodes.items(.main_token)[node_index] = p.tok_i;
    }
}

fn add_extra(p: *Parse, extra: anytype) Allocator.Error!Node.Index {
    const fields = std.meta.fields(@TypeOf(extra));
    try p.extra_data.ensure_unused_capacity(p.gpa, fields.len);
    const result = @as(u32, @int_cast(p.extra_data.items.len));
    inline for (fields) |field| {
        comptime assert(field.type == Node.Index);
        p.extra_data.append_assume_capacity(@field(extra, field.name));
    }
    return result;
}

fn warn_expected(p: *Parse, expected_token: Token.Tag) error{OutOfMemory}!void {
    @setCold(true);
    try p.warn_msg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn warn(p: *Parse, error_tag: AstError.Tag) error{OutOfMemory}!void {
    @setCold(true);
    try p.warn_msg(.{ .tag = error_tag, .token = p.tok_i });
}

fn warn_msg(p: *Parse, msg: Ast.Error) error{OutOfMemory}!void {
    @setCold(true);
    switch (msg.tag) {
        .expected_semi_after_decl,
        .expected_semi_after_stmt,
        .expected_comma_after_field,
        .expected_comma_after_arg,
        .expected_comma_after_param,
        .expected_comma_after_initializer,
        .expected_comma_after_switch_prong,
        .expected_comma_after_for_operand,
        .expected_comma_after_capture,
        .expected_semi_or_else,
        .expected_semi_or_lbrace,
        .expected_token,
        .expected_block,
        .expected_block_or_assignment,
        .expected_block_or_expr,
        .expected_block_or_field,
        .expected_expr,
        .expected_expr_or_assignment,
        .expected_fn,
        .expected_inlinable,
        .expected_labelable,
        .expected_param_list,
        .expected_prefix_expr,
        .expected_primary_type_expr,
        .expected_pub_item,
        .expected_return_type,
        .expected_suffix_op,
        .expected_type_expr,
        .expected_var_decl,
        .expected_var_decl_or_fn,
        .expected_loop_payload,
        .expected_container,
        => if (msg.token != 0 and !p.tokens_on_same_line(msg.token - 1, msg.token)) {
            var copy = msg;
            copy.token_is_prev = true;
            copy.token -= 1;
            return p.errors.append(p.gpa, copy);
        },
        else => {},
    }
    try p.errors.append(p.gpa, msg);
}

fn fail(p: *Parse, tag: Ast.Error.Tag) error{ ParseError, OutOfMemory } {
    @setCold(true);
    return p.fail_msg(.{ .tag = tag, .token = p.tok_i });
}

fn fail_expected(p: *Parse, expected_token: Token.Tag) error{ ParseError, OutOfMemory } {
    @setCold(true);
    return p.fail_msg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn fail_msg(p: *Parse, msg: Ast.Error) error{ ParseError, OutOfMemory } {
    @setCold(true);
    try p.warn_msg(msg);
    return error.ParseError;
}

/// Root <- skip container_doc_comment? ContainerMembers eof
pub fn parse_root(p: *Parse) !void {
    // Root node must be index 0.
    p.nodes.append_assume_capacity(.{
        .tag = .root,
        .main_token = 0,
        .data = undefined,
    });
    const root_members = try p.parse_container_members();
    const root_decls = try root_members.to_span(p);
    if (p.token_tags[p.tok_i] != .eof) {
        try p.warn_expected(.eof);
    }
    p.nodes.items(.data)[0] = .{
        .lhs = root_decls.start,
        .rhs = root_decls.end,
    };
}

/// Parse in ZON mode. Subset of the language.
/// TODO: set a flag in Parse struct, and honor that flag
/// by emitting compilation errors when non-zon nodes are encountered.
pub fn parse_zon(p: *Parse) !void {
    // We must use index 0 so that 0 can be used as null elsewhere.
    p.nodes.append_assume_capacity(.{
        .tag = .root,
        .main_token = 0,
        .data = undefined,
    });
    const node_index = p.expect_expr() catch |err| switch (err) {
        error.ParseError => {
            assert(p.errors.items.len > 0);
            return;
        },
        else => |e| return e,
    };
    if (p.token_tags[p.tok_i] != .eof) {
        try p.warn_expected(.eof);
    }
    p.nodes.items(.data)[0] = .{
        .lhs = node_index,
        .rhs = undefined,
    };
}

/// ContainerMembers <- ContainerDeclaration* (ContainerField COMMA)* (ContainerField / ContainerDeclaration*)
///
/// ContainerDeclaration <- TestDecl / ComptimeDecl / doc_comment? KEYWORD_pub? Decl
///
/// ComptimeDecl <- KEYWORD_comptime Block
fn parse_container_members(p: *Parse) Allocator.Error!Members {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    var field_state: union(enum) {
        /// No fields have been seen.
        none,
        /// Currently parsing fields.
        seen,
        /// Saw fields and then a declaration after them.
        /// Payload is first token of previous declaration.
        end: Node.Index,
        /// There was a declaration between fields, don't report more errors.
        err,
    } = .none;

    var last_field: TokenIndex = undefined;

    // Skip container doc comments.
    while (p.eat_token(.container_doc_comment)) |_| {}

    var trailing = false;
    while (true) {
        const doc_comment = try p.eat_doc_comments();

        switch (p.token_tags[p.tok_i]) {
            .keyword_test => {
                if (doc_comment) |some| {
                    try p.warn_msg(.{ .tag = .test_doc_comment, .token = some });
                }
                const test_decl_node = try p.expect_test_decl_recoverable();
                if (test_decl_node != 0) {
                    if (field_state == .seen) {
                        field_state = .{ .end = test_decl_node };
                    }
                    try p.scratch.append(p.gpa, test_decl_node);
                }
                trailing = false;
            },
            .keyword_comptime => switch (p.token_tags[p.tok_i + 1]) {
                .l_brace => {
                    if (doc_comment) |some| {
                        try p.warn_msg(.{ .tag = .comptime_doc_comment, .token = some });
                    }
                    const comptime_token = p.next_token();
                    const block = p.parse_block() catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ParseError => blk: {
                            p.find_next_container_member();
                            break :blk null_node;
                        },
                    };
                    if (block != 0) {
                        const comptime_node = try p.add_node(.{
                            .tag = .@"comptime",
                            .main_token = comptime_token,
                            .data = .{
                                .lhs = block,
                                .rhs = undefined,
                            },
                        });
                        if (field_state == .seen) {
                            field_state = .{ .end = comptime_node };
                        }
                        try p.scratch.append(p.gpa, comptime_node);
                    }
                    trailing = false;
                },
                else => {
                    const identifier = p.tok_i;
                    defer last_field = identifier;
                    const container_field = p.expect_container_field() catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ParseError => {
                            p.find_next_container_member();
                            continue;
                        },
                    };
                    switch (field_state) {
                        .none => field_state = .seen,
                        .err, .seen => {},
                        .end => |node| {
                            try p.warn_msg(.{
                                .tag = .decl_between_fields,
                                .token = p.nodes.items(.main_token)[node],
                            });
                            try p.warn_msg(.{
                                .tag = .previous_field,
                                .is_note = true,
                                .token = last_field,
                            });
                            try p.warn_msg(.{
                                .tag = .next_field,
                                .is_note = true,
                                .token = identifier,
                            });
                            // Continue parsing; error will be reported later.
                            field_state = .err;
                        },
                    }
                    try p.scratch.append(p.gpa, container_field);
                    switch (p.token_tags[p.tok_i]) {
                        .comma => {
                            p.tok_i += 1;
                            trailing = true;
                            continue;
                        },
                        .r_brace, .eof => {
                            trailing = false;
                            break;
                        },
                        else => {},
                    }
                    // There is not allowed to be a decl after a field with no comma.
                    // Report error but recover parser.
                    try p.warn(.expected_comma_after_field);
                    p.find_next_container_member();
                },
            },
            .keyword_pub => {
                p.tok_i += 1;
                const top_level_decl = try p.expect_top_level_decl_recoverable();
                if (top_level_decl != 0) {
                    if (field_state == .seen) {
                        field_state = .{ .end = top_level_decl };
                    }
                    try p.scratch.append(p.gpa, top_level_decl);
                }
                trailing = p.token_tags[p.tok_i - 1] == .semicolon;
            },
            .keyword_usingnamespace => {
                const node = try p.expect_using_namespace_recoverable();
                if (node != 0) {
                    if (field_state == .seen) {
                        field_state = .{ .end = node };
                    }
                    try p.scratch.append(p.gpa, node);
                }
                trailing = p.token_tags[p.tok_i - 1] == .semicolon;
            },
            .keyword_const,
            .keyword_var,
            .keyword_threadlocal,
            .keyword_export,
            .keyword_extern,
            .keyword_inline,
            .keyword_noinline,
            .keyword_fn,
            => {
                const top_level_decl = try p.expect_top_level_decl_recoverable();
                if (top_level_decl != 0) {
                    if (field_state == .seen) {
                        field_state = .{ .end = top_level_decl };
                    }
                    try p.scratch.append(p.gpa, top_level_decl);
                }
                trailing = p.token_tags[p.tok_i - 1] == .semicolon;
            },
            .eof, .r_brace => {
                if (doc_comment) |tok| {
                    try p.warn_msg(.{
                        .tag = .unattached_doc_comment,
                        .token = tok,
                    });
                }
                break;
            },
            else => {
                const c_container = p.parse_cstyle_container() catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ParseError => false,
                };
                if (c_container) continue;

                const identifier = p.tok_i;
                defer last_field = identifier;
                const container_field = p.expect_container_field() catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ParseError => {
                        p.find_next_container_member();
                        continue;
                    },
                };
                switch (field_state) {
                    .none => field_state = .seen,
                    .err, .seen => {},
                    .end => |node| {
                        try p.warn_msg(.{
                            .tag = .decl_between_fields,
                            .token = p.nodes.items(.main_token)[node],
                        });
                        try p.warn_msg(.{
                            .tag = .previous_field,
                            .is_note = true,
                            .token = last_field,
                        });
                        try p.warn_msg(.{
                            .tag = .next_field,
                            .is_note = true,
                            .token = identifier,
                        });
                        // Continue parsing; error will be reported later.
                        field_state = .err;
                    },
                }
                try p.scratch.append(p.gpa, container_field);
                switch (p.token_tags[p.tok_i]) {
                    .comma => {
                        p.tok_i += 1;
                        trailing = true;
                        continue;
                    },
                    .r_brace, .eof => {
                        trailing = false;
                        break;
                    },
                    else => {},
                }
                // There is not allowed to be a decl after a field with no comma.
                // Report error but recover parser.
                try p.warn(.expected_comma_after_field);
                if (p.token_tags[p.tok_i] == .semicolon and p.token_tags[identifier] == .identifier) {
                    try p.warn_msg(.{
                        .tag = .var_const_decl,
                        .is_note = true,
                        .token = identifier,
                    });
                }
                p.find_next_container_member();
                continue;
            },
        }
    }

    const items = p.scratch.items[scratch_top..];
    switch (items.len) {
        0 => return Members{
            .len = 0,
            .lhs = 0,
            .rhs = 0,
            .trailing = trailing,
        },
        1 => return Members{
            .len = 1,
            .lhs = items[0],
            .rhs = 0,
            .trailing = trailing,
        },
        2 => return Members{
            .len = 2,
            .lhs = items[0],
            .rhs = items[1],
            .trailing = trailing,
        },
        else => {
            const span = try p.list_to_span(items);
            return Members{
                .len = items.len,
                .lhs = span.start,
                .rhs = span.end,
                .trailing = trailing,
            };
        },
    }
}

/// Attempts to find next container member by searching for certain tokens
fn find_next_container_member(p: *Parse) void {
    var level: u32 = 0;
    while (true) {
        const tok = p.next_token();
        switch (p.token_tags[tok]) {
            // Any of these can start a new top level declaration.
            .keyword_test,
            .keyword_comptime,
            .keyword_pub,
            .keyword_export,
            .keyword_extern,
            .keyword_inline,
            .keyword_noinline,
            .keyword_usingnamespace,
            .keyword_threadlocal,
            .keyword_const,
            .keyword_var,
            .keyword_fn,
            => {
                if (level == 0) {
                    p.tok_i -= 1;
                    return;
                }
            },
            .identifier => {
                if (p.token_tags[tok + 1] == .comma and level == 0) {
                    p.tok_i -= 1;
                    return;
                }
            },
            .comma, .semicolon => {
                // this decl was likely meant to end here
                if (level == 0) {
                    return;
                }
            },
            .l_paren, .l_bracket, .l_brace => level += 1,
            .r_paren, .r_bracket => {
                if (level != 0) level -= 1;
            },
            .r_brace => {
                if (level == 0) {
                    // end of container, exit
                    p.tok_i -= 1;
                    return;
                }
                level -= 1;
            },
            .eof => {
                p.tok_i -= 1;
                return;
            },
            else => {},
        }
    }
}

/// Attempts to find the next statement by searching for a semicolon
fn find_next_stmt(p: *Parse) void {
    var level: u32 = 0;
    while (true) {
        const tok = p.next_token();
        switch (p.token_tags[tok]) {
            .l_brace => level += 1,
            .r_brace => {
                if (level == 0) {
                    p.tok_i -= 1;
                    return;
                }
                level -= 1;
            },
            .semicolon => {
                if (level == 0) {
                    return;
                }
            },
            .eof => {
                p.tok_i -= 1;
                return;
            },
            else => {},
        }
    }
}

/// TestDecl <- KEYWORD_test (STRINGLITERALSINGLE / IDENTIFIER)? Block
fn expect_test_decl(p: *Parse) !Node.Index {
    const test_token = p.assert_token(.keyword_test);
    const name_token = switch (p.token_tags[p.tok_i]) {
        .string_literal, .identifier => p.next_token(),
        else => null,
    };
    const block_node = try p.parse_block();
    if (block_node == 0) return p.fail(.expected_block);
    return p.add_node(.{
        .tag = .test_decl,
        .main_token = test_token,
        .data = .{
            .lhs = name_token orelse 0,
            .rhs = block_node,
        },
    });
}

fn expect_test_decl_recoverable(p: *Parse) error{OutOfMemory}!Node.Index {
    return p.expect_test_decl() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.find_next_container_member();
            return null_node;
        },
    };
}

/// Decl
///     <- (KEYWORD_export / KEYWORD_extern STRINGLITERALSINGLE? / KEYWORD_inline / KEYWORD_noinline)? FnProto (SEMICOLON / Block)
///      / (KEYWORD_export / KEYWORD_extern STRINGLITERALSINGLE?)? KEYWORD_threadlocal? VarDecl
///      / KEYWORD_usingnamespace Expr SEMICOLON
fn expect_top_level_decl(p: *Parse) !Node.Index {
    const extern_export_inline_token = p.next_token();
    var is_extern: bool = false;
    var expect_fn: bool = false;
    var expect_var_or_fn: bool = false;
    switch (p.token_tags[extern_export_inline_token]) {
        .keyword_extern => {
            _ = p.eat_token(.string_literal);
            is_extern = true;
            expect_var_or_fn = true;
        },
        .keyword_export => expect_var_or_fn = true,
        .keyword_inline, .keyword_noinline => expect_fn = true,
        else => p.tok_i -= 1,
    }
    const fn_proto = try p.parse_fn_proto();
    if (fn_proto != 0) {
        switch (p.token_tags[p.tok_i]) {
            .semicolon => {
                p.tok_i += 1;
                return fn_proto;
            },
            .l_brace => {
                if (is_extern) {
                    try p.warn_msg(.{ .tag = .extern_fn_body, .token = extern_export_inline_token });
                    return null_node;
                }
                const fn_decl_index = try p.reserve_node(.fn_decl);
                errdefer p.unreserve_node(fn_decl_index);

                const body_block = try p.parse_block();
                assert(body_block != 0);
                return p.set_node(fn_decl_index, .{
                    .tag = .fn_decl,
                    .main_token = p.nodes.items(.main_token)[fn_proto],
                    .data = .{
                        .lhs = fn_proto,
                        .rhs = body_block,
                    },
                });
            },
            else => {
                // Since parse_block only return error.ParseError on
                // a missing '}' we can assume this function was
                // supposed to end here.
                try p.warn(.expected_semi_or_lbrace);
                return null_node;
            },
        }
    }
    if (expect_fn) {
        try p.warn(.expected_fn);
        return error.ParseError;
    }

    const thread_local_token = p.eat_token(.keyword_threadlocal);
    const var_decl = try p.parse_global_var_decl();
    if (var_decl != 0) {
        return var_decl;
    }
    if (thread_local_token != null) {
        return p.fail(.expected_var_decl);
    }
    if (expect_var_or_fn) {
        return p.fail(.expected_var_decl_or_fn);
    }
    if (p.token_tags[p.tok_i] != .keyword_usingnamespace) {
        return p.fail(.expected_pub_item);
    }
    return p.expect_using_namespace();
}

fn expect_top_level_decl_recoverable(p: *Parse) error{OutOfMemory}!Node.Index {
    return p.expect_top_level_decl() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.find_next_container_member();
            return null_node;
        },
    };
}

fn expect_using_namespace(p: *Parse) !Node.Index {
    const usingnamespace_token = p.assert_token(.keyword_usingnamespace);
    const expr = try p.expect_expr();
    try p.expect_semicolon(.expected_semi_after_decl, false);
    return p.add_node(.{
        .tag = .@"usingnamespace",
        .main_token = usingnamespace_token,
        .data = .{
            .lhs = expr,
            .rhs = undefined,
        },
    });
}

fn expect_using_namespace_recoverable(p: *Parse) error{OutOfMemory}!Node.Index {
    return p.expect_using_namespace() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.find_next_container_member();
            return null_node;
        },
    };
}

/// FnProto <- KEYWORD_fn IDENTIFIER? LPAREN ParamDeclList RPAREN ByteAlign? AddrSpace? LinkSection? CallConv? EXCLAMATIONMARK? TypeExpr
fn parse_fn_proto(p: *Parse) !Node.Index {
    const fn_token = p.eat_token(.keyword_fn) orelse return null_node;

    // We want the fn proto node to be before its children in the array.
    const fn_proto_index = try p.reserve_node(.fn_proto);
    errdefer p.unreserve_node(fn_proto_index);

    _ = p.eat_token(.identifier);
    const params = try p.parse_param_decl_list();
    const align_expr = try p.parse_byte_align();
    const addrspace_expr = try p.parse_addr_space();
    const section_expr = try p.parse_link_section();
    const callconv_expr = try p.parse_callconv();
    _ = p.eat_token(.bang);

    const return_type_expr = try p.parse_type_expr();
    if (return_type_expr == 0) {
        // most likely the user forgot to specify the return type.
        // Mark return type as invalid and try to continue.
        try p.warn(.expected_return_type);
    }

    if (align_expr == 0 and section_expr == 0 and callconv_expr == 0 and addrspace_expr == 0) {
        switch (params) {
            .zero_or_one => |param| return p.set_node(fn_proto_index, .{
                .tag = .fn_proto_simple,
                .main_token = fn_token,
                .data = .{
                    .lhs = param,
                    .rhs = return_type_expr,
                },
            }),
            .multi => |span| {
                return p.set_node(fn_proto_index, .{
                    .tag = .fn_proto_multi,
                    .main_token = fn_token,
                    .data = .{
                        .lhs = try p.add_extra(Node.SubRange{
                            .start = span.start,
                            .end = span.end,
                        }),
                        .rhs = return_type_expr,
                    },
                });
            },
        }
    }
    switch (params) {
        .zero_or_one => |param| return p.set_node(fn_proto_index, .{
            .tag = .fn_proto_one,
            .main_token = fn_token,
            .data = .{
                .lhs = try p.add_extra(Node.FnProtoOne{
                    .param = param,
                    .align_expr = align_expr,
                    .addrspace_expr = addrspace_expr,
                    .section_expr = section_expr,
                    .callconv_expr = callconv_expr,
                }),
                .rhs = return_type_expr,
            },
        }),
        .multi => |span| {
            return p.set_node(fn_proto_index, .{
                .tag = .fn_proto,
                .main_token = fn_token,
                .data = .{
                    .lhs = try p.add_extra(Node.FnProto{
                        .params_start = span.start,
                        .params_end = span.end,
                        .align_expr = align_expr,
                        .addrspace_expr = addrspace_expr,
                        .section_expr = section_expr,
                        .callconv_expr = callconv_expr,
                    }),
                    .rhs = return_type_expr,
                },
            });
        },
    }
}

/// VarDeclProto <- (KEYWORD_const / KEYWORD_var) IDENTIFIER (COLON TypeExpr)? ByteAlign? AddrSpace? LinkSection?
/// Returns a `*_var_decl` node with its rhs (init expression) initialized to 0.
fn parse_var_decl_proto(p: *Parse) !Node.Index {
    const mut_token = p.eat_token(.keyword_const) orelse
        p.eat_token(.keyword_var) orelse
        return null_node;

    _ = try p.expect_token(.identifier);
    const type_node: Node.Index = if (p.eat_token(.colon) == null) 0 else try p.expect_type_expr();
    const align_node = try p.parse_byte_align();
    const addrspace_node = try p.parse_addr_space();
    const section_node = try p.parse_link_section();

    if (section_node == 0 and addrspace_node == 0) {
        if (align_node == 0) {
            return p.add_node(.{
                .tag = .simple_var_decl,
                .main_token = mut_token,
                .data = .{
                    .lhs = type_node,
                    .rhs = 0,
                },
            });
        }

        if (type_node == 0) {
            return p.add_node(.{
                .tag = .aligned_var_decl,
                .main_token = mut_token,
                .data = .{
                    .lhs = align_node,
                    .rhs = 0,
                },
            });
        }

        return p.add_node(.{
            .tag = .local_var_decl,
            .main_token = mut_token,
            .data = .{
                .lhs = try p.add_extra(Node.LocalVarDecl{
                    .type_node = type_node,
                    .align_node = align_node,
                }),
                .rhs = 0,
            },
        });
    } else {
        return p.add_node(.{
            .tag = .global_var_decl,
            .main_token = mut_token,
            .data = .{
                .lhs = try p.add_extra(Node.GlobalVarDecl{
                    .type_node = type_node,
                    .align_node = align_node,
                    .addrspace_node = addrspace_node,
                    .section_node = section_node,
                }),
                .rhs = 0,
            },
        });
    }
}

/// GlobalVarDecl <- VarDeclProto (EQUAL Expr?) SEMICOLON
fn parse_global_var_decl(p: *Parse) !Node.Index {
    const var_decl = try p.parse_var_decl_proto();
    if (var_decl == 0) {
        return null_node;
    }

    const init_node: Node.Index = switch (p.token_tags[p.tok_i]) {
        .equal_equal => blk: {
            try p.warn(.wrong_equal_var_decl);
            p.tok_i += 1;
            break :blk try p.expect_expr();
        },
        .equal => blk: {
            p.tok_i += 1;
            break :blk try p.expect_expr();
        },
        else => 0,
    };

    p.nodes.items(.data)[var_decl].rhs = init_node;

    try p.expect_semicolon(.expected_semi_after_decl, false);
    return var_decl;
}

/// ContainerField <- doc_comment? KEYWORD_comptime? !KEYWORD_fn (IDENTIFIER COLON)? TypeExpr ByteAlign? (EQUAL Expr)?
fn expect_container_field(p: *Parse) !Node.Index {
    _ = p.eat_token(.keyword_comptime);
    const main_token = p.tok_i;
    if (p.token_tags[p.tok_i] == .identifier and p.token_tags[p.tok_i + 1] == .colon) p.tok_i += 2;
    const type_expr = try p.expect_type_expr();
    const align_expr = try p.parse_byte_align();
    const value_expr: Node.Index = if (p.eat_token(.equal) == null) 0 else try p.expect_expr();

    if (align_expr == 0) {
        return p.add_node(.{
            .tag = .container_field_init,
            .main_token = main_token,
            .data = .{
                .lhs = type_expr,
                .rhs = value_expr,
            },
        });
    } else if (value_expr == 0) {
        return p.add_node(.{
            .tag = .container_field_align,
            .main_token = main_token,
            .data = .{
                .lhs = type_expr,
                .rhs = align_expr,
            },
        });
    } else {
        return p.add_node(.{
            .tag = .container_field,
            .main_token = main_token,
            .data = .{
                .lhs = type_expr,
                .rhs = try p.add_extra(Node.ContainerField{
                    .align_expr = align_expr,
                    .value_expr = value_expr,
                }),
            },
        });
    }
}

/// Statement
///     <- KEYWORD_comptime ComptimeStatement
///      / KEYWORD_nosuspend BlockExprStatement
///      / KEYWORD_suspend BlockExprStatement
///      / KEYWORD_defer BlockExprStatement
///      / KEYWORD_errdefer Payload? BlockExprStatement
///      / IfStatement
///      / LabeledStatement
///      / SwitchExpr
///      / VarDeclExprStatement
fn expect_statement(p: *Parse, allow_defer_var: bool) Error!Node.Index {
    if (p.eat_token(.keyword_comptime)) |comptime_token| {
        const block_expr = try p.parse_block_expr();
        if (block_expr != 0) {
            return p.add_node(.{
                .tag = .@"comptime",
                .main_token = comptime_token,
                .data = .{
                    .lhs = block_expr,
                    .rhs = undefined,
                },
            });
        }

        if (allow_defer_var) {
            return p.expect_var_decl_expr_statement(comptime_token);
        } else {
            const assign = try p.expect_assign_expr();
            try p.expect_semicolon(.expected_semi_after_stmt, true);
            return p.add_node(.{
                .tag = .@"comptime",
                .main_token = comptime_token,
                .data = .{
                    .lhs = assign,
                    .rhs = undefined,
                },
            });
        }
    }

    switch (p.token_tags[p.tok_i]) {
        .keyword_nosuspend => {
            return p.add_node(.{
                .tag = .@"nosuspend",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.expect_block_expr_statement(),
                    .rhs = undefined,
                },
            });
        },
        .keyword_suspend => {
            const token = p.next_token();
            const block_expr = try p.expect_block_expr_statement();
            return p.add_node(.{
                .tag = .@"suspend",
                .main_token = token,
                .data = .{
                    .lhs = block_expr,
                    .rhs = undefined,
                },
            });
        },
        .keyword_defer => if (allow_defer_var) return p.add_node(.{
            .tag = .@"defer",
            .main_token = p.next_token(),
            .data = .{
                .lhs = undefined,
                .rhs = try p.expect_block_expr_statement(),
            },
        }),
        .keyword_errdefer => if (allow_defer_var) return p.add_node(.{
            .tag = .@"errdefer",
            .main_token = p.next_token(),
            .data = .{
                .lhs = try p.parse_payload(),
                .rhs = try p.expect_block_expr_statement(),
            },
        }),
        .keyword_switch => return p.expect_switch_expr(),
        .keyword_if => return p.expect_if_statement(),
        .keyword_enum, .keyword_struct, .keyword_union => {
            const identifier = p.tok_i + 1;
            if (try p.parse_cstyle_container()) {
                // Return something so that `expect_statement` is happy.
                return p.add_node(.{
                    .tag = .identifier,
                    .main_token = identifier,
                    .data = .{
                        .lhs = undefined,
                        .rhs = undefined,
                    },
                });
            }
        },
        else => {},
    }

    const labeled_statement = try p.parse_labeled_statement();
    if (labeled_statement != 0) return labeled_statement;

    if (allow_defer_var) {
        return p.expect_var_decl_expr_statement(null);
    } else {
        const assign = try p.expect_assign_expr();
        try p.expect_semicolon(.expected_semi_after_stmt, true);
        return assign;
    }
}

/// ComptimeStatement
///     <- BlockExpr
///      / VarDeclExprStatement
fn expect_comptime_statement(p: *Parse, comptime_token: TokenIndex) !Node.Index {
    const block_expr = try p.parse_block_expr();
    if (block_expr != 0) {
        return p.add_node(.{
            .tag = .@"comptime",
            .main_token = comptime_token,
            .data = .{ .lhs = block_expr, .rhs = undefined },
        });
    }
    return p.expect_var_decl_expr_statement(comptime_token);
}

/// VarDeclExprStatement
///    <- VarDeclProto (COMMA (VarDeclProto / Expr))* EQUAL Expr SEMICOLON
///     / Expr (AssignOp Expr / (COMMA (VarDeclProto / Expr))+ EQUAL Expr)? SEMICOLON
fn expect_var_decl_expr_statement(p: *Parse, comptime_token: ?TokenIndex) !Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    while (true) {
        const var_decl_proto = try p.parse_var_decl_proto();
        if (var_decl_proto != 0) {
            try p.scratch.append(p.gpa, var_decl_proto);
        } else {
            const expr = try p.parse_expr();
            if (expr == 0) {
                if (p.scratch.items.len == scratch_top) {
                    // We parsed nothing
                    return p.fail(.expected_statement);
                } else {
                    // We've had at least one LHS, but had a bad comma
                    return p.fail(.expected_expr_or_var_decl);
                }
            }
            try p.scratch.append(p.gpa, expr);
        }
        _ = p.eat_token(.comma) orelse break;
    }

    const lhs_count = p.scratch.items.len - scratch_top;
    assert(lhs_count > 0);

    const equal_token = p.eat_token(.equal) orelse eql: {
        if (lhs_count > 1) {
            // Definitely a destructure, so allow recovering from ==
            if (p.eat_token(.equal_equal)) |tok| {
                try p.warn_msg(.{ .tag = .wrong_equal_var_decl, .token = tok });
                break :eql tok;
            }
            return p.fail_expected(.equal);
        }
        const lhs = p.scratch.items[scratch_top];
        switch (p.nodes.items(.tag)[lhs]) {
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                // Definitely a var decl, so allow recovering from ==
                if (p.eat_token(.equal_equal)) |tok| {
                    try p.warn_msg(.{ .tag = .wrong_equal_var_decl, .token = tok });
                    break :eql tok;
                }
                return p.fail_expected(.equal);
            },
            else => {},
        }

        const expr = try p.finish_assign_expr(lhs);
        try p.expect_semicolon(.expected_semi_after_stmt, true);
        if (comptime_token) |t| {
            return p.add_node(.{
                .tag = .@"comptime",
                .main_token = t,
                .data = .{
                    .lhs = expr,
                    .rhs = undefined,
                },
            });
        } else {
            return expr;
        }
    };

    const rhs = try p.expect_expr();
    try p.expect_semicolon(.expected_semi_after_stmt, true);

    if (lhs_count == 1) {
        const lhs = p.scratch.items[scratch_top];
        switch (p.nodes.items(.tag)[lhs]) {
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                p.nodes.items(.data)[lhs].rhs = rhs;
                // Don't need to wrap in comptime
                return lhs;
            },
            else => {},
        }
        const expr = try p.add_node(.{
            .tag = .assign,
            .main_token = equal_token,
            .data = .{ .lhs = lhs, .rhs = rhs },
        });
        if (comptime_token) |t| {
            return p.add_node(.{
                .tag = .@"comptime",
                .main_token = t,
                .data = .{
                    .lhs = expr,
                    .rhs = undefined,
                },
            });
        } else {
            return expr;
        }
    }

    // An actual destructure! No need for any `comptime` wrapper here.

    const extra_start = p.extra_data.items.len;
    try p.extra_data.ensure_unused_capacity(p.gpa, lhs_count + 1);
    p.extra_data.append_assume_capacity(@int_cast(lhs_count));
    p.extra_data.append_slice_assume_capacity(p.scratch.items[scratch_top..]);

    return p.add_node(.{
        .tag = .assign_destructure,
        .main_token = equal_token,
        .data = .{
            .lhs = @int_cast(extra_start),
            .rhs = rhs,
        },
    });
}

/// If a parse error occurs, reports an error, but then finds the next statement
/// and returns that one instead. If a parse error occurs but there is no following
/// statement, returns 0.
fn expect_statement_recoverable(p: *Parse) Error!Node.Index {
    while (true) {
        return p.expect_statement(true) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseError => {
                p.find_next_stmt(); // Try to skip to the next statement.
                switch (p.token_tags[p.tok_i]) {
                    .r_brace => return null_node,
                    .eof => return error.ParseError,
                    else => continue,
                }
            },
        };
    }
}

/// IfStatement
///     <- IfPrefix BlockExpr ( KEYWORD_else Payload? Statement )?
///      / IfPrefix AssignExpr ( SEMICOLON / KEYWORD_else Payload? Statement )
fn expect_if_statement(p: *Parse) !Node.Index {
    const if_token = p.assert_token(.keyword_if);
    _ = try p.expect_token(.l_paren);
    const condition = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.parse_ptr_payload();

    // TODO propose to change the syntax so that semicolons are always required
    // inside if statements, even if there is an `else`.
    var else_required = false;
    const then_expr = blk: {
        const block_expr = try p.parse_block_expr();
        if (block_expr != 0) break :blk block_expr;
        const assign_expr = try p.parse_assign_expr();
        if (assign_expr == 0) {
            return p.fail(.expected_block_or_assignment);
        }
        if (p.eat_token(.semicolon)) |_| {
            return p.add_node(.{
                .tag = .if_simple,
                .main_token = if_token,
                .data = .{
                    .lhs = condition,
                    .rhs = assign_expr,
                },
            });
        }
        else_required = true;
        break :blk assign_expr;
    };
    _ = p.eat_token(.keyword_else) orelse {
        if (else_required) {
            try p.warn(.expected_semi_or_else);
        }
        return p.add_node(.{
            .tag = .if_simple,
            .main_token = if_token,
            .data = .{
                .lhs = condition,
                .rhs = then_expr,
            },
        });
    };
    _ = try p.parse_payload();
    const else_expr = try p.expect_statement(false);
    return p.add_node(.{
        .tag = .@"if",
        .main_token = if_token,
        .data = .{
            .lhs = condition,
            .rhs = try p.add_extra(Node.If{
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        },
    });
}

/// LabeledStatement <- BlockLabel? (Block / LoopStatement)
fn parse_labeled_statement(p: *Parse) !Node.Index {
    const label_token = p.parse_block_label();
    const block = try p.parse_block();
    if (block != 0) return block;

    const loop_stmt = try p.parse_loop_statement();
    if (loop_stmt != 0) return loop_stmt;

    if (label_token != 0) {
        const after_colon = p.tok_i;
        const node = try p.parse_type_expr();
        if (node != 0) {
            const a = try p.parse_byte_align();
            const b = try p.parse_addr_space();
            const c = try p.parse_link_section();
            const d = if (p.eat_token(.equal) == null) 0 else try p.expect_expr();
            if (a != 0 or b != 0 or c != 0 or d != 0) {
                return p.fail_msg(.{ .tag = .expected_var_const, .token = label_token });
            }
        }
        return p.fail_msg(.{ .tag = .expected_labelable, .token = after_colon });
    }

    return null_node;
}

/// LoopStatement <- KEYWORD_inline? (ForStatement / WhileStatement)
fn parse_loop_statement(p: *Parse) !Node.Index {
    const inline_token = p.eat_token(.keyword_inline);

    const for_statement = try p.parse_for_statement();
    if (for_statement != 0) return for_statement;

    const while_statement = try p.parse_while_statement();
    if (while_statement != 0) return while_statement;

    if (inline_token == null) return null_node;

    // If we've seen "inline", there should have been a "for" or "while"
    return p.fail(.expected_inlinable);
}

/// ForStatement
///     <- ForPrefix BlockExpr ( KEYWORD_else Statement )?
///      / ForPrefix AssignExpr ( SEMICOLON / KEYWORD_else Statement )
fn parse_for_statement(p: *Parse) !Node.Index {
    const for_token = p.eat_token(.keyword_for) orelse return null_node;

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    const inputs = try p.for_prefix();

    var else_required = false;
    var seen_semicolon = false;
    const then_expr = blk: {
        const block_expr = try p.parse_block_expr();
        if (block_expr != 0) break :blk block_expr;
        const assign_expr = try p.parse_assign_expr();
        if (assign_expr == 0) {
            return p.fail(.expected_block_or_assignment);
        }
        if (p.eat_token(.semicolon)) |_| {
            seen_semicolon = true;
            break :blk assign_expr;
        }
        else_required = true;
        break :blk assign_expr;
    };
    var has_else = false;
    if (!seen_semicolon and p.eat_token(.keyword_else) != null) {
        try p.scratch.append(p.gpa, then_expr);
        const else_stmt = try p.expect_statement(false);
        try p.scratch.append(p.gpa, else_stmt);
        has_else = true;
    } else if (inputs == 1) {
        if (else_required) try p.warn(.expected_semi_or_else);
        return p.add_node(.{
            .tag = .for_simple,
            .main_token = for_token,
            .data = .{
                .lhs = p.scratch.items[scratch_top],
                .rhs = then_expr,
            },
        });
    } else {
        if (else_required) try p.warn(.expected_semi_or_else);
        try p.scratch.append(p.gpa, then_expr);
    }
    return p.add_node(.{
        .tag = .@"for",
        .main_token = for_token,
        .data = .{
            .lhs = (try p.list_to_span(p.scratch.items[scratch_top..])).start,
            .rhs = @as(u32, @bit_cast(Node.For{
                .inputs = @as(u31, @int_cast(inputs)),
                .has_else = has_else,
            })),
        },
    });
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileStatement
///     <- WhilePrefix BlockExpr ( KEYWORD_else Payload? Statement )?
///      / WhilePrefix AssignExpr ( SEMICOLON / KEYWORD_else Payload? Statement )
fn parse_while_statement(p: *Parse) !Node.Index {
    const while_token = p.eat_token(.keyword_while) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const condition = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.parse_ptr_payload();
    const cont_expr = try p.parse_while_continue_expr();

    // TODO propose to change the syntax so that semicolons are always required
    // inside while statements, even if there is an `else`.
    var else_required = false;
    const then_expr = blk: {
        const block_expr = try p.parse_block_expr();
        if (block_expr != 0) break :blk block_expr;
        const assign_expr = try p.parse_assign_expr();
        if (assign_expr == 0) {
            return p.fail(.expected_block_or_assignment);
        }
        if (p.eat_token(.semicolon)) |_| {
            if (cont_expr == 0) {
                return p.add_node(.{
                    .tag = .while_simple,
                    .main_token = while_token,
                    .data = .{
                        .lhs = condition,
                        .rhs = assign_expr,
                    },
                });
            } else {
                return p.add_node(.{
                    .tag = .while_cont,
                    .main_token = while_token,
                    .data = .{
                        .lhs = condition,
                        .rhs = try p.add_extra(Node.WhileCont{
                            .cont_expr = cont_expr,
                            .then_expr = assign_expr,
                        }),
                    },
                });
            }
        }
        else_required = true;
        break :blk assign_expr;
    };
    _ = p.eat_token(.keyword_else) orelse {
        if (else_required) {
            try p.warn(.expected_semi_or_else);
        }
        if (cont_expr == 0) {
            return p.add_node(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = then_expr,
                },
            });
        } else {
            return p.add_node(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = try p.add_extra(Node.WhileCont{
                        .cont_expr = cont_expr,
                        .then_expr = then_expr,
                    }),
                },
            });
        }
    };
    _ = try p.parse_payload();
    const else_expr = try p.expect_statement(false);
    return p.add_node(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{
            .lhs = condition,
            .rhs = try p.add_extra(Node.While{
                .cont_expr = cont_expr,
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        },
    });
}

/// BlockExprStatement
///     <- BlockExpr
///      / AssignExpr SEMICOLON
fn parse_block_expr_statement(p: *Parse) !Node.Index {
    const block_expr = try p.parse_block_expr();
    if (block_expr != 0) {
        return block_expr;
    }
    const assign_expr = try p.parse_assign_expr();
    if (assign_expr != 0) {
        try p.expect_semicolon(.expected_semi_after_stmt, true);
        return assign_expr;
    }
    return null_node;
}

fn expect_block_expr_statement(p: *Parse) !Node.Index {
    const node = try p.parse_block_expr_statement();
    if (node == 0) {
        return p.fail(.expected_block_or_expr);
    }
    return node;
}

/// BlockExpr <- BlockLabel? Block
fn parse_block_expr(p: *Parse) Error!Node.Index {
    switch (p.token_tags[p.tok_i]) {
        .identifier => {
            if (p.token_tags[p.tok_i + 1] == .colon and
                p.token_tags[p.tok_i + 2] == .l_brace)
            {
                p.tok_i += 2;
                return p.parse_block();
            } else {
                return null_node;
            }
        },
        .l_brace => return p.parse_block(),
        else => return null_node,
    }
}

/// AssignExpr <- Expr (AssignOp Expr / (COMMA Expr)+ EQUAL Expr)?
///
/// AssignOp
///     <- ASTERISKEQUAL
///      / ASTERISKPIPEEQUAL
///      / SLASHEQUAL
///      / PERCENTEQUAL
///      / PLUSEQUAL
///      / PLUSPIPEEQUAL
///      / MINUSEQUAL
///      / MINUSPIPEEQUAL
///      / LARROW2EQUAL
///      / LARROW2PIPEEQUAL
///      / RARROW2EQUAL
///      / AMPERSANDEQUAL
///      / CARETEQUAL
///      / PIPEEQUAL
///      / ASTERISKPERCENTEQUAL
///      / PLUSPERCENTEQUAL
///      / MINUSPERCENTEQUAL
///      / EQUAL
fn parse_assign_expr(p: *Parse) !Node.Index {
    const expr = try p.parse_expr();
    if (expr == 0) return null_node;
    return p.finish_assign_expr(expr);
}

/// SingleAssignExpr <- Expr (AssignOp Expr)?
fn parse_single_assign_expr(p: *Parse) !Node.Index {
    const lhs = try p.parse_expr();
    if (lhs == 0) return null_node;
    const tag = assign_op_node(p.token_tags[p.tok_i]) orelse return lhs;
    return p.add_node(.{
        .tag = tag,
        .main_token = p.next_token(),
        .data = .{
            .lhs = lhs,
            .rhs = try p.expect_expr(),
        },
    });
}

fn finish_assign_expr(p: *Parse, lhs: Node.Index) !Node.Index {
    const tok = p.token_tags[p.tok_i];
    if (tok == .comma) return p.finish_assign_destructure_expr(lhs);
    const tag = assign_op_node(tok) orelse return lhs;
    return p.add_node(.{
        .tag = tag,
        .main_token = p.next_token(),
        .data = .{
            .lhs = lhs,
            .rhs = try p.expect_expr(),
        },
    });
}

fn assign_op_node(tok: Token.Tag) ?Node.Tag {
    return switch (tok) {
        .asterisk_equal => .assign_mul,
        .slash_equal => .assign_div,
        .percent_equal => .assign_mod,
        .plus_equal => .assign_add,
        .minus_equal => .assign_sub,
        .angle_bracket_angle_bracket_left_equal => .assign_shl,
        .angle_bracket_angle_bracket_left_pipe_equal => .assign_shl_sat,
        .angle_bracket_angle_bracket_right_equal => .assign_shr,
        .ampersand_equal => .assign_bit_and,
        .caret_equal => .assign_bit_xor,
        .pipe_equal => .assign_bit_or,
        .asterisk_percent_equal => .assign_mul_wrap,
        .plus_percent_equal => .assign_add_wrap,
        .minus_percent_equal => .assign_sub_wrap,
        .asterisk_pipe_equal => .assign_mul_sat,
        .plus_pipe_equal => .assign_add_sat,
        .minus_pipe_equal => .assign_sub_sat,
        .equal => .assign,
        else => null,
    };
}

fn finish_assign_destructure_expr(p: *Parse, first_lhs: Node.Index) !Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    try p.scratch.append(p.gpa, first_lhs);

    while (p.eat_token(.comma)) |_| {
        const expr = try p.expect_expr();
        try p.scratch.append(p.gpa, expr);
    }

    const equal_token = try p.expect_token(.equal);

    const rhs = try p.expect_expr();

    const lhs_count = p.scratch.items.len - scratch_top;
    assert(lhs_count > 1); // we already had first_lhs, and must have at least one more lvalue

    const extra_start = p.extra_data.items.len;
    try p.extra_data.ensure_unused_capacity(p.gpa, lhs_count + 1);
    p.extra_data.append_assume_capacity(@int_cast(lhs_count));
    p.extra_data.append_slice_assume_capacity(p.scratch.items[scratch_top..]);

    return p.add_node(.{
        .tag = .assign_destructure,
        .main_token = equal_token,
        .data = .{
            .lhs = @int_cast(extra_start),
            .rhs = rhs,
        },
    });
}

fn expect_single_assign_expr(p: *Parse) !Node.Index {
    const expr = try p.parse_single_assign_expr();
    if (expr == 0) {
        return p.fail(.expected_expr_or_assignment);
    }
    return expr;
}

fn expect_assign_expr(p: *Parse) !Node.Index {
    const expr = try p.parse_assign_expr();
    if (expr == 0) {
        return p.fail(.expected_expr_or_assignment);
    }
    return expr;
}

fn parse_expr(p: *Parse) Error!Node.Index {
    return p.parse_expr_precedence(0);
}

fn expect_expr(p: *Parse) Error!Node.Index {
    const node = try p.parse_expr();
    if (node == 0) {
        return p.fail(.expected_expr);
    } else {
        return node;
    }
}

const Assoc = enum {
    left,
    none,
};

const OperInfo = struct {
    prec: i8,
    tag: Node.Tag,
    assoc: Assoc = Assoc.left,
};

// A table of binary operator information. Higher precedence numbers are
// stickier. All operators at the same precedence level should have the same
// associativity.
const operTable = std.enums.direct_enum_array_default(Token.Tag, OperInfo, .{ .prec = -1, .tag = Node.Tag.root }, 0, .{
    .keyword_or = .{ .prec = 10, .tag = .bool_or },

    .keyword_and = .{ .prec = 20, .tag = .bool_and },

    .equal_equal = .{ .prec = 30, .tag = .equal_equal, .assoc = Assoc.none },
    .bang_equal = .{ .prec = 30, .tag = .bang_equal, .assoc = Assoc.none },
    .angle_bracket_left = .{ .prec = 30, .tag = .less_than, .assoc = Assoc.none },
    .angle_bracket_right = .{ .prec = 30, .tag = .greater_than, .assoc = Assoc.none },
    .angle_bracket_left_equal = .{ .prec = 30, .tag = .less_or_equal, .assoc = Assoc.none },
    .angle_bracket_right_equal = .{ .prec = 30, .tag = .greater_or_equal, .assoc = Assoc.none },

    .ampersand = .{ .prec = 40, .tag = .bit_and },
    .caret = .{ .prec = 40, .tag = .bit_xor },
    .pipe = .{ .prec = 40, .tag = .bit_or },
    .keyword_orelse = .{ .prec = 40, .tag = .@"orelse" },
    .keyword_catch = .{ .prec = 40, .tag = .@"catch" },

    .angle_bracket_angle_bracket_left = .{ .prec = 50, .tag = .shl },
    .angle_bracket_angle_bracket_left_pipe = .{ .prec = 50, .tag = .shl_sat },
    .angle_bracket_angle_bracket_right = .{ .prec = 50, .tag = .shr },

    .plus = .{ .prec = 60, .tag = .add },
    .minus = .{ .prec = 60, .tag = .sub },
    .plus_plus = .{ .prec = 60, .tag = .array_cat },
    .plus_percent = .{ .prec = 60, .tag = .add_wrap },
    .minus_percent = .{ .prec = 60, .tag = .sub_wrap },
    .plus_pipe = .{ .prec = 60, .tag = .add_sat },
    .minus_pipe = .{ .prec = 60, .tag = .sub_sat },

    .pipe_pipe = .{ .prec = 70, .tag = .merge_error_sets },
    .asterisk = .{ .prec = 70, .tag = .mul },
    .slash = .{ .prec = 70, .tag = .div },
    .percent = .{ .prec = 70, .tag = .mod },
    .asterisk_asterisk = .{ .prec = 70, .tag = .array_mult },
    .asterisk_percent = .{ .prec = 70, .tag = .mul_wrap },
    .asterisk_pipe = .{ .prec = 70, .tag = .mul_sat },
});

fn parse_expr_precedence(p: *Parse, min_prec: i32) Error!Node.Index {
    assert(min_prec >= 0);
    var node = try p.parse_prefix_expr();
    if (node == 0) {
        return null_node;
    }

    var banned_prec: i8 = -1;

    while (true) {
        const tok_tag = p.token_tags[p.tok_i];
        const info = operTable[@as(usize, @int_cast(@int_from_enum(tok_tag)))];
        if (info.prec < min_prec) {
            break;
        }
        if (info.prec == banned_prec) {
            return p.fail(.chained_comparison_operators);
        }

        const oper_token = p.next_token();
        // Special-case handling for "catch"
        if (tok_tag == .keyword_catch) {
            _ = try p.parse_payload();
        }
        const rhs = try p.parse_expr_precedence(info.prec + 1);
        if (rhs == 0) {
            try p.warn(.expected_expr);
            return node;
        }

        {
            const tok_len = tok_tag.lexeme().?.len;
            const char_before = p.source[p.token_starts[oper_token] - 1];
            const char_after = p.source[p.token_starts[oper_token] + tok_len];
            if (tok_tag == .ampersand and char_after == '&') {
                // without types we don't know if '&&' was intended as 'bitwise_and address_of', or a c-style logical_and
                // The best the parser can do is recommend changing it to 'and' or ' & &'
                try p.warn_msg(.{ .tag = .invalid_ampersand_ampersand, .token = oper_token });
            } else if (std.ascii.is_whitespace(char_before) != std.ascii.is_whitespace(char_after)) {
                try p.warn_msg(.{ .tag = .mismatched_binary_op_whitespace, .token = oper_token });
            }
        }

        node = try p.add_node(.{
            .tag = info.tag,
            .main_token = oper_token,
            .data = .{
                .lhs = node,
                .rhs = rhs,
            },
        });

        if (info.assoc == Assoc.none) {
            banned_prec = info.prec;
        }
    }

    return node;
}

/// PrefixExpr <- PrefixOp* PrimaryExpr
///
/// PrefixOp
///     <- EXCLAMATIONMARK
///      / MINUS
///      / TILDE
///      / MINUSPERCENT
///      / AMPERSAND
///      / KEYWORD_try
///      / KEYWORD_await
fn parse_prefix_expr(p: *Parse) Error!Node.Index {
    const tag: Node.Tag = switch (p.token_tags[p.tok_i]) {
        .bang => .bool_not,
        .minus => .negation,
        .tilde => .bit_not,
        .minus_percent => .negation_wrap,
        .ampersand => .address_of,
        .keyword_try => .@"try",
        .keyword_await => .@"await",
        else => return p.parse_primary_expr(),
    };
    return p.add_node(.{
        .tag = tag,
        .main_token = p.next_token(),
        .data = .{
            .lhs = try p.expect_prefix_expr(),
            .rhs = undefined,
        },
    });
}

fn expect_prefix_expr(p: *Parse) Error!Node.Index {
    const node = try p.parse_prefix_expr();
    if (node == 0) {
        return p.fail(.expected_prefix_expr);
    }
    return node;
}

/// TypeExpr <- PrefixTypeOp* ErrorUnionExpr
///
/// PrefixTypeOp
///     <- QUESTIONMARK
///      / KEYWORD_anyframe MINUSRARROW
///      / SliceTypeStart (ByteAlign / AddrSpace / KEYWORD_const / KEYWORD_volatile / KEYWORD_allowzero)*
///      / PtrTypeStart (AddrSpace / KEYWORD_align LPAREN Expr (COLON Expr COLON Expr)? RPAREN / KEYWORD_const / KEYWORD_volatile / KEYWORD_allowzero)*
///      / ArrayTypeStart
///
/// SliceTypeStart <- LBRACKET (COLON Expr)? RBRACKET
///
/// PtrTypeStart
///     <- ASTERISK
///      / ASTERISK2
///      / LBRACKET ASTERISK (LETTERC / COLON Expr)? RBRACKET
///
/// ArrayTypeStart <- LBRACKET Expr (COLON Expr)? RBRACKET
fn parse_type_expr(p: *Parse) Error!Node.Index {
    switch (p.token_tags[p.tok_i]) {
        .question_mark => return p.add_node(.{
            .tag = .optional_type,
            .main_token = p.next_token(),
            .data = .{
                .lhs = try p.expect_type_expr(),
                .rhs = undefined,
            },
        }),
        .keyword_anyframe => switch (p.token_tags[p.tok_i + 1]) {
            .arrow => return p.add_node(.{
                .tag = .anyframe_type,
                .main_token = p.next_token(),
                .data = .{
                    .lhs = p.next_token(),
                    .rhs = try p.expect_type_expr(),
                },
            }),
            else => return p.parse_error_union_expr(),
        },
        .asterisk => {
            const asterisk = p.next_token();
            const mods = try p.parse_ptr_modifiers();
            const elem_type = try p.expect_type_expr();
            if (mods.bit_range_start != 0) {
                return p.add_node(.{
                    .tag = .ptr_type_bit_range,
                    .main_token = asterisk,
                    .data = .{
                        .lhs = try p.add_extra(Node.PtrTypeBitRange{
                            .sentinel = 0,
                            .align_node = mods.align_node,
                            .addrspace_node = mods.addrspace_node,
                            .bit_range_start = mods.bit_range_start,
                            .bit_range_end = mods.bit_range_end,
                        }),
                        .rhs = elem_type,
                    },
                });
            } else if (mods.addrspace_node != 0) {
                return p.add_node(.{
                    .tag = .ptr_type,
                    .main_token = asterisk,
                    .data = .{
                        .lhs = try p.add_extra(Node.PtrType{
                            .sentinel = 0,
                            .align_node = mods.align_node,
                            .addrspace_node = mods.addrspace_node,
                        }),
                        .rhs = elem_type,
                    },
                });
            } else {
                return p.add_node(.{
                    .tag = .ptr_type_aligned,
                    .main_token = asterisk,
                    .data = .{
                        .lhs = mods.align_node,
                        .rhs = elem_type,
                    },
                });
            }
        },
        .asterisk_asterisk => {
            const asterisk = p.next_token();
            const mods = try p.parse_ptr_modifiers();
            const elem_type = try p.expect_type_expr();
            const inner: Node.Index = inner: {
                if (mods.bit_range_start != 0) {
                    break :inner try p.add_node(.{
                        .tag = .ptr_type_bit_range,
                        .main_token = asterisk,
                        .data = .{
                            .lhs = try p.add_extra(Node.PtrTypeBitRange{
                                .sentinel = 0,
                                .align_node = mods.align_node,
                                .addrspace_node = mods.addrspace_node,
                                .bit_range_start = mods.bit_range_start,
                                .bit_range_end = mods.bit_range_end,
                            }),
                            .rhs = elem_type,
                        },
                    });
                } else if (mods.addrspace_node != 0) {
                    break :inner try p.add_node(.{
                        .tag = .ptr_type,
                        .main_token = asterisk,
                        .data = .{
                            .lhs = try p.add_extra(Node.PtrType{
                                .sentinel = 0,
                                .align_node = mods.align_node,
                                .addrspace_node = mods.addrspace_node,
                            }),
                            .rhs = elem_type,
                        },
                    });
                } else {
                    break :inner try p.add_node(.{
                        .tag = .ptr_type_aligned,
                        .main_token = asterisk,
                        .data = .{
                            .lhs = mods.align_node,
                            .rhs = elem_type,
                        },
                    });
                }
            };
            return p.add_node(.{
                .tag = .ptr_type_aligned,
                .main_token = asterisk,
                .data = .{
                    .lhs = 0,
                    .rhs = inner,
                },
            });
        },
        .l_bracket => switch (p.token_tags[p.tok_i + 1]) {
            .asterisk => {
                _ = p.next_token();
                const asterisk = p.next_token();
                var sentinel: Node.Index = 0;
                if (p.eat_token(.identifier)) |ident| {
                    const ident_slice = p.source[p.token_starts[ident]..p.token_starts[ident + 1]];
                    if (!std.mem.eql(u8, std.mem.trim_right(u8, ident_slice, &std.ascii.whitespace), "c")) {
                        p.tok_i -= 1;
                    }
                } else if (p.eat_token(.colon)) |_| {
                    sentinel = try p.expect_expr();
                }
                _ = try p.expect_token(.r_bracket);
                const mods = try p.parse_ptr_modifiers();
                const elem_type = try p.expect_type_expr();
                if (mods.bit_range_start == 0) {
                    if (sentinel == 0 and mods.addrspace_node == 0) {
                        return p.add_node(.{
                            .tag = .ptr_type_aligned,
                            .main_token = asterisk,
                            .data = .{
                                .lhs = mods.align_node,
                                .rhs = elem_type,
                            },
                        });
                    } else if (mods.align_node == 0 and mods.addrspace_node == 0) {
                        return p.add_node(.{
                            .tag = .ptr_type_sentinel,
                            .main_token = asterisk,
                            .data = .{
                                .lhs = sentinel,
                                .rhs = elem_type,
                            },
                        });
                    } else {
                        return p.add_node(.{
                            .tag = .ptr_type,
                            .main_token = asterisk,
                            .data = .{
                                .lhs = try p.add_extra(Node.PtrType{
                                    .sentinel = sentinel,
                                    .align_node = mods.align_node,
                                    .addrspace_node = mods.addrspace_node,
                                }),
                                .rhs = elem_type,
                            },
                        });
                    }
                } else {
                    return p.add_node(.{
                        .tag = .ptr_type_bit_range,
                        .main_token = asterisk,
                        .data = .{
                            .lhs = try p.add_extra(Node.PtrTypeBitRange{
                                .sentinel = sentinel,
                                .align_node = mods.align_node,
                                .addrspace_node = mods.addrspace_node,
                                .bit_range_start = mods.bit_range_start,
                                .bit_range_end = mods.bit_range_end,
                            }),
                            .rhs = elem_type,
                        },
                    });
                }
            },
            else => {
                const lbracket = p.next_token();
                const len_expr = try p.parse_expr();
                const sentinel: Node.Index = if (p.eat_token(.colon)) |_|
                    try p.expect_expr()
                else
                    0;
                _ = try p.expect_token(.r_bracket);
                if (len_expr == 0) {
                    const mods = try p.parse_ptr_modifiers();
                    const elem_type = try p.expect_type_expr();
                    if (mods.bit_range_start != 0) {
                        try p.warn_msg(.{
                            .tag = .invalid_bit_range,
                            .token = p.nodes.items(.main_token)[mods.bit_range_start],
                        });
                    }
                    if (sentinel == 0 and mods.addrspace_node == 0) {
                        return p.add_node(.{
                            .tag = .ptr_type_aligned,
                            .main_token = lbracket,
                            .data = .{
                                .lhs = mods.align_node,
                                .rhs = elem_type,
                            },
                        });
                    } else if (mods.align_node == 0 and mods.addrspace_node == 0) {
                        return p.add_node(.{
                            .tag = .ptr_type_sentinel,
                            .main_token = lbracket,
                            .data = .{
                                .lhs = sentinel,
                                .rhs = elem_type,
                            },
                        });
                    } else {
                        return p.add_node(.{
                            .tag = .ptr_type,
                            .main_token = lbracket,
                            .data = .{
                                .lhs = try p.add_extra(Node.PtrType{
                                    .sentinel = sentinel,
                                    .align_node = mods.align_node,
                                    .addrspace_node = mods.addrspace_node,
                                }),
                                .rhs = elem_type,
                            },
                        });
                    }
                } else {
                    switch (p.token_tags[p.tok_i]) {
                        .keyword_align,
                        .keyword_const,
                        .keyword_volatile,
                        .keyword_allowzero,
                        .keyword_addrspace,
                        => return p.fail(.ptr_mod_on_array_child_type),
                        else => {},
                    }
                    const elem_type = try p.expect_type_expr();
                    if (sentinel == 0) {
                        return p.add_node(.{
                            .tag = .array_type,
                            .main_token = lbracket,
                            .data = .{
                                .lhs = len_expr,
                                .rhs = elem_type,
                            },
                        });
                    } else {
                        return p.add_node(.{
                            .tag = .array_type_sentinel,
                            .main_token = lbracket,
                            .data = .{
                                .lhs = len_expr,
                                .rhs = try p.add_extra(Node.ArrayTypeSentinel{
                                    .sentinel = sentinel,
                                    .elem_type = elem_type,
                                }),
                            },
                        });
                    }
                }
            },
        },
        else => return p.parse_error_union_expr(),
    }
}

fn expect_type_expr(p: *Parse) Error!Node.Index {
    const node = try p.parse_type_expr();
    if (node == 0) {
        return p.fail(.expected_type_expr);
    }
    return node;
}

/// PrimaryExpr
///     <- AsmExpr
///      / IfExpr
///      / KEYWORD_break BreakLabel? Expr?
///      / KEYWORD_comptime Expr
///      / KEYWORD_nosuspend Expr
///      / KEYWORD_continue BreakLabel?
///      / KEYWORD_resume Expr
///      / KEYWORD_return Expr?
///      / BlockLabel? LoopExpr
///      / Block
///      / CurlySuffixExpr
fn parse_primary_expr(p: *Parse) !Node.Index {
    switch (p.token_tags[p.tok_i]) {
        .keyword_asm => return p.expect_asm_expr(),
        .keyword_if => return p.parse_if_expr(),
        .keyword_break => {
            return p.add_node(.{
                .tag = .@"break",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.parse_break_label(),
                    .rhs = try p.parse_expr(),
                },
            });
        },
        .keyword_continue => {
            return p.add_node(.{
                .tag = .@"continue",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.parse_break_label(),
                    .rhs = undefined,
                },
            });
        },
        .keyword_comptime => {
            return p.add_node(.{
                .tag = .@"comptime",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.expect_expr(),
                    .rhs = undefined,
                },
            });
        },
        .keyword_nosuspend => {
            return p.add_node(.{
                .tag = .@"nosuspend",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.expect_expr(),
                    .rhs = undefined,
                },
            });
        },
        .keyword_resume => {
            return p.add_node(.{
                .tag = .@"resume",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.expect_expr(),
                    .rhs = undefined,
                },
            });
        },
        .keyword_return => {
            return p.add_node(.{
                .tag = .@"return",
                .main_token = p.next_token(),
                .data = .{
                    .lhs = try p.parse_expr(),
                    .rhs = undefined,
                },
            });
        },
        .identifier => {
            if (p.token_tags[p.tok_i + 1] == .colon) {
                switch (p.token_tags[p.tok_i + 2]) {
                    .keyword_inline => {
                        p.tok_i += 3;
                        switch (p.token_tags[p.tok_i]) {
                            .keyword_for => return p.parse_for(expect_expr),
                            .keyword_while => return p.parse_while_expr(),
                            else => return p.fail(.expected_inlinable),
                        }
                    },
                    .keyword_for => {
                        p.tok_i += 2;
                        return p.parse_for(expect_expr);
                    },
                    .keyword_while => {
                        p.tok_i += 2;
                        return p.parse_while_expr();
                    },
                    .l_brace => {
                        p.tok_i += 2;
                        return p.parse_block();
                    },
                    else => return p.parse_curly_suffix_expr(),
                }
            } else {
                return p.parse_curly_suffix_expr();
            }
        },
        .keyword_inline => {
            p.tok_i += 1;
            switch (p.token_tags[p.tok_i]) {
                .keyword_for => return p.parse_for(expect_expr),
                .keyword_while => return p.parse_while_expr(),
                else => return p.fail(.expected_inlinable),
            }
        },
        .keyword_for => return p.parse_for(expect_expr),
        .keyword_while => return p.parse_while_expr(),
        .l_brace => return p.parse_block(),
        else => return p.parse_curly_suffix_expr(),
    }
}

/// IfExpr <- IfPrefix Expr (KEYWORD_else Payload? Expr)?
fn parse_if_expr(p: *Parse) !Node.Index {
    return p.parse_if(expect_expr);
}

/// Block <- LBRACE Statement* RBRACE
fn parse_block(p: *Parse) !Node.Index {
    const lbrace = p.eat_token(.l_brace) orelse return null_node;
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    while (true) {
        if (p.token_tags[p.tok_i] == .r_brace) break;
        const statement = try p.expect_statement_recoverable();
        if (statement == 0) break;
        try p.scratch.append(p.gpa, statement);
    }
    _ = try p.expect_token(.r_brace);
    const semicolon = (p.token_tags[p.tok_i - 2] == .semicolon);
    const statements = p.scratch.items[scratch_top..];
    switch (statements.len) {
        0 => return p.add_node(.{
            .tag = .block_two,
            .main_token = lbrace,
            .data = .{
                .lhs = 0,
                .rhs = 0,
            },
        }),
        1 => return p.add_node(.{
            .tag = if (semicolon) .block_two_semicolon else .block_two,
            .main_token = lbrace,
            .data = .{
                .lhs = statements[0],
                .rhs = 0,
            },
        }),
        2 => return p.add_node(.{
            .tag = if (semicolon) .block_two_semicolon else .block_two,
            .main_token = lbrace,
            .data = .{
                .lhs = statements[0],
                .rhs = statements[1],
            },
        }),
        else => {
            const span = try p.list_to_span(statements);
            return p.add_node(.{
                .tag = if (semicolon) .block_semicolon else .block,
                .main_token = lbrace,
                .data = .{
                    .lhs = span.start,
                    .rhs = span.end,
                },
            });
        },
    }
}

/// ForPrefix <- KEYWORD_for LPAREN ForInput (COMMA ForInput)* COMMA? RPAREN ForPayload
///
/// ForInput <- Expr (DOT2 Expr?)?
///
/// ForPayload <- PIPE ASTERISK? IDENTIFIER (COMMA ASTERISK? IDENTIFIER)* PIPE
fn for_prefix(p: *Parse) Error!usize {
    const start = p.scratch.items.len;
    _ = try p.expect_token(.l_paren);

    while (true) {
        var input = try p.expect_expr();
        if (p.eat_token(.ellipsis2)) |ellipsis| {
            input = try p.add_node(.{
                .tag = .for_range,
                .main_token = ellipsis,
                .data = .{
                    .lhs = input,
                    .rhs = try p.parse_expr(),
                },
            });
        }

        try p.scratch.append(p.gpa, input);
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_brace, .r_bracket => return p.fail_expected(.r_paren),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_for_operand),
        }
        if (p.eat_token(.r_paren)) |_| break;
    }
    const inputs = p.scratch.items.len - start;

    _ = p.eat_token(.pipe) orelse {
        try p.warn(.expected_loop_payload);
        return inputs;
    };

    var warned_excess = false;
    var captures: u32 = 0;
    while (true) {
        _ = p.eat_token(.asterisk);
        const identifier = try p.expect_token(.identifier);
        captures += 1;
        if (captures > inputs and !warned_excess) {
            try p.warn_msg(.{ .tag = .extra_for_capture, .token = identifier });
            warned_excess = true;
        }
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            .pipe => {
                p.tok_i += 1;
                break;
            },
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_capture),
        }
        if (p.eat_token(.pipe)) |_| break;
    }

    if (captures < inputs) {
        const index = p.scratch.items.len - captures;
        const input = p.nodes.items(.main_token)[p.scratch.items[index]];
        try p.warn_msg(.{ .tag = .for_input_not_captured, .token = input });
    }
    return inputs;
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileExpr <- WhilePrefix Expr (KEYWORD_else Payload? Expr)?
fn parse_while_expr(p: *Parse) !Node.Index {
    const while_token = p.eat_token(.keyword_while) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const condition = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.parse_ptr_payload();
    const cont_expr = try p.parse_while_continue_expr();

    const then_expr = try p.expect_expr();
    _ = p.eat_token(.keyword_else) orelse {
        if (cont_expr == 0) {
            return p.add_node(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = then_expr,
                },
            });
        } else {
            return p.add_node(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = try p.add_extra(Node.WhileCont{
                        .cont_expr = cont_expr,
                        .then_expr = then_expr,
                    }),
                },
            });
        }
    };
    _ = try p.parse_payload();
    const else_expr = try p.expect_expr();
    return p.add_node(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{
            .lhs = condition,
            .rhs = try p.add_extra(Node.While{
                .cont_expr = cont_expr,
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        },
    });
}

/// CurlySuffixExpr <- TypeExpr InitList?
///
/// InitList
///     <- LBRACE FieldInit (COMMA FieldInit)* COMMA? RBRACE
///      / LBRACE Expr (COMMA Expr)* COMMA? RBRACE
///      / LBRACE RBRACE
fn parse_curly_suffix_expr(p: *Parse) !Node.Index {
    const lhs = try p.parse_type_expr();
    if (lhs == 0) return null_node;
    const lbrace = p.eat_token(.l_brace) orelse return lhs;

    // If there are 0 or 1 items, we can use ArrayInitOne/StructInitOne;
    // otherwise we use the full ArrayInit/StructInit.

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    const field_init = try p.parse_field_init();
    if (field_init != 0) {
        try p.scratch.append(p.gpa, field_init);
        while (true) {
            switch (p.token_tags[p.tok_i]) {
                .comma => p.tok_i += 1,
                .r_brace => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_paren, .r_bracket => return p.fail_expected(.r_brace),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_initializer),
            }
            if (p.eat_token(.r_brace)) |_| break;
            const next = try p.expect_field_init();
            try p.scratch.append(p.gpa, next);
        }
        const comma = (p.token_tags[p.tok_i - 2] == .comma);
        const inits = p.scratch.items[scratch_top..];
        switch (inits.len) {
            0 => unreachable,
            1 => return p.add_node(.{
                .tag = if (comma) .struct_init_one_comma else .struct_init_one,
                .main_token = lbrace,
                .data = .{
                    .lhs = lhs,
                    .rhs = inits[0],
                },
            }),
            else => return p.add_node(.{
                .tag = if (comma) .struct_init_comma else .struct_init,
                .main_token = lbrace,
                .data = .{
                    .lhs = lhs,
                    .rhs = try p.add_extra(try p.list_to_span(inits)),
                },
            }),
        }
    }

    while (true) {
        if (p.eat_token(.r_brace)) |_| break;
        const elem_init = try p.expect_expr();
        try p.scratch.append(p.gpa, elem_init);
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            .r_brace => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_paren, .r_bracket => return p.fail_expected(.r_brace),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_initializer),
        }
    }
    const comma = (p.token_tags[p.tok_i - 2] == .comma);
    const inits = p.scratch.items[scratch_top..];
    switch (inits.len) {
        0 => return p.add_node(.{
            .tag = .struct_init_one,
            .main_token = lbrace,
            .data = .{
                .lhs = lhs,
                .rhs = 0,
            },
        }),
        1 => return p.add_node(.{
            .tag = if (comma) .array_init_one_comma else .array_init_one,
            .main_token = lbrace,
            .data = .{
                .lhs = lhs,
                .rhs = inits[0],
            },
        }),
        else => return p.add_node(.{
            .tag = if (comma) .array_init_comma else .array_init,
            .main_token = lbrace,
            .data = .{
                .lhs = lhs,
                .rhs = try p.add_extra(try p.list_to_span(inits)),
            },
        }),
    }
}

/// ErrorUnionExpr <- SuffixExpr (EXCLAMATIONMARK TypeExpr)?
fn parse_error_union_expr(p: *Parse) !Node.Index {
    const suffix_expr = try p.parse_suffix_expr();
    if (suffix_expr == 0) return null_node;
    const bang = p.eat_token(.bang) orelse return suffix_expr;
    return p.add_node(.{
        .tag = .error_union,
        .main_token = bang,
        .data = .{
            .lhs = suffix_expr,
            .rhs = try p.expect_type_expr(),
        },
    });
}

/// SuffixExpr
///     <- KEYWORD_async PrimaryTypeExpr SuffixOp* FnCallArguments
///      / PrimaryTypeExpr (SuffixOp / FnCallArguments)*
///
/// FnCallArguments <- LPAREN ExprList RPAREN
///
/// ExprList <- (Expr COMMA)* Expr?
fn parse_suffix_expr(p: *Parse) !Node.Index {
    if (p.eat_token(.keyword_async)) |_| {
        var res = try p.expect_primary_type_expr();
        while (true) {
            const node = try p.parse_suffix_op(res);
            if (node == 0) break;
            res = node;
        }
        const lparen = p.eat_token(.l_paren) orelse {
            try p.warn(.expected_param_list);
            return res;
        };
        const scratch_top = p.scratch.items.len;
        defer p.scratch.shrink_retaining_capacity(scratch_top);
        while (true) {
            if (p.eat_token(.r_paren)) |_| break;
            const param = try p.expect_expr();
            try p.scratch.append(p.gpa, param);
            switch (p.token_tags[p.tok_i]) {
                .comma => p.tok_i += 1,
                .r_paren => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_brace, .r_bracket => return p.fail_expected(.r_paren),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_arg),
            }
        }
        const comma = (p.token_tags[p.tok_i - 2] == .comma);
        const params = p.scratch.items[scratch_top..];
        switch (params.len) {
            0 => return p.add_node(.{
                .tag = if (comma) .async_call_one_comma else .async_call_one,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = 0,
                },
            }),
            1 => return p.add_node(.{
                .tag = if (comma) .async_call_one_comma else .async_call_one,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = params[0],
                },
            }),
            else => return p.add_node(.{
                .tag = if (comma) .async_call_comma else .async_call,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = try p.add_extra(try p.list_to_span(params)),
                },
            }),
        }
    }

    var res = try p.parse_primary_type_expr();
    if (res == 0) return res;
    while (true) {
        const suffix_op = try p.parse_suffix_op(res);
        if (suffix_op != 0) {
            res = suffix_op;
            continue;
        }
        const lparen = p.eat_token(.l_paren) orelse return res;
        const scratch_top = p.scratch.items.len;
        defer p.scratch.shrink_retaining_capacity(scratch_top);
        while (true) {
            if (p.eat_token(.r_paren)) |_| break;
            const param = try p.expect_expr();
            try p.scratch.append(p.gpa, param);
            switch (p.token_tags[p.tok_i]) {
                .comma => p.tok_i += 1,
                .r_paren => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_brace, .r_bracket => return p.fail_expected(.r_paren),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_arg),
            }
        }
        const comma = (p.token_tags[p.tok_i - 2] == .comma);
        const params = p.scratch.items[scratch_top..];
        res = switch (params.len) {
            0 => try p.add_node(.{
                .tag = if (comma) .call_one_comma else .call_one,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = 0,
                },
            }),
            1 => try p.add_node(.{
                .tag = if (comma) .call_one_comma else .call_one,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = params[0],
                },
            }),
            else => try p.add_node(.{
                .tag = if (comma) .call_comma else .call,
                .main_token = lparen,
                .data = .{
                    .lhs = res,
                    .rhs = try p.add_extra(try p.list_to_span(params)),
                },
            }),
        };
    }
}

/// PrimaryTypeExpr
///     <- BUILTINIDENTIFIER FnCallArguments
///      / CHAR_LITERAL
///      / ContainerDecl
///      / DOT IDENTIFIER
///      / DOT InitList
///      / ErrorSetDecl
///      / FLOAT
///      / FnProto
///      / GroupedExpr
///      / LabeledTypeExpr
///      / IDENTIFIER
///      / IfTypeExpr
///      / INTEGER
///      / KEYWORD_comptime TypeExpr
///      / KEYWORD_error DOT IDENTIFIER
///      / KEYWORD_anyframe
///      / KEYWORD_unreachable
///      / STRINGLITERAL
///      / SwitchExpr
///
/// ContainerDecl <- (KEYWORD_extern / KEYWORD_packed)? ContainerDeclAuto
///
/// ContainerDeclAuto <- ContainerDeclType LBRACE container_doc_comment? ContainerMembers RBRACE
///
/// InitList
///     <- LBRACE FieldInit (COMMA FieldInit)* COMMA? RBRACE
///      / LBRACE Expr (COMMA Expr)* COMMA? RBRACE
///      / LBRACE RBRACE
///
/// ErrorSetDecl <- KEYWORD_error LBRACE IdentifierList RBRACE
///
/// GroupedExpr <- LPAREN Expr RPAREN
///
/// IfTypeExpr <- IfPrefix TypeExpr (KEYWORD_else Payload? TypeExpr)?
///
/// LabeledTypeExpr
///     <- BlockLabel Block
///      / BlockLabel? LoopTypeExpr
///
/// LoopTypeExpr <- KEYWORD_inline? (ForTypeExpr / WhileTypeExpr)
fn parse_primary_type_expr(p: *Parse) !Node.Index {
    switch (p.token_tags[p.tok_i]) {
        .char_literal => return p.add_node(.{
            .tag = .char_literal,
            .main_token = p.next_token(),
            .data = .{
                .lhs = undefined,
                .rhs = undefined,
            },
        }),
        .number_literal => return p.add_node(.{
            .tag = .number_literal,
            .main_token = p.next_token(),
            .data = .{
                .lhs = undefined,
                .rhs = undefined,
            },
        }),
        .keyword_unreachable => return p.add_node(.{
            .tag = .unreachable_literal,
            .main_token = p.next_token(),
            .data = .{
                .lhs = undefined,
                .rhs = undefined,
            },
        }),
        .keyword_anyframe => return p.add_node(.{
            .tag = .anyframe_literal,
            .main_token = p.next_token(),
            .data = .{
                .lhs = undefined,
                .rhs = undefined,
            },
        }),
        .string_literal => {
            const main_token = p.next_token();
            return p.add_node(.{
                .tag = .string_literal,
                .main_token = main_token,
                .data = .{
                    .lhs = undefined,
                    .rhs = undefined,
                },
            });
        },

        .builtin => return p.parse_builtin_call(),
        .keyword_fn => return p.parse_fn_proto(),
        .keyword_if => return p.parse_if(expect_type_expr),
        .keyword_switch => return p.expect_switch_expr(),

        .keyword_extern,
        .keyword_packed,
        => {
            p.tok_i += 1;
            return p.parse_container_decl_auto();
        },

        .keyword_struct,
        .keyword_opaque,
        .keyword_enum,
        .keyword_union,
        => return p.parse_container_decl_auto(),

        .keyword_comptime => return p.add_node(.{
            .tag = .@"comptime",
            .main_token = p.next_token(),
            .data = .{
                .lhs = try p.expect_type_expr(),
                .rhs = undefined,
            },
        }),
        .multiline_string_literal_line => {
            const first_line = p.next_token();
            while (p.token_tags[p.tok_i] == .multiline_string_literal_line) {
                p.tok_i += 1;
            }
            return p.add_node(.{
                .tag = .multiline_string_literal,
                .main_token = first_line,
                .data = .{
                    .lhs = first_line,
                    .rhs = p.tok_i - 1,
                },
            });
        },
        .identifier => switch (p.token_tags[p.tok_i + 1]) {
            .colon => switch (p.token_tags[p.tok_i + 2]) {
                .keyword_inline => {
                    p.tok_i += 3;
                    switch (p.token_tags[p.tok_i]) {
                        .keyword_for => return p.parse_for(expect_type_expr),
                        .keyword_while => return p.parse_while_type_expr(),
                        else => return p.fail(.expected_inlinable),
                    }
                },
                .keyword_for => {
                    p.tok_i += 2;
                    return p.parse_for(expect_type_expr);
                },
                .keyword_while => {
                    p.tok_i += 2;
                    return p.parse_while_type_expr();
                },
                .l_brace => {
                    p.tok_i += 2;
                    return p.parse_block();
                },
                else => return p.add_node(.{
                    .tag = .identifier,
                    .main_token = p.next_token(),
                    .data = .{
                        .lhs = undefined,
                        .rhs = undefined,
                    },
                }),
            },
            else => return p.add_node(.{
                .tag = .identifier,
                .main_token = p.next_token(),
                .data = .{
                    .lhs = undefined,
                    .rhs = undefined,
                },
            }),
        },
        .keyword_inline => {
            p.tok_i += 1;
            switch (p.token_tags[p.tok_i]) {
                .keyword_for => return p.parse_for(expect_type_expr),
                .keyword_while => return p.parse_while_type_expr(),
                else => return p.fail(.expected_inlinable),
            }
        },
        .keyword_for => return p.parse_for(expect_type_expr),
        .keyword_while => return p.parse_while_type_expr(),
        .period => switch (p.token_tags[p.tok_i + 1]) {
            .identifier => return p.add_node(.{
                .tag = .enum_literal,
                .data = .{
                    .lhs = p.next_token(), // dot
                    .rhs = undefined,
                },
                .main_token = p.next_token(), // identifier
            }),
            .l_brace => {
                const lbrace = p.tok_i + 1;
                p.tok_i = lbrace + 1;

                // If there are 0, 1, or 2 items, we can use ArrayInitDotTwo/StructInitDotTwo;
                // otherwise we use the full ArrayInitDot/StructInitDot.

                const scratch_top = p.scratch.items.len;
                defer p.scratch.shrink_retaining_capacity(scratch_top);
                const field_init = try p.parse_field_init();
                if (field_init != 0) {
                    try p.scratch.append(p.gpa, field_init);
                    while (true) {
                        switch (p.token_tags[p.tok_i]) {
                            .comma => p.tok_i += 1,
                            .r_brace => {
                                p.tok_i += 1;
                                break;
                            },
                            .colon, .r_paren, .r_bracket => return p.fail_expected(.r_brace),
                            // Likely just a missing comma; give error but continue parsing.
                            else => try p.warn(.expected_comma_after_initializer),
                        }
                        if (p.eat_token(.r_brace)) |_| break;
                        const next = try p.expect_field_init();
                        try p.scratch.append(p.gpa, next);
                    }
                    const comma = (p.token_tags[p.tok_i - 2] == .comma);
                    const inits = p.scratch.items[scratch_top..];
                    switch (inits.len) {
                        0 => unreachable,
                        1 => return p.add_node(.{
                            .tag = if (comma) .struct_init_dot_two_comma else .struct_init_dot_two,
                            .main_token = lbrace,
                            .data = .{
                                .lhs = inits[0],
                                .rhs = 0,
                            },
                        }),
                        2 => return p.add_node(.{
                            .tag = if (comma) .struct_init_dot_two_comma else .struct_init_dot_two,
                            .main_token = lbrace,
                            .data = .{
                                .lhs = inits[0],
                                .rhs = inits[1],
                            },
                        }),
                        else => {
                            const span = try p.list_to_span(inits);
                            return p.add_node(.{
                                .tag = if (comma) .struct_init_dot_comma else .struct_init_dot,
                                .main_token = lbrace,
                                .data = .{
                                    .lhs = span.start,
                                    .rhs = span.end,
                                },
                            });
                        },
                    }
                }

                while (true) {
                    if (p.eat_token(.r_brace)) |_| break;
                    const elem_init = try p.expect_expr();
                    try p.scratch.append(p.gpa, elem_init);
                    switch (p.token_tags[p.tok_i]) {
                        .comma => p.tok_i += 1,
                        .r_brace => {
                            p.tok_i += 1;
                            break;
                        },
                        .colon, .r_paren, .r_bracket => return p.fail_expected(.r_brace),
                        // Likely just a missing comma; give error but continue parsing.
                        else => try p.warn(.expected_comma_after_initializer),
                    }
                }
                const comma = (p.token_tags[p.tok_i - 2] == .comma);
                const inits = p.scratch.items[scratch_top..];
                switch (inits.len) {
                    0 => return p.add_node(.{
                        .tag = .struct_init_dot_two,
                        .main_token = lbrace,
                        .data = .{
                            .lhs = 0,
                            .rhs = 0,
                        },
                    }),
                    1 => return p.add_node(.{
                        .tag = if (comma) .array_init_dot_two_comma else .array_init_dot_two,
                        .main_token = lbrace,
                        .data = .{
                            .lhs = inits[0],
                            .rhs = 0,
                        },
                    }),
                    2 => return p.add_node(.{
                        .tag = if (comma) .array_init_dot_two_comma else .array_init_dot_two,
                        .main_token = lbrace,
                        .data = .{
                            .lhs = inits[0],
                            .rhs = inits[1],
                        },
                    }),
                    else => {
                        const span = try p.list_to_span(inits);
                        return p.add_node(.{
                            .tag = if (comma) .array_init_dot_comma else .array_init_dot,
                            .main_token = lbrace,
                            .data = .{
                                .lhs = span.start,
                                .rhs = span.end,
                            },
                        });
                    },
                }
            },
            else => return null_node,
        },
        .keyword_error => switch (p.token_tags[p.tok_i + 1]) {
            .l_brace => {
                const error_token = p.tok_i;
                p.tok_i += 2;
                while (true) {
                    if (p.eat_token(.r_brace)) |_| break;
                    _ = try p.eat_doc_comments();
                    _ = try p.expect_token(.identifier);
                    switch (p.token_tags[p.tok_i]) {
                        .comma => p.tok_i += 1,
                        .r_brace => {
                            p.tok_i += 1;
                            break;
                        },
                        .colon, .r_paren, .r_bracket => return p.fail_expected(.r_brace),
                        // Likely just a missing comma; give error but continue parsing.
                        else => try p.warn(.expected_comma_after_field),
                    }
                }
                return p.add_node(.{
                    .tag = .error_set_decl,
                    .main_token = error_token,
                    .data = .{
                        .lhs = undefined,
                        .rhs = p.tok_i - 1, // rbrace
                    },
                });
            },
            else => {
                const main_token = p.next_token();
                const period = p.eat_token(.period);
                if (period == null) try p.warn_expected(.period);
                const identifier = p.eat_token(.identifier);
                if (identifier == null) try p.warn_expected(.identifier);
                return p.add_node(.{
                    .tag = .error_value,
                    .main_token = main_token,
                    .data = .{
                        .lhs = period orelse 0,
                        .rhs = identifier orelse 0,
                    },
                });
            },
        },
        .l_paren => return p.add_node(.{
            .tag = .grouped_expression,
            .main_token = p.next_token(),
            .data = .{
                .lhs = try p.expect_expr(),
                .rhs = try p.expect_token(.r_paren),
            },
        }),
        else => return null_node,
    }
}

fn expect_primary_type_expr(p: *Parse) !Node.Index {
    const node = try p.parse_primary_type_expr();
    if (node == 0) {
        return p.fail(.expected_primary_type_expr);
    }
    return node;
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileTypeExpr <- WhilePrefix TypeExpr (KEYWORD_else Payload? TypeExpr)?
fn parse_while_type_expr(p: *Parse) !Node.Index {
    const while_token = p.eat_token(.keyword_while) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const condition = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.parse_ptr_payload();
    const cont_expr = try p.parse_while_continue_expr();

    const then_expr = try p.expect_type_expr();
    _ = p.eat_token(.keyword_else) orelse {
        if (cont_expr == 0) {
            return p.add_node(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = then_expr,
                },
            });
        } else {
            return p.add_node(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{
                    .lhs = condition,
                    .rhs = try p.add_extra(Node.WhileCont{
                        .cont_expr = cont_expr,
                        .then_expr = then_expr,
                    }),
                },
            });
        }
    };
    _ = try p.parse_payload();
    const else_expr = try p.expect_type_expr();
    return p.add_node(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{
            .lhs = condition,
            .rhs = try p.add_extra(Node.While{
                .cont_expr = cont_expr,
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        },
    });
}

/// SwitchExpr <- KEYWORD_switch LPAREN Expr RPAREN LBRACE SwitchProngList RBRACE
fn expect_switch_expr(p: *Parse) !Node.Index {
    const switch_token = p.assert_token(.keyword_switch);
    _ = try p.expect_token(.l_paren);
    const expr_node = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.expect_token(.l_brace);
    const cases = try p.parse_switch_prong_list();
    const trailing_comma = p.token_tags[p.tok_i - 1] == .comma;
    _ = try p.expect_token(.r_brace);

    return p.add_node(.{
        .tag = if (trailing_comma) .switch_comma else .@"switch",
        .main_token = switch_token,
        .data = .{
            .lhs = expr_node,
            .rhs = try p.add_extra(Node.SubRange{
                .start = cases.start,
                .end = cases.end,
            }),
        },
    });
}

/// AsmExpr <- KEYWORD_asm KEYWORD_volatile? LPAREN Expr AsmOutput? RPAREN
///
/// AsmOutput <- COLON AsmOutputList AsmInput?
///
/// AsmInput <- COLON AsmInputList AsmClobbers?
///
/// AsmClobbers <- COLON StringList
///
/// StringList <- (STRINGLITERAL COMMA)* STRINGLITERAL?
///
/// AsmOutputList <- (AsmOutputItem COMMA)* AsmOutputItem?
///
/// AsmInputList <- (AsmInputItem COMMA)* AsmInputItem?
fn expect_asm_expr(p: *Parse) !Node.Index {
    const asm_token = p.assert_token(.keyword_asm);
    _ = p.eat_token(.keyword_volatile);
    _ = try p.expect_token(.l_paren);
    const template = try p.expect_expr();

    if (p.eat_token(.r_paren)) |rparen| {
        return p.add_node(.{
            .tag = .asm_simple,
            .main_token = asm_token,
            .data = .{
                .lhs = template,
                .rhs = rparen,
            },
        });
    }

    _ = try p.expect_token(.colon);

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    while (true) {
        const output_item = try p.parse_asm_output_item();
        if (output_item == 0) break;
        try p.scratch.append(p.gpa, output_item);
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            // All possible delimiters.
            .colon, .r_paren, .r_brace, .r_bracket => break,
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn_expected(.comma),
        }
    }
    if (p.eat_token(.colon)) |_| {
        while (true) {
            const input_item = try p.parse_asm_input_item();
            if (input_item == 0) break;
            try p.scratch.append(p.gpa, input_item);
            switch (p.token_tags[p.tok_i]) {
                .comma => p.tok_i += 1,
                // All possible delimiters.
                .colon, .r_paren, .r_brace, .r_bracket => break,
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn_expected(.comma),
            }
        }
        if (p.eat_token(.colon)) |_| {
            while (p.eat_token(.string_literal)) |_| {
                switch (p.token_tags[p.tok_i]) {
                    .comma => p.tok_i += 1,
                    .colon, .r_paren, .r_brace, .r_bracket => break,
                    // Likely just a missing comma; give error but continue parsing.
                    else => try p.warn_expected(.comma),
                }
            }
        }
    }
    const rparen = try p.expect_token(.r_paren);
    const span = try p.list_to_span(p.scratch.items[scratch_top..]);
    return p.add_node(.{
        .tag = .@"asm",
        .main_token = asm_token,
        .data = .{
            .lhs = template,
            .rhs = try p.add_extra(Node.Asm{
                .items_start = span.start,
                .items_end = span.end,
                .rparen = rparen,
            }),
        },
    });
}

/// AsmOutputItem <- LBRACKET IDENTIFIER RBRACKET STRINGLITERAL LPAREN (MINUSRARROW TypeExpr / IDENTIFIER) RPAREN
fn parse_asm_output_item(p: *Parse) !Node.Index {
    _ = p.eat_token(.l_bracket) orelse return null_node;
    const identifier = try p.expect_token(.identifier);
    _ = try p.expect_token(.r_bracket);
    _ = try p.expect_token(.string_literal);
    _ = try p.expect_token(.l_paren);
    const type_expr: Node.Index = blk: {
        if (p.eat_token(.arrow)) |_| {
            break :blk try p.expect_type_expr();
        } else {
            _ = try p.expect_token(.identifier);
            break :blk null_node;
        }
    };
    const rparen = try p.expect_token(.r_paren);
    return p.add_node(.{
        .tag = .asm_output,
        .main_token = identifier,
        .data = .{
            .lhs = type_expr,
            .rhs = rparen,
        },
    });
}

/// AsmInputItem <- LBRACKET IDENTIFIER RBRACKET STRINGLITERAL LPAREN Expr RPAREN
fn parse_asm_input_item(p: *Parse) !Node.Index {
    _ = p.eat_token(.l_bracket) orelse return null_node;
    const identifier = try p.expect_token(.identifier);
    _ = try p.expect_token(.r_bracket);
    _ = try p.expect_token(.string_literal);
    _ = try p.expect_token(.l_paren);
    const expr = try p.expect_expr();
    const rparen = try p.expect_token(.r_paren);
    return p.add_node(.{
        .tag = .asm_input,
        .main_token = identifier,
        .data = .{
            .lhs = expr,
            .rhs = rparen,
        },
    });
}

/// BreakLabel <- COLON IDENTIFIER
fn parse_break_label(p: *Parse) !TokenIndex {
    _ = p.eat_token(.colon) orelse return null_node;
    return p.expect_token(.identifier);
}

/// BlockLabel <- IDENTIFIER COLON
fn parse_block_label(p: *Parse) TokenIndex {
    if (p.token_tags[p.tok_i] == .identifier and
        p.token_tags[p.tok_i + 1] == .colon)
    {
        const identifier = p.tok_i;
        p.tok_i += 2;
        return identifier;
    }
    return null_node;
}

/// FieldInit <- DOT IDENTIFIER EQUAL Expr
fn parse_field_init(p: *Parse) !Node.Index {
    if (p.token_tags[p.tok_i + 0] == .period and
        p.token_tags[p.tok_i + 1] == .identifier and
        p.token_tags[p.tok_i + 2] == .equal)
    {
        p.tok_i += 3;
        return p.expect_expr();
    } else {
        return null_node;
    }
}

fn expect_field_init(p: *Parse) !Node.Index {
    if (p.token_tags[p.tok_i] != .period or
        p.token_tags[p.tok_i + 1] != .identifier or
        p.token_tags[p.tok_i + 2] != .equal)
        return p.fail(.expected_initializer);

    p.tok_i += 3;
    return p.expect_expr();
}

/// WhileContinueExpr <- COLON LPAREN AssignExpr RPAREN
fn parse_while_continue_expr(p: *Parse) !Node.Index {
    _ = p.eat_token(.colon) orelse {
        if (p.token_tags[p.tok_i] == .l_paren and
            p.tokens_on_same_line(p.tok_i - 1, p.tok_i))
            return p.fail(.expected_continue_expr);
        return null_node;
    };
    _ = try p.expect_token(.l_paren);
    const node = try p.parse_assign_expr();
    if (node == 0) return p.fail(.expected_expr_or_assignment);
    _ = try p.expect_token(.r_paren);
    return node;
}

/// LinkSection <- KEYWORD_linksection LPAREN Expr RPAREN
fn parse_link_section(p: *Parse) !Node.Index {
    _ = p.eat_token(.keyword_linksection) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const expr_node = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    return expr_node;
}

/// CallConv <- KEYWORD_callconv LPAREN Expr RPAREN
fn parse_callconv(p: *Parse) !Node.Index {
    _ = p.eat_token(.keyword_callconv) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const expr_node = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    return expr_node;
}

/// AddrSpace <- KEYWORD_addrspace LPAREN Expr RPAREN
fn parse_addr_space(p: *Parse) !Node.Index {
    _ = p.eat_token(.keyword_addrspace) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const expr_node = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    return expr_node;
}

/// This function can return null nodes and then still return nodes afterwards,
/// such as in the case of anytype and `...`. Caller must look for rparen to find
/// out when there are no more param decls left.
///
/// ParamDecl
///     <- doc_comment? (KEYWORD_noalias / KEYWORD_comptime)? (IDENTIFIER COLON)? ParamType
///      / DOT3
///
/// ParamType
///     <- KEYWORD_anytype
///      / TypeExpr
fn expect_param_decl(p: *Parse) !Node.Index {
    _ = try p.eat_doc_comments();
    switch (p.token_tags[p.tok_i]) {
        .keyword_noalias, .keyword_comptime => p.tok_i += 1,
        .ellipsis3 => {
            p.tok_i += 1;
            return null_node;
        },
        else => {},
    }
    if (p.token_tags[p.tok_i] == .identifier and
        p.token_tags[p.tok_i + 1] == .colon)
    {
        p.tok_i += 2;
    }
    switch (p.token_tags[p.tok_i]) {
        .keyword_anytype => {
            p.tok_i += 1;
            return null_node;
        },
        else => return p.expect_type_expr(),
    }
}

/// Payload <- PIPE IDENTIFIER PIPE
fn parse_payload(p: *Parse) !TokenIndex {
    _ = p.eat_token(.pipe) orelse return null_node;
    const identifier = try p.expect_token(.identifier);
    _ = try p.expect_token(.pipe);
    return identifier;
}

/// PtrPayload <- PIPE ASTERISK? IDENTIFIER PIPE
fn parse_ptr_payload(p: *Parse) !TokenIndex {
    _ = p.eat_token(.pipe) orelse return null_node;
    _ = p.eat_token(.asterisk);
    const identifier = try p.expect_token(.identifier);
    _ = try p.expect_token(.pipe);
    return identifier;
}

/// Returns the first identifier token, if any.
///
/// PtrIndexPayload <- PIPE ASTERISK? IDENTIFIER (COMMA IDENTIFIER)? PIPE
fn parse_ptr_index_payload(p: *Parse) !TokenIndex {
    _ = p.eat_token(.pipe) orelse return null_node;
    _ = p.eat_token(.asterisk);
    const identifier = try p.expect_token(.identifier);
    if (p.eat_token(.comma) != null) {
        _ = try p.expect_token(.identifier);
    }
    _ = try p.expect_token(.pipe);
    return identifier;
}

/// SwitchProng <- KEYWORD_inline? SwitchCase EQUALRARROW PtrIndexPayload? AssignExpr
///
/// SwitchCase
///     <- SwitchItem (COMMA SwitchItem)* COMMA?
///      / KEYWORD_else
fn parse_switch_prong(p: *Parse) !Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    const is_inline = p.eat_token(.keyword_inline) != null;

    if (p.eat_token(.keyword_else) == null) {
        while (true) {
            const item = try p.parse_switch_item();
            if (item == 0) break;
            try p.scratch.append(p.gpa, item);
            if (p.eat_token(.comma) == null) break;
        }
        if (scratch_top == p.scratch.items.len) {
            if (is_inline) p.tok_i -= 1;
            return null_node;
        }
    }
    const arrow_token = try p.expect_token(.equal_angle_bracket_right);
    _ = try p.parse_ptr_index_payload();

    const items = p.scratch.items[scratch_top..];
    switch (items.len) {
        0 => return p.add_node(.{
            .tag = if (is_inline) .switch_case_inline_one else .switch_case_one,
            .main_token = arrow_token,
            .data = .{
                .lhs = 0,
                .rhs = try p.expect_single_assign_expr(),
            },
        }),
        1 => return p.add_node(.{
            .tag = if (is_inline) .switch_case_inline_one else .switch_case_one,
            .main_token = arrow_token,
            .data = .{
                .lhs = items[0],
                .rhs = try p.expect_single_assign_expr(),
            },
        }),
        else => return p.add_node(.{
            .tag = if (is_inline) .switch_case_inline else .switch_case,
            .main_token = arrow_token,
            .data = .{
                .lhs = try p.add_extra(try p.list_to_span(items)),
                .rhs = try p.expect_single_assign_expr(),
            },
        }),
    }
}

/// SwitchItem <- Expr (DOT3 Expr)?
fn parse_switch_item(p: *Parse) !Node.Index {
    const expr = try p.parse_expr();
    if (expr == 0) return null_node;

    if (p.eat_token(.ellipsis3)) |token| {
        return p.add_node(.{
            .tag = .switch_range,
            .main_token = token,
            .data = .{
                .lhs = expr,
                .rhs = try p.expect_expr(),
            },
        });
    }
    return expr;
}

const PtrModifiers = struct {
    align_node: Node.Index,
    addrspace_node: Node.Index,
    bit_range_start: Node.Index,
    bit_range_end: Node.Index,
};

fn parse_ptr_modifiers(p: *Parse) !PtrModifiers {
    var result: PtrModifiers = .{
        .align_node = 0,
        .addrspace_node = 0,
        .bit_range_start = 0,
        .bit_range_end = 0,
    };
    var saw_const = false;
    var saw_volatile = false;
    var saw_allowzero = false;
    while (true) {
        switch (p.token_tags[p.tok_i]) {
            .keyword_align => {
                if (result.align_node != 0) {
                    try p.warn(.extra_align_qualifier);
                }
                p.tok_i += 1;
                _ = try p.expect_token(.l_paren);
                result.align_node = try p.expect_expr();

                if (p.eat_token(.colon)) |_| {
                    result.bit_range_start = try p.expect_expr();
                    _ = try p.expect_token(.colon);
                    result.bit_range_end = try p.expect_expr();
                }

                _ = try p.expect_token(.r_paren);
            },
            .keyword_const => {
                if (saw_const) {
                    try p.warn(.extra_const_qualifier);
                }
                p.tok_i += 1;
                saw_const = true;
            },
            .keyword_volatile => {
                if (saw_volatile) {
                    try p.warn(.extra_volatile_qualifier);
                }
                p.tok_i += 1;
                saw_volatile = true;
            },
            .keyword_allowzero => {
                if (saw_allowzero) {
                    try p.warn(.extra_allowzero_qualifier);
                }
                p.tok_i += 1;
                saw_allowzero = true;
            },
            .keyword_addrspace => {
                if (result.addrspace_node != 0) {
                    try p.warn(.extra_addrspace_qualifier);
                }
                result.addrspace_node = try p.parse_addr_space();
            },
            else => return result,
        }
    }
}

/// SuffixOp
///     <- LBRACKET Expr (DOT2 (Expr? (COLON Expr)?)?)? RBRACKET
///      / DOT IDENTIFIER
///      / DOTASTERISK
///      / DOTQUESTIONMARK
fn parse_suffix_op(p: *Parse, lhs: Node.Index) !Node.Index {
    switch (p.token_tags[p.tok_i]) {
        .l_bracket => {
            const lbracket = p.next_token();
            const index_expr = try p.expect_expr();

            if (p.eat_token(.ellipsis2)) |_| {
                const end_expr = try p.parse_expr();
                if (p.eat_token(.colon)) |_| {
                    const sentinel = try p.expect_expr();
                    _ = try p.expect_token(.r_bracket);
                    return p.add_node(.{
                        .tag = .slice_sentinel,
                        .main_token = lbracket,
                        .data = .{
                            .lhs = lhs,
                            .rhs = try p.add_extra(Node.SliceSentinel{
                                .start = index_expr,
                                .end = end_expr,
                                .sentinel = sentinel,
                            }),
                        },
                    });
                }
                _ = try p.expect_token(.r_bracket);
                if (end_expr == 0) {
                    return p.add_node(.{
                        .tag = .slice_open,
                        .main_token = lbracket,
                        .data = .{
                            .lhs = lhs,
                            .rhs = index_expr,
                        },
                    });
                }
                return p.add_node(.{
                    .tag = .slice,
                    .main_token = lbracket,
                    .data = .{
                        .lhs = lhs,
                        .rhs = try p.add_extra(Node.Slice{
                            .start = index_expr,
                            .end = end_expr,
                        }),
                    },
                });
            }
            _ = try p.expect_token(.r_bracket);
            return p.add_node(.{
                .tag = .array_access,
                .main_token = lbracket,
                .data = .{
                    .lhs = lhs,
                    .rhs = index_expr,
                },
            });
        },
        .period_asterisk => return p.add_node(.{
            .tag = .deref,
            .main_token = p.next_token(),
            .data = .{
                .lhs = lhs,
                .rhs = undefined,
            },
        }),
        .invalid_periodasterisks => {
            try p.warn(.asterisk_after_ptr_deref);
            return p.add_node(.{
                .tag = .deref,
                .main_token = p.next_token(),
                .data = .{
                    .lhs = lhs,
                    .rhs = undefined,
                },
            });
        },
        .period => switch (p.token_tags[p.tok_i + 1]) {
            .identifier => return p.add_node(.{
                .tag = .field_access,
                .main_token = p.next_token(),
                .data = .{
                    .lhs = lhs,
                    .rhs = p.next_token(),
                },
            }),
            .question_mark => return p.add_node(.{
                .tag = .unwrap_optional,
                .main_token = p.next_token(),
                .data = .{
                    .lhs = lhs,
                    .rhs = p.next_token(),
                },
            }),
            .l_brace => {
                // this a misplaced `.{`, handle the error somewhere else
                return null_node;
            },
            else => {
                p.tok_i += 1;
                try p.warn(.expected_suffix_op);
                return null_node;
            },
        },
        else => return null_node,
    }
}

/// Caller must have already verified the first token.
///
/// ContainerDeclAuto <- ContainerDeclType LBRACE container_doc_comment? ContainerMembers RBRACE
///
/// ContainerDeclType
///     <- KEYWORD_struct (LPAREN Expr RPAREN)?
///      / KEYWORD_opaque
///      / KEYWORD_enum (LPAREN Expr RPAREN)?
///      / KEYWORD_union (LPAREN (KEYWORD_enum (LPAREN Expr RPAREN)? / Expr) RPAREN)?
fn parse_container_decl_auto(p: *Parse) !Node.Index {
    const main_token = p.next_token();
    const arg_expr = switch (p.token_tags[main_token]) {
        .keyword_opaque => null_node,
        .keyword_struct, .keyword_enum => blk: {
            if (p.eat_token(.l_paren)) |_| {
                const expr = try p.expect_expr();
                _ = try p.expect_token(.r_paren);
                break :blk expr;
            } else {
                break :blk null_node;
            }
        },
        .keyword_union => blk: {
            if (p.eat_token(.l_paren)) |_| {
                if (p.eat_token(.keyword_enum)) |_| {
                    if (p.eat_token(.l_paren)) |_| {
                        const enum_tag_expr = try p.expect_expr();
                        _ = try p.expect_token(.r_paren);
                        _ = try p.expect_token(.r_paren);

                        _ = try p.expect_token(.l_brace);
                        const members = try p.parse_container_members();
                        const members_span = try members.to_span(p);
                        _ = try p.expect_token(.r_brace);
                        return p.add_node(.{
                            .tag = switch (members.trailing) {
                                true => .tagged_union_enum_tag_trailing,
                                false => .tagged_union_enum_tag,
                            },
                            .main_token = main_token,
                            .data = .{
                                .lhs = enum_tag_expr,
                                .rhs = try p.add_extra(members_span),
                            },
                        });
                    } else {
                        _ = try p.expect_token(.r_paren);

                        _ = try p.expect_token(.l_brace);
                        const members = try p.parse_container_members();
                        _ = try p.expect_token(.r_brace);
                        if (members.len <= 2) {
                            return p.add_node(.{
                                .tag = switch (members.trailing) {
                                    true => .tagged_union_two_trailing,
                                    false => .tagged_union_two,
                                },
                                .main_token = main_token,
                                .data = .{
                                    .lhs = members.lhs,
                                    .rhs = members.rhs,
                                },
                            });
                        } else {
                            const span = try members.to_span(p);
                            return p.add_node(.{
                                .tag = switch (members.trailing) {
                                    true => .tagged_union_trailing,
                                    false => .tagged_union,
                                },
                                .main_token = main_token,
                                .data = .{
                                    .lhs = span.start,
                                    .rhs = span.end,
                                },
                            });
                        }
                    }
                } else {
                    const expr = try p.expect_expr();
                    _ = try p.expect_token(.r_paren);
                    break :blk expr;
                }
            } else {
                break :blk null_node;
            }
        },
        else => {
            p.tok_i -= 1;
            return p.fail(.expected_container);
        },
    };
    _ = try p.expect_token(.l_brace);
    const members = try p.parse_container_members();
    _ = try p.expect_token(.r_brace);
    if (arg_expr == 0) {
        if (members.len <= 2) {
            return p.add_node(.{
                .tag = switch (members.trailing) {
                    true => .container_decl_two_trailing,
                    false => .container_decl_two,
                },
                .main_token = main_token,
                .data = .{
                    .lhs = members.lhs,
                    .rhs = members.rhs,
                },
            });
        } else {
            const span = try members.to_span(p);
            return p.add_node(.{
                .tag = switch (members.trailing) {
                    true => .container_decl_trailing,
                    false => .container_decl,
                },
                .main_token = main_token,
                .data = .{
                    .lhs = span.start,
                    .rhs = span.end,
                },
            });
        }
    } else {
        const span = try members.to_span(p);
        return p.add_node(.{
            .tag = switch (members.trailing) {
                true => .container_decl_arg_trailing,
                false => .container_decl_arg,
            },
            .main_token = main_token,
            .data = .{
                .lhs = arg_expr,
                .rhs = try p.add_extra(Node.SubRange{
                    .start = span.start,
                    .end = span.end,
                }),
            },
        });
    }
}

/// Give a helpful error message for those transitioning from
/// C's 'struct Foo {};' to Zig's 'const Foo = struct {};'.
fn parse_cstyle_container(p: *Parse) Error!bool {
    const main_token = p.tok_i;
    switch (p.token_tags[p.tok_i]) {
        .keyword_enum, .keyword_union, .keyword_struct => {},
        else => return false,
    }
    const identifier = p.tok_i + 1;
    if (p.token_tags[identifier] != .identifier) return false;
    p.tok_i += 2;

    try p.warn_msg(.{
        .tag = .c_style_container,
        .token = identifier,
        .extra = .{ .expected_tag = p.token_tags[main_token] },
    });
    try p.warn_msg(.{
        .tag = .zig_style_container,
        .is_note = true,
        .token = identifier,
        .extra = .{ .expected_tag = p.token_tags[main_token] },
    });

    _ = try p.expect_token(.l_brace);
    _ = try p.parse_container_members();
    _ = try p.expect_token(.r_brace);
    try p.expect_semicolon(.expected_semi_after_decl, true);
    return true;
}

/// Holds temporary data until we are ready to construct the full ContainerDecl AST node.
///
/// ByteAlign <- KEYWORD_align LPAREN Expr RPAREN
fn parse_byte_align(p: *Parse) !Node.Index {
    _ = p.eat_token(.keyword_align) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const expr = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    return expr;
}

/// SwitchProngList <- (SwitchProng COMMA)* SwitchProng?
fn parse_switch_prong_list(p: *Parse) !Node.SubRange {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);

    while (true) {
        const item = try parse_switch_prong(p);
        if (item == 0) break;

        try p.scratch.append(p.gpa, item);

        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            // All possible delimiters.
            .colon, .r_paren, .r_brace, .r_bracket => break,
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_switch_prong),
        }
    }
    return p.list_to_span(p.scratch.items[scratch_top..]);
}

/// ParamDeclList <- (ParamDecl COMMA)* ParamDecl?
fn parse_param_decl_list(p: *Parse) !SmallSpan {
    _ = try p.expect_token(.l_paren);
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    var varargs: union(enum) { none, seen, nonfinal: TokenIndex } = .none;
    while (true) {
        if (p.eat_token(.r_paren)) |_| break;
        if (varargs == .seen) varargs = .{ .nonfinal = p.tok_i };
        const param = try p.expect_param_decl();
        if (param != 0) {
            try p.scratch.append(p.gpa, param);
        } else if (p.token_tags[p.tok_i - 1] == .ellipsis3) {
            if (varargs == .none) varargs = .seen;
        }
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_brace, .r_bracket => return p.fail_expected(.r_paren),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_param),
        }
    }
    if (varargs == .nonfinal) {
        try p.warn_msg(.{ .tag = .varargs_nonfinal, .token = varargs.nonfinal });
    }
    const params = p.scratch.items[scratch_top..];
    return switch (params.len) {
        0 => SmallSpan{ .zero_or_one = 0 },
        1 => SmallSpan{ .zero_or_one = params[0] },
        else => SmallSpan{ .multi = try p.list_to_span(params) },
    };
}

/// FnCallArguments <- LPAREN ExprList RPAREN
///
/// ExprList <- (Expr COMMA)* Expr?
fn parse_builtin_call(p: *Parse) !Node.Index {
    const builtin_token = p.assert_token(.builtin);
    _ = p.eat_token(.l_paren) orelse {
        try p.warn(.expected_param_list);
        // Pretend this was an identifier so we can continue parsing.
        return p.add_node(.{
            .tag = .identifier,
            .main_token = builtin_token,
            .data = .{
                .lhs = undefined,
                .rhs = undefined,
            },
        });
    };
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    while (true) {
        if (p.eat_token(.r_paren)) |_| break;
        const param = try p.expect_expr();
        try p.scratch.append(p.gpa, param);
        switch (p.token_tags[p.tok_i]) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_arg),
        }
    }
    const comma = (p.token_tags[p.tok_i - 2] == .comma);
    const params = p.scratch.items[scratch_top..];
    switch (params.len) {
        0 => return p.add_node(.{
            .tag = .builtin_call_two,
            .main_token = builtin_token,
            .data = .{
                .lhs = 0,
                .rhs = 0,
            },
        }),
        1 => return p.add_node(.{
            .tag = if (comma) .builtin_call_two_comma else .builtin_call_two,
            .main_token = builtin_token,
            .data = .{
                .lhs = params[0],
                .rhs = 0,
            },
        }),
        2 => return p.add_node(.{
            .tag = if (comma) .builtin_call_two_comma else .builtin_call_two,
            .main_token = builtin_token,
            .data = .{
                .lhs = params[0],
                .rhs = params[1],
            },
        }),
        else => {
            const span = try p.list_to_span(params);
            return p.add_node(.{
                .tag = if (comma) .builtin_call_comma else .builtin_call,
                .main_token = builtin_token,
                .data = .{
                    .lhs = span.start,
                    .rhs = span.end,
                },
            });
        },
    }
}

/// IfPrefix <- KEYWORD_if LPAREN Expr RPAREN PtrPayload?
fn parse_if(p: *Parse, comptime bodyParseFn: fn (p: *Parse) Error!Node.Index) !Node.Index {
    const if_token = p.eat_token(.keyword_if) orelse return null_node;
    _ = try p.expect_token(.l_paren);
    const condition = try p.expect_expr();
    _ = try p.expect_token(.r_paren);
    _ = try p.parse_ptr_payload();

    const then_expr = try bodyParseFn(p);
    assert(then_expr != 0);

    _ = p.eat_token(.keyword_else) orelse return p.add_node(.{
        .tag = .if_simple,
        .main_token = if_token,
        .data = .{
            .lhs = condition,
            .rhs = then_expr,
        },
    });
    _ = try p.parse_payload();
    const else_expr = try bodyParseFn(p);
    assert(else_expr != 0);

    return p.add_node(.{
        .tag = .@"if",
        .main_token = if_token,
        .data = .{
            .lhs = condition,
            .rhs = try p.add_extra(Node.If{
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        },
    });
}

/// ForExpr <- ForPrefix Expr (KEYWORD_else Expr)?
///
/// ForTypeExpr <- ForPrefix TypeExpr (KEYWORD_else TypeExpr)?
fn parse_for(p: *Parse, comptime bodyParseFn: fn (p: *Parse) Error!Node.Index) !Node.Index {
    const for_token = p.eat_token(.keyword_for) orelse return null_node;

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrink_retaining_capacity(scratch_top);
    const inputs = try p.for_prefix();

    const then_expr = try bodyParseFn(p);
    var has_else = false;
    if (p.eat_token(.keyword_else)) |_| {
        try p.scratch.append(p.gpa, then_expr);
        const else_expr = try bodyParseFn(p);
        try p.scratch.append(p.gpa, else_expr);
        has_else = true;
    } else if (inputs == 1) {
        return p.add_node(.{
            .tag = .for_simple,
            .main_token = for_token,
            .data = .{
                .lhs = p.scratch.items[scratch_top],
                .rhs = then_expr,
            },
        });
    } else {
        try p.scratch.append(p.gpa, then_expr);
    }
    return p.add_node(.{
        .tag = .@"for",
        .main_token = for_token,
        .data = .{
            .lhs = (try p.list_to_span(p.scratch.items[scratch_top..])).start,
            .rhs = @as(u32, @bit_cast(Node.For{
                .inputs = @as(u31, @int_cast(inputs)),
                .has_else = has_else,
            })),
        },
    });
}

/// Skips over doc comment tokens. Returns the first one, if any.
fn eat_doc_comments(p: *Parse) Allocator.Error!?TokenIndex {
    if (p.eat_token(.doc_comment)) |tok| {
        var first_line = tok;
        if (tok > 0 and tokens_on_same_line(p, tok - 1, tok)) {
            try p.warn_msg(.{
                .tag = .same_line_doc_comment,
                .token = tok,
            });
            first_line = p.eat_token(.doc_comment) orelse return null;
        }
        while (p.eat_token(.doc_comment)) |_| {}
        return first_line;
    }
    return null;
}

fn tokens_on_same_line(p: *Parse, token1: TokenIndex, token2: TokenIndex) bool {
    return std.mem.index_of_scalar(u8, p.source[p.token_starts[token1]..p.token_starts[token2]], '\n') == null;
}

fn eat_token(p: *Parse, tag: Token.Tag) ?TokenIndex {
    return if (p.token_tags[p.tok_i] == tag) p.next_token() else null;
}

fn assert_token(p: *Parse, tag: Token.Tag) TokenIndex {
    const token = p.next_token();
    assert(p.token_tags[token] == tag);
    return token;
}

fn expect_token(p: *Parse, tag: Token.Tag) Error!TokenIndex {
    if (p.token_tags[p.tok_i] != tag) {
        return p.fail_msg(.{
            .tag = .expected_token,
            .token = p.tok_i,
            .extra = .{ .expected_tag = tag },
        });
    }
    return p.next_token();
}

fn expect_semicolon(p: *Parse, error_tag: AstError.Tag, recoverable: bool) Error!void {
    if (p.token_tags[p.tok_i] == .semicolon) {
        _ = p.next_token();
        return;
    }
    try p.warn(error_tag);
    if (!recoverable) return error.ParseError;
}

fn next_token(p: *Parse) TokenIndex {
    const result = p.tok_i;
    p.tok_i += 1;
    return result;
}

const null_node: Node.Index = 0;

const Parse = @This();
const std = @import("../std.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Node = Ast.Node;
const AstError = Ast.Error;
const TokenIndex = Ast.TokenIndex;
const Token = std.zig.Token;

test {
    _ = @import("parser_test.zig");
}
