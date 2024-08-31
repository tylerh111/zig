/// Delete this to find out where URL escaping needs to be added.
const missing_feature_url_escape = true;

const gpa = std.heap.wasm_allocator;

const std = @import("std");
const log = std.log;
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const Walk = @import("Walk.zig");
const markdown = @import("markdown.zig");
const Decl = @import("Decl.zig");

const js = struct {
    extern "js" fn log(ptr: [*]const u8, len: usize) void;
    extern "js" fn panic(ptr: [*]const u8, len: usize) noreturn;
};

pub const std_options: std.Options = .{
    .log_fn = log_fn,
    //.log_level = .debug,
};

pub fn panic(msg: []const u8, st: ?*std.builtin.StackTrace, addr: ?usize) noreturn {
    _ = st;
    _ = addr;
    log.err("panic: {s}", .{msg});
    @trap();
}

fn log_fn(
    comptime message_level: log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime message_level.as_text();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tag_name(scope) ++ "): ";
    var buf: [500]u8 = undefined;
    const line = std.fmt.buf_print(&buf, level_txt ++ prefix2 ++ format, args) catch l: {
        buf[buf.len - 3 ..][0..3].* = "...".*;
        break :l &buf;
    };
    js.log(line.ptr, line.len);
}

export fn alloc(n: usize) [*]u8 {
    const slice = gpa.alloc(u8, n) catch @panic("OOM");
    return slice.ptr;
}

export fn unpack(tar_ptr: [*]u8, tar_len: usize) void {
    const tar_bytes = tar_ptr[0..tar_len];
    //log.debug("received {d} bytes of tar file", .{tar_bytes.len});

    unpack_inner(tar_bytes) catch |err| {
        fatal("unable to unpack tar: {s}", .{@errorName(err)});
    };
}

var query_string: std.ArrayListUnmanaged(u8) = .{};
var query_results: std.ArrayListUnmanaged(Decl.Index) = .{};

/// Resizes the query string to be the correct length; returns the pointer to
/// the query string.
export fn query_begin(query_string_len: usize) [*]u8 {
    query_string.resize(gpa, query_string_len) catch @panic("OOM");
    return query_string.items.ptr;
}

/// Executes the query. Returns the pointer to the query results which is an
/// array of u32.
/// The first element is the length of the array.
/// Subsequent elements are Decl.Index values which are all public
/// declarations.
export fn query_exec(ignore_case: bool) [*]Decl.Index {
    const query = query_string.items;
    log.debug("querying '{s}'", .{query});
    query_exec_fallible(query, ignore_case) catch |err| switch (err) {
        error.OutOfMemory => @panic("OOM"),
    };
    query_results.items[0] = @enumFromInt(query_results.items.len - 1);
    return query_results.items.ptr;
}

const max_matched_items = 1000;

fn query_exec_fallible(query: []const u8, ignore_case: bool) !void {
    const Score = packed struct(u32) {
        points: u16,
        segments: u16,
    };
    const g = struct {
        var full_path_search_text: std.ArrayListUnmanaged(u8) = .{};
        var full_path_search_text_lower: std.ArrayListUnmanaged(u8) = .{};
        var doc_search_text: std.ArrayListUnmanaged(u8) = .{};
        /// Each element matches a corresponding query_results element.
        var scores: std.ArrayListUnmanaged(Score) = .{};
    };

    // First element stores the size of the list.
    try query_results.resize(gpa, 1);
    // Corresponding point value is meaningless and therefore undefined.
    try g.scores.resize(gpa, 1);

    decl_loop: for (Walk.decls.items, 0..) |*decl, decl_index| {
        const info = decl.extra_info();
        if (!info.is_pub) continue;

        try decl.reset_with_path(&g.full_path_search_text);
        if (decl.parent != .none)
            try Decl.append_parent_ns(&g.full_path_search_text, decl.parent);
        try g.full_path_search_text.append_slice(gpa, info.name);

        try g.full_path_search_text_lower.resize(gpa, g.full_path_search_text.items.len);
        @memcpy(g.full_path_search_text_lower.items, g.full_path_search_text.items);

        const ast = decl.file.get_ast();
        try collect_docs(&g.doc_search_text, ast, info.first_doc_comment);

        if (ignore_case) {
            ascii_lower(g.full_path_search_text_lower.items);
            ascii_lower(g.doc_search_text.items);
        }

        var it = std.mem.tokenize_scalar(u8, query, ' ');
        var points: u16 = 0;
        var bypass_limit = false;
        while (it.next()) |term| {
            // exact, case sensitive match of full decl path
            if (std.mem.eql(u8, g.full_path_search_text.items, term)) {
                points += 4;
                bypass_limit = true;
                continue;
            }
            // exact, case sensitive match of just decl name
            if (std.mem.eql(u8, info.name, term)) {
                points += 3;
                bypass_limit = true;
                continue;
            }
            // substring, case insensitive match of full decl path
            if (std.mem.index_of(u8, g.full_path_search_text_lower.items, term) != null) {
                points += 2;
                continue;
            }
            if (std.mem.index_of(u8, g.doc_search_text.items, term) != null) {
                points += 1;
                continue;
            }
            continue :decl_loop;
        }

        if (query_results.items.len < max_matched_items or bypass_limit) {
            try query_results.append(gpa, @enumFromInt(decl_index));
            try g.scores.append(gpa, .{
                .points = points,
                .segments = @int_cast(count_scalar(g.full_path_search_text.items, '.')),
            });
        }
    }

    const sort_context: struct {
        pub fn swap(sc: @This(), a_index: usize, b_index: usize) void {
            _ = sc;
            std.mem.swap(Score, &g.scores.items[a_index], &g.scores.items[b_index]);
            std.mem.swap(Decl.Index, &query_results.items[a_index], &query_results.items[b_index]);
        }

        pub fn less_than(sc: @This(), a_index: usize, b_index: usize) bool {
            _ = sc;
            const a_score = g.scores.items[a_index];
            const b_score = g.scores.items[b_index];
            if (b_score.points < a_score.points) {
                return true;
            } else if (b_score.points > a_score.points) {
                return false;
            } else if (a_score.segments < b_score.segments) {
                return true;
            } else if (a_score.segments > b_score.segments) {
                return false;
            } else {
                const a_decl = query_results.items[a_index];
                const b_decl = query_results.items[b_index];
                const a_file_path = a_decl.get().file.path();
                const b_file_path = b_decl.get().file.path();
                // This neglects to check the local namespace inside the file.
                return std.mem.less_than(u8, b_file_path, a_file_path);
            }
        }
    } = .{};

    std.mem.sort_unstable_context(1, query_results.items.len, sort_context);

    if (query_results.items.len > max_matched_items)
        query_results.shrink_retaining_capacity(max_matched_items);
}

const String = Slice(u8);

fn Slice(T: type) type {
    return packed struct(u64) {
        ptr: u32,
        len: u32,

        fn init(s: []const T) @This() {
            return .{
                .ptr = @int_from_ptr(s.ptr),
                .len = s.len,
            };
        }
    };
}

const ErrorIdentifier = packed struct(u64) {
    token_index: Ast.TokenIndex,
    decl_index: Decl.Index,

    fn has_docs(ei: ErrorIdentifier) bool {
        const decl_index = ei.decl_index;
        const ast = decl_index.get().file.get_ast();
        const token_tags = ast.tokens.items(.tag);
        const token_index = ei.token_index;
        if (token_index == 0) return false;
        return token_tags[token_index - 1] == .doc_comment;
    }

    fn html(ei: ErrorIdentifier, base_decl: Decl.Index, out: *std.ArrayListUnmanaged(u8)) Oom!void {
        const decl_index = ei.decl_index;
        const ast = decl_index.get().file.get_ast();
        const name = ast.token_slice(ei.token_index);
        const first_doc_comment = Decl.find_first_doc_comment(ast, ei.token_index);
        const has_docs = ast.tokens.items(.tag)[first_doc_comment] == .doc_comment;
        const has_link = base_decl != decl_index;

        try out.append_slice(gpa, "<dt>");
        try out.append_slice(gpa, name);
        if (has_link) {
            try out.append_slice(gpa, " <a href=\"#");
            _ = missing_feature_url_escape;
            try decl_index.get().fqn(out);
            try out.append_slice(gpa, "\">");
            try out.append_slice(gpa, decl_index.get().extra_info().name);
            try out.append_slice(gpa, "</a>");
        }
        try out.append_slice(gpa, "</dt>");

        if (has_docs) {
            try out.append_slice(gpa, "<dd>");
            try render_docs(out, decl_index, first_doc_comment, false);
            try out.append_slice(gpa, "</dd>");
        }
    }
};

var string_result: std.ArrayListUnmanaged(u8) = .{};
var error_set_result: std.StringArrayHashMapUnmanaged(ErrorIdentifier) = .{};

export fn decl_error_set(decl_index: Decl.Index) Slice(ErrorIdentifier) {
    return Slice(ErrorIdentifier).init(decl_error_set_fallible(decl_index) catch @panic("OOM"));
}

export fn error_set_node_list(base_decl: Decl.Index, node: Ast.Node.Index) Slice(ErrorIdentifier) {
    error_set_result.clear_retaining_capacity();
    add_errors_from_expr(base_decl, &error_set_result, node) catch @panic("OOM");
    sort_error_set_result();
    return Slice(ErrorIdentifier).init(error_set_result.values());
}

export fn fn_error_set_decl(decl_index: Decl.Index, node: Ast.Node.Index) Decl.Index {
    return switch (decl_index.get().file.categorize_expr(node)) {
        .alias => |aliasee| fn_error_set_decl(aliasee, aliasee.get().ast_node),
        else => decl_index,
    };
}

export fn decl_field_count(decl_index: Decl.Index) u32 {
    switch (decl_index.get().categorize()) {
        .namespace => |node| return decl_index.get().file.get().field_count(node),
        else => return 0,
    }
}

fn decl_error_set_fallible(decl_index: Decl.Index) Oom![]ErrorIdentifier {
    error_set_result.clear_retaining_capacity();
    try add_errors_from_decl(decl_index, &error_set_result);
    sort_error_set_result();
    return error_set_result.values();
}

fn sort_error_set_result() void {
    const sort_context: struct {
        pub fn less_than(sc: @This(), a_index: usize, b_index: usize) bool {
            _ = sc;
            const a_name = error_set_result.keys()[a_index];
            const b_name = error_set_result.keys()[b_index];
            return std.mem.less_than(u8, a_name, b_name);
        }
    } = .{};
    error_set_result.sort_unstable(sort_context);
}

fn add_errors_from_decl(
    decl_index: Decl.Index,
    out: *std.StringArrayHashMapUnmanaged(ErrorIdentifier),
) Oom!void {
    switch (decl_index.get().categorize()) {
        .error_set => |node| try add_errors_from_expr(decl_index, out, node),
        .alias => |aliasee| try add_errors_from_decl(aliasee, out),
        else => |cat| log.debug("unable to add_errors_from_decl: {any}", .{cat}),
    }
}

fn add_errors_from_expr(
    decl_index: Decl.Index,
    out: *std.StringArrayHashMapUnmanaged(ErrorIdentifier),
    node: Ast.Node.Index,
) Oom!void {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);

    switch (decl.file.categorize_expr(node)) {
        .error_set => |n| switch (node_tags[n]) {
            .error_set_decl => {
                try add_errors_from_node(decl_index, out, node);
            },
            .merge_error_sets => {
                try add_errors_from_expr(decl_index, out, node_datas[node].lhs);
                try add_errors_from_expr(decl_index, out, node_datas[node].rhs);
            },
            else => unreachable,
        },
        .alias => |aliasee| {
            try add_errors_from_decl(aliasee, out);
        },
        else => return,
    }
}

fn add_errors_from_node(
    decl_index: Decl.Index,
    out: *std.StringArrayHashMapUnmanaged(ErrorIdentifier),
    node: Ast.Node.Index,
) Oom!void {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const main_tokens = ast.nodes.items(.main_token);
    const token_tags = ast.tokens.items(.tag);
    const error_token = main_tokens[node];
    var tok_i = error_token + 2;
    while (true) : (tok_i += 1) switch (token_tags[tok_i]) {
        .doc_comment, .comma => {},
        .identifier => {
            const name = ast.token_slice(tok_i);
            const gop = try out.get_or_put(gpa, name);
            // If there are more than one, take the one with doc comments.
            // If they both have doc comments, prefer the existing one.
            const new: ErrorIdentifier = .{
                .token_index = tok_i,
                .decl_index = decl_index,
            };
            if (!gop.found_existing or
                (!gop.value_ptr.has_docs() and new.has_docs()))
            {
                gop.value_ptr.* = new;
            }
        },
        .r_brace => break,
        else => unreachable,
    };
}

export fn type_fn_fields(decl_index: Decl.Index) Slice(Ast.Node.Index) {
    return decl_fields(decl_index);
}

export fn decl_fields(decl_index: Decl.Index) Slice(Ast.Node.Index) {
    return Slice(Ast.Node.Index).init(decl_fields_fallible(decl_index) catch @panic("OOM"));
}

export fn decl_params(decl_index: Decl.Index) Slice(Ast.Node.Index) {
    return Slice(Ast.Node.Index).init(decl_params_fallible(decl_index) catch @panic("OOM"));
}

fn decl_fields_fallible(decl_index: Decl.Index) ![]Ast.Node.Index {
    const g = struct {
        var result: std.ArrayListUnmanaged(Ast.Node.Index) = .{};
    };
    g.result.clear_retaining_capacity();
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const node_tags = ast.nodes.items(.tag);
    const value_node = decl.value_node() orelse return &.{};
    var buf: [2]Ast.Node.Index = undefined;
    const container_decl = ast.full_container_decl(&buf, value_node) orelse return &.{};
    for (container_decl.ast.members) |member_node| switch (node_tags[member_node]) {
        .container_field_init,
        .container_field_align,
        .container_field,
        => try g.result.append(gpa, member_node),

        else => continue,
    };
    return g.result.items;
}

fn decl_params_fallible(decl_index: Decl.Index) ![]Ast.Node.Index {
    const g = struct {
        var result: std.ArrayListUnmanaged(Ast.Node.Index) = .{};
    };
    g.result.clear_retaining_capacity();
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const value_node = decl.value_node() orelse return &.{};
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = ast.full_fn_proto(&buf, value_node) orelse return &.{};
    try g.result.append_slice(gpa, fn_proto.ast.params);
    return g.result.items;
}

export fn error_html(base_decl: Decl.Index, error_identifier: ErrorIdentifier) String {
    string_result.clear_retaining_capacity();
    error_identifier.html(base_decl, &string_result) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_field_html(decl_index: Decl.Index, field_node: Ast.Node.Index) String {
    string_result.clear_retaining_capacity();
    decl_field_html_fallible(&string_result, decl_index, field_node) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_param_html(decl_index: Decl.Index, param_node: Ast.Node.Index) String {
    string_result.clear_retaining_capacity();
    decl_param_html_fallible(&string_result, decl_index, param_node) catch @panic("OOM");
    return String.init(string_result.items);
}

fn decl_field_html_fallible(
    out: *std.ArrayListUnmanaged(u8),
    decl_index: Decl.Index,
    field_node: Ast.Node.Index,
) !void {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    try out.append_slice(gpa, "<pre><code>");
    try file_source_html(decl.file, out, field_node, .{});
    try out.append_slice(gpa, "</code></pre>");

    const field = ast.full_container_field(field_node).?;
    const first_doc_comment = Decl.find_first_doc_comment(ast, field.first_token());

    if (ast.tokens.items(.tag)[first_doc_comment] == .doc_comment) {
        try out.append_slice(gpa, "<div class=\"fieldDocs\">");
        try render_docs(out, decl_index, first_doc_comment, false);
        try out.append_slice(gpa, "</div>");
    }
}

fn decl_param_html_fallible(
    out: *std.ArrayListUnmanaged(u8),
    decl_index: Decl.Index,
    param_node: Ast.Node.Index,
) !void {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const token_tags = ast.tokens.items(.tag);
    const colon = ast.first_token(param_node) - 1;
    const name_token = colon - 1;
    const first_doc_comment = f: {
        var it = ast.first_token(param_node);
        while (it > 0) {
            it -= 1;
            switch (token_tags[it]) {
                .doc_comment, .colon, .identifier, .keyword_comptime, .keyword_noalias => {},
                else => break,
            }
        }
        break :f it + 1;
    };
    const name = ast.token_slice(name_token);

    try out.append_slice(gpa, "<pre><code>");
    try append_escaped(out, name);
    try out.append_slice(gpa, ": ");
    try file_source_html(decl.file, out, param_node, .{});
    try out.append_slice(gpa, "</code></pre>");

    if (ast.tokens.items(.tag)[first_doc_comment] == .doc_comment) {
        try out.append_slice(gpa, "<div class=\"fieldDocs\">");
        try render_docs(out, decl_index, first_doc_comment, false);
        try out.append_slice(gpa, "</div>");
    }
}

export fn decl_fn_proto_html(decl_index: Decl.Index, linkify_fn_name: bool) String {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);
    const proto_node = switch (node_tags[decl.ast_node]) {
        .fn_decl => node_datas[decl.ast_node].lhs,

        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        => decl.ast_node,

        else => unreachable,
    };

    string_result.clear_retaining_capacity();
    file_source_html(decl.file, &string_result, proto_node, .{
        .skip_doc_comments = true,
        .skip_comments = true,
        .collapse_whitespace = true,
        .fn_link = if (linkify_fn_name) decl_index else .none,
    }) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_source_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();

    string_result.clear_retaining_capacity();
    file_source_html(decl.file, &string_result, decl.ast_node, .{}) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_doctest_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const doctest_ast_node = decl.file.get().doctests.get(decl.ast_node) orelse
        return String.init("");

    string_result.clear_retaining_capacity();
    file_source_html(decl.file, &string_result, doctest_ast_node, .{}) catch |err| {
        fatal("unable to render source: {s}", .{@errorName(err)});
    };
    return String.init(string_result.items);
}

export fn decl_fqn(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    string_result.clear_retaining_capacity();
    decl.fqn(&string_result) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_parent(decl_index: Decl.Index) Decl.Index {
    const decl = decl_index.get();
    return decl.parent;
}

export fn fn_error_set(decl_index: Decl.Index) Ast.Node.Index {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    var buf: [1]Ast.Node.Index = undefined;
    const full = ast.full_fn_proto(&buf, decl.ast_node).?;
    const node_tags = ast.nodes.items(.tag);
    const node_datas = ast.nodes.items(.data);
    return switch (node_tags[full.ast.return_type]) {
        .error_set_decl => full.ast.return_type,
        .error_union => node_datas[full.ast.return_type].lhs,
        else => 0,
    };
}

export fn decl_file_path(decl_index: Decl.Index) String {
    string_result.clear_retaining_capacity();
    string_result.append_slice(gpa, decl_index.get().file.path()) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_category_name(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const token_tags = ast.tokens.items(.tag);
    const name = switch (decl.categorize()) {
        .namespace => |node| {
            const node_tags = ast.nodes.items(.tag);
            if (node_tags[decl.ast_node] == .root)
                return String.init("struct");
            string_result.clear_retaining_capacity();
            var buf: [2]Ast.Node.Index = undefined;
            const container_decl = ast.full_container_decl(&buf, node).?;
            if (container_decl.layout_token) |t| {
                if (token_tags[t] == .keyword_extern) {
                    string_result.append_slice(gpa, "extern ") catch @panic("OOM");
                }
            }
            const main_token_tag = token_tags[container_decl.ast.main_token];
            string_result.append_slice(gpa, main_token_tag.lexeme().?) catch @panic("OOM");
            return String.init(string_result.items);
        },
        .global_variable => "Global Variable",
        .function => "Function",
        .type_function => "Type Function",
        .type, .type_type => "Type",
        .error_set => "Error Set",
        .global_const => "Constant",
        .primitive => "Primitive Value",
        .alias => "Alias",
    };
    return String.init(name);
}

export fn decl_name(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    string_result.clear_retaining_capacity();
    const name = n: {
        if (decl.parent == .none) {
            // Then it is the root struct of a file.
            break :n std.fs.path.stem(decl.file.path());
        }
        break :n decl.extra_info().name;
    };
    string_result.append_slice(gpa, name) catch @panic("OOM");
    return String.init(string_result.items);
}

export fn decl_docs_html(decl_index: Decl.Index, short: bool) String {
    const decl = decl_index.get();
    string_result.clear_retaining_capacity();
    render_docs(&string_result, decl_index, decl.extra_info().first_doc_comment, short) catch @panic("OOM");
    return String.init(string_result.items);
}

fn collect_docs(
    list: *std.ArrayListUnmanaged(u8),
    ast: *const Ast,
    first_doc_comment: Ast.TokenIndex,
) Oom!void {
    const token_tags = ast.tokens.items(.tag);
    list.clear_retaining_capacity();
    var it = first_doc_comment;
    while (true) : (it += 1) switch (token_tags[it]) {
        .doc_comment, .container_doc_comment => {
            // It is tempting to trim this string but think carefully about how
            // that will affect the markdown parser.
            const line = ast.token_slice(it)[3..];
            try list.append_slice(gpa, line);
        },
        else => break,
    };
}

fn render_docs(
    out: *std.ArrayListUnmanaged(u8),
    decl_index: Decl.Index,
    first_doc_comment: Ast.TokenIndex,
    short: bool,
) Oom!void {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    const token_tags = ast.tokens.items(.tag);

    var parser = try markdown.Parser.init(gpa);
    defer parser.deinit();
    var it = first_doc_comment;
    while (true) : (it += 1) switch (token_tags[it]) {
        .doc_comment, .container_doc_comment => {
            const line = ast.token_slice(it)[3..];
            if (short and line.len == 0) break;
            try parser.feed_line(line);
        },
        else => break,
    };

    var parsed_doc = try parser.end_input();
    defer parsed_doc.deinit(gpa);

    const g = struct {
        var link_buffer: std.ArrayListUnmanaged(u8) = .{};
    };

    const Writer = std.ArrayListUnmanaged(u8).Writer;
    const Renderer = markdown.Renderer(Writer, Decl.Index);
    const renderer: Renderer = .{
        .context = decl_index,
        .render_fn = struct {
            fn render(
                r: Renderer,
                doc: markdown.Document,
                node: markdown.Document.Node.Index,
                writer: Writer,
            ) !void {
                const data = doc.nodes.items(.data)[@int_from_enum(node)];
                switch (doc.nodes.items(.tag)[@int_from_enum(node)]) {
                    .code_span => {
                        try writer.write_all("<code>");
                        const content = doc.string(data.text.content);
                        if (resolve_decl_path(r.context, content)) |resolved_decl_index| {
                            g.link_buffer.clear_retaining_capacity();
                            try resolve_decl_link(resolved_decl_index, &g.link_buffer);

                            try writer.write_all("<a href=\"#");
                            _ = missing_feature_url_escape;
                            try writer.write_all(g.link_buffer.items);
                            try writer.print("\">{}</a>", .{markdown.fmt_html(content)});
                        } else {
                            try writer.print("{}", .{markdown.fmt_html(content)});
                        }

                        try writer.write_all("</code>");
                    },

                    else => try Renderer.render_default(r, doc, node, writer),
                }
            }
        }.render,
    };
    try renderer.render(parsed_doc, out.writer(gpa));
}

fn resolve_decl_path(decl_index: Decl.Index, path: []const u8) ?Decl.Index {
    var path_components = std.mem.split_scalar(u8, path, '.');
    var current_decl_index = decl_index.get().lookup(path_components.first()) orelse return null;
    while (path_components.next()) |component| {
        switch (current_decl_index.get().categorize()) {
            .alias => |aliasee| current_decl_index = aliasee,
            else => {},
        }
        current_decl_index = current_decl_index.get().get_child(component) orelse return null;
    }
    return current_decl_index;
}

export fn decl_type_html(decl_index: Decl.Index) String {
    const decl = decl_index.get();
    const ast = decl.file.get_ast();
    string_result.clear_retaining_capacity();
    t: {
        // If there is an explicit type, use it.
        if (ast.full_var_decl(decl.ast_node)) |var_decl| {
            if (var_decl.ast.type_node != 0) {
                string_result.append_slice(gpa, "<code>") catch @panic("OOM");
                file_source_html(decl.file, &string_result, var_decl.ast.type_node, .{
                    .skip_comments = true,
                    .collapse_whitespace = true,
                }) catch |e| {
                    fatal("unable to render html: {s}", .{@errorName(e)});
                };
                string_result.append_slice(gpa, "</code>") catch @panic("OOM");
                break :t;
            }
        }
    }
    return String.init(string_result.items);
}

const Oom = error{OutOfMemory};

fn unpack_inner(tar_bytes: []u8) !void {
    var fbs = std.io.fixed_buffer_stream(tar_bytes);
    var file_name_buffer: [1024]u8 = undefined;
    var link_name_buffer: [1024]u8 = undefined;
    var it = std.tar.iterator(fbs.reader(), .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });
    while (try it.next()) |tar_file| {
        switch (tar_file.kind) {
            .file => {
                if (tar_file.size == 0 and tar_file.name.len == 0) break;
                if (std.mem.ends_with(u8, tar_file.name, ".zig")) {
                    log.debug("found file: '{s}'", .{tar_file.name});
                    const file_name = try gpa.dupe(u8, tar_file.name);
                    if (std.mem.index_of_scalar(u8, file_name, '/')) |pkg_name_end| {
                        const pkg_name = file_name[0..pkg_name_end];
                        const gop = try Walk.modules.get_or_put(gpa, pkg_name);
                        const file: Walk.File.Index = @enumFromInt(Walk.files.entries.len);
                        if (!gop.found_existing or
                            std.mem.eql(u8, file_name[pkg_name_end..], "/root.zig") or
                            std.mem.eql(u8, file_name[pkg_name_end + 1 .. file_name.len - ".zig".len], pkg_name))
                        {
                            gop.value_ptr.* = file;
                        }
                        const file_bytes = tar_bytes[fbs.pos..][0..@int_cast(tar_file.size)];
                        assert(file == try Walk.add_file(file_name, file_bytes));
                    }
                } else {
                    log.warn("skipping: '{s}' - the tar creation should have done that", .{
                        tar_file.name,
                    });
                }
            },
            else => continue,
        }
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    var buf: [500]u8 = undefined;
    const line = std.fmt.buf_print(&buf, format, args) catch l: {
        buf[buf.len - 3 ..][0..3].* = "...".*;
        break :l &buf;
    };
    js.panic(line.ptr, line.len);
}

fn ascii_lower(bytes: []u8) void {
    for (bytes) |*b| b.* = std.ascii.to_lower(b.*);
}

export fn module_name(index: u32) String {
    const names = Walk.modules.keys();
    return String.init(if (index >= names.len) "" else names[index]);
}

export fn find_module_root(pkg: Walk.ModuleIndex) Decl.Index {
    const root_file = Walk.modules.values()[@int_from_enum(pkg)];
    const result = root_file.find_root_decl();
    assert(result != .none);
    return result;
}

/// Set by `set_input_string`.
var input_string: std.ArrayListUnmanaged(u8) = .{};

export fn set_input_string(len: usize) [*]u8 {
    input_string.resize(gpa, len) catch @panic("OOM");
    return input_string.items.ptr;
}

/// Looks up the root struct decl corresponding to a file by path.
/// Uses `input_string`.
export fn find_file_root() Decl.Index {
    const file: Walk.File.Index = @enumFromInt(Walk.files.get_index(input_string.items) orelse return .none);
    return file.find_root_decl();
}

/// Uses `input_string`.
/// Tries to look up the Decl component-wise but then falls back to a file path
/// based scan.
export fn find_decl() Decl.Index {
    const result = Decl.find(input_string.items);
    if (result != .none) return result;

    const g = struct {
        var match_fqn: std.ArrayListUnmanaged(u8) = .{};
    };
    for (Walk.decls.items, 0..) |*decl, decl_index| {
        g.match_fqn.clear_retaining_capacity();
        decl.fqn(&g.match_fqn) catch @panic("OOM");
        if (std.mem.eql(u8, g.match_fqn.items, input_string.items)) {
            //const path = @as(Decl.Index, @enumFromInt(decl_index)).get().file.path();
            //log.debug("find_decl '{s}' found in {s}", .{ input_string.items, path });
            return @enumFromInt(decl_index);
        }
    }
    return .none;
}

/// Set only by `categorize_decl`; read only by `get_aliasee`, valid only
/// when `categorize_decl` returns `.alias`.
var global_aliasee: Decl.Index = .none;

export fn get_aliasee() Decl.Index {
    return global_aliasee;
}
export fn categorize_decl(decl_index: Decl.Index, resolve_alias_count: usize) Walk.Category.Tag {
    global_aliasee = .none;
    var chase_alias_n = resolve_alias_count;
    var decl = decl_index.get();
    while (true) {
        const result = decl.categorize();
        switch (result) {
            .alias => |new_index| {
                assert(new_index != .none);
                global_aliasee = new_index;
                if (chase_alias_n > 0) {
                    chase_alias_n -= 1;
                    decl = new_index.get();
                    continue;
                }
            },
            else => {},
        }
        return result;
    }
}

export fn type_fn_members(parent: Decl.Index, include_private: bool) Slice(Decl.Index) {
    return namespace_members(parent, include_private);
}

export fn namespace_members(parent: Decl.Index, include_private: bool) Slice(Decl.Index) {
    const g = struct {
        var members: std.ArrayListUnmanaged(Decl.Index) = .{};
    };

    g.members.clear_retaining_capacity();

    for (Walk.decls.items, 0..) |*decl, i| {
        if (decl.parent == parent) {
            if (include_private or decl.is_pub()) {
                g.members.append(gpa, @enumFromInt(i)) catch @panic("OOM");
            }
        }
    }

    return Slice(Decl.Index).init(g.members.items);
}

const RenderSourceOptions = struct {
    skip_doc_comments: bool = false,
    skip_comments: bool = false,
    collapse_whitespace: bool = false,
    fn_link: Decl.Index = .none,
};

fn file_source_html(
    file_index: Walk.File.Index,
    out: *std.ArrayListUnmanaged(u8),
    root_node: Ast.Node.Index,
    options: RenderSourceOptions,
) !void {
    const ast = file_index.get_ast();
    const file = file_index.get();

    const g = struct {
        var field_access_buffer: std.ArrayListUnmanaged(u8) = .{};
    };

    const token_tags = ast.tokens.items(.tag);
    const token_starts = ast.tokens.items(.start);
    const main_tokens = ast.nodes.items(.main_token);

    const start_token = ast.first_token(root_node);
    const end_token = ast.last_token(root_node) + 1;

    var cursor: usize = token_starts[start_token];

    var indent: usize = 0;
    if (std.mem.last_index_of(u8, ast.source[0..cursor], "\n")) |newline_index| {
        for (ast.source[newline_index + 1 .. cursor]) |c| {
            if (c == ' ') {
                indent += 1;
            } else {
                break;
            }
        }
    }

    for (
        token_tags[start_token..end_token],
        token_starts[start_token..end_token],
        start_token..,
    ) |tag, start, token_index| {
        const between = ast.source[cursor..start];
        if (std.mem.trim(u8, between, " \t\r\n").len > 0) {
            if (!options.skip_comments) {
                try out.append_slice(gpa, "<span class=\"tok-comment\">");
                try append_unindented(out, between, indent);
                try out.append_slice(gpa, "</span>");
            }
        } else if (between.len > 0) {
            if (options.collapse_whitespace) {
                if (out.items.len > 0 and out.items[out.items.len - 1] != ' ')
                    try out.append(gpa, ' ');
            } else {
                try append_unindented(out, between, indent);
            }
        }
        if (tag == .eof) break;
        const slice = ast.token_slice(token_index);
        cursor = start + slice.len;
        switch (tag) {
            .eof => unreachable,

            .keyword_addrspace,
            .keyword_align,
            .keyword_and,
            .keyword_asm,
            .keyword_async,
            .keyword_await,
            .keyword_break,
            .keyword_catch,
            .keyword_comptime,
            .keyword_const,
            .keyword_continue,
            .keyword_defer,
            .keyword_else,
            .keyword_enum,
            .keyword_errdefer,
            .keyword_error,
            .keyword_export,
            .keyword_extern,
            .keyword_for,
            .keyword_if,
            .keyword_inline,
            .keyword_noalias,
            .keyword_noinline,
            .keyword_nosuspend,
            .keyword_opaque,
            .keyword_or,
            .keyword_orelse,
            .keyword_packed,
            .keyword_anyframe,
            .keyword_pub,
            .keyword_resume,
            .keyword_return,
            .keyword_linksection,
            .keyword_callconv,
            .keyword_struct,
            .keyword_suspend,
            .keyword_switch,
            .keyword_test,
            .keyword_threadlocal,
            .keyword_try,
            .keyword_union,
            .keyword_unreachable,
            .keyword_usingnamespace,
            .keyword_var,
            .keyword_volatile,
            .keyword_allowzero,
            .keyword_while,
            .keyword_anytype,
            .keyword_fn,
            => {
                try out.append_slice(gpa, "<span class=\"tok-kw\">");
                try append_escaped(out, slice);
                try out.append_slice(gpa, "</span>");
            },

            .string_literal,
            .char_literal,
            .multiline_string_literal_line,
            => {
                try out.append_slice(gpa, "<span class=\"tok-str\">");
                try append_escaped(out, slice);
                try out.append_slice(gpa, "</span>");
            },

            .builtin => {
                try out.append_slice(gpa, "<span class=\"tok-builtin\">");
                try append_escaped(out, slice);
                try out.append_slice(gpa, "</span>");
            },

            .doc_comment,
            .container_doc_comment,
            => {
                if (!options.skip_doc_comments) {
                    try out.append_slice(gpa, "<span class=\"tok-comment\">");
                    try append_escaped(out, slice);
                    try out.append_slice(gpa, "</span>");
                }
            },

            .identifier => i: {
                if (options.fn_link != .none) {
                    const fn_link = options.fn_link.get();
                    const fn_token = main_tokens[fn_link.ast_node];
                    if (token_index == fn_token + 1) {
                        try out.append_slice(gpa, "<a class=\"tok-fn\" href=\"#");
                        _ = missing_feature_url_escape;
                        try fn_link.fqn(out);
                        try out.append_slice(gpa, "\">");
                        try append_escaped(out, slice);
                        try out.append_slice(gpa, "</a>");
                        break :i;
                    }
                }

                if (token_index > 0 and token_tags[token_index - 1] == .keyword_fn) {
                    try out.append_slice(gpa, "<span class=\"tok-fn\">");
                    try append_escaped(out, slice);
                    try out.append_slice(gpa, "</span>");
                    break :i;
                }

                if (Walk.is_primitive_non_type(slice)) {
                    try out.append_slice(gpa, "<span class=\"tok-null\">");
                    try append_escaped(out, slice);
                    try out.append_slice(gpa, "</span>");
                    break :i;
                }

                if (std.zig.primitives.is_primitive(slice)) {
                    try out.append_slice(gpa, "<span class=\"tok-type\">");
                    try append_escaped(out, slice);
                    try out.append_slice(gpa, "</span>");
                    break :i;
                }

                if (file.token_parents.get(token_index)) |field_access_node| {
                    g.field_access_buffer.clear_retaining_capacity();
                    try walk_field_accesses(file_index, &g.field_access_buffer, field_access_node);
                    if (g.field_access_buffer.items.len > 0) {
                        try out.append_slice(gpa, "<a href=\"#");
                        _ = missing_feature_url_escape;
                        try out.append_slice(gpa, g.field_access_buffer.items);
                        try out.append_slice(gpa, "\">");
                        try append_escaped(out, slice);
                        try out.append_slice(gpa, "</a>");
                    } else {
                        try append_escaped(out, slice);
                    }
                    break :i;
                }

                {
                    g.field_access_buffer.clear_retaining_capacity();
                    try resolve_ident_link(file_index, &g.field_access_buffer, token_index);
                    if (g.field_access_buffer.items.len > 0) {
                        try out.append_slice(gpa, "<a href=\"#");
                        _ = missing_feature_url_escape;
                        try out.append_slice(gpa, g.field_access_buffer.items);
                        try out.append_slice(gpa, "\">");
                        try append_escaped(out, slice);
                        try out.append_slice(gpa, "</a>");
                        break :i;
                    }
                }

                try append_escaped(out, slice);
            },

            .number_literal => {
                try out.append_slice(gpa, "<span class=\"tok-number\">");
                try append_escaped(out, slice);
                try out.append_slice(gpa, "</span>");
            },

            .bang,
            .pipe,
            .pipe_pipe,
            .pipe_equal,
            .equal,
            .equal_equal,
            .equal_angle_bracket_right,
            .bang_equal,
            .l_paren,
            .r_paren,
            .semicolon,
            .percent,
            .percent_equal,
            .l_brace,
            .r_brace,
            .l_bracket,
            .r_bracket,
            .period,
            .period_asterisk,
            .ellipsis2,
            .ellipsis3,
            .caret,
            .caret_equal,
            .plus,
            .plus_plus,
            .plus_equal,
            .plus_percent,
            .plus_percent_equal,
            .plus_pipe,
            .plus_pipe_equal,
            .minus,
            .minus_equal,
            .minus_percent,
            .minus_percent_equal,
            .minus_pipe,
            .minus_pipe_equal,
            .asterisk,
            .asterisk_equal,
            .asterisk_asterisk,
            .asterisk_percent,
            .asterisk_percent_equal,
            .asterisk_pipe,
            .asterisk_pipe_equal,
            .arrow,
            .colon,
            .slash,
            .slash_equal,
            .comma,
            .ampersand,
            .ampersand_equal,
            .question_mark,
            .angle_bracket_left,
            .angle_bracket_left_equal,
            .angle_bracket_angle_bracket_left,
            .angle_bracket_angle_bracket_left_equal,
            .angle_bracket_angle_bracket_left_pipe,
            .angle_bracket_angle_bracket_left_pipe_equal,
            .angle_bracket_right,
            .angle_bracket_right_equal,
            .angle_bracket_angle_bracket_right,
            .angle_bracket_angle_bracket_right_equal,
            .tilde,
            => try append_escaped(out, slice),

            .invalid, .invalid_periodasterisks => return error.InvalidToken,
        }
    }
}

fn unindent(s: []const u8, indent: usize) []const u8 {
    var indent_idx: usize = 0;
    for (s) |c| {
        if (c == ' ' and indent_idx < indent) {
            indent_idx += 1;
        } else {
            break;
        }
    }
    return s[indent_idx..];
}

fn append_unindented(out: *std.ArrayListUnmanaged(u8), s: []const u8, indent: usize) !void {
    var it = std.mem.split(u8, s, "\n");
    var is_first_line = true;
    while (it.next()) |line| {
        if (is_first_line) {
            try append_escaped(out, line);
            is_first_line = false;
        } else {
            try out.append_slice(gpa, "\n");
            try append_escaped(out, unindent(line, indent));
        }
    }
}

fn resolve_ident_link(
    file_index: Walk.File.Index,
    out: *std.ArrayListUnmanaged(u8),
    ident_token: Ast.TokenIndex,
) Oom!void {
    const decl_index = file_index.get().lookup_token(ident_token);
    if (decl_index == .none) return;
    try resolve_decl_link(decl_index, out);
}

fn resolve_decl_link(decl_index: Decl.Index, out: *std.ArrayListUnmanaged(u8)) Oom!void {
    const decl = decl_index.get();
    switch (decl.categorize()) {
        .alias => |alias_decl| try alias_decl.get().fqn(out),
        else => try decl.fqn(out),
    }
}

fn walk_field_accesses(
    file_index: Walk.File.Index,
    out: *std.ArrayListUnmanaged(u8),
    node: Ast.Node.Index,
) Oom!void {
    const ast = file_index.get_ast();
    const node_tags = ast.nodes.items(.tag);
    assert(node_tags[node] == .field_access);
    const node_datas = ast.nodes.items(.data);
    const main_tokens = ast.nodes.items(.main_token);
    const object_node = node_datas[node].lhs;
    const dot_token = main_tokens[node];
    const field_ident = dot_token + 1;
    switch (node_tags[object_node]) {
        .identifier => {
            const lhs_ident = main_tokens[object_node];
            try resolve_ident_link(file_index, out, lhs_ident);
        },
        .field_access => {
            try walk_field_accesses(file_index, out, object_node);
        },
        else => {},
    }
    if (out.items.len > 0) {
        try out.append(gpa, '.');
        try out.append_slice(gpa, ast.token_slice(field_ident));
    }
}

fn append_escaped(out: *std.ArrayListUnmanaged(u8), s: []const u8) !void {
    for (s) |c| {
        try out.ensure_unused_capacity(gpa, 6);
        switch (c) {
            '&' => out.append_slice_assume_capacity("&amp;"),
            '<' => out.append_slice_assume_capacity("&lt;"),
            '>' => out.append_slice_assume_capacity("&gt;"),
            '"' => out.append_slice_assume_capacity("&quot;"),
            else => out.append_assume_capacity(c),
        }
    }
}

fn count_scalar(haystack: []const u8, needle: u8) usize {
    var total: usize = 0;
    for (haystack) |elem| {
        if (elem == needle)
            total += 1;
    }
    return total;
}
