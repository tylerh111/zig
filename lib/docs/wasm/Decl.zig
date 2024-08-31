ast_node: Ast.Node.Index,
file: Walk.File.Index,
/// The decl whose namespace this is in.
parent: Index,

pub const ExtraInfo = struct {
    is_pub: bool,
    name: []const u8,
    /// This might not be a doc_comment token in which case there are no doc comments.
    first_doc_comment: Ast.TokenIndex,
};

pub const Index = enum(u32) {
    none = std.math.max_int(u32),
    _,

    pub fn get(i: Index) *Decl {
        return &Walk.decls.items[@int_from_enum(i)];
    }
};

pub fn is_pub(d: *const Decl) bool {
    return d.extra_info().is_pub;
}

pub fn extra_info(d: *const Decl) ExtraInfo {
    const ast = d.file.get_ast();
    const token_tags = ast.tokens.items(.tag);
    const node_tags = ast.nodes.items(.tag);
    switch (node_tags[d.ast_node]) {
        .root => return .{
            .name = "",
            .is_pub = true,
            .first_doc_comment = if (token_tags[0] == .container_doc_comment)
                0
            else
                token_tags.len - 1,
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.full_var_decl(d.ast_node).?;
            const name_token = var_decl.ast.mut_token + 1;
            assert(token_tags[name_token] == .identifier);
            const ident_name = ast.token_slice(name_token);
            return .{
                .name = ident_name,
                .is_pub = var_decl.visib_token != null,
                .first_doc_comment = find_first_doc_comment(ast, var_decl.first_token()),
            };
        },

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = ast.full_fn_proto(&buf, d.ast_node).?;
            const name_token = fn_proto.name_token.?;
            assert(token_tags[name_token] == .identifier);
            const ident_name = ast.token_slice(name_token);
            return .{
                .name = ident_name,
                .is_pub = fn_proto.visib_token != null,
                .first_doc_comment = find_first_doc_comment(ast, fn_proto.first_token()),
            };
        },

        else => |t| {
            log.debug("hit '{s}'", .{@tag_name(t)});
            unreachable;
        },
    }
}

pub fn value_node(d: *const Decl) ?Ast.Node.Index {
    const ast = d.file.get_ast();
    const node_tags = ast.nodes.items(.tag);
    const token_tags = ast.tokens.items(.tag);
    return switch (node_tags[d.ast_node]) {
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        .root,
        => d.ast_node,

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = ast.full_var_decl(d.ast_node).?;
            if (token_tags[var_decl.ast.mut_token] == .keyword_const)
                return var_decl.ast.init_node;

            return null;
        },

        else => null,
    };
}

pub fn categorize(decl: *const Decl) Walk.Category {
    return decl.file.categorize_decl(decl.ast_node);
}

/// Looks up a direct child of `decl` by name.
pub fn get_child(decl: *const Decl, name: []const u8) ?Decl.Index {
    switch (decl.categorize()) {
        .alias => |aliasee| return aliasee.get().get_child(name),
        .namespace => |node| {
            const file = decl.file.get();
            const scope = file.scopes.get(node) orelse return null;
            const child_node = scope.get_child(name) orelse return null;
            return file.node_decls.get(child_node);
        },
        else => return null,
    }
}

/// Looks up a decl by name accessible in `decl`'s namespace.
pub fn lookup(decl: *const Decl, name: []const u8) ?Decl.Index {
    const namespace_node = switch (decl.categorize()) {
        .namespace => |node| node,
        else => decl.parent.get().ast_node,
    };
    const file = decl.file.get();
    const scope = file.scopes.get(namespace_node) orelse return null;
    const resolved_node = scope.lookup(&file.ast, name) orelse return null;
    return file.node_decls.get(resolved_node);
}

/// Appends the fully qualified name to `out`.
pub fn fqn(decl: *const Decl, out: *std.ArrayListUnmanaged(u8)) Oom!void {
    try decl.append_path(out);
    if (decl.parent != .none) {
        try append_parent_ns(out, decl.parent);
        try out.append_slice(gpa, decl.extra_info().name);
    } else {
        out.items.len -= 1; // remove the trailing '.'
    }
}

pub fn reset_with_path(decl: *const Decl, list: *std.ArrayListUnmanaged(u8)) Oom!void {
    list.clear_retaining_capacity();
    try append_path(decl, list);
}

pub fn append_path(decl: *const Decl, list: *std.ArrayListUnmanaged(u8)) Oom!void {
    const start = list.items.len;
    // Prefer the module name alias.
    for (Walk.modules.keys(), Walk.modules.values()) |pkg_name, pkg_file| {
        if (pkg_file == decl.file) {
            try list.ensure_unused_capacity(gpa, pkg_name.len + 1);
            list.append_slice_assume_capacity(pkg_name);
            list.append_assume_capacity('.');
            return;
        }
    }

    const file_path = decl.file.path();
    try list.ensure_unused_capacity(gpa, file_path.len + 1);
    list.append_slice_assume_capacity(file_path);
    for (list.items[start..]) |*byte| switch (byte.*) {
        '/' => byte.* = '.',
        else => continue,
    };
    if (std.mem.ends_with(u8, list.items, ".zig")) {
        list.items.len -= 3;
    } else {
        list.append_assume_capacity('.');
    }
}

pub fn append_parent_ns(list: *std.ArrayListUnmanaged(u8), parent: Decl.Index) Oom!void {
    assert(parent != .none);
    const decl = parent.get();
    if (decl.parent != .none) {
        try append_parent_ns(list, decl.parent);
        try list.append_slice(gpa, decl.extra_info().name);
        try list.append(gpa, '.');
    }
}

pub fn find_first_doc_comment(ast: *const Ast, token: Ast.TokenIndex) Ast.TokenIndex {
    const token_tags = ast.tokens.items(.tag);
    var it = token;
    while (it > 0) {
        it -= 1;
        if (token_tags[it] != .doc_comment) {
            return it + 1;
        }
    }
    return it;
}

/// Successively looks up each component.
pub fn find(search_string: []const u8) Decl.Index {
    var path_components = std.mem.split_scalar(u8, search_string, '.');
    const file = Walk.modules.get(path_components.first()) orelse return .none;
    var current_decl_index = file.find_root_decl();
    while (path_components.next()) |component| {
        while (true) switch (current_decl_index.get().categorize()) {
            .alias => |aliasee| current_decl_index = aliasee,
            else => break,
        };
        current_decl_index = current_decl_index.get().get_child(component) orelse return .none;
    }
    return current_decl_index;
}

const Decl = @This();
const std = @import("std");
const Ast = std.zig.Ast;
const Walk = @import("Walk.zig");
const gpa = std.heap.wasm_allocator;
const assert = std.debug.assert;
const log = std.log;
const Oom = error{OutOfMemory};
