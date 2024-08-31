const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const mem = std.mem;
const math = std.math;
const meta = std.meta;
const CallingConvention = std.builtin.CallingConvention;
const clang = @import("clang.zig");
const aro = @import("aro");
const CToken = aro.Tokenizer.Token;
const Node = ast.Node;
const Tag = Node.Tag;
const common = @import("aro_translate_c");
const ast = common.ast;
const Error = common.Error;
const MacroProcessingError = common.MacroProcessingError;
const TypeError = common.TypeError;
const TransError = common.TransError;
const SymbolTable = common.SymbolTable;
const AliasList = common.AliasList;
const ResultUsed = common.ResultUsed;
const Scope = common.ScopeExtra(Context, clang.QualType);
const PatternList = common.PatternList;
const MacroSlicer = common.MacroSlicer;

pub const Context = struct {
    gpa: mem.Allocator,
    arena: mem.Allocator,
    source_manager: *clang.SourceManager,
    decl_table: std.AutoArrayHashMapUnmanaged(usize, []const u8) = .{},
    alias_list: AliasList,
    global_scope: *Scope.Root,
    clang_context: *clang.ASTContext,
    mangle_count: u32 = 0,
    /// Table of record decls that have been demoted to opaques.
    opaque_demotes: std.AutoHashMapUnmanaged(usize, void) = .{},
    /// Table of unnamed enums and records that are child types of typedefs.
    unnamed_typedefs: std.AutoHashMapUnmanaged(usize, []const u8) = .{},
    /// Needed to decide if we are parsing a typename
    typedefs: std.StringArrayHashMapUnmanaged(void) = .{},

    /// This one is different than the root scope's name table. This contains
    /// a list of names that we found by visiting all the top level decls without
    /// translating them. The other maps are updated as we translate; this one is updated
    /// up front in a pre-processing step.
    global_names: std.StringArrayHashMapUnmanaged(void) = .{},

    /// This is similar to `global_names`, but contains names which we would
    /// *like* to use, but do not strictly *have* to if they are unavailable.
    /// These are relevant to types, which ideally we would name like
    /// 'struct_foo' with an alias 'foo', but if either of those names is taken,
    /// may be mangled.
    /// This is distinct from `global_names` so we can detect at a type
    /// declaration whether or not the name is available.
    weak_global_names: std.StringArrayHashMapUnmanaged(void) = .{},

    pattern_list: PatternList,

    fn get_mangle(c: *Context) u32 {
        c.mangle_count += 1;
        return c.mangle_count;
    }

    /// Convert a null-terminated C string to a slice allocated in the arena
    fn str(c: *Context, s: [*:0]const u8) ![]u8 {
        return c.arena.dupe(u8, mem.slice_to(s, 0));
    }

    /// Convert a clang source location to a file:line:column string
    fn loc_str(c: *Context, loc: clang.SourceLocation) ![]u8 {
        const spelling_loc = c.source_manager.getSpellingLoc(loc);
        const filename_c = c.source_manager.getFilename(spelling_loc);
        const filename = if (filename_c) |s| try c.str(s) else @as([]const u8, "(no file)");

        const line = c.source_manager.getSpellingLineNumber(spelling_loc);
        const column = c.source_manager.getSpellingColumnNumber(spelling_loc);
        return std.fmt.alloc_print(c.arena, "{s}:{d}:{d}", .{ filename, line, column });
    }
};

pub fn translate(
    gpa: mem.Allocator,
    args_begin: [*]?[*]const u8,
    args_end: [*]?[*]const u8,
    errors: *std.zig.ErrorBundle,
    resources_path: [*:0]const u8,
) !std.zig.Ast {
    var clang_errors: []clang.ErrorMsg = &.{};

    const ast_unit = clang.LoadFromCommandLine(
        args_begin,
        args_end,
        &clang_errors.ptr,
        &clang_errors.len,
        resources_path,
    ) orelse {
        defer clang.ErrorMsg.delete(clang_errors.ptr, clang_errors.len);

        var bundle: std.zig.ErrorBundle.Wip = undefined;
        try bundle.init(gpa);
        defer bundle.deinit();

        for (clang_errors) |c_error| {
            const line = line: {
                const source = c_error.source orelse break :line 0;
                var start = c_error.offset;
                while (start > 0) : (start -= 1) {
                    if (source[start - 1] == '\n') break;
                }
                var end = c_error.offset;
                while (true) : (end += 1) {
                    if (source[end] == 0) break;
                    if (source[end] == '\n') break;
                }
                break :line try bundle.add_string(source[start..end]);
            };

            try bundle.add_root_error_message(.{
                .msg = try bundle.add_string(c_error.msg_ptr[0..c_error.msg_len]),
                .src_loc = if (c_error.filename_ptr) |filename_ptr| try bundle.add_source_location(.{
                    .src_path = try bundle.add_string(filename_ptr[0..c_error.filename_len]),
                    .span_start = c_error.offset,
                    .span_main = c_error.offset,
                    .span_end = c_error.offset + 1,
                    .line = c_error.line,
                    .column = c_error.column,
                    .source_line = line,
                }) else .none,
            });
        }
        errors.* = try bundle.to_owned_bundle("");

        return error.SemanticAnalyzeFail;
    };
    defer ast_unit.delete();

    // For memory that has the same lifetime as the Ast that we return
    // from this function.
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var context = Context{
        .gpa = gpa,
        .arena = arena,
        .source_manager = ast_unit.getSourceManager(),
        .alias_list = AliasList.init(gpa),
        .global_scope = try arena.create(Scope.Root),
        .clang_context = ast_unit.getASTContext(),
        .pattern_list = try PatternList.init(gpa),
    };
    context.global_scope.* = Scope.Root.init(&context);
    defer {
        context.decl_table.deinit(gpa);
        context.alias_list.deinit();
        context.global_names.deinit(gpa);
        context.opaque_demotes.deinit(gpa);
        context.unnamed_typedefs.deinit(gpa);
        context.typedefs.deinit(gpa);
        context.global_scope.deinit();
        context.pattern_list.deinit(gpa);
    }

    inline for (@typeInfo(std.zig.c_builtins).Struct.decls) |decl| {
        const builtin = try Tag.pub_var_simple.create(arena, .{
            .name = decl.name,
            .init = try Tag.import_c_builtin.create(arena, decl.name),
        });
        try add_top_level_decl(&context, decl.name, builtin);
    }

    try prepopulate_global_name_table(ast_unit, &context);

    if (!ast_unit.visitLocalTopLevelDecls(&context, decl_visitor_c)) {
        return error.OutOfMemory;
    }

    try trans_preprocessor_entities(&context, ast_unit);

    for (context.alias_list.items) |alias| {
        const node = try Tag.alias.create(arena, .{ .actual = alias.alias, .mangled = alias.name });
        try add_top_level_decl(&context, alias.alias, node);
    }

    return ast.render(gpa, context.global_scope.nodes.items);
}

/// Determines whether macro is of the form: `#define FOO FOO` (Possibly with trailing tokens)
/// Macros of this form will not be translated.
fn is_self_defined_macro(unit: *const clang.ASTUnit, c: *const Context, macro: *const clang.MacroDefinitionRecord) !bool {
    const source = try get_macro_text(unit, c, macro);
    var tokenizer: aro.Tokenizer = .{
        .buf = source,
        .source = .unused,
        .langopts = .{},
    };
    const name_tok = tokenizer.next_no_ws();
    const name = source[name_tok.start..name_tok.end];

    const first_tok = tokenizer.next_no_ws();
    // We do not just check for `.Identifier` below because keyword tokens are preferentially matched first by
    // the tokenizer.
    // In other words we would miss `#define inline inline` (`inline` is a valid c89 identifier)
    if (first_tok.id == .eof) return false;
    return mem.eql(u8, name, source[first_tok.start..first_tok.end]);
}

fn prepopulate_global_name_table(ast_unit: *clang.ASTUnit, c: *Context) !void {
    if (!ast_unit.visitLocalTopLevelDecls(c, decl_visitor_names_only_c)) {
        return error.OutOfMemory;
    }

    // TODO if we see #undef, delete it from the table
    var it = ast_unit.getLocalPreprocessingEntities_begin();
    const it_end = ast_unit.getLocalPreprocessingEntities_end();

    while (it.I != it_end.I) : (it.I += 1) {
        const entity = it.deref();
        switch (entity.get_kind()) {
            .MacroDefinitionKind => {
                const macro = @as(*clang.MacroDefinitionRecord, @ptr_cast(entity));
                const raw_name = macro.getName_getNameStart();
                const name = try c.str(raw_name);

                if (!try is_self_defined_macro(ast_unit, c, macro)) {
                    try c.global_names.put(c.gpa, name, {});
                }
            },
            else => {},
        }
    }
}

fn decl_visitor_names_only_c(context: ?*anyopaque, decl: *const clang.Decl) callconv(.C) bool {
    const c: *Context = @ptr_cast(@align_cast(context));
    decl_visitor_names_only(c, decl) catch return false;
    return true;
}

fn decl_visitor_c(context: ?*anyopaque, decl: *const clang.Decl) callconv(.C) bool {
    const c: *Context = @ptr_cast(@align_cast(context));
    decl_visitor(c, decl) catch return false;
    return true;
}

fn decl_visitor_names_only(c: *Context, decl: *const clang.Decl) Error!void {
    if (decl.castToNamedDecl()) |named_decl| {
        const decl_name = try c.str(named_decl.getName_bytes_begin());

        switch (decl.get_kind()) {
            .Record, .Enum => {
                // These types are prefixed with the container kind.
                const container_prefix = if (decl.get_kind() == .Record) prefix: {
                    const record_decl: *const clang.RecordDecl = @ptr_cast(decl);
                    if (record_decl.is_union()) {
                        break :prefix "union";
                    } else {
                        break :prefix "struct";
                    }
                } else "enum";
                const prefixed_name = try std.fmt.alloc_print(c.arena, "{s}_{s}", .{ container_prefix, decl_name });
                // `decl_name` and `prefixed_name` are the preferred names for this type.
                // However, we can name it anything else if necessary, so these are "weak names".
                try c.weak_global_names.ensure_unused_capacity(c.gpa, 2);
                c.weak_global_names.put_assume_capacity(decl_name, {});
                c.weak_global_names.put_assume_capacity(prefixed_name, {});
            },
            else => {
                try c.global_names.put(c.gpa, decl_name, {});
            },
        }

        // Check for typedefs with unnamed enum/record child types.
        if (decl.get_kind() == .Typedef) {
            const typedef_decl = @as(*const clang.TypedefNameDecl, @ptr_cast(decl));
            var child_ty = typedef_decl.getUnderlyingType().getTypePtr();
            const addr: usize = while (true) switch (child_ty.getTypeClass()) {
                .Enum => {
                    const enum_ty = @as(*const clang.EnumType, @ptr_cast(child_ty));
                    const enum_decl = enum_ty.get_decl();
                    // check if this decl is unnamed
                    if (@as(*const clang.NamedDecl, @ptr_cast(enum_decl)).getName_bytes_begin()[0] != 0) return;
                    break @int_from_ptr(enum_decl.getCanonicalDecl());
                },
                .Record => {
                    const record_ty = @as(*const clang.RecordType, @ptr_cast(child_ty));
                    const record_decl = record_ty.get_decl();
                    // check if this decl is unnamed
                    if (@as(*const clang.NamedDecl, @ptr_cast(record_decl)).getName_bytes_begin()[0] != 0) return;
                    break @int_from_ptr(record_decl.getCanonicalDecl());
                },
                .Elaborated => {
                    const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(child_ty));
                    child_ty = elaborated_ty.getNamedType().getTypePtr();
                },
                .Decayed => {
                    const decayed_ty = @as(*const clang.DecayedType, @ptr_cast(child_ty));
                    child_ty = decayed_ty.getDecayedType().getTypePtr();
                },
                .Attributed => {
                    const attributed_ty = @as(*const clang.AttributedType, @ptr_cast(child_ty));
                    child_ty = attributed_ty.getEquivalentType().getTypePtr();
                },
                .MacroQualified => {
                    const macroqualified_ty = @as(*const clang.MacroQualifiedType, @ptr_cast(child_ty));
                    child_ty = macroqualified_ty.getModifiedType().getTypePtr();
                },
                else => return,
            };

            const result = try c.unnamed_typedefs.get_or_put(c.gpa, addr);
            if (result.found_existing) {
                // One typedef can declare multiple names.
                // Don't put this one in `decl_table` so it's processed later.
                return;
            }
            result.value_ptr.* = decl_name;
            // Put this typedef in the decl_table to avoid redefinitions.
            try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(typedef_decl.getCanonicalDecl()), decl_name);
            try c.typedefs.put(c.gpa, decl_name, {});
        }
    }
}

fn decl_visitor(c: *Context, decl: *const clang.Decl) Error!void {
    switch (decl.get_kind()) {
        .Function => {
            return visit_fn_decl(c, @as(*const clang.FunctionDecl, @ptr_cast(decl)));
        },
        .Typedef => {
            try trans_type_def(c, &c.global_scope.base, @as(*const clang.TypedefNameDecl, @ptr_cast(decl)));
        },
        .Enum => {
            try trans_enum_decl(c, &c.global_scope.base, @as(*const clang.EnumDecl, @ptr_cast(decl)));
        },
        .Record => {
            try trans_record_decl(c, &c.global_scope.base, @as(*const clang.RecordDecl, @ptr_cast(decl)));
        },
        .Var => {
            return visit_var_decl(c, @as(*const clang.VarDecl, @ptr_cast(decl)), null);
        },
        .Empty => {
            // Do nothing
        },
        .FileScopeAsm => {
            try trans_file_scope_asm(c, &c.global_scope.base, @as(*const clang.FileScopeAsmDecl, @ptr_cast(decl)));
        },
        else => {
            const decl_name = try c.str(decl.getDeclKindName());
            try warn(c, &c.global_scope.base, decl.getLocation(), "ignoring {s} declaration", .{decl_name});
        },
    }
}

fn trans_file_scope_asm(c: *Context, scope: *Scope, file_scope_asm: *const clang.FileScopeAsmDecl) Error!void {
    const asm_string = file_scope_asm.getAsmString();
    var len: usize = undefined;
    const bytes_ptr = asm_string.getString_bytes_begin_size(&len);

    const str = try std.fmt.alloc_print(c.arena, "\"{}\"", .{std.zig.fmt_escapes(bytes_ptr[0..len])});
    const str_node = try Tag.string_literal.create(c.arena, str);

    const asm_node = try Tag.asm_simple.create(c.arena, str_node);
    const block = try Tag.block_single.create(c.arena, asm_node);
    const comptime_node = try Tag.@"comptime".create(c.arena, block);

    try scope.append_node(comptime_node);
}

fn visit_fn_decl(c: *Context, fn_decl: *const clang.FunctionDecl) Error!void {
    const fn_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(fn_decl)).getName_bytes_begin());
    if (c.global_scope.sym_table.contains(fn_name))
        return; // Avoid processing this decl twice

    // Skip this declaration if a proper definition exists
    if (!fn_decl.isThisDeclarationADefinition()) {
        if (fn_decl.getDefinition()) |def|
            return visit_fn_decl(c, def);
    }

    const fn_decl_loc = fn_decl.getLocation();
    const has_body = fn_decl.hasBody();
    const storage_class = fn_decl.getStorageClass();
    const is_always_inline = has_body and fn_decl.hasAlwaysInlineAttr();
    var decl_ctx = FnDeclContext{
        .fn_name = fn_name,
        .has_body = has_body,
        .storage_class = storage_class,
        .is_always_inline = is_always_inline,
        .is_export = switch (storage_class) {
            .None => has_body and !is_always_inline and !fn_decl.isInlineSpecified(),
            .Extern, .Static => false,
            .PrivateExtern => return fail_decl(c, fn_decl_loc, fn_name, "unsupported storage class: private extern", .{}),
            .Auto => unreachable, // Not legal on functions
            .Register => unreachable, // Not legal on functions
        },
    };

    var fn_qt = fn_decl.get_type();

    const fn_type = while (true) {
        const fn_type = fn_qt.getTypePtr();

        switch (fn_type.getTypeClass()) {
            .Attributed => {
                const attr_type = @as(*const clang.AttributedType, @ptr_cast(fn_type));
                fn_qt = attr_type.getEquivalentType();
            },
            .Paren => {
                const paren_type = @as(*const clang.ParenType, @ptr_cast(fn_type));
                fn_qt = paren_type.getInnerType();
            },
            else => break fn_type,
        }
    };
    const fn_ty = @as(*const clang.FunctionType, @ptr_cast(fn_type));
    const return_qt = fn_ty.get_return_type();

    const proto_node = switch (fn_type.getTypeClass()) {
        .FunctionProto => blk: {
            const fn_proto_type = @as(*const clang.FunctionProtoType, @ptr_cast(fn_type));
            if (has_body and fn_proto_type.isVariadic()) {
                decl_ctx.has_body = false;
                decl_ctx.storage_class = .Extern;
                decl_ctx.is_export = false;
                decl_ctx.is_always_inline = false;
                try warn(c, &c.global_scope.base, fn_decl_loc, "TODO unable to translate variadic function, demoted to extern", .{});
            }
            break :blk trans_fn_proto(c, fn_decl, fn_proto_type, fn_decl_loc, decl_ctx, true) catch |err| switch (err) {
                error.UnsupportedType => {
                    return fail_decl(c, fn_decl_loc, fn_name, "unable to resolve prototype of function", .{});
                },
                error.OutOfMemory => |e| return e,
            };
        },
        .FunctionNoProto => blk: {
            const fn_no_proto_type = @as(*const clang.FunctionType, @ptr_cast(fn_type));
            break :blk trans_fn_no_proto(c, fn_no_proto_type, fn_decl_loc, decl_ctx, true) catch |err| switch (err) {
                error.UnsupportedType => {
                    return fail_decl(c, fn_decl_loc, fn_name, "unable to resolve prototype of function", .{});
                },
                error.OutOfMemory => |e| return e,
            };
        },
        else => return fail_decl(c, fn_decl_loc, fn_name, "unable to resolve function type {}", .{fn_type.getTypeClass()}),
    };

    if (!decl_ctx.has_body) {
        return add_top_level_decl(c, fn_name, Node.init_payload(&proto_node.base));
    }

    // actual function definition with body
    const body_stmt = fn_decl.getBody();
    var block_scope = try Scope.Block.init(c, &c.global_scope.base, false);
    block_scope.return_type = return_qt;
    defer block_scope.deinit();

    const scope = &block_scope.base;

    var param_id: c_uint = 0;
    for (proto_node.data.params) |*param| {
        const param_name = param.name orelse {
            proto_node.data.is_extern = true;
            proto_node.data.is_export = false;
            proto_node.data.is_inline = false;
            try warn(c, &c.global_scope.base, fn_decl_loc, "function {s} parameter has no name, demoted to extern", .{fn_name});
            return add_top_level_decl(c, fn_name, Node.init_payload(&proto_node.base));
        };

        const c_param = fn_decl.getParamDecl(param_id);
        const qual_type = c_param.getOriginalType();
        const is_const = qual_type.isConstQualified();

        const mangled_param_name = try block_scope.make_mangled_name(c, param_name);
        param.name = mangled_param_name;

        if (!is_const) {
            const bare_arg_name = try std.fmt.alloc_print(c.arena, "arg_{s}", .{mangled_param_name});
            const arg_name = try block_scope.make_mangled_name(c, bare_arg_name);
            param.name = arg_name;

            const redecl_node = try Tag.arg_redecl.create(c.arena, .{ .actual = mangled_param_name, .mangled = arg_name });
            try block_scope.statements.append(redecl_node);
        }
        try block_scope.discard_variable(c, mangled_param_name);

        param_id += 1;
    }

    const casted_body = @as(*const clang.CompoundStmt, @ptr_cast(body_stmt));
    trans_compound_stmt_inline(c, casted_body, &block_scope) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.UnsupportedTranslation,
        error.UnsupportedType,
        => {
            proto_node.data.is_extern = true;
            proto_node.data.is_export = false;
            proto_node.data.is_inline = false;
            try warn(c, &c.global_scope.base, fn_decl_loc, "unable to translate function, demoted to extern", .{});
            return add_top_level_decl(c, fn_name, Node.init_payload(&proto_node.base));
        },
    };
    // add return statement if the function didn't have one
    blk: {
        const maybe_body = try block_scope.complete(c);
        if (fn_ty.getNoReturnAttr() or is_anyopaque(return_qt) or maybe_body.is_noreturn(false)) {
            proto_node.data.body = maybe_body;
            break :blk;
        }

        const rhs = trans_zero_init_expr(c, scope, fn_decl_loc, return_qt.getTypePtr()) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            error.UnsupportedTranslation,
            error.UnsupportedType,
            => {
                proto_node.data.is_extern = true;
                proto_node.data.is_export = false;
                proto_node.data.is_inline = false;
                try warn(c, &c.global_scope.base, fn_decl_loc, "unable to create a return value for function, demoted to extern", .{});
                return add_top_level_decl(c, fn_name, Node.init_payload(&proto_node.base));
            },
        };
        const ret = try Tag.@"return".create(c.arena, rhs);
        try block_scope.statements.append(ret);
        proto_node.data.body = try block_scope.complete(c);
    }

    return add_top_level_decl(c, fn_name, Node.init_payload(&proto_node.base));
}

fn trans_qual_type_maybe_initialized(c: *Context, scope: *Scope, qt: clang.QualType, decl_init: ?*const clang.Expr, loc: clang.SourceLocation) TransError!Node {
    return if (decl_init) |init_expr|
        trans_qual_type_initialized(c, scope, qt, init_expr, loc)
    else
        trans_qual_type(c, scope, qt, loc);
}

/// This is used in global scope to convert a string literal `S` to [*c]u8:
/// &(struct {
///     var static = S.*;
/// }).static;
fn string_literal_to_char_star(c: *Context, str: Node) Error!Node {
    const var_name = Scope.Block.static_inner_name;

    const variables = try c.arena.alloc(Node, 1);
    variables[0] = try Tag.mut_str.create(c.arena, .{ .name = var_name, .init = str });

    const anon_struct = try Tag.@"struct".create(c.arena, .{
        .layout = .none,
        .fields = &.{},
        .functions = &.{},
        .variables = variables,
    });

    const member_access = try Tag.field_access.create(c.arena, .{
        .lhs = anon_struct,
        .field_name = var_name,
    });
    return Tag.address_of.create(c.arena, member_access);
}

/// if mangled_name is not null, this var decl was declared in a block scope.
fn visit_var_decl(c: *Context, var_decl: *const clang.VarDecl, mangled_name: ?[]const u8) Error!void {
    const var_name = mangled_name orelse try c.str(@as(*const clang.NamedDecl, @ptr_cast(var_decl)).getName_bytes_begin());
    if (c.global_scope.sym_table.contains(var_name))
        return; // Avoid processing this decl twice

    const is_pub = mangled_name == null;
    const is_threadlocal = var_decl.getTLSKind() != .None;
    const scope = &c.global_scope.base;
    const var_decl_loc = var_decl.getLocation();

    const qual_type = var_decl.getTypeSourceInfo_getType();
    const storage_class = var_decl.getStorageClass();
    const has_init = var_decl.hasInit();
    const decl_init = var_decl.getInit();
    var is_const = qual_type.isConstQualified();

    // In C extern variables with initializers behave like Zig exports.
    // extern int foo = 2;
    // does the same as:
    // extern int foo;
    // int foo = 2;
    var is_extern = storage_class == .Extern and !has_init;
    var is_export = !is_extern and storage_class != .Static;

    if (!is_extern and qual_type_was_demoted_to_opaque(c, qual_type)) {
        return fail_decl(c, var_decl_loc, var_name, "non-extern variable has opaque type", .{});
    }

    const type_node = trans_qual_type_maybe_initialized(c, scope, qual_type, decl_init, var_decl_loc) catch |err| switch (err) {
        error.UnsupportedTranslation, error.UnsupportedType => {
            return fail_decl(c, var_decl_loc, var_name, "unable to resolve variable type", .{});
        },
        error.OutOfMemory => |e| return e,
    };

    var init_node: ?Node = null;

    // If the initialization expression is not present, initialize with undefined.
    // If it is an integer literal, we can skip the @as since it will be redundant
    // with the variable type.
    if (has_init) trans_init: {
        if (decl_init) |expr| {
            const node_or_error = if (expr.getStmtClass() == .StringLiteralClass)
                trans_string_literal_initializer(c, @as(*const clang.StringLiteral, @ptr_cast(expr)), type_node)
            else
                trans_expr_coercing(c, scope, expr, .used);
            init_node = node_or_error catch |err| switch (err) {
                error.UnsupportedTranslation,
                error.UnsupportedType,
                => {
                    is_extern = true;
                    is_export = false;
                    try warn(c, scope, var_decl_loc, "unable to translate variable initializer, demoted to extern", .{});
                    break :trans_init;
                },
                error.OutOfMemory => |e| return e,
            };
            if (!qual_type_is_boolean(qual_type) and is_bool_res(init_node.?)) {
                init_node = try Tag.int_from_bool.create(c.arena, init_node.?);
            } else if (init_node.?.tag() == .string_literal and qual_type_is_char_star(qual_type)) {
                init_node = try string_literal_to_char_star(c, init_node.?);
            }
        } else {
            init_node = Tag.undefined_literal.init();
        }
    } else if (storage_class != .Extern) {
        // The C language specification states that variables with static or threadlocal
        // storage without an initializer are initialized to a zero value.

        // std.mem.zeroes(T)
        init_node = try Tag.std_mem_zeroes.create(c.arena, type_node);
    } else if (qual_type.getTypeClass() == .IncompleteArray) {
        // Oh no, an extern array of unknown size! These are really fun because there's no
        // direct equivalent in Zig. To translate correctly, we'll have to create a C-pointer
        // to the data initialized via @extern.

        const name_str = try std.fmt.alloc_print(c.arena, "\"{s}\"", .{var_name});
        init_node = try Tag.builtin_extern.create(c.arena, .{
            .type = type_node,
            .name = try Tag.string_literal.create(c.arena, name_str),
        });

        // Since this is really a pointer to the underlying data, we tweak a few properties.
        is_extern = false;
        is_const = true;
    }

    const linksection_string = blk: {
        var str_len: usize = undefined;
        if (var_decl.getSectionAttribute(&str_len)) |str_ptr| {
            break :blk str_ptr[0..str_len];
        }
        break :blk null;
    };

    const node = try Tag.var_decl.create(c.arena, .{
        .is_pub = is_pub,
        .is_const = is_const,
        .is_extern = is_extern,
        .is_export = is_export,
        .is_threadlocal = is_threadlocal,
        .linksection_string = linksection_string,
        .alignment = ClangAlignment.for_var(c, var_decl).zig_alignment(),
        .name = var_name,
        .type = type_node,
        .init = init_node,
    });
    return add_top_level_decl(c, var_name, node);
}

const builtin_typedef_map = std.StaticStringMap([]const u8).init_comptime(.{
    .{ "uint8_t", "u8" },
    .{ "int8_t", "i8" },
    .{ "uint16_t", "u16" },
    .{ "int16_t", "i16" },
    .{ "uint32_t", "u32" },
    .{ "int32_t", "i32" },
    .{ "uint64_t", "u64" },
    .{ "int64_t", "i64" },
    .{ "intptr_t", "isize" },
    .{ "uintptr_t", "usize" },
    .{ "ssize_t", "isize" },
    .{ "size_t", "usize" },
});

fn trans_type_def(c: *Context, scope: *Scope, typedef_decl: *const clang.TypedefNameDecl) Error!void {
    if (c.decl_table.get(@int_from_ptr(typedef_decl.getCanonicalDecl()))) |_|
        return; // Avoid processing this decl twice
    const toplevel = scope.id == .root;
    const bs: *Scope.Block = if (!toplevel) try scope.find_block_scope(c) else undefined;

    var name: []const u8 = try c.str(@as(*const clang.NamedDecl, @ptr_cast(typedef_decl)).getName_bytes_begin());
    try c.typedefs.put(c.gpa, name, {});

    if (builtin_typedef_map.get(name)) |builtin| {
        return c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(typedef_decl.getCanonicalDecl()), builtin);
    }
    if (!toplevel) name = try bs.make_mangled_name(c, name);
    try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(typedef_decl.getCanonicalDecl()), name);

    const child_qt = typedef_decl.getUnderlyingType();
    const typedef_loc = typedef_decl.getLocation();
    const init_node = trans_qual_type(c, scope, child_qt, typedef_loc) catch |err| switch (err) {
        error.UnsupportedType => {
            return fail_decl(c, typedef_loc, name, "unable to resolve typedef child type", .{});
        },
        error.OutOfMemory => |e| return e,
    };

    const payload = try c.arena.create(ast.Payload.SimpleVarDecl);
    payload.* = .{
        .base = .{ .tag = ([2]Tag{ .var_simple, .pub_var_simple })[@int_from_bool(toplevel)] },
        .data = .{
            .name = name,
            .init = init_node,
        },
    };
    const node = Node.init_payload(&payload.base);

    if (toplevel) {
        try add_top_level_decl(c, name, node);
    } else {
        try scope.append_node(node);
        if (node.tag() != .pub_var_simple) {
            try bs.discard_variable(c, name);
        }
    }
}

/// Build a getter function for a flexible array member at the end of a C struct
/// e.g. `T items[]` or `T items[0]`. The generated function returns a [*c] pointer
/// to the flexible array with the correct const and volatile qualifiers
fn build_flexible_array_fn(
    c: *Context,
    scope: *Scope,
    layout: *const clang.ASTRecordLayout,
    field_name: []const u8,
    field_decl: *const clang.FieldDecl,
) TypeError!Node {
    const field_qt = field_decl.get_type();
    const field_qt_canon = qual_type_canon(field_qt);

    const u8_type = try Tag.type.create(c.arena, "u8");
    const self_param_name = "self";
    const self_param = try Tag.identifier.create(c.arena, self_param_name);
    const self_type = try Tag.typeof.create(c.arena, self_param);

    const fn_params = try c.arena.alloc(ast.Payload.Param, 1);

    fn_params[0] = .{
        .name = self_param_name,
        .type = Tag.@"anytype".init(),
        .is_noalias = false,
    };

    const array_type = @as(*const clang.ArrayType, @ptr_cast(field_qt_canon));
    const element_qt = array_type.getElementType();
    const element_type = try trans_qual_type(c, scope, element_qt, field_decl.getLocation());

    var block_scope = try Scope.Block.init(c, scope, false);
    defer block_scope.deinit();

    const intermediate_type_name = try block_scope.make_mangled_name(c, "Intermediate");
    const intermediate_type = try Tag.helpers_flexible_array_type.create(c.arena, .{ .lhs = self_type, .rhs = u8_type });
    const intermediate_type_decl = try Tag.var_simple.create(c.arena, .{
        .name = intermediate_type_name,
        .init = intermediate_type,
    });
    try block_scope.statements.append(intermediate_type_decl);
    const intermediate_type_ident = try Tag.identifier.create(c.arena, intermediate_type_name);

    const return_type_name = try block_scope.make_mangled_name(c, "ReturnType");
    const return_type = try Tag.helpers_flexible_array_type.create(c.arena, .{ .lhs = self_type, .rhs = element_type });
    const return_type_decl = try Tag.var_simple.create(c.arena, .{
        .name = return_type_name,
        .init = return_type,
    });
    try block_scope.statements.append(return_type_decl);
    const return_type_ident = try Tag.identifier.create(c.arena, return_type_name);

    const field_index = field_decl.getFieldIndex();
    const bit_offset = layout.getFieldOffset(field_index); // this is a target-specific constant based on the struct layout
    const byte_offset = bit_offset / 8;

    const casted_self = try Tag.as.create(c.arena, .{
        .lhs = intermediate_type_ident,
        .rhs = try Tag.ptr_cast.create(c.arena, self_param),
    });
    const field_offset = try trans_create_node_number(c, byte_offset, .int);
    const field_ptr = try Tag.add.create(c.arena, .{ .lhs = casted_self, .rhs = field_offset });

    const ptr_cast = try Tag.as.create(c.arena, .{
        .lhs = return_type_ident,
        .rhs = try Tag.ptr_cast.create(
            c.arena,
            try Tag.align_cast.create(
                c.arena,
                field_ptr,
            ),
        ),
    });
    const return_stmt = try Tag.@"return".create(c.arena, ptr_cast);
    try block_scope.statements.append(return_stmt);

    const payload = try c.arena.create(ast.Payload.Func);
    payload.* = .{
        .base = .{ .tag = .func },
        .data = .{
            .is_pub = true,
            .is_extern = false,
            .is_export = false,
            .is_inline = false,
            .is_var_args = false,
            .name = field_name,
            .linksection_string = null,
            .explicit_callconv = null,
            .params = fn_params,
            .return_type = return_type,
            .body = try block_scope.complete(c),
            .alignment = null,
        },
    };
    return Node.init_payload(&payload.base);
}

/// Return true if `field_decl` is the flexible array field for its parent record
fn is_flexible_array_field_decl(c: *Context, field_decl: *const clang.FieldDecl) bool {
    const record_decl = field_decl.getParent() orelse return false;
    const record_flexible_field = flexible_array_field(c, record_decl) orelse return false;
    return field_decl == record_flexible_field;
}

/// Find the flexible array field for a record if any. A flexible array field is an
/// incomplete or zero-length array that occurs as the last field of a record.
/// clang's RecordDecl::hasFlexibleArrayMember is not suitable for determining
/// this because it returns false for a record that ends with a zero-length
/// array, but we consider those to be flexible arrays
fn flexible_array_field(c: *Context, record_def: *const clang.RecordDecl) ?*const clang.FieldDecl {
    var it = record_def.field_begin();
    const end_it = record_def.field_end();
    var flexible_field: ?*const clang.FieldDecl = null;
    while (it.neq(end_it)) : (it = it.next()) {
        const field_decl = it.deref();
        const ty = qual_type_canon(field_decl.get_type());
        const incomplete_or_zero_size = ty.isIncompleteOrZeroLengthArrayType(c.clang_context);
        if (incomplete_or_zero_size) {
            flexible_field = field_decl;
        } else {
            flexible_field = null;
        }
    }
    return flexible_field;
}

fn mangle_weak_global_name(c: *Context, want_name: []const u8) ![]const u8 {
    var cur_name = want_name;

    if (!c.weak_global_names.contains(want_name)) {
        // This type wasn't noticed by the name detection pass, so nothing has been treating this as
        // a weak global name. We must mangle it to avoid conflicts with locals.
        cur_name = try std.fmt.alloc_print(c.arena, "{s}_{d}", .{ want_name, c.get_mangle() });
    }

    while (c.global_names.contains(cur_name)) {
        cur_name = try std.fmt.alloc_print(c.arena, "{s}_{d}", .{ want_name, c.get_mangle() });
    }
    return cur_name;
}

fn trans_record_decl(c: *Context, scope: *Scope, record_decl: *const clang.RecordDecl) Error!void {
    if (c.decl_table.get(@int_from_ptr(record_decl.getCanonicalDecl()))) |_|
        return; // Avoid processing this decl twice
    const record_loc = record_decl.getLocation();
    const toplevel = scope.id == .root;
    const bs: *Scope.Block = if (!toplevel) try scope.find_block_scope(c) else undefined;

    var is_union = false;
    var container_kind_name: []const u8 = undefined;
    var bare_name: []const u8 = try c.str(@as(*const clang.NamedDecl, @ptr_cast(record_decl)).getName_bytes_begin());

    if (record_decl.is_union()) {
        container_kind_name = "union";
        is_union = true;
    } else if (record_decl.is_struct()) {
        container_kind_name = "struct";
    } else {
        try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), bare_name);
        return fail_decl(c, record_loc, bare_name, "record {s} is not a struct or union", .{bare_name});
    }

    var is_unnamed = false;
    var name = bare_name;
    if (c.unnamed_typedefs.get(@int_from_ptr(record_decl.getCanonicalDecl()))) |typedef_name| {
        bare_name = typedef_name;
        name = typedef_name;
    } else {
        // Record declarations such as `struct {...} x` have no name but they're not
        // anonymous hence here isAnonymousStructOrUnion is not needed
        if (bare_name.len == 0) {
            bare_name = try std.fmt.alloc_print(c.arena, "unnamed_{d}", .{c.get_mangle()});
            is_unnamed = true;
        }
        name = try std.fmt.alloc_print(c.arena, "{s}_{s}", .{ container_kind_name, bare_name });
        if (toplevel and !is_unnamed) {
            name = try mangle_weak_global_name(c, name);
        }
    }
    if (!toplevel) name = try bs.make_mangled_name(c, name);
    try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), name);

    const is_pub = toplevel and !is_unnamed;
    const init_node = blk: {
        const record_def = record_decl.getDefinition() orelse {
            try c.opaque_demotes.put(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), {});
            break :blk Tag.opaque_literal.init();
        };

        var fields = std.ArrayList(ast.Payload.Record.Field).init(c.gpa);
        defer fields.deinit();

        var functions = std.ArrayList(Node).init(c.gpa);
        defer functions.deinit();

        const flexible_field = flexible_array_field(c, record_def);
        var unnamed_field_count: u32 = 0;
        var it = record_def.field_begin();
        const end_it = record_def.field_end();
        const layout = record_def.getASTRecordLayout(c.clang_context);
        const record_alignment = layout.get_alignment();

        while (it.neq(end_it)) : (it = it.next()) {
            const field_decl = it.deref();
            const field_loc = field_decl.getLocation();
            const field_qt = field_decl.get_type();

            if (field_decl.isBitField()) {
                try c.opaque_demotes.put(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), {});
                try warn(c, scope, field_loc, "{s} demoted to opaque type - has bitfield", .{container_kind_name});
                break :blk Tag.opaque_literal.init();
            }

            var is_anon = false;
            var field_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(field_decl)).getName_bytes_begin());
            if (field_decl.isAnonymousStructOrUnion() or field_name.len == 0) {
                // Context.get_mangle() is not used here because doing so causes unpredictable field names for anonymous fields.
                field_name = try std.fmt.alloc_print(c.arena, "unnamed_{d}", .{unnamed_field_count});
                unnamed_field_count += 1;
                is_anon = true;
            }
            if (flexible_field == field_decl) {
                const flexible_array_fn = build_flexible_array_fn(c, scope, layout, field_name, field_decl) catch |err| switch (err) {
                    error.UnsupportedType => {
                        try c.opaque_demotes.put(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), {});
                        try warn(c, scope, record_loc, "{s} demoted to opaque type - unable to translate type of flexible array field {s}", .{ container_kind_name, field_name });
                        break :blk Tag.opaque_literal.init();
                    },
                    else => |e| return e,
                };
                try functions.append(flexible_array_fn);
                continue;
            }
            const field_type = trans_qual_type(c, scope, field_qt, field_loc) catch |err| switch (err) {
                error.UnsupportedType => {
                    try c.opaque_demotes.put(c.gpa, @int_from_ptr(record_decl.getCanonicalDecl()), {});
                    try warn(c, scope, record_loc, "{s} demoted to opaque type - unable to translate type of field {s}", .{ container_kind_name, field_name });
                    break :blk Tag.opaque_literal.init();
                },
                else => |e| return e,
            };

            const alignment = if (flexible_field != null and field_decl.getFieldIndex() == 0)
                @as(c_uint, @int_cast(record_alignment))
            else
                ClangAlignment.for_field(c, field_decl, record_def).zig_alignment();

            // C99 introduced designated initializers for structs. Omitted fields are implicitly
            // initialized to zero. Some C APIs are designed with this in mind. Defaulting to zero
            // values for translated struct fields permits Zig code to comfortably use such an API.
            const default_value = if (record_decl.is_struct())
                try Tag.std_mem_zeroes.create(c.arena, field_type)
            else
                null;

            if (is_anon) {
                try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(field_decl.getCanonicalDecl()), field_name);
            }

            try fields.append(.{
                .name = field_name,
                .type = field_type,
                .alignment = alignment,
                .default_value = default_value,
            });
        }

        const record_payload = try c.arena.create(ast.Payload.Record);
        record_payload.* = .{
            .base = .{ .tag = ([2]Tag{ .@"struct", .@"union" })[@int_from_bool(is_union)] },
            .data = .{
                .layout = .@"extern",
                .fields = try c.arena.dupe(ast.Payload.Record.Field, fields.items),
                .functions = try c.arena.dupe(Node, functions.items),
                .variables = &.{},
            },
        };
        break :blk Node.init_payload(&record_payload.base);
    };

    const payload = try c.arena.create(ast.Payload.SimpleVarDecl);
    payload.* = .{
        .base = .{ .tag = ([2]Tag{ .var_simple, .pub_var_simple })[@int_from_bool(is_pub)] },
        .data = .{
            .name = name,
            .init = init_node,
        },
    };
    const node = Node.init_payload(&payload.base);
    if (toplevel) {
        try add_top_level_decl(c, name, node);
        // Only add the alias if the name is available *and* it was caught by
        // name detection. Don't bother performing a weak mangle, since a
        // mangled name is of no real use here.
        if (!is_unnamed and !c.global_names.contains(bare_name) and c.weak_global_names.contains(bare_name))
            try c.alias_list.append(.{ .alias = bare_name, .name = name });
    } else {
        try scope.append_node(node);
        if (node.tag() != .pub_var_simple) {
            try bs.discard_variable(c, name);
        }
    }
}

fn trans_enum_decl(c: *Context, scope: *Scope, enum_decl: *const clang.EnumDecl) Error!void {
    if (c.decl_table.get(@int_from_ptr(enum_decl.getCanonicalDecl()))) |_|
        return; // Avoid processing this decl twice
    const enum_loc = enum_decl.getLocation();
    const toplevel = scope.id == .root;
    const bs: *Scope.Block = if (!toplevel) try scope.find_block_scope(c) else undefined;

    var is_unnamed = false;
    var bare_name: []const u8 = try c.str(@as(*const clang.NamedDecl, @ptr_cast(enum_decl)).getName_bytes_begin());
    var name = bare_name;
    if (c.unnamed_typedefs.get(@int_from_ptr(enum_decl.getCanonicalDecl()))) |typedef_name| {
        bare_name = typedef_name;
        name = typedef_name;
    } else {
        if (bare_name.len == 0) {
            bare_name = try std.fmt.alloc_print(c.arena, "unnamed_{d}", .{c.get_mangle()});
            is_unnamed = true;
        }
        name = try std.fmt.alloc_print(c.arena, "enum_{s}", .{bare_name});
        if (toplevel and !is_unnamed) {
            name = try mangle_weak_global_name(c, name);
        }
    }
    if (!toplevel) name = try bs.make_mangled_name(c, name);
    try c.decl_table.put_no_clobber(c.gpa, @int_from_ptr(enum_decl.getCanonicalDecl()), name);

    const enum_type_node = if (enum_decl.getDefinition()) |enum_def| blk: {
        var it = enum_def.enumerator_begin();
        const end_it = enum_def.enumerator_end();
        while (it.neq(end_it)) : (it = it.next()) {
            const enum_const = it.deref();
            var enum_val_name: []const u8 = try c.str(@as(*const clang.NamedDecl, @ptr_cast(enum_const)).getName_bytes_begin());
            if (!toplevel) {
                enum_val_name = try bs.make_mangled_name(c, enum_val_name);
            }

            const enum_const_qt = @as(*const clang.ValueDecl, @ptr_cast(enum_const)).get_type();
            const enum_const_loc = @as(*const clang.Decl, @ptr_cast(enum_const)).getLocation();
            const enum_const_type_node: ?Node = trans_qual_type(c, scope, enum_const_qt, enum_const_loc) catch |err| switch (err) {
                error.UnsupportedType => null,
                else => |e| return e,
            };

            const enum_const_def = try Tag.enum_constant.create(c.arena, .{
                .name = enum_val_name,
                .is_public = toplevel,
                .type = enum_const_type_node,
                // TODO: as of LLVM 18, the return value from `enum_const.getInitVal` here needs
                // to be freed with a call to its free() method.
                .value = try trans_create_node_apint(c, enum_const.getInitVal()),
            });
            if (toplevel)
                try add_top_level_decl(c, enum_val_name, enum_const_def)
            else {
                try scope.append_node(enum_const_def);
                try bs.discard_variable(c, enum_val_name);
            }
        }

        const int_type = enum_decl.getIntegerType();
        // The underlying type may be null in case of forward-declared enum
        // types, while that's not ISO-C compliant many compilers allow this and
        // default to the usual integer type used for all the enums.

        // default to c_int since msvc and gcc default to different types
        break :blk if (int_type.ptr != null)
            trans_qual_type(c, scope, int_type, enum_loc) catch |err| switch (err) {
                error.UnsupportedType => {
                    return fail_decl(c, enum_loc, name, "unable to translate enum integer type", .{});
                },
                else => |e| return e,
            }
        else
            try Tag.type.create(c.arena, "c_int");
    } else blk: {
        try c.opaque_demotes.put(c.gpa, @int_from_ptr(enum_decl.getCanonicalDecl()), {});
        break :blk Tag.opaque_literal.init();
    };

    const is_pub = toplevel and !is_unnamed;
    const payload = try c.arena.create(ast.Payload.SimpleVarDecl);
    payload.* = .{
        .base = .{ .tag = ([2]Tag{ .var_simple, .pub_var_simple })[@int_from_bool(is_pub)] },
        .data = .{
            .init = enum_type_node,
            .name = name,
        },
    };
    const node = Node.init_payload(&payload.base);
    if (toplevel) {
        try add_top_level_decl(c, name, node);
        // Only add the alias if the name is available *and* it was caught by
        // name detection. Don't bother performing a weak mangle, since a
        // mangled name is of no real use here.
        if (!is_unnamed and !c.global_names.contains(bare_name) and c.weak_global_names.contains(bare_name))
            try c.alias_list.append(.{ .alias = bare_name, .name = name });
    } else {
        try scope.append_node(node);
        if (node.tag() != .pub_var_simple) {
            try bs.discard_variable(c, name);
        }
    }
}

fn trans_stmt(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.Stmt,
    result_used: ResultUsed,
) TransError!Node {
    const sc = stmt.getStmtClass();
    switch (sc) {
        .BinaryOperatorClass => return trans_binary_operator(c, scope, @as(*const clang.BinaryOperator, @ptr_cast(stmt)), result_used),
        .CompoundStmtClass => return trans_compound_stmt(c, scope, @as(*const clang.CompoundStmt, @ptr_cast(stmt))),
        .CStyleCastExprClass => return trans_cstyle_cast_expr_class(c, scope, @as(*const clang.CStyleCastExpr, @ptr_cast(stmt)), result_used),
        .DeclStmtClass => return trans_decl_stmt(c, scope, @as(*const clang.DeclStmt, @ptr_cast(stmt))),
        .DeclRefExprClass => return trans_decl_ref_expr(c, scope, @as(*const clang.DeclRefExpr, @ptr_cast(stmt))),
        .ImplicitCastExprClass => return trans_implicit_cast_expr(c, scope, @as(*const clang.ImplicitCastExpr, @ptr_cast(stmt)), result_used),
        .IntegerLiteralClass => return trans_integer_literal(c, scope, @as(*const clang.IntegerLiteral, @ptr_cast(stmt)), result_used, .with_as),
        .ReturnStmtClass => return trans_return_stmt(c, scope, @as(*const clang.ReturnStmt, @ptr_cast(stmt))),
        .StringLiteralClass => return trans_string_literal(c, scope, @as(*const clang.StringLiteral, @ptr_cast(stmt)), result_used),
        .ParenExprClass => {
            const expr = try trans_expr(c, scope, @as(*const clang.ParenExpr, @ptr_cast(stmt)).getSubExpr(), .used);
            return maybe_suppress_result(c, result_used, expr);
        },
        .InitListExprClass => return trans_init_list_expr(c, scope, @as(*const clang.InitListExpr, @ptr_cast(stmt)), result_used),
        .ImplicitValueInitExprClass => return trans_implicit_value_init_expr(c, scope, @as(*const clang.Expr, @ptr_cast(stmt))),
        .IfStmtClass => return trans_if_stmt(c, scope, @as(*const clang.IfStmt, @ptr_cast(stmt))),
        .WhileStmtClass => return trans_while_loop(c, scope, @as(*const clang.WhileStmt, @ptr_cast(stmt))),
        .DoStmtClass => return trans_do_while_loop(c, scope, @as(*const clang.DoStmt, @ptr_cast(stmt))),
        .NullStmtClass => {
            return Tag.empty_block.init();
        },
        .ContinueStmtClass => return Tag.@"continue".init(),
        .BreakStmtClass => return Tag.@"break".init(),
        .ForStmtClass => return trans_for_loop(c, scope, @as(*const clang.ForStmt, @ptr_cast(stmt))),
        .FloatingLiteralClass => return trans_floating_literal(c, @as(*const clang.FloatingLiteral, @ptr_cast(stmt)), result_used),
        .ConditionalOperatorClass => {
            return trans_conditional_operator(c, scope, @as(*const clang.ConditionalOperator, @ptr_cast(stmt)), result_used);
        },
        .BinaryConditionalOperatorClass => {
            return trans_binary_conditional_operator(c, scope, @as(*const clang.BinaryConditionalOperator, @ptr_cast(stmt)), result_used);
        },
        .SwitchStmtClass => return trans_switch(c, scope, @as(*const clang.SwitchStmt, @ptr_cast(stmt))),
        .CaseStmtClass, .DefaultStmtClass => {
            return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "TODO complex switch", .{});
        },
        .ConstantExprClass => return trans_constant_expr(c, scope, @as(*const clang.Expr, @ptr_cast(stmt)), result_used),
        .PredefinedExprClass => return trans_predefined_expr(c, scope, @as(*const clang.PredefinedExpr, @ptr_cast(stmt)), result_used),
        .CharacterLiteralClass => return trans_char_literal(c, scope, @as(*const clang.CharacterLiteral, @ptr_cast(stmt)), result_used, .with_as),
        .StmtExprClass => return trans_stmt_expr(c, scope, @as(*const clang.StmtExpr, @ptr_cast(stmt)), result_used),
        .MemberExprClass => return trans_member_expr(c, scope, @as(*const clang.MemberExpr, @ptr_cast(stmt)), result_used),
        .ArraySubscriptExprClass => return trans_array_access(c, scope, @as(*const clang.ArraySubscriptExpr, @ptr_cast(stmt)), result_used),
        .CallExprClass => return trans_call_expr(c, scope, @as(*const clang.CallExpr, @ptr_cast(stmt)), result_used),
        .UnaryExprOrTypeTraitExprClass => return trans_unary_expr_or_type_trait_expr(c, scope, @as(*const clang.UnaryExprOrTypeTraitExpr, @ptr_cast(stmt)), result_used),
        .UnaryOperatorClass => return trans_unary_operator(c, scope, @as(*const clang.UnaryOperator, @ptr_cast(stmt)), result_used),
        .CompoundAssignOperatorClass => return trans_compound_assign_operator(c, scope, @as(*const clang.CompoundAssignOperator, @ptr_cast(stmt)), result_used),
        .OpaqueValueExprClass => {
            const source_expr = @as(*const clang.OpaqueValueExpr, @ptr_cast(stmt)).getSourceExpr().?;
            const expr = try trans_expr(c, scope, source_expr, .used);
            return maybe_suppress_result(c, result_used, expr);
        },
        .OffsetOfExprClass => return trans_offset_of_expr(c, @as(*const clang.OffsetOfExpr, @ptr_cast(stmt)), result_used),
        .CompoundLiteralExprClass => {
            const compound_literal = @as(*const clang.CompoundLiteralExpr, @ptr_cast(stmt));
            return trans_expr(c, scope, compound_literal.getInitializer(), result_used);
        },
        .GenericSelectionExprClass => {
            const gen_sel = @as(*const clang.GenericSelectionExpr, @ptr_cast(stmt));
            return trans_expr(c, scope, gen_sel.getResultExpr(), result_used);
        },
        .ConvertVectorExprClass => {
            const conv_vec = @as(*const clang.ConvertVectorExpr, @ptr_cast(stmt));
            const conv_vec_node = try trans_convert_vector_expr(c, scope, conv_vec);
            return maybe_suppress_result(c, result_used, conv_vec_node);
        },
        .ShuffleVectorExprClass => {
            const shuffle_vec_expr = @as(*const clang.ShuffleVectorExpr, @ptr_cast(stmt));
            const shuffle_vec_node = try trans_shuffle_vector_expr(c, scope, shuffle_vec_expr);
            return maybe_suppress_result(c, result_used, shuffle_vec_node);
        },
        .ChooseExprClass => {
            const choose_expr = @as(*const clang.ChooseExpr, @ptr_cast(stmt));
            return trans_expr(c, scope, choose_expr.getChosenSubExpr(), result_used);
        },
        // When adding new cases here, see comment for maybe_blockify()
        .GCCAsmStmtClass,
        .GotoStmtClass,
        .IndirectGotoStmtClass,
        .AttributedStmtClass,
        .AddrLabelExprClass,
        .AtomicExprClass,
        .BlockExprClass,
        .UserDefinedLiteralClass,
        .BuiltinBitCastExprClass,
        .DesignatedInitExprClass,
        .LabelStmtClass,
        => return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "TODO implement translation of stmt class {s}", .{@tag_name(sc)}),
        else => return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "unsupported stmt class {s}", .{@tag_name(sc)}),
    }
}

/// See https://clang.llvm.org/docs/LanguageExtensions.html#langext-builtin-convertvector
fn trans_convert_vector_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.ConvertVectorExpr,
) TransError!Node {
    const base_stmt = @as(*const clang.Stmt, @ptr_cast(expr));

    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const src_expr = expr.getSrcExpr();
    const src_type = qual_type_canon(src_expr.get_type());
    const src_vector_ty = @as(*const clang.VectorType, @ptr_cast(src_type));
    const src_element_qt = src_vector_ty.getElementType();

    const src_expr_node = try trans_expr(c, &block_scope.base, src_expr, .used);

    const dst_qt = expr.getTypeSourceInfo_getType();
    const dst_type_node = try trans_qual_type(c, &block_scope.base, dst_qt, base_stmt.getBeginLoc());
    const dst_vector_ty = @as(*const clang.VectorType, @ptr_cast(qual_type_canon(dst_qt)));
    const num_elements = dst_vector_ty.getNumElements();
    const dst_element_qt = dst_vector_ty.getElementType();

    // workaround for https://github.com/ziglang/zig/issues/8322
    // we store the casted results into temp variables and use those
    // to initialize the vector. Eventually we can just directly
    // construct the init_list from casted source members
    var i: usize = 0;
    while (i < num_elements) : (i += 1) {
        const mangled_name = try block_scope.make_mangled_name(c, "tmp");
        const value = try Tag.array_access.create(c.arena, .{
            .lhs = src_expr_node,
            .rhs = try trans_create_node_number(c, i, .int),
        });
        const tmp_decl_node = try Tag.var_simple.create(c.arena, .{
            .name = mangled_name,
            .init = try trans_ccast(c, &block_scope.base, base_stmt.getBeginLoc(), dst_element_qt, src_element_qt, value),
        });
        try block_scope.statements.append(tmp_decl_node);
    }

    const init_list = try c.arena.alloc(Node, num_elements);
    for (init_list, 0..) |*init, init_index| {
        const tmp_decl = block_scope.statements.items[init_index];
        const name = tmp_decl.cast_tag(.var_simple).?.data.name;
        init.* = try Tag.identifier.create(c.arena, name);
    }

    const vec_init = try Tag.array_init.create(c.arena, .{
        .cond = dst_type_node,
        .cases = init_list,
    });

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = vec_init,
    });
    try block_scope.statements.append(break_node);
    return block_scope.complete(c);
}

fn make_shuffle_mask(c: *Context, scope: *Scope, expr: *const clang.ShuffleVectorExpr, vector_len: Node) TransError!Node {
    const num_subexprs = expr.getNumSubExprs();
    assert(num_subexprs >= 3); // two source vectors + at least 1 index expression
    const mask_len = num_subexprs - 2;

    const mask_type = try Tag.vector.create(c.arena, .{
        .lhs = try trans_create_node_number(c, mask_len, .int),
        .rhs = try Tag.type.create(c.arena, "i32"),
    });

    const init_list = try c.arena.alloc(Node, mask_len);

    for (init_list, 0..) |*init, i| {
        const index_expr = try trans_expr_coercing(c, scope, expr.getExpr(@as(c_uint, @int_cast(i + 2))), .used);
        const converted_index = try Tag.helpers_shuffle_vector_index.create(c.arena, .{ .lhs = index_expr, .rhs = vector_len });
        init.* = converted_index;
    }

    return Tag.array_init.create(c.arena, .{
        .cond = mask_type,
        .cases = init_list,
    });
}

/// @typeInfo(@TypeOf(vec_node)).Vector.<field>
fn vector_type_info(arena: mem.Allocator, vec_node: Node, field: []const u8) TransError!Node {
    const typeof_call = try Tag.typeof.create(arena, vec_node);
    const typeinfo_call = try Tag.typeinfo.create(arena, typeof_call);
    const vector_type_info = try Tag.field_access.create(arena, .{ .lhs = typeinfo_call, .field_name = "Vector" });
    return Tag.field_access.create(arena, .{ .lhs = vector_type_info, .field_name = field });
}

fn trans_shuffle_vector_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.ShuffleVectorExpr,
) TransError!Node {
    const base_expr = @as(*const clang.Expr, @ptr_cast(expr));
    const num_subexprs = expr.getNumSubExprs();
    if (num_subexprs < 3) return fail(c, error.UnsupportedTranslation, base_expr.getBeginLoc(), "ShuffleVector needs at least 1 index", .{});

    const a = try trans_expr(c, scope, expr.getExpr(0), .used);
    const b = try trans_expr(c, scope, expr.getExpr(1), .used);

    // clang requires first two arguments to __builtin_shufflevector to be same type
    const vector_child_type = try vector_type_info(c.arena, a, "child");
    const vector_len = try vector_type_info(c.arena, a, "len");
    const shuffle_mask = try make_shuffle_mask(c, scope, expr, vector_len);

    return Tag.shuffle.create(c.arena, .{
        .element_type = vector_child_type,
        .a = a,
        .b = b,
        .mask_vector = shuffle_mask,
    });
}

/// Translate a "simple" offsetof expression containing exactly one component,
/// when that component is of kind .Field - e.g. offsetof(mytype, myfield)
fn trans_simple_offset_of_expr(c: *Context, expr: *const clang.OffsetOfExpr) TransError!Node {
    assert(expr.getNumComponents() == 1);
    const component = expr.getComponent(0);
    if (component.get_kind() == .Field) {
        const field_decl = component.getField();
        if (field_decl.getParent()) |record_decl| {
            if (c.decl_table.get(@int_from_ptr(record_decl.getCanonicalDecl()))) |type_name| {
                const type_node = try Tag.type.create(c.arena, type_name);

                const raw_field_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(field_decl)).getName_bytes_begin());
                const quoted_field_name = try std.fmt.alloc_print(c.arena, "\"{s}\"", .{raw_field_name});
                const field_name_node = try Tag.string_literal.create(c.arena, quoted_field_name);

                return Tag.offset_of.create(c.arena, .{
                    .lhs = type_node,
                    .rhs = field_name_node,
                });
            }
        }
    }
    return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "failed to translate simple OffsetOfExpr", .{});
}

fn trans_offset_of_expr(
    c: *Context,
    expr: *const clang.OffsetOfExpr,
    result_used: ResultUsed,
) TransError!Node {
    if (expr.getNumComponents() == 1) {
        const offsetof_expr = try trans_simple_offset_of_expr(c, expr);
        return maybe_suppress_result(c, result_used, offsetof_expr);
    }

    // TODO implement OffsetOfExpr with more than 1 component
    // OffsetOfExpr API:
    //     call expr.getComponent(idx) while idx < expr.getNumComponents()
    //     component.get_kind() will be either .Array or .Field (other kinds are C++-only)
    //     if .Field, use component.getField() to retrieve *clang.FieldDecl
    //     if .Array, use component.getArrayExprIndex() to get a c_uint which
    //         can be passed to expr.getIndexExpr(expr_index) to get the *clang.Expr for the array index

    return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "TODO: implement complex OffsetOfExpr translation", .{});
}

/// Cast a signed integer node to a usize, for use in pointer arithmetic. Negative numbers
/// will become very large positive numbers but that is ok since we only use this in
/// pointer arithmetic expressions, where wraparound will ensure we get the correct value.
/// node -> @bit_cast(usize, @int_cast(isize, node))
fn usize_cast_for_wrapping_ptr_arithmetic(gpa: mem.Allocator, node: Node) TransError!Node {
    const intcast_node = try Tag.as.create(gpa, .{
        .lhs = try Tag.type.create(gpa, "isize"),
        .rhs = try Tag.int_cast.create(gpa, node),
    });

    return Tag.as.create(gpa, .{
        .lhs = try Tag.type.create(gpa, "usize"),
        .rhs = try Tag.bit_cast.create(gpa, intcast_node),
    });
}

/// Translate an arithmetic expression with a pointer operand and a signed-integer operand.
/// Zig requires a usize argument for pointer arithmetic, so we int_cast to isize and then
/// bitcast to usize; pointer wraparound make the math work.
/// Zig pointer addition is not commutative (unlike C); the pointer operand needs to be on the left.
/// The + operator in C is not a sequence point so it should be safe to switch the order if necessary.
fn trans_create_pointer_arithmetic_signed_op(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.BinaryOperator,
    result_used: ResultUsed,
) TransError!Node {
    const is_add = stmt.getOpcode() == .Add;
    const lhs = stmt.getLHS();
    const rhs = stmt.getRHS();
    const swap_operands = is_add and c_is_signed_integer(get_expr_qual_type(c, lhs));

    const swizzled_lhs = if (swap_operands) rhs else lhs;
    const swizzled_rhs = if (swap_operands) lhs else rhs;

    const lhs_node = try trans_expr(c, scope, swizzled_lhs, .used);
    const rhs_node = try trans_expr(c, scope, swizzled_rhs, .used);

    const bitcast_node = try usize_cast_for_wrapping_ptr_arithmetic(c.arena, rhs_node);

    return trans_create_node_infix_op(
        c,
        if (is_add) .add else .sub,
        lhs_node,
        bitcast_node,
        result_used,
    );
}

fn trans_binary_operator(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.BinaryOperator,
    result_used: ResultUsed,
) TransError!Node {
    const op = stmt.getOpcode();
    const qt = stmt.get_type();
    const isPointerDiffExpr = c_is_pointer_diff_expr(stmt);
    switch (op) {
        .Assign => return try trans_create_node_assign(c, scope, result_used, stmt.getLHS(), stmt.getRHS()),
        .Comma => {
            var block_scope = try Scope.Block.init(c, scope, true);
            defer block_scope.deinit();

            const lhs = try trans_expr(c, &block_scope.base, stmt.getLHS(), .unused);
            try block_scope.statements.append(lhs);

            const rhs = try trans_expr(c, &block_scope.base, stmt.getRHS(), .used);
            const break_node = try Tag.break_val.create(c.arena, .{
                .label = block_scope.label,
                .val = rhs,
            });
            try block_scope.statements.append(break_node);
            const block_node = try block_scope.complete(c);
            return maybe_suppress_result(c, result_used, block_node);
        },
        .Div => {
            if (c_is_signed_integer(qt)) {
                // signed integer division uses @div_trunc
                const lhs = try trans_expr(c, scope, stmt.getLHS(), .used);
                const rhs = try trans_expr(c, scope, stmt.getRHS(), .used);
                const div_trunc = try Tag.div_trunc.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
                return maybe_suppress_result(c, result_used, div_trunc);
            }
        },
        .Rem => {
            if (c_is_signed_integer(qt)) {
                // signed integer remainder uses std.zig.c_translation.signed_remainder
                const lhs = try trans_expr(c, scope, stmt.getLHS(), .used);
                const rhs = try trans_expr(c, scope, stmt.getRHS(), .used);
                const rem = try Tag.signed_remainder.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
                return maybe_suppress_result(c, result_used, rem);
            }
        },
        .Shl => {
            return trans_create_node_shift_op(c, scope, stmt, .shl, result_used);
        },
        .Shr => {
            return trans_create_node_shift_op(c, scope, stmt, .shr, result_used);
        },
        .LAnd => {
            return trans_create_node_bool_infix_op(c, scope, stmt, .@"and", result_used);
        },
        .LOr => {
            return trans_create_node_bool_infix_op(c, scope, stmt, .@"or", result_used);
        },
        .Add, .Sub => {
            // `ptr + idx` and `idx + ptr` -> ptr + @bit_cast(usize, @int_cast(isize, idx))
            // `ptr - idx` -> ptr - @bit_cast(usize, @int_cast(isize, idx))
            if (qual_type_is_ptr(qt) and (c_is_signed_integer(get_expr_qual_type(c, stmt.getLHS())) or
                c_is_signed_integer(get_expr_qual_type(c, stmt.getRHS())))) return trans_create_pointer_arithmetic_signed_op(c, scope, stmt, result_used);
        },
        else => {},
    }
    var op_id: Tag = undefined;
    switch (op) {
        .Add => {
            if (c_is_unsigned_integer(qt)) {
                op_id = .add_wrap;
            } else {
                op_id = .add;
            }
        },
        .Sub => {
            if (c_is_unsigned_integer(qt) or isPointerDiffExpr) {
                op_id = .sub_wrap;
            } else {
                op_id = .sub;
            }
        },
        .Mul => {
            if (c_is_unsigned_integer(qt)) {
                op_id = .mul_wrap;
            } else {
                op_id = .mul;
            }
        },
        .Div => {
            // unsigned/float division uses the operator
            op_id = .div;
        },
        .Rem => {
            // unsigned/float division uses the operator
            op_id = .mod;
        },
        .LT => {
            op_id = .less_than;
        },
        .GT => {
            op_id = .greater_than;
        },
        .LE => {
            op_id = .less_than_equal;
        },
        .GE => {
            op_id = .greater_than_equal;
        },
        .EQ => {
            op_id = .equal;
        },
        .NE => {
            op_id = .not_equal;
        },
        .And => {
            op_id = .bit_and;
        },
        .Xor => {
            op_id = .bit_xor;
        },
        .Or => {
            op_id = .bit_or;
        },
        else => unreachable,
    }

    const lhs_uncasted = try trans_expr(c, scope, stmt.getLHS(), .used);
    const rhs_uncasted = try trans_expr(c, scope, stmt.getRHS(), .used);

    const lhs = if (is_bool_res(lhs_uncasted))
        try Tag.int_from_bool.create(c.arena, lhs_uncasted)
    else if (isPointerDiffExpr)
        try Tag.int_from_ptr.create(c.arena, lhs_uncasted)
    else
        lhs_uncasted;

    const rhs = if (is_bool_res(rhs_uncasted))
        try Tag.int_from_bool.create(c.arena, rhs_uncasted)
    else if (isPointerDiffExpr)
        try Tag.int_from_ptr.create(c.arena, rhs_uncasted)
    else
        rhs_uncasted;

    const infixOpNode = try trans_create_node_infix_op(c, op_id, lhs, rhs, result_used);
    if (isPointerDiffExpr) {
        // @div_exact(@bit_cast(<platform-ptrdiff_t>, @int_from_ptr(lhs) -% @int_from_ptr(rhs)), @size_of(<lhs target type>))
        const ptrdiff_type = try trans_qual_type_int_width_of(c, qt, true);

        // C standard requires that pointer subtraction operands are of the same type,
        // otherwise it is undefined behavior. So we can assume the left and right
        // sides are the same QualType and arbitrarily choose left.
        const lhs_expr = stmt.getLHS();
        const lhs_qt = get_expr_qual_type(c, lhs_expr);
        const lhs_qt_translated = try trans_qual_type(c, scope, lhs_qt, lhs_expr.getBeginLoc());
        const c_pointer = get_container(c, lhs_qt_translated).?;
        const elem_type = c_pointer.cast_tag(.c_pointer).?.data.elem_type;
        const sizeof = try Tag.sizeof.create(c.arena, elem_type);

        const bitcast = try Tag.as.create(c.arena, .{
            .lhs = ptrdiff_type,
            .rhs = try Tag.bit_cast.create(c.arena, infixOpNode),
        });

        return Tag.div_exact.create(c.arena, .{
            .lhs = bitcast,
            .rhs = sizeof,
        });
    }
    return infixOpNode;
}

fn trans_compound_stmt_inline(
    c: *Context,
    stmt: *const clang.CompoundStmt,
    block: *Scope.Block,
) TransError!void {
    var it = stmt.body_begin();
    const end_it = stmt.body_end();
    while (it != end_it) : (it += 1) {
        const result = try trans_stmt(c, &block.base, it[0], .unused);
        switch (result.tag()) {
            .declaration, .empty_block => {},
            else => try block.statements.append(result),
        }
    }
}

fn trans_compound_stmt(c: *Context, scope: *Scope, stmt: *const clang.CompoundStmt) TransError!Node {
    var block_scope = try Scope.Block.init(c, scope, false);
    defer block_scope.deinit();
    try trans_compound_stmt_inline(c, stmt, &block_scope);
    return try block_scope.complete(c);
}

fn trans_cstyle_cast_expr_class(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.CStyleCastExpr,
    result_used: ResultUsed,
) TransError!Node {
    const cast_expr = @as(*const clang.CastExpr, @ptr_cast(stmt));
    const sub_expr = stmt.getSubExpr();
    const dst_type = stmt.get_type();
    const src_type = sub_expr.get_type();
    const sub_expr_node = try trans_expr(c, scope, sub_expr, .used);
    const loc = stmt.getBeginLoc();

    const cast_node = if (cast_expr.getCastKind() == .ToUnion) blk: {
        const field_decl = cast_expr.getTargetFieldForToUnionCast(dst_type, src_type).?; // C syntax error if target field is null
        const field_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(field_decl)).getName_bytes_begin());

        const union_ty = try trans_qual_type(c, scope, dst_type, loc);

        const inits = [1]ast.Payload.ContainerInit.Initializer{.{ .name = field_name, .value = sub_expr_node }};
        break :blk try Tag.container_init.create(c.arena, .{
            .lhs = union_ty,
            .inits = try c.arena.dupe(ast.Payload.ContainerInit.Initializer, &inits),
        });
    } else (try trans_ccast(
        c,
        scope,
        loc,
        dst_type,
        src_type,
        sub_expr_node,
    ));
    return maybe_suppress_result(c, result_used, cast_node);
}

/// The alignment of a variable or field
const ClangAlignment = struct {
    /// Clang reports the alignment in bits, we use bytes
    /// Clang uses 0 for "no alignment specified", we use null
    bit_alignment: c_uint,
    /// If the field or variable is marked as 'packed'
    ///
    /// According to the GCC variable attribute docs, this impacts alignment
    /// https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html
    ///
    /// > The packed attribute specifies that a structure member
    /// > should have the smallest possible alignment
    ///
    /// Note also that specifying the 'packed' attribute on a structure
    /// implicitly packs all its fields (making their alignment 1).
    ///
    /// This will be null if the AST node doesn't support packing (functions)
    is_packed: ?bool,

    /// Get the alignment for a field, optionally taking into account the parent record
    pub fn for_field(c: *const Context, field: *const clang.FieldDecl, parent: ?*const clang.RecordDecl) ClangAlignment {
        const parent_packed = if (parent) |record| record.getPackedAttribute() else false;
        // NOTE: According to GCC docs, parent attribute packed implies child attribute packed
        return ClangAlignment{
            .bit_alignment = field.getAlignedAttribute(c.clang_context),
            .is_packed = field.getPackedAttribute() or parent_packed,
        };
    }

    pub fn for_var(c: *const Context, var_decl: *const clang.VarDecl) ClangAlignment {
        return ClangAlignment{
            .bit_alignment = var_decl.getAlignedAttribute(c.clang_context),
            .is_packed = var_decl.getPackedAttribute(),
        };
    }

    pub fn for_func(c: *const Context, fun: *const clang.FunctionDecl) ClangAlignment {
        return ClangAlignment{
            .bit_alignment = fun.getAlignedAttribute(c.clang_context),
            .is_packed = null, // not supported by GCC/clang (or meaningful),
        };
    }

    /// Translate the clang alignment info into a zig alignment
    ///
    /// Returns null if there is no special alignment info
    pub fn zig_alignment(self: ClangAlignment) ?c_uint {
        if (self.bit_alignment != 0) {
            return self.bit_alignment / 8;
        } else if (self.is_packed orelse false) {
            return 1;
        } else {
            return null;
        }
    }
};

fn trans_decl_stmt_one(
    c: *Context,
    scope: *Scope,
    decl: *const clang.Decl,
    block_scope: *Scope.Block,
) TransError!void {
    switch (decl.get_kind()) {
        .Var => {
            const var_decl = @as(*const clang.VarDecl, @ptr_cast(decl));
            const decl_init = var_decl.getInit();
            const loc = decl.getLocation();

            const qual_type = var_decl.getTypeSourceInfo_getType();
            const name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(var_decl)).getName_bytes_begin());
            const mangled_name = try block_scope.make_mangled_name(c, name);

            if (var_decl.getStorageClass() == .Extern) {
                // This is actually a global variable, put it in the global scope and reference it.
                // `_ = mangled_name;`
                return visit_var_decl(c, var_decl, mangled_name);
            } else if (qual_type_was_demoted_to_opaque(c, qual_type)) {
                return fail(c, error.UnsupportedTranslation, loc, "local variable has opaque type", .{});
            }

            const is_static_local = var_decl.isStaticLocal();
            const is_const = qual_type.isConstQualified();
            const type_node = try trans_qual_type_maybe_initialized(c, scope, qual_type, decl_init, loc);

            var init_node = if (decl_init) |expr|
                if (expr.getStmtClass() == .StringLiteralClass)
                    try trans_string_literal_initializer(c, @as(*const clang.StringLiteral, @ptr_cast(expr)), type_node)
                else
                    try trans_expr_coercing(c, scope, expr, .used)
            else if (is_static_local)
                try Tag.std_mem_zeroes.create(c.arena, type_node)
            else
                Tag.undefined_literal.init();
            if (!qual_type_is_boolean(qual_type) and is_bool_res(init_node)) {
                init_node = try Tag.int_from_bool.create(c.arena, init_node);
            } else if (init_node.tag() == .string_literal and qual_type_is_char_star(qual_type)) {
                const dst_type_node = try trans_qual_type(c, scope, qual_type, loc);
                init_node = try remove_cvqualifiers(c, dst_type_node, init_node);
            }

            const var_name: []const u8 = if (is_static_local) Scope.Block.static_inner_name else mangled_name;
            var node = try Tag.var_decl.create(c.arena, .{
                .is_pub = false,
                .is_const = is_const,
                .is_extern = false,
                .is_export = false,
                .is_threadlocal = var_decl.getTLSKind() != .None,
                .linksection_string = null,
                .alignment = ClangAlignment.for_var(c, var_decl).zig_alignment(),
                .name = var_name,
                .type = type_node,
                .init = init_node,
            });
            if (is_static_local) {
                node = try Tag.static_local_var.create(c.arena, .{ .name = mangled_name, .init = node });
            }
            try block_scope.statements.append(node);
            try block_scope.discard_variable(c, mangled_name);

            const cleanup_attr = var_decl.getCleanupAttribute();
            if (cleanup_attr) |fn_decl| {
                const cleanup_fn_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(fn_decl)).getName_bytes_begin());
                const fn_id = try Tag.identifier.create(c.arena, cleanup_fn_name);

                const varname = try Tag.identifier.create(c.arena, mangled_name);
                const args = try c.arena.alloc(Node, 1);
                args[0] = try Tag.address_of.create(c.arena, varname);

                const cleanup_call = try Tag.call.create(c.arena, .{ .lhs = fn_id, .args = args });
                const discard = try Tag.discard.create(c.arena, .{ .should_skip = false, .value = cleanup_call });
                const deferred_cleanup = try Tag.@"defer".create(c.arena, discard);

                try block_scope.statements.append(deferred_cleanup);
            }
        },
        .Typedef => {
            try trans_type_def(c, scope, @as(*const clang.TypedefNameDecl, @ptr_cast(decl)));
        },
        .Record => {
            try trans_record_decl(c, scope, @as(*const clang.RecordDecl, @ptr_cast(decl)));
        },
        .Enum => {
            try trans_enum_decl(c, scope, @as(*const clang.EnumDecl, @ptr_cast(decl)));
        },
        .Function => {
            try visit_fn_decl(c, @as(*const clang.FunctionDecl, @ptr_cast(decl)));
        },
        else => {
            const decl_name = try c.str(decl.getDeclKindName());
            try warn(c, &c.global_scope.base, decl.getLocation(), "ignoring {s} declaration", .{decl_name});
        },
    }
}

fn trans_decl_stmt(c: *Context, scope: *Scope, stmt: *const clang.DeclStmt) TransError!Node {
    const block_scope = try scope.find_block_scope(c);

    var it = stmt.decl_begin();
    const end_it = stmt.decl_end();
    while (it != end_it) : (it += 1) {
        try trans_decl_stmt_one(c, scope, it[0], block_scope);
    }
    return Tag.declaration.init();
}

fn trans_decl_ref_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.DeclRefExpr,
) TransError!Node {
    const value_decl = expr.get_decl();
    const name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(value_decl)).getName_bytes_begin());
    const mangled_name = scope.get_alias(name);
    var ref_expr = if (c_is_function_decl_ref(@as(*const clang.Expr, @ptr_cast(expr))))
        try Tag.fn_identifier.create(c.arena, mangled_name)
    else
        try Tag.identifier.create(c.arena, mangled_name);

    if (@as(*const clang.Decl, @ptr_cast(value_decl)).get_kind() == .Var) {
        const var_decl = @as(*const clang.VarDecl, @ptr_cast(value_decl));
        if (var_decl.isStaticLocal()) {
            ref_expr = try Tag.field_access.create(c.arena, .{
                .lhs = ref_expr,
                .field_name = Scope.Block.static_inner_name,
            });
        }
    }
    scope.skip_variable_discard(mangled_name);
    return ref_expr;
}

fn trans_implicit_cast_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.ImplicitCastExpr,
    result_used: ResultUsed,
) TransError!Node {
    const sub_expr = expr.getSubExpr();
    const dest_type = get_expr_qual_type(c, @as(*const clang.Expr, @ptr_cast(expr)));
    const src_type = get_expr_qual_type(c, sub_expr);
    switch (expr.getCastKind()) {
        .BitCast, .FloatingCast, .FloatingToIntegral, .IntegralToFloating, .IntegralCast, .PointerToIntegral, .IntegralToPointer => {
            const sub_expr_node = try trans_expr(c, scope, sub_expr, .used);
            const casted = try trans_ccast(c, scope, expr.getBeginLoc(), dest_type, src_type, sub_expr_node);
            return maybe_suppress_result(c, result_used, casted);
        },
        .LValueToRValue, .NoOp, .FunctionToPointerDecay => {
            const sub_expr_node = try trans_expr(c, scope, sub_expr, .used);
            return maybe_suppress_result(c, result_used, sub_expr_node);
        },
        .ArrayToPointerDecay => {
            const sub_expr_node = try trans_expr(c, scope, sub_expr, .used);
            if (expr_is_narrow_string_literal(sub_expr) or expr_is_flexible_array_ref(c, sub_expr)) {
                return maybe_suppress_result(c, result_used, sub_expr_node);
            }

            const addr = try Tag.address_of.create(c.arena, sub_expr_node);
            const casted = try trans_cptr_cast(c, scope, expr.getBeginLoc(), dest_type, src_type, addr);
            return maybe_suppress_result(c, result_used, casted);
        },
        .NullToPointer => {
            return Tag.null_literal.init();
        },
        .PointerToBoolean => {
            // @int_from_ptr(val) != 0
            const ptr_node = try trans_expr(c, scope, sub_expr, .used);
            const int_from_ptr = try Tag.int_from_ptr.create(c.arena, ptr_node);

            const ne = try Tag.not_equal.create(c.arena, .{ .lhs = int_from_ptr, .rhs = Tag.zero_literal.init() });
            return maybe_suppress_result(c, result_used, ne);
        },
        .IntegralToBoolean, .FloatingToBoolean => {
            const sub_expr_node = try trans_expr(c, scope, sub_expr, .used);

            // The expression is already a boolean one, return it as-is
            if (is_bool_res(sub_expr_node))
                return maybe_suppress_result(c, result_used, sub_expr_node);

            // val != 0
            const ne = try Tag.not_equal.create(c.arena, .{ .lhs = sub_expr_node, .rhs = Tag.zero_literal.init() });
            return maybe_suppress_result(c, result_used, ne);
        },
        .BuiltinFnToFnPtr => {
            return trans_builtin_fn_expr(c, scope, sub_expr, result_used);
        },
        .ToVoid => {
            // Should only appear in the rhs and lhs of a ConditionalOperator
            return trans_expr(c, scope, sub_expr, .unused);
        },
        else => |kind| return fail(
            c,
            error.UnsupportedTranslation,
            @as(*const clang.Stmt, @ptr_cast(expr)).getBeginLoc(),
            "unsupported CastKind {s}",
            .{@tag_name(kind)},
        ),
    }
}

fn is_builtin_defined(name: []const u8) bool {
    inline for (@typeInfo(std.zig.c_builtins).Struct.decls) |decl| {
        if (std.mem.eql(u8, name, decl.name)) return true;
    }
    return false;
}

fn trans_builtin_fn_expr(c: *Context, scope: *Scope, expr: *const clang.Expr, used: ResultUsed) TransError!Node {
    const node = try trans_expr(c, scope, expr, used);
    if (node.cast_tag(.fn_identifier)) |ident| {
        const name = ident.data;
        if (!is_builtin_defined(name)) return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "TODO implement function '{s}' in std.zig.c_builtins", .{name});
    }
    return node;
}

fn trans_bool_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.Expr,
    used: ResultUsed,
) TransError!Node {
    if (@as(*const clang.Stmt, @ptr_cast(expr)).getStmtClass() == .IntegerLiteralClass) {
        var signum: c_int = undefined;
        if (!(@as(*const clang.IntegerLiteral, @ptr_cast(expr)).getSignum(&signum, c.clang_context))) {
            return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "invalid integer literal", .{});
        }
        const is_zero = signum == 0;
        return Node{ .tag_if_small_enough = @int_from_enum(([2]Tag{ .true_literal, .false_literal })[@int_from_bool(is_zero)]) };
    }

    const res = try trans_expr(c, scope, expr, used);
    if (is_bool_res(res)) {
        return maybe_suppress_result(c, used, res);
    }

    const ty = get_expr_qual_type(c, expr).getTypePtr();
    const node = try finish_bool_expr(c, scope, expr.getBeginLoc(), ty, res, used);

    return maybe_suppress_result(c, used, node);
}

fn expr_is_boolean_type(expr: *const clang.Expr) bool {
    return qual_type_is_boolean(expr.get_type());
}

fn expr_is_narrow_string_literal(expr: *const clang.Expr) bool {
    switch (expr.getStmtClass()) {
        .StringLiteralClass => {
            const string_lit = @as(*const clang.StringLiteral, @ptr_cast(expr));
            return string_lit.getCharByteWidth() == 1;
        },
        .PredefinedExprClass => return true,
        .UnaryOperatorClass => {
            const op_expr = @as(*const clang.UnaryOperator, @ptr_cast(expr)).getSubExpr();
            return expr_is_narrow_string_literal(op_expr);
        },
        .ParenExprClass => {
            const op_expr = @as(*const clang.ParenExpr, @ptr_cast(expr)).getSubExpr();
            return expr_is_narrow_string_literal(op_expr);
        },
        .GenericSelectionExprClass => {
            const gen_sel = @as(*const clang.GenericSelectionExpr, @ptr_cast(expr));
            return expr_is_narrow_string_literal(gen_sel.getResultExpr());
        },
        else => return false,
    }
}

fn expr_is_flexible_array_ref(c: *Context, expr: *const clang.Expr) bool {
    if (expr.getStmtClass() == .MemberExprClass) {
        const member_expr = @as(*const clang.MemberExpr, @ptr_cast(expr));
        const member_decl = member_expr.getMemberDecl();
        const decl_kind = @as(*const clang.Decl, @ptr_cast(member_decl)).get_kind();
        if (decl_kind == .Field) {
            const field_decl = @as(*const clang.FieldDecl, @ptr_cast(member_decl));
            return is_flexible_array_field_decl(c, field_decl);
        }
    }
    return false;
}

fn is_bool_res(res: Node) bool {
    switch (res.tag()) {
        .@"or",
        .@"and",
        .equal,
        .not_equal,
        .less_than,
        .less_than_equal,
        .greater_than,
        .greater_than_equal,
        .not,
        .false_literal,
        .true_literal,
        => return true,
        else => return false,
    }
}

fn finish_bool_expr(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    ty: *const clang.Type,
    node: Node,
    used: ResultUsed,
) TransError!Node {
    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));

            switch (builtin_ty.get_kind()) {
                .Bool => return node,
                .Char_U,
                .UChar,
                .Char_S,
                .SChar,
                .UShort,
                .UInt,
                .ULong,
                .ULongLong,
                .Short,
                .Int,
                .Long,
                .LongLong,
                .UInt128,
                .Int128,
                .Float,
                .Double,
                .Float128,
                .LongDouble,
                .WChar_U,
                .Char8,
                .Char16,
                .Char32,
                .WChar_S,
                .Float16,
                => {
                    // node != 0
                    return Tag.not_equal.create(c.arena, .{ .lhs = node, .rhs = Tag.zero_literal.init() });
                },
                .NullPtr => {
                    // node == null
                    return Tag.equal.create(c.arena, .{ .lhs = node, .rhs = Tag.null_literal.init() });
                },
                else => {},
            }
        },
        .Pointer => {
            if (node.tag() == .string_literal) {
                // @int_from_ptr(node) != 0
                const int_from_ptr = try Tag.int_from_ptr.create(c.arena, node);
                return Tag.not_equal.create(c.arena, .{ .lhs = int_from_ptr, .rhs = Tag.zero_literal.init() });
            }
            // node != null
            return Tag.not_equal.create(c.arena, .{ .lhs = node, .rhs = Tag.null_literal.init() });
        },
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));
            const typedef_decl = typedef_ty.get_decl();
            const underlying_type = typedef_decl.getUnderlyingType();
            return finish_bool_expr(c, scope, loc, underlying_type.getTypePtr(), node, used);
        },
        .Enum => {
            // node != 0
            return Tag.not_equal.create(c.arena, .{ .lhs = node, .rhs = Tag.zero_literal.init() });
        },
        .Elaborated => {
            const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(ty));
            const named_type = elaborated_ty.getNamedType();
            return finish_bool_expr(c, scope, loc, named_type.getTypePtr(), node, used);
        },
        else => {},
    }
    return fail(c, error.UnsupportedType, loc, "unsupported bool expression type", .{});
}

const SuppressCast = enum {
    with_as,
    no_as,
};
fn trans_integer_literal(
    c: *Context,
    scope: *Scope,
    expr: *const clang.IntegerLiteral,
    result_used: ResultUsed,
    suppress_as: SuppressCast,
) TransError!Node {
    var eval_result: clang.ExprEvalResult = undefined;
    if (!expr.EvaluateAsInt(&eval_result, c.clang_context)) {
        const loc = expr.getBeginLoc();
        return fail(c, error.UnsupportedTranslation, loc, "invalid integer literal", .{});
    }

    if (suppress_as == .no_as) {
        const int_lit_node = try trans_create_node_apint(c, eval_result.Val.getInt());
        return maybe_suppress_result(c, result_used, int_lit_node);
    }

    // Integer literals in C have types, and this can matter for several reasons.
    // For example, this is valid C:
    //     unsigned char y = 256;
    // How this gets evaluated is the 256 is an integer, which gets truncated to signed char, then bit-casted
    // to unsigned char, resulting in 0. In order for this to work, we have to emit this zig code:
    //     var y = @as(u8, @bit_cast(@as(i8, @truncate(@as(c_int, 256)))));
    // Ideally in translate-c we could flatten this out to simply:
    //     var y: u8 = 0;
    // But the first step is to be correct, and the next step is to make the output more elegant.

    // @as(T, x)
    const expr_base = @as(*const clang.Expr, @ptr_cast(expr));
    const ty_node = try trans_qual_type(c, scope, expr_base.get_type(), expr_base.getBeginLoc());
    const rhs = try trans_create_node_apint(c, eval_result.Val.getInt());
    const as = try Tag.as.create(c.arena, .{ .lhs = ty_node, .rhs = rhs });
    return maybe_suppress_result(c, result_used, as);
}

fn trans_return_stmt(
    c: *Context,
    scope: *Scope,
    expr: *const clang.ReturnStmt,
) TransError!Node {
    const val_expr = expr.getRetValue() orelse
        return Tag.return_void.init();

    var rhs = try trans_expr_coercing(c, scope, val_expr, .used);
    const return_qt = scope.find_block_return_type();
    if (is_bool_res(rhs) and !qual_type_is_boolean(return_qt)) {
        rhs = try Tag.int_from_bool.create(c.arena, rhs);
    }
    return Tag.@"return".create(c.arena, rhs);
}

fn trans_narrow_string_literal(
    c: *Context,
    stmt: *const clang.StringLiteral,
    result_used: ResultUsed,
) TransError!Node {
    var len: usize = undefined;
    const bytes_ptr = stmt.getString_bytes_begin_size(&len);

    const str = try std.fmt.alloc_print(c.arena, "\"{}\"", .{std.zig.fmt_escapes(bytes_ptr[0..len])});
    const node = try Tag.string_literal.create(c.arena, str);
    return maybe_suppress_result(c, result_used, node);
}

fn trans_string_literal(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.StringLiteral,
    result_used: ResultUsed,
) TransError!Node {
    const kind = stmt.get_kind();
    switch (kind) {
        .Ascii, .UTF8 => return trans_narrow_string_literal(c, stmt, result_used),
        .UTF16, .UTF32, .Wide => {
            const str_type = @tag_name(stmt.get_kind());
            const name = try std.fmt.alloc_print(c.arena, "zig.{s}_string_{d}", .{ str_type, c.get_mangle() });

            const expr_base = @as(*const clang.Expr, @ptr_cast(stmt));
            const array_type = try trans_qual_type_initialized(c, scope, expr_base.get_type(), expr_base, expr_base.getBeginLoc());
            const lit_array = try trans_string_literal_initializer(c, stmt, array_type);
            const decl = try Tag.var_simple.create(c.arena, .{ .name = name, .init = lit_array });
            try scope.append_node(decl);
            const node = try Tag.identifier.create(c.arena, name);
            return maybe_suppress_result(c, result_used, node);
        },
    }
}

fn get_array_payload(array_type: Node) ast.Payload.Array.ArrayTypeInfo {
    return (array_type.cast_tag(.array_type) orelse array_type.cast_tag(.null_sentinel_array_type).?).data;
}

/// Translate a string literal that is initializing an array. In general narrow string
/// literals become `"<string>".*` or `"<string>"[0..<size>].*` if they need truncation.
/// Wide string literals become an array of integers. zero-fillers pad out the array to
/// the appropriate length, if necessary.
fn trans_string_literal_initializer(
    c: *Context,
    stmt: *const clang.StringLiteral,
    array_type: Node,
) TransError!Node {
    assert(array_type.tag() == .array_type or array_type.tag() == .null_sentinel_array_type);

    const is_narrow = stmt.get_kind() == .Ascii or stmt.get_kind() == .UTF8;

    const str_length = stmt.get_length();
    const payload = get_array_payload(array_type);
    const array_size = payload.len;
    const elem_type = payload.elem_type;

    if (array_size == 0) return Tag.empty_array.create(c.arena, elem_type);

    const num_inits = @min(str_length, array_size);
    const init_node = if (num_inits > 0) blk: {
        if (is_narrow) {
            // "string literal".* or string literal"[0..num_inits].*
            var str = try trans_narrow_string_literal(c, stmt, .used);
            if (str_length != array_size) str = try Tag.string_slice.create(c.arena, .{ .string = str, .end = num_inits });
            break :blk try Tag.deref.create(c.arena, str);
        } else {
            const init_list = try c.arena.alloc(Node, num_inits);
            var i: c_uint = 0;
            while (i < num_inits) : (i += 1) {
                init_list[i] = try trans_create_char_lit_node(c, false, stmt.getCodeUnit(i));
            }
            const init_args = .{ .len = num_inits, .elem_type = elem_type };
            const init_array_type = try if (array_type.tag() == .array_type) Tag.array_type.create(c.arena, init_args) else Tag.null_sentinel_array_type.create(c.arena, init_args);
            break :blk try Tag.array_init.create(c.arena, .{
                .cond = init_array_type,
                .cases = init_list,
            });
        }
    } else null;

    if (num_inits == array_size) return init_node.?; // init_node is only null if num_inits == 0; but if num_inits == array_size == 0 we've already returned
    assert(array_size > str_length); // If array_size <= str_length, `num_inits == array_size` and we've already returned.

    const filler_node = try Tag.array_filler.create(c.arena, .{
        .type = elem_type,
        .filler = Tag.zero_literal.init(),
        .count = array_size - str_length,
    });

    if (init_node) |some| {
        return Tag.array_cat.create(c.arena, .{ .lhs = some, .rhs = filler_node });
    } else {
        return filler_node;
    }
}

/// determine whether `stmt` is a "pointer subtraction expression" - a subtraction where
/// both operands resolve to addresses. The C standard requires that both operands
/// point to elements of the same array object, but we do not verify that here.
fn c_is_pointer_diff_expr(stmt: *const clang.BinaryOperator) bool {
    const lhs = @as(*const clang.Stmt, @ptr_cast(stmt.getLHS()));
    const rhs = @as(*const clang.Stmt, @ptr_cast(stmt.getRHS()));
    return stmt.getOpcode() == .Sub and
        qual_type_is_ptr(@as(*const clang.Expr, @ptr_cast(lhs)).get_type()) and
        qual_type_is_ptr(@as(*const clang.Expr, @ptr_cast(rhs)).get_type());
}

fn c_is_enum(qt: clang.QualType) bool {
    return qt.getCanonicalType().getTypeClass() == .Enum;
}

fn c_is_vector(qt: clang.QualType) bool {
    return qt.getCanonicalType().getTypeClass() == .Vector;
}

/// Get the underlying int type of an enum. The C compiler chooses a signed int
/// type that is large enough to hold all of the enum's values. It is not required
/// to be the smallest possible type that can hold all the values.
fn c_int_type_for_enum(enum_qt: clang.QualType) clang.QualType {
    assert(c_is_enum(enum_qt));
    const ty = enum_qt.getCanonicalType().getTypePtr();
    const enum_ty = @as(*const clang.EnumType, @ptr_cast(ty));
    const enum_decl = enum_ty.get_decl();
    return enum_decl.getIntegerType();
}

// when modifying this function, make sure to also update std.zig.c_translation.cast
fn trans_ccast(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    dst_type: clang.QualType,
    src_type: clang.QualType,
    expr: Node,
) !Node {
    if (qual_type_canon(dst_type).isVoidType()) return expr;
    if (dst_type.eq(src_type)) return expr;
    if (qual_type_is_ptr(dst_type) and qual_type_is_ptr(src_type))
        return trans_cptr_cast(c, scope, loc, dst_type, src_type, expr);
    if (c_is_enum(dst_type)) return trans_ccast(c, scope, loc, c_int_type_for_enum(dst_type), src_type, expr);
    if (c_is_enum(src_type)) return trans_ccast(c, scope, loc, dst_type, c_int_type_for_enum(src_type), expr);

    const dst_node = try trans_qual_type(c, scope, dst_type, loc);
    if (c_is_integer(dst_type) and c_is_integer(src_type)) {
        // 1. If src_type is an enum, determine the underlying signed int type
        // 2. Extend or truncate without changing signed-ness.
        // 3. Bit-cast to correct signed-ness
        const src_type_is_signed = c_is_signed_integer(src_type);
        var src_int_expr = expr;

        if (is_bool_res(src_int_expr)) {
            src_int_expr = try Tag.int_from_bool.create(c.arena, src_int_expr);
            return Tag.as.create(c.arena, .{ .lhs = dst_node, .rhs = src_int_expr });
        }

        switch (c_int_type_cmp(dst_type, src_type)) {
            .lt => {
                // @truncate(SameSignSmallerInt, src_int_expr)
                const ty_node = try trans_qual_type_int_width_of(c, dst_type, src_type_is_signed);
                src_int_expr = try Tag.as.create(c.arena, .{
                    .lhs = ty_node,
                    .rhs = try Tag.truncate.create(c.arena, src_int_expr),
                });
            },
            .gt => {
                // @as(SameSignBiggerInt, src_int_expr)
                const ty_node = try trans_qual_type_int_width_of(c, dst_type, src_type_is_signed);
                src_int_expr = try Tag.as.create(c.arena, .{ .lhs = ty_node, .rhs = src_int_expr });
            },
            .eq => {
                // src_int_expr = src_int_expr
            },
        }
        // @as(dest_type, @bit_cast(intermediate_value))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.bit_cast.create(c.arena, src_int_expr),
        });
    }
    if (c_is_vector(src_type) or c_is_vector(dst_type)) {
        // C cast where at least 1 operand is a vector requires them to be same size
        // @as(dest_type, @bit_cast(val))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.bit_cast.create(c.arena, expr),
        });
    }
    if (c_is_integer(dst_type) and qual_type_is_ptr(src_type)) {
        // @int_cast(dest_type, @int_from_ptr(val))
        const int_from_ptr = try Tag.int_from_ptr.create(c.arena, expr);
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.int_cast.create(c.arena, int_from_ptr),
        });
    }
    if (c_is_integer(src_type) and qual_type_is_ptr(dst_type)) {
        // @as(dest_type, @ptrFromInt(val))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.ptr_from_int.create(c.arena, expr),
        });
    }
    if (c_is_floating(src_type) and c_is_floating(dst_type)) {
        // @as(dest_type, @float_cast(val))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.float_cast.create(c.arena, expr),
        });
    }
    if (c_is_floating(src_type) and !c_is_floating(dst_type)) {
        // bool expression: floating val != 0
        if (qual_type_is_boolean(dst_type)) {
            return Tag.not_equal.create(c.arena, .{
                .lhs = expr,
                .rhs = Tag.zero_literal.init(),
            });
        }

        // @as(dest_type, @int_from_float(val))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.int_from_float.create(c.arena, expr),
        });
    }
    if (!c_is_floating(src_type) and c_is_floating(dst_type)) {
        var rhs = expr;
        if (qual_type_is_boolean(src_type) or is_bool_res(rhs)) rhs = try Tag.int_from_bool.create(c.arena, expr);
        // @as(dest_type, @float_from_int(val))
        return Tag.as.create(c.arena, .{
            .lhs = dst_node,
            .rhs = try Tag.float_from_int.create(c.arena, rhs),
        });
    }
    if (qual_type_is_boolean(src_type) and !qual_type_is_boolean(dst_type)) {
        // @int_from_bool returns a u1
        // TODO: if dst_type is 1 bit & signed (bitfield) we need @bit_cast
        // instead of @as
        const int_from_bool = try Tag.int_from_bool.create(c.arena, expr);
        return Tag.as.create(c.arena, .{ .lhs = dst_node, .rhs = int_from_bool });
    }
    // @as(dest_type, val)
    return Tag.as.create(c.arena, .{ .lhs = dst_node, .rhs = expr });
}

fn trans_expr(c: *Context, scope: *Scope, expr: *const clang.Expr, used: ResultUsed) TransError!Node {
    return trans_stmt(c, scope, @as(*const clang.Stmt, @ptr_cast(expr)), used);
}

/// Same as `trans_expr` but with the knowledge that the operand will be type coerced, and therefore
/// an `@as` would be redundant. This is used to prevent redundant `@as` in integer literals.
fn trans_expr_coercing(c: *Context, scope: *Scope, expr: *const clang.Expr, used: ResultUsed) TransError!Node {
    switch (@as(*const clang.Stmt, @ptr_cast(expr)).getStmtClass()) {
        .IntegerLiteralClass => {
            return trans_integer_literal(c, scope, @as(*const clang.IntegerLiteral, @ptr_cast(expr)), .used, .no_as);
        },
        .CharacterLiteralClass => {
            return trans_char_literal(c, scope, @as(*const clang.CharacterLiteral, @ptr_cast(expr)), .used, .no_as);
        },
        .UnaryOperatorClass => {
            const un_expr = @as(*const clang.UnaryOperator, @ptr_cast(expr));
            if (un_expr.getOpcode() == .Extension) {
                return trans_expr_coercing(c, scope, un_expr.getSubExpr(), used);
            }
        },
        .ImplicitCastExprClass => {
            const cast_expr = @as(*const clang.ImplicitCastExpr, @ptr_cast(expr));
            const sub_expr = cast_expr.getSubExpr();
            switch (@as(*const clang.Stmt, @ptr_cast(sub_expr)).getStmtClass()) {
                .IntegerLiteralClass, .CharacterLiteralClass => switch (cast_expr.getCastKind()) {
                    .IntegralToFloating => return trans_expr_coercing(c, scope, sub_expr, used),
                    .IntegralCast => {
                        const dest_type = get_expr_qual_type(c, expr);
                        if (literal_fits_in_type(c, sub_expr, dest_type))
                            return trans_expr_coercing(c, scope, sub_expr, used);
                    },
                    else => {},
                },
                else => {},
            }
        },
        else => {},
    }
    return trans_expr(c, scope, expr, .used);
}

fn literal_fits_in_type(c: *Context, expr: *const clang.Expr, qt: clang.QualType) bool {
    var width = qual_type_int_bit_width(c, qt) catch 8;
    if (width == 0) width = 8; // Byte is the smallest type.
    const is_signed = c_is_signed_integer(qt);
    const width_max_int = (@as(u64, 1) << math.lossy_cast(u6, width - @int_from_bool(is_signed))) - 1;

    switch (@as(*const clang.Stmt, @ptr_cast(expr)).getStmtClass()) {
        .CharacterLiteralClass => {
            const char_lit = @as(*const clang.CharacterLiteral, @ptr_cast(expr));
            const val = char_lit.get_value();
            // If the val is less than the max int then it fits.
            return val <= width_max_int;
        },
        .IntegerLiteralClass => {
            const int_lit = @as(*const clang.IntegerLiteral, @ptr_cast(expr));
            var eval_result: clang.ExprEvalResult = undefined;
            if (!int_lit.EvaluateAsInt(&eval_result, c.clang_context)) {
                return false;
            }

            const int = eval_result.Val.getInt();
            return int.lessThanEqual(width_max_int);
        },
        else => unreachable,
    }
}

fn trans_init_list_expr_record(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    expr: *const clang.InitListExpr,
    ty: *const clang.Type,
) TransError!Node {
    var is_union_type = false;
    // Unions and Structs are both represented as RecordDecl
    const record_ty = ty.getAsRecordType() orelse
        blk: {
        is_union_type = true;
        break :blk ty.getAsUnionType();
    } orelse unreachable;
    const record_decl = record_ty.get_decl();
    const record_def = record_decl.getDefinition() orelse
        unreachable;

    const ty_node = try trans_type(c, scope, ty, loc);
    const init_count = expr.getNumInits();
    var field_inits = std.ArrayList(ast.Payload.ContainerInit.Initializer).init(c.gpa);
    defer field_inits.deinit();

    if (init_count == 0) {
        const source_loc = @as(*const clang.Expr, @ptr_cast(expr)).getBeginLoc();
        return trans_zero_init_expr(c, scope, source_loc, ty);
    }

    var init_i: c_uint = 0;
    var it = record_def.field_begin();
    const end_it = record_def.field_end();
    while (it.neq(end_it)) : (it = it.next()) {
        const field_decl = it.deref();

        // The initializer for a union type has a single entry only
        if (is_union_type and field_decl != expr.getInitializedFieldInUnion()) {
            continue;
        }

        assert(init_i < init_count);
        const elem_expr = expr.getInit(init_i);
        init_i += 1;

        // Generate the field assignment expression:
        //     .field_name = expr
        var raw_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(field_decl)).getName_bytes_begin());
        if (field_decl.isAnonymousStructOrUnion()) {
            const name = c.decl_table.get(@int_from_ptr(field_decl.getCanonicalDecl())).?;
            raw_name = try c.arena.dupe(u8, name);
        }

        var init_expr = try trans_expr(c, scope, elem_expr, .used);
        const field_qt = field_decl.get_type();
        if (init_expr.tag() == .string_literal and qual_type_is_char_star(field_qt)) {
            if (scope.id == .root) {
                init_expr = try string_literal_to_char_star(c, init_expr);
            } else {
                const dst_type_node = try trans_qual_type(c, scope, field_qt, loc);
                init_expr = try remove_cvqualifiers(c, dst_type_node, init_expr);
            }
        }
        try field_inits.append(.{
            .name = raw_name,
            .value = init_expr,
        });
    }
    if (ty_node.cast_tag(.identifier)) |ident_node| {
        scope.skip_variable_discard(ident_node.data);
    }
    return Tag.container_init.create(c.arena, .{
        .lhs = ty_node,
        .inits = try c.arena.dupe(ast.Payload.ContainerInit.Initializer, field_inits.items),
    });
}

fn trans_init_list_expr_array(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    expr: *const clang.InitListExpr,
    ty: *const clang.Type,
) TransError!Node {
    const arr_type = ty.getAsArrayTypeUnsafe();
    const child_qt = arr_type.getElementType();
    const child_type = try trans_qual_type(c, scope, child_qt, loc);
    const init_count = expr.getNumInits();
    assert(@as(*const clang.Type, @ptr_cast(arr_type)).isConstantArrayType());
    const const_arr_ty = @as(*const clang.ConstantArrayType, @ptr_cast(arr_type));
    const size_ap_int = const_arr_ty.get_size();
    const all_count = size_ap_int.get_limited_value(usize);
    const leftover_count = all_count - init_count;

    if (all_count == 0) {
        return Tag.empty_array.create(c.arena, child_type);
    }

    if (expr.isStringLiteralInit()) {
        assert(init_count == 1);
        const init_expr = expr.getInit(0);
        const string_literal = init_expr.castToStringLiteral().?;
        return try trans_string_literal(c, scope, string_literal, .used);
    }

    const init_node = if (init_count != 0) blk: {
        const init_list = try c.arena.alloc(Node, init_count);

        for (init_list, 0..) |*init, i| {
            const elem_expr = expr.getInit(@as(c_uint, @int_cast(i)));
            init.* = try trans_expr_coercing(c, scope, elem_expr, .used);
        }
        const init_node = try Tag.array_init.create(c.arena, .{
            .cond = try Tag.array_type.create(c.arena, .{ .len = init_count, .elem_type = child_type }),
            .cases = init_list,
        });
        if (leftover_count == 0) {
            return init_node;
        }
        break :blk init_node;
    } else null;

    assert(expr.hasArrayFiller());
    const filler_val_expr = expr.getArrayFiller();
    const filler_node = try Tag.array_filler.create(c.arena, .{
        .type = child_type,
        .filler = try trans_expr_coercing(c, scope, filler_val_expr, .used),
        .count = leftover_count,
    });

    if (init_node) |some| {
        return Tag.array_cat.create(c.arena, .{ .lhs = some, .rhs = filler_node });
    } else {
        return filler_node;
    }
}

fn trans_init_list_expr_vector(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    expr: *const clang.InitListExpr,
) TransError!Node {
    const qt = get_expr_qual_type(c, @as(*const clang.Expr, @ptr_cast(expr)));
    const vector_ty = @as(*const clang.VectorType, @ptr_cast(qual_type_canon(qt)));

    const init_count = expr.getNumInits();
    const num_elements = vector_ty.getNumElements();
    const element_qt = vector_ty.getElementType();

    if (init_count == 0) {
        const vec_node = try Tag.vector.create(c.arena, .{
            .lhs = try trans_create_node_number(c, num_elements, .int),
            .rhs = try trans_qual_type(c, scope, element_qt, loc),
        });

        return Tag.as.create(c.arena, .{
            .lhs = vec_node,
            .rhs = try Tag.vector_zero_init.create(c.arena, Tag.zero_literal.init()),
        });
    }

    const vector_type = try trans_qual_type(c, scope, qt, loc);

    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    // workaround for https://github.com/ziglang/zig/issues/8322
    // we store the initializers in temp variables and use those
    // to initialize the vector. Eventually we can just directly
    // construct the init_list from casted source members
    var i: usize = 0;
    while (i < init_count) : (i += 1) {
        const mangled_name = try block_scope.make_mangled_name(c, "tmp");
        const init_expr = expr.getInit(@as(c_uint, @int_cast(i)));
        const tmp_decl_node = try Tag.var_simple.create(c.arena, .{
            .name = mangled_name,
            .init = try trans_expr(c, &block_scope.base, init_expr, .used),
        });
        try block_scope.statements.append(tmp_decl_node);
    }

    const init_list = try c.arena.alloc(Node, num_elements);
    for (init_list, 0..) |*init, init_index| {
        if (init_index < init_count) {
            const tmp_decl = block_scope.statements.items[init_index];
            const name = tmp_decl.cast_tag(.var_simple).?.data.name;
            init.* = try Tag.identifier.create(c.arena, name);
        } else {
            init.* = Tag.undefined_literal.init();
        }
    }

    const array_init = try Tag.array_init.create(c.arena, .{
        .cond = vector_type,
        .cases = init_list,
    });
    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = array_init,
    });
    try block_scope.statements.append(break_node);

    return block_scope.complete(c);
}

fn trans_init_list_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.InitListExpr,
    used: ResultUsed,
) TransError!Node {
    const qt = get_expr_qual_type(c, @as(*const clang.Expr, @ptr_cast(expr)));
    var qual_type = qt.getTypePtr();
    const source_loc = @as(*const clang.Expr, @ptr_cast(expr)).getBeginLoc();

    if (qual_type_was_demoted_to_opaque(c, qt)) {
        return fail(c, error.UnsupportedTranslation, source_loc, "cannot initialize opaque type", .{});
    }

    if (qual_type.isRecordType()) {
        return maybe_suppress_result(c, used, try trans_init_list_expr_record(
            c,
            scope,
            source_loc,
            expr,
            qual_type,
        ));
    } else if (qual_type.isArrayType()) {
        return maybe_suppress_result(c, used, try trans_init_list_expr_array(
            c,
            scope,
            source_loc,
            expr,
            qual_type,
        ));
    } else if (qual_type.isVectorType()) {
        return maybe_suppress_result(c, used, try trans_init_list_expr_vector(c, scope, source_loc, expr));
    } else {
        const type_name = try c.str(qual_type.getTypeClassName());
        return fail(c, error.UnsupportedType, source_loc, "unsupported initlist type: '{s}'", .{type_name});
    }
}

fn trans_zero_init_expr(
    c: *Context,
    scope: *Scope,
    source_loc: clang.SourceLocation,
    ty: *const clang.Type,
) TransError!Node {
    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));
            switch (builtin_ty.get_kind()) {
                .Bool => return Tag.false_literal.init(),
                .Char_U,
                .UChar,
                .Char_S,
                .Char8,
                .SChar,
                .UShort,
                .UInt,
                .ULong,
                .ULongLong,
                .Short,
                .Int,
                .Long,
                .LongLong,
                .UInt128,
                .Int128,
                .Float,
                .Double,
                .Float128,
                .Float16,
                .LongDouble,
                => return Tag.zero_literal.init(),
                else => return fail(c, error.UnsupportedType, source_loc, "unsupported builtin type", .{}),
            }
        },
        .Pointer => return Tag.null_literal.init(),
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));
            const typedef_decl = typedef_ty.get_decl();
            return trans_zero_init_expr(
                c,
                scope,
                source_loc,
                typedef_decl.getUnderlyingType().getTypePtr(),
            );
        },
        else => return Tag.std_mem_zeroes.create(c.arena, try trans_type(c, scope, ty, source_loc)),
    }
}

fn trans_implicit_value_init_expr(
    c: *Context,
    scope: *Scope,
    expr: *const clang.Expr,
) TransError!Node {
    const source_loc = expr.getBeginLoc();
    const qt = get_expr_qual_type(c, expr);
    const ty = qt.getTypePtr();
    return trans_zero_init_expr(c, scope, source_loc, ty);
}

/// If a statement can possibly translate to a Zig assignment (either directly because it's
/// an assignment in C or indirectly via result assignment to `_`) AND it's the sole statement
/// in the body of an if statement or loop, then we need to put the statement into its own block.
/// The `else` case here corresponds to statements that could result in an assignment. If a statement
/// class never needs a block, add its enum to the top prong.
fn maybe_blockify(c: *Context, scope: *Scope, stmt: *const clang.Stmt) TransError!Node {
    switch (stmt.getStmtClass()) {
        .BreakStmtClass,
        .CompoundStmtClass,
        .ContinueStmtClass,
        .DeclRefExprClass,
        .DeclStmtClass,
        .DoStmtClass,
        .ForStmtClass,
        .IfStmtClass,
        .ReturnStmtClass,
        .NullStmtClass,
        .WhileStmtClass,
        => return trans_stmt(c, scope, stmt, .unused),
        else => return blockify(c, scope, stmt),
    }
}

fn blockify(c: *Context, scope: *Scope, stmt: *const clang.Stmt) TransError!Node {
    var block_scope = try Scope.Block.init(c, scope, false);
    defer block_scope.deinit();
    const result = try trans_stmt(c, &block_scope.base, stmt, .unused);
    try block_scope.statements.append(result);
    return block_scope.complete(c);
}

fn trans_if_stmt(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.IfStmt,
) TransError!Node {
    // if (c) t
    // if (c) t else e
    var cond_scope = Scope.Condition{
        .base = .{
            .parent = scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();
    const cond_expr = @as(*const clang.Expr, @ptr_cast(stmt.getCond()));
    const cond = try trans_bool_expr(c, &cond_scope.base, cond_expr, .used);

    const then_stmt = stmt.getThen();
    const else_stmt = stmt.getElse();
    const then_class = then_stmt.getStmtClass();
    // block needed to keep else statement from attaching to inner while
    const must_blockify = (else_stmt != null) and switch (then_class) {
        .DoStmtClass, .ForStmtClass, .WhileStmtClass => true,
        else => false,
    };

    const then_body = if (must_blockify)
        try blockify(c, scope, then_stmt)
    else
        try maybe_blockify(c, scope, then_stmt);

    const else_body = if (else_stmt) |expr|
        try maybe_blockify(c, scope, expr)
    else
        null;
    return Tag.@"if".create(c.arena, .{ .cond = cond, .then = then_body, .@"else" = else_body });
}

fn trans_while_loop(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.WhileStmt,
) TransError!Node {
    var cond_scope = Scope.Condition{
        .base = .{
            .parent = scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();
    const cond_expr = @as(*const clang.Expr, @ptr_cast(stmt.getCond()));
    const cond = try trans_bool_expr(c, &cond_scope.base, cond_expr, .used);

    var loop_scope = Scope{
        .parent = scope,
        .id = .loop,
    };
    const body = try maybe_blockify(c, &loop_scope, stmt.getBody());
    return Tag.@"while".create(c.arena, .{ .cond = cond, .body = body, .cont_expr = null });
}

fn trans_do_while_loop(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.DoStmt,
) TransError!Node {
    var loop_scope = Scope{
        .parent = scope,
        .id = .do_loop,
    };

    // if (!cond) break;
    var cond_scope = Scope.Condition{
        .base = .{
            .parent = scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();
    const cond = try trans_bool_expr(c, &cond_scope.base, @as(*const clang.Expr, @ptr_cast(stmt.getCond())), .used);
    const if_not_break = switch (cond.tag()) {
        .true_literal => {
            const body_node = try maybe_blockify(c, scope, stmt.getBody());
            return Tag.while_true.create(c.arena, body_node);
        },
        else => try Tag.if_not_break.create(c.arena, cond),
    };

    var body_node = try trans_stmt(c, &loop_scope, stmt.getBody(), .unused);
    if (body_node.is_noreturn(true)) {
        // The body node ends in a noreturn statement. Simply put it in a while (true)
        // in case it contains breaks or continues.
    } else if (stmt.getBody().getStmtClass() == .CompoundStmtClass) {
        // there's already a block in C, so we'll append our condition to it.
        // c: do {
        // c:   a;
        // c:   b;
        // c: } while(c);
        // zig: while (true) {
        // zig:   a;
        // zig:   b;
        // zig:   if (!cond) break;
        // zig: }
        const block = body_node.cast_tag(.block).?;
        block.data.stmts.len += 1; // This is safe since we reserve one extra space in Scope.Block.complete.
        block.data.stmts[block.data.stmts.len - 1] = if_not_break;
    } else {
        // the C statement is without a block, so we need to create a block to contain it.
        // c: do
        // c:   a;
        // c: while(c);
        // zig: while (true) {
        // zig:   a;
        // zig:   if (!cond) break;
        // zig: }
        const statements = try c.arena.alloc(Node, 2);
        statements[0] = body_node;
        statements[1] = if_not_break;
        body_node = try Tag.block.create(c.arena, .{ .label = null, .stmts = statements });
    }
    return Tag.while_true.create(c.arena, body_node);
}

fn trans_for_loop(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.ForStmt,
) TransError!Node {
    var loop_scope = Scope{
        .parent = scope,
        .id = .loop,
    };

    var block_scope: ?Scope.Block = null;
    defer if (block_scope) |*bs| bs.deinit();

    if (stmt.getInit()) |init| {
        block_scope = try Scope.Block.init(c, scope, false);
        loop_scope.parent = &block_scope.?.base;
        const init_node = try trans_stmt(c, &block_scope.?.base, init, .unused);
        if (init_node.tag() != .declaration) try block_scope.?.statements.append(init_node);
    }
    var cond_scope = Scope.Condition{
        .base = .{
            .parent = &loop_scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();

    const cond = if (stmt.getCond()) |cond|
        try trans_bool_expr(c, &cond_scope.base, cond, .used)
    else
        Tag.true_literal.init();

    const cont_expr = if (stmt.getInc()) |incr|
        try trans_expr(c, &cond_scope.base, incr, .unused)
    else
        null;

    const body = try maybe_blockify(c, &loop_scope, stmt.getBody());
    const while_node = try Tag.@"while".create(c.arena, .{ .cond = cond, .body = body, .cont_expr = cont_expr });
    if (block_scope) |*bs| {
        try bs.statements.append(while_node);
        return try bs.complete(c);
    } else {
        return while_node;
    }
}

fn trans_switch(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.SwitchStmt,
) TransError!Node {
    var loop_scope = Scope{
        .parent = scope,
        .id = .loop,
    };

    var block_scope = try Scope.Block.init(c, &loop_scope, false);
    defer block_scope.deinit();

    const base_scope = &block_scope.base;

    var cond_scope = Scope.Condition{
        .base = .{
            .parent = base_scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();
    const switch_expr = try trans_expr(c, &cond_scope.base, stmt.getCond(), .used);

    var cases = std.ArrayList(Node).init(c.gpa);
    defer cases.deinit();
    var has_default = false;

    const body = stmt.getBody();
    assert(body.getStmtClass() == .CompoundStmtClass);
    const compound_stmt = @as(*const clang.CompoundStmt, @ptr_cast(body));
    var it = compound_stmt.body_begin();
    const end_it = compound_stmt.body_end();
    // Iterate over switch body and collect all cases.
    // Fallthrough is handled by duplicating statements.
    while (it != end_it) : (it += 1) {
        switch (it[0].getStmtClass()) {
            .CaseStmtClass => {
                var items = std.ArrayList(Node).init(c.gpa);
                defer items.deinit();
                const sub = try trans_case_stmt(c, base_scope, it[0], &items);
                const res = try trans_switch_prong_stmt(c, base_scope, sub, it, end_it);

                if (items.items.len == 0) {
                    has_default = true;
                    const switch_else = try Tag.switch_else.create(c.arena, res);
                    try cases.append(switch_else);
                } else {
                    const switch_prong = try Tag.switch_prong.create(c.arena, .{
                        .cases = try c.arena.dupe(Node, items.items),
                        .cond = res,
                    });
                    try cases.append(switch_prong);
                }
            },
            .DefaultStmtClass => {
                has_default = true;
                const default_stmt = @as(*const clang.DefaultStmt, @ptr_cast(it[0]));

                var sub = default_stmt.getSubStmt();
                while (true) switch (sub.getStmtClass()) {
                    .CaseStmtClass => sub = @as(*const clang.CaseStmt, @ptr_cast(sub)).getSubStmt(),
                    .DefaultStmtClass => sub = @as(*const clang.DefaultStmt, @ptr_cast(sub)).getSubStmt(),
                    else => break,
                };

                const res = try trans_switch_prong_stmt(c, base_scope, sub, it, end_it);

                const switch_else = try Tag.switch_else.create(c.arena, res);
                try cases.append(switch_else);
            },
            else => {}, // collected in trans_switch_prong_stmt
        }
    }

    if (!has_default) {
        const else_prong = try Tag.switch_else.create(c.arena, Tag.empty_block.init());
        try cases.append(else_prong);
    }

    const switch_node = try Tag.@"switch".create(c.arena, .{
        .cond = switch_expr,
        .cases = try c.arena.dupe(Node, cases.items),
    });
    try block_scope.statements.append(switch_node);
    try block_scope.statements.append(Tag.@"break".init());
    const while_body = try block_scope.complete(c);

    return Tag.while_true.create(c.arena, while_body);
}

/// Collects all items for this case, returns the first statement after the labels.
/// If items ends up empty, the prong should be translated as an else.
fn trans_case_stmt(c: *Context, scope: *Scope, stmt: *const clang.Stmt, items: *std.ArrayList(Node)) TransError!*const clang.Stmt {
    var sub = stmt;
    var seen_default = false;
    while (true) {
        switch (sub.getStmtClass()) {
            .DefaultStmtClass => {
                seen_default = true;
                items.items.len = 0;
                const default_stmt = @as(*const clang.DefaultStmt, @ptr_cast(sub));
                sub = default_stmt.getSubStmt();
            },
            .CaseStmtClass => {
                const case_stmt = @as(*const clang.CaseStmt, @ptr_cast(sub));

                if (seen_default) {
                    items.items.len = 0;
                    sub = case_stmt.getSubStmt();
                    continue;
                }

                const expr = if (case_stmt.getRHS()) |rhs| blk: {
                    const lhs_node = try trans_expr_coercing(c, scope, case_stmt.getLHS(), .used);
                    const rhs_node = try trans_expr_coercing(c, scope, rhs, .used);

                    break :blk try Tag.ellipsis3.create(c.arena, .{ .lhs = lhs_node, .rhs = rhs_node });
                } else try trans_expr_coercing(c, scope, case_stmt.getLHS(), .used);

                try items.append(expr);
                sub = case_stmt.getSubStmt();
            },
            else => return sub,
        }
    }
}

/// Collects all statements seen by this case into a block.
/// Avoids creating a block if the first statement is a break or return.
fn trans_switch_prong_stmt(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.Stmt,
    parent_it: clang.CompoundStmt.ConstBodyIterator,
    parent_end_it: clang.CompoundStmt.ConstBodyIterator,
) TransError!Node {
    switch (stmt.getStmtClass()) {
        .BreakStmtClass => return Tag.@"break".init(),
        .ReturnStmtClass => return trans_stmt(c, scope, stmt, .unused),
        .CaseStmtClass, .DefaultStmtClass => unreachable,
        else => {
            var block_scope = try Scope.Block.init(c, scope, false);
            defer block_scope.deinit();

            // we do not need to translate `stmt` since it is the first stmt of `parent_it`
            try trans_switch_prong_stmt_inline(c, &block_scope, parent_it, parent_end_it);
            return try block_scope.complete(c);
        },
    }
}

/// Collects all statements seen by this case into a block.
fn trans_switch_prong_stmt_inline(
    c: *Context,
    block: *Scope.Block,
    start_it: clang.CompoundStmt.ConstBodyIterator,
    end_it: clang.CompoundStmt.ConstBodyIterator,
) TransError!void {
    var it = start_it;
    while (it != end_it) : (it += 1) {
        switch (it[0].getStmtClass()) {
            .ReturnStmtClass => {
                const result = try trans_stmt(c, &block.base, it[0], .unused);
                try block.statements.append(result);
                return;
            },
            .BreakStmtClass => {
                try block.statements.append(Tag.@"break".init());
                return;
            },
            .CaseStmtClass => {
                var sub = @as(*const clang.CaseStmt, @ptr_cast(it[0])).getSubStmt();
                while (true) switch (sub.getStmtClass()) {
                    .CaseStmtClass => sub = @as(*const clang.CaseStmt, @ptr_cast(sub)).getSubStmt(),
                    .DefaultStmtClass => sub = @as(*const clang.DefaultStmt, @ptr_cast(sub)).getSubStmt(),
                    else => break,
                };
                const result = try trans_stmt(c, &block.base, sub, .unused);
                assert(result.tag() != .declaration);
                try block.statements.append(result);
                if (result.is_noreturn(true)) {
                    return;
                }
            },
            .DefaultStmtClass => {
                var sub = @as(*const clang.DefaultStmt, @ptr_cast(it[0])).getSubStmt();
                while (true) switch (sub.getStmtClass()) {
                    .CaseStmtClass => sub = @as(*const clang.CaseStmt, @ptr_cast(sub)).getSubStmt(),
                    .DefaultStmtClass => sub = @as(*const clang.DefaultStmt, @ptr_cast(sub)).getSubStmt(),
                    else => break,
                };
                const result = try trans_stmt(c, &block.base, sub, .unused);
                assert(result.tag() != .declaration);
                try block.statements.append(result);
                if (result.is_noreturn(true)) {
                    return;
                }
            },
            .CompoundStmtClass => {
                const result = try trans_compound_stmt(c, &block.base, @as(*const clang.CompoundStmt, @ptr_cast(it[0])));
                try block.statements.append(result);
                if (result.is_noreturn(true)) {
                    return;
                }
            },
            else => {
                const result = try trans_stmt(c, &block.base, it[0], .unused);
                switch (result.tag()) {
                    .declaration, .empty_block => {},
                    else => try block.statements.append(result),
                }
            },
        }
    }
    return;
}

fn trans_constant_expr(c: *Context, scope: *Scope, expr: *const clang.Expr, used: ResultUsed) TransError!Node {
    var result: clang.ExprEvalResult = undefined;
    if (!expr.evaluateAsConstantExpr(&result, .Normal, c.clang_context))
        return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "invalid constant expression", .{});

    switch (result.Val.get_kind()) {
        .Int => {
            // See comment in `trans_integer_literal` for why this code is here.
            // @as(T, x)
            const expr_base = @as(*const clang.Expr, @ptr_cast(expr));
            const as_node = try Tag.as.create(c.arena, .{
                .lhs = try trans_qual_type(c, scope, expr_base.get_type(), expr_base.getBeginLoc()),
                .rhs = try trans_create_node_apint(c, result.Val.getInt()),
            });
            return maybe_suppress_result(c, used, as_node);
        },
        else => |kind| {
            return fail(c, error.UnsupportedTranslation, expr.getBeginLoc(), "unsupported constant expression kind '{}'", .{kind});
        },
    }
}

fn trans_predefined_expr(c: *Context, scope: *Scope, expr: *const clang.PredefinedExpr, used: ResultUsed) TransError!Node {
    return trans_string_literal(c, scope, expr.getFunctionName(), used);
}

fn trans_create_char_lit_node(c: *Context, narrow: bool, val: u32) TransError!Node {
    return Tag.char_literal.create(c.arena, if (narrow)
        try std.fmt.alloc_print(c.arena, "'{'}'", .{std.zig.fmt_escapes(&.{@as(u8, @int_cast(val))})})
    else
        try std.fmt.alloc_print(c.arena, "'\\u{{{x}}}'", .{val}));
}

fn trans_char_literal(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.CharacterLiteral,
    result_used: ResultUsed,
    suppress_as: SuppressCast,
) TransError!Node {
    const kind = stmt.get_kind();
    const val = stmt.get_value();
    const narrow = kind == .Ascii or kind == .UTF8;
    // C has a somewhat obscure feature called multi-character character constant
    // e.g. 'abcd'
    const int_lit_node = if (kind == .Ascii and val > 255)
        try trans_create_node_number(c, val, .int)
    else
        try trans_create_char_lit_node(c, narrow, val);

    if (suppress_as == .no_as) {
        return maybe_suppress_result(c, result_used, int_lit_node);
    }
    // See comment in `trans_integer_literal` for why this code is here.
    // @as(T, x)
    const expr_base = @as(*const clang.Expr, @ptr_cast(stmt));
    const as_node = try Tag.as.create(c.arena, .{
        .lhs = try trans_qual_type(c, scope, expr_base.get_type(), expr_base.getBeginLoc()),
        .rhs = int_lit_node,
    });
    return maybe_suppress_result(c, result_used, as_node);
}

fn trans_stmt_expr(c: *Context, scope: *Scope, stmt: *const clang.StmtExpr, used: ResultUsed) TransError!Node {
    const comp = stmt.getSubStmt();
    if (used == .unused) {
        return trans_compound_stmt(c, scope, comp);
    }
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    var it = comp.body_begin();
    const end_it = comp.body_end();
    while (it != end_it - 1) : (it += 1) {
        const result = try trans_stmt(c, &block_scope.base, it[0], .unused);
        switch (result.tag()) {
            .declaration, .empty_block => {},
            else => try block_scope.statements.append(result),
        }
    }

    const last_result = try trans_stmt(c, &block_scope.base, it[0], .used);
    switch (last_result.tag()) {
        .declaration, .empty_block => {},
        else => {
            const break_node = try Tag.break_val.create(c.arena, .{
                .label = block_scope.label,
                .val = last_result,
            });
            try block_scope.statements.append(break_node);
        },
    }
    const res = try block_scope.complete(c);
    return maybe_suppress_result(c, used, res);
}

fn trans_member_expr(c: *Context, scope: *Scope, stmt: *const clang.MemberExpr, result_used: ResultUsed) TransError!Node {
    var container_node = try trans_expr(c, scope, stmt.get_base(), .used);
    if (stmt.isArrow()) {
        container_node = try Tag.deref.create(c.arena, container_node);
    }

    const member_decl = stmt.getMemberDecl();
    const name = blk: {
        const decl_kind = @as(*const clang.Decl, @ptr_cast(member_decl)).get_kind();
        // If we're referring to a anonymous struct/enum find the bogus name
        // we've assigned to it during the RecordDecl translation
        if (decl_kind == .Field) {
            const field_decl = @as(*const clang.FieldDecl, @ptr_cast(member_decl));
            if (field_decl.isAnonymousStructOrUnion()) {
                const name = c.decl_table.get(@int_from_ptr(field_decl.getCanonicalDecl())).?;
                break :blk try c.arena.dupe(u8, name);
            }
        }
        const decl = @as(*const clang.NamedDecl, @ptr_cast(member_decl));
        break :blk try c.str(decl.getName_bytes_begin());
    };

    var node = try Tag.field_access.create(c.arena, .{ .lhs = container_node, .field_name = name });
    if (expr_is_flexible_array_ref(c, @as(*const clang.Expr, @ptr_cast(stmt)))) {
        node = try Tag.call.create(c.arena, .{ .lhs = node, .args = &.{} });
    }
    return maybe_suppress_result(c, result_used, node);
}

/// ptr[subscr] (`subscr` is a signed integer expression, `ptr` a pointer) becomes:
/// (blk: {
///     const tmp = subscr;
///     if (tmp >= 0) break :blk ptr + @int_cast(usize, tmp) else break :blk ptr - ~@bit_cast(usize, @int_cast(isize, tmp) +% -1);
/// }).*
/// Todo: rip this out once `[*]T + isize` becomes valid.
fn trans_signed_array_access(
    c: *Context,
    scope: *Scope,
    container_expr: *const clang.Expr,
    subscr_expr: *const clang.Expr,
    result_used: ResultUsed,
) TransError!Node {
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const tmp = try block_scope.make_mangled_name(c, "tmp");

    const subscr_node = try trans_expr(c, &block_scope.base, subscr_expr, .used);
    const subscr_decl = try Tag.var_simple.create(c.arena, .{ .name = tmp, .init = subscr_node });
    try block_scope.statements.append(subscr_decl);

    const tmp_ref = try Tag.identifier.create(c.arena, tmp);

    const container_node = try trans_expr(c, &block_scope.base, container_expr, .used);

    const cond_node = try Tag.greater_than_equal.create(c.arena, .{ .lhs = tmp_ref, .rhs = Tag.zero_literal.init() });

    const then_value = try Tag.add.create(c.arena, .{
        .lhs = container_node,
        .rhs = try Tag.as.create(c.arena, .{
            .lhs = try Tag.type.create(c.arena, "usize"),
            .rhs = try Tag.int_cast.create(c.arena, tmp_ref),
        }),
    });

    const then_body = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = then_value,
    });

    const minuend = container_node;
    const signed_size = try Tag.as.create(c.arena, .{
        .lhs = try Tag.type.create(c.arena, "isize"),
        .rhs = try Tag.int_cast.create(c.arena, tmp_ref),
    });
    const to_cast = try Tag.add_wrap.create(c.arena, .{
        .lhs = signed_size,
        .rhs = try Tag.negate.create(c.arena, Tag.one_literal.init()),
    });
    const bitcast_node = try Tag.as.create(c.arena, .{
        .lhs = try Tag.type.create(c.arena, "usize"),
        .rhs = try Tag.bit_cast.create(c.arena, to_cast),
    });
    const subtrahend = try Tag.bit_not.create(c.arena, bitcast_node);
    const difference = try Tag.sub.create(c.arena, .{
        .lhs = minuend,
        .rhs = subtrahend,
    });
    const else_body = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = difference,
    });

    const if_node = try Tag.@"if".create(c.arena, .{
        .cond = cond_node,
        .then = then_body,
        .@"else" = else_body,
    });

    try block_scope.statements.append(if_node);
    const block_node = try block_scope.complete(c);

    const derefed = try Tag.deref.create(c.arena, block_node);

    return maybe_suppress_result(c, result_used, derefed);
}

fn trans_array_access(c: *Context, scope: *Scope, stmt: *const clang.ArraySubscriptExpr, result_used: ResultUsed) TransError!Node {
    const base_stmt = stmt.get_base();
    const base_qt = get_expr_qual_type(c, base_stmt);
    const is_vector = c_is_vector(base_qt);

    const subscr_expr = stmt.getIdx();
    const subscr_qt = get_expr_qual_type(c, subscr_expr);
    const is_longlong = c_is_long_long_integer(subscr_qt);
    const is_signed = c_is_signed_integer(subscr_qt);
    const is_nonnegative_int_literal = c_is_non_negative_int_literal(c, subscr_expr);

    // Unwrap the base statement if it's an array decayed to a bare pointer type
    // so that we index the array itself
    var unwrapped_base = base_stmt;
    if (@as(*const clang.Stmt, @ptr_cast(base_stmt)).getStmtClass() == .ImplicitCastExprClass) {
        const implicit_cast = @as(*const clang.ImplicitCastExpr, @ptr_cast(base_stmt));

        if (implicit_cast.getCastKind() == .ArrayToPointerDecay) {
            unwrapped_base = implicit_cast.getSubExpr();
        }
    }

    // Special case: actual pointer (not decayed array) and signed integer subscript
    // See discussion at https://github.com/ziglang/zig/pull/8589
    if (is_signed and (base_stmt == unwrapped_base) and !is_vector and !is_nonnegative_int_literal)
        return trans_signed_array_access(c, scope, base_stmt, subscr_expr, result_used);

    const container_node = try trans_expr(c, scope, unwrapped_base, .used);
    const rhs = if (is_longlong or is_signed) blk: {
        // check if long long first so that signed long long doesn't just become unsigned long long
        const typeid_node = if (is_longlong) try Tag.type.create(c.arena, "usize") else try trans_qual_type_int_width_of(c, subscr_qt, false);
        break :blk try Tag.as.create(c.arena, .{
            .lhs = typeid_node,
            .rhs = try Tag.int_cast.create(
                c.arena,
                try trans_expr(c, scope, subscr_expr, .used),
            ),
        });
    } else try trans_expr(c, scope, subscr_expr, .used);

    const node = try Tag.array_access.create(c.arena, .{
        .lhs = container_node,
        .rhs = rhs,
    });
    return maybe_suppress_result(c, result_used, node);
}

/// Check if an expression is ultimately a reference to a function declaration
/// (which means it should not be unwrapped with `.?` in translated code)
fn c_is_function_decl_ref(expr: *const clang.Expr) bool {
    switch (expr.getStmtClass()) {
        .ParenExprClass => {
            const op_expr = @as(*const clang.ParenExpr, @ptr_cast(expr)).getSubExpr();
            return c_is_function_decl_ref(op_expr);
        },
        .DeclRefExprClass => {
            const decl_ref = @as(*const clang.DeclRefExpr, @ptr_cast(expr));
            const value_decl = decl_ref.get_decl();
            const qt = value_decl.get_type();
            return qual_type_child_is_fn_proto(qt);
        },
        .ImplicitCastExprClass => {
            const implicit_cast = @as(*const clang.ImplicitCastExpr, @ptr_cast(expr));
            const cast_kind = implicit_cast.getCastKind();
            if (cast_kind == .BuiltinFnToFnPtr) return true;
            if (cast_kind == .FunctionToPointerDecay) {
                return c_is_function_decl_ref(implicit_cast.getSubExpr());
            }
            return false;
        },
        .UnaryOperatorClass => {
            const un_op = @as(*const clang.UnaryOperator, @ptr_cast(expr));
            const opcode = un_op.getOpcode();
            return (opcode == .AddrOf or opcode == .Deref) and c_is_function_decl_ref(un_op.getSubExpr());
        },
        .GenericSelectionExprClass => {
            const gen_sel = @as(*const clang.GenericSelectionExpr, @ptr_cast(expr));
            return c_is_function_decl_ref(gen_sel.getResultExpr());
        },
        else => return false,
    }
}

fn trans_call_expr(c: *Context, scope: *Scope, stmt: *const clang.CallExpr, result_used: ResultUsed) TransError!Node {
    const callee = stmt.getCallee();
    const raw_fn_expr = try trans_expr(c, scope, callee, .used);

    var is_ptr = false;
    const fn_ty = qual_type_get_fn_proto(callee.get_type(), &is_ptr);

    const fn_expr = if (is_ptr and fn_ty != null and !c_is_function_decl_ref(callee))
        try Tag.unwrap.create(c.arena, raw_fn_expr)
    else
        raw_fn_expr;

    const num_args = stmt.getNumArgs();
    const args = try c.arena.alloc(Node, num_args);

    const c_args = stmt.getArgs();
    var i: usize = 0;
    while (i < num_args) : (i += 1) {
        var arg = try trans_expr(c, scope, c_args[i], .used);

        // In C the result type of a boolean expression is int. If this result is passed as
        // an argument to a function whose parameter is also int, there is no cast. Therefore
        // in Zig we'll need to cast it from bool to u1 (which will safely coerce to c_int).
        if (fn_ty) |ty| {
            switch (ty) {
                .Proto => |fn_proto| {
                    const param_count = fn_proto.getNumParams();
                    if (i < param_count) {
                        const param_qt = fn_proto.getParamType(@as(c_uint, @int_cast(i)));
                        if (is_bool_res(arg) and c_is_native_int(param_qt)) {
                            arg = try Tag.int_from_bool.create(c.arena, arg);
                        } else if (arg.tag() == .string_literal and qual_type_is_char_star(param_qt)) {
                            const loc = @as(*const clang.Stmt, @ptr_cast(stmt)).getBeginLoc();
                            const dst_type_node = try trans_qual_type(c, scope, param_qt, loc);
                            arg = try remove_cvqualifiers(c, dst_type_node, arg);
                        }
                    }
                },
                else => {},
            }
        }
        args[i] = arg;
    }
    const node = try Tag.call.create(c.arena, .{ .lhs = fn_expr, .args = args });
    if (fn_ty) |ty| {
        const canon = ty.get_return_type().getCanonicalType();
        const ret_ty = canon.getTypePtr();
        if (ret_ty.isVoidType()) {
            return node;
        }
    }

    return maybe_suppress_result(c, result_used, node);
}

const ClangFunctionType = union(enum) {
    Proto: *const clang.FunctionProtoType,
    NoProto: *const clang.FunctionType,

    fn get_return_type(self: @This()) clang.QualType {
        switch (@as(meta.Tag(@This()), self)) {
            .Proto => return self.Proto.get_return_type(),
            .NoProto => return self.NoProto.get_return_type(),
        }
    }
};

fn qual_type_get_fn_proto(qt: clang.QualType, is_ptr: *bool) ?ClangFunctionType {
    const canon = qt.getCanonicalType();
    var ty = canon.getTypePtr();
    is_ptr.* = false;

    if (ty.getTypeClass() == .Pointer) {
        is_ptr.* = true;
        const child_qt = ty.getPointeeType();
        ty = child_qt.getTypePtr();
    }
    if (ty.getTypeClass() == .FunctionProto) {
        return ClangFunctionType{ .Proto = @as(*const clang.FunctionProtoType, @ptr_cast(ty)) };
    }
    if (ty.getTypeClass() == .FunctionNoProto) {
        return ClangFunctionType{ .NoProto = @as(*const clang.FunctionType, @ptr_cast(ty)) };
    }
    return null;
}

fn trans_unary_expr_or_type_trait_expr(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.UnaryExprOrTypeTraitExpr,
    result_used: ResultUsed,
) TransError!Node {
    const loc = stmt.getBeginLoc();
    const type_node = try trans_qual_type(c, scope, stmt.getTypeOfArgument(), loc);

    const kind = stmt.get_kind();
    const node = switch (kind) {
        .SizeOf => try Tag.sizeof.create(c.arena, type_node),
        .AlignOf => try Tag.alignof.create(c.arena, type_node),
        .DataSizeOf,
        .PreferredAlignOf,
        .VecStep,
        .OpenMPRequiredSimdAlign,
        => return fail(
            c,
            error.UnsupportedTranslation,
            loc,
            "unsupported type trait kind {}",
            .{kind},
        ),
    };
    return maybe_suppress_result(c, result_used, node);
}

fn qual_type_has_wrapping_overflow(qt: clang.QualType) bool {
    if (c_is_unsigned_integer(qt)) {
        // unsigned integer overflow wraps around.
        return true;
    } else {
        // float, signed integer, and pointer overflow is undefined behavior.
        return false;
    }
}

fn trans_unary_operator(c: *Context, scope: *Scope, stmt: *const clang.UnaryOperator, used: ResultUsed) TransError!Node {
    const op_expr = stmt.getSubExpr();
    switch (stmt.getOpcode()) {
        .PostInc => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_post_crement(c, scope, stmt, .add_wrap_assign, used)
        else
            return trans_create_post_crement(c, scope, stmt, .add_assign, used),
        .PostDec => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_post_crement(c, scope, stmt, .sub_wrap_assign, used)
        else
            return trans_create_post_crement(c, scope, stmt, .sub_assign, used),
        .PreInc => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_pre_crement(c, scope, stmt, .add_wrap_assign, used)
        else
            return trans_create_pre_crement(c, scope, stmt, .add_assign, used),
        .PreDec => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_pre_crement(c, scope, stmt, .sub_wrap_assign, used)
        else
            return trans_create_pre_crement(c, scope, stmt, .sub_assign, used),
        .AddrOf => {
            return Tag.address_of.create(c.arena, try trans_expr(c, scope, op_expr, used));
        },
        .Deref => {
            if (qual_type_was_demoted_to_opaque(c, stmt.get_type()))
                return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "cannot dereference opaque type", .{});

            const node = try trans_expr(c, scope, op_expr, used);
            var is_ptr = false;
            const fn_ty = qual_type_get_fn_proto(op_expr.get_type(), &is_ptr);
            if (fn_ty != null and is_ptr)
                return node;
            return Tag.deref.create(c.arena, node);
        },
        .Plus => return trans_expr(c, scope, op_expr, used),
        .Minus => {
            if (!qual_type_has_wrapping_overflow(op_expr.get_type())) {
                const sub_expr_node = try trans_expr(c, scope, op_expr, .used);
                const to_negate = if (is_bool_res(sub_expr_node)) blk: {
                    const ty_node = try Tag.type.create(c.arena, "c_int");
                    const int_node = try Tag.int_from_bool.create(c.arena, sub_expr_node);
                    break :blk try Tag.as.create(c.arena, .{ .lhs = ty_node, .rhs = int_node });
                } else sub_expr_node;
                return Tag.negate.create(c.arena, to_negate);
            } else if (c_is_unsigned_integer(op_expr.get_type())) {
                // use -% x for unsigned integers
                return Tag.negate_wrap.create(c.arena, try trans_expr(c, scope, op_expr, .used));
            } else return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "C negation with non float non integer", .{});
        },
        .Not => {
            return Tag.bit_not.create(c.arena, try trans_expr(c, scope, op_expr, .used));
        },
        .LNot => {
            return Tag.not.create(c.arena, try trans_bool_expr(c, scope, op_expr, .used));
        },
        .Extension => {
            return trans_expr(c, scope, stmt.getSubExpr(), used);
        },
        else => return fail(c, error.UnsupportedTranslation, stmt.getBeginLoc(), "unsupported C translation {}", .{stmt.getOpcode()}),
    }
}

fn trans_create_pre_crement(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.UnaryOperator,
    op: Tag,
    used: ResultUsed,
) TransError!Node {
    const op_expr = stmt.getSubExpr();

    if (used == .unused) {
        // common case
        // c: ++expr
        // zig: expr += 1
        const lhs = try trans_expr(c, scope, op_expr, .used);
        const rhs = Tag.one_literal.init();
        return trans_create_node_infix_op(c, op, lhs, rhs, .used);
    }
    // worst case
    // c: ++expr
    // zig: (blk: {
    // zig:     const _ref = &expr;
    // zig:     _ref.* += 1;
    // zig:     break :blk _ref.*
    // zig: })
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const ref = try block_scope.reserve_mangled_name(c, "ref");
    const expr = try trans_expr(c, &block_scope.base, op_expr, .used);
    const addr_of = try Tag.address_of.create(c.arena, expr);
    const ref_decl = try Tag.var_simple.create(c.arena, .{ .name = ref, .init = addr_of });
    try block_scope.statements.append(ref_decl);

    const lhs_node = try Tag.identifier.create(c.arena, ref);
    const ref_node = try Tag.deref.create(c.arena, lhs_node);
    const node = try trans_create_node_infix_op(c, op, ref_node, Tag.one_literal.init(), .used);
    try block_scope.statements.append(node);

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = ref_node,
    });
    try block_scope.statements.append(break_node);
    return block_scope.complete(c);
}

fn trans_create_post_crement(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.UnaryOperator,
    op: Tag,
    used: ResultUsed,
) TransError!Node {
    const op_expr = stmt.getSubExpr();

    if (used == .unused) {
        // common case
        // c: expr++
        // zig: expr += 1
        const lhs = try trans_expr(c, scope, op_expr, .used);
        const rhs = Tag.one_literal.init();
        return trans_create_node_infix_op(c, op, lhs, rhs, .used);
    }
    // worst case
    // c: expr++
    // zig: (blk: {
    // zig:     const _ref = &expr;
    // zig:     const _tmp = _ref.*;
    // zig:     _ref.* += 1;
    // zig:     break :blk _tmp
    // zig: })
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();
    const ref = try block_scope.reserve_mangled_name(c, "ref");
    const tmp = try block_scope.reserve_mangled_name(c, "tmp");

    const expr = try trans_expr(c, &block_scope.base, op_expr, .used);
    const addr_of = try Tag.address_of.create(c.arena, expr);
    const ref_decl = try Tag.var_simple.create(c.arena, .{ .name = ref, .init = addr_of });
    try block_scope.statements.append(ref_decl);

    const lhs_node = try Tag.identifier.create(c.arena, ref);
    const ref_node = try Tag.deref.create(c.arena, lhs_node);

    const tmp_decl = try Tag.var_simple.create(c.arena, .{ .name = tmp, .init = ref_node });
    try block_scope.statements.append(tmp_decl);

    const node = try trans_create_node_infix_op(c, op, ref_node, Tag.one_literal.init(), .used);
    try block_scope.statements.append(node);

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = try Tag.identifier.create(c.arena, tmp),
    });
    try block_scope.statements.append(break_node);
    return block_scope.complete(c);
}

fn trans_compound_assign_operator(c: *Context, scope: *Scope, stmt: *const clang.CompoundAssignOperator, used: ResultUsed) TransError!Node {
    switch (stmt.getOpcode()) {
        .MulAssign => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_compound_assign(c, scope, stmt, .mul_wrap_assign, used)
        else
            return trans_create_compound_assign(c, scope, stmt, .mul_assign, used),
        .AddAssign => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_compound_assign(c, scope, stmt, .add_wrap_assign, used)
        else
            return trans_create_compound_assign(c, scope, stmt, .add_assign, used),
        .SubAssign => if (qual_type_has_wrapping_overflow(stmt.get_type()))
            return trans_create_compound_assign(c, scope, stmt, .sub_wrap_assign, used)
        else
            return trans_create_compound_assign(c, scope, stmt, .sub_assign, used),
        .DivAssign => return trans_create_compound_assign(c, scope, stmt, .div_assign, used),
        .RemAssign => return trans_create_compound_assign(c, scope, stmt, .mod_assign, used),
        .ShlAssign => return trans_create_compound_assign(c, scope, stmt, .shl_assign, used),
        .ShrAssign => return trans_create_compound_assign(c, scope, stmt, .shr_assign, used),
        .AndAssign => return trans_create_compound_assign(c, scope, stmt, .bit_and_assign, used),
        .XorAssign => return trans_create_compound_assign(c, scope, stmt, .bit_xor_assign, used),
        .OrAssign => return trans_create_compound_assign(c, scope, stmt, .bit_or_assign, used),
        else => return fail(
            c,
            error.UnsupportedTranslation,
            stmt.getBeginLoc(),
            "unsupported C translation {}",
            .{stmt.getOpcode()},
        ),
    }
}

fn trans_create_compound_assign(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.CompoundAssignOperator,
    op: Tag,
    used: ResultUsed,
) TransError!Node {
    const is_shift = op == .shl_assign or op == .shr_assign;
    const is_div = op == .div_assign;
    const is_mod = op == .mod_assign;
    const lhs = stmt.getLHS();
    const rhs = stmt.getRHS();
    const loc = stmt.getBeginLoc();
    const lhs_qt = get_expr_qual_type(c, lhs);
    const rhs_qt = get_expr_qual_type(c, rhs);
    const is_signed = c_is_signed_integer(lhs_qt);
    const is_ptr_op_signed = qual_type_is_ptr(lhs_qt) and c_is_signed_integer(rhs_qt);
    const requires_cast = !lhs_qt.eq(rhs_qt) and !is_ptr_op_signed;

    if (used == .unused) {
        // common case
        // c: lhs += rhs
        // zig: lhs += rhs
        const lhs_node = try trans_expr(c, scope, lhs, .used);
        var rhs_node = try trans_expr(c, scope, rhs, .used);
        if (is_ptr_op_signed) rhs_node = try usize_cast_for_wrapping_ptr_arithmetic(c.arena, rhs_node);

        if ((is_mod or is_div) and is_signed) {
            if (requires_cast) rhs_node = try trans_ccast(c, scope, loc, lhs_qt, rhs_qt, rhs_node);
            const operands = .{ .lhs = lhs_node, .rhs = rhs_node };
            const builtin = if (is_mod)
                try Tag.signed_remainder.create(c.arena, operands)
            else
                try Tag.div_trunc.create(c.arena, operands);

            return trans_create_node_infix_op(c, .assign, lhs_node, builtin, .used);
        }

        if (is_shift) {
            rhs_node = try Tag.int_cast.create(c.arena, rhs_node);
        } else if (requires_cast) {
            rhs_node = try trans_ccast(c, scope, loc, lhs_qt, rhs_qt, rhs_node);
        }
        return trans_create_node_infix_op(c, op, lhs_node, rhs_node, .used);
    }
    // worst case
    // c:   lhs += rhs
    // zig: (blk: {
    // zig:     const _ref = &lhs;
    // zig:     _ref.* += rhs;
    // zig:     break :blk _ref.*
    // zig: })
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();
    const ref = try block_scope.reserve_mangled_name(c, "ref");

    const expr = try trans_expr(c, &block_scope.base, lhs, .used);
    const addr_of = try Tag.address_of.create(c.arena, expr);
    const ref_decl = try Tag.var_simple.create(c.arena, .{ .name = ref, .init = addr_of });
    try block_scope.statements.append(ref_decl);

    const lhs_node = try Tag.identifier.create(c.arena, ref);
    const ref_node = try Tag.deref.create(c.arena, lhs_node);

    var rhs_node = try trans_expr(c, &block_scope.base, rhs, .used);
    if (is_ptr_op_signed) rhs_node = try usize_cast_for_wrapping_ptr_arithmetic(c.arena, rhs_node);
    if ((is_mod or is_div) and is_signed) {
        if (requires_cast) rhs_node = try trans_ccast(c, scope, loc, lhs_qt, rhs_qt, rhs_node);
        const operands = .{ .lhs = ref_node, .rhs = rhs_node };
        const builtin = if (is_mod)
            try Tag.signed_remainder.create(c.arena, operands)
        else
            try Tag.div_trunc.create(c.arena, operands);

        const assign = try trans_create_node_infix_op(c, .assign, ref_node, builtin, .used);
        try block_scope.statements.append(assign);
    } else {
        if (is_shift) {
            rhs_node = try Tag.int_cast.create(c.arena, rhs_node);
        } else if (requires_cast) {
            rhs_node = try trans_ccast(c, &block_scope.base, loc, lhs_qt, rhs_qt, rhs_node);
        }

        const assign = try trans_create_node_infix_op(c, op, ref_node, rhs_node, .used);
        try block_scope.statements.append(assign);
    }

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = ref_node,
    });
    try block_scope.statements.append(break_node);
    return block_scope.complete(c);
}

fn remove_cvqualifiers(c: *Context, dst_type_node: Node, expr: Node) Error!Node {
    const const_casted = try Tag.const_cast.create(c.arena, expr);
    const volatile_casted = try Tag.volatile_cast.create(c.arena, const_casted);
    return Tag.as.create(c.arena, .{
        .lhs = dst_type_node,
        .rhs = try Tag.ptr_cast.create(c.arena, volatile_casted),
    });
}

fn trans_cptr_cast(
    c: *Context,
    scope: *Scope,
    loc: clang.SourceLocation,
    dst_type: clang.QualType,
    src_type: clang.QualType,
    expr: Node,
) !Node {
    const ty = dst_type.getTypePtr();
    const child_type = ty.getPointeeType();
    const src_ty = src_type.getTypePtr();
    const src_child_type = src_ty.getPointeeType();
    const dst_type_node = try trans_type(c, scope, ty, loc);

    if (!src_ty.isArrayType() and ((src_child_type.isConstQualified() and
        !child_type.isConstQualified()) or
        (src_child_type.isVolatileQualified() and
        !child_type.isVolatileQualified())))
    {
        return remove_cvqualifiers(c, dst_type_node, expr);
    } else {
        // Implicit downcasting from higher to lower alignment values is forbidden,
        // use @align_cast to side-step this problem
        const rhs = if (qual_type_canon(child_type).isVoidType())
            // void has 1-byte alignment, so @align_cast is not needed
            expr
        else if (type_is_opaque(c, qual_type_canon(child_type), loc))
            // For opaque types a ptr_cast is enough
            expr
        else blk: {
            break :blk try Tag.align_cast.create(c.arena, expr);
        };
        return Tag.as.create(c.arena, .{
            .lhs = dst_type_node,
            .rhs = try Tag.ptr_cast.create(c.arena, rhs),
        });
    }
}

fn trans_floating_literal(c: *Context, expr: *const clang.FloatingLiteral, used: ResultUsed) TransError!Node {
    // TODO use something more accurate than widening to a larger float type and printing that result
    switch (expr.getRawSemantics()) {
        .IEEEhalf, // f16
        .IEEEsingle, // f32
        .IEEEdouble, // f64
        => {
            var dbl = expr.getValueAsApproximateDouble();
            const is_negative = dbl < 0; // -0.0 is considered non-negative
            if (is_negative) dbl = -dbl;
            const str = if (dbl == @floor(dbl))
                try std.fmt.alloc_print(c.arena, "{d}.0", .{dbl})
            else
                try std.fmt.alloc_print(c.arena, "{d}", .{dbl});
            var node = try Tag.float_literal.create(c.arena, str);
            if (is_negative) node = try Tag.negate.create(c.arena, node);
            return maybe_suppress_result(c, used, node);
        },
        .x87DoubleExtended, // f80
        .IEEEquad, // f128
        => return trans_floating_literal_quad(c, expr, used),
        else => |format| return fail(
            c,
            error.UnsupportedTranslation,
            expr.getBeginLoc(),
            "unsupported floating point constant format {}",
            .{format},
        ),
    }
}

fn trans_floating_literal_quad(c: *Context, expr: *const clang.FloatingLiteral, used: ResultUsed) TransError!Node {
    assert(switch (expr.getRawSemantics()) {
        .x87DoubleExtended, .IEEEquad => true,
        else => false,
    });

    var low: u64 = undefined;
    var high: u64 = undefined;
    expr.getValueAsApproximateQuadBits(&low, &high);
    var quad: f128 = @bit_cast(low | @as(u128, high) << 64);
    const is_negative = quad < 0; // -0.0 is considered non-negative
    if (is_negative) quad = -quad;

    // TODO implement decimal format for f128 <https://github.com/ziglang/zig/issues/1181>
    // in the meantime, if the value can be roundtripped by casting it to f64, serializing it to
    // the decimal format and parsing it back as the exact same f128 value, then use that serialized form
    const str = fmt_decimal: {
        var buf: [512]u8 = undefined; // should be large enough to print any f64 in decimal form
        const dbl: f64 = @float_cast(quad);
        const temp_str = if (dbl == @floor(dbl))
            std.fmt.buf_print(&buf, "{d}.0", .{dbl}) catch |err| switch (err) {
                error.NoSpaceLeft => unreachable,
            }
        else
            std.fmt.buf_print(&buf, "{d}", .{dbl}) catch |err| switch (err) {
                error.NoSpaceLeft => unreachable,
            };
        const could_roundtrip = if (std.fmt.parse_float(f128, temp_str)) |parsed_quad|
            quad == parsed_quad
        else |_|
            false;
        break :fmt_decimal if (could_roundtrip) try c.arena.dupe(u8, temp_str) else null;
    }
    // otherwise, fall back to the hexadecimal format
    orelse try std.fmt.alloc_print(c.arena, "{x}", .{quad});

    var node = try Tag.float_literal.create(c.arena, str);
    if (is_negative) node = try Tag.negate.create(c.arena, node);
    return maybe_suppress_result(c, used, node);
}

fn trans_binary_conditional_operator(c: *Context, scope: *Scope, stmt: *const clang.BinaryConditionalOperator, used: ResultUsed) TransError!Node {
    // GNU extension of the ternary operator where the middle expression is
    // omitted, the condition itself is returned if it evaluates to true
    const qt = @as(*const clang.Expr, @ptr_cast(stmt)).get_type();
    const res_is_bool = qual_type_is_boolean(qt);
    const casted_stmt = @as(*const clang.AbstractConditionalOperator, @ptr_cast(stmt));
    const cond_expr = casted_stmt.getCond();
    const false_expr = casted_stmt.getFalseExpr();

    // c:   (cond_expr)?:(false_expr)
    // zig: (blk: {
    //          const _cond_temp = (cond_expr);
    //          break :blk if (_cond_temp) _cond_temp else (false_expr);
    //      })
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const cond_temp = try block_scope.reserve_mangled_name(c, "cond_temp");
    const init_node = try trans_expr(c, &block_scope.base, cond_expr, .used);
    const ref_decl = try Tag.var_simple.create(c.arena, .{ .name = cond_temp, .init = init_node });
    try block_scope.statements.append(ref_decl);

    var cond_scope = Scope.Condition{
        .base = .{
            .parent = &block_scope.base,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();

    const cond_ident = try Tag.identifier.create(c.arena, cond_temp);
    const ty = get_expr_qual_type(c, cond_expr).getTypePtr();
    const cond_node = try finish_bool_expr(c, &cond_scope.base, cond_expr.getBeginLoc(), ty, cond_ident, .used);
    var then_body = cond_ident;
    if (!res_is_bool and is_bool_res(init_node)) {
        then_body = try Tag.int_from_bool.create(c.arena, then_body);
    }

    var else_body = try trans_expr(c, &block_scope.base, false_expr, .used);
    if (!res_is_bool and is_bool_res(else_body)) {
        else_body = try Tag.int_from_bool.create(c.arena, else_body);
    }
    const if_node = try Tag.@"if".create(c.arena, .{
        .cond = cond_node,
        .then = then_body,
        .@"else" = else_body,
    });
    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = if_node,
    });
    try block_scope.statements.append(break_node);
    const res = try block_scope.complete(c);
    return maybe_suppress_result(c, used, res);
}

fn trans_conditional_operator(c: *Context, scope: *Scope, stmt: *const clang.ConditionalOperator, used: ResultUsed) TransError!Node {
    var cond_scope = Scope.Condition{
        .base = .{
            .parent = scope,
            .id = .condition,
        },
    };
    defer cond_scope.deinit();

    const qt = @as(*const clang.Expr, @ptr_cast(stmt)).get_type();
    const res_is_bool = qual_type_is_boolean(qt);
    const casted_stmt = @as(*const clang.AbstractConditionalOperator, @ptr_cast(stmt));
    const cond_expr = casted_stmt.getCond();
    const true_expr = casted_stmt.getTrueExpr();
    const false_expr = casted_stmt.getFalseExpr();

    const cond = try trans_bool_expr(c, &cond_scope.base, cond_expr, .used);

    var then_body = try trans_expr(c, scope, true_expr, used);
    if (!res_is_bool and is_bool_res(then_body)) {
        then_body = try Tag.int_from_bool.create(c.arena, then_body);
    }

    var else_body = try trans_expr(c, scope, false_expr, used);
    if (!res_is_bool and is_bool_res(else_body)) {
        else_body = try Tag.int_from_bool.create(c.arena, else_body);
    }

    const if_node = try Tag.@"if".create(c.arena, .{
        .cond = cond,
        .then = then_body,
        .@"else" = else_body,
    });
    // Clang inserts ImplicitCast(ToVoid)'s to both rhs and lhs so we don't need to suppress the result here.
    return if_node;
}

fn maybe_suppress_result(c: *Context, used: ResultUsed, result: Node) TransError!Node {
    if (used == .used) return result;
    return Tag.discard.create(c.arena, .{ .should_skip = false, .value = result });
}

fn add_top_level_decl(c: *Context, name: []const u8, decl_node: Node) !void {
    const gop = try c.global_scope.sym_table.get_or_put(name);
    if (!gop.found_existing) {
        gop.value_ptr.* = decl_node;
        try c.global_scope.nodes.append(decl_node);
    }
}

fn trans_qual_type_initialized_string_literal(c: *Context, elem_ty: Node, string_lit: *const clang.StringLiteral) TypeError!Node {
    const string_lit_size = string_lit.get_length();
    const array_size = @as(usize, @int_cast(string_lit_size));

    // incomplete array initialized with empty string, will be translated as [1]T{0}
    // see https://github.com/ziglang/zig/issues/8256
    if (array_size == 0) return Tag.array_type.create(c.arena, .{ .len = 1, .elem_type = elem_ty });

    return Tag.null_sentinel_array_type.create(c.arena, .{ .len = array_size, .elem_type = elem_ty });
}

/// Translate a qualtype for a variable with an initializer. This only matters
/// for incomplete arrays, since the initializer determines the size of the array.
fn trans_qual_type_initialized(
    c: *Context,
    scope: *Scope,
    qt: clang.QualType,
    decl_init: *const clang.Expr,
    source_loc: clang.SourceLocation,
) TypeError!Node {
    const ty = qt.getTypePtr();
    if (ty.getTypeClass() == .IncompleteArray) {
        const incomplete_array_ty = @as(*const clang.IncompleteArrayType, @ptr_cast(ty));
        const elem_ty = try trans_type(c, scope, incomplete_array_ty.getElementType().getTypePtr(), source_loc);

        switch (decl_init.getStmtClass()) {
            .StringLiteralClass => {
                const string_lit = @as(*const clang.StringLiteral, @ptr_cast(decl_init));
                return trans_qual_type_initialized_string_literal(c, elem_ty, string_lit);
            },
            .InitListExprClass => {
                const init_expr = @as(*const clang.InitListExpr, @ptr_cast(decl_init));
                const size = init_expr.getNumInits();

                if (init_expr.isStringLiteralInit()) {
                    assert(size == 1);
                    const string_lit = init_expr.getInit(0).castToStringLiteral().?;
                    return trans_qual_type_initialized_string_literal(c, elem_ty, string_lit);
                }

                return Tag.array_type.create(c.arena, .{ .len = size, .elem_type = elem_ty });
            },
            else => {},
        }
    }
    return trans_qual_type(c, scope, qt, source_loc);
}

fn trans_qual_type(c: *Context, scope: *Scope, qt: clang.QualType, source_loc: clang.SourceLocation) TypeError!Node {
    return trans_type(c, scope, qt.getTypePtr(), source_loc);
}

/// Produces a Zig AST node by translating a Clang QualType, respecting the width, but modifying the signed-ness.
/// Asserts the type is an integer.
fn trans_qual_type_int_width_of(c: *Context, ty: clang.QualType, is_signed: bool) TypeError!Node {
    return trans_type_int_width_of(c, qual_type_canon(ty), is_signed);
}

/// Produces a Zig AST node by translating a Clang Type, respecting the width, but modifying the signed-ness.
/// Asserts the type is an integer.
fn trans_type_int_width_of(c: *Context, ty: *const clang.Type, is_signed: bool) TypeError!Node {
    assert(ty.getTypeClass() == .Builtin);
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));
    return Tag.type.create(c.arena, switch (builtin_ty.get_kind()) {
        .Char_U, .Char_S, .UChar, .SChar, .Char8 => if (is_signed) "i8" else "u8",
        .UShort, .Short => if (is_signed) "c_short" else "c_ushort",
        .UInt, .Int => if (is_signed) "c_int" else "c_uint",
        .ULong, .Long => if (is_signed) "c_long" else "c_ulong",
        .ULongLong, .LongLong => if (is_signed) "c_longlong" else "c_ulonglong",
        .UInt128, .Int128 => if (is_signed) "i128" else "u128",
        .Char16 => if (is_signed) "i16" else "u16",
        .Char32 => if (is_signed) "i32" else "u32",
        else => unreachable, // only call this function when it has already been determined the type is int
    });
}

fn is_cbuiltin_type(qt: clang.QualType, kind: clang.BuiltinTypeKind) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin)
        return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return builtin_ty.get_kind() == kind;
}

fn qual_type_is_ptr(qt: clang.QualType) bool {
    return qual_type_canon(qt).getTypeClass() == .Pointer;
}

fn qual_type_is_boolean(qt: clang.QualType) bool {
    return qual_type_canon(qt).isBooleanType();
}

fn qual_type_int_bit_width(c: *Context, qt: clang.QualType) !u32 {
    const ty = qt.getTypePtr();

    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));

            switch (builtin_ty.get_kind()) {
                .Char_U,
                .UChar,
                .Char_S,
                .SChar,
                => return 8,
                .UInt128,
                .Int128,
                => return 128,
                else => return 0,
            }

            unreachable;
        },
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));
            const typedef_decl = typedef_ty.get_decl();
            const type_name = try c.str(@as(*const clang.NamedDecl, @ptr_cast(typedef_decl)).getName_bytes_begin());

            if (mem.eql(u8, type_name, "uint8_t") or mem.eql(u8, type_name, "int8_t")) {
                return 8;
            } else if (mem.eql(u8, type_name, "uint16_t") or mem.eql(u8, type_name, "int16_t")) {
                return 16;
            } else if (mem.eql(u8, type_name, "uint32_t") or mem.eql(u8, type_name, "int32_t")) {
                return 32;
            } else if (mem.eql(u8, type_name, "uint64_t") or mem.eql(u8, type_name, "int64_t")) {
                return 64;
            } else {
                return 0;
            }
        },
        else => return 0,
    }
}

fn qual_type_child_is_fn_proto(qt: clang.QualType) bool {
    const ty = qual_type_canon(qt);

    switch (ty.getTypeClass()) {
        .FunctionProto, .FunctionNoProto => return true,
        else => return false,
    }
}

fn qual_type_canon(qt: clang.QualType) *const clang.Type {
    const canon = qt.getCanonicalType();
    return canon.getTypePtr();
}

fn get_expr_qual_type(c: *Context, expr: *const clang.Expr) clang.QualType {
    blk: {
        // If this is a C `char *`, turn it into a `const char *`
        if (expr.getStmtClass() != .ImplicitCastExprClass) break :blk;
        const cast_expr = @as(*const clang.ImplicitCastExpr, @ptr_cast(expr));
        if (cast_expr.getCastKind() != .ArrayToPointerDecay) break :blk;
        const sub_expr = cast_expr.getSubExpr();
        if (sub_expr.getStmtClass() != .StringLiteralClass) break :blk;
        const array_qt = sub_expr.get_type();
        const array_type = @as(*const clang.ArrayType, @ptr_cast(array_qt.getTypePtr()));
        var pointee_qt = array_type.getElementType();
        pointee_qt.addConst();
        return c.clang_context.getPointerType(pointee_qt);
    }
    return expr.get_type();
}

fn type_is_opaque(c: *Context, ty: *const clang.Type, loc: clang.SourceLocation) bool {
    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));
            return builtin_ty.get_kind() == .Void;
        },
        .Record => {
            const record_ty = @as(*const clang.RecordType, @ptr_cast(ty));
            const record_decl = record_ty.get_decl();
            const record_def = record_decl.getDefinition() orelse
                return true;
            var it = record_def.field_begin();
            const end_it = record_def.field_end();
            while (it.neq(end_it)) : (it = it.next()) {
                const field_decl = it.deref();

                if (field_decl.isBitField()) {
                    return true;
                }
            }
            return false;
        },
        .Elaborated => {
            const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(ty));
            const qt = elaborated_ty.getNamedType();
            return type_is_opaque(c, qt.getTypePtr(), loc);
        },
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));
            const typedef_decl = typedef_ty.get_decl();
            const underlying_type = typedef_decl.getUnderlyingType();
            return type_is_opaque(c, underlying_type.getTypePtr(), loc);
        },
        else => return false,
    }
}

/// plain `char *` (not const; not explicitly signed or unsigned)
fn qual_type_is_char_star(qt: clang.QualType) bool {
    if (qual_type_is_ptr(qt)) {
        const child_qt = qual_type_canon(qt).getPointeeType();
        return c_is_unqualified_char(child_qt) and !child_qt.isConstQualified();
    }
    return false;
}

/// C `char` without explicit signed or unsigned qualifier
fn c_is_unqualified_char(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .Char_S, .Char_U => true,
        else => false,
    };
}

fn c_is_integer(qt: clang.QualType) bool {
    return c_is_signed_integer(qt) or c_is_unsigned_integer(qt);
}

fn c_is_unsigned_integer(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .Char_U,
        .UChar,
        .Char_S,
        .UShort,
        .UInt,
        .ULong,
        .ULongLong,
        .UInt128,
        .WChar_U,
        => true,
        else => false,
    };
}

fn c_int_type_to_index(qt: clang.QualType) u8 {
    const c_type = qual_type_canon(qt);
    assert(c_type.getTypeClass() == .Builtin);
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .Bool, .Char_U, .Char_S, .UChar, .SChar, .Char8 => 1,
        .WChar_U, .WChar_S => 2,
        .UShort, .Short, .Char16 => 3,
        .UInt, .Int, .Char32 => 4,
        .ULong, .Long => 5,
        .ULongLong, .LongLong => 6,
        .UInt128, .Int128 => 7,
        else => unreachable,
    };
}

fn c_int_type_cmp(a: clang.QualType, b: clang.QualType) math.Order {
    const a_index = c_int_type_to_index(a);
    const b_index = c_int_type_to_index(b);
    return math.order(a_index, b_index);
}

/// Checks if expr is an integer literal >= 0
fn c_is_non_negative_int_literal(c: *Context, expr: *const clang.Expr) bool {
    if (@as(*const clang.Stmt, @ptr_cast(expr)).getStmtClass() == .IntegerLiteralClass) {
        var signum: c_int = undefined;
        if (!(@as(*const clang.IntegerLiteral, @ptr_cast(expr)).getSignum(&signum, c.clang_context))) {
            return false;
        }
        return signum >= 0;
    }
    return false;
}

fn c_is_signed_integer(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .SChar,
        .Short,
        .Int,
        .Long,
        .LongLong,
        .Int128,
        .WChar_S,
        => true,
        else => false,
    };
}

fn c_is_native_int(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return builtin_ty.get_kind() == .Int;
}

fn c_is_floating(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .Float,
        .Double,
        .Float128,
        .LongDouble,
        => true,
        else => false,
    };
}

fn c_is_long_long_integer(qt: clang.QualType) bool {
    const c_type = qual_type_canon(qt);
    if (c_type.getTypeClass() != .Builtin) return false;
    const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(c_type));
    return switch (builtin_ty.get_kind()) {
        .LongLong, .ULongLong, .Int128, .UInt128 => true,
        else => false,
    };
}
fn trans_create_node_assign(
    c: *Context,
    scope: *Scope,
    result_used: ResultUsed,
    lhs: *const clang.Expr,
    rhs: *const clang.Expr,
) !Node {
    // common case
    // c:   lhs = rhs
    // zig: lhs = rhs
    if (result_used == .unused) {
        const lhs_node = try trans_expr(c, scope, lhs, .used);
        var rhs_node = try trans_expr_coercing(c, scope, rhs, .used);
        if (!expr_is_boolean_type(lhs) and is_bool_res(rhs_node)) {
            rhs_node = try Tag.int_from_bool.create(c.arena, rhs_node);
        }
        return trans_create_node_infix_op(c, .assign, lhs_node, rhs_node, .used);
    }

    // worst case
    // c:   lhs = rhs
    // zig: (blk: {
    // zig:     const _tmp = rhs;
    // zig:     lhs = _tmp;
    // zig:     break :blk _tmp
    // zig: })
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const tmp = try block_scope.reserve_mangled_name(c, "tmp");
    var rhs_node = try trans_expr(c, &block_scope.base, rhs, .used);
    if (!expr_is_boolean_type(lhs) and is_bool_res(rhs_node)) {
        rhs_node = try Tag.int_from_bool.create(c.arena, rhs_node);
    }

    const tmp_decl = try Tag.var_simple.create(c.arena, .{ .name = tmp, .init = rhs_node });
    try block_scope.statements.append(tmp_decl);

    const lhs_node = try trans_expr(c, &block_scope.base, lhs, .used);
    const tmp_ident = try Tag.identifier.create(c.arena, tmp);
    const assign = try trans_create_node_infix_op(c, .assign, lhs_node, tmp_ident, .used);
    try block_scope.statements.append(assign);

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = tmp_ident,
    });
    try block_scope.statements.append(break_node);
    return block_scope.complete(c);
}

fn trans_create_node_infix_op(
    c: *Context,
    op: Tag,
    lhs: Node,
    rhs: Node,
    used: ResultUsed,
) !Node {
    const payload = try c.arena.create(ast.Payload.BinOp);
    payload.* = .{
        .base = .{ .tag = op },
        .data = .{
            .lhs = lhs,
            .rhs = rhs,
        },
    };
    return maybe_suppress_result(c, used, Node.init_payload(&payload.base));
}

fn trans_create_node_bool_infix_op(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.BinaryOperator,
    op: Tag,
    used: ResultUsed,
) !Node {
    std.debug.assert(op == .@"and" or op == .@"or");

    const lhs = try trans_bool_expr(c, scope, stmt.getLHS(), .used);
    const rhs = try trans_bool_expr(c, scope, stmt.getRHS(), .used);

    return trans_create_node_infix_op(c, op, lhs, rhs, used);
}

fn trans_create_node_apint(c: *Context, int: *const clang.APSInt) !Node {
    const num_limbs = math.cast(usize, int.getNumWords()) orelse return error.OutOfMemory;
    var aps_int = int;
    const is_negative = int.is_signed() and int.is_negative();
    if (is_negative) aps_int = aps_int.negate();
    defer if (is_negative) {
        aps_int.free();
    };

    const limbs = try c.arena.alloc(math.big.Limb, num_limbs);
    defer c.arena.free(limbs);

    const data = aps_int.getRawData();
    switch (@size_of(math.big.Limb)) {
        8 => {
            var i: usize = 0;
            while (i < num_limbs) : (i += 1) {
                limbs[i] = data[i];
            }
        },
        4 => {
            var limb_i: usize = 0;
            var data_i: usize = 0;
            while (limb_i < num_limbs) : ({
                limb_i += 2;
                data_i += 1;
            }) {
                limbs[limb_i] = @as(u32, @truncate(data[data_i]));
                limbs[limb_i + 1] = @as(u32, @truncate(data[data_i] >> 32));
            }
        },
        else => @compile_error("unimplemented"),
    }

    const big: math.big.int.Const = .{ .limbs = limbs, .positive = true };
    const str = big.to_string_alloc(c.arena, 10, .lower) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    const res = try Tag.integer_literal.create(c.arena, str);
    if (is_negative) return Tag.negate.create(c.arena, res);
    return res;
}

fn trans_create_node_number(c: *Context, num: anytype, num_kind: enum { int, float }) !Node {
    const fmt_s = switch (@typeInfo(@TypeOf(num))) {
        .Int, .ComptimeInt => "{d}",
        else => "{s}",
    };
    const str = try std.fmt.alloc_print(c.arena, fmt_s, .{num});
    if (num_kind == .float)
        return Tag.float_literal.create(c.arena, str)
    else
        return Tag.integer_literal.create(c.arena, str);
}

fn trans_create_node_macro_fn(c: *Context, name: []const u8, ref: Node, proto_alias: *ast.Payload.Func) !Node {
    var fn_params = std.ArrayList(ast.Payload.Param).init(c.gpa);
    defer fn_params.deinit();

    for (proto_alias.data.params) |param| {
        const param_name = param.name orelse
            try std.fmt.alloc_print(c.arena, "arg_{d}", .{c.get_mangle()});

        try fn_params.append(.{
            .name = param_name,
            .type = param.type,
            .is_noalias = param.is_noalias,
        });
    }

    const init = if (ref.cast_tag(.var_decl)) |v|
        v.data.init.?
    else if (ref.cast_tag(.var_simple) orelse ref.cast_tag(.pub_var_simple)) |v|
        v.data.init
    else
        unreachable;

    const unwrap_expr = try Tag.unwrap.create(c.arena, init);
    const args = try c.arena.alloc(Node, fn_params.items.len);
    for (fn_params.items, 0..) |param, i| {
        args[i] = try Tag.identifier.create(c.arena, param.name.?);
    }
    const call_expr = try Tag.call.create(c.arena, .{
        .lhs = unwrap_expr,
        .args = args,
    });
    const return_expr = try Tag.@"return".create(c.arena, call_expr);
    const block = try Tag.block_single.create(c.arena, return_expr);

    return Tag.pub_inline_fn.create(c.arena, .{
        .name = name,
        .params = try c.arena.dupe(ast.Payload.Param, fn_params.items),
        .return_type = proto_alias.data.return_type,
        .body = block,
    });
}

fn trans_create_node_shift_op(
    c: *Context,
    scope: *Scope,
    stmt: *const clang.BinaryOperator,
    op: Tag,
    used: ResultUsed,
) !Node {
    std.debug.assert(op == .shl or op == .shr);

    const lhs_expr = stmt.getLHS();
    const rhs_expr = stmt.getRHS();
    // lhs >> @as(u5, rh)

    const lhs = try trans_expr(c, scope, lhs_expr, .used);

    const rhs = try trans_expr_coercing(c, scope, rhs_expr, .used);
    const rhs_casted = try Tag.int_cast.create(c.arena, rhs);

    return trans_create_node_infix_op(c, op, lhs, rhs_casted, used);
}

fn trans_type(c: *Context, scope: *Scope, ty: *const clang.Type, source_loc: clang.SourceLocation) TypeError!Node {
    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));
            return Tag.type.create(c.arena, switch (builtin_ty.get_kind()) {
                .Void => "anyopaque",
                .Bool => "bool",
                .Char_U, .UChar, .Char_S, .Char8 => "u8",
                .SChar => "i8",
                .UShort => "c_ushort",
                .UInt => "c_uint",
                .ULong => "c_ulong",
                .ULongLong => "c_ulonglong",
                .Short => "c_short",
                .Int => "c_int",
                .Long => "c_long",
                .LongLong => "c_longlong",
                .UInt128 => "u128",
                .Int128 => "i128",
                .Float => "f32",
                .Double => "f64",
                .Float128 => "f128",
                .Float16 => "f16",
                .LongDouble => "c_longdouble",
                else => return fail(c, error.UnsupportedType, source_loc, "unsupported builtin type", .{}),
            });
        },
        .FunctionProto => {
            const fn_proto_ty = @as(*const clang.FunctionProtoType, @ptr_cast(ty));
            const fn_proto = try trans_fn_proto(c, null, fn_proto_ty, source_loc, null, false);
            return Node.init_payload(&fn_proto.base);
        },
        .FunctionNoProto => {
            const fn_no_proto_ty = @as(*const clang.FunctionType, @ptr_cast(ty));
            const fn_proto = try trans_fn_no_proto(c, fn_no_proto_ty, source_loc, null, false);
            return Node.init_payload(&fn_proto.base);
        },
        .Paren => {
            const paren_ty = @as(*const clang.ParenType, @ptr_cast(ty));
            return trans_qual_type(c, scope, paren_ty.getInnerType(), source_loc);
        },
        .Pointer => {
            const child_qt = ty.getPointeeType();
            const is_fn_proto = qual_type_child_is_fn_proto(child_qt);
            const is_const = is_fn_proto or child_qt.isConstQualified();
            const is_volatile = child_qt.isVolatileQualified();
            const elem_type = try trans_qual_type(c, scope, child_qt, source_loc);
            const ptr_info = .{
                .is_const = is_const,
                .is_volatile = is_volatile,
                .elem_type = elem_type,
            };
            if (is_fn_proto or
                type_is_opaque(c, child_qt.getTypePtr(), source_loc) or
                qual_type_was_demoted_to_opaque(c, child_qt))
            {
                const ptr = try Tag.single_pointer.create(c.arena, ptr_info);
                return Tag.optional_type.create(c.arena, ptr);
            }

            return Tag.c_pointer.create(c.arena, ptr_info);
        },
        .ConstantArray => {
            const const_arr_ty = @as(*const clang.ConstantArrayType, @ptr_cast(ty));

            const size_ap_int = const_arr_ty.get_size();
            const size = size_ap_int.get_limited_value(usize);
            const elem_type = try trans_type(c, scope, const_arr_ty.getElementType().getTypePtr(), source_loc);

            return Tag.array_type.create(c.arena, .{ .len = size, .elem_type = elem_type });
        },
        .IncompleteArray => {
            const incomplete_array_ty = @as(*const clang.IncompleteArrayType, @ptr_cast(ty));

            const child_qt = incomplete_array_ty.getElementType();
            const is_const = child_qt.isConstQualified();
            const is_volatile = child_qt.isVolatileQualified();
            const elem_type = try trans_qual_type(c, scope, child_qt, source_loc);

            return Tag.c_pointer.create(c.arena, .{ .is_const = is_const, .is_volatile = is_volatile, .elem_type = elem_type });
        },
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));

            const typedef_decl = typedef_ty.get_decl();
            var trans_scope = scope;
            if (@as(*const clang.Decl, @ptr_cast(typedef_decl)).castToNamedDecl()) |named_decl| {
                const decl_name = try c.str(named_decl.getName_bytes_begin());
                if (c.global_names.get(decl_name)) |_| trans_scope = &c.global_scope.base;
                if (builtin_typedef_map.get(decl_name)) |builtin| return Tag.type.create(c.arena, builtin);
            }
            try trans_type_def(c, trans_scope, typedef_decl);
            const name = c.decl_table.get(@int_from_ptr(typedef_decl.getCanonicalDecl())).?;
            return Tag.identifier.create(c.arena, name);
        },
        .Record => {
            const record_ty = @as(*const clang.RecordType, @ptr_cast(ty));

            const record_decl = record_ty.get_decl();
            var trans_scope = scope;
            if (@as(*const clang.Decl, @ptr_cast(record_decl)).castToNamedDecl()) |named_decl| {
                const decl_name = try c.str(named_decl.getName_bytes_begin());
                if (c.weak_global_names.contains(decl_name)) trans_scope = &c.global_scope.base;
            }
            try trans_record_decl(c, trans_scope, record_decl);
            const name = c.decl_table.get(@int_from_ptr(record_decl.getCanonicalDecl())).?;
            return Tag.identifier.create(c.arena, name);
        },
        .Enum => {
            const enum_ty = @as(*const clang.EnumType, @ptr_cast(ty));

            const enum_decl = enum_ty.get_decl();
            var trans_scope = scope;
            if (@as(*const clang.Decl, @ptr_cast(enum_decl)).castToNamedDecl()) |named_decl| {
                const decl_name = try c.str(named_decl.getName_bytes_begin());
                if (c.weak_global_names.contains(decl_name)) trans_scope = &c.global_scope.base;
            }
            try trans_enum_decl(c, trans_scope, enum_decl);
            const name = c.decl_table.get(@int_from_ptr(enum_decl.getCanonicalDecl())).?;
            return Tag.identifier.create(c.arena, name);
        },
        .Elaborated => {
            const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(ty));
            return trans_qual_type(c, scope, elaborated_ty.getNamedType(), source_loc);
        },
        .Decayed => {
            const decayed_ty = @as(*const clang.DecayedType, @ptr_cast(ty));
            return trans_qual_type(c, scope, decayed_ty.getDecayedType(), source_loc);
        },
        .Attributed => {
            const attributed_ty = @as(*const clang.AttributedType, @ptr_cast(ty));
            return trans_qual_type(c, scope, attributed_ty.getEquivalentType(), source_loc);
        },
        .MacroQualified => {
            const macroqualified_ty = @as(*const clang.MacroQualifiedType, @ptr_cast(ty));
            return trans_qual_type(c, scope, macroqualified_ty.getModifiedType(), source_loc);
        },
        .TypeOf => {
            const typeof_ty = @as(*const clang.TypeOfType, @ptr_cast(ty));
            return trans_qual_type(c, scope, typeof_ty.getUnmodifiedType(), source_loc);
        },
        .TypeOfExpr => {
            const typeofexpr_ty = @as(*const clang.TypeOfExprType, @ptr_cast(ty));
            const underlying_expr = trans_expr(c, scope, typeofexpr_ty.getUnderlyingExpr(), .used) catch |err| switch (err) {
                error.UnsupportedTranslation => {
                    return fail(c, error.UnsupportedType, source_loc, "unsupported underlying expression for TypeOfExpr", .{});
                },
                else => |e| return e,
            };
            return Tag.typeof.create(c.arena, underlying_expr);
        },
        .Vector => {
            const vector_ty = @as(*const clang.VectorType, @ptr_cast(ty));
            const num_elements = vector_ty.getNumElements();
            const element_qt = vector_ty.getElementType();
            return Tag.vector.create(c.arena, .{
                .lhs = try trans_create_node_number(c, num_elements, .int),
                .rhs = try trans_qual_type(c, scope, element_qt, source_loc),
            });
        },
        .BitInt, .ExtVector => {
            const type_name = try c.str(ty.getTypeClassName());
            return fail(c, error.UnsupportedType, source_loc, "TODO implement translation of type: '{s}'", .{type_name});
        },
        else => {
            const type_name = try c.str(ty.getTypeClassName());
            return fail(c, error.UnsupportedType, source_loc, "unsupported type: '{s}'", .{type_name});
        },
    }
}

fn qual_type_was_demoted_to_opaque(c: *Context, qt: clang.QualType) bool {
    const ty = qt.getTypePtr();
    switch (qt.getTypeClass()) {
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));

            const typedef_decl = typedef_ty.get_decl();
            const underlying_type = typedef_decl.getUnderlyingType();
            return qual_type_was_demoted_to_opaque(c, underlying_type);
        },
        .Record => {
            const record_ty = @as(*const clang.RecordType, @ptr_cast(ty));

            const record_decl = record_ty.get_decl();
            const canonical = @int_from_ptr(record_decl.getCanonicalDecl());
            if (c.opaque_demotes.contains(canonical)) return true;

            // check all childern for opaque types.
            var it = record_decl.field_begin();
            const end_it = record_decl.field_end();
            while (it.neq(end_it)) : (it = it.next()) {
                const field_decl = it.deref();
                if (qual_type_was_demoted_to_opaque(c, field_decl.get_type())) return true;
            }
            return false;
        },
        .Enum => {
            const enum_ty = @as(*const clang.EnumType, @ptr_cast(ty));

            const enum_decl = enum_ty.get_decl();
            const canonical = @int_from_ptr(enum_decl.getCanonicalDecl());
            return c.opaque_demotes.contains(canonical);
        },
        .Elaborated => {
            const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(ty));
            return qual_type_was_demoted_to_opaque(c, elaborated_ty.getNamedType());
        },
        .Decayed => {
            const decayed_ty = @as(*const clang.DecayedType, @ptr_cast(ty));
            return qual_type_was_demoted_to_opaque(c, decayed_ty.getDecayedType());
        },
        .Attributed => {
            const attributed_ty = @as(*const clang.AttributedType, @ptr_cast(ty));
            return qual_type_was_demoted_to_opaque(c, attributed_ty.getEquivalentType());
        },
        .MacroQualified => {
            const macroqualified_ty = @as(*const clang.MacroQualifiedType, @ptr_cast(ty));
            return qual_type_was_demoted_to_opaque(c, macroqualified_ty.getModifiedType());
        },
        else => return false,
    }
}

fn is_anyopaque(qt: clang.QualType) bool {
    const ty = qt.getTypePtr();
    switch (ty.getTypeClass()) {
        .Builtin => {
            const builtin_ty = @as(*const clang.BuiltinType, @ptr_cast(ty));
            return builtin_ty.get_kind() == .Void;
        },
        .Typedef => {
            const typedef_ty = @as(*const clang.TypedefType, @ptr_cast(ty));
            const typedef_decl = typedef_ty.get_decl();
            return is_anyopaque(typedef_decl.getUnderlyingType());
        },
        .Elaborated => {
            const elaborated_ty = @as(*const clang.ElaboratedType, @ptr_cast(ty));
            return is_anyopaque(elaborated_ty.getNamedType().getCanonicalType());
        },
        .Decayed => {
            const decayed_ty = @as(*const clang.DecayedType, @ptr_cast(ty));
            return is_anyopaque(decayed_ty.getDecayedType().getCanonicalType());
        },
        .Attributed => {
            const attributed_ty = @as(*const clang.AttributedType, @ptr_cast(ty));
            return is_anyopaque(attributed_ty.getEquivalentType().getCanonicalType());
        },
        .MacroQualified => {
            const macroqualified_ty = @as(*const clang.MacroQualifiedType, @ptr_cast(ty));
            return is_anyopaque(macroqualified_ty.getModifiedType().getCanonicalType());
        },
        else => return false,
    }
}

const FnDeclContext = struct {
    fn_name: []const u8,
    has_body: bool,
    storage_class: clang.StorageClass,
    is_always_inline: bool,
    is_export: bool,
};

fn trans_cc(
    c: *Context,
    fn_ty: *const clang.FunctionType,
    source_loc: clang.SourceLocation,
) !CallingConvention {
    const clang_cc = fn_ty.getCallConv();
    switch (clang_cc) {
        .C => return CallingConvention.C,
        .X86StdCall => return CallingConvention.Stdcall,
        .X86FastCall => return CallingConvention.Fastcall,
        .X86VectorCall, .AArch64VectorCall => return CallingConvention.Vectorcall,
        .X86ThisCall => return CallingConvention.Thiscall,
        .AAPCS => return CallingConvention.AAPCS,
        .AAPCS_VFP => return CallingConvention.AAPCSVFP,
        .X86_64SysV => return CallingConvention.SysV,
        else => return fail(
            c,
            error.UnsupportedType,
            source_loc,
            "unsupported calling convention: {s}",
            .{@tag_name(clang_cc)},
        ),
    }
}

fn trans_fn_proto(
    c: *Context,
    fn_decl: ?*const clang.FunctionDecl,
    fn_proto_ty: *const clang.FunctionProtoType,
    source_loc: clang.SourceLocation,
    fn_decl_context: ?FnDeclContext,
    is_pub: bool,
) !*ast.Payload.Func {
    const fn_ty = @as(*const clang.FunctionType, @ptr_cast(fn_proto_ty));
    const cc = try trans_cc(c, fn_ty, source_loc);
    const is_var_args = fn_proto_ty.isVariadic();
    return finish_trans_fn_proto(c, fn_decl, fn_proto_ty, fn_ty, source_loc, fn_decl_context, is_var_args, cc, is_pub);
}

fn trans_fn_no_proto(
    c: *Context,
    fn_ty: *const clang.FunctionType,
    source_loc: clang.SourceLocation,
    fn_decl_context: ?FnDeclContext,
    is_pub: bool,
) !*ast.Payload.Func {
    const cc = try trans_cc(c, fn_ty, source_loc);
    const is_var_args = if (fn_decl_context) |ctx| (!ctx.is_export and ctx.storage_class != .Static and !ctx.is_always_inline) else true;
    return finish_trans_fn_proto(c, null, null, fn_ty, source_loc, fn_decl_context, is_var_args, cc, is_pub);
}

fn finish_trans_fn_proto(
    c: *Context,
    fn_decl: ?*const clang.FunctionDecl,
    fn_proto_ty: ?*const clang.FunctionProtoType,
    fn_ty: *const clang.FunctionType,
    source_loc: clang.SourceLocation,
    fn_decl_context: ?FnDeclContext,
    is_var_args: bool,
    cc: CallingConvention,
    is_pub: bool,
) !*ast.Payload.Func {
    const is_export = if (fn_decl_context) |ctx| ctx.is_export else false;
    const is_extern = if (fn_decl_context) |ctx| !ctx.has_body else false;
    const is_inline = if (fn_decl_context) |ctx| ctx.is_always_inline else false;
    const scope = &c.global_scope.base;

    const param_count: usize = if (fn_proto_ty != null) fn_proto_ty.?.getNumParams() else 0;
    var fn_params = try std.ArrayList(ast.Payload.Param).init_capacity(c.gpa, param_count);
    defer fn_params.deinit();

    var i: usize = 0;
    while (i < param_count) : (i += 1) {
        const param_qt = fn_proto_ty.?.getParamType(@as(c_uint, @int_cast(i)));
        const is_noalias = param_qt.isRestrictQualified();

        const param_name: ?[]const u8 =
            if (fn_decl) |decl|
        blk: {
            const param = decl.getParamDecl(@as(c_uint, @int_cast(i)));
            const param_name: []const u8 = try c.str(@as(*const clang.NamedDecl, @ptr_cast(param)).getName_bytes_begin());
            if (param_name.len < 1)
                break :blk null;

            break :blk param_name;
        } else null;
        const type_node = try trans_qual_type(c, scope, param_qt, source_loc);

        fn_params.add_one_assume_capacity().* = .{
            .is_noalias = is_noalias,
            .name = param_name,
            .type = type_node,
        };
    }

    const linksection_string = blk: {
        if (fn_decl) |decl| {
            var str_len: usize = undefined;
            if (decl.getSectionAttribute(&str_len)) |str_ptr| {
                break :blk str_ptr[0..str_len];
            }
        }
        break :blk null;
    };

    const alignment = if (fn_decl) |decl| ClangAlignment.for_func(c, decl).zig_alignment() else null;

    const explicit_callconv = if ((is_inline or is_export or is_extern) and cc == .C) null else cc;

    const return_type_node = blk: {
        if (fn_ty.getNoReturnAttr()) {
            break :blk Tag.noreturn_type.init();
        } else {
            const return_qt = fn_ty.get_return_type();
            if (is_anyopaque(return_qt)) {
                // convert primitive anyopaque to actual void (only for return type)
                break :blk Tag.void_type.init();
            } else {
                break :blk trans_qual_type(c, scope, return_qt, source_loc) catch |err| switch (err) {
                    error.UnsupportedType => {
                        try warn(c, scope, source_loc, "unsupported function proto return type", .{});
                        return err;
                    },
                    error.OutOfMemory => |e| return e,
                };
            }
        }
    };
    const name: ?[]const u8 = if (fn_decl_context) |ctx| ctx.fn_name else null;
    const payload = try c.arena.create(ast.Payload.Func);
    payload.* = .{
        .base = .{ .tag = .func },
        .data = .{
            .is_pub = is_pub,
            .is_extern = is_extern,
            .is_export = is_export,
            .is_inline = is_inline,
            .is_var_args = is_var_args,
            .name = name,
            .linksection_string = linksection_string,
            .explicit_callconv = explicit_callconv,
            .params = try c.arena.dupe(ast.Payload.Param, fn_params.items),
            .return_type = return_type_node,
            .body = null,
            .alignment = alignment,
        },
    };
    return payload;
}

fn warn(c: *Context, scope: *Scope, loc: clang.SourceLocation, comptime format: []const u8, args: anytype) !void {
    const str = try c.loc_str(loc);
    const value = try std.fmt.alloc_print(c.arena, "// {s}: warning: " ++ format, .{str} ++ args);
    try scope.append_node(try Tag.warning.create(c.arena, value));
}

fn fail(
    c: *Context,
    err: anytype,
    source_loc: clang.SourceLocation,
    comptime format: []const u8,
    args: anytype,
) (@TypeOf(err) || error{OutOfMemory}) {
    try warn(c, &c.global_scope.base, source_loc, format, args);
    return err;
}

pub fn fail_decl(c: *Context, loc: clang.SourceLocation, name: []const u8, comptime format: []const u8, args: anytype) Error!void {
    // location
    // pub const name = @compile_error(msg);
    const fail_msg = try std.fmt.alloc_print(c.arena, format, args);
    try add_top_level_decl(c, name, try Tag.fail_decl.create(c.arena, .{ .actual = name, .mangled = fail_msg }));
    const str = try c.loc_str(loc);
    const location_comment = try std.fmt.alloc_print(c.arena, "// {s}", .{str});
    try c.global_scope.nodes.append(try Tag.warning.create(c.arena, location_comment));
}

const MacroCtx = struct {
    source: []const u8,
    list: []const CToken,
    i: usize = 0,
    loc: clang.SourceLocation,
    name: []const u8,
    refs_var_decl: bool = false,

    fn peek(self: *MacroCtx) ?CToken.Id {
        if (self.i >= self.list.len) return null;
        return self.list[self.i + 1].id;
    }

    fn next(self: *MacroCtx) ?CToken.Id {
        if (self.i >= self.list.len) return null;
        self.i += 1;
        return self.list[self.i].id;
    }

    fn skip(self: *MacroCtx, c: *Context, expected_id: CToken.Id) ParseError!void {
        const next_id = self.next().?;
        if (next_id != expected_id and !(expected_id == .identifier and next_id == .extended_identifier)) {
            try self.fail(
                c,
                "unable to translate C expr: expected '{s}' instead got '{s}'",
                .{ expected_id.symbol(), next_id.symbol() },
            );
            return error.ParseError;
        }
    }

    fn slice(self: *MacroCtx) []const u8 {
        const tok = self.list[self.i];
        return self.source[tok.start..tok.end];
    }

    fn fail(self: *MacroCtx, c: *Context, comptime fmt: []const u8, args: anytype) !void {
        return fail_decl(c, self.loc, self.name, fmt, args);
    }

    fn make_slicer(self: *const MacroCtx) MacroSlicer {
        return .{ .source = self.source, .tokens = self.list };
    }

    const MacroTranslateError = union(enum) {
        undefined_identifier: []const u8,
        invalid_arg_usage: []const u8,
    };

    fn check_translatable_macro(self: *MacroCtx, scope: *Scope, params: []const ast.Payload.Param) ?MacroTranslateError {
        const slicer = self.make_slicer();
        var last_is_type_kw = false;
        var i: usize = 1; // index 0 is the macro name
        while (i < self.list.len) : (i += 1) {
            const token = self.list[i];
            switch (token.id) {
                .period, .arrow => i += 1, // skip next token since field identifiers can be unknown
                .keyword_struct, .keyword_union, .keyword_enum => if (!last_is_type_kw) {
                    last_is_type_kw = true;
                    continue;
                },
                .identifier, .extended_identifier => {
                    const identifier = slicer.slice(token);
                    const is_param = for (params) |param| {
                        if (param.name != null and mem.eql(u8, identifier, param.name.?)) break true;
                    } else false;
                    if (is_param and last_is_type_kw) {
                        return .{ .invalid_arg_usage = identifier };
                    }
                    if (!scope.contains(identifier) and !is_builtin_defined(identifier) and !is_param) {
                        return .{ .undefined_identifier = identifier };
                    }
                },
                else => {},
            }
            last_is_type_kw = false;
        }
        return null;
    }
};

fn get_macro_text(unit: *const clang.ASTUnit, c: *const Context, macro: *const clang.MacroDefinitionRecord) ![]const u8 {
    const begin_loc = macro.getSourceRange_getBegin();
    const end_loc = clang.Lexer.getLocForEndOfToken(macro.getSourceRange_getEnd(), c.source_manager, unit);

    const begin_c = c.source_manager.getCharacterData(begin_loc);
    const end_c = c.source_manager.getCharacterData(end_loc);
    const slice_len = @int_from_ptr(end_c) - @int_from_ptr(begin_c);

    var comp = aro.Compilation.init(c.gpa);
    defer comp.deinit();
    const result = comp.add_source_from_buffer("", begin_c[0..slice_len]) catch return error.OutOfMemory;

    return c.arena.dupe(u8, result.buf);
}

fn trans_preprocessor_entities(c: *Context, unit: *clang.ASTUnit) Error!void {
    // TODO if we see #undef, delete it from the table
    var it = unit.getLocalPreprocessingEntities_begin();
    const it_end = unit.getLocalPreprocessingEntities_end();
    var tok_list = std.ArrayList(CToken).init(c.gpa);
    defer tok_list.deinit();
    const scope = c.global_scope;

    while (it.I != it_end.I) : (it.I += 1) {
        const entity = it.deref();
        tok_list.items.len = 0;
        switch (entity.get_kind()) {
            .MacroDefinitionKind => {
                const macro = @as(*clang.MacroDefinitionRecord, @ptr_cast(entity));
                const raw_name = macro.getName_getNameStart();
                const begin_loc = macro.getSourceRange_getBegin();

                const name = try c.str(raw_name);
                if (scope.contains_now(name)) {
                    continue;
                }

                const source = try get_macro_text(unit, c, macro);

                try common.tokenize_macro(source, &tok_list);

                var macro_ctx = MacroCtx{
                    .source = source,
                    .list = tok_list.items,
                    .name = name,
                    .loc = begin_loc,
                };
                assert(mem.eql(u8, macro_ctx.slice(), name));

                var macro_fn = false;
                switch (macro_ctx.peek().?) {
                    .identifier, .extended_identifier => {
                        // if it equals itself, ignore. for example, from stdio.h:
                        // #define stdin stdin
                        const tok = macro_ctx.list[1];
                        if (mem.eql(u8, name, source[tok.start..tok.end])) {
                            assert(!c.global_names.contains(source[tok.start..tok.end]));
                            continue;
                        }
                    },
                    .nl, .eof => {
                        // this means it is a macro without a value
                        // We define it as an empty string so that it can still be used with ++
                        const str_node = try Tag.string_literal.create(c.arena, "\"\"");
                        const var_decl = try Tag.pub_var_simple.create(c.arena, .{ .name = name, .init = str_node });
                        try add_top_level_decl(c, name, var_decl);
                        try c.global_scope.blank_macros.put(name, {});
                        continue;
                    },
                    .l_paren => {
                        // if the name is immediately followed by a '(' then it is a function
                        macro_fn = macro_ctx.list[0].end == macro_ctx.list[1].start;
                    },
                    else => {},
                }

                (if (macro_fn)
                    trans_macro_fn_define(c, &macro_ctx)
                else
                    trans_macro_define(c, &macro_ctx)) catch |err| switch (err) {
                    error.ParseError => continue,
                    error.OutOfMemory => |e| return e,
                };
            },
            else => {},
        }
    }
}

fn trans_macro_define(c: *Context, m: *MacroCtx) ParseError!void {
    const scope = &c.global_scope.base;

    if (m.check_translatable_macro(scope, &.{})) |err| switch (err) {
        .undefined_identifier => |ident| return m.fail(c, "unable to translate macro: undefined identifier `{s}`", .{ident}),
        .invalid_arg_usage => unreachable, // no args
    };

    // Check if the macro only uses other blank macros.
    while (true) {
        switch (m.peek().?) {
            .identifier, .extended_identifier => {
                const tok = m.list[m.i + 1];
                const slice = m.source[tok.start..tok.end];
                if (c.global_scope.blank_macros.contains(slice)) {
                    m.i += 1;
                    continue;
                }
            },
            .eof, .nl => {
                try c.global_scope.blank_macros.put(m.name, {});
                const init_node = try Tag.string_literal.create(c.arena, "\"\"");
                const var_decl = try Tag.pub_var_simple.create(c.arena, .{ .name = m.name, .init = init_node });
                try add_top_level_decl(c, m.name, var_decl);
                return;
            },
            else => {},
        }
        break;
    }

    const init_node = try parse_cexpr(c, m, scope);
    const last = m.next().?;
    if (last != .eof and last != .nl)
        return m.fail(c, "unable to translate C expr: unexpected token '{s}'", .{last.symbol()});

    const node = node: {
        const var_decl = try Tag.pub_var_simple.create(c.arena, .{ .name = m.name, .init = init_node });

        if (get_fn_proto(c, var_decl)) |proto_node| {
            // If a macro aliases a global variable which is a function pointer, we conclude that
            // the macro is intended to represent a function that assumes the function pointer
            // variable is non-null and calls it.
            break :node try trans_create_node_macro_fn(c, m.name, var_decl, proto_node);
        } else if (m.refs_var_decl) {
            const return_type = try Tag.typeof.create(c.arena, init_node);
            const return_expr = try Tag.@"return".create(c.arena, init_node);
            const block = try Tag.block_single.create(c.arena, return_expr);
            try warn(c, scope, m.loc, "macro '{s}' contains a runtime value, translated to function", .{m.name});

            break :node try Tag.pub_inline_fn.create(c.arena, .{
                .name = m.name,
                .params = &.{},
                .return_type = return_type,
                .body = block,
            });
        }

        break :node var_decl;
    };

    try add_top_level_decl(c, m.name, node);
}

fn trans_macro_fn_define(c: *Context, m: *MacroCtx) ParseError!void {
    const macro_slicer = m.make_slicer();
    if (try c.pattern_list.match(c.gpa, macro_slicer)) |pattern| {
        const decl = try Tag.pub_var_simple.create(c.arena, .{
            .name = m.name,
            .init = try Tag.helpers_macro.create(c.arena, pattern.impl),
        });
        try add_top_level_decl(c, m.name, decl);
        return;
    }

    var block_scope = try Scope.Block.init(c, &c.global_scope.base, false);
    defer block_scope.deinit();
    const scope = &block_scope.base;

    try m.skip(c, .l_paren);

    var fn_params = std.ArrayList(ast.Payload.Param).init(c.gpa);
    defer fn_params.deinit();

    while (true) {
        switch (m.peek().?) {
            .identifier, .extended_identifier => _ = m.next(),
            else => break,
        }

        const mangled_name = try block_scope.make_mangled_name(c, m.slice());
        try fn_params.append(.{
            .is_noalias = false,
            .name = mangled_name,
            .type = Tag.@"anytype".init(),
        });
        try block_scope.discard_variable(c, mangled_name);
        if (m.peek().? != .comma) break;
        _ = m.next();
    }

    try m.skip(c, .r_paren);

    if (m.check_translatable_macro(scope, fn_params.items)) |err| switch (err) {
        .undefined_identifier => |ident| return m.fail(c, "unable to translate macro: undefined identifier `{s}`", .{ident}),
        .invalid_arg_usage => |ident| return m.fail(c, "unable to translate macro: untranslatable usage of arg `{s}`", .{ident}),
    };

    const expr = try parse_cexpr(c, m, scope);
    const last = m.next().?;
    if (last != .eof and last != .nl)
        return m.fail(c, "unable to translate C expr: unexpected token '{s}'", .{last.symbol()});

    const typeof_arg = if (expr.cast_tag(.block)) |some| blk: {
        const stmts = some.data.stmts;
        const blk_last = stmts[stmts.len - 1];
        const br = blk_last.cast_tag(.break_val).?;
        break :blk br.data.val;
    } else expr;

    const return_type = if (typeof_arg.cast_tag(.helpers_cast) orelse typeof_arg.cast_tag(.std_mem_zeroinit)) |some|
        some.data.lhs
    else if (typeof_arg.cast_tag(.std_mem_zeroes)) |some|
        some.data
    else
        try Tag.typeof.create(c.arena, typeof_arg);

    const return_expr = try Tag.@"return".create(c.arena, expr);
    try block_scope.statements.append(return_expr);

    const fn_decl = try Tag.pub_inline_fn.create(c.arena, .{
        .name = m.name,
        .params = try c.arena.dupe(ast.Payload.Param, fn_params.items),
        .return_type = return_type,
        .body = try block_scope.complete(c),
    });
    try add_top_level_decl(c, m.name, fn_decl);
}

const ParseError = Error || error{ParseError};

fn parse_cexpr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    // TODO parseCAssignExpr here
    var block_scope = try Scope.Block.init(c, scope, true);
    defer block_scope.deinit();

    const node = try parse_ccond_expr(c, m, &block_scope.base);
    if (m.next().? != .comma) {
        m.i -= 1;
        return node;
    }

    var last = node;
    while (true) {
        // suppress result
        const ignore = try Tag.discard.create(c.arena, .{ .should_skip = false, .value = last });
        try block_scope.statements.append(ignore);

        last = try parse_ccond_expr(c, m, &block_scope.base);
        if (m.next().? != .comma) {
            m.i -= 1;
            break;
        }
    }

    const break_node = try Tag.break_val.create(c.arena, .{
        .label = block_scope.label,
        .val = last,
    });
    try block_scope.statements.append(break_node);
    return try block_scope.complete(c);
}

fn parse_cnum_lit(ctx: *Context, m: *MacroCtx) ParseError!Node {
    const lit_bytes = m.slice();
    var bytes = try std.ArrayListUnmanaged(u8).init_capacity(ctx.arena, lit_bytes.len + 3);

    const prefix = aro.Tree.Token.NumberPrefix.from_string(lit_bytes);
    switch (prefix) {
        .binary => bytes.append_slice_assume_capacity("0b"),
        .octal => bytes.append_slice_assume_capacity("0o"),
        .hex => bytes.append_slice_assume_capacity("0x"),
        .decimal => {},
    }

    const after_prefix = lit_bytes[prefix.string_len()..];
    const after_int = for (after_prefix, 0..) |c, i| switch (c) {
        '.' => {
            if (i == 0) {
                bytes.append_assume_capacity('0');
            }
            break after_prefix[i..];
        },
        'e', 'E' => {
            if (prefix != .hex) break after_prefix[i..];
            bytes.append_assume_capacity(c);
        },
        'p', 'P' => break after_prefix[i..],
        '0'...'9', 'a'...'d', 'A'...'D', 'f', 'F' => {
            if (!prefix.digit_allowed(c)) break after_prefix[i..];
            bytes.append_assume_capacity(c);
        },
        '\'' => {
            bytes.append_assume_capacity('_');
        },
        else => break after_prefix[i..],
    } else "";

    const after_frac = frac: {
        if (after_int.len == 0 or after_int[0] != '.') break :frac after_int;
        bytes.append_assume_capacity('.');
        for (after_int[1..], 1..) |c, i| {
            if (c == '\'') {
                bytes.append_assume_capacity('_');
                continue;
            }
            if (!prefix.digit_allowed(c)) break :frac after_int[i..];
            bytes.append_assume_capacity(c);
        }
        break :frac "";
    };

    const suffix_str = exponent: {
        if (after_frac.len == 0) break :exponent after_frac;
        switch (after_frac[0]) {
            'e', 'E' => {},
            'p', 'P' => if (prefix != .hex) break :exponent after_frac,
            else => break :exponent after_frac,
        }
        bytes.append_assume_capacity(after_frac[0]);
        for (after_frac[1..], 1..) |c, i| switch (c) {
            '+', '-', '0'...'9' => {
                bytes.append_assume_capacity(c);
            },
            '\'' => {
                bytes.append_assume_capacity('_');
            },
            else => break :exponent after_frac[i..],
        };
        break :exponent "";
    };

    const is_float = after_int.len != suffix_str.len;
    const suffix = aro.Tree.Token.NumberSuffix.from_string(suffix_str, if (is_float) .float else .int) orelse {
        try m.fail(ctx, "invalid number suffix: '{s}'", .{suffix_str});
        return error.ParseError;
    };
    if (suffix.is_imaginary()) {
        try m.fail(ctx, "TODO: imaginary literals", .{});
        return error.ParseError;
    }
    if (suffix.is_bit_int()) {
        try m.fail(ctx, "TODO: _BitInt literals", .{});
        return error.ParseError;
    }

    if (is_float) {
        const type_node = try Tag.type.create(ctx.arena, switch (suffix) {
            .F16 => "f16",
            .F => "f32",
            .None => "f64",
            .L => "c_longdouble",
            .W => "f80",
            .Q, .F128 => "f128",
            else => unreachable,
        });
        const rhs = try Tag.float_literal.create(ctx.arena, bytes.items);
        return Tag.as.create(ctx.arena, .{ .lhs = type_node, .rhs = rhs });
    } else {
        const type_node = try Tag.type.create(ctx.arena, switch (suffix) {
            .None => "c_int",
            .U => "c_uint",
            .L => "c_long",
            .UL => "c_ulong",
            .LL => "c_longlong",
            .ULL => "c_ulonglong",
            else => unreachable,
        });
        const value = std.fmt.parse_int(i128, bytes.items, 0) catch math.max_int(i128);

        // make the output less noisy by skipping promote_int_literal where
        // it's guaranteed to not be required because of C standard type constraints
        const guaranteed_to_fit = switch (suffix) {
            .None => math.cast(i16, value) != null,
            .U => math.cast(u16, value) != null,
            .L => math.cast(i32, value) != null,
            .UL => math.cast(u32, value) != null,
            .LL => math.cast(i64, value) != null,
            .ULL => math.cast(u64, value) != null,
            else => unreachable,
        };

        const literal_node = try Tag.integer_literal.create(ctx.arena, bytes.items);
        if (guaranteed_to_fit) {
            return Tag.as.create(ctx.arena, .{ .lhs = type_node, .rhs = literal_node });
        } else {
            return Tag.helpers_promoteIntLiteral.create(ctx.arena, .{
                .type = type_node,
                .value = literal_node,
                .base = try Tag.enum_literal.create(ctx.arena, @tag_name(prefix)),
            });
        }
    }
}

fn zigify_escape_sequences(ctx: *Context, m: *MacroCtx) ![]const u8 {
    var source = m.slice();
    for (source, 0..) |c, i| {
        if (c == '\"' or c == '\'') {
            source = source[i..];
            break;
        }
    }
    for (source) |c| {
        if (c == '\\' or c == '\t') {
            break;
        }
    } else return source;
    var bytes = try ctx.arena.alloc(u8, source.len * 2);
    var state: enum {
        start,
        escape,
        hex,
        octal,
    } = .start;
    var i: usize = 0;
    var count: u8 = 0;
    var num: u8 = 0;
    for (source) |c| {
        switch (state) {
            .escape => {
                switch (c) {
                    'n', 'r', 't', '\\', '\'', '\"' => {
                        bytes[i] = c;
                    },
                    '0'...'7' => {
                        count += 1;
                        num += c - '0';
                        state = .octal;
                        bytes[i] = 'x';
                    },
                    'x' => {
                        state = .hex;
                        bytes[i] = 'x';
                    },
                    'a' => {
                        bytes[i] = 'x';
                        i += 1;
                        bytes[i] = '0';
                        i += 1;
                        bytes[i] = '7';
                    },
                    'b' => {
                        bytes[i] = 'x';
                        i += 1;
                        bytes[i] = '0';
                        i += 1;
                        bytes[i] = '8';
                    },
                    'f' => {
                        bytes[i] = 'x';
                        i += 1;
                        bytes[i] = '0';
                        i += 1;
                        bytes[i] = 'C';
                    },
                    'v' => {
                        bytes[i] = 'x';
                        i += 1;
                        bytes[i] = '0';
                        i += 1;
                        bytes[i] = 'B';
                    },
                    '?' => {
                        i -= 1;
                        bytes[i] = '?';
                    },
                    'u', 'U' => {
                        try m.fail(ctx, "macro tokenizing failed: TODO unicode escape sequences", .{});
                        return error.ParseError;
                    },
                    else => {
                        try m.fail(ctx, "macro tokenizing failed: unknown escape sequence", .{});
                        return error.ParseError;
                    },
                }
                i += 1;
                if (state == .escape)
                    state = .start;
            },
            .start => {
                if (c == '\t') {
                    bytes[i] = '\\';
                    i += 1;
                    bytes[i] = 't';
                    i += 1;
                    continue;
                }
                if (c == '\\') {
                    state = .escape;
                }
                bytes[i] = c;
                i += 1;
            },
            .hex => {
                switch (c) {
                    '0'...'9' => {
                        num = std.math.mul(u8, num, 16) catch {
                            try m.fail(ctx, "macro tokenizing failed: hex literal overflowed", .{});
                            return error.ParseError;
                        };
                        num += c - '0';
                    },
                    'a'...'f' => {
                        num = std.math.mul(u8, num, 16) catch {
                            try m.fail(ctx, "macro tokenizing failed: hex literal overflowed", .{});
                            return error.ParseError;
                        };
                        num += c - 'a' + 10;
                    },
                    'A'...'F' => {
                        num = std.math.mul(u8, num, 16) catch {
                            try m.fail(ctx, "macro tokenizing failed: hex literal overflowed", .{});
                            return error.ParseError;
                        };
                        num += c - 'A' + 10;
                    },
                    else => {
                        i += std.fmt.format_int_buf(bytes[i..], num, 16, .lower, std.fmt.FormatOptions{ .fill = '0', .width = 2 });
                        num = 0;
                        if (c == '\\')
                            state = .escape
                        else
                            state = .start;
                        bytes[i] = c;
                        i += 1;
                    },
                }
            },
            .octal => {
                const accept_digit = switch (c) {
                    // The maximum length of a octal literal is 3 digits
                    '0'...'7' => count < 3,
                    else => false,
                };

                if (accept_digit) {
                    count += 1;
                    num = std.math.mul(u8, num, 8) catch {
                        try m.fail(ctx, "macro tokenizing failed: octal literal overflowed", .{});
                        return error.ParseError;
                    };
                    num += c - '0';
                } else {
                    i += std.fmt.format_int_buf(bytes[i..], num, 16, .lower, std.fmt.FormatOptions{ .fill = '0', .width = 2 });
                    num = 0;
                    count = 0;
                    if (c == '\\')
                        state = .escape
                    else
                        state = .start;
                    bytes[i] = c;
                    i += 1;
                }
            },
        }
    }
    if (state == .hex or state == .octal)
        i += std.fmt.format_int_buf(bytes[i..], num, 16, .lower, std.fmt.FormatOptions{ .fill = '0', .width = 2 });
    return bytes[0..i];
}

/// non-ASCII characters (c > 127) are also treated as non-printable by fmt_slice_escape_lower.
/// If a C string literal or char literal in a macro is not valid UTF-8, we need to escape
/// non-ASCII characters so that the Zig source we output will itself be UTF-8.
fn escape_unprintables(ctx: *Context, m: *MacroCtx) ![]const u8 {
    const zigified = try zigify_escape_sequences(ctx, m);
    if (std.unicode.utf8_validate_slice(zigified)) return zigified;

    const formatter = std.fmt.fmt_slice_escape_lower(zigified);
    const encoded_size = @as(usize, @int_cast(std.fmt.count("{s}", .{formatter})));
    const output = try ctx.arena.alloc(u8, encoded_size);
    return std.fmt.buf_print(output, "{s}", .{formatter}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
        else => |e| return e,
    };
}

fn parse_cprimary_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    const tok = m.next().?;
    const slice = m.slice();
    switch (tok) {
        .char_literal,
        .char_literal_utf_8,
        .char_literal_utf_16,
        .char_literal_utf_32,
        .char_literal_wide,
        => {
            if (slice[0] != '\'' or slice[1] == '\\' or slice.len == 3) {
                return Tag.char_literal.create(c.arena, try escape_unprintables(c, m));
            } else {
                const str = try std.fmt.alloc_print(c.arena, "0x{s}", .{std.fmt.fmt_slice_hex_lower(slice[1 .. slice.len - 1])});
                return Tag.integer_literal.create(c.arena, str);
            }
        },
        .string_literal,
        .string_literal_utf_16,
        .string_literal_utf_8,
        .string_literal_utf_32,
        .string_literal_wide,
        => {
            return Tag.string_literal.create(c.arena, try escape_unprintables(c, m));
        },
        .pp_num => {
            return parse_cnum_lit(c, m);
        },
        .identifier, .extended_identifier => {
            if (c.global_scope.blank_macros.contains(slice)) {
                return parse_cprimary_expr(c, m, scope);
            }
            const mangled_name = scope.get_alias(slice);
            if (builtin_typedef_map.get(mangled_name)) |ty| return Tag.type.create(c.arena, ty);
            const identifier = try Tag.identifier.create(c.arena, mangled_name);
            scope.skip_variable_discard(identifier.cast_tag(.identifier).?.data);
            refs_var: {
                const ident_node = c.global_scope.sym_table.get(slice) orelse break :refs_var;
                const var_decl_node = ident_node.cast_tag(.var_decl) orelse break :refs_var;
                if (!var_decl_node.data.is_const) m.refs_var_decl = true;
            }
            return identifier;
        },
        .l_paren => {
            const inner_node = try parse_cexpr(c, m, scope);

            try m.skip(c, .r_paren);
            return inner_node;
        },
        else => {
            // for handling type macros (EVIL)
            // TODO maybe detect and treat type macros as typedefs in parse_cspecifier_qualifier_list?
            m.i -= 1;
            if (try parse_ctype_name(c, m, scope, true)) |type_name| {
                return type_name;
            }
            try m.fail(c, "unable to translate C expr: unexpected token '{s}'", .{tok.symbol()});
            return error.ParseError;
        },
    }
}

fn macro_int_from_bool(c: *Context, node: Node) !Node {
    if (!is_bool_res(node)) {
        return node;
    }

    return Tag.int_from_bool.create(c.arena, node);
}

fn macro_int_to_bool(c: *Context, node: Node) !Node {
    if (is_bool_res(node)) {
        return node;
    }
    if (node.tag() == .string_literal) {
        // @int_from_ptr(node) != 0
        const int_from_ptr = try Tag.int_from_ptr.create(c.arena, node);
        return Tag.not_equal.create(c.arena, .{ .lhs = int_from_ptr, .rhs = Tag.zero_literal.init() });
    }
    // node != 0
    return Tag.not_equal.create(c.arena, .{ .lhs = node, .rhs = Tag.zero_literal.init() });
}

fn parse_ccond_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    const node = try parse_cor_expr(c, m, scope);
    if (m.peek().? != .question_mark) {
        return node;
    }
    _ = m.next();

    const then_body = try parse_cor_expr(c, m, scope);
    try m.skip(c, .colon);
    const else_body = try parse_ccond_expr(c, m, scope);
    return Tag.@"if".create(c.arena, .{ .cond = node, .then = then_body, .@"else" = else_body });
}

fn parse_cor_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cand_expr(c, m, scope);
    while (m.next().? == .pipe_pipe) {
        const lhs = try macro_int_to_bool(c, node);
        const rhs = try macro_int_to_bool(c, try parse_cand_expr(c, m, scope));
        node = try Tag.@"or".create(c.arena, .{ .lhs = lhs, .rhs = rhs });
    }
    m.i -= 1;
    return node;
}

fn parse_cand_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cbit_or_expr(c, m, scope);
    while (m.next().? == .ampersand_ampersand) {
        const lhs = try macro_int_to_bool(c, node);
        const rhs = try macro_int_to_bool(c, try parse_cbit_or_expr(c, m, scope));
        node = try Tag.@"and".create(c.arena, .{ .lhs = lhs, .rhs = rhs });
    }
    m.i -= 1;
    return node;
}

fn parse_cbit_or_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cbit_xor_expr(c, m, scope);
    while (m.next().? == .pipe) {
        const lhs = try macro_int_from_bool(c, node);
        const rhs = try macro_int_from_bool(c, try parse_cbit_xor_expr(c, m, scope));
        node = try Tag.bit_or.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
    }
    m.i -= 1;
    return node;
}

fn parse_cbit_xor_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cbit_and_expr(c, m, scope);
    while (m.next().? == .caret) {
        const lhs = try macro_int_from_bool(c, node);
        const rhs = try macro_int_from_bool(c, try parse_cbit_and_expr(c, m, scope));
        node = try Tag.bit_xor.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
    }
    m.i -= 1;
    return node;
}

fn parse_cbit_and_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_ceq_expr(c, m, scope);
    while (m.next().? == .ampersand) {
        const lhs = try macro_int_from_bool(c, node);
        const rhs = try macro_int_from_bool(c, try parse_ceq_expr(c, m, scope));
        node = try Tag.bit_and.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
    }
    m.i -= 1;
    return node;
}

fn parse_ceq_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_crel_expr(c, m, scope);
    while (true) {
        switch (m.peek().?) {
            .bang_equal => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_crel_expr(c, m, scope));
                node = try Tag.not_equal.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .equal_equal => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_crel_expr(c, m, scope));
                node = try Tag.equal.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            else => return node,
        }
    }
}

fn parse_crel_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cshift_expr(c, m, scope);
    while (true) {
        switch (m.peek().?) {
            .angle_bracket_right => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cshift_expr(c, m, scope));
                node = try Tag.greater_than.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .angle_bracket_right_equal => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cshift_expr(c, m, scope));
                node = try Tag.greater_than_equal.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .angle_bracket_left => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cshift_expr(c, m, scope));
                node = try Tag.less_than.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .angle_bracket_left_equal => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cshift_expr(c, m, scope));
                node = try Tag.less_than_equal.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            else => return node,
        }
    }
}

fn parse_cshift_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cadd_sub_expr(c, m, scope);
    while (true) {
        switch (m.peek().?) {
            .angle_bracket_angle_bracket_left => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cadd_sub_expr(c, m, scope));
                node = try Tag.shl.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .angle_bracket_angle_bracket_right => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cadd_sub_expr(c, m, scope));
                node = try Tag.shr.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            else => return node,
        }
    }
}

fn parse_cadd_sub_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_cmul_expr(c, m, scope);
    while (true) {
        switch (m.peek().?) {
            .plus => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cmul_expr(c, m, scope));
                node = try Tag.add.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .minus => {
                _ = m.next();
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_cmul_expr(c, m, scope));
                node = try Tag.sub.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            else => return node,
        }
    }
}

fn parse_cmul_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    var node = try parse_ccast_expr(c, m, scope);
    while (true) {
        switch (m.next().?) {
            .asterisk => {
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_ccast_expr(c, m, scope));
                node = try Tag.mul.create(c.arena, .{ .lhs = lhs, .rhs = rhs });
            },
            .slash => {
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_ccast_expr(c, m, scope));
                node = try Tag.macro_arithmetic.create(c.arena, .{ .op = .div, .lhs = lhs, .rhs = rhs });
            },
            .percent => {
                const lhs = try macro_int_from_bool(c, node);
                const rhs = try macro_int_from_bool(c, try parse_ccast_expr(c, m, scope));
                node = try Tag.macro_arithmetic.create(c.arena, .{ .op = .rem, .lhs = lhs, .rhs = rhs });
            },
            else => {
                m.i -= 1;
                return node;
            },
        }
    }
}

fn parse_ccast_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    switch (m.next().?) {
        .l_paren => {
            if (try parse_ctype_name(c, m, scope, true)) |type_name| {
                while (true) {
                    const next_token = m.next().?;
                    switch (next_token) {
                        .r_paren => break,
                        else => |next_tag| {
                            // Skip trailing blank defined before the RParen.
                            if ((next_tag == .identifier or next_tag == .extended_identifier) and
                                c.global_scope.blank_macros.contains(m.slice()))
                                continue;

                            try m.fail(
                                c,
                                "unable to translate C expr: expected ')' instead got '{s}'",
                                .{next_token.symbol()},
                            );
                            return error.ParseError;
                        },
                    }
                }
                if (m.peek().? == .l_brace) {
                    // initializer list
                    return parse_cpostfix_expr(c, m, scope, type_name);
                }
                const node_to_cast = try parse_ccast_expr(c, m, scope);
                return Tag.helpers_cast.create(c.arena, .{ .lhs = type_name, .rhs = node_to_cast });
            }
        },
        else => {},
    }
    m.i -= 1;
    return parse_cunary_expr(c, m, scope);
}

// allow_fail is set when unsure if we are parsing a type-name
fn parse_ctype_name(c: *Context, m: *MacroCtx, scope: *Scope, allow_fail: bool) ParseError!?Node {
    if (try parse_cspecifier_qualifier_list(c, m, scope, allow_fail)) |node| {
        return try parse_cabstract_declarator(c, m, node);
    } else {
        return null;
    }
}

fn parse_cspecifier_qualifier_list(c: *Context, m: *MacroCtx, scope: *Scope, allow_fail: bool) ParseError!?Node {
    const tok = m.next().?;
    switch (tok) {
        .identifier, .extended_identifier => {
            if (c.global_scope.blank_macros.contains(m.slice())) {
                return try parse_cspecifier_qualifier_list(c, m, scope, allow_fail);
            }
            const mangled_name = scope.get_alias(m.slice());
            if (!allow_fail or c.typedefs.contains(mangled_name)) {
                if (builtin_typedef_map.get(mangled_name)) |ty| return try Tag.type.create(c.arena, ty);
                return try Tag.identifier.create(c.arena, mangled_name);
            }
        },
        .keyword_void => return try Tag.type.create(c.arena, "anyopaque"),
        .keyword_bool => return try Tag.type.create(c.arena, "bool"),
        .keyword_char,
        .keyword_int,
        .keyword_short,
        .keyword_long,
        .keyword_float,
        .keyword_double,
        .keyword_signed,
        .keyword_unsigned,
        .keyword_complex,
        => {
            m.i -= 1;
            return try parse_cnumeric_type(c, m);
        },
        .keyword_enum, .keyword_struct, .keyword_union => {
            // struct Foo will be declared as struct_Foo by trans_record_decl
            const slice = m.slice();
            try m.skip(c, .identifier);

            const name = try std.fmt.alloc_print(c.arena, "{s}_{s}", .{ slice, m.slice() });
            return try Tag.identifier.create(c.arena, name);
        },
        else => {},
    }

    if (allow_fail) {
        m.i -= 1;
        return null;
    } else {
        try m.fail(c, "unable to translate C expr: unexpected token '{s}'", .{tok.symbol()});
        return error.ParseError;
    }
}

fn parse_cnumeric_type(c: *Context, m: *MacroCtx) ParseError!Node {
    const KwCounter = struct {
        double: u8 = 0,
        long: u8 = 0,
        int: u8 = 0,
        float: u8 = 0,
        short: u8 = 0,
        char: u8 = 0,
        unsigned: u8 = 0,
        signed: u8 = 0,
        complex: u8 = 0,

        fn eql(self: @This(), other: @This()) bool {
            return meta.eql(self, other);
        }
    };

    // Yes, these can be in *any* order
    // This still doesn't cover cases where for example volatile is intermixed

    var kw = KwCounter{};
    // prevent overflow
    var i: u8 = 0;
    while (i < math.max_int(u8)) : (i += 1) {
        switch (m.next().?) {
            .keyword_double => kw.double += 1,
            .keyword_long => kw.long += 1,
            .keyword_int => kw.int += 1,
            .keyword_float => kw.float += 1,
            .keyword_short => kw.short += 1,
            .keyword_char => kw.char += 1,
            .keyword_unsigned => kw.unsigned += 1,
            .keyword_signed => kw.signed += 1,
            .keyword_complex => kw.complex += 1,
            else => {
                m.i -= 1;
                break;
            },
        }
    }

    if (kw.eql(.{ .int = 1 }) or kw.eql(.{ .signed = 1 }) or kw.eql(.{ .signed = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_int");

    if (kw.eql(.{ .unsigned = 1 }) or kw.eql(.{ .unsigned = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_uint");

    if (kw.eql(.{ .long = 1 }) or kw.eql(.{ .signed = 1, .long = 1 }) or kw.eql(.{ .long = 1, .int = 1 }) or kw.eql(.{ .signed = 1, .long = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_long");

    if (kw.eql(.{ .unsigned = 1, .long = 1 }) or kw.eql(.{ .unsigned = 1, .long = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_ulong");

    if (kw.eql(.{ .long = 2 }) or kw.eql(.{ .signed = 1, .long = 2 }) or kw.eql(.{ .long = 2, .int = 1 }) or kw.eql(.{ .signed = 1, .long = 2, .int = 1 }))
        return Tag.type.create(c.arena, "c_longlong");

    if (kw.eql(.{ .unsigned = 1, .long = 2 }) or kw.eql(.{ .unsigned = 1, .long = 2, .int = 1 }))
        return Tag.type.create(c.arena, "c_ulonglong");

    if (kw.eql(.{ .signed = 1, .char = 1 }))
        return Tag.type.create(c.arena, "i8");

    if (kw.eql(.{ .char = 1 }) or kw.eql(.{ .unsigned = 1, .char = 1 }))
        return Tag.type.create(c.arena, "u8");

    if (kw.eql(.{ .short = 1 }) or kw.eql(.{ .signed = 1, .short = 1 }) or kw.eql(.{ .short = 1, .int = 1 }) or kw.eql(.{ .signed = 1, .short = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_short");

    if (kw.eql(.{ .unsigned = 1, .short = 1 }) or kw.eql(.{ .unsigned = 1, .short = 1, .int = 1 }))
        return Tag.type.create(c.arena, "c_ushort");

    if (kw.eql(.{ .float = 1 }))
        return Tag.type.create(c.arena, "f32");

    if (kw.eql(.{ .double = 1 }))
        return Tag.type.create(c.arena, "f64");

    if (kw.eql(.{ .long = 1, .double = 1 })) {
        try m.fail(c, "unable to translate: TODO long double", .{});
        return error.ParseError;
    }

    if (kw.eql(.{ .float = 1, .complex = 1 })) {
        try m.fail(c, "unable to translate: TODO _Complex", .{});
        return error.ParseError;
    }

    if (kw.eql(.{ .double = 1, .complex = 1 })) {
        try m.fail(c, "unable to translate: TODO _Complex", .{});
        return error.ParseError;
    }

    if (kw.eql(.{ .long = 1, .double = 1, .complex = 1 })) {
        try m.fail(c, "unable to translate: TODO _Complex", .{});
        return error.ParseError;
    }

    try m.fail(c, "unable to translate: invalid numeric type", .{});
    return error.ParseError;
}

fn parse_cabstract_declarator(c: *Context, m: *MacroCtx, node: Node) ParseError!Node {
    switch (m.next().?) {
        .asterisk => {
            // last token of `node`
            const prev_id = m.list[m.i - 1].id;

            if (prev_id == .keyword_void) {
                const ptr = try Tag.single_pointer.create(c.arena, .{
                    .is_const = false,
                    .is_volatile = false,
                    .elem_type = node,
                });
                return Tag.optional_type.create(c.arena, ptr);
            } else {
                return Tag.c_pointer.create(c.arena, .{
                    .is_const = false,
                    .is_volatile = false,
                    .elem_type = node,
                });
            }
        },
        else => {
            m.i -= 1;
            return node;
        },
    }
}

fn parse_cpostfix_expr(c: *Context, m: *MacroCtx, scope: *Scope, type_name: ?Node) ParseError!Node {
    var node = try parse_cpostfix_expr_inner(c, m, scope, type_name);
    // In C the preprocessor would handle concatting strings while expanding macros.
    // This should do approximately the same by concatting any strings and identifiers
    // after a primary or postfix expression.
    while (true) {
        switch (m.peek().?) {
            .string_literal,
            .string_literal_utf_16,
            .string_literal_utf_8,
            .string_literal_utf_32,
            .string_literal_wide,
            => {},
            .identifier, .extended_identifier => {
                const tok = m.list[m.i + 1];
                const slice = m.source[tok.start..tok.end];
                if (c.global_scope.blank_macros.contains(slice)) {
                    m.i += 1;
                    continue;
                }
            },
            else => break,
        }
        const rhs = try parse_cpostfix_expr_inner(c, m, scope, type_name);
        node = try Tag.array_cat.create(c.arena, .{ .lhs = node, .rhs = rhs });
    }
    return node;
}

fn parse_cpostfix_expr_inner(c: *Context, m: *MacroCtx, scope: *Scope, type_name: ?Node) ParseError!Node {
    var node = type_name orelse try parse_cprimary_expr(c, m, scope);
    while (true) {
        switch (m.next().?) {
            .period => {
                try m.skip(c, .identifier);

                node = try Tag.field_access.create(c.arena, .{ .lhs = node, .field_name = m.slice() });
            },
            .arrow => {
                try m.skip(c, .identifier);

                const deref = try Tag.deref.create(c.arena, node);
                node = try Tag.field_access.create(c.arena, .{ .lhs = deref, .field_name = m.slice() });
            },
            .l_bracket => {
                const index_val = try macro_int_from_bool(c, try parse_cexpr(c, m, scope));
                const index = try Tag.as.create(c.arena, .{
                    .lhs = try Tag.type.create(c.arena, "usize"),
                    .rhs = try Tag.int_cast.create(c.arena, index_val),
                });
                node = try Tag.array_access.create(c.arena, .{ .lhs = node, .rhs = index });
                try m.skip(c, .r_bracket);
            },
            .l_paren => {
                if (m.peek().? == .r_paren) {
                    m.i += 1;
                    node = try Tag.call.create(c.arena, .{ .lhs = node, .args = &[0]Node{} });
                } else {
                    var args = std.ArrayList(Node).init(c.gpa);
                    defer args.deinit();
                    while (true) {
                        const arg = try parse_ccond_expr(c, m, scope);
                        try args.append(arg);
                        const next_id = m.next().?;
                        switch (next_id) {
                            .comma => {},
                            .r_paren => break,
                            else => {
                                try m.fail(c, "unable to translate C expr: expected ',' or ')' instead got '{s}'", .{next_id.symbol()});
                                return error.ParseError;
                            },
                        }
                    }
                    node = try Tag.call.create(c.arena, .{ .lhs = node, .args = try c.arena.dupe(Node, args.items) });
                }
            },
            .l_brace => {
                // Check for designated field initializers
                if (m.peek().? == .period) {
                    var init_vals = std.ArrayList(ast.Payload.ContainerInitDot.Initializer).init(c.gpa);
                    defer init_vals.deinit();

                    while (true) {
                        try m.skip(c, .period);
                        try m.skip(c, .identifier);
                        const name = m.slice();
                        try m.skip(c, .equal);

                        const val = try parse_ccond_expr(c, m, scope);
                        try init_vals.append(.{ .name = name, .value = val });
                        const next_id = m.next().?;
                        switch (next_id) {
                            .comma => {},
                            .r_brace => break,
                            else => {
                                try m.fail(c, "unable to translate C expr: expected ',' or '}}' instead got '{s}'", .{next_id.symbol()});
                                return error.ParseError;
                            },
                        }
                    }
                    const tuple_node = try Tag.container_init_dot.create(c.arena, try c.arena.dupe(ast.Payload.ContainerInitDot.Initializer, init_vals.items));
                    node = try Tag.std_mem_zeroinit.create(c.arena, .{ .lhs = node, .rhs = tuple_node });
                    continue;
                }

                var init_vals = std.ArrayList(Node).init(c.gpa);
                defer init_vals.deinit();

                while (true) {
                    const val = try parse_ccond_expr(c, m, scope);
                    try init_vals.append(val);
                    const next_id = m.next().?;
                    switch (next_id) {
                        .comma => {},
                        .r_brace => break,
                        else => {
                            try m.fail(c, "unable to translate C expr: expected ',' or '}}' instead got '{s}'", .{next_id.symbol()});
                            return error.ParseError;
                        },
                    }
                }
                const tuple_node = try Tag.tuple.create(c.arena, try c.arena.dupe(Node, init_vals.items));
                node = try Tag.std_mem_zeroinit.create(c.arena, .{ .lhs = node, .rhs = tuple_node });
            },
            .plus_plus, .minus_minus => {
                try m.fail(c, "TODO postfix inc/dec expr", .{});
                return error.ParseError;
            },
            else => {
                m.i -= 1;
                return node;
            },
        }
    }
}

fn parse_cunary_expr(c: *Context, m: *MacroCtx, scope: *Scope) ParseError!Node {
    switch (m.next().?) {
        .bang => {
            const operand = try macro_int_to_bool(c, try parse_ccast_expr(c, m, scope));
            return Tag.not.create(c.arena, operand);
        },
        .minus => {
            const operand = try macro_int_from_bool(c, try parse_ccast_expr(c, m, scope));
            return Tag.negate.create(c.arena, operand);
        },
        .plus => return try parse_ccast_expr(c, m, scope),
        .tilde => {
            const operand = try macro_int_from_bool(c, try parse_ccast_expr(c, m, scope));
            return Tag.bit_not.create(c.arena, operand);
        },
        .asterisk => {
            const operand = try parse_ccast_expr(c, m, scope);
            return Tag.deref.create(c.arena, operand);
        },
        .ampersand => {
            const operand = try parse_ccast_expr(c, m, scope);
            return Tag.address_of.create(c.arena, operand);
        },
        .keyword_sizeof => {
            const operand = if (m.peek().? == .l_paren) blk: {
                _ = m.next();
                const inner = (try parse_ctype_name(c, m, scope, false)).?;
                try m.skip(c, .r_paren);
                break :blk inner;
            } else try parse_cunary_expr(c, m, scope);

            return Tag.helpers_sizeof.create(c.arena, operand);
        },
        .keyword_alignof => {
            // TODO this won't work if using <stdalign.h>'s
            // #define alignof _Alignof
            try m.skip(c, .l_paren);
            const operand = (try parse_ctype_name(c, m, scope, false)).?;
            try m.skip(c, .r_paren);

            return Tag.alignof.create(c.arena, operand);
        },
        .plus_plus, .minus_minus => {
            try m.fail(c, "TODO unary inc/dec expr", .{});
            return error.ParseError;
        },
        else => {
            m.i -= 1;
            return try parse_cpostfix_expr(c, m, scope, null);
        },
    }
}

fn get_container(c: *Context, node: Node) ?Node {
    switch (node.tag()) {
        .@"union",
        .@"struct",
        .address_of,
        .bit_not,
        .not,
        .optional_type,
        .negate,
        .negate_wrap,
        .array_type,
        .c_pointer,
        .single_pointer,
        => return node,

        .identifier => {
            const ident = node.cast_tag(.identifier).?;
            if (c.global_scope.sym_table.get(ident.data)) |value| {
                if (value.cast_tag(.var_decl)) |var_decl|
                    return get_container(c, var_decl.data.init.?);
                if (value.cast_tag(.var_simple) orelse value.cast_tag(.pub_var_simple)) |var_decl|
                    return get_container(c, var_decl.data.init);
            }
        },

        .field_access => {
            const field_access = node.cast_tag(.field_access).?;

            if (get_container_type_of(c, field_access.data.lhs)) |ty_node| {
                if (ty_node.cast_tag(.@"struct") orelse ty_node.cast_tag(.@"union")) |container| {
                    for (container.data.fields) |field| {
                        if (mem.eql(u8, field.name, field_access.data.field_name)) {
                            return get_container(c, field.type);
                        }
                    }
                }
            }
        },

        else => {},
    }
    return null;
}

fn get_container_type_of(c: *Context, ref: Node) ?Node {
    if (ref.cast_tag(.identifier)) |ident| {
        if (c.global_scope.sym_table.get(ident.data)) |value| {
            if (value.cast_tag(.var_decl)) |var_decl| {
                return get_container(c, var_decl.data.type);
            }
        }
    } else if (ref.cast_tag(.field_access)) |field_access| {
        if (get_container_type_of(c, field_access.data.lhs)) |ty_node| {
            if (ty_node.cast_tag(.@"struct") orelse ty_node.cast_tag(.@"union")) |container| {
                for (container.data.fields) |field| {
                    if (mem.eql(u8, field.name, field_access.data.field_name)) {
                        return get_container(c, field.type);
                    }
                }
            } else return ty_node;
        }
    }
    return null;
}

fn get_fn_proto(c: *Context, ref: Node) ?*ast.Payload.Func {
    const init = if (ref.cast_tag(.var_decl)) |v|
        v.data.init orelse return null
    else if (ref.cast_tag(.var_simple) orelse ref.cast_tag(.pub_var_simple)) |v|
        v.data.init
    else
        return null;
    if (get_container_type_of(c, init)) |ty_node| {
        if (ty_node.cast_tag(.optional_type)) |prefix| {
            if (prefix.data.cast_tag(.single_pointer)) |sp| {
                if (sp.data.elem_type.cast_tag(.func)) |fn_proto| {
                    return fn_proto;
                }
            }
        }
    }
    return null;
}
