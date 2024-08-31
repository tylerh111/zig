//! Ingests an AST and produces ZIR code.
const AstGen = @This();

const std = @import("std");
const Ast = std.zig.Ast;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;

const is_primitive = std.zig.primitives.is_primitive;

const Zir = std.zig.Zir;
const BuiltinFn = std.zig.BuiltinFn;
const AstRlAnnotate = std.zig.AstRlAnnotate;

gpa: Allocator,
tree: *const Ast,
/// The set of nodes which, given the choice, must expose a result pointer to
/// sub-expressions. See `AstRlAnnotate` for details.
nodes_need_rl: *const AstRlAnnotate.RlNeededSet,
instructions: std.MultiArrayList(Zir.Inst) = .{},
extra: ArrayListUnmanaged(u32) = .{},
string_bytes: ArrayListUnmanaged(u8) = .{},
/// Tracks the current byte offset within the source file.
/// Used to populate line deltas in the ZIR. AstGen maintains
/// this "cursor" throughout the entire AST lowering process in order
/// to avoid starting over the line/column scan for every declaration, which
/// would be O(N^2).
source_offset: u32 = 0,
/// Tracks the corresponding line of `source_offset`.
/// This value is absolute.
source_line: u32 = 0,
/// Tracks the corresponding column of `source_offset`.
/// This value is absolute.
source_column: u32 = 0,
/// Used for temporary allocations; freed after AstGen is complete.
/// The resulting ZIR code has no references to anything in this arena.
arena: Allocator,
string_table: std.HashMapUnmanaged(u32, void, StringIndexContext, std.hash_map.default_max_load_percentage) = .{},
compile_errors: ArrayListUnmanaged(Zir.Inst.CompileErrors.Item) = .{},
/// The topmost block of the current function.
fn_block: ?*GenZir = null,
fn_var_args: bool = false,
/// Whether we are somewhere within a function. If `true`, any container decls may be
/// generic and thus must be tunneled through closure.
within_fn: bool = false,
/// The return type of the current function. This may be a trivial `Ref`, or
/// otherwise it refers to a `ret_type` instruction.
fn_ret_ty: Zir.Inst.Ref = .none,
/// Maps string table indexes to the first `@import` ZIR instruction
/// that uses this string as the operand.
imports: std.AutoArrayHashMapUnmanaged(Zir.NullTerminatedString, Ast.TokenIndex) = .{},
/// Used for temporary storage when building payloads.
scratch: std.ArrayListUnmanaged(u32) = .{},
/// Whenever a `ref` instruction is needed, it is created and saved in this
/// table instead of being immediately appended to the current block body.
/// Then, when the instruction is being added to the parent block (typically from
/// set_block_body), if it has a ref_table entry, then the ref instruction is added
/// there. This makes sure two properties are upheld:
/// 1. All pointers to the same locals return the same address. This is required
///    to be compliant with the language specification.
/// 2. `ref` instructions will dominate their uses. This is a required property
///    of ZIR.
/// The key is the ref operand; the value is the ref instruction.
ref_table: std.AutoHashMapUnmanaged(Zir.Inst.Index, Zir.Inst.Index) = .{},

const InnerError = error{ OutOfMemory, AnalysisFail };

fn add_extra(astgen: *AstGen, extra: anytype) Allocator.Error!u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    try astgen.extra.ensure_unused_capacity(astgen.gpa, fields.len);
    return add_extra_assume_capacity(astgen, extra);
}

fn add_extra_assume_capacity(astgen: *AstGen, extra: anytype) u32 {
    const fields = std.meta.fields(@TypeOf(extra));
    const extra_index: u32 = @int_cast(astgen.extra.items.len);
    astgen.extra.items.len += fields.len;
    set_extra(astgen, extra_index, extra);
    return extra_index;
}

fn set_extra(astgen: *AstGen, index: usize, extra: anytype) void {
    const fields = std.meta.fields(@TypeOf(extra));
    var i = index;
    inline for (fields) |field| {
        astgen.extra.items[i] = switch (field.type) {
            u32 => @field(extra, field.name),

            Zir.Inst.Ref,
            Zir.Inst.Index,
            Zir.Inst.Declaration.Name,
            Zir.NullTerminatedString,
            => @int_from_enum(@field(extra, field.name)),

            i32,
            Zir.Inst.Call.Flags,
            Zir.Inst.BuiltinCall.Flags,
            Zir.Inst.SwitchBlock.Bits,
            Zir.Inst.SwitchBlockErrUnion.Bits,
            Zir.Inst.FuncFancy.Bits,
            Zir.Inst.Declaration.Flags,
            => @bit_cast(@field(extra, field.name)),

            else => @compile_error("bad field type"),
        };
        i += 1;
    }
}

fn reserve_extra(astgen: *AstGen, size: usize) Allocator.Error!u32 {
    const extra_index: u32 = @int_cast(astgen.extra.items.len);
    try astgen.extra.resize(astgen.gpa, extra_index + size);
    return extra_index;
}

fn append_refs(astgen: *AstGen, refs: []const Zir.Inst.Ref) !void {
    return astgen.extra.append_slice(astgen.gpa, @ptr_cast(refs));
}

fn append_refs_assume_capacity(astgen: *AstGen, refs: []const Zir.Inst.Ref) void {
    astgen.extra.append_slice_assume_capacity(@ptr_cast(refs));
}

pub fn generate(gpa: Allocator, tree: Ast) Allocator.Error!Zir {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    var nodes_need_rl = try AstRlAnnotate.annotate(gpa, arena.allocator(), tree);
    defer nodes_need_rl.deinit(gpa);

    var astgen: AstGen = .{
        .gpa = gpa,
        .arena = arena.allocator(),
        .tree = &tree,
        .nodes_need_rl = &nodes_need_rl,
    };
    defer astgen.deinit(gpa);

    // String table index 0 is reserved for `NullTerminatedString.empty`.
    try astgen.string_bytes.append(gpa, 0);

    // We expect at least as many ZIR instructions and extra data items
    // as AST nodes.
    try astgen.instructions.ensure_total_capacity(gpa, tree.nodes.len);

    // First few indexes of extra are reserved and set at the end.
    const reserved_count = @typeInfo(Zir.ExtraIndex).Enum.fields.len;
    try astgen.extra.ensure_total_capacity(gpa, tree.nodes.len + reserved_count);
    astgen.extra.items.len += reserved_count;

    var top_scope: Scope.Top = .{};

    var gz_instructions: std.ArrayListUnmanaged(Zir.Inst.Index) = .{};
    var gen_scope: GenZir = .{
        .is_comptime = true,
        .parent = &top_scope.base,
        .anon_name_strategy = .parent,
        .decl_node_index = 0,
        .decl_line = 0,
        .astgen = &astgen,
        .instructions = &gz_instructions,
        .instructions_top = 0,
    };
    defer gz_instructions.deinit(gpa);

    // The AST -> ZIR lowering process assumes an AST that does not have any
    // parse errors.
    if (tree.errors.len == 0) {
        if (AstGen.struct_decl_inner(
            &gen_scope,
            &gen_scope.base,
            0,
            tree.container_decl_root(),
            .auto,
            0,
        )) |struct_decl_ref| {
            assert(struct_decl_ref.to_index().? == .main_struct_inst);
        } else |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AnalysisFail => {}, // Handled via compile_errors below.
        }
    } else {
        try lower_ast_errors(&astgen);
    }

    const err_index = @int_from_enum(Zir.ExtraIndex.compile_errors);
    if (astgen.compile_errors.items.len == 0) {
        astgen.extra.items[err_index] = 0;
    } else {
        try astgen.extra.ensure_unused_capacity(gpa, 1 + astgen.compile_errors.items.len *
            @typeInfo(Zir.Inst.CompileErrors.Item).Struct.fields.len);

        astgen.extra.items[err_index] = astgen.add_extra_assume_capacity(Zir.Inst.CompileErrors{
            .items_len = @int_cast(astgen.compile_errors.items.len),
        });

        for (astgen.compile_errors.items) |item| {
            _ = astgen.add_extra_assume_capacity(item);
        }
    }

    const imports_index = @int_from_enum(Zir.ExtraIndex.imports);
    if (astgen.imports.count() == 0) {
        astgen.extra.items[imports_index] = 0;
    } else {
        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.Imports).Struct.fields.len +
            astgen.imports.count() * @typeInfo(Zir.Inst.Imports.Item).Struct.fields.len);

        astgen.extra.items[imports_index] = astgen.add_extra_assume_capacity(Zir.Inst.Imports{
            .imports_len = @int_cast(astgen.imports.count()),
        });

        var it = astgen.imports.iterator();
        while (it.next()) |entry| {
            _ = astgen.add_extra_assume_capacity(Zir.Inst.Imports.Item{
                .name = entry.key_ptr.*,
                .token = entry.value_ptr.*,
            });
        }
    }

    return Zir{
        .instructions = astgen.instructions.to_owned_slice(),
        .string_bytes = try astgen.string_bytes.to_owned_slice(gpa),
        .extra = try astgen.extra.to_owned_slice(gpa),
    };
}

fn deinit(astgen: *AstGen, gpa: Allocator) void {
    astgen.instructions.deinit(gpa);
    astgen.extra.deinit(gpa);
    astgen.string_table.deinit(gpa);
    astgen.string_bytes.deinit(gpa);
    astgen.compile_errors.deinit(gpa);
    astgen.imports.deinit(gpa);
    astgen.scratch.deinit(gpa);
    astgen.ref_table.deinit(gpa);
}

const ResultInfo = struct {
    /// The semantics requested for the result location
    rl: Loc,

    /// The "operator" consuming the result location
    ctx: Context = .none,

    /// Turns a `coerced_ty` back into a `ty`. Should be called at branch points
    /// such as if and switch expressions.
    fn br(ri: ResultInfo) ResultInfo {
        return switch (ri.rl) {
            .coerced_ty => |ty| .{
                .rl = .{ .ty = ty },
                .ctx = ri.ctx,
            },
            else => ri,
        };
    }

    fn zir_tag(ri: ResultInfo) Zir.Inst.Tag {
        switch (ri.rl) {
            .ty => return switch (ri.ctx) {
                .shift_op => .as_shift_operand,
                else => .as_node,
            },
            else => unreachable,
        }
    }

    const Loc = union(enum) {
        /// The expression is the right-hand side of assignment to `_`. Only the side-effects of the
        /// expression should be generated. The result instruction from the expression must
        /// be ignored.
        discard,
        /// The expression has an inferred type, and it will be evaluated as an rvalue.
        none,
        /// The expression will be coerced into this type, but it will be evaluated as an rvalue.
        ty: Zir.Inst.Ref,
        /// Same as `ty` but it is guaranteed that Sema will additionally perform the coercion,
        /// so no `as` instruction needs to be emitted.
        coerced_ty: Zir.Inst.Ref,
        /// The expression must generate a pointer rather than a value. For example, the left hand side
        /// of an assignment uses this kind of result location.
        ref,
        /// The expression must generate a pointer rather than a value, and the pointer will be coerced
        /// by other code to this type, which is guaranteed by earlier instructions to be a pointer type.
        ref_coerced_ty: Zir.Inst.Ref,
        /// The expression must store its result into this typed pointer. The result instruction
        /// from the expression must be ignored.
        ptr: PtrResultLoc,
        /// The expression must store its result into this allocation, which has an inferred type.
        /// The result instruction from the expression must be ignored.
        /// Always an instruction with tag `alloc_inferred`.
        inferred_ptr: Zir.Inst.Ref,
        /// The expression has a sequence of pointers to store its results into due to a destructure
        /// operation. Each of these pointers may or may not have an inferred type.
        destructure: struct {
            /// The AST node of the destructure operation itself.
            src_node: Ast.Node.Index,
            /// The pointers to store results into.
            components: []const DestructureComponent,
        },

        const DestructureComponent = union(enum) {
            typed_ptr: PtrResultLoc,
            inferred_ptr: Zir.Inst.Ref,
            discard,
        };

        const PtrResultLoc = struct {
            inst: Zir.Inst.Ref,
            src_node: ?Ast.Node.Index = null,
        };

        /// Find the result type for a cast builtin given the result location.
        /// If the location does not have a known result type, returns `null`.
        fn result_type(rl: Loc, gz: *GenZir, node: Ast.Node.Index) !?Zir.Inst.Ref {
            return switch (rl) {
                .discard, .none, .ref, .inferred_ptr, .destructure => null,
                .ty, .coerced_ty => |ty_ref| ty_ref,
                .ref_coerced_ty => |ptr_ty| try gz.add_un_node(.elem_type, ptr_ty, node),
                .ptr => |ptr| {
                    const ptr_ty = try gz.add_un_node(.typeof, ptr.inst, node);
                    return try gz.add_un_node(.elem_type, ptr_ty, node);
                },
            };
        }

        /// Find the result type for a cast builtin given the result location.
        /// If the location does not have a known result type, emits an error on
        /// the given node.
        fn result_type_for_cast(rl: Loc, gz: *GenZir, node: Ast.Node.Index, builtin_name: []const u8) !Zir.Inst.Ref {
            const astgen = gz.astgen;
            if (try rl.result_type(gz, node)) |ty| return ty;
            switch (rl) {
                .destructure => |destructure| return astgen.fail_node_notes(node, "{s} must have a known result type", .{builtin_name}, &.{
                    try astgen.err_note_node(destructure.src_node, "destructure expressions do not provide a single result type", .{}),
                    try astgen.err_note_node(node, "use @as to provide explicit result type", .{}),
                }),
                else => return astgen.fail_node_notes(node, "{s} must have a known result type", .{builtin_name}, &.{
                    try astgen.err_note_node(node, "use @as to provide explicit result type", .{}),
                }),
            }
        }
    };

    const Context = enum {
        /// The expression is the operand to a return expression.
        @"return",
        /// The expression is the input to an error-handling operator (if-else, try, or catch).
        error_handling_expr,
        /// The expression is the right-hand side of a shift operation.
        shift_op,
        /// The expression is an argument in a function call.
        fn_arg,
        /// The expression is the right-hand side of an initializer for a `const` variable
        const_init,
        /// The expression is the right-hand side of an assignment expression.
        assignment,
        /// No specific operator in particular.
        none,
    };
};

const coerced_align_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .u29_type } };
const coerced_addrspace_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .address_space_type } };
const coerced_linksection_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .slice_const_u8_type } };
const coerced_type_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .type_type } };
const coerced_bool_ri: ResultInfo = .{ .rl = .{ .coerced_ty = .bool_type } };

fn type_expr(gz: *GenZir, scope: *Scope, type_node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    return comptime_expr(gz, scope, coerced_type_ri, type_node);
}

fn reachable_type_expr(
    gz: *GenZir,
    scope: *Scope,
    type_node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return reachable_expr_comptime(gz, scope, coerced_type_ri, type_node, reachable_node, true);
}

/// Same as `expr` but fails with a compile error if the result type is `noreturn`.
fn reachable_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return reachable_expr_comptime(gz, scope, ri, node, reachable_node, false);
}

fn reachable_expr_comptime(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    reachable_node: Ast.Node.Index,
    force_comptime: bool,
) InnerError!Zir.Inst.Ref {
    const result_inst = if (force_comptime)
        try comptime_expr(gz, scope, ri, node)
    else
        try expr(gz, scope, ri, node);

    if (gz.ref_is_no_return(result_inst)) {
        try gz.astgen.append_error_node_notes(reachable_node, "unreachable code", .{}, &[_]u32{
            try gz.astgen.err_note_node(node, "control flow is diverted here", .{}),
        });
    }
    return result_inst;
}

fn lval_expr(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    switch (node_tags[node]) {
        .root => unreachable,
        .@"usingnamespace" => unreachable,
        .test_decl => unreachable,
        .global_var_decl => unreachable,
        .local_var_decl => unreachable,
        .simple_var_decl => unreachable,
        .aligned_var_decl => unreachable,
        .switch_case => unreachable,
        .switch_case_inline => unreachable,
        .switch_case_one => unreachable,
        .switch_case_inline_one => unreachable,
        .container_field_init => unreachable,
        .container_field_align => unreachable,
        .container_field => unreachable,
        .asm_output => unreachable,
        .asm_input => unreachable,

        .assign,
        .assign_destructure,
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
        .add,
        .add_wrap,
        .add_sat,
        .sub,
        .sub_wrap,
        .sub_sat,
        .mul,
        .mul_wrap,
        .mul_sat,
        .div,
        .mod,
        .bit_and,
        .bit_or,
        .shl,
        .shl_sat,
        .shr,
        .bit_xor,
        .bang_equal,
        .equal_equal,
        .greater_than,
        .greater_or_equal,
        .less_than,
        .less_or_equal,
        .array_cat,
        .array_mult,
        .bool_and,
        .bool_or,
        .@"asm",
        .asm_simple,
        .string_literal,
        .number_literal,
        .call,
        .call_comma,
        .async_call,
        .async_call_comma,
        .call_one,
        .call_one_comma,
        .async_call_one,
        .async_call_one_comma,
        .unreachable_literal,
        .@"return",
        .@"if",
        .if_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .bool_not,
        .address_of,
        .optional_type,
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        .@"break",
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .array_type,
        .array_type_sentinel,
        .enum_literal,
        .multiline_string_literal,
        .char_literal,
        .@"defer",
        .@"errdefer",
        .@"catch",
        .error_union,
        .merge_error_sets,
        .switch_range,
        .for_range,
        .@"await",
        .bit_not,
        .negation,
        .negation_wrap,
        .@"resume",
        .@"try",
        .slice,
        .slice_open,
        .slice_sentinel,
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        .@"switch",
        .switch_comma,
        .@"for",
        .for_simple,
        .@"suspend",
        .@"continue",
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        .fn_decl,
        .anyframe_type,
        .anyframe_literal,
        .error_set_decl,
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .@"comptime",
        .@"nosuspend",
        .error_value,
        => return astgen.fail_node(node, "invalid left-hand side to assignment", .{}),

        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const builtin_token = main_tokens[node];
            const builtin_name = tree.token_slice(builtin_token);
            // If the builtin is an invalid name, we don't cause an error here; instead
            // let it pass, and the error will be "invalid builtin function" later.
            if (BuiltinFn.list.get(builtin_name)) |info| {
                if (!info.allows_lvalue) {
                    return astgen.fail_node(node, "invalid left-hand side to assignment", .{});
                }
            }
        },

        // These can be assigned to.
        .unwrap_optional,
        .deref,
        .field_access,
        .array_access,
        .identifier,
        .grouped_expression,
        .@"orelse",
        => {},
    }
    return expr(gz, scope, .{ .rl = .ref }, node);
}

/// Turn Zig AST into untyped ZIR instructions.
/// When `rl` is discard, ptr, inferred_ptr, or inferred_ptr, the
/// result instruction can be used to inspect whether it is is_no_return() but that is it,
/// it must otherwise not be used.
fn expr(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);

    const prev_anon_name_strategy = gz.anon_name_strategy;
    defer gz.anon_name_strategy = prev_anon_name_strategy;
    if (!node_uses_anon_name_strategy(tree, node)) {
        gz.anon_name_strategy = .anon;
    }

    switch (node_tags[node]) {
        .root => unreachable, // Top-level declaration.
        .@"usingnamespace" => unreachable, // Top-level declaration.
        .test_decl => unreachable, // Top-level declaration.
        .container_field_init => unreachable, // Top-level declaration.
        .container_field_align => unreachable, // Top-level declaration.
        .container_field => unreachable, // Top-level declaration.
        .fn_decl => unreachable, // Top-level declaration.

        .global_var_decl => unreachable, // Handled in `block_expr`.
        .local_var_decl => unreachable, // Handled in `block_expr`.
        .simple_var_decl => unreachable, // Handled in `block_expr`.
        .aligned_var_decl => unreachable, // Handled in `block_expr`.
        .@"defer" => unreachable, // Handled in `block_expr`.
        .@"errdefer" => unreachable, // Handled in `block_expr`.

        .switch_case => unreachable, // Handled in `switch_expr`.
        .switch_case_inline => unreachable, // Handled in `switch_expr`.
        .switch_case_one => unreachable, // Handled in `switch_expr`.
        .switch_case_inline_one => unreachable, // Handled in `switch_expr`.
        .switch_range => unreachable, // Handled in `switch_expr`.

        .asm_output => unreachable, // Handled in `asm_expr`.
        .asm_input => unreachable, // Handled in `asm_expr`.

        .for_range => unreachable, // Handled in `for_expr`.

        .assign => {
            try assign(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_destructure => {
            // Note that this variant does not declare any new var/const: that
            // variant is handled by `block_expr_stmts`.
            try assign_destructure(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_shl => {
            try assign_shift(gz, scope, node, .shl);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_shl_sat => {
            try assign_shift_sat(gz, scope, node);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_shr => {
            try assign_shift(gz, scope, node, .shr);
            return rvalue(gz, ri, .void_value, node);
        },

        .assign_bit_and => {
            try assign_op(gz, scope, node, .bit_and);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_bit_or => {
            try assign_op(gz, scope, node, .bit_or);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_bit_xor => {
            try assign_op(gz, scope, node, .xor);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_div => {
            try assign_op(gz, scope, node, .div);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub => {
            try assign_op(gz, scope, node, .sub);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub_wrap => {
            try assign_op(gz, scope, node, .subwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_sub_sat => {
            try assign_op(gz, scope, node, .sub_sat);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mod => {
            try assign_op(gz, scope, node, .mod_rem);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add => {
            try assign_op(gz, scope, node, .add);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add_wrap => {
            try assign_op(gz, scope, node, .addwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_add_sat => {
            try assign_op(gz, scope, node, .add_sat);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul => {
            try assign_op(gz, scope, node, .mul);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul_wrap => {
            try assign_op(gz, scope, node, .mulwrap);
            return rvalue(gz, ri, .void_value, node);
        },
        .assign_mul_sat => {
            try assign_op(gz, scope, node, .mul_sat);
            return rvalue(gz, ri, .void_value, node);
        },

        // zig fmt: off
        .shl => return shift_op(gz, scope, ri, node, node_datas[node].lhs, node_datas[node].rhs, .shl),
        .shr => return shift_op(gz, scope, ri, node, node_datas[node].lhs, node_datas[node].rhs, .shr),

        .add      => return simple_bin_op(gz, scope, ri, node, .add),
        .add_wrap => return simple_bin_op(gz, scope, ri, node, .addwrap),
        .add_sat  => return simple_bin_op(gz, scope, ri, node, .add_sat),
        .sub      => return simple_bin_op(gz, scope, ri, node, .sub),
        .sub_wrap => return simple_bin_op(gz, scope, ri, node, .subwrap),
        .sub_sat  => return simple_bin_op(gz, scope, ri, node, .sub_sat),
        .mul      => return simple_bin_op(gz, scope, ri, node, .mul),
        .mul_wrap => return simple_bin_op(gz, scope, ri, node, .mulwrap),
        .mul_sat  => return simple_bin_op(gz, scope, ri, node, .mul_sat),
        .div      => return simple_bin_op(gz, scope, ri, node, .div),
        .mod      => return simple_bin_op(gz, scope, ri, node, .mod_rem),
        .shl_sat  => return simple_bin_op(gz, scope, ri, node, .shl_sat),

        .bit_and          => return simple_bin_op(gz, scope, ri, node, .bit_and),
        .bit_or           => return simple_bin_op(gz, scope, ri, node, .bit_or),
        .bit_xor          => return simple_bin_op(gz, scope, ri, node, .xor),
        .bang_equal       => return simple_bin_op(gz, scope, ri, node, .cmp_neq),
        .equal_equal      => return simple_bin_op(gz, scope, ri, node, .cmp_eq),
        .greater_than     => return simple_bin_op(gz, scope, ri, node, .cmp_gt),
        .greater_or_equal => return simple_bin_op(gz, scope, ri, node, .cmp_gte),
        .less_than        => return simple_bin_op(gz, scope, ri, node, .cmp_lt),
        .less_or_equal    => return simple_bin_op(gz, scope, ri, node, .cmp_lte),
        .array_cat        => return simple_bin_op(gz, scope, ri, node, .array_cat),

        .array_mult => {
            // This syntax form does not currently use the result type in the language specification.
            // However, the result type can be used to emit more optimal code for large multiplications by
            // having Sema perform a coercion before the multiplication operation.
            const result = try gz.add_pl_node(.array_mul, node, Zir.Inst.ArrayMul{
                .res_ty = if (try ri.rl.result_type(gz, node)) |t| t else .none,
                .lhs = try expr(gz, scope, .{ .rl = .none }, node_datas[node].lhs),
                .rhs = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[node].rhs),
            });
            return rvalue(gz, ri, result, node);
        },

        .error_union      => return simple_bin_op(gz, scope, ri, node, .error_union_type),
        .merge_error_sets => return simple_bin_op(gz, scope, ri, node, .merge_error_sets),

        .bool_and => return bool_bin_op(gz, scope, ri, node, .bool_br_and),
        .bool_or  => return bool_bin_op(gz, scope, ri, node, .bool_br_or),

        .bool_not => return simple_un_op(gz, scope, ri, node, coerced_bool_ri, node_datas[node].lhs, .bool_not),
        .bit_not  => return simple_un_op(gz, scope, ri, node, .{ .rl = .none }, node_datas[node].lhs, .bit_not),

        .negation      => return   negation(gz, scope, ri, node),
        .negation_wrap => return simple_un_op(gz, scope, ri, node, .{ .rl = .none }, node_datas[node].lhs, .negate_wrap),

        .identifier => return identifier(gz, scope, ri, node),

        .asm_simple,
        .@"asm",
        => return asm_expr(gz, scope, ri, node, tree.full_asm(node).?),

        .string_literal           => return string_literal(gz, ri, node),
        .multiline_string_literal => return multiline_string_literal(gz, ri, node),

        .number_literal => return number_literal(gz, ri, node, node, .positive),
        // zig fmt: on

        .builtin_call_two, .builtin_call_two_comma => {
            if (node_datas[node].lhs == 0) {
                const params = [_]Ast.Node.Index{};
                return builtin_call(gz, scope, ri, node, &params);
            } else if (node_datas[node].rhs == 0) {
                const params = [_]Ast.Node.Index{node_datas[node].lhs};
                return builtin_call(gz, scope, ri, node, &params);
            } else {
                const params = [_]Ast.Node.Index{ node_datas[node].lhs, node_datas[node].rhs };
                return builtin_call(gz, scope, ri, node, &params);
            }
        },
        .builtin_call, .builtin_call_comma => {
            const params = tree.extra_data[node_datas[node].lhs..node_datas[node].rhs];
            return builtin_call(gz, scope, ri, node, params);
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
            return call_expr(gz, scope, ri, node, tree.full_call(&buf, node).?);
        },

        .unreachable_literal => {
            try emit_dbg_node(gz, node);
            _ = try gz.add_as_index(.{
                .tag = .@"unreachable",
                .data = .{ .@"unreachable" = .{
                    .src_node = gz.node_index_to_relative(node),
                } },
            });
            return Zir.Inst.Ref.unreachable_value;
        },
        .@"return" => return ret(gz, scope, node),
        .field_access => return field_access(gz, scope, ri, node),

        .if_simple,
        .@"if",
        => {
            const if_full = tree.full_if(node).?;
            no_switch_on_err: {
                const error_token = if_full.error_token orelse break :no_switch_on_err;
                switch (node_tags[if_full.ast.else_expr]) {
                    .@"switch", .switch_comma => {},
                    else => break :no_switch_on_err,
                }
                const switch_operand = node_datas[if_full.ast.else_expr].lhs;
                if (node_tags[switch_operand] != .identifier) break :no_switch_on_err;
                if (!mem.eql(u8, tree.token_slice(error_token), tree.token_slice(main_tokens[switch_operand]))) break :no_switch_on_err;
                return switch_expr_err_union(gz, scope, ri.br(), node, .@"if");
            }
            return if_expr(gz, scope, ri.br(), node, if_full);
        },

        .while_simple,
        .while_cont,
        .@"while",
        => return while_expr(gz, scope, ri.br(), node, tree.full_while(node).?, false),

        .for_simple, .@"for" => return for_expr(gz, scope, ri.br(), node, tree.full_for(node).?, false),

        .slice_open => {
            const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[node].lhs);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
            const start = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[node].rhs);
            try emit_dbg_stmt(gz, cursor);
            const result = try gz.add_pl_node(.slice_start, node, Zir.Inst.SliceStart{
                .lhs = lhs,
                .start = start,
            });
            return rvalue(gz, ri, result, node);
        },
        .slice => {
            const extra = tree.extra_data(node_datas[node].rhs, Ast.Node.Slice);
            const lhs_node = node_datas[node].lhs;
            const lhs_tag = node_tags[lhs_node];
            const lhs_is_slice_sentinel = lhs_tag == .slice_sentinel;
            const lhs_is_open_slice = lhs_tag == .slice_open or
                (lhs_is_slice_sentinel and tree.extra_data(node_datas[lhs_node].rhs, Ast.Node.SliceSentinel).end == 0);
            if (lhs_is_open_slice and node_is_trivially_zero(tree, extra.start)) {
                const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[lhs_node].lhs);

                const start = if (lhs_is_slice_sentinel) start: {
                    const lhs_extra = tree.extra_data(node_datas[lhs_node].rhs, Ast.Node.SliceSentinel);
                    break :start try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, lhs_extra.start);
                } else try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[lhs_node].rhs);

                const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
                const len = if (extra.end != 0) try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.end) else .none;
                try emit_dbg_stmt(gz, cursor);
                const result = try gz.add_pl_node(.slice_length, node, Zir.Inst.SliceLength{
                    .lhs = lhs,
                    .start = start,
                    .len = len,
                    .start_src_node_offset = gz.node_index_to_relative(lhs_node),
                    .sentinel = .none,
                });
                return rvalue(gz, ri, result, node);
            }
            const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[node].lhs);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
            const start = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.start);
            const end = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.end);
            try emit_dbg_stmt(gz, cursor);
            const result = try gz.add_pl_node(.slice_end, node, Zir.Inst.SliceEnd{
                .lhs = lhs,
                .start = start,
                .end = end,
            });
            return rvalue(gz, ri, result, node);
        },
        .slice_sentinel => {
            const extra = tree.extra_data(node_datas[node].rhs, Ast.Node.SliceSentinel);
            const lhs_node = node_datas[node].lhs;
            const lhs_tag = node_tags[lhs_node];
            const lhs_is_slice_sentinel = lhs_tag == .slice_sentinel;
            const lhs_is_open_slice = lhs_tag == .slice_open or
                (lhs_is_slice_sentinel and tree.extra_data(node_datas[lhs_node].rhs, Ast.Node.SliceSentinel).end == 0);
            if (lhs_is_open_slice and node_is_trivially_zero(tree, extra.start)) {
                const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[lhs_node].lhs);

                const start = if (lhs_is_slice_sentinel) start: {
                    const lhs_extra = tree.extra_data(node_datas[lhs_node].rhs, Ast.Node.SliceSentinel);
                    break :start try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, lhs_extra.start);
                } else try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[lhs_node].rhs);

                const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
                const len = if (extra.end != 0) try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.end) else .none;
                const sentinel = try expr(gz, scope, .{ .rl = .none }, extra.sentinel);
                try emit_dbg_stmt(gz, cursor);
                const result = try gz.add_pl_node(.slice_length, node, Zir.Inst.SliceLength{
                    .lhs = lhs,
                    .start = start,
                    .len = len,
                    .start_src_node_offset = gz.node_index_to_relative(lhs_node),
                    .sentinel = sentinel,
                });
                return rvalue(gz, ri, result, node);
            }
            const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[node].lhs);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
            const start = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.start);
            const end = if (extra.end != 0) try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, extra.end) else .none;
            const sentinel = try expr(gz, scope, .{ .rl = .none }, extra.sentinel);
            try emit_dbg_stmt(gz, cursor);
            const result = try gz.add_pl_node(.slice_sentinel, node, Zir.Inst.SliceSentinel{
                .lhs = lhs,
                .start = start,
                .end = end,
                .sentinel = sentinel,
            });
            return rvalue(gz, ri, result, node);
        },

        .deref => {
            const lhs = try expr(gz, scope, .{ .rl = .none }, node_datas[node].lhs);
            _ = try gz.add_un_node(.validate_deref, lhs, node);
            switch (ri.rl) {
                .ref, .ref_coerced_ty => return lhs,
                else => {
                    const result = try gz.add_un_node(.load, lhs, node);
                    return rvalue(gz, ri, result, node);
                },
            }
        },
        .address_of => {
            const operand_rl: ResultInfo.Loc = if (try ri.rl.result_type(gz, node)) |res_ty_inst| rl: {
                _ = try gz.add_un_tok(.validate_ref_ty, res_ty_inst, tree.first_token(node));
                break :rl .{ .ref_coerced_ty = res_ty_inst };
            } else .ref;
            const result = try expr(gz, scope, .{ .rl = operand_rl }, node_datas[node].lhs);
            return rvalue(gz, ri, result, node);
        },
        .optional_type => {
            const operand = try type_expr(gz, scope, node_datas[node].lhs);
            const result = try gz.add_un_node(.optional_type, operand, node);
            return rvalue(gz, ri, result, node);
        },
        .unwrap_optional => switch (ri.rl) {
            .ref, .ref_coerced_ty => {
                const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[node].lhs);

                const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
                try emit_dbg_stmt(gz, cursor);

                return gz.add_un_node(.optional_payload_safe_ptr, lhs, node);
            },
            else => {
                const lhs = try expr(gz, scope, .{ .rl = .none }, node_datas[node].lhs);

                const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
                try emit_dbg_stmt(gz, cursor);

                return rvalue(gz, ri, try gz.add_un_node(.optional_payload_safe, lhs, node), node);
            },
        },
        .block_two, .block_two_semicolon => {
            const statements = [2]Ast.Node.Index{ node_datas[node].lhs, node_datas[node].rhs };
            if (node_datas[node].lhs == 0) {
                return block_expr(gz, scope, ri, node, statements[0..0]);
            } else if (node_datas[node].rhs == 0) {
                return block_expr(gz, scope, ri, node, statements[0..1]);
            } else {
                return block_expr(gz, scope, ri, node, statements[0..2]);
            }
        },
        .block, .block_semicolon => {
            const statements = tree.extra_data[node_datas[node].lhs..node_datas[node].rhs];
            return block_expr(gz, scope, ri, node, statements);
        },
        .enum_literal => return simple_str_tok(gz, ri, main_tokens[node], node, .enum_literal),
        .error_value => return simple_str_tok(gz, ri, node_datas[node].rhs, node, .error_value),
        // TODO restore this when implementing https://github.com/ziglang/zig/issues/6025
        // .anyframe_literal => return rvalue(gz, ri, .anyframe_type, node),
        .anyframe_literal => {
            const result = try gz.add_un_node(.anyframe_type, .void_type, node);
            return rvalue(gz, ri, result, node);
        },
        .anyframe_type => {
            const return_type = try type_expr(gz, scope, node_datas[node].rhs);
            const result = try gz.add_un_node(.anyframe_type, return_type, node);
            return rvalue(gz, ri, result, node);
        },
        .@"catch" => {
            const catch_token = main_tokens[node];
            const payload_token: ?Ast.TokenIndex = if (token_tags[catch_token + 1] == .pipe)
                catch_token + 2
            else
                null;
            no_switch_on_err: {
                const capture_token = payload_token orelse break :no_switch_on_err;
                switch (node_tags[node_datas[node].rhs]) {
                    .@"switch", .switch_comma => {},
                    else => break :no_switch_on_err,
                }
                const switch_operand = node_datas[node_datas[node].rhs].lhs;
                if (node_tags[switch_operand] != .identifier) break :no_switch_on_err;
                if (!mem.eql(u8, tree.token_slice(capture_token), tree.token_slice(main_tokens[switch_operand]))) break :no_switch_on_err;
                return switch_expr_err_union(gz, scope, ri.br(), node, .@"catch");
            }
            switch (ri.rl) {
                .ref, .ref_coerced_ty => return orelse_catch_expr(
                    gz,
                    scope,
                    ri,
                    node,
                    node_datas[node].lhs,
                    .is_non_err_ptr,
                    .err_union_payload_unsafe_ptr,
                    .err_union_code_ptr,
                    node_datas[node].rhs,
                    payload_token,
                ),
                else => return orelse_catch_expr(
                    gz,
                    scope,
                    ri,
                    node,
                    node_datas[node].lhs,
                    .is_non_err,
                    .err_union_payload_unsafe,
                    .err_union_code,
                    node_datas[node].rhs,
                    payload_token,
                ),
            }
        },
        .@"orelse" => switch (ri.rl) {
            .ref, .ref_coerced_ty => return orelse_catch_expr(
                gz,
                scope,
                ri,
                node,
                node_datas[node].lhs,
                .is_non_null_ptr,
                .optional_payload_unsafe_ptr,
                undefined,
                node_datas[node].rhs,
                null,
            ),
            else => return orelse_catch_expr(
                gz,
                scope,
                ri,
                node,
                node_datas[node].lhs,
                .is_non_null,
                .optional_payload_unsafe,
                undefined,
                node_datas[node].rhs,
                null,
            ),
        },

        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => return ptr_type(gz, scope, ri, node, tree.full_ptr_type(node).?),

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
            return container_decl(gz, scope, ri, node, tree.full_container_decl(&buf, node).?);
        },

        .@"break" => return break_expr(gz, scope, node),
        .@"continue" => return continue_expr(gz, scope, node),
        .grouped_expression => return expr(gz, scope, ri, node_datas[node].lhs),
        .array_type => return array_type(gz, scope, ri, node),
        .array_type_sentinel => return array_type_sentinel(gz, scope, ri, node),
        .char_literal => return char_literal(gz, ri, node),
        .error_set_decl => return error_set_decl(gz, ri, node),
        .array_access => return array_access(gz, scope, ri, node),
        .@"comptime" => return comptime_expr_ast(gz, scope, ri, node),
        .@"switch", .switch_comma => return switch_expr(gz, scope, ri.br(), node),

        .@"nosuspend" => return nosuspend_expr(gz, scope, ri, node),
        .@"suspend" => return suspend_expr(gz, scope, node),
        .@"await" => return await_expr(gz, scope, ri, node),
        .@"resume" => return resume_expr(gz, scope, ri, node),

        .@"try" => return try_expr(gz, scope, ri, node, node_datas[node].lhs),

        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            var buf: [2]Ast.Node.Index = undefined;
            return array_init_expr(gz, scope, ri, node, tree.full_array_init(&buf, node).?);
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
            return struct_init_expr(gz, scope, ri, node, tree.full_struct_init(&buf, node).?);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            return fn_proto_expr(gz, scope, ri, node, tree.full_fn_proto(&buf, node).?);
        },
    }
}

fn nosuspend_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const body_node = node_datas[node].lhs;
    assert(body_node != 0);
    if (gz.nosuspend_node != 0) {
        try astgen.append_error_node_notes(node, "redundant nosuspend block", .{}, &[_]u32{
            try astgen.err_note_node(gz.nosuspend_node, "other nosuspend block here", .{}),
        });
    }
    gz.nosuspend_node = node;
    defer gz.nosuspend_node = 0;
    return expr(gz, scope, ri, body_node);
}

fn suspend_expr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const body_node = node_datas[node].lhs;

    if (gz.nosuspend_node != 0) {
        return astgen.fail_node_notes(node, "suspend inside nosuspend block", .{}, &[_]u32{
            try astgen.err_note_node(gz.nosuspend_node, "nosuspend block here", .{}),
        });
    }
    if (gz.suspend_node != 0) {
        return astgen.fail_node_notes(node, "cannot suspend inside suspend block", .{}, &[_]u32{
            try astgen.err_note_node(gz.suspend_node, "other suspend block here", .{}),
        });
    }
    assert(body_node != 0);

    const suspend_inst = try gz.make_block_inst(.suspend_block, node);
    try gz.instructions.append(gpa, suspend_inst);

    var suspend_scope = gz.make_sub_block(scope);
    suspend_scope.suspend_node = node;
    defer suspend_scope.unstack();

    const body_result = try full_body_expr(&suspend_scope, &suspend_scope.base, .{ .rl = .none }, body_node);
    if (!gz.ref_is_no_return(body_result)) {
        _ = try suspend_scope.add_break(.break_inline, suspend_inst, .void_value);
    }
    try suspend_scope.set_block_body(suspend_inst);

    return suspend_inst.to_ref();
}

fn await_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const rhs_node = node_datas[node].lhs;

    if (gz.suspend_node != 0) {
        return astgen.fail_node_notes(node, "cannot await inside suspend block", .{}, &[_]u32{
            try astgen.err_note_node(gz.suspend_node, "suspend block here", .{}),
        });
    }
    const operand = try expr(gz, scope, .{ .rl = .ref }, rhs_node);
    const result = if (gz.nosuspend_node != 0)
        try gz.add_extended_payload(.await_nosuspend, Zir.Inst.UnNode{
            .node = gz.node_index_to_relative(node),
            .operand = operand,
        })
    else
        try gz.add_un_node(.@"await", operand, node);

    return rvalue(gz, ri, result, node);
}

fn resume_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const rhs_node = node_datas[node].lhs;
    const operand = try expr(gz, scope, .{ .rl = .ref }, rhs_node);
    const result = try gz.add_un_node(.@"resume", operand, node);
    return rvalue(gz, ri, result, node);
}

fn fn_proto_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    if (fn_proto.name_token) |some| {
        return astgen.fail_tok(some, "function type cannot have a name", .{});
    }

    const is_extern = blk: {
        const maybe_extern_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk token_tags[maybe_extern_token] == .keyword_extern;
    };
    assert(!is_extern);

    var block_scope = gz.make_sub_block(scope);
    defer block_scope.unstack();

    const block_inst = try gz.make_block_inst(.block_inline, node);

    var noalias_bits: u32 = 0;
    const is_var_args = is_var_args: {
        var param_type_i: usize = 0;
        var it = fn_proto.iterate(tree);
        while (it.next()) |param| : (param_type_i += 1) {
            const is_comptime = if (param.comptime_noalias) |token| switch (token_tags[token]) {
                .keyword_noalias => is_comptime: {
                    noalias_bits |= @as(u32, 1) << (std.math.cast(u5, param_type_i) orelse
                        return astgen.fail_tok(token, "this compiler implementation only supports 'noalias' on the first 32 parameters", .{}));
                    break :is_comptime false;
                },
                .keyword_comptime => true,
                else => false,
            } else false;

            const is_anytype = if (param.anytype_ellipsis3) |token| blk: {
                switch (token_tags[token]) {
                    .keyword_anytype => break :blk true,
                    .ellipsis3 => break :is_var_args true,
                    else => unreachable,
                }
            } else false;

            const param_name = if (param.name_token) |name_token| blk: {
                if (mem.eql(u8, "_", tree.token_slice(name_token)))
                    break :blk .empty;

                break :blk try astgen.ident_as_string(name_token);
            } else .empty;

            if (is_anytype) {
                const name_token = param.name_token orelse param.anytype_ellipsis3.?;

                const tag: Zir.Inst.Tag = if (is_comptime)
                    .param_anytype_comptime
                else
                    .param_anytype;
                _ = try block_scope.add_str_tok(tag, param_name, name_token);
            } else {
                const param_type_node = param.type_expr;
                assert(param_type_node != 0);
                var param_gz = block_scope.make_sub_block(scope);
                defer param_gz.unstack();
                const param_type = try full_body_expr(&param_gz, scope, coerced_type_ri, param_type_node);
                const param_inst_expected: Zir.Inst.Index = @enumFromInt(astgen.instructions.len + 1);
                _ = try param_gz.add_break_with_src_node(.break_inline, param_inst_expected, param_type, param_type_node);
                const main_tokens = tree.nodes.items(.main_token);
                const name_token = param.name_token orelse main_tokens[param_type_node];
                const tag: Zir.Inst.Tag = if (is_comptime) .param_comptime else .param;
                const param_inst = try block_scope.add_param(&param_gz, tag, name_token, param_name, param.first_doc_comment);
                assert(param_inst_expected == param_inst);
            }
        }
        break :is_var_args false;
    };

    if (fn_proto.ast.align_expr != 0) {
        return astgen.fail_node(fn_proto.ast.align_expr, "function type cannot have an alignment", .{});
    }

    if (fn_proto.ast.addrspace_expr != 0) {
        return astgen.fail_node(fn_proto.ast.addrspace_expr, "function type cannot have an addrspace", .{});
    }

    if (fn_proto.ast.section_expr != 0) {
        return astgen.fail_node(fn_proto.ast.section_expr, "function type cannot have a linksection", .{});
    }

    const cc: Zir.Inst.Ref = if (fn_proto.ast.callconv_expr != 0)
        try expr(
            &block_scope,
            scope,
            .{ .rl = .{ .coerced_ty = .calling_convention_type } },
            fn_proto.ast.callconv_expr,
        )
    else
        Zir.Inst.Ref.none;

    const maybe_bang = tree.first_token(fn_proto.ast.return_type) - 1;
    const is_inferred_error = token_tags[maybe_bang] == .bang;
    if (is_inferred_error) {
        return astgen.fail_tok(maybe_bang, "function type cannot have an inferred error set", .{});
    }
    const ret_ty = try expr(&block_scope, scope, coerced_type_ri, fn_proto.ast.return_type);

    const result = try block_scope.add_func(.{
        .src_node = fn_proto.ast.proto_node,

        .cc_ref = cc,
        .cc_gz = null,
        .align_ref = .none,
        .align_gz = null,
        .ret_ref = ret_ty,
        .ret_gz = null,
        .section_ref = .none,
        .section_gz = null,
        .addrspace_ref = .none,
        .addrspace_gz = null,

        .param_block = block_inst,
        .body_gz = null,
        .lib_name = .empty,
        .is_var_args = is_var_args,
        .is_inferred_error = false,
        .is_test = false,
        .is_extern = false,
        .is_noinline = false,
        .noalias_bits = noalias_bits,
    });

    _ = try block_scope.add_break(.break_inline, block_inst, result);
    try block_scope.set_block_body(block_inst);
    try gz.instructions.append(astgen.gpa, block_inst);

    return rvalue(gz, ri, block_inst.to_ref(), fn_proto.ast.proto_node);
}

fn array_init_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    array_init: Ast.full.ArrayInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    assert(array_init.ast.elements.len != 0); // Otherwise it would be struct init.

    const array_ty: Zir.Inst.Ref, const elem_ty: Zir.Inst.Ref = inst: {
        if (array_init.ast.type_expr == 0) break :inst .{ .none, .none };

        infer: {
            const array_type: Ast.full.ArrayType = tree.full_array_type(array_init.ast.type_expr) orelse break :infer;
            // This intentionally does not support `@"_"` syntax.
            if (node_tags[array_type.ast.elem_count] == .identifier and
                mem.eql(u8, tree.token_slice(main_tokens[array_type.ast.elem_count]), "_"))
            {
                const len_inst = try gz.add_int(array_init.ast.elements.len);
                const elem_type = try type_expr(gz, scope, array_type.ast.elem_type);
                if (array_type.ast.sentinel == 0) {
                    const array_type_inst = try gz.add_pl_node(.array_type, array_init.ast.type_expr, Zir.Inst.Bin{
                        .lhs = len_inst,
                        .rhs = elem_type,
                    });
                    break :inst .{ array_type_inst, elem_type };
                } else {
                    const sentinel = try comptime_expr(gz, scope, .{ .rl = .{ .ty = elem_type } }, array_type.ast.sentinel);
                    const array_type_inst = try gz.add_pl_node(
                        .array_type_sentinel,
                        array_init.ast.type_expr,
                        Zir.Inst.ArrayTypeSentinel{
                            .len = len_inst,
                            .elem_type = elem_type,
                            .sentinel = sentinel,
                        },
                    );
                    break :inst .{ array_type_inst, elem_type };
                }
            }
        }
        const array_type_inst = try type_expr(gz, scope, array_init.ast.type_expr);
        _ = try gz.add_pl_node(.validate_array_init_ty, node, Zir.Inst.ArrayInit{
            .ty = array_type_inst,
            .init_count = @int_cast(array_init.ast.elements.len),
        });
        break :inst .{ array_type_inst, .none };
    };

    if (array_ty != .none) {
        // Typed inits do not use RLS for language simplicity.
        switch (ri.rl) {
            .discard => {
                if (elem_ty != .none) {
                    const elem_ri: ResultInfo = .{ .rl = .{ .ty = elem_ty } };
                    for (array_init.ast.elements) |elem_init| {
                        _ = try expr(gz, scope, elem_ri, elem_init);
                    }
                } else {
                    for (array_init.ast.elements, 0..) |elem_init, i| {
                        const this_elem_ty = try gz.add(.{
                            .tag = .array_init_elem_type,
                            .data = .{ .bin = .{
                                .lhs = array_ty,
                                .rhs = @enumFromInt(i),
                            } },
                        });
                        _ = try expr(gz, scope, .{ .rl = .{ .ty = this_elem_ty } }, elem_init);
                    }
                }
                return .void_value;
            },
            .ref => return array_init_expr_typed(gz, scope, node, array_init.ast.elements, array_ty, elem_ty, true),
            else => {
                const array_inst = try array_init_expr_typed(gz, scope, node, array_init.ast.elements, array_ty, elem_ty, false);
                return rvalue(gz, ri, array_inst, node);
            },
        }
    }

    switch (ri.rl) {
        .none => return array_init_expr_anon(gz, scope, node, array_init.ast.elements),
        .discard => {
            for (array_init.ast.elements) |elem_init| {
                _ = try expr(gz, scope, .{ .rl = .discard }, elem_init);
            }
            return Zir.Inst.Ref.void_value;
        },
        .ref => {
            const result = try array_init_expr_anon(gz, scope, node, array_init.ast.elements);
            return gz.add_un_tok(.ref, result, tree.first_token(node));
        },
        .ref_coerced_ty => |ptr_ty_inst| {
            const dest_arr_ty_inst = try gz.add_pl_node(.validate_array_init_ref_ty, node, Zir.Inst.ArrayInitRefTy{
                .ptr_ty = ptr_ty_inst,
                .elem_count = @int_cast(array_init.ast.elements.len),
            });
            return array_init_expr_typed(gz, scope, node, array_init.ast.elements, dest_arr_ty_inst, .none, true);
        },
        .ty, .coerced_ty => |result_ty_inst| {
            _ = try gz.add_pl_node(.validate_array_init_result_ty, node, Zir.Inst.ArrayInit{
                .ty = result_ty_inst,
                .init_count = @int_cast(array_init.ast.elements.len),
            });
            return array_init_expr_typed(gz, scope, node, array_init.ast.elements, result_ty_inst, .none, false);
        },
        .ptr => |ptr| {
            try array_init_expr_ptr(gz, scope, node, array_init.ast.elements, ptr.inst);
            return .void_value;
        },
        .inferred_ptr => {
            // We can't get elem pointers of an untyped inferred alloc, so must perform a
            // standard anonymous initialization followed by an rvalue store.
            // See corresponding logic in struct_init_expr.
            const result = try array_init_expr_anon(gz, scope, node, array_init.ast.elements);
            return rvalue(gz, ri, result, node);
        },
        .destructure => |destructure| {
            // Untyped init - destructure directly into result pointers
            if (array_init.ast.elements.len != destructure.components.len) {
                return astgen.fail_node_notes(node, "expected {} elements for destructure, found {}", .{
                    destructure.components.len,
                    array_init.ast.elements.len,
                }, &.{
                    try astgen.err_note_node(destructure.src_node, "result destructured here", .{}),
                });
            }
            for (array_init.ast.elements, destructure.components) |elem_init, ds_comp| {
                const elem_ri: ResultInfo = .{ .rl = switch (ds_comp) {
                    .typed_ptr => |ptr_rl| .{ .ptr = ptr_rl },
                    .inferred_ptr => |ptr_inst| .{ .inferred_ptr = ptr_inst },
                    .discard => .discard,
                } };
                _ = try expr(gz, scope, elem_ri, elem_init);
            }
            return .void_value;
        },
    }
}

/// An array initialization expression using an `array_init_anon` instruction.
fn array_init_expr_anon(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const payload_index = try add_extra(astgen, Zir.Inst.MultiOp{
        .operands_len = @int_cast(elements.len),
    });
    var extra_index = try reserve_extra(astgen, elements.len);

    for (elements) |elem_init| {
        const elem_ref = try expr(gz, scope, .{ .rl = .none }, elem_init);
        astgen.extra.items[extra_index] = @int_from_enum(elem_ref);
        extra_index += 1;
    }
    return try gz.add_pl_node_payload_index(.array_init_anon, node, payload_index);
}

/// An array initialization expression using an `array_init` or `array_init_ref` instruction.
fn array_init_expr_typed(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
    ty_inst: Zir.Inst.Ref,
    maybe_elem_ty_inst: Zir.Inst.Ref,
    is_ref: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const len = elements.len + 1; // +1 for type
    const payload_index = try add_extra(astgen, Zir.Inst.MultiOp{
        .operands_len = @int_cast(len),
    });
    var extra_index = try reserve_extra(astgen, len);
    astgen.extra.items[extra_index] = @int_from_enum(ty_inst);
    extra_index += 1;

    if (maybe_elem_ty_inst != .none) {
        const elem_ri: ResultInfo = .{ .rl = .{ .coerced_ty = maybe_elem_ty_inst } };
        for (elements) |elem_init| {
            const elem_inst = try expr(gz, scope, elem_ri, elem_init);
            astgen.extra.items[extra_index] = @int_from_enum(elem_inst);
            extra_index += 1;
        }
    } else {
        for (elements, 0..) |elem_init, i| {
            const ri: ResultInfo = .{ .rl = .{ .coerced_ty = try gz.add(.{
                .tag = .array_init_elem_type,
                .data = .{ .bin = .{
                    .lhs = ty_inst,
                    .rhs = @enumFromInt(i),
                } },
            }) } };

            const elem_inst = try expr(gz, scope, ri, elem_init);
            astgen.extra.items[extra_index] = @int_from_enum(elem_inst);
            extra_index += 1;
        }
    }

    const tag: Zir.Inst.Tag = if (is_ref) .array_init_ref else .array_init;
    return try gz.add_pl_node_payload_index(tag, node, payload_index);
}

/// An array initialization expression using element pointers.
fn array_init_expr_ptr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    elements: []const Ast.Node.Index,
    ptr_inst: Zir.Inst.Ref,
) InnerError!void {
    const astgen = gz.astgen;

    const array_ptr_inst = try gz.add_un_node(.opt_eu_base_ptr_init, ptr_inst, node);

    const payload_index = try add_extra(astgen, Zir.Inst.Block{
        .body_len = @int_cast(elements.len),
    });
    var extra_index = try reserve_extra(astgen, elements.len);

    for (elements, 0..) |elem_init, i| {
        const elem_ptr_inst = try gz.add_pl_node(.array_init_elem_ptr, elem_init, Zir.Inst.ElemPtrImm{
            .ptr = array_ptr_inst,
            .index = @int_cast(i),
        });
        astgen.extra.items[extra_index] = @int_from_enum(elem_ptr_inst.to_index().?);
        extra_index += 1;
        _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{ .inst = elem_ptr_inst } } }, elem_init);
    }

    _ = try gz.add_pl_node_payload_index(.validate_ptr_array_init, node, payload_index);
}

fn struct_init_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    if (struct_init.ast.type_expr == 0) {
        if (struct_init.ast.fields.len == 0) {
            // Anonymous init with no fields.
            switch (ri.rl) {
                .discard => return .void_value,
                .ref_coerced_ty => |ptr_ty_inst| return gz.add_un_node(.struct_init_empty_ref_result, ptr_ty_inst, node),
                .ty, .coerced_ty => |ty_inst| return gz.add_un_node(.struct_init_empty_result, ty_inst, node),
                .ptr => {
                    // TODO: should we modify this to use RLS for the field stores here?
                    const ty_inst = (try ri.rl.result_type(gz, node)).?;
                    const val = try gz.add_un_node(.struct_init_empty_result, ty_inst, node);
                    return rvalue(gz, ri, val, node);
                },
                .none, .ref, .inferred_ptr => {
                    return rvalue(gz, ri, .empty_struct, node);
                },
                .destructure => |destructure| {
                    return astgen.fail_node_notes(node, "empty initializer cannot be destructured", .{}, &.{
                        try astgen.err_note_node(destructure.src_node, "result destructured here", .{}),
                    });
                },
            }
        }
    } else array: {
        const node_tags = tree.nodes.items(.tag);
        const main_tokens = tree.nodes.items(.main_token);
        const array_type: Ast.full.ArrayType = tree.full_array_type(struct_init.ast.type_expr) orelse {
            if (struct_init.ast.fields.len == 0) {
                const ty_inst = try type_expr(gz, scope, struct_init.ast.type_expr);
                const result = try gz.add_un_node(.struct_init_empty, ty_inst, node);
                return rvalue(gz, ri, result, node);
            }
            break :array;
        };
        const is_inferred_array_len = node_tags[array_type.ast.elem_count] == .identifier and
            // This intentionally does not support `@"_"` syntax.
            mem.eql(u8, tree.token_slice(main_tokens[array_type.ast.elem_count]), "_");
        if (struct_init.ast.fields.len == 0) {
            if (is_inferred_array_len) {
                const elem_type = try type_expr(gz, scope, array_type.ast.elem_type);
                const array_type_inst = if (array_type.ast.sentinel == 0) blk: {
                    break :blk try gz.add_pl_node(.array_type, struct_init.ast.type_expr, Zir.Inst.Bin{
                        .lhs = .zero_usize,
                        .rhs = elem_type,
                    });
                } else blk: {
                    const sentinel = try comptime_expr(gz, scope, .{ .rl = .{ .ty = elem_type } }, array_type.ast.sentinel);
                    break :blk try gz.add_pl_node(
                        .array_type_sentinel,
                        struct_init.ast.type_expr,
                        Zir.Inst.ArrayTypeSentinel{
                            .len = .zero_usize,
                            .elem_type = elem_type,
                            .sentinel = sentinel,
                        },
                    );
                };
                const result = try gz.add_un_node(.struct_init_empty, array_type_inst, node);
                return rvalue(gz, ri, result, node);
            }
            const ty_inst = try type_expr(gz, scope, struct_init.ast.type_expr);
            const result = try gz.add_un_node(.struct_init_empty, ty_inst, node);
            return rvalue(gz, ri, result, node);
        } else {
            return astgen.fail_node(
                struct_init.ast.type_expr,
                "initializing array with struct syntax",
                .{},
            );
        }
    }

    {
        var sfba = std.heap.stack_fallback(256, astgen.arena);
        const sfba_allocator = sfba.get();

        var duplicate_names = std.AutoArrayHashMap(Zir.NullTerminatedString, ArrayListUnmanaged(Ast.TokenIndex)).init(sfba_allocator);
        try duplicate_names.ensure_total_capacity(@int_cast(struct_init.ast.fields.len));

        // When there aren't errors, use this to avoid a second iteration.
        var any_duplicate = false;

        for (struct_init.ast.fields) |field| {
            const name_token = tree.first_token(field) - 2;
            const name_index = try astgen.ident_as_string(name_token);

            const gop = try duplicate_names.get_or_put(name_index);

            if (gop.found_existing) {
                try gop.value_ptr.append(sfba_allocator, name_token);
                any_duplicate = true;
            } else {
                gop.value_ptr.* = .{};
                try gop.value_ptr.append(sfba_allocator, name_token);
            }
        }

        if (any_duplicate) {
            var it = duplicate_names.iterator();

            while (it.next()) |entry| {
                const record = entry.value_ptr.*;
                if (record.items.len > 1) {
                    var error_notes = std.ArrayList(u32).init(astgen.arena);

                    for (record.items[1..]) |duplicate| {
                        try error_notes.append(try astgen.err_note_tok(duplicate, "duplicate name here", .{}));
                    }

                    try error_notes.append(try astgen.err_note_node(node, "struct declared here", .{}));

                    try astgen.append_error_tok_notes(
                        record.items[0],
                        "duplicate struct field name",
                        .{},
                        error_notes.items,
                    );
                }
            }

            return error.AnalysisFail;
        }
    }

    if (struct_init.ast.type_expr != 0) {
        // Typed inits do not use RLS for language simplicity.
        const ty_inst = try type_expr(gz, scope, struct_init.ast.type_expr);
        _ = try gz.add_un_node(.validate_struct_init_ty, ty_inst, node);
        switch (ri.rl) {
            .ref => return struct_init_expr_typed(gz, scope, node, struct_init, ty_inst, true),
            else => {
                const struct_inst = try struct_init_expr_typed(gz, scope, node, struct_init, ty_inst, false);
                return rvalue(gz, ri, struct_inst, node);
            },
        }
    }

    switch (ri.rl) {
        .none => return struct_init_expr_anon(gz, scope, node, struct_init),
        .discard => {
            // Even if discarding we must perform side-effects.
            for (struct_init.ast.fields) |field_init| {
                _ = try expr(gz, scope, .{ .rl = .discard }, field_init);
            }
            return .void_value;
        },
        .ref => {
            const result = try struct_init_expr_anon(gz, scope, node, struct_init);
            return gz.add_un_tok(.ref, result, tree.first_token(node));
        },
        .ref_coerced_ty => |ptr_ty_inst| {
            const result_ty_inst = try gz.add_un_node(.elem_type, ptr_ty_inst, node);
            _ = try gz.add_un_node(.validate_struct_init_result_ty, result_ty_inst, node);
            return struct_init_expr_typed(gz, scope, node, struct_init, result_ty_inst, true);
        },
        .ty, .coerced_ty => |result_ty_inst| {
            _ = try gz.add_un_node(.validate_struct_init_result_ty, result_ty_inst, node);
            return struct_init_expr_typed(gz, scope, node, struct_init, result_ty_inst, false);
        },
        .ptr => |ptr| {
            try struct_init_expr_ptr(gz, scope, node, struct_init, ptr.inst);
            return .void_value;
        },
        .inferred_ptr => {
            // We can't get field pointers of an untyped inferred alloc, so must perform a
            // standard anonymous initialization followed by an rvalue store.
            // See corresponding logic in array_init_expr.
            const struct_inst = try struct_init_expr_anon(gz, scope, node, struct_init);
            return rvalue(gz, ri, struct_inst, node);
        },
        .destructure => |destructure| {
            // This is an untyped init, so is an actual struct, which does
            // not support destructuring.
            return astgen.fail_node_notes(node, "struct value cannot be destructured", .{}, &.{
                try astgen.err_note_node(destructure.src_node, "result destructured here", .{}),
            });
        },
    }
}

/// A struct initialization expression using a `struct_init_anon` instruction.
fn struct_init_expr_anon(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const payload_index = try add_extra(astgen, Zir.Inst.StructInitAnon{
        .fields_len = @int_cast(struct_init.ast.fields.len),
    });
    const field_size = @typeInfo(Zir.Inst.StructInitAnon.Item).Struct.fields.len;
    var extra_index: usize = try reserve_extra(astgen, struct_init.ast.fields.len * field_size);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.first_token(field_init) - 2;
        const str_index = try astgen.ident_as_string(name_token);
        set_extra(astgen, extra_index, Zir.Inst.StructInitAnon.Item{
            .field_name = str_index,
            .init = try expr(gz, scope, .{ .rl = .none }, field_init),
        });
        extra_index += field_size;
    }

    return gz.add_pl_node_payload_index(.struct_init_anon, node, payload_index);
}

/// A struct initialization expression using a `struct_init` or `struct_init_ref` instruction.
fn struct_init_expr_typed(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    ty_inst: Zir.Inst.Ref,
    is_ref: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const payload_index = try add_extra(astgen, Zir.Inst.StructInit{
        .fields_len = @int_cast(struct_init.ast.fields.len),
    });
    const field_size = @typeInfo(Zir.Inst.StructInit.Item).Struct.fields.len;
    var extra_index: usize = try reserve_extra(astgen, struct_init.ast.fields.len * field_size);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.first_token(field_init) - 2;
        const str_index = try astgen.ident_as_string(name_token);
        const field_ty_inst = try gz.add_pl_node(.struct_init_field_type, field_init, Zir.Inst.FieldType{
            .container_type = ty_inst,
            .name_start = str_index,
        });
        set_extra(astgen, extra_index, Zir.Inst.StructInit.Item{
            .field_type = field_ty_inst.to_index().?,
            .init = try expr(gz, scope, .{ .rl = .{ .coerced_ty = field_ty_inst } }, field_init),
        });
        extra_index += field_size;
    }

    const tag: Zir.Inst.Tag = if (is_ref) .struct_init_ref else .struct_init;
    return gz.add_pl_node_payload_index(tag, node, payload_index);
}

/// A struct initialization expression using field pointers.
fn struct_init_expr_ptr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    struct_init: Ast.full.StructInit,
    ptr_inst: Zir.Inst.Ref,
) InnerError!void {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const struct_ptr_inst = try gz.add_un_node(.opt_eu_base_ptr_init, ptr_inst, node);

    const payload_index = try add_extra(astgen, Zir.Inst.Block{
        .body_len = @int_cast(struct_init.ast.fields.len),
    });
    var extra_index = try reserve_extra(astgen, struct_init.ast.fields.len);

    for (struct_init.ast.fields) |field_init| {
        const name_token = tree.first_token(field_init) - 2;
        const str_index = try astgen.ident_as_string(name_token);
        const field_ptr = try gz.add_pl_node(.struct_init_field_ptr, field_init, Zir.Inst.Field{
            .lhs = struct_ptr_inst,
            .field_name_start = str_index,
        });
        astgen.extra.items[extra_index] = @int_from_enum(field_ptr.to_index().?);
        extra_index += 1;
        _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{ .inst = field_ptr } } }, field_init);
    }

    _ = try gz.add_pl_node_payload_index(.validate_ptr_struct_init, node, payload_index);
}

/// This explicitly calls expr in a comptime scope by wrapping it in a `block_comptime` if
/// necessary. It should be used whenever we need to force compile-time evaluation of something,
/// such as a type.
/// The function corresponding to `comptime` expression syntax is `comptime_expr_ast`.
fn comptime_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    if (gz.is_comptime) {
        // No need to change anything!
        return expr(gz, scope, ri, node);
    }

    // There's an optimization here: if the body will be evaluated at comptime regardless, there's
    // no need to wrap it in a block. This is hard to determine in general, but we can identify a
    // common subset of trivially comptime expressions to take down the size of the ZIR a bit.
    const tree = gz.astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);
    switch (node_tags[node]) {
        // Any identifier in `primitive_instrs` is trivially comptime. In particular, this includes
        // some common types, so we can elide `block_comptime` for a few common type annotations.
        .identifier => {
            const ident_token = main_tokens[node];
            const ident_name_raw = tree.token_slice(ident_token);
            if (primitive_instrs.get(ident_name_raw)) |zir_const_ref| {
                // No need to worry about result location here, we're not creating a comptime block!
                return rvalue(gz, ri, zir_const_ref, node);
            }
        },

        // We can also avoid the block for a few trivial AST tags which are always comptime-known.
        .number_literal, .string_literal, .multiline_string_literal, .enum_literal, .error_value => {
            // No need to worry about result location here, we're not creating a comptime block!
            return expr(gz, scope, ri, node);
        },

        // Lastly, for labelled blocks, avoid emitting a labelled block directly inside this
        // comptime block, because that would be silly! Note that we don't bother doing this for
        // unlabelled blocks, since they don't generate blocks at comptime anyway (see `block_expr`).
        .block_two, .block_two_semicolon, .block, .block_semicolon => {
            const token_tags = tree.tokens.items(.tag);
            const lbrace = main_tokens[node];
            // Careful! We can't pass in the real result location here, since it may
            // refer to runtime memory. A runtime-to-comptime boundary has to remove
            // result location information, compute the result, and copy it to the true
            // result location at runtime. We do this below as well.
            const ty_only_ri: ResultInfo = .{
                .ctx = ri.ctx,
                .rl = if (try ri.rl.result_type(gz, node)) |res_ty|
                    .{ .coerced_ty = res_ty }
                else
                    .none,
            };
            if (token_tags[lbrace - 1] == .colon and
                token_tags[lbrace - 2] == .identifier)
            {
                const node_datas = tree.nodes.items(.data);
                switch (node_tags[node]) {
                    .block_two, .block_two_semicolon => {
                        const stmts: [2]Ast.Node.Index = .{ node_datas[node].lhs, node_datas[node].rhs };
                        const stmt_slice = if (stmts[0] == 0)
                            stmts[0..0]
                        else if (stmts[1] == 0)
                            stmts[0..1]
                        else
                            stmts[0..2];

                        const block_ref = try labeled_block_expr(gz, scope, ty_only_ri, node, stmt_slice, true);
                        return rvalue(gz, ri, block_ref, node);
                    },
                    .block, .block_semicolon => {
                        const stmts = tree.extra_data[node_datas[node].lhs..node_datas[node].rhs];
                        // Replace result location and copy back later - see above.
                        const block_ref = try labeled_block_expr(gz, scope, ty_only_ri, node, stmts, true);
                        return rvalue(gz, ri, block_ref, node);
                    },
                    else => unreachable,
                }
            }
        },

        // In other cases, we don't optimize anything - we need a wrapper comptime block.
        else => {},
    }

    var block_scope = gz.make_sub_block(scope);
    block_scope.is_comptime = true;
    defer block_scope.unstack();

    const block_inst = try gz.make_block_inst(.block_comptime, node);
    // Replace result location and copy back later - see above.
    const ty_only_ri: ResultInfo = .{
        .ctx = ri.ctx,
        .rl = if (try ri.rl.result_type(gz, node)) |res_ty|
            .{ .coerced_ty = res_ty }
        else
            .none,
    };
    const block_result = try full_body_expr(&block_scope, scope, ty_only_ri, node);
    if (!gz.ref_is_no_return(block_result)) {
        _ = try block_scope.add_break(.@"break", block_inst, block_result);
    }
    try block_scope.set_block_body(block_inst);
    try gz.instructions.append(gz.astgen.gpa, block_inst);

    return rvalue(gz, ri, block_inst.to_ref(), node);
}

/// This one is for an actual `comptime` syntax, and will emit a compile error if
/// the scope is already known to be comptime-evaluated.
/// See `comptime_expr` for the helper function for calling expr in a comptime scope.
fn comptime_expr_ast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (gz.is_comptime) {
        return astgen.fail_node(node, "redundant comptime keyword in already comptime scope", .{});
    }
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const body_node = node_datas[node].lhs;
    return comptime_expr(gz, scope, ri, body_node);
}

/// Restore the error return trace index. Performs the restore only if the result is a non-error or
/// if the result location is a non-error-handling expression.
fn restore_err_ret_index(
    gz: *GenZir,
    bt: GenZir.BranchTarget,
    ri: ResultInfo,
    node: Ast.Node.Index,
    result: Zir.Inst.Ref,
) !void {
    const op = switch (node_may_eval_to_error(gz.astgen.tree, node)) {
        .always => return, // never restore/pop
        .never => .none, // always restore/pop
        .maybe => switch (ri.ctx) {
            .error_handling_expr, .@"return", .fn_arg, .const_init => switch (ri.rl) {
                .ptr => |ptr_res| try gz.add_un_node(.load, ptr_res.inst, node),
                .inferred_ptr => blk: {
                    // This is a terrible workaround for Sema's inability to load from a .alloc_inferred ptr
                    // before its type has been resolved. There is no valid operand to use here, so error
                    // traces will be popped prematurely.
                    // TODO: Update this to do a proper load from the rl_ptr, once Sema can support it.
                    break :blk .none;
                },
                .destructure => return, // value must be a tuple or array, so never restore/pop
                else => result,
            },
            else => .none, // always restore/pop
        },
    };
    _ = try gz.add_restore_err_ret_index(bt, .{ .if_non_error = op }, node);
}

fn break_expr(parent_gz: *GenZir, parent_scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const break_label = node_datas[node].lhs;
    const rhs = node_datas[node].rhs;

    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const block_gz = scope.cast(GenZir).?;

                if (block_gz.cur_defer_node != 0) {
                    // We are breaking out of a `defer` block.
                    return astgen.fail_node_notes(node, "cannot break out of defer expression", .{}, &.{
                        try astgen.err_note_node(
                            block_gz.cur_defer_node,
                            "defer expression here",
                            .{},
                        ),
                    });
                }

                const block_inst = blk: {
                    if (break_label != 0) {
                        if (block_gz.label) |*label| {
                            if (try astgen.token_ident_eql(label.token, break_label)) {
                                label.used = true;
                                break :blk label.block_inst;
                            }
                        }
                    } else if (block_gz.break_block.unwrap()) |i| {
                        break :blk i;
                    }
                    // If not the target, start over with the parent
                    scope = block_gz.parent;
                    continue;
                };
                // If we made it here, this block is the target of the break expr

                const break_tag: Zir.Inst.Tag = if (block_gz.is_inline)
                    .break_inline
                else
                    .@"break";

                if (rhs == 0) {
                    _ = try rvalue(parent_gz, block_gz.break_result_info, .void_value, node);

                    try gen_defers(parent_gz, scope, parent_scope, .normal_only);

                    // As our last action before the break, "pop" the error trace if needed
                    if (!block_gz.is_comptime)
                        _ = try parent_gz.add_restore_err_ret_index(.{ .block = block_inst }, .always, node);

                    _ = try parent_gz.add_break(break_tag, block_inst, .void_value);
                    return Zir.Inst.Ref.unreachable_value;
                }

                const operand = try reachable_expr(parent_gz, parent_scope, block_gz.break_result_info, rhs, node);

                try gen_defers(parent_gz, scope, parent_scope, .normal_only);

                // As our last action before the break, "pop" the error trace if needed
                if (!block_gz.is_comptime)
                    try restore_err_ret_index(parent_gz, .{ .block = block_inst }, block_gz.break_result_info, rhs, operand);

                switch (block_gz.break_result_info.rl) {
                    .ptr => {
                        // In this case we don't have any mechanism to intercept it;
                        // we assume the result location is written, and we break with void.
                        _ = try parent_gz.add_break(break_tag, block_inst, .void_value);
                    },
                    .discard => {
                        _ = try parent_gz.add_break(break_tag, block_inst, .void_value);
                    },
                    else => {
                        _ = try parent_gz.add_break_with_src_node(break_tag, block_inst, operand, rhs);
                    },
                }
                return Zir.Inst.Ref.unreachable_value;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .namespace => break,
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .top => unreachable,
        }
    }
    if (break_label != 0) {
        const label_name = try astgen.identifier_token_string(break_label);
        return astgen.fail_tok(break_label, "label not found: '{s}'", .{label_name});
    } else {
        return astgen.fail_node(node, "break expression outside loop", .{});
    }
}

fn continue_expr(parent_gz: *GenZir, parent_scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const break_label = node_datas[node].lhs;

    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const gen_zir = scope.cast(GenZir).?;

                if (gen_zir.cur_defer_node != 0) {
                    return astgen.fail_node_notes(node, "cannot continue out of defer expression", .{}, &.{
                        try astgen.err_note_node(
                            gen_zir.cur_defer_node,
                            "defer expression here",
                            .{},
                        ),
                    });
                }
                const continue_block = gen_zir.continue_block.unwrap() orelse {
                    scope = gen_zir.parent;
                    continue;
                };
                if (break_label != 0) blk: {
                    if (gen_zir.label) |*label| {
                        if (try astgen.token_ident_eql(label.token, break_label)) {
                            label.used = true;
                            break :blk;
                        }
                    }
                    // found continue but either it has a different label, or no label
                    scope = gen_zir.parent;
                    continue;
                }

                const break_tag: Zir.Inst.Tag = if (gen_zir.is_inline)
                    .break_inline
                else
                    .@"break";
                if (break_tag == .break_inline) {
                    _ = try parent_gz.add_un_node(.check_comptime_control_flow, continue_block.to_ref(), node);
                }

                // As our last action before the continue, "pop" the error trace if needed
                if (!gen_zir.is_comptime)
                    _ = try parent_gz.add_restore_err_ret_index(.{ .block = continue_block }, .always, node);

                _ = try parent_gz.add_break(break_tag, continue_block, .void_value);
                return Zir.Inst.Ref.unreachable_value;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;
                try parent_gz.add_defer(defer_scope.index, defer_scope.len);
            },
            .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => break,
            .top => unreachable,
        }
    }
    if (break_label != 0) {
        const label_name = try astgen.identifier_token_string(break_label);
        return astgen.fail_tok(break_label, "label not found: '{s}'", .{label_name});
    } else {
        return astgen.fail_node(node, "continue expression outside loop", .{});
    }
}

/// Similar to `expr`, but intended for use when `gz` corresponds to a body
/// which will contain only this node's code. Differs from `expr` in that if the
/// root expression is an unlabeled block, does not emit an actual block.
/// Instead, the block contents are emitted directly into `gz`.
fn full_body_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const tree = gz.astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);
    var stmt_buf: [2]Ast.Node.Index = undefined;
    const statements: []const Ast.Node.Index = switch (node_tags[node]) {
        else => return expr(gz, scope, ri, node),
        .block_two, .block_two_semicolon => if (node_datas[node].lhs == 0) s: {
            break :s &.{};
        } else if (node_datas[node].rhs == 0) s: {
            stmt_buf[0] = node_datas[node].lhs;
            break :s stmt_buf[0..1];
        } else s: {
            stmt_buf[0] = node_datas[node].lhs;
            stmt_buf[1] = node_datas[node].rhs;
            break :s stmt_buf[0..2];
        },
        .block, .block_semicolon => tree.extra_data[node_datas[node].lhs..node_datas[node].rhs],
    };

    const lbrace = main_tokens[node];
    if (token_tags[lbrace - 1] == .colon and
        token_tags[lbrace - 2] == .identifier)
    {
        // Labeled blocks are tricky - forwarding result location information properly is non-trivial,
        // plus if this block is exited with a `break_inline` we aren't allowed multiple breaks. This
        // case is rare, so just treat it as a normal expression and create a nested block.
        return expr(gz, scope, ri, node);
    }

    var sub_gz = gz.make_sub_block(scope);
    try block_expr_stmts(&sub_gz, &sub_gz.base, statements);

    return rvalue(gz, ri, .void_value, node);
}

fn block_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    const lbrace = main_tokens[block_node];
    if (token_tags[lbrace - 1] == .colon and
        token_tags[lbrace - 2] == .identifier)
    {
        return labeled_block_expr(gz, scope, ri, block_node, statements, false);
    }

    if (!gz.is_comptime) {
        // Since this block is unlabeled, its control flow is effectively linear and we
        // can *almost* get away with inlining the block here. However, we actually need
        // to preserve the .block for Sema, to properly pop the error return trace.

        const block_tag: Zir.Inst.Tag = .block;
        const block_inst = try gz.make_block_inst(block_tag, block_node);
        try gz.instructions.append(astgen.gpa, block_inst);

        var block_scope = gz.make_sub_block(scope);
        defer block_scope.unstack();

        try block_expr_stmts(&block_scope, &block_scope.base, statements);

        if (!block_scope.ends_with_no_return()) {
            // As our last action before the break, "pop" the error trace if needed
            _ = try gz.add_restore_err_ret_index(.{ .block = block_inst }, .always, block_node);
            _ = try block_scope.add_break(.@"break", block_inst, .void_value);
        }

        try block_scope.set_block_body(block_inst);
    } else {
        var sub_gz = gz.make_sub_block(scope);
        try block_expr_stmts(&sub_gz, &sub_gz.base, statements);
    }

    return rvalue(gz, ri, .void_value, block_node);
}

fn check_label_redefinition(astgen: *AstGen, parent_scope: *Scope, label: Ast.TokenIndex) !void {
    // Look for the label in the scope.
    var scope = parent_scope;
    while (true) {
        switch (scope.tag) {
            .gen_zir => {
                const gen_zir = scope.cast(GenZir).?;
                if (gen_zir.label) |prev_label| {
                    if (try astgen.token_ident_eql(label, prev_label.token)) {
                        const label_name = try astgen.identifier_token_string(label);
                        return astgen.fail_tok_notes(label, "redefinition of label '{s}'", .{
                            label_name,
                        }, &[_]u32{
                            try astgen.err_note_tok(
                                prev_label.token,
                                "previous definition here",
                                .{},
                            ),
                        });
                    }
                }
                scope = gen_zir.parent;
            },
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => break,
            .top => unreachable,
        }
    }
}

fn labeled_block_expr(
    gz: *GenZir,
    parent_scope: *Scope,
    ri: ResultInfo,
    block_node: Ast.Node.Index,
    statements: []const Ast.Node.Index,
    force_comptime: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    const lbrace = main_tokens[block_node];
    const label_token = lbrace - 2;
    assert(token_tags[label_token] == .identifier);

    try astgen.check_label_redefinition(parent_scope, label_token);

    const need_rl = astgen.nodes_need_rl.contains(block_node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(gz, block_node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    // Reserve the Block ZIR instruction index so that we can put it into the GenZir struct
    // so that break statements can reference it.
    const block_tag: Zir.Inst.Tag = if (force_comptime) .block_comptime else .block;
    const block_inst = try gz.make_block_inst(block_tag, block_node);
    try gz.instructions.append(astgen.gpa, block_inst);
    var block_scope = gz.make_sub_block(parent_scope);
    block_scope.label = GenZir.Label{
        .token = label_token,
        .block_inst = block_inst,
    };
    block_scope.set_break_result_info(block_ri);
    if (force_comptime) block_scope.is_comptime = true;
    defer block_scope.unstack();

    try block_expr_stmts(&block_scope, &block_scope.base, statements);
    if (!block_scope.ends_with_no_return()) {
        // As our last action before the return, "pop" the error trace if needed
        _ = try gz.add_restore_err_ret_index(.{ .block = block_inst }, .always, block_node);
        _ = try block_scope.add_break(.@"break", block_inst, .void_value);
    }

    if (!block_scope.label.?.used) {
        try astgen.append_error_tok(label_token, "unused block label", .{});
    }

    try block_scope.set_block_body(block_inst);
    if (need_result_rvalue) {
        return rvalue(gz, ri, block_inst.to_ref(), block_node);
    } else {
        return block_inst.to_ref();
    }
}

fn block_expr_stmts(gz: *GenZir, parent_scope: *Scope, statements: []const Ast.Node.Index) !void {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);

    if (statements.len == 0) return;

    var block_arena = std.heap.ArenaAllocator.init(gz.astgen.gpa);
    defer block_arena.deinit();
    const block_arena_allocator = block_arena.allocator();

    var noreturn_src_node: Ast.Node.Index = 0;
    var scope = parent_scope;
    for (statements) |statement| {
        if (noreturn_src_node != 0) {
            try astgen.append_error_node_notes(
                statement,
                "unreachable code",
                .{},
                &[_]u32{
                    try astgen.err_note_node(
                        noreturn_src_node,
                        "control flow is diverted here",
                        .{},
                    ),
                },
            );
        }
        var inner_node = statement;
        while (true) {
            switch (node_tags[inner_node]) {
                // zig fmt: off
                .global_var_decl,
                .local_var_decl,
                .simple_var_decl,
                .aligned_var_decl, => scope = try var_decl(gz, scope, statement, block_arena_allocator, tree.full_var_decl(statement).?),

                .assign_destructure => scope = try assign_destructure_maybe_decls(gz, scope, statement, block_arena_allocator),

                .@"defer"    => scope = try defer_stmt(gz, scope, statement, block_arena_allocator, .defer_normal),
                .@"errdefer" => scope = try defer_stmt(gz, scope, statement, block_arena_allocator, .defer_error),

                .assign => try assign(gz, scope, statement),

                .assign_shl => try assign_shift(gz, scope, statement, .shl),
                .assign_shr => try assign_shift(gz, scope, statement, .shr),

                .assign_bit_and  => try assign_op(gz, scope, statement, .bit_and),
                .assign_bit_or   => try assign_op(gz, scope, statement, .bit_or),
                .assign_bit_xor  => try assign_op(gz, scope, statement, .xor),
                .assign_div      => try assign_op(gz, scope, statement, .div),
                .assign_sub      => try assign_op(gz, scope, statement, .sub),
                .assign_sub_wrap => try assign_op(gz, scope, statement, .subwrap),
                .assign_mod      => try assign_op(gz, scope, statement, .mod_rem),
                .assign_add      => try assign_op(gz, scope, statement, .add),
                .assign_add_wrap => try assign_op(gz, scope, statement, .addwrap),
                .assign_mul      => try assign_op(gz, scope, statement, .mul),
                .assign_mul_wrap => try assign_op(gz, scope, statement, .mulwrap),

                .grouped_expression => {
                    inner_node = node_data[statement].lhs;
                    continue;
                },

                .while_simple,
                .while_cont,
                .@"while", => _ = try while_expr(gz, scope, .{ .rl = .none }, inner_node, tree.full_while(inner_node).?, true),

                .for_simple,
                .@"for", => _ = try for_expr(gz, scope, .{ .rl = .none }, inner_node, tree.full_for(inner_node).?, true),

                else => noreturn_src_node = try unused_result_expr(gz, scope, inner_node),
                // zig fmt: on
            }
            break;
        }
    }

    if (noreturn_src_node == 0) {
        try gen_defers(gz, parent_scope, scope, .normal_only);
    }
    try check_used(gz, parent_scope, scope);
}

/// Returns AST source node of the thing that is noreturn if the statement is
/// definitely `noreturn`. Otherwise returns 0.
fn unused_result_expr(gz: *GenZir, scope: *Scope, statement: Ast.Node.Index) InnerError!Ast.Node.Index {
    try emit_dbg_node(gz, statement);
    // We need to emit an error if the result is not `noreturn` or `void`, but
    // we want to avoid adding the ZIR instruction if possible for performance.
    const maybe_unused_result = try expr(gz, scope, .{ .rl = .none }, statement);
    return add_ensure_result(gz, maybe_unused_result, statement);
}

fn add_ensure_result(gz: *GenZir, maybe_unused_result: Zir.Inst.Ref, statement: Ast.Node.Index) InnerError!Ast.Node.Index {
    var noreturn_src_node: Ast.Node.Index = 0;
    const elide_check = if (maybe_unused_result.to_index()) |inst| b: {
        // Note that this array becomes invalid after appending more items to it
        // in the above while loop.
        const zir_tags = gz.astgen.instructions.items(.tag);
        switch (zir_tags[@int_from_enum(inst)]) {
            // For some instructions, modify the zir data
            // so we can avoid a separate ensure_result_used instruction.
            .call, .field_call => {
                const break_extra = gz.astgen.instructions.items(.data)[@int_from_enum(inst)].pl_node.payload_index;
                comptime assert(std.meta.field_index(Zir.Inst.Call, "flags") ==
                    std.meta.field_index(Zir.Inst.FieldCall, "flags"));
                const flags: *Zir.Inst.Call.Flags = @ptr_cast(&gz.astgen.extra.items[
                    break_extra + std.meta.field_index(Zir.Inst.Call, "flags").?
                ]);
                flags.ensure_result_used = true;
                break :b true;
            },
            .builtin_call => {
                const break_extra = gz.astgen.instructions.items(.data)[@int_from_enum(inst)].pl_node.payload_index;
                const flags: *Zir.Inst.BuiltinCall.Flags = @ptr_cast(&gz.astgen.extra.items[
                    break_extra + std.meta.field_index(Zir.Inst.BuiltinCall, "flags").?
                ]);
                flags.ensure_result_used = true;
                break :b true;
            },

            // ZIR instructions that might be a type other than `noreturn` or `void`.
            .add,
            .addwrap,
            .add_sat,
            .add_unsafe,
            .param,
            .param_comptime,
            .param_anytype,
            .param_anytype_comptime,
            .alloc,
            .alloc_mut,
            .alloc_comptime_mut,
            .alloc_inferred,
            .alloc_inferred_mut,
            .alloc_inferred_comptime,
            .alloc_inferred_comptime_mut,
            .make_ptr_const,
            .array_cat,
            .array_mul,
            .array_type,
            .array_type_sentinel,
            .elem_type,
            .indexable_ptr_elem_type,
            .vector_elem_type,
            .vector_type,
            .indexable_ptr_len,
            .anyframe_type,
            .as_node,
            .as_shift_operand,
            .bit_and,
            .bitcast,
            .bit_or,
            .block,
            .block_comptime,
            .block_inline,
            .declaration,
            .suspend_block,
            .loop,
            .bool_br_and,
            .bool_br_or,
            .bool_not,
            .cmp_lt,
            .cmp_lte,
            .cmp_eq,
            .cmp_gte,
            .cmp_gt,
            .cmp_neq,
            .decl_ref,
            .decl_val,
            .load,
            .div,
            .elem_ptr,
            .elem_val,
            .elem_ptr_node,
            .elem_val_node,
            .elem_val_imm,
            .field_ptr,
            .field_val,
            .field_ptr_named,
            .field_val_named,
            .func,
            .func_inferred,
            .func_fancy,
            .int,
            .int_big,
            .float,
            .float128,
            .int_type,
            .is_non_null,
            .is_non_null_ptr,
            .is_non_err,
            .is_non_err_ptr,
            .ret_is_non_err,
            .mod_rem,
            .mul,
            .mulwrap,
            .mul_sat,
            .ref,
            .shl,
            .shl_sat,
            .shr,
            .str,
            .sub,
            .subwrap,
            .sub_sat,
            .negate,
            .negate_wrap,
            .typeof,
            .typeof_builtin,
            .xor,
            .optional_type,
            .optional_payload_safe,
            .optional_payload_unsafe,
            .optional_payload_safe_ptr,
            .optional_payload_unsafe_ptr,
            .err_union_payload_unsafe,
            .err_union_payload_unsafe_ptr,
            .err_union_code,
            .err_union_code_ptr,
            .ptr_type,
            .enum_literal,
            .merge_error_sets,
            .error_union_type,
            .bit_not,
            .error_value,
            .slice_start,
            .slice_end,
            .slice_sentinel,
            .slice_length,
            .import,
            .switch_block,
            .switch_block_ref,
            .switch_block_err_union,
            .union_init,
            .field_type_ref,
            .error_set_decl,
            .error_set_decl_anon,
            .error_set_decl_func,
            .enum_from_int,
            .int_from_enum,
            .type_info,
            .size_of,
            .bit_size_of,
            .typeof_log2_int_type,
            .int_from_ptr,
            .align_of,
            .int_from_bool,
            .embed_file,
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
            .abs,
            .floor,
            .ceil,
            .trunc,
            .round,
            .tag_name,
            .type_name,
            .frame_type,
            .frame_size,
            .int_from_float,
            .float_from_int,
            .ptr_from_int,
            .float_cast,
            .int_cast,
            .ptr_cast,
            .truncate,
            .has_decl,
            .has_field,
            .clz,
            .ctz,
            .pop_count,
            .byte_swap,
            .bit_reverse,
            .div_exact,
            .div_floor,
            .div_trunc,
            .mod,
            .rem,
            .shl_exact,
            .shr_exact,
            .bit_offset_of,
            .offset_of,
            .splat,
            .reduce,
            .shuffle,
            .atomic_load,
            .atomic_rmw,
            .mul_add,
            .max,
            .min,
            .c_import,
            .@"resume",
            .@"await",
            .ret_err_value_code,
            .ret_ptr,
            .ret_type,
            .for_len,
            .@"try",
            .try_ptr,
            .opt_eu_base_ptr_init,
            .coerce_ptr_elem_ty,
            .struct_init_empty,
            .struct_init_empty_result,
            .struct_init_empty_ref_result,
            .struct_init_anon,
            .struct_init,
            .struct_init_ref,
            .struct_init_field_type,
            .struct_init_field_ptr,
            .array_init_anon,
            .array_init,
            .array_init_ref,
            .validate_array_init_ref_ty,
            .array_init_elem_type,
            .array_init_elem_ptr,
            => break :b false,

            .extended => switch (gz.astgen.instructions.items(.data)[@int_from_enum(inst)].extended.opcode) {
                .breakpoint,
                .fence,
                .set_float_mode,
                .set_align_stack,
                .set_cold,
                => break :b true,
                else => break :b false,
            },

            // ZIR instructions that are always `noreturn`.
            .@"break",
            .break_inline,
            .condbr,
            .condbr_inline,
            .compile_error,
            .ret_node,
            .ret_load,
            .ret_implicit,
            .ret_err_value,
            .@"unreachable",
            .repeat,
            .repeat_inline,
            .panic,
            .trap,
            .check_comptime_control_flow,
            => {
                noreturn_src_node = statement;
                break :b true;
            },

            // ZIR instructions that are always `void`.
            .dbg_stmt,
            .dbg_var_ptr,
            .dbg_var_val,
            .ensure_result_used,
            .ensure_result_non_error,
            .ensure_err_union_payload_void,
            .@"export",
            .export_value,
            .set_eval_branch_quota,
            .atomic_store,
            .store_node,
            .store_to_inferred_ptr,
            .resolve_inferred_alloc,
            .set_runtime_safety,
            .memcpy,
            .memset,
            .validate_deref,
            .validate_destructure,
            .save_err_ret_index,
            .restore_err_ret_index_unconditional,
            .restore_err_ret_index_fn_entry,
            .validate_struct_init_ty,
            .validate_struct_init_result_ty,
            .validate_ptr_struct_init,
            .validate_array_init_ty,
            .validate_array_init_result_ty,
            .validate_ptr_array_init,
            .validate_ref_ty,
            => break :b true,

            .@"defer" => unreachable,
            .defer_err_code => unreachable,
        }
    } else switch (maybe_unused_result) {
        .none => unreachable,

        .unreachable_value => b: {
            noreturn_src_node = statement;
            break :b true;
        },

        .void_value => true,

        else => false,
    };
    if (!elide_check) {
        _ = try gz.add_un_node(.ensure_result_used, maybe_unused_result, statement);
    }
    return noreturn_src_node;
}

fn count_defers(outer_scope: *Scope, inner_scope: *Scope) struct {
    have_any: bool,
    have_normal: bool,
    have_err: bool,
    need_err_code: bool,
} {
    var have_normal = false;
    var have_err = false;
    var need_err_code = false;
    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;

                have_normal = true;
            },
            .defer_error => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;

                have_err = true;

                const have_err_payload = defer_scope.remapped_err_code != .none;
                need_err_code = need_err_code or have_err_payload;
            },
            .namespace => unreachable,
            .top => unreachable,
        }
    }
    return .{
        .have_any = have_normal or have_err,
        .have_normal = have_normal,
        .have_err = have_err,
        .need_err_code = need_err_code,
    };
}

const DefersToEmit = union(enum) {
    both: Zir.Inst.Ref, // err code
    both_sans_err,
    normal_only,
};

fn gen_defers(
    gz: *GenZir,
    outer_scope: *Scope,
    inner_scope: *Scope,
    which_ones: DefersToEmit,
) InnerError!void {
    const gpa = gz.astgen.gpa;

    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => scope = scope.cast(Scope.LocalVal).?.parent,
            .local_ptr => scope = scope.cast(Scope.LocalPtr).?.parent,
            .defer_normal => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;
                try gz.add_defer(defer_scope.index, defer_scope.len);
            },
            .defer_error => {
                const defer_scope = scope.cast(Scope.Defer).?;
                scope = defer_scope.parent;
                switch (which_ones) {
                    .both_sans_err => {
                        try gz.add_defer(defer_scope.index, defer_scope.len);
                    },
                    .both => |err_code| {
                        if (defer_scope.remapped_err_code.unwrap()) |remapped_err_code| {
                            try gz.instructions.ensure_unused_capacity(gpa, 1);
                            try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

                            const payload_index = try gz.astgen.add_extra(Zir.Inst.DeferErrCode{
                                .remapped_err_code = remapped_err_code,
                                .index = defer_scope.index,
                                .len = defer_scope.len,
                            });
                            const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
                            gz.astgen.instructions.append_assume_capacity(.{
                                .tag = .defer_err_code,
                                .data = .{ .defer_err_code = .{
                                    .err_code = err_code,
                                    .payload_index = payload_index,
                                } },
                            });
                            gz.instructions.append_assume_capacity(new_index);
                        } else {
                            try gz.add_defer(defer_scope.index, defer_scope.len);
                        }
                    },
                    .normal_only => continue,
                }
            },
            .namespace => unreachable,
            .top => unreachable,
        }
    }
}

fn check_used(gz: *GenZir, outer_scope: *Scope, inner_scope: *Scope) InnerError!void {
    const astgen = gz.astgen;

    var scope = inner_scope;
    while (scope != outer_scope) {
        switch (scope.tag) {
            .gen_zir => scope = scope.cast(GenZir).?.parent,
            .local_val => {
                const s = scope.cast(Scope.LocalVal).?;
                if (s.used == 0 and s.discarded == 0) {
                    try astgen.append_error_tok(s.token_src, "unused {s}", .{@tag_name(s.id_cat)});
                } else if (s.used != 0 and s.discarded != 0) {
                    try astgen.append_error_tok_notes(s.discarded, "pointless discard of {s}", .{@tag_name(s.id_cat)}, &[_]u32{
                        try gz.astgen.err_note_tok(s.used, "used here", .{}),
                    });
                }
                scope = s.parent;
            },
            .local_ptr => {
                const s = scope.cast(Scope.LocalPtr).?;
                if (s.used == 0 and s.discarded == 0) {
                    try astgen.append_error_tok(s.token_src, "unused {s}", .{@tag_name(s.id_cat)});
                } else {
                    if (s.used != 0 and s.discarded != 0) {
                        try astgen.append_error_tok_notes(s.discarded, "pointless discard of {s}", .{@tag_name(s.id_cat)}, &[_]u32{
                            try astgen.err_note_tok(s.used, "used here", .{}),
                        });
                    }
                    if (s.id_cat == .@"local variable" and !s.used_as_lvalue) {
                        try astgen.append_error_tok_notes(s.token_src, "local variable is never mutated", .{}, &.{
                            try astgen.err_note_tok(s.token_src, "consider using 'const'", .{}),
                        });
                    }
                }

                scope = s.parent;
            },
            .defer_normal, .defer_error => scope = scope.cast(Scope.Defer).?.parent,
            .namespace => unreachable,
            .top => unreachable,
        }
    }
}

fn defer_stmt(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
    scope_tag: Scope.Tag,
) InnerError!*Scope {
    var defer_gen = gz.make_sub_block(scope);
    defer_gen.cur_defer_node = node;
    defer_gen.any_defer_node = node;
    defer defer_gen.unstack();

    const tree = gz.astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const expr_node = node_datas[node].rhs;

    const payload_token = node_datas[node].lhs;
    var local_val_scope: Scope.LocalVal = undefined;
    var opt_remapped_err_code: Zir.Inst.OptionalIndex = .none;
    const have_err_code = scope_tag == .defer_error and payload_token != 0;
    const sub_scope = if (!have_err_code) &defer_gen.base else blk: {
        const ident_name = try gz.astgen.ident_as_string(payload_token);
        const remapped_err_code: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        opt_remapped_err_code = remapped_err_code.to_optional();
        try gz.astgen.instructions.append(gz.astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        const remapped_err_code_ref = remapped_err_code.to_ref();
        local_val_scope = .{
            .parent = &defer_gen.base,
            .gen_zir = gz,
            .name = ident_name,
            .inst = remapped_err_code_ref,
            .token_src = payload_token,
            .id_cat = .capture,
        };
        try gz.add_dbg_var(.dbg_var_val, ident_name, remapped_err_code_ref);
        break :blk &local_val_scope.base;
    };
    _ = try unused_result_expr(&defer_gen, sub_scope, expr_node);
    try check_used(gz, scope, sub_scope);
    _ = try defer_gen.add_break(.break_inline, @enumFromInt(0), .void_value);

    // We must handle ref_table for remapped_err_code manually.
    const body = defer_gen.instructions_slice();
    const body_len = blk: {
        var refs: u32 = 0;
        if (opt_remapped_err_code.unwrap()) |remapped_err_code| {
            var cur_inst = remapped_err_code;
            while (gz.astgen.ref_table.get(cur_inst)) |ref_inst| {
                refs += 1;
                cur_inst = ref_inst;
            }
        }
        break :blk gz.astgen.count_body_len_after_fixups(body) + refs;
    };

    const index: u32 = @int_cast(gz.astgen.extra.items.len);
    try gz.astgen.extra.ensure_unused_capacity(gz.astgen.gpa, body_len);
    if (opt_remapped_err_code.unwrap()) |remapped_err_code| {
        if (gz.astgen.ref_table.fetch_remove(remapped_err_code)) |kv| {
            gz.astgen.append_possibly_refd_body_inst(&gz.astgen.extra, kv.value);
        }
    }
    gz.astgen.append_body_with_fixups(body);

    const defer_scope = try block_arena.create(Scope.Defer);

    defer_scope.* = .{
        .base = .{ .tag = scope_tag },
        .parent = scope,
        .index = index,
        .len = body_len,
        .remapped_err_code = opt_remapped_err_code,
    };
    return &defer_scope.base;
}

fn var_decl(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
    var_decl: Ast.full.VarDecl,
) InnerError!*Scope {
    try emit_dbg_node(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    const name_token = var_decl.ast.mut_token + 1;
    const ident_name_raw = tree.token_slice(name_token);
    if (mem.eql(u8, ident_name_raw, "_")) {
        return astgen.fail_tok(name_token, "'_' used as an identifier without @\"_\" syntax", .{});
    }
    const ident_name = try astgen.ident_as_string(name_token);

    try astgen.detect_local_shadowing(
        scope,
        ident_name,
        name_token,
        ident_name_raw,
        if (token_tags[var_decl.ast.mut_token] == .keyword_const) .@"local constant" else .@"local variable",
    );

    if (var_decl.ast.init_node == 0) {
        return astgen.fail_node(node, "variables must be initialized", .{});
    }

    if (var_decl.ast.addrspace_node != 0) {
        return astgen.fail_tok(main_tokens[var_decl.ast.addrspace_node], "cannot set address space of local variable '{s}'", .{ident_name_raw});
    }

    if (var_decl.ast.section_node != 0) {
        return astgen.fail_tok(main_tokens[var_decl.ast.section_node], "cannot set section of local variable '{s}'", .{ident_name_raw});
    }

    const align_inst: Zir.Inst.Ref = if (var_decl.ast.align_node != 0)
        try expr(gz, scope, coerced_align_ri, var_decl.ast.align_node)
    else
        .none;

    switch (token_tags[var_decl.ast.mut_token]) {
        .keyword_const => {
            if (var_decl.comptime_token) |comptime_token| {
                try astgen.append_error_tok(comptime_token, "'comptime const' is redundant; instead wrap the initialization expression with 'comptime'", .{});
            }

            // Depending on the type of AST the initialization expression is, we may need an lvalue
            // or an rvalue as a result location. If it is an rvalue, we can use the instruction as
            // the variable, no memory location needed.
            const type_node = var_decl.ast.type_node;
            if (align_inst == .none and
                !astgen.nodes_need_rl.contains(node))
            {
                const result_info: ResultInfo = if (type_node != 0) .{
                    .rl = .{ .ty = try type_expr(gz, scope, type_node) },
                    .ctx = .const_init,
                } else .{ .rl = .none, .ctx = .const_init };
                const prev_anon_name_strategy = gz.anon_name_strategy;
                gz.anon_name_strategy = .dbg_var;
                const init_inst = try reachable_expr(gz, scope, result_info, var_decl.ast.init_node, node);
                gz.anon_name_strategy = prev_anon_name_strategy;

                try gz.add_dbg_var(.dbg_var_val, ident_name, init_inst);

                // The const init expression may have modified the error return trace, so signal
                // to Sema that it should save the new index for restoring later.
                if (node_may_append_to_error_trace(tree, var_decl.ast.init_node))
                    _ = try gz.add_save_err_ret_index(.{ .if_of_error_type = init_inst });

                const sub_scope = try block_arena.create(Scope.LocalVal);
                sub_scope.* = .{
                    .parent = scope,
                    .gen_zir = gz,
                    .name = ident_name,
                    .inst = init_inst,
                    .token_src = name_token,
                    .id_cat = .@"local constant",
                };
                return &sub_scope.base;
            }

            const is_comptime = gz.is_comptime or
                tree.nodes.items(.tag)[var_decl.ast.init_node] == .@"comptime";

            var resolve_inferred_alloc: Zir.Inst.Ref = .none;
            var opt_type_inst: Zir.Inst.Ref = .none;
            const init_rl: ResultInfo.Loc = if (type_node != 0) init_rl: {
                const type_inst = try type_expr(gz, scope, type_node);
                opt_type_inst = type_inst;
                if (align_inst == .none) {
                    break :init_rl .{ .ptr = .{ .inst = try gz.add_un_node(.alloc, type_inst, node) } };
                } else {
                    break :init_rl .{ .ptr = .{ .inst = try gz.add_alloc_extended(.{
                        .node = node,
                        .type_inst = type_inst,
                        .align_inst = align_inst,
                        .is_const = true,
                        .is_comptime = is_comptime,
                    }) } };
                }
            } else init_rl: {
                const alloc_inst = if (align_inst == .none) ptr: {
                    const tag: Zir.Inst.Tag = if (is_comptime)
                        .alloc_inferred_comptime
                    else
                        .alloc_inferred;
                    break :ptr try gz.add_node(tag, node);
                } else ptr: {
                    break :ptr try gz.add_alloc_extended(.{
                        .node = node,
                        .type_inst = .none,
                        .align_inst = align_inst,
                        .is_const = true,
                        .is_comptime = is_comptime,
                    });
                };
                resolve_inferred_alloc = alloc_inst;
                break :init_rl .{ .inferred_ptr = alloc_inst };
            };
            const var_ptr = switch (init_rl) {
                .ptr => |ptr| ptr.inst,
                .inferred_ptr => |inst| inst,
                else => unreachable,
            };
            const init_result_info: ResultInfo = .{ .rl = init_rl, .ctx = .const_init };

            const prev_anon_name_strategy = gz.anon_name_strategy;
            gz.anon_name_strategy = .dbg_var;
            defer gz.anon_name_strategy = prev_anon_name_strategy;
            const init_inst = try reachable_expr(gz, scope, init_result_info, var_decl.ast.init_node, node);

            // The const init expression may have modified the error return trace, so signal
            // to Sema that it should save the new index for restoring later.
            if (node_may_append_to_error_trace(tree, var_decl.ast.init_node))
                _ = try gz.add_save_err_ret_index(.{ .if_of_error_type = init_inst });

            const const_ptr = if (resolve_inferred_alloc != .none) p: {
                _ = try gz.add_un_node(.resolve_inferred_alloc, resolve_inferred_alloc, node);
                break :p var_ptr;
            } else try gz.add_un_node(.make_ptr_const, var_ptr, node);

            try gz.add_dbg_var(.dbg_var_ptr, ident_name, const_ptr);

            const sub_scope = try block_arena.create(Scope.LocalPtr);
            sub_scope.* = .{
                .parent = scope,
                .gen_zir = gz,
                .name = ident_name,
                .ptr = const_ptr,
                .token_src = name_token,
                .maybe_comptime = true,
                .id_cat = .@"local constant",
            };
            return &sub_scope.base;
        },
        .keyword_var => {
            if (var_decl.comptime_token != null and gz.is_comptime)
                return astgen.fail_tok(var_decl.comptime_token.?, "'comptime var' is redundant in comptime scope", .{});
            const is_comptime = var_decl.comptime_token != null or gz.is_comptime;
            var resolve_inferred_alloc: Zir.Inst.Ref = .none;
            const alloc: Zir.Inst.Ref, const result_info: ResultInfo = if (var_decl.ast.type_node != 0) a: {
                const type_inst = try type_expr(gz, scope, var_decl.ast.type_node);
                const alloc = alloc: {
                    if (align_inst == .none) {
                        const tag: Zir.Inst.Tag = if (is_comptime)
                            .alloc_comptime_mut
                        else
                            .alloc_mut;
                        break :alloc try gz.add_un_node(tag, type_inst, node);
                    } else {
                        break :alloc try gz.add_alloc_extended(.{
                            .node = node,
                            .type_inst = type_inst,
                            .align_inst = align_inst,
                            .is_const = false,
                            .is_comptime = is_comptime,
                        });
                    }
                };
                break :a .{ alloc, .{ .rl = .{ .ptr = .{ .inst = alloc } } } };
            } else a: {
                const alloc = alloc: {
                    if (align_inst == .none) {
                        const tag: Zir.Inst.Tag = if (is_comptime)
                            .alloc_inferred_comptime_mut
                        else
                            .alloc_inferred_mut;
                        break :alloc try gz.add_node(tag, node);
                    } else {
                        break :alloc try gz.add_alloc_extended(.{
                            .node = node,
                            .type_inst = .none,
                            .align_inst = align_inst,
                            .is_const = false,
                            .is_comptime = is_comptime,
                        });
                    }
                };
                resolve_inferred_alloc = alloc;
                break :a .{ alloc, .{ .rl = .{ .inferred_ptr = alloc } } };
            };
            const prev_anon_name_strategy = gz.anon_name_strategy;
            gz.anon_name_strategy = .dbg_var;
            _ = try reachable_expr_comptime(gz, scope, result_info, var_decl.ast.init_node, node, is_comptime);
            gz.anon_name_strategy = prev_anon_name_strategy;
            if (resolve_inferred_alloc != .none) {
                _ = try gz.add_un_node(.resolve_inferred_alloc, resolve_inferred_alloc, node);
            }

            try gz.add_dbg_var(.dbg_var_ptr, ident_name, alloc);

            const sub_scope = try block_arena.create(Scope.LocalPtr);
            sub_scope.* = .{
                .parent = scope,
                .gen_zir = gz,
                .name = ident_name,
                .ptr = alloc,
                .token_src = name_token,
                .maybe_comptime = is_comptime,
                .id_cat = .@"local variable",
            };
            return &sub_scope.base;
        },
        else => unreachable,
    }
}

fn emit_dbg_node(gz: *GenZir, node: Ast.Node.Index) !void {
    // The instruction emitted here is for debugging runtime code.
    // If the current block will be evaluated only during semantic analysis
    // then no dbg_stmt ZIR instruction is needed.
    if (gz.is_comptime) return;
    const astgen = gz.astgen;
    astgen.advance_source_cursor_to_node(node);
    const line = astgen.source_line - gz.decl_line;
    const column = astgen.source_column;
    try emit_dbg_stmt(gz, .{ line, column });
}

fn assign(gz: *GenZir, scope: *Scope, infix_node: Ast.Node.Index) InnerError!void {
    try emit_dbg_node(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);

    const lhs = node_datas[infix_node].lhs;
    const rhs = node_datas[infix_node].rhs;
    if (node_tags[lhs] == .identifier) {
        // This intentionally does not support `@"_"` syntax.
        const ident_name = tree.token_slice(main_tokens[lhs]);
        if (mem.eql(u8, ident_name, "_")) {
            _ = try expr(gz, scope, .{ .rl = .discard, .ctx = .assignment }, rhs);
            return;
        }
    }
    const lvalue = try lval_expr(gz, scope, lhs);
    _ = try expr(gz, scope, .{ .rl = .{ .ptr = .{
        .inst = lvalue,
        .src_node = infix_node,
    } } }, rhs);
}

/// Handles destructure assignments where no LHS is a `const` or `var` decl.
fn assign_destructure(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!void {
    try emit_dbg_node(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);

    const full = tree.assign_destructure(node);
    if (full.comptime_token != null and gz.is_comptime) {
        return astgen.fail_node(node, "redundant comptime keyword in already comptime scope", .{});
    }

    // If this expression is marked comptime, we must wrap the whole thing in a comptime block.
    var gz_buf: GenZir = undefined;
    const inner_gz = if (full.comptime_token) |_| bs: {
        gz_buf = gz.make_sub_block(scope);
        gz_buf.is_comptime = true;
        break :bs &gz_buf;
    } else gz;
    defer if (full.comptime_token) |_| inner_gz.unstack();

    const rl_components = try astgen.arena.alloc(ResultInfo.Loc.DestructureComponent, full.ast.variables.len);
    for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
        if (node_tags[variable_node] == .identifier) {
            // This intentionally does not support `@"_"` syntax.
            const ident_name = tree.token_slice(main_tokens[variable_node]);
            if (mem.eql(u8, ident_name, "_")) {
                variable_rl.* = .discard;
                continue;
            }
        }
        variable_rl.* = .{ .typed_ptr = .{
            .inst = try lval_expr(inner_gz, scope, variable_node),
            .src_node = variable_node,
        } };
    }

    const ri: ResultInfo = .{ .rl = .{ .destructure = .{
        .src_node = node,
        .components = rl_components,
    } } };

    _ = try expr(inner_gz, scope, ri, full.ast.value_expr);

    if (full.comptime_token) |_| {
        const comptime_block_inst = try gz.make_block_inst(.block_comptime, node);
        _ = try inner_gz.add_break(.@"break", comptime_block_inst, .void_value);
        try inner_gz.set_block_body(comptime_block_inst);
        try gz.instructions.append(gz.astgen.gpa, comptime_block_inst);
    }
}

/// Handles destructure assignments where the LHS may contain `const` or `var` decls.
fn assign_destructure_maybe_decls(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    block_arena: Allocator,
) InnerError!*Scope {
    try emit_dbg_node(gz, node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const node_tags = tree.nodes.items(.tag);

    const full = tree.assign_destructure(node);
    if (full.comptime_token != null and gz.is_comptime) {
        return astgen.fail_node(node, "redundant comptime keyword in already comptime scope", .{});
    }

    const is_comptime = full.comptime_token != null or gz.is_comptime;
    const value_is_comptime = node_tags[full.ast.value_expr] == .@"comptime";

    // When declaring consts via a destructure, we always use a result pointer.
    // This avoids the need to create tuple types, and is also likely easier to
    // optimize, since it's a bit tricky for the optimizer to "split up" the
    // value into individual pointer writes down the line.

    // We know this rl information won't live past the evaluation of this
    // expression, so it may as well go in the block arena.
    const rl_components = try block_arena.alloc(ResultInfo.Loc.DestructureComponent, full.ast.variables.len);
    var any_non_const_variables = false;
    var any_lvalue_expr = false;
    for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
        switch (node_tags[variable_node]) {
            .identifier => {
                // This intentionally does not support `@"_"` syntax.
                const ident_name = tree.token_slice(main_tokens[variable_node]);
                if (mem.eql(u8, ident_name, "_")) {
                    any_non_const_variables = true;
                    variable_rl.* = .discard;
                    continue;
                }
            },
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                const full_var_decl = tree.full_var_decl(variable_node).?;

                const name_token = full_var_decl.ast.mut_token + 1;
                const ident_name_raw = tree.token_slice(name_token);
                if (mem.eql(u8, ident_name_raw, "_")) {
                    return astgen.fail_tok(name_token, "'_' used as an identifier without @\"_\" syntax", .{});
                }

                // We detect shadowing in the second pass over these, while we're creating scopes.

                if (full_var_decl.ast.addrspace_node != 0) {
                    return astgen.fail_tok(main_tokens[full_var_decl.ast.addrspace_node], "cannot set address space of local variable '{s}'", .{ident_name_raw});
                }
                if (full_var_decl.ast.section_node != 0) {
                    return astgen.fail_tok(main_tokens[full_var_decl.ast.section_node], "cannot set section of local variable '{s}'", .{ident_name_raw});
                }

                const is_const = switch (token_tags[full_var_decl.ast.mut_token]) {
                    .keyword_var => false,
                    .keyword_const => true,
                    else => unreachable,
                };
                if (!is_const) any_non_const_variables = true;

                // We also mark `const`s as comptime if the RHS is definitely comptime-known.
                const this_variable_comptime = is_comptime or (is_const and value_is_comptime);

                const align_inst: Zir.Inst.Ref = if (full_var_decl.ast.align_node != 0)
                    try expr(gz, scope, coerced_align_ri, full_var_decl.ast.align_node)
                else
                    .none;

                if (full_var_decl.ast.type_node != 0) {
                    // Typed alloc
                    const type_inst = try type_expr(gz, scope, full_var_decl.ast.type_node);
                    const ptr = if (align_inst == .none) ptr: {
                        const tag: Zir.Inst.Tag = if (is_const)
                            .alloc
                        else if (this_variable_comptime)
                            .alloc_comptime_mut
                        else
                            .alloc_mut;
                        break :ptr try gz.add_un_node(tag, type_inst, node);
                    } else try gz.add_alloc_extended(.{
                        .node = node,
                        .type_inst = type_inst,
                        .align_inst = align_inst,
                        .is_const = is_const,
                        .is_comptime = this_variable_comptime,
                    });
                    variable_rl.* = .{ .typed_ptr = .{ .inst = ptr } };
                } else {
                    // Inferred alloc
                    const ptr = if (align_inst == .none) ptr: {
                        const tag: Zir.Inst.Tag = if (is_const) tag: {
                            break :tag if (this_variable_comptime) .alloc_inferred_comptime else .alloc_inferred;
                        } else tag: {
                            break :tag if (this_variable_comptime) .alloc_inferred_comptime_mut else .alloc_inferred_mut;
                        };
                        break :ptr try gz.add_node(tag, node);
                    } else try gz.add_alloc_extended(.{
                        .node = node,
                        .type_inst = .none,
                        .align_inst = align_inst,
                        .is_const = is_const,
                        .is_comptime = this_variable_comptime,
                    });
                    variable_rl.* = .{ .inferred_ptr = ptr };
                }

                continue;
            },
            else => {},
        }
        // This variable is just an lvalue expression.
        // We will fill in its result pointer later, inside a comptime block.
        any_non_const_variables = true;
        any_lvalue_expr = true;
        variable_rl.* = .{ .typed_ptr = .{
            .inst = undefined,
            .src_node = variable_node,
        } };
    }

    if (full.comptime_token != null and !any_non_const_variables) {
        try astgen.append_error_tok(full.comptime_token.?, "'comptime const' is redundant; instead wrap the initialization expression with 'comptime'", .{});
    }

    // If this expression is marked comptime, we must wrap it in a comptime block.
    var gz_buf: GenZir = undefined;
    const inner_gz = if (full.comptime_token) |_| bs: {
        gz_buf = gz.make_sub_block(scope);
        gz_buf.is_comptime = true;
        break :bs &gz_buf;
    } else gz;
    defer if (full.comptime_token) |_| inner_gz.unstack();

    if (any_lvalue_expr) {
        // At least one variable was an lvalue expr. Iterate again in order to
        // evaluate the lvalues from within the possible block_comptime.
        for (rl_components, full.ast.variables) |*variable_rl, variable_node| {
            if (variable_rl.* != .typed_ptr) continue;
            switch (node_tags[variable_node]) {
                .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => continue,
                else => {},
            }
            variable_rl.typed_ptr.inst = try lval_expr(inner_gz, scope, variable_node);
        }
    }

    // We can't give a reasonable anon name strategy for destructured inits, so
    // leave it at its default of `.anon`.
    _ = try reachable_expr(inner_gz, scope, .{ .rl = .{ .destructure = .{
        .src_node = node,
        .components = rl_components,
    } } }, full.ast.value_expr, node);

    if (full.comptime_token) |_| {
        // Finish the block_comptime. Inferred alloc resolution etc will occur
        // in the parent block.
        const comptime_block_inst = try gz.make_block_inst(.block_comptime, node);
        _ = try inner_gz.add_break(.@"break", comptime_block_inst, .void_value);
        try inner_gz.set_block_body(comptime_block_inst);
        try gz.instructions.append(gz.astgen.gpa, comptime_block_inst);
    }

    // Now, iterate over the variable exprs to construct any new scopes.
    // If there were any inferred allocations, resolve them.
    // If there were any `const` decls, make the pointer constant.
    var cur_scope = scope;
    for (rl_components, full.ast.variables) |variable_rl, variable_node| {
        switch (node_tags[variable_node]) {
            .local_var_decl, .simple_var_decl, .aligned_var_decl => {},
            else => continue, // We were mutating an existing lvalue - nothing to do
        }
        const full_var_decl = tree.full_var_decl(variable_node).?;
        const raw_ptr = switch (variable_rl) {
            .discard => unreachable,
            .typed_ptr => |typed_ptr| typed_ptr.inst,
            .inferred_ptr => |ptr_inst| ptr_inst,
        };
        // If the alloc was inferred, resolve it.
        if (full_var_decl.ast.type_node == 0) {
            _ = try gz.add_un_node(.resolve_inferred_alloc, raw_ptr, variable_node);
        }
        const is_const = switch (token_tags[full_var_decl.ast.mut_token]) {
            .keyword_var => false,
            .keyword_const => true,
            else => unreachable,
        };
        // If the alloc was const, make it const.
        const var_ptr = if (is_const and full_var_decl.ast.type_node != 0) make_const: {
            // Note that we don't do this if type_node == 0 since `resolve_inferred_alloc`
            // handles it for us.
            break :make_const try gz.add_un_node(.make_ptr_const, raw_ptr, node);
        } else raw_ptr;
        const name_token = full_var_decl.ast.mut_token + 1;
        const ident_name_raw = tree.token_slice(name_token);
        const ident_name = try astgen.ident_as_string(name_token);
        try astgen.detect_local_shadowing(
            cur_scope,
            ident_name,
            name_token,
            ident_name_raw,
            if (is_const) .@"local constant" else .@"local variable",
        );
        try gz.add_dbg_var(.dbg_var_ptr, ident_name, var_ptr);
        // Finally, create the scope.
        const sub_scope = try block_arena.create(Scope.LocalPtr);
        sub_scope.* = .{
            .parent = cur_scope,
            .gen_zir = gz,
            .name = ident_name,
            .ptr = var_ptr,
            .token_src = name_token,
            .maybe_comptime = is_const or is_comptime,
            .id_cat = if (is_const) .@"local constant" else .@"local variable",
        };
        cur_scope = &sub_scope.base;
    }

    return cur_scope;
}

fn assign_op(
    gz: *GenZir,
    scope: *Scope,
    infix_node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!void {
    try emit_dbg_node(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const lhs_ptr = try lval_expr(gz, scope, node_datas[infix_node].lhs);

    const cursor = switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => maybe_advance_source_cursor_to_main_token(gz, infix_node),
        else => undefined,
    };
    const lhs = try gz.add_un_node(.load, lhs_ptr, infix_node);
    const lhs_type = try gz.add_un_node(.typeof, lhs, infix_node);
    const rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = lhs_type } }, node_datas[infix_node].rhs);

    switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => {
            try emit_dbg_stmt(gz, cursor);
        },
        else => {},
    }
    const result = try gz.add_pl_node(op_inst_tag, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.add_pl_node(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn assign_shift(
    gz: *GenZir,
    scope: *Scope,
    infix_node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!void {
    try emit_dbg_node(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const lhs_ptr = try lval_expr(gz, scope, node_datas[infix_node].lhs);
    const lhs = try gz.add_un_node(.load, lhs_ptr, infix_node);
    const rhs_type = try gz.add_un_node(.typeof_log2_int_type, lhs, infix_node);
    const rhs = try expr(gz, scope, .{ .rl = .{ .ty = rhs_type } }, node_datas[infix_node].rhs);

    const result = try gz.add_pl_node(op_inst_tag, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.add_pl_node(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn assign_shift_sat(gz: *GenZir, scope: *Scope, infix_node: Ast.Node.Index) InnerError!void {
    try emit_dbg_node(gz, infix_node);
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const lhs_ptr = try lval_expr(gz, scope, node_datas[infix_node].lhs);
    const lhs = try gz.add_un_node(.load, lhs_ptr, infix_node);
    // Saturating shift-left allows any integer type for both the LHS and RHS.
    const rhs = try expr(gz, scope, .{ .rl = .none }, node_datas[infix_node].rhs);

    const result = try gz.add_pl_node(.shl_sat, infix_node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    _ = try gz.add_pl_node(.store_node, infix_node, Zir.Inst.Bin{
        .lhs = lhs_ptr,
        .rhs = result,
    });
}

fn ptr_type(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    ptr_info: Ast.full.PtrType,
) InnerError!Zir.Inst.Ref {
    if (ptr_info.size == .C and ptr_info.allowzero_token != null) {
        return gz.astgen.fail_tok(ptr_info.allowzero_token.?, "C pointers always allow address zero", .{});
    }

    const source_offset = gz.astgen.source_offset;
    const source_line = gz.astgen.source_line;
    const source_column = gz.astgen.source_column;
    const elem_type = try type_expr(gz, scope, ptr_info.ast.child_type);

    var sentinel_ref: Zir.Inst.Ref = .none;
    var align_ref: Zir.Inst.Ref = .none;
    var addrspace_ref: Zir.Inst.Ref = .none;
    var bit_start_ref: Zir.Inst.Ref = .none;
    var bit_end_ref: Zir.Inst.Ref = .none;
    var trailing_count: u32 = 0;

    if (ptr_info.ast.sentinel != 0) {
        // These attributes can appear in any order and they all come before the
        // element type so we need to reset the source cursor before generating them.
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        sentinel_ref = try comptime_expr(gz, scope, .{ .rl = .{ .ty = elem_type } }, ptr_info.ast.sentinel);
        trailing_count += 1;
    }
    if (ptr_info.ast.addrspace_node != 0) {
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        addrspace_ref = try expr(gz, scope, coerced_addrspace_ri, ptr_info.ast.addrspace_node);
        trailing_count += 1;
    }
    if (ptr_info.ast.align_node != 0) {
        gz.astgen.source_offset = source_offset;
        gz.astgen.source_line = source_line;
        gz.astgen.source_column = source_column;

        align_ref = try expr(gz, scope, coerced_align_ri, ptr_info.ast.align_node);
        trailing_count += 1;
    }
    if (ptr_info.ast.bit_range_start != 0) {
        assert(ptr_info.ast.bit_range_end != 0);
        bit_start_ref = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .u16_type } }, ptr_info.ast.bit_range_start);
        bit_end_ref = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .u16_type } }, ptr_info.ast.bit_range_end);
        trailing_count += 2;
    }

    const gpa = gz.astgen.gpa;
    try gz.instructions.ensure_unused_capacity(gpa, 1);
    try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);
    try gz.astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.PtrType).Struct.fields.len +
        trailing_count);

    const payload_index = gz.astgen.add_extra_assume_capacity(Zir.Inst.PtrType{
        .elem_type = elem_type,
        .src_node = gz.node_index_to_relative(node),
    });
    if (sentinel_ref != .none) {
        gz.astgen.extra.append_assume_capacity(@int_from_enum(sentinel_ref));
    }
    if (align_ref != .none) {
        gz.astgen.extra.append_assume_capacity(@int_from_enum(align_ref));
    }
    if (addrspace_ref != .none) {
        gz.astgen.extra.append_assume_capacity(@int_from_enum(addrspace_ref));
    }
    if (bit_start_ref != .none) {
        gz.astgen.extra.append_assume_capacity(@int_from_enum(bit_start_ref));
        gz.astgen.extra.append_assume_capacity(@int_from_enum(bit_end_ref));
    }

    const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
    const result = new_index.to_ref();
    gz.astgen.instructions.append_assume_capacity(.{ .tag = .ptr_type, .data = .{
        .ptr_type = .{
            .flags = .{
                .is_allowzero = ptr_info.allowzero_token != null,
                .is_mutable = ptr_info.const_token == null,
                .is_volatile = ptr_info.volatile_token != null,
                .has_sentinel = sentinel_ref != .none,
                .has_align = align_ref != .none,
                .has_addrspace = addrspace_ref != .none,
                .has_bit_range = bit_start_ref != .none,
            },
            .size = ptr_info.size,
            .payload_index = payload_index,
        },
    } });
    gz.instructions.append_assume_capacity(new_index);

    return rvalue(gz, ri, result, node);
}

fn array_type(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) !Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    const len_node = node_datas[node].lhs;
    if (node_tags[len_node] == .identifier and
        mem.eql(u8, tree.token_slice(main_tokens[len_node]), "_"))
    {
        return astgen.fail_node(len_node, "unable to infer array size", .{});
    }
    const len = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, len_node);
    const elem_type = try type_expr(gz, scope, node_datas[node].rhs);

    const result = try gz.add_pl_node(.array_type, node, Zir.Inst.Bin{
        .lhs = len,
        .rhs = elem_type,
    });
    return rvalue(gz, ri, result, node);
}

fn array_type_sentinel(gz: *GenZir, scope: *Scope, ri: ResultInfo, node: Ast.Node.Index) !Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const extra = tree.extra_data(node_datas[node].rhs, Ast.Node.ArrayTypeSentinel);

    const len_node = node_datas[node].lhs;
    if (node_tags[len_node] == .identifier and
        mem.eql(u8, tree.token_slice(main_tokens[len_node]), "_"))
    {
        return astgen.fail_node(len_node, "unable to infer array size", .{});
    }
    const len = try reachable_expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, len_node, node);
    const elem_type = try type_expr(gz, scope, extra.elem_type);
    const sentinel = try reachable_expr_comptime(gz, scope, .{ .rl = .{ .coerced_ty = elem_type } }, extra.sentinel, node, true);

    const result = try gz.add_pl_node(.array_type_sentinel, node, Zir.Inst.ArrayTypeSentinel{
        .len = len,
        .elem_type = elem_type,
        .sentinel = sentinel,
    });
    return rvalue(gz, ri, result, node);
}

const WipMembers = struct {
    payload: *ArrayListUnmanaged(u32),
    payload_top: usize,
    field_bits_start: u32,
    fields_start: u32,
    fields_end: u32,
    decl_index: u32 = 0,
    field_index: u32 = 0,

    const Self = @This();

    fn init(gpa: Allocator, payload: *ArrayListUnmanaged(u32), decl_count: u32, field_count: u32, comptime bits_per_field: u32, comptime max_field_size: u32) Allocator.Error!Self {
        const payload_top: u32 = @int_cast(payload.items.len);
        const field_bits_start = payload_top + decl_count;
        const fields_start = field_bits_start + if (bits_per_field > 0) blk: {
            const fields_per_u32 = 32 / bits_per_field;
            break :blk (field_count + fields_per_u32 - 1) / fields_per_u32;
        } else 0;
        const payload_end = fields_start + field_count * max_field_size;
        try payload.resize(gpa, payload_end);
        return .{
            .payload = payload,
            .payload_top = payload_top,
            .field_bits_start = field_bits_start,
            .fields_start = fields_start,
            .fields_end = fields_start,
        };
    }

    fn next_decl(self: *Self, decl_inst: Zir.Inst.Index) void {
        self.payload.items[self.payload_top + self.decl_index] = @int_from_enum(decl_inst);
        self.decl_index += 1;
    }

    fn next_field(self: *Self, comptime bits_per_field: u32, bits: [bits_per_field]bool) void {
        const fields_per_u32 = 32 / bits_per_field;
        const index = self.field_bits_start + self.field_index / fields_per_u32;
        assert(index < self.fields_start);
        var bit_bag: u32 = if (self.field_index % fields_per_u32 == 0) 0 else self.payload.items[index];
        bit_bag >>= bits_per_field;
        comptime var i = 0;
        inline while (i < bits_per_field) : (i += 1) {
            bit_bag |= @as(u32, @int_from_bool(bits[i])) << (32 - bits_per_field + i);
        }
        self.payload.items[index] = bit_bag;
        self.field_index += 1;
    }

    fn append_to_field(self: *Self, data: u32) void {
        assert(self.fields_end < self.payload.items.len);
        self.payload.items[self.fields_end] = data;
        self.fields_end += 1;
    }

    fn finish_bits(self: *Self, comptime bits_per_field: u32) void {
        if (bits_per_field > 0) {
            const fields_per_u32 = 32 / bits_per_field;
            const empty_field_slots = fields_per_u32 - (self.field_index % fields_per_u32);
            if (self.field_index > 0 and empty_field_slots < fields_per_u32) {
                const index = self.field_bits_start + self.field_index / fields_per_u32;
                self.payload.items[index] >>= @int_cast(empty_field_slots * bits_per_field);
            }
        }
    }

    fn decls_slice(self: *Self) []u32 {
        return self.payload.items[self.payload_top..][0..self.decl_index];
    }

    fn fields_slice(self: *Self) []u32 {
        return self.payload.items[self.field_bits_start..self.fields_end];
    }

    fn deinit(self: *Self) void {
        self.payload.items.len = self.payload_top;
    }
};

fn fn_decl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    decl_node: Ast.Node.Index,
    body_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
) InnerError!void {
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    // missing function name already happened in scan_decls()
    const fn_name_token = fn_proto.name_token orelse return error.AnalysisFail;

    // We insert this at the beginning so that its instruction index marks the
    // start of the top level declaration.
    const decl_inst = try gz.make_block_inst(.declaration, fn_proto.ast.proto_node);
    astgen.advance_source_cursor_to_node(decl_node);

    var decl_gz: GenZir = .{
        .is_comptime = true,
        .decl_node_index = fn_proto.ast.proto_node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer decl_gz.unstack();

    var fn_gz: GenZir = .{
        .is_comptime = false,
        .decl_node_index = fn_proto.ast.proto_node,
        .decl_line = decl_gz.decl_line,
        .parent = &decl_gz.base,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = GenZir.unstacked_top,
    };
    defer fn_gz.unstack();

    // Set this now, since parameter types, return type, etc may be generic.
    const prev_within_fn = astgen.within_fn;
    defer astgen.within_fn = prev_within_fn;
    astgen.within_fn = true;

    const is_pub = fn_proto.visib_token != null;
    const is_export = blk: {
        const maybe_export_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk token_tags[maybe_export_token] == .keyword_export;
    };
    const is_extern = blk: {
        const maybe_extern_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk token_tags[maybe_extern_token] == .keyword_extern;
    };
    const has_inline_keyword = blk: {
        const maybe_inline_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk token_tags[maybe_inline_token] == .keyword_inline;
    };
    const is_noinline = blk: {
        const maybe_noinline_token = fn_proto.extern_export_inline_token orelse break :blk false;
        break :blk token_tags[maybe_noinline_token] == .keyword_noinline;
    };

    const doc_comment_index = try astgen.doc_comment_as_string(fn_proto.first_token());

    wip_members.next_decl(decl_inst);

    var noalias_bits: u32 = 0;
    var params_scope = &fn_gz.base;
    const is_var_args = is_var_args: {
        var param_type_i: usize = 0;
        var it = fn_proto.iterate(tree);
        while (it.next()) |param| : (param_type_i += 1) {
            const is_comptime = if (param.comptime_noalias) |token| switch (token_tags[token]) {
                .keyword_noalias => is_comptime: {
                    noalias_bits |= @as(u32, 1) << (std.math.cast(u5, param_type_i) orelse
                        return astgen.fail_tok(token, "this compiler implementation only supports 'noalias' on the first 32 parameters", .{}));
                    break :is_comptime false;
                },
                .keyword_comptime => true,
                else => false,
            } else false;

            const is_anytype = if (param.anytype_ellipsis3) |token| blk: {
                switch (token_tags[token]) {
                    .keyword_anytype => break :blk true,
                    .ellipsis3 => break :is_var_args true,
                    else => unreachable,
                }
            } else false;

            const param_name: Zir.NullTerminatedString = if (param.name_token) |name_token| blk: {
                const name_bytes = tree.token_slice(name_token);
                if (mem.eql(u8, "_", name_bytes))
                    break :blk .empty;

                const param_name = try astgen.ident_as_string(name_token);
                if (!is_extern) {
                    try astgen.detect_local_shadowing(params_scope, param_name, name_token, name_bytes, .@"function parameter");
                }
                break :blk param_name;
            } else if (!is_extern) {
                if (param.anytype_ellipsis3) |tok| {
                    return astgen.fail_tok(tok, "missing parameter name", .{});
                } else {
                    ambiguous: {
                        if (tree.nodes.items(.tag)[param.type_expr] != .identifier) break :ambiguous;
                        const main_token = tree.nodes.items(.main_token)[param.type_expr];
                        const identifier_str = tree.token_slice(main_token);
                        if (is_primitive(identifier_str)) break :ambiguous;
                        return astgen.fail_node_notes(
                            param.type_expr,
                            "missing parameter name or type",
                            .{},
                            &[_]u32{
                                try astgen.err_note_node(
                                    param.type_expr,
                                    "if this is a name, annotate its type '{s}: T'",
                                    .{identifier_str},
                                ),
                                try astgen.err_note_node(
                                    param.type_expr,
                                    "if this is a type, give it a name '<name>: {s}'",
                                    .{identifier_str},
                                ),
                            },
                        );
                    }
                    return astgen.fail_node(param.type_expr, "missing parameter name", .{});
                }
            } else .empty;

            const param_inst = if (is_anytype) param: {
                const name_token = param.name_token orelse param.anytype_ellipsis3.?;
                const tag: Zir.Inst.Tag = if (is_comptime)
                    .param_anytype_comptime
                else
                    .param_anytype;
                break :param try decl_gz.add_str_tok(tag, param_name, name_token);
            } else param: {
                const param_type_node = param.type_expr;
                assert(param_type_node != 0);
                var param_gz = decl_gz.make_sub_block(scope);
                defer param_gz.unstack();
                const param_type = try full_body_expr(&param_gz, params_scope, coerced_type_ri, param_type_node);
                const param_inst_expected: Zir.Inst.Index = @enumFromInt(astgen.instructions.len + 1);
                _ = try param_gz.add_break_with_src_node(.break_inline, param_inst_expected, param_type, param_type_node);

                const main_tokens = tree.nodes.items(.main_token);
                const name_token = param.name_token orelse main_tokens[param_type_node];
                const tag: Zir.Inst.Tag = if (is_comptime) .param_comptime else .param;
                const param_inst = try decl_gz.add_param(&param_gz, tag, name_token, param_name, param.first_doc_comment);
                assert(param_inst_expected == param_inst);
                break :param param_inst.to_ref();
            };

            if (param_name == .empty or is_extern) continue;

            const sub_scope = try astgen.arena.create(Scope.LocalVal);
            sub_scope.* = .{
                .parent = params_scope,
                .gen_zir = &decl_gz,
                .name = param_name,
                .inst = param_inst,
                .token_src = param.name_token.?,
                .id_cat = .@"function parameter",
            };
            params_scope = &sub_scope.base;
        }
        break :is_var_args false;
    };

    const lib_name = if (fn_proto.lib_name) |lib_name_token| blk: {
        const lib_name_str = try astgen.str_lit_as_string(lib_name_token);
        const lib_name_slice = astgen.string_bytes.items[@int_from_enum(lib_name_str.index)..][0..lib_name_str.len];
        if (mem.index_of_scalar(u8, lib_name_slice, 0) != null) {
            return astgen.fail_tok(lib_name_token, "library name cannot contain null bytes", .{});
        } else if (lib_name_str.len == 0) {
            return astgen.fail_tok(lib_name_token, "library name cannot be empty", .{});
        }
        break :blk lib_name_str.index;
    } else .empty;

    const maybe_bang = tree.first_token(fn_proto.ast.return_type) - 1;
    const is_inferred_error = token_tags[maybe_bang] == .bang;

    // After creating the function ZIR instruction, it will need to update the break
    // instructions inside the expression blocks for align, addrspace, cc, and ret_ty
    // to use the function instruction as the "block" to break from.

    var align_gz = decl_gz.make_sub_block(params_scope);
    defer align_gz.unstack();
    const align_ref: Zir.Inst.Ref = if (fn_proto.ast.align_expr == 0) .none else inst: {
        const inst = try expr(&decl_gz, params_scope, coerced_align_ri, fn_proto.ast.align_expr);
        if (align_gz.instructions_slice().len == 0) {
            // In this case we will send a len=0 body which can be encoded more efficiently.
            break :inst inst;
        }
        _ = try align_gz.add_break(.break_inline, @enumFromInt(0), inst);
        break :inst inst;
    };

    var addrspace_gz = decl_gz.make_sub_block(params_scope);
    defer addrspace_gz.unstack();
    const addrspace_ref: Zir.Inst.Ref = if (fn_proto.ast.addrspace_expr == 0) .none else inst: {
        const inst = try expr(&decl_gz, params_scope, coerced_addrspace_ri, fn_proto.ast.addrspace_expr);
        if (addrspace_gz.instructions_slice().len == 0) {
            // In this case we will send a len=0 body which can be encoded more efficiently.
            break :inst inst;
        }
        _ = try addrspace_gz.add_break(.break_inline, @enumFromInt(0), inst);
        break :inst inst;
    };

    var section_gz = decl_gz.make_sub_block(params_scope);
    defer section_gz.unstack();
    const section_ref: Zir.Inst.Ref = if (fn_proto.ast.section_expr == 0) .none else inst: {
        const inst = try expr(&decl_gz, params_scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, fn_proto.ast.section_expr);
        if (section_gz.instructions_slice().len == 0) {
            // In this case we will send a len=0 body which can be encoded more efficiently.
            break :inst inst;
        }
        _ = try section_gz.add_break(.break_inline, @enumFromInt(0), inst);
        break :inst inst;
    };

    var cc_gz = decl_gz.make_sub_block(params_scope);
    defer cc_gz.unstack();
    const cc_ref: Zir.Inst.Ref = blk: {
        if (fn_proto.ast.callconv_expr != 0) {
            if (has_inline_keyword) {
                return astgen.fail_node(
                    fn_proto.ast.callconv_expr,
                    "explicit callconv incompatible with inline keyword",
                    .{},
                );
            }
            const inst = try expr(
                &decl_gz,
                params_scope,
                .{ .rl = .{ .coerced_ty = .calling_convention_type } },
                fn_proto.ast.callconv_expr,
            );
            if (cc_gz.instructions_slice().len == 0) {
                // In this case we will send a len=0 body which can be encoded more efficiently.
                break :blk inst;
            }
            _ = try cc_gz.add_break(.break_inline, @enumFromInt(0), inst);
            break :blk inst;
        } else if (is_extern) {
            // note: https://github.com/ziglang/zig/issues/5269
            break :blk .calling_convention_c;
        } else if (has_inline_keyword) {
            break :blk .calling_convention_inline;
        } else {
            break :blk .none;
        }
    };

    var ret_gz = decl_gz.make_sub_block(params_scope);
    defer ret_gz.unstack();
    const ret_ref: Zir.Inst.Ref = inst: {
        const inst = try full_body_expr(&ret_gz, params_scope, coerced_type_ri, fn_proto.ast.return_type);
        if (ret_gz.instructions_slice().len == 0) {
            // In this case we will send a len=0 body which can be encoded more efficiently.
            break :inst inst;
        }
        _ = try ret_gz.add_break(.break_inline, @enumFromInt(0), inst);
        break :inst inst;
    };

    const func_inst: Zir.Inst.Ref = if (body_node == 0) func: {
        if (!is_extern) {
            return astgen.fail_tok(fn_proto.ast.fn_token, "non-extern function has no body", .{});
        }
        if (is_inferred_error) {
            return astgen.fail_tok(maybe_bang, "function prototype may not have inferred error set", .{});
        }
        break :func try decl_gz.add_func(.{
            .src_node = decl_node,
            .cc_ref = cc_ref,
            .cc_gz = &cc_gz,
            .align_ref = align_ref,
            .align_gz = &align_gz,
            .ret_ref = ret_ref,
            .ret_gz = &ret_gz,
            .section_ref = section_ref,
            .section_gz = &section_gz,
            .addrspace_ref = addrspace_ref,
            .addrspace_gz = &addrspace_gz,
            .param_block = decl_inst,
            .body_gz = null,
            .lib_name = lib_name,
            .is_var_args = is_var_args,
            .is_inferred_error = false,
            .is_test = false,
            .is_extern = true,
            .is_noinline = is_noinline,
            .noalias_bits = noalias_bits,
        });
    } else func: {
        // as a scope, fn_gz encloses ret_gz, but for instruction list, fn_gz stacks on ret_gz
        fn_gz.instructions_top = ret_gz.instructions.items.len;

        const prev_fn_block = astgen.fn_block;
        const prev_fn_ret_ty = astgen.fn_ret_ty;
        defer {
            astgen.fn_block = prev_fn_block;
            astgen.fn_ret_ty = prev_fn_ret_ty;
        }
        astgen.fn_block = &fn_gz;
        astgen.fn_ret_ty = if (is_inferred_error or ret_ref.to_index() != null) r: {
            // We're essentially guaranteed to need the return type at some point,
            // since the return type is likely not `void` or `noreturn` so there
            // will probably be an explicit return requiring RLS. Fetch this
            // return type now so the rest of the function can use it.
            break :r try fn_gz.add_node(.ret_type, decl_node);
        } else ret_ref;

        const prev_var_args = astgen.fn_var_args;
        astgen.fn_var_args = is_var_args;
        defer astgen.fn_var_args = prev_var_args;

        astgen.advance_source_cursor_to_node(body_node);
        const lbrace_line = astgen.source_line - decl_gz.decl_line;
        const lbrace_column = astgen.source_column;

        _ = try full_body_expr(&fn_gz, params_scope, .{ .rl = .none }, body_node);
        try check_used(gz, &fn_gz.base, params_scope);

        if (!fn_gz.ends_with_no_return()) {
            // As our last action before the return, "pop" the error trace if needed
            _ = try fn_gz.add_restore_err_ret_index(.ret, .always, decl_node);

            // Add implicit return at end of function.
            _ = try fn_gz.add_un_tok(.ret_implicit, .void_value, tree.last_token(body_node));
        }

        break :func try decl_gz.add_func(.{
            .src_node = decl_node,
            .cc_ref = cc_ref,
            .cc_gz = &cc_gz,
            .align_ref = align_ref,
            .align_gz = &align_gz,
            .ret_ref = ret_ref,
            .ret_gz = &ret_gz,
            .section_ref = section_ref,
            .section_gz = &section_gz,
            .addrspace_ref = addrspace_ref,
            .addrspace_gz = &addrspace_gz,
            .lbrace_line = lbrace_line,
            .lbrace_column = lbrace_column,
            .param_block = decl_inst,
            .body_gz = &fn_gz,
            .lib_name = lib_name,
            .is_var_args = is_var_args,
            .is_inferred_error = is_inferred_error,
            .is_test = false,
            .is_extern = false,
            .is_noinline = is_noinline,
            .noalias_bits = noalias_bits,
        });
    };

    // We add this at the end so that its instruction index marks the end range
    // of the top level declaration. add_func already unstacked fn_gz and ret_gz.
    _ = try decl_gz.add_break(.break_inline, decl_inst, func_inst);

    try set_declaration(
        decl_inst,
        std.zig.hash_src(tree.get_node_source(decl_node)),
        .{ .named = fn_name_token },
        decl_gz.decl_line - gz.decl_line,
        is_pub,
        is_export,
        doc_comment_index,
        &decl_gz,
        // align, linksection, and addrspace are passed in the func instruction in this case.
        // TODO: move them from the function instruction to the declaration instruction?
        null,
    );
}

fn global_var_decl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
    var_decl: Ast.full.VarDecl,
) InnerError!void {
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    const is_mutable = token_tags[var_decl.ast.mut_token] == .keyword_var;
    // We do this at the beginning so that the instruction index marks the range start
    // of the top level declaration.
    const decl_inst = try gz.make_block_inst(.declaration, node);

    const name_token = var_decl.ast.mut_token + 1;
    astgen.advance_source_cursor_to_node(node);

    var block_scope: GenZir = .{
        .parent = scope,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .astgen = astgen,
        .is_comptime = true,
        .anon_name_strategy = .parent,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer block_scope.unstack();

    const is_pub = var_decl.visib_token != null;
    const is_export = blk: {
        const maybe_export_token = var_decl.extern_export_token orelse break :blk false;
        break :blk token_tags[maybe_export_token] == .keyword_export;
    };
    const is_extern = blk: {
        const maybe_extern_token = var_decl.extern_export_token orelse break :blk false;
        break :blk token_tags[maybe_extern_token] == .keyword_extern;
    };
    wip_members.next_decl(decl_inst);

    const is_threadlocal = if (var_decl.threadlocal_token) |tok| blk: {
        if (!is_mutable) {
            return astgen.fail_tok(tok, "threadlocal variable cannot be constant", .{});
        }
        break :blk true;
    } else false;

    const lib_name = if (var_decl.lib_name) |lib_name_token| blk: {
        const lib_name_str = try astgen.str_lit_as_string(lib_name_token);
        const lib_name_slice = astgen.string_bytes.items[@int_from_enum(lib_name_str.index)..][0..lib_name_str.len];
        if (mem.index_of_scalar(u8, lib_name_slice, 0) != null) {
            return astgen.fail_tok(lib_name_token, "library name cannot contain null bytes", .{});
        } else if (lib_name_str.len == 0) {
            return astgen.fail_tok(lib_name_token, "library name cannot be empty", .{});
        }
        break :blk lib_name_str.index;
    } else .empty;

    const doc_comment_index = try astgen.doc_comment_as_string(var_decl.first_token());

    assert(var_decl.comptime_token == null); // handled by parser

    const var_inst: Zir.Inst.Ref = if (var_decl.ast.init_node != 0) vi: {
        if (is_extern) {
            return astgen.fail_node(
                var_decl.ast.init_node,
                "extern variables have no initializers",
                .{},
            );
        }

        const type_inst: Zir.Inst.Ref = if (var_decl.ast.type_node != 0)
            try expr(
                &block_scope,
                &block_scope.base,
                coerced_type_ri,
                var_decl.ast.type_node,
            )
        else
            .none;

        const init_inst = try expr(
            &block_scope,
            &block_scope.base,
            if (type_inst != .none) .{ .rl = .{ .ty = type_inst } } else .{ .rl = .none },
            var_decl.ast.init_node,
        );

        if (is_mutable) {
            const var_inst = try block_scope.add_var(.{
                .var_type = type_inst,
                .lib_name = .empty,
                .align_inst = .none, // passed via the decls data
                .init = init_inst,
                .is_extern = false,
                .is_const = !is_mutable,
                .is_threadlocal = is_threadlocal,
            });
            break :vi var_inst;
        } else {
            break :vi init_inst;
        }
    } else if (!is_extern) {
        return astgen.fail_node(node, "variables must be initialized", .{});
    } else if (var_decl.ast.type_node != 0) vi: {
        // Extern variable which has an explicit type.
        const type_inst = try type_expr(&block_scope, &block_scope.base, var_decl.ast.type_node);

        const var_inst = try block_scope.add_var(.{
            .var_type = type_inst,
            .lib_name = lib_name,
            .align_inst = .none, // passed via the decls data
            .init = .none,
            .is_extern = true,
            .is_const = !is_mutable,
            .is_threadlocal = is_threadlocal,
        });
        break :vi var_inst;
    } else {
        return astgen.fail_node(node, "unable to infer variable type", .{});
    };

    // We do this at the end so that the instruction index marks the end
    // range of a top level declaration.
    _ = try block_scope.add_break_with_src_node(.break_inline, decl_inst, var_inst, node);

    var align_gz = block_scope.make_sub_block(scope);
    if (var_decl.ast.align_node != 0) {
        const align_inst = try full_body_expr(&align_gz, &align_gz.base, coerced_align_ri, var_decl.ast.align_node);
        _ = try align_gz.add_break_with_src_node(.break_inline, decl_inst, align_inst, node);
    }

    var linksection_gz = align_gz.make_sub_block(scope);
    if (var_decl.ast.section_node != 0) {
        const linksection_inst = try full_body_expr(&linksection_gz, &linksection_gz.base, coerced_linksection_ri, var_decl.ast.section_node);
        _ = try linksection_gz.add_break_with_src_node(.break_inline, decl_inst, linksection_inst, node);
    }

    var addrspace_gz = linksection_gz.make_sub_block(scope);
    if (var_decl.ast.addrspace_node != 0) {
        const addrspace_inst = try full_body_expr(&addrspace_gz, &addrspace_gz.base, coerced_addrspace_ri, var_decl.ast.addrspace_node);
        _ = try addrspace_gz.add_break_with_src_node(.break_inline, decl_inst, addrspace_inst, node);
    }

    try set_declaration(
        decl_inst,
        std.zig.hash_src(tree.get_node_source(node)),
        .{ .named = name_token },
        block_scope.decl_line - gz.decl_line,
        is_pub,
        is_export,
        doc_comment_index,
        &block_scope,
        .{
            .align_gz = &align_gz,
            .linksection_gz = &linksection_gz,
            .addrspace_gz = &addrspace_gz,
        },
    );
}

fn comptime_decl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const body_node = node_datas[node].lhs;

    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.make_block_inst(.declaration, node);
    wip_members.next_decl(decl_inst);
    astgen.advance_source_cursor_to_node(node);

    var decl_block: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer decl_block.unstack();

    const block_result = try full_body_expr(&decl_block, &decl_block.base, .{ .rl = .none }, body_node);
    if (decl_block.is_empty() or !decl_block.ref_is_no_return(block_result)) {
        _ = try decl_block.add_break(.break_inline, decl_inst, .void_value);
    }

    try set_declaration(
        decl_inst,
        std.zig.hash_src(tree.get_node_source(node)),
        .@"comptime",
        decl_block.decl_line - gz.decl_line,
        false,
        false,
        .empty,
        &decl_block,
        null,
    );
}

fn usingnamespace_decl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const type_expr = node_datas[node].lhs;
    const is_pub = blk: {
        const main_tokens = tree.nodes.items(.main_token);
        const token_tags = tree.tokens.items(.tag);
        const main_token = main_tokens[node];
        break :blk (main_token > 0 and token_tags[main_token - 1] == .keyword_pub);
    };
    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.make_block_inst(.declaration, node);
    wip_members.next_decl(decl_inst);
    astgen.advance_source_cursor_to_node(node);

    var decl_block: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer decl_block.unstack();

    const namespace_inst = try type_expr(&decl_block, &decl_block.base, type_expr);
    _ = try decl_block.add_break(.break_inline, decl_inst, namespace_inst);

    try set_declaration(
        decl_inst,
        std.zig.hash_src(tree.get_node_source(node)),
        .@"usingnamespace",
        decl_block.decl_line - gz.decl_line,
        is_pub,
        false,
        .empty,
        &decl_block,
        null,
    );
}

fn test_decl(
    astgen: *AstGen,
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    node: Ast.Node.Index,
) InnerError!void {
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const body_node = node_datas[node].rhs;

    // Up top so the ZIR instruction index marks the start range of this
    // top-level declaration.
    const decl_inst = try gz.make_block_inst(.declaration, node);

    wip_members.next_decl(decl_inst);
    astgen.advance_source_cursor_to_node(node);

    var decl_block: GenZir = .{
        .is_comptime = true,
        .decl_node_index = node,
        .decl_line = astgen.source_line,
        .parent = scope,
        .astgen = astgen,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer decl_block.unstack();

    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);
    const test_token = main_tokens[node];
    const test_name_token = test_token + 1;
    const test_name: DeclarationName = switch (token_tags[test_name_token]) {
        else => .unnamed_test,
        .string_literal => .{ .named_test = test_name_token },
        .identifier => blk: {
            const ident_name_raw = tree.token_slice(test_name_token);

            if (mem.eql(u8, ident_name_raw, "_")) return astgen.fail_tok(test_name_token, "'_' used as an identifier without @\"_\" syntax", .{});

            // if not @"" syntax, just use raw token slice
            if (ident_name_raw[0] != '@') {
                if (is_primitive(ident_name_raw)) return astgen.fail_tok(test_name_token, "cannot test a primitive", .{});
            }

            // Local variables, including function parameters.
            const name_str_index = try astgen.ident_as_string(test_name_token);
            var s = scope;
            var found_already: ?Ast.Node.Index = null; // we have found a decl with the same name already
            var num_namespaces_out: u32 = 0;
            var capturing_namespace: ?*Scope.Namespace = null;
            while (true) switch (s.tag) {
                .local_val => {
                    const local_val = s.cast(Scope.LocalVal).?;
                    if (local_val.name == name_str_index) {
                        local_val.used = test_name_token;
                        return astgen.fail_tok_notes(test_name_token, "cannot test a {s}", .{
                            @tag_name(local_val.id_cat),
                        }, &[_]u32{
                            try astgen.err_note_tok(local_val.token_src, "{s} declared here", .{
                                @tag_name(local_val.id_cat),
                            }),
                        });
                    }
                    s = local_val.parent;
                },
                .local_ptr => {
                    const local_ptr = s.cast(Scope.LocalPtr).?;
                    if (local_ptr.name == name_str_index) {
                        local_ptr.used = test_name_token;
                        return astgen.fail_tok_notes(test_name_token, "cannot test a {s}", .{
                            @tag_name(local_ptr.id_cat),
                        }, &[_]u32{
                            try astgen.err_note_tok(local_ptr.token_src, "{s} declared here", .{
                                @tag_name(local_ptr.id_cat),
                            }),
                        });
                    }
                    s = local_ptr.parent;
                },
                .gen_zir => s = s.cast(GenZir).?.parent,
                .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
                .namespace => {
                    const ns = s.cast(Scope.Namespace).?;
                    if (ns.decls.get(name_str_index)) |i| {
                        if (found_already) |f| {
                            return astgen.fail_tok_notes(test_name_token, "ambiguous reference", .{}, &.{
                                try astgen.err_note_node(f, "declared here", .{}),
                                try astgen.err_note_node(i, "also declared here", .{}),
                            });
                        }
                        // We found a match but must continue looking for ambiguous references to decls.
                        found_already = i;
                    }
                    num_namespaces_out += 1;
                    capturing_namespace = ns;
                    s = ns.parent;
                },
                .top => break,
            };
            if (found_already == null) {
                const ident_name = try astgen.identifier_token_string(test_name_token);
                return astgen.fail_tok(test_name_token, "use of undeclared identifier '{s}'", .{ident_name});
            }

            break :blk .{ .decltest = name_str_index };
        },
    };

    var fn_block: GenZir = .{
        .is_comptime = false,
        .decl_node_index = node,
        .decl_line = decl_block.decl_line,
        .parent = &decl_block.base,
        .astgen = astgen,
        .instructions = decl_block.instructions,
        .instructions_top = decl_block.instructions.items.len,
    };
    defer fn_block.unstack();

    const prev_within_fn = astgen.within_fn;
    const prev_fn_block = astgen.fn_block;
    const prev_fn_ret_ty = astgen.fn_ret_ty;
    astgen.within_fn = true;
    astgen.fn_block = &fn_block;
    astgen.fn_ret_ty = .anyerror_void_error_union_type;
    defer {
        astgen.within_fn = prev_within_fn;
        astgen.fn_block = prev_fn_block;
        astgen.fn_ret_ty = prev_fn_ret_ty;
    }

    astgen.advance_source_cursor_to_node(body_node);
    const lbrace_line = astgen.source_line - decl_block.decl_line;
    const lbrace_column = astgen.source_column;

    const block_result = try full_body_expr(&fn_block, &fn_block.base, .{ .rl = .none }, body_node);
    if (fn_block.is_empty() or !fn_block.ref_is_no_return(block_result)) {

        // As our last action before the return, "pop" the error trace if needed
        _ = try fn_block.add_restore_err_ret_index(.ret, .always, node);

        // Add implicit return at end of function.
        _ = try fn_block.add_un_tok(.ret_implicit, .void_value, tree.last_token(body_node));
    }

    const func_inst = try decl_block.add_func(.{
        .src_node = node,

        .cc_ref = .none,
        .cc_gz = null,
        .align_ref = .none,
        .align_gz = null,
        .ret_ref = .anyerror_void_error_union_type,
        .ret_gz = null,
        .section_ref = .none,
        .section_gz = null,
        .addrspace_ref = .none,
        .addrspace_gz = null,

        .lbrace_line = lbrace_line,
        .lbrace_column = lbrace_column,
        .param_block = decl_inst,
        .body_gz = &fn_block,
        .lib_name = .empty,
        .is_var_args = false,
        .is_inferred_error = false,
        .is_test = true,
        .is_extern = false,
        .is_noinline = false,
        .noalias_bits = 0,
    });

    _ = try decl_block.add_break(.break_inline, decl_inst, func_inst);

    try set_declaration(
        decl_inst,
        std.zig.hash_src(tree.get_node_source(node)),
        test_name,
        decl_block.decl_line - gz.decl_line,
        false,
        false,
        .empty,
        &decl_block,
        null,
    );
}

fn struct_decl_inner(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
    layout: std.builtin.Type.ContainerLayout,
    backing_int_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const decl_inst = try gz.reserve_instruction_index();

    if (container_decl.ast.members.len == 0 and backing_int_node == 0) {
        try gz.set_struct(decl_inst, .{
            .src_node = node,
            .layout = layout,
            .captures_len = 0,
            .fields_len = 0,
            .decls_len = 0,
            .has_backing_int = false,
            .known_non_opv = false,
            .known_comptime_only = false,
            .is_tuple = false,
            .any_comptime_fields = false,
            .any_default_inits = false,
            .any_aligned_fields = false,
            .fields_hash = std.zig.hash_src(@tag_name(layout)),
        });
        return decl_inst.to_ref();
    }

    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;

    var namespace: Scope.Namespace = .{
        .parent = scope,
        .node = node,
        .inst = decl_inst,
        .declaring_gz = gz,
        .maybe_generic = astgen.within_fn,
    };
    defer namespace.deinit(gpa);

    // The struct_decl instruction introduces a scope in which the decls of the struct
    // are in scope, so that field types, alignments, and default value expressions
    // can refer to decls within the struct itself.
    astgen.advance_source_cursor_to_node(node);
    var block_scope: GenZir = .{
        .parent = &namespace.base,
        .decl_node_index = node,
        .decl_line = gz.decl_line,
        .astgen = astgen,
        .is_comptime = true,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer block_scope.unstack();

    const scratch_top = astgen.scratch.items.len;
    defer astgen.scratch.items.len = scratch_top;

    var backing_int_body_len: usize = 0;
    const backing_int_ref: Zir.Inst.Ref = blk: {
        if (backing_int_node != 0) {
            if (layout != .@"packed") {
                return astgen.fail_node(backing_int_node, "non-packed struct does not support backing integer type", .{});
            } else {
                const backing_int_ref = try type_expr(&block_scope, &namespace.base, backing_int_node);
                if (!block_scope.is_empty()) {
                    if (!block_scope.ends_with_no_return()) {
                        _ = try block_scope.add_break(.break_inline, decl_inst, backing_int_ref);
                    }

                    const body = block_scope.instructions_slice();
                    const old_scratch_len = astgen.scratch.items.len;
                    try astgen.scratch.ensure_unused_capacity(gpa, count_body_len_after_fixups(astgen, body));
                    append_body_with_fixups_array_list(astgen, &astgen.scratch, body);
                    backing_int_body_len = astgen.scratch.items.len - old_scratch_len;
                    block_scope.instructions.items.len = block_scope.instructions_top;
                }
                break :blk backing_int_ref;
            }
        } else {
            break :blk .none;
        }
    };

    const decl_count = try astgen.scan_decls(&namespace, container_decl.ast.members);
    const field_count: u32 = @int_cast(container_decl.ast.members.len - decl_count);

    const bits_per_field = 4;
    const max_field_size = 5;
    var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, field_count, bits_per_field, max_field_size);
    defer wip_members.deinit();

    // We will use the scratch buffer, starting here, for the bodies:
    //    bodies: { // for every fields_len
    //        field_type_body_inst: Inst, // for each field_type_body_len
    //        align_body_inst: Inst, // for each align_body_len
    //        init_body_inst: Inst, // for each init_body_len
    //    }
    // Note that the scratch buffer is simultaneously being used by WipMembers, however
    // it will not access any elements beyond this point in the ArrayList. It also
    // accesses via the ArrayList items field so it can handle the scratch buffer being
    // reallocated.
    // No defer needed here because it is handled by `wip_members.deinit()` above.
    const bodies_start = astgen.scratch.items.len;

    const node_tags = tree.nodes.items(.tag);
    const is_tuple = for (container_decl.ast.members) |member_node| {
        const container_field = tree.full_container_field(member_node) orelse continue;
        if (container_field.ast.tuple_like) break true;
    } else false;

    if (is_tuple) switch (layout) {
        .auto => {},
        .@"extern" => return astgen.fail_node(node, "extern tuples are not supported", .{}),
        .@"packed" => return astgen.fail_node(node, "packed tuples are not supported", .{}),
    };

    if (is_tuple) for (container_decl.ast.members) |member_node| {
        switch (node_tags[member_node]) {
            .container_field_init,
            .container_field_align,
            .container_field,
            .@"comptime",
            .test_decl,
            => continue,
            else => {
                const tuple_member = for (container_decl.ast.members) |maybe_tuple| switch (node_tags[maybe_tuple]) {
                    .container_field_init,
                    .container_field_align,
                    .container_field,
                    => break maybe_tuple,
                    else => {},
                } else unreachable;
                return astgen.fail_node_notes(
                    member_node,
                    "tuple declarations cannot contain declarations",
                    .{},
                    &[_]u32{
                        try astgen.err_note_node(tuple_member, "tuple field here", .{}),
                    },
                );
            },
        }
    };

    var fields_hasher = std.zig.SrcHasher.init(.{});
    fields_hasher.update(@tag_name(layout));
    if (backing_int_node != 0) {
        fields_hasher.update(tree.get_node_source(backing_int_node));
    }

    var sfba = std.heap.stack_fallback(256, astgen.arena);
    const sfba_allocator = sfba.get();

    var duplicate_names = std.AutoArrayHashMap(Zir.NullTerminatedString, std.ArrayListUnmanaged(Ast.TokenIndex)).init(sfba_allocator);
    try duplicate_names.ensure_total_capacity(field_count);

    // When there aren't errors, use this to avoid a second iteration.
    var any_duplicate = false;

    var known_non_opv = false;
    var known_comptime_only = false;
    var any_comptime_fields = false;
    var any_aligned_fields = false;
    var any_default_inits = false;
    for (container_decl.ast.members) |member_node| {
        var member = switch (try container_member(&block_scope, &namespace.base, &wip_members, member_node)) {
            .decl => continue,
            .field => |field| field,
        };

        fields_hasher.update(tree.get_node_source(member_node));

        if (!is_tuple) {
            const field_name = try astgen.ident_as_string(member.ast.main_token);

            member.convert_to_non_tuple_like(astgen.tree.nodes);
            assert(!member.ast.tuple_like);

            wip_members.append_to_field(@int_from_enum(field_name));

            const gop = try duplicate_names.get_or_put(field_name);

            if (gop.found_existing) {
                try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
                any_duplicate = true;
            } else {
                gop.value_ptr.* = .{};
                try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
            }
        } else if (!member.ast.tuple_like) {
            return astgen.fail_tok(member.ast.main_token, "tuple field has a name", .{});
        }

        const doc_comment_index = try astgen.doc_comment_as_string(member.first_token());
        wip_members.append_to_field(@int_from_enum(doc_comment_index));

        if (member.ast.type_expr == 0) {
            return astgen.fail_tok(member.ast.main_token, "struct field missing type", .{});
        }

        const field_type = try type_expr(&block_scope, &namespace.base, member.ast.type_expr);
        const have_type_body = !block_scope.is_empty();
        const have_align = member.ast.align_expr != 0;
        const have_value = member.ast.value_expr != 0;
        const is_comptime = member.comptime_token != null;

        if (is_comptime) {
            switch (layout) {
                .@"packed" => return astgen.fail_tok(member.comptime_token.?, "packed struct fields cannot be marked comptime", .{}),
                .@"extern" => return astgen.fail_tok(member.comptime_token.?, "extern struct fields cannot be marked comptime", .{}),
                .auto => any_comptime_fields = true,
            }
        } else {
            known_non_opv = known_non_opv or
                node_implies_more_than_one_possible_value(tree, member.ast.type_expr);
            known_comptime_only = known_comptime_only or
                node_implies_comptime_only(tree, member.ast.type_expr);
        }
        wip_members.next_field(bits_per_field, .{ have_align, have_value, is_comptime, have_type_body });

        if (have_type_body) {
            if (!block_scope.ends_with_no_return()) {
                _ = try block_scope.add_break(.break_inline, decl_inst, field_type);
            }
            const body = block_scope.instructions_slice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensure_unused_capacity(gpa, count_body_len_after_fixups(astgen, body));
            append_body_with_fixups_array_list(astgen, &astgen.scratch, body);
            wip_members.append_to_field(@int_cast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        } else {
            wip_members.append_to_field(@int_from_enum(field_type));
        }

        if (have_align) {
            if (layout == .@"packed") {
                try astgen.append_error_node(member.ast.align_expr, "unable to override alignment of packed struct fields", .{});
            }
            any_aligned_fields = true;
            const align_ref = try expr(&block_scope, &namespace.base, coerced_align_ri, member.ast.align_expr);
            if (!block_scope.ends_with_no_return()) {
                _ = try block_scope.add_break(.break_inline, decl_inst, align_ref);
            }
            const body = block_scope.instructions_slice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensure_unused_capacity(gpa, count_body_len_after_fixups(astgen, body));
            append_body_with_fixups_array_list(astgen, &astgen.scratch, body);
            wip_members.append_to_field(@int_cast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        }

        if (have_value) {
            any_default_inits = true;

            // The decl_inst is used as here so that we can easily reconstruct a mapping
            // between it and the field type when the fields inits are analzyed.
            const ri: ResultInfo = .{ .rl = if (field_type == .none) .none else .{ .coerced_ty = decl_inst.to_ref() } };

            const default_inst = try expr(&block_scope, &namespace.base, ri, member.ast.value_expr);
            if (!block_scope.ends_with_no_return()) {
                _ = try block_scope.add_break(.break_inline, decl_inst, default_inst);
            }
            const body = block_scope.instructions_slice();
            const old_scratch_len = astgen.scratch.items.len;
            try astgen.scratch.ensure_unused_capacity(gpa, count_body_len_after_fixups(astgen, body));
            append_body_with_fixups_array_list(astgen, &astgen.scratch, body);
            wip_members.append_to_field(@int_cast(astgen.scratch.items.len - old_scratch_len));
            block_scope.instructions.items.len = block_scope.instructions_top;
        } else if (member.comptime_token) |comptime_token| {
            return astgen.fail_tok(comptime_token, "comptime field without default initialization value", .{});
        }
    }

    if (any_duplicate) {
        var it = duplicate_names.iterator();

        while (it.next()) |entry| {
            const record = entry.value_ptr.*;
            if (record.items.len > 1) {
                var error_notes = std.ArrayList(u32).init(astgen.arena);

                for (record.items[1..]) |duplicate| {
                    try error_notes.append(try astgen.err_note_tok(duplicate, "duplicate field here", .{}));
                }

                try error_notes.append(try astgen.err_note_node(node, "struct declared here", .{}));

                try astgen.append_error_tok_notes(
                    record.items[0],
                    "duplicate struct field name",
                    .{},
                    error_notes.items,
                );
            }
        }

        return error.AnalysisFail;
    }

    var fields_hash: std.zig.SrcHash = undefined;
    fields_hasher.final(&fields_hash);

    try gz.set_struct(decl_inst, .{
        .src_node = node,
        .layout = layout,
        .captures_len = @int_cast(namespace.captures.count()),
        .fields_len = field_count,
        .decls_len = decl_count,
        .has_backing_int = backing_int_ref != .none,
        .known_non_opv = known_non_opv,
        .known_comptime_only = known_comptime_only,
        .is_tuple = is_tuple,
        .any_comptime_fields = any_comptime_fields,
        .any_default_inits = any_default_inits,
        .any_aligned_fields = any_aligned_fields,
        .fields_hash = fields_hash,
    });

    wip_members.finish_bits(bits_per_field);
    const decls_slice = wip_members.decls_slice();
    const fields_slice = wip_members.fields_slice();
    const bodies_slice = astgen.scratch.items[bodies_start..];
    try astgen.extra.ensure_unused_capacity(gpa, backing_int_body_len + 2 +
        decls_slice.len + namespace.captures.count() + fields_slice.len + bodies_slice.len);
    astgen.extra.append_slice_assume_capacity(@ptr_cast(namespace.captures.keys()));
    if (backing_int_ref != .none) {
        astgen.extra.append_assume_capacity(@int_cast(backing_int_body_len));
        if (backing_int_body_len == 0) {
            astgen.extra.append_assume_capacity(@int_from_enum(backing_int_ref));
        } else {
            astgen.extra.append_slice_assume_capacity(astgen.scratch.items[scratch_top..][0..backing_int_body_len]);
        }
    }
    astgen.extra.append_slice_assume_capacity(decls_slice);
    astgen.extra.append_slice_assume_capacity(fields_slice);
    astgen.extra.append_slice_assume_capacity(bodies_slice);

    block_scope.unstack();
    return decl_inst.to_ref();
}

fn union_decl_inner(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    members: []const Ast.Node.Index,
    layout: std.builtin.Type.ContainerLayout,
    arg_node: Ast.Node.Index,
    auto_enum_tok: ?Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const decl_inst = try gz.reserve_instruction_index();

    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    var namespace: Scope.Namespace = .{
        .parent = scope,
        .node = node,
        .inst = decl_inst,
        .declaring_gz = gz,
        .maybe_generic = astgen.within_fn,
    };
    defer namespace.deinit(gpa);

    // The union_decl instruction introduces a scope in which the decls of the union
    // are in scope, so that field types, alignments, and default value expressions
    // can refer to decls within the union itself.
    astgen.advance_source_cursor_to_node(node);
    var block_scope: GenZir = .{
        .parent = &namespace.base,
        .decl_node_index = node,
        .decl_line = gz.decl_line,
        .astgen = astgen,
        .is_comptime = true,
        .instructions = gz.instructions,
        .instructions_top = gz.instructions.items.len,
    };
    defer block_scope.unstack();

    const decl_count = try astgen.scan_decls(&namespace, members);
    const field_count: u32 = @int_cast(members.len - decl_count);

    if (layout != .auto and (auto_enum_tok != null or arg_node != 0)) {
        if (arg_node != 0) {
            return astgen.fail_node(arg_node, "{s} union does not support enum tag type", .{@tag_name(layout)});
        } else {
            return astgen.fail_tok(auto_enum_tok.?, "{s} union does not support enum tag type", .{@tag_name(layout)});
        }
    }

    const arg_inst: Zir.Inst.Ref = if (arg_node != 0)
        try type_expr(&block_scope, &namespace.base, arg_node)
    else
        .none;

    const bits_per_field = 4;
    const max_field_size = 5;
    var any_aligned_fields = false;
    var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, field_count, bits_per_field, max_field_size);
    defer wip_members.deinit();

    var fields_hasher = std.zig.SrcHasher.init(.{});
    fields_hasher.update(@tag_name(layout));
    fields_hasher.update(&.{@int_from_bool(auto_enum_tok != null)});
    if (arg_node != 0) {
        fields_hasher.update(astgen.tree.get_node_source(arg_node));
    }

    var sfba = std.heap.stack_fallback(256, astgen.arena);
    const sfba_allocator = sfba.get();

    var duplicate_names = std.AutoArrayHashMap(Zir.NullTerminatedString, std.ArrayListUnmanaged(Ast.TokenIndex)).init(sfba_allocator);
    try duplicate_names.ensure_total_capacity(field_count);

    // When there aren't errors, use this to avoid a second iteration.
    var any_duplicate = false;

    for (members) |member_node| {
        var member = switch (try container_member(&block_scope, &namespace.base, &wip_members, member_node)) {
            .decl => continue,
            .field => |field| field,
        };
        fields_hasher.update(astgen.tree.get_node_source(member_node));
        member.convert_to_non_tuple_like(astgen.tree.nodes);
        if (member.ast.tuple_like) {
            return astgen.fail_tok(member.ast.main_token, "union field missing name", .{});
        }
        if (member.comptime_token) |comptime_token| {
            return astgen.fail_tok(comptime_token, "union fields cannot be marked comptime", .{});
        }

        const field_name = try astgen.ident_as_string(member.ast.main_token);
        wip_members.append_to_field(@int_from_enum(field_name));

        const gop = try duplicate_names.get_or_put(field_name);

        if (gop.found_existing) {
            try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
            any_duplicate = true;
        } else {
            gop.value_ptr.* = .{};
            try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
        }

        const doc_comment_index = try astgen.doc_comment_as_string(member.first_token());
        wip_members.append_to_field(@int_from_enum(doc_comment_index));

        const have_type = member.ast.type_expr != 0;
        const have_align = member.ast.align_expr != 0;
        const have_value = member.ast.value_expr != 0;
        const unused = false;
        wip_members.next_field(bits_per_field, .{ have_type, have_align, have_value, unused });

        if (have_type) {
            const field_type = try type_expr(&block_scope, &namespace.base, member.ast.type_expr);
            wip_members.append_to_field(@int_from_enum(field_type));
        } else if (arg_inst == .none and auto_enum_tok == null) {
            return astgen.fail_node(member_node, "union field missing type", .{});
        }
        if (have_align) {
            const align_inst = try expr(&block_scope, &block_scope.base, coerced_align_ri, member.ast.align_expr);
            wip_members.append_to_field(@int_from_enum(align_inst));
            any_aligned_fields = true;
        }
        if (have_value) {
            if (arg_inst == .none) {
                return astgen.fail_node_notes(
                    node,
                    "explicitly valued tagged union missing integer tag type",
                    .{},
                    &[_]u32{
                        try astgen.err_note_node(
                            member.ast.value_expr,
                            "tag value specified here",
                            .{},
                        ),
                    },
                );
            }
            if (auto_enum_tok == null) {
                return astgen.fail_node_notes(
                    node,
                    "explicitly valued tagged union requires inferred enum tag type",
                    .{},
                    &[_]u32{
                        try astgen.err_note_node(
                            member.ast.value_expr,
                            "tag value specified here",
                            .{},
                        ),
                    },
                );
            }
            const tag_value = try expr(&block_scope, &block_scope.base, .{ .rl = .{ .ty = arg_inst } }, member.ast.value_expr);
            wip_members.append_to_field(@int_from_enum(tag_value));
        }
    }

    if (any_duplicate) {
        var it = duplicate_names.iterator();

        while (it.next()) |entry| {
            const record = entry.value_ptr.*;
            if (record.items.len > 1) {
                var error_notes = std.ArrayList(u32).init(astgen.arena);

                for (record.items[1..]) |duplicate| {
                    try error_notes.append(try astgen.err_note_tok(duplicate, "duplicate field here", .{}));
                }

                try error_notes.append(try astgen.err_note_node(node, "union declared here", .{}));

                try astgen.append_error_tok_notes(
                    record.items[0],
                    "duplicate union field name",
                    .{},
                    error_notes.items,
                );
            }
        }

        return error.AnalysisFail;
    }

    var fields_hash: std.zig.SrcHash = undefined;
    fields_hasher.final(&fields_hash);

    if (!block_scope.is_empty()) {
        _ = try block_scope.add_break(.break_inline, decl_inst, .void_value);
    }

    const body = block_scope.instructions_slice();
    const body_len = astgen.count_body_len_after_fixups(body);

    try gz.set_union(decl_inst, .{
        .src_node = node,
        .layout = layout,
        .tag_type = arg_inst,
        .captures_len = @int_cast(namespace.captures.count()),
        .body_len = body_len,
        .fields_len = field_count,
        .decls_len = decl_count,
        .auto_enum_tag = auto_enum_tok != null,
        .any_aligned_fields = any_aligned_fields,
        .fields_hash = fields_hash,
    });

    wip_members.finish_bits(bits_per_field);
    const decls_slice = wip_members.decls_slice();
    const fields_slice = wip_members.fields_slice();
    try astgen.extra.ensure_unused_capacity(gpa, namespace.captures.count() + decls_slice.len + body_len + fields_slice.len);
    astgen.extra.append_slice_assume_capacity(@ptr_cast(namespace.captures.keys()));
    astgen.extra.append_slice_assume_capacity(decls_slice);
    astgen.append_body_with_fixups(body);
    astgen.extra.append_slice_assume_capacity(fields_slice);

    block_scope.unstack();
    return decl_inst.to_ref();
}

fn container_decl(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    container_decl: Ast.full.ContainerDecl,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    const prev_fn_block = astgen.fn_block;
    astgen.fn_block = null;
    defer astgen.fn_block = prev_fn_block;

    // We must not create any types until Sema. Here the goal is only to generate
    // ZIR for all the field types, alignments, and default value expressions.

    switch (token_tags[container_decl.ast.main_token]) {
        .keyword_struct => {
            const layout: std.builtin.Type.ContainerLayout = if (container_decl.layout_token) |t| switch (token_tags[t]) {
                .keyword_packed => .@"packed",
                .keyword_extern => .@"extern",
                else => unreachable,
            } else .auto;

            const result = try struct_decl_inner(gz, scope, node, container_decl, layout, container_decl.ast.arg);
            return rvalue(gz, ri, result, node);
        },
        .keyword_union => {
            const layout: std.builtin.Type.ContainerLayout = if (container_decl.layout_token) |t| switch (token_tags[t]) {
                .keyword_packed => .@"packed",
                .keyword_extern => .@"extern",
                else => unreachable,
            } else .auto;

            const result = try union_decl_inner(gz, scope, node, container_decl.ast.members, layout, container_decl.ast.arg, container_decl.ast.enum_token);
            return rvalue(gz, ri, result, node);
        },
        .keyword_enum => {
            if (container_decl.layout_token) |t| {
                return astgen.fail_tok(t, "enums do not support 'packed' or 'extern'; instead provide an explicit integer tag type", .{});
            }
            // Count total fields as well as how many have explicitly provided tag values.
            const counts = blk: {
                var values: usize = 0;
                var total_fields: usize = 0;
                var decls: usize = 0;
                var nonexhaustive_node: Ast.Node.Index = 0;
                var nonfinal_nonexhaustive = false;
                for (container_decl.ast.members) |member_node| {
                    var member = tree.full_container_field(member_node) orelse {
                        decls += 1;
                        continue;
                    };
                    member.convert_to_non_tuple_like(astgen.tree.nodes);
                    if (member.ast.tuple_like) {
                        return astgen.fail_tok(member.ast.main_token, "enum field missing name", .{});
                    }
                    if (member.comptime_token) |comptime_token| {
                        return astgen.fail_tok(comptime_token, "enum fields cannot be marked comptime", .{});
                    }
                    if (member.ast.type_expr != 0) {
                        return astgen.fail_node_notes(
                            member.ast.type_expr,
                            "enum fields do not have types",
                            .{},
                            &[_]u32{
                                try astgen.err_note_node(
                                    node,
                                    "consider 'union(enum)' here to make it a tagged union",
                                    .{},
                                ),
                            },
                        );
                    }
                    if (member.ast.align_expr != 0) {
                        return astgen.fail_node(member.ast.align_expr, "enum fields cannot be aligned", .{});
                    }

                    const name_token = member.ast.main_token;
                    if (mem.eql(u8, tree.token_slice(name_token), "_")) {
                        if (nonexhaustive_node != 0) {
                            return astgen.fail_node_notes(
                                member_node,
                                "redundant non-exhaustive enum mark",
                                .{},
                                &[_]u32{
                                    try astgen.err_note_node(
                                        nonexhaustive_node,
                                        "other mark here",
                                        .{},
                                    ),
                                },
                            );
                        }
                        nonexhaustive_node = member_node;
                        if (member.ast.value_expr != 0) {
                            return astgen.fail_node(member.ast.value_expr, "'_' is used to mark an enum as non-exhaustive and cannot be assigned a value", .{});
                        }
                        continue;
                    } else if (nonexhaustive_node != 0) {
                        nonfinal_nonexhaustive = true;
                    }
                    total_fields += 1;
                    if (member.ast.value_expr != 0) {
                        if (container_decl.ast.arg == 0) {
                            return astgen.fail_node(member.ast.value_expr, "value assigned to enum tag with inferred tag type", .{});
                        }
                        values += 1;
                    }
                }
                if (nonfinal_nonexhaustive) {
                    return astgen.fail_node(nonexhaustive_node, "'_' field of non-exhaustive enum must be last", .{});
                }
                break :blk .{
                    .total_fields = total_fields,
                    .values = values,
                    .decls = decls,
                    .nonexhaustive_node = nonexhaustive_node,
                };
            };
            if (counts.nonexhaustive_node != 0 and container_decl.ast.arg == 0) {
                try astgen.append_error_node_notes(
                    node,
                    "non-exhaustive enum missing integer tag type",
                    .{},
                    &[_]u32{
                        try astgen.err_note_node(
                            counts.nonexhaustive_node,
                            "marked non-exhaustive here",
                            .{},
                        ),
                    },
                );
            }
            // In this case we must generate ZIR code for the tag values, similar to
            // how structs are handled above.
            const nonexhaustive = counts.nonexhaustive_node != 0;

            const decl_inst = try gz.reserve_instruction_index();

            var namespace: Scope.Namespace = .{
                .parent = scope,
                .node = node,
                .inst = decl_inst,
                .declaring_gz = gz,
                .maybe_generic = astgen.within_fn,
            };
            defer namespace.deinit(gpa);

            // The enum_decl instruction introduces a scope in which the decls of the enum
            // are in scope, so that tag values can refer to decls within the enum itself.
            astgen.advance_source_cursor_to_node(node);
            var block_scope: GenZir = .{
                .parent = &namespace.base,
                .decl_node_index = node,
                .decl_line = gz.decl_line,
                .astgen = astgen,
                .is_comptime = true,
                .instructions = gz.instructions,
                .instructions_top = gz.instructions.items.len,
            };
            defer block_scope.unstack();

            _ = try astgen.scan_decls(&namespace, container_decl.ast.members);
            namespace.base.tag = .namespace;

            const arg_inst: Zir.Inst.Ref = if (container_decl.ast.arg != 0)
                try comptime_expr(&block_scope, &namespace.base, coerced_type_ri, container_decl.ast.arg)
            else
                .none;

            const bits_per_field = 1;
            const max_field_size = 3;
            var wip_members = try WipMembers.init(gpa, &astgen.scratch, @int_cast(counts.decls), @int_cast(counts.total_fields), bits_per_field, max_field_size);
            defer wip_members.deinit();

            var fields_hasher = std.zig.SrcHasher.init(.{});
            if (container_decl.ast.arg != 0) {
                fields_hasher.update(tree.get_node_source(container_decl.ast.arg));
            }
            fields_hasher.update(&.{@int_from_bool(nonexhaustive)});

            var sfba = std.heap.stack_fallback(256, astgen.arena);
            const sfba_allocator = sfba.get();

            var duplicate_names = std.AutoArrayHashMap(Zir.NullTerminatedString, std.ArrayListUnmanaged(Ast.TokenIndex)).init(sfba_allocator);
            try duplicate_names.ensure_total_capacity(counts.total_fields);

            // When there aren't errors, use this to avoid a second iteration.
            var any_duplicate = false;

            for (container_decl.ast.members) |member_node| {
                if (member_node == counts.nonexhaustive_node)
                    continue;
                fields_hasher.update(tree.get_node_source(member_node));
                var member = switch (try container_member(&block_scope, &namespace.base, &wip_members, member_node)) {
                    .decl => continue,
                    .field => |field| field,
                };
                member.convert_to_non_tuple_like(astgen.tree.nodes);
                assert(member.comptime_token == null);
                assert(member.ast.type_expr == 0);
                assert(member.ast.align_expr == 0);

                const field_name = try astgen.ident_as_string(member.ast.main_token);
                wip_members.append_to_field(@int_from_enum(field_name));

                const gop = try duplicate_names.get_or_put(field_name);

                if (gop.found_existing) {
                    try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
                    any_duplicate = true;
                } else {
                    gop.value_ptr.* = .{};
                    try gop.value_ptr.append(sfba_allocator, member.ast.main_token);
                }

                const doc_comment_index = try astgen.doc_comment_as_string(member.first_token());
                wip_members.append_to_field(@int_from_enum(doc_comment_index));

                const have_value = member.ast.value_expr != 0;
                wip_members.next_field(bits_per_field, .{have_value});

                if (have_value) {
                    if (arg_inst == .none) {
                        return astgen.fail_node_notes(
                            node,
                            "explicitly valued enum missing integer tag type",
                            .{},
                            &[_]u32{
                                try astgen.err_note_node(
                                    member.ast.value_expr,
                                    "tag value specified here",
                                    .{},
                                ),
                            },
                        );
                    }
                    const tag_value_inst = try expr(&block_scope, &namespace.base, .{ .rl = .{ .ty = arg_inst } }, member.ast.value_expr);
                    wip_members.append_to_field(@int_from_enum(tag_value_inst));
                }
            }

            if (any_duplicate) {
                var it = duplicate_names.iterator();

                while (it.next()) |entry| {
                    const record = entry.value_ptr.*;
                    if (record.items.len > 1) {
                        var error_notes = std.ArrayList(u32).init(astgen.arena);

                        for (record.items[1..]) |duplicate| {
                            try error_notes.append(try astgen.err_note_tok(duplicate, "duplicate field here", .{}));
                        }

                        try error_notes.append(try astgen.err_note_node(node, "enum declared here", .{}));

                        try astgen.append_error_tok_notes(
                            record.items[0],
                            "duplicate enum field name",
                            .{},
                            error_notes.items,
                        );
                    }
                }

                return error.AnalysisFail;
            }

            if (!block_scope.is_empty()) {
                _ = try block_scope.add_break(.break_inline, decl_inst, .void_value);
            }

            var fields_hash: std.zig.SrcHash = undefined;
            fields_hasher.final(&fields_hash);

            const body = block_scope.instructions_slice();
            const body_len = astgen.count_body_len_after_fixups(body);

            try gz.set_enum(decl_inst, .{
                .src_node = node,
                .nonexhaustive = nonexhaustive,
                .tag_type = arg_inst,
                .captures_len = @int_cast(namespace.captures.count()),
                .body_len = body_len,
                .fields_len = @int_cast(counts.total_fields),
                .decls_len = @int_cast(counts.decls),
                .fields_hash = fields_hash,
            });

            wip_members.finish_bits(bits_per_field);
            const decls_slice = wip_members.decls_slice();
            const fields_slice = wip_members.fields_slice();
            try astgen.extra.ensure_unused_capacity(gpa, namespace.captures.count() + decls_slice.len + body_len + fields_slice.len);
            astgen.extra.append_slice_assume_capacity(@ptr_cast(namespace.captures.keys()));
            astgen.extra.append_slice_assume_capacity(decls_slice);
            astgen.append_body_with_fixups(body);
            astgen.extra.append_slice_assume_capacity(fields_slice);

            block_scope.unstack();
            return rvalue(gz, ri, decl_inst.to_ref(), node);
        },
        .keyword_opaque => {
            assert(container_decl.ast.arg == 0);

            const decl_inst = try gz.reserve_instruction_index();

            var namespace: Scope.Namespace = .{
                .parent = scope,
                .node = node,
                .inst = decl_inst,
                .declaring_gz = gz,
                .maybe_generic = astgen.within_fn,
            };
            defer namespace.deinit(gpa);

            astgen.advance_source_cursor_to_node(node);
            var block_scope: GenZir = .{
                .parent = &namespace.base,
                .decl_node_index = node,
                .decl_line = gz.decl_line,
                .astgen = astgen,
                .is_comptime = true,
                .instructions = gz.instructions,
                .instructions_top = gz.instructions.items.len,
            };
            defer block_scope.unstack();

            const decl_count = try astgen.scan_decls(&namespace, container_decl.ast.members);

            var wip_members = try WipMembers.init(gpa, &astgen.scratch, decl_count, 0, 0, 0);
            defer wip_members.deinit();

            for (container_decl.ast.members) |member_node| {
                const res = try container_member(&block_scope, &namespace.base, &wip_members, member_node);
                if (res == .field) {
                    return astgen.fail_node(member_node, "opaque types cannot have fields", .{});
                }
            }

            try gz.set_opaque(decl_inst, .{
                .src_node = node,
                .captures_len = @int_cast(namespace.captures.count()),
                .decls_len = decl_count,
            });

            wip_members.finish_bits(0);
            const decls_slice = wip_members.decls_slice();
            try astgen.extra.ensure_unused_capacity(gpa, namespace.captures.count() + decls_slice.len);
            astgen.extra.append_slice_assume_capacity(@ptr_cast(namespace.captures.keys()));
            astgen.extra.append_slice_assume_capacity(decls_slice);

            block_scope.unstack();
            return rvalue(gz, ri, decl_inst.to_ref(), node);
        },
        else => unreachable,
    }
}

const ContainerMemberResult = union(enum) { decl, field: Ast.full.ContainerField };

fn container_member(
    gz: *GenZir,
    scope: *Scope,
    wip_members: *WipMembers,
    member_node: Ast.Node.Index,
) InnerError!ContainerMemberResult {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    switch (node_tags[member_node]) {
        .container_field_init,
        .container_field_align,
        .container_field,
        => return ContainerMemberResult{ .field = tree.full_container_field(member_node).? },

        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => {
            var buf: [1]Ast.Node.Index = undefined;
            const full = tree.full_fn_proto(&buf, member_node).?;
            const body = if (node_tags[member_node] == .fn_decl) node_datas[member_node].rhs else 0;

            astgen.fn_decl(gz, scope, wip_members, member_node, body, full) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {},
            };
        },

        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            astgen.global_var_decl(gz, scope, wip_members, member_node, tree.full_var_decl(member_node).?) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {},
            };
        },

        .@"comptime" => {
            astgen.comptime_decl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {},
            };
        },
        .@"usingnamespace" => {
            astgen.usingnamespace_decl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {},
            };
        },
        .test_decl => {
            astgen.test_decl(gz, scope, wip_members, member_node) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AnalysisFail => {},
            };
        },
        else => unreachable,
    }
    return .decl;
}

fn error_set_decl(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    const payload_index = try reserve_extra(astgen, @typeInfo(Zir.Inst.ErrorSetDecl).Struct.fields.len);
    var fields_len: usize = 0;
    {
        var idents: std.AutoHashMapUnmanaged(Zir.NullTerminatedString, Ast.TokenIndex) = .{};
        defer idents.deinit(gpa);

        const error_token = main_tokens[node];
        var tok_i = error_token + 2;
        while (true) : (tok_i += 1) {
            switch (token_tags[tok_i]) {
                .doc_comment, .comma => {},
                .identifier => {
                    const str_index = try astgen.ident_as_string(tok_i);
                    const gop = try idents.get_or_put(gpa, str_index);
                    if (gop.found_existing) {
                        const name = try gpa.dupe(u8, mem.span(astgen.null_terminated_string(str_index)));
                        defer gpa.free(name);
                        return astgen.fail_tok_notes(
                            tok_i,
                            "duplicate error set field '{s}'",
                            .{name},
                            &[_]u32{
                                try astgen.err_note_tok(
                                    gop.value_ptr.*,
                                    "previous declaration here",
                                    .{},
                                ),
                            },
                        );
                    }
                    gop.value_ptr.* = tok_i;

                    try astgen.extra.ensure_unused_capacity(gpa, 2);
                    astgen.extra.append_assume_capacity(@int_from_enum(str_index));
                    const doc_comment_index = try astgen.doc_comment_as_string(tok_i);
                    astgen.extra.append_assume_capacity(@int_from_enum(doc_comment_index));
                    fields_len += 1;
                },
                .r_brace => break,
                else => unreachable,
            }
        }
    }

    set_extra(astgen, payload_index, Zir.Inst.ErrorSetDecl{
        .fields_len = @int_cast(fields_len),
    });
    const result = try gz.add_pl_node_payload_index(.error_set_decl, node, payload_index);
    return rvalue(gz, ri, result, node);
}

fn try_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;

    const fn_block = astgen.fn_block orelse {
        return astgen.fail_node(node, "'try' outside function scope", .{});
    };

    if (parent_gz.any_defer_node != 0) {
        return astgen.fail_node_notes(node, "'try' not allowed inside defer expression", .{}, &.{
            try astgen.err_note_node(
                parent_gz.any_defer_node,
                "defer expression here",
                .{},
            ),
        });
    }

    // Ensure debug line/column information is emitted for this try expression.
    // Then we will save the line/column so that we can emit another one that goes
    // "backwards" because we want to evaluate the operand, but then put the debug
    // info back at the try keyword for error return tracing.
    if (!parent_gz.is_comptime) {
        try emit_dbg_node(parent_gz, node);
    }
    const try_lc = LineColumn{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const operand_ri: ResultInfo = switch (ri.rl) {
        .ref, .ref_coerced_ty => .{ .rl = .ref, .ctx = .error_handling_expr },
        else => .{ .rl = .none, .ctx = .error_handling_expr },
    };
    // This could be a pointer or value depending on the `ri` parameter.
    const operand = try reachable_expr(parent_gz, scope, operand_ri, operand_node, node);
    const block_tag: Zir.Inst.Tag = if (operand_ri.rl == .ref) .try_ptr else .@"try";
    const try_inst = try parent_gz.make_block_inst(block_tag, node);
    try parent_gz.instructions.append(astgen.gpa, try_inst);

    var else_scope = parent_gz.make_sub_block(scope);
    defer else_scope.unstack();

    const err_tag = switch (ri.rl) {
        .ref, .ref_coerced_ty => Zir.Inst.Tag.err_union_code_ptr,
        else => Zir.Inst.Tag.err_union_code,
    };
    const err_code = try else_scope.add_un_node(err_tag, operand, node);
    try gen_defers(&else_scope, &fn_block.base, scope, .{ .both = err_code });
    try emit_dbg_stmt(&else_scope, try_lc);
    _ = try else_scope.add_un_node(.ret_node, err_code, node);

    try else_scope.set_try_body(try_inst, operand);
    const result = try_inst.to_ref();
    switch (ri.rl) {
        .ref, .ref_coerced_ty => return result,
        else => return rvalue(parent_gz, ri, result, node),
    }
}

fn orelse_catch_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs: Ast.Node.Index,
    cond_op: Zir.Inst.Tag,
    unwrap_op: Zir.Inst.Tag,
    unwrap_code_op: Zir.Inst.Tag,
    rhs: Ast.Node.Index,
    payload_token: ?Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    const do_err_trace = astgen.fn_block != null and (cond_op == .is_non_err or cond_op == .is_non_err_ptr);

    var block_scope = parent_gz.make_sub_block(scope);
    block_scope.set_break_result_info(block_ri);
    defer block_scope.unstack();

    const operand_ri: ResultInfo = switch (block_scope.break_result_info.rl) {
        .ref, .ref_coerced_ty => .{ .rl = .ref, .ctx = if (do_err_trace) .error_handling_expr else .none },
        else => .{ .rl = .none, .ctx = if (do_err_trace) .error_handling_expr else .none },
    };
    // This could be a pointer or value depending on the `operand_ri` parameter.
    // We cannot use `block_scope.break_result_info` because that has the bare
    // type, whereas this expression has the optional type. Later we make
    // up for this fact by calling rvalue on the else branch.
    const operand = try reachable_expr(&block_scope, &block_scope.base, operand_ri, lhs, rhs);
    const cond = try block_scope.add_un_node(cond_op, operand, node);
    const condbr = try block_scope.add_cond_br(.condbr, node);

    const block = try parent_gz.make_block_inst(.block, node);
    try block_scope.set_block_body(block);
    // block_scope unstacked now, can add new instructions to parent_gz
    try parent_gz.instructions.append(astgen.gpa, block);

    var then_scope = block_scope.make_sub_block(scope);
    defer then_scope.unstack();

    // This could be a pointer or value depending on `unwrap_op`.
    const unwrapped_payload = try then_scope.add_un_node(unwrap_op, operand, node);
    const then_result = switch (ri.rl) {
        .ref, .ref_coerced_ty => unwrapped_payload,
        else => try rvalue(&then_scope, block_scope.break_result_info, unwrapped_payload, node),
    };
    _ = try then_scope.add_break_with_src_node(.@"break", block, then_result, node);

    var else_scope = block_scope.make_sub_block(scope);
    defer else_scope.unstack();

    // We know that the operand (almost certainly) modified the error return trace,
    // so signal to Sema that it should save the new index for restoring later.
    if (do_err_trace and node_may_append_to_error_trace(tree, lhs))
        _ = try else_scope.add_save_err_ret_index(.always);

    var err_val_scope: Scope.LocalVal = undefined;
    const else_sub_scope = blk: {
        const payload = payload_token orelse break :blk &else_scope.base;
        const err_str = tree.token_slice(payload);
        if (mem.eql(u8, err_str, "_")) {
            return astgen.fail_tok(payload, "discard of error capture; omit it instead", .{});
        }
        const err_name = try astgen.ident_as_string(payload);

        try astgen.detect_local_shadowing(scope, err_name, payload, err_str, .capture);

        err_val_scope = .{
            .parent = &else_scope.base,
            .gen_zir = &else_scope,
            .name = err_name,
            .inst = try else_scope.add_un_node(unwrap_code_op, operand, node),
            .token_src = payload,
            .id_cat = .capture,
        };
        break :blk &err_val_scope.base;
    };

    const else_result = try full_body_expr(&else_scope, else_sub_scope, block_scope.break_result_info, rhs);
    if (!else_scope.ends_with_no_return()) {
        // As our last action before the break, "pop" the error trace if needed
        if (do_err_trace)
            try restore_err_ret_index(&else_scope, .{ .block = block }, block_scope.break_result_info, rhs, else_result);

        _ = try else_scope.add_break_with_src_node(.@"break", block, else_result, rhs);
    }
    try check_used(parent_gz, &else_scope.base, else_sub_scope);

    try set_cond_br_payload(condbr, cond, &then_scope, &else_scope);

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, block.to_ref(), node);
    } else {
        return block.to_ref();
    }
}

/// Return whether the identifier names of two tokens are equal. Resolves @""
/// tokens without allocating.
/// OK in theory it could do it without allocating. This implementation
/// allocates when the @"" form is used.
fn token_ident_eql(astgen: *AstGen, token1: Ast.TokenIndex, token2: Ast.TokenIndex) !bool {
    const ident_name_1 = try astgen.identifier_token_string(token1);
    const ident_name_2 = try astgen.identifier_token_string(token2);
    return mem.eql(u8, ident_name_1, ident_name_2);
}

fn field_access(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    switch (ri.rl) {
        .ref, .ref_coerced_ty => return add_field_access(.field_ptr, gz, scope, .{ .rl = .ref }, node),
        else => {
            const access = try add_field_access(.field_val, gz, scope, .{ .rl = .none }, node);
            return rvalue(gz, ri, access, node);
        },
    }
}

fn add_field_access(
    tag: Zir.Inst.Tag,
    gz: *GenZir,
    scope: *Scope,
    lhs_ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const node_datas = tree.nodes.items(.data);

    const object_node = node_datas[node].lhs;
    const dot_token = main_tokens[node];
    const field_ident = dot_token + 1;
    const str_index = try astgen.ident_as_string(field_ident);
    const lhs = try expr(gz, scope, lhs_ri, object_node);

    const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
    try emit_dbg_stmt(gz, cursor);

    return gz.add_pl_node(tag, node, Zir.Inst.Field{
        .lhs = lhs,
        .field_name_start = str_index,
    });
}

fn array_access(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const tree = gz.astgen.tree;
    const node_datas = tree.nodes.items(.data);
    switch (ri.rl) {
        .ref, .ref_coerced_ty => {
            const lhs = try expr(gz, scope, .{ .rl = .ref }, node_datas[node].lhs);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);

            const rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[node].rhs);
            try emit_dbg_stmt(gz, cursor);

            return gz.add_pl_node(.elem_ptr_node, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
        },
        else => {
            const lhs = try expr(gz, scope, .{ .rl = .none }, node_datas[node].lhs);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);

            const rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, node_datas[node].rhs);
            try emit_dbg_stmt(gz, cursor);

            return rvalue(gz, ri, try gz.add_pl_node(.elem_val_node, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs }), node);
        },
    }
}

fn simple_bin_op(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    if (op_inst_tag == .cmp_neq or op_inst_tag == .cmp_eq) {
        const node_tags = tree.nodes.items(.tag);
        const str = if (op_inst_tag == .cmp_eq) "==" else "!=";
        if (node_tags[node_datas[node].lhs] == .string_literal or
            node_tags[node_datas[node].rhs] == .string_literal)
            return astgen.fail_node(node, "cannot compare strings with {s}", .{str});
    }

    const lhs = try reachable_expr(gz, scope, .{ .rl = .none }, node_datas[node].lhs, node);
    const cursor = switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => maybe_advance_source_cursor_to_main_token(gz, node),
        else => undefined,
    };
    const rhs = try reachable_expr(gz, scope, .{ .rl = .none }, node_datas[node].rhs, node);

    switch (op_inst_tag) {
        .add, .sub, .mul, .div, .mod_rem => {
            try emit_dbg_stmt(gz, cursor);
        },
        else => {},
    }
    const result = try gz.add_pl_node(op_inst_tag, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
    return rvalue(gz, ri, result, node);
}

fn simple_str_tok(
    gz: *GenZir,
    ri: ResultInfo,
    ident_token: Ast.TokenIndex,
    node: Ast.Node.Index,
    op_inst_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const str_index = try astgen.ident_as_string(ident_token);
    const result = try gz.add_str_tok(op_inst_tag, str_index, ident_token);
    return rvalue(gz, ri, result, node);
}

fn bool_bin_op(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    zir_tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const lhs = try expr(gz, scope, coerced_bool_ri, node_datas[node].lhs);
    const bool_br = (try gz.add_pl_node_payload_index(zir_tag, node, undefined)).to_index().?;

    var rhs_scope = gz.make_sub_block(scope);
    defer rhs_scope.unstack();
    const rhs = try full_body_expr(&rhs_scope, &rhs_scope.base, coerced_bool_ri, node_datas[node].rhs);
    if (!gz.ref_is_no_return(rhs)) {
        _ = try rhs_scope.add_break_with_src_node(.break_inline, bool_br, rhs, node_datas[node].rhs);
    }
    try rhs_scope.set_bool_br_body(bool_br, lhs);

    const block_ref = bool_br.to_ref();
    return rvalue(gz, ri, block_ref, node);
}

fn if_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    if_full: Ast.full.If,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    const do_err_trace = astgen.fn_block != null and if_full.error_token != null;

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    var block_scope = parent_gz.make_sub_block(scope);
    block_scope.set_break_result_info(block_ri);
    defer block_scope.unstack();

    const payload_is_ref = if (if_full.payload_token) |payload_token|
        token_tags[payload_token] == .asterisk
    else
        false;

    try emit_dbg_node(parent_gz, if_full.ast.cond_expr);
    const cond: struct {
        inst: Zir.Inst.Ref,
        bool_bit: Zir.Inst.Ref,
    } = c: {
        if (if_full.error_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none, .ctx = .error_handling_expr };
            const err_union = try expr(&block_scope, &block_scope.base, cond_ri, if_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_err_ptr else .is_non_err;
            break :c .{
                .inst = err_union,
                .bool_bit = try block_scope.add_un_node(tag, err_union, if_full.ast.cond_expr),
            };
        } else if (if_full.payload_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const optional = try expr(&block_scope, &block_scope.base, cond_ri, if_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_null_ptr else .is_non_null;
            break :c .{
                .inst = optional,
                .bool_bit = try block_scope.add_un_node(tag, optional, if_full.ast.cond_expr),
            };
        } else {
            const cond = try expr(&block_scope, &block_scope.base, coerced_bool_ri, if_full.ast.cond_expr);
            break :c .{
                .inst = cond,
                .bool_bit = cond,
            };
        }
    };

    const condbr = try block_scope.add_cond_br(.condbr, node);

    const block = try parent_gz.make_block_inst(.block, node);
    try block_scope.set_block_body(block);
    // block_scope unstacked now, can add new instructions to parent_gz
    try parent_gz.instructions.append(astgen.gpa, block);

    var then_scope = parent_gz.make_sub_block(scope);
    defer then_scope.unstack();

    var payload_val_scope: Scope.LocalVal = undefined;

    const then_node = if_full.ast.then_expr;
    const then_sub_scope = s: {
        if (if_full.error_token != null) {
            if (if_full.payload_token) |payload_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_payload_unsafe_ptr
                else
                    .err_union_payload_unsafe;
                const payload_inst = try then_scope.add_un_node(tag, cond.inst, then_node);
                const token_name_index = payload_token + @int_from_bool(payload_is_ref);
                const ident_name = try astgen.ident_as_string(token_name_index);
                const token_name_str = tree.token_slice(token_name_index);
                if (mem.eql(u8, "_", token_name_str))
                    break :s &then_scope.base;
                try astgen.detect_local_shadowing(&then_scope.base, ident_name, token_name_index, token_name_str, .capture);
                payload_val_scope = .{
                    .parent = &then_scope.base,
                    .gen_zir = &then_scope,
                    .name = ident_name,
                    .inst = payload_inst,
                    .token_src = token_name_index,
                    .id_cat = .capture,
                };
                try then_scope.add_dbg_var(.dbg_var_val, ident_name, payload_inst);
                break :s &payload_val_scope.base;
            } else {
                _ = try then_scope.add_un_node(.ensure_err_union_payload_void, cond.inst, node);
                break :s &then_scope.base;
            }
        } else if (if_full.payload_token) |payload_token| {
            const ident_token = if (payload_is_ref) payload_token + 1 else payload_token;
            const tag: Zir.Inst.Tag = if (payload_is_ref)
                .optional_payload_unsafe_ptr
            else
                .optional_payload_unsafe;
            const ident_bytes = tree.token_slice(ident_token);
            if (mem.eql(u8, "_", ident_bytes))
                break :s &then_scope.base;
            const payload_inst = try then_scope.add_un_node(tag, cond.inst, then_node);
            const ident_name = try astgen.ident_as_string(ident_token);
            try astgen.detect_local_shadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
            payload_val_scope = .{
                .parent = &then_scope.base,
                .gen_zir = &then_scope,
                .name = ident_name,
                .inst = payload_inst,
                .token_src = ident_token,
                .id_cat = .capture,
            };
            try then_scope.add_dbg_var(.dbg_var_val, ident_name, payload_inst);
            break :s &payload_val_scope.base;
        } else {
            break :s &then_scope.base;
        }
    };

    const then_result = try full_body_expr(&then_scope, then_sub_scope, block_scope.break_result_info, then_node);
    try check_used(parent_gz, &then_scope.base, then_sub_scope);
    if (!then_scope.ends_with_no_return()) {
        _ = try then_scope.add_break_with_src_node(.@"break", block, then_result, then_node);
    }

    var else_scope = parent_gz.make_sub_block(scope);
    defer else_scope.unstack();

    // We know that the operand (almost certainly) modified the error return trace,
    // so signal to Sema that it should save the new index for restoring later.
    if (do_err_trace and node_may_append_to_error_trace(tree, if_full.ast.cond_expr))
        _ = try else_scope.add_save_err_ret_index(.always);

    const else_node = if_full.ast.else_expr;
    if (else_node != 0) {
        const sub_scope = s: {
            if (if_full.error_token) |error_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_code_ptr
                else
                    .err_union_code;
                const payload_inst = try else_scope.add_un_node(tag, cond.inst, if_full.ast.cond_expr);
                const ident_name = try astgen.ident_as_string(error_token);
                const error_token_str = tree.token_slice(error_token);
                if (mem.eql(u8, "_", error_token_str))
                    break :s &else_scope.base;
                try astgen.detect_local_shadowing(&else_scope.base, ident_name, error_token, error_token_str, .capture);
                payload_val_scope = .{
                    .parent = &else_scope.base,
                    .gen_zir = &else_scope,
                    .name = ident_name,
                    .inst = payload_inst,
                    .token_src = error_token,
                    .id_cat = .capture,
                };
                try else_scope.add_dbg_var(.dbg_var_val, ident_name, payload_inst);
                break :s &payload_val_scope.base;
            } else {
                break :s &else_scope.base;
            }
        };
        const else_result = try full_body_expr(&else_scope, sub_scope, block_scope.break_result_info, else_node);
        if (!else_scope.ends_with_no_return()) {
            // As our last action before the break, "pop" the error trace if needed
            if (do_err_trace)
                try restore_err_ret_index(&else_scope, .{ .block = block }, block_scope.break_result_info, else_node, else_result);
            _ = try else_scope.add_break_with_src_node(.@"break", block, else_result, else_node);
        }
        try check_used(parent_gz, &else_scope.base, sub_scope);
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.add_break(.@"break", block, result);
    }

    try set_cond_br_payload(condbr, cond.bool_bit, &then_scope, &else_scope);

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, block.to_ref(), node);
    } else {
        return block.to_ref();
    }
}

/// Supports `else_scope` stacked on `then_scope`. Unstacks `else_scope` then `then_scope`.
fn set_cond_br_payload(
    condbr: Zir.Inst.Index,
    cond: Zir.Inst.Ref,
    then_scope: *GenZir,
    else_scope: *GenZir,
) !void {
    defer then_scope.unstack();
    defer else_scope.unstack();
    const astgen = then_scope.astgen;
    const then_body = then_scope.instructions_slice_upto(else_scope);
    const else_body = else_scope.instructions_slice();
    const then_body_len = astgen.count_body_len_after_fixups(then_body);
    const else_body_len = astgen.count_body_len_after_fixups(else_body);
    try astgen.extra.ensure_unused_capacity(
        astgen.gpa,
        @typeInfo(Zir.Inst.CondBr).Struct.fields.len + then_body_len + else_body_len,
    );

    const zir_datas = astgen.instructions.items(.data);
    zir_datas[@int_from_enum(condbr)].pl_node.payload_index = astgen.add_extra_assume_capacity(Zir.Inst.CondBr{
        .condition = cond,
        .then_body_len = then_body_len,
        .else_body_len = else_body_len,
    });
    astgen.append_body_with_fixups(then_body);
    astgen.append_body_with_fixups(else_body);
}

fn while_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    while_full: Ast.full.While,
    is_statement: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    if (while_full.label_token) |label_token| {
        try astgen.check_label_redefinition(scope, label_token);
    }

    const is_inline = while_full.inline_token != null;
    if (parent_gz.is_comptime and is_inline) {
        return astgen.fail_tok(while_full.inline_token.?, "redundant inline keyword in comptime scope", .{});
    }
    const loop_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .loop;
    const loop_block = try parent_gz.make_block_inst(loop_tag, node);
    try parent_gz.instructions.append(astgen.gpa, loop_block);

    var loop_scope = parent_gz.make_sub_block(scope);
    loop_scope.is_inline = is_inline;
    loop_scope.set_break_result_info(block_ri);
    defer loop_scope.unstack();

    var cond_scope = parent_gz.make_sub_block(&loop_scope.base);
    defer cond_scope.unstack();

    const payload_is_ref = if (while_full.payload_token) |payload_token|
        token_tags[payload_token] == .asterisk
    else
        false;

    try emit_dbg_node(parent_gz, while_full.ast.cond_expr);
    const cond: struct {
        inst: Zir.Inst.Ref,
        bool_bit: Zir.Inst.Ref,
    } = c: {
        if (while_full.error_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const err_union = try full_body_expr(&cond_scope, &cond_scope.base, cond_ri, while_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_err_ptr else .is_non_err;
            break :c .{
                .inst = err_union,
                .bool_bit = try cond_scope.add_un_node(tag, err_union, while_full.ast.cond_expr),
            };
        } else if (while_full.payload_token) |_| {
            const cond_ri: ResultInfo = .{ .rl = if (payload_is_ref) .ref else .none };
            const optional = try full_body_expr(&cond_scope, &cond_scope.base, cond_ri, while_full.ast.cond_expr);
            const tag: Zir.Inst.Tag = if (payload_is_ref) .is_non_null_ptr else .is_non_null;
            break :c .{
                .inst = optional,
                .bool_bit = try cond_scope.add_un_node(tag, optional, while_full.ast.cond_expr),
            };
        } else {
            const cond = try full_body_expr(&cond_scope, &cond_scope.base, coerced_bool_ri, while_full.ast.cond_expr);
            break :c .{
                .inst = cond,
                .bool_bit = cond,
            };
        }
    };

    const condbr_tag: Zir.Inst.Tag = if (is_inline) .condbr_inline else .condbr;
    const condbr = try cond_scope.add_cond_br(condbr_tag, node);
    const block_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .block;
    const cond_block = try loop_scope.make_block_inst(block_tag, node);
    try cond_scope.set_block_body(cond_block);
    // cond_scope unstacked now, can add new instructions to loop_scope
    try loop_scope.instructions.append(astgen.gpa, cond_block);

    // make scope now but don't stack on parent_gz until loop_scope
    // gets unstacked after cont_expr is emitted and added below
    var then_scope = parent_gz.make_sub_block(&cond_scope.base);
    then_scope.instructions_top = GenZir.unstacked_top;
    defer then_scope.unstack();

    var dbg_var_name: Zir.NullTerminatedString = .empty;
    var dbg_var_inst: Zir.Inst.Ref = undefined;
    var opt_payload_inst: Zir.Inst.OptionalIndex = .none;
    var payload_val_scope: Scope.LocalVal = undefined;
    const then_sub_scope = s: {
        if (while_full.error_token != null) {
            if (while_full.payload_token) |payload_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_payload_unsafe_ptr
                else
                    .err_union_payload_unsafe;
                // will add this instruction to then_scope.instructions below
                const payload_inst = try then_scope.make_un_node(tag, cond.inst, while_full.ast.cond_expr);
                opt_payload_inst = payload_inst.to_optional();
                const ident_token = payload_token + @int_from_bool(payload_is_ref);
                const ident_bytes = tree.token_slice(ident_token);
                if (mem.eql(u8, "_", ident_bytes))
                    break :s &then_scope.base;
                const ident_name = try astgen.ident_as_string(ident_token);
                try astgen.detect_local_shadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
                payload_val_scope = .{
                    .parent = &then_scope.base,
                    .gen_zir = &then_scope,
                    .name = ident_name,
                    .inst = payload_inst.to_ref(),
                    .token_src = ident_token,
                    .id_cat = .capture,
                };
                dbg_var_name = ident_name;
                dbg_var_inst = payload_inst.to_ref();
                break :s &payload_val_scope.base;
            } else {
                _ = try then_scope.add_un_node(.ensure_err_union_payload_void, cond.inst, node);
                break :s &then_scope.base;
            }
        } else if (while_full.payload_token) |payload_token| {
            const ident_token = if (payload_is_ref) payload_token + 1 else payload_token;
            const tag: Zir.Inst.Tag = if (payload_is_ref)
                .optional_payload_unsafe_ptr
            else
                .optional_payload_unsafe;
            // will add this instruction to then_scope.instructions below
            const payload_inst = try then_scope.make_un_node(tag, cond.inst, while_full.ast.cond_expr);
            opt_payload_inst = payload_inst.to_optional();
            const ident_name = try astgen.ident_as_string(ident_token);
            const ident_bytes = tree.token_slice(ident_token);
            if (mem.eql(u8, "_", ident_bytes))
                break :s &then_scope.base;
            try astgen.detect_local_shadowing(&then_scope.base, ident_name, ident_token, ident_bytes, .capture);
            payload_val_scope = .{
                .parent = &then_scope.base,
                .gen_zir = &then_scope,
                .name = ident_name,
                .inst = payload_inst.to_ref(),
                .token_src = ident_token,
                .id_cat = .capture,
            };
            dbg_var_name = ident_name;
            dbg_var_inst = payload_inst.to_ref();
            break :s &payload_val_scope.base;
        } else {
            break :s &then_scope.base;
        }
    };

    var continue_scope = parent_gz.make_sub_block(then_sub_scope);
    continue_scope.instructions_top = GenZir.unstacked_top;
    defer continue_scope.unstack();
    const continue_block = try then_scope.make_block_inst(block_tag, node);

    const repeat_tag: Zir.Inst.Tag = if (is_inline) .repeat_inline else .repeat;
    _ = try loop_scope.add_node(repeat_tag, node);

    try loop_scope.set_block_body(loop_block);
    loop_scope.break_block = loop_block.to_optional();
    loop_scope.continue_block = continue_block.to_optional();
    if (while_full.label_token) |label_token| {
        loop_scope.label = .{
            .token = label_token,
            .block_inst = loop_block,
        };
    }

    // done adding instructions to loop_scope, can now stack then_scope
    then_scope.instructions_top = then_scope.instructions.items.len;

    const then_node = while_full.ast.then_expr;
    if (opt_payload_inst.unwrap()) |payload_inst| {
        try then_scope.instructions.append(astgen.gpa, payload_inst);
    }
    if (dbg_var_name != .empty) try then_scope.add_dbg_var(.dbg_var_val, dbg_var_name, dbg_var_inst);
    try then_scope.instructions.append(astgen.gpa, continue_block);
    // This code could be improved to avoid emitting the continue expr when there
    // are no jumps to it. This happens when the last statement of a while body is noreturn
    // and there are no `continue` statements.
    // Tracking issue: https://github.com/ziglang/zig/issues/9185
    if (while_full.ast.cont_expr != 0) {
        _ = try unused_result_expr(&then_scope, then_sub_scope, while_full.ast.cont_expr);
    }

    continue_scope.instructions_top = continue_scope.instructions.items.len;
    {
        try emit_dbg_node(&continue_scope, then_node);
        const unused_result = try full_body_expr(&continue_scope, &continue_scope.base, .{ .rl = .none }, then_node);
        _ = try add_ensure_result(&continue_scope, unused_result, then_node);
    }
    try check_used(parent_gz, &then_scope.base, then_sub_scope);
    const break_tag: Zir.Inst.Tag = if (is_inline) .break_inline else .@"break";
    if (!continue_scope.ends_with_no_return()) {
        _ = try continue_scope.add_break(break_tag, continue_block, .void_value);
    }
    try continue_scope.set_block_body(continue_block);
    _ = try then_scope.add_break(break_tag, cond_block, .void_value);

    var else_scope = parent_gz.make_sub_block(&cond_scope.base);
    defer else_scope.unstack();

    const else_node = while_full.ast.else_expr;
    if (else_node != 0) {
        const sub_scope = s: {
            if (while_full.error_token) |error_token| {
                const tag: Zir.Inst.Tag = if (payload_is_ref)
                    .err_union_code_ptr
                else
                    .err_union_code;
                const else_payload_inst = try else_scope.add_un_node(tag, cond.inst, while_full.ast.cond_expr);
                const ident_name = try astgen.ident_as_string(error_token);
                const ident_bytes = tree.token_slice(error_token);
                if (mem.eql(u8, ident_bytes, "_"))
                    break :s &else_scope.base;
                try astgen.detect_local_shadowing(&else_scope.base, ident_name, error_token, ident_bytes, .capture);
                payload_val_scope = .{
                    .parent = &else_scope.base,
                    .gen_zir = &else_scope,
                    .name = ident_name,
                    .inst = else_payload_inst,
                    .token_src = error_token,
                    .id_cat = .capture,
                };
                try else_scope.add_dbg_var(.dbg_var_val, ident_name, else_payload_inst);
                break :s &payload_val_scope.base;
            } else {
                break :s &else_scope.base;
            }
        };
        // Remove the continue block and break block so that `continue` and `break`
        // control flow apply to outer loops; not this one.
        loop_scope.continue_block = .none;
        loop_scope.break_block = .none;
        const else_result = try full_body_expr(&else_scope, sub_scope, loop_scope.break_result_info, else_node);
        if (is_statement) {
            _ = try add_ensure_result(&else_scope, else_result, else_node);
        }

        try check_used(parent_gz, &else_scope.base, sub_scope);
        if (!else_scope.ends_with_no_return()) {
            _ = try else_scope.add_break_with_src_node(break_tag, loop_block, else_result, else_node);
        }
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.add_break(break_tag, loop_block, result);
    }

    if (loop_scope.label) |some| {
        if (!some.used) {
            try astgen.append_error_tok(some.token, "unused while loop label", .{});
        }
    }

    try set_cond_br_payload(condbr, cond.bool_bit, &then_scope, &else_scope);

    const result = if (need_result_rvalue)
        try rvalue(parent_gz, ri, loop_block.to_ref(), node)
    else
        loop_block.to_ref();

    if (is_statement) {
        _ = try parent_gz.add_un_node(.ensure_result_used, result, node);
    }

    return result;
}

fn for_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    for_full: Ast.full.For,
    is_statement: bool,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;

    if (for_full.label_token) |label_token| {
        try astgen.check_label_redefinition(scope, label_token);
    }

    const need_rl = astgen.nodes_need_rl.contains(node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    const is_inline = for_full.inline_token != null;
    if (parent_gz.is_comptime and is_inline) {
        return astgen.fail_tok(for_full.inline_token.?, "redundant inline keyword in comptime scope", .{});
    }
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);
    const node_tags = tree.nodes.items(.tag);
    const node_data = tree.nodes.items(.data);
    const gpa = astgen.gpa;

    // For counters, this is the start value; for indexables, this is the base
    // pointer that can be used with elem_ptr and similar instructions.
    // Special value `none` means that this is a counter and its start value is
    // zero, indicating that the main index counter can be used directly.
    const indexables = try gpa.alloc(Zir.Inst.Ref, for_full.ast.inputs.len);
    defer gpa.free(indexables);
    // elements of this array can be `none`, indicating no length check.
    const lens = try gpa.alloc(Zir.Inst.Ref, for_full.ast.inputs.len);
    defer gpa.free(lens);

    // We will use a single zero-based counter no matter how many indexables there are.
    const index_ptr = blk: {
        const alloc_tag: Zir.Inst.Tag = if (is_inline) .alloc_comptime_mut else .alloc;
        const index_ptr = try parent_gz.add_un_node(alloc_tag, .usize_type, node);
        // initialize to zero
        _ = try parent_gz.add_pl_node(.store_node, node, Zir.Inst.Bin{
            .lhs = index_ptr,
            .rhs = .zero_usize,
        });
        break :blk index_ptr;
    };

    var any_len_checks = false;

    {
        var capture_token = for_full.payload_token;
        for (for_full.ast.inputs, indexables, lens) |input, *indexable_ref, *len_ref| {
            const capture_is_ref = token_tags[capture_token] == .asterisk;
            const ident_tok = capture_token + @int_from_bool(capture_is_ref);
            const is_discard = mem.eql(u8, tree.token_slice(ident_tok), "_");

            if (is_discard and capture_is_ref) {
                return astgen.fail_tok(capture_token, "pointer modifier invalid on discard", .{});
            }
            // Skip over the comma, and on to the next capture (or the ending pipe character).
            capture_token = ident_tok + 2;

            try emit_dbg_node(parent_gz, input);
            if (node_tags[input] == .for_range) {
                if (capture_is_ref) {
                    return astgen.fail_tok(ident_tok, "cannot capture reference to range", .{});
                }
                const start_node = node_data[input].lhs;
                const start_val = try expr(parent_gz, scope, .{ .rl = .{ .ty = .usize_type } }, start_node);

                const end_node = node_data[input].rhs;
                const end_val = if (end_node != 0)
                    try expr(parent_gz, scope, .{ .rl = .{ .ty = .usize_type } }, node_data[input].rhs)
                else
                    .none;

                if (end_val == .none and is_discard) {
                    return astgen.fail_tok(ident_tok, "discard of unbounded counter", .{});
                }

                const start_is_zero = node_is_trivially_zero(tree, start_node);
                const range_len = if (end_val == .none or start_is_zero)
                    end_val
                else
                    try parent_gz.add_pl_node(.sub, input, Zir.Inst.Bin{
                        .lhs = end_val,
                        .rhs = start_val,
                    });

                any_len_checks = any_len_checks or range_len != .none;
                indexable_ref.* = if (start_is_zero) .none else start_val;
                len_ref.* = range_len;
            } else {
                const indexable = try expr(parent_gz, scope, .{ .rl = .none }, input);

                any_len_checks = true;
                indexable_ref.* = indexable;
                len_ref.* = indexable;
            }
        }
    }

    if (!any_len_checks) {
        return astgen.fail_node(node, "unbounded for loop", .{});
    }

    // We use a dedicated ZIR instruction to assert the lengths to assist with
    // nicer error reporting as well as fewer ZIR bytes emitted.
    const len: Zir.Inst.Ref = len: {
        const lens_len: u32 = @int_cast(lens.len);
        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.MultiOp).Struct.fields.len + lens_len);
        const len = try parent_gz.add_pl_node(.for_len, node, Zir.Inst.MultiOp{
            .operands_len = lens_len,
        });
        append_refs_assume_capacity(astgen, lens);
        break :len len;
    };

    const loop_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .loop;
    const loop_block = try parent_gz.make_block_inst(loop_tag, node);
    try parent_gz.instructions.append(gpa, loop_block);

    var loop_scope = parent_gz.make_sub_block(scope);
    loop_scope.is_inline = is_inline;
    loop_scope.set_break_result_info(block_ri);
    defer loop_scope.unstack();

    // We need to finish loop_scope later once we have the deferred refs from then_scope. However, the
    // load must be removed from instructions in the meantime or it appears to be part of parent_gz.
    const index = try loop_scope.add_un_node(.load, index_ptr, node);
    _ = loop_scope.instructions.pop();

    var cond_scope = parent_gz.make_sub_block(&loop_scope.base);
    defer cond_scope.unstack();

    // Check the condition.
    const cond = try cond_scope.add_pl_node(.cmp_lt, node, Zir.Inst.Bin{
        .lhs = index,
        .rhs = len,
    });

    const condbr_tag: Zir.Inst.Tag = if (is_inline) .condbr_inline else .condbr;
    const condbr = try cond_scope.add_cond_br(condbr_tag, node);
    const block_tag: Zir.Inst.Tag = if (is_inline) .block_inline else .block;
    const cond_block = try loop_scope.make_block_inst(block_tag, node);
    try cond_scope.set_block_body(cond_block);

    loop_scope.break_block = loop_block.to_optional();
    loop_scope.continue_block = cond_block.to_optional();
    if (for_full.label_token) |label_token| {
        loop_scope.label = .{
            .token = label_token,
            .block_inst = loop_block,
        };
    }

    const then_node = for_full.ast.then_expr;
    var then_scope = parent_gz.make_sub_block(&cond_scope.base);
    defer then_scope.unstack();

    const capture_scopes = try gpa.alloc(Scope.LocalVal, for_full.ast.inputs.len);
    defer gpa.free(capture_scopes);

    const then_sub_scope = blk: {
        var capture_token = for_full.payload_token;
        var capture_sub_scope: *Scope = &then_scope.base;
        for (for_full.ast.inputs, indexables, capture_scopes) |input, indexable_ref, *capture_scope| {
            const capture_is_ref = token_tags[capture_token] == .asterisk;
            const ident_tok = capture_token + @int_from_bool(capture_is_ref);
            const capture_name = tree.token_slice(ident_tok);
            // Skip over the comma, and on to the next capture (or the ending pipe character).
            capture_token = ident_tok + 2;

            if (mem.eql(u8, capture_name, "_")) continue;

            const name_str_index = try astgen.ident_as_string(ident_tok);
            try astgen.detect_local_shadowing(capture_sub_scope, name_str_index, ident_tok, capture_name, .capture);

            const capture_inst = inst: {
                const is_counter = node_tags[input] == .for_range;

                if (indexable_ref == .none) {
                    // Special case: the main index can be used directly.
                    assert(is_counter);
                    assert(!capture_is_ref);
                    break :inst index;
                }

                // For counters, we add the index variable to the start value; for
                // indexables, we use it as an element index. This is so similar
                // that they can share the same code paths, branching only on the
                // ZIR tag.
                const switch_cond = (@as(u2, @int_from_bool(capture_is_ref)) << 1) | @int_from_bool(is_counter);
                const tag: Zir.Inst.Tag = switch (switch_cond) {
                    0b00 => .elem_val,
                    0b01 => .add,
                    0b10 => .elem_ptr,
                    0b11 => unreachable, // compile error emitted already
                };
                break :inst try then_scope.add_pl_node(tag, input, Zir.Inst.Bin{
                    .lhs = indexable_ref,
                    .rhs = index,
                });
            };

            capture_scope.* = .{
                .parent = capture_sub_scope,
                .gen_zir = &then_scope,
                .name = name_str_index,
                .inst = capture_inst,
                .token_src = ident_tok,
                .id_cat = .capture,
            };

            try then_scope.add_dbg_var(.dbg_var_val, name_str_index, capture_inst);
            capture_sub_scope = &capture_scope.base;
        }

        break :blk capture_sub_scope;
    };

    const then_result = try full_body_expr(&then_scope, then_sub_scope, .{ .rl = .none }, then_node);
    _ = try add_ensure_result(&then_scope, then_result, then_node);

    try check_used(parent_gz, &then_scope.base, then_sub_scope);

    const break_tag: Zir.Inst.Tag = if (is_inline) .break_inline else .@"break";

    _ = try then_scope.add_break(break_tag, cond_block, .void_value);

    var else_scope = parent_gz.make_sub_block(&cond_scope.base);
    defer else_scope.unstack();

    const else_node = for_full.ast.else_expr;
    if (else_node != 0) {
        const sub_scope = &else_scope.base;
        // Remove the continue block and break block so that `continue` and `break`
        // control flow apply to outer loops; not this one.
        loop_scope.continue_block = .none;
        loop_scope.break_block = .none;
        const else_result = try full_body_expr(&else_scope, sub_scope, loop_scope.break_result_info, else_node);
        if (is_statement) {
            _ = try add_ensure_result(&else_scope, else_result, else_node);
        }
        if (!else_scope.ends_with_no_return()) {
            _ = try else_scope.add_break_with_src_node(break_tag, loop_block, else_result, else_node);
        }
    } else {
        const result = try rvalue(&else_scope, ri, .void_value, node);
        _ = try else_scope.add_break(break_tag, loop_block, result);
    }

    if (loop_scope.label) |some| {
        if (!some.used) {
            try astgen.append_error_tok(some.token, "unused for loop label", .{});
        }
    }

    try set_cond_br_payload(condbr, cond, &then_scope, &else_scope);

    // then_block and else_block unstacked now, can resurrect loop_scope to finally finish it
    {
        loop_scope.instructions_top = loop_scope.instructions.items.len;
        try loop_scope.instructions.append_slice(gpa, &.{ index.to_index().?, cond_block });

        // Increment the index variable.
        const index_plus_one = try loop_scope.add_pl_node(.add_unsafe, node, Zir.Inst.Bin{
            .lhs = index,
            .rhs = .one_usize,
        });
        _ = try loop_scope.add_pl_node(.store_node, node, Zir.Inst.Bin{
            .lhs = index_ptr,
            .rhs = index_plus_one,
        });
        const repeat_tag: Zir.Inst.Tag = if (is_inline) .repeat_inline else .repeat;
        _ = try loop_scope.add_node(repeat_tag, node);

        try loop_scope.set_block_body(loop_block);
    }

    const result = if (need_result_rvalue)
        try rvalue(parent_gz, ri, loop_block.to_ref(), node)
    else
        loop_block.to_ref();

    if (is_statement) {
        _ = try parent_gz.add_un_node(.ensure_result_used, result, node);
    }
    return result;
}

fn switch_expr_err_union(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    catch_or_if_node: Ast.Node.Index,
    node_ty: enum { @"catch", @"if" },
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    const if_full = switch (node_ty) {
        .@"catch" => undefined,
        .@"if" => tree.full_if(catch_or_if_node).?,
    };

    const switch_node, const operand_node, const error_payload = switch (node_ty) {
        .@"catch" => .{
            node_datas[catch_or_if_node].rhs,
            node_datas[catch_or_if_node].lhs,
            main_tokens[catch_or_if_node] + 2,
        },
        .@"if" => .{
            if_full.ast.else_expr,
            if_full.ast.cond_expr,
            if_full.error_token.?,
        },
    };
    assert(node_tags[switch_node] == .@"switch" or node_tags[switch_node] == .switch_comma);

    const do_err_trace = astgen.fn_block != null;

    const extra = tree.extra_data(node_datas[switch_node].rhs, Ast.Node.SubRange);
    const case_nodes = tree.extra_data[extra.start..extra.end];

    const need_rl = astgen.nodes_need_rl.contains(catch_or_if_node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, catch_or_if_node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };

    const payload_is_ref = switch (node_ty) {
        .@"if" => if_full.payload_token != null and token_tags[if_full.payload_token.?] == .asterisk,
        .@"catch" => ri.rl == .ref or ri.rl == .ref_coerced_ty,
    };

    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);
    var scalar_cases_len: u32 = 0;
    var multi_cases_len: u32 = 0;
    var inline_cases_len: u32 = 0;
    var has_else = false;
    var else_node: Ast.Node.Index = 0;
    var else_src: ?Ast.TokenIndex = null;
    for (case_nodes) |case_node| {
        const case = tree.full_switch_case(case_node).?;

        if (case.ast.values.len == 0) {
            const case_src = case.ast.arrow_token - 1;
            if (else_src) |src| {
                return astgen.fail_tok_notes(
                    case_src,
                    "multiple else prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.err_note_tok(
                            src,
                            "previous else prong here",
                            .{},
                        ),
                    },
                );
            }
            has_else = true;
            else_node = case_node;
            else_src = case_src;
            continue;
        } else if (case.ast.values.len == 1 and
            node_tags[case.ast.values[0]] == .identifier and
            mem.eql(u8, tree.token_slice(main_tokens[case.ast.values[0]]), "_"))
        {
            const case_src = case.ast.arrow_token - 1;
            return astgen.fail_tok_notes(
                case_src,
                "'_' prong is not allowed when switching on errors",
                .{},
                &[_]u32{
                    try astgen.err_note_tok(
                        case_src,
                        "consider using 'else'",
                        .{},
                    ),
                },
            );
        }

        for (case.ast.values) |val| {
            if (node_tags[val] == .string_literal)
                return astgen.fail_node(val, "cannot switch on strings", .{});
        }

        if (case.ast.values.len == 1 and node_tags[case.ast.values[0]] != .switch_range) {
            scalar_cases_len += 1;
        } else {
            multi_cases_len += 1;
        }
        if (case.inline_token != null) {
            inline_cases_len += 1;
        }
    }

    const operand_ri: ResultInfo = .{
        .rl = if (payload_is_ref) .ref else .none,
        .ctx = .error_handling_expr,
    };

    astgen.advance_source_cursor_to_node(operand_node);
    const operand_lc = LineColumn{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const raw_operand = try reachable_expr(parent_gz, scope, operand_ri, operand_node, switch_node);
    const item_ri: ResultInfo = .{ .rl = .none };

    // This contains the data that goes into the `extra` array for the SwitchBlockErrUnion, except
    // the first cases_nodes.len slots are a table that indexes payloads later in the array,
    // with the non-error and else case indices coming first, then scalar_cases_len indexes, then
    // multi_cases_len indexes
    const payloads = &astgen.scratch;
    const scratch_top = astgen.scratch.items.len;
    const case_table_start = scratch_top;
    const scalar_case_table = case_table_start + 1 + @int_from_bool(has_else);
    const multi_case_table = scalar_case_table + scalar_cases_len;
    const case_table_end = multi_case_table + multi_cases_len;

    try astgen.scratch.resize(gpa, case_table_end);
    defer astgen.scratch.items.len = scratch_top;

    var block_scope = parent_gz.make_sub_block(scope);
    // block_scope not used for collecting instructions
    block_scope.instructions_top = GenZir.unstacked_top;
    block_scope.set_break_result_info(block_ri);

    // Sema expects a dbg_stmt immediately before switch_block_err_union
    try emit_dbg_stmt_force_current_index(parent_gz, operand_lc);
    // This gets added to the parent block later, after the item expressions.
    const switch_block = try parent_gz.make_block_inst(.switch_block_err_union, switch_node);

    // We re-use this same scope for all cases, including the special prong, if any.
    var case_scope = parent_gz.make_sub_block(&block_scope.base);
    case_scope.instructions_top = GenZir.unstacked_top;

    {
        const body_len_index: u32 = @int_cast(payloads.items.len);
        payloads.items[case_table_start] = body_len_index;
        try payloads.resize(gpa, body_len_index + 1); // body_len

        case_scope.instructions_top = parent_gz.instructions.items.len;
        defer case_scope.unstack();

        const unwrap_payload_tag: Zir.Inst.Tag = if (payload_is_ref)
            .err_union_payload_unsafe_ptr
        else
            .err_union_payload_unsafe;

        const unwrapped_payload = try case_scope.add_un_node(
            unwrap_payload_tag,
            raw_operand,
            catch_or_if_node,
        );

        switch (node_ty) {
            .@"catch" => {
                const case_result = switch (ri.rl) {
                    .ref, .ref_coerced_ty => unwrapped_payload,
                    else => try rvalue(
                        &case_scope,
                        block_scope.break_result_info,
                        unwrapped_payload,
                        catch_or_if_node,
                    ),
                };
                _ = try case_scope.add_break_with_src_node(
                    .@"break",
                    switch_block,
                    case_result,
                    catch_or_if_node,
                );
            },
            .@"if" => {
                var payload_val_scope: Scope.LocalVal = undefined;

                const then_node = if_full.ast.then_expr;
                const then_sub_scope = s: {
                    assert(if_full.error_token != null);
                    if (if_full.payload_token) |payload_token| {
                        const token_name_index = payload_token + @int_from_bool(payload_is_ref);
                        const ident_name = try astgen.ident_as_string(token_name_index);
                        const token_name_str = tree.token_slice(token_name_index);
                        if (mem.eql(u8, "_", token_name_str))
                            break :s &case_scope.base;
                        try astgen.detect_local_shadowing(
                            &case_scope.base,
                            ident_name,
                            token_name_index,
                            token_name_str,
                            .capture,
                        );
                        payload_val_scope = .{
                            .parent = &case_scope.base,
                            .gen_zir = &case_scope,
                            .name = ident_name,
                            .inst = unwrapped_payload,
                            .token_src = token_name_index,
                            .id_cat = .capture,
                        };
                        try case_scope.add_dbg_var(.dbg_var_val, ident_name, unwrapped_payload);
                        break :s &payload_val_scope.base;
                    } else {
                        _ = try case_scope.add_un_node(
                            .ensure_err_union_payload_void,
                            raw_operand,
                            catch_or_if_node,
                        );
                        break :s &case_scope.base;
                    }
                };
                const then_result = try expr(
                    &case_scope,
                    then_sub_scope,
                    block_scope.break_result_info,
                    then_node,
                );
                try check_used(parent_gz, &case_scope.base, then_sub_scope);
                if (!case_scope.ends_with_no_return()) {
                    _ = try case_scope.add_break_with_src_node(
                        .@"break",
                        switch_block,
                        then_result,
                        then_node,
                    );
                }
            },
        }

        const case_slice = case_scope.instructions_slice();
        // Since we use the switch_block_err_union instruction itself to refer
        // to the capture, which will not be added to the child block, we need
        // to handle ref_table manually.
        const refs_len = refs: {
            var n: usize = 0;
            var check_inst = switch_block;
            while (astgen.ref_table.get(check_inst)) |ref_inst| {
                n += 1;
                check_inst = ref_inst;
            }
            break :refs n;
        };
        const body_len = refs_len + astgen.count_body_len_after_fixups(case_slice);
        try payloads.ensure_unused_capacity(gpa, body_len);
        const capture: Zir.Inst.SwitchBlock.ProngInfo.Capture = switch (node_ty) {
            .@"catch" => .none,
            .@"if" => if (if_full.payload_token == null)
                .none
            else if (payload_is_ref)
                .by_ref
            else
                .by_val,
        };
        payloads.items[body_len_index] = @bit_cast(Zir.Inst.SwitchBlock.ProngInfo{
            .body_len = @int_cast(body_len),
            .capture = capture,
            .is_inline = false,
            .has_tag_capture = false,
        });
        if (astgen.ref_table.fetch_remove(switch_block)) |kv| {
            append_possibly_refd_body_inst(astgen, payloads, kv.value);
        }
        append_body_with_fixups_array_list(astgen, payloads, case_slice);
    }

    const err_name = blk: {
        const err_str = tree.token_slice(error_payload);
        if (mem.eql(u8, err_str, "_")) {
            return astgen.fail_tok(error_payload, "discard of error capture; omit it instead", .{});
        }
        const err_name = try astgen.ident_as_string(error_payload);
        try astgen.detect_local_shadowing(scope, err_name, error_payload, err_str, .capture);

        break :blk err_name;
    };

    // allocate a shared dummy instruction for the error capture
    const err_inst = err_inst: {
        const inst: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        try astgen.instructions.append(astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        break :err_inst inst;
    };

    // In this pass we generate all the item and prong expressions for error cases.
    var multi_case_index: u32 = 0;
    var scalar_case_index: u32 = 0;
    var any_uses_err_capture = false;
    for (case_nodes) |case_node| {
        const case = tree.full_switch_case(case_node).?;

        const is_multi_case = case.ast.values.len > 1 or
            (case.ast.values.len == 1 and node_tags[case.ast.values[0]] == .switch_range);

        var dbg_var_name: Zir.NullTerminatedString = .empty;
        var dbg_var_inst: Zir.Inst.Ref = undefined;
        var err_scope: Scope.LocalVal = undefined;
        var capture_scope: Scope.LocalVal = undefined;

        const sub_scope = blk: {
            err_scope = .{
                .parent = &case_scope.base,
                .gen_zir = &case_scope,
                .name = err_name,
                .inst = err_inst.to_ref(),
                .token_src = error_payload,
                .id_cat = .capture,
            };

            const capture_token = case.payload_token orelse break :blk &err_scope.base;
            if (token_tags[capture_token] != .identifier) {
                return astgen.fail_tok(capture_token + 1, "error set cannot be captured by reference", .{});
            }

            const capture_slice = tree.token_slice(capture_token);
            if (mem.eql(u8, capture_slice, "_")) {
                return astgen.fail_tok(capture_token, "discard of error capture; omit it instead", .{});
            }
            const tag_name = try astgen.ident_as_string(capture_token);
            try astgen.detect_local_shadowing(&case_scope.base, tag_name, capture_token, capture_slice, .capture);

            capture_scope = .{
                .parent = &case_scope.base,
                .gen_zir = &case_scope,
                .name = tag_name,
                .inst = switch_block.to_ref(),
                .token_src = capture_token,
                .id_cat = .capture,
            };
            dbg_var_name = tag_name;
            dbg_var_inst = switch_block.to_ref();

            err_scope.parent = &capture_scope.base;

            break :blk &err_scope.base;
        };

        const header_index: u32 = @int_cast(payloads.items.len);
        const body_len_index = if (is_multi_case) blk: {
            payloads.items[multi_case_table + multi_case_index] = header_index;
            multi_case_index += 1;
            try payloads.resize(gpa, header_index + 3); // items_len, ranges_len, body_len

            // items
            var items_len: u32 = 0;
            for (case.ast.values) |item_node| {
                if (node_tags[item_node] == .switch_range) continue;
                items_len += 1;

                const item_inst = try comptime_expr(parent_gz, scope, item_ri, item_node);
                try payloads.append(gpa, @int_from_enum(item_inst));
            }

            // ranges
            var ranges_len: u32 = 0;
            for (case.ast.values) |range| {
                if (node_tags[range] != .switch_range) continue;
                ranges_len += 1;

                const first = try comptime_expr(parent_gz, scope, item_ri, node_datas[range].lhs);
                const last = try comptime_expr(parent_gz, scope, item_ri, node_datas[range].rhs);
                try payloads.append_slice(gpa, &[_]u32{
                    @int_from_enum(first), @int_from_enum(last),
                });
            }

            payloads.items[header_index] = items_len;
            payloads.items[header_index + 1] = ranges_len;
            break :blk header_index + 2;
        } else if (case_node == else_node) blk: {
            payloads.items[case_table_start + 1] = header_index;
            try payloads.resize(gpa, header_index + 1); // body_len
            break :blk header_index;
        } else blk: {
            payloads.items[scalar_case_table + scalar_case_index] = header_index;
            scalar_case_index += 1;
            try payloads.resize(gpa, header_index + 2); // item, body_len
            const item_node = case.ast.values[0];
            const item_inst = try comptime_expr(parent_gz, scope, item_ri, item_node);
            payloads.items[header_index] = @int_from_enum(item_inst);
            break :blk header_index + 1;
        };

        {
            // temporarily stack case_scope on parent_gz
            case_scope.instructions_top = parent_gz.instructions.items.len;
            defer case_scope.unstack();

            if (do_err_trace and node_may_append_to_error_trace(tree, operand_node))
                _ = try case_scope.add_save_err_ret_index(.always);

            if (dbg_var_name != .empty) {
                try case_scope.add_dbg_var(.dbg_var_val, dbg_var_name, dbg_var_inst);
            }

            const target_expr_node = case.ast.target_expr;
            const case_result = try full_body_expr(&case_scope, sub_scope, block_scope.break_result_info, target_expr_node);
            // check capture_scope, not err_scope to avoid false positive unused error capture
            try check_used(parent_gz, &case_scope.base, err_scope.parent);
            const uses_err = err_scope.used != 0 or err_scope.discarded != 0;
            if (uses_err) {
                try case_scope.add_dbg_var(.dbg_var_val, err_name, err_inst.to_ref());
                any_uses_err_capture = true;
            }

            if (!parent_gz.ref_is_no_return(case_result)) {
                if (do_err_trace)
                    try restore_err_ret_index(
                        &case_scope,
                        .{ .block = switch_block },
                        block_scope.break_result_info,
                        target_expr_node,
                        case_result,
                    );

                _ = try case_scope.add_break_with_src_node(.@"break", switch_block, case_result, target_expr_node);
            }

            const case_slice = case_scope.instructions_slice();
            // Since we use the switch_block_err_union instruction itself to refer
            // to the capture, which will not be added to the child block, we need
            // to handle ref_table manually.
            const refs_len = refs: {
                var n: usize = 0;
                var check_inst = switch_block;
                while (astgen.ref_table.get(check_inst)) |ref_inst| {
                    n += 1;
                    check_inst = ref_inst;
                }
                if (uses_err) {
                    check_inst = err_inst;
                    while (astgen.ref_table.get(check_inst)) |ref_inst| {
                        n += 1;
                        check_inst = ref_inst;
                    }
                }
                break :refs n;
            };
            const body_len = refs_len + astgen.count_body_len_after_fixups(case_slice);
            try payloads.ensure_unused_capacity(gpa, body_len);
            payloads.items[body_len_index] = @bit_cast(Zir.Inst.SwitchBlock.ProngInfo{
                .body_len = @int_cast(body_len),
                .capture = if (case.payload_token != null) .by_val else .none,
                .is_inline = case.inline_token != null,
                .has_tag_capture = false,
            });
            if (astgen.ref_table.fetch_remove(switch_block)) |kv| {
                append_possibly_refd_body_inst(astgen, payloads, kv.value);
            }
            if (uses_err) {
                if (astgen.ref_table.fetch_remove(err_inst)) |kv| {
                    append_possibly_refd_body_inst(astgen, payloads, kv.value);
                }
            }
            append_body_with_fixups_array_list(astgen, payloads, case_slice);
        }
    }
    // Now that the item expressions are generated we can add this.
    try parent_gz.instructions.append(gpa, switch_block);

    try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.SwitchBlockErrUnion).Struct.fields.len +
        @int_from_bool(multi_cases_len != 0) +
        payloads.items.len - case_table_end +
        (case_table_end - case_table_start) * @typeInfo(Zir.Inst.As).Struct.fields.len);

    const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.SwitchBlockErrUnion{
        .operand = raw_operand,
        .bits = Zir.Inst.SwitchBlockErrUnion.Bits{
            .has_multi_cases = multi_cases_len != 0,
            .has_else = has_else,
            .scalar_cases_len = @int_cast(scalar_cases_len),
            .any_uses_err_capture = any_uses_err_capture,
            .payload_is_ref = payload_is_ref,
        },
        .main_src_node_offset = parent_gz.node_index_to_relative(catch_or_if_node),
    });

    if (multi_cases_len != 0) {
        astgen.extra.append_assume_capacity(multi_cases_len);
    }

    if (any_uses_err_capture) {
        astgen.extra.append_assume_capacity(@int_from_enum(err_inst));
    }

    const zir_datas = astgen.instructions.items(.data);
    zir_datas[@int_from_enum(switch_block)].pl_node.payload_index = payload_index;

    for (payloads.items[case_table_start..case_table_end], 0..) |start_index, i| {
        var body_len_index = start_index;
        var end_index = start_index;
        const table_index = case_table_start + i;
        if (table_index < scalar_case_table) {
            end_index += 1;
        } else if (table_index < multi_case_table) {
            body_len_index += 1;
            end_index += 2;
        } else {
            body_len_index += 2;
            const items_len = payloads.items[start_index];
            const ranges_len = payloads.items[start_index + 1];
            end_index += 3 + items_len + 2 * ranges_len;
        }
        const prong_info: Zir.Inst.SwitchBlock.ProngInfo = @bit_cast(payloads.items[body_len_index]);
        end_index += prong_info.body_len;
        astgen.extra.append_slice_assume_capacity(payloads.items[start_index..end_index]);
    }

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, switch_block.to_ref(), switch_node);
    } else {
        return switch_block.to_ref();
    }
}

fn switch_expr(
    parent_gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    switch_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = parent_gz.astgen;
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);
    const operand_node = node_datas[switch_node].lhs;
    const extra = tree.extra_data(node_datas[switch_node].rhs, Ast.Node.SubRange);
    const case_nodes = tree.extra_data[extra.start..extra.end];

    const need_rl = astgen.nodes_need_rl.contains(switch_node);
    const block_ri: ResultInfo = if (need_rl) ri else .{
        .rl = switch (ri.rl) {
            .ptr => .{ .ty = (try ri.rl.result_type(parent_gz, switch_node)).? },
            .inferred_ptr => .none,
            else => ri.rl,
        },
        .ctx = ri.ctx,
    };
    // We need to call `rvalue` to write through to the pointer only if we had a
    // result pointer and aren't forwarding it.
    const LocTag = @typeInfo(ResultInfo.Loc).Union.tag_type.?;
    const need_result_rvalue = @as(LocTag, block_ri.rl) != @as(LocTag, ri.rl);

    // We perform two passes over the AST. This first pass is to collect information
    // for the following variables, make note of the special prong AST node index,
    // and bail out with a compile error if there are multiple special prongs present.
    var any_payload_is_ref = false;
    var any_has_tag_capture = false;
    var scalar_cases_len: u32 = 0;
    var multi_cases_len: u32 = 0;
    var inline_cases_len: u32 = 0;
    var special_prong: Zir.SpecialProng = .none;
    var special_node: Ast.Node.Index = 0;
    var else_src: ?Ast.TokenIndex = null;
    var underscore_src: ?Ast.TokenIndex = null;
    for (case_nodes) |case_node| {
        const case = tree.full_switch_case(case_node).?;
        if (case.payload_token) |payload_token| {
            const ident = if (token_tags[payload_token] == .asterisk) blk: {
                any_payload_is_ref = true;
                break :blk payload_token + 1;
            } else payload_token;
            if (token_tags[ident + 1] == .comma) {
                any_has_tag_capture = true;
            }
        }
        // Check for else/`_` prong.
        if (case.ast.values.len == 0) {
            const case_src = case.ast.arrow_token - 1;
            if (else_src) |src| {
                return astgen.fail_tok_notes(
                    case_src,
                    "multiple else prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.err_note_tok(
                            src,
                            "previous else prong here",
                            .{},
                        ),
                    },
                );
            } else if (underscore_src) |some_underscore| {
                return astgen.fail_node_notes(
                    switch_node,
                    "else and '_' prong in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.err_note_tok(
                            case_src,
                            "else prong here",
                            .{},
                        ),
                        try astgen.err_note_tok(
                            some_underscore,
                            "'_' prong here",
                            .{},
                        ),
                    },
                );
            }
            special_node = case_node;
            special_prong = .@"else";
            else_src = case_src;
            continue;
        } else if (case.ast.values.len == 1 and
            node_tags[case.ast.values[0]] == .identifier and
            mem.eql(u8, tree.token_slice(main_tokens[case.ast.values[0]]), "_"))
        {
            const case_src = case.ast.arrow_token - 1;
            if (underscore_src) |src| {
                return astgen.fail_tok_notes(
                    case_src,
                    "multiple '_' prongs in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.err_note_tok(
                            src,
                            "previous '_' prong here",
                            .{},
                        ),
                    },
                );
            } else if (else_src) |some_else| {
                return astgen.fail_node_notes(
                    switch_node,
                    "else and '_' prong in switch expression",
                    .{},
                    &[_]u32{
                        try astgen.err_note_tok(
                            some_else,
                            "else prong here",
                            .{},
                        ),
                        try astgen.err_note_tok(
                            case_src,
                            "'_' prong here",
                            .{},
                        ),
                    },
                );
            }
            if (case.inline_token != null) {
                return astgen.fail_tok(case_src, "cannot inline '_' prong", .{});
            }
            special_node = case_node;
            special_prong = .under;
            underscore_src = case_src;
            continue;
        }

        for (case.ast.values) |val| {
            if (node_tags[val] == .string_literal)
                return astgen.fail_node(val, "cannot switch on strings", .{});
        }

        if (case.ast.values.len == 1 and node_tags[case.ast.values[0]] != .switch_range) {
            scalar_cases_len += 1;
        } else {
            multi_cases_len += 1;
        }
        if (case.inline_token != null) {
            inline_cases_len += 1;
        }
    }

    const operand_ri: ResultInfo = .{ .rl = if (any_payload_is_ref) .ref else .none };

    astgen.advance_source_cursor_to_node(operand_node);
    const operand_lc = LineColumn{ astgen.source_line - parent_gz.decl_line, astgen.source_column };

    const raw_operand = try expr(parent_gz, scope, operand_ri, operand_node);
    const item_ri: ResultInfo = .{ .rl = .none };

    // This contains the data that goes into the `extra` array for the SwitchBlock/SwitchBlockMulti,
    // except the first cases_nodes.len slots are a table that indexes payloads later in the array, with
    // the special case index coming first, then scalar_case_len indexes, then multi_cases_len indexes
    const payloads = &astgen.scratch;
    const scratch_top = astgen.scratch.items.len;
    const case_table_start = scratch_top;
    const scalar_case_table = case_table_start + @int_from_bool(special_prong != .none);
    const multi_case_table = scalar_case_table + scalar_cases_len;
    const case_table_end = multi_case_table + multi_cases_len;
    try astgen.scratch.resize(gpa, case_table_end);
    defer astgen.scratch.items.len = scratch_top;

    var block_scope = parent_gz.make_sub_block(scope);
    // block_scope not used for collecting instructions
    block_scope.instructions_top = GenZir.unstacked_top;
    block_scope.set_break_result_info(block_ri);

    // Sema expects a dbg_stmt immediately before switch_block(_ref)
    try emit_dbg_stmt_force_current_index(parent_gz, operand_lc);
    // This gets added to the parent block later, after the item expressions.
    const switch_tag: Zir.Inst.Tag = if (any_payload_is_ref) .switch_block_ref else .switch_block;
    const switch_block = try parent_gz.make_block_inst(switch_tag, switch_node);

    // We re-use this same scope for all cases, including the special prong, if any.
    var case_scope = parent_gz.make_sub_block(&block_scope.base);
    case_scope.instructions_top = GenZir.unstacked_top;

    // If any prong has an inline tag capture, allocate a shared dummy instruction for it
    const tag_inst = if (any_has_tag_capture) tag_inst: {
        const inst: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        try astgen.instructions.append(astgen.gpa, .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .value_placeholder,
                .small = undefined,
                .operand = undefined,
            } },
        });
        break :tag_inst inst;
    } else undefined;

    // In this pass we generate all the item and prong expressions.
    var multi_case_index: u32 = 0;
    var scalar_case_index: u32 = 0;
    for (case_nodes) |case_node| {
        const case = tree.full_switch_case(case_node).?;

        const is_multi_case = case.ast.values.len > 1 or
            (case.ast.values.len == 1 and node_tags[case.ast.values[0]] == .switch_range);

        var dbg_var_name: Zir.NullTerminatedString = .empty;
        var dbg_var_inst: Zir.Inst.Ref = undefined;
        var dbg_var_tag_name: Zir.NullTerminatedString = .empty;
        var dbg_var_tag_inst: Zir.Inst.Ref = undefined;
        var has_tag_capture = false;
        var capture_val_scope: Scope.LocalVal = undefined;
        var tag_scope: Scope.LocalVal = undefined;

        var capture: Zir.Inst.SwitchBlock.ProngInfo.Capture = .none;

        const sub_scope = blk: {
            const payload_token = case.payload_token orelse break :blk &case_scope.base;
            const ident = if (token_tags[payload_token] == .asterisk)
                payload_token + 1
            else
                payload_token;

            const is_ptr = ident != payload_token;
            capture = if (is_ptr) .by_ref else .by_val;

            const ident_slice = tree.token_slice(ident);
            var payload_sub_scope: *Scope = undefined;
            if (mem.eql(u8, ident_slice, "_")) {
                if (is_ptr) {
                    return astgen.fail_tok(payload_token, "pointer modifier invalid on discard", .{});
                }
                payload_sub_scope = &case_scope.base;
            } else {
                const capture_name = try astgen.ident_as_string(ident);
                try astgen.detect_local_shadowing(&case_scope.base, capture_name, ident, ident_slice, .capture);
                capture_val_scope = .{
                    .parent = &case_scope.base,
                    .gen_zir = &case_scope,
                    .name = capture_name,
                    .inst = switch_block.to_ref(),
                    .token_src = ident,
                    .id_cat = .capture,
                };
                dbg_var_name = capture_name;
                dbg_var_inst = switch_block.to_ref();
                payload_sub_scope = &capture_val_scope.base;
            }

            const tag_token = if (token_tags[ident + 1] == .comma)
                ident + 2
            else
                break :blk payload_sub_scope;
            const tag_slice = tree.token_slice(tag_token);
            if (mem.eql(u8, tag_slice, "_")) {
                return astgen.fail_tok(tag_token, "discard of tag capture; omit it instead", .{});
            } else if (case.inline_token == null) {
                return astgen.fail_tok(tag_token, "tag capture on non-inline prong", .{});
            }
            const tag_name = try astgen.ident_as_string(tag_token);
            try astgen.detect_local_shadowing(payload_sub_scope, tag_name, tag_token, tag_slice, .@"switch tag capture");

            assert(any_has_tag_capture);
            has_tag_capture = true;

            tag_scope = .{
                .parent = payload_sub_scope,
                .gen_zir = &case_scope,
                .name = tag_name,
                .inst = tag_inst.to_ref(),
                .token_src = tag_token,
                .id_cat = .@"switch tag capture",
            };
            dbg_var_tag_name = tag_name;
            dbg_var_tag_inst = tag_inst.to_ref();
            break :blk &tag_scope.base;
        };

        const header_index: u32 = @int_cast(payloads.items.len);
        const body_len_index = if (is_multi_case) blk: {
            payloads.items[multi_case_table + multi_case_index] = header_index;
            multi_case_index += 1;
            try payloads.resize(gpa, header_index + 3); // items_len, ranges_len, body_len

            // items
            var items_len: u32 = 0;
            for (case.ast.values) |item_node| {
                if (node_tags[item_node] == .switch_range) continue;
                items_len += 1;

                const item_inst = try comptime_expr(parent_gz, scope, item_ri, item_node);
                try payloads.append(gpa, @int_from_enum(item_inst));
            }

            // ranges
            var ranges_len: u32 = 0;
            for (case.ast.values) |range| {
                if (node_tags[range] != .switch_range) continue;
                ranges_len += 1;

                const first = try comptime_expr(parent_gz, scope, item_ri, node_datas[range].lhs);
                const last = try comptime_expr(parent_gz, scope, item_ri, node_datas[range].rhs);
                try payloads.append_slice(gpa, &[_]u32{
                    @int_from_enum(first), @int_from_enum(last),
                });
            }

            payloads.items[header_index] = items_len;
            payloads.items[header_index + 1] = ranges_len;
            break :blk header_index + 2;
        } else if (case_node == special_node) blk: {
            payloads.items[case_table_start] = header_index;
            try payloads.resize(gpa, header_index + 1); // body_len
            break :blk header_index;
        } else blk: {
            payloads.items[scalar_case_table + scalar_case_index] = header_index;
            scalar_case_index += 1;
            try payloads.resize(gpa, header_index + 2); // item, body_len
            const item_node = case.ast.values[0];
            const item_inst = try comptime_expr(parent_gz, scope, item_ri, item_node);
            payloads.items[header_index] = @int_from_enum(item_inst);
            break :blk header_index + 1;
        };

        {
            // temporarily stack case_scope on parent_gz
            case_scope.instructions_top = parent_gz.instructions.items.len;
            defer case_scope.unstack();

            if (dbg_var_name != .empty) {
                try case_scope.add_dbg_var(.dbg_var_val, dbg_var_name, dbg_var_inst);
            }
            if (dbg_var_tag_name != .empty) {
                try case_scope.add_dbg_var(.dbg_var_val, dbg_var_tag_name, dbg_var_tag_inst);
            }
            const target_expr_node = case.ast.target_expr;
            const case_result = try full_body_expr(&case_scope, sub_scope, block_scope.break_result_info, target_expr_node);
            try check_used(parent_gz, &case_scope.base, sub_scope);
            if (!parent_gz.ref_is_no_return(case_result)) {
                _ = try case_scope.add_break_with_src_node(.@"break", switch_block, case_result, target_expr_node);
            }

            const case_slice = case_scope.instructions_slice();
            // Since we use the switch_block instruction itself to refer to the
            // capture, which will not be added to the child block, we need to
            // handle ref_table manually, and the same for the inline tag
            // capture instruction.
            const refs_len = refs: {
                var n: usize = 0;
                var check_inst = switch_block;
                while (astgen.ref_table.get(check_inst)) |ref_inst| {
                    n += 1;
                    check_inst = ref_inst;
                }
                if (has_tag_capture) {
                    check_inst = tag_inst;
                    while (astgen.ref_table.get(check_inst)) |ref_inst| {
                        n += 1;
                        check_inst = ref_inst;
                    }
                }
                break :refs n;
            };
            const body_len = refs_len + astgen.count_body_len_after_fixups(case_slice);
            try payloads.ensure_unused_capacity(gpa, body_len);
            payloads.items[body_len_index] = @bit_cast(Zir.Inst.SwitchBlock.ProngInfo{
                .body_len = @int_cast(body_len),
                .capture = capture,
                .is_inline = case.inline_token != null,
                .has_tag_capture = has_tag_capture,
            });
            if (astgen.ref_table.fetch_remove(switch_block)) |kv| {
                append_possibly_refd_body_inst(astgen, payloads, kv.value);
            }
            if (has_tag_capture) {
                if (astgen.ref_table.fetch_remove(tag_inst)) |kv| {
                    append_possibly_refd_body_inst(astgen, payloads, kv.value);
                }
            }
            append_body_with_fixups_array_list(astgen, payloads, case_slice);
        }
    }
    // Now that the item expressions are generated we can add this.
    try parent_gz.instructions.append(gpa, switch_block);

    try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.SwitchBlock).Struct.fields.len +
        @int_from_bool(multi_cases_len != 0) +
        @int_from_bool(any_has_tag_capture) +
        payloads.items.len - case_table_end +
        (case_table_end - case_table_start) * @typeInfo(Zir.Inst.As).Struct.fields.len);

    const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.SwitchBlock{
        .operand = raw_operand,
        .bits = Zir.Inst.SwitchBlock.Bits{
            .has_multi_cases = multi_cases_len != 0,
            .has_else = special_prong == .@"else",
            .has_under = special_prong == .under,
            .any_has_tag_capture = any_has_tag_capture,
            .scalar_cases_len = @int_cast(scalar_cases_len),
        },
    });

    if (multi_cases_len != 0) {
        astgen.extra.append_assume_capacity(multi_cases_len);
    }

    if (any_has_tag_capture) {
        astgen.extra.append_assume_capacity(@int_from_enum(tag_inst));
    }

    const zir_datas = astgen.instructions.items(.data);
    zir_datas[@int_from_enum(switch_block)].pl_node.payload_index = payload_index;

    for (payloads.items[case_table_start..case_table_end], 0..) |start_index, i| {
        var body_len_index = start_index;
        var end_index = start_index;
        const table_index = case_table_start + i;
        if (table_index < scalar_case_table) {
            end_index += 1;
        } else if (table_index < multi_case_table) {
            body_len_index += 1;
            end_index += 2;
        } else {
            body_len_index += 2;
            const items_len = payloads.items[start_index];
            const ranges_len = payloads.items[start_index + 1];
            end_index += 3 + items_len + 2 * ranges_len;
        }
        const prong_info: Zir.Inst.SwitchBlock.ProngInfo = @bit_cast(payloads.items[body_len_index]);
        end_index += prong_info.body_len;
        astgen.extra.append_slice_assume_capacity(payloads.items[start_index..end_index]);
    }

    if (need_result_rvalue) {
        return rvalue(parent_gz, ri, switch_block.to_ref(), switch_node);
    } else {
        return switch_block.to_ref();
    }
}

fn ret(gz: *GenZir, scope: *Scope, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);

    if (astgen.fn_block == null) {
        return astgen.fail_node(node, "'return' outside function scope", .{});
    }

    if (gz.any_defer_node != 0) {
        return astgen.fail_node_notes(node, "cannot return from defer expression", .{}, &.{
            try astgen.err_note_node(
                gz.any_defer_node,
                "defer expression here",
                .{},
            ),
        });
    }

    // Ensure debug line/column information is emitted for this return expression.
    // Then we will save the line/column so that we can emit another one that goes
    // "backwards" because we want to evaluate the operand, but then put the debug
    // info back at the return keyword for error return tracing.
    if (!gz.is_comptime) {
        try emit_dbg_node(gz, node);
    }
    const ret_lc = LineColumn{ astgen.source_line - gz.decl_line, astgen.source_column };

    const defer_outer = &astgen.fn_block.?.base;

    const operand_node = node_datas[node].lhs;
    if (operand_node == 0) {
        // Returning a void value; skip error defers.
        try gen_defers(gz, defer_outer, scope, .normal_only);

        // As our last action before the return, "pop" the error trace if needed
        _ = try gz.add_restore_err_ret_index(.ret, .always, node);

        _ = try gz.add_un_node(.ret_node, .void_value, node);
        return Zir.Inst.Ref.unreachable_value;
    }

    if (node_tags[operand_node] == .error_value) {
        // Hot path for `return error.Foo`. This bypasses result location logic as well as logic
        // for detecting whether to add something to the function's inferred error set.
        const ident_token = node_datas[operand_node].rhs;
        const err_name_str_index = try astgen.ident_as_string(ident_token);
        const defer_counts = count_defers(defer_outer, scope);
        if (!defer_counts.need_err_code) {
            try gen_defers(gz, defer_outer, scope, .both_sans_err);
            try emit_dbg_stmt(gz, ret_lc);
            _ = try gz.add_str_tok(.ret_err_value, err_name_str_index, ident_token);
            return Zir.Inst.Ref.unreachable_value;
        }
        const err_code = try gz.add_str_tok(.ret_err_value_code, err_name_str_index, ident_token);
        try gen_defers(gz, defer_outer, scope, .{ .both = err_code });
        try emit_dbg_stmt(gz, ret_lc);
        _ = try gz.add_un_node(.ret_node, err_code, node);
        return Zir.Inst.Ref.unreachable_value;
    }

    const ri: ResultInfo = if (astgen.nodes_need_rl.contains(node)) .{
        .rl = .{ .ptr = .{ .inst = try gz.add_node(.ret_ptr, node) } },
        .ctx = .@"return",
    } else .{
        .rl = .{ .coerced_ty = astgen.fn_ret_ty },
        .ctx = .@"return",
    };
    const prev_anon_name_strategy = gz.anon_name_strategy;
    gz.anon_name_strategy = .func;
    const operand = try reachable_expr(gz, scope, ri, operand_node, node);
    gz.anon_name_strategy = prev_anon_name_strategy;

    switch (node_may_eval_to_error(tree, operand_node)) {
        .never => {
            // Returning a value that cannot be an error; skip error defers.
            try gen_defers(gz, defer_outer, scope, .normal_only);

            // As our last action before the return, "pop" the error trace if needed
            _ = try gz.add_restore_err_ret_index(.ret, .always, node);

            try emit_dbg_stmt(gz, ret_lc);
            try gz.add_ret(ri, operand, node);
            return Zir.Inst.Ref.unreachable_value;
        },
        .always => {
            // Value is always an error. Emit both error defers and regular defers.
            const err_code = if (ri.rl == .ptr) try gz.add_un_node(.load, ri.rl.ptr.inst, node) else operand;
            try gen_defers(gz, defer_outer, scope, .{ .both = err_code });
            try emit_dbg_stmt(gz, ret_lc);
            try gz.add_ret(ri, operand, node);
            return Zir.Inst.Ref.unreachable_value;
        },
        .maybe => {
            const defer_counts = count_defers(defer_outer, scope);
            if (!defer_counts.have_err) {
                // Only regular defers; no branch needed.
                try gen_defers(gz, defer_outer, scope, .normal_only);
                try emit_dbg_stmt(gz, ret_lc);

                // As our last action before the return, "pop" the error trace if needed
                const result = if (ri.rl == .ptr) try gz.add_un_node(.load, ri.rl.ptr.inst, node) else operand;
                _ = try gz.add_restore_err_ret_index(.ret, .{ .if_non_error = result }, node);

                try gz.add_ret(ri, operand, node);
                return Zir.Inst.Ref.unreachable_value;
            }

            // Emit conditional branch for generating errdefers.
            const result = if (ri.rl == .ptr) try gz.add_un_node(.load, ri.rl.ptr.inst, node) else operand;
            const is_non_err = try gz.add_un_node(.ret_is_non_err, result, node);
            const condbr = try gz.add_cond_br(.condbr, node);

            var then_scope = gz.make_sub_block(scope);
            defer then_scope.unstack();

            try gen_defers(&then_scope, defer_outer, scope, .normal_only);

            // As our last action before the return, "pop" the error trace if needed
            _ = try then_scope.add_restore_err_ret_index(.ret, .always, node);

            try emit_dbg_stmt(&then_scope, ret_lc);
            try then_scope.add_ret(ri, operand, node);

            var else_scope = gz.make_sub_block(scope);
            defer else_scope.unstack();

            const which_ones: DefersToEmit = if (!defer_counts.need_err_code) .both_sans_err else .{
                .both = try else_scope.add_un_node(.err_union_code, result, node),
            };
            try gen_defers(&else_scope, defer_outer, scope, which_ones);
            try emit_dbg_stmt(&else_scope, ret_lc);
            try else_scope.add_ret(ri, operand, node);

            try set_cond_br_payload(condbr, is_non_err, &then_scope, &else_scope);

            return Zir.Inst.Ref.unreachable_value;
        },
    }
}

/// Parses the string `buf` as a base 10 integer of type `u16`.
///
/// Unlike std.fmt.parse_int, does not allow the '_' character in `buf`.
fn parse_bit_count(buf: []const u8) std.fmt.ParseIntError!u16 {
    if (buf.len == 0) return error.InvalidCharacter;

    var x: u16 = 0;

    for (buf) |c| {
        const digit = switch (c) {
            '0'...'9' => c - '0',
            else => return error.InvalidCharacter,
        };

        if (x != 0) x = try std.math.mul(u16, x, 10);
        x = try std.math.add(u16, x, digit);
    }

    return x;
}

fn identifier(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    ident: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);

    const ident_token = main_tokens[ident];
    const ident_name_raw = tree.token_slice(ident_token);
    if (mem.eql(u8, ident_name_raw, "_")) {
        return astgen.fail_node(ident, "'_' used as an identifier without @\"_\" syntax", .{});
    }

    // if not @"" syntax, just use raw token slice
    if (ident_name_raw[0] != '@') {
        if (primitive_instrs.get(ident_name_raw)) |zir_const_ref| {
            return rvalue(gz, ri, zir_const_ref, ident);
        }

        if (ident_name_raw.len >= 2) integer: {
            const first_c = ident_name_raw[0];
            if (first_c == 'i' or first_c == 'u') {
                const signedness: std.builtin.Signedness = switch (first_c == 'i') {
                    true => .signed,
                    false => .unsigned,
                };
                if (ident_name_raw.len >= 3 and ident_name_raw[1] == '0') {
                    return astgen.fail_node(
                        ident,
                        "primitive integer type '{s}' has leading zero",
                        .{ident_name_raw},
                    );
                }
                const bit_count = parse_bit_count(ident_name_raw[1..]) catch |err| switch (err) {
                    error.Overflow => return astgen.fail_node(
                        ident,
                        "primitive integer type '{s}' exceeds maximum bit width of 65535",
                        .{ident_name_raw},
                    ),
                    error.InvalidCharacter => break :integer,
                };
                const result = try gz.add(.{
                    .tag = .int_type,
                    .data = .{ .int_type = .{
                        .src_node = gz.node_index_to_relative(ident),
                        .signedness = signedness,
                        .bit_count = bit_count,
                    } },
                });
                return rvalue(gz, ri, result, ident);
            }
        }
    }

    // Local variables, including function parameters.
    return local_var_ref(gz, scope, ri, ident, ident_token);
}

fn local_var_ref(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    ident: Ast.Node.Index,
    ident_token: Ast.TokenIndex,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const name_str_index = try astgen.ident_as_string(ident_token);
    var s = scope;
    var found_already: ?Ast.Node.Index = null; // we have found a decl with the same name already
    var found_needs_tunnel: bool = undefined; // defined when `found_already != null`
    var found_namespaces_out: u32 = undefined; // defined when `found_already != null`

    // The number of namespaces above `gz` we currently are
    var num_namespaces_out: u32 = 0;
    // defined by `num_namespaces_out != 0`
    var capturing_namespace: *Scope.Namespace = undefined;

    while (true) switch (s.tag) {
        .local_val => {
            const local_val = s.cast(Scope.LocalVal).?;

            if (local_val.name == name_str_index) {
                // Locals cannot shadow anything, so we do not need to look for ambiguous
                // references in this case.
                if (ri.rl == .discard and ri.ctx == .assignment) {
                    local_val.discarded = ident_token;
                } else {
                    local_val.used = ident_token;
                }

                const value_inst = if (num_namespaces_out != 0) try tunnel_through_closure(
                    gz,
                    ident,
                    num_namespaces_out,
                    .{ .ref = local_val.inst },
                    .{ .token = local_val.token_src },
                ) else local_val.inst;

                return rvalue_no_coerce_pre_ref(gz, ri, value_inst, ident);
            }
            s = local_val.parent;
        },
        .local_ptr => {
            const local_ptr = s.cast(Scope.LocalPtr).?;
            if (local_ptr.name == name_str_index) {
                if (ri.rl == .discard and ri.ctx == .assignment) {
                    local_ptr.discarded = ident_token;
                } else {
                    local_ptr.used = ident_token;
                }

                // Can't close over a runtime variable
                if (num_namespaces_out != 0 and !local_ptr.maybe_comptime and !gz.is_typeof) {
                    const ident_name = try astgen.identifier_token_string(ident_token);
                    return astgen.fail_node_notes(ident, "mutable '{s}' not accessible from here", .{ident_name}, &.{
                        try astgen.err_note_tok(local_ptr.token_src, "declared mutable here", .{}),
                        try astgen.err_note_node(capturing_namespace.node, "crosses namespace boundary here", .{}),
                    });
                }

                switch (ri.rl) {
                    .ref, .ref_coerced_ty => {
                        const ptr_inst = if (num_namespaces_out != 0) try tunnel_through_closure(
                            gz,
                            ident,
                            num_namespaces_out,
                            .{ .ref = local_ptr.ptr },
                            .{ .token = local_ptr.token_src },
                        ) else local_ptr.ptr;
                        local_ptr.used_as_lvalue = true;
                        return ptr_inst;
                    },
                    else => {
                        const val_inst = if (num_namespaces_out != 0) try tunnel_through_closure(
                            gz,
                            ident,
                            num_namespaces_out,
                            .{ .ref_load = local_ptr.ptr },
                            .{ .token = local_ptr.token_src },
                        ) else try gz.add_un_node(.load, local_ptr.ptr, ident);
                        return rvalue_no_coerce_pre_ref(gz, ri, val_inst, ident);
                    },
                }
            }
            s = local_ptr.parent;
        },
        .gen_zir => s = s.cast(GenZir).?.parent,
        .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
        .namespace => {
            const ns = s.cast(Scope.Namespace).?;
            if (ns.decls.get(name_str_index)) |i| {
                if (found_already) |f| {
                    return astgen.fail_node_notes(ident, "ambiguous reference", .{}, &.{
                        try astgen.err_note_node(f, "declared here", .{}),
                        try astgen.err_note_node(i, "also declared here", .{}),
                    });
                }
                // We found a match but must continue looking for ambiguous references to decls.
                found_already = i;
                found_needs_tunnel = ns.maybe_generic;
                found_namespaces_out = num_namespaces_out;
            }
            num_namespaces_out += 1;
            capturing_namespace = ns;
            s = ns.parent;
        },
        .top => break,
    };
    if (found_already == null) {
        const ident_name = try astgen.identifier_token_string(ident_token);
        return astgen.fail_node(ident, "use of undeclared identifier '{s}'", .{ident_name});
    }

    // Decl references happen by name rather than ZIR index so that when unrelated
    // decls are modified, ZIR code containing references to them can be unmodified.

    if (found_namespaces_out > 0 and found_needs_tunnel) {
        switch (ri.rl) {
            .ref, .ref_coerced_ty => return tunnel_through_closure(
                gz,
                ident,
                found_namespaces_out,
                .{ .decl_ref = name_str_index },
                .{ .node = found_already.? },
            ),
            else => {
                const result = try tunnel_through_closure(
                    gz,
                    ident,
                    found_namespaces_out,
                    .{ .decl_val = name_str_index },
                    .{ .node = found_already.? },
                );
                return rvalue_no_coerce_pre_ref(gz, ri, result, ident);
            },
        }
    }

    switch (ri.rl) {
        .ref, .ref_coerced_ty => return gz.add_str_tok(.decl_ref, name_str_index, ident_token),
        else => {
            const result = try gz.add_str_tok(.decl_val, name_str_index, ident_token);
            return rvalue_no_coerce_pre_ref(gz, ri, result, ident);
        },
    }
}

/// Access a ZIR instruction through closure. May tunnel through arbitrarily
/// many namespaces, adding closure captures as required.
/// Returns the index of the `closure_get` instruction added to `gz`.
fn tunnel_through_closure(
    gz: *GenZir,
    /// The node which references the value to be captured.
    inner_ref_node: Ast.Node.Index,
    /// The number of namespaces being tunnelled through. At least 1.
    num_tunnels: u32,
    /// The value being captured.
    value: union(enum) {
        ref: Zir.Inst.Ref,
        ref_load: Zir.Inst.Ref,
        decl_val: Zir.NullTerminatedString,
        decl_ref: Zir.NullTerminatedString,
    },
    /// The location of the value's declaration.
    decl_src: union(enum) {
        token: Ast.TokenIndex,
        node: Ast.Node.Index,
    },
) !Zir.Inst.Ref {
    switch (value) {
        .ref => |v| if (v.to_index() == null) return v, // trivial value; do not need tunnel
        .ref_load => |v| assert(v.to_index() != null), // there are no constant pointer refs
        .decl_val, .decl_ref => {},
    }

    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    // Otherwise we need a tunnel. First, figure out the path of namespaces we
    // are tunneling through. This is usually only going to be one or two, so
    // use an SFBA to optimize for the common case.
    var sfba = std.heap.stack_fallback(@size_of(usize) * 2, astgen.arena);
    var intermediate_tunnels = try sfba.get().alloc(*Scope.Namespace, num_tunnels - 1);

    const root_ns = ns: {
        var i: usize = num_tunnels - 1;
        var scope: *Scope = gz.parent;
        while (i > 0) {
            if (scope.cast(Scope.Namespace)) |mid_ns| {
                i -= 1;
                intermediate_tunnels[i] = mid_ns;
            }
            scope = scope.parent().?;
        }
        while (true) {
            if (scope.cast(Scope.Namespace)) |ns| break :ns ns;
            scope = scope.parent().?;
        }
    };

    // Now that we know the scopes we're tunneling through, begin adding
    // captures as required, starting with the outermost namespace.
    const root_capture = Zir.Inst.Capture.wrap(switch (value) {
        .ref => |v| .{ .instruction = v.to_index().? },
        .ref_load => |v| .{ .instruction_load = v.to_index().? },
        .decl_val => |str| .{ .decl_val = str },
        .decl_ref => |str| .{ .decl_ref = str },
    });
    var cur_capture_index = std.math.cast(
        u16,
        (try root_ns.captures.get_or_put(gpa, root_capture)).index,
    ) orelse return astgen.fail_node_notes(root_ns.node, "this compiler implementation only supports up to 65536 captures per namespace", .{}, &.{
        switch (decl_src) {
            .token => |t| try astgen.err_note_tok(t, "captured value here", .{}),
            .node => |n| try astgen.err_note_node(n, "captured value here", .{}),
        },
        try astgen.err_note_node(inner_ref_node, "value used here", .{}),
    });

    for (intermediate_tunnels) |tunnel_ns| {
        cur_capture_index = std.math.cast(
            u16,
            (try tunnel_ns.captures.get_or_put(gpa, Zir.Inst.Capture.wrap(.{ .nested = cur_capture_index }))).index,
        ) orelse return astgen.fail_node_notes(tunnel_ns.node, "this compiler implementation only supports up to 65536 captures per namespace", .{}, &.{
            switch (decl_src) {
                .token => |t| try astgen.err_note_tok(t, "captured value here", .{}),
                .node => |n| try astgen.err_note_node(n, "captured value here", .{}),
            },
            try astgen.err_note_node(inner_ref_node, "value used here", .{}),
        });
    }

    // Add an instruction to get the value from the closure.
    return gz.add_extended_node_small(.closure_get, inner_ref_node, cur_capture_index);
}

fn string_literal(
    gz: *GenZir,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const str_lit_token = main_tokens[node];
    const str = try astgen.str_lit_as_string(str_lit_token);
    const result = try gz.add(.{
        .tag = .str,
        .data = .{ .str = .{
            .start = str.index,
            .len = str.len,
        } },
    });
    return rvalue(gz, ri, result, node);
}

fn multiline_string_literal(
    gz: *GenZir,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const str = try astgen.str_lit_node_as_string(node);
    const result = try gz.add(.{
        .tag = .str,
        .data = .{ .str = .{
            .start = str.index,
            .len = str.len,
        } },
    });
    return rvalue(gz, ri, result, node);
}

fn char_literal(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const main_token = main_tokens[node];
    const slice = tree.token_slice(main_token);

    switch (std.zig.parse_char_literal(slice)) {
        .success => |codepoint| {
            const result = try gz.add_int(codepoint);
            return rvalue(gz, ri, result, node);
        },
        .failure => |err| return astgen.fail_with_str_lit_error(err, main_token, slice, 0),
    }
}

const Sign = enum { negative, positive };

fn number_literal(gz: *GenZir, ri: ResultInfo, node: Ast.Node.Index, source_node: Ast.Node.Index, sign: Sign) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const num_token = main_tokens[node];
    const bytes = tree.token_slice(num_token);

    const result: Zir.Inst.Ref = switch (std.zig.parse_number_literal(bytes)) {
        .int => |num| switch (num) {
            0 => if (sign == .positive) .zero else return astgen.fail_tok_notes(
                num_token,
                "integer literal '-0' is ambiguous",
                .{},
                &.{
                    try astgen.err_note_tok(num_token, "use '0' for an integer zero", .{}),
                    try astgen.err_note_tok(num_token, "use '-0.0' for a floating-point signed zero", .{}),
                },
            ),
            1 => {
                // Handle the negation here!
                const result: Zir.Inst.Ref = switch (sign) {
                    .positive => .one,
                    .negative => .negative_one,
                };
                return rvalue(gz, ri, result, source_node);
            },
            else => try gz.add_int(num),
        },
        .big_int => |base| big: {
            const gpa = astgen.gpa;
            var big_int = try std.math.big.int.Managed.init(gpa);
            defer big_int.deinit();
            const prefix_offset: usize = if (base == .decimal) 0 else 2;
            big_int.set_string(@int_from_enum(base), bytes[prefix_offset..]) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // caught in `parse_number_literal`
                error.InvalidBase => unreachable, // we only pass 16, 8, 2, see above
                error.OutOfMemory => return error.OutOfMemory,
            };

            const limbs = big_int.limbs[0..big_int.len()];
            assert(big_int.is_positive());
            break :big try gz.add_int_big(limbs);
        },
        .float => {
            const unsigned_float_number = std.fmt.parse_float(f128, bytes) catch |err| switch (err) {
                error.InvalidCharacter => unreachable, // validated by tokenizer
            };
            const float_number = switch (sign) {
                .negative => -unsigned_float_number,
                .positive => unsigned_float_number,
            };
            // If the value fits into a f64 without losing any precision, store it that way.
            @setFloatMode(.strict);
            const smaller_float: f64 = @float_cast(float_number);
            const bigger_again: f128 = smaller_float;
            if (bigger_again == float_number) {
                const result = try gz.add_float(smaller_float);
                return rvalue(gz, ri, result, source_node);
            }
            // We need to use 128 bits. Break the float into 4 u32 values so we can
            // put it into the `extra` array.
            const int_bits: u128 = @bit_cast(float_number);
            const result = try gz.add_pl_node(.float128, node, Zir.Inst.Float128{
                .piece0 = @truncate(int_bits),
                .piece1 = @truncate(int_bits >> 32),
                .piece2 = @truncate(int_bits >> 64),
                .piece3 = @truncate(int_bits >> 96),
            });
            return rvalue(gz, ri, result, source_node);
        },
        .failure => |err| return astgen.fail_with_number_error(err, num_token, bytes),
    };

    if (sign == .positive) {
        return rvalue(gz, ri, result, source_node);
    } else {
        const negated = try gz.add_un_node(.negate, result, source_node);
        return rvalue(gz, ri, negated, source_node);
    }
}

fn fail_with_number_error(astgen: *AstGen, err: std.zig.number_literal.Error, token: Ast.TokenIndex, bytes: []const u8) InnerError {
    const is_float = std.mem.index_of_scalar(u8, bytes, '.') != null;
    switch (err) {
        .leading_zero => if (is_float) {
            return astgen.fail_tok(token, "number '{s}' has leading zero", .{bytes});
        } else {
            return astgen.fail_tok_notes(token, "number '{s}' has leading zero", .{bytes}, &.{
                try astgen.err_note_tok(token, "use '0o' prefix for octal literals", .{}),
            });
        },
        .digit_after_base => return astgen.fail_tok(token, "expected a digit after base prefix", .{}),
        .upper_case_base => |i| return astgen.fail_off(token, @int_cast(i), "base prefix must be lowercase", .{}),
        .invalid_float_base => |i| return astgen.fail_off(token, @int_cast(i), "invalid base for float literal", .{}),
        .repeated_underscore => |i| return astgen.fail_off(token, @int_cast(i), "repeated digit separator", .{}),
        .invalid_underscore_after_special => |i| return astgen.fail_off(token, @int_cast(i), "expected digit before digit separator", .{}),
        .invalid_digit => |info| return astgen.fail_off(token, @int_cast(info.i), "invalid digit '{c}' for {s} base", .{ bytes[info.i], @tag_name(info.base) }),
        .invalid_digit_exponent => |i| return astgen.fail_off(token, @int_cast(i), "invalid digit '{c}' in exponent", .{bytes[i]}),
        .duplicate_exponent => |i| return astgen.fail_off(token, @int_cast(i), "duplicate exponent", .{}),
        .exponent_after_underscore => |i| return astgen.fail_off(token, @int_cast(i), "expected digit before exponent", .{}),
        .special_after_underscore => |i| return astgen.fail_off(token, @int_cast(i), "expected digit before '{c}'", .{bytes[i]}),
        .trailing_special => |i| return astgen.fail_off(token, @int_cast(i), "expected digit after '{c}'", .{bytes[i - 1]}),
        .trailing_underscore => |i| return astgen.fail_off(token, @int_cast(i), "trailing digit separator", .{}),
        .duplicate_period => unreachable, // Validated by tokenizer
        .invalid_character => unreachable, // Validated by tokenizer
        .invalid_exponent_sign => |i| {
            assert(bytes.len >= 2 and bytes[0] == '0' and bytes[1] == 'x'); // Validated by tokenizer
            return astgen.fail_off(token, @int_cast(i), "sign '{c}' cannot follow digit '{c}' in hex base", .{ bytes[i], bytes[i - 1] });
        },
    }
}

fn asm_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    full: Ast.full.Asm,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);
    const token_tags = tree.tokens.items(.tag);

    const TagAndTmpl = struct { tag: Zir.Inst.Extended, tmpl: Zir.NullTerminatedString };
    const tag_and_tmpl: TagAndTmpl = switch (node_tags[full.ast.template]) {
        .string_literal => .{
            .tag = .@"asm",
            .tmpl = (try astgen.str_lit_as_string(main_tokens[full.ast.template])).index,
        },
        .multiline_string_literal => .{
            .tag = .@"asm",
            .tmpl = (try astgen.str_lit_node_as_string(full.ast.template)).index,
        },
        else => .{
            .tag = .asm_expr,
            .tmpl = @enumFromInt(@int_from_enum(try comptime_expr(gz, scope, .{ .rl = .none }, full.ast.template))),
        },
    };

    // See https://github.com/ziglang/zig/issues/215 and related issues discussing
    // possible inline assembly improvements. Until then here is status quo AstGen
    // for assembly syntax. It's used by std lib crypto aesni.zig.
    const is_container_asm = astgen.fn_block == null;
    if (is_container_asm) {
        if (full.volatile_token) |t|
            return astgen.fail_tok(t, "volatile is meaningless on global assembly", .{});
        if (full.outputs.len != 0 or full.inputs.len != 0 or full.first_clobber != null)
            return astgen.fail_node(node, "global assembly cannot have inputs, outputs, or clobbers", .{});
    } else {
        if (full.outputs.len == 0 and full.volatile_token == null) {
            return astgen.fail_node(node, "assembly expression with no output must be marked volatile", .{});
        }
    }
    if (full.outputs.len > 32) {
        return astgen.fail_node(full.outputs[32], "too many asm outputs", .{});
    }
    var outputs_buffer: [32]Zir.Inst.Asm.Output = undefined;
    const outputs = outputs_buffer[0..full.outputs.len];

    var output_type_bits: u32 = 0;

    for (full.outputs, 0..) |output_node, i| {
        const symbolic_name = main_tokens[output_node];
        const name = try astgen.ident_as_string(symbolic_name);
        const constraint_token = symbolic_name + 2;
        const constraint = (try astgen.str_lit_as_string(constraint_token)).index;
        const has_arrow = token_tags[symbolic_name + 4] == .arrow;
        if (has_arrow) {
            if (output_type_bits != 0) {
                return astgen.fail_node(output_node, "inline assembly allows up to one output value", .{});
            }
            output_type_bits |= @as(u32, 1) << @int_cast(i);
            const out_type_node = node_datas[output_node].lhs;
            const out_type_inst = try type_expr(gz, scope, out_type_node);
            outputs[i] = .{
                .name = name,
                .constraint = constraint,
                .operand = out_type_inst,
            };
        } else {
            const ident_token = symbolic_name + 4;
            // TODO have a look at #215 and related issues and decide how to
            // handle outputs. Do we want this to be identifiers?
            // Or maybe we want to force this to be expressions with a pointer type.
            outputs[i] = .{
                .name = name,
                .constraint = constraint,
                .operand = try local_var_ref(gz, scope, .{ .rl = .ref }, node, ident_token),
            };
        }
    }

    if (full.inputs.len > 32) {
        return astgen.fail_node(full.inputs[32], "too many asm inputs", .{});
    }
    var inputs_buffer: [32]Zir.Inst.Asm.Input = undefined;
    const inputs = inputs_buffer[0..full.inputs.len];

    for (full.inputs, 0..) |input_node, i| {
        const symbolic_name = main_tokens[input_node];
        const name = try astgen.ident_as_string(symbolic_name);
        const constraint_token = symbolic_name + 2;
        const constraint = (try astgen.str_lit_as_string(constraint_token)).index;
        const operand = try expr(gz, scope, .{ .rl = .none }, node_datas[input_node].lhs);
        inputs[i] = .{
            .name = name,
            .constraint = constraint,
            .operand = operand,
        };
    }

    var clobbers_buffer: [32]u32 = undefined;
    var clobber_i: usize = 0;
    if (full.first_clobber) |first_clobber| clobbers: {
        // asm ("foo" ::: "a", "b")
        // asm ("foo" ::: "a", "b",)
        var tok_i = first_clobber;
        while (true) : (tok_i += 1) {
            if (clobber_i >= clobbers_buffer.len) {
                return astgen.fail_tok(tok_i, "too many asm clobbers", .{});
            }
            clobbers_buffer[clobber_i] = @int_from_enum((try astgen.str_lit_as_string(tok_i)).index);
            clobber_i += 1;
            tok_i += 1;
            switch (token_tags[tok_i]) {
                .r_paren => break :clobbers,
                .comma => {
                    if (token_tags[tok_i + 1] == .r_paren) {
                        break :clobbers;
                    } else {
                        continue;
                    }
                },
                else => unreachable,
            }
        }
    }

    const result = try gz.add_asm(.{
        .tag = tag_and_tmpl.tag,
        .node = node,
        .asm_source = tag_and_tmpl.tmpl,
        .is_volatile = full.volatile_token != null,
        .output_type_bits = output_type_bits,
        .outputs = outputs,
        .inputs = inputs,
        .clobbers = clobbers_buffer[0..clobber_i],
    });
    return rvalue(gz, ri, result, node);
}

fn as(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs: Ast.Node.Index,
    rhs: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const dest_type = try type_expr(gz, scope, lhs);
    const result = try reachable_expr(gz, scope, .{ .rl = .{ .ty = dest_type } }, rhs, node);
    return rvalue(gz, ri, result, node);
}

fn union_init(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const union_type = try type_expr(gz, scope, params[0]);
    const field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1]);
    const field_type = try gz.add_pl_node(.field_type_ref, node, Zir.Inst.FieldTypeRef{
        .container_type = union_type,
        .field_name = field_name,
    });
    const init = try reachable_expr(gz, scope, .{ .rl = .{ .ty = field_type } }, params[2], node);
    const result = try gz.add_pl_node(.union_init, node, Zir.Inst.UnionInit{
        .union_type = union_type,
        .init = init,
        .field_name = field_name,
    });
    return rvalue(gz, ri, result, node);
}

fn bit_cast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const dest_type = try ri.rl.result_type_for_cast(gz, node, "@bit_cast");
    const operand = try reachable_expr(gz, scope, .{ .rl = .none }, operand_node, node);
    const result = try gz.add_pl_node(.bitcast, node, Zir.Inst.Bin{
        .lhs = dest_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, node);
}

/// Handle one or more nested pointer cast builtins:
/// * @ptr_cast
/// * @align_cast
/// * @addrSpaceCast
/// * @constCast
/// * @volatileCast
/// Any sequence of such builtins is treated as a single operation. This allowed
/// for sequences like `@ptr_cast(@align_cast(ptr))` to work correctly despite the
/// intermediate result type being unknown.
fn ptr_cast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    root_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);
    const node_datas = tree.nodes.items(.data);
    const node_tags = tree.nodes.items(.tag);

    const FlagsInt = @typeInfo(Zir.Inst.FullPtrCastFlags).Struct.backing_integer.?;
    var flags: Zir.Inst.FullPtrCastFlags = .{};

    // Note that all pointer cast builtins have one parameter, so we only need
    // to handle `builtin_call_two`.
    var node = root_node;
    while (true) {
        switch (node_tags[node]) {
            .builtin_call_two, .builtin_call_two_comma => {},
            .grouped_expression => {
                // Handle the chaining even with redundant parentheses
                node = node_datas[node].lhs;
                continue;
            },
            else => break,
        }

        if (node_datas[node].lhs == 0) break; // 0 args

        const builtin_token = main_tokens[node];
        const builtin_name = tree.token_slice(builtin_token);
        const info = BuiltinFn.list.get(builtin_name) orelse break;
        if (node_datas[node].rhs == 0) {
            // 1 arg
            if (info.param_count != 1) break;

            switch (info.tag) {
                else => break,
                inline .ptr_cast,
                .align_cast,
                .addrspace_cast,
                .const_cast,
                .volatile_cast,
                => |tag| {
                    if (@field(flags, @tag_name(tag))) {
                        return astgen.fail_node(node, "redundant {s}", .{builtin_name});
                    }
                    @field(flags, @tag_name(tag)) = true;
                },
            }

            node = node_datas[node].lhs;
        } else {
            // 2 args
            if (info.param_count != 2) break;

            switch (info.tag) {
                else => break,
                .field_parent_ptr => {
                    if (flags.ptr_cast) break;

                    const flags_int: FlagsInt = @bit_cast(flags);
                    const cursor = maybe_advance_source_cursor_to_main_token(gz, root_node);
                    const parent_ptr_type = try ri.rl.result_type_for_cast(gz, root_node, "@align_cast");
                    const field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, node_datas[node].lhs);
                    const field_ptr = try expr(gz, scope, .{ .rl = .none }, node_datas[node].rhs);
                    try emit_dbg_stmt(gz, cursor);
                    const result = try gz.add_extended_payload_small(.field_parent_ptr, flags_int, Zir.Inst.FieldParentPtr{
                        .src_node = gz.node_index_to_relative(node),
                        .parent_ptr_type = parent_ptr_type,
                        .field_name = field_name,
                        .field_ptr = field_ptr,
                    });
                    return rvalue(gz, ri, result, root_node);
                },
            }
        }
    }

    const flags_int: FlagsInt = @bit_cast(flags);
    assert(flags_int != 0);

    const ptr_only: Zir.Inst.FullPtrCastFlags = .{ .ptr_cast = true };
    if (flags_int == @as(FlagsInt, @bit_cast(ptr_only))) {
        // Special case: simpler representation
        return type_cast(gz, scope, ri, root_node, node, .ptr_cast, "@ptr_cast");
    }

    const no_result_ty_flags: Zir.Inst.FullPtrCastFlags = .{
        .const_cast = true,
        .volatile_cast = true,
    };
    if ((flags_int & ~@as(FlagsInt, @bit_cast(no_result_ty_flags))) == 0) {
        // Result type not needed
        const cursor = maybe_advance_source_cursor_to_main_token(gz, root_node);
        const operand = try expr(gz, scope, .{ .rl = .none }, node);
        try emit_dbg_stmt(gz, cursor);
        const result = try gz.add_extended_payload_small(.ptr_cast_no_dest, flags_int, Zir.Inst.UnNode{
            .node = gz.node_index_to_relative(root_node),
            .operand = operand,
        });
        return rvalue(gz, ri, result, root_node);
    }

    // Full cast including result type

    const cursor = maybe_advance_source_cursor_to_main_token(gz, root_node);
    const result_type = try ri.rl.result_type_for_cast(gz, root_node, flags.need_result_type_builtin_name());
    const operand = try expr(gz, scope, .{ .rl = .none }, node);
    try emit_dbg_stmt(gz, cursor);
    const result = try gz.add_extended_payload_small(.ptr_cast_full, flags_int, Zir.Inst.BinNode{
        .node = gz.node_index_to_relative(root_node),
        .lhs = result_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, root_node);
}

fn type_of(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    args: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (args.len < 1) {
        return astgen.fail_node(node, "expected at least 1 argument, found 0", .{});
    }
    const gpa = astgen.gpa;
    if (args.len == 1) {
        const typeof_inst = try gz.make_block_inst(.typeof_builtin, node);

        var typeof_scope = gz.make_sub_block(scope);
        typeof_scope.is_comptime = false;
        typeof_scope.is_typeof = true;
        typeof_scope.c_import = false;
        defer typeof_scope.unstack();

        const ty_expr = try reachable_expr(&typeof_scope, &typeof_scope.base, .{ .rl = .none }, args[0], node);
        if (!gz.ref_is_no_return(ty_expr)) {
            _ = try typeof_scope.add_break(.break_inline, typeof_inst, ty_expr);
        }
        try typeof_scope.set_block_body(typeof_inst);

        // typeof_scope unstacked now, can add new instructions to gz
        try gz.instructions.append(gpa, typeof_inst);
        return rvalue(gz, ri, typeof_inst.to_ref(), node);
    }
    const payload_size: u32 = std.meta.fields(Zir.Inst.TypeOfPeer).len;
    const payload_index = try reserve_extra(astgen, payload_size + args.len);
    const args_index = payload_index + payload_size;

    const typeof_inst = try gz.add_extended_multi_op_payload_index(.typeof_peer, payload_index, args.len);

    var typeof_scope = gz.make_sub_block(scope);
    typeof_scope.is_comptime = false;

    for (args, 0..) |arg, i| {
        const param_ref = try reachable_expr(&typeof_scope, &typeof_scope.base, .{ .rl = .none }, arg, node);
        astgen.extra.items[args_index + i] = @int_from_enum(param_ref);
    }
    _ = try typeof_scope.add_break(.break_inline, typeof_inst.to_index().?, .void_value);

    const body = typeof_scope.instructions_slice();
    const body_len = astgen.count_body_len_after_fixups(body);
    astgen.set_extra(payload_index, Zir.Inst.TypeOfPeer{
        .body_len = @int_cast(body_len),
        .body_index = @int_cast(astgen.extra.items.len),
        .src_node = gz.node_index_to_relative(node),
    });
    try astgen.extra.ensure_unused_capacity(gpa, body_len);
    astgen.append_body_with_fixups(body);
    typeof_scope.unstack();

    return rvalue(gz, ri, typeof_inst, node);
}

fn min_max(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    args: []const Ast.Node.Index,
    comptime op: enum { min, max },
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    if (args.len < 2) {
        return astgen.fail_node(node, "expected at least 2 arguments, found 0", .{});
    }
    if (args.len == 2) {
        const tag: Zir.Inst.Tag = switch (op) {
            .min => .min,
            .max => .max,
        };
        const a = try expr(gz, scope, .{ .rl = .none }, args[0]);
        const b = try expr(gz, scope, .{ .rl = .none }, args[1]);
        const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{
            .lhs = a,
            .rhs = b,
        });
        return rvalue(gz, ri, result, node);
    }
    const payload_index = try add_extra(astgen, Zir.Inst.NodeMultiOp{
        .src_node = gz.node_index_to_relative(node),
    });
    var extra_index = try reserve_extra(gz.astgen, args.len);
    for (args) |arg| {
        const arg_ref = try expr(gz, scope, .{ .rl = .none }, arg);
        astgen.extra.items[extra_index] = @int_from_enum(arg_ref);
        extra_index += 1;
    }
    const tag: Zir.Inst.Extended = switch (op) {
        .min => .min_multi,
        .max => .max_multi,
    };
    const result = try gz.add_extended_multi_op_payload_index(tag, payload_index, args.len);
    return rvalue(gz, ri, result, node);
}

fn builtin_call(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const main_tokens = tree.nodes.items(.main_token);

    const builtin_token = main_tokens[node];
    const builtin_name = tree.token_slice(builtin_token);

    // We handle the different builtins manually because they have different semantics depending
    // on the function. For example, `@as` and others participate in result location semantics,
    // and `@c_import` creates a special scope that collects a .c source code text buffer.
    // Also, some builtins have a variable number of parameters.

    const info = BuiltinFn.list.get(builtin_name) orelse {
        return astgen.fail_node(node, "invalid builtin function: '{s}'", .{
            builtin_name,
        });
    };
    if (info.param_count) |expected| {
        if (expected != params.len) {
            const s = if (expected == 1) "" else "s";
            return astgen.fail_node(node, "expected {d} argument{s}, found {d}", .{
                expected, s, params.len,
            });
        }
    }

    // Check function scope-only builtins

    if (astgen.fn_block == null and info.illegal_outside_function)
        return astgen.fail_node(node, "'{s}' outside function scope", .{builtin_name});

    switch (info.tag) {
        .import => {
            const node_tags = tree.nodes.items(.tag);
            const operand_node = params[0];

            if (node_tags[operand_node] != .string_literal) {
                // Spec reference: https://github.com/ziglang/zig/issues/2206
                return astgen.fail_node(operand_node, "@import operand must be a string literal", .{});
            }
            const str_lit_token = main_tokens[operand_node];
            const str = try astgen.str_lit_as_string(str_lit_token);
            const str_slice = astgen.string_bytes.items[@int_from_enum(str.index)..][0..str.len];
            if (mem.index_of_scalar(u8, str_slice, 0) != null) {
                return astgen.fail_tok(str_lit_token, "import path cannot contain null bytes", .{});
            } else if (str.len == 0) {
                return astgen.fail_tok(str_lit_token, "import path cannot be empty", .{});
            }
            const result = try gz.add_str_tok(.import, str.index, str_lit_token);
            const gop = try astgen.imports.get_or_put(astgen.gpa, str.index);
            if (!gop.found_existing) {
                gop.value_ptr.* = str_lit_token;
            }
            return rvalue(gz, ri, result, node);
        },
        .compile_log => {
            const payload_index = try add_extra(gz.astgen, Zir.Inst.NodeMultiOp{
                .src_node = gz.node_index_to_relative(node),
            });
            var extra_index = try reserve_extra(gz.astgen, params.len);
            for (params) |param| {
                const param_ref = try expr(gz, scope, .{ .rl = .none }, param);
                astgen.extra.items[extra_index] = @int_from_enum(param_ref);
                extra_index += 1;
            }
            const result = try gz.add_extended_multi_op_payload_index(.compile_log, payload_index, params.len);
            return rvalue(gz, ri, result, node);
        },
        .field => {
            if (ri.rl == .ref or ri.rl == .ref_coerced_ty) {
                return gz.add_pl_node(.field_ptr_named, node, Zir.Inst.FieldNamed{
                    .lhs = try expr(gz, scope, .{ .rl = .ref }, params[0]),
                    .field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1]),
                });
            }
            const result = try gz.add_pl_node(.field_val_named, node, Zir.Inst.FieldNamed{
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },

        // zig fmt: off
        .as         => return as(       gz, scope, ri, node, params[0], params[1]),
        .bit_cast   => return bit_cast(  gz, scope, ri, node, params[0]),
        .TypeOf     => return type_of(   gz, scope, ri, node, params),
        .union_init => return union_init(gz, scope, ri, node, params),
        .c_import   => return c_import(  gz, scope,     node, params[0]),
        .min        => return min_max(   gz, scope, ri, node, params, .min),
        .max        => return min_max(   gz, scope, ri, node, params, .max),
        // zig fmt: on

        .@"export" => {
            const node_tags = tree.nodes.items(.tag);
            const node_datas = tree.nodes.items(.data);
            // This function causes a Decl to be exported. The first parameter is not an expression,
            // but an identifier of the Decl to be exported.
            var namespace: Zir.Inst.Ref = .none;
            var decl_name: Zir.NullTerminatedString = .empty;
            switch (node_tags[params[0]]) {
                .identifier => {
                    const ident_token = main_tokens[params[0]];
                    if (is_primitive(tree.token_slice(ident_token))) {
                        return astgen.fail_tok(ident_token, "unable to export primitive value", .{});
                    }
                    decl_name = try astgen.ident_as_string(ident_token);

                    var s = scope;
                    var found_already: ?Ast.Node.Index = null; // we have found a decl with the same name already
                    while (true) switch (s.tag) {
                        .local_val => {
                            const local_val = s.cast(Scope.LocalVal).?;
                            if (local_val.name == decl_name) {
                                local_val.used = ident_token;
                                _ = try gz.add_pl_node(.export_value, node, Zir.Inst.ExportValue{
                                    .operand = local_val.inst,
                                    .options = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .export_options_type } }, params[1]),
                                });
                                return rvalue(gz, ri, .void_value, node);
                            }
                            s = local_val.parent;
                        },
                        .local_ptr => {
                            const local_ptr = s.cast(Scope.LocalPtr).?;
                            if (local_ptr.name == decl_name) {
                                if (!local_ptr.maybe_comptime)
                                    return astgen.fail_node(params[0], "unable to export runtime-known value", .{});
                                local_ptr.used = ident_token;
                                const loaded = try gz.add_un_node(.load, local_ptr.ptr, node);
                                _ = try gz.add_pl_node(.export_value, node, Zir.Inst.ExportValue{
                                    .operand = loaded,
                                    .options = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .export_options_type } }, params[1]),
                                });
                                return rvalue(gz, ri, .void_value, node);
                            }
                            s = local_ptr.parent;
                        },
                        .gen_zir => s = s.cast(GenZir).?.parent,
                        .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
                        .namespace => {
                            const ns = s.cast(Scope.Namespace).?;
                            if (ns.decls.get(decl_name)) |i| {
                                if (found_already) |f| {
                                    return astgen.fail_node_notes(node, "ambiguous reference", .{}, &.{
                                        try astgen.err_note_node(f, "declared here", .{}),
                                        try astgen.err_note_node(i, "also declared here", .{}),
                                    });
                                }
                                // We found a match but must continue looking for ambiguous references to decls.
                                found_already = i;
                            }
                            s = ns.parent;
                        },
                        .top => break,
                    };
                    if (found_already == null) {
                        const ident_name = try astgen.identifier_token_string(ident_token);
                        return astgen.fail_node(params[0], "use of undeclared identifier '{s}'", .{ident_name});
                    }
                },
                .field_access => {
                    const namespace_node = node_datas[params[0]].lhs;
                    namespace = try type_expr(gz, scope, namespace_node);
                    const dot_token = main_tokens[params[0]];
                    const field_ident = dot_token + 1;
                    decl_name = try astgen.ident_as_string(field_ident);
                },
                else => return astgen.fail_node(params[0], "symbol to export must identify a declaration", .{}),
            }
            const options = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .export_options_type } }, params[1]);
            _ = try gz.add_pl_node(.@"export", node, Zir.Inst.Export{
                .namespace = namespace,
                .decl_name = decl_name,
                .options = options,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .@"extern" => {
            const type_inst = try type_expr(gz, scope, params[0]);
            const options = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .extern_options_type } }, params[1]);
            const result = try gz.add_extended_payload(.builtin_extern, Zir.Inst.BinNode{
                .node = gz.node_index_to_relative(node),
                .lhs = type_inst,
                .rhs = options,
            });
            return rvalue(gz, ri, result, node);
        },
        .fence => {
            const order = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } }, params[0]);
            _ = try gz.add_extended_payload(.fence, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = order,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .set_float_mode => {
            const order = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .float_mode_type } }, params[0]);
            _ = try gz.add_extended_payload(.set_float_mode, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = order,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .set_align_stack => {
            const order = try expr(gz, scope, coerced_align_ri, params[0]);
            _ = try gz.add_extended_payload(.set_align_stack, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = order,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .set_cold => {
            const order = try expr(gz, scope, ri, params[0]);
            _ = try gz.add_extended_payload(.set_cold, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = order,
            });
            return rvalue(gz, ri, .void_value, node);
        },

        .src => {
            const token_starts = tree.tokens.items(.start);
            const node_start = token_starts[tree.first_token(node)];
            astgen.advance_source_cursor(node_start);
            const result = try gz.add_extended_payload(.builtin_src, Zir.Inst.Src{
                .node = gz.node_index_to_relative(node),
                .line = astgen.source_line,
                .column = astgen.source_column,
            });
            return rvalue(gz, ri, result, node);
        },

        // zig fmt: off
        .This               => return rvalue(gz, ri, try gz.add_node_extended(.this,               node), node),
        .return_address     => return rvalue(gz, ri, try gz.add_node_extended(.ret_addr,           node), node),
        .error_return_trace => return rvalue(gz, ri, try gz.add_node_extended(.error_return_trace, node), node),
        .frame              => return rvalue(gz, ri, try gz.add_node_extended(.frame,              node), node),
        .frame_address      => return rvalue(gz, ri, try gz.add_node_extended(.frame_address,      node), node),
        .breakpoint         => return rvalue(gz, ri, try gz.add_node_extended(.breakpoint,         node), node),
        .in_comptime        => return rvalue(gz, ri, try gz.add_node_extended(.in_comptime,        node), node),

        .type_info   => return simple_un_op_type(gz, scope, ri, node, params[0], .type_info),
        .size_of     => return simple_un_op_type(gz, scope, ri, node, params[0], .size_of),
        .bit_size_of => return simple_un_op_type(gz, scope, ri, node, params[0], .bit_size_of),
        .align_of    => return simple_un_op_type(gz, scope, ri, node, params[0], .align_of),

        .int_from_ptr          => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_ptr),
        .compile_error         => return simple_un_op(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },   params[0], .compile_error),
        .set_eval_branch_quota => return simple_un_op(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .u32_type } },              params[0], .set_eval_branch_quota),
        .int_from_enum         => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_enum),
        .int_from_bool         => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .int_from_bool),
        .embed_file            => return simple_un_op(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } },   params[0], .embed_file),
        .error_name            => return simple_un_op(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .anyerror_type } },         params[0], .error_name),
        .set_runtime_safety    => return simple_un_op(gz, scope, ri, node, coerced_bool_ri,                                      params[0], .set_runtime_safety),
        .sqrt                  => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .sqrt),
        .sin                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .sin),
        .cos                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .cos),
        .tan                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .tan),
        .exp                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .exp),
        .exp2                  => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .exp2),
        .log                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log),
        .log2                  => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log2),
        .log10                 => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .log10),
        .abs                   => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .abs),
        .floor                 => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .floor),
        .ceil                  => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .ceil),
        .trunc                 => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .trunc),
        .round                 => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .round),
        .tag_name              => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .tag_name),
        .type_name             => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .type_name),
        .Frame                 => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .frame_type),
        .frame_size            => return simple_un_op(gz, scope, ri, node, .{ .rl = .none },                                     params[0], .frame_size),

        .int_from_float => return type_cast(gz, scope, ri, node, params[0], .int_from_float, builtin_name),
        .float_from_int => return type_cast(gz, scope, ri, node, params[0], .float_from_int, builtin_name),
        .ptr_from_int   => return type_cast(gz, scope, ri, node, params[0], .ptr_from_int, builtin_name),
        .enum_from_int  => return type_cast(gz, scope, ri, node, params[0], .enum_from_int, builtin_name),
        .float_cast     => return type_cast(gz, scope, ri, node, params[0], .float_cast, builtin_name),
        .int_cast       => return type_cast(gz, scope, ri, node, params[0], .int_cast, builtin_name),
        .truncate       => return type_cast(gz, scope, ri, node, params[0], .truncate, builtin_name),
        // zig fmt: on

        .Type => {
            const operand = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .type_info_type } }, params[0]);

            const gpa = gz.astgen.gpa;

            try gz.instructions.ensure_unused_capacity(gpa, 1);
            try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

            const payload_index = try gz.astgen.add_extra(Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
            gz.astgen.instructions.append_assume_capacity(.{
                .tag = .extended,
                .data = .{ .extended = .{
                    .opcode = .reify,
                    .small = @int_from_enum(gz.anon_name_strategy),
                    .operand = payload_index,
                } },
            });
            gz.instructions.append_assume_capacity(new_index);
            const result = new_index.to_ref();
            return rvalue(gz, ri, result, node);
        },
        .panic => {
            try emit_dbg_node(gz, node);
            return simple_un_op(gz, scope, ri, node, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0], .panic);
        },
        .trap => {
            try emit_dbg_node(gz, node);
            _ = try gz.add_node(.trap, node);
            return rvalue(gz, ri, .unreachable_value, node);
        },
        .int_from_error => {
            const operand = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const result = try gz.add_extended_payload(.int_from_error, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .error_from_int => {
            const operand = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const result = try gz.add_extended_payload(.error_from_int, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .error_cast => {
            try emit_dbg_node(gz, node);

            const result = try gz.add_extended_payload(.error_cast, Zir.Inst.BinNode{
                .lhs = try ri.rl.result_type_for_cast(gz, node, builtin_name),
                .rhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .node = gz.node_index_to_relative(node),
            });
            return rvalue(gz, ri, result, node);
        },
        .ptr_cast,
        .align_cast,
        .addrspace_cast,
        .const_cast,
        .volatile_cast,
        => return ptr_cast(gz, scope, ri, node),

        // zig fmt: off
        .has_decl  => return has_decl_or_field(gz, scope, ri, node, params[0], params[1], .has_decl),
        .has_field => return has_decl_or_field(gz, scope, ri, node, params[0], params[1], .has_field),

        .clz         => return bit_builtin(gz, scope, ri, node, params[0], .clz),
        .ctz         => return bit_builtin(gz, scope, ri, node, params[0], .ctz),
        .pop_count   => return bit_builtin(gz, scope, ri, node, params[0], .pop_count),
        .byte_swap   => return bit_builtin(gz, scope, ri, node, params[0], .byte_swap),
        .bit_reverse => return bit_builtin(gz, scope, ri, node, params[0], .bit_reverse),

        .div_exact => return div_builtin(gz, scope, ri, node, params[0], params[1], .div_exact),
        .div_floor => return div_builtin(gz, scope, ri, node, params[0], params[1], .div_floor),
        .div_trunc => return div_builtin(gz, scope, ri, node, params[0], params[1], .div_trunc),
        .mod       => return div_builtin(gz, scope, ri, node, params[0], params[1], .mod),
        .rem       => return div_builtin(gz, scope, ri, node, params[0], params[1], .rem),

        .shl_exact => return shift_op(gz, scope, ri, node, params[0], params[1], .shl_exact),
        .shr_exact => return shift_op(gz, scope, ri, node, params[0], params[1], .shr_exact),

        .bit_offset_of => return offset_of(gz, scope, ri, node, params[0], params[1], .bit_offset_of),
        .offset_of     => return offset_of(gz, scope, ri, node, params[0], params[1], .offset_of),

        .c_undef   => return simple_cbuiltin(gz, scope, ri, node, params[0], .c_undef),
        .c_include => return simple_cbuiltin(gz, scope, ri, node, params[0], .c_include),

        .cmpxchg_strong => return cmpxchg(gz, scope, ri, node, params, 1),
        .cmpxchg_weak   => return cmpxchg(gz, scope, ri, node, params, 0),
        // zig fmt: on

        .wasm_memory_size => {
            const operand = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]);
            const result = try gz.add_extended_payload(.wasm_memory_size, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .wasm_memory_grow => {
            const index_arg = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]);
            const delta_arg = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .usize_type } }, params[1]);
            const result = try gz.add_extended_payload(.wasm_memory_grow, Zir.Inst.BinNode{
                .node = gz.node_index_to_relative(node),
                .lhs = index_arg,
                .rhs = delta_arg,
            });
            return rvalue(gz, ri, result, node);
        },
        .c_define => {
            if (!gz.c_import) return gz.astgen.fail_node(node, "C define valid only inside C import block", .{});
            const name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0]);
            const value = try comptime_expr(gz, scope, .{ .rl = .none }, params[1]);
            const result = try gz.add_extended_payload(.c_define, Zir.Inst.BinNode{
                .node = gz.node_index_to_relative(node),
                .lhs = name,
                .rhs = value,
            });
            return rvalue(gz, ri, result, node);
        },

        .splat => {
            const result_type = try ri.rl.result_type_for_cast(gz, node, builtin_name);
            const elem_type = try gz.add_un_node(.vector_elem_type, result_type, node);
            const scalar = try expr(gz, scope, .{ .rl = .{ .ty = elem_type } }, params[0]);
            const result = try gz.add_pl_node(.splat, node, Zir.Inst.Bin{
                .lhs = result_type,
                .rhs = scalar,
            });
            return rvalue(gz, ri, result, node);
        },
        .reduce => {
            const op = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .reduce_op_type } }, params[0]);
            const scalar = try expr(gz, scope, .{ .rl = .none }, params[1]);
            const result = try gz.add_pl_node(.reduce, node, Zir.Inst.Bin{
                .lhs = op,
                .rhs = scalar,
            });
            return rvalue(gz, ri, result, node);
        },

        .add_with_overflow => return overflow_arithmetic(gz, scope, ri, node, params, .add_with_overflow),
        .sub_with_overflow => return overflow_arithmetic(gz, scope, ri, node, params, .sub_with_overflow),
        .mul_with_overflow => return overflow_arithmetic(gz, scope, ri, node, params, .mul_with_overflow),
        .shl_with_overflow => return overflow_arithmetic(gz, scope, ri, node, params, .shl_with_overflow),

        .atomic_load => {
            const result = try gz.add_pl_node(.atomic_load, node, Zir.Inst.AtomicLoad{
                // zig fmt: off
                .elem_type = try type_expr(gz, scope,                                                   params[0]),
                .ptr       = try expr    (gz, scope, .{ .rl = .none },                                 params[1]),
                .ordering  = try expr    (gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } }, params[2]),
                // zig fmt: on
            });
            return rvalue(gz, ri, result, node);
        },
        .atomic_rmw => {
            const int_type = try type_expr(gz, scope, params[0]);
            const result = try gz.add_pl_node(.atomic_rmw, node, Zir.Inst.AtomicRmw{
                // zig fmt: off
                .ptr       = try expr(gz, scope, .{ .rl = .none },                                  params[1]),
                .operation = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_rmw_op_type } }, params[2]),
                .operand   = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                    params[3]),
                .ordering  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } },  params[4]),
                // zig fmt: on
            });
            return rvalue(gz, ri, result, node);
        },
        .atomic_store => {
            const int_type = try type_expr(gz, scope, params[0]);
            _ = try gz.add_pl_node(.atomic_store, node, Zir.Inst.AtomicStore{
                // zig fmt: off
                .ptr      = try expr(gz, scope, .{ .rl = .none },                                 params[1]),
                .operand  = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                   params[2]),
                .ordering = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } }, params[3]),
                // zig fmt: on
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .mul_add => {
            const float_type = try type_expr(gz, scope, params[0]);
            const mulend1 = try expr(gz, scope, .{ .rl = .{ .coerced_ty = float_type } }, params[1]);
            const mulend2 = try expr(gz, scope, .{ .rl = .{ .coerced_ty = float_type } }, params[2]);
            const addend = try expr(gz, scope, .{ .rl = .{ .ty = float_type } }, params[3]);
            const result = try gz.add_pl_node(.mul_add, node, Zir.Inst.MulAdd{
                .mulend1 = mulend1,
                .mulend2 = mulend2,
                .addend = addend,
            });
            return rvalue(gz, ri, result, node);
        },
        .call => {
            const modifier = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .call_modifier_type } }, params[0]);
            const callee = try expr(gz, scope, .{ .rl = .none }, params[1]);
            const args = try expr(gz, scope, .{ .rl = .none }, params[2]);
            const result = try gz.add_pl_node(.builtin_call, node, Zir.Inst.BuiltinCall{
                .modifier = modifier,
                .callee = callee,
                .args = args,
                .flags = .{
                    .is_nosuspend = gz.nosuspend_node != 0,
                    .ensure_result_used = false,
                },
            });
            return rvalue(gz, ri, result, node);
        },
        .field_parent_ptr => {
            const parent_ptr_type = try ri.rl.result_type_for_cast(gz, node, builtin_name);
            const field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, params[0]);
            const result = try gz.add_extended_payload_small(.field_parent_ptr, 0, Zir.Inst.FieldParentPtr{
                .src_node = gz.node_index_to_relative(node),
                .parent_ptr_type = parent_ptr_type,
                .field_name = field_name,
                .field_ptr = try expr(gz, scope, .{ .rl = .none }, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .memcpy => {
            _ = try gz.add_pl_node(.memcpy, node, Zir.Inst.Bin{
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .rhs = try expr(gz, scope, .{ .rl = .none }, params[1]),
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .memset => {
            const lhs = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const lhs_ty = try gz.add_un_node(.typeof, lhs, params[0]);
            const elem_ty = try gz.add_un_node(.indexable_ptr_elem_type, lhs_ty, params[0]);
            _ = try gz.add_pl_node(.memset, node, Zir.Inst.Bin{
                .lhs = lhs,
                .rhs = try expr(gz, scope, .{ .rl = .{ .coerced_ty = elem_ty } }, params[1]),
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .shuffle => {
            const result = try gz.add_pl_node(.shuffle, node, Zir.Inst.Shuffle{
                .elem_type = try type_expr(gz, scope, params[0]),
                .a = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .b = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .mask = try comptime_expr(gz, scope, .{ .rl = .none }, params[3]),
            });
            return rvalue(gz, ri, result, node);
        },
        .select => {
            const result = try gz.add_extended_payload(.select, Zir.Inst.Select{
                .node = gz.node_index_to_relative(node),
                .elem_type = try type_expr(gz, scope, params[0]),
                .pred = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .a = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .b = try expr(gz, scope, .{ .rl = .none }, params[3]),
            });
            return rvalue(gz, ri, result, node);
        },
        .async_call => {
            const result = try gz.add_extended_payload(.builtin_async_call, Zir.Inst.AsyncCall{
                .node = gz.node_index_to_relative(node),
                .frame_buffer = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .result_ptr = try expr(gz, scope, .{ .rl = .none }, params[1]),
                .fn_ptr = try expr(gz, scope, .{ .rl = .none }, params[2]),
                .args = try expr(gz, scope, .{ .rl = .none }, params[3]),
            });
            return rvalue(gz, ri, result, node);
        },
        .Vector => {
            const result = try gz.add_pl_node(.vector_type, node, Zir.Inst.Bin{
                .lhs = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]),
                .rhs = try type_expr(gz, scope, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .prefetch => {
            const ptr = try expr(gz, scope, .{ .rl = .none }, params[0]);
            const options = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .prefetch_options_type } }, params[1]);
            _ = try gz.add_extended_payload(.prefetch, Zir.Inst.BinNode{
                .node = gz.node_index_to_relative(node),
                .lhs = ptr,
                .rhs = options,
            });
            return rvalue(gz, ri, .void_value, node);
        },
        .c_va_arg => {
            const result = try gz.add_extended_payload(.c_va_arg, Zir.Inst.BinNode{
                .node = gz.node_index_to_relative(node),
                .lhs = try expr(gz, scope, .{ .rl = .none }, params[0]),
                .rhs = try type_expr(gz, scope, params[1]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_copy => {
            const result = try gz.add_extended_payload(.c_va_copy, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = try expr(gz, scope, .{ .rl = .none }, params[0]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_end => {
            const result = try gz.add_extended_payload(.c_va_end, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = try expr(gz, scope, .{ .rl = .none }, params[0]),
            });
            return rvalue(gz, ri, result, node);
        },
        .c_va_start => {
            if (!astgen.fn_var_args) {
                return astgen.fail_node(node, "'@cVaStart' in a non-variadic function", .{});
            }
            return rvalue(gz, ri, try gz.add_node_extended(.c_va_start, node), node);
        },

        .work_item_id => {
            const operand = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]);
            const result = try gz.add_extended_payload(.work_item_id, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .work_group_size => {
            const operand = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]);
            const result = try gz.add_extended_payload(.work_group_size, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
        .work_group_id => {
            const operand = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .u32_type } }, params[0]);
            const result = try gz.add_extended_payload(.work_group_id, Zir.Inst.UnNode{
                .node = gz.node_index_to_relative(node),
                .operand = operand,
            });
            return rvalue(gz, ri, result, node);
        },
    }
}

fn has_decl_or_field(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const container_type = try type_expr(gz, scope, lhs_node);
    const name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, rhs_node);
    const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{
        .lhs = container_type,
        .rhs = name,
    });
    return rvalue(gz, ri, result, node);
}

fn type_cast(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
    builtin_name: []const u8,
) InnerError!Zir.Inst.Ref {
    const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
    const result_type = try ri.rl.result_type_for_cast(gz, node, builtin_name);
    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);

    try emit_dbg_stmt(gz, cursor);
    const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{
        .lhs = result_type,
        .rhs = operand,
    });
    return rvalue(gz, ri, result, node);
}

fn simple_un_op_type(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const operand = try type_expr(gz, scope, operand_node);
    const result = try gz.add_un_node(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn simple_un_op(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_ri: ResultInfo,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
    const operand = if (tag == .compile_error)
        try comptime_expr(gz, scope, operand_ri, operand_node)
    else
        try expr(gz, scope, operand_ri, operand_node);
    switch (tag) {
        .tag_name, .error_name, .int_from_ptr => try emit_dbg_stmt(gz, cursor),
        else => {},
    }
    const result = try gz.add_un_node(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn negation(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    // Check for float literal as the sub-expression because we want to preserve
    // its negativity rather than having it go through comptime subtraction.
    const operand_node = node_datas[node].lhs;
    if (node_tags[operand_node] == .number_literal) {
        return number_literal(gz, ri, operand_node, node, .negative);
    }

    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);
    const result = try gz.add_un_node(.negate, operand, node);
    return rvalue(gz, ri, result, node);
}

fn cmpxchg(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
    small: u16,
) InnerError!Zir.Inst.Ref {
    const int_type = try type_expr(gz, scope, params[0]);
    const result = try gz.add_extended_payload_small(.cmpxchg, small, Zir.Inst.Cmpxchg{
        // zig fmt: off
        .node           = gz.node_index_to_relative(node),
        .ptr            = try expr(gz, scope, .{ .rl = .none },                                 params[1]),
        .expected_value = try expr(gz, scope, .{ .rl = .{ .ty = int_type } },                   params[2]),
        .new_value      = try expr(gz, scope, .{ .rl = .{ .coerced_ty = int_type } },           params[3]),
        .success_order  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } }, params[4]),
        .failure_order  = try expr(gz, scope, .{ .rl = .{ .coerced_ty = .atomic_order_type } }, params[5]),
        // zig fmt: on
    });
    return rvalue(gz, ri, result, node);
}

fn bit_builtin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const operand = try expr(gz, scope, .{ .rl = .none }, operand_node);
    const result = try gz.add_un_node(tag, operand, node);
    return rvalue(gz, ri, result, node);
}

fn div_builtin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
    const lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node);
    const rhs = try expr(gz, scope, .{ .rl = .none }, rhs_node);

    try emit_dbg_stmt(gz, cursor);
    const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{ .lhs = lhs, .rhs = rhs });
    return rvalue(gz, ri, result, node);
}

fn simple_cbuiltin(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    operand_node: Ast.Node.Index,
    tag: Zir.Inst.Extended,
) InnerError!Zir.Inst.Ref {
    const name: []const u8 = if (tag == .c_undef) "C undef" else "C include";
    if (!gz.c_import) return gz.astgen.fail_node(node, "{s} valid only inside C import block", .{name});
    const operand = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, operand_node);
    _ = try gz.add_extended_payload(tag, Zir.Inst.UnNode{
        .node = gz.node_index_to_relative(node),
        .operand = operand,
    });
    return rvalue(gz, ri, .void_value, node);
}

fn offset_of(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const type_inst = try type_expr(gz, scope, lhs_node);
    const field_name = try comptime_expr(gz, scope, .{ .rl = .{ .coerced_ty = .slice_const_u8_type } }, rhs_node);
    const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{
        .lhs = type_inst,
        .rhs = field_name,
    });
    return rvalue(gz, ri, result, node);
}

fn shift_op(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    lhs_node: Ast.Node.Index,
    rhs_node: Ast.Node.Index,
    tag: Zir.Inst.Tag,
) InnerError!Zir.Inst.Ref {
    const lhs = try expr(gz, scope, .{ .rl = .none }, lhs_node);

    const cursor = switch (gz.astgen.tree.nodes.items(.tag)[node]) {
        .shl, .shr => maybe_advance_source_cursor_to_main_token(gz, node),
        else => undefined,
    };

    const log2_int_type = try gz.add_un_node(.typeof_log2_int_type, lhs, lhs_node);
    const rhs = try expr(gz, scope, .{ .rl = .{ .ty = log2_int_type }, .ctx = .shift_op }, rhs_node);

    switch (gz.astgen.tree.nodes.items(.tag)[node]) {
        .shl, .shr => try emit_dbg_stmt(gz, cursor),
        else => undefined,
    }

    const result = try gz.add_pl_node(tag, node, Zir.Inst.Bin{
        .lhs = lhs,
        .rhs = rhs,
    });
    return rvalue(gz, ri, result, node);
}

fn c_import(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
    body_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;
    const gpa = astgen.gpa;

    if (gz.c_import) return gz.astgen.fail_node(node, "cannot nest @c_import", .{});

    var block_scope = gz.make_sub_block(scope);
    block_scope.is_comptime = true;
    block_scope.c_import = true;
    defer block_scope.unstack();

    const block_inst = try gz.make_block_inst(.c_import, node);
    const block_result = try full_body_expr(&block_scope, &block_scope.base, .{ .rl = .none }, body_node);
    _ = try gz.add_un_node(.ensure_result_used, block_result, node);
    if (!gz.ref_is_no_return(block_result)) {
        _ = try block_scope.add_break(.break_inline, block_inst, .void_value);
    }
    try block_scope.set_block_body(block_inst);
    // block_scope unstacked now, can add new instructions to gz
    try gz.instructions.append(gpa, block_inst);

    return block_inst.to_ref();
}

fn overflow_arithmetic(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    params: []const Ast.Node.Index,
    tag: Zir.Inst.Extended,
) InnerError!Zir.Inst.Ref {
    const lhs = try expr(gz, scope, .{ .rl = .none }, params[0]);
    const rhs = try expr(gz, scope, .{ .rl = .none }, params[1]);
    const result = try gz.add_extended_payload(tag, Zir.Inst.BinNode{
        .node = gz.node_index_to_relative(node),
        .lhs = lhs,
        .rhs = rhs,
    });
    return rvalue(gz, ri, result, node);
}

fn call_expr(
    gz: *GenZir,
    scope: *Scope,
    ri: ResultInfo,
    node: Ast.Node.Index,
    call: Ast.full.Call,
) InnerError!Zir.Inst.Ref {
    const astgen = gz.astgen;

    const callee = try callee_expr(gz, scope, call.ast.fn_expr);
    const modifier: std.builtin.CallModifier = blk: {
        if (gz.is_comptime) {
            break :blk .compile_time;
        }
        if (call.async_token != null) {
            break :blk .async_kw;
        }
        if (gz.nosuspend_node != 0) {
            break :blk .no_async;
        }
        break :blk .auto;
    };

    {
        astgen.advance_source_cursor(astgen.tree.tokens.items(.start)[call.ast.lparen]);
        const line = astgen.source_line - gz.decl_line;
        const column = astgen.source_column;
        // Sema expects a dbg_stmt immediately before call,
        try emit_dbg_stmt_force_current_index(gz, .{ line, column });
    }

    switch (callee) {
        .direct => |obj| assert(obj != .none),
        .field => |field| assert(field.obj_ptr != .none),
    }
    assert(node != 0);

    const call_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
    const call_inst = call_index.to_ref();
    try gz.astgen.instructions.append(astgen.gpa, undefined);
    try gz.instructions.append(astgen.gpa, call_index);

    const scratch_top = astgen.scratch.items.len;
    defer astgen.scratch.items.len = scratch_top;

    var scratch_index = scratch_top;
    try astgen.scratch.resize(astgen.gpa, scratch_top + call.ast.params.len);

    for (call.ast.params) |param_node| {
        var arg_block = gz.make_sub_block(scope);
        defer arg_block.unstack();

        // `call_inst` is reused to provide the param type.
        const arg_ref = try full_body_expr(&arg_block, &arg_block.base, .{ .rl = .{ .coerced_ty = call_inst }, .ctx = .fn_arg }, param_node);
        _ = try arg_block.add_break_with_src_node(.break_inline, call_index, arg_ref, param_node);

        const body = arg_block.instructions_slice();
        try astgen.scratch.ensure_unused_capacity(astgen.gpa, count_body_len_after_fixups(astgen, body));
        append_body_with_fixups_array_list(astgen, &astgen.scratch, body);

        astgen.scratch.items[scratch_index] = @int_cast(astgen.scratch.items.len - scratch_top);
        scratch_index += 1;
    }

    // If our result location is a try/catch/error-union-if/return, a function argument,
    // or an initializer for a `const` variable, the error trace propagates.
    // Otherwise, it should always be popped (handled in Sema).
    const propagate_error_trace = switch (ri.ctx) {
        .error_handling_expr, .@"return", .fn_arg, .const_init => true,
        else => false,
    };

    switch (callee) {
        .direct => |callee_obj| {
            const payload_index = try add_extra(astgen, Zir.Inst.Call{
                .callee = callee_obj,
                .flags = .{
                    .pop_error_return_trace = !propagate_error_trace,
                    .packed_modifier = @int_cast(@int_from_enum(modifier)),
                    .args_len = @int_cast(call.ast.params.len),
                },
            });
            if (call.ast.params.len != 0) {
                try astgen.extra.append_slice(astgen.gpa, astgen.scratch.items[scratch_top..]);
            }
            gz.astgen.instructions.set(@int_from_enum(call_index), .{
                .tag = .call,
                .data = .{ .pl_node = .{
                    .src_node = gz.node_index_to_relative(node),
                    .payload_index = payload_index,
                } },
            });
        },
        .field => |callee_field| {
            const payload_index = try add_extra(astgen, Zir.Inst.FieldCall{
                .obj_ptr = callee_field.obj_ptr,
                .field_name_start = callee_field.field_name_start,
                .flags = .{
                    .pop_error_return_trace = !propagate_error_trace,
                    .packed_modifier = @int_cast(@int_from_enum(modifier)),
                    .args_len = @int_cast(call.ast.params.len),
                },
            });
            if (call.ast.params.len != 0) {
                try astgen.extra.append_slice(astgen.gpa, astgen.scratch.items[scratch_top..]);
            }
            gz.astgen.instructions.set(@int_from_enum(call_index), .{
                .tag = .field_call,
                .data = .{ .pl_node = .{
                    .src_node = gz.node_index_to_relative(node),
                    .payload_index = payload_index,
                } },
            });
        },
    }
    return rvalue(gz, ri, call_inst, node); // TODO function call with result location
}

const Callee = union(enum) {
    field: struct {
        /// A *pointer* to the object the field is fetched on, so that we can
        /// promote the lvalue to an address if the first parameter requires it.
        obj_ptr: Zir.Inst.Ref,
        /// Offset into `string_bytes`.
        field_name_start: Zir.NullTerminatedString,
    },
    direct: Zir.Inst.Ref,
};

/// callee_expr generates the function part of a call expression (f in f(x)), but
/// *not* the callee argument to the @call() builtin. Its purpose is to
/// distinguish between standard calls and method call syntax `a.b()`. Thus, if
/// the lhs is a field access, we return using the `field` union field;
/// otherwise, we use the `direct` union field.
fn callee_expr(
    gz: *GenZir,
    scope: *Scope,
    node: Ast.Node.Index,
) InnerError!Callee {
    const astgen = gz.astgen;
    const tree = astgen.tree;

    const tag = tree.nodes.items(.tag)[node];
    switch (tag) {
        .field_access => {
            const main_tokens = tree.nodes.items(.main_token);
            const node_datas = tree.nodes.items(.data);
            const object_node = node_datas[node].lhs;
            const dot_token = main_tokens[node];
            const field_ident = dot_token + 1;
            const str_index = try astgen.ident_as_string(field_ident);
            // Capture the object by reference so we can promote it to an
            // address in Sema if needed.
            const lhs = try expr(gz, scope, .{ .rl = .ref }, object_node);

            const cursor = maybe_advance_source_cursor_to_main_token(gz, node);
            try emit_dbg_stmt(gz, cursor);

            return .{ .field = .{
                .obj_ptr = lhs,
                .field_name_start = str_index,
            } };
        },
        else => return .{ .direct = try expr(gz, scope, .{ .rl = .none }, node) },
    }
}

const primitive_instrs = std.StaticStringMap(Zir.Inst.Ref).init_comptime(.{
    .{ "anyerror", .anyerror_type },
    .{ "anyframe", .anyframe_type },
    .{ "anyopaque", .anyopaque_type },
    .{ "bool", .bool_type },
    .{ "c_int", .c_int_type },
    .{ "c_long", .c_long_type },
    .{ "c_longdouble", .c_longdouble_type },
    .{ "c_longlong", .c_longlong_type },
    .{ "c_char", .c_char_type },
    .{ "c_short", .c_short_type },
    .{ "c_uint", .c_uint_type },
    .{ "c_ulong", .c_ulong_type },
    .{ "c_ulonglong", .c_ulonglong_type },
    .{ "c_ushort", .c_ushort_type },
    .{ "comptime_float", .comptime_float_type },
    .{ "comptime_int", .comptime_int_type },
    .{ "f128", .f128_type },
    .{ "f16", .f16_type },
    .{ "f32", .f32_type },
    .{ "f64", .f64_type },
    .{ "f80", .f80_type },
    .{ "false", .bool_false },
    .{ "i16", .i16_type },
    .{ "i32", .i32_type },
    .{ "i64", .i64_type },
    .{ "i128", .i128_type },
    .{ "i8", .i8_type },
    .{ "isize", .isize_type },
    .{ "noreturn", .noreturn_type },
    .{ "null", .null_value },
    .{ "true", .bool_true },
    .{ "type", .type_type },
    .{ "u16", .u16_type },
    .{ "u29", .u29_type },
    .{ "u32", .u32_type },
    .{ "u64", .u64_type },
    .{ "u128", .u128_type },
    .{ "u1", .u1_type },
    .{ "u8", .u8_type },
    .{ "undefined", .undef },
    .{ "usize", .usize_type },
    .{ "void", .void_type },
});

comptime {
    // These checks ensure that std.zig.primitives stays in sync with the primitive->Zir map.
    const primitives = std.zig.primitives;
    for (primitive_instrs.keys(), primitive_instrs.values()) |key, value| {
        if (!primitives.is_primitive(key)) {
            @compile_error("std.zig.is_primitive() is not aware of Zir instr '" ++ @tag_name(value) ++ "'");
        }
    }
    for (primitives.names.keys()) |key| {
        if (primitive_instrs.get(key) == null) {
            @compile_error("std.zig.primitives entry '" ++ key ++ "' does not have a corresponding Zir instr");
        }
    }
}

fn node_is_trivially_zero(tree: *const Ast, node: Ast.Node.Index) bool {
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);

    switch (node_tags[node]) {
        .number_literal => {
            const ident = main_tokens[node];
            return switch (std.zig.parse_number_literal(tree.token_slice(ident))) {
                .int => |number| switch (number) {
                    0 => true,
                    else => false,
                },
                else => false,
            };
        },
        else => return false,
    }
}

fn node_may_append_to_error_trace(tree: *const Ast, start_node: Ast.Node.Index) bool {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    var node = start_node;
    while (true) {
        switch (node_tags[node]) {
            // These don't have the opportunity to call any runtime functions.
            .error_value,
            .identifier,
            .@"comptime",
            => return false,

            // Forward the question to the LHS sub-expression.
            .grouped_expression,
            .@"try",
            .@"nosuspend",
            .unwrap_optional,
            => node = node_datas[node].lhs,

            // Anything that does not eval to an error is guaranteed to pop any
            // additions to the error trace, so it effectively does not append.
            else => return node_may_eval_to_error(tree, start_node) != .never,
        }
    }
}

fn node_may_eval_to_error(tree: *const Ast, start_node: Ast.Node.Index) BuiltinFn.EvalToError {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    var node = start_node;
    while (true) {
        switch (node_tags[node]) {
            .root,
            .@"usingnamespace",
            .test_decl,
            .switch_case,
            .switch_case_inline,
            .switch_case_one,
            .switch_case_inline_one,
            .container_field_init,
            .container_field_align,
            .container_field,
            .asm_output,
            .asm_input,
            => unreachable,

            .error_value => return .always,

            .@"asm",
            .asm_simple,
            .identifier,
            .field_access,
            .deref,
            .array_access,
            .while_simple,
            .while_cont,
            .for_simple,
            .if_simple,
            .@"while",
            .@"if",
            .@"for",
            .@"switch",
            .switch_comma,
            .call_one,
            .call_one_comma,
            .async_call_one,
            .async_call_one_comma,
            .call,
            .call_comma,
            .async_call,
            .async_call_comma,
            => return .maybe,

            .@"return",
            .@"break",
            .@"continue",
            .bit_not,
            .bool_not,
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            .@"defer",
            .@"errdefer",
            .address_of,
            .optional_type,
            .negation,
            .negation_wrap,
            .@"resume",
            .array_type,
            .array_type_sentinel,
            .ptr_type_aligned,
            .ptr_type_sentinel,
            .ptr_type,
            .ptr_type_bit_range,
            .@"suspend",
            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            .fn_decl,
            .anyframe_type,
            .anyframe_literal,
            .number_literal,
            .enum_literal,
            .string_literal,
            .multiline_string_literal,
            .char_literal,
            .unreachable_literal,
            .error_set_decl,
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            .add,
            .add_wrap,
            .add_sat,
            .array_cat,
            .array_mult,
            .assign,
            .assign_destructure,
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
            .error_union,
            .greater_or_equal,
            .greater_than,
            .less_or_equal,
            .less_than,
            .merge_error_sets,
            .mod,
            .mul,
            .mul_wrap,
            .mul_sat,
            .switch_range,
            .for_range,
            .sub,
            .sub_wrap,
            .sub_sat,
            .slice,
            .slice_open,
            .slice_sentinel,
            .array_init_one,
            .array_init_one_comma,
            .array_init_dot_two,
            .array_init_dot_two_comma,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init,
            .array_init_comma,
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init,
            .struct_init_comma,
            => return .never,

            // Forward the question to the LHS sub-expression.
            .grouped_expression,
            .@"try",
            .@"await",
            .@"comptime",
            .@"nosuspend",
            .unwrap_optional,
            => node = node_datas[node].lhs,

            // LHS sub-expression may still be an error under the outer optional or error union
            .@"catch",
            .@"orelse",
            => return .maybe,

            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            => {
                const lbrace = main_tokens[node];
                if (token_tags[lbrace - 1] == .colon) {
                    // Labeled blocks may need a memory location to forward
                    // to their break statements.
                    return .maybe;
                } else {
                    return .never;
                }
            },

            .builtin_call,
            .builtin_call_comma,
            .builtin_call_two,
            .builtin_call_two_comma,
            => {
                const builtin_token = main_tokens[node];
                const builtin_name = tree.token_slice(builtin_token);
                // If the builtin is an invalid name, we don't cause an error here; instead
                // let it pass, and the error will be "invalid builtin function" later.
                const builtin_info = BuiltinFn.list.get(builtin_name) orelse return .maybe;
                return builtin_info.eval_to_error;
            },
        }
    }
}

/// Returns `true` if it is known the type expression has more than one possible value;
/// `false` otherwise.
fn node_implies_more_than_one_possible_value(tree: *const Ast, start_node: Ast.Node.Index) bool {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    var node = start_node;
    while (true) {
        switch (node_tags[node]) {
            .root,
            .@"usingnamespace",
            .test_decl,
            .switch_case,
            .switch_case_inline,
            .switch_case_one,
            .switch_case_inline_one,
            .container_field_init,
            .container_field_align,
            .container_field,
            .asm_output,
            .asm_input,
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => unreachable,

            .@"return",
            .@"break",
            .@"continue",
            .bit_not,
            .bool_not,
            .@"defer",
            .@"errdefer",
            .address_of,
            .negation,
            .negation_wrap,
            .@"resume",
            .array_type,
            .@"suspend",
            .fn_decl,
            .anyframe_literal,
            .number_literal,
            .enum_literal,
            .string_literal,
            .multiline_string_literal,
            .char_literal,
            .unreachable_literal,
            .error_set_decl,
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            .@"asm",
            .asm_simple,
            .add,
            .add_wrap,
            .add_sat,
            .array_cat,
            .array_mult,
            .assign,
            .assign_destructure,
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
            .error_union,
            .greater_or_equal,
            .greater_than,
            .less_or_equal,
            .less_than,
            .merge_error_sets,
            .mod,
            .mul,
            .mul_wrap,
            .mul_sat,
            .switch_range,
            .for_range,
            .field_access,
            .sub,
            .sub_wrap,
            .sub_sat,
            .slice,
            .slice_open,
            .slice_sentinel,
            .deref,
            .array_access,
            .error_value,
            .while_simple,
            .while_cont,
            .for_simple,
            .if_simple,
            .@"catch",
            .@"orelse",
            .array_init_one,
            .array_init_one_comma,
            .array_init_dot_two,
            .array_init_dot_two_comma,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init,
            .array_init_comma,
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init,
            .struct_init_comma,
            .@"while",
            .@"if",
            .@"for",
            .@"switch",
            .switch_comma,
            .call_one,
            .call_one_comma,
            .async_call_one,
            .async_call_one_comma,
            .call,
            .call_comma,
            .async_call,
            .async_call_comma,
            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            .builtin_call,
            .builtin_call_comma,
            .builtin_call_two,
            .builtin_call_two_comma,
            // these are function bodies, not pointers
            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            => return false,

            // Forward the question to the LHS sub-expression.
            .grouped_expression,
            .@"try",
            .@"await",
            .@"comptime",
            .@"nosuspend",
            .unwrap_optional,
            => node = node_datas[node].lhs,

            .ptr_type_aligned,
            .ptr_type_sentinel,
            .ptr_type,
            .ptr_type_bit_range,
            .optional_type,
            .anyframe_type,
            .array_type_sentinel,
            => return true,

            .identifier => {
                const main_tokens = tree.nodes.items(.main_token);
                const ident_bytes = tree.token_slice(main_tokens[node]);
                if (primitive_instrs.get(ident_bytes)) |primitive| switch (primitive) {
                    .anyerror_type,
                    .anyframe_type,
                    .anyopaque_type,
                    .bool_type,
                    .c_int_type,
                    .c_long_type,
                    .c_longdouble_type,
                    .c_longlong_type,
                    .c_char_type,
                    .c_short_type,
                    .c_uint_type,
                    .c_ulong_type,
                    .c_ulonglong_type,
                    .c_ushort_type,
                    .comptime_float_type,
                    .comptime_int_type,
                    .f16_type,
                    .f32_type,
                    .f64_type,
                    .f80_type,
                    .f128_type,
                    .i16_type,
                    .i32_type,
                    .i64_type,
                    .i128_type,
                    .i8_type,
                    .isize_type,
                    .type_type,
                    .u16_type,
                    .u29_type,
                    .u32_type,
                    .u64_type,
                    .u128_type,
                    .u1_type,
                    .u8_type,
                    .usize_type,
                    => return true,

                    .void_type,
                    .bool_false,
                    .bool_true,
                    .null_value,
                    .undef,
                    .noreturn_type,
                    => return false,

                    else => unreachable, // that's all the values from `primitives`.
                } else {
                    return false;
                }
            },
        }
    }
}

/// Returns `true` if it is known the expression is a type that cannot be used at runtime;
/// `false` otherwise.
fn node_implies_comptime_only(tree: *const Ast, start_node: Ast.Node.Index) bool {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    var node = start_node;
    while (true) {
        switch (node_tags[node]) {
            .root,
            .@"usingnamespace",
            .test_decl,
            .switch_case,
            .switch_case_inline,
            .switch_case_one,
            .switch_case_inline_one,
            .container_field_init,
            .container_field_align,
            .container_field,
            .asm_output,
            .asm_input,
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => unreachable,

            .@"return",
            .@"break",
            .@"continue",
            .bit_not,
            .bool_not,
            .@"defer",
            .@"errdefer",
            .address_of,
            .negation,
            .negation_wrap,
            .@"resume",
            .array_type,
            .@"suspend",
            .fn_decl,
            .anyframe_literal,
            .number_literal,
            .enum_literal,
            .string_literal,
            .multiline_string_literal,
            .char_literal,
            .unreachable_literal,
            .error_set_decl,
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            .tagged_union,
            .tagged_union_trailing,
            .tagged_union_two,
            .tagged_union_two_trailing,
            .tagged_union_enum_tag,
            .tagged_union_enum_tag_trailing,
            .@"asm",
            .asm_simple,
            .add,
            .add_wrap,
            .add_sat,
            .array_cat,
            .array_mult,
            .assign,
            .assign_destructure,
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
            .error_union,
            .greater_or_equal,
            .greater_than,
            .less_or_equal,
            .less_than,
            .merge_error_sets,
            .mod,
            .mul,
            .mul_wrap,
            .mul_sat,
            .switch_range,
            .for_range,
            .field_access,
            .sub,
            .sub_wrap,
            .sub_sat,
            .slice,
            .slice_open,
            .slice_sentinel,
            .deref,
            .array_access,
            .error_value,
            .while_simple,
            .while_cont,
            .for_simple,
            .if_simple,
            .@"catch",
            .@"orelse",
            .array_init_one,
            .array_init_one_comma,
            .array_init_dot_two,
            .array_init_dot_two_comma,
            .array_init_dot,
            .array_init_dot_comma,
            .array_init,
            .array_init_comma,
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init,
            .struct_init_comma,
            .@"while",
            .@"if",
            .@"for",
            .@"switch",
            .switch_comma,
            .call_one,
            .call_one_comma,
            .async_call_one,
            .async_call_one_comma,
            .call,
            .call_comma,
            .async_call,
            .async_call_comma,
            .block_two,
            .block_two_semicolon,
            .block,
            .block_semicolon,
            .builtin_call,
            .builtin_call_comma,
            .builtin_call_two,
            .builtin_call_two_comma,
            .ptr_type_aligned,
            .ptr_type_sentinel,
            .ptr_type,
            .ptr_type_bit_range,
            .optional_type,
            .anyframe_type,
            .array_type_sentinel,
            => return false,

            // these are function bodies, not pointers
            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            => return true,

            // Forward the question to the LHS sub-expression.
            .grouped_expression,
            .@"try",
            .@"await",
            .@"comptime",
            .@"nosuspend",
            .unwrap_optional,
            => node = node_datas[node].lhs,

            .identifier => {
                const main_tokens = tree.nodes.items(.main_token);
                const ident_bytes = tree.token_slice(main_tokens[node]);
                if (primitive_instrs.get(ident_bytes)) |primitive| switch (primitive) {
                    .anyerror_type,
                    .anyframe_type,
                    .anyopaque_type,
                    .bool_type,
                    .c_int_type,
                    .c_long_type,
                    .c_longdouble_type,
                    .c_longlong_type,
                    .c_char_type,
                    .c_short_type,
                    .c_uint_type,
                    .c_ulong_type,
                    .c_ulonglong_type,
                    .c_ushort_type,
                    .f16_type,
                    .f32_type,
                    .f64_type,
                    .f80_type,
                    .f128_type,
                    .i16_type,
                    .i32_type,
                    .i64_type,
                    .i128_type,
                    .i8_type,
                    .isize_type,
                    .u16_type,
                    .u29_type,
                    .u32_type,
                    .u64_type,
                    .u128_type,
                    .u1_type,
                    .u8_type,
                    .usize_type,
                    .void_type,
                    .bool_false,
                    .bool_true,
                    .null_value,
                    .undef,
                    .noreturn_type,
                    => return false,

                    .comptime_float_type,
                    .comptime_int_type,
                    .type_type,
                    => return true,

                    else => unreachable, // that's all the values from `primitives`.
                } else {
                    return false;
                }
            },
        }
    }
}

/// Returns `true` if the node uses `gz.anon_name_strategy`.
fn node_uses_anon_name_strategy(tree: *const Ast, node: Ast.Node.Index) bool {
    const node_tags = tree.nodes.items(.tag);
    switch (node_tags[node]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => return true,
        .builtin_call_two, .builtin_call_two_comma, .builtin_call, .builtin_call_comma => {
            const builtin_token = tree.nodes.items(.main_token)[node];
            const builtin_name = tree.token_slice(builtin_token);
            return std.mem.eql(u8, builtin_name, "@Type");
        },
        else => return false,
    }
}

/// Applies `rl` semantics to `result`. Expressions which do not do their own handling of
/// result locations must call this function on their result.
/// As an example, if `ri.rl` is `.ptr`, it will write the result to the pointer.
/// If `ri.rl` is `.ty`, it will coerce the result to the type.
/// Assumes nothing stacked on `gz`.
fn rvalue(
    gz: *GenZir,
    ri: ResultInfo,
    raw_result: Zir.Inst.Ref,
    src_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return rvalue_inner(gz, ri, raw_result, src_node, true);
}

/// Like `rvalue`, but refuses to perform coercions before taking references for
/// the `ref_coerced_ty` result type. This is used for local variables which do
/// not have `alloc`s, because we want variables to have consistent addresses,
/// i.e. we want them to act like lvalues.
fn rvalue_no_coerce_pre_ref(
    gz: *GenZir,
    ri: ResultInfo,
    raw_result: Zir.Inst.Ref,
    src_node: Ast.Node.Index,
) InnerError!Zir.Inst.Ref {
    return rvalue_inner(gz, ri, raw_result, src_node, false);
}

fn rvalue_inner(
    gz: *GenZir,
    ri: ResultInfo,
    raw_result: Zir.Inst.Ref,
    src_node: Ast.Node.Index,
    allow_coerce_pre_ref: bool,
) InnerError!Zir.Inst.Ref {
    const result = r: {
        if (raw_result.to_index()) |result_index| {
            const zir_tags = gz.astgen.instructions.items(.tag);
            const data = gz.astgen.instructions.items(.data)[@int_from_enum(result_index)];
            if (zir_tags[@int_from_enum(result_index)].is_always_void(data)) {
                break :r Zir.Inst.Ref.void_value;
            }
        }
        break :r raw_result;
    };
    if (gz.ends_with_no_return()) return result;
    switch (ri.rl) {
        .none, .coerced_ty => return result,
        .discard => {
            // Emit a compile error for discarding error values.
            _ = try gz.add_un_node(.ensure_result_non_error, result, src_node);
            return .void_value;
        },
        .ref, .ref_coerced_ty => {
            const coerced_result = if (allow_coerce_pre_ref and ri.rl == .ref_coerced_ty) res: {
                const ptr_ty = ri.rl.ref_coerced_ty;
                break :res try gz.add_pl_node(.coerce_ptr_elem_ty, src_node, Zir.Inst.Bin{
                    .lhs = ptr_ty,
                    .rhs = result,
                });
            } else result;
            // We need a pointer but we have a value.
            // Unfortunately it's not quite as simple as directly emitting a ref
            // instruction here because we need subsequent address-of operator on
            // const locals to return the same address.
            const astgen = gz.astgen;
            const tree = astgen.tree;
            const src_token = tree.first_token(src_node);
            const result_index = coerced_result.to_index() orelse
                return gz.add_un_tok(.ref, coerced_result, src_token);
            const zir_tags = gz.astgen.instructions.items(.tag);
            if (zir_tags[@int_from_enum(result_index)].is_param() or astgen.is_inferred(coerced_result))
                return gz.add_un_tok(.ref, coerced_result, src_token);
            const gop = try astgen.ref_table.get_or_put(astgen.gpa, result_index);
            if (!gop.found_existing) {
                gop.value_ptr.* = try gz.make_un_tok(.ref, coerced_result, src_token);
            }
            return gop.value_ptr.*.to_ref();
        },
        .ty => |ty_inst| {
            // Quickly eliminate some common, unnecessary type coercion.
            const as_ty = @as(u64, @int_from_enum(Zir.Inst.Ref.type_type)) << 32;
            const as_bool = @as(u64, @int_from_enum(Zir.Inst.Ref.bool_type)) << 32;
            const as_void = @as(u64, @int_from_enum(Zir.Inst.Ref.void_type)) << 32;
            const as_comptime_int = @as(u64, @int_from_enum(Zir.Inst.Ref.comptime_int_type)) << 32;
            const as_usize = @as(u64, @int_from_enum(Zir.Inst.Ref.usize_type)) << 32;
            const as_u8 = @as(u64, @int_from_enum(Zir.Inst.Ref.u8_type)) << 32;
            switch ((@as(u64, @int_from_enum(ty_inst)) << 32) | @as(u64, @int_from_enum(result))) {
                as_ty | @int_from_enum(Zir.Inst.Ref.u1_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u8_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.i8_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u16_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u29_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.i16_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u32_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.i32_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u64_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.i64_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.u128_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.i128_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.usize_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.isize_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_char_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_short_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_ushort_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_int_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_uint_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_long_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_ulong_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_longlong_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_ulonglong_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.c_longdouble_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.f16_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.f32_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.f64_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.f80_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.f128_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.anyopaque_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.bool_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.void_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.type_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.anyerror_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.comptime_int_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.comptime_float_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.noreturn_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.anyframe_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.null_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.undefined_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.enum_literal_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.atomic_order_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.atomic_rmw_op_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.calling_convention_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.address_space_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.float_mode_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.reduce_op_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.call_modifier_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.prefetch_options_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.export_options_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.extern_options_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.type_info_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.manyptr_u8_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.manyptr_const_u8_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.manyptr_const_u8_sentinel_0_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.single_const_pointer_to_comptime_int_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.slice_const_u8_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.slice_const_u8_sentinel_0_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.anyerror_void_error_union_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.generic_poison_type),
                as_ty | @int_from_enum(Zir.Inst.Ref.empty_struct_type),
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.zero),
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.one),
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.negative_one),
                as_usize | @int_from_enum(Zir.Inst.Ref.zero_usize),
                as_usize | @int_from_enum(Zir.Inst.Ref.one_usize),
                as_u8 | @int_from_enum(Zir.Inst.Ref.zero_u8),
                as_u8 | @int_from_enum(Zir.Inst.Ref.one_u8),
                as_u8 | @int_from_enum(Zir.Inst.Ref.four_u8),
                as_bool | @int_from_enum(Zir.Inst.Ref.bool_true),
                as_bool | @int_from_enum(Zir.Inst.Ref.bool_false),
                as_void | @int_from_enum(Zir.Inst.Ref.void_value),
                => return result, // type of result is already correct

                as_usize | @int_from_enum(Zir.Inst.Ref.zero) => return .zero_usize,
                as_u8 | @int_from_enum(Zir.Inst.Ref.zero) => return .zero_u8,
                as_usize | @int_from_enum(Zir.Inst.Ref.one) => return .one_usize,
                as_u8 | @int_from_enum(Zir.Inst.Ref.one) => return .one_u8,
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.zero_usize) => return .zero,
                as_u8 | @int_from_enum(Zir.Inst.Ref.zero_usize) => return .zero_u8,
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.one_usize) => return .one,
                as_u8 | @int_from_enum(Zir.Inst.Ref.one_usize) => return .one_u8,
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.zero_u8) => return .zero,
                as_usize | @int_from_enum(Zir.Inst.Ref.zero_u8) => return .zero_usize,
                as_comptime_int | @int_from_enum(Zir.Inst.Ref.one_u8) => return .one,
                as_usize | @int_from_enum(Zir.Inst.Ref.one_u8) => return .one_usize,

                // Need an explicit type coercion instruction.
                else => return gz.add_pl_node(ri.zir_tag(), src_node, Zir.Inst.As{
                    .dest_type = ty_inst,
                    .operand = result,
                }),
            }
        },
        .ptr => |ptr_res| {
            _ = try gz.add_pl_node(.store_node, ptr_res.src_node orelse src_node, Zir.Inst.Bin{
                .lhs = ptr_res.inst,
                .rhs = result,
            });
            return .void_value;
        },
        .inferred_ptr => |alloc| {
            _ = try gz.add_pl_node(.store_to_inferred_ptr, src_node, Zir.Inst.Bin{
                .lhs = alloc,
                .rhs = result,
            });
            return .void_value;
        },
        .destructure => |destructure| {
            const components = destructure.components;
            _ = try gz.add_pl_node(.validate_destructure, src_node, Zir.Inst.ValidateDestructure{
                .operand = result,
                .destructure_node = gz.node_index_to_relative(destructure.src_node),
                .expect_len = @int_cast(components.len),
            });
            for (components, 0..) |component, i| {
                if (component == .discard) continue;
                const elem_val = try gz.add(.{
                    .tag = .elem_val_imm,
                    .data = .{ .elem_val_imm = .{
                        .operand = result,
                        .idx = @int_cast(i),
                    } },
                });
                switch (component) {
                    .typed_ptr => |ptr_res| {
                        _ = try gz.add_pl_node(.store_node, ptr_res.src_node orelse src_node, Zir.Inst.Bin{
                            .lhs = ptr_res.inst,
                            .rhs = elem_val,
                        });
                    },
                    .inferred_ptr => |ptr_inst| {
                        _ = try gz.add_pl_node(.store_to_inferred_ptr, src_node, Zir.Inst.Bin{
                            .lhs = ptr_inst,
                            .rhs = elem_val,
                        });
                    },
                    .discard => unreachable,
                }
            }
            return .void_value;
        },
    }
}

/// Given an identifier token, obtain the string for it.
/// If the token uses @"" syntax, parses as a string, reports errors if applicable,
/// and allocates the result within `astgen.arena`.
/// Otherwise, returns a reference to the source code bytes directly.
/// See also `append_ident_str` and `parse_str_lit`.
fn identifier_token_string(astgen: *AstGen, token: Ast.TokenIndex) InnerError![]const u8 {
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);
    assert(token_tags[token] == .identifier);
    const ident_name = tree.token_slice(token);
    if (!mem.starts_with(u8, ident_name, "@")) {
        return ident_name;
    }
    var buf: ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(astgen.gpa);
    try astgen.parse_str_lit(token, &buf, ident_name, 1);
    if (mem.index_of_scalar(u8, buf.items, 0) != null) {
        return astgen.fail_tok(token, "identifier cannot contain null bytes", .{});
    } else if (buf.items.len == 0) {
        return astgen.fail_tok(token, "identifier cannot be empty", .{});
    }
    const duped = try astgen.arena.dupe(u8, buf.items);
    return duped;
}

/// Given an identifier token, obtain the string for it (possibly parsing as a string
/// literal if it is @"" syntax), and append the string to `buf`.
/// See also `identifier_token_string` and `parse_str_lit`.
fn append_ident_str(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    buf: *ArrayListUnmanaged(u8),
) InnerError!void {
    const tree = astgen.tree;
    const token_tags = tree.tokens.items(.tag);
    assert(token_tags[token] == .identifier);
    const ident_name = tree.token_slice(token);
    if (!mem.starts_with(u8, ident_name, "@")) {
        return buf.append_slice(astgen.gpa, ident_name);
    } else {
        const start = buf.items.len;
        try astgen.parse_str_lit(token, buf, ident_name, 1);
        const slice = buf.items[start..];
        if (mem.index_of_scalar(u8, slice, 0) != null) {
            return astgen.fail_tok(token, "identifier cannot contain null bytes", .{});
        } else if (slice.len == 0) {
            return astgen.fail_tok(token, "identifier cannot be empty", .{});
        }
    }
}

/// Appends the result to `buf`.
fn parse_str_lit(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    buf: *ArrayListUnmanaged(u8),
    bytes: []const u8,
    offset: u32,
) InnerError!void {
    const raw_string = bytes[offset..];
    var buf_managed = buf.to_managed(astgen.gpa);
    const result = std.zig.string_literal.parse_write(buf_managed.writer(), raw_string);
    buf.* = buf_managed.move_to_unmanaged();
    switch (try result) {
        .success => return,
        .failure => |err| return astgen.fail_with_str_lit_error(err, token, bytes, offset),
    }
}

fn fail_with_str_lit_error(astgen: *AstGen, err: std.zig.string_literal.Error, token: Ast.TokenIndex, bytes: []const u8, offset: u32) InnerError {
    const raw_string = bytes[offset..];
    switch (err) {
        .invalid_escape_character => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "invalid escape character: '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .expected_hex_digit => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "expected hex digit, found '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .empty_unicode_escape_sequence => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "empty unicode escape sequence",
                .{},
            );
        },
        .expected_hex_digit_or_rbrace => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "expected hex digit or '}}', found '{c}'",
                .{raw_string[bad_index]},
            );
        },
        .invalid_unicode_codepoint => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "unicode escape does not correspond to a valid codepoint",
                .{},
            );
        },
        .expected_lbrace => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "expected '{{', found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .expected_rbrace => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "expected '}}', found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .expected_single_quote => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "expected single quote ('), found '{c}",
                .{raw_string[bad_index]},
            );
        },
        .invalid_character => |bad_index| {
            return astgen.fail_off(
                token,
                offset + @as(u32, @int_cast(bad_index)),
                "invalid byte in string or character literal: '{c}'",
                .{raw_string[bad_index]},
            );
        },
    }
}

fn fail_node(
    astgen: *AstGen,
    node: Ast.Node.Index,
    comptime format: []const u8,
    args: anytype,
) InnerError {
    return astgen.fail_node_notes(node, format, args, &[0]u32{});
}

fn append_error_node(
    astgen: *AstGen,
    node: Ast.Node.Index,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!void {
    try astgen.append_error_node_notes(node, format, args, &[0]u32{});
}

fn append_error_node_notes(
    astgen: *AstGen,
    node: Ast.Node.Index,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) Allocator.Error!void {
    @setCold(true);
    const string_bytes = &astgen.string_bytes;
    const msg: Zir.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(astgen.gpa).print(format ++ "\x00", args);
    const notes_index: u32 = if (notes.len != 0) blk: {
        const notes_start = astgen.extra.items.len;
        try astgen.extra.ensure_total_capacity(astgen.gpa, notes_start + 1 + notes.len);
        astgen.extra.append_assume_capacity(@int_cast(notes.len));
        astgen.extra.append_slice_assume_capacity(notes);
        break :blk @int_cast(notes_start);
    } else 0;
    try astgen.compile_errors.append(astgen.gpa, .{
        .msg = msg,
        .node = node,
        .token = 0,
        .byte_offset = 0,
        .notes = notes_index,
    });
}

fn fail_node_notes(
    astgen: *AstGen,
    node: Ast.Node.Index,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) InnerError {
    try append_error_node_notes(astgen, node, format, args, notes);
    return error.AnalysisFail;
}

fn fail_tok(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
) InnerError {
    return astgen.fail_tok_notes(token, format, args, &[0]u32{});
}

fn append_error_tok(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
) !void {
    try astgen.append_error_tok_notes_off(token, 0, format, args, &[0]u32{});
}

fn fail_tok_notes(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) InnerError {
    try append_error_tok_notes_off(astgen, token, 0, format, args, notes);
    return error.AnalysisFail;
}

fn append_error_tok_notes(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) !void {
    return append_error_tok_notes_off(astgen, token, 0, format, args, notes);
}

/// Same as `fail`, except given a token plus an offset from its starting byte
/// offset.
fn fail_off(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
) InnerError {
    try append_error_tok_notes_off(astgen, token, byte_offset, format, args, &.{});
    return error.AnalysisFail;
}

fn append_error_tok_notes_off(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
    notes: []const u32,
) !void {
    @setCold(true);
    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const msg: Zir.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(gpa).print(format ++ "\x00", args);
    const notes_index: u32 = if (notes.len != 0) blk: {
        const notes_start = astgen.extra.items.len;
        try astgen.extra.ensure_total_capacity(gpa, notes_start + 1 + notes.len);
        astgen.extra.append_assume_capacity(@int_cast(notes.len));
        astgen.extra.append_slice_assume_capacity(notes);
        break :blk @int_cast(notes_start);
    } else 0;
    try astgen.compile_errors.append(gpa, .{
        .msg = msg,
        .node = 0,
        .token = token,
        .byte_offset = byte_offset,
        .notes = notes_index,
    });
}

fn err_note_tok(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    return err_note_tok_off(astgen, token, 0, format, args);
}

fn err_note_tok_off(
    astgen: *AstGen,
    token: Ast.TokenIndex,
    byte_offset: u32,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    @setCold(true);
    const string_bytes = &astgen.string_bytes;
    const msg: Zir.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(astgen.gpa).print(format ++ "\x00", args);
    return astgen.add_extra(Zir.Inst.CompileErrors.Item{
        .msg = msg,
        .node = 0,
        .token = token,
        .byte_offset = byte_offset,
        .notes = 0,
    });
}

fn err_note_node(
    astgen: *AstGen,
    node: Ast.Node.Index,
    comptime format: []const u8,
    args: anytype,
) Allocator.Error!u32 {
    @setCold(true);
    const string_bytes = &astgen.string_bytes;
    const msg: Zir.NullTerminatedString = @enumFromInt(string_bytes.items.len);
    try string_bytes.writer(astgen.gpa).print(format ++ "\x00", args);
    return astgen.add_extra(Zir.Inst.CompileErrors.Item{
        .msg = msg,
        .node = node,
        .token = 0,
        .byte_offset = 0,
        .notes = 0,
    });
}

fn ident_as_string(astgen: *AstGen, ident_token: Ast.TokenIndex) !Zir.NullTerminatedString {
    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const str_index: u32 = @int_cast(string_bytes.items.len);
    try astgen.append_ident_str(ident_token, string_bytes);
    const key: []const u8 = string_bytes.items[str_index..];
    const gop = try astgen.string_table.get_or_put_context_adapted(gpa, key, StringIndexAdapter{
        .bytes = string_bytes,
    }, StringIndexContext{
        .bytes = string_bytes,
    });
    if (gop.found_existing) {
        string_bytes.shrink_retaining_capacity(str_index);
        return @enumFromInt(gop.key_ptr.*);
    } else {
        gop.key_ptr.* = str_index;
        try string_bytes.append(gpa, 0);
        return @enumFromInt(str_index);
    }
}

/// Adds a doc comment block to `string_bytes` by walking backwards from `end_token`.
/// `end_token` must point at the first token after the last doc coment line.
/// Returns 0 if no doc comment is present.
fn doc_comment_as_string(astgen: *AstGen, end_token: Ast.TokenIndex) !Zir.NullTerminatedString {
    if (end_token == 0) return .empty;

    const token_tags = astgen.tree.tokens.items(.tag);

    var tok = end_token - 1;
    while (token_tags[tok] == .doc_comment) {
        if (tok == 0) break;
        tok -= 1;
    } else {
        tok += 1;
    }

    return doc_comment_as_string_from_first(astgen, end_token, tok);
}

/// end_token must be > the index of the last doc comment.
fn doc_comment_as_string_from_first(
    astgen: *AstGen,
    end_token: Ast.TokenIndex,
    start_token: Ast.TokenIndex,
) !Zir.NullTerminatedString {
    if (start_token == end_token) return .empty;

    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const str_index: u32 = @int_cast(string_bytes.items.len);
    const token_starts = astgen.tree.tokens.items(.start);
    const token_tags = astgen.tree.tokens.items(.tag);

    const total_bytes = token_starts[end_token] - token_starts[start_token];
    try string_bytes.ensure_unused_capacity(gpa, total_bytes);

    var current_token = start_token;
    while (current_token < end_token) : (current_token += 1) {
        switch (token_tags[current_token]) {
            .doc_comment => {
                const tok_bytes = astgen.tree.token_slice(current_token)[3..];
                string_bytes.append_slice_assume_capacity(tok_bytes);
                if (current_token != end_token - 1) {
                    string_bytes.append_assume_capacity('\n');
                }
            },
            else => break,
        }
    }

    const key: []const u8 = string_bytes.items[str_index..];
    const gop = try astgen.string_table.get_or_put_context_adapted(gpa, key, StringIndexAdapter{
        .bytes = string_bytes,
    }, StringIndexContext{
        .bytes = string_bytes,
    });

    if (gop.found_existing) {
        string_bytes.shrink_retaining_capacity(str_index);
        return @enumFromInt(gop.key_ptr.*);
    } else {
        gop.key_ptr.* = str_index;
        try string_bytes.append(gpa, 0);
        return @enumFromInt(str_index);
    }
}

const IndexSlice = struct { index: Zir.NullTerminatedString, len: u32 };

fn str_lit_as_string(astgen: *AstGen, str_lit_token: Ast.TokenIndex) !IndexSlice {
    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const str_index: u32 = @int_cast(string_bytes.items.len);
    const token_bytes = astgen.tree.token_slice(str_lit_token);
    try astgen.parse_str_lit(str_lit_token, string_bytes, token_bytes, 0);
    const key: []const u8 = string_bytes.items[str_index..];
    if (std.mem.index_of_scalar(u8, key, 0)) |_| return .{
        .index = @enumFromInt(str_index),
        .len = @int_cast(key.len),
    };
    const gop = try astgen.string_table.get_or_put_context_adapted(gpa, key, StringIndexAdapter{
        .bytes = string_bytes,
    }, StringIndexContext{
        .bytes = string_bytes,
    });
    if (gop.found_existing) {
        string_bytes.shrink_retaining_capacity(str_index);
        return .{
            .index = @enumFromInt(gop.key_ptr.*),
            .len = @int_cast(key.len),
        };
    } else {
        gop.key_ptr.* = str_index;
        // Still need a null byte because we are using the same table
        // to lookup null terminated strings, so if we get a match, it has to
        // be null terminated for that to work.
        try string_bytes.append(gpa, 0);
        return .{
            .index = @enumFromInt(str_index),
            .len = @int_cast(key.len),
        };
    }
}

fn str_lit_node_as_string(astgen: *AstGen, node: Ast.Node.Index) !IndexSlice {
    const tree = astgen.tree;
    const node_datas = tree.nodes.items(.data);

    const start = node_datas[node].lhs;
    const end = node_datas[node].rhs;

    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const str_index = string_bytes.items.len;

    // First line: do not append a newline.
    var tok_i = start;
    {
        const slice = tree.token_slice(tok_i);
        const carriage_return_ending: usize = if (slice[slice.len - 2] == '\r') 2 else 1;
        const line_bytes = slice[2 .. slice.len - carriage_return_ending];
        try string_bytes.append_slice(gpa, line_bytes);
        tok_i += 1;
    }
    // Following lines: each line prepends a newline.
    while (tok_i <= end) : (tok_i += 1) {
        const slice = tree.token_slice(tok_i);
        const carriage_return_ending: usize = if (slice[slice.len - 2] == '\r') 2 else 1;
        const line_bytes = slice[2 .. slice.len - carriage_return_ending];
        try string_bytes.ensure_unused_capacity(gpa, line_bytes.len + 1);
        string_bytes.append_assume_capacity('\n');
        string_bytes.append_slice_assume_capacity(line_bytes);
    }
    const len = string_bytes.items.len - str_index;
    try string_bytes.append(gpa, 0);
    return IndexSlice{
        .index = @enumFromInt(str_index),
        .len = @int_cast(len),
    };
}

fn test_name_string(astgen: *AstGen, str_lit_token: Ast.TokenIndex) !Zir.NullTerminatedString {
    const gpa = astgen.gpa;
    const string_bytes = &astgen.string_bytes;
    const str_index: u32 = @int_cast(string_bytes.items.len);
    const token_bytes = astgen.tree.token_slice(str_lit_token);
    try string_bytes.append(gpa, 0); // Indicates this is a test.
    try astgen.parse_str_lit(str_lit_token, string_bytes, token_bytes, 0);
    const slice = string_bytes.items[str_index + 1 ..];
    if (mem.index_of_scalar(u8, slice, 0) != null) {
        return astgen.fail_tok(str_lit_token, "test name cannot contain null bytes", .{});
    } else if (slice.len == 0) {
        return astgen.fail_tok(str_lit_token, "empty test name must be omitted", .{});
    }
    try string_bytes.append(gpa, 0);
    return @enumFromInt(str_index);
}

const Scope = struct {
    tag: Tag,

    fn cast(base: *Scope, comptime T: type) ?*T {
        if (T == Defer) {
            switch (base.tag) {
                .defer_normal, .defer_error => return @align_cast(@fieldParentPtr("base", base)),
                else => return null,
            }
        }
        if (T == Namespace) {
            switch (base.tag) {
                .namespace => return @align_cast(@fieldParentPtr("base", base)),
                else => return null,
            }
        }
        if (base.tag != T.base_tag)
            return null;

        return @align_cast(@fieldParentPtr("base", base));
    }

    fn parent(base: *Scope) ?*Scope {
        return switch (base.tag) {
            .gen_zir => base.cast(GenZir).?.parent,
            .local_val => base.cast(LocalVal).?.parent,
            .local_ptr => base.cast(LocalPtr).?.parent,
            .defer_normal, .defer_error => base.cast(Defer).?.parent,
            .namespace => base.cast(Namespace).?.parent,
            .top => null,
        };
    }

    const Tag = enum {
        gen_zir,
        local_val,
        local_ptr,
        defer_normal,
        defer_error,
        namespace,
        top,
    };

    /// The category of identifier. These tag names are user-visible in compile errors.
    const IdCat = enum {
        @"function parameter",
        @"local constant",
        @"local variable",
        @"switch tag capture",
        capture,
    };

    /// This is always a `const` local and importantly the `inst` is a value type, not a pointer.
    /// This structure lives as long as the AST generation of the Block
    /// node that contains the variable.
    const LocalVal = struct {
        const base_tag: Tag = .local_val;
        base: Scope = Scope{ .tag = base_tag },
        /// Parents can be: `LocalVal`, `LocalPtr`, `GenZir`, `Defer`, `Namespace`.
        parent: *Scope,
        gen_zir: *GenZir,
        inst: Zir.Inst.Ref,
        /// Source location of the corresponding variable declaration.
        token_src: Ast.TokenIndex,
        /// Track the first identifer where it is referenced.
        /// 0 means never referenced.
        used: Ast.TokenIndex = 0,
        /// Track the identifier where it is discarded, like this `_ = foo;`.
        /// 0 means never discarded.
        discarded: Ast.TokenIndex = 0,
        /// String table index.
        name: Zir.NullTerminatedString,
        id_cat: IdCat,
    };

    /// This could be a `const` or `var` local. It has a pointer instead of a value.
    /// This structure lives as long as the AST generation of the Block
    /// node that contains the variable.
    const LocalPtr = struct {
        const base_tag: Tag = .local_ptr;
        base: Scope = Scope{ .tag = base_tag },
        /// Parents can be: `LocalVal`, `LocalPtr`, `GenZir`, `Defer`, `Namespace`.
        parent: *Scope,
        gen_zir: *GenZir,
        ptr: Zir.Inst.Ref,
        /// Source location of the corresponding variable declaration.
        token_src: Ast.TokenIndex,
        /// Track the first identifer where it is referenced.
        /// 0 means never referenced.
        used: Ast.TokenIndex = 0,
        /// Track the identifier where it is discarded, like this `_ = foo;`.
        /// 0 means never discarded.
        discarded: Ast.TokenIndex = 0,
        /// Whether this value is used as an lvalue after inititialization.
        /// If not, we know it can be `const`, so will emit a compile error if it is `var`.
        used_as_lvalue: bool = false,
        /// String table index.
        name: Zir.NullTerminatedString,
        id_cat: IdCat,
        /// true means we find out during Sema whether the value is comptime.
        /// false means it is already known at AstGen the value is runtime-known.
        maybe_comptime: bool,
    };

    const Defer = struct {
        base: Scope,
        /// Parents can be: `LocalVal`, `LocalPtr`, `GenZir`, `Defer`, `Namespace`.
        parent: *Scope,
        index: u32,
        len: u32,
        remapped_err_code: Zir.Inst.OptionalIndex = .none,
    };

    /// Represents a global scope that has any number of declarations in it.
    /// Each declaration has this as the parent scope.
    const Namespace = struct {
        const base_tag: Tag = .namespace;
        base: Scope = Scope{ .tag = base_tag },

        /// Parents can be: `LocalVal`, `LocalPtr`, `GenZir`, `Defer`, `Namespace`.
        parent: *Scope,
        /// Maps string table index to the source location of declaration,
        /// for the purposes of reporting name shadowing compile errors.
        decls: std.AutoHashMapUnmanaged(Zir.NullTerminatedString, Ast.Node.Index) = .{},
        node: Ast.Node.Index,
        inst: Zir.Inst.Index,
        maybe_generic: bool,

        /// The astgen scope containing this namespace.
        /// Only valid during astgen.
        declaring_gz: ?*GenZir,

        /// Set of captures used by this namespace.
        captures: std.AutoArrayHashMapUnmanaged(Zir.Inst.Capture, void) = .{},

        fn deinit(self: *Namespace, gpa: Allocator) void {
            self.decls.deinit(gpa);
            self.captures.deinit(gpa);
            self.* = undefined;
        }
    };

    const Top = struct {
        const base_tag: Scope.Tag = .top;
        base: Scope = Scope{ .tag = base_tag },
    };
};

/// This is a temporary structure; references to it are valid only
/// while constructing a `Zir`.
const GenZir = struct {
    const base_tag: Scope.Tag = .gen_zir;
    base: Scope = Scope{ .tag = base_tag },
    /// Whether we're already in a scope known to be comptime. This is set
    /// whenever we know Sema will analyze the current block with `is_comptime`,
    /// for instance when we're within a `struct_decl` or a `block_comptime`.
    is_comptime: bool,
    /// Whether we're in an expression within a `@TypeOf` operand. In this case, closure of runtime
    /// variables is permitted where it is usually not.
    is_typeof: bool = false,
    /// This is set to true for a `GenZir` of a `block_inline`, indicating that
    /// exits from this block should use `break_inline` rather than `break`.
    is_inline: bool = false,
    c_import: bool = false,
    /// How decls created in this scope should be named.
    anon_name_strategy: Zir.Inst.NameStrategy = .anon,
    /// The containing decl AST node.
    decl_node_index: Ast.Node.Index,
    /// The containing decl line index, absolute.
    decl_line: u32,
    /// Parents can be: `LocalVal`, `LocalPtr`, `GenZir`, `Defer`, `Namespace`.
    parent: *Scope,
    /// All `GenZir` scopes for the same ZIR share this.
    astgen: *AstGen,
    /// Keeps track of the list of instructions in this scope. Possibly shared.
    /// Indexes to instructions in `astgen`.
    instructions: *ArrayListUnmanaged(Zir.Inst.Index),
    /// A sub-block may share its instructions ArrayList with containing GenZir,
    /// if use is strictly nested. This saves prior size of list for unstacking.
    instructions_top: usize,
    label: ?Label = null,
    break_block: Zir.Inst.OptionalIndex = .none,
    continue_block: Zir.Inst.OptionalIndex = .none,
    /// Only valid when set_break_result_info is called.
    break_result_info: AstGen.ResultInfo = undefined,

    suspend_node: Ast.Node.Index = 0,
    nosuspend_node: Ast.Node.Index = 0,
    /// Set if this GenZir is a defer.
    cur_defer_node: Ast.Node.Index = 0,
    // Set if this GenZir is a defer or it is inside a defer.
    any_defer_node: Ast.Node.Index = 0,

    const unstacked_top = std.math.max_int(usize);
    /// Call unstack before adding any new instructions to containing GenZir.
    fn unstack(self: *GenZir) void {
        if (self.instructions_top != unstacked_top) {
            self.instructions.items.len = self.instructions_top;
            self.instructions_top = unstacked_top;
        }
    }

    fn is_empty(self: *const GenZir) bool {
        return (self.instructions_top == unstacked_top) or
            (self.instructions.items.len == self.instructions_top);
    }

    fn instructions_slice(self: *const GenZir) []Zir.Inst.Index {
        return if (self.instructions_top == unstacked_top)
            &[0]Zir.Inst.Index{}
        else
            self.instructions.items[self.instructions_top..];
    }

    fn instructions_slice_upto(self: *const GenZir, stacked_gz: *GenZir) []Zir.Inst.Index {
        return if (self.instructions_top == unstacked_top)
            &[0]Zir.Inst.Index{}
        else if (self.instructions == stacked_gz.instructions and stacked_gz.instructions_top != unstacked_top)
            self.instructions.items[self.instructions_top..stacked_gz.instructions_top]
        else
            self.instructions.items[self.instructions_top..];
    }

    fn make_sub_block(gz: *GenZir, scope: *Scope) GenZir {
        return .{
            .is_comptime = gz.is_comptime,
            .is_typeof = gz.is_typeof,
            .c_import = gz.c_import,
            .decl_node_index = gz.decl_node_index,
            .decl_line = gz.decl_line,
            .parent = scope,
            .astgen = gz.astgen,
            .suspend_node = gz.suspend_node,
            .nosuspend_node = gz.nosuspend_node,
            .any_defer_node = gz.any_defer_node,
            .instructions = gz.instructions,
            .instructions_top = gz.instructions.items.len,
        };
    }

    const Label = struct {
        token: Ast.TokenIndex,
        block_inst: Zir.Inst.Index,
        used: bool = false,
    };

    /// Assumes nothing stacked on `gz`.
    fn ends_with_no_return(gz: GenZir) bool {
        if (gz.is_empty()) return false;
        const tags = gz.astgen.instructions.items(.tag);
        const last_inst = gz.instructions.items[gz.instructions.items.len - 1];
        return tags[@int_from_enum(last_inst)].is_no_return();
    }

    /// TODO all uses of this should be replaced with uses of `ends_with_no_return`.
    fn ref_is_no_return(gz: GenZir, inst_ref: Zir.Inst.Ref) bool {
        if (inst_ref == .unreachable_value) return true;
        if (inst_ref.to_index()) |inst_index| {
            return gz.astgen.instructions.items(.tag)[@int_from_enum(inst_index)].is_no_return();
        }
        return false;
    }

    fn node_index_to_relative(gz: GenZir, node_index: Ast.Node.Index) i32 {
        return @as(i32, @bit_cast(node_index)) - @as(i32, @bit_cast(gz.decl_node_index));
    }

    fn token_index_to_relative(gz: GenZir, token: Ast.TokenIndex) u32 {
        return token - gz.src_token();
    }

    fn src_token(gz: GenZir) Ast.TokenIndex {
        return gz.astgen.tree.first_token(gz.decl_node_index);
    }

    fn set_break_result_info(gz: *GenZir, parent_ri: AstGen.ResultInfo) void {
        // Depending on whether the result location is a pointer or value, different
        // ZIR needs to be generated. In the former case we rely on storing to the
        // pointer to communicate the result, and use breakvoid; in the latter case
        // the block break instructions will have the result values.
        switch (parent_ri.rl) {
            .coerced_ty => |ty_inst| {
                // Type coercion needs to happen before breaks.
                gz.break_result_info = .{ .rl = .{ .ty = ty_inst }, .ctx = parent_ri.ctx };
            },
            .discard => {
                // We don't forward the result context here. This prevents
                // "unnecessary discard" errors from being caused by expressions
                // far from the actual discard, such as a `break` from a
                // discarded block.
                gz.break_result_info = .{ .rl = .discard };
            },
            else => {
                gz.break_result_info = parent_ri;
            },
        }
    }

    /// Assumes nothing stacked on `gz`. Unstacks `gz`.
    fn set_bool_br_body(gz: *GenZir, bool_br: Zir.Inst.Index, bool_br_lhs: Zir.Inst.Ref) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;
        const body = gz.instructions_slice();
        const body_len = astgen.count_body_len_after_fixups(body);
        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.BoolBr).Struct.fields.len + body_len,
        );
        const zir_datas = astgen.instructions.items(.data);
        zir_datas[@int_from_enum(bool_br)].pl_node.payload_index = astgen.add_extra_assume_capacity(Zir.Inst.BoolBr{
            .lhs = bool_br_lhs,
            .body_len = body_len,
        });
        astgen.append_body_with_fixups(body);
        gz.unstack();
    }

    /// Assumes nothing stacked on `gz`. Unstacks `gz`.
    fn set_block_body(gz: *GenZir, inst: Zir.Inst.Index) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;
        const body = gz.instructions_slice();
        const body_len = astgen.count_body_len_after_fixups(body);
        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.Block).Struct.fields.len + body_len,
        );
        const zir_datas = astgen.instructions.items(.data);
        zir_datas[@int_from_enum(inst)].pl_node.payload_index = astgen.add_extra_assume_capacity(
            Zir.Inst.Block{ .body_len = body_len },
        );
        astgen.append_body_with_fixups(body);
        gz.unstack();
    }

    /// Assumes nothing stacked on `gz`. Unstacks `gz`.
    fn set_try_body(gz: *GenZir, inst: Zir.Inst.Index, operand: Zir.Inst.Ref) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;
        const body = gz.instructions_slice();
        const body_len = astgen.count_body_len_after_fixups(body);
        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.Try).Struct.fields.len + body_len,
        );
        const zir_datas = astgen.instructions.items(.data);
        zir_datas[@int_from_enum(inst)].pl_node.payload_index = astgen.add_extra_assume_capacity(
            Zir.Inst.Try{
                .operand = operand,
                .body_len = body_len,
            },
        );
        astgen.append_body_with_fixups(body);
        gz.unstack();
    }

    /// Must be called with the following stack set up:
    ///  * gz (bottom)
    ///  * align_gz
    ///  * addrspace_gz
    ///  * section_gz
    ///  * cc_gz
    ///  * ret_gz
    ///  * body_gz (top)
    /// Unstacks all of those except for `gz`.
    fn add_func(gz: *GenZir, args: struct {
        src_node: Ast.Node.Index,
        lbrace_line: u32 = 0,
        lbrace_column: u32 = 0,
        param_block: Zir.Inst.Index,

        align_gz: ?*GenZir,
        addrspace_gz: ?*GenZir,
        section_gz: ?*GenZir,
        cc_gz: ?*GenZir,
        ret_gz: ?*GenZir,
        body_gz: ?*GenZir,

        align_ref: Zir.Inst.Ref,
        addrspace_ref: Zir.Inst.Ref,
        section_ref: Zir.Inst.Ref,
        cc_ref: Zir.Inst.Ref,
        ret_ref: Zir.Inst.Ref,

        lib_name: Zir.NullTerminatedString,
        noalias_bits: u32,
        is_var_args: bool,
        is_inferred_error: bool,
        is_test: bool,
        is_extern: bool,
        is_noinline: bool,
    }) !Zir.Inst.Ref {
        assert(args.src_node != 0);
        const astgen = gz.astgen;
        const gpa = astgen.gpa;
        const ret_ref = if (args.ret_ref == .void_type) .none else args.ret_ref;
        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);

        try astgen.instructions.ensure_unused_capacity(gpa, 1);

        var body: []Zir.Inst.Index = &[0]Zir.Inst.Index{};
        var ret_body: []Zir.Inst.Index = &[0]Zir.Inst.Index{};
        var src_locs_and_hash_buffer: [7]u32 = undefined;
        var src_locs_and_hash: []u32 = src_locs_and_hash_buffer[0..0];
        if (args.body_gz) |body_gz| {
            const tree = astgen.tree;
            const node_tags = tree.nodes.items(.tag);
            const node_datas = tree.nodes.items(.data);
            const token_starts = tree.tokens.items(.start);
            const fn_decl = args.src_node;
            assert(node_tags[fn_decl] == .fn_decl or node_tags[fn_decl] == .test_decl);
            const block = node_datas[fn_decl].rhs;
            const rbrace_start = token_starts[tree.last_token(block)];
            astgen.advance_source_cursor(rbrace_start);
            const rbrace_line: u32 = @int_cast(astgen.source_line - gz.decl_line);
            const rbrace_column: u32 = @int_cast(astgen.source_column);

            const columns = args.lbrace_column | (rbrace_column << 16);

            const proto_hash: std.zig.SrcHash = switch (node_tags[fn_decl]) {
                .fn_decl => sig_hash: {
                    const proto_node = node_datas[fn_decl].lhs;
                    break :sig_hash std.zig.hash_src(tree.get_node_source(proto_node));
                },
                .test_decl => std.zig.hash_src(""), // tests don't have a prototype
                else => unreachable,
            };
            const proto_hash_arr: [4]u32 = @bit_cast(proto_hash);

            src_locs_and_hash_buffer = .{
                args.lbrace_line,
                rbrace_line,
                columns,
                proto_hash_arr[0],
                proto_hash_arr[1],
                proto_hash_arr[2],
                proto_hash_arr[3],
            };
            src_locs_and_hash = &src_locs_and_hash_buffer;

            body = body_gz.instructions_slice();
            if (args.ret_gz) |ret_gz|
                ret_body = ret_gz.instructions_slice_upto(body_gz);
        } else {
            if (args.ret_gz) |ret_gz|
                ret_body = ret_gz.instructions_slice();
        }
        const body_len = astgen.count_body_len_after_fixups(body);

        if (args.cc_ref != .none or args.lib_name != .empty or args.is_var_args or args.is_test or
            args.is_extern or args.align_ref != .none or args.section_ref != .none or
            args.addrspace_ref != .none or args.noalias_bits != 0 or args.is_noinline)
        {
            var align_body: []Zir.Inst.Index = &.{};
            var addrspace_body: []Zir.Inst.Index = &.{};
            var section_body: []Zir.Inst.Index = &.{};
            var cc_body: []Zir.Inst.Index = &.{};
            if (args.ret_gz != null) {
                align_body = args.align_gz.?.instructions_slice_upto(args.addrspace_gz.?);
                addrspace_body = args.addrspace_gz.?.instructions_slice_upto(args.section_gz.?);
                section_body = args.section_gz.?.instructions_slice_upto(args.cc_gz.?);
                cc_body = args.cc_gz.?.instructions_slice_upto(args.ret_gz.?);
            }

            try astgen.extra.ensure_unused_capacity(
                gpa,
                @typeInfo(Zir.Inst.FuncFancy).Struct.fields.len +
                    fancy_fn_expr_extra_len(astgen, align_body, args.align_ref) +
                    fancy_fn_expr_extra_len(astgen, addrspace_body, args.addrspace_ref) +
                    fancy_fn_expr_extra_len(astgen, section_body, args.section_ref) +
                    fancy_fn_expr_extra_len(astgen, cc_body, args.cc_ref) +
                    fancy_fn_expr_extra_len(astgen, ret_body, ret_ref) +
                    body_len + src_locs_and_hash.len +
                    @int_from_bool(args.lib_name != .empty) +
                    @int_from_bool(args.noalias_bits != 0),
            );
            const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.FuncFancy{
                .param_block = args.param_block,
                .body_len = body_len,
                .bits = .{
                    .is_var_args = args.is_var_args,
                    .is_inferred_error = args.is_inferred_error,
                    .is_test = args.is_test,
                    .is_extern = args.is_extern,
                    .is_noinline = args.is_noinline,
                    .has_lib_name = args.lib_name != .empty,
                    .has_any_noalias = args.noalias_bits != 0,

                    .has_align_ref = args.align_ref != .none,
                    .has_addrspace_ref = args.addrspace_ref != .none,
                    .has_section_ref = args.section_ref != .none,
                    .has_cc_ref = args.cc_ref != .none,
                    .has_ret_ty_ref = ret_ref != .none,

                    .has_align_body = align_body.len != 0,
                    .has_addrspace_body = addrspace_body.len != 0,
                    .has_section_body = section_body.len != 0,
                    .has_cc_body = cc_body.len != 0,
                    .has_ret_ty_body = ret_body.len != 0,
                },
            });
            if (args.lib_name != .empty) {
                astgen.extra.append_assume_capacity(@int_from_enum(args.lib_name));
            }

            const zir_datas = astgen.instructions.items(.data);
            if (align_body.len != 0) {
                astgen.extra.append_assume_capacity(count_body_len_after_fixups(astgen, align_body));
                astgen.append_body_with_fixups(align_body);
                const break_extra = zir_datas[@int_from_enum(align_body[align_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (args.align_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(args.align_ref));
            }
            if (addrspace_body.len != 0) {
                astgen.extra.append_assume_capacity(count_body_len_after_fixups(astgen, addrspace_body));
                astgen.append_body_with_fixups(addrspace_body);
                const break_extra =
                    zir_datas[@int_from_enum(addrspace_body[addrspace_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (args.addrspace_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(args.addrspace_ref));
            }
            if (section_body.len != 0) {
                astgen.extra.append_assume_capacity(count_body_len_after_fixups(astgen, section_body));
                astgen.append_body_with_fixups(section_body);
                const break_extra =
                    zir_datas[@int_from_enum(section_body[section_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (args.section_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(args.section_ref));
            }
            if (cc_body.len != 0) {
                astgen.extra.append_assume_capacity(count_body_len_after_fixups(astgen, cc_body));
                astgen.append_body_with_fixups(cc_body);
                const break_extra = zir_datas[@int_from_enum(cc_body[cc_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (args.cc_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(args.cc_ref));
            }
            if (ret_body.len != 0) {
                astgen.extra.append_assume_capacity(count_body_len_after_fixups(astgen, ret_body));
                astgen.append_body_with_fixups(ret_body);
                const break_extra = zir_datas[@int_from_enum(ret_body[ret_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (ret_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(ret_ref));
            }

            if (args.noalias_bits != 0) {
                astgen.extra.append_assume_capacity(args.noalias_bits);
            }

            astgen.append_body_with_fixups(body);
            astgen.extra.append_slice_assume_capacity(src_locs_and_hash);

            // Order is important when unstacking.
            if (args.body_gz) |body_gz| body_gz.unstack();
            if (args.ret_gz != null) {
                args.ret_gz.?.unstack();
                args.cc_gz.?.unstack();
                args.section_gz.?.unstack();
                args.addrspace_gz.?.unstack();
                args.align_gz.?.unstack();
            }

            try gz.instructions.ensure_unused_capacity(gpa, 1);

            astgen.instructions.append_assume_capacity(.{
                .tag = .func_fancy,
                .data = .{ .pl_node = .{
                    .src_node = gz.node_index_to_relative(args.src_node),
                    .payload_index = payload_index,
                } },
            });
            gz.instructions.append_assume_capacity(new_index);
            return new_index.to_ref();
        } else {
            try astgen.extra.ensure_unused_capacity(
                gpa,
                @typeInfo(Zir.Inst.Func).Struct.fields.len + 1 +
                    fancy_fn_expr_extra_len(astgen, ret_body, ret_ref) +
                    body_len + src_locs_and_hash.len,
            );

            const ret_body_len = if (ret_body.len != 0)
                count_body_len_after_fixups(astgen, ret_body)
            else
                @int_from_bool(ret_ref != .none);

            const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.Func{
                .param_block = args.param_block,
                .ret_body_len = ret_body_len,
                .body_len = body_len,
            });
            const zir_datas = astgen.instructions.items(.data);
            if (ret_body.len != 0) {
                astgen.append_body_with_fixups(ret_body);

                const break_extra = zir_datas[@int_from_enum(ret_body[ret_body.len - 1])].@"break".payload_index;
                astgen.extra.items[break_extra + std.meta.field_index(Zir.Inst.Break, "block_inst").?] =
                    @int_from_enum(new_index);
            } else if (ret_ref != .none) {
                astgen.extra.append_assume_capacity(@int_from_enum(ret_ref));
            }
            astgen.append_body_with_fixups(body);
            astgen.extra.append_slice_assume_capacity(src_locs_and_hash);

            // Order is important when unstacking.
            if (args.body_gz) |body_gz| body_gz.unstack();
            if (args.ret_gz) |ret_gz| ret_gz.unstack();
            if (args.cc_gz) |cc_gz| cc_gz.unstack();
            if (args.section_gz) |section_gz| section_gz.unstack();
            if (args.addrspace_gz) |addrspace_gz| addrspace_gz.unstack();
            if (args.align_gz) |align_gz| align_gz.unstack();

            try gz.instructions.ensure_unused_capacity(gpa, 1);

            const tag: Zir.Inst.Tag = if (args.is_inferred_error) .func_inferred else .func;
            astgen.instructions.append_assume_capacity(.{
                .tag = tag,
                .data = .{ .pl_node = .{
                    .src_node = gz.node_index_to_relative(args.src_node),
                    .payload_index = payload_index,
                } },
            });
            gz.instructions.append_assume_capacity(new_index);
            return new_index.to_ref();
        }
    }

    fn fancy_fn_expr_extra_len(astgen: *AstGen, body: []Zir.Inst.Index, ref: Zir.Inst.Ref) u32 {
        // In the case of non-empty body, there is one for the body length,
        // and then one for each instruction.
        return count_body_len_after_fixups(astgen, body) + @int_from_bool(ref != .none);
    }

    fn add_var(gz: *GenZir, args: struct {
        align_inst: Zir.Inst.Ref,
        lib_name: Zir.NullTerminatedString,
        var_type: Zir.Inst.Ref,
        init: Zir.Inst.Ref,
        is_extern: bool,
        is_const: bool,
        is_threadlocal: bool,
    }) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);

        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.ExtendedVar).Struct.fields.len +
                @int_from_bool(args.lib_name != .empty) +
                @int_from_bool(args.align_inst != .none) +
                @int_from_bool(args.init != .none),
        );
        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.ExtendedVar{
            .var_type = args.var_type,
        });
        if (args.lib_name != .empty) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.lib_name));
        }
        if (args.align_inst != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.align_inst));
        }
        if (args.init != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.init));
        }

        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .variable,
                .small = @bit_cast(Zir.Inst.ExtendedVar.Small{
                    .has_lib_name = args.lib_name != .empty,
                    .has_align = args.align_inst != .none,
                    .has_init = args.init != .none,
                    .is_extern = args.is_extern,
                    .is_const = args.is_const,
                    .is_threadlocal = args.is_threadlocal,
                }),
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_int(gz: *GenZir, integer: u64) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = .int,
            .data = .{ .int = integer },
        });
    }

    fn add_int_big(gz: *GenZir, limbs: []const std.math.big.Limb) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.string_bytes.ensure_unused_capacity(gpa, @size_of(std.math.big.Limb) * limbs.len);

        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .int_big,
            .data = .{ .str = .{
                .start = @enumFromInt(astgen.string_bytes.items.len),
                .len = @int_cast(limbs.len),
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        astgen.string_bytes.append_slice_assume_capacity(mem.slice_as_bytes(limbs));
        return new_index.to_ref();
    }

    fn add_float(gz: *GenZir, number: f64) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = .float,
            .data = .{ .float = number },
        });
    }

    fn add_un_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        operand: Zir.Inst.Ref,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Ref {
        assert(operand != .none);
        return gz.add(.{
            .tag = tag,
            .data = .{ .un_node = .{
                .operand = operand,
                .src_node = gz.node_index_to_relative(src_node),
            } },
        });
    }

    fn make_un_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        operand: Zir.Inst.Ref,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Index {
        assert(operand != .none);
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        try gz.astgen.instructions.append(gz.astgen.gpa, .{
            .tag = tag,
            .data = .{ .un_node = .{
                .operand = operand,
                .src_node = gz.node_index_to_relative(src_node),
            } },
        });
        return new_index;
    }

    fn add_pl_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
        extra: anytype,
    ) !Zir.Inst.Ref {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

        const payload_index = try gz.astgen.add_extra(extra);
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.append_assume_capacity(.{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.node_index_to_relative(src_node),
                .payload_index = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_pl_node_payload_index(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
        payload_index: u32,
    ) !Zir.Inst.Ref {
        return try gz.add(.{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.node_index_to_relative(src_node),
                .payload_index = payload_index,
            } },
        });
    }

    /// Supports `param_gz` stacked on `gz`. Assumes nothing stacked on `param_gz`. Unstacks `param_gz`.
    fn add_param(
        gz: *GenZir,
        param_gz: *GenZir,
        tag: Zir.Inst.Tag,
        /// Absolute token index. This function does the conversion to Decl offset.
        abs_tok_index: Ast.TokenIndex,
        name: Zir.NullTerminatedString,
        first_doc_comment: ?Ast.TokenIndex,
    ) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        const param_body = param_gz.instructions_slice();
        const body_len = gz.astgen.count_body_len_after_fixups(param_body);
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.Param).Struct.fields.len + body_len);

        const doc_comment_index = if (first_doc_comment) |first|
            try gz.astgen.doc_comment_as_string_from_first(abs_tok_index, first)
        else
            .empty;

        const payload_index = gz.astgen.add_extra_assume_capacity(Zir.Inst.Param{
            .name = name,
            .doc_comment = doc_comment_index,
            .body_len = @int_cast(body_len),
        });
        gz.astgen.append_body_with_fixups(param_body);
        param_gz.unstack();

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.append_assume_capacity(.{
            .tag = tag,
            .data = .{ .pl_tok = .{
                .src_tok = gz.token_index_to_relative(abs_tok_index),
                .payload_index = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn add_extended_payload(gz: *GenZir, opcode: Zir.Inst.Extended, extra: anytype) !Zir.Inst.Ref {
        return add_extended_payload_small(gz, opcode, undefined, extra);
    }

    fn add_extended_payload_small(
        gz: *GenZir,
        opcode: Zir.Inst.Extended,
        small: u16,
        extra: anytype,
    ) !Zir.Inst.Ref {
        const gpa = gz.astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

        const payload_index = try gz.astgen.add_extra(extra);
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = opcode,
                .small = small,
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_extended_multi_op(
        gz: *GenZir,
        opcode: Zir.Inst.Extended,
        node: Ast.Node.Index,
        operands: []const Zir.Inst.Ref,
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.NodeMultiOp).Struct.fields.len + operands.len,
        );

        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.NodeMultiOp{
            .src_node = gz.node_index_to_relative(node),
        });
        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = opcode,
                .small = @int_cast(operands.len),
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        astgen.append_refs_assume_capacity(operands);
        return new_index.to_ref();
    }

    fn add_extended_multi_op_payload_index(
        gz: *GenZir,
        opcode: Zir.Inst.Extended,
        payload_index: u32,
        trailing_len: usize,
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = opcode,
                .small = @int_cast(trailing_len),
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_extended_node_small(
        gz: *GenZir,
        opcode: Zir.Inst.Extended,
        src_node: Ast.Node.Index,
        small: u16,
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = opcode,
                .small = small,
                .operand = @bit_cast(gz.node_index_to_relative(src_node)),
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_un_tok(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        operand: Zir.Inst.Ref,
        /// Absolute token index. This function does the conversion to Decl offset.
        abs_tok_index: Ast.TokenIndex,
    ) !Zir.Inst.Ref {
        assert(operand != .none);
        return gz.add(.{
            .tag = tag,
            .data = .{ .un_tok = .{
                .operand = operand,
                .src_tok = gz.token_index_to_relative(abs_tok_index),
            } },
        });
    }

    fn make_un_tok(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        operand: Zir.Inst.Ref,
        /// Absolute token index. This function does the conversion to Decl offset.
        abs_tok_index: Ast.TokenIndex,
    ) !Zir.Inst.Index {
        const astgen = gz.astgen;
        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        assert(operand != .none);
        try astgen.instructions.append(astgen.gpa, .{
            .tag = tag,
            .data = .{ .un_tok = .{
                .operand = operand,
                .src_tok = gz.token_index_to_relative(abs_tok_index),
            } },
        });
        return new_index;
    }

    fn add_str_tok(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        str_index: Zir.NullTerminatedString,
        /// Absolute token index. This function does the conversion to Decl offset.
        abs_tok_index: Ast.TokenIndex,
    ) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = tag,
            .data = .{ .str_tok = .{
                .start = str_index,
                .src_tok = gz.token_index_to_relative(abs_tok_index),
            } },
        });
    }

    fn add_save_err_ret_index(
        gz: *GenZir,
        cond: union(enum) {
            always: void,
            if_of_error_type: Zir.Inst.Ref,
        },
    ) !Zir.Inst.Index {
        return gz.add_as_index(.{
            .tag = .save_err_ret_index,
            .data = .{ .save_err_ret_index = .{
                .operand = switch (cond) {
                    .if_of_error_type => |x| x,
                    else => .none,
                },
            } },
        });
    }

    const BranchTarget = union(enum) {
        ret,
        block: Zir.Inst.Index,
    };

    fn add_restore_err_ret_index(
        gz: *GenZir,
        bt: BranchTarget,
        cond: union(enum) {
            always: void,
            if_non_error: Zir.Inst.Ref,
        },
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Index {
        switch (cond) {
            .always => return gz.add_as_index(.{
                .tag = .restore_err_ret_index_unconditional,
                .data = .{ .un_node = .{
                    .operand = switch (bt) {
                        .ret => .none,
                        .block => |b| b.to_ref(),
                    },
                    .src_node = gz.node_index_to_relative(src_node),
                } },
            }),
            .if_non_error => |operand| switch (bt) {
                .ret => return gz.add_as_index(.{
                    .tag = .restore_err_ret_index_fn_entry,
                    .data = .{ .un_node = .{
                        .operand = operand,
                        .src_node = gz.node_index_to_relative(src_node),
                    } },
                }),
                .block => |block| return (try gz.add_extended_payload(
                    .restore_err_ret_index,
                    Zir.Inst.RestoreErrRetIndex{
                        .src_node = gz.node_index_to_relative(src_node),
                        .block = block.to_ref(),
                        .operand = operand,
                    },
                )).to_index().?,
            },
        }
    }

    fn add_break(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        block_inst: Zir.Inst.Index,
        operand: Zir.Inst.Ref,
    ) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);

        const new_index = try gz.make_break(tag, block_inst, operand);
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn make_break(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        block_inst: Zir.Inst.Index,
        operand: Zir.Inst.Ref,
    ) !Zir.Inst.Index {
        return gz.make_break_common(tag, block_inst, operand, null);
    }

    fn add_break_with_src_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        block_inst: Zir.Inst.Index,
        operand: Zir.Inst.Ref,
        operand_src_node: Ast.Node.Index,
    ) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);

        const new_index = try gz.make_break_with_src_node(tag, block_inst, operand, operand_src_node);
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn make_break_with_src_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        block_inst: Zir.Inst.Index,
        operand: Zir.Inst.Ref,
        operand_src_node: Ast.Node.Index,
    ) !Zir.Inst.Index {
        return gz.make_break_common(tag, block_inst, operand, operand_src_node);
    }

    fn make_break_common(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        block_inst: Zir.Inst.Index,
        operand: Zir.Inst.Ref,
        operand_src_node: ?Ast.Node.Index,
    ) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.Break).Struct.fields.len);

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.append_assume_capacity(.{
            .tag = tag,
            .data = .{ .@"break" = .{
                .operand = operand,
                .payload_index = gz.astgen.add_extra_assume_capacity(Zir.Inst.Break{
                    .operand_src_node = if (operand_src_node) |src_node|
                        gz.node_index_to_relative(src_node)
                    else
                        Zir.Inst.Break.no_src_node,
                    .block_inst = block_inst,
                }),
            } },
        });
        return new_index;
    }

    fn add_bin(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        lhs: Zir.Inst.Ref,
        rhs: Zir.Inst.Ref,
    ) !Zir.Inst.Ref {
        assert(lhs != .none);
        assert(rhs != .none);
        return gz.add(.{
            .tag = tag,
            .data = .{ .bin = .{
                .lhs = lhs,
                .rhs = rhs,
            } },
        });
    }

    fn add_defer(gz: *GenZir, index: u32, len: u32) !void {
        _ = try gz.add(.{
            .tag = .@"defer",
            .data = .{ .@"defer" = .{
                .index = index,
                .len = len,
            } },
        });
    }

    fn add_decl(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        decl_index: u32,
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.node_index_to_relative(src_node),
                .payload_index = decl_index,
            } },
        });
    }

    fn add_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = tag,
            .data = .{ .node = gz.node_index_to_relative(src_node) },
        });
    }

    fn add_inst_node(
        gz: *GenZir,
        tag: Zir.Inst.Tag,
        inst: Zir.Inst.Index,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = tag,
            .data = .{ .inst_node = .{
                .inst = inst,
                .src_node = gz.node_index_to_relative(src_node),
            } },
        });
    }

    fn add_node_extended(
        gz: *GenZir,
        opcode: Zir.Inst.Extended,
        /// Absolute node index. This function does the conversion to offset from Decl.
        src_node: Ast.Node.Index,
    ) !Zir.Inst.Ref {
        return gz.add(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = opcode,
                .small = undefined,
                .operand = @bit_cast(gz.node_index_to_relative(src_node)),
            } },
        });
    }

    fn add_alloc_extended(
        gz: *GenZir,
        args: struct {
            /// Absolute node index. This function does the conversion to offset from Decl.
            node: Ast.Node.Index,
            type_inst: Zir.Inst.Ref,
            align_inst: Zir.Inst.Ref,
            is_const: bool,
            is_comptime: bool,
        },
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.extra.ensure_unused_capacity(
            gpa,
            @typeInfo(Zir.Inst.AllocExtended).Struct.fields.len +
                @int_from_bool(args.type_inst != .none) +
                @int_from_bool(args.align_inst != .none),
        );
        const payload_index = gz.astgen.add_extra_assume_capacity(Zir.Inst.AllocExtended{
            .src_node = gz.node_index_to_relative(args.node),
        });
        if (args.type_inst != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.type_inst));
        }
        if (args.align_inst != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.align_inst));
        }

        const has_type: u4 = @int_from_bool(args.type_inst != .none);
        const has_align: u4 = @int_from_bool(args.align_inst != .none);
        const is_const: u4 = @int_from_bool(args.is_const);
        const is_comptime: u4 = @int_from_bool(args.is_comptime);
        const small: u16 = has_type | (has_align << 1) | (is_const << 2) | (is_comptime << 3);

        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .alloc,
                .small = small,
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    fn add_asm(
        gz: *GenZir,
        args: struct {
            tag: Zir.Inst.Extended,
            /// Absolute node index. This function does the conversion to offset from Decl.
            node: Ast.Node.Index,
            asm_source: Zir.NullTerminatedString,
            output_type_bits: u32,
            is_volatile: bool,
            outputs: []const Zir.Inst.Asm.Output,
            inputs: []const Zir.Inst.Asm.Input,
            clobbers: []const u32,
        },
    ) !Zir.Inst.Ref {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.instructions.ensure_unused_capacity(gpa, 1);
        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.Asm).Struct.fields.len +
            args.outputs.len * @typeInfo(Zir.Inst.Asm.Output).Struct.fields.len +
            args.inputs.len * @typeInfo(Zir.Inst.Asm.Input).Struct.fields.len +
            args.clobbers.len);

        const payload_index = gz.astgen.add_extra_assume_capacity(Zir.Inst.Asm{
            .src_node = gz.node_index_to_relative(args.node),
            .asm_source = args.asm_source,
            .output_type_bits = args.output_type_bits,
        });
        for (args.outputs) |output| {
            _ = gz.astgen.add_extra_assume_capacity(output);
        }
        for (args.inputs) |input| {
            _ = gz.astgen.add_extra_assume_capacity(input);
        }
        gz.astgen.extra.append_slice_assume_capacity(args.clobbers);

        //  * 0b00000000_000XXXXX - `outputs_len`.
        //  * 0b000000XX_XXX00000 - `inputs_len`.
        //  * 0b0XXXXX00_00000000 - `clobbers_len`.
        //  * 0bX0000000_00000000 - is volatile
        const small: u16 = @as(u16, @int_cast(args.outputs.len)) |
            @as(u16, @int_cast(args.inputs.len << 5)) |
            @as(u16, @int_cast(args.clobbers.len << 10)) |
            (@as(u16, @int_from_bool(args.is_volatile)) << 15);

        const new_index: Zir.Inst.Index = @enumFromInt(astgen.instructions.len);
        astgen.instructions.append_assume_capacity(.{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = args.tag,
                .small = small,
                .operand = payload_index,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index.to_ref();
    }

    /// Note that this returns a `Zir.Inst.Index` not a ref.
    /// Does *not* append the block instruction to the scope.
    /// Leaves the `payload_index` field undefined.
    fn make_block_inst(gz: *GenZir, tag: Zir.Inst.Tag, node: Ast.Node.Index) !Zir.Inst.Index {
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        const gpa = gz.astgen.gpa;
        try gz.astgen.instructions.append(gpa, .{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.node_index_to_relative(node),
                .payload_index = undefined,
            } },
        });
        return new_index;
    }

    /// Note that this returns a `Zir.Inst.Index` not a ref.
    /// Leaves the `payload_index` field undefined.
    fn add_cond_br(gz: *GenZir, tag: Zir.Inst.Tag, node: Ast.Node.Index) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);
        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        try gz.astgen.instructions.append(gpa, .{
            .tag = tag,
            .data = .{ .pl_node = .{
                .src_node = gz.node_index_to_relative(node),
                .payload_index = undefined,
            } },
        });
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn set_struct(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        captures_len: u32,
        fields_len: u32,
        decls_len: u32,
        has_backing_int: bool,
        layout: std.builtin.Type.ContainerLayout,
        known_non_opv: bool,
        known_comptime_only: bool,
        is_tuple: bool,
        any_comptime_fields: bool,
        any_default_inits: bool,
        any_aligned_fields: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        // Node 0 is valid for the root `struct_decl` of a file!
        assert(args.src_node != 0 or gz.parent.tag == .top);

        const fields_hash_arr: [4]u32 = @bit_cast(args.fields_hash);

        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.StructDecl).Struct.fields.len + 3);
        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.StructDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_node = gz.node_index_to_relative(args.src_node),
        });

        if (args.captures_len != 0) {
            astgen.extra.append_assume_capacity(args.captures_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.append_assume_capacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.append_assume_capacity(args.decls_len);
        }
        astgen.instructions.set(@int_from_enum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .struct_decl,
                .small = @bit_cast(Zir.Inst.StructDecl.Small{
                    .has_captures_len = args.captures_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .has_backing_int = args.has_backing_int,
                    .known_non_opv = args.known_non_opv,
                    .known_comptime_only = args.known_comptime_only,
                    .is_tuple = args.is_tuple,
                    .name_strategy = gz.anon_name_strategy,
                    .layout = args.layout,
                    .any_comptime_fields = args.any_comptime_fields,
                    .any_default_inits = args.any_default_inits,
                    .any_aligned_fields = args.any_aligned_fields,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn set_union(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        tag_type: Zir.Inst.Ref,
        captures_len: u32,
        body_len: u32,
        fields_len: u32,
        decls_len: u32,
        layout: std.builtin.Type.ContainerLayout,
        auto_enum_tag: bool,
        any_aligned_fields: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != 0);

        const fields_hash_arr: [4]u32 = @bit_cast(args.fields_hash);

        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.UnionDecl).Struct.fields.len + 5);
        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.UnionDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_node = gz.node_index_to_relative(args.src_node),
        });

        if (args.tag_type != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.tag_type));
        }
        if (args.captures_len != 0) {
            astgen.extra.append_assume_capacity(args.captures_len);
        }
        if (args.body_len != 0) {
            astgen.extra.append_assume_capacity(args.body_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.append_assume_capacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.append_assume_capacity(args.decls_len);
        }
        astgen.instructions.set(@int_from_enum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .union_decl,
                .small = @bit_cast(Zir.Inst.UnionDecl.Small{
                    .has_tag_type = args.tag_type != .none,
                    .has_captures_len = args.captures_len != 0,
                    .has_body_len = args.body_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                    .layout = args.layout,
                    .auto_enum_tag = args.auto_enum_tag,
                    .any_aligned_fields = args.any_aligned_fields,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn set_enum(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        tag_type: Zir.Inst.Ref,
        captures_len: u32,
        body_len: u32,
        fields_len: u32,
        decls_len: u32,
        nonexhaustive: bool,
        fields_hash: std.zig.SrcHash,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != 0);

        const fields_hash_arr: [4]u32 = @bit_cast(args.fields_hash);

        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.EnumDecl).Struct.fields.len + 5);
        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.EnumDecl{
            .fields_hash_0 = fields_hash_arr[0],
            .fields_hash_1 = fields_hash_arr[1],
            .fields_hash_2 = fields_hash_arr[2],
            .fields_hash_3 = fields_hash_arr[3],
            .src_node = gz.node_index_to_relative(args.src_node),
        });

        if (args.tag_type != .none) {
            astgen.extra.append_assume_capacity(@int_from_enum(args.tag_type));
        }
        if (args.captures_len != 0) {
            astgen.extra.append_assume_capacity(args.captures_len);
        }
        if (args.body_len != 0) {
            astgen.extra.append_assume_capacity(args.body_len);
        }
        if (args.fields_len != 0) {
            astgen.extra.append_assume_capacity(args.fields_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.append_assume_capacity(args.decls_len);
        }
        astgen.instructions.set(@int_from_enum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .enum_decl,
                .small = @bit_cast(Zir.Inst.EnumDecl.Small{
                    .has_tag_type = args.tag_type != .none,
                    .has_captures_len = args.captures_len != 0,
                    .has_body_len = args.body_len != 0,
                    .has_fields_len = args.fields_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                    .nonexhaustive = args.nonexhaustive,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn set_opaque(gz: *GenZir, inst: Zir.Inst.Index, args: struct {
        src_node: Ast.Node.Index,
        captures_len: u32,
        decls_len: u32,
    }) !void {
        const astgen = gz.astgen;
        const gpa = astgen.gpa;

        assert(args.src_node != 0);

        try astgen.extra.ensure_unused_capacity(gpa, @typeInfo(Zir.Inst.OpaqueDecl).Struct.fields.len + 2);
        const payload_index = astgen.add_extra_assume_capacity(Zir.Inst.OpaqueDecl{
            .src_node = gz.node_index_to_relative(args.src_node),
        });

        if (args.captures_len != 0) {
            astgen.extra.append_assume_capacity(args.captures_len);
        }
        if (args.decls_len != 0) {
            astgen.extra.append_assume_capacity(args.decls_len);
        }
        astgen.instructions.set(@int_from_enum(inst), .{
            .tag = .extended,
            .data = .{ .extended = .{
                .opcode = .opaque_decl,
                .small = @bit_cast(Zir.Inst.OpaqueDecl.Small{
                    .has_captures_len = args.captures_len != 0,
                    .has_decls_len = args.decls_len != 0,
                    .name_strategy = gz.anon_name_strategy,
                }),
                .operand = payload_index,
            } },
        });
    }

    fn add(gz: *GenZir, inst: Zir.Inst) !Zir.Inst.Ref {
        return (try gz.add_as_index(inst)).to_ref();
    }

    fn add_as_index(gz: *GenZir, inst: Zir.Inst) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.append_assume_capacity(inst);
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn reserve_instruction_index(gz: *GenZir) !Zir.Inst.Index {
        const gpa = gz.astgen.gpa;
        try gz.instructions.ensure_unused_capacity(gpa, 1);
        try gz.astgen.instructions.ensure_unused_capacity(gpa, 1);

        const new_index: Zir.Inst.Index = @enumFromInt(gz.astgen.instructions.len);
        gz.astgen.instructions.len += 1;
        gz.instructions.append_assume_capacity(new_index);
        return new_index;
    }

    fn add_ret(gz: *GenZir, ri: ResultInfo, operand: Zir.Inst.Ref, node: Ast.Node.Index) !void {
        switch (ri.rl) {
            .ptr => |ptr_res| _ = try gz.add_un_node(.ret_load, ptr_res.inst, node),
            .coerced_ty => _ = try gz.add_un_node(.ret_node, operand, node),
            else => unreachable,
        }
    }

    fn add_dbg_var(gz: *GenZir, tag: Zir.Inst.Tag, name: Zir.NullTerminatedString, inst: Zir.Inst.Ref) !void {
        if (gz.is_comptime) return;

        _ = try gz.add(.{ .tag = tag, .data = .{
            .str_op = .{
                .str = name,
                .operand = inst,
            },
        } });
    }
};

/// This can only be for short-lived references; the memory becomes invalidated
/// when another string is added.
fn null_terminated_string(astgen: AstGen, index: Zir.NullTerminatedString) [*:0]const u8 {
    return @ptr_cast(astgen.string_bytes.items[@int_from_enum(index)..]);
}

/// Local variables shadowing detection, including function parameters.
fn detect_local_shadowing(
    astgen: *AstGen,
    scope: *Scope,
    ident_name: Zir.NullTerminatedString,
    name_token: Ast.TokenIndex,
    token_bytes: []const u8,
    id_cat: Scope.IdCat,
) !void {
    const gpa = astgen.gpa;
    if (token_bytes[0] != '@' and is_primitive(token_bytes)) {
        return astgen.fail_tok_notes(name_token, "name shadows primitive '{s}'", .{
            token_bytes,
        }, &[_]u32{
            try astgen.err_note_tok(name_token, "consider using @\"{s}\" to disambiguate", .{
                token_bytes,
            }),
        });
    }

    var s = scope;
    var outer_scope = false;
    while (true) switch (s.tag) {
        .local_val => {
            const local_val = s.cast(Scope.LocalVal).?;
            if (local_val.name == ident_name) {
                const name_slice = mem.span(astgen.null_terminated_string(ident_name));
                const name = try gpa.dupe(u8, name_slice);
                defer gpa.free(name);
                if (outer_scope) {
                    return astgen.fail_tok_notes(name_token, "{s} '{s}' shadows {s} from outer scope", .{
                        @tag_name(id_cat), name, @tag_name(local_val.id_cat),
                    }, &[_]u32{
                        try astgen.err_note_tok(
                            local_val.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                return astgen.fail_tok_notes(name_token, "redeclaration of {s} '{s}'", .{
                    @tag_name(local_val.id_cat), name,
                }, &[_]u32{
                    try astgen.err_note_tok(
                        local_val.token_src,
                        "previous declaration here",
                        .{},
                    ),
                });
            }
            s = local_val.parent;
        },
        .local_ptr => {
            const local_ptr = s.cast(Scope.LocalPtr).?;
            if (local_ptr.name == ident_name) {
                const name_slice = mem.span(astgen.null_terminated_string(ident_name));
                const name = try gpa.dupe(u8, name_slice);
                defer gpa.free(name);
                if (outer_scope) {
                    return astgen.fail_tok_notes(name_token, "{s} '{s}' shadows {s} from outer scope", .{
                        @tag_name(id_cat), name, @tag_name(local_ptr.id_cat),
                    }, &[_]u32{
                        try astgen.err_note_tok(
                            local_ptr.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                return astgen.fail_tok_notes(name_token, "redeclaration of {s} '{s}'", .{
                    @tag_name(local_ptr.id_cat), name,
                }, &[_]u32{
                    try astgen.err_note_tok(
                        local_ptr.token_src,
                        "previous declaration here",
                        .{},
                    ),
                });
            }
            s = local_ptr.parent;
        },
        .namespace => {
            outer_scope = true;
            const ns = s.cast(Scope.Namespace).?;
            const decl_node = ns.decls.get(ident_name) orelse {
                s = ns.parent;
                continue;
            };
            const name_slice = mem.span(astgen.null_terminated_string(ident_name));
            const name = try gpa.dupe(u8, name_slice);
            defer gpa.free(name);
            return astgen.fail_tok_notes(name_token, "{s} shadows declaration of '{s}'", .{
                @tag_name(id_cat), name,
            }, &[_]u32{
                try astgen.err_note_node(decl_node, "declared here", .{}),
            });
        },
        .gen_zir => {
            s = s.cast(GenZir).?.parent;
            outer_scope = true;
        },
        .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
        .top => break,
    };
}

const LineColumn = struct { u32, u32 };

/// Advances the source cursor to the main token of `node` if not in comptime scope.
/// Usually paired with `emit_dbg_stmt`.
fn maybe_advance_source_cursor_to_main_token(gz: *GenZir, node: Ast.Node.Index) LineColumn {
    if (gz.is_comptime) return .{ gz.astgen.source_line - gz.decl_line, gz.astgen.source_column };

    const tree = gz.astgen.tree;
    const token_starts = tree.tokens.items(.start);
    const main_tokens = tree.nodes.items(.main_token);
    const node_start = token_starts[main_tokens[node]];
    gz.astgen.advance_source_cursor(node_start);

    return .{ gz.astgen.source_line - gz.decl_line, gz.astgen.source_column };
}

/// Advances the source cursor to the beginning of `node`.
fn advance_source_cursor_to_node(astgen: *AstGen, node: Ast.Node.Index) void {
    const tree = astgen.tree;
    const token_starts = tree.tokens.items(.start);
    const node_start = token_starts[tree.first_token(node)];
    astgen.advance_source_cursor(node_start);
}

/// Advances the source cursor to an absolute byte offset `end` in the file.
fn advance_source_cursor(astgen: *AstGen, end: usize) void {
    const source = astgen.tree.source;
    var i = astgen.source_offset;
    var line = astgen.source_line;
    var column = astgen.source_column;
    assert(i <= end);
    while (i < end) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    astgen.source_offset = i;
    astgen.source_line = line;
    astgen.source_column = column;
}

fn scan_decls(astgen: *AstGen, namespace: *Scope.Namespace, members: []const Ast.Node.Index) !u32 {
    const gpa = astgen.gpa;
    const tree = astgen.tree;
    const node_tags = tree.nodes.items(.tag);
    const main_tokens = tree.nodes.items(.main_token);
    const token_tags = tree.tokens.items(.tag);

    // We don't have shadowing for test names, so we just track those for duplicate reporting locally.
    var named_tests: std.AutoHashMapUnmanaged(Zir.NullTerminatedString, Ast.Node.Index) = .{};
    var decltests: std.AutoHashMapUnmanaged(Zir.NullTerminatedString, Ast.Node.Index) = .{};
    defer {
        named_tests.deinit(gpa);
        decltests.deinit(gpa);
    }

    var decl_count: u32 = 0;
    for (members) |member_node| {
        const name_token = switch (node_tags[member_node]) {
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => blk: {
                decl_count += 1;
                break :blk main_tokens[member_node] + 1;
            },

            .fn_proto_simple,
            .fn_proto_multi,
            .fn_proto_one,
            .fn_proto,
            .fn_decl,
            => blk: {
                decl_count += 1;
                const ident = main_tokens[member_node] + 1;
                if (token_tags[ident] != .identifier) {
                    switch (astgen.fail_node(member_node, "missing function name", .{})) {
                        error.AnalysisFail => continue,
                        error.OutOfMemory => return error.OutOfMemory,
                    }
                }
                break :blk ident;
            },

            .@"comptime", .@"usingnamespace" => {
                decl_count += 1;
                continue;
            },

            .test_decl => {
                decl_count += 1;
                // We don't want shadowing detection here, and test names work a bit differently, so
                // we must do the redeclaration detection ourselves.
                const test_name_token = main_tokens[member_node] + 1;
                switch (token_tags[test_name_token]) {
                    else => {}, // unnamed test
                    .string_literal => {
                        const name = try astgen.str_lit_as_string(test_name_token);
                        const gop = try named_tests.get_or_put(gpa, name.index);
                        if (gop.found_existing) {
                            const name_slice = astgen.string_bytes.items[@int_from_enum(name.index)..][0..name.len];
                            const name_duped = try gpa.dupe(u8, name_slice);
                            defer gpa.free(name_duped);
                            try astgen.append_error_node_notes(member_node, "duplicate test name '{s}'", .{name_duped}, &.{
                                try astgen.err_note_node(gop.value_ptr.*, "other test here", .{}),
                            });
                        } else {
                            gop.value_ptr.* = member_node;
                        }
                    },
                    .identifier => {
                        const name = try astgen.ident_as_string(test_name_token);
                        const gop = try decltests.get_or_put(gpa, name);
                        if (gop.found_existing) {
                            const name_slice = mem.span(astgen.null_terminated_string(name));
                            const name_duped = try gpa.dupe(u8, name_slice);
                            defer gpa.free(name_duped);
                            try astgen.append_error_node_notes(member_node, "duplicate decltest '{s}'", .{name_duped}, &.{
                                try astgen.err_note_node(gop.value_ptr.*, "other decltest here", .{}),
                            });
                        } else {
                            gop.value_ptr.* = member_node;
                        }
                    },
                }
                continue;
            },

            else => continue,
        };

        const token_bytes = astgen.tree.token_slice(name_token);
        if (token_bytes[0] != '@' and is_primitive(token_bytes)) {
            switch (astgen.fail_tok_notes(name_token, "name shadows primitive '{s}'", .{
                token_bytes,
            }, &[_]u32{
                try astgen.err_note_tok(name_token, "consider using @\"{s}\" to disambiguate", .{
                    token_bytes,
                }),
            })) {
                error.AnalysisFail => continue,
                error.OutOfMemory => return error.OutOfMemory,
            }
        }

        const name_str_index = try astgen.ident_as_string(name_token);
        const gop = try namespace.decls.get_or_put(gpa, name_str_index);
        if (gop.found_existing) {
            const name = try gpa.dupe(u8, mem.span(astgen.null_terminated_string(name_str_index)));
            defer gpa.free(name);
            switch (astgen.fail_node_notes(member_node, "redeclaration of '{s}'", .{
                name,
            }, &[_]u32{
                try astgen.err_note_node(gop.value_ptr.*, "other declaration here", .{}),
            })) {
                error.AnalysisFail => continue,
                error.OutOfMemory => return error.OutOfMemory,
            }
        }

        var s = namespace.parent;
        while (true) switch (s.tag) {
            .local_val => {
                const local_val = s.cast(Scope.LocalVal).?;
                if (local_val.name == name_str_index) {
                    return astgen.fail_tok_notes(name_token, "declaration '{s}' shadows {s} from outer scope", .{
                        token_bytes, @tag_name(local_val.id_cat),
                    }, &[_]u32{
                        try astgen.err_note_tok(
                            local_val.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                s = local_val.parent;
            },
            .local_ptr => {
                const local_ptr = s.cast(Scope.LocalPtr).?;
                if (local_ptr.name == name_str_index) {
                    return astgen.fail_tok_notes(name_token, "declaration '{s}' shadows {s} from outer scope", .{
                        token_bytes, @tag_name(local_ptr.id_cat),
                    }, &[_]u32{
                        try astgen.err_note_tok(
                            local_ptr.token_src,
                            "previous declaration here",
                            .{},
                        ),
                    });
                }
                s = local_ptr.parent;
            },
            .namespace => s = s.cast(Scope.Namespace).?.parent,
            .gen_zir => s = s.cast(GenZir).?.parent,
            .defer_normal, .defer_error => s = s.cast(Scope.Defer).?.parent,
            .top => break,
        };
        gop.value_ptr.* = member_node;
    }
    return decl_count;
}

fn is_inferred(astgen: *AstGen, ref: Zir.Inst.Ref) bool {
    const inst = ref.to_index() orelse return false;
    const zir_tags = astgen.instructions.items(.tag);
    return switch (zir_tags[@int_from_enum(inst)]) {
        .alloc_inferred,
        .alloc_inferred_mut,
        .alloc_inferred_comptime,
        .alloc_inferred_comptime_mut,
        => true,

        .extended => {
            const zir_data = astgen.instructions.items(.data);
            if (zir_data[@int_from_enum(inst)].extended.opcode != .alloc) return false;
            const small: Zir.Inst.AllocExtended.Small = @bit_cast(zir_data[@int_from_enum(inst)].extended.small);
            return !small.has_type;
        },

        else => false,
    };
}

/// Assumes capacity for body has already been added. Needed capacity taking into
/// account fixups can be found with `count_body_len_after_fixups`.
fn append_body_with_fixups(astgen: *AstGen, body: []const Zir.Inst.Index) void {
    return append_body_with_fixups_array_list(astgen, &astgen.extra, body);
}

fn append_body_with_fixups_array_list(
    astgen: *AstGen,
    list: *std.ArrayListUnmanaged(u32),
    body: []const Zir.Inst.Index,
) void {
    for (body) |body_inst| {
        append_possibly_refd_body_inst(astgen, list, body_inst);
    }
}

fn append_possibly_refd_body_inst(
    astgen: *AstGen,
    list: *std.ArrayListUnmanaged(u32),
    body_inst: Zir.Inst.Index,
) void {
    list.append_assume_capacity(@int_from_enum(body_inst));
    const kv = astgen.ref_table.fetch_remove(body_inst) orelse return;
    const ref_inst = kv.value;
    return append_possibly_refd_body_inst(astgen, list, ref_inst);
}

fn count_body_len_after_fixups(astgen: *AstGen, body: []const Zir.Inst.Index) u32 {
    var count = body.len;
    for (body) |body_inst| {
        var check_inst = body_inst;
        while (astgen.ref_table.get(check_inst)) |ref_inst| {
            count += 1;
            check_inst = ref_inst;
        }
    }
    return @int_cast(count);
}

fn emit_dbg_stmt(gz: *GenZir, lc: LineColumn) !void {
    if (gz.is_comptime) return;
    if (gz.instructions.items.len > gz.instructions_top) {
        const astgen = gz.astgen;
        const last = gz.instructions.items[gz.instructions.items.len - 1];
        if (astgen.instructions.items(.tag)[@int_from_enum(last)] == .dbg_stmt) {
            astgen.instructions.items(.data)[@int_from_enum(last)].dbg_stmt = .{
                .line = lc[0],
                .column = lc[1],
            };
            return;
        }
    }

    _ = try gz.add(.{ .tag = .dbg_stmt, .data = .{
        .dbg_stmt = .{
            .line = lc[0],
            .column = lc[1],
        },
    } });
}

/// In some cases, Sema expects us to generate a `dbg_stmt` at the instruction
/// *index* directly preceding the next instruction (e.g. if a call is %10, it
/// expects a dbg_stmt at %9). TODO: this logic may allow redundant dbg_stmt
/// instructions; fix up Sema so we don't need it!
fn emit_dbg_stmt_force_current_index(gz: *GenZir, lc: LineColumn) !void {
    const astgen = gz.astgen;
    if (gz.instructions.items.len > gz.instructions_top and
        @int_from_enum(gz.instructions.items[gz.instructions.items.len - 1]) == astgen.instructions.len - 1)
    {
        const last = astgen.instructions.len - 1;
        if (astgen.instructions.items(.tag)[last] == .dbg_stmt) {
            astgen.instructions.items(.data)[last].dbg_stmt = .{
                .line = lc[0],
                .column = lc[1],
            };
            return;
        }
    }

    _ = try gz.add(.{ .tag = .dbg_stmt, .data = .{
        .dbg_stmt = .{
            .line = lc[0],
            .column = lc[1],
        },
    } });
}

fn lower_ast_errors(astgen: *AstGen) !void {
    const tree = astgen.tree;
    assert(tree.errors.len > 0);

    const gpa = astgen.gpa;
    const parse_err = tree.errors[0];

    var msg: std.ArrayListUnmanaged(u8) = .{};
    defer msg.deinit(gpa);

    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);

    var notes: std.ArrayListUnmanaged(u32) = .{};
    defer notes.deinit(gpa);

    if (token_tags[parse_err.token + @int_from_bool(parse_err.token_is_prev)] == .invalid) {
        const tok = parse_err.token + @int_from_bool(parse_err.token_is_prev);
        const bad_off: u32 = @int_cast(tree.token_slice(parse_err.token + @int_from_bool(parse_err.token_is_prev)).len);
        const byte_abs = token_starts[parse_err.token + @int_from_bool(parse_err.token_is_prev)] + bad_off;
        try notes.append(gpa, try astgen.err_note_tok_off(tok, bad_off, "invalid byte: '{'}'", .{
            std.zig.fmt_escapes(tree.source[byte_abs..][0..1]),
        }));
    }

    for (tree.errors[1..]) |note| {
        if (!note.is_note) break;

        msg.clear_retaining_capacity();
        try tree.render_error(note, msg.writer(gpa));
        try notes.append(gpa, try astgen.err_note_tok(note.token, "{s}", .{msg.items}));
    }

    const extra_offset = tree.error_offset(parse_err);
    msg.clear_retaining_capacity();
    try tree.render_error(parse_err, msg.writer(gpa));
    try astgen.append_error_tok_notes_off(parse_err.token, extra_offset, "{s}", .{msg.items}, notes.items);
}

const DeclarationName = union(enum) {
    named: Ast.TokenIndex,
    named_test: Ast.TokenIndex,
    unnamed_test,
    decltest: Zir.NullTerminatedString,
    @"comptime",
    @"usingnamespace",
};

/// Sets all extra data for a `declaration` instruction.
/// Unstacks `value_gz`, `align_gz`, `linksection_gz`, and `addrspace_gz`.
fn set_declaration(
    decl_inst: Zir.Inst.Index,
    src_hash: std.zig.SrcHash,
    name: DeclarationName,
    line_offset: u32,
    is_pub: bool,
    is_export: bool,
    doc_comment: Zir.NullTerminatedString,
    value_gz: *GenZir,
    /// May be `null` if all these blocks would be empty.
    /// If `null`, then `value_gz` must have nothing stacked on it.
    extra_gzs: ?struct {
        /// Must be stacked on `value_gz`.
        align_gz: *GenZir,
        /// Must be stacked on `align_gz`.
        linksection_gz: *GenZir,
        /// Must be stacked on `linksection_gz`, and have nothing stacked on it.
        addrspace_gz: *GenZir,
    },
) !void {
    const astgen = value_gz.astgen;
    const gpa = astgen.gpa;

    const empty_body: []Zir.Inst.Index = &.{};
    const value_body, const align_body, const linksection_body, const addrspace_body = if (extra_gzs) |e| .{
        value_gz.instructions_slice_upto(e.align_gz),
        e.align_gz.instructions_slice_upto(e.linksection_gz),
        e.linksection_gz.instructions_slice_upto(e.addrspace_gz),
        e.addrspace_gz.instructions_slice(),
    } else .{ value_gz.instructions_slice(), empty_body, empty_body, empty_body };

    const value_len = astgen.count_body_len_after_fixups(value_body);
    const align_len = astgen.count_body_len_after_fixups(align_body);
    const linksection_len = astgen.count_body_len_after_fixups(linksection_body);
    const addrspace_len = astgen.count_body_len_after_fixups(addrspace_body);

    const true_doc_comment: Zir.NullTerminatedString = switch (name) {
        .decltest => |test_name| test_name,
        else => doc_comment,
    };

    const src_hash_arr: [4]u32 = @bit_cast(src_hash);

    const extra: Zir.Inst.Declaration = .{
        .src_hash_0 = src_hash_arr[0],
        .src_hash_1 = src_hash_arr[1],
        .src_hash_2 = src_hash_arr[2],
        .src_hash_3 = src_hash_arr[3],
        .name = switch (name) {
            .named => |tok| @enumFromInt(@int_from_enum(try astgen.ident_as_string(tok))),
            .named_test => |tok| @enumFromInt(@int_from_enum(try astgen.test_name_string(tok))),
            .unnamed_test => .unnamed_test,
            .decltest => .decltest,
            .@"comptime" => .@"comptime",
            .@"usingnamespace" => .@"usingnamespace",
        },
        .line_offset = line_offset,
        .flags = .{
            .value_body_len = @int_cast(value_len),
            .is_pub = is_pub,
            .is_export = is_export,
            .has_doc_comment = true_doc_comment != .empty,
            .has_align_linksection_addrspace = align_len != 0 or linksection_len != 0 or addrspace_len != 0,
        },
    };
    astgen.instructions.items(.data)[@int_from_enum(decl_inst)].pl_node.payload_index = try astgen.add_extra(extra);
    if (extra.flags.has_doc_comment) {
        try astgen.extra.append(gpa, @int_from_enum(true_doc_comment));
    }
    if (extra.flags.has_align_linksection_addrspace) {
        try astgen.extra.append_slice(gpa, &.{
            align_len,
            linksection_len,
            addrspace_len,
        });
    }
    try astgen.extra.ensure_unused_capacity(gpa, value_len + align_len + linksection_len + addrspace_len);
    astgen.append_body_with_fixups(value_body);
    if (extra.flags.has_align_linksection_addrspace) {
        astgen.append_body_with_fixups(align_body);
        astgen.append_body_with_fixups(linksection_body);
        astgen.append_body_with_fixups(addrspace_body);
    }

    if (extra_gzs) |e| {
        e.addrspace_gz.unstack();
        e.linksection_gz.unstack();
        e.align_gz.unstack();
    }
    value_gz.unstack();
}
