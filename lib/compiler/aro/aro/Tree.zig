const std = @import("std");
const Interner = @import("../backend.zig").Interner;
const Attribute = @import("Attribute.zig");
const CodeGen = @import("CodeGen.zig");
const Compilation = @import("Compilation.zig");
const number_affixes = @import("Tree/number_affixes.zig");
const Source = @import("Source.zig");
const Tokenizer = @import("Tokenizer.zig");
const Type = @import("Type.zig");
const Value = @import("Value.zig");
const StringInterner = @import("StringInterner.zig");

pub const Token = struct {
    id: Id,
    loc: Source.Location,

    pub const List = std.MultiArrayList(Token);
    pub const Id = Tokenizer.Token.Id;
    pub const NumberPrefix = number_affixes.Prefix;
    pub const NumberSuffix = number_affixes.Suffix;
};

pub const TokenWithExpansionLocs = struct {
    id: Token.Id,
    flags: packed struct {
        expansion_disabled: bool = false,
        is_macro_arg: bool = false,
    } = .{},
    /// This location contains the actual token slice which might be generated.
    /// If it is generated then there is guaranteed to be at least one
    /// expansion location.
    loc: Source.Location,
    expansion_locs: ?[*]Source.Location = null,

    pub fn expansion_slice(tok: TokenWithExpansionLocs) []const Source.Location {
        const locs = tok.expansion_locs orelse return &[0]Source.Location{};
        var i: usize = 0;
        while (locs[i].id != .unused) : (i += 1) {}
        return locs[0..i];
    }

    pub fn add_expansion_location(tok: *TokenWithExpansionLocs, gpa: std.mem.Allocator, new: []const Source.Location) !void {
        if (new.len == 0 or tok.id == .whitespace or tok.id == .macro_ws or tok.id == .placemarker) return;
        var list = std.ArrayList(Source.Location).init(gpa);
        defer {
            @memset(list.items.ptr[list.items.len..list.capacity], .{});
            // Add a sentinel to indicate the end of the list since
            // the ArrayList's capacity isn't guaranteed to be exactly
            // what we ask for.
            if (list.capacity > 0) {
                list.items.ptr[list.capacity - 1].byte_offset = 1;
            }
            tok.expansion_locs = list.items.ptr;
        }

        if (tok.expansion_locs) |locs| {
            var i: usize = 0;
            while (locs[i].id != .unused) : (i += 1) {}
            list.items = locs[0..i];
            while (locs[i].byte_offset != 1) : (i += 1) {}
            list.capacity = i + 1;
        }

        const min_len = @max(list.items.len + new.len + 1, 4);
        const wanted_len = std.math.ceil_power_of_two(usize, min_len) catch
            return error.OutOfMemory;
        try list.ensure_total_capacity(wanted_len);

        for (new) |new_loc| {
            if (new_loc.id == .generated) continue;
            list.append_assume_capacity(new_loc);
        }
    }

    pub fn free(expansion_locs: ?[*]Source.Location, gpa: std.mem.Allocator) void {
        const locs = expansion_locs orelse return;
        var i: usize = 0;
        while (locs[i].id != .unused) : (i += 1) {}
        while (locs[i].byte_offset != 1) : (i += 1) {}
        gpa.free(locs[0 .. i + 1]);
    }

    pub fn dupe(tok: TokenWithExpansionLocs, gpa: std.mem.Allocator) !TokenWithExpansionLocs {
        var copy = tok;
        copy.expansion_locs = null;
        try copy.add_expansion_location(gpa, tok.expansion_slice());
        return copy;
    }

    pub fn check_ms_eof(tok: TokenWithExpansionLocs, source: Source, comp: *Compilation) !void {
        std.debug.assert(tok.id == .eof);
        if (source.buf.len > tok.loc.byte_offset and source.buf[tok.loc.byte_offset] == 0x1A) {
            try comp.addDiagnostic(.{
                .tag = .ctrl_z_eof,
                .loc = .{
                    .id = source.id,
                    .byte_offset = tok.loc.byte_offset,
                    .line = tok.loc.line,
                },
            }, &.{});
        }
    }
};

pub const TokenIndex = u32;
pub const NodeIndex = enum(u32) { none, _ };
pub const ValueMap = std.AutoHashMap(NodeIndex, Value);

const Tree = @This();

comp: *Compilation,
arena: std.heap.ArenaAllocator,
generated: []const u8,
tokens: Token.List.Slice,
nodes: Node.List.Slice,
data: []const NodeIndex,
root_decls: []const NodeIndex,
value_map: ValueMap,

pub const gen_ir = CodeGen.gen_ir;

pub fn deinit(tree: *Tree) void {
    tree.comp.gpa.free(tree.root_decls);
    tree.comp.gpa.free(tree.data);
    tree.nodes.deinit(tree.comp.gpa);
    tree.arena.deinit();
    tree.value_map.deinit();
}

pub const GNUAssemblyQualifiers = struct {
    @"volatile": bool = false,
    @"inline": bool = false,
    goto: bool = false,
};

pub const Node = struct {
    tag: Tag,
    ty: Type = .{ .specifier = .void },
    data: Data,

    pub const Range = struct { start: u32, end: u32 };

    pub const Data = union {
        decl: struct {
            name: TokenIndex,
            node: NodeIndex = .none,
        },
        decl_ref: TokenIndex,
        range: Range,
        if3: struct {
            cond: NodeIndex,
            body: u32,
        },
        un: NodeIndex,
        bin: struct {
            lhs: NodeIndex,
            rhs: NodeIndex,
        },
        member: struct {
            lhs: NodeIndex,
            index: u32,
        },
        union_init: struct {
            field_index: u32,
            node: NodeIndex,
        },
        cast: struct {
            operand: NodeIndex,
            kind: CastKind,
        },
        int: u64,
        return_zero: bool,

        pub fn for_decl(data: Data, tree: *const Tree) struct {
            decls: []const NodeIndex,
            cond: NodeIndex,
            incr: NodeIndex,
            body: NodeIndex,
        } {
            const items = tree.data[data.range.start..data.range.end];
            const decls = items[0 .. items.len - 3];

            return .{
                .decls = decls,
                .cond = items[items.len - 3],
                .incr = items[items.len - 2],
                .body = items[items.len - 1],
            };
        }

        pub fn for_stmt(data: Data, tree: *const Tree) struct {
            init: NodeIndex,
            cond: NodeIndex,
            incr: NodeIndex,
            body: NodeIndex,
        } {
            const items = tree.data[data.if3.body..];

            return .{
                .init = items[0],
                .cond = items[1],
                .incr = items[2],
                .body = data.if3.cond,
            };
        }
    };

    pub const List = std.MultiArrayList(Node);
};

pub const CastKind = enum(u8) {
    /// Does nothing except possibly add qualifiers
    no_op,
    /// Interpret one bit pattern as another. Used for operands which have the same
    /// size and unrelated types, e.g. casting one pointer type to another
    bitcast,
    /// Convert T[] to T *
    array_to_pointer,
    /// Converts an lvalue to an rvalue
    lval_to_rval,
    /// Convert a function type to a pointer to a function
    function_to_pointer,
    /// Convert a pointer type to a _Bool
    pointer_to_bool,
    /// Convert a pointer type to an integer type
    pointer_to_int,
    /// Convert _Bool to an integer type
    bool_to_int,
    /// Convert _Bool to a floating type
    bool_to_float,
    /// Convert a _Bool to a pointer; will cause a  warning
    bool_to_pointer,
    /// Convert an integer type to _Bool
    int_to_bool,
    /// Convert an integer to a floating type
    int_to_float,
    /// Convert a complex integer to a complex floating type
    complex_int_to_complex_float,
    /// Convert an integer type to a pointer type
    int_to_pointer,
    /// Convert a floating type to a _Bool
    float_to_bool,
    /// Convert a floating type to an integer
    float_to_int,
    /// Convert a complex floating type to a complex integer
    complex_float_to_complex_int,
    /// Convert one integer type to another
    int_cast,
    /// Convert one complex integer type to another
    complex_int_cast,
    /// Convert real part of complex integer to a integer
    complex_int_to_real,
    /// Create a complex integer type using operand as the real part
    real_to_complex_int,
    /// Convert one floating type to another
    float_cast,
    /// Convert one complex floating type to another
    complex_float_cast,
    /// Convert real part of complex float to a float
    complex_float_to_real,
    /// Create a complex floating type using operand as the real part
    real_to_complex_float,
    /// Convert type to void
    to_void,
    /// Convert a literal 0 to a null pointer
    null_to_pointer,
    /// GNU cast-to-union extension
    union_cast,
    /// Create vector where each value is same as the input scalar.
    vector_splat,
};

pub const Tag = enum(u8) {
    /// Must appear at index 0. Also used as the tag for __builtin_types_compatible_p arguments, since the arguments are types
    /// Reaching it is always the result of a bug.
    invalid,

    // ====== Decl ======

    // _Static_assert
    static_assert,

    // function prototype
    fn_proto,
    static_fn_proto,
    inline_fn_proto,
    inline_static_fn_proto,

    // function definition
    fn_def,
    static_fn_def,
    inline_fn_def,
    inline_static_fn_def,

    // variable declaration
    @"var",
    extern_var,
    static_var,
    // same as static_var, used for __func__, __FUNCTION__ and __PRETTY_FUNCTION__
    implicit_static_var,
    threadlocal_var,
    threadlocal_extern_var,
    threadlocal_static_var,

    /// __asm__("...") at file scope
    file_scope_asm,

    // typedef declaration
    typedef,

    // container declarations
    /// { lhs; rhs; }
    struct_decl_two,
    /// { lhs; rhs; }
    union_decl_two,
    /// { lhs, rhs, }
    enum_decl_two,
    /// { range }
    struct_decl,
    /// { range }
    union_decl,
    /// { range }
    enum_decl,
    /// struct decl_ref;
    struct_forward_decl,
    /// union decl_ref;
    union_forward_decl,
    /// enum decl_ref;
    enum_forward_decl,

    /// name = node
    enum_field_decl,
    /// ty name : node
    /// name == 0 means unnamed
    record_field_decl,
    /// Used when a record has an unnamed record as a field
    indirect_record_field_decl,

    // ====== Stmt ======

    labeled_stmt,
    /// { first; second; } first and second may be null
    compound_stmt_two,
    /// { data }
    compound_stmt,
    /// if (first) data[second] else data[second+1];
    if_then_else_stmt,
    /// if (first) second; second may be null
    if_then_stmt,
    /// switch (first) second
    switch_stmt,
    /// case first: second
    case_stmt,
    /// case data[body]...data[body+1]: cond
    case_range_stmt,
    /// default: first
    default_stmt,
    /// while (first) second
    while_stmt,
    /// do second while(first);
    do_while_stmt,
    /// for (data[..]; data[len-3]; data[len-2]) data[len-1]
    for_decl_stmt,
    /// for (;;;) first
    forever_stmt,
    /// for (data[first]; data[first+1]; data[first+2]) second
    for_stmt,
    /// goto first;
    goto_stmt,
    /// goto *un;
    computed_goto_stmt,
    // continue; first and second unused
    continue_stmt,
    // break; first and second unused
    break_stmt,
    // null statement (just a semicolon); first and second unused
    null_stmt,
    /// return first; first may be null
    return_stmt,
    /// Assembly statement of the form __asm__("string literal")
    gnu_asm_simple,

    // ====== Expr ======

    /// lhs , rhs
    comma_expr,
    /// lhs ? data[0] : data[1]
    binary_cond_expr,
    /// Used as the base for casts of the lhs in `binary_cond_expr`.
    cond_dummy_expr,
    /// lhs ? data[0] : data[1]
    cond_expr,
    /// lhs = rhs
    assign_expr,
    /// lhs *= rhs
    mul_assign_expr,
    /// lhs /= rhs
    div_assign_expr,
    /// lhs %= rhs
    mod_assign_expr,
    /// lhs += rhs
    add_assign_expr,
    /// lhs -= rhs
    sub_assign_expr,
    /// lhs <<= rhs
    shl_assign_expr,
    /// lhs >>= rhs
    shr_assign_expr,
    /// lhs &= rhs
    bit_and_assign_expr,
    /// lhs ^= rhs
    bit_xor_assign_expr,
    /// lhs |= rhs
    bit_or_assign_expr,
    /// lhs || rhs
    bool_or_expr,
    /// lhs && rhs
    bool_and_expr,
    /// lhs | rhs
    bit_or_expr,
    /// lhs ^ rhs
    bit_xor_expr,
    /// lhs & rhs
    bit_and_expr,
    /// lhs == rhs
    equal_expr,
    /// lhs != rhs
    not_equal_expr,
    /// lhs < rhs
    less_than_expr,
    /// lhs <= rhs
    less_than_equal_expr,
    /// lhs > rhs
    greater_than_expr,
    /// lhs >= rhs
    greater_than_equal_expr,
    /// lhs << rhs
    shl_expr,
    /// lhs >> rhs
    shr_expr,
    /// lhs + rhs
    add_expr,
    /// lhs - rhs
    sub_expr,
    /// lhs * rhs
    mul_expr,
    /// lhs / rhs
    div_expr,
    /// lhs % rhs
    mod_expr,
    /// Explicit: (type) cast
    explicit_cast,
    /// Implicit: cast
    implicit_cast,
    /// &un
    addr_of_expr,
    /// &&decl_ref
    addr_of_label,
    /// *un
    deref_expr,
    /// +un
    plus_expr,
    /// -un
    negate_expr,
    /// ~un
    bit_not_expr,
    /// !un
    bool_not_expr,
    /// ++un
    pre_inc_expr,
    /// --un
    pre_dec_expr,
    /// __imag un
    imag_expr,
    /// __real un
    real_expr,
    /// lhs[rhs]  lhs is pointer/array type, rhs is integer type
    array_access_expr,
    /// first(second) second may be 0
    call_expr_one,
    /// data[0](data[1..])
    call_expr,
    /// decl
    builtin_call_expr_one,
    builtin_call_expr,
    /// lhs.member
    member_access_expr,
    /// lhs->member
    member_access_ptr_expr,
    /// un++
    post_inc_expr,
    /// un--
    post_dec_expr,
    /// (un)
    paren_expr,
    /// decl_ref
    decl_ref_expr,
    /// decl_ref
    enumeration_ref,
    /// C23 bool literal `true` / `false`
    bool_literal,
    /// C23 nullptr literal
    nullptr_literal,
    /// integer literal, always unsigned
    int_literal,
    /// Same as int_literal, but originates from a char literal
    char_literal,
    /// a floating point literal
    float_literal,
    /// wraps a float or double literal: un
    imaginary_literal,
    /// tree.str[index..][0..len]
    string_literal_expr,
    /// sizeof(un?)
    sizeof_expr,
    /// _Alignof(un?)
    alignof_expr,
    /// _Generic(controlling lhs, chosen rhs)
    generic_expr_one,
    /// _Generic(controlling range[0], chosen range[1], rest range[2..])
    generic_expr,
    /// ty: un
    generic_association_expr,
    // default: un
    generic_default_expr,
    /// __builtin_choose_expr(lhs, data[0], data[1])
    builtin_choose_expr,
    /// __builtin_types_compatible_p(lhs, rhs)
    builtin_types_compatible_p,
    /// decl - special builtins require custom parsing
    special_builtin_call_one,
    /// ({ un })
    stmt_expr,

    // ====== Initializer expressions ======

    /// { lhs, rhs }
    array_init_expr_two,
    /// { range }
    array_init_expr,
    /// { lhs, rhs }
    struct_init_expr_two,
    /// { range }
    struct_init_expr,
    /// { union_init }
    union_init_expr,
    /// (ty){ un }
    compound_literal_expr,
    /// (static ty){ un }
    static_compound_literal_expr,
    /// (thread_local ty){ un }
    thread_local_compound_literal_expr,
    /// (static thread_local ty){ un }
    static_thread_local_compound_literal_expr,

    /// Inserted at the end of a function body if no return stmt is found.
    /// ty is the functions return type
    /// data is return_zero which is true if the function is called "main" and ty is compatible with int
    implicit_return,

    /// Inserted in array_init_expr to represent unspecified elements.
    /// data.int contains the amount of elements.
    array_filler_expr,
    /// Inserted in record and scalar initializers for unspecified elements.
    default_init_expr,

    pub fn is_implicit(tag: Tag) bool {
        return switch (tag) {
            .implicit_cast,
            .implicit_return,
            .array_filler_expr,
            .default_init_expr,
            .implicit_static_var,
            .cond_dummy_expr,
            => true,
            else => false,
        };
    }
};

pub fn is_bitfield(tree: *const Tree, node: NodeIndex) bool {
    return tree.bitfield_width(node, false) != null;
}

/// Returns null if node is not a bitfield. If inspect_lval is true, this function will
/// recurse into implicit lval_to_rval casts (useful for arithmetic conversions)
pub fn bitfield_width(tree: *const Tree, node: NodeIndex, inspect_lval: bool) ?u32 {
    if (node == .none) return null;
    switch (tree.nodes.items(.tag)[@int_from_enum(node)]) {
        .member_access_expr, .member_access_ptr_expr => {
            const member = tree.nodes.items(.data)[@int_from_enum(node)].member;
            var ty = tree.nodes.items(.ty)[@int_from_enum(member.lhs)];
            if (ty.is_ptr()) ty = ty.elem_type();
            const record_ty = ty.get(.@"struct") orelse ty.get(.@"union") orelse return null;
            const field = record_ty.data.record.fields[member.index];
            return field.bit_width;
        },
        .implicit_cast => {
            if (!inspect_lval) return null;

            const data = tree.nodes.items(.data)[@int_from_enum(node)];
            return switch (data.cast.kind) {
                .lval_to_rval => tree.bitfield_width(data.cast.operand, false),
                else => null,
            };
        },
        else => return null,
    }
}

pub fn is_lval(tree: *const Tree, node: NodeIndex) bool {
    var is_const: bool = undefined;
    return tree.is_lval_extra(node, &is_const);
}

pub fn is_lval_extra(tree: *const Tree, node: NodeIndex, is_const: *bool) bool {
    is_const.* = false;
    switch (tree.nodes.items(.tag)[@int_from_enum(node)]) {
        .compound_literal_expr,
        .static_compound_literal_expr,
        .thread_local_compound_literal_expr,
        .static_thread_local_compound_literal_expr,
        => {
            is_const.* = tree.nodes.items(.ty)[@int_from_enum(node)].is_const();
            return true;
        },
        .string_literal_expr => return true,
        .member_access_ptr_expr => {
            const lhs_expr = tree.nodes.items(.data)[@int_from_enum(node)].member.lhs;
            const ptr_ty = tree.nodes.items(.ty)[@int_from_enum(lhs_expr)];
            if (ptr_ty.is_ptr()) is_const.* = ptr_ty.elem_type().is_const();
            return true;
        },
        .array_access_expr => {
            const lhs_expr = tree.nodes.items(.data)[@int_from_enum(node)].bin.lhs;
            if (lhs_expr != .none) {
                const array_ty = tree.nodes.items(.ty)[@int_from_enum(lhs_expr)];
                if (array_ty.is_ptr() or array_ty.is_array()) is_const.* = array_ty.elem_type().is_const();
            }
            return true;
        },
        .decl_ref_expr => {
            const decl_ty = tree.nodes.items(.ty)[@int_from_enum(node)];
            is_const.* = decl_ty.is_const();
            return true;
        },
        .deref_expr => {
            const data = tree.nodes.items(.data)[@int_from_enum(node)];
            const operand_ty = tree.nodes.items(.ty)[@int_from_enum(data.un)];
            if (operand_ty.is_func()) return false;
            if (operand_ty.is_ptr() or operand_ty.is_array()) is_const.* = operand_ty.elem_type().is_const();
            return true;
        },
        .member_access_expr => {
            const data = tree.nodes.items(.data)[@int_from_enum(node)];
            return tree.is_lval_extra(data.member.lhs, is_const);
        },
        .paren_expr => {
            const data = tree.nodes.items(.data)[@int_from_enum(node)];
            return tree.is_lval_extra(data.un, is_const);
        },
        .builtin_choose_expr => {
            const data = tree.nodes.items(.data)[@int_from_enum(node)];

            if (tree.value_map.get(data.if3.cond)) |val| {
                const offset = @int_from_bool(val.is_zero(tree.comp));
                return tree.is_lval_extra(tree.data[data.if3.body + offset], is_const);
            }
            return false;
        },
        else => return false,
    }
}

pub fn tok_slice(tree: *const Tree, tok_i: TokenIndex) []const u8 {
    if (tree.tokens.items(.id)[tok_i].lexeme()) |some| return some;
    const loc = tree.tokens.items(.loc)[tok_i];
    var tmp_tokenizer = Tokenizer{
        .buf = tree.comp.get_source(loc.id).buf,
        .langopts = tree.comp.langopts,
        .index = loc.byte_offset,
        .source = .generated,
    };
    const tok = tmp_tokenizer.next();
    return tmp_tokenizer.buf[tok.start..tok.end];
}

pub fn dump(tree: *const Tree, config: std.io.tty.Config, writer: anytype) !void {
    const mapper = tree.comp.string_interner.get_fast_type_mapper(tree.comp.gpa) catch tree.comp.string_interner.get_slow_type_mapper();
    defer mapper.deinit(tree.comp.gpa);

    for (tree.root_decls) |i| {
        try tree.dump_node(i, 0, mapper, config, writer);
        try writer.write_byte('\n');
    }
}

fn dump_field_attributes(tree: *const Tree, attributes: []const Attribute, level: u32, writer: anytype) !void {
    for (attributes) |attr| {
        try writer.write_byte_ntimes(' ', level);
        try writer.print("field attr: {s}", .{@tag_name(attr.tag)});
        try tree.dump_attribute(attr, writer);
    }
}

fn dump_attribute(tree: *const Tree, attr: Attribute, writer: anytype) !void {
    switch (attr.tag) {
        inline else => |tag| {
            const args = @field(attr.args, @tag_name(tag));
            const fields = @typeInfo(@TypeOf(args)).Struct.fields;
            if (fields.len == 0) {
                try writer.write_byte('\n');
                return;
            }
            try writer.write_byte(' ');
            inline for (fields, 0..) |f, i| {
                if (comptime std.mem.eql(u8, f.name, "__name_tok")) continue;
                if (i != 0) {
                    try writer.write_all(", ");
                }
                try writer.write_all(f.name);
                try writer.write_all(": ");
                switch (f.type) {
                    Interner.Ref => try writer.print("\"{s}\"", .{tree.interner.get(@field(args, f.name)).bytes}),
                    ?Interner.Ref => try writer.print("\"{?s}\"", .{if (@field(args, f.name)) |str| tree.interner.get(str).bytes else null}),
                    else => switch (@typeInfo(f.type)) {
                        .Enum => try writer.write_all(@tag_name(@field(args, f.name))),
                        else => try writer.print("{any}", .{@field(args, f.name)}),
                    },
                }
            }
            try writer.write_byte('\n');
            return;
        },
    }
}

fn dump_node(
    tree: *const Tree,
    node: NodeIndex,
    level: u32,
    mapper: StringInterner.TypeMapper,
    config: std.io.tty.Config,
    w: anytype,
) !void {
    const delta = 2;
    const half = delta / 2;
    const TYPE = std.io.tty.Color.bright_magenta;
    const TAG = std.io.tty.Color.bright_cyan;
    const IMPLICIT = std.io.tty.Color.bright_blue;
    const NAME = std.io.tty.Color.bright_red;
    const LITERAL = std.io.tty.Color.bright_green;
    const ATTRIBUTE = std.io.tty.Color.bright_yellow;
    std.debug.assert(node != .none);

    const tag = tree.nodes.items(.tag)[@int_from_enum(node)];
    const data = tree.nodes.items(.data)[@int_from_enum(node)];
    const ty = tree.nodes.items(.ty)[@int_from_enum(node)];
    try w.write_byte_ntimes(' ', level);

    try config.set_color(w, if (tag.is_implicit()) IMPLICIT else TAG);
    try w.print("{s}: ", .{@tag_name(tag)});
    if (tag == .implicit_cast or tag == .explicit_cast) {
        try config.set_color(w, .white);
        try w.print("({s}) ", .{@tag_name(data.cast.kind)});
    }
    try config.set_color(w, TYPE);
    try w.write_byte('\'');
    try ty.dump(mapper, tree.comp.langopts, w);
    try w.write_byte('\'');

    if (tree.is_lval(node)) {
        try config.set_color(w, ATTRIBUTE);
        try w.write_all(" lvalue");
    }
    if (tree.is_bitfield(node)) {
        try config.set_color(w, ATTRIBUTE);
        try w.write_all(" bitfield");
    }
    if (tree.value_map.get(node)) |val| {
        try config.set_color(w, LITERAL);
        try w.write_all(" (value: ");
        try val.print(ty, tree.comp, w);
        try w.write_byte(')');
    }
    if (tag == .implicit_return and data.return_zero) {
        try config.set_color(w, IMPLICIT);
        try w.write_all(" (value: 0)");
        try config.set_color(w, .reset);
    }

    try w.write_all("\n");
    try config.set_color(w, .reset);

    if (ty.specifier == .attributed) {
        try config.set_color(w, ATTRIBUTE);
        for (ty.data.attributed.attributes) |attr| {
            try w.write_byte_ntimes(' ', level + half);
            try w.print("attr: {s}", .{@tag_name(attr.tag)});
            try tree.dump_attribute(attr, w);
        }
        try config.set_color(w, .reset);
    }

    switch (tag) {
        .invalid => unreachable,
        .file_scope_asm => {
            try w.write_byte_ntimes(' ', level + 1);
            try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
        },
        .gnu_asm_simple => {
            try w.write_byte_ntimes(' ', level);
            try tree.dump_node(data.un, level, mapper, config, w);
        },
        .static_assert => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("condition:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            if (data.bin.rhs != .none) {
                try w.write_byte_ntimes(' ', level + 1);
                try w.write_all("diagnostic:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .fn_proto,
        .static_fn_proto,
        .inline_fn_proto,
        .inline_static_fn_proto,
        => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
        },
        .fn_def,
        .static_fn_def,
        .inline_fn_def,
        .inline_static_fn_def,
        => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("body:\n");
            try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
        },
        .typedef,
        .@"var",
        .extern_var,
        .static_var,
        .implicit_static_var,
        .threadlocal_var,
        .threadlocal_extern_var,
        .threadlocal_static_var,
        => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("init:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .enum_field_decl => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("value:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .record_field_decl => {
            if (data.decl.name != 0) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("name: ");
                try config.set_color(w, NAME);
                try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
                try config.set_color(w, .reset);
            }
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("bits:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .indirect_record_field_decl => {},
        .compound_stmt,
        .array_init_expr,
        .struct_init_expr,
        .enum_decl,
        .struct_decl,
        .union_decl,
        => {
            const maybe_field_attributes = if (ty.get_record()) |record| record.field_attributes else null;
            for (tree.data[data.range.start..data.range.end], 0..) |stmt, i| {
                if (i != 0) try w.write_byte('\n');
                try tree.dump_node(stmt, level + delta, mapper, config, w);
                if (maybe_field_attributes) |field_attributes| {
                    if (field_attributes[i].len == 0) continue;

                    try config.set_color(w, ATTRIBUTE);
                    try tree.dump_field_attributes(field_attributes[i], level + delta + half, w);
                    try config.set_color(w, .reset);
                }
            }
        },
        .compound_stmt_two,
        .array_init_expr_two,
        .struct_init_expr_two,
        .enum_decl_two,
        .struct_decl_two,
        .union_decl_two,
        => {
            var attr_array = [2][]const Attribute{ &.{}, &.{} };
            const empty: [][]const Attribute = &attr_array;
            const field_attributes = if (ty.get_record()) |record| (record.field_attributes orelse empty.ptr) else empty.ptr;
            if (data.bin.lhs != .none) {
                try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
                if (field_attributes[0].len > 0) {
                    try config.set_color(w, ATTRIBUTE);
                    try tree.dump_field_attributes(field_attributes[0], level + delta + half, w);
                    try config.set_color(w, .reset);
                }
            }
            if (data.bin.rhs != .none) {
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
                if (field_attributes[1].len > 0) {
                    try config.set_color(w, ATTRIBUTE);
                    try tree.dump_field_attributes(field_attributes[1], level + delta + half, w);
                    try config.set_color(w, .reset);
                }
            }
        },
        .union_init_expr => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("field index: ");
            try config.set_color(w, LITERAL);
            try w.print("{d}\n", .{data.union_init.field_index});
            try config.set_color(w, .reset);
            if (data.union_init.node != .none) {
                try tree.dump_node(data.union_init.node, level + delta, mapper, config, w);
            }
        },
        .compound_literal_expr,
        .static_compound_literal_expr,
        .thread_local_compound_literal_expr,
        .static_thread_local_compound_literal_expr,
        => {
            try tree.dump_node(data.un, level + half, mapper, config, w);
        },
        .labeled_stmt => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("label: ");
            try config.set_color(w, LITERAL);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("stmt:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .case_stmt => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("value:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            if (data.bin.rhs != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("stmt:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .case_range_stmt => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("range start:\n");
            try tree.dump_node(tree.data[data.if3.body], level + delta, mapper, config, w);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("range end:\n");
            try tree.dump_node(tree.data[data.if3.body + 1], level + delta, mapper, config, w);

            if (data.if3.cond != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("stmt:\n");
                try tree.dump_node(data.if3.cond, level + delta, mapper, config, w);
            }
        },
        .default_stmt => {
            if (data.un != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("stmt:\n");
                try tree.dump_node(data.un, level + delta, mapper, config, w);
            }
        },
        .binary_cond_expr, .cond_expr, .if_then_else_stmt, .builtin_choose_expr => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("cond:\n");
            try tree.dump_node(data.if3.cond, level + delta, mapper, config, w);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("then:\n");
            try tree.dump_node(tree.data[data.if3.body], level + delta, mapper, config, w);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("else:\n");
            try tree.dump_node(tree.data[data.if3.body + 1], level + delta, mapper, config, w);
        },
        .builtin_types_compatible_p => {
            std.debug.assert(tree.nodes.items(.tag)[@int_from_enum(data.bin.lhs)] == .invalid);
            std.debug.assert(tree.nodes.items(.tag)[@int_from_enum(data.bin.rhs)] == .invalid);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("lhs: ");

            const lhs_ty = tree.nodes.items(.ty)[@int_from_enum(data.bin.lhs)];
            try config.set_color(w, TYPE);
            try lhs_ty.dump(mapper, tree.comp.langopts, w);
            try config.set_color(w, .reset);
            try w.write_byte('\n');

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("rhs: ");

            const rhs_ty = tree.nodes.items(.ty)[@int_from_enum(data.bin.rhs)];
            try config.set_color(w, TYPE);
            try rhs_ty.dump(mapper, tree.comp.langopts, w);
            try config.set_color(w, .reset);
            try w.write_byte('\n');
        },
        .if_then_stmt => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("cond:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);

            if (data.bin.rhs != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("then:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .switch_stmt, .while_stmt, .do_while_stmt => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("cond:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);

            if (data.bin.rhs != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("body:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .for_decl_stmt => {
            const for_decl = data.for_decl(tree);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("decl:\n");
            for (for_decl.decls) |decl| {
                try tree.dump_node(decl, level + delta, mapper, config, w);
                try w.write_byte('\n');
            }
            if (for_decl.cond != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("cond:\n");
                try tree.dump_node(for_decl.cond, level + delta, mapper, config, w);
            }
            if (for_decl.incr != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("incr:\n");
                try tree.dump_node(for_decl.incr, level + delta, mapper, config, w);
            }
            if (for_decl.body != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("body:\n");
                try tree.dump_node(for_decl.body, level + delta, mapper, config, w);
            }
        },
        .forever_stmt => {
            if (data.un != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("body:\n");
                try tree.dump_node(data.un, level + delta, mapper, config, w);
            }
        },
        .for_stmt => {
            const for_stmt = data.for_stmt(tree);

            if (for_stmt.init != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("init:\n");
                try tree.dump_node(for_stmt.init, level + delta, mapper, config, w);
            }
            if (for_stmt.cond != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("cond:\n");
                try tree.dump_node(for_stmt.cond, level + delta, mapper, config, w);
            }
            if (for_stmt.incr != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("incr:\n");
                try tree.dump_node(for_stmt.incr, level + delta, mapper, config, w);
            }
            if (for_stmt.body != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("body:\n");
                try tree.dump_node(for_stmt.body, level + delta, mapper, config, w);
            }
        },
        .goto_stmt, .addr_of_label => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("label: ");
            try config.set_color(w, LITERAL);
            try w.print("{s}\n", .{tree.tok_slice(data.decl_ref)});
            try config.set_color(w, .reset);
        },
        .continue_stmt, .break_stmt, .implicit_return, .null_stmt => {},
        .return_stmt => {
            if (data.un != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("expr:\n");
                try tree.dump_node(data.un, level + delta, mapper, config, w);
            }
        },
        .call_expr => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("lhs:\n");
            try tree.dump_node(tree.data[data.range.start], level + delta, mapper, config, w);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("args:\n");
            for (tree.data[data.range.start + 1 .. data.range.end]) |arg| try tree.dump_node(arg, level + delta, mapper, config, w);
        },
        .call_expr_one => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("lhs:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            if (data.bin.rhs != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("arg:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .builtin_call_expr => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(@int_from_enum(tree.data[data.range.start]))});
            try config.set_color(w, .reset);

            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("args:\n");
            for (tree.data[data.range.start + 1 .. data.range.end]) |arg| try tree.dump_node(arg, level + delta, mapper, config, w);
        },
        .builtin_call_expr_one => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("arg:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .special_builtin_call_one => {
            try w.write_byte_ntimes(' ', level + half);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl.name)});
            try config.set_color(w, .reset);
            if (data.decl.node != .none) {
                try w.write_byte_ntimes(' ', level + half);
                try w.write_all("arg:\n");
                try tree.dump_node(data.decl.node, level + delta, mapper, config, w);
            }
        },
        .comma_expr,
        .assign_expr,
        .mul_assign_expr,
        .div_assign_expr,
        .mod_assign_expr,
        .add_assign_expr,
        .sub_assign_expr,
        .shl_assign_expr,
        .shr_assign_expr,
        .bit_and_assign_expr,
        .bit_xor_assign_expr,
        .bit_or_assign_expr,
        .bool_or_expr,
        .bool_and_expr,
        .bit_or_expr,
        .bit_xor_expr,
        .bit_and_expr,
        .equal_expr,
        .not_equal_expr,
        .less_than_expr,
        .less_than_equal_expr,
        .greater_than_expr,
        .greater_than_equal_expr,
        .shl_expr,
        .shr_expr,
        .add_expr,
        .sub_expr,
        .mul_expr,
        .div_expr,
        .mod_expr,
        => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("lhs:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("rhs:\n");
            try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
        },
        .explicit_cast, .implicit_cast => try tree.dump_node(data.cast.operand, level + delta, mapper, config, w),
        .addr_of_expr,
        .computed_goto_stmt,
        .deref_expr,
        .plus_expr,
        .negate_expr,
        .bit_not_expr,
        .bool_not_expr,
        .pre_inc_expr,
        .pre_dec_expr,
        .imag_expr,
        .real_expr,
        .post_inc_expr,
        .post_dec_expr,
        .paren_expr,
        => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("operand:\n");
            try tree.dump_node(data.un, level + delta, mapper, config, w);
        },
        .decl_ref_expr => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl_ref)});
            try config.set_color(w, .reset);
        },
        .enumeration_ref => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{tree.tok_slice(data.decl_ref)});
            try config.set_color(w, .reset);
        },
        .bool_literal,
        .nullptr_literal,
        .int_literal,
        .char_literal,
        .float_literal,
        .string_literal_expr,
        => {},
        .member_access_expr, .member_access_ptr_expr => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("lhs:\n");
            try tree.dump_node(data.member.lhs, level + delta, mapper, config, w);

            var lhs_ty = tree.nodes.items(.ty)[@int_from_enum(data.member.lhs)];
            if (lhs_ty.is_ptr()) lhs_ty = lhs_ty.elem_type();
            lhs_ty = lhs_ty.canonicalize(.standard);

            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("name: ");
            try config.set_color(w, NAME);
            try w.print("{s}\n", .{mapper.lookup(lhs_ty.data.record.fields[data.member.index].name)});
            try config.set_color(w, .reset);
        },
        .array_access_expr => {
            if (data.bin.lhs != .none) {
                try w.write_byte_ntimes(' ', level + 1);
                try w.write_all("lhs:\n");
                try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            }
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("index:\n");
            try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
        },
        .sizeof_expr, .alignof_expr => {
            if (data.un != .none) {
                try w.write_byte_ntimes(' ', level + 1);
                try w.write_all("expr:\n");
                try tree.dump_node(data.un, level + delta, mapper, config, w);
            }
        },
        .generic_expr_one => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("controlling:\n");
            try tree.dump_node(data.bin.lhs, level + delta, mapper, config, w);
            try w.write_byte_ntimes(' ', level + 1);
            if (data.bin.rhs != .none) {
                try w.write_all("chosen:\n");
                try tree.dump_node(data.bin.rhs, level + delta, mapper, config, w);
            }
        },
        .generic_expr => {
            const nodes = tree.data[data.range.start..data.range.end];
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("controlling:\n");
            try tree.dump_node(nodes[0], level + delta, mapper, config, w);
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("chosen:\n");
            try tree.dump_node(nodes[1], level + delta, mapper, config, w);
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("rest:\n");
            for (nodes[2..]) |expr| {
                try tree.dump_node(expr, level + delta, mapper, config, w);
            }
        },
        .generic_association_expr, .generic_default_expr, .stmt_expr, .imaginary_literal => {
            try tree.dump_node(data.un, level + delta, mapper, config, w);
        },
        .array_filler_expr => {
            try w.write_byte_ntimes(' ', level + 1);
            try w.write_all("count: ");
            try config.set_color(w, LITERAL);
            try w.print("{d}\n", .{data.int});
            try config.set_color(w, .reset);
        },
        .struct_forward_decl,
        .union_forward_decl,
        .enum_forward_decl,
        .default_init_expr,
        .cond_dummy_expr,
        => {},
    }
}
