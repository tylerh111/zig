const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const big = std.math.big;
const Compilation = @import("Compilation.zig");
const Source = @import("Source.zig");
const Tokenizer = @import("Tokenizer.zig");
const Preprocessor = @import("Preprocessor.zig");
const Tree = @import("Tree.zig");
const Token = Tree.Token;
const NumberPrefix = Token.NumberPrefix;
const NumberSuffix = Token.NumberSuffix;
const TokenIndex = Tree.TokenIndex;
const NodeIndex = Tree.NodeIndex;
const Type = @import("Type.zig");
const Diagnostics = @import("Diagnostics.zig");
const NodeList = std.ArrayList(NodeIndex);
const InitList = @import("InitList.zig");
const Attribute = @import("Attribute.zig");
const char_info = @import("char_info.zig");
const text_literal = @import("text_literal.zig");
const Value = @import("Value.zig");
const SymbolStack = @import("SymbolStack.zig");
const Symbol = SymbolStack.Symbol;
const record_layout = @import("record_layout.zig");
const StrInt = @import("StringInterner.zig");
const StringId = StrInt.StringId;
const Builtins = @import("Builtins.zig");
const Builtin = Builtins.Builtin;
const target_util = @import("target.zig");

const Switch = struct {
    default: ?TokenIndex = null,
    ranges: std.ArrayList(Range),
    ty: Type,
    comp: *Compilation,

    const Range = struct {
        first: Value,
        last: Value,
        tok: TokenIndex,
    };

    fn add(self: *Switch, first: Value, last: Value, tok: TokenIndex) !?Range {
        for (self.ranges.items) |range| {
            if (last.compare(.gte, range.first, self.comp) and first.compare(.lte, range.last, self.comp)) {
                return range; // They overlap.
            }
        }
        try self.ranges.append(.{
            .first = first,
            .last = last,
            .tok = tok,
        });
        return null;
    }
};

const Label = union(enum) {
    unresolved_goto: TokenIndex,
    label: TokenIndex,
};

pub const Error = Compilation.Error || error{ParsingFailed};

/// An attribute that has been parsed but not yet validated in its context
const TentativeAttribute = struct {
    attr: Attribute,
    tok: TokenIndex,
};

/// How the parser handles const int decl references when it is expecting an integer
/// constant expression.
const ConstDeclFoldingMode = enum {
    /// fold const decls as if they were literals
    fold_const_decls,
    /// fold const decls as if they were literals and issue GNU extension diagnostic
    gnu_folding_extension,
    /// fold const decls as if they were literals and issue VLA diagnostic
    gnu_vla_folding_extension,
    /// folding const decls is prohibited; return an unavailable value
    no_const_decl_folding,
};

const Parser = @This();

// values from preprocessor
pp: *Preprocessor,
comp: *Compilation,
gpa: mem.Allocator,
tok_ids: []const Token.Id,
tok_i: TokenIndex = 0,

// values of the incomplete Tree
arena: Allocator,
nodes: Tree.Node.List = .{},
data: NodeList,
value_map: Tree.ValueMap,

// buffers used during compilation
syms: SymbolStack = .{},
strings: std.ArrayList(u8),
labels: std.ArrayList(Label),
list_buf: NodeList,
decl_buf: NodeList,
param_buf: std.ArrayList(Type.Func.Param),
enum_buf: std.ArrayList(Type.Enum.Field),
record_buf: std.ArrayList(Type.Record.Field),
attr_buf: std.MultiArrayList(TentativeAttribute) = .{},
attr_application_buf: std.ArrayListUnmanaged(Attribute) = .{},
field_attr_buf: std.ArrayList([]const Attribute),
/// type name -> variable name location for tentative definitions (top-level defs with thus-far-incomplete types)
/// e.g. `struct Foo bar;` where `struct Foo` is not defined yet.
/// The key is the StringId of `Foo` and the value is the TokenIndex of `bar`
/// Items are removed if the type is subsequently completed with a definition.
/// We only store the first tentative definition that uses a given type because this map is only used
/// for issuing an error message, and correcting the first error for a type will fix all of them for that type.
tentative_defs: std.AutoHashMapUnmanaged(StringId, TokenIndex) = .{},

// configuration and miscellaneous info
no_eval: bool = false,
in_macro: bool = false,
extension_suppressed: bool = false,
contains_address_of_label: bool = false,
label_count: u32 = 0,
const_decl_folding: ConstDeclFoldingMode = .fold_const_decls,
/// location of first computed goto in function currently being parsed
/// if a computed goto is used, the function must contain an
/// address-of-label expression (tracked with contains_address_of_label)
computed_goto_tok: ?TokenIndex = null,

/// Various variables that are different for each function.
func: struct {
    /// null if not in function, will always be plain func, var_args_func or old_style_func
    ty: ?Type = null,
    name: TokenIndex = 0,
    ident: ?Result = null,
    pretty_ident: ?Result = null,
} = .{},
/// Various variables that are different for each record.
record: struct {
    // invalid means we're not parsing a record
    kind: Token.Id = .invalid,
    flexible_field: ?TokenIndex = null,
    start: usize = 0,
    field_attr_start: usize = 0,

    fn add_field(r: @This(), p: *Parser, name: StringId, tok: TokenIndex) Error!void {
        var i = p.record_members.items.len;
        while (i > r.start) {
            i -= 1;
            if (p.record_members.items[i].name == name) {
                try p.err_str(.duplicate_member, tok, p.tok_slice(tok));
                try p.err_tok(.previous_definition, p.record_members.items[i].tok);
                break;
            }
        }
        try p.record_members.append(p.gpa, .{ .name = name, .tok = tok });
    }

    fn add_fields_from_anonymous(r: @This(), p: *Parser, ty: Type) Error!void {
        for (ty.data.record.fields) |f| {
            if (f.is_anonymous_record()) {
                try r.add_fields_from_anonymous(p, f.ty.canonicalize(.standard));
            } else if (f.name_tok != 0) {
                try r.add_field(p, f.name, f.name_tok);
            }
        }
    }
} = .{},
record_members: std.ArrayListUnmanaged(struct { tok: TokenIndex, name: StringId }) = .{},
@"switch": ?*Switch = null,
in_loop: bool = false,
pragma_pack: ?u8 = null,
string_ids: struct {
    declspec_id: StringId,
    main_id: StringId,
    file: StringId,
    jmp_buf: StringId,
    sigjmp_buf: StringId,
    ucontext_t: StringId,
},

/// Checks codepoint for various pedantic warnings
/// Returns true if diagnostic issued
fn check_identifier_codepoint_warnings(comp: *Compilation, codepoint: u21, loc: Source.Location) Compilation.Error!bool {
    assert(codepoint >= 0x80);

    const err_start = comp.diagnostics.list.items.len;

    if (!char_info.is_c99_id_char(codepoint)) {
        try comp.addDiagnostic(.{
            .tag = .c99_compat,
            .loc = loc,
        }, &.{});
    }
    if (char_info.is_invisible(codepoint)) {
        try comp.addDiagnostic(.{
            .tag = .unicode_zero_width,
            .loc = loc,
            .extra = .{ .actual_codepoint = codepoint },
        }, &.{});
    }
    if (char_info.homoglyph(codepoint)) |resembles| {
        try comp.addDiagnostic(.{
            .tag = .unicode_homoglyph,
            .loc = loc,
            .extra = .{ .codepoints = .{ .actual = codepoint, .resembles = resembles } },
        }, &.{});
    }
    return comp.diagnostics.list.items.len != err_start;
}

/// Issues diagnostics for the current extended identifier token
/// Return value indicates whether the token should be considered an identifier
/// true means consider the token to actually be an identifier
/// false means it is not
fn validate_extended_identifier(p: *Parser) !bool {
    assert(p.tok_ids[p.tok_i] == .extended_identifier);

    const slice = p.tok_slice(p.tok_i);
    const view = std.unicode.Utf8View.init(slice) catch {
        try p.err_tok(.invalid_utf8, p.tok_i);
        return error.FatalError;
    };
    var it = view.iterator();

    var valid_identifier = true;
    var warned = false;
    var len: usize = 0;
    var invalid_char: u21 = undefined;
    var loc = p.pp.tokens.items(.loc)[p.tok_i];

    var normalized = true;
    var last_canonical_class: char_info.CanonicalCombiningClass = .not_reordered;
    const standard = p.comp.langopts.standard;
    while (it.next_codepoint()) |codepoint| {
        defer {
            len += 1;
            loc.byte_offset += std.unicode.utf8_codepoint_sequence_length(codepoint) catch unreachable;
        }
        if (codepoint == '$') {
            warned = true;
            if (p.comp.langopts.dollars_in_identifiers) try p.comp.addDiagnostic(.{
                .tag = .dollar_in_identifier_extension,
                .loc = loc,
            }, &.{});
        }

        if (codepoint <= 0x7F) continue;
        if (!valid_identifier) continue;

        const allowed = standard.codepoint_allowed_in_identifier(codepoint, len == 0);
        if (!allowed) {
            invalid_char = codepoint;
            valid_identifier = false;
            continue;
        }

        if (!warned) {
            warned = try check_identifier_codepoint_warnings(p.comp, codepoint, loc);
        }

        // Check NFC normalization.
        if (!normalized) continue;
        const canonical_class = char_info.get_canonical_class(codepoint);
        if (@int_from_enum(last_canonical_class) > @int_from_enum(canonical_class) and
            canonical_class != .not_reordered)
        {
            normalized = false;
            try p.err_str(.identifier_not_normalized, p.tok_i, slice);
            continue;
        }
        if (char_info.is_normalized(codepoint) != .yes) {
            normalized = false;
            try p.err_extra(.identifier_not_normalized, p.tok_i, .{ .normalized = slice });
        }
        last_canonical_class = canonical_class;
    }

    if (!valid_identifier) {
        if (len == 1) {
            try p.err_extra(.unexpected_character, p.tok_i, .{ .actual_codepoint = invalid_char });
            return false;
        } else {
            try p.err_extra(.invalid_identifier_start_char, p.tok_i, .{ .actual_codepoint = invalid_char });
        }
    }

    return true;
}

fn eat_identifier(p: *Parser) !?TokenIndex {
    switch (p.tok_ids[p.tok_i]) {
        .identifier => {},
        .extended_identifier => {
            if (!try p.validate_extended_identifier()) {
                p.tok_i += 1;
                return null;
            }
        },
        else => return null,
    }
    p.tok_i += 1;

    // Handle illegal '$' characters in identifiers
    if (!p.comp.langopts.dollars_in_identifiers) {
        if (p.tok_ids[p.tok_i] == .invalid and p.tok_slice(p.tok_i)[0] == '$') {
            try p.err(.dollars_in_identifiers);
            p.tok_i += 1;
            return error.ParsingFailed;
        }
    }

    return p.tok_i - 1;
}

fn expect_identifier(p: *Parser) Error!TokenIndex {
    const actual = p.tok_ids[p.tok_i];
    if (actual != .identifier and actual != .extended_identifier) {
        return p.err_expected_token(.identifier, actual);
    }

    return (try p.eat_identifier()) orelse error.ParsingFailed;
}

fn eat_token(p: *Parser, id: Token.Id) ?TokenIndex {
    assert(id != .identifier and id != .extended_identifier); // use eat_identifier
    if (p.tok_ids[p.tok_i] == id) {
        defer p.tok_i += 1;
        return p.tok_i;
    } else return null;
}

fn expect_token(p: *Parser, expected: Token.Id) Error!TokenIndex {
    assert(expected != .identifier and expected != .extended_identifier); // use expect_identifier
    const actual = p.tok_ids[p.tok_i];
    if (actual != expected) return p.err_expected_token(expected, actual);
    defer p.tok_i += 1;
    return p.tok_i;
}

pub fn tok_slice(p: *Parser, tok: TokenIndex) []const u8 {
    if (p.tok_ids[tok].lexeme()) |some| return some;
    const loc = p.pp.tokens.items(.loc)[tok];
    var tmp_tokenizer = Tokenizer{
        .buf = p.comp.get_source(loc.id).buf,
        .langopts = p.comp.langopts,
        .index = loc.byte_offset,
        .source = .generated,
    };
    const res = tmp_tokenizer.next();
    return tmp_tokenizer.buf[res.start..res.end];
}

fn expect_closing(p: *Parser, opening: TokenIndex, id: Token.Id) Error!void {
    _ = p.expect_token(id) catch |e| {
        if (e == error.ParsingFailed) {
            try p.err_tok(switch (id) {
                .r_paren => .to_match_paren,
                .r_brace => .to_match_brace,
                .r_bracket => .to_match_brace,
                else => unreachable,
            }, opening);
        }
        return e;
    };
}

fn err_overflow(p: *Parser, op_tok: TokenIndex, res: Result) !void {
    try p.err_str(.overflow, op_tok, try res.str(p));
}

fn err_expected_token(p: *Parser, expected: Token.Id, actual: Token.Id) Error {
    switch (actual) {
        .invalid => try p.err_extra(.expected_invalid, p.tok_i, .{ .tok_id_expected = expected }),
        .eof => try p.err_extra(.expected_eof, p.tok_i, .{ .tok_id_expected = expected }),
        else => try p.err_extra(.expected_token, p.tok_i, .{ .tok_id = .{
            .expected = expected,
            .actual = actual,
        } }),
    }
    return error.ParsingFailed;
}

pub fn err_str(p: *Parser, tag: Diagnostics.Tag, tok_i: TokenIndex, str: []const u8) Compilation.Error!void {
    @setCold(true);
    return p.err_extra(tag, tok_i, .{ .str = str });
}

pub fn err_extra(p: *Parser, tag: Diagnostics.Tag, tok_i: TokenIndex, extra: Diagnostics.Message.Extra) Compilation.Error!void {
    @setCold(true);
    const tok = p.pp.tokens.get(tok_i);
    var loc = tok.loc;
    if (tok_i != 0 and tok.id == .eof) {
        // if the token is EOF, point at the end of the previous token instead
        const prev = p.pp.tokens.get(tok_i - 1);
        loc = prev.loc;
        loc.byte_offset += @int_cast(p.tok_slice(tok_i - 1).len);
    }
    try p.comp.addDiagnostic(.{
        .tag = tag,
        .loc = loc,
        .extra = extra,
    }, p.pp.expansion_slice(tok_i));
}

pub fn err_tok(p: *Parser, tag: Diagnostics.Tag, tok_i: TokenIndex) Compilation.Error!void {
    @setCold(true);
    return p.err_extra(tag, tok_i, .{ .none = {} });
}

pub fn err(p: *Parser, tag: Diagnostics.Tag) Compilation.Error!void {
    @setCold(true);
    return p.err_extra(tag, p.tok_i, .{ .none = {} });
}

pub fn todo(p: *Parser, msg: []const u8) Error {
    try p.err_str(.todo, p.tok_i, msg);
    return error.ParsingFailed;
}

pub fn remove_null(p: *Parser, str: Value) !Value {
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;
    {
        const bytes = p.comp.interner.get(str.ref()).bytes;
        try p.strings.append_slice(bytes[0 .. bytes.len - 1]);
    }
    return Value.intern(p.comp, .{ .bytes = p.strings.items[strings_top..] });
}

pub fn type_str(p: *Parser, ty: Type) ![]const u8 {
    if (@import("builtin").mode != .Debug) {
        if (ty.is(.invalid)) {
            return "Tried to render invalid type - this is an aro bug.";
        }
    }
    if (Type.Builder.from_type(ty).str(p.comp.langopts)) |str| return str;
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    const mapper = p.comp.string_interner.get_slow_type_mapper();
    try ty.print(mapper, p.comp.langopts, p.strings.writer());
    return try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
}

pub fn type_pair_str(p: *Parser, a: Type, b: Type) ![]const u8 {
    return p.type_pair_str_extra(a, " and ", b);
}

pub fn type_pair_str_extra(p: *Parser, a: Type, msg: []const u8, b: Type) ![]const u8 {
    if (@import("builtin").mode != .Debug) {
        if (a.is(.invalid) or b.is(.invalid)) {
            return "Tried to render invalid type - this is an aro bug.";
        }
    }
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    try p.strings.append('\'');
    const mapper = p.comp.string_interner.get_slow_type_mapper();
    try a.print(mapper, p.comp.langopts, p.strings.writer());
    try p.strings.append('\'');
    try p.strings.append_slice(msg);
    try p.strings.append('\'');
    try b.print(mapper, p.comp.langopts, p.strings.writer());
    try p.strings.append('\'');
    return try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
}

pub fn float_value_changed_str(p: *Parser, res: *Result, old_value: Value, int_ty: Type) ![]const u8 {
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    var w = p.strings.writer();
    const type_pair_str = try p.type_pair_str_extra(res.ty, " to ", int_ty);
    try w.write_all(type_pair_str);

    try w.write_all(" changes ");
    if (res.val.is_zero(p.comp)) try w.write_all("non-zero ");
    try w.write_all("value from ");
    try old_value.print(res.ty, p.comp, w);
    try w.write_all(" to ");
    try res.val.print(int_ty, p.comp, w);

    return try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
}

fn check_deprecated_unavailable(p: *Parser, ty: Type, usage_tok: TokenIndex, decl_tok: TokenIndex) !void {
    if (ty.get_attribute(.@"error")) |@"error"| {
        const strings_top = p.strings.items.len;
        defer p.strings.items.len = strings_top;

        const w = p.strings.writer();
        const msg_str = p.comp.interner.get(@"error".msg.ref()).bytes;
        try w.print("call to '{s}' declared with attribute error: {}", .{
            p.tok_slice(@"error".__name_tok), std.zig.fmt_escapes(msg_str),
        });
        const str = try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
        try p.err_str(.error_attribute, usage_tok, str);
    }
    if (ty.get_attribute(.warning)) |warning| {
        const strings_top = p.strings.items.len;
        defer p.strings.items.len = strings_top;

        const w = p.strings.writer();
        const msg_str = p.comp.interner.get(warning.msg.ref()).bytes;
        try w.print("call to '{s}' declared with attribute warning: {}", .{
            p.tok_slice(warning.__name_tok), std.zig.fmt_escapes(msg_str),
        });
        const str = try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
        try p.err_str(.warning_attribute, usage_tok, str);
    }
    if (ty.get_attribute(.unavailable)) |unavailable| {
        try p.err_deprecated(.unavailable, usage_tok, unavailable.msg);
        try p.err_str(.unavailable_note, unavailable.__name_tok, p.tok_slice(decl_tok));
        return error.ParsingFailed;
    } else if (ty.get_attribute(.deprecated)) |deprecated| {
        try p.err_deprecated(.deprecated_declarations, usage_tok, deprecated.msg);
        try p.err_str(.deprecated_note, deprecated.__name_tok, p.tok_slice(decl_tok));
    }
}

fn err_deprecated(p: *Parser, tag: Diagnostics.Tag, tok_i: TokenIndex, msg: ?Value) Compilation.Error!void {
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    const w = p.strings.writer();
    try w.print("'{s}' is ", .{p.tok_slice(tok_i)});
    const reason: []const u8 = switch (tag) {
        .unavailable => "unavailable",
        .deprecated_declarations => "deprecated",
        else => unreachable,
    };
    try w.write_all(reason);
    if (msg) |m| {
        const str = p.comp.interner.get(m.ref()).bytes;
        try w.print(": {}", .{std.zig.fmt_escapes(str)});
    }
    const str = try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
    return p.err_str(tag, tok_i, str);
}

fn add_node(p: *Parser, node: Tree.Node) Allocator.Error!NodeIndex {
    if (p.in_macro) return .none;
    const res = p.nodes.len;
    try p.nodes.append(p.gpa, node);
    return @enumFromInt(res);
}

fn add_list(p: *Parser, nodes: []const NodeIndex) Allocator.Error!Tree.Node.Range {
    if (p.in_macro) return Tree.Node.Range{ .start = 0, .end = 0 };
    const start: u32 = @int_cast(p.data.items.len);
    try p.data.append_slice(nodes);
    const end: u32 = @int_cast(p.data.items.len);
    return Tree.Node.Range{ .start = start, .end = end };
}

fn find_label(p: *Parser, name: []const u8) ?TokenIndex {
    for (p.labels.items) |item| {
        switch (item) {
            .label => |l| if (mem.eql(u8, p.tok_slice(l), name)) return l,
            .unresolved_goto => {},
        }
    }
    return null;
}

fn node_is(p: *Parser, node: NodeIndex, tag: Tree.Tag) bool {
    return p.get_node(node, tag) != null;
}

fn get_node(p: *Parser, node: NodeIndex, tag: Tree.Tag) ?NodeIndex {
    var cur = node;
    const tags = p.nodes.items(.tag);
    const data = p.nodes.items(.data);
    while (true) {
        const cur_tag = tags[@int_from_enum(cur)];
        if (cur_tag == .paren_expr) {
            cur = data[@int_from_enum(cur)].un;
        } else if (cur_tag == tag) {
            return cur;
        } else {
            return null;
        }
    }
}

fn node_is_compound_literal(p: *Parser, node: NodeIndex) bool {
    var cur = node;
    const tags = p.nodes.items(.tag);
    const data = p.nodes.items(.data);
    while (true) {
        switch (tags[@int_from_enum(cur)]) {
            .paren_expr => cur = data[@int_from_enum(cur)].un,
            .compound_literal_expr,
            .static_compound_literal_expr,
            .thread_local_compound_literal_expr,
            .static_thread_local_compound_literal_expr,
            => return true,
            else => return false,
        }
    }
}

fn tmp_tree(p: *Parser) Tree {
    return .{
        .nodes = p.nodes.slice(),
        .data = p.data.items,
        .value_map = p.value_map,
        .comp = p.comp,
        .arena = undefined,
        .generated = undefined,
        .tokens = undefined,
        .root_decls = undefined,
    };
}

fn pragma(p: *Parser) Compilation.Error!bool {
    var found_pragma = false;
    while (p.eat_token(.keyword_pragma)) |_| {
        found_pragma = true;

        const name_tok = p.tok_i;
        const name = p.tok_slice(name_tok);

        const end_idx = mem.index_of_scalar_pos(Token.Id, p.tok_ids, p.tok_i, .nl).?;
        const pragma_len = @as(TokenIndex, @int_cast(end_idx)) - p.tok_i;
        defer p.tok_i += pragma_len + 1; // skip past .nl as well
        if (p.comp.get_pragma(name)) |prag| {
            try prag.parser_cb(p, p.tok_i);
        }
    }
    return found_pragma;
}

/// Issue errors for top-level definitions whose type was never completed.
fn diagnose_incomplete_definitions(p: *Parser) !void {
    @setCold(true);

    const node_slices = p.nodes.slice();
    const tags = node_slices.items(.tag);
    const tys = node_slices.items(.ty);
    const data = node_slices.items(.data);

    for (p.decl_buf.items) |decl_node| {
        const idx = @int_from_enum(decl_node);
        switch (tags[idx]) {
            .struct_forward_decl, .union_forward_decl, .enum_forward_decl => {},
            else => continue,
        }

        const ty = tys[idx];
        const decl_type_name = if (ty.get_record()) |rec|
            rec.name
        else if (ty.get(.@"enum")) |en|
            en.data.@"enum".name
        else
            unreachable;

        const tentative_def_tok = p.tentative_defs.get(decl_type_name) orelse continue;
        const type_str = try p.type_str(ty);
        try p.err_str(.tentative_definition_incomplete, tentative_def_tok, type_str);
        try p.err_str(.forward_declaration_here, data[idx].decl_ref, type_str);
    }
}

/// root : (decl | assembly ';' | static_assert)*
pub fn parse(pp: *Preprocessor) Compilation.Error!Tree {
    assert(pp.linemarkers == .none);
    pp.comp.pragma_event(.before_parse);

    var arena = std.heap.ArenaAllocator.init(pp.comp.gpa);
    errdefer arena.deinit();
    var p = Parser{
        .pp = pp,
        .comp = pp.comp,
        .gpa = pp.comp.gpa,
        .arena = arena.allocator(),
        .tok_ids = pp.tokens.items(.id),
        .strings = std.ArrayList(u8).init(pp.comp.gpa),
        .value_map = Tree.ValueMap.init(pp.comp.gpa),
        .data = NodeList.init(pp.comp.gpa),
        .labels = std.ArrayList(Label).init(pp.comp.gpa),
        .list_buf = NodeList.init(pp.comp.gpa),
        .decl_buf = NodeList.init(pp.comp.gpa),
        .param_buf = std.ArrayList(Type.Func.Param).init(pp.comp.gpa),
        .enum_buf = std.ArrayList(Type.Enum.Field).init(pp.comp.gpa),
        .record_buf = std.ArrayList(Type.Record.Field).init(pp.comp.gpa),
        .field_attr_buf = std.ArrayList([]const Attribute).init(pp.comp.gpa),
        .string_ids = .{
            .declspec_id = try StrInt.intern(pp.comp, "__declspec"),
            .main_id = try StrInt.intern(pp.comp, "main"),
            .file = try StrInt.intern(pp.comp, "FILE"),
            .jmp_buf = try StrInt.intern(pp.comp, "jmp_buf"),
            .sigjmp_buf = try StrInt.intern(pp.comp, "sigjmp_buf"),
            .ucontext_t = try StrInt.intern(pp.comp, "ucontext_t"),
        },
    };
    errdefer {
        p.nodes.deinit(pp.comp.gpa);
        p.value_map.deinit();
    }
    defer {
        p.data.deinit();
        p.labels.deinit();
        p.strings.deinit();
        p.syms.deinit(pp.comp.gpa);
        p.list_buf.deinit();
        p.decl_buf.deinit();
        p.param_buf.deinit();
        p.enum_buf.deinit();
        p.record_buf.deinit();
        p.record_members.deinit(pp.comp.gpa);
        p.attr_buf.deinit(pp.comp.gpa);
        p.attr_application_buf.deinit(pp.comp.gpa);
        p.tentative_defs.deinit(pp.comp.gpa);
        assert(p.field_attr_buf.items.len == 0);
        p.field_attr_buf.deinit();
    }

    try p.syms.push_scope(&p);
    defer p.syms.pop_scope();

    // NodeIndex 0 must be invalid
    _ = try p.add_node(.{ .tag = .invalid, .ty = undefined, .data = undefined });

    {
        if (p.comp.langopts.has_char8_t()) {
            try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "char8_t"), .{ .specifier = .uchar }, 0, .none);
        }
        try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "__int128_t"), .{ .specifier = .int128 }, 0, .none);
        try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "__uint128_t"), .{ .specifier = .uint128 }, 0, .none);

        const elem_ty = try p.arena.create(Type);
        elem_ty.* = .{ .specifier = .char };
        try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "__builtin_ms_va_list"), .{
            .specifier = .pointer,
            .data = .{ .sub_type = elem_ty },
        }, 0, .none);

        const ty = &pp.comp.types.va_list;
        try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "__builtin_va_list"), ty.*, 0, .none);

        if (ty.is_array()) ty.decay_array();

        try p.syms.define_typedef(&p, try StrInt.intern(p.comp, "__NSConstantString"), pp.comp.types.ns_constant_string.ty, 0, .none);
    }

    while (p.eat_token(.eof) == null) {
        if (try p.pragma()) continue;
        if (try p.parse_or_next_decl(static_assert)) continue;
        if (try p.parse_or_next_decl(decl)) continue;
        if (p.eat_token(.keyword_extension)) |_| {
            const saved_extension = p.extension_suppressed;
            defer p.extension_suppressed = saved_extension;
            p.extension_suppressed = true;

            if (try p.parse_or_next_decl(decl)) continue;
            switch (p.tok_ids[p.tok_i]) {
                .semicolon => p.tok_i += 1,
                .keyword_static_assert,
                .keyword_c23_static_assert,
                .keyword_pragma,
                .keyword_extension,
                .keyword_asm,
                .keyword_asm1,
                .keyword_asm2,
                => {},
                else => try p.err(.expected_external_decl),
            }
            continue;
        }
        if (p.assembly(.global) catch |er| switch (er) {
            error.ParsingFailed => {
                p.next_extern_decl();
                continue;
            },
            else => |e| return e,
        }) |node| {
            try p.decl_buf.append(node);
            continue;
        }
        if (p.eat_token(.semicolon)) |tok| {
            try p.err_tok(.extra_semi, tok);
            continue;
        }
        try p.err(.expected_external_decl);
        p.tok_i += 1;
    }
    if (p.tentative_defs.count() > 0) {
        try p.diagnose_incomplete_definitions();
    }

    const root_decls = try p.decl_buf.to_owned_slice();
    errdefer pp.comp.gpa.free(root_decls);
    if (root_decls.len == 0) {
        try p.err_tok(.empty_translation_unit, p.tok_i - 1);
    }
    pp.comp.pragma_event(.after_parse);

    const data = try p.data.to_owned_slice();
    errdefer pp.comp.gpa.free(data);
    return Tree{
        .comp = pp.comp,
        .tokens = pp.tokens.slice(),
        .arena = arena,
        .generated = pp.comp.generated_buf.items,
        .nodes = p.nodes.to_owned_slice(),
        .data = data,
        .root_decls = root_decls,
        .value_map = p.value_map,
    };
}

fn skip_to_pragma_sentinel(p: *Parser) void {
    while (true) : (p.tok_i += 1) {
        if (p.tok_ids[p.tok_i] == .nl) return;
        if (p.tok_ids[p.tok_i] == .eof) {
            p.tok_i -= 1;
            return;
        }
    }
}

fn parse_or_next_decl(p: *Parser, comptime func: fn (*Parser) Error!bool) Compilation.Error!bool {
    return func(p) catch |er| switch (er) {
        error.ParsingFailed => {
            p.next_extern_decl();
            return true;
        },
        else => |e| return e,
    };
}

fn next_extern_decl(p: *Parser) void {
    var parens: u32 = 0;
    while (true) : (p.tok_i += 1) {
        switch (p.tok_ids[p.tok_i]) {
            .l_paren, .l_brace, .l_bracket => parens += 1,
            .r_paren, .r_brace, .r_bracket => if (parens != 0) {
                parens -= 1;
            },
            .keyword_typedef,
            .keyword_extern,
            .keyword_static,
            .keyword_auto,
            .keyword_register,
            .keyword_thread_local,
            .keyword_c23_thread_local,
            .keyword_inline,
            .keyword_inline1,
            .keyword_inline2,
            .keyword_noreturn,
            .keyword_void,
            .keyword_bool,
            .keyword_c23_bool,
            .keyword_char,
            .keyword_short,
            .keyword_int,
            .keyword_long,
            .keyword_signed,
            .keyword_unsigned,
            .keyword_float,
            .keyword_double,
            .keyword_complex,
            .keyword_atomic,
            .keyword_enum,
            .keyword_struct,
            .keyword_union,
            .keyword_alignas,
            .keyword_c23_alignas,
            .identifier,
            .extended_identifier,
            .keyword_typeof,
            .keyword_typeof1,
            .keyword_typeof2,
            .keyword_typeof_unqual,
            .keyword_extension,
            .keyword_bit_int,
            => if (parens == 0) return,
            .keyword_pragma => p.skip_to_pragma_sentinel(),
            .eof => return,
            .semicolon => if (parens == 0) {
                p.tok_i += 1;
                return;
            },
            else => {},
        }
    }
}

fn skip_to(p: *Parser, id: Token.Id) void {
    var parens: u32 = 0;
    while (true) : (p.tok_i += 1) {
        if (p.tok_ids[p.tok_i] == id and parens == 0) {
            p.tok_i += 1;
            return;
        }
        switch (p.tok_ids[p.tok_i]) {
            .l_paren, .l_brace, .l_bracket => parens += 1,
            .r_paren, .r_brace, .r_bracket => if (parens != 0) {
                parens -= 1;
            },
            .keyword_pragma => p.skip_to_pragma_sentinel(),
            .eof => return,
            else => {},
        }
    }
}

/// Called after a typedef is defined
fn typedef_defined(p: *Parser, name: StringId, ty: Type) void {
    if (name == p.string_ids.file) {
        p.comp.types.file = ty;
    } else if (name == p.string_ids.jmp_buf) {
        p.comp.types.jmp_buf = ty;
    } else if (name == p.string_ids.sigjmp_buf) {
        p.comp.types.sigjmp_buf = ty;
    } else if (name == p.string_ids.ucontext_t) {
        p.comp.types.ucontext_t = ty;
    }
}

// ====== declarations ======

/// decl
///  : decl_spec (init_declarator ( ',' init_declarator)*)? ';'
///  | decl_spec declarator decl* compound_stmt
fn decl(p: *Parser) Error!bool {
    _ = try p.pragma();
    const first_tok = p.tok_i;
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;

    try p.attribute_specifier();

    var decl_spec = if (try p.decl_spec()) |some| some else blk: {
        if (p.func.ty != null) {
            p.tok_i = first_tok;
            return false;
        }
        switch (p.tok_ids[first_tok]) {
            .asterisk, .l_paren, .identifier, .extended_identifier => {},
            else => if (p.tok_i != first_tok) {
                try p.err(.expected_ident_or_l_paren);
                return error.ParsingFailed;
            } else return false,
        }
        var spec: Type.Builder = .{};
        break :blk DeclSpec{ .ty = try spec.finish(p) };
    };
    if (decl_spec.noreturn) |tok| {
        const attr = Attribute{ .tag = .noreturn, .args = .{ .noreturn = .{} }, .syntax = .keyword };
        try p.attr_buf.append(p.gpa, .{ .attr = attr, .tok = tok });
    }
    var init_d = (try p.init_declarator(&decl_spec, attr_buf_top)) orelse {
        _ = try p.expect_token(.semicolon);
        if (decl_spec.ty.is(.@"enum") or
            (decl_spec.ty.is_record() and !decl_spec.ty.is_anonymous_record(p.comp) and
            !decl_spec.ty.is_typeof())) // we follow GCC and clang's behavior here
        {
            const specifier = decl_spec.ty.canonicalize(.standard).specifier;
            const attrs = p.attr_buf.items(.attr)[attr_buf_top..];
            const toks = p.attr_buf.items(.tok)[attr_buf_top..];
            for (attrs, toks) |attr, tok| {
                try p.err_extra(.ignored_record_attr, tok, .{
                    .ignored_record_attr = .{ .tag = attr.tag, .specifier = switch (specifier) {
                        .@"enum" => .@"enum",
                        .@"struct" => .@"struct",
                        .@"union" => .@"union",
                        else => unreachable,
                    } },
                });
            }
            return true;
        }

        try p.err_tok(.missing_declaration, first_tok);
        return true;
    };

    // Check for function definition.
    if (init_d.d.func_declarator != null and init_d.initializer.node == .none and init_d.d.ty.is_func()) fn_def: {
        if (decl_spec.auto_type) |tok_i| {
            try p.err_str(.auto_type_not_allowed, tok_i, "function return type");
            return error.ParsingFailed;
        }

        switch (p.tok_ids[p.tok_i]) {
            .comma, .semicolon => break :fn_def,
            .l_brace => {},
            else => if (init_d.d.old_style_func == null) {
                try p.err(.expected_fn_body);
                return true;
            },
        }
        if (p.func.ty != null) try p.err(.func_not_in_root);

        const node = try p.add_node(undefined); // reserve space
        const interned_declarator_name = try StrInt.intern(p.comp, p.tok_slice(init_d.d.name));
        try p.syms.define_symbol(p, interned_declarator_name, init_d.d.ty, init_d.d.name, node, .{}, false);

        const func = p.func;
        p.func = .{
            .ty = init_d.d.ty,
            .name = init_d.d.name,
        };
        if (interned_declarator_name == p.string_ids.main_id and !init_d.d.ty.return_type().is(.int)) {
            try p.err_tok(.main_return_type, init_d.d.name);
        }
        defer p.func = func;

        try p.syms.push_scope(p);
        defer p.syms.pop_scope();

        // Collect old style parameter declarations.
        if (init_d.d.old_style_func != null) {
            const attrs = init_d.d.ty.get_attributes();
            var base_ty = if (init_d.d.ty.specifier == .attributed) init_d.d.ty.data.attributed.base else init_d.d.ty;
            base_ty.specifier = .func;
            init_d.d.ty = try base_ty.with_attributes(p.arena, attrs);

            const param_buf_top = p.param_buf.items.len;
            defer p.param_buf.items.len = param_buf_top;

            param_loop: while (true) {
                const param_decl_spec = (try p.decl_spec()) orelse break;
                if (p.eat_token(.semicolon)) |semi| {
                    try p.err_tok(.missing_declaration, semi);
                    continue :param_loop;
                }

                while (true) {
                    const attr_buf_top_declarator = p.attr_buf.len;
                    defer p.attr_buf.len = attr_buf_top_declarator;

                    var d = (try p.declarator(param_decl_spec.ty, .param)) orelse {
                        try p.err_tok(.missing_declaration, first_tok);
                        _ = try p.expect_token(.semicolon);
                        continue :param_loop;
                    };
                    try p.attribute_specifier();

                    if (d.ty.has_incomplete_size() and !d.ty.is(.void)) try p.err_str(.parameter_incomplete_ty, d.name, try p.type_str(d.ty));
                    if (d.ty.is_func()) {
                        // Params declared as functions are converted to function pointers.
                        const elem_ty = try p.arena.create(Type);
                        elem_ty.* = d.ty;
                        d.ty = Type{
                            .specifier = .pointer,
                            .data = .{ .sub_type = elem_ty },
                        };
                    } else if (d.ty.is_array()) {
                        // params declared as arrays are converted to pointers
                        d.ty.decay_array();
                    } else if (d.ty.is(.void)) {
                        try p.err_tok(.invalid_void_param, d.name);
                    }

                    // find and correct parameter types
                    // TODO check for missing declarations and redefinitions
                    const name_str = p.tok_slice(d.name);
                    const interned_name = try StrInt.intern(p.comp, name_str);
                    for (init_d.d.ty.params()) |*param| {
                        if (param.name == interned_name) {
                            param.ty = d.ty;
                            break;
                        }
                    } else {
                        try p.err_str(.parameter_missing, d.name, name_str);
                    }
                    d.ty = try Attribute.applyParameterAttributes(p, d.ty, attr_buf_top_declarator, .alignas_on_param);

                    // bypass redefinition check to avoid duplicate errors
                    try p.syms.define(p.gpa, .{
                        .kind = .def,
                        .name = interned_name,
                        .tok = d.name,
                        .ty = d.ty,
                        .val = .{},
                    });
                    if (p.eat_token(.comma) == null) break;
                }
                _ = try p.expect_token(.semicolon);
            }
        } else {
            for (init_d.d.ty.params()) |param| {
                if (param.ty.has_unbound_vla()) try p.err_tok(.unbound_vla, param.name_tok);
                if (param.ty.has_incomplete_size() and !param.ty.is(.void) and param.ty.specifier != .invalid) try p.err_str(.parameter_incomplete_ty, param.name_tok, try p.type_str(param.ty));

                if (param.name == .empty) {
                    try p.err_tok(.omitting_parameter_name, param.name_tok);
                    continue;
                }

                // bypass redefinition check to avoid duplicate errors
                try p.syms.define(p.gpa, .{
                    .kind = .def,
                    .name = param.name,
                    .tok = param.name_tok,
                    .ty = param.ty,
                    .val = .{},
                });
            }
        }

        const body = (try p.compound_stmt(true, null)) orelse {
            assert(init_d.d.old_style_func != null);
            try p.err(.expected_fn_body);
            return true;
        };
        p.nodes.set(@int_from_enum(node), .{
            .ty = init_d.d.ty,
            .tag = try decl_spec.validate_fn_def(p),
            .data = .{ .decl = .{ .name = init_d.d.name, .node = body } },
        });
        try p.decl_buf.append(node);

        // check gotos
        if (func.ty == null) {
            for (p.labels.items) |item| {
                if (item == .unresolved_goto)
                    try p.err_str(.undeclared_label, item.unresolved_goto, p.tok_slice(item.unresolved_goto));
            }
            if (p.computed_goto_tok) |goto_tok| {
                if (!p.contains_address_of_label) try p.err_tok(.invalid_computed_goto, goto_tok);
            }
            p.labels.items.len = 0;
            p.label_count = 0;
            p.contains_address_of_label = false;
            p.computed_goto_tok = null;
        }
        return true;
    }

    // Declare all variable/typedef declarators.
    var warned_auto = false;
    while (true) {
        if (init_d.d.old_style_func) |tok_i| try p.err_tok(.invalid_old_style_params, tok_i);
        const tag = try decl_spec.validate(p, &init_d.d.ty, init_d.initializer.node != .none);

        const node = try p.add_node(.{ .ty = init_d.d.ty, .tag = tag, .data = .{
            .decl = .{ .name = init_d.d.name, .node = init_d.initializer.node },
        } });
        try p.decl_buf.append(node);

        const interned_name = try StrInt.intern(p.comp, p.tok_slice(init_d.d.name));
        if (decl_spec.storage_class == .typedef) {
            try p.syms.define_typedef(p, interned_name, init_d.d.ty, init_d.d.name, node);
            p.typedef_defined(interned_name, init_d.d.ty);
        } else if (init_d.initializer.node != .none or
            (p.func.ty != null and decl_spec.storage_class != .@"extern"))
        {
            // TODO validate global variable/constexpr initializer comptime known
            try p.syms.define_symbol(
                p,
                interned_name,
                init_d.d.ty,
                init_d.d.name,
                node,
                if (init_d.d.ty.is_const() or decl_spec.constexpr != null) init_d.initializer.val else .{},
                decl_spec.constexpr != null,
            );
        } else {
            try p.syms.declare_symbol(p, interned_name, init_d.d.ty, init_d.d.name, node);
        }

        if (p.eat_token(.comma) == null) break;

        if (!warned_auto) {
            if (decl_spec.auto_type) |tok_i| {
                try p.err_tok(.auto_type_requires_single_declarator, tok_i);
                warned_auto = true;
            }
            if (p.comp.langopts.standard.at_least(.c23) and decl_spec.storage_class == .auto) {
                try p.err_tok(.c23_auto_single_declarator, decl_spec.storage_class.auto);
                warned_auto = true;
            }
        }

        init_d = (try p.init_declarator(&decl_spec, attr_buf_top)) orelse {
            try p.err(.expected_ident_or_l_paren);
            continue;
        };
    }

    _ = try p.expect_token(.semicolon);
    return true;
}

fn static_assert_message(p: *Parser, cond_node: NodeIndex, message: Result) !?[]const u8 {
    const cond_tag = p.nodes.items(.tag)[@int_from_enum(cond_node)];
    if (cond_tag != .builtin_types_compatible_p and message.node == .none) return null;

    var buf = std.ArrayList(u8).init(p.gpa);
    defer buf.deinit();

    if (cond_tag == .builtin_types_compatible_p) {
        const mapper = p.comp.string_interner.get_slow_type_mapper();
        const data = p.nodes.items(.data)[@int_from_enum(cond_node)].bin;

        try buf.append_slice("'__builtin_types_compatible_p(");

        const lhs_ty = p.nodes.items(.ty)[@int_from_enum(data.lhs)];
        try lhs_ty.print(mapper, p.comp.langopts, buf.writer());
        try buf.append_slice(", ");

        const rhs_ty = p.nodes.items(.ty)[@int_from_enum(data.rhs)];
        try rhs_ty.print(mapper, p.comp.langopts, buf.writer());

        try buf.append_slice(")'");
    }
    if (message.node != .none) {
        assert(p.nodes.items(.tag)[@int_from_enum(message.node)] == .string_literal_expr);
        if (buf.items.len > 0) {
            try buf.append(' ');
        }
        const bytes = p.comp.interner.get(message.val.ref()).bytes;
        try buf.ensure_unused_capacity(bytes.len);
        try Value.print_string(bytes, message.ty, p.comp, buf.writer());
    }
    return try p.comp.diagnostics.arena.allocator().dupe(u8, buf.items);
}

/// static_assert
///    : keyword_static_assert '(' integer_const_expr (',' STRING_LITERAL)? ')' ';'
///    | keyword_c23_static_assert '(' integer_const_expr (',' STRING_LITERAL)? ')' ';'
fn static_assert(p: *Parser) Error!bool {
    const static_assert = p.eat_token(.keyword_static_assert) orelse p.eat_token(.keyword_c23_static_assert) orelse return false;
    const l_paren = try p.expect_token(.l_paren);
    const res_token = p.tok_i;
    var res = try p.const_expr(.gnu_folding_extension);
    const res_node = res.node;
    const str = if (p.eat_token(.comma) != null)
        switch (p.tok_ids[p.tok_i]) {
            .string_literal,
            .string_literal_utf_16,
            .string_literal_utf_8,
            .string_literal_utf_32,
            .string_literal_wide,
            .unterminated_string_literal,
            => try p.string_literal(),
            else => {
                try p.err(.expected_str_literal);
                return error.ParsingFailed;
            },
        }
    else
        Result{};
    try p.expect_closing(l_paren, .r_paren);
    _ = try p.expect_token(.semicolon);
    if (str.node == .none) {
        try p.err_tok(.static_assert_missing_message, static_assert);
        try p.err_str(.pre_c23_compat, static_assert, "'_Static_assert' with no message");
    }

    // Array will never be zero; a value of zero for a pointer is a null pointer constant
    if ((res.ty.is_array() or res.ty.is_ptr()) and !res.val.is_zero(p.comp)) {
        const err_start = p.comp.diagnostics.list.items.len;
        try p.err_tok(.const_decl_folded, res_token);
        if (res.ty.is_ptr() and err_start != p.comp.diagnostics.list.items.len) {
            // Don't show the note if the .const_decl_folded diagnostic was not added
            try p.err_tok(.constant_expression_conversion_not_allowed, res_token);
        }
    }
    try res.bool_cast(p, .{ .specifier = .bool }, res_token);
    if (res.val.opt_ref == .none) {
        if (res.ty.specifier != .invalid) {
            try p.err_tok(.static_assert_not_constant, res_token);
        }
    } else {
        if (!res.val.to_bool(p.comp)) {
            if (try p.static_assert_message(res_node, str)) |message| {
                try p.err_str(.static_assert_failure_message, static_assert, message);
            } else {
                try p.err_tok(.static_assert_failure, static_assert);
            }
        }
    }

    const node = try p.add_node(.{
        .tag = .static_assert,
        .data = .{ .bin = .{
            .lhs = res.node,
            .rhs = str.node,
        } },
    });
    try p.decl_buf.append(node);
    return true;
}

pub const DeclSpec = struct {
    storage_class: union(enum) {
        auto: TokenIndex,
        @"extern": TokenIndex,
        register: TokenIndex,
        static: TokenIndex,
        typedef: TokenIndex,
        none,
    } = .none,
    thread_local: ?TokenIndex = null,
    constexpr: ?TokenIndex = null,
    @"inline": ?TokenIndex = null,
    noreturn: ?TokenIndex = null,
    auto_type: ?TokenIndex = null,
    ty: Type,

    fn validate_param(d: DeclSpec, p: *Parser, ty: *Type) Error!void {
        switch (d.storage_class) {
            .none => {},
            .register => ty.qual.register = true,
            .auto, .@"extern", .static, .typedef => |tok_i| try p.err_tok(.invalid_storage_on_param, tok_i),
        }
        if (d.thread_local) |tok_i| try p.err_tok(.threadlocal_non_var, tok_i);
        if (d.@"inline") |tok_i| try p.err_str(.func_spec_non_func, tok_i, "inline");
        if (d.noreturn) |tok_i| try p.err_str(.func_spec_non_func, tok_i, "_Noreturn");
        if (d.constexpr) |tok_i| try p.err_tok(.invalid_storage_on_param, tok_i);
        if (d.auto_type) |tok_i| {
            try p.err_str(.auto_type_not_allowed, tok_i, "function prototype");
            ty.* = Type.invalid;
        }
    }

    fn validate_fn_def(d: DeclSpec, p: *Parser) Error!Tree.Tag {
        switch (d.storage_class) {
            .none, .@"extern", .static => {},
            .auto, .register, .typedef => |tok_i| try p.err_tok(.illegal_storage_on_func, tok_i),
        }
        if (d.thread_local) |tok_i| try p.err_tok(.threadlocal_non_var, tok_i);
        if (d.constexpr) |tok_i| try p.err_tok(.illegal_storage_on_func, tok_i);

        const is_static = d.storage_class == .static;
        const is_inline = d.@"inline" != null;
        if (is_static) {
            if (is_inline) return .inline_static_fn_def;
            return .static_fn_def;
        } else {
            if (is_inline) return .inline_fn_def;
            return .fn_def;
        }
    }

    fn validate(d: DeclSpec, p: *Parser, ty: *Type, has_init: bool) Error!Tree.Tag {
        const is_static = d.storage_class == .static;
        if (ty.is_func() and d.storage_class != .typedef) {
            switch (d.storage_class) {
                .none, .@"extern" => {},
                .static => |tok_i| if (p.func.ty != null) try p.err_tok(.static_func_not_global, tok_i),
                .typedef => unreachable,
                .auto, .register => |tok_i| try p.err_tok(.illegal_storage_on_func, tok_i),
            }
            if (d.thread_local) |tok_i| try p.err_tok(.threadlocal_non_var, tok_i);
            if (d.constexpr) |tok_i| try p.err_tok(.illegal_storage_on_func, tok_i);

            const is_inline = d.@"inline" != null;
            if (is_static) {
                if (is_inline) return .inline_static_fn_proto;
                return .static_fn_proto;
            } else {
                if (is_inline) return .inline_fn_proto;
                return .fn_proto;
            }
        } else {
            if (d.@"inline") |tok_i| try p.err_str(.func_spec_non_func, tok_i, "inline");
            // TODO move to attribute validation
            if (d.noreturn) |tok_i| try p.err_str(.func_spec_non_func, tok_i, "_Noreturn");
            switch (d.storage_class) {
                .auto => if (p.func.ty == null and !p.comp.langopts.standard.at_least(.c23)) {
                    try p.err(.illegal_storage_on_global);
                },
                .register => if (p.func.ty == null) try p.err(.illegal_storage_on_global),
                .typedef => return .typedef,
                else => {},
            }
            ty.qual.register = d.storage_class == .register;

            const is_extern = d.storage_class == .@"extern" and !has_init;
            if (d.thread_local != null) {
                if (is_static) return .threadlocal_static_var;
                if (is_extern) return .threadlocal_extern_var;
                return .threadlocal_var;
            } else {
                if (is_static) return .static_var;
                if (is_extern) return .extern_var;
                return .@"var";
            }
        }
    }
};

/// typeof
///   : keyword_typeof '(' type_name ')'
///   | keyword_typeof '(' expr ')'
fn typeof(p: *Parser) Error!?Type {
    var unqual = false;
    switch (p.tok_ids[p.tok_i]) {
        .keyword_typeof, .keyword_typeof1, .keyword_typeof2 => p.tok_i += 1,
        .keyword_typeof_unqual => {
            p.tok_i += 1;
            unqual = true;
        },
        else => return null,
    }
    const l_paren = try p.expect_token(.l_paren);
    if (try p.type_name()) |ty| {
        try p.expect_closing(l_paren, .r_paren);
        const typeof_ty = try p.arena.create(Type);
        typeof_ty.* = .{
            .data = ty.data,
            .qual = if (unqual) .{} else ty.qual.inherit_from_typeof(),
            .specifier = ty.specifier,
        };

        return Type{
            .data = .{ .sub_type = typeof_ty },
            .specifier = .typeof_type,
        };
    }
    const typeof_expr = try p.parse_no_eval(expr);
    try typeof_expr.expect(p);
    try p.expect_closing(l_paren, .r_paren);
    // Special case nullptr_t since it's defined as typeof(nullptr)
    if (typeof_expr.ty.is(.nullptr_t)) {
        return Type{
            .specifier = .nullptr_t,
            .qual = if (unqual) .{} else typeof_expr.ty.qual.inherit_from_typeof(),
        };
    }

    const inner = try p.arena.create(Type.Expr);
    inner.* = .{
        .node = typeof_expr.node,
        .ty = .{
            .data = typeof_expr.ty.data,
            .qual = if (unqual) .{} else typeof_expr.ty.qual.inherit_from_typeof(),
            .specifier = typeof_expr.ty.specifier,
            .decayed = typeof_expr.ty.decayed,
        },
    };

    return Type{
        .data = .{ .expr = inner },
        .specifier = .typeof_expr,
        .decayed = typeof_expr.ty.decayed,
    };
}

/// decl_spec: (storage_class_spec | type_spec | type_qual | funcSpec | alignSpec)+
/// funcSpec : keyword_inline | keyword_noreturn
fn decl_spec(p: *Parser) Error!?DeclSpec {
    var d: DeclSpec = .{ .ty = .{ .specifier = undefined } };
    var spec: Type.Builder = .{};

    var combined_auto = !p.comp.langopts.standard.at_least(.c23);
    const start = p.tok_i;
    while (true) {
        if (!combined_auto and d.storage_class == .auto) {
            try spec.combine(p, .c23_auto, d.storage_class.auto);
            combined_auto = true;
        }
        if (try p.storage_class_spec(&d)) continue;
        if (try p.type_spec(&spec)) continue;
        const id = p.tok_ids[p.tok_i];
        switch (id) {
            .keyword_inline, .keyword_inline1, .keyword_inline2 => {
                if (d.@"inline" != null) {
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "inline");
                }
                d.@"inline" = p.tok_i;
            },
            .keyword_noreturn => {
                if (d.noreturn != null) {
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "_Noreturn");
                }
                d.noreturn = p.tok_i;
            },
            else => break,
        }
        p.tok_i += 1;
    }

    if (p.tok_i == start) return null;

    d.ty = try spec.finish(p);
    d.auto_type = spec.auto_type_tok;
    return d;
}

/// storage_class_spec:
///  : keyword_typedef
///  | keyword_extern
///  | keyword_static
///  | keyword_threadlocal
///  | keyword_auto
///  | keyword_register
fn storage_class_spec(p: *Parser, d: *DeclSpec) Error!bool {
    const start = p.tok_i;
    while (true) {
        const id = p.tok_ids[p.tok_i];
        switch (id) {
            .keyword_typedef,
            .keyword_extern,
            .keyword_static,
            .keyword_auto,
            .keyword_register,
            => {
                if (d.storage_class != .none) {
                    try p.err_str(.multiple_storage_class, p.tok_i, @tag_name(d.storage_class));
                    return error.ParsingFailed;
                }
                if (d.thread_local != null) {
                    switch (id) {
                        .keyword_extern, .keyword_static => {},
                        else => try p.err_str(.cannot_combine_spec, p.tok_i, id.lexeme().?),
                    }
                    if (d.constexpr) |tok| try p.err_str(.cannot_combine_spec, p.tok_i, p.tok_ids[tok].lexeme().?);
                }
                if (d.constexpr != null) {
                    switch (id) {
                        .keyword_auto, .keyword_register, .keyword_static => {},
                        else => try p.err_str(.cannot_combine_spec, p.tok_i, id.lexeme().?),
                    }
                    if (d.thread_local) |tok| try p.err_str(.cannot_combine_spec, p.tok_i, p.tok_ids[tok].lexeme().?);
                }
                switch (id) {
                    .keyword_typedef => d.storage_class = .{ .typedef = p.tok_i },
                    .keyword_extern => d.storage_class = .{ .@"extern" = p.tok_i },
                    .keyword_static => d.storage_class = .{ .static = p.tok_i },
                    .keyword_auto => d.storage_class = .{ .auto = p.tok_i },
                    .keyword_register => d.storage_class = .{ .register = p.tok_i },
                    else => unreachable,
                }
            },
            .keyword_thread_local,
            .keyword_c23_thread_local,
            => {
                if (d.thread_local != null) {
                    try p.err_str(.duplicate_decl_spec, p.tok_i, id.lexeme().?);
                }
                if (d.constexpr) |tok| try p.err_str(.cannot_combine_spec, p.tok_i, p.tok_ids[tok].lexeme().?);
                switch (d.storage_class) {
                    .@"extern", .none, .static => {},
                    else => try p.err_str(.cannot_combine_spec, p.tok_i, @tag_name(d.storage_class)),
                }
                d.thread_local = p.tok_i;
            },
            .keyword_constexpr => {
                if (d.constexpr != null) {
                    try p.err_str(.duplicate_decl_spec, p.tok_i, id.lexeme().?);
                }
                if (d.thread_local) |tok| try p.err_str(.cannot_combine_spec, p.tok_i, p.tok_ids[tok].lexeme().?);
                switch (d.storage_class) {
                    .auto, .register, .none, .static => {},
                    else => try p.err_str(.cannot_combine_spec, p.tok_i, @tag_name(d.storage_class)),
                }
                d.constexpr = p.tok_i;
            },
            else => break,
        }
        p.tok_i += 1;
    }
    return p.tok_i != start;
}

const InitDeclarator = struct { d: Declarator, initializer: Result = .{} };

/// attribute
///  : attrIdentifier
///  | attrIdentifier '(' identifier ')'
///  | attrIdentifier '(' identifier (',' expr)+ ')'
///  | attrIdentifier '(' (expr (',' expr)*)? ')'
fn attribute(p: *Parser, kind: Attribute.Kind, namespace: ?[]const u8) Error!?TentativeAttribute {
    const name_tok = p.tok_i;
    switch (p.tok_ids[p.tok_i]) {
        .keyword_const, .keyword_const1, .keyword_const2 => p.tok_i += 1,
        else => _ = try p.expect_identifier(),
    }
    const name = p.tok_slice(name_tok);

    const attr = Attribute.from_string(kind, namespace, name) orelse {
        const tag: Diagnostics.Tag = if (kind == .declspec) .declspec_attr_not_supported else .unknown_attribute;
        try p.err_str(tag, name_tok, name);
        if (p.eat_token(.l_paren)) |_| p.skip_to(.r_paren);
        return null;
    };

    const required_count = Attribute.required_arg_count(attr);
    var arguments = Attribute.init_arguments(attr, name_tok);
    var arg_idx: u32 = 0;

    switch (p.tok_ids[p.tok_i]) {
        .comma, .r_paren => {}, // will be consumed in attributeList
        .l_paren => blk: {
            p.tok_i += 1;
            if (p.eat_token(.r_paren)) |_| break :blk;

            if (Attribute.wants_ident_enum(attr)) {
                if (try p.eat_identifier()) |ident| {
                    if (Attribute.diagnose_ident(attr, &arguments, p.tok_slice(ident))) |msg| {
                        try p.err_extra(msg.tag, ident, msg.extra);
                        p.skip_to(.r_paren);
                        return error.ParsingFailed;
                    }
                } else {
                    try p.err_extra(.attribute_requires_identifier, name_tok, .{ .str = name });
                    return error.ParsingFailed;
                }
            } else {
                const arg_start = p.tok_i;
                var first_expr = try p.assign_expr();
                try first_expr.expect(p);
                if (try p.diagnose(attr, &arguments, arg_idx, first_expr)) |msg| {
                    try p.err_extra(msg.tag, arg_start, msg.extra);
                    p.skip_to(.r_paren);
                    return error.ParsingFailed;
                }
            }
            arg_idx += 1;
            while (p.eat_token(.r_paren) == null) : (arg_idx += 1) {
                _ = try p.expect_token(.comma);

                const arg_start = p.tok_i;
                var arg_expr = try p.assign_expr();
                try arg_expr.expect(p);
                if (try p.diagnose(attr, &arguments, arg_idx, arg_expr)) |msg| {
                    try p.err_extra(msg.tag, arg_start, msg.extra);
                    p.skip_to(.r_paren);
                    return error.ParsingFailed;
                }
            }
        },
        else => {},
    }
    if (arg_idx < required_count) {
        try p.err_extra(.attribute_not_enough_args, name_tok, .{ .attr_arg_count = .{ .attribute = attr, .expected = required_count } });
        return error.ParsingFailed;
    }
    return TentativeAttribute{ .attr = .{ .tag = attr, .args = arguments, .syntax = kind.to_syntax() }, .tok = name_tok };
}

fn diagnose(p: *Parser, attr: Attribute.Tag, arguments: *Attribute.Arguments, arg_idx: u32, res: Result) !?Diagnostics.Message {
    if (Attribute.wants_alignment(attr, arg_idx)) {
        return Attribute.diagnose_alignment(attr, arguments, arg_idx, res, p);
    }
    const node = p.nodes.get(@int_from_enum(res.node));
    return Attribute.diagnose(attr, arguments, arg_idx, res, node, p);
}

/// attributeList : (attribute (',' attribute)*)?
fn gnu_attribute_list(p: *Parser) Error!void {
    if (p.tok_ids[p.tok_i] == .r_paren) return;

    if (try p.attribute(.gnu, null)) |attr| try p.attr_buf.append(p.gpa, attr);
    while (p.tok_ids[p.tok_i] != .r_paren) {
        _ = try p.expect_token(.comma);
        if (try p.attribute(.gnu, null)) |attr| try p.attr_buf.append(p.gpa, attr);
    }
}

fn c23_attribute_list(p: *Parser) Error!void {
    while (p.tok_ids[p.tok_i] != .r_bracket) {
        const namespace_tok = try p.expect_identifier();
        var namespace: ?[]const u8 = null;
        if (p.eat_token(.colon_colon)) |_| {
            namespace = p.tok_slice(namespace_tok);
        } else {
            p.tok_i -= 1;
        }
        if (try p.attribute(.c23, namespace)) |attr| try p.attr_buf.append(p.gpa, attr);
        _ = p.eat_token(.comma);
    }
}

fn msvc_attribute_list(p: *Parser) Error!void {
    while (p.tok_ids[p.tok_i] != .r_paren) {
        if (try p.attribute(.declspec, null)) |attr| try p.attr_buf.append(p.gpa, attr);
        _ = p.eat_token(.comma);
    }
}

fn c23_attribute(p: *Parser) !bool {
    if (!p.comp.langopts.standard.at_least(.c23)) return false;
    const bracket1 = p.eat_token(.l_bracket) orelse return false;
    const bracket2 = p.eat_token(.l_bracket) orelse {
        p.tok_i -= 1;
        return false;
    };

    try p.c23_attribute_list();

    _ = try p.expect_closing(bracket2, .r_bracket);
    _ = try p.expect_closing(bracket1, .r_bracket);

    return true;
}

fn msvc_attribute(p: *Parser) !bool {
    _ = p.eat_token(.keyword_declspec) orelse return false;
    const l_paren = try p.expect_token(.l_paren);
    try p.msvc_attribute_list();
    _ = try p.expect_closing(l_paren, .r_paren);

    return true;
}

fn gnu_attribute(p: *Parser) !bool {
    switch (p.tok_ids[p.tok_i]) {
        .keyword_attribute1, .keyword_attribute2 => p.tok_i += 1,
        else => return false,
    }
    const paren1 = try p.expect_token(.l_paren);
    const paren2 = try p.expect_token(.l_paren);

    try p.gnu_attribute_list();

    _ = try p.expect_closing(paren2, .r_paren);
    _ = try p.expect_closing(paren1, .r_paren);
    return true;
}

fn attribute_specifier(p: *Parser) Error!void {
    return attribute_specifier_extra(p, null);
}

/// attribute_specifier : (keyword_attribute '( '(' attributeList ')' ')')*
fn attribute_specifier_extra(p: *Parser, declarator_name: ?TokenIndex) Error!void {
    while (true) {
        if (try p.gnu_attribute()) continue;
        if (try p.c23_attribute()) continue;
        const maybe_declspec_tok = p.tok_i;
        const attr_buf_top = p.attr_buf.len;
        if (try p.msvc_attribute()) {
            if (declarator_name) |name_tok| {
                try p.err_tok(.declspec_not_allowed_after_declarator, maybe_declspec_tok);
                try p.err_tok(.declarator_name_tok, name_tok);
                p.attr_buf.len = attr_buf_top;
            }
            continue;
        }
        break;
    }
}

/// init_declarator : declarator assembly? attribute_specifier? ('=' initializer)?
fn init_declarator(p: *Parser, decl_spec: *DeclSpec, attr_buf_top: usize) Error!?InitDeclarator {
    const this_attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = this_attr_buf_top;

    var init_d = InitDeclarator{
        .d = (try p.declarator(decl_spec.ty, .normal)) orelse return null,
    };

    if (decl_spec.ty.is(.c23_auto) and !init_d.d.ty.is(.c23_auto)) {
        try p.err_tok(.c23_auto_plain_declarator, decl_spec.storage_class.auto);
        return error.ParsingFailed;
    }

    try p.attribute_specifier_extra(init_d.d.name);
    _ = try p.assembly(.decl_label);
    try p.attribute_specifier_extra(init_d.d.name);

    var apply_var_attributes = false;
    if (decl_spec.storage_class == .typedef) {
        if (decl_spec.auto_type) |tok_i| {
            try p.err_str(.auto_type_not_allowed, tok_i, "typedef");
            return error.ParsingFailed;
        }
        init_d.d.ty = try Attribute.apply_type_attributes(p, init_d.d.ty, attr_buf_top, null);
    } else if (init_d.d.ty.is_func()) {
        init_d.d.ty = try Attribute.apply_function_attributes(p, init_d.d.ty, attr_buf_top);
    } else {
        apply_var_attributes = true;
    }

    if (p.eat_token(.equal)) |eq| init: {
        if (decl_spec.storage_class == .typedef or
            (init_d.d.func_declarator != null and init_d.d.ty.is_func()))
        {
            try p.err_tok(.illegal_initializer, eq);
        } else if (init_d.d.ty.is(.variable_len_array)) {
            try p.err_tok(.vla_init, eq);
        } else if (decl_spec.storage_class == .@"extern") {
            try p.err(.extern_initializer);
            decl_spec.storage_class = .none;
        }

        if (init_d.d.ty.has_incomplete_size() and !init_d.d.ty.is(.incomplete_array)) {
            try p.err_str(.variable_incomplete_ty, init_d.d.name, try p.type_str(init_d.d.ty));
            return error.ParsingFailed;
        }
        if (p.tok_ids[p.tok_i] == .l_brace and init_d.d.ty.is(.c23_auto)) {
            try p.err_tok(.c23_auto_scalar_init, decl_spec.storage_class.auto);
            return error.ParsingFailed;
        }

        try p.syms.push_scope(p);
        defer p.syms.pop_scope();

        const interned_name = try StrInt.intern(p.comp, p.tok_slice(init_d.d.name));
        try p.syms.declare_symbol(p, interned_name, init_d.d.ty, init_d.d.name, .none);
        var init_list_expr = try p.initializer(init_d.d.ty);
        init_d.initializer = init_list_expr;
        if (!init_list_expr.ty.is_array()) break :init;
        if (init_d.d.ty.specifier == .incomplete_array) {
            // Modifying .data is exceptionally allowed for .incomplete_array.
            init_d.d.ty.data.array.len = init_list_expr.ty.array_len() orelse break :init;
            init_d.d.ty.specifier = .array;
        }
    }

    const name = init_d.d.name;
    const c23_auto = init_d.d.ty.is(.c23_auto);
    if (init_d.d.ty.is(.auto_type) or c23_auto) {
        if (init_d.initializer.node == .none) {
            init_d.d.ty = Type.invalid;
            if (c23_auto) {
                try p.err_str(.c32_auto_requires_initializer, decl_spec.storage_class.auto, p.tok_slice(name));
            } else {
                try p.err_str(.auto_type_requires_initializer, name, p.tok_slice(name));
            }
            return init_d;
        } else {
            init_d.d.ty.specifier = init_d.initializer.ty.specifier;
            init_d.d.ty.data = init_d.initializer.ty.data;
            init_d.d.ty.decayed = init_d.initializer.ty.decayed;
        }
    }
    if (apply_var_attributes) {
        init_d.d.ty = try Attribute.apply_variable_attributes(p, init_d.d.ty, attr_buf_top, null);
    }
    if (decl_spec.storage_class != .typedef and init_d.d.ty.has_incomplete_size()) incomplete: {
        const specifier = init_d.d.ty.canonicalize(.standard).specifier;
        if (decl_spec.storage_class == .@"extern") switch (specifier) {
            .@"struct", .@"union", .@"enum" => break :incomplete,
            .incomplete_array => {
                init_d.d.ty.decay_array();
                break :incomplete;
            },
            else => {},
        };
        // if there was an initializer expression it must have contained an error
        if (init_d.initializer.node != .none) break :incomplete;

        if (p.func.ty == null) {
            if (specifier == .incomplete_array) {
                // TODO properly check this after finishing parsing
                try p.err_str(.tentative_array, name, try p.type_str(init_d.d.ty));
                break :incomplete;
            } else if (init_d.d.ty.get_record()) |record| {
                _ = try p.tentative_defs.get_or_put_value(p.gpa, record.name, init_d.d.name);
                break :incomplete;
            } else if (init_d.d.ty.get(.@"enum")) |en| {
                _ = try p.tentative_defs.get_or_put_value(p.gpa, en.data.@"enum".name, init_d.d.name);
                break :incomplete;
            }
        }
        try p.err_str(.variable_incomplete_ty, name, try p.type_str(init_d.d.ty));
    }
    return init_d;
}

/// type_spec
///  : keyword_void
///  | keyword_auto_type
///  | keyword_char
///  | keyword_short
///  | keyword_int
///  | keyword_long
///  | keyword_float
///  | keyword_double
///  | keyword_signed
///  | keyword_unsigned
///  | keyword_bool
///  | keyword_c23_bool
///  | keyword_complex
///  | atomicTypeSpec
///  | record_spec
///  | enum_spec
///  | typedef  // IDENTIFIER
///  | typeof
///  | keyword_bit_int '(' integer_const_expr ')'
/// atomicTypeSpec : keyword_atomic '(' type_name ')'
/// alignSpec
///   : keyword_alignas '(' type_name ')'
///   | keyword_alignas '(' integer_const_expr ')'
///   | keyword_c23_alignas '(' type_name ')'
///   | keyword_c23_alignas '(' integer_const_expr ')'
fn type_spec(p: *Parser, ty: *Type.Builder) Error!bool {
    const start = p.tok_i;
    while (true) {
        try p.attribute_specifier();

        if (try p.typeof()) |inner_ty| {
            try ty.combine_from_typeof(p, inner_ty, start);
            continue;
        }
        if (try p.type_qual(&ty.qual)) continue;
        switch (p.tok_ids[p.tok_i]) {
            .keyword_void => try ty.combine(p, .void, p.tok_i),
            .keyword_auto_type => {
                try p.err_tok(.auto_type_extension, p.tok_i);
                try ty.combine(p, .auto_type, p.tok_i);
            },
            .keyword_bool, .keyword_c23_bool => try ty.combine(p, .bool, p.tok_i),
            .keyword_int8, .keyword_int8_2, .keyword_char => try ty.combine(p, .char, p.tok_i),
            .keyword_int16, .keyword_int16_2, .keyword_short => try ty.combine(p, .short, p.tok_i),
            .keyword_int32, .keyword_int32_2, .keyword_int => try ty.combine(p, .int, p.tok_i),
            .keyword_long => try ty.combine(p, .long, p.tok_i),
            .keyword_int64, .keyword_int64_2 => try ty.combine(p, .long_long, p.tok_i),
            .keyword_int128 => try ty.combine(p, .int128, p.tok_i),
            .keyword_signed => try ty.combine(p, .signed, p.tok_i),
            .keyword_unsigned => try ty.combine(p, .unsigned, p.tok_i),
            .keyword_fp16 => try ty.combine(p, .fp16, p.tok_i),
            .keyword_float16 => try ty.combine(p, .float16, p.tok_i),
            .keyword_float => try ty.combine(p, .float, p.tok_i),
            .keyword_double => try ty.combine(p, .double, p.tok_i),
            .keyword_complex => try ty.combine(p, .complex, p.tok_i),
            .keyword_float80 => try ty.combine(p, .float80, p.tok_i),
            .keyword_float128_1, .keyword_float128_2 => {
                if (!p.comp.has_float128()) {
                    try p.err_str(.type_not_supported_on_target, p.tok_i, p.tok_ids[p.tok_i].lexeme().?);
                }
                try ty.combine(p, .float128, p.tok_i);
            },
            .keyword_atomic => {
                const atomic_tok = p.tok_i;
                p.tok_i += 1;
                const l_paren = p.eat_token(.l_paren) orelse {
                    // _Atomic qualifier not _Atomic(type_name)
                    p.tok_i = atomic_tok;
                    break;
                };
                const inner_ty = (try p.type_name()) orelse {
                    try p.err(.expected_type);
                    return error.ParsingFailed;
                };
                try p.expect_closing(l_paren, .r_paren);

                const new_spec = Type.Builder.from_type(inner_ty);
                try ty.combine(p, new_spec, atomic_tok);

                if (ty.qual.atomic != null)
                    try p.err_str(.duplicate_decl_spec, atomic_tok, "atomic")
                else
                    ty.qual.atomic = atomic_tok;
                continue;
            },
            .keyword_alignas,
            .keyword_c23_alignas,
            => {
                const align_tok = p.tok_i;
                p.tok_i += 1;
                const l_paren = try p.expect_token(.l_paren);
                const typename_start = p.tok_i;
                if (try p.type_name()) |inner_ty| {
                    if (!inner_ty.alignable()) {
                        try p.err_str(.invalid_alignof, typename_start, try p.type_str(inner_ty));
                    }
                    const alignment = Attribute.Alignment{ .requested = inner_ty.alignof(p.comp) };
                    try p.attr_buf.append(p.gpa, .{
                        .attr = .{ .tag = .aligned, .args = .{
                            .aligned = .{ .alignment = alignment, .__name_tok = align_tok },
                        }, .syntax = .keyword },
                        .tok = align_tok,
                    });
                } else {
                    const arg_start = p.tok_i;
                    const res = try p.integer_const_expr(.no_const_decl_folding);
                    if (!res.val.is_zero(p.comp)) {
                        var args = Attribute.init_arguments(.aligned, align_tok);
                        if (try p.diagnose(.aligned, &args, 0, res)) |msg| {
                            try p.err_extra(msg.tag, arg_start, msg.extra);
                            p.skip_to(.r_paren);
                            return error.ParsingFailed;
                        }
                        args.aligned.alignment.?.node = res.node;
                        try p.attr_buf.append(p.gpa, .{
                            .attr = .{ .tag = .aligned, .args = args, .syntax = .keyword },
                            .tok = align_tok,
                        });
                    }
                }
                try p.expect_closing(l_paren, .r_paren);
                continue;
            },
            .keyword_stdcall,
            .keyword_stdcall2,
            .keyword_thiscall,
            .keyword_thiscall2,
            .keyword_vectorcall,
            .keyword_vectorcall2,
            => try p.attr_buf.append(p.gpa, .{
                .attr = .{ .tag = .calling_convention, .args = .{
                    .calling_convention = .{ .cc = switch (p.tok_ids[p.tok_i]) {
                        .keyword_stdcall,
                        .keyword_stdcall2,
                        => .stdcall,
                        .keyword_thiscall,
                        .keyword_thiscall2,
                        => .thiscall,
                        .keyword_vectorcall,
                        .keyword_vectorcall2,
                        => .vectorcall,
                        else => unreachable,
                    } },
                }, .syntax = .keyword },
                .tok = p.tok_i,
            }),
            .keyword_struct, .keyword_union => {
                const tag_tok = p.tok_i;
                const record_ty = try p.record_spec();
                try ty.combine(p, Type.Builder.from_type(record_ty), tag_tok);
                continue;
            },
            .keyword_enum => {
                const tag_tok = p.tok_i;
                const enum_ty = try p.enum_spec();
                try ty.combine(p, Type.Builder.from_type(enum_ty), tag_tok);
                continue;
            },
            .identifier, .extended_identifier => {
                var interned_name = try StrInt.intern(p.comp, p.tok_slice(p.tok_i));
                var declspec_found = false;

                if (interned_name == p.string_ids.declspec_id) {
                    try p.err_tok(.declspec_not_enabled, p.tok_i);
                    p.tok_i += 1;
                    if (p.eat_token(.l_paren)) |_| {
                        p.skip_to(.r_paren);
                        continue;
                    }
                    declspec_found = true;
                }
                if (ty.typedef != null) break;
                if (declspec_found) {
                    interned_name = try StrInt.intern(p.comp, p.tok_slice(p.tok_i));
                }
                const typedef = (try p.syms.find_typedef(p, interned_name, p.tok_i, ty.specifier != .none)) orelse break;
                if (!ty.combine_typedef(p, typedef.ty, typedef.tok)) break;
            },
            .keyword_bit_int => {
                try p.err(.bit_int);
                const bit_int_tok = p.tok_i;
                p.tok_i += 1;
                const l_paren = try p.expect_token(.l_paren);
                const res = try p.integer_const_expr(.gnu_folding_extension);
                try p.expect_closing(l_paren, .r_paren);

                var bits: u64 = undefined;
                if (res.val.opt_ref == .none) {
                    try p.err_tok(.expected_integer_constant_expr, bit_int_tok);
                    return error.ParsingFailed;
                } else if (res.val.compare(.lte, Value.zero, p.comp)) {
                    bits = 0;
                } else {
                    bits = res.val.to_int(u64, p.comp) orelse std.math.max_int(u64);
                }

                try ty.combine(p, .{ .bit_int = bits }, bit_int_tok);
                continue;
            },
            else => break,
        }
        // consume single token specifiers here
        p.tok_i += 1;
    }
    return p.tok_i != start;
}

fn get_anonymous_name(p: *Parser, kind_tok: TokenIndex) !StringId {
    const loc = p.pp.tokens.items(.loc)[kind_tok];
    const source = p.comp.get_source(loc.id);
    const line_col = source.line_col(loc);

    const kind_str = switch (p.tok_ids[kind_tok]) {
        .keyword_struct, .keyword_union, .keyword_enum => p.tok_slice(kind_tok),
        else => "record field",
    };

    const str = try std.fmt.alloc_print(
        p.arena,
        "(anonymous {s} at {s}:{d}:{d})",
        .{ kind_str, source.path, line_col.line_no, line_col.col },
    );
    return StrInt.intern(p.comp, str);
}

/// record_spec
///  : (keyword_struct | keyword_union) IDENTIFIER? { recordDecl* }
///  | (keyword_struct | keyword_union) IDENTIFIER
fn record_spec(p: *Parser) Error!Type {
    const starting_pragma_pack = p.pragma_pack;
    const kind_tok = p.tok_i;
    const is_struct = p.tok_ids[kind_tok] == .keyword_struct;
    p.tok_i += 1;
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    try p.attribute_specifier();

    const maybe_ident = try p.eat_identifier();
    const l_brace = p.eat_token(.l_brace) orelse {
        const ident = maybe_ident orelse {
            try p.err(.ident_or_l_brace);
            return error.ParsingFailed;
        };
        // check if this is a reference to a previous type
        const interned_name = try StrInt.intern(p.comp, p.tok_slice(ident));
        if (try p.syms.find_tag(p, interned_name, p.tok_ids[kind_tok], ident, p.tok_ids[p.tok_i])) |prev| {
            return prev.ty;
        } else {
            // this is a forward declaration, create a new record Type.
            const record_ty = try Type.Record.create(p.arena, interned_name);
            const ty = try Attribute.apply_type_attributes(p, .{
                .specifier = if (is_struct) .@"struct" else .@"union",
                .data = .{ .record = record_ty },
            }, attr_buf_top, null);
            try p.syms.define(p.gpa, .{
                .kind = if (is_struct) .@"struct" else .@"union",
                .name = interned_name,
                .tok = ident,
                .ty = ty,
                .val = .{},
            });
            try p.decl_buf.append(try p.add_node(.{
                .tag = if (is_struct) .struct_forward_decl else .union_forward_decl,
                .ty = ty,
                .data = .{ .decl_ref = ident },
            }));
            return ty;
        }
    };

    var done = false;
    errdefer if (!done) p.skip_to(.r_brace);

    // Get forward declared type or create a new one
    var defined = false;
    const record_ty: *Type.Record = if (maybe_ident) |ident| record_ty: {
        const ident_str = p.tok_slice(ident);
        const interned_name = try StrInt.intern(p.comp, ident_str);
        if (try p.syms.define_tag(p, interned_name, p.tok_ids[kind_tok], ident)) |prev| {
            if (!prev.ty.has_incomplete_size()) {
                // if the record isn't incomplete, this is a redefinition
                try p.err_str(.redefinition, ident, ident_str);
                try p.err_tok(.previous_definition, prev.tok);
            } else {
                defined = true;
                break :record_ty prev.ty.get(if (is_struct) .@"struct" else .@"union").?.data.record;
            }
        }
        break :record_ty try Type.Record.create(p.arena, interned_name);
    } else try Type.Record.create(p.arena, try p.get_anonymous_name(kind_tok));

    // Initially create ty as a regular non-attributed type, since attributes for a record
    // can be specified after the closing rbrace, which we haven't encountered yet.
    var ty = Type{
        .specifier = if (is_struct) .@"struct" else .@"union",
        .data = .{ .record = record_ty },
    };

    // declare a symbol for the type
    // We need to replace the symbol's type if it has attributes
    if (maybe_ident != null and !defined) {
        try p.syms.define(p.gpa, .{
            .kind = if (is_struct) .@"struct" else .@"union",
            .name = record_ty.name,
            .tok = maybe_ident.?,
            .ty = ty,
            .val = .{},
        });
    }

    // reserve space for this record
    try p.decl_buf.append(.none);
    const decl_buf_top = p.decl_buf.items.len;
    const record_buf_top = p.record_buf.items.len;
    errdefer p.decl_buf.items.len = decl_buf_top - 1;
    defer {
        p.decl_buf.items.len = decl_buf_top;
        p.record_buf.items.len = record_buf_top;
    }

    const old_record = p.record;
    const old_members = p.record_members.items.len;
    const old_field_attr_start = p.field_attr_buf.items.len;
    p.record = .{
        .kind = p.tok_ids[kind_tok],
        .start = p.record_members.items.len,
        .field_attr_start = p.field_attr_buf.items.len,
    };
    defer p.record = old_record;
    defer p.record_members.items.len = old_members;
    defer p.field_attr_buf.items.len = old_field_attr_start;

    try p.record_decls();

    if (p.record.flexible_field) |some| {
        if (p.record_buf.items[record_buf_top..].len == 1 and is_struct) {
            try p.err_tok(.flexible_in_empty, some);
        }
    }

    for (p.record_buf.items[record_buf_top..]) |field| {
        if (field.ty.has_incomplete_size() and !field.ty.is(.incomplete_array)) break;
    } else {
        record_ty.fields = try p.arena.dupe(Type.Record.Field, p.record_buf.items[record_buf_top..]);
    }
    const attr_count = p.field_attr_buf.items.len - old_field_attr_start;
    const record_decls = p.decl_buf.items[decl_buf_top..];
    if (attr_count > 0) {
        if (attr_count != record_decls.len) {
            // A mismatch here means that non-field decls were parsed. This can happen if there were
            // parse errors during attribute parsing. Bail here because if there are any field attributes,
            // there must be exactly one per field.
            return error.ParsingFailed;
        }
        const field_attr_slice = p.field_attr_buf.items[old_field_attr_start..];
        const duped = try p.arena.dupe([]const Attribute, field_attr_slice);
        record_ty.field_attributes = duped.ptr;
    }

    if (p.record_buf.items.len == record_buf_top) {
        try p.err_str(.empty_record, kind_tok, p.tok_slice(kind_tok));
        try p.err_str(.empty_record_size, kind_tok, p.tok_slice(kind_tok));
    }
    try p.expect_closing(l_brace, .r_brace);
    done = true;
    try p.attribute_specifier();

    ty = try Attribute.apply_type_attributes(p, .{
        .specifier = if (is_struct) .@"struct" else .@"union",
        .data = .{ .record = record_ty },
    }, attr_buf_top, null);
    if (ty.specifier == .attributed and maybe_ident != null) {
        const ident_str = p.tok_slice(maybe_ident.?);
        const interned_name = try StrInt.intern(p.comp, ident_str);
        const ptr = p.syms.get_ptr(interned_name, .tags);
        ptr.ty = ty;
    }

    if (!ty.has_incomplete_size()) {
        const pragma_pack_value = switch (p.comp.langopts.emulate) {
            .clang => starting_pragma_pack,
            .gcc => p.pragma_pack,
            // TODO: msvc considers `#pragma pack` on a per-field basis
            .msvc => p.pragma_pack,
        };
        record_layout.compute(record_ty, ty, p.comp, pragma_pack_value);
    }

    // finish by creating a node
    var node: Tree.Node = .{
        .tag = if (is_struct) .struct_decl_two else .union_decl_two,
        .ty = ty,
        .data = .{ .bin = .{ .lhs = .none, .rhs = .none } },
    };
    switch (record_decls.len) {
        0 => {},
        1 => node.data = .{ .bin = .{ .lhs = record_decls[0], .rhs = .none } },
        2 => node.data = .{ .bin = .{ .lhs = record_decls[0], .rhs = record_decls[1] } },
        else => {
            node.tag = if (is_struct) .struct_decl else .union_decl;
            node.data = .{ .range = try p.add_list(record_decls) };
        },
    }
    p.decl_buf.items[decl_buf_top - 1] = try p.add_node(node);
    if (p.func.ty == null) {
        _ = p.tentative_defs.remove(record_ty.name);
    }
    return ty;
}

/// recordDecl
///  : spec_qual (record_declarator (',' record_declarator)*)? ;
///  | static_assert
fn record_decls(p: *Parser) Error!void {
    while (true) {
        if (try p.pragma()) continue;
        if (try p.parse_or_next_decl(static_assert)) continue;
        if (p.eat_token(.keyword_extension)) |_| {
            const saved_extension = p.extension_suppressed;
            defer p.extension_suppressed = saved_extension;
            p.extension_suppressed = true;

            if (try p.parse_or_next_decl(record_declarator)) continue;
            try p.err(.expected_type);
            p.next_extern_decl();
            continue;
        }
        if (try p.parse_or_next_decl(record_declarator)) continue;
        break;
    }
}

/// record_declarator : keyword_extension? declarator (':' integer_const_expr)?
fn record_declarator(p: *Parser) Error!bool {
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    const base_ty = (try p.spec_qual()) orelse return false;

    try p.attribute_specifier(); // .record
    while (true) {
        const this_decl_top = p.attr_buf.len;
        defer p.attr_buf.len = this_decl_top;

        try p.attribute_specifier();

        // 0 means unnamed
        var name_tok: TokenIndex = 0;
        var ty = base_ty;
        if (ty.is(.auto_type)) {
            try p.err_str(.auto_type_not_allowed, p.tok_i, if (p.record.kind == .keyword_struct) "struct member" else "union member");
            ty = Type.invalid;
        }
        var bits_node: NodeIndex = .none;
        var bits: ?u32 = null;
        const first_tok = p.tok_i;
        if (try p.declarator(ty, .record)) |d| {
            name_tok = d.name;
            ty = d.ty;
        }

        if (p.eat_token(.colon)) |_| bits: {
            const bits_tok = p.tok_i;
            const res = try p.integer_const_expr(.gnu_folding_extension);
            if (!ty.is_int()) {
                try p.err_str(.non_int_bitfield, first_tok, try p.type_str(ty));
                break :bits;
            }

            if (res.val.opt_ref == .none) {
                try p.err_tok(.expected_integer_constant_expr, bits_tok);
                break :bits;
            } else if (res.val.compare(.lt, Value.zero, p.comp)) {
                try p.err_str(.negative_bitwidth, first_tok, try res.str(p));
                break :bits;
            }

            // incomplete size error is reported later
            const bit_size = ty.bit_sizeof(p.comp) orelse break :bits;
            const bits_unchecked = res.val.to_int(u32, p.comp) orelse std.math.max_int(u32);
            if (bits_unchecked > bit_size) {
                try p.err_tok(.bitfield_too_big, name_tok);
                break :bits;
            } else if (bits_unchecked == 0 and name_tok != 0) {
                try p.err_tok(.zero_width_named_field, name_tok);
                break :bits;
            }

            bits = bits_unchecked;
            bits_node = res.node;
        }

        try p.attribute_specifier(); // .record
        const to_append = try Attribute.apply_field_attributes(p, &ty, attr_buf_top);

        const any_fields_have_attrs = p.field_attr_buf.items.len > p.record.field_attr_start;

        if (any_fields_have_attrs) {
            try p.field_attr_buf.append(to_append);
        } else {
            if (to_append.len > 0) {
                const preceding = p.record_members.items.len - p.record.start;
                if (preceding > 0) {
                    try p.field_attr_buf.append_ntimes(&.{}, preceding);
                }
                try p.field_attr_buf.append(to_append);
            }
        }

        if (name_tok == 0 and bits_node == .none) unnamed: {
            if (ty.is(.@"enum") or ty.has_incomplete_size()) break :unnamed;
            if (ty.is_anonymous_record(p.comp)) {
                // An anonymous record appears as indirect fields on the parent
                try p.record_buf.append(.{
                    .name = try p.get_anonymous_name(first_tok),
                    .ty = ty,
                });
                const node = try p.add_node(.{
                    .tag = .indirect_record_field_decl,
                    .ty = ty,
                    .data = undefined,
                });
                try p.decl_buf.append(node);
                try p.record.add_fields_from_anonymous(p, ty);
                break; // must be followed by a semicolon
            }
            try p.err(.missing_declaration);
        } else {
            const interned_name = if (name_tok != 0) try StrInt.intern(p.comp, p.tok_slice(name_tok)) else try p.get_anonymous_name(first_tok);
            try p.record_buf.append(.{
                .name = interned_name,
                .ty = ty,
                .name_tok = name_tok,
                .bit_width = bits,
            });
            if (name_tok != 0) try p.record.add_field(p, interned_name, name_tok);
            const node = try p.add_node(.{
                .tag = .record_field_decl,
                .ty = ty,
                .data = .{ .decl = .{ .name = name_tok, .node = bits_node } },
            });
            try p.decl_buf.append(node);
        }

        if (ty.is_func()) {
            try p.err_tok(.func_field, first_tok);
        } else if (ty.is(.variable_len_array)) {
            try p.err_tok(.vla_field, first_tok);
        } else if (ty.is(.incomplete_array)) {
            if (p.record.kind == .keyword_union) {
                try p.err_tok(.flexible_in_union, first_tok);
            }
            if (p.record.flexible_field) |some| {
                if (p.record.kind == .keyword_struct) {
                    try p.err_tok(.flexible_non_final, some);
                }
            }
            p.record.flexible_field = first_tok;
        } else if (ty.specifier != .invalid and ty.has_incomplete_size()) {
            try p.err_str(.field_incomplete_ty, first_tok, try p.type_str(ty));
        } else if (p.record.flexible_field) |some| {
            if (some != first_tok and p.record.kind == .keyword_struct) try p.err_tok(.flexible_non_final, some);
        }
        if (p.eat_token(.comma) == null) break;
    }

    if (p.eat_token(.semicolon) == null) {
        const tok_id = p.tok_ids[p.tok_i];
        if (tok_id == .r_brace) {
            try p.err(.missing_semicolon);
        } else {
            return p.err_expected_token(.semicolon, tok_id);
        }
    }

    return true;
}

/// spec_qual : (type_spec | type_qual | alignSpec)+
fn spec_qual(p: *Parser) Error!?Type {
    var spec: Type.Builder = .{};
    if (try p.type_spec(&spec)) {
        return try spec.finish(p);
    }
    return null;
}

/// enum_spec
///  : keyword_enum IDENTIFIER? (: type_name)? { enumerator (',' enumerator)? ',') }
///  | keyword_enum IDENTIFIER (: type_name)?
fn enum_spec(p: *Parser) Error!Type {
    const enum_tok = p.tok_i;
    p.tok_i += 1;
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    try p.attribute_specifier();

    const maybe_ident = try p.eat_identifier();
    const fixed_ty = if (p.eat_token(.colon)) |colon| fixed: {
        const fixed = (try p.type_name()) orelse {
            if (p.record.kind != .invalid) {
                // This is a bit field.
                p.tok_i -= 1;
                break :fixed null;
            }
            try p.err(.expected_type);
            try p.err_tok(.enum_fixed, colon);
            break :fixed null;
        };
        try p.err_tok(.enum_fixed, colon);
        break :fixed fixed;
    } else null;

    const l_brace = p.eat_token(.l_brace) orelse {
        const ident = maybe_ident orelse {
            try p.err(.ident_or_l_brace);
            return error.ParsingFailed;
        };
        // check if this is a reference to a previous type
        const interned_name = try StrInt.intern(p.comp, p.tok_slice(ident));
        if (try p.syms.find_tag(p, interned_name, .keyword_enum, ident, p.tok_ids[p.tok_i])) |prev| {
            // only check fixed underlying type in forward declarations and not in references.
            if (p.tok_ids[p.tok_i] == .semicolon)
                try p.check_enum_fixed_ty(fixed_ty, ident, prev);
            return prev.ty;
        } else {
            // this is a forward declaration, create a new enum Type.
            const enum_ty = try Type.Enum.create(p.arena, interned_name, fixed_ty);
            const ty = try Attribute.apply_type_attributes(p, .{
                .specifier = .@"enum",
                .data = .{ .@"enum" = enum_ty },
            }, attr_buf_top, null);
            try p.syms.define(p.gpa, .{
                .kind = .@"enum",
                .name = interned_name,
                .tok = ident,
                .ty = ty,
                .val = .{},
            });
            try p.decl_buf.append(try p.add_node(.{
                .tag = .enum_forward_decl,
                .ty = ty,
                .data = .{ .decl_ref = ident },
            }));
            return ty;
        }
    };

    var done = false;
    errdefer if (!done) p.skip_to(.r_brace);

    // Get forward declared type or create a new one
    var defined = false;
    const enum_ty: *Type.Enum = if (maybe_ident) |ident| enum_ty: {
        const ident_str = p.tok_slice(ident);
        const interned_name = try StrInt.intern(p.comp, ident_str);
        if (try p.syms.define_tag(p, interned_name, .keyword_enum, ident)) |prev| {
            const enum_ty = prev.ty.get(.@"enum").?.data.@"enum";
            if (!enum_ty.is_incomplete() and !enum_ty.fixed) {
                // if the enum isn't incomplete, this is a redefinition
                try p.err_str(.redefinition, ident, ident_str);
                try p.err_tok(.previous_definition, prev.tok);
            } else {
                try p.check_enum_fixed_ty(fixed_ty, ident, prev);
                defined = true;
                break :enum_ty enum_ty;
            }
        }
        break :enum_ty try Type.Enum.create(p.arena, interned_name, fixed_ty);
    } else try Type.Enum.create(p.arena, try p.get_anonymous_name(enum_tok), fixed_ty);

    // reserve space for this enum
    try p.decl_buf.append(.none);
    const decl_buf_top = p.decl_buf.items.len;
    const list_buf_top = p.list_buf.items.len;
    const enum_buf_top = p.enum_buf.items.len;
    errdefer p.decl_buf.items.len = decl_buf_top - 1;
    defer {
        p.decl_buf.items.len = decl_buf_top;
        p.list_buf.items.len = list_buf_top;
        p.enum_buf.items.len = enum_buf_top;
    }

    var e = Enumerator.init(fixed_ty);
    while (try p.enumerator(&e)) |field_and_node| {
        try p.enum_buf.append(field_and_node.field);
        try p.list_buf.append(field_and_node.node);
        if (p.eat_token(.comma) == null) break;
    }

    if (p.enum_buf.items.len == enum_buf_top) try p.err(.empty_enum);
    try p.expect_closing(l_brace, .r_brace);
    done = true;
    try p.attribute_specifier();

    const ty = try Attribute.apply_type_attributes(p, .{
        .specifier = .@"enum",
        .data = .{ .@"enum" = enum_ty },
    }, attr_buf_top, null);
    if (!enum_ty.fixed) {
        const tag_specifier = try e.get_type_specifier(p, ty.enum_is_packed(p.comp), maybe_ident orelse enum_tok);
        enum_ty.tag_ty = .{ .specifier = tag_specifier };
    }

    const enum_fields = p.enum_buf.items[enum_buf_top..];
    const field_nodes = p.list_buf.items[list_buf_top..];

    if (fixed_ty == null) {
        for (enum_fields, 0..) |*field, i| {
            if (field.ty.eql(Type.int, p.comp, false)) continue;

            const sym = p.syms.get(field.name, .vars) orelse continue;
            if (sym.kind != .enumeration) continue; // already an error

            var res = Result{ .node = field.node, .ty = field.ty, .val = sym.val };
            const dest_ty = if (p.comp.fixed_enum_tag_specifier()) |some|
                Type{ .specifier = some }
            else if (try res.int_fits_in_type(p, Type.int))
                Type.int
            else if (!res.ty.eql(enum_ty.tag_ty, p.comp, false))
                enum_ty.tag_ty
            else
                continue;

            const symbol = p.syms.get_ptr(field.name, .vars);
            try symbol.val.int_cast(dest_ty, p.comp);
            symbol.ty = dest_ty;
            p.nodes.items(.ty)[@int_from_enum(field_nodes[i])] = dest_ty;
            field.ty = dest_ty;
            res.ty = dest_ty;

            if (res.node != .none) {
                try res.implicit_cast(p, .int_cast);
                field.node = res.node;
                p.nodes.items(.data)[@int_from_enum(field_nodes[i])].decl.node = res.node;
            }
        }
    }

    enum_ty.fields = try p.arena.dupe(Type.Enum.Field, enum_fields);

    // declare a symbol for the type
    if (maybe_ident != null and !defined) {
        try p.syms.define(p.gpa, .{
            .kind = .@"enum",
            .name = enum_ty.name,
            .ty = ty,
            .tok = maybe_ident.?,
            .val = .{},
        });
    }

    // finish by creating a node
    var node: Tree.Node = .{ .tag = .enum_decl_two, .ty = ty, .data = .{
        .bin = .{ .lhs = .none, .rhs = .none },
    } };
    switch (field_nodes.len) {
        0 => {},
        1 => node.data = .{ .bin = .{ .lhs = field_nodes[0], .rhs = .none } },
        2 => node.data = .{ .bin = .{ .lhs = field_nodes[0], .rhs = field_nodes[1] } },
        else => {
            node.tag = .enum_decl;
            node.data = .{ .range = try p.add_list(field_nodes) };
        },
    }
    p.decl_buf.items[decl_buf_top - 1] = try p.add_node(node);
    if (p.func.ty == null) {
        _ = p.tentative_defs.remove(enum_ty.name);
    }
    return ty;
}

fn check_enum_fixed_ty(p: *Parser, fixed_ty: ?Type, ident_tok: TokenIndex, prev: Symbol) !void {
    const enum_ty = prev.ty.get(.@"enum").?.data.@"enum";
    if (fixed_ty) |some| {
        if (!enum_ty.fixed) {
            try p.err_tok(.enum_prev_nonfixed, ident_tok);
            try p.err_tok(.previous_definition, prev.tok);
            return error.ParsingFailed;
        }

        if (!enum_ty.tag_ty.eql(some, p.comp, false)) {
            const str = try p.type_pair_str_extra(some, " (was ", enum_ty.tag_ty);
            try p.err_str(.enum_different_explicit_ty, ident_tok, str);
            try p.err_tok(.previous_definition, prev.tok);
            return error.ParsingFailed;
        }
    } else if (enum_ty.fixed) {
        try p.err_tok(.enum_prev_fixed, ident_tok);
        try p.err_tok(.previous_definition, prev.tok);
        return error.ParsingFailed;
    }
}

const Enumerator = struct {
    res: Result,
    num_positive_bits: usize = 0,
    num_negative_bits: usize = 0,
    fixed: bool,

    fn init(fixed_ty: ?Type) Enumerator {
        return .{
            .res = .{ .ty = fixed_ty orelse .{ .specifier = .int } },
            .fixed = fixed_ty != null,
        };
    }

    /// Increment enumerator value adjusting type if needed.
    fn incr(e: *Enumerator, p: *Parser, tok: TokenIndex) !void {
        e.res.node = .none;
        const old_val = e.res.val;
        if (old_val.opt_ref == .none) {
            // First enumerator, set to 0 fits in all types.
            e.res.val = Value.zero;
            return;
        }
        if (try e.res.val.add(e.res.val, Value.one, e.res.ty, p.comp)) {
            const byte_size = e.res.ty.sizeof(p.comp).?;
            const bit_size: u8 = @int_cast(if (e.res.ty.is_unsigned_int(p.comp)) byte_size * 8 else byte_size * 8 - 1);
            if (e.fixed) {
                try p.err_str(.enum_not_representable_fixed, tok, try p.type_str(e.res.ty));
                return;
            }
            const new_ty = if (p.comp.next_largest_int_same_sign(e.res.ty)) |larger| blk: {
                try p.err_tok(.enumerator_overflow, tok);
                break :blk larger;
            } else blk: {
                try p.err_extra(.enum_not_representable, tok, .{ .pow_2_as_string = bit_size });
                break :blk Type{ .specifier = .ulong_long };
            };
            e.res.ty = new_ty;
            _ = try e.res.val.add(old_val, Value.one, e.res.ty, p.comp);
        }
    }

    /// Set enumerator value to specified value.
    fn set(e: *Enumerator, p: *Parser, res: Result, tok: TokenIndex) !void {
        if (res.ty.specifier == .invalid) return;
        if (e.fixed and !res.ty.eql(e.res.ty, p.comp, false)) {
            if (!try res.int_fits_in_type(p, e.res.ty)) {
                try p.err_str(.enum_not_representable_fixed, tok, try p.type_str(e.res.ty));
                return error.ParsingFailed;
            }
            var copy = res;
            copy.ty = e.res.ty;
            try copy.implicit_cast(p, .int_cast);
            e.res = copy;
        } else {
            e.res = res;
            try e.res.int_cast(p, e.res.ty.integer_promotion(p.comp), tok);
        }
    }

    fn get_type_specifier(e: *const Enumerator, p: *Parser, is_packed: bool, tok: TokenIndex) !Type.Specifier {
        if (p.comp.fixed_enum_tag_specifier()) |tag_specifier| return tag_specifier;

        const char_width = (Type{ .specifier = .schar }).sizeof(p.comp).? * 8;
        const short_width = (Type{ .specifier = .short }).sizeof(p.comp).? * 8;
        const int_width = (Type{ .specifier = .int }).sizeof(p.comp).? * 8;
        if (e.num_negative_bits > 0) {
            if (is_packed and e.num_negative_bits <= char_width and e.num_positive_bits < char_width) {
                return .schar;
            } else if (is_packed and e.num_negative_bits <= short_width and e.num_positive_bits < short_width) {
                return .short;
            } else if (e.num_negative_bits <= int_width and e.num_positive_bits < int_width) {
                return .int;
            }
            const long_width = (Type{ .specifier = .long }).sizeof(p.comp).? * 8;
            if (e.num_negative_bits <= long_width and e.num_positive_bits < long_width) {
                return .long;
            }
            const long_long_width = (Type{ .specifier = .long_long }).sizeof(p.comp).? * 8;
            if (e.num_negative_bits > long_long_width or e.num_positive_bits >= long_long_width) {
                try p.err_tok(.enum_too_large, tok);
            }
            return .long_long;
        }
        if (is_packed and e.num_positive_bits <= char_width) {
            return .uchar;
        } else if (is_packed and e.num_positive_bits <= short_width) {
            return .ushort;
        } else if (e.num_positive_bits <= int_width) {
            return .uint;
        } else if (e.num_positive_bits <= (Type{ .specifier = .long }).sizeof(p.comp).? * 8) {
            return .ulong;
        }
        return .ulong_long;
    }
};

const EnumFieldAndNode = struct { field: Type.Enum.Field, node: NodeIndex };

/// enumerator : IDENTIFIER ('=' integer_const_expr)
fn enumerator(p: *Parser, e: *Enumerator) Error!?EnumFieldAndNode {
    _ = try p.pragma();
    const name_tok = (try p.eat_identifier()) orelse {
        if (p.tok_ids[p.tok_i] == .r_brace) return null;
        try p.err(.expected_identifier);
        p.skip_to(.r_brace);
        return error.ParsingFailed;
    };
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    try p.attribute_specifier();

    const err_start = p.comp.diagnostics.list.items.len;
    if (p.eat_token(.equal)) |_| {
        const specified = try p.integer_const_expr(.gnu_folding_extension);
        if (specified.val.opt_ref == .none) {
            try p.err_tok(.enum_val_unavailable, name_tok + 2);
            try e.incr(p, name_tok);
        } else {
            try e.set(p, specified, name_tok);
        }
    } else {
        try e.incr(p, name_tok);
    }

    var res = e.res;
    res.ty = try Attribute.apply_enumerator_attributes(p, res.ty, attr_buf_top);

    if (res.ty.is_unsigned_int(p.comp) or res.val.compare(.gte, Value.zero, p.comp)) {
        e.num_positive_bits = @max(e.num_positive_bits, res.val.min_unsigned_bits(p.comp));
    } else {
        e.num_negative_bits = @max(e.num_negative_bits, res.val.min_signed_bits(p.comp));
    }

    if (err_start == p.comp.diagnostics.list.items.len) {
        // only do these warnings if we didn't already warn about overflow or non-representable values
        if (e.res.val.compare(.lt, Value.zero, p.comp)) {
            const min_int = (Type{ .specifier = .int }).min_int(p.comp);
            const min_val = try Value.int(min_int, p.comp);
            if (e.res.val.compare(.lt, min_val, p.comp)) {
                try p.err_str(.enumerator_too_small, name_tok, try e.res.str(p));
            }
        } else {
            const max_int = (Type{ .specifier = .int }).max_int(p.comp);
            const max_val = try Value.int(max_int, p.comp);
            if (e.res.val.compare(.gt, max_val, p.comp)) {
                try p.err_str(.enumerator_too_large, name_tok, try e.res.str(p));
            }
        }
    }

    const interned_name = try StrInt.intern(p.comp, p.tok_slice(name_tok));
    try p.syms.define_enumeration(p, interned_name, res.ty, name_tok, e.res.val);
    const node = try p.add_node(.{
        .tag = .enum_field_decl,
        .ty = res.ty,
        .data = .{ .decl = .{
            .name = name_tok,
            .node = res.node,
        } },
    });
    try p.value_map.put(node, e.res.val);
    return EnumFieldAndNode{ .field = .{
        .name = interned_name,
        .ty = res.ty,
        .name_tok = name_tok,
        .node = res.node,
    }, .node = node };
}

/// type_qual : keyword_const | keyword_restrict | keyword_volatile | keyword_atomic
fn type_qual(p: *Parser, b: *Type.Qualifiers.Builder) Error!bool {
    var any = false;
    while (true) {
        switch (p.tok_ids[p.tok_i]) {
            .keyword_restrict, .keyword_restrict1, .keyword_restrict2 => {
                if (b.restrict != null)
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "restrict")
                else
                    b.restrict = p.tok_i;
            },
            .keyword_const, .keyword_const1, .keyword_const2 => {
                if (b.@"const" != null)
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "const")
                else
                    b.@"const" = p.tok_i;
            },
            .keyword_volatile, .keyword_volatile1, .keyword_volatile2 => {
                if (b.@"volatile" != null)
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "volatile")
                else
                    b.@"volatile" = p.tok_i;
            },
            .keyword_atomic => {
                // _Atomic(type_name) instead of just _Atomic
                if (p.tok_ids[p.tok_i + 1] == .l_paren) break;
                if (b.atomic != null)
                    try p.err_str(.duplicate_decl_spec, p.tok_i, "atomic")
                else
                    b.atomic = p.tok_i;
            },
            else => break,
        }
        p.tok_i += 1;
        any = true;
    }
    return any;
}

const Declarator = struct {
    name: TokenIndex,
    ty: Type,
    func_declarator: ?TokenIndex = null,
    old_style_func: ?TokenIndex = null,
};
const DeclaratorKind = enum { normal, abstract, param, record };

/// declarator : pointer? (IDENTIFIER | '(' declarator ')') direct_declarator*
/// abstractDeclarator
/// : pointer? ('(' abstractDeclarator ')')? directAbstractDeclarator*
fn declarator(
    p: *Parser,
    base_type: Type,
    kind: DeclaratorKind,
) Error!?Declarator {
    const start = p.tok_i;
    var d = Declarator{ .name = 0, .ty = try p.pointer(base_type) };
    if (base_type.is(.auto_type) and !d.ty.is(.auto_type)) {
        try p.err_tok(.auto_type_requires_plain_declarator, start);
        return error.ParsingFailed;
    }

    const maybe_ident = p.tok_i;
    if (kind != .abstract and (try p.eat_identifier()) != null) {
        d.name = maybe_ident;
        const combine_tok = p.tok_i;
        d.ty = try p.direct_declarator(d.ty, &d, kind);
        try d.ty.validate_combined_type(p, combine_tok);
        return d;
    } else if (p.eat_token(.l_paren)) |l_paren| blk: {
        var res = (try p.declarator(.{ .specifier = .void }, kind)) orelse {
            p.tok_i = l_paren;
            break :blk;
        };
        try p.expect_closing(l_paren, .r_paren);
        const suffix_start = p.tok_i;
        const outer = try p.direct_declarator(d.ty, &d, kind);
        try res.ty.combine(outer);
        try res.ty.validate_combined_type(p, suffix_start);
        res.old_style_func = d.old_style_func;
        if (d.func_declarator) |some| res.func_declarator = some;
        return res;
    }

    const expected_ident = p.tok_i;

    d.ty = try p.direct_declarator(d.ty, &d, kind);

    if (kind == .normal and !d.ty.is_enum_or_record()) {
        try p.err_tok(.expected_ident_or_l_paren, expected_ident);
        return error.ParsingFailed;
    }
    try d.ty.validate_combined_type(p, expected_ident);
    if (start == p.tok_i) return null;
    return d;
}

/// direct_declarator
///  : '[' type_qual* assign_expr? ']' direct_declarator?
///  | '[' keyword_static type_qual* assign_expr ']' direct_declarator?
///  | '[' type_qual+ keyword_static assign_expr ']' direct_declarator?
///  | '[' type_qual* '*' ']' direct_declarator?
///  | '(' param_decls ')' direct_declarator?
///  | '(' (IDENTIFIER (',' IDENTIFIER))? ')' direct_declarator?
/// directAbstractDeclarator
///  : '[' type_qual* assign_expr? ']'
///  | '[' keyword_static type_qual* assign_expr ']'
///  | '[' type_qual+ keyword_static assign_expr ']'
///  | '[' '*' ']'
///  | '(' param_decls? ')'
fn direct_declarator(p: *Parser, base_type: Type, d: *Declarator, kind: DeclaratorKind) Error!Type {
    if (p.eat_token(.l_bracket)) |l_bracket| {
        if (p.tok_ids[p.tok_i] == .l_bracket) {
            switch (kind) {
                .normal, .record => if (p.comp.langopts.standard.at_least(.c23)) {
                    p.tok_i -= 1;
                    return base_type;
                },
                .param, .abstract => {},
            }
            try p.err(.expected_expr);
            return error.ParsingFailed;
        }
        var res_ty = Type{
            // so that we can get any restrict type that might be present
            .specifier = .pointer,
        };
        var quals = Type.Qualifiers.Builder{};

        var got_quals = try p.type_qual(&quals);
        var static = p.eat_token(.keyword_static);
        if (static != null and !got_quals) got_quals = try p.type_qual(&quals);
        var star = p.eat_token(.asterisk);
        const size_tok = p.tok_i;

        const const_decl_folding = p.const_decl_folding;
        p.const_decl_folding = .gnu_vla_folding_extension;
        const size = if (star) |_| Result{} else try p.assign_expr();
        p.const_decl_folding = const_decl_folding;

        try p.expect_closing(l_bracket, .r_bracket);

        if (star != null and static != null) {
            try p.err_tok(.invalid_static_star, static.?);
            static = null;
        }
        if (kind != .param) {
            if (static != null)
                try p.err_tok(.static_non_param, l_bracket)
            else if (got_quals)
                try p.err_tok(.array_qualifiers, l_bracket);
            if (star) |some| try p.err_tok(.star_non_param, some);
            static = null;
            quals = .{};
            star = null;
        } else {
            try quals.finish(p, &res_ty);
        }
        if (static) |_| try size.expect(p);

        if (base_type.is(.auto_type)) {
            try p.err_str(.array_of_auto_type, d.name, p.tok_slice(d.name));
            return error.ParsingFailed;
        }

        const outer = try p.direct_declarator(base_type, d, kind);
        var max_bits = p.comp.target.ptr_bit_width();
        if (max_bits > 61) max_bits = 61;
        const max_bytes = (@as(u64, 1) << @truncate(max_bits)) - 1;

        if (!size.ty.is_int()) {
            try p.err_str(.array_size_non_int, size_tok, try p.type_str(size.ty));
            return error.ParsingFailed;
        }
        if (base_type.is(.c23_auto)) {
            // issue error later
            return Type.invalid;
        } else if (size.val.opt_ref == .none) {
            if (size.node != .none) {
                try p.err_tok(.vla, size_tok);
                if (p.func.ty == null and kind != .param and p.record.kind == .invalid) {
                    try p.err_tok(.variable_len_array_file_scope, d.name);
                }
                const expr_ty = try p.arena.create(Type.Expr);
                expr_ty.ty = .{ .specifier = .void };
                expr_ty.node = size.node;
                res_ty.data = .{ .expr = expr_ty };
                res_ty.specifier = .variable_len_array;

                if (static) |some| try p.err_tok(.useless_static, some);
            } else if (star) |_| {
                const elem_ty = try p.arena.create(Type);
                elem_ty.* = .{ .specifier = .void };
                res_ty.data = .{ .sub_type = elem_ty };
                res_ty.specifier = .unspecified_variable_len_array;
            } else {
                const arr_ty = try p.arena.create(Type.Array);
                arr_ty.elem = .{ .specifier = .void };
                arr_ty.len = 0;
                res_ty.data = .{ .array = arr_ty };
                res_ty.specifier = .incomplete_array;
            }
        } else {
            // `outer` is validated later so it may be invalid here
            const outer_size = outer.sizeof(p.comp);
            const max_elems = max_bytes / @max(1, outer_size orelse 1);

            var size_val = size.val;
            if (size_val.is_zero(p.comp)) {
                try p.err_tok(.zero_length_array, l_bracket);
            } else if (size_val.compare(.lt, Value.zero, p.comp)) {
                try p.err_tok(.negative_array_size, l_bracket);
                return error.ParsingFailed;
            }
            const arr_ty = try p.arena.create(Type.Array);
            arr_ty.elem = .{ .specifier = .void };
            arr_ty.len = size_val.to_int(u64, p.comp) orelse std.math.max_int(u64);
            if (arr_ty.len > max_elems) {
                try p.err_tok(.array_too_large, l_bracket);
                arr_ty.len = max_elems;
            }
            res_ty.data = .{ .array = arr_ty };
            res_ty.specifier = .array;
        }

        try res_ty.combine(outer);
        return res_ty;
    } else if (p.eat_token(.l_paren)) |l_paren| {
        d.func_declarator = l_paren;

        const func_ty = try p.arena.create(Type.Func);
        func_ty.params = &.{};
        func_ty.return_type.specifier = .void;
        var specifier: Type.Specifier = .func;

        if (p.eat_token(.ellipsis)) |_| {
            try p.err(.param_before_var_args);
            try p.expect_closing(l_paren, .r_paren);
            var res_ty = Type{ .specifier = .func, .data = .{ .func = func_ty } };

            const outer = try p.direct_declarator(base_type, d, kind);
            try res_ty.combine(outer);
            return res_ty;
        }

        if (try p.param_decls(d)) |params| {
            func_ty.params = params;
            if (p.eat_token(.ellipsis)) |_| specifier = .var_args_func;
        } else if (p.tok_ids[p.tok_i] == .r_paren) {
            specifier = if (p.comp.langopts.standard.at_least(.c23))
                .func
            else
                .old_style_func;
        } else if (p.tok_ids[p.tok_i] == .identifier or p.tok_ids[p.tok_i] == .extended_identifier) {
            d.old_style_func = p.tok_i;
            const param_buf_top = p.param_buf.items.len;
            try p.syms.push_scope(p);
            defer {
                p.param_buf.items.len = param_buf_top;
                p.syms.pop_scope();
            }

            specifier = .old_style_func;
            while (true) {
                const name_tok = try p.expect_identifier();
                const interned_name = try StrInt.intern(p.comp, p.tok_slice(name_tok));
                try p.syms.define_param(p, interned_name, undefined, name_tok);
                try p.param_buf.append(.{
                    .name = interned_name,
                    .name_tok = name_tok,
                    .ty = .{ .specifier = .int },
                });
                if (p.eat_token(.comma) == null) break;
            }
            func_ty.params = try p.arena.dupe(Type.Func.Param, p.param_buf.items[param_buf_top..]);
        } else {
            try p.err(.expected_param_decl);
        }

        try p.expect_closing(l_paren, .r_paren);
        var res_ty = Type{
            .specifier = specifier,
            .data = .{ .func = func_ty },
        };

        const outer = try p.direct_declarator(base_type, d, kind);
        try res_ty.combine(outer);
        return res_ty;
    } else return base_type;
}

/// pointer : '*' type_qual* pointer?
fn pointer(p: *Parser, base_ty: Type) Error!Type {
    var ty = base_ty;
    while (p.eat_token(.asterisk)) |_| {
        const elem_ty = try p.arena.create(Type);
        elem_ty.* = ty;
        ty = Type{
            .specifier = .pointer,
            .data = .{ .sub_type = elem_ty },
        };
        var quals = Type.Qualifiers.Builder{};
        _ = try p.type_qual(&quals);
        try quals.finish(p, &ty);
    }
    return ty;
}

/// param_decls : paramDecl (',' paramDecl)* (',' '...')
/// paramDecl : decl_spec (declarator | abstractDeclarator)
fn param_decls(p: *Parser, d: *Declarator) Error!?[]Type.Func.Param {
    // TODO warn about visibility of types declared here
    const param_buf_top = p.param_buf.items.len;
    defer p.param_buf.items.len = param_buf_top;
    try p.syms.push_scope(p);
    defer p.syms.pop_scope();

    while (true) {
        const attr_buf_top = p.attr_buf.len;
        defer p.attr_buf.len = attr_buf_top;
        const param_decl_spec = if (try p.decl_spec()) |some|
            some
        else if (p.comp.langopts.standard.at_least(.c23) and
            (p.tok_ids[p.tok_i] == .identifier or p.tok_ids[p.tok_i] == .extended_identifier))
        {
            // handle deprecated K&R style parameters
            const identifier = try p.expect_identifier();
            try p.err_str(.unknown_type_name, identifier, p.tok_slice(identifier));
            if (d.old_style_func == null) d.old_style_func = identifier;

            try p.param_buf.append(.{
                .name = try StrInt.intern(p.comp, p.tok_slice(identifier)),
                .name_tok = identifier,
                .ty = .{ .specifier = .int },
            });

            if (p.eat_token(.comma) == null) break;
            if (p.tok_ids[p.tok_i] == .ellipsis) break;
            continue;
        } else if (p.param_buf.items.len == param_buf_top) {
            return null;
        } else blk: {
            var spec: Type.Builder = .{};
            break :blk DeclSpec{ .ty = try spec.finish(p) };
        };

        var name_tok: TokenIndex = 0;
        const first_tok = p.tok_i;
        var param_ty = param_decl_spec.ty;
        if (try p.declarator(param_decl_spec.ty, .param)) |some| {
            if (some.old_style_func) |tok_i| try p.err_tok(.invalid_old_style_params, tok_i);
            try p.attribute_specifier();

            name_tok = some.name;
            param_ty = some.ty;
            if (some.name != 0) {
                const interned_name = try StrInt.intern(p.comp, p.tok_slice(name_tok));
                try p.syms.define_param(p, interned_name, param_ty, name_tok);
            }
        }
        param_ty = try Attribute.applyParameterAttributes(p, param_ty, attr_buf_top, .alignas_on_param);

        if (param_ty.is_func()) {
            // params declared as functions are converted to function pointers
            const elem_ty = try p.arena.create(Type);
            elem_ty.* = param_ty;
            param_ty = Type{
                .specifier = .pointer,
                .data = .{ .sub_type = elem_ty },
            };
        } else if (param_ty.is_array()) {
            // params declared as arrays are converted to pointers
            param_ty.decay_array();
        } else if (param_ty.is(.void)) {
            // validate void parameters
            if (p.param_buf.items.len == param_buf_top) {
                if (p.tok_ids[p.tok_i] != .r_paren) {
                    try p.err(.void_only_param);
                    if (param_ty.any_qual()) try p.err(.void_param_qualified);
                    return error.ParsingFailed;
                }
                return &[0]Type.Func.Param{};
            }
            try p.err(.void_must_be_first_param);
            return error.ParsingFailed;
        }

        try param_decl_spec.validate_param(p, &param_ty);
        try p.param_buf.append(.{
            .name = if (name_tok == 0) .empty else try StrInt.intern(p.comp, p.tok_slice(name_tok)),
            .name_tok = if (name_tok == 0) first_tok else name_tok,
            .ty = param_ty,
        });

        if (p.eat_token(.comma) == null) break;
        if (p.tok_ids[p.tok_i] == .ellipsis) break;
    }
    return try p.arena.dupe(Type.Func.Param, p.param_buf.items[param_buf_top..]);
}

/// type_name : spec_qual abstractDeclarator
fn type_name(p: *Parser) Error!?Type {
    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    const ty = (try p.spec_qual()) orelse return null;
    if (try p.declarator(ty, .abstract)) |some| {
        if (some.old_style_func) |tok_i| try p.err_tok(.invalid_old_style_params, tok_i);
        return try Attribute.apply_type_attributes(p, some.ty, attr_buf_top, .align_ignored);
    }
    return try Attribute.apply_type_attributes(p, ty, attr_buf_top, .align_ignored);
}

/// initializer
///  : assign_expr
///  | '{' initializerItems '}'
fn initializer(p: *Parser, init_ty: Type) Error!Result {
    // fast path for non-braced initializers
    if (p.tok_ids[p.tok_i] != .l_brace) {
        const tok = p.tok_i;
        var res = try p.assign_expr();
        try res.expect(p);
        if (try p.coerce_array_init(&res, tok, init_ty)) return res;
        try p.coerce_init(&res, tok, init_ty);
        return res;
    }
    if (init_ty.is(.auto_type)) {
        try p.err(.auto_type_with_init_list);
        return error.ParsingFailed;
    }

    var il: InitList = .{};
    defer il.deinit(p.gpa);

    _ = try p.initializer_item(&il, init_ty);

    const res = try p.convert_init_list(il, init_ty);
    var res_ty = p.nodes.items(.ty)[@int_from_enum(res)];
    res_ty.qual = init_ty.qual;
    return Result{ .ty = res_ty, .node = res };
}

/// initializerItems : designation? initializer (',' designation? initializer)* ','?
/// designation : designator+ '='
/// designator
///  : '[' integer_const_expr ']'
///  | '.' identifier
fn initializer_item(p: *Parser, il: *InitList, init_ty: Type) Error!bool {
    const l_brace = p.eat_token(.l_brace) orelse {
        const tok = p.tok_i;
        var res = try p.assign_expr();
        if (res.empty(p)) return false;

        const arr = try p.coerce_array_init(&res, tok, init_ty);
        if (!arr) try p.coerce_init(&res, tok, init_ty);
        if (il.tok != 0) {
            try p.err_tok(.initializer_overrides, tok);
            try p.err_tok(.previous_initializer, il.tok);
        }
        il.node = res.node;
        il.tok = tok;
        return true;
    };

    const is_scalar = init_ty.is_scalar();
    const is_complex = init_ty.is_complex();
    const scalar_inits_needed: usize = if (is_complex) 2 else 1;
    if (p.eat_token(.r_brace)) |_| {
        if (is_scalar) try p.err_tok(.empty_scalar_init, l_brace);
        if (il.tok != 0) {
            try p.err_tok(.initializer_overrides, l_brace);
            try p.err_tok(.previous_initializer, il.tok);
        }
        il.node = .none;
        il.tok = l_brace;
        return true;
    }

    var count: u64 = 0;
    var warned_excess = false;
    var is_str_init = false;
    var index_hint: ?u64 = null;
    while (true) : (count += 1) {
        errdefer p.skip_to(.r_brace);

        var first_tok = p.tok_i;
        var cur_ty = init_ty;
        var cur_il = il;
        var designation = false;
        var cur_index_hint: ?u64 = null;
        while (true) {
            if (p.eat_token(.l_bracket)) |l_bracket| {
                if (!cur_ty.is_array()) {
                    try p.err_str(.invalid_array_designator, l_bracket, try p.type_str(cur_ty));
                    return error.ParsingFailed;
                }
                const expr_tok = p.tok_i;
                const index_res = try p.integer_const_expr(.gnu_folding_extension);
                try p.expect_closing(l_bracket, .r_bracket);

                if (index_res.val.opt_ref == .none) {
                    try p.err_tok(.expected_integer_constant_expr, expr_tok);
                    return error.ParsingFailed;
                } else if (index_res.val.compare(.lt, Value.zero, p.comp)) {
                    try p.err_str(.negative_array_designator, l_bracket + 1, try index_res.str(p));
                    return error.ParsingFailed;
                }

                const max_len = cur_ty.array_len() orelse std.math.max_int(usize);
                const index_int = index_res.val.to_int(u64, p.comp) orelse std.math.max_int(u64);
                if (index_int >= max_len) {
                    try p.err_str(.oob_array_designator, l_bracket + 1, try index_res.str(p));
                    return error.ParsingFailed;
                }
                cur_index_hint = cur_index_hint orelse index_int;

                cur_il = try cur_il.find(p.gpa, index_int);
                cur_ty = cur_ty.elem_type();
                designation = true;
            } else if (p.eat_token(.period)) |period| {
                const field_tok = try p.expect_identifier();
                const field_str = p.tok_slice(field_tok);
                const field_name = try StrInt.intern(p.comp, field_str);
                cur_ty = cur_ty.canonicalize(.standard);
                if (!cur_ty.is_record()) {
                    try p.err_str(.invalid_field_designator, period, try p.type_str(cur_ty));
                    return error.ParsingFailed;
                } else if (!cur_ty.has_field(field_name)) {
                    try p.err_str(.no_such_field_designator, period, field_str);
                    return error.ParsingFailed;
                }

                // TODO check if union already has field set
                outer: while (true) {
                    for (cur_ty.data.record.fields, 0..) |f, i| {
                        if (f.is_anonymous_record()) {
                            // Recurse into anonymous field if it has a field by the name.
                            if (!f.ty.has_field(field_name)) continue;
                            cur_ty = f.ty.canonicalize(.standard);
                            cur_il = try il.find(p.gpa, i);
                            cur_index_hint = cur_index_hint orelse i;
                            continue :outer;
                        }
                        if (field_name == f.name) {
                            cur_il = try cur_il.find(p.gpa, i);
                            cur_ty = f.ty;
                            cur_index_hint = cur_index_hint orelse i;
                            break :outer;
                        }
                    }
                    unreachable; // we already checked that the starting type has this field
                }
                designation = true;
            } else break;
        }
        if (designation) index_hint = null;
        defer index_hint = cur_index_hint orelse null;

        if (designation) _ = try p.expect_token(.equal);

        if (!designation and cur_ty.has_attribute(.designated_init)) {
            try p.err(.designated_init_needed);
        }

        var saw = false;
        if (is_str_init and p.is_string_init(init_ty)) {
            // discard further strings
            var tmp_il = InitList{};
            defer tmp_il.deinit(p.gpa);
            saw = try p.initializer_item(&tmp_il, .{ .specifier = .void });
        } else if (count == 0 and p.is_string_init(init_ty)) {
            is_str_init = true;
            saw = try p.initializer_item(il, init_ty);
        } else if (is_scalar and count >= scalar_inits_needed) {
            // discard further scalars
            var tmp_il = InitList{};
            defer tmp_il.deinit(p.gpa);
            saw = try p.initializer_item(&tmp_il, .{ .specifier = .void });
        } else if (p.tok_ids[p.tok_i] == .l_brace) {
            if (designation) {
                // designation overrides previous value, let existing mechanism handle it
                saw = try p.initializer_item(cur_il, cur_ty);
            } else if (try p.find_aggregate_initializer(&cur_il, &cur_ty, &index_hint)) {
                saw = try p.initializer_item(cur_il, cur_ty);
            } else {
                // discard further values
                var tmp_il = InitList{};
                defer tmp_il.deinit(p.gpa);
                saw = try p.initializer_item(&tmp_il, .{ .specifier = .void });
                if (!warned_excess) try p.err_tok(if (init_ty.is_array()) .excess_array_init else .excess_struct_init, first_tok);
                warned_excess = true;
            }
        } else single_item: {
            first_tok = p.tok_i;
            var res = try p.assign_expr();
            saw = !res.empty(p);
            if (!saw) break :single_item;

            excess: {
                if (index_hint) |*hint| {
                    if (try p.find_scalar_initializer_at(&cur_il, &cur_ty, &res, first_tok, hint)) break :excess;
                } else if (try p.find_scalar_initializer(&cur_il, &cur_ty, &res, first_tok)) break :excess;

                if (designation) break :excess;
                if (!warned_excess) try p.err_tok(if (init_ty.is_array()) .excess_array_init else .excess_struct_init, first_tok);
                warned_excess = true;

                break :single_item;
            }

            const arr = try p.coerce_array_init(&res, first_tok, cur_ty);
            if (!arr) try p.coerce_init(&res, first_tok, cur_ty);
            if (cur_il.tok != 0) {
                try p.err_tok(.initializer_overrides, first_tok);
                try p.err_tok(.previous_initializer, cur_il.tok);
            }
            cur_il.node = res.node;
            cur_il.tok = first_tok;
        }

        if (!saw) {
            if (designation) {
                try p.err(.expected_expr);
                return error.ParsingFailed;
            }
            break;
        } else if (count == 1) {
            if (is_str_init) try p.err_tok(.excess_str_init, first_tok);
            if (is_scalar and !is_complex) try p.err_tok(.excess_scalar_init, first_tok);
        } else if (count == 2) {
            if (is_scalar and is_complex) try p.err_tok(.excess_scalar_init, first_tok);
        }

        if (p.eat_token(.comma) == null) break;
    }
    try p.expect_closing(l_brace, .r_brace);

    if (is_complex and count == 1) { // count of 1 means we saw exactly 2 items in the initializer list
        try p.err_tok(.complex_component_init, l_brace);
    }
    if (is_scalar or is_str_init) return true;
    if (il.tok != 0) {
        try p.err_tok(.initializer_overrides, l_brace);
        try p.err_tok(.previous_initializer, il.tok);
    }
    il.node = .none;
    il.tok = l_brace;
    return true;
}

/// Returns true if the value is unused.
fn find_scalar_initializer_at(p: *Parser, il: **InitList, ty: *Type, res: *Result, first_tok: TokenIndex, start_index: *u64) Error!bool {
    if (ty.is_array()) {
        if (il.*.node != .none) return false;
        start_index.* += 1;

        const arr_ty = ty.*;
        const elem_count = arr_ty.array_len() orelse std.math.max_int(u64);
        if (elem_count == 0) {
            try p.err_tok(.empty_aggregate_init_braces, first_tok);
            return error.ParsingFailed;
        }
        const elem_ty = arr_ty.elem_type();
        const arr_il = il.*;
        if (start_index.* < elem_count) {
            ty.* = elem_ty;
            il.* = try arr_il.find(p.gpa, start_index.*);
            _ = try p.find_scalar_initializer(il, ty, res, first_tok);
            return true;
        }
        return false;
    } else if (ty.get(.@"struct")) |struct_ty| {
        if (il.*.node != .none) return false;
        start_index.* += 1;

        const fields = struct_ty.data.record.fields;
        if (fields.len == 0) {
            try p.err_tok(.empty_aggregate_init_braces, first_tok);
            return error.ParsingFailed;
        }
        const struct_il = il.*;
        if (start_index.* < fields.len) {
            const field = fields[@int_cast(start_index.*)];
            ty.* = field.ty;
            il.* = try struct_il.find(p.gpa, start_index.*);
            _ = try p.find_scalar_initializer(il, ty, res, first_tok);
            return true;
        }
        return false;
    } else if (ty.get(.@"union")) |_| {
        return false;
    }
    return il.*.node == .none;
}

/// Returns true if the value is unused.
fn find_scalar_initializer(p: *Parser, il: **InitList, ty: *Type, res: *Result, first_tok: TokenIndex) Error!bool {
    const actual_ty = res.ty;
    if (ty.is_array() or ty.is_complex()) {
        if (il.*.node != .none) return false;
        if (try p.coerce_array_init_extra(res, first_tok, ty.*, false)) return true;
        const start_index = il.*.list.items.len;
        var index = if (start_index != 0) il.*.list.items[start_index - 1].index else start_index;

        const arr_ty = ty.*;
        const elem_count: u64 = arr_ty.expected_init_list_size() orelse std.math.max_int(u64);
        if (elem_count == 0) {
            try p.err_tok(.empty_aggregate_init_braces, first_tok);
            return error.ParsingFailed;
        }
        const elem_ty = arr_ty.elem_type();
        const arr_il = il.*;
        while (index < elem_count) : (index += 1) {
            ty.* = elem_ty;
            il.* = try arr_il.find(p.gpa, index);
            if (il.*.node == .none and actual_ty.eql(elem_ty, p.comp, false)) return true;
            if (try p.find_scalar_initializer(il, ty, res, first_tok)) return true;
        }
        return false;
    } else if (ty.get(.@"struct")) |struct_ty| {
        if (il.*.node != .none) return false;
        if (actual_ty.eql(ty.*, p.comp, false)) return true;
        const start_index = il.*.list.items.len;
        var index = if (start_index != 0) il.*.list.items[start_index - 1].index + 1 else start_index;

        const fields = struct_ty.data.record.fields;
        if (fields.len == 0) {
            try p.err_tok(.empty_aggregate_init_braces, first_tok);
            return error.ParsingFailed;
        }
        const struct_il = il.*;
        while (index < fields.len) : (index += 1) {
            const field = fields[@int_cast(index)];
            ty.* = field.ty;
            il.* = try struct_il.find(p.gpa, index);
            if (il.*.node == .none and actual_ty.eql(field.ty, p.comp, false)) return true;
            if (il.*.node == .none and try p.coerce_array_init_extra(res, first_tok, ty.*, false)) return true;
            if (try p.find_scalar_initializer(il, ty, res, first_tok)) return true;
        }
        return false;
    } else if (ty.get(.@"union")) |union_ty| {
        if (il.*.node != .none) return false;
        if (actual_ty.eql(ty.*, p.comp, false)) return true;
        if (union_ty.data.record.fields.len == 0) {
            try p.err_tok(.empty_aggregate_init_braces, first_tok);
            return error.ParsingFailed;
        }
        ty.* = union_ty.data.record.fields[0].ty;
        il.* = try il.*.find(p.gpa, 0);
        // if (il.*.node == .none and actual_ty.eql(ty, p.comp, false)) return true;
        if (try p.coerce_array_init_extra(res, first_tok, ty.*, false)) return true;
        if (try p.find_scalar_initializer(il, ty, res, first_tok)) return true;
        return false;
    }
    return il.*.node == .none;
}

fn find_aggregate_initializer(p: *Parser, il: **InitList, ty: *Type, start_index: *?u64) Error!bool {
    if (ty.is_array()) {
        if (il.*.node != .none) return false;
        const list_index = il.*.list.items.len;
        const index = if (start_index.*) |*some| blk: {
            some.* += 1;
            break :blk some.*;
        } else if (list_index != 0)
            il.*.list.items[list_index - 1].index + 1
        else
            list_index;

        const arr_ty = ty.*;
        const elem_count = arr_ty.array_len() orelse std.math.max_int(u64);
        const elem_ty = arr_ty.elem_type();
        if (index < elem_count) {
            ty.* = elem_ty;
            il.* = try il.*.find(p.gpa, index);
            return true;
        }
        return false;
    } else if (ty.get(.@"struct")) |struct_ty| {
        if (il.*.node != .none) return false;
        const list_index = il.*.list.items.len;
        const index = if (start_index.*) |*some| blk: {
            some.* += 1;
            break :blk some.*;
        } else if (list_index != 0)
            il.*.list.items[list_index - 1].index + 1
        else
            list_index;

        const field_count = struct_ty.data.record.fields.len;
        if (index < field_count) {
            ty.* = struct_ty.data.record.fields[@int_cast(index)].ty;
            il.* = try il.*.find(p.gpa, index);
            return true;
        }
        return false;
    } else if (ty.get(.@"union")) |union_ty| {
        if (il.*.node != .none) return false;
        if (start_index.*) |_| return false; // overrides
        if (union_ty.data.record.fields.len == 0) return false;

        ty.* = union_ty.data.record.fields[0].ty;
        il.* = try il.*.find(p.gpa, 0);
        return true;
    } else {
        try p.err(.too_many_scalar_init_braces);
        return il.*.node == .none;
    }
}

fn coerce_array_init(p: *Parser, item: *Result, tok: TokenIndex, target: Type) !bool {
    return p.coerce_array_init_extra(item, tok, target, true);
}

fn coerce_array_init_extra(p: *Parser, item: *Result, tok: TokenIndex, target: Type, report_err: bool) !bool {
    if (!target.is_array()) return false;

    const is_str_lit = p.node_is(item.node, .string_literal_expr);
    if (!is_str_lit and !p.node_is_compound_literal(item.node) or !item.ty.is_array()) {
        if (!report_err) return false;
        try p.err_tok(.array_init_str, tok);
        return true; // do not do further coercion
    }

    const target_spec = target.elem_type().canonicalize(.standard).specifier;
    const item_spec = item.ty.elem_type().canonicalize(.standard).specifier;

    const compatible = target.elem_type().eql(item.ty.elem_type(), p.comp, false) or
        (is_str_lit and item_spec == .char and (target_spec == .uchar or target_spec == .schar)) or
        (is_str_lit and item_spec == .uchar and (target_spec == .uchar or target_spec == .schar or target_spec == .char));
    if (!compatible) {
        if (!report_err) return false;
        const e_msg = " with array of type ";
        try p.err_str(.incompatible_array_init, tok, try p.type_pair_str_extra(target, e_msg, item.ty));
        return true; // do not do further coercion
    }

    if (target.get(.array)) |arr_ty| {
        assert(item.ty.specifier == .array);
        const len = item.ty.array_len().?;
        const array_len = arr_ty.array_len().?;
        if (is_str_lit) {
            // the null byte of a string can be dropped
            if (len - 1 > array_len and report_err) {
                try p.err_tok(.str_init_too_long, tok);
            }
        } else if (len > array_len and report_err) {
            try p.err_str(
                .arr_init_too_long,
                tok,
                try p.type_pair_str_extra(target, " with array of type ", item.ty),
            );
        }
    }
    return true;
}

fn coerce_init(p: *Parser, item: *Result, tok: TokenIndex, target: Type) !void {
    if (target.is(.void)) return; // Do not do type coercion on excess items

    const node = item.node;
    try item.lval_conversion(p);
    if (target.is(.auto_type)) {
        if (p.get_node(node, .member_access_expr) orelse p.get_node(node, .member_access_ptr_expr)) |member_node| {
            if (p.tmp_tree().is_bitfield(member_node)) try p.err_tok(.auto_type_from_bitfield, tok);
        }
        return;
    } else if (target.is(.c23_auto)) {
        return;
    }

    try item.coerce(p, target, tok, .init);
}

fn is_string_init(p: *Parser, ty: Type) bool {
    if (!ty.is_array() or !ty.elem_type().is_int()) return false;
    var i = p.tok_i;
    while (true) : (i += 1) {
        switch (p.tok_ids[i]) {
            .l_paren => {},
            .string_literal,
            .string_literal_utf_16,
            .string_literal_utf_8,
            .string_literal_utf_32,
            .string_literal_wide,
            => return true,
            else => return false,
        }
    }
}

/// Convert InitList into an AST
fn convert_init_list(p: *Parser, il: InitList, init_ty: Type) Error!NodeIndex {
    const is_complex = init_ty.is_complex();
    if (init_ty.is_scalar() and !is_complex) {
        if (il.node == .none) {
            return p.add_node(.{ .tag = .default_init_expr, .ty = init_ty, .data = undefined });
        }
        return il.node;
    } else if (init_ty.is(.variable_len_array)) {
        return error.ParsingFailed; // vla invalid, reported earlier
    } else if (init_ty.is_array() or is_complex) {
        if (il.node != .none) {
            return il.node;
        }
        const list_buf_top = p.list_buf.items.len;
        defer p.list_buf.items.len = list_buf_top;

        const elem_ty = init_ty.elem_type();

        const max_items: u64 = init_ty.expected_init_list_size() orelse std.math.max_int(usize);
        var start: u64 = 0;
        for (il.list.items) |*init| {
            if (init.index > start) {
                const elem = try p.add_node(.{
                    .tag = .array_filler_expr,
                    .ty = elem_ty,
                    .data = .{ .int = init.index - start },
                });
                try p.list_buf.append(elem);
            }
            start = init.index + 1;

            const elem = try p.convert_init_list(init.list, elem_ty);
            try p.list_buf.append(elem);
        }

        var arr_init_node: Tree.Node = .{
            .tag = .array_init_expr_two,
            .ty = init_ty,
            .data = .{ .bin = .{ .lhs = .none, .rhs = .none } },
        };

        if (init_ty.specifier == .incomplete_array) {
            arr_init_node.ty.specifier = .array;
            arr_init_node.ty.data.array.len = start;
        } else if (init_ty.is(.incomplete_array)) {
            const arr_ty = try p.arena.create(Type.Array);
            arr_ty.* = .{ .elem = init_ty.elem_type(), .len = start };
            arr_init_node.ty = .{
                .specifier = .array,
                .data = .{ .array = arr_ty },
            };
            const attrs = init_ty.get_attributes();
            arr_init_node.ty = try arr_init_node.ty.with_attributes(p.arena, attrs);
        } else if (start < max_items) {
            const elem = try p.add_node(.{
                .tag = .array_filler_expr,
                .ty = elem_ty,
                .data = .{ .int = max_items - start },
            });
            try p.list_buf.append(elem);
        }

        const items = p.list_buf.items[list_buf_top..];
        switch (items.len) {
            0 => {},
            1 => arr_init_node.data.bin.lhs = items[0],
            2 => arr_init_node.data.bin = .{ .lhs = items[0], .rhs = items[1] },
            else => {
                arr_init_node.tag = .array_init_expr;
                arr_init_node.data = .{ .range = try p.add_list(items) };
            },
        }
        return try p.add_node(arr_init_node);
    } else if (init_ty.get(.@"struct")) |struct_ty| {
        assert(!struct_ty.has_incomplete_size());
        if (il.node != .none) {
            return il.node;
        }

        const list_buf_top = p.list_buf.items.len;
        defer p.list_buf.items.len = list_buf_top;

        var init_index: usize = 0;
        for (struct_ty.data.record.fields, 0..) |f, i| {
            if (init_index < il.list.items.len and il.list.items[init_index].index == i) {
                const item = try p.convert_init_list(il.list.items[init_index].list, f.ty);
                try p.list_buf.append(item);
                init_index += 1;
            } else {
                const item = try p.add_node(.{ .tag = .default_init_expr, .ty = f.ty, .data = undefined });
                try p.list_buf.append(item);
            }
        }

        var struct_init_node: Tree.Node = .{
            .tag = .struct_init_expr_two,
            .ty = init_ty,
            .data = .{ .bin = .{ .lhs = .none, .rhs = .none } },
        };
        const items = p.list_buf.items[list_buf_top..];
        switch (items.len) {
            0 => {},
            1 => struct_init_node.data.bin.lhs = items[0],
            2 => struct_init_node.data.bin = .{ .lhs = items[0], .rhs = items[1] },
            else => {
                struct_init_node.tag = .struct_init_expr;
                struct_init_node.data = .{ .range = try p.add_list(items) };
            },
        }
        return try p.add_node(struct_init_node);
    } else if (init_ty.get(.@"union")) |union_ty| {
        if (il.node != .none) {
            return il.node;
        }

        var union_init_node: Tree.Node = .{
            .tag = .union_init_expr,
            .ty = init_ty,
            .data = .{ .union_init = .{ .field_index = 0, .node = .none } },
        };
        if (union_ty.data.record.fields.len == 0) {
            // do nothing for empty unions
        } else if (il.list.items.len == 0) {
            union_init_node.data.union_init.node = try p.add_node(.{
                .tag = .default_init_expr,
                .ty = init_ty,
                .data = undefined,
            });
        } else {
            const init = il.list.items[0];
            const index: u32 = @truncate(init.index);
            const field_ty = union_ty.data.record.fields[index].ty;
            union_init_node.data.union_init = .{
                .field_index = index,
                .node = try p.convert_init_list(init.list, field_ty),
            };
        }
        return try p.add_node(union_init_node);
    } else {
        return error.ParsingFailed; // initializer target is invalid, reported earlier
    }
}

fn msvc_asm_stmt(p: *Parser) Error!?NodeIndex {
    return p.todo("MSVC assembly statements");
}

/// asm_operand : ('[' IDENTIFIER ']')? asm_str '(' expr ')'
fn asm_operand(p: *Parser, names: *std.ArrayList(?TokenIndex), constraints: *NodeList, exprs: *NodeList) Error!void {
    if (p.eat_token(.l_bracket)) |l_bracket| {
        const ident = (try p.eat_identifier()) orelse {
            try p.err(.expected_identifier);
            return error.ParsingFailed;
        };
        try names.append(ident);
        try p.expect_closing(l_bracket, .r_bracket);
    } else {
        try names.append(null);
    }
    const constraint = try p.asm_str();
    try constraints.append(constraint.node);

    const l_paren = p.eat_token(.l_paren) orelse {
        try p.err_extra(.expected_token, p.tok_i, .{ .tok_id = .{ .actual = p.tok_ids[p.tok_i], .expected = .l_paren } });
        return error.ParsingFailed;
    };
    const res = try p.expr();
    try p.expect_closing(l_paren, .r_paren);
    try res.expect(p);
    try exprs.append(res.node);
}

/// gnu_asm_stmt
///  : asm_str
///  | asm_str ':' asm_operand*
///  | asm_str ':' asm_operand* ':' asm_operand*
///  | asm_str ':' asm_operand* ':' asm_operand* : asm_str? (',' asm_str)*
///  | asm_str ':' asm_operand* ':' asm_operand* : asm_str? (',' asm_str)* : IDENTIFIER (',' IDENTIFIER)*
fn gnu_asm_stmt(p: *Parser, quals: Tree.GNUAssemblyQualifiers, l_paren: TokenIndex) Error!NodeIndex {
    const asm_str = try p.asm_str();
    try p.check_asm_str(asm_str.val, l_paren);

    if (p.tok_ids[p.tok_i] == .r_paren) {
        return p.add_node(.{
            .tag = .gnu_asm_simple,
            .ty = .{ .specifier = .void },
            .data = .{ .un = asm_str.node },
        });
    }

    const expected_items = 8; // arbitrarily chosen, most assembly will have fewer than 8 inputs/outputs/constraints/names
    const bytes_needed = expected_items * @size_of(?TokenIndex) + expected_items * 3 * @size_of(NodeIndex);

    var stack_fallback = std.heap.stack_fallback(bytes_needed, p.gpa);
    const allocator = stack_fallback.get();

    // TODO: Consider using a TokenIndex of 0 instead of null if we need to store the names in the tree
    var names = std.ArrayList(?TokenIndex).init_capacity(allocator, expected_items) catch unreachable; // stack allocation already succeeded
    defer names.deinit();
    var constraints = NodeList.init_capacity(allocator, expected_items) catch unreachable; // stack allocation already succeeded
    defer constraints.deinit();
    var exprs = NodeList.init_capacity(allocator, expected_items) catch unreachable; //stack allocation already succeeded
    defer exprs.deinit();
    var clobbers = NodeList.init_capacity(allocator, expected_items) catch unreachable; //stack allocation already succeeded
    defer clobbers.deinit();

    // Outputs
    var ate_extra_colon = false;
    if (p.eat_token(.colon) orelse p.eat_token(.colon_colon)) |tok_i| {
        ate_extra_colon = p.tok_ids[tok_i] == .colon_colon;
        if (!ate_extra_colon) {
            if (p.tok_ids[p.tok_i].is_string_literal() or p.tok_ids[p.tok_i] == .l_bracket) {
                while (true) {
                    try p.asm_operand(&names, &constraints, &exprs);
                    if (p.eat_token(.comma) == null) break;
                }
            }
        }
    }

    const num_outputs = names.items.len;

    // Inputs
    if (ate_extra_colon or p.tok_ids[p.tok_i] == .colon or p.tok_ids[p.tok_i] == .colon_colon) {
        if (ate_extra_colon) {
            ate_extra_colon = false;
        } else {
            ate_extra_colon = p.tok_ids[p.tok_i] == .colon_colon;
            p.tok_i += 1;
        }
        if (!ate_extra_colon) {
            if (p.tok_ids[p.tok_i].is_string_literal() or p.tok_ids[p.tok_i] == .l_bracket) {
                while (true) {
                    try p.asm_operand(&names, &constraints, &exprs);
                    if (p.eat_token(.comma) == null) break;
                }
            }
        }
    }
    std.debug.assert(names.items.len == constraints.items.len and constraints.items.len == exprs.items.len);
    const num_inputs = names.items.len - num_outputs;
    _ = num_inputs;

    // Clobbers
    if (ate_extra_colon or p.tok_ids[p.tok_i] == .colon or p.tok_ids[p.tok_i] == .colon_colon) {
        if (ate_extra_colon) {
            ate_extra_colon = false;
        } else {
            ate_extra_colon = p.tok_ids[p.tok_i] == .colon_colon;
            p.tok_i += 1;
        }
        if (!ate_extra_colon and p.tok_ids[p.tok_i].is_string_literal()) {
            while (true) {
                const clobber = try p.asm_str();
                try clobbers.append(clobber.node);
                if (p.eat_token(.comma) == null) break;
            }
        }
    }

    if (!quals.goto and (p.tok_ids[p.tok_i] != .r_paren or ate_extra_colon)) {
        try p.err_extra(.expected_token, p.tok_i, .{ .tok_id = .{ .actual = p.tok_ids[p.tok_i], .expected = .r_paren } });
        return error.ParsingFailed;
    }

    // Goto labels
    var num_labels: u32 = 0;
    if (ate_extra_colon or p.tok_ids[p.tok_i] == .colon) {
        if (!ate_extra_colon) {
            p.tok_i += 1;
        }
        while (true) {
            const ident = (try p.eat_identifier()) orelse {
                try p.err(.expected_identifier);
                return error.ParsingFailed;
            };
            const ident_str = p.tok_slice(ident);
            const label = p.find_label(ident_str) orelse blk: {
                try p.labels.append(.{ .unresolved_goto = ident });
                break :blk ident;
            };
            try names.append(ident);

            const elem_ty = try p.arena.create(Type);
            elem_ty.* = .{ .specifier = .void };
            const result_ty = Type{ .specifier = .pointer, .data = .{ .sub_type = elem_ty } };

            const label_addr_node = try p.add_node(.{
                .tag = .addr_of_label,
                .data = .{ .decl_ref = label },
                .ty = result_ty,
            });
            try exprs.append(label_addr_node);

            num_labels += 1;
            if (p.eat_token(.comma) == null) break;
        }
    } else if (quals.goto) {
        try p.err_extra(.expected_token, p.tok_i, .{ .tok_id = .{ .actual = p.tok_ids[p.tok_i], .expected = .colon } });
        return error.ParsingFailed;
    }

    // TODO: validate and insert into AST
    return .none;
}

fn check_asm_str(p: *Parser, asm_str: Value, tok: TokenIndex) !void {
    if (!p.comp.langopts.gnu_asm) {
        const str = p.comp.interner.get(asm_str.ref()).bytes;
        if (str.len > 1) {
            // Empty string (just a NUL byte) is ok because it does not emit any assembly
            try p.err_tok(.gnu_asm_disabled, tok);
        }
    }
}

/// assembly
///  : keyword_asm asmQual* '(' asm_str ')'
///  | keyword_asm asmQual* '(' gnu_asm_stmt ')'
///  | keyword_asm msvc_asm_stmt
fn assembly(p: *Parser, kind: enum { global, decl_label, stmt }) Error!?NodeIndex {
    const asm_tok = p.tok_i;
    switch (p.tok_ids[p.tok_i]) {
        .keyword_asm => {
            try p.err(.extension_token_used);
            p.tok_i += 1;
        },
        .keyword_asm1, .keyword_asm2 => p.tok_i += 1,
        else => return null,
    }

    if (!p.tok_ids[p.tok_i].can_open_gccasm_stmt()) {
        return p.msvc_asm_stmt();
    }

    var quals: Tree.GNUAssemblyQualifiers = .{};
    while (true) : (p.tok_i += 1) switch (p.tok_ids[p.tok_i]) {
        .keyword_volatile, .keyword_volatile1, .keyword_volatile2 => {
            if (kind != .stmt) try p.err_str(.meaningless_asm_qual, p.tok_i, "volatile");
            if (quals.@"volatile") try p.err_str(.duplicate_asm_qual, p.tok_i, "volatile");
            quals.@"volatile" = true;
        },
        .keyword_inline, .keyword_inline1, .keyword_inline2 => {
            if (kind != .stmt) try p.err_str(.meaningless_asm_qual, p.tok_i, "inline");
            if (quals.@"inline") try p.err_str(.duplicate_asm_qual, p.tok_i, "inline");
            quals.@"inline" = true;
        },
        .keyword_goto => {
            if (kind != .stmt) try p.err_str(.meaningless_asm_qual, p.tok_i, "goto");
            if (quals.goto) try p.err_str(.duplicate_asm_qual, p.tok_i, "goto");
            quals.goto = true;
        },
        else => break,
    };

    const l_paren = try p.expect_token(.l_paren);
    var result_node: NodeIndex = .none;
    switch (kind) {
        .decl_label => {
            const asm_str = try p.asm_str();
            const str = try p.remove_null(asm_str.val);

            const attr = Attribute{ .tag = .asm_label, .args = .{ .asm_label = .{ .name = str } }, .syntax = .keyword };
            try p.attr_buf.append(p.gpa, .{ .attr = attr, .tok = asm_tok });
        },
        .global => {
            const asm_str = try p.asm_str();
            try p.check_asm_str(asm_str.val, l_paren);
            result_node = try p.add_node(.{
                .tag = .file_scope_asm,
                .ty = .{ .specifier = .void },
                .data = .{ .decl = .{ .name = asm_tok, .node = asm_str.node } },
            });
        },
        .stmt => result_node = try p.gnu_asm_stmt(quals, l_paren),
    }
    try p.expect_closing(l_paren, .r_paren);

    if (kind != .decl_label) _ = try p.expect_token(.semicolon);
    return result_node;
}

/// Same as string_literal but errors on unicode and wide string literals
fn asm_str(p: *Parser) Error!Result {
    var i = p.tok_i;
    while (true) : (i += 1) switch (p.tok_ids[i]) {
        .string_literal, .unterminated_string_literal => {},
        .string_literal_utf_16, .string_literal_utf_8, .string_literal_utf_32 => {
            try p.err_str(.invalid_asm_str, p.tok_i, "unicode");
            return error.ParsingFailed;
        },
        .string_literal_wide => {
            try p.err_str(.invalid_asm_str, p.tok_i, "wide");
            return error.ParsingFailed;
        },
        else => {
            if (i == p.tok_i) {
                try p.err_str(.expected_str_literal_in, p.tok_i, "asm");
                return error.ParsingFailed;
            }
            break;
        },
    };
    return try p.string_literal();
}

// ====== statements ======

/// stmt
///  : labeled_stmt
///  | compound_stmt
///  | keyword_if '(' expr ')' stmt (keyword_else stmt)?
///  | keyword_switch '(' expr ')' stmt
///  | keyword_while '(' expr ')' stmt
///  | keyword_do stmt while '(' expr ')' ';'
///  | keyword_for '(' (decl | expr? ';') expr? ';' expr? ')' stmt
///  | keyword_goto (IDENTIFIER | ('*' expr)) ';'
///  | keyword_continue ';'
///  | keyword_break ';'
///  | keyword_return expr? ';'
///  | assembly ';'
///  | expr? ';'
fn stmt(p: *Parser) Error!NodeIndex {
    if (try p.labeled_stmt()) |some| return some;
    if (try p.compound_stmt(false, null)) |some| return some;
    if (p.eat_token(.keyword_if)) |_| {
        const l_paren = try p.expect_token(.l_paren);
        const cond_tok = p.tok_i;
        var cond = try p.expr();
        try cond.expect(p);
        try cond.lval_conversion(p);
        try cond.usual_unary_conversion(p, cond_tok);
        if (!cond.ty.is_scalar())
            try p.err_str(.statement_scalar, l_paren + 1, try p.type_str(cond.ty));
        try cond.save_value(p);
        try p.expect_closing(l_paren, .r_paren);

        const then = try p.stmt();
        const @"else" = if (p.eat_token(.keyword_else)) |_| try p.stmt() else .none;

        if (then != .none and @"else" != .none)
            return try p.add_node(.{
                .tag = .if_then_else_stmt,
                .data = .{ .if3 = .{ .cond = cond.node, .body = (try p.add_list(&.{ then, @"else" })).start } },
            })
        else
            return try p.add_node(.{
                .tag = .if_then_stmt,
                .data = .{ .bin = .{ .lhs = cond.node, .rhs = then } },
            });
    }
    if (p.eat_token(.keyword_switch)) |_| {
        const l_paren = try p.expect_token(.l_paren);
        const cond_tok = p.tok_i;
        var cond = try p.expr();
        try cond.expect(p);
        try cond.lval_conversion(p);
        try cond.usual_unary_conversion(p, cond_tok);

        if (!cond.ty.is_int())
            try p.err_str(.statement_int, l_paren + 1, try p.type_str(cond.ty));
        try cond.save_value(p);
        try p.expect_closing(l_paren, .r_paren);

        const old_switch = p.@"switch";
        var @"switch" = Switch{
            .ranges = std.ArrayList(Switch.Range).init(p.gpa),
            .ty = cond.ty,
            .comp = p.comp,
        };
        p.@"switch" = &@"switch";
        defer {
            @"switch".ranges.deinit();
            p.@"switch" = old_switch;
        }

        const body = try p.stmt();

        return try p.add_node(.{
            .tag = .switch_stmt,
            .data = .{ .bin = .{ .lhs = cond.node, .rhs = body } },
        });
    }
    if (p.eat_token(.keyword_while)) |_| {
        const l_paren = try p.expect_token(.l_paren);
        const cond_tok = p.tok_i;
        var cond = try p.expr();
        try cond.expect(p);
        try cond.lval_conversion(p);
        try cond.usual_unary_conversion(p, cond_tok);
        if (!cond.ty.is_scalar())
            try p.err_str(.statement_scalar, l_paren + 1, try p.type_str(cond.ty));
        try cond.save_value(p);
        try p.expect_closing(l_paren, .r_paren);

        const body = body: {
            const old_loop = p.in_loop;
            p.in_loop = true;
            defer p.in_loop = old_loop;
            break :body try p.stmt();
        };

        return try p.add_node(.{
            .tag = .while_stmt,
            .data = .{ .bin = .{ .lhs = cond.node, .rhs = body } },
        });
    }
    if (p.eat_token(.keyword_do)) |_| {
        const body = body: {
            const old_loop = p.in_loop;
            p.in_loop = true;
            defer p.in_loop = old_loop;
            break :body try p.stmt();
        };

        _ = try p.expect_token(.keyword_while);
        const l_paren = try p.expect_token(.l_paren);
        const cond_tok = p.tok_i;
        var cond = try p.expr();
        try cond.expect(p);
        try cond.lval_conversion(p);
        try cond.usual_unary_conversion(p, cond_tok);

        if (!cond.ty.is_scalar())
            try p.err_str(.statement_scalar, l_paren + 1, try p.type_str(cond.ty));
        try cond.save_value(p);
        try p.expect_closing(l_paren, .r_paren);

        _ = try p.expect_token(.semicolon);
        return try p.add_node(.{
            .tag = .do_while_stmt,
            .data = .{ .bin = .{ .lhs = cond.node, .rhs = body } },
        });
    }
    if (p.eat_token(.keyword_for)) |_| {
        try p.syms.push_scope(p);
        defer p.syms.pop_scope();
        const decl_buf_top = p.decl_buf.items.len;
        defer p.decl_buf.items.len = decl_buf_top;

        const l_paren = try p.expect_token(.l_paren);
        const got_decl = try p.decl();

        // for (init
        const init_start = p.tok_i;
        var err_start = p.comp.diagnostics.list.items.len;
        var init = if (!got_decl) try p.expr() else Result{};
        try init.save_value(p);
        try init.maybe_warn_unused(p, init_start, err_start);
        if (!got_decl) _ = try p.expect_token(.semicolon);

        // for (init; cond
        const cond_tok = p.tok_i;
        var cond = try p.expr();
        if (cond.node != .none) {
            try cond.lval_conversion(p);
            try cond.usual_unary_conversion(p, cond_tok);
            if (!cond.ty.is_scalar())
                try p.err_str(.statement_scalar, l_paren + 1, try p.type_str(cond.ty));
        }
        try cond.save_value(p);
        _ = try p.expect_token(.semicolon);

        // for (init; cond; incr
        const incr_start = p.tok_i;
        err_start = p.comp.diagnostics.list.items.len;
        var incr = try p.expr();
        try incr.maybe_warn_unused(p, incr_start, err_start);
        try incr.save_value(p);
        try p.expect_closing(l_paren, .r_paren);

        const body = body: {
            const old_loop = p.in_loop;
            p.in_loop = true;
            defer p.in_loop = old_loop;
            break :body try p.stmt();
        };

        if (got_decl) {
            const start = (try p.add_list(p.decl_buf.items[decl_buf_top..])).start;
            const end = (try p.add_list(&.{ cond.node, incr.node, body })).end;

            return try p.add_node(.{
                .tag = .for_decl_stmt,
                .data = .{ .range = .{ .start = start, .end = end } },
            });
        } else if (init.node == .none and cond.node == .none and incr.node == .none) {
            return try p.add_node(.{
                .tag = .forever_stmt,
                .data = .{ .un = body },
            });
        } else return try p.add_node(.{ .tag = .for_stmt, .data = .{ .if3 = .{
            .cond = body,
            .body = (try p.add_list(&.{ init.node, cond.node, incr.node })).start,
        } } });
    }
    if (p.eat_token(.keyword_goto)) |goto_tok| {
        if (p.eat_token(.asterisk)) |_| {
            const expr_tok = p.tok_i;
            var e = try p.expr();
            try e.expect(p);
            try e.lval_conversion(p);
            p.computed_goto_tok = p.computed_goto_tok orelse goto_tok;
            if (!e.ty.is_ptr()) {
                const elem_ty = try p.arena.create(Type);
                elem_ty.* = .{ .specifier = .void, .qual = .{ .@"const" = true } };
                const result_ty = Type{
                    .specifier = .pointer,
                    .data = .{ .sub_type = elem_ty },
                };
                if (!e.ty.is_int()) {
                    try p.err_str(.incompatible_arg, expr_tok, try p.type_pair_str_extra(e.ty, " to parameter of incompatible type ", result_ty));
                    return error.ParsingFailed;
                }
                if (e.val.is_zero(p.comp)) {
                    try e.null_cast(p, result_ty);
                } else {
                    try p.err_str(.implicit_int_to_ptr, expr_tok, try p.type_pair_str_extra(e.ty, " to ", result_ty));
                    try e.ptr_cast(p, result_ty);
                }
            }

            try e.un(p, .computed_goto_stmt);
            _ = try p.expect_token(.semicolon);
            return e.node;
        }
        const name_tok = try p.expect_identifier();
        const str = p.tok_slice(name_tok);
        if (p.find_label(str) == null) {
            try p.labels.append(.{ .unresolved_goto = name_tok });
        }
        _ = try p.expect_token(.semicolon);
        return try p.add_node(.{
            .tag = .goto_stmt,
            .data = .{ .decl_ref = name_tok },
        });
    }
    if (p.eat_token(.keyword_continue)) |cont| {
        if (!p.in_loop) try p.err_tok(.continue_not_in_loop, cont);
        _ = try p.expect_token(.semicolon);
        return try p.add_node(.{ .tag = .continue_stmt, .data = undefined });
    }
    if (p.eat_token(.keyword_break)) |br| {
        if (!p.in_loop and p.@"switch" == null) try p.err_tok(.break_not_in_loop_or_switch, br);
        _ = try p.expect_token(.semicolon);
        return try p.add_node(.{ .tag = .break_stmt, .data = undefined });
    }
    if (try p.return_stmt()) |some| return some;
    if (try p.assembly(.stmt)) |some| return some;

    const expr_start = p.tok_i;
    const err_start = p.comp.diagnostics.list.items.len;

    const e = try p.expr();
    if (e.node != .none) {
        _ = try p.expect_token(.semicolon);
        try e.maybe_warn_unused(p, expr_start, err_start);
        return e.node;
    }

    const attr_buf_top = p.attr_buf.len;
    defer p.attr_buf.len = attr_buf_top;
    try p.attribute_specifier();

    if (p.eat_token(.semicolon)) |_| {
        var null_node: Tree.Node = .{ .tag = .null_stmt, .data = undefined };
        null_node.ty = try Attribute.apply_statement_attributes(p, null_node.ty, expr_start, attr_buf_top);
        return p.add_node(null_node);
    }

    try p.err(.expected_stmt);
    return error.ParsingFailed;
}

/// labeled_stmt
/// : IDENTIFIER ':' stmt
/// | keyword_case integer_const_expr ':' stmt
/// | keyword_default ':' stmt
fn labeled_stmt(p: *Parser) Error!?NodeIndex {
    if ((p.tok_ids[p.tok_i] == .identifier or p.tok_ids[p.tok_i] == .extended_identifier) and p.tok_ids[p.tok_i + 1] == .colon) {
        const name_tok = try p.expect_identifier();
        const str = p.tok_slice(name_tok);
        if (p.find_label(str)) |some| {
            try p.err_str(.duplicate_label, name_tok, str);
            try p.err_str(.previous_label, some, str);
        } else {
            p.label_count += 1;
            try p.labels.append(.{ .label = name_tok });
            var i: usize = 0;
            while (i < p.labels.items.len) {
                if (p.labels.items[i] == .unresolved_goto and
                    mem.eql(u8, p.tok_slice(p.labels.items[i].unresolved_goto), str))
                {
                    _ = p.labels.swap_remove(i);
                } else i += 1;
            }
        }

        p.tok_i += 1;
        const attr_buf_top = p.attr_buf.len;
        defer p.attr_buf.len = attr_buf_top;
        try p.attribute_specifier();

        var labeled_stmt = Tree.Node{
            .tag = .labeled_stmt,
            .data = .{ .decl = .{ .name = name_tok, .node = try p.labelable_stmt() } },
        };
        labeled_stmt.ty = try Attribute.apply_label_attributes(p, labeled_stmt.ty, attr_buf_top);
        return try p.add_node(labeled_stmt);
    } else if (p.eat_token(.keyword_case)) |case| {
        const first_item = try p.integer_const_expr(.gnu_folding_extension);
        const ellipsis = p.tok_i;
        const second_item = if (p.eat_token(.ellipsis) != null) blk: {
            try p.err_tok(.gnu_switch_range, ellipsis);
            break :blk try p.integer_const_expr(.gnu_folding_extension);
        } else null;
        _ = try p.expect_token(.colon);

        if (p.@"switch") |some| check: {
            if (some.ty.has_incomplete_size()) break :check; // error already reported for incomplete size

            const first = first_item.val;
            const last = if (second_item) |second| second.val else first;
            if (first.opt_ref == .none) {
                try p.err_tok(.case_val_unavailable, case + 1);
                break :check;
            } else if (last.opt_ref == .none) {
                try p.err_tok(.case_val_unavailable, ellipsis + 1);
                break :check;
            } else if (last.compare(.lt, first, p.comp)) {
                try p.err_tok(.empty_case_range, case + 1);
                break :check;
            }

            // TODO cast to target type
            const prev = (try some.add(first, last, case + 1)) orelse break :check;

            // TODO check which value was already handled
            try p.err_str(.duplicate_switch_case, case + 1, try first_item.str(p));
            try p.err_tok(.previous_case, prev.tok);
        } else {
            try p.err_str(.case_not_in_switch, case, "case");
        }

        const s = try p.labelable_stmt();
        if (second_item) |some| return try p.add_node(.{
            .tag = .case_range_stmt,
            .data = .{ .if3 = .{ .cond = s, .body = (try p.add_list(&.{ first_item.node, some.node })).start } },
        }) else return try p.add_node(.{
            .tag = .case_stmt,
            .data = .{ .bin = .{ .lhs = first_item.node, .rhs = s } },
        });
    } else if (p.eat_token(.keyword_default)) |default| {
        _ = try p.expect_token(.colon);
        const s = try p.labelable_stmt();
        const node = try p.add_node(.{
            .tag = .default_stmt,
            .data = .{ .un = s },
        });
        const @"switch" = p.@"switch" orelse {
            try p.err_str(.case_not_in_switch, default, "default");
            return node;
        };
        if (@"switch".default) |previous| {
            try p.err_tok(.multiple_default, default);
            try p.err_tok(.previous_case, previous);
        } else {
            @"switch".default = default;
        }
        return node;
    } else return null;
}

fn labelable_stmt(p: *Parser) Error!NodeIndex {
    if (p.tok_ids[p.tok_i] == .r_brace) {
        try p.err(.label_compound_end);
        return p.add_node(.{ .tag = .null_stmt, .data = undefined });
    }
    return p.stmt();
}

const StmtExprState = struct {
    last_expr_tok: TokenIndex = 0,
    last_expr_res: Result = .{ .ty = .{ .specifier = .void } },
};

/// compound_stmt : '{' ( decl | keyword_extension decl | static_assert | stmt)* '}'
fn compound_stmt(p: *Parser, is_fn_body: bool, stmt_expr_state: ?*StmtExprState) Error!?NodeIndex {
    const l_brace = p.eat_token(.l_brace) orelse return null;

    const decl_buf_top = p.decl_buf.items.len;
    defer p.decl_buf.items.len = decl_buf_top;

    // the parameters of a function are in the same scope as the body
    if (!is_fn_body) try p.syms.push_scope(p);
    defer if (!is_fn_body) p.syms.pop_scope();

    var noreturn_index: ?TokenIndex = null;
    var noreturn_label_count: u32 = 0;

    while (p.eat_token(.r_brace) == null) : (_ = try p.pragma()) {
        if (stmt_expr_state) |state| state.* = .{};
        if (try p.parse_or_next_stmt(static_assert, l_brace)) continue;
        if (try p.parse_or_next_stmt(decl, l_brace)) continue;
        if (p.eat_token(.keyword_extension)) |ext| {
            const saved_extension = p.extension_suppressed;
            defer p.extension_suppressed = saved_extension;
            p.extension_suppressed = true;

            if (try p.parse_or_next_stmt(decl, l_brace)) continue;
            p.tok_i = ext;
        }
        const stmt_tok = p.tok_i;
        const s = p.stmt() catch |er| switch (er) {
            error.ParsingFailed => {
                try p.next_stmt(l_brace);
                continue;
            },
            else => |e| return e,
        };
        if (s == .none) continue;
        if (stmt_expr_state) |state| {
            state.* = .{
                .last_expr_tok = stmt_tok,
                .last_expr_res = .{
                    .node = s,
                    .ty = p.nodes.items(.ty)[@int_from_enum(s)],
                },
            };
        }
        try p.decl_buf.append(s);

        if (noreturn_index == null and p.node_is_noreturn(s) == .yes) {
            noreturn_index = p.tok_i;
            noreturn_label_count = p.label_count;
        }
        switch (p.nodes.items(.tag)[@int_from_enum(s)]) {
            .case_stmt, .default_stmt, .labeled_stmt => noreturn_index = null,
            else => {},
        }
    }

    if (noreturn_index) |some| {
        // if new labels were defined we cannot be certain that the code is unreachable
        if (some != p.tok_i - 1 and noreturn_label_count == p.label_count) try p.err_tok(.unreachable_code, some);
    }
    if (is_fn_body) {
        const last_noreturn = if (p.decl_buf.items.len == decl_buf_top)
            .no
        else
            p.node_is_noreturn(p.decl_buf.items[p.decl_buf.items.len - 1]);

        if (last_noreturn != .yes) {
            const ret_ty = p.func.ty.?.return_type();
            var return_zero = false;
            if (last_noreturn == .no and !ret_ty.is(.void) and !ret_ty.is_func() and !ret_ty.is_array()) {
                const func_name = p.tok_slice(p.func.name);
                const interned_name = try StrInt.intern(p.comp, func_name);
                if (interned_name == p.string_ids.main_id and ret_ty.is(.int)) {
                    return_zero = true;
                } else {
                    try p.err_str(.func_does_not_return, p.tok_i - 1, func_name);
                }
            }
            try p.decl_buf.append(try p.add_node(.{ .tag = .implicit_return, .ty = p.func.ty.?.return_type(), .data = .{ .return_zero = return_zero } }));
        }
        if (p.func.ident) |some| try p.decl_buf.insert(decl_buf_top, some.node);
        if (p.func.pretty_ident) |some| try p.decl_buf.insert(decl_buf_top, some.node);
    }

    var node: Tree.Node = .{
        .tag = .compound_stmt_two,
        .data = .{ .bin = .{ .lhs = .none, .rhs = .none } },
    };
    const statements = p.decl_buf.items[decl_buf_top..];
    switch (statements.len) {
        0 => {},
        1 => node.data = .{ .bin = .{ .lhs = statements[0], .rhs = .none } },
        2 => node.data = .{ .bin = .{ .lhs = statements[0], .rhs = statements[1] } },
        else => {
            node.tag = .compound_stmt;
            node.data = .{ .range = try p.add_list(statements) };
        },
    }
    return try p.add_node(node);
}

const NoreturnKind = enum { no, yes, complex };

fn node_is_noreturn(p: *Parser, node: NodeIndex) NoreturnKind {
    switch (p.nodes.items(.tag)[@int_from_enum(node)]) {
        .break_stmt, .continue_stmt, .return_stmt => return .yes,
        .if_then_else_stmt => {
            const data = p.data.items[p.nodes.items(.data)[@int_from_enum(node)].if3.body..];
            const then_type = p.node_is_noreturn(data[0]);
            const else_type = p.node_is_noreturn(data[1]);
            if (then_type == .complex or else_type == .complex) return .complex;
            if (then_type == .yes and else_type == .yes) return .yes;
            return .no;
        },
        .compound_stmt_two => {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            const lhs_type = if (data.bin.lhs != .none) p.node_is_noreturn(data.bin.lhs) else .no;
            const rhs_type = if (data.bin.rhs != .none) p.node_is_noreturn(data.bin.rhs) else .no;
            if (lhs_type == .complex or rhs_type == .complex) return .complex;
            if (lhs_type == .yes or rhs_type == .yes) return .yes;
            return .no;
        },
        .compound_stmt => {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            var it = data.range.start;
            while (it != data.range.end) : (it += 1) {
                const kind = p.node_is_noreturn(p.data.items[it]);
                if (kind != .no) return kind;
            }
            return .no;
        },
        .labeled_stmt => {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            return p.node_is_noreturn(data.decl.node);
        },
        .default_stmt => {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            if (data.un == .none) return .no;
            return p.node_is_noreturn(data.un);
        },
        .while_stmt, .do_while_stmt, .for_decl_stmt, .forever_stmt, .for_stmt, .switch_stmt => return .complex,
        else => return .no,
    }
}

fn parse_or_next_stmt(p: *Parser, comptime func: fn (*Parser) Error!bool, l_brace: TokenIndex) !bool {
    return func(p) catch |er| switch (er) {
        error.ParsingFailed => {
            try p.next_stmt(l_brace);
            return true;
        },
        else => |e| return e,
    };
}

fn next_stmt(p: *Parser, l_brace: TokenIndex) !void {
    var parens: u32 = 0;
    while (p.tok_i < p.tok_ids.len) : (p.tok_i += 1) {
        switch (p.tok_ids[p.tok_i]) {
            .l_paren, .l_brace, .l_bracket => parens += 1,
            .r_paren, .r_bracket => if (parens != 0) {
                parens -= 1;
            },
            .r_brace => if (parens == 0)
                return
            else {
                parens -= 1;
            },
            .semicolon => if (parens == 0) {
                p.tok_i += 1;
                return;
            },
            .keyword_for,
            .keyword_while,
            .keyword_do,
            .keyword_if,
            .keyword_goto,
            .keyword_switch,
            .keyword_case,
            .keyword_default,
            .keyword_continue,
            .keyword_break,
            .keyword_return,
            .keyword_typedef,
            .keyword_extern,
            .keyword_static,
            .keyword_auto,
            .keyword_register,
            .keyword_thread_local,
            .keyword_c23_thread_local,
            .keyword_inline,
            .keyword_inline1,
            .keyword_inline2,
            .keyword_noreturn,
            .keyword_void,
            .keyword_bool,
            .keyword_c23_bool,
            .keyword_char,
            .keyword_short,
            .keyword_int,
            .keyword_long,
            .keyword_signed,
            .keyword_unsigned,
            .keyword_float,
            .keyword_double,
            .keyword_complex,
            .keyword_atomic,
            .keyword_enum,
            .keyword_struct,
            .keyword_union,
            .keyword_alignas,
            .keyword_c23_alignas,
            .keyword_typeof,
            .keyword_typeof1,
            .keyword_typeof2,
            .keyword_typeof_unqual,
            .keyword_extension,
            => if (parens == 0) return,
            .keyword_pragma => p.skip_to_pragma_sentinel(),
            else => {},
        }
    }
    p.tok_i -= 1; // So we can consume EOF
    try p.expect_closing(l_brace, .r_brace);
    unreachable;
}

fn return_stmt(p: *Parser) Error!?NodeIndex {
    const ret_tok = p.eat_token(.keyword_return) orelse return null;

    const e_tok = p.tok_i;
    var e = try p.expr();
    _ = try p.expect_token(.semicolon);
    const ret_ty = p.func.ty.?.return_type();

    if (p.func.ty.?.has_attribute(.noreturn)) {
        try p.err_str(.invalid_noreturn, e_tok, p.tok_slice(p.func.name));
    }

    if (e.node == .none) {
        if (!ret_ty.is(.void)) try p.err_str(.func_should_return, ret_tok, p.tok_slice(p.func.name));
        return try p.add_node(.{ .tag = .return_stmt, .data = .{ .un = e.node } });
    } else if (ret_ty.is(.void)) {
        try p.err_str(.void_func_returns_value, e_tok, p.tok_slice(p.func.name));
        return try p.add_node(.{ .tag = .return_stmt, .data = .{ .un = e.node } });
    }

    try e.lval_conversion(p);
    try e.coerce(p, ret_ty, e_tok, .ret);

    try e.save_value(p);
    return try p.add_node(.{ .tag = .return_stmt, .data = .{ .un = e.node } });
}

// ====== expressions ======

pub fn macro_expr(p: *Parser) Compilation.Error!bool {
    const res = p.cond_expr() catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FatalError => return error.FatalError,
        error.ParsingFailed => return false,
    };
    if (res.val.opt_ref == .none) {
        try p.err_tok(.expected_expr, p.tok_i);
        return false;
    }
    return res.val.to_bool(p.comp);
}

const CallExpr = union(enum) {
    standard: NodeIndex,
    builtin: struct {
        node: NodeIndex,
        tag: Builtin.Tag,
    },

    fn init(p: *Parser, call_node: NodeIndex, func_node: NodeIndex) CallExpr {
        if (p.get_node(call_node, .builtin_call_expr_one)) |node| {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            const name = p.tok_slice(data.decl.name);
            const builtin_ty = p.comp.builtins.lookup(name);
            return .{ .builtin = .{ .node = node, .tag = builtin_ty.builtin.tag } };
        }
        return .{ .standard = func_node };
    }

    fn should_perform_lval_conversion(self: CallExpr, arg_idx: u32) bool {
        return switch (self) {
            .standard => true,
            .builtin => |builtin| switch (builtin.tag) {
                Builtin.tag_from_name("__builtin_va_start").?,
                Builtin.tag_from_name("__va_start").?,
                Builtin.tag_from_name("va_start").?,
                => arg_idx != 1,
                else => true,
            },
        };
    }

    fn should_promote_var_arg(self: CallExpr, arg_idx: u32) bool {
        return switch (self) {
            .standard => true,
            .builtin => |builtin| switch (builtin.tag) {
                Builtin.tag_from_name("__builtin_va_start").?,
                Builtin.tag_from_name("__va_start").?,
                Builtin.tag_from_name("va_start").?,
                => arg_idx != 1,
                Builtin.tag_from_name("__builtin_complex").?,
                Builtin.tag_from_name("__builtin_add_overflow").?,
                Builtin.tag_from_name("__builtin_sub_overflow").?,
                Builtin.tag_from_name("__builtin_mul_overflow").?,
                => false,
                else => true,
            },
        };
    }

    fn should_coerce_arg(self: CallExpr, arg_idx: u32) bool {
        _ = self;
        _ = arg_idx;
        return true;
    }

    fn check_var_arg(self: CallExpr, p: *Parser, first_after: TokenIndex, param_tok: TokenIndex, arg: *Result, arg_idx: u32) !void {
        @setEvalBranchQuota(10_000);
        if (self == .standard) return;

        const builtin_tok = p.nodes.items(.data)[@int_from_enum(self.builtin.node)].decl.name;
        switch (self.builtin.tag) {
            Builtin.tag_from_name("__builtin_va_start").?,
            Builtin.tag_from_name("__va_start").?,
            Builtin.tag_from_name("va_start").?,
            => return p.check_va_start_arg(builtin_tok, first_after, param_tok, arg, arg_idx),
            Builtin.tag_from_name("__builtin_complex").? => return p.check_complex_arg(builtin_tok, first_after, param_tok, arg, arg_idx),
            Builtin.tag_from_name("__builtin_add_overflow").?,
            Builtin.tag_from_name("__builtin_sub_overflow").?,
            Builtin.tag_from_name("__builtin_mul_overflow").?,
            => return p.check_arith_overflow_arg(builtin_tok, first_after, param_tok, arg, arg_idx),

            else => {},
        }
    }

    /// Some functions cannot be expressed as standard C prototypes. For example `__builtin_complex` requires
    /// two arguments of the same real floating point type (e.g. two doubles or two floats). These functions are
    /// encoded as varargs functions with custom typechecking. Since varargs functions do not have a fixed number
    /// of arguments, `param_count_override` is used to tell us how many arguments we should actually expect to see for
    /// these custom-typechecked functions.
    fn param_count_override(self: CallExpr) ?u32 {
        @setEvalBranchQuota(10_000);
        return switch (self) {
            .standard => null,
            .builtin => |builtin| switch (builtin.tag) {
                Builtin.tag_from_name("__c11_atomic_thread_fence").?,
                Builtin.tag_from_name("__c11_atomic_signal_fence").?,
                Builtin.tag_from_name("__c11_atomic_is_lock_free").?,
                => 1,

                Builtin.tag_from_name("__builtin_complex").?,
                Builtin.tag_from_name("__c11_atomic_load").?,
                Builtin.tag_from_name("__c11_atomic_init").?,
                => 2,

                Builtin.tag_from_name("__c11_atomic_store").?,
                Builtin.tag_from_name("__c11_atomic_exchange").?,
                Builtin.tag_from_name("__c11_atomic_fetch_add").?,
                Builtin.tag_from_name("__c11_atomic_fetch_sub").?,
                Builtin.tag_from_name("__c11_atomic_fetch_or").?,
                Builtin.tag_from_name("__c11_atomic_fetch_xor").?,
                Builtin.tag_from_name("__c11_atomic_fetch_and").?,
                Builtin.tag_from_name("__atomic_fetch_add").?,
                Builtin.tag_from_name("__atomic_fetch_sub").?,
                Builtin.tag_from_name("__atomic_fetch_and").?,
                Builtin.tag_from_name("__atomic_fetch_xor").?,
                Builtin.tag_from_name("__atomic_fetch_or").?,
                Builtin.tag_from_name("__atomic_fetch_nand").?,
                Builtin.tag_from_name("__atomic_add_fetch").?,
                Builtin.tag_from_name("__atomic_sub_fetch").?,
                Builtin.tag_from_name("__atomic_and_fetch").?,
                Builtin.tag_from_name("__atomic_xor_fetch").?,
                Builtin.tag_from_name("__atomic_or_fetch").?,
                Builtin.tag_from_name("__atomic_nand_fetch").?,
                Builtin.tag_from_name("__builtin_add_overflow").?,
                Builtin.tag_from_name("__builtin_sub_overflow").?,
                Builtin.tag_from_name("__builtin_mul_overflow").?,
                => 3,

                Builtin.tag_from_name("__c11_atomic_compare_exchange_strong").?,
                Builtin.tag_from_name("__c11_atomic_compare_exchange_weak").?,
                => 5,

                Builtin.tag_from_name("__atomic_compare_exchange").?,
                Builtin.tag_from_name("__atomic_compare_exchange_n").?,
                => 6,
                else => null,
            },
        };
    }

    fn return_type(self: CallExpr, p: *Parser, callable_ty: Type) Type {
        return switch (self) {
            .standard => callable_ty.return_type(),
            .builtin => |builtin| switch (builtin.tag) {
                Builtin.tag_from_name("__c11_atomic_exchange").? => {
                    if (p.list_buf.items.len != 4) return Type.invalid; // wrong number of arguments; already an error
                    const second_param = p.list_buf.items[2];
                    return p.nodes.items(.ty)[@int_from_enum(second_param)];
                },
                Builtin.tag_from_name("__c11_atomic_load").? => {
                    if (p.list_buf.items.len != 3) return Type.invalid; // wrong number of arguments; already an error
                    const first_param = p.list_buf.items[1];
                    const ty = p.nodes.items(.ty)[@int_from_enum(first_param)];
                    if (!ty.is_ptr()) return Type.invalid;
                    return ty.elem_type();
                },

                Builtin.tag_from_name("__atomic_fetch_add").?,
                Builtin.tag_from_name("__atomic_add_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_add").?,

                Builtin.tag_from_name("__atomic_fetch_sub").?,
                Builtin.tag_from_name("__atomic_sub_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_sub").?,

                Builtin.tag_from_name("__atomic_fetch_and").?,
                Builtin.tag_from_name("__atomic_and_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_and").?,

                Builtin.tag_from_name("__atomic_fetch_xor").?,
                Builtin.tag_from_name("__atomic_xor_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_xor").?,

                Builtin.tag_from_name("__atomic_fetch_or").?,
                Builtin.tag_from_name("__atomic_or_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_or").?,

                Builtin.tag_from_name("__atomic_fetch_nand").?,
                Builtin.tag_from_name("__atomic_nand_fetch").?,
                Builtin.tag_from_name("__c11_atomic_fetch_nand").?,
                => {
                    if (p.list_buf.items.len != 3) return Type.invalid; // wrong number of arguments; already an error
                    const second_param = p.list_buf.items[2];
                    return p.nodes.items(.ty)[@int_from_enum(second_param)];
                },
                Builtin.tag_from_name("__builtin_complex").? => {
                    if (p.list_buf.items.len < 1) return Type.invalid; // not enough arguments; already an error
                    const last_param = p.list_buf.items[p.list_buf.items.len - 1];
                    return p.nodes.items(.ty)[@int_from_enum(last_param)].make_complex();
                },
                Builtin.tag_from_name("__atomic_compare_exchange").?,
                Builtin.tag_from_name("__atomic_compare_exchange_n").?,
                Builtin.tag_from_name("__c11_atomic_is_lock_free").?,
                => .{ .specifier = .bool },
                else => callable_ty.return_type(),

                Builtin.tag_from_name("__c11_atomic_compare_exchange_strong").?,
                Builtin.tag_from_name("__c11_atomic_compare_exchange_weak").?,
                => {
                    if (p.list_buf.items.len != 6) return Type.invalid; // wrong number of arguments
                    const third_param = p.list_buf.items[3];
                    return p.nodes.items(.ty)[@int_from_enum(third_param)];
                },
            },
        };
    }

    fn finish(self: CallExpr, p: *Parser, ty: Type, list_buf_top: usize, arg_count: u32) Error!Result {
        const ret_ty = self.return_type(p, ty);
        switch (self) {
            .standard => |func_node| {
                var call_node: Tree.Node = .{
                    .tag = .call_expr_one,
                    .ty = ret_ty,
                    .data = .{ .bin = .{ .lhs = func_node, .rhs = .none } },
                };
                const args = p.list_buf.items[list_buf_top..];
                switch (arg_count) {
                    0 => {},
                    1 => call_node.data.bin.rhs = args[1], // args[0] == func.node
                    else => {
                        call_node.tag = .call_expr;
                        call_node.data = .{ .range = try p.add_list(args) };
                    },
                }
                return Result{ .node = try p.add_node(call_node), .ty = ret_ty };
            },
            .builtin => |builtin| {
                const index = @int_from_enum(builtin.node);
                var call_node = p.nodes.get(index);
                defer p.nodes.set(index, call_node);
                call_node.ty = ret_ty;
                const args = p.list_buf.items[list_buf_top..];
                switch (arg_count) {
                    0 => {},
                    1 => call_node.data.decl.node = args[1], // args[0] == func.node
                    else => {
                        call_node.tag = .builtin_call_expr;
                        args[0] = @enumFromInt(call_node.data.decl.name);
                        call_node.data = .{ .range = try p.add_list(args) };
                    },
                }
                return Result{ .node = builtin.node, .ty = ret_ty };
            },
        }
    }
};

pub const Result = struct {
    node: NodeIndex = .none,
    ty: Type = .{ .specifier = .int },
    val: Value = .{},

    pub fn str(res: Result, p: *Parser) ![]const u8 {
        switch (res.val.opt_ref) {
            .none => return "(none)",
            .null => return "nullptr_t",
            else => {},
        }
        const strings_top = p.strings.items.len;
        defer p.strings.items.len = strings_top;

        try res.val.print(res.ty, p.comp, p.strings.writer());
        return try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
    }

    fn expect(res: Result, p: *Parser) Error!void {
        if (p.in_macro) {
            if (res.val.opt_ref == .none) {
                try p.err_tok(.expected_expr, p.tok_i);
                return error.ParsingFailed;
            }
            return;
        }
        if (res.node == .none) {
            try p.err_tok(.expected_expr, p.tok_i);
            return error.ParsingFailed;
        }
    }

    fn empty(res: Result, p: *Parser) bool {
        if (p.in_macro) return res.val.opt_ref == .none;
        return res.node == .none;
    }

    fn maybe_warn_unused(res: Result, p: *Parser, expr_start: TokenIndex, err_start: usize) Error!void {
        if (res.ty.is(.void) or res.node == .none) return;
        // don't warn about unused result if the expression contained errors besides other unused results
        for (p.comp.diagnostics.list.items[err_start..]) |err_item| {
            if (err_item.tag != .unused_value) return;
        }
        var cur_node = res.node;
        while (true) switch (p.nodes.items(.tag)[@int_from_enum(cur_node)]) {
            .invalid, // So that we don't need to check for node == 0
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
            .pre_inc_expr,
            .pre_dec_expr,
            .post_inc_expr,
            .post_dec_expr,
            => return,
            .call_expr_one => {
                const fn_ptr = p.nodes.items(.data)[@int_from_enum(cur_node)].bin.lhs;
                const fn_ty = p.nodes.items(.ty)[@int_from_enum(fn_ptr)].elem_type();
                const cast_info = p.nodes.items(.data)[@int_from_enum(fn_ptr)].cast.operand;
                const decl_ref = p.nodes.items(.data)[@int_from_enum(cast_info)].decl_ref;
                if (fn_ty.has_attribute(.nodiscard)) try p.err_str(.nodiscard_unused, expr_start, p.tok_slice(decl_ref));
                if (fn_ty.has_attribute(.warn_unused_result)) try p.err_str(.warn_unused_result, expr_start, p.tok_slice(decl_ref));
                return;
            },
            .call_expr => {
                const fn_ptr = p.data.items[p.nodes.items(.data)[@int_from_enum(cur_node)].range.start];
                const fn_ty = p.nodes.items(.ty)[@int_from_enum(fn_ptr)].elem_type();
                const cast_info = p.nodes.items(.data)[@int_from_enum(fn_ptr)].cast.operand;
                const decl_ref = p.nodes.items(.data)[@int_from_enum(cast_info)].decl_ref;
                if (fn_ty.has_attribute(.nodiscard)) try p.err_str(.nodiscard_unused, expr_start, p.tok_slice(decl_ref));
                if (fn_ty.has_attribute(.warn_unused_result)) try p.err_str(.warn_unused_result, expr_start, p.tok_slice(decl_ref));
                return;
            },
            .stmt_expr => {
                const body = p.nodes.items(.data)[@int_from_enum(cur_node)].un;
                switch (p.nodes.items(.tag)[@int_from_enum(body)]) {
                    .compound_stmt_two => {
                        const body_stmt = p.nodes.items(.data)[@int_from_enum(body)].bin;
                        cur_node = if (body_stmt.rhs != .none) body_stmt.rhs else body_stmt.lhs;
                    },
                    .compound_stmt => {
                        const data = p.nodes.items(.data)[@int_from_enum(body)];
                        cur_node = p.data.items[data.range.end - 1];
                    },
                    else => unreachable,
                }
            },
            .comma_expr => cur_node = p.nodes.items(.data)[@int_from_enum(cur_node)].bin.rhs,
            .paren_expr => cur_node = p.nodes.items(.data)[@int_from_enum(cur_node)].un,
            else => break,
        };
        try p.err_tok(.unused_value, expr_start);
    }

    fn bool_res(lhs: *Result, p: *Parser, tag: Tree.Tag, rhs: Result) !void {
        if (lhs.val.opt_ref == .null) {
            lhs.val = Value.zero;
        }
        if (lhs.ty.specifier != .invalid) {
            lhs.ty = Type.int;
        }
        return lhs.bin(p, tag, rhs);
    }

    fn bin(lhs: *Result, p: *Parser, tag: Tree.Tag, rhs: Result) !void {
        lhs.node = try p.add_node(.{
            .tag = tag,
            .ty = lhs.ty,
            .data = .{ .bin = .{ .lhs = lhs.node, .rhs = rhs.node } },
        });
    }

    fn un(operand: *Result, p: *Parser, tag: Tree.Tag) Error!void {
        operand.node = try p.add_node(.{
            .tag = tag,
            .ty = operand.ty,
            .data = .{ .un = operand.node },
        });
    }

    fn implicit_cast(operand: *Result, p: *Parser, kind: Tree.CastKind) Error!void {
        operand.node = try p.add_node(.{
            .tag = .implicit_cast,
            .ty = operand.ty,
            .data = .{ .cast = .{ .operand = operand.node, .kind = kind } },
        });
    }

    fn adjust_cond_expr_ptrs(a: *Result, tok: TokenIndex, b: *Result, p: *Parser) !bool {
        assert(a.ty.is_ptr() and b.ty.is_ptr());

        const a_elem = a.ty.elem_type();
        const b_elem = b.ty.elem_type();
        if (a_elem.eql(b_elem, p.comp, true)) return true;

        var adjusted_elem_ty = try p.arena.create(Type);
        adjusted_elem_ty.* = a_elem;

        const has_void_star_branch = a.ty.is_void_star() or b.ty.is_void_star();
        const only_quals_differ = a_elem.eql(b_elem, p.comp, false);
        const pointers_compatible = only_quals_differ or has_void_star_branch;

        if (!pointers_compatible or has_void_star_branch) {
            if (!pointers_compatible) {
                try p.err_str(.pointer_mismatch, tok, try p.type_pair_str_extra(a.ty, " and ", b.ty));
            }
            adjusted_elem_ty.* = .{ .specifier = .void };
        }
        if (pointers_compatible) {
            adjusted_elem_ty.qual = a_elem.qual.merge_cv(b_elem.qual);
        }
        if (!adjusted_elem_ty.eql(a_elem, p.comp, true)) {
            a.ty = .{
                .data = .{ .sub_type = adjusted_elem_ty },
                .specifier = .pointer,
            };
            try a.implicit_cast(p, .bitcast);
        }
        if (!adjusted_elem_ty.eql(b_elem, p.comp, true)) {
            b.ty = .{
                .data = .{ .sub_type = adjusted_elem_ty },
                .specifier = .pointer,
            };
            try b.implicit_cast(p, .bitcast);
        }
        return true;
    }

    /// Adjust types for binary operation, returns true if the result can and should be evaluated.
    fn adjust_types(a: *Result, tok: TokenIndex, b: *Result, p: *Parser, kind: enum {
        integer,
        arithmetic,
        boolean_logic,
        relational,
        equality,
        conditional,
        add,
        sub,
    }) !bool {
        if (b.ty.specifier == .invalid) {
            try a.save_value(p);
            a.ty = Type.invalid;
        }
        if (a.ty.specifier == .invalid) {
            return false;
        }
        try a.lval_conversion(p);
        try b.lval_conversion(p);

        const a_vec = a.ty.is(.vector);
        const b_vec = b.ty.is(.vector);
        if (a_vec and b_vec) {
            if (a.ty.eql(b.ty, p.comp, false)) {
                return a.should_eval(b, p);
            }
            return a.invalid_bin_ty(tok, b, p);
        } else if (a_vec) {
            if (b.coerce_extra(p, a.ty.elem_type(), tok, .test_coerce)) {
                try b.save_value(p);
                try b.implicit_cast(p, .vector_splat);
                return a.should_eval(b, p);
            } else |er| switch (er) {
                error.CoercionFailed => return a.invalid_bin_ty(tok, b, p),
                else => |e| return e,
            }
        } else if (b_vec) {
            if (a.coerce_extra(p, b.ty.elem_type(), tok, .test_coerce)) {
                try a.save_value(p);
                try a.implicit_cast(p, .vector_splat);
                return a.should_eval(b, p);
            } else |er| switch (er) {
                error.CoercionFailed => return a.invalid_bin_ty(tok, b, p),
                else => |e| return e,
            }
        }

        const a_int = a.ty.is_int();
        const b_int = b.ty.is_int();
        if (a_int and b_int) {
            try a.usual_arithmetic_conversion(b, p, tok);
            return a.should_eval(b, p);
        }
        if (kind == .integer) return a.invalid_bin_ty(tok, b, p);

        const a_float = a.ty.is_float();
        const b_float = b.ty.is_float();
        const a_arithmetic = a_int or a_float;
        const b_arithmetic = b_int or b_float;
        if (a_arithmetic and b_arithmetic) {
            // <, <=, >, >= only work on real types
            if (kind == .relational and (!a.ty.is_real() or !b.ty.is_real()))
                return a.invalid_bin_ty(tok, b, p);

            try a.usual_arithmetic_conversion(b, p, tok);
            return a.should_eval(b, p);
        }
        if (kind == .arithmetic) return a.invalid_bin_ty(tok, b, p);

        const a_nullptr = a.ty.is(.nullptr_t);
        const b_nullptr = b.ty.is(.nullptr_t);
        const a_ptr = a.ty.is_ptr();
        const b_ptr = b.ty.is_ptr();
        const a_scalar = a_arithmetic or a_ptr;
        const b_scalar = b_arithmetic or b_ptr;
        switch (kind) {
            .boolean_logic => {
                if (!(a_scalar or a_nullptr) or !(b_scalar or b_nullptr)) return a.invalid_bin_ty(tok, b, p);

                // Do integer promotions but nothing else
                if (a_int) try a.int_cast(p, a.ty.integer_promotion(p.comp), tok);
                if (b_int) try b.int_cast(p, b.ty.integer_promotion(p.comp), tok);
                return a.should_eval(b, p);
            },
            .relational, .equality => {
                if (kind == .equality and (a_nullptr or b_nullptr)) {
                    if (a_nullptr and b_nullptr) return a.should_eval(b, p);
                    const nullptr_res = if (a_nullptr) a else b;
                    const other_res = if (a_nullptr) b else a;
                    if (other_res.ty.is_ptr()) {
                        try nullptr_res.null_cast(p, other_res.ty);
                        return other_res.should_eval(nullptr_res, p);
                    } else if (other_res.val.is_zero(p.comp)) {
                        other_res.val = Value.null;
                        try other_res.null_cast(p, nullptr_res.ty);
                        return other_res.should_eval(nullptr_res, p);
                    }
                    return a.invalid_bin_ty(tok, b, p);
                }
                // comparisons between floats and pointes not allowed
                if (!a_scalar or !b_scalar or (a_float and b_ptr) or (b_float and a_ptr))
                    return a.invalid_bin_ty(tok, b, p);

                if ((a_int or b_int) and !(a.val.is_zero(p.comp) or b.val.is_zero(p.comp))) {
                    try p.err_str(.comparison_ptr_int, tok, try p.type_pair_str(a.ty, b.ty));
                } else if (a_ptr and b_ptr) {
                    if (!a.ty.is_void_star() and !b.ty.is_void_star() and !a.ty.eql(b.ty, p.comp, false))
                        try p.err_str(.comparison_distinct_ptr, tok, try p.type_pair_str(a.ty, b.ty));
                } else if (a_ptr) {
                    try b.ptr_cast(p, a.ty);
                } else {
                    assert(b_ptr);
                    try a.ptr_cast(p, b.ty);
                }

                return a.should_eval(b, p);
            },
            .conditional => {
                // doesn't matter what we return here, as the result is ignored
                if (a.ty.is(.void) or b.ty.is(.void)) {
                    try a.to_void(p);
                    try b.to_void(p);
                    return true;
                }
                if (a_nullptr and b_nullptr) return true;
                if ((a_ptr and b_int) or (a_int and b_ptr)) {
                    if (a.val.is_zero(p.comp) or b.val.is_zero(p.comp)) {
                        try a.null_cast(p, b.ty);
                        try b.null_cast(p, a.ty);
                        return true;
                    }
                    const int_ty = if (a_int) a else b;
                    const ptr_ty = if (a_ptr) a else b;
                    try p.err_str(.implicit_int_to_ptr, tok, try p.type_pair_str_extra(int_ty.ty, " to ", ptr_ty.ty));
                    try int_ty.ptr_cast(p, ptr_ty.ty);

                    return true;
                }
                if (a_ptr and b_ptr) return a.adjust_cond_expr_ptrs(tok, b, p);
                if ((a_ptr and b_nullptr) or (a_nullptr and b_ptr)) {
                    const nullptr_res = if (a_nullptr) a else b;
                    const ptr_res = if (a_nullptr) b else a;
                    try nullptr_res.null_cast(p, ptr_res.ty);
                    return true;
                }
                if (a.ty.is_record() and b.ty.is_record() and a.ty.eql(b.ty, p.comp, false)) {
                    return true;
                }
                return a.invalid_bin_ty(tok, b, p);
            },
            .add => {
                // if both aren't arithmetic one should be pointer and the other an integer
                if (a_ptr == b_ptr or a_int == b_int) return a.invalid_bin_ty(tok, b, p);

                // Do integer promotions but nothing else
                if (a_int) try a.int_cast(p, a.ty.integer_promotion(p.comp), tok);
                if (b_int) try b.int_cast(p, b.ty.integer_promotion(p.comp), tok);

                // The result type is the type of the pointer operand
                if (a_int) a.ty = b.ty else b.ty = a.ty;
                return a.should_eval(b, p);
            },
            .sub => {
                // if both aren't arithmetic then either both should be pointers or just a
                if (!a_ptr or !(b_ptr or b_int)) return a.invalid_bin_ty(tok, b, p);

                if (a_ptr and b_ptr) {
                    if (!a.ty.eql(b.ty, p.comp, false)) try p.err_str(.incompatible_pointers, tok, try p.type_pair_str(a.ty, b.ty));
                    a.ty = p.comp.types.ptrdiff;
                }

                // Do integer promotion on b if needed
                if (b_int) try b.int_cast(p, b.ty.integer_promotion(p.comp), tok);
                return a.should_eval(b, p);
            },
            else => return a.invalid_bin_ty(tok, b, p),
        }
    }

    fn lval_conversion(res: *Result, p: *Parser) Error!void {
        if (res.ty.is_func()) {
            const elem_ty = try p.arena.create(Type);
            elem_ty.* = res.ty;
            res.ty.specifier = .pointer;
            res.ty.data = .{ .sub_type = elem_ty };
            try res.implicit_cast(p, .function_to_pointer);
        } else if (res.ty.is_array()) {
            res.val = .{};
            res.ty.decay_array();
            try res.implicit_cast(p, .array_to_pointer);
        } else if (!p.in_macro and p.tmp_tree().is_lval(res.node)) {
            res.ty.qual = .{};
            try res.implicit_cast(p, .lval_to_rval);
        }
    }

    fn bool_cast(res: *Result, p: *Parser, bool_ty: Type, tok: TokenIndex) Error!void {
        if (res.ty.is_array()) {
            if (res.val.is(.bytes, p.comp)) {
                try p.err_str(.string_literal_to_bool, tok, try p.type_pair_str_extra(res.ty, " to ", bool_ty));
            } else {
                try p.err_str(.array_address_to_bool, tok, p.tok_slice(tok));
            }
            try res.lval_conversion(p);
            res.val = Value.one;
            res.ty = bool_ty;
            try res.implicit_cast(p, .pointer_to_bool);
        } else if (res.ty.is_ptr()) {
            res.val.bool_cast(p.comp);
            res.ty = bool_ty;
            try res.implicit_cast(p, .pointer_to_bool);
        } else if (res.ty.is_int() and !res.ty.is(.bool)) {
            res.val.bool_cast(p.comp);
            res.ty = bool_ty;
            try res.implicit_cast(p, .int_to_bool);
        } else if (res.ty.is_float()) {
            const old_value = res.val;
            const value_change_kind = try res.val.float_to_int(bool_ty, p.comp);
            try res.float_to_int_warning(p, bool_ty, old_value, value_change_kind, tok);
            if (!res.ty.is_real()) {
                res.ty = res.ty.make_real();
                try res.implicit_cast(p, .complex_float_to_real);
            }
            res.ty = bool_ty;
            try res.implicit_cast(p, .float_to_bool);
        }
    }

    fn int_cast(res: *Result, p: *Parser, int_ty: Type, tok: TokenIndex) Error!void {
        if (int_ty.has_incomplete_size()) return error.ParsingFailed; // Diagnostic already issued
        if (res.ty.is(.bool)) {
            res.ty = int_ty.make_real();
            try res.implicit_cast(p, .bool_to_int);
            if (!int_ty.is_real()) {
                res.ty = int_ty;
                try res.implicit_cast(p, .real_to_complex_int);
            }
        } else if (res.ty.is_ptr()) {
            res.ty = int_ty.make_real();
            try res.implicit_cast(p, .pointer_to_int);
            if (!int_ty.is_real()) {
                res.ty = int_ty;
                try res.implicit_cast(p, .real_to_complex_int);
            }
        } else if (res.ty.is_float()) {
            const old_value = res.val;
            const value_change_kind = try res.val.float_to_int(int_ty, p.comp);
            try res.float_to_int_warning(p, int_ty, old_value, value_change_kind, tok);
            const old_real = res.ty.is_real();
            const new_real = int_ty.is_real();
            if (old_real and new_real) {
                res.ty = int_ty;
                try res.implicit_cast(p, .float_to_int);
            } else if (old_real) {
                res.ty = int_ty.make_real();
                try res.implicit_cast(p, .float_to_int);
                res.ty = int_ty;
                try res.implicit_cast(p, .real_to_complex_int);
            } else if (new_real) {
                res.ty = res.ty.make_real();
                try res.implicit_cast(p, .complex_float_to_real);
                res.ty = int_ty;
                try res.implicit_cast(p, .float_to_int);
            } else {
                res.ty = int_ty;
                try res.implicit_cast(p, .complex_float_to_complex_int);
            }
        } else if (!res.ty.eql(int_ty, p.comp, true)) {
            try res.val.int_cast(int_ty, p.comp);
            const old_real = res.ty.is_real();
            const new_real = int_ty.is_real();
            if (old_real and new_real) {
                res.ty = int_ty;
                try res.implicit_cast(p, .int_cast);
            } else if (old_real) {
                const real_int_ty = int_ty.make_real();
                if (!res.ty.eql(real_int_ty, p.comp, false)) {
                    res.ty = real_int_ty;
                    try res.implicit_cast(p, .int_cast);
                }
                res.ty = int_ty;
                try res.implicit_cast(p, .real_to_complex_int);
            } else if (new_real) {
                res.ty = res.ty.make_real();
                try res.implicit_cast(p, .complex_int_to_real);
                res.ty = int_ty;
                try res.implicit_cast(p, .int_cast);
            } else {
                res.ty = int_ty;
                try res.implicit_cast(p, .complex_int_cast);
            }
        }
    }

    fn float_to_int_warning(res: *Result, p: *Parser, int_ty: Type, old_value: Value, change_kind: Value.FloatToIntChangeKind, tok: TokenIndex) !void {
        switch (change_kind) {
            .none => return p.err_str(.float_to_int, tok, try p.type_pair_str_extra(res.ty, " to ", int_ty)),
            .out_of_range => return p.err_str(.float_out_of_range, tok, try p.type_pair_str_extra(res.ty, " to ", int_ty)),
            .overflow => return p.err_str(.float_overflow_conversion, tok, try p.type_pair_str_extra(res.ty, " to ", int_ty)),
            .nonzero_to_zero => return p.err_str(.float_zero_conversion, tok, try p.float_value_changed_str(res, old_value, int_ty)),
            .value_changed => return p.err_str(.float_value_changed, tok, try p.float_value_changed_str(res, old_value, int_ty)),
        }
    }

    fn float_cast(res: *Result, p: *Parser, float_ty: Type) Error!void {
        if (res.ty.is(.bool)) {
            try res.val.int_to_float(float_ty, p.comp);
            res.ty = float_ty.make_real();
            try res.implicit_cast(p, .bool_to_float);
            if (!float_ty.is_real()) {
                res.ty = float_ty;
                try res.implicit_cast(p, .real_to_complex_float);
            }
        } else if (res.ty.is_int()) {
            try res.val.int_to_float(float_ty, p.comp);
            const old_real = res.ty.is_real();
            const new_real = float_ty.is_real();
            if (old_real and new_real) {
                res.ty = float_ty;
                try res.implicit_cast(p, .int_to_float);
            } else if (old_real) {
                res.ty = float_ty.make_real();
                try res.implicit_cast(p, .int_to_float);
                res.ty = float_ty;
                try res.implicit_cast(p, .real_to_complex_float);
            } else if (new_real) {
                res.ty = res.ty.make_real();
                try res.implicit_cast(p, .complex_int_to_real);
                res.ty = float_ty;
                try res.implicit_cast(p, .int_to_float);
            } else {
                res.ty = float_ty;
                try res.implicit_cast(p, .complex_int_to_complex_float);
            }
        } else if (!res.ty.eql(float_ty, p.comp, true)) {
            try res.val.float_cast(float_ty, p.comp);
            const old_real = res.ty.is_real();
            const new_real = float_ty.is_real();
            if (old_real and new_real) {
                res.ty = float_ty;
                try res.implicit_cast(p, .float_cast);
            } else if (old_real) {
                if (res.ty.float_rank() != float_ty.float_rank()) {
                    res.ty = float_ty.make_real();
                    try res.implicit_cast(p, .float_cast);
                }
                res.ty = float_ty;
                try res.implicit_cast(p, .real_to_complex_float);
            } else if (new_real) {
                res.ty = res.ty.make_real();
                try res.implicit_cast(p, .complex_float_to_real);
                if (res.ty.float_rank() != float_ty.float_rank()) {
                    res.ty = float_ty;
                    try res.implicit_cast(p, .float_cast);
                }
            } else {
                res.ty = float_ty;
                try res.implicit_cast(p, .complex_float_cast);
            }
        }
    }

    /// Converts a bool or integer to a pointer
    fn ptr_cast(res: *Result, p: *Parser, ptr_ty: Type) Error!void {
        if (res.ty.is(.bool)) {
            res.ty = ptr_ty;
            try res.implicit_cast(p, .bool_to_pointer);
        } else if (res.ty.is_int()) {
            try res.val.int_cast(ptr_ty, p.comp);
            res.ty = ptr_ty;
            try res.implicit_cast(p, .int_to_pointer);
        }
    }

    /// Convert pointer to one with a different child type
    fn ptr_child_type_cast(res: *Result, p: *Parser, ptr_ty: Type) Error!void {
        res.ty = ptr_ty;
        return res.implicit_cast(p, .bitcast);
    }

    fn to_void(res: *Result, p: *Parser) Error!void {
        if (!res.ty.is(.void)) {
            res.ty = .{ .specifier = .void };
            try res.implicit_cast(p, .to_void);
        }
    }

    fn null_cast(res: *Result, p: *Parser, ptr_ty: Type) Error!void {
        if (!res.ty.is(.nullptr_t) and !res.val.is_zero(p.comp)) return;
        res.ty = ptr_ty;
        try res.implicit_cast(p, .null_to_pointer);
    }

    fn usual_unary_conversion(res: *Result, p: *Parser, tok: TokenIndex) Error!void {
        if (res.ty.is_float()) fp_eval: {
            const eval_method = p.comp.langopts.fp_eval_method orelse break :fp_eval;
            switch (eval_method) {
                .source => {},
                .indeterminate => unreachable,
                .double => {
                    if (res.ty.float_rank() < (Type{ .specifier = .double }).float_rank()) {
                        const spec: Type.Specifier = if (res.ty.is_real()) .double else .complex_double;
                        return res.float_cast(p, .{ .specifier = spec });
                    }
                },
                .extended => {
                    if (res.ty.float_rank() < (Type{ .specifier = .long_double }).float_rank()) {
                        const spec: Type.Specifier = if (res.ty.is_real()) .long_double else .complex_long_double;
                        return res.float_cast(p, .{ .specifier = spec });
                    }
                },
            }
        }

        if (res.ty.is(.fp16) and !p.comp.langopts.use_native_half_type) {
            return res.float_cast(p, .{ .specifier = .float });
        }
        if (res.ty.is_int()) {
            if (p.tmp_tree().bitfield_width(res.node, true)) |width| {
                if (res.ty.bitfield_promotion(p.comp, width)) |promotion_ty| {
                    return res.int_cast(p, promotion_ty, tok);
                }
            }
            return res.int_cast(p, res.ty.integer_promotion(p.comp), tok);
        }
    }

    fn usual_arithmetic_conversion(a: *Result, b: *Result, p: *Parser, tok: TokenIndex) Error!void {
        try a.usual_unary_conversion(p, tok);
        try b.usual_unary_conversion(p, tok);

        // if either is a float cast to that type
        if (a.ty.is_float() or b.ty.is_float()) {
            const float_types = [7][2]Type.Specifier{
                .{ .complex_long_double, .long_double },
                .{ .complex_float128, .float128 },
                .{ .complex_float80, .float80 },
                .{ .complex_double, .double },
                .{ .complex_float, .float },
                // No `_Complex __fp16` type
                .{ .invalid, .fp16 },
                // No `_Complex _Float16`
                .{ .invalid, .float16 },
            };
            const a_spec = a.ty.canonicalize(.standard).specifier;
            const b_spec = b.ty.canonicalize(.standard).specifier;
            if (p.comp.target.c_type_bit_size(.longdouble) == 128) {
                if (try a.float_conversion(b, a_spec, b_spec, p, float_types[0])) return;
            }
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[1])) return;
            if (p.comp.target.c_type_bit_size(.longdouble) == 80) {
                if (try a.float_conversion(b, a_spec, b_spec, p, float_types[0])) return;
            }
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[2])) return;
            if (p.comp.target.c_type_bit_size(.longdouble) == 64) {
                if (try a.float_conversion(b, a_spec, b_spec, p, float_types[0])) return;
            }
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[3])) return;
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[4])) return;
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[5])) return;
            if (try a.float_conversion(b, a_spec, b_spec, p, float_types[6])) return;
        }

        if (a.ty.eql(b.ty, p.comp, true)) {
            // cast to promoted type
            try a.int_cast(p, a.ty, tok);
            try b.int_cast(p, b.ty, tok);
            return;
        }

        const target = a.ty.integer_conversion(b.ty, p.comp);
        if (!target.is_real()) {
            try a.save_value(p);
            try b.save_value(p);
        }
        try a.int_cast(p, target, tok);
        try b.int_cast(p, target, tok);
    }

    fn float_conversion(a: *Result, b: *Result, a_spec: Type.Specifier, b_spec: Type.Specifier, p: *Parser, pair: [2]Type.Specifier) !bool {
        if (a_spec == pair[0] or a_spec == pair[1] or
            b_spec == pair[0] or b_spec == pair[1])
        {
            const both_real = a.ty.is_real() and b.ty.is_real();
            const res_spec = pair[@int_from_bool(both_real)];
            const ty = Type{ .specifier = res_spec };
            try a.float_cast(p, ty);
            try b.float_cast(p, ty);
            return true;
        }
        return false;
    }

    fn invalid_bin_ty(a: *Result, tok: TokenIndex, b: *Result, p: *Parser) Error!bool {
        try p.err_str(.invalid_bin_types, tok, try p.type_pair_str(a.ty, b.ty));
        a.val = .{};
        b.val = .{};
        a.ty = Type.invalid;
        return false;
    }

    fn should_eval(a: *Result, b: *Result, p: *Parser) Error!bool {
        if (p.no_eval) return false;
        if (a.val.opt_ref != .none and b.val.opt_ref != .none)
            return true;

        try a.save_value(p);
        try b.save_value(p);
        return p.no_eval;
    }

    /// Saves value and replaces it with `.unavailable`.
    fn save_value(res: *Result, p: *Parser) !void {
        assert(!p.in_macro);
        if (res.val.opt_ref == .none or res.val.opt_ref == .null) return;
        if (!p.in_macro) try p.value_map.put(res.node, res.val);
        res.val = .{};
    }

    fn cast_type(res: *Result, p: *Parser, to: Type, operand_tok: TokenIndex, l_paren: TokenIndex) !void {
        var cast_kind: Tree.CastKind = undefined;

        if (to.is(.void)) {
            // everything can cast to void
            cast_kind = .to_void;
            res.val = .{};
        } else if (to.is(.nullptr_t)) {
            if (res.ty.is(.nullptr_t)) {
                cast_kind = .no_op;
            } else {
                try p.err_str(.invalid_object_cast, l_paren, try p.type_pair_str_extra(res.ty, " to ", to));
                return error.ParsingFailed;
            }
        } else if (res.ty.is(.nullptr_t)) {
            if (to.is(.bool)) {
                try res.null_cast(p, res.ty);
                res.val.bool_cast(p.comp);
                res.ty = .{ .specifier = .bool };
                try res.implicit_cast(p, .pointer_to_bool);
                try res.save_value(p);
            } else if (to.is_ptr()) {
                try res.null_cast(p, to);
            } else {
                try p.err_str(.invalid_object_cast, l_paren, try p.type_pair_str_extra(res.ty, " to ", to));
                return error.ParsingFailed;
            }
            cast_kind = .no_op;
        } else if (res.val.is_zero(p.comp) and to.is_ptr()) {
            cast_kind = .null_to_pointer;
        } else if (to.is_scalar()) cast: {
            const old_float = res.ty.is_float();
            const new_float = to.is_float();

            if (new_float and res.ty.is_ptr()) {
                try p.err_str(.invalid_cast_to_float, l_paren, try p.type_str(to));
                return error.ParsingFailed;
            } else if (old_float and to.is_ptr()) {
                try p.err_str(.invalid_cast_to_pointer, l_paren, try p.type_str(res.ty));
                return error.ParsingFailed;
            }
            const old_real = res.ty.is_real();
            const new_real = to.is_real();

            if (to.eql(res.ty, p.comp, false)) {
                cast_kind = .no_op;
            } else if (to.is(.bool)) {
                if (res.ty.is_ptr()) {
                    cast_kind = .pointer_to_bool;
                } else if (res.ty.is_int()) {
                    if (!old_real) {
                        res.ty = res.ty.make_real();
                        try res.implicit_cast(p, .complex_int_to_real);
                    }
                    cast_kind = .int_to_bool;
                } else if (old_float) {
                    if (!old_real) {
                        res.ty = res.ty.make_real();
                        try res.implicit_cast(p, .complex_float_to_real);
                    }
                    cast_kind = .float_to_bool;
                }
            } else if (to.is_int()) {
                if (res.ty.is(.bool)) {
                    if (!new_real) {
                        res.ty = to.make_real();
                        try res.implicit_cast(p, .bool_to_int);
                        cast_kind = .real_to_complex_int;
                    } else {
                        cast_kind = .bool_to_int;
                    }
                } else if (res.ty.is_int()) {
                    if (old_real and new_real) {
                        cast_kind = .int_cast;
                    } else if (old_real) {
                        res.ty = to.make_real();
                        try res.implicit_cast(p, .int_cast);
                        cast_kind = .real_to_complex_int;
                    } else if (new_real) {
                        res.ty = res.ty.make_real();
                        try res.implicit_cast(p, .complex_int_to_real);
                        cast_kind = .int_cast;
                    } else {
                        cast_kind = .complex_int_cast;
                    }
                } else if (res.ty.is_ptr()) {
                    if (!new_real) {
                        res.ty = to.make_real();
                        try res.implicit_cast(p, .pointer_to_int);
                        cast_kind = .real_to_complex_int;
                    } else {
                        cast_kind = .pointer_to_int;
                    }
                } else if (old_real and new_real) {
                    cast_kind = .float_to_int;
                } else if (old_real) {
                    res.ty = to.make_real();
                    try res.implicit_cast(p, .float_to_int);
                    cast_kind = .real_to_complex_int;
                } else if (new_real) {
                    res.ty = res.ty.make_real();
                    try res.implicit_cast(p, .complex_float_to_real);
                    cast_kind = .float_to_int;
                } else {
                    cast_kind = .complex_float_to_complex_int;
                }
            } else if (to.is_ptr()) {
                if (res.ty.is_array())
                    cast_kind = .array_to_pointer
                else if (res.ty.is_ptr())
                    cast_kind = .bitcast
                else if (res.ty.is_func())
                    cast_kind = .function_to_pointer
                else if (res.ty.is(.bool))
                    cast_kind = .bool_to_pointer
                else if (res.ty.is_int()) {
                    if (!old_real) {
                        res.ty = res.ty.make_real();
                        try res.implicit_cast(p, .complex_int_to_real);
                    }
                    cast_kind = .int_to_pointer;
                } else {
                    try p.err_str(.cond_expr_type, operand_tok, try p.type_str(res.ty));
                    return error.ParsingFailed;
                }
            } else if (new_float) {
                if (res.ty.is(.bool)) {
                    if (!new_real) {
                        res.ty = to.make_real();
                        try res.implicit_cast(p, .bool_to_float);
                        cast_kind = .real_to_complex_float;
                    } else {
                        cast_kind = .bool_to_float;
                    }
                } else if (res.ty.is_int()) {
                    if (old_real and new_real) {
                        cast_kind = .int_to_float;
                    } else if (old_real) {
                        res.ty = to.make_real();
                        try res.implicit_cast(p, .int_to_float);
                        cast_kind = .real_to_complex_float;
                    } else if (new_real) {
                        res.ty = res.ty.make_real();
                        try res.implicit_cast(p, .complex_int_to_real);
                        cast_kind = .int_to_float;
                    } else {
                        cast_kind = .complex_int_to_complex_float;
                    }
                } else if (old_real and new_real) {
                    cast_kind = .float_cast;
                } else if (old_real) {
                    res.ty = to.make_real();
                    try res.implicit_cast(p, .float_cast);
                    cast_kind = .real_to_complex_float;
                } else if (new_real) {
                    res.ty = res.ty.make_real();
                    try res.implicit_cast(p, .complex_float_to_real);
                    cast_kind = .float_cast;
                } else {
                    cast_kind = .complex_float_cast;
                }
            }
            if (res.val.opt_ref == .none) break :cast;

            const old_int = res.ty.is_int() or res.ty.is_ptr();
            const new_int = to.is_int() or to.is_ptr();
            if (to.is(.bool)) {
                res.val.bool_cast(p.comp);
            } else if (old_float and new_int) {
                // Explicit cast, no conversion warning
                _ = try res.val.float_to_int(to, p.comp);
            } else if (new_float and old_int) {
                try res.val.int_to_float(to, p.comp);
            } else if (new_float and old_float) {
                try res.val.float_cast(to, p.comp);
            } else if (old_int and new_int) {
                if (to.has_incomplete_size()) {
                    try p.err_str(.cast_to_incomplete_type, l_paren, try p.type_str(to));
                    return error.ParsingFailed;
                }
                try res.val.int_cast(to, p.comp);
            }
        } else if (to.get(.@"union")) |union_ty| {
            if (union_ty.data.record.has_field_of_type(res.ty, p.comp)) {
                cast_kind = .union_cast;
                try p.err_tok(.gnu_union_cast, l_paren);
            } else {
                if (union_ty.data.record.is_incomplete()) {
                    try p.err_str(.cast_to_incomplete_type, l_paren, try p.type_str(to));
                } else {
                    try p.err_str(.invalid_union_cast, l_paren, try p.type_str(res.ty));
                }
                return error.ParsingFailed;
            }
        } else {
            if (to.is(.auto_type)) {
                try p.err_tok(.invalid_cast_to_auto_type, l_paren);
            } else {
                try p.err_str(.invalid_cast_type, l_paren, try p.type_str(to));
            }
            return error.ParsingFailed;
        }
        if (to.any_qual()) try p.err_str(.qual_cast, l_paren, try p.type_str(to));
        if (to.is_int() and res.ty.is_ptr() and to.size_compare(res.ty, p.comp) == .lt) {
            try p.err_str(.cast_to_smaller_int, l_paren, try p.type_pair_str_extra(to, " from ", res.ty));
        }
        res.ty = to;
        res.ty.qual = .{};
        res.node = try p.add_node(.{
            .tag = .explicit_cast,
            .ty = res.ty,
            .data = .{ .cast = .{ .operand = res.node, .kind = cast_kind } },
        });
    }

    fn int_fits_in_type(res: Result, p: *Parser, ty: Type) !bool {
        const max_int = try Value.int(ty.max_int(p.comp), p.comp);
        const min_int = try Value.int(ty.min_int(p.comp), p.comp);
        return res.val.compare(.lte, max_int, p.comp) and
            (res.ty.is_unsigned_int(p.comp) or res.val.compare(.gte, min_int, p.comp));
    }

    const CoerceContext = union(enum) {
        assign,
        init,
        ret,
        arg: TokenIndex,
        test_coerce,

        fn note(c: CoerceContext, p: *Parser) !void {
            switch (c) {
                .arg => |tok| try p.err_tok(.parameter_here, tok),
                .test_coerce => unreachable,
                else => {},
            }
        }

        fn type_pair_str(c: CoerceContext, p: *Parser, dest_ty: Type, src_ty: Type) ![]const u8 {
            switch (c) {
                .assign, .init => return p.type_pair_str_extra(dest_ty, " from incompatible type ", src_ty),
                .ret => return p.type_pair_str_extra(src_ty, " from a function with incompatible result type ", dest_ty),
                .arg => return p.type_pair_str_extra(src_ty, " to parameter of incompatible type ", dest_ty),
                .test_coerce => unreachable,
            }
        }
    };

    /// Perform assignment-like coercion to `dest_ty`.
    fn coerce(res: *Result, p: *Parser, dest_ty: Type, tok: TokenIndex, c: CoerceContext) Error!void {
        if (res.ty.specifier == .invalid or dest_ty.specifier == .invalid) {
            res.ty = Type.invalid;
            return;
        }
        return res.coerce_extra(p, dest_ty, tok, c) catch |er| switch (er) {
            error.CoercionFailed => unreachable,
            else => |e| return e,
        };
    }

    fn coerce_extra(
        res: *Result,
        p: *Parser,
        dest_ty: Type,
        tok: TokenIndex,
        c: CoerceContext,
    ) (Error || error{CoercionFailed})!void {
        // Subject of the coercion does not need to be qualified.
        var unqual_ty = dest_ty.canonicalize(.standard);
        unqual_ty.qual = .{};
        if (unqual_ty.is(.nullptr_t)) {
            if (res.ty.is(.nullptr_t)) return;
        } else if (unqual_ty.is(.bool)) {
            if (res.ty.is_scalar() and !res.ty.is(.nullptr_t)) {
                // this is ridiculous but it's what clang does
                try res.bool_cast(p, unqual_ty, tok);
                return;
            }
        } else if (unqual_ty.is_int()) {
            if (res.ty.is_int() or res.ty.is_float()) {
                try res.int_cast(p, unqual_ty, tok);
                return;
            } else if (res.ty.is_ptr()) {
                if (c == .test_coerce) return error.CoercionFailed;
                try p.err_str(.implicit_ptr_to_int, tok, try p.type_pair_str_extra(res.ty, " to ", dest_ty));
                try c.note(p);
                try res.int_cast(p, unqual_ty, tok);
                return;
            }
        } else if (unqual_ty.is_float()) {
            if (res.ty.is_int() or res.ty.is_float()) {
                try res.float_cast(p, unqual_ty);
                return;
            }
        } else if (unqual_ty.is_ptr()) {
            if (res.ty.is(.nullptr_t) or res.val.is_zero(p.comp)) {
                try res.null_cast(p, dest_ty);
                return;
            } else if (res.ty.is_int() and res.ty.is_real()) {
                if (c == .test_coerce) return error.CoercionFailed;
                try p.err_str(.implicit_int_to_ptr, tok, try p.type_pair_str_extra(res.ty, " to ", dest_ty));
                try c.note(p);
                try res.ptr_cast(p, unqual_ty);
                return;
            } else if (res.ty.is_void_star() or unqual_ty.eql(res.ty, p.comp, true)) {
                return; // ok
            } else if (unqual_ty.is_void_star() and res.ty.is_ptr() or (res.ty.is_int() and res.ty.is_real())) {
                return; // ok
            } else if (unqual_ty.eql(res.ty, p.comp, false)) {
                if (!unqual_ty.elem_type().qual.has_quals(res.ty.elem_type().qual)) {
                    try p.err_str(switch (c) {
                        .assign => .ptr_assign_discards_quals,
                        .init => .ptr_init_discards_quals,
                        .ret => .ptr_ret_discards_quals,
                        .arg => .ptr_arg_discards_quals,
                        .test_coerce => return error.CoercionFailed,
                    }, tok, try c.type_pair_str(p, dest_ty, res.ty));
                }
                try res.ptr_cast(p, unqual_ty);
                return;
            } else if (res.ty.is_ptr()) {
                const different_sign_only = unqual_ty.elem_type().same_rank_different_sign(res.ty.elem_type(), p.comp);
                try p.err_str(switch (c) {
                    .assign => ([2]Diagnostics.Tag{ .incompatible_ptr_assign, .incompatible_ptr_assign_sign })[@int_from_bool(different_sign_only)],
                    .init => ([2]Diagnostics.Tag{ .incompatible_ptr_init, .incompatible_ptr_init_sign })[@int_from_bool(different_sign_only)],
                    .ret => ([2]Diagnostics.Tag{ .incompatible_return, .incompatible_return_sign })[@int_from_bool(different_sign_only)],
                    .arg => ([2]Diagnostics.Tag{ .incompatible_ptr_arg, .incompatible_ptr_arg_sign })[@int_from_bool(different_sign_only)],
                    .test_coerce => return error.CoercionFailed,
                }, tok, try c.type_pair_str(p, dest_ty, res.ty));
                try c.note(p);
                try res.ptr_child_type_cast(p, unqual_ty);
                return;
            }
        } else if (unqual_ty.is_record()) {
            if (unqual_ty.eql(res.ty, p.comp, false)) {
                return; // ok
            }

            if (c == .arg) if (unqual_ty.get(.@"union")) |union_ty| {
                if (dest_ty.has_attribute(.transparent_union)) transparent_union: {
                    res.coerce_extra(p, union_ty.data.record.fields[0].ty, tok, .test_coerce) catch |er| switch (er) {
                        error.CoercionFailed => break :transparent_union,
                        else => |e| return e,
                    };
                    res.node = try p.add_node(.{
                        .tag = .union_init_expr,
                        .ty = dest_ty,
                        .data = .{ .union_init = .{ .field_index = 0, .node = res.node } },
                    });
                    res.ty = dest_ty;
                    return;
                }
            };
        } else if (unqual_ty.is(.vector)) {
            if (unqual_ty.eql(res.ty, p.comp, false)) {
                return; // ok
            }
        } else {
            if (c == .assign and (unqual_ty.is_array() or unqual_ty.is_func())) {
                try p.err_tok(.not_assignable, tok);
                return;
            } else if (c == .test_coerce) {
                return error.CoercionFailed;
            }
            // This case should not be possible and an error should have already been emitted but we
            // might still have attempted to parse further so return error.ParsingFailed here to stop.
            return error.ParsingFailed;
        }

        try p.err_str(switch (c) {
            .assign => .incompatible_assign,
            .init => .incompatible_init,
            .ret => .incompatible_return,
            .arg => .incompatible_arg,
            .test_coerce => return error.CoercionFailed,
        }, tok, try c.type_pair_str(p, dest_ty, res.ty));
        try c.note(p);
    }
};

/// expr : assign_expr (',' assign_expr)*
fn expr(p: *Parser) Error!Result {
    var expr_start = p.tok_i;
    var err_start = p.comp.diagnostics.list.items.len;
    var lhs = try p.assign_expr();
    if (p.tok_ids[p.tok_i] == .comma) try lhs.expect(p);
    while (p.eat_token(.comma)) |_| {
        try lhs.maybe_warn_unused(p, expr_start, err_start);
        expr_start = p.tok_i;
        err_start = p.comp.diagnostics.list.items.len;

        var rhs = try p.assign_expr();
        try rhs.expect(p);
        try rhs.lval_conversion(p);
        lhs.val = rhs.val;
        lhs.ty = rhs.ty;
        try lhs.bin(p, .comma_expr, rhs);
    }
    return lhs;
}

fn tok_to_tag(p: *Parser, tok: TokenIndex) Tree.Tag {
    return switch (p.tok_ids[tok]) {
        .equal => .assign_expr,
        .asterisk_equal => .mul_assign_expr,
        .slash_equal => .div_assign_expr,
        .percent_equal => .mod_assign_expr,
        .plus_equal => .add_assign_expr,
        .minus_equal => .sub_assign_expr,
        .angle_bracket_angle_bracket_left_equal => .shl_assign_expr,
        .angle_bracket_angle_bracket_right_equal => .shr_assign_expr,
        .ampersand_equal => .bit_and_assign_expr,
        .caret_equal => .bit_xor_assign_expr,
        .pipe_equal => .bit_or_assign_expr,
        .equal_equal => .equal_expr,
        .bang_equal => .not_equal_expr,
        .angle_bracket_left => .less_than_expr,
        .angle_bracket_left_equal => .less_than_equal_expr,
        .angle_bracket_right => .greater_than_expr,
        .angle_bracket_right_equal => .greater_than_equal_expr,
        .angle_bracket_angle_bracket_left => .shl_expr,
        .angle_bracket_angle_bracket_right => .shr_expr,
        .plus => .add_expr,
        .minus => .sub_expr,
        .asterisk => .mul_expr,
        .slash => .div_expr,
        .percent => .mod_expr,
        else => unreachable,
    };
}

/// assign_expr
///  : cond_expr
///  | un_expr ('=' | '*=' | '/=' | '%=' | '+=' | '-=' | '<<=' | '>>=' | '&=' | '^=' | '|=') assign_expr
fn assign_expr(p: *Parser) Error!Result {
    var lhs = try p.cond_expr();
    if (lhs.empty(p)) return lhs;

    const tok = p.tok_i;
    const eq = p.eat_token(.equal);
    const mul = eq orelse p.eat_token(.asterisk_equal);
    const div = mul orelse p.eat_token(.slash_equal);
    const mod = div orelse p.eat_token(.percent_equal);
    const add = mod orelse p.eat_token(.plus_equal);
    const sub = add orelse p.eat_token(.minus_equal);
    const shl = sub orelse p.eat_token(.angle_bracket_angle_bracket_left_equal);
    const shr = shl orelse p.eat_token(.angle_bracket_angle_bracket_right_equal);
    const bit_and = shr orelse p.eat_token(.ampersand_equal);
    const bit_xor = bit_and orelse p.eat_token(.caret_equal);
    const bit_or = bit_xor orelse p.eat_token(.pipe_equal);

    const tag = p.tok_to_tag(bit_or orelse return lhs);
    var rhs = try p.assign_expr();
    try rhs.expect(p);
    try rhs.lval_conversion(p);

    var is_const: bool = undefined;
    if (!p.tmp_tree().is_lval_extra(lhs.node, &is_const) or is_const) {
        try p.err_tok(.not_assignable, tok);
        return error.ParsingFailed;
    }

    // adjust_types will do do lvalue conversion but we do not want that
    var lhs_copy = lhs;
    switch (tag) {
        .assign_expr => {}, // handle plain assignment separately
        .mul_assign_expr,
        .div_assign_expr,
        .mod_assign_expr,
        => {
            if (rhs.val.is_zero(p.comp) and lhs.ty.is_int() and rhs.ty.is_int()) {
                switch (tag) {
                    .div_assign_expr => try p.err_str(.division_by_zero, div.?, "division"),
                    .mod_assign_expr => try p.err_str(.division_by_zero, mod.?, "remainder"),
                    else => {},
                }
            }
            _ = try lhs_copy.adjust_types(tok, &rhs, p, if (tag == .mod_assign_expr) .integer else .arithmetic);
            try lhs.bin(p, tag, rhs);
            return lhs;
        },
        .sub_assign_expr,
        .add_assign_expr,
        => {
            if (lhs.ty.is_ptr() and rhs.ty.is_int()) {
                try rhs.ptr_cast(p, lhs.ty);
            } else {
                _ = try lhs_copy.adjust_types(tok, &rhs, p, .arithmetic);
            }
            try lhs.bin(p, tag, rhs);
            return lhs;
        },
        .shl_assign_expr,
        .shr_assign_expr,
        .bit_and_assign_expr,
        .bit_xor_assign_expr,
        .bit_or_assign_expr,
        => {
            _ = try lhs_copy.adjust_types(tok, &rhs, p, .integer);
            try lhs.bin(p, tag, rhs);
            return lhs;
        },
        else => unreachable,
    }

    try rhs.coerce(p, lhs.ty, tok, .assign);

    try lhs.bin(p, tag, rhs);
    return lhs;
}

/// Returns a parse error if the expression is not an integer constant
/// integer_const_expr : const_expr
fn integer_const_expr(p: *Parser, decl_folding: ConstDeclFoldingMode) Error!Result {
    const start = p.tok_i;
    const res = try p.const_expr(decl_folding);
    if (!res.ty.is_int() and res.ty.specifier != .invalid) {
        try p.err_tok(.expected_integer_constant_expr, start);
        return error.ParsingFailed;
    }
    return res;
}

/// Caller is responsible for issuing a diagnostic if result is invalid/unavailable
/// const_expr : cond_expr
fn const_expr(p: *Parser, decl_folding: ConstDeclFoldingMode) Error!Result {
    const const_decl_folding = p.const_decl_folding;
    defer p.const_decl_folding = const_decl_folding;
    p.const_decl_folding = decl_folding;

    const res = try p.cond_expr();
    try res.expect(p);

    if (res.ty.specifier == .invalid or res.val.opt_ref == .none) return res;

    // save_value sets val to unavailable
    var copy = res;
    try copy.save_value(p);
    return res;
}

/// cond_expr : lor_expr ('?' expression? ':' cond_expr)?
fn cond_expr(p: *Parser) Error!Result {
    const cond_tok = p.tok_i;
    var cond = try p.lor_expr();
    if (cond.empty(p) or p.eat_token(.question_mark) == null) return cond;
    try cond.lval_conversion(p);
    const saved_eval = p.no_eval;

    if (!cond.ty.is_scalar()) {
        try p.err_str(.cond_expr_type, cond_tok, try p.type_str(cond.ty));
        return error.ParsingFailed;
    }

    // Prepare for possible binary conditional expression.
    const maybe_colon = p.eat_token(.colon);

    // Depending on the value of the condition, avoid evaluating unreachable branches.
    var then_expr = blk: {
        defer p.no_eval = saved_eval;
        if (cond.val.opt_ref != .none and !cond.val.to_bool(p.comp)) p.no_eval = true;
        break :blk try p.expr();
    };
    try then_expr.expect(p);

    // If we saw a colon then this is a binary conditional expression.
    if (maybe_colon) |colon| {
        var cond_then = cond;
        cond_then.node = try p.add_node(.{ .tag = .cond_dummy_expr, .ty = cond.ty, .data = .{ .un = cond.node } });
        _ = try cond_then.adjust_types(colon, &then_expr, p, .conditional);
        cond.ty = then_expr.ty;
        cond.node = try p.add_node(.{
            .tag = .binary_cond_expr,
            .ty = cond.ty,
            .data = .{ .if3 = .{ .cond = cond.node, .body = (try p.add_list(&.{ cond_then.node, then_expr.node })).start } },
        });
        return cond;
    }

    const colon = try p.expect_token(.colon);
    var else_expr = blk: {
        defer p.no_eval = saved_eval;
        if (cond.val.opt_ref != .none and cond.val.to_bool(p.comp)) p.no_eval = true;
        break :blk try p.cond_expr();
    };
    try else_expr.expect(p);

    _ = try then_expr.adjust_types(colon, &else_expr, p, .conditional);

    if (cond.val.opt_ref != .none) {
        cond.val = if (cond.val.to_bool(p.comp)) then_expr.val else else_expr.val;
    } else {
        try then_expr.save_value(p);
        try else_expr.save_value(p);
    }
    cond.ty = then_expr.ty;
    cond.node = try p.add_node(.{
        .tag = .cond_expr,
        .ty = cond.ty,
        .data = .{ .if3 = .{ .cond = cond.node, .body = (try p.add_list(&.{ then_expr.node, else_expr.node })).start } },
    });
    return cond;
}

/// lor_expr : land_expr ('||' land_expr)*
fn lor_expr(p: *Parser) Error!Result {
    var lhs = try p.land_expr();
    if (lhs.empty(p)) return lhs;
    const saved_eval = p.no_eval;
    defer p.no_eval = saved_eval;

    while (p.eat_token(.pipe_pipe)) |tok| {
        if (lhs.val.opt_ref != .none and lhs.val.to_bool(p.comp)) p.no_eval = true;
        var rhs = try p.land_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(tok, &rhs, p, .boolean_logic)) {
            const res = lhs.val.to_bool(p.comp) or rhs.val.to_bool(p.comp);
            lhs.val = Value.from_bool(res);
        }
        try lhs.bool_res(p, .bool_or_expr, rhs);
    }
    return lhs;
}

/// land_expr : or_expr ('&&' or_expr)*
fn land_expr(p: *Parser) Error!Result {
    var lhs = try p.or_expr();
    if (lhs.empty(p)) return lhs;
    const saved_eval = p.no_eval;
    defer p.no_eval = saved_eval;

    while (p.eat_token(.ampersand_ampersand)) |tok| {
        if (lhs.val.opt_ref != .none and !lhs.val.to_bool(p.comp)) p.no_eval = true;
        var rhs = try p.or_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(tok, &rhs, p, .boolean_logic)) {
            const res = lhs.val.to_bool(p.comp) and rhs.val.to_bool(p.comp);
            lhs.val = Value.from_bool(res);
        }
        try lhs.bool_res(p, .bool_and_expr, rhs);
    }
    return lhs;
}

/// or_expr : xor_expr ('|' xor_expr)*
fn or_expr(p: *Parser) Error!Result {
    var lhs = try p.xor_expr();
    if (lhs.empty(p)) return lhs;
    while (p.eat_token(.pipe)) |tok| {
        var rhs = try p.xor_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(tok, &rhs, p, .integer)) {
            lhs.val = try lhs.val.bit_or(rhs.val, p.comp);
        }
        try lhs.bin(p, .bit_or_expr, rhs);
    }
    return lhs;
}

/// xor_expr : and_expr ('^' and_expr)*
fn xor_expr(p: *Parser) Error!Result {
    var lhs = try p.and_expr();
    if (lhs.empty(p)) return lhs;
    while (p.eat_token(.caret)) |tok| {
        var rhs = try p.and_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(tok, &rhs, p, .integer)) {
            lhs.val = try lhs.val.bit_xor(rhs.val, p.comp);
        }
        try lhs.bin(p, .bit_xor_expr, rhs);
    }
    return lhs;
}

/// and_expr : eq_expr ('&' eq_expr)*
fn and_expr(p: *Parser) Error!Result {
    var lhs = try p.eq_expr();
    if (lhs.empty(p)) return lhs;
    while (p.eat_token(.ampersand)) |tok| {
        var rhs = try p.eq_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(tok, &rhs, p, .integer)) {
            lhs.val = try lhs.val.bit_and(rhs.val, p.comp);
        }
        try lhs.bin(p, .bit_and_expr, rhs);
    }
    return lhs;
}

/// eq_expr : comp_expr (('==' | '!=') comp_expr)*
fn eq_expr(p: *Parser) Error!Result {
    var lhs = try p.comp_expr();
    if (lhs.empty(p)) return lhs;
    while (true) {
        const eq = p.eat_token(.equal_equal);
        const ne = eq orelse p.eat_token(.bang_equal);
        const tag = p.tok_to_tag(ne orelse break);
        var rhs = try p.comp_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(ne.?, &rhs, p, .equality)) {
            const op: std.math.CompareOperator = if (tag == .equal_expr) .eq else .neq;
            const res = lhs.val.compare(op, rhs.val, p.comp);
            lhs.val = Value.from_bool(res);
        }
        try lhs.bool_res(p, tag, rhs);
    }
    return lhs;
}

/// comp_expr : shift_expr (('<' | '<=' | '>' | '>=') shift_expr)*
fn comp_expr(p: *Parser) Error!Result {
    var lhs = try p.shift_expr();
    if (lhs.empty(p)) return lhs;
    while (true) {
        const lt = p.eat_token(.angle_bracket_left);
        const le = lt orelse p.eat_token(.angle_bracket_left_equal);
        const gt = le orelse p.eat_token(.angle_bracket_right);
        const ge = gt orelse p.eat_token(.angle_bracket_right_equal);
        const tag = p.tok_to_tag(ge orelse break);
        var rhs = try p.shift_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(ge.?, &rhs, p, .relational)) {
            const op: std.math.CompareOperator = switch (tag) {
                .less_than_expr => .lt,
                .less_than_equal_expr => .lte,
                .greater_than_expr => .gt,
                .greater_than_equal_expr => .gte,
                else => unreachable,
            };
            const res = lhs.val.compare(op, rhs.val, p.comp);
            lhs.val = Value.from_bool(res);
        }
        try lhs.bool_res(p, tag, rhs);
    }
    return lhs;
}

/// shift_expr : add_expr (('<<' | '>>') add_expr)*
fn shift_expr(p: *Parser) Error!Result {
    var lhs = try p.add_expr();
    if (lhs.empty(p)) return lhs;
    while (true) {
        const shl = p.eat_token(.angle_bracket_angle_bracket_left);
        const shr = shl orelse p.eat_token(.angle_bracket_angle_bracket_right);
        const tag = p.tok_to_tag(shr orelse break);
        var rhs = try p.add_expr();
        try rhs.expect(p);

        if (try lhs.adjust_types(shr.?, &rhs, p, .integer)) {
            if (rhs.val.compare(.lt, Value.zero, p.comp)) {
                try p.err_str(.negative_shift_count, shl orelse shr.?, try rhs.str(p));
            }
            if (rhs.val.compare(.gte, try Value.int(lhs.ty.bit_sizeof(p.comp).?, p.comp), p.comp)) {
                try p.err_str(.too_big_shift_count, shl orelse shr.?, try rhs.str(p));
            }
            if (shl != null) {
                if (try lhs.val.shl(lhs.val, rhs.val, lhs.ty, p.comp) and
                    lhs.ty.signedness(p.comp) != .unsigned) try p.err_overflow(shl.?, lhs);
            } else {
                lhs.val = try lhs.val.shr(rhs.val, lhs.ty, p.comp);
            }
        }
        try lhs.bin(p, tag, rhs);
    }
    return lhs;
}

/// add_expr : mul_expr (('+' | '-') mul_expr)*
fn add_expr(p: *Parser) Error!Result {
    var lhs = try p.mul_expr();
    if (lhs.empty(p)) return lhs;
    while (true) {
        const plus = p.eat_token(.plus);
        const minus = plus orelse p.eat_token(.minus);
        const tag = p.tok_to_tag(minus orelse break);
        var rhs = try p.mul_expr();
        try rhs.expect(p);

        const lhs_ty = lhs.ty;
        if (try lhs.adjust_types(minus.?, &rhs, p, if (plus != null) .add else .sub)) {
            if (plus != null) {
                if (try lhs.val.add(lhs.val, rhs.val, lhs.ty, p.comp) and
                    lhs.ty.signedness(p.comp) != .unsigned) try p.err_overflow(plus.?, lhs);
            } else {
                if (try lhs.val.sub(lhs.val, rhs.val, lhs.ty, p.comp) and
                    lhs.ty.signedness(p.comp) != .unsigned) try p.err_overflow(minus.?, lhs);
            }
        }
        if (lhs.ty.specifier != .invalid and lhs_ty.is_ptr() and !lhs_ty.is_void_star() and lhs_ty.elem_type().has_incomplete_size()) {
            try p.err_str(.ptr_arithmetic_incomplete, minus.?, try p.type_str(lhs_ty.elem_type()));
            lhs.ty = Type.invalid;
        }
        try lhs.bin(p, tag, rhs);
    }
    return lhs;
}

/// mul_expr : cast_expr (('*' | '/' | '%') cast_expr)*´
fn mul_expr(p: *Parser) Error!Result {
    var lhs = try p.cast_expr();
    if (lhs.empty(p)) return lhs;
    while (true) {
        const mul = p.eat_token(.asterisk);
        const div = mul orelse p.eat_token(.slash);
        const percent = div orelse p.eat_token(.percent);
        const tag = p.tok_to_tag(percent orelse break);
        var rhs = try p.cast_expr();
        try rhs.expect(p);

        if (rhs.val.is_zero(p.comp) and mul == null and !p.no_eval and lhs.ty.is_int() and rhs.ty.is_int()) {
            const err_tag: Diagnostics.Tag = if (p.in_macro) .division_by_zero_macro else .division_by_zero;
            lhs.val = .{};
            if (div != null) {
                try p.err_str(err_tag, div.?, "division");
            } else {
                try p.err_str(err_tag, percent.?, "remainder");
            }
            if (p.in_macro) return error.ParsingFailed;
        }

        if (try lhs.adjust_types(percent.?, &rhs, p, if (tag == .mod_expr) .integer else .arithmetic)) {
            if (mul != null) {
                if (try lhs.val.mul(lhs.val, rhs.val, lhs.ty, p.comp) and
                    lhs.ty.signedness(p.comp) != .unsigned) try p.err_overflow(mul.?, lhs);
            } else if (div != null) {
                if (try lhs.val.div(lhs.val, rhs.val, lhs.ty, p.comp) and
                    lhs.ty.signedness(p.comp) != .unsigned) try p.err_overflow(mul.?, lhs);
            } else {
                var res = try Value.rem(lhs.val, rhs.val, lhs.ty, p.comp);
                if (res.opt_ref == .none) {
                    if (p.in_macro) {
                        // match clang behavior by defining invalid remainder to be zero in macros
                        res = Value.zero;
                    } else {
                        try lhs.save_value(p);
                        try rhs.save_value(p);
                    }
                }
                lhs.val = res;
            }
        }

        try lhs.bin(p, tag, rhs);
    }
    return lhs;
}

/// This will always be the last message, if present
fn remove_unused_warning_for_tok(p: *Parser, last_expr_tok: TokenIndex) void {
    if (last_expr_tok == 0) return;
    if (p.comp.diagnostics.list.items.len == 0) return;

    const last_expr_loc = p.pp.tokens.items(.loc)[last_expr_tok];
    const last_msg = p.comp.diagnostics.list.items[p.comp.diagnostics.list.items.len - 1];

    if (last_msg.tag == .unused_value and last_msg.loc.eql(last_expr_loc)) {
        p.comp.diagnostics.list.items.len = p.comp.diagnostics.list.items.len - 1;
    }
}

/// cast_expr
///  :  '(' compound_stmt ')'
///  |  '(' type_name ')' cast_expr
///  | '(' type_name ')' '{' initializerItems '}'
///  | __builtin_choose_expr '(' integer_const_expr ',' assign_expr ',' assign_expr ')'
///  | __builtin_va_arg '(' assign_expr ',' type_name ')'
///  | __builtin_offsetof '(' type_name ',' offsetof_member_designator ')'
///  | __builtin_bitoffsetof '(' type_name ',' offsetof_member_designator ')'
///  | un_expr
fn cast_expr(p: *Parser) Error!Result {
    if (p.eat_token(.l_paren)) |l_paren| cast_expr: {
        if (p.tok_ids[p.tok_i] == .l_brace) {
            try p.err(.gnu_statement_expression);
            if (p.func.ty == null) {
                try p.err(.stmt_expr_not_allowed_file_scope);
                return error.ParsingFailed;
            }
            var stmt_expr_state: StmtExprState = .{};
            const body_node = (try p.compound_stmt(false, &stmt_expr_state)).?; // compound_stmt only returns null if .l_brace isn't the first token
            p.remove_unused_warning_for_tok(stmt_expr_state.last_expr_tok);

            var res = Result{
                .node = body_node,
                .ty = stmt_expr_state.last_expr_res.ty,
                .val = stmt_expr_state.last_expr_res.val,
            };
            try p.expect_closing(l_paren, .r_paren);
            try res.un(p, .stmt_expr);
            return res;
        }
        const ty = (try p.type_name()) orelse {
            p.tok_i -= 1;
            break :cast_expr;
        };
        try p.expect_closing(l_paren, .r_paren);

        if (p.tok_ids[p.tok_i] == .l_brace) {
            // Compound literal; handled in un_expr
            p.tok_i = l_paren;
            break :cast_expr;
        }

        const operand_tok = p.tok_i;
        var operand = try p.cast_expr();
        try operand.expect(p);
        try operand.lval_conversion(p);
        try operand.cast_type(p, ty, operand_tok, l_paren);
        return operand;
    }
    switch (p.tok_ids[p.tok_i]) {
        .builtin_choose_expr => return p.builtin_choose_expr(),
        .builtin_va_arg => return p.builtin_va_arg(),
        .builtin_offsetof => return p.builtin_offsetof(false),
        .builtin_bitoffsetof => return p.builtin_offsetof(true),
        .builtin_types_compatible_p => return p.types_compatible(),
        // TODO: other special-cased builtins
        else => {},
    }
    return p.un_expr();
}

fn types_compatible(p: *Parser) Error!Result {
    p.tok_i += 1;
    const l_paren = try p.expect_token(.l_paren);

    const first = (try p.type_name()) orelse {
        try p.err(.expected_type);
        p.skip_to(.r_paren);
        return error.ParsingFailed;
    };
    const lhs = try p.add_node(.{ .tag = .invalid, .ty = first, .data = undefined });
    _ = try p.expect_token(.comma);

    const second = (try p.type_name()) orelse {
        try p.err(.expected_type);
        p.skip_to(.r_paren);
        return error.ParsingFailed;
    };
    const rhs = try p.add_node(.{ .tag = .invalid, .ty = second, .data = undefined });

    try p.expect_closing(l_paren, .r_paren);

    var first_unqual = first.canonicalize(.standard);
    first_unqual.qual.@"const" = false;
    first_unqual.qual.@"volatile" = false;
    var second_unqual = second.canonicalize(.standard);
    second_unqual.qual.@"const" = false;
    second_unqual.qual.@"volatile" = false;

    const compatible = first_unqual.eql(second_unqual, p.comp, true);

    const res = Result{
        .val = Value.from_bool(compatible),
        .node = try p.add_node(.{ .tag = .builtin_types_compatible_p, .ty = Type.int, .data = .{ .bin = .{
            .lhs = lhs,
            .rhs = rhs,
        } } }),
    };
    try p.value_map.put(res.node, res.val);
    return res;
}

fn builtin_choose_expr(p: *Parser) Error!Result {
    p.tok_i += 1;
    const l_paren = try p.expect_token(.l_paren);
    const cond_tok = p.tok_i;
    var cond = try p.integer_const_expr(.no_const_decl_folding);
    if (cond.val.opt_ref == .none) {
        try p.err_tok(.builtin_choose_cond, cond_tok);
        return error.ParsingFailed;
    }

    _ = try p.expect_token(.comma);

    var then_expr = if (cond.val.to_bool(p.comp)) try p.assign_expr() else try p.parse_no_eval(assign_expr);
    try then_expr.expect(p);

    _ = try p.expect_token(.comma);

    var else_expr = if (!cond.val.to_bool(p.comp)) try p.assign_expr() else try p.parse_no_eval(assign_expr);
    try else_expr.expect(p);

    try p.expect_closing(l_paren, .r_paren);

    if (cond.val.to_bool(p.comp)) {
        cond.val = then_expr.val;
        cond.ty = then_expr.ty;
    } else {
        cond.val = else_expr.val;
        cond.ty = else_expr.ty;
    }
    cond.node = try p.add_node(.{
        .tag = .builtin_choose_expr,
        .ty = cond.ty,
        .data = .{ .if3 = .{ .cond = cond.node, .body = (try p.add_list(&.{ then_expr.node, else_expr.node })).start } },
    });
    return cond;
}

fn builtin_va_arg(p: *Parser) Error!Result {
    const builtin_tok = p.tok_i;
    p.tok_i += 1;

    const l_paren = try p.expect_token(.l_paren);
    const va_list_tok = p.tok_i;
    var va_list = try p.assign_expr();
    try va_list.expect(p);
    try va_list.lval_conversion(p);

    _ = try p.expect_token(.comma);

    const ty = (try p.type_name()) orelse {
        try p.err(.expected_type);
        return error.ParsingFailed;
    };
    try p.expect_closing(l_paren, .r_paren);

    if (!va_list.ty.eql(p.comp.types.va_list, p.comp, true)) {
        try p.err_str(.incompatible_va_arg, va_list_tok, try p.type_str(va_list.ty));
        return error.ParsingFailed;
    }

    return Result{ .ty = ty, .node = try p.add_node(.{
        .tag = .special_builtin_call_one,
        .ty = ty,
        .data = .{ .decl = .{ .name = builtin_tok, .node = va_list.node } },
    }) };
}

fn builtin_offsetof(p: *Parser, want_bits: bool) Error!Result {
    const builtin_tok = p.tok_i;
    p.tok_i += 1;

    const l_paren = try p.expect_token(.l_paren);
    const ty_tok = p.tok_i;

    const ty = (try p.type_name()) orelse {
        try p.err(.expected_type);
        p.skip_to(.r_paren);
        return error.ParsingFailed;
    };

    if (!ty.is_record()) {
        try p.err_str(.offsetof_ty, ty_tok, try p.type_str(ty));
        p.skip_to(.r_paren);
        return error.ParsingFailed;
    } else if (ty.has_incomplete_size()) {
        try p.err_str(.offsetof_incomplete, ty_tok, try p.type_str(ty));
        p.skip_to(.r_paren);
        return error.ParsingFailed;
    }

    _ = try p.expect_token(.comma);

    const offsetof_expr = try p.offsetof_member_designator(ty, want_bits);

    try p.expect_closing(l_paren, .r_paren);

    return Result{
        .ty = p.comp.types.size,
        .val = offsetof_expr.val,
        .node = try p.add_node(.{
            .tag = .special_builtin_call_one,
            .ty = p.comp.types.size,
            .data = .{ .decl = .{ .name = builtin_tok, .node = offsetof_expr.node } },
        }),
    };
}

/// offsetof_member_designator: IDENTIFIER ('.' IDENTIFIER | '[' expr ']' )*
fn offsetof_member_designator(p: *Parser, base_ty: Type, want_bits: bool) Error!Result {
    errdefer p.skip_to(.r_paren);
    const base_field_name_tok = try p.expect_identifier();
    const base_field_name = try StrInt.intern(p.comp, p.tok_slice(base_field_name_tok));
    try p.validate_field_access(base_ty, base_ty, base_field_name_tok, base_field_name);
    const base_node = try p.add_node(.{ .tag = .default_init_expr, .ty = base_ty, .data = undefined });

    var cur_offset: u64 = 0;
    const base_record_ty = base_ty.canonicalize(.standard);
    var lhs = try p.field_access_extra(base_node, base_record_ty, base_field_name, false, &cur_offset);

    var total_offset = cur_offset;
    while (true) switch (p.tok_ids[p.tok_i]) {
        .period => {
            p.tok_i += 1;
            const field_name_tok = try p.expect_identifier();
            const field_name = try StrInt.intern(p.comp, p.tok_slice(field_name_tok));

            if (!lhs.ty.is_record()) {
                try p.err_str(.offsetof_ty, field_name_tok, try p.type_str(lhs.ty));
                return error.ParsingFailed;
            }
            try p.validate_field_access(lhs.ty, lhs.ty, field_name_tok, field_name);
            const record_ty = lhs.ty.canonicalize(.standard);
            lhs = try p.field_access_extra(lhs.node, record_ty, field_name, false, &cur_offset);
            total_offset += cur_offset;
        },
        .l_bracket => {
            const l_bracket_tok = p.tok_i;
            p.tok_i += 1;
            var index = try p.expr();
            try index.expect(p);
            _ = try p.expect_closing(l_bracket_tok, .r_bracket);

            if (!lhs.ty.is_array()) {
                try p.err_str(.offsetof_array, l_bracket_tok, try p.type_str(lhs.ty));
                return error.ParsingFailed;
            }
            var ptr = lhs;
            try ptr.lval_conversion(p);
            try index.lval_conversion(p);

            if (!index.ty.is_int()) try p.err_tok(.invalid_index, l_bracket_tok);
            try p.check_array_bounds(index, lhs, l_bracket_tok);

            try index.save_value(p);
            try ptr.bin(p, .array_access_expr, index);
            lhs = ptr;
        },
        else => break,
    };
    const val = try Value.int(if (want_bits) total_offset else total_offset / 8, p.comp);
    return Result{ .ty = base_ty, .val = val, .node = lhs.node };
}

/// un_expr
///  : (compound_literal | primary_expr) suffix_expr*
///  | '&&' IDENTIFIER
///  | ('&' | '*' | '+' | '-' | '~' | '!' | '++' | '--' | keyword_extension | keyword_imag | keyword_real) cast_expr
///  | keyword_sizeof un_expr
///  | keyword_sizeof '(' type_name ')'
///  | keyword_alignof '(' type_name ')'
///  | keyword_c23_alignof '(' type_name ')'
fn un_expr(p: *Parser) Error!Result {
    const tok = p.tok_i;
    switch (p.tok_ids[tok]) {
        .ampersand_ampersand => {
            const address_tok = p.tok_i;
            p.tok_i += 1;
            const name_tok = try p.expect_identifier();
            try p.err_tok(.gnu_label_as_value, address_tok);
            p.contains_address_of_label = true;

            const str = p.tok_slice(name_tok);
            if (p.find_label(str) == null) {
                try p.labels.append(.{ .unresolved_goto = name_tok });
            }
            const elem_ty = try p.arena.create(Type);
            elem_ty.* = .{ .specifier = .void };
            const result_ty = Type{ .specifier = .pointer, .data = .{ .sub_type = elem_ty } };
            return Result{
                .node = try p.add_node(.{
                    .tag = .addr_of_label,
                    .data = .{ .decl_ref = name_tok },
                    .ty = result_ty,
                }),
                .ty = result_ty,
            };
        },
        .ampersand => {
            if (p.in_macro) {
                try p.err(.invalid_preproc_operator);
                return error.ParsingFailed;
            }
            p.tok_i += 1;
            var operand = try p.cast_expr();
            try operand.expect(p);

            const tree = p.tmp_tree();
            if (p.get_node(operand.node, .member_access_expr) orelse
                p.get_node(operand.node, .member_access_ptr_expr)) |member_node|
            {
                if (tree.is_bitfield(member_node)) try p.err_tok(.addr_of_bitfield, tok);
            }
            if (!tree.is_lval(operand.node)) {
                try p.err_tok(.addr_of_rvalue, tok);
            }
            if (operand.ty.qual.register) try p.err_tok(.addr_of_register, tok);

            const elem_ty = try p.arena.create(Type);
            elem_ty.* = operand.ty;
            operand.ty = Type{
                .specifier = .pointer,
                .data = .{ .sub_type = elem_ty },
            };
            try operand.save_value(p);
            try operand.un(p, .addr_of_expr);
            return operand;
        },
        .asterisk => {
            const asterisk_loc = p.tok_i;
            p.tok_i += 1;
            var operand = try p.cast_expr();
            try operand.expect(p);

            if (operand.ty.is_array() or operand.ty.is_ptr() or operand.ty.is_func()) {
                try operand.lval_conversion(p);
                operand.ty = operand.ty.elem_type();
            } else {
                try p.err_tok(.indirection_ptr, tok);
            }
            if (operand.ty.has_incomplete_size() and !operand.ty.is(.void)) {
                try p.err_str(.deref_incomplete_ty_ptr, asterisk_loc, try p.type_str(operand.ty));
            }
            operand.ty.qual = .{};
            try operand.un(p, .deref_expr);
            return operand;
        },
        .plus => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            if (!operand.ty.is_int() and !operand.ty.is_float())
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));

            try operand.usual_unary_conversion(p, tok);

            return operand;
        },
        .minus => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            if (!operand.ty.is_int() and !operand.ty.is_float())
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));

            try operand.usual_unary_conversion(p, tok);
            if (operand.val.is(.int, p.comp) or operand.val.is(.float, p.comp)) {
                _ = try operand.val.sub(Value.zero, operand.val, operand.ty, p.comp);
            } else {
                operand.val = .{};
            }
            try operand.un(p, .negate_expr);
            return operand;
        },
        .plus_plus => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            if (!operand.ty.is_scalar())
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));
            if (operand.ty.is_complex())
                try p.err_str(.complex_prefix_postfix_op, p.tok_i, try p.type_str(operand.ty));

            if (!p.tmp_tree().is_lval(operand.node) or operand.ty.is_const()) {
                try p.err_tok(.not_assignable, tok);
                return error.ParsingFailed;
            }
            try operand.usual_unary_conversion(p, tok);

            if (operand.val.is(.int, p.comp) or operand.val.is(.int, p.comp)) {
                if (try operand.val.add(operand.val, Value.one, operand.ty, p.comp))
                    try p.err_overflow(tok, operand);
            } else {
                operand.val = .{};
            }

            try operand.un(p, .pre_inc_expr);
            return operand;
        },
        .minus_minus => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            if (!operand.ty.is_scalar())
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));
            if (operand.ty.is_complex())
                try p.err_str(.complex_prefix_postfix_op, p.tok_i, try p.type_str(operand.ty));

            if (!p.tmp_tree().is_lval(operand.node) or operand.ty.is_const()) {
                try p.err_tok(.not_assignable, tok);
                return error.ParsingFailed;
            }
            try operand.usual_unary_conversion(p, tok);

            if (operand.val.is(.int, p.comp) or operand.val.is(.int, p.comp)) {
                if (try operand.val.sub(operand.val, Value.one, operand.ty, p.comp))
                    try p.err_overflow(tok, operand);
            } else {
                operand.val = .{};
            }

            try operand.un(p, .pre_dec_expr);
            return operand;
        },
        .tilde => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            try operand.usual_unary_conversion(p, tok);
            if (operand.ty.is_int()) {
                if (operand.val.is(.int, p.comp)) {
                    operand.val = try operand.val.bit_not(operand.ty, p.comp);
                }
            } else if (operand.ty.is_complex()) {
                try p.err_str(.complex_conj, tok, try p.type_str(operand.ty));
            } else {
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));
                operand.val = .{};
            }
            try operand.un(p, .bit_not_expr);
            return operand;
        },
        .bang => {
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            if (!operand.ty.is_scalar())
                try p.err_str(.invalid_argument_un, tok, try p.type_str(operand.ty));

            try operand.usual_unary_conversion(p, tok);
            if (operand.val.is(.int, p.comp)) {
                operand.val = Value.from_bool(!operand.val.to_bool(p.comp));
            } else if (operand.val.opt_ref == .null) {
                operand.val = Value.one;
            } else {
                if (operand.ty.is_decayed()) {
                    operand.val = Value.zero;
                } else {
                    operand.val = .{};
                }
            }
            operand.ty = .{ .specifier = .int };
            try operand.un(p, .bool_not_expr);
            return operand;
        },
        .keyword_sizeof => {
            p.tok_i += 1;
            const expected_paren = p.tok_i;
            var res = Result{};
            if (try p.type_name()) |ty| {
                res.ty = ty;
                try p.err_tok(.expected_parens_around_typename, expected_paren);
            } else if (p.eat_token(.l_paren)) |l_paren| {
                if (try p.type_name()) |ty| {
                    res.ty = ty;
                    try p.expect_closing(l_paren, .r_paren);
                } else {
                    p.tok_i = expected_paren;
                    res = try p.parse_no_eval(un_expr);
                }
            } else {
                res = try p.parse_no_eval(un_expr);
            }

            if (res.ty.is(.void)) {
                try p.err_str(.pointer_arith_void, tok, "sizeof");
            } else if (res.ty.is_decayed()) {
                const array_ty = res.ty.original_type_of_decayed_array();
                const err_str = try p.type_pair_str_extra(res.ty, " instead of ", array_ty);
                try p.err_str(.sizeof_array_arg, tok, err_str);
            }
            if (res.ty.sizeof(p.comp)) |size| {
                if (size == 0) {
                    try p.err_tok(.sizeof_returns_zero, tok);
                }
                res.val = try Value.int(size, p.comp);
                res.ty = p.comp.types.size;
            } else {
                res.val = .{};
                if (res.ty.has_incomplete_size()) {
                    try p.err_str(.invalid_sizeof, expected_paren - 1, try p.type_str(res.ty));
                    res.ty = Type.invalid;
                } else {
                    res.ty = p.comp.types.size;
                }
            }
            try res.un(p, .sizeof_expr);
            return res;
        },
        .keyword_alignof,
        .keyword_alignof1,
        .keyword_alignof2,
        .keyword_c23_alignof,
        => {
            p.tok_i += 1;
            const expected_paren = p.tok_i;
            var res = Result{};
            if (try p.type_name()) |ty| {
                res.ty = ty;
                try p.err_tok(.expected_parens_around_typename, expected_paren);
            } else if (p.eat_token(.l_paren)) |l_paren| {
                if (try p.type_name()) |ty| {
                    res.ty = ty;
                    try p.expect_closing(l_paren, .r_paren);
                } else {
                    p.tok_i = expected_paren;
                    res = try p.parse_no_eval(un_expr);
                    try p.err_tok(.alignof_expr, expected_paren);
                }
            } else {
                res = try p.parse_no_eval(un_expr);
                try p.err_tok(.alignof_expr, expected_paren);
            }

            if (res.ty.is(.void)) {
                try p.err_str(.pointer_arith_void, tok, "alignof");
            }
            if (res.ty.alignable()) {
                res.val = try Value.int(res.ty.alignof(p.comp), p.comp);
                res.ty = p.comp.types.size;
            } else {
                try p.err_str(.invalid_alignof, expected_paren, try p.type_str(res.ty));
                res.ty = Type.invalid;
            }
            try res.un(p, .alignof_expr);
            return res;
        },
        .keyword_extension => {
            p.tok_i += 1;
            const saved_extension = p.extension_suppressed;
            defer p.extension_suppressed = saved_extension;
            p.extension_suppressed = true;

            var child = try p.cast_expr();
            try child.expect(p);
            return child;
        },
        .keyword_imag1, .keyword_imag2 => {
            const imag_tok = p.tok_i;
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            if (!operand.ty.is_int() and !operand.ty.is_float()) {
                try p.err_str(.invalid_imag, imag_tok, try p.type_str(operand.ty));
            }
            if (operand.ty.is_real()) {
                switch (p.comp.langopts.emulate) {
                    .msvc => {}, // Doesn't support `_Complex` or `__imag` in the first place
                    .gcc => operand.val = Value.zero,
                    .clang => {
                        if (operand.val.is(.int, p.comp)) {
                            operand.val = Value.zero;
                        } else {
                            operand.val = .{};
                        }
                    },
                }
            }
            // convert _Complex T to T
            operand.ty = operand.ty.make_real();
            try operand.un(p, .imag_expr);
            return operand;
        },
        .keyword_real1, .keyword_real2 => {
            const real_tok = p.tok_i;
            p.tok_i += 1;

            var operand = try p.cast_expr();
            try operand.expect(p);
            try operand.lval_conversion(p);
            if (!operand.ty.is_int() and !operand.ty.is_float()) {
                try p.err_str(.invalid_real, real_tok, try p.type_str(operand.ty));
            }
            // convert _Complex T to T
            operand.ty = operand.ty.make_real();
            try operand.un(p, .real_expr);
            return operand;
        },
        else => {
            var lhs = try p.compound_literal();
            if (lhs.empty(p)) {
                lhs = try p.primary_expr();
                if (lhs.empty(p)) return lhs;
            }
            while (true) {
                const suffix = try p.suffix_expr(lhs);
                if (suffix.empty(p)) break;
                lhs = suffix;
            }
            return lhs;
        },
    }
}

/// compound_literal
///  : '(' storage_class_spec* type_name ')' '{' initializer_list '}'
///  | '(' storage_class_spec* type_name ')' '{' initializer_list ',' '}'
fn compound_literal(p: *Parser) Error!Result {
    const l_paren = p.eat_token(.l_paren) orelse return Result{};

    var d: DeclSpec = .{ .ty = .{ .specifier = undefined } };
    const any = if (p.comp.langopts.standard.at_least(.c23))
        try p.storage_class_spec(&d)
    else
        false;

    const tag: Tree.Tag = switch (d.storage_class) {
        .static => if (d.thread_local != null)
            .static_thread_local_compound_literal_expr
        else
            .static_compound_literal_expr,
        .register, .none => if (d.thread_local != null)
            .thread_local_compound_literal_expr
        else
            .compound_literal_expr,
        .auto, .@"extern", .typedef => |tok| blk: {
            try p.err_str(.invalid_compound_literal_storage_class, tok, @tag_name(d.storage_class));
            d.storage_class = .none;
            break :blk if (d.thread_local != null)
                .thread_local_compound_literal_expr
            else
                .compound_literal_expr;
        },
    };

    var ty = (try p.type_name()) orelse {
        p.tok_i = l_paren;
        if (any) {
            try p.err(.expected_type);
            return error.ParsingFailed;
        }
        return Result{};
    };
    if (d.storage_class == .register) ty.qual.register = true;
    try p.expect_closing(l_paren, .r_paren);

    if (ty.is_func()) {
        try p.err(.func_init);
    } else if (ty.is(.variable_len_array)) {
        try p.err(.vla_init);
    } else if (ty.has_incomplete_size() and !ty.is(.incomplete_array)) {
        try p.err_str(.variable_incomplete_ty, p.tok_i, try p.type_str(ty));
        return error.ParsingFailed;
    }
    var init_list_expr = try p.initializer(ty);
    if (d.constexpr) |_| {
        // TODO error if not constexpr
    }
    try init_list_expr.un(p, tag);
    return init_list_expr;
}

/// suffix_expr
///  : '[' expr ']'
///  | '(' argumentExprList? ')'
///  | '.' IDENTIFIER
///  | '->' IDENTIFIER
///  | '++'
///  | '--'
/// argumentExprList : assign_expr (',' assign_expr)*
fn suffix_expr(p: *Parser, lhs: Result) Error!Result {
    assert(!lhs.empty(p));
    switch (p.tok_ids[p.tok_i]) {
        .l_paren => return p.call_expr(lhs),
        .plus_plus => {
            defer p.tok_i += 1;

            var operand = lhs;
            if (!operand.ty.is_scalar())
                try p.err_str(.invalid_argument_un, p.tok_i, try p.type_str(operand.ty));
            if (operand.ty.is_complex())
                try p.err_str(.complex_prefix_postfix_op, p.tok_i, try p.type_str(operand.ty));

            if (!p.tmp_tree().is_lval(operand.node) or operand.ty.is_const()) {
                try p.err(.not_assignable);
                return error.ParsingFailed;
            }
            try operand.usual_unary_conversion(p, p.tok_i);

            try operand.un(p, .post_inc_expr);
            return operand;
        },
        .minus_minus => {
            defer p.tok_i += 1;

            var operand = lhs;
            if (!operand.ty.is_scalar())
                try p.err_str(.invalid_argument_un, p.tok_i, try p.type_str(operand.ty));
            if (operand.ty.is_complex())
                try p.err_str(.complex_prefix_postfix_op, p.tok_i, try p.type_str(operand.ty));

            if (!p.tmp_tree().is_lval(operand.node) or operand.ty.is_const()) {
                try p.err(.not_assignable);
                return error.ParsingFailed;
            }
            try operand.usual_unary_conversion(p, p.tok_i);

            try operand.un(p, .post_dec_expr);
            return operand;
        },
        .l_bracket => {
            const l_bracket = p.tok_i;
            p.tok_i += 1;
            var index = try p.expr();
            try index.expect(p);
            try p.expect_closing(l_bracket, .r_bracket);

            const array_before_conversion = lhs;
            const index_before_conversion = index;
            var ptr = lhs;
            try ptr.lval_conversion(p);
            try index.lval_conversion(p);
            if (ptr.ty.is_ptr()) {
                ptr.ty = ptr.ty.elem_type();
                if (!index.ty.is_int()) try p.err_tok(.invalid_index, l_bracket);
                try p.check_array_bounds(index_before_conversion, array_before_conversion, l_bracket);
            } else if (index.ty.is_ptr()) {
                index.ty = index.ty.elem_type();
                if (!ptr.ty.is_int()) try p.err_tok(.invalid_index, l_bracket);
                try p.check_array_bounds(array_before_conversion, index_before_conversion, l_bracket);
                std.mem.swap(Result, &ptr, &index);
            } else {
                try p.err_tok(.invalid_subscript, l_bracket);
            }

            try ptr.save_value(p);
            try index.save_value(p);
            try ptr.bin(p, .array_access_expr, index);
            return ptr;
        },
        .period => {
            p.tok_i += 1;
            const name = try p.expect_identifier();
            return p.field_access(lhs, name, false);
        },
        .arrow => {
            p.tok_i += 1;
            const name = try p.expect_identifier();
            if (lhs.ty.is_array()) {
                var copy = lhs;
                copy.ty.decay_array();
                try copy.implicit_cast(p, .array_to_pointer);
                return p.field_access(copy, name, true);
            }
            return p.field_access(lhs, name, true);
        },
        else => return Result{},
    }
}

fn field_access(
    p: *Parser,
    lhs: Result,
    field_name_tok: TokenIndex,
    is_arrow: bool,
) !Result {
    const expr_ty = lhs.ty;
    const is_ptr = expr_ty.is_ptr();
    const expr_base_ty = if (is_ptr) expr_ty.elem_type() else expr_ty;
    const record_ty = expr_base_ty.canonicalize(.standard);

    switch (record_ty.specifier) {
        .@"struct", .@"union" => {},
        else => {
            try p.err_str(.expected_record_ty, field_name_tok, try p.type_str(expr_ty));
            return error.ParsingFailed;
        },
    }
    if (record_ty.has_incomplete_size()) {
        try p.err_str(.deref_incomplete_ty_ptr, field_name_tok - 2, try p.type_str(expr_base_ty));
        return error.ParsingFailed;
    }
    if (is_arrow and !is_ptr) try p.err_str(.member_expr_not_ptr, field_name_tok, try p.type_str(expr_ty));
    if (!is_arrow and is_ptr) try p.err_str(.member_expr_ptr, field_name_tok, try p.type_str(expr_ty));

    const field_name = try StrInt.intern(p.comp, p.tok_slice(field_name_tok));
    try p.validate_field_access(record_ty, expr_ty, field_name_tok, field_name);
    var discard: u64 = 0;
    return p.field_access_extra(lhs.node, record_ty, field_name, is_arrow, &discard);
}

fn validate_field_access(p: *Parser, record_ty: Type, expr_ty: Type, field_name_tok: TokenIndex, field_name: StringId) Error!void {
    if (record_ty.has_field(field_name)) return;

    p.strings.items.len = 0;

    try p.strings.writer().print("'{s}' in '", .{p.tok_slice(field_name_tok)});
    const mapper = p.comp.string_interner.get_slow_type_mapper();
    try expr_ty.print(mapper, p.comp.langopts, p.strings.writer());
    try p.strings.append('\'');

    const duped = try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items);
    try p.err_str(.no_such_member, field_name_tok, duped);
    return error.ParsingFailed;
}

fn field_access_extra(p: *Parser, lhs: NodeIndex, record_ty: Type, field_name: StringId, is_arrow: bool, offset_bits: *u64) Error!Result {
    for (record_ty.data.record.fields, 0..) |f, i| {
        if (f.is_anonymous_record()) {
            if (!f.ty.has_field(field_name)) continue;
            const inner = try p.add_node(.{
                .tag = if (is_arrow) .member_access_ptr_expr else .member_access_expr,
                .ty = f.ty,
                .data = .{ .member = .{ .lhs = lhs, .index = @int_cast(i) } },
            });
            const ret = p.field_access_extra(inner, f.ty, field_name, false, offset_bits);
            offset_bits.* = f.layout.offset_bits;
            return ret;
        }
        if (field_name == f.name) {
            offset_bits.* = f.layout.offset_bits;
            return Result{
                .ty = f.ty,
                .node = try p.add_node(.{
                    .tag = if (is_arrow) .member_access_ptr_expr else .member_access_expr,
                    .ty = f.ty,
                    .data = .{ .member = .{ .lhs = lhs, .index = @int_cast(i) } },
                }),
            };
        }
    }
    // We already checked that this container has a field by the name.
    unreachable;
}

fn check_va_start_arg(p: *Parser, builtin_tok: TokenIndex, first_after: TokenIndex, param_tok: TokenIndex, arg: *Result, idx: u32) !void {
    assert(idx != 0);
    if (idx > 1) {
        try p.err_tok(.closing_paren, first_after);
        return error.ParsingFailed;
    }

    var func_ty = p.func.ty orelse {
        try p.err_tok(.va_start_not_in_func, builtin_tok);
        return;
    };
    const func_params = func_ty.params();
    if (func_ty.specifier != .var_args_func or func_params.len == 0) {
        return p.err_tok(.va_start_fixed_args, builtin_tok);
    }
    const last_param_name = func_params[func_params.len - 1].name;
    const decl_ref = p.get_node(arg.node, .decl_ref_expr);
    if (decl_ref == null or last_param_name != try StrInt.intern(p.comp, p.tok_slice(p.nodes.items(.data)[@int_from_enum(decl_ref.?)].decl_ref))) {
        try p.err_tok(.va_start_not_last_param, param_tok);
    }
}

fn check_arith_overflow_arg(p: *Parser, builtin_tok: TokenIndex, first_after: TokenIndex, param_tok: TokenIndex, arg: *Result, idx: u32) !void {
    _ = builtin_tok;
    _ = first_after;
    if (idx <= 1) {
        if (!arg.ty.is_int()) {
            return p.err_str(.overflow_builtin_requires_int, param_tok, try p.type_str(arg.ty));
        }
    } else if (idx == 2) {
        if (!arg.ty.is_ptr()) return p.err_str(.overflow_result_requires_ptr, param_tok, try p.type_str(arg.ty));
        const child = arg.ty.elem_type();
        if (!child.is_int() or child.is(.bool) or child.is(.@"enum") or child.qual.@"const") return p.err_str(.overflow_result_requires_ptr, param_tok, try p.type_str(arg.ty));
    }
}

fn check_complex_arg(p: *Parser, builtin_tok: TokenIndex, first_after: TokenIndex, param_tok: TokenIndex, arg: *Result, idx: u32) !void {
    _ = builtin_tok;
    _ = first_after;
    if (idx <= 1 and !arg.ty.is_float()) {
        try p.err_str(.not_floating_type, param_tok, try p.type_str(arg.ty));
    } else if (idx == 1) {
        const prev_idx = p.list_buf.items[p.list_buf.items.len - 1];
        const prev_ty = p.nodes.items(.ty)[@int_from_enum(prev_idx)];
        if (!prev_ty.eql(arg.ty, p.comp, false)) {
            try p.err_str(.argument_types_differ, param_tok, try p.type_pair_str_extra(prev_ty, " vs ", arg.ty));
        }
    }
}

fn call_expr(p: *Parser, lhs: Result) Error!Result {
    const l_paren = p.tok_i;
    p.tok_i += 1;
    const ty = lhs.ty.is_callable() orelse {
        try p.err_str(.not_callable, l_paren, try p.type_str(lhs.ty));
        return error.ParsingFailed;
    };
    const params = ty.params();
    var func = lhs;
    try func.lval_conversion(p);

    const list_buf_top = p.list_buf.items.len;
    defer p.list_buf.items.len = list_buf_top;
    try p.list_buf.append(func.node);
    var arg_count: u32 = 0;
    var first_after = l_paren;

    const call_expr = CallExpr.init(p, lhs.node, func.node);

    while (p.eat_token(.r_paren) == null) {
        const param_tok = p.tok_i;
        if (arg_count == params.len) first_after = p.tok_i;
        var arg = try p.assign_expr();
        try arg.expect(p);

        if (call_expr.should_perform_lval_conversion(arg_count)) {
            try arg.lval_conversion(p);
        }
        if (arg.ty.has_incomplete_size() and !arg.ty.is(.void)) return error.ParsingFailed;

        if (arg_count >= params.len) {
            if (call_expr.should_promote_var_arg(arg_count)) {
                if (arg.ty.is_int()) try arg.int_cast(p, arg.ty.integer_promotion(p.comp), param_tok);
                if (arg.ty.is(.float)) try arg.float_cast(p, .{ .specifier = .double });
            }
            try call_expr.check_var_arg(p, first_after, param_tok, &arg, arg_count);
            try arg.save_value(p);
            try p.list_buf.append(arg.node);
            arg_count += 1;

            _ = p.eat_token(.comma) orelse {
                try p.expect_closing(l_paren, .r_paren);
                break;
            };
            continue;
        }
        const p_ty = params[arg_count].ty;
        if (call_expr.should_coerce_arg(arg_count)) {
            try arg.coerce(p, p_ty, param_tok, .{ .arg = params[arg_count].name_tok });
        }
        try arg.save_value(p);
        try p.list_buf.append(arg.node);
        arg_count += 1;

        _ = p.eat_token(.comma) orelse {
            try p.expect_closing(l_paren, .r_paren);
            break;
        };
    }

    const actual: u32 = @int_cast(arg_count);
    const extra = Diagnostics.Message.Extra{ .arguments = .{
        .expected = @int_cast(params.len),
        .actual = actual,
    } };
    if (call_expr.param_count_override()) |expected| {
        if (expected != actual) {
            try p.err_extra(.expected_arguments, first_after, .{ .arguments = .{ .expected = expected, .actual = actual } });
        }
    } else if (ty.is(.func) and params.len != arg_count) {
        try p.err_extra(.expected_arguments, first_after, extra);
    } else if (ty.is(.old_style_func) and params.len != arg_count) {
        if (params.len == 0)
            try p.err_tok(.passing_args_to_kr, first_after)
        else
            try p.err_extra(.expected_arguments_old, first_after, extra);
    } else if (ty.is(.var_args_func) and arg_count < params.len) {
        try p.err_extra(.expected_at_least_arguments, first_after, extra);
    }

    return call_expr.finish(p, ty, list_buf_top, arg_count);
}

fn check_array_bounds(p: *Parser, index: Result, array: Result, tok: TokenIndex) !void {
    if (index.val.opt_ref == .none) return;

    const array_len = array.ty.array_len() orelse return;
    if (array_len == 0) return;

    if (array_len == 1) {
        if (p.get_node(array.node, .member_access_expr) orelse p.get_node(array.node, .member_access_ptr_expr)) |node| {
            const data = p.nodes.items(.data)[@int_from_enum(node)];
            var lhs = p.nodes.items(.ty)[@int_from_enum(data.member.lhs)];
            if (lhs.get(.pointer)) |ptr| {
                lhs = ptr.data.sub_type.*;
            }
            if (lhs.is(.@"struct")) {
                const record = lhs.get_record().?;
                if (data.member.index + 1 == record.fields.len) {
                    if (!index.val.is_zero(p.comp)) {
                        try p.err_str(.old_style_flexible_struct, tok, try index.str(p));
                    }
                    return;
                }
            }
        }
    }
    const index_int = index.val.to_int(u64, p.comp) orelse std.math.max_int(u64);
    if (index.ty.is_unsigned_int(p.comp)) {
        if (index_int >= array_len) {
            try p.err_str(.array_after, tok, try index.str(p));
        }
    } else {
        if (index.val.compare(.lt, Value.zero, p.comp)) {
            try p.err_str(.array_before, tok, try index.str(p));
        } else if (index_int >= array_len) {
            try p.err_str(.array_after, tok, try index.str(p));
        }
    }
}

/// primary_expr
///  : IDENTIFIER
///  | keyword_true
///  | keyword_false
///  | keyword_nullptr
///  | INTEGER_LITERAL
///  | FLOAT_LITERAL
///  | IMAGINARY_LITERAL
///  | CHAR_LITERAL
///  | STRING_LITERAL
///  | '(' expr ')'
///  | generic_selection
fn primary_expr(p: *Parser) Error!Result {
    if (p.eat_token(.l_paren)) |l_paren| {
        var e = try p.expr();
        try e.expect(p);
        try p.expect_closing(l_paren, .r_paren);
        try e.un(p, .paren_expr);
        return e;
    }
    switch (p.tok_ids[p.tok_i]) {
        .identifier, .extended_identifier => {
            const name_tok = try p.expect_identifier();
            const name = p.tok_slice(name_tok);
            const interned_name = try StrInt.intern(p.comp, name);
            if (p.syms.find_symbol(interned_name)) |sym| {
                try p.check_deprecated_unavailable(sym.ty, name_tok, sym.tok);
                if (sym.kind == .constexpr) {
                    return Result{
                        .val = sym.val,
                        .ty = sym.ty,
                        .node = try p.add_node(.{
                            .tag = .decl_ref_expr,
                            .ty = sym.ty,
                            .data = .{ .decl_ref = name_tok },
                        }),
                    };
                }
                if (sym.val.is(.int, p.comp)) {
                    switch (p.const_decl_folding) {
                        .gnu_folding_extension => try p.err_tok(.const_decl_folded, name_tok),
                        .gnu_vla_folding_extension => try p.err_tok(.const_decl_folded_vla, name_tok),
                        else => {},
                    }
                }
                return Result{
                    .val = if (p.const_decl_folding == .no_const_decl_folding and sym.kind != .enumeration) Value{} else sym.val,
                    .ty = sym.ty,
                    .node = try p.add_node(.{
                        .tag = if (sym.kind == .enumeration) .enumeration_ref else .decl_ref_expr,
                        .ty = sym.ty,
                        .data = .{ .decl_ref = name_tok },
                    }),
                };
            }
            if (try p.comp.builtins.get_or_create(p.comp, name, p.arena)) |some| {
                for (p.tok_ids[p.tok_i..]) |id| switch (id) {
                    .r_paren => {}, // closing grouped expr
                    .l_paren => break, // beginning of a call
                    else => {
                        try p.err_tok(.builtin_must_be_called, name_tok);
                        return error.ParsingFailed;
                    },
                };
                if (some.builtin.properties.header != .none) {
                    try p.err_str(.implicit_builtin, name_tok, name);
                    try p.err_extra(.implicit_builtin_header_note, name_tok, .{ .builtin_with_header = .{
                        .builtin = some.builtin.tag,
                        .header = some.builtin.properties.header,
                    } });
                }

                return Result{
                    .ty = some.ty,
                    .node = try p.add_node(.{
                        .tag = .builtin_call_expr_one,
                        .ty = some.ty,
                        .data = .{ .decl = .{ .name = name_tok, .node = .none } },
                    }),
                };
            }
            if (p.tok_ids[p.tok_i] == .l_paren and !p.comp.langopts.standard.at_least(.c23)) {
                // allow implicitly declaring functions before C99 like `puts("foo")`
                if (mem.starts_with(u8, name, "__builtin_"))
                    try p.err_str(.unknown_builtin, name_tok, name)
                else
                    try p.err_str(.implicit_func_decl, name_tok, name);

                const func_ty = try p.arena.create(Type.Func);
                func_ty.* = .{ .return_type = .{ .specifier = .int }, .params = &.{} };
                const ty: Type = .{ .specifier = .old_style_func, .data = .{ .func = func_ty } };
                const node = try p.add_node(.{
                    .ty = ty,
                    .tag = .fn_proto,
                    .data = .{ .decl = .{ .name = name_tok } },
                });

                try p.decl_buf.append(node);
                try p.syms.declare_symbol(p, interned_name, ty, name_tok, node);

                return Result{
                    .ty = ty,
                    .node = try p.add_node(.{
                        .tag = .decl_ref_expr,
                        .ty = ty,
                        .data = .{ .decl_ref = name_tok },
                    }),
                };
            }
            try p.err_str(.undeclared_identifier, name_tok, p.tok_slice(name_tok));
            return error.ParsingFailed;
        },
        .keyword_true, .keyword_false => |id| {
            p.tok_i += 1;
            const res = Result{
                .val = Value.from_bool(id == .keyword_true),
                .ty = .{ .specifier = .bool },
                .node = try p.add_node(.{ .tag = .bool_literal, .ty = .{ .specifier = .bool }, .data = undefined }),
            };
            std.debug.assert(!p.in_macro); // Should have been replaced with .one / .zero
            try p.value_map.put(res.node, res.val);
            return res;
        },
        .keyword_nullptr => {
            defer p.tok_i += 1;
            try p.err_str(.pre_c23_compat, p.tok_i, "'nullptr'");
            return Result{
                .val = Value.null,
                .ty = .{ .specifier = .nullptr_t },
                .node = try p.add_node(.{
                    .tag = .nullptr_literal,
                    .ty = .{ .specifier = .nullptr_t },
                    .data = undefined,
                }),
            };
        },
        .macro_func, .macro_function => {
            defer p.tok_i += 1;
            var ty: Type = undefined;
            var tok = p.tok_i;
            if (p.func.ident) |some| {
                ty = some.ty;
                tok = p.nodes.items(.data)[@int_from_enum(some.node)].decl.name;
            } else if (p.func.ty) |_| {
                const strings_top = p.strings.items.len;
                defer p.strings.items.len = strings_top;

                try p.strings.append_slice(p.tok_slice(p.func.name));
                try p.strings.append(0);
                const predef = try p.make_predefined_identifier(strings_top);
                ty = predef.ty;
                p.func.ident = predef;
            } else {
                const strings_top = p.strings.items.len;
                defer p.strings.items.len = strings_top;

                try p.strings.append(0);
                const predef = try p.make_predefined_identifier(strings_top);
                ty = predef.ty;
                p.func.ident = predef;
                try p.decl_buf.append(predef.node);
            }
            if (p.func.ty == null) try p.err(.predefined_top_level);
            return Result{
                .ty = ty,
                .node = try p.add_node(.{
                    .tag = .decl_ref_expr,
                    .ty = ty,
                    .data = .{ .decl_ref = tok },
                }),
            };
        },
        .macro_pretty_func => {
            defer p.tok_i += 1;
            var ty: Type = undefined;
            if (p.func.pretty_ident) |some| {
                ty = some.ty;
            } else if (p.func.ty) |func_ty| {
                const strings_top = p.strings.items.len;
                defer p.strings.items.len = strings_top;

                const mapper = p.comp.string_interner.get_slow_type_mapper();
                try Type.print_named(func_ty, p.tok_slice(p.func.name), mapper, p.comp.langopts, p.strings.writer());
                try p.strings.append(0);
                const predef = try p.make_predefined_identifier(strings_top);
                ty = predef.ty;
                p.func.pretty_ident = predef;
            } else {
                const strings_top = p.strings.items.len;
                defer p.strings.items.len = strings_top;

                try p.strings.append_slice("top level\x00");
                const predef = try p.make_predefined_identifier(strings_top);
                ty = predef.ty;
                p.func.pretty_ident = predef;
                try p.decl_buf.append(predef.node);
            }
            if (p.func.ty == null) try p.err(.predefined_top_level);
            return Result{
                .ty = ty,
                .node = try p.add_node(.{
                    .tag = .decl_ref_expr,
                    .ty = ty,
                    .data = .{ .decl_ref = p.tok_i },
                }),
            };
        },
        .string_literal,
        .string_literal_utf_16,
        .string_literal_utf_8,
        .string_literal_utf_32,
        .string_literal_wide,
        .unterminated_string_literal,
        => return p.string_literal(),
        .char_literal,
        .char_literal_utf_8,
        .char_literal_utf_16,
        .char_literal_utf_32,
        .char_literal_wide,
        .empty_char_literal,
        .unterminated_char_literal,
        => return p.char_literal(),
        .zero => {
            p.tok_i += 1;
            var res: Result = .{ .val = Value.zero, .ty = if (p.in_macro) p.comp.types.intmax else Type.int };
            res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
            if (!p.in_macro) try p.value_map.put(res.node, res.val);
            return res;
        },
        .one => {
            p.tok_i += 1;
            var res: Result = .{ .val = Value.one, .ty = if (p.in_macro) p.comp.types.intmax else Type.int };
            res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
            if (!p.in_macro) try p.value_map.put(res.node, res.val);
            return res;
        },
        .pp_num => return p.pp_num(),
        .embed_byte => {
            assert(!p.in_macro);
            const loc = p.pp.tokens.items(.loc)[p.tok_i];
            p.tok_i += 1;
            const buf = p.comp.get_source(.generated).buf[loc.byte_offset..];
            var byte: u8 = buf[0] - '0';
            for (buf[1..]) |c| {
                if (!std.ascii.is_digit(c)) break;
                byte *= 10;
                byte += c - '0';
            }
            var res: Result = .{ .val = try Value.int(byte, p.comp) };
            res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
            try p.value_map.put(res.node, res.val);
            return res;
        },
        .keyword_generic => return p.generic_selection(),
        else => return Result{},
    }
}

fn make_predefined_identifier(p: *Parser, strings_top: usize) !Result {
    const end: u32 = @int_cast(p.strings.items.len);
    const elem_ty = .{ .specifier = .char, .qual = .{ .@"const" = true } };
    const arr_ty = try p.arena.create(Type.Array);
    arr_ty.* = .{ .elem = elem_ty, .len = end - strings_top };
    const ty: Type = .{ .specifier = .array, .data = .{ .array = arr_ty } };

    const slice = p.strings.items[strings_top..];
    const val = try Value.intern(p.comp, .{ .bytes = slice });

    const str_lit = try p.add_node(.{ .tag = .string_literal_expr, .ty = ty, .data = undefined });
    if (!p.in_macro) try p.value_map.put(str_lit, val);

    return Result{ .ty = ty, .node = try p.add_node(.{
        .tag = .implicit_static_var,
        .ty = ty,
        .data = .{ .decl = .{ .name = p.tok_i, .node = str_lit } },
    }) };
}

fn string_literal(p: *Parser) Error!Result {
    var string_end = p.tok_i;
    var string_kind: text_literal.Kind = .char;
    while (text_literal.Kind.classify(p.tok_ids[string_end], .string_literal)) |next| : (string_end += 1) {
        string_kind = string_kind.concat(next) catch {
            try p.err_tok(.unsupported_str_cat, string_end);
            while (p.tok_ids[p.tok_i].is_string_literal()) : (p.tok_i += 1) {}
            return error.ParsingFailed;
        };
        if (string_kind == .unterminated) {
            try p.err_tok(.unterminated_string_literal_error, string_end);
            p.tok_i = string_end + 1;
            return error.ParsingFailed;
        }
    }
    assert(string_end > p.tok_i);

    const char_width = string_kind.char_unit_size(p.comp);

    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    while (p.tok_i < string_end) : (p.tok_i += 1) {
        const this_kind = text_literal.Kind.classify(p.tok_ids[p.tok_i], .string_literal).?;
        const slice = this_kind.content_slice(p.tok_slice(p.tok_i));
        var char_literal_parser = text_literal.Parser.init(slice, this_kind, 0x10ffff, p.comp);

        try p.strings.ensure_unused_capacity((slice.len + 1) * @int_from_enum(char_width)); // +1 for null terminator
        while (char_literal_parser.next()) |item| switch (item) {
            .value => |v| {
                switch (char_width) {
                    .@"1" => p.strings.append_assume_capacity(@int_cast(v)),
                    .@"2" => {
                        const word: u16 = @int_cast(v);
                        p.strings.append_slice_assume_capacity(mem.as_bytes(&word));
                    },
                    .@"4" => p.strings.append_slice_assume_capacity(mem.as_bytes(&v)),
                }
            },
            .codepoint => |c| {
                switch (char_width) {
                    .@"1" => {
                        var buf: [4]u8 = undefined;
                        const written = std.unicode.utf8_encode(c, &buf) catch unreachable;
                        const encoded = buf[0..written];
                        p.strings.append_slice_assume_capacity(encoded);
                    },
                    .@"2" => {
                        var utf16_buf: [2]u16 = undefined;
                        var utf8_buf: [4]u8 = undefined;
                        const utf8_written = std.unicode.utf8_encode(c, &utf8_buf) catch unreachable;
                        const utf16_written = std.unicode.utf8_to_utf16_le(&utf16_buf, utf8_buf[0..utf8_written]) catch unreachable;
                        const bytes = std.mem.slice_as_bytes(utf16_buf[0..utf16_written]);
                        p.strings.append_slice_assume_capacity(bytes);
                    },
                    .@"4" => {
                        const val: u32 = c;
                        p.strings.append_slice_assume_capacity(mem.as_bytes(&val));
                    },
                }
            },
            .improperly_encoded => |bytes| p.strings.append_slice_assume_capacity(bytes),
            .utf8_text => |view| {
                switch (char_width) {
                    .@"1" => p.strings.append_slice_assume_capacity(view.bytes),
                    .@"2" => {
                        const capacity_slice: []align(@alignOf(u16)) u8 = @align_cast(p.strings.unused_capacity_slice());
                        const dest_len = std.mem.align_backward(usize, capacity_slice.len, 2);
                        const dest = std.mem.bytes_as_slice(u16, capacity_slice[0..dest_len]);
                        const words_written = std.unicode.utf8_to_utf16_le(dest, view.bytes) catch unreachable;
                        p.strings.resize(p.strings.items.len + words_written * 2) catch unreachable;
                    },
                    .@"4" => {
                        var it = view.iterator();
                        while (it.next_codepoint()) |codepoint| {
                            const val: u32 = codepoint;
                            p.strings.append_slice_assume_capacity(mem.as_bytes(&val));
                        }
                    },
                }
            },
        };
        for (char_literal_parser.errors()) |item| {
            try p.err_extra(item.tag, p.tok_i, item.extra);
        }
    }
    p.strings.append_ntimes_assume_capacity(0, @int_from_enum(char_width));
    const slice = p.strings.items[strings_top..];

    // TODO this won't do anything if there is a cache hit
    const interned_align = mem.align_forward(
        usize,
        p.comp.interner.strings.items.len,
        string_kind.internal_storage_alignment(p.comp),
    );
    try p.comp.interner.strings.resize(p.gpa, interned_align);

    const val = try Value.intern(p.comp, .{ .bytes = slice });

    const arr_ty = try p.arena.create(Type.Array);
    arr_ty.* = .{ .elem = string_kind.element_type(p.comp), .len = @div_exact(slice.len, @int_from_enum(char_width)) };
    var res: Result = .{
        .ty = .{
            .specifier = .array,
            .data = .{ .array = arr_ty },
        },
        .val = val,
    };
    res.node = try p.add_node(.{ .tag = .string_literal_expr, .ty = res.ty, .data = undefined });
    if (!p.in_macro) try p.value_map.put(res.node, res.val);
    return res;
}

fn char_literal(p: *Parser) Error!Result {
    defer p.tok_i += 1;
    const tok_id = p.tok_ids[p.tok_i];
    const char_kind = text_literal.Kind.classify(tok_id, .char_literal) orelse {
        if (tok_id == .empty_char_literal) {
            try p.err(.empty_char_literal_error);
        } else if (tok_id == .unterminated_char_literal) {
            try p.err(.unterminated_char_literal_error);
        } else unreachable;
        return .{
            .ty = Type.int,
            .val = Value.zero,
            .node = try p.add_node(.{ .tag = .char_literal, .ty = Type.int, .data = undefined }),
        };
    };
    if (char_kind == .utf_8) try p.err(.u8_char_lit);
    var val: u32 = 0;

    const slice = char_kind.content_slice(p.tok_slice(p.tok_i));

    var is_multichar = false;
    if (slice.len == 1 and std.ascii.is_ascii(slice[0])) {
        // fast path: single unescaped ASCII char
        val = slice[0];
    } else {
        const max_codepoint = char_kind.max_codepoint(p.comp);
        var char_literal_parser = text_literal.Parser.init(slice, char_kind, max_codepoint, p.comp);

        const max_chars_expected = 4;
        var stack_fallback = std.heap.stack_fallback(max_chars_expected * @size_of(u32), p.comp.gpa);
        var chars = std.ArrayList(u32).init_capacity(stack_fallback.get(), max_chars_expected) catch unreachable; // stack allocation already succeeded
        defer chars.deinit();

        while (char_literal_parser.next()) |item| switch (item) {
            .value => |v| try chars.append(v),
            .codepoint => |c| try chars.append(c),
            .improperly_encoded => |s| {
                try chars.ensure_unused_capacity(s.len);
                for (s) |c| chars.append_assume_capacity(c);
            },
            .utf8_text => |view| {
                var it = view.iterator();
                var max_codepoint_seen: u21 = 0;
                try chars.ensure_unused_capacity(view.bytes.len);
                while (it.next_codepoint()) |c| {
                    max_codepoint_seen = @max(max_codepoint_seen, c);
                    chars.append_assume_capacity(c);
                }
                if (max_codepoint_seen > max_codepoint) {
                    char_literal_parser.err(.char_too_large, .{ .none = {} });
                }
            },
        };

        is_multichar = chars.items.len > 1;
        if (is_multichar) {
            if (char_kind == .char and chars.items.len == 4) {
                char_literal_parser.warn(.four_char_char_literal, .{ .none = {} });
            } else if (char_kind == .char) {
                char_literal_parser.warn(.multichar_literal_warning, .{ .none = {} });
            } else {
                const kind = switch (char_kind) {
                    .wide => "wide",
                    .utf_8, .utf_16, .utf_32 => "Unicode",
                    else => unreachable,
                };
                char_literal_parser.err(.invalid_multichar_literal, .{ .str = kind });
            }
        }

        var multichar_overflow = false;
        if (char_kind == .char and is_multichar) {
            for (chars.items) |item| {
                val, const overflowed = @shl_with_overflow(val, 8);
                multichar_overflow = multichar_overflow or overflowed != 0;
                val += @as(u8, @truncate(item));
            }
        } else if (chars.items.len > 0) {
            val = chars.items[chars.items.len - 1];
        }

        if (multichar_overflow) {
            char_literal_parser.err(.char_lit_too_wide, .{ .none = {} });
        }

        for (char_literal_parser.errors()) |item| {
            try p.err_extra(item.tag, p.tok_i, item.extra);
        }
    }

    const ty = char_kind.char_literal_type(p.comp);
    // This is the type the literal will have if we're in a macro; macros always operate on intmax_t/uintmax_t values
    const macro_ty = if (ty.is_unsigned_int(p.comp) or (char_kind == .char and p.comp.get_char_signedness() == .unsigned))
        p.comp.types.intmax.make_integer_unsigned()
    else
        p.comp.types.intmax;

    var value = try Value.int(val, p.comp);
    // C99 6.4.4.4.10
    // > If an integer character constant contains a single character or escape sequence,
    // > its value is the one that results when an object with type char whose value is
    // > that of the single character or escape sequence is converted to type int.
    // This conversion only matters if `char` is signed and has a high-order bit of `1`
    if (char_kind == .char and !is_multichar and val > 0x7F and p.comp.get_char_signedness() == .signed) {
        try value.int_cast(.{ .specifier = .char }, p.comp);
    }

    const res = Result{
        .ty = if (p.in_macro) macro_ty else ty,
        .val = value,
        .node = try p.add_node(.{ .tag = .char_literal, .ty = ty, .data = undefined }),
    };
    if (!p.in_macro) try p.value_map.put(res.node, res.val);
    return res;
}

fn parse_float(p: *Parser, buf: []const u8, suffix: NumberSuffix) !Result {
    const ty = Type{ .specifier = switch (suffix) {
        .None, .I => .double,
        .F, .IF => .float,
        .F16 => .float16,
        .L, .IL => .long_double,
        .W, .IW => .float80,
        .Q, .IQ, .F128, .IF128 => .float128,
        else => unreachable,
    } };
    const val = try Value.intern(p.comp, key: {
        try p.strings.ensure_unused_capacity(buf.len);

        const strings_top = p.strings.items.len;
        defer p.strings.items.len = strings_top;
        for (buf) |c| {
            if (c != '\'') p.strings.append_assume_capacity(c);
        }

        const float = std.fmt.parse_float(f128, p.strings.items[strings_top..]) catch unreachable;
        const bits = ty.bit_sizeof(p.comp).?;
        break :key switch (bits) {
            16 => .{ .float = .{ .f16 = @float_cast(float) } },
            32 => .{ .float = .{ .f32 = @float_cast(float) } },
            64 => .{ .float = .{ .f64 = @float_cast(float) } },
            80 => .{ .float = .{ .f80 = @float_cast(float) } },
            128 => .{ .float = .{ .f128 = @float_cast(float) } },
            else => unreachable,
        };
    });
    var res = Result{
        .ty = ty,
        .node = try p.add_node(.{ .tag = .float_literal, .ty = ty, .data = undefined }),
        .val = val,
    };
    if (suffix.is_imaginary()) {
        try p.err(.gnu_imaginary_constant);
        res.ty = .{ .specifier = switch (suffix) {
            .I => .complex_double,
            .IF => .complex_float,
            .IL => .complex_long_double,
            .IW => .complex_float80,
            .IQ, .IF128 => .complex_float128,
            else => unreachable,
        } };
        res.val = .{}; // TODO add complex values
        try res.un(p, .imaginary_literal);
    }
    return res;
}

fn get_integer_part(p: *Parser, buf: []const u8, prefix: NumberPrefix, tok_i: TokenIndex) ![]const u8 {
    if (buf[0] == '.') return "";

    if (!prefix.digit_allowed(buf[0])) {
        switch (prefix) {
            .binary => try p.err_extra(.invalid_binary_digit, tok_i, .{ .ascii = @int_cast(buf[0]) }),
            .octal => try p.err_extra(.invalid_octal_digit, tok_i, .{ .ascii = @int_cast(buf[0]) }),
            .hex => try p.err_str(.invalid_int_suffix, tok_i, buf),
            .decimal => unreachable,
        }
        return error.ParsingFailed;
    }

    for (buf, 0..) |c, idx| {
        if (idx == 0) continue;
        switch (c) {
            '.' => return buf[0..idx],
            'p', 'P' => return if (prefix == .hex) buf[0..idx] else {
                try p.err_str(.invalid_int_suffix, tok_i, buf[idx..]);
                return error.ParsingFailed;
            },
            'e', 'E' => {
                switch (prefix) {
                    .hex => continue,
                    .decimal => return buf[0..idx],
                    .binary => try p.err_extra(.invalid_binary_digit, tok_i, .{ .ascii = @int_cast(c) }),
                    .octal => try p.err_extra(.invalid_octal_digit, tok_i, .{ .ascii = @int_cast(c) }),
                }
                return error.ParsingFailed;
            },
            '0'...'9', 'a'...'d', 'A'...'D', 'f', 'F' => {
                if (!prefix.digit_allowed(c)) {
                    switch (prefix) {
                        .binary => try p.err_extra(.invalid_binary_digit, tok_i, .{ .ascii = @int_cast(c) }),
                        .octal => try p.err_extra(.invalid_octal_digit, tok_i, .{ .ascii = @int_cast(c) }),
                        .decimal, .hex => try p.err_str(.invalid_int_suffix, tok_i, buf[idx..]),
                    }
                    return error.ParsingFailed;
                }
            },
            '\'' => {},
            else => return buf[0..idx],
        }
    }
    return buf;
}

fn fixed_size_int(p: *Parser, base: u8, buf: []const u8, suffix: NumberSuffix, tok_i: TokenIndex) !Result {
    var val: u64 = 0;
    var overflow = false;
    for (buf) |c| {
        const digit: u64 = switch (c) {
            '0'...'9' => c - '0',
            'A'...'Z' => c - 'A' + 10,
            'a'...'z' => c - 'a' + 10,
            '\'' => continue,
            else => unreachable,
        };

        if (val != 0) {
            const product, const overflowed = @mulWithOverflow(val, base);
            if (overflowed != 0) {
                overflow = true;
            }
            val = product;
        }
        const sum, const overflowed = @add_with_overflow(val, digit);
        if (overflowed != 0) overflow = true;
        val = sum;
    }
    var res: Result = .{ .val = try Value.int(val, p.comp) };
    if (overflow) {
        try p.err_tok(.int_literal_too_big, tok_i);
        res.ty = .{ .specifier = .ulong_long };
        res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
        if (!p.in_macro) try p.value_map.put(res.node, res.val);
        return res;
    }
    if (suffix.is_signed_integer()) {
        if (val > p.comp.types.intmax.max_int(p.comp)) {
            try p.err_tok(.implicitly_unsigned_literal, tok_i);
        }
    }

    const signed_specs = .{ .int, .long, .long_long };
    const unsigned_specs = .{ .uint, .ulong, .ulong_long };
    const signed_oct_hex_specs = .{ .int, .uint, .long, .ulong, .long_long, .ulong_long };
    const specs: []const Type.Specifier = if (suffix.signedness() == .unsigned)
        &unsigned_specs
    else if (base == 10)
        &signed_specs
    else
        &signed_oct_hex_specs;

    const suffix_ty: Type = .{ .specifier = switch (suffix) {
        .None, .I => .int,
        .U, .IU => .uint,
        .UL, .IUL => .ulong,
        .ULL, .IULL => .ulong_long,
        .L, .IL => .long,
        .LL, .ILL => .long_long,
        else => unreachable,
    } };

    for (specs) |spec| {
        res.ty = Type{ .specifier = spec };
        if (res.ty.compare_integer_ranks(suffix_ty, p.comp).compare(.lt)) continue;
        const max_int = res.ty.max_int(p.comp);
        if (val <= max_int) break;
    } else {
        res.ty = .{ .specifier = .ulong_long };
    }

    res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
    if (!p.in_macro) try p.value_map.put(res.node, res.val);
    return res;
}

fn parse_int(p: *Parser, prefix: NumberPrefix, buf: []const u8, suffix: NumberSuffix, tok_i: TokenIndex) !Result {
    if (prefix == .binary) {
        try p.err_tok(.binary_integer_literal, tok_i);
    }
    const base = @int_from_enum(prefix);
    var res = if (suffix.is_bit_int())
        try p.bit_int(base, buf, suffix, tok_i)
    else
        try p.fixed_size_int(base, buf, suffix, tok_i);

    if (suffix.is_imaginary()) {
        try p.err_tok(.gnu_imaginary_constant, tok_i);
        res.ty = res.ty.make_complex();
        res.val = .{};
        try res.un(p, .imaginary_literal);
    }
    return res;
}

fn bit_int(p: *Parser, base: u8, buf: []const u8, suffix: NumberSuffix, tok_i: TokenIndex) Error!Result {
    try p.err_str(.pre_c23_compat, tok_i, "'_BitInt' suffix for literals");
    try p.err_tok(.bitint_suffix, tok_i);

    var managed = try big.int.Managed.init(p.gpa);
    defer managed.deinit();

    {
        try p.strings.ensure_unused_capacity(buf.len);

        const strings_top = p.strings.items.len;
        defer p.strings.items.len = strings_top;
        for (buf) |c| {
            if (c != '\'') p.strings.append_assume_capacity(c);
        }

        managed.set_string(base, p.strings.items[strings_top..]) catch |e| switch (e) {
            error.InvalidBase => unreachable, // `base` is one of 2, 8, 10, 16
            error.InvalidCharacter => unreachable, // digits validated by Tokenizer
            else => |er| return er,
        };
    }
    const c = managed.to_const();
    const bits_needed: std.math.IntFittingRange(0, Compilation.bit_int_max_bits) = blk: {
        // Literal `0` requires at least 1 bit
        const count = @max(1, c.bit_count_twos_comp());
        // The wb suffix results in a _BitInt that includes space for the sign bit even if the
        // value of the constant is positive or was specified in hexadecimal or octal notation.
        const sign_bits = @int_from_bool(suffix.is_signed_integer());
        const bits_needed = count + sign_bits;
        if (bits_needed > Compilation.bit_int_max_bits) {
            const specifier: Type.Builder.Specifier = switch (suffix) {
                .WB => .{ .bit_int = 0 },
                .UWB => .{ .ubit_int = 0 },
                .IWB => .{ .complex_bit_int = 0 },
                .IUWB => .{ .complex_ubit_int = 0 },
                else => unreachable,
            };
            try p.err_str(.bit_int_too_big, tok_i, specifier.str(p.comp.langopts).?);
            return error.ParsingFailed;
        }
        break :blk @int_cast(bits_needed);
    };

    var res: Result = .{
        .val = try Value.intern(p.comp, .{ .int = .{ .big_int = c } }),
        .ty = .{
            .specifier = .bit_int,
            .data = .{ .int = .{ .bits = bits_needed, .signedness = suffix.signedness() } },
        },
    };
    res.node = try p.add_node(.{ .tag = .int_literal, .ty = res.ty, .data = undefined });
    if (!p.in_macro) try p.value_map.put(res.node, res.val);
    return res;
}

fn get_frac_part(p: *Parser, buf: []const u8, prefix: NumberPrefix, tok_i: TokenIndex) ![]const u8 {
    if (buf.len == 0 or buf[0] != '.') return "";
    assert(prefix != .octal);
    if (prefix == .binary) {
        try p.err_str(.invalid_int_suffix, tok_i, buf);
        return error.ParsingFailed;
    }
    for (buf, 0..) |c, idx| {
        if (idx == 0) continue;
        if (c == '\'') continue;
        if (!prefix.digit_allowed(c)) return buf[0..idx];
    }
    return buf;
}

fn get_exponent(p: *Parser, buf: []const u8, prefix: NumberPrefix, tok_i: TokenIndex) ![]const u8 {
    if (buf.len == 0) return "";

    switch (buf[0]) {
        'e', 'E' => assert(prefix == .decimal),
        'p', 'P' => if (prefix != .hex) {
            try p.err_str(.invalid_float_suffix, tok_i, buf);
            return error.ParsingFailed;
        },
        else => return "",
    }
    const end = for (buf, 0..) |c, idx| {
        if (idx == 0) continue;
        if (idx == 1 and (c == '+' or c == '-')) continue;
        switch (c) {
            '0'...'9' => {},
            '\'' => continue,
            else => break idx,
        }
    } else buf.len;
    const exponent = buf[0..end];
    if (std.mem.index_of_any(u8, exponent, "0123456789") == null) {
        try p.err_tok(.exponent_has_no_digits, tok_i);
        return error.ParsingFailed;
    }
    return exponent;
}

/// Using an explicit `tok_i` parameter instead of `p.tok_i` makes it easier
/// to parse numbers in pragma handlers.
pub fn parse_number_token(p: *Parser, tok_i: TokenIndex) !Result {
    const buf = p.tok_slice(tok_i);
    const prefix = NumberPrefix.from_string(buf);
    const after_prefix = buf[prefix.string_len()..];

    const int_part = try p.get_integer_part(after_prefix, prefix, tok_i);

    const after_int = after_prefix[int_part.len..];

    const frac = try p.get_frac_part(after_int, prefix, tok_i);
    const after_frac = after_int[frac.len..];

    const exponent = try p.get_exponent(after_frac, prefix, tok_i);
    const suffix_str = after_frac[exponent.len..];
    const is_float = (exponent.len > 0 or frac.len > 0);
    const suffix = NumberSuffix.from_string(suffix_str, if (is_float) .float else .int) orelse {
        if (is_float) {
            try p.err_str(.invalid_float_suffix, tok_i, suffix_str);
        } else {
            try p.err_str(.invalid_int_suffix, tok_i, suffix_str);
        }
        return error.ParsingFailed;
    };

    if (is_float) {
        assert(prefix == .hex or prefix == .decimal);
        if (prefix == .hex and exponent.len == 0) {
            try p.err_tok(.hex_floating_constant_requires_exponent, tok_i);
            return error.ParsingFailed;
        }
        const number = buf[0 .. buf.len - suffix_str.len];
        return p.parse_float(number, suffix);
    } else {
        return p.parse_int(prefix, int_part, suffix, tok_i);
    }
}

fn pp_num(p: *Parser) Error!Result {
    defer p.tok_i += 1;
    var res = try p.parse_number_token(p.tok_i);
    if (p.in_macro) {
        if (res.ty.is_float() or !res.ty.is_real()) {
            try p.err_tok(.float_literal_in_pp_expr, p.tok_i);
            return error.ParsingFailed;
        }
        res.ty = if (res.ty.is_unsigned_int(p.comp)) p.comp.types.intmax.make_integer_unsigned() else p.comp.types.intmax;
    } else if (res.val.opt_ref != .none) {
        // TODO add complex values
        try p.value_map.put(res.node, res.val);
    }
    return res;
}

/// Run a parser function but do not evaluate the result
fn parse_no_eval(p: *Parser, comptime func: fn (*Parser) Error!Result) Error!Result {
    const no_eval = p.no_eval;
    defer p.no_eval = no_eval;
    p.no_eval = true;
    const parsed = try func(p);
    try parsed.expect(p);
    return parsed;
}

/// generic_selection : keyword_generic '(' assign_expr ',' genericAssoc (',' genericAssoc)* ')'
/// genericAssoc
///  : type_name ':' assign_expr
///  | keyword_default ':' assign_expr
fn generic_selection(p: *Parser) Error!Result {
    p.tok_i += 1;
    const l_paren = try p.expect_token(.l_paren);
    const controlling_tok = p.tok_i;
    const controlling = try p.parse_no_eval(assign_expr);
    _ = try p.expect_token(.comma);
    var controlling_ty = controlling.ty;
    if (controlling_ty.is_array()) controlling_ty.decay_array();

    const list_buf_top = p.list_buf.items.len;
    defer p.list_buf.items.len = list_buf_top;
    try p.list_buf.append(controlling.node);

    // Use decl_buf to store the token indexes of previous cases
    const decl_buf_top = p.decl_buf.items.len;
    defer p.decl_buf.items.len = decl_buf_top;

    var default_tok: ?TokenIndex = null;
    var default: Result = undefined;
    var chosen_tok: TokenIndex = undefined;
    var chosen: Result = .{};
    while (true) {
        const start = p.tok_i;
        if (try p.type_name()) |ty| blk: {
            if (ty.is_array()) {
                try p.err_tok(.generic_array_type, start);
            } else if (ty.is_func()) {
                try p.err_tok(.generic_func_type, start);
            } else if (ty.any_qual()) {
                try p.err_tok(.generic_qual_type, start);
            }
            _ = try p.expect_token(.colon);
            const node = try p.assign_expr();
            try node.expect(p);

            if (ty.eql(controlling_ty, p.comp, false)) {
                if (chosen.node == .none) {
                    chosen = node;
                    chosen_tok = start;
                    break :blk;
                }
                try p.err_str(.generic_duplicate, start, try p.type_str(ty));
                try p.err_str(.generic_duplicate_here, chosen_tok, try p.type_str(ty));
            }
            for (p.list_buf.items[list_buf_top + 1 ..], p.decl_buf.items[decl_buf_top..]) |item, prev_tok| {
                const prev_ty = p.nodes.items(.ty)[@int_from_enum(item)];
                if (prev_ty.eql(ty, p.comp, true)) {
                    try p.err_str(.generic_duplicate, start, try p.type_str(ty));
                    try p.err_str(.generic_duplicate_here, @int_from_enum(prev_tok), try p.type_str(ty));
                }
            }
            try p.list_buf.append(try p.add_node(.{
                .tag = .generic_association_expr,
                .ty = ty,
                .data = .{ .un = node.node },
            }));
            try p.decl_buf.append(@enumFromInt(start));
        } else if (p.eat_token(.keyword_default)) |tok| {
            if (default_tok) |prev| {
                try p.err_tok(.generic_duplicate_default, tok);
                try p.err_tok(.previous_case, prev);
            }
            default_tok = tok;
            _ = try p.expect_token(.colon);
            default = try p.assign_expr();
            try default.expect(p);
        } else {
            if (p.list_buf.items.len == list_buf_top + 1) {
                try p.err(.expected_type);
                return error.ParsingFailed;
            }
            break;
        }
        if (p.eat_token(.comma) == null) break;
    }
    try p.expect_closing(l_paren, .r_paren);

    if (chosen.node == .none) {
        if (default_tok != null) {
            try p.list_buf.insert(list_buf_top + 1, try p.add_node(.{
                .tag = .generic_default_expr,
                .data = .{ .un = default.node },
            }));
            chosen = default;
        } else {
            try p.err_str(.generic_no_match, controlling_tok, try p.type_str(controlling_ty));
            return error.ParsingFailed;
        }
    } else {
        try p.list_buf.insert(list_buf_top + 1, try p.add_node(.{
            .tag = .generic_association_expr,
            .data = .{ .un = chosen.node },
        }));
        if (default_tok != null) {
            try p.list_buf.append(try p.add_node(.{
                .tag = .generic_default_expr,
                .data = .{ .un = chosen.node },
            }));
        }
    }

    var generic_node: Tree.Node = .{
        .tag = .generic_expr_one,
        .ty = chosen.ty,
        .data = .{ .bin = .{ .lhs = controlling.node, .rhs = chosen.node } },
    };
    const associations = p.list_buf.items[list_buf_top..];
    if (associations.len > 2) { // associations[0] == controlling.node
        generic_node.tag = .generic_expr;
        generic_node.data = .{ .range = try p.add_list(associations) };
    }
    chosen.node = try p.add_node(generic_node);
    return chosen;
}
