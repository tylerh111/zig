const std = @import("std");
const mem = std.mem;
const ZigType = std.builtin.Type;
const CallingConvention = @import("../backend.zig").CallingConvention;
const Compilation = @import("Compilation.zig");
const Diagnostics = @import("Diagnostics.zig");
const Parser = @import("Parser.zig");
const Tree = @import("Tree.zig");
const NodeIndex = Tree.NodeIndex;
const TokenIndex = Tree.TokenIndex;
const Type = @import("Type.zig");
const Value = @import("Value.zig");

const Attribute = @This();

tag: Tag,
syntax: Syntax,
args: Arguments,

pub const Syntax = enum {
    c23,
    declspec,
    gnu,
    keyword,
};

pub const Kind = enum {
    c23,
    declspec,
    gnu,

    pub fn to_syntax(kind: Kind) Syntax {
        return switch (kind) {
            .c23 => .c23,
            .declspec => .declspec,
            .gnu => .gnu,
        };
    }
};

pub const ArgumentType = enum {
    string,
    identifier,
    int,
    alignment,
    float,
    expression,
    nullptr_t,

    pub fn to_string(self: ArgumentType) []const u8 {
        return switch (self) {
            .string => "a string",
            .identifier => "an identifier",
            .int, .alignment => "an integer constant",
            .nullptr_t => "nullptr",
            .float => "a floating point number",
            .expression => "an expression",
        };
    }
};

/// number of required arguments
pub fn required_arg_count(attr: Tag) u32 {
    switch (attr) {
        inline else => |tag| {
            comptime var needed = 0;
            comptime {
                const fields = std.meta.fields(@field(attributes, @tag_name(tag)));
                for (fields) |arg_field| {
                    if (!mem.eql(u8, arg_field.name, "__name_tok") and @typeInfo(arg_field.type) != .Optional) needed += 1;
                }
            }
            return needed;
        },
    }
}

/// maximum number of args that can be passed
pub fn max_arg_count(attr: Tag) u32 {
    switch (attr) {
        inline else => |tag| {
            comptime var max = 0;
            comptime {
                const fields = std.meta.fields(@field(attributes, @tag_name(tag)));
                for (fields) |arg_field| {
                    if (!mem.eql(u8, arg_field.name, "__name_tok")) max += 1;
                }
            }
            return max;
        },
    }
}

fn UnwrapOptional(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .Optional => |optional| optional.child,
        else => T,
    };
}

pub const Formatting = struct {
    /// The quote char (single or double) to use when printing identifiers/strings corresponding
    /// to the enum in the first field of the `attr`. Identifier enums use single quotes, string enums
    /// use double quotes
    fn quote_char(attr: Tag) []const u8 {
        switch (attr) {
            .calling_convention => unreachable,
            inline else => |tag| {
                const fields = std.meta.fields(@field(attributes, @tag_name(tag)));

                if (fields.len == 0) unreachable;
                const Unwrapped = UnwrapOptional(fields[0].type);
                if (@typeInfo(Unwrapped) != .Enum) unreachable;

                return if (Unwrapped.opts.enum_kind == .identifier) "'" else "\"";
            },
        }
    }

    /// returns a comma-separated string of quoted enum values, representing the valid
    /// choices for the string or identifier enum of the first field of the `attr`.
    pub fn choices(attr: Tag) []const u8 {
        switch (attr) {
            .calling_convention => unreachable,
            inline else => |tag| {
                const fields = std.meta.fields(@field(attributes, @tag_name(tag)));

                if (fields.len == 0) unreachable;
                const Unwrapped = UnwrapOptional(fields[0].type);
                if (@typeInfo(Unwrapped) != .Enum) unreachable;

                const enum_fields = @typeInfo(Unwrapped).Enum.fields;
                @setEvalBranchQuota(3000);
                const quote = comptime quote_char(@enumFromInt(@int_from_enum(tag)));
                comptime var values: []const u8 = quote ++ enum_fields[0].name ++ quote;
                inline for (enum_fields[1..]) |enum_field| {
                    values = values ++ ", ";
                    values = values ++ quote ++ enum_field.name ++ quote;
                }
                return values;
            },
        }
    }
};

/// Checks if the first argument (if it exists) is an identifier enum
pub fn wants_ident_enum(attr: Tag) bool {
    switch (attr) {
        .calling_convention => return false,
        inline else => |tag| {
            const fields = std.meta.fields(@field(attributes, @tag_name(tag)));

            if (fields.len == 0) return false;
            const Unwrapped = UnwrapOptional(fields[0].type);
            if (@typeInfo(Unwrapped) != .Enum) return false;

            return Unwrapped.opts.enum_kind == .identifier;
        },
    }
}

pub fn diagnose_ident(attr: Tag, arguments: *Arguments, ident: []const u8) ?Diagnostics.Message {
    switch (attr) {
        inline else => |tag| {
            const fields = std.meta.fields(@field(attributes, @tag_name(tag)));
            if (fields.len == 0) unreachable;
            const Unwrapped = UnwrapOptional(fields[0].type);
            if (@typeInfo(Unwrapped) != .Enum) unreachable;
            if (std.meta.string_to_enum(Unwrapped, normalize(ident))) |enum_val| {
                @field(@field(arguments, @tag_name(tag)), fields[0].name) = enum_val;
                return null;
            }
            return Diagnostics.Message{
                .tag = .unknown_attr_enum,
                .extra = .{ .attr_enum = .{ .tag = attr } },
            };
        },
    }
}

pub fn wants_alignment(attr: Tag, idx: usize) bool {
    switch (attr) {
        inline else => |tag| {
            const fields = std.meta.fields(@field(attributes, @tag_name(tag)));
            if (fields.len == 0) return false;

            return switch (idx) {
                inline 0...fields.len - 1 => |i| UnwrapOptional(fields[i].type) == Alignment,
                else => false,
            };
        },
    }
}

pub fn diagnose_alignment(attr: Tag, arguments: *Arguments, arg_idx: u32, res: Parser.Result, p: *Parser) !?Diagnostics.Message {
    switch (attr) {
        inline else => |tag| {
            const arg_fields = std.meta.fields(@field(attributes, @tag_name(tag)));
            if (arg_fields.len == 0) unreachable;

            switch (arg_idx) {
                inline 0...arg_fields.len - 1 => |arg_i| {
                    if (UnwrapOptional(arg_fields[arg_i].type) != Alignment) unreachable;

                    if (!res.val.is(.int, p.comp)) return Diagnostics.Message{ .tag = .alignas_unavailable };
                    if (res.val.compare(.lt, Value.zero, p.comp)) {
                        return Diagnostics.Message{ .tag = .negative_alignment, .extra = .{ .str = try res.str(p) } };
                    }
                    const requested = res.val.to_int(u29, p.comp) orelse {
                        return Diagnostics.Message{ .tag = .maximum_alignment, .extra = .{ .str = try res.str(p) } };
                    };
                    if (!std.mem.is_valid_align(requested)) return Diagnostics.Message{ .tag = .non_pow2_align };

                    @field(@field(arguments, @tag_name(tag)), arg_fields[arg_i].name) = Alignment{ .requested = requested };
                    return null;
                },
                else => unreachable,
            }
        },
    }
}

fn diagnose_field(
    comptime decl: ZigType.Declaration,
    comptime field: ZigType.StructField,
    comptime Wanted: type,
    arguments: *Arguments,
    res: Parser.Result,
    node: Tree.Node,
    p: *Parser,
) !?Diagnostics.Message {
    if (res.val.opt_ref == .none) {
        if (Wanted == Identifier and node.tag == .decl_ref_expr) {
            @field(@field(arguments, decl.name), field.name) = Identifier{ .tok = node.data.decl_ref };
            return null;
        }
        return invalid_arg_msg(Wanted, .expression);
    }
    const key = p.comp.interner.get(res.val.ref());
    switch (key) {
        .int => {
            if (@typeInfo(Wanted) == .Int) {
                @field(@field(arguments, decl.name), field.name) = res.val.to_int(Wanted, p.comp) orelse return .{
                    .tag = .attribute_int_out_of_range,
                    .extra = .{ .str = try res.str(p) },
                };
                return null;
            }
        },
        .bytes => |bytes| {
            if (Wanted == Value) {
                std.debug.assert(node.tag == .string_literal_expr);
                if (!node.ty.elem_type().is(.char) and !node.ty.elem_type().is(.uchar)) {
                    return .{
                        .tag = .attribute_requires_string,
                        .extra = .{ .str = decl.name },
                    };
                }
                @field(@field(arguments, decl.name), field.name) = try p.remove_null(res.val);
                return null;
            } else if (@typeInfo(Wanted) == .Enum and @hasDecl(Wanted, "opts") and Wanted.opts.enum_kind == .string) {
                const str = bytes[0 .. bytes.len - 1];
                if (std.meta.string_to_enum(Wanted, str)) |enum_val| {
                    @field(@field(arguments, decl.name), field.name) = enum_val;
                    return null;
                } else {
                    @setEvalBranchQuota(3000);
                    return .{
                        .tag = .unknown_attr_enum,
                        .extra = .{ .attr_enum = .{ .tag = std.meta.string_to_enum(Tag, decl.name).? } },
                    };
                }
            }
        },
        else => {},
    }
    return invalid_arg_msg(Wanted, switch (key) {
        .int => .int,
        .bytes => .string,
        .float => .float,
        .null => .nullptr_t,
        else => unreachable,
    });
}

fn invalid_arg_msg(comptime Expected: type, actual: ArgumentType) Diagnostics.Message {
    return .{
        .tag = .attribute_arg_invalid,
        .extra = .{ .attr_arg_type = .{ .expected = switch (Expected) {
            Value => .string,
            Identifier => .identifier,
            u32 => .int,
            Alignment => .alignment,
            CallingConvention => .identifier,
            else => switch (@typeInfo(Expected)) {
                .Enum => if (Expected.opts.enum_kind == .string) .string else .identifier,
                else => unreachable,
            },
        }, .actual = actual } },
    };
}

pub fn diagnose(attr: Tag, arguments: *Arguments, arg_idx: u32, res: Parser.Result, node: Tree.Node, p: *Parser) !?Diagnostics.Message {
    switch (attr) {
        inline else => |tag| {
            const decl = @typeInfo(attributes).Struct.decls[@int_from_enum(tag)];
            const max_arg_count = comptime max_arg_count(tag);
            if (arg_idx >= max_arg_count) return Diagnostics.Message{
                .tag = .attribute_too_many_args,
                .extra = .{ .attr_arg_count = .{ .attribute = attr, .expected = max_arg_count } },
            };
            const arg_fields = std.meta.fields(@field(attributes, decl.name));
            switch (arg_idx) {
                inline 0...arg_fields.len - 1 => |arg_i| {
                    return diagnose_field(decl, arg_fields[arg_i], UnwrapOptional(arg_fields[arg_i].type), arguments, res, node, p);
                },
                else => unreachable,
            }
        },
    }
}

const EnumTypes = enum {
    string,
    identifier,
};
pub const Alignment = struct {
    node: NodeIndex = .none,
    requested: u29,
};
pub const Identifier = struct {
    tok: TokenIndex = 0,
};

const attributes = struct {
    pub const access = struct {
        access_mode: enum {
            read_only,
            read_write,
            write_only,
            none,

            const opts = struct {
                const enum_kind = .identifier;
            };
        },
        ref_index: u32,
        size_index: ?u32 = null,
    };
    pub const alias = struct {
        alias: Value,
    };
    pub const aligned = struct {
        alignment: ?Alignment = null,
        __name_tok: TokenIndex,
    };
    pub const alloc_align = struct {
        position: u32,
    };
    pub const alloc_size = struct {
        position_1: u32,
        position_2: ?u32 = null,
    };
    pub const allocate = struct {
        segname: Value,
    };
    pub const allocator = struct {};
    pub const always_inline = struct {};
    pub const appdomain = struct {};
    pub const artificial = struct {};
    pub const assume_aligned = struct {
        alignment: Alignment,
        offset: ?u32 = null,
    };
    pub const cleanup = struct {
        function: Identifier,
    };
    pub const code_seg = struct {
        segname: Value,
    };
    pub const cold = struct {};
    pub const common = struct {};
    pub const @"const" = struct {};
    pub const constructor = struct {
        priority: ?u32 = null,
    };
    pub const copy = struct {
        function: Identifier,
    };
    pub const deprecated = struct {
        msg: ?Value = null,
        __name_tok: TokenIndex,
    };
    pub const designated_init = struct {};
    pub const destructor = struct {
        priority: ?u32 = null,
    };
    pub const dllexport = struct {};
    pub const dllimport = struct {};
    pub const @"error" = struct {
        msg: Value,
        __name_tok: TokenIndex,
    };
    pub const externally_visible = struct {};
    pub const fallthrough = struct {};
    pub const flatten = struct {};
    pub const format = struct {
        archetype: enum {
            printf,
            scanf,
            strftime,
            strfmon,

            const opts = struct {
                const enum_kind = .identifier;
            };
        },
        string_index: u32,
        first_to_check: u32,
    };
    pub const format_arg = struct {
        string_index: u32,
    };
    pub const gnu_inline = struct {};
    pub const hot = struct {};
    pub const ifunc = struct {
        resolver: Value,
    };
    pub const interrupt = struct {};
    pub const interrupt_handler = struct {};
    pub const jitintrinsic = struct {};
    pub const leaf = struct {};
    pub const malloc = struct {};
    pub const may_alias = struct {};
    pub const mode = struct {
        mode: enum {
            // zig fmt: off
                byte,  word,  pointer,
                BI,    QI,    HI,
                PSI,   SI,    PDI,
                DI,    TI,    OI,
                XI,    QF,    HF,
                TQF,   SF,    DF,
                XF,    SD,    DD,
                TD,    TF,    QQ,
                HQ,    SQ,    DQ,
                TQ,    UQQ,   UHQ,
                USQ,   UDQ,   UTQ,
                HA,    SA,    DA,
                TA,    UHA,   USA,
                UDA,   UTA,   CC,
                BLK,   VOID,  QC,
                HC,    SC,    DC,
                XC,    TC,    CQI,
                CHI,   CSI,   CDI,
                CTI,   COI,   CPSI,
                BND32, BND64,
                // zig fmt: on

            const opts = struct {
                const enum_kind = .identifier;
            };
        },
    };
    pub const naked = struct {};
    pub const no_address_safety_analysis = struct {};
    pub const no_icf = struct {};
    pub const no_instrument_function = struct {};
    pub const no_profile_instrument_function = struct {};
    pub const no_reorder = struct {};
    pub const no_sanitize = struct {
        /// Todo: represent args as union?
        alignment: Value,
        object_size: ?Value = null,
    };
    pub const no_sanitize_address = struct {};
    pub const no_sanitize_coverage = struct {};
    pub const no_sanitize_thread = struct {};
    pub const no_sanitize_undefined = struct {};
    pub const no_split_stack = struct {};
    pub const no_stack_limit = struct {};
    pub const no_stack_protector = struct {};
    pub const @"noalias" = struct {};
    pub const noclone = struct {};
    pub const nocommon = struct {};
    pub const nodiscard = struct {};
    pub const noinit = struct {};
    pub const @"noinline" = struct {};
    pub const noipa = struct {};
    // TODO: arbitrary number of arguments
    //    const nonnull = struct {
    //    //            arg_index: []const u32,
    //        };
    //    };
    pub const nonstring = struct {};
    pub const noplt = struct {};
    pub const @"noreturn" = struct {};
    // TODO: union args ?
    //    const optimize = struct {
    //    //            optimize, // u32 | []const u8 -- optimize?
    //        };
    //    };
    pub const @"packed" = struct {};
    pub const patchable_function_entry = struct {};
    pub const persistent = struct {};
    pub const process = struct {};
    pub const pure = struct {};
    pub const reproducible = struct {};
    pub const restrict = struct {};
    pub const retain = struct {};
    pub const returns_nonnull = struct {};
    pub const returns_twice = struct {};
    pub const safebuffers = struct {};
    pub const scalar_storage_order = struct {
        order: enum {
            @"little-endian",
            @"big-endian",

            const opts = struct {
                const enum_kind = .string;
            };
        },
    };
    pub const section = struct {
        name: Value,
    };
    pub const selectany = struct {};
    pub const sentinel = struct {
        position: ?u32 = null,
    };
    pub const simd = struct {
        mask: ?enum {
            notinbranch,
            inbranch,

            const opts = struct {
                const enum_kind = .string;
            };
        } = null,
    };
    pub const spectre = struct {
        arg: enum {
            nomitigation,

            const opts = struct {
                const enum_kind = .identifier;
            };
        },
    };
    pub const stack_protect = struct {};
    pub const symver = struct {
        version: Value, // TODO: validate format "name2@nodename"

    };
    pub const target = struct {
        options: Value, // TODO: multiple arguments

    };
    pub const target_clones = struct {
        options: Value, // TODO: multiple arguments

    };
    pub const thread = struct {};
    pub const tls_model = struct {
        model: enum {
            @"global-dynamic",
            @"local-dynamic",
            @"initial-exec",
            @"local-exec",

            const opts = struct {
                const enum_kind = .string;
            };
        },
    };
    pub const transparent_union = struct {};
    pub const unavailable = struct {
        msg: ?Value = null,
        __name_tok: TokenIndex,
    };
    pub const uninitialized = struct {};
    pub const unsequenced = struct {};
    pub const unused = struct {};
    pub const used = struct {};
    pub const uuid = struct {
        uuid: Value,
    };
    pub const vector_size = struct {
        bytes: u32, // TODO: validate "The bytes argument must be a positive power-of-two multiple of the base type size"

    };
    pub const visibility = struct {
        visibility_type: enum {
            default,
            hidden,
            internal,
            protected,

            const opts = struct {
                const enum_kind = .string;
            };
        },
    };
    pub const warn_if_not_aligned = struct {
        alignment: Alignment,
    };
    pub const warn_unused_result = struct {};
    pub const warning = struct {
        msg: Value,
        __name_tok: TokenIndex,
    };
    pub const weak = struct {};
    pub const weakref = struct {
        target: ?Value = null,
    };
    pub const zero_call_used_regs = struct {
        choice: enum {
            skip,
            used,
            @"used-gpr",
            @"used-arg",
            @"used-gpr-arg",
            all,
            @"all-gpr",
            @"all-arg",
            @"all-gpr-arg",

            const opts = struct {
                const enum_kind = .string;
            };
        },
    };
    pub const asm_label = struct {
        name: Value,
    };
    pub const calling_convention = struct {
        cc: CallingConvention,
    };
};

pub const Tag = std.meta.DeclEnum(attributes);

pub const Arguments = blk: {
    const decls = @typeInfo(attributes).Struct.decls;
    var union_fields: [decls.len]ZigType.UnionField = undefined;
    for (decls, &union_fields) |decl, *field| {
        field.* = .{
            .name = decl.name ++ "",
            .type = @field(attributes, decl.name),
            .alignment = 0,
        };
    }

    break :blk @Type(.{
        .Union = .{
            .layout = .auto,
            .tag_type = null,
            .fields = &union_fields,
            .decls = &.{},
        },
    });
};

pub fn ArgumentsForTag(comptime tag: Tag) type {
    const decl = @typeInfo(attributes).Struct.decls[@int_from_enum(tag)];
    return @field(attributes, decl.name);
}

pub fn init_arguments(tag: Tag, name_tok: TokenIndex) Arguments {
    switch (tag) {
        inline else => |arg_tag| {
            const union_element = @field(attributes, @tag_name(arg_tag));
            const init = std.mem.zero_init(union_element, .{});
            var args = @union_init(Arguments, @tag_name(arg_tag), init);
            if (@has_field(@field(attributes, @tag_name(arg_tag)), "__name_tok")) {
                @field(args, @tag_name(arg_tag)).__name_tok = name_tok;
            }
            return args;
        },
    }
}

pub fn from_string(kind: Kind, namespace: ?[]const u8, name: []const u8) ?Tag {
    const Properties = struct {
        tag: Tag,
        gnu: bool = false,
        declspec: bool = false,
        c23: bool = false,
    };
    const attribute_names = @import("Attribute/names.zig").with(Properties);

    const normalized = normalize(name);
    const actual_kind: Kind = if (namespace) |ns| blk: {
        const normalized_ns = normalize(ns);
        if (mem.eql(u8, normalized_ns, "gnu")) {
            break :blk .gnu;
        }
        return null;
    } else kind;

    const tag_and_opts = attribute_names.from_name(normalized) orelse return null;
    switch (actual_kind) {
        inline else => |tag| {
            if (@field(tag_and_opts.properties, @tag_name(tag)))
                return tag_and_opts.properties.tag;
        },
    }
    return null;
}

pub fn normalize(name: []const u8) []const u8 {
    if (name.len >= 4 and mem.starts_with(u8, name, "__") and mem.ends_with(u8, name, "__")) {
        return name[2 .. name.len - 2];
    }
    return name;
}

fn ignored_attr_err(p: *Parser, tok: TokenIndex, attr: Attribute.Tag, context: []const u8) !void {
    const strings_top = p.strings.items.len;
    defer p.strings.items.len = strings_top;

    try p.strings.writer().print("attribute '{s}' ignored on {s}", .{ @tag_name(attr), context });
    const str = try p.comp.diagnostics.arena.allocator().dupe(u8, p.strings.items[strings_top..]);
    try p.err_str(.ignored_attribute, tok, str);
}

pub const applyParameterAttributes = apply_variable_attributes;
pub fn apply_variable_attributes(p: *Parser, ty: Type, attr_buf_start: usize, tag: ?Diagnostics.Tag) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    var base_ty = ty;
    if (base_ty.specifier == .attributed) base_ty = base_ty.data.attributed.base;
    var common = false;
    var nocommon = false;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        // zig fmt: off
        .alias, .may_alias, .deprecated, .unavailable, .unused, .warn_if_not_aligned, .weak, .used,
        .noinit, .retain, .persistent, .section, .mode, .asm_label,
         => try p.attr_application_buf.append(p.gpa, attr),
        // zig fmt: on
        .common => if (nocommon) {
            try p.err_tok(.ignore_common, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            common = true;
        },
        .nocommon => if (common) {
            try p.err_tok(.ignore_nocommon, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            nocommon = true;
        },
        .vector_size => try attr.apply_vector_size(p, tok, &base_ty),
        .aligned => try attr.apply_aligned(p, base_ty, tag),
        .nonstring => if (!base_ty.is_array() or !(base_ty.is(.char) or base_ty.is(.uchar) or base_ty.is(.schar))) {
            try p.err_str(.non_string_ignored, tok, try p.type_str(ty));
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
        },
        .uninitialized => if (p.func.ty == null) {
            try p.err_str(.local_variable_attribute, tok, "uninitialized");
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
        },
        .cleanup => if (p.func.ty == null) {
            try p.err_str(.local_variable_attribute, tok, "cleanup");
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
        },
        .alloc_size,
        .copy,
        .tls_model,
        .visibility,
        => std.debug.panic("apply variable attribute {s}", .{@tag_name(attr.tag)}),
        else => try ignored_attr_err(p, tok, attr.tag, "variables"),
    };
    const existing = ty.get_attributes();
    if (existing.len == 0 and p.attr_application_buf.items.len == 0) return base_ty;
    if (existing.len == 0) return base_ty.with_attributes(p.arena, p.attr_application_buf.items);

    const attributed_type = try Type.Attributed.create(p.arena, base_ty, existing, p.attr_application_buf.items);
    return Type{ .specifier = .attributed, .data = .{ .attributed = attributed_type } };
}

pub fn apply_field_attributes(p: *Parser, field_ty: *Type, attr_buf_start: usize) ![]const Attribute {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        // zig fmt: off
        .@"packed", .may_alias, .deprecated, .unavailable, .unused, .warn_if_not_aligned, .mode,
        => try p.attr_application_buf.append(p.gpa, attr),
        // zig fmt: on
        .vector_size => try attr.apply_vector_size(p, tok, field_ty),
        .aligned => try attr.apply_aligned(p, field_ty.*, null),
        else => try ignored_attr_err(p, tok, attr.tag, "fields"),
    };
    if (p.attr_application_buf.items.len == 0) return &[0]Attribute{};
    return p.arena.dupe(Attribute, p.attr_application_buf.items);
}

pub fn apply_type_attributes(p: *Parser, ty: Type, attr_buf_start: usize, tag: ?Diagnostics.Tag) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    var base_ty = ty;
    if (base_ty.specifier == .attributed) base_ty = base_ty.data.attributed.base;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        // zig fmt: off
        .@"packed", .may_alias, .deprecated, .unavailable, .unused, .warn_if_not_aligned, .mode,
         => try p.attr_application_buf.append(p.gpa, attr),
        // zig fmt: on
        .transparent_union => try attr.apply_transparent_union(p, tok, base_ty),
        .vector_size => try attr.apply_vector_size(p, tok, &base_ty),
        .aligned => try attr.apply_aligned(p, base_ty, tag),
        .designated_init => if (base_ty.is(.@"struct")) {
            try p.attr_application_buf.append(p.gpa, attr);
        } else {
            try p.err_tok(.designated_init_invalid, tok);
        },
        .alloc_size,
        .copy,
        .scalar_storage_order,
        .nonstring,
        => std.debug.panic("apply type attribute {s}", .{@tag_name(attr.tag)}),
        else => try ignored_attr_err(p, tok, attr.tag, "types"),
    };

    const existing = ty.get_attributes();
    // TODO: the alignment annotation on a type should override
    // the decl it refers to. This might not be true for others.  Maybe bug.

    // if there are annotations on this type def use those.
    if (p.attr_application_buf.items.len > 0) {
        return try base_ty.with_attributes(p.arena, p.attr_application_buf.items);
    } else if (existing.len > 0) {
        // else use the ones on the typedef decl we were refering to.
        return try base_ty.with_attributes(p.arena, existing);
    }
    return base_ty;
}

pub fn apply_function_attributes(p: *Parser, ty: Type, attr_buf_start: usize) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    var base_ty = ty;
    if (base_ty.specifier == .attributed) base_ty = base_ty.data.attributed.base;
    var hot = false;
    var cold = false;
    var @"noinline" = false;
    var always_inline = false;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        // zig fmt: off
        .noreturn, .unused, .used, .warning, .deprecated, .unavailable, .weak, .pure, .leaf,
        .@"const", .warn_unused_result, .section, .returns_nonnull, .returns_twice, .@"error",
        .externally_visible, .retain, .flatten, .gnu_inline, .alias, .asm_label, .nodiscard,
        .reproducible, .unsequenced,
         => try p.attr_application_buf.append(p.gpa, attr),
        // zig fmt: on
        .hot => if (cold) {
            try p.err_tok(.ignore_hot, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            hot = true;
        },
        .cold => if (hot) {
            try p.err_tok(.ignore_cold, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            cold = true;
        },
        .always_inline => if (@"noinline") {
            try p.err_tok(.ignore_always_inline, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            always_inline = true;
        },
        .@"noinline" => if (always_inline) {
            try p.err_tok(.ignore_noinline, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            @"noinline" = true;
        },
        .aligned => try attr.apply_aligned(p, base_ty, null),
        .format => try attr.apply_format(p, base_ty),
        .calling_convention => switch (attr.args.calling_convention.cc) {
            .C => continue,
            .stdcall, .thiscall => switch (p.comp.target.cpu.arch) {
                .x86 => try p.attr_application_buf.append(p.gpa, attr),
                else => try p.err_str(.callconv_not_supported, tok, p.tok_ids[tok].lexeme().?),
            },
            .vectorcall => switch (p.comp.target.cpu.arch) {
                .x86, .aarch64, .aarch64_be, .aarch64_32 => try p.attr_application_buf.append(p.gpa, attr),
                else => try p.err_str(.callconv_not_supported, tok, p.tok_ids[tok].lexeme().?),
            },
        },
        .access,
        .alloc_align,
        .alloc_size,
        .artificial,
        .assume_aligned,
        .constructor,
        .copy,
        .destructor,
        .format_arg,
        .ifunc,
        .interrupt,
        .interrupt_handler,
        .malloc,
        .no_address_safety_analysis,
        .no_icf,
        .no_instrument_function,
        .no_profile_instrument_function,
        .no_reorder,
        .no_sanitize,
        .no_sanitize_address,
        .no_sanitize_coverage,
        .no_sanitize_thread,
        .no_sanitize_undefined,
        .no_split_stack,
        .no_stack_limit,
        .no_stack_protector,
        .noclone,
        .noipa,
        // .nonnull,
        .noplt,
        // .optimize,
        .patchable_function_entry,
        .sentinel,
        .simd,
        .stack_protect,
        .symver,
        .target,
        .target_clones,
        .visibility,
        .weakref,
        .zero_call_used_regs,
        => std.debug.panic("apply type attribute {s}", .{@tag_name(attr.tag)}),
        else => try ignored_attr_err(p, tok, attr.tag, "functions"),
    };
    return ty.with_attributes(p.arena, p.attr_application_buf.items);
}

pub fn apply_label_attributes(p: *Parser, ty: Type, attr_buf_start: usize) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    var hot = false;
    var cold = false;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        .unused => try p.attr_application_buf.append(p.gpa, attr),
        .hot => if (cold) {
            try p.err_tok(.ignore_hot, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            hot = true;
        },
        .cold => if (hot) {
            try p.err_tok(.ignore_cold, tok);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
            cold = true;
        },
        else => try ignored_attr_err(p, tok, attr.tag, "labels"),
    };
    return ty.with_attributes(p.arena, p.attr_application_buf.items);
}

pub fn apply_statement_attributes(p: *Parser, ty: Type, expr_start: TokenIndex, attr_buf_start: usize) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        .fallthrough => if (p.tok_ids[p.tok_i] != .keyword_case and p.tok_ids[p.tok_i] != .keyword_default) {
            // TODO: this condition is not completely correct; the last statement of a compound
            // statement is also valid if it precedes a switch label (so intervening '}' are ok,
            // but only if they close a compound statement)
            try p.err_tok(.invalid_fallthrough, expr_start);
        } else {
            try p.attr_application_buf.append(p.gpa, attr);
        },
        else => try p.err_str(.cannot_apply_attribute_to_statement, tok, @tag_name(attr.tag)),
    };
    return ty.with_attributes(p.arena, p.attr_application_buf.items);
}

pub fn apply_enumerator_attributes(p: *Parser, ty: Type, attr_buf_start: usize) !Type {
    const attrs = p.attr_buf.items(.attr)[attr_buf_start..];
    const toks = p.attr_buf.items(.tok)[attr_buf_start..];
    p.attr_application_buf.items.len = 0;
    for (attrs, toks) |attr, tok| switch (attr.tag) {
        .deprecated, .unavailable => try p.attr_application_buf.append(p.gpa, attr),
        else => try ignored_attr_err(p, tok, attr.tag, "enums"),
    };
    return ty.with_attributes(p.arena, p.attr_application_buf.items);
}

fn apply_aligned(attr: Attribute, p: *Parser, ty: Type, tag: ?Diagnostics.Tag) !void {
    const base = ty.canonicalize(.standard);
    if (attr.args.aligned.alignment) |alignment| alignas: {
        if (attr.syntax != .keyword) break :alignas;

        const align_tok = attr.args.aligned.__name_tok;
        if (tag) |t| try p.err_tok(t, align_tok);

        const default_align = base.alignof(p.comp);
        if (ty.is_func()) {
            try p.err_tok(.alignas_on_func, align_tok);
        } else if (alignment.requested < default_align) {
            try p.err_extra(.minimum_alignment, align_tok, .{ .unsigned = default_align });
        }
    }
    try p.attr_application_buf.append(p.gpa, attr);
}

fn apply_transparent_union(attr: Attribute, p: *Parser, tok: TokenIndex, ty: Type) !void {
    const union_ty = ty.get(.@"union") orelse {
        return p.err_tok(.transparent_union_wrong_type, tok);
    };
    // TODO validate union defined at end
    if (union_ty.data.record.is_incomplete()) return;
    const fields = union_ty.data.record.fields;
    if (fields.len == 0) {
        return p.err_tok(.transparent_union_one_field, tok);
    }
    const first_field_size = fields[0].ty.bit_sizeof(p.comp).?;
    for (fields[1..]) |field| {
        const field_size = field.ty.bit_sizeof(p.comp).?;
        if (field_size == first_field_size) continue;
        const mapper = p.comp.string_interner.get_slow_type_mapper();
        const str = try std.fmt.alloc_print(
            p.comp.diagnostics.arena.allocator(),
            "'{s}' ({d}",
            .{ mapper.lookup(field.name), field_size },
        );
        try p.err_str(.transparent_union_size, field.name_tok, str);
        return p.err_extra(.transparent_union_size_note, fields[0].name_tok, .{ .unsigned = first_field_size });
    }

    try p.attr_application_buf.append(p.gpa, attr);
}

fn apply_vector_size(attr: Attribute, p: *Parser, tok: TokenIndex, ty: *Type) !void {
    if (!(ty.is_int() or ty.is_float()) or !ty.is_real()) {
        const orig_ty = try p.type_str(ty.*);
        ty.* = Type.invalid;
        return p.err_str(.invalid_vec_elem_ty, tok, orig_ty);
    }
    const vec_bytes = attr.args.vector_size.bytes;
    const ty_size = ty.sizeof(p.comp).?;
    if (vec_bytes % ty_size != 0) {
        return p.err_tok(.vec_size_not_multiple, tok);
    }
    const vec_size = vec_bytes / ty_size;

    const arr_ty = try p.arena.create(Type.Array);
    arr_ty.* = .{ .elem = ty.*, .len = vec_size };
    ty.* = Type{
        .specifier = .vector,
        .data = .{ .array = arr_ty },
    };
}

fn apply_format(attr: Attribute, p: *Parser, ty: Type) !void {
    // TODO validate
    _ = ty;
    try p.attr_application_buf.append(p.gpa, attr);
}
