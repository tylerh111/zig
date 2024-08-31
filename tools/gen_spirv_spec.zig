const std = @import("std");
const Allocator = std.mem.Allocator;
const g = @import("spirv/grammar.zig");
const CoreRegistry = g.CoreRegistry;
const ExtensionRegistry = g.ExtensionRegistry;
const Instruction = g.Instruction;
const OperandKind = g.OperandKind;
const Enumerant = g.Enumerant;
const Operand = g.Operand;

const ExtendedStructSet = std.StringHashMap(void);

const Extension = struct {
    name: []const u8,
    spec: ExtensionRegistry,
};

const CmpInst = struct {
    fn lt(_: CmpInst, a: Instruction, b: Instruction) bool {
        return a.opcode < b.opcode;
    }
};

const StringPair = struct { []const u8, []const u8 };

const StringPairContext = struct {
    pub fn hash(_: @This(), a: StringPair) u32 {
        var hasher = std.hash.Wyhash.init(0);
        const x, const y = a;
        hasher.update(x);
        hasher.update(y);
        return @truncate(hasher.final());
    }

    pub fn eql(_: @This(), a: StringPair, b: StringPair, b_index: usize) bool {
        _ = b_index;
        const a_x, const a_y = a;
        const b_x, const b_y = b;
        return std.mem.eql(u8, a_x, b_x) and std.mem.eql(u8, a_y, b_y);
    }
};

const OperandKindMap = std.ArrayHashMap(StringPair, OperandKind, StringPairContext, true);

/// Khronos made it so that these names are not defined explicitly, so
/// we need to hardcode it (like they did).
/// See https://github.com/KhronosGroup/SPIRV-Registry/
const set_names = std.StaticStringMap([]const u8).init_comptime(.{
    .{ "opencl.std.100", "OpenCL.std" },
    .{ "glsl.std.450", "GLSL.std.450" },
    .{ "opencl.debuginfo.100", "OpenCL.DebugInfo.100" },
    .{ "spv-amd-shader-ballot", "SPV_AMD_shader_ballot" },
    .{ "nonsemantic.shader.debuginfo.100", "NonSemantic.Shader.DebugInfo.100" },
    .{ "nonsemantic.vkspreflection", "NonSemantic.VkspReflection" },
    .{ "nonsemantic.clspvreflection", "NonSemantic.ClspvReflection.6" }, // This version needs to be handled manually
    .{ "spv-amd-gcn-shader", "SPV_AMD_gcn_shader" },
    .{ "spv-amd-shader-trinary-minmax", "SPV_AMD_shader_trinary_minmax" },
    .{ "debuginfo", "DebugInfo" },
    .{ "nonsemantic.debugprintf", "NonSemantic.DebugPrintf" },
    .{ "spv-amd-shader-explicit-vertex-parameter", "SPV_AMD_shader_explicit_vertex_parameter" },
    .{ "nonsemantic.debugbreak", "NonSemantic.DebugBreak" },
    .{ "zig", "zig" },
});

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const args = try std.process.args_alloc(a);
    if (args.len != 3) {
        usage_and_exit(args[0], 1);
    }

    const json_path = try std.fs.path.join(a, &.{ args[1], "include/spirv/unified1/" });
    const dir = try std.fs.cwd().open_dir(json_path, .{ .iterate = true });

    const core_spec = try read_registry(CoreRegistry, a, dir, "spirv.core.grammar.json");
    std.sort.block(Instruction, core_spec.instructions, CmpInst{}, CmpInst.lt);

    var exts = std.ArrayList(Extension).init(a);

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) {
            continue;
        }

        try read_ext_registry(&exts, a, dir, entry.name);
    }

    try read_ext_registry(&exts, a, std.fs.cwd(), args[2]);

    var bw = std.io.buffered_writer(std.io.get_std_out().writer());
    try render(bw.writer(), a, core_spec, exts.items);
    try bw.flush();
}

fn read_ext_registry(exts: *std.ArrayList(Extension), a: Allocator, dir: std.fs.Dir, sub_path: []const u8) !void {
    const filename = std.fs.path.basename(sub_path);
    if (!std.mem.starts_with(u8, filename, "extinst.")) {
        return;
    }

    std.debug.assert(std.mem.ends_with(u8, filename, ".grammar.json"));
    const name = filename["extinst.".len .. filename.len - ".grammar.json".len];
    const spec = try read_registry(ExtensionRegistry, a, dir, sub_path);

    std.sort.block(Instruction, spec.instructions, CmpInst{}, CmpInst.lt);

    try exts.append(.{ .name = set_names.get(name).?, .spec = spec });
}

fn read_registry(comptime RegistryType: type, a: Allocator, dir: std.fs.Dir, path: []const u8) !RegistryType {
    const spec = try dir.read_file_alloc(a, path, std.math.max_int(usize));
    // Required for json parsing.
    @setEvalBranchQuota(10000);

    var scanner = std.json.Scanner.init_complete_input(a, spec);
    var diagnostics = std.json.Diagnostics{};
    scanner.enable_diagnostics(&diagnostics);
    const parsed = std.json.parse_from_token_source(RegistryType, a, &scanner, .{}) catch |err| {
        std.debug.print("{s}:{}:{}:\n", .{ path, diagnostics.get_line(), diagnostics.get_column() });
        return err;
    };
    return parsed.value;
}

/// Returns a set with types that require an extra struct for the `Instruction` interface
/// to the spir-v spec, or whether the original type can be used.
fn extended_structs(
    a: Allocator,
    kinds: []const OperandKind,
) !ExtendedStructSet {
    var map = ExtendedStructSet.init(a);
    try map.ensure_total_capacity(@as(u32, @int_cast(kinds.len)));

    for (kinds) |kind| {
        const enumerants = kind.enumerants orelse continue;

        for (enumerants) |enumerant| {
            if (enumerant.parameters.len > 0) {
                break;
            }
        } else continue;

        map.put_assume_capacity(kind.kind, {});
    }

    return map;
}

// Return a score for a particular priority. Duplicate instruction/operand enum values are
// removed by picking the tag with the lowest score to keep, and by making an alias for the
// other. Note that the tag does not need to be just a tag at this point, in which case it
// gets the lowest score automatically anyway.
fn tag_priority_score(tag: []const u8) usize {
    if (tag.len == 0) {
        return 1;
    } else if (std.mem.eql(u8, tag, "EXT")) {
        return 2;
    } else if (std.mem.eql(u8, tag, "KHR")) {
        return 3;
    } else {
        return 4;
    }
}

fn render(writer: anytype, a: Allocator, registry: CoreRegistry, extensions: []const Extension) !void {
    try writer.write_all(
        \\//! This file is auto-generated by tools/gen_spirv_spec.zig.
        \\
        \\const std = @import("std");
        \\
        \\pub const Version = packed struct(Word) {
        \\    padding: u8 = 0,
        \\    minor: u8,
        \\    major: u8,
        \\    padding0: u8 = 0,
        \\
        \\    pub fn to_word(self: @This()) Word {
        \\        return @bit_cast(self);
        \\    }
        \\};
        \\
        \\pub const Word = u32;
        \\pub const IdResult = enum(Word) {
        \\    none,
        \\    _,
        \\
        \\    pub fn format(
        \\        self: IdResult,
        \\        comptime _: []const u8,
        \\        _: std.fmt.FormatOptions,
        \\        writer: anytype,
        \\    ) @TypeOf(writer).Error!void {
        \\        switch (self) {
        \\            .none => try writer.write_all("(none)"),
        \\            else => try writer.print("%{}", .{@int_from_enum(self)}),
        \\        }
        \\    }
        \\};
        \\pub const IdResultType = IdResult;
        \\pub const IdRef = IdResult;
        \\
        \\pub const IdMemorySemantics = IdRef;
        \\pub const IdScope = IdRef;
        \\
        \\pub const LiteralInteger = Word;
        \\pub const LiteralFloat = Word;
        \\pub const LiteralString = []const u8;
        \\pub const LiteralContextDependentNumber = union(enum) {
        \\    int32: i32,
        \\    uint32: u32,
        \\    int64: i64,
        \\    uint64: u64,
        \\    float32: f32,
        \\    float64: f64,
        \\};
        \\pub const LiteralExtInstInteger = struct{ inst: Word };
        \\pub const LiteralSpecConstantOpInteger = struct { opcode: Opcode };
        \\pub const PairLiteralIntegerIdRef = struct { value: LiteralInteger, label: IdRef };
        \\pub const PairIdRefLiteralInteger = struct { target: IdRef, member: LiteralInteger };
        \\pub const PairIdRefIdRef = [2]IdRef;
        \\
        \\pub const Quantifier = enum {
        \\    required,
        \\    optional,
        \\    variadic,
        \\};
        \\
        \\pub const Operand = struct {
        \\    kind: OperandKind,
        \\    quantifier: Quantifier,
        \\};
        \\
        \\pub const OperandCategory = enum {
        \\    bit_enum,
        \\    value_enum,
        \\    id,
        \\    literal,
        \\    composite,
        \\};
        \\
        \\pub const Enumerant = struct {
        \\    name: []const u8,
        \\    value: Word,
        \\    parameters: []const OperandKind,
        \\};
        \\
        \\pub const Instruction = struct {
        \\    name: []const u8,
        \\    opcode: Word,
        \\    operands: []const Operand,
        \\};
        \\
        \\pub const zig_generator_id: Word = 41;
        \\
    );

    try writer.print(
        \\pub const version = Version{{ .major = {}, .minor = {}, .patch = {} }};
        \\pub const magic_number: Word = {s};
        \\
        \\
    ,
        .{ registry.major_version, registry.minor_version, registry.revision, registry.magic_number },
    );

    // Merge the operand kinds from all extensions together.
    // var all_operand_kinds = std.ArrayList(OperandKind).init(a);
    // try all_operand_kinds.append_slice(registry.operand_kinds);
    var all_operand_kinds = OperandKindMap.init(a);
    for (registry.operand_kinds) |kind| {
        try all_operand_kinds.put_no_clobber(.{ "core", kind.kind }, kind);
    }
    for (extensions) |ext| {
        // Note: extensions may define the same operand kind, with different
        // parameters. Instead of trying to merge them, just discriminate them
        // using the name of the extension. This is similar to what
        // the official headers do.

        try all_operand_kinds.ensure_unused_capacity(ext.spec.operand_kinds.len);
        for (ext.spec.operand_kinds) |kind| {
            var new_kind = kind;
            new_kind.kind = try std.mem.join(a, ".", &.{ ext.name, kind.kind });
            try all_operand_kinds.put_no_clobber(.{ ext.name, kind.kind }, new_kind);
        }
    }

    const extended_structs = try extended_structs(a, all_operand_kinds.values());
    // Note: extensions don't seem to have class.
    try render_class(writer, a, registry.instructions);
    try render_operand_kind(writer, all_operand_kinds.values());
    try render_opcodes(writer, a, registry.instructions, extended_structs);
    try render_operand_kinds(writer, a, all_operand_kinds.values(), extended_structs);
    try render_instruction_set(writer, a, registry, extensions, all_operand_kinds);
}

fn render_instruction_set(
    writer: anytype,
    a: Allocator,
    core: CoreRegistry,
    extensions: []const Extension,
    all_operand_kinds: OperandKindMap,
) !void {
    _ = a;
    try writer.write_all(
        \\pub const InstructionSet = enum {
        \\    core,
    );

    for (extensions) |ext| {
        try writer.print("{p},\n", .{std.zig.fmt_id(ext.name)});
    }

    try writer.write_all(
        \\
        \\    pub fn instructions(self: InstructionSet) []const Instruction {
        \\        return switch (self) {
        \\
    );

    try render_instructions_case(writer, "core", core.instructions, all_operand_kinds);
    for (extensions) |ext| {
        try render_instructions_case(writer, ext.name, ext.spec.instructions, all_operand_kinds);
    }

    try writer.write_all(
        \\        };
        \\    }
        \\};
        \\
    );
}

fn render_instructions_case(
    writer: anytype,
    set_name: []const u8,
    instructions: []const Instruction,
    all_operand_kinds: OperandKindMap,
) !void {
    // Note: theoretically we could dedup from tags and give every instruction a list of aliases,
    // but there aren't so many total aliases and that would add more overhead in total. We will
    // just filter those out when needed.

    try writer.print(".{p_} => &[_]Instruction{{\n", .{std.zig.fmt_id(set_name)});

    for (instructions) |inst| {
        try writer.print(
            \\.{{
            \\    .name = "{s}",
            \\    .opcode = {},
            \\    .operands = &[_]Operand{{
            \\
        , .{ inst.opname, inst.opcode });

        for (inst.operands) |operand| {
            const quantifier = if (operand.quantifier) |q|
                switch (q) {
                    .@"?" => "optional",
                    .@"*" => "variadic",
                }
            else
                "required";

            const kind = all_operand_kinds.get(.{ set_name, operand.kind }) orelse
                all_operand_kinds.get(.{ "core", operand.kind }).?;
            try writer.print(".{{.kind = .{p_}, .quantifier = .{s}}},\n", .{ std.zig.fmt_id(kind.kind), quantifier });
        }

        try writer.write_all(
            \\    },
            \\},
            \\
        );
    }

    try writer.write_all(
        \\},
        \\
    );
}

fn render_class(writer: anytype, a: Allocator, instructions: []const Instruction) !void {
    var class_map = std.StringArrayHashMap(void).init(a);

    for (instructions) |inst| {
        if (std.mem.eql(u8, inst.class.?, "@exclude")) {
            continue;
        }
        try class_map.put(inst.class.?, {});
    }

    try writer.write_all("pub const Class = enum {\n");
    for (class_map.keys()) |class| {
        try render_instruction_class(writer, class);
        try writer.write_all(",\n");
    }
    try writer.write_all("};\n\n");
}

fn render_instruction_class(writer: anytype, class: []const u8) !void {
    // Just assume that these wont clobber zig builtin types.
    var prev_was_sep = true;
    for (class) |c| {
        switch (c) {
            '-', '_' => prev_was_sep = true,
            else => if (prev_was_sep) {
                try writer.write_byte(std.ascii.to_upper(c));
                prev_was_sep = false;
            } else {
                try writer.write_byte(std.ascii.to_lower(c));
            },
        }
    }
}

fn render_operand_kind(writer: anytype, operands: []const OperandKind) !void {
    try writer.write_all(
        \\pub const OperandKind = enum {
        \\    Opcode,
        \\
    );
    for (operands) |operand| {
        try writer.print("{p},\n", .{std.zig.fmt_id(operand.kind)});
    }
    try writer.write_all(
        \\
        \\pub fn category(self: OperandKind) OperandCategory {
        \\    return switch (self) {
        \\        .Opcode => .literal,
        \\
    );
    for (operands) |operand| {
        const cat = switch (operand.category) {
            .BitEnum => "bit_enum",
            .ValueEnum => "value_enum",
            .Id => "id",
            .Literal => "literal",
            .Composite => "composite",
        };
        try writer.print(".{p_} => .{s},\n", .{ std.zig.fmt_id(operand.kind), cat });
    }
    try writer.write_all(
        \\    };
        \\}
        \\pub fn enumerants(self: OperandKind) []const Enumerant {
        \\    return switch (self) {
        \\        .Opcode => unreachable,
        \\
    );
    for (operands) |operand| {
        switch (operand.category) {
            .BitEnum, .ValueEnum => {},
            else => {
                try writer.print(".{p_} => unreachable,\n", .{std.zig.fmt_id(operand.kind)});
                continue;
            },
        }

        try writer.print(".{p_} => &[_]Enumerant{{", .{std.zig.fmt_id(operand.kind)});
        for (operand.enumerants.?) |enumerant| {
            if (enumerant.value == .bitflag and std.mem.eql(u8, enumerant.enumerant, "None")) {
                continue;
            }
            try render_enumerant(writer, enumerant);
            try writer.write_all(",");
        }
        try writer.write_all("},\n");
    }
    try writer.write_all("};\n}\n};\n");
}

fn render_enumerant(writer: anytype, enumerant: Enumerant) !void {
    try writer.print(".{{.name = \"{s}\", .value = ", .{enumerant.enumerant});
    switch (enumerant.value) {
        .bitflag => |flag| try writer.write_all(flag),
        .int => |int| try writer.print("{}", .{int}),
    }
    try writer.write_all(", .parameters = &[_]OperandKind{");
    for (enumerant.parameters, 0..) |param, i| {
        if (i != 0)
            try writer.write_all(", ");
        // Note, param.quantifier will always be one.
        try writer.print(".{p_}", .{std.zig.fmt_id(param.kind)});
    }
    try writer.write_all("}}");
}

fn render_opcodes(
    writer: anytype,
    a: Allocator,
    instructions: []const Instruction,
    extended_structs: ExtendedStructSet,
) !void {
    var inst_map = std.AutoArrayHashMap(u32, usize).init(a);
    try inst_map.ensure_total_capacity(instructions.len);

    var aliases = std.ArrayList(struct { inst: usize, alias: usize }).init(a);
    try aliases.ensure_total_capacity(instructions.len);

    for (instructions, 0..) |inst, i| {
        if (std.mem.eql(u8, inst.class.?, "@exclude")) {
            continue;
        }
        const result = inst_map.get_or_put_assume_capacity(inst.opcode);
        if (!result.found_existing) {
            result.value_ptr.* = i;
            continue;
        }

        const existing = instructions[result.value_ptr.*];

        const tag_index = std.mem.index_of_diff(u8, inst.opname, existing.opname).?;
        const inst_priority = tag_priority_score(inst.opname[tag_index..]);
        const existing_priority = tag_priority_score(existing.opname[tag_index..]);

        if (inst_priority < existing_priority) {
            aliases.append_assume_capacity(.{ .inst = result.value_ptr.*, .alias = i });
            result.value_ptr.* = i;
        } else {
            aliases.append_assume_capacity(.{ .inst = i, .alias = result.value_ptr.* });
        }
    }

    const instructions_indices = inst_map.values();

    try writer.write_all("pub const Opcode = enum(u16) {\n");
    for (instructions_indices) |i| {
        const inst = instructions[i];
        try writer.print("{p} = {},\n", .{ std.zig.fmt_id(inst.opname), inst.opcode });
    }

    try writer.write_all(
        \\
    );

    for (aliases.items) |alias| {
        try writer.print("pub const {} = Opcode.{p_};\n", .{
            std.zig.fmt_id(instructions[alias.inst].opname),
            std.zig.fmt_id(instructions[alias.alias].opname),
        });
    }

    try writer.write_all(
        \\
        \\pub fn Operands(comptime self: Opcode) type {
        \\    return switch (self) {
        \\
    );

    for (instructions_indices) |i| {
        const inst = instructions[i];
        try render_operand(writer, .instruction, inst.opname, inst.operands, extended_structs);
    }

    try writer.write_all(
        \\    };
        \\}
        \\pub fn class(self: Opcode) Class {
        \\    return switch (self) {
        \\
    );

    for (instructions_indices) |i| {
        const inst = instructions[i];
        try writer.print(".{p_} => .", .{std.zig.fmt_id(inst.opname)});
        try render_instruction_class(writer, inst.class.?);
        try writer.write_all(",\n");
    }

    try writer.write_all(
        \\   };
        \\}
        \\};
        \\
    );
}

fn render_operand_kinds(
    writer: anytype,
    a: Allocator,
    kinds: []const OperandKind,
    extended_structs: ExtendedStructSet,
) !void {
    for (kinds) |kind| {
        switch (kind.category) {
            .ValueEnum => try render_value_enum(writer, a, kind, extended_structs),
            .BitEnum => try render_bit_enum(writer, a, kind, extended_structs),
            else => {},
        }
    }
}

fn render_value_enum(
    writer: anytype,
    a: Allocator,
    enumeration: OperandKind,
    extended_structs: ExtendedStructSet,
) !void {
    const enumerants = enumeration.enumerants orelse return error.InvalidRegistry;

    var enum_map = std.AutoArrayHashMap(u32, usize).init(a);
    try enum_map.ensure_total_capacity(enumerants.len);

    var aliases = std.ArrayList(struct { enumerant: usize, alias: usize }).init(a);
    try aliases.ensure_total_capacity(enumerants.len);

    for (enumerants, 0..) |enumerant, i| {
        try writer.context.flush();
        const value: u31 = switch (enumerant.value) {
            .int => |value| value,
            // Some extensions declare ints as string
            .bitflag => |value| try std.fmt.parse_int(u31, value, 10),
        };
        const result = enum_map.get_or_put_assume_capacity(value);
        if (!result.found_existing) {
            result.value_ptr.* = i;
            continue;
        }

        const existing = enumerants[result.value_ptr.*];

        const tag_index = std.mem.index_of_diff(u8, enumerant.enumerant, existing.enumerant).?;
        const enum_priority = tag_priority_score(enumerant.enumerant[tag_index..]);
        const existing_priority = tag_priority_score(existing.enumerant[tag_index..]);

        if (enum_priority < existing_priority) {
            aliases.append_assume_capacity(.{ .enumerant = result.value_ptr.*, .alias = i });
            result.value_ptr.* = i;
        } else {
            aliases.append_assume_capacity(.{ .enumerant = i, .alias = result.value_ptr.* });
        }
    }

    const enum_indices = enum_map.values();

    try writer.print("pub const {} = enum(u32) {{\n", .{std.zig.fmt_id(enumeration.kind)});

    for (enum_indices) |i| {
        const enumerant = enumerants[i];
        // if (enumerant.value != .int) return error.InvalidRegistry;

        switch (enumerant.value) {
            .int => |value| try writer.print("{p} = {},\n", .{ std.zig.fmt_id(enumerant.enumerant), value }),
            .bitflag => |value| try writer.print("{p} = {s},\n", .{ std.zig.fmt_id(enumerant.enumerant), value }),
        }
    }

    try writer.write_byte('\n');

    for (aliases.items) |alias| {
        try writer.print("pub const {} = {}.{p_};\n", .{
            std.zig.fmt_id(enumerants[alias.enumerant].enumerant),
            std.zig.fmt_id(enumeration.kind),
            std.zig.fmt_id(enumerants[alias.alias].enumerant),
        });
    }

    if (!extended_structs.contains(enumeration.kind)) {
        try writer.write_all("};\n");
        return;
    }

    try writer.print("\npub const Extended = union({}) {{\n", .{std.zig.fmt_id(enumeration.kind)});

    for (enum_indices) |i| {
        const enumerant = enumerants[i];
        try render_operand(writer, .@"union", enumerant.enumerant, enumerant.parameters, extended_structs);
    }

    try writer.write_all("};\n};\n");
}

fn render_bit_enum(
    writer: anytype,
    a: Allocator,
    enumeration: OperandKind,
    extended_structs: ExtendedStructSet,
) !void {
    try writer.print("pub const {} = packed struct {{\n", .{std.zig.fmt_id(enumeration.kind)});

    var flags_by_bitpos = [_]?usize{null} ** 32;
    const enumerants = enumeration.enumerants orelse return error.InvalidRegistry;

    var aliases = std.ArrayList(struct { flag: usize, alias: u5 }).init(a);
    try aliases.ensure_total_capacity(enumerants.len);

    for (enumerants, 0..) |enumerant, i| {
        if (enumerant.value != .bitflag) return error.InvalidRegistry;
        const value = try parse_hex_int(enumerant.value.bitflag);
        if (value == 0) {
            continue; // Skip 'none' items
        } else if (std.mem.eql(u8, enumerant.enumerant, "FlagIsPublic")) {
            // This flag is special and poorly defined in the json files.
            // Just skip it for now
            continue;
        }

        std.debug.assert(@pop_count(value) == 1);

        const bitpos = std.math.log2_int(u32, value);
        if (flags_by_bitpos[bitpos]) |*existing| {
            const tag_index = std.mem.index_of_diff(u8, enumerant.enumerant, enumerants[existing.*].enumerant).?;
            const enum_priority = tag_priority_score(enumerant.enumerant[tag_index..]);
            const existing_priority = tag_priority_score(enumerants[existing.*].enumerant[tag_index..]);

            if (enum_priority < existing_priority) {
                aliases.append_assume_capacity(.{ .flag = existing.*, .alias = bitpos });
                existing.* = i;
            } else {
                aliases.append_assume_capacity(.{ .flag = i, .alias = bitpos });
            }
        } else {
            flags_by_bitpos[bitpos] = i;
        }
    }

    for (flags_by_bitpos, 0..) |maybe_flag_index, bitpos| {
        if (maybe_flag_index) |flag_index| {
            try writer.print("{p_}", .{std.zig.fmt_id(enumerants[flag_index].enumerant)});
        } else {
            try writer.print("_reserved_bit_{}", .{bitpos});
        }

        try writer.write_all(": bool = false,\n");
    }

    try writer.write_byte('\n');

    for (aliases.items) |alias| {
        try writer.print("pub const {}: {} = .{{.{p_} = true}};\n", .{
            std.zig.fmt_id(enumerants[alias.flag].enumerant),
            std.zig.fmt_id(enumeration.kind),
            std.zig.fmt_id(enumerants[flags_by_bitpos[alias.alias].?].enumerant),
        });
    }

    if (!extended_structs.contains(enumeration.kind)) {
        try writer.write_all("};\n");
        return;
    }

    try writer.print("\npub const Extended = struct {{\n", .{});

    for (flags_by_bitpos, 0..) |maybe_flag_index, bitpos| {
        const flag_index = maybe_flag_index orelse {
            try writer.print("_reserved_bit_{}: bool = false,\n", .{bitpos});
            continue;
        };
        const enumerant = enumerants[flag_index];

        try render_operand(writer, .mask, enumerant.enumerant, enumerant.parameters, extended_structs);
    }

    try writer.write_all("};\n};\n");
}

fn render_operand(
    writer: anytype,
    kind: enum {
        @"union",
        instruction,
        mask,
    },
    field_name: []const u8,
    parameters: []const Operand,
    extended_structs: ExtendedStructSet,
) !void {
    if (kind == .instruction) {
        try writer.write_byte('.');
    }
    try writer.print("{}", .{std.zig.fmt_id(field_name)});
    if (parameters.len == 0) {
        switch (kind) {
            .@"union" => try writer.write_all(",\n"),
            .instruction => try writer.write_all(" => void,\n"),
            .mask => try writer.write_all(": bool = false,\n"),
        }
        return;
    }

    if (kind == .instruction) {
        try writer.write_all(" => ");
    } else {
        try writer.write_all(": ");
    }

    if (kind == .mask) {
        try writer.write_byte('?');
    }

    try writer.write_all("struct{");

    for (parameters, 0..) |param, j| {
        if (j != 0) {
            try writer.write_all(", ");
        }

        try render_field_name(writer, parameters, j);
        try writer.write_all(": ");

        if (param.quantifier) |q| {
            switch (q) {
                .@"?" => try writer.write_byte('?'),
                .@"*" => try writer.write_all("[]const "),
            }
        }

        try writer.print("{}", .{std.zig.fmt_id(param.kind)});

        if (extended_structs.contains(param.kind)) {
            try writer.write_all(".Extended");
        }

        if (param.quantifier) |q| {
            switch (q) {
                .@"?" => try writer.write_all(" = null"),
                .@"*" => try writer.write_all(" = &.{}"),
            }
        }
    }

    try writer.write_all("}");

    if (kind == .mask) {
        try writer.write_all(" = null");
    }

    try writer.write_all(",\n");
}

fn render_field_name(writer: anytype, operands: []const Operand, field_index: usize) !void {
    const operand = operands[field_index];

    // Should be enough for all names - adjust as needed.
    var name_backing_buffer: [64]u8 = undefined;
    var name_buffer = std.ArrayListUnmanaged(u8).init_buffer(&name_backing_buffer);

    derive_from_kind: {
        // Operand names are often in the json encoded as "'Name'" (with two sets of quotes).
        // Additionally, some operands have ~ in them at the end (D~ref~).
        const name = std.mem.trim(u8, operand.name, "'~");
        if (name.len == 0) {
            break :derive_from_kind;
        }

        // Some names have weird characters in them (like newlines) - skip any such ones.
        // Use the same loop to transform to snake-case.
        for (name) |c| {
            switch (c) {
                'a'...'z', '0'...'9' => name_buffer.append_assume_capacity(c),
                'A'...'Z' => name_buffer.append_assume_capacity(std.ascii.to_lower(c)),
                ' ', '~' => name_buffer.append_assume_capacity('_'),
                else => break :derive_from_kind,
            }
        }

        // Assume there are no duplicate 'name' fields.
        try writer.print("{p_}", .{std.zig.fmt_id(name_buffer.items)});
        return;
    }

    // Translate to snake case.
    name_buffer.items.len = 0;
    for (operand.kind, 0..) |c, i| {
        switch (c) {
            'a'...'z', '0'...'9' => name_buffer.append_assume_capacity(c),
            'A'...'Z' => if (i > 0 and std.ascii.is_lower(operand.kind[i - 1])) {
                name_buffer.append_slice_assume_capacity(&[_]u8{ '_', std.ascii.to_lower(c) });
            } else {
                name_buffer.append_assume_capacity(std.ascii.to_lower(c));
            },
            else => unreachable, // Assume that the name is valid C-syntax (and contains no underscores).
        }
    }

    try writer.print("{p_}", .{std.zig.fmt_id(name_buffer.items)});

    // For fields derived from type name, there could be any amount.
    // Simply check against all other fields, and if another similar one exists, add a number.
    const need_extra_index = for (operands, 0..) |other_operand, i| {
        if (i != field_index and std.mem.eql(u8, operand.kind, other_operand.kind)) {
            break true;
        }
    } else false;

    if (need_extra_index) {
        try writer.print("_{}", .{field_index});
    }
}

fn parse_hex_int(text: []const u8) !u31 {
    const prefix = "0x";
    if (!std.mem.starts_with(u8, text, prefix))
        return error.InvalidHexInt;
    return try std.fmt.parse_int(u31, text[prefix.len..], 16);
}

fn usage_and_exit(arg0: []const u8, code: u8) noreturn {
    std.io.get_std_err().writer().print(
        \\Usage: {s} <SPIRV-Headers repository path> <path/to/zig/src/codegen/spirv/extinst.zig.grammar.json>
        \\
        \\Generates Zig bindings for SPIR-V specifications found in the SPIRV-Headers
        \\repository. The result, printed to stdout, should be used to update
        \\files in src/codegen/spirv. Don't forget to format the output.
        \\
        \\<SPIRV-Headers repository path> should point to a clone of
        \\https://github.com/KhronosGroup/SPIRV-Headers/
        \\
    , .{arg0}) catch std.process.exit(1);
    std.process.exit(code);
}
