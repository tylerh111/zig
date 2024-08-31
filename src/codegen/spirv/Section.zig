//! Represents a section or subsection of instructions in a SPIR-V binary. Instructions can be append
//! to separate sections, which can then later be merged into the final binary.
const Section = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const spec = @import("spec.zig");
const Word = spec.Word;
const DoubleWord = std.meta.Int(.unsigned, @bitSizeOf(Word) * 2);
const Log2Word = std.math.Log2Int(Word);

const Opcode = spec.Opcode;

/// The instructions in this section. Memory is owned by the Module
/// externally associated to this Section.
instructions: std.ArrayListUnmanaged(Word) = .{},

pub fn deinit(section: *Section, allocator: Allocator) void {
    section.instructions.deinit(allocator);
    section.* = undefined;
}

/// Clear the instructions in this section
pub fn reset(section: *Section) void {
    section.instructions.items.len = 0;
}

pub fn to_words(section: Section) []Word {
    return section.instructions.items;
}

/// Append the instructions from another section into this section.
pub fn append(section: *Section, allocator: Allocator, other_section: Section) !void {
    try section.instructions.append_slice(allocator, other_section.instructions.items);
}

/// Ensure capacity of at least `capacity` more words in this section.
pub fn ensure_unused_capacity(section: *Section, allocator: Allocator, capacity: usize) !void {
    try section.instructions.ensure_unused_capacity(allocator, capacity);
}

/// Write an instruction and size, operands are to be inserted manually.
pub fn emit_raw(
    section: *Section,
    allocator: Allocator,
    opcode: Opcode,
    operand_words: usize, // opcode itself not included
) !void {
    const word_count = 1 + operand_words;
    try section.instructions.ensure_unused_capacity(allocator, word_count);
    section.write_word((@as(Word, @int_cast(word_count << 16))) | @int_from_enum(opcode));
}

/// Write an entire instruction, including all operands
pub fn emit_raw_instruction(
    section: *Section,
    allocator: Allocator,
    opcode: Opcode,
    operands: []const Word,
) !void {
    try section.emit_raw(allocator, opcode, operands.len);
    section.write_words(operands);
}

pub fn emit(
    section: *Section,
    allocator: Allocator,
    comptime opcode: spec.Opcode,
    operands: opcode.Operands(),
) !void {
    const word_count = instruction_size(opcode, operands);
    try section.instructions.ensure_unused_capacity(allocator, word_count);
    section.write_word(@as(Word, @int_cast(word_count << 16)) | @int_from_enum(opcode));
    section.write_operands(opcode.Operands(), operands);
}

pub fn emit_branch(
    section: *Section,
    allocator: Allocator,
    target_label: spec.IdRef,
) !void {
    try section.emit(allocator, .OpBranch, .{
        .target_label = target_label,
    });
}

pub fn emit_spec_constant_op(
    section: *Section,
    allocator: Allocator,
    comptime opcode: spec.Opcode,
    operands: opcode.Operands(),
) !void {
    const word_count = operands_size(opcode.Operands(), operands);
    try section.emit_raw(allocator, .OpSpecConstantOp, 1 + word_count);
    section.write_operand(spec.IdRef, operands.id_result_type);
    section.write_operand(spec.IdRef, operands.id_result);
    section.write_operand(Opcode, opcode);

    const fields = @typeInfo(opcode.Operands()).Struct.fields;
    // First 2 fields are always id_result_type and id_result.
    inline for (fields[2..]) |field| {
        section.write_operand(field.type, @field(operands, field.name));
    }
}

pub fn write_word(section: *Section, word: Word) void {
    section.instructions.append_assume_capacity(word);
}

pub fn write_words(section: *Section, words: []const Word) void {
    section.instructions.append_slice_assume_capacity(words);
}

pub fn write_double_word(section: *Section, dword: DoubleWord) void {
    section.write_words(&.{
        @truncate(dword),
        @truncate(dword >> @bitSizeOf(Word)),
    });
}

fn write_operands(section: *Section, comptime Operands: type, operands: Operands) void {
    const fields = switch (@typeInfo(Operands)) {
        .Struct => |info| info.fields,
        .Void => return,
        else => unreachable,
    };

    inline for (fields) |field| {
        section.write_operand(field.type, @field(operands, field.name));
    }
}

pub fn write_operand(section: *Section, comptime Operand: type, operand: Operand) void {
    switch (Operand) {
        spec.IdResult => section.write_word(@int_from_enum(operand)),

        spec.LiteralInteger => section.write_word(operand),

        spec.LiteralString => section.write_string(operand),

        spec.LiteralContextDependentNumber => section.write_context_dependent_number(operand),

        spec.LiteralExtInstInteger => section.write_word(operand.inst),

        // TODO: Where this type is used (OpSpecConstantOp) is currently not correct in the spec json,
        // so it most likely needs to be altered into something that can actually describe the entire
        // instruction in which it is used.
        spec.LiteralSpecConstantOpInteger => section.write_word(@int_from_enum(operand.opcode)),

        spec.PairLiteralIntegerIdRef => section.write_words(&.{ operand.value, @enumFromInt(operand.label) }),
        spec.PairIdRefLiteralInteger => section.write_words(&.{ @int_from_enum(operand.target), operand.member }),
        spec.PairIdRefIdRef => section.write_words(&.{ @int_from_enum(operand[0]), @int_from_enum(operand[1]) }),

        else => switch (@typeInfo(Operand)) {
            .Enum => section.write_word(@int_from_enum(operand)),
            .Optional => |info| if (operand) |child| {
                section.write_operand(info.child, child);
            },
            .Pointer => |info| {
                std.debug.assert(info.size == .Slice); // Should be no other pointer types in the spec.
                for (operand) |item| {
                    section.write_operand(info.child, item);
                }
            },
            .Struct => |info| {
                if (info.layout == .@"packed") {
                    section.write_word(@as(Word, @bit_cast(operand)));
                } else {
                    section.write_extended_mask(Operand, operand);
                }
            },
            .Union => section.write_extended_union(Operand, operand),
            else => unreachable,
        },
    }
}

fn write_string(section: *Section, str: []const u8) void {
    // TODO: Not actually sure whether this is correct for big-endian.
    // See https://www.khronos.org/registry/spir-v/specs/unified1/SPIRV.html#Literal
    const zero_terminated_len = str.len + 1;
    var i: usize = 0;
    while (i < zero_terminated_len) : (i += @size_of(Word)) {
        var word: Word = 0;

        var j: usize = 0;
        while (j < @size_of(Word) and i + j < str.len) : (j += 1) {
            word |= @as(Word, str[i + j]) << @as(Log2Word, @int_cast(j * @bitSizeOf(u8)));
        }

        section.instructions.append_assume_capacity(word);
    }
}

fn write_context_dependent_number(section: *Section, operand: spec.LiteralContextDependentNumber) void {
    switch (operand) {
        .int32 => |int| section.write_word(@bit_cast(int)),
        .uint32 => |int| section.write_word(@bit_cast(int)),
        .int64 => |int| section.write_double_word(@bit_cast(int)),
        .uint64 => |int| section.write_double_word(@bit_cast(int)),
        .float32 => |float| section.write_word(@bit_cast(float)),
        .float64 => |float| section.write_double_word(@bit_cast(float)),
    }
}

fn write_extended_mask(section: *Section, comptime Operand: type, operand: Operand) void {
    var mask: Word = 0;
    inline for (@typeInfo(Operand).Struct.fields, 0..) |field, bit| {
        switch (@typeInfo(field.type)) {
            .Optional => if (@field(operand, field.name) != null) {
                mask |= 1 << @as(u5, @int_cast(bit));
            },
            .Bool => if (@field(operand, field.name)) {
                mask |= 1 << @as(u5, @int_cast(bit));
            },
            else => unreachable,
        }
    }

    section.write_word(mask);

    inline for (@typeInfo(Operand).Struct.fields) |field| {
        switch (@typeInfo(field.type)) {
            .Optional => |info| if (@field(operand, field.name)) |child| {
                section.write_operands(info.child, child);
            },
            .Bool => {},
            else => unreachable,
        }
    }
}

fn write_extended_union(section: *Section, comptime Operand: type, operand: Operand) void {
    const tag = std.meta.active_tag(operand);
    section.write_word(@int_from_enum(tag));

    inline for (@typeInfo(Operand).Union.fields) |field| {
        if (@field(Operand, field.name) == tag) {
            section.write_operands(field.type, @field(operand, field.name));
            return;
        }
    }
    unreachable;
}

fn instruction_size(comptime opcode: spec.Opcode, operands: opcode.Operands()) usize {
    return 1 + operands_size(opcode.Operands(), operands);
}

fn operands_size(comptime Operands: type, operands: Operands) usize {
    const fields = switch (@typeInfo(Operands)) {
        .Struct => |info| info.fields,
        .Void => return 0,
        else => unreachable,
    };

    var total: usize = 0;
    inline for (fields) |field| {
        total += operand_size(field.type, @field(operands, field.name));
    }

    return total;
}

fn operand_size(comptime Operand: type, operand: Operand) usize {
    return switch (Operand) {
        spec.IdResult,
        spec.LiteralInteger,
        spec.LiteralExtInstInteger,
        => 1,

        spec.LiteralString => std.math.div_ceil(usize, operand.len + 1, @size_of(Word)) catch unreachable, // Add one for zero-terminator

        spec.LiteralContextDependentNumber => switch (operand) {
            .int32, .uint32, .float32 => 1,
            .int64, .uint64, .float64 => 2,
        },

        // TODO: Where this type is used (OpSpecConstantOp) is currently not correct in the spec
        // json, so it most likely needs to be altered into something that can actually
        // describe the entire insturction in which it is used.
        spec.LiteralSpecConstantOpInteger => 1,

        spec.PairLiteralIntegerIdRef,
        spec.PairIdRefLiteralInteger,
        spec.PairIdRefIdRef,
        => 2,

        else => switch (@typeInfo(Operand)) {
            .Enum => 1,
            .Optional => |info| if (operand) |child| operand_size(info.child, child) else 0,
            .Pointer => |info| blk: {
                std.debug.assert(info.size == .Slice); // Should be no other pointer types in the spec.
                var total: usize = 0;
                for (operand) |item| {
                    total += operand_size(info.child, item);
                }
                break :blk total;
            },
            .Struct => |info| if (info.layout == .@"packed") 1 else extended_mask_size(Operand, operand),
            .Union => extended_union_size(Operand, operand),
            else => unreachable,
        },
    };
}

fn extended_mask_size(comptime Operand: type, operand: Operand) usize {
    var total: usize = 0;
    var any_set = false;
    inline for (@typeInfo(Operand).Struct.fields) |field| {
        switch (@typeInfo(field.type)) {
            .Optional => |info| if (@field(operand, field.name)) |child| {
                total += operands_size(info.child, child);
                any_set = true;
            },
            .Bool => if (@field(operand, field.name)) {
                any_set = true;
            },
            else => unreachable,
        }
    }
    return total + 1; // Add one for the mask itself.
}

fn extended_union_size(comptime Operand: type, operand: Operand) usize {
    const tag = std.meta.active_tag(operand);
    inline for (@typeInfo(Operand).Union.fields) |field| {
        if (@field(Operand, field.name) == tag) {
            // Add one for the tag itself.
            return 1 + operands_size(field.type, @field(operand, field.name));
        }
    }
    unreachable;
}

test "SPIR-V Section emit() - no operands" {
    var section = Section{};
    defer section.deinit(std.testing.allocator);

    try section.emit(std.testing.allocator, .OpNop, {});

    try testing.expect(section.instructions.items[0] == (@as(Word, 1) << 16) | @int_from_enum(Opcode.OpNop));
}

test "SPIR-V Section emit() - simple" {
    var section = Section{};
    defer section.deinit(std.testing.allocator);

    try section.emit(std.testing.allocator, .OpUndef, .{
        .id_result_type = @enumFromInt(0),
        .id_result = @enumFromInt(1),
    });

    try testing.expect_equal_slices(Word, &.{
        (@as(Word, 3) << 16) | @int_from_enum(Opcode.OpUndef),
        0,
        1,
    }, section.instructions.items);
}

test "SPIR-V Section emit() - string" {
    var section = Section{};
    defer section.deinit(std.testing.allocator);

    try section.emit(std.testing.allocator, .OpSource, .{
        .source_language = .Unknown,
        .version = 123,
        .file = @enumFromInt(256),
        .source = "pub fn main() void {}",
    });

    try testing.expect_equal_slices(Word, &.{
        (@as(Word, 10) << 16) | @int_from_enum(Opcode.OpSource),
        @int_from_enum(spec.SourceLanguage.Unknown),
        123,
        456,
        std.mem.bytes_to_value(Word, "pub "),
        std.mem.bytes_to_value(Word, "fn m"),
        std.mem.bytes_to_value(Word, "ain("),
        std.mem.bytes_to_value(Word, ") vo"),
        std.mem.bytes_to_value(Word, "id {"),
        std.mem.bytes_to_value(Word, "}\x00\x00\x00"),
    }, section.instructions.items);
}

test "SPIR-V Section emit() - extended mask" {
    if (@import("builtin").zig_backend == .stage1) return error.SkipZigTest;

    var section = Section{};
    defer section.deinit(std.testing.allocator);

    try section.emit(std.testing.allocator, .OpLoopMerge, .{
        .merge_block = @enumFromInt(10),
        .continue_target = @enumFromInt(20),
        .loop_control = .{
            .Unroll = true,
            .DependencyLength = .{
                .literal_integer = 2,
            },
        },
    });

    try testing.expect_equal_slices(Word, &.{
        (@as(Word, 5) << 16) | @int_from_enum(Opcode.OpLoopMerge),
        10,
        20,
        @as(Word, @bit_cast(spec.LoopControl{ .Unroll = true, .DependencyLength = true })),
        2,
    }, section.instructions.items);
}

test "SPIR-V Section emit() - extended union" {
    var section = Section{};
    defer section.deinit(std.testing.allocator);

    try section.emit(std.testing.allocator, .OpExecutionMode, .{
        .entry_point = @enumFromInt(888),
        .mode = .{
            .LocalSize = .{ .x_size = 4, .y_size = 8, .z_size = 16 },
        },
    });

    try testing.expect_equal_slices(Word, &.{
        (@as(Word, 6) << 16) | @int_from_enum(Opcode.OpExecutionMode),
        888,
        @int_from_enum(spec.ExecutionMode.LocalSize),
        4,
        8,
        16,
    }, section.instructions.items);
}
