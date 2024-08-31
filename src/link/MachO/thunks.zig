pub fn create_thunks(sect_id: u8, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const slice = macho_file.sections.slice();
    const header = &slice.items(.header)[sect_id];
    const atoms = slice.items(.atoms)[sect_id].items;
    assert(atoms.len > 0);

    for (atoms) |atom_index| {
        macho_file.get_atom(atom_index).?.value = @bit_cast(@as(i64, -1));
    }

    var i: usize = 0;
    while (i < atoms.len) {
        const start = i;
        const start_atom = macho_file.get_atom(atoms[start]).?;
        assert(start_atom.flags.alive);
        start_atom.value = try advance(header, start_atom.size, start_atom.alignment);
        i += 1;

        while (i < atoms.len and
            header.size - start_atom.value < max_allowed_distance) : (i += 1)
        {
            const atom_index = atoms[i];
            const atom = macho_file.get_atom(atom_index).?;
            assert(atom.flags.alive);
            atom.value = try advance(header, atom.size, atom.alignment);
        }

        // Insert a thunk at the group end
        const thunk_index = try macho_file.add_thunk();
        const thunk = macho_file.get_thunk(thunk_index);
        thunk.out_n_sect = sect_id;

        // Scan relocs in the group and create trampolines for any unreachable callsite
        for (atoms[start..i]) |atom_index| {
            const atom = macho_file.get_atom(atom_index).?;
            log.debug("atom({d}) {s}", .{ atom_index, atom.get_name(macho_file) });
            for (atom.get_relocs(macho_file)) |rel| {
                if (rel.type != .branch) continue;
                if (is_reachable(atom, rel, macho_file)) continue;
                try thunk.symbols.put(gpa, rel.target, {});
            }
            try atom.add_extra(.{ .thunk = thunk_index }, macho_file);
            atom.flags.thunk = true;
        }

        thunk.value = try advance(header, thunk.size(), .@"4");

        log.debug("thunk({d}) : {}", .{ thunk_index, thunk.fmt(macho_file) });
    }
}

fn advance(sect: *macho.section_64, size: u64, alignment: Atom.Alignment) !u64 {
    const offset = alignment.forward(sect.size);
    const padding = offset - sect.size;
    sect.size += padding + size;
    sect.@"align" = @max(sect.@"align", alignment.to_log2_units());
    return offset;
}

fn is_reachable(atom: *const Atom, rel: Relocation, macho_file: *MachO) bool {
    const target = rel.get_target_symbol(macho_file);
    if (target.flags.stubs or target.flags.objc_stubs) return false;
    if (atom.out_n_sect != target.out_n_sect) return false;
    const target_atom = target.get_atom(macho_file).?;
    if (target_atom.value == @as(u64, @bit_cast(@as(i64, -1)))) return false;
    const saddr = @as(i64, @int_cast(atom.get_address(macho_file))) + @as(i64, @int_cast(rel.offset - atom.off));
    const taddr: i64 = @int_cast(rel.get_target_address(macho_file));
    _ = math.cast(i28, taddr + rel.addend - saddr) orelse return false;
    return true;
}

pub const Thunk = struct {
    value: u64 = 0,
    out_n_sect: u8 = 0,
    symbols: std.AutoArrayHashMapUnmanaged(Symbol.Index, void) = .{},

    pub fn deinit(thunk: *Thunk, allocator: Allocator) void {
        thunk.symbols.deinit(allocator);
    }

    pub fn size(thunk: Thunk) usize {
        return thunk.symbols.keys().len * trampoline_size;
    }

    pub fn get_address(thunk: Thunk, macho_file: *MachO) u64 {
        const header = macho_file.sections.items(.header)[thunk.out_n_sect];
        return header.addr + thunk.value;
    }

    pub fn get_target_address(thunk: Thunk, sym_index: Symbol.Index, macho_file: *MachO) u64 {
        return thunk.get_address(macho_file) + thunk.symbols.get_index(sym_index).? * trampoline_size;
    }

    pub fn write(thunk: Thunk, macho_file: *MachO, writer: anytype) !void {
        for (thunk.symbols.keys(), 0..) |sym_index, i| {
            const sym = macho_file.get_symbol(sym_index);
            const saddr = thunk.get_address(macho_file) + i * trampoline_size;
            const taddr = sym.get_address(.{}, macho_file);
            const pages = try aarch64.calc_number_of_pages(@int_cast(saddr), @int_cast(taddr));
            try writer.write_int(u32, aarch64.Instruction.adrp(.x16, pages).to_u32(), .little);
            const off: u12 = @truncate(taddr);
            try writer.write_int(u32, aarch64.Instruction.add(.x16, .x16, off, false).to_u32(), .little);
            try writer.write_int(u32, aarch64.Instruction.br(.x16).to_u32(), .little);
        }
    }

    pub fn format(
        thunk: Thunk,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = thunk;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compile_error("do not format Thunk directly");
    }

    pub fn fmt(thunk: Thunk, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .thunk = thunk,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        thunk: Thunk,
        macho_file: *MachO,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = unused_fmt_string;
        const thunk = ctx.thunk;
        const macho_file = ctx.macho_file;
        try writer.print("@{x} : size({x})\n", .{ thunk.value, thunk.size() });
        for (thunk.symbols.keys()) |index| {
            const sym = macho_file.get_symbol(index);
            try writer.print("  %{d} : {s} : @{x}\n", .{ index, sym.get_name(macho_file), sym.value });
        }
    }

    const trampoline_size = 3 * @size_of(u32);

    pub const Index = u32;
};

/// Branch instruction has 26 bits immediate but is 4 byte aligned.
const jump_bits = @bitSizeOf(i28);
const max_distance = (1 << (jump_bits - 1));

/// A branch will need an extender if its target is larger than
/// `2^(jump_bits - 1) - margin` where margin is some arbitrary number.
/// mold uses 5MiB margin, while ld64 uses 4MiB margin. We will follow mold
/// and assume margin to be 5MiB.
const max_allowed_distance = max_distance - 0x500_000;

const aarch64 = @import("../aarch64.zig");
const assert = std.debug.assert;
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const std = @import("std");
const trace = @import("../../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const MachO = @import("../MachO.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
