index: File.Index,

sections: std.MultiArrayList(Section) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

objc_methnames: std.ArrayListUnmanaged(u8) = .{},
objc_selrefs: [@size_of(u64)]u8 = [_]u8{0} ** @size_of(u64),

num_rebase_relocs: u32 = 0,
output_symtab_ctx: MachO.SymtabCtx = .{},

pub fn deinit(self: *InternalObject, allocator: Allocator) void {
    for (self.sections.items(.relocs)) |*relocs| {
        relocs.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.atoms.deinit(allocator);
    self.symbols.deinit(allocator);
    self.objc_methnames.deinit(allocator);
}

pub fn add_symbol(self: *InternalObject, name: [:0]const u8, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.comp.gpa;
    try self.symbols.ensure_unused_capacity(gpa, 1);
    const off = try macho_file.strings.insert(gpa, name);
    const gop = try macho_file.get_or_create_global(off);
    self.symbols.add_one_assume_capacity().* = gop.index;
    const sym = macho_file.get_symbol(gop.index);
    sym.file = self.index;
    sym.value = 0;
    sym.atom = 0;
    sym.nlist_idx = 0;
    sym.flags = .{ .global = true };
    return gop.index;
}

/// Creates a fake input sections __TEXT,__objc_methname and __DATA,__objc_selrefs.
pub fn add_objc_msgsend_sections(self: *InternalObject, sym_name: []const u8, macho_file: *MachO) !Atom.Index {
    const methname_atom_index = try self.add_objc_methname_section(sym_name, macho_file);
    return try self.add_objc_selrefs_section(methname_atom_index, macho_file);
}

fn add_objc_methname_section(self: *InternalObject, methname: []const u8, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.comp.gpa;
    const atom_index = try macho_file.add_atom();
    try self.atoms.append(gpa, atom_index);

    const atom = macho_file.get_atom(atom_index).?;
    atom.atom_index = atom_index;
    atom.file = self.index;
    atom.size = methname.len + 1;
    atom.alignment = .@"1";

    const n_sect = try self.add_section(gpa, "__TEXT", "__objc_methname");
    const sect = &self.sections.items(.header)[n_sect];
    sect.flags = macho.S_CSTRING_LITERALS;
    sect.size = atom.size;
    sect.@"align" = 0;
    atom.n_sect = n_sect;
    self.sections.items(.extra)[n_sect].is_objc_methname = true;

    sect.offset = @int_cast(self.objc_methnames.items.len);
    try self.objc_methnames.ensure_unused_capacity(gpa, methname.len + 1);
    self.objc_methnames.writer(gpa).print("{s}\x00", .{methname}) catch unreachable;

    return atom_index;
}

fn add_objc_selrefs_section(self: *InternalObject, methname_atom_index: Atom.Index, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.comp.gpa;
    const atom_index = try macho_file.add_atom();
    try self.atoms.append(gpa, atom_index);

    const atom = macho_file.get_atom(atom_index).?;
    atom.atom_index = atom_index;
    atom.file = self.index;
    atom.size = @size_of(u64);
    atom.alignment = .@"8";

    const n_sect = try self.add_section(gpa, "__DATA", "__objc_selrefs");
    const sect = &self.sections.items(.header)[n_sect];
    sect.flags = macho.S_LITERAL_POINTERS | macho.S_ATTR_NO_DEAD_STRIP;
    sect.offset = 0;
    sect.size = atom.size;
    sect.@"align" = 3;
    atom.n_sect = n_sect;
    self.sections.items(.extra)[n_sect].is_objc_selref = true;

    const relocs = &self.sections.items(.relocs)[n_sect];
    try relocs.ensure_unused_capacity(gpa, 1);
    relocs.append_assume_capacity(.{
        .tag = .local,
        .offset = 0,
        .target = methname_atom_index,
        .addend = 0,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .length = 3,
            .symbolnum = 0, // Only used when synthesising unwind records so can be anything
            .has_subtractor = false,
        },
    });
    try atom.add_extra(.{ .rel_index = 0, .rel_count = 1 }, macho_file);
    atom.flags.relocs = true;
    self.num_rebase_relocs += 1;

    return atom_index;
}

pub fn resolve_literals(self: InternalObject, lp: *MachO.LiteralPool, macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const slice = self.sections.slice();
    for (slice.items(.header), self.atoms.items, 0..) |header, atom_index, n_sect| {
        if (Object.is_cstring_literal(header) or Object.is_fixed_size_literal(header)) {
            const data = try self.get_section_data(@int_cast(n_sect));
            const atom = macho_file.get_atom(atom_index).?;
            const res = try lp.insert(gpa, header.type(), data);
            if (!res.found_existing) {
                res.atom.* = atom_index;
            }
            atom.flags.literal_pool = true;
            try atom.add_extra(.{ .literal_index = res.index }, macho_file);
        } else if (Object.is_ptr_literal(header)) {
            const atom = macho_file.get_atom(atom_index).?;
            const relocs = atom.get_relocs(macho_file);
            assert(relocs.len == 1);
            const rel = relocs[0];
            assert(rel.tag == .local);
            const target = macho_file.get_atom(rel.target).?;
            const addend = std.math.cast(u32, rel.addend) orelse return error.Overflow;
            const target_size = std.math.cast(usize, target.size) orelse return error.Overflow;
            try buffer.ensure_unused_capacity(target_size);
            buffer.resize(target_size) catch unreachable;
            try target.get_data(macho_file, buffer.items);
            const res = try lp.insert(gpa, header.type(), buffer.items[addend..]);
            buffer.clear_retaining_capacity();
            if (!res.found_existing) {
                res.atom.* = atom_index;
            }
            atom.flags.literal_pool = true;
            try atom.add_extra(.{ .literal_index = res.index }, macho_file);
        }
    }
}

pub fn dedup_literals(self: InternalObject, lp: MachO.LiteralPool, macho_file: *MachO) void {
    for (self.atoms.items) |atom_index| {
        const atom = macho_file.get_atom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        if (!atom.flags.relocs) continue;

        const relocs = blk: {
            const extra = atom.get_extra(macho_file).?;
            const relocs = self.sections.items(.relocs)[atom.n_sect].items;
            break :blk relocs[extra.rel_index..][0..extra.rel_count];
        };
        for (relocs) |*rel| switch (rel.tag) {
            .local => {
                const target = macho_file.get_atom(rel.target).?;
                if (target.get_literal_pool_index(macho_file)) |lp_index| {
                    const lp_atom = lp.get_atom(lp_index, macho_file);
                    if (target.atom_index != lp_atom.atom_index) {
                        lp_atom.alignment = lp_atom.alignment.max(target.alignment);
                        target.flags.alive = false;
                        rel.target = lp_atom.atom_index;
                    }
                }
            },
            .@"extern" => {
                const target_sym = rel.get_target_symbol(macho_file);
                if (target_sym.get_atom(macho_file)) |target_atom| {
                    if (target_atom.get_literal_pool_index(macho_file)) |lp_index| {
                        const lp_atom = lp.get_atom(lp_index, macho_file);
                        if (target_atom.atom_index != lp_atom.atom_index) {
                            lp_atom.alignment = lp_atom.alignment.max(target_atom.alignment);
                            target_atom.flags.alive = false;
                            target_sym.atom = lp_atom.atom_index;
                        }
                    }
                }
            },
        };
    }

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        if (!sym.flags.objc_stubs) continue;
        var extra = sym.get_extra(macho_file).?;
        const atom = macho_file.get_atom(extra.objc_selrefs).?;
        if (atom.get_literal_pool_index(macho_file)) |lp_index| {
            const lp_atom = lp.get_atom(lp_index, macho_file);
            if (atom.atom_index != lp_atom.atom_index) {
                lp_atom.alignment = lp_atom.alignment.max(atom.alignment);
                atom.flags.alive = false;
                extra.objc_selrefs = lp_atom.atom_index;
                sym.set_extra(extra, macho_file);
            }
        }
    }
}

pub fn calc_symtab_size(self: *InternalObject, macho_file: *MachO) !void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        if (sym.get_file(macho_file)) |file| if (file.get_index() != self.index) continue;
        sym.flags.output_symtab = true;
        if (sym.is_local()) {
            try sym.add_extra(.{ .symtab = self.output_symtab_ctx.nlocals }, macho_file);
            self.output_symtab_ctx.nlocals += 1;
        } else if (sym.flags.@"export") {
            try sym.add_extra(.{ .symtab = self.output_symtab_ctx.nexports }, macho_file);
            self.output_symtab_ctx.nexports += 1;
        } else {
            assert(sym.flags.import);
            try sym.add_extra(.{ .symtab = self.output_symtab_ctx.nimports }, macho_file);
            self.output_symtab_ctx.nimports += 1;
        }
        self.output_symtab_ctx.strsize += @as(u32, @int_cast(sym.get_name(macho_file).len + 1));
    }
}

pub fn write_symtab(self: InternalObject, macho_file: *MachO, ctx: anytype) void {
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        if (sym.get_file(macho_file)) |file| if (file.get_index() != self.index) continue;
        const idx = sym.get_output_symtab_index(macho_file) orelse continue;
        const n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
        ctx.strtab.append_slice_assume_capacity(sym.get_name(macho_file));
        ctx.strtab.append_assume_capacity(0);
        const out_sym = &ctx.symtab.items[idx];
        out_sym.n_strx = n_strx;
        sym.set_output_sym(macho_file, out_sym);
    }
}

fn add_section(self: *InternalObject, allocator: Allocator, segname: []const u8, sectname: []const u8) !u32 {
    const n_sect = @as(u32, @int_cast(try self.sections.add_one(allocator)));
    self.sections.set(n_sect, .{
        .header = .{
            .sectname = MachO.make_static_string(sectname),
            .segname = MachO.make_static_string(segname),
        },
    });
    return n_sect;
}

fn get_section_data(self: *const InternalObject, index: u32) error{Overflow}![]const u8 {
    const slice = self.sections.slice();
    assert(index < slice.items(.header).len);
    const sect = slice.items(.header)[index];
    const extra = slice.items(.extra)[index];
    if (extra.is_objc_methname) {
        const size = std.math.cast(usize, sect.size) orelse return error.Overflow;
        return self.objc_methnames.items[sect.offset..][0..size];
    } else if (extra.is_objc_selref)
        return &self.objc_selrefs
    else
        @panic("ref to non-existent section");
}

pub fn get_atom_data(self: *const InternalObject, atom: Atom, buffer: []u8) error{Overflow}!void {
    assert(buffer.len == atom.size);
    const data = try self.get_section_data(atom.n_sect);
    const off = std.math.cast(usize, atom.off) orelse return error.Overflow;
    const size = std.math.cast(usize, atom.size) orelse return error.Overflow;
    @memcpy(buffer, data[off..][0..size]);
}

pub fn get_atom_relocs(self: *const InternalObject, atom: Atom, macho_file: *MachO) []const Relocation {
    if (!atom.flags.relocs) return &[0]Relocation{};
    const extra = atom.get_extra(macho_file).?;
    const relocs = self.sections.items(.relocs)[atom.n_sect];
    return relocs.items[extra.rel_index..][0..extra.rel_count];
}

pub fn get_string(self: InternalObject, off: u32) [:0]const u8 {
    _ = self;
    _ = off;
    // We don't have any local strings for synthetic atoms.
    return "";
}

pub fn as_file(self: *InternalObject) File {
    return .{ .internal = self };
}

const FormatContext = struct {
    self: *InternalObject,
    macho_file: *MachO,
};

pub fn fmt_atoms(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(format_atoms) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

fn format_atoms(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.write_all("  atoms\n");
    for (ctx.self.atoms.items) |atom_index| {
        const atom = ctx.macho_file.get_atom(atom_index).?;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

pub fn fmt_symtab(self: *InternalObject, macho_file: *MachO) std.fmt.Formatter(format_symtab) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

fn format_symtab(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.write_all("  symbols\n");
    for (ctx.self.symbols.items) |index| {
        const global = ctx.macho_file.get_symbol(index);
        try writer.print("    {}\n", .{global.fmt(ctx.macho_file)});
    }
}

const Section = struct {
    header: macho.section_64,
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
    extra: Extra = .{},

    const Extra = packed struct {
        is_objc_methname: bool = false,
        is_objc_selref: bool = false,
    };
};

const assert = std.debug.assert;
const macho = std.macho;
const mem = std.mem;
const std = @import("std");

const Allocator = std.mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const InternalObject = @This();
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
