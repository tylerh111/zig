pub fn gc_atoms(macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;

    var objects = try std.ArrayList(File.Index).init_capacity(gpa, macho_file.objects.items.len + 1);
    defer objects.deinit();
    for (macho_file.objects.items) |index| objects.append_assume_capacity(index);
    if (macho_file.internal_object) |index| objects.append_assume_capacity(index);

    var roots = std.ArrayList(*Atom).init(gpa);
    defer roots.deinit();

    try collect_roots(&roots, objects.items, macho_file);
    mark(roots.items, objects.items, macho_file);
    prune(objects.items, macho_file);
}

fn collect_roots(roots: *std.ArrayList(*Atom), objects: []const File.Index, macho_file: *MachO) !void {
    for (objects) |index| {
        const object = macho_file.get_file(index).?;
        for (object.get_symbols()) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const file = sym.get_file(macho_file) orelse continue;
            if (file.get_index() != index) continue;
            if (sym.flags.no_dead_strip or (macho_file.base.is_dyn_lib() and sym.visibility == .global))
                try mark_symbol(sym, roots, macho_file);
        }

        for (object.get_atoms()) |atom_index| {
            const atom = macho_file.get_atom(atom_index).?;
            const isec = atom.get_input_section(macho_file);
            switch (isec.type()) {
                macho.S_MOD_INIT_FUNC_POINTERS,
                macho.S_MOD_TERM_FUNC_POINTERS,
                => if (mark_atom(atom)) try roots.append(atom),

                else => if (isec.is_dont_dead_strip() and mark_atom(atom)) {
                    try roots.append(atom);
                },
            }
        }
    }

    for (macho_file.objects.items) |index| {
        for (macho_file.get_file(index).?.object.unwind_records.items) |cu_index| {
            const cu = macho_file.get_unwind_record(cu_index);
            if (!cu.alive) continue;
            if (cu.get_fde(macho_file)) |fde| {
                if (fde.get_cie(macho_file).get_personality(macho_file)) |sym| try mark_symbol(sym, roots, macho_file);
            } else if (cu.get_personality(macho_file)) |sym| try mark_symbol(sym, roots, macho_file);
        }
    }

    for (macho_file.undefined_symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        try mark_symbol(sym, roots, macho_file);
    }

    for (&[_]?Symbol.Index{
        macho_file.entry_index,
        macho_file.dyld_stub_binder_index,
        macho_file.objc_msg_send_index,
    }) |index| {
        if (index) |idx| {
            const sym = macho_file.get_symbol(idx);
            try mark_symbol(sym, roots, macho_file);
        }
    }
}

fn mark_symbol(sym: *Symbol, roots: *std.ArrayList(*Atom), macho_file: *MachO) !void {
    const atom = sym.get_atom(macho_file) orelse return;
    if (mark_atom(atom)) try roots.append(atom);
}

fn mark_atom(atom: *Atom) bool {
    const already_visited = atom.flags.visited;
    atom.flags.visited = true;
    return atom.flags.alive and !already_visited;
}

fn mark(roots: []*Atom, objects: []const File.Index, macho_file: *MachO) void {
    for (roots) |root| {
        mark_live(root, macho_file);
    }

    var loop: bool = true;
    while (loop) {
        loop = false;

        for (objects) |index| {
            for (macho_file.get_file(index).?.get_atoms()) |atom_index| {
                const atom = macho_file.get_atom(atom_index).?;
                const isec = atom.get_input_section(macho_file);
                if (isec.is_dont_dead_strip_if_references_live() and
                    !(mem.eql(u8, isec.sect_name(), "__eh_frame") or
                    mem.eql(u8, isec.sect_name(), "__compact_unwind") or
                    isec.attrs() & macho.S_ATTR_DEBUG != 0) and
                    !atom.flags.alive and refers_live(atom, macho_file))
                {
                    mark_live(atom, macho_file);
                    loop = true;
                }
            }
        }
    }
}

fn mark_live(atom: *Atom, macho_file: *MachO) void {
    assert(atom.flags.visited);
    atom.flags.alive = true;
    track_live_log.debug("{}marking live atom({d},{s})", .{
        track_live_level,
        atom.atom_index,
        atom.get_name(macho_file),
    });

    if (build_options.enable_logging)
        track_live_level.incr();

    for (atom.get_relocs(macho_file)) |rel| {
        const target_atom = switch (rel.tag) {
            .local => rel.get_target_atom(macho_file),
            .@"extern" => rel.get_target_symbol(macho_file).get_atom(macho_file),
        };
        if (target_atom) |ta| {
            if (mark_atom(ta)) mark_live(ta, macho_file);
        }
    }

    for (atom.get_unwind_records(macho_file)) |cu_index| {
        const cu = macho_file.get_unwind_record(cu_index);
        const cu_atom = cu.get_atom(macho_file);
        if (mark_atom(cu_atom)) mark_live(cu_atom, macho_file);

        if (cu.get_lsda_atom(macho_file)) |lsda| {
            if (mark_atom(lsda)) mark_live(lsda, macho_file);
        }
        if (cu.get_fde(macho_file)) |fde| {
            const fde_atom = fde.get_atom(macho_file);
            if (mark_atom(fde_atom)) mark_live(fde_atom, macho_file);

            if (fde.get_lsda_atom(macho_file)) |lsda| {
                if (mark_atom(lsda)) mark_live(lsda, macho_file);
            }
        }
    }
}

fn refers_live(atom: *Atom, macho_file: *MachO) bool {
    for (atom.get_relocs(macho_file)) |rel| {
        const target_atom = switch (rel.tag) {
            .local => rel.get_target_atom(macho_file),
            .@"extern" => rel.get_target_symbol(macho_file).get_atom(macho_file),
        };
        if (target_atom) |ta| {
            if (ta.flags.alive) return true;
        }
    }
    return false;
}

fn prune(objects: []const File.Index, macho_file: *MachO) void {
    for (objects) |index| {
        for (macho_file.get_file(index).?.get_atoms()) |atom_index| {
            const atom = macho_file.get_atom(atom_index).?;
            if (atom.flags.alive and !atom.flags.visited) {
                atom.flags.alive = false;
                atom.mark_unwind_records_dead(macho_file);
            }
        }
    }
}

const Level = struct {
    value: usize = 0,

    fn incr(self: *@This()) void {
        self.value += 1;
    }

    pub fn format(
        self: *const @This(),
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.write_byte_ntimes(' ', self.value);
    }
};

var track_live_level: Level = .{};

const assert = std.debug.assert;
const build_options = @import("build_options");
const log = std.log.scoped(.dead_strip);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../../tracy.zig").trace;
const track_live_log = std.log.scoped(.dead_strip_track_live);
const std = @import("std");

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Symbol = @import("Symbol.zig");
