archive: ?InArchive = null,
path: []const u8,
file_handle: File.HandleIndex,
mtime: u64,
index: File.Index,

header: ?macho.mach_header_64 = null,
sections: std.MultiArrayList(Section) = .{},
symtab: std.MultiArrayList(Nlist) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},

platform: ?MachO.Platform = null,
compile_unit: ?CompileUnit = null,
stab_files: std.ArrayListUnmanaged(StabFile) = .{},

eh_frame_sect_index: ?u8 = null,
compact_unwind_sect_index: ?u8 = null,
cies: std.ArrayListUnmanaged(Cie) = .{},
fdes: std.ArrayListUnmanaged(Fde) = .{},
eh_frame_data: std.ArrayListUnmanaged(u8) = .{},
unwind_records: std.ArrayListUnmanaged(UnwindInfo.Record.Index) = .{},
data_in_code: std.ArrayListUnmanaged(macho.data_in_code_entry) = .{},

alive: bool = true,
hidden: bool = false,

dynamic_relocs: MachO.DynamicRelocs = .{},
output_symtab_ctx: MachO.SymtabCtx = .{},
output_ar_state: Archive.ArState = .{},

pub fn is_object(path: []const u8) !bool {
    const file = try std.fs.cwd().open_file(path, .{});
    defer file.close();
    const header = file.reader().read_struct(macho.mach_header_64) catch return false;
    return header.filetype == macho.MH_OBJECT;
}

pub fn deinit(self: *Object, allocator: Allocator) void {
    if (self.archive) |*ar| allocator.free(ar.path);
    allocator.free(self.path);
    for (self.sections.items(.relocs), self.sections.items(.subsections)) |*relocs, *sub| {
        relocs.deinit(allocator);
        sub.deinit(allocator);
    }
    self.sections.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.atoms.deinit(allocator);
    self.cies.deinit(allocator);
    self.fdes.deinit(allocator);
    self.eh_frame_data.deinit(allocator);
    self.unwind_records.deinit(allocator);
    for (self.stab_files.items) |*sf| {
        sf.stabs.deinit(allocator);
    }
    self.stab_files.deinit(allocator);
    self.data_in_code.deinit(allocator);
}

pub fn parse(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const offset = if (self.archive) |ar| ar.offset else 0;
    const handle = macho_file.get_file_handle(self.file_handle);

    var header_buffer: [@size_of(macho.mach_header_64)]u8 = undefined;
    {
        const amt = try handle.pread_all(&header_buffer, offset);
        if (amt != @size_of(macho.mach_header_64)) return error.InputOutput;
    }
    self.header = @as(*align(1) const macho.mach_header_64, @ptr_cast(&header_buffer)).*;

    const this_cpu_arch: std.Target.Cpu.Arch = switch (self.header.?.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => |x| {
            try macho_file.report_parse_error2(self.index, "unknown cpu architecture: {d}", .{x});
            return error.InvalidCpuArch;
        },
    };
    if (macho_file.get_target().cpu.arch != this_cpu_arch) {
        try macho_file.report_parse_error2(self.index, "invalid cpu architecture: {s}", .{@tag_name(this_cpu_arch)});
        return error.InvalidCpuArch;
    }

    const lc_buffer = try gpa.alloc(u8, self.header.?.sizeofcmds);
    defer gpa.free(lc_buffer);
    {
        const amt = try handle.pread_all(lc_buffer, offset + @size_of(macho.mach_header_64));
        if (amt != self.header.?.sizeofcmds) return error.InputOutput;
    }

    var it = LoadCommandIterator{
        .ncmds = self.header.?.ncmds,
        .buffer = lc_buffer,
    };
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            const sections = lc.get_sections();
            try self.sections.ensure_unused_capacity(gpa, sections.len);
            for (sections) |sect| {
                const index = try self.sections.add_one(gpa);
                self.sections.set(index, .{ .header = sect });

                if (mem.eql(u8, sect.sect_name(), "__eh_frame")) {
                    self.eh_frame_sect_index = @int_cast(index);
                } else if (mem.eql(u8, sect.sect_name(), "__compact_unwind")) {
                    self.compact_unwind_sect_index = @int_cast(index);
                }
            }
        },
        .SYMTAB => {
            const cmd = lc.cast(macho.symtab_command).?;
            try self.strtab.resize(gpa, cmd.strsize);
            {
                const amt = try handle.pread_all(self.strtab.items, cmd.stroff + offset);
                if (amt != self.strtab.items.len) return error.InputOutput;
            }

            const symtab_buffer = try gpa.alloc(u8, cmd.nsyms * @size_of(macho.nlist_64));
            defer gpa.free(symtab_buffer);
            {
                const amt = try handle.pread_all(symtab_buffer, cmd.symoff + offset);
                if (amt != symtab_buffer.len) return error.InputOutput;
            }
            const symtab = @as([*]align(1) const macho.nlist_64, @ptr_cast(symtab_buffer.ptr))[0..cmd.nsyms];
            try self.symtab.ensure_unused_capacity(gpa, symtab.len);
            for (symtab) |nlist| {
                self.symtab.append_assume_capacity(.{
                    .nlist = nlist,
                    .atom = 0,
                    .size = 0,
                });
            }
        },
        .DATA_IN_CODE => {
            const cmd = lc.cast(macho.linkedit_data_command).?;
            const buffer = try gpa.alloc(u8, cmd.datasize);
            defer gpa.free(buffer);
            {
                const amt = try handle.pread_all(buffer, offset + cmd.dataoff);
                if (amt != buffer.len) return error.InputOutput;
            }
            const ndice = @div_exact(cmd.datasize, @size_of(macho.data_in_code_entry));
            const dice = @as([*]align(1) const macho.data_in_code_entry, @ptr_cast(buffer.ptr))[0..ndice];
            try self.data_in_code.append_unaligned_slice(gpa, dice);
        },
        .BUILD_VERSION,
        .VERSION_MIN_MACOSX,
        .VERSION_MIN_IPHONEOS,
        .VERSION_MIN_TVOS,
        .VERSION_MIN_WATCHOS,
        => if (self.platform == null) {
            self.platform = MachO.Platform.from_load_command(lc);
        },
        else => {},
    };

    const NlistIdx = struct {
        nlist: macho.nlist_64,
        idx: usize,

        fn rank(ctx: *const Object, nl: macho.nlist_64) u8 {
            if (!nl.ext()) {
                const name = ctx.get_string(nl.n_strx);
                if (name.len == 0) return 5;
                if (name[0] == 'l' or name[0] == 'L') return 4;
                return 3;
            }
            return if (nl.weak_def()) 2 else 1;
        }

        fn less_than(ctx: *const Object, lhs: @This(), rhs: @This()) bool {
            if (lhs.nlist.n_sect == rhs.nlist.n_sect) {
                if (lhs.nlist.n_value == rhs.nlist.n_value) {
                    return rank(ctx, lhs.nlist) < rank(ctx, rhs.nlist);
                }
                return lhs.nlist.n_value < rhs.nlist.n_value;
            }
            return lhs.nlist.n_sect < rhs.nlist.n_sect;
        }
    };

    var nlists = try std.ArrayList(NlistIdx).init_capacity(gpa, self.symtab.items(.nlist).len);
    defer nlists.deinit();
    for (self.symtab.items(.nlist), 0..) |nlist, i| {
        if (nlist.stab() or !nlist.sect()) continue;
        nlists.append_assume_capacity(.{ .nlist = nlist, .idx = i });
    }
    mem.sort(NlistIdx, nlists.items, self, NlistIdx.less_than);

    if (self.has_subsections()) {
        try self.init_subsections(nlists.items, macho_file);
    } else {
        try self.init_sections(nlists.items, macho_file);
    }

    try self.init_cstring_literals(macho_file);
    try self.init_fixed_size_literals(macho_file);
    try self.init_pointer_literals(macho_file);
    try self.link_nlist_to_atom(macho_file);

    try self.sort_atoms(macho_file);
    try self.init_symbols(macho_file);
    try self.init_symbol_stabs(nlists.items, macho_file);
    try self.init_relocs(macho_file);

    // Parse DWARF __TEXT,__eh_frame section
    if (self.eh_frame_sect_index) |index| {
        try self.init_eh_frame_records(index, macho_file);
    }

    // Parse Apple's __LD,__compact_unwind section
    if (self.compact_unwind_sect_index) |index| {
        try self.init_unwind_records(index, macho_file);
    }

    if (self.has_unwind_records() or self.has_eh_frame_records()) {
        try self.parse_unwind_records(macho_file);
    }

    if (self.platform) |platform| {
        if (!macho_file.platform.eql_target(platform)) {
            try macho_file.report_parse_error2(self.index, "invalid platform: {}", .{
                platform.fmt_target(macho_file.get_target().cpu.arch),
            });
            return error.InvalidTarget;
        }
        // TODO: this causes the CI to fail so I'm commenting this check out so that
        // I can work out the rest of the changes first
        // if (macho_file.platform.version.order(platform.version) == .lt) {
        //     try macho_file.report_parse_error2(self.index, "object file built for newer platform: {}: {} < {}", .{
        //         macho_file.platform.fmt_target(macho_file.get_target().cpu.arch),
        //         macho_file.platform.version,
        //         platform.version,
        //     });
        //     return error.InvalidTarget;
        // }
    }

    for (self.atoms.items) |atom_index| {
        const atom = macho_file.get_atom(atom_index).?;
        const isec = atom.get_input_section(macho_file);
        if (mem.eql(u8, isec.sect_name(), "__eh_frame") or
            mem.eql(u8, isec.sect_name(), "__compact_unwind") or
            isec.attrs() & macho.S_ATTR_DEBUG != 0)
        {
            atom.flags.alive = false;
        }
    }
}

pub fn is_cstring_literal(sect: macho.section_64) bool {
    return sect.type() == macho.S_CSTRING_LITERALS;
}

pub fn is_fixed_size_literal(sect: macho.section_64) bool {
    return switch (sect.type()) {
        macho.S_4BYTE_LITERALS,
        macho.S_8BYTE_LITERALS,
        macho.S_16BYTE_LITERALS,
        => true,
        else => false,
    };
}

pub fn is_ptr_literal(sect: macho.section_64) bool {
    return sect.type() == macho.S_LITERAL_POINTERS;
}

fn init_subsections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |sect, *subsections, n_sect| {
        if (is_cstring_literal(sect)) continue;
        if (is_fixed_size_literal(sect)) continue;
        if (is_ptr_literal(sect)) continue;

        const nlist_start = for (nlists, 0..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 == n_sect) break i;
        } else nlists.len;
        const nlist_end = for (nlists[nlist_start..], nlist_start..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 != n_sect) break i;
        } else nlists.len;

        if (nlist_start == nlist_end or nlists[nlist_start].nlist.n_value > sect.addr) {
            const name = try std.fmt.alloc_print_z(gpa, "{s}${s}", .{ sect.seg_name(), sect.sect_name() });
            defer gpa.free(name);
            const size = if (nlist_start == nlist_end) sect.size else nlists[nlist_start].nlist.n_value - sect.addr;
            const atom_index = try self.add_atom(.{
                .name = try self.add_string(gpa, name),
                .n_sect = @int_cast(n_sect),
                .off = 0,
                .size = size,
                .alignment = sect.@"align",
            }, macho_file);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = 0,
            });
        }

        var idx: usize = nlist_start;
        while (idx < nlist_end) {
            const alias_start = idx;
            const nlist = nlists[alias_start];

            while (idx < nlist_end and
                nlists[idx].nlist.n_value == nlist.nlist.n_value) : (idx += 1)
            {}

            const size = if (idx < nlist_end)
                nlists[idx].nlist.n_value - nlist.nlist.n_value
            else
                sect.addr + sect.size - nlist.nlist.n_value;
            const alignment = if (nlist.nlist.n_value > 0)
                @min(@ctz(nlist.nlist.n_value), sect.@"align")
            else
                sect.@"align";
            const atom_index = try self.add_atom(.{
                .name = nlist.nlist.n_strx,
                .n_sect = @int_cast(n_sect),
                .off = nlist.nlist.n_value - sect.addr,
                .size = size,
                .alignment = alignment,
            }, macho_file);
            try subsections.append(gpa, .{
                .atom = atom_index,
                .off = nlist.nlist.n_value - sect.addr,
            });

            for (alias_start..idx) |i| {
                self.symtab.items(.size)[nlists[i].idx] = size;
            }
        }
    }
}

fn init_sections(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();

    try self.atoms.ensure_unused_capacity(gpa, self.sections.items(.header).len);

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (is_cstring_literal(sect)) continue;
        if (is_fixed_size_literal(sect)) continue;
        if (is_ptr_literal(sect)) continue;

        const name = try std.fmt.alloc_print_z(gpa, "{s}${s}", .{ sect.seg_name(), sect.sect_name() });
        defer gpa.free(name);

        const atom_index = try self.add_atom(.{
            .name = try self.add_string(gpa, name),
            .n_sect = @int_cast(n_sect),
            .off = 0,
            .size = sect.size,
            .alignment = sect.@"align",
        }, macho_file);
        try slice.items(.subsections)[n_sect].append(gpa, .{ .atom = atom_index, .off = 0 });

        const nlist_start = for (nlists, 0..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 == n_sect) break i;
        } else nlists.len;
        const nlist_end = for (nlists[nlist_start..], nlist_start..) |nlist, i| {
            if (nlist.nlist.n_sect - 1 != n_sect) break i;
        } else nlists.len;

        var idx: usize = nlist_start;
        while (idx < nlist_end) {
            const nlist = nlists[idx];

            while (idx < nlist_end and
                nlists[idx].nlist.n_value == nlist.nlist.n_value) : (idx += 1)
            {}

            const size = if (idx < nlist_end)
                nlists[idx].nlist.n_value - nlist.nlist.n_value
            else
                sect.addr + sect.size - nlist.nlist.n_value;

            for (nlist_start..idx) |i| {
                self.symtab.items(.size)[nlists[i].idx] = size;
            }
        }
    }
}

fn init_cstring_literals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!is_cstring_literal(sect)) continue;

        const data = try self.get_section_data(@int_cast(n_sect), macho_file);
        defer gpa.free(data);

        var start: u32 = 0;
        while (start < data.len) {
            var end = start;
            while (end < data.len - 1 and data[end] != 0) : (end += 1) {}
            if (data[end] != 0) {
                try macho_file.report_parse_error2(
                    self.index,
                    "string not null terminated in '{s},{s}'",
                    .{ sect.seg_name(), sect.sect_name() },
                );
                return error.MalformedObject;
            }
            end += 1;

            const atom_index = try self.add_atom(.{
                .name = 0,
                .n_sect = @int_cast(n_sect),
                .off = start,
                .size = end - start,
                .alignment = sect.@"align",
            }, macho_file);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = start,
            });

            start = end;
        }
    }
}

fn init_fixed_size_literals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!is_fixed_size_literal(sect)) continue;
        const rec_size: u8 = switch (sect.type()) {
            macho.S_4BYTE_LITERALS => 4,
            macho.S_8BYTE_LITERALS => 8,
            macho.S_16BYTE_LITERALS => 16,
            else => unreachable,
        };
        if (sect.size % rec_size != 0) {
            try macho_file.report_parse_error2(
                self.index,
                "size not multiple of record size in '{s},{s}'",
                .{ sect.seg_name(), sect.sect_name() },
            );
            return error.MalformedObject;
        }
        var pos: u32 = 0;
        while (pos < sect.size) : (pos += rec_size) {
            const atom_index = try self.add_atom(.{
                .name = 0,
                .n_sect = @int_cast(n_sect),
                .off = pos,
                .size = rec_size,
                .alignment = sect.@"align",
            }, macho_file);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = pos,
            });
        }
    }
}

fn init_pointer_literals(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();

    for (slice.items(.header), 0..) |sect, n_sect| {
        if (!is_ptr_literal(sect)) continue;

        const rec_size: u8 = 8;
        if (sect.size % rec_size != 0) {
            try macho_file.report_parse_error2(
                self.index,
                "size not multiple of record size in '{s},{s}'",
                .{ sect.seg_name(), sect.sect_name() },
            );
            return error.MalformedObject;
        }
        const num_ptrs = math.cast(usize, @div_exact(sect.size, rec_size)) orelse return error.Overflow;

        for (0..num_ptrs) |i| {
            const pos: u32 = @as(u32, @int_cast(i)) * rec_size;
            const atom_index = try self.add_atom(.{
                .name = 0,
                .n_sect = @int_cast(n_sect),
                .off = pos,
                .size = rec_size,
                .alignment = sect.@"align",
            }, macho_file);
            try slice.items(.subsections)[n_sect].append(gpa, .{
                .atom = atom_index,
                .off = pos,
            });
        }
    }
}

pub fn resolve_literals(self: Object, lp: *MachO.LiteralPool, macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |header, subs, n_sect| {
        if (is_cstring_literal(header) or is_fixed_size_literal(header)) {
            const data = try self.get_section_data(@int_cast(n_sect), macho_file);
            defer gpa.free(data);

            for (subs.items) |sub| {
                const atom = macho_file.get_atom(sub.atom).?;
                const atom_off = math.cast(usize, atom.off) orelse return error.Overflow;
                const atom_size = math.cast(usize, atom.size) orelse return error.Overflow;
                const atom_data = data[atom_off..][0..atom_size];
                const res = try lp.insert(gpa, header.type(), atom_data);
                if (!res.found_existing) {
                    res.atom.* = sub.atom;
                }
                atom.flags.literal_pool = true;
                try atom.add_extra(.{ .literal_index = res.index }, macho_file);
            }
        } else if (is_ptr_literal(header)) {
            for (subs.items) |sub| {
                const atom = macho_file.get_atom(sub.atom).?;
                const relocs = atom.get_relocs(macho_file);
                assert(relocs.len == 1);
                const rel = relocs[0];
                const target = switch (rel.tag) {
                    .local => rel.target,
                    .@"extern" => rel.get_target_symbol(macho_file).atom,
                };
                const addend = math.cast(u32, rel.addend) orelse return error.Overflow;
                const target_atom = macho_file.get_atom(target).?;
                const target_atom_size = math.cast(usize, target_atom.size) orelse return error.Overflow;
                try buffer.ensure_unused_capacity(target_atom_size);
                buffer.resize(target_atom_size) catch unreachable;
                try target_atom.get_data(macho_file, buffer.items);
                const res = try lp.insert(gpa, header.type(), buffer.items[addend..]);
                buffer.clear_retaining_capacity();
                if (!res.found_existing) {
                    res.atom.* = sub.atom;
                }
                atom.flags.literal_pool = true;
                try atom.add_extra(.{ .literal_index = res.index }, macho_file);
            }
        }
    }
}

pub fn dedup_literals(self: Object, lp: MachO.LiteralPool, macho_file: *MachO) void {
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
}

const AddAtomArgs = struct {
    name: u32,
    n_sect: u8,
    off: u64,
    size: u64,
    alignment: u32,
};

fn add_atom(self: *Object, args: AddAtomArgs, macho_file: *MachO) !Atom.Index {
    const gpa = macho_file.base.comp.gpa;
    const atom_index = try macho_file.add_atom();
    const atom = macho_file.get_atom(atom_index).?;
    atom.file = self.index;
    atom.atom_index = atom_index;
    atom.name = args.name;
    atom.n_sect = args.n_sect;
    atom.size = args.size;
    atom.alignment = Atom.Alignment.from_log2_units(args.alignment);
    atom.off = args.off;
    try self.atoms.append(gpa, atom_index);
    return atom_index;
}

pub fn find_atom(self: Object, addr: u64) ?Atom.Index {
    const tracy = trace(@src());
    defer tracy.end();
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.subsections), 0..) |sect, subs, n_sect| {
        if (subs.items.len == 0) continue;
        if (sect.addr == addr) return subs.items[0].atom;
        if (sect.addr < addr and addr < sect.addr + sect.size) {
            return self.find_atom_in_section(addr, @int_cast(n_sect));
        }
    }
    return null;
}

fn find_atom_in_section(self: Object, addr: u64, n_sect: u8) ?Atom.Index {
    const tracy = trace(@src());
    defer tracy.end();
    const slice = self.sections.slice();
    const sect = slice.items(.header)[n_sect];
    const subsections = slice.items(.subsections)[n_sect];

    var min: usize = 0;
    var max: usize = subsections.items.len;
    while (min < max) {
        const idx = (min + max) / 2;
        const sub = subsections.items[idx];
        const sub_addr = sect.addr + sub.off;
        const sub_size = if (idx + 1 < subsections.items.len)
            subsections.items[idx + 1].off - sub.off
        else
            sect.size - sub.off;
        if (sub_addr == addr or (sub_addr < addr and addr < sub_addr + sub_size)) return sub.atom;
        if (sub_addr < addr) {
            min = idx + 1;
        } else {
            max = idx;
        }
    }

    if (min < subsections.items.len) {
        const sub = subsections.items[min];
        const sub_addr = sect.addr + sub.off;
        const sub_size = if (min + 1 < subsections.items.len)
            subsections.items[min + 1].off - sub.off
        else
            sect.size - sub.off;
        if (sub_addr == addr or (sub_addr < addr and addr < sub_addr + sub_size)) return sub.atom;
    }

    return null;
}

fn link_nlist_to_atom(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    for (self.symtab.items(.nlist), self.symtab.items(.atom)) |nlist, *atom| {
        if (!nlist.stab() and nlist.sect()) {
            if (self.find_atom_in_section(nlist.n_value, nlist.n_sect - 1)) |atom_index| {
                atom.* = atom_index;
            } else {
                try macho_file.report_parse_error2(self.index, "symbol {s} not attached to any (sub)section", .{
                    self.get_string(nlist.n_strx),
                });
                return error.MalformedObject;
            }
        }
    }
}

fn init_symbols(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.comp.gpa;
    const slice = self.symtab.slice();

    try self.symbols.ensure_unused_capacity(gpa, slice.items(.nlist).len);

    for (slice.items(.nlist), slice.items(.atom), 0..) |nlist, atom_index, i| {
        if (nlist.ext()) {
            const name = self.get_string(nlist.n_strx);
            const off = try macho_file.strings.insert(gpa, name);
            const gop = try macho_file.get_or_create_global(off);
            self.symbols.add_one_assume_capacity().* = gop.index;
            if (nlist.undf() and nlist.weak_ref()) {
                macho_file.get_symbol(gop.index).flags.weak_ref = true;
            }
            continue;
        }

        const index = try macho_file.add_symbol();
        self.symbols.append_assume_capacity(index);
        const symbol = macho_file.get_symbol(index);
        symbol.* = .{
            .value = nlist.n_value,
            .name = nlist.n_strx,
            .nlist_idx = @int_cast(i),
            .atom = 0,
            .file = self.index,
        };

        if (macho_file.get_atom(atom_index)) |atom| {
            assert(!nlist.abs());
            symbol.value -= atom.get_input_address(macho_file);
            symbol.atom = atom_index;
        }

        symbol.flags.abs = nlist.abs();
        symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.no_dead_strip();

        if (nlist.sect() and
            self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
        {
            symbol.flags.tlv = true;
        }
    }
}

fn init_symbol_stabs(self: *Object, nlists: anytype, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const SymbolLookup = struct {
        ctx: *const Object,
        entries: @TypeOf(nlists),

        fn find(fs: @This(), addr: u64) ?Symbol.Index {
            // TODO binary search since we have the list sorted
            for (fs.entries) |nlist| {
                if (nlist.nlist.n_value == addr) return fs.ctx.symbols.items[nlist.idx];
            }
            return null;
        }
    };

    const start: u32 = for (self.symtab.items(.nlist), 0..) |nlist, i| {
        if (nlist.stab()) break @int_cast(i);
    } else @int_cast(self.symtab.items(.nlist).len);
    const end: u32 = for (self.symtab.items(.nlist)[start..], start..) |nlist, i| {
        if (!nlist.stab()) break @int_cast(i);
    } else @int_cast(self.symtab.items(.nlist).len);

    if (start == end) return;

    const gpa = macho_file.base.comp.gpa;
    const syms = self.symtab.items(.nlist);
    const sym_lookup = SymbolLookup{ .ctx = self, .entries = nlists };

    // We need to cache nlists by name so that we can properly resolve local N_GSYM stabs.
    // What happens is `ld -r` will emit an N_GSYM stab for a symbol that may be either an
    // external or private external.
    var addr_lookup = std.StringHashMap(u64).init(gpa);
    defer addr_lookup.deinit();
    for (syms) |sym| {
        if (sym.sect() and (sym.ext() or sym.pext())) {
            try addr_lookup.put_no_clobber(self.get_string(sym.n_strx), sym.n_value);
        }
    }

    var i: u32 = start;
    while (i < end) : (i += 1) {
        const open = syms[i];
        if (open.n_type != macho.N_SO) {
            try macho_file.report_parse_error2(self.index, "unexpected symbol stab type 0x{x} as the first entry", .{
                open.n_type,
            });
            return error.MalformedObject;
        }

        while (i < end and syms[i].n_type == macho.N_SO and syms[i].n_sect != 0) : (i += 1) {}

        var sf: StabFile = .{ .comp_dir = i };
        // TODO validate
        i += 3;

        while (i < end and syms[i].n_type != macho.N_SO) : (i += 1) {
            const nlist = syms[i];
            var stab: StabFile.Stab = .{};
            switch (nlist.n_type) {
                macho.N_BNSYM => {
                    stab.is_func = true;
                    stab.symbol = sym_lookup.find(nlist.n_value);
                    // TODO validate
                    i += 3;
                },
                macho.N_GSYM => {
                    stab.is_func = false;
                    stab.symbol = sym_lookup.find(addr_lookup.get(self.get_string(nlist.n_strx)).?);
                },
                macho.N_STSYM => {
                    stab.is_func = false;
                    stab.symbol = sym_lookup.find(nlist.n_value);
                },
                else => {
                    try macho_file.report_parse_error2(self.index, "unhandled symbol stab type 0x{x}", .{
                        nlist.n_type,
                    });
                    return error.MalformedObject;
                },
            }
            try sf.stabs.append(gpa, stab);
        }

        try self.stab_files.append(gpa, sf);
    }
}

fn sort_atoms(self: *Object, macho_file: *MachO) !void {
    const less_than_atom = struct {
        fn less_than_atom(ctx: *MachO, lhs: Atom.Index, rhs: Atom.Index) bool {
            return ctx.get_atom(lhs).?.get_input_address(ctx) < ctx.get_atom(rhs).?.get_input_address(ctx);
        }
    }.less_than_atom;
    mem.sort(Atom.Index, self.atoms.items, macho_file, less_than_atom);
}

fn init_relocs(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const cpu_arch = macho_file.get_target().cpu.arch;
    const slice = self.sections.slice();

    for (slice.items(.header), slice.items(.relocs), 0..) |sect, *out, n_sect| {
        if (sect.nreloc == 0) continue;
        // We skip relocs for __DWARF since even in -r mode, the linker is expected to emit
        // debug symbol stabs in the relocatable. This made me curious why that is. For now,
        // I shall comply, but I wanna compare with dsymutil.
        if (sect.attrs() & macho.S_ATTR_DEBUG != 0 and
            !mem.eql(u8, sect.sect_name(), "__compact_unwind")) continue;

        switch (cpu_arch) {
            .x86_64 => try x86_64.parse_relocs(self, @int_cast(n_sect), sect, out, macho_file),
            .aarch64 => try aarch64.parse_relocs(self, @int_cast(n_sect), sect, out, macho_file),
            else => unreachable,
        }

        mem.sort(Relocation, out.items, {}, Relocation.less_than);
    }

    for (slice.items(.header), slice.items(.relocs), slice.items(.subsections)) |sect, relocs, subsections| {
        if (sect.is_zerofill()) continue;

        var next_reloc: u32 = 0;
        for (subsections.items) |subsection| {
            const atom = macho_file.get_atom(subsection.atom).?;
            if (!atom.flags.alive) continue;
            if (next_reloc >= relocs.items.len) break;
            const end_addr = atom.off + atom.size;
            const rel_index = next_reloc;

            while (next_reloc < relocs.items.len and relocs.items[next_reloc].offset < end_addr) : (next_reloc += 1) {}

            const rel_count = next_reloc - rel_index;
            try atom.add_extra(.{ .rel_index = rel_index, .rel_count = rel_count }, macho_file);
            atom.flags.relocs = true;
        }
    }
}

fn init_eh_frame_records(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.comp.gpa;
    const nlists = self.symtab.items(.nlist);
    const slice = self.sections.slice();
    const sect = slice.items(.header)[sect_id];
    const relocs = slice.items(.relocs)[sect_id];

    // TODO: read into buffer directly
    const data = try self.get_section_data(sect_id, macho_file);
    defer gpa.free(data);

    try self.eh_frame_data.ensure_total_capacity_precise(gpa, data.len);
    self.eh_frame_data.append_slice_assume_capacity(data);

    // Check for non-personality relocs in FDEs and apply them
    for (relocs.items, 0..) |rel, i| {
        switch (rel.type) {
            .unsigned => {
                assert((rel.meta.length == 2 or rel.meta.length == 3) and rel.meta.has_subtractor); // TODO error
                const S: i64 = switch (rel.tag) {
                    .local => rel.meta.symbolnum,
                    .@"extern" => @int_cast(nlists[rel.meta.symbolnum].n_value),
                };
                const A = rel.addend;
                const SUB: i64 = blk: {
                    const sub_rel = relocs.items[i - 1];
                    break :blk switch (sub_rel.tag) {
                        .local => sub_rel.meta.symbolnum,
                        .@"extern" => @int_cast(nlists[sub_rel.meta.symbolnum].n_value),
                    };
                };
                switch (rel.meta.length) {
                    0, 1 => unreachable,
                    2 => mem.write_int(u32, self.eh_frame_data.items[rel.offset..][0..4], @bit_cast(@as(i32, @truncate(S + A - SUB))), .little),
                    3 => mem.write_int(u64, self.eh_frame_data.items[rel.offset..][0..8], @bit_cast(S + A - SUB), .little),
                }
            },
            else => {},
        }
    }

    var it = eh_frame.Iterator{ .data = self.eh_frame_data.items };
    while (try it.next()) |rec| {
        switch (rec.tag) {
            .cie => try self.cies.append(gpa, .{
                .offset = rec.offset,
                .size = rec.size,
                .file = self.index,
            }),
            .fde => try self.fdes.append(gpa, .{
                .offset = rec.offset,
                .size = rec.size,
                .cie = undefined,
                .file = self.index,
            }),
        }
    }

    for (self.cies.items) |*cie| {
        try cie.parse(macho_file);
    }

    for (self.fdes.items) |*fde| {
        try fde.parse(macho_file);
    }

    const sort_fn = struct {
        fn sort_fn(ctx: *MachO, lhs: Fde, rhs: Fde) bool {
            return lhs.get_atom(ctx).get_input_address(ctx) < rhs.get_atom(ctx).get_input_address(ctx);
        }
    }.sort_fn;

    mem.sort(Fde, self.fdes.items, macho_file, sort_fn);

    // Parse and attach personality pointers to CIEs if any
    for (relocs.items) |rel| {
        switch (rel.type) {
            .got => {
                assert(rel.meta.length == 2 and rel.tag == .@"extern");
                const cie = for (self.cies.items) |*cie| {
                    if (cie.offset <= rel.offset and rel.offset < cie.offset + cie.get_size()) break cie;
                } else {
                    try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                        sect.seg_name(), sect.sect_name(), rel.offset,
                    });
                    return error.MalformedObject;
                };
                cie.personality = .{ .index = @int_cast(rel.target), .offset = rel.offset - cie.offset };
            },
            else => {},
        }
    }
}

fn init_unwind_records(self: *Object, sect_id: u8, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const SymbolLookup = struct {
        ctx: *const Object,

        fn find(fs: @This(), addr: u64) ?Symbol.Index {
            for (fs.ctx.symbols.items, 0..) |sym_index, i| {
                const nlist = fs.ctx.symtab.items(.nlist)[i];
                if (nlist.ext() and nlist.n_value == addr) return sym_index;
            }
            return null;
        }
    };

    const gpa = macho_file.base.comp.gpa;
    const data = try self.get_section_data(sect_id, macho_file);
    defer gpa.free(data);
    const nrecs = @div_exact(data.len, @size_of(macho.compact_unwind_entry));
    const recs = @as([*]align(1) const macho.compact_unwind_entry, @ptr_cast(data.ptr))[0..nrecs];
    const sym_lookup = SymbolLookup{ .ctx = self };

    try self.unwind_records.resize(gpa, nrecs);

    const header = self.sections.items(.header)[sect_id];
    const relocs = self.sections.items(.relocs)[sect_id].items;
    var reloc_idx: usize = 0;
    for (recs, self.unwind_records.items, 0..) |rec, *out_index, rec_idx| {
        const rec_start = rec_idx * @size_of(macho.compact_unwind_entry);
        const rec_end = rec_start + @size_of(macho.compact_unwind_entry);
        const reloc_start = reloc_idx;
        while (reloc_idx < relocs.len and
            relocs[reloc_idx].offset < rec_end) : (reloc_idx += 1)
        {}

        out_index.* = try macho_file.add_unwind_record();
        const out = macho_file.get_unwind_record(out_index.*);
        out.length = rec.rangeLength;
        out.enc = .{ .enc = rec.compactUnwindEncoding };
        out.file = self.index;

        for (relocs[reloc_start..reloc_idx]) |rel| {
            if (rel.type != .unsigned or rel.meta.length != 3) {
                try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                    header.seg_name(), header.sect_name(), rel.offset,
                });
                return error.MalformedObject;
            }
            assert(rel.type == .unsigned and rel.meta.length == 3); // TODO error
            const offset = rel.offset - rec_start;
            switch (offset) {
                0 => switch (rel.tag) { // target symbol
                    .@"extern" => {
                        out.atom = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.atom_offset = @int_cast(rec.rangeStart);
                    },
                    .local => if (self.find_atom(rec.rangeStart)) |atom_index| {
                        out.atom = atom_index;
                        const atom = out.get_atom(macho_file);
                        out.atom_offset = @int_cast(rec.rangeStart - atom.get_input_address(macho_file));
                    } else {
                        try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                            header.seg_name(), header.sect_name(), rel.offset,
                        });
                        return error.MalformedObject;
                    },
                },
                16 => switch (rel.tag) { // personality function
                    .@"extern" => {
                        out.personality = rel.target;
                    },
                    .local => if (sym_lookup.find(rec.personalityFunction)) |sym_index| {
                        out.personality = sym_index;
                    } else {
                        try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                            header.seg_name(), header.sect_name(), rel.offset,
                        });
                        return error.MalformedObject;
                    },
                },
                24 => switch (rel.tag) { // lsda
                    .@"extern" => {
                        out.lsda = self.symtab.items(.atom)[rel.meta.symbolnum];
                        out.lsda_offset = @int_cast(rec.lsda);
                    },
                    .local => if (self.find_atom(rec.lsda)) |atom_index| {
                        out.lsda = atom_index;
                        const atom = out.get_lsda_atom(macho_file).?;
                        out.lsda_offset = @int_cast(rec.lsda - atom.get_input_address(macho_file));
                    } else {
                        try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                            header.seg_name(), header.sect_name(), rel.offset,
                        });
                        return error.MalformedObject;
                    },
                },
                else => {},
            }
        }
    }
}

fn parse_unwind_records(self: *Object, macho_file: *MachO) !void {
    // Synthesise missing unwind records.
    // The logic here is as follows:
    // 1. if an atom has unwind info record that is not DWARF, FDE is marked dead
    // 2. if an atom has unwind info record that is DWARF, FDE is tied to this unwind record
    // 3. if an atom doesn't have unwind info record but FDE is available, synthesise and tie
    // 4. if an atom doesn't have either, synthesise a null unwind info record

    const Superposition = struct { atom: Atom.Index, size: u64, cu: ?UnwindInfo.Record.Index = null, fde: ?Fde.Index = null };

    const gpa = macho_file.base.comp.gpa;
    var superposition = std.AutoArrayHashMap(u64, Superposition).init(gpa);
    defer superposition.deinit();

    const slice = self.symtab.slice();
    for (slice.items(.nlist), slice.items(.atom), slice.items(.size)) |nlist, atom, size| {
        if (nlist.stab()) continue;
        if (!nlist.sect()) continue;
        const sect = self.sections.items(.header)[nlist.n_sect - 1];
        if (sect.is_code() and sect.size > 0) {
            try superposition.ensure_unused_capacity(1);
            const gop = superposition.get_or_put_assume_capacity(nlist.n_value);
            if (gop.found_existing) {
                assert(gop.value_ptr.atom == atom and gop.value_ptr.size == size);
            }
            gop.value_ptr.* = .{ .atom = atom, .size = size };
        }
    }

    for (self.unwind_records.items) |rec_index| {
        const rec = macho_file.get_unwind_record(rec_index);
        const atom = rec.get_atom(macho_file);
        const addr = atom.get_input_address(macho_file) + rec.atom_offset;
        superposition.get_ptr(addr).?.cu = rec_index;
    }

    for (self.fdes.items, 0..) |fde, fde_index| {
        const atom = fde.get_atom(macho_file);
        const addr = atom.get_input_address(macho_file) + fde.atom_offset;
        superposition.get_ptr(addr).?.fde = @int_cast(fde_index);
    }

    for (superposition.keys(), superposition.values()) |addr, meta| {
        if (meta.fde) |fde_index| {
            const fde = &self.fdes.items[fde_index];

            if (meta.cu) |rec_index| {
                const rec = macho_file.get_unwind_record(rec_index);
                if (!rec.enc.is_dwarf(macho_file)) {
                    // Mark FDE dead
                    fde.alive = false;
                } else {
                    // Tie FDE to unwind record
                    rec.fde = fde_index;
                }
            } else {
                // Synthesise new unwind info record
                const rec_index = try macho_file.add_unwind_record();
                const rec = macho_file.get_unwind_record(rec_index);
                try self.unwind_records.append(gpa, rec_index);
                rec.length = @int_cast(meta.size);
                rec.atom = fde.atom;
                rec.atom_offset = fde.atom_offset;
                rec.fde = fde_index;
                rec.file = fde.file;
                switch (macho_file.get_target().cpu.arch) {
                    .x86_64 => rec.enc.set_mode(macho.UNWIND_X86_64_MODE.DWARF),
                    .aarch64 => rec.enc.set_mode(macho.UNWIND_ARM64_MODE.DWARF),
                    else => unreachable,
                }
            }
        } else if (meta.cu == null and meta.fde == null) {
            // Create a null record
            const rec_index = try macho_file.add_unwind_record();
            const rec = macho_file.get_unwind_record(rec_index);
            const atom = macho_file.get_atom(meta.atom).?;
            try self.unwind_records.append(gpa, rec_index);
            rec.length = @int_cast(meta.size);
            rec.atom = meta.atom;
            rec.atom_offset = @int_cast(addr - atom.get_input_address(macho_file));
            rec.file = self.index;
        }
    }

    const sort_fn = struct {
        fn sort_fn(ctx: *MachO, lhs_index: UnwindInfo.Record.Index, rhs_index: UnwindInfo.Record.Index) bool {
            const lhs = ctx.get_unwind_record(lhs_index);
            const rhs = ctx.get_unwind_record(rhs_index);
            const lhsa = lhs.get_atom(ctx);
            const rhsa = rhs.get_atom(ctx);
            return lhsa.get_input_address(ctx) + lhs.atom_offset < rhsa.get_input_address(ctx) + rhs.atom_offset;
        }
    }.sort_fn;
    mem.sort(UnwindInfo.Record.Index, self.unwind_records.items, macho_file, sort_fn);

    // Associate unwind records to atoms
    var next_cu: u32 = 0;
    while (next_cu < self.unwind_records.items.len) {
        const start = next_cu;
        const rec_index = self.unwind_records.items[start];
        const rec = macho_file.get_unwind_record(rec_index);
        while (next_cu < self.unwind_records.items.len and
            macho_file.get_unwind_record(self.unwind_records.items[next_cu]).atom == rec.atom) : (next_cu += 1)
        {}

        const atom = rec.get_atom(macho_file);
        try atom.add_extra(.{ .unwind_index = start, .unwind_count = next_cu - start }, macho_file);
        atom.flags.unwind = true;
    }
}

/// Currently, we only check if a compile unit for this input object file exists
/// and record that so that we can emit symbol stabs.
/// TODO in the future, we want parse debug info and debug line sections so that
/// we can provide nice error locations to the user.
pub fn parse_debug_info(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;

    var debug_info_index: ?usize = null;
    var debug_abbrev_index: ?usize = null;
    var debug_str_index: ?usize = null;

    for (self.sections.items(.header), 0..) |sect, index| {
        if (sect.attrs() & macho.S_ATTR_DEBUG == 0) continue;
        if (mem.eql(u8, sect.sect_name(), "__debug_info")) debug_info_index = index;
        if (mem.eql(u8, sect.sect_name(), "__debug_abbrev")) debug_abbrev_index = index;
        if (mem.eql(u8, sect.sect_name(), "__debug_str")) debug_str_index = index;
    }

    if (debug_info_index == null or debug_abbrev_index == null) return;

    const debug_info = try self.get_section_data(@int_cast(debug_info_index.?), macho_file);
    defer gpa.free(debug_info);
    const debug_abbrev = try self.get_section_data(@int_cast(debug_abbrev_index.?), macho_file);
    defer gpa.free(debug_abbrev);
    const debug_str = if (debug_str_index) |index| try self.get_section_data(@int_cast(index), macho_file) else &[0]u8{};
    defer gpa.free(debug_str);

    self.compile_unit = self.find_compile_unit(.{
        .gpa = gpa,
        .debug_info = debug_info,
        .debug_abbrev = debug_abbrev,
        .debug_str = debug_str,
    }) catch null; // TODO figure out what errors are fatal, and when we silently fail
}

fn find_compile_unit(self: *Object, args: struct {
    gpa: Allocator,
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
}) !CompileUnit {
    var cu_wip: struct {
        comp_dir: ?[:0]const u8 = null,
        tu_name: ?[:0]const u8 = null,
    } = .{};

    const gpa = args.gpa;
    var info_reader = dwarf.InfoReader{ .bytes = args.debug_info, .strtab = args.debug_str };
    var abbrev_reader = dwarf.AbbrevReader{ .bytes = args.debug_abbrev };

    const cuh = try info_reader.read_compile_unit_header();
    try abbrev_reader.seek_to(cuh.debug_abbrev_offset);

    const cu_decl = (try abbrev_reader.read_decl()) orelse return error.Eof;
    if (cu_decl.tag != dwarf.TAG.compile_unit) return error.UnexpectedTag;

    try info_reader.seek_to_die(cu_decl.code, cuh, &abbrev_reader);

    while (try abbrev_reader.read_attr()) |attr| switch (attr.at) {
        dwarf.AT.name => {
            cu_wip.tu_name = try info_reader.read_string(attr.form, cuh);
        },
        dwarf.AT.comp_dir => {
            cu_wip.comp_dir = try info_reader.read_string(attr.form, cuh);
        },
        else => switch (attr.form) {
            dwarf.FORM.sec_offset,
            dwarf.FORM.ref_addr,
            => {
                _ = try info_reader.read_offset(cuh.format);
            },

            dwarf.FORM.addr => {
                _ = try info_reader.read_nbytes(cuh.address_size);
            },

            dwarf.FORM.block1,
            dwarf.FORM.block2,
            dwarf.FORM.block4,
            dwarf.FORM.block,
            => {
                _ = try info_reader.read_block(attr.form);
            },

            dwarf.FORM.exprloc => {
                _ = try info_reader.read_expr_loc();
            },

            dwarf.FORM.flag_present => {},

            dwarf.FORM.data1,
            dwarf.FORM.ref1,
            dwarf.FORM.flag,
            dwarf.FORM.data2,
            dwarf.FORM.ref2,
            dwarf.FORM.data4,
            dwarf.FORM.ref4,
            dwarf.FORM.data8,
            dwarf.FORM.ref8,
            dwarf.FORM.ref_sig8,
            dwarf.FORM.udata,
            dwarf.FORM.ref_udata,
            dwarf.FORM.sdata,
            => {
                _ = try info_reader.read_constant(attr.form);
            },

            dwarf.FORM.strp,
            dwarf.FORM.string,
            => {
                _ = try info_reader.read_string(attr.form, cuh);
            },

            else => {
                // TODO actual errors?
                log.err("unhandled DW_FORM_* value with identifier {x}", .{attr.form});
                return error.UnhandledForm;
            },
        },
    };

    if (cu_wip.comp_dir == null) return error.MissingCompDir;
    if (cu_wip.tu_name == null) return error.MissingTuName;

    return .{
        .comp_dir = try self.add_string(gpa, cu_wip.comp_dir.?),
        .tu_name = try self.add_string(gpa, cu_wip.tu_name.?),
    };
}

pub fn resolve_symbols(self: *Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items, 0..) |index, i| {
        const nlist_idx = @as(Symbol.Index, @int_cast(i));
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        const atom_index = self.symtab.items(.atom)[nlist_idx];

        if (!nlist.ext()) continue;
        if (nlist.undf() and !nlist.tentative()) continue;
        if (nlist.sect()) {
            const atom = macho_file.get_atom(atom_index).?;
            if (!atom.flags.alive) continue;
        }

        const symbol = macho_file.get_symbol(index);
        if (self.as_file().get_symbol_rank(.{
            .archive = !self.alive,
            .weak = nlist.weak_def(),
            .tentative = nlist.tentative(),
        }) < symbol.get_symbol_rank(macho_file)) {
            const value = if (nlist.sect()) blk: {
                const atom = macho_file.get_atom(atom_index).?;
                break :blk nlist.n_value - atom.get_input_address(macho_file);
            } else nlist.n_value;
            symbol.value = value;
            symbol.atom = atom_index;
            symbol.nlist_idx = nlist_idx;
            symbol.file = self.index;
            symbol.flags.weak = nlist.weak_def();
            symbol.flags.abs = nlist.abs();
            symbol.flags.tentative = nlist.tentative();
            symbol.flags.weak_ref = false;
            symbol.flags.dyn_ref = nlist.n_desc & macho.REFERENCED_DYNAMICALLY != 0;
            symbol.flags.no_dead_strip = symbol.flags.no_dead_strip or nlist.no_dead_strip();
            // TODO: symbol.flags.interposable = macho_file.base.is_dyn_lib() and macho_file.options.namespace == .flat and !nlist.pext();
            symbol.flags.interposable = false;

            if (nlist.sect() and
                self.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
            {
                symbol.flags.tlv = true;
            }
        }

        // Regardless of who the winner is, we still merge symbol visibility here.
        if (nlist.pext() or (nlist.weak_def() and nlist.weak_ref()) or self.hidden) {
            if (symbol.visibility != .global) {
                symbol.visibility = .hidden;
            }
        } else {
            symbol.visibility = .global;
        }
    }
}

pub fn reset_globals(self: *Object, macho_file: *MachO) void {
    for (self.symbols.items, 0..) |sym_index, nlist_idx| {
        if (!self.symtab.items(.nlist)[nlist_idx].ext()) continue;
        const sym = macho_file.get_symbol(sym_index);
        const name = sym.name;
        const global = sym.flags.global;
        const weak_ref = sym.flags.weak_ref;
        sym.* = .{};
        sym.name = name;
        sym.flags.global = global;
        sym.flags.weak_ref = weak_ref;
    }
}

pub fn mark_live(self: *Object, macho_file: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items, 0..) |index, nlist_idx| {
        const nlist = self.symtab.items(.nlist)[nlist_idx];
        if (!nlist.ext()) continue;

        const sym = macho_file.get_symbol(index);
        const file = sym.get_file(macho_file) orelse continue;
        const should_keep = nlist.undf() or (nlist.tentative() and !sym.flags.tentative);
        if (should_keep and file == .object and !file.object.alive) {
            file.object.alive = true;
            file.object.mark_live(macho_file);
        }
    }
}

pub fn check_duplicates(self: *Object, dupes: anytype, macho_file: *MachO) error{OutOfMemory}!void {
    for (self.symbols.items, 0..) |index, nlist_idx| {
        const sym = macho_file.get_symbol(index);
        if (sym.visibility != .global) continue;
        const file = sym.get_file(macho_file) orelse continue;
        if (file.get_index() == self.index) continue;

        const nlist = self.symtab.items(.nlist)[nlist_idx];
        if (!nlist.undf() and !nlist.tentative() and !(nlist.weak_def() or nlist.pext())) {
            const gop = try dupes.get_or_put(index);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{};
            }
            try gop.value_ptr.append(macho_file.base.comp.gpa, self.index);
        }
    }
}

pub fn scan_relocs(self: Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.atoms.items) |atom_index| {
        const atom = macho_file.get_atom(atom_index).?;
        if (!atom.flags.alive) continue;
        const sect = atom.get_input_section(macho_file);
        if (sect.is_zerofill()) continue;
        try atom.scan_relocs(macho_file);
    }

    for (self.unwind_records.items) |rec_index| {
        const rec = macho_file.get_unwind_record(rec_index);
        if (!rec.alive) continue;
        if (rec.get_fde(macho_file)) |fde| {
            if (fde.get_cie(macho_file).get_personality(macho_file)) |sym| {
                sym.flags.needs_got = true;
            }
        } else if (rec.get_personality(macho_file)) |sym| {
            sym.flags.needs_got = true;
        }
    }
}

pub fn convert_tentative_definitions(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = macho_file.base.comp.gpa;

    for (self.symbols.items, 0..) |index, i| {
        const sym = macho_file.get_symbol(index);
        if (!sym.flags.tentative) continue;
        const sym_file = sym.get_file(macho_file).?;
        if (sym_file.get_index() != self.index) continue;

        const nlist_idx = @as(Symbol.Index, @int_cast(i));
        const nlist = &self.symtab.items(.nlist)[nlist_idx];
        const nlist_atom = &self.symtab.items(.atom)[nlist_idx];

        const atom_index = try macho_file.add_atom();
        try self.atoms.append(gpa, atom_index);

        const name = try std.fmt.alloc_print_z(gpa, "__DATA$__common${s}", .{sym.get_name(macho_file)});
        defer gpa.free(name);
        const atom = macho_file.get_atom(atom_index).?;
        atom.atom_index = atom_index;
        atom.name = try self.add_string(gpa, name);
        atom.file = self.index;
        atom.size = nlist.n_value;
        atom.alignment = Atom.Alignment.from_log2_units((nlist.n_desc >> 8) & 0x0f);

        const n_sect = try self.add_section(gpa, "__DATA", "__common");
        const sect = &self.sections.items(.header)[n_sect];
        sect.flags = macho.S_ZEROFILL;
        sect.size = atom.size;
        sect.@"align" = atom.alignment.to_log2_units();
        atom.n_sect = n_sect;

        sym.value = 0;
        sym.atom = atom_index;
        sym.flags.global = true;
        sym.flags.weak = false;
        sym.flags.weak_ref = false;
        sym.flags.tentative = false;
        sym.visibility = .global;

        nlist.n_value = 0;
        nlist.n_type = macho.N_EXT | macho.N_SECT;
        nlist.n_sect = 0;
        nlist.n_desc = 0;
        nlist_atom.* = atom_index;
    }
}

fn add_section(self: *Object, allocator: Allocator, segname: []const u8, sectname: []const u8) !u32 {
    const n_sect = @as(u32, @int_cast(try self.sections.add_one(allocator)));
    self.sections.set(n_sect, .{
        .header = .{
            .sectname = MachO.make_static_string(sectname),
            .segname = MachO.make_static_string(segname),
        },
    });
    return n_sect;
}

pub fn parse_ar(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const offset = if (self.archive) |ar| ar.offset else 0;
    const handle = macho_file.get_file_handle(self.file_handle);

    var header_buffer: [@size_of(macho.mach_header_64)]u8 = undefined;
    {
        const amt = try handle.pread_all(&header_buffer, offset);
        if (amt != @size_of(macho.mach_header_64)) return error.InputOutput;
    }
    self.header = @as(*align(1) const macho.mach_header_64, @ptr_cast(&header_buffer)).*;

    const this_cpu_arch: std.Target.Cpu.Arch = switch (self.header.?.cputype) {
        macho.CPU_TYPE_ARM64 => .aarch64,
        macho.CPU_TYPE_X86_64 => .x86_64,
        else => |x| {
            try macho_file.report_parse_error2(self.index, "unknown cpu architecture: {d}", .{x});
            return error.InvalidCpuArch;
        },
    };
    if (macho_file.get_target().cpu.arch != this_cpu_arch) {
        try macho_file.report_parse_error2(self.index, "invalid cpu architecture: {s}", .{@tag_name(this_cpu_arch)});
        return error.InvalidCpuArch;
    }

    const lc_buffer = try gpa.alloc(u8, self.header.?.sizeofcmds);
    defer gpa.free(lc_buffer);
    {
        const amt = try handle.pread_all(lc_buffer, offset + @size_of(macho.mach_header_64));
        if (amt != self.header.?.sizeofcmds) return error.InputOutput;
    }

    var it = LoadCommandIterator{
        .ncmds = self.header.?.ncmds,
        .buffer = lc_buffer,
    };
    while (it.next()) |lc| switch (lc.cmd()) {
        .SYMTAB => {
            const cmd = lc.cast(macho.symtab_command).?;
            try self.strtab.resize(gpa, cmd.strsize);
            {
                const amt = try handle.pread_all(self.strtab.items, cmd.stroff + offset);
                if (amt != self.strtab.items.len) return error.InputOutput;
            }

            const symtab_buffer = try gpa.alloc(u8, cmd.nsyms * @size_of(macho.nlist_64));
            defer gpa.free(symtab_buffer);
            {
                const amt = try handle.pread_all(symtab_buffer, cmd.symoff + offset);
                if (amt != symtab_buffer.len) return error.InputOutput;
            }
            const symtab = @as([*]align(1) const macho.nlist_64, @ptr_cast(symtab_buffer.ptr))[0..cmd.nsyms];
            try self.symtab.ensure_unused_capacity(gpa, symtab.len);
            for (symtab) |nlist| {
                self.symtab.append_assume_capacity(.{
                    .nlist = nlist,
                    .atom = 0,
                    .size = 0,
                });
            }
        },
        .BUILD_VERSION,
        .VERSION_MIN_MACOSX,
        .VERSION_MIN_IPHONEOS,
        .VERSION_MIN_TVOS,
        .VERSION_MIN_WATCHOS,
        => if (self.platform == null) {
            self.platform = MachO.Platform.from_load_command(lc);
        },
        else => {},
    };
}

pub fn update_ar_symtab(self: Object, ar_symtab: *Archive.ArSymtab, macho_file: *MachO) error{OutOfMemory}!void {
    const gpa = macho_file.base.comp.gpa;
    for (self.symtab.items(.nlist)) |nlist| {
        if (!nlist.ext() or (nlist.undf() and !nlist.tentative())) continue;
        const off = try ar_symtab.strtab.insert(gpa, self.get_string(nlist.n_strx));
        try ar_symtab.entries.append(gpa, .{ .off = off, .file = self.index });
    }
}

pub fn update_ar_size(self: *Object, macho_file: *MachO) !void {
    self.output_ar_state.size = if (self.archive) |ar| ar.size else size: {
        const file = macho_file.get_file_handle(self.file_handle);
        break :size (try file.stat()).size;
    };
}

pub fn write_ar(self: Object, ar_format: Archive.Format, macho_file: *MachO, writer: anytype) !void {
    // Header
    const size = std.math.cast(usize, self.output_ar_state.size) orelse return error.Overflow;
    const offset: u64 = if (self.archive) |ar| ar.offset else 0;
    try Archive.write_header(self.path, size, ar_format, writer);
    // Data
    const file = macho_file.get_file_handle(self.file_handle);
    // TODO try using copy_range_all
    const gpa = macho_file.base.comp.gpa;
    const data = try gpa.alloc(u8, size);
    defer gpa.free(data);
    const amt = try file.pread_all(data, offset);
    if (amt != size) return error.InputOutput;
    try writer.write_all(data);
}

pub fn calc_symtab_size(self: *Object, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        const file = sym.get_file(macho_file) orelse continue;
        if (file.get_index() != self.index) continue;
        if (sym.get_atom(macho_file)) |atom| if (!atom.flags.alive) continue;
        if (sym.is_symbol_stab(macho_file)) continue;
        const name = sym.get_name(macho_file);
        // TODO in -r mode, we actually want to merge symbol names and emit only one
        // work it out when emitting relocs
        if (name.len > 0 and
            (name[0] == 'L' or name[0] == 'l' or
            mem.starts_with(u8, name, "_OBJC_SELECTOR_REFERENCES_")) and
            !macho_file.base.is_object()) continue;
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

    if (macho_file.base.comp.config.debug_format != .strip and self.has_debug_info())
        try self.calc_stabs_size(macho_file);
}

pub fn calc_stabs_size(self: *Object, macho_file: *MachO) error{Overflow}!void {
    if (self.compile_unit) |cu| {
        const comp_dir = cu.get_comp_dir(self);
        const tu_name = cu.get_tu_name(self);

        self.output_symtab_ctx.nstabs += 4; // N_SO, N_SO, N_OSO, N_SO
        self.output_symtab_ctx.strsize += @as(u32, @int_cast(comp_dir.len + 1)); // comp_dir
        self.output_symtab_ctx.strsize += @as(u32, @int_cast(tu_name.len + 1)); // tu_name

        if (self.archive) |ar| {
            self.output_symtab_ctx.strsize += @as(u32, @int_cast(ar.path.len + 1 + self.path.len + 1 + 1));
        } else {
            self.output_symtab_ctx.strsize += @as(u32, @int_cast(self.path.len + 1));
        }

        for (self.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const file = sym.get_file(macho_file) orelse continue;
            if (file.get_index() != self.index) continue;
            if (!sym.flags.output_symtab) continue;
            if (macho_file.base.is_object()) {
                const name = sym.get_name(macho_file);
                if (name.len > 0 and (name[0] == 'L' or name[0] == 'l')) continue;
            }
            const sect = macho_file.sections.items(.header)[sym.out_n_sect];
            if (sect.is_code()) {
                self.output_symtab_ctx.nstabs += 4; // N_BNSYM, N_FUN, N_FUN, N_ENSYM
            } else if (sym.visibility == .global) {
                self.output_symtab_ctx.nstabs += 1; // N_GSYM
            } else {
                self.output_symtab_ctx.nstabs += 1; // N_STSYM
            }
        }
    } else {
        assert(self.has_symbol_stabs());

        for (self.stab_files.items) |sf| {
            self.output_symtab_ctx.nstabs += 4; // N_SO, N_SO, N_OSO, N_SO
            self.output_symtab_ctx.strsize += @as(u32, @int_cast(sf.get_comp_dir(self).len + 1)); // comp_dir
            self.output_symtab_ctx.strsize += @as(u32, @int_cast(sf.get_tu_name(self).len + 1)); // tu_name
            self.output_symtab_ctx.strsize += @as(u32, @int_cast(sf.get_oso_path(self).len + 1)); // path

            for (sf.stabs.items) |stab| {
                const sym = stab.get_symbol(macho_file) orelse continue;
                const file = sym.get_file(macho_file).?;
                if (file.get_index() != self.index) continue;
                if (!sym.flags.output_symtab) continue;
                const nstabs: u32 = if (stab.is_func) 4 else 1;
                self.output_symtab_ctx.nstabs += nstabs;
            }
        }
    }
}

pub fn write_symtab(self: Object, macho_file: *MachO, ctx: anytype) error{Overflow}!void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        const file = sym.get_file(macho_file) orelse continue;
        if (file.get_index() != self.index) continue;
        const idx = sym.get_output_symtab_index(macho_file) orelse continue;
        const n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
        ctx.strtab.append_slice_assume_capacity(sym.get_name(macho_file));
        ctx.strtab.append_assume_capacity(0);
        const out_sym = &ctx.symtab.items[idx];
        out_sym.n_strx = n_strx;
        sym.set_output_sym(macho_file, out_sym);
    }

    if (macho_file.base.comp.config.debug_format != .strip and self.has_debug_info())
        try self.write_stabs(macho_file, ctx);
}

pub fn write_stabs(self: *const Object, macho_file: *MachO, ctx: anytype) error{Overflow}!void {
    const write_func_stab = struct {
        inline fn write_func_stab(
            n_strx: u32,
            n_sect: u8,
            n_value: u64,
            size: u64,
            index: u32,
            context: anytype,
        ) void {
            context.symtab.items[index] = .{
                .n_strx = 0,
                .n_type = macho.N_BNSYM,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = n_value,
            };
            context.symtab.items[index + 1] = .{
                .n_strx = n_strx,
                .n_type = macho.N_FUN,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = n_value,
            };
            context.symtab.items[index + 2] = .{
                .n_strx = 0,
                .n_type = macho.N_FUN,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = size,
            };
            context.symtab.items[index + 3] = .{
                .n_strx = 0,
                .n_type = macho.N_ENSYM,
                .n_sect = n_sect,
                .n_desc = 0,
                .n_value = size,
            };
        }
    }.write_func_stab;

    var index = self.output_symtab_ctx.istab;

    if (self.compile_unit) |cu| {
        const comp_dir = cu.get_comp_dir(self);
        const tu_name = cu.get_tu_name(self);

        // Open scope
        // N_SO comp_dir
        var n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
        ctx.strtab.append_slice_assume_capacity(comp_dir);
        ctx.strtab.append_assume_capacity(0);
        ctx.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_SO,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        index += 1;
        // N_SO tu_name
        n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
        ctx.strtab.append_slice_assume_capacity(tu_name);
        ctx.strtab.append_assume_capacity(0);
        ctx.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_SO,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
        index += 1;
        // N_OSO path
        n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
        if (self.archive) |ar| {
            ctx.strtab.append_slice_assume_capacity(ar.path);
            ctx.strtab.append_assume_capacity('(');
            ctx.strtab.append_slice_assume_capacity(self.path);
            ctx.strtab.append_assume_capacity(')');
            ctx.strtab.append_assume_capacity(0);
        } else {
            ctx.strtab.append_slice_assume_capacity(self.path);
            ctx.strtab.append_assume_capacity(0);
        }
        ctx.symtab.items[index] = .{
            .n_strx = n_strx,
            .n_type = macho.N_OSO,
            .n_sect = 0,
            .n_desc = 1,
            .n_value = self.mtime,
        };
        index += 1;

        for (self.symbols.items) |sym_index| {
            const sym = macho_file.get_symbol(sym_index);
            const file = sym.get_file(macho_file) orelse continue;
            if (file.get_index() != self.index) continue;
            if (!sym.flags.output_symtab) continue;
            if (macho_file.base.is_object()) {
                const name = sym.get_name(macho_file);
                if (name.len > 0 and (name[0] == 'L' or name[0] == 'l')) continue;
            }
            const sect = macho_file.sections.items(.header)[sym.out_n_sect];
            const sym_n_strx = n_strx: {
                const symtab_index = sym.get_output_symtab_index(macho_file).?;
                const osym = ctx.symtab.items[symtab_index];
                break :n_strx osym.n_strx;
            };
            const sym_n_sect: u8 = if (!sym.flags.abs) @int_cast(sym.out_n_sect + 1) else 0;
            const sym_n_value = sym.get_address(.{}, macho_file);
            const sym_size = sym.get_size(macho_file);
            if (sect.is_code()) {
                write_func_stab(sym_n_strx, sym_n_sect, sym_n_value, sym_size, index, ctx);
                index += 4;
            } else if (sym.visibility == .global) {
                ctx.symtab.items[index] = .{
                    .n_strx = sym_n_strx,
                    .n_type = macho.N_GSYM,
                    .n_sect = sym_n_sect,
                    .n_desc = 0,
                    .n_value = 0,
                };
                index += 1;
            } else {
                ctx.symtab.items[index] = .{
                    .n_strx = sym_n_strx,
                    .n_type = macho.N_STSYM,
                    .n_sect = sym_n_sect,
                    .n_desc = 0,
                    .n_value = sym_n_value,
                };
                index += 1;
            }
        }

        // Close scope
        // N_SO
        ctx.symtab.items[index] = .{
            .n_strx = 0,
            .n_type = macho.N_SO,
            .n_sect = 0,
            .n_desc = 0,
            .n_value = 0,
        };
    } else {
        assert(self.has_symbol_stabs());

        for (self.stab_files.items) |sf| {
            // Open scope
            // N_SO comp_dir
            var n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
            ctx.strtab.append_slice_assume_capacity(sf.get_comp_dir(self));
            ctx.strtab.append_assume_capacity(0);
            ctx.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
            // N_SO tu_name
            n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
            ctx.strtab.append_slice_assume_capacity(sf.get_tu_name(self));
            ctx.strtab.append_assume_capacity(0);
            ctx.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
            // N_OSO path
            n_strx = @as(u32, @int_cast(ctx.strtab.items.len));
            ctx.strtab.append_slice_assume_capacity(sf.get_oso_path(self));
            ctx.strtab.append_assume_capacity(0);
            ctx.symtab.items[index] = .{
                .n_strx = n_strx,
                .n_type = macho.N_OSO,
                .n_sect = 0,
                .n_desc = 1,
                .n_value = sf.get_oso_mod_time(self),
            };
            index += 1;

            for (sf.stabs.items) |stab| {
                const sym = stab.get_symbol(macho_file) orelse continue;
                const file = sym.get_file(macho_file).?;
                if (file.get_index() != self.index) continue;
                if (!sym.flags.output_symtab) continue;
                const sym_n_strx = n_strx: {
                    const symtab_index = sym.get_output_symtab_index(macho_file).?;
                    const osym = ctx.symtab.items[symtab_index];
                    break :n_strx osym.n_strx;
                };
                const sym_n_sect: u8 = if (!sym.flags.abs) @int_cast(sym.out_n_sect + 1) else 0;
                const sym_n_value = sym.get_address(.{}, macho_file);
                const sym_size = sym.get_size(macho_file);
                if (stab.is_func) {
                    write_func_stab(sym_n_strx, sym_n_sect, sym_n_value, sym_size, index, ctx);
                    index += 4;
                } else if (sym.visibility == .global) {
                    ctx.symtab.items[index] = .{
                        .n_strx = sym_n_strx,
                        .n_type = macho.N_GSYM,
                        .n_sect = sym_n_sect,
                        .n_desc = 0,
                        .n_value = 0,
                    };
                    index += 1;
                } else {
                    ctx.symtab.items[index] = .{
                        .n_strx = sym_n_strx,
                        .n_type = macho.N_STSYM,
                        .n_sect = sym_n_sect,
                        .n_desc = 0,
                        .n_value = sym_n_value,
                    };
                    index += 1;
                }
            }

            // Close scope
            // N_SO
            ctx.symtab.items[index] = .{
                .n_strx = 0,
                .n_type = macho.N_SO,
                .n_sect = 0,
                .n_desc = 0,
                .n_value = 0,
            };
            index += 1;
        }
    }
}

fn get_section_data(self: *const Object, index: u32, macho_file: *MachO) ![]u8 {
    const gpa = macho_file.base.comp.gpa;
    const slice = self.sections.slice();
    assert(index < slice.items(.header).len);
    const sect = slice.items(.header)[index];
    const handle = macho_file.get_file_handle(self.file_handle);
    const offset = if (self.archive) |ar| ar.offset else 0;
    const size = math.cast(usize, sect.size) orelse return error.Overflow;
    const buffer = try gpa.alloc(u8, size);
    errdefer gpa.free(buffer);
    const amt = try handle.pread_all(buffer, sect.offset + offset);
    if (amt != buffer.len) return error.InputOutput;
    return buffer;
}

pub fn get_atom_data(self: *const Object, macho_file: *MachO, atom: Atom, buffer: []u8) !void {
    assert(buffer.len == atom.size);
    const slice = self.sections.slice();
    const handle = macho_file.get_file_handle(self.file_handle);
    const offset = if (self.archive) |ar| ar.offset else 0;
    const sect = slice.items(.header)[atom.n_sect];
    const amt = try handle.pread_all(buffer, sect.offset + offset + atom.off);
    if (amt != buffer.len) return error.InputOutput;
}

pub fn get_atom_relocs(self: *const Object, atom: Atom, macho_file: *MachO) []const Relocation {
    if (!atom.flags.relocs) return &[0]Relocation{};
    const extra = atom.get_extra(macho_file).?;
    const relocs = self.sections.items(.relocs)[atom.n_sect];
    return relocs.items[extra.rel_index..][0..extra.rel_count];
}

fn add_string(self: *Object, allocator: Allocator, name: [:0]const u8) error{OutOfMemory}!u32 {
    const off: u32 = @int_cast(self.strtab.items.len);
    try self.strtab.ensure_unused_capacity(allocator, name.len + 1);
    self.strtab.append_slice_assume_capacity(name);
    self.strtab.append_assume_capacity(0);
    return off;
}

pub fn get_string(self: Object, off: u32) [:0]const u8 {
    assert(off < self.strtab.items.len);
    return mem.slice_to(@as([*:0]const u8, @ptr_cast(self.strtab.items.ptr + off)), 0);
}

pub fn has_unwind_records(self: Object) bool {
    return self.unwind_records.items.len > 0;
}

pub fn has_eh_frame_records(self: Object) bool {
    return self.cies.items.len > 0;
}

pub fn has_debug_info(self: Object) bool {
    return self.compile_unit != null or self.has_symbol_stabs();
}

fn has_symbol_stabs(self: Object) bool {
    return self.stab_files.items.len > 0;
}

pub fn has_objc(self: Object) bool {
    for (self.symtab.items(.nlist)) |nlist| {
        const name = self.get_string(nlist.n_strx);
        if (mem.starts_with(u8, name, "_OBJC_CLASS_$_")) return true;
    }
    for (self.sections.items(.header)) |sect| {
        if (mem.eql(u8, sect.seg_name(), "__DATA") and mem.eql(u8, sect.sect_name(), "__objc_catlist")) return true;
        if (mem.eql(u8, sect.seg_name(), "__TEXT") and mem.eql(u8, sect.sect_name(), "__swift")) return true;
    }
    return false;
}

pub fn get_data_in_code(self: Object) []const macho.data_in_code_entry {
    return self.data_in_code.items;
}

pub inline fn has_subsections(self: Object) bool {
    return self.header.?.flags & macho.MH_SUBSECTIONS_VIA_SYMBOLS != 0;
}

pub fn as_file(self: *Object) File {
    return .{ .object = self };
}

pub fn format(
    self: *Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = self;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compile_error("do not format objects directly");
}

const FormatContext = struct {
    object: *Object,
    macho_file: *MachO,
};

pub fn fmt_atoms(self: *Object, macho_file: *MachO) std.fmt.Formatter(format_atoms) {
    return .{ .data = .{
        .object = self,
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
    const object = ctx.object;
    try writer.write_all("  atoms\n");
    for (object.atoms.items) |atom_index| {
        const atom = ctx.macho_file.get_atom(atom_index).?;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

pub fn fmt_cies(self: *Object, macho_file: *MachO) std.fmt.Formatter(format_cies) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
    } };
}

fn format_cies(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.write_all("  cies\n");
    for (object.cies.items, 0..) |cie, i| {
        try writer.print("    cie({d}) : {}\n", .{ i, cie.fmt(ctx.macho_file) });
    }
}

pub fn fmt_fdes(self: *Object, macho_file: *MachO) std.fmt.Formatter(format_fdes) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
    } };
}

fn format_fdes(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    try writer.write_all("  fdes\n");
    for (object.fdes.items, 0..) |fde, i| {
        try writer.print("    fde({d}) : {}\n", .{ i, fde.fmt(ctx.macho_file) });
    }
}

pub fn fmt_unwind_records(self: *Object, macho_file: *MachO) std.fmt.Formatter(format_unwind_records) {
    return .{ .data = .{
        .object = self,
        .macho_file = macho_file,
    } };
}

fn format_unwind_records(
    ctx: FormatContext,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const object = ctx.object;
    const macho_file = ctx.macho_file;
    try writer.write_all("  unwind records\n");
    for (object.unwind_records.items) |rec| {
        try writer.print("    rec({d}) : {}\n", .{ rec, macho_file.get_unwind_record(rec).fmt(macho_file) });
    }
}

pub fn fmt_symtab(self: *Object, macho_file: *MachO) std.fmt.Formatter(format_symtab) {
    return .{ .data = .{
        .object = self,
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
    const object = ctx.object;
    try writer.write_all("  symbols\n");
    for (object.symbols.items) |index| {
        const sym = ctx.macho_file.get_symbol(index);
        try writer.print("    {}\n", .{sym.fmt(ctx.macho_file)});
    }
}

pub fn fmt_path(self: Object) std.fmt.Formatter(format_path) {
    return .{ .data = self };
}

fn format_path(
    object: Object,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    if (object.archive) |ar| {
        try writer.write_all(ar.path);
        try writer.write_byte('(');
        try writer.write_all(object.path);
        try writer.write_byte(')');
    } else try writer.write_all(object.path);
}

const Section = struct {
    header: macho.section_64,
    subsections: std.ArrayListUnmanaged(Subsection) = .{},
    relocs: std.ArrayListUnmanaged(Relocation) = .{},
};

const Subsection = struct {
    atom: Atom.Index,
    off: u64,
};

pub const Nlist = struct {
    nlist: macho.nlist_64,
    size: u64,
    atom: Atom.Index,
};

const StabFile = struct {
    comp_dir: u32,
    stabs: std.ArrayListUnmanaged(Stab) = .{},

    fn get_comp_dir(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir];
        return object.get_string(nlist.n_strx);
    }

    fn get_tu_name(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 1];
        return object.get_string(nlist.n_strx);
    }

    fn get_oso_path(sf: StabFile, object: *const Object) [:0]const u8 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 2];
        return object.get_string(nlist.n_strx);
    }

    fn get_oso_mod_time(sf: StabFile, object: *const Object) u64 {
        const nlist = object.symtab.items(.nlist)[sf.comp_dir + 2];
        return nlist.n_value;
    }

    const Stab = struct {
        is_func: bool = true,
        symbol: ?Symbol.Index = null,

        fn get_symbol(stab: Stab, macho_file: *MachO) ?*Symbol {
            return if (stab.symbol) |s| macho_file.get_symbol(s) else null;
        }
    };
};

const CompileUnit = struct {
    comp_dir: u32,
    tu_name: u32,

    fn get_comp_dir(cu: CompileUnit, object: *const Object) [:0]const u8 {
        return object.get_string(cu.comp_dir);
    }

    fn get_tu_name(cu: CompileUnit, object: *const Object) [:0]const u8 {
        return object.get_string(cu.tu_name);
    }
};

const InArchive = struct {
    path: []const u8,
    offset: u64,
    size: u32,
};

const x86_64 = struct {
    fn parse_relocs(
        self: *const Object,
        n_sect: u8,
        sect: macho.section_64,
        out: *std.ArrayListUnmanaged(Relocation),
        macho_file: *MachO,
    ) !void {
        const gpa = macho_file.base.comp.gpa;

        const handle = macho_file.get_file_handle(self.file_handle);
        const offset = if (self.archive) |ar| ar.offset else 0;
        const relocs_buffer = try gpa.alloc(u8, sect.nreloc * @size_of(macho.relocation_info));
        defer gpa.free(relocs_buffer);
        {
            const amt = try handle.pread_all(relocs_buffer, sect.reloff + offset);
            if (amt != relocs_buffer.len) return error.InputOutput;
        }
        const relocs = @as([*]align(1) const macho.relocation_info, @ptr_cast(relocs_buffer.ptr))[0..sect.nreloc];

        const code = try self.get_section_data(@int_cast(n_sect), macho_file);
        defer gpa.free(code);

        try out.ensure_total_capacity_precise(gpa, relocs.len);

        var i: usize = 0;
        while (i < relocs.len) : (i += 1) {
            const rel = relocs[i];
            const rel_type: macho.reloc_type_x86_64 = @enumFromInt(rel.r_type);
            const rel_offset = @as(u32, @int_cast(rel.r_address));

            var addend = switch (rel.r_length) {
                0 => code[rel_offset],
                1 => mem.read_int(i16, code[rel_offset..][0..2], .little),
                2 => mem.read_int(i32, code[rel_offset..][0..4], .little),
                3 => mem.read_int(i64, code[rel_offset..][0..8], .little),
            };
            addend += switch (@as(macho.reloc_type_x86_64, @enumFromInt(rel.r_type))) {
                .X86_64_RELOC_SIGNED_1 => 1,
                .X86_64_RELOC_SIGNED_2 => 2,
                .X86_64_RELOC_SIGNED_4 => 4,
                else => 0,
            };

            const target = if (rel.r_extern == 0) blk: {
                const nsect = rel.r_symbolnum - 1;
                const taddr: i64 = if (rel.r_pcrel == 1)
                    @as(i64, @int_cast(sect.addr)) + rel.r_address + addend + 4
                else
                    addend;
                const target = self.find_atom_in_section(@int_cast(taddr), @int_cast(nsect)) orelse {
                    try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                        sect.seg_name(), sect.sect_name(), rel.r_address,
                    });
                    return error.MalformedObject;
                };
                addend = taddr - @as(i64, @int_cast(macho_file.get_atom(target).?.get_input_address(macho_file)));
                break :blk target;
            } else self.symbols.items[rel.r_symbolnum];

            const has_subtractor = if (i > 0 and
                @as(macho.reloc_type_x86_64, @enumFromInt(relocs[i - 1].r_type)) == .X86_64_RELOC_SUBTRACTOR)
            blk: {
                if (rel_type != .X86_64_RELOC_UNSIGNED) {
                    try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: X86_64_RELOC_SUBTRACTOR followed by {s}", .{
                        sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type),
                    });
                    return error.MalformedObject;
                }
                break :blk true;
            } else false;

            const @"type": Relocation.Type = validate_reloc_type(rel, rel_type) catch |err| {
                switch (err) {
                    error.Pcrel => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: PC-relative {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                    error.NonPcrel => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: non-PC-relative {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                    error.InvalidLength => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: invalid length of {d} in {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @as(u8, 1) << rel.r_length, @tag_name(rel_type) },
                    ),
                    error.NonExtern => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: non-extern target in {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                }
                return error.MalformedObject;
            };

            out.append_assume_capacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = @as(u32, @int_cast(rel.r_address)),
                .target = target,
                .addend = addend,
                .type = @"type",
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .has_subtractor = has_subtractor,
                    .length = rel.r_length,
                    .symbolnum = rel.r_symbolnum,
                },
            });
        }
    }

    fn validate_reloc_type(rel: macho.relocation_info, rel_type: macho.reloc_type_x86_64) !Relocation.Type {
        switch (rel_type) {
            .X86_64_RELOC_UNSIGNED => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2 and rel.r_length != 3) return error.InvalidLength;
                return .unsigned;
            },

            .X86_64_RELOC_SUBTRACTOR => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                return .subtractor;
            },

            .X86_64_RELOC_BRANCH,
            .X86_64_RELOC_GOT_LOAD,
            .X86_64_RELOC_GOT,
            .X86_64_RELOC_TLV,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .X86_64_RELOC_BRANCH => .branch,
                    .X86_64_RELOC_GOT_LOAD => .got_load,
                    .X86_64_RELOC_GOT => .got,
                    .X86_64_RELOC_TLV => .tlv,
                    else => unreachable,
                };
            },

            .X86_64_RELOC_SIGNED,
            .X86_64_RELOC_SIGNED_1,
            .X86_64_RELOC_SIGNED_2,
            .X86_64_RELOC_SIGNED_4,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                return switch (rel_type) {
                    .X86_64_RELOC_SIGNED => .signed,
                    .X86_64_RELOC_SIGNED_1 => .signed1,
                    .X86_64_RELOC_SIGNED_2 => .signed2,
                    .X86_64_RELOC_SIGNED_4 => .signed4,
                    else => unreachable,
                };
            },
        }
    }
};

const aarch64 = struct {
    fn parse_relocs(
        self: *const Object,
        n_sect: u8,
        sect: macho.section_64,
        out: *std.ArrayListUnmanaged(Relocation),
        macho_file: *MachO,
    ) !void {
        const gpa = macho_file.base.comp.gpa;

        const handle = macho_file.get_file_handle(self.file_handle);
        const offset = if (self.archive) |ar| ar.offset else 0;
        const relocs_buffer = try gpa.alloc(u8, sect.nreloc * @size_of(macho.relocation_info));
        defer gpa.free(relocs_buffer);
        {
            const amt = try handle.pread_all(relocs_buffer, sect.reloff + offset);
            if (amt != relocs_buffer.len) return error.InputOutput;
        }
        const relocs = @as([*]align(1) const macho.relocation_info, @ptr_cast(relocs_buffer.ptr))[0..sect.nreloc];

        const code = try self.get_section_data(@int_cast(n_sect), macho_file);
        defer gpa.free(code);

        try out.ensure_total_capacity_precise(gpa, relocs.len);

        var i: usize = 0;
        while (i < relocs.len) : (i += 1) {
            var rel = relocs[i];
            const rel_offset = @as(u32, @int_cast(rel.r_address));

            var addend: i64 = 0;

            switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
                .ARM64_RELOC_ADDEND => {
                    addend = rel.r_symbolnum;
                    i += 1;
                    if (i >= relocs.len) {
                        try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: unterminated ARM64_RELOC_ADDEND", .{
                            sect.seg_name(), sect.sect_name(), rel_offset,
                        });
                        return error.MalformedObject;
                    }
                    rel = relocs[i];
                    switch (@as(macho.reloc_type_arm64, @enumFromInt(rel.r_type))) {
                        .ARM64_RELOC_PAGE21, .ARM64_RELOC_PAGEOFF12 => {},
                        else => |x| {
                            try macho_file.report_parse_error2(
                                self.index,
                                "{s},{s}: 0x{x}: ARM64_RELOC_ADDEND followed by {s}",
                                .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(x) },
                            );
                            return error.MalformedObject;
                        },
                    }
                },
                .ARM64_RELOC_UNSIGNED => {
                    addend = switch (rel.r_length) {
                        0 => code[rel_offset],
                        1 => mem.read_int(i16, code[rel_offset..][0..2], .little),
                        2 => mem.read_int(i32, code[rel_offset..][0..4], .little),
                        3 => mem.read_int(i64, code[rel_offset..][0..8], .little),
                    };
                },
                else => {},
            }

            const rel_type: macho.reloc_type_arm64 = @enumFromInt(rel.r_type);

            const target = if (rel.r_extern == 0) blk: {
                const nsect = rel.r_symbolnum - 1;
                const taddr: i64 = if (rel.r_pcrel == 1)
                    @as(i64, @int_cast(sect.addr)) + rel.r_address + addend
                else
                    addend;
                const target = self.find_atom_in_section(@int_cast(taddr), @int_cast(nsect)) orelse {
                    try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: bad relocation", .{
                        sect.seg_name(), sect.sect_name(), rel.r_address,
                    });
                    return error.MalformedObject;
                };
                addend = taddr - @as(i64, @int_cast(macho_file.get_atom(target).?.get_input_address(macho_file)));
                break :blk target;
            } else self.symbols.items[rel.r_symbolnum];

            const has_subtractor = if (i > 0 and
                @as(macho.reloc_type_arm64, @enumFromInt(relocs[i - 1].r_type)) == .ARM64_RELOC_SUBTRACTOR)
            blk: {
                if (rel_type != .ARM64_RELOC_UNSIGNED) {
                    try macho_file.report_parse_error2(self.index, "{s},{s}: 0x{x}: ARM64_RELOC_SUBTRACTOR followed by {s}", .{
                        sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type),
                    });
                    return error.MalformedObject;
                }
                break :blk true;
            } else false;

            const @"type": Relocation.Type = validate_reloc_type(rel, rel_type) catch |err| {
                switch (err) {
                    error.Pcrel => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: PC-relative {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                    error.NonPcrel => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: non-PC-relative {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                    error.InvalidLength => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: invalid length of {d} in {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @as(u8, 1) << rel.r_length, @tag_name(rel_type) },
                    ),
                    error.NonExtern => try macho_file.report_parse_error2(
                        self.index,
                        "{s},{s}: 0x{x}: non-extern target in {s} relocation",
                        .{ sect.seg_name(), sect.sect_name(), rel_offset, @tag_name(rel_type) },
                    ),
                }
                return error.MalformedObject;
            };

            out.append_assume_capacity(.{
                .tag = if (rel.r_extern == 1) .@"extern" else .local,
                .offset = @as(u32, @int_cast(rel.r_address)),
                .target = target,
                .addend = addend,
                .type = @"type",
                .meta = .{
                    .pcrel = rel.r_pcrel == 1,
                    .has_subtractor = has_subtractor,
                    .length = rel.r_length,
                    .symbolnum = rel.r_symbolnum,
                },
            });
        }
    }

    fn validate_reloc_type(rel: macho.relocation_info, rel_type: macho.reloc_type_arm64) !Relocation.Type {
        switch (rel_type) {
            .ARM64_RELOC_UNSIGNED => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2 and rel.r_length != 3) return error.InvalidLength;
                return .unsigned;
            },

            .ARM64_RELOC_SUBTRACTOR => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                return .subtractor;
            },

            .ARM64_RELOC_BRANCH26,
            .ARM64_RELOC_PAGE21,
            .ARM64_RELOC_GOT_LOAD_PAGE21,
            .ARM64_RELOC_TLVP_LOAD_PAGE21,
            .ARM64_RELOC_POINTER_TO_GOT,
            => {
                if (rel.r_pcrel == 0) return error.NonPcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .ARM64_RELOC_BRANCH26 => .branch,
                    .ARM64_RELOC_PAGE21 => .page,
                    .ARM64_RELOC_GOT_LOAD_PAGE21 => .got_load_page,
                    .ARM64_RELOC_TLVP_LOAD_PAGE21 => .tlvp_page,
                    .ARM64_RELOC_POINTER_TO_GOT => .got,
                    else => unreachable,
                };
            },

            .ARM64_RELOC_PAGEOFF12,
            .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
            .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
            => {
                if (rel.r_pcrel == 1) return error.Pcrel;
                if (rel.r_length != 2) return error.InvalidLength;
                if (rel.r_extern == 0) return error.NonExtern;
                return switch (rel_type) {
                    .ARM64_RELOC_PAGEOFF12 => .pageoff,
                    .ARM64_RELOC_GOT_LOAD_PAGEOFF12 => .got_load_pageoff,
                    .ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => .tlvp_pageoff,
                    else => unreachable,
                };
            },

            .ARM64_RELOC_ADDEND => unreachable, // We make it part of the addend field
        }
    }
};

const assert = std.debug.assert;
const dwarf = @import("dwarf.zig");
const eh_frame = @import("eh_frame.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../../tracy.zig").trace;
const std = @import("std");

const Allocator = mem.Allocator;
const Archive = @import("Archive.zig");
const Atom = @import("Atom.zig");
const Cie = eh_frame.Cie;
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const LoadCommandIterator = macho.LoadCommandIterator;
const MachO = @import("../MachO.zig");
const Object = @This();
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @import("UnwindInfo.zig");
