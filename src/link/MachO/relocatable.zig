pub fn flush_object(macho_file: *MachO, comp: *Compilation, module_obj_path: ?[]const u8) link.File.FlushError!void {
    const gpa = macho_file.base.comp.gpa;

    var positionals = std.ArrayList(Compilation.LinkObject).init(gpa);
    defer positionals.deinit();
    try positionals.ensure_unused_capacity(comp.objects.len);
    positionals.append_slice_assume_capacity(comp.objects);

    for (comp.c_object_table.keys()) |key| {
        try positionals.append(.{ .path = key.status.success.object_path });
    }

    if (module_obj_path) |path| try positionals.append(.{ .path = path });

    if (macho_file.get_zig_object() == null and positionals.items.len == 1) {
        // Instead of invoking a full-blown `-r` mode on the input which sadly will strip all
        // debug info segments/sections (this is apparently by design by Apple), we copy
        // the *only* input file over.
        // TODO: in the future, when we implement `dsymutil` alternative directly in the Zig
        // compiler, investigate if we can get rid of this `if` prong here.
        const path = positionals.items[0].path;
        const in_file = try std.fs.cwd().open_file(path, .{});
        const stat = try in_file.stat();
        const amt = try in_file.copy_range_all(0, macho_file.base.file.?, 0, stat.size);
        if (amt != stat.size) return error.InputOutput; // TODO: report an actual user error
        return;
    }

    for (positionals.items) |obj| {
        macho_file.parse_positional(obj.path, obj.must_link) catch |err| switch (err) {
            error.MalformedObject,
            error.MalformedArchive,
            error.InvalidCpuArch,
            error.InvalidTarget,
            => continue, // already reported
            error.UnknownFileType => try macho_file.report_parse_error(obj.path, "unknown file type for an object file", .{}),
            else => |e| try macho_file.report_parse_error(
                obj.path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    if (comp.link_errors.items.len > 0) return error.FlushFailure;

    try macho_file.add_undefined_globals();
    try macho_file.resolve_symbols();
    try macho_file.parse_debug_info();
    try macho_file.dedup_literals();
    mark_exports(macho_file);
    claim_unresolved(macho_file);
    try init_output_sections(macho_file);
    try macho_file.sort_sections();
    try macho_file.add_atoms_to_sections();
    try calc_section_sizes(macho_file);

    try create_segment(macho_file);
    try allocate_sections(macho_file);
    allocate_segment(macho_file);

    var off = off: {
        const seg = macho_file.segments.items[0];
        const off = math.cast(u32, seg.fileoff + seg.filesize) orelse return error.Overflow;
        break :off mem.align_forward(u32, off, @alignOf(macho.relocation_info));
    };
    off = allocate_sections_relocs(macho_file, off);

    if (build_options.enable_logging) {
        state_log.debug("{}", .{macho_file.dump_state()});
    }

    try macho_file.calc_symtab_size();
    try write_atoms(macho_file);
    try write_compact_unwind(macho_file);
    try write_eh_frame(macho_file);

    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try macho_file.write_data_in_code(0, off);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try macho_file.write_symtab(off);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try macho_file.write_strtab(off);

    // In order to please Apple ld (and possibly other MachO linkers in the wild),
    // we will now sanitize segment names of Zig-specific segments.
    sanitize_zig_sections(macho_file);

    const ncmds, const sizeofcmds = try write_load_commands(macho_file);
    try write_header(macho_file, ncmds, sizeofcmds);
}

pub fn flush_static_lib(macho_file: *MachO, comp: *Compilation, module_obj_path: ?[]const u8) link.File.FlushError!void {
    const gpa = comp.gpa;

    var positionals = std.ArrayList(Compilation.LinkObject).init(gpa);
    defer positionals.deinit();

    try positionals.ensure_unused_capacity(comp.objects.len);
    positionals.append_slice_assume_capacity(comp.objects);

    for (comp.c_object_table.keys()) |key| {
        try positionals.append(.{ .path = key.status.success.object_path });
    }

    if (module_obj_path) |path| try positionals.append(.{ .path = path });

    if (comp.include_compiler_rt) {
        try positionals.append(.{ .path = comp.compiler_rt_obj.?.full_object_path });
    }

    for (positionals.items) |obj| {
        parse_positional(macho_file, obj.path) catch |err| switch (err) {
            error.MalformedObject,
            error.MalformedArchive,
            error.InvalidCpuArch,
            error.InvalidTarget,
            => continue, // already reported
            error.UnknownFileType => try macho_file.report_parse_error(obj.path, "unknown file type for an object file", .{}),
            else => |e| try macho_file.report_parse_error(
                obj.path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    if (comp.link_errors.items.len > 0) return error.FlushFailure;

    // First, we flush relocatable object file generated with our backends.
    if (macho_file.get_zig_object()) |zo| {
        zo.resolve_symbols(macho_file);
        zo.as_file().mark_exports_relocatable(macho_file);
        zo.as_file().claim_unresolved_relocatable(macho_file);
        try macho_file.sort_sections();
        try macho_file.add_atoms_to_sections();
        try calc_section_sizes(macho_file);
        try create_segment(macho_file);
        try allocate_sections(macho_file);
        allocate_segment(macho_file);

        var off = off: {
            const seg = macho_file.segments.items[0];
            const off = math.cast(u32, seg.fileoff + seg.filesize) orelse return error.Overflow;
            break :off mem.align_forward(u32, off, @alignOf(macho.relocation_info));
        };
        off = allocate_sections_relocs(macho_file, off);

        if (build_options.enable_logging) {
            state_log.debug("{}", .{macho_file.dump_state()});
        }

        try macho_file.calc_symtab_size();
        try write_atoms(macho_file);

        off = mem.align_forward(u32, off, @alignOf(u64));
        off = try macho_file.write_data_in_code(0, off);
        off = mem.align_forward(u32, off, @alignOf(u64));
        off = try macho_file.write_symtab(off);
        off = mem.align_forward(u32, off, @alignOf(u64));
        off = try macho_file.write_strtab(off);

        // In order to please Apple ld (and possibly other MachO linkers in the wild),
        // we will now sanitize segment names of Zig-specific segments.
        sanitize_zig_sections(macho_file);

        const ncmds, const sizeofcmds = try write_load_commands(macho_file);
        try write_header(macho_file, ncmds, sizeofcmds);

        // TODO we can avoid reading in the file contents we just wrote if we give the linker
        // ability to write directly to a buffer.
        try zo.read_file_contents(off, macho_file);
    }

    var files = std.ArrayList(File.Index).init(gpa);
    defer files.deinit();
    try files.ensure_total_capacity_precise(macho_file.objects.items.len + 1);
    if (macho_file.get_zig_object()) |zo| files.append_assume_capacity(zo.index);
    for (macho_file.objects.items) |index| files.append_assume_capacity(index);

    const format: Archive.Format = .p32;
    const ptr_width = Archive.ptr_width(format);

    // Update ar symtab from parsed objects
    var ar_symtab: Archive.ArSymtab = .{};
    defer ar_symtab.deinit(gpa);

    for (files.items) |index| {
        try macho_file.get_file(index).?.update_ar_symtab(&ar_symtab, macho_file);
    }

    ar_symtab.sort();

    // Update sizes of contributing objects
    for (files.items) |index| {
        try macho_file.get_file(index).?.update_ar_size(macho_file);
    }

    // Update file offsets of contributing objects
    const total_size: usize = blk: {
        var pos: usize = Archive.SARMAG;
        pos += @size_of(Archive.ar_hdr);
        pos += mem.align_forward(usize, Archive.SYMDEF.len + 1, ptr_width);
        pos += ar_symtab.size(format);

        for (files.items) |index| {
            const file = macho_file.get_file(index).?;
            const state = switch (file) {
                .zig_object => |x| &x.output_ar_state,
                .object => |x| &x.output_ar_state,
                else => unreachable,
            };
            const path = switch (file) {
                .zig_object => |x| x.path,
                .object => |x| x.path,
                else => unreachable,
            };
            pos = mem.align_forward(usize, pos, 2);
            state.file_off = pos;
            pos += @size_of(Archive.ar_hdr);
            pos += mem.align_forward(usize, path.len + 1, ptr_width);
            pos += math.cast(usize, state.size) orelse return error.Overflow;
        }

        break :blk pos;
    };

    if (build_options.enable_logging) {
        state_log.debug("ar_symtab\n{}\n", .{ar_symtab.fmt(macho_file)});
    }

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensure_total_capacity_precise(total_size);
    const writer = buffer.writer();

    // Write magic
    try writer.write_all(Archive.ARMAG);

    // Write symtab
    try ar_symtab.write(format, macho_file, writer);

    // Write object files
    for (files.items) |index| {
        const aligned = mem.align_forward(usize, buffer.items.len, 2);
        const padding = aligned - buffer.items.len;
        if (padding > 0) {
            try writer.write_byte_ntimes(0, padding);
        }
        try macho_file.get_file(index).?.write_ar(format, macho_file, writer);
    }

    assert(buffer.items.len == total_size);

    try macho_file.base.file.?.set_end_pos(total_size);
    try macho_file.base.file.?.pwrite_all(buffer.items, 0);

    if (comp.link_errors.items.len > 0) return error.FlushFailure;
}

fn parse_positional(macho_file: *MachO, path: []const u8) MachO.ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();
    if (try Object.is_object(path)) {
        try parse_object(macho_file, path);
    } else if (try fat.is_fat_library(path)) {
        const fat_arch = try macho_file.parse_fat_library(path);
        if (try Archive.is_archive(path, fat_arch)) {
            try parse_archive(macho_file, path, fat_arch);
        } else return error.UnknownFileType;
    } else if (try Archive.is_archive(path, null)) {
        try parse_archive(macho_file, path, null);
    } else return error.UnknownFileType;
}

fn parse_object(macho_file: *MachO, path: []const u8) MachO.ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const file = try std.fs.cwd().open_file(path, .{});
    errdefer file.close();
    const handle = try macho_file.add_file_handle(file);
    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @as(u64, @int_cast(@div_floor(stat.mtime, 1_000_000_000)));
    };
    const index = @as(File.Index, @int_cast(try macho_file.files.add_one(gpa)));
    macho_file.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, path),
        .file_handle = handle,
        .mtime = mtime,
        .index = index,
    } });
    try macho_file.objects.append(gpa, index);

    const object = macho_file.get_file(index).?.object;
    try object.parse_ar(macho_file);
}

fn parse_archive(macho_file: *MachO, path: []const u8, fat_arch: ?fat.Arch) MachO.ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;

    const file = try std.fs.cwd().open_file(path, .{});
    errdefer file.close();
    const handle = try macho_file.add_file_handle(file);

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(macho_file, path, handle, fat_arch);

    var has_parse_error = false;
    for (archive.objects.items) |extracted| {
        const index = @as(File.Index, @int_cast(try macho_file.files.add_one(gpa)));
        macho_file.files.set(index, .{ .object = extracted });
        const object = &macho_file.files.items(.data)[index].object;
        object.index = index;
        object.parse_ar(macho_file) catch |err| switch (err) {
            error.InvalidCpuArch => has_parse_error = true,
            else => |e| return e,
        };
        try macho_file.objects.append(gpa, index);
    }
    if (has_parse_error) return error.MalformedArchive;
}

fn mark_exports(macho_file: *MachO) void {
    if (macho_file.get_zig_object()) |zo| {
        zo.as_file().mark_exports_relocatable(macho_file);
    }
    for (macho_file.objects.items) |index| {
        macho_file.get_file(index).?.mark_exports_relocatable(macho_file);
    }
}

pub fn claim_unresolved(macho_file: *MachO) void {
    if (macho_file.get_zig_object()) |zo| {
        zo.as_file().claim_unresolved_relocatable(macho_file);
    }
    for (macho_file.objects.items) |index| {
        macho_file.get_file(index).?.claim_unresolved_relocatable(macho_file);
    }
}

fn init_output_sections(macho_file: *MachO) !void {
    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.init_output_section(atom.get_input_section(macho_file), macho_file);
        }
    }

    const needs_unwind_info = for (macho_file.objects.items) |index| {
        if (macho_file.get_file(index).?.object.has_unwind_records()) break true;
    } else false;
    if (needs_unwind_info) {
        macho_file.unwind_info_sect_index = try macho_file.add_section("__LD", "__compact_unwind", .{
            .flags = macho.S_ATTR_DEBUG,
        });
    }

    const needs_eh_frame = for (macho_file.objects.items) |index| {
        if (macho_file.get_file(index).?.object.has_eh_frame_records()) break true;
    } else false;
    if (needs_eh_frame) {
        assert(needs_unwind_info);
        macho_file.eh_frame_sect_index = try macho_file.add_section("__TEXT", "__eh_frame", .{});
    }
}

fn calc_section_sizes(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const slice = macho_file.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |*header, atoms| {
        if (atoms.items.len == 0) continue;
        for (atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index).?;
            const atom_alignment = atom.alignment.to_byte_units() orelse 1;
            const offset = mem.align_forward(u64, header.size, atom_alignment);
            const padding = offset - header.size;
            atom.value = offset;
            header.size += padding + atom.size;
            header.@"align" = @max(header.@"align", atom.alignment.to_log2_units());
            header.nreloc += atom.calc_num_relocs(macho_file);
        }
    }

    if (macho_file.unwind_info_sect_index) |index| {
        calc_compact_unwind_size(macho_file, index);
    }

    if (macho_file.eh_frame_sect_index) |index| {
        const sect = &macho_file.sections.items(.header)[index];
        sect.size = try eh_frame.calc_size(macho_file);
        sect.@"align" = 3;
        sect.nreloc = eh_frame.calc_num_relocs(macho_file);
    }

    if (macho_file.get_zig_object()) |zo| {
        for (zo.atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const header = &macho_file.sections.items(.header)[atom.out_n_sect];
            if (!macho_file.is_zig_section(atom.out_n_sect) and !macho_file.is_debug_section(atom.out_n_sect)) continue;
            header.nreloc += atom.calc_num_relocs(macho_file);
        }
    }
}

fn calc_compact_unwind_size(macho_file: *MachO, sect_index: u8) void {
    var size: u32 = 0;
    var nreloc: u32 = 0;

    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.unwind_records.items) |irec| {
            const rec = macho_file.get_unwind_record(irec);
            if (!rec.alive) continue;
            size += @size_of(macho.compact_unwind_entry);
            nreloc += 1;
            if (rec.get_personality(macho_file)) |_| {
                nreloc += 1;
            }
            if (rec.get_lsda_atom(macho_file)) |_| {
                nreloc += 1;
            }
        }
    }

    const sect = &macho_file.sections.items(.header)[sect_index];
    sect.size = size;
    sect.nreloc = nreloc;
    sect.@"align" = 3;
}

fn allocate_sections(macho_file: *MachO) !void {
    const slice = macho_file.sections.slice();
    for (slice.items(.header)) |*header| {
        const needed_size = header.size;
        header.size = 0;
        const alignment = try math.powi(u32, 2, header.@"align");
        if (!header.is_zerofill()) {
            if (needed_size > macho_file.allocated_size(header.offset)) {
                header.offset = math.cast(u32, macho_file.find_free_space(needed_size, alignment)) orelse
                    return error.Overflow;
            }
        }
        if (needed_size > macho_file.allocated_size_virtual(header.addr)) {
            header.addr = macho_file.find_free_space_virtual(needed_size, alignment);
        }
        header.size = needed_size;
    }
}

/// Renames segment names in Zig sections to standard MachO segment names such as
/// `__TEXT`, `__DATA_CONST` and `__DATA`.
/// TODO: I think I may be able to get rid of this if I rework section/segment
/// allocation mechanism to not rely so much on having `_ZIG` sections always
/// pushed to the back. For instance, this is not a problem in ELF linker.
/// Then, we can create sections with the correct name from the start in `MachO.init_metadata`.
fn sanitize_zig_sections(macho_file: *MachO) void {
    if (macho_file.zig_text_sect_index) |index| {
        const header = &macho_file.sections.items(.header)[index];
        header.segname = MachO.make_static_string("__TEXT");
    }
    if (macho_file.zig_const_sect_index) |index| {
        const header = &macho_file.sections.items(.header)[index];
        header.segname = MachO.make_static_string("__DATA_CONST");
    }
    if (macho_file.zig_data_sect_index) |index| {
        const header = &macho_file.sections.items(.header)[index];
        header.segname = MachO.make_static_string("__DATA");
    }
    if (macho_file.zig_bss_sect_index) |index| {
        const header = &macho_file.sections.items(.header)[index];
        header.segname = MachO.make_static_string("__DATA");
    }
}

fn create_segment(macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;

    // For relocatable, we only ever need a single segment so create it now.
    const prot: macho.vm_prot_t = macho.PROT.READ | macho.PROT.WRITE | macho.PROT.EXEC;
    try macho_file.segments.append(gpa, .{
        .cmdsize = @size_of(macho.segment_command_64),
        .segname = MachO.make_static_string(""),
        .maxprot = prot,
        .initprot = prot,
    });
    const seg = &macho_file.segments.items[0];
    seg.nsects = @int_cast(macho_file.sections.items(.header).len);
    seg.cmdsize += seg.nsects * @size_of(macho.section_64);
}

fn allocate_segment(macho_file: *MachO) void {
    // Allocate the single segment.
    const seg = &macho_file.segments.items[0];
    var vmaddr: u64 = 0;
    var fileoff: u64 = load_commands.calc_load_commands_size_object(macho_file) + @size_of(macho.mach_header_64);
    seg.vmaddr = vmaddr;
    seg.fileoff = fileoff;

    for (macho_file.sections.items(.header)) |header| {
        vmaddr = @max(vmaddr, header.addr + header.size);
        if (!header.is_zerofill()) {
            fileoff = @max(fileoff, header.offset + header.size);
        }
    }

    seg.vmsize = vmaddr - seg.vmaddr;
    seg.filesize = fileoff - seg.fileoff;
}

fn allocate_sections_relocs(macho_file: *MachO, off: u32) u32 {
    var fileoff = off;
    const slice = macho_file.sections.slice();
    for (slice.items(.header)) |*header| {
        if (header.nreloc == 0) continue;
        header.reloff = mem.align_forward(u32, fileoff, @alignOf(macho.relocation_info));
        fileoff = header.reloff + header.nreloc * @size_of(macho.relocation_info);
    }
    return fileoff;
}

// We need to sort relocations in descending order to be compatible with Apple's linker.
fn sort_reloc(ctx: void, lhs: macho.relocation_info, rhs: macho.relocation_info) bool {
    _ = ctx;
    return lhs.r_address > rhs.r_address;
}

fn write_atoms(macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const cpu_arch = macho_file.get_target().cpu.arch;
    const slice = macho_file.sections.slice();

    var relocs = std.ArrayList(macho.relocation_info).init(gpa);
    defer relocs.deinit();

    for (slice.items(.header), slice.items(.atoms), 0..) |header, atoms, i| {
        if (atoms.items.len == 0) continue;
        if (header.is_zerofill()) continue;
        if (macho_file.is_zig_section(@int_cast(i)) or macho_file.is_debug_section(@int_cast(i))) continue;

        const size = math.cast(usize, header.size) orelse return error.Overflow;
        const code = try gpa.alloc(u8, size);
        defer gpa.free(code);
        const padding_byte: u8 = if (header.is_code() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(code, padding_byte);

        try relocs.ensure_total_capacity(header.nreloc);

        for (atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index).?;
            assert(atom.flags.alive);
            const off = math.cast(usize, atom.value) orelse return error.Overflow;
            const atom_size = math.cast(usize, atom.size) orelse return error.Overflow;
            try atom.get_data(macho_file, code[off..][0..atom_size]);
            try atom.write_relocs(macho_file, code[off..][0..atom_size], &relocs);
        }

        assert(relocs.items.len == header.nreloc);

        mem.sort(macho.relocation_info, relocs.items, {}, sort_reloc);

        // TODO scattered writes?
        try macho_file.base.file.?.pwrite_all(code, header.offset);
        try macho_file.base.file.?.pwrite_all(mem.slice_as_bytes(relocs.items), header.reloff);

        relocs.clear_retaining_capacity();
    }

    if (macho_file.get_zig_object()) |zo| {
        // TODO: this is ugly; perhaps we should aggregrate before?
        var zo_relocs = std.AutoArrayHashMap(u8, std.ArrayList(macho.relocation_info)).init(gpa);
        defer {
            for (zo_relocs.values()) |*list| {
                list.deinit();
            }
            zo_relocs.deinit();
        }

        for (macho_file.sections.items(.header), 0..) |header, n_sect| {
            if (header.is_zerofill()) continue;
            if (!macho_file.is_zig_section(@int_cast(n_sect)) and !macho_file.is_debug_section(@int_cast(n_sect))) continue;
            const gop = try zo_relocs.get_or_put(@int_cast(n_sect));
            if (gop.found_existing) continue;
            gop.value_ptr.* = try std.ArrayList(macho.relocation_info).init_capacity(gpa, header.nreloc);
        }

        for (zo.atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const header = macho_file.sections.items(.header)[atom.out_n_sect];
            if (header.is_zerofill()) continue;
            if (!macho_file.is_zig_section(atom.out_n_sect) and !macho_file.is_debug_section(atom.out_n_sect)) continue;
            if (atom.get_relocs(macho_file).len == 0) continue;
            const atom_size = math.cast(usize, atom.size) orelse return error.Overflow;
            const code = try gpa.alloc(u8, atom_size);
            defer gpa.free(code);
            atom.get_data(macho_file, code) catch |err| switch (err) {
                error.InputOutput => {
                    try macho_file.report_unexpected_error("fetching code for '{s}' failed", .{
                        atom.get_name(macho_file),
                    });
                    return error.FlushFailure;
                },
                else => |e| {
                    try macho_file.report_unexpected_error("unexpected error while fetching code for '{s}': {s}", .{
                        atom.get_name(macho_file),
                        @errorName(e),
                    });
                    return error.FlushFailure;
                },
            };
            const file_offset = header.offset + atom.value;
            const rels = zo_relocs.get_ptr(atom.out_n_sect).?;
            try atom.write_relocs(macho_file, code, rels);
            try macho_file.base.file.?.pwrite_all(code, file_offset);
        }

        for (zo_relocs.keys(), zo_relocs.values()) |sect_id, rels| {
            const header = macho_file.sections.items(.header)[sect_id];
            assert(rels.items.len == header.nreloc);
            mem.sort(macho.relocation_info, rels.items, {}, sort_reloc);
            try macho_file.base.file.?.pwrite_all(mem.slice_as_bytes(rels.items), header.reloff);
        }
    }
}

fn write_compact_unwind(macho_file: *MachO) !void {
    const sect_index = macho_file.unwind_info_sect_index orelse return;
    const gpa = macho_file.base.comp.gpa;
    const header = macho_file.sections.items(.header)[sect_index];

    const nrecs = math.cast(usize, @div_exact(header.size, @size_of(macho.compact_unwind_entry))) orelse return error.Overflow;
    var entries = try std.ArrayList(macho.compact_unwind_entry).init_capacity(gpa, nrecs);
    defer entries.deinit();

    var relocs = try std.ArrayList(macho.relocation_info).init_capacity(gpa, header.nreloc);
    defer relocs.deinit();

    const add_reloc = struct {
        fn add_reloc(offset: i32, cpu_arch: std.Target.Cpu.Arch) macho.relocation_info {
            return .{
                .r_address = offset,
                .r_symbolnum = 0,
                .r_pcrel = 0,
                .r_length = 3,
                .r_extern = 0,
                .r_type = switch (cpu_arch) {
                    .aarch64 => @int_from_enum(macho.reloc_type_arm64.ARM64_RELOC_UNSIGNED),
                    .x86_64 => @int_from_enum(macho.reloc_type_x86_64.X86_64_RELOC_UNSIGNED),
                    else => unreachable,
                },
            };
        }
    }.add_reloc;

    var offset: i32 = 0;
    for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        for (object.unwind_records.items) |irec| {
            const rec = macho_file.get_unwind_record(irec);
            if (!rec.alive) continue;

            var out: macho.compact_unwind_entry = .{
                .rangeStart = 0,
                .rangeLength = rec.length,
                .compactUnwindEncoding = rec.enc.enc,
                .personalityFunction = 0,
                .lsda = 0,
            };

            {
                // Function address
                const atom = rec.get_atom(macho_file);
                const addr = rec.get_atom_address(macho_file);
                out.rangeStart = addr;
                var reloc = add_reloc(offset, macho_file.get_target().cpu.arch);
                reloc.r_symbolnum = atom.out_n_sect + 1;
                relocs.append_assume_capacity(reloc);
            }

            // Personality function
            if (rec.get_personality(macho_file)) |sym| {
                const r_symbolnum = math.cast(u24, sym.get_output_symtab_index(macho_file).?) orelse return error.Overflow;
                var reloc = add_reloc(offset + 16, macho_file.get_target().cpu.arch);
                reloc.r_symbolnum = r_symbolnum;
                reloc.r_extern = 1;
                relocs.append_assume_capacity(reloc);
            }

            // LSDA address
            if (rec.get_lsda_atom(macho_file)) |atom| {
                const addr = rec.get_lsda_address(macho_file);
                out.lsda = addr;
                var reloc = add_reloc(offset + 24, macho_file.get_target().cpu.arch);
                reloc.r_symbolnum = atom.out_n_sect + 1;
                relocs.append_assume_capacity(reloc);
            }

            entries.append_assume_capacity(out);
            offset += @size_of(macho.compact_unwind_entry);
        }
    }

    assert(entries.items.len == nrecs);
    assert(relocs.items.len == header.nreloc);

    mem.sort(macho.relocation_info, relocs.items, {}, sort_reloc);

    // TODO scattered writes?
    try macho_file.base.file.?.pwrite_all(mem.slice_as_bytes(entries.items), header.offset);
    try macho_file.base.file.?.pwrite_all(mem.slice_as_bytes(relocs.items), header.reloff);
}

fn write_eh_frame(macho_file: *MachO) !void {
    const sect_index = macho_file.eh_frame_sect_index orelse return;
    const gpa = macho_file.base.comp.gpa;
    const header = macho_file.sections.items(.header)[sect_index];
    const size = math.cast(usize, header.size) orelse return error.Overflow;

    const code = try gpa.alloc(u8, size);
    defer gpa.free(code);

    var relocs = try std.ArrayList(macho.relocation_info).init_capacity(gpa, header.nreloc);
    defer relocs.deinit();

    try eh_frame.write_relocs(macho_file, code, &relocs);
    assert(relocs.items.len == header.nreloc);

    mem.sort(macho.relocation_info, relocs.items, {}, sort_reloc);

    // TODO scattered writes?
    try macho_file.base.file.?.pwrite_all(code, header.offset);
    try macho_file.base.file.?.pwrite_all(mem.slice_as_bytes(relocs.items), header.reloff);
}

fn write_load_commands(macho_file: *MachO) !struct { usize, usize } {
    const gpa = macho_file.base.comp.gpa;
    const needed_size = load_commands.calc_load_commands_size_object(macho_file);
    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);

    var stream = std.io.fixed_buffer_stream(buffer);
    const writer = stream.writer();

    var ncmds: usize = 0;

    // Segment and section load commands
    {
        assert(macho_file.segments.items.len == 1);
        const seg = macho_file.segments.items[0];
        try writer.write_struct(seg);
        for (macho_file.sections.items(.header)) |header| {
            try writer.write_struct(header);
        }
        ncmds += 1;
    }

    try writer.write_struct(macho_file.data_in_code_cmd);
    ncmds += 1;
    try writer.write_struct(macho_file.symtab_cmd);
    ncmds += 1;
    try writer.write_struct(macho_file.dysymtab_cmd);
    ncmds += 1;

    if (macho_file.platform.is_build_version_compatible()) {
        try load_commands.write_build_version_lc(macho_file.platform, macho_file.sdk_version, writer);
        ncmds += 1;
    } else {
        try load_commands.write_version_min_lc(macho_file.platform, macho_file.sdk_version, writer);
        ncmds += 1;
    }

    assert(stream.pos == needed_size);

    try macho_file.base.file.?.pwrite_all(buffer, @size_of(macho.mach_header_64));

    return .{ ncmds, buffer.len };
}

fn write_header(macho_file: *MachO, ncmds: usize, sizeofcmds: usize) !void {
    var header: macho.mach_header_64 = .{};
    header.filetype = macho.MH_OBJECT;

    const subsections_via_symbols = for (macho_file.objects.items) |index| {
        const object = macho_file.get_file(index).?.object;
        if (object.has_subsections()) break true;
    } else false;
    if (subsections_via_symbols) {
        header.flags |= macho.MH_SUBSECTIONS_VIA_SYMBOLS;
    }

    switch (macho_file.get_target().cpu.arch) {
        .aarch64 => {
            header.cputype = macho.CPU_TYPE_ARM64;
            header.cpusubtype = macho.CPU_SUBTYPE_ARM_ALL;
        },
        .x86_64 => {
            header.cputype = macho.CPU_TYPE_X86_64;
            header.cpusubtype = macho.CPU_SUBTYPE_X86_64_ALL;
        },
        else => {},
    }

    header.ncmds = @int_cast(ncmds);
    header.sizeofcmds = @int_cast(sizeofcmds);

    try macho_file.base.file.?.pwrite_all(mem.as_bytes(&header), 0);
}

const assert = std.debug.assert;
const build_options = @import("build_options");
const eh_frame = @import("eh_frame.zig");
const fat = @import("fat.zig");
const link = @import("../../link.zig");
const load_commands = @import("load_commands.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const state_log = std.log.scoped(.link_state);
const std = @import("std");
const trace = @import("../../tracy.zig").trace;

const Archive = @import("Archive.zig");
const Atom = @import("Atom.zig");
const Compilation = @import("../../Compilation.zig");
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
