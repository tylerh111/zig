/// Address offset allocated for this Atom wrt to its section start address.
value: u64 = 0,

/// Name of this Atom.
name: u32 = 0,

/// Index into linker's input file table.
file: File.Index = 0,

/// Size of this atom
size: u64 = 0,

/// Alignment of this atom as a power of two.
alignment: Alignment = .@"1",

/// Index of the input section.
n_sect: u32 = 0,

/// Index of the output section.
out_n_sect: u8 = 0,

/// Offset within the parent section pointed to by n_sect.
/// off + size <= parent section size.
off: u64 = 0,

/// Index of this atom in the linker's atoms table.
atom_index: Index = 0,

flags: Flags = .{},

/// Points to the previous and next neighbors, based on the `text_offset`.
/// This can be used to find, for example, the capacity of this `TextBlock`.
prev_index: Index = 0,
next_index: Index = 0,

extra: u32 = 0,

pub fn get_name(self: Atom, macho_file: *MachO) [:0]const u8 {
    return switch (self.get_file(macho_file)) {
        .dylib => unreachable,
        .zig_object => |x| x.strtab.get_assume_exists(self.name),
        inline else => |x| x.get_string(self.name),
    };
}

pub fn get_file(self: Atom, macho_file: *MachO) File {
    return macho_file.get_file(self.file).?;
}

pub fn get_data(self: Atom, macho_file: *MachO, buffer: []u8) !void {
    assert(buffer.len == self.size);
    switch (self.get_file(macho_file)) {
        .internal => |x| try x.get_atom_data(self, buffer),
        .object => |x| try x.get_atom_data(macho_file, self, buffer),
        .zig_object => |x| try x.get_atom_data(macho_file, self, buffer),
        else => unreachable,
    }
}

pub fn get_relocs(self: Atom, macho_file: *MachO) []const Relocation {
    return switch (self.get_file(macho_file)) {
        .dylib => unreachable,
        inline else => |x| x.get_atom_relocs(self, macho_file),
    };
}

pub fn get_input_section(self: Atom, macho_file: *MachO) macho.section_64 {
    return switch (self.get_file(macho_file)) {
        .dylib => unreachable,
        .zig_object => |x| x.get_input_section(self, macho_file),
        .object => |x| x.sections.items(.header)[self.n_sect],
        .internal => |x| x.sections.items(.header)[self.n_sect],
    };
}

pub fn get_input_address(self: Atom, macho_file: *MachO) u64 {
    return self.get_input_section(macho_file).addr + self.off;
}

pub fn get_address(self: Atom, macho_file: *MachO) u64 {
    const header = macho_file.sections.items(.header)[self.out_n_sect];
    return header.addr + self.value;
}

pub fn get_priority(self: Atom, macho_file: *MachO) u64 {
    const file = self.get_file(macho_file);
    return (@as(u64, @int_cast(file.get_index())) << 32) | @as(u64, @int_cast(self.n_sect));
}

pub fn get_unwind_records(self: Atom, macho_file: *MachO) []const UnwindInfo.Record.Index {
    if (!self.flags.unwind) return &[0]UnwindInfo.Record.Index{};
    const extra = self.get_extra(macho_file).?;
    return switch (self.get_file(macho_file)) {
        .dylib, .zig_object, .internal => unreachable,
        .object => |x| x.unwind_records.items[extra.unwind_index..][0..extra.unwind_count],
    };
}

pub fn mark_unwind_records_dead(self: Atom, macho_file: *MachO) void {
    for (self.get_unwind_records(macho_file)) |cu_index| {
        const cu = macho_file.get_unwind_record(cu_index);
        cu.alive = false;

        if (cu.get_fde_ptr(macho_file)) |fde| {
            fde.alive = false;
        }
    }
}

pub fn get_thunk(self: Atom, macho_file: *MachO) *Thunk {
    assert(self.flags.thunk);
    const extra = self.get_extra(macho_file).?;
    return macho_file.get_thunk(extra.thunk);
}

pub fn get_literal_pool_index(self: Atom, macho_file: *MachO) ?MachO.LiteralPool.Index {
    if (!self.flags.literal_pool) return null;
    return self.get_extra(macho_file).?.literal_index;
}

const AddExtraOpts = struct {
    thunk: ?u32 = null,
    rel_index: ?u32 = null,
    rel_count: ?u32 = null,
    unwind_index: ?u32 = null,
    unwind_count: ?u32 = null,
    literal_index: ?u32 = null,
};

pub fn add_extra(atom: *Atom, opts: AddExtraOpts, macho_file: *MachO) !void {
    if (atom.get_extra(macho_file) == null) {
        atom.extra = try macho_file.add_atom_extra(.{});
    }
    var extra = atom.get_extra(macho_file).?;
    inline for (@typeInfo(@TypeOf(opts)).Struct.fields) |field| {
        if (@field(opts, field.name)) |x| {
            @field(extra, field.name) = x;
        }
    }
    atom.set_extra(extra, macho_file);
}

pub inline fn get_extra(atom: Atom, macho_file: *MachO) ?Extra {
    return macho_file.get_atom_extra(atom.extra);
}

pub inline fn set_extra(atom: Atom, extra: Extra, macho_file: *MachO) void {
    macho_file.set_atom_extra(atom.extra, extra);
}

pub fn init_output_section(sect: macho.section_64, macho_file: *MachO) !u8 {
    if (macho_file.base.is_relocatable()) {
        const osec = macho_file.get_section_by_name(sect.seg_name(), sect.sect_name()) orelse
            try macho_file.add_section(
            sect.seg_name(),
            sect.sect_name(),
            .{ .flags = sect.flags },
        );
        return osec;
    }

    const segname, const sectname, const flags = blk: {
        if (sect.is_code()) break :blk .{
            "__TEXT",
            "__text",
            macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        };

        switch (sect.type()) {
            macho.S_4BYTE_LITERALS,
            macho.S_8BYTE_LITERALS,
            macho.S_16BYTE_LITERALS,
            => break :blk .{ "__TEXT", "__const", macho.S_REGULAR },

            macho.S_CSTRING_LITERALS => {
                if (mem.starts_with(u8, sect.sect_name(), "__objc")) break :blk .{
                    sect.seg_name(), sect.sect_name(), macho.S_REGULAR,
                };
                break :blk .{ "__TEXT", "__cstring", macho.S_CSTRING_LITERALS };
            },

            macho.S_MOD_INIT_FUNC_POINTERS,
            macho.S_MOD_TERM_FUNC_POINTERS,
            => break :blk .{ "__DATA_CONST", sect.sect_name(), sect.flags },

            macho.S_LITERAL_POINTERS,
            macho.S_ZEROFILL,
            macho.S_GB_ZEROFILL,
            macho.S_THREAD_LOCAL_VARIABLES,
            macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
            macho.S_THREAD_LOCAL_REGULAR,
            macho.S_THREAD_LOCAL_ZEROFILL,
            => break :blk .{ sect.seg_name(), sect.sect_name(), sect.flags },

            macho.S_COALESCED => break :blk .{
                sect.seg_name(),
                sect.sect_name(),
                macho.S_REGULAR,
            },

            macho.S_REGULAR => {
                const segname = sect.seg_name();
                const sectname = sect.sect_name();
                if (mem.eql(u8, segname, "__DATA")) {
                    if (mem.eql(u8, sectname, "__cfstring") or
                        mem.eql(u8, sectname, "__objc_classlist") or
                        mem.eql(u8, sectname, "__objc_imageinfo")) break :blk .{
                        "__DATA_CONST",
                        sectname,
                        macho.S_REGULAR,
                    };
                }
                break :blk .{ segname, sectname, sect.flags };
            },

            else => break :blk .{ sect.seg_name(), sect.sect_name(), sect.flags },
        }
    };
    return macho_file.get_section_by_name(segname, sectname) orelse try macho_file.add_section(
        segname,
        sectname,
        .{ .flags = flags },
    );
}

/// Returns how much room there is to grow in virtual address space.
/// File offset relocation happens transparently, so it is not included in
/// this calculation.
pub fn capacity(self: Atom, macho_file: *MachO) u64 {
    const next_addr = if (macho_file.get_atom(self.next_index)) |next|
        next.get_address(macho_file)
    else
        std.math.max_int(u32);
    return next_addr - self.get_address(macho_file);
}

pub fn free_list_eligible(self: Atom, macho_file: *MachO) bool {
    // No need to keep a free list node for the last block.
    const next = macho_file.get_atom(self.next_index) orelse return false;
    const cap = next.get_address(macho_file) - self.get_address(macho_file);
    const ideal_cap = MachO.pad_to_ideal(self.size);
    if (cap <= ideal_cap) return false;
    const surplus = cap - ideal_cap;
    return surplus >= MachO.min_text_capacity;
}

pub fn allocate(self: *Atom, macho_file: *MachO) !void {
    const sect = &macho_file.sections.items(.header)[self.out_n_sect];
    const free_list = &macho_file.sections.items(.free_list)[self.out_n_sect];
    const last_atom_index = &macho_file.sections.items(.last_atom_index)[self.out_n_sect];
    const new_atom_ideal_capacity = MachO.pad_to_ideal(self.size);

    // We use these to indicate our intention to update metadata, placing the new atom,
    // and possibly removing a free list node.
    // It would be simpler to do it inside the for loop below, but that would cause a
    // problem if an error was returned later in the function. So this action
    // is actually carried out at the end of the function, when errors are no longer possible.
    var atom_placement: ?Atom.Index = null;
    var free_list_removal: ?usize = null;

    // First we look for an appropriately sized free list node.
    // The list is unordered. We'll just take the first thing that works.
    self.value = blk: {
        var i: usize = free_list.items.len;
        while (i < free_list.items.len) {
            const big_atom_index = free_list.items[i];
            const big_atom = macho_file.get_atom(big_atom_index).?;
            // We now have a pointer to a live atom that has too much capacity.
            // Is it enough that we could fit this new atom?
            const cap = big_atom.capacity(macho_file);
            const ideal_capacity = MachO.pad_to_ideal(cap);
            const ideal_capacity_end_vaddr = std.math.add(u64, big_atom.value, ideal_capacity) catch ideal_capacity;
            const capacity_end_vaddr = big_atom.value + cap;
            const new_start_vaddr_unaligned = capacity_end_vaddr - new_atom_ideal_capacity;
            const new_start_vaddr = self.alignment.backward(new_start_vaddr_unaligned);
            if (new_start_vaddr < ideal_capacity_end_vaddr) {
                // Additional bookkeeping here to notice if this free list node
                // should be deleted because the block that it points to has grown to take up
                // more of the extra capacity.
                if (!big_atom.free_list_eligible(macho_file)) {
                    _ = free_list.swap_remove(i);
                } else {
                    i += 1;
                }
                continue;
            }
            // At this point we know that we will place the new block here. But the
            // remaining question is whether there is still yet enough capacity left
            // over for there to still be a free list node.
            const remaining_capacity = new_start_vaddr - ideal_capacity_end_vaddr;
            const keep_free_list_node = remaining_capacity >= MachO.min_text_capacity;

            // Set up the metadata to be updated, after errors are no longer possible.
            atom_placement = big_atom_index;
            if (!keep_free_list_node) {
                free_list_removal = i;
            }
            break :blk new_start_vaddr;
        } else if (macho_file.get_atom(last_atom_index.*)) |last| {
            const ideal_capacity = MachO.pad_to_ideal(last.size);
            const ideal_capacity_end_vaddr = last.value + ideal_capacity;
            const new_start_vaddr = self.alignment.forward(ideal_capacity_end_vaddr);
            // Set up the metadata to be updated, after errors are no longer possible.
            atom_placement = last.atom_index;
            break :blk new_start_vaddr;
        } else {
            break :blk 0;
        }
    };

    log.debug("allocated atom({d}) : '{s}' at 0x{x} to 0x{x}", .{
        self.atom_index,
        self.get_name(macho_file),
        self.get_address(macho_file),
        self.get_address(macho_file) + self.size,
    });

    const expand_section = if (atom_placement) |placement_index|
        macho_file.get_atom(placement_index).?.next_index == 0
    else
        true;
    if (expand_section) {
        const needed_size = self.value + self.size;
        try macho_file.grow_section(self.out_n_sect, needed_size);
        last_atom_index.* = self.atom_index;

        // const zig_object = macho_file_file.get_zig_object().?;
        // if (zig_object.dwarf) |_| {
        //     // The .debug_info section has `low_pc` and `high_pc` values which is the virtual address
        //     // range of the compilation unit. When we expand the text section, this range changes,
        //     // so the DW_TAG.compile_unit tag of the .debug_info section becomes dirty.
        //     zig_object.debug_info_header_dirty = true;
        //     // This becomes dirty for the same reason. We could potentially make this more
        //     // fine-grained with the addition of support for more compilation units. It is planned to
        //     // model each package as a different compilation unit.
        //     zig_object.debug_aranges_section_dirty = true;
        // }
    }
    sect.@"align" = @max(sect.@"align", self.alignment.to_log2_units());

    // This function can also reallocate an atom.
    // In this case we need to "unplug" it from its previous location before
    // plugging it in to its new location.
    if (macho_file.get_atom(self.prev_index)) |prev| {
        prev.next_index = self.next_index;
    }
    if (macho_file.get_atom(self.next_index)) |next| {
        next.prev_index = self.prev_index;
    }

    if (atom_placement) |big_atom_index| {
        const big_atom = macho_file.get_atom(big_atom_index).?;
        self.prev_index = big_atom_index;
        self.next_index = big_atom.next_index;
        big_atom.next_index = self.atom_index;
    } else {
        self.prev_index = 0;
        self.next_index = 0;
    }
    if (free_list_removal) |i| {
        _ = free_list.swap_remove(i);
    }

    self.flags.alive = true;
}

pub fn shrink(self: *Atom, macho_file: *MachO) void {
    _ = self;
    _ = macho_file;
}

pub fn grow(self: *Atom, macho_file: *MachO) !void {
    if (!self.alignment.check(self.value) or self.size > self.capacity(macho_file))
        try self.allocate(macho_file);
}

pub fn free(self: *Atom, macho_file: *MachO) void {
    log.debug("free_atom {d} ({s})", .{ self.atom_index, self.get_name(macho_file) });

    const comp = macho_file.base.comp;
    const gpa = comp.gpa;
    const free_list = &macho_file.sections.items(.free_list)[self.out_n_sect];
    const last_atom_index = &macho_file.sections.items(.last_atom_index)[self.out_n_sect];
    var already_have_free_list_node = false;
    {
        var i: usize = 0;
        // TODO turn free_list into a hash map
        while (i < free_list.items.len) {
            if (free_list.items[i] == self.atom_index) {
                _ = free_list.swap_remove(i);
                continue;
            }
            if (free_list.items[i] == self.prev_index) {
                already_have_free_list_node = true;
            }
            i += 1;
        }
    }

    if (macho_file.get_atom(last_atom_index.*)) |last_atom| {
        if (last_atom.atom_index == self.atom_index) {
            if (macho_file.get_atom(self.prev_index)) |_| {
                // TODO shrink the section size here
                last_atom_index.* = self.prev_index;
            } else {
                last_atom_index.* = 0;
            }
        }
    }

    if (macho_file.get_atom(self.prev_index)) |prev| {
        prev.next_index = self.next_index;
        if (!already_have_free_list_node and prev.*.free_list_eligible(macho_file)) {
            // The free list is heuristics, it doesn't have to be perfect, so we can
            // ignore the OOM here.
            free_list.append(gpa, prev.atom_index) catch {};
        }
    } else {
        self.prev_index = 0;
    }

    if (macho_file.get_atom(self.next_index)) |next| {
        next.prev_index = self.prev_index;
    } else {
        self.next_index = 0;
    }

    // TODO create relocs free list
    self.free_relocs(macho_file);
    // TODO figure out how to free input section mappind in ZigModule
    // const zig_object = macho_file.zig_object_ptr().?
    // assert(zig_object.atoms.swap_remove(self.atom_index));
    self.* = .{};
}

pub fn add_reloc(self: *Atom, macho_file: *MachO, reloc: Relocation) !void {
    const gpa = macho_file.base.comp.gpa;
    const file = self.get_file(macho_file);
    assert(file == .zig_object);
    assert(self.flags.relocs);
    var extra = self.get_extra(macho_file).?;
    const rels = &file.zig_object.relocs.items[extra.rel_index];
    try rels.append(gpa, reloc);
    extra.rel_count += 1;
    self.set_extra(extra, macho_file);
}

pub fn free_relocs(self: *Atom, macho_file: *MachO) void {
    if (!self.flags.relocs) return;
    self.get_file(macho_file).zig_object.free_atom_relocs(self.*, macho_file);
    var extra = self.get_extra(macho_file).?;
    extra.rel_count = 0;
    self.set_extra(extra, macho_file);
}

pub fn scan_relocs(self: Atom, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    assert(self.flags.alive);

    const dynrel_ctx = switch (self.get_file(macho_file)) {
        .zig_object => |x| &x.dynamic_relocs,
        .object => |x| &x.dynamic_relocs,
        else => unreachable,
    };
    const relocs = self.get_relocs(macho_file);

    for (relocs) |rel| {
        if (try self.report_undef_symbol(rel, macho_file)) continue;

        switch (rel.type) {
            .branch => {
                const symbol = rel.get_target_symbol(macho_file);
                if (symbol.flags.import or (symbol.flags.@"export" and symbol.flags.weak) or symbol.flags.interposable) {
                    symbol.flags.stubs = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                } else if (mem.starts_with(u8, symbol.get_name(macho_file), "_objc_msgSend$")) {
                    symbol.flags.objc_stubs = true;
                }
            },

            .got_load,
            .got_load_page,
            .got_load_pageoff,
            => {
                const symbol = rel.get_target_symbol(macho_file);
                if (symbol.flags.import or
                    (symbol.flags.@"export" and symbol.flags.weak) or
                    symbol.flags.interposable or
                    macho_file.get_target().cpu.arch == .aarch64) // TODO relax on arm64
                {
                    symbol.flags.needs_got = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                }
            },

            .zig_got_load => {
                assert(rel.get_target_symbol(macho_file).flags.has_zig_got);
            },

            .got => {
                rel.get_target_symbol(macho_file).flags.needs_got = true;
            },

            .tlv,
            .tlvp_page,
            .tlvp_pageoff,
            => {
                const symbol = rel.get_target_symbol(macho_file);
                if (!symbol.flags.tlv) {
                    try macho_file.report_parse_error2(
                        self.get_file(macho_file).get_index(),
                        "{s}: illegal thread-local variable reference to regular symbol {s}",
                        .{ self.get_name(macho_file), symbol.get_name(macho_file) },
                    );
                }
                if (symbol.flags.import or (symbol.flags.@"export" and symbol.flags.weak) or symbol.flags.interposable) {
                    symbol.flags.tlv_ptr = true;
                    if (symbol.flags.weak) {
                        macho_file.binds_to_weak = true;
                    }
                }
            },

            .unsigned => {
                if (rel.meta.length == 3) { // TODO this really should check if this is pointer width
                    if (rel.tag == .@"extern") {
                        const symbol = rel.get_target_symbol(macho_file);
                        if (symbol.is_tlv_init(macho_file)) {
                            macho_file.has_tlv = true;
                            continue;
                        }
                        if (symbol.flags.import) {
                            dynrel_ctx.bind_relocs += 1;
                            if (symbol.flags.weak) {
                                dynrel_ctx.weak_bind_relocs += 1;
                                macho_file.binds_to_weak = true;
                            }
                            continue;
                        }
                        if (symbol.flags.@"export" and symbol.flags.weak) {
                            dynrel_ctx.weak_bind_relocs += 1;
                            macho_file.binds_to_weak = true;
                        } else if (symbol.flags.interposable) {
                            dynrel_ctx.bind_relocs += 1;
                        }
                    }
                    dynrel_ctx.rebase_relocs += 1;
                }
            },

            .signed,
            .signed1,
            .signed2,
            .signed4,
            .page,
            .pageoff,
            .subtractor,
            => {},
        }
    }
}

fn report_undef_symbol(self: Atom, rel: Relocation, macho_file: *MachO) !bool {
    if (rel.tag == .local) return false;

    const sym = rel.get_target_symbol(macho_file);
    if (sym.get_file(macho_file) == null) {
        const gpa = macho_file.base.comp.gpa;
        const gop = try macho_file.undefs.get_or_put(gpa, rel.target);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(gpa, self.atom_index);
        return true;
    }

    return false;
}

pub fn resolve_relocs(self: Atom, macho_file: *MachO, buffer: []u8) !void {
    const tracy = trace(@src());
    defer tracy.end();

    assert(!self.get_input_section(macho_file).is_zerofill());
    const file = self.get_file(macho_file);
    const name = self.get_name(macho_file);
    const relocs = self.get_relocs(macho_file);

    relocs_log.debug("{x}: {s}", .{ self.get_address(macho_file), name });

    var has_error = false;
    var stream = std.io.fixed_buffer_stream(buffer);
    var i: usize = 0;
    while (i < relocs.len) : (i += 1) {
        const rel = relocs[i];
        const rel_offset = rel.offset - self.off;
        const subtractor = if (rel.meta.has_subtractor) relocs[i - 1] else null;

        if (rel.tag == .@"extern") {
            if (rel.get_target_symbol(macho_file).get_file(macho_file) == null) continue;
        }

        try stream.seek_to(rel_offset);
        self.resolve_reloc_inner(rel, subtractor, buffer, macho_file, stream.writer()) catch |err| {
            switch (err) {
                error.RelaxFail => {
                    const target = switch (rel.tag) {
                        .@"extern" => rel.get_target_symbol(macho_file).get_name(macho_file),
                        .local => rel.get_target_atom(macho_file).get_name(macho_file),
                    };
                    try macho_file.report_parse_error2(
                        file.get_index(),
                        "{s}: 0x{x}: 0x{x}: failed to relax relocation: type {s}, target {s}",
                        .{ name, self.get_address(macho_file), rel.offset, @tag_name(rel.type), target },
                    );
                    has_error = true;
                },
                error.RelaxFailUnexpectedInstruction => has_error = true,
                else => |e| return e,
            }
        };
    }

    if (has_error) return error.ResolveFailed;
}

const ResolveError = error{
    RelaxFail,
    RelaxFailUnexpectedInstruction,
    NoSpaceLeft,
    DivisionByZero,
    UnexpectedRemainder,
    Overflow,
    OutOfMemory,
};

fn resolve_reloc_inner(
    self: Atom,
    rel: Relocation,
    subtractor: ?Relocation,
    code: []u8,
    macho_file: *MachO,
    writer: anytype,
) ResolveError!void {
    const cpu_arch = macho_file.get_target().cpu.arch;
    const rel_offset = math.cast(usize, rel.offset - self.off) orelse return error.Overflow;
    const seg_id = macho_file.sections.items(.segment_id)[self.out_n_sect];
    const seg = macho_file.segments.items[seg_id];
    const P = @as(i64, @int_cast(self.get_address(macho_file))) + @as(i64, @int_cast(rel_offset));
    const A = rel.addend + rel.get_reloc_addend(cpu_arch);
    const S: i64 = @int_cast(rel.get_target_address(macho_file));
    const G: i64 = @int_cast(rel.get_got_target_address(macho_file));
    const TLS = @as(i64, @int_cast(macho_file.get_tls_address()));
    const SUB = if (subtractor) |sub| @as(i64, @int_cast(sub.get_target_address(macho_file))) else 0;
    // Address of the __got_zig table entry if any.
    const ZIG_GOT = @as(i64, @int_cast(rel.get_zig_got_target_address(macho_file)));

    const div_exact = struct {
        fn div_exact(atom: Atom, r: Relocation, num: u12, den: u12, ctx: *MachO) !u12 {
            return math.div_exact(u12, num, den) catch {
                try ctx.report_parse_error2(atom.get_file(ctx).get_index(), "{s}: unexpected remainder when resolving {s} at offset 0x{x}", .{
                    atom.get_name(ctx),
                    r.fmt_pretty(ctx.get_target().cpu.arch),
                    r.offset,
                });
                return error.UnexpectedRemainder;
            };
        }
    }.div_exact;

    switch (rel.tag) {
        .local => relocs_log.debug("  {x}<+{d}>: {s}: [=> {x}] atom({d})", .{
            P,
            rel_offset,
            @tag_name(rel.type),
            S + A - SUB,
            rel.get_target_atom(macho_file).atom_index,
        }),
        .@"extern" => relocs_log.debug("  {x}<+{d}>: {s}: [=> {x}] G({x}) ZG({x}) ({s})", .{
            P,
            rel_offset,
            @tag_name(rel.type),
            S + A - SUB,
            G + A,
            ZIG_GOT + A,
            rel.get_target_symbol(macho_file).get_name(macho_file),
        }),
    }

    switch (rel.type) {
        .subtractor => {},

        .unsigned => {
            assert(!rel.meta.pcrel);
            if (rel.meta.length == 3) {
                if (rel.tag == .@"extern") {
                    const sym = rel.get_target_symbol(macho_file);
                    if (sym.is_tlv_init(macho_file)) {
                        try writer.write_int(u64, @int_cast(S - TLS), .little);
                        return;
                    }
                    const entry = bind.Entry{
                        .target = rel.target,
                        .offset = @as(u64, @int_cast(P)) - seg.vmaddr,
                        .segment_id = seg_id,
                        .addend = A,
                    };
                    if (sym.flags.import) {
                        macho_file.bind.entries.append_assume_capacity(entry);
                        if (sym.flags.weak) {
                            macho_file.weak_bind.entries.append_assume_capacity(entry);
                        }
                        return;
                    }
                    if (sym.flags.@"export" and sym.flags.weak) {
                        macho_file.weak_bind.entries.append_assume_capacity(entry);
                    } else if (sym.flags.interposable) {
                        macho_file.bind.entries.append_assume_capacity(entry);
                    }
                }
                macho_file.rebase.entries.append_assume_capacity(.{
                    .offset = @as(u64, @int_cast(P)) - seg.vmaddr,
                    .segment_id = seg_id,
                });
                try writer.write_int(u64, @bit_cast(S + A - SUB), .little);
            } else if (rel.meta.length == 2) {
                try writer.write_int(u32, @bit_cast(@as(i32, @truncate(S + A - SUB))), .little);
            } else unreachable;
        },

        .got => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            try writer.write_int(i32, @int_cast(G + A - P), .little);
        },

        .branch => {
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            assert(rel.tag == .@"extern");

            switch (cpu_arch) {
                .x86_64 => try writer.write_int(i32, @int_cast(S + A - P), .little),
                .aarch64 => {
                    const disp: i28 = math.cast(i28, S + A - P) orelse blk: {
                        const thunk = self.get_thunk(macho_file);
                        const S_: i64 = @int_cast(thunk.get_target_address(rel.target, macho_file));
                        break :blk math.cast(i28, S_ + A - P) orelse return error.Overflow;
                    };
                    aarch64.write_branch_imm(disp, code[rel_offset..][0..4]);
                },
                else => unreachable,
            }
        },

        .got_load => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            if (rel.get_target_symbol(macho_file).flags.has_got) {
                try writer.write_int(i32, @int_cast(G + A - P), .little);
            } else {
                try x86_64.relax_got_load(self, code[rel_offset - 3 ..], rel, macho_file);
                try writer.write_int(i32, @int_cast(S + A - P), .little);
            }
        },

        .zig_got_load => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            switch (cpu_arch) {
                .x86_64 => try writer.write_int(i32, @int_cast(ZIG_GOT + A - P), .little),
                .aarch64 => @panic("TODO resolve __got_zig indirection reloc"),
                else => unreachable,
            }
        },

        .tlv => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            const sym = rel.get_target_symbol(macho_file);
            if (sym.flags.tlv_ptr) {
                const S_: i64 = @int_cast(sym.get_tlv_ptr_address(macho_file));
                try writer.write_int(i32, @int_cast(S_ + A - P), .little);
            } else {
                try x86_64.relax_tlv(code[rel_offset - 3 ..]);
                try writer.write_int(i32, @int_cast(S + A - P), .little);
            }
        },

        .signed, .signed1, .signed2, .signed4 => {
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            try writer.write_int(i32, @int_cast(S + A - P), .little);
        },

        .page,
        .got_load_page,
        .tlvp_page,
        => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(rel.meta.pcrel);
            const sym = rel.get_target_symbol(macho_file);
            const source = math.cast(u64, P) orelse return error.Overflow;
            const target = target: {
                const target = switch (rel.type) {
                    .page => S + A,
                    .got_load_page => G + A,
                    .tlvp_page => if (sym.flags.tlv_ptr) blk: {
                        const S_: i64 = @int_cast(sym.get_tlv_ptr_address(macho_file));
                        break :blk S_ + A;
                    } else S + A,
                    else => unreachable,
                };
                break :target math.cast(u64, target) orelse return error.Overflow;
            };
            const pages = @as(u21, @bit_cast(try aarch64.calc_number_of_pages(@int_cast(source), @int_cast(target))));
            aarch64.write_adrp_inst(pages, code[rel_offset..][0..4]);
        },

        .pageoff => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(!rel.meta.pcrel);
            const target = math.cast(u64, S + A) orelse return error.Overflow;
            const inst_code = code[rel_offset..][0..4];
            if (aarch64.is_arithmetic_op(inst_code)) {
                aarch64.write_add_imm_inst(@truncate(target), inst_code);
            } else {
                var inst = aarch64.Instruction{
                    .load_store_register = mem.bytes_to_value(std.meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.load_store_register,
                    ), inst_code),
                };
                inst.load_store_register.offset = switch (inst.load_store_register.size) {
                    0 => if (inst.load_store_register.v == 1)
                        try div_exact(self, rel, @truncate(target), 16, macho_file)
                    else
                        @truncate(target),
                    1 => try div_exact(self, rel, @truncate(target), 2, macho_file),
                    2 => try div_exact(self, rel, @truncate(target), 4, macho_file),
                    3 => try div_exact(self, rel, @truncate(target), 8, macho_file),
                };
                try writer.write_int(u32, inst.to_u32(), .little);
            }
        },

        .got_load_pageoff => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(!rel.meta.pcrel);
            const target = math.cast(u64, G + A) orelse return error.Overflow;
            aarch64.write_load_store_reg_inst(try div_exact(self, rel, @truncate(target), 8, macho_file), code[rel_offset..][0..4]);
        },

        .tlvp_pageoff => {
            assert(rel.tag == .@"extern");
            assert(rel.meta.length == 2);
            assert(!rel.meta.pcrel);

            const sym = rel.get_target_symbol(macho_file);
            const target = target: {
                const target = if (sym.flags.tlv_ptr) blk: {
                    const S_: i64 = @int_cast(sym.get_tlv_ptr_address(macho_file));
                    break :blk S_ + A;
                } else S + A;
                break :target math.cast(u64, target) orelse return error.Overflow;
            };

            const RegInfo = struct {
                rd: u5,
                rn: u5,
                size: u2,
            };

            const inst_code = code[rel_offset..][0..4];
            const reg_info: RegInfo = blk: {
                if (aarch64.is_arithmetic_op(inst_code)) {
                    const inst = mem.bytes_to_value(std.meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.add_subtract_immediate,
                    ), inst_code);
                    break :blk .{
                        .rd = inst.rd,
                        .rn = inst.rn,
                        .size = inst.sf,
                    };
                } else {
                    const inst = mem.bytes_to_value(std.meta.TagPayload(
                        aarch64.Instruction,
                        aarch64.Instruction.load_store_register,
                    ), inst_code);
                    break :blk .{
                        .rd = inst.rt,
                        .rn = inst.rn,
                        .size = inst.size,
                    };
                }
            };

            var inst = if (sym.flags.tlv_ptr) aarch64.Instruction{
                .load_store_register = .{
                    .rt = reg_info.rd,
                    .rn = reg_info.rn,
                    .offset = try div_exact(self, rel, @truncate(target), 8, macho_file),
                    .opc = 0b01,
                    .op1 = 0b01,
                    .v = 0,
                    .size = reg_info.size,
                },
            } else aarch64.Instruction{
                .add_subtract_immediate = .{
                    .rd = reg_info.rd,
                    .rn = reg_info.rn,
                    .imm12 = @truncate(target),
                    .sh = 0,
                    .s = 0,
                    .op = 0,
                    .sf = @as(u1, @truncate(reg_info.size)),
                },
            };
            try writer.write_int(u32, inst.to_u32(), .little);
        },
    }
}

const x86_64 = struct {
    fn relax_got_load(self: Atom, code: []u8, rel: Relocation, macho_file: *MachO) ResolveError!void {
        const old_inst = disassemble(code) orelse return error.RelaxFail;
        switch (old_inst.encoding.mnemonic) {
            .mov => {
                const inst = Instruction.new(old_inst.prefix, .lea, &old_inst.ops) catch return error.RelaxFail;
                relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
                encode(&.{inst}, code) catch return error.RelaxFail;
            },
            else => |x| {
                var err = try macho_file.add_error_with_notes(2);
                try err.add_msg(macho_file, "{s}: 0x{x}: 0x{x}: failed to relax relocation of type {s}", .{
                    self.get_name(macho_file),
                    self.get_address(macho_file),
                    rel.offset,
                    @tag_name(rel.type),
                });
                try err.add_note(macho_file, "expected .mov instruction but found .{s}", .{@tag_name(x)});
                try err.add_note(macho_file, "while parsing {}", .{self.get_file(macho_file).fmt_path()});
                return error.RelaxFailUnexpectedInstruction;
            },
        }
    }

    fn relax_tlv(code: []u8) error{RelaxFail}!void {
        const old_inst = disassemble(code) orelse return error.RelaxFail;
        switch (old_inst.encoding.mnemonic) {
            .mov => {
                const inst = Instruction.new(old_inst.prefix, .lea, &old_inst.ops) catch return error.RelaxFail;
                relocs_log.debug("    relaxing {} => {}", .{ old_inst.encoding, inst.encoding });
                encode(&.{inst}, code) catch return error.RelaxFail;
            },
            else => return error.RelaxFail,
        }
    }

    fn disassemble(code: []const u8) ?Instruction {
        var disas = Disassembler.init(code);
        const inst = disas.next() catch return null;
        return inst;
    }

    fn encode(insts: []const Instruction, code: []u8) !void {
        var stream = std.io.fixed_buffer_stream(code);
        const writer = stream.writer();
        for (insts) |inst| {
            try inst.encode(writer, .{});
        }
    }

    const bits = @import("../../arch/x86_64/bits.zig");
    const encoder = @import("../../arch/x86_64/encoder.zig");
    const Disassembler = @import("../../arch/x86_64/Disassembler.zig");
    const Immediate = bits.Immediate;
    const Instruction = encoder.Instruction;
};

pub fn calc_num_relocs(self: Atom, macho_file: *MachO) u32 {
    const relocs = self.get_relocs(macho_file);
    switch (macho_file.get_target().cpu.arch) {
        .aarch64 => {
            var nreloc: u32 = 0;
            for (relocs) |rel| {
                nreloc += 1;
                switch (rel.type) {
                    .page, .pageoff => if (rel.addend > 0) {
                        nreloc += 1;
                    },
                    else => {},
                }
            }
            return nreloc;
        },
        .x86_64 => return @int_cast(relocs.len),
        else => unreachable,
    }
}

pub fn write_relocs(self: Atom, macho_file: *MachO, code: []u8, buffer: *std.ArrayList(macho.relocation_info)) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = macho_file.get_target().cpu.arch;
    const relocs = self.get_relocs(macho_file);
    var stream = std.io.fixed_buffer_stream(code);

    for (relocs) |rel| {
        const rel_offset = rel.offset - self.off;
        const r_address: i32 = math.cast(i32, self.value + rel_offset) orelse return error.Overflow;
        const r_symbolnum = r_symbolnum: {
            const r_symbolnum: u32 = switch (rel.tag) {
                .local => rel.get_target_atom(macho_file).out_n_sect + 1,
                .@"extern" => rel.get_target_symbol(macho_file).get_output_symtab_index(macho_file).?,
            };
            break :r_symbolnum math.cast(u24, r_symbolnum) orelse return error.Overflow;
        };
        const r_extern = rel.tag == .@"extern";
        var addend = rel.addend + rel.get_reloc_addend(cpu_arch);
        if (rel.tag == .local) {
            const target: i64 = @int_cast(rel.get_target_address(macho_file));
            addend += target;
        }

        try stream.seek_to(rel_offset);

        switch (cpu_arch) {
            .aarch64 => {
                if (rel.type == .unsigned) switch (rel.meta.length) {
                    0, 1 => unreachable,
                    2 => try stream.writer().write_int(i32, @truncate(addend), .little),
                    3 => try stream.writer().write_int(i64, addend, .little),
                } else if (addend > 0) {
                    buffer.append_assume_capacity(.{
                        .r_address = r_address,
                        .r_symbolnum = @bit_cast(math.cast(i24, addend) orelse return error.Overflow),
                        .r_pcrel = 0,
                        .r_length = 2,
                        .r_extern = 0,
                        .r_type = @int_from_enum(macho.reloc_type_arm64.ARM64_RELOC_ADDEND),
                    });
                }

                const r_type: macho.reloc_type_arm64 = switch (rel.type) {
                    .page => .ARM64_RELOC_PAGE21,
                    .pageoff => .ARM64_RELOC_PAGEOFF12,
                    .got_load_page => .ARM64_RELOC_GOT_LOAD_PAGE21,
                    .got_load_pageoff => .ARM64_RELOC_GOT_LOAD_PAGEOFF12,
                    .tlvp_page => .ARM64_RELOC_TLVP_LOAD_PAGE21,
                    .tlvp_pageoff => .ARM64_RELOC_TLVP_LOAD_PAGEOFF12,
                    .branch => .ARM64_RELOC_BRANCH26,
                    .got => .ARM64_RELOC_POINTER_TO_GOT,
                    .subtractor => .ARM64_RELOC_SUBTRACTOR,
                    .unsigned => .ARM64_RELOC_UNSIGNED,

                    .zig_got_load,
                    .signed,
                    .signed1,
                    .signed2,
                    .signed4,
                    .got_load,
                    .tlv,
                    => unreachable,
                };
                buffer.append_assume_capacity(.{
                    .r_address = r_address,
                    .r_symbolnum = r_symbolnum,
                    .r_pcrel = @int_from_bool(rel.meta.pcrel),
                    .r_extern = @int_from_bool(r_extern),
                    .r_length = rel.meta.length,
                    .r_type = @int_from_enum(r_type),
                });
            },
            .x86_64 => {
                if (rel.meta.pcrel) {
                    if (rel.tag == .local) {
                        addend -= @as(i64, @int_cast(self.get_address(macho_file) + rel_offset));
                    } else {
                        addend += 4;
                    }
                }
                switch (rel.meta.length) {
                    0, 1 => unreachable,
                    2 => try stream.writer().write_int(i32, @truncate(addend), .little),
                    3 => try stream.writer().write_int(i64, addend, .little),
                }

                const r_type: macho.reloc_type_x86_64 = switch (rel.type) {
                    .signed => .X86_64_RELOC_SIGNED,
                    .signed1 => .X86_64_RELOC_SIGNED_1,
                    .signed2 => .X86_64_RELOC_SIGNED_2,
                    .signed4 => .X86_64_RELOC_SIGNED_4,
                    .got_load => .X86_64_RELOC_GOT_LOAD,
                    .tlv => .X86_64_RELOC_TLV,
                    .branch => .X86_64_RELOC_BRANCH,
                    .got => .X86_64_RELOC_GOT,
                    .subtractor => .X86_64_RELOC_SUBTRACTOR,
                    .unsigned => .X86_64_RELOC_UNSIGNED,

                    .zig_got_load,
                    .page,
                    .pageoff,
                    .got_load_page,
                    .got_load_pageoff,
                    .tlvp_page,
                    .tlvp_pageoff,
                    => unreachable,
                };
                buffer.append_assume_capacity(.{
                    .r_address = r_address,
                    .r_symbolnum = r_symbolnum,
                    .r_pcrel = @int_from_bool(rel.meta.pcrel),
                    .r_extern = @int_from_bool(r_extern),
                    .r_length = rel.meta.length,
                    .r_type = @int_from_enum(r_type),
                });
            },
            else => unreachable,
        }
    }
}

pub fn format(
    atom: Atom,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = atom;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compile_error("do not format Atom directly");
}

pub fn fmt(atom: Atom, macho_file: *MachO) std.fmt.Formatter(format2) {
    return .{ .data = .{
        .atom = atom,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    atom: Atom,
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
    const atom = ctx.atom;
    const macho_file = ctx.macho_file;
    try writer.print("atom({d}) : {s} : @{x} : sect({d}) : align({x}) : size({x}) : nreloc({d})", .{
        atom.atom_index,                atom.get_name(macho_file), atom.get_address(macho_file),
        atom.out_n_sect,                atom.alignment,           atom.size,
        atom.get_relocs(macho_file).len,
    });
    if (atom.flags.thunk) try writer.print(" : thunk({d})", .{atom.get_extra(macho_file).?.thunk});
    if (!atom.flags.alive) try writer.write_all(" : [*]");
    if (atom.flags.unwind) {
        try writer.write_all(" : unwind{ ");
        const extra = atom.get_extra(macho_file).?;
        for (atom.get_unwind_records(macho_file), extra.unwind_index..) |index, i| {
            const rec = macho_file.get_unwind_record(index);
            try writer.print("{d}", .{index});
            if (!rec.alive) try writer.write_all("([*])");
            if (i < extra.unwind_index + extra.unwind_count - 1) try writer.write_all(", ");
        }
        try writer.write_all(" }");
    }
}

pub const Index = u32;

pub const Flags = packed struct {
    /// Specifies whether this atom is alive or has been garbage collected.
    alive: bool = true,

    /// Specifies if this atom has been visited during garbage collection.
    visited: bool = false,

    /// Whether this atom has a range extension thunk.
    thunk: bool = false,

    /// Whether this atom has any relocations.
    relocs: bool = false,

    /// Whether this atom has any unwind records.
    unwind: bool = false,

    /// Whether this atom has LiteralPool entry.
    literal_pool: bool = false,
};

pub const Extra = struct {
    /// Index of the range extension thunk of this atom.
    thunk: u32 = 0,

    /// Start index of relocations belonging to this atom.
    rel_index: u32 = 0,

    /// Count of relocations belonging to this atom.
    rel_count: u32 = 0,

    /// Start index of relocations belonging to this atom.
    unwind_index: u32 = 0,

    /// Count of relocations belonging to this atom.
    unwind_count: u32 = 0,

    /// Index into LiteralPool entry for this atom.
    literal_index: u32 = 0,
};

pub const Alignment = @import("../../InternPool.zig").Alignment;

const aarch64 = @import("../aarch64.zig");
const assert = std.debug.assert;
const bind = @import("dyld_info/bind.zig");
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const log = std.log.scoped(.link);
const relocs_log = std.log.scoped(.link_relocs);
const std = @import("std");
const trace = @import("../../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @This();
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const Thunk = @import("thunks.zig").Thunk;
const UnwindInfo = @import("UnwindInfo.zig");
