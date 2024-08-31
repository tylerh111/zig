data: std.ArrayListUnmanaged(u8) = .{},
/// Externally owned memory.
path: []const u8,
index: File.Index,

symtab: std.MultiArrayList(Nlist) = .{},
strtab: StringTable = .{},

symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
globals_lookup: std.AutoHashMapUnmanaged(u32, Symbol.Index) = .{},

/// Table of tracked LazySymbols.
lazy_syms: LazySymbolTable = .{},

/// Table of tracked Decls.
decls: DeclTable = .{},

/// Table of unnamed constants associated with a parent `Decl`.
/// We store them here so that we can free the constants whenever the `Decl`
/// needs updating or is freed.
///
/// For example,
///
/// ```zig
/// const Foo = struct{
///     a: u8,
/// };
///
/// pub fn main() void {
///     var foo = Foo{ .a = 1 };
///     _ = foo;
/// }
/// ```
///
/// value assigned to label `foo` is an unnamed constant belonging/associated
/// with `Decl` `main`, and lives as long as that `Decl`.
unnamed_consts: UnnamedConstTable = .{},

/// Table of tracked AnonDecls.
anon_decls: AnonDeclTable = .{},

/// TLV initializers indexed by Atom.Index.
tlv_initializers: TlvInitializerTable = .{},

/// A table of relocations.
relocs: RelocationTable = .{},

dwarf: ?Dwarf = null,

dynamic_relocs: MachO.DynamicRelocs = .{},
output_symtab_ctx: MachO.SymtabCtx = .{},
output_ar_state: Archive.ArState = .{},

debug_strtab_dirty: bool = false,
debug_abbrev_dirty: bool = false,
debug_aranges_dirty: bool = false,
debug_info_header_dirty: bool = false,
debug_line_header_dirty: bool = false,

pub fn init(self: *ZigObject, macho_file: *MachO) !void {
    const comp = macho_file.base.comp;
    const gpa = comp.gpa;

    try self.atoms.append(gpa, 0); // null input section
    try self.strtab.buffer.append(gpa, 0);

    switch (comp.config.debug_format) {
        .strip => {},
        .dwarf => |v| {
            assert(v == .@"32");
            self.dwarf = Dwarf.init(&macho_file.base, .dwarf32);
            self.debug_strtab_dirty = true;
            self.debug_abbrev_dirty = true;
            self.debug_aranges_dirty = true;
            self.debug_info_header_dirty = true;
            self.debug_line_header_dirty = true;
        },
        .code_view => unreachable,
    }
}

pub fn deinit(self: *ZigObject, allocator: Allocator) void {
    self.data.deinit(allocator);
    self.symtab.deinit(allocator);
    self.strtab.deinit(allocator);
    self.symbols.deinit(allocator);
    self.atoms.deinit(allocator);
    self.globals_lookup.deinit(allocator);

    {
        var it = self.decls.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.exports.deinit(allocator);
        }
        self.decls.deinit(allocator);
    }

    self.lazy_syms.deinit(allocator);

    {
        var it = self.unnamed_consts.value_iterator();
        while (it.next()) |syms| {
            syms.deinit(allocator);
        }
        self.unnamed_consts.deinit(allocator);
    }

    {
        var it = self.anon_decls.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.exports.deinit(allocator);
        }
        self.anon_decls.deinit(allocator);
    }

    for (self.relocs.items) |*list| {
        list.deinit(allocator);
    }
    self.relocs.deinit(allocator);

    for (self.tlv_initializers.values()) |*tlv_init| {
        tlv_init.deinit(allocator);
    }
    self.tlv_initializers.deinit(allocator);

    if (self.dwarf) |*dw| {
        dw.deinit();
    }
}

fn add_nlist(self: *ZigObject, allocator: Allocator) !Symbol.Index {
    try self.symtab.ensure_unused_capacity(allocator, 1);
    const index = @as(Symbol.Index, @int_cast(self.symtab.add_one_assume_capacity()));
    self.symtab.set(index, .{
        .nlist = MachO.null_sym,
        .size = 0,
        .atom = 0,
    });
    return index;
}

pub fn add_atom(self: *ZigObject, macho_file: *MachO) !Symbol.Index {
    const gpa = macho_file.base.comp.gpa;
    const atom_index = try macho_file.add_atom();
    const symbol_index = try macho_file.add_symbol();
    const nlist_index = try self.add_nlist(gpa);

    try self.atoms.append(gpa, atom_index);
    try self.symbols.append(gpa, symbol_index);

    const atom = macho_file.get_atom(atom_index).?;
    atom.file = self.index;
    atom.atom_index = atom_index;

    const symbol = macho_file.get_symbol(symbol_index);
    symbol.file = self.index;
    symbol.atom = atom_index;

    self.symtab.items(.atom)[nlist_index] = atom_index;
    symbol.nlist_idx = nlist_index;

    const relocs_index = @as(u32, @int_cast(self.relocs.items.len));
    const relocs = try self.relocs.add_one(gpa);
    relocs.* = .{};
    try atom.add_extra(.{ .rel_index = relocs_index, .rel_count = 0 }, macho_file);
    atom.flags.relocs = true;

    return symbol_index;
}

pub fn get_atom_data(self: ZigObject, macho_file: *MachO, atom: Atom, buffer: []u8) !void {
    assert(atom.file == self.index);
    assert(atom.size == buffer.len);
    const sect = macho_file.sections.items(.header)[atom.out_n_sect];
    assert(!sect.is_zerofill());

    switch (sect.type()) {
        macho.S_THREAD_LOCAL_REGULAR => {
            const tlv = self.tlv_initializers.get(atom.atom_index).?;
            @memcpy(buffer, tlv.data);
        },
        macho.S_THREAD_LOCAL_VARIABLES => {
            @memset(buffer, 0);
        },
        else => {
            const file_offset = sect.offset + atom.value;
            const amt = try macho_file.base.file.?.pread_all(buffer, file_offset);
            if (amt != buffer.len) return error.InputOutput;
        },
    }
}

pub fn get_atom_relocs(self: *ZigObject, atom: Atom, macho_file: *MachO) []const Relocation {
    if (!atom.flags.relocs) return &[0]Relocation{};
    const extra = atom.get_extra(macho_file).?;
    const relocs = self.relocs.items[extra.rel_index];
    return relocs.items[0..extra.rel_count];
}

pub fn free_atom_relocs(self: *ZigObject, atom: Atom, macho_file: *MachO) void {
    if (atom.flags.relocs) {
        const extra = atom.get_extra(macho_file).?;
        self.relocs.items[extra.rel_index].clear_retaining_capacity();
    }
}

pub fn resolve_symbols(self: *ZigObject, macho_file: *MachO) void {
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
            .archive = false,
            .weak = nlist.weak_def(),
            .tentative = nlist.tentative(),
        }) < symbol.get_symbol_rank(macho_file)) {
            const value = if (nlist.sect()) blk: {
                const atom = macho_file.get_atom(atom_index).?;
                break :blk nlist.n_value - atom.get_input_address(macho_file);
            } else nlist.n_value;
            const out_n_sect = if (nlist.sect()) macho_file.get_atom(atom_index).?.out_n_sect else 0;
            symbol.value = value;
            symbol.atom = atom_index;
            symbol.out_n_sect = out_n_sect;
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
                macho_file.sections.items(.header)[nlist.n_sect - 1].type() == macho.S_THREAD_LOCAL_VARIABLES)
            {
                symbol.flags.tlv = true;
            }
        }

        // Regardless of who the winner is, we still merge symbol visibility here.
        if (nlist.pext() or (nlist.weak_def() and nlist.weak_ref())) {
            if (symbol.visibility != .global) {
                symbol.visibility = .hidden;
            }
        } else {
            symbol.visibility = .global;
        }
    }
}

pub fn reset_globals(self: *ZigObject, macho_file: *MachO) void {
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

pub fn mark_live(self: *ZigObject, macho_file: *MachO) void {
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

pub fn check_duplicates(self: *ZigObject, dupes: anytype, macho_file: *MachO) !void {
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

pub fn resolve_literals(self: *ZigObject, lp: *MachO.LiteralPool, macho_file: *MachO) !void {
    _ = self;
    _ = lp;
    _ = macho_file;
    // TODO
}

pub fn dedup_literals(self: *ZigObject, lp: MachO.LiteralPool, macho_file: *MachO) void {
    _ = self;
    _ = lp;
    _ = macho_file;
    // TODO
}

/// This is just a temporary helper function that allows us to re-read what we wrote to file into a buffer.
/// We need this so that we can write to an archive.
/// TODO implement writing ZigObject data directly to a buffer instead.
pub fn read_file_contents(self: *ZigObject, size: usize, macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;
    try self.data.resize(gpa, size);
    const amt = try macho_file.base.file.?.pread_all(self.data.items, 0);
    if (amt != size) return error.InputOutput;
}

pub fn update_ar_symtab(self: ZigObject, ar_symtab: *Archive.ArSymtab, macho_file: *MachO) error{OutOfMemory}!void {
    const gpa = macho_file.base.comp.gpa;
    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        const file = sym.get_file(macho_file).?;
        assert(file.get_index() == self.index);
        if (!sym.flags.@"export") continue;
        const off = try ar_symtab.strtab.insert(gpa, sym.get_name(macho_file));
        try ar_symtab.entries.append(gpa, .{ .off = off, .file = self.index });
    }
}

pub fn update_ar_size(self: *ZigObject) void {
    self.output_ar_state.size = self.data.items.len;
}

pub fn write_ar(self: ZigObject, ar_format: Archive.Format, writer: anytype) !void {
    // Header
    const size = std.math.cast(usize, self.output_ar_state.size) orelse return error.Overflow;
    try Archive.write_header(self.path, size, ar_format, writer);
    // Data
    try writer.write_all(self.data.items);
}

pub fn scan_relocs(self: *ZigObject, macho_file: *MachO) !void {
    for (self.atoms.items) |atom_index| {
        const atom = macho_file.get_atom(atom_index) orelse continue;
        if (!atom.flags.alive) continue;
        const sect = atom.get_input_section(macho_file);
        if (sect.is_zerofill()) continue;
        try atom.scan_relocs(macho_file);
    }
}

pub fn calc_symtab_size(self: *ZigObject, macho_file: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.symbols.items) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        const file = sym.get_file(macho_file) orelse continue;
        if (file.get_index() != self.index) continue;
        if (sym.get_atom(macho_file)) |atom| if (!atom.flags.alive) continue;
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

pub fn write_symtab(self: ZigObject, macho_file: *MachO, ctx: anytype) void {
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
}

pub fn get_input_section(self: ZigObject, atom: Atom, macho_file: *MachO) macho.section_64 {
    _ = self;
    var sect = macho_file.sections.items(.header)[atom.out_n_sect];
    sect.addr = 0;
    sect.offset = 0;
    sect.size = atom.size;
    sect.@"align" = atom.alignment.to_log2_units();
    return sect;
}

pub fn flush_module(self: *ZigObject, macho_file: *MachO) !void {
    // Handle any lazy symbols that were emitted by incremental compilation.
    if (self.lazy_syms.get_ptr(.none)) |metadata| {
        const zcu = macho_file.base.comp.module.?;

        // Most lazy symbols can be updated on first use, but
        // anyerror needs to wait for everything to be flushed.
        if (metadata.text_state != .unused) self.update_lazy_symbol(
            macho_file,
            link.File.LazySymbol.init_decl(.code, null, zcu),
            metadata.text_symbol_index,
        ) catch |err| return switch (err) {
            error.CodegenFail => error.FlushFailure,
            else => |e| e,
        };
        if (metadata.const_state != .unused) self.update_lazy_symbol(
            macho_file,
            link.File.LazySymbol.init_decl(.const_data, null, zcu),
            metadata.const_symbol_index,
        ) catch |err| return switch (err) {
            error.CodegenFail => error.FlushFailure,
            else => |e| e,
        };
    }
    for (self.lazy_syms.values()) |*metadata| {
        if (metadata.text_state != .unused) metadata.text_state = .flushed;
        if (metadata.const_state != .unused) metadata.const_state = .flushed;
    }

    if (self.dwarf) |*dw| {
        const zcu = macho_file.base.comp.module.?;
        try dw.flush_module(zcu);

        if (self.debug_abbrev_dirty) {
            try dw.write_dbg_abbrev();
            self.debug_abbrev_dirty = false;
        }

        if (self.debug_info_header_dirty) {
            // Currently only one compilation unit is supported, so the address range is simply
            // identical to the main program header virtual address and memory size.
            const text_section = macho_file.sections.items(.header)[macho_file.zig_text_sect_index.?];
            const low_pc = text_section.addr;
            const high_pc = text_section.addr + text_section.size;
            try dw.write_dbg_info_header(zcu, low_pc, high_pc);
            self.debug_info_header_dirty = false;
        }

        if (self.debug_aranges_dirty) {
            // Currently only one compilation unit is supported, so the address range is simply
            // identical to the main program header virtual address and memory size.
            const text_section = macho_file.sections.items(.header)[macho_file.zig_text_sect_index.?];
            try dw.write_dbg_aranges(text_section.addr, text_section.size);
            self.debug_aranges_dirty = false;
        }

        if (self.debug_line_header_dirty) {
            try dw.write_dbg_line_header();
            self.debug_line_header_dirty = false;
        }

        if (!macho_file.base.is_relocatable()) {
            const d_sym = macho_file.get_debug_symbols().?;
            const sect_index = d_sym.debug_str_section_index.?;
            if (self.debug_strtab_dirty or dw.strtab.buffer.items.len != d_sym.get_section(sect_index).size) {
                const needed_size = @as(u32, @int_cast(dw.strtab.buffer.items.len));
                try d_sym.grow_section(sect_index, needed_size, false, macho_file);
                try d_sym.file.pwrite_all(dw.strtab.buffer.items, d_sym.get_section(sect_index).offset);
                self.debug_strtab_dirty = false;
            }
        } else {
            const sect_index = macho_file.debug_str_sect_index.?;
            if (self.debug_strtab_dirty or dw.strtab.buffer.items.len != macho_file.sections.items(.header)[sect_index].size) {
                const needed_size = @as(u32, @int_cast(dw.strtab.buffer.items.len));
                try macho_file.grow_section(sect_index, needed_size);
                try macho_file.base.file.?.pwrite_all(dw.strtab.buffer.items, macho_file.sections.items(.header)[sect_index].offset);
                self.debug_strtab_dirty = false;
            }
        }
    }

    // The point of flush_module() is to commit changes, so in theory, nothing should
    // be dirty after this. However, it is possible for some things to remain
    // dirty because they fail to be written in the event of compile errors,
    // such as debug_line_header_dirty and debug_info_header_dirty.
    assert(!self.debug_abbrev_dirty);
    assert(!self.debug_aranges_dirty);
    assert(!self.debug_strtab_dirty);
}

pub fn get_decl_vaddr(
    self: *ZigObject,
    macho_file: *MachO,
    decl_index: InternPool.DeclIndex,
    reloc_info: link.File.RelocInfo,
) !u64 {
    const sym_index = try self.get_or_create_metadata_for_decl(macho_file, decl_index);
    const sym = macho_file.get_symbol(sym_index);
    const vaddr = sym.get_address(.{}, macho_file);
    const parent_atom = macho_file.get_symbol(reloc_info.parent_atom_index).get_atom(macho_file).?;
    try parent_atom.add_reloc(macho_file, .{
        .tag = .@"extern",
        .offset = @int_cast(reloc_info.offset),
        .target = sym_index,
        .addend = reloc_info.addend,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .has_subtractor = false,
            .length = 3,
            .symbolnum = @int_cast(sym.nlist_idx),
        },
    });
    return vaddr;
}

pub fn get_anon_decl_vaddr(
    self: *ZigObject,
    macho_file: *MachO,
    decl_val: InternPool.Index,
    reloc_info: link.File.RelocInfo,
) !u64 {
    const sym_index = self.anon_decls.get(decl_val).?.symbol_index;
    const sym = macho_file.get_symbol(sym_index);
    const vaddr = sym.get_address(.{}, macho_file);
    const parent_atom = macho_file.get_symbol(reloc_info.parent_atom_index).get_atom(macho_file).?;
    try parent_atom.add_reloc(macho_file, .{
        .tag = .@"extern",
        .offset = @int_cast(reloc_info.offset),
        .target = sym_index,
        .addend = reloc_info.addend,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .has_subtractor = false,
            .length = 3,
            .symbolnum = @int_cast(sym.nlist_idx),
        },
    });
    return vaddr;
}

pub fn lower_anon_decl(
    self: *ZigObject,
    macho_file: *MachO,
    decl_val: InternPool.Index,
    explicit_alignment: Atom.Alignment,
    src_loc: Module.SrcLoc,
) !codegen.Result {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;
    const ty = Type.from_interned(mod.intern_pool.type_of(decl_val));
    const decl_alignment = switch (explicit_alignment) {
        .none => ty.abi_alignment(mod),
        else => explicit_alignment,
    };
    if (self.anon_decls.get(decl_val)) |metadata| {
        const existing_alignment = macho_file.get_symbol(metadata.symbol_index).get_atom(macho_file).?.alignment;
        if (decl_alignment.order(existing_alignment).compare(.lte))
            return .ok;
    }

    var name_buf: [32]u8 = undefined;
    const name = std.fmt.buf_print(&name_buf, "__anon_{d}", .{
        @int_from_enum(decl_val),
    }) catch unreachable;
    const res = self.lower_const(
        macho_file,
        name,
        Value.from_interned(decl_val),
        decl_alignment,
        macho_file.zig_const_sect_index.?,
        src_loc,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |e| return .{ .fail = try Module.ErrorMsg.create(
            gpa,
            src_loc,
            "unable to lower constant value: {s}",
            .{@errorName(e)},
        ) },
    };
    const sym_index = switch (res) {
        .ok => |sym_index| sym_index,
        .fail => |em| return .{ .fail = em },
    };
    try self.anon_decls.put(gpa, decl_val, .{ .symbol_index = sym_index });
    return .ok;
}

fn free_unnamed_consts(self: *ZigObject, macho_file: *MachO, decl_index: InternPool.DeclIndex) void {
    const gpa = macho_file.base.comp.gpa;
    const unnamed_consts = self.unnamed_consts.get_ptr(decl_index) orelse return;
    for (unnamed_consts.items) |sym_index| {
        self.free_decl_metadata(macho_file, sym_index);
    }
    unnamed_consts.clear_and_free(gpa);
}

fn free_decl_metadata(self: *ZigObject, macho_file: *MachO, sym_index: Symbol.Index) void {
    _ = self;
    const gpa = macho_file.base.comp.gpa;
    const sym = macho_file.get_symbol(sym_index);
    sym.get_atom(macho_file).?.free(macho_file);
    log.debug("adding %{d} to local symbols free list", .{sym_index});
    macho_file.symbols_free_list.append(gpa, sym_index) catch {};
    macho_file.symbols.items[sym_index] = .{};
    // TODO free GOT entry here
}

pub fn free_decl(self: *ZigObject, macho_file: *MachO, decl_index: InternPool.DeclIndex) void {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);

    log.debug("free_decl {*}", .{decl});

    if (self.decls.fetch_remove(decl_index)) |const_kv| {
        var kv = const_kv;
        const sym_index = kv.value.symbol_index;
        self.free_decl_metadata(macho_file, sym_index);
        self.free_unnamed_consts(macho_file, decl_index);
        kv.value.exports.deinit(gpa);
    }

    // TODO free decl in dSYM
}

pub fn update_func(
    self: *ZigObject,
    macho_file: *MachO,
    mod: *Module,
    func_index: InternPool.Index,
    air: Air,
    liveness: Liveness,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const func = mod.func_info(func_index);
    const decl_index = func.owner_decl;
    const decl = mod.decl_ptr(decl_index);

    const sym_index = try self.get_or_create_metadata_for_decl(macho_file, decl_index);
    self.free_unnamed_consts(macho_file, decl_index);
    macho_file.get_symbol(sym_index).get_atom(macho_file).?.free_relocs(macho_file);

    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    var decl_state: ?Dwarf.DeclState = if (self.dwarf) |*dw| try dw.init_decl_state(mod, decl_index) else null;
    defer if (decl_state) |*ds| ds.deinit();

    const dio: codegen.DebugInfoOutput = if (decl_state) |*ds| .{ .dwarf = ds } else .none;
    const res = try codegen.generate_function(
        &macho_file.base,
        decl.src_loc(mod),
        func_index,
        air,
        liveness,
        &code_buffer,
        dio,
    );

    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            func.analysis(&mod.intern_pool).state = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            return;
        },
    };

    const sect_index = try self.get_decl_output_section(macho_file, decl, code);
    try self.update_decl_code(macho_file, decl_index, sym_index, sect_index, code);

    if (decl_state) |*ds| {
        const sym = macho_file.get_symbol(sym_index);
        try self.dwarf.?.commit_decl_state(
            mod,
            decl_index,
            sym.get_address(.{}, macho_file),
            sym.get_atom(macho_file).?.size,
            ds,
        );
    }

    // Since we updated the vaddr and the size, each corresponding export
    // symbol also needs to be updated.
    return self.update_exports(macho_file, mod, .{ .decl_index = decl_index }, mod.get_decl_exports(decl_index));
}

pub fn update_decl(
    self: *ZigObject,
    macho_file: *MachO,
    mod: *Module,
    decl_index: InternPool.DeclIndex,
) link.File.UpdateDeclError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const decl = mod.decl_ptr(decl_index);

    if (decl.val.get_extern_func(mod)) |_| {
        return;
    }

    if (decl.is_extern(mod)) {
        // Extern variable gets a __got entry only
        const variable = decl.get_owned_variable(mod).?;
        const name = decl.name.to_slice(&mod.intern_pool);
        const lib_name = variable.lib_name.to_slice(&mod.intern_pool);
        const index = try self.get_global_symbol(macho_file, name, lib_name);
        const actual_index = self.symbols.items[index];
        macho_file.get_symbol(actual_index).flags.needs_got = true;
        return;
    }

    const sym_index = try self.get_or_create_metadata_for_decl(macho_file, decl_index);
    macho_file.get_symbol(sym_index).get_atom(macho_file).?.free_relocs(macho_file);

    const gpa = macho_file.base.comp.gpa;
    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    var decl_state: ?Dwarf.DeclState = if (self.dwarf) |*dw| try dw.init_decl_state(mod, decl_index) else null;
    defer if (decl_state) |*ds| ds.deinit();

    const decl_val = if (decl.val.get_variable(mod)) |variable| Value.from_interned(variable.init) else decl.val;
    const dio: codegen.DebugInfoOutput = if (decl_state) |*ds| .{ .dwarf = ds } else .none;
    const res = try codegen.generate_symbol(&macho_file.base, decl.src_loc(mod), decl_val, &code_buffer, dio, .{
        .parent_atom_index = sym_index,
    });

    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            decl.analysis = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            return;
        },
    };
    const sect_index = try self.get_decl_output_section(macho_file, decl, code);
    const is_threadlocal = switch (macho_file.sections.items(.header)[sect_index].type()) {
        macho.S_THREAD_LOCAL_ZEROFILL, macho.S_THREAD_LOCAL_REGULAR => true,
        else => false,
    };
    if (is_threadlocal) {
        try self.update_tlv(macho_file, decl_index, sym_index, sect_index, code);
    } else {
        try self.update_decl_code(macho_file, decl_index, sym_index, sect_index, code);
    }

    if (decl_state) |*ds| {
        const sym = macho_file.get_symbol(sym_index);
        try self.dwarf.?.commit_decl_state(
            mod,
            decl_index,
            sym.get_address(.{}, macho_file),
            sym.get_atom(macho_file).?.size,
            ds,
        );
    }

    // Since we updated the vaddr and the size, each corresponding export symbol also
    // needs to be updated.
    try self.update_exports(macho_file, mod, .{ .decl_index = decl_index }, mod.get_decl_exports(decl_index));
}

fn update_decl_code(
    self: *ZigObject,
    macho_file: *MachO,
    decl_index: InternPool.DeclIndex,
    sym_index: Symbol.Index,
    sect_index: u8,
    code: []const u8,
) !void {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);
    const decl_name = try decl.fully_qualified_name(mod);

    log.debug("update_decl_code {}{*}", .{ decl_name.fmt(&mod.intern_pool), decl });

    const required_alignment = decl.get_alignment(mod);

    const sect = &macho_file.sections.items(.header)[sect_index];
    const sym = macho_file.get_symbol(sym_index);
    const nlist = &self.symtab.items(.nlist)[sym.nlist_idx];
    const atom = sym.get_atom(macho_file).?;

    sym.out_n_sect = sect_index;
    atom.out_n_sect = sect_index;

    sym.name = try self.strtab.insert(gpa, decl_name.to_slice(&mod.intern_pool));
    atom.flags.alive = true;
    atom.name = sym.name;
    nlist.n_strx = sym.name;
    nlist.n_type = macho.N_SECT;
    nlist.n_sect = sect_index + 1;
    self.symtab.items(.size)[sym.nlist_idx] = code.len;

    const old_size = atom.size;
    const old_vaddr = atom.value;
    atom.alignment = required_alignment;
    atom.size = code.len;

    if (old_size > 0) {
        const capacity = atom.capacity(macho_file);
        const need_realloc = code.len > capacity or !required_alignment.check(atom.value);

        if (need_realloc) {
            try atom.grow(macho_file);
            log.debug("growing {} from 0x{x} to 0x{x}", .{ decl_name.fmt(&mod.intern_pool), old_vaddr, atom.value });
            if (old_vaddr != atom.value) {
                sym.value = 0;
                nlist.n_value = 0;

                if (!macho_file.base.is_relocatable()) {
                    log.debug("  (updating offset table entry)", .{});
                    assert(sym.flags.has_zig_got);
                    const extra = sym.get_extra(macho_file).?;
                    try macho_file.zig_got.write_one(macho_file, extra.zig_got);
                }
            }
        } else if (code.len < old_size) {
            atom.shrink(macho_file);
        } else if (macho_file.get_atom(atom.next_index) == null) {
            const needed_size = atom.value + code.len;
            sect.size = needed_size;
        }
    } else {
        try atom.allocate(macho_file);
        errdefer self.free_decl_metadata(macho_file, sym_index);

        sym.value = 0;
        sym.flags.needs_zig_got = true;
        nlist.n_value = 0;

        if (!macho_file.base.is_relocatable()) {
            const gop = try sym.get_or_create_zig_got_entry(sym_index, macho_file);
            try macho_file.zig_got.write_one(macho_file, gop.index);
        }
    }

    if (!sect.is_zerofill()) {
        const file_offset = sect.offset + atom.value;
        try macho_file.base.file.?.pwrite_all(code, file_offset);
    }
}

/// Lowering a TLV on macOS involves two stages:
/// 1. first we lower the initializer into appopriate section (__thread_data or __thread_bss)
/// 2. next, we create a corresponding threadlocal variable descriptor in __thread_vars
fn update_tlv(
    self: *ZigObject,
    macho_file: *MachO,
    decl_index: InternPool.DeclIndex,
    sym_index: Symbol.Index,
    sect_index: u8,
    code: []const u8,
) !void {
    const mod = macho_file.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);
    const decl_name = try decl.fully_qualified_name(mod);

    log.debug("update_tlv {} ({*})", .{ decl_name.fmt(&mod.intern_pool), decl });

    const decl_name_slice = decl_name.to_slice(&mod.intern_pool);
    const required_alignment = decl.get_alignment(mod);

    // 1. Lower TLV initializer
    const init_sym_index = try self.create_tlv_initializer(
        macho_file,
        decl_name_slice,
        required_alignment,
        sect_index,
        code,
    );

    // 2. Create TLV descriptor
    try self.create_tlv_descriptor(macho_file, sym_index, init_sym_index, decl_name_slice);
}

fn create_tlv_initializer(
    self: *ZigObject,
    macho_file: *MachO,
    name: []const u8,
    alignment: Atom.Alignment,
    sect_index: u8,
    code: []const u8,
) !Symbol.Index {
    const gpa = macho_file.base.comp.gpa;
    const sym_name = try std.fmt.alloc_print(gpa, "{s}$tlv$init", .{name});
    defer gpa.free(sym_name);

    const sym_index = try self.add_atom(macho_file);
    const sym = macho_file.get_symbol(sym_index);
    const nlist = &self.symtab.items(.nlist)[sym.nlist_idx];
    const atom = sym.get_atom(macho_file).?;

    sym.out_n_sect = sect_index;
    atom.out_n_sect = sect_index;

    sym.value = 0;
    sym.name = try self.strtab.insert(gpa, sym_name);
    atom.flags.alive = true;
    atom.name = sym.name;
    nlist.n_strx = sym.name;
    nlist.n_sect = sect_index + 1;
    nlist.n_type = macho.N_SECT;
    nlist.n_value = 0;
    self.symtab.items(.size)[sym.nlist_idx] = code.len;

    atom.alignment = alignment;
    atom.size = code.len;

    const slice = macho_file.sections.slice();
    const header = slice.items(.header)[sect_index];
    const atoms = &slice.items(.atoms)[sect_index];

    const gop = try self.tlv_initializers.get_or_put(gpa, atom.atom_index);
    assert(!gop.found_existing); // TODO incremental updates
    gop.value_ptr.* = .{ .symbol_index = sym_index };

    // We only store the data for the TLV if it's non-zerofill.
    if (!header.is_zerofill()) {
        gop.value_ptr.data = try gpa.dupe(u8, code);
    }

    try atoms.append(gpa, atom.atom_index);

    return sym_index;
}

fn create_tlv_descriptor(
    self: *ZigObject,
    macho_file: *MachO,
    sym_index: Symbol.Index,
    init_sym_index: Symbol.Index,
    name: []const u8,
) !void {
    const gpa = macho_file.base.comp.gpa;

    const sym = macho_file.get_symbol(sym_index);
    const nlist = &self.symtab.items(.nlist)[sym.nlist_idx];
    const atom = sym.get_atom(macho_file).?;
    const alignment = Atom.Alignment.from_nonzero_byte_units(@alignOf(u64));
    const size: u64 = @size_of(u64) * 3;

    const sect_index = macho_file.get_section_by_name("__DATA", "__thread_vars") orelse
        try macho_file.add_section("__DATA", "__thread_vars", .{
        .flags = macho.S_THREAD_LOCAL_VARIABLES,
    });
    sym.out_n_sect = sect_index;
    atom.out_n_sect = sect_index;

    sym.value = 0;
    sym.name = try self.strtab.insert(gpa, name);
    atom.flags.alive = true;
    atom.name = sym.name;
    nlist.n_strx = sym.name;
    nlist.n_sect = sect_index + 1;
    nlist.n_type = macho.N_SECT;
    nlist.n_value = 0;
    self.symtab.items(.size)[sym.nlist_idx] = size;

    atom.alignment = alignment;
    atom.size = size;

    const tlv_bootstrap_index = try self.get_global_symbol(macho_file, "_tlv_bootstrap", null);
    try atom.add_reloc(macho_file, .{
        .tag = .@"extern",
        .offset = 0,
        .target = self.symbols.items[tlv_bootstrap_index],
        .addend = 0,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .has_subtractor = false,
            .length = 3,
            .symbolnum = @int_cast(tlv_bootstrap_index),
        },
    });
    try atom.add_reloc(macho_file, .{
        .tag = .@"extern",
        .offset = 16,
        .target = init_sym_index,
        .addend = 0,
        .type = .unsigned,
        .meta = .{
            .pcrel = false,
            .has_subtractor = false,
            .length = 3,
            .symbolnum = @int_cast(macho_file.get_symbol(init_sym_index).nlist_idx),
        },
    });

    try macho_file.sections.items(.atoms)[sect_index].append(gpa, atom.atom_index);
}

fn get_decl_output_section(
    self: *ZigObject,
    macho_file: *MachO,
    decl: *const Module.Decl,
    code: []const u8,
) error{OutOfMemory}!u8 {
    _ = self;
    const mod = macho_file.base.comp.module.?;
    const any_non_single_threaded = macho_file.base.comp.config.any_non_single_threaded;
    const sect_id: u8 = switch (decl.type_of(mod).zig_type_tag(mod)) {
        .Fn => macho_file.zig_text_sect_index.?,
        else => blk: {
            if (decl.get_owned_variable(mod)) |variable| {
                if (variable.is_threadlocal and any_non_single_threaded) {
                    const is_all_zeroes = for (code) |byte| {
                        if (byte != 0) break false;
                    } else true;
                    if (is_all_zeroes) break :blk macho_file.get_section_by_name("__DATA", "__thread_bss") orelse try macho_file.add_section(
                        "__DATA",
                        "__thread_bss",
                        .{ .flags = macho.S_THREAD_LOCAL_ZEROFILL },
                    );
                    break :blk macho_file.get_section_by_name("__DATA", "__thread_data") orelse try macho_file.add_section(
                        "__DATA",
                        "__thread_data",
                        .{ .flags = macho.S_THREAD_LOCAL_REGULAR },
                    );
                }

                if (variable.is_const) break :blk macho_file.zig_const_sect_index.?;
                if (Value.from_interned(variable.init).is_undef_deep(mod)) {
                    // TODO: get the optimize_mode from the Module that owns the decl instead
                    // of using the root module here.
                    break :blk switch (macho_file.base.comp.root_mod.optimize_mode) {
                        .Debug, .ReleaseSafe => macho_file.zig_data_sect_index.?,
                        .ReleaseFast, .ReleaseSmall => macho_file.zig_bss_sect_index.?,
                    };
                }

                // TODO I blatantly copied the logic from the Wasm linker, but is there a less
                // intrusive check for all zeroes than this?
                const is_all_zeroes = for (code) |byte| {
                    if (byte != 0) break false;
                } else true;
                if (is_all_zeroes) break :blk macho_file.zig_bss_sect_index.?;
                break :blk macho_file.zig_data_sect_index.?;
            }
            break :blk macho_file.zig_const_sect_index.?;
        },
    };
    return sect_id;
}

pub fn lower_unnamed_const(
    self: *ZigObject,
    macho_file: *MachO,
    val: Value,
    decl_index: InternPool.DeclIndex,
) !u32 {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;
    const gop = try self.unnamed_consts.get_or_put(gpa, decl_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    const unnamed_consts = gop.value_ptr;
    const decl = mod.decl_ptr(decl_index);
    const decl_name = try decl.fully_qualified_name(mod);
    const index = unnamed_consts.items.len;
    const name = try std.fmt.alloc_print(gpa, "__unnamed_{}_{d}", .{ decl_name.fmt(&mod.intern_pool), index });
    defer gpa.free(name);
    const sym_index = switch (try self.lower_const(
        macho_file,
        name,
        val,
        val.type_of(mod).abi_alignment(mod),
        macho_file.zig_const_sect_index.?,
        decl.src_loc(mod),
    )) {
        .ok => |sym_index| sym_index,
        .fail => |em| {
            decl.analysis = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            log.err("{s}", .{em.msg});
            return error.CodegenFail;
        },
    };
    const sym = macho_file.get_symbol(sym_index);
    try unnamed_consts.append(gpa, sym.atom);
    return sym_index;
}

const LowerConstResult = union(enum) {
    ok: Symbol.Index,
    fail: *Module.ErrorMsg,
};

fn lower_const(
    self: *ZigObject,
    macho_file: *MachO,
    name: []const u8,
    val: Value,
    required_alignment: Atom.Alignment,
    output_section_index: u8,
    src_loc: Module.SrcLoc,
) !LowerConstResult {
    const gpa = macho_file.base.comp.gpa;

    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const sym_index = try self.add_atom(macho_file);

    const res = try codegen.generate_symbol(&macho_file.base, src_loc, val, &code_buffer, .{
        .none = {},
    }, .{
        .parent_atom_index = sym_index,
    });
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| return .{ .fail = em },
    };

    const sym = macho_file.get_symbol(sym_index);
    const name_str_index = try self.strtab.insert(gpa, name);
    sym.name = name_str_index;
    sym.out_n_sect = output_section_index;

    const nlist = &self.symtab.items(.nlist)[sym.nlist_idx];
    nlist.n_strx = name_str_index;
    nlist.n_type = macho.N_SECT;
    nlist.n_sect = output_section_index + 1;
    self.symtab.items(.size)[sym.nlist_idx] = code.len;

    const atom = sym.get_atom(macho_file).?;
    atom.flags.alive = true;
    atom.name = name_str_index;
    atom.alignment = required_alignment;
    atom.size = code.len;
    atom.out_n_sect = output_section_index;

    try atom.allocate(macho_file);
    // TODO rename and re-audit this method
    errdefer self.free_decl_metadata(macho_file, sym_index);

    sym.value = 0;
    nlist.n_value = 0;

    const sect = macho_file.sections.items(.header)[output_section_index];
    const file_offset = sect.offset + atom.value;
    try macho_file.base.file.?.pwrite_all(code, file_offset);

    return .{ .ok = sym_index };
}

pub fn update_exports(
    self: *ZigObject,
    macho_file: *MachO,
    mod: *Module,
    exported: Module.Exported,
    exports: []const *Module.Export,
) link.File.UpdateExportsError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = macho_file.base.comp.gpa;
    const metadata = switch (exported) {
        .decl_index => |decl_index| blk: {
            _ = try self.get_or_create_metadata_for_decl(macho_file, decl_index);
            break :blk self.decls.get_ptr(decl_index).?;
        },
        .value => |value| self.anon_decls.get_ptr(value) orelse blk: {
            const first_exp = exports[0];
            const res = try self.lower_anon_decl(macho_file, value, .none, first_exp.get_src_loc(mod));
            switch (res) {
                .ok => {},
                .fail => |em| {
                    // TODO maybe it's enough to return an error here and let Module.process_exports_inner
                    // handle the error?
                    try mod.failed_exports.ensure_unused_capacity(mod.gpa, 1);
                    mod.failed_exports.put_assume_capacity_no_clobber(first_exp, em);
                    return;
                },
            }
            break :blk self.anon_decls.get_ptr(value).?;
        },
    };
    const sym_index = metadata.symbol_index;
    const nlist_idx = macho_file.get_symbol(sym_index).nlist_idx;
    const nlist = self.symtab.items(.nlist)[nlist_idx];

    for (exports) |exp| {
        if (exp.opts.section.unwrap()) |section_name| {
            if (!section_name.eql_slice("__text", &mod.intern_pool)) {
                try mod.failed_exports.ensure_unused_capacity(mod.gpa, 1);
                mod.failed_exports.put_assume_capacity_no_clobber(exp, try Module.ErrorMsg.create(
                    gpa,
                    exp.get_src_loc(mod),
                    "Unimplemented: ExportOptions.section",
                    .{},
                ));
                continue;
            }
        }
        if (exp.opts.linkage == .link_once) {
            try mod.failed_exports.put_no_clobber(mod.gpa, exp, try Module.ErrorMsg.create(
                gpa,
                exp.get_src_loc(mod),
                "Unimplemented: GlobalLinkage.link_once",
                .{},
            ));
            continue;
        }

        const exp_name = exp.opts.name.to_slice(&mod.intern_pool);
        const global_nlist_index = if (metadata.@"export"(self, exp_name)) |exp_index|
            exp_index.*
        else blk: {
            const global_nlist_index = try self.get_global_symbol(macho_file, exp_name, null);
            try metadata.exports.append(gpa, global_nlist_index);
            break :blk global_nlist_index;
        };
        const global_nlist = &self.symtab.items(.nlist)[global_nlist_index];
        global_nlist.n_value = nlist.n_value;
        global_nlist.n_sect = nlist.n_sect;
        global_nlist.n_type = macho.N_EXT | macho.N_SECT;
        self.symtab.items(.size)[global_nlist_index] = self.symtab.items(.size)[nlist_idx];
        self.symtab.items(.atom)[global_nlist_index] = self.symtab.items(.atom)[nlist_idx];

        switch (exp.opts.linkage) {
            .internal => {
                // Symbol should be hidden, or in MachO lingo, private extern.
                global_nlist.n_type |= macho.N_PEXT;
            },
            .strong => {},
            .weak => {
                // Weak linkage is specified as part of n_desc field.
                // Symbol's n_type is like for a symbol with strong linkage.
                global_nlist.n_desc |= macho.N_WEAK_DEF;
            },
            else => unreachable,
        }
    }
}

fn update_lazy_symbol(
    self: *ZigObject,
    macho_file: *MachO,
    lazy_sym: link.File.LazySymbol,
    symbol_index: Symbol.Index,
) !void {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;

    var required_alignment: Atom.Alignment = .none;
    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const name_str_index = blk: {
        const name = try std.fmt.alloc_print(gpa, "__lazy_{s}_{}", .{
            @tag_name(lazy_sym.kind),
            lazy_sym.ty.fmt(mod),
        });
        defer gpa.free(name);
        break :blk try self.strtab.insert(gpa, name);
    };

    const src = if (lazy_sym.ty.get_owner_decl_or_null(mod)) |owner_decl|
        mod.decl_ptr(owner_decl).src_loc(mod)
    else
        Module.SrcLoc{
            .file_scope = undefined,
            .parent_decl_node = undefined,
            .lazy = .unneeded,
        };
    const res = try codegen.generate_lazy_symbol(
        &macho_file.base,
        src,
        lazy_sym,
        &required_alignment,
        &code_buffer,
        .none,
        .{ .parent_atom_index = symbol_index },
    );
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            log.err("{s}", .{em.msg});
            return error.CodegenFail;
        },
    };

    const output_section_index = switch (lazy_sym.kind) {
        .code => macho_file.zig_text_sect_index.?,
        .const_data => macho_file.zig_const_sect_index.?,
    };
    const sym = macho_file.get_symbol(symbol_index);
    sym.name = name_str_index;
    sym.out_n_sect = output_section_index;

    const nlist = &self.symtab.items(.nlist)[sym.nlist_idx];
    nlist.n_strx = name_str_index;
    nlist.n_type = macho.N_SECT;
    nlist.n_sect = output_section_index + 1;
    self.symtab.items(.size)[sym.nlist_idx] = code.len;

    const atom = sym.get_atom(macho_file).?;
    atom.flags.alive = true;
    atom.name = name_str_index;
    atom.alignment = required_alignment;
    atom.size = code.len;
    atom.out_n_sect = output_section_index;

    try atom.allocate(macho_file);
    errdefer self.free_decl_metadata(macho_file, symbol_index);

    sym.value = 0;
    sym.flags.needs_zig_got = true;
    nlist.n_value = 0;

    if (!macho_file.base.is_relocatable()) {
        const gop = try sym.get_or_create_zig_got_entry(symbol_index, macho_file);
        try macho_file.zig_got.write_one(macho_file, gop.index);
    }

    const sect = macho_file.sections.items(.header)[output_section_index];
    const file_offset = sect.offset + atom.value;
    try macho_file.base.file.?.pwrite_all(code, file_offset);
}

/// Must be called only after a successful call to `update_decl`.
pub fn update_decl_line_number(self: *ZigObject, mod: *Module, decl_index: InternPool.DeclIndex) !void {
    if (self.dwarf) |*dw| {
        try dw.update_decl_line_number(mod, decl_index);
    }
}

pub fn delete_decl_export(
    self: *ZigObject,
    macho_file: *MachO,
    decl_index: InternPool.DeclIndex,
    name: InternPool.NullTerminatedString,
) void {
    const mod = macho_file.base.comp.module.?;

    const metadata = self.decls.get_ptr(decl_index) orelse return;
    const nlist_index = metadata.@"export"(self, name.to_slice(&mod.intern_pool)) orelse return;

    log.debug("deleting export '{}'", .{name.fmt(&mod.intern_pool)});

    const nlist = &self.symtab.items(.nlist)[nlist_index.*];
    self.symtab.items(.size)[nlist_index.*] = 0;
    _ = self.globals_lookup.remove(nlist.n_strx);
    const sym_index = macho_file.globals.get(nlist.n_strx).?;
    const sym = macho_file.get_symbol(sym_index);
    if (sym.file == self.index) {
        _ = macho_file.globals.swap_remove(nlist.n_strx);
        sym.* = .{};
    }
    nlist.* = MachO.null_sym;
}

pub fn get_global_symbol(self: *ZigObject, macho_file: *MachO, name: []const u8, lib_name: ?[]const u8) !u32 {
    _ = lib_name;
    const gpa = macho_file.base.comp.gpa;
    const sym_name = try std.fmt.alloc_print(gpa, "_{s}", .{name});
    defer gpa.free(sym_name);
    const off = try self.strtab.insert(gpa, sym_name);
    const lookup_gop = try self.globals_lookup.get_or_put(gpa, off);
    if (!lookup_gop.found_existing) {
        const nlist_index = try self.add_nlist(gpa);
        const nlist = &self.symtab.items(.nlist)[nlist_index];
        nlist.n_strx = off;
        nlist.n_type = macho.N_EXT;
        lookup_gop.value_ptr.* = nlist_index;
        const global_name_off = try macho_file.strings.insert(gpa, sym_name);
        const gop = try macho_file.get_or_create_global(global_name_off);
        try self.symbols.append(gpa, gop.index);
    }
    return lookup_gop.value_ptr.*;
}

pub fn get_or_create_metadata_for_decl(
    self: *ZigObject,
    macho_file: *MachO,
    decl_index: InternPool.DeclIndex,
) !Symbol.Index {
    const gpa = macho_file.base.comp.gpa;
    const gop = try self.decls.get_or_put(gpa, decl_index);
    if (!gop.found_existing) {
        const any_non_single_threaded = macho_file.base.comp.config.any_non_single_threaded;
        const sym_index = try self.add_atom(macho_file);
        const mod = macho_file.base.comp.module.?;
        const decl = mod.decl_ptr(decl_index);
        const sym = macho_file.get_symbol(sym_index);
        if (decl.get_owned_variable(mod)) |variable| {
            if (variable.is_threadlocal and any_non_single_threaded) {
                sym.flags.tlv = true;
            }
        }
        if (!sym.flags.tlv) {
            sym.flags.needs_zig_got = true;
        }
        gop.value_ptr.* = .{ .symbol_index = sym_index };
    }
    return gop.value_ptr.symbol_index;
}

pub fn get_or_create_metadata_for_lazy_symbol(
    self: *ZigObject,
    macho_file: *MachO,
    lazy_sym: link.File.LazySymbol,
) !Symbol.Index {
    const gpa = macho_file.base.comp.gpa;
    const mod = macho_file.base.comp.module.?;
    const gop = try self.lazy_syms.get_or_put(gpa, lazy_sym.get_decl(mod));
    errdefer _ = if (!gop.found_existing) self.lazy_syms.pop();
    if (!gop.found_existing) gop.value_ptr.* = .{};
    const metadata: struct {
        symbol_index: *Symbol.Index,
        state: *LazySymbolMetadata.State,
    } = switch (lazy_sym.kind) {
        .code => .{
            .symbol_index = &gop.value_ptr.text_symbol_index,
            .state = &gop.value_ptr.text_state,
        },
        .const_data => .{
            .symbol_index = &gop.value_ptr.const_symbol_index,
            .state = &gop.value_ptr.const_state,
        },
    };
    switch (metadata.state.*) {
        .unused => {
            const symbol_index = try self.add_atom(macho_file);
            const sym = macho_file.get_symbol(symbol_index);
            sym.flags.needs_zig_got = true;
            metadata.symbol_index.* = symbol_index;
        },
        .pending_flush => return metadata.symbol_index.*,
        .flushed => {},
    }
    metadata.state.* = .pending_flush;
    const symbol_index = metadata.symbol_index.*;
    // anyerror needs to be deferred until flush_module
    if (lazy_sym.get_decl(mod) != .none) try self.update_lazy_symbol(macho_file, lazy_sym, symbol_index);
    return symbol_index;
}

pub fn as_file(self: *ZigObject) File {
    return .{ .zig_object = self };
}

pub fn fmt_symtab(self: *ZigObject, macho_file: *MachO) std.fmt.Formatter(format_symtab) {
    return .{ .data = .{
        .self = self,
        .macho_file = macho_file,
    } };
}

const FormatContext = struct {
    self: *ZigObject,
    macho_file: *MachO,
};

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
        const sym = ctx.macho_file.get_symbol(index);
        try writer.print("    {}\n", .{sym.fmt(ctx.macho_file)});
    }
}

pub fn fmt_atoms(self: *ZigObject, macho_file: *MachO) std.fmt.Formatter(format_atoms) {
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
        const atom = ctx.macho_file.get_atom(atom_index) orelse continue;
        try writer.print("    {}\n", .{atom.fmt(ctx.macho_file)});
    }
}

const DeclMetadata = struct {
    symbol_index: Symbol.Index,
    /// A list of all exports aliases of this Decl.
    exports: std.ArrayListUnmanaged(Symbol.Index) = .{},

    fn @"export"(m: DeclMetadata, zig_object: *ZigObject, name: []const u8) ?*u32 {
        for (m.exports.items) |*exp| {
            const nlist = zig_object.symtab.items(.nlist)[exp.*];
            const exp_name = zig_object.strtab.get_assume_exists(nlist.n_strx);
            if (mem.eql(u8, name, exp_name)) return exp;
        }
        return null;
    }
};

const LazySymbolMetadata = struct {
    const State = enum { unused, pending_flush, flushed };
    text_symbol_index: Symbol.Index = undefined,
    const_symbol_index: Symbol.Index = undefined,
    text_state: State = .unused,
    const_state: State = .unused,
};

const TlvInitializer = struct {
    symbol_index: Symbol.Index,
    data: []const u8 = &[0]u8{},

    fn deinit(tlv_init: *TlvInitializer, allocator: Allocator) void {
        allocator.free(tlv_init.data);
    }
};

const DeclTable = std.AutoHashMapUnmanaged(InternPool.DeclIndex, DeclMetadata);
const UnnamedConstTable = std.AutoHashMapUnmanaged(InternPool.DeclIndex, std.ArrayListUnmanaged(Symbol.Index));
const AnonDeclTable = std.AutoHashMapUnmanaged(InternPool.Index, DeclMetadata);
const LazySymbolTable = std.AutoArrayHashMapUnmanaged(InternPool.OptionalDeclIndex, LazySymbolMetadata);
const RelocationTable = std.ArrayListUnmanaged(std.ArrayListUnmanaged(Relocation));
const TlvInitializerTable = std.AutoArrayHashMapUnmanaged(Atom.Index, TlvInitializer);

const assert = std.debug.assert;
const builtin = @import("builtin");
const codegen = @import("../../codegen.zig");
const link = @import("../../link.zig");
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const trace = @import("../../tracy.zig").trace;
const std = @import("std");

const Air = @import("../../Air.zig");
const Allocator = std.mem.Allocator;
const Archive = @import("Archive.zig");
const Atom = @import("Atom.zig");
const Dwarf = @import("../Dwarf.zig");
const File = @import("file.zig").File;
const InternPool = @import("../../InternPool.zig");
const Liveness = @import("../../Liveness.zig");
const MachO = @import("../MachO.zig");
const Nlist = Object.Nlist;
const Module = @import("../../Module.zig");
const Object = @import("Object.zig");
const Relocation = @import("Relocation.zig");
const Symbol = @import("Symbol.zig");
const StringTable = @import("../StringTable.zig");
const Type = @import("../../type.zig").Type;
const Value = @import("../../Value.zig");
const ZigObject = @This();
