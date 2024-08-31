//! The main driver of the COFF linker.
//! Currently uses our own implementation for the incremental linker, and falls back to
//! LLD for traditional linking (linking relocatable object files).
//! LLD is also the default linker for LLVM.

/// If this is not null, an object file is created by LLVM and emitted to zcu_object_sub_path.
llvm_object: ?*LlvmObject = null,

base: link.File,
image_base: u64,
subsystem: ?std.Target.SubSystem,
tsaware: bool,
nxcompat: bool,
dynamicbase: bool,
/// TODO this and minor_subsystem_version should be combined into one property and left as
/// default or populated together. They should not be separate fields.
major_subsystem_version: u16,
minor_subsystem_version: u16,
lib_dirs: []const []const u8,
entry: link.File.OpenOptions.Entry,
entry_addr: ?u32,
module_definition_file: ?[]const u8,
pdb_out_path: ?[]const u8,

ptr_width: PtrWidth,
page_size: u32,

objects: std.ArrayListUnmanaged(Object) = .{},

sections: std.MultiArrayList(Section) = .{},
data_directories: [coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES]coff.ImageDataDirectory,

text_section_index: ?u16 = null,
got_section_index: ?u16 = null,
rdata_section_index: ?u16 = null,
data_section_index: ?u16 = null,
reloc_section_index: ?u16 = null,
idata_section_index: ?u16 = null,

locals: std.ArrayListUnmanaged(coff.Symbol) = .{},
globals: std.ArrayListUnmanaged(SymbolWithLoc) = .{},
resolver: std.StringHashMapUnmanaged(u32) = .{},
unresolved: std.AutoArrayHashMapUnmanaged(u32, bool) = .{},
need_got_table: std.AutoHashMapUnmanaged(u32, void) = .{},

locals_free_list: std.ArrayListUnmanaged(u32) = .{},
globals_free_list: std.ArrayListUnmanaged(u32) = .{},

strtab: StringTable = .{},
strtab_offset: ?u32 = null,

temp_strtab: StringTable = .{},

got_table: TableSection(SymbolWithLoc) = .{},

/// A table of ImportTables partitioned by the library name.
/// Key is an offset into the interning string table `temp_strtab`.
import_tables: std.AutoArrayHashMapUnmanaged(u32, ImportTable) = .{},

got_table_count_dirty: bool = true,
got_table_contents_dirty: bool = true,
imports_count_dirty: bool = true,

/// Table of tracked LazySymbols.
lazy_syms: LazySymbolTable = .{},

/// Table of tracked Decls.
decls: DeclTable = .{},

/// List of atoms that are either synthetic or map directly to the Zig source program.
atoms: std.ArrayListUnmanaged(Atom) = .{},

/// Table of atoms indexed by the symbol index.
atom_by_index_table: std.AutoHashMapUnmanaged(u32, Atom.Index) = .{},

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
unnamed_const_atoms: UnnamedConstTable = .{},
anon_decls: AnonDeclTable = .{},

/// A table of relocations indexed by the owning them `Atom`.
/// Note that once we refactor `Atom`'s lifetime and ownership rules,
/// this will be a table indexed by index into the list of Atoms.
relocs: RelocTable = .{},

/// A table of base relocations indexed by the owning them `Atom`.
/// Note that once we refactor `Atom`'s lifetime and ownership rules,
/// this will be a table indexed by index into the list of Atoms.
base_relocs: BaseRelocationTable = .{},

/// Hot-code swapping state.
hot_state: if (is_hot_update_compatible) HotUpdateState else struct {} = .{},

const is_hot_update_compatible = switch (builtin.target.os.tag) {
    .windows => true,
    else => false,
};

const HotUpdateState = struct {
    /// Base address at which the process (image) got loaded.
    /// We need this info to correctly slide pointers when relocating.
    loaded_base_address: ?std.os.windows.HMODULE = null,
};

const DeclTable = std.AutoArrayHashMapUnmanaged(InternPool.DeclIndex, DeclMetadata);
const AnonDeclTable = std.AutoHashMapUnmanaged(InternPool.Index, DeclMetadata);
const RelocTable = std.AutoArrayHashMapUnmanaged(Atom.Index, std.ArrayListUnmanaged(Relocation));
const BaseRelocationTable = std.AutoArrayHashMapUnmanaged(Atom.Index, std.ArrayListUnmanaged(u32));
const UnnamedConstTable = std.AutoArrayHashMapUnmanaged(InternPool.DeclIndex, std.ArrayListUnmanaged(Atom.Index));

const default_file_alignment: u16 = 0x200;
const default_size_of_stack_reserve: u32 = 0x1000000;
const default_size_of_stack_commit: u32 = 0x1000;
const default_size_of_heap_reserve: u32 = 0x100000;
const default_size_of_heap_commit: u32 = 0x1000;

const Section = struct {
    header: coff.SectionHeader,

    last_atom_index: ?Atom.Index = null,

    /// A list of atoms that have surplus capacity. This list can have false
    /// positives, as functions grow and shrink over time, only sometimes being added
    /// or removed from the freelist.
    ///
    /// An atom has surplus capacity when its overcapacity value is greater than
    /// pad_to_ideal(minimum_atom_size). That is, when it has so
    /// much extra capacity, that we could fit a small new symbol in it, itself with
    /// ideal_capacity or more.
    ///
    /// Ideal capacity is defined by size + (size / ideal_factor).
    ///
    /// Overcapacity is measured by actual_capacity - ideal_capacity. Note that
    /// overcapacity can be negative. A simple way to have negative overcapacity is to
    /// allocate a fresh atom, which will have ideal capacity, and then grow it
    /// by 1 byte. It will then have -1 overcapacity.
    free_list: std.ArrayListUnmanaged(Atom.Index) = .{},
};

const LazySymbolTable = std.AutoArrayHashMapUnmanaged(InternPool.OptionalDeclIndex, LazySymbolMetadata);

const LazySymbolMetadata = struct {
    const State = enum { unused, pending_flush, flushed };
    text_atom: Atom.Index = undefined,
    rdata_atom: Atom.Index = undefined,
    text_state: State = .unused,
    rdata_state: State = .unused,
};

const DeclMetadata = struct {
    atom: Atom.Index,
    section: u16,
    /// A list of all exports aliases of this Decl.
    exports: std.ArrayListUnmanaged(u32) = .{},

    fn deinit(m: *DeclMetadata, allocator: Allocator) void {
        m.exports.deinit(allocator);
    }

    fn get_export(m: DeclMetadata, coff_file: *const Coff, name: []const u8) ?u32 {
        for (m.exports.items) |exp| {
            if (mem.eql(u8, name, coff_file.get_symbol_name(.{
                .sym_index = exp,
                .file = null,
            }))) return exp;
        }
        return null;
    }

    fn get_export_ptr(m: *DeclMetadata, coff_file: *Coff, name: []const u8) ?*u32 {
        for (m.exports.items) |*exp| {
            if (mem.eql(u8, name, coff_file.get_symbol_name(.{
                .sym_index = exp.*,
                .file = null,
            }))) return exp;
        }
        return null;
    }
};

pub const PtrWidth = enum {
    p32,
    p64,

    /// Size in bytes.
    pub fn size(pw: PtrWidth) u4 {
        return switch (pw) {
            .p32 => 4,
            .p64 => 8,
        };
    }
};

pub const SymbolWithLoc = struct {
    // Index into the respective symbol table.
    sym_index: u32,

    // null means it's a synthetic global or Zig source.
    file: ?u32 = null,

    pub fn eql(this: SymbolWithLoc, other: SymbolWithLoc) bool {
        if (this.file == null and other.file == null) {
            return this.sym_index == other.sym_index;
        }
        if (this.file != null and other.file != null) {
            return this.sym_index == other.sym_index and this.file.? == other.file.?;
        }
        return false;
    }
};

/// When allocating, the ideal_capacity is calculated by
/// actual_capacity + (actual_capacity / ideal_factor)
const ideal_factor = 3;

/// In order for a slice of bytes to be considered eligible to keep metadata pointing at
/// it as a possible place to put new symbols, it must have enough room for this many bytes
/// (plus extra for reserved capacity).
const minimum_text_block_size = 64;
pub const min_text_capacity = pad_to_ideal(minimum_text_block_size);

pub fn create_empty(
    arena: Allocator,
    comp: *Compilation,
    emit: Compilation.Emit,
    options: link.File.OpenOptions,
) !*Coff {
    const target = comp.root_mod.resolved_target.result;
    assert(target.ofmt == .coff);
    const optimize_mode = comp.root_mod.optimize_mode;
    const output_mode = comp.config.output_mode;
    const link_mode = comp.config.link_mode;
    const use_llvm = comp.config.use_llvm;
    const use_lld = build_options.have_llvm and comp.config.use_lld;

    const ptr_width: PtrWidth = switch (target.ptr_bit_width()) {
        0...32 => .p32,
        33...64 => .p64,
        else => return error.UnsupportedCOFFArchitecture,
    };
    const page_size: u32 = switch (target.cpu.arch) {
        else => 0x1000,
    };

    // If using LLD to link, this code should produce an object file so that it
    // can be passed to LLD.
    // If using LLVM to generate the object file for the zig compilation unit,
    // we need a place to put the object file so that it can be subsequently
    // handled.
    const zcu_object_sub_path = if (!use_lld and !use_llvm)
        null
    else
        try std.fmt.alloc_print(arena, "{s}.obj", .{emit.sub_path});

    const self = try arena.create(Coff);
    self.* = .{
        .base = .{
            .tag = .coff,
            .comp = comp,
            .emit = emit,
            .zcu_object_sub_path = zcu_object_sub_path,
            .stack_size = options.stack_size orelse 16777216,
            .gc_sections = options.gc_sections orelse (optimize_mode != .Debug),
            .print_gc_sections = options.print_gc_sections,
            .allow_shlib_undefined = options.allow_shlib_undefined orelse false,
            .file = null,
            .disable_lld_caching = options.disable_lld_caching,
            .build_id = options.build_id,
            .rpath_list = options.rpath_list,
        },
        .ptr_width = ptr_width,
        .page_size = page_size,

        .data_directories = [1]coff.ImageDataDirectory{.{
            .virtual_address = 0,
            .size = 0,
        }} ** coff.IMAGE_NUMBEROF_DIRECTORY_ENTRIES,

        .image_base = options.image_base orelse switch (output_mode) {
            .Exe => switch (target.cpu.arch) {
                .aarch64 => 0x140000000,
                .x86_64, .x86 => 0x400000,
                else => unreachable,
            },
            .Lib => 0x10000000,
            .Obj => 0,
        },

        // Subsystem depends on the set of public symbol names from linked objects.
        // See LinkerDriver::inferSubsystem from the LLD project for the flow chart.
        .subsystem = options.subsystem,

        .entry = options.entry,

        .tsaware = options.tsaware,
        .nxcompat = options.nxcompat,
        .dynamicbase = options.dynamicbase,
        .major_subsystem_version = options.major_subsystem_version orelse 6,
        .minor_subsystem_version = options.minor_subsystem_version orelse 0,
        .lib_dirs = options.lib_dirs,
        .entry_addr = math.cast(u32, options.entry_addr orelse 0) orelse
            return error.EntryAddressTooBig,
        .module_definition_file = options.module_definition_file,
        .pdb_out_path = options.pdb_out_path,
    };
    if (use_llvm and comp.config.have_zcu) {
        self.llvm_object = try LlvmObject.create(arena, comp);
    }
    errdefer self.base.destroy();

    if (use_lld and (use_llvm or !comp.config.have_zcu)) {
        // LLVM emits the object file (if any); LLD links it into the final product.
        return self;
    }

    // What path should this COFF linker code output to?
    // If using LLD to link, this code should produce an object file so that it
    // can be passed to LLD.
    const sub_path = if (use_lld) zcu_object_sub_path.? else emit.sub_path;
    self.base.file = try emit.directory.handle.create_file(sub_path, .{
        .truncate = true,
        .read = true,
        .mode = link.File.determine_mode(use_lld, output_mode, link_mode),
    });

    assert(self.llvm_object == null);
    const gpa = comp.gpa;

    try self.strtab.buffer.ensure_unused_capacity(gpa, @size_of(u32));
    self.strtab.buffer.append_ntimes_assume_capacity(0, @size_of(u32));

    try self.temp_strtab.buffer.append(gpa, 0);

    // Index 0 is always a null symbol.
    try self.locals.append(gpa, .{
        .name = [_]u8{0} ** 8,
        .value = 0,
        .section_number = .UNDEFINED,
        .type = .{ .base_type = .NULL, .complex_type = .NULL },
        .storage_class = .NULL,
        .number_of_aux_symbols = 0,
    });

    if (self.text_section_index == null) {
        const file_size: u32 = @int_cast(options.program_code_size_hint);
        self.text_section_index = try self.allocate_section(".text", file_size, .{
            .CNT_CODE = 1,
            .MEM_EXECUTE = 1,
            .MEM_READ = 1,
        });
    }

    if (self.got_section_index == null) {
        const file_size = @as(u32, @int_cast(options.symbol_count_hint)) * self.ptr_width.size();
        self.got_section_index = try self.allocate_section(".got", file_size, .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
        });
    }

    if (self.rdata_section_index == null) {
        const file_size: u32 = self.page_size;
        self.rdata_section_index = try self.allocate_section(".rdata", file_size, .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
        });
    }

    if (self.data_section_index == null) {
        const file_size: u32 = self.page_size;
        self.data_section_index = try self.allocate_section(".data", file_size, .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
            .MEM_WRITE = 1,
        });
    }

    if (self.idata_section_index == null) {
        const file_size = @as(u32, @int_cast(options.symbol_count_hint)) * self.ptr_width.size();
        self.idata_section_index = try self.allocate_section(".idata", file_size, .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_READ = 1,
        });
    }

    if (self.reloc_section_index == null) {
        const file_size = @as(u32, @int_cast(options.symbol_count_hint)) * @size_of(coff.BaseRelocation);
        self.reloc_section_index = try self.allocate_section(".reloc", file_size, .{
            .CNT_INITIALIZED_DATA = 1,
            .MEM_DISCARDABLE = 1,
            .MEM_READ = 1,
        });
    }

    if (self.strtab_offset == null) {
        const file_size = @as(u32, @int_cast(self.strtab.buffer.items.len));
        self.strtab_offset = self.find_free_space(file_size, @alignOf(u32)); // 4bytes aligned seems like a good idea here
        log.debug("found strtab free space 0x{x} to 0x{x}", .{ self.strtab_offset.?, self.strtab_offset.? + file_size });
    }

    {
        // We need to find out what the max file offset is according to section headers.
        // Otherwise, we may end up with an COFF binary with file size not matching the final section's
        // offset + it's filesize.
        // TODO I don't like this here one bit
        var max_file_offset: u64 = 0;
        for (self.sections.items(.header)) |header| {
            if (header.pointer_to_raw_data + header.size_of_raw_data > max_file_offset) {
                max_file_offset = header.pointer_to_raw_data + header.size_of_raw_data;
            }
        }
        try self.base.file.?.pwrite_all(&[_]u8{0}, max_file_offset);
    }

    return self;
}

pub fn open(
    arena: Allocator,
    comp: *Compilation,
    emit: Compilation.Emit,
    options: link.File.OpenOptions,
) !*Coff {
    // TODO: restore saved linker state, don't truncate the file, and
    // participate in incremental compilation.
    return create_empty(arena, comp, emit, options);
}

pub fn deinit(self: *Coff) void {
    const gpa = self.base.comp.gpa;

    if (self.llvm_object) |llvm_object| llvm_object.deinit();

    for (self.objects.items) |*object| {
        object.deinit(gpa);
    }
    self.objects.deinit(gpa);

    for (self.sections.items(.free_list)) |*free_list| {
        free_list.deinit(gpa);
    }
    self.sections.deinit(gpa);

    self.atoms.deinit(gpa);
    self.locals.deinit(gpa);
    self.globals.deinit(gpa);

    {
        var it = self.resolver.key_iterator();
        while (it.next()) |key_ptr| {
            gpa.free(key_ptr.*);
        }
        self.resolver.deinit(gpa);
    }

    self.unresolved.deinit(gpa);
    self.locals_free_list.deinit(gpa);
    self.globals_free_list.deinit(gpa);
    self.strtab.deinit(gpa);
    self.temp_strtab.deinit(gpa);
    self.got_table.deinit(gpa);

    for (self.import_tables.values()) |*itab| {
        itab.deinit(gpa);
    }
    self.import_tables.deinit(gpa);

    self.lazy_syms.deinit(gpa);

    for (self.decls.values()) |*metadata| {
        metadata.deinit(gpa);
    }
    self.decls.deinit(gpa);

    self.atom_by_index_table.deinit(gpa);

    for (self.unnamed_const_atoms.values()) |*atoms| {
        atoms.deinit(gpa);
    }
    self.unnamed_const_atoms.deinit(gpa);

    {
        var it = self.anon_decls.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.exports.deinit(gpa);
        }
        self.anon_decls.deinit(gpa);
    }

    for (self.relocs.values()) |*relocs| {
        relocs.deinit(gpa);
    }
    self.relocs.deinit(gpa);

    for (self.base_relocs.values()) |*relocs| {
        relocs.deinit(gpa);
    }
    self.base_relocs.deinit(gpa);
}

fn allocate_section(self: *Coff, name: []const u8, size: u32, flags: coff.SectionHeaderFlags) !u16 {
    const index = @as(u16, @int_cast(self.sections.slice().len));
    const off = self.find_free_space(size, default_file_alignment);
    // Memory is always allocated in sequence
    // TODO: investigate if we can allocate .text last; this way it would never need to grow in memory!
    const vaddr = blk: {
        if (index == 0) break :blk self.page_size;
        const prev_header = self.sections.items(.header)[index - 1];
        break :blk mem.align_forward(u32, prev_header.virtual_address + prev_header.virtual_size, self.page_size);
    };
    // We commit more memory than needed upfront so that we don't have to reallocate too soon.
    const memsz = mem.align_forward(u32, size, self.page_size) * 100;
    log.debug("found {s} free space 0x{x} to 0x{x} (0x{x} - 0x{x})", .{
        name,
        off,
        off + size,
        vaddr,
        vaddr + size,
    });
    var header = coff.SectionHeader{
        .name = undefined,
        .virtual_size = memsz,
        .virtual_address = vaddr,
        .size_of_raw_data = size,
        .pointer_to_raw_data = off,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .flags = flags,
    };
    const gpa = self.base.comp.gpa;
    try self.set_section_name(&header, name);
    try self.sections.append(gpa, .{ .header = header });
    return index;
}

fn grow_section(self: *Coff, sect_id: u32, needed_size: u32) !void {
    const header = &self.sections.items(.header)[sect_id];
    const maybe_last_atom_index = self.sections.items(.last_atom_index)[sect_id];
    const sect_capacity = self.allocated_size(header.pointer_to_raw_data);

    if (needed_size > sect_capacity) {
        const new_offset = self.find_free_space(needed_size, default_file_alignment);
        const current_size = if (maybe_last_atom_index) |last_atom_index| blk: {
            const last_atom = self.get_atom(last_atom_index);
            const sym = last_atom.get_symbol(self);
            break :blk (sym.value + last_atom.size) - header.virtual_address;
        } else 0;
        log.debug("moving {s} from 0x{x} to 0x{x}", .{
            self.get_section_name(header),
            header.pointer_to_raw_data,
            new_offset,
        });
        const amt = try self.base.file.?.copy_range_all(
            header.pointer_to_raw_data,
            self.base.file.?,
            new_offset,
            current_size,
        );
        if (amt != current_size) return error.InputOutput;
        header.pointer_to_raw_data = new_offset;
    }

    const sect_vm_capacity = self.allocated_virtual_size(header.virtual_address);
    if (needed_size > sect_vm_capacity) {
        self.mark_relocs_dirty_by_address(header.virtual_address + header.virtual_size);
        try self.grow_section_virtual_memory(sect_id, needed_size);
    }

    header.virtual_size = @max(header.virtual_size, needed_size);
    header.size_of_raw_data = needed_size;
}

fn grow_section_virtual_memory(self: *Coff, sect_id: u32, needed_size: u32) !void {
    const header = &self.sections.items(.header)[sect_id];
    const increased_size = pad_to_ideal(needed_size);
    const old_aligned_end = header.virtual_address + mem.align_forward(u32, header.virtual_size, self.page_size);
    const new_aligned_end = header.virtual_address + mem.align_forward(u32, increased_size, self.page_size);
    const diff = new_aligned_end - old_aligned_end;
    log.debug("growing {s} in virtual memory by {x}", .{ self.get_section_name(header), diff });

    // TODO: enforce order by increasing VM addresses in self.sections container.
    // This is required by the loader anyhow as far as I can tell.
    for (self.sections.items(.header)[sect_id + 1 ..], 0..) |*next_header, next_sect_id| {
        const maybe_last_atom_index = self.sections.items(.last_atom_index)[sect_id + 1 + next_sect_id];
        next_header.virtual_address += diff;

        if (maybe_last_atom_index) |last_atom_index| {
            var atom_index = last_atom_index;
            while (true) {
                const atom = self.get_atom(atom_index);
                const sym = atom.get_symbol_ptr(self);
                sym.value += diff;

                if (atom.prev_index) |prev_index| {
                    atom_index = prev_index;
                } else break;
            }
        }
    }

    header.virtual_size = increased_size;
}

fn allocate_atom(self: *Coff, atom_index: Atom.Index, new_atom_size: u32, alignment: u32) !u32 {
    const tracy = trace(@src());
    defer tracy.end();

    const atom = self.get_atom(atom_index);
    const sect_id = @int_from_enum(atom.get_symbol(self).section_number) - 1;
    const header = &self.sections.items(.header)[sect_id];
    const free_list = &self.sections.items(.free_list)[sect_id];
    const maybe_last_atom_index = &self.sections.items(.last_atom_index)[sect_id];
    const new_atom_ideal_capacity = if (header.is_code()) pad_to_ideal(new_atom_size) else new_atom_size;

    // We use these to indicate our intention to update metadata, placing the new atom,
    // and possibly removing a free list node.
    // It would be simpler to do it inside the for loop below, but that would cause a
    // problem if an error was returned later in the function. So this action
    // is actually carried out at the end of the function, when errors are no longer possible.
    var atom_placement: ?Atom.Index = null;
    var free_list_removal: ?usize = null;

    // First we look for an appropriately sized free list node.
    // The list is unordered. We'll just take the first thing that works.
    const vaddr = blk: {
        var i: usize = 0;
        while (i < free_list.items.len) {
            const big_atom_index = free_list.items[i];
            const big_atom = self.get_atom(big_atom_index);
            // We now have a pointer to a live atom that has too much capacity.
            // Is it enough that we could fit this new atom?
            const sym = big_atom.get_symbol(self);
            const capacity = big_atom.capacity(self);
            const ideal_capacity = if (header.is_code()) pad_to_ideal(capacity) else capacity;
            const ideal_capacity_end_vaddr = math.add(u32, sym.value, ideal_capacity) catch ideal_capacity;
            const capacity_end_vaddr = sym.value + capacity;
            const new_start_vaddr_unaligned = capacity_end_vaddr - new_atom_ideal_capacity;
            const new_start_vaddr = mem.align_backward(u32, new_start_vaddr_unaligned, alignment);
            if (new_start_vaddr < ideal_capacity_end_vaddr) {
                // Additional bookkeeping here to notice if this free list node
                // should be deleted because the atom that it points to has grown to take up
                // more of the extra capacity.
                if (!big_atom.free_list_eligible(self)) {
                    _ = free_list.swap_remove(i);
                } else {
                    i += 1;
                }
                continue;
            }
            // At this point we know that we will place the new atom here. But the
            // remaining question is whether there is still yet enough capacity left
            // over for there to still be a free list node.
            const remaining_capacity = new_start_vaddr - ideal_capacity_end_vaddr;
            const keep_free_list_node = remaining_capacity >= min_text_capacity;

            // Set up the metadata to be updated, after errors are no longer possible.
            atom_placement = big_atom_index;
            if (!keep_free_list_node) {
                free_list_removal = i;
            }
            break :blk new_start_vaddr;
        } else if (maybe_last_atom_index.*) |last_index| {
            const last = self.get_atom(last_index);
            const last_symbol = last.get_symbol(self);
            const ideal_capacity = if (header.is_code()) pad_to_ideal(last.size) else last.size;
            const ideal_capacity_end_vaddr = last_symbol.value + ideal_capacity;
            const new_start_vaddr = mem.align_forward(u32, ideal_capacity_end_vaddr, alignment);
            atom_placement = last_index;
            break :blk new_start_vaddr;
        } else {
            break :blk mem.align_forward(u32, header.virtual_address, alignment);
        }
    };

    const expand_section = if (atom_placement) |placement_index|
        self.get_atom(placement_index).next_index == null
    else
        true;
    if (expand_section) {
        const needed_size: u32 = (vaddr + new_atom_size) - header.virtual_address;
        try self.grow_section(sect_id, needed_size);
        maybe_last_atom_index.* = atom_index;
    }
    self.get_atom_ptr(atom_index).size = new_atom_size;

    if (atom.prev_index) |prev_index| {
        const prev = self.get_atom_ptr(prev_index);
        prev.next_index = atom.next_index;
    }
    if (atom.next_index) |next_index| {
        const next = self.get_atom_ptr(next_index);
        next.prev_index = atom.prev_index;
    }

    if (atom_placement) |big_atom_index| {
        const big_atom = self.get_atom_ptr(big_atom_index);
        const atom_ptr = self.get_atom_ptr(atom_index);
        atom_ptr.prev_index = big_atom_index;
        atom_ptr.next_index = big_atom.next_index;
        big_atom.next_index = atom_index;
    } else {
        const atom_ptr = self.get_atom_ptr(atom_index);
        atom_ptr.prev_index = null;
        atom_ptr.next_index = null;
    }
    if (free_list_removal) |i| {
        _ = free_list.swap_remove(i);
    }

    return vaddr;
}

pub fn allocate_symbol(self: *Coff) !u32 {
    const gpa = self.base.comp.gpa;
    try self.locals.ensure_unused_capacity(gpa, 1);

    const index = blk: {
        if (self.locals_free_list.pop_or_null()) |index| {
            log.debug("  (reusing symbol index {d})", .{index});
            break :blk index;
        } else {
            log.debug("  (allocating symbol index {d})", .{self.locals.items.len});
            const index = @as(u32, @int_cast(self.locals.items.len));
            _ = self.locals.add_one_assume_capacity();
            break :blk index;
        }
    };

    self.locals.items[index] = .{
        .name = [_]u8{0} ** 8,
        .value = 0,
        .section_number = .UNDEFINED,
        .type = .{ .base_type = .NULL, .complex_type = .NULL },
        .storage_class = .NULL,
        .number_of_aux_symbols = 0,
    };

    return index;
}

fn allocate_global(self: *Coff) !u32 {
    const gpa = self.base.comp.gpa;
    try self.globals.ensure_unused_capacity(gpa, 1);

    const index = blk: {
        if (self.globals_free_list.pop_or_null()) |index| {
            log.debug("  (reusing global index {d})", .{index});
            break :blk index;
        } else {
            log.debug("  (allocating global index {d})", .{self.globals.items.len});
            const index = @as(u32, @int_cast(self.globals.items.len));
            _ = self.globals.add_one_assume_capacity();
            break :blk index;
        }
    };

    self.globals.items[index] = .{
        .sym_index = 0,
        .file = null,
    };

    return index;
}

fn add_got_entry(self: *Coff, target: SymbolWithLoc) !void {
    const gpa = self.base.comp.gpa;
    if (self.got_table.lookup.contains(target)) return;
    const got_index = try self.got_table.allocate_entry(gpa, target);
    try self.write_offset_table_entry(got_index);
    self.got_table_count_dirty = true;
    self.mark_relocs_dirty_by_target(target);
}

pub fn create_atom(self: *Coff) !Atom.Index {
    const gpa = self.base.comp.gpa;
    const atom_index = @as(Atom.Index, @int_cast(self.atoms.items.len));
    const atom = try self.atoms.add_one(gpa);
    const sym_index = try self.allocate_symbol();
    try self.atom_by_index_table.put_no_clobber(gpa, sym_index, atom_index);
    atom.* = .{
        .sym_index = sym_index,
        .file = null,
        .size = 0,
        .prev_index = null,
        .next_index = null,
    };
    log.debug("creating ATOM(%{d}) at index {d}", .{ sym_index, atom_index });
    return atom_index;
}

fn grow_atom(self: *Coff, atom_index: Atom.Index, new_atom_size: u32, alignment: u32) !u32 {
    const atom = self.get_atom(atom_index);
    const sym = atom.get_symbol(self);
    const align_ok = mem.align_backward(u32, sym.value, alignment) == sym.value;
    const need_realloc = !align_ok or new_atom_size > atom.capacity(self);
    if (!need_realloc) return sym.value;
    return self.allocate_atom(atom_index, new_atom_size, alignment);
}

fn shrink_atom(self: *Coff, atom_index: Atom.Index, new_block_size: u32) void {
    _ = self;
    _ = atom_index;
    _ = new_block_size;
    // TODO check the new capacity, and if it crosses the size threshold into a big enough
    // capacity, insert a free list node for it.
}

fn write_atom(self: *Coff, atom_index: Atom.Index, code: []u8) !void {
    const atom = self.get_atom(atom_index);
    const sym = atom.get_symbol(self);
    const section = self.sections.get(@int_from_enum(sym.section_number) - 1);
    const file_offset = section.header.pointer_to_raw_data + sym.value - section.header.virtual_address;

    log.debug("writing atom for symbol {s} at file offset 0x{x} to 0x{x}", .{
        atom.get_name(self),
        file_offset,
        file_offset + code.len,
    });

    const gpa = self.base.comp.gpa;

    // Gather relocs which can be resolved.
    // We need to do this as we will be applying different slide values depending
    // if we are running in hot-code swapping mode or not.
    // TODO: how crazy would it be to try and apply the actual image base of the loaded
    // process for the in-file values rather than the Windows defaults?
    var relocs = std.ArrayList(*Relocation).init(gpa);
    defer relocs.deinit();

    if (self.relocs.get_ptr(atom_index)) |rels| {
        try relocs.ensure_total_capacity_precise(rels.items.len);
        for (rels.items) |*reloc| {
            if (reloc.is_resolvable(self) and reloc.dirty) {
                relocs.append_assume_capacity(reloc);
            }
        }
    }

    if (is_hot_update_compatible) {
        if (self.base.child_pid) |handle| {
            const slide = @int_from_ptr(self.hot_state.loaded_base_address.?);

            const mem_code = try gpa.dupe(u8, code);
            defer gpa.free(mem_code);
            self.resolve_relocs(atom_index, relocs.items, mem_code, slide);

            const vaddr = sym.value + slide;
            const pvaddr = @as(*anyopaque, @ptrFromInt(vaddr));

            log.debug("writing to memory at address {x}", .{vaddr});

            if (build_options.enable_logging) {
                try debug_mem(gpa, handle, pvaddr, mem_code);
            }

            if (section.header.flags.MEM_WRITE == 0) {
                write_mem_protected(handle, pvaddr, mem_code) catch |err| {
                    log.warn("writing to protected memory failed with error: {s}", .{@errorName(err)});
                };
            } else {
                write_mem(handle, pvaddr, mem_code) catch |err| {
                    log.warn("writing to protected memory failed with error: {s}", .{@errorName(err)});
                };
            }
        }
    }

    self.resolve_relocs(atom_index, relocs.items, code, self.image_base);
    try self.base.file.?.pwrite_all(code, file_offset);

    // Now we can mark the relocs as resolved.
    while (relocs.pop_or_null()) |reloc| {
        reloc.dirty = false;
    }
}

fn debug_mem(allocator: Allocator, handle: std.process.Child.Id, pvaddr: std.os.windows.LPVOID, code: []const u8) !void {
    const buffer = try allocator.alloc(u8, code.len);
    defer allocator.free(buffer);
    const memread = try std.os.windows.ReadProcessMemory(handle, pvaddr, buffer);
    log.debug("to write: {x}", .{std.fmt.fmt_slice_hex_lower(code)});
    log.debug("in memory: {x}", .{std.fmt.fmt_slice_hex_lower(memread)});
}

fn write_mem_protected(handle: std.process.Child.Id, pvaddr: std.os.windows.LPVOID, code: []const u8) !void {
    const old_prot = try std.os.windows.VirtualProtectEx(handle, pvaddr, code.len, std.os.windows.PAGE_EXECUTE_WRITECOPY);
    try write_mem(handle, pvaddr, code);
    // TODO: We can probably just set the pages writeable and leave it at that without having to restore the attributes.
    // For that though, we want to track which page has already been modified.
    _ = try std.os.windows.VirtualProtectEx(handle, pvaddr, code.len, old_prot);
}

fn write_mem(handle: std.process.Child.Id, pvaddr: std.os.windows.LPVOID, code: []const u8) !void {
    const amt = try std.os.windows.WriteProcessMemory(handle, pvaddr, code);
    if (amt != code.len) return error.InputOutput;
}

fn write_offset_table_entry(self: *Coff, index: usize) !void {
    const sect_id = self.got_section_index.?;

    if (self.got_table_count_dirty) {
        const needed_size = @as(u32, @int_cast(self.got_table.entries.items.len * self.ptr_width.size()));
        try self.grow_section(sect_id, needed_size);
        self.got_table_count_dirty = false;
    }

    const header = &self.sections.items(.header)[sect_id];
    const entry = self.got_table.entries.items[index];
    const entry_value = self.get_symbol(entry).value;
    const entry_offset = index * self.ptr_width.size();
    const file_offset = header.pointer_to_raw_data + entry_offset;
    const vmaddr = header.virtual_address + entry_offset;

    log.debug("writing GOT entry {d}: @{x} => {x}", .{ index, vmaddr, entry_value + self.image_base });

    switch (self.ptr_width) {
        .p32 => {
            var buf: [4]u8 = undefined;
            mem.write_int(u32, &buf, @as(u32, @int_cast(entry_value + self.image_base)), .little);
            try self.base.file.?.pwrite_all(&buf, file_offset);
        },
        .p64 => {
            var buf: [8]u8 = undefined;
            mem.write_int(u64, &buf, entry_value + self.image_base, .little);
            try self.base.file.?.pwrite_all(&buf, file_offset);
        },
    }

    if (is_hot_update_compatible) {
        if (self.base.child_pid) |handle| {
            const gpa = self.base.comp.gpa;
            const slide = @int_from_ptr(self.hot_state.loaded_base_address.?);
            const actual_vmaddr = vmaddr + slide;
            const pvaddr = @as(*anyopaque, @ptrFromInt(actual_vmaddr));
            log.debug("writing GOT entry to memory at address {x}", .{actual_vmaddr});
            if (build_options.enable_logging) {
                switch (self.ptr_width) {
                    .p32 => {
                        var buf: [4]u8 = undefined;
                        try debug_mem(gpa, handle, pvaddr, &buf);
                    },
                    .p64 => {
                        var buf: [8]u8 = undefined;
                        try debug_mem(gpa, handle, pvaddr, &buf);
                    },
                }
            }

            switch (self.ptr_width) {
                .p32 => {
                    var buf: [4]u8 = undefined;
                    mem.write_int(u32, &buf, @as(u32, @int_cast(entry_value + slide)), .little);
                    write_mem(handle, pvaddr, &buf) catch |err| {
                        log.warn("writing to protected memory failed with error: {s}", .{@errorName(err)});
                    };
                },
                .p64 => {
                    var buf: [8]u8 = undefined;
                    mem.write_int(u64, &buf, entry_value + slide, .little);
                    write_mem(handle, pvaddr, &buf) catch |err| {
                        log.warn("writing to protected memory failed with error: {s}", .{@errorName(err)});
                    };
                },
            }
        }
    }
}

fn mark_relocs_dirty_by_target(self: *Coff, target: SymbolWithLoc) void {
    // TODO: reverse-lookup might come in handy here
    for (self.relocs.values()) |*relocs| {
        for (relocs.items) |*reloc| {
            if (!reloc.target.eql(target)) continue;
            reloc.dirty = true;
        }
    }
}

fn mark_relocs_dirty_by_address(self: *Coff, addr: u32) void {
    const got_moved = blk: {
        const sect_id = self.got_section_index orelse break :blk false;
        break :blk self.sections.items(.header)[sect_id].virtual_address >= addr;
    };

    // TODO: dirty relocations targeting import table if that got moved in memory

    for (self.relocs.values()) |*relocs| {
        for (relocs.items) |*reloc| {
            if (reloc.is_got_indirection()) {
                reloc.dirty = reloc.dirty or got_moved;
            } else {
                const target_vaddr = reloc.get_target_address(self) orelse continue;
                if (target_vaddr >= addr) reloc.dirty = true;
            }
        }
    }

    // TODO: dirty only really affected GOT cells
    for (self.got_table.entries.items) |entry| {
        const target_addr = self.get_symbol(entry).value;
        if (target_addr >= addr) {
            self.got_table_contents_dirty = true;
            break;
        }
    }
}

fn resolve_relocs(self: *Coff, atom_index: Atom.Index, relocs: []*const Relocation, code: []u8, image_base: u64) void {
    log.debug("relocating '{s}'", .{self.get_atom(atom_index).get_name(self)});
    for (relocs) |reloc| {
        reloc.resolve(atom_index, code, image_base, self);
    }
}

pub fn ptrace_attach(self: *Coff, handle: std.process.Child.Id) !void {
    if (!is_hot_update_compatible) return;

    log.debug("attaching to process with handle {*}", .{handle});
    self.hot_state.loaded_base_address = std.os.windows.ProcessBaseAddress(handle) catch |err| {
        log.warn("failed to get base address for the process with error: {s}", .{@errorName(err)});
        return;
    };
}

pub fn ptrace_detach(self: *Coff, handle: std.process.Child.Id) void {
    if (!is_hot_update_compatible) return;

    log.debug("detaching from process with handle {*}", .{handle});
    self.hot_state.loaded_base_address = null;
}

fn free_atom(self: *Coff, atom_index: Atom.Index) void {
    log.debug("free_atom {d}", .{atom_index});

    const gpa = self.base.comp.gpa;

    // Remove any relocs and base relocs associated with this Atom
    Atom.free_relocations(self, atom_index);

    const atom = self.get_atom(atom_index);
    const sym = atom.get_symbol(self);
    const sect_id = @int_from_enum(sym.section_number) - 1;
    const free_list = &self.sections.items(.free_list)[sect_id];
    var already_have_free_list_node = false;
    {
        var i: usize = 0;
        // TODO turn free_list into a hash map
        while (i < free_list.items.len) {
            if (free_list.items[i] == atom_index) {
                _ = free_list.swap_remove(i);
                continue;
            }
            if (free_list.items[i] == atom.prev_index) {
                already_have_free_list_node = true;
            }
            i += 1;
        }
    }

    const maybe_last_atom_index = &self.sections.items(.last_atom_index)[sect_id];
    if (maybe_last_atom_index.*) |last_atom_index| {
        if (last_atom_index == atom_index) {
            if (atom.prev_index) |prev_index| {
                // TODO shrink the section size here
                maybe_last_atom_index.* = prev_index;
            } else {
                maybe_last_atom_index.* = null;
            }
        }
    }

    if (atom.prev_index) |prev_index| {
        const prev = self.get_atom_ptr(prev_index);
        prev.next_index = atom.next_index;

        if (!already_have_free_list_node and prev.*.free_list_eligible(self)) {
            // The free list is heuristics, it doesn't have to be perfect, so we can
            // ignore the OOM here.
            free_list.append(gpa, prev_index) catch {};
        }
    } else {
        self.get_atom_ptr(atom_index).prev_index = null;
    }

    if (atom.next_index) |next_index| {
        self.get_atom_ptr(next_index).prev_index = atom.prev_index;
    } else {
        self.get_atom_ptr(atom_index).next_index = null;
    }

    // Appending to free lists is allowed to fail because the free lists are heuristics based anyway.
    const sym_index = atom.get_symbol_index().?;
    self.locals_free_list.append(gpa, sym_index) catch {};

    // Try freeing GOT atom if this decl had one
    self.got_table.free_entry(gpa, .{ .sym_index = sym_index });

    self.locals.items[sym_index].section_number = .UNDEFINED;
    _ = self.atom_by_index_table.remove(sym_index);
    log.debug("  adding local symbol index {d} to free list", .{sym_index});
    self.get_atom_ptr(atom_index).sym_index = 0;
}

pub fn update_func(self: *Coff, mod: *Module, func_index: InternPool.Index, air: Air, liveness: Liveness) !void {
    if (build_options.skip_non_native and builtin.object_format != .coff) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (self.llvm_object) |llvm_object| {
        return llvm_object.update_func(mod, func_index, air, liveness);
    }
    const tracy = trace(@src());
    defer tracy.end();

    const func = mod.func_info(func_index);
    const decl_index = func.owner_decl;
    const decl = mod.decl_ptr(decl_index);

    const atom_index = try self.get_or_create_atom_for_decl(decl_index);
    self.free_unnamed_consts(decl_index);
    Atom.free_relocations(self, atom_index);

    const gpa = self.base.comp.gpa;
    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const res = try codegen.generate_function(
        &self.base,
        decl.src_loc(mod),
        func_index,
        air,
        liveness,
        &code_buffer,
        .none,
    );
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            func.analysis(&mod.intern_pool).state = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            return;
        },
    };

    try self.update_decl_code(decl_index, code, .FUNCTION);

    // Since we updated the vaddr and the size, each corresponding export
    // symbol also needs to be updated.
    return self.update_exports(mod, .{ .decl_index = decl_index }, mod.get_decl_exports(decl_index));
}

pub fn lower_unnamed_const(self: *Coff, val: Value, decl_index: InternPool.DeclIndex) !u32 {
    const gpa = self.base.comp.gpa;
    const mod = self.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);
    const gop = try self.unnamed_const_atoms.get_or_put(gpa, decl_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    const unnamed_consts = gop.value_ptr;
    const decl_name = try decl.fully_qualified_name(mod);
    const index = unnamed_consts.items.len;
    const sym_name = try std.fmt.alloc_print(gpa, "__unnamed_{}_{d}", .{ decl_name.fmt(&mod.intern_pool), index });
    defer gpa.free(sym_name);
    const ty = val.type_of(mod);
    const atom_index = switch (try self.lower_const(sym_name, val, ty.abi_alignment(mod), self.rdata_section_index.?, decl.src_loc(mod))) {
        .ok => |atom_index| atom_index,
        .fail => |em| {
            decl.analysis = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            log.err("{s}", .{em.msg});
            return error.CodegenFail;
        },
    };
    try unnamed_consts.append(gpa, atom_index);
    return self.get_atom(atom_index).get_symbol_index().?;
}

const LowerConstResult = union(enum) {
    ok: Atom.Index,
    fail: *Module.ErrorMsg,
};

fn lower_const(self: *Coff, name: []const u8, val: Value, required_alignment: InternPool.Alignment, sect_id: u16, src_loc: Module.SrcLoc) !LowerConstResult {
    const gpa = self.base.comp.gpa;

    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const atom_index = try self.create_atom();
    const sym = self.get_atom(atom_index).get_symbol_ptr(self);
    try self.set_symbol_name(sym, name);
    sym.section_number = @as(coff.SectionNumber, @enumFromInt(sect_id + 1));

    const res = try codegen.generate_symbol(&self.base, src_loc, val, &code_buffer, .none, .{
        .parent_atom_index = self.get_atom(atom_index).get_symbol_index().?,
    });
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| return .{ .fail = em },
    };

    const atom = self.get_atom_ptr(atom_index);
    atom.size = @as(u32, @int_cast(code.len));
    atom.get_symbol_ptr(self).value = try self.allocate_atom(
        atom_index,
        atom.size,
        @int_cast(required_alignment.to_byte_units().?),
    );
    errdefer self.free_atom(atom_index);

    log.debug("allocated atom for {s} at 0x{x}", .{ name, atom.get_symbol(self).value });
    log.debug("  (required alignment 0x{x})", .{required_alignment});

    try self.write_atom(atom_index, code);

    return .{ .ok = atom_index };
}

pub fn update_decl(
    self: *Coff,
    mod: *Module,
    decl_index: InternPool.DeclIndex,
) link.File.UpdateDeclError!void {
    if (build_options.skip_non_native and builtin.object_format != .coff) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (self.llvm_object) |llvm_object| return llvm_object.update_decl(mod, decl_index);
    const tracy = trace(@src());
    defer tracy.end();

    const decl = mod.decl_ptr(decl_index);

    if (decl.val.get_extern_func(mod)) |_| {
        return;
    }

    const gpa = self.base.comp.gpa;
    if (decl.is_extern(mod)) {
        // TODO make this part of get_global_symbol
        const variable = decl.get_owned_variable(mod).?;
        const name = decl.name.to_slice(&mod.intern_pool);
        const lib_name = variable.lib_name.to_slice(&mod.intern_pool);
        const global_index = try self.get_global_symbol(name, lib_name);
        try self.need_got_table.put(gpa, global_index, {});
        return;
    }

    const atom_index = try self.get_or_create_atom_for_decl(decl_index);
    Atom.free_relocations(self, atom_index);
    const atom = self.get_atom(atom_index);

    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const decl_val = if (decl.val.get_variable(mod)) |variable| Value.from_interned(variable.init) else decl.val;
    const res = try codegen.generate_symbol(&self.base, decl.src_loc(mod), decl_val, &code_buffer, .none, .{
        .parent_atom_index = atom.get_symbol_index().?,
    });
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            decl.analysis = .codegen_failure;
            try mod.failed_decls.put(mod.gpa, decl_index, em);
            return;
        },
    };

    try self.update_decl_code(decl_index, code, .NULL);

    // Since we updated the vaddr and the size, each corresponding export
    // symbol also needs to be updated.
    return self.update_exports(mod, .{ .decl_index = decl_index }, mod.get_decl_exports(decl_index));
}

fn update_lazy_symbol_atom(
    self: *Coff,
    sym: link.File.LazySymbol,
    atom_index: Atom.Index,
    section_index: u16,
) !void {
    const gpa = self.base.comp.gpa;
    const mod = self.base.comp.module.?;

    var required_alignment: InternPool.Alignment = .none;
    var code_buffer = std.ArrayList(u8).init(gpa);
    defer code_buffer.deinit();

    const name = try std.fmt.alloc_print(gpa, "__lazy_{s}_{}", .{
        @tag_name(sym.kind),
        sym.ty.fmt(mod),
    });
    defer gpa.free(name);

    const atom = self.get_atom_ptr(atom_index);
    const local_sym_index = atom.get_symbol_index().?;

    const src = if (sym.ty.get_owner_decl_or_null(mod)) |owner_decl|
        mod.decl_ptr(owner_decl).src_loc(mod)
    else
        Module.SrcLoc{
            .file_scope = undefined,
            .parent_decl_node = undefined,
            .lazy = .unneeded,
        };
    const res = try codegen.generate_lazy_symbol(
        &self.base,
        src,
        sym,
        &required_alignment,
        &code_buffer,
        .none,
        .{ .parent_atom_index = local_sym_index },
    );
    const code = switch (res) {
        .ok => code_buffer.items,
        .fail => |em| {
            log.err("{s}", .{em.msg});
            return error.CodegenFail;
        },
    };

    const code_len = @as(u32, @int_cast(code.len));
    const symbol = atom.get_symbol_ptr(self);
    try self.set_symbol_name(symbol, name);
    symbol.section_number = @as(coff.SectionNumber, @enumFromInt(section_index + 1));
    symbol.type = .{ .complex_type = .NULL, .base_type = .NULL };

    const vaddr = try self.allocate_atom(atom_index, code_len, @int_cast(required_alignment.to_byte_units() orelse 0));
    errdefer self.free_atom(atom_index);

    log.debug("allocated atom for {s} at 0x{x}", .{ name, vaddr });
    log.debug("  (required alignment 0x{x})", .{required_alignment});

    atom.size = code_len;
    symbol.value = vaddr;

    try self.add_got_entry(.{ .sym_index = local_sym_index });
    try self.write_atom(atom_index, code);
}

pub fn get_or_create_atom_for_lazy_symbol(self: *Coff, sym: link.File.LazySymbol) !Atom.Index {
    const gpa = self.base.comp.gpa;
    const mod = self.base.comp.module.?;
    const gop = try self.lazy_syms.get_or_put(gpa, sym.get_decl(mod));
    errdefer _ = if (!gop.found_existing) self.lazy_syms.pop();
    if (!gop.found_existing) gop.value_ptr.* = .{};
    const metadata: struct { atom: *Atom.Index, state: *LazySymbolMetadata.State } = switch (sym.kind) {
        .code => .{ .atom = &gop.value_ptr.text_atom, .state = &gop.value_ptr.text_state },
        .const_data => .{ .atom = &gop.value_ptr.rdata_atom, .state = &gop.value_ptr.rdata_state },
    };
    switch (metadata.state.*) {
        .unused => metadata.atom.* = try self.create_atom(),
        .pending_flush => return metadata.atom.*,
        .flushed => {},
    }
    metadata.state.* = .pending_flush;
    const atom = metadata.atom.*;
    // anyerror needs to be deferred until flush_module
    if (sym.get_decl(mod) != .none) try self.update_lazy_symbol_atom(sym, atom, switch (sym.kind) {
        .code => self.text_section_index.?,
        .const_data => self.rdata_section_index.?,
    });
    return atom;
}

pub fn get_or_create_atom_for_decl(self: *Coff, decl_index: InternPool.DeclIndex) !Atom.Index {
    const gpa = self.base.comp.gpa;
    const gop = try self.decls.get_or_put(gpa, decl_index);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .atom = try self.create_atom(),
            .section = self.get_decl_output_section(decl_index),
            .exports = .{},
        };
    }
    return gop.value_ptr.atom;
}

fn get_decl_output_section(self: *Coff, decl_index: InternPool.DeclIndex) u16 {
    const decl = self.base.comp.module.?.decl_ptr(decl_index);
    const mod = self.base.comp.module.?;
    const ty = decl.type_of(mod);
    const zig_ty = ty.zig_type_tag(mod);
    const val = decl.val;
    const index: u16 = blk: {
        if (val.is_undef_deep(mod)) {
            // TODO in release-fast and release-small, we should put undef in .bss
            break :blk self.data_section_index.?;
        }

        switch (zig_ty) {
            // TODO: what if this is a function pointer?
            .Fn => break :blk self.text_section_index.?,
            else => {
                if (val.get_variable(mod)) |_| {
                    break :blk self.data_section_index.?;
                }
                break :blk self.rdata_section_index.?;
            },
        }
    };
    return index;
}

fn update_decl_code(self: *Coff, decl_index: InternPool.DeclIndex, code: []u8, complex_type: coff.ComplexType) !void {
    const mod = self.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);

    const decl_name = try decl.fully_qualified_name(mod);

    log.debug("update_decl_code {}{*}", .{ decl_name.fmt(&mod.intern_pool), decl });
    const required_alignment: u32 = @int_cast(decl.get_alignment(mod).to_byte_units() orelse 0);

    const decl_metadata = self.decls.get(decl_index).?;
    const atom_index = decl_metadata.atom;
    const atom = self.get_atom(atom_index);
    const sym_index = atom.get_symbol_index().?;
    const sect_index = decl_metadata.section;
    const code_len = @as(u32, @int_cast(code.len));

    if (atom.size != 0) {
        const sym = atom.get_symbol_ptr(self);
        try self.set_symbol_name(sym, decl_name.to_slice(&mod.intern_pool));
        sym.section_number = @as(coff.SectionNumber, @enumFromInt(sect_index + 1));
        sym.type = .{ .complex_type = complex_type, .base_type = .NULL };

        const capacity = atom.capacity(self);
        const need_realloc = code.len > capacity or !mem.is_aligned_generic(u64, sym.value, required_alignment);
        if (need_realloc) {
            const vaddr = try self.grow_atom(atom_index, code_len, required_alignment);
            log.debug("growing {} from 0x{x} to 0x{x}", .{ decl_name.fmt(&mod.intern_pool), sym.value, vaddr });
            log.debug("  (required alignment 0x{x}", .{required_alignment});

            if (vaddr != sym.value) {
                sym.value = vaddr;
                log.debug("  (updating GOT entry)", .{});
                const got_entry_index = self.got_table.lookup.get(.{ .sym_index = sym_index }).?;
                try self.write_offset_table_entry(got_entry_index);
                self.mark_relocs_dirty_by_target(.{ .sym_index = sym_index });
            }
        } else if (code_len < atom.size) {
            self.shrink_atom(atom_index, code_len);
        }
        self.get_atom_ptr(atom_index).size = code_len;
    } else {
        const sym = atom.get_symbol_ptr(self);
        try self.set_symbol_name(sym, decl_name.to_slice(&mod.intern_pool));
        sym.section_number = @as(coff.SectionNumber, @enumFromInt(sect_index + 1));
        sym.type = .{ .complex_type = complex_type, .base_type = .NULL };

        const vaddr = try self.allocate_atom(atom_index, code_len, required_alignment);
        errdefer self.free_atom(atom_index);
        log.debug("allocated atom for {} at 0x{x}", .{ decl_name.fmt(&mod.intern_pool), vaddr });
        self.get_atom_ptr(atom_index).size = code_len;
        sym.value = vaddr;

        try self.add_got_entry(.{ .sym_index = sym_index });
    }

    try self.write_atom(atom_index, code);
}

fn free_unnamed_consts(self: *Coff, decl_index: InternPool.DeclIndex) void {
    const gpa = self.base.comp.gpa;
    const unnamed_consts = self.unnamed_const_atoms.get_ptr(decl_index) orelse return;
    for (unnamed_consts.items) |atom_index| {
        self.free_atom(atom_index);
    }
    unnamed_consts.clear_and_free(gpa);
}

pub fn free_decl(self: *Coff, decl_index: InternPool.DeclIndex) void {
    if (self.llvm_object) |llvm_object| return llvm_object.free_decl(decl_index);

    const gpa = self.base.comp.gpa;
    const mod = self.base.comp.module.?;
    const decl = mod.decl_ptr(decl_index);

    log.debug("free_decl {*}", .{decl});

    if (self.decls.fetch_ordered_remove(decl_index)) |const_kv| {
        var kv = const_kv;
        self.free_atom(kv.value.atom);
        self.free_unnamed_consts(decl_index);
        kv.value.exports.deinit(gpa);
    }
}

pub fn update_exports(
    self: *Coff,
    mod: *Module,
    exported: Module.Exported,
    exports: []const *Module.Export,
) link.File.UpdateExportsError!void {
    if (build_options.skip_non_native and builtin.object_format != .coff) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }

    const ip = &mod.intern_pool;
    const comp = self.base.comp;
    const target = comp.root_mod.resolved_target.result;

    if (comp.config.use_llvm) {
        // Even in the case of LLVM, we need to notice certain exported symbols in order to
        // detect the default subsystem.
        for (exports) |exp| {
            const exported_decl_index = switch (exp.exported) {
                .decl_index => |i| i,
                .value => continue,
            };
            const exported_decl = mod.decl_ptr(exported_decl_index);
            if (exported_decl.get_owned_function(mod) == null) continue;
            const winapi_cc = switch (target.cpu.arch) {
                .x86 => std.builtin.CallingConvention.Stdcall,
                else => std.builtin.CallingConvention.C,
            };
            const decl_cc = exported_decl.type_of(mod).fn_calling_convention(mod);
            if (decl_cc == .C and exp.opts.name.eql_slice("main", ip) and comp.config.link_libc) {
                mod.stage1_flags.have_c_main = true;
            } else if (decl_cc == winapi_cc and target.os.tag == .windows) {
                if (exp.opts.name.eql_slice("WinMain", ip)) {
                    mod.stage1_flags.have_winmain = true;
                } else if (exp.opts.name.eql_slice("wWinMain", ip)) {
                    mod.stage1_flags.have_wwinmain = true;
                } else if (exp.opts.name.eql_slice("WinMainCRTStartup", ip)) {
                    mod.stage1_flags.have_winmain_crt_startup = true;
                } else if (exp.opts.name.eql_slice("w_win_main_crtstartup", ip)) {
                    mod.stage1_flags.have_wwinmain_crt_startup = true;
                } else if (exp.opts.name.eql_slice("DllMainCRTStartup", ip)) {
                    mod.stage1_flags.have_dllmain_crt_startup = true;
                }
            }
        }
    }

    if (self.llvm_object) |llvm_object| return llvm_object.update_exports(mod, exported, exports);

    const gpa = comp.gpa;

    const metadata = switch (exported) {
        .decl_index => |decl_index| blk: {
            _ = try self.get_or_create_atom_for_decl(decl_index);
            break :blk self.decls.get_ptr(decl_index).?;
        },
        .value => |value| self.anon_decls.get_ptr(value) orelse blk: {
            const first_exp = exports[0];
            const res = try self.lower_anon_decl(value, .none, first_exp.get_src_loc(mod));
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
    const atom_index = metadata.atom;
    const atom = self.get_atom(atom_index);

    for (exports) |exp| {
        log.debug("adding new export '{}'", .{exp.opts.name.fmt(&mod.intern_pool)});

        if (exp.opts.section.to_slice(&mod.intern_pool)) |section_name| {
            if (!mem.eql(u8, section_name, ".text")) {
                try mod.failed_exports.put_no_clobber(gpa, exp, try Module.ErrorMsg.create(
                    gpa,
                    exp.get_src_loc(mod),
                    "Unimplemented: ExportOptions.section",
                    .{},
                ));
                continue;
            }
        }

        if (exp.opts.linkage == .link_once) {
            try mod.failed_exports.put_no_clobber(gpa, exp, try Module.ErrorMsg.create(
                gpa,
                exp.get_src_loc(mod),
                "Unimplemented: GlobalLinkage.link_once",
                .{},
            ));
            continue;
        }

        const exp_name = exp.opts.name.to_slice(&mod.intern_pool);
        const sym_index = metadata.get_export(self, exp_name) orelse blk: {
            const sym_index = if (self.get_global_index(exp_name)) |global_index| ind: {
                const global = self.globals.items[global_index];
                // TODO this is just plain wrong as it all should happen in a single `resolve_symbols`
                // pass. This will go away once we abstact away Zig's incremental compilation into
                // its own module.
                if (global.file == null and self.get_symbol(global).section_number == .UNDEFINED) {
                    _ = self.unresolved.swap_remove(global_index);
                    break :ind global.sym_index;
                }
                break :ind try self.allocate_symbol();
            } else try self.allocate_symbol();
            try metadata.exports.append(gpa, sym_index);
            break :blk sym_index;
        };
        const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
        const sym = self.get_symbol_ptr(sym_loc);
        try self.set_symbol_name(sym, exp_name);
        sym.value = atom.get_symbol(self).value;
        sym.section_number = @as(coff.SectionNumber, @enumFromInt(metadata.section + 1));
        sym.type = atom.get_symbol(self).type;

        switch (exp.opts.linkage) {
            .strong => {
                sym.storage_class = .EXTERNAL;
            },
            .internal => @panic("TODO Internal"),
            .weak => @panic("TODO WeakExternal"),
            else => unreachable,
        }

        try self.resolve_global_symbol(sym_loc);
    }
}

pub fn delete_decl_export(
    self: *Coff,
    decl_index: InternPool.DeclIndex,
    name: InternPool.NullTerminatedString,
) void {
    if (self.llvm_object) |_| return;
    const metadata = self.decls.get_ptr(decl_index) orelse return;
    const mod = self.base.comp.module.?;
    const name_slice = name.to_slice(&mod.intern_pool);
    const sym_index = metadata.get_export_ptr(self, name_slice) orelse return;

    const gpa = self.base.comp.gpa;
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index.*, .file = null };
    const sym = self.get_symbol_ptr(sym_loc);
    log.debug("deleting export '{}'", .{name.fmt(&mod.intern_pool)});
    assert(sym.storage_class == .EXTERNAL and sym.section_number != .UNDEFINED);
    sym.* = .{
        .name = [_]u8{0} ** 8,
        .value = 0,
        .section_number = .UNDEFINED,
        .type = .{ .base_type = .NULL, .complex_type = .NULL },
        .storage_class = .NULL,
        .number_of_aux_symbols = 0,
    };
    self.locals_free_list.append(gpa, sym_index.*) catch {};

    if (self.resolver.fetch_remove(name_slice)) |entry| {
        defer gpa.free(entry.key);
        self.globals_free_list.append(gpa, entry.value) catch {};
        self.globals.items[entry.value] = .{
            .sym_index = 0,
            .file = null,
        };
    }

    sym_index.* = 0;
}

fn resolve_global_symbol(self: *Coff, current: SymbolWithLoc) !void {
    const gpa = self.base.comp.gpa;
    const sym = self.get_symbol(current);
    const sym_name = self.get_symbol_name(current);

    const gop = try self.get_or_put_global_ptr(sym_name);
    if (!gop.found_existing) {
        gop.value_ptr.* = current;
        if (sym.section_number == .UNDEFINED) {
            try self.unresolved.put_no_clobber(gpa, self.get_global_index(sym_name).?, false);
        }
        return;
    }

    log.debug("TODO finish resolveGlobalSymbols implementation", .{});

    if (sym.section_number == .UNDEFINED) return;

    _ = self.unresolved.swap_remove(self.get_global_index(sym_name).?);

    gop.value_ptr.* = current;
}

pub fn flush(self: *Coff, arena: Allocator, prog_node: std.Progress.Node) link.File.FlushError!void {
    const comp = self.base.comp;
    const use_lld = build_options.have_llvm and comp.config.use_lld;
    if (use_lld) {
        return lld.link_with_lld(self, arena, prog_node);
    }
    switch (comp.config.output_mode) {
        .Exe, .Obj => return self.flush_module(arena, prog_node),
        .Lib => return error.TODOImplementWritingLibFiles,
    }
}

pub fn flush_module(self: *Coff, arena: Allocator, prog_node: std.Progress.Node) link.File.FlushError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const comp = self.base.comp;
    const gpa = comp.gpa;

    if (self.llvm_object) |llvm_object| {
        try self.base.emit_llvm_object(arena, llvm_object, prog_node);
        return;
    }

    const sub_prog_node = prog_node.start("COFF Flush", 0);
    defer sub_prog_node.end();

    const module = comp.module orelse return error.LinkingWithoutZigSourceUnimplemented;

    if (self.lazy_syms.get_ptr(.none)) |metadata| {
        // Most lazy symbols can be updated on first use, but
        // anyerror needs to wait for everything to be flushed.
        if (metadata.text_state != .unused) self.update_lazy_symbol_atom(
            link.File.LazySymbol.init_decl(.code, null, module),
            metadata.text_atom,
            self.text_section_index.?,
        ) catch |err| return switch (err) {
            error.CodegenFail => error.FlushFailure,
            else => |e| e,
        };
        if (metadata.rdata_state != .unused) self.update_lazy_symbol_atom(
            link.File.LazySymbol.init_decl(.const_data, null, module),
            metadata.rdata_atom,
            self.rdata_section_index.?,
        ) catch |err| return switch (err) {
            error.CodegenFail => error.FlushFailure,
            else => |e| e,
        };
    }
    for (self.lazy_syms.values()) |*metadata| {
        if (metadata.text_state != .unused) metadata.text_state = .flushed;
        if (metadata.rdata_state != .unused) metadata.rdata_state = .flushed;
    }

    {
        var it = self.need_got_table.iterator();
        while (it.next()) |entry| {
            const global = self.globals.items[entry.key_ptr.*];
            try self.add_got_entry(global);
        }
    }

    while (self.unresolved.pop_or_null()) |entry| {
        assert(entry.value);
        const global = self.globals.items[entry.key];
        const sym = self.get_symbol(global);
        const res = try self.import_tables.get_or_put(gpa, sym.value);
        const itable = res.value_ptr;
        if (!res.found_existing) {
            itable.* = .{};
        }
        if (itable.lookup.contains(global)) continue;
        // TODO: we could technically write the pointer placeholder for to-be-bound import here,
        // but since this happens in flush, there is currently no point.
        _ = try itable.add_import(gpa, global);
        self.imports_count_dirty = true;
    }

    try self.write_import_tables();

    for (self.relocs.keys(), self.relocs.values()) |atom_index, relocs| {
        const needs_update = for (relocs.items) |reloc| {
            if (reloc.dirty) break true;
        } else false;

        if (!needs_update) continue;

        const atom = self.get_atom(atom_index);
        const sym = atom.get_symbol(self);
        const section = self.sections.get(@int_from_enum(sym.section_number) - 1).header;
        const file_offset = section.pointer_to_raw_data + sym.value - section.virtual_address;

        var code = std.ArrayList(u8).init(gpa);
        defer code.deinit();
        try code.resize(math.cast(usize, atom.size) orelse return error.Overflow);
        assert(atom.size > 0);

        const amt = try self.base.file.?.pread_all(code.items, file_offset);
        if (amt != code.items.len) return error.InputOutput;

        try self.write_atom(atom_index, code.items);
    }

    // Update GOT if it got moved in memory.
    if (self.got_table_contents_dirty) {
        for (self.got_table.entries.items, 0..) |entry, i| {
            if (!self.got_table.lookup.contains(entry)) continue;
            // TODO: write all in one go rather than incrementally.
            try self.write_offset_table_entry(i);
        }
        self.got_table_contents_dirty = false;
    }

    try self.write_base_relocations();

    if (self.get_entry_point()) |entry_sym_loc| {
        self.entry_addr = self.get_symbol(entry_sym_loc).value;
    }

    if (build_options.enable_logging) {
        self.log_symtab();
        self.log_import_tables();
    }

    try self.write_strtab();
    try self.write_data_directories_headers();
    try self.write_section_headers();

    if (self.entry_addr == null and comp.config.output_mode == .Exe) {
        log.debug("flushing. no_entry_point_found = true\n", .{});
        comp.link_error_flags.no_entry_point_found = true;
    } else {
        log.debug("flushing. no_entry_point_found = false\n", .{});
        comp.link_error_flags.no_entry_point_found = false;
        try self.write_header();
    }

    assert(!self.imports_count_dirty);
}

pub fn get_decl_vaddr(self: *Coff, decl_index: InternPool.DeclIndex, reloc_info: link.File.RelocInfo) !u64 {
    assert(self.llvm_object == null);

    const this_atom_index = try self.get_or_create_atom_for_decl(decl_index);
    const sym_index = self.get_atom(this_atom_index).get_symbol_index().?;
    const atom_index = self.get_atom_index_for_symbol(.{ .sym_index = reloc_info.parent_atom_index, .file = null }).?;
    const target = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    try Atom.add_relocation(self, atom_index, .{
        .type = .direct,
        .target = target,
        .offset = @as(u32, @int_cast(reloc_info.offset)),
        .addend = reloc_info.addend,
        .pcrel = false,
        .length = 3,
    });
    try Atom.add_base_relocation(self, atom_index, @as(u32, @int_cast(reloc_info.offset)));

    return 0;
}

pub fn lower_anon_decl(
    self: *Coff,
    decl_val: InternPool.Index,
    explicit_alignment: InternPool.Alignment,
    src_loc: Module.SrcLoc,
) !codegen.Result {
    const gpa = self.base.comp.gpa;
    const mod = self.base.comp.module.?;
    const ty = Type.from_interned(mod.intern_pool.type_of(decl_val));
    const decl_alignment = switch (explicit_alignment) {
        .none => ty.abi_alignment(mod),
        else => explicit_alignment,
    };
    if (self.anon_decls.get(decl_val)) |metadata| {
        const existing_addr = self.get_atom(metadata.atom).get_symbol(self).value;
        if (decl_alignment.check(existing_addr))
            return .ok;
    }

    const val = Value.from_interned(decl_val);
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.buf_print(&name_buf, "__anon_{d}", .{
        @int_from_enum(decl_val),
    }) catch unreachable;
    const res = self.lower_const(
        name,
        val,
        decl_alignment,
        self.rdata_section_index.?,
        src_loc,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |e| return .{ .fail = try Module.ErrorMsg.create(
            gpa,
            src_loc,
            "lower_anon_decl failed with error: {s}",
            .{@errorName(e)},
        ) },
    };
    const atom_index = switch (res) {
        .ok => |atom_index| atom_index,
        .fail => |em| return .{ .fail = em },
    };
    try self.anon_decls.put(gpa, decl_val, .{ .atom = atom_index, .section = self.rdata_section_index.? });
    return .ok;
}

pub fn get_anon_decl_vaddr(self: *Coff, decl_val: InternPool.Index, reloc_info: link.File.RelocInfo) !u64 {
    assert(self.llvm_object == null);

    const this_atom_index = self.anon_decls.get(decl_val).?.atom;
    const sym_index = self.get_atom(this_atom_index).get_symbol_index().?;
    const atom_index = self.get_atom_index_for_symbol(.{ .sym_index = reloc_info.parent_atom_index, .file = null }).?;
    const target = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    try Atom.add_relocation(self, atom_index, .{
        .type = .direct,
        .target = target,
        .offset = @as(u32, @int_cast(reloc_info.offset)),
        .addend = reloc_info.addend,
        .pcrel = false,
        .length = 3,
    });
    try Atom.add_base_relocation(self, atom_index, @as(u32, @int_cast(reloc_info.offset)));

    return 0;
}

pub fn get_global_symbol(self: *Coff, name: []const u8, lib_name_name: ?[]const u8) !u32 {
    const gop = try self.get_or_put_global_ptr(name);
    const global_index = self.get_global_index(name).?;

    if (gop.found_existing) {
        return global_index;
    }

    const sym_index = try self.allocate_symbol();
    const sym_loc = SymbolWithLoc{ .sym_index = sym_index, .file = null };
    gop.value_ptr.* = sym_loc;

    const gpa = self.base.comp.gpa;
    const sym = self.get_symbol_ptr(sym_loc);
    try self.set_symbol_name(sym, name);
    sym.storage_class = .EXTERNAL;

    if (lib_name_name) |lib_name| {
        // We repurpose the 'value' of the Symbol struct to store an offset into
        // temporary string table where we will store the library name hint.
        sym.value = try self.temp_strtab.insert(gpa, lib_name);
    }

    try self.unresolved.put_no_clobber(gpa, global_index, true);

    return global_index;
}

pub fn update_decl_line_number(self: *Coff, module: *Module, decl_index: InternPool.DeclIndex) !void {
    _ = self;
    _ = module;
    _ = decl_index;
    log.debug("TODO implement update_decl_line_number", .{});
}

/// TODO: note if we need to rewrite base relocations by dirtying any of the entries in the global table
/// TODO: note that .ABSOLUTE is used as padding within each block; we could use this fact to do
///       incremental updates and writes into the table instead of doing it all at once
fn write_base_relocations(self: *Coff) !void {
    const gpa = self.base.comp.gpa;

    var page_table = std.AutoHashMap(u32, std.ArrayList(coff.BaseRelocation)).init(gpa);
    defer {
        var it = page_table.value_iterator();
        while (it.next()) |inner| {
            inner.deinit();
        }
        page_table.deinit();
    }

    {
        var it = self.base_relocs.iterator();
        while (it.next()) |entry| {
            const atom_index = entry.key_ptr.*;
            const atom = self.get_atom(atom_index);
            const sym = atom.get_symbol(self);
            const offsets = entry.value_ptr.*;

            for (offsets.items) |offset| {
                const rva = sym.value + offset;
                const page = mem.align_backward(u32, rva, self.page_size);
                const gop = try page_table.get_or_put(page);
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.ArrayList(coff.BaseRelocation).init(gpa);
                }
                try gop.value_ptr.append(.{
                    .offset = @as(u12, @int_cast(rva - page)),
                    .type = .DIR64,
                });
            }
        }

        {
            const header = &self.sections.items(.header)[self.got_section_index.?];
            for (self.got_table.entries.items, 0..) |entry, index| {
                if (!self.got_table.lookup.contains(entry)) continue;

                const sym = self.get_symbol(entry);
                if (sym.section_number == .UNDEFINED) continue;

                const rva = @as(u32, @int_cast(header.virtual_address + index * self.ptr_width.size()));
                const page = mem.align_backward(u32, rva, self.page_size);
                const gop = try page_table.get_or_put(page);
                if (!gop.found_existing) {
                    gop.value_ptr.* = std.ArrayList(coff.BaseRelocation).init(gpa);
                }
                try gop.value_ptr.append(.{
                    .offset = @as(u12, @int_cast(rva - page)),
                    .type = .DIR64,
                });
            }
        }
    }

    // Sort pages by address.
    var pages = try std.ArrayList(u32).init_capacity(gpa, page_table.count());
    defer pages.deinit();
    {
        var it = page_table.key_iterator();
        while (it.next()) |page| {
            pages.append_assume_capacity(page.*);
        }
    }
    mem.sort(u32, pages.items, {}, std.sort.asc(u32));

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    for (pages.items) |page| {
        const entries = page_table.get_ptr(page).?;
        // Pad to required 4byte alignment
        if (!mem.is_aligned_generic(
            usize,
            entries.items.len * @size_of(coff.BaseRelocation),
            @size_of(u32),
        )) {
            try entries.append(.{
                .offset = 0,
                .type = .ABSOLUTE,
            });
        }

        const block_size = @as(
            u32,
            @int_cast(entries.items.len * @size_of(coff.BaseRelocation) + @size_of(coff.BaseRelocationDirectoryEntry)),
        );
        try buffer.ensure_unused_capacity(block_size);
        buffer.append_slice_assume_capacity(mem.as_bytes(&coff.BaseRelocationDirectoryEntry{
            .page_rva = page,
            .block_size = block_size,
        }));
        buffer.append_slice_assume_capacity(mem.slice_as_bytes(entries.items));
    }

    const header = &self.sections.items(.header)[self.reloc_section_index.?];
    const needed_size = @as(u32, @int_cast(buffer.items.len));
    try self.grow_section(self.reloc_section_index.?, needed_size);

    try self.base.file.?.pwrite_all(buffer.items, header.pointer_to_raw_data);

    self.data_directories[@int_from_enum(coff.DirectoryEntry.BASERELOC)] = .{
        .virtual_address = header.virtual_address,
        .size = needed_size,
    };
}

fn write_import_tables(self: *Coff) !void {
    if (self.idata_section_index == null) return;
    if (!self.imports_count_dirty) return;

    const gpa = self.base.comp.gpa;

    const ext = ".dll";
    const header = &self.sections.items(.header)[self.idata_section_index.?];

    // Calculate needed size
    var iat_size: u32 = 0;
    var dir_table_size: u32 = @size_of(coff.ImportDirectoryEntry); // sentinel
    var lookup_table_size: u32 = 0;
    var names_table_size: u32 = 0;
    var dll_names_size: u32 = 0;
    for (self.import_tables.keys(), 0..) |off, i| {
        const lib_name = self.temp_strtab.get_assume_exists(off);
        const itable = self.import_tables.values()[i];
        iat_size += itable.size() + 8;
        dir_table_size += @size_of(coff.ImportDirectoryEntry);
        lookup_table_size += @as(u32, @int_cast(itable.entries.items.len + 1)) * @size_of(coff.ImportLookupEntry64.ByName);
        for (itable.entries.items) |entry| {
            const sym_name = self.get_symbol_name(entry);
            names_table_size += 2 + mem.align_forward(u32, @as(u32, @int_cast(sym_name.len + 1)), 2);
        }
        dll_names_size += @as(u32, @int_cast(lib_name.len + ext.len + 1));
    }

    const needed_size = iat_size + dir_table_size + lookup_table_size + names_table_size + dll_names_size;
    try self.grow_section(self.idata_section_index.?, needed_size);

    // Do the actual writes
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensure_total_capacity_precise(needed_size);
    buffer.resize(needed_size) catch unreachable;

    const dir_header_size = @size_of(coff.ImportDirectoryEntry);
    const lookup_entry_size = @size_of(coff.ImportLookupEntry64.ByName);

    var iat_offset: u32 = 0;
    var dir_table_offset = iat_size;
    var lookup_table_offset = dir_table_offset + dir_table_size;
    var names_table_offset = lookup_table_offset + lookup_table_size;
    var dll_names_offset = names_table_offset + names_table_size;
    for (self.import_tables.keys(), 0..) |off, i| {
        const lib_name = self.temp_strtab.get_assume_exists(off);
        const itable = self.import_tables.values()[i];

        // Lookup table header
        const lookup_header = coff.ImportDirectoryEntry{
            .import_lookup_table_rva = header.virtual_address + lookup_table_offset,
            .time_date_stamp = 0,
            .forwarder_chain = 0,
            .name_rva = header.virtual_address + dll_names_offset,
            .import_address_table_rva = header.virtual_address + iat_offset,
        };
        @memcpy(buffer.items[dir_table_offset..][0..@size_of(coff.ImportDirectoryEntry)], mem.as_bytes(&lookup_header));
        dir_table_offset += dir_header_size;

        for (itable.entries.items) |entry| {
            const import_name = self.get_symbol_name(entry);

            // IAT and lookup table entry
            const lookup = coff.ImportLookupEntry64.ByName{ .name_table_rva = @as(u31, @int_cast(header.virtual_address + names_table_offset)) };
            @memcpy(
                buffer.items[iat_offset..][0..@size_of(coff.ImportLookupEntry64.ByName)],
                mem.as_bytes(&lookup),
            );
            iat_offset += lookup_entry_size;
            @memcpy(
                buffer.items[lookup_table_offset..][0..@size_of(coff.ImportLookupEntry64.ByName)],
                mem.as_bytes(&lookup),
            );
            lookup_table_offset += lookup_entry_size;

            // Names table entry
            mem.write_int(u16, buffer.items[names_table_offset..][0..2], 0, .little); // Hint set to 0 until we learn how to parse DLLs
            names_table_offset += 2;
            @memcpy(buffer.items[names_table_offset..][0..import_name.len], import_name);
            names_table_offset += @as(u32, @int_cast(import_name.len));
            buffer.items[names_table_offset] = 0;
            names_table_offset += 1;
            if (!mem.is_aligned_generic(usize, names_table_offset, @size_of(u16))) {
                buffer.items[names_table_offset] = 0;
                names_table_offset += 1;
            }
        }

        // IAT sentinel
        mem.write_int(u64, buffer.items[iat_offset..][0..lookup_entry_size], 0, .little);
        iat_offset += 8;

        // Lookup table sentinel
        @memcpy(
            buffer.items[lookup_table_offset..][0..@size_of(coff.ImportLookupEntry64.ByName)],
            mem.as_bytes(&coff.ImportLookupEntry64.ByName{ .name_table_rva = 0 }),
        );
        lookup_table_offset += lookup_entry_size;

        // DLL name
        @memcpy(buffer.items[dll_names_offset..][0..lib_name.len], lib_name);
        dll_names_offset += @as(u32, @int_cast(lib_name.len));
        @memcpy(buffer.items[dll_names_offset..][0..ext.len], ext);
        dll_names_offset += @as(u32, @int_cast(ext.len));
        buffer.items[dll_names_offset] = 0;
        dll_names_offset += 1;
    }

    // Sentinel
    const lookup_header = coff.ImportDirectoryEntry{
        .import_lookup_table_rva = 0,
        .time_date_stamp = 0,
        .forwarder_chain = 0,
        .name_rva = 0,
        .import_address_table_rva = 0,
    };
    @memcpy(
        buffer.items[dir_table_offset..][0..@size_of(coff.ImportDirectoryEntry)],
        mem.as_bytes(&lookup_header),
    );
    dir_table_offset += dir_header_size;

    assert(dll_names_offset == needed_size);

    try self.base.file.?.pwrite_all(buffer.items, header.pointer_to_raw_data);

    self.data_directories[@int_from_enum(coff.DirectoryEntry.IMPORT)] = .{
        .virtual_address = header.virtual_address + iat_size,
        .size = dir_table_size,
    };
    self.data_directories[@int_from_enum(coff.DirectoryEntry.IAT)] = .{
        .virtual_address = header.virtual_address,
        .size = iat_size,
    };

    self.imports_count_dirty = false;
}

fn write_strtab(self: *Coff) !void {
    if (self.strtab_offset == null) return;

    const allocated_size = self.allocated_size(self.strtab_offset.?);
    const needed_size = @as(u32, @int_cast(self.strtab.buffer.items.len));

    if (needed_size > allocated_size) {
        self.strtab_offset = null;
        self.strtab_offset = @as(u32, @int_cast(self.find_free_space(needed_size, @alignOf(u32))));
    }

    log.debug("writing strtab from 0x{x} to 0x{x}", .{ self.strtab_offset.?, self.strtab_offset.? + needed_size });

    const gpa = self.base.comp.gpa;
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    try buffer.ensure_total_capacity_precise(needed_size);
    buffer.append_slice_assume_capacity(self.strtab.buffer.items);
    // Here, we do a trick in that we do not commit the size of the strtab to strtab buffer, instead
    // we write the length of the strtab to a temporary buffer that goes to file.
    mem.write_int(u32, buffer.items[0..4], @as(u32, @int_cast(self.strtab.buffer.items.len)), .little);

    try self.base.file.?.pwrite_all(buffer.items, self.strtab_offset.?);
}

fn write_section_headers(self: *Coff) !void {
    const offset = self.get_section_headers_offset();
    try self.base.file.?.pwrite_all(mem.slice_as_bytes(self.sections.items(.header)), offset);
}

fn write_data_directories_headers(self: *Coff) !void {
    const offset = self.get_data_directory_headers_offset();
    try self.base.file.?.pwrite_all(mem.slice_as_bytes(&self.data_directories), offset);
}

fn write_header(self: *Coff) !void {
    const target = self.base.comp.root_mod.resolved_target.result;
    const gpa = self.base.comp.gpa;
    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();
    const writer = buffer.writer();

    try buffer.ensure_total_capacity(self.get_size_of_headers());
    writer.write_all(msdos_stub) catch unreachable;
    mem.write_int(u32, buffer.items[0x3c..][0..4], msdos_stub.len, .little);

    writer.write_all("PE\x00\x00") catch unreachable;
    var flags = coff.CoffHeaderFlags{
        .EXECUTABLE_IMAGE = 1,
        .DEBUG_STRIPPED = 1, // TODO
    };
    switch (self.ptr_width) {
        .p32 => flags.@"32BIT_MACHINE" = 1,
        .p64 => flags.LARGE_ADDRESS_AWARE = 1,
    }
    if (self.base.comp.config.output_mode == .Lib and self.base.comp.config.link_mode == .dynamic) {
        flags.DLL = 1;
    }

    const timestamp = std.time.timestamp();
    const size_of_optional_header = @as(u16, @int_cast(self.get_optional_header_size() + self.get_data_directory_headers_size()));
    var coff_header = coff.CoffHeader{
        .machine = coff.MachineType.from_target_cpu_arch(target.cpu.arch),
        .number_of_sections = @as(u16, @int_cast(self.sections.slice().len)), // TODO what if we prune a section
        .time_date_stamp = @as(u32, @truncate(@as(u64, @bit_cast(timestamp)))),
        .pointer_to_symbol_table = self.strtab_offset orelse 0,
        .number_of_symbols = 0,
        .size_of_optional_header = size_of_optional_header,
        .flags = flags,
    };

    writer.write_all(mem.as_bytes(&coff_header)) catch unreachable;

    const dll_flags: coff.DllFlags = .{
        .HIGH_ENTROPY_VA = 1, // TODO do we want to permit non-PIE builds at all?
        .DYNAMIC_BASE = 1,
        .TERMINAL_SERVER_AWARE = 1, // We are not a legacy app
        .NX_COMPAT = 1, // We are compatible with Data Execution Prevention
    };
    const subsystem: coff.Subsystem = .WINDOWS_CUI;
    const size_of_image: u32 = self.get_size_of_image();
    const size_of_headers: u32 = mem.align_forward(u32, self.get_size_of_headers(), default_file_alignment);
    const base_of_code = self.sections.get(self.text_section_index.?).header.virtual_address;
    const base_of_data = self.sections.get(self.data_section_index.?).header.virtual_address;

    var size_of_code: u32 = 0;
    var size_of_initialized_data: u32 = 0;
    var size_of_uninitialized_data: u32 = 0;
    for (self.sections.items(.header)) |header| {
        if (header.flags.CNT_CODE == 1) {
            size_of_code += header.size_of_raw_data;
        }
        if (header.flags.CNT_INITIALIZED_DATA == 1) {
            size_of_initialized_data += header.size_of_raw_data;
        }
        if (header.flags.CNT_UNINITIALIZED_DATA == 1) {
            size_of_uninitialized_data += header.size_of_raw_data;
        }
    }

    switch (self.ptr_width) {
        .p32 => {
            var opt_header = coff.OptionalHeaderPE32{
                .magic = coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                .major_linker_version = 0,
                .minor_linker_version = 0,
                .size_of_code = size_of_code,
                .size_of_initialized_data = size_of_initialized_data,
                .size_of_uninitialized_data = size_of_uninitialized_data,
                .address_of_entry_point = self.entry_addr orelse 0,
                .base_of_code = base_of_code,
                .base_of_data = base_of_data,
                .image_base = @int_cast(self.image_base),
                .section_alignment = self.page_size,
                .file_alignment = default_file_alignment,
                .major_operating_system_version = 6,
                .minor_operating_system_version = 0,
                .major_image_version = 0,
                .minor_image_version = 0,
                .major_subsystem_version = @int_cast(self.major_subsystem_version),
                .minor_subsystem_version = @int_cast(self.minor_subsystem_version),
                .win32_version_value = 0,
                .size_of_image = size_of_image,
                .size_of_headers = size_of_headers,
                .checksum = 0,
                .subsystem = subsystem,
                .dll_flags = dll_flags,
                .size_of_stack_reserve = default_size_of_stack_reserve,
                .size_of_stack_commit = default_size_of_stack_commit,
                .size_of_heap_reserve = default_size_of_heap_reserve,
                .size_of_heap_commit = default_size_of_heap_commit,
                .loader_flags = 0,
                .number_of_rva_and_sizes = @int_cast(self.data_directories.len),
            };
            writer.write_all(mem.as_bytes(&opt_header)) catch unreachable;
        },
        .p64 => {
            var opt_header = coff.OptionalHeaderPE64{
                .magic = coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                .major_linker_version = 0,
                .minor_linker_version = 0,
                .size_of_code = size_of_code,
                .size_of_initialized_data = size_of_initialized_data,
                .size_of_uninitialized_data = size_of_uninitialized_data,
                .address_of_entry_point = self.entry_addr orelse 0,
                .base_of_code = base_of_code,
                .image_base = self.image_base,
                .section_alignment = self.page_size,
                .file_alignment = default_file_alignment,
                .major_operating_system_version = 6,
                .minor_operating_system_version = 0,
                .major_image_version = 0,
                .minor_image_version = 0,
                .major_subsystem_version = self.major_subsystem_version,
                .minor_subsystem_version = self.minor_subsystem_version,
                .win32_version_value = 0,
                .size_of_image = size_of_image,
                .size_of_headers = size_of_headers,
                .checksum = 0,
                .subsystem = subsystem,
                .dll_flags = dll_flags,
                .size_of_stack_reserve = default_size_of_stack_reserve,
                .size_of_stack_commit = default_size_of_stack_commit,
                .size_of_heap_reserve = default_size_of_heap_reserve,
                .size_of_heap_commit = default_size_of_heap_commit,
                .loader_flags = 0,
                .number_of_rva_and_sizes = @int_cast(self.data_directories.len),
            };
            writer.write_all(mem.as_bytes(&opt_header)) catch unreachable;
        },
    }

    try self.base.file.?.pwrite_all(buffer.items, 0);
}

pub fn pad_to_ideal(actual_size: anytype) @TypeOf(actual_size) {
    return actual_size +| (actual_size / ideal_factor);
}

fn detect_alloc_collision(self: *Coff, start: u32, size: u32) ?u32 {
    const headers_size = @max(self.get_size_of_headers(), self.page_size);
    if (start < headers_size)
        return headers_size;

    const end = start + pad_to_ideal(size);

    if (self.strtab_offset) |off| {
        const tight_size = @as(u32, @int_cast(self.strtab.buffer.items.len));
        const increased_size = pad_to_ideal(tight_size);
        const test_end = off + increased_size;
        if (end > off and start < test_end) {
            return test_end;
        }
    }

    for (self.sections.items(.header)) |header| {
        const tight_size = header.size_of_raw_data;
        const increased_size = pad_to_ideal(tight_size);
        const test_end = header.pointer_to_raw_data + increased_size;
        if (end > header.pointer_to_raw_data and start < test_end) {
            return test_end;
        }
    }

    return null;
}

fn allocated_size(self: *Coff, start: u32) u32 {
    if (start == 0)
        return 0;
    var min_pos: u32 = std.math.max_int(u32);
    if (self.strtab_offset) |off| {
        if (off > start and off < min_pos) min_pos = off;
    }
    for (self.sections.items(.header)) |header| {
        if (header.pointer_to_raw_data <= start) continue;
        if (header.pointer_to_raw_data < min_pos) min_pos = header.pointer_to_raw_data;
    }
    return min_pos - start;
}

fn find_free_space(self: *Coff, object_size: u32, min_alignment: u32) u32 {
    var start: u32 = 0;
    while (self.detect_alloc_collision(start, object_size)) |item_end| {
        start = mem.align_forward(u32, item_end, min_alignment);
    }
    return start;
}

fn allocated_virtual_size(self: *Coff, start: u32) u32 {
    if (start == 0)
        return 0;
    var min_pos: u32 = std.math.max_int(u32);
    for (self.sections.items(.header)) |header| {
        if (header.virtual_address <= start) continue;
        if (header.virtual_address < min_pos) min_pos = header.virtual_address;
    }
    return min_pos - start;
}

inline fn get_size_of_headers(self: Coff) u32 {
    const msdos_hdr_size = msdos_stub.len + 4;
    return @as(u32, @int_cast(msdos_hdr_size + @size_of(coff.CoffHeader) + self.get_optional_header_size() +
        self.get_data_directory_headers_size() + self.get_section_headers_size()));
}

inline fn get_optional_header_size(self: Coff) u32 {
    return switch (self.ptr_width) {
        .p32 => @as(u32, @int_cast(@size_of(coff.OptionalHeaderPE32))),
        .p64 => @as(u32, @int_cast(@size_of(coff.OptionalHeaderPE64))),
    };
}

inline fn get_data_directory_headers_size(self: Coff) u32 {
    return @as(u32, @int_cast(self.data_directories.len * @size_of(coff.ImageDataDirectory)));
}

inline fn get_section_headers_size(self: Coff) u32 {
    return @as(u32, @int_cast(self.sections.slice().len * @size_of(coff.SectionHeader)));
}

inline fn get_data_directory_headers_offset(self: Coff) u32 {
    const msdos_hdr_size = msdos_stub.len + 4;
    return @as(u32, @int_cast(msdos_hdr_size + @size_of(coff.CoffHeader) + self.get_optional_header_size()));
}

inline fn get_section_headers_offset(self: Coff) u32 {
    return self.get_data_directory_headers_offset() + self.get_data_directory_headers_size();
}

inline fn get_size_of_image(self: Coff) u32 {
    var image_size: u32 = mem.align_forward(u32, self.get_size_of_headers(), self.page_size);
    for (self.sections.items(.header)) |header| {
        image_size += mem.align_forward(u32, header.virtual_size, self.page_size);
    }
    return image_size;
}

/// Returns symbol location corresponding to the set entrypoint (if any).
pub fn get_entry_point(self: Coff) ?SymbolWithLoc {
    const comp = self.base.comp;

    // TODO This is incomplete.
    // The entry symbol name depends on the subsystem as well as the set of
    // public symbol names from linked objects.
    // See LinkerDriver::findDefaultEntry from the LLD project for the flow chart.
    const entry_name = switch (self.entry) {
        .disabled => return null,
        .default => switch (comp.config.output_mode) {
            .Exe => "w_win_main_crtstartup",
            .Obj, .Lib => return null,
        },
        .enabled => "w_win_main_crtstartup",
        .named => |name| name,
    };
    const global_index = self.resolver.get(entry_name) orelse return null;
    return self.globals.items[global_index];
}

/// Returns pointer-to-symbol described by `sym_loc` descriptor.
pub fn get_symbol_ptr(self: *Coff, sym_loc: SymbolWithLoc) *coff.Symbol {
    assert(sym_loc.file == null); // TODO linking object files
    return &self.locals.items[sym_loc.sym_index];
}

/// Returns symbol described by `sym_loc` descriptor.
pub fn get_symbol(self: *const Coff, sym_loc: SymbolWithLoc) *const coff.Symbol {
    assert(sym_loc.file == null); // TODO linking object files
    return &self.locals.items[sym_loc.sym_index];
}

/// Returns name of the symbol described by `sym_loc` descriptor.
pub fn get_symbol_name(self: *const Coff, sym_loc: SymbolWithLoc) []const u8 {
    assert(sym_loc.file == null); // TODO linking object files
    const sym = self.get_symbol(sym_loc);
    const offset = sym.get_name_offset() orelse return sym.get_name().?;
    return self.strtab.get(offset).?;
}

/// Returns pointer to the global entry for `name` if one exists.
pub fn get_global_ptr(self: *Coff, name: []const u8) ?*SymbolWithLoc {
    const global_index = self.resolver.get(name) orelse return null;
    return &self.globals.items[global_index];
}

/// Returns the global entry for `name` if one exists.
pub fn get_global(self: *const Coff, name: []const u8) ?SymbolWithLoc {
    const global_index = self.resolver.get(name) orelse return null;
    return self.globals.items[global_index];
}

/// Returns the index of the global entry for `name` if one exists.
pub fn get_global_index(self: *const Coff, name: []const u8) ?u32 {
    return self.resolver.get(name);
}

/// Returns global entry at `index`.
pub fn get_global_by_index(self: *const Coff, index: u32) SymbolWithLoc {
    assert(index < self.globals.items.len);
    return self.globals.items[index];
}

const GetOrPutGlobalPtrResult = struct {
    found_existing: bool,
    value_ptr: *SymbolWithLoc,
};

/// Used only for disambiguating local from global at relocation level.
/// TODO this must go away.
pub const global_symbol_bit: u32 = 0x80000000;
pub const global_symbol_mask: u32 = 0x7fffffff;

/// Return pointer to the global entry for `name` if one exists.
/// Puts a new global entry for `name` if one doesn't exist, and
/// returns a pointer to it.
pub fn get_or_put_global_ptr(self: *Coff, name: []const u8) !GetOrPutGlobalPtrResult {
    if (self.get_global_ptr(name)) |ptr| {
        return GetOrPutGlobalPtrResult{ .found_existing = true, .value_ptr = ptr };
    }
    const gpa = self.base.comp.gpa;
    const global_index = try self.allocate_global();
    const global_name = try gpa.dupe(u8, name);
    _ = try self.resolver.put(gpa, global_name, global_index);
    const ptr = &self.globals.items[global_index];
    return GetOrPutGlobalPtrResult{ .found_existing = false, .value_ptr = ptr };
}

pub fn get_atom(self: *const Coff, atom_index: Atom.Index) Atom {
    assert(atom_index < self.atoms.items.len);
    return self.atoms.items[atom_index];
}

pub fn get_atom_ptr(self: *Coff, atom_index: Atom.Index) *Atom {
    assert(atom_index < self.atoms.items.len);
    return &self.atoms.items[atom_index];
}

/// Returns atom if there is an atom referenced by the symbol described by `sym_loc` descriptor.
/// Returns null on failure.
pub fn get_atom_index_for_symbol(self: *const Coff, sym_loc: SymbolWithLoc) ?Atom.Index {
    assert(sym_loc.file == null); // TODO linking with object files
    return self.atom_by_index_table.get(sym_loc.sym_index);
}

fn set_section_name(self: *Coff, header: *coff.SectionHeader, name: []const u8) !void {
    if (name.len <= 8) {
        @memcpy(header.name[0..name.len], name);
        @memset(header.name[name.len..], 0);
        return;
    }
    const gpa = self.base.comp.gpa;
    const offset = try self.strtab.insert(gpa, name);
    const name_offset = fmt.buf_print(&header.name, "/{d}", .{offset}) catch unreachable;
    @memset(header.name[name_offset.len..], 0);
}

fn get_section_name(self: *const Coff, header: *const coff.SectionHeader) []const u8 {
    if (header.get_name()) |name| {
        return name;
    }
    const offset = header.get_name_offset().?;
    return self.strtab.get(offset).?;
}

fn set_symbol_name(self: *Coff, symbol: *coff.Symbol, name: []const u8) !void {
    if (name.len <= 8) {
        @memcpy(symbol.name[0..name.len], name);
        @memset(symbol.name[name.len..], 0);
        return;
    }
    const gpa = self.base.comp.gpa;
    const offset = try self.strtab.insert(gpa, name);
    @memset(symbol.name[0..4], 0);
    mem.write_int(u32, symbol.name[4..8], offset, .little);
}

fn log_sym_attributes(sym: *const coff.Symbol, buf: *[4]u8) []const u8 {
    @memset(buf[0..4], '_');
    switch (sym.section_number) {
        .UNDEFINED => {
            buf[3] = 'u';
            switch (sym.storage_class) {
                .EXTERNAL => buf[1] = 'e',
                .WEAK_EXTERNAL => buf[1] = 'w',
                .NULL => {},
                else => unreachable,
            }
        },
        .ABSOLUTE => unreachable, // handle ABSOLUTE
        .DEBUG => unreachable,
        else => {
            buf[0] = 's';
            switch (sym.storage_class) {
                .EXTERNAL => buf[1] = 'e',
                .WEAK_EXTERNAL => buf[1] = 'w',
                .NULL => {},
                else => unreachable,
            }
        },
    }
    return buf[0..];
}

fn log_symtab(self: *Coff) void {
    var buf: [4]u8 = undefined;

    log.debug("symtab:", .{});
    log.debug("  object(null)", .{});
    for (self.locals.items, 0..) |*sym, sym_id| {
        const where = if (sym.section_number == .UNDEFINED) "ord" else "sect";
        const def_index: u16 = switch (sym.section_number) {
            .UNDEFINED => 0, // TODO
            .ABSOLUTE => unreachable, // TODO
            .DEBUG => unreachable, // TODO
            else => @int_from_enum(sym.section_number),
        };
        log.debug("    %{d}: {?s} @{x} in {s}({d}), {s}", .{
            sym_id,
            self.get_symbol_name(.{ .sym_index = @as(u32, @int_cast(sym_id)), .file = null }),
            sym.value,
            where,
            def_index,
            log_sym_attributes(sym, &buf),
        });
    }

    log.debug("globals table:", .{});
    for (self.globals.items) |sym_loc| {
        const sym_name = self.get_symbol_name(sym_loc);
        log.debug("  {s} => %{d} in object({?d})", .{ sym_name, sym_loc.sym_index, sym_loc.file });
    }

    log.debug("GOT entries:", .{});
    log.debug("{}", .{self.got_table});
}

fn log_sections(self: *Coff) void {
    log.debug("sections:", .{});
    for (self.sections.items(.header)) |*header| {
        log.debug("  {s}: VM({x}, {x}) FILE({x}, {x})", .{
            self.get_section_name(header),
            header.virtual_address,
            header.virtual_address + header.virtual_size,
            header.pointer_to_raw_data,
            header.pointer_to_raw_data + header.size_of_raw_data,
        });
    }
}

fn log_import_tables(self: *const Coff) void {
    log.debug("import tables:", .{});
    for (self.import_tables.keys(), 0..) |off, i| {
        const itable = self.import_tables.values()[i];
        log.debug("{}", .{itable.fmt_debug(.{
            .coff_file = self,
            .index = i,
            .name_off = off,
        })});
    }
}

const Coff = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const coff = std.coff;
const fmt = std.fmt;
const log = std.log.scoped(.link);
const math = std.math;
const mem = std.mem;

const Allocator = std.mem.Allocator;

const codegen = @import("../codegen.zig");
const link = @import("../link.zig");
const lld = @import("Coff/lld.zig");
const trace = @import("../tracy.zig").trace;

const Air = @import("../Air.zig");
pub const Atom = @import("Coff/Atom.zig");
const Compilation = @import("../Compilation.zig");
const ImportTable = @import("Coff/ImportTable.zig");
const Liveness = @import("../Liveness.zig");
const LlvmObject = @import("../codegen/llvm.zig").Object;
const Module = @import("../Module.zig");
const InternPool = @import("../InternPool.zig");
const Object = @import("Coff/Object.zig");
const Relocation = @import("Coff/Relocation.zig");
const TableSection = @import("table_section.zig").TableSection;
const StringTable = @import("StringTable.zig");
const Type = @import("../type.zig").Type;
const Value = @import("../Value.zig");

pub const base_tag: link.File.Tag = .coff;

const msdos_stub = @embed_file("msdos-stub.bin");
