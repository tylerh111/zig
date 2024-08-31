base: link.File,

/// If this is not null, an object file is created by LLVM and emitted to zcu_object_sub_path.
llvm_object: ?*LlvmObject = null,

/// Debug symbols bundle (or dSym).
d_sym: ?DebugSymbols = null,

/// A list of all input files.
/// Index of each input file also encodes the priority or precedence of one input file
/// over another.
files: std.MultiArrayList(File.Entry) = .{},
/// Long-lived list of all file descriptors.
/// We store them globally rather than per actual File so that we can re-use
/// one file handle per every object file within an archive.
file_handles: std.ArrayListUnmanaged(File.Handle) = .{},
zig_object: ?File.Index = null,
internal_object: ?File.Index = null,
objects: std.ArrayListUnmanaged(File.Index) = .{},
dylibs: std.ArrayListUnmanaged(File.Index) = .{},

segments: std.ArrayListUnmanaged(macho.segment_command_64) = .{},
sections: std.MultiArrayList(Section) = .{},

symbols: std.ArrayListUnmanaged(Symbol) = .{},
symbols_extra: std.ArrayListUnmanaged(u32) = .{},
symbols_free_list: std.ArrayListUnmanaged(Symbol.Index) = .{},
globals: std.AutoArrayHashMapUnmanaged(u32, Symbol.Index) = .{},
/// This table will be populated after `scan_relocs` has run.
/// Key is symbol index.
undefs: std.AutoHashMapUnmanaged(Symbol.Index, std.ArrayListUnmanaged(Atom.Index)) = .{},
/// Global symbols we need to resolve for the link to succeed.
undefined_symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},
boundary_symbols: std.ArrayListUnmanaged(Symbol.Index) = .{},

dyld_info_cmd: macho.dyld_info_command = .{},
symtab_cmd: macho.symtab_command = .{},
dysymtab_cmd: macho.dysymtab_command = .{},
function_starts_cmd: macho.linkedit_data_command = .{ .cmd = .FUNCTION_STARTS },
data_in_code_cmd: macho.linkedit_data_command = .{ .cmd = .DATA_IN_CODE },
uuid_cmd: macho.uuid_command = .{ .uuid = [_]u8{0} ** 16 },
codesig_cmd: macho.linkedit_data_command = .{ .cmd = .CODE_SIGNATURE },

pagezero_seg_index: ?u8 = null,
text_seg_index: ?u8 = null,
linkedit_seg_index: ?u8 = null,
text_sect_index: ?u8 = null,
data_sect_index: ?u8 = null,
got_sect_index: ?u8 = null,
stubs_sect_index: ?u8 = null,
stubs_helper_sect_index: ?u8 = null,
la_symbol_ptr_sect_index: ?u8 = null,
tlv_ptr_sect_index: ?u8 = null,
eh_frame_sect_index: ?u8 = null,
unwind_info_sect_index: ?u8 = null,
objc_stubs_sect_index: ?u8 = null,

mh_execute_header_index: ?Symbol.Index = null,
mh_dylib_header_index: ?Symbol.Index = null,
dyld_private_index: ?Symbol.Index = null,
dyld_stub_binder_index: ?Symbol.Index = null,
dso_handle_index: ?Symbol.Index = null,
objc_msg_send_index: ?Symbol.Index = null,
entry_index: ?Symbol.Index = null,

/// List of atoms that are either synthetic or map directly to the Zig source program.
atoms: std.ArrayListUnmanaged(Atom) = .{},
atoms_extra: std.ArrayListUnmanaged(u32) = .{},
thunks: std.ArrayListUnmanaged(Thunk) = .{},
unwind_records: std.ArrayListUnmanaged(UnwindInfo.Record) = .{},

/// String interning table
strings: StringTable = .{},

/// Output synthetic sections
symtab: std.ArrayListUnmanaged(macho.nlist_64) = .{},
strtab: std.ArrayListUnmanaged(u8) = .{},
indsymtab: Indsymtab = .{},
got: GotSection = .{},
zig_got: ZigGotSection = .{},
stubs: StubsSection = .{},
stubs_helper: StubsHelperSection = .{},
objc_stubs: ObjcStubsSection = .{},
la_symbol_ptr: LaSymbolPtrSection = .{},
tlv_ptr: TlvPtrSection = .{},
rebase: RebaseSection = .{},
bind: BindSection = .{},
weak_bind: WeakBindSection = .{},
lazy_bind: LazyBindSection = .{},
export_trie: ExportTrieSection = .{},
unwind_info: UnwindInfo = .{},

/// Tracked loadable segments during incremental linking.
zig_text_seg_index: ?u8 = null,
zig_got_seg_index: ?u8 = null,
zig_const_seg_index: ?u8 = null,
zig_data_seg_index: ?u8 = null,
zig_bss_seg_index: ?u8 = null,

/// Tracked section headers with incremental updates to Zig object.
zig_text_sect_index: ?u8 = null,
zig_got_sect_index: ?u8 = null,
zig_const_sect_index: ?u8 = null,
zig_data_sect_index: ?u8 = null,
zig_bss_sect_index: ?u8 = null,

/// Tracked DWARF section headers that apply only when we emit relocatable.
/// For executable and loadable images, DWARF is tracked directly by dSYM bundle object.
debug_info_sect_index: ?u8 = null,
debug_abbrev_sect_index: ?u8 = null,
debug_str_sect_index: ?u8 = null,
debug_aranges_sect_index: ?u8 = null,
debug_line_sect_index: ?u8 = null,

has_tlv: bool = false,
binds_to_weak: bool = false,
weak_defines: bool = false,

/// Options
/// SDK layout
sdk_layout: ?SdkLayout,
/// Size of the __PAGEZERO segment.
pagezero_size: ?u64,
/// Minimum space for future expansion of the load commands.
headerpad_size: ?u32,
/// Set enough space as if all paths were MATPATHLEN.
headerpad_max_install_names: bool,
/// Remove dylibs that are unreachable by the entry point or exported symbols.
dead_strip_dylibs: bool,
/// Treatment of undefined symbols
undefined_treatment: UndefinedTreatment,
/// Resolved list of library search directories
lib_dirs: []const []const u8,
/// Resolved list of framework search directories
framework_dirs: []const []const u8,
/// List of input frameworks
frameworks: []const Framework,
/// Install name for the dylib.
/// TODO: unify with soname
install_name: ?[]const u8,
/// Path to entitlements file.
entitlements: ?[]const u8,
compatibility_version: ?std.SemanticVersion,
/// Entry name
entry_name: ?[]const u8,
platform: Platform,
sdk_version: ?std.SemanticVersion,
/// When set to true, the linker will hoist all dylibs including system dependent dylibs.
no_implicit_dylibs: bool = false,
/// Whether the linker should parse and always force load objects containing ObjC in archives.
// TODO: in Zig we currently take -ObjC as always on
force_load_objc: bool = true,

/// Hot-code swapping state.
hot_state: if (is_hot_update_compatible) HotUpdateState else struct {} = .{},

/// When adding a new field, remember to update `hash_add_frameworks`.
pub const Framework = struct {
    needed: bool = false,
    weak: bool = false,
    path: []const u8,
};

pub fn hash_add_frameworks(man: *Cache.Manifest, hm: []const Framework) !void {
    for (hm) |value| {
        man.hash.add(value.needed);
        man.hash.add(value.weak);
        _ = try man.add_file(value.path, null);
    }
}

pub fn create_empty(
    arena: Allocator,
    comp: *Compilation,
    emit: Compilation.Emit,
    options: link.File.OpenOptions,
) !*MachO {
    const target = comp.root_mod.resolved_target.result;
    assert(target.ofmt == .macho);

    const gpa = comp.gpa;
    const use_llvm = comp.config.use_llvm;
    const opt_zcu = comp.module;
    const optimize_mode = comp.root_mod.optimize_mode;
    const output_mode = comp.config.output_mode;
    const link_mode = comp.config.link_mode;

    // If using LLVM to generate the object file for the zig compilation unit,
    // we need a place to put the object file so that it can be subsequently
    // handled.
    const zcu_object_sub_path = if (!use_llvm)
        null
    else
        try std.fmt.alloc_print(arena, "{s}.o", .{emit.sub_path});
    const allow_shlib_undefined = options.allow_shlib_undefined orelse false;

    const self = try arena.create(MachO);
    self.* = .{
        .base = .{
            .tag = .macho,
            .comp = comp,
            .emit = emit,
            .zcu_object_sub_path = zcu_object_sub_path,
            .gc_sections = options.gc_sections orelse (optimize_mode != .Debug),
            .print_gc_sections = options.print_gc_sections,
            .stack_size = options.stack_size orelse 16777216,
            .allow_shlib_undefined = allow_shlib_undefined,
            .file = null,
            .disable_lld_caching = options.disable_lld_caching,
            .build_id = options.build_id,
            .rpath_list = options.rpath_list,
        },
        .pagezero_size = options.pagezero_size,
        .headerpad_size = options.headerpad_size,
        .headerpad_max_install_names = options.headerpad_max_install_names,
        .dead_strip_dylibs = options.dead_strip_dylibs,
        .sdk_layout = options.darwin_sdk_layout,
        .frameworks = options.frameworks,
        .install_name = options.install_name,
        .entitlements = options.entitlements,
        .compatibility_version = options.compatibility_version,
        .entry_name = switch (options.entry) {
            .disabled => null,
            .default => if (output_mode != .Exe) null else default_entry_symbol_name,
            .enabled => default_entry_symbol_name,
            .named => |name| name,
        },
        .platform = Platform.from_target(target),
        .sdk_version = if (options.darwin_sdk_layout) |layout| infer_sdk_version(comp, layout) else null,
        .undefined_treatment = if (allow_shlib_undefined) .dynamic_lookup else .@"error",
        .lib_dirs = options.lib_dirs,
        .framework_dirs = options.framework_dirs,
        .force_load_objc = options.force_load_objc,
    };
    if (use_llvm and comp.config.have_zcu) {
        self.llvm_object = try LlvmObject.create(arena, comp);
    }
    errdefer self.base.destroy();

    self.base.file = try emit.directory.handle.create_file(emit.sub_path, .{
        .truncate = true,
        .read = true,
        .mode = link.File.determine_mode(false, output_mode, link_mode),
    });

    // Append null file
    try self.files.append(gpa, .null);
    // Atom at index 0 is reserved as null atom
    try self.atoms.append(gpa, .{});
    try self.atoms_extra.append(gpa, 0);
    // Append empty string to string tables
    try self.strings.buffer.append(gpa, 0);
    try self.strtab.append(gpa, 0);
    // Append null symbols
    try self.symbols.append(gpa, .{});
    try self.symbols_extra.append(gpa, 0);

    if (opt_zcu) |zcu| {
        if (!use_llvm) {
            const index: File.Index = @int_cast(try self.files.add_one(gpa));
            self.files.set(index, .{ .zig_object = .{
                .index = index,
                .path = try std.fmt.alloc_print(arena, "{s}.o", .{fs.path.stem(
                    zcu.main_mod.root_src_path,
                )}),
            } });
            self.zig_object = index;
            const zo = self.get_zig_object().?;
            try zo.init(self);

            try self.init_metadata(.{
                .emit = emit,
                .zo = zo,
                .symbol_count_hint = options.symbol_count_hint,
                .program_code_size_hint = options.program_code_size_hint,
            });
        }
    }

    return self;
}

pub fn open(
    arena: Allocator,
    comp: *Compilation,
    emit: Compilation.Emit,
    options: link.File.OpenOptions,
) !*MachO {
    // TODO: restore saved linker state, don't truncate the file, and
    // participate in incremental compilation.
    return create_empty(arena, comp, emit, options);
}

pub fn deinit(self: *MachO) void {
    const gpa = self.base.comp.gpa;

    if (self.llvm_object) |llvm_object| llvm_object.deinit();

    if (self.d_sym) |*d_sym| {
        d_sym.deinit();
    }

    for (self.file_handles.items) |handle| {
        handle.close();
    }
    self.file_handles.deinit(gpa);

    for (self.files.items(.tags), self.files.items(.data)) |tag, *data| switch (tag) {
        .null => {},
        .zig_object => data.zig_object.deinit(gpa),
        .internal => data.internal.deinit(gpa),
        .object => data.object.deinit(gpa),
        .dylib => data.dylib.deinit(gpa),
    };
    self.files.deinit(gpa);
    self.objects.deinit(gpa);
    self.dylibs.deinit(gpa);

    self.segments.deinit(gpa);
    for (self.sections.items(.atoms)) |*list| {
        list.deinit(gpa);
    }
    self.sections.deinit(gpa);

    self.symbols.deinit(gpa);
    self.symbols_extra.deinit(gpa);
    self.symbols_free_list.deinit(gpa);
    self.globals.deinit(gpa);
    {
        var it = self.undefs.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(gpa);
        }
        self.undefs.deinit(gpa);
    }
    self.undefined_symbols.deinit(gpa);
    self.boundary_symbols.deinit(gpa);

    self.strings.deinit(gpa);
    self.symtab.deinit(gpa);
    self.strtab.deinit(gpa);
    self.got.deinit(gpa);
    self.zig_got.deinit(gpa);
    self.stubs.deinit(gpa);
    self.objc_stubs.deinit(gpa);
    self.tlv_ptr.deinit(gpa);
    self.rebase.deinit(gpa);
    self.bind.deinit(gpa);
    self.weak_bind.deinit(gpa);
    self.lazy_bind.deinit(gpa);
    self.export_trie.deinit(gpa);
    self.unwind_info.deinit(gpa);

    self.atoms.deinit(gpa);
    self.atoms_extra.deinit(gpa);
    for (self.thunks.items) |*thunk| {
        thunk.deinit(gpa);
    }
    self.thunks.deinit(gpa);
    self.unwind_records.deinit(gpa);
}

pub fn flush(self: *MachO, arena: Allocator, prog_node: std.Progress.Node) link.File.FlushError!void {
    try self.flush_module(arena, prog_node);
}

pub fn flush_module(self: *MachO, arena: Allocator, prog_node: std.Progress.Node) link.File.FlushError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const comp = self.base.comp;
    const gpa = comp.gpa;

    if (self.llvm_object) |llvm_object| {
        try self.base.emit_llvm_object(arena, llvm_object, prog_node);
    }

    const sub_prog_node = prog_node.start("MachO Flush", 0);
    defer sub_prog_node.end();

    const directory = self.base.emit.directory;
    const full_out_path = try directory.join(arena, &[_][]const u8{self.base.emit.sub_path});
    const module_obj_path: ?[]const u8 = if (self.base.zcu_object_sub_path) |path| blk: {
        if (fs.path.dirname(full_out_path)) |dirname| {
            break :blk try fs.path.join(arena, &.{ dirname, path });
        } else {
            break :blk path;
        }
    } else null;

    // --verbose-link
    if (comp.verbose_link) try self.dump_argv(comp);

    if (self.get_zig_object()) |zo| try zo.flush_module(self);
    if (self.base.is_static_lib()) return relocatable.flush_static_lib(self, comp, module_obj_path);
    if (self.base.is_object()) return relocatable.flush_object(self, comp, module_obj_path);

    var positionals = std.ArrayList(Compilation.LinkObject).init(gpa);
    defer positionals.deinit();

    try positionals.ensure_unused_capacity(comp.objects.len);
    positionals.append_slice_assume_capacity(comp.objects);

    // This is a set of object files emitted by clang in a single `build-exe` invocation.
    // For instance, the implicit `a.o` as compiled by `zig build-exe a.c` will end up
    // in this set.
    try positionals.ensure_unused_capacity(comp.c_object_table.keys().len);
    for (comp.c_object_table.keys()) |key| {
        positionals.append_assume_capacity(.{ .path = key.status.success.object_path });
    }

    if (module_obj_path) |path| try positionals.append(.{ .path = path });

    for (positionals.items) |obj| {
        self.parse_positional(obj.path, obj.must_link) catch |err| switch (err) {
            error.MalformedObject,
            error.MalformedArchive,
            error.MalformedDylib,
            error.InvalidCpuArch,
            error.InvalidTarget,
            => continue, // already reported
            error.UnknownFileType => try self.report_parse_error(obj.path, "unknown file type for an object file", .{}),
            else => |e| try self.report_parse_error(
                obj.path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    var system_libs = std.ArrayList(SystemLib).init(gpa);
    defer system_libs.deinit();

    // libs
    try system_libs.ensure_unused_capacity(comp.system_libs.values().len);
    for (comp.system_libs.values()) |info| {
        system_libs.append_assume_capacity(.{
            .needed = info.needed,
            .weak = info.weak,
            .path = info.path.?,
        });
    }

    // frameworks
    try system_libs.ensure_unused_capacity(self.frameworks.len);
    for (self.frameworks) |info| {
        system_libs.append_assume_capacity(.{
            .needed = info.needed,
            .weak = info.weak,
            .path = info.path,
        });
    }

    // libc++ dep
    if (comp.config.link_libcpp) {
        try system_libs.ensure_unused_capacity(2);
        system_libs.append_assume_capacity(.{ .path = comp.libcxxabi_static_lib.?.full_object_path });
        system_libs.append_assume_capacity(.{ .path = comp.libcxx_static_lib.?.full_object_path });
    }

    // libc/libSystem dep
    self.resolve_lib_system(arena, comp, &system_libs) catch |err| switch (err) {
        error.MissingLibSystem => {}, // already reported
        else => |e| return e, // TODO: convert into an error
    };

    for (system_libs.items) |lib| {
        self.parse_library(lib, false) catch |err| switch (err) {
            error.MalformedArchive,
            error.MalformedDylib,
            error.InvalidCpuArch,
            => continue, // already reported
            error.UnknownFileType => try self.report_parse_error(lib.path, "unknown file type for a library", .{}),
            else => |e| try self.report_parse_error(
                lib.path,
                "unexpected error: parsing library failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    // Finally, link against compiler_rt.
    const compiler_rt_path: ?[]const u8 = blk: {
        if (comp.compiler_rt_lib) |x| break :blk x.full_object_path;
        if (comp.compiler_rt_obj) |x| break :blk x.full_object_path;
        break :blk null;
    };
    if (compiler_rt_path) |path| {
        self.parse_positional(path, false) catch |err| switch (err) {
            error.MalformedObject,
            error.MalformedArchive,
            error.InvalidCpuArch,
            error.InvalidTarget,
            => {}, // already reported
            error.UnknownFileType => try self.report_parse_error(path, "unknown file type for a library", .{}),
            else => |e| try self.report_parse_error(
                path,
                "unexpected error: parsing input file failed with error {s}",
                .{@errorName(e)},
            ),
        };
    }

    if (comp.link_errors.items.len > 0) return error.FlushFailure;

    for (self.dylibs.items) |index| {
        self.get_file(index).?.dylib.umbrella = index;
    }

    if (self.dylibs.items.len > 0) {
        self.parse_dependent_dylibs() catch |err| {
            switch (err) {
                error.MissingLibraryDependencies => {},
                else => |e| try self.report_unexpected_error(
                    "unexpected error while parsing dependent libraries: {s}",
                    .{@errorName(e)},
                ),
            }
            return error.FlushFailure;
        };
    }

    for (self.dylibs.items) |index| {
        const dylib = self.get_file(index).?.dylib;
        if (!dylib.explicit and !dylib.hoisted) continue;
        try dylib.init_symbols(self);
    }

    {
        const index = @as(File.Index, @int_cast(try self.files.add_one(gpa)));
        self.files.set(index, .{ .internal = .{ .index = index } });
        self.internal_object = index;
    }

    try self.add_undefined_globals();
    try self.resolve_symbols();
    try self.parse_debug_info();
    try self.resolve_synthetic_symbols();

    try self.convert_tentative_definitions();
    try self.create_objc_sections();
    try self.dedup_literals();
    try self.claim_unresolved();

    if (self.base.gc_sections) {
        try dead_strip.gc_atoms(self);
    }

    self.check_duplicates() catch |err| switch (err) {
        error.HasDuplicates => return error.FlushFailure,
        else => |e| {
            try self.report_unexpected_error("unexpected error while checking for duplicate symbol definitions", .{});
            return e;
        },
    };

    self.mark_imports_and_exports();
    self.dead_strip_dylibs();

    for (self.dylibs.items, 1..) |index, ord| {
        const dylib = self.get_file(index).?.dylib;
        dylib.ordinal = @int_cast(ord);
    }

    self.scan_relocs() catch |err| switch (err) {
        error.HasUndefinedSymbols => return error.FlushFailure,
        else => |e| {
            try self.report_unexpected_error("unexpected error while scanning relocations", .{});
            return e;
        },
    };

    try self.init_output_sections();
    try self.init_synthetic_sections();
    try self.sort_sections();
    try self.add_atoms_to_sections();
    try self.calc_section_sizes();
    try self.generate_unwind_info();
    try self.init_segments();

    try self.allocate_sections();
    self.allocate_segments();
    self.allocate_synthetic_symbols();
    try self.allocate_linkedit_segment();

    if (build_options.enable_logging) {
        state_log.debug("{}", .{self.dump_state()});
    }

    try self.init_dyld_info_sections();

    // Beyond this point, everything has been allocated a virtual address and we can resolve
    // the relocations, and commit objects to file.
    if (self.get_zig_object()) |zo| {
        var has_resolve_error = false;

        for (zo.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const sect = &self.sections.items(.header)[atom.out_n_sect];
            if (sect.is_zerofill()) continue;
            if (!self.is_zig_section(atom.out_n_sect)) continue; // Non-Zig sections are handled separately
            if (atom.get_relocs(self).len == 0) continue;
            // TODO: we will resolve and write ZigObject's TLS data twice:
            // once here, and once in write_atoms
            const atom_size = math.cast(usize, atom.size) orelse return error.Overflow;
            const code = try gpa.alloc(u8, atom_size);
            defer gpa.free(code);
            atom.get_data(self, code) catch |err| switch (err) {
                error.InputOutput => {
                    try self.report_unexpected_error("fetching code for '{s}' failed", .{
                        atom.get_name(self),
                    });
                    return error.FlushFailure;
                },
                else => |e| {
                    try self.report_unexpected_error("unexpected error while fetching code for '{s}': {s}", .{
                        atom.get_name(self),
                        @errorName(e),
                    });
                    return error.FlushFailure;
                },
            };
            const file_offset = sect.offset + atom.value;
            atom.resolve_relocs(self, code) catch |err| switch (err) {
                error.ResolveFailed => has_resolve_error = true,
                else => |e| {
                    try self.report_unexpected_error("unexpected error while resolving relocations", .{});
                    return e;
                },
            };
            try self.base.file.?.pwrite_all(code, file_offset);
        }

        if (has_resolve_error) return error.FlushFailure;
    }

    self.write_atoms() catch |err| switch (err) {
        error.ResolveFailed => return error.FlushFailure,
        else => |e| {
            try self.report_unexpected_error("unexpected error while resolving relocations", .{});
            return e;
        },
    };
    try self.write_unwind_info();
    try self.finalize_dyld_info_sections();
    try self.write_synthetic_sections();

    var off = math.cast(u32, self.get_linkedit_segment().fileoff) orelse return error.Overflow;
    off = try self.write_dyld_info_sections(off);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try self.write_function_starts(off);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try self.write_data_in_code(self.get_text_segment().vmaddr, off);
    try self.calc_symtab_size();
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try self.write_symtab(off);
    off = mem.align_forward(u32, off, @alignOf(u32));
    off = try self.write_indsymtab(off);
    off = mem.align_forward(u32, off, @alignOf(u64));
    off = try self.write_strtab(off);

    self.get_linkedit_segment().filesize = off - self.get_linkedit_segment().fileoff;

    var codesig: ?CodeSignature = if (self.requires_code_sig()) blk: {
        // Preallocate space for the code signature.
        // We need to do this at this stage so that we have the load commands with proper values
        // written out to the file.
        // The most important here is to have the correct vm and filesize of the __LINKEDIT segment
        // where the code signature goes into.
        var codesig = CodeSignature.init(self.get_page_size());
        codesig.code_directory.ident = fs.path.basename(full_out_path);
        if (self.entitlements) |path| try codesig.add_entitlements(gpa, path);
        try self.write_code_signature_padding(&codesig);
        break :blk codesig;
    } else null;
    defer if (codesig) |*csig| csig.deinit(gpa);

    self.get_linkedit_segment().vmsize = mem.align_forward(
        u64,
        self.get_linkedit_segment().filesize,
        self.get_page_size(),
    );

    const ncmds, const sizeofcmds, const uuid_cmd_offset = try self.write_load_commands();
    try self.write_header(ncmds, sizeofcmds);
    try self.write_uuid(uuid_cmd_offset, self.requires_code_sig());
    if (self.get_debug_symbols()) |dsym| try dsym.flush_module(self);

    if (codesig) |*csig| {
        try self.write_code_signature(csig); // code signing always comes last
        const emit = self.base.emit;
        try invalidate_kernel_cache(emit.directory.handle, emit.sub_path);
    }
}

/// --verbose-link output
fn dump_argv(self: *MachO, comp: *Compilation) !void {
    const gpa = self.base.comp.gpa;
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const directory = self.base.emit.directory;
    const full_out_path = try directory.join(arena, &[_][]const u8{self.base.emit.sub_path});
    const module_obj_path: ?[]const u8 = if (self.base.zcu_object_sub_path) |path| blk: {
        if (fs.path.dirname(full_out_path)) |dirname| {
            break :blk try fs.path.join(arena, &.{ dirname, path });
        } else {
            break :blk path;
        }
    } else null;

    var argv = std.ArrayList([]const u8).init(arena);

    try argv.append("zig");

    if (self.base.is_static_lib()) {
        try argv.append("ar");
    } else {
        try argv.append("ld");
    }

    if (self.base.is_object()) {
        try argv.append("-r");
    }

    if (self.base.is_relocatable()) {
        for (comp.objects) |obj| {
            try argv.append(obj.path);
        }

        for (comp.c_object_table.keys()) |key| {
            try argv.append(key.status.success.object_path);
        }

        if (module_obj_path) |p| {
            try argv.append(p);
        }
    } else {
        if (!self.base.is_static()) {
            try argv.append("-dynamic");
        }

        if (self.base.is_dyn_lib()) {
            try argv.append("-dylib");

            if (self.install_name) |install_name| {
                try argv.append("-install_name");
                try argv.append(install_name);
            }
        }

        try argv.append("-platform_version");
        try argv.append(@tag_name(self.platform.os_tag));
        try argv.append(try std.fmt.alloc_print(arena, "{}", .{self.platform.version}));

        if (self.sdk_version) |ver| {
            try argv.append(try std.fmt.alloc_print(arena, "{d}.{d}", .{ ver.major, ver.minor }));
        } else {
            try argv.append(try std.fmt.alloc_print(arena, "{}", .{self.platform.version}));
        }

        if (comp.sysroot) |syslibroot| {
            try argv.append("-syslibroot");
            try argv.append(syslibroot);
        }

        for (self.base.rpath_list) |rpath| {
            try argv.append("-rpath");
            try argv.append(rpath);
        }

        if (self.pagezero_size) |size| {
            try argv.append("-pagezero_size");
            try argv.append(try std.fmt.alloc_print(arena, "0x{x}", .{size}));
        }

        if (self.headerpad_size) |size| {
            try argv.append("-headerpad_size");
            try argv.append(try std.fmt.alloc_print(arena, "0x{x}", .{size}));
        }

        if (self.headerpad_max_install_names) {
            try argv.append("-headerpad_max_install_names");
        }

        if (self.base.gc_sections) {
            try argv.append("-dead_strip");
        }

        if (self.dead_strip_dylibs) {
            try argv.append("-dead_strip_dylibs");
        }

        if (self.force_load_objc) {
            try argv.append("-ObjC");
        }

        if (self.entry_name) |entry_name| {
            try argv.append_slice(&.{ "-e", entry_name });
        }

        try argv.append("-o");
        try argv.append(full_out_path);

        if (self.base.is_dyn_lib() and self.base.allow_shlib_undefined) {
            try argv.append("-undefined");
            try argv.append("dynamic_lookup");
        }

        for (comp.objects) |obj| {
            // TODO: verify this
            if (obj.must_link) {
                try argv.append("-force_load");
            }
            try argv.append(obj.path);
        }

        for (comp.c_object_table.keys()) |key| {
            try argv.append(key.status.success.object_path);
        }

        if (module_obj_path) |p| {
            try argv.append(p);
        }

        for (self.lib_dirs) |lib_dir| {
            const arg = try std.fmt.alloc_print(arena, "-L{s}", .{lib_dir});
            try argv.append(arg);
        }

        for (comp.system_libs.keys()) |l_name| {
            const info = comp.system_libs.get(l_name).?;
            const arg = if (info.needed)
                try std.fmt.alloc_print(arena, "-needed-l{s}", .{l_name})
            else if (info.weak)
                try std.fmt.alloc_print(arena, "-weak-l{s}", .{l_name})
            else
                try std.fmt.alloc_print(arena, "-l{s}", .{l_name});
            try argv.append(arg);
        }

        for (self.framework_dirs) |f_dir| {
            try argv.append("-F");
            try argv.append(f_dir);
        }

        for (self.frameworks) |framework| {
            const name = fs.path.stem(framework.path);
            const arg = if (framework.needed)
                try std.fmt.alloc_print(arena, "-needed_framework {s}", .{name})
            else if (framework.weak)
                try std.fmt.alloc_print(arena, "-weak_framework {s}", .{name})
            else
                try std.fmt.alloc_print(arena, "-framework {s}", .{name});
            try argv.append(arg);
        }

        if (comp.config.link_libcpp) {
            try argv.append(comp.libcxxabi_static_lib.?.full_object_path);
            try argv.append(comp.libcxx_static_lib.?.full_object_path);
        }

        try argv.append("-lSystem");

        if (comp.compiler_rt_lib) |lib| try argv.append(lib.full_object_path);
        if (comp.compiler_rt_obj) |obj| try argv.append(obj.full_object_path);
    }

    Compilation.dump_argv(argv.items);
}

pub fn resolve_lib_system(
    self: *MachO,
    arena: Allocator,
    comp: *Compilation,
    out_libs: anytype,
) !void {
    var test_path = std.ArrayList(u8).init(arena);
    var checked_paths = std.ArrayList([]const u8).init(arena);

    success: {
        if (self.sdk_layout) |sdk_layout| switch (sdk_layout) {
            .sdk => {
                const dir = try fs.path.join(arena, &[_][]const u8{ comp.sysroot.?, "usr", "lib" });
                if (try access_lib_path(arena, &test_path, &checked_paths, dir, "System")) break :success;
            },
            .vendored => {
                const dir = try comp.zig_lib_directory.join(arena, &[_][]const u8{ "libc", "darwin" });
                if (try access_lib_path(arena, &test_path, &checked_paths, dir, "System")) break :success;
            },
        };

        for (self.lib_dirs) |dir| {
            if (try access_lib_path(arena, &test_path, &checked_paths, dir, "System")) break :success;
        }

        try self.report_missing_library_error(checked_paths.items, "unable to find libSystem system library", .{});
        return error.MissingLibSystem;
    }

    const libsystem_path = try arena.dupe(u8, test_path.items);
    try out_libs.append(.{
        .needed = true,
        .path = libsystem_path,
    });
}

pub const ParseError = error{
    MalformedObject,
    MalformedArchive,
    MalformedDylib,
    MalformedTbd,
    NotLibStub,
    InvalidCpuArch,
    InvalidTarget,
    InvalidTargetFatLibrary,
    IncompatibleDylibVersion,
    OutOfMemory,
    Overflow,
    InputOutput,
    EndOfStream,
    FileSystem,
    NotSupported,
    Unhandled,
    UnknownFileType,
} || fs.File.SeekError || fs.File.OpenError || fs.File.ReadError || tapi.TapiError;

pub fn parse_positional(self: *MachO, path: []const u8, must_link: bool) ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();
    if (try Object.is_object(path)) {
        try self.parse_object(path);
    } else {
        try self.parse_library(.{ .path = path }, must_link);
    }
}

fn parse_library(self: *MachO, lib: SystemLib, must_link: bool) ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();
    if (try fat.is_fat_library(lib.path)) {
        const fat_arch = try self.parse_fat_library(lib.path);
        if (try Archive.is_archive(lib.path, fat_arch)) {
            try self.parse_archive(lib, must_link, fat_arch);
        } else if (try Dylib.is_dylib(lib.path, fat_arch)) {
            _ = try self.parse_dylib(lib, true, fat_arch);
        } else return error.UnknownFileType;
    } else if (try Archive.is_archive(lib.path, null)) {
        try self.parse_archive(lib, must_link, null);
    } else if (try Dylib.is_dylib(lib.path, null)) {
        _ = try self.parse_dylib(lib, true, null);
    } else {
        _ = self.parse_tbd(lib, true) catch |err| switch (err) {
            error.MalformedTbd => return error.UnknownFileType,
            else => |e| return e,
        };
    }
}

fn parse_object(self: *MachO, path: []const u8) ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    const file = try fs.cwd().open_file(path, .{});
    const handle = try self.add_file_handle(file);
    const mtime: u64 = mtime: {
        const stat = file.stat() catch break :mtime 0;
        break :mtime @as(u64, @int_cast(@div_floor(stat.mtime, 1_000_000_000)));
    };
    const index = @as(File.Index, @int_cast(try self.files.add_one(gpa)));
    self.files.set(index, .{ .object = .{
        .path = try gpa.dupe(u8, path),
        .file_handle = handle,
        .mtime = mtime,
        .index = index,
    } });
    try self.objects.append(gpa, index);

    const object = self.get_file(index).?.object;
    try object.parse(self);
}

pub fn parse_fat_library(self: *MachO, path: []const u8) !fat.Arch {
    var buffer: [2]fat.Arch = undefined;
    const fat_archs = try fat.parse_archs(path, &buffer);
    const cpu_arch = self.get_target().cpu.arch;
    for (fat_archs) |arch| {
        if (arch.tag == cpu_arch) return arch;
    }
    try self.report_parse_error(path, "missing arch in universal file: expected {s}", .{@tag_name(cpu_arch)});
    return error.InvalidCpuArch;
}

fn parse_archive(self: *MachO, lib: SystemLib, must_link: bool, fat_arch: ?fat.Arch) ParseError!void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;

    const file = try fs.cwd().open_file(lib.path, .{});
    const handle = try self.add_file_handle(file);

    var archive = Archive{};
    defer archive.deinit(gpa);
    try archive.parse(self, lib.path, handle, fat_arch);

    var has_parse_error = false;
    for (archive.objects.items) |extracted| {
        const index = @as(File.Index, @int_cast(try self.files.add_one(gpa)));
        self.files.set(index, .{ .object = extracted });
        const object = &self.files.items(.data)[index].object;
        object.index = index;
        object.alive = must_link or lib.needed; // TODO: or self.options.all_load;
        object.hidden = lib.hidden;
        object.parse(self) catch |err| switch (err) {
            error.MalformedObject,
            error.InvalidCpuArch,
            error.InvalidTarget,
            => has_parse_error = true,
            else => |e| return e,
        };
        try self.objects.append(gpa, index);

        // Finally, we do a post-parse check for -ObjC to see if we need to force load this member
        // anyhow.
        object.alive = object.alive or (self.force_load_objc and object.has_objc());
    }
    if (has_parse_error) return error.MalformedArchive;
}

fn parse_dylib(self: *MachO, lib: SystemLib, explicit: bool, fat_arch: ?fat.Arch) ParseError!File.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;

    const file = try fs.cwd().open_file(lib.path, .{});
    defer file.close();

    const index = @as(File.Index, @int_cast(try self.files.add_one(gpa)));
    self.files.set(index, .{ .dylib = .{
        .path = try gpa.dupe(u8, lib.path),
        .index = index,
        .needed = lib.needed,
        .weak = lib.weak,
        .reexport = lib.reexport,
        .explicit = explicit,
    } });
    const dylib = &self.files.items(.data)[index].dylib;
    try dylib.parse(self, file, fat_arch);

    try self.dylibs.append(gpa, index);

    return index;
}

fn parse_tbd(self: *MachO, lib: SystemLib, explicit: bool) ParseError!File.Index {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    const file = try fs.cwd().open_file(lib.path, .{});
    defer file.close();

    var lib_stub = LibStub.load_from_file(gpa, file) catch return error.MalformedTbd; // TODO actually handle different errors
    defer lib_stub.deinit();

    const index = @as(File.Index, @int_cast(try self.files.add_one(gpa)));
    self.files.set(index, .{ .dylib = .{
        .path = try gpa.dupe(u8, lib.path),
        .index = index,
        .needed = lib.needed,
        .weak = lib.weak,
        .reexport = lib.reexport,
        .explicit = explicit,
    } });
    const dylib = &self.files.items(.data)[index].dylib;
    try dylib.parse_tbd(self.get_target().cpu.arch, self.platform, lib_stub, self);
    try self.dylibs.append(gpa, index);

    return index;
}

/// According to ld64's manual, public (i.e., system) dylibs/frameworks are hoisted into the final
/// image unless overriden by -no_implicit_dylibs.
fn is_hoisted(self: *MachO, install_name: []const u8) bool {
    if (self.no_implicit_dylibs) return true;
    if (fs.path.dirname(install_name)) |dirname| {
        if (mem.starts_with(u8, dirname, "/usr/lib")) return true;
        if (eat_prefix(dirname, "/System/Library/Frameworks/")) |path| {
            const basename = fs.path.basename(install_name);
            if (mem.index_of_scalar(u8, path, '.')) |index| {
                if (mem.eql(u8, basename, path[0..index])) return true;
            }
        }
    }
    return false;
}

fn access_lib_path(
    arena: Allocator,
    test_path: *std.ArrayList(u8),
    checked_paths: *std.ArrayList([]const u8),
    search_dir: []const u8,
    name: []const u8,
) !bool {
    const sep = fs.path.sep_str;

    for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
        test_path.clear_retaining_capacity();
        try test_path.writer().print("{s}" ++ sep ++ "lib{s}{s}", .{ search_dir, name, ext });
        try checked_paths.append(try arena.dupe(u8, test_path.items));
        fs.cwd().access(test_path.items, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        return true;
    }

    return false;
}

fn access_framework_path(
    arena: Allocator,
    test_path: *std.ArrayList(u8),
    checked_paths: *std.ArrayList([]const u8),
    search_dir: []const u8,
    name: []const u8,
) !bool {
    const sep = fs.path.sep_str;

    for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
        test_path.clear_retaining_capacity();
        try test_path.writer().print("{s}" ++ sep ++ "{s}.framework" ++ sep ++ "{s}{s}", .{
            search_dir,
            name,
            name,
            ext,
        });
        try checked_paths.append(try arena.dupe(u8, test_path.items));
        fs.cwd().access(test_path.items, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        return true;
    }

    return false;
}

fn parse_dependent_dylibs(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    const lib_dirs = self.lib_dirs;
    const framework_dirs = self.framework_dirs;

    var arena_alloc = std.heap.ArenaAllocator.init(gpa);
    defer arena_alloc.deinit();
    const arena = arena_alloc.allocator();

    // TODO handle duplicate dylibs - it is not uncommon to have the same dylib loaded multiple times
    // in which case we should track that and return File.Index immediately instead re-parsing paths.

    var has_errors = false;
    var index: usize = 0;
    while (index < self.dylibs.items.len) : (index += 1) {
        const dylib_index = self.dylibs.items[index];

        var dependents = std.ArrayList(struct { id: Dylib.Id, file: File.Index }).init(gpa);
        defer dependents.deinit();
        try dependents.ensure_total_capacity_precise(self.get_file(dylib_index).?.dylib.dependents.items.len);

        const is_weak = self.get_file(dylib_index).?.dylib.weak;
        for (self.get_file(dylib_index).?.dylib.dependents.items) |id| {
            // We will search for the dependent dylibs in the following order:
            // 1. Basename is in search lib directories or framework directories
            // 2. If name is an absolute path, search as-is optionally prepending a syslibroot
            //    if specified.
            // 3. If name is a relative path, substitute @rpath, @loader_path, @executable_path with
            //    dependees list of rpaths, and search there.
            // 4. Finally, just search the provided relative path directly in CWD.
            var test_path = std.ArrayList(u8).init(arena);
            var checked_paths = std.ArrayList([]const u8).init(arena);

            const full_path = full_path: {
                {
                    const stem = fs.path.stem(id.name);

                    // Framework
                    for (framework_dirs) |dir| {
                        test_path.clear_retaining_capacity();
                        if (try access_framework_path(arena, &test_path, &checked_paths, dir, stem)) break :full_path test_path.items;
                    }

                    // Library
                    const lib_name = eat_prefix(stem, "lib") orelse stem;
                    for (lib_dirs) |dir| {
                        test_path.clear_retaining_capacity();
                        if (try access_lib_path(arena, &test_path, &checked_paths, dir, lib_name)) break :full_path test_path.items;
                    }
                }

                if (fs.path.is_absolute(id.name)) {
                    const existing_ext = fs.path.extension(id.name);
                    const path = if (existing_ext.len > 0) id.name[0 .. id.name.len - existing_ext.len] else id.name;
                    for (&[_][]const u8{ ".tbd", ".dylib", "" }) |ext| {
                        test_path.clear_retaining_capacity();
                        if (self.base.comp.sysroot) |root| {
                            try test_path.writer().print("{s}" ++ fs.path.sep_str ++ "{s}{s}", .{ root, path, ext });
                        } else {
                            try test_path.writer().print("{s}{s}", .{ path, ext });
                        }
                        try checked_paths.append(try arena.dupe(u8, test_path.items));
                        fs.cwd().access(test_path.items, .{}) catch |err| switch (err) {
                            error.FileNotFound => continue,
                            else => |e| return e,
                        };
                        break :full_path test_path.items;
                    }
                }

                if (eat_prefix(id.name, "@rpath/")) |path| {
                    const dylib = self.get_file(dylib_index).?.dylib;
                    for (self.get_file(dylib.umbrella).?.dylib.rpaths.keys()) |rpath| {
                        const prefix = eat_prefix(rpath, "@loader_path/") orelse rpath;
                        const rel_path = try fs.path.join(arena, &.{ prefix, path });
                        try checked_paths.append(rel_path);
                        var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
                        const full_path = fs.realpath(rel_path, &buffer) catch continue;
                        break :full_path try arena.dupe(u8, full_path);
                    }
                } else if (eat_prefix(id.name, "@loader_path/")) |_| {
                    try self.report_parse_error2(dylib_index, "TODO handle install_name '{s}'", .{id.name});
                    return error.Unhandled;
                } else if (eat_prefix(id.name, "@executable_path/")) |_| {
                    try self.report_parse_error2(dylib_index, "TODO handle install_name '{s}'", .{id.name});
                    return error.Unhandled;
                }

                try checked_paths.append(try arena.dupe(u8, id.name));
                var buffer: [fs.MAX_PATH_BYTES]u8 = undefined;
                if (fs.realpath(id.name, &buffer)) |full_path| {
                    break :full_path try arena.dupe(u8, full_path);
                } else |_| {
                    try self.report_missing_dependency_error(
                        self.get_file(dylib_index).?.dylib.get_umbrella(self).index,
                        id.name,
                        checked_paths.items,
                        "unable to resolve dependency",
                        .{},
                    );
                    has_errors = true;
                    continue;
                }
            };
            const lib = SystemLib{
                .path = full_path,
                .weak = is_weak,
            };
            const file_index = file_index: {
                if (try fat.is_fat_library(lib.path)) {
                    const fat_arch = try self.parse_fat_library(lib.path);
                    if (try Dylib.is_dylib(lib.path, fat_arch)) {
                        break :file_index try self.parse_dylib(lib, false, fat_arch);
                    } else break :file_index @as(File.Index, 0);
                } else if (try Dylib.is_dylib(lib.path, null)) {
                    break :file_index try self.parse_dylib(lib, false, null);
                } else {
                    const file_index = self.parse_tbd(lib, false) catch |err| switch (err) {
                        error.MalformedTbd => @as(File.Index, 0),
                        else => |e| return e,
                    };
                    break :file_index file_index;
                }
            };
            dependents.append_assume_capacity(.{ .id = id, .file = file_index });
        }

        const dylib = self.get_file(dylib_index).?.dylib;
        for (dependents.items) |entry| {
            const id = entry.id;
            const file_index = entry.file;
            if (self.get_file(file_index)) |file| {
                const dep_dylib = file.dylib;
                dep_dylib.hoisted = self.is_hoisted(id.name);
                if (self.get_file(dep_dylib.umbrella) == null) {
                    dep_dylib.umbrella = dylib.umbrella;
                }
                if (!dep_dylib.hoisted) {
                    const umbrella = dep_dylib.get_umbrella(self);
                    for (dep_dylib.exports.items(.name), dep_dylib.exports.items(.flags)) |off, flags| {
                        try umbrella.add_export(gpa, dep_dylib.get_string(off), flags);
                    }
                    try umbrella.rpaths.ensure_unused_capacity(gpa, dep_dylib.rpaths.keys().len);
                    for (dep_dylib.rpaths.keys()) |rpath| {
                        umbrella.rpaths.put_assume_capacity(try gpa.dupe(u8, rpath), {});
                    }
                }
            } else {
                try self.report_dependency_error(
                    dylib.get_umbrella(self).index,
                    id.name,
                    "unable to resolve dependency",
                    .{},
                );
                has_errors = true;
            }
        }
    }

    if (has_errors) return error.MissingLibraryDependencies;
}

pub fn add_undefined_globals(self: *MachO) !void {
    const gpa = self.base.comp.gpa;

    try self.undefined_symbols.ensure_unused_capacity(gpa, self.base.comp.force_undefined_symbols.keys().len);
    for (self.base.comp.force_undefined_symbols.keys()) |name| {
        const off = try self.strings.insert(gpa, name);
        const gop = try self.get_or_create_global(off);
        self.undefined_symbols.append_assume_capacity(gop.index);
    }

    if (!self.base.is_dyn_lib() and self.entry_name != null) {
        const off = try self.strings.insert(gpa, self.entry_name.?);
        const gop = try self.get_or_create_global(off);
        self.entry_index = gop.index;
    }

    {
        const off = try self.strings.insert(gpa, "dyld_stub_binder");
        const gop = try self.get_or_create_global(off);
        self.dyld_stub_binder_index = gop.index;
    }

    {
        const off = try self.strings.insert(gpa, "_objc_msgSend");
        const gop = try self.get_or_create_global(off);
        self.objc_msg_send_index = gop.index;
    }
}

/// When resolving symbols, we approach the problem similarly to `mold`.
/// 1. Resolve symbols across all objects (including those preemptively extracted archives).
/// 2. Resolve symbols across all shared objects.
/// 3. Mark live objects (see `MachO.mark_live`)
/// 4. Reset state of all resolved globals since we will redo this bit on the pruned set.
/// 5. Remove references to dead objects/shared objects
/// 6. Re-run symbol resolution on pruned objects and shared objects sets.
pub fn resolve_symbols(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // Resolve symbols in the ZigObject. For now, we assume that it's always live.
    if (self.get_zig_object()) |zo| zo.as_file().resolve_symbols(self);
    // Resolve symbols on the set of all objects and shared objects (even if some are unneeded).
    for (self.objects.items) |index| self.get_file(index).?.resolve_symbols(self);
    for (self.dylibs.items) |index| self.get_file(index).?.resolve_symbols(self);

    // Mark live objects.
    self.mark_live();

    // Reset state of all globals after marking live objects.
    if (self.get_zig_object()) |zo| zo.as_file().reset_globals(self);
    for (self.objects.items) |index| self.get_file(index).?.reset_globals(self);
    for (self.dylibs.items) |index| self.get_file(index).?.reset_globals(self);

    // Prune dead objects.
    var i: usize = 0;
    while (i < self.objects.items.len) {
        const index = self.objects.items[i];
        if (!self.get_file(index).?.object.alive) {
            _ = self.objects.ordered_remove(i);
            self.files.items(.data)[index].object.deinit(self.base.comp.gpa);
            self.files.set(index, .null);
        } else i += 1;
    }

    // Re-resolve the symbols.
    if (self.get_zig_object()) |zo| zo.resolve_symbols(self);
    for (self.objects.items) |index| self.get_file(index).?.resolve_symbols(self);
    for (self.dylibs.items) |index| self.get_file(index).?.resolve_symbols(self);
}

fn mark_live(self: *MachO) void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.undefined_symbols.items) |index| {
        if (self.get_symbol(index).get_file(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }
    if (self.entry_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self)) |file| {
            if (file == .object) file.object.alive = true;
        }
    }
    if (self.get_zig_object()) |zo| zo.mark_live(self);
    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;
        if (object.alive) object.mark_live(self);
    }
}

pub fn parse_debug_info(self: *MachO) !void {
    for (self.objects.items) |index| {
        try self.get_file(index).?.object.parse_debug_info(self);
    }
}

fn resolve_synthetic_symbols(self: *MachO) !void {
    const internal = self.get_internal_object() orelse return;

    if (!self.base.is_dyn_lib()) {
        self.mh_execute_header_index = try internal.add_symbol("__mh_execute_header", self);
        const sym = self.get_symbol(self.mh_execute_header_index.?);
        sym.flags.@"export" = true;
        sym.flags.dyn_ref = true;
        sym.visibility = .global;
    } else {
        self.mh_dylib_header_index = try internal.add_symbol("__mh_dylib_header", self);
    }

    self.dso_handle_index = try internal.add_symbol("___dso_handle", self);
    self.dyld_private_index = try internal.add_symbol("dyld_private", self);

    {
        const gpa = self.base.comp.gpa;
        var boundary_symbols = std.AutoHashMap(Symbol.Index, void).init(gpa);
        defer boundary_symbols.deinit();

        for (self.objects.items) |index| {
            const object = self.get_file(index).?.object;
            for (object.symbols.items, 0..) |sym_index, i| {
                const nlist = object.symtab.items(.nlist)[i];
                const name = self.get_symbol(sym_index).get_name(self);
                if (!nlist.undf() or !nlist.ext()) continue;
                if (mem.starts_with(u8, name, "segment$start$") or
                    mem.starts_with(u8, name, "segment$stop$") or
                    mem.starts_with(u8, name, "section$start$") or
                    mem.starts_with(u8, name, "section$stop$"))
                {
                    _ = try boundary_symbols.put(sym_index, {});
                }
            }
        }

        try self.boundary_symbols.ensure_total_capacity_precise(gpa, boundary_symbols.count());

        var it = boundary_symbols.iterator();
        while (it.next()) |entry| {
            _ = try internal.add_symbol(self.get_symbol(entry.key_ptr.*).get_name(self), self);
            self.boundary_symbols.append_assume_capacity(entry.key_ptr.*);
        }
    }
}

fn convert_tentative_definitions(self: *MachO) !void {
    for (self.objects.items) |index| {
        try self.get_file(index).?.object.convert_tentative_definitions(self);
    }
}

fn create_objc_sections(self: *MachO) !void {
    const gpa = self.base.comp.gpa;
    var objc_msgsend_syms = std.AutoArrayHashMap(Symbol.Index, void).init(gpa);
    defer objc_msgsend_syms.deinit();

    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;

        for (object.symbols.items, 0..) |sym_index, i| {
            const nlist_idx = @as(Symbol.Index, @int_cast(i));
            const nlist = object.symtab.items(.nlist)[nlist_idx];
            if (!nlist.ext()) continue;
            if (!nlist.undf()) continue;

            const sym = self.get_symbol(sym_index);
            if (sym.get_file(self) != null) continue;
            if (mem.starts_with(u8, sym.get_name(self), "_objc_msgSend$")) {
                _ = try objc_msgsend_syms.put(sym_index, {});
            }
        }
    }

    for (objc_msgsend_syms.keys()) |sym_index| {
        const internal = self.get_internal_object().?;
        const sym = self.get_symbol(sym_index);
        _ = try internal.add_symbol(sym.get_name(self), self);
        sym.visibility = .hidden;
        const name = eat_prefix(sym.get_name(self), "_objc_msgSend$").?;
        const selrefs_index = try internal.add_objc_msgsend_sections(name, self);
        try sym.add_extra(.{ .objc_selrefs = selrefs_index }, self);
        sym.flags.objc_stubs = true;
    }
}

pub fn dedup_literals(self: *MachO) !void {
    const gpa = self.base.comp.gpa;
    var lp: LiteralPool = .{};
    defer lp.deinit(gpa);

    if (self.get_zig_object()) |zo| {
        try zo.resolve_literals(&lp, self);
    }
    for (self.objects.items) |index| {
        try self.get_file(index).?.object.resolve_literals(&lp, self);
    }
    if (self.get_internal_object()) |object| {
        try object.resolve_literals(&lp, self);
    }

    if (self.get_zig_object()) |zo| {
        zo.dedup_literals(lp, self);
    }
    for (self.objects.items) |index| {
        self.get_file(index).?.object.dedup_literals(lp, self);
    }
    if (self.get_internal_object()) |object| {
        object.dedup_literals(lp, self);
    }
}

fn claim_unresolved(self: *MachO) error{OutOfMemory}!void {
    if (self.get_zig_object()) |zo| {
        try zo.as_file().claim_unresolved(self);
    }
    for (self.objects.items) |index| {
        try self.get_file(index).?.claim_unresolved(self);
    }
}

fn check_duplicates(self: *MachO) !void {
    const gpa = self.base.comp.gpa;

    var dupes = std.AutoArrayHashMap(Symbol.Index, std.ArrayListUnmanaged(File.Index)).init(gpa);
    defer {
        for (dupes.values()) |*list| {
            list.deinit(gpa);
        }
        dupes.deinit();
    }

    if (self.get_zig_object()) |zo| {
        try zo.check_duplicates(&dupes, self);
    }

    for (self.objects.items) |index| {
        try self.get_file(index).?.object.check_duplicates(&dupes, self);
    }

    try self.report_duplicates(dupes);
}

fn mark_imports_and_exports(self: *MachO) void {
    if (self.get_zig_object()) |zo| {
        zo.as_file().mark_imports_exports(self);
    }
    for (self.objects.items) |index| {
        self.get_file(index).?.mark_imports_exports(self);
    }

    for (self.undefined_symbols.items) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self)) |file| {
            if (sym.visibility != .global) continue;
            if (file == .dylib and !sym.flags.abs) sym.flags.import = true;
        }
    }

    for (&[_]?Symbol.Index{
        self.entry_index,
        self.dyld_stub_binder_index,
        self.objc_msg_send_index,
    }) |index| {
        if (index) |idx| {
            const sym = self.get_symbol(idx);
            if (sym.get_file(self)) |file| {
                if (file == .dylib) sym.flags.import = true;
            }
        }
    }
}

fn dead_strip_dylibs(self: *MachO) void {
    for (&[_]?Symbol.Index{
        self.entry_index,
        self.dyld_stub_binder_index,
        self.objc_msg_send_index,
    }) |index| {
        if (index) |idx| {
            const sym = self.get_symbol(idx);
            if (sym.get_file(self)) |file| {
                if (file == .dylib) file.dylib.referenced = true;
            }
        }
    }

    for (self.dylibs.items) |index| {
        self.get_file(index).?.dylib.mark_referenced(self);
    }

    var i: usize = 0;
    while (i < self.dylibs.items.len) {
        const index = self.dylibs.items[i];
        if (!self.get_file(index).?.dylib.is_alive(self)) {
            _ = self.dylibs.ordered_remove(i);
            self.files.items(.data)[index].dylib.deinit(self.base.comp.gpa);
            self.files.set(index, .null);
        } else i += 1;
    }
}

fn scan_relocs(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (self.get_zig_object()) |zo| try zo.scan_relocs(self);

    for (self.objects.items) |index| {
        try self.get_file(index).?.object.scan_relocs(self);
    }

    try self.report_undefs();

    if (self.entry_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) != null) {
            if (sym.flags.import) sym.flags.stubs = true;
        }
    }

    if (self.dyld_stub_binder_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) != null) sym.flags.needs_got = true;
    }

    if (self.objc_msg_send_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) != null)
            sym.flags.needs_got = true; // TODO is it always needed, or only if we are synthesising fast stubs?
    }

    for (self.symbols.items, 0..) |*symbol, i| {
        const index = @as(Symbol.Index, @int_cast(i));
        if (symbol.flags.needs_got) {
            log.debug("'{s}' needs GOT", .{symbol.get_name(self)});
            try self.got.add_symbol(index, self);
        }
        if (symbol.flags.stubs) {
            log.debug("'{s}' needs STUBS", .{symbol.get_name(self)});
            try self.stubs.add_symbol(index, self);
        }
        if (symbol.flags.tlv_ptr) {
            log.debug("'{s}' needs TLV pointer", .{symbol.get_name(self)});
            try self.tlv_ptr.add_symbol(index, self);
        }
        if (symbol.flags.objc_stubs) {
            log.debug("'{s}' needs OBJC STUBS", .{symbol.get_name(self)});
            try self.objc_stubs.add_symbol(index, self);
        }
    }
}

fn report_undefs(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    switch (self.undefined_treatment) {
        .dynamic_lookup, .suppress => return,
        .@"error", .warn => {},
    }

    const max_notes = 4;

    var has_undefs = false;
    var it = self.undefs.iterator();
    while (it.next()) |entry| {
        const undef_sym = self.get_symbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @int_from_bool(notes.items.len > max_notes);

        var err = try self.add_error_with_notes(nnotes);
        try err.add_msg(self, "undefined symbol: {s}", .{undef_sym.get_name(self)});
        has_undefs = true;

        var inote: usize = 0;
        while (inote < @min(notes.items.len, max_notes)) : (inote += 1) {
            const atom = self.get_atom(notes.items[inote]).?;
            const file = atom.get_file(self);
            try err.add_note(self, "referenced by {}:{s}", .{ file.fmt_path(), atom.get_name(self) });
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.add_note(self, "referenced {d} more times", .{remaining});
        }
    }

    for (self.undefined_symbols.items) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) != null) continue; // If undefined in an object file, will be reported above
        has_undefs = true;
        var err = try self.add_error_with_notes(1);
        try err.add_msg(self, "undefined symbol: {s}", .{sym.get_name(self)});
        try err.add_note(self, "-u command line option", .{});
    }

    if (self.entry_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) == null) {
            has_undefs = true;
            var err = try self.add_error_with_notes(1);
            try err.add_msg(self, "undefined symbol: {s}", .{sym.get_name(self)});
            try err.add_note(self, "implicit entry/start for main executable", .{});
        }
    }

    if (self.dyld_stub_binder_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) == null and self.stubs_sect_index != null) {
            has_undefs = true;
            var err = try self.add_error_with_notes(1);
            try err.add_msg(self, "undefined symbol: {s}", .{sym.get_name(self)});
            try err.add_note(self, "implicit -u command line option", .{});
        }
    }

    if (self.objc_msg_send_index) |index| {
        const sym = self.get_symbol(index);
        if (sym.get_file(self) == null and self.objc_stubs_sect_index != null) {
            has_undefs = true;
            var err = try self.add_error_with_notes(1);
            try err.add_msg(self, "undefined symbol: {s}", .{sym.get_name(self)});
            try err.add_note(self, "implicit -u command line option", .{});
        }
    }

    if (has_undefs) return error.HasUndefinedSymbols;
}

fn init_output_sections(self: *MachO) !void {
    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.init_output_section(atom.get_input_section(self), self);
        }
    }
    if (self.get_internal_object()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = try Atom.init_output_section(atom.get_input_section(self), self);
        }
    }
    self.text_sect_index = self.get_section_by_name("__TEXT", "__text") orelse
        try self.add_section("__TEXT", "__text", .{
        .alignment = switch (self.get_target().cpu.arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => unreachable,
        },
        .flags = macho.S_REGULAR |
            macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
    });
    self.data_sect_index = self.get_section_by_name("__DATA", "__data") orelse
        try self.add_section("__DATA", "__data", .{});
}

fn init_synthetic_sections(self: *MachO) !void {
    const cpu_arch = self.get_target().cpu.arch;

    if (self.got.symbols.items.len > 0) {
        self.got_sect_index = try self.add_section("__DATA_CONST", "__got", .{
            .flags = macho.S_NON_LAZY_SYMBOL_POINTERS,
            .reserved1 = @int_cast(self.stubs.symbols.items.len),
        });
    }

    if (self.stubs.symbols.items.len > 0) {
        self.stubs_sect_index = try self.add_section("__TEXT", "__stubs", .{
            .flags = macho.S_SYMBOL_STUBS |
                macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
            .reserved1 = 0,
            .reserved2 = switch (cpu_arch) {
                .x86_64 => 6,
                .aarch64 => 3 * @size_of(u32),
                else => 0,
            },
        });
        self.stubs_helper_sect_index = try self.add_section("__TEXT", "__stub_helper", .{
            .flags = macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        self.la_symbol_ptr_sect_index = try self.add_section("__DATA", "__la_symbol_ptr", .{
            .flags = macho.S_LAZY_SYMBOL_POINTERS,
            .reserved1 = @int_cast(self.stubs.symbols.items.len + self.got.symbols.items.len),
        });
    }

    if (self.objc_stubs.symbols.items.len > 0) {
        self.objc_stubs_sect_index = try self.add_section("__TEXT", "__objc_stubs", .{
            .flags = macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
    }

    if (self.tlv_ptr.symbols.items.len > 0) {
        self.tlv_ptr_sect_index = try self.add_section("__DATA", "__thread_ptrs", .{
            .flags = macho.S_THREAD_LOCAL_VARIABLE_POINTERS,
        });
    }

    const needs_unwind_info = for (self.objects.items) |index| {
        if (self.get_file(index).?.object.has_unwind_records()) break true;
    } else false;
    if (needs_unwind_info) {
        self.unwind_info_sect_index = try self.add_section("__TEXT", "__unwind_info", .{});
    }

    const needs_eh_frame = for (self.objects.items) |index| {
        if (self.get_file(index).?.object.has_eh_frame_records()) break true;
    } else false;
    if (needs_eh_frame) {
        assert(needs_unwind_info);
        self.eh_frame_sect_index = try self.add_section("__TEXT", "__eh_frame", .{});
    }

    for (self.boundary_symbols.items) |sym_index| {
        const gpa = self.base.comp.gpa;
        const sym = self.get_symbol(sym_index);
        const name = sym.get_name(self);

        if (eat_prefix(name, "segment$start$")) |segname| {
            if (self.get_segment_by_name(segname) == null) { // TODO check segname is valid
                const prot = get_segment_prot(segname);
                _ = try self.segments.append(gpa, .{
                    .cmdsize = @size_of(macho.segment_command_64),
                    .segname = make_static_string(segname),
                    .initprot = prot,
                    .maxprot = prot,
                });
            }
        } else if (eat_prefix(name, "segment$stop$")) |segname| {
            if (self.get_segment_by_name(segname) == null) { // TODO check segname is valid
                const prot = get_segment_prot(segname);
                _ = try self.segments.append(gpa, .{
                    .cmdsize = @size_of(macho.segment_command_64),
                    .segname = make_static_string(segname),
                    .initprot = prot,
                    .maxprot = prot,
                });
            }
        } else if (eat_prefix(name, "section$start$")) |actual_name| {
            const sep = mem.index_of_scalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep]; // TODO check segname is valid
            const sectname = actual_name[sep + 1 ..]; // TODO check sectname is valid
            if (self.get_section_by_name(segname, sectname) == null) {
                _ = try self.add_section(segname, sectname, .{});
            }
        } else if (eat_prefix(name, "section$stop$")) |actual_name| {
            const sep = mem.index_of_scalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep]; // TODO check segname is valid
            const sectname = actual_name[sep + 1 ..]; // TODO check sectname is valid
            if (self.get_section_by_name(segname, sectname) == null) {
                _ = try self.add_section(segname, sectname, .{});
            }
        } else unreachable;
    }
}

fn get_segment_prot(segname: []const u8) macho.vm_prot_t {
    if (mem.eql(u8, segname, "__PAGEZERO")) return macho.PROT.NONE;
    if (mem.eql(u8, segname, "__TEXT")) return macho.PROT.READ | macho.PROT.EXEC;
    if (mem.eql(u8, segname, "__LINKEDIT")) return macho.PROT.READ;
    return macho.PROT.READ | macho.PROT.WRITE;
}

fn get_segment_rank(segname: []const u8) u8 {
    if (mem.eql(u8, segname, "__PAGEZERO")) return 0x0;
    if (mem.eql(u8, segname, "__LINKEDIT")) return 0xf;
    if (mem.index_of(u8, segname, "ZIG")) |_| return 0xe;
    if (mem.starts_with(u8, segname, "__TEXT")) return 0x1;
    if (mem.starts_with(u8, segname, "__DATA_CONST")) return 0x2;
    if (mem.starts_with(u8, segname, "__DATA")) return 0x3;
    return 0x4;
}

fn segment_less_than(ctx: void, lhs: []const u8, rhs: []const u8) bool {
    _ = ctx;
    const lhs_rank = get_segment_rank(lhs);
    const rhs_rank = get_segment_rank(rhs);
    if (lhs_rank == rhs_rank) {
        return mem.order(u8, lhs, rhs) == .lt;
    }
    return lhs_rank < rhs_rank;
}

fn get_section_rank(section: macho.section_64) u8 {
    if (section.is_code()) {
        if (mem.eql(u8, "__text", section.sect_name())) return 0x0;
        if (section.type() == macho.S_SYMBOL_STUBS) return 0x1;
        return 0x2;
    }
    switch (section.type()) {
        macho.S_NON_LAZY_SYMBOL_POINTERS,
        macho.S_LAZY_SYMBOL_POINTERS,
        => return 0x0,

        macho.S_MOD_INIT_FUNC_POINTERS => return 0x1,
        macho.S_MOD_TERM_FUNC_POINTERS => return 0x2,
        macho.S_ZEROFILL => return 0xf,
        macho.S_THREAD_LOCAL_REGULAR => return 0xd,
        macho.S_THREAD_LOCAL_ZEROFILL => return 0xe,

        else => {
            if (mem.eql(u8, "__unwind_info", section.sect_name())) return 0xe;
            if (mem.eql(u8, "__compact_unwind", section.sect_name())) return 0xe;
            if (mem.eql(u8, "__eh_frame", section.sect_name())) return 0xf;
            return 0x3;
        },
    }
}

fn section_less_than(ctx: void, lhs: macho.section_64, rhs: macho.section_64) bool {
    if (mem.eql(u8, lhs.seg_name(), rhs.seg_name())) {
        const lhs_rank = get_section_rank(lhs);
        const rhs_rank = get_section_rank(rhs);
        if (lhs_rank == rhs_rank) {
            return mem.order(u8, lhs.sect_name(), rhs.sect_name()) == .lt;
        }
        return lhs_rank < rhs_rank;
    }
    return segment_less_than(ctx, lhs.seg_name(), rhs.seg_name());
}

pub fn sort_sections(self: *MachO) !void {
    const Entry = struct {
        index: u8,

        pub fn less_than(macho_file: *MachO, lhs: @This(), rhs: @This()) bool {
            return section_less_than(
                {},
                macho_file.sections.items(.header)[lhs.index],
                macho_file.sections.items(.header)[rhs.index],
            );
        }
    };

    const gpa = self.base.comp.gpa;

    var entries = try std.ArrayList(Entry).init_capacity(gpa, self.sections.slice().len);
    defer entries.deinit();
    for (0..self.sections.slice().len) |index| {
        entries.append_assume_capacity(.{ .index = @int_cast(index) });
    }

    mem.sort(Entry, entries.items, self, Entry.less_than);

    const backlinks = try gpa.alloc(u8, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.index] = @int_cast(i);
    }

    var slice = self.sections.to_owned_slice();
    defer slice.deinit(gpa);

    try self.sections.ensure_total_capacity(gpa, slice.len);
    for (entries.items) |sorted| {
        self.sections.append_assume_capacity(slice.get(sorted.index));
    }

    if (self.get_zig_object()) |zo| {
        for (zo.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }

        for (zo.symtab.items(.nlist)) |*sym| {
            if (sym.sect()) {
                sym.n_sect = backlinks[sym.n_sect - 1] + 1;
            }
        }

        for (zo.symbols.items) |sym_index| {
            const sym = self.get_symbol(sym_index);
            const atom = sym.get_atom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.get_file(self).?.get_index() != zo.index) continue;
            sym.out_n_sect = backlinks[sym.out_n_sect];
        }
    }

    for (self.objects.items) |index| {
        for (self.get_file(index).?.object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }
    }

    if (self.get_internal_object()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            atom.out_n_sect = backlinks[atom.out_n_sect];
        }
    }

    for (&[_]*?u8{
        &self.data_sect_index,
        &self.got_sect_index,
        &self.zig_text_sect_index,
        &self.zig_got_sect_index,
        &self.zig_const_sect_index,
        &self.zig_data_sect_index,
        &self.zig_bss_sect_index,
        &self.stubs_sect_index,
        &self.stubs_helper_sect_index,
        &self.la_symbol_ptr_sect_index,
        &self.tlv_ptr_sect_index,
        &self.eh_frame_sect_index,
        &self.unwind_info_sect_index,
        &self.objc_stubs_sect_index,
        &self.debug_info_sect_index,
        &self.debug_str_sect_index,
        &self.debug_line_sect_index,
        &self.debug_abbrev_sect_index,
        &self.debug_info_sect_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }
}

pub fn add_atoms_to_sections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;
        for (object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.comp.gpa, atom_index);
        }
        for (object.symbols.items) |sym_index| {
            const sym = self.get_symbol(sym_index);
            const atom = sym.get_atom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.get_file(self).?.get_index() != index) continue;
            sym.out_n_sect = atom.out_n_sect;
        }
    }
    if (self.get_internal_object()) |object| {
        for (object.atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const atoms = &self.sections.items(.atoms)[atom.out_n_sect];
            try atoms.append(self.base.comp.gpa, atom_index);
        }
        for (object.symbols.items) |sym_index| {
            const sym = self.get_symbol(sym_index);
            const atom = sym.get_atom(self) orelse continue;
            if (!atom.flags.alive) continue;
            if (sym.get_file(self).?.get_index() != object.index) continue;
            sym.out_n_sect = atom.out_n_sect;
        }
    }
}

fn calc_section_sizes(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const cpu_arch = self.get_target().cpu.arch;

    if (self.data_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size += @size_of(u64);
        header.@"align" = 3;
    }

    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.atoms)) |*header, atoms| {
        if (atoms.items.len == 0) continue;
        if (self.requires_thunks() and header.is_code()) continue;

        for (atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index).?;
            const atom_alignment = atom.alignment.to_byte_units() orelse 1;
            const offset = mem.align_forward(u64, header.size, atom_alignment);
            const padding = offset - header.size;
            atom.value = offset;
            header.size += padding + atom.size;
            header.@"align" = @max(header.@"align", atom.alignment.to_log2_units());
        }
    }

    if (self.requires_thunks()) {
        for (slice.items(.header), slice.items(.atoms), 0..) |header, atoms, i| {
            if (!header.is_code()) continue;
            if (atoms.items.len == 0) continue;

            // Create jump/branch range extenders if needed.
            try thunks.create_thunks(@int_cast(i), self);
        }
    }

    if (self.got_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.got.size();
        header.@"align" = 3;
    }

    if (self.stubs_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.stubs.size(self);
        header.@"align" = switch (cpu_arch) {
            .x86_64 => 1,
            .aarch64 => 2,
            else => 0,
        };
    }

    if (self.stubs_helper_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.stubs_helper.size(self);
        header.@"align" = 2;
    }

    if (self.la_symbol_ptr_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.la_symbol_ptr.size(self);
        header.@"align" = 3;
    }

    if (self.tlv_ptr_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.tlv_ptr.size();
        header.@"align" = 3;
    }

    if (self.objc_stubs_sect_index) |idx| {
        const header = &self.sections.items(.header)[idx];
        header.size = self.objc_stubs.size(self);
        header.@"align" = switch (cpu_arch) {
            .x86_64 => 0,
            .aarch64 => 2,
            else => 0,
        };
    }
}

fn generate_unwind_info(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    if (self.eh_frame_sect_index) |index| {
        const sect = &self.sections.items(.header)[index];
        sect.size = try eh_frame.calc_size(self);
        sect.@"align" = 3;
    }
    if (self.unwind_info_sect_index) |index| {
        const sect = &self.sections.items(.header)[index];
        self.unwind_info.generate(self) catch |err| switch (err) {
            error.TooManyPersonalities => return self.report_unexpected_error(
                "too many personalities in unwind info",
                .{},
            ),
            else => |e| return e,
        };
        sect.size = self.unwind_info.calc_size();
        sect.@"align" = 2;
    }
}

fn init_segments(self: *MachO) !void {
    const gpa = self.base.comp.gpa;
    const slice = self.sections.slice();

    // Add __PAGEZERO if required
    const pagezero_size = self.pagezero_size orelse default_pagezero_size;
    const aligned_pagezero_size = mem.align_backward(u64, pagezero_size, self.get_page_size());
    if (!self.base.is_dyn_lib() and aligned_pagezero_size > 0) {
        if (aligned_pagezero_size != pagezero_size) {
            // TODO convert into a warning
            log.warn("requested __PAGEZERO size (0x{x}) is not page aligned", .{pagezero_size});
            log.warn("  rounding down to 0x{x}", .{aligned_pagezero_size});
        }
        self.pagezero_seg_index = try self.add_segment("__PAGEZERO", .{ .vmsize = aligned_pagezero_size });
    }

    // __TEXT segment is non-optional
    self.text_seg_index = try self.add_segment("__TEXT", .{ .prot = get_segment_prot("__TEXT") });

    // Next, create segments required by sections
    for (slice.items(.header)) |header| {
        const segname = header.seg_name();
        if (self.get_segment_by_name(segname) == null) {
            _ = try self.add_segment(segname, .{ .prot = get_segment_prot(segname) });
        }
    }

    // Add __LINKEDIT
    self.linkedit_seg_index = try self.add_segment("__LINKEDIT", .{ .prot = get_segment_prot("__LINKEDIT") });

    // Sort segments
    const Entry = struct {
        index: u8,

        pub fn less_than(macho_file: *MachO, lhs: @This(), rhs: @This()) bool {
            return segment_less_than(
                {},
                macho_file.segments.items[lhs.index].seg_name(),
                macho_file.segments.items[rhs.index].seg_name(),
            );
        }
    };

    var entries = try std.ArrayList(Entry).init_capacity(gpa, self.segments.items.len);
    defer entries.deinit();
    for (0..self.segments.items.len) |index| {
        entries.append_assume_capacity(.{ .index = @int_cast(index) });
    }

    mem.sort(Entry, entries.items, self, Entry.less_than);

    const backlinks = try gpa.alloc(u8, entries.items.len);
    defer gpa.free(backlinks);
    for (entries.items, 0..) |entry, i| {
        backlinks[entry.index] = @int_cast(i);
    }

    const segments = try self.segments.to_owned_slice(gpa);
    defer gpa.free(segments);

    try self.segments.ensure_total_capacity_precise(gpa, segments.len);
    for (entries.items) |sorted| {
        self.segments.append_assume_capacity(segments[sorted.index]);
    }

    for (&[_]*?u8{
        &self.pagezero_seg_index,
        &self.text_seg_index,
        &self.linkedit_seg_index,
        &self.zig_text_seg_index,
        &self.zig_got_seg_index,
        &self.zig_const_seg_index,
        &self.zig_data_seg_index,
        &self.zig_bss_seg_index,
    }) |maybe_index| {
        if (maybe_index.*) |*index| {
            index.* = backlinks[index.*];
        }
    }

    // Attach sections to segments
    for (slice.items(.header), slice.items(.segment_id)) |header, *seg_id| {
        const segname = header.seg_name();
        const segment_id = self.get_segment_by_name(segname) orelse blk: {
            const segment_id = @as(u8, @int_cast(self.segments.items.len));
            const protection = get_segment_prot(segname);
            try self.segments.append(gpa, .{
                .cmdsize = @size_of(macho.segment_command_64),
                .segname = make_static_string(segname),
                .maxprot = protection,
                .initprot = protection,
            });
            break :blk segment_id;
        };
        const segment = &self.segments.items[segment_id];
        segment.cmdsize += @size_of(macho.section_64);
        segment.nsects += 1;
        seg_id.* = segment_id;
    }

    // Set __DATA_CONST as READ_ONLY
    if (self.get_segment_by_name("__DATA_CONST")) |seg_id| {
        const seg = &self.segments.items[seg_id];
        seg.flags |= macho.SG_READ_ONLY;
    }
}

fn allocate_sections(self: *MachO) !void {
    const headerpad = try load_commands.calc_min_header_pad_size(self);
    var vmaddr: u64 = if (self.pagezero_seg_index) |index|
        self.segments.items[index].vmaddr + self.segments.items[index].vmsize
    else
        0;
    vmaddr += headerpad;
    var fileoff = headerpad;
    var prev_seg_id: u8 = if (self.pagezero_seg_index) |index| index + 1 else 0;

    const page_size = self.get_page_size();
    const slice = self.sections.slice();
    const last_index = for (0..slice.items(.header).len) |i| {
        if (self.is_zig_section(@int_cast(i))) break i;
    } else slice.items(.header).len;

    for (slice.items(.header)[0..last_index], slice.items(.segment_id)[0..last_index]) |*header, curr_seg_id| {
        if (prev_seg_id != curr_seg_id) {
            vmaddr = mem.align_forward(u64, vmaddr, page_size);
            fileoff = mem.align_forward(u32, fileoff, page_size);
        }

        const alignment = try math.powi(u32, 2, header.@"align");

        vmaddr = mem.align_forward(u64, vmaddr, alignment);
        header.addr = vmaddr;
        vmaddr += header.size;

        if (!header.is_zerofill()) {
            fileoff = mem.align_forward(u32, fileoff, alignment);
            header.offset = fileoff;
            fileoff += @int_cast(header.size);
        }

        prev_seg_id = curr_seg_id;
    }

    fileoff = mem.align_forward(u32, fileoff, page_size);
    for (slice.items(.header)[last_index..], slice.items(.segment_id)[last_index..]) |*header, seg_id| {
        if (header.is_zerofill()) continue;
        if (header.offset < fileoff) {
            const existing_size = header.size;
            header.size = 0;

            // Must move the entire section.
            const new_offset = self.find_free_space(existing_size, page_size);

            log.debug("moving '{s},{s}' from 0x{x} to 0x{x}", .{
                header.seg_name(),
                header.sect_name(),
                header.offset,
                new_offset,
            });

            try self.copy_range_all_zero_out(header.offset, new_offset, existing_size);

            header.offset = @int_cast(new_offset);
            header.size = existing_size;
            self.segments.items[seg_id].fileoff = new_offset;
        }
    }
}

/// We allocate segments in a separate step to also consider segments that have no sections.
fn allocate_segments(self: *MachO) void {
    const first_index = if (self.pagezero_seg_index) |index| index + 1 else 0;
    const last_index = for (0..self.segments.items.len) |i| {
        if (self.is_zig_segment(@int_cast(i))) break i;
    } else self.segments.items.len;

    var vmaddr: u64 = if (self.pagezero_seg_index) |index|
        self.segments.items[index].vmaddr + self.segments.items[index].vmsize
    else
        0;
    var fileoff: u64 = 0;

    const page_size = self.get_page_size();
    const slice = self.sections.slice();

    var next_sect_id: u8 = 0;
    for (self.segments.items[first_index..last_index], first_index..last_index) |*seg, seg_id| {
        seg.vmaddr = vmaddr;
        seg.fileoff = fileoff;

        while (next_sect_id < slice.items(.header).len) : (next_sect_id += 1) {
            const header = slice.items(.header)[next_sect_id];
            const sid = slice.items(.segment_id)[next_sect_id];

            if (seg_id != sid) break;

            vmaddr = header.addr + header.size;
            if (!header.is_zerofill()) {
                fileoff = header.offset + header.size;
            }
        }

        seg.vmsize = vmaddr - seg.vmaddr;
        seg.filesize = fileoff - seg.fileoff;

        vmaddr = mem.align_forward(u64, vmaddr, page_size);
        fileoff = mem.align_forward(u64, fileoff, page_size);
    }
}

fn allocate_synthetic_symbols(self: *MachO) void {
    const text_seg = self.get_text_segment();

    if (self.mh_execute_header_index) |index| {
        const global = self.get_symbol(index);
        global.value = text_seg.vmaddr;
    }

    if (self.data_sect_index) |idx| {
        const sect = self.sections.items(.header)[idx];
        for (&[_]?Symbol.Index{
            self.dso_handle_index,
            self.mh_dylib_header_index,
            self.dyld_private_index,
        }) |maybe_index| {
            if (maybe_index) |index| {
                const global = self.get_symbol(index);
                global.value = sect.addr;
                global.out_n_sect = idx;
            }
        }
    }

    for (self.boundary_symbols.items) |sym_index| {
        const sym = self.get_symbol(sym_index);
        const name = sym.get_name(self);

        sym.flags.@"export" = false;
        sym.value = text_seg.vmaddr;

        if (mem.starts_with(u8, name, "segment$start$")) {
            const segname = name["segment$start$".len..];
            if (self.get_segment_by_name(segname)) |seg_id| {
                const seg = self.segments.items[seg_id];
                sym.value = seg.vmaddr;
            }
        } else if (mem.starts_with(u8, name, "segment$stop$")) {
            const segname = name["segment$stop$".len..];
            if (self.get_segment_by_name(segname)) |seg_id| {
                const seg = self.segments.items[seg_id];
                sym.value = seg.vmaddr + seg.vmsize;
            }
        } else if (mem.starts_with(u8, name, "section$start$")) {
            const actual_name = name["section$start$".len..];
            const sep = mem.index_of_scalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep];
            const sectname = actual_name[sep + 1 ..];
            if (self.get_section_by_name(segname, sectname)) |sect_id| {
                const sect = self.sections.items(.header)[sect_id];
                sym.value = sect.addr;
                sym.out_n_sect = sect_id;
            }
        } else if (mem.starts_with(u8, name, "section$stop$")) {
            const actual_name = name["section$stop$".len..];
            const sep = mem.index_of_scalar(u8, actual_name, '$').?; // TODO error rather than a panic
            const segname = actual_name[0..sep];
            const sectname = actual_name[sep + 1 ..];
            if (self.get_section_by_name(segname, sectname)) |sect_id| {
                const sect = self.sections.items(.header)[sect_id];
                sym.value = sect.addr + sect.size;
                sym.out_n_sect = sect_id;
            }
        } else unreachable;
    }

    if (self.objc_stubs.symbols.items.len > 0) {
        const addr = self.sections.items(.header)[self.objc_stubs_sect_index.?].addr;

        for (self.objc_stubs.symbols.items, 0..) |sym_index, idx| {
            const sym = self.get_symbol(sym_index);
            sym.value = addr + idx * ObjcStubsSection.entry_size(self.get_target().cpu.arch);
            sym.out_n_sect = self.objc_stubs_sect_index.?;
        }
    }
}

fn allocate_linkedit_segment(self: *MachO) !void {
    var fileoff: u64 = 0;
    var vmaddr: u64 = 0;

    for (self.segments.items) |seg| {
        if (fileoff < seg.fileoff + seg.filesize) fileoff = seg.fileoff + seg.filesize;
        if (vmaddr < seg.vmaddr + seg.vmsize) vmaddr = seg.vmaddr + seg.vmsize;
    }

    const page_size = self.get_page_size();
    const seg = self.get_linkedit_segment();
    seg.vmaddr = mem.align_forward(u64, vmaddr, page_size);
    seg.fileoff = mem.align_forward(u64, fileoff, page_size);
}

fn init_dyld_info_sections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;

    if (self.zig_got_sect_index != null) try self.zig_got.add_dyld_relocs(self);
    if (self.got_sect_index != null) try self.got.add_dyld_relocs(self);
    if (self.tlv_ptr_sect_index != null) try self.tlv_ptr.add_dyld_relocs(self);
    if (self.la_symbol_ptr_sect_index != null) try self.la_symbol_ptr.add_dyld_relocs(self);
    try self.init_export_trie();

    var objects = try std.ArrayList(File.Index).init_capacity(gpa, self.objects.items.len + 1);
    defer objects.deinit();
    if (self.get_zig_object()) |zo| objects.append_assume_capacity(zo.index);
    objects.append_slice_assume_capacity(self.objects.items);

    var nrebases: usize = 0;
    var nbinds: usize = 0;
    var nweak_binds: usize = 0;
    for (objects.items) |index| {
        const ctx = switch (self.get_file(index).?) {
            .zig_object => |x| x.dynamic_relocs,
            .object => |x| x.dynamic_relocs,
            else => unreachable,
        };
        nrebases += ctx.rebase_relocs;
        nbinds += ctx.bind_relocs;
        nweak_binds += ctx.weak_bind_relocs;
    }
    if (self.get_internal_object()) |int| {
        nrebases += int.num_rebase_relocs;
    }
    try self.rebase.entries.ensure_unused_capacity(gpa, nrebases);
    try self.bind.entries.ensure_unused_capacity(gpa, nbinds);
    try self.weak_bind.entries.ensure_unused_capacity(gpa, nweak_binds);
}

fn init_export_trie(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    try self.export_trie.init(gpa);

    const seg = self.get_text_segment();
    for (self.objects.items) |index| {
        for (self.get_file(index).?.get_symbols()) |sym_index| {
            const sym = self.get_symbol(sym_index);
            if (!sym.flags.@"export") continue;
            if (sym.get_atom(self)) |atom| if (!atom.flags.alive) continue;
            if (sym.get_file(self).?.get_index() != index) continue;
            var flags: u64 = if (sym.flags.abs)
                macho.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE
            else if (sym.flags.tlv)
                macho.EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL
            else
                macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR;
            if (sym.flags.weak) {
                flags |= macho.EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION;
                self.weak_defines = true;
                self.binds_to_weak = true;
            }
            try self.export_trie.put(gpa, .{
                .name = sym.get_name(self),
                .vmaddr_offset = sym.get_address(.{ .stubs = false }, self) - seg.vmaddr,
                .export_flags = flags,
            });
        }
    }

    if (self.mh_execute_header_index) |index| {
        const sym = self.get_symbol(index);
        try self.export_trie.put(gpa, .{
            .name = sym.get_name(self),
            .vmaddr_offset = sym.get_address(.{}, self) - seg.vmaddr,
            .export_flags = macho.EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }
}

fn write_atoms(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    const cpu_arch = self.get_target().cpu.arch;
    const slice = self.sections.slice();

    var has_resolve_error = false;
    for (slice.items(.header), slice.items(.atoms)) |header, atoms| {
        if (atoms.items.len == 0) continue;
        if (header.is_zerofill()) continue;

        const size = math.cast(usize, header.size) orelse return error.Overflow;
        const buffer = try gpa.alloc(u8, size);
        defer gpa.free(buffer);
        const padding_byte: u8 = if (header.is_code() and cpu_arch == .x86_64) 0xcc else 0;
        @memset(buffer, padding_byte);

        for (atoms.items) |atom_index| {
            const atom = self.get_atom(atom_index).?;
            assert(atom.flags.alive);
            const off = math.cast(usize, atom.value) orelse return error.Overflow;
            const atom_size = math.cast(usize, atom.size) orelse return error.Overflow;
            try atom.get_data(self, buffer[off..][0..atom_size]);
            atom.resolve_relocs(self, buffer[off..][0..atom_size]) catch |err| switch (err) {
                error.ResolveFailed => has_resolve_error = true,
                else => |e| return e,
            };
        }

        try self.base.file.?.pwrite_all(buffer, header.offset);
    }

    for (self.thunks.items) |thunk| {
        const header = slice.items(.header)[thunk.out_n_sect];
        const offset = thunk.value + header.offset;
        const buffer = try gpa.alloc(u8, thunk.size());
        defer gpa.free(buffer);
        var stream = std.io.fixed_buffer_stream(buffer);
        try thunk.write(self, stream.writer());
        try self.base.file.?.pwrite_all(buffer, offset);
    }

    if (has_resolve_error) return error.ResolveFailed;
}

fn write_unwind_info(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;

    if (self.eh_frame_sect_index) |index| {
        const header = self.sections.items(.header)[index];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        const buffer = try gpa.alloc(u8, size);
        defer gpa.free(buffer);
        eh_frame.write(self, buffer);
        try self.base.file.?.pwrite_all(buffer, header.offset);
    }

    if (self.unwind_info_sect_index) |index| {
        const header = self.sections.items(.header)[index];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        const buffer = try gpa.alloc(u8, size);
        defer gpa.free(buffer);
        try self.unwind_info.write(self, buffer);
        try self.base.file.?.pwrite_all(buffer, header.offset);
    }
}

fn finalize_dyld_info_sections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.comp.gpa;

    try self.rebase.finalize(gpa);
    try self.bind.finalize(gpa, self);
    try self.weak_bind.finalize(gpa, self);
    try self.lazy_bind.finalize(gpa, self);
    try self.export_trie.finalize(gpa);
}

fn write_synthetic_sections(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;

    if (self.got_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.got.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }

    if (self.stubs_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.stubs.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }

    if (self.stubs_helper_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.stubs_helper.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }

    if (self.la_symbol_ptr_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.la_symbol_ptr.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }

    if (self.tlv_ptr_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.tlv_ptr.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }

    if (self.objc_stubs_sect_index) |sect_id| {
        const header = self.sections.items(.header)[sect_id];
        const size = math.cast(usize, header.size) orelse return error.Overflow;
        var buffer = try std.ArrayList(u8).init_capacity(gpa, size);
        defer buffer.deinit();
        try self.objc_stubs.write(self, buffer.writer());
        assert(buffer.items.len == header.size);
        try self.base.file.?.pwrite_all(buffer.items, header.offset);
    }
}

fn write_dyld_info_sections(self: *MachO, off: u32) !u32 {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.base.comp.gpa;
    const cmd = &self.dyld_info_cmd;
    var needed_size: u32 = 0;

    cmd.rebase_off = needed_size;
    cmd.rebase_size = mem.align_forward(u32, @int_cast(self.rebase.size()), @alignOf(u64));
    needed_size += cmd.rebase_size;

    cmd.bind_off = needed_size;
    cmd.bind_size = mem.align_forward(u32, @int_cast(self.bind.size()), @alignOf(u64));
    needed_size += cmd.bind_size;

    cmd.weak_bind_off = needed_size;
    cmd.weak_bind_size = mem.align_forward(u32, @int_cast(self.weak_bind.size()), @alignOf(u64));
    needed_size += cmd.weak_bind_size;

    cmd.lazy_bind_off = needed_size;
    cmd.lazy_bind_size = mem.align_forward(u32, @int_cast(self.lazy_bind.size()), @alignOf(u64));
    needed_size += cmd.lazy_bind_size;

    cmd.export_off = needed_size;
    cmd.export_size = mem.align_forward(u32, @int_cast(self.export_trie.size), @alignOf(u64));
    needed_size += cmd.export_size;

    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);
    @memset(buffer, 0);

    var stream = std.io.fixed_buffer_stream(buffer);
    const writer = stream.writer();

    try self.rebase.write(writer);
    try stream.seek_to(cmd.bind_off);
    try self.bind.write(writer);
    try stream.seek_to(cmd.weak_bind_off);
    try self.weak_bind.write(writer);
    try stream.seek_to(cmd.lazy_bind_off);
    try self.lazy_bind.write(writer);
    try stream.seek_to(cmd.export_off);
    try self.export_trie.write(writer);

    cmd.rebase_off += off;
    cmd.bind_off += off;
    cmd.weak_bind_off += off;
    cmd.lazy_bind_off += off;
    cmd.export_off += off;

    try self.base.file.?.pwrite_all(buffer, off);

    return off + needed_size;
}

fn write_function_starts(self: *MachO, off: u32) !u32 {
    // TODO actually write it out
    const cmd = &self.function_starts_cmd;
    cmd.dataoff = off;
    return off;
}

pub fn write_data_in_code(self: *MachO, base_address: u64, off: u32) !u32 {
    const cmd = &self.data_in_code_cmd;
    cmd.dataoff = off;

    const gpa = self.base.comp.gpa;
    var dices = std.ArrayList(macho.data_in_code_entry).init(gpa);
    defer dices.deinit();

    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;
        const in_dices = object.get_data_in_code();

        try dices.ensure_unused_capacity(in_dices.len);

        var next_dice: usize = 0;
        for (object.atoms.items) |atom_index| {
            if (next_dice >= in_dices.len) break;
            const atom = self.get_atom(atom_index) orelse continue;
            const start_off = atom.get_input_address(self);
            const end_off = start_off + atom.size;
            const start_dice = next_dice;

            if (end_off < in_dices[next_dice].offset) continue;

            while (next_dice < in_dices.len and
                in_dices[next_dice].offset < end_off) : (next_dice += 1)
            {}

            if (atom.flags.alive) for (in_dices[start_dice..next_dice]) |dice| {
                dices.append_assume_capacity(.{
                    .offset = @int_cast(atom.get_address(self) + dice.offset - start_off - base_address),
                    .length = dice.length,
                    .kind = dice.kind,
                });
            };
        }
    }

    const needed_size = math.cast(u32, dices.items.len * @size_of(macho.data_in_code_entry)) orelse return error.Overflow;
    cmd.datasize = needed_size;

    try self.base.file.?.pwrite_all(mem.slice_as_bytes(dices.items), cmd.dataoff);

    return off + needed_size;
}

pub fn calc_symtab_size(self: *MachO) !void {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.comp.gpa;

    var nlocals: u32 = 0;
    var nstabs: u32 = 0;
    var nexports: u32 = 0;
    var nimports: u32 = 0;
    var strsize: u32 = 0;

    var files = std.ArrayList(File.Index).init(gpa);
    defer files.deinit();
    try files.ensure_total_capacity_precise(self.objects.items.len + self.dylibs.items.len + 2);
    if (self.zig_object) |index| files.append_assume_capacity(index);
    for (self.objects.items) |index| files.append_assume_capacity(index);
    for (self.dylibs.items) |index| files.append_assume_capacity(index);
    if (self.internal_object) |index| files.append_assume_capacity(index);

    for (files.items) |index| {
        const file = self.get_file(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.ilocal = nlocals;
        ctx.istab = nstabs;
        ctx.iexport = nexports;
        ctx.iimport = nimports;
        try file.calc_symtab_size(self);
        nlocals += ctx.nlocals;
        nstabs += ctx.nstabs;
        nexports += ctx.nexports;
        nimports += ctx.nimports;
        strsize += ctx.strsize;
    }

    for (files.items) |index| {
        const file = self.get_file(index).?;
        const ctx = switch (file) {
            inline else => |x| &x.output_symtab_ctx,
        };
        ctx.istab += nlocals;
        ctx.iexport += nlocals + nstabs;
        ctx.iimport += nlocals + nstabs + nexports;
    }

    {
        const cmd = &self.symtab_cmd;
        cmd.nsyms = nlocals + nstabs + nexports + nimports;
        cmd.strsize = strsize + 1;
    }

    {
        const cmd = &self.dysymtab_cmd;
        cmd.ilocalsym = 0;
        cmd.nlocalsym = nlocals + nstabs;
        cmd.iextdefsym = nlocals + nstabs;
        cmd.nextdefsym = nexports;
        cmd.iundefsym = nlocals + nstabs + nexports;
        cmd.nundefsym = nimports;
    }
}

pub fn write_symtab(self: *MachO, off: u32) !u32 {
    const tracy = trace(@src());
    defer tracy.end();
    const gpa = self.base.comp.gpa;
    const cmd = &self.symtab_cmd;
    cmd.symoff = off;

    try self.symtab.resize(gpa, cmd.nsyms);
    try self.strtab.ensure_unused_capacity(gpa, cmd.strsize - 1);

    if (self.get_zig_object()) |zo| {
        zo.write_symtab(self, self);
    }
    for (self.objects.items) |index| {
        try self.get_file(index).?.write_symtab(self, self);
    }
    for (self.dylibs.items) |index| {
        try self.get_file(index).?.write_symtab(self, self);
    }
    if (self.get_internal_object()) |internal| {
        internal.write_symtab(self, self);
    }

    assert(self.strtab.items.len == cmd.strsize);

    try self.base.file.?.pwrite_all(mem.slice_as_bytes(self.symtab.items), cmd.symoff);

    return off + cmd.nsyms * @size_of(macho.nlist_64);
}

fn write_indsymtab(self: *MachO, off: u32) !u32 {
    const gpa = self.base.comp.gpa;
    const cmd = &self.dysymtab_cmd;
    cmd.indirectsymoff = off;
    cmd.nindirectsyms = self.indsymtab.nsyms(self);

    const needed_size = cmd.nindirectsyms * @size_of(u32);
    var buffer = try std.ArrayList(u8).init_capacity(gpa, needed_size);
    defer buffer.deinit();
    try self.indsymtab.write(self, buffer.writer());

    try self.base.file.?.pwrite_all(buffer.items, cmd.indirectsymoff);
    assert(buffer.items.len == needed_size);

    return off + needed_size;
}

pub fn write_strtab(self: *MachO, off: u32) !u32 {
    const cmd = &self.symtab_cmd;
    cmd.stroff = off;
    try self.base.file.?.pwrite_all(self.strtab.items, cmd.stroff);
    return off + cmd.strsize;
}

fn write_load_commands(self: *MachO) !struct { usize, usize, u64 } {
    const gpa = self.base.comp.gpa;
    const needed_size = try load_commands.calc_load_commands_size(self, false);
    const buffer = try gpa.alloc(u8, needed_size);
    defer gpa.free(buffer);

    var stream = std.io.fixed_buffer_stream(buffer);
    const writer = stream.writer();

    var ncmds: usize = 0;

    // Segment and section load commands
    {
        const slice = self.sections.slice();
        var sect_id: usize = 0;
        for (self.segments.items) |seg| {
            try writer.write_struct(seg);
            for (slice.items(.header)[sect_id..][0..seg.nsects]) |header| {
                try writer.write_struct(header);
            }
            sect_id += seg.nsects;
        }
        ncmds += self.segments.items.len;
    }

    try writer.write_struct(self.dyld_info_cmd);
    ncmds += 1;
    try writer.write_struct(self.function_starts_cmd);
    ncmds += 1;
    try writer.write_struct(self.data_in_code_cmd);
    ncmds += 1;
    try writer.write_struct(self.symtab_cmd);
    ncmds += 1;
    try writer.write_struct(self.dysymtab_cmd);
    ncmds += 1;
    try load_commands.write_dylinker_lc(writer);
    ncmds += 1;

    if (self.entry_index) |global_index| {
        const sym = self.get_symbol(global_index);
        const seg = self.get_text_segment();
        const entryoff: u32 = if (sym.get_file(self) == null)
            0
        else
            @as(u32, @int_cast(sym.get_address(.{ .stubs = true }, self) - seg.vmaddr));
        try writer.write_struct(macho.entry_point_command{
            .entryoff = entryoff,
            .stacksize = self.base.stack_size,
        });
        ncmds += 1;
    }

    if (self.base.is_dyn_lib()) {
        try load_commands.write_dylib_id_lc(self, writer);
        ncmds += 1;
    }

    try load_commands.write_rpath_lcs(self.base.rpath_list, writer);
    ncmds += self.base.rpath_list.len;

    try writer.write_struct(macho.source_version_command{ .version = 0 });
    ncmds += 1;

    if (self.platform.is_build_version_compatible()) {
        try load_commands.write_build_version_lc(self.platform, self.sdk_version, writer);
        ncmds += 1;
    } else {
        try load_commands.write_version_min_lc(self.platform, self.sdk_version, writer);
        ncmds += 1;
    }

    const uuid_cmd_offset = @size_of(macho.mach_header_64) + stream.pos;
    try writer.write_struct(self.uuid_cmd);
    ncmds += 1;

    for (self.dylibs.items) |index| {
        const dylib = self.get_file(index).?.dylib;
        assert(dylib.is_alive(self));
        const dylib_id = dylib.id.?;
        try load_commands.write_dylib_lc(.{
            .cmd = if (dylib.weak)
                .LOAD_WEAK_DYLIB
            else if (dylib.reexport)
                .REEXPORT_DYLIB
            else
                .LOAD_DYLIB,
            .name = dylib_id.name,
            .timestamp = dylib_id.timestamp,
            .current_version = dylib_id.current_version,
            .compatibility_version = dylib_id.compatibility_version,
        }, writer);
        ncmds += 1;
    }

    if (self.requires_code_sig()) {
        try writer.write_struct(self.codesig_cmd);
        ncmds += 1;
    }

    assert(stream.pos == needed_size);

    try self.base.file.?.pwrite_all(buffer, @size_of(macho.mach_header_64));

    return .{ ncmds, buffer.len, uuid_cmd_offset };
}

fn write_header(self: *MachO, ncmds: usize, sizeofcmds: usize) !void {
    var header: macho.mach_header_64 = .{};
    header.flags = macho.MH_NOUNDEFS | macho.MH_DYLDLINK;

    // TODO: if (self.options.namespace == .two_level) {
    header.flags |= macho.MH_TWOLEVEL;
    // }

    switch (self.get_target().cpu.arch) {
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

    if (self.base.is_dyn_lib()) {
        header.filetype = macho.MH_DYLIB;
    } else {
        header.filetype = macho.MH_EXECUTE;
        header.flags |= macho.MH_PIE;
    }

    const has_reexports = for (self.dylibs.items) |index| {
        if (self.get_file(index).?.dylib.reexport) break true;
    } else false;
    if (!has_reexports) {
        header.flags |= macho.MH_NO_REEXPORTED_DYLIBS;
    }

    if (self.has_tlv) {
        header.flags |= macho.MH_HAS_TLV_DESCRIPTORS;
    }
    if (self.binds_to_weak) {
        header.flags |= macho.MH_BINDS_TO_WEAK;
    }
    if (self.weak_defines) {
        header.flags |= macho.MH_WEAK_DEFINES;
    }

    header.ncmds = @int_cast(ncmds);
    header.sizeofcmds = @int_cast(sizeofcmds);

    log.debug("writing Mach-O header {}", .{header});

    try self.base.file.?.pwrite_all(mem.as_bytes(&header), 0);
}

fn write_uuid(self: *MachO, uuid_cmd_offset: u64, has_codesig: bool) !void {
    const file_size = if (!has_codesig) blk: {
        const seg = self.get_linkedit_segment();
        break :blk seg.fileoff + seg.filesize;
    } else self.codesig_cmd.dataoff;
    try calc_uuid(self.base.comp, self.base.file.?, file_size, &self.uuid_cmd.uuid);
    const offset = uuid_cmd_offset + @size_of(macho.load_command);
    try self.base.file.?.pwrite_all(&self.uuid_cmd.uuid, offset);
}

pub fn write_code_signature_padding(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = self.get_linkedit_segment();
    // Code signature data has to be 16-bytes aligned for Apple tools to recognize the file
    // https://github.com/opensource-apple/cctools/blob/fdb4825f303fd5c0751be524babd32958181b3ed/libstuff/checkout.c#L271
    const offset = mem.align_forward(u64, seg.fileoff + seg.filesize, 16);
    const needed_size = code_sig.estimate_size(offset);
    seg.filesize = offset + needed_size - seg.fileoff;
    seg.vmsize = mem.align_forward(u64, seg.filesize, self.get_page_size());
    log.debug("writing code signature padding from 0x{x} to 0x{x}", .{ offset, offset + needed_size });
    // Pad out the space. We need to do this to calculate valid hashes for everything in the file
    // except for code signature data.
    try self.base.file.?.pwrite_all(&[_]u8{0}, offset + needed_size - 1);

    self.codesig_cmd.dataoff = @as(u32, @int_cast(offset));
    self.codesig_cmd.datasize = @as(u32, @int_cast(needed_size));
}

pub fn write_code_signature(self: *MachO, code_sig: *CodeSignature) !void {
    const seg = self.get_text_segment();
    const offset = self.codesig_cmd.dataoff;

    var buffer = std.ArrayList(u8).init(self.base.comp.gpa);
    defer buffer.deinit();
    try buffer.ensure_total_capacity_precise(code_sig.size());
    try code_sig.write_adhoc_signature(self, .{
        .file = self.base.file.?,
        .exec_seg_base = seg.fileoff,
        .exec_seg_limit = seg.filesize,
        .file_size = offset,
        .dylib = self.base.is_dyn_lib(),
    }, buffer.writer());
    assert(buffer.items.len == code_sig.size());

    log.debug("writing code signature from 0x{x} to 0x{x}", .{
        offset,
        offset + buffer.items.len,
    });

    try self.base.file.?.pwrite_all(buffer.items, offset);
}

pub fn update_func(self: *MachO, mod: *Module, func_index: InternPool.Index, air: Air, liveness: Liveness) !void {
    if (build_options.skip_non_native and builtin.object_format != .macho) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (self.llvm_object) |llvm_object| return llvm_object.update_func(mod, func_index, air, liveness);
    return self.get_zig_object().?.update_func(self, mod, func_index, air, liveness);
}

pub fn lower_unnamed_const(self: *MachO, val: Value, decl_index: InternPool.DeclIndex) !u32 {
    return self.get_zig_object().?.lower_unnamed_const(self, val, decl_index);
}

pub fn update_decl(self: *MachO, mod: *Module, decl_index: InternPool.DeclIndex) !void {
    if (build_options.skip_non_native and builtin.object_format != .macho) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (self.llvm_object) |llvm_object| return llvm_object.update_decl(mod, decl_index);
    return self.get_zig_object().?.update_decl(self, mod, decl_index);
}

pub fn update_decl_line_number(self: *MachO, module: *Module, decl_index: InternPool.DeclIndex) !void {
    if (self.llvm_object) |_| return;
    return self.get_zig_object().?.update_decl_line_number(module, decl_index);
}

pub fn update_exports(
    self: *MachO,
    mod: *Module,
    exported: Module.Exported,
    exports: []const *Module.Export,
) link.File.UpdateExportsError!void {
    if (build_options.skip_non_native and builtin.object_format != .macho) {
        @panic("Attempted to compile for object format that was disabled by build configuration");
    }
    if (self.llvm_object) |llvm_object| return llvm_object.update_exports(mod, exported, exports);
    return self.get_zig_object().?.update_exports(self, mod, exported, exports);
}

pub fn delete_decl_export(
    self: *MachO,
    decl_index: InternPool.DeclIndex,
    name: InternPool.NullTerminatedString,
) Allocator.Error!void {
    if (self.llvm_object) |_| return;
    return self.get_zig_object().?.delete_decl_export(self, decl_index, name);
}

pub fn free_decl(self: *MachO, decl_index: InternPool.DeclIndex) void {
    if (self.llvm_object) |llvm_object| return llvm_object.free_decl(decl_index);
    return self.get_zig_object().?.free_decl(decl_index);
}

pub fn get_decl_vaddr(self: *MachO, decl_index: InternPool.DeclIndex, reloc_info: link.File.RelocInfo) !u64 {
    assert(self.llvm_object == null);
    return self.get_zig_object().?.get_decl_vaddr(self, decl_index, reloc_info);
}

pub fn lower_anon_decl(
    self: *MachO,
    decl_val: InternPool.Index,
    explicit_alignment: InternPool.Alignment,
    src_loc: Module.SrcLoc,
) !codegen.Result {
    return self.get_zig_object().?.lower_anon_decl(self, decl_val, explicit_alignment, src_loc);
}

pub fn get_anon_decl_vaddr(self: *MachO, decl_val: InternPool.Index, reloc_info: link.File.RelocInfo) !u64 {
    assert(self.llvm_object == null);
    return self.get_zig_object().?.get_anon_decl_vaddr(self, decl_val, reloc_info);
}

pub fn get_global_symbol(self: *MachO, name: []const u8, lib_name: ?[]const u8) !u32 {
    return self.get_zig_object().?.get_global_symbol(self, name, lib_name);
}

pub fn pad_to_ideal(actual_size: anytype) @TypeOf(actual_size) {
    return actual_size +| (actual_size / ideal_factor);
}

fn detect_alloc_collision(self: *MachO, start: u64, size: u64) ?u64 {
    // Conservatively commit one page size as reserved space for the headers as we
    // expect it to grow and everything else be moved in flush anyhow.
    const header_size = self.get_page_size();
    if (start < header_size)
        return header_size;

    const end = start + pad_to_ideal(size);

    for (self.sections.items(.header)) |header| {
        if (header.is_zerofill()) continue;
        const increased_size = pad_to_ideal(header.size);
        const test_end = header.offset +| increased_size;
        if (end > header.offset and start < test_end) {
            return test_end;
        }
    }

    for (self.segments.items) |seg| {
        const increased_size = pad_to_ideal(seg.filesize);
        const test_end = seg.fileoff +| increased_size;
        if (end > seg.fileoff and start < test_end) {
            return test_end;
        }
    }

    return null;
}

fn detect_alloc_collision_virtual(self: *MachO, start: u64, size: u64) ?u64 {
    // Conservatively commit one page size as reserved space for the headers as we
    // expect it to grow and everything else be moved in flush anyhow.
    const header_size = self.get_page_size();
    if (start < header_size)
        return header_size;

    const end = start + pad_to_ideal(size);

    for (self.sections.items(.header)) |header| {
        const increased_size = pad_to_ideal(header.size);
        const test_end = header.addr +| increased_size;
        if (end > header.addr and start < test_end) {
            return test_end;
        }
    }

    for (self.segments.items) |seg| {
        const increased_size = pad_to_ideal(seg.vmsize);
        const test_end = seg.vmaddr +| increased_size;
        if (end > seg.vmaddr and start < test_end) {
            return test_end;
        }
    }

    return null;
}

pub fn allocated_size(self: *MachO, start: u64) u64 {
    if (start == 0) return 0;

    var min_pos: u64 = std.math.max_int(u64);

    for (self.sections.items(.header)) |header| {
        if (header.offset <= start) continue;
        if (header.offset < min_pos) min_pos = header.offset;
    }

    for (self.segments.items) |seg| {
        if (seg.fileoff <= start) continue;
        if (seg.fileoff < min_pos) min_pos = seg.fileoff;
    }

    return min_pos - start;
}

pub fn allocated_size_virtual(self: *MachO, start: u64) u64 {
    if (start == 0) return 0;

    var min_pos: u64 = std.math.max_int(u64);

    for (self.sections.items(.header)) |header| {
        if (header.addr <= start) continue;
        if (header.addr < min_pos) min_pos = header.addr;
    }

    for (self.segments.items) |seg| {
        if (seg.vmaddr <= start) continue;
        if (seg.vmaddr < min_pos) min_pos = seg.vmaddr;
    }

    return min_pos - start;
}

pub fn find_free_space(self: *MachO, object_size: u64, min_alignment: u32) u64 {
    var start: u64 = 0;
    while (self.detect_alloc_collision(start, object_size)) |item_end| {
        start = mem.align_forward(u64, item_end, min_alignment);
    }
    return start;
}

pub fn find_free_space_virtual(self: *MachO, object_size: u64, min_alignment: u32) u64 {
    var start: u64 = 0;
    while (self.detect_alloc_collision_virtual(start, object_size)) |item_end| {
        start = mem.align_forward(u64, item_end, min_alignment);
    }
    return start;
}

pub fn copy_range_all(self: *MachO, old_offset: u64, new_offset: u64, size: u64) !void {
    const file = self.base.file.?;
    const amt = try file.copy_range_all(old_offset, file, new_offset, size);
    if (amt != size) return error.InputOutput;
}

/// Like File.copy_range_all but also ensures the source region is zeroed out after copy.
/// This is so that we guarantee zeroed out regions for mapping of zerofill sections by the loader.
fn copy_range_all_zero_out(self: *MachO, old_offset: u64, new_offset: u64, size: u64) !void {
    const gpa = self.base.comp.gpa;
    try self.copy_range_all(old_offset, new_offset, size);
    const size_u = math.cast(usize, size) orelse return error.Overflow;
    const zeroes = try gpa.alloc(u8, size_u);
    defer gpa.free(zeroes);
    @memset(zeroes, 0);
    try self.base.file.?.pwrite_all(zeroes, old_offset);
}

const InitMetadataOptions = struct {
    emit: Compilation.Emit,
    zo: *ZigObject,
    symbol_count_hint: u64,
    program_code_size_hint: u64,
};

// TODO: move to ZigObject
fn init_metadata(self: *MachO, options: InitMetadataOptions) !void {
    if (!self.base.is_relocatable()) {
        const base_vmaddr = blk: {
            const pagezero_size = self.pagezero_size orelse default_pagezero_size;
            break :blk mem.align_backward(u64, pagezero_size, self.get_page_size());
        };

        {
            const filesize = options.program_code_size_hint;
            const off = self.find_free_space(filesize, self.get_page_size());
            self.zig_text_seg_index = try self.add_segment("__TEXT_ZIG", .{
                .fileoff = off,
                .filesize = filesize,
                .vmaddr = base_vmaddr + 0x8000000,
                .vmsize = filesize,
                .prot = macho.PROT.READ | macho.PROT.EXEC,
            });
        }

        {
            const filesize = options.symbol_count_hint * @size_of(u64);
            const off = self.find_free_space(filesize, self.get_page_size());
            self.zig_got_seg_index = try self.add_segment("__GOT_ZIG", .{
                .fileoff = off,
                .filesize = filesize,
                .vmaddr = base_vmaddr + 0x4000000,
                .vmsize = filesize,
                .prot = macho.PROT.READ | macho.PROT.WRITE,
            });
        }

        {
            const filesize: u64 = 1024;
            const off = self.find_free_space(filesize, self.get_page_size());
            self.zig_const_seg_index = try self.add_segment("__CONST_ZIG", .{
                .fileoff = off,
                .filesize = filesize,
                .vmaddr = base_vmaddr + 0xc000000,
                .vmsize = filesize,
                .prot = macho.PROT.READ | macho.PROT.WRITE,
            });
        }

        {
            const filesize: u64 = 1024;
            const off = self.find_free_space(filesize, self.get_page_size());
            self.zig_data_seg_index = try self.add_segment("__DATA_ZIG", .{
                .fileoff = off,
                .filesize = filesize,
                .vmaddr = base_vmaddr + 0x10000000,
                .vmsize = filesize,
                .prot = macho.PROT.READ | macho.PROT.WRITE,
            });
        }

        {
            const memsize: u64 = 1024;
            self.zig_bss_seg_index = try self.add_segment("__BSS_ZIG", .{
                .vmaddr = base_vmaddr + 0x14000000,
                .vmsize = memsize,
                .prot = macho.PROT.READ | macho.PROT.WRITE,
            });
        }

        if (options.zo.dwarf) |_| {
            // Create dSYM bundle.
            log.debug("creating {s}.dSYM bundle", .{options.emit.sub_path});

            const gpa = self.base.comp.gpa;
            const sep = fs.path.sep_str;
            const d_sym_path = try std.fmt.alloc_print(
                gpa,
                "{s}.dSYM" ++ sep ++ "Contents" ++ sep ++ "Resources" ++ sep ++ "DWARF",
                .{options.emit.sub_path},
            );
            defer gpa.free(d_sym_path);

            var d_sym_bundle = try options.emit.directory.handle.make_open_path(d_sym_path, .{});
            defer d_sym_bundle.close();

            const d_sym_file = try d_sym_bundle.create_file(options.emit.sub_path, .{
                .truncate = false,
                .read = true,
            });

            self.d_sym = .{ .allocator = gpa, .file = d_sym_file };
            try self.d_sym.?.init_metadata(self);
        }
    }

    const append_sect = struct {
        fn append_sect(macho_file: *MachO, sect_id: u8, seg_id: u8) void {
            const sect = &macho_file.sections.items(.header)[sect_id];
            const seg = macho_file.segments.items[seg_id];
            sect.addr = seg.vmaddr;
            sect.offset = @int_cast(seg.fileoff);
            sect.size = seg.vmsize;
            macho_file.sections.items(.segment_id)[sect_id] = seg_id;
        }
    }.append_sect;

    const alloc_sect = struct {
        fn alloc_sect(macho_file: *MachO, sect_id: u8, size: u64) !void {
            const sect = &macho_file.sections.items(.header)[sect_id];
            const alignment = try math.powi(u32, 2, sect.@"align");
            if (!sect.is_zerofill()) {
                sect.offset = math.cast(u32, macho_file.find_free_space(size, alignment)) orelse
                    return error.Overflow;
            }
            sect.addr = macho_file.find_free_space_virtual(size, alignment);
            sect.size = size;
        }
    }.alloc_sect;

    {
        self.zig_text_sect_index = try self.add_section("__TEXT_ZIG", "__text_zig", .{
            .alignment = switch (self.get_target().cpu.arch) {
                .aarch64 => 2,
                .x86_64 => 0,
                else => unreachable,
            },
            .flags = macho.S_REGULAR | macho.S_ATTR_PURE_INSTRUCTIONS | macho.S_ATTR_SOME_INSTRUCTIONS,
        });
        if (self.base.is_relocatable()) {
            try alloc_sect(self, self.zig_text_sect_index.?, options.program_code_size_hint);
        } else {
            append_sect(self, self.zig_text_sect_index.?, self.zig_text_seg_index.?);
        }
    }

    if (!self.base.is_relocatable()) {
        self.zig_got_sect_index = try self.add_section("__GOT_ZIG", "__got_zig", .{
            .alignment = 3,
        });
        append_sect(self, self.zig_got_sect_index.?, self.zig_got_seg_index.?);
    }

    {
        self.zig_const_sect_index = try self.add_section("__CONST_ZIG", "__const_zig", .{});
        if (self.base.is_relocatable()) {
            try alloc_sect(self, self.zig_const_sect_index.?, 1024);
        } else {
            append_sect(self, self.zig_const_sect_index.?, self.zig_const_seg_index.?);
        }
    }

    {
        self.zig_data_sect_index = try self.add_section("__DATA_ZIG", "__data_zig", .{});
        if (self.base.is_relocatable()) {
            try alloc_sect(self, self.zig_data_sect_index.?, 1024);
        } else {
            append_sect(self, self.zig_data_sect_index.?, self.zig_data_seg_index.?);
        }
    }

    {
        self.zig_bss_sect_index = try self.add_section("__BSS_ZIG", "__bss_zig", .{
            .flags = macho.S_ZEROFILL,
        });
        if (self.base.is_relocatable()) {
            try alloc_sect(self, self.zig_bss_sect_index.?, 1024);
        } else {
            append_sect(self, self.zig_bss_sect_index.?, self.zig_bss_seg_index.?);
        }
    }

    if (self.base.is_relocatable() and options.zo.dwarf != null) {
        {
            self.debug_str_sect_index = try self.add_section("__DWARF", "__debug_str", .{
                .flags = macho.S_ATTR_DEBUG,
            });
            try alloc_sect(self, self.debug_str_sect_index.?, 200);
        }

        {
            self.debug_info_sect_index = try self.add_section("__DWARF", "__debug_info", .{
                .flags = macho.S_ATTR_DEBUG,
            });
            try alloc_sect(self, self.debug_info_sect_index.?, 200);
        }

        {
            self.debug_abbrev_sect_index = try self.add_section("__DWARF", "__debug_abbrev", .{
                .flags = macho.S_ATTR_DEBUG,
            });
            try alloc_sect(self, self.debug_abbrev_sect_index.?, 128);
        }

        {
            self.debug_aranges_sect_index = try self.add_section("__DWARF", "__debug_aranges", .{
                .alignment = 4,
                .flags = macho.S_ATTR_DEBUG,
            });
            try alloc_sect(self, self.debug_aranges_sect_index.?, 160);
        }

        {
            self.debug_line_sect_index = try self.add_section("__DWARF", "__debug_line", .{
                .flags = macho.S_ATTR_DEBUG,
            });
            try alloc_sect(self, self.debug_line_sect_index.?, 250);
        }
    }
}

pub fn grow_section(self: *MachO, sect_index: u8, needed_size: u64) !void {
    if (self.base.is_relocatable()) {
        try self.grow_section_relocatable(sect_index, needed_size);
    } else {
        try self.grow_section_non_relocatable(sect_index, needed_size);
    }
}

fn grow_section_non_relocatable(self: *MachO, sect_index: u8, needed_size: u64) !void {
    const sect = &self.sections.items(.header)[sect_index];

    if (needed_size > self.allocated_size(sect.offset) and !sect.is_zerofill()) {
        const existing_size = sect.size;
        sect.size = 0;

        // Must move the entire section.
        const alignment = self.get_page_size();
        const new_offset = self.find_free_space(needed_size, alignment);

        log.debug("moving '{s},{s}' from 0x{x} to 0x{x}", .{
            sect.seg_name(),
            sect.sect_name(),
            sect.offset,
            new_offset,
        });

        try self.copy_range_all_zero_out(sect.offset, new_offset, existing_size);

        sect.offset = @int_cast(new_offset);
    }

    sect.size = needed_size;

    const seg_id = self.sections.items(.segment_id)[sect_index];
    const seg = &self.segments.items[seg_id];
    seg.fileoff = sect.offset;

    if (!sect.is_zerofill()) {
        seg.filesize = needed_size;
    }

    const mem_capacity = self.allocated_size_virtual(seg.vmaddr);
    if (needed_size > mem_capacity) {
        var err = try self.add_error_with_notes(2);
        try err.add_msg(self, "fatal linker error: cannot expand segment seg({d})({s}) in virtual memory", .{
            seg_id,
            seg.seg_name(),
        });
        try err.add_note(self, "TODO: emit relocations to memory locations in self-hosted backends", .{});
        try err.add_note(self, "as a workaround, try increasing pre-allocated virtual memory of each segment", .{});
    }

    seg.vmsize = needed_size;
}

fn grow_section_relocatable(self: *MachO, sect_index: u8, needed_size: u64) !void {
    const sect = &self.sections.items(.header)[sect_index];

    if (needed_size > self.allocated_size(sect.offset) and !sect.is_zerofill()) {
        const existing_size = sect.size;
        sect.size = 0;

        // Must move the entire section.
        const alignment = try math.powi(u32, 2, sect.@"align");
        const new_offset = self.find_free_space(needed_size, alignment);
        const new_addr = self.find_free_space_virtual(needed_size, alignment);

        log.debug("new '{s},{s}' file offset 0x{x} to 0x{x} (0x{x} - 0x{x})", .{
            sect.seg_name(),
            sect.sect_name(),
            new_offset,
            new_offset + existing_size,
            new_addr,
            new_addr + existing_size,
        });

        try self.copy_range_all(sect.offset, new_offset, existing_size);

        sect.offset = @int_cast(new_offset);
        sect.addr = new_addr;
    }

    sect.size = needed_size;
}

pub fn mark_dirty(self: *MachO, sect_index: u8) void {
    if (self.get_zig_object()) |zo| {
        if (self.debug_info_sect_index.? == sect_index) {
            zo.debug_info_header_dirty = true;
        } else if (self.debug_line_sect_index.? == sect_index) {
            zo.debug_line_header_dirty = true;
        } else if (self.debug_abbrev_sect_index.? == sect_index) {
            zo.debug_abbrev_dirty = true;
        } else if (self.debug_str_sect_index.? == sect_index) {
            zo.debug_strtab_dirty = true;
        } else if (self.debug_aranges_sect_index.? == sect_index) {
            zo.debug_aranges_dirty = true;
        }
    }
}

pub fn get_target(self: MachO) std.Target {
    return self.base.comp.root_mod.resolved_target.result;
}

/// XNU starting with Big Sur running on arm64 is caching inodes of running binaries.
/// Any change to the binary will effectively invalidate the kernel's cache
/// resulting in a SIGKILL on each subsequent run. Since when doing incremental
/// linking we're modifying a binary in-place, this will end up with the kernel
/// killing it on every subsequent run. To circumvent it, we will copy the file
/// into a new inode, remove the original file, and rename the copy to match
/// the original file. This is super messy, but there doesn't seem any other
/// way to please the XNU.
pub fn invalidate_kernel_cache(dir: fs.Dir, sub_path: []const u8) !void {
    if (comptime builtin.target.is_darwin() and builtin.target.cpu.arch == .aarch64) {
        try dir.copy_file(sub_path, dir, sub_path, .{});
    }
}

inline fn conform_uuid(out: *[Md5.digest_length]u8) void {
    // LC_UUID uuids should conform to RFC 4122 UUID version 4 & UUID version 5 formats
    out[6] = (out[6] & 0x0F) | (3 << 4);
    out[8] = (out[8] & 0x3F) | 0x80;
}

pub inline fn get_page_size(self: MachO) u16 {
    return switch (self.get_target().cpu.arch) {
        .aarch64 => 0x4000,
        .x86_64 => 0x1000,
        else => unreachable,
    };
}

pub fn requires_code_sig(self: MachO) bool {
    if (self.entitlements) |_| return true;
    // TODO: enable once we support this linker option
    // if (self.options.adhoc_codesign) |cs| return cs;
    const target = self.get_target();
    return switch (target.cpu.arch) {
        .aarch64 => switch (target.os.tag) {
            .macos => true,
            .watchos, .tvos, .ios, .visionos => target.abi == .simulator,
            else => false,
        },
        .x86_64 => false,
        else => unreachable,
    };
}

inline fn requires_thunks(self: MachO) bool {
    return self.get_target().cpu.arch == .aarch64;
}

pub fn is_zig_segment(self: MachO, seg_id: u8) bool {
    inline for (&[_]?u8{
        self.zig_text_seg_index,
        self.zig_got_seg_index,
        self.zig_const_seg_index,
        self.zig_data_seg_index,
        self.zig_bss_seg_index,
    }) |maybe_index| {
        if (maybe_index) |index| {
            if (index == seg_id) return true;
        }
    }
    return false;
}

pub fn is_zig_section(self: MachO, sect_id: u8) bool {
    inline for (&[_]?u8{
        self.zig_text_sect_index,
        self.zig_got_sect_index,
        self.zig_const_sect_index,
        self.zig_data_sect_index,
        self.zig_bss_sect_index,
    }) |maybe_index| {
        if (maybe_index) |index| {
            if (index == sect_id) return true;
        }
    }
    return false;
}

pub fn is_debug_section(self: MachO, sect_id: u8) bool {
    inline for (&[_]?u8{
        self.debug_info_sect_index,
        self.debug_abbrev_sect_index,
        self.debug_str_sect_index,
        self.debug_aranges_sect_index,
        self.debug_line_sect_index,
    }) |maybe_index| {
        if (maybe_index) |index| {
            if (index == sect_id) return true;
        }
    }
    return false;
}

pub fn add_segment(self: *MachO, name: []const u8, opts: struct {
    vmaddr: u64 = 0,
    vmsize: u64 = 0,
    fileoff: u64 = 0,
    filesize: u64 = 0,
    prot: macho.vm_prot_t = macho.PROT.NONE,
}) error{OutOfMemory}!u8 {
    const gpa = self.base.comp.gpa;
    const index = @as(u8, @int_cast(self.segments.items.len));
    try self.segments.append(gpa, .{
        .segname = make_static_string(name),
        .vmaddr = opts.vmaddr,
        .vmsize = opts.vmsize,
        .fileoff = opts.fileoff,
        .filesize = opts.filesize,
        .maxprot = opts.prot,
        .initprot = opts.prot,
        .nsects = 0,
        .cmdsize = @size_of(macho.segment_command_64),
    });
    return index;
}

const AddSectionOpts = struct {
    alignment: u32 = 0,
    flags: u32 = macho.S_REGULAR,
    reserved1: u32 = 0,
    reserved2: u32 = 0,
};

pub fn add_section(
    self: *MachO,
    segname: []const u8,
    sectname: []const u8,
    opts: AddSectionOpts,
) !u8 {
    const gpa = self.base.comp.gpa;
    const index = @as(u8, @int_cast(try self.sections.add_one(gpa)));
    self.sections.set(index, .{
        .segment_id = 0, // Segments will be created automatically later down the pipeline.
        .header = .{
            .sectname = make_static_string(sectname),
            .segname = make_static_string(segname),
            .@"align" = opts.alignment,
            .flags = opts.flags,
            .reserved1 = opts.reserved1,
            .reserved2 = opts.reserved2,
        },
    });
    return index;
}

pub fn make_static_string(bytes: []const u8) [16]u8 {
    var buf = [_]u8{0} ** 16;
    @memcpy(buf[0..bytes.len], bytes);
    return buf;
}

pub fn get_segment_by_name(self: MachO, segname: []const u8) ?u8 {
    for (self.segments.items, 0..) |seg, i| {
        if (mem.eql(u8, segname, seg.seg_name())) return @as(u8, @int_cast(i));
    } else return null;
}

pub fn get_section_by_name(self: MachO, segname: []const u8, sectname: []const u8) ?u8 {
    for (self.sections.items(.header), 0..) |header, i| {
        if (mem.eql(u8, header.seg_name(), segname) and mem.eql(u8, header.sect_name(), sectname))
            return @as(u8, @int_cast(i));
    } else return null;
}

pub fn get_tls_address(self: MachO) u64 {
    for (self.sections.items(.header)) |header| switch (header.type()) {
        macho.S_THREAD_LOCAL_REGULAR,
        macho.S_THREAD_LOCAL_ZEROFILL,
        => return header.addr,
        else => {},
    };
    return 0;
}

pub inline fn get_text_segment(self: *MachO) *macho.segment_command_64 {
    return &self.segments.items[self.text_seg_index.?];
}

pub inline fn get_linkedit_segment(self: *MachO) *macho.segment_command_64 {
    return &self.segments.items[self.linkedit_seg_index.?];
}

pub fn get_file(self: *MachO, index: File.Index) ?File {
    const tag = self.files.items(.tags)[index];
    return switch (tag) {
        .null => null,
        .zig_object => .{ .zig_object = &self.files.items(.data)[index].zig_object },
        .internal => .{ .internal = &self.files.items(.data)[index].internal },
        .object => .{ .object = &self.files.items(.data)[index].object },
        .dylib => .{ .dylib = &self.files.items(.data)[index].dylib },
    };
}

pub fn get_zig_object(self: *MachO) ?*ZigObject {
    const index = self.zig_object orelse return null;
    return self.get_file(index).?.zig_object;
}

pub fn get_internal_object(self: *MachO) ?*InternalObject {
    const index = self.internal_object orelse return null;
    return self.get_file(index).?.internal;
}

pub fn add_file_handle(self: *MachO, file: fs.File) !File.HandleIndex {
    const gpa = self.base.comp.gpa;
    const index: File.HandleIndex = @int_cast(self.file_handles.items.len);
    const fh = try self.file_handles.add_one(gpa);
    fh.* = file;
    return index;
}

pub fn get_file_handle(self: MachO, index: File.HandleIndex) File.Handle {
    assert(index < self.file_handles.items.len);
    return self.file_handles.items[index];
}

pub fn add_atom(self: *MachO) error{OutOfMemory}!Atom.Index {
    const index = @as(Atom.Index, @int_cast(self.atoms.items.len));
    const atom = try self.atoms.add_one(self.base.comp.gpa);
    atom.* = .{};
    return index;
}

pub fn get_atom(self: *MachO, index: Atom.Index) ?*Atom {
    if (index == 0) return null;
    assert(index < self.atoms.items.len);
    return &self.atoms.items[index];
}

pub fn add_atom_extra(self: *MachO, extra: Atom.Extra) !u32 {
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    try self.atoms_extra.ensure_unused_capacity(self.base.comp.gpa, fields.len);
    return self.add_atom_extra_assume_capacity(extra);
}

pub fn add_atom_extra_assume_capacity(self: *MachO, extra: Atom.Extra) u32 {
    const index = @as(u32, @int_cast(self.atoms_extra.items.len));
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    inline for (fields) |field| {
        self.atoms_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compile_error("bad field type"),
        });
    }
    return index;
}

pub fn get_atom_extra(self: *MachO, index: u32) ?Atom.Extra {
    if (index == 0) return null;
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    var i: usize = index;
    var result: Atom.Extra = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => self.atoms_extra.items[i],
            else => @compile_error("bad field type"),
        };
        i += 1;
    }
    return result;
}

pub fn set_atom_extra(self: *MachO, index: u32, extra: Atom.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Atom.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.atoms_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compile_error("bad field type"),
        };
    }
}

pub fn add_symbol(self: *MachO) !Symbol.Index {
    const index = @as(Symbol.Index, @int_cast(self.symbols.items.len));
    const symbol = try self.symbols.add_one(self.base.comp.gpa);
    symbol.* = .{};
    return index;
}

pub fn get_symbol(self: *MachO, index: Symbol.Index) *Symbol {
    assert(index < self.symbols.items.len);
    return &self.symbols.items[index];
}

pub fn add_symbol_extra(self: *MachO, extra: Symbol.Extra) !u32 {
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    try self.symbols_extra.ensure_unused_capacity(self.base.comp.gpa, fields.len);
    return self.add_symbol_extra_assume_capacity(extra);
}

pub fn add_symbol_extra_assume_capacity(self: *MachO, extra: Symbol.Extra) u32 {
    const index = @as(u32, @int_cast(self.symbols_extra.items.len));
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields) |field| {
        self.symbols_extra.append_assume_capacity(switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compile_error("bad field type"),
        });
    }
    return index;
}

pub fn get_symbol_extra(self: MachO, index: u32) ?Symbol.Extra {
    if (index == 0) return null;
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    var i: usize = index;
    var result: Symbol.Extra = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => self.symbols_extra.items[i],
            else => @compile_error("bad field type"),
        };
        i += 1;
    }
    return result;
}

pub fn set_symbol_extra(self: *MachO, index: u32, extra: Symbol.Extra) void {
    assert(index > 0);
    const fields = @typeInfo(Symbol.Extra).Struct.fields;
    inline for (fields, 0..) |field, i| {
        self.symbols_extra.items[index + i] = switch (field.type) {
            u32 => @field(extra, field.name),
            else => @compile_error("bad field type"),
        };
    }
}

const GetOrCreateGlobalResult = struct {
    found_existing: bool,
    index: Symbol.Index,
};

pub fn get_or_create_global(self: *MachO, off: u32) !GetOrCreateGlobalResult {
    const gpa = self.base.comp.gpa;
    const gop = try self.globals.get_or_put(gpa, off);
    if (!gop.found_existing) {
        const index = try self.add_symbol();
        const global = self.get_symbol(index);
        global.name = off;
        global.flags.global = true;
        gop.value_ptr.* = index;
    }
    return .{
        .found_existing = gop.found_existing,
        .index = gop.value_ptr.*,
    };
}

pub fn get_global_by_name(self: *MachO, name: []const u8) ?Symbol.Index {
    const off = self.strings.get_offset(name) orelse return null;
    return self.globals.get(off);
}

pub fn add_unwind_record(self: *MachO) !UnwindInfo.Record.Index {
    const index = @as(UnwindInfo.Record.Index, @int_cast(self.unwind_records.items.len));
    const rec = try self.unwind_records.add_one(self.base.comp.gpa);
    rec.* = .{};
    return index;
}

pub fn get_unwind_record(self: *MachO, index: UnwindInfo.Record.Index) *UnwindInfo.Record {
    assert(index < self.unwind_records.items.len);
    return &self.unwind_records.items[index];
}

pub fn add_thunk(self: *MachO) !Thunk.Index {
    const index = @as(Thunk.Index, @int_cast(self.thunks.items.len));
    const thunk = try self.thunks.add_one(self.base.comp.gpa);
    thunk.* = .{};
    return index;
}

pub fn get_thunk(self: *MachO, index: Thunk.Index) *Thunk {
    assert(index < self.thunks.items.len);
    return &self.thunks.items[index];
}

pub fn eat_prefix(path: []const u8, prefix: []const u8) ?[]const u8 {
    if (mem.starts_with(u8, path, prefix)) return path[prefix.len..];
    return null;
}

const ErrorWithNotes = struct {
    /// Allocated index in comp.link_errors array.
    index: usize,

    /// Next available note slot.
    note_slot: usize = 0,

    pub fn add_msg(
        err: ErrorWithNotes,
        macho_file: *MachO,
        comptime format: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        const comp = macho_file.base.comp;
        const gpa = comp.gpa;
        const err_msg = &comp.link_errors.items[err.index];
        err_msg.msg = try std.fmt.alloc_print(gpa, format, args);
    }

    pub fn add_note(
        err: *ErrorWithNotes,
        macho_file: *MachO,
        comptime format: []const u8,
        args: anytype,
    ) error{OutOfMemory}!void {
        const comp = macho_file.base.comp;
        const gpa = comp.gpa;
        const err_msg = &comp.link_errors.items[err.index];
        assert(err.note_slot < err_msg.notes.len);
        err_msg.notes[err.note_slot] = .{ .msg = try std.fmt.alloc_print(gpa, format, args) };
        err.note_slot += 1;
    }
};

pub fn add_error_with_notes(self: *MachO, note_count: usize) error{OutOfMemory}!ErrorWithNotes {
    const comp = self.base.comp;
    const gpa = comp.gpa;
    try comp.link_errors.ensure_unused_capacity(gpa, 1);
    return self.add_error_with_notes_assume_capacity(note_count);
}

fn add_error_with_notes_assume_capacity(self: *MachO, note_count: usize) error{OutOfMemory}!ErrorWithNotes {
    const comp = self.base.comp;
    const gpa = comp.gpa;
    const index = comp.link_errors.items.len;
    const err = comp.link_errors.add_one_assume_capacity();
    err.* = .{ .msg = undefined, .notes = try gpa.alloc(link.File.ErrorMsg, note_count) };
    return .{ .index = index };
}

pub fn report_parse_error(
    self: *MachO,
    path: []const u8,
    comptime format: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(1);
    try err.add_msg(self, format, args);
    try err.add_note(self, "while parsing {s}", .{path});
}

pub fn report_parse_error2(
    self: *MachO,
    file_index: File.Index,
    comptime format: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(1);
    try err.add_msg(self, format, args);
    try err.add_note(self, "while parsing {}", .{self.get_file(file_index).?.fmt_path()});
}

fn report_missing_library_error(
    self: *MachO,
    checked_paths: []const []const u8,
    comptime format: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(checked_paths.len);
    try err.add_msg(self, format, args);
    for (checked_paths) |path| {
        try err.add_note(self, "tried {s}", .{path});
    }
}

fn report_missing_dependency_error(
    self: *MachO,
    parent: File.Index,
    path: []const u8,
    checked_paths: []const []const u8,
    comptime format: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(2 + checked_paths.len);
    try err.add_msg(self, format, args);
    try err.add_note(self, "while resolving {s}", .{path});
    try err.add_note(self, "a dependency of {}", .{self.get_file(parent).?.fmt_path()});
    for (checked_paths) |p| {
        try err.add_note(self, "tried {s}", .{p});
    }
}

fn report_dependency_error(
    self: *MachO,
    parent: File.Index,
    path: []const u8,
    comptime format: []const u8,
    args: anytype,
) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(2);
    try err.add_msg(self, format, args);
    try err.add_note(self, "while parsing {s}", .{path});
    try err.add_note(self, "a dependency of {}", .{self.get_file(parent).?.fmt_path()});
}

pub fn report_unexpected_error(self: *MachO, comptime format: []const u8, args: anytype) error{OutOfMemory}!void {
    var err = try self.add_error_with_notes(1);
    try err.add_msg(self, format, args);
    try err.add_note(self, "please report this as a linker bug on https://github.com/ziglang/zig/issues/new/choose", .{});
}

fn report_duplicates(self: *MachO, dupes: anytype) error{ HasDuplicates, OutOfMemory }!void {
    const tracy = trace(@src());
    defer tracy.end();

    const max_notes = 3;

    var has_dupes = false;
    var it = dupes.iterator();
    while (it.next()) |entry| {
        const sym = self.get_symbol(entry.key_ptr.*);
        const notes = entry.value_ptr.*;
        const nnotes = @min(notes.items.len, max_notes) + @int_from_bool(notes.items.len > max_notes);

        var err = try self.add_error_with_notes(nnotes + 1);
        try err.add_msg(self, "duplicate symbol definition: {s}", .{sym.get_name(self)});
        try err.add_note(self, "defined by {}", .{sym.get_file(self).?.fmt_path()});

        var inote: usize = 0;
        while (inote < @min(notes.items.len, max_notes)) : (inote += 1) {
            const file = self.get_file(notes.items[inote]).?;
            try err.add_note(self, "defined by {}", .{file.fmt_path()});
        }

        if (notes.items.len > max_notes) {
            const remaining = notes.items.len - max_notes;
            try err.add_note(self, "defined {d} more times", .{remaining});
        }

        has_dupes = true;
    }

    if (has_dupes) return error.HasDuplicates;
}

pub fn get_debug_symbols(self: *MachO) ?*DebugSymbols {
    if (self.d_sym) |*ds| return ds;
    return null;
}

pub fn ptrace_attach(self: *MachO, pid: std.posix.pid_t) !void {
    if (!is_hot_update_compatible) return;

    const mach_task = try std.c.mach_task_for_pid(pid);
    log.debug("Mach task for pid {d}: {any}", .{ pid, mach_task });
    self.hot_state.mach_task = mach_task;

    // TODO start exception handler in another thread

    // TODO enable ones we register for exceptions
    // try std.os.ptrace(std.os.darwin.PT.ATTACHEXC, pid, 0, 0);
}

pub fn ptrace_detach(self: *MachO, pid: std.posix.pid_t) !void {
    if (!is_hot_update_compatible) return;

    _ = pid;

    // TODO stop exception handler

    // TODO see comment in ptrace_attach
    // try std.os.ptrace(std.os.darwin.PT.DETACH, pid, 0, 0);

    self.hot_state.mach_task = null;
}

pub fn dump_state(self: *MachO) std.fmt.Formatter(fmt_dump_state) {
    return .{ .data = self };
}

fn fmt_dump_state(
    self: *MachO,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    if (self.get_zig_object()) |zo| {
        try writer.print("zig_object({d}) : {s}\n", .{ zo.index, zo.path });
        try writer.print("{}{}\n", .{
            zo.fmt_atoms(self),
            zo.fmt_symtab(self),
        });
    }
    for (self.objects.items) |index| {
        const object = self.get_file(index).?.object;
        try writer.print("object({d}) : {} : has_debug({})", .{
            index,
            object.fmt_path(),
            object.has_debug_info(),
        });
        if (!object.alive) try writer.write_all(" : ([*])");
        try writer.write_byte('\n');
        try writer.print("{}{}{}{}{}\n", .{
            object.fmt_atoms(self),
            object.fmt_cies(self),
            object.fmt_fdes(self),
            object.fmt_unwind_records(self),
            object.fmt_symtab(self),
        });
    }
    for (self.dylibs.items) |index| {
        const dylib = self.get_file(index).?.dylib;
        try writer.print("dylib({d}) : {s} : needed({}) : weak({})", .{
            index,
            dylib.path,
            dylib.needed,
            dylib.weak,
        });
        if (!dylib.is_alive(self)) try writer.write_all(" : ([*])");
        try writer.write_byte('\n');
        try writer.print("{}\n", .{dylib.fmt_symtab(self)});
    }
    if (self.get_internal_object()) |internal| {
        try writer.print("internal({d}) : internal\n", .{internal.index});
        try writer.print("{}{}\n", .{ internal.fmt_atoms(self), internal.fmt_symtab(self) });
    }
    try writer.write_all("thunks\n");
    for (self.thunks.items, 0..) |thunk, index| {
        try writer.print("thunk({d}) : {}\n", .{ index, thunk.fmt(self) });
    }
    try writer.print("stubs\n{}\n", .{self.stubs.fmt(self)});
    try writer.print("objc_stubs\n{}\n", .{self.objc_stubs.fmt(self)});
    try writer.print("got\n{}\n", .{self.got.fmt(self)});
    try writer.print("zig_got\n{}\n", .{self.zig_got.fmt(self)});
    try writer.print("tlv_ptr\n{}\n", .{self.tlv_ptr.fmt(self)});
    try writer.write_byte('\n');
    try writer.print("sections\n{}\n", .{self.fmt_sections()});
    try writer.print("segments\n{}\n", .{self.fmt_segments()});
}

fn fmt_sections(self: *MachO) std.fmt.Formatter(format_sections) {
    return .{ .data = self };
}

fn format_sections(
    self: *MachO,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const slice = self.sections.slice();
    for (slice.items(.header), slice.items(.segment_id), 0..) |header, seg_id, i| {
        try writer.print(
            "sect({d}) : seg({d}) : {s},{s} : @{x} ({x}) : align({x}) : size({x}) : relocs({x};{d})\n",
            .{
                i,               seg_id,      header.seg_name(), header.sect_name(), header.addr, header.offset,
                header.@"align", header.size, header.reloff,    header.nreloc,
            },
        );
    }
}

fn fmt_segments(self: *MachO) std.fmt.Formatter(format_segments) {
    return .{ .data = self };
}

fn format_segments(
    self: *MachO,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    for (self.segments.items, 0..) |seg, i| {
        try writer.print("seg({d}) : {s} : @{x}-{x} ({x}-{x})\n", .{
            i,           seg.seg_name(),              seg.vmaddr, seg.vmaddr + seg.vmsize,
            seg.fileoff, seg.fileoff + seg.filesize,
        });
    }
}

pub fn fmt_sect_type(tt: u8) std.fmt.Formatter(format_sect_type) {
    return .{ .data = tt };
}

fn format_sect_type(
    tt: u8,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = unused_fmt_string;
    const name = switch (tt) {
        macho.S_REGULAR => "REGULAR",
        macho.S_ZEROFILL => "ZEROFILL",
        macho.S_CSTRING_LITERALS => "CSTRING_LITERALS",
        macho.S_4BYTE_LITERALS => "4BYTE_LITERALS",
        macho.S_8BYTE_LITERALS => "8BYTE_LITERALS",
        macho.S_16BYTE_LITERALS => "16BYTE_LITERALS",
        macho.S_LITERAL_POINTERS => "LITERAL_POINTERS",
        macho.S_NON_LAZY_SYMBOL_POINTERS => "NON_LAZY_SYMBOL_POINTERS",
        macho.S_LAZY_SYMBOL_POINTERS => "LAZY_SYMBOL_POINTERS",
        macho.S_SYMBOL_STUBS => "SYMBOL_STUBS",
        macho.S_MOD_INIT_FUNC_POINTERS => "MOD_INIT_FUNC_POINTERS",
        macho.S_MOD_TERM_FUNC_POINTERS => "MOD_TERM_FUNC_POINTERS",
        macho.S_COALESCED => "COALESCED",
        macho.S_GB_ZEROFILL => "GB_ZEROFILL",
        macho.S_INTERPOSING => "INTERPOSING",
        macho.S_DTRACE_DOF => "DTRACE_DOF",
        macho.S_THREAD_LOCAL_REGULAR => "THREAD_LOCAL_REGULAR",
        macho.S_THREAD_LOCAL_ZEROFILL => "THREAD_LOCAL_ZEROFILL",
        macho.S_THREAD_LOCAL_VARIABLES => "THREAD_LOCAL_VARIABLES",
        macho.S_THREAD_LOCAL_VARIABLE_POINTERS => "THREAD_LOCAL_VARIABLE_POINTERS",
        macho.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => "THREAD_LOCAL_INIT_FUNCTION_POINTERS",
        macho.S_INIT_FUNC_OFFSETS => "INIT_FUNC_OFFSETS",
        else => |x| return writer.print("UNKNOWN({x})", .{x}),
    };
    try writer.print("{s}", .{name});
}

const is_hot_update_compatible = switch (builtin.target.os.tag) {
    .macos => true,
    else => false,
};

const default_entry_symbol_name = "_main";

pub const base_tag: link.File.Tag = link.File.Tag.macho;

const Section = struct {
    header: macho.section_64,
    segment_id: u8,
    atoms: std.ArrayListUnmanaged(Atom.Index) = .{},
    free_list: std.ArrayListUnmanaged(Atom.Index) = .{},
    last_atom_index: Atom.Index = 0,
};

pub const LiteralPool = struct {
    table: std.AutoArrayHashMapUnmanaged(void, void) = .{},
    keys: std.ArrayListUnmanaged(Key) = .{},
    values: std.ArrayListUnmanaged(Atom.Index) = .{},
    data: std.ArrayListUnmanaged(u8) = .{},

    pub fn deinit(lp: *LiteralPool, allocator: Allocator) void {
        lp.table.deinit(allocator);
        lp.keys.deinit(allocator);
        lp.values.deinit(allocator);
        lp.data.deinit(allocator);
    }

    pub fn get_atom(lp: LiteralPool, index: Index, macho_file: *MachO) *Atom {
        assert(index < lp.values.items.len);
        return macho_file.get_atom(lp.values.items[index]).?;
    }

    const InsertResult = struct {
        found_existing: bool,
        index: Index,
        atom: *Atom.Index,
    };

    pub fn insert(lp: *LiteralPool, allocator: Allocator, @"type": u8, string: []const u8) !InsertResult {
        const size: u32 = @int_cast(string.len);
        try lp.data.ensure_unused_capacity(allocator, size);
        const off: u32 = @int_cast(lp.data.items.len);
        lp.data.append_slice_assume_capacity(string);
        const adapter = Adapter{ .lp = lp };
        const key = Key{ .off = off, .size = size, .seed = @"type" };
        const gop = try lp.table.get_or_put_adapted(allocator, key, adapter);
        if (!gop.found_existing) {
            try lp.keys.append(allocator, key);
            _ = try lp.values.add_one(allocator);
        }
        return .{
            .found_existing = gop.found_existing,
            .index = @int_cast(gop.index),
            .atom = &lp.values.items[gop.index],
        };
    }

    const Key = struct {
        off: u32,
        size: u32,
        seed: u8,

        fn get_data(key: Key, lp: *const LiteralPool) []const u8 {
            return lp.data.items[key.off..][0..key.size];
        }

        fn eql(key: Key, other: Key, lp: *const LiteralPool) bool {
            const key_data = key.get_data(lp);
            const other_data = other.get_data(lp);
            return mem.eql(u8, key_data, other_data);
        }

        fn hash(key: Key, lp: *const LiteralPool) u32 {
            const data = key.get_data(lp);
            return @truncate(Hash.hash(key.seed, data));
        }
    };

    const Adapter = struct {
        lp: *const LiteralPool,

        pub fn eql(ctx: @This(), key: Key, b_void: void, b_map_index: usize) bool {
            _ = b_void;
            const other = ctx.lp.keys.items[b_map_index];
            return key.eql(other, ctx.lp);
        }

        pub fn hash(ctx: @This(), key: Key) u32 {
            return key.hash(ctx.lp);
        }
    };

    pub const Index = u32;
};

const HotUpdateState = struct {
    mach_task: ?std.c.MachTask = null,
};

pub const DynamicRelocs = struct {
    rebase_relocs: u32 = 0,
    bind_relocs: u32 = 0,
    weak_bind_relocs: u32 = 0,
};

pub const SymtabCtx = struct {
    ilocal: u32 = 0,
    istab: u32 = 0,
    iexport: u32 = 0,
    iimport: u32 = 0,
    nlocals: u32 = 0,
    nstabs: u32 = 0,
    nexports: u32 = 0,
    nimports: u32 = 0,
    strsize: u32 = 0,
};

pub const null_sym = macho.nlist_64{
    .n_strx = 0,
    .n_type = 0,
    .n_sect = 0,
    .n_desc = 0,
    .n_value = 0,
};

pub const Platform = struct {
    os_tag: std.Target.Os.Tag,
    abi: std.Target.Abi,
    version: std.SemanticVersion,

    /// Using Apple's ld64 as our blueprint, `min_version` as well as `sdk_version` are set to
    /// the extracted minimum platform version.
    pub fn from_load_command(lc: macho.LoadCommandIterator.LoadCommand) Platform {
        switch (lc.cmd()) {
            .BUILD_VERSION => {
                const cmd = lc.cast(macho.build_version_command).?;
                return .{
                    .os_tag = switch (cmd.platform) {
                        .MACOS => .macos,
                        .IOS, .IOSSIMULATOR => .ios,
                        .TVOS, .TVOSSIMULATOR => .tvos,
                        .WATCHOS, .WATCHOSSIMULATOR => .watchos,
                        .MACCATALYST => .ios,
                        .VISIONOS, .VISIONOSSIMULATOR => .visionos,
                        else => @panic("TODO"),
                    },
                    .abi = switch (cmd.platform) {
                        .MACCATALYST => .macabi,
                        .IOSSIMULATOR,
                        .TVOSSIMULATOR,
                        .WATCHOSSIMULATOR,
                        .VISIONOSSIMULATOR,
                        => .simulator,
                        else => .none,
                    },
                    .version = apple_version_to_semantic_version(cmd.minos),
                };
            },
            .VERSION_MIN_MACOSX,
            .VERSION_MIN_IPHONEOS,
            .VERSION_MIN_TVOS,
            .VERSION_MIN_WATCHOS,
            => {
                const cmd = lc.cast(macho.version_min_command).?;
                return .{
                    .os_tag = switch (lc.cmd()) {
                        .VERSION_MIN_MACOSX => .macos,
                        .VERSION_MIN_IPHONEOS => .ios,
                        .VERSION_MIN_TVOS => .tvos,
                        .VERSION_MIN_WATCHOS => .watchos,
                        else => unreachable,
                    },
                    .abi = .none,
                    .version = apple_version_to_semantic_version(cmd.version),
                };
            },
            else => unreachable,
        }
    }

    pub fn from_target(target: std.Target) Platform {
        return .{
            .os_tag = target.os.tag,
            .abi = target.abi,
            .version = target.os.version_range.semver.min,
        };
    }

    pub fn to_apple_version(plat: Platform) u32 {
        return semantic_version_to_apple_version(plat.version);
    }

    pub fn to_apple_platform(plat: Platform) macho.PLATFORM {
        return switch (plat.os_tag) {
            .macos => .MACOS,
            .ios => switch (plat.abi) {
                .simulator => .IOSSIMULATOR,
                .macabi => .MACCATALYST,
                else => .IOS,
            },
            .tvos => if (plat.abi == .simulator) .TVOSSIMULATOR else .TVOS,
            .watchos => if (plat.abi == .simulator) .WATCHOSSIMULATOR else .WATCHOS,
            .visionos => if (plat.abi == .simulator) .VISIONOSSIMULATOR else .VISIONOS,
            else => unreachable,
        };
    }

    pub fn is_build_version_compatible(plat: Platform) bool {
        inline for (supported_platforms) |sup_plat| {
            if (sup_plat[0] == plat.os_tag and sup_plat[1] == plat.abi) {
                return sup_plat[2] <= plat.to_apple_version();
            }
        }
        return false;
    }

    pub fn is_version_min_compatible(plat: Platform) bool {
        inline for (supported_platforms) |sup_plat| {
            if (sup_plat[0] == plat.os_tag and sup_plat[1] == plat.abi) {
                return sup_plat[3] <= plat.to_apple_version();
            }
        }
        return false;
    }

    pub fn fmt_target(plat: Platform, cpu_arch: std.Target.Cpu.Arch) std.fmt.Formatter(format_target) {
        return .{ .data = .{ .platform = plat, .cpu_arch = cpu_arch } };
    }

    const FmtCtx = struct {
        platform: Platform,
        cpu_arch: std.Target.Cpu.Arch,
    };

    pub fn format_target(
        ctx: FmtCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("{s}-{s}", .{ @tag_name(ctx.cpu_arch), @tag_name(ctx.platform.os_tag) });
        if (ctx.platform.abi != .none) {
            try writer.print("-{s}", .{@tag_name(ctx.platform.abi)});
        }
    }

    /// Caller owns the memory.
    pub fn alloc_print_target(plat: Platform, gpa: Allocator, cpu_arch: std.Target.Cpu.Arch) error{OutOfMemory}![]u8 {
        var buffer = std.ArrayList(u8).init(gpa);
        defer buffer.deinit();
        try buffer.writer().print("{}", .{plat.fmt_target(cpu_arch)});
        return buffer.to_owned_slice();
    }

    pub fn eql_target(plat: Platform, other: Platform) bool {
        return plat.os_tag == other.os_tag and plat.abi == other.abi;
    }
};

const SupportedPlatforms = struct {
    std.Target.Os.Tag,
    std.Target.Abi,
    u32, // Min platform version for which to emit LC_BUILD_VERSION
    u32, // Min supported platform version
};

// Source: https://github.com/apple-oss-distributions/ld64/blob/59a99ab60399c5e6c49e6945a9e1049c42b71135/src/ld/PlatformSupport.cpp#L52
// zig fmt: off
const supported_platforms = [_]SupportedPlatforms{
    .{ .macos,    .none,      0xA0E00, 0xA0800 },
    .{ .ios,      .none,      0xC0000, 0x70000 },
    .{ .tvos,     .none,      0xC0000, 0x70000 },
    .{ .watchos,  .none,      0x50000, 0x20000 },
    .{ .visionos, .none,      0x10000, 0x10000 },
    .{ .ios,      .simulator, 0xD0000, 0x80000 },
    .{ .tvos,     .simulator, 0xD0000, 0x80000 },
    .{ .watchos,  .simulator, 0x60000, 0x20000 },
    .{ .visionos, .simulator, 0x10000, 0x10000 },
};
// zig fmt: on

pub inline fn semantic_version_to_apple_version(version: std.SemanticVersion) u32 {
    const major = version.major;
    const minor = version.minor;
    const patch = version.patch;
    return (@as(u32, @int_cast(major)) << 16) | (@as(u32, @int_cast(minor)) << 8) | @as(u32, @int_cast(patch));
}

pub inline fn apple_version_to_semantic_version(version: u32) std.SemanticVersion {
    return .{
        .major = @as(u16, @truncate(version >> 16)),
        .minor = @as(u8, @truncate(version >> 8)),
        .patch = @as(u8, @truncate(version)),
    };
}

fn infer_sdk_version(comp: *Compilation, sdk_layout: SdkLayout) ?std.SemanticVersion {
    const gpa = comp.gpa;

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const sdk_dir = switch (sdk_layout) {
        .sdk => comp.sysroot.?,
        .vendored => fs.path.join(arena, &.{ comp.zig_lib_directory.path.?, "libc", "darwin" }) catch return null,
    };
    if (read_sdk_version_from_settings(arena, sdk_dir)) |ver| {
        return parse_sdk_version(ver);
    } else |_| {
        // Read from settings should always succeed when vendored.
        // TODO: convert to fatal linker error
        if (sdk_layout == .vendored) @panic("zig installation bug: unable to parse SDK version");
    }

    // infer from pathname
    const stem = fs.path.stem(sdk_dir);
    const start = for (stem, 0..) |c, i| {
        if (std.ascii.is_digit(c)) break i;
    } else stem.len;
    const end = for (stem[start..], start..) |c, i| {
        if (std.ascii.is_digit(c) or c == '.') continue;
        break i;
    } else stem.len;
    return parse_sdk_version(stem[start..end]);
}

// Official Apple SDKs ship with a `SDKSettings.json` located at the top of SDK fs layout.
// Use property `MinimalDisplayName` to determine version.
// The file/property is also available with vendored libc.
fn read_sdk_version_from_settings(arena: Allocator, dir: []const u8) ![]const u8 {
    const sdk_path = try fs.path.join(arena, &.{ dir, "SDKSettings.json" });
    const contents = try fs.cwd().read_file_alloc(arena, sdk_path, std.math.max_int(u16));
    const parsed = try std.json.parse_from_slice(std.json.Value, arena, contents, .{});
    if (parsed.value.object.get("MinimalDisplayName")) |ver| return ver.string;
    return error.SdkVersionFailure;
}

// Versions reported by Apple aren't exactly semantically valid as they usually omit
// the patch component, so we parse SDK value by hand.
fn parse_sdk_version(raw: []const u8) ?std.SemanticVersion {
    var parsed: std.SemanticVersion = .{
        .major = 0,
        .minor = 0,
        .patch = 0,
    };

    const parse_next = struct {
        fn parse_next(it: anytype) ?u16 {
            const nn = it.next() orelse return null;
            return std.fmt.parse_int(u16, nn, 10) catch null;
        }
    }.parse_next;

    var it = std.mem.split_any(u8, raw, ".");
    parsed.major = parse_next(&it) orelse return null;
    parsed.minor = parse_next(&it) orelse return null;
    parsed.patch = parse_next(&it) orelse 0;
    return parsed;
}

/// When allocating, the ideal_capacity is calculated by
/// actual_capacity + (actual_capacity / ideal_factor)
const ideal_factor = 3;

/// In order for a slice of bytes to be considered eligible to keep metadata pointing at
/// it as a possible place to put new symbols, it must have enough room for this many bytes
/// (plus extra for reserved capacity).
const minimum_text_block_size = 64;
pub const min_text_capacity = pad_to_ideal(minimum_text_block_size);

/// Default virtual memory offset corresponds to the size of __PAGEZERO segment and
/// start of __TEXT segment.
pub const default_pagezero_size: u64 = 0x100000000;

/// We commit 0x1000 = 4096 bytes of space to the header and
/// the table of load commands. This should be plenty for any
/// potential future extensions.
pub const default_headerpad_size: u32 = 0x1000;

const SystemLib = struct {
    path: []const u8,
    needed: bool = false,
    weak: bool = false,
    hidden: bool = false,
    reexport: bool = false,
    must_link: bool = false,
};

pub const SdkLayout = std.zig.LibCDirs.DarwinSdkLayout;

const UndefinedTreatment = enum {
    @"error",
    warn,
    suppress,
    dynamic_lookup,
};

const MachO = @This();

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const fs = std.fs;
const log = std.log.scoped(.link);
const state_log = std.log.scoped(.link_state);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const aarch64 = @import("../arch/aarch64/bits.zig");
const calc_uuid = @import("MachO/uuid.zig").calc_uuid;
const codegen = @import("../codegen.zig");
const dead_strip = @import("MachO/dead_strip.zig");
const eh_frame = @import("MachO/eh_frame.zig");
const fat = @import("MachO/fat.zig");
const link = @import("../link.zig");
const llvm_backend = @import("../codegen/llvm.zig");
const load_commands = @import("MachO/load_commands.zig");
const relocatable = @import("MachO/relocatable.zig");
const tapi = @import("tapi.zig");
const target_util = @import("../target.zig");
const thunks = @import("MachO/thunks.zig");
const trace = @import("../tracy.zig").trace;
const synthetic = @import("MachO/synthetic.zig");

const Air = @import("../Air.zig");
const Alignment = Atom.Alignment;
const Allocator = mem.Allocator;
const Archive = @import("MachO/Archive.zig");
pub const Atom = @import("MachO/Atom.zig");
const BindSection = synthetic.BindSection;
const Cache = std.Build.Cache;
const CodeSignature = @import("MachO/CodeSignature.zig");
const Compilation = @import("../Compilation.zig");
pub const DebugSymbols = @import("MachO/DebugSymbols.zig");
const Dylib = @import("MachO/Dylib.zig");
const ExportTrieSection = synthetic.ExportTrieSection;
const File = @import("MachO/file.zig").File;
const GotSection = synthetic.GotSection;
const Hash = std.hash.Wyhash;
const Indsymtab = synthetic.Indsymtab;
const InternalObject = @import("MachO/InternalObject.zig");
const ObjcStubsSection = synthetic.ObjcStubsSection;
const Object = @import("MachO/Object.zig");
const LazyBindSection = synthetic.LazyBindSection;
const LaSymbolPtrSection = synthetic.LaSymbolPtrSection;
const LibStub = tapi.LibStub;
const Liveness = @import("../Liveness.zig");
const LlvmObject = @import("../codegen/llvm.zig").Object;
const Md5 = std.crypto.hash.Md5;
const Module = @import("../Module.zig");
const InternPool = @import("../InternPool.zig");
const RebaseSection = synthetic.RebaseSection;
pub const Relocation = @import("MachO/Relocation.zig");
const StringTable = @import("StringTable.zig");
const StubsSection = synthetic.StubsSection;
const StubsHelperSection = synthetic.StubsHelperSection;
const Symbol = @import("MachO/Symbol.zig");
const Thunk = thunks.Thunk;
const TlvPtrSection = synthetic.TlvPtrSection;
const Value = @import("../Value.zig");
const UnwindInfo = @import("MachO/UnwindInfo.zig");
const WeakBindSection = synthetic.WeakBindSection;
const ZigGotSection = synthetic.ZigGotSection;
const ZigObject = @import("MachO/ZigObject.zig");
