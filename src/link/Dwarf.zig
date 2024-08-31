allocator: Allocator,
bin_file: *File,
format: Format,
ptr_width: PtrWidth,

/// A list of `Atom`s whose Line Number Programs have surplus capacity.
/// This is the same concept as `Section.free_list` in Elf; see those doc comments.
src_fn_free_list: std.AutoHashMapUnmanaged(Atom.Index, void) = .{},
src_fn_first_index: ?Atom.Index = null,
src_fn_last_index: ?Atom.Index = null,
src_fns: std.ArrayListUnmanaged(Atom) = .{},
src_fn_decls: AtomTable = .{},

/// A list of `Atom`s whose corresponding .debug_info tags have surplus capacity.
/// This is the same concept as `text_block_free_list`; see those doc comments.
di_atom_free_list: std.AutoHashMapUnmanaged(Atom.Index, void) = .{},
di_atom_first_index: ?Atom.Index = null,
di_atom_last_index: ?Atom.Index = null,
di_atoms: std.ArrayListUnmanaged(Atom) = .{},
di_atom_decls: AtomTable = .{},

dbg_line_header: DbgLineHeader,

abbrev_table_offset: ?u64 = null,

/// TODO replace with InternPool
/// Table of debug symbol names.
strtab: StringTable = .{},

/// Quick lookup array of all defined source files referenced by at least one Decl.
/// They will end up in the DWARF debug_line header as two lists:
/// * []include_directory
/// * []file_names
di_files: std.AutoArrayHashMapUnmanaged(*const Module.File, void) = .{},

global_abbrev_relocs: std.ArrayListUnmanaged(AbbrevRelocation) = .{},

const AtomTable = std.AutoHashMapUnmanaged(InternPool.DeclIndex, Atom.Index);

const Atom = struct {
    /// Offset into .debug_info pointing to the tag for this Decl, or
    /// offset from the beginning of the Debug Line Program header that contains this function.
    off: u32,
    /// Size of the .debug_info tag for this Decl, not including padding, or
    /// size of the line number program component belonging to this function, not
    /// including padding.
    len: u32,

    prev_index: ?Index,
    next_index: ?Index,

    pub const Index = u32;
};

const DbgLineHeader = struct {
    minimum_instruction_length: u8,
    maximum_operations_per_instruction: u8,
    default_is_stmt: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
};

/// Represents state of the analysed Decl.
/// Includes Decl's abbrev table of type Types, matching arena
/// and a set of relocations that will be resolved once this
/// Decl's inner Atom is assigned an offset within the DWARF section.
pub const DeclState = struct {
    dwarf: *Dwarf,
    mod: *Module,
    di_atom_decls: *const AtomTable,
    dbg_line_func: InternPool.Index,
    dbg_line: std.ArrayList(u8),
    dbg_info: std.ArrayList(u8),
    abbrev_type_arena: std.heap.ArenaAllocator,
    abbrev_table: std.ArrayListUnmanaged(AbbrevEntry),
    abbrev_resolver: std.AutoHashMapUnmanaged(InternPool.Index, u32),
    abbrev_relocs: std.ArrayListUnmanaged(AbbrevRelocation),
    exprloc_relocs: std.ArrayListUnmanaged(ExprlocRelocation),

    pub fn deinit(self: *DeclState) void {
        const gpa = self.dwarf.allocator;
        self.dbg_line.deinit();
        self.dbg_info.deinit();
        self.abbrev_type_arena.deinit();
        self.abbrev_table.deinit(gpa);
        self.abbrev_resolver.deinit(gpa);
        self.abbrev_relocs.deinit(gpa);
        self.exprloc_relocs.deinit(gpa);
    }

    /// Adds local type relocation of the form: @offset => @this + addend
    /// @this signifies the offset within the .debug_abbrev section of the containing atom.
    fn add_type_reloc_local(self: *DeclState, atom_index: Atom.Index, offset: u32, addend: u32) !void {
        log.debug("{x}: @this + {x}", .{ offset, addend });
        try self.abbrev_relocs.append(self.dwarf.allocator, .{
            .target = null,
            .atom_index = atom_index,
            .offset = offset,
            .addend = addend,
        });
    }

    /// Adds global type relocation of the form: @offset => @symbol + 0
    /// @symbol signifies a type abbreviation posititioned somewhere in the .debug_abbrev section
    /// which we use as our target of the relocation.
    fn add_type_reloc_global(self: *DeclState, atom_index: Atom.Index, ty: Type, offset: u32) !void {
        const gpa = self.dwarf.allocator;
        const resolv = self.abbrev_resolver.get(ty.to_intern()) orelse blk: {
            const sym_index: u32 = @int_cast(self.abbrev_table.items.len);
            try self.abbrev_table.append(gpa, .{
                .atom_index = atom_index,
                .type = ty,
                .offset = undefined,
            });
            log.debug("%{d}: {}", .{ sym_index, ty.fmt(self.mod) });
            try self.abbrev_resolver.put_no_clobber(gpa, ty.to_intern(), sym_index);
            break :blk sym_index;
        };
        log.debug("{x}: %{d} + 0", .{ offset, resolv });
        try self.abbrev_relocs.append(gpa, .{
            .target = resolv,
            .atom_index = atom_index,
            .offset = offset,
            .addend = 0,
        });
    }

    fn add_dbg_info_type(
        self: *DeclState,
        mod: *Module,
        atom_index: Atom.Index,
        ty: Type,
    ) error{OutOfMemory}!void {
        const dbg_info_buffer = &self.dbg_info;
        const target = mod.get_target();
        const target_endian = target.cpu.arch.endian();
        const ip = &mod.intern_pool;

        switch (ty.zig_type_tag(mod)) {
            .NoReturn => unreachable,
            .Void => {
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.zero_bit_type));
            },
            .Bool => {
                try dbg_info_buffer.ensure_unused_capacity(12);
                dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.base_type));
                // DW.AT.encoding, DW.FORM.data1
                dbg_info_buffer.append_assume_capacity(DW.ATE.boolean);
                // DW.AT.byte_size, DW.FORM.udata
                try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));
                // DW.AT.name, DW.FORM.string
                try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
            },
            .Int => {
                const info = ty.int_info(mod);
                try dbg_info_buffer.ensure_unused_capacity(12);
                dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.base_type));
                // DW.AT.encoding, DW.FORM.data1
                dbg_info_buffer.append_assume_capacity(switch (info.signedness) {
                    .signed => DW.ATE.signed,
                    .unsigned => DW.ATE.unsigned,
                });
                // DW.AT.byte_size, DW.FORM.udata
                try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));
                // DW.AT.name, DW.FORM.string
                try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
            },
            .Optional => {
                if (ty.is_ptr_like_optional(mod)) {
                    try dbg_info_buffer.ensure_unused_capacity(12);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.base_type));
                    // DW.AT.encoding, DW.FORM.data1
                    dbg_info_buffer.append_assume_capacity(DW.ATE.address);
                    // DW.AT.byte_size, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));
                    // DW.AT.name, DW.FORM.string
                    try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
                } else {
                    // Non-pointer optionals are structs: struct { .maybe = *, .val = * }
                    const payload_ty = ty.optional_child(mod);
                    // DW.AT.structure_type
                    try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_type));
                    // DW.AT.byte_size, DW.FORM.udata
                    const abi_size = ty.abi_size(mod);
                    try leb128.write_uleb128(dbg_info_buffer.writer(), abi_size);
                    // DW.AT.name, DW.FORM.string
                    try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(21);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("maybe");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    var index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, Type.bool, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.member
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("val");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, payload_ty, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    const offset = abi_size - payload_ty.abi_size(mod);
                    try leb128.write_uleb128(dbg_info_buffer.writer(), offset);
                    // DW.AT.structure_type delimit children
                    try dbg_info_buffer.append(0);
                }
            },
            .Pointer => {
                if (ty.is_slice(mod)) {
                    // Slices are structs: struct { .ptr = *, .len = N }
                    const ptr_bits = target.ptr_bit_width();
                    const ptr_bytes: u8 = @int_cast(@div_exact(ptr_bits, 8));
                    // DW.AT.structure_type
                    try dbg_info_buffer.ensure_unused_capacity(2);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_type));
                    // DW.AT.byte_size, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));
                    // DW.AT.name, DW.FORM.string
                    try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(21);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("ptr");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    var index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    const ptr_ty = ty.slice_ptr_field_type(mod);
                    try self.add_type_reloc_global(atom_index, ptr_ty, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.member
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("len");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, Type.usize, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    dbg_info_buffer.append_assume_capacity(ptr_bytes);
                    // DW.AT.structure_type delimit children
                    dbg_info_buffer.append_assume_capacity(0);
                } else {
                    try dbg_info_buffer.ensure_unused_capacity(9);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.ptr_type));
                    // DW.AT.type, DW.FORM.ref4
                    const index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, ty.child_type(mod), @int_cast(index));
                }
            },
            .Array => {
                // DW.AT.array_type
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.array_type));
                // DW.AT.name, DW.FORM.string
                try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});
                // DW.AT.type, DW.FORM.ref4
                var index = dbg_info_buffer.items.len;
                try dbg_info_buffer.ensure_unused_capacity(9);
                dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                try self.add_type_reloc_global(atom_index, ty.child_type(mod), @int_cast(index));
                // DW.AT.subrange_type
                dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.array_dim));
                // DW.AT.type, DW.FORM.ref4
                index = dbg_info_buffer.items.len;
                dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                try self.add_type_reloc_global(atom_index, Type.usize, @int_cast(index));
                // DW.AT.count, DW.FORM.udata
                const len = ty.array_len_including_sentinel(mod);
                try leb128.write_uleb128(dbg_info_buffer.writer(), len);
                // DW.AT.array_type delimit children
                try dbg_info_buffer.append(0);
            },
            .Struct => {
                // DW.AT.structure_type
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_type));
                // DW.AT.byte_size, DW.FORM.udata
                try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));

                blk: {
                    switch (ip.index_to_key(ty.ip_index)) {
                        .anon_struct_type => |fields| {
                            // DW.AT.name, DW.FORM.string
                            try dbg_info_buffer.writer().print("{}\x00", .{ty.fmt(mod)});

                            for (fields.types.get(ip), 0..) |field_ty, field_index| {
                                // DW.AT.member
                                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_member));
                                // DW.AT.name, DW.FORM.string
                                try dbg_info_buffer.writer().print("{d}\x00", .{field_index});
                                // DW.AT.type, DW.FORM.ref4
                                const index = dbg_info_buffer.items.len;
                                try dbg_info_buffer.append_ntimes(0, 4);
                                try self.add_type_reloc_global(atom_index, Type.from_interned(field_ty), @int_cast(index));
                                // DW.AT.data_member_location, DW.FORM.udata
                                const field_off = ty.struct_field_offset(field_index, mod);
                                try leb128.write_uleb128(dbg_info_buffer.writer(), field_off);
                            }
                        },
                        .struct_type => {
                            const struct_type = ip.load_struct_type(ty.to_intern());
                            // DW.AT.name, DW.FORM.string
                            try ty.print(dbg_info_buffer.writer(), mod);
                            try dbg_info_buffer.append(0);

                            if (struct_type.layout == .@"packed") {
                                log.debug("TODO implement .debug_info for packed structs", .{});
                                break :blk;
                            }

                            if (struct_type.is_tuple(ip)) {
                                for (struct_type.field_types.get(ip), struct_type.offsets.get(ip), 0..) |field_ty, field_off, field_index| {
                                    if (!Type.from_interned(field_ty).has_runtime_bits(mod)) continue;
                                    // DW.AT.member
                                    try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_member));
                                    // DW.AT.name, DW.FORM.string
                                    try dbg_info_buffer.writer().print("{d}\x00", .{field_index});
                                    // DW.AT.type, DW.FORM.ref4
                                    const index = dbg_info_buffer.items.len;
                                    try dbg_info_buffer.append_ntimes(0, 4);
                                    try self.add_type_reloc_global(atom_index, Type.from_interned(field_ty), @int_cast(index));
                                    // DW.AT.data_member_location, DW.FORM.udata
                                    try leb128.write_uleb128(dbg_info_buffer.writer(), field_off);
                                }
                            } else {
                                for (
                                    struct_type.field_names.get(ip),
                                    struct_type.field_types.get(ip),
                                    struct_type.offsets.get(ip),
                                ) |field_name, field_ty, field_off| {
                                    if (!Type.from_interned(field_ty).has_runtime_bits(mod)) continue;
                                    const field_name_slice = field_name.to_slice(ip);
                                    // DW.AT.member
                                    try dbg_info_buffer.ensure_unused_capacity(field_name_slice.len + 2);
                                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                                    // DW.AT.name, DW.FORM.string
                                    dbg_info_buffer.append_slice_assume_capacity(field_name_slice[0 .. field_name_slice.len + 1]);
                                    // DW.AT.type, DW.FORM.ref4
                                    const index = dbg_info_buffer.items.len;
                                    try dbg_info_buffer.append_ntimes(0, 4);
                                    try self.add_type_reloc_global(atom_index, Type.from_interned(field_ty), @int_cast(index));
                                    // DW.AT.data_member_location, DW.FORM.udata
                                    try leb128.write_uleb128(dbg_info_buffer.writer(), field_off);
                                }
                            }
                        },
                        else => unreachable,
                    }
                }

                // DW.AT.structure_type delimit children
                try dbg_info_buffer.append(0);
            },
            .Enum => {
                // DW.AT.enumeration_type
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.enum_type));
                // DW.AT.byte_size, DW.FORM.udata
                try leb128.write_uleb128(dbg_info_buffer.writer(), ty.abi_size(mod));
                // DW.AT.name, DW.FORM.string
                try ty.print(dbg_info_buffer.writer(), mod);
                try dbg_info_buffer.append(0);

                const enum_type = ip.load_enum_type(ty.ip_index);
                for (enum_type.names.get(ip), 0..) |field_name, field_i| {
                    const field_name_slice = field_name.to_slice(ip);
                    // DW.AT.enumerator
                    try dbg_info_buffer.ensure_unused_capacity(field_name_slice.len + 2 + @size_of(u64));
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.enum_variant));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity(field_name_slice[0 .. field_name_slice.len + 1]);
                    // DW.AT.const_value, DW.FORM.data8
                    const value: u64 = value: {
                        if (enum_type.values.len == 0) break :value field_i; // auto-numbered
                        const value = enum_type.values.get(ip)[field_i];
                        // TODO do not assume a 64bit enum value - could be bigger.
                        // See https://github.com/ziglang/zig/issues/645
                        const field_int_val = try Value.from_interned(value).int_from_enum(ty, mod);
                        break :value @bit_cast(field_int_val.to_signed_int(mod));
                    };
                    mem.write_int(u64, dbg_info_buffer.add_many_as_array_assume_capacity(8), value, target_endian);
                }

                // DW.AT.enumeration_type delimit children
                try dbg_info_buffer.append(0);
            },
            .Union => {
                const union_obj = mod.type_to_union(ty).?;
                const layout = mod.get_union_layout(union_obj);
                const payload_offset = if (layout.tag_align.compare(.gte, layout.payload_align)) layout.tag_size else 0;
                const tag_offset = if (layout.tag_align.compare(.gte, layout.payload_align)) 0 else layout.payload_size;
                // TODO this is temporary to match current state of unions in Zig - we don't yet have
                // safety checks implemented meaning the implicit tag is not yet stored and generated
                // for untagged unions.
                const is_tagged = layout.tag_size > 0;
                if (is_tagged) {
                    // DW.AT.structure_type
                    try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_type));
                    // DW.AT.byte_size, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), layout.abi_size);
                    // DW.AT.name, DW.FORM.string
                    try ty.print(dbg_info_buffer.writer(), mod);
                    try dbg_info_buffer.append(0);

                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(13);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("payload");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    const inner_union_index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_local(atom_index, @int_cast(inner_union_index), 5);
                    // DW.AT.data_member_location, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), payload_offset);
                }

                // DW.AT.union_type
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.union_type));
                // DW.AT.byte_size, DW.FORM.udata,
                try leb128.write_uleb128(dbg_info_buffer.writer(), layout.payload_size);
                // DW.AT.name, DW.FORM.string
                if (is_tagged) {
                    try dbg_info_buffer.writer().print("AnonUnion\x00", .{});
                } else {
                    try ty.print(dbg_info_buffer.writer(), mod);
                    try dbg_info_buffer.append(0);
                }

                for (union_obj.field_types.get(ip), union_obj.load_tag_type(ip).names.get(ip)) |field_ty, field_name| {
                    if (!Type.from_interned(field_ty).has_runtime_bits(mod)) continue;
                    const field_name_slice = field_name.to_slice(ip);
                    // DW.AT.member
                    try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    try dbg_info_buffer.append_slice(field_name_slice[0 .. field_name_slice.len + 1]);
                    // DW.AT.type, DW.FORM.ref4
                    const index = dbg_info_buffer.items.len;
                    try dbg_info_buffer.append_ntimes(0, 4);
                    try self.add_type_reloc_global(atom_index, Type.from_interned(field_ty), @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    try dbg_info_buffer.append(0);
                }
                // DW.AT.union_type delimit children
                try dbg_info_buffer.append(0);

                if (is_tagged) {
                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(9);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("tag");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    const index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, Type.from_interned(union_obj.enum_tag_ty), @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), tag_offset);

                    // DW.AT.structure_type delimit children
                    try dbg_info_buffer.append(0);
                }
            },
            .ErrorSet => try add_dbg_info_error_set(mod, ty, target, &self.dbg_info),
            .ErrorUnion => {
                const error_ty = ty.error_union_set(mod);
                const payload_ty = ty.error_union_payload(mod);
                const payload_align = if (payload_ty.is_no_return(mod)) .none else payload_ty.abi_alignment(mod);
                const error_align = Type.anyerror.abi_alignment(mod);
                const abi_size = ty.abi_size(mod);
                const payload_off = if (error_align.compare(.gte, payload_align)) Type.anyerror.abi_size(mod) else 0;
                const error_off = if (error_align.compare(.gte, payload_align)) 0 else payload_ty.abi_size(mod);

                // DW.AT.structure_type
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.struct_type));
                // DW.AT.byte_size, DW.FORM.udata
                try leb128.write_uleb128(dbg_info_buffer.writer(), abi_size);
                // DW.AT.name, DW.FORM.string
                try ty.print(dbg_info_buffer.writer(), mod);
                try dbg_info_buffer.append(0);

                if (!payload_ty.is_no_return(mod)) {
                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(11);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("value");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    const index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, payload_ty, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), payload_off);
                }

                {
                    // DW.AT.member
                    try dbg_info_buffer.ensure_unused_capacity(9);
                    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.struct_member));
                    // DW.AT.name, DW.FORM.string
                    dbg_info_buffer.append_slice_assume_capacity("err");
                    dbg_info_buffer.append_assume_capacity(0);
                    // DW.AT.type, DW.FORM.ref4
                    const index = dbg_info_buffer.items.len;
                    dbg_info_buffer.append_ntimes_assume_capacity(0, 4);
                    try self.add_type_reloc_global(atom_index, error_ty, @int_cast(index));
                    // DW.AT.data_member_location, DW.FORM.udata
                    try leb128.write_uleb128(dbg_info_buffer.writer(), error_off);
                }

                // DW.AT.structure_type delimit children
                try dbg_info_buffer.append(0);
            },
            else => {
                log.debug("TODO implement .debug_info for type '{}'", .{ty.fmt(self.mod)});
                try dbg_info_buffer.append(@int_from_enum(AbbrevCode.zero_bit_type));
            },
        }
    }

    pub const DbgInfoLoc = union(enum) {
        register: u8,
        register_pair: [2]u8,
        stack: struct {
            fp_register: u8,
            offset: i32,
        },
        wasm_local: u32,
        memory: u64,
        linker_load: LinkerLoad,
        immediate: u64,
        undef,
        none,
        nop,
    };

    pub fn gen_arg_dbg_info(
        self: *DeclState,
        name: [:0]const u8,
        ty: Type,
        owner_decl: InternPool.DeclIndex,
        loc: DbgInfoLoc,
    ) error{OutOfMemory}!void {
        const dbg_info = &self.dbg_info;
        const atom_index = self.di_atom_decls.get(owner_decl).?;
        const name_with_null = name.ptr[0 .. name.len + 1];

        switch (loc) {
            .register => |reg| {
                try dbg_info.ensure_unused_capacity(4);
                dbg_info.append_assume_capacity(@int_from_enum(AbbrevCode.parameter));
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                if (reg < 32) {
                    expr_len.writer().write_byte(DW.OP.reg0 + reg) catch unreachable;
                } else {
                    expr_len.writer().write_byte(DW.OP.regx) catch unreachable;
                    leb128.write_uleb128(expr_len.writer(), reg) catch unreachable;
                }
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                if (reg < 32) {
                    dbg_info.append_assume_capacity(DW.OP.reg0 + reg);
                } else {
                    dbg_info.append_assume_capacity(DW.OP.regx);
                    leb128.write_uleb128(dbg_info.writer(), reg) catch unreachable;
                }
            },
            .register_pair => |regs| {
                const reg_bits = self.mod.get_target().ptr_bit_width();
                const reg_bytes: u8 = @int_cast(@div_exact(reg_bits, 8));
                const abi_size = ty.abi_size(self.mod);
                try dbg_info.ensure_unused_capacity(10);
                dbg_info.append_assume_capacity(@int_from_enum(AbbrevCode.parameter));
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                for (regs, 0..) |reg, reg_i| {
                    if (reg < 32) {
                        expr_len.writer().write_byte(DW.OP.reg0 + reg) catch unreachable;
                    } else {
                        expr_len.writer().write_byte(DW.OP.regx) catch unreachable;
                        leb128.write_uleb128(expr_len.writer(), reg) catch unreachable;
                    }
                    expr_len.writer().write_byte(DW.OP.piece) catch unreachable;
                    leb128.write_uleb128(
                        expr_len.writer(),
                        @min(abi_size - reg_i * reg_bytes, reg_bytes),
                    ) catch unreachable;
                }
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                for (regs, 0..) |reg, reg_i| {
                    if (reg < 32) {
                        dbg_info.append_assume_capacity(DW.OP.reg0 + reg);
                    } else {
                        dbg_info.append_assume_capacity(DW.OP.regx);
                        leb128.write_uleb128(dbg_info.writer(), reg) catch unreachable;
                    }
                    dbg_info.append_assume_capacity(DW.OP.piece);
                    leb128.write_uleb128(
                        dbg_info.writer(),
                        @min(abi_size - reg_i * reg_bytes, reg_bytes),
                    ) catch unreachable;
                }
            },
            .stack => |info| {
                try dbg_info.ensure_unused_capacity(9);
                dbg_info.append_assume_capacity(@int_from_enum(AbbrevCode.parameter));
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                if (info.fp_register < 32) {
                    expr_len.writer().write_byte(DW.OP.breg0 + info.fp_register) catch unreachable;
                } else {
                    expr_len.writer().write_byte(DW.OP.bregx) catch unreachable;
                    leb128.write_uleb128(expr_len.writer(), info.fp_register) catch unreachable;
                }
                leb128.write_ileb128(expr_len.writer(), info.offset) catch unreachable;
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                if (info.fp_register < 32) {
                    dbg_info.append_assume_capacity(DW.OP.breg0 + info.fp_register);
                } else {
                    dbg_info.append_assume_capacity(DW.OP.bregx);
                    leb128.write_uleb128(dbg_info.writer(), info.fp_register) catch unreachable;
                }
                leb128.write_ileb128(dbg_info.writer(), info.offset) catch unreachable;
            },
            .wasm_local => |value| {
                const leb_size = link.File.Wasm.get_uleb128_size(value);
                try dbg_info.ensure_unused_capacity(3 + leb_size);
                // wasm locations are encoded as follow:
                // DW_OP_WASM_location wasm-op
                // where wasm-op is defined as
                // wasm-op := wasm-local | wasm-global | wasm-operand_stack
                // where each argument is encoded as
                // <opcode> i:uleb128
                dbg_info.append_slice_assume_capacity(&.{
                    @int_from_enum(AbbrevCode.parameter),
                    DW.OP.WASM_location,
                    DW.OP.WASM_local,
                });
                leb128.write_uleb128(dbg_info.writer(), value) catch unreachable;
            },
            else => unreachable,
        }

        try dbg_info.ensure_unused_capacity(5 + name_with_null.len);
        const index = dbg_info.items.len;
        dbg_info.append_ntimes_assume_capacity(0, 4);
        try self.add_type_reloc_global(atom_index, ty, @int_cast(index)); // DW.AT.type, DW.FORM.ref4
        dbg_info.append_slice_assume_capacity(name_with_null); // DW.AT.name, DW.FORM.string
    }

    pub fn gen_var_dbg_info(
        self: *DeclState,
        name: [:0]const u8,
        ty: Type,
        owner_decl: InternPool.DeclIndex,
        is_ptr: bool,
        loc: DbgInfoLoc,
    ) error{OutOfMemory}!void {
        const dbg_info = &self.dbg_info;
        const atom_index = self.di_atom_decls.get(owner_decl).?;
        const name_with_null = name.ptr[0 .. name.len + 1];
        try dbg_info.append(@int_from_enum(AbbrevCode.variable));
        const gpa = self.dwarf.allocator;
        const mod = self.mod;
        const target = mod.get_target();
        const endian = target.cpu.arch.endian();
        const child_ty = if (is_ptr) ty.child_type(mod) else ty;

        switch (loc) {
            .register => |reg| {
                try dbg_info.ensure_unused_capacity(3);
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                if (reg < 32) {
                    expr_len.writer().write_byte(DW.OP.reg0 + reg) catch unreachable;
                } else {
                    expr_len.writer().write_byte(DW.OP.regx) catch unreachable;
                    leb128.write_uleb128(expr_len.writer(), reg) catch unreachable;
                }
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                if (reg < 32) {
                    dbg_info.append_assume_capacity(DW.OP.reg0 + reg);
                } else {
                    dbg_info.append_assume_capacity(DW.OP.regx);
                    leb128.write_uleb128(dbg_info.writer(), reg) catch unreachable;
                }
            },

            .register_pair => |regs| {
                const reg_bits = self.mod.get_target().ptr_bit_width();
                const reg_bytes: u8 = @int_cast(@div_exact(reg_bits, 8));
                const abi_size = child_ty.abi_size(self.mod);
                try dbg_info.ensure_unused_capacity(9);
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                for (regs, 0..) |reg, reg_i| {
                    if (reg < 32) {
                        expr_len.writer().write_byte(DW.OP.reg0 + reg) catch unreachable;
                    } else {
                        expr_len.writer().write_byte(DW.OP.regx) catch unreachable;
                        leb128.write_uleb128(expr_len.writer(), reg) catch unreachable;
                    }
                    expr_len.writer().write_byte(DW.OP.piece) catch unreachable;
                    leb128.write_uleb128(
                        expr_len.writer(),
                        @min(abi_size - reg_i * reg_bytes, reg_bytes),
                    ) catch unreachable;
                }
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                for (regs, 0..) |reg, reg_i| {
                    if (reg < 32) {
                        dbg_info.append_assume_capacity(DW.OP.reg0 + reg);
                    } else {
                        dbg_info.append_assume_capacity(DW.OP.regx);
                        leb128.write_uleb128(dbg_info.writer(), reg) catch unreachable;
                    }
                    dbg_info.append_assume_capacity(DW.OP.piece);
                    leb128.write_uleb128(
                        dbg_info.writer(),
                        @min(abi_size - reg_i * reg_bytes, reg_bytes),
                    ) catch unreachable;
                }
            },

            .stack => |info| {
                try dbg_info.ensure_unused_capacity(9);
                // DW.AT.location, DW.FORM.exprloc
                var expr_len = std.io.counting_writer(std.io.null_writer);
                if (info.fp_register < 32) {
                    expr_len.writer().write_byte(DW.OP.breg0 + info.fp_register) catch unreachable;
                } else {
                    expr_len.writer().write_byte(DW.OP.bregx) catch unreachable;
                    leb128.write_uleb128(expr_len.writer(), info.fp_register) catch unreachable;
                }
                leb128.write_ileb128(expr_len.writer(), info.offset) catch unreachable;
                leb128.write_uleb128(dbg_info.writer(), expr_len.bytes_written) catch unreachable;
                if (info.fp_register < 32) {
                    dbg_info.append_assume_capacity(DW.OP.breg0 + info.fp_register);
                } else {
                    dbg_info.append_assume_capacity(DW.OP.bregx);
                    leb128.write_uleb128(dbg_info.writer(), info.fp_register) catch unreachable;
                }
                leb128.write_ileb128(dbg_info.writer(), info.offset) catch unreachable;
            },

            .wasm_local => |value| {
                const leb_size = link.File.Wasm.get_uleb128_size(value);
                try dbg_info.ensure_unused_capacity(2 + leb_size);
                // wasm locals are encoded as follow:
                // DW_OP_WASM_location wasm-op
                // where wasm-op is defined as
                // wasm-op := wasm-local | wasm-global | wasm-operand_stack
                // where wasm-local is encoded as
                // wasm-local := 0x00 i:uleb128
                dbg_info.append_slice_assume_capacity(&.{
                    DW.OP.WASM_location,
                    DW.OP.WASM_local,
                });
                leb128.write_uleb128(dbg_info.writer(), value) catch unreachable;
            },

            .memory,
            .linker_load,
            => {
                const ptr_width: u8 = @int_cast(@div_exact(target.ptr_bit_width(), 8));
                try dbg_info.ensure_unused_capacity(2 + ptr_width);
                dbg_info.append_slice_assume_capacity(&[2]u8{ // DW.AT.location, DW.FORM.exprloc
                    1 + ptr_width + @int_from_bool(is_ptr),
                    DW.OP.addr, // literal address
                });
                const offset: u32 = @int_cast(dbg_info.items.len);
                const addr = switch (loc) {
                    .memory => |x| x,
                    else => 0,
                };
                switch (ptr_width) {
                    0...4 => {
                        try dbg_info.writer().write_int(u32, @int_cast(addr), endian);
                    },
                    5...8 => {
                        try dbg_info.writer().write_int(u64, addr, endian);
                    },
                    else => unreachable,
                }
                if (is_ptr) {
                    // We need deref the address as we point to the value via GOT entry.
                    try dbg_info.append(DW.OP.deref);
                }
                switch (loc) {
                    .linker_load => |load_struct| switch (load_struct.type) {
                        .direct => {
                            log.debug("{x}: target sym %{d}", .{ offset, load_struct.sym_index });
                            try self.exprloc_relocs.append(gpa, .{
                                .type = .direct_load,
                                .target = load_struct.sym_index,
                                .offset = offset,
                            });
                        },
                        .got => {
                            log.debug("{x}: target sym %{d} via GOT", .{ offset, load_struct.sym_index });
                            try self.exprloc_relocs.append(gpa, .{
                                .type = .got_load,
                                .target = load_struct.sym_index,
                                .offset = offset,
                            });
                        },
                        else => {}, // TODO
                    },
                    else => {},
                }
            },

            .immediate => |x| {
                try dbg_info.ensure_unused_capacity(2);
                const fixup = dbg_info.items.len;
                dbg_info.append_slice_assume_capacity(&[2]u8{ // DW.AT.location, DW.FORM.exprloc
                    1,
                    if (child_ty.is_signed_int(mod)) DW.OP.consts else DW.OP.constu,
                });
                if (child_ty.is_signed_int(mod)) {
                    try leb128.write_ileb128(dbg_info.writer(), @as(i64, @bit_cast(x)));
                } else {
                    try leb128.write_uleb128(dbg_info.writer(), x);
                }
                try dbg_info.append(DW.OP.stack_value);
                dbg_info.items[fixup] += @int_cast(dbg_info.items.len - fixup - 2);
            },

            .undef => {
                // DW.AT.location, DW.FORM.exprloc
                // uleb128(exprloc_len)
                // DW.OP.implicit_value uleb128(len_of_bytes) bytes
                const abi_size: u32 = @int_cast(child_ty.abi_size(mod));
                var implicit_value_len = std.ArrayList(u8).init(gpa);
                defer implicit_value_len.deinit();
                try leb128.write_uleb128(implicit_value_len.writer(), abi_size);
                const total_exprloc_len = 1 + implicit_value_len.items.len + abi_size;
                try leb128.write_uleb128(dbg_info.writer(), total_exprloc_len);
                try dbg_info.ensure_unused_capacity(total_exprloc_len);
                dbg_info.append_assume_capacity(DW.OP.implicit_value);
                dbg_info.append_slice_assume_capacity(implicit_value_len.items);
                dbg_info.append_ntimes_assume_capacity(0xaa, abi_size);
            },

            .none => {
                try dbg_info.ensure_unused_capacity(3);
                dbg_info.append_slice_assume_capacity(&[3]u8{ // DW.AT.location, DW.FORM.exprloc
                    2, DW.OP.lit0, DW.OP.stack_value,
                });
            },

            .nop => {
                try dbg_info.ensure_unused_capacity(2);
                dbg_info.append_slice_assume_capacity(&[2]u8{ // DW.AT.location, DW.FORM.exprloc
                    1, DW.OP.nop,
                });
            },
        }

        try dbg_info.ensure_unused_capacity(5 + name_with_null.len);
        const index = dbg_info.items.len;
        dbg_info.append_ntimes_assume_capacity(0, 4); // dw.at.type, dw.form.ref4
        try self.add_type_reloc_global(atom_index, child_ty, @int_cast(index));
        dbg_info.append_slice_assume_capacity(name_with_null); // DW.AT.name, DW.FORM.string
    }

    pub fn advance_pcand_line(
        self: *DeclState,
        delta_line: i33,
        delta_pc: u64,
    ) error{OutOfMemory}!void {
        const dbg_line = &self.dbg_line;
        try dbg_line.ensure_unused_capacity(5 + 5 + 1);

        const header = self.dwarf.dbg_line_header;
        assert(header.maximum_operations_per_instruction == 1);
        const delta_op: u64 = 0;

        const remaining_delta_line: i9 = @int_cast(if (delta_line < header.line_base or
            delta_line - header.line_base >= header.line_range)
        remaining: {
            assert(delta_line != 0);
            dbg_line.append_assume_capacity(DW.LNS.advance_line);
            leb128.write_ileb128(dbg_line.writer(), delta_line) catch unreachable;
            break :remaining 0;
        } else delta_line);

        const op_advance = @div_exact(delta_pc, header.minimum_instruction_length) *
            header.maximum_operations_per_instruction + delta_op;
        const max_op_advance: u9 = (std.math.max_int(u8) - header.opcode_base) / header.line_range;
        const remaining_op_advance: u8 = @int_cast(if (op_advance >= 2 * max_op_advance) remaining: {
            dbg_line.append_assume_capacity(DW.LNS.advance_pc);
            leb128.write_uleb128(dbg_line.writer(), op_advance) catch unreachable;
            break :remaining 0;
        } else if (op_advance >= max_op_advance) remaining: {
            dbg_line.append_assume_capacity(DW.LNS.const_add_pc);
            break :remaining op_advance - max_op_advance;
        } else op_advance);

        if (remaining_delta_line == 0 and remaining_op_advance == 0) {
            dbg_line.append_assume_capacity(DW.LNS.copy);
        } else {
            dbg_line.append_assume_capacity(@int_cast((remaining_delta_line - header.line_base) +
                (header.line_range * remaining_op_advance) + header.opcode_base));
        }
    }

    pub fn set_column(self: *DeclState, column: u32) error{OutOfMemory}!void {
        try self.dbg_line.ensure_unused_capacity(1 + 5);
        self.dbg_line.append_assume_capacity(DW.LNS.set_column);
        leb128.write_uleb128(self.dbg_line.writer(), column + 1) catch unreachable;
    }

    pub fn set_prologue_end(self: *DeclState) error{OutOfMemory}!void {
        try self.dbg_line.append(DW.LNS.set_prologue_end);
    }

    pub fn set_epilogue_begin(self: *DeclState) error{OutOfMemory}!void {
        try self.dbg_line.append(DW.LNS.set_epilogue_begin);
    }

    pub fn set_inline_func(self: *DeclState, func: InternPool.Index) error{OutOfMemory}!void {
        if (self.dbg_line_func == func) return;

        try self.dbg_line.ensure_unused_capacity((1 + 4) + (1 + 5));

        const old_func_info = self.mod.func_info(self.dbg_line_func);
        const new_func_info = self.mod.func_info(func);

        const old_file = try self.dwarf.add_difile(self.mod, old_func_info.owner_decl);
        const new_file = try self.dwarf.add_difile(self.mod, new_func_info.owner_decl);
        if (old_file != new_file) {
            self.dbg_line.append_assume_capacity(DW.LNS.set_file);
            leb128.write_unsigned_fixed(4, self.dbg_line.add_many_as_array_assume_capacity(4), new_file);
        }

        const old_src_line: i33 = self.mod.decl_ptr(old_func_info.owner_decl).src_line;
        const new_src_line: i33 = self.mod.decl_ptr(new_func_info.owner_decl).src_line;
        if (new_src_line != old_src_line) {
            self.dbg_line.append_assume_capacity(DW.LNS.advance_line);
            leb128.write_signed_fixed(5, self.dbg_line.add_many_as_array_assume_capacity(5), new_src_line - old_src_line);
        }

        self.dbg_line_func = func;
    }
};

pub const AbbrevEntry = struct {
    atom_index: Atom.Index,
    type: Type,
    offset: u32,
};

pub const AbbrevRelocation = struct {
    /// If target is null, we deal with a local relocation that is based on simple offset + addend
    /// only.
    target: ?u32,
    atom_index: Atom.Index,
    offset: u32,
    addend: u32,
};

pub const ExprlocRelocation = struct {
    /// Type of the relocation: direct load ref, or GOT load ref (via GOT table)
    type: enum {
        direct_load,
        got_load,
    },
    /// Index of the target in the linker's locals symbol table.
    target: u32,
    /// Offset within the debug info buffer where to patch up the address value.
    offset: u32,
};

pub const PtrWidth = enum { p32, p64 };

pub const AbbrevCode = enum(u8) {
    null,
    padding,
    compile_unit,
    subprogram,
    subprogram_retvoid,
    base_type,
    ptr_type,
    struct_type,
    struct_member,
    enum_type,
    enum_variant,
    union_type,
    zero_bit_type,
    parameter,
    variable,
    array_type,
    array_dim,
};

/// The reloc offset for the virtual address of a function in its Line Number Program.
/// Size is a virtual address integer.
const dbg_line_vaddr_reloc_index = 3;
/// The reloc offset for the virtual address of a function in its .debug_info TAG.subprogram.
/// Size is a virtual address integer.
const dbg_info_low_pc_reloc_index = 1;

const min_nop_size = 2;

/// When allocating, the ideal_capacity is calculated by
/// actual_capacity + (actual_capacity / ideal_factor)
const ideal_factor = 3;

pub fn init(lf: *File, format: Format) Dwarf {
    const comp = lf.comp;
    const gpa = comp.gpa;
    const target = comp.root_mod.resolved_target.result;
    const ptr_width: PtrWidth = switch (target.ptr_bit_width()) {
        0...32 => .p32,
        33...64 => .p64,
        else => unreachable,
    };
    return .{
        .allocator = gpa,
        .bin_file = lf,
        .format = format,
        .ptr_width = ptr_width,
        .dbg_line_header = switch (target.cpu.arch) {
            .x86_64, .aarch64 => .{
                .minimum_instruction_length = 1,
                .maximum_operations_per_instruction = 1,
                .default_is_stmt = true,
                .line_base = -5,
                .line_range = 14,
                .opcode_base = DW.LNS.set_isa + 1,
            },
            else => .{
                .minimum_instruction_length = 1,
                .maximum_operations_per_instruction = 1,
                .default_is_stmt = true,
                .line_base = 1,
                .line_range = 1,
                .opcode_base = DW.LNS.set_isa + 1,
            },
        },
    };
}

pub fn deinit(self: *Dwarf) void {
    const gpa = self.allocator;

    self.src_fn_free_list.deinit(gpa);
    self.src_fns.deinit(gpa);
    self.src_fn_decls.deinit(gpa);

    self.di_atom_free_list.deinit(gpa);
    self.di_atoms.deinit(gpa);
    self.di_atom_decls.deinit(gpa);

    self.strtab.deinit(gpa);
    self.di_files.deinit(gpa);
    self.global_abbrev_relocs.deinit(gpa);
}

/// Initializes Decl's state and its matching output buffers.
/// Call this before `commit_decl_state`.
pub fn init_decl_state(self: *Dwarf, mod: *Module, decl_index: InternPool.DeclIndex) !DeclState {
    const tracy = trace(@src());
    defer tracy.end();

    const decl = mod.decl_ptr(decl_index);
    const decl_linkage_name = try decl.fully_qualified_name(mod);

    log.debug("init_decl_state {}{*}", .{ decl_linkage_name.fmt(&mod.intern_pool), decl });

    const gpa = self.allocator;
    var decl_state: DeclState = .{
        .dwarf = self,
        .mod = mod,
        .di_atom_decls = &self.di_atom_decls,
        .dbg_line_func = undefined,
        .dbg_line = std.ArrayList(u8).init(gpa),
        .dbg_info = std.ArrayList(u8).init(gpa),
        .abbrev_type_arena = std.heap.ArenaAllocator.init(gpa),
        .abbrev_table = .{},
        .abbrev_resolver = .{},
        .abbrev_relocs = .{},
        .exprloc_relocs = .{},
    };
    errdefer decl_state.deinit();
    const dbg_line_buffer = &decl_state.dbg_line;
    const dbg_info_buffer = &decl_state.dbg_info;

    const di_atom_index = try self.get_or_create_atom_for_decl(.di_atom, decl_index);

    assert(decl.has_tv);

    switch (decl.type_of(mod).zig_type_tag(mod)) {
        .Fn => {
            _ = try self.get_or_create_atom_for_decl(.src_fn, decl_index);

            // For functions we need to add a prologue to the debug line program.
            const ptr_width_bytes = self.ptr_width_bytes();
            try dbg_line_buffer.ensure_total_capacity((3 + ptr_width_bytes) + (1 + 4) + (1 + 4) + (1 + 5) + 1);

            decl_state.dbg_line_func = decl.val.to_intern();
            const func = decl.val.get_function(mod).?;
            log.debug("decl.src_line={d}, func.lbrace_line={d}, func.rbrace_line={d}", .{
                decl.src_line,
                func.lbrace_line,
                func.rbrace_line,
            });
            const line: u28 = @int_cast(decl.src_line + func.lbrace_line);

            dbg_line_buffer.append_slice_assume_capacity(&.{
                DW.LNS.extended_op,
                ptr_width_bytes + 1,
                DW.LNE.set_address,
            });
            // This is the "relocatable" vaddr, corresponding to `code_buffer` index `0`.
            assert(dbg_line_vaddr_reloc_index == dbg_line_buffer.items.len);
            dbg_line_buffer.append_ntimes_assume_capacity(0, ptr_width_bytes);

            dbg_line_buffer.append_assume_capacity(DW.LNS.advance_line);
            // This is the "relocatable" relative line offset from the previous function's end curly
            // to this function's begin curly.
            assert(self.get_reloc_dbg_line_off() == dbg_line_buffer.items.len);
            // Here we use a ULEB128-fixed-4 to make sure this field can be overwritten later.
            leb128.write_unsigned_fixed(4, dbg_line_buffer.add_many_as_array_assume_capacity(4), line);

            dbg_line_buffer.append_assume_capacity(DW.LNS.set_file);
            assert(self.get_reloc_dbg_file_index() == dbg_line_buffer.items.len);
            // Once we support more than one source file, this will have the ability to be more
            // than one possible value.
            const file_index = try self.add_difile(mod, decl_index);
            leb128.write_unsigned_fixed(4, dbg_line_buffer.add_many_as_array_assume_capacity(4), file_index);

            dbg_line_buffer.append_assume_capacity(DW.LNS.set_column);
            leb128.write_uleb128(dbg_line_buffer.writer(), func.lbrace_column + 1) catch unreachable;

            // Emit a line for the begin curly with prologue_end=false. The codegen will
            // do the work of setting prologue_end=true and epilogue_begin=true.
            dbg_line_buffer.append_assume_capacity(DW.LNS.copy);

            // .debug_info subprogram
            const decl_name_slice = decl.name.to_slice(&mod.intern_pool);
            const decl_linkage_name_slice = decl_linkage_name.to_slice(&mod.intern_pool);
            try dbg_info_buffer.ensure_unused_capacity(1 + ptr_width_bytes + 4 + 4 +
                (decl_name_slice.len + 1) + (decl_linkage_name_slice.len + 1));

            const fn_ret_type = decl.type_of(mod).fn_return_type(mod);
            const fn_ret_has_bits = fn_ret_type.has_runtime_bits(mod);
            dbg_info_buffer.append_assume_capacity(@int_from_enum(
                @as(AbbrevCode, if (fn_ret_has_bits) .subprogram else .subprogram_retvoid),
            ));
            // These get overwritten after generating the machine code. These values are
            // "relocations" and have to be in this fixed place so that functions can be
            // moved in virtual address space.
            assert(dbg_info_low_pc_reloc_index == dbg_info_buffer.items.len);
            dbg_info_buffer.append_ntimes_assume_capacity(0, ptr_width_bytes); // DW.AT.low_pc, DW.FORM.addr
            assert(self.get_reloc_dbg_info_subprogram_high_pc() == dbg_info_buffer.items.len);
            dbg_info_buffer.append_ntimes_assume_capacity(0, 4); // DW.AT.high_pc, DW.FORM.data4
            if (fn_ret_has_bits) {
                try decl_state.add_type_reloc_global(di_atom_index, fn_ret_type, @int_cast(dbg_info_buffer.items.len));
                dbg_info_buffer.append_ntimes_assume_capacity(0, 4); // DW.AT.type, DW.FORM.ref4
            }
            dbg_info_buffer.append_slice_assume_capacity(
                decl_name_slice[0 .. decl_name_slice.len + 1],
            ); // DW.AT.name, DW.FORM.string
            dbg_info_buffer.append_slice_assume_capacity(
                decl_linkage_name_slice[0 .. decl_linkage_name_slice.len + 1],
            ); // DW.AT.linkage_name, DW.FORM.string
        },
        else => {
            // TODO implement .debug_info for global variables
        },
    }

    return decl_state;
}

pub fn commit_decl_state(
    self: *Dwarf,
    zcu: *Module,
    decl_index: InternPool.DeclIndex,
    sym_addr: u64,
    sym_size: u64,
    decl_state: *DeclState,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const gpa = self.allocator;
    const decl = zcu.decl_ptr(decl_index);
    const ip = &zcu.intern_pool;
    const namespace = zcu.namespace_ptr(decl.src_namespace);
    const target = namespace.file_scope.mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();

    var dbg_line_buffer = &decl_state.dbg_line;
    var dbg_info_buffer = &decl_state.dbg_info;

    assert(decl.has_tv);
    switch (decl.type_of(zcu).zig_type_tag(zcu)) {
        .Fn => {
            try decl_state.set_inline_func(decl.val.to_intern());

            // Since the Decl is a function, we need to update the .debug_line program.
            // Perform the relocations based on vaddr.
            switch (self.ptr_width) {
                .p32 => {
                    {
                        const ptr = dbg_line_buffer.items[dbg_line_vaddr_reloc_index..][0..4];
                        mem.write_int(u32, ptr, @int_cast(sym_addr), target_endian);
                    }
                    {
                        const ptr = dbg_info_buffer.items[dbg_info_low_pc_reloc_index..][0..4];
                        mem.write_int(u32, ptr, @int_cast(sym_addr), target_endian);
                    }
                },
                .p64 => {
                    {
                        const ptr = dbg_line_buffer.items[dbg_line_vaddr_reloc_index..][0..8];
                        mem.write_int(u64, ptr, sym_addr, target_endian);
                    }
                    {
                        const ptr = dbg_info_buffer.items[dbg_info_low_pc_reloc_index..][0..8];
                        mem.write_int(u64, ptr, sym_addr, target_endian);
                    }
                },
            }
            {
                log.debug("relocating subprogram high PC value: {x} => {x}", .{
                    self.get_reloc_dbg_info_subprogram_high_pc(),
                    sym_size,
                });
                const ptr = dbg_info_buffer.items[self.get_reloc_dbg_info_subprogram_high_pc()..][0..4];
                mem.write_int(u32, ptr, @int_cast(sym_size), target_endian);
            }

            try dbg_line_buffer.append_slice(&[_]u8{ DW.LNS.extended_op, 1, DW.LNE.end_sequence });

            // Now we have the full contents and may allocate a region to store it.

            // This logic is nearly identical to the logic below in `updateDeclDebugInfo` for
            // `TextBlock` and the .debug_info. If you are editing this logic, you
            // probably need to edit that logic too.
            const src_fn_index = self.src_fn_decls.get(decl_index).?;
            const src_fn = self.get_atom_ptr(.src_fn, src_fn_index);
            src_fn.len = @int_cast(dbg_line_buffer.items.len);

            if (self.src_fn_last_index) |last_index| blk: {
                if (src_fn_index == last_index) break :blk;
                if (src_fn.next_index) |next_index| {
                    const next = self.get_atom_ptr(.src_fn, next_index);
                    // Update existing function - non-last item.
                    if (src_fn.off + src_fn.len + min_nop_size > next.off) {
                        // It grew too big, so we move it to a new location.
                        if (src_fn.prev_index) |prev_index| {
                            self.src_fn_free_list.put(gpa, prev_index, {}) catch {};
                            self.get_atom_ptr(.src_fn, prev_index).next_index = src_fn.next_index;
                        }
                        next.prev_index = src_fn.prev_index;
                        src_fn.next_index = null;
                        // Populate where it used to be with NOPs.
                        switch (self.bin_file.tag) {
                            .elf => {
                                const elf_file = self.bin_file.cast(File.Elf).?;
                                const debug_line_sect = &elf_file.shdrs.items[elf_file.debug_line_section_index.?];
                                const file_pos = debug_line_sect.sh_offset + src_fn.off;
                                try pwrite_dbg_line_nops(elf_file.base.file.?, file_pos, 0, &[0]u8{}, src_fn.len);
                            },
                            .macho => {
                                const macho_file = self.bin_file.cast(File.MachO).?;
                                if (macho_file.base.is_relocatable()) {
                                    const debug_line_sect = &macho_file.sections.items(.header)[macho_file.debug_line_sect_index.?];
                                    const file_pos = debug_line_sect.offset + src_fn.off;
                                    try pwrite_dbg_line_nops(macho_file.base.file.?, file_pos, 0, &[0]u8{}, src_fn.len);
                                } else {
                                    const d_sym = macho_file.get_debug_symbols().?;
                                    const debug_line_sect = d_sym.get_section_ptr(d_sym.debug_line_section_index.?);
                                    const file_pos = debug_line_sect.offset + src_fn.off;
                                    try pwrite_dbg_line_nops(d_sym.file, file_pos, 0, &[0]u8{}, src_fn.len);
                                }
                            },
                            .wasm => {
                                // const wasm_file = self.bin_file.cast(File.Wasm).?;
                                // const debug_line = wasm_file.get_atom_ptr(wasm_file.debug_line_atom.?).code;
                                // write_dbg_line_nops_buffered(debug_line.items, src_fn.off, 0, &.{}, src_fn.len);
                            },
                            else => unreachable,
                        }
                        // TODO Look at the free list before appending at the end.
                        src_fn.prev_index = last_index;
                        const last = self.get_atom_ptr(.src_fn, last_index);
                        last.next_index = src_fn_index;
                        self.src_fn_last_index = src_fn_index;

                        src_fn.off = last.off + pad_to_ideal(last.len);
                    }
                } else if (src_fn.prev_index == null) {
                    // Append new function.
                    // TODO Look at the free list before appending at the end.
                    src_fn.prev_index = last_index;
                    const last = self.get_atom_ptr(.src_fn, last_index);
                    last.next_index = src_fn_index;
                    self.src_fn_last_index = src_fn_index;

                    src_fn.off = last.off + pad_to_ideal(last.len);
                }
            } else {
                // This is the first function of the Line Number Program.
                self.src_fn_first_index = src_fn_index;
                self.src_fn_last_index = src_fn_index;

                src_fn.off = pad_to_ideal(self.dbg_line_needed_header_bytes(&[0][]u8{}, &[0][]u8{}));
            }

            const last_src_fn_index = self.src_fn_last_index.?;
            const last_src_fn = self.get_atom(.src_fn, last_src_fn_index);
            const needed_size = last_src_fn.off + last_src_fn.len;
            const prev_padding_size: u32 = if (src_fn.prev_index) |prev_index| blk: {
                const prev = self.get_atom(.src_fn, prev_index);
                break :blk src_fn.off - (prev.off + prev.len);
            } else 0;
            const next_padding_size: u32 = if (src_fn.next_index) |next_index| blk: {
                const next = self.get_atom(.src_fn, next_index);
                break :blk next.off - (src_fn.off + src_fn.len);
            } else 0;

            // We only have support for one compilation unit so far, so the offsets are directly
            // from the .debug_line section.
            switch (self.bin_file.tag) {
                .elf => {
                    const elf_file = self.bin_file.cast(File.Elf).?;
                    const shdr_index = elf_file.debug_line_section_index.?;
                    try elf_file.grow_non_alloc_section(shdr_index, needed_size, 1, true);
                    const debug_line_sect = elf_file.shdrs.items[shdr_index];
                    const file_pos = debug_line_sect.sh_offset + src_fn.off;
                    try pwrite_dbg_line_nops(
                        elf_file.base.file.?,
                        file_pos,
                        prev_padding_size,
                        dbg_line_buffer.items,
                        next_padding_size,
                    );
                },

                .macho => {
                    const macho_file = self.bin_file.cast(File.MachO).?;
                    if (macho_file.base.is_relocatable()) {
                        const sect_index = macho_file.debug_line_sect_index.?;
                        try macho_file.grow_section(sect_index, needed_size);
                        const sect = macho_file.sections.items(.header)[sect_index];
                        const file_pos = sect.offset + src_fn.off;
                        try pwrite_dbg_line_nops(
                            macho_file.base.file.?,
                            file_pos,
                            prev_padding_size,
                            dbg_line_buffer.items,
                            next_padding_size,
                        );
                    } else {
                        const d_sym = macho_file.get_debug_symbols().?;
                        const sect_index = d_sym.debug_line_section_index.?;
                        try d_sym.grow_section(sect_index, needed_size, true, macho_file);
                        const sect = d_sym.get_section(sect_index);
                        const file_pos = sect.offset + src_fn.off;
                        try pwrite_dbg_line_nops(
                            d_sym.file,
                            file_pos,
                            prev_padding_size,
                            dbg_line_buffer.items,
                            next_padding_size,
                        );
                    }
                },

                .wasm => {
                    // const wasm_file = self.bin_file.cast(File.Wasm).?;
                    // const atom = wasm_file.get_atom_ptr(wasm_file.debug_line_atom.?);
                    // const debug_line = &atom.code;
                    // const segment_size = debug_line.items.len;
                    // if (needed_size != segment_size) {
                    //     log.debug(" needed size does not equal allocated size: {d}", .{needed_size});
                    //     if (needed_size > segment_size) {
                    //         log.debug("  allocating {d} bytes for 'debug line' information", .{needed_size - segment_size});
                    //         try debug_line.resize(self.allocator, needed_size);
                    //         @memset(debug_line.items[segment_size..], 0);
                    //     }
                    //     debug_line.items.len = needed_size;
                    // }
                    // write_dbg_line_nops_buffered(
                    //     debug_line.items,
                    //     src_fn.off,
                    //     prev_padding_size,
                    //     dbg_line_buffer.items,
                    //     next_padding_size,
                    // );
                },
                else => unreachable,
            }

            // .debug_info - End the TAG.subprogram children.
            try dbg_info_buffer.append(0);
        },
        else => {},
    }

    if (dbg_info_buffer.items.len == 0)
        return;

    const di_atom_index = self.di_atom_decls.get(decl_index).?;
    if (decl_state.abbrev_table.items.len > 0) {
        // Now we emit the .debug_info types of the Decl. These will count towards the size of
        // the buffer, so we have to do it before computing the offset, and we can't perform the actual
        // relocations yet.
        var sym_index: usize = 0;
        while (sym_index < decl_state.abbrev_table.items.len) : (sym_index += 1) {
            const symbol = &decl_state.abbrev_table.items[sym_index];
            const ty = symbol.type;
            if (ip.is_error_set_type(ty.to_intern())) continue;

            symbol.offset = @int_cast(dbg_info_buffer.items.len);
            try decl_state.add_dbg_info_type(zcu, di_atom_index, ty);
        }
    }

    try self.update_decl_debug_info_allocation(di_atom_index, @int_cast(dbg_info_buffer.items.len));

    while (decl_state.abbrev_relocs.pop_or_null()) |reloc| {
        if (reloc.target) |reloc_target| {
            const symbol = decl_state.abbrev_table.items[reloc_target];
            const ty = symbol.type;
            if (ip.is_error_set_type(ty.to_intern())) {
                log.debug("resolving %{d} deferred until flush", .{reloc_target});
                try self.global_abbrev_relocs.append(gpa, .{
                    .target = null,
                    .offset = reloc.offset,
                    .atom_index = reloc.atom_index,
                    .addend = reloc.addend,
                });
            } else {
                const atom = self.get_atom(.di_atom, symbol.atom_index);
                const value = atom.off + symbol.offset + reloc.addend;
                log.debug("{x}: [() => {x}] (%{d}, '{}')", .{
                    reloc.offset,
                    value,
                    reloc_target,
                    ty.fmt(zcu),
                });
                mem.write_int(
                    u32,
                    dbg_info_buffer.items[reloc.offset..][0..@size_of(u32)],
                    value,
                    target_endian,
                );
            }
        } else {
            const atom = self.get_atom(.di_atom, reloc.atom_index);
            mem.write_int(
                u32,
                dbg_info_buffer.items[reloc.offset..][0..@size_of(u32)],
                atom.off + reloc.offset + reloc.addend,
                target_endian,
            );
        }
    }

    while (decl_state.exprloc_relocs.pop_or_null()) |reloc| {
        switch (self.bin_file.tag) {
            .macho => {
                const macho_file = self.bin_file.cast(File.MachO).?;
                if (macho_file.base.is_relocatable()) {
                    // TODO
                } else {
                    const d_sym = macho_file.get_debug_symbols().?;
                    try d_sym.relocs.append(d_sym.allocator, .{
                        .type = switch (reloc.type) {
                            .direct_load => .direct_load,
                            .got_load => .got_load,
                        },
                        .target = reloc.target,
                        .offset = reloc.offset + self.get_atom(.di_atom, di_atom_index).off,
                        .addend = 0,
                    });
                }
            },
            .elf => {}, // TODO
            else => unreachable,
        }
    }

    try self.write_decl_debug_info(di_atom_index, dbg_info_buffer.items);
}

fn update_decl_debug_info_allocation(self: *Dwarf, atom_index: Atom.Index, len: u32) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // This logic is nearly identical to the logic above in `update_decl` for
    // `SrcFn` and the line number programs. If you are editing this logic, you
    // probably need to edit that logic too.
    const gpa = self.allocator;

    const atom = self.get_atom_ptr(.di_atom, atom_index);
    atom.len = len;
    if (self.di_atom_last_index) |last_index| blk: {
        if (atom_index == last_index) break :blk;
        if (atom.next_index) |next_index| {
            const next = self.get_atom_ptr(.di_atom, next_index);
            // Update existing Decl - non-last item.
            if (atom.off + atom.len + min_nop_size > next.off) {
                // It grew too big, so we move it to a new location.
                if (atom.prev_index) |prev_index| {
                    self.di_atom_free_list.put(gpa, prev_index, {}) catch {};
                    self.get_atom_ptr(.di_atom, prev_index).next_index = atom.next_index;
                }
                next.prev_index = atom.prev_index;
                atom.next_index = null;
                // Populate where it used to be with NOPs.
                switch (self.bin_file.tag) {
                    .elf => {
                        const elf_file = self.bin_file.cast(File.Elf).?;
                        const debug_info_sect = &elf_file.shdrs.items[elf_file.debug_info_section_index.?];
                        const file_pos = debug_info_sect.sh_offset + atom.off;
                        try pwrite_dbg_info_nops(elf_file.base.file.?, file_pos, 0, &[0]u8{}, atom.len, false);
                    },
                    .macho => {
                        const macho_file = self.bin_file.cast(File.MachO).?;
                        if (macho_file.base.is_relocatable()) {
                            const debug_info_sect = macho_file.sections.items(.header)[macho_file.debug_info_sect_index.?];
                            const file_pos = debug_info_sect.offset + atom.off;
                            try pwrite_dbg_info_nops(macho_file.base.file.?, file_pos, 0, &[0]u8{}, atom.len, false);
                        } else {
                            const d_sym = macho_file.get_debug_symbols().?;
                            const debug_info_sect = d_sym.get_section_ptr(d_sym.debug_info_section_index.?);
                            const file_pos = debug_info_sect.offset + atom.off;
                            try pwrite_dbg_info_nops(d_sym.file, file_pos, 0, &[0]u8{}, atom.len, false);
                        }
                    },
                    .wasm => {
                        // const wasm_file = self.bin_file.cast(File.Wasm).?;
                        // const debug_info_index = wasm_file.debug_info_atom.?;
                        // const debug_info = &wasm_file.get_atom_ptr(debug_info_index).code;
                        // try write_dbg_info_nops_to_array_list(gpa, debug_info, atom.off, 0, &.{0}, atom.len, false);
                    },
                    else => unreachable,
                }
                // TODO Look at the free list before appending at the end.
                atom.prev_index = last_index;
                const last = self.get_atom_ptr(.di_atom, last_index);
                last.next_index = atom_index;
                self.di_atom_last_index = atom_index;

                atom.off = last.off + pad_to_ideal(last.len);
            }
        } else if (atom.prev_index == null) {
            // Append new Decl.
            // TODO Look at the free list before appending at the end.
            atom.prev_index = last_index;
            const last = self.get_atom_ptr(.di_atom, last_index);
            last.next_index = atom_index;
            self.di_atom_last_index = atom_index;

            atom.off = last.off + pad_to_ideal(last.len);
        }
    } else {
        // This is the first Decl of the .debug_info
        self.di_atom_first_index = atom_index;
        self.di_atom_last_index = atom_index;

        atom.off = @int_cast(pad_to_ideal(self.dbg_info_header_bytes()));
    }
}

fn write_decl_debug_info(self: *Dwarf, atom_index: Atom.Index, dbg_info_buf: []const u8) !void {
    const tracy = trace(@src());
    defer tracy.end();

    // This logic is nearly identical to the logic above in `update_decl` for
    // `SrcFn` and the line number programs. If you are editing this logic, you
    // probably need to edit that logic too.

    const atom = self.get_atom(.di_atom, atom_index);
    const last_decl_index = self.di_atom_last_index.?;
    const last_decl = self.get_atom(.di_atom, last_decl_index);
    // +1 for a trailing zero to end the children of the decl tag.
    const needed_size = last_decl.off + last_decl.len + 1;
    const prev_padding_size: u32 = if (atom.prev_index) |prev_index| blk: {
        const prev = self.get_atom(.di_atom, prev_index);
        break :blk atom.off - (prev.off + prev.len);
    } else 0;
    const next_padding_size: u32 = if (atom.next_index) |next_index| blk: {
        const next = self.get_atom(.di_atom, next_index);
        break :blk next.off - (atom.off + atom.len);
    } else 0;

    // To end the children of the decl tag.
    const trailing_zero = atom.next_index == null;

    // We only have support for one compilation unit so far, so the offsets are directly
    // from the .debug_info section.
    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const shdr_index = elf_file.debug_info_section_index.?;
            try elf_file.grow_non_alloc_section(shdr_index, needed_size, 1, true);
            const debug_info_sect = &elf_file.shdrs.items[shdr_index];
            const file_pos = debug_info_sect.sh_offset + atom.off;
            try pwrite_dbg_info_nops(
                elf_file.base.file.?,
                file_pos,
                prev_padding_size,
                dbg_info_buf,
                next_padding_size,
                trailing_zero,
            );
        },

        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const sect_index = macho_file.debug_info_sect_index.?;
                try macho_file.grow_section(sect_index, needed_size);
                const sect = macho_file.sections.items(.header)[sect_index];
                const file_pos = sect.offset + atom.off;
                try pwrite_dbg_info_nops(
                    macho_file.base.file.?,
                    file_pos,
                    prev_padding_size,
                    dbg_info_buf,
                    next_padding_size,
                    trailing_zero,
                );
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const sect_index = d_sym.debug_info_section_index.?;
                try d_sym.grow_section(sect_index, needed_size, true, macho_file);
                const sect = d_sym.get_section(sect_index);
                const file_pos = sect.offset + atom.off;
                try pwrite_dbg_info_nops(
                    d_sym.file,
                    file_pos,
                    prev_padding_size,
                    dbg_info_buf,
                    next_padding_size,
                    trailing_zero,
                );
            }
        },

        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const info_atom = wasm_file.debug_info_atom.?;
            // const debug_info = &wasm_file.get_atom_ptr(info_atom).code;
            // const segment_size = debug_info.items.len;
            // if (needed_size != segment_size) {
            //     log.debug(" needed size does not equal allocated size: {d}", .{needed_size});
            //     if (needed_size > segment_size) {
            //         log.debug("  allocating {d} bytes for 'debug info' information", .{needed_size - segment_size});
            //         try debug_info.resize(self.allocator, needed_size);
            //         @memset(debug_info.items[segment_size..], 0);
            //     }
            //     debug_info.items.len = needed_size;
            // }
            // log.debug(" write_dbg_info_nops_to_array_list debug_info_len={d} offset={d} content_len={d} next_padding_size={d}", .{
            //     debug_info.items.len, atom.off, dbg_info_buf.len, next_padding_size,
            // });
            // try write_dbg_info_nops_to_array_list(
            //     gpa,
            //     debug_info,
            //     atom.off,
            //     prev_padding_size,
            //     dbg_info_buf,
            //     next_padding_size,
            //     trailing_zero,
            // );
        },
        else => unreachable,
    }
}

pub fn update_decl_line_number(self: *Dwarf, mod: *Module, decl_index: InternPool.DeclIndex) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const atom_index = try self.get_or_create_atom_for_decl(.src_fn, decl_index);
    const atom = self.get_atom(.src_fn, atom_index);
    if (atom.len == 0) return;

    const decl = mod.decl_ptr(decl_index);
    const func = decl.val.get_function(mod).?;
    log.debug("decl.src_line={d}, func.lbrace_line={d}, func.rbrace_line={d}", .{
        decl.src_line,
        func.lbrace_line,
        func.rbrace_line,
    });
    const line: u28 = @int_cast(decl.src_line + func.lbrace_line);
    var data: [4]u8 = undefined;
    leb128.write_unsigned_fixed(4, &data, line);

    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const shdr = elf_file.shdrs.items[elf_file.debug_line_section_index.?];
            const file_pos = shdr.sh_offset + atom.off + self.get_reloc_dbg_line_off();
            try elf_file.base.file.?.pwrite_all(&data, file_pos);
        },
        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const sect = macho_file.sections.items(.header)[macho_file.debug_line_sect_index.?];
                const file_pos = sect.offset + atom.off + self.get_reloc_dbg_line_off();
                try macho_file.base.file.?.pwrite_all(&data, file_pos);
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const sect = d_sym.get_section(d_sym.debug_line_section_index.?);
                const file_pos = sect.offset + atom.off + self.get_reloc_dbg_line_off();
                try d_sym.file.pwrite_all(&data, file_pos);
            }
        },
        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const offset = atom.off + self.get_reloc_dbg_line_off();
            // const line_atom_index = wasm_file.debug_line_atom.?;
            // wasm_file.get_atom_ptr(line_atom_index).code.items[offset..][0..data.len].* = data;
        },
        else => unreachable,
    }
}

pub fn free_decl(self: *Dwarf, decl_index: InternPool.DeclIndex) void {
    const gpa = self.allocator;

    // Free SrcFn atom
    if (self.src_fn_decls.fetch_remove(decl_index)) |kv| {
        const src_fn_index = kv.value;
        const src_fn = self.get_atom(.src_fn, src_fn_index);
        _ = self.src_fn_free_list.remove(src_fn_index);

        if (src_fn.prev_index) |prev_index| {
            self.src_fn_free_list.put(gpa, prev_index, {}) catch {};
            const prev = self.get_atom_ptr(.src_fn, prev_index);
            prev.next_index = src_fn.next_index;
            if (src_fn.next_index) |next_index| {
                self.get_atom_ptr(.src_fn, next_index).prev_index = prev_index;
            } else {
                self.src_fn_last_index = prev_index;
            }
        } else if (src_fn.next_index) |next_index| {
            self.src_fn_first_index = next_index;
            self.get_atom_ptr(.src_fn, next_index).prev_index = null;
        }
        if (self.src_fn_first_index == src_fn_index) {
            self.src_fn_first_index = src_fn.next_index;
        }
        if (self.src_fn_last_index == src_fn_index) {
            self.src_fn_last_index = src_fn.prev_index;
        }
    }

    // Free DI atom
    if (self.di_atom_decls.fetch_remove(decl_index)) |kv| {
        const di_atom_index = kv.value;
        const di_atom = self.get_atom_ptr(.di_atom, di_atom_index);

        if (self.di_atom_first_index == di_atom_index) {
            self.di_atom_first_index = di_atom.next_index;
        }
        if (self.di_atom_last_index == di_atom_index) {
            // TODO shrink the .debug_info section size here
            self.di_atom_last_index = di_atom.prev_index;
        }

        if (di_atom.prev_index) |prev_index| {
            self.get_atom_ptr(.di_atom, prev_index).next_index = di_atom.next_index;
            // TODO the free list logic like we do for SrcFn above
        } else {
            di_atom.prev_index = null;
        }

        if (di_atom.next_index) |next_index| {
            self.get_atom_ptr(.di_atom, next_index).prev_index = di_atom.prev_index;
        } else {
            di_atom.next_index = null;
        }
    }
}

pub fn write_dbg_abbrev(self: *Dwarf) !void {
    // These are LEB encoded but since the values are all less than 127
    // we can simply append these bytes.
    // zig fmt: off
    const abbrev_buf = [_]u8{
        @int_from_enum(AbbrevCode.padding),
        @as(u8, 0x80) | @as(u7, @truncate(DW.TAG.ZIG_padding >> 0)),
        @as(u8, 0x80) | @as(u7, @truncate(DW.TAG.ZIG_padding >> 7)),
        @as(u8, 0x00) | @as(u7, @int_cast(DW.TAG.ZIG_padding >> 14)),
        DW.CHILDREN.no,
        0, 0,

        @int_from_enum(AbbrevCode.compile_unit),
        DW.TAG.compile_unit,
        DW.CHILDREN.yes,
        DW.AT.stmt_list, DW.FORM.sec_offset,
        DW.AT.low_pc,    DW.FORM.addr,
        DW.AT.high_pc,   DW.FORM.addr,
        DW.AT.name,      DW.FORM.strp,
        DW.AT.comp_dir,  DW.FORM.strp,
        DW.AT.producer,  DW.FORM.strp,
        DW.AT.language,  DW.FORM.data2,
        0,               0,

        @int_from_enum(AbbrevCode.subprogram),
        DW.TAG.subprogram,
        DW.CHILDREN.yes,
        DW.AT.low_pc,       DW.FORM.addr,
        DW.AT.high_pc,      DW.FORM.data4,
        DW.AT.type,         DW.FORM.ref4,
        DW.AT.name,         DW.FORM.string,
        DW.AT.linkage_name, DW.FORM.string,
        0,                  0,

        @int_from_enum(AbbrevCode.subprogram_retvoid),
        DW.TAG.subprogram,
        DW.CHILDREN.yes,
        DW.AT.low_pc,       DW.FORM.addr,
        DW.AT.high_pc,      DW.FORM.data4,
        DW.AT.name,         DW.FORM.string,
        DW.AT.linkage_name, DW.FORM.string,
        0,                  0,

        @int_from_enum(AbbrevCode.base_type),
        DW.TAG.base_type, DW.CHILDREN.no,
        DW.AT.encoding,   DW.FORM.data1,
        DW.AT.byte_size,  DW.FORM.udata,
        DW.AT.name,       DW.FORM.string,
        0,                0,

        @int_from_enum(AbbrevCode.ptr_type),
        DW.TAG.pointer_type, DW.CHILDREN.no,
        DW.AT.type,          DW.FORM.ref4,
        0,                   0,

        @int_from_enum(AbbrevCode.struct_type),
        DW.TAG.structure_type, DW.CHILDREN.yes,
        DW.AT.byte_size,       DW.FORM.udata,
        DW.AT.name,            DW.FORM.string,
        0,                     0,

        @int_from_enum(AbbrevCode.struct_member),
        DW.TAG.member,
        DW.CHILDREN.no,
        DW.AT.name,                 DW.FORM.string,
        DW.AT.type,                 DW.FORM.ref4,
        DW.AT.data_member_location, DW.FORM.udata,
        0,                          0,

        @int_from_enum(AbbrevCode.enum_type),
        DW.TAG.enumeration_type,
        DW.CHILDREN.yes,
        DW.AT.byte_size, DW.FORM.udata,
        DW.AT.name,      DW.FORM.string,
        0,               0,

        @int_from_enum(AbbrevCode.enum_variant),
        DW.TAG.enumerator, DW.CHILDREN.no,
        DW.AT.name,        DW.FORM.string,
        DW.AT.const_value, DW.FORM.data8,
        0,                 0,

        @int_from_enum(AbbrevCode.union_type),
        DW.TAG.union_type, DW.CHILDREN.yes,
        DW.AT.byte_size,   DW.FORM.udata,
        DW.AT.name,        DW.FORM.string,
        0,                 0,

        @int_from_enum(AbbrevCode.zero_bit_type),
        DW.TAG.unspecified_type,
        DW.CHILDREN.no,
        0, 0,

        @int_from_enum(AbbrevCode.parameter),
        DW.TAG.formal_parameter,
        DW.CHILDREN.no,
        DW.AT.location, DW.FORM.exprloc,
        DW.AT.type,     DW.FORM.ref4,
        DW.AT.name,     DW.FORM.string,
        0,              0,

        @int_from_enum(AbbrevCode.variable),
        DW.TAG.variable,
        DW.CHILDREN.no,
        DW.AT.location, DW.FORM.exprloc,
        DW.AT.type,     DW.FORM.ref4,
        DW.AT.name,     DW.FORM.string,
        0,              0,

        @int_from_enum(AbbrevCode.array_type),
        DW.TAG.array_type,
        DW.CHILDREN.yes,
        DW.AT.name, DW.FORM.string,
        DW.AT.type, DW.FORM.ref4,
        0,          0,

        @int_from_enum(AbbrevCode.array_dim),
        DW.TAG.subrange_type,
        DW.CHILDREN.no,
        DW.AT.type,  DW.FORM.ref4,
        DW.AT.count, DW.FORM.udata,
        0,           0,

        0,
    };
    // zig fmt: on
    const abbrev_offset = 0;
    self.abbrev_table_offset = abbrev_offset;

    const needed_size = abbrev_buf.len;
    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const shdr_index = elf_file.debug_abbrev_section_index.?;
            try elf_file.grow_non_alloc_section(shdr_index, needed_size, 1, false);
            const debug_abbrev_sect = &elf_file.shdrs.items[shdr_index];
            const file_pos = debug_abbrev_sect.sh_offset + abbrev_offset;
            try elf_file.base.file.?.pwrite_all(&abbrev_buf, file_pos);
        },
        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const sect_index = macho_file.debug_abbrev_sect_index.?;
                try macho_file.grow_section(sect_index, needed_size);
                const sect = macho_file.sections.items(.header)[sect_index];
                const file_pos = sect.offset + abbrev_offset;
                try macho_file.base.file.?.pwrite_all(&abbrev_buf, file_pos);
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const sect_index = d_sym.debug_abbrev_section_index.?;
                try d_sym.grow_section(sect_index, needed_size, false, macho_file);
                const sect = d_sym.get_section(sect_index);
                const file_pos = sect.offset + abbrev_offset;
                try d_sym.file.pwrite_all(&abbrev_buf, file_pos);
            }
        },
        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const debug_abbrev = &wasm_file.get_atom_ptr(wasm_file.debug_abbrev_atom.?).code;
            // try debug_abbrev.resize(gpa, needed_size);
            // debug_abbrev.items[0..abbrev_buf.len].* = abbrev_buf;
        },
        else => unreachable,
    }
}

fn dbg_info_header_bytes(self: *Dwarf) usize {
    _ = self;
    return 120;
}

pub fn write_dbg_info_header(self: *Dwarf, zcu: *Module, low_pc: u64, high_pc: u64) !void {
    // If this value is null it means there is an error in the module;
    // leave debug_info_header_dirty=true.
    const first_dbg_info_off = self.get_debug_info_off() orelse return;

    // We have a function to compute the upper bound size, because it's needed
    // for determining where to put the offset of the first `LinkBlock`.
    const needed_bytes = self.dbg_info_header_bytes();
    var di_buf = try std.ArrayList(u8).init_capacity(self.allocator, needed_bytes);
    defer di_buf.deinit();

    const comp = self.bin_file.comp;
    const target = comp.root_mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();
    const init_len_size: usize = switch (self.format) {
        .dwarf32 => 4,
        .dwarf64 => 12,
    };

    // initial length - length of the .debug_info contribution for this compilation unit,
    // not including the initial length itself.
    // We have to come back and write it later after we know the size.
    const after_init_len = di_buf.items.len + init_len_size;
    const dbg_info_end = self.get_debug_info_end().?;
    const init_len = dbg_info_end - after_init_len + 1;

    if (self.format == .dwarf64) di_buf.append_ntimes_assume_capacity(0xff, 4);
    self.write_offset_assume_capacity(&di_buf, init_len);

    mem.write_int(u16, di_buf.add_many_as_array_assume_capacity(2), 4, target_endian); // DWARF version
    const abbrev_offset = self.abbrev_table_offset.?;

    self.write_offset_assume_capacity(&di_buf, abbrev_offset);
    di_buf.append_assume_capacity(self.ptr_width_bytes()); // address size

    // Write the form for the compile unit, which must match the abbrev table above.
    const name_strp = try self.strtab.insert(self.allocator, zcu.root_mod.root_src_path);
    var compile_unit_dir_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const compile_unit_dir = resolve_compilation_dir(zcu, &compile_unit_dir_buffer);
    const comp_dir_strp = try self.strtab.insert(self.allocator, compile_unit_dir);
    const producer_strp = try self.strtab.insert(self.allocator, link.producer_string);

    di_buf.append_assume_capacity(@int_from_enum(AbbrevCode.compile_unit));
    self.write_offset_assume_capacity(&di_buf, 0); // DW.AT.stmt_list, DW.FORM.sec_offset
    self.write_addr_assume_capacity(&di_buf, low_pc);
    self.write_addr_assume_capacity(&di_buf, high_pc);
    self.write_offset_assume_capacity(&di_buf, name_strp);
    self.write_offset_assume_capacity(&di_buf, comp_dir_strp);
    self.write_offset_assume_capacity(&di_buf, producer_strp);

    // We are still waiting on dwarf-std.org to assign DW_LANG_Zig a number:
    // http://dwarfstd.org/ShowIssue.php?issue=171115.1
    // Until then we say it is C99.
    mem.write_int(u16, di_buf.add_many_as_array_assume_capacity(2), DW.LANG.C99, target_endian);

    if (di_buf.items.len > first_dbg_info_off) {
        // Move the first N decls to the end to make more padding for the header.
        @panic("TODO: handle .debug_info header exceeding its padding");
    }
    const jmp_amt = first_dbg_info_off - di_buf.items.len;
    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const debug_info_sect = &elf_file.shdrs.items[elf_file.debug_info_section_index.?];
            const file_pos = debug_info_sect.sh_offset;
            try pwrite_dbg_info_nops(elf_file.base.file.?, file_pos, 0, di_buf.items, jmp_amt, false);
        },
        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const debug_info_sect = macho_file.sections.items(.header)[macho_file.debug_info_sect_index.?];
                const file_pos = debug_info_sect.offset;
                try pwrite_dbg_info_nops(macho_file.base.file.?, file_pos, 0, di_buf.items, jmp_amt, false);
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const debug_info_sect = d_sym.get_section(d_sym.debug_info_section_index.?);
                const file_pos = debug_info_sect.offset;
                try pwrite_dbg_info_nops(d_sym.file, file_pos, 0, di_buf.items, jmp_amt, false);
            }
        },
        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const debug_info = &wasm_file.get_atom_ptr(wasm_file.debug_info_atom.?).code;
            // try write_dbg_info_nops_to_array_list(self.allocator, debug_info, 0, 0, di_buf.items, jmp_amt, false);
        },
        else => unreachable,
    }
}

fn resolve_compilation_dir(module: *Module, buffer: *[std.fs.MAX_PATH_BYTES]u8) []const u8 {
    // We fully resolve all paths at this point to avoid lack of source line info in stack
    // traces or lack of debugging information which, if relative paths were used, would
    // be very location dependent.
    // TODO: the only concern I have with this is WASI as either host or target, should
    // we leave the paths as relative then?
    const root_dir_path = module.root_mod.root.root_dir.path orelse ".";
    const sub_path = module.root_mod.root.sub_path;
    const realpath = if (std.fs.path.is_absolute(root_dir_path)) r: {
        @memcpy(buffer[0..root_dir_path.len], root_dir_path);
        break :r root_dir_path;
    } else std.fs.realpath(root_dir_path, buffer) catch return root_dir_path;
    const len = realpath.len + 1 + sub_path.len;
    if (buffer.len < len) return root_dir_path;
    buffer[realpath.len] = '/';
    @memcpy(buffer[realpath.len + 1 ..][0..sub_path.len], sub_path);
    return buffer[0..len];
}

fn write_addr_assume_capacity(self: *Dwarf, buf: *std.ArrayList(u8), addr: u64) void {
    const comp = self.bin_file.comp;
    const target = comp.root_mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();
    switch (self.ptr_width) {
        .p32 => mem.write_int(u32, buf.add_many_as_array_assume_capacity(4), @int_cast(addr), target_endian),
        .p64 => mem.write_int(u64, buf.add_many_as_array_assume_capacity(8), addr, target_endian),
    }
}

fn write_offset_assume_capacity(self: *Dwarf, buf: *std.ArrayList(u8), off: u64) void {
    const comp = self.bin_file.comp;
    const target = comp.root_mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();
    switch (self.format) {
        .dwarf32 => mem.write_int(u32, buf.add_many_as_array_assume_capacity(4), @int_cast(off), target_endian),
        .dwarf64 => mem.write_int(u64, buf.add_many_as_array_assume_capacity(8), off, target_endian),
    }
}

/// Writes to the file a buffer, prefixed and suffixed by the specified number of
/// bytes of NOPs. Asserts each padding size is at least `min_nop_size` and total padding bytes
/// are less than 1044480 bytes (if this limit is ever reached, this function can be
/// improved to make more than one pwritev call, or the limit can be raised by a fixed
/// amount by increasing the length of `vecs`).
fn pwrite_dbg_line_nops(
    file: fs.File,
    offset: u64,
    prev_padding_size: usize,
    buf: []const u8,
    next_padding_size: usize,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const page_of_nops = [1]u8{DW.LNS.negate_stmt} ** 4096;
    const three_byte_nop = [3]u8{ DW.LNS.advance_pc, 0b1000_0000, 0 };
    var vecs: [512]std.posix.iovec_const = undefined;
    var vec_index: usize = 0;
    {
        var padding_left = prev_padding_size;
        if (padding_left % 2 != 0) {
            vecs[vec_index] = .{
                .base = &three_byte_nop,
                .len = three_byte_nop.len,
            };
            vec_index += 1;
            padding_left -= three_byte_nop.len;
        }
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = padding_left,
            };
            vec_index += 1;
        }
    }

    vecs[vec_index] = .{
        .base = buf.ptr,
        .len = buf.len,
    };
    if (buf.len > 0) vec_index += 1;

    {
        var padding_left = next_padding_size;
        if (padding_left % 2 != 0) {
            vecs[vec_index] = .{
                .base = &three_byte_nop,
                .len = three_byte_nop.len,
            };
            vec_index += 1;
            padding_left -= three_byte_nop.len;
        }
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = padding_left,
            };
            vec_index += 1;
        }
    }
    try file.pwritev_all(vecs[0..vec_index], offset - prev_padding_size);
}

fn write_dbg_line_nops_buffered(
    buf: []u8,
    offset: u32,
    prev_padding_size: usize,
    content: []const u8,
    next_padding_size: usize,
) void {
    assert(buf.len >= content.len + prev_padding_size + next_padding_size);
    const tracy = trace(@src());
    defer tracy.end();

    const three_byte_nop = [3]u8{ DW.LNS.advance_pc, 0b1000_0000, 0 };
    {
        var padding_left = prev_padding_size;
        if (padding_left % 2 != 0) {
            buf[offset - padding_left ..][0..3].* = three_byte_nop;
            padding_left -= 3;
        }

        while (padding_left > 0) : (padding_left -= 1) {
            buf[offset - padding_left] = DW.LNS.negate_stmt;
        }
    }

    @memcpy(buf[offset..][0..content.len], content);

    {
        var padding_left = next_padding_size;
        if (padding_left % 2 != 0) {
            buf[offset + content.len + padding_left ..][0..3].* = three_byte_nop;
            padding_left -= 3;
        }

        while (padding_left > 0) : (padding_left -= 1) {
            buf[offset + content.len + padding_left] = DW.LNS.negate_stmt;
        }
    }
}

/// Writes to the file a buffer, prefixed and suffixed by the specified number of
/// bytes of padding.
fn pwrite_dbg_info_nops(
    file: fs.File,
    offset: u64,
    prev_padding_size: usize,
    buf: []const u8,
    next_padding_size: usize,
    trailing_zero: bool,
) !void {
    const tracy = trace(@src());
    defer tracy.end();

    const page_of_nops = [1]u8{@int_from_enum(AbbrevCode.padding)} ** 4096;
    var vecs: [32]std.posix.iovec_const = undefined;
    var vec_index: usize = 0;
    {
        var padding_left = prev_padding_size;
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = padding_left,
            };
            vec_index += 1;
        }
    }

    vecs[vec_index] = .{
        .base = buf.ptr,
        .len = buf.len,
    };
    if (buf.len > 0) vec_index += 1;

    {
        var padding_left = next_padding_size;
        while (padding_left > page_of_nops.len) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = page_of_nops.len,
            };
            vec_index += 1;
            padding_left -= page_of_nops.len;
        }
        if (padding_left > 0) {
            vecs[vec_index] = .{
                .base = &page_of_nops,
                .len = padding_left,
            };
            vec_index += 1;
        }
    }

    if (trailing_zero) {
        var zbuf = [1]u8{0};
        vecs[vec_index] = .{
            .base = &zbuf,
            .len = zbuf.len,
        };
        vec_index += 1;
    }

    try file.pwritev_all(vecs[0..vec_index], offset - prev_padding_size);
}

fn write_dbg_info_nops_to_array_list(
    gpa: Allocator,
    buffer: *std.ArrayListUnmanaged(u8),
    offset: u32,
    prev_padding_size: usize,
    content: []const u8,
    next_padding_size: usize,
    trailing_zero: bool,
) Allocator.Error!void {
    try buffer.resize(gpa, @max(
        buffer.items.len,
        offset + content.len + next_padding_size + 1,
    ));
    @memset(buffer.items[offset - prev_padding_size .. offset], @int_from_enum(AbbrevCode.padding));
    @memcpy(buffer.items[offset..][0..content.len], content);
    @memset(buffer.items[offset + content.len ..][0..next_padding_size], @int_from_enum(AbbrevCode.padding));

    if (trailing_zero) {
        buffer.items[offset + content.len + next_padding_size] = 0;
    }
}

pub fn write_dbg_aranges(self: *Dwarf, addr: u64, size: u64) !void {
    const comp = self.bin_file.comp;
    const target = comp.root_mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();
    const ptr_width_bytes = self.ptr_width_bytes();

    // Enough for all the data without resizing. When support for more compilation units
    // is added, the size of this section will become more variable.
    var di_buf = try std.ArrayList(u8).init_capacity(self.allocator, 100);
    defer di_buf.deinit();

    // initial length - length of the .debug_aranges contribution for this compilation unit,
    // not including the initial length itself.
    // We have to come back and write it later after we know the size.
    if (self.format == .dwarf64) di_buf.append_ntimes_assume_capacity(0xff, 4);
    const init_len_index = di_buf.items.len;
    self.write_offset_assume_capacity(&di_buf, 0);
    const after_init_len = di_buf.items.len;
    mem.write_int(u16, di_buf.add_many_as_array_assume_capacity(2), 2, target_endian); // version

    // When more than one compilation unit is supported, this will be the offset to it.
    // For now it is always at offset 0 in .debug_info.
    self.write_offset_assume_capacity(&di_buf, 0); // .debug_info offset
    di_buf.append_assume_capacity(ptr_width_bytes); // address_size
    di_buf.append_assume_capacity(0); // segment_selector_size

    const end_header_offset = di_buf.items.len;
    const begin_entries_offset = mem.align_forward(usize, end_header_offset, ptr_width_bytes * 2);
    di_buf.append_ntimes_assume_capacity(0, begin_entries_offset - end_header_offset);

    // Currently only one compilation unit is supported, so the address range is simply
    // identical to the main program header virtual address and memory size.
    self.write_addr_assume_capacity(&di_buf, addr);
    self.write_addr_assume_capacity(&di_buf, size);

    // Sentinel.
    self.write_addr_assume_capacity(&di_buf, 0);
    self.write_addr_assume_capacity(&di_buf, 0);

    // Go back and populate the initial length.
    const init_len = di_buf.items.len - after_init_len;
    switch (self.format) {
        .dwarf32 => mem.write_int(u32, di_buf.items[init_len_index..][0..4], @int_cast(init_len), target_endian),
        .dwarf64 => mem.write_int(u64, di_buf.items[init_len_index..][0..8], init_len, target_endian),
    }

    const needed_size: u32 = @int_cast(di_buf.items.len);
    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const shdr_index = elf_file.debug_aranges_section_index.?;
            try elf_file.grow_non_alloc_section(shdr_index, needed_size, 16, false);
            const debug_aranges_sect = &elf_file.shdrs.items[shdr_index];
            const file_pos = debug_aranges_sect.sh_offset;
            try elf_file.base.file.?.pwrite_all(di_buf.items, file_pos);
        },
        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const sect_index = macho_file.debug_aranges_sect_index.?;
                try macho_file.grow_section(sect_index, needed_size);
                const sect = macho_file.sections.items(.header)[sect_index];
                const file_pos = sect.offset;
                try macho_file.base.file.?.pwrite_all(di_buf.items, file_pos);
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const sect_index = d_sym.debug_aranges_section_index.?;
                try d_sym.grow_section(sect_index, needed_size, false, macho_file);
                const sect = d_sym.get_section(sect_index);
                const file_pos = sect.offset;
                try d_sym.file.pwrite_all(di_buf.items, file_pos);
            }
        },
        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const debug_ranges = &wasm_file.get_atom_ptr(wasm_file.debug_ranges_atom.?).code;
            // try debug_ranges.resize(gpa, needed_size);
            // @memcpy(debug_ranges.items[0..di_buf.items.len], di_buf.items);
        },
        else => unreachable,
    }
}

pub fn write_dbg_line_header(self: *Dwarf) !void {
    const comp = self.bin_file.comp;
    const gpa = self.allocator;
    const target = comp.root_mod.resolved_target.result;
    const target_endian = target.cpu.arch.endian();
    const init_len_size: usize = switch (self.format) {
        .dwarf32 => 4,
        .dwarf64 => 12,
    };

    const dbg_line_prg_off = self.get_debug_line_program_off() orelse return;
    assert(self.get_debug_line_program_end().? != 0);

    // Convert all input DI files into a set of include dirs and file names.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const paths = try self.gen_include_dirs_and_file_names(arena.allocator());

    // The size of this header is variable, depending on the number of directories,
    // files, and padding. We have a function to compute the upper bound size, however,
    // because it's needed for determining where to put the offset of the first `SrcFn`.
    const needed_bytes = self.dbg_line_needed_header_bytes(paths.dirs, paths.files);
    var di_buf = try std.ArrayList(u8).init_capacity(gpa, needed_bytes);
    defer di_buf.deinit();

    if (self.format == .dwarf64) di_buf.append_ntimes_assume_capacity(0xff, 4);
    self.write_offset_assume_capacity(&di_buf, 0);

    mem.write_int(u16, di_buf.add_many_as_array_assume_capacity(2), 4, target_endian); // version

    // Empirically, debug info consumers do not respect this field, or otherwise
    // consider it to be an error when it does not point exactly to the end of the header.
    // Therefore we rely on the NOP jump at the beginning of the Line Number Program for
    // padding rather than this field.
    const before_header_len = di_buf.items.len;
    self.write_offset_assume_capacity(&di_buf, 0); // We will come back and write this.
    const after_header_len = di_buf.items.len;

    assert(self.dbg_line_header.opcode_base == DW.LNS.set_isa + 1);
    di_buf.append_slice_assume_capacity(&[_]u8{
        self.dbg_line_header.minimum_instruction_length,
        self.dbg_line_header.maximum_operations_per_instruction,
        @int_from_bool(self.dbg_line_header.default_is_stmt),
        @bit_cast(self.dbg_line_header.line_base),
        self.dbg_line_header.line_range,
        self.dbg_line_header.opcode_base,

        // Standard opcode lengths. The number of items here is based on `opcode_base`.
        // The value is the number of LEB128 operands the instruction takes.
        0, // `DW.LNS.copy`
        1, // `DW.LNS.advance_pc`
        1, // `DW.LNS.advance_line`
        1, // `DW.LNS.set_file`
        1, // `DW.LNS.set_column`
        0, // `DW.LNS.negate_stmt`
        0, // `DW.LNS.set_basic_block`
        0, // `DW.LNS.const_add_pc`
        1, // `DW.LNS.fixed_advance_pc`
        0, // `DW.LNS.set_prologue_end`
        0, // `DW.LNS.set_epilogue_begin`
        1, // `DW.LNS.set_isa`
    });

    for (paths.dirs, 0..) |dir, i| {
        log.debug("adding new include dir at {d} of '{s}'", .{ i + 1, dir });
        di_buf.append_slice_assume_capacity(dir);
        di_buf.append_assume_capacity(0);
    }
    di_buf.append_assume_capacity(0); // include directories sentinel

    for (paths.files, 0..) |file, i| {
        const dir_index = paths.files_dirs_indexes[i];
        log.debug("adding new file name at {d} of '{s}' referencing directory {d}", .{
            i + 1,
            file,
            dir_index + 1,
        });
        di_buf.append_slice_assume_capacity(file);
        di_buf.append_slice_assume_capacity(&[_]u8{
            0, // null byte for the relative path name
            @int_cast(dir_index), // directory_index
            0, // mtime (TODO supply this)
            0, // file size bytes (TODO supply this)
        });
    }
    di_buf.append_assume_capacity(0); // file names sentinel

    const header_len = di_buf.items.len - after_header_len;
    switch (self.format) {
        .dwarf32 => mem.write_int(u32, di_buf.items[before_header_len..][0..4], @int_cast(header_len), target_endian),
        .dwarf64 => mem.write_int(u64, di_buf.items[before_header_len..][0..8], header_len, target_endian),
    }

    assert(needed_bytes == di_buf.items.len);

    if (di_buf.items.len > dbg_line_prg_off) {
        const needed_with_padding = pad_to_ideal(needed_bytes);
        const delta = needed_with_padding - dbg_line_prg_off;

        const first_fn_index = self.src_fn_first_index.?;
        const first_fn = self.get_atom(.src_fn, first_fn_index);
        const last_fn_index = self.src_fn_last_index.?;
        const last_fn = self.get_atom(.src_fn, last_fn_index);

        var src_fn_index = first_fn_index;

        var buffer = try gpa.alloc(u8, last_fn.off + last_fn.len - first_fn.off);
        defer gpa.free(buffer);

        switch (self.bin_file.tag) {
            .elf => {
                const elf_file = self.bin_file.cast(File.Elf).?;
                const shdr_index = elf_file.debug_line_section_index.?;
                const needed_size = elf_file.shdrs.items[shdr_index].sh_size + delta;
                try elf_file.grow_non_alloc_section(shdr_index, needed_size, 1, true);
                const file_pos = elf_file.shdrs.items[shdr_index].sh_offset + first_fn.off;

                const amt = try elf_file.base.file.?.pread_all(buffer, file_pos);
                if (amt != buffer.len) return error.InputOutput;

                try elf_file.base.file.?.pwrite_all(buffer, file_pos + delta);
            },
            .macho => {
                const macho_file = self.bin_file.cast(File.MachO).?;
                if (macho_file.base.is_relocatable()) {
                    const sect_index = macho_file.debug_line_sect_index.?;
                    const needed_size: u32 = @int_cast(macho_file.sections.items(.header)[sect_index].size + delta);
                    try macho_file.grow_section(sect_index, needed_size);
                    const file_pos = macho_file.sections.items(.header)[sect_index].offset + first_fn.off;

                    const amt = try macho_file.base.file.?.pread_all(buffer, file_pos);
                    if (amt != buffer.len) return error.InputOutput;

                    try macho_file.base.file.?.pwrite_all(buffer, file_pos + delta);
                } else {
                    const d_sym = macho_file.get_debug_symbols().?;
                    const sect_index = d_sym.debug_line_section_index.?;
                    const needed_size: u32 = @int_cast(d_sym.get_section(sect_index).size + delta);
                    try d_sym.grow_section(sect_index, needed_size, true, macho_file);
                    const file_pos = d_sym.get_section(sect_index).offset + first_fn.off;

                    const amt = try d_sym.file.pread_all(buffer, file_pos);
                    if (amt != buffer.len) return error.InputOutput;

                    try d_sym.file.pwrite_all(buffer, file_pos + delta);
                }
            },
            .wasm => {
                _ = &buffer;
                // const wasm_file = self.bin_file.cast(File.Wasm).?;
                // const debug_line = &wasm_file.get_atom_ptr(wasm_file.debug_line_atom.?).code;
                // {
                //     const src = debug_line.items[first_fn.off..];
                //     @memcpy(buffer[0..src.len], src);
                // }
                // try debug_line.resize(self.allocator, debug_line.items.len + delta);
                // @memcpy(debug_line.items[first_fn.off + delta ..][0..buffer.len], buffer);
            },
            else => unreachable,
        }

        while (true) {
            const src_fn = self.get_atom_ptr(.src_fn, src_fn_index);
            src_fn.off += delta;

            if (src_fn.next_index) |next_index| {
                src_fn_index = next_index;
            } else break;
        }
    }

    // Backpatch actual length of the debug line program
    const init_len = self.get_debug_line_program_end().? - init_len_size;
    switch (self.format) {
        .dwarf32 => {
            mem.write_int(u32, di_buf.items[0..4], @int_cast(init_len), target_endian);
        },
        .dwarf64 => {
            mem.write_int(u64, di_buf.items[4..][0..8], init_len, target_endian);
        },
    }

    // We use NOPs because consumers empirically do not respect the header length field.
    const jmp_amt = self.get_debug_line_program_off().? - di_buf.items.len;
    switch (self.bin_file.tag) {
        .elf => {
            const elf_file = self.bin_file.cast(File.Elf).?;
            const debug_line_sect = &elf_file.shdrs.items[elf_file.debug_line_section_index.?];
            const file_pos = debug_line_sect.sh_offset;
            try pwrite_dbg_line_nops(elf_file.base.file.?, file_pos, 0, di_buf.items, jmp_amt);
        },
        .macho => {
            const macho_file = self.bin_file.cast(File.MachO).?;
            if (macho_file.base.is_relocatable()) {
                const debug_line_sect = macho_file.sections.items(.header)[macho_file.debug_line_sect_index.?];
                const file_pos = debug_line_sect.offset;
                try pwrite_dbg_line_nops(macho_file.base.file.?, file_pos, 0, di_buf.items, jmp_amt);
            } else {
                const d_sym = macho_file.get_debug_symbols().?;
                const debug_line_sect = d_sym.get_section(d_sym.debug_line_section_index.?);
                const file_pos = debug_line_sect.offset;
                try pwrite_dbg_line_nops(d_sym.file, file_pos, 0, di_buf.items, jmp_amt);
            }
        },
        .wasm => {
            // const wasm_file = self.bin_file.cast(File.Wasm).?;
            // const debug_line = &wasm_file.get_atom_ptr(wasm_file.debug_line_atom.?).code;
            // write_dbg_line_nops_buffered(debug_line.items, 0, 0, di_buf.items, jmp_amt);
        },
        else => unreachable,
    }
}

fn get_debug_info_off(self: Dwarf) ?u32 {
    const first_index = self.di_atom_first_index orelse return null;
    const first = self.get_atom(.di_atom, first_index);
    return first.off;
}

fn get_debug_info_end(self: Dwarf) ?u32 {
    const last_index = self.di_atom_last_index orelse return null;
    const last = self.get_atom(.di_atom, last_index);
    return last.off + last.len;
}

fn get_debug_line_program_off(self: Dwarf) ?u32 {
    const first_index = self.src_fn_first_index orelse return null;
    const first = self.get_atom(.src_fn, first_index);
    return first.off;
}

fn get_debug_line_program_end(self: Dwarf) ?u32 {
    const last_index = self.src_fn_last_index orelse return null;
    const last = self.get_atom(.src_fn, last_index);
    return last.off + last.len;
}

/// Always 4 or 8 depending on whether this is 32-bit or 64-bit format.
fn ptr_width_bytes(self: Dwarf) u8 {
    return switch (self.ptr_width) {
        .p32 => 4,
        .p64 => 8,
    };
}

fn dbg_line_needed_header_bytes(self: Dwarf, dirs: []const []const u8, files: []const []const u8) u32 {
    var size: usize = switch (self.format) { // length field
        .dwarf32 => 4,
        .dwarf64 => 12,
    };
    size += @size_of(u16); // version field
    size += switch (self.format) { // offset to end-of-header
        .dwarf32 => 4,
        .dwarf64 => 8,
    };
    size += 18; // opcodes

    for (dirs) |dir| { // include dirs
        size += dir.len + 1;
    }
    size += 1; // include dirs sentinel

    for (files) |file| { // file names
        size += file.len + 1 + 1 + 1 + 1;
    }
    size += 1; // file names sentinel

    return @int_cast(size);
}

/// The reloc offset for the line offset of a function from the previous function's line.
/// It's a fixed-size 4-byte ULEB128.
fn get_reloc_dbg_line_off(self: Dwarf) usize {
    return dbg_line_vaddr_reloc_index + self.ptr_width_bytes() + 1;
}

fn get_reloc_dbg_file_index(self: Dwarf) usize {
    return self.get_reloc_dbg_line_off() + 5;
}

fn get_reloc_dbg_info_subprogram_high_pc(self: Dwarf) u32 {
    return dbg_info_low_pc_reloc_index + self.ptr_width_bytes();
}

fn pad_to_ideal(actual_size: anytype) @TypeOf(actual_size) {
    return actual_size +| (actual_size / ideal_factor);
}

pub fn flush_module(self: *Dwarf, module: *Module) !void {
    const comp = self.bin_file.comp;
    const target = comp.root_mod.resolved_target.result;

    if (self.global_abbrev_relocs.items.len > 0) {
        const gpa = self.allocator;
        var arena_alloc = std.heap.ArenaAllocator.init(gpa);
        defer arena_alloc.deinit();
        const arena = arena_alloc.allocator();

        var dbg_info_buffer = std.ArrayList(u8).init(arena);
        try add_dbg_info_error_set_names(
            module,
            Type.anyerror,
            module.global_error_set.keys(),
            target,
            &dbg_info_buffer,
        );

        const di_atom_index = try self.create_atom(.di_atom);
        log.debug("update_decl_debug_info_allocation in flush_module", .{});
        try self.update_decl_debug_info_allocation(di_atom_index, @int_cast(dbg_info_buffer.items.len));
        log.debug("write_decl_debug_info in flush_module", .{});
        try self.write_decl_debug_info(di_atom_index, dbg_info_buffer.items);

        const file_pos = switch (self.bin_file.tag) {
            .elf => pos: {
                const elf_file = self.bin_file.cast(File.Elf).?;
                const debug_info_sect = &elf_file.shdrs.items[elf_file.debug_info_section_index.?];
                break :pos debug_info_sect.sh_offset;
            },
            .macho => pos: {
                const macho_file = self.bin_file.cast(File.MachO).?;
                if (macho_file.base.is_relocatable()) {
                    const debug_info_sect = &macho_file.sections.items(.header)[macho_file.debug_info_sect_index.?];
                    break :pos debug_info_sect.offset;
                } else {
                    const d_sym = macho_file.get_debug_symbols().?;
                    const debug_info_sect = d_sym.get_section_ptr(d_sym.debug_info_section_index.?);
                    break :pos debug_info_sect.offset;
                }
            },
            // for wasm, the offset is always 0 as we write to memory first
            .wasm => 0,
            else => unreachable,
        };

        var buf: [@size_of(u32)]u8 = undefined;
        mem.write_int(u32, &buf, self.get_atom(.di_atom, di_atom_index).off, target.cpu.arch.endian());

        while (self.global_abbrev_relocs.pop_or_null()) |reloc| {
            const atom = self.get_atom(.di_atom, reloc.atom_index);
            switch (self.bin_file.tag) {
                .elf => {
                    const elf_file = self.bin_file.cast(File.Elf).?;
                    try elf_file.base.file.?.pwrite_all(&buf, file_pos + atom.off + reloc.offset);
                },
                .macho => {
                    const macho_file = self.bin_file.cast(File.MachO).?;
                    if (macho_file.base.is_relocatable()) {
                        try macho_file.base.file.?.pwrite_all(&buf, file_pos + atom.off + reloc.offset);
                    } else {
                        const d_sym = macho_file.get_debug_symbols().?;
                        try d_sym.file.pwrite_all(&buf, file_pos + atom.off + reloc.offset);
                    }
                },
                .wasm => {
                    // const wasm_file = self.bin_file.cast(File.Wasm).?;
                    // const debug_info = wasm_file.get_atom_ptr(wasm_file.debug_info_atom.?).code;
                    // debug_info.items[atom.off + reloc.offset ..][0..buf.len].* = buf;
                },
                else => unreachable,
            }
        }
    }
}

fn add_difile(self: *Dwarf, mod: *Module, decl_index: InternPool.DeclIndex) !u28 {
    const decl = mod.decl_ptr(decl_index);
    const file_scope = decl.get_file_scope(mod);
    const gop = try self.di_files.get_or_put(self.allocator, file_scope);
    if (!gop.found_existing) {
        switch (self.bin_file.tag) {
            .elf => {
                const elf_file = self.bin_file.cast(File.Elf).?;
                elf_file.mark_dirty(elf_file.debug_line_section_index.?);
            },
            .macho => {
                const macho_file = self.bin_file.cast(File.MachO).?;
                if (macho_file.base.is_relocatable()) {
                    macho_file.mark_dirty(macho_file.debug_line_sect_index.?);
                } else {
                    const d_sym = macho_file.get_debug_symbols().?;
                    d_sym.mark_dirty(d_sym.debug_line_section_index.?, macho_file);
                }
            },
            .wasm => {},
            else => unreachable,
        }
    }
    return @int_cast(gop.index + 1);
}

fn gen_include_dirs_and_file_names(self: *Dwarf, arena: Allocator) !struct {
    dirs: []const []const u8,
    files: []const []const u8,
    files_dirs_indexes: []u28,
} {
    var dirs = std.StringArrayHashMap(void).init(arena);
    try dirs.ensure_total_capacity(self.di_files.count());

    var files = std.ArrayList([]const u8).init(arena);
    try files.ensure_total_capacity_precise(self.di_files.count());

    var files_dir_indexes = std.ArrayList(u28).init(arena);
    try files_dir_indexes.ensure_total_capacity(self.di_files.count());

    for (self.di_files.keys()) |dif| {
        const full_path = try dif.mod.root.join_string(arena, dif.sub_file_path);
        const dir_path = std.fs.path.dirname(full_path) orelse ".";
        const sub_file_path = std.fs.path.basename(full_path);
        // https://github.com/ziglang/zig/issues/19353
        var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const resolved = if (!std.fs.path.is_absolute(dir_path))
            std.posix.realpath(dir_path, &buffer) catch dir_path
        else
            dir_path;

        const dir_index: u28 = index: {
            const dirs_gop = dirs.get_or_put_assume_capacity(try arena.dupe(u8, resolved));
            break :index @int_cast(dirs_gop.index + 1);
        };

        files_dir_indexes.append_assume_capacity(dir_index);
        files.append_assume_capacity(sub_file_path);
    }

    return .{
        .dirs = dirs.keys(),
        .files = files.items,
        .files_dirs_indexes = files_dir_indexes.items,
    };
}

fn add_dbg_info_error_set(
    mod: *Module,
    ty: Type,
    target: std.Target,
    dbg_info_buffer: *std.ArrayList(u8),
) !void {
    return add_dbg_info_error_set_names(mod, ty, ty.error_set_names(mod).get(&mod.intern_pool), target, dbg_info_buffer);
}

fn add_dbg_info_error_set_names(
    mod: *Module,
    /// Used for printing the type name only.
    ty: Type,
    error_names: []const InternPool.NullTerminatedString,
    target: std.Target,
    dbg_info_buffer: *std.ArrayList(u8),
) !void {
    const target_endian = target.cpu.arch.endian();

    // DW.AT.enumeration_type
    try dbg_info_buffer.append(@int_from_enum(AbbrevCode.enum_type));
    // DW.AT.byte_size, DW.FORM.udata
    const abi_size = Type.anyerror.abi_size(mod);
    try leb128.write_uleb128(dbg_info_buffer.writer(), abi_size);
    // DW.AT.name, DW.FORM.string
    try ty.print(dbg_info_buffer.writer(), mod);
    try dbg_info_buffer.append(0);

    // DW.AT.enumerator
    const no_error = "(no error)";
    try dbg_info_buffer.ensure_unused_capacity(no_error.len + 2 + @size_of(u64));
    dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.enum_variant));
    // DW.AT.name, DW.FORM.string
    dbg_info_buffer.append_slice_assume_capacity(no_error);
    dbg_info_buffer.append_assume_capacity(0);
    // DW.AT.const_value, DW.FORM.data8
    mem.write_int(u64, dbg_info_buffer.add_many_as_array_assume_capacity(8), 0, target_endian);

    for (error_names) |error_name| {
        const int = try mod.get_error_value(error_name);
        const error_name_slice = error_name.to_slice(&mod.intern_pool);
        // DW.AT.enumerator
        try dbg_info_buffer.ensure_unused_capacity(error_name_slice.len + 2 + @size_of(u64));
        dbg_info_buffer.append_assume_capacity(@int_from_enum(AbbrevCode.enum_variant));
        // DW.AT.name, DW.FORM.string
        dbg_info_buffer.append_slice_assume_capacity(error_name_slice[0 .. error_name_slice.len + 1]);
        // DW.AT.const_value, DW.FORM.data8
        mem.write_int(u64, dbg_info_buffer.add_many_as_array_assume_capacity(8), int, target_endian);
    }

    // DW.AT.enumeration_type delimit children
    try dbg_info_buffer.append(0);
}

const Kind = enum { src_fn, di_atom };

fn create_atom(self: *Dwarf, comptime kind: Kind) !Atom.Index {
    const index = blk: {
        switch (kind) {
            .src_fn => {
                const index: Atom.Index = @int_cast(self.src_fns.items.len);
                _ = try self.src_fns.add_one(self.allocator);
                break :blk index;
            },
            .di_atom => {
                const index: Atom.Index = @int_cast(self.di_atoms.items.len);
                _ = try self.di_atoms.add_one(self.allocator);
                break :blk index;
            },
        }
    };
    const atom = self.get_atom_ptr(kind, index);
    atom.* = .{
        .off = 0,
        .len = 0,
        .prev_index = null,
        .next_index = null,
    };
    return index;
}

fn get_or_create_atom_for_decl(self: *Dwarf, comptime kind: Kind, decl_index: InternPool.DeclIndex) !Atom.Index {
    switch (kind) {
        .src_fn => {
            const gop = try self.src_fn_decls.get_or_put(self.allocator, decl_index);
            if (!gop.found_existing) {
                gop.value_ptr.* = try self.create_atom(kind);
            }
            return gop.value_ptr.*;
        },
        .di_atom => {
            const gop = try self.di_atom_decls.get_or_put(self.allocator, decl_index);
            if (!gop.found_existing) {
                gop.value_ptr.* = try self.create_atom(kind);
            }
            return gop.value_ptr.*;
        },
    }
}

fn get_atom(self: *const Dwarf, comptime kind: Kind, index: Atom.Index) Atom {
    return switch (kind) {
        .src_fn => self.src_fns.items[index],
        .di_atom => self.di_atoms.items[index],
    };
}

fn get_atom_ptr(self: *Dwarf, comptime kind: Kind, index: Atom.Index) *Atom {
    return switch (kind) {
        .src_fn => &self.src_fns.items[index],
        .di_atom => &self.di_atoms.items[index],
    };
}

pub const Format = enum {
    dwarf32,
    dwarf64,
};

const Dwarf = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const fs = std.fs;
const leb128 = std.leb;
const log = std.log.scoped(.dwarf);
const mem = std.mem;

const link = @import("../link.zig");
const trace = @import("../tracy.zig").trace;

const Allocator = mem.Allocator;
const DW = std.dwarf;
const File = link.File;
const LinkBlock = File.LinkBlock;
const LinkFn = File.LinkFn;
const LinkerLoad = @import("../codegen.zig").LinkerLoad;
const Module = @import("../Module.zig");
const InternPool = @import("../InternPool.zig");
const StringTable = @import("StringTable.zig");
const Type = @import("../type.zig").Type;
const Value = @import("../Value.zig");
