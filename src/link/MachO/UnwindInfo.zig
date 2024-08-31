/// List of all unwind records gathered from all objects and sorted
/// by allocated relative function address within the section.
records: std.ArrayListUnmanaged(Record.Index) = .{},

/// List of all personalities referenced by either unwind info entries
/// or __eh_frame entries.
personalities: [max_personalities]Symbol.Index = undefined,
personalities_count: u2 = 0,

/// List of common encodings sorted in descending order with the most common first.
common_encodings: [max_common_encodings]Encoding = undefined,
common_encodings_count: u7 = 0,

/// List of record indexes containing an LSDA pointer.
lsdas: std.ArrayListUnmanaged(u32) = .{},
lsdas_lookup: std.ArrayListUnmanaged(u32) = .{},

/// List of second level pages.
pages: std.ArrayListUnmanaged(Page) = .{},

pub fn deinit(info: *UnwindInfo, allocator: Allocator) void {
    info.records.deinit(allocator);
    info.pages.deinit(allocator);
    info.lsdas.deinit(allocator);
    info.lsdas_lookup.deinit(allocator);
}

fn can_fold(macho_file: *MachO, lhs_index: Record.Index, rhs_index: Record.Index) bool {
    const cpu_arch = macho_file.get_target().cpu.arch;
    const lhs = macho_file.get_unwind_record(lhs_index);
    const rhs = macho_file.get_unwind_record(rhs_index);
    if (cpu_arch == .x86_64) {
        if (lhs.enc.get_mode() == @int_from_enum(macho.UNWIND_X86_64_MODE.STACK_IND) or
            rhs.enc.get_mode() == @int_from_enum(macho.UNWIND_X86_64_MODE.STACK_IND)) return false;
    }
    const lhs_per = lhs.personality orelse 0;
    const rhs_per = rhs.personality orelse 0;
    return lhs.enc.eql(rhs.enc) and
        lhs_per == rhs_per and
        lhs.fde == rhs.fde and
        lhs.get_lsda_atom(macho_file) == null and rhs.get_lsda_atom(macho_file) == null;
}

pub fn generate(info: *UnwindInfo, macho_file: *MachO) !void {
    const gpa = macho_file.base.comp.gpa;

    log.debug("generating unwind info", .{});

    // Collect all unwind records
    for (macho_file.sections.items(.atoms)) |atoms| {
        for (atoms.items) |atom_index| {
            const atom = macho_file.get_atom(atom_index) orelse continue;
            if (!atom.flags.alive) continue;
            const recs = atom.get_unwind_records(macho_file);
            try info.records.ensure_unused_capacity(gpa, recs.len);
            for (recs) |rec| {
                if (!macho_file.get_unwind_record(rec).alive) continue;
                info.records.append_assume_capacity(rec);
            }
        }
    }

    // Encode records
    for (info.records.items) |index| {
        const rec = macho_file.get_unwind_record(index);
        if (rec.get_fde(macho_file)) |fde| {
            rec.enc.set_dwarf_section_offset(@int_cast(fde.out_offset));
            if (fde.get_lsda_atom(macho_file)) |lsda| {
                rec.lsda = lsda.atom_index;
                rec.lsda_offset = fde.lsda_offset;
                rec.enc.set_has_lsda(true);
            }
            const cie = fde.get_cie(macho_file);
            if (cie.get_personality(macho_file)) |_| {
                const personality_index = try info.get_or_put_personality_function(cie.personality.?.index); // TODO handle error
                rec.enc.set_personality_index(personality_index + 1);
            }
        } else if (rec.get_personality(macho_file)) |_| {
            const personality_index = try info.get_or_put_personality_function(rec.personality.?); // TODO handle error
            rec.enc.set_personality_index(personality_index + 1);
        }
    }

    // Sort by assigned relative address within each output section
    const sort_fn = struct {
        fn sort_fn(ctx: *MachO, lhs_index: Record.Index, rhs_index: Record.Index) bool {
            const lhs = ctx.get_unwind_record(lhs_index);
            const rhs = ctx.get_unwind_record(rhs_index);
            const lhsa = lhs.get_atom(ctx);
            const rhsa = rhs.get_atom(ctx);
            if (lhsa.out_n_sect == rhsa.out_n_sect) return lhs.get_atom_address(ctx) < rhs.get_atom_address(ctx);
            return lhsa.out_n_sect < rhsa.out_n_sect;
        }
    }.sort_fn;
    mem.sort(Record.Index, info.records.items, macho_file, sort_fn);

    // Fold the records
    // Any adjacent two records that share encoding can be folded into one.
    {
        var i: usize = 0;
        var j: usize = 1;
        while (j < info.records.items.len) : (j += 1) {
            if (can_fold(macho_file, info.records.items[i], info.records.items[j])) {
                const rec = macho_file.get_unwind_record(info.records.items[i]);
                rec.length += macho_file.get_unwind_record(info.records.items[j]).length + 1;
            } else {
                i += 1;
                info.records.items[i] = info.records.items[j];
            }
        }
        info.records.shrink_and_free(gpa, i + 1);
    }

    for (info.records.items) |rec_index| {
        const rec = macho_file.get_unwind_record(rec_index);
        const atom = rec.get_atom(macho_file);
        log.debug("@{x}-{x} : {s} : rec({d}) : {}", .{
            rec.get_atom_address(macho_file),
            rec.get_atom_address(macho_file) + rec.length,
            atom.get_name(macho_file),
            rec_index,
            rec.enc,
        });
    }

    // Calculate common encodings
    {
        const CommonEncWithCount = struct {
            enc: Encoding,
            count: u32,

            fn greater_than(ctx: void, lhs: @This(), rhs: @This()) bool {
                _ = ctx;
                return lhs.count > rhs.count;
            }
        };

        const Context = struct {
            pub fn hash(ctx: @This(), key: Encoding) u32 {
                _ = ctx;
                return key.enc;
            }

            pub fn eql(
                ctx: @This(),
                key1: Encoding,
                key2: Encoding,
                b_index: usize,
            ) bool {
                _ = ctx;
                _ = b_index;
                return key1.eql(key2);
            }
        };

        var common_encodings_counts = std.ArrayHashMap(
            Encoding,
            CommonEncWithCount,
            Context,
            false,
        ).init(gpa);
        defer common_encodings_counts.deinit();

        for (info.records.items) |rec_index| {
            const rec = macho_file.get_unwind_record(rec_index);
            if (rec.enc.is_dwarf(macho_file)) continue;
            const gop = try common_encodings_counts.get_or_put(rec.enc);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .enc = rec.enc,
                    .count = 0,
                };
            }
            gop.value_ptr.count += 1;
        }

        const slice = common_encodings_counts.values();
        mem.sort(CommonEncWithCount, slice, {}, CommonEncWithCount.greater_than);

        var i: u7 = 0;
        while (i < slice.len) : (i += 1) {
            if (i >= max_common_encodings) break;
            if (slice[i].count < 2) continue;
            info.append_common_encoding(slice[i].enc);
            log.debug("adding common encoding: {d} => {}", .{ i, slice[i].enc });
        }
    }

    // Compute page allocations
    {
        var i: u32 = 0;
        while (i < info.records.items.len) {
            const rec = macho_file.get_unwind_record(info.records.items[i]);
            const range_start_max: u64 = rec.get_atom_address(macho_file) + compressed_entry_func_offset_mask;
            var encoding_count: u9 = info.common_encodings_count;
            var space_left: u32 = second_level_page_words -
                @size_of(macho.unwind_info_compressed_second_level_page_header) / @size_of(u32);
            var page = Page{
                .kind = undefined,
                .start = i,
                .count = 0,
            };

            while (space_left >= 1 and i < info.records.items.len) {
                const next = macho_file.get_unwind_record(info.records.items[i]);
                const is_dwarf = next.enc.is_dwarf(macho_file);

                if (next.get_atom_address(macho_file) >= range_start_max) {
                    break;
                } else if (info.get_common_encoding(next.enc) != null or
                    page.get_page_encoding(next.enc) != null and !is_dwarf)
                {
                    i += 1;
                    space_left -= 1;
                } else if (space_left >= 2 and encoding_count < max_compact_encodings) {
                    page.append_page_encoding(next.enc);
                    i += 1;
                    space_left -= 2;
                    encoding_count += 1;
                } else {
                    break;
                }
            }

            page.count = @as(u16, @int_cast(i - page.start));

            if (i < info.records.items.len and page.count < max_regular_second_level_entries) {
                page.kind = .regular;
                page.count = @as(u16, @int_cast(@min(
                    max_regular_second_level_entries,
                    info.records.items.len - page.start,
                )));
                i = page.start + page.count;
            } else {
                page.kind = .compressed;
            }

            log.debug("{}", .{page.fmt(info.*)});

            try info.pages.append(gpa, page);
        }
    }

    // Save records having an LSDA pointer
    log.debug("LSDA pointers:", .{});
    try info.lsdas_lookup.ensure_total_capacity_precise(gpa, info.records.items.len);
    for (info.records.items, 0..) |index, i| {
        const rec = macho_file.get_unwind_record(index);
        info.lsdas_lookup.append_assume_capacity(@int_cast(info.lsdas.items.len));
        if (rec.get_lsda_atom(macho_file)) |lsda| {
            log.debug("  @{x} => lsda({d})", .{ rec.get_atom_address(macho_file), lsda.atom_index });
            try info.lsdas.append(gpa, @int_cast(i));
        }
    }
}

pub fn calc_size(info: UnwindInfo) usize {
    var total_size: usize = 0;
    total_size += @size_of(macho.unwind_info_section_header);
    total_size +=
        @as(usize, @int_cast(info.common_encodings_count)) * @size_of(macho.compact_unwind_encoding_t);
    total_size += @as(usize, @int_cast(info.personalities_count)) * @size_of(u32);
    total_size += (info.pages.items.len + 1) * @size_of(macho.unwind_info_section_header_index_entry);
    total_size += info.lsdas.items.len * @size_of(macho.unwind_info_section_header_lsda_index_entry);
    total_size += info.pages.items.len * second_level_page_bytes;
    return total_size;
}

pub fn write(info: UnwindInfo, macho_file: *MachO, buffer: []u8) !void {
    const seg = macho_file.get_text_segment();
    const header = macho_file.sections.items(.header)[macho_file.unwind_info_sect_index.?];

    var stream = std.io.fixed_buffer_stream(buffer);
    const writer = stream.writer();

    const common_encodings_offset: u32 = @size_of(macho.unwind_info_section_header);
    const common_encodings_count: u32 = info.common_encodings_count;
    const personalities_offset: u32 = common_encodings_offset + common_encodings_count * @size_of(u32);
    const personalities_count: u32 = info.personalities_count;
    const indexes_offset: u32 = personalities_offset + personalities_count * @size_of(u32);
    const indexes_count: u32 = @as(u32, @int_cast(info.pages.items.len + 1));

    try writer.write_struct(macho.unwind_info_section_header{
        .commonEncodingsArraySectionOffset = common_encodings_offset,
        .commonEncodingsArrayCount = common_encodings_count,
        .personalityArraySectionOffset = personalities_offset,
        .personalityArrayCount = personalities_count,
        .indexSectionOffset = indexes_offset,
        .indexCount = indexes_count,
    });

    try writer.write_all(mem.slice_as_bytes(info.common_encodings[0..info.common_encodings_count]));

    for (info.personalities[0..info.personalities_count]) |sym_index| {
        const sym = macho_file.get_symbol(sym_index);
        try writer.write_int(u32, @int_cast(sym.get_got_address(macho_file) - seg.vmaddr), .little);
    }

    const pages_base_offset = @as(u32, @int_cast(header.size - (info.pages.items.len * second_level_page_bytes)));
    const lsda_base_offset = @as(u32, @int_cast(pages_base_offset -
        (info.lsdas.items.len * @size_of(macho.unwind_info_section_header_lsda_index_entry))));
    for (info.pages.items, 0..) |page, i| {
        assert(page.count > 0);
        const rec = macho_file.get_unwind_record(info.records.items[page.start]);
        try writer.write_struct(macho.unwind_info_section_header_index_entry{
            .functionOffset = @as(u32, @int_cast(rec.get_atom_address(macho_file) - seg.vmaddr)),
            .secondLevelPagesSectionOffset = @as(u32, @int_cast(pages_base_offset + i * second_level_page_bytes)),
            .lsdaIndexArraySectionOffset = lsda_base_offset +
                info.lsdas_lookup.items[page.start] * @size_of(macho.unwind_info_section_header_lsda_index_entry),
        });
    }

    const last_rec = macho_file.get_unwind_record(info.records.items[info.records.items.len - 1]);
    const sentinel_address = @as(u32, @int_cast(last_rec.get_atom_address(macho_file) + last_rec.length - seg.vmaddr));
    try writer.write_struct(macho.unwind_info_section_header_index_entry{
        .functionOffset = sentinel_address,
        .secondLevelPagesSectionOffset = 0,
        .lsdaIndexArraySectionOffset = lsda_base_offset +
            @as(u32, @int_cast(info.lsdas.items.len)) * @size_of(macho.unwind_info_section_header_lsda_index_entry),
    });

    for (info.lsdas.items) |index| {
        const rec = macho_file.get_unwind_record(info.records.items[index]);
        try writer.write_struct(macho.unwind_info_section_header_lsda_index_entry{
            .functionOffset = @as(u32, @int_cast(rec.get_atom_address(macho_file) - seg.vmaddr)),
            .lsdaOffset = @as(u32, @int_cast(rec.get_lsda_address(macho_file) - seg.vmaddr)),
        });
    }

    for (info.pages.items) |page| {
        const start = stream.pos;
        try page.write(info, macho_file, writer);
        const nwritten = stream.pos - start;
        if (nwritten < second_level_page_bytes) {
            const padding = math.cast(usize, second_level_page_bytes - nwritten) orelse return error.Overflow;
            try writer.write_byte_ntimes(0, padding);
        }
    }

    @memset(buffer[stream.pos..], 0);
}

fn get_or_put_personality_function(info: *UnwindInfo, sym_index: Symbol.Index) error{TooManyPersonalities}!u2 {
    comptime var index: u2 = 0;
    inline while (index < max_personalities) : (index += 1) {
        if (info.personalities[index] == sym_index) {
            return index;
        } else if (index == info.personalities_count) {
            info.personalities[index] = sym_index;
            info.personalities_count += 1;
            return index;
        }
    }
    return error.TooManyPersonalities;
}

fn append_common_encoding(info: *UnwindInfo, enc: Encoding) void {
    assert(info.common_encodings_count <= max_common_encodings);
    info.common_encodings[info.common_encodings_count] = enc;
    info.common_encodings_count += 1;
}

fn get_common_encoding(info: UnwindInfo, enc: Encoding) ?u7 {
    comptime var index: u7 = 0;
    inline while (index < max_common_encodings) : (index += 1) {
        if (index >= info.common_encodings_count) return null;
        if (info.common_encodings[index].eql(enc)) {
            return index;
        }
    }
    return null;
}

pub const Encoding = extern struct {
    enc: macho.compact_unwind_encoding_t,

    pub fn get_mode(enc: Encoding) u4 {
        comptime assert(macho.UNWIND_ARM64_MODE_MASK == macho.UNWIND_X86_64_MODE_MASK);
        const shift = comptime @ctz(macho.UNWIND_ARM64_MODE_MASK);
        return @as(u4, @truncate((enc.enc & macho.UNWIND_ARM64_MODE_MASK) >> shift));
    }

    pub fn is_dwarf(enc: Encoding, macho_file: *MachO) bool {
        const mode = enc.get_mode();
        return switch (macho_file.get_target().cpu.arch) {
            .aarch64 => @as(macho.UNWIND_ARM64_MODE, @enumFromInt(mode)) == .DWARF,
            .x86_64 => @as(macho.UNWIND_X86_64_MODE, @enumFromInt(mode)) == .DWARF,
            else => unreachable,
        };
    }

    pub fn set_mode(enc: *Encoding, mode: anytype) void {
        comptime assert(macho.UNWIND_ARM64_MODE_MASK == macho.UNWIND_X86_64_MODE_MASK);
        const shift = comptime @ctz(macho.UNWIND_ARM64_MODE_MASK);
        enc.enc |= @as(u32, @int_cast(@int_from_enum(mode))) << shift;
    }

    pub fn has_lsda(enc: Encoding) bool {
        const shift = comptime @ctz(macho.UNWIND_HAS_LSDA);
        const has_lsda = @as(u1, @truncate((enc.enc & macho.UNWIND_HAS_LSDA) >> shift));
        return has_lsda == 1;
    }

    pub fn set_has_lsda(enc: *Encoding, has_lsda: bool) void {
        const shift = comptime @ctz(macho.UNWIND_HAS_LSDA);
        const mask = @as(u32, @int_cast(@int_from_bool(has_lsda))) << shift;
        enc.enc |= mask;
    }

    pub fn get_personality_index(enc: Encoding) u2 {
        const shift = comptime @ctz(macho.UNWIND_PERSONALITY_MASK);
        const index = @as(u2, @truncate((enc.enc & macho.UNWIND_PERSONALITY_MASK) >> shift));
        return index;
    }

    pub fn set_personality_index(enc: *Encoding, index: u2) void {
        const shift = comptime @ctz(macho.UNWIND_PERSONALITY_MASK);
        const mask = @as(u32, @int_cast(index)) << shift;
        enc.enc |= mask;
    }

    pub fn get_dwarf_section_offset(enc: Encoding) u24 {
        const offset = @as(u24, @truncate(enc.enc));
        return offset;
    }

    pub fn set_dwarf_section_offset(enc: *Encoding, offset: u24) void {
        enc.enc |= offset;
    }

    pub fn eql(enc: Encoding, other: Encoding) bool {
        return enc.enc == other.enc;
    }

    pub fn format(
        enc: Encoding,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("0x{x:0>8}", .{enc.enc});
    }
};

pub const Record = struct {
    length: u32 = 0,
    enc: Encoding = .{ .enc = 0 },
    atom: Atom.Index = 0,
    atom_offset: u32 = 0,
    lsda: Atom.Index = 0,
    lsda_offset: u32 = 0,
    personality: ?Symbol.Index = null, // TODO make this zero-is-null
    fde: Fde.Index = 0, // TODO actually make FDE at 0 an invalid FDE
    file: File.Index = 0,
    alive: bool = true,

    pub fn get_object(rec: Record, macho_file: *MachO) *Object {
        return macho_file.get_file(rec.file).?.object;
    }

    pub fn get_atom(rec: Record, macho_file: *MachO) *Atom {
        return macho_file.get_atom(rec.atom).?;
    }

    pub fn get_lsda_atom(rec: Record, macho_file: *MachO) ?*Atom {
        return macho_file.get_atom(rec.lsda);
    }

    pub fn get_personality(rec: Record, macho_file: *MachO) ?*Symbol {
        const personality = rec.personality orelse return null;
        return macho_file.get_symbol(personality);
    }

    pub fn get_fde(rec: Record, macho_file: *MachO) ?Fde {
        if (!rec.enc.is_dwarf(macho_file)) return null;
        return rec.get_object(macho_file).fdes.items[rec.fde];
    }

    pub fn get_fde_ptr(rec: Record, macho_file: *MachO) ?*Fde {
        if (!rec.enc.is_dwarf(macho_file)) return null;
        return &rec.get_object(macho_file).fdes.items[rec.fde];
    }

    pub fn get_atom_address(rec: Record, macho_file: *MachO) u64 {
        const atom = rec.get_atom(macho_file);
        return atom.get_address(macho_file) + rec.atom_offset;
    }

    pub fn get_lsda_address(rec: Record, macho_file: *MachO) u64 {
        const lsda = rec.get_lsda_atom(macho_file) orelse return 0;
        return lsda.get_address(macho_file) + rec.lsda_offset;
    }

    pub fn format(
        rec: Record,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = rec;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compile_error("do not format UnwindInfo.Records directly");
    }

    pub fn fmt(rec: Record, macho_file: *MachO) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .rec = rec,
            .macho_file = macho_file,
        } };
    }

    const FormatContext = struct {
        rec: Record,
        macho_file: *MachO,
    };

    fn format2(
        ctx: FormatContext,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const rec = ctx.rec;
        const macho_file = ctx.macho_file;
        try writer.print("{x} : len({x})", .{
            rec.enc.enc, rec.length,
        });
        if (rec.enc.is_dwarf(macho_file)) try writer.print(" : fde({d})", .{rec.fde});
        try writer.print(" : {s}", .{rec.get_atom(macho_file).get_name(macho_file)});
        if (!rec.alive) try writer.write_all(" : [*]");
    }

    pub const Index = u32;
};

const max_personalities = 3;
const max_common_encodings = 127;
const max_compact_encodings = 256;

const second_level_page_bytes = 0x1000;
const second_level_page_words = second_level_page_bytes / @size_of(u32);

const max_regular_second_level_entries =
    (second_level_page_bytes - @size_of(macho.unwind_info_regular_second_level_page_header)) /
    @size_of(macho.unwind_info_regular_second_level_entry);

const max_compressed_second_level_entries =
    (second_level_page_bytes - @size_of(macho.unwind_info_compressed_second_level_page_header)) /
    @size_of(u32);

const compressed_entry_func_offset_mask = ~@as(u24, 0);

const Page = struct {
    kind: enum { regular, compressed },
    start: u32,
    count: u16,
    page_encodings: [max_compact_encodings]Encoding = undefined,
    page_encodings_count: u9 = 0,

    fn append_page_encoding(page: *Page, enc: Encoding) void {
        assert(page.page_encodings_count <= max_compact_encodings);
        page.page_encodings[page.page_encodings_count] = enc;
        page.page_encodings_count += 1;
    }

    fn get_page_encoding(page: Page, enc: Encoding) ?u8 {
        comptime var index: u9 = 0;
        inline while (index < max_compact_encodings) : (index += 1) {
            if (index >= page.page_encodings_count) return null;
            if (page.page_encodings[index].eql(enc)) {
                return @as(u8, @int_cast(index));
            }
        }
        return null;
    }

    fn format(
        page: *const Page,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = page;
        _ = unused_format_string;
        _ = options;
        _ = writer;
        @compile_error("do not format Page directly; use page.fmt()");
    }

    const FormatPageContext = struct {
        page: Page,
        info: UnwindInfo,
    };

    fn format2(
        ctx: FormatPageContext,
        comptime unused_format_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        _ = unused_format_string;
        try writer.write_all("Page:\n");
        try writer.print("  kind: {s}\n", .{@tag_name(ctx.page.kind)});
        try writer.print("  entries: {d} - {d}\n", .{
            ctx.page.start,
            ctx.page.start + ctx.page.count,
        });
        try writer.print("  encodings (count = {d})\n", .{ctx.page.page_encodings_count});
        for (ctx.page.page_encodings[0..ctx.page.page_encodings_count], 0..) |enc, i| {
            try writer.print("    {d}: {}\n", .{ ctx.info.common_encodings_count + i, enc });
        }
    }

    fn fmt(page: Page, info: UnwindInfo) std.fmt.Formatter(format2) {
        return .{ .data = .{
            .page = page,
            .info = info,
        } };
    }

    fn write(page: Page, info: UnwindInfo, macho_file: *MachO, writer: anytype) !void {
        const seg = macho_file.get_text_segment();

        switch (page.kind) {
            .regular => {
                try writer.write_struct(macho.unwind_info_regular_second_level_page_header{
                    .entryPageOffset = @size_of(macho.unwind_info_regular_second_level_page_header),
                    .entryCount = page.count,
                });

                for (info.records.items[page.start..][0..page.count]) |index| {
                    const rec = macho_file.get_unwind_record(index);
                    try writer.write_struct(macho.unwind_info_regular_second_level_entry{
                        .functionOffset = @as(u32, @int_cast(rec.get_atom_address(macho_file) - seg.vmaddr)),
                        .encoding = rec.enc.enc,
                    });
                }
            },
            .compressed => {
                const entry_offset = @size_of(macho.unwind_info_compressed_second_level_page_header) +
                    @as(u16, @int_cast(page.page_encodings_count)) * @size_of(u32);
                try writer.write_struct(macho.unwind_info_compressed_second_level_page_header{
                    .entryPageOffset = entry_offset,
                    .entryCount = page.count,
                    .encodingsPageOffset = @size_of(macho.unwind_info_compressed_second_level_page_header),
                    .encodingsCount = page.page_encodings_count,
                });

                for (page.page_encodings[0..page.page_encodings_count]) |enc| {
                    try writer.write_int(u32, enc.enc, .little);
                }

                assert(page.count > 0);
                const first_rec = macho_file.get_unwind_record(info.records.items[page.start]);
                for (info.records.items[page.start..][0..page.count]) |index| {
                    const rec = macho_file.get_unwind_record(index);
                    const enc_index = blk: {
                        if (info.get_common_encoding(rec.enc)) |id| break :blk id;
                        const ncommon = info.common_encodings_count;
                        break :blk ncommon + page.get_page_encoding(rec.enc).?;
                    };
                    const compressed = macho.UnwindInfoCompressedEntry{
                        .funcOffset = @as(u24, @int_cast(rec.get_atom_address(macho_file) - first_rec.get_atom_address(macho_file))),
                        .encodingIndex = @as(u8, @int_cast(enc_index)),
                    };
                    try writer.write_struct(compressed);
                }
            },
        }
    }
};

const std = @import("std");
const assert = std.debug.assert;
const eh_frame = @import("eh_frame.zig");
const fs = std.fs;
const leb = std.leb;
const log = std.log.scoped(.link);
const macho = std.macho;
const math = std.math;
const mem = std.mem;
const trace = @import("../../tracy.zig").trace;

const Allocator = mem.Allocator;
const Atom = @import("Atom.zig");
const Fde = eh_frame.Fde;
const File = @import("file.zig").File;
const MachO = @import("../MachO.zig");
const Object = @import("Object.zig");
const Symbol = @import("Symbol.zig");
const UnwindInfo = @This();
